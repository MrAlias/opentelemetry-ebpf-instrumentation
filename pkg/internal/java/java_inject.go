// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javaagent // import "go.opentelemetry.io/obi/pkg/internal/java"

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/jvmtools/jvm"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/obi"
)

const (
	ObiJavaAgentFileName             = "obi-java-agent.jar"
	javaAgentEmbedPlaceholder        = "OBI_JAVA_AGENT_PLACEHOLDER"
	maxJavaRemoteParentTimeoutMillis = int64(1<<31 - 1)
	maxJVMAttachResponseBytes        = 64 << 10
	maxJavaAgentTempCreateAttempts   = 100
	maxUID                           = uint64(1<<32 - 1)
	javaAuthorizationReadyTimeout    = 12 * time.Second
)

//go:embed embedded/obi-java-agent.jar
var embeddedJavaAgentBytes []byte

type JavaInjectError struct {
	Message string
}

func (e *JavaInjectError) Error() string {
	return e.Message
}

type JavaInjector struct {
	log                   *slog.Logger
	cfg                   *obi.Config
	remoteParentServerUID int
	currentAttachID       int64
	mu                    sync.Mutex
}

type javaAttacher interface {
	BindTarget(int, uint64) error
	BindTargetFromProcFD(int, uint64, int) error
	ValidateTarget() error
	CloseTarget() error
	Init()
	Cleanup() error
	AttachContext(context.Context, int, []string, bool) (io.ReadCloser, error)
}

type lifecycleJavaAttacher interface {
	ConfigureAttachLifecycle(int64, func(int64, func() error) error)
	Terminate() error
}

// PreparedExecutable owns the exact process handle captured before Java
// authorization begins. Its attachment may run asynchronously, but it can
// never look up a replacement process by numeric PID after readiness unblocks.
type PreparedExecutable interface {
	NewExecutableContext(context.Context) error
	Close() error
}

type preparedExecutable struct {
	mu                      sync.Mutex
	injector                *JavaInjector
	instrumentable          *ebpf.Instrumentable
	attacher                javaAttacher
	authorizationGeneration uint64
	started                 bool
	closed                  bool
	closeErr                error
}

func (p *preparedExecutable) NewExecutableContext(ctx context.Context) (resultErr error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return errors.New("prepared Java target is already closed")
	}
	if p.started {
		return errors.New("prepared Java target was already used")
	}
	p.started = true
	resultErr = p.injector.newExecutableContext(
		ctx,
		p.instrumentable,
		p.attacher,
		p.authorizationGeneration,
	)
	return errors.Join(resultErr, p.closeLocked())
}

func (p *preparedExecutable) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closeLocked()
}

func (p *preparedExecutable) closeLocked() error {
	if !p.closed {
		p.closed = true
		// If this prepared operation was rejected or canceled before the tracer
		// completed authorization, release only its exact readiness generation
		// fail-closed. A stale or already-completed generation ignores this call.
		p.instrumentable.FileInfo.CompleteJavaAgentAuthorization(
			p.authorizationGeneration, 0,
		)
		p.closeErr = p.attacher.CloseTarget()
	}
	return p.closeErr
}

var newJavaAttacher = func(log *slog.Logger) javaAttacher {
	return jvm.NewJAttacher(log, 0, nil)
}

var (
	readJavaCapabilityRandom   = rand.Read
	javaTargetProcessStartTime = procs.ProcessStartTime
	javaAttachSerial           = make(chan struct{}, 1)
)

func acquireJavaAttach(ctx context.Context) (func(), error) {
	select {
	case javaAttachSerial <- struct{}{}:
		return func() { <-javaAttachSerial }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func validateJavaTargetLifetime(fi *exec.FileInfo) error {
	if fi == nil {
		return errors.New("java process has no executable identity")
	}
	if fi.ProcessStartTime() == 0 {
		return nil
	}
	current, err := javaTargetProcessStartTime(fi.Pid())
	if err != nil {
		return fmt.Errorf("revalidating Java target process lifetime: %w", err)
	}
	if current != fi.ProcessStartTime() {
		return fmt.Errorf(
			"revalidating Java target process lifetime: PID %d changed from start %d to %d",
			fi.Pid(), fi.ProcessStartTime(), current,
		)
	}
	return nil
}

func bindJavaTarget(attacher javaAttacher, fi *exec.FileInfo) error {
	if fi == nil {
		return errors.New("java process has no executable identity")
	}
	// A zero start time is retained only for legacy unit fixtures. Every Linux
	// discovery FileInfo carries both a nonzero start token and a pinned procfd.
	if fi.ProcessStartTime() == 0 {
		return attacher.BindTarget(int(fi.Pid()), 0)
	}
	return fi.UseProcessHandle(func(procFD int) error {
		return attacher.BindTargetFromProcFD(
			int(fi.Pid()), fi.ProcessStartTime(), procFD,
		)
	})
}

func NewJavaInjector(cfg *obi.Config) (*JavaInjector, error) {
	if !cfg.Java.Enabled {
		return nil, nil
	}
	if strings.ContainsRune(cfg.Java.RemoteParent.SocketPath, ',') {
		return nil, errors.New("javaagent.remote_parent.socket_path must not contain a comma")
	}
	if cfg.Java.RemoteParent.Timeout.Milliseconds() > maxJavaRemoteParentTimeoutMillis {
		return nil, errors.New("javaagent.remote_parent.timeout must not exceed 2147483647ms")
	}
	if err := ensureEmbeddedAgent(); err != nil {
		return nil, err
	}

	return &JavaInjector{
		cfg:                   cfg,
		log:                   slog.With("component", "javaagent.Injector"),
		remoteParentServerUID: os.Geteuid(),
		currentAttachID:       0,
	}, nil
}

func tempDirPath(root, dir string) (string, bool) {
	if root == "" {
		return "", false
	}

	cleanDir := filepath.Clean(dir)
	if !filepath.IsAbs(cleanDir) {
		return "", false
	}

	fullDir := filepath.Join(root, strings.TrimPrefix(cleanDir, "/"))
	rel, err := filepath.Rel(root, fullDir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}

	return fullDir, true
}

func openRootDirectory(root string) (int, error) {
	if root == "" {
		return -1, errors.New("empty process root path")
	}

	// The final component is intentionally followed because /proc/<pid>/root is
	// a kernel-provided link. Paths inside it are opened separately without following links.
	return unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
}

func targetPathComponents(path string) ([]string, bool) {
	cleanPath := filepath.Clean(path)
	if path == "" || !filepath.IsAbs(cleanPath) {
		return nil, false
	}
	if cleanPath == string(filepath.Separator) {
		return nil, true
	}

	components := strings.Split(strings.TrimPrefix(cleanPath, string(filepath.Separator)), string(filepath.Separator))
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			return nil, false
		}
	}

	return components, true
}

func openTargetDirectory(rootFD int, targetPath string) (int, error) {
	components, ok := targetPathComponents(targetPath)
	if !ok {
		return -1, fmt.Errorf("invalid target directory %q", targetPath)
	}

	flags := unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	currentFD, err := unix.Openat(rootFD, ".", flags, 0)
	if err != nil {
		return -1, err
	}

	for _, component := range components {
		nextFD, err := unix.Openat(currentFD, component, flags, 0)
		_ = unix.Close(currentFD)
		if err != nil {
			return -1, err
		}
		currentFD = nextFD
	}

	return currentFD, nil
}

func dirOK(root, dir string) bool {
	rootFD, err := openRootDirectory(root)
	if err != nil {
		return false
	}
	defer unix.Close(rootFD)

	dirFD, err := openTargetDirectory(rootFD, dir)
	if err != nil {
		return false
	}
	_ = unix.Close(dirFD)

	return true
}

func (i *JavaInjector) findTempDirAt(rootFD int, ie *ebpf.Instrumentable) (string, int, error) {
	if tmpDir, ok := ie.FileInfo.ServiceAttrs().EnvVars["TMPDIR"]; ok {
		if dirFD, err := openTargetDirectory(rootFD, tmpDir); err == nil {
			return tmpDir, dirFD, nil
		}
	}

	tmpDir := "/tmp"
	if dirFD, err := openTargetDirectory(rootFD, tmpDir); err == nil {
		return tmpDir, dirFD, nil
	}

	tmpDir = "/var/tmp"
	if dirFD, err := openTargetDirectory(rootFD, tmpDir); err == nil {
		return tmpDir, dirFD, nil
	}

	return "", -1, errors.New("couldn't find suitable temp directory for injection")
}

func (i *JavaInjector) findTempDir(root string, ie *ebpf.Instrumentable) (string, error) {
	rootFD, err := openRootDirectory(root)
	if err != nil {
		return "", errors.New("couldn't find suitable temp directory for injection")
	}
	defer unix.Close(rootFD)

	tmpDir, dirFD, err := i.findTempDirAt(rootFD, ie)
	if err != nil {
		return "", err
	}
	_ = unix.Close(dirFD)

	return tmpDir, nil
}

func (i *JavaInjector) nextAttachID() int64 {
	i.mu.Lock()
	defer i.mu.Unlock()

	i.currentAttachID++
	return i.currentAttachID
}

func (i *JavaInjector) runIfCurrentAttach(
	attachID int64,
	fn func() error,
) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.currentAttachID != attachID {
		return nil
	}

	return fn()
}

func (i *JavaInjector) NewExecutable(ie *ebpf.Instrumentable) error {
	return i.NewExecutableContext(context.Background(), ie)
}

func (i *JavaInjector) NewExecutableContext(
	parent context.Context,
	ie *ebpf.Instrumentable,
) (resultErr error) {
	if ie == nil || ie.Type != svc.InstrumentableJava {
		return nil
	}
	if err := validateJavaTargetLifetime(ie.FileInfo); err != nil {
		return err
	}
	attacher := newJavaAttacher(i.log)
	if err := bindJavaTarget(attacher, ie.FileInfo); err != nil {
		return fmt.Errorf("binding exact Java target process: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, attacher.CloseTarget()) }()
	return i.newExecutableContext(parent, ie, attacher, 0)
}

func (i *JavaInjector) newExecutableContext(
	parent context.Context,
	ie *ebpf.Instrumentable,
	attacher javaAttacher,
	authorizationGeneration uint64,
) (resultErr error) {
	readyCtx, cancelReady := context.WithTimeout(parent, javaAuthorizationReadyTimeout)
	var capability uint64
	var err error
	if authorizationGeneration == 0 {
		capability, err = ie.FileInfo.WaitJavaAgentAuthorization(readyCtx)
	} else {
		capability, err = ie.FileInfo.WaitJavaAgentAuthorizationGeneration(
			readyCtx, authorizationGeneration,
		)
	}
	cancelReady()
	if err != nil {
		return fmt.Errorf("waiting for Java process authorization: %w", err)
	}
	if capability == 0 {
		return &JavaInjectError{Message: "Java process capability was not prepared before attach"}
	}
	if err := parent.Err(); err != nil {
		return fmt.Errorf("starting Java attach: %w", err)
	}
	releaseAttach, err := acquireJavaAttach(parent)
	if err != nil {
		return fmt.Errorf("waiting for the process-wide Java attach gate: %w", err)
	}
	defer releaseAttach()
	if err := validateJavaTargetLifetime(ie.FileInfo); err != nil {
		return err
	}
	attachID := i.nextAttachID()
	if lifecycle, ok := attacher.(lifecycleJavaAttacher); ok {
		lifecycle.ConfigureAttachLifecycle(attachID, i.runIfCurrentAttach)
		defer func() { resultErr = errors.Join(resultErr, lifecycle.Terminate()) }()
	}
	ctx, cancel := context.WithTimeout(parent, i.cfg.Java.Timeout)
	defer cancel()

	if err := attacher.ValidateTarget(); err != nil {
		return fmt.Errorf("revalidating exact Java target after authorization: %w", err)
	}
	ok, jdk8, err := i.verifyJVMVersion(ctx, attacher, ie.FileInfo.Pid())
	if err != nil {
		return i.attachError(ctx, ie, err)
	}
	if !ok {
		return &JavaInjectError{Message: "unsupported Java version for OpenTelemetry eBPF instrumentation"}
	}

	var loaded bool
	if jdk8 {
		loaded, err = i.jdkAgentAlreadyLoadedHotspot8(ctx, attacher, ie.FileInfo.Pid())
	} else {
		loaded, err = i.jdkAgentAlreadyLoaded(ctx, attacher, ie.FileInfo.Pid())
	}
	if err != nil {
		return i.attachError(ctx, ie, err)
	}
	if loaded {
		i.log.Info("OpenTelemetry eBPF Java Agent already loaded, reconfiguring")
	}
	if err := validateJavaTargetLifetime(ie.FileInfo); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := attacher.ValidateTarget(); err != nil {
		return fmt.Errorf("revalidating exact Java target before agent copy: %w", err)
	}
	i.log.Info("injecting OpenTelemetry eBPF instrumentation for Java process", "pid", ie.FileInfo.Pid())
	agentPath, err := i.copyAgent(ie, attacher.ValidateTarget)
	if err != nil {
		i.log.Error("failed to extract java agent", "pid", ie.FileInfo.Pid(), "error", err)
		return err
	}
	if err := validateJavaTargetLifetime(ie.FileInfo); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := attacher.ValidateTarget(); err != nil {
		return fmt.Errorf("revalidating exact Java target before agent load: %w", err)
	}
	if err := i.attachJDKAgentWithCapability(
		ctx, attacher, ie.FileInfo.Pid(), agentPath, capability,
	); err != nil {
		i.log.Error("couldn't attach OpenTelemetry eBPF Java Agent", "pid", ie.FileInfo.Pid(), "path", agentPath, "error", err)
		return i.attachError(ctx, ie, err)
	}
	if err := validateJavaTargetLifetime(ie.FileInfo); err != nil {
		return err
	}

	return nil
}

func (i *JavaInjector) PrepareExecutable(
	ie *ebpf.Instrumentable,
) (_ PreparedExecutable, resultErr error) {
	if ie == nil || ie.Type != svc.InstrumentableJava {
		return nil, nil
	}
	if ie.FileInfo == nil {
		return nil, errors.New("java process has no executable identity")
	}
	if err := validateJavaTargetLifetime(ie.FileInfo); err != nil {
		return nil, err
	}
	// Every EventCreated/attachment attempt starts a fresh process epoch. A
	// previous R(capability) marker is eventually removed after cleanup, so
	// reusing the nonzero value already stored on a recycled FileInfo would
	// otherwise reopen a retired capability after its transient marker is gone.
	authorizationGeneration := ie.FileInfo.PrepareJavaAgentCapability(0)
	attacher := newJavaAttacher(i.log)
	if err := bindJavaTarget(attacher, ie.FileInfo); err != nil {
		ie.FileInfo.CompleteJavaAgentAuthorization(authorizationGeneration, 0)
		return nil, fmt.Errorf("binding prepared Java target process: %w", err)
	}
	defer func() {
		if resultErr != nil {
			ie.FileInfo.CompleteJavaAgentAuthorization(authorizationGeneration, 0)
			resultErr = errors.Join(resultErr, attacher.CloseTarget())
		}
	}()
	for range 4 {
		var random [8]byte
		if _, err := readJavaCapabilityRandom(random[:]); err != nil {
			return nil, fmt.Errorf("generate Java process capability: %w", err)
		}
		capability := binary.LittleEndian.Uint64(random[:]) & uint64(1<<63-1)
		if capability != 0 {
			if !ie.FileInfo.SetJavaAgentCapabilityForGeneration(
				authorizationGeneration, capability,
			) {
				return nil, errors.New("prepared Java authorization generation was superseded")
			}
			return &preparedExecutable{
				injector:                i,
				instrumentable:          ie,
				attacher:                attacher,
				authorizationGeneration: authorizationGeneration,
			}, nil
		}
	}

	return nil, errors.New("generate nonzero Java process capability")
}

func (i *JavaInjector) attachError(ctx context.Context, ie *ebpf.Instrumentable, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		if errors.Is(ctxErr, context.Canceled) {
			return fmt.Errorf("java attach canceled: %w", ctxErr)
		}
		i.log.Warn("java attach timed out", "timeout", i.cfg.Java.Timeout, "pid", ie.FileInfo.Pid())
		return errors.Join(
			&JavaInjectError{Message: "java attach timed out"},
			ctxErr,
		)
	}

	return err
}

func ensureEmbeddedAgent() error {
	if len(embeddedJavaAgentBytes) == 0 || strings.TrimSpace(string(embeddedJavaAgentBytes)) == javaAgentEmbedPlaceholder {
		return errors.New("embedded OBI java agent artifact is missing from this build; Java TLS telemetry generation will be disabled")
	}

	return nil
}

// to be changed in tests
var rootDirForPID func(app.PID) string = ebpfcommon.RootDirectoryForPID

type javaAgentTarget interface {
	ReadFrom(io.Reader) (int64, error)
	Chmod(os.FileMode) error
	Close() error
}

func populateJavaAgentTarget(target javaAgentTarget, source io.Reader) (resultErr error) {
	defer func() {
		if err := target.Close(); err != nil {
			resultErr = errors.Join(
				resultErr,
				fmt.Errorf("error closing target OBI java agent: %w", err),
			)
		}
	}()

	if _, err := target.ReadFrom(source); err != nil {
		return fmt.Errorf("error writing java agent to target location: %w", err)
	}
	if err := target.Chmod(0o644); err != nil {
		return fmt.Errorf("error setting permissions on target OBI java agent: %w", err)
	}

	return nil
}

func createJavaAgentTempFile(dirFD int) (*os.File, string, error) {
	for range maxJavaAgentTempCreateAttempts {
		var suffix [8]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, "", fmt.Errorf("generate temporary OBI java agent name: %w", err)
		}

		name := fmt.Sprintf("%s.tmp-%x", ObiJavaAgentFileName, suffix)
		fd, err := unix.Openat(
			dirFD,
			name,
			unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0o600,
		)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return nil, "", err
		}

		file := os.NewFile(uintptr(fd), name)
		if file == nil {
			_ = unix.Close(fd)
			return nil, "", errors.New("create file handle for temporary OBI java agent")
		}

		return file, name, nil
	}

	return nil, "", fmt.Errorf("unable to allocate a unique OBI java agent name after %d attempts", maxJavaAgentTempCreateAttempts)
}

func (i *JavaInjector) copyAgent(
	ie *ebpf.Instrumentable,
	validateTarget ...func() error,
) (string, error) {
	root := rootDirForPID(ie.FileInfo.Pid())
	rootFD, err := openRootDirectory(root)
	if err != nil {
		return "", fmt.Errorf("error accessing process root: %w", err)
	}
	defer unix.Close(rootFD)
	if len(validateTarget) != 0 && validateTarget[0] != nil {
		if err := validateTarget[0](); err != nil {
			return "", fmt.Errorf("revalidating process after opening its root: %w", err)
		}
	}

	tempDir, tempDirFD, err := i.findTempDirAt(rootFD, ie)
	if err != nil {
		return "", fmt.Errorf("error accessing temp directory: %w", err)
	}
	defer unix.Close(tempDirFD)

	fullTempDir, ok := tempDirPath(root, tempDir)
	if !ok {
		return "", fmt.Errorf("invalid temp directory for injection: %q", tempDir)
	}

	i.log.Info("found injection directory for process", "pid", ie.FileInfo.Pid(), "path", fullTempDir)

	source := bytes.NewReader(embeddedJavaAgentBytes)
	target, tmpTargetName, err := createJavaAgentTempFile(tempDirFD)
	if err != nil {
		return "", fmt.Errorf("unable to create target OBI java agent: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = unix.Unlinkat(tempDirFD, tmpTargetName, 0)
		}
	}()

	if err := populateJavaAgentTarget(target, source); err != nil {
		return "", err
	}

	if err = unix.Renameat(tempDirFD, tmpTargetName, tempDirFD, ObiJavaAgentFileName); err != nil {
		return "", fmt.Errorf("unable to move target OBI java agent into place: %w", err)
	}
	cleanup = false

	agentPathContainer := filepath.Join(tempDir, ObiJavaAgentFileName)

	return agentPathContainer, nil
}

type attachResponseState struct {
	firstLineSeen          bool
	hotspotStatusSeen      bool
	hotspotAgentResultSeen bool
	openJ9ACKSeen          bool
}

func (s *attachResponseState) parseLine(raw string) error {
	line := strings.TrimSpace(strings.TrimSuffix(raw, "\x00"))
	if line == "" {
		return nil
	}

	if !s.firstLineSeen {
		s.firstLineSeen = true
		if status, err := strconv.Atoi(line); err == nil {
			s.hotspotStatusSeen = true
			if status != 0 {
				return fmt.Errorf("java VM attach failed with status %d", status)
			}
			return nil
		}
	}

	if s.hotspotStatusSeen {
		if s.hotspotAgentResultSeen {
			return fmt.Errorf("java VM attach returned unexpected response %q", line)
		}

		codeText := line
		const returnCodePrefix = "return code:"
		if strings.HasPrefix(line, returnCodePrefix) {
			codeText = strings.TrimSpace(strings.TrimPrefix(line, returnCodePrefix))
		}
		code, err := strconv.Atoi(codeText)
		if err != nil {
			return fmt.Errorf("java VM agent failed with response %q", line)
		}
		s.hotspotAgentResultSeen = true
		if code != 0 {
			return fmt.Errorf("java VM agent failed with return code %d", code)
		}
		return nil
	}

	if line == "ATTACH_ACK" {
		s.openJ9ACKSeen = true
		return nil
	}

	const returnCodePrefix = "return code:"
	if strings.HasPrefix(line, returnCodePrefix) {
		code, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, returnCodePrefix)))
		if err != nil {
			return fmt.Errorf("invalid JVM agent return code %q", line)
		}
		if code != 0 {
			return fmt.Errorf("java VM agent failed with return code %d", code)
		}
	}

	return nil
}

func (s *attachResponseState) finish(openJ9 bool) error {
	if openJ9 {
		if !s.openJ9ACKSeen {
			return errors.New("openJ9 attach response ended without ATTACH_ACK")
		}
		return nil
	}
	if !s.hotspotStatusSeen {
		return errors.New("hotSpot attach response ended without a status")
	}
	if !s.hotspotAgentResultSeen {
		return errors.New("hotSpot attach response ended without an agent result")
	}
	return nil
}

func closeOnContext(ctx context.Context, closer io.Closer) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		_ = closer.Close()
	})

	return func() {
		if !stop() {
			<-done
		}
	}
}

var readUIDMapForPID = func(pid app.PID) ([]byte, error) {
	return os.ReadFile(filepath.Join("/proc", strconv.Itoa(int(pid)), "uid_map"))
}

func mapUID(uidMap io.Reader, hostUID int) (uint64, error) {
	if hostUID < 0 {
		return 0, fmt.Errorf("invalid host UID %d", hostUID)
	}

	hostUID64 := uint64(hostUID)
	scanner := bufio.NewScanner(uidMap)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 {
			return 0, fmt.Errorf("invalid UID map entry on line %d", lineNumber)
		}

		insideID, err := strconv.ParseUint(fields[0], 10, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid target UID on line %d: %w", lineNumber, err)
		}
		outsideID, err := strconv.ParseUint(fields[1], 10, 32)
		if err != nil {
			return 0, fmt.Errorf("invalid host UID on line %d: %w", lineNumber, err)
		}
		length, err := strconv.ParseUint(fields[2], 10, 32)
		if err != nil || length == 0 {
			if err == nil {
				err = errors.New("mapping length is zero")
			}
			return 0, fmt.Errorf("invalid UID range on line %d: %w", lineNumber, err)
		}

		uidSpaceSize := maxUID + 1
		if outsideID+length > uidSpaceSize || insideID+length > uidSpaceSize {
			return 0, fmt.Errorf("user ID range on line %d exceeds the UID address space", lineNumber)
		}
		if hostUID64 < outsideID || hostUID64-outsideID >= length {
			continue
		}

		return insideID + hostUID64 - outsideID, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("read UID map: %w", err)
	}

	return 0, fmt.Errorf("host UID %d is not mapped into the target user namespace", hostUID)
}

func (i *JavaInjector) targetRemoteParentServerUID(pid app.PID) (uint64, error) {
	uidMap, err := readUIDMapForPID(pid)
	if err != nil {
		return 0, fmt.Errorf("read target UID map: %w", err)
	}

	return mapUID(bytes.NewReader(uidMap), i.remoteParentServerUID)
}

func (i *JavaInjector) attachOptsWithCapability(
	pid app.PID, processCapability uint64,
) (string, error) {
	var opts []string
	if i.cfg.Java.Debug {
		opts = append(opts, "debug=true")
	}
	if i.cfg.Java.DebugInstrumentation {
		opts = append(opts, "debugBB=true")
	}

	transport := i.cfg.Java.RemoteParent.Transport
	if transport == "" {
		transport = obi.JavaRemoteParentDisabled
	}
	var serverUIDOption string
	if transport == obi.JavaRemoteParentUnix || transport == obi.JavaRemoteParentAuto {
		serverUID, err := i.targetRemoteParentServerUID(pid)
		if err != nil {
			if transport == obi.JavaRemoteParentUnix {
				return "", fmt.Errorf(
					"map OBI UID %d into target JVM %d user namespace: %w",
					i.remoteParentServerUID,
					pid,
					err,
				)
			}
			if i.log != nil {
				i.log.Warn(
					"Java remote-parent Unix fallback unavailable in target user namespace; using sockopt only",
					"pid", pid,
					"error", err,
				)
			}
			transport = obi.JavaRemoteParentGetsockopt
		} else {
			serverUIDOption = "remoteParentServerUid=" + strconv.FormatUint(serverUID, 10)
		}
	}
	opts = append(opts, "remoteParentTransport="+string(transport))
	if serverUIDOption != "" {
		opts = append(opts, serverUIDOption)
	}
	if i.cfg.Java.RemoteParent.SocketPath != "" {
		opts = append(opts, "remoteParentSocket="+i.cfg.Java.RemoteParent.SocketPath)
	}
	if i.cfg.Java.RemoteParent.Timeout > 0 {
		timeoutMillis := max(i.cfg.Java.RemoteParent.Timeout.Milliseconds(), 1)
		opts = append(opts, "remoteParentTimeoutMillis="+strconv.FormatInt(timeoutMillis, 10))
	}
	if processCapability != 0 {
		opts = append(
			opts,
			"processCapability="+strconv.FormatUint(processCapability, 10),
		)
	}

	return "=" + strings.Join(opts, ","), nil
}

func (i *JavaInjector) attachJDKAgent(
	ctx context.Context, attacher javaAttacher, pid app.PID, path string,
) (resultErr error) {
	return i.attachJDKAgentWithCapability(ctx, attacher, pid, path, 0)
}

func (i *JavaInjector) attachJDKAgentWithCapability(
	ctx context.Context,
	attacher javaAttacher,
	pid app.PID,
	path string,
	processCapability uint64,
) (resultErr error) {
	attachOpts, err := i.attachOptsWithCapability(pid, processCapability)
	if err != nil {
		return err
	}

	attacher.Init()
	defer func() { resultErr = errors.Join(resultErr, attacher.Cleanup()) }()

	out, err := attacher.AttachContext(
		ctx, int(pid), []string{"load", "instrument", "false", path + attachOpts}, false,
	)
	if err != nil {
		i.log.Error("error executing command for the JVM", "pid", pid, "error", err)
		return err
	}
	if out == nil {
		return errors.New("java VM attach returned no response")
	}
	defer func() { resultErr = errors.Join(resultErr, out.Close()) }()
	defer closeOnContext(ctx, out)()

	reader := bufio.NewReader(out)
	buf := bytes.Buffer{}
	response := attachResponseState{}
	responseBytes := 0
	for {
		b, err := reader.ReadByte()
		if err != nil {
			if err == io.EOF { // hotspot terminates with EOF
				if err := response.parseLine(buf.String()); err != nil {
					return err
				}
				return response.finish(false)
			}
			return fmt.Errorf("error reading line %w", err)
		}

		responseBytes++
		if responseBytes > maxJVMAttachResponseBytes {
			return fmt.Errorf("java VM attach response exceeds %d bytes", maxJVMAttachResponseBytes)
		}
		buf.WriteByte(b)
		switch b {
		case '\n':
			if err := response.parseLine(buf.String()); err != nil {
				return err
			}

			buf.Reset()
		case 0: // j9 terminates with 0
			if err := response.parseLine(buf.String()); err != nil {
				return err
			}
			return response.finish(true)
		}
	}
}

func (i *JavaInjector) jdkAgentAlreadyLoaded(
	ctx context.Context, attacher javaAttacher, pid app.PID,
) (loaded bool, resultErr error) {
	attacher.Init()
	defer func() { resultErr = errors.Join(resultErr, attacher.Cleanup()) }()

	// OpenJ9 doesn't support listing loaded classes
	out, err := attacher.AttachContext(ctx, int(pid), []string{"jcmd", "VM.class_hierarchy"}, true)
	if err != nil {
		i.log.Error("error executing command for the JVM", "pid", pid, "error", err)
		return false, err
	}

	if out == nil {
		return false, nil
	}
	defer func() { resultErr = errors.Join(resultErr, out.Close()) }()
	defer closeOnContext(ctx, out)()

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		s := scanner.Text()
		// We check for io.opentelemetry.obi.java.Agent/0x<address>
		if strings.Contains(s, "io.opentelemetry.obi.java.Agent/0x") {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("read loaded JVM classes: %w", err)
	}

	return false, nil
}

// Hotspot version 8 doesn't support VM.class_hierarchy, we use GC.class_histogram and look for the class itself
// without the address
func (i *JavaInjector) jdkAgentAlreadyLoadedHotspot8(
	ctx context.Context, attacher javaAttacher, pid app.PID,
) (loaded bool, resultErr error) {
	attacher.Init()
	defer func() { resultErr = errors.Join(resultErr, attacher.Cleanup()) }()

	// OpenJ9 doesn't support listing loaded classes
	out, err := attacher.AttachContext(ctx, int(pid), []string{"jcmd", "GC.class_histogram"}, true)
	if err != nil {
		i.log.Error("error executing command for the JVM", "pid", pid, "error", err)
		return false, err
	}

	if out == nil {
		return false, nil
	}
	defer func() { resultErr = errors.Join(resultErr, out.Close()) }()
	defer closeOnContext(ctx, out)()

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		s := scanner.Text()
		// We check for io.opentelemetry.obi.java.Agent
		if strings.Contains(s, "io.opentelemetry.obi.java.Agent") {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("read loaded JVM classes: %w", err)
	}

	return false, nil
}

func (i *JavaInjector) verifyJVMVersion(
	ctx context.Context, attacher javaAttacher, pid app.PID,
) (supported bool, jdk8 bool, resultErr error) {
	attacher.Init()
	defer func() { resultErr = errors.Join(resultErr, attacher.Cleanup()) }()

	// OpenJ9 doesn't support VM.version command
	out, err := attacher.AttachContext(ctx, int(pid), []string{"jcmd", "VM.version"}, true)
	if err != nil {
		i.log.Error("error executing command for the JVM", "pid", pid, "error", err)
		return false, false, err
	}

	if out == nil {
		return true, false, nil
	}
	defer func() { resultErr = errors.Join(resultErr, out.Close()) }()
	defer closeOnContext(ctx, out)()

	scanner := bufio.NewScanner(out)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "JDK ") {
			// JDK 8 is special, failing to properly detect it can cause errors in applications if they are
			// loaded more than once
			return !strings.HasPrefix(line, "JDK 28"), strings.HasPrefix(line, "JDK 8"), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, false, fmt.Errorf("read JVM version: %w", err)
	}

	return false, false, nil
}
