// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	requestVersion     = uint16(3)
	requestSize        = 24
	recordVersion      = uint16(1)
	recordSize         = 64
	operationTake      = byte(1)
	operationDrop      = byte(2)
	operationProbe     = byte(3)
	sourceDirect       = byte(1)
	sourceTask         = byte(2)
	statusValid        = byte(1)
	statusMissing      = byte(2)
	statusStale        = byte(3)
	statusMalformed    = byte(5)
	statusOverload     = byte(11)
	requestTimeout     = 500 * time.Millisecond
	timeoutDelay       = 200 * time.Millisecond
	maxTakeRequests    = uint32(10_000)
	maxMatchingTakes   = uint64(1_000)
	maxInflightLimit   = uint64(1_024)
	maxDrainTimeout    = 30 * time.Second
	maxRequestTimeout  = 30 * time.Second
	maxTimeoutDelay    = 30 * time.Second
	defaultInflight    = uint64(64)
	defaultDrain       = time.Second
	defaultFaultMode   = "alternating"
	summaryVersion     = 1
	summaryKind        = "fault_bridge_final"
	maxSummaryBytes    = 4 * 1024
	maxTempAttempts    = 16
	linuxATEmptyPath   = 0x1000
	maxLogEntries      = int(maxTakeRequests) + 2
	maxLogMessageBytes = 1024
	logDrainTimeout    = 25 * time.Millisecond
	forcedDrainGrace   = 100 * time.Millisecond

	exitSignalDrained         = "signal_drained"
	exitRequestLimitReached   = "request_limit_reached"
	exitInflightLimitExceeded = "inflight_limit_exceeded"
	exitMalformedRequest      = "malformed_request"
	exitPartialRequest        = "partial_request"
	exitTransportError        = "transport_error"
	exitDrainTimeout          = "drain_timeout"
	exitStartupError          = "startup_error"
	exitSocketCleanupError    = "socket_cleanup_error"
)

type faultRequestStage uint8

const (
	faultRequestPreParse faultRequestStage = iota + 1
	faultRequestResponsePending
	faultRequestTerminal
)

type faultServer struct {
	mode               string
	matchingValidTakes uint64
	maxRequests        uint64
	maxInflight        uint64
	requestTimeout     time.Duration
	timeoutDelay       time.Duration
	drainTimeout       time.Duration
	stdout             io.Writer
	stderr             io.Writer
	takes              atomic.Uint32

	mu                    sync.Mutex
	acceptedRequests      uint64
	admissionRejections   uint64
	malformedRequests     uint64
	partialRequests       uint64
	transportErrors       uint64
	acceptTransportErrors uint64
	drainCancellations    uint64
	socketCleanupErrors   uint64
	parsedOperations      faultOperationCounts
	responses             faultResponseCounts
	withheldTimeouts      uint64
	inflight              uint64
	observedMaxInflight   uint64
	active                map[*net.UnixConn]faultActiveRequest
	fatalClassification   string
	fatalError            error

	diagnostics *faultDiagnostics

	beforeRequestParse   func()
	afterResponsePlanned func()
	beforeRequestRelease func()
	beforeSocketCleanup  func()
	acceptUnix           func(*net.UnixListener) (*net.UnixConn, error)
}

type faultActiveRequest struct {
	stage          faultRequestStage
	responseStatus string
}

type faultLogEntry struct {
	writer  io.Writer
	message string
}

type faultDiagnostics struct {
	stdout io.Writer
	stderr io.Writer

	mu     sync.Mutex
	queue  chan faultLogEntry
	done   chan struct{}
	closed bool
}

type faultDiagnosticWriter struct {
	diagnostics *faultDiagnostics
	writer      io.Writer
}

type faultResponse struct {
	payload []byte
	status  string
	delay   time.Duration
}

type faultRequest struct {
	operation byte
	source    byte
}

type faultOperationCounts struct {
	Discard   uint64 `json:"discard"`
	Negotiate uint64 `json:"negotiate"`
	Take      uint64 `json:"take"`
}

type faultResponseCounts struct {
	BadMagic        uint64 `json:"bad_magic"`
	BadSize         uint64 `json:"bad_size"`
	Disconnect      uint64 `json:"disconnect"`
	Malformed       uint64 `json:"malformed"`
	Missing         uint64 `json:"missing"`
	Overload        uint64 `json:"overload"`
	Stale           uint64 `json:"stale"`
	Timeout         uint64 `json:"timeout"`
	Truncated       uint64 `json:"truncated"`
	Valid           uint64 `json:"valid"`
	VersionMismatch uint64 `json:"version_mismatch"`
	ZeroSpanID      uint64 `json:"zero_span_id"`
	ZeroTraceID     uint64 `json:"zero_trace_id"`
}

type faultSummaryLimits struct {
	DrainTimeoutNS   int64  `json:"drain_timeout_ns"`
	MaxInflight      uint64 `json:"max_inflight"`
	MaxRequests      uint64 `json:"max_requests"`
	RequestTimeoutNS int64  `json:"request_timeout_ns"`
	TimeoutDelayNS   int64  `json:"timeout_delay_ns"`
}

type faultUnresolvedRequests struct {
	PreParse         uint64              `json:"pre_parse"`
	PendingResponses faultResponseCounts `json:"pending_responses"`
	Terminal         uint64              `json:"terminal"`
}

type faultSummary struct {
	SchemaVersion         int                     `json:"schema_version"`
	Kind                  string                  `json:"kind"`
	Mode                  string                  `json:"mode"`
	MatchingValidTakes    uint64                  `json:"matching_valid_takes"`
	Limits                faultSummaryLimits      `json:"limits"`
	StartedAt             string                  `json:"started_at"`
	FinishedAt            string                  `json:"finished_at"`
	ExitClassification    string                  `json:"exit_classification"`
	AcceptedRequests      uint64                  `json:"accepted_requests"`
	ParsedOperations      faultOperationCounts    `json:"parsed_operations"`
	Responses             faultResponseCounts     `json:"responses"`
	WithheldTimeouts      uint64                  `json:"withheld_timeouts"`
	AdmissionRejections   uint64                  `json:"admission_rejections"`
	MalformedRequests     uint64                  `json:"malformed_requests"`
	PartialRequests       uint64                  `json:"partial_requests"`
	TransportErrors       uint64                  `json:"transport_errors"`
	AcceptTransportErrors uint64                  `json:"accept_transport_errors"`
	DrainCancellations    uint64                  `json:"drain_cancellations"`
	SocketCleanupErrors   uint64                  `json:"socket_cleanup_errors"`
	MaxInflight           uint64                  `json:"max_inflight"`
	FinalInflight         uint64                  `json:"final_inflight"`
	UnresolvedRequests    faultUnresolvedRequests `json:"unresolved_requests"`
}

type faultBridgeRunHooks struct {
	configureServer func(*faultServer)
	publish         faultSummaryPublishHooks
}

func main() {
	os.Exit(mainExitCode())
}

func mainExitCode() int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return runFaultBridge(ctx, os.Args[1:], os.Stdout, os.Stderr)
}

func runFaultBridge(ctx context.Context, arguments []string, stdout, stderr io.Writer) int {
	return runFaultBridgeWithHooks(
		ctx, arguments, stdout, stderr, faultBridgeRunHooks{},
	)
}

func runFaultBridgeWithHooks(
	ctx context.Context,
	arguments []string,
	stdout, stderr io.Writer,
	hooks faultBridgeRunHooks,
) int {
	diagnostics := newFaultDiagnostics(stdout, stderr)
	defer diagnostics.stop()
	stdout = diagnostics.writer(diagnostics.stdout)
	stderr = diagnostics.writer(diagnostics.stderr)

	var socketPath string
	var summaryPath string
	var mode string
	var matchingValidTakes uint64
	var maxRequests uint64
	var maxInflight uint64
	var drainTimeout time.Duration
	flags := flag.NewFlagSet("fault-bridge", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&socketPath, "socket", "/var/run/obi/java-remote-parent.sock", "Unix socket path")
	flags.StringVar(&summaryPath, "summary", "", "final JSON summary path")
	flags.StringVar(&mode, "mode", environmentOrDefault("FAULT_MODE", defaultFaultMode), "fault mode")
	flags.Uint64Var(&matchingValidTakes, "matching-valid-takes", 1, "valid takes returned by matching mode")
	flags.Uint64Var(&maxRequests, "max-requests", uint64(maxTakeRequests), "accepted request limit")
	flags.Uint64Var(&maxInflight, "max-inflight", defaultInflight, "concurrent request limit")
	flags.DurationVar(&drainTimeout, "drain-timeout", defaultDrain, "shutdown drain limit")
	if err := flags.Parse(arguments); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || !filepath.IsAbs(socketPath) {
		diagnostics.printf(
			diagnostics.stderr,
			"fault bridge requires an absolute --socket and no positional arguments\n",
		)
		return 2
	}
	if summaryPath != "" &&
		(!filepath.IsAbs(summaryPath) || filepath.Clean(summaryPath) != summaryPath ||
			filepath.Clean(summaryPath) == filepath.Clean(socketPath)) {
		diagnostics.printf(
			diagnostics.stderr,
			"fault bridge requires a clean absolute --summary distinct from --socket\n",
		)
		return 2
	}
	if summaryPath != "" && runtime.GOOS != "linux" {
		diagnostics.printf(
			diagnostics.stderr,
			"fault bridge summary publication requires Linux\n",
		)
		return 2
	}
	if !validFaultMode(mode) {
		diagnostics.printf(diagnostics.stderr, "fault bridge mode %q is unsupported\n", mode)
		return 2
	}
	if !validMatchingTakeCount(mode, matchingValidTakes) {
		diagnostics.printf(
			diagnostics.stderr,
			"fault bridge matching-valid-takes must be 1 outside matching mode or between 1 and %d in matching mode\n",
			maxMatchingTakes,
		)
		return 2
	}
	if maxRequests == 0 || maxRequests > uint64(maxTakeRequests) {
		diagnostics.printf(
			diagnostics.stderr,
			"fault bridge max-requests must be between 1 and %d\n",
			maxTakeRequests,
		)
		return 2
	}
	if maxInflight == 0 || maxInflight > maxInflightLimit || maxInflight > maxRequests {
		diagnostics.printf(
			diagnostics.stderr,
			"fault bridge max-inflight must be between 1 and min(max-requests,%d)\n",
			maxInflightLimit,
		)
		return 2
	}
	if drainTimeout <= 0 || drainTimeout > maxDrainTimeout {
		diagnostics.printf(
			diagnostics.stderr,
			"fault bridge drain-timeout must be greater than zero and at most %s\n",
			maxDrainTimeout,
		)
		return 2
	}
	if summaryPath != "" {
		if err := prepareSummaryPath(summaryPath); err != nil {
			diagnostics.printf(diagnostics.stderr, "fault bridge failed: %v\n", err)
			return 1
		}
	}

	startedAt := time.Now().UTC()
	server := &faultServer{
		mode:               mode,
		matchingValidTakes: matchingValidTakes,
		maxRequests:        maxRequests,
		maxInflight:        maxInflight,
		requestTimeout:     requestTimeout,
		timeoutDelay:       timeoutDelay,
		drainTimeout:       drainTimeout,
		stdout:             stdout,
		stderr:             stderr,
		active:             make(map[*net.UnixConn]faultActiveRequest),
		diagnostics:        diagnostics,
	}
	if hooks.configureServer != nil {
		hooks.configureServer(server)
	}
	classification, serveErr := serve(ctx, socketPath, server)
	finishedAt := time.Now().UTC()
	summary := server.summary(startedAt, finishedAt, classification)
	if summaryPath != "" {
		if err := writeFaultSummaryWithHooks(summaryPath, summary, hooks.publish); err != nil {
			diagnostics.printf(
				diagnostics.stderr,
				"fault bridge failed to publish summary: %v\n",
				err,
			)
			return 1
		}
	}
	if serveErr != nil {
		diagnostics.printf(diagnostics.stderr, "fault bridge failed: %v\n", serveErr)
		return 1
	}
	return 0
}

func serve(
	ctx context.Context,
	socketPath string,
	server *faultServer,
) (classification string, returnedErr error) {
	server.setDefaults()
	if ctx.Err() != nil {
		return exitSignalDrained, nil
	}
	socketLease, err := prepareSocketPath(socketPath)
	if err != nil {
		return exitStartupError, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return exitStartupError, errors.Join(
			fmt.Errorf("listen: %w", err), socketLease.closeDirectory(),
		)
	}
	// UnixListener otherwise unlinks its pathname on Close without checking that
	// the pathname still identifies the socket created by this process.
	listener.SetUnlinkOnClose(false)
	if err := socketLease.captureCreatedSocket(); err != nil {
		cleanupErr := socketLease.close(listener)
		if !socketLease.createdKnown {
			cleanupErr = errors.Join(
				cleanupErr,
				errors.New("created socket cleanup identity is unavailable"),
			)
		}
		if cleanupErr != nil {
			server.recordSocketCleanupError()
		}
		return exitStartupError, errors.Join(err, cleanupErr)
	}
	defer func() {
		if server.beforeSocketCleanup != nil {
			server.beforeSocketCleanup()
		}
		cleanupErr := socketLease.close(listener)
		if cleanupErr == nil {
			return
		}
		server.recordSocketCleanupError()
		if returnedErr == nil {
			classification = exitSocketCleanupError
		}
		returnedErr = errors.Join(returnedErr, cleanupErr)
	}()
	if server.diagnostics == nil {
		server.diagnostics = newFaultDiagnostics(server.stdout, server.stderr)
		defer server.diagnostics.stop()
	}

	var handlers sync.WaitGroup
	handlerCtx, cancelHandlers := context.WithCancel(context.Background())
	defer cancelHandlers()
	var admissionOnce sync.Once
	var admissionMu sync.Mutex
	admissionReason := ""
	stopAdmission := func(reason string) {
		admissionOnce.Do(func() {
			admissionMu.Lock()
			admissionReason = reason
			admissionMu.Unlock()
			_ = listener.Close()
		})
	}
	currentAdmissionReason := func() string {
		admissionMu.Lock()
		defer admissionMu.Unlock()
		return admissionReason
	}

	contextWatcherDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			stopAdmission(exitSignalDrained)
		case <-contextWatcherDone:
		}
	}()
	defer close(contextWatcherDone)
	server.logf(
		"fault bridge ready socket=%s mode=%s matching_valid_takes=%d max_requests=%d max_inflight=%d\n",
		socketPath,
		server.mode,
		server.matchingValidTakes,
		server.maxRequests,
		server.maxInflight,
	)

	for {
		connection, err := server.acceptConnection(listener)
		if err != nil {
			if currentAdmissionReason() != "" || errors.Is(err, net.ErrClosed) {
				break
			}
			server.recordAcceptTransportError()
			server.recordFatal(exitTransportError, fmt.Errorf("accept: %w", err))
			stopAdmission(exitTransportError)
			break
		}
		if ctx.Err() != nil {
			server.rejectAdmission()
			_ = connection.Close()
			stopAdmission(exitSignalDrained)
			break
		}
		accepted, admitted := server.admit(connection)
		if !admitted {
			_ = connection.Close()
			limitErr := fmt.Errorf("concurrent request limit %d reached", server.maxInflight)
			server.recordFatal(exitInflightLimitExceeded, limitErr)
			stopAdmission(exitInflightLimitExceeded)
			break
		}
		handlers.Add(1)
		go func(connection *net.UnixConn) {
			defer handlers.Done()
			defer func() {
				_ = connection.Close()
				server.release(connection)
			}()
			defer func() {
				if server.beforeRequestRelease != nil {
					server.beforeRequestRelease()
				}
			}()
			classification, handleErr := handle(handlerCtx, connection, server)
			if handleErr == nil || errors.Is(handleErr, context.Canceled) {
				return
			}
			if server.mode == "matching" {
				handleErr = fmt.Errorf("handle matching request: %w", handleErr)
			}
			if server.recordFatal(classification, handleErr) {
				server.errorf("fault bridge request rejected: %v\n", handleErr)
				stopAdmission(classification)
			}
		}(connection)
		if accepted == server.maxRequests {
			stopAdmission(exitRequestLimitReached)
			break
		}
	}

	if server.inflightCount() != 0 {
		drained := make(chan struct{})
		go func() {
			handlers.Wait()
			close(drained)
		}()
		timer := time.NewTimer(server.drainTimeout)
		select {
		case <-drained:
			timer.Stop()
		case <-timer.C:
			if server.inflightCount() == 0 {
				break
			}
			cancelHandlers()
			server.closeActive()
			forcedTimer := time.NewTimer(forcedDrainGrace)
			select {
			case <-drained:
				forcedTimer.Stop()
			case <-forcedTimer.C:
				if server.inflightCount() != 0 {
					return exitDrainTimeout, fmt.Errorf(
						"request drain exceeded %s and forced shutdown exceeded %s",
						server.drainTimeout,
						forcedDrainGrace,
					)
				}
			}
			return exitDrainTimeout, fmt.Errorf(
				"request drain exceeded %s", server.drainTimeout,
			)
		}
	}

	if classification, fatalErr := server.fatal(); fatalErr != nil {
		return classification, fatalErr
	}
	classification = currentAdmissionReason()
	if classification == "" {
		classification = exitSignalDrained
	}
	return classification, nil
}

type faultSocketLease struct {
	directory     *os.File
	directoryInfo os.FileInfo
	directoryPath string
	name          string
	created       unix.Stat_t
	createdKnown  bool
	closed        bool
}

func prepareSocketPath(socketPath string) (*faultSocketLease, error) {
	directoryPath := filepath.Dir(socketPath)
	directory, err := os.Open(directoryPath)
	if err != nil {
		return nil, fmt.Errorf("open socket directory: %w", err)
	}
	lease := &faultSocketLease{
		directory:     directory,
		directoryPath: directoryPath,
		name:          filepath.Base(socketPath),
	}
	fail := func(cause error) (*faultSocketLease, error) {
		return nil, errors.Join(cause, lease.closeDirectory())
	}
	directoryInfo, err := directory.Stat()
	if err != nil {
		return fail(fmt.Errorf("inspect socket directory: %w", err))
	}
	lease.directoryInfo = directoryInfo
	if err := revalidateSocketDirectory(directoryPath, directoryInfo); err != nil {
		return fail(err)
	}

	var stale unix.Stat_t
	err = unix.Fstatat(
		int(directory.Fd()), lease.name, &stale, unix.AT_SYMLINK_NOFOLLOW,
	)
	if errors.Is(err, unix.ENOENT) {
		return lease, nil
	}
	if err != nil {
		return fail(fmt.Errorf("inspect socket path: %w", err))
	}
	if err := validateOwnedSocketStat(stale); err != nil {
		return fail(fmt.Errorf("refusing to replace socket path %q: %w", socketPath, err))
	}
	if err := unlinkSocketFile(int(directory.Fd()), lease.name, stale); err != nil {
		return fail(fmt.Errorf("remove stale socket: %w", err))
	}
	if err := revalidateSocketDirectory(directoryPath, directoryInfo); err != nil {
		return fail(err)
	}
	return lease, nil
}

func (l *faultSocketLease) captureCreatedSocket() error {
	if err := revalidateSocketDirectory(l.directoryPath, l.directoryInfo); err != nil {
		return err
	}
	if err := unix.Fstatat(
		int(l.directory.Fd()), l.name, &l.created, unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return fmt.Errorf("inspect created socket: %w", err)
	}
	if err := validateOwnedSocketStat(l.created); err != nil {
		return fmt.Errorf("validate created socket: %w", err)
	}
	l.createdKnown = true
	if err := unix.Fchmodat(int(l.directory.Fd()), l.name, 0o660, 0); err != nil {
		return fmt.Errorf("set socket permissions: %w", err)
	}
	var current unix.Stat_t
	if err := unix.Fstatat(
		int(l.directory.Fd()), l.name, &current, unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return fmt.Errorf("reinspect created socket: %w", err)
	}
	if !sameSocketFile(l.created, current) {
		return errors.New("created socket identity changed")
	}
	if err := validateOwnedSocketStat(current); err != nil {
		return fmt.Errorf("revalidate created socket: %w", err)
	}
	if current.Mode&0o777 != 0o660 {
		return errors.New("created socket permissions are not canonical")
	}
	l.created = current
	return revalidateSocketDirectory(l.directoryPath, l.directoryInfo)
}

func (l *faultSocketLease) close(listener *net.UnixListener) error {
	var cleanupErrors []error
	if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		cleanupErrors = append(cleanupErrors, fmt.Errorf("close socket listener: %w", err))
	}
	if l.createdKnown {
		if err := unlinkSocketFile(int(l.directory.Fd()), l.name, l.created); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("remove created socket: %w", err))
		}
	}
	if err := l.closeDirectory(); err != nil {
		cleanupErrors = append(cleanupErrors, err)
	}
	return errors.Join(cleanupErrors...)
}

func (l *faultSocketLease) closeDirectory() error {
	if l == nil || l.directory == nil || l.closed {
		return nil
	}
	l.closed = true
	if err := l.directory.Close(); err != nil {
		return fmt.Errorf("close socket directory: %w", err)
	}
	return nil
}

func revalidateSocketDirectory(path string, expected os.FileInfo) error {
	current, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("reinspect socket directory: %w", err)
	}
	if !current.IsDir() || !os.SameFile(expected, current) {
		return errors.New("socket directory identity changed")
	}
	return validateSocketDirectoryStat(current)
}

func validateSocketDirectoryStat(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("socket directory ownership is unavailable")
	}
	// Same-EUID processes and root are trusted. Excluding group/other writers makes
	// the descriptor-bound identity checks meaningful for every weaker principal.
	if stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf(
			"socket directory must be owned by effective user %d and not group/other writable, got owner %d mode %#o",
			os.Geteuid(),
			stat.Uid,
			info.Mode().Perm(),
		)
	}
	return nil
}

func validateOpenSocketDirectory(directoryFD int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(directoryFD, &stat); err != nil {
		return fmt.Errorf("inspect open socket directory: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) ||
		stat.Mode&0o022 != 0 {
		return errors.New("open socket directory is no longer owned and protected from group/other writes")
	}
	return nil
}

func validateOwnedSocketStat(stat unix.Stat_t) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return errors.New("path is not a socket")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("socket owner %d is not effective user %d", stat.Uid, os.Geteuid())
	}
	return nil
}

func sameSocketFile(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino &&
		left.Mode&unix.S_IFMT == right.Mode&unix.S_IFMT
}

func unlinkSocketFile(directoryFD int, name string, expected unix.Stat_t) error {
	if err := validateOpenSocketDirectory(directoryFD); err != nil {
		return err
	}
	var current unix.Stat_t
	if err := unix.Fstatat(directoryFD, name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	if !sameSocketFile(expected, current) {
		return errors.New("refusing to unlink changed socket file")
	}
	return unix.Unlinkat(directoryFD, name, 0)
}

func prepareSummaryPath(summaryPath string) error {
	_, err := os.Lstat(summaryPath)
	if errors.Is(err, os.ErrNotExist) {
		return validateSummaryParentPath(filepath.Dir(summaryPath))
	}
	if err != nil {
		return fmt.Errorf("inspect summary path: %w", err)
	}
	return fmt.Errorf("refusing to replace existing summary path %q", summaryPath)
}

func validateSummaryParentPath(directoryPath string) error {
	directory, err := os.Open(directoryPath)
	if err != nil {
		return fmt.Errorf("open summary directory: %w", err)
	}
	defer directory.Close()
	directoryInfo, err := directory.Stat()
	if err != nil {
		return fmt.Errorf("inspect summary directory: %w", err)
	}
	if !directoryInfo.IsDir() {
		return errors.New("summary parent is not a directory")
	}
	return revalidateSummaryDirectory(directoryPath, directoryInfo)
}

func (s *faultServer) setDefaults() {
	if s.maxRequests == 0 {
		s.maxRequests = uint64(maxTakeRequests)
	}
	if s.maxInflight == 0 {
		s.maxInflight = defaultInflight
	}
	if s.requestTimeout == 0 {
		s.requestTimeout = requestTimeout
	}
	if s.timeoutDelay == 0 {
		s.timeoutDelay = timeoutDelay
	}
	if s.drainTimeout == 0 {
		s.drainTimeout = defaultDrain
	}
	if s.stdout == nil {
		s.stdout = io.Discard
	}
	if s.stderr == nil {
		s.stderr = io.Discard
	}
	if s.active == nil {
		s.active = make(map[*net.UnixConn]faultActiveRequest)
	}
}

func (s *faultServer) acceptConnection(
	listener *net.UnixListener,
) (*net.UnixConn, error) {
	if s.acceptUnix != nil {
		return s.acceptUnix(listener)
	}
	return listener.AcceptUnix()
}

func (s *faultServer) admit(connection *net.UnixConn) (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acceptedRequests++
	accepted := s.acceptedRequests
	if s.inflight >= s.maxInflight {
		s.admissionRejections++
		return accepted, false
	}
	s.inflight++
	if s.inflight > s.observedMaxInflight {
		s.observedMaxInflight = s.inflight
	}
	s.active[connection] = faultActiveRequest{stage: faultRequestPreParse}
	return accepted, true
}

func (s *faultServer) rejectAdmission() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acceptedRequests++
	s.admissionRejections++
}

func (s *faultServer) release(connection *net.UnixConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	active, present := s.active[connection]
	if !present || active.stage != faultRequestTerminal || s.inflight == 0 {
		panic("fault bridge released an inactive connection")
	}
	delete(s.active, connection)
	s.inflight--
}

func (s *faultServer) closeActive() {
	s.mu.Lock()
	connections := make([]*net.UnixConn, 0, len(s.active))
	for connection := range s.active {
		connections = append(connections, connection)
	}
	s.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}

func (s *faultServer) inflightCount() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inflight
}

func (s *faultServer) planResponse(
	connection *net.UnixConn,
	request faultRequest,
) faultResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	active := s.requireActiveStage(connection, faultRequestPreParse)
	switch request.operation {
	case operationTake:
		s.parsedOperations.Take++
	case operationDrop:
		s.parsedOperations.Discard++
	case operationProbe:
		s.parsedOperations.Negotiate++
	default:
		panic("parsed fault bridge operation became invalid")
	}
	response := s.response(request.operation, request.source)
	active.stage = faultRequestResponsePending
	active.responseStatus = response.status
	s.active[connection] = active
	return response
}

func (s *faultServer) recordResponse(connection *net.UnixConn, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	active := s.requireActiveStage(connection, faultRequestResponsePending)
	if active.responseStatus != status {
		panic("fault bridge response status changed after planning")
	}
	incrementResponseCount(&s.responses, status)
	if status == "timeout" {
		s.withheldTimeouts++
	}
	active.stage = faultRequestTerminal
	s.active[connection] = active
}

func incrementResponseCount(responses *faultResponseCounts, status string) {
	switch status {
	case "bad-magic":
		responses.BadMagic++
	case "bad-size":
		responses.BadSize++
	case "disconnect":
		responses.Disconnect++
	case "malformed":
		responses.Malformed++
	case "missing":
		responses.Missing++
	case "overload":
		responses.Overload++
	case "stale":
		responses.Stale++
	case "timeout":
		responses.Timeout++
	case "truncated":
		responses.Truncated++
	case "valid":
		responses.Valid++
	case "version-mismatch":
		responses.VersionMismatch++
	case "zero-span-id":
		responses.ZeroSpanID++
	case "zero-trace-id":
		responses.ZeroTraceID++
	default:
		panic("fault bridge response status became invalid")
	}
}

func (s *faultServer) recordCanceledResponse(connection *net.UnixConn, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	active := s.requireActiveStage(connection, faultRequestResponsePending)
	if status != "timeout" || active.responseStatus != status {
		panic("fault bridge canceled a non-timeout response")
	}
	s.drainCancellations++
	active.stage = faultRequestTerminal
	s.active[connection] = active
}

func (s *faultServer) recordMalformedRequest(connection *net.UnixConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	active := s.requireActiveStage(connection, faultRequestPreParse)
	s.malformedRequests++
	active.stage = faultRequestTerminal
	s.active[connection] = active
}

func (s *faultServer) recordPartialRequest(connection *net.UnixConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	active := s.requireActiveStage(connection, faultRequestPreParse)
	s.partialRequests++
	s.transportErrors++
	active.stage = faultRequestTerminal
	s.active[connection] = active
}

func (s *faultServer) recordWriteTransportError(connection *net.UnixConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	active := s.requireActiveStage(connection, faultRequestResponsePending)
	s.transportErrors++
	active.stage = faultRequestTerminal
	s.active[connection] = active
}

func (s *faultServer) recordAcceptTransportError() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.transportErrors++
	s.acceptTransportErrors++
}

func (s *faultServer) recordSocketCleanupError() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.socketCleanupErrors++
}

func (s *faultServer) requireActiveStage(
	connection *net.UnixConn,
	expected faultRequestStage,
) faultActiveRequest {
	active, ok := s.active[connection]
	if !ok || active.stage != expected {
		panic("fault bridge request lifecycle became invalid")
	}
	return active
}

func (s *faultServer) recordFatal(classification string, err error) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fatalError != nil {
		return false
	}
	s.fatalClassification = classification
	s.fatalError = err
	return true
}

func (s *faultServer) fatal() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fatalClassification, s.fatalError
}

func (s *faultServer) logRequest(request faultRequest, status string) {
	s.logf(
		"fault bridge operation=%s status=%s take_count=%d source=%s\n",
		operationName(request.operation), status, s.takes.Load(), sourceName(request.source),
	)
}

func (s *faultServer) logf(format string, arguments ...any) {
	if s.diagnostics != nil {
		s.diagnostics.printf(s.diagnostics.stdout, format, arguments...)
	}
}

func (s *faultServer) errorf(format string, arguments ...any) {
	if s.diagnostics != nil {
		s.diagnostics.printf(s.diagnostics.stderr, format, arguments...)
	}
}

func newFaultDiagnostics(stdout, stderr io.Writer) *faultDiagnostics {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	diagnostics := &faultDiagnostics{
		stdout: stdout,
		stderr: stderr,
		queue:  make(chan faultLogEntry, maxLogEntries),
		done:   make(chan struct{}),
	}
	// This goroutine is the only place that may call an external diagnostic
	// writer. Producers only retain bounded messages in the bounded queue.
	go func(queue <-chan faultLogEntry, done chan<- struct{}) {
		defer close(done)
		for entry := range queue {
			_, _ = io.WriteString(entry.writer, entry.message)
		}
	}(diagnostics.queue, diagnostics.done)
	return diagnostics
}

func (d *faultDiagnostics) stop() {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	close(d.queue)
	d.mu.Unlock()
	timer := time.NewTimer(logDrainTimeout)
	defer timer.Stop()
	select {
	case <-d.done:
	case <-timer.C:
	}
}

func (d *faultDiagnostics) writer(writer io.Writer) io.Writer {
	return faultDiagnosticWriter{diagnostics: d, writer: writer}
}

func (w faultDiagnosticWriter) Write(payload []byte) (int, error) {
	w.diagnostics.enqueue(w.writer, boundedDiagnosticMessage(payload))
	return len(payload), nil
}

func (d *faultDiagnostics) printf(writer io.Writer, format string, arguments ...any) {
	boundedArguments := make([]any, len(arguments))
	for index, argument := range arguments {
		switch value := argument.(type) {
		case string:
			boundedArguments[index] = boundedDiagnosticText(value)
		case error:
			boundedArguments[index] = boundedDiagnosticText(value.Error())
		default:
			boundedArguments[index] = argument
		}
	}
	var message bytes.Buffer
	limited := &boundedDiagnosticBuffer{buffer: &message, remaining: maxLogMessageBytes}
	_, _ = fmt.Fprintf(limited, format, boundedArguments...)
	d.enqueue(writer, message.String())
}

func (d *faultDiagnostics) enqueue(writer io.Writer, message string) {
	message = strings.Clone(message[:min(len(message), maxLogMessageBytes)])
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	select {
	case d.queue <- faultLogEntry{writer: writer, message: message}:
	default:
	}
}

type boundedDiagnosticBuffer struct {
	buffer    *bytes.Buffer
	remaining int
}

func (w *boundedDiagnosticBuffer) Write(payload []byte) (int, error) {
	written := len(payload)
	if w.remaining == 0 {
		return written, nil
	}
	retained := min(len(payload), w.remaining)
	_, _ = w.buffer.Write(payload[:retained])
	w.remaining -= retained
	return written, nil
}

func boundedDiagnosticMessage(payload []byte) string {
	return string(payload[:min(len(payload), maxLogMessageBytes)])
}

func boundedDiagnosticText(value string) string {
	return value[:min(len(value), maxLogMessageBytes)]
}

func (s *faultServer) summary(startedAt, finishedAt time.Time, classification string) faultSummary {
	s.mu.Lock()
	defer s.mu.Unlock()
	var unresolved faultUnresolvedRequests
	for _, active := range s.active {
		switch active.stage {
		case faultRequestPreParse:
			unresolved.PreParse++
		case faultRequestResponsePending:
			incrementResponseCount(&unresolved.PendingResponses, active.responseStatus)
		case faultRequestTerminal:
			unresolved.Terminal++
		default:
			panic("fault bridge request lifecycle became invalid")
		}
	}
	if uint64(len(s.active)) != s.inflight {
		panic("fault bridge active request count became invalid")
	}
	return faultSummary{
		SchemaVersion:      summaryVersion,
		Kind:               summaryKind,
		Mode:               s.mode,
		MatchingValidTakes: s.matchingValidTakes,
		Limits: faultSummaryLimits{
			DrainTimeoutNS:   s.drainTimeout.Nanoseconds(),
			MaxInflight:      s.maxInflight,
			MaxRequests:      s.maxRequests,
			RequestTimeoutNS: s.requestTimeout.Nanoseconds(),
			TimeoutDelayNS:   s.timeoutDelay.Nanoseconds(),
		},
		StartedAt:             startedAt.UTC().Format(time.RFC3339Nano),
		FinishedAt:            finishedAt.UTC().Format(time.RFC3339Nano),
		ExitClassification:    classification,
		AcceptedRequests:      s.acceptedRequests,
		ParsedOperations:      s.parsedOperations,
		Responses:             s.responses,
		WithheldTimeouts:      s.withheldTimeouts,
		AdmissionRejections:   s.admissionRejections,
		MalformedRequests:     s.malformedRequests,
		PartialRequests:       s.partialRequests,
		TransportErrors:       s.transportErrors,
		AcceptTransportErrors: s.acceptTransportErrors,
		DrainCancellations:    s.drainCancellations,
		SocketCleanupErrors:   s.socketCleanupErrors,
		MaxInflight:           s.observedMaxInflight,
		FinalInflight:         s.inflight,
		UnresolvedRequests:    unresolved,
	}
}

func validateFaultSummary(summary faultSummary) error {
	if summary.SchemaVersion != summaryVersion || summary.Kind != summaryKind {
		return errors.New("invalid fault bridge summary identity")
	}
	if !validFaultMode(summary.Mode) ||
		!validMatchingTakeCount(summary.Mode, summary.MatchingValidTakes) {
		return errors.New("invalid fault bridge summary mode")
	}
	limits := summary.Limits
	if limits.MaxRequests == 0 || limits.MaxRequests > uint64(maxTakeRequests) ||
		limits.MaxInflight == 0 || limits.MaxInflight > maxInflightLimit ||
		limits.MaxInflight > limits.MaxRequests || limits.RequestTimeoutNS <= 0 ||
		limits.RequestTimeoutNS > maxRequestTimeout.Nanoseconds() ||
		limits.TimeoutDelayNS <= 0 || limits.TimeoutDelayNS > maxTimeoutDelay.Nanoseconds() ||
		limits.DrainTimeoutNS <= 0 ||
		limits.DrainTimeoutNS > maxDrainTimeout.Nanoseconds() {
		return errors.New("invalid fault bridge summary limits")
	}
	startedAt, err := time.Parse(time.RFC3339Nano, summary.StartedAt)
	if err != nil || startedAt.IsZero() || startedAt.Location() != time.UTC ||
		summary.StartedAt != startedAt.UTC().Format(time.RFC3339Nano) {
		return errors.New("invalid fault bridge summary start time")
	}
	finishedAt, err := time.Parse(time.RFC3339Nano, summary.FinishedAt)
	if err != nil || finishedAt.IsZero() || finishedAt.Location() != time.UTC ||
		summary.FinishedAt != finishedAt.UTC().Format(time.RFC3339Nano) ||
		finishedAt.Before(startedAt) {
		return errors.New("invalid fault bridge summary finish time")
	}
	if !validExitClassification(summary.ExitClassification) {
		return errors.New("invalid fault bridge summary exit classification")
	}
	parsed, parsedOK := boundedCountTotal(
		summary.AcceptedRequests,
		summary.ParsedOperations.Discard,
		summary.ParsedOperations.Negotiate,
		summary.ParsedOperations.Take,
	)
	responses, responsesOK := boundedCountTotal(
		summary.AcceptedRequests,
		summary.Responses.BadMagic,
		summary.Responses.BadSize,
		summary.Responses.Disconnect,
		summary.Responses.Malformed,
		summary.Responses.Missing,
		summary.Responses.Overload,
		summary.Responses.Stale,
		summary.Responses.Timeout,
		summary.Responses.Truncated,
		summary.Responses.Valid,
		summary.Responses.VersionMismatch,
		summary.Responses.ZeroSpanID,
		summary.Responses.ZeroTraceID,
	)
	pending := summary.UnresolvedRequests.PendingResponses
	pendingTotal, pendingOK := boundedCountTotal(
		summary.AcceptedRequests,
		pending.BadMagic,
		pending.BadSize,
		pending.Disconnect,
		pending.Malformed,
		pending.Missing,
		pending.Overload,
		pending.Stale,
		pending.Timeout,
		pending.Truncated,
		pending.Valid,
		pending.VersionMismatch,
		pending.ZeroSpanID,
		pending.ZeroTraceID,
	)
	accountedResponses := addResponseCounts(summary.Responses, pending)
	if summary.AcceptedRequests > limits.MaxRequests ||
		summary.MaxInflight > limits.MaxInflight ||
		summary.FinalInflight > limits.MaxInflight ||
		!parsedOK || !responsesOK || !pendingOK ||
		summary.AdmissionRejections > 1 ||
		summary.AdmissionRejections > summary.AcceptedRequests ||
		(summary.AdmissionRejections != 0 && summary.AcceptTransportErrors != 0) ||
		summary.MalformedRequests > summary.AcceptedRequests ||
		summary.PartialRequests > summary.AcceptedRequests ||
		summary.AcceptTransportErrors > 1 ||
		(summary.AcceptTransportErrors != 0 &&
			summary.AcceptedRequests >= limits.MaxRequests) ||
		summary.TransportErrors <
			summary.PartialRequests+summary.AcceptTransportErrors ||
		summary.TransportErrors >
			summary.AcceptedRequests+summary.AcceptTransportErrors ||
		summary.DrainCancellations > summary.AcceptedRequests ||
		summary.SocketCleanupErrors > 1 ||
		summary.UnresolvedRequests.PreParse > summary.AcceptedRequests ||
		summary.UnresolvedRequests.Terminal > summary.AcceptedRequests ||
		parsed+summary.MalformedRequests+summary.PartialRequests+
			summary.AdmissionRejections+summary.UnresolvedRequests.PreParse !=
			summary.AcceptedRequests ||
		responses+pendingTotal > parsed ||
		summary.WithheldTimeouts != summary.Responses.Timeout ||
		!validResponseCounts(
			summary.Mode,
			summary.MatchingValidTakes,
			summary.ParsedOperations,
			accountedResponses,
		) {
		return errors.New("invalid fault bridge summary counters")
	}
	if !validResponseDeficit(summary, parsed, responses, pendingTotal) {
		return errors.New("invalid fault bridge summary response deficit")
	}
	admitted := summary.AcceptedRequests - summary.AdmissionRejections
	if admitted == 0 && summary.MaxInflight != 0 ||
		admitted > 0 && (summary.MaxInflight == 0 || summary.MaxInflight > admitted) ||
		summary.FinalInflight > admitted ||
		summary.FinalInflight > summary.MaxInflight ||
		summary.UnresolvedRequests.PreParse+pendingTotal+
			summary.UnresolvedRequests.Terminal != summary.FinalInflight {
		return errors.New("invalid fault bridge summary concurrency")
	}
	if err := validateExitSummary(summary, parsed, responses); err != nil {
		return err
	}
	return nil
}

func boundedCountTotal(limit uint64, values ...uint64) (uint64, bool) {
	var total uint64
	for _, value := range values {
		if value > limit {
			return 0, false
		}
		total += value
	}
	return total, total <= limit
}

func validResponseCounts(
	mode string,
	matchingValidTakes uint64,
	operations faultOperationCounts,
	responses faultResponseCounts,
) bool {
	expected, ok := expectedResponseCounts(mode, matchingValidTakes, operations)
	if !ok {
		return false
	}
	return responses.BadMagic <= expected.BadMagic &&
		responses.BadSize <= expected.BadSize &&
		responses.Disconnect <= expected.Disconnect &&
		responses.Malformed <= expected.Malformed &&
		responses.Missing <= expected.Missing &&
		responses.Overload <= expected.Overload &&
		responses.Stale <= expected.Stale &&
		responses.Timeout <= expected.Timeout &&
		responses.Truncated <= expected.Truncated &&
		responses.Valid <= expected.Valid &&
		responses.VersionMismatch <= expected.VersionMismatch &&
		responses.ZeroSpanID <= expected.ZeroSpanID &&
		responses.ZeroTraceID <= expected.ZeroTraceID
}

func addResponseCounts(left, right faultResponseCounts) faultResponseCounts {
	return faultResponseCounts{
		BadMagic:        left.BadMagic + right.BadMagic,
		BadSize:         left.BadSize + right.BadSize,
		Disconnect:      left.Disconnect + right.Disconnect,
		Malformed:       left.Malformed + right.Malformed,
		Missing:         left.Missing + right.Missing,
		Overload:        left.Overload + right.Overload,
		Stale:           left.Stale + right.Stale,
		Timeout:         left.Timeout + right.Timeout,
		Truncated:       left.Truncated + right.Truncated,
		Valid:           left.Valid + right.Valid,
		VersionMismatch: left.VersionMismatch + right.VersionMismatch,
		ZeroSpanID:      left.ZeroSpanID + right.ZeroSpanID,
		ZeroTraceID:     left.ZeroTraceID + right.ZeroTraceID,
	}
}

func expectedResponseCounts(
	mode string,
	matchingValidTakes uint64,
	operations faultOperationCounts,
) (faultResponseCounts, bool) {
	expected := faultResponseCounts{
		Missing: operations.Discard + operations.Negotiate,
	}
	switch mode {
	case "missing":
		expected.Missing += operations.Take
	case "matching":
		validTakes := uint64(0)
		if operations.Take > 1 {
			validTakes = min(operations.Take-1, matchingValidTakes)
		}
		expected.Valid = validTakes
		expected.Missing += operations.Take - validTakes
	case defaultFaultMode:
		expected.Stale = (operations.Take + 1) / 2
		expected.Malformed = operations.Take / 2
	case "timeout":
		expected.Timeout = operations.Take
	case "disconnect":
		expected.Disconnect = operations.Take
	case "overload":
		expected.Overload = operations.Take
	case "truncated":
		expected.Truncated = operations.Take
	case "bad-magic":
		expected.BadMagic = operations.Take
	case "bad-size":
		expected.BadSize = operations.Take
	case "version-mismatch":
		expected.VersionMismatch = operations.Take
	case "zero-trace-id":
		expected.ZeroTraceID = operations.Take
	case "zero-span-id":
		expected.ZeroSpanID = operations.Take
	default:
		return faultResponseCounts{}, false
	}
	return expected, true
}

func validResponseDeficit(
	summary faultSummary,
	parsed, responses, pending uint64,
) bool {
	expected, ok := expectedResponseCounts(
		summary.Mode,
		summary.MatchingValidTakes,
		summary.ParsedOperations,
	)
	if !ok {
		return false
	}
	pendingResponses := summary.UnresolvedRequests.PendingResponses
	timeoutAccounted := summary.Responses.Timeout + pendingResponses.Timeout
	disconnectAccounted := summary.Responses.Disconnect + pendingResponses.Disconnect
	if timeoutAccounted > expected.Timeout || disconnectAccounted != expected.Disconnect ||
		expected.Timeout-timeoutAccounted != summary.DrainCancellations {
		return false
	}
	if responses+pending+summary.DrainCancellations > parsed {
		return false
	}
	payloadDeficit := parsed - responses - pending - summary.DrainCancellations
	writeTransportErrors := summary.TransportErrors - summary.PartialRequests -
		summary.AcceptTransportErrors
	return payloadDeficit == writeTransportErrors
}

func validateExitSummary(summary faultSummary, parsed, responses uint64) error {
	unresolved := summary.UnresolvedRequests.PreParse +
		summary.UnresolvedRequests.PendingResponses.total() +
		summary.UnresolvedRequests.Terminal
	if summary.ExitClassification != exitDrainTimeout &&
		(summary.FinalInflight != 0 || unresolved != 0 || summary.DrainCancellations != 0) {
		return errors.New("invalid fault bridge unresolved exit state")
	}
	if (summary.SocketCleanupErrors == 0 &&
		summary.ExitClassification == exitSocketCleanupError) ||
		(summary.SocketCleanupErrors != 0 &&
			(summary.ExitClassification == exitSignalDrained ||
				summary.ExitClassification == exitRequestLimitReached)) {
		return errors.New("invalid fault bridge socket cleanup state")
	}
	successfulDrain := func() bool {
		return summary.MalformedRequests == 0 && summary.PartialRequests == 0 &&
			summary.TransportErrors == 0 && responses == parsed &&
			summary.FinalInflight == 0 && unresolved == 0 &&
			summary.DrainCancellations == 0
	}
	switch summary.ExitClassification {
	case exitSignalDrained:
		if !successfulDrain() {
			return errors.New("invalid fault bridge signal completion")
		}
	case exitRequestLimitReached:
		if summary.AcceptedRequests != summary.Limits.MaxRequests ||
			summary.AdmissionRejections != 0 || !successfulDrain() {
			return errors.New("invalid fault bridge request-limit completion")
		}
	case exitInflightLimitExceeded:
		if summary.AdmissionRejections == 0 ||
			summary.MaxInflight != summary.Limits.MaxInflight ||
			parsed-responses != summary.TransportErrors-summary.PartialRequests-
				summary.AcceptTransportErrors {
			return errors.New("invalid fault bridge inflight-limit failure")
		}
	case exitMalformedRequest:
		if summary.MalformedRequests == 0 {
			return errors.New("invalid fault bridge malformed-request failure")
		}
	case exitPartialRequest:
		if summary.PartialRequests == 0 {
			return errors.New("invalid fault bridge partial-request failure")
		}
	case exitTransportError:
		if summary.TransportErrors == 0 {
			return errors.New("invalid fault bridge transport failure")
		}
	case exitDrainTimeout:
		if summary.MaxInflight == 0 ||
			summary.AcceptedRequests == summary.AdmissionRejections {
			return errors.New("invalid fault bridge drain-timeout failure")
		}
	case exitStartupError:
		if summary.AcceptedRequests != 0 || parsed != 0 || responses != 0 ||
			summary.AdmissionRejections != 0 || summary.MalformedRequests != 0 ||
			summary.PartialRequests != 0 || summary.TransportErrors != 0 ||
			summary.AcceptTransportErrors != 0 ||
			summary.WithheldTimeouts != 0 || summary.MaxInflight != 0 {
			return errors.New("invalid fault bridge startup failure")
		}
	case exitSocketCleanupError:
		if summary.SocketCleanupErrors != 1 || !successfulDrain() {
			return errors.New("invalid fault bridge socket-cleanup failure")
		}
	}
	return nil
}

func validExitClassification(classification string) bool {
	switch classification {
	case exitSignalDrained,
		exitRequestLimitReached,
		exitInflightLimitExceeded,
		exitMalformedRequest,
		exitPartialRequest,
		exitTransportError,
		exitDrainTimeout,
		exitStartupError,
		exitSocketCleanupError:
		return true
	default:
		return false
	}
}

func (counts faultOperationCounts) total() uint64 {
	return counts.Discard + counts.Negotiate + counts.Take
}

func (counts faultResponseCounts) total() uint64 {
	return counts.BadMagic + counts.BadSize + counts.Disconnect + counts.Malformed +
		counts.Missing + counts.Overload + counts.Stale + counts.Timeout +
		counts.Truncated + counts.Valid + counts.VersionMismatch + counts.ZeroSpanID +
		counts.ZeroTraceID
}

type faultSummaryPublishHooks struct {
	afterLink func() error
}

func writeFaultSummary(summaryPath string, summary faultSummary) error {
	return writeFaultSummaryWithHooks(summaryPath, summary, faultSummaryPublishHooks{})
}

func writeFaultSummaryWithHooks(
	summaryPath string,
	summary faultSummary,
	hooks faultSummaryPublishHooks,
) (returnedErr error) {
	if runtime.GOOS != "linux" {
		return errors.New("fault bridge summary publication requires Linux")
	}
	if err := validateFaultSummary(summary); err != nil {
		return err
	}
	if !filepath.IsAbs(summaryPath) || filepath.Clean(summaryPath) != summaryPath {
		return errors.New("summary path must be absolute and clean")
	}
	payload, err := json.Marshal(summary)
	if err != nil {
		return fmt.Errorf("marshal summary: %w", err)
	}
	payload = append(payload, '\n')
	if len(payload) > maxSummaryBytes {
		return fmt.Errorf("summary exceeds %d bytes", maxSummaryBytes)
	}

	directoryPath := filepath.Dir(summaryPath)
	directory, err := os.Open(directoryPath)
	if err != nil {
		return fmt.Errorf("open summary directory: %w", err)
	}
	defer directory.Close()
	directoryInfo, err := directory.Stat()
	if err != nil {
		return fmt.Errorf("inspect summary directory: %w", err)
	}
	if !directoryInfo.IsDir() {
		return errors.New("summary parent is not a directory")
	}
	if err := revalidateSummaryDirectory(directoryPath, directoryInfo); err != nil {
		return err
	}
	directoryFD := int(directory.Fd())
	temporary, temporaryName, err := createSummaryTemporary(directoryFD)
	if err != nil {
		return err
	}
	temporaryPresent := true
	published := false
	committed := false
	var temporaryStat unix.Stat_t
	defer func() {
		var cleanupErrors []error
		if temporary != nil {
			if err := temporary.Close(); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("close summary temporary: %w", err))
			}
		}
		if temporaryPresent {
			if err := unlinkSummaryFile(directoryFD, temporaryName, temporaryStat); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("remove summary temporary: %w", err))
			}
		}
		if published && !committed {
			if err := unlinkSummaryFile(directoryFD, filepath.Base(summaryPath), temporaryStat); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("roll back summary: %w", err))
			}
			if err := directory.Sync(); err != nil {
				cleanupErrors = append(cleanupErrors, fmt.Errorf("sync rolled-back summary directory: %w", err))
			}
		}
		if len(cleanupErrors) > 0 {
			returnedErr = errors.Join(append([]error{returnedErr}, cleanupErrors...)...)
		}
	}()
	if err := unix.Fstat(int(temporary.Fd()), &temporaryStat); err != nil {
		return fmt.Errorf("inspect summary temporary: %w", err)
	}
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("set summary permissions: %w", err)
	}
	written, err := temporary.Write(payload)
	if err != nil {
		return fmt.Errorf("write summary: %w", err)
	}
	if written != len(payload) {
		return io.ErrShortWrite
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync summary: %w", err)
	}
	if err := unix.Fstat(int(temporary.Fd()), &temporaryStat); err != nil {
		return fmt.Errorf("reinspect summary temporary: %w", err)
	}
	if err := validateSummaryFileStat(temporaryStat, int64(len(payload)), 1); err != nil {
		return fmt.Errorf("validate written summary temporary: %w", err)
	}
	if err := revalidateSummaryDirectory(directoryPath, directoryInfo); err != nil {
		return err
	}
	var namedTemporaryStat unix.Stat_t
	if err := unix.Fstatat(
		directoryFD, temporaryName, &namedTemporaryStat, unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return fmt.Errorf("inspect named summary temporary: %w", err)
	}
	if !sameSummaryFile(temporaryStat, namedTemporaryStat) {
		return errors.New("summary temporary identity changed")
	}
	if err := linkOpenSummaryFile(
		int(temporary.Fd()), directoryFD, filepath.Base(summaryPath),
	); err != nil {
		return fmt.Errorf("publish summary: %w", err)
	}
	published = true
	if hooks.afterLink != nil {
		if err := hooks.afterLink(); err != nil {
			return fmt.Errorf("after publishing summary: %w", err)
		}
	}
	var publishedStat unix.Stat_t
	if err := unix.Fstatat(
		directoryFD, filepath.Base(summaryPath), &publishedStat, unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return fmt.Errorf("inspect published summary: %w", err)
	}
	if !sameSummaryFile(temporaryStat, publishedStat) {
		return errors.New("published summary identity changed")
	}
	if err := validateSummaryFileStat(publishedStat, int64(len(payload)), 2); err != nil {
		return fmt.Errorf("validate published summary: %w", err)
	}
	if err := unlinkSummaryFile(directoryFD, temporaryName, temporaryStat); err != nil {
		return fmt.Errorf("remove summary temporary: %w", err)
	}
	temporaryPresent = false
	closeErr := temporary.Close()
	temporary = nil
	if closeErr != nil {
		return fmt.Errorf("close summary temporary: %w", closeErr)
	}
	if err := unix.Fstatat(
		directoryFD, filepath.Base(summaryPath), &publishedStat, unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return fmt.Errorf("reinspect published summary: %w", err)
	}
	if !sameSummaryFile(temporaryStat, publishedStat) {
		return errors.New("published summary identity changed after temporary cleanup")
	}
	if err := validateSummaryFileStat(publishedStat, int64(len(payload)), 1); err != nil {
		return fmt.Errorf("revalidate published summary: %w", err)
	}
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync summary directory: %w", err)
	}
	if err := revalidateSummaryDirectory(directoryPath, directoryInfo); err != nil {
		return err
	}
	committed = true
	return nil
}

func createSummaryTemporary(directoryFD int) (*os.File, string, error) {
	for range maxTempAttempts {
		var random [16]byte
		if _, err := cryptorand.Read(random[:]); err != nil {
			return nil, "", fmt.Errorf("generate summary temporary name: %w", err)
		}
		name := ".faultbridge-summary.tmp-" + hex.EncodeToString(random[:])
		fd, err := unix.Openat(
			directoryFD,
			name,
			unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0o600,
		)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return nil, "", fmt.Errorf("create summary temporary: %w", err)
		}
		file := os.NewFile(uintptr(fd), name)
		if file == nil {
			_ = unix.Close(fd)
			return nil, "", errors.New("wrap summary temporary")
		}
		return file, name, nil
	}
	return nil, "", errors.New("create unique summary temporary")
}

func linkOpenSummaryFile(sourceFD, directoryFD int, destination string) error {
	if runtime.GOOS != "linux" {
		return errors.New("descriptor-bound summary publication requires Linux")
	}
	err := unix.Linkat(sourceFD, "", directoryFD, destination, linuxATEmptyPath)
	if err == nil {
		return nil
	}
	if !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EINVAL) &&
		!errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ENOSYS) &&
		!errors.Is(err, unix.EOPNOTSUPP) && !errors.Is(err, unix.EPERM) {
		return err
	}
	procFDPath := fmt.Sprintf("/proc/self/fd/%d", sourceFD)
	return unix.Linkat(
		unix.AT_FDCWD, procFDPath, directoryFD, destination, unix.AT_SYMLINK_FOLLOW,
	)
}

func revalidateSummaryDirectory(path string, expected os.FileInfo) error {
	current, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("reinspect summary directory: %w", err)
	}
	if !current.IsDir() || !os.SameFile(expected, current) {
		return errors.New("summary directory identity changed")
	}
	stat, ok := current.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("summary directory ownership is unavailable")
	}
	if stat.Uid != uint32(os.Geteuid()) || current.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf(
			"summary directory must be owned by effective user %d and private, got owner %d mode %#o",
			os.Geteuid(),
			stat.Uid,
			current.Mode().Perm(),
		)
	}
	return nil
}

func validateSummaryFileStat(stat unix.Stat_t, expectedSize int64, expectedLinks uint64) error {
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o777 != 0o600 ||
		stat.Size != expectedSize ||
		uint64(stat.Nlink) != expectedLinks { //nolint:unconvert // Stat_t.Nlink widths vary by OS.
		return errors.New("summary file metadata is not canonical")
	}
	return nil
}

func sameSummaryFile(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino
}

func unlinkSummaryFile(directoryFD int, name string, expected unix.Stat_t) error {
	if err := validateOpenSummaryDirectory(directoryFD); err != nil {
		return err
	}
	var current unix.Stat_t
	if err := unix.Fstatat(directoryFD, name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	if !sameSummaryFile(expected, current) {
		return errors.New("refusing to unlink changed summary file")
	}
	return unix.Unlinkat(directoryFD, name, 0)
}

func validateOpenSummaryDirectory(directoryFD int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(directoryFD, &stat); err != nil {
		return fmt.Errorf("inspect open summary directory: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) ||
		stat.Mode&0o077 != 0 {
		return errors.New("open summary directory is no longer owned and private")
	}
	return nil
}

func writeResponse(connection *net.UnixConn, payload []byte) error {
	for len(payload) > 0 {
		written, err := connection.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrUnexpectedEOF
		}
		payload = payload[written:]
	}
	return nil
}

func handle(ctx context.Context, connection *net.UnixConn, server *faultServer) (string, error) {
	if err := connection.SetDeadline(time.Now().Add(server.requestTimeout)); err != nil {
		server.recordPartialRequest(connection)
		return exitTransportError, err
	}
	if server.beforeRequestParse != nil {
		server.beforeRequestParse()
	}
	payload := make([]byte, requestSize)
	if _, err := io.ReadFull(connection, payload); err != nil {
		server.recordPartialRequest(connection)
		return exitPartialRequest, fmt.Errorf("read request: %w", err)
	}
	request, err := parseRequest(payload)
	if err != nil {
		server.recordMalformedRequest(connection)
		return exitMalformedRequest, err
	}
	if server.mode == "matching" && request.source != sourceDirect {
		server.recordMalformedRequest(connection)
		return exitMalformedRequest, fmt.Errorf(
			"matching request source must be direct, got %s",
			sourceName(request.source),
		)
	}
	response := server.planResponse(connection, request)
	if server.afterResponsePlanned != nil {
		server.afterResponsePlanned()
	}
	if response.delay > 0 {
		timer := time.NewTimer(response.delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			server.recordCanceledResponse(connection, response.status)
			return exitDrainTimeout, ctx.Err()
		case <-timer.C:
		}
	}
	if len(response.payload) > 0 {
		if err := writeResponse(connection, response.payload); err != nil {
			server.recordWriteTransportError(connection)
			return exitTransportError, fmt.Errorf("write response: %w", err)
		}
	}
	server.recordResponse(connection, response.status)
	if server.mode != "missing" {
		server.logRequest(request, response.status)
	}
	return "", nil
}

func parseRequest(request []byte) (faultRequest, error) {
	if len(request) != requestSize || string(request[:4]) != "OBIQ" ||
		binary.LittleEndian.Uint16(request[4:6]) != requestVersion ||
		binary.LittleEndian.Uint16(request[6:8]) != requestSize {
		return faultRequest{}, errors.New("invalid request envelope")
	}
	if request[10] != 0 || request[11] != 0 ||
		binary.LittleEndian.Uint32(request[12:16]) == 0 ||
		binary.LittleEndian.Uint64(request[16:24]) == 0 {
		return faultRequest{}, errors.New("invalid request identity or reserved bytes")
	}
	switch request[9] {
	case sourceDirect, sourceTask:
	default:
		return faultRequest{}, errors.New("invalid request source")
	}
	switch request[8] {
	case operationTake, operationDrop, operationProbe:
		return faultRequest{operation: request[8], source: request[9]}, nil
	default:
		return faultRequest{}, errors.New("invalid request operation")
	}
}

func (s *faultServer) response(operation, source byte) faultResponse {
	if operation != operationTake {
		return responseWithStatus(statusMissing)
	}
	count := s.takes.Add(1)
	if count > maxTakeRequests {
		return responseWithStatus(statusOverload)
	}

	switch s.mode {
	case "missing":
		return responseWithStatus(statusMissing)
	case "matching":
		if source != sourceDirect || count == 1 || uint64(count) > s.matchingValidTakes+1 {
			return responseWithStatus(statusMissing)
		}
		return faultResponse{payload: validRecord(), status: statusName(statusValid)}
	case defaultFaultMode:
		if count%2 != 0 {
			return responseWithStatus(statusStale)
		}
		return responseWithStatus(statusMalformed)
	case "timeout":
		delay := s.timeoutDelay
		if delay == 0 {
			delay = timeoutDelay
		}
		return faultResponse{status: "timeout", delay: delay}
	case "disconnect":
		return faultResponse{status: "disconnect"}
	case "overload":
		return responseWithStatus(statusOverload)
	case "truncated":
		return faultResponse{payload: statusRecord(statusMissing)[:recordSize/2], status: "truncated"}
	case "bad-magic":
		record := statusRecord(statusMissing)
		record[0] = 'X'
		return faultResponse{payload: record, status: "bad-magic"}
	case "bad-size":
		record := statusRecord(statusMissing)
		binary.LittleEndian.PutUint16(record[6:8], recordSize-1)
		return faultResponse{payload: record, status: "bad-size"}
	case "version-mismatch":
		record := statusRecord(statusMissing)
		binary.LittleEndian.PutUint16(record[4:6], recordVersion+1)
		return faultResponse{payload: record, status: "version-mismatch"}
	case "zero-trace-id":
		record := validRecord()
		clear(record[16:32])
		return faultResponse{payload: record, status: "zero-trace-id"}
	case "zero-span-id":
		record := validRecord()
		clear(record[32:40])
		return faultResponse{payload: record, status: "zero-span-id"}
	default:
		panic("validated fault mode became invalid")
	}
}

func responseWithStatus(status byte) faultResponse {
	return faultResponse{payload: statusRecord(status), status: statusName(status)}
}

func statusRecord(status byte) []byte {
	record := make([]byte, recordSize)
	copy(record[:4], "OBIJ")
	binary.LittleEndian.PutUint16(record[4:6], recordVersion)
	binary.LittleEndian.PutUint16(record[6:8], recordSize)
	record[8] = status
	return record
}

func validRecord() []byte {
	record := statusRecord(statusValid)
	record[9] = 1
	copy(record[16:32], []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	})
	copy(record[32:40], []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17})
	binary.LittleEndian.PutUint64(record[40:48], 0x0102030405060708)
	binary.LittleEndian.PutUint64(record[48:56], 0x1112131415161718)
	return record
}

func validFaultMode(mode string) bool {
	switch mode {
	case defaultFaultMode,
		"missing",
		"matching",
		"timeout",
		"disconnect",
		"overload",
		"truncated",
		"bad-magic",
		"bad-size",
		"version-mismatch",
		"zero-trace-id",
		"zero-span-id":
		return true
	default:
		return false
	}
}

func validMatchingTakeCount(mode string, count uint64) bool {
	if mode != "matching" {
		return count == 1
	}
	return count >= 1 && count <= maxMatchingTakes
}

func environmentOrDefault(name, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

func operationName(operation byte) string {
	switch operation {
	case operationTake:
		return "take"
	case operationDrop:
		return "discard"
	case operationProbe:
		return "negotiate"
	default:
		return "unknown"
	}
}

func sourceName(source byte) string {
	switch source {
	case sourceDirect:
		return "direct"
	case sourceTask:
		return "task"
	default:
		return "unknown"
	}
}

func statusName(status byte) string {
	switch status {
	case statusValid:
		return "valid"
	case statusMissing:
		return "missing"
	case statusStale:
		return "stale"
	case statusMalformed:
		return "malformed"
	case statusOverload:
		return "overload"
	default:
		return "unknown"
	}
}
