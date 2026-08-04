// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javabridge // import "go.opentelemetry.io/obi/pkg/internal/javabridge"

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	defaultMaxConcurrentRequests    = 64
	defaultIdentityCacheEntries     = 16384
	defaultPreAuthTimeout           = 250 * time.Millisecond
	defaultRateLimitWindow          = time.Second
	defaultMaxRequestsPerWindow     = 16384
	defaultMaxPeerRequestsPerWindow = 4096
	defaultMaxRateLimitedPeers      = defaultMaxRequestsPerWindow
	maxPeerThreads                  = 4096
	maxTransportTimeout             = time.Duration(1<<31-1) * time.Millisecond
)

var errIdentityResolutionOverload = errors.New("java bridge identity resolution overloaded")

type Identity struct {
	TID       uint32
	PID       uint32
	Namespace uint32
}

type Handler interface {
	HandleAuthenticated(context.Context, Identity, Operation, LookupSource, uint64) Record
}

type IdentityResolver interface {
	Resolve(ctx context.Context, peerPID int32, namespaceTID uint32) (Identity, error)
}

type Server struct {
	log              *slog.Logger
	listener         *net.UnixListener
	socketPath       *guardedSocketPath
	socketInfo       os.FileInfo
	timeout          time.Duration
	preAuthTimeout   time.Duration
	resolver         IdentityResolver
	handler          Handler
	active           chan struct{}
	preAuth          chan struct{}
	authenticated    chan struct{}
	maxPeerRequests  int
	peerMu           sync.Mutex
	peerRequests     map[int32]int
	rateNow          func() time.Time
	rateWindow       time.Duration
	maxRateRequests  int
	maxPeerRate      int
	maxRatePeers     int
	rateWindowStart  time.Time
	rateRequests     int
	peerRateRequests map[int32]int
	connections      sync.WaitGroup
	logFailures      [2]atomic.Uint64
	observe          func(Operation, Status)
	closeOnce        sync.Once
	listenerClose    error
}

type guardedSocketPath struct {
	directory *os.File
	name      string
}

type ServerOptions struct {
	SocketPath    string
	SocketGID     int
	Timeout       time.Duration
	MaxConcurrent int
	Resolver      IdentityResolver
	Log           *slog.Logger
	Observe       func(Operation, Status)
}

func NewServer(options ServerOptions, handler Handler) (*Server, error) {
	if handler == nil {
		return nil, errors.New("java bridge fallback handler is required")
	}
	if !filepath.IsAbs(options.SocketPath) {
		return nil, fmt.Errorf("java bridge socket path must be absolute: %q", options.SocketPath)
	}
	if err := validateSocketPathAliases(options.SocketPath); err != nil {
		return nil, err
	}
	canonicalPath, err := canonicalSocketPath(options.SocketPath)
	if err != nil {
		return nil, err
	}
	if options.Timeout <= 0 {
		return nil, errors.New("java bridge fallback timeout must be greater than zero")
	}
	if options.Timeout > maxTransportTimeout {
		return nil, errors.New("java bridge fallback timeout must not exceed 2147483647ms")
	}
	socketGID := options.SocketGID
	if socketGID < 0 {
		socketGID = os.Getegid()
	}

	maxConcurrent := options.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = defaultMaxConcurrentRequests
	}
	maxPeer := maxConcurrent / 2
	if maxPeer == 0 {
		maxPeer = 1
	}
	resolver := options.Resolver
	if resolver == nil {
		resolver = &procIdentityResolver{}
	}
	log := options.Log
	if log == nil {
		log = slog.With("component", "java-remote-parent")
	}

	socketPath, err := prepareSocketPath(canonicalPath, socketGID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if socketPath != nil {
			_ = socketPath.Close()
		}
	}()

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath.anchored(), Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("listen on Java bridge fallback socket: %w", err)
	}
	listener.SetUnlinkOnClose(false)
	cleanup := true
	var socketInfo os.FileInfo
	defer func() {
		if cleanup {
			_ = listener.Close()
			_ = socketPath.removeIfSame(socketInfo)
		}
	}()
	socketInfo, err = socketPath.stat()
	if err != nil {
		return nil, fmt.Errorf("stat Java bridge fallback socket: %w", err)
	}

	if err := socketPath.chown(socketGID); err != nil {
		return nil, fmt.Errorf("set Java bridge fallback socket group: %w", err)
	}
	socketInfo, err = refreshSocketPathIdentity(socketPath, socketInfo)
	if err != nil {
		return nil, err
	}
	if err := socketPath.chmod(0o660); err != nil {
		return nil, fmt.Errorf("set Java bridge fallback socket permissions: %w", err)
	}
	socketInfo, err = refreshSocketPathIdentity(socketPath, socketInfo)
	if err != nil {
		return nil, err
	}

	cleanup = false
	guard := socketPath
	socketPath = nil
	return &Server{
		log:              log,
		listener:         listener,
		socketPath:       guard,
		socketInfo:       socketInfo,
		timeout:          options.Timeout,
		preAuthTimeout:   defaultPreAuthTimeout,
		resolver:         resolver,
		handler:          handler,
		active:           make(chan struct{}, maxConcurrent),
		preAuth:          make(chan struct{}, maxConcurrent),
		authenticated:    make(chan struct{}, maxConcurrent),
		maxPeerRequests:  maxPeer,
		peerRequests:     make(map[int32]int),
		rateNow:          time.Now,
		rateWindow:       defaultRateLimitWindow,
		maxRateRequests:  defaultMaxRequestsPerWindow,
		maxPeerRate:      defaultMaxPeerRequestsPerWindow,
		maxRatePeers:     defaultMaxRateLimitedPeers,
		peerRateRequests: make(map[int32]int),
		observe:          options.Observe,
	}, nil
}

func (p *guardedSocketPath) anchored() string {
	return filepath.Join("/proc/self/fd", strconv.FormatUint(uint64(p.directory.Fd()), 10), p.name)
}

func (p *guardedSocketPath) stat() (os.FileInfo, error) {
	return os.Lstat(p.anchored())
}

func (p *guardedSocketPath) chown(gid int) error {
	return unix.Fchownat(int(p.directory.Fd()), p.name, -1, gid, unix.AT_SYMLINK_NOFOLLOW)
}

func (p *guardedSocketPath) chmod(mode os.FileMode) error {
	return unix.Fchmodat(int(p.directory.Fd()), p.name, uint32(mode.Perm()), 0)
}

func (p *guardedSocketPath) Close() error {
	return p.directory.Close()
}

func refreshSocketPathIdentity(socketPath *guardedSocketPath, previous os.FileInfo) (os.FileInfo, error) {
	current, err := socketPath.stat()
	if err != nil {
		return nil, fmt.Errorf("stat Java bridge fallback socket: %w", err)
	}
	if !os.SameFile(previous, current) {
		return nil, errors.New("java bridge fallback socket changed during initialization")
	}
	return current, nil
}

func sameSocketPathIdentity(expected, current os.FileInfo) bool {
	if !os.SameFile(expected, current) ||
		expected.Mode() != current.Mode() ||
		expected.Size() != current.Size() {
		return false
	}
	expectedStat, expectedOK := expected.Sys().(*syscall.Stat_t)
	currentStat, currentOK := current.Sys().(*syscall.Stat_t)
	return expectedOK && currentOK &&
		expectedStat.Uid == currentStat.Uid &&
		expectedStat.Gid == currentStat.Gid &&
		expectedStat.Ctim == currentStat.Ctim
}

func (p *guardedSocketPath) removeIfSame(expected os.FileInfo) error {
	if expected == nil {
		return nil
	}
	info, err := p.stat()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !sameSocketPathIdentity(expected, info) {
		return nil
	}
	if err := unix.Unlinkat(int(p.directory.Fd()), p.name, 0); err != nil &&
		!errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func prepareSocketPath(socketPath string, socketGID int) (*guardedSocketPath, error) {
	parent := filepath.Dir(socketPath)
	parentInfo, err := os.Lstat(parent)
	if err == nil && parentInfo.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("java bridge fallback socket parent must be a real directory: %q", parent)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect Java bridge fallback socket directory: %w", err)
	}

	directory, created, err := openSocketDirectory(parent)
	if err != nil {
		return nil, err
	}
	name := filepath.Base(socketPath)
	if name == "." || name == string(filepath.Separator) {
		_ = directory.Close()
		return nil, fmt.Errorf("java bridge fallback socket path has no file name: %q", socketPath)
	}
	path := &guardedSocketPath{directory: directory, name: name}
	cleanup := true
	defer func() {
		if cleanup {
			_ = path.Close()
		}
	}()

	parentInfo, err = directory.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect Java bridge fallback socket directory: %w", err)
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !parentInfo.IsDir() || !ok {
		return nil, fmt.Errorf("java bridge fallback socket parent must be a real directory: %q", parent)
	}
	if int(parentStat.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("java bridge fallback socket directory must be owned by OBI: %q", parent)
	}
	if created {
		if err := unix.Fchownat(int(directory.Fd()), ".", -1, socketGID, 0); err != nil {
			return nil, fmt.Errorf("set Java bridge fallback socket directory group: %w", err)
		}
		if err := unix.Fchmodat(int(directory.Fd()), ".", 0o750, 0); err != nil {
			return nil, fmt.Errorf("set Java bridge fallback socket directory permissions: %w", err)
		}
		parentInfo, err = directory.Stat()
		if err != nil {
			return nil, fmt.Errorf("inspect Java bridge fallback socket directory: %w", err)
		}
		parentStat, ok = parentInfo.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, fmt.Errorf("java bridge fallback socket directory has unexpected stat type: %q", parent)
		}
	}
	if int(parentStat.Gid) != socketGID {
		return nil, fmt.Errorf("java bridge fallback socket directory must use configured group %d: %q", socketGID, parent)
	}
	if parentInfo.Mode().Perm()&0o027 != 0 {
		return nil, fmt.Errorf("java bridge fallback socket directory must not be group writable or world accessible: %q", parent)
	}

	info, err := path.stat()
	if errors.Is(err, os.ErrNotExist) {
		cleanup = false
		return path, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inspect Java bridge fallback socket path: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return nil, fmt.Errorf("refusing to replace non-socket Java bridge path %q", socketPath)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return nil, fmt.Errorf("refusing to replace Java bridge socket not owned by OBI: %q", socketPath)
	}
	if err := unix.Unlinkat(int(directory.Fd()), path.name, 0); err != nil {
		return nil, fmt.Errorf("remove stale Java bridge fallback socket: %w", err)
	}

	cleanup = false
	return path, nil
}

func openSocketDirectory(parent string) (*os.File, bool, error) {
	existing := filepath.Clean(parent)
	missing := make([]string, 0)
	for {
		_, err := os.Lstat(existing)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, false, fmt.Errorf("inspect Java bridge fallback socket directory: %w", err)
		}
		next := filepath.Dir(existing)
		if next == existing {
			return nil, false, fmt.Errorf("find existing Java bridge fallback socket ancestor: %q", parent)
		}
		missing = append(missing, filepath.Base(existing))
		existing = next
	}

	directoryFD, systemUID, err := openDirectoryNoSymlinks(existing)
	if err != nil {
		return nil, false, fmt.Errorf("open Java bridge fallback socket directory: %w", err)
	}

	created := false
	openedPath := existing
	for index := len(missing) - 1; index >= 0; index-- {
		component := missing[index]
		made := false
		if err := unix.Mkdirat(directoryFD, component, 0o750); err == nil {
			made = true
		} else if !errors.Is(err, unix.EEXIST) {
			_ = unix.Close(directoryFD)
			return nil, false, fmt.Errorf("create Java bridge fallback socket directory: %w", err)
		}
		nextFD, err := unix.Openat(
			directoryFD,
			component,
			unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		_ = unix.Close(directoryFD)
		if err != nil {
			return nil, false, fmt.Errorf("open Java bridge fallback socket directory: %w", err)
		}
		directoryFD = nextFD
		openedPath = filepath.Join(openedPath, component)
		if err := validateSocketAncestor(directoryFD, openedPath, systemUID); err != nil {
			_ = unix.Close(directoryFD)
			return nil, false, fmt.Errorf("open Java bridge fallback socket directory: %w", err)
		}
		if index == 0 {
			created = made
		}
	}

	return os.NewFile(uintptr(directoryFD), parent), created, nil
}

func openDirectoryNoSymlinks(path string) (int, uint32, error) {
	directoryFD, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, 0, err
	}
	var rootStat unix.Stat_t
	if err := unix.Fstat(directoryFD, &rootStat); err != nil {
		_ = unix.Close(directoryFD)
		return -1, 0, err
	}
	if err := validateSocketAncestor(directoryFD, "/", rootStat.Uid); err != nil {
		_ = unix.Close(directoryFD)
		return -1, 0, err
	}
	openedPath := string(filepath.Separator)
	for component := range strings.SplitSeq(strings.TrimPrefix(filepath.Clean(path), "/"), "/") {
		if component == "" {
			continue
		}
		nextFD, openErr := unix.Openat(
			directoryFD,
			component,
			unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
			0,
		)
		_ = unix.Close(directoryFD)
		if openErr != nil {
			return -1, 0, openErr
		}
		directoryFD = nextFD
		openedPath = filepath.Join(openedPath, component)
		if err := validateSocketAncestor(directoryFD, openedPath, rootStat.Uid); err != nil {
			_ = unix.Close(directoryFD)
			return -1, 0, err
		}
	}
	return directoryFD, rootStat.Uid, nil
}

func validateSocketPathAliases(path string) error {
	cleanPath := filepath.Clean(path)
	var rootStat unix.Stat_t
	if err := unix.Lstat(string(filepath.Separator), &rootStat); err != nil {
		return fmt.Errorf("inspect Java bridge socket root: %w", err)
	}

	current := string(filepath.Separator)
	for component := range strings.SplitSeq(strings.TrimPrefix(cleanPath, "/"), "/") {
		if component == "" {
			continue
		}
		candidate := filepath.Join(current, component)
		var candidateStat unix.Stat_t
		if err := unix.Lstat(candidate, &candidateStat); errors.Is(err, unix.ENOENT) {
			return nil
		} else if err != nil {
			return fmt.Errorf("inspect Java bridge socket alias: %w", err)
		}
		if candidateStat.Mode&unix.S_IFMT != unix.S_IFLNK {
			current = candidate
			continue
		}
		if candidate == cleanPath {
			return fmt.Errorf("java bridge socket path must not be a symlink: %q", path)
		}

		var parentStat unix.Stat_t
		if err := unix.Stat(current, &parentStat); err != nil {
			return fmt.Errorf("inspect Java bridge socket alias parent: %w", err)
		}
		if err := validateSocketAlias(candidate, current, candidateStat, parentStat, rootStat.Uid); err != nil {
			return err
		}
		current = candidate
	}

	return nil
}

func validateSocketAlias(
	path, parent string,
	aliasStat, parentStat unix.Stat_t,
	systemUID uint32,
) error {
	// The JVM resolves the configured alias in its own mount namespace. Only
	// trust aliases whose entries cannot be redirected by another UID; the
	// server independently anchors the resolved target with a directory fd.
	if aliasStat.Uid != systemUID && int(aliasStat.Uid) != os.Geteuid() {
		return fmt.Errorf("java bridge socket alias has an untrusted owner: %q", path)
	}
	if parentStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("java bridge socket alias parent is not a directory: %q", parent)
	}
	if parentStat.Uid != systemUID && int(parentStat.Uid) != os.Geteuid() {
		return fmt.Errorf("java bridge socket alias parent has an untrusted owner: %q", parent)
	}
	if parentStat.Mode&0o022 != 0 && parentStat.Mode&unix.S_ISVTX == 0 {
		return fmt.Errorf("java bridge socket alias is in a writable parent: %q", parent)
	}
	return nil
}

func validateSocketAncestor(directoryFD int, path string, systemUID uint32) error {
	var stat unix.Stat_t
	if err := unix.Fstat(directoryFD, &stat); err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("java bridge socket ancestor is not a directory: %q", path)
	}
	if stat.Uid != systemUID && int(stat.Uid) != os.Geteuid() {
		return fmt.Errorf("java bridge socket ancestor has an untrusted owner: %q", path)
	}
	if stat.Mode&0o022 != 0 && stat.Mode&unix.S_ISVTX == 0 {
		return fmt.Errorf("java bridge socket ancestor is writable without the sticky bit: %q", path)
	}
	return nil
}

func (s *Server) Serve(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = s.listener.Close()
		case <-done:
		}
	}()
	defer close(done)
	defer s.connections.Wait()

	for {
		conn, err := s.listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept Java bridge fallback request: %w", err)
		}
		acceptedAt := time.Now()
		if err := conn.SetDeadline(acceptedAt.Add(s.timeout)); err != nil {
			s.logFailure("deadline")
			_ = conn.Close()
			continue
		}

		peerPID, err := peerPID(conn)
		if err != nil {
			s.observeOutcome(OperationNegotiate, StatusUnauthorized)
			s.writeStatus(conn, StatusUnauthorized)
			_ = conn.Close()
			continue
		}
		if !s.acquirePreAuth(peerPID) {
			s.observeOutcome(OperationNegotiate, StatusOverload)
			s.writeStatus(conn, StatusOverload)
			_ = conn.Close()
			continue
		}

		s.connections.Add(1)
		go func() {
			defer s.connections.Done()
			defer s.releaseRequest(peerPID)
			s.handleConnection(ctx, conn, peerPID, acceptedAt)
		}()
	}
}

func (s *Server) handleConnection(
	ctx context.Context, conn *net.UnixConn, peerPID int32, acceptedAt time.Time,
) {
	defer conn.Close()
	preAuthHeld := true
	defer func() {
		if preAuthHeld {
			s.releasePreAuth()
		}
	}()

	deadline := acceptedAt.Add(s.timeout)
	preAuthDeadline := acceptedAt.Add(s.preAuthTimeout)
	if deadline.Before(preAuthDeadline) {
		preAuthDeadline = deadline
	}
	if err := conn.SetDeadline(preAuthDeadline); err != nil {
		s.logFailure("deadline")
		return
	}

	requestBytes := make([]byte, RequestSize)
	if _, err := io.ReadFull(conn, requestBytes); err != nil {
		status := StatusMalformed
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			status = StatusTimeout
		}
		_ = conn.SetDeadline(deadline)
		s.observeOutcome(OperationNegotiate, status)
		s.writeStatus(conn, status)
		return
	}
	request, err := UnmarshalRequest(requestBytes)
	if err != nil {
		status := StatusMalformed
		if errors.Is(err, ErrVersionMismatch) {
			status = StatusVersionMismatch
		}
		s.observeOutcome(OperationNegotiate, status)
		s.writeStatus(conn, status)
		return
	}

	select {
	case s.authenticated <- struct{}{}:
		s.releasePreAuth()
		preAuthHeld = false
		defer func() { <-s.authenticated }()
	default:
		s.observeOutcome(request.Operation, StatusOverload)
		s.writeStatus(conn, StatusOverload)
		return
	}
	if err := conn.SetDeadline(deadline); err != nil {
		s.logFailure("deadline")
		return
	}

	resolveCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	identity, err := s.resolver.Resolve(resolveCtx, peerPID, request.NamespaceTID)
	if err != nil {
		status := StatusUnauthorized
		if errors.Is(err, errIdentityResolutionOverload) {
			status = StatusOverload
		} else if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			status = StatusTimeout
		}
		s.observeOutcome(request.Operation, status)
		s.writeStatus(conn, status)
		return
	}
	if resolveCtx.Err() != nil || !time.Now().Before(deadline) {
		s.observeOutcome(request.Operation, StatusTimeout)
		s.writeStatus(conn, StatusTimeout)
		return
	}

	response := s.handler.HandleAuthenticated(
		resolveCtx, identity, request.Operation, request.Source, request.ProcessIncarnation,
	)
	s.observeOutcome(request.Operation, response.Status)
	s.writeRecord(conn, response)
}

func (s *Server) acquirePreAuth(peerPID int32) bool {
	select {
	case s.active <- struct{}{}:
	default:
		return false
	}
	select {
	case s.preAuth <- struct{}{}:
	default:
		<-s.active
		return false
	}

	s.peerMu.Lock()
	defer s.peerMu.Unlock()
	if s.peerRequests[peerPID] >= s.maxPeerRequests {
		<-s.preAuth
		<-s.active
		return false
	}
	if !s.acquireRateLimitLocked(peerPID) {
		<-s.preAuth
		<-s.active
		return false
	}
	s.peerRequests[peerPID]++

	return true
}

func (s *Server) acquireRateLimitLocked(peerPID int32) bool {
	now := s.rateNow()
	if s.rateWindowStart.IsZero() || now.Before(s.rateWindowStart) ||
		!now.Before(s.rateWindowStart.Add(s.rateWindow)) {
		s.rateWindowStart = now
		s.rateRequests = 0
		clear(s.peerRateRequests)
	}

	peerRequests, knownPeer := s.peerRateRequests[peerPID]
	if s.rateRequests >= s.maxRateRequests || peerRequests >= s.maxPeerRate {
		return false
	}
	if !knownPeer && len(s.peerRateRequests) >= s.maxRatePeers {
		return false
	}

	s.rateRequests++
	s.peerRateRequests[peerPID] = peerRequests + 1
	return true
}

func (s *Server) releasePreAuth() {
	<-s.preAuth
}

func (s *Server) releaseRequest(peerPID int32) {
	defer func() { <-s.active }()
	s.peerMu.Lock()
	defer s.peerMu.Unlock()

	remaining := s.peerRequests[peerPID] - 1
	if remaining <= 0 {
		delete(s.peerRequests, peerPID)
		return
	}
	s.peerRequests[peerPID] = remaining
}

func (s *Server) observeOutcome(operation Operation, status Status) {
	if s.observe != nil {
		s.observe(operation, status)
	}
}

func peerPID(conn *net.UnixConn) (int32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}

	var (
		credentials *unix.Ucred
		controlErr  error
	)
	if err := raw.Control(func(fd uintptr) {
		credentials, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if controlErr != nil {
		return 0, controlErr
	}
	if credentials == nil || credentials.Pid <= 0 {
		return 0, errors.New("java bridge peer has no process credentials")
	}

	return credentials.Pid, nil
}

func (s *Server) writeStatus(conn *net.UnixConn, status Status) {
	s.writeRecord(conn, Record{Status: status})
}

func (s *Server) writeRecord(conn *net.UnixConn, record Record) {
	encoded, err := record.MarshalBinary()
	if err != nil {
		encoded, _ = (Record{Status: StatusTransportError}).MarshalBinary()
	}
	if _, err := conn.Write(encoded); err != nil {
		s.logFailure("write")
	}
}

func (s *Server) logFailure(stage string) {
	var counter *atomic.Uint64
	switch stage {
	case "deadline":
		counter = &s.logFailures[0]
	case "write":
		counter = &s.logFailures[1]
	default:
		return
	}

	count := counter.Add(1)
	if count&(count-1) != 0 {
		return
	}
	s.log.Debug("Java remote-parent fallback request failed", "stage", stage, "count", count)
}

func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		s.listenerClose = s.listener.Close()
		if errors.Is(s.listenerClose, net.ErrClosed) {
			s.listenerClose = nil
		}
		s.listenerClose = errors.Join(
			s.listenerClose,
			s.socketPath.removeIfSame(s.socketInfo),
			s.socketPath.Close(),
		)
	})

	return s.listenerClose
}

type procIdentityResolver struct {
	root        string
	threadLimit int
	cacheLimit  int
	cacheMu     sync.Mutex
	cache       map[procIdentityKey]string
	scansMu     sync.Mutex
	scans       map[int32]*procIdentityScan
	coldScans   uint64
}

type procIdentityKey struct {
	peerPID      int32
	namespaceTID uint32
}

type procIdentityScan struct {
	turn chan struct{}
	refs int
}

func (r *procIdentityResolver) Resolve(ctx context.Context, peerPID int32, namespaceTID uint32) (Identity, error) {
	if peerPID <= 0 || namespaceTID == 0 {
		return Identity{}, errors.New("invalid Java bridge peer identity")
	}
	if err := ctx.Err(); err != nil {
		return Identity{}, err
	}

	root := r.root
	if root == "" {
		root = "/proc"
	}
	key := procIdentityKey{peerPID: peerPID, namespaceTID: namespaceTID}
	if identity, found, err := r.resolveCachedTask(ctx, root, key); found || err != nil {
		return identity, err
	}

	release, err := r.acquirePeerScan(ctx, peerPID)
	if err != nil {
		return Identity{}, err
	}
	defer release()
	if identity, found, err := r.resolveCachedTask(ctx, root, key); found || err != nil {
		return identity, err
	}
	r.scansMu.Lock()
	r.coldScans++
	r.scansMu.Unlock()

	threadLimit := r.threadLimit
	if threadLimit <= 0 {
		threadLimit = maxPeerThreads
	}

	_, namespacePID, err := readProcIdentity(
		ctx, filepath.Join(root, strconv.Itoa(int(peerPID)), "status"), "NStgid", false,
	)
	if err != nil {
		return Identity{}, err
	}

	taskDir := filepath.Join(root, strconv.Itoa(int(peerPID)), "task")
	directory, err := os.Open(taskDir)
	if err != nil {
		return Identity{}, fmt.Errorf("read Java bridge peer tasks: %w", err)
	}
	defer directory.Close()
	tasks, err := directory.ReadDir(threadLimit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return Identity{}, fmt.Errorf("read Java bridge peer tasks: %w", err)
	}
	if len(tasks) > threadLimit {
		return Identity{}, fmt.Errorf(
			"%w: peer exceeds thread validation limit %d", errIdentityResolutionOverload, threadLimit,
		)
	}

	discovered := make(map[uint32]string, len(tasks))
	cacheDiscovered := true
	defer func() {
		if cacheDiscovered {
			r.cacheTasks(peerPID, discovered)
		}
	}()
	for _, task := range tasks {
		if err := ctx.Err(); err != nil {
			return Identity{}, err
		}
		if !task.IsDir() {
			continue
		}
		tgid, tid, err := readProcIdentity(
			ctx, filepath.Join(taskDir, task.Name(), "status"), "NSpid", true,
		)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return Identity{}, ctxErr
			}
			continue
		}
		if tgid != peerPID {
			continue
		}
		if _, exists := discovered[tid]; exists {
			cacheDiscovered = false
			return Identity{}, errors.New("java bridge namespace thread identity has multiple matches")
		}
		discovered[tid] = task.Name()
	}
	if err := ctx.Err(); err != nil {
		return Identity{}, err
	}
	_, matched := discovered[namespaceTID]
	if !matched {
		return Identity{}, errors.New("java bridge namespace thread identity has no matches")
	}

	if err := ctx.Err(); err != nil {
		return Identity{}, err
	}
	namespaceInfo, err := os.Stat(filepath.Join(root, strconv.Itoa(int(peerPID)), "ns", "pid_for_children"))
	if err != nil {
		return Identity{}, fmt.Errorf("stat Java bridge peer PID namespace: %w", err)
	}
	stat, ok := namespaceInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return Identity{}, errors.New("java bridge peer PID namespace has unexpected stat type")
	}

	identity := Identity{
		TID:       namespaceTID,
		PID:       namespacePID,
		Namespace: uint32(stat.Ino),
	}
	return identity, nil
}

func (r *procIdentityResolver) resolveCachedTask(
	ctx context.Context, root string, key procIdentityKey,
) (Identity, bool, error) {
	task, ok := r.cachedTask(key)
	if !ok {
		return Identity{}, false, nil
	}
	identity, err := resolveProcTask(ctx, root, key.peerPID, key.namespaceTID, task)
	if err == nil {
		return identity, true, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return Identity{}, true, ctxErr
	}
	r.deleteCachedTask(key, task)

	return Identity{}, false, nil
}

func (r *procIdentityResolver) acquirePeerScan(ctx context.Context, peerPID int32) (func(), error) {
	r.scansMu.Lock()
	if r.scans == nil {
		r.scans = make(map[int32]*procIdentityScan)
	}
	scan := r.scans[peerPID]
	if scan == nil {
		scan = &procIdentityScan{turn: make(chan struct{}, 1)}
		scan.turn <- struct{}{}
		r.scans[peerPID] = scan
	}
	scan.refs++
	r.scansMu.Unlock()

	select {
	case <-scan.turn:
		return func() {
			scan.turn <- struct{}{}
			r.releasePeerScan(peerPID, scan)
		}, nil
	case <-ctx.Done():
		r.releasePeerScan(peerPID, scan)
		return nil, ctx.Err()
	}
}

func (r *procIdentityResolver) releasePeerScan(peerPID int32, scan *procIdentityScan) {
	r.scansMu.Lock()
	defer r.scansMu.Unlock()

	scan.refs--
	if scan.refs == 0 && r.scans[peerPID] == scan {
		delete(r.scans, peerPID)
	}
}

func (r *procIdentityResolver) cachedTask(key procIdentityKey) (string, bool) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()

	task, ok := r.cache[key]
	return task, ok
}

func (r *procIdentityResolver) cacheTasks(peerPID int32, tasks map[uint32]string) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()

	if r.cache == nil {
		r.cache = make(map[procIdentityKey]string)
	}
	limit := r.cacheLimit
	if limit <= 0 {
		limit = defaultIdentityCacheEntries
	}
	for namespaceTID, task := range tasks {
		key := procIdentityKey{peerPID: peerPID, namespaceTID: namespaceTID}
		if _, exists := r.cache[key]; !exists && len(r.cache) >= limit {
			for evicted := range r.cache {
				delete(r.cache, evicted)
				break
			}
		}
		r.cache[key] = task
	}
}

func (r *procIdentityResolver) deleteCachedTask(key procIdentityKey, task string) {
	r.cacheMu.Lock()
	defer r.cacheMu.Unlock()

	if r.cache[key] == task {
		delete(r.cache, key)
	}
}

func resolveProcTask(
	ctx context.Context, root string, peerPID int32, namespaceTID uint32, task string,
) (Identity, error) {
	processRoot := filepath.Join(root, strconv.Itoa(int(peerPID)))
	_, namespacePID, err := readProcIdentity(
		ctx, filepath.Join(processRoot, "status"), "NStgid", false,
	)
	if err != nil {
		return Identity{}, err
	}

	tgid, tid, err := readProcIdentity(
		ctx, filepath.Join(processRoot, "task", task, "status"), "NSpid", true,
	)
	if err != nil {
		return Identity{}, err
	}
	if tgid != peerPID {
		return Identity{}, errors.New("cached Java bridge thread no longer belongs to peer")
	}
	if tid != namespaceTID {
		return Identity{}, errors.New("cached Java bridge namespace thread identity changed")
	}

	namespaceInfo, err := os.Stat(filepath.Join(processRoot, "ns", "pid_for_children"))
	if err != nil {
		return Identity{}, fmt.Errorf("stat Java bridge peer PID namespace: %w", err)
	}
	stat, ok := namespaceInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return Identity{}, errors.New("java bridge peer PID namespace has unexpected stat type")
	}

	return Identity{TID: namespaceTID, PID: namespacePID, Namespace: uint32(stat.Ino)}, nil
}

func readProcIdentity(
	ctx context.Context, path string, namespaceKey string, requireTgid bool,
) (int32, uint32, error) {
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	file, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	var (
		tgid        int32
		namespaceID uint32
		haveTgid    = !requireTgid
		haveNS      bool
	)
	scanner := bufio.NewScanner(io.LimitReader(file, 256*1024))
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return 0, 0, err
		}
		key, value, found := strings.Cut(scanner.Text(), ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "Tgid":
			if requireTgid {
				parsed, parseErr := strconv.ParseInt(value, 10, 32)
				if parseErr != nil || parsed <= 0 {
					return 0, 0, errors.New("invalid Java bridge peer thread process identity")
				}
				tgid = int32(parsed)
				haveTgid = true
			}
		default:
			if key == namespaceKey {
				parsed, parseErr := lastNamespaceID(value)
				if parseErr != nil {
					return 0, 0, parseErr
				}
				namespaceID = parsed
				haveNS = true
			}
		}
		if haveTgid && haveNS {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, 0, err
	}
	if !haveTgid || !haveNS {
		return 0, 0, errors.New("missing Java bridge peer process identity")
	}

	return tgid, namespaceID, nil
}

func lastNamespaceID(value string) (uint32, error) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0, errors.New("missing PID namespace identity")
	}
	id, err := strconv.ParseUint(fields[len(fields)-1], 10, 32)
	if err != nil || id == 0 {
		return 0, errors.New("invalid PID namespace identity")
	}

	return uint32(id), nil
}
