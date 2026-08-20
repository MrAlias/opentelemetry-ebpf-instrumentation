// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package jvm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

func bindCurrentProcess(t *testing.T, attacher *JAttacher, start uint64) error {
	t.Helper()
	err := attacher.BindTarget(os.Getpid(), start)
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) {
		t.Skipf("pidfds are unavailable in this test environment: %v", err)
	}
	return err
}

func requireAnonymousPIDFD(t *testing.T, attacher *JAttacher) {
	t.Helper()
	if attacher.targetPIDFD < 0 {
		t.Skip("anonymous pidfd is unavailable; OpenJ9 exact verification requires pidfd_getfd")
	}
}

func TestJAttacherBindsAndValidatesExactCurrentProcess(t *testing.T) {
	start, err := procs.ProcessStartTime(app.PID(os.Getpid()))
	require.NoError(t, err)
	attacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)), 0, nil)

	require.NoError(t, bindCurrentProcess(t, attacher, start))
	assert.Equal(t, os.Getpid(), attacher.targetPID)
	assert.Equal(t, start, attacher.targetStart)
	assert.GreaterOrEqual(t, attacher.targetProcFD, 0)
	require.NoError(t, attacher.ValidateTarget())
	require.NoError(t, attacher.CloseTarget())
	assert.Equal(t, -1, attacher.targetPIDFD)
	assert.Equal(t, -1, attacher.targetProcFD)
}

func TestJAttacherDuplicatesSuppliedDiscoveryProcFD(t *testing.T) {
	start, err := procs.ProcessStartTime(app.PID(os.Getpid()))
	require.NoError(t, err)
	discoveryHandle, err := os.Open("/proc/self")
	require.NoError(t, err)
	attacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)), 0, nil)

	err = attacher.BindTargetFromProcFD(
		os.Getpid(), start, int(discoveryHandle.Fd()),
	)
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) {
		require.NoError(t, discoveryHandle.Close())
		t.Skipf("exact procfd signaling is unavailable in this test environment: %v", err)
	}
	require.NoError(t, err)
	require.NoError(t, discoveryHandle.Close())
	require.NoError(t, attacher.ValidateTarget(),
		"attacher must own a duplicate independent of FileInfo")
	require.NoError(t, attacher.CloseTarget())
}

func TestJAttacherRejectsSuppliedProcFDForDifferentPID(t *testing.T) {
	start, err := procs.ProcessStartTime(app.PID(os.Getpid()))
	require.NoError(t, err)
	discoveryHandle, err := os.Open("/proc/self")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, discoveryHandle.Close()) })
	attacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)), 0, nil)

	err = attacher.BindTargetFromProcFD(
		os.Getpid()+1, start, int(discoveryHandle.Fd()),
	)
	require.ErrorContains(t, err, "procfd identifies PID")
	assert.Equal(t, -1, attacher.targetPIDFD)
	assert.Equal(t, -1, attacher.targetProcFD)
}

func TestJAttacherRejectsWrongStartAndReleasesPIDFD(t *testing.T) {
	start, err := procs.ProcessStartTime(app.PID(os.Getpid()))
	require.NoError(t, err)
	attacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)), 0, nil)

	err = bindCurrentProcess(t, attacher, start+1)
	require.ErrorContains(t, err, "changed from start")
	assert.Equal(t, -1, attacher.targetPIDFD)
	assert.Equal(t, -1, attacher.targetProcFD)
	assert.Zero(t, attacher.targetPID)
	assert.Zero(t, attacher.targetStart)
}

func TestJAttacherUsesStableProcFDWhenPIDFDOpenIsUnavailable(t *testing.T) {
	start, err := procs.ProcessStartTime(app.PID(os.Getpid()))
	require.NoError(t, err)
	originalOpen := openJVMTargetPIDFD
	originalSignal := signalJVMTargetPIDFD
	openJVMTargetPIDFD = func(int, int) (int, error) {
		return -1, unix.ENOSYS
	}
	var signalFDs []int
	var signals []syscall.Signal
	signalJVMTargetPIDFD = func(fd int, signal syscall.Signal, _ *unix.Siginfo, _ int) error {
		signalFDs = append(signalFDs, fd)
		signals = append(signals, signal)
		return nil
	}
	t.Cleanup(func() {
		openJVMTargetPIDFD = originalOpen
		signalJVMTargetPIDFD = originalSignal
	})
	attacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)), 0, nil)

	require.NoError(t, attacher.BindTarget(os.Getpid(), start))
	assert.Equal(t, -1, attacher.targetPIDFD)
	assert.GreaterOrEqual(t, attacher.targetProcFD, 0)
	require.NoError(t, attacher.signalTarget(os.Getpid(), syscall.SIGQUIT))
	require.Len(t, signalFDs, 5)
	for _, fd := range signalFDs {
		assert.Equal(t, attacher.targetProcFD, fd)
	}
	assert.Equal(t, []syscall.Signal{0, 0, 0, 0, syscall.SIGQUIT}, signals)
	require.NoError(t, attacher.CloseTarget())
}

func TestJAttacherFailsClosedWithoutExactSignalSupport(t *testing.T) {
	start, err := procs.ProcessStartTime(app.PID(os.Getpid()))
	require.NoError(t, err)
	originalOpen := openJVMTargetPIDFD
	originalSignal := signalJVMTargetPIDFD
	openJVMTargetPIDFD = func(int, int) (int, error) { return -1, unix.ENOSYS }
	signalJVMTargetPIDFD = func(int, syscall.Signal, *unix.Siginfo, int) error {
		return unix.ENOSYS
	}
	t.Cleanup(func() {
		openJVMTargetPIDFD = originalOpen
		signalJVMTargetPIDFD = originalSignal
	})
	attacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)), 0, nil)

	err = attacher.BindTarget(os.Getpid(), start)
	require.ErrorIs(t, err, unix.ENOSYS)
	require.ErrorContains(t, err, "requires kernel pidfd_send_signal support")
	assert.Equal(t, -1, attacher.targetPIDFD)
	assert.Equal(t, -1, attacher.targetProcFD)
}

func TestValidateOpenJ9PeerRequiresAnonymousPIDFD(t *testing.T) {
	start, err := procs.ProcessStartTime(app.PID(os.Getpid()))
	require.NoError(t, err)
	originalOpen := openJVMTargetPIDFD
	originalSignal := signalJVMTargetPIDFD
	openJVMTargetPIDFD = func(int, int) (int, error) { return -1, unix.ENOSYS }
	signalJVMTargetPIDFD = func(int, syscall.Signal, *unix.Siginfo, int) error {
		return nil
	}
	t.Cleanup(func() {
		openJVMTargetPIDFD = originalOpen
		signalJVMTargetPIDFD = originalSignal
	})
	attacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)), 0, nil)
	require.NoError(t, attacher.BindTarget(os.Getpid(), start))
	t.Cleanup(func() { require.NoError(t, attacher.CloseTarget()) })
	require.Equal(t, -1, attacher.targetPIDFD)

	err = attacher.validateOpenJ9Peer(t.Context(), -1)
	require.ErrorIs(t, err, errOpenJ9PeerVerificationUnavailable)
}

func TestStableProcFDDoesNotFollowExitedTarget(t *testing.T) {
	process := exec.Command("sh", "-c", "sleep 30")
	require.NoError(t, process.Start())
	processExited := false
	t.Cleanup(func() {
		if !processExited {
			_ = process.Process.Kill()
			_ = process.Wait()
		}
	})
	start, err := procs.ProcessStartTime(app.PID(process.Process.Pid))
	require.NoError(t, err)
	originalOpen := openJVMTargetPIDFD
	openJVMTargetPIDFD = func(int, int) (int, error) { return -1, unix.ENOSYS }
	t.Cleanup(func() { openJVMTargetPIDFD = originalOpen })
	attacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)), 0, nil)
	require.NoError(t, attacher.BindTarget(process.Process.Pid, start))
	t.Cleanup(func() { require.NoError(t, attacher.CloseTarget()) })

	require.NoError(t, process.Process.Kill())
	require.Error(t, process.Wait())
	processExited = true
	err = attacher.ValidateTarget()
	require.Error(t, err)
}

func TestValidateHotspotPeerRequiresExactHostPID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "attach.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	accepted := make(chan *net.UnixConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := listener.AcceptUnix()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()
	client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	var server *net.UnixConn
	select {
	case err := <-acceptErr:
		require.NoError(t, err)
	case server = <-accepted:
	}
	require.NotNil(t, server)
	t.Cleanup(func() { _ = server.Close() })

	require.NoError(t, validateHotspotPeer(server, os.Getpid()))
	require.ErrorContains(t, validateHotspotPeer(server, os.Getpid()+1), "does not match exact target")
}

func tcpConnectionFD(t *testing.T, connection *net.TCPConn) int {
	t.Helper()
	raw, err := connection.SyscallConn()
	require.NoError(t, err)
	fd := -1
	require.NoError(t, raw.Control(func(current uintptr) {
		fd = int(current)
	}))
	require.GreaterOrEqual(t, fd, 0)
	return fd
}

func duplicateTCPConnectionFD(t *testing.T, connection *net.TCPConn) int {
	t.Helper()
	fd := tcpConnectionFD(t, connection)
	duplicate, err := unix.Dup(fd)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(duplicate) })
	return duplicate
}

func openJ9TCPPair(t *testing.T) (client, server *net.TCPConn) {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	client, err = net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	server, err = listener.AcceptTCP()
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}

func TestOpenJ9CandidateRequiresTCPStreamProtocol(t *testing.T) {
	client, _ := openJ9TCPPair(t)
	tcp, err := openJ9TCPStream(tcpConnectionFD(t, client))
	require.NoError(t, err)
	require.True(t, tcp)

	udp, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(udp) })
	tcp, err = openJ9TCPStream(udp)
	require.NoError(t, err)
	require.False(t, tcp)
}

func TestCurrentOpenJ9TCPSocketDiagnosticMatchesExactCookie(t *testing.T) {
	client, _ := openJ9TCPPair(t)
	fd := tcpConnectionFD(t, client)
	local, peer, err := openJ9SocketEndpoints(fd)
	require.NoError(t, err)
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	require.NoError(t, err)

	matched, err := currentOpenJ9TCPSocketDiagnostic(
		t.Context(), local, peer, cookie,
	)
	require.NoError(t, err)
	require.True(t, matched)

	matched, err = currentOpenJ9TCPSocketDiagnostic(
		t.Context(), local, peer, cookie+1,
	)
	require.NoError(t, err)
	require.False(t, matched)
}

func openJ9DiagnosticForConnection(
	t *testing.T, connection *net.TCPConn,
) openJ9TCPSocketDiagnostic {
	t.Helper()
	fd := tcpConnectionFD(t, connection)
	local, peer, err := openJ9SocketEndpoints(fd)
	require.NoError(t, err)
	domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	require.NoError(t, err)
	require.Equal(t, local.family, domain)
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	require.NoError(t, err)
	return openJ9TCPSocketDiagnostic{
		local:  local,
		peer:   peer,
		state:  openJ9TCPStateEstablished,
		cookie: cookie,
	}
}

func stubOpenJ9SocketDiagnostics(
	t *testing.T,
	diagnostics []openJ9TCPSocketDiagnostic,
	diagnosticErr error,
) {
	t.Helper()
	originalDiagnose := diagnoseOpenJ9TCPSocket
	diagnoseOpenJ9TCPSocket = func(
		ctx context.Context,
		local, peer inetEndpoint,
		cookie uint64,
	) (bool, error) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if diagnosticErr != nil {
			return false, diagnosticErr
		}
		for _, diagnostic := range diagnostics {
			if diagnostic.state == openJ9TCPStateEstablished &&
				diagnostic.local == local && diagnostic.peer == peer &&
				diagnostic.cookie == cookie {
				return true, nil
			}
		}
		return false, nil
	}
	t.Cleanup(func() { diagnoseOpenJ9TCPSocket = originalDiagnose })
}

func TestValidateOpenJ9PeerPinsExactTargetSocket(t *testing.T) {
	start, err := procs.ProcessStartTime(app.PID(os.Getpid()))
	require.NoError(t, err)
	attacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)), 0, nil)
	require.NoError(t, bindCurrentProcess(t, attacher, start))
	requireAnonymousPIDFD(t, attacher)
	t.Cleanup(func() { require.NoError(t, attacher.CloseTarget()) })

	client, server := openJ9TCPPair(t)
	clientFD := tcpConnectionFD(t, client)
	serverFD := duplicateTCPConnectionFD(t, server)
	stubOpenJ9SocketDiagnostics(
		t, []openJ9TCPSocketDiagnostic{openJ9DiagnosticForConnection(t, client)}, nil,
	)
	originalDuplicate := duplicateJVMTargetFD
	duplicateJVMTargetFD = func(_ int, targetFD int, _ int) (int, error) {
		if targetFD != clientFD {
			return -1, unix.EBADF
		}
		return unix.Dup(clientFD)
	}
	t.Cleanup(func() { duplicateJVMTargetFD = originalDuplicate })

	require.NoError(t, attacher.validateOpenJ9Peer(t.Context(), serverFD))
}

func TestValidateOpenJ9PeerRejectsSameTupleWithDifferentSocketCookie(t *testing.T) {
	start, err := procs.ProcessStartTime(app.PID(os.Getpid()))
	require.NoError(t, err)
	attacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)), 0, nil)
	require.NoError(t, bindCurrentProcess(t, attacher, start))
	requireAnonymousPIDFD(t, attacher)
	t.Cleanup(func() { require.NoError(t, attacher.CloseTarget()) })

	client, server := openJ9TCPPair(t)
	clientFD := tcpConnectionFD(t, client)
	serverFD := duplicateTCPConnectionFD(t, server)
	diagnostic := openJ9DiagnosticForConnection(t, client)
	diagnostic.cookie++
	stubOpenJ9SocketDiagnostics(t, []openJ9TCPSocketDiagnostic{diagnostic}, nil)
	originalDuplicate := duplicateJVMTargetFD
	duplicateJVMTargetFD = func(_ int, targetFD int, _ int) (int, error) {
		if targetFD != clientFD {
			return -1, unix.EBADF
		}
		return unix.Dup(clientFD)
	}
	t.Cleanup(func() { duplicateJVMTargetFD = originalDuplicate })

	err = attacher.validateOpenJ9Peer(t.Context(), serverFD)
	require.ErrorIs(t, err, errOpenJ9PeerMismatch)
}

func TestVerifyOpenJ9CandidatePreservesCallerCancellation(t *testing.T) {
	client, server := openJ9TCPPair(t)
	clientFD := tcpConnectionFD(t, client)
	serverFD := tcpConnectionFD(t, server)

	ctx, cancel := context.WithCancel(t.Context())
	originalDiagnose := diagnoseOpenJ9TCPSocket
	diagnoseOpenJ9TCPSocket = func(
		context.Context, inetEndpoint, inetEndpoint, uint64,
	) (bool, error) {
		cancel()
		return false, ctx.Err()
	}
	t.Cleanup(func() { diagnoseOpenJ9TCPSocket = originalDiagnose })

	matched, err := verifyOpenJ9CandidateInCurrentNetNS(
		ctx, serverFD, clientFD,
	)
	require.False(t, matched)
	require.ErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, errOpenJ9PeerVerificationUnavailable)
}

func TestValidateOpenJ9PeerFailsClosedWithoutSocketDiagnostics(t *testing.T) {
	start, err := procs.ProcessStartTime(app.PID(os.Getpid()))
	require.NoError(t, err)
	attacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)), 0, nil)
	require.NoError(t, bindCurrentProcess(t, attacher, start))
	requireAnonymousPIDFD(t, attacher)
	t.Cleanup(func() { require.NoError(t, attacher.CloseTarget()) })

	client, server := openJ9TCPPair(t)
	clientFD := tcpConnectionFD(t, client)
	serverFD := duplicateTCPConnectionFD(t, server)
	stubOpenJ9SocketDiagnostics(t, nil, unix.EPERM)
	originalDuplicate := duplicateJVMTargetFD
	duplicateJVMTargetFD = func(_ int, targetFD int, _ int) (int, error) {
		if targetFD != clientFD {
			return -1, unix.EBADF
		}
		return unix.Dup(clientFD)
	}
	t.Cleanup(func() { duplicateJVMTargetFD = originalDuplicate })

	err = attacher.validateOpenJ9Peer(t.Context(), serverFD)
	require.ErrorIs(t, err, errOpenJ9PeerVerificationUnavailable)
}

func TestValidateOpenJ9PeerRejectsSocketOutsideTarget(t *testing.T) {
	start, err := procs.ProcessStartTime(app.PID(os.Getpid()))
	require.NoError(t, err)
	attacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)), 0, nil)
	require.NoError(t, bindCurrentProcess(t, attacher, start))
	requireAnonymousPIDFD(t, attacher)
	t.Cleanup(func() { require.NoError(t, attacher.CloseTarget()) })

	_, server := openJ9TCPPair(t)
	serverFD := duplicateTCPConnectionFD(t, server)
	originalDuplicate := duplicateJVMTargetFD
	duplicateJVMTargetFD = func(int, int, int) (int, error) {
		return -1, unix.EBADF
	}
	t.Cleanup(func() { duplicateJVMTargetFD = originalDuplicate })

	err = attacher.validateOpenJ9Peer(t.Context(), serverFD)
	require.ErrorIs(t, err, errOpenJ9PeerMismatch)
}

func TestValidateOpenJ9PeerFailsClosedWithoutPIDFDGetFD(t *testing.T) {
	start, err := procs.ProcessStartTime(app.PID(os.Getpid()))
	require.NoError(t, err)
	attacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)), 0, nil)
	require.NoError(t, bindCurrentProcess(t, attacher, start))
	requireAnonymousPIDFD(t, attacher)
	t.Cleanup(func() { require.NoError(t, attacher.CloseTarget()) })

	_, server := openJ9TCPPair(t)
	serverFD := duplicateTCPConnectionFD(t, server)
	originalDuplicate := duplicateJVMTargetFD
	duplicateJVMTargetFD = func(int, int, int) (int, error) {
		return -1, unix.ENOSYS
	}
	t.Cleanup(func() { duplicateJVMTargetFD = originalDuplicate })

	err = attacher.validateOpenJ9Peer(t.Context(), serverFD)
	require.ErrorIs(t, err, errOpenJ9PeerVerificationUnavailable)
}

func TestOpenJ9VerificationRestoresPrivilegesForPIDFDGetFD(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required to exercise root-to-nonroot pidfd_getfd verification")
	}

	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	require.NoError(t, err)
	server, err := listener.AcceptTCP()
	require.NoError(t, err)
	t.Cleanup(func() { _ = server.Close() })
	clientFile, err := client.File()
	require.NoError(t, err)
	require.NoError(t, client.Close())

	const targetID = 65534
	process := exec.Command("/bin/sleep", "30")
	process.ExtraFiles = []*os.File{clientFile}
	process.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:         targetID,
			Gid:         targetID,
			NoSetGroups: true,
		},
		Pdeathsig: syscall.SIGKILL,
	}
	if err := process.Start(); err != nil {
		require.NoError(t, clientFile.Close())
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("environment denies root-to-nonroot helper startup: %v", err)
		}
		require.NoError(t, err)
	}
	require.NoError(t, clientFile.Close())
	processExited := false
	t.Cleanup(func() {
		if !processExited {
			_ = process.Process.Kill()
			_ = process.Wait()
		}
	})
	_, err = os.Readlink(fmt.Sprintf("/proc/%d/fd/3", process.Process.Pid))
	require.NoError(t, err)

	start, err := procs.ProcessStartTime(app.PID(process.Process.Pid))
	require.NoError(t, err)
	attacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)), 0, nil)
	attacher.Init()
	require.NoError(t, attacher.BindTarget(process.Process.Pid, start))
	t.Cleanup(func() { require.NoError(t, attacher.CloseTarget()) })
	if attacher.targetPIDFD < 0 {
		t.Skip("anonymous pidfd is unavailable")
	}

	type duplicateResult struct {
		fd               int
		beforeRestoreErr error
		err              error
	}
	resultCh := make(chan duplicateResult, 1)
	go func() {
		runtime.LockOSThread()
		// Never unlock the thread after changing credentials; the runtime will
		// destroy it when this goroutine returns, as in the production path.
		if err := setThreadCredentials(targetID, targetID); err != nil {
			resultCh <- duplicateResult{fd: -1, err: err}
			return
		}
		beforeRestore, beforeRestoreErr := unix.PidfdGetfd(attacher.targetPIDFD, 3, 0)
		if beforeRestore >= 0 {
			_ = unix.Close(beforeRestore)
		}
		if err := setThreadCredentials(attacher.myUID, attacher.myGID); err != nil {
			resultCh <- duplicateResult{
				fd: -1, beforeRestoreErr: beforeRestoreErr, err: err,
			}
			return
		}
		fd, err := unix.PidfdGetfd(attacher.targetPIDFD, 3, 0)
		resultCh <- duplicateResult{
			fd: fd, beforeRestoreErr: beforeRestoreErr, err: err,
		}
	}()
	result := <-resultCh
	require.ErrorIs(t, result.beforeRestoreErr, unix.EPERM)
	if errors.Is(result.err, unix.EPERM) || errors.Is(result.err, unix.EACCES) ||
		errors.Is(result.err, unix.ENOSYS) {
		t.Skipf("environment denies pidfd_getfd despite restored root credentials: %v", result.err)
	}
	require.NoError(t, result.err)
	require.GreaterOrEqual(t, result.fd, 0)
	t.Cleanup(func() { _ = unix.Close(result.fd) })

	serverFD := duplicateTCPConnectionFD(t, server)
	matched, err := verifyOpenJ9CandidateInCurrentNetNS(
		t.Context(), serverFD, result.fd,
	)
	require.NoError(t, err)
	require.True(t, matched)

	require.NoError(t, process.Process.Kill())
	require.Error(t, process.Wait())
	processExited = true
}

func TestAttachCredentialsRemainLocalToSacrificialThread(t *testing.T) {
	const helperEnv = "OBI_TEST_THREAD_LOCAL_ATTACH_CREDENTIALS"
	if os.Getenv(helperEnv) == "" {
		if os.Geteuid() != 0 {
			t.Skip("changing to a distinct effective UID requires root")
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestAttachCredentialsRemainLocalToSacrificialThread$")
		cmd.Env = append(os.Environ(), helperEnv+"=1")
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "credential isolation helper failed: %s", output)
		return
	}

	runtime.GOMAXPROCS(2)
	observerReady := make(chan struct{})
	credentialsChanged := make(chan struct{})
	releaseThreads := make(chan struct{})
	observedEUID := make(chan int, 1)
	changeErr := make(chan error, 1)
	done := make(chan struct{}, 2)

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		close(observerReady)
		<-credentialsChanged
		euid, _, errno := unix.RawSyscall(unix.SYS_GETEUID, 0, 0, 0)
		if errno != 0 {
			observedEUID <- -1
		} else {
			observedEUID <- int(euid)
		}
		<-releaseThreads
		done <- struct{}{}
	}()

	go func() {
		<-observerReady
		runtime.LockOSThread()
		// Deliberately do not unlock this tainted thread. The runtime destroys
		// it when the goroutine returns, matching the production attach path.
		changeErr <- setThreadCredentials(65534, 65534)
		close(credentialsChanged)
		<-releaseThreads
		done <- struct{}{}
	}()

	require.NoError(t, <-changeErr)
	assert.Zero(t, <-observedEUID, "observer thread inherited target credentials")
	close(releaseThreads)
	<-done
	<-done
}
