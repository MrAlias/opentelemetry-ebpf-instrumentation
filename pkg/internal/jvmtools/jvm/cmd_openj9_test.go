// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package jvm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestNewJ9AttacherUsesNegativeFDSentinel(t *testing.T) {
	attacher := newJ9Attacher(slog.Default())

	if attacher.fd >= 0 {
		t.Fatalf("expected negative fd sentinel, got %d", attacher.fd)
	}
}

func TestWriteCommandPreservesSyscallError(t *testing.T) {
	err := writeCommand(-1, "ATTACH_DETACHED")

	if !errors.Is(err, syscall.EBADF) {
		t.Fatalf("expected EBADF, got %v", err)
	}
}

func TestJ9ReaderReadReturnsZeroCountOnSyscallError(t *testing.T) {
	attacher := newJ9Attacher(slog.Default())
	attacher.fd = 1 << 30

	n, err := (&j9Reader{attacher: attacher}).Read(make([]byte, 1))
	if n != 0 {
		t.Fatalf("expected zero byte count, got %d", n)
	}
	if !errors.Is(err, syscall.EBADF) {
		t.Fatalf("expected EBADF, got %v", err)
	}
}

func TestAcquireOpenJ9LockStopsAtContextDeadline(t *testing.T) {
	tmpPath := t.TempDir()
	lockDir := filepath.Join(tmpPath, ".com_ibm_tools_attach")
	require.NoError(t, os.MkdirAll(lockDir, 0o700))
	lockPath := filepath.Join(lockDir, "_attachlock")
	locked, err := syscall.Open(lockPath, syscall.O_WRONLY|syscall.O_CREAT, 0o600)
	require.NoError(t, err)
	t.Cleanup(func() { _ = syscall.Close(locked) })
	require.NoError(t, syscall.Flock(locked, syscall.LOCK_EX|syscall.LOCK_NB))

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	fd, err := acquireLock(ctx, tmpPath, "", "_attachlock")

	require.Equal(t, -1, fd)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestAcceptOpenJ9ClientStopsAtContextDeadline(t *testing.T) {
	listener, _, err := createAttachSocket()
	if errors.Is(err, syscall.EPERM) {
		t.Skip("sandbox does not permit creating an OpenJ9 attach listener")
	}
	require.NoError(t, err)
	t.Cleanup(func() { _ = syscall.Close(listener) })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	fd, err := acceptClient(ctx, listener, 1)

	require.Equal(t, -1, fd)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestAcceptOpenJ9ClientRejectsDecoyAndContinues(t *testing.T) {
	listener, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = syscall.Close(listener) })
	require.NoError(t, unix.Bind(listener, &unix.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{127, 0, 0, 1},
	}))
	require.NoError(t, unix.Listen(listener, 8))
	address, err := unix.Getsockname(listener)
	require.NoError(t, err)
	port := address.(*unix.SockaddrInet4).Port

	const key = uint64(0x1234)
	handshake := append(
		[]byte(fmt.Sprintf("ATTACH_CONNECTED %016x ", key)),
		0,
	)
	wrong, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err)
	t.Cleanup(func() { _ = wrong.Close() })
	_, err = wrong.Write(handshake)
	require.NoError(t, err)
	right, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err)
	t.Cleanup(func() { _ = right.Close() })
	_, err = right.Write(handshake)
	require.NoError(t, err)

	validationCalls := 0
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	accepted, err := acceptClient(ctx, listener, key, func(int) error {
		validationCalls++
		if validationCalls == 1 {
			return errOpenJ9PeerMismatch
		}
		return nil
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = syscall.Close(accepted) })
	require.Equal(t, 2, validationCalls)
}

func TestAcceptOpenJ9ClientAuthenticatesBeforeExactPeerScan(t *testing.T) {
	listener, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = syscall.Close(listener) })
	require.NoError(t, unix.Bind(listener, &unix.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{127, 0, 0, 1},
	}))
	require.NoError(t, unix.Listen(listener, 8))
	address, err := unix.Getsockname(listener)
	require.NoError(t, err)
	port := address.(*unix.SockaddrInet4).Port

	const key = uint64(0x1234)
	wrong, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err)
	t.Cleanup(func() { _ = wrong.Close() })
	_, err = wrong.Write(make([]byte, 35))
	require.NoError(t, err)
	right, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err)
	t.Cleanup(func() { _ = right.Close() })
	handshake := append(
		[]byte(fmt.Sprintf("ATTACH_CONNECTED %016x ", key)),
		0,
	)
	_, err = right.Write(handshake)
	require.NoError(t, err)

	validationCalls := 0
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	accepted, err := acceptClient(ctx, listener, key, func(int) error {
		validationCalls++
		return nil
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = syscall.Close(accepted) })
	require.Equal(t, 1, validationCalls)
}

func TestAcceptOpenJ9ClientBoundsUnauthenticatedHandshake(t *testing.T) {
	listener, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = syscall.Close(listener) })
	require.NoError(t, unix.Bind(listener, &unix.SockaddrInet4{
		Port: 0,
		Addr: [4]byte{127, 0, 0, 1},
	}))
	require.NoError(t, unix.Listen(listener, 8))
	address, err := unix.Getsockname(listener)
	require.NoError(t, err)
	port := address.(*unix.SockaddrInet4).Port

	originalTimeout := openJ9HandshakeTimeout
	openJ9HandshakeTimeout = 20 * time.Millisecond
	t.Cleanup(func() { openJ9HandshakeTimeout = originalTimeout })
	slow, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err)
	t.Cleanup(func() { _ = slow.Close() })

	const key = uint64(0x1234)
	right, err := net.Dial("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	require.NoError(t, err)
	t.Cleanup(func() { _ = right.Close() })
	handshake := append(
		[]byte(fmt.Sprintf("ATTACH_CONNECTED %016x ", key)),
		0,
	)
	_, err = right.Write(handshake)
	require.NoError(t, err)

	validationCalls := 0
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	accepted, err := acceptClient(ctx, listener, key, func(int) error {
		validationCalls++
		return nil
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = syscall.Close(accepted) })
	require.Equal(t, 1, validationCalls)
}

func TestJ9ReaderAndDetachStopAtContextDeadline(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = syscall.Close(fds[1]) })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	attacher := newJ9Attacher(slog.Default())
	attacher.fd = fds[0]
	reader := &j9Reader{attacher: attacher, ctx: ctx}

	_, err = reader.Read(make([]byte, 1))
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NoError(t, reader.Close())
	require.Equal(t, -1, attacher.fd)
}

func TestNotifySemaphoreHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := notifySemaphore(ctx, t.TempDir(), 1, 1)

	require.ErrorIs(t, err, context.Canceled)
}

func TestNotifySemaphoreDoesNotBlockWhenSaturated(t *testing.T) {
	tmpPath := t.TempDir()
	attachDir := filepath.Join(tmpPath, ".com_ibm_tools_attach")
	require.NoError(t, os.MkdirAll(attachDir, 0o700))
	notifierPath := filepath.Join(attachDir, "_notifier")
	require.NoError(t, os.WriteFile(notifierPath, nil, 0o600))

	semKey, err := ftok(notifierPath, 0xa1)
	require.NoError(t, err)
	semID, err := semget(semKey, 1, unix.IPC_CREAT|unix.IPC_EXCL|0o600)
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.ENOSPC) {
		t.Skipf("system V semaphores are unavailable: %v", err)
	}
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _, errno := unix.Syscall6(
			unix.SYS_SEMCTL,
			uintptr(semID),
			0,
			uintptr(unix.IPC_RMID),
			0,
			0,
			0,
		)
		require.Zero(t, errno)
	})

	const maxSemaphoreValue = int16(1<<15 - 1)
	require.NoError(t, semop(semID, []sembuf{createSembuf(0, maxSemaphoreValue, 0)}))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = notifySemaphore(ctx, tmpPath, 1, 1)

	require.ErrorIs(t, err, unix.ERANGE)
	require.NoError(t, ctx.Err())
}
