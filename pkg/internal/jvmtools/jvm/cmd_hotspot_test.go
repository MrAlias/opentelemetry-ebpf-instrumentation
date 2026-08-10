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
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

func TestAttachContextReturnsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	attacher := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)))

	out, err := attacher.AttachContext(ctx, os.Getpid(), []string{"jcmd"}, true)
	require.Nil(t, out)
	require.ErrorIs(t, err, context.Canceled)
}

func TestStartAttachMechanismStopsOnContextCancellationAndRemovesAttachFile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tmpPath := t.TempDir()
	signal.Ignore(syscall.SIGQUIT)
	defer signal.Reset(syscall.SIGQUIT)

	pid := os.Getpid()
	nspid := 9_999_992
	attachPid := 9_999_993
	attachFile := filepath.Join(tmpPath, fmt.Sprintf(".attach_pid%d", nspid))

	errCh := make(chan error, 1)
	go func() {
		errCh <- startAttachMechanism(ctx, pid, nspid, attachPid, tmpPath)
	}()

	require.Eventually(t, func() bool {
		_, err := os.Stat(attachFile)
		return err == nil
	}, time.Second, time.Millisecond)

	cancel()

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for startAttachMechanism to stop")
	}

	_, err := os.Stat(attachFile)
	require.True(t, os.IsNotExist(err), "attach file should be removed, stat error: %v", err)
}

func TestWriteHotspotCommandClosesSocketOnContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn := newBlockingConn()
	errCh := make(chan error, 1)
	go func() {
		errCh <- writeHotspotCommand(ctx, conn, []string{"jcmd"})
	}()

	select {
	case <-conn.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for socket write to start")
	}

	cancel()

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for writeHotspotCommand to stop")
	}

	select {
	case <-conn.closed:
	default:
		t.Fatal("expected canceled context to close the socket")
	}
}

func TestHotspotFallbackStillValidatesExactPeer(t *testing.T) {
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
	target := NewJAttacher(slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, target.BindTarget(os.Getpid(), start))
	t.Cleanup(func() { require.NoError(t, target.CloseTarget()) })
	require.Equal(t, -1, target.targetPIDFD)

	const namespacePID = 9_999_990
	path := filepath.Join(t.TempDir(), fmt.Sprintf(".java_pid%d", namespacePID))
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan struct{})
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr == nil {
			_ = connection.Close()
		}
		close(accepted)
	}()

	peerErr := errors.New("test exact-peer rejection")
	originalValidatePeer := validateHotspotSocketPeer
	validationCalls := 0
	validateHotspotSocketPeer = func(_ net.Conn, expectedPID int) error {
		validationCalls++
		require.Equal(t, expectedPID, os.Getpid())
		return peerErr
	}
	t.Cleanup(func() { validateHotspotSocketPeer = originalValidatePeer })

	reader, err := jattachHotspot(
		t.Context(), os.Getpid(), namespacePID, os.Getpid(),
		[]string{"jcmd"}, filepath.Dir(path),
		slog.New(slog.NewTextHandler(io.Discard, nil)), target,
	)
	require.Nil(t, reader)
	require.ErrorIs(t, err, peerErr)
	require.Equal(t, 1, validationCalls)
	<-accepted
}

type blockingConn struct {
	writeStarted chan struct{}
	closed       chan struct{}
	startOnce    sync.Once
	closeOnce    sync.Once
}

func newBlockingConn() *blockingConn {
	return &blockingConn{
		writeStarted: make(chan struct{}),
		closed:       make(chan struct{}),
	}
}

func (c *blockingConn) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (c *blockingConn) Write(_ []byte) (int, error) {
	c.startOnce.Do(func() {
		close(c.writeStarted)
	})
	<-c.closed
	return 0, net.ErrClosed
}

func (c *blockingConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
	})
	return nil
}

func (c *blockingConn) LocalAddr() net.Addr {
	return testAddr("local")
}

func (c *blockingConn) RemoteAddr() net.Addr {
	return testAddr("remote")
}

func (c *blockingConn) SetDeadline(_ time.Time) error {
	return nil
}

func (c *blockingConn) SetReadDeadline(_ time.Time) error {
	return nil
}

func (c *blockingConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

type testAddr string

func (a testAddr) Network() string {
	return string(a)
}

func (a testAddr) String() string {
	return string(a)
}
