// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javabridge

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type staticResolver struct {
	identity Identity
	err      error
}

func (r staticResolver) Resolve(context.Context, int32, uint32) (Identity, error) {
	return r.identity, r.err
}

type namespaceResolver struct {
	namespaceTID uint32
	identity     Identity
}

func (r namespaceResolver) Resolve(
	_ context.Context, _ int32, namespaceTID uint32,
) (Identity, error) {
	if namespaceTID != r.namespaceTID {
		return Identity{}, errors.New("namespace thread is not owned by peer")
	}
	return r.identity, nil
}

type fakeRateClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeRateClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeRateClock) Advance(elapsed time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(elapsed)
}

type timeoutResolver struct{}

func (timeoutResolver) Resolve(ctx context.Context, _ int32, _ uint32) (Identity, error) {
	if _, ok := ctx.Deadline(); !ok {
		return Identity{}, context.Canceled
	}
	return Identity{}, context.DeadlineExceeded
}

type validAfterCancellationResolver struct {
	identity Identity
	started  chan struct{}
}

func (r validAfterCancellationResolver) Resolve(
	ctx context.Context, _ int32, _ uint32,
) (Identity, error) {
	close(r.started)
	<-ctx.Done()
	return r.identity, nil
}

type calledResolver struct {
	called atomic.Bool
}

func (r *calledResolver) Resolve(context.Context, int32, uint32) (Identity, error) {
	r.called.Store(true)
	return Identity{}, nil
}

type cancelAfterContext struct {
	context.Context
	cancelAt int
	checks   int
}

func (c *cancelAfterContext) Err() error {
	c.checks++
	if c.checks >= c.cancelAt {
		return context.Canceled
	}
	return nil
}

type recordingHandler struct {
	mu          sync.Mutex
	calls       atomic.Int32
	identity    Identity
	operation   Operation
	incarnation uint64
	record      Record
}

type observedOutcome struct {
	operation Operation
	status    Status
}

func (h *recordingHandler) HandleAuthenticated(
	_ context.Context, identity Identity, operation Operation, incarnation uint64,
) Record {
	h.calls.Add(1)
	h.mu.Lock()
	defer h.mu.Unlock()
	h.identity = identity
	h.operation = operation
	h.incarnation = incarnation
	return h.record
}

func TestFallbackServerAuthenticatesAndHandlesRequest(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "bridge.sock")
	identity := Identity{TID: 7, PID: 5, Namespace: 3}
	handler := &recordingHandler{record: Record{Status: StatusValid}}
	handler.record.TraceID[15] = 1
	handler.record.SpanID[7] = 1
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		SocketGID:  -1,
		Timeout:    time.Second,
		Resolver:   staticResolver{identity: identity},
	}, handler)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})

	request, err := (Request{
		Operation:          OperationTake,
		NamespaceTID:       7,
		ProcessIncarnation: 11,
	}).MarshalBinary()
	require.NoError(t, err)
	response := fallbackRoundTrip(t, socketPath, request)
	assert.Equal(t, StatusValid, response.Status)

	handler.mu.Lock()
	defer handler.mu.Unlock()
	assert.Equal(t, identity, handler.identity)
	assert.Equal(t, OperationTake, handler.operation)
	assert.Equal(t, uint64(11), handler.incarnation)
}

func TestFallbackServerRateLimitsSequentialFloodAndRecovers(t *testing.T) {
	const namespaceTID = uint32(3)
	identity := Identity{TID: namespaceTID, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{identity: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	socketPath := filepath.Join(t.TempDir(), "bridge.sock")
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		SocketGID:  -1,
		Timeout:    time.Second,
		Resolver: namespaceResolver{
			namespaceTID: namespaceTID,
			identity:     identity,
		},
	}, handler)
	require.NoError(t, err)
	clock := &fakeRateClock{now: time.Unix(100, 0)}
	server.rateNow = clock.Now
	server.rateWindow = time.Second
	server.maxRateRequests = 4
	server.maxPeerRate = 2
	server.maxRatePeers = 1
	serveFallbackServer(t, server)

	malformed := make([]byte, RequestSize)
	for range 2 {
		assert.Equal(t, StatusMalformed, fallbackRoundTrip(t, socketPath, malformed).Status)
	}
	assert.Equal(t, StatusOverload, fallbackRoundTrip(t, socketPath, malformed).Status)

	request, err := (Request{
		Operation:          OperationTake,
		NamespaceTID:       namespaceTID,
		ProcessIncarnation: testProcessIncarnation,
	}).MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, StatusOverload, fallbackRoundTrip(t, socketPath, request).Status)
	assert.Len(t, handler.remoteParents.(*fakeBridgeMap).values, 1)

	clock.Advance(time.Second)
	assert.Equal(t, StatusValid, fallbackRoundTrip(t, socketPath, request).Status)
	assert.Equal(t, StatusAlreadyConsumed, fallbackRoundTrip(t, socketPath, request).Status)
}

func TestFallbackServerRateLimiterBoundsPeerStateAndRecovers(t *testing.T) {
	server, err := NewServer(ServerOptions{
		SocketPath: filepath.Join(t.TempDir(), "bridge.sock"),
		SocketGID:  -1,
		Timeout:    time.Second,
	}, &recordingHandler{})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, server.Close()) })

	clock := &fakeRateClock{now: time.Unix(100, 0)}
	server.rateNow = clock.Now
	server.rateWindow = time.Second
	server.maxRateRequests = 4
	server.maxPeerRate = 2
	server.maxRatePeers = 4

	admit := func(peerPID int32) bool {
		if !server.acquirePreAuth(peerPID) {
			return false
		}
		server.releasePreAuth()
		server.releaseRequest(peerPID)
		return true
	}

	assert.True(t, admit(1))
	assert.True(t, admit(1))
	assert.False(t, admit(1))
	assert.Equal(t, 2, server.rateRequests)
	assert.True(t, admit(2))
	assert.True(t, admit(3))
	assert.False(t, admit(4))
	assert.Equal(t, 4, server.rateRequests)
	assert.Len(t, server.peerRateRequests, 3)

	clock.Advance(time.Second)
	server.maxPeerRate = 4
	for peerPID := int32(4); peerPID <= 7; peerPID++ {
		assert.True(t, admit(peerPID))
	}
	assert.False(t, admit(8))
	assert.Len(t, server.peerRateRequests, 4)

	clock.Advance(time.Second)
	assert.True(t, admit(8))
	assert.Equal(t, 1, server.rateRequests)
	assert.Equal(t, map[int32]int{8: 1}, server.peerRateRequests)
}

func TestFallbackServerRejectsEveryPartialRequest(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "bridge.sock")
	handler := &recordingHandler{}
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		SocketGID:  -1,
		Timeout:    time.Second,
		Resolver:   staticResolver{},
	}, handler)
	require.NoError(t, err)
	serveFallbackServer(t, server)

	request, err := (Request{
		Operation:          OperationTake,
		NamespaceTID:       7,
		ProcessIncarnation: 11,
	}).MarshalBinary()
	require.NoError(t, err)
	for size := 1; size < int(RequestSize); size++ {
		t.Run(fmt.Sprintf("%d_bytes", size), func(t *testing.T) {
			conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
			require.NoError(t, err)
			defer conn.Close()
			require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
			_, err = conn.Write(request[:size])
			require.NoError(t, err)
			require.NoError(t, conn.CloseWrite())

			response := readFallbackRecord(t, conn)
			assert.Equal(t, StatusMalformed, response.Status)
		})
	}
	assert.Zero(t, handler.calls.Load())
}

func TestFallbackServerUsesOneRequestPrefixPerConnection(t *testing.T) {
	request, err := (Request{
		Operation:          OperationTake,
		NamespaceTID:       7,
		ProcessIncarnation: 11,
	}).MarshalBinary()
	require.NoError(t, err)

	tests := []struct {
		name    string
		trailer []byte
	}{
		{name: "trailing bytes", trailer: []byte{0xaa, 0xbb, 0xcc}},
		{name: "repeated request", trailer: request},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			socketPath := filepath.Join(t.TempDir(), "bridge.sock")
			handler := &recordingHandler{record: Record{Status: StatusMissing}}
			server, err := NewServer(ServerOptions{
				SocketPath: socketPath,
				SocketGID:  -1,
				Timeout:    time.Second,
				Resolver:   staticResolver{},
			}, handler)
			require.NoError(t, err)
			serveFallbackServer(t, server)

			conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
			require.NoError(t, err)
			defer conn.Close()
			require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
			_, err = conn.Write(append(append([]byte(nil), request...), test.trailer...))
			require.NoError(t, err)
			assert.Equal(t, StatusMissing, readFallbackRecord(t, conn).Status)

			trailingResponse := make([]byte, 1)
			_, err = conn.Read(trailingResponse)
			require.Error(t, err)
			assert.True(t, errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET), err)
			assert.Equal(t, int32(1), handler.calls.Load())

			assert.Equal(t, StatusMissing, fallbackRoundTrip(t, socketPath, request).Status)
			assert.Equal(t, int32(2), handler.calls.Load())
		})
	}
}

func TestFallbackServerRejectsInvalidRequestFields(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "bridge.sock")
	handler := &recordingHandler{}
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		SocketGID:  -1,
		Timeout:    time.Second,
		Resolver:   staticResolver{},
	}, handler)
	require.NoError(t, err)
	serveFallbackServer(t, server)

	valid, err := (Request{Operation: OperationTake, NamespaceTID: 7}).MarshalBinary()
	require.NoError(t, err)
	tests := []struct {
		name   string
		mutate func([]byte)
		status Status
	}{
		{
			name:   "unknown operation",
			mutate: func(request []byte) { request[8] = 0xff },
			status: StatusMalformed,
		},
		{
			name: "declared size",
			mutate: func(request []byte) {
				binary.LittleEndian.PutUint16(request[6:8], RequestSize+1)
			},
			status: StatusMalformed,
		},
		{
			name: "version",
			mutate: func(request []byte) {
				binary.LittleEndian.PutUint16(request[4:6], RequestVersion+1)
			},
			status: StatusVersionMismatch,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := append([]byte(nil), valid...)
			test.mutate(request)
			assert.Equal(t, test.status, fallbackRoundTrip(t, socketPath, request).Status)
		})
	}
	assert.Zero(t, handler.calls.Load())
}

func TestFallbackServerUnauthorizedRequestPreservesOneShotParent(t *testing.T) {
	const namespaceTID = uint32(3)
	identity := Identity{TID: namespaceTID, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{identity: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	socketPath := filepath.Join(t.TempDir(), "bridge.sock")
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		SocketGID:  -1,
		Timeout:    time.Second,
		Resolver: namespaceResolver{
			namespaceTID: namespaceTID,
			identity:     identity,
		},
	}, handler)
	require.NoError(t, err)
	serveFallbackServer(t, server)

	unauthorized, err := (Request{
		Operation:          OperationTake,
		NamespaceTID:       namespaceTID + 1,
		ProcessIncarnation: testProcessIncarnation,
	}).MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, StatusUnauthorized, fallbackRoundTrip(t, socketPath, unauthorized).Status)
	assert.Len(t, handler.remoteParents.(*fakeBridgeMap).values, 1)

	wrongCapability, err := (Request{
		Operation:          OperationTake,
		NamespaceTID:       namespaceTID,
		ProcessIncarnation: testProcessIncarnation + 1,
	}).MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, StatusUnauthorized, fallbackRoundTrip(t, socketPath, wrongCapability).Status)
	assert.Len(t, handler.remoteParents.(*fakeBridgeMap).values, 1)

	legitimate, err := (Request{
		Operation:          OperationTake,
		NamespaceTID:       namespaceTID,
		ProcessIncarnation: testProcessIncarnation,
	}).MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, StatusValid, fallbackRoundTrip(t, socketPath, legitimate).Status)
	assert.Equal(t, StatusAlreadyConsumed, fallbackRoundTrip(t, socketPath, legitimate).Status)
}

func TestFallbackServerRejectsMalformedRequest(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "bridge.sock")
	handler := &recordingHandler{}
	observed := make(chan observedOutcome, 1)
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		SocketGID:  -1,
		Timeout:    time.Second,
		Resolver:   staticResolver{},
		Observe: func(operation Operation, status Status) {
			observed <- observedOutcome{operation: operation, status: status}
		},
	}, handler)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})

	request := make([]byte, RequestSize)
	response := fallbackRoundTrip(t, socketPath, request)
	assert.Equal(t, StatusMalformed, response.Status)
	assert.Equal(t, observedOutcome{
		operation: OperationNegotiate,
		status:    StatusMalformed,
	}, <-observed)
}

func TestFallbackServerReportsRequestVersionMismatch(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "bridge.sock")
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		SocketGID:  -1,
		Timeout:    time.Second,
		Resolver:   staticResolver{},
	}, &recordingHandler{})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})

	request, err := (Request{Operation: OperationTake, NamespaceTID: 7}).MarshalBinary()
	require.NoError(t, err)
	request[4] = 3
	response := fallbackRoundTrip(t, socketPath, request)
	assert.Equal(t, StatusVersionMismatch, response.Status)
}

func TestFallbackServerNegotiatesRegisteredProcessIdentity(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "bridge.sock")
	resolver := &calledResolver{}
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		SocketGID:  -1,
		Timeout:    time.Second,
		Resolver:   resolver,
	}, &recordingHandler{record: Record{Status: StatusMissing}})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})

	request, err := (Request{
		Operation:          OperationNegotiate,
		NamespaceTID:       7,
		ProcessIncarnation: 11,
	}).MarshalBinary()
	require.NoError(t, err)
	response := fallbackRoundTrip(t, socketPath, request)

	assert.Equal(t, StatusMissing, response.Status)
	assert.True(t, resolver.called.Load())
}

func TestFallbackServerBoundsResolutionByRequestDeadline(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "bridge.sock")
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		SocketGID:  -1,
		Timeout:    time.Second,
		Resolver:   timeoutResolver{},
	}, &recordingHandler{})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})

	request, err := (Request{Operation: OperationTake, NamespaceTID: 7}).MarshalBinary()
	require.NoError(t, err)
	response := fallbackRoundTrip(t, socketPath, request)
	assert.Equal(t, StatusTimeout, response.Status)
}

func TestFallbackServerDoesNotConsumeAfterResolutionCancellation(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "bridge.sock")
	resolver := validAfterCancellationResolver{
		identity: Identity{TID: 7, PID: 5, Namespace: 3},
		started:  make(chan struct{}),
	}
	handler := &recordingHandler{record: Record{Status: StatusValid}}
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		SocketGID:  -1,
		Timeout:    time.Second,
		Resolver:   resolver,
	}, handler)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()

	request, err := (Request{
		Operation:          OperationTake,
		NamespaceTID:       7,
		ProcessIncarnation: 11,
	}).MarshalBinary()
	require.NoError(t, err)
	conn, err := net.DialTimeout("unix", socketPath, time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
	_, err = conn.Write(request)
	require.NoError(t, err)

	<-resolver.started
	cancel()
	responseBytes := make([]byte, RecordSize)
	_, err = io.ReadFull(conn, responseBytes)
	require.NoError(t, err)
	response, err := UnmarshalRecord(responseBytes)
	require.NoError(t, err)
	assert.Equal(t, StatusTimeout, response.Status)
	assert.Zero(t, handler.calls.Load())
	require.NoError(t, <-done)
}

func TestFallbackServerReportsIdentityResolutionOverload(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "bridge.sock")
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		SocketGID:  -1,
		Timeout:    time.Second,
		Resolver: staticResolver{
			err: fmt.Errorf("thread bound: %w", errIdentityResolutionOverload),
		},
	}, &recordingHandler{})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})

	request, err := (Request{Operation: OperationTake, NamespaceTID: 7}).MarshalBinary()
	require.NoError(t, err)
	response := fallbackRoundTrip(t, socketPath, request)
	assert.Equal(t, StatusOverload, response.Status)
}

func TestFallbackServerPreAuthAdmissionLimitsOnePeerAndRecovers(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "bridge.sock")
	handler := &recordingHandler{record: Record{Status: StatusValid}}
	observed := make(chan observedOutcome, 8)
	server, err := NewServer(ServerOptions{
		SocketPath:    socketPath,
		SocketGID:     -1,
		Timeout:       3 * time.Second,
		MaxConcurrent: 4,
		Resolver:      staticResolver{},
		Observe: func(operation Operation, status Status) {
			observed <- observedOutcome{operation: operation, status: status}
		},
	}, handler)
	require.NoError(t, err)
	server.preAuthTimeout = 2 * time.Second
	peerRequestCount := func() int {
		server.peerMu.Lock()
		defer server.peerMu.Unlock()
		count := 0
		for _, requests := range server.peerRequests {
			count += requests
		}
		return count
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})

	slowConnections := make([]net.Conn, server.maxPeerRequests)
	for i := range slowConnections {
		slowConnections[i], err = net.DialTimeout("unix", socketPath, time.Second)
		require.NoError(t, err)
		connection := slowConnections[i]
		t.Cleanup(func() { _ = connection.Close() })
	}
	require.Eventually(t, func() bool {
		return len(server.preAuth) == server.maxPeerRequests &&
			peerRequestCount() == server.maxPeerRequests
	}, time.Second, time.Millisecond)

	request, err := (Request{
		Operation:          OperationTake,
		NamespaceTID:       7,
		ProcessIncarnation: 11,
	}).MarshalBinary()
	require.NoError(t, err)
	overloaded, err := net.DialTimeout("unix", socketPath, time.Second)
	require.NoError(t, err)
	defer overloaded.Close()
	require.NoError(t, overloaded.SetDeadline(time.Now().Add(time.Second)))
	overloadBytes := make([]byte, RecordSize)
	_, err = io.ReadFull(overloaded, overloadBytes)
	require.NoError(t, err)
	response, err := UnmarshalRecord(overloadBytes)
	require.NoError(t, err)
	assert.Equal(t, StatusOverload, response.Status)
	assert.Equal(t, observedOutcome{
		operation: OperationNegotiate,
		status:    StatusOverload,
	}, <-observed)

	require.NoError(t, slowConnections[0].Close())
	require.Eventually(t, func() bool {
		return len(server.preAuth) == server.maxPeerRequests-1 &&
			peerRequestCount() == server.maxPeerRequests-1
	}, time.Second, time.Millisecond)

	response = fallbackRoundTrip(t, socketPath, request)
	assert.Equal(t, StatusValid, response.Status)

	for _, connection := range slowConnections[1:] {
		require.NoError(t, connection.Close())
	}
	require.Eventually(t, func() bool {
		return len(server.active) == 0 && len(server.preAuth) == 0 &&
			len(server.authenticated) == 0 &&
			peerRequestCount() == 0
	}, time.Second, time.Millisecond)
}

func TestFallbackServerMaxConcurrentBoundsAllRequestPhases(t *testing.T) {
	server, err := NewServer(ServerOptions{
		SocketPath:    filepath.Join(t.TempDir(), "bridge.sock"),
		SocketGID:     -1,
		Timeout:       time.Second,
		MaxConcurrent: 4,
		Resolver:      staticResolver{},
	}, &recordingHandler{})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, server.Close()) })

	for peerPID := int32(1); peerPID <= 4; peerPID++ {
		require.True(t, server.acquirePreAuth(peerPID))
	}
	assert.False(t, server.acquirePreAuth(5))
	assert.Len(t, server.active, 4)

	for peerPID := int32(1); peerPID <= 4; peerPID++ {
		server.releasePreAuth()
		server.releaseRequest(peerPID)
	}
	assert.Empty(t, server.active)
	assert.Empty(t, server.preAuth)
	assert.Empty(t, server.peerRequests)
}

func TestFallbackServerBoundsPreAuthReadDeadline(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "bridge.sock")
	observed := make(chan observedOutcome, 1)
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		SocketGID:  -1,
		Timeout:    3 * time.Second,
		Resolver:   staticResolver{},
		Observe: func(operation Operation, status Status) {
			observed <- observedOutcome{operation: operation, status: status}
		},
	}, &recordingHandler{})
	require.NoError(t, err)
	server.preAuthTimeout = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})

	conn, err := net.DialTimeout("unix", socketPath, time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))

	responseBytes := make([]byte, RecordSize)
	_, err = io.ReadFull(conn, responseBytes)
	require.NoError(t, err)
	response, err := UnmarshalRecord(responseBytes)
	require.NoError(t, err)
	assert.Equal(t, StatusTimeout, response.Status)
	assert.Equal(t, observedOutcome{
		operation: OperationNegotiate,
		status:    StatusTimeout,
	}, <-observed)
}

func TestFallbackServerBoundsFailureLogs(t *testing.T) {
	var output bytes.Buffer
	server := &Server{
		log: slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})),
	}

	for range 10 {
		server.logFailure("write")
	}
	for range 3 {
		server.logFailure("deadline")
	}
	server.logFailure("unknown")

	logs := output.Bytes()
	assert.Equal(t, 4, bytes.Count(logs, []byte("stage=write")))
	assert.Equal(t, 2, bytes.Count(logs, []byte("stage=deadline")))
	assert.NotContains(t, string(logs), "stage=unknown")
}

func TestFallbackServerRefusesNonSocketPath(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "bridge.sock")
	require.NoError(t, os.WriteFile(socketPath, []byte("keep"), 0o600))

	_, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		SocketGID:  -1,
		Timeout:    time.Second,
	}, &recordingHandler{})
	require.ErrorContains(t, err, "refusing to replace non-socket")
	contents, readErr := os.ReadFile(socketPath)
	require.NoError(t, readErr)
	assert.Equal(t, "keep", string(contents))
}

func TestFallbackServerCreatesProtectedGroupSocket(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "bridge")
	socketPath := filepath.Join(parent, "bridge.sock")
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		SocketGID:  -1,
		Timeout:    time.Second,
	}, &recordingHandler{})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, server.Close()) })

	parentInfo, err := os.Lstat(parent)
	require.NoError(t, err)
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	assert.Equal(t, uint32(os.Geteuid()), parentStat.Uid)
	assert.Equal(t, uint32(os.Getegid()), parentStat.Gid)
	assert.Equal(t, os.FileMode(0o750), parentInfo.Mode().Perm())

	socketInfo, err := os.Lstat(socketPath)
	require.NoError(t, err)
	socketStat, ok := socketInfo.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	assert.Equal(t, uint32(os.Geteuid()), socketStat.Uid)
	assert.Equal(t, uint32(os.Getegid()), socketStat.Gid)
	assert.Equal(t, os.FileMode(0o660), socketInfo.Mode().Perm())
}

func TestFallbackServerPreservesReplacementPathOnShutdown(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "bridge.sock")
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		SocketGID:  -1,
		Timeout:    time.Second,
	}, &recordingHandler{})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()

	require.NoError(t, os.Remove(socketPath))
	require.NoError(t, os.WriteFile(socketPath, []byte("replacement"), 0o600))
	cancel()
	require.NoError(t, <-done)
	require.NoError(t, server.Close())

	contents, err := os.ReadFile(socketPath)
	require.NoError(t, err)
	assert.Equal(t, "replacement", string(contents))
}

func TestRemoveSocketPathIfSameUsesFileIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bridge.sock")
	directory, _, err := openSocketDirectory(filepath.Dir(path))
	require.NoError(t, err)
	guard := &guardedSocketPath{directory: directory, name: filepath.Base(path)}
	t.Cleanup(func() { require.NoError(t, guard.Close()) })
	require.NoError(t, os.WriteFile(path, []byte("original"), 0o600))
	original, err := guard.stat()
	require.NoError(t, err)
	require.NoError(t, os.Remove(path))
	require.NoError(t, os.WriteFile(path, []byte("replacement"), 0o600))

	require.NoError(t, guard.removeIfSame(original))
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "replacement", string(contents))
}

func TestFallbackServerSupportsProtectedAncestorSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "run")
	require.NoError(t, os.Mkdir(target, 0o700))
	alias := filepath.Join(root, "var-run")
	require.NoError(t, os.Symlink(target, alias))
	socketPath := filepath.Join(alias, "obi", "bridge.sock")
	identity := Identity{TID: 7, PID: 5, Namespace: 3}

	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		SocketGID:  -1,
		Timeout:    time.Second,
		Resolver:   staticResolver{identity: identity},
	}, &recordingHandler{record: Record{Status: StatusMissing}})
	require.NoError(t, err)
	serveFallbackServer(t, server)

	info, err := os.Lstat(socketPath)
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&os.ModeSocket)

	request, err := (Request{
		Operation:          OperationTake,
		NamespaceTID:       identity.TID,
		ProcessIncarnation: 11,
	}).MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, StatusMissing, fallbackRoundTrip(t, socketPath, request).Status)
}

func TestFallbackServerSupportsTrustedAliasInStickyParent(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	require.NoError(t, os.Mkdir(target, 0o700))
	sticky := filepath.Join(root, "sticky")
	require.NoError(t, os.Mkdir(sticky, 0o700))
	require.NoError(t, os.Chmod(sticky, os.ModeSticky|0o777))
	alias := filepath.Join(sticky, "run")
	require.NoError(t, os.Symlink(target, alias))

	server, err := NewServer(ServerOptions{
		SocketPath: filepath.Join(alias, "obi", "bridge.sock"),
		SocketGID:  -1,
		Timeout:    time.Second,
	}, &recordingHandler{})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, server.Close()) })
}

func TestFallbackServerAncestorSwapCannotRedirectBind(t *testing.T) {
	root := t.TempDir()
	trusted := filepath.Join(root, "trusted")
	attacker := filepath.Join(root, "attacker")
	require.NoError(t, os.Mkdir(trusted, 0o700))
	require.NoError(t, os.Mkdir(attacker, 0o700))
	attackerParent := filepath.Join(attacker, "obi")
	require.NoError(t, os.Mkdir(attackerParent, 0o700))
	attackerPath := filepath.Join(attackerParent, "bridge.sock")
	require.NoError(t, os.WriteFile(attackerPath, []byte("keep"), 0o600))

	alias := filepath.Join(root, "run")
	require.NoError(t, os.Symlink(trusted, alias))
	socketPath := filepath.Join(alias, "obi", "bridge.sock")
	canonicalPath, err := canonicalSocketPath(socketPath)
	require.NoError(t, err)
	require.NoError(t, os.Remove(alias))
	require.NoError(t, os.Symlink(attacker, alias))

	server, err := NewServer(ServerOptions{
		SocketPath: canonicalPath,
		SocketGID:  -1,
		Timeout:    time.Second,
	}, &recordingHandler{})
	require.NoError(t, err)

	trustedPath := canonicalPath
	trustedInfo, err := os.Lstat(trustedPath)
	require.NoError(t, err)
	assert.NotZero(t, trustedInfo.Mode()&os.ModeSocket)
	contents, err := os.ReadFile(attackerPath)
	require.NoError(t, err)
	assert.Equal(t, "keep", string(contents))

	require.NoError(t, server.Close())
	_, err = os.Lstat(trustedPath)
	require.ErrorIs(t, err, os.ErrNotExist)
	contents, err = os.ReadFile(attackerPath)
	require.NoError(t, err)
	assert.Equal(t, "keep", string(contents))
}

func TestFallbackServerRejectsUntrustedSocketDirectory(t *testing.T) {
	t.Run("symlink in writable parent", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target")
		require.NoError(t, os.Mkdir(target, 0o700))
		writable := filepath.Join(root, "writable")
		require.NoError(t, os.Mkdir(writable, 0o700))
		require.NoError(t, os.Chmod(writable, 0o777))
		alias := filepath.Join(writable, "bridge")
		require.NoError(t, os.Symlink(target, alias))

		_, err := NewServer(ServerOptions{
			SocketPath: filepath.Join(alias, "bridge.sock"),
			SocketGID:  -1,
			Timeout:    time.Second,
		}, &recordingHandler{})
		require.ErrorContains(t, err, "alias is in a writable parent")
	})

	t.Run("untrusted-owned symlink", func(t *testing.T) {
		trustedUID := uint32(os.Geteuid())
		untrustedUID := trustedUID + 1
		if untrustedUID == trustedUID {
			untrustedUID--
		}
		err := validateSocketAlias(
			"/trusted/alias",
			"/trusted",
			unix.Stat_t{Mode: unix.S_IFLNK, Uid: untrustedUID},
			unix.Stat_t{Mode: unix.S_IFDIR | 0o700, Uid: trustedUID},
			trustedUID,
		)
		require.ErrorContains(t, err, "alias has an untrusted owner")
	})

	t.Run("final socket symlink", func(t *testing.T) {
		root := t.TempDir()
		target := filepath.Join(root, "target")
		require.NoError(t, os.WriteFile(target, []byte("keep"), 0o600))
		socketPath := filepath.Join(root, "bridge.sock")
		require.NoError(t, os.Symlink(target, socketPath))

		_, err := NewServer(ServerOptions{
			SocketPath: socketPath,
			SocketGID:  -1,
			Timeout:    time.Second,
		}, &recordingHandler{})
		require.ErrorContains(t, err, "socket path must not be a symlink")
		contents, readErr := os.ReadFile(target)
		require.NoError(t, readErr)
		assert.Equal(t, "keep", string(contents))
	})

	t.Run("writable ancestor", func(t *testing.T) {
		root := t.TempDir()
		writable := filepath.Join(root, "writable")
		parent := filepath.Join(writable, "bridge")
		require.NoError(t, os.MkdirAll(parent, 0o700))
		require.NoError(t, os.Chmod(writable, 0o777))

		_, err := NewServer(ServerOptions{
			SocketPath: filepath.Join(parent, "bridge.sock"),
			SocketGID:  -1,
			Timeout:    time.Second,
		}, &recordingHandler{})
		require.ErrorContains(t, err, "writable without the sticky bit")
	})

	t.Run("world accessible", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "bridge")
		require.NoError(t, os.Mkdir(parent, 0o755))
		require.NoError(t, os.Chmod(parent, 0o755))

		_, err := NewServer(ServerOptions{
			SocketPath: filepath.Join(parent, "bridge.sock"),
			SocketGID:  -1,
			Timeout:    time.Second,
		}, &recordingHandler{})
		require.ErrorContains(t, err, "world accessible")
	})

	t.Run("wrong group", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "bridge")
		require.NoError(t, os.Mkdir(parent, 0o700))

		_, err := NewServer(ServerOptions{
			SocketPath: filepath.Join(parent, "bridge.sock"),
			SocketGID:  os.Getegid() + 1,
			Timeout:    time.Second,
		}, &recordingHandler{})
		require.ErrorContains(t, err, "configured group")
	})
}

func TestFallbackServerRejectsTimeoutOutsideNativeRange(t *testing.T) {
	_, err := NewServer(ServerOptions{
		SocketPath: filepath.Join(t.TempDir(), "bridge.sock"),
		SocketGID:  -1,
		Timeout:    maxTransportTimeout + time.Millisecond,
	}, &recordingHandler{})
	require.ErrorContains(t, err, "must not exceed")
}

func TestLastNamespaceID(t *testing.T) {
	id, err := lastNamespaceID("300 20 7")
	require.NoError(t, err)
	assert.Equal(t, uint32(7), id)

	_, err = lastNamespaceID("")
	require.Error(t, err)
}

func TestProcIdentityResolverUsesPeerProcess(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tid := uint32(unix.Gettid())
	identity, err := (&procIdentityResolver{}).Resolve(t.Context(), int32(os.Getpid()), tid)
	require.NoError(t, err)
	assert.Equal(t, tid, identity.TID)
	assert.NotZero(t, identity.PID)
	assert.NotZero(t, identity.Namespace)

	_, err = (&procIdentityResolver{}).Resolve(t.Context(), int32(os.Getpid()), ^uint32(0))
	require.Error(t, err)
}

func TestProcIdentityResolverHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := (&procIdentityResolver{}).Resolve(ctx, int32(os.Getpid()), uint32(unix.Gettid()))
	require.ErrorIs(t, err, context.Canceled)
}

func TestProcIdentityResolverBoundsTaskDirectoryRead(t *testing.T) {
	const peerPID = int32(123)
	root := t.TempDir()
	processDir := filepath.Join(root, "123")
	taskDir := filepath.Join(processDir, "task")
	require.NoError(t, os.MkdirAll(taskDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(processDir, "status"), []byte("NStgid:\t123\n"), 0o600))
	for _, task := range []string{"1", "2", "3"} {
		require.NoError(t, os.Mkdir(filepath.Join(taskDir, task), 0o750))
	}

	_, err := (&procIdentityResolver{root: root, threadLimit: 2}).Resolve(t.Context(), peerPID, 1)
	require.ErrorContains(t, err, "exceeds thread validation limit 2")
}

func TestProcIdentityResolverCachesValidatedThreadLookup(t *testing.T) {
	const (
		peerPID      = int32(123)
		namespaceTID = uint32(7)
	)
	root := t.TempDir()
	processDir := filepath.Join(root, "123")
	taskDir := filepath.Join(processDir, "task")
	namespaceDir := filepath.Join(processDir, "ns")
	require.NoError(t, os.MkdirAll(filepath.Join(taskDir, "456"), 0o750))
	require.NoError(t, os.MkdirAll(namespaceDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(processDir, "status"), []byte("NStgid:\t123\n"), 0o600))
	require.NoError(t, os.WriteFile(
		filepath.Join(taskDir, "456", "status"),
		[]byte("Tgid:\t123\nNSpid:\t456 7\n"),
		0o600,
	))
	require.NoError(t, os.WriteFile(filepath.Join(namespaceDir, "pid_for_children"), nil, 0o600))

	resolver := &procIdentityResolver{root: root, threadLimit: 1}
	identity, err := resolver.Resolve(t.Context(), peerPID, namespaceTID)
	require.NoError(t, err)
	assert.Equal(t, namespaceTID, identity.TID)

	require.NoError(t, os.Mkdir(filepath.Join(taskDir, "999"), 0o750))
	identity, err = resolver.Resolve(t.Context(), peerPID, namespaceTID)
	require.NoError(t, err)
	assert.Equal(t, namespaceTID, identity.TID)

	_, err = resolver.Resolve(t.Context(), peerPID, namespaceTID+1)
	require.ErrorContains(t, err, "exceeds thread validation limit 1")
}

func TestProcIdentityResolverRetainsValidatedPartialScanOnTimeout(t *testing.T) {
	const peerPID = int32(123)
	root := t.TempDir()
	processDir := filepath.Join(root, "123")
	taskDir := filepath.Join(processDir, "task")
	namespaceDir := filepath.Join(processDir, "ns")
	require.NoError(t, os.MkdirAll(taskDir, 0o750))
	require.NoError(t, os.MkdirAll(namespaceDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(processDir, "status"), []byte("NStgid:\t123\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(namespaceDir, "pid_for_children"), nil, 0o600))
	for i := 1; i <= 3; i++ {
		task := filepath.Join(taskDir, fmt.Sprintf("%06d", i))
		require.NoError(t, os.Mkdir(task, 0o750))
		require.NoError(t, os.WriteFile(
			filepath.Join(task, "status"),
			[]byte(fmt.Sprintf("Tgid:\t123\nNSpid:\t%d\n", i)),
			0o600,
		))
	}

	resolver := &procIdentityResolver{root: root}
	ctx := &cancelAfterContext{Context: context.Background(), cancelAt: 10}
	_, err := resolver.Resolve(ctx, peerPID, 3)
	require.ErrorIs(t, err, context.Canceled)

	resolver.cacheMu.Lock()
	_, cached := resolver.cache[procIdentityKey{peerPID: peerPID, namespaceTID: 1}]
	resolver.cacheMu.Unlock()
	require.True(t, cached)

	identity, err := resolver.Resolve(t.Context(), peerPID, 1)
	require.NoError(t, err)
	assert.Equal(t, uint32(1), identity.TID)
}

func TestProcIdentityResolverSerializesConcurrentColdScansPerPeer(t *testing.T) {
	const (
		peerPID = int32(123)
		threads = 50
		callers = 16
	)
	root := t.TempDir()
	processDir := filepath.Join(root, "123")
	taskDir := filepath.Join(processDir, "task")
	namespaceDir := filepath.Join(processDir, "ns")
	require.NoError(t, os.MkdirAll(taskDir, 0o750))
	require.NoError(t, os.MkdirAll(namespaceDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(processDir, "status"), []byte("NStgid:\t123\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(namespaceDir, "pid_for_children"), nil, 0o600))
	for i := 1; i <= threads; i++ {
		task := filepath.Join(taskDir, fmt.Sprintf("%06d", i))
		require.NoError(t, os.Mkdir(task, 0o750))
		require.NoError(t, os.WriteFile(
			filepath.Join(task, "status"),
			[]byte(fmt.Sprintf("Tgid:\t123\nNSpid:\t%d\n", i)),
			0o600,
		))
	}

	resolver := &procIdentityResolver{root: root}
	start := make(chan struct{})
	results := make(chan error, callers)
	for range callers {
		go func() {
			<-start
			identity, err := resolver.Resolve(t.Context(), peerPID, threads)
			if err == nil && identity.TID != threads {
				err = fmt.Errorf("unexpected identity TID %d", identity.TID)
			}
			results <- err
		}()
	}
	close(start)
	for range callers {
		require.NoError(t, <-results)
	}

	resolver.scansMu.Lock()
	coldScans := resolver.coldScans
	resolver.scansMu.Unlock()
	assert.Equal(t, uint64(1), coldScans)
}

func BenchmarkProcIdentityResolverCached(b *testing.B) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	resolver := &procIdentityResolver{}
	peerPID := int32(os.Getpid())
	tid := uint32(unix.Gettid())
	_, err := resolver.Resolve(b.Context(), peerPID, tid)
	require.NoError(b, err)

	b.ResetTimer()
	for range b.N {
		_, err := resolver.Resolve(b.Context(), peerPID, tid)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProcIdentityResolverCold(b *testing.B) {
	for _, threads := range []int{50, 200, 1000} {
		b.Run(fmt.Sprintf("threads-%d", threads), func(b *testing.B) {
			const peerPID = int32(123)
			root := b.TempDir()
			processDir := filepath.Join(root, "123")
			taskDir := filepath.Join(processDir, "task")
			namespaceDir := filepath.Join(processDir, "ns")
			require.NoError(b, os.MkdirAll(taskDir, 0o750))
			require.NoError(b, os.MkdirAll(namespaceDir, 0o750))
			require.NoError(b, os.WriteFile(
				filepath.Join(processDir, "status"), []byte("NStgid:\t123\n"), 0o600,
			))
			require.NoError(b, os.WriteFile(
				filepath.Join(namespaceDir, "pid_for_children"), nil, 0o600,
			))
			for i := 1; i <= threads; i++ {
				task := filepath.Join(taskDir, fmt.Sprintf("%06d", i))
				require.NoError(b, os.Mkdir(task, 0o750))
				require.NoError(b, os.WriteFile(
					filepath.Join(task, "status"),
					[]byte(fmt.Sprintf("Tgid:\t123\nNSpid:\t%d\n", i)),
					0o600,
				))
			}

			b.ReportMetric(float64(threads), "threads")
			b.ResetTimer()
			for range b.N {
				resolver := &procIdentityResolver{root: root}
				_, err := resolver.Resolve(b.Context(), peerPID, uint32(threads))
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func fallbackRoundTrip(t *testing.T, socketPath string, request []byte) Record {
	t.Helper()
	conn, err := net.DialTimeout("unix", socketPath, time.Second)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
	_, err = conn.Write(request)
	if err != nil {
		require.True(t,
			errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET),
			"unexpected fallback request write error: %v", err,
		)
	}
	record := readFallbackRecord(t, conn)
	if err != nil {
		require.NotEqual(t, StatusValid, record.Status)
	}
	return record
}

func readFallbackRecord(t *testing.T, reader io.Reader) Record {
	t.Helper()
	response := make([]byte, RecordSize)
	_, err := io.ReadFull(reader, response)
	require.NoError(t, err)
	record, err := UnmarshalRecord(response)
	require.NoError(t, err)
	return record
}

func serveFallbackServer(t *testing.T, server *Server) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})
}
