// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javabridge

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testProcessIncarnation = uint64(0x123456789abcdef0)

type fakeBridgeMap struct {
	mu                sync.Mutex
	values            map[any]any
	lookupCount       int
	lookupErr         error
	updateErr         error
	deleteErr         error
	iterateErr        error
	afterIterate      func()
	afterLookup       func(int)
	afterLookupResult func(any, error)
	beforeUpdate      func(any, any, ebpf.MapUpdateFlags)
	afterUpdate       func(any, any)
	afterDelete       func(any)
}

type fakeCleanupEntry struct {
	key   any
	value any
}

type fakeCleanupIterator struct {
	entries []fakeCleanupEntry
	index   int
	err     error
}

func (i *fakeCleanupIterator) Next(keyOut, valueOut any) bool {
	if i.index >= len(i.entries) {
		return false
	}
	entry := i.entries[i.index]
	i.index++
	reflect.ValueOf(keyOut).Elem().Set(reflect.ValueOf(entry.key))
	reflect.ValueOf(valueOut).Elem().Set(reflect.ValueOf(entry.value))
	return true
}

func (i *fakeCleanupIterator) Err() error { return i.err }

func (m *fakeBridgeMap) Iterate() cleanupIterator {
	m.mu.Lock()
	entries := make([]fakeCleanupEntry, 0, len(m.values))
	for key, value := range m.values {
		entries = append(entries, fakeCleanupEntry{key: key, value: value})
	}
	err := m.iterateErr
	afterIterate := m.afterIterate
	m.mu.Unlock()
	if afterIterate != nil {
		afterIterate()
	}
	return &fakeCleanupIterator{entries: entries, err: err}
}

func (m *fakeBridgeMap) Lookup(key, valueOut any) error {
	m.mu.Lock()
	mapKey := indirectValue(key)
	if m.lookupErr != nil {
		err := m.lookupErr
		afterLookupResult := m.afterLookupResult
		m.mu.Unlock()
		if afterLookupResult != nil {
			afterLookupResult(mapKey, err)
		}
		return err
	}
	value, ok := m.values[mapKey]
	if !ok {
		afterLookupResult := m.afterLookupResult
		m.mu.Unlock()
		if afterLookupResult != nil {
			afterLookupResult(mapKey, ebpf.ErrKeyNotExist)
		}
		return ebpf.ErrKeyNotExist
	}
	reflect.ValueOf(valueOut).Elem().Set(reflect.ValueOf(value))
	m.lookupCount++
	count := m.lookupCount
	afterLookup := m.afterLookup
	afterLookupResult := m.afterLookupResult
	m.mu.Unlock()
	if afterLookup != nil {
		afterLookup(count)
	}
	if afterLookupResult != nil {
		afterLookupResult(mapKey, nil)
	}
	return nil
}

func (m *fakeBridgeMap) Update(key, value any, flags ebpf.MapUpdateFlags) error {
	m.mu.Lock()
	if m.updateErr != nil {
		err := m.updateErr
		m.mu.Unlock()
		return err
	}
	mapKey := indirectValue(key)
	mapValue := indirectValue(value)
	if m.beforeUpdate != nil {
		m.beforeUpdate(mapKey, mapValue, flags)
	}
	_, exists := m.values[mapKey]
	if exists && flags == ebpf.UpdateNoExist {
		m.mu.Unlock()
		return ebpf.ErrKeyExist
	}
	if !exists && flags == ebpf.UpdateExist {
		m.mu.Unlock()
		return ebpf.ErrKeyNotExist
	}
	m.values[mapKey] = mapValue
	afterUpdate := m.afterUpdate
	m.mu.Unlock()
	if afterUpdate != nil {
		afterUpdate(mapKey, mapValue)
	}
	return nil
}

func (m *fakeBridgeMap) Delete(key any) error {
	m.mu.Lock()
	if m.deleteErr != nil {
		err := m.deleteErr
		m.mu.Unlock()
		return err
	}
	mapKey := indirectValue(key)
	if _, exists := m.values[mapKey]; !exists {
		m.mu.Unlock()
		return ebpf.ErrKeyNotExist
	}
	delete(m.values, mapKey)
	afterDelete := m.afterDelete
	m.mu.Unlock()
	if afterDelete != nil {
		afterDelete(mapKey)
	}
	return nil
}

func indirectValue(value any) any {
	reflected := reflect.ValueOf(value)
	if reflected.Kind() == reflect.Pointer {
		return reflected.Elem().Interface()
	}
	return value
}

func TestMapHandlerKernelMapLayouts(t *testing.T) {
	var connection connectionInfoNS
	assert.Equal(t, uintptr(40), unsafe.Sizeof(connection))
	assert.Equal(t, uintptr(36), unsafe.Offsetof(connection.NetNS))
	var cookieConnection connectionInfoNetNSCookie
	assert.Equal(t, uintptr(48), unsafe.Sizeof(cookieConnection))
	assert.Equal(t, uintptr(40), unsafe.Offsetof(cookieConnection.NetNSCookie))
	assert.Equal(t, uintptr(56), unsafe.Sizeof(connectionClaim{}))
	assert.Equal(t, uintptr(24), unsafe.Offsetof(connectionClaim{}.NetNSCookie))
	assert.Equal(t, uintptr(32), unsafe.Offsetof(connectionClaim{}.IncomingGeneration))
	assert.Equal(t, uintptr(40), unsafe.Offsetof(connectionClaim{}.SocketCookie))
	assert.Equal(t, uintptr(48), unsafe.Offsetof(connectionClaim{}.NetNS))

	var state stateValue
	assert.Equal(t, uintptr(128), unsafe.Sizeof(state))
	assert.Equal(t, uintptr(4), unsafe.Offsetof(state.Aliases))
	assert.Equal(t, uintptr(16), unsafe.Offsetof(state.Connection))
	assert.Equal(t, uintptr(52), unsafe.Offsetof(state.ConnectionNetNS))
	assert.Equal(t, uintptr(56), unsafe.Offsetof(state.ProcessIncarnation))
	assert.Equal(t, uintptr(64), unsafe.Offsetof(state.Response))

	assert.Equal(t, uintptr(16), unsafe.Sizeof(virtualThreadIdentity{}))
	assert.Equal(t, uintptr(24), unsafe.Sizeof(ownerValue{}))
	assert.Equal(t, uintptr(32), unsafe.Sizeof(terminalValue{}))
	assert.Equal(t, uintptr(32), unsafe.Sizeof(generationIndexValue{}))
	assert.Equal(t, uintptr(24), unsafe.Sizeof(generationClaim{}))
}

func TestFakeBridgeMapHonorsUpdateFlags(t *testing.T) {
	m := &fakeBridgeMap{values: make(map[any]any)}
	key := stateKey{Generation: 10}
	value := uint64(1)

	require.ErrorIs(t, m.Update(&key, &value, ebpf.UpdateExist), ebpf.ErrKeyNotExist)
	require.NoError(t, m.Update(&key, &value, ebpf.UpdateNoExist))
	replacement := uint64(2)
	require.ErrorIs(t, m.Update(&key, &replacement, ebpf.UpdateNoExist), ebpf.ErrKeyExist)
	assert.Equal(t, value, m.values[key])
}

func TestMapHandlerGenerationReservationTruthTable(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: identity, Generation: 10}

	tests := []struct {
		name      string
		lifecycle uint8
		present   bool
		markedAt  uint64
		ambiguous bool
	}{
		{name: "live missing", ambiguous: true},
		{name: "live reserved", present: true},
		{name: "live fenced", present: true, markedAt: 1, ambiguous: true},
		{name: "terminal missing", lifecycle: lifecycleConsumed},
		{name: "terminal reserved", lifecycle: lifecycleConsumed, present: true, ambiguous: true},
		{
			name: "terminal fenced", lifecycle: lifecycleConsumed, present: true, markedAt: 1,
			ambiguous: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := testMapHandler(nil, nil, nil)
			if test.present {
				handler.ambiguity.(*fakeBridgeMap).values[key] = test.markedAt
			}
			ambiguous, failed := handler.generationAmbiguous(resolvedCandidate{
				Owner: identity, Generation: key.Generation, Lifecycle: test.lifecycle,
			})
			assert.False(t, failed)
			assert.Equal(t, test.ambiguous, ambiguous)
		})
	}
}

func TestMapHandlerMarkAmbiguousPromotesReservation(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: identity, Generation: 10}
	handler := testMapHandler(nil, nil, nil)
	ambiguity := handler.ambiguity.(*fakeBridgeMap)
	ambiguity.values[key] = uint64(0)

	assert.True(t, handler.markAmbiguous(resolvedCandidate{Owner: identity, Generation: 10}))
	assert.Equal(t, uint64(11*time.Second), ambiguity.values[key])
}

func TestMapHandlerMarkAmbiguousAcceptsConcurrentFence(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: identity, Generation: 10}
	handler := testMapHandler(nil, nil, nil)
	ambiguity := handler.ambiguity.(*fakeBridgeMap)
	concurrentMarker := uint64(12 * time.Second)
	ambiguity.beforeUpdate = func(mapKey, _ any, flags ebpf.MapUpdateFlags) {
		require.Equal(t, key, mapKey)
		require.Equal(t, ebpf.UpdateNoExist, flags)
		ambiguity.values[mapKey] = concurrentMarker
	}

	assert.True(t, handler.markAmbiguous(resolvedCandidate{Owner: identity, Generation: 10}))
	assert.Equal(t, concurrentMarker, ambiguity.values[key])
}

func TestNewMapHandlerRequiresGenerationCoordinator(t *testing.T) {
	assert.Panics(t, func() {
		NewMapHandler(Maps{}, time.Second, nil)
	})
}

func TestGenerationCoordinatorNilLocksFailClosed(t *testing.T) {
	var coordinator *GenerationCoordinator
	assert.Panics(t, func() { coordinator.tryLockHandler() })
	assert.Panics(t, func() { coordinator.lockCleanup() })
}

func TestGenerationCoordinatorBlocksCleanupDuringDelayedHandler(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{identity: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	var now atomic.Int64
	now.Store(int64(11 * time.Second))
	handler.monoTimeNow = func() time.Duration {
		return time.Duration(now.Load())
	}
	cleanup := testCleanup(handler)
	require.Same(t, handler.coordinator, cleanup.coordinator)
	require.Same(t, handler.claims, cleanup.maps.claims)

	claimed := make(chan struct{})
	resume := make(chan struct{})
	var resumeOnce sync.Once
	var delayOnce sync.Once
	t.Cleanup(func() { resumeOnce.Do(func() { close(resume) }) })
	handler.claims.(*fakeBridgeMap).afterUpdate = func(any, any) {
		delayOnce.Do(func() {
			close(claimed)
			<-resume
		})
	}
	result := make(chan Record, 1)
	go func() {
		result <- handler.Handle(identity, OperationTake)
	}()
	select {
	case <-claimed:
	case <-time.After(time.Second):
		t.Fatal("handler did not acquire its generation claim")
	}

	now.Store(int64(10*time.Second + handler.ttl + time.Nanosecond))
	cleanupStarted := make(chan struct{})
	sweepEntered := make(chan struct{})
	var sweepEnteredOnce sync.Once
	cleanup.maps.generations.(*fakeBridgeMap).afterIterate = func() {
		sweepEnteredOnce.Do(func() { close(sweepEntered) })
	}
	type cleanupResult struct {
		stats CleanupStats
		err   error
	}
	cleanupFinished := make(chan cleanupResult, 1)
	go func() {
		close(cleanupStarted)
		stats, err := cleanup.SweepWithStats()
		cleanupFinished <- cleanupResult{stats: stats, err: err}
	}()
	select {
	case <-cleanupStarted:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not begin its coordinator acquisition")
	}
	select {
	case <-sweepEntered:
		t.Fatal("cleanup entered its real map sweep while the handler owned its claim")
	case <-time.After(50 * time.Millisecond):
	}
	key := stateKey{Owner: identity, Generation: 10}
	assert.Contains(t, handler.claims.(*fakeBridgeMap).values, key)
	assert.Contains(t, handler.states.(*fakeBridgeMap).values, key)
	assert.Contains(t, handler.generations.(*fakeBridgeMap).values, key)
	assert.Contains(t, handler.remoteParents.(*fakeBridgeMap).values, identity)

	resumeOnce.Do(func() { close(resume) })
	select {
	case record := <-result:
		assert.Equal(t, StatusStale, record.Status)
	case <-time.After(time.Second):
		t.Fatal("handler did not complete after it was resumed")
	}
	select {
	case <-sweepEntered:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not enter its real map sweep after the handler completed")
	}
	select {
	case completed := <-cleanupFinished:
		require.NoError(t, completed.err)
		assert.Equal(t, CleanupStats{}, completed.stats)
	case <-time.After(time.Second):
		t.Fatal("cleanup did not finish after the handler completed")
	}
}

func TestGenerationCoordinatorFailsHandlerOpenDuringCleanup(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{identity: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	cleanup := testCleanup(handler)

	sweepEntered := make(chan struct{})
	resumeSweep := make(chan struct{})
	var resumeOnce sync.Once
	var enterOnce sync.Once
	t.Cleanup(func() { resumeOnce.Do(func() { close(resumeSweep) }) })
	cleanup.maps.generations.(*fakeBridgeMap).afterIterate = func() {
		enterOnce.Do(func() { close(sweepEntered) })
		<-resumeSweep
	}

	type cleanupResult struct {
		stats CleanupStats
		err   error
	}
	cleanupFinished := make(chan cleanupResult, 1)
	go func() {
		stats, err := cleanup.SweepWithStats()
		cleanupFinished <- cleanupResult{stats: stats, err: err}
	}()
	select {
	case <-sweepEntered:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not acquire the generation coordinator")
	}

	negotiateResult := make(chan Record, 1)
	go func() {
		negotiateResult <- handler.HandleAuthenticated(
			t.Context(),
			identity,
			OperationNegotiate,
			LookupSourceDirect,
			testProcessIncarnation,
		)
	}()
	select {
	case record := <-negotiateResult:
		assert.Equal(t, StatusMissing, record.Status)
	case <-time.After(time.Second):
		t.Fatal("negotiation blocked during generation cleanup")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result := make(chan Record, 1)
	go func() {
		result <- handler.HandleAuthenticated(
			ctx,
			identity,
			OperationTake,
			LookupSourceDirect,
			testProcessIncarnation,
		)
	}()
	select {
	case record := <-result:
		assert.Equal(t, StatusTimeout, record.Status)
		assert.NoError(t, ctx.Err())
	case <-time.After(time.Second):
		t.Fatal("handler blocked behind cleanup instead of failing open")
	}
	assert.Empty(t, handler.claims.(*fakeBridgeMap).values)
	assert.NotEmpty(t, handler.states.(*fakeBridgeMap).values)
	assert.NotEmpty(t, handler.generations.(*fakeBridgeMap).values)
	assert.NotEmpty(t, handler.remoteParents.(*fakeBridgeMap).values)

	resumeOnce.Do(func() { close(resumeSweep) })
	select {
	case completed := <-cleanupFinished:
		require.NoError(t, completed.err)
	case <-time.After(time.Second):
		t.Fatal("cleanup did not finish after release")
	}
}

func TestMapHandlerRejectsMissingOwnerMap(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{identity: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	handler.owners = nil

	assert.Equal(t, StatusUnsupported, handler.Handle(identity, OperationTake).Status)
}

func TestMinimizeDisabledMapsPreservesVirtualThreadTracingCapacity(t *testing.T) {
	spec := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{
		"incoming_trace_ambiguity":           {MaxEntries: 128},
		"incoming_trace_candidates":          {MaxEntries: 128},
		"incoming_trace_claims":              {MaxEntries: 128},
		"incoming_trace_heads":               {MaxEntries: 128},
		"java_authorized_processes":          {MaxEntries: 128},
		"java_process_incarnations":          {MaxEntries: 128},
		"java_remote_parent_receive_cursors": {MaxEntries: 128},
		"java_thread_mapping_claims":         {MaxEntries: 128},
		"java_vt_identities":                 {MaxEntries: 128},
		"java_vt_threads":                    {MaxEntries: 128},
		"sk_ssl_prewrite_map":                {Type: ebpf.SkStorage},
		"ssl_prewrite_connection_ambiguity":  {MaxEntries: 128},
		"ssl_prewrite_connection_claims":     {MaxEntries: 128},
		"ssl_prewrite_connection_owners":     {MaxEntries: 128},
		"ssl_prewrite_tp":                    {MaxEntries: 128},
	}}

	MinimizeDisabledMaps(spec)

	for _, name := range []string{
		"incoming_trace_ambiguity",
		"incoming_trace_candidates",
		"incoming_trace_claims",
		"incoming_trace_heads",
		"java_remote_parent_receive_cursors",
		"java_thread_mapping_claims",
		"ssl_prewrite_connection_ambiguity",
		"ssl_prewrite_connection_claims",
		"ssl_prewrite_connection_owners",
		"ssl_prewrite_tp",
	} {
		assert.Equal(t, uint32(1), spec.Maps[name].MaxEntries, name)
	}
	assert.Equal(t, uint32(0), spec.Maps["sk_ssl_prewrite_map"].MaxEntries)
	for _, name := range []string{
		"java_authorized_processes",
		"java_process_incarnations",
		"java_vt_identities",
		"java_vt_threads",
	} {
		assert.Equal(t, uint32(128), spec.Maps[name].MaxEntries, name)
	}
}

func TestMapHandlerTakesCurrentRemoteParentOnce(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	encoded := validEncodedRecord(t, 10)
	handler := testMapHandler(
		map[Identity]any{identity: encoded},
		nil,
		nil,
	)

	result := handler.Handle(identity, OperationTake)
	assert.Equal(t, StatusValid, result.Status)
	assert.Equal(t, uint64(10), result.Generation)
	assert.Empty(t, handler.generations.(*fakeBridgeMap).values)
	assert.Equal(t, StatusAlreadyConsumed, handler.Handle(identity, OperationTake).Status)
}

func TestMapHandlerDeadlineBeforeClaimPreservesParent(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{identity: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	remoteParents := handler.remoteParents.(*fakeBridgeMap)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	remoteParents.afterLookup = func(count int) {
		if count == 3 {
			<-ctx.Done()
		}
	}

	result := handler.HandleAuthenticated(
		ctx, identity, OperationTake, LookupSourceDirect, testProcessIncarnation,
	)
	assert.Equal(t, StatusTimeout, result.Status)
	require.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
	assert.Empty(t, handler.claims.(*fakeBridgeMap).values)

	remoteParents.afterLookup = nil
	retry := handler.HandleAuthenticated(
		t.Context(), identity, OperationTake, LookupSourceDirect, testProcessIncarnation,
	)
	assert.Equal(t, StatusValid, retry.Status)
}

func TestMapHandlerFinishesClaimThatCrossesDeadline(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{identity: validEncodedRecord(t, 10)},
		nil,
		nil,
	)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	handler.claims.(*fakeBridgeMap).afterUpdate = func(_, _ any) {
		<-ctx.Done()
	}

	result := handler.HandleAuthenticated(
		ctx, identity, OperationTake, LookupSourceDirect, testProcessIncarnation,
	)
	assert.Equal(t, StatusValid, result.Status)
	require.ErrorIs(t, ctx.Err(), context.DeadlineExceeded)
	assert.Equal(t, StatusAlreadyConsumed, handler.Handle(identity, OperationTake).Status)
}

func TestMapHandlerRejectsReusedPeerProcessIncarnation(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{identity: validEncodedRecord(t, 10)},
		nil,
		nil,
	)

	result := handler.HandleAuthenticated(
		t.Context(), identity, OperationNegotiate, LookupSourceDirect, testProcessIncarnation+1,
	)
	assert.Equal(t, StatusUnauthorized, result.Status)
	assert.Equal(
		t, StatusMissing,
		handler.HandleAuthenticated(
			t.Context(), identity, OperationNegotiate, LookupSourceDirect, testProcessIncarnation,
		).Status,
	)
	assert.Equal(
		t, StatusValid,
		handler.HandleAuthenticated(
			t.Context(), identity, OperationTake, LookupSourceDirect, testProcessIncarnation,
		).Status,
	)
}

func TestMapHandlerRequiresExactProcessCapability(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	process := javaProcessIdentity(identity)

	t.Run("missing userspace authorization", func(t *testing.T) {
		handler := testMapHandler(nil, nil, nil)
		delete(handler.authorized.(*fakeBridgeMap).values, process)

		assert.Equal(
			t, StatusUnauthorized,
			handler.HandleAuthenticated(
				t.Context(), identity, OperationNegotiate, LookupSourceDirect, testProcessIncarnation,
			).Status,
		)
	})

	t.Run("registered token differs from authorization", func(t *testing.T) {
		handler := testMapHandler(nil, nil, nil)
		handler.incarnations.(*fakeBridgeMap).values[process] = testProcessIncarnation + 1

		assert.Equal(
			t, StatusUnauthorized,
			handler.HandleAuthenticated(
				t.Context(), identity, OperationNegotiate, LookupSourceDirect, testProcessIncarnation,
			).Status,
		)
	})
}

func TestMapHandlerResolvesOneExecutorParent(t *testing.T) {
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	parent := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{parent: validEncodedRecord(t, 10)},
		map[Identity]any{child: activeTaskLink(parent, 10)},
		nil,
	)

	assert.Equal(t, StatusValid, handler.HandleTask(child, OperationTake).Status)
}

func TestMapHandlerLinkedParentSurvivesOwnerReuse(t *testing.T) {
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)},
		map[Identity]any{child: activeTaskLink(owner, 10)},
		nil,
	)

	delete(handler.owners.(*fakeBridgeMap).values, owner)
	delete(handler.remoteParents.(*fakeBridgeMap).values, owner)
	handler.remoteParents.(*fakeBridgeMap).values[owner] = validEncodedRecord(t, 11)
	seedOwnerState(handler, owner, 11)

	linked := handler.HandleTask(child, OperationTake)
	assert.Equal(t, StatusValid, linked.Status)
	assert.Equal(t, uint64(10), linked.Generation)
	assert.NotContains(t, handler.states.(*fakeBridgeMap).values, stateKey{
		Owner: owner, Generation: 10,
	})
	assert.Contains(t, handler.states.(*fakeBridgeMap).values, stateKey{
		Owner: owner, Generation: 11,
	})
	assert.Equal(t, uint64(11), handler.owners.(*fakeBridgeMap).values[owner].(ownerValue).Generation)

	direct := handler.Handle(owner, OperationTake)
	assert.Equal(t, StatusValid, direct.Status)
	assert.Equal(t, uint64(11), direct.Generation)
}

func TestMapHandlerLinkedParentRequiresCompletePreservedState(t *testing.T) {
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	owner := Identity{TID: 3, PID: 2, Namespace: 1}

	tests := []struct {
		name      string
		configure func(*MapHandler, stateKey)
	}{
		{
			name: "aliases",
			configure: func(handler *MapHandler, key stateKey) {
				state := handler.states.(*fakeBridgeMap).values[key].(stateValue)
				state.Aliases = 0
				handler.states.(*fakeBridgeMap).values[key] = state
			},
		},
		{
			name: "generation index",
			configure: func(handler *MapHandler, key stateKey) {
				delete(handler.generations.(*fakeBridgeMap).values, key)
			},
		},
		{
			name: "connection",
			configure: func(handler *MapHandler, _ stateKey) {
				clear(handler.connections.(*fakeBridgeMap).values)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := testMapHandler(
				map[Identity]any{owner: validEncodedRecord(t, 10)},
				map[Identity]any{child: activeTaskLink(owner, 10)},
				nil,
			)
			key := stateKey{Owner: owner, Generation: 10}
			test.configure(handler, key)

			assert.NotEqual(t, StatusValid, handler.HandleTask(child, OperationTake).Status)
		})
	}
}

func TestMapHandlerRejectsConflictingResolution(t *testing.T) {
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	parent := Identity{TID: 3, PID: 2, Namespace: 1}

	t.Run("direct and task sources remain independent", func(t *testing.T) {
		handler := testMapHandler(
			map[Identity]any{
				child:  validEncodedRecord(t, 10),
				parent: validEncodedRecord(t, 11),
			},
			map[Identity]any{child: activeTaskLink(parent, 11)},
			nil,
		)
		direct := handler.Handle(child, OperationTake)
		assert.Equal(t, StatusValid, direct.Status)
		assert.Equal(t, uint64(10), direct.Generation)
		assert.Contains(t, handler.remoteParents.(*fakeBridgeMap).values, parent)

		linked := handler.HandleTask(child, OperationTake)
		assert.Equal(t, StatusValid, linked.Status)
		assert.Equal(t, uint64(11), linked.Generation)
	})

	t.Run("task-only state cannot satisfy a direct lookup", func(t *testing.T) {
		handler := testMapHandler(
			map[Identity]any{parent: validEncodedRecord(t, 11)},
			map[Identity]any{child: activeTaskLink(parent, 11)},
			nil,
		)

		direct := handler.Handle(child, OperationTake)
		assert.Equal(t, StatusMissing, direct.Status)
		assert.Contains(t, handler.remoteParents.(*fakeBridgeMap).values, parent)
		assert.Contains(t, handler.tasks.(*fakeBridgeMap).values, child)
		assert.Empty(t, handler.claims.(*fakeBridgeMap).values)
	})

	t.Run("self link", func(t *testing.T) {
		handler := testMapHandler(
			nil,
			map[Identity]any{child: activeTaskLink(child, 10)},
			nil,
		)
		assert.Equal(t, StatusMissing, handler.HandleTask(child, OperationTake).Status)
	})

	t.Run("kernel marker", func(t *testing.T) {
		handler := testMapHandler(
			map[Identity]any{child: validEncodedRecord(t, 10)},
			nil,
			map[Identity]any{child: uint64(1)},
		)
		assert.Equal(t, StatusAmbiguous, handler.Handle(child, OperationTake).Status)
		assert.Empty(t, handler.remoteParents.(*fakeBridgeMap).values)
	})

	t.Run("fallback record", func(t *testing.T) {
		encoded, err := (Record{Status: StatusAmbiguous}).MarshalBinary()
		require.NoError(t, err)
		handler := testMapHandler(
			map[Identity]any{child: [RecordSize]byte(encoded)},
			nil,
			nil,
		)
		assert.Equal(t, StatusAmbiguous, handler.Handle(child, OperationTake).Status)
	})

	t.Run("stale linked owner does not leak a marker", func(t *testing.T) {
		handler := testMapHandler(
			map[Identity]any{child: validEncodedRecord(t, 10)},
			map[Identity]any{child: activeTaskLink(parent, 11)},
			nil,
		)

		assert.Equal(t, StatusValid, handler.Handle(child, OperationTake).Status)
		assert.NotContains(t, handler.ambiguity.(*fakeBridgeMap).values, stateKey{
			Owner: parent, Generation: 11,
		})
	})
}

func TestMapHandlerRejectsStaleOrReusedExecutorLink(t *testing.T) {
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	owner := Identity{TID: 3, PID: 2, Namespace: 1}

	t.Run("expired", func(t *testing.T) {
		link := activeTaskLink(owner, 10)
		link.ObservedMonotonicNS = uint64(10 * time.Second)
		handler := testMapHandler(
			map[Identity]any{owner: validEncodedRecord(t, 10)},
			map[Identity]any{child: link},
			nil,
		)
		handler.monoTimeNow = func() time.Duration { return 41 * time.Second }

		assert.Equal(t, StatusMissing, handler.HandleTask(child, OperationTake).Status)
		assert.Contains(t, handler.remoteParents.(*fakeBridgeMap).values, owner)
	})

	t.Run("generation mismatch", func(t *testing.T) {
		handler := testMapHandler(
			map[Identity]any{owner: validEncodedRecord(t, 11)},
			map[Identity]any{child: activeTaskLink(owner, 10)},
			nil,
		)

		assert.Equal(t, StatusMissing, handler.HandleTask(child, OperationTake).Status)
		assert.Contains(t, handler.remoteParents.(*fakeBridgeMap).values, owner)
	})

	t.Run("missing generation", func(t *testing.T) {
		link := activeTaskLink(owner, 0)
		handler := testMapHandler(
			map[Identity]any{owner: validEncodedRecord(t, 10)},
			map[Identity]any{child: link},
			nil,
		)

		assert.Equal(t, StatusMissing, handler.HandleTask(child, OperationTake).Status)
	})

	t.Run("replacement after stale lookup", func(t *testing.T) {
		stale := activeTaskLink(owner, 9)
		stale.ObservedMonotonicNS = uint64(10 * time.Second)
		replacement := activeTaskLink(owner, 10)
		handler := testMapHandler(
			map[Identity]any{owner: validEncodedRecord(t, 10)},
			map[Identity]any{child: stale},
			nil,
		)
		handler.monoTimeNow = func() time.Duration { return 41 * time.Second }
		tasks := handler.tasks.(*fakeBridgeMap)
		tasks.afterLookup = func(count int) {
			if count != 1 {
				return
			}
			tasks.mu.Lock()
			tasks.values[child] = replacement
			tasks.mu.Unlock()
			key := stateKey{Owner: owner, Generation: replacement.Generation}
			state := handler.states.(*fakeBridgeMap).values[key].(stateValue)
			state.Aliases = 1
			handler.states.(*fakeBridgeMap).values[key] = state
		}

		assert.Equal(t, StatusMissing, handler.HandleTask(child, OperationTake).Status)
		assert.Equal(t, replacement, tasks.values[child])

		handler.monoTimeNow = func() time.Duration { return 11 * time.Second }
		assert.Equal(t, StatusValid, handler.HandleTask(child, OperationTake).Status)
	})
}

func TestMapHandlerTranslatesMountedVirtualThreads(t *testing.T) {
	carrier := Identity{TID: 4, PID: 2, Namespace: 1}
	virtualOwner := carrier
	virtualOwner.TID = virtualThreadTIDFlag | 42
	handler := testMapHandler(
		map[Identity]any{virtualOwner: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	mountVirtualThread(handler, carrier, 42)

	assert.Equal(t, StatusValid, handler.Handle(carrier, OperationTake).Status)
}

func TestMapHandlerVirtualThreadRemountAndCarrierReuse(t *testing.T) {
	carrierOne := Identity{TID: 4, PID: 2, Namespace: 1}
	carrierTwo := Identity{TID: 5, PID: 2, Namespace: 1}
	virtualOwner := carrierOne
	virtualOwner.TID = virtualThreadTIDFlag | 42
	handler := testMapHandler(
		map[Identity]any{virtualOwner: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	mountVirtualThread(handler, carrierOne, 42)

	assert.Equal(t, StatusValid, handler.Handle(carrierOne, OperationTake).Status)
	delete(handler.virtualThreads.(*fakeBridgeMap).values, carrierOne)
	mountVirtualThread(handler, carrierTwo, 42)
	assert.Equal(t, StatusAlreadyConsumed, handler.Handle(carrierTwo, OperationTake).Status)

	virtualOwner.TID = virtualThreadTIDFlag | 43
	handler.remoteParents.(*fakeBridgeMap).values[virtualOwner] = validEncodedRecord(t, 11)
	seedOwnerState(handler, virtualOwner, 11)
	delete(handler.virtualThreads.(*fakeBridgeMap).values, carrierTwo)
	mountVirtualThread(handler, carrierOne, 43)
	assert.Equal(t, StatusValid, handler.Handle(carrierOne, OperationTake).Status)
}

func TestMapHandlerDoesNotTranslateUnmountedCarrier(t *testing.T) {
	carrier := Identity{TID: 4, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{carrier: validEncodedRecord(t, 10)},
		nil,
		nil,
	)

	assert.Equal(t, StatusValid, handler.Handle(carrier, OperationTake).Status)
}

func TestMapHandlerVirtualThreadDiscardConsumesSyntheticOwner(t *testing.T) {
	carrier := Identity{TID: 4, PID: 2, Namespace: 1}
	virtualOwner := carrier
	virtualOwner.TID = virtualThreadTIDFlag | 42
	handler := testMapHandler(
		map[Identity]any{virtualOwner: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	mountVirtualThread(handler, carrier, uint64(1)<<63|42)

	assert.Equal(t, StatusMissing, handler.Handle(carrier, OperationDiscard).Status)
	assert.Empty(t, handler.remoteParents.(*fakeBridgeMap).values)
}

func TestMapHandlerRejectsUnverifiedMountedVirtualThread(t *testing.T) {
	carrier := Identity{TID: 4, PID: 2, Namespace: 1}
	const virtualThreadID = uint64(42)
	virtualOwner := javaVirtualThreadOwner(carrier, virtualThreadID)

	tests := []struct {
		name     string
		expected Status
		mutate   func(*MapHandler)
	}{
		{
			name:     "zero mounted virtual thread id",
			expected: StatusAmbiguous,
			mutate: func(handler *MapHandler) {
				mounted := handler.virtualThreads.(*fakeBridgeMap).values[carrier].(virtualThreadIdentity)
				mounted.VirtualThreadID = 0
				handler.virtualThreads.(*fakeBridgeMap).values[carrier] = mounted
			},
		},
		{
			name:     "zero mounted process incarnation",
			expected: StatusAmbiguous,
			mutate: func(handler *MapHandler) {
				mounted := handler.virtualThreads.(*fakeBridgeMap).values[carrier].(virtualThreadIdentity)
				mounted.ProcessIncarnation = 0
				handler.virtualThreads.(*fakeBridgeMap).values[carrier] = mounted
			},
		},
		{
			name:     "missing current process incarnation",
			expected: StatusMissing,
			mutate: func(handler *MapHandler) {
				delete(handler.incarnations.(*fakeBridgeMap).values, javaProcessIdentity(carrier))
			},
		},
		{
			name:     "changed current process incarnation",
			expected: StatusUnauthorized,
			mutate: func(handler *MapHandler) {
				handler.incarnations.(*fakeBridgeMap).values[javaProcessIdentity(carrier)] = uint64(9)
			},
		},
		{
			name:     "missing full identity guard",
			expected: StatusMissing,
			mutate: func(handler *MapHandler) {
				delete(handler.vtIdentities.(*fakeBridgeMap).values, virtualOwner)
			},
		},
		{
			name:     "different full virtual thread id",
			expected: StatusAmbiguous,
			mutate: func(handler *MapHandler) {
				registered := handler.vtIdentities.(*fakeBridgeMap).values[virtualOwner].(virtualThreadIdentity)
				registered.VirtualThreadID += uint64(1) << 31
				handler.vtIdentities.(*fakeBridgeMap).values[virtualOwner] = registered
			},
		},
		{
			name:     "different guarded process incarnation",
			expected: StatusAmbiguous,
			mutate: func(handler *MapHandler) {
				registered := handler.vtIdentities.(*fakeBridgeMap).values[virtualOwner].(virtualThreadIdentity)
				registered.ProcessIncarnation++
				handler.vtIdentities.(*fakeBridgeMap).values[virtualOwner] = registered
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := testMapHandler(
				map[Identity]any{virtualOwner: validEncodedRecord(t, 10)},
				nil,
				nil,
			)
			mountVirtualThread(handler, carrier, virtualThreadID)
			test.mutate(handler)

			assert.Equal(t, test.expected, handler.Handle(carrier, OperationTake).Status)
			assert.NotEmpty(t, handler.remoteParents.(*fakeBridgeMap).values)
		})
	}
}

func TestMapHandlerRejectsFullWidthVirtualThreadCollision(t *testing.T) {
	carrier := Identity{TID: 4, PID: 2, Namespace: 1}
	const originalID = uint64(42)
	collidingID := originalID + uint64(1)<<31
	virtualOwner := javaVirtualThreadOwner(carrier, originalID)
	handler := testMapHandler(
		map[Identity]any{virtualOwner: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	mountVirtualThread(handler, carrier, originalID)
	mounted := handler.virtualThreads.(*fakeBridgeMap).values[carrier].(virtualThreadIdentity)
	mounted.VirtualThreadID = collidingID
	handler.virtualThreads.(*fakeBridgeMap).values[carrier] = mounted

	assert.Equal(t, StatusAmbiguous, handler.Handle(carrier, OperationTake).Status)
	assert.NotEmpty(t, handler.remoteParents.(*fakeBridgeMap).values)
}

func TestMapHandlerRequiresCurrentProcessIncarnation(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	process := javaProcessIdentity(identity)

	for _, test := range []struct {
		name     string
		expected Status
		mutate   func(*MapHandler)
	}{
		{
			name:     "missing registration",
			expected: StatusMissing,
			mutate: func(handler *MapHandler) {
				delete(handler.incarnations.(*fakeBridgeMap).values, process)
			},
		},
		{
			name:     "zero registration",
			expected: StatusAmbiguous,
			mutate: func(handler *MapHandler) {
				handler.incarnations.(*fakeBridgeMap).values[process] = uint64(0)
			},
		},
		{
			name:     "owner from prior process",
			expected: StatusAmbiguous,
			mutate: func(handler *MapHandler) {
				owner := handler.owners.(*fakeBridgeMap).values[identity].(ownerValue)
				owner.ProcessIncarnation++
				handler.owners.(*fakeBridgeMap).values[identity] = owner
			},
		},
		{
			name:     "state from prior process",
			expected: StatusAmbiguous,
			mutate: func(handler *MapHandler) {
				key := stateKey{Owner: identity, Generation: 10}
				state := handler.states.(*fakeBridgeMap).values[key].(stateValue)
				state.ProcessIncarnation++
				handler.states.(*fakeBridgeMap).values[key] = state
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := testMapHandler(
				map[Identity]any{identity: validEncodedRecord(t, 10)},
				nil,
				nil,
			)
			test.mutate(handler)

			assert.Equal(t, test.expected, handler.Handle(identity, OperationTake).Status)
			assert.NotEmpty(t, handler.remoteParents.(*fakeBridgeMap).values)
		})
	}

	t.Run("terminal from prior process", func(t *testing.T) {
		handler := testMapHandler(nil, nil, nil)
		handler.terminals.(*fakeBridgeMap).values[identity] = terminalValue{
			Generation:          10,
			ObservedMonotonicNS: uint64(10 * time.Second),
			ProcessIncarnation:  testProcessIncarnation + 1,
			Lifecycle:           lifecycleConsumed,
		}

		assert.Equal(t, StatusAmbiguous, handler.Handle(identity, OperationTake).Status)
	})
}

func TestMapHandlerConsumedCacheIsScopedToProcessIncarnation(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{identity: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	assert.Equal(t, StatusValid, handler.Handle(identity, OperationTake).Status)

	const nextIncarnation = testProcessIncarnation + 1
	handler.authorized.(*fakeBridgeMap).values[javaProcessIdentity(identity)] = nextIncarnation
	handler.incarnations.(*fakeBridgeMap).values[javaProcessIdentity(identity)] = nextIncarnation
	handler.remoteParents.(*fakeBridgeMap).values[identity] = validEncodedRecord(t, 11)
	seedOwnerStateWithIncarnation(handler, identity, 11, nextIncarnation)

	assert.Equal(t, StatusValid, handler.Handle(identity, OperationTake).Status)
}

func TestMapHandlerRejectsStaleAndMalformedRecords(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}

	t.Run("stale", func(t *testing.T) {
		handler := testMapHandler(
			map[Identity]any{identity: validEncodedRecord(t, 10)},
			nil,
			nil,
		)
		handler.monoTimeNow = func() time.Duration { return 41 * time.Second }
		assert.Equal(t, StatusStale, handler.Handle(identity, OperationTake).Status)
	})

	t.Run("malformed", func(t *testing.T) {
		handler := testMapHandler(
			map[Identity]any{identity: [RecordSize]byte{}},
			nil,
			nil,
		)
		assert.Equal(t, StatusMalformed, handler.Handle(identity, OperationTake).Status)
	})

	t.Run("version mismatch", func(t *testing.T) {
		encoded := validEncodedRecord(t, 10)
		encoded[4] = 2
		handler := testMapHandler(
			map[Identity]any{identity: encoded},
			nil,
			nil,
		)
		assert.Equal(t, StatusVersionMismatch, handler.Handle(identity, OperationTake).Status)
	})
}

func TestMapHandlerQuarantinesMalformedFallbackAndAllowsOwnerReuse(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{identity: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	handler.remoteParents.(*fakeBridgeMap).values[identity] = [RecordSize]byte{}

	assert.Equal(t, StatusMalformed, handler.Handle(identity, OperationTake).Status)
	assert.Empty(t, handler.remoteParents.(*fakeBridgeMap).values)
	assert.Empty(t, handler.owners.(*fakeBridgeMap).values)
	assert.Empty(t, handler.states.(*fakeBridgeMap).values)
	assert.Empty(t, handler.generations.(*fakeBridgeMap).values)
	assert.Empty(t, handler.connections.(*fakeBridgeMap).values)
	assert.Empty(t, handler.cookieConnections.(*fakeBridgeMap).values)

	handler.remoteParents.(*fakeBridgeMap).values[identity] = validEncodedRecord(t, 11)
	seedOwnerState(handler, identity, 11)
	assert.Equal(t, StatusValid, handler.Handle(identity, OperationTake).Status)
}

func TestMapHandlerMalformedFallbackQuarantinePreservesReplacement(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{identity: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	handler.remoteParents.(*fakeBridgeMap).values[identity] = [RecordSize]byte{}
	remoteParents := handler.remoteParents.(*fakeBridgeMap)
	remoteParents.afterLookup = func(count int) {
		if count != 3 {
			return
		}
		remoteParents.mu.Lock()
		remoteParents.values[identity] = validEncodedRecord(t, 11)
		remoteParents.mu.Unlock()
		handler.owners.(*fakeBridgeMap).values[identity] = ownerValue{
			Generation:         11,
			ProcessIncarnation: testProcessIncarnation,
			Lifecycle:          lifecycleActive,
		}
	}

	assert.Equal(t, StatusMalformed, handler.Handle(identity, OperationTake).Status)
	var preserved [RecordSize]byte
	require.NoError(t, remoteParents.Lookup(&identity, &preserved))
	record, err := UnmarshalRecord(preserved[:])
	require.NoError(t, err)
	assert.Equal(t, uint64(11), record.Generation)
}

func TestMapHandlerQuarantinesMalformedFallbackWithInvalidOwner(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	tests := []struct {
		name  string
		owner ownerValue
	}{
		{
			name: "zero generation",
			owner: ownerValue{
				ProcessIncarnation: testProcessIncarnation,
				Lifecycle:          lifecycleActive,
			},
		},
		{
			name: "reserved bytes",
			owner: ownerValue{
				Generation:         10,
				ProcessIncarnation: testProcessIncarnation,
				Lifecycle:          lifecycleActive,
				Reserved:           [7]byte{1},
			},
		},
		{
			name: "stale incarnation",
			owner: ownerValue{
				Generation:         10,
				ProcessIncarnation: testProcessIncarnation + 1,
				Lifecycle:          lifecycleActive,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := testMapHandler(
				map[Identity]any{identity: validEncodedRecord(t, 10)},
				nil,
				nil,
			)
			handler.remoteParents.(*fakeBridgeMap).values[identity] = [RecordSize]byte{}
			handler.owners.(*fakeBridgeMap).values[identity] = test.owner

			assert.Equal(t, StatusMalformed, handler.Handle(identity, OperationTake).Status)
			assert.Empty(t, handler.remoteParents.(*fakeBridgeMap).values)
			assert.Empty(t, handler.owners.(*fakeBridgeMap).values)

			handler.remoteParents.(*fakeBridgeMap).values[identity] = validEncodedRecord(t, 11)
			seedOwnerState(handler, identity, 11)
			assert.Equal(t, StatusValid, handler.Handle(identity, OperationTake).Status)
		})
	}
}

func TestMapHandlerDiscardDoesNotReturnContext(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{identity: validEncodedRecord(t, 10)},
		nil,
		nil,
	)

	result := handler.Handle(identity, OperationDiscard)
	assert.Equal(t, StatusMissing, result.Status)
	assert.False(t, result.IsValidRemoteParent())
	assert.Equal(t, StatusAlreadyConsumed, handler.Handle(identity, OperationTake).Status)
}

func TestMapHandlerHonorsTerminalFromPrimaryTransport(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	child := Identity{TID: 4, PID: 2, Namespace: 1}

	tests := []struct {
		name      string
		identity  Identity
		tasks     map[Identity]any
		lifecycle uint8
		status    Status
	}{
		{
			name:      "direct consumed",
			identity:  owner,
			lifecycle: lifecycleConsumed,
			status:    StatusAlreadyConsumed,
		},
		{
			name:      "linked discarded",
			identity:  child,
			tasks:     map[Identity]any{child: activeTaskLink(owner, 10)},
			lifecycle: lifecycleDiscarded,
			status:    StatusAlreadyConsumed,
		},
		{
			name:      "direct stale",
			identity:  owner,
			lifecycle: lifecycleStale,
			status:    StatusStale,
		},
		{
			name:      "direct ambiguous",
			identity:  owner,
			lifecycle: lifecycleAmbiguous,
			status:    StatusAmbiguous,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := testMapHandler(nil, test.tasks, nil)
			handler.terminals.(*fakeBridgeMap).values[owner] = terminalValue{
				Generation:          10,
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  testProcessIncarnation,
				Lifecycle:           test.lifecycle,
			}

			var result Record
			if test.tasks != nil {
				result = handler.HandleTask(test.identity, OperationTake)
			} else {
				result = handler.Handle(test.identity, OperationTake)
			}
			assert.Equal(t, test.status, result.Status)
		})
	}
}

func TestMapHandlerCleansKernelStateBeforeSequentialRequest(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{identity: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	seedOwnerState(handler, identity, 10)

	assert.Equal(t, StatusValid, handler.Handle(identity, OperationTake).Status)
	assert.Empty(t, handler.owners.(*fakeBridgeMap).values)
	assert.Empty(t, handler.states.(*fakeBridgeMap).values)
	assert.Empty(t, handler.claims.(*fakeBridgeMap).values)

	handler.remoteParents.(*fakeBridgeMap).values[identity] = validEncodedRecord(t, 11)
	seedOwnerState(handler, identity, 11)
	assert.Equal(t, StatusValid, handler.Handle(identity, OperationTake).Status)
}

func TestMapHandlerReleasesConnectionHandoff(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	connection := connectionInfo{SourcePort: 12345, DestinationPort: 443}
	const connectionNetNS = uint32(17)
	handler := testMapHandler(
		map[Identity]any{identity: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	seedOwnerState(handler, identity, 10)
	requestKey := stateKey{Owner: identity, Generation: 10}
	state := handler.states.(*fakeBridgeMap).values[requestKey].(stateValue)
	clear(handler.connections.(*fakeBridgeMap).values)
	clear(handler.cookieConnections.(*fakeBridgeMap).values)
	state.Connection = connection
	state.ConnectionNetNS = connectionNetNS
	handler.states.(*fakeBridgeMap).values[requestKey] = state
	seedConnectionClaim(handler, connectionInfoNS{
		Connection: connection,
		NetNS:      connectionNetNS,
	}, identity, 10)

	assert.Equal(t, StatusValid, handler.Handle(identity, OperationTake).Status)
	assert.Empty(t, handler.connections.(*fakeBridgeMap).values)
	assert.Empty(t, handler.cookieConnections.(*fakeBridgeMap).values)
}

func TestMapHandlerConnectionCleanupIsNetworkNamespaceScoped(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{identity: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	requestKey := stateKey{Owner: identity, Generation: 10}
	state := handler.states.(*fakeBridgeMap).values[requestKey].(stateValue)
	otherKey := connectionInfoNS{
		Connection: state.Connection,
		NetNS:      state.ConnectionNetNS + 1,
	}
	otherOwner := Identity{TID: 99, PID: 98, Namespace: 97}
	seedConnectionClaim(handler, otherKey, otherOwner, 11)
	otherClaim := handler.connections.(*fakeBridgeMap).values[otherKey].(connectionClaim)
	otherCookieKey := connectionCookieKey(otherKey, otherClaim)

	assert.Equal(t, StatusValid, handler.Handle(identity, OperationTake).Status)
	assert.Equal(t, otherClaim, handler.connections.(*fakeBridgeMap).values[otherKey])
	assert.Equal(t, otherClaim,
		handler.cookieConnections.(*fakeBridgeMap).values[otherCookieKey])
}

func TestMapHandlerHonorsClaimFromPrimaryTransport(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{identity: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	seedOwnerState(handler, identity, 10)
	handler.claims.(*fakeBridgeMap).values[stateKey{
		Owner: identity, Generation: 10,
	}] = testGenerationClaim(lifecycleConsumed)

	assert.Equal(t, StatusAlreadyConsumed, handler.Handle(identity, OperationTake).Status)
	assert.NotEmpty(t, handler.remoteParents.(*fakeBridgeMap).values)
}

func TestMapHandlerHonorsAmbiguousClaimFromPrimaryTransport(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{identity: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	handler.claims.(*fakeBridgeMap).values[stateKey{
		Owner: identity, Generation: 10,
	}] = testGenerationClaim(lifecycleAmbiguous)

	assert.Equal(t, StatusAmbiguous, handler.Handle(identity, OperationTake).Status)
	assert.NotEmpty(t, handler.remoteParents.(*fakeBridgeMap).values)
}

func TestMapHandlerRejectsUncommittedGenerationWithoutCleanup(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}

	tests := []struct {
		name             string
		status           Status
		breakPublication func(*MapHandler)
	}{
		{
			name:   "owner commit marker missing",
			status: StatusMissing,
			breakPublication: func(handler *MapHandler) {
				delete(handler.owners.(*fakeBridgeMap).values, identity)
			},
		},
		{
			name:   "state missing",
			status: StatusMissing,
			breakPublication: func(handler *MapHandler) {
				delete(handler.states.(*fakeBridgeMap).values, stateKey{Owner: identity, Generation: 10})
			},
		},
		{
			name:   "connection index missing",
			status: StatusAmbiguous,
			breakPublication: func(handler *MapHandler) {
				clear(handler.connections.(*fakeBridgeMap).values)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := testMapHandler(
				map[Identity]any{identity: validEncodedRecord(t, 10)},
				nil,
				nil,
			)
			test.breakPublication(handler)

			assert.Equal(t, test.status, handler.Handle(identity, OperationTake).Status)
			assert.NotEmpty(t, handler.remoteParents.(*fakeBridgeMap).values)
			assert.Empty(t, handler.claims.(*fakeBridgeMap).values)
		})
	}
}

func TestMapHandlerRevalidatesPublicationAfterClaim(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}

	t.Run("owner disappears", func(t *testing.T) {
		handler := testMapHandler(
			map[Identity]any{identity: validEncodedRecord(t, 10)},
			nil,
			nil,
		)
		handler.claims.(*fakeBridgeMap).afterUpdate = func(any, any) {
			delete(handler.owners.(*fakeBridgeMap).values, identity)
		}

		assert.Equal(t, StatusAlreadyConsumed, handler.Handle(identity, OperationTake).Status)
		assert.NotEmpty(t, handler.remoteParents.(*fakeBridgeMap).values)
		assert.Empty(t, handler.claims.(*fakeBridgeMap).values)
	})

	t.Run("state disappears", func(t *testing.T) {
		handler := testMapHandler(
			map[Identity]any{identity: validEncodedRecord(t, 10)},
			nil,
			nil,
		)
		handler.claims.(*fakeBridgeMap).afterUpdate = func(any, any) {
			delete(handler.states.(*fakeBridgeMap).values, stateKey{Owner: identity, Generation: 10})
		}

		assert.Equal(t, StatusMissing, handler.Handle(identity, OperationTake).Status)
		assert.Empty(t, handler.remoteParents.(*fakeBridgeMap).values)
		assert.Empty(t, handler.claims.(*fakeBridgeMap).values)
	})

	t.Run("connection changes", func(t *testing.T) {
		handler := testMapHandler(
			map[Identity]any{identity: validEncodedRecord(t, 10)},
			nil,
			nil,
		)
		handler.claims.(*fakeBridgeMap).afterUpdate = func(any, any) {
			for connection := range handler.connections.(*fakeBridgeMap).values {
				handler.connections.(*fakeBridgeMap).values[connection] = connectionClaim{
					Owner:      identity,
					Generation: 11,
				}
			}
		}

		assert.Equal(t, StatusAmbiguous, handler.Handle(identity, OperationTake).Status)
		assert.Empty(t, handler.remoteParents.(*fakeBridgeMap).values)
		assert.Empty(t, handler.claims.(*fakeBridgeMap).values)
	})

	t.Run("fallback changes generation", func(t *testing.T) {
		handler := testMapHandler(
			map[Identity]any{identity: validEncodedRecord(t, 10)},
			nil,
			nil,
		)
		handler.claims.(*fakeBridgeMap).afterUpdate = func(any, any) {
			handler.remoteParents.(*fakeBridgeMap).values[identity] = validEncodedRecord(t, 11)
		}

		assert.Equal(t, StatusAmbiguous, handler.Handle(identity, OperationTake).Status)
		var preserved [RecordSize]byte
		require.NoError(t, handler.remoteParents.Lookup(&identity, &preserved))
		record, err := UnmarshalRecord(preserved[:])
		require.NoError(t, err)
		assert.Equal(t, uint64(11), record.Generation)
		assert.Empty(t, handler.claims.(*fakeBridgeMap).values)
	})
}

func TestMapHandlerLateConsumerPreservesNextGeneration(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{identity: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	seedOwnerState(handler, identity, 10)

	remoteParents := handler.remoteParents.(*fakeBridgeMap)
	remoteParents.afterLookup = func(count int) {
		if count != 2 {
			return
		}
		remoteParents.mu.Lock()
		remoteParents.values[identity] = validEncodedRecord(t, 11)
		remoteParents.mu.Unlock()
		handler.owners.(*fakeBridgeMap).values[identity] = ownerValue{
			Generation:         11,
			ProcessIncarnation: testProcessIncarnation,
			Lifecycle:          lifecycleActive,
		}
	}

	assert.Equal(t, StatusAlreadyConsumed, handler.Handle(identity, OperationTake).Status)
	var restored [RecordSize]byte
	require.NoError(t, remoteParents.Lookup(&identity, &restored))
	record, err := UnmarshalRecord(restored[:])
	require.NoError(t, err)
	assert.Equal(t, uint64(11), record.Generation)
	assert.Empty(t, handler.claims.(*fakeBridgeMap).values)

	seedOwnerState(handler, identity, 11)
	assert.Equal(t, StatusValid, handler.Handle(identity, OperationTake).Status)
}

func TestMapHandlerTaskSourceIgnoresAConcurrentDirectGeneration(t *testing.T) {
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	parent := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{
			child:  validEncodedRecord(t, 10),
			parent: validEncodedRecord(t, 11),
		},
		map[Identity]any{child: activeTaskLink(parent, 11)},
		nil,
	)
	linked := handler.HandleTask(child, OperationTake)
	assert.Equal(t, StatusValid, linked.Status)
	assert.Equal(t, uint64(11), linked.Generation)
	remoteParents := handler.remoteParents.(*fakeBridgeMap)
	var preserved [RecordSize]byte
	require.NoError(t, remoteParents.Lookup(&child, &preserved))
	record, err := UnmarshalRecord(preserved[:])
	require.NoError(t, err)
	assert.Equal(t, uint64(10), record.Generation)
}

func TestMapHandlerRevalidatesBeforeDeletingReusableKeys(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}

	t.Run("fallback", func(t *testing.T) {
		handler := testMapHandler(
			map[Identity]any{identity: validEncodedRecord(t, 10)},
			nil,
			nil,
		)
		remoteParents := handler.remoteParents.(*fakeBridgeMap)
		remoteParents.afterLookup = func(count int) {
			if count != 1 {
				return
			}
			remoteParents.mu.Lock()
			remoteParents.values[identity] = validEncodedRecord(t, 11)
			remoteParents.mu.Unlock()
			handler.owners.(*fakeBridgeMap).values[identity] = ownerValue{
				Generation:         11,
				ProcessIncarnation: testProcessIncarnation,
				Lifecycle:          lifecycleActive,
			}
		}

		assert.True(t, handler.deleteRemoteParentGeneration(
			identity, 10, testProcessIncarnation,
		))
		assert.Contains(t, remoteParents.values, identity)
	})

	t.Run("owner", func(t *testing.T) {
		handler := testMapHandler(
			map[Identity]any{identity: validEncodedRecord(t, 10)},
			nil,
			nil,
		)
		owners := handler.owners.(*fakeBridgeMap)
		owners.afterLookup = func(count int) {
			if count == 1 {
				owners.mu.Lock()
				owners.values[identity] = ownerValue{
					Generation:         11,
					ProcessIncarnation: testProcessIncarnation,
					Lifecycle:          lifecycleActive,
				}
				owners.mu.Unlock()
			}
		}

		assert.False(t, handler.deleteOwnerGeneration(
			identity, 10, testProcessIncarnation,
		))
		assert.Equal(t, uint64(11), owners.values[identity].(ownerValue).Generation)
	})

	t.Run("connection", func(t *testing.T) {
		handler := testMapHandler(nil, nil, nil)
		key := connectionInfoNS{
			Connection: connectionInfo{SourcePort: 12345, DestinationPort: 443},
			NetNS:      17,
		}
		connections := handler.connections.(*fakeBridgeMap)
		cookieConnections := handler.cookieConnections.(*fakeBridgeMap)
		seedConnectionClaim(handler, key, identity, 10)
		oldClaim := connections.values[key].(connectionClaim)
		oldCookieKey := connectionCookieKey(key, oldClaim)
		newClaim := oldClaim
		newClaim.Generation = 11
		newClaim.NetNSCookie++
		newClaim.IncomingGeneration++
		newCookieKey := connectionCookieKey(key, newClaim)
		connections.afterLookup = func(count int) {
			if count == 1 {
				connections.mu.Lock()
				connections.values[key] = newClaim
				connections.mu.Unlock()
				cookieConnections.mu.Lock()
				delete(cookieConnections.values, oldCookieKey)
				cookieConnections.values[newCookieKey] = newClaim
				cookieConnections.mu.Unlock()
			}
		}

		assert.True(t, handler.releaseConnection(identity, 10, key.Connection, key.NetNS))
		assert.Equal(t, newClaim, connections.values[key])
		assert.Equal(t, newClaim, cookieConnections.values[newCookieKey])
	})

	t.Run("connection cookie deletion error", func(t *testing.T) {
		handler := testMapHandler(nil, nil, nil)
		key := connectionInfoNS{
			Connection: connectionInfo{SourcePort: 12345, DestinationPort: 443},
			NetNS:      17,
		}
		seedConnectionClaim(handler, key, identity, 10)
		connections := handler.connections.(*fakeBridgeMap)
		cookieConnections := handler.cookieConnections.(*fakeBridgeMap)
		cookieConnections.deleteErr = errors.New("unexpected cookie connection deletion")

		assert.False(t, handler.releaseConnection(identity, 10, key.Connection, key.NetNS))
		assert.Contains(t, connections.values, key)
		assert.NotEmpty(t, cookieConnections.values)

		cookieConnections.deleteErr = nil
		assert.True(t, handler.releaseConnection(identity, 10, key.Connection, key.NetNS))
		assert.Empty(t, connections.values)
		assert.Empty(t, cookieConnections.values)
	})

	t.Run("generation index", func(t *testing.T) {
		handler := testMapHandler(
			map[Identity]any{identity: validEncodedRecord(t, 10)},
			nil,
			nil,
		)
		key := stateKey{Owner: identity, Generation: 10}
		generations := handler.generations.(*fakeBridgeMap)
		generations.afterLookup = func(count int) {
			if count == 1 {
				generations.mu.Lock()
				generations.values[key] = generationIndexValue{
					Process:             javaProcessIdentity(identity),
					ProcessIncarnation:  testProcessIncarnation + 1,
					ObservedMonotonicNS: uint64(11 * time.Second),
				}
				generations.mu.Unlock()
			}
		}

		assert.False(t, handler.deleteGenerationIndex(key, testProcessIncarnation))
		assert.Equal(
			t,
			testProcessIncarnation+1,
			generations.values[key].(generationIndexValue).ProcessIncarnation,
		)
	})
}

func TestMapHandlerReleasesClaimWhenGenerationCleanupFails(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	testError := errors.New("injected map failure")

	tests := []struct {
		name      string
		status    Status
		configure func(*MapHandler)
	}{
		{
			name:   "owner revalidation lookup",
			status: StatusTransportError,
			configure: func(handler *MapHandler) {
				handler.claims.(*fakeBridgeMap).afterUpdate = func(any, any) {
					handler.owners.(*fakeBridgeMap).lookupErr = testError
				}
			},
		},
		{
			name:   "state revalidation lookup",
			status: StatusTransportError,
			configure: func(handler *MapHandler) {
				handler.claims.(*fakeBridgeMap).afterUpdate = func(any, any) {
					handler.states.(*fakeBridgeMap).lookupErr = testError
				}
			},
		},
		{
			name:   "connection delete",
			status: StatusTransportError,
			configure: func(handler *MapHandler) {
				handler.connections.(*fakeBridgeMap).deleteErr = testError
			},
		},
		{
			name:   "terminal update",
			status: StatusTransportError,
			configure: func(handler *MapHandler) {
				handler.terminals.(*fakeBridgeMap).updateErr = testError
			},
		},
		{
			name:   "state delete",
			status: StatusTransportError,
			configure: func(handler *MapHandler) {
				handler.states.(*fakeBridgeMap).deleteErr = testError
			},
		},
		{
			name:   "fallback delete",
			status: StatusTransportError,
			configure: func(handler *MapHandler) {
				handler.remoteParents.(*fakeBridgeMap).deleteErr = testError
			},
		},
		{
			name:   "owner delete",
			status: StatusTransportError,
			configure: func(handler *MapHandler) {
				handler.owners.(*fakeBridgeMap).deleteErr = testError
			},
		},
		{
			name:   "ambiguity delete",
			status: StatusAmbiguous,
			configure: func(handler *MapHandler) {
				handler.claims.(*fakeBridgeMap).afterUpdate = func(any, any) {
					handler.ambiguity.(*fakeBridgeMap).values[stateKey{
						Owner: identity, Generation: 10,
					}] = uint64(11 * time.Second)
					handler.ambiguity.(*fakeBridgeMap).deleteErr = testError
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := testMapHandler(
				map[Identity]any{identity: validEncodedRecord(t, 10)},
				nil,
				nil,
			)
			test.configure(handler)

			assert.Equal(t, test.status, handler.Handle(identity, OperationTake).Status)
			assert.Empty(t, handler.claims.(*fakeBridgeMap).values)
		})
	}
}

func testMapHandler(remoteParents, tasks, ambiguity map[Identity]any) *MapHandler {
	if remoteParents == nil {
		remoteParents = make(map[Identity]any)
	}
	if tasks == nil {
		tasks = make(map[Identity]any)
	}
	if ambiguity == nil {
		ambiguity = make(map[Identity]any)
	}
	handler := &MapHandler{
		remoteParents:     &fakeBridgeMap{values: identityValues(remoteParents)},
		tasks:             &fakeBridgeMap{values: identityValues(tasks)},
		virtualThreads:    &fakeBridgeMap{values: make(map[any]any)},
		vtIdentities:      &fakeBridgeMap{values: make(map[any]any)},
		authorized:        &fakeBridgeMap{values: make(map[any]any)},
		incarnations:      &fakeBridgeMap{values: make(map[any]any)},
		connections:       &fakeBridgeMap{values: make(map[any]any)},
		cookieConnections: &fakeBridgeMap{values: make(map[any]any)},
		ambiguity:         &fakeBridgeMap{values: ambiguityValues(ambiguity, remoteParents)},
		owners:            &fakeBridgeMap{values: make(map[any]any)},
		states:            &fakeBridgeMap{values: make(map[any]any)},
		generations:       &fakeBridgeMap{values: make(map[any]any)},
		terminals:         &fakeBridgeMap{values: make(map[any]any)},
		claims:            &fakeBridgeMap{values: make(map[any]any)},
		ownerGuards:       &fakeBridgeMap{values: make(map[any]any)},
		coordinator:       NewGenerationCoordinator(),
		ttl:               30 * time.Second,
		monoTimeNow:       func() time.Duration { return 11 * time.Second },
		consumed:          make(map[consumedIdentity]time.Duration),
	}
	process := Identity{
		TID:       2,
		PID:       2,
		Namespace: 1,
	}
	handler.authorized.(*fakeBridgeMap).values[process] = testProcessIncarnation
	handler.incarnations.(*fakeBridgeMap).values[process] = testProcessIncarnation
	for identity, encoded := range remoteParents {
		value, ok := encoded.([RecordSize]byte)
		if !ok {
			continue
		}
		record, err := UnmarshalRecord(value[:])
		if err == nil && record.Generation != 0 {
			seedOwnerState(handler, identity, record.Generation)
		}
	}
	for _, value := range tasks {
		link, ok := value.(taskLink)
		if !ok || link.Generation == 0 {
			continue
		}
		key := stateKey{Owner: link.Owner, Generation: link.Generation}
		state, ok := handler.states.(*fakeBridgeMap).values[key].(stateValue)
		if !ok {
			continue
		}
		state.Aliases++
		handler.states.(*fakeBridgeMap).values[key] = state
	}
	return handler
}

func ambiguityValues(
	ambiguity map[Identity]any,
	remoteParents map[Identity]any,
) map[any]any {
	values := make(map[any]any, len(ambiguity))
	for identity, value := range ambiguity {
		generation := uint64(10)
		if encoded, ok := remoteParents[identity].([RecordSize]byte); ok {
			if record, err := UnmarshalRecord(encoded[:]); err == nil && record.Generation != 0 {
				generation = record.Generation
			}
		}
		values[stateKey{Owner: identity, Generation: generation}] = value
	}
	return values
}

func activeTaskLink(owner Identity, generation uint64) taskLink {
	return taskLink{
		Owner:               owner,
		Generation:          generation,
		ObservedMonotonicNS: uint64(10 * time.Second),
	}
}

func mountVirtualThread(handler *MapHandler, carrier Identity, virtualThreadID uint64) {
	mounted := virtualThreadIdentity{
		VirtualThreadID:    virtualThreadID,
		ProcessIncarnation: testProcessIncarnation,
	}
	handler.virtualThreads.(*fakeBridgeMap).values[carrier] = mounted
	handler.incarnations.(*fakeBridgeMap).values[javaProcessIdentity(carrier)] = testProcessIncarnation
	synthetic := javaVirtualThreadOwner(carrier, virtualThreadID)
	handler.vtIdentities.(*fakeBridgeMap).values[synthetic] = mounted
}

func identityValues(values map[Identity]any) map[any]any {
	converted := make(map[any]any, len(values))
	for key, value := range values {
		converted[key] = value
	}
	return converted
}

func seedOwnerState(handler *MapHandler, identity Identity, generation uint64) {
	seedOwnerStateWithIncarnation(
		handler, identity, generation, testProcessIncarnation,
	)
}

func seedOwnerStateWithIncarnation(
	handler *MapHandler,
	identity Identity,
	generation uint64,
	processIncarnation uint64,
) {
	key := stateKey{Owner: identity, Generation: generation}
	if _, exists := handler.ambiguity.(*fakeBridgeMap).values[key]; !exists {
		handler.ambiguity.(*fakeBridgeMap).values[key] = uint64(0)
	}
	encoded := handler.remoteParents.(*fakeBridgeMap).values[identity].([RecordSize]byte)
	record, _ := UnmarshalRecord(encoded[:])
	connection := connectionInfo{
		SourcePort:      uint16(identity.TID),
		DestinationPort: uint16(generation),
	}
	connectionKey := connectionInfoNS{
		Connection: connection,
		NetNS:      identity.Namespace,
	}
	seedConnectionClaim(handler, connectionKey, identity, generation)

	handler.owners.(*fakeBridgeMap).values[identity] = ownerValue{
		Generation:         generation,
		ProcessIncarnation: processIncarnation,
		Lifecycle:          lifecycleActive,
	}
	handler.states.(*fakeBridgeMap).values[key] = stateValue{
		Lifecycle:           lifecycleActive,
		ObservedMonotonicNS: record.ObservedMonotonicNS,
		Connection:          connection,
		ConnectionNetNS:     connectionKey.NetNS,
		ProcessIncarnation:  processIncarnation,
		Response:            encoded,
	}
	handler.generations.(*fakeBridgeMap).values[key] = generationIndexValue{
		Process:             javaProcessIdentity(identity),
		ProcessIncarnation:  processIncarnation,
		ObservedMonotonicNS: record.ObservedMonotonicNS,
	}
}

func seedConnectionClaim(
	handler *MapHandler,
	connectionKey connectionInfoNS,
	identity Identity,
	generation uint64,
) {
	netnsCookie := uint64(connectionKey.NetNS)<<32 | generation | 1
	incomingGeneration := generation + 1
	if incomingGeneration == 0 {
		incomingGeneration = 1
	}
	connectionValue := connectionClaim{
		Owner:              identity,
		Generation:         generation,
		NetNSCookie:        netnsCookie,
		IncomingGeneration: incomingGeneration,
		SocketCookie:       generation | 1,
		NetNS:              connectionKey.NetNS,
	}
	handler.connections.(*fakeBridgeMap).values[connectionKey] = connectionValue
	handler.cookieConnections.(*fakeBridgeMap).values[connectionInfoNetNSCookie{
		Connection:  connectionKey.Connection,
		NetNSCookie: netnsCookie,
	}] = connectionValue
}

func validEncodedRecord(t *testing.T, generation uint64) [RecordSize]byte {
	t.Helper()
	record := Record{
		Status:              StatusValid,
		Generation:          generation,
		ObservedMonotonicNS: uint64(10 * time.Second),
	}
	record.TraceID[15] = 1
	record.SpanID[7] = 1
	encoded, err := record.MarshalBinary()
	require.NoError(t, err)
	if len(encoded) != int(RecordSize) {
		t.Fatal(fmt.Errorf("unexpected record size %d", len(encoded)))
	}
	return [RecordSize]byte(encoded)
}

func testGenerationClaim(lifecycle uint8) generationClaim {
	return generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycle,
	}
}
