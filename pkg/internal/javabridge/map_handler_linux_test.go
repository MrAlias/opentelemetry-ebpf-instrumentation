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
	updateCount       int
	deleteCount       int
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
	m.updateCount++
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
	m.deleteCount++
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

func TestMapHandlerRequiresOwnerGuardMap(t *testing.T) {
	handler := testMapHandler(nil, nil, nil)
	handler.ownerGuards = nil

	assert.Equal(t, StatusUnsupported, handler.Handle(
		Identity{TID: 3, PID: 2, Namespace: 1}, OperationTake,
	).Status)
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
		assert.NotContains(t, cleanup.maps.claims.(*fakeBridgeMap).values, key)
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

func TestMapHandlerRejectsTaskLinkObservationReplacement(t *testing.T) {
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	link := activeTaskLink(owner, 10)
	link.ObservedMonotonicNS--
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)},
		map[Identity]any{child: link},
		nil,
	)

	assert.Equal(t, StatusAmbiguous, handler.HandleTask(child, OperationTake).Status)
	assert.Empty(t, handler.claims.(*fakeBridgeMap).values)
	assert.Contains(t, handler.states.(*fakeBridgeMap).values, stateKey{
		Owner: owner, Generation: 10,
	})
}

func TestMapHandlerRejectsTaskTargetSnapshotReplacement(t *testing.T) {
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}

	for _, test := range []struct {
		name   string
		mutate func(*stateValue, *generationIndexValue, *Record)
	}{
		{
			name: "observation",
			mutate: func(state *stateValue, index *generationIndexValue, record *Record) {
				record.ObservedMonotonicNS++
				state.ObservedMonotonicNS = record.ObservedMonotonicNS
				index.ObservedMonotonicNS = record.ObservedMonotonicNS
			},
		},
		{
			name: "payload",
			mutate: func(_ *stateValue, _ *generationIndexValue, record *Record) {
				record.SpanID[6] = 1
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := testMapHandler(
				map[Identity]any{owner: validEncodedRecord(t, 10)},
				map[Identity]any{child: activeTaskLink(owner, 10)},
				nil,
			)
			states := handler.states.(*fakeBridgeMap)
			replacement := states.values[key].(stateValue)
			index := handler.generations.(*fakeBridgeMap).values[key].(generationIndexValue)
			record, err := UnmarshalRecord(replacement.Response[:])
			require.NoError(t, err)
			test.mutate(&replacement, &index, &record)
			encoded, err := record.MarshalBinary()
			require.NoError(t, err)
			replacement.Response = [RecordSize]byte(encoded)
			replaced := false
			states.afterLookup = func(count int) {
				if count != 2 || replaced {
					return
				}
				replaced = true
				states.mu.Lock()
				states.values[key] = replacement
				states.mu.Unlock()
				generations := handler.generations.(*fakeBridgeMap)
				generations.mu.Lock()
				generations.values[key] = index
				generations.mu.Unlock()
			}

			result := handler.HandleTask(child, OperationTake)
			assert.Equal(t, StatusAmbiguous, result.Status)
			assert.False(t, result.IsValidRemoteParent())
			assert.True(t, replaced)
			assert.Equal(t, replacement, states.values[key])
			assert.NotContains(t, handler.claims.(*fakeBridgeMap).values, key)
		})
	}
}

func TestMapHandlerRejectsTaskTerminalSnapshotReplacement(t *testing.T) {
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)},
		map[Identity]any{child: activeTaskLink(owner, 10)},
		nil,
	)
	delete(handler.states.(*fakeBridgeMap).values, key)
	delete(handler.generations.(*fakeBridgeMap).values, key)
	delete(handler.ambiguity.(*fakeBridgeMap).values, key)
	original := terminalValue{
		Generation:          10,
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}
	replacement := original
	replacement.Lifecycle = lifecycleAmbiguous
	terminals := handler.terminals.(*fakeBridgeMap)
	terminals.values[owner] = original
	terminals.afterLookup = func(count int) {
		if count == 2 {
			terminals.mu.Lock()
			terminals.values[owner] = replacement
			terminals.mu.Unlock()
		}
	}

	result := handler.HandleTask(child, OperationTake)
	assert.Equal(t, StatusAmbiguous, result.Status)
	assert.False(t, result.IsValidRemoteParent())
	assert.Equal(t, replacement, terminals.values[owner])
	assert.Empty(t, handler.claims.(*fakeBridgeMap).values)
}

func TestMapHandlerAllowsTaskAliasCountChangeAfterClaim(t *testing.T) {
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)},
		map[Identity]any{child: activeTaskLink(owner, 10)},
		nil,
	)
	state := handler.states.(*fakeBridgeMap).values[key].(stateValue)
	state.Aliases = 2
	handler.states.(*fakeBridgeMap).values[key] = state
	changed := false
	handler.claims.(*fakeBridgeMap).afterUpdate = func(updatedKey, _ any) {
		if updatedKey != key || changed {
			return
		}
		changed = true
		current := handler.states.(*fakeBridgeMap).values[key].(stateValue)
		current.Aliases = 1
		handler.states.(*fakeBridgeMap).values[key] = current
	}

	result := handler.HandleTask(child, OperationTake)
	assert.Equal(t, StatusValid, result.Status)
	assert.True(t, result.IsValidRemoteParent())
}

func TestMapHandlerRetainedTaskClaimOutranksTargetDisappearance(t *testing.T) {
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)},
		map[Identity]any{child: activeTaskLink(owner, 10)},
		nil,
	)
	retained := *cleanupGenerationClaim(
		lifecycleConsumed, uint64(11*time.Second),
	)
	collided := false
	claims := handler.claims.(*fakeBridgeMap)
	claims.beforeUpdate = func(updatedKey, _ any, flags ebpf.MapUpdateFlags) {
		if updatedKey != key || flags != ebpf.UpdateNoExist || collided {
			return
		}
		collided = true
		claims.values[key] = retained
		delete(handler.states.(*fakeBridgeMap).values, key)
		delete(handler.generations.(*fakeBridgeMap).values, key)
		delete(handler.ambiguity.(*fakeBridgeMap).values, key)
	}

	result := handler.HandleTask(child, OperationTake)
	assert.Equal(t, StatusAlreadyConsumed, result.Status)
	assert.False(t, result.IsValidRemoteParent())
	assert.True(t, collided)
	assert.Equal(t, retained, claims.values[key])
	assert.NotContains(t, handler.states.(*fakeBridgeMap).values, key)
	assert.NotContains(t, handler.generations.(*fakeBridgeMap).values, key)
}

func TestMapHandlerClaimOnlyTaskGeneration(t *testing.T) {
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	oldKey := stateKey{Owner: owner, Generation: 10}
	newLink := activeTaskLink(owner, 11)

	newHandler := func(t *testing.T) *MapHandler {
		handler := testMapHandler(
			map[Identity]any{owner: validEncodedRecord(t, 10)},
			map[Identity]any{child: activeTaskLink(owner, 10)},
			nil,
		)
		delete(handler.states.(*fakeBridgeMap).values, oldKey)
		delete(handler.generations.(*fakeBridgeMap).values, oldKey)
		delete(handler.ambiguity.(*fakeBridgeMap).values, oldKey)
		handler.remoteParents.(*fakeBridgeMap).values[owner] = validEncodedRecord(t, 11)
		seedOwnerState(handler, owner, 11)
		handler.terminals.(*fakeBridgeMap).values[owner] = terminalValue{
			Generation:          11,
			ObservedMonotonicNS: uint64(11 * time.Second),
			ProcessIncarnation:  testProcessIncarnation,
			Lifecycle:           lifecycleConsumed,
		}
		return handler
	}

	t.Run("retained exact claim outranks successor terminal", func(t *testing.T) {
		handler := newHandler(t)
		retained := *cleanupGenerationClaim(
			lifecycleConsumed, uint64(11*time.Second),
		)
		handler.claims.(*fakeBridgeMap).values[oldKey] = retained

		result := handler.HandleTask(child, OperationTake)
		assert.Equal(t, StatusAlreadyConsumed, result.Status)
		assert.False(t, result.IsValidRemoteParent())
		assert.Equal(t, retained, handler.claims.(*fakeBridgeMap).values[oldKey])
	})

	t.Run("successor terminal is not old generation authority", func(t *testing.T) {
		handler := newHandler(t)

		result := handler.HandleTask(child, OperationTake)
		assert.Equal(t, StatusMissing, result.Status)
		assert.False(t, result.IsValidRemoteParent())
		assert.Empty(t, handler.consumed)
	})

	t.Run("task rebind during exact claim lookup wins", func(t *testing.T) {
		handler := newHandler(t)
		retained := *cleanupGenerationClaim(
			lifecycleConsumed, uint64(11*time.Second),
		)
		claims := handler.claims.(*fakeBridgeMap)
		claims.values[oldKey] = retained
		claims.afterLookupResult = func(lookedUpKey any, err error) {
			if lookedUpKey == oldKey && err == nil {
				handler.tasks.(*fakeBridgeMap).values[child] = newLink
			}
		}

		result := handler.HandleTask(child, OperationTake)
		assert.Equal(t, StatusAmbiguous, result.Status)
		assert.False(t, result.IsValidRemoteParent())
		assert.Equal(t, newLink, handler.tasks.(*fakeBridgeMap).values[child])
		assert.Equal(t, retained, claims.values[oldKey])
		assert.Empty(t, handler.consumed)
	})

	validExactTerminal := terminalValue{
		Generation:          10,
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}
	malformedTerminals := map[string]terminalValue{
		"zero lifecycle": func() terminalValue {
			terminal := validExactTerminal
			terminal.Lifecycle = 0
			return terminal
		}(),
		"zero observation": func() terminalValue {
			terminal := validExactTerminal
			terminal.ObservedMonotonicNS = 0
			return terminal
		}(),
		"invalid lifecycle": func() terminalValue {
			terminal := validExactTerminal
			terminal.Lifecycle = lifecycleCleanup
			return terminal
		}(),
		"reserved bytes": func() terminalValue {
			terminal := validExactTerminal
			terminal.Reserved[0] = 1
			return terminal
		}(),
	}
	for name, terminal := range malformedTerminals {
		for _, retained := range []bool{false, true} {
			t.Run(fmt.Sprintf("malformed exact terminal/%s/retained=%t", name, retained), func(t *testing.T) {
				handler := testMapHandler(
					map[Identity]any{owner: validEncodedRecord(t, 10)},
					map[Identity]any{child: activeTaskLink(owner, 10)},
					nil,
				)
				delete(handler.states.(*fakeBridgeMap).values, oldKey)
				delete(handler.generations.(*fakeBridgeMap).values, oldKey)
				delete(handler.ambiguity.(*fakeBridgeMap).values, oldKey)
				handler.terminals.(*fakeBridgeMap).values[owner] = terminal
				expected := StatusMissing
				if retained {
					expected = StatusAlreadyConsumed
					handler.claims.(*fakeBridgeMap).values[oldKey] =
						*cleanupGenerationClaim(lifecycleConsumed, uint64(11*time.Second))
				}

				result := handler.HandleTask(child, OperationTake)
				assert.Equal(t, expected, result.Status)
				assert.False(t, result.IsValidRemoteParent())
			})
		}
	}
}

func TestMapHandlerClaimOnlyRetryObservesCommittedExactClaim(t *testing.T) {
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)},
		map[Identity]any{child: activeTaskLink(owner, 10)},
		nil,
	)
	removed := false
	handler.claims.(*fakeBridgeMap).afterUpdate = func(updatedKey, _ any) {
		if updatedKey != key || removed {
			return
		}
		removed = true
		delete(handler.states.(*fakeBridgeMap).values, key)
		delete(handler.generations.(*fakeBridgeMap).values, key)
	}

	first := handler.HandleTask(child, OperationTake)
	assert.Equal(t, StatusAmbiguous, first.Status)
	assert.False(t, first.IsValidRemoteParent())
	assert.True(t, removed)
	retained := handler.claims.(*fakeBridgeMap).values[key].(generationClaim)
	assert.Equal(t, lifecycleCleanup, retained.Lifecycle)
	assert.Equal(t, lifecycleConsumed, retained.Reserved[0])

	second := handler.HandleTask(child, OperationTake)
	assert.Equal(t, StatusAlreadyConsumed, second.Status)
	assert.False(t, second.IsValidRemoteParent())
	assert.Equal(t, retained, handler.claims.(*fakeBridgeMap).values[key])
}

func TestMapHandlerRevalidatesExactTaskAuthority(t *testing.T) {
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	oldLink := activeTaskLink(owner, 10)
	newLink := activeTaskLink(owner, 11)

	newHandler := func(t *testing.T) *MapHandler {
		handler := testMapHandler(
			map[Identity]any{owner: validEncodedRecord(t, 10)},
			map[Identity]any{child: oldLink},
			nil,
		)
		handler.remoteParents.(*fakeBridgeMap).values[owner] = validEncodedRecord(t, 11)
		seedOwnerState(handler, owner, 11)
		return handler
	}

	t.Run("replacement after resolution lookup", func(t *testing.T) {
		handler := newHandler(t)
		tasks := handler.tasks.(*fakeBridgeMap)
		tasks.afterLookup = func(count int) {
			if count == 1 {
				tasks.mu.Lock()
				tasks.values[child] = newLink
				tasks.mu.Unlock()
			}
		}

		result := handler.HandleTask(child, OperationTake)
		assert.Equal(t, StatusAmbiguous, result.Status)
		assert.False(t, result.IsValidRemoteParent())
		assert.Equal(t, newLink, tasks.values[child])
		assert.NotContains(t, handler.claims.(*fakeBridgeMap).values, stateKey{
			Owner: owner, Generation: 10,
		})
	})

	t.Run("replacement while old target disappears", func(t *testing.T) {
		handler := newHandler(t)
		oldKey := stateKey{Owner: owner, Generation: 10}
		tasks := handler.tasks.(*fakeBridgeMap)
		tasks.afterLookup = func(count int) {
			if count == 1 {
				tasks.mu.Lock()
				tasks.values[child] = newLink
				tasks.mu.Unlock()
				delete(handler.states.(*fakeBridgeMap).values, oldKey)
			}
		}

		result := handler.HandleTask(child, OperationTake)
		assert.Equal(t, StatusAmbiguous, result.Status)
		assert.False(t, result.IsValidRemoteParent())
		assert.Equal(t, newLink, tasks.values[child])
		assert.NotContains(t, handler.claims.(*fakeBridgeMap).values, oldKey)
	})

	t.Run("replacement while old payload disappears", func(t *testing.T) {
		handler := newHandler(t)
		oldKey := stateKey{Owner: owner, Generation: 10}
		states := handler.states.(*fakeBridgeMap)
		states.afterLookup = func(count int) {
			if count == 2 {
				handler.tasks.(*fakeBridgeMap).values[child] = newLink
				delete(states.values, oldKey)
			}
		}

		result := handler.HandleTask(child, OperationTake)
		assert.Equal(t, StatusAmbiguous, result.Status)
		assert.False(t, result.IsValidRemoteParent())
		assert.Equal(t, newLink, handler.tasks.(*fakeBridgeMap).values[child])
		assert.NotContains(t, handler.claims.(*fakeBridgeMap).values, oldKey)
	})

	t.Run("replacement after claim", func(t *testing.T) {
		handler := newHandler(t)
		oldKey := stateKey{Owner: owner, Generation: 10}
		handler.claims.(*fakeBridgeMap).afterUpdate = func(updatedKey, _ any) {
			if updatedKey == oldKey {
				handler.tasks.(*fakeBridgeMap).values[child] = newLink
			}
		}

		result := handler.HandleTask(child, OperationTake)
		assert.Equal(t, StatusAmbiguous, result.Status)
		assert.False(t, result.IsValidRemoteParent())
		assert.Equal(t, newLink, handler.tasks.(*fakeBridgeMap).values[child])
	})

	t.Run("replacement outranks pre-claim owner guard", func(t *testing.T) {
		handler := newHandler(t)
		oldKey := stateKey{Owner: owner, Generation: 10}
		guard := testGenerationClaim(lifecyclePublishing)
		guard.ProcessIncarnation = 10
		guards := handler.ownerGuards.(*fakeBridgeMap)
		guards.values[owner] = guard
		rebound := false
		guards.afterLookupResult = func(key any, err error) {
			if rebound || key != owner || err != nil {
				return
			}
			rebound = true
			handler.tasks.(*fakeBridgeMap).values[child] = newLink
		}

		result := handler.HandleTask(child, OperationTake)
		assert.Equal(t, StatusAmbiguous, result.Status)
		assert.False(t, result.IsValidRemoteParent())
		assert.True(t, rebound)
		assert.Equal(t, newLink, handler.tasks.(*fakeBridgeMap).values[child])
		assert.NotContains(t, handler.claims.(*fakeBridgeMap).values, oldKey)
		assert.Equal(t, guard, guards.values[owner])
	})

	t.Run("replacement outranks disappeared collided claim", func(t *testing.T) {
		handler := newHandler(t)
		oldKey := stateKey{Owner: owner, Generation: 10}
		claims := handler.claims.(*fakeBridgeMap)
		claims.beforeUpdate = func(updatedKey, _ any, flags ebpf.MapUpdateFlags) {
			if updatedKey != oldKey || flags != ebpf.UpdateNoExist {
				return
			}
			claims.values[oldKey] = testGenerationClaim(lifecycleConsumed)
			claims.lookupErr = ebpf.ErrKeyNotExist
		}
		claims.afterLookupResult = func(key any, err error) {
			if key == oldKey && errors.Is(err, ebpf.ErrKeyNotExist) {
				handler.tasks.(*fakeBridgeMap).values[child] = newLink
			}
		}

		result := handler.HandleTask(child, OperationTake)
		assert.Equal(t, StatusAmbiguous, result.Status)
		assert.False(t, result.IsValidRemoteParent())
		assert.Equal(t, newLink, handler.tasks.(*fakeBridgeMap).values[child])
		assert.Contains(t, claims.values, oldKey)
	})

	t.Run("replacement while post-claim state disappears", func(t *testing.T) {
		handler := newHandler(t)
		oldKey := stateKey{Owner: owner, Generation: 10}
		tasks := handler.tasks.(*fakeBridgeMap)
		tasks.afterLookup = func(count int) {
			if count == 5 {
				tasks.mu.Lock()
				tasks.values[child] = newLink
				tasks.mu.Unlock()
				delete(handler.states.(*fakeBridgeMap).values, oldKey)
			}
		}

		result := handler.HandleTask(child, OperationTake)
		assert.Equal(t, StatusAmbiguous, result.Status)
		assert.False(t, result.IsValidRemoteParent())
		assert.Equal(t, newLink, tasks.values[child])
		assert.Contains(t, handler.claims.(*fakeBridgeMap).values, oldKey)
		assert.NotZero(t, handler.ambiguity.(*fakeBridgeMap).values[oldKey])
	})

	t.Run("replacement outranks post-claim owner guard", func(t *testing.T) {
		handler := newHandler(t)
		oldKey := stateKey{Owner: owner, Generation: 10}
		guard := testGenerationClaim(lifecyclePublishing)
		guard.ProcessIncarnation = 10
		handler.claims.(*fakeBridgeMap).afterUpdate = func(updatedKey, _ any) {
			if updatedKey == oldKey {
				handler.tasks.(*fakeBridgeMap).values[child] = newLink
				handler.ownerGuards.(*fakeBridgeMap).values[owner] = guard
			}
		}

		result := handler.HandleTask(child, OperationTake)
		assert.Equal(t, StatusAmbiguous, result.Status)
		assert.False(t, result.IsValidRemoteParent())
		assert.Equal(t, newLink, handler.tasks.(*fakeBridgeMap).values[child])
		assert.Contains(t, handler.claims.(*fakeBridgeMap).values, oldKey)
		assert.Equal(t, guard, handler.ownerGuards.(*fakeBridgeMap).values[owner])
		assert.NotZero(t, handler.ambiguity.(*fakeBridgeMap).values[oldKey])
	})

	t.Run("replacement while retained claim is read", func(t *testing.T) {
		handler := newHandler(t)
		oldKey := stateKey{Owner: owner, Generation: 10}
		handler.ambiguity.(*fakeBridgeMap).values[oldKey] = uint64(10 * time.Second)
		handler.claims.(*fakeBridgeMap).values[oldKey] = testGenerationClaim(lifecycleConsumed)
		claims := handler.claims.(*fakeBridgeMap)
		claims.afterLookupResult = func(key any, err error) {
			if err == nil && key == oldKey {
				handler.tasks.(*fakeBridgeMap).values[child] = newLink
			}
		}

		result := handler.HandleTask(child, OperationTake)
		assert.Equal(t, StatusAmbiguous, result.Status)
		assert.False(t, result.IsValidRemoteParent())
		assert.Equal(t, newLink, handler.tasks.(*fakeBridgeMap).values[child])
		assert.Empty(t, handler.consumed)
	})
}

func TestMapHandlerMalformedTaskSnapshotNeverQuarantinesSuccessor(t *testing.T) {
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	oldKey := stateKey{Owner: owner, Generation: 10}
	newKey := stateKey{Owner: owner, Generation: 11}
	oldLink := activeTaskLink(owner, 10)
	newLink := activeTaskLink(owner, 11)

	type successorSnapshot struct {
		fallback      [RecordSize]byte
		owner         ownerValue
		state         stateValue
		generation    generationIndexValue
		connectionKey connectionInfoNS
		connection    connectionClaim
		cookieKey     connectionInfoNetNSCookie
	}
	newHandler := func(t *testing.T) (*MapHandler, successorSnapshot) {
		t.Helper()
		handler := testMapHandler(
			map[Identity]any{owner: validEncodedRecord(t, 10)},
			map[Identity]any{child: oldLink},
			nil,
		)
		delete(handler.owners.(*fakeBridgeMap).values, owner)
		delete(handler.remoteParents.(*fakeBridgeMap).values, owner)
		handler.remoteParents.(*fakeBridgeMap).values[owner] = validEncodedRecord(t, 11)
		seedOwnerState(handler, owner, 11)

		state := handler.states.(*fakeBridgeMap).values[newKey].(stateValue)
		connectionKey := connectionInfoNS{
			Connection: state.Connection,
			NetNS:      state.ConnectionNetNS,
		}
		connection := handler.connections.(*fakeBridgeMap).values[connectionKey].(connectionClaim)
		return handler, successorSnapshot{
			fallback:      handler.remoteParents.(*fakeBridgeMap).values[owner].([RecordSize]byte),
			owner:         handler.owners.(*fakeBridgeMap).values[owner].(ownerValue),
			state:         state,
			generation:    handler.generations.(*fakeBridgeMap).values[newKey].(generationIndexValue),
			connectionKey: connectionKey,
			connection:    connection,
			cookieKey: connectionInfoNetNSCookie{
				Connection:  state.Connection,
				NetNSCookie: connection.NetNSCookie,
			},
		}
	}
	assertSuccessorUnchanged := func(t *testing.T, handler *MapHandler, expected successorSnapshot) {
		t.Helper()
		assert.Equal(t, expected.fallback,
			handler.remoteParents.(*fakeBridgeMap).values[owner])
		assert.Equal(t, expected.owner, handler.owners.(*fakeBridgeMap).values[owner])
		assert.Equal(t, expected.state, handler.states.(*fakeBridgeMap).values[newKey])
		assert.Equal(t, expected.generation,
			handler.generations.(*fakeBridgeMap).values[newKey])
		assert.Equal(t, expected.connection,
			handler.connections.(*fakeBridgeMap).values[expected.connectionKey])
		assert.Equal(t, expected.connection,
			handler.cookieConnections.(*fakeBridgeMap).values[expected.cookieKey])
		assert.Equal(t, uint64(0), handler.ambiguity.(*fakeBridgeMap).values[newKey])
		assert.NotContains(t, handler.claims.(*fakeBridgeMap).values, newKey)
		assert.NotContains(t, handler.ownerGuards.(*fakeBridgeMap).values, owner)
	}
	corruptOldStateAfterResolution := func(handler *MapHandler, rebind bool) {
		states := handler.states.(*fakeBridgeMap)
		states.afterLookup = func(count int) {
			switch count {
			case 2:
				states.mu.Lock()
				state := states.values[oldKey].(stateValue)
				state.Response = [RecordSize]byte{}
				states.values[oldKey] = state
				states.mu.Unlock()
			case 3:
				if rebind {
					tasks := handler.tasks.(*fakeBridgeMap)
					tasks.mu.Lock()
					tasks.values[child] = newLink
					tasks.mu.Unlock()
				}
			}
		}
	}

	t.Run("exact old snapshot replacement remains unmarked", func(t *testing.T) {
		handler, successor := newHandler(t)
		corruptOldStateAfterResolution(handler, false)

		result := handler.HandleTask(child, OperationTake)
		assert.Equal(t, StatusAmbiguous, result.Status)
		assert.Equal(t, uint64(0), handler.ambiguity.(*fakeBridgeMap).values[oldKey])
		assert.NotContains(t, handler.claims.(*fakeBridgeMap).values, oldKey)
		assertSuccessorUnchanged(t, handler, successor)
	})

	t.Run("task rebind prevents old-generation quarantine", func(t *testing.T) {
		handler, successor := newHandler(t)
		corruptOldStateAfterResolution(handler, true)

		result := handler.HandleTask(child, OperationTake)
		assert.Equal(t, StatusAmbiguous, result.Status)
		assert.Equal(t, uint64(0), handler.ambiguity.(*fakeBridgeMap).values[oldKey])
		assert.NotContains(t, handler.claims.(*fakeBridgeMap).values, oldKey)
		assert.Equal(t, newLink, handler.tasks.(*fakeBridgeMap).values[child])
		assertSuccessorUnchanged(t, handler, successor)
	})

	t.Run("released old reservation is never recreated", func(t *testing.T) {
		handler, successor := newHandler(t)
		corruptOldStateAfterResolution(handler, false)
		ambiguity := handler.ambiguity.(*fakeBridgeMap)
		ambiguity.afterLookupResult = func(key any, err error) {
			if key == oldKey && err == nil {
				ambiguity.mu.Lock()
				delete(ambiguity.values, oldKey)
				ambiguity.mu.Unlock()
			}
		}

		result := handler.HandleTask(child, OperationTake)
		assert.Equal(t, StatusAmbiguous, result.Status)
		assert.NotContains(t, ambiguity.values, oldKey)
		assert.NotContains(t, handler.claims.(*fakeBridgeMap).values, oldKey)
		assertSuccessorUnchanged(t, handler, successor)
	})
}

func TestMapHandlerTaskObservationLookupFailureIsTransportError(t *testing.T) {
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)},
		map[Identity]any{child: activeTaskLink(owner, 10)},
		nil,
	)
	states := handler.states.(*fakeBridgeMap)
	states.afterLookup = func(count int) {
		if count == 1 {
			states.lookupErr = errors.New("injected task observation lookup failure")
		}
	}

	result := handler.HandleTask(child, OperationTake)
	assert.Equal(t, StatusTransportError, result.Status)
	assert.False(t, result.IsValidRemoteParent())
	assert.Empty(t, handler.consumed)
}

func TestMapHandlerTakesResetDetachedTaskAndRetainsRecoveryFences(t *testing.T) {
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)},
		map[Identity]any{child: activeTaskLink(owner, 10)},
		nil,
	)
	oldKey := stateKey{Owner: owner, Generation: 10}
	oldState := handler.states.(*fakeBridgeMap).values[oldKey].(stateValue)
	oldConnectionKey := connectionInfoNS{
		Connection: oldState.Connection,
		NetNS:      oldState.ConnectionNetNS,
	}
	oldConnection := handler.connections.(*fakeBridgeMap).values[oldConnectionKey].(connectionClaim)
	delete(handler.connections.(*fakeBridgeMap).values, oldConnectionKey)
	delete(handler.cookieConnections.(*fakeBridgeMap).values, connectionInfoNetNSCookie{
		Connection:  oldState.Connection,
		NetNSCookie: oldConnection.NetNSCookie,
	})
	delete(handler.owners.(*fakeBridgeMap).values, owner)
	delete(handler.remoteParents.(*fakeBridgeMap).values, owner)

	handler.remoteParents.(*fakeBridgeMap).values[owner] = validEncodedRecord(t, 11)
	seedOwnerState(handler, owner, 11)

	linked := handler.HandleTask(child, OperationTake)
	assert.Equal(t, StatusValid, linked.Status)
	assert.Equal(t, uint64(10), linked.Generation)
	assert.Contains(t, handler.states.(*fakeBridgeMap).values, oldKey)
	assert.Contains(t, handler.generations.(*fakeBridgeMap).values, oldKey)
	claimed, ok := handler.claims.(*fakeBridgeMap).values[oldKey].(generationClaim)
	require.True(t, ok)
	assert.Equal(t, testProcessIncarnation, claimed.ProcessIncarnation)
	assert.Equal(t, lifecycleCleanup, claimed.Lifecycle)
	assert.Equal(t, lifecycleConsumed, claimed.Reserved[0])
	guard, ok := handler.ownerGuards.(*fakeBridgeMap).values[owner].(generationClaim)
	require.True(t, ok)
	assert.Equal(t, uint64(10), guard.ProcessIncarnation)
	assert.Equal(t, lifecycleCleanup, guard.Lifecycle)
	assert.Equal(t, lifecyclePublishing, guard.Reserved[0])
	assert.NotZero(t, handler.ambiguity.(*fakeBridgeMap).values[oldKey])
	assert.Equal(t, uint64(11),
		handler.owners.(*fakeBridgeMap).values[owner].(ownerValue).Generation)
	assert.Equal(t, uint64(11), func() uint64 {
		encoded := handler.remoteParents.(*fakeBridgeMap).values[owner].([RecordSize]byte)
		record, err := UnmarshalRecord(encoded[:])
		require.NoError(t, err)
		return record.Generation
	}())

	assert.Equal(t, StatusAlreadyConsumed, handler.HandleTask(child, OperationTake).Status)
	assert.Equal(t, StatusAlreadyConsumed, handler.HandleTask(child, OperationDiscard).Status)
	assert.Equal(t, StatusOverload, handler.Handle(owner, OperationTake).Status)
}

func TestMapHandlerRetainsDetachedTaskWhenAliasDisappearsAfterClaim(t *testing.T) {
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)},
		map[Identity]any{child: activeTaskLink(owner, 10)},
		nil,
	)
	oldKey := stateKey{Owner: owner, Generation: 10}
	oldState := handler.states.(*fakeBridgeMap).values[oldKey].(stateValue)
	oldConnectionKey := connectionInfoNS{
		Connection: oldState.Connection,
		NetNS:      oldState.ConnectionNetNS,
	}
	oldConnection := handler.connections.(*fakeBridgeMap).values[oldConnectionKey].(connectionClaim)
	oldCookieKey := connectionInfoNetNSCookie{
		Connection:  oldState.Connection,
		NetNSCookie: oldConnection.NetNSCookie,
	}

	delete(handler.owners.(*fakeBridgeMap).values, owner)
	delete(handler.remoteParents.(*fakeBridgeMap).values, owner)
	handler.remoteParents.(*fakeBridgeMap).values[owner] = validEncodedRecord(t, 11)
	seedOwnerState(handler, owner, 11)
	handler.claims.(*fakeBridgeMap).afterUpdate = func(updatedKey, _ any) {
		if updatedKey != oldKey {
			return
		}
		state := handler.states.(*fakeBridgeMap).values[oldKey].(stateValue)
		state.Aliases = 0
		handler.states.(*fakeBridgeMap).values[oldKey] = state
	}

	result := handler.HandleTask(child, OperationTake)
	assert.Equal(t, StatusAmbiguous, result.Status)
	assert.Contains(t, handler.states.(*fakeBridgeMap).values, oldKey)
	assert.Contains(t, handler.generations.(*fakeBridgeMap).values, oldKey)
	assert.Contains(t, handler.connections.(*fakeBridgeMap).values, oldConnectionKey)
	assert.Contains(t, handler.cookieConnections.(*fakeBridgeMap).values, oldCookieKey)
	assert.Contains(t, handler.claims.(*fakeBridgeMap).values, oldKey)
	guard, ok := handler.ownerGuards.(*fakeBridgeMap).values[owner].(generationClaim)
	require.True(t, ok)
	assert.Equal(t, lifecycleCleanup, guard.Lifecycle)
	assert.Equal(t, lifecyclePublishing, guard.Reserved[0])
	assert.NotZero(t, handler.ambiguity.(*fakeBridgeMap).values[oldKey])
	assert.Equal(t, uint64(11),
		handler.owners.(*fakeBridgeMap).values[owner].(ownerValue).Generation)
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

func TestMapHandlerDefersMalformedFallbackToCoordinatedCleanup(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{identity: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	handler.remoteParents.(*fakeBridgeMap).values[identity] = [RecordSize]byte{}
	key := stateKey{Owner: identity, Generation: 10}
	owner := handler.owners.(*fakeBridgeMap).values[identity]
	state := handler.states.(*fakeBridgeMap).values[key]
	generation := handler.generations.(*fakeBridgeMap).values[key]

	assert.Equal(t, StatusMalformed, handler.Handle(identity, OperationTake).Status)
	assert.Equal(t, [RecordSize]byte{}, handler.remoteParents.(*fakeBridgeMap).values[identity])
	assert.Equal(t, owner, handler.owners.(*fakeBridgeMap).values[identity])
	assert.Equal(t, state, handler.states.(*fakeBridgeMap).values[key])
	assert.Equal(t, generation, handler.generations.(*fakeBridgeMap).values[key])
	assert.Empty(t, handler.claims.(*fakeBridgeMap).values)
	assert.Empty(t, handler.ownerGuards.(*fakeBridgeMap).values)

	cleanup := testCleanup(handler)
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	claim := cleanup.maps.claims.(*fakeBridgeMap).values[key].(generationClaim)
	guard := cleanup.maps.ownerGuards.(*fakeBridgeMap).values[identity].(generationClaim)
	assert.True(t, validGenerationCleanupClaim(claim))
	assert.True(t, validGenerationCleanupGuard(identity, guard))
	assert.Equal(t, uint64(now), cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
	assert.Contains(t, cleanup.maps.states.(*fakeBridgeMap).values, key)

	now += cleanup.ttl + time.Nanosecond
	for range 4 {
		_, err = cleanup.SweepWithStats()
		require.NoError(t, err)
	}
	assert.Empty(t, handler.remoteParents.(*fakeBridgeMap).values)
	assert.Empty(t, handler.owners.(*fakeBridgeMap).values)
	assert.Empty(t, handler.states.(*fakeBridgeMap).values)
	assert.Empty(t, handler.generations.(*fakeBridgeMap).values)
	assert.Empty(t, handler.connections.(*fakeBridgeMap).values)
	assert.Empty(t, handler.cookieConnections.(*fakeBridgeMap).values)
	assert.NotContains(t, handler.ambiguity.(*fakeBridgeMap).values, key)
	assert.NotContains(t, handler.claims.(*fakeBridgeMap).values, key)
	assert.NotContains(t, handler.ownerGuards.(*fakeBridgeMap).values, identity)

	handler.remoteParents.(*fakeBridgeMap).values[identity] = validEncodedRecord(t, 11)
	seedOwnerState(handler, identity, 11)
	assert.Equal(t, StatusValid, handler.Handle(identity, OperationTake).Status)
}

func TestMapHandlerMalformedFallbackSnapshotNeverQuarantinesSuccessor(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{identity: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	handler.remoteParents.(*fakeBridgeMap).values[identity] = [RecordSize]byte{}
	remoteParents := handler.remoteParents.(*fakeBridgeMap)
	newKey := stateKey{Owner: identity, Generation: 11}
	var successorState stateValue
	var successorConnectionKey connectionInfoNS
	var successorConnection connectionClaim
	remoteParents.afterLookup = func(count int) {
		if count != 2 {
			return
		}
		remoteParents.mu.Lock()
		remoteParents.values[identity] = validEncodedRecord(t, 11)
		remoteParents.mu.Unlock()
		seedOwnerState(handler, identity, 11)
		successorState = handler.states.(*fakeBridgeMap).values[newKey].(stateValue)
		successorConnectionKey = connectionInfoNS{
			Connection: successorState.Connection,
			NetNS:      successorState.ConnectionNetNS,
		}
		successorConnection = handler.connections.(*fakeBridgeMap).
			values[successorConnectionKey].(connectionClaim)
	}

	assert.Equal(t, StatusMalformed, handler.Handle(identity, OperationTake).Status)
	assert.Equal(t, validEncodedRecord(t, 11), remoteParents.values[identity])
	assert.Equal(t, ownerValue{
		Generation:         11,
		ProcessIncarnation: testProcessIncarnation,
		Lifecycle:          lifecycleActive,
	}, handler.owners.(*fakeBridgeMap).values[identity])
	assert.Equal(t, successorState, handler.states.(*fakeBridgeMap).values[newKey])
	assert.Equal(t, generationIndexValue{
		Process:             javaProcessIdentity(identity),
		ProcessIncarnation:  testProcessIncarnation,
		ObservedMonotonicNS: successorState.ObservedMonotonicNS,
	}, handler.generations.(*fakeBridgeMap).values[newKey])
	assert.Equal(t, successorConnection,
		handler.connections.(*fakeBridgeMap).values[successorConnectionKey])
	assert.Equal(t, successorConnection,
		handler.cookieConnections.(*fakeBridgeMap).values[connectionInfoNetNSCookie{
			Connection:  successorState.Connection,
			NetNSCookie: successorConnection.NetNSCookie,
		}])
	assert.NotContains(t, handler.terminals.(*fakeBridgeMap).values, identity)
	assert.Empty(t, handler.claims.(*fakeBridgeMap).values)
	assert.Empty(t, handler.ownerGuards.(*fakeBridgeMap).values)
	assert.Equal(t, uint64(0), handler.ambiguity.(*fakeBridgeMap).values[newKey])
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
			assert.Equal(t, [RecordSize]byte{},
				handler.remoteParents.(*fakeBridgeMap).values[identity])
			assert.Equal(t, test.owner, handler.owners.(*fakeBridgeMap).values[identity])

			handler.remoteParents.(*fakeBridgeMap).values[identity] = validEncodedRecord(t, 11)
			seedOwnerState(handler, identity, 11)
			assert.Equal(t, StatusValid, handler.Handle(identity, OperationTake).Status)
		})
	}
}

func TestMapHandlerMalformedFallbackPreservesOwnerDetachGuard(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	guard := generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  10,
		Lifecycle:           lifecyclePublishing,
	}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)}, nil, nil,
	)
	handler.remoteParents.(*fakeBridgeMap).values[owner] = [RecordSize]byte{}
	handler.ownerGuards.(*fakeBridgeMap).values[owner] = guard

	assert.Equal(t, StatusMalformed, handler.Handle(owner, OperationTake).Status)
	assert.Equal(t, guard, handler.ownerGuards.(*fakeBridgeMap).values[owner])
	assert.NotContains(t, handler.claims.(*fakeBridgeMap).values, stateKey{
		Owner: owner, Generation: 10,
	})
	assert.Contains(t, handler.remoteParents.(*fakeBridgeMap).values, owner)
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

func TestMapHandlerRetainedExactClaimOutranksTerminal(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}

	tests := []struct {
		name              string
		terminalLifecycle uint8
		claim             *generationClaim
		status            Status
	}{
		{
			name:              "discarded cleanup outranks ambiguous terminal",
			terminalLifecycle: lifecycleAmbiguous,
			claim: cleanupGenerationClaim(
				lifecycleDiscarded, uint64(11*time.Second),
			),
			status: StatusAlreadyConsumed,
		},
		{
			name:              "ambiguous cleanup outranks consumed terminal",
			terminalLifecycle: lifecycleConsumed,
			claim: cleanupGenerationClaim(
				lifecycleAmbiguous, uint64(11*time.Second),
			),
			status: StatusAmbiguous,
		},
		{
			name:              "publishing cleanup outranks consumed terminal",
			terminalLifecycle: lifecycleConsumed,
			claim: cleanupGenerationClaim(
				lifecyclePublishing, uint64(11*time.Second),
			),
			status: StatusOverload,
		},
		{
			name:              "malformed cleanup outranks stale terminal",
			terminalLifecycle: lifecycleStale,
			claim: func() *generationClaim {
				claim := cleanupGenerationClaim(
					lifecycleConsumed, uint64(11*time.Second),
				)
				claim.Reserved[1] = 1
				return claim
			}(),
			status: StatusAmbiguous,
		},
		{
			name:              "terminal remains authoritative without exact claim",
			terminalLifecycle: lifecycleStale,
			status:            StatusStale,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := testMapHandler(nil, nil, nil)
			handler.terminals.(*fakeBridgeMap).values[owner] = terminalValue{
				Generation:          key.Generation,
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  testProcessIncarnation,
				Lifecycle:           test.terminalLifecycle,
			}
			if test.claim != nil {
				handler.claims.(*fakeBridgeMap).values[key] = *test.claim
			}

			assert.Equal(t, test.status, handler.Handle(owner, OperationTake).Status)
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

func TestMapHandlerRejectsMalformedConnectionMetadata(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	for _, test := range []struct {
		name   string
		mutate func(*stateValue)
	}{
		{
			name: "zero network namespace",
			mutate: func(state *stateValue) {
				state.ConnectionNetNS = 0
			},
		},
		{
			name: "empty connection",
			mutate: func(state *stateValue) {
				state.Connection = connectionInfo{}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := testMapHandler(
				map[Identity]any{identity: validEncodedRecord(t, 10)}, nil, nil,
			)
			key := stateKey{Owner: identity, Generation: 10}
			state := handler.states.(*fakeBridgeMap).values[key].(stateValue)
			test.mutate(&state)
			handler.states.(*fakeBridgeMap).values[key] = state
			clear(handler.connections.(*fakeBridgeMap).values)
			clear(handler.cookieConnections.(*fakeBridgeMap).values)
			connectionKey := connectionInfoNS{
				Connection: state.Connection,
				NetNS:      state.ConnectionNetNS,
			}
			seedConnectionClaim(handler, connectionKey, identity, key.Generation)
			record, err := UnmarshalRecord(state.Response[:])
			require.NoError(t, err)

			assert.False(t, validFinishState(state, record, testProcessIncarnation))
			assert.Equal(t, StatusAmbiguous, handler.Handle(identity, OperationTake).Status)
			assert.Empty(t, handler.claims.(*fakeBridgeMap).values)
			assert.Empty(t, handler.ownerGuards.(*fakeBridgeMap).values)
			assert.Equal(t, state, handler.states.(*fakeBridgeMap).values[key])
			assert.Contains(t, handler.connections.(*fakeBridgeMap).values, connectionKey)
		})
	}
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

func TestMapHandlerRejectsForeignIncarnationClaimCollision(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{identity: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	seedOwnerState(handler, identity, 10)
	key := stateKey{Owner: identity, Generation: 10}
	claim := testGenerationClaim(lifecycleConsumed)
	claim.ProcessIncarnation++
	handler.claims.(*fakeBridgeMap).values[key] = claim

	assert.Equal(t, StatusAmbiguous, handler.Handle(identity, OperationTake).Status)
	assert.Equal(t, claim, handler.claims.(*fakeBridgeMap).values[key])
	assert.NotEmpty(t, handler.remoteParents.(*fakeBridgeMap).values)
	assert.Empty(t, handler.consumed)
}

func TestMapHandlerPropagatesRacedClaimStatus(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	for _, operation := range []Operation{OperationTake, OperationDiscard} {
		for _, test := range []struct {
			name          string
			claim         generationClaim
			expected      Status
			marksConsumed bool
		}{
			{
				name:     "publishing",
				claim:    testGenerationClaim(lifecyclePublishing),
				expected: StatusOverload,
			},
			{
				name:          "consumed",
				claim:         testGenerationClaim(lifecycleConsumed),
				expected:      StatusAlreadyConsumed,
				marksConsumed: true,
			},
			{
				name:          "discarded",
				claim:         testGenerationClaim(lifecycleDiscarded),
				expected:      StatusAlreadyConsumed,
				marksConsumed: true,
			},
			{
				name:          "stale",
				claim:         testGenerationClaim(lifecycleStale),
				expected:      StatusAlreadyConsumed,
				marksConsumed: true,
			},
			{
				name:     "ambiguous",
				claim:    testGenerationClaim(lifecycleAmbiguous),
				expected: StatusAmbiguous,
			},
			{
				name: "foreign incarnation",
				claim: func() generationClaim {
					claim := testGenerationClaim(lifecycleConsumed)
					claim.ProcessIncarnation++
					return claim
				}(),
				expected: StatusAmbiguous,
			},
		} {
			t.Run(fmt.Sprintf("%s/%s", operation, test.name), func(t *testing.T) {
				handler := testMapHandler(
					map[Identity]any{identity: validEncodedRecord(t, 10)}, nil,
					map[Identity]any{identity: uint64(10 * time.Second)},
				)
				key := stateKey{Owner: identity, Generation: 10}
				claims := handler.claims.(*fakeBridgeMap)
				claims.beforeUpdate = func(updatedKey, _ any, flags ebpf.MapUpdateFlags) {
					if updatedKey == key && flags == ebpf.UpdateNoExist {
						claims.values[key] = test.claim
					}
				}

				result := handler.Handle(identity, operation)
				assert.Equal(t, test.expected, result.Status)
				assert.False(t, result.IsValidRemoteParent())
				assert.Equal(t, test.claim, claims.values[key])
				assert.Equal(t, test.marksConsumed, len(handler.consumed) != 0)
			})
		}
	}
}

func TestMapHandlerNeverRollsBackVisibleFinalClaim(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	for _, operation := range []Operation{OperationTake, OperationDiscard} {
		t.Run(operation.String(), func(t *testing.T) {
			handler := testMapHandler(
				map[Identity]any{identity: validEncodedRecord(t, 10)}, nil, nil,
			)
			key := stateKey{Owner: identity, Generation: 10}
			guard := testGenerationClaim(lifecyclePublishing)
			guard.ProcessIncarnation = 10
			handler.claims.(*fakeBridgeMap).afterUpdate = func(updatedKey, _ any) {
				if updatedKey == key {
					handler.ownerGuards.(*fakeBridgeMap).values[identity] = guard
				}
			}

			result := handler.Handle(identity, operation)
			assert.Equal(t, StatusOverload, result.Status)
			assert.False(t, result.IsValidRemoteParent())
			claim, ok := handler.claims.(*fakeBridgeMap).values[key].(generationClaim)
			require.True(t, ok)
			assert.Equal(t, lifecycleCleanup, claim.Lifecycle)
			expectedOrigin := lifecycleConsumed
			if operation == OperationDiscard {
				expectedOrigin = lifecycleDiscarded
			}
			assert.Equal(t, expectedOrigin, claim.Reserved[0])
			assert.NotZero(t, handler.ambiguity.(*fakeBridgeMap).values[key])

			retry := handler.Handle(identity, OperationTake)
			assert.Equal(t, StatusAlreadyConsumed, retry.Status)
			assert.Equal(t, claim, handler.claims.(*fakeBridgeMap).values[key])
		})
	}
}

func TestMapHandlerAmbiguousConsumePreservesStatusWhenGuardAppears(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{identity: validEncodedRecord(t, 10)}, nil,
		map[Identity]any{identity: uint64(10 * time.Second)},
	)
	key := stateKey{Owner: identity, Generation: 10}
	guard := testGenerationClaim(lifecyclePublishing)
	guard.ProcessIncarnation = 10
	handler.claims.(*fakeBridgeMap).afterUpdate = func(updatedKey, _ any) {
		if updatedKey == key {
			handler.ownerGuards.(*fakeBridgeMap).values[identity] = guard
		}
	}

	result := handler.Handle(identity, OperationTake)
	assert.Equal(t, StatusAmbiguous, result.Status)
	claim := handler.claims.(*fakeBridgeMap).values[key].(generationClaim)
	assert.Equal(t, lifecycleCleanup, claim.Lifecycle)
	assert.Equal(t, lifecycleDiscarded, claim.Reserved[0])
	assert.Equal(t, guard, handler.ownerGuards.(*fakeBridgeMap).values[identity])
	assert.NotZero(t, handler.ambiguity.(*fakeBridgeMap).values[key])
}

func TestMapHandlerCancellationBeforeClaimNeverCommits(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	for _, test := range []struct {
		name      string
		configure func(*MapHandler)
	}{
		{name: "valid take"},
		{
			name: "ambiguous consume",
			configure: func(handler *MapHandler) {
				handler.ambiguity.(*fakeBridgeMap).values[stateKey{
					Owner: identity, Generation: 10,
				}] = uint64(10 * time.Second)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := testMapHandler(
				map[Identity]any{identity: validEncodedRecord(t, 10)}, nil, nil,
			)
			if test.configure != nil {
				test.configure(handler)
			}
			ctx, cancel := context.WithCancel(t.Context())
			handler.ownerGuards.(*fakeBridgeMap).afterLookupResult = func(key any, err error) {
				if key == identity && errors.Is(err, ebpf.ErrKeyNotExist) {
					cancel()
				}
			}

			result := handler.HandleAuthenticated(
				ctx, identity, OperationTake, LookupSourceDirect, testProcessIncarnation,
			)
			assert.Equal(t, StatusTimeout, result.Status)
			assert.False(t, result.IsValidRemoteParent())
			assert.NotContains(t, handler.claims.(*fakeBridgeMap).values, stateKey{
				Owner: identity, Generation: 10,
			})
		})
	}
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
		assert.NotEmpty(t, handler.claims.(*fakeBridgeMap).values)
		assert.NotZero(t, handler.ambiguity.(*fakeBridgeMap).values[stateKey{
			Owner: identity, Generation: 10,
		}])
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
		assert.NotEmpty(t, handler.remoteParents.(*fakeBridgeMap).values)
		assert.NotEmpty(t, handler.claims.(*fakeBridgeMap).values)
		assert.NotZero(t, handler.ambiguity.(*fakeBridgeMap).values[stateKey{
			Owner: identity, Generation: 10,
		}])
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
		assert.NotEmpty(t, handler.remoteParents.(*fakeBridgeMap).values)
		assert.NotEmpty(t, handler.claims.(*fakeBridgeMap).values)
	})

	t.Run("connection cookie disappears", func(t *testing.T) {
		handler := testMapHandler(
			map[Identity]any{identity: validEncodedRecord(t, 10)},
			nil,
			nil,
		)
		handler.claims.(*fakeBridgeMap).afterUpdate = func(any, any) {
			clear(handler.cookieConnections.(*fakeBridgeMap).values)
		}

		assert.Equal(t, StatusAmbiguous, handler.Handle(identity, OperationTake).Status)
		assert.NotEmpty(t, handler.remoteParents.(*fakeBridgeMap).values)
		assert.NotEmpty(t, handler.claims.(*fakeBridgeMap).values)
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

func TestMapHandlerCompareReleasesOnlyItsOwnClaim(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{identity: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	key := stateKey{Owner: identity, Generation: 10}
	replacement := generationClaim{
		ObservedMonotonicNS: uint64(12 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecyclePublishing,
	}
	handler.claims.(*fakeBridgeMap).afterUpdate = func(any, any) {
		handler.claims.(*fakeBridgeMap).values[key] = replacement
		handler.owners.(*fakeBridgeMap).lookupErr = errors.New("injected owner lookup failure")
	}

	assert.Equal(t, StatusTransportError, handler.Handle(identity, OperationTake).Status)
	assert.Equal(t, replacement, handler.claims.(*fakeBridgeMap).values[key])
}

func TestMapHandlerRetainsClaimWhenOwnershipIsUncertain(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}

	tests := []struct {
		name      string
		configure func(*MapHandler)
	}{
		{
			name: "owner has same generation from another incarnation",
			configure: func(handler *MapHandler) {
				handler.owners.(*fakeBridgeMap).values[identity] = ownerValue{
					Generation:         10,
					ProcessIncarnation: testProcessIncarnation + 1,
					Lifecycle:          lifecycleActive,
				}
			},
		},
		{
			name: "state key belongs to another incarnation",
			configure: func(handler *MapHandler) {
				key := stateKey{Owner: identity, Generation: 10}
				state := handler.states.(*fakeBridgeMap).values[key].(stateValue)
				state.ProcessIncarnation++
				handler.states.(*fakeBridgeMap).values[key] = state
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
			handler.claims.(*fakeBridgeMap).afterUpdate = func(any, any) {
				test.configure(handler)
			}

			assert.Equal(t, StatusAmbiguous, handler.Handle(identity, OperationTake).Status)
			assert.NotEmpty(t, handler.claims.(*fakeBridgeMap).values)
		})
	}
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

	t.Run("fallback same generation replacement", func(t *testing.T) {
		handler := testMapHandler(
			map[Identity]any{identity: validEncodedRecord(t, 10)}, nil, nil,
		)
		remoteParents := handler.remoteParents.(*fakeBridgeMap)
		replacement := validEncodedRecord(t, 10)
		replacement[16] = 2
		remoteParents.afterLookup = func(count int) {
			if count != 1 {
				return
			}
			remoteParents.mu.Lock()
			remoteParents.values[identity] = replacement
			remoteParents.mu.Unlock()
		}

		assert.False(t, handler.deleteRemoteParentGeneration(
			identity, 10, testProcessIncarnation,
		))
		assert.Equal(t, replacement, remoteParents.values[identity])
	})

	t.Run("fallback non-valid same generation", func(t *testing.T) {
		handler := testMapHandler(
			map[Identity]any{identity: validEncodedRecord(t, 10)}, nil, nil,
		)
		record := Record{
			Status:              StatusMissing,
			Generation:          10,
			ObservedMonotonicNS: uint64(10 * time.Second),
		}
		encoded, err := record.MarshalBinary()
		require.NoError(t, err)
		replacement := [RecordSize]byte(encoded)
		handler.remoteParents.(*fakeBridgeMap).values[identity] = replacement

		assert.False(t, handler.deleteRemoteParentGeneration(
			identity, 10, testProcessIncarnation,
		))
		assert.Equal(t, replacement,
			handler.remoteParents.(*fakeBridgeMap).values[identity])
	})

	t.Run("owner", func(t *testing.T) {
		handler := testMapHandler(
			map[Identity]any{identity: validEncodedRecord(t, 10)},
			nil,
			nil,
		)
		owners := handler.owners.(*fakeBridgeMap)
		expected := owners.values[identity].(ownerValue)
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

		assert.True(t, handler.deleteOwnerGeneration(identity, expected))
		assert.Equal(t, uint64(11), owners.values[identity].(ownerValue).Generation)
	})

	t.Run("owner same generation different incarnation", func(t *testing.T) {
		handler := testMapHandler(
			map[Identity]any{identity: validEncodedRecord(t, 10)},
			nil,
			nil,
		)
		owners := handler.owners.(*fakeBridgeMap)
		owners.values[identity] = ownerValue{
			Generation:         10,
			ProcessIncarnation: testProcessIncarnation + 1,
			Lifecycle:          lifecycleActive,
		}

		assert.False(t, handler.deleteOwnerGeneration(identity, ownerValue{
			Generation:         10,
			ProcessIncarnation: testProcessIncarnation,
			Lifecycle:          lifecycleActive,
		}))
		assert.Equal(
			t, testProcessIncarnation+1,
			owners.values[identity].(ownerValue).ProcessIncarnation,
		)
	})

	t.Run("owner same generation lifecycle replacement", func(t *testing.T) {
		handler := testMapHandler(
			map[Identity]any{identity: validEncodedRecord(t, 10)}, nil, nil,
		)
		owners := handler.owners.(*fakeBridgeMap)
		expected := owners.values[identity].(ownerValue)
		replacement := expected
		replacement.Lifecycle = lifecyclePublishing
		owners.afterLookup = func(count int) {
			if count != 1 {
				return
			}
			owners.mu.Lock()
			owners.values[identity] = replacement
			owners.mu.Unlock()
		}

		assert.False(t, handler.deleteOwnerGeneration(identity, expected))
		assert.Equal(t, replacement, owners.values[identity])
	})

	t.Run("generation index", func(t *testing.T) {
		handler := testMapHandler(
			map[Identity]any{identity: validEncodedRecord(t, 10)},
			nil,
			nil,
		)
		key := stateKey{Owner: identity, Generation: 10}
		generations := handler.generations.(*fakeBridgeMap)
		expected := generations.values[key].(generationIndexValue)
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

		assert.False(t, handler.deleteGenerationIndex(key, expected))
		assert.Equal(
			t,
			testProcessIncarnation+1,
			generations.values[key].(generationIndexValue).ProcessIncarnation,
		)
	})

	t.Run("generation index observation replacement", func(t *testing.T) {
		handler := testMapHandler(
			map[Identity]any{identity: validEncodedRecord(t, 10)}, nil, nil,
		)
		key := stateKey{Owner: identity, Generation: 10}
		generations := handler.generations.(*fakeBridgeMap)
		expected := generations.values[key].(generationIndexValue)
		replacement := expected
		replacement.ObservedMonotonicNS++
		generations.afterLookup = func(count int) {
			if count != 1 {
				return
			}
			generations.mu.Lock()
			generations.values[key] = replacement
			generations.mu.Unlock()
		}

		assert.False(t, handler.deleteGenerationIndex(key, expected))
		assert.Equal(t, replacement, generations.values[key])
	})
}

func TestMapHandlerRetainsClaimWhenTargetReappearsDuringFinish(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: identity, Generation: 10}

	tests := []struct {
		name      string
		status    Status
		configure func(*MapHandler)
	}{
		{
			name:   "connection cursor",
			status: StatusValid,
			configure: func(handler *MapHandler) {
				connections := handler.connections.(*fakeBridgeMap)
				connections.afterDelete = func(deletedKey any) {
					connections.values[deletedKey] = connectionClaim{
						Owner: identity, Generation: 10,
					}
				}
			},
		},
		{
			name:   "cookie cursor",
			status: StatusValid,
			configure: func(handler *MapHandler) {
				cookies := handler.cookieConnections.(*fakeBridgeMap)
				cookies.afterDelete = func(deletedKey any) {
					cookies.values[deletedKey] = connectionClaim{
						Owner: identity, Generation: 10,
					}
				}
			},
		},
		{
			name:   "state key",
			status: StatusValid,
			configure: func(handler *MapHandler) {
				states := handler.states.(*fakeBridgeMap)
				states.afterDelete = func(any) {
					states.values[key] = stateValue{
						ProcessIncarnation: testProcessIncarnation + 1,
					}
				}
			},
		},
		{
			name:   "generation key",
			status: StatusValid,
			configure: func(handler *MapHandler) {
				generations := handler.generations.(*fakeBridgeMap)
				generations.afterDelete = func(any) {
					generations.values[key] = generationIndexValue{
						ProcessIncarnation: testProcessIncarnation + 1,
					}
				}
			},
		},
		{
			name:   "owner generation",
			status: StatusValid,
			configure: func(handler *MapHandler) {
				owners := handler.owners.(*fakeBridgeMap)
				owners.afterDelete = func(any) {
					owners.values[identity] = ownerValue{
						Generation:         10,
						ProcessIncarnation: testProcessIncarnation + 1,
					}
				}
			},
		},
		{
			name:   "fallback generation",
			status: StatusValid,
			configure: func(handler *MapHandler) {
				fallbacks := handler.remoteParents.(*fakeBridgeMap)
				fallbacks.afterDelete = func(any) {
					fallbacks.values[identity] = validEncodedRecord(t, 10)
				}
			},
		},
		{
			name:   "terminal generation",
			status: StatusValid,
			configure: func(handler *MapHandler) {
				terminals := handler.terminals.(*fakeBridgeMap)
				terminals.afterUpdate = func(any, any) {
					terminals.values[identity] = terminalValue{
						Generation:          10,
						ObservedMonotonicNS: uint64(12 * time.Second),
						ProcessIncarnation:  testProcessIncarnation + 1,
						Lifecycle:           lifecycleConsumed,
					}
				}
			},
		},
		{
			name:   "ambiguity marker",
			status: StatusAmbiguous,
			configure: func(handler *MapHandler) {
				ambiguity := handler.ambiguity.(*fakeBridgeMap)
				handler.claims.(*fakeBridgeMap).afterUpdate = func(any, any) {
					ambiguity.values[key] = uint64(11 * time.Second)
				}
				ambiguity.afterDelete = func(any) {
					ambiguity.values[key] = uint64(12 * time.Second)
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
			assert.NotEmpty(t, handler.claims.(*fakeBridgeMap).values)
		})
	}
}

func TestMapHandlerRestoresMarkerAfterFinishBarrierLoss(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)}, nil, nil,
	)
	handler.terminals.(*fakeBridgeMap).afterUpdate = func(any, any) {
		delete(handler.ambiguity.(*fakeBridgeMap).values, key)
	}

	assert.Equal(t, StatusValid, handler.Handle(owner, OperationTake).Status)
	assert.Contains(t, handler.claims.(*fakeBridgeMap).values, key)
	assert.Contains(t, handler.ownerGuards.(*fakeBridgeMap).values, owner)
	assert.NotZero(t, handler.ambiguity.(*fakeBridgeMap).values[key])
	assert.Contains(t, handler.states.(*fakeBridgeMap).values, key)
}

func TestMapHandlerAcceptsMarkerDisappearanceAtOrderedRelease(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)}, nil, nil,
	)
	ambiguity := handler.ambiguity.(*fakeBridgeMap)
	eligibleLookups := 0
	ambiguity.afterLookup = func(int) {
		if _, statePresent := handler.states.(*fakeBridgeMap).values[key]; statePresent {
			return
		}
		if _, indexPresent := handler.generations.(*fakeBridgeMap).values[key]; indexPresent {
			return
		}
		if _, ownerPresent := handler.owners.(*fakeBridgeMap).values[owner]; ownerPresent {
			return
		}
		if _, fallbackPresent := handler.remoteParents.(*fakeBridgeMap).values[owner]; fallbackPresent {
			return
		}
		eligibleLookups++
		if eligibleLookups == 3 {
			ambiguity.mu.Lock()
			delete(ambiguity.values, key)
			ambiguity.mu.Unlock()
		}
	}

	assert.Equal(t, StatusValid, handler.Handle(owner, OperationTake).Status)
	assert.GreaterOrEqual(t, eligibleLookups, 3)
	assert.Empty(t, handler.claims.(*fakeBridgeMap).values)
	assert.NotContains(t, ambiguity.values, key)
	assert.NotContains(t, handler.states.(*fakeBridgeMap).values, key)
	assert.NotContains(t, handler.generations.(*fakeBridgeMap).values, key)
}

func TestMapHandlerConvergesWhenClaimDisappearsAfterMarkerRelease(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)}, nil, nil,
	)
	claims := handler.claims.(*fakeBridgeMap)
	handler.ambiguity.(*fakeBridgeMap).afterDelete = func(deleted any) {
		if deleted != key {
			return
		}
		claims.mu.Lock()
		delete(claims.values, key)
		claims.mu.Unlock()
	}

	assert.Equal(t, StatusValid, handler.Handle(owner, OperationTake).Status)
	assert.NotContains(t, claims.values, key)
	assert.NotContains(t, handler.ownerGuards.(*fakeBridgeMap).values, owner)
	assert.NotContains(t, handler.ambiguity.(*fakeBridgeMap).values, key)
	assert.NotContains(t, handler.states.(*fakeBridgeMap).values, key)
	assert.NotContains(t, handler.generations.(*fakeBridgeMap).values, key)
}

func TestMapHandlerRetainsClaimAfterGenerationCleanupStarts(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	testError := errors.New("injected map failure")

	tests := []struct {
		name        string
		status      Status
		retainClaim bool
		configure   func(*MapHandler)
	}{
		{
			name:        "process incarnation revalidation lookup",
			status:      StatusTransportError,
			retainClaim: true,
			configure: func(handler *MapHandler) {
				handler.claims.(*fakeBridgeMap).afterUpdate = func(any, any) {
					handler.incarnations.(*fakeBridgeMap).lookupErr = testError
				}
			},
		},
		{
			name:        "owner revalidation lookup",
			status:      StatusTransportError,
			retainClaim: true,
			configure: func(handler *MapHandler) {
				handler.claims.(*fakeBridgeMap).afterUpdate = func(any, any) {
					handler.owners.(*fakeBridgeMap).lookupErr = testError
				}
			},
		},
		{
			name:        "state revalidation lookup",
			status:      StatusTransportError,
			retainClaim: true,
			configure: func(handler *MapHandler) {
				handler.claims.(*fakeBridgeMap).afterUpdate = func(any, any) {
					handler.states.(*fakeBridgeMap).lookupErr = testError
				}
			},
		},
		{
			name:        "generation revalidation lookup",
			status:      StatusTransportError,
			retainClaim: true,
			configure: func(handler *MapHandler) {
				handler.claims.(*fakeBridgeMap).afterUpdate = func(any, any) {
					handler.generations.(*fakeBridgeMap).lookupErr = testError
				}
			},
		},
		{
			name:        "ambiguity revalidation lookup",
			status:      StatusTransportError,
			retainClaim: true,
			configure: func(handler *MapHandler) {
				handler.claims.(*fakeBridgeMap).afterUpdate = func(any, any) {
					handler.ambiguity.(*fakeBridgeMap).lookupErr = testError
				}
			},
		},
		{
			name:        "connection revalidation lookup",
			status:      StatusTransportError,
			retainClaim: true,
			configure: func(handler *MapHandler) {
				handler.claims.(*fakeBridgeMap).afterUpdate = func(any, any) {
					handler.connections.(*fakeBridgeMap).lookupErr = testError
				}
			},
		},
		{
			name:        "cookie connection revalidation lookup",
			status:      StatusTransportError,
			retainClaim: true,
			configure: func(handler *MapHandler) {
				handler.claims.(*fakeBridgeMap).afterUpdate = func(any, any) {
					handler.cookieConnections.(*fakeBridgeMap).lookupErr = testError
				}
			},
		},
		{
			name:        "fallback revalidation lookup",
			status:      StatusTransportError,
			retainClaim: true,
			configure: func(handler *MapHandler) {
				handler.claims.(*fakeBridgeMap).afterUpdate = func(any, any) {
					handler.remoteParents.(*fakeBridgeMap).lookupErr = testError
				}
			},
		},
		{
			name:        "connection delete",
			status:      StatusValid,
			retainClaim: true,
			configure: func(handler *MapHandler) {
				handler.connections.(*fakeBridgeMap).deleteErr = testError
			},
		},
		{
			name:        "terminal update",
			status:      StatusValid,
			retainClaim: true,
			configure: func(handler *MapHandler) {
				handler.terminals.(*fakeBridgeMap).updateErr = testError
			},
		},
		{
			name:        "state delete",
			status:      StatusValid,
			retainClaim: true,
			configure: func(handler *MapHandler) {
				handler.states.(*fakeBridgeMap).deleteErr = testError
			},
		},
		{
			name:        "fallback delete",
			status:      StatusValid,
			retainClaim: true,
			configure: func(handler *MapHandler) {
				handler.remoteParents.(*fakeBridgeMap).deleteErr = testError
			},
		},
		{
			name:        "owner delete",
			status:      StatusValid,
			retainClaim: true,
			configure: func(handler *MapHandler) {
				handler.owners.(*fakeBridgeMap).deleteErr = testError
			},
		},
		{
			name:        "ambiguity delete",
			status:      StatusAmbiguous,
			retainClaim: true,
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
			if test.retainClaim {
				assert.NotEmpty(t, handler.claims.(*fakeBridgeMap).values)
			} else {
				assert.Empty(t, handler.claims.(*fakeBridgeMap).values)
			}
		})
	}
}

func TestMapHandlerAmbiguousConsumeMarksPostClaimValidationLoss(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)}, nil, nil,
	)
	key := stateKey{Owner: owner, Generation: 10}
	encoded := handler.remoteParents.(*fakeBridgeMap).values[owner].([RecordSize]byte)
	handler.claims.(*fakeBridgeMap).afterUpdate = func(updatedKey, _ any) {
		if updatedKey != key {
			return
		}
		index := handler.generations.(*fakeBridgeMap).values[key].(generationIndexValue)
		index.ObservedMonotonicNS++
		handler.generations.(*fakeBridgeMap).values[key] = index
	}

	committed, status, err := handler.consume(t.Context(), []resolvedCandidate{{
		Owner:              owner,
		Generation:         10,
		ProcessIncarnation: testProcessIncarnation,
		Encoded:            encoded,
	}}, lifecycleAmbiguous)
	require.NoError(t, err)
	assert.True(t, committed)
	assert.Equal(t, StatusUnknown, status)
	assert.Contains(t, handler.claims.(*fakeBridgeMap).values, key)
	assert.NotZero(t, handler.ambiguity.(*fakeBridgeMap).values[key])
}

func TestMapHandlerAmbiguousConsumeContinuesPastIndependentFences(t *testing.T) {
	owners := []Identity{
		{TID: 3, PID: 2, Namespace: 1},
		{TID: 4, PID: 2, Namespace: 1},
	}

	tests := []struct {
		name          string
		order         []int
		collided      map[int]bool
		guarded       map[int]bool
		wantCommitted bool
	}{
		{
			name:          "collision then free",
			order:         []int{0, 1},
			collided:      map[int]bool{0: true},
			wantCommitted: true,
		},
		{
			name:          "free then collision",
			order:         []int{0, 1},
			collided:      map[int]bool{1: true},
			wantCommitted: true,
		},
		{
			name:          "all collide",
			order:         []int{0, 1},
			collided:      map[int]bool{0: true, 1: true},
			wantCommitted: false,
		},
		{
			name:          "foreign guard then free",
			order:         []int{0, 1},
			guarded:       map[int]bool{0: true},
			wantCommitted: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			remoteParents := map[Identity]any{
				owners[0]: validEncodedRecord(t, 10),
				owners[1]: validEncodedRecord(t, 10),
			}
			handler := testMapHandler(remoteParents, nil, nil)
			// Stop each newly claimed candidate after durable E/G acquisition so
			// the deferred producer handoff remains directly observable.
			handler.terminals.(*fakeBridgeMap).updateErr = errors.New(
				"injected terminal publication failure",
			)

			candidates := make([]resolvedCandidate, 0, len(test.order))
			collidedClaims := make(map[int]generationClaim)
			guardClaims := make(map[int]generationClaim)
			for _, index := range test.order {
				key := stateKey{Owner: owners[index], Generation: 10}
				if test.collided[index] {
					claim := *cleanupGenerationClaim(
						lifecycleConsumed,
						uint64(10*time.Second),
					)
					handler.claims.(*fakeBridgeMap).values[key] = claim
					collidedClaims[index] = claim
				}
				if test.guarded[index] {
					guard := testGenerationClaim(lifecyclePublishing)
					handler.ownerGuards.(*fakeBridgeMap).values[owners[index]] = guard
					guardClaims[index] = guard
				}
				candidates = append(candidates, resolvedCandidate{
					Owner:              owners[index],
					Generation:         10,
					ProcessIncarnation: testProcessIncarnation,
					Encoded:            remoteParents[owners[index]].([RecordSize]byte),
				})
			}

			committed, status, err := handler.consume(
				t.Context(), candidates, lifecycleAmbiguous,
			)
			require.NoError(t, err)
			assert.Equal(t, test.wantCommitted, committed)
			assert.Equal(t, StatusUnknown, status)

			for index := range owners {
				key := stateKey{Owner: owners[index], Generation: 10}
				switch {
				case test.collided[index]:
					assert.Equal(t, collidedClaims[index],
						handler.claims.(*fakeBridgeMap).values[key])
				case test.guarded[index]:
					assert.NotContains(t, handler.claims.(*fakeBridgeMap).values, key)
					assert.Equal(t, guardClaims[index],
						handler.ownerGuards.(*fakeBridgeMap).values[owners[index]])
				default:
					claim, ok := handler.claims.(*fakeBridgeMap).values[key].(generationClaim)
					require.True(t, ok)
					assert.Equal(t, lifecycleCleanup, claim.Lifecycle)
					assert.Equal(t, lifecycleDiscarded, claim.Reserved[0])
					guard, ok := handler.ownerGuards.(*fakeBridgeMap).values[owners[index]].(generationClaim)
					require.True(t, ok)
					assert.Equal(t, lifecycleCleanup, guard.Lifecycle)
					assert.Equal(t, lifecyclePublishing, guard.Reserved[0])
				}
			}
		})
	}
}

func TestMapHandlerAmbiguousConsumeRetainsClaimOnTransportUncertainty(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{identity: validEncodedRecord(t, 10)}, nil,
		map[Identity]any{identity: uint64(10 * time.Second)},
	)
	transportErr := errors.New("injected ambiguous-consume transport failure")
	handler.claims.(*fakeBridgeMap).afterUpdate = func(any, any) {
		handler.generations.(*fakeBridgeMap).lookupErr = transportErr
	}

	assert.Equal(t, StatusTransportError, handler.Handle(identity, OperationTake).Status)
	key := stateKey{Owner: identity, Generation: 10}
	claim := handler.claims.(*fakeBridgeMap).values[key].(generationClaim)
	assert.Equal(t, lifecycleCleanup, claim.Lifecycle)
	assert.Equal(t, lifecycleDiscarded, claim.Reserved[0])
	assert.Greater(t, claim.ObservedMonotonicNS, uint64(10*time.Second))
	handler.generations.(*fakeBridgeMap).lookupErr = nil
	assert.Equal(t, StatusAlreadyConsumed, handler.Handle(identity, OperationTake).Status)
}

func TestMapHandlerAmbiguousConsumeRetainsFinalClaimAfterValidationLoss(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{identity: validEncodedRecord(t, 10)}, nil,
		map[Identity]any{identity: uint64(10 * time.Second)},
	)
	handler.claims.(*fakeBridgeMap).afterUpdate = func(any, any) {
		delete(handler.states.(*fakeBridgeMap).values,
			stateKey{Owner: identity, Generation: 10})
	}

	assert.Equal(t, StatusAmbiguous, handler.Handle(identity, OperationTake).Status)
	key := stateKey{Owner: identity, Generation: 10}
	claim := handler.claims.(*fakeBridgeMap).values[key].(generationClaim)
	assert.Equal(t, lifecycleCleanup, claim.Lifecycle)
	assert.Equal(t, lifecycleDiscarded, claim.Reserved[0])
	assert.Greater(t, claim.ObservedMonotonicNS, uint64(10*time.Second))
	assert.NotZero(t, handler.ambiguity.(*fakeBridgeMap).values[key])
}

func TestMapHandlerMalformedFallbackNeverAcquiresClaim(t *testing.T) {
	identity := Identity{TID: 3, PID: 2, Namespace: 1}
	for _, test := range []struct {
		name      string
		configure func(*MapHandler)
	}{
		{
			name: "process lookup error",
			configure: func(handler *MapHandler) {
				handler.incarnations.(*fakeBridgeMap).lookupErr = errors.New("injected incarnation revalidation failure")
			},
		},
		{
			name: "owner lookup error",
			configure: func(handler *MapHandler) {
				handler.owners.(*fakeBridgeMap).lookupErr = errors.New("injected owner revalidation failure")
			},
		},
		{
			name: "incarnation replacement",
			configure: func(handler *MapHandler) {
				handler.incarnations.(*fakeBridgeMap).values[javaProcessIdentity(identity)] =
					testProcessIncarnation + 1
			},
		},
		{
			name: "owner replacement",
			configure: func(handler *MapHandler) {
				handler.owners.(*fakeBridgeMap).values[identity] = ownerValue{
					Generation:         11,
					ProcessIncarnation: testProcessIncarnation,
					Lifecycle:          lifecycleActive,
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := testMapHandler(
				map[Identity]any{identity: validEncodedRecord(t, 10)}, nil, nil,
			)
			handler.remoteParents.(*fakeBridgeMap).values[identity] = [RecordSize]byte{}
			triggered := false
			handler.claims.(*fakeBridgeMap).afterUpdate = func(any, any) {
				triggered = true
				test.configure(handler)
			}

			assert.Equal(t, StatusMalformed, handler.Handle(identity, OperationTake).Status)
			assert.False(t, triggered)
			assert.Empty(t, handler.claims.(*fakeBridgeMap).values)
		})
	}
}

func TestMapHandlerRetainsOneShotClaimWhenForeignGuardWinsFinishRace(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)}, nil, nil,
	)
	foreignGuard := generationClaim{
		ObservedMonotonicNS: uint64(9 * time.Second),
		ProcessIncarnation:  10,
		Lifecycle:           lifecyclePublishing,
	}
	claims := handler.claims.(*fakeBridgeMap)
	claims.afterLookup = func(count int) {
		if count == 1 {
			guards := handler.ownerGuards.(*fakeBridgeMap)
			guards.mu.Lock()
			guards.values[owner] = foreignGuard
			guards.mu.Unlock()
		}
	}

	assert.Equal(t, StatusValid, handler.Handle(owner, OperationTake).Status)
	assert.Contains(t, claims.values, key)
	assert.Equal(t, foreignGuard, handler.ownerGuards.(*fakeBridgeMap).values[owner])
	assert.NotZero(t, handler.ambiguity.(*fakeBridgeMap).values[key])
	assert.Empty(t, handler.terminals.(*fakeBridgeMap).values)
}

func TestMapHandlerDoesNotRemarkOldGenerationAfterFinalGuardRelease(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	oldKey := stateKey{Owner: owner, Generation: 10}
	successorKey := stateKey{Owner: owner, Generation: 11}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)}, nil, nil,
	)
	claims := handler.claims.(*fakeBridgeMap)
	guards := handler.ownerGuards.(*fakeBridgeMap)
	guards.afterDelete = func(deleted any) {
		deletedOwner, ok := deleted.(Identity)
		if !ok || deletedOwner != owner {
			return
		}
		handler.remoteParents.(*fakeBridgeMap).values[owner] = validEncodedRecord(t, 11)
		seedOwnerState(handler, owner, 11)
	}

	assert.Equal(t, StatusValid, handler.Handle(owner, OperationTake).Status)
	assert.Empty(t, claims.values)
	assert.Empty(t, guards.values)
	assert.NotContains(t, handler.ambiguity.(*fakeBridgeMap).values, oldKey)
	assert.Contains(t, handler.ambiguity.(*fakeBridgeMap).values, successorKey)
	assert.NotContains(t, handler.states.(*fakeBridgeMap).values, oldKey)
	assert.Contains(t, handler.states.(*fakeBridgeMap).values, successorKey)
	assert.Contains(t, handler.generations.(*fakeBridgeMap).values, successorKey)
	assert.Equal(t, uint64(11),
		handler.owners.(*fakeBridgeMap).values[owner].(ownerValue).Generation)
	assert.Equal(t, validEncodedRecord(t, 11),
		handler.remoteParents.(*fakeBridgeMap).values[owner])
}

func TestMapHandlerActiveFinishRejectsTerminalReplacement(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)}, nil, nil,
	)
	key := stateKey{Owner: owner, Generation: 10}
	state := handler.states.(*fakeBridgeMap).values[key].(stateValue)
	record, err := UnmarshalRecord(state.Response[:])
	require.NoError(t, err)
	claim := testGoGenerationClaim(lifecycleConsumed)
	handler.claims.(*fakeBridgeMap).values[key] = claim
	replacement := terminalValue{
		Generation:          11,
		ObservedMonotonicNS: uint64(11 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}
	replaced := false
	handler.terminals.(*fakeBridgeMap).afterUpdate = func(updatedKey, _ any) {
		if updatedKey != owner || replaced {
			return
		}
		replaced = true
		handler.terminals.(*fakeBridgeMap).values[owner] = replacement
	}

	result := handler.finish(
		owner, record, testProcessIncarnation, lifecycleConsumed, &claim,
	)
	assert.False(t, result.complete)
	assert.True(t, result.mutationStarted)
	assert.True(t, replaced)
	assert.Equal(t, replacement, handler.terminals.(*fakeBridgeMap).values[owner])
	assert.Contains(t, handler.states.(*fakeBridgeMap).values, key)
	assert.Contains(t, handler.generations.(*fakeBridgeMap).values, key)
	assert.NotZero(t, handler.ambiguity.(*fakeBridgeMap).values[key])
	assert.Zero(t, claim)
	retainedClaim := handler.claims.(*fakeBridgeMap).values[key].(generationClaim)
	assert.True(t, validGenerationCleanupClaim(retainedClaim))
	assert.Equal(t, lifecycleConsumed, retainedClaim.Reserved[0])
	retainedGuard := handler.ownerGuards.(*fakeBridgeMap).values[owner].(generationClaim)
	assert.True(t, validGenerationCleanupGuard(owner, retainedGuard))
	assert.Equal(t, key.Generation, retainedGuard.ProcessIncarnation)
}

func TestMapHandlerDetachedFinishRejectsPublishedTerminalReplacement(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)},
		map[Identity]any{child: activeTaskLink(owner, 10)},
		nil,
	)
	oldKey := stateKey{Owner: owner, Generation: 10}
	oldState := handler.states.(*fakeBridgeMap).values[oldKey].(stateValue)
	require.Equal(t, uint32(1), oldState.Aliases)
	oldRecord, err := UnmarshalRecord(oldState.Response[:])
	require.NoError(t, err)
	handler.remoteParents.(*fakeBridgeMap).values[owner] = validEncodedRecord(t, 11)
	seedOwnerState(handler, owner, 11)
	successorKey := stateKey{Owner: owner, Generation: 11}
	replacement := terminalValue{
		Generation:          11,
		ObservedMonotonicNS: uint64(11 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}
	replaced := false
	handler.terminals.(*fakeBridgeMap).afterUpdate = func(updatedKey, _ any) {
		if updatedKey != owner || replaced {
			return
		}
		replaced = true
		handler.terminals.(*fakeBridgeMap).values[owner] = replacement
	}
	claim := testGoGenerationClaim(lifecycleConsumed)
	handler.claims.(*fakeBridgeMap).values[oldKey] = claim

	result := handler.finish(
		owner, oldRecord, testProcessIncarnation, lifecycleConsumed, &claim,
	)
	assert.False(t, result.complete)
	assert.True(t, result.mutationStarted)
	assert.True(t, replaced)
	assert.Equal(t, replacement, handler.terminals.(*fakeBridgeMap).values[owner])
	assert.Contains(t, handler.states.(*fakeBridgeMap).values, oldKey)
	assert.Contains(t, handler.generations.(*fakeBridgeMap).values, oldKey)
	assert.Contains(t, handler.states.(*fakeBridgeMap).values, successorKey)
	assert.Contains(t, handler.generations.(*fakeBridgeMap).values, successorKey)
	assert.NotZero(t, handler.ambiguity.(*fakeBridgeMap).values[oldKey])
	assert.Zero(t, claim)
	retainedClaim := handler.claims.(*fakeBridgeMap).values[oldKey].(generationClaim)
	assert.True(t, validGenerationCleanupClaim(retainedClaim))
	assert.Equal(t, lifecycleConsumed, retainedClaim.Reserved[0])
	retainedGuard := handler.ownerGuards.(*fakeBridgeMap).values[owner].(generationClaim)
	assert.True(t, validGenerationCleanupGuard(owner, retainedGuard))
	assert.Equal(t, oldKey.Generation, retainedGuard.ProcessIncarnation)
}

func TestMapHandlerAliasedFinishPreservesSuccessorTerminalAndCleansOldGeneration(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)},
		map[Identity]any{child: activeTaskLink(owner, 10)},
		nil,
	)
	oldKey := stateKey{Owner: owner, Generation: 10}
	oldState := handler.states.(*fakeBridgeMap).values[oldKey].(stateValue)
	require.Equal(t, uint32(1), oldState.Aliases)
	oldRecord, err := UnmarshalRecord(oldState.Response[:])
	require.NoError(t, err)
	handler.remoteParents.(*fakeBridgeMap).values[owner] = validEncodedRecord(t, 11)
	seedOwnerState(handler, owner, 11)
	successorKey := stateKey{Owner: owner, Generation: 11}
	successorTerminal := terminalValue{
		Generation:          11,
		ObservedMonotonicNS: uint64(11 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}
	handler.terminals.(*fakeBridgeMap).values[owner] = successorTerminal
	claim := testGoGenerationClaim(lifecycleConsumed)
	handler.claims.(*fakeBridgeMap).values[oldKey] = claim

	result := handler.finish(
		owner, oldRecord, testProcessIncarnation, lifecycleConsumed, &claim,
	)
	assert.True(t, result.complete)
	assert.True(t, result.mutationStarted)
	assert.Equal(t, successorTerminal, handler.terminals.(*fakeBridgeMap).values[owner])
	assert.NotContains(t, handler.states.(*fakeBridgeMap).values, oldKey)
	assert.NotContains(t, handler.generations.(*fakeBridgeMap).values, oldKey)
	assert.Contains(t, handler.states.(*fakeBridgeMap).values, successorKey)
	assert.Contains(t, handler.generations.(*fakeBridgeMap).values, successorKey)
	assert.Equal(t, uint64(11),
		handler.owners.(*fakeBridgeMap).values[owner].(ownerValue).Generation)
	assert.Zero(t, claim)
	assert.NotContains(t, handler.claims.(*fakeBridgeMap).values, oldKey)
	assert.NotContains(t, handler.ownerGuards.(*fakeBridgeMap).values, owner)
	assert.NotContains(t, handler.ambiguity.(*fakeBridgeMap).values, oldKey)
	for _, value := range handler.connections.(*fakeBridgeMap).values {
		assert.NotEqual(t, uint64(10), value.(connectionClaim).Generation)
	}
	for _, value := range handler.cookieConnections.(*fakeBridgeMap).values {
		assert.NotEqual(t, uint64(10), value.(connectionClaim).Generation)
	}
}

func TestMapHandlerRetainsUnaliasedGenerationWhenOwnerChangesDuringRevalidation(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)}, nil, nil,
	)
	oldKey := stateKey{Owner: owner, Generation: 10}
	oldState := handler.states.(*fakeBridgeMap).values[oldKey].(stateValue)
	oldRecord, err := UnmarshalRecord(oldState.Response[:])
	require.NoError(t, err)
	successorTerminal := terminalValue{
		Generation:          11,
		ObservedMonotonicNS: uint64(11 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}
	owners := handler.owners.(*fakeBridgeMap)
	claim := testGoGenerationClaim(lifecycleConsumed)
	handler.claims.(*fakeBridgeMap).values[oldKey] = claim
	owners.afterLookup = func(count int) {
		if count != 1 {
			return
		}
		handler.remoteParents.(*fakeBridgeMap).values[owner] = validEncodedRecord(t, 11)
		seedOwnerState(handler, owner, 11)
		handler.terminals.(*fakeBridgeMap).values[owner] = successorTerminal
	}

	result := handler.finish(
		owner, oldRecord, testProcessIncarnation, lifecycleConsumed, &claim,
	)
	assert.False(t, result.complete)
	assert.True(t, result.mutationStarted)
	assert.Equal(t, successorTerminal, handler.terminals.(*fakeBridgeMap).values[owner])
	assert.Contains(t, handler.states.(*fakeBridgeMap).values, oldKey)
	assert.Contains(t, handler.generations.(*fakeBridgeMap).values, oldKey)
	assert.Equal(t, uint64(11), owners.values[owner].(ownerValue).Generation)
	assert.Zero(t, claim)
	retainedClaim := handler.claims.(*fakeBridgeMap).values[oldKey].(generationClaim)
	assert.Equal(t, lifecycleCleanup, retainedClaim.Lifecycle)
	assert.Equal(t, lifecycleConsumed, retainedClaim.Reserved[0])
	retainedGuard := handler.ownerGuards.(*fakeBridgeMap).values[owner].(generationClaim)
	assert.Equal(t, lifecycleCleanup, retainedGuard.Lifecycle)
	assert.Equal(t, lifecyclePublishing, retainedGuard.Reserved[0])
	assert.NotZero(t, handler.ambiguity.(*fakeBridgeMap).values[oldKey])
}

func TestMapHandlerFinishRetiresGenerationFencesInOrder(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)}, nil, nil,
	)
	key := stateKey{Owner: owner, Generation: 10}
	state := handler.states.(*fakeBridgeMap).values[key].(stateValue)
	record, err := UnmarshalRecord(state.Response[:])
	require.NoError(t, err)
	claim := testGoGenerationClaim(lifecycleConsumed)
	claims := handler.claims.(*fakeBridgeMap)
	guards := handler.ownerGuards.(*fakeBridgeMap)
	ambiguity := handler.ambiguity.(*fakeBridgeMap)
	claims.values[key] = claim

	retired := make([]string, 0, 3)
	ambiguity.afterDelete = func(deletedKey any) {
		assert.Equal(t, key, deletedKey)
		retired = append(retired, "M")
		assert.NotContains(t, ambiguity.values, key)
		assert.Contains(t, claims.values, key)
		assert.Contains(t, guards.values, owner)
	}
	claims.afterDelete = func(deletedKey any) {
		assert.Equal(t, key, deletedKey)
		retired = append(retired, "E")
		assert.NotContains(t, ambiguity.values, key)
		assert.NotContains(t, claims.values, key)
		assert.Contains(t, guards.values, owner)
	}
	guards.afterDelete = func(deletedKey any) {
		assert.Equal(t, owner, deletedKey)
		retired = append(retired, "G")
		assert.NotContains(t, ambiguity.values, key)
		assert.NotContains(t, claims.values, key)
		assert.NotContains(t, guards.values, owner)
	}

	result := handler.finish(
		owner, record, testProcessIncarnation, lifecycleConsumed, &claim,
	)
	require.True(t, result.complete)
	assert.Equal(t, []string{"M", "E", "G"}, retired)
}

func TestMapHandlerActiveFinishClaimBlocksSuccessorStageAfterOwnerRevalidation(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)}, nil, nil,
	)
	oldKey := stateKey{Owner: owner, Generation: 10}
	oldState := handler.states.(*fakeBridgeMap).values[oldKey].(stateValue)
	oldRecord, err := UnmarshalRecord(oldState.Response[:])
	require.NoError(t, err)
	claim := testGoGenerationClaim(lifecycleConsumed)
	handler.claims.(*fakeBridgeMap).values[oldKey] = claim
	stageAttempted := false
	stageBlockedByGuard := false
	markerNonzero := false
	owners := handler.owners.(*fakeBridgeMap)
	owners.afterLookup = func(count int) {
		if count != 2 {
			return
		}
		stageAttempted = true
		guards := handler.ownerGuards.(*fakeBridgeMap)
		guards.mu.Lock()
		_, stageBlockedByGuard = guards.values[owner]
		guards.mu.Unlock()
		marker, ok := handler.ambiguity.(*fakeBridgeMap).values[oldKey].(uint64)
		markerNonzero = ok && marker != 0
	}

	assert.True(t, handler.finishClaimed(
		owner, oldRecord, testProcessIncarnation, lifecycleConsumed, &claim,
	))
	assert.True(t, stageAttempted)
	assert.True(t, stageBlockedByGuard)
	assert.True(t, markerNonzero)
	assert.Equal(t, uint64(10),
		handler.terminals.(*fakeBridgeMap).values[owner].(terminalValue).Generation)
	assert.NotContains(t, handler.states.(*fakeBridgeMap).values, oldKey)
	assert.NotContains(t, handler.generations.(*fakeBridgeMap).values, oldKey)
	assert.Empty(t, handler.claims.(*fakeBridgeMap).values)
}

func TestMapHandlerActiveFinishReplacesDetachedPredecessorTerminal(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)},
		map[Identity]any{child: activeTaskLink(owner, 10)},
		nil,
	)
	oldKey := stateKey{Owner: owner, Generation: 10}
	oldState := handler.states.(*fakeBridgeMap).values[oldKey].(stateValue)
	require.Equal(t, uint32(1), oldState.Aliases)
	oldRecord, err := UnmarshalRecord(oldState.Response[:])
	require.NoError(t, err)
	handler.remoteParents.(*fakeBridgeMap).values[owner] = validEncodedRecord(t, 11)
	seedOwnerState(handler, owner, 11)
	oldTerminal := terminalValue{
		Generation:          10,
		ObservedMonotonicNS: oldRecord.ObservedMonotonicNS,
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}
	handler.terminals.(*fakeBridgeMap).values[owner] = oldTerminal
	oldClaim := testGoGenerationClaim(lifecycleConsumed)
	handler.claims.(*fakeBridgeMap).values[oldKey] = oldClaim

	assert.True(t, handler.finishClaimed(
		owner, oldRecord, testProcessIncarnation, lifecycleConsumed, &oldClaim,
	))
	assert.Equal(t, oldTerminal, handler.terminals.(*fakeBridgeMap).values[owner])
	assert.NotContains(t, handler.ambiguity.(*fakeBridgeMap).values, oldKey)
	assert.NotContains(t, handler.ownerGuards.(*fakeBridgeMap).values, owner)
	assert.NotContains(t, handler.claims.(*fakeBridgeMap).values, oldKey)

	newKey := stateKey{Owner: owner, Generation: 11}
	newState := handler.states.(*fakeBridgeMap).values[newKey].(stateValue)
	newRecord, err := UnmarshalRecord(newState.Response[:])
	require.NoError(t, err)
	newClaim := testGoGenerationClaim(lifecycleConsumed)
	handler.claims.(*fakeBridgeMap).values[newKey] = newClaim
	assert.True(t, handler.finishClaimed(
		owner, newRecord, testProcessIncarnation, lifecycleConsumed, &newClaim,
	))
	assert.Equal(t, terminalValue{
		Generation:          11,
		ObservedMonotonicNS: newRecord.ObservedMonotonicNS,
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}, handler.terminals.(*fakeBridgeMap).values[owner])
	assert.NotContains(t, handler.claims.(*fakeBridgeMap).values, oldKey)
}

func TestMapHandlerDetachedFinishWithoutOldStateRetainsClaimAndIndex(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)}, nil, nil,
	)
	oldKey := stateKey{Owner: owner, Generation: 10}
	oldState := handler.states.(*fakeBridgeMap).values[oldKey].(stateValue)
	oldRecord, err := UnmarshalRecord(oldState.Response[:])
	require.NoError(t, err)
	delete(handler.states.(*fakeBridgeMap).values, oldKey)
	handler.remoteParents.(*fakeBridgeMap).values[owner] = validEncodedRecord(t, 11)
	seedOwnerState(handler, owner, 11)
	successorTerminal := terminalValue{
		Generation:          11,
		ObservedMonotonicNS: uint64(11 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}
	handler.terminals.(*fakeBridgeMap).values[owner] = successorTerminal
	claim := testGoGenerationClaim(lifecycleConsumed)
	originalClaim := claim
	handler.claims.(*fakeBridgeMap).values[oldKey] = claim

	assert.False(t, handler.finishClaimed(
		owner, oldRecord, testProcessIncarnation, lifecycleConsumed, &claim,
	))
	assert.Zero(t, claim)
	retained := handler.claims.(*fakeBridgeMap).values[oldKey].(generationClaim)
	assert.Equal(t, lifecycleCleanup, retained.Lifecycle)
	assert.Equal(t, lifecycleConsumed, retained.Reserved[0])
	assert.Greater(t, retained.ObservedMonotonicNS, originalClaim.ObservedMonotonicNS)
	assert.Contains(t, handler.generations.(*fakeBridgeMap).values, oldKey)
	assert.Equal(t, successorTerminal, handler.terminals.(*fakeBridgeMap).values[owner])
	assert.Equal(t, uint64(11),
		handler.owners.(*fakeBridgeMap).values[owner].(ownerValue).Generation)
}

func TestMapHandlerMalformedActiveOwnerCannotOverwriteTerminal(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)}, nil, nil,
	)
	key := stateKey{Owner: owner, Generation: 10}
	state := handler.states.(*fakeBridgeMap).values[key].(stateValue)
	record, err := UnmarshalRecord(state.Response[:])
	require.NoError(t, err)
	indexed := handler.owners.(*fakeBridgeMap).values[owner].(ownerValue)
	indexed.Lifecycle = lifecyclePublishing
	handler.owners.(*fakeBridgeMap).values[owner] = indexed
	successor := terminalValue{
		Generation:          11,
		ObservedMonotonicNS: uint64(11 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}
	handler.terminals.(*fakeBridgeMap).values[owner] = successor

	claim := testGoGenerationClaim(lifecycleConsumed)
	handler.claims.(*fakeBridgeMap).values[key] = claim
	result := handler.finish(
		owner, record, testProcessIncarnation, lifecycleConsumed, &claim,
	)
	assert.False(t, result.complete)
	assert.True(t, result.mutationStarted)
	assert.Equal(t, successor, handler.terminals.(*fakeBridgeMap).values[owner])
	assert.Contains(t, handler.claims.(*fakeBridgeMap).values, key)
	assert.Contains(t, handler.ownerGuards.(*fakeBridgeMap).values, owner)
	assert.NotZero(t, handler.ambiguity.(*fakeBridgeMap).values[key])
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

func testGoGenerationClaim(lifecycle uint8) generationClaim {
	claim := testGenerationClaim(lifecycle)
	claim.Reserved[6] = generationGoProducerTag
	return claim
}

func cleanupGenerationClaim(
	origin uint8,
	observedMonotonicNS uint64,
) *generationClaim {
	claim := generationClaim{
		ObservedMonotonicNS: observedMonotonicNS,
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleCleanup,
	}
	claim.Reserved[0] = origin
	return &claim
}
