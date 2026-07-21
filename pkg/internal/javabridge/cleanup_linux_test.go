// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javabridge

import (
	"errors"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCleanupKernelMapLayouts(t *testing.T) {
	assert.Equal(t, uintptr(16), unsafe.Sizeof(handoffKey{}))
	assert.Equal(t, uintptr(16), unsafe.Sizeof(handoffClaimValue{}))
	assert.Equal(t, uintptr(24), unsafe.Sizeof(retiredProcessKey{}))
	assert.Equal(t, uintptr(24), unsafe.Sizeof(generationClaim{}))
}

func TestCleanupStatsCountGenerationOnce(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	cleanup := testCleanup(handler)
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{Cleaned: 1}, stats)

	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
}

func TestCleanupStatsDetectFallbackEviction(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*MapHandler, Identity)
	}{
		{
			name: "missing",
			configure: func(handler *MapHandler, owner Identity) {
				delete(handler.remoteParents.(*fakeBridgeMap).values, owner)
			},
		},
		{
			name: "different generation",
			configure: func(handler *MapHandler, owner Identity) {
				handler.remoteParents.(*fakeBridgeMap).values[owner] = validEncodedRecord(t, 11)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			handler := testMapHandler(
				map[Identity]any{owner: validEncodedRecord(t, 10)},
				nil,
				nil,
			)
			test.configure(handler, owner)
			cleanup := testCleanup(handler)

			stats, err := cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{Cleaned: 1, Evicted: 1}, stats)
			assert.Empty(t, cleanup.maps.generations.(*fakeBridgeMap).values)
		})
	}
}

func TestCleanupStatsDoNotClassifyExpiredGenerationAsEvicted(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	delete(handler.remoteParents.(*fakeBridgeMap).values, owner)
	cleanup := testCleanup(handler)
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{Cleaned: 1}, stats)
}

func TestCleanupStatsDoNotClassifyPublishingGenerationAsEvicted(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	delete(handler.remoteParents.(*fakeBridgeMap).values, owner)
	indexed := handler.owners.(*fakeBridgeMap).values[owner].(ownerValue)
	indexed.Lifecycle = lifecyclePublishing
	handler.owners.(*fakeBridgeMap).values[owner] = indexed
	cleanup := testCleanup(handler)

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.NotEmpty(t, cleanup.maps.generations.(*fakeBridgeMap).values)
}

func TestCleanupStatsRevalidateFallbackEviction(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	encoded := validEncodedRecord(t, 10)
	handler := testMapHandler(map[Identity]any{owner: encoded}, nil, nil)
	delete(handler.remoteParents.(*fakeBridgeMap).values, owner)
	generations := handler.generations.(*fakeBridgeMap)
	generations.afterLookup = func(count int) {
		if count != 1 {
			return
		}
		handler.remoteParents.(*fakeBridgeMap).values[owner] = encoded
	}
	cleanup := testCleanup(handler)

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.NotEmpty(t, cleanup.maps.generations.(*fakeBridgeMap).values)
	assert.Contains(t, cleanup.maps.remoteParents.(*fakeBridgeMap).values, owner)
}

func TestCleanupStatsCountMalformedGenerationOnce(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	handler.remoteParents.(*fakeBridgeMap).values[owner] = [RecordSize]byte{}
	cleanup := testCleanup(handler)

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{Cleaned: 1}, stats)
}

func TestCleanupStatsCountRetirementWithoutDeletingTaskLink(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	handler := testMapHandler(nil, map[Identity]any{
		child: activeTaskLink(owner, 10),
	}, nil)
	cleanup := testCleanup(handler)
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	process := javaProcessIdentity(owner)
	cleanup.maps.retired.(*fakeBridgeMap).values[retiredProcessKey{
		Process:            process,
		ProcessIncarnation: testProcessIncarnation,
	}] = uint64(41 * time.Second)

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{Cleaned: 1}, stats)
	assert.NotEmpty(t, cleanup.maps.tasks.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.retired.(*fakeBridgeMap).values)
}

func TestCleanupRemovesExpiredGenerationAndTombstones(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)},
		map[Identity]any{child: activeTaskLink(owner, 10)},
		nil,
	)
	cleanup := testCleanup(handler)
	cleanup.ttl = 30 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }

	key := stateKey{Owner: owner, Generation: 10}
	handoff := handoffKey{PID: child.PID, Namespace: child.Namespace, Token: 77}
	cleanup.maps.handoffs.(*fakeBridgeMap).values[handoff] = activeTaskLink(owner, 10)
	cleanup.maps.handoffClaims.(*fakeBridgeMap).values[handoff] = handoffClaimValue{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
	}
	cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(10 * time.Second)
	cleanup.maps.claims.(*fakeBridgeMap).values[key] = testGenerationClaim(lifecycleConsumed)

	require.NoError(t, cleanup.Sweep())
	for name, bridgeMap := range map[string]cleanupMap{
		"fallback":       cleanup.maps.remoteParents,
		"connections":    cleanup.maps.connections,
		"ambiguity":      cleanup.maps.ambiguity,
		"owners":         cleanup.maps.owners,
		"states":         cleanup.maps.states,
		"generations":    cleanup.maps.generations,
		"claims":         cleanup.maps.claims,
		"handoff claims": cleanup.maps.handoffClaims,
	} {
		assert.Empty(t, bridgeMap.(*fakeBridgeMap).values, name)
	}
	assert.NotEmpty(t, cleanup.maps.tasks.(*fakeBridgeMap).values)
	assert.NotEmpty(t, cleanup.maps.handoffs.(*fakeBridgeMap).values)
	assert.NotEmpty(t, cleanup.maps.incarnations.(*fakeBridgeMap).values)
}

func TestCleanupDoesNotStealFreshGenerationClaim(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	cleanup := testCleanup(handler)
	cleanup.ttl = 30 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	key := stateKey{Owner: owner, Generation: 10}
	claim := generationClaim{
		ObservedMonotonicNS: uint64(41 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}
	cleanup.maps.claims.(*fakeBridgeMap).values[key] = claim

	require.NoError(t, cleanup.Sweep())
	assert.Equal(t, claim, cleanup.maps.claims.(*fakeBridgeMap).values[key])
	assert.Contains(t, cleanup.maps.remoteParents.(*fakeBridgeMap).values, owner)
	assert.Contains(t, cleanup.maps.owners.(*fakeBridgeMap).values, owner)
	assert.Contains(t, cleanup.maps.generations.(*fakeBridgeMap).values, key)
}

func TestCleanupRetiredProcessDoesNotDeleteReusedPIDState(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	process := javaProcessIdentity(owner)
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	cleanup := testCleanup(handler)
	cleanup.monoTimeNow = func() time.Duration { return 11 * time.Second }

	oldVirtualOwner := javaVirtualThreadOwner(owner, 42)
	newVirtualOwner := javaVirtualThreadOwner(owner, 43)
	oldIdentity := virtualThreadIdentity{
		VirtualThreadID:    42,
		ProcessIncarnation: testProcessIncarnation,
	}
	newIdentity := virtualThreadIdentity{
		VirtualThreadID:    43,
		ProcessIncarnation: testProcessIncarnation + 1,
	}
	cleanup.maps.vtIdentities.(*fakeBridgeMap).values[oldVirtualOwner] = oldIdentity
	cleanup.maps.vtIdentities.(*fakeBridgeMap).values[newVirtualOwner] = newIdentity
	cleanup.maps.incarnations.(*fakeBridgeMap).values[process] = testProcessIncarnation + 1
	retirement := retiredProcessKey{
		Process:            process,
		ProcessIncarnation: testProcessIncarnation,
	}
	cleanup.maps.retired.(*fakeBridgeMap).values[retirement] = uint64(11 * time.Second)

	require.NoError(t, cleanup.Sweep())
	assert.Empty(t, cleanup.maps.generations.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.states.(*fakeBridgeMap).values)
	assert.Equal(
		t, oldIdentity, cleanup.maps.vtIdentities.(*fakeBridgeMap).values[oldVirtualOwner],
	)
	assert.Equal(
		t, newIdentity, cleanup.maps.vtIdentities.(*fakeBridgeMap).values[newVirtualOwner],
	)
	assert.Equal(
		t, testProcessIncarnation+1, cleanup.maps.incarnations.(*fakeBridgeMap).values[process],
	)
	assert.Empty(t, cleanup.maps.retired.(*fakeBridgeMap).values)
}

func TestCleanupInfersRetirementWhenExitMarkerIsMissing(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	carrier := Identity{TID: 4, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	cleanup := testCleanup(handler)
	delete(cleanup.maps.incarnations.(*fakeBridgeMap).values, javaProcessIdentity(owner))
	identity := virtualThreadIdentity{
		VirtualThreadID:    42,
		ProcessIncarnation: testProcessIncarnation,
	}
	cleanup.maps.virtualThreads.(*fakeBridgeMap).values[carrier] = identity
	virtualOwner := javaVirtualThreadOwner(carrier, 42)
	cleanup.maps.vtIdentities.(*fakeBridgeMap).values[virtualOwner] = identity

	require.NoError(t, cleanup.Sweep())
	assert.Empty(t, cleanup.maps.remoteParents.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.owners.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.states.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.generations.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.connections.(*fakeBridgeMap).values)
	assert.Equal(t, identity, cleanup.maps.virtualThreads.(*fakeBridgeMap).values[carrier])
	assert.Equal(t, identity, cleanup.maps.vtIdentities.(*fakeBridgeMap).values[virtualOwner])
}

func TestCleanupDoesNotDeleteProcessIncarnation(t *testing.T) {
	process := Identity{TID: 2, PID: 2, Namespace: 1}
	handler := testMapHandler(nil, nil, nil)
	cleanup := testCleanup(handler)
	incarnations := cleanup.maps.incarnations.(*fakeBridgeMap)
	incarnations.values[process] = testProcessIncarnation + 1
	retirement := retiredProcessKey{
		Process:            process,
		ProcessIncarnation: testProcessIncarnation,
	}
	cleanup.maps.retired.(*fakeBridgeMap).values[retirement] = uint64(11 * time.Second)

	require.NoError(t, cleanup.Sweep())
	assert.Equal(t, testProcessIncarnation+1, incarnations.values[process])
}

func TestCleanupPreservesReusedPIDVirtualThreadReplacement(t *testing.T) {
	carrier := Identity{TID: 4, PID: 2, Namespace: 1}
	process := javaProcessIdentity(carrier)
	handler := testMapHandler(nil, nil, nil)
	cleanup := testCleanup(handler)
	oldIdentity := virtualThreadIdentity{
		VirtualThreadID:    42,
		ProcessIncarnation: testProcessIncarnation,
	}
	newIdentity := virtualThreadIdentity{
		VirtualThreadID:    42,
		ProcessIncarnation: testProcessIncarnation + 1,
	}
	virtualThreads := cleanup.maps.virtualThreads.(*fakeBridgeMap)
	virtualThreads.values[carrier] = newIdentity
	virtualThreads.deleteErr = errors.New("unexpected virtual-thread deletion")
	virtualOwner := javaVirtualThreadOwner(carrier, oldIdentity.VirtualThreadID)
	vtIdentities := cleanup.maps.vtIdentities.(*fakeBridgeMap)
	vtIdentities.values[virtualOwner] = newIdentity
	vtIdentities.deleteErr = errors.New("unexpected virtual-thread identity deletion")
	cleanup.maps.incarnations.(*fakeBridgeMap).values[process] = testProcessIncarnation + 1
	cleanup.maps.retired.(*fakeBridgeMap).values[retiredProcessKey{
		Process:            process,
		ProcessIncarnation: testProcessIncarnation,
	}] = uint64(11 * time.Second)

	require.NoError(t, cleanup.Sweep())
	assert.Equal(t, newIdentity, virtualThreads.values[carrier])
	assert.Equal(t, newIdentity, vtIdentities.values[virtualOwner])
}

func TestCleanupQuarantinesMalformedFallbackAndAllowsOwnerReuse(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	handler.remoteParents.(*fakeBridgeMap).values[owner] = [RecordSize]byte{}
	cleanup := testCleanup(handler)
	cleanup.monoTimeNow = func() time.Duration { return 11 * time.Second }

	require.NoError(t, cleanup.Sweep())
	assert.Empty(t, cleanup.maps.remoteParents.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.owners.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.states.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.generations.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.connections.(*fakeBridgeMap).values)

	handler.remoteParents.(*fakeBridgeMap).values[owner] = validEncodedRecord(t, 11)
	seedOwnerState(handler, owner, 11)
	assert.Equal(t, StatusValid, handler.Handle(owner, OperationTake).Status)
}

func TestCleanupMalformedFallbackQuarantinePreservesReplacement(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	handler.remoteParents.(*fakeBridgeMap).values[owner] = [RecordSize]byte{}
	cleanup := testCleanup(handler)
	remoteParents := cleanup.maps.remoteParents.(*fakeBridgeMap)
	remoteParents.afterLookup = func(count int) {
		if count != 1 {
			return
		}
		remoteParents.mu.Lock()
		remoteParents.values[owner] = validEncodedRecord(t, 11)
		remoteParents.mu.Unlock()
		handler.owners.(*fakeBridgeMap).values[owner] = ownerValue{
			Generation:         11,
			ProcessIncarnation: testProcessIncarnation,
			Lifecycle:          lifecycleActive,
		}
	}

	require.NoError(t, cleanup.Sweep())
	var preserved [RecordSize]byte
	require.NoError(t, remoteParents.Lookup(&owner, &preserved))
	record, err := UnmarshalRecord(preserved[:])
	require.NoError(t, err)
	assert.Equal(t, uint64(11), record.Generation)
}

func TestCleanupNeverDeletesTaskOrHandoffLinks(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	handoff := handoffKey{PID: child.PID, Namespace: child.Namespace, Token: 77}
	stale := activeTaskLink(owner, 10)

	for _, test := range []struct {
		name string
		key  any
		get  func(*Cleanup) *fakeBridgeMap
	}{
		{
			name: "task",
			key:  child,
			get: func(cleanup *Cleanup) *fakeBridgeMap {
				return cleanup.maps.tasks.(*fakeBridgeMap)
			},
		},
		{
			name: "handoff",
			key:  handoff,
			get: func(cleanup *Cleanup) *fakeBridgeMap {
				return cleanup.maps.handoffs.(*fakeBridgeMap)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := testMapHandler(nil, nil, nil)
			cleanup := testCleanup(handler)
			cleanup.ttl = 30 * time.Second
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
			bridgeMap := test.get(cleanup)
			bridgeMap.values[test.key] = stale
			bridgeMap.deleteErr = errors.New("unexpected link deletion")

			require.NoError(t, cleanup.Sweep())
			assert.Equal(t, stale, bridgeMap.values[test.key])
		})
	}
}

func testCleanup(handler *MapHandler) *Cleanup {
	newMap := func() cleanupMap { return &fakeBridgeMap{values: make(map[any]any)} }
	return &Cleanup{
		maps: cleanupMaps{
			remoteParents:  handler.remoteParents.(cleanupMap),
			tasks:          handler.tasks.(cleanupMap),
			virtualThreads: handler.virtualThreads.(cleanupMap),
			vtIdentities:   handler.vtIdentities.(cleanupMap),
			incarnations:   handler.incarnations.(cleanupMap),
			connections:    handler.connections.(cleanupMap),
			ambiguity:      handler.ambiguity.(cleanupMap),
			owners:         handler.owners.(cleanupMap),
			states:         handler.states.(cleanupMap),
			generations:    handler.generations.(cleanupMap),
			terminals:      handler.terminals.(cleanupMap),
			claims:         handler.claims.(cleanupMap),
			handoffs:       newMap(),
			handoffClaims:  newMap(),
			retired:        newMap(),
		},
		ttl:         handler.ttl,
		monoTimeNow: handler.monoTimeNow,
	}
}
