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

func TestCleanupCookieDeleteErrorPreservesConnectionLocator(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)},
		nil,
		nil,
	)
	cleanup := testCleanup(handler)
	connections := cleanup.maps.connections.(*fakeBridgeMap)
	cookieConnections := cleanup.maps.cookieConnections.(*fakeBridgeMap)
	var connectionKey connectionInfoNS
	var connection connectionClaim
	for key, value := range connections.values {
		connectionKey = key.(connectionInfoNS)
		connection = value.(connectionClaim)
	}
	cookieConnections.deleteErr = errors.New("unexpected cookie connection deletion")

	require.Error(t, cleanup.deleteConnectionIndexes(connectionKey, connection))
	assert.Contains(t, connections.values, connectionKey)
	assert.NotEmpty(t, cookieConnections.values)

	cookieConnections.deleteErr = nil
	require.NoError(t, cleanup.deleteConnectionIndexes(connectionKey, connection))
	assert.Empty(t, connections.values)
	assert.Empty(t, cookieConnections.values)
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

func TestCleanupPreservesGenerationObservedDuringEnumeration(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	encoded := validEncodedRecordObservedAt(t, 10, 10*time.Second)
	handler := testMapHandler(map[Identity]any{owner: encoded}, nil, nil)
	cleanup := testCleanup(handler)
	now := 9 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }

	remoteParents := cleanup.maps.remoteParents.(*fakeBridgeMap)
	owners := cleanup.maps.owners.(*fakeBridgeMap)
	states := cleanup.maps.states.(*fakeBridgeMap)
	generations := cleanup.maps.generations.(*fakeBridgeMap)
	connections := cleanup.maps.connections.(*fakeBridgeMap)
	cookieConnections := cleanup.maps.cookieConnections.(*fakeBridgeMap)
	generations.afterIterate = func() {
		now = 11 * time.Second
	}

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, encoded, remoteParents.values[owner])
	assert.Contains(t, owners.values, owner)
	assert.Contains(t, states.values, stateKey{Owner: owner, Generation: 10})
	assert.Contains(t, generations.values, stateKey{Owner: owner, Generation: 10})
	assert.Len(t, connections.values, 1)
	assert.Len(t, cookieConnections.values, 1)

	generations.afterIterate = nil
	now = 41 * time.Second
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{Cleaned: 1}, stats)
	assert.Empty(t, remoteParents.values)
	assert.Empty(t, owners.values)
	assert.Empty(t, states.values)
	assert.Empty(t, generations.values)
	assert.Empty(t, connections.values)
	assert.Empty(t, cookieConnections.values)
}

func TestCleanupPreservesOrphanFallbackObservedDuringEnumeration(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	encoded := validEncodedRecordObservedAt(t, 10, 10*time.Second)
	handler := testMapHandler(nil, nil, nil)
	cleanup := testCleanup(handler)
	now := 9 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }

	remoteParents := cleanup.maps.remoteParents.(*fakeBridgeMap)
	remoteParents.values[owner] = encoded
	remoteParents.afterIterate = func() {
		now = 11 * time.Second
	}

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, encoded, remoteParents.values[owner])
	assert.Empty(t, cleanup.maps.owners.(*fakeBridgeMap).values)

	remoteParents.afterIterate = nil
	now = 41 * time.Second
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{Cleaned: 1}, stats)
	assert.Empty(t, remoteParents.values)
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

func TestCleanupAliasedGenerationDoesNotLookEvicted(t *testing.T) {
	for _, detachOwner := range []bool{false, true} {
		name := "active owner"
		if detachOwner {
			name = "detached owner"
		}
		t.Run(name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			child := Identity{TID: 4, PID: 2, Namespace: 1}
			handler := testMapHandler(
				map[Identity]any{owner: validEncodedRecord(t, 10)},
				map[Identity]any{child: activeTaskLink(owner, 10)},
				nil,
			)
			if detachOwner {
				delete(handler.owners.(*fakeBridgeMap).values, owner)
			}
			delete(handler.remoteParents.(*fakeBridgeMap).values, owner)
			cleanup := testCleanup(handler)

			stats, err := cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Contains(t, cleanup.maps.generations.(*fakeBridgeMap).values, stateKey{
				Owner: owner, Generation: 10,
			})
		})
	}
}

func TestCleanupExpiredPreservedGenerationLeavesReusedOwner(t *testing.T) {
	for _, orphan := range []bool{false, true} {
		indexName := "indexed"
		if orphan {
			indexName = "orphaned index"
		}
		for _, released := range []bool{false, true} {
			aliasName := "live alias"
			if released {
				aliasName = "released alias"
			}
			t.Run(indexName+"/"+aliasName, func(t *testing.T) {
				owner := Identity{TID: 3, PID: 2, Namespace: 1}
				child := Identity{TID: 4, PID: 2, Namespace: 1}
				oldKey := stateKey{Owner: owner, Generation: 10}
				handler := testMapHandler(
					map[Identity]any{owner: validEncodedRecord(t, 10)},
					map[Identity]any{child: activeTaskLink(owner, 10)},
					nil,
				)
				delete(handler.owners.(*fakeBridgeMap).values, owner)
				delete(handler.remoteParents.(*fakeBridgeMap).values, owner)
				if released {
					delete(handler.tasks.(*fakeBridgeMap).values, child)
					state := handler.states.(*fakeBridgeMap).values[oldKey].(stateValue)
					state.Aliases = 0
					handler.states.(*fakeBridgeMap).values[oldKey] = state
				}
				if orphan {
					delete(handler.generations.(*fakeBridgeMap).values, oldKey)
				}

				next := validEncodedRecord(t, 11)
				record, err := UnmarshalRecord(next[:])
				require.NoError(t, err)
				record.ObservedMonotonicNS = uint64(40 * time.Second)
				encoded, err := record.MarshalBinary()
				require.NoError(t, err)
				handler.remoteParents.(*fakeBridgeMap).values[owner] = [RecordSize]byte(encoded)
				seedOwnerState(handler, owner, 11)

				cleanup := testCleanup(handler)
				cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
				stats, err := cleanup.SweepWithStats()
				require.NoError(t, err)
				assert.Equal(t, CleanupStats{Cleaned: 1}, stats)
				assert.NotContains(t, cleanup.maps.states.(*fakeBridgeMap).values, oldKey)
				assert.Contains(t, cleanup.maps.states.(*fakeBridgeMap).values, stateKey{
					Owner: owner, Generation: 11,
				})
				assert.Equal(
					t,
					uint64(11),
					cleanup.maps.owners.(*fakeBridgeMap).values[owner].(ownerValue).Generation,
				)
				var fallback [RecordSize]byte
				require.NoError(t, cleanup.maps.remoteParents.Lookup(&owner, &fallback))
				preserved, err := UnmarshalRecord(fallback[:])
				require.NoError(t, err)
				assert.Equal(t, uint64(11), preserved.Generation)
			})
		}
	}
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
	assert.Empty(t, cleanup.maps.cookieConnections.(*fakeBridgeMap).values)
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
	assert.Empty(t, cleanup.maps.cookieConnections.(*fakeBridgeMap).values)

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
			remoteParents:                  handler.remoteParents.(cleanupMap),
			tasks:                          handler.tasks.(cleanupMap),
			virtualThreads:                 handler.virtualThreads.(cleanupMap),
			vtIdentities:                   handler.vtIdentities.(cleanupMap),
			incarnations:                   handler.incarnations.(cleanupMap),
			connections:                    handler.connections.(cleanupMap),
			cookieConnections:              handler.cookieConnections.(cleanupMap),
			ambiguity:                      handler.ambiguity.(cleanupMap),
			owners:                         handler.owners.(cleanupMap),
			states:                         handler.states.(cleanupMap),
			generations:                    handler.generations.(cleanupMap),
			terminals:                      handler.terminals.(cleanupMap),
			claims:                         handler.claims.(cleanupMap),
			handoffs:                       newMap(),
			handoffClaims:                  newMap(),
			retired:                        newMap(),
			sslPrewrite:                    newMap(),
			sslPrewriteConnectionAmbiguity: newMap(),
			sslPrewriteConnectionClaims:    newMap(),
			sslPrewriteConnectionOwners:    newMap(),
		},
		ttl:         handler.ttl,
		monoTimeNow: handler.monoTimeNow,
	}
}

func validEncodedRecordObservedAt(
	t *testing.T,
	generation uint64,
	observed time.Duration,
) [RecordSize]byte {
	t.Helper()
	encoded := validEncodedRecord(t, generation)
	record, err := UnmarshalRecord(encoded[:])
	require.NoError(t, err)
	record.ObservedMonotonicNS = uint64(observed)
	updated, err := record.MarshalBinary()
	require.NoError(t, err)
	copy(encoded[:], updated)
	return encoded
}
