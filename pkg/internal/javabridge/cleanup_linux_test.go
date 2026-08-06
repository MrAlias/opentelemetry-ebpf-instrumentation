// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javabridge

import (
	"errors"
	"maps"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCleanupKernelMapLayouts(t *testing.T) {
	assert.Equal(t, uintptr(16), unsafe.Sizeof(handoffKey{}))
	assert.Equal(t, uintptr(16), unsafe.Sizeof(handoffClaimValue{}))
	assert.Equal(t, uintptr(24), unsafe.Sizeof(retiredProcessKey{}))
	assert.Equal(t, uintptr(24), unsafe.Sizeof(generationClaim{}))
	assert.Equal(t, uintptr(23), unsafe.Offsetof(generationClaim{}.Reserved)+6)
	assert.Equal(t, uint8(0x47), generationGoProducerTag)
}

func taggedGoGenerationClaim(
	lifecycle uint8,
	observedMonotonicNS uint64,
	processIncarnation uint64,
) generationClaim {
	return generationClaim{
		ObservedMonotonicNS: observedMonotonicNS,
		ProcessIncarnation:  processIncarnation,
		Lifecycle:           lifecycle,
		Reserved:            [7]byte{6: generationGoProducerTag},
	}
}

func generationRecoveryCleanup(t *testing.T) *Cleanup {
	t.Helper()
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 100 * time.Second }
	resetGenerationRecoverySweep(cleanup)
	return cleanup
}

func resetGenerationRecoverySweep(cleanup *Cleanup) {
	cleanup.currentSweepClaims = make(map[stateKey]generationClaim)
	cleanup.currentSweepGuards = make(map[Identity]generationClaim)
	cleanup.currentSweepAmbiguities = make(map[stateKey]uint64)
}

func TestGenerationGoProducerTagAndHandoffValidation(t *testing.T) {
	for _, lifecycle := range []uint8{
		lifecycleConsumed,
		lifecycleDiscarded,
		lifecycleStale,
		lifecycleAmbiguous,
		lifecyclePublishing,
	} {
		producer := taggedGoGenerationClaim(lifecycle, 10, testProcessIncarnation)
		require.True(t, validGenerationProducerClaim(producer))
		cleanup, err := generationProducerHandoffValue(producer, 9)
		require.NoError(t, err)
		assert.Equal(t, uint64(11), cleanup.ObservedMonotonicNS)
		assert.Equal(t, testProcessIncarnation, cleanup.ProcessIncarnation)
		assert.Equal(t, lifecycleCleanup, cleanup.Lifecycle)
		assert.Equal(t, [7]byte{lifecycle}, cleanup.Reserved)
	}

	valid := taggedGoGenerationClaim(lifecycleConsumed, 10, testProcessIncarnation)
	for _, test := range []struct {
		name   string
		mutate func(*generationClaim)
	}{
		{name: "untagged", mutate: func(claim *generationClaim) { claim.Reserved = [7]byte{} }},
		{name: "wrong tag", mutate: func(claim *generationClaim) { claim.Reserved[6]++ }},
		{name: "extra metadata", mutate: func(claim *generationClaim) { claim.Reserved[1] = 1 }},
		{name: "active lifecycle", mutate: func(claim *generationClaim) { claim.Lifecycle = lifecycleActive }},
		{name: "cleanup lifecycle", mutate: func(claim *generationClaim) { claim.Lifecycle = lifecycleCleanup }},
		{name: "zero timestamp", mutate: func(claim *generationClaim) { claim.ObservedMonotonicNS = 0 }},
		{name: "zero incarnation", mutate: func(claim *generationClaim) { claim.ProcessIncarnation = 0 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			claim := valid
			test.mutate(&claim)
			assert.False(t, validGenerationProducerClaim(claim))
			_, err := generationProducerHandoffValue(claim, 20)
			require.Error(t, err)
		})
	}

	saturated := valid
	saturated.ObservedMonotonicNS = ^uint64(0)
	_, err := generationProducerHandoffValue(saturated, 100*time.Second)
	require.Error(t, err)
	_, err = generationProducerHandoffValue(valid, -1)
	require.Error(t, err)
}

func TestMapHandlerTaggedProducerClaimStatusParity(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	for _, test := range []struct {
		name      string
		lifecycle uint8
		status    Status
	}{
		{name: "publishing", lifecycle: lifecyclePublishing, status: StatusOverload},
		{name: "ambiguous", lifecycle: lifecycleAmbiguous, status: StatusAmbiguous},
		{name: "consumed", lifecycle: lifecycleConsumed, status: StatusAlreadyConsumed},
		{name: "discarded", lifecycle: lifecycleDiscarded, status: StatusAlreadyConsumed},
		{name: "stale", lifecycle: lifecycleStale, status: StatusAlreadyConsumed},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := testMapHandler(
				map[Identity]any{owner: validEncodedRecord(t, key.Generation)}, nil, nil,
			)
			claim := taggedGoGenerationClaim(
				test.lifecycle, uint64(10*time.Second), testProcessIncarnation,
			)
			handler.claims.(*fakeBridgeMap).values[key] = claim

			result := handler.Handle(owner, OperationTake)
			assert.Equal(t, test.status, result.Status)
			assert.Equal(t, claim, handler.claims.(*fakeBridgeMap).values[key])
			assert.Contains(t, handler.remoteParents.(*fakeBridgeMap).values, owner)
		})
	}
}

func TestCleanupRecoversTaggedGoGenerationHandoffShapes(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	producerClaim := taggedGoGenerationClaim(
		lifecycleConsumed, uint64(10*time.Second), testProcessIncarnation,
	)
	producerGuard := taggedGoGenerationClaim(
		lifecyclePublishing, uint64(11*time.Second), key.Generation,
	)
	cleanupClaim := generationClaim{
		ObservedMonotonicNS: uint64(20 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecycleConsumed},
	}
	cleanupGuard := generationClaim{
		ObservedMonotonicNS: uint64(21 * time.Second),
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecyclePublishing},
	}

	for _, test := range []struct {
		name          string
		claim         *generationClaim
		guard         *generationClaim
		markerPresent bool
		marker        uint64
		wantOrder     []string
	}{
		{
			name:  "tagged E only publishes G before E",
			claim: &producerClaim, markerPresent: true,
			wantOrder: []string{"G", "E"},
		},
		{
			name:  "tagged E and tagged G convert E before G",
			claim: &producerClaim, guard: &producerGuard,
			markerPresent: true, marker: uint64(12 * time.Second),
			wantOrder: []string{"E", "G"},
		},
		{
			name:  "cleanup E permits tagged G tail",
			claim: &cleanupClaim, guard: &producerGuard,
			wantOrder: []string{"G"},
		},
		{
			name:  "cleanup G permits tagged E tail",
			claim: &producerClaim, guard: &cleanupGuard,
			markerPresent: true, marker: uint64(12 * time.Second),
			wantOrder: []string{"E"},
		},
		{
			name:      "tagged G alone becomes a cleanup tail",
			guard:     &producerGuard,
			wantOrder: []string{"G"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cleanup := generationRecoveryCleanup(t)
			claims := cleanup.maps.claims.(*fakeBridgeMap)
			guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
			markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
			if test.claim != nil {
				claims.values[key] = *test.claim
			}
			if test.guard != nil {
				guards.values[owner] = *test.guard
			}
			if test.markerPresent {
				markers.values[key] = test.marker
			}
			var order []string
			claims.afterUpdate = func(any, any) { order = append(order, "E") }
			guards.afterUpdate = func(any, any) { order = append(order, "G") }

			require.NoError(t, cleanup.recoverGoGenerationProducerHandoffs())
			assert.Equal(t, test.wantOrder, order)
			if test.claim == nil {
				assert.NotContains(t, claims.values, key)
			} else {
				got := claims.values[key].(generationClaim)
				if validGenerationProducerClaim(*test.claim) {
					assert.True(t, validGenerationCleanupClaim(got))
					assert.Equal(t, test.claim.Lifecycle, got.Reserved[0])
					assert.Greater(t, got.ObservedMonotonicNS, test.claim.ObservedMonotonicNS)
				} else {
					assert.Equal(t, *test.claim, got)
				}
			}
			gotGuard := guards.values[owner].(generationClaim)
			assert.True(t, validGenerationCleanupGuard(owner, gotGuard))
			assert.Equal(t, key.Generation, gotGuard.ProcessIncarnation)
			if test.guard != nil && validGenerationProducerClaim(*test.guard) {
				assert.Greater(t, gotGuard.ObservedMonotonicNS, test.guard.ObservedMonotonicNS)
			}
			if test.markerPresent {
				assert.Equal(t, test.marker, markers.values[key])
			} else {
				assert.NotContains(t, markers.values, key)
			}
		})
	}
}

func TestCleanupNeverAdoptsUntaggedGenerationProducers(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	markers := []struct {
		name    string
		present bool
		value   uint64
	}{
		{name: "absent"},
		{name: "reserved", present: true},
		{name: "promoted", present: true, value: uint64(time.Second)},
	}
	for _, producer := range []struct {
		name      string
		lifecycle uint8
	}{
		{name: "consumed", lifecycle: lifecycleConsumed},
		{name: "discarded", lifecycle: lifecycleDiscarded},
		{name: "stale", lifecycle: lifecycleStale},
		{name: "ambiguous", lifecycle: lifecycleAmbiguous},
		{name: "publishing", lifecycle: lifecyclePublishing},
	} {
		for _, marker := range markers {
			t.Run(marker.name+"-"+producer.name, func(t *testing.T) {
				cleanup := generationRecoveryCleanup(t)
				claims := cleanup.maps.claims.(*fakeBridgeMap)
				guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
				ambiguity := cleanup.maps.ambiguity.(*fakeBridgeMap)
				claim := generationClaim{
					ObservedMonotonicNS: 1,
					ProcessIncarnation:  testProcessIncarnation,
					Lifecycle:           producer.lifecycle,
				}
				guard := generationClaim{
					ObservedMonotonicNS: 1,
					ProcessIncarnation:  key.Generation,
					Lifecycle:           lifecyclePublishing,
				}
				claims.values[key] = claim
				guards.values[owner] = guard
				if marker.present {
					ambiguity.values[key] = marker.value
				}

				require.NoError(t, cleanup.recoverGoGenerationProducerHandoffs())
				assert.Equal(t, claim, claims.values[key])
				assert.Equal(t, guard, guards.values[owner])
				assert.Zero(t, claims.updateCount)
				assert.Zero(t, guards.updateCount)
				if marker.present {
					assert.Equal(t, marker.value, ambiguity.values[key])
				} else {
					assert.NotContains(t, ambiguity.values, key)
				}
			})
		}
	}
}

func TestCleanupTaggedGenerationRecoveryRequiresCompleteFenceSnapshots(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	producerClaim := taggedGoGenerationClaim(
		lifecycleConsumed, uint64(10*time.Second), testProcessIncarnation,
	)
	producerGuard := taggedGoGenerationClaim(
		lifecyclePublishing, uint64(11*time.Second), key.Generation,
	)
	injected := errors.New("injected generation fence iteration failure")
	for _, target := range []string{"claims", "guards"} {
		t.Run(target, func(t *testing.T) {
			cleanup := generationRecoveryCleanup(t)
			claims := cleanup.maps.claims.(*fakeBridgeMap)
			guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
			claims.values[key] = producerClaim
			guards.values[owner] = producerGuard
			if target == "claims" {
				claims.iterateErr = injected
			} else {
				guards.iterateErr = injected
			}

			err := cleanup.recoverGoGenerationProducerHandoffs()
			require.ErrorIs(t, err, injected)
			assert.Equal(t, producerClaim, claims.values[key])
			assert.Equal(t, producerGuard, guards.values[owner])
			assert.Zero(t, claims.updateCount)
			assert.Zero(t, guards.updateCount)
		})
	}
}

func TestCleanupForeignGenerationGuardBlocksTaggedClaim(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	producerClaim := taggedGoGenerationClaim(
		lifecycleConsumed, uint64(10*time.Second), testProcessIncarnation,
	)
	foreignGuard := generationClaim{
		ObservedMonotonicNS: uint64(11 * time.Second),
		ProcessIncarnation:  key.Generation + 1,
		Lifecycle:           lifecyclePublishing,
	}
	cleanup := generationRecoveryCleanup(t)
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
	claims.values[key] = producerClaim
	guards.values[owner] = foreignGuard

	require.NoError(t, cleanup.recoverGoGenerationProducerHandoffs())
	assert.Equal(t, producerClaim, claims.values[key])
	assert.Equal(t, foreignGuard, guards.values[owner])
	assert.Zero(t, claims.updateCount)
	assert.Zero(t, guards.updateCount)
}

func TestCleanupTaggedGenerationGuardRequiresAbsentOrCleanupClaim(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	producerGuard := taggedGoGenerationClaim(lifecyclePublishing, 10, key.Generation)
	for _, test := range []struct {
		name  string
		claim generationClaim
	}{
		{
			name: "tagged producer",
			claim: taggedGoGenerationClaim(
				lifecycleConsumed, 10, testProcessIncarnation,
			),
		},
		{
			name: "untagged producer",
			claim: generationClaim{
				ObservedMonotonicNS: 10,
				ProcessIncarnation:  testProcessIncarnation,
				Lifecycle:           lifecycleConsumed,
			},
		},
		{
			name: "malformed producer tag",
			claim: generationClaim{
				ObservedMonotonicNS: 10,
				ProcessIncarnation:  testProcessIncarnation,
				Lifecycle:           lifecycleConsumed,
				Reserved:            [7]byte{1: 1, 6: generationGoProducerTag},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cleanup := generationRecoveryCleanup(t)
			claims := cleanup.maps.claims.(*fakeBridgeMap)
			guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
			claims.values[key] = test.claim
			guards.values[owner] = producerGuard

			require.NoError(t, cleanup.recoverGoGenerationProducerGuardTail(key, producerGuard))
			assert.Equal(t, test.claim, claims.values[key])
			assert.Equal(t, producerGuard, guards.values[owner])
			assert.Zero(t, guards.updateCount)
		})
	}
}

func TestCleanupRetriesFailedTaggedGenerationHandoffsOnLaterSweep(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	producerClaim := taggedGoGenerationClaim(
		lifecycleConsumed, uint64(10*time.Second), testProcessIncarnation,
	)
	producerGuard := taggedGoGenerationClaim(
		lifecyclePublishing, uint64(11*time.Second), key.Generation,
	)
	injected := errors.New("injected producer handoff failure")

	t.Run("claim", func(t *testing.T) {
		cleanup := generationRecoveryCleanup(t)
		claims := cleanup.maps.claims.(*fakeBridgeMap)
		guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
		claims.values[key] = producerClaim
		claims.updateErr = injected

		err := cleanup.recoverGoGenerationProducerHandoffs()
		require.ErrorIs(t, err, injected)
		assert.Equal(t, producerClaim, claims.values[key])
		assert.True(t, validGenerationCleanupGuard(owner, guards.values[owner].(generationClaim)))
		assert.Equal(t, 1, claims.updateCount)

		claims.updateErr = nil
		resetGenerationRecoverySweep(cleanup)
		require.NoError(t, cleanup.recoverGoGenerationProducerHandoffs())
		assert.True(t, validGenerationCleanupClaim(claims.values[key].(generationClaim)))
		assert.Equal(t, 2, claims.updateCount)
	})

	t.Run("guard", func(t *testing.T) {
		cleanup := generationRecoveryCleanup(t)
		claims := cleanup.maps.claims.(*fakeBridgeMap)
		guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
		claims.values[key] = producerClaim
		guards.values[owner] = producerGuard
		guards.updateErr = injected

		err := cleanup.recoverGoGenerationProducerHandoffs()
		require.ErrorIs(t, err, injected)
		assert.True(t, validGenerationCleanupClaim(claims.values[key].(generationClaim)))
		assert.Equal(t, producerGuard, guards.values[owner])
		assert.Equal(t, 1, guards.updateCount)

		guards.updateErr = nil
		resetGenerationRecoverySweep(cleanup)
		require.NoError(t, cleanup.recoverGoGenerationProducerHandoffs())
		assert.True(t, validGenerationCleanupGuard(owner, guards.values[owner].(generationClaim)))
		assert.Equal(t, 2, guards.updateCount)
	})
}

func TestCleanupTaggedGenerationRecoveryPreservesSuccessors(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	producerClaim := taggedGoGenerationClaim(lifecycleConsumed, 10, testProcessIncarnation)
	producerGuard := taggedGoGenerationClaim(lifecyclePublishing, 11, key.Generation)

	t.Run("claim", func(t *testing.T) {
		for _, successor := range []generationClaim{
			producerClaim,
			{
				ObservedMonotonicNS: 12,
				ProcessIncarnation:  testProcessIncarnation + 1,
				Lifecycle:           lifecycleConsumed,
			},
		} {
			cleanup := generationRecoveryCleanup(t)
			claims := cleanup.maps.claims.(*fakeBridgeMap)
			guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
			claims.values[key] = producerClaim
			guards.values[owner] = producerGuard
			claims.afterUpdate = func(updatedKey, _ any) {
				claims.mu.Lock()
				claims.values[updatedKey] = successor
				claims.mu.Unlock()
			}

			require.NoError(t, cleanup.recoverGoGenerationProducerHandoffs())
			assert.Equal(t, successor, claims.values[key])
			assert.Equal(t, producerGuard, guards.values[owner])
			assert.Equal(t, 1, claims.updateCount)
			assert.Zero(t, guards.updateCount)
		}
	})

	t.Run("guard", func(t *testing.T) {
		cleanup := generationRecoveryCleanup(t)
		claims := cleanup.maps.claims.(*fakeBridgeMap)
		guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
		claims.values[key] = producerClaim
		guards.values[owner] = producerGuard
		guards.afterUpdate = func(updatedKey, _ any) {
			guards.mu.Lock()
			guards.values[updatedKey] = producerGuard
			guards.mu.Unlock()
		}

		require.NoError(t, cleanup.recoverGoGenerationProducerHandoffs())
		assert.True(t, validGenerationCleanupClaim(claims.values[key].(generationClaim)))
		assert.Equal(t, producerGuard, guards.values[owner])
		assert.Equal(t, 1, guards.updateCount)
	})
}

func TestCleanupTaggedGenerationRecoveryRejectsSaturatedTimestamp(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	producer := taggedGoGenerationClaim(
		lifecycleConsumed, ^uint64(0), testProcessIncarnation,
	)
	cleanup := generationRecoveryCleanup(t)
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
	claims.values[key] = producer

	require.Error(t, cleanup.recoverGoGenerationProducerHandoffs())
	assert.Equal(t, producer, claims.values[key])
	assert.NotContains(t, guards.values, owner)
	assert.Zero(t, claims.updateCount)
	assert.Zero(t, guards.updateCount)

	t.Run("guard tail", func(t *testing.T) {
		cleanup := generationRecoveryCleanup(t)
		claims := cleanup.maps.claims.(*fakeBridgeMap)
		guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
		guard := taggedGoGenerationClaim(
			lifecyclePublishing, ^uint64(0), key.Generation,
		)
		guards.values[owner] = guard

		require.Error(t, cleanup.recoverGoGenerationProducerHandoffs())
		assert.Empty(t, claims.values)
		assert.Equal(t, guard, guards.values[owner])
		assert.Zero(t, guards.updateCount)
	})

	t.Run("claim and guard pair", func(t *testing.T) {
		cleanup := generationRecoveryCleanup(t)
		claims := cleanup.maps.claims.(*fakeBridgeMap)
		guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
		claim := taggedGoGenerationClaim(
			lifecycleConsumed, uint64(10*time.Second), testProcessIncarnation,
		)
		guard := taggedGoGenerationClaim(
			lifecyclePublishing, ^uint64(0), key.Generation,
		)
		claims.values[key] = claim
		guards.values[owner] = guard

		require.Error(t, cleanup.recoverGoGenerationProducerHandoffs())
		assert.Equal(t, claim, claims.values[key])
		assert.Equal(t, guard, guards.values[owner])
		assert.Zero(t, claims.updateCount)
		assert.Zero(t, guards.updateCount)
	})
}

func TestCleanupTaggedGenerationRecoveryAgesBeforePayloadMutation(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, key.Generation)}, nil, nil,
	)
	cleanup := testCleanup(handler)
	cleanup.ttl = time.Second
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	cleanup.maps.claims.(*fakeBridgeMap).values[key] = taggedGoGenerationClaim(
		lifecycleConsumed, uint64(10*time.Second), testProcessIncarnation,
	)
	cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner] = taggedGoGenerationClaim(
		lifecyclePublishing, uint64(11*time.Second), key.Generation,
	)
	cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(12 * time.Second)

	parentsBefore := maps.Clone(cleanup.maps.remoteParents.(*fakeBridgeMap).values)
	statesBefore := maps.Clone(cleanup.maps.states.(*fakeBridgeMap).values)
	generationsBefore := maps.Clone(cleanup.maps.generations.(*fakeBridgeMap).values)
	connectionsBefore := maps.Clone(cleanup.maps.connections.(*fakeBridgeMap).values)
	cookiesBefore := maps.Clone(cleanup.maps.cookieConnections.(*fakeBridgeMap).values)
	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, parentsBefore, cleanup.maps.remoteParents.(*fakeBridgeMap).values)
	assert.Equal(t, statesBefore, cleanup.maps.states.(*fakeBridgeMap).values)
	assert.Equal(t, generationsBefore, cleanup.maps.generations.(*fakeBridgeMap).values)
	assert.Equal(t, connectionsBefore, cleanup.maps.connections.(*fakeBridgeMap).values)
	assert.Equal(t, cookiesBefore, cleanup.maps.cookieConnections.(*fakeBridgeMap).values)
	assert.True(t, validGenerationCleanupClaim(
		cleanup.maps.claims.(*fakeBridgeMap).values[key].(generationClaim),
	))
	assert.True(t, validGenerationCleanupGuard(
		owner, cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner].(generationClaim),
	))

	now = 43 * time.Second
	var total CleanupStats
	for range 4 {
		stats, err = cleanup.SweepWithStats()
		require.NoError(t, err)
		total.Cleaned += stats.Cleaned
		total.Evicted += stats.Evicted
	}
	assert.Equal(t, CleanupStats{Cleaned: 1}, total)
	assert.NotContains(t, cleanup.maps.remoteParents.(*fakeBridgeMap).values, owner)
	assert.NotContains(t, cleanup.maps.states.(*fakeBridgeMap).values, key)
	assert.NotContains(t, cleanup.maps.generations.(*fakeBridgeMap).values, key)
	assert.NotContains(t, cleanup.maps.claims.(*fakeBridgeMap).values, key)
	assert.NotContains(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values, owner)
	assert.NotContains(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values, key)
}

func TestNewCleanupRejectsNilGenerationCoordinator(t *testing.T) {
	assert.PanicsWithValue(t, "nil Java generation coordinator", func() {
		NewCleanup(Maps{}, time.Second, nil)
	})
}

func TestCleanupRejectsMissingGenerationCoordinator(t *testing.T) {
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.coordinator = nil

	stats, err := cleanup.SweepWithStats()
	require.Error(t, err)
	assert.Equal(t, CleanupStats{}, stats)
}

func TestCleanupSweepSerializesWithRealMapHandlerRequest(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)}, nil, nil,
	)
	cleanup := testCleanup(handler)
	enteredHandler := make(chan struct{})
	releaseHandler := make(chan struct{})
	var releaseHandlerOnce sync.Once
	t.Cleanup(func() { releaseHandlerOnce.Do(func() { close(releaseHandler) }) })
	handler.remoteParents.(*fakeBridgeMap).afterLookup = func(count int) {
		if count != 1 {
			return
		}
		close(enteredHandler)
		<-releaseHandler
	}
	handlerResult := make(chan Record, 1)
	go func() {
		handlerResult <- handler.Handle(owner, OperationTake)
	}()
	select {
	case <-enteredHandler:
	case <-time.After(time.Second):
		t.Fatal("handler did not enter its coordinated lookup")
	}

	cleanupStarted := make(chan struct{})
	sweepEntered := make(chan struct{})
	var sweepEnteredOnce sync.Once
	cleanup.maps.generations.(*fakeBridgeMap).afterIterate = func() {
		sweepEnteredOnce.Do(func() { close(sweepEntered) })
	}
	cleanupResult := make(chan error, 1)
	go func() {
		close(cleanupStarted)
		cleanupResult <- cleanup.Sweep()
	}()
	select {
	case <-cleanupStarted:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not start")
	}
	require.Eventually(t, func() bool {
		unlock, locked := handler.coordinator.tryLockHandler()
		if locked {
			unlock()
		}
		return !locked
	}, time.Second, time.Millisecond, "cleanup did not queue for the coordinator")
	select {
	case <-sweepEntered:
		t.Fatal("cleanup entered the generation sweep while the handler was active")
	default:
	}

	releaseHandlerOnce.Do(func() { close(releaseHandler) })
	select {
	case result := <-handlerResult:
		assert.Equal(t, StatusValid, result.Status)
	case <-time.After(time.Second):
		t.Fatal("handler did not finish after release")
	}
	select {
	case err := <-cleanupResult:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("cleanup did not finish after the handler")
	}
	assert.NotContains(t, cleanup.maps.states.(*fakeBridgeMap).values,
		stateKey{Owner: owner, Generation: 10})
}

func TestCleanupSSLPrewriteSweepDoesNotBlockMapHandler(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)}, nil, nil,
	)
	cleanup := testCleanup(handler)
	enteredSSL := make(chan struct{})
	releaseSSL := make(chan struct{})
	var enteredSSLOnce sync.Once
	var releaseSSLOnce sync.Once
	t.Cleanup(func() { releaseSSLOnce.Do(func() { close(releaseSSL) }) })
	cleanup.maps.sslPrewriteConnectionClaims.(*fakeBridgeMap).afterIterate = func() {
		enteredSSLOnce.Do(func() { close(enteredSSL) })
		<-releaseSSL
	}

	cleanupResult := make(chan error, 1)
	go func() { cleanupResult <- cleanup.Sweep() }()
	select {
	case <-enteredSSL:
	case <-time.After(time.Second):
		t.Fatal("cleanup did not enter the SSL-prewrite sweep")
	}

	handlerResult := make(chan Record, 1)
	go func() { handlerResult <- handler.Handle(owner, OperationTake) }()
	select {
	case result := <-handlerResult:
		assert.Equal(t, StatusValid, result.Status)
	case <-time.After(time.Second):
		t.Fatal("handler blocked during unrelated SSL-prewrite cleanup")
	}

	releaseSSLOnce.Do(func() { close(releaseSSL) })
	select {
	case err := <-cleanupResult:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("cleanup did not finish after SSL-prewrite release")
	}
}

func TestCleanupCookieDeleteErrorPreservesConnectionLocator(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)}, nil, nil,
	)
	cleanup := testCleanup(handler)
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	key := stateKey{Owner: owner, Generation: 10}
	ownership := seedAgedGenerationCleanupFence(
		t, cleanup, key, testProcessIncarnation,
	)
	connections := cleanup.maps.connections.(*fakeBridgeMap)
	cookieConnections := cleanup.maps.cookieConnections.(*fakeBridgeMap)
	var connectionKey connectionInfoNS
	var connection connectionClaim
	for mapKey, value := range connections.values {
		connectionKey = mapKey.(connectionInfoNS)
		connection = value.(connectionClaim)
	}
	cookieConnections.deleteErr = errors.New("injected cookie connection deletion failure")

	deleted, err := cleanup.deleteConnectionIndexesWithOwnership(
		ownership, connectionKey, connection,
	)
	require.Error(t, err)
	assert.False(t, deleted)
	assert.Contains(t, connections.values, connectionKey)
	assert.NotEmpty(t, cookieConnections.values)

	cookieConnections.deleteErr = nil
	deleted, err = cleanup.deleteConnectionIndexesWithOwnership(
		ownership, connectionKey, connection,
	)
	require.NoError(t, err)
	assert.True(t, deleted)
	assert.Empty(t, connections.values)
	assert.Empty(t, cookieConnections.values)
}

func TestCleanupDeleteExactPreservesReplacementBeforeFinalRead(t *testing.T) {
	const key = uint64(1)
	const expected = uint64(10)
	const replacement = uint64(11)
	m := &fakeBridgeMap{values: map[any]any{key: expected}}
	m.afterLookup = func(count int) {
		if count != 1 {
			return
		}
		m.mu.Lock()
		m.values[key] = replacement
		m.mu.Unlock()
	}

	deleted, err := cleanupDeleteExact[uint64, uint64](m, key, expected)
	require.NoError(t, err)
	assert.False(t, deleted)
	assert.Equal(t, replacement, m.values[key])
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

	key := stateKey{Owner: owner, Generation: 10}
	stats := sweepSeededGenerationToCompletion(
		t, cleanup, key, testProcessIncarnation,
	)
	assert.Equal(t, CleanupStats{Cleaned: 1}, stats)

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
}

func TestCleanupPreservesLiveGenerationReservation(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)}, nil, nil,
	)
	cleanup := testCleanup(handler)
	key := stateKey{Owner: owner, Generation: 10}

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, uint64(0), cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
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
	stats = sweepSeededGenerationToCompletion(
		t, cleanup, stateKey{Owner: owner, Generation: 10}, testProcessIncarnation,
	)
	assert.Equal(t, CleanupStats{Cleaned: 1}, stats)
	assert.Empty(t, remoteParents.values)
	assert.Empty(t, owners.values)
	assert.Empty(t, states.values)
	assert.Empty(t, generations.values)
	assert.Empty(t, connections.values)
	assert.Empty(t, cookieConnections.values)
}

func TestCleanupPreservesOwnerlessFallbackWithoutIncarnationAuthority(t *testing.T) {
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
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, encoded, remoteParents.values[owner])
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
			now := 11 * time.Second
			cleanup.monoTimeNow = func() time.Duration { return now }

			stats, err := cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{Evicted: 1}, stats)
			assert.NotEmpty(t, cleanup.maps.generations.(*fakeBridgeMap).values)

			now = 42 * time.Second
			stats, err = cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			stats, err = cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{Cleaned: 1}, stats)
			assert.Empty(t, cleanup.maps.generations.(*fakeBridgeMap).values)
		})
	}
}

func TestCleanupStatsRejectMalformedFallbackEvictionGraph(t *testing.T) {
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
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			handler := testMapHandler(
				map[Identity]any{owner: validEncodedRecord(t, key.Generation)}, nil, nil,
			)
			delete(handler.remoteParents.(*fakeBridgeMap).values, owner)
			state := handler.states.(*fakeBridgeMap).values[key].(stateValue)
			test.mutate(&state)
			handler.states.(*fakeBridgeMap).values[key] = state
			clear(handler.connections.(*fakeBridgeMap).values)
			clear(handler.cookieConnections.(*fakeBridgeMap).values)
			seedConnectionClaim(handler, connectionInfoNS{
				Connection: state.Connection,
				NetNS:      state.ConnectionNetNS,
			}, owner, key.Generation)
			cleanup := testCleanup(handler)
			cleanup.monoTimeNow = func() time.Duration { return 11 * time.Second }

			stats, err := cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Contains(t, cleanup.maps.generations.(*fakeBridgeMap).values, key)
			assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
			assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
			assert.Equal(t, uint64(0),
				cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
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

	stats := sweepSeededGenerationToCompletion(
		t, cleanup, stateKey{Owner: owner, Generation: 10}, testProcessIncarnation,
	)
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
				stats := sweepSeededGenerationToCompletion(
					t, cleanup, oldKey, testProcessIncarnation,
				)
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
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }

	stats := sweepSeededGenerationToCompletion(
		t, cleanup, stateKey{Owner: owner, Generation: 10}, testProcessIncarnation,
	)
	assert.Equal(t, CleanupStats{Cleaned: 1}, stats)
}

func TestCleanupMalformedArtifactsWithoutIncarnationConverge(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	for _, test := range []struct {
		name    string
		seed    func(*MapHandler)
		present func(*MapHandler) bool
	}{
		{
			name: "generation index",
			seed: func(handler *MapHandler) {
				handler.generations.(*fakeBridgeMap).values[key] = generationIndexValue{
					Process:             javaProcessIdentity(owner),
					ObservedMonotonicNS: uint64(10 * time.Second),
				}
			},
			present: func(handler *MapHandler) bool {
				_, ok := handler.generations.(*fakeBridgeMap).values[key]
				return ok
			},
		},
		{
			name: "state",
			seed: func(handler *MapHandler) {
				handler.states.(*fakeBridgeMap).values[key] = stateValue{
					Lifecycle:           lifecycleActive,
					ObservedMonotonicNS: uint64(10 * time.Second),
					Connection: connectionInfo{
						SourcePort: 3, DestinationPort: 10,
					},
					ConnectionNetNS: owner.Namespace,
					Response: validEncodedRecordObservedAt(
						t, key.Generation, 10*time.Second,
					),
				}
			},
			present: func(handler *MapHandler) bool {
				_, ok := handler.states.(*fakeBridgeMap).values[key]
				return ok
			},
		},
		{
			name: "owner",
			seed: func(handler *MapHandler) {
				handler.owners.(*fakeBridgeMap).values[owner] = ownerValue{
					Generation: key.Generation,
					Lifecycle:  lifecycleActive,
				}
			},
			present: func(handler *MapHandler) bool {
				_, ok := handler.owners.(*fakeBridgeMap).values[owner]
				return ok
			},
		},
		{
			name: "terminal",
			seed: func(handler *MapHandler) {
				handler.terminals.(*fakeBridgeMap).values[owner] = terminalValue{
					Generation:          key.Generation,
					ObservedMonotonicNS: uint64(10 * time.Second),
					Lifecycle:           lifecycleConsumed,
				}
			},
			present: func(handler *MapHandler) bool {
				_, ok := handler.terminals.(*fakeBridgeMap).values[owner]
				return ok
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := testMapHandler(nil, nil, nil)
			test.seed(handler)
			cleanup := testCleanup(handler)
			now := 41 * time.Second
			cleanup.monoTimeNow = func() time.Duration { return now }

			stats, err := cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.True(t, test.present(handler))
			claim, ok := cleanup.maps.claims.(*fakeBridgeMap).values[key].(generationClaim)
			require.True(t, ok)
			assert.Equal(t, key.Generation, claim.ProcessIncarnation)
			assert.Equal(t, lifecycleCleanup, claim.Lifecycle)
			assert.Equal(t, lifecycleStale, claim.Reserved[0])

			now = 72*time.Second + time.Nanosecond
			stats, err = cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{Cleaned: 1}, stats)
			assert.False(t, test.present(handler))
			assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
			assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
			assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
		})
	}
}

func TestCleanupNoncanonicalLogicalKeysAreExactOnly(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	canonicalKey := stateKey{Owner: owner, Generation: 10}
	canonicalIndex := generationIndexValue{
		Process:             javaProcessIdentity(owner),
		ProcessIncarnation:  testProcessIncarnation,
		ObservedMonotonicNS: uint64(10 * time.Second),
	}
	canonicalState := stateValue{
		Lifecycle:           lifecycleActive,
		ObservedMonotonicNS: uint64(10 * time.Second),
		Connection: connectionInfo{
			SourcePort: 3, DestinationPort: 10,
		},
		ConnectionNetNS:    owner.Namespace,
		ProcessIncarnation: testProcessIncarnation,
		Response: validEncodedRecordObservedAt(
			t, canonicalKey.Generation, 10*time.Second,
		),
	}
	for _, malformedKey := range []stateKey{
		{Owner: owner},
		{Owner: owner, Reserved: 1, Generation: canonicalKey.Generation},
	} {
		name := "zero generation"
		if malformedKey.Reserved != 0 {
			name = "reserved key"
		}
		t.Run(name, func(t *testing.T) {
			handler := testMapHandler(nil, nil, nil)
			handler.generations.(*fakeBridgeMap).values[canonicalKey] = canonicalIndex
			handler.states.(*fakeBridgeMap).values[canonicalKey] = canonicalState
			handler.generations.(*fakeBridgeMap).values[malformedKey] = generationIndexValue{}
			handler.states.(*fakeBridgeMap).values[malformedKey] = stateValue{}
			cleanup := testCleanup(handler)
			cleanup.monoTimeNow = func() time.Duration { return 11 * time.Second }

			stats, err := cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{Cleaned: 1}, stats)
			assert.NotContains(t, cleanup.maps.generations.(*fakeBridgeMap).values, malformedKey)
			assert.NotContains(t, cleanup.maps.states.(*fakeBridgeMap).values, malformedKey)
			assert.Equal(t, canonicalIndex,
				cleanup.maps.generations.(*fakeBridgeMap).values[canonicalKey])
			assert.Equal(t, canonicalState,
				cleanup.maps.states.(*fakeBridgeMap).values[canonicalKey])
			assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
			assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
		})
	}

	malformedKey := stateKey{Owner: owner, Reserved: 1, Generation: 10}
	for _, artifact := range []string{"generation", "state"} {
		t.Run(artifact+" replacement", func(t *testing.T) {
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			switch artifact {
			case "generation":
				oldValue := generationIndexValue{}
				replacement := generationIndexValue{ObservedMonotonicNS: 1}
				entries := cleanup.maps.generations.(*fakeBridgeMap)
				entries.values[malformedKey] = oldValue
				entries.afterLookup = func(count int) {
					if count == 1 {
						entries.values[malformedKey] = replacement
					}
				}
				require.NoError(t, cleanup.Sweep())
				assert.Equal(t, replacement, entries.values[malformedKey])
			case "state":
				oldValue := stateValue{}
				replacement := stateValue{ObservedMonotonicNS: 1}
				entries := cleanup.maps.states.(*fakeBridgeMap)
				entries.values[malformedKey] = oldValue
				entries.afterLookup = func(count int) {
					if count == 1 {
						entries.values[malformedKey] = replacement
					}
				}
				require.NoError(t, cleanup.Sweep())
				assert.Equal(t, replacement, entries.values[malformedKey])
			}
		})
	}
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
	cleanup.maps.claims.(*fakeBridgeMap).values[key] = generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecycleConsumed},
	}

	stats := sweepSeededGenerationToCompletion(t, cleanup, key, testProcessIncarnation)
	assert.Equal(t, CleanupStats{Cleaned: 1}, stats)
	for name, bridgeMap := range map[string]cleanupMap{
		"fallback":    cleanup.maps.remoteParents,
		"connections": cleanup.maps.connections,
		"ambiguity":   cleanup.maps.ambiguity,
		"owners":      cleanup.maps.owners,
		"states":      cleanup.maps.states,
		"generations": cleanup.maps.generations,
		"claims":      cleanup.maps.claims,
	} {
		assert.Empty(t, bridgeMap.(*fakeBridgeMap).values, name)
	}
	assert.Equal(t, handoffClaimValue{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
	}, cleanup.maps.handoffClaims.(*fakeBridgeMap).values[handoff])
	assert.NotEmpty(t, cleanup.maps.tasks.(*fakeBridgeMap).values)
	assert.NotEmpty(t, cleanup.maps.handoffs.(*fakeBridgeMap).values)
	assert.NotEmpty(t, cleanup.maps.incarnations.(*fakeBridgeMap).values)
}

func TestCleanupNeverDeletesLRUHandoffClaims(t *testing.T) {
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.ttl = 30 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }

	claims := cleanup.maps.handoffClaims.(*fakeBridgeMap)
	values := map[handoffKey]handoffClaimValue{
		{PID: 1, Namespace: 2, Token: 3}: {
			ObservedMonotonicNS: 0,
			ProcessIncarnation:  testProcessIncarnation,
		},
		{PID: 4, Namespace: 5, Token: 6}: {
			ObservedMonotonicNS: uint64(10 * time.Second),
			ProcessIncarnation:  testProcessIncarnation,
		},
		{PID: 7, Namespace: 8, Token: 9}: {
			ObservedMonotonicNS: uint64(10 * time.Second),
			ProcessIncarnation:  testProcessIncarnation + 1,
		},
	}
	for key, value := range values {
		claims.values[key] = value
	}
	deletes := 0
	claims.afterDelete = func(any) { deletes++ }

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Zero(t, deletes)
	for key, value := range values {
		assert.Equal(t, value, claims.values[key])
	}
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
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }

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

	sweepSeededGenerationToCompletion(
		t, cleanup, stateKey{Owner: owner, Generation: 10}, testProcessIncarnation,
	)
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
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	delete(cleanup.maps.incarnations.(*fakeBridgeMap).values, javaProcessIdentity(owner))
	identity := virtualThreadIdentity{
		VirtualThreadID:    42,
		ProcessIncarnation: testProcessIncarnation,
	}
	cleanup.maps.virtualThreads.(*fakeBridgeMap).values[carrier] = identity
	virtualOwner := javaVirtualThreadOwner(carrier, 42)
	cleanup.maps.vtIdentities.(*fakeBridgeMap).values[virtualOwner] = identity

	sweepSeededGenerationToCompletion(
		t, cleanup, stateKey{Owner: owner, Generation: 10}, testProcessIncarnation,
	)
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
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }

	sweepSeededGenerationToCompletion(
		t, cleanup, stateKey{Owner: owner, Generation: 10}, testProcessIncarnation,
	)
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

func TestCleanupInvalidOwnerFallbackConvergesAndPreservesReplacement(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	invalidOwner := ownerValue{Generation: key.Generation, Lifecycle: lifecycleActive}
	encoded := validEncodedRecordObservedAt(t, key.Generation, 10*time.Second)

	t.Run("converges", func(t *testing.T) {
		handler := testMapHandler(nil, nil, nil)
		handler.owners.(*fakeBridgeMap).values[owner] = invalidOwner
		handler.remoteParents.(*fakeBridgeMap).values[owner] = encoded
		cleanup := testCleanup(handler)
		now := 41 * time.Second
		cleanup.monoTimeNow = func() time.Duration { return now }

		stats, err := cleanup.SweepWithStats()
		require.NoError(t, err)
		assert.Equal(t, CleanupStats{}, stats)
		assert.Equal(t, invalidOwner, cleanup.maps.owners.(*fakeBridgeMap).values[owner])
		assert.Equal(t, encoded, cleanup.maps.remoteParents.(*fakeBridgeMap).values[owner])
		claim := cleanup.maps.claims.(*fakeBridgeMap).values[key].(generationClaim)
		assert.Equal(t, key.Generation, claim.ProcessIncarnation)
		assert.Equal(t, lifecycleStale, claim.Reserved[0])

		now = 72*time.Second + time.Nanosecond
		stats, err = cleanup.SweepWithStats()
		require.NoError(t, err)
		assert.Equal(t, CleanupStats{Cleaned: 1}, stats)
		assert.NotContains(t, cleanup.maps.owners.(*fakeBridgeMap).values, owner)
		assert.NotContains(t, cleanup.maps.remoteParents.(*fakeBridgeMap).values, owner)
		assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
		assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
		assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
	})

	t.Run("preserves replacement", func(t *testing.T) {
		handler := testMapHandler(nil, nil, nil)
		handler.owners.(*fakeBridgeMap).values[owner] = invalidOwner
		handler.remoteParents.(*fakeBridgeMap).values[owner] = encoded
		cleanup := testCleanup(handler)
		cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
		seedAgedGenerationCleanupFence(t, cleanup, key, key.Generation)
		successorOwner := ownerValue{
			Generation:         11,
			ProcessIncarnation: testProcessIncarnation,
			Lifecycle:          lifecycleActive,
		}
		successor := validEncodedRecordObservedAt(t, 11, 40*time.Second)
		parents := cleanup.maps.remoteParents.(*fakeBridgeMap)
		owners := cleanup.maps.owners.(*fakeBridgeMap)
		injected := false
		parents.afterLookup = func(count int) {
			if injected || count != 3 {
				return
			}
			injected = true
			parents.mu.Lock()
			parents.values[owner] = successor
			parents.mu.Unlock()
			owners.mu.Lock()
			owners.values[owner] = successorOwner
			owners.mu.Unlock()
		}
		record, err := UnmarshalRecord(encoded[:])
		require.NoError(t, err)

		cleaned, err := cleanup.cleanupInvalidOwnerFallback(
			owner, invalidOwner, encoded, record,
		)
		require.NoError(t, err)
		assert.False(t, cleaned)
		require.True(t, injected)
		assert.Equal(t, successor, parents.values[owner])
		assert.Equal(t, successorOwner, owners.values[owner])
	})
}

func TestCleanupValidOrphanOwnerConvergesAndPreservesReplacement(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	indexed := ownerValue{
		Generation:         key.Generation,
		ProcessIncarnation: testProcessIncarnation,
		Lifecycle:          lifecycleActive,
	}

	t.Run("converges", func(t *testing.T) {
		handler := testMapHandler(nil, nil, nil)
		handler.owners.(*fakeBridgeMap).values[owner] = indexed
		cleanup := testCleanup(handler)
		now := 41 * time.Second
		cleanup.monoTimeNow = func() time.Duration { return now }
		_, ready, err := cleanup.claimGenerationCleanupForArtifact(
			key, indexed.ProcessIncarnation, lifecycleStale,
			func() (bool, error) {
				return cleanupExactMatches(cleanup.maps.owners, owner, indexed)
			},
		)
		require.NoError(t, err)
		assert.False(t, ready)

		stats, err := cleanup.SweepWithStats()
		require.NoError(t, err)
		assert.Equal(t, CleanupStats{}, stats)
		assert.Equal(t, indexed, cleanup.maps.owners.(*fakeBridgeMap).values[owner])

		now = 72*time.Second + time.Nanosecond
		stats, err = cleanup.SweepWithStats()
		require.NoError(t, err)
		assert.Equal(t, CleanupStats{Cleaned: 1}, stats)
		assert.NotContains(t, cleanup.maps.owners.(*fakeBridgeMap).values, owner)
		assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
		assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
		assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
	})

	t.Run("preserves replacement", func(t *testing.T) {
		handler := testMapHandler(nil, nil, nil)
		handler.owners.(*fakeBridgeMap).values[owner] = indexed
		cleanup := testCleanup(handler)
		cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
		seedAgedGenerationCleanupFence(t, cleanup, key, indexed.ProcessIncarnation)
		successor := ownerValue{
			Generation:         11,
			ProcessIncarnation: testProcessIncarnation,
			Lifecycle:          lifecycleActive,
		}
		owners := cleanup.maps.owners.(*fakeBridgeMap)
		injected := false
		owners.afterLookup = func(count int) {
			if injected || count != 4 {
				return
			}
			injected = true
			owners.mu.Lock()
			owners.values[owner] = successor
			owners.mu.Unlock()
		}

		cleaned, err := cleanup.cleanupOrphanOwner(owner, indexed)
		require.NoError(t, err)
		assert.False(t, cleaned)
		require.True(t, injected)
		assert.Equal(t, successor, owners.values[owner])
	})
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
			ownerGuards:                    handler.ownerGuards.(cleanupMap),
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
		coordinator: handler.coordinator,
	}
}

func seedAgedGenerationCleanupFence(
	t *testing.T,
	cleanup *Cleanup,
	key stateKey,
	processIncarnation uint64,
) generationCleanupOwnership {
	t.Helper()
	require.NotZero(t, key.Generation)
	require.Zero(t, key.Reserved)
	require.NotZero(t, processIncarnation)
	now := cleanup.monoTimeNow()
	retention := cleanup.ttl
	if retention < javaRemoteParentMinimumFenceAge {
		retention = javaRemoteParentMinimumFenceAge
	}
	require.Greater(t, now, retention+time.Nanosecond)
	observed := uint64(now - retention - time.Nanosecond)

	claims := cleanup.maps.claims.(*fakeBridgeMap)
	claim := generationClaim{
		ObservedMonotonicNS: observed,
		ProcessIncarnation:  processIncarnation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecycleStale},
	}
	if existing, ok := claims.values[key]; ok {
		claim = existing.(generationClaim)
		require.True(t, validGenerationCleanupClaim(claim))
		require.Equal(t, processIncarnation, claim.ProcessIncarnation)
		require.True(t, cleanup.generationCleanupFenceExpired(
			now, claim.ObservedMonotonicNS,
		))
	} else {
		claims.values[key] = claim
	}

	guardKey := key.Owner
	guard := generationClaim{
		ObservedMonotonicNS: observed,
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecyclePublishing},
	}
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
	if existing, ok := guards.values[guardKey]; ok {
		guard = existing.(generationClaim)
		require.True(t, validGenerationCleanupGuard(guardKey, guard))
		require.Equal(t, key.Generation, guard.ProcessIncarnation)
	} else {
		guards.values[guardKey] = guard
	}

	ambiguity := cleanup.maps.ambiguity.(*fakeBridgeMap)
	markedAt := observed
	if existing, ok := ambiguity.values[key]; ok {
		markedAt = existing.(uint64)
		if markedAt == 0 {
			markedAt = observed
			ambiguity.values[key] = markedAt
		}
	} else {
		ambiguity.values[key] = markedAt
	}
	require.True(t, cleanup.generationCleanupFenceExpired(now, markedAt))

	ownership := generationCleanupOwnership{
		claim: claim,
		fence: generationTeardownFence{
			key: key, claim: claim, guardKey: guardKey, guardClaim: guard,
			markedAt: markedAt,
		},
		ready: true,
	}
	matched, err := generationTeardownFenceMatches(
		cleanup.maps.claims, cleanup.maps.ownerGuards, cleanup.maps.ambiguity, ownership.fence,
	)
	require.NoError(t, err)
	require.True(t, matched)
	return ownership
}

func sweepSeededGenerationToCompletion(
	t *testing.T,
	cleanup *Cleanup,
	key stateKey,
	processIncarnation uint64,
) CleanupStats {
	t.Helper()
	seedAgedGenerationCleanupFence(t, cleanup, key, processIncarnation)
	var total CleanupStats
	for range 4 {
		stats, err := cleanup.SweepWithStats()
		require.NoError(t, err)
		total.Cleaned += stats.Cleaned
		total.Evicted += stats.Evicted
	}
	return total
}

func TestCleanupAcquiresCompleteFenceBeforeMutation(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	cleanup := testCleanup(testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)}, nil, nil,
	))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	key := stateKey{Owner: owner, Generation: 10}

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Contains(t, cleanup.maps.states.(*fakeBridgeMap).values, key)
	assert.Contains(t, cleanup.maps.generations.(*fakeBridgeMap).values, key)
	assert.Contains(t, cleanup.maps.owners.(*fakeBridgeMap).values, owner)
	assert.Contains(t, cleanup.maps.remoteParents.(*fakeBridgeMap).values, owner)
	assert.NotEmpty(t, cleanup.maps.connections.(*fakeBridgeMap).values)
	assert.NotEmpty(t, cleanup.maps.cookieConnections.(*fakeBridgeMap).values)

	claim := cleanup.maps.claims.(*fakeBridgeMap).values[key].(generationClaim)
	guardKey := owner
	guard := cleanup.maps.ownerGuards.(*fakeBridgeMap).values[guardKey].(generationClaim)
	markedAt := cleanup.maps.ambiguity.(*fakeBridgeMap).values[key].(uint64)
	assert.Equal(t, uint64(41*time.Second), claim.ObservedMonotonicNS)
	assert.Equal(t, uint64(41*time.Second), guard.ObservedMonotonicNS)
	assert.Equal(t, uint64(41*time.Second), markedAt)
	assert.Equal(t, uint64(10), guard.ProcessIncarnation)

	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Contains(t, cleanup.maps.generations.(*fakeBridgeMap).values, key)
}

func TestCleanupNewMarkerMustAgeFromPromotionTime(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	cleanup := testCleanup(testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)}, nil, nil,
	))
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	key := stateKey{Owner: owner, Generation: 10}
	guardKey := owner
	cleanup.maps.claims.(*fakeBridgeMap).values[key] = generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecycleStale},
	}
	cleanup.maps.ownerGuards.(*fakeBridgeMap).values[guardKey] = generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecyclePublishing},
	}

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, uint64(now), cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
	assert.Contains(t, cleanup.maps.states.(*fakeBridgeMap).values, key)

	now = 42 * time.Second
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Contains(t, cleanup.maps.states.(*fakeBridgeMap).values, key)
}

func TestCleanupFenceAgeUsesStrictRetentionBoundary(t *testing.T) {
	const observed = uint64(10 * time.Second)
	for _, test := range []struct {
		name      string
		ttl       time.Duration
		retention time.Duration
	}{
		{name: "configured TTL", ttl: 30 * time.Second, retention: 30 * time.Second},
		{name: "minimum fence age", ttl: 100 * time.Millisecond, retention: time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			cleanup.ttl = test.ttl
			boundary := time.Duration(observed) + test.retention
			assert.False(t, cleanup.generationCleanupFenceExpired(boundary, observed))
			assert.True(t, cleanup.generationCleanupFenceExpired(
				boundary+time.Nanosecond, observed,
			))
			assert.False(t, cleanup.generationCleanupFenceExpired(
				time.Duration(observed)-time.Nanosecond, observed,
			))
		})
	}
}

func TestCleanupRejectsIncompleteOrFreshFence(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*Cleanup, stateKey)
	}{
		{
			name: "missing exact claim",
			configure: func(cleanup *Cleanup, key stateKey) {
				delete(cleanup.maps.claims.(*fakeBridgeMap).values, key)
			},
		},
		{
			name: "missing guard",
			configure: func(cleanup *Cleanup, key stateKey) {
				delete(cleanup.maps.ownerGuards.(*fakeBridgeMap).values, key.Owner)
			},
		},
		{
			name: "wrong guard generation",
			configure: func(cleanup *Cleanup, key stateKey) {
				guardKey := key.Owner
				guard := cleanup.maps.ownerGuards.(*fakeBridgeMap).values[guardKey].(generationClaim)
				guard.ProcessIncarnation++
				cleanup.maps.ownerGuards.(*fakeBridgeMap).values[guardKey] = guard
			},
		},
		{
			name: "malformed guard",
			configure: func(cleanup *Cleanup, key stateKey) {
				guardKey := key.Owner
				guard := cleanup.maps.ownerGuards.(*fakeBridgeMap).values[guardKey].(generationClaim)
				guard.Reserved[1] = 1
				cleanup.maps.ownerGuards.(*fakeBridgeMap).values[guardKey] = guard
			},
		},
		{
			name: "fresh marker",
			configure: func(cleanup *Cleanup, key stateKey) {
				cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(41 * time.Second)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			cleanup := testCleanup(testMapHandler(
				map[Identity]any{owner: validEncodedRecord(t, 10)}, nil, nil,
			))
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
			key := stateKey{Owner: owner, Generation: 10}
			seedAgedGenerationCleanupFence(t, cleanup, key, testProcessIncarnation)
			test.configure(cleanup, key)

			stats, err := cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Contains(t, cleanup.maps.states.(*fakeBridgeMap).values, key)
			assert.Contains(t, cleanup.maps.generations.(*fakeBridgeMap).values, key)
			assert.Contains(t, cleanup.maps.owners.(*fakeBridgeMap).values, owner)
			assert.Contains(t, cleanup.maps.remoteParents.(*fakeBridgeMap).values, owner)
			assert.NotEmpty(t, cleanup.maps.connections.(*fakeBridgeMap).values)
			assert.NotEmpty(t, cleanup.maps.cookieConnections.(*fakeBridgeMap).values)
		})
	}
}

func TestCleanupRetainsIndexUntilPhysicalSnapshotConverges(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	cleanup := testCleanup(testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)}, nil, nil,
	))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	key := stateKey{Owner: owner, Generation: 10}
	seedAgedGenerationCleanupFence(t, cleanup, key, testProcessIncarnation)
	connections := cleanup.maps.connections.(*fakeBridgeMap)
	cookieConnections := cleanup.maps.cookieConnections.(*fakeBridgeMap)
	connectionIterations := 0
	cookieIterations := 0
	connections.afterIterate = func() { connectionIterations++ }
	cookieConnections.afterIterate = func() { cookieIterations++ }

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, 1, connectionIterations)
	assert.Equal(t, 1, cookieIterations)
	assert.Empty(t, connections.values)
	assert.Empty(t, cookieConnections.values)
	assert.NotContains(t, cleanup.maps.states.(*fakeBridgeMap).values, key)
	assert.Contains(t, cleanup.maps.generations.(*fakeBridgeMap).values, key)
	assert.Contains(t, cleanup.maps.owners.(*fakeBridgeMap).values, owner)
	assert.Contains(t, cleanup.maps.claims.(*fakeBridgeMap).values, key)
	assert.Contains(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values, owner)
	assert.Contains(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values, key)

	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{Cleaned: 1}, stats)
	assert.NotContains(t, cleanup.maps.generations.(*fakeBridgeMap).values, key)
	assert.NotContains(t, cleanup.maps.owners.(*fakeBridgeMap).values, owner)
	assert.NotContains(t, cleanup.maps.claims.(*fakeBridgeMap).values, key)
	assert.NotContains(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values, owner)
	assert.NotContains(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values, key)
}

func TestCleanupRetainedGenerationIndexDoesNotTouchCoherentSuccessor(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(nil, nil, nil)
	handler.remoteParents.(*fakeBridgeMap).values[owner] =
		validEncodedRecordObservedAt(t, 11, 40*time.Second)
	seedOwnerState(handler, owner, 11)
	oldKey := stateKey{Owner: owner, Generation: 10}
	handler.generations.(*fakeBridgeMap).values[oldKey] = generationIndexValue{
		Process:             javaProcessIdentity(owner),
		ProcessIncarnation:  testProcessIncarnation,
		ObservedMonotonicNS: uint64(10 * time.Second),
	}
	cleanup := testCleanup(handler)
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	seedAgedGenerationCleanupFence(t, cleanup, oldKey, testProcessIncarnation)

	newKey := stateKey{Owner: owner, Generation: 11}
	expectedOwner := handler.owners.(*fakeBridgeMap).values[owner]
	expectedState := handler.states.(*fakeBridgeMap).values[newKey]
	expectedIndex := handler.generations.(*fakeBridgeMap).values[newKey]
	expectedFallback := handler.remoteParents.(*fakeBridgeMap).values[owner]
	expectedConnections := make(map[any]any)
	for key, value := range handler.connections.(*fakeBridgeMap).values {
		expectedConnections[key] = value
	}
	expectedCookieConnections := make(map[any]any)
	for key, value := range handler.cookieConnections.(*fakeBridgeMap).values {
		expectedCookieConnections[key] = value
	}

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{Cleaned: 1}, stats)
	assert.NotContains(t, handler.generations.(*fakeBridgeMap).values, oldKey)
	assert.Equal(t, expectedOwner, handler.owners.(*fakeBridgeMap).values[owner])
	assert.Equal(t, expectedState, handler.states.(*fakeBridgeMap).values[newKey])
	assert.Equal(t, expectedIndex, handler.generations.(*fakeBridgeMap).values[newKey])
	assert.Equal(t, expectedFallback, handler.remoteParents.(*fakeBridgeMap).values[owner])
	assert.Equal(t, expectedConnections, handler.connections.(*fakeBridgeMap).values)
	assert.Equal(t, expectedCookieConnections, handler.cookieConnections.(*fakeBridgeMap).values)
}

func TestCleanupRejectsIncoherentSuccessor(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(nil, nil, nil)
	handler.remoteParents.(*fakeBridgeMap).values[owner] =
		validEncodedRecordObservedAt(t, 11, 40*time.Second)
	seedOwnerState(handler, owner, 11)
	clear(handler.cookieConnections.(*fakeBridgeMap).values)
	oldKey := stateKey{Owner: owner, Generation: 10}
	oldIndex := generationIndexValue{
		Process:             javaProcessIdentity(owner),
		ProcessIncarnation:  testProcessIncarnation,
		ObservedMonotonicNS: uint64(10 * time.Second),
	}
	handler.generations.(*fakeBridgeMap).values[oldKey] = oldIndex
	cleanup := testCleanup(handler)
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	seedAgedGenerationCleanupFence(t, cleanup, oldKey, testProcessIncarnation)

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, oldIndex, handler.generations.(*fakeBridgeMap).values[oldKey])
	assert.Contains(t, handler.claims.(*fakeBridgeMap).values, oldKey)
	assert.Contains(t, handler.ownerGuards.(*fakeBridgeMap).values, owner)
}

func TestCleanupIncompletePhysicalSnapshotRetainsDurableRoot(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	cleanup := testCleanup(testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)}, nil, nil,
	))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	key := stateKey{Owner: owner, Generation: 10}
	seedAgedGenerationCleanupFence(t, cleanup, key, testProcessIncarnation)
	cleanup.maps.connections.(*fakeBridgeMap).iterateErr = errors.New("injected scan failure")

	stats, err := cleanup.SweepWithStats()
	require.Error(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Contains(t, cleanup.maps.generations.(*fakeBridgeMap).values, key)
	assert.Contains(t, cleanup.maps.claims.(*fakeBridgeMap).values, key)
	assert.Contains(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values, owner)
	assert.Contains(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values, key)
}

func TestCleanupIncompleteLogicalSnapshotRetainsMarkerFreeFenceTail(t *testing.T) {
	for _, test := range []struct {
		name   string
		inject func(*Cleanup)
	}{
		{
			name: "generation scan",
			inject: func(cleanup *Cleanup) {
				cleanup.maps.generations.(*fakeBridgeMap).iterateErr =
					errors.New("injected generation scan failure")
			},
		},
		{
			name: "state scan",
			inject: func(cleanup *Cleanup) {
				cleanup.maps.states.(*fakeBridgeMap).iterateErr =
					errors.New("injected state scan failure")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
			claim := generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  testProcessIncarnation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{lifecycleStale},
			}
			guard := generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  key.Generation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{lifecyclePublishing},
			}
			cleanup.maps.claims.(*fakeBridgeMap).values[key] = claim
			cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner] = guard
			test.inject(cleanup)

			stats, err := cleanup.SweepWithStats()
			require.ErrorContains(t, err, "injected")
			assert.Equal(t, CleanupStats{}, stats)
			assert.Equal(t, claim, cleanup.maps.claims.(*fakeBridgeMap).values[key])
			assert.Equal(t, guard, cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner])
			assert.Equal(t, uint64(41*time.Second),
				cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
		})
	}
}

func TestCleanupFinalFenceReleaseOrder(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	key := stateKey{Owner: owner, Generation: 10}
	seedAgedGenerationCleanupFence(t, cleanup, key, testProcessIncarnation)
	var order []string
	cleanup.maps.ambiguity.(*fakeBridgeMap).afterDelete = func(any) {
		order = append(order, "marker")
	}
	cleanup.maps.claims.(*fakeBridgeMap).afterDelete = func(deleted any) {
		if deleted == key {
			order = append(order, "claim")
		}
	}
	cleanup.maps.ownerGuards.(*fakeBridgeMap).afterDelete = func(any) {
		order = append(order, "guard")
	}

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, []string{"marker", "claim", "guard"}, order)
	assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
}

func TestCleanupFinalFenceReleaseConvergesWhenClaimDisappears(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	key := stateKey{Owner: owner, Generation: 10}
	ownership := seedAgedGenerationCleanupFence(
		t, cleanup, key, testProcessIncarnation,
	)
	cleanup.generationSnapshotComplete = true
	cleanup.stateSnapshotComplete = true
	cleanup.physicalGenerations = make(map[stateKey]struct{})

	claims := cleanup.maps.claims.(*fakeBridgeMap)
	cleanup.maps.ambiguity.(*fakeBridgeMap).afterDelete = func(any) {
		claims.mu.Lock()
		delete(claims.values, key)
		claims.mu.Unlock()
	}

	complete, err := cleanup.finishGenerationCleanupFenced(key, ownership)
	require.NoError(t, err)
	assert.True(t, complete)
	assert.NotContains(t, claims.values, key)
	assert.NotContains(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values,
		ownership.fence.guardKey)
	assert.NotContains(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values, key)
}

func TestCleanupGuardReleaseFailureRetainsGuardTail(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	key := stateKey{Owner: owner, Generation: 10}
	seedAgedGenerationCleanupFence(t, cleanup, key, testProcessIncarnation)
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
	claims.afterDelete = func(deleted any) {
		if deleted == key {
			guards.deleteErr = errors.New("injected guard release failure")
		}
	}

	stats, err := cleanup.SweepWithStats()
	require.Error(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.NotContains(t, claims.values, key)
	assert.Contains(t, guards.values, owner)
	assert.NotContains(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values, key)

	claims.afterDelete = nil
	guards.deleteErr = nil
	now = 72*time.Second + time.Nanosecond
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Empty(t, claims.values)
	assert.Empty(t, guards.values)
	assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
}

func TestCleanupReleasesAgedMarkerOnlyTailWithCompleteSnapshots(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	key := stateKey{Owner: owner, Generation: 10}
	cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(10 * time.Second)

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, uint64(10*time.Second),
		cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
}

func TestCleanupReleasesClaimGuardTailWithoutRecreatingMarker(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	guardKey := owner
	claim := generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecycleConsumed},
	}
	guard := generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecyclePublishing},
	}
	newCleanup := func() *Cleanup {
		cleanup := testCleanup(testMapHandler(nil, nil, nil))
		cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
		claims := cleanup.maps.claims.(*fakeBridgeMap)
		claims.values[key] = claim
		cleanup.maps.ownerGuards.(*fakeBridgeMap).values[guardKey] = guard
		return cleanup
	}

	t.Run("release", func(t *testing.T) {
		cleanup := newCleanup()
		markerTouched := false
		cleanup.maps.ambiguity.(*fakeBridgeMap).afterUpdate = func(any, any) {
			markerTouched = true
		}

		stats, err := cleanup.SweepWithStats()
		require.NoError(t, err)
		assert.Equal(t, CleanupStats{}, stats)
		assert.False(t, markerTouched)
		assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
		assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
		assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
	})

	t.Run("successor reservation before claim release", func(t *testing.T) {
		cleanup := newCleanup()
		claims := cleanup.maps.claims.(*fakeBridgeMap)
		guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
		markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
		injected := false
		guards.afterLookupResult = func(lookedUp any, err error) {
			if injected || lookedUp != guardKey || err != nil {
				return
			}
			injected = true
			markers.mu.Lock()
			markers.values[key] = uint64(0)
			markers.mu.Unlock()
		}

		stats, err := cleanup.SweepWithStats()
		require.NoError(t, err)
		assert.Equal(t, CleanupStats{}, stats)
		assert.True(t, injected)
		assert.Equal(t, claim, claims.values[key])
		assert.Equal(t, guard, guards.values[guardKey])
		assert.Equal(t, uint64(0), markers.values[key])
	})

	t.Run("successor reservation after claim release", func(t *testing.T) {
		cleanup := newCleanup()
		claims := cleanup.maps.claims.(*fakeBridgeMap)
		guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
		markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
		claims.afterDelete = func(deleted any) {
			if deleted == key {
				markers.values[key] = uint64(0)
			}
		}

		stats, err := cleanup.SweepWithStats()
		require.NoError(t, err)
		assert.Equal(t, CleanupStats{}, stats)
		assert.NotContains(t, claims.values, key)
		assert.NotContains(t, guards.values, guardKey)
		assert.Equal(t, uint64(0), markers.values[key])
	})
}

func TestCleanupMarkerOnlyTailRequiresStableAgedAbsenceProof(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	markedAt := uint64(10 * time.Second)
	newCleanup := func() *Cleanup {
		cleanup := testCleanup(testMapHandler(nil, nil, nil))
		cleanup.generationSnapshotComplete = true
		cleanup.stateSnapshotComplete = true
		cleanup.physicalGenerations = make(map[stateKey]struct{})
		cleanup.currentSweepAmbiguities = make(map[stateKey]uint64)
		cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = markedAt
		return cleanup
	}

	t.Run("fresh marker", func(t *testing.T) {
		cleanup := newCleanup()
		released, err := cleanup.releaseGenerationCleanupMarkerTail(
			key, markedAt, 11*time.Second,
		)
		require.NoError(t, err)
		assert.False(t, released)
		assert.Equal(t, markedAt, cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
	})

	t.Run("incomplete snapshot", func(t *testing.T) {
		cleanup := newCleanup()
		cleanup.stateSnapshotComplete = false
		released, err := cleanup.releaseGenerationCleanupMarkerTail(
			key, markedAt, 41*time.Second,
		)
		require.NoError(t, err)
		assert.False(t, released)
		assert.Equal(t, markedAt, cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
	})

	t.Run("generation artifact", func(t *testing.T) {
		cleanup := newCleanup()
		cleanup.maps.states.(*fakeBridgeMap).values[key] = stateValue{
			ObservedMonotonicNS: uint64(5 * time.Second),
		}
		released, err := cleanup.releaseGenerationCleanupMarkerTail(
			key, markedAt, 41*time.Second,
		)
		require.NoError(t, err)
		assert.False(t, released)
		assert.Equal(t, markedAt, cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
	})

	t.Run("reappearing exact claim", func(t *testing.T) {
		cleanup := newCleanup()
		claims := cleanup.maps.claims.(*fakeBridgeMap)
		injected := false
		claims.afterLookupResult = func(lookedUp any, err error) {
			if injected || lookedUp != key || !errors.Is(err, ebpf.ErrKeyNotExist) {
				return
			}
			injected = true
			claims.mu.Lock()
			claims.values[key] = generationClaim{
				ObservedMonotonicNS: uint64(40 * time.Second),
				ProcessIncarnation:  testProcessIncarnation,
				Lifecycle:           lifecycleConsumed,
			}
			claims.mu.Unlock()
		}
		released, err := cleanup.releaseGenerationCleanupMarkerTail(
			key, markedAt, 41*time.Second,
		)
		require.NoError(t, err)
		assert.False(t, injected)
		assert.False(t, released)
		assert.Equal(t, markedAt, cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
		assert.NotContains(t, claims.values, key)
	})
}

func TestCleanupReleasesPartialFenceTailsWithoutArtifactAuthority(t *testing.T) {
	for _, markerPresent := range []bool{true, false} {
		name := "guard only"
		if markerPresent {
			name = "marker and guard"
		}
		t.Run(name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
			key := stateKey{Owner: owner, Generation: 10}
			guardKey := owner
			cleanup.maps.ownerGuards.(*fakeBridgeMap).values[guardKey] = generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  key.Generation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{lifecyclePublishing},
			}
			if markerPresent {
				cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(10 * time.Second)
			}

			stats, err := cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			if markerPresent {
				assert.Contains(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values, guardKey)
				assert.Contains(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values, key)
			} else {
				assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
				assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
			}
		})
	}
}

func TestCleanupReleasesAgedGuardBehindZeroReservationWithoutTouchingGeneration(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	handler := testMapHandler(nil, nil, nil)
	handler.remoteParents.(*fakeBridgeMap).values[owner] =
		validEncodedRecordObservedAt(t, 10, 40*time.Second)
	seedOwnerState(handler, owner, 10)
	key := stateKey{Owner: owner, Generation: 10}
	guardKey := owner
	guard := generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecyclePublishing},
	}
	handler.ownerGuards.(*fakeBridgeMap).values[guardKey] = guard
	cleanup := testCleanup(handler)
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }

	expectedOwner := handler.owners.(*fakeBridgeMap).values[owner]
	expectedState := handler.states.(*fakeBridgeMap).values[key]
	expectedIndex := handler.generations.(*fakeBridgeMap).values[key]
	expectedFallback := handler.remoteParents.(*fakeBridgeMap).values[owner]
	expectedConnections := maps.Clone(handler.connections.(*fakeBridgeMap).values)
	expectedCookieConnections := maps.Clone(handler.cookieConnections.(*fakeBridgeMap).values)

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.NotContains(t, handler.ownerGuards.(*fakeBridgeMap).values, guardKey)
	assert.Equal(t, uint64(0), handler.ambiguity.(*fakeBridgeMap).values[key])
	assert.Equal(t, expectedOwner, handler.owners.(*fakeBridgeMap).values[owner])
	assert.Equal(t, expectedState, handler.states.(*fakeBridgeMap).values[key])
	assert.Equal(t, expectedIndex, handler.generations.(*fakeBridgeMap).values[key])
	assert.Equal(t, expectedFallback, handler.remoteParents.(*fakeBridgeMap).values[owner])
	assert.Equal(t, expectedConnections, handler.connections.(*fakeBridgeMap).values)
	assert.Equal(t, expectedCookieConnections, handler.cookieConnections.(*fakeBridgeMap).values)
}

func TestCleanupReservedGuardTailRetainsGuardWhenFenceChanges(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	guardKey := owner
	guard := generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecyclePublishing},
	}
	newCleanup := func() *Cleanup {
		cleanup := testCleanup(testMapHandler(nil, nil, nil))
		cleanup.currentSweepClaims = make(map[stateKey]generationClaim)
		cleanup.currentSweepGuards = make(map[Identity]generationClaim)
		cleanup.maps.ownerGuards.(*fakeBridgeMap).values[guardKey] = guard
		cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(0)
		return cleanup
	}

	t.Run("exact claim reappears", func(t *testing.T) {
		cleanup := newCleanup()
		claims := cleanup.maps.claims.(*fakeBridgeMap)
		injected := false
		claims.afterLookupResult = func(lookedUp any, err error) {
			if injected || lookedUp != key || !errors.Is(err, ebpf.ErrKeyNotExist) {
				return
			}
			injected = true
			claims.mu.Lock()
			claims.values[key] = generationClaim{
				ObservedMonotonicNS: uint64(40 * time.Second),
				ProcessIncarnation:  testProcessIncarnation,
				Lifecycle:           lifecycleConsumed,
			}
			claims.mu.Unlock()
		}

		released, err := cleanup.releaseGenerationCleanupReservedGuardTail(
			guardKey, guard, 41*time.Second,
		)
		require.NoError(t, err)
		assert.True(t, injected)
		assert.False(t, released)
		assert.Equal(t, guard, cleanup.maps.ownerGuards.(*fakeBridgeMap).values[guardKey])
		assert.Contains(t, claims.values, key)
		assert.Equal(t, uint64(0), cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
	})

	t.Run("reservation is promoted", func(t *testing.T) {
		cleanup := newCleanup()
		markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
		baseline := markers.lookupCount
		promoted := uint64(40 * time.Second)
		markers.afterLookup = func(count int) {
			if count != baseline+1 {
				return
			}
			markers.mu.Lock()
			markers.values[key] = promoted
			markers.mu.Unlock()
		}

		released, err := cleanup.releaseGenerationCleanupReservedGuardTail(
			guardKey, guard, 41*time.Second,
		)
		require.NoError(t, err)
		assert.False(t, released)
		assert.Equal(t, guard, cleanup.maps.ownerGuards.(*fakeBridgeMap).values[guardKey])
		assert.Equal(t, promoted, markers.values[key])
	})
}

func TestCleanupConnectionDeletionRevalidatesFenceBetweenIndexes(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	cleanup := testCleanup(testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)}, nil, nil,
	))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	key := stateKey{Owner: owner, Generation: 10}
	seedAgedGenerationCleanupFence(t, cleanup, key, testProcessIncarnation)
	index := cleanup.maps.generations.(*fakeBridgeMap).values[key].(generationIndexValue)
	hookCalled := false
	cleanup.maps.cookieConnections.(*fakeBridgeMap).afterDelete = func(any) {
		hookCalled = true
		cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(41 * time.Second)
	}

	cleaned, err := cleanup.cleanupGeneration(key, index)
	assert.True(t, hookCalled)
	assert.Error(t, err)
	assert.False(t, cleaned)
	assert.Empty(t, cleanup.maps.cookieConnections.(*fakeBridgeMap).values)
	assert.NotEmpty(t, cleanup.maps.connections.(*fakeBridgeMap).values)
	assert.Contains(t, cleanup.maps.states.(*fakeBridgeMap).values, key)
	assert.Contains(t, cleanup.maps.generations.(*fakeBridgeMap).values, key)
	assert.Contains(t, cleanup.maps.owners.(*fakeBridgeMap).values, owner)
	assert.Contains(t, cleanup.maps.remoteParents.(*fakeBridgeMap).values, owner)
}

func TestCleanupMalformedGuardIsFailClosed(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	cleanup := testCleanup(testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, 10)}, nil, nil,
	))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	key := stateKey{Owner: owner, Generation: 10}
	guardKey := owner
	malformed := generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecyclePublishing},
	}
	malformed.Reserved[1] = 1
	cleanup.maps.ownerGuards.(*fakeBridgeMap).values[guardKey] = malformed

	for range 3 {
		stats, err := cleanup.SweepWithStats()
		require.NoError(t, err)
		assert.Equal(t, CleanupStats{}, stats)
	}
	assert.Equal(t, malformed, cleanup.maps.ownerGuards.(*fakeBridgeMap).values[guardKey])
	assert.Contains(t, cleanup.maps.states.(*fakeBridgeMap).values, key)
	assert.Contains(t, cleanup.maps.generations.(*fakeBridgeMap).values, key)
	assert.Contains(t, cleanup.maps.owners.(*fakeBridgeMap).values, owner)
}

func TestCleanupMalformedRootAdoptsRetainedExactClaim(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	key := stateKey{Owner: owner, Generation: 10}
	cleanup.maps.states.(*fakeBridgeMap).values[key] = stateValue{
		ObservedMonotonicNS: uint64(10 * time.Second),
		Lifecycle:           lifecycleActive,
	}
	seedAgedGenerationCleanupFence(t, cleanup, key, testProcessIncarnation)

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{Cleaned: 1}, stats)
	assert.Empty(t, cleanup.maps.states.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
}

func TestCleanupPhysicalSweepIsLinear(t *testing.T) {
	handler := testMapHandler(nil, nil, nil)
	const generations = 64
	for i := uint32(1); i <= generations; i++ {
		owner := Identity{TID: i, PID: i, Namespace: 1}
		handler.remoteParents.(*fakeBridgeMap).values[owner] = validEncodedRecord(t, 10)
		seedOwnerState(handler, owner, 10)
		delete(handler.remoteParents.(*fakeBridgeMap).values, owner)
		delete(handler.owners.(*fakeBridgeMap).values, owner)
		delete(handler.states.(*fakeBridgeMap).values, stateKey{Owner: owner, Generation: 10})
		delete(handler.generations.(*fakeBridgeMap).values, stateKey{Owner: owner, Generation: 10})
	}
	cleanup := testCleanup(handler)
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	for i := uint32(1); i <= generations; i++ {
		owner := Identity{TID: i, PID: i, Namespace: 1}
		seedAgedGenerationCleanupFence(
			t, cleanup, stateKey{Owner: owner, Generation: 10}, testProcessIncarnation,
		)
	}
	connectionIterations := 0
	cookieIterations := 0
	cleanup.maps.connections.(*fakeBridgeMap).afterIterate = func() { connectionIterations++ }
	cleanup.maps.cookieConnections.(*fakeBridgeMap).afterIterate = func() { cookieIterations++ }

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, 1, connectionIterations)
	assert.Equal(t, 1, cookieIterations)
	assert.Empty(t, cleanup.maps.connections.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.cookieConnections.(*fakeBridgeMap).values)
}

func TestCleanupOriginClaimsBehindZeroReservationAcquireFence(t *testing.T) {
	for _, test := range []struct {
		name   string
		origin uint8
	}{
		{name: "consumed", origin: lifecycleConsumed},
		{name: "discarded", origin: lifecycleDiscarded},
		{name: "stale", origin: lifecycleStale},
		{name: "ambiguous", origin: lifecycleAmbiguous},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			now := 41 * time.Second
			cleanup.monoTimeNow = func() time.Duration { return now }
			claim := generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  testProcessIncarnation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{test.origin},
			}
			cleanup.maps.claims.(*fakeBridgeMap).values[key] = claim
			cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(0)

			stats, err := cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Equal(t, claim, cleanup.maps.claims.(*fakeBridgeMap).values[key])
			guard, ok := cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner].(generationClaim)
			require.True(t, ok)
			assert.Equal(t, uint64(now), guard.ObservedMonotonicNS)
			assert.Equal(t, key.Generation, guard.ProcessIncarnation)
			assert.Equal(t, lifecycleCleanup, guard.Lifecycle)
			assert.Equal(t, [7]byte{lifecyclePublishing}, guard.Reserved)
			assert.Equal(t, uint64(now), cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])

			// G and M must independently age after they are filled/promoted.
			now++
			stats, err = cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Equal(t, claim, cleanup.maps.claims.(*fakeBridgeMap).values[key])
			assert.Equal(t, guard, cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner])
			assert.Equal(t, uint64(41*time.Second),
				cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
		})
	}
}

func TestCleanupPublishingClaimBehindZeroReservationPreservesCoherentGraph(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	const generation = uint64(10)
	key := stateKey{Owner: owner, Generation: generation}
	handler := testMapHandler(map[Identity]any{
		owner: validEncodedRecordObservedAt(t, generation, 10*time.Second),
	}, nil, nil)
	cleanup := testCleanup(handler)
	cleanup.monoTimeNow = func() time.Duration { return 42*time.Second + time.Nanosecond }
	claim := generationClaim{
		ObservedMonotonicNS: uint64(11 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecyclePublishing},
	}
	guard := generationClaim{
		ObservedMonotonicNS: uint64(11 * time.Second),
		ProcessIncarnation:  generation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecyclePublishing},
	}
	cleanup.maps.claims.(*fakeBridgeMap).values[key] = claim
	cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner] = guard

	expectedOwner := cleanup.maps.owners.(*fakeBridgeMap).values[owner]
	expectedState := cleanup.maps.states.(*fakeBridgeMap).values[key]
	expectedIndex := cleanup.maps.generations.(*fakeBridgeMap).values[key]
	expectedFallback := cleanup.maps.remoteParents.(*fakeBridgeMap).values[owner]
	expectedConnections := maps.Clone(cleanup.maps.connections.(*fakeBridgeMap).values)
	expectedCookieConnections := maps.Clone(cleanup.maps.cookieConnections.(*fakeBridgeMap).values)

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.NotContains(t, cleanup.maps.claims.(*fakeBridgeMap).values, key)
	assert.NotContains(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values, owner)
	assert.Equal(t, uint64(0), cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
	assert.Equal(t, expectedOwner, cleanup.maps.owners.(*fakeBridgeMap).values[owner])
	assert.Equal(t, expectedState, cleanup.maps.states.(*fakeBridgeMap).values[key])
	assert.Equal(t, expectedIndex, cleanup.maps.generations.(*fakeBridgeMap).values[key])
	assert.Equal(t, expectedFallback, cleanup.maps.remoteParents.(*fakeBridgeMap).values[owner])
	assert.Equal(t, expectedConnections, cleanup.maps.connections.(*fakeBridgeMap).values)
	assert.Equal(t, expectedCookieConnections,
		cleanup.maps.cookieConnections.(*fakeBridgeMap).values)
}

func TestCleanupPublishingClaimBehindZeroReservationPreservesDetachedAlias(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	handler := testMapHandler(map[Identity]any{
		owner: validEncodedRecordObservedAt(t, key.Generation, 10*time.Second),
	}, nil, nil)
	state := handler.states.(*fakeBridgeMap).values[key].(stateValue)
	state.Aliases = 1
	handler.states.(*fakeBridgeMap).values[key] = state
	delete(handler.owners.(*fakeBridgeMap).values, owner)
	delete(handler.remoteParents.(*fakeBridgeMap).values, owner)
	clear(handler.connections.(*fakeBridgeMap).values)
	clear(handler.cookieConnections.(*fakeBridgeMap).values)

	cleanup := testCleanup(handler)
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	claim := generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecyclePublishing},
	}
	guard := generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecyclePublishing},
	}
	cleanup.maps.claims.(*fakeBridgeMap).values[key] = claim
	cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner] = guard

	expectedState := handler.states.(*fakeBridgeMap).values[key]
	expectedIndex := handler.generations.(*fakeBridgeMap).values[key]
	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, expectedState, cleanup.maps.states.(*fakeBridgeMap).values[key])
	assert.Equal(t, expectedIndex, cleanup.maps.generations.(*fakeBridgeMap).values[key])
	assert.NotContains(t, cleanup.maps.claims.(*fakeBridgeMap).values, key)
	assert.NotContains(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values, owner)
	assert.Equal(t, uint64(0), cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
}

func TestCleanupPublishingClaimBehindZeroReservationReleasesAbsentTail(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	cleanup.maps.claims.(*fakeBridgeMap).values[key] = generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecyclePublishing},
	}
	cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner] = generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecyclePublishing},
	}
	cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(0)

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
	assert.Equal(t, uint64(0), cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
}

func TestCleanupPublishingClaimBehindZeroReservationRejectsMalformedGraphs(t *testing.T) {
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
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			handler := testMapHandler(map[Identity]any{
				owner: validEncodedRecordObservedAt(t, key.Generation, 10*time.Second),
			}, nil, nil)
			state := handler.states.(*fakeBridgeMap).values[key].(stateValue)
			test.mutate(&state)
			handler.states.(*fakeBridgeMap).values[key] = state
			clear(handler.connections.(*fakeBridgeMap).values)
			clear(handler.cookieConnections.(*fakeBridgeMap).values)
			seedConnectionClaim(handler, connectionInfoNS{
				Connection: state.Connection,
				NetNS:      state.ConnectionNetNS,
			}, owner, key.Generation)

			cleanup := testCleanup(handler)
			claim := generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  testProcessIncarnation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{lifecyclePublishing},
			}
			guard := generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  key.Generation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{lifecyclePublishing},
			}
			cleanup.maps.claims.(*fakeBridgeMap).values[key] = claim
			cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner] = guard
			cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(0)
			zero := uint64(0)

			released, err := cleanup.releaseGenerationPublishingCleanupTail(
				key, claim, &zero, 41*time.Second,
			)
			require.NoError(t, err)
			assert.False(t, released)
			assert.Equal(t, claim, cleanup.maps.claims.(*fakeBridgeMap).values[key])
			assert.Equal(t, guard, cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner])
			assert.Equal(t, uint64(0), cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
		})
	}
}

func TestCleanupMarkedPartialFenceReconstructsMissingClaims(t *testing.T) {
	for _, guardPresent := range []bool{false, true} {
		name := "marker only"
		if guardPresent {
			name = "marker and guard"
		}
		t.Run(name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			now := 41 * time.Second
			cleanup.monoTimeNow = func() time.Duration { return now }
			cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(10 * time.Second)
			if guardPresent {
				cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner] = generationClaim{
					ObservedMonotonicNS: uint64(10 * time.Second),
					ProcessIncarnation:  key.Generation,
					Lifecycle:           lifecycleCleanup,
					Reserved:            [7]byte{lifecyclePublishing},
				}
			}

			stats, err := cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			claim, ok := cleanup.maps.claims.(*fakeBridgeMap).values[key].(generationClaim)
			require.True(t, ok)
			assert.Equal(t, uint64(now), claim.ObservedMonotonicNS)
			assert.Equal(t, key.Generation, claim.ProcessIncarnation)
			assert.Equal(t, lifecycleCleanup, claim.Lifecycle)
			assert.Equal(t, [7]byte{lifecycleAmbiguous}, claim.Reserved)
			guard, ok := cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner].(generationClaim)
			require.True(t, ok)
			if guardPresent {
				assert.Equal(t, uint64(10*time.Second), guard.ObservedMonotonicNS)
			} else {
				assert.Equal(t, uint64(now), guard.ObservedMonotonicNS)
			}
			assert.Equal(t, key.Generation, guard.ProcessIncarnation)
			assert.Equal(t, lifecycleCleanup, guard.Lifecycle)
			assert.Equal(t, [7]byte{lifecyclePublishing}, guard.Reserved)
			assert.Equal(t, uint64(10*time.Second),
				cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])

			// The fresh synthetic E (and G, when absent) cannot be retired yet.
			now++
			stats, err = cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Equal(t, claim, cleanup.maps.claims.(*fakeBridgeMap).values[key])
			assert.Equal(t, guard, cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner])
			assert.Equal(t, uint64(10*time.Second),
				cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])

			var retirementOrder []string
			cleanup.maps.ambiguity.(*fakeBridgeMap).afterDelete = func(any) {
				retirementOrder = append(retirementOrder, "marker")
			}
			cleanup.maps.claims.(*fakeBridgeMap).afterDelete = func(any) {
				retirementOrder = append(retirementOrder, "claim")
			}
			cleanup.maps.ownerGuards.(*fakeBridgeMap).afterDelete = func(any) {
				retirementOrder = append(retirementOrder, "guard")
			}
			now = 72*time.Second + time.Nanosecond
			stats, err = cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Equal(t, []string{"marker", "claim", "guard"}, retirementOrder)
			assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
			assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
			assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
		})
	}
}

func TestCleanupMarkerFreeArtifactlessClaimTail(t *testing.T) {
	for _, test := range []struct {
		name   string
		origin uint8
	}{
		{name: "consumed", origin: lifecycleConsumed},
		{name: "discarded", origin: lifecycleDiscarded},
		{name: "stale", origin: lifecycleStale},
		{name: "ambiguous", origin: lifecycleAmbiguous},
		{name: "publishing", origin: lifecyclePublishing},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
			cleanup.maps.claims.(*fakeBridgeMap).values[key] = generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  testProcessIncarnation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{test.origin},
			}

			stats, err := cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
			assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
			assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
		})
	}
}

func TestCleanupProducerAndMalformedExactClaimsFailClosed(t *testing.T) {
	producer := func(lifecycle uint8) generationClaim {
		return generationClaim{
			ObservedMonotonicNS: uint64(10 * time.Second),
			ProcessIncarnation:  testProcessIncarnation,
			Lifecycle:           lifecycle,
		}
	}
	cleanupClaim := func(origin uint8) generationClaim {
		claim := producer(lifecycleCleanup)
		claim.Reserved[0] = origin
		return claim
	}
	malformedTrailing := cleanupClaim(lifecycleConsumed)
	malformedTrailing.Reserved[1] = 1
	malformedTimestamp := cleanupClaim(lifecycleConsumed)
	malformedTimestamp.ObservedMonotonicNS = 0
	malformedToken := cleanupClaim(lifecycleConsumed)
	malformedToken.ProcessIncarnation = 0

	for _, test := range []struct {
		name  string
		claim generationClaim
	}{
		{name: "producer consumed", claim: producer(lifecycleConsumed)},
		{name: "producer discarded", claim: producer(lifecycleDiscarded)},
		{name: "producer stale", claim: producer(lifecycleStale)},
		{name: "producer ambiguous", claim: producer(lifecycleAmbiguous)},
		{name: "producer publishing", claim: producer(lifecyclePublishing)},
		{name: "cleanup origin zero", claim: cleanupClaim(0)},
		{name: "cleanup origin active", claim: cleanupClaim(lifecycleActive)},
		{name: "cleanup origin cleanup", claim: cleanupClaim(lifecycleCleanup)},
		{name: "cleanup trailing reserved", claim: malformedTrailing},
		{name: "cleanup zero timestamp", claim: malformedTimestamp},
		{name: "cleanup zero token", claim: malformedToken},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			guard := generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  key.Generation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{lifecyclePublishing},
			}
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
			cleanup.maps.claims.(*fakeBridgeMap).values[key] = test.claim
			cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner] = guard
			cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(10 * time.Second)

			stats, err := cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Equal(t, test.claim, cleanup.maps.claims.(*fakeBridgeMap).values[key])
			assert.Equal(t, guard, cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner])
			assert.Equal(t, uint64(10*time.Second),
				cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
		})
	}
}

func TestCleanupProducerAndMalformedOwnerGuardsFailClosed(t *testing.T) {
	validGuard := func() generationClaim {
		return generationClaim{
			ObservedMonotonicNS: uint64(10 * time.Second),
			ProcessIncarnation:  10,
			Lifecycle:           lifecycleCleanup,
			Reserved:            [7]byte{lifecyclePublishing},
		}
	}
	producer := validGuard()
	producer.Lifecycle = lifecyclePublishing
	producer.Reserved = [7]byte{}
	wrongOrigin := validGuard()
	wrongOrigin.Reserved[0] = lifecycleAmbiguous
	trailingReserved := validGuard()
	trailingReserved.Reserved[1] = 1
	zeroTimestamp := validGuard()
	zeroTimestamp.ObservedMonotonicNS = 0
	zeroToken := validGuard()
	zeroToken.ProcessIncarnation = 0

	for _, test := range []struct {
		name  string
		guard generationClaim
	}{
		{name: "producer publishing", guard: producer},
		{name: "cleanup wrong origin", guard: wrongOrigin},
		{name: "cleanup trailing reserved", guard: trailingReserved},
		{name: "cleanup zero timestamp", guard: zeroTimestamp},
		{name: "cleanup zero token", guard: zeroToken},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
			cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner] = test.guard
			cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(10 * time.Second)

			stats, err := cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
			assert.Equal(t, test.guard,
				cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner])
			assert.Equal(t, uint64(10*time.Second),
				cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
		})
	}
}

func TestCleanupByteIdenticalFenceSuccessorSurvivesSnapshotTail(t *testing.T) {
	for _, successor := range []string{"marker", "claim", "guard"} {
		t.Run(successor, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
			ownership := seedAgedGenerationCleanupFence(
				t, cleanup, key, testProcessIncarnation,
			)
			claims := cleanup.maps.claims.(*fakeBridgeMap)
			guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
			markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
			injected := false
			switch successor {
			case "marker":
				markers.afterDelete = func(deleted any) {
					if injected || deleted != key {
						return
					}
					injected = true
					markers.mu.Lock()
					markers.values[key] = ownership.fence.markedAt
					markers.mu.Unlock()
				}
			case "claim":
				claims.afterDelete = func(deleted any) {
					if injected || deleted != key {
						return
					}
					injected = true
					claims.mu.Lock()
					claims.values[key] = ownership.claim
					claims.mu.Unlock()
				}
			case "guard":
				guards.afterDelete = func(deleted any) {
					if injected || deleted != owner {
						return
					}
					injected = true
					guards.mu.Lock()
					guards.values[owner] = ownership.fence.guardClaim
					guards.mu.Unlock()
				}
			}

			stats, err := cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			require.True(t, injected)
			switch successor {
			case "marker":
				assert.Equal(t, ownership.fence.markedAt, markers.values[key])
				assert.Equal(t, ownership.claim, claims.values[key])
				assert.Equal(t, ownership.fence.guardClaim, guards.values[owner])
			case "claim":
				assert.NotContains(t, markers.values, key)
				assert.Equal(t, ownership.claim, claims.values[key])
				assert.Equal(t, ownership.fence.guardClaim, guards.values[owner])
			case "guard":
				assert.NotContains(t, markers.values, key)
				assert.NotContains(t, claims.values, key)
				assert.Equal(t, ownership.fence.guardClaim, guards.values[owner])
			}
		})
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

func TestCleanupPhysicalOnlyGenerationFenceLifecycle(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	const generation = uint64(10)
	key := stateKey{Owner: owner, Generation: generation}
	connectionKey := connectionInfoNS{
		Connection: connectionInfo{SourcePort: 3, DestinationPort: 10},
		NetNS:      owner.Namespace,
	}
	handler := testMapHandler(nil, nil, nil)
	seedConnectionClaim(handler, connectionKey, owner, generation)
	cleanup := testCleanup(handler)
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }

	connections := cleanup.maps.connections.(*fakeBridgeMap)
	cookieConnections := cleanup.maps.cookieConnections.(*fakeBridgeMap)
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
	markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
	var publicationOrder []string
	guards.afterUpdate = func(any, any) {
		publicationOrder = append(publicationOrder, "guard")
	}
	claims.afterUpdate = func(any, any) {
		publicationOrder = append(publicationOrder, "claim")
	}
	markers.afterUpdate = func(any, any) {
		publicationOrder = append(publicationOrder, "marker")
	}

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, []string{"guard", "claim", "marker"}, publicationOrder)
	assert.Len(t, connections.values, 1)
	assert.Len(t, cookieConnections.values, 1)

	claim, ok := claims.values[key].(generationClaim)
	require.True(t, ok)
	assert.Equal(t, uint64(now), claim.ObservedMonotonicNS)
	assert.Equal(t, generation, claim.ProcessIncarnation)
	assert.Equal(t, lifecycleCleanup, claim.Lifecycle)
	assert.Equal(t, [7]byte{lifecycleAmbiguous}, claim.Reserved)
	guard, ok := guards.values[owner].(generationClaim)
	require.True(t, ok)
	assert.Equal(t, uint64(now), guard.ObservedMonotonicNS)
	assert.Equal(t, generation, guard.ProcessIncarnation)
	assert.Equal(t, lifecycleCleanup, guard.Lifecycle)
	assert.Equal(t, [7]byte{lifecyclePublishing}, guard.Reserved)
	assert.Equal(t, uint64(now), markers.values[key])

	var physicalDeleteOrder []string
	cookieConnections.afterDelete = func(any) {
		physicalDeleteOrder = append(physicalDeleteOrder, "cookie")
	}
	connections.afterDelete = func(any) {
		physicalDeleteOrder = append(physicalDeleteOrder, "connection")
	}
	now = 72*time.Second + time.Nanosecond
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, []string{"cookie", "connection"}, physicalDeleteOrder)
	assert.Empty(t, connections.values)
	assert.Empty(t, cookieConnections.values)
	assert.Equal(t, claim, claims.values[key])
	assert.Equal(t, guard, guards.values[owner])
	assert.Equal(t, uint64(41*time.Second), markers.values[key])

	var retirementOrder []string
	markers.afterDelete = func(any) {
		retirementOrder = append(retirementOrder, "marker")
	}
	claims.afterDelete = func(any) {
		retirementOrder = append(retirementOrder, "claim")
	}
	guards.afterDelete = func(any) {
		retirementOrder = append(retirementOrder, "guard")
	}
	now = 103*time.Second + 2*time.Nanosecond
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, []string{"marker", "claim", "guard"}, retirementOrder)
	assert.Empty(t, claims.values)
	assert.Empty(t, guards.values)
	assert.Empty(t, markers.values)
}

func TestCleanupPhysicalOnlyRootReplacementStopsFenceAcquisition(t *testing.T) {
	for _, test := range []struct {
		name        string
		inject      func(*Cleanup, func())
		expectGuard bool
		expectClaim bool
	}{
		{
			name: "before guard",
			inject: func(_ *Cleanup, replace func()) {
				replace()
			},
		},
		{
			name: "guard to claim",
			inject: func(cleanup *Cleanup, replace func()) {
				cleanup.maps.ownerGuards.(*fakeBridgeMap).afterUpdate = func(any, any) {
					replace()
				}
			},
			expectGuard: true,
		},
		{
			name: "claim to marker",
			inject: func(cleanup *Cleanup, replace func()) {
				cleanup.maps.claims.(*fakeBridgeMap).afterUpdate = func(any, any) {
					replace()
				}
			},
			expectGuard: true,
			expectClaim: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			connectionKey := connectionInfoNS{
				Connection: connectionInfo{SourcePort: 3, DestinationPort: 10},
				NetNS:      owner.Namespace,
			}
			handler := testMapHandler(nil, nil, nil)
			seedConnectionClaim(handler, connectionKey, owner, key.Generation)
			cleanup := testCleanup(handler)
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
			connections := cleanup.maps.connections.(*fakeBridgeMap)
			rootClaim := connections.values[connectionKey].(connectionClaim)
			root := physicalGenerationCleanupRoot{
				kind:          physicalGenerationConnectionRoot,
				connectionKey: connectionKey,
				claim:         rootClaim,
			}
			replaced := false
			replace := func() {
				if replaced {
					return
				}
				replaced = true
				replacement := rootClaim
				replacement.IncomingGeneration++
				connections.values[connectionKey] = replacement
			}

			if test.name == "before guard" {
				test.inject(cleanup, func() {})
			} else {
				test.inject(cleanup, replace)
			}
			rootMatches := func() (bool, error) {
				if test.name == "before guard" {
					replace()
				}
				return cleanup.physicalGenerationCleanupRootMatches(
					key, []physicalGenerationCleanupRoot{root},
				)
			}
			_, ready, err := cleanup.claimGenerationCleanupForArtifact(
				key, key.Generation, lifecycleAmbiguous, rootMatches,
			)
			require.NoError(t, err)
			assert.False(t, ready)
			require.True(t, replaced)
			assert.Equal(t, test.expectGuard,
				len(cleanup.maps.ownerGuards.(*fakeBridgeMap).values) == 1)
			assert.Equal(t, test.expectClaim,
				len(cleanup.maps.claims.(*fakeBridgeMap).values) == 1)
			assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
			assert.Len(t, cleanup.maps.connections.(*fakeBridgeMap).values, 1)
			assert.Len(t, cleanup.maps.cookieConnections.(*fakeBridgeMap).values, 1)
		})
	}
}

func TestCleanupPhysicalFenceTreatsClaimIncarnationAsOpaque(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	connectionKey := connectionInfoNS{
		Connection: connectionInfo{SourcePort: 3, DestinationPort: 10},
		NetNS:      owner.Namespace,
	}
	handler := testMapHandler(nil, nil, nil)
	seedConnectionClaim(handler, connectionKey, owner, key.Generation)
	cleanup := testCleanup(handler)
	claim := generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecycleAmbiguous},
	}
	guard := generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecyclePublishing},
	}
	index := generationIndexValue{
		Process:             javaProcessIdentity(owner),
		ProcessIncarnation:  testProcessIncarnation,
		ObservedMonotonicNS: uint64(40 * time.Second),
	}
	cleanup.maps.claims.(*fakeBridgeMap).values[key] = claim
	cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner] = guard
	cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(10 * time.Second)
	cleanup.maps.generations.(*fakeBridgeMap).values[key] = index
	connection := cleanup.maps.connections.(*fakeBridgeMap).values[connectionKey].(connectionClaim)

	deleted, err := cleanup.deleteConnectionIndexesFenced(
		key, connectionKey, connection, 41*time.Second,
	)
	require.NoError(t, err)
	assert.True(t, deleted)
	assert.Empty(t, cleanup.maps.connections.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.cookieConnections.(*fakeBridgeMap).values)
	assert.Equal(t, index, cleanup.maps.generations.(*fakeBridgeMap).values[key])
	assert.Equal(t, claim, cleanup.maps.claims.(*fakeBridgeMap).values[key])
	assert.Equal(t, guard, cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner])
	assert.Equal(t, uint64(10*time.Second),
		cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
}

func TestCleanupPhysicalOnlyBootstrapRequiresCompletePhysicalScan(t *testing.T) {
	for _, test := range []struct {
		name   string
		inject func(*Cleanup)
	}{
		{
			name: "connection scan",
			inject: func(cleanup *Cleanup) {
				cleanup.maps.connections.(*fakeBridgeMap).iterateErr = errors.New("injected scan failure")
			},
		},
		{
			name: "cookie scan",
			inject: func(cleanup *Cleanup) {
				cleanup.maps.cookieConnections.(*fakeBridgeMap).iterateErr =
					errors.New("injected scan failure")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			connectionKey := connectionInfoNS{
				Connection: connectionInfo{SourcePort: 3, DestinationPort: 10},
				NetNS:      owner.Namespace,
			}
			handler := testMapHandler(nil, nil, nil)
			seedConnectionClaim(handler, connectionKey, owner, 10)
			cleanup := testCleanup(handler)
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
			test.inject(cleanup)

			stats, err := cleanup.SweepWithStats()
			require.ErrorContains(t, err, "injected scan failure")
			assert.Equal(t, CleanupStats{}, stats)
			assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
			assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
			assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
			assert.Len(t, cleanup.maps.connections.(*fakeBridgeMap).values, 1)
			assert.Len(t, cleanup.maps.cookieConnections.(*fakeBridgeMap).values, 1)
		})
	}
}

func TestCleanupPhysicalOnlyMalformedRootDoesNotBootstrap(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*MapHandler, connectionInfoNS)
	}{
		{
			name: "connection root",
			configure: func(handler *MapHandler, connectionKey connectionInfoNS) {
				clear(handler.cookieConnections.(*fakeBridgeMap).values)
				connections := handler.connections.(*fakeBridgeMap)
				claim := connections.values[connectionKey].(connectionClaim)
				claim.Reserved = 1
				connections.values[connectionKey] = claim
			},
		},
		{
			name: "cookie root",
			configure: func(handler *MapHandler, _ connectionInfoNS) {
				clear(handler.connections.(*fakeBridgeMap).values)
				cookies := handler.cookieConnections.(*fakeBridgeMap)
				for rawKey, rawValue := range cookies.values {
					delete(cookies.values, rawKey)
					cookieKey := rawKey.(connectionInfoNetNSCookie)
					cookieKey.Reserved = 1
					cookies.values[cookieKey] = rawValue
				}
			},
		},
		{
			name: "empty connection root",
			configure: func(handler *MapHandler, connectionKey connectionInfoNS) {
				clear(handler.cookieConnections.(*fakeBridgeMap).values)
				connections := handler.connections.(*fakeBridgeMap)
				claim := connections.values[connectionKey]
				delete(connections.values, connectionKey)
				connectionKey.Connection = connectionInfo{}
				connections.values[connectionKey] = claim
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			connectionKey := connectionInfoNS{
				Connection: connectionInfo{SourcePort: 3, DestinationPort: 10},
				NetNS:      owner.Namespace,
			}
			handler := testMapHandler(nil, nil, nil)
			seedConnectionClaim(handler, connectionKey, owner, 10)
			test.configure(handler, connectionKey)
			cleanup := testCleanup(handler)
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }

			stats, err := cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
			assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
			assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
			assert.Equal(t, 1,
				len(cleanup.maps.connections.(*fakeBridgeMap).values)+
					len(cleanup.maps.cookieConnections.(*fakeBridgeMap).values))
		})
	}
}
