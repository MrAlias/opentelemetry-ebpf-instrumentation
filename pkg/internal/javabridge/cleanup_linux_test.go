// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javabridge

import (
	"errors"
	"maps"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCleanupKernelMapLayouts(t *testing.T) {
	assert.Equal(t, uintptr(24), unsafe.Sizeof(handoffKey{}))
	assert.Equal(t, uintptr(16), unsafe.Offsetof(handoffKey{}.ProcessIncarnation))
	assert.Equal(t, uintptr(16), unsafe.Sizeof(handoffClaimValue{}))
	assert.Equal(t, uintptr(24), unsafe.Sizeof(threadMappingClaimValue{}))
	assert.Equal(t, uintptr(12), unsafe.Offsetof(threadMappingClaimValue{}.Reserved))
	assert.Equal(t, uintptr(16), unsafe.Offsetof(threadMappingClaimValue{}.ProcessIncarnation))
	assert.Equal(t, uintptr(24), unsafe.Sizeof(retiredProcessKey{}))
	assert.Equal(t, uintptr(24), unsafe.Sizeof(generationClaim{}))
	assert.Equal(t, unsafe.Offsetof(generationClaim{}.Reserved)+6, uintptr(23))
	assert.Equal(t, uintptr(40), unsafe.Sizeof(aliasReplayKey{}))
	assert.Equal(t, uintptr(72), unsafe.Sizeof(aliasReplayValue{}))
	assert.Equal(t, uint8(0x47), generationGoProducerTag)
	assert.Equal(t, uint8(0x48), javaRemoteParentTerminalHandoffGenerationClaimTag)
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

func taggedGoPublishingGenerationClaim(
	target uint8,
	observedMonotonicNS uint64,
	processIncarnation uint64,
) generationClaim {
	claim := taggedGoGenerationClaim(
		lifecyclePublishing, observedMonotonicNS, processIncarnation,
	)
	claim.Reserved[0] = target
	return claim
}

func exactMarkerTailClaimForTest(
	key stateKey,
	observedMonotonicNS uint64,
) generationClaim {
	return generationClaim{
		ObservedMonotonicNS: observedMonotonicNS,
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecycleCleanup,
		Reserved: [7]byte{
			0: lifecycleAmbiguous,
			6: generationGoProducerTag,
		},
	}
}

func pointerTo[T any](value T) *T { return &value }

func TestValidExactMarkerTailCleanupClaimIsUnforgeablyNarrow(t *testing.T) {
	key := stateKey{
		Owner: Identity{TID: 3, PID: 2, Namespace: 1}, Generation: 10,
	}
	valid := exactMarkerTailClaimForTest(key, uint64(10*time.Second))
	for _, test := range []struct {
		name        string
		key         stateKey
		claim       generationClaim
		wantExact   bool
		wantGeneric bool
	}{
		{name: "tagged exact", key: key, claim: valid, wantExact: true},
		{
			name: "untagged BPF shape", key: key,
			claim: func() generationClaim {
				claim := valid
				claim.Reserved[6] = 0
				return claim
			}(),
			wantGeneric: true,
		},
		{
			name: "tagged producer", key: key,
			claim: taggedGoGenerationClaim(
				lifecycleAmbiguous, uint64(10*time.Second), key.Generation,
			),
		},
		{
			name: "tagged publishing", key: key,
			claim: taggedGoPublishingGenerationClaim(
				lifecycleAmbiguous, uint64(10*time.Second), key.Generation,
			),
		},
		{
			name: "wrong tag", key: key,
			claim: func() generationClaim { claim := valid; claim.Reserved[6]++; return claim }(),
		},
		{
			name: "extra metadata", key: key,
			claim: func() generationClaim { claim := valid; claim.Reserved[1] = 1; return claim }(),
		},
		{
			name: "wrong incarnation", key: key,
			claim: func() generationClaim { claim := valid; claim.ProcessIncarnation++; return claim }(),
		},
		{
			name: "wrong origin", key: key,
			claim: func() generationClaim { claim := valid; claim.Reserved[0] = lifecycleStale; return claim }(),
		},
		{
			name: "wrong lifecycle", key: key,
			claim: func() generationClaim { claim := valid; claim.Lifecycle = lifecycleConsumed; return claim }(),
		},
		{
			name: "zero timestamp", key: key,
			claim: func() generationClaim { claim := valid; claim.ObservedMonotonicNS = 0; return claim }(),
		},
		{
			name: "malformed key",
			key: stateKey{
				Owner: key.Owner, Generation: key.Generation, Reserved: 1,
			},
			claim: valid,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.wantExact,
				validExactMarkerTailCleanupClaim(test.key, test.claim))
			assert.Equal(t, test.wantGeneric, validGenerationCleanupClaim(test.claim))
		})
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
	publishing := taggedGoPublishingGenerationClaim(
		lifecycleConsumed, 10, testProcessIncarnation,
	)
	require.True(t, validGenerationProducerClaim(publishing))
	publishingCleanup, err := generationProducerHandoffValue(publishing, 9)
	require.NoError(t, err)
	assert.Equal(t, [7]byte{lifecycleConsumed}, publishingCleanup.Reserved)

	// The same tag-only publishing shape is G producer state, not an E claim.
	producerGuard := taggedGoGenerationClaim(
		lifecyclePublishing, 10, testProcessIncarnation,
	)
	assert.False(t, validGenerationProducerClaim(producerGuard))
	guardCleanup, err := generationProducerHandoffValue(producerGuard, 9)
	require.NoError(t, err)
	assert.Equal(t, [7]byte{lifecyclePublishing}, guardCleanup.Reserved)

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
	_, err = generationProducerHandoffValue(saturated, 100*time.Second)
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
			if test.lifecycle == lifecyclePublishing {
				claim = taggedGoPublishingGenerationClaim(
					lifecycleConsumed, uint64(10*time.Second), testProcessIncarnation,
				)
			}
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

func TestCleanupRetirementDeletesParkedTaskUnderExactClaim(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	handler := testMapHandler(nil, map[Identity]any{
		child: activeTaskLink(owner, 10),
	}, nil)
	cleanup := testCleanup(handler)
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	process := javaProcessIdentity(owner)
	delete(cleanup.maps.incarnations.(*fakeBridgeMap).values, process)
	cleanup.maps.retired.(*fakeBridgeMap).values[retiredProcessKey{
		Process:            process,
		ProcessIncarnation: testProcessIncarnation,
	}] = uint64(41 * time.Second)

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{Cleaned: 1}, stats)
	assert.Empty(t, cleanup.maps.tasks.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.taskClaims.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.retired.(*fakeBridgeMap).values)
}

func TestJavaRemoteParentProcessCleanupClaimEncoding(t *testing.T) {
	process := Identity{TID: 22, PID: 22, Namespace: 7}
	claim, valid := javaRemoteParentProcessCleanupClaim(
		(17*time.Second)+(23*time.Nanosecond), process, testProcessIncarnation,
	)
	require.True(t, valid)
	assert.Equal(t, process.PID, claim.Child.PID)
	assert.Equal(t, process.Namespace, claim.Child.Namespace)
	assert.NotZero(t, claim.Reserved&javaRemoteParentProcessCleanupClaimTag)
	assert.Equal(t, testProcessIncarnation, claim.ProcessIncarnation)
	assert.True(t, validJavaRemoteParentProcessCleanupClaim(process, claim))

	next, valid := javaRemoteParentProcessCleanupClaim(
		(17*time.Second)+(24*time.Nanosecond), process, testProcessIncarnation,
	)
	require.True(t, valid)
	assert.NotEqual(t, claim, next, "successive P claims need exact ABA identity")

	_, valid = javaRemoteParentProcessCleanupClaim(0, process, testProcessIncarnation)
	assert.False(t, valid)
	_, valid = javaRemoteParentProcessCleanupClaim(time.Second, Identity{}, testProcessIncarnation)
	assert.False(t, valid)
	_, valid = javaRemoteParentProcessCleanupClaim(time.Second, process, 0)
	assert.False(t, valid)
}

func TestCleanupPublishesRetirementBeforeDeletingUnauthorizedIncarnation(t *testing.T) {
	handler := testMapHandler(nil, nil, nil)
	cleanup := testCleanup(handler)
	process := Identity{TID: 2, PID: 2, Namespace: 1}
	delete(cleanup.maps.authorized.(*fakeBridgeMap).values, process)

	require.NoError(t, cleanup.Sweep())

	assert.NotContains(t, cleanup.maps.incarnations.(*fakeBridgeMap).values, process)
	marker := retiredProcessKey{
		Process: process, ProcessIncarnation: testProcessIncarnation,
	}
	assert.NotZero(t, cleanup.maps.retired.(*fakeBridgeMap).values[marker])
	assert.NotContains(t, cleanup.maps.threadMappingClaims.(*fakeBridgeMap).values, process)
}

func TestCleanupRetiresPredecessorAcrossCapabilityRotationWindow(t *testing.T) {
	handler := testMapHandler(nil, nil, nil)
	cleanup := testCleanup(handler)
	process := Identity{TID: 2, PID: 2, Namespace: 1}
	cleanup.maps.authorized.(*fakeBridgeMap).values[process] = uint64(73)

	require.NoError(t, cleanup.Sweep())

	assert.Equal(t, uint64(73), cleanup.maps.authorized.(*fakeBridgeMap).values[process])
	assert.NotContains(t, cleanup.maps.incarnations.(*fakeBridgeMap).values, process)
	assert.NotZero(t, cleanup.maps.retired.(*fakeBridgeMap).values[retiredProcessKey{
		Process: process, ProcessIncarnation: testProcessIncarnation,
	}])
}

func TestCleanupRetirementMarkerFailurePreservesIncarnationAndRetries(t *testing.T) {
	handler := testMapHandler(nil, nil, nil)
	cleanup := testCleanup(handler)
	process := Identity{TID: 2, PID: 2, Namespace: 1}
	delete(cleanup.maps.authorized.(*fakeBridgeMap).values, process)
	retired := cleanup.maps.retired.(*fakeBridgeMap)
	retired.updateErr = errors.New("retirement map full")

	err := cleanup.Sweep()
	require.ErrorContains(t, err, "publishing Java process retirement marker")
	assert.Equal(t, testProcessIncarnation,
		cleanup.maps.incarnations.(*fakeBridgeMap).values[process])
	assert.NotContains(t, cleanup.maps.threadMappingClaims.(*fakeBridgeMap).values, process)

	retired.updateErr = nil
	require.NoError(t, cleanup.Sweep())
	assert.NotContains(t, cleanup.maps.incarnations.(*fakeBridgeMap).values, process)
	assert.NotZero(t, retired.values[retiredProcessKey{
		Process: process, ProcessIncarnation: testProcessIncarnation,
	}])
}

func TestCleanupRetriesUnauthorizedRetirementAfterSameSweepCapacityRecovery(t *testing.T) {
	handler := testMapHandler(nil, nil, nil)
	cleanup := testCleanup(handler)
	process := Identity{TID: 2, PID: 2, Namespace: 1}
	delete(cleanup.maps.authorized.(*fakeBridgeMap).values, process)
	retired := cleanup.maps.retired.(*fakeBridgeMap)
	retired.updateErr = errors.New("retirement map full")
	retired.afterFailedUpdate = func() {
		retired.mu.Lock()
		retired.updateErr = nil
		retired.mu.Unlock()
	}

	require.NoError(t, cleanup.Sweep())
	assert.NotContains(t, cleanup.maps.incarnations.(*fakeBridgeMap).values, process)
	assert.NotZero(t, retired.values[retiredProcessKey{
		Process: process, ProcessIncarnation: testProcessIncarnation,
	}])
}

func TestCleanupRecoversCoupledProcessClaimAndRetirementCapacity(t *testing.T) {
	handler := testMapHandler(nil, nil, nil)
	cleanup := testCleanup(handler)
	process := Identity{TID: 2, PID: 2, Namespace: 1}
	delete(cleanup.maps.authorized.(*fakeBridgeMap).values, process)

	// Fill R with an already-quiescent process. Its sweep-start marker holds one
	// P slot until finalization, while the unauthorized current process uses the
	// other slot and initially cannot publish its own marker. Cleanup must release
	// that unsuccessful P root, finalize the old R/P pair, and retry in this sweep.
	oldProcess := Identity{TID: 9, PID: 9, Namespace: 1}
	oldRetirement := retiredProcessKey{
		Process: oldProcess, ProcessIncarnation: 73,
	}
	retired := cleanup.maps.retired.(*fakeBridgeMap)
	retired.maxEntries = 1
	retired.values[oldRetirement] = uint64(10 * time.Second)
	claims := cleanup.maps.threadMappingClaims.(*fakeBridgeMap)
	claims.maxEntries = 2

	require.NoError(t, cleanup.Sweep())

	currentRetirement := retiredProcessKey{
		Process: process, ProcessIncarnation: testProcessIncarnation,
	}
	assert.NotContains(t, retired.values, oldRetirement)
	assert.NotZero(t, retired.values[currentRetirement])
	assert.NotContains(t, cleanup.maps.incarnations.(*fakeBridgeMap).values, process)
	assert.Empty(t, claims.values)
}

func TestCleanupForeignProcessClaimPreservesUnauthorizedIncarnation(t *testing.T) {
	handler := testMapHandler(nil, nil, nil)
	cleanup := testCleanup(handler)
	process := Identity{TID: 2, PID: 2, Namespace: 1}
	delete(cleanup.maps.authorized.(*fakeBridgeMap).values, process)
	foreign := threadMappingClaimValue{
		Child:              Identity{TID: 9, PID: 2, Namespace: 1},
		ProcessIncarnation: testProcessIncarnation,
	}
	cleanup.maps.threadMappingClaims.(*fakeBridgeMap).values[process] = foreign

	require.NoError(t, cleanup.Sweep())

	assert.Equal(t, testProcessIncarnation,
		cleanup.maps.incarnations.(*fakeBridgeMap).values[process])
	assert.Equal(t, foreign, cleanup.maps.threadMappingClaims.(*fakeBridgeMap).values[process])
	assert.Empty(t, cleanup.maps.retired.(*fakeBridgeMap).values)
}

func TestCleanupReauthorizationAfterMarkerPublicationPreservesIncarnation(t *testing.T) {
	handler := testMapHandler(nil, nil, nil)
	cleanup := testCleanup(handler)
	process := Identity{TID: 2, PID: 2, Namespace: 1}
	delete(cleanup.maps.authorized.(*fakeBridgeMap).values, process)
	retired := cleanup.maps.retired.(*fakeBridgeMap)
	retired.afterUpdate = func(any, any) {
		authorized := cleanup.maps.authorized.(*fakeBridgeMap)
		authorized.mu.Lock()
		authorized.values[process] = testProcessIncarnation
		authorized.mu.Unlock()
	}

	require.NoError(t, cleanup.Sweep())

	assert.Equal(t, testProcessIncarnation,
		cleanup.maps.incarnations.(*fakeBridgeMap).values[process])
	assert.NotZero(t, retired.values[retiredProcessKey{
		Process: process, ProcessIncarnation: testProcessIncarnation,
	}])
	assert.NotContains(t, cleanup.maps.threadMappingClaims.(*fakeBridgeMap).values, process)
}

func TestCleanupProcessClaimSerializesSameCapabilityRegistration(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	predecessor := activeTaskLink(owner, 10)
	successor := activeTaskLink(owner, 11)
	process := javaProcessIdentity(child)

	t.Run("cleanup wins P before registration", func(t *testing.T) {
		cleanup := testCleanup(testMapHandler(nil, map[Identity]any{child: predecessor}, nil))
		cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
		delete(cleanup.maps.incarnations.(*fakeBridgeMap).values, process)
		claims := cleanup.maps.threadMappingClaims.(*fakeBridgeMap)
		tasks := cleanup.maps.tasks.(*fakeBridgeMap)
		registrationBlocked := false
		claims.afterUpdate = func(key, _ any) {
			if key != process {
				return
			}
			registration := threadMappingClaimValue{
				Child: child, ProcessIncarnation: testProcessIncarnation,
			}
			registrationBlocked = errors.Is(
				claims.Update(&process, &registration, ebpf.UpdateNoExist),
				ebpf.ErrKeyExist,
			)
		}
		claims.afterDelete = func(key any) {
			if key == process {
				cleanup.maps.incarnations.(*fakeBridgeMap).values[process] = testProcessIncarnation
				tasks.values[child] = successor
			}
		}

		require.NoError(t, cleanup.Sweep())
		assert.True(t, registrationBlocked)
		assert.Zero(t, tasks.deleteCount,
			"incarnation absence without an exact marker cannot delete an alias-owning task")
		assert.Equal(t, successor, tasks.values[child],
			"registration may publish only after cleanup releases P")
		assert.Empty(t, claims.values)
	})

	t.Run("registration wins P before cleanup", func(t *testing.T) {
		cleanup := testCleanup(testMapHandler(nil, map[Identity]any{child: predecessor}, nil))
		cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
		delete(cleanup.maps.incarnations.(*fakeBridgeMap).values, process)
		registration := threadMappingClaimValue{
			Child: child, ProcessIncarnation: testProcessIncarnation,
		}
		claims := cleanup.maps.threadMappingClaims.(*fakeBridgeMap)
		claims.values[process] = registration

		require.NoError(t, cleanup.Sweep())
		assert.Equal(t, predecessor, cleanup.maps.tasks.(*fakeBridgeMap).values[child])
		assert.Equal(t, registration, claims.values[process])
	})
}

func TestCleanupRecoversProcessAndTaskClaimsBeforeLiveRegistration(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	link := activeTaskLink(owner, 10)
	cleanup := testCleanup(testMapHandler(nil, map[Identity]any{child: link}, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	process := javaProcessIdentity(child)
	processClaim, valid := javaRemoteParentProcessCleanupClaim(
		40*time.Second, process, testProcessIncarnation,
	)
	require.True(t, valid)
	taskClaim, valid := javaRemoteParentTaskCleanupClaim(
		40*time.Second, testProcessIncarnation,
	)
	require.True(t, valid)
	cleanup.maps.threadMappingClaims.(*fakeBridgeMap).values[process] = processClaim
	cleanup.maps.taskClaims.(*fakeBridgeMap).values[child] = taskClaim

	require.NoError(t, cleanup.Sweep())
	assert.Equal(t, link, cleanup.maps.tasks.(*fakeBridgeMap).values[child])
	assert.Empty(t, cleanup.maps.taskClaims.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.threadMappingClaims.(*fakeBridgeMap).values)
}

func TestCleanupExitMarkerQuiescesExactVisibleIncarnation(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	link := activeTaskLink(owner, 10)
	cleanup := testCleanup(testMapHandler(nil, map[Identity]any{child: link}, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	process := javaProcessIdentity(child)
	retiredKey := retiredProcessKey{
		Process: process, ProcessIncarnation: testProcessIncarnation,
	}
	cleanup.maps.retired.(*fakeBridgeMap).values[retiredKey] = uint64(40 * time.Second)

	require.NoError(t, cleanup.Sweep())
	assert.NotContains(t, cleanup.maps.tasks.(*fakeBridgeMap).values, child)
	assert.NotContains(t, cleanup.maps.incarnations.(*fakeBridgeMap).values, process)
	assert.NotContains(t, cleanup.maps.retired.(*fakeBridgeMap).values, retiredKey)
	assert.Empty(t, cleanup.maps.threadMappingClaims.(*fakeBridgeMap).values)
}

func TestCleanupFullDisjointHandoffMapsMakeProgress(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	process := javaProcessIdentity(child)
	resolvedKey := handoffKey{
		PID: 9, Namespace: child.Namespace, Token: 88,
		ProcessIncarnation: testProcessIncarnation,
	}
	retiredKey := handoffKey{
		PID: child.PID, Namespace: child.Namespace, Token: 77,
		ProcessIncarnation: testProcessIncarnation,
	}
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	delete(cleanup.maps.incarnations.(*fakeBridgeMap).values, process)
	seedProcessRetirementForTest(cleanup, process, testProcessIncarnation)

	claims := cleanup.maps.handoffClaims.(*fakeBridgeMap)
	claims.maxEntries = 1
	claims.values[resolvedKey] = handoffClaimValue{
		ObservedMonotonicNS: uint64(10*time.Second) | javaRemoteParentTaskCleanupClaimTag,
		ProcessIncarnation:  testProcessIncarnation,
	}

	handoffs := cleanup.maps.handoffs.(*fakeBridgeMap)
	handoffs.values[retiredKey] = activeTaskLink(owner, 10)
	mutations := cleanup.maps.handoffMutations.(*fakeBridgeMap)
	mutations.maxEntries = 1
	mutation, valid := javaRemoteParentTaskCleanupClaim(
		40*time.Second, testProcessIncarnation,
	)
	require.True(t, valid)
	mutations.values[retiredKey] = mutation

	require.NoError(t, cleanup.Sweep())
	assert.Empty(t, handoffs.values,
		"recovering the full M entry must retire H without first inserting C")
	assert.Empty(t, claims.values,
		"the resolved full-C entry must be reclaimed after M recovery frees capacity")
	assert.Empty(t, mutations.values)
	assert.Empty(t, cleanup.maps.threadMappingClaims.(*fakeBridgeMap).values)
}

func TestCleanupRecoversProcessAndHandoffMutationClaims(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	process := javaProcessIdentity(child)
	key := handoffKey{
		PID: child.PID, Namespace: child.Namespace, Token: 77,
		ProcessIncarnation: testProcessIncarnation,
	}
	handoff := activeTaskLink(owner, 10)

	for _, test := range []struct {
		name    string
		retired bool
	}{
		{name: "live capability"},
		{name: "retired capability", retired: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
			cleanup.maps.handoffs.(*fakeBridgeMap).values[key] = handoff
			processClaim, valid := javaRemoteParentProcessCleanupClaim(
				40*time.Second, process, testProcessIncarnation,
			)
			require.True(t, valid)
			mutation, valid := javaRemoteParentTaskCleanupClaim(
				40*time.Second, testProcessIncarnation,
			)
			require.True(t, valid)
			cleanup.maps.threadMappingClaims.(*fakeBridgeMap).values[process] = processClaim
			cleanup.maps.handoffMutations.(*fakeBridgeMap).values[key] = mutation
			if test.retired {
				delete(cleanup.maps.incarnations.(*fakeBridgeMap).values, process)
				seedProcessRetirementForTest(cleanup, process, testProcessIncarnation)
			}

			require.NoError(t, cleanup.Sweep())
			if test.retired {
				assert.NotContains(t, cleanup.maps.handoffs.(*fakeBridgeMap).values, key)
				assert.NotContains(t, cleanup.maps.handoffClaims.(*fakeBridgeMap).values, key)
			} else {
				assert.Equal(t, handoff, cleanup.maps.handoffs.(*fakeBridgeMap).values[key])
				assert.NotContains(t, cleanup.maps.handoffClaims.(*fakeBridgeMap).values, key,
					"live recovery must not terminalize H")
			}
			assert.Empty(t, cleanup.maps.handoffMutations.(*fakeBridgeMap).values)
			assert.Empty(t, cleanup.maps.threadMappingClaims.(*fakeBridgeMap).values)
		})
	}
}

func TestCleanupRetiredTaskClaimPreservesSuccessorRaces(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	predecessor := activeTaskLink(owner, 10)
	successor := activeTaskLink(owner, 11)
	successor.ProcessIncarnation++
	process := javaProcessIdentity(child)

	t.Run("replacement before claim", func(t *testing.T) {
		cleanup := testCleanup(testMapHandler(nil, map[Identity]any{child: predecessor}, nil))
		cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
		cleanup.maps.incarnations.(*fakeBridgeMap).values[process] = successor.ProcessIncarnation
		seedProcessRetirementForTest(cleanup, process, predecessor.ProcessIncarnation)
		tasks := cleanup.maps.tasks.(*fakeBridgeMap)
		claims := cleanup.maps.taskClaims.(*fakeBridgeMap)
		claims.beforeUpdate = func(any, any, ebpf.MapUpdateFlags) {
			tasks.values[child] = successor
		}

		require.NoError(t, cleanup.Sweep())
		assert.Equal(t, successor, tasks.values[child])
		assert.Empty(t, claims.values)
	})

	t.Run("publisher waits for exact release", func(t *testing.T) {
		cleanup := testCleanup(testMapHandler(nil, map[Identity]any{child: predecessor}, nil))
		cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
		delete(cleanup.maps.incarnations.(*fakeBridgeMap).values, process)
		seedProcessRetirementForTest(cleanup, process, predecessor.ProcessIncarnation)
		tasks := cleanup.maps.tasks.(*fakeBridgeMap)
		claims := cleanup.maps.taskClaims.(*fakeBridgeMap)
		publisherBlocked := false
		claims.afterUpdate = func(key, _ any) {
			_, publisherBlocked = claims.values[key]
		}
		claims.afterDelete = func(key any) {
			if key == child {
				tasks.values[child] = successor
			}
		}

		require.NoError(t, cleanup.Sweep())
		assert.True(t, publisherBlocked)
		assert.Equal(t, successor, tasks.values[child],
			"no task mutation may occur after releasing T(execution)")
		assert.Empty(t, claims.values)
	})
}

func TestCleanupRetiredTaskClaimContentionAndRetirementRevalidation(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	link := activeTaskLink(owner, 10)
	process := javaProcessIdentity(child)

	t.Run("foreign claim preserves task", func(t *testing.T) {
		cleanup := testCleanup(testMapHandler(nil, map[Identity]any{child: link}, nil))
		cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
		delete(cleanup.maps.incarnations.(*fakeBridgeMap).values, process)
		foreign := handoffClaimValue{
			ObservedMonotonicNS: uint64(40 * time.Second),
			ProcessIncarnation:  testProcessIncarnation,
		}
		claims := cleanup.maps.taskClaims.(*fakeBridgeMap)
		claims.values[child] = foreign

		require.NoError(t, cleanup.Sweep())
		assert.Equal(t, link, cleanup.maps.tasks.(*fakeBridgeMap).values[child])
		assert.Equal(t, foreign, claims.values[child])
	})

	t.Run("retirement revoked under claim", func(t *testing.T) {
		cleanup := testCleanup(testMapHandler(nil, map[Identity]any{child: link}, nil))
		cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
		incarnations := cleanup.maps.incarnations.(*fakeBridgeMap)
		delete(incarnations.values, process)
		seedProcessRetirementForTest(cleanup, process, link.ProcessIncarnation)
		claims := cleanup.maps.taskClaims.(*fakeBridgeMap)
		claims.afterUpdate = func(any, any) {
			incarnations.values[process] = testProcessIncarnation
		}

		require.NoError(t, cleanup.Sweep())
		assert.Equal(t, link, cleanup.maps.tasks.(*fakeBridgeMap).values[child])
		assert.Empty(t, claims.values)
	})
}

func TestCleanupRecoversTaggedRetiredTaskClaim(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	link := activeTaskLink(owner, 10)
	cleanup := testCleanup(testMapHandler(nil, map[Identity]any{child: link}, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	process := javaProcessIdentity(child)
	delete(cleanup.maps.incarnations.(*fakeBridgeMap).values, process)
	seedProcessRetirementForTest(cleanup, process, link.ProcessIncarnation)
	claim, valid := javaRemoteParentTaskCleanupClaim(40*time.Second, testProcessIncarnation)
	require.True(t, valid)
	cleanup.maps.taskClaims.(*fakeBridgeMap).values[child] = claim

	require.NoError(t, cleanup.Sweep())
	assert.Empty(t, cleanup.maps.tasks.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.taskClaims.(*fakeBridgeMap).values)
}

func TestCleanupRecoveredTaskClaimReleasesForLiveCapability(t *testing.T) {
	for _, test := range []struct {
		name          string
		initiallyLive bool
	}{
		{name: "already live", initiallyLive: true},
		{name: "becomes live before deletion"},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			child := Identity{TID: 4, PID: 2, Namespace: 1}
			link := activeTaskLink(owner, 10)
			successor := activeTaskLink(owner, 11)
			cleanup := testCleanup(testMapHandler(nil, map[Identity]any{child: link}, nil))
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
			process := javaProcessIdentity(child)
			incarnations := cleanup.maps.incarnations.(*fakeBridgeMap)
			if !test.initiallyLive {
				delete(incarnations.values, process)
			}
			claim, valid := javaRemoteParentTaskCleanupClaim(
				40*time.Second, testProcessIncarnation,
			)
			require.True(t, valid)
			claims := cleanup.maps.taskClaims.(*fakeBridgeMap)
			claims.values[child] = claim
			tasks := cleanup.maps.tasks.(*fakeBridgeMap)
			if !test.initiallyLive {
				tasks.afterLookup = func(count int) {
					if count == 1 {
						incarnations.values[process] = testProcessIncarnation
					}
				}
			}
			published := false
			claims.afterDelete = func(key any) {
				if key == child {
					published = true
					tasks.values[child] = successor
				}
			}

			require.NoError(t, cleanup.Sweep())
			assert.True(t, published)
			assert.Zero(t, tasks.deleteCount)
			assert.Equal(t, successor, tasks.values[child])
			assert.Empty(t, claims.values)
		})
	}
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
	handoff := handoffKey{
		PID: child.PID, Namespace: child.Namespace, Token: 77,
		ProcessIncarnation: testProcessIncarnation,
	}
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

func TestCleanupRemovesOnlyRetiredCapabilityHandoffs(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	process := javaProcessIdentity(owner)
	predecessorIncarnation := testProcessIncarnation
	successorIncarnation := testProcessIncarnation + 1
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	cleanup.maps.incarnations.(*fakeBridgeMap).values[process] = successorIncarnation
	cleanup.maps.authorized.(*fakeBridgeMap).values[process] = successorIncarnation
	cleanup.maps.retired.(*fakeBridgeMap).values[retiredProcessKey{
		Process:            process,
		ProcessIncarnation: predecessorIncarnation,
	}] = uint64(10 * time.Second)

	predecessor := activeTaskLink(owner, 10)
	predecessor.ProcessIncarnation = predecessorIncarnation
	malformedPredecessor := predecessor
	malformedPredecessor.Owner.PID++
	malformedPredecessor.Reserved = 1
	successor := activeTaskLink(owner, 11)
	successor.ProcessIncarnation = successorIncarnation
	malformedSuccessor := successor
	malformedSuccessor.Reserved = 1
	handoffs := cleanup.maps.handoffs.(*fakeBridgeMap)
	retiredKey := handoffKey{
		PID: owner.PID, Namespace: owner.Namespace, Token: 1,
		ProcessIncarnation: predecessorIncarnation,
	}
	malformedRetiredKey := retiredKey
	malformedRetiredKey.Token = 2
	liveKey := handoffKey{
		PID: owner.PID, Namespace: owner.Namespace, Token: 3,
		ProcessIncarnation: successorIncarnation,
	}
	malformedLiveKey := liveKey
	malformedLiveKey.Token = 4
	handoffs.values[retiredKey] = predecessor
	handoffs.values[malformedRetiredKey] = malformedPredecessor
	handoffs.values[liveKey] = successor
	handoffs.values[malformedLiveKey] = malformedSuccessor

	require.NoError(t, cleanup.Sweep())
	assert.NotContains(t, handoffs.values, retiredKey)
	assert.NotContains(t, handoffs.values, malformedRetiredKey)
	assert.Equal(t, successor, handoffs.values[liveKey])
	assert.Equal(t, malformedSuccessor, handoffs.values[malformedLiveKey])
}

func TestCleanupRequiresExactRetirementMarkerBeforeCarrierReplaySeparation(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	process := javaProcessIdentity(owner)
	delete(cleanup.maps.incarnations.(*fakeBridgeMap).values, process)
	key := handoffKey{
		PID: owner.PID, Namespace: owner.Namespace, Token: 1,
		ProcessIncarnation: testProcessIncarnation,
	}
	link := activeTaskLink(owner, 10)
	handoffs := cleanup.maps.handoffs.(*fakeBridgeMap)
	handoffs.values[key] = link
	replayKey := aliasReplayKey{
		Owner:               link.Owner,
		Generation:          link.Generation,
		ObservedMonotonicNS: link.ObservedMonotonicNS,
		ProcessIncarnation:  link.ProcessIncarnation,
	}
	replay := boundAliasReplayForTest(aliasReplayValue{
		TransitionMonotonicNS: uint64(20 * time.Second),
		References:            1,
		Lifecycle:             lifecycleStale,
	})
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	replays.values[replayKey] = replay

	require.NoError(t, cleanup.Sweep())
	assert.Equal(t, link, handoffs.values[key])
	assert.Equal(t, replay, replays.values[replayKey],
		"incarnation absence under P cannot strand a positive replay by deleting its carrier")

	seedProcessRetirementForTest(cleanup, process, testProcessIncarnation)
	require.NoError(t, cleanup.Sweep())
	assert.NotContains(t, handoffs.values, key)
	assert.Contains(t, replays.values, replayKey)

	now += javaRemoteParentMinimumFenceAge
	require.NoError(t, cleanup.Sweep())
	assert.NotContains(t, replays.values, replayKey)
}

func TestCleanupRetiredHandoffPreservesSameKeyReplacement(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	process := javaProcessIdentity(owner)
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	cleanup.maps.incarnations.(*fakeBridgeMap).values[process] = testProcessIncarnation + 1
	cleanup.maps.authorized.(*fakeBridgeMap).values[process] = testProcessIncarnation + 1
	seedProcessRetirementForTest(cleanup, process, testProcessIncarnation)
	key := handoffKey{
		PID: owner.PID, Namespace: owner.Namespace, Token: 1,
		ProcessIncarnation: testProcessIncarnation,
	}
	expected := activeTaskLink(owner, 10)
	replacement := activeTaskLink(owner, 11)
	handoffs := cleanup.maps.handoffs.(*fakeBridgeMap)
	handoffs.values[key] = expected
	handoffs.afterLookup = func(count int) {
		if count != 1 {
			return
		}
		handoffs.mu.Lock()
		handoffs.values[key] = replacement
		handoffs.mu.Unlock()
	}

	require.NoError(t, cleanup.Sweep())
	assert.Equal(t, replacement, handoffs.values[key])
}

func TestCleanupRetiredHandoffNoLongerPinsPositiveAliasReplay(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	process := javaProcessIdentity(owner)
	predecessorIncarnation := testProcessIncarnation
	successorIncarnation := testProcessIncarnation + 1
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.maps.incarnations.(*fakeBridgeMap).values[process] = successorIncarnation
	cleanup.maps.retired.(*fakeBridgeMap).values[retiredProcessKey{
		Process:            process,
		ProcessIncarnation: predecessorIncarnation,
	}] = uint64(90 * time.Second)
	replayKey := aliasReplayKey{
		Owner:               owner,
		Generation:          10,
		ObservedMonotonicNS: uint64(90 * time.Second),
		ProcessIncarnation:  predecessorIncarnation,
	}
	cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey] = boundAliasReplayForTest(aliasReplayValue{
		TransitionMonotonicNS: uint64(90 * time.Second),
		References:            1,
		Lifecycle:             lifecycleStale,
	})
	handoff := handoffKey{
		PID: owner.PID, Namespace: owner.Namespace, Token: 1,
		ProcessIncarnation: predecessorIncarnation,
	}
	link := activeTaskLink(owner, replayKey.Generation)
	link.ObservedMonotonicNS = replayKey.ObservedMonotonicNS
	link.ProcessIncarnation = predecessorIncarnation
	cleanup.maps.handoffs.(*fakeBridgeMap).values[handoff] = link
	now := 100 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }

	require.NoError(t, cleanup.Sweep())
	assert.NotContains(t, cleanup.maps.handoffs.(*fakeBridgeMap).values, handoff)
	assert.Contains(t, cleanup.maps.aliasReplays.(*fakeBridgeMap).values, replayKey)

	now += javaRemoteParentMinimumFenceAge
	require.NoError(t, cleanup.Sweep())
	assert.NotContains(t, cleanup.maps.aliasReplays.(*fakeBridgeMap).values, replayKey)
}

func TestCleanupReclaimsClaimCapacityAroundRetiredHandoff(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	process := javaProcessIdentity(owner)
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	delete(cleanup.maps.incarnations.(*fakeBridgeMap).values, process)
	seedProcessRetirementForTest(cleanup, process, testProcessIncarnation)

	resolvedKey := handoffKey{
		PID: 9, Namespace: 1, Token: 8,
		ProcessIncarnation: testProcessIncarnation,
	}
	retiredKey := handoffKey{
		PID: owner.PID, Namespace: owner.Namespace, Token: 7,
		ProcessIncarnation: testProcessIncarnation,
	}
	claims := cleanup.maps.handoffClaims.(*fakeBridgeMap)
	claims.maxEntries = 1
	claims.values[resolvedKey] = handoffClaimValue{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
	}
	handoffs := cleanup.maps.handoffs.(*fakeBridgeMap)
	handoffs.values[retiredKey] = activeTaskLink(owner, 10)

	require.NoError(t, cleanup.Sweep())
	assert.NotContains(t, handoffs.values, retiredKey,
		"retired-H cleanup must not depend on inserting another C entry")
	assert.Empty(t, claims.values,
		"the recurring no-H pass must reclaim resolved admission tickets")
	assert.Empty(t, cleanup.maps.handoffMutations.(*fakeBridgeMap).values)
}

func TestCleanupReclaimsResolvedHandoffClaimUnderMutation(t *testing.T) {
	key := handoffKey{
		PID: 1, Namespace: 2, Token: 3,
		ProcessIncarnation: testProcessIncarnation,
	}
	claim := handoffClaimValue{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
	}

	t.Run("exact no-H claim", func(t *testing.T) {
		cleanup := testCleanup(testMapHandler(nil, nil, nil))
		cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
		claims := cleanup.maps.handoffClaims.(*fakeBridgeMap)
		claims.values[key] = claim

		require.NoError(t, cleanup.Sweep())
		assert.NotContains(t, claims.values, key)
		assert.Empty(t, cleanup.maps.handoffMutations.(*fakeBridgeMap).values)
	})

	t.Run("second H check observes a publisher", func(t *testing.T) {
		cleanup := testCleanup(testMapHandler(nil, nil, nil))
		cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
		claims := cleanup.maps.handoffClaims.(*fakeBridgeMap)
		claims.values[key] = claim
		handoffs := cleanup.maps.handoffs.(*fakeBridgeMap)
		mutations := cleanup.maps.handoffMutations.(*fakeBridgeMap)
		carrier := activeTaskLink(Identity{TID: 4, PID: 1, Namespace: 2}, 10)
		lookupsUnderMutation := 0
		handoffs.afterLookupResult = func(lookupKey any, err error) {
			if lookupKey != key {
				return
			}
			assert.Contains(t, mutations.values, key)
			lookupsUnderMutation++
			if lookupsUnderMutation == 1 && errors.Is(err, ebpf.ErrKeyNotExist) {
				handoffs.values[key] = carrier
			}
		}

		require.NoError(t, cleanup.Sweep())
		assert.GreaterOrEqual(t, lookupsUnderMutation, 2)
		assert.Equal(t, carrier, handoffs.values[key])
		assert.Equal(t, claim, claims.values[key])
		assert.Empty(t, mutations.values)
	})

	t.Run("claim replacement after enumeration", func(t *testing.T) {
		cleanup := testCleanup(testMapHandler(nil, nil, nil))
		cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
		claims := cleanup.maps.handoffClaims.(*fakeBridgeMap)
		claims.values[key] = claim
		replacement := claim
		replacement.ObservedMonotonicNS++
		claims.afterIterate = func() { claims.values[key] = replacement }

		require.NoError(t, cleanup.Sweep())
		assert.NotContains(t, claims.values, key,
			"the post-pass may safely reclaim the replacement after a new exact snapshot")
		assert.Empty(t, cleanup.maps.handoffMutations.(*fakeBridgeMap).values)
	})

	t.Run("delete uncertainty retains recoverable M", func(t *testing.T) {
		cleanup := testCleanup(testMapHandler(nil, nil, nil))
		cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
		claims := cleanup.maps.handoffClaims.(*fakeBridgeMap)
		claims.values[key] = claim
		injected := errors.New("injected handoff claim delete failure")
		claims.deleteErr = injected

		err := cleanup.Sweep()
		require.ErrorContains(t, err, injected.Error())
		assert.Equal(t, claim, claims.values[key])
		mutations := cleanup.maps.handoffMutations.(*fakeBridgeMap)
		mutation, present := mutations.values[key].(handoffClaimValue)
		require.True(t, present)
		assert.True(t, validJavaRemoteParentTaskCleanupClaim(mutation))

		claims.deleteErr = nil
		require.NoError(t, cleanup.Sweep())
		assert.NotContains(t, claims.values, key)
		assert.Empty(t, mutations.values)
		assert.Empty(t, cleanup.maps.threadMappingClaims.(*fakeBridgeMap).values)
	})
}

func terminalHandoffCleanupFixture(
	t *testing.T,
	references uint32,
) (*Cleanup, handoffKey, handoffClaimValue, taskLink, stateKey, aliasReplayKey) {
	t.Helper()
	owner := Identity{TID: 4, PID: 1, Namespace: 2}
	const generation = uint64(10)
	handler := testMapHandler(map[Identity]any{
		owner: validEncodedRecord(t, generation),
	}, nil, nil)
	process := javaProcessIdentity(owner)
	handler.authorized.(*fakeBridgeMap).values[process] = testProcessIncarnation
	handler.incarnations.(*fakeBridgeMap).values[process] = testProcessIncarnation

	cleanup := testCleanup(handler)
	cleanup.monoTimeNow = func() time.Duration { return 20 * time.Second }
	key := handoffKey{
		PID: owner.PID, Namespace: owner.Namespace, Token: 3,
		ProcessIncarnation: testProcessIncarnation,
	}
	claim := handoffClaimValue{
		ObservedMonotonicNS: uint64(10*time.Second) | javaRemoteParentTaskCleanupClaimTag,
		ProcessIncarnation:  testProcessIncarnation,
	}
	carrier := activeTaskLink(owner, generation)
	cleanup.maps.handoffClaims.(*fakeBridgeMap).values[key] = claim
	cleanup.maps.handoffs.(*fakeBridgeMap).values[key] = carrier

	generationKey := stateKey{Owner: owner, Generation: generation}
	state := cleanup.maps.states.(*fakeBridgeMap).values[generationKey].(stateValue)
	state.Aliases = references
	cleanup.maps.states.(*fakeBridgeMap).values[generationKey] = state
	replayKey := aliasReplayKeyForState(generationKey, state)
	replay := boundAliasReplayForStateForTest(handler, generationKey, state, aliasReplayValue{
		TransitionMonotonicNS: state.ObservedMonotonicNS,
		References:            references,
		Lifecycle:             lifecycleActive,
	})
	cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey] = replay
	return cleanup, key, claim, carrier, generationKey, replayKey
}

func deleteTerminalHandoffClaimAfterHObservation(
	t *testing.T,
	cleanup *Cleanup,
	key handoffKey,
) *bool {
	t.Helper()
	deleted := new(bool)
	handoffs := cleanup.maps.handoffs.(*fakeBridgeMap)
	handoffs.afterLookupResult = func(lookupKey any, err error) {
		if *deleted || lookupKey != key || err != nil {
			return
		}
		assert.Contains(t, cleanup.maps.handoffMutations.(*fakeBridgeMap).values, key)
		process := Identity{TID: key.PID, PID: key.PID, Namespace: key.Namespace}
		assert.Contains(t, cleanup.maps.threadMappingClaims.(*fakeBridgeMap).values, process)
		delete(cleanup.maps.handoffClaims.(*fakeBridgeMap).values, key)
		*deleted = true
	}
	return deleted
}

func assertTerminalHandoffReferencesReleased(
	t *testing.T,
	cleanup *Cleanup,
	generationKey stateKey,
	replayKey aliasReplayKey,
) {
	t.Helper()
	if state, present := cleanup.maps.states.(*fakeBridgeMap).values[generationKey].(stateValue); present {
		assert.Zero(t, state.Aliases)
	}
	if replay, present := cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey].(aliasReplayValue); present {
		assert.Zero(t, replay.References)
	}
}

func TestCleanupDrainsHandoffWhenTerminalClaimDisappearsUnderMutation(t *testing.T) {
	t.Run("terminal delete after H observation converges", func(t *testing.T) {
		cleanup, key, _, carrier, generationKey, replayKey := terminalHandoffCleanupFixture(t, 1)
		deleted := deleteTerminalHandoffClaimAfterHObservation(t, cleanup, key)
		prepared := false
		cleanup.maps.handoffMutations.(*fakeBridgeMap).afterUpdate = func(_ any, value any) {
			prepared = prepared || validJavaRemoteParentTerminalHandoffCleanupClaim(
				value.(handoffClaimValue),
			)
		}
		counterUpdateFenced := false
		cleanup.maps.aliasReplays.(*fakeBridgeMap).beforeUpdate = func(
			updatedKey any,
			updatedValue any,
			_ ebpf.MapUpdateFlags,
		) {
			if updatedKey != replayKey || updatedValue.(aliasReplayValue).References != 0 {
				return
			}
			mutation := cleanup.maps.handoffMutations.(*fakeBridgeMap).values[key].(handoffClaimValue)
			claimKey, claim, valid := terminalHandoffGenerationCleanupClaim(mutation, carrier)
			require.True(t, valid)
			assert.Equal(t, claim, cleanup.maps.claims.(*fakeBridgeMap).values[claimKey])
			counterUpdateFenced = true
		}

		require.NoError(t, cleanup.Sweep())
		require.True(t, *deleted)
		assert.True(t, prepared)
		assert.True(t, counterUpdateFenced)
		assert.NotContains(t, cleanup.maps.handoffClaims.(*fakeBridgeMap).values, key)
		assert.NotContains(t, cleanup.maps.handoffs.(*fakeBridgeMap).values, key)
		assert.Empty(t, cleanup.maps.handoffMutations.(*fakeBridgeMap).values)
		assert.Empty(t, cleanup.maps.threadMappingClaims.(*fakeBridgeMap).values)
		assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
		assertTerminalHandoffReferencesReleased(t, cleanup, generationKey, replayKey)
	})

	t.Run("claim replacement is not a terminal delete", func(t *testing.T) {
		cleanup, key, claim, carrier, generationKey, replayKey := terminalHandoffCleanupFixture(t, 1)
		replacement := claim
		replacement.ObservedMonotonicNS++
		replaced := false
		cleanup.maps.handoffs.(*fakeBridgeMap).afterLookupResult = func(
			lookupKey any,
			err error,
		) {
			if replaced || lookupKey != key || err != nil {
				return
			}
			cleanup.maps.handoffClaims.(*fakeBridgeMap).values[key] = replacement
			replaced = true
		}
		prepared := false
		cleanup.maps.handoffMutations.(*fakeBridgeMap).afterUpdate = func(_ any, value any) {
			prepared = prepared || validJavaRemoteParentTerminalHandoffCleanupClaim(
				value.(handoffClaimValue),
			)
		}

		require.NoError(t, cleanup.Sweep())
		require.True(t, replaced)
		assert.False(t, prepared)
		assert.Equal(t, replacement, cleanup.maps.handoffClaims.(*fakeBridgeMap).values[key])
		assert.Equal(t, carrier, cleanup.maps.handoffs.(*fakeBridgeMap).values[key])
		assert.Empty(t, cleanup.maps.handoffMutations.(*fakeBridgeMap).values)
		assert.Empty(t, cleanup.maps.threadMappingClaims.(*fakeBridgeMap).values)
		assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
		state := cleanup.maps.states.(*fakeBridgeMap).values[generationKey].(stateValue)
		assert.Equal(t, uint32(1), state.Aliases)
		replay := cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey].(aliasReplayValue)
		assert.Equal(t, uint32(1), replay.References)
	})

	t.Run("non-unique counts retain recoverable intent", func(t *testing.T) {
		cleanup, key, _, carrier, generationKey, replayKey := terminalHandoffCleanupFixture(t, 2)
		deleted := deleteTerminalHandoffClaimAfterHObservation(t, cleanup, key)

		require.NoError(t, cleanup.Sweep())
		require.True(t, *deleted)
		assert.Equal(t, carrier, cleanup.maps.handoffs.(*fakeBridgeMap).values[key])
		mutation := cleanup.maps.handoffMutations.(*fakeBridgeMap).values[key].(handoffClaimValue)
		assert.True(t, validJavaRemoteParentTaskCleanupClaim(mutation))
		assert.False(t, validJavaRemoteParentTerminalHandoffCleanupClaim(mutation))
		assert.NotEmpty(t, cleanup.maps.threadMappingClaims.(*fakeBridgeMap).values)
		claimKey, generationClaim, valid := terminalHandoffGenerationCleanupClaim(mutation, carrier)
		require.True(t, valid)
		assert.Equal(t, generationClaim, cleanup.maps.claims.(*fakeBridgeMap).values[claimKey])
		state := cleanup.maps.states.(*fakeBridgeMap).values[generationKey].(stateValue)
		assert.Equal(t, uint32(2), state.Aliases)
		replay := cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey].(aliasReplayValue)
		assert.Equal(t, uint32(2), replay.References)

		// A sibling carrier can finish its ordinary BPF release while P prevents
		// replacement retains. Recovery then proves that H owns the final pair.
		state.Aliases = 1
		cleanup.maps.states.(*fakeBridgeMap).values[generationKey] = state
		replay.References = 1
		cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey] = replay
		require.NoError(t, cleanup.Sweep())
		assert.NotContains(t, cleanup.maps.handoffs.(*fakeBridgeMap).values, key)
		assert.Empty(t, cleanup.maps.handoffMutations.(*fakeBridgeMap).values)
		assert.Empty(t, cleanup.maps.threadMappingClaims.(*fakeBridgeMap).values)
		assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
		assertTerminalHandoffReferencesReleased(t, cleanup, generationKey, replayKey)
	})

	t.Run("foreign generation claim preserves terminal H", func(t *testing.T) {
		cleanup, key, _, carrier, generationKey, replayKey := terminalHandoffCleanupFixture(t, 1)
		deleted := deleteTerminalHandoffClaimAfterHObservation(t, cleanup, key)
		foreign := testGenerationClaim(lifecycleConsumed)
		cleanup.maps.claims.(*fakeBridgeMap).values[generationKey] = foreign

		require.NoError(t, cleanup.Sweep())
		require.True(t, *deleted)
		assert.Equal(t, carrier, cleanup.maps.handoffs.(*fakeBridgeMap).values[key])
		assert.Equal(t, foreign, cleanup.maps.claims.(*fakeBridgeMap).values[generationKey])
		mutation := cleanup.maps.handoffMutations.(*fakeBridgeMap).values[key].(handoffClaimValue)
		assert.True(t, validJavaRemoteParentResolvedHandoffCleanupClaim(mutation))
		assert.False(t, validJavaRemoteParentTerminalHandoffCleanupClaim(mutation))
		state := cleanup.maps.states.(*fakeBridgeMap).values[generationKey].(stateValue)
		assert.Equal(t, uint32(1), state.Aliases)
		replay := cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey].(aliasReplayValue)
		assert.Equal(t, uint32(1), replay.References)

		delete(cleanup.maps.claims.(*fakeBridgeMap).values, generationKey)
		require.NoError(t, cleanup.Sweep())
		assert.NotContains(t, cleanup.maps.handoffs.(*fakeBridgeMap).values, key)
		assert.Empty(t, cleanup.maps.handoffMutations.(*fakeBridgeMap).values)
		assert.Empty(t, cleanup.maps.threadMappingClaims.(*fakeBridgeMap).values)
		assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
		assertTerminalHandoffReferencesReleased(t, cleanup, generationKey, replayKey)
	})

	t.Run("replay update error keeps phase M and P", func(t *testing.T) {
		cleanup, key, _, carrier, generationKey, replayKey := terminalHandoffCleanupFixture(t, 1)
		deleted := deleteTerminalHandoffClaimAfterHObservation(t, cleanup, key)
		injected := errors.New("injected terminal replay update failure")
		cleanup.maps.aliasReplays.(*fakeBridgeMap).updateErr = injected

		err := cleanup.Sweep()
		require.ErrorContains(t, err, injected.Error())
		require.True(t, *deleted)
		assert.Equal(t, carrier, cleanup.maps.handoffs.(*fakeBridgeMap).values[key])
		mutation := cleanup.maps.handoffMutations.(*fakeBridgeMap).values[key].(handoffClaimValue)
		assert.True(t, validJavaRemoteParentTerminalHandoffCleanupClaim(mutation))
		assert.NotEmpty(t, cleanup.maps.threadMappingClaims.(*fakeBridgeMap).values)
		claimKey, generationClaim, valid := terminalHandoffGenerationCleanupClaim(mutation, carrier)
		require.True(t, valid)
		assert.Equal(t, generationClaim, cleanup.maps.claims.(*fakeBridgeMap).values[claimKey])

		cleanup.maps.aliasReplays.(*fakeBridgeMap).updateErr = nil
		require.NoError(t, cleanup.Sweep())
		assert.NotContains(t, cleanup.maps.handoffs.(*fakeBridgeMap).values, key)
		assert.Empty(t, cleanup.maps.handoffMutations.(*fakeBridgeMap).values)
		assert.Empty(t, cleanup.maps.threadMappingClaims.(*fakeBridgeMap).values)
		assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
		assertTerminalHandoffReferencesReleased(t, cleanup, generationKey, replayKey)
	})
}

func TestCleanupPreservesMalformedHandoffClaims(t *testing.T) {
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
	cleanup.maps.authorized.(*fakeBridgeMap).values[process] = testProcessIncarnation + 1
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

func TestCleanupRetiredAliasedGenerationConvergesWithoutCurrentIncarnation(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, key.Generation)},
		map[Identity]any{child: activeTaskLink(owner, key.Generation)}, nil,
	)
	state := handler.states.(*fakeBridgeMap).values[key].(stateValue)
	replayKey := aliasReplayKeyForState(key, state)
	initialReplay := handler.aliasReplays.(*fakeBridgeMap).values[replayKey].(aliasReplayValue)
	cleanup := testCleanup(handler)
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	delete(cleanup.maps.incarnations.(*fakeBridgeMap).values, javaProcessIdentity(owner))

	sweepSeededGenerationToCompletion(t, cleanup, key, state.ProcessIncarnation)
	assert.NotContains(t, cleanup.maps.remoteParents.(*fakeBridgeMap).values, owner)
	assert.NotContains(t, cleanup.maps.owners.(*fakeBridgeMap).values, owner)
	assert.NotContains(t, cleanup.maps.states.(*fakeBridgeMap).values, key)
	assert.NotContains(t, cleanup.maps.generations.(*fakeBridgeMap).values, key)
	for _, value := range cleanup.maps.connections.(*fakeBridgeMap).values {
		assert.NotEqual(t, key.Generation, value.(connectionClaim).Generation)
	}
	for _, value := range cleanup.maps.cookieConnections.(*fakeBridgeMap).values {
		assert.NotEqual(t, key.Generation, value.(connectionClaim).Generation)
	}
	finalReplay := cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey].(aliasReplayValue)
	assert.True(t, validAliasReplayFinal(finalReplay))
	assert.Equal(t, lifecycleStale, finalReplay.Lifecycle)
	assert.Equal(t, aliasReplayBindingOf(initialReplay), aliasReplayBindingOf(finalReplay))
	assert.NotContains(t, cleanup.maps.claims.(*fakeBridgeMap).values, key)
	assert.NotContains(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values, owner)
	assert.NotContains(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values, key)
}

func TestCleanupDoesNotDeleteProcessIncarnation(t *testing.T) {
	process := Identity{TID: 2, PID: 2, Namespace: 1}
	handler := testMapHandler(nil, nil, nil)
	cleanup := testCleanup(handler)
	incarnations := cleanup.maps.incarnations.(*fakeBridgeMap)
	incarnations.values[process] = testProcessIncarnation + 1
	cleanup.maps.authorized.(*fakeBridgeMap).values[process] = testProcessIncarnation + 1
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

func TestCleanupNeverDeletesLiveTaskOrHandoffLinks(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	child := Identity{TID: 4, PID: 2, Namespace: 1}
	handoff := handoffKey{
		PID: child.PID, Namespace: child.Namespace, Token: 77,
		ProcessIncarnation: testProcessIncarnation,
	}
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
			authorized:                     handler.authorized.(cleanupMap),
			incarnations:                   handler.incarnations.(cleanupMap),
			connections:                    handler.connections.(cleanupMap),
			cookieConnections:              handler.cookieConnections.(cleanupMap),
			ambiguity:                      handler.ambiguity.(cleanupMap),
			owners:                         handler.owners.(cleanupMap),
			states:                         handler.states.(cleanupMap),
			generations:                    handler.generations.(cleanupMap),
			terminals:                      handler.terminals.(cleanupMap),
			claims:                         handler.claims.(cleanupMap),
			aliasReplays:                   handler.aliasReplays.(cleanupMap),
			ownerGuards:                    handler.ownerGuards.(cleanupMap),
			handoffs:                       newMap(),
			handoffClaims:                  newMap(),
			handoffMutations:               newMap(),
			taskClaims:                     newMap(),
			threadMappingClaims:            newMap(),
			retired:                        newMap(),
			sslPrewrite:                    newMap(),
			sslPrewriteConnectionAmbiguity: newMap(),
			sslPrewriteConnectionClaims:    newMap(),
			sslPrewriteConnectionOwners:    newMap(),
		},
		ttl:                  handler.ttl,
		monoTimeNow:          handler.monoTimeNow,
		aliasReplayNoCarrier: make(map[aliasReplayKey]aliasReplayNoCarrierObservation),
		processClaims:        make(map[Identity]threadMappingClaimValue),
		coordinator:          handler.coordinator,
	}
}

func seedProcessRetirementForTest(
	cleanup *Cleanup,
	process Identity,
	processIncarnation uint64,
) {
	cleanup.maps.retired.(*fakeBridgeMap).values[retiredProcessKey{
		Process:            process,
		ProcessIncarnation: processIncarnation,
	}] = uint64(time.Second)
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
	handler.remoteParents.(*fakeBridgeMap).values[owner] = validEncodedRecordObservedAt(t, 11, 40*time.Second)
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
	handler.remoteParents.(*fakeBridgeMap).values[owner] = validEncodedRecordObservedAt(t, 11, 40*time.Second)
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
				cleanup.maps.generations.(*fakeBridgeMap).iterateErr = errors.New("injected generation scan failure")
			},
		},
		{
			name: "state scan",
			inject: func(cleanup *Cleanup) {
				cleanup.maps.states.(*fakeBridgeMap).iterateErr = errors.New("injected state scan failure")
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
	require.NoError(t, cleanup.snapshotAliasReplayState())
	authorizeGenerationReplayScanForTest(cleanup, key)

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
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	key := stateKey{Owner: owner, Generation: 10}
	cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(10 * time.Second)
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, uint64(10*time.Second),
		cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
	claim, ok := cleanup.maps.claims.(*fakeBridgeMap).values[key].(generationClaim)
	require.True(t, ok)
	assert.Equal(t, uint64(now), claim.ObservedMonotonicNS)
	assert.Empty(t, guards.values)
	assert.Zero(t, guards.updateCount)

	now = 72*time.Second + time.Nanosecond
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	refreshed, ok := cleanup.maps.claims.(*fakeBridgeMap).values[key].(generationClaim)
	require.True(t, ok)
	assert.Equal(t, uint64(now), refreshed.ObservedMonotonicNS)
	assert.Empty(t, guards.values)
	assert.Zero(t, guards.updateCount)
	assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)

	now += 30*time.Second + time.Nanosecond
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
	assert.Empty(t, guards.values)
	assert.Zero(t, guards.updateCount)
	assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
}

func TestCleanupCapsOutstandingExactMarkerTailClaims(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	for i := range javaRemoteParentMaxExactTailClaims {
		tailKey := stateKey{
			Owner: Identity{
				TID: uint32(i + 100), PID: 99, Namespace: 1,
			},
			Generation: 1,
		}
		claims.values[tailKey] = exactMarkerTailClaimForTest(
			tailKey, uint64(40*time.Second),
		)
	}
	cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(10 * time.Second)

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Len(t, claims.values, javaRemoteParentMaxExactTailClaims)
	assert.NotContains(t, claims.values, key)
	assert.Equal(t, uint64(10*time.Second),
		cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
	assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
}

func TestCleanupExactMarkerTailCommitErrorConsumesAdmissionBudget(t *testing.T) {
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	for i := range javaRemoteParentMaxExactTailClaims - 1 {
		key := stateKey{
			Owner:      Identity{TID: uint32(i + 100), PID: 99, Namespace: 1},
			Generation: 1,
		}
		claims.values[key] = exactMarkerTailClaimForTest(key, uint64(40*time.Second))
	}
	first := stateKey{
		Owner: Identity{TID: 3, PID: 2, Namespace: 1}, Generation: 10,
	}
	second := stateKey{
		Owner: Identity{TID: 4, PID: 2, Namespace: 1}, Generation: 11,
	}
	markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
	markers.values[first] = uint64(10 * time.Second)
	markers.values[second] = uint64(10 * time.Second)
	claims.updateCommitErr = errors.New("injected committed update error")

	stats, err := cleanup.SweepWithStats()
	require.ErrorContains(t, err, "injected committed update error")
	assert.Equal(t, CleanupStats{}, stats)
	assert.Len(t, claims.values, javaRemoteParentMaxExactTailClaims)
	_, firstClaimed := claims.values[first]
	_, secondClaimed := claims.values[second]
	assert.NotEqual(t, firstClaimed, secondClaimed)
	assert.Equal(t, uint64(10*time.Second), markers.values[first])
	assert.Equal(t, uint64(10*time.Second), markers.values[second])
	assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
}

func TestCleanupExactMarkerTailUncertainUpdateStopsAdmission(t *testing.T) {
	for _, test := range []struct {
		name      string
		committed bool
	}{
		{name: "not committed"},
		{name: "committed with error", committed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
			claims := cleanup.maps.claims.(*fakeBridgeMap)
			for i := range javaRemoteParentMaxExactTailClaims - 1 {
				key := stateKey{
					Owner:      Identity{TID: uint32(i + 100), PID: 99, Namespace: 1},
					Generation: 1,
				}
				claims.values[key] = exactMarkerTailClaimForTest(
					key, uint64(40*time.Second),
				)
			}
			first := stateKey{
				Owner: Identity{TID: 3, PID: 2, Namespace: 1}, Generation: 10,
			}
			second := stateKey{
				Owner: Identity{TID: 4, PID: 2, Namespace: 1}, Generation: 11,
			}
			markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
			markers.values[first] = uint64(10 * time.Second)
			markers.values[second] = uint64(10 * time.Second)
			updateErr := errors.New("injected uncertain exact-tail update")
			lookupErr := errors.New("injected uncertain exact-tail readback")
			if test.committed {
				claims.updateCommitErr = updateErr
				claims.afterUpdate = func(any, any) { claims.lookupErr = lookupErr }
			} else {
				claims.updateErr = updateErr
				claims.afterFailedUpdate = func() { claims.lookupErr = lookupErr }
			}
			claims.afterLookupResult = func(_ any, errorValue error) {
				if errors.Is(errorValue, lookupErr) {
					claims.lookupErr = nil
				}
			}

			stats, err := cleanup.SweepWithStats()
			require.ErrorContains(t, err, updateErr.Error())
			require.ErrorContains(t, err, lookupErr.Error())
			assert.Equal(t, CleanupStats{}, stats)
			_, firstClaimed := claims.values[first]
			_, secondClaimed := claims.values[second]
			if test.committed {
				assert.Len(t, claims.values, javaRemoteParentMaxExactTailClaims)
				assert.NotEqual(t, firstClaimed, secondClaimed)
			} else {
				assert.Len(t, claims.values, javaRemoteParentMaxExactTailClaims-1)
				assert.False(t, firstClaimed)
				assert.False(t, secondClaimed)
			}
			assert.Equal(t, uint64(10*time.Second), markers.values[first])
			assert.Equal(t, uint64(10*time.Second), markers.values[second])
			assert.Equal(t, 1, claims.updateCount)
			assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
		})
	}
}

func TestCleanupExactMarkerTailAdmissionRetriesAfterMapError(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
	markers.values[key] = uint64(10 * time.Second)
	claims.updateErr = errors.New("injected claim capacity error")

	stats, err := cleanup.SweepWithStats()
	require.ErrorContains(t, err, "injected claim capacity error")
	assert.Equal(t, CleanupStats{}, stats)
	assert.Empty(t, claims.values)
	assert.Empty(t, guards.values)
	assert.Zero(t, guards.updateCount)
	assert.Equal(t, uint64(10*time.Second), markers.values[key])

	claims.updateErr = nil
	now++
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Contains(t, claims.values, key)
	assert.Empty(t, guards.values)
	assert.Zero(t, guards.updateCount)
	assert.Equal(t, uint64(10*time.Second), markers.values[key])
}

func TestCleanupOrdinaryClaimsDoNotConsumeExactTailBudget(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	const ordinaryClaims = javaRemoteParentMaxExactTailClaims + 100
	for i := range ordinaryClaims {
		ordinaryKey := stateKey{
			Owner:      Identity{TID: uint32(i + 100), PID: 99, Namespace: 1},
			Generation: 1,
		}
		claims.values[ordinaryKey] = generationClaim{
			ObservedMonotonicNS: uint64(40 * time.Second),
			ProcessIncarnation:  testProcessIncarnation,
			Lifecycle:           lifecycleConsumed,
		}
	}
	cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(10 * time.Second)

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Len(t, claims.values, ordinaryClaims+1)
	assert.Contains(t, claims.values, key)
	assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
}

func TestCleanupConcurrentUntaggedClaimsCannotConsumeOrForgeExactTailBudget(t *testing.T) {
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	for i := range javaRemoteParentMaxExactTailClaims - 1 {
		key := stateKey{
			Owner:      Identity{TID: uint32(i + 100), PID: 99, Namespace: 1},
			Generation: 1,
		}
		claims.values[key] = exactMarkerTailClaimForTest(key, uint64(40*time.Second))
	}
	insertUntagged := func(offset uint32) {
		for i := range javaRemoteParentMaxExactTailClaims {
			key := stateKey{
				Owner:      Identity{TID: uint32(i) + offset, PID: 98, Namespace: 1},
				Generation: 2,
			}
			// This intentionally resembles the historical synthetic shape, but
			// lacks the Go-only tag and therefore remains ordinary BPF authority.
			claims.values[key] = generationClaim{
				ObservedMonotonicNS: uint64(40 * time.Second),
				ProcessIncarnation:  key.Generation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{lifecycleAmbiguous},
			}
		}
	}
	insertUntagged(2000)
	firstMarker := stateKey{
		Owner: Identity{TID: 3, PID: 2, Namespace: 1}, Generation: 10,
	}
	secondMarker := stateKey{
		Owner: Identity{TID: 4, PID: 2, Namespace: 1}, Generation: 11,
	}
	markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
	markers.values[firstMarker] = uint64(10 * time.Second)
	markers.values[secondMarker] = uint64(10 * time.Second)
	armed := false
	markers.afterIterate = func() { armed = true }
	injected := false
	claims.afterIterate = func() {
		if !armed || injected {
			return
		}
		injected = true
		insertUntagged(4000)
	}

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	require.True(t, injected)
	_, firstClaimed := claims.values[firstMarker]
	_, secondClaimed := claims.values[secondMarker]
	assert.NotEqual(t, firstClaimed, secondClaimed)
	tagged := 0
	untagged := 0
	for rawKey, rawClaim := range claims.values {
		key := rawKey.(stateKey)
		claim := rawClaim.(generationClaim)
		if validExactMarkerTailCleanupClaim(key, claim) {
			tagged++
		} else if claim.Reserved == ([7]byte{lifecycleAmbiguous}) {
			untagged++
		}
	}
	assert.Equal(t, javaRemoteParentMaxExactTailClaims, tagged)
	assert.Equal(t, 2*javaRemoteParentMaxExactTailClaims, untagged)
	assert.Len(t, claims.values, 3*javaRemoteParentMaxExactTailClaims)
	assert.Equal(t, uint64(10*time.Second), markers.values[firstMarker])
	assert.Equal(t, uint64(10*time.Second), markers.values[secondMarker])
	assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
}

func TestCleanupExactMarkerTailBacklogConvergesInBoundedBatches(t *testing.T) {
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
	for i := range javaRemoteParentMaxExactTailClaims + 1 {
		key := stateKey{
			Owner:      Identity{TID: uint32(i + 100), PID: 99, Namespace: 1},
			Generation: 1,
		}
		markers.values[key] = uint64(10 * time.Second)
	}
	sweep := func() {
		t.Helper()
		stats, err := cleanup.SweepWithStats()
		require.NoError(t, err)
		assert.Equal(t, CleanupStats{}, stats)
		assert.Empty(t, guards.values)
		assert.Zero(t, guards.updateCount)
		for rawKey, rawClaim := range claims.values {
			assert.True(t, validExactMarkerTailCleanupClaim(
				rawKey.(stateKey), rawClaim.(generationClaim),
			))
		}
	}

	sweep()
	assert.Len(t, claims.values, javaRemoteParentMaxExactTailClaims)
	assert.Len(t, markers.values, javaRemoteParentMaxExactTailClaims+1)

	now = 72*time.Second + time.Nanosecond
	sweep()
	assert.Len(t, claims.values, javaRemoteParentMaxExactTailClaims)
	assert.Len(t, markers.values, 1)

	now += 30*time.Second + time.Nanosecond
	sweep()
	assert.Empty(t, claims.values)
	assert.Len(t, markers.values, 1)

	now++
	sweep()
	assert.Len(t, claims.values, 1)
	assert.Len(t, markers.values, 1)

	now += 30*time.Second + time.Nanosecond
	sweep()
	assert.Len(t, claims.values, 1)
	assert.Empty(t, markers.values)

	now += 30*time.Second + time.Nanosecond
	sweep()
	assert.Empty(t, claims.values)
	assert.Empty(t, markers.values)
}

func TestCleanupIncompleteClaimSnapshotDisablesExactTailAdmission(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(10 * time.Second)
	cleanup.maps.claims.(*fakeBridgeMap).iterateErr = errors.New("injected claim scan failure")

	stats, err := cleanup.SweepWithStats()
	require.ErrorContains(t, err, "injected claim scan failure")
	assert.Equal(t, CleanupStats{}, stats)
	assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
	assert.Equal(t, uint64(10*time.Second),
		cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
}

func TestCleanupExactTailAdmissionRequiresCompletePayloadSnapshots(t *testing.T) {
	for _, test := range []struct {
		name   string
		inject func(*Cleanup)
	}{
		{
			name: "generation",
			inject: func(cleanup *Cleanup) {
				cleanup.maps.generations.(*fakeBridgeMap).iterateErr = errors.New("injected scan failure")
			},
		},
		{
			name: "state",
			inject: func(cleanup *Cleanup) {
				cleanup.maps.states.(*fakeBridgeMap).iterateErr = errors.New("injected scan failure")
			},
		},
		{
			name: "connection",
			inject: func(cleanup *Cleanup) {
				cleanup.maps.connections.(*fakeBridgeMap).iterateErr = errors.New("injected scan failure")
			},
		},
		{
			name: "cookie connection",
			inject: func(cleanup *Cleanup) {
				cleanup.maps.cookieConnections.(*fakeBridgeMap).iterateErr = errors.New("injected scan failure")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
			cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(10 * time.Second)
			test.inject(cleanup)

			stats, err := cleanup.SweepWithStats()
			require.ErrorContains(t, err, "injected scan failure")
			assert.Equal(t, CleanupStats{}, stats)
			assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
			assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
			assert.Equal(t, uint64(10*time.Second),
				cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
		})
	}
}

func TestCleanupExactTailAdmissionDoesNotRequireAliasReplaySnapshot(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(10 * time.Second)
	cleanup.maps.aliasReplays.(*fakeBridgeMap).iterateErr = errors.New("injected scan failure")

	stats, err := cleanup.SweepWithStats()
	require.ErrorContains(t, err, "injected scan failure")
	assert.Equal(t, CleanupStats{}, stats)
	claim, present := cleanup.maps.claims.(*fakeBridgeMap).values[key].(generationClaim)
	require.True(t, present)
	assert.Equal(t, uint64(41*time.Second), claim.ObservedMonotonicNS)
	assert.Equal(t, key.Generation, claim.ProcessIncarnation)
	assert.Equal(t, [7]byte{
		0: lifecycleAmbiguous,
		6: generationGoProducerTag,
	}, claim.Reserved)
	assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
	assert.Equal(t, uint64(10*time.Second),
		cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
}

func TestCleanupValidTerminalWithoutGuardRemainsStatusOnly(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	terminal := terminalValue{
		Generation:          10,
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 100 * time.Second }
	cleanup.maps.terminals.(*fakeBridgeMap).values[owner] = terminal
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, terminal, cleanup.maps.terminals.(*fakeBridgeMap).values[owner])
	assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
	assert.Empty(t, guards.values)
	assert.Zero(t, guards.updateCount)
	assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
}

func TestCleanupFreshTerminalExclusivelyOwnsEveryGenericFenceShape(t *testing.T) {
	tests := []struct {
		name        string
		marker      *uint64
		claimOrigin *uint8
		guard       bool
	}{
		{name: "guard only", guard: true},
		{name: "claim only", claimOrigin: pointerTo(lifecycleConsumed)},
		{name: "claim and guard", claimOrigin: pointerTo(lifecyclePublishing), guard: true},
		{name: "zero reservation and guard", marker: pointerTo(uint64(0)), guard: true},
		{name: "zero reservation and semantic claim", marker: pointerTo(uint64(0)), claimOrigin: pointerTo(lifecycleConsumed)},
		{name: "zero reservation semantic tuple", marker: pointerTo(uint64(0)), claimOrigin: pointerTo(lifecycleConsumed), guard: true},
		{name: "zero reservation publishing tuple", marker: pointerTo(uint64(0)), claimOrigin: pointerTo(lifecyclePublishing), guard: true},
		{name: "marker only", marker: pointerTo(uint64(10 * time.Second))},
		{name: "marked claim without guard", marker: pointerTo(uint64(10 * time.Second)), claimOrigin: pointerTo(lifecycleConsumed)},
		{name: "marked semantic tuple", marker: pointerTo(uint64(10 * time.Second)), claimOrigin: pointerTo(lifecycleConsumed), guard: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			terminal := terminalValue{
				Generation:          key.Generation,
				ObservedMonotonicNS: uint64(40 * time.Second),
				ProcessIncarnation:  testProcessIncarnation,
				Lifecycle:           lifecycleConsumed,
			}
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
			terminals := cleanup.maps.terminals.(*fakeBridgeMap)
			claims := cleanup.maps.claims.(*fakeBridgeMap)
			guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
			markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
			terminals.values[owner] = terminal
			if test.claimOrigin != nil {
				claims.values[key] = generationClaim{
					ObservedMonotonicNS: uint64(10 * time.Second),
					ProcessIncarnation:  terminal.ProcessIncarnation,
					Lifecycle:           lifecycleCleanup,
					Reserved:            [7]byte{*test.claimOrigin},
				}
			}
			if test.guard {
				guards.values[owner] = generationClaim{
					ObservedMonotonicNS: uint64(10 * time.Second),
					ProcessIncarnation:  key.Generation,
					Lifecycle:           lifecycleCleanup,
					Reserved:            [7]byte{lifecyclePublishing},
				}
			}
			if test.marker != nil {
				markers.values[key] = *test.marker
			}
			claimsBefore := maps.Clone(claims.values)
			guardsBefore := maps.Clone(guards.values)
			markersBefore := maps.Clone(markers.values)

			stats, err := cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Equal(t, terminal, terminals.values[owner])
			assert.Equal(t, claimsBefore, claims.values)
			assert.Equal(t, guardsBefore, guards.values)
			assert.Equal(t, markersBefore, markers.values)
			assert.Zero(t, claims.updateCount)
			assert.Zero(t, claims.deleteCount)
			assert.Zero(t, guards.updateCount)
			assert.Zero(t, guards.deleteCount)
			assert.Zero(t, markers.updateCount)
			assert.Zero(t, markers.deleteCount)
		})
	}
}

func TestCleanupTerminalInsertedAfterEnumerationBlocksGenericRecovery(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	terminal := terminalValue{
		Generation:          key.Generation,
		ObservedMonotonicNS: uint64(40 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	terminals := cleanup.maps.terminals.(*fakeBridgeMap)
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
	markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
	guards.values[owner] = generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecyclePublishing},
	}
	markers.values[key] = uint64(10 * time.Second)
	terminals.afterIterate = func() { terminals.values[owner] = terminal }

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, terminal, terminals.values[owner])
	assert.Empty(t, claims.values)
	assert.Zero(t, claims.updateCount)
	assert.Len(t, guards.values, 1)
	assert.Zero(t, guards.deleteCount)
	assert.Equal(t, uint64(10*time.Second), markers.values[key])
	assert.Zero(t, markers.deleteCount)
}

func TestCleanupFailedTerminalClaimDoesNotFallThroughToGenericRecovery(t *testing.T) {
	for _, test := range []struct {
		name      string
		committed bool
	}{
		{name: "not committed"},
		{name: "committed with error", committed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			terminal := terminalValue{
				Generation:          key.Generation,
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  testProcessIncarnation,
				Lifecycle:           lifecycleConsumed,
			}
			guard := generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  key.Generation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{lifecyclePublishing},
			}
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
			terminals := cleanup.maps.terminals.(*fakeBridgeMap)
			claims := cleanup.maps.claims.(*fakeBridgeMap)
			guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
			markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
			terminals.values[owner] = terminal
			guards.values[owner] = guard
			markers.values[key] = uint64(10 * time.Second)
			injected := errors.New("injected terminal claim failure")
			if test.committed {
				claims.updateCommitErr = injected
			} else {
				claims.updateErr = injected
			}

			stats, err := cleanup.SweepWithStats()
			require.ErrorContains(t, err, injected.Error())
			assert.Equal(t, CleanupStats{}, stats)
			assert.Equal(t, terminal, terminals.values[owner])
			assert.Equal(t, guard, guards.values[owner])
			assert.Equal(t, uint64(10*time.Second), markers.values[key])
			assert.Equal(t, 1, claims.updateCount)
			if test.committed {
				claim, ok := claims.values[key].(generationClaim)
				require.True(t, ok)
				assert.Equal(t, terminal.ProcessIncarnation, claim.ProcessIncarnation)
				assert.Equal(t, [7]byte{terminal.Lifecycle}, claim.Reserved)
			} else {
				assert.Empty(t, claims.values)
			}
		})
	}
}

func TestCleanupArtifactClaimPinsTerminalInsertionAndReplacement(t *testing.T) {
	for _, test := range []struct {
		name        string
		seed        bool
		installHook func(*fakeBridgeMap, Identity, terminalValue) func() bool
	}{
		{
			name: "inserted after initial miss",
			installHook: func(terminals *fakeBridgeMap, owner Identity, terminal terminalValue) func() bool {
				injected := false
				terminals.afterLookupResult = func(key any, err error) {
					if !injected && key == owner && errors.Is(err, ebpf.ErrKeyNotExist) {
						injected = true
						terminals.values[owner] = terminal
					}
				}
				return func() bool { return injected }
			},
		},
		{
			name: "retained terminal replaced during revalidation",
			seed: true,
			installHook: func(terminals *fakeBridgeMap, owner Identity, terminal terminalValue) func() bool {
				injected := false
				terminals.afterLookup = func(count int) {
					if count == 2 {
						injected = true
						replacement := terminal
						replacement.ProcessIncarnation++
						terminals.values[owner] = replacement
					}
				}
				return func() bool { return injected }
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			terminal := terminalValue{
				Generation:          key.Generation,
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  testProcessIncarnation,
				Lifecycle:           lifecycleConsumed,
			}
			stateProcessIncarnation := key.Generation
			if test.seed {
				stateProcessIncarnation = terminal.ProcessIncarnation
			}
			state := stateValue{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  stateProcessIncarnation,
			}
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			cleanup.monoTimeNow = func() time.Duration { return 100 * time.Second }
			cleanup.maps.states.(*fakeBridgeMap).values[key] = state
			seedAgedGenerationCleanupFence(t, cleanup, key, state.ProcessIncarnation)
			if test.seed {
				claim := cleanup.maps.claims.(*fakeBridgeMap).values[key].(generationClaim)
				claim.Reserved[0] = terminal.Lifecycle
				cleanup.maps.claims.(*fakeBridgeMap).values[key] = claim
			}
			terminals := cleanup.maps.terminals.(*fakeBridgeMap)
			if test.seed {
				terminals.values[owner] = terminal
			}
			injected := test.installHook(terminals, owner, terminal)
			claimsBefore := maps.Clone(cleanup.maps.claims.(*fakeBridgeMap).values)
			guardsBefore := maps.Clone(cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
			markersBefore := maps.Clone(cleanup.maps.ambiguity.(*fakeBridgeMap).values)

			cleaned, err := cleanup.quarantineMalformedState(key, state)
			require.NoError(t, err)
			require.True(t, injected())
			assert.False(t, cleaned)
			assert.Equal(t, state, cleanup.maps.states.(*fakeBridgeMap).values[key])
			assert.Equal(t, claimsBefore, cleanup.maps.claims.(*fakeBridgeMap).values)
			assert.Equal(t, guardsBefore, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
			assert.Equal(t, markersBefore, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
			assert.Contains(t, terminals.values, owner)
		})
	}
}

func TestCleanupInvalidLifecycleTerminalUsesFullRecoveryFence(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	terminal := terminalValue{
		Generation:          key.Generation,
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleActive,
	}
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	cleanup.maps.terminals.(*fakeBridgeMap).values[owner] = terminal
	cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(10 * time.Second)

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, terminal, cleanup.maps.terminals.(*fakeBridgeMap).values[owner])
	assert.Contains(t, cleanup.maps.claims.(*fakeBridgeMap).values, key)
	assert.Contains(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values, owner)
	assert.Equal(t, uint64(10*time.Second),
		cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
}

func TestCleanupValidTerminalRecoversOnlyMatchingExistingGuard(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	terminal := terminalValue{
		Generation:          key.Generation,
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}
	matchingGuard := generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecyclePublishing},
	}

	t.Run("matching guard", func(t *testing.T) {
		cleanup := testCleanup(testMapHandler(nil, nil, nil))
		now := 41 * time.Second
		cleanup.monoTimeNow = func() time.Duration { return now }
		cleanup.maps.terminals.(*fakeBridgeMap).values[owner] = terminal
		cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner] = matchingGuard
		cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(10 * time.Second)

		stats, err := cleanup.SweepWithStats()
		require.NoError(t, err)
		assert.Equal(t, CleanupStats{}, stats)
		assert.Equal(t, terminal, cleanup.maps.terminals.(*fakeBridgeMap).values[owner])
		claim, present := cleanup.maps.claims.(*fakeBridgeMap).values[key].(generationClaim)
		require.True(t, present)
		assert.Equal(t, terminal.ProcessIncarnation, claim.ProcessIncarnation)
		assert.Equal(t, [7]byte{terminal.Lifecycle}, claim.Reserved)
		assert.Equal(t, matchingGuard,
			cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner])
		assert.Equal(t, uint64(10*time.Second),
			cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])

		now = 72*time.Second + time.Nanosecond
		stats, err = cleanup.SweepWithStats()
		require.NoError(t, err)
		assert.Equal(t, CleanupStats{}, stats)
		assert.Equal(t, terminal, cleanup.maps.terminals.(*fakeBridgeMap).values[owner])
		assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
		assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
		assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
	})

	t.Run("foreign guard", func(t *testing.T) {
		foreign := matchingGuard
		foreign.ProcessIncarnation++
		foreign.ObservedMonotonicNS = uint64(40 * time.Second)
		cleanup := testCleanup(testMapHandler(nil, nil, nil))
		cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
		cleanup.maps.terminals.(*fakeBridgeMap).values[owner] = terminal
		cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner] = foreign

		stats, err := cleanup.SweepWithStats()
		require.NoError(t, err)
		assert.Equal(t, CleanupStats{}, stats)
		assert.Equal(t, terminal, cleanup.maps.terminals.(*fakeBridgeMap).values[owner])
		assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
		assert.Equal(t, foreign, cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner])
		assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
	})
}

func TestCleanupValidTerminalRetiresCrashFenceTails(t *testing.T) {
	for _, test := range []struct {
		name       string
		withClaim  bool
		withReplay bool
	}{
		{name: "claim and guard", withClaim: true, withReplay: true},
		{name: "guard only"},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			terminal := terminalValue{
				Generation:          key.Generation,
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  testProcessIncarnation,
				Lifecycle:           lifecycleConsumed,
			}
			claim := generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  terminal.ProcessIncarnation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{terminal.Lifecycle},
			}
			guard := generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  key.Generation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{lifecyclePublishing},
			}
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
			cleanup.maps.terminals.(*fakeBridgeMap).values[owner] = terminal
			cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner] = guard
			if test.withClaim {
				cleanup.maps.claims.(*fakeBridgeMap).values[key] = claim
			}
			if test.withReplay {
				replayKey := aliasReplayKeyForTerminal(key, terminal)
				cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey] = boundAliasReplayForTest(aliasReplayValue{
					TransitionMonotonicNS: uint64(10 * time.Second),
					References:            1,
					Lifecycle:             terminal.Lifecycle,
				})
			}

			stats, err := cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Equal(t, terminal, cleanup.maps.terminals.(*fakeBridgeMap).values[owner])
			assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
			assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
			assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
		})
	}
}

func TestCleanupTerminalUpgradesStrandedExactTailBeforeRetirement(t *testing.T) {
	for _, markerPresent := range []bool{false, true} {
		name := "marker absent"
		if markerPresent {
			name = "marker present"
		}
		t.Run(name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			terminal := terminalValue{
				Generation:          key.Generation,
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  testProcessIncarnation,
				Lifecycle:           lifecycleConsumed,
			}
			guard := generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  key.Generation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{lifecyclePublishing},
			}
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			now := 41 * time.Second
			cleanup.monoTimeNow = func() time.Duration { return now }
			terminals := cleanup.maps.terminals.(*fakeBridgeMap)
			claims := cleanup.maps.claims.(*fakeBridgeMap)
			guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
			markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
			replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
			terminals.values[owner] = terminal
			claims.values[key] = exactMarkerTailClaimForTest(key, uint64(10*time.Second))
			guards.values[owner] = guard
			if markerPresent {
				markers.values[key] = uint64(10 * time.Second)
			}
			replayKey := aliasReplayKeyForTerminal(key, terminal)
			replays.values[replayKey] = activeAliasReplayForTest()

			stats, err := cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			upgraded := claims.values[key].(generationClaim)
			assert.True(t, validGenerationCleanupClaim(upgraded))
			assert.Equal(t, terminal.ProcessIncarnation, upgraded.ProcessIncarnation)
			assert.Equal(t, [7]byte{terminal.Lifecycle}, upgraded.Reserved)
			assert.Equal(t, uint64(now), upgraded.ObservedMonotonicNS)
			assert.Equal(t, guard, guards.values[owner])
			assert.Contains(t, markers.values, key)
			assert.Equal(t, activeAliasReplayForTest(), replays.values[replayKey])

			now += 30*time.Second + time.Nanosecond
			stats, err = cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Equal(t, terminal, terminals.values[owner])
			assert.Empty(t, claims.values)
			assert.Empty(t, guards.values)
			assert.Empty(t, markers.values)
			finalReplay := replays.values[replayKey].(aliasReplayValue)
			assert.True(t, validAliasReplayFinal(finalReplay))
			assert.Equal(t, terminal.Lifecycle, finalReplay.Lifecycle)
		})
	}
}

func TestCleanupTerminalReconstructsMarkerAfterExactTailUpgradeFailure(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	terminal := terminalValue{
		Generation:          key.Generation,
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}
	guard := generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecyclePublishing},
	}
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	terminals := cleanup.maps.terminals.(*fakeBridgeMap)
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
	markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	terminals.values[owner] = terminal
	claims.values[key] = exactMarkerTailClaimForTest(key, uint64(10*time.Second))
	guards.values[owner] = guard
	replayKey := aliasReplayKeyForTerminal(key, terminal)
	replays.values[replayKey] = activeAliasReplayForTest()
	injected := errors.New("injected marker reconstruction failure")
	markers.updateErr = injected

	stats, err := cleanup.SweepWithStats()
	require.ErrorContains(t, err, injected.Error())
	assert.Equal(t, CleanupStats{}, stats)
	upgraded := claims.values[key].(generationClaim)
	assert.True(t, validGenerationCleanupClaim(upgraded))
	assert.Equal(t, terminal.ProcessIncarnation, upgraded.ProcessIncarnation)
	assert.Equal(t, [7]byte{terminal.Lifecycle}, upgraded.Reserved)
	assert.Empty(t, markers.values)
	assert.Equal(t, activeAliasReplayForTest(), replays.values[replayKey])

	markers.updateErr = nil
	now += 30*time.Second + time.Nanosecond
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, uint64(now), markers.values[key])
	assert.Equal(t, activeAliasReplayForTest(), replays.values[replayKey])

	now += 30*time.Second + time.Nanosecond
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, terminal, terminals.values[owner])
	assert.Empty(t, claims.values)
	assert.Empty(t, guards.values)
	assert.Empty(t, markers.values)
	finalReplay := replays.values[replayKey].(aliasReplayValue)
	assert.True(t, validAliasReplayFinal(finalReplay))
	assert.Equal(t, terminal.Lifecycle, finalReplay.Lifecycle)
}

func TestCleanupTerminalMarkerReconstructionCommittedErrorConverges(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	terminal := terminalValue{
		Generation:          key.Generation,
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}
	claim := generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  terminal.ProcessIncarnation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{terminal.Lifecycle},
	}
	guard := generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecyclePublishing},
	}
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	cleanup.maps.terminals.(*fakeBridgeMap).values[owner] = terminal
	cleanup.maps.claims.(*fakeBridgeMap).values[key] = claim
	cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner] = guard
	replayKey := aliasReplayKeyForTerminal(key, terminal)
	cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey] = activeAliasReplayForTest()
	markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
	injected := errors.New("injected committed marker reconstruction failure")
	markers.updateCommitErr = injected

	stats, err := cleanup.SweepWithStats()
	require.ErrorContains(t, err, injected.Error())
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, uint64(now), markers.values[key])
	assert.Equal(t, claim, cleanup.maps.claims.(*fakeBridgeMap).values[key])
	assert.Equal(t, guard, cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner])
	assert.Equal(t, activeAliasReplayForTest(),
		cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey])

	markers.updateCommitErr = nil
	now += 30*time.Second + time.Nanosecond
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
	assert.Empty(t, markers.values)
	assert.True(t, validAliasReplayFinal(
		cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey].(aliasReplayValue),
	))
}

func TestCleanupTerminalMarkerReconstructionRejectsSuccessorTuple(t *testing.T) {
	for _, replace := range []string{"claim", "guard", "replay"} {
		t.Run(replace, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			terminal := terminalValue{
				Generation:          key.Generation,
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  testProcessIncarnation,
				Lifecycle:           lifecycleConsumed,
			}
			claim := generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  terminal.ProcessIncarnation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{terminal.Lifecycle},
			}
			guard := generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  key.Generation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{lifecyclePublishing},
			}
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
			terminals := cleanup.maps.terminals.(*fakeBridgeMap)
			claims := cleanup.maps.claims.(*fakeBridgeMap)
			guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
			markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
			replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
			terminals.values[owner] = terminal
			claims.values[key] = claim
			guards.values[owner] = guard
			replayKey := aliasReplayKeyForTerminal(key, terminal)
			replays.values[replayKey] = activeAliasReplayForTest()
			markers.beforeUpdate = func(any, any, ebpf.MapUpdateFlags) {
				switch replace {
				case "claim":
					successor := claim
					successor.ObservedMonotonicNS++
					claims.values[key] = successor
				case "guard":
					successor := guard
					successor.ObservedMonotonicNS++
					guards.values[owner] = successor
				case "replay":
					successor := activeAliasReplayForTest()
					successor.References++
					replays.values[replayKey] = successor
				}
			}

			stats, err := cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Equal(t, uint64(41*time.Second), markers.values[key])
			assert.Zero(t, claims.deleteCount)
			assert.Zero(t, guards.deleteCount)
			assert.Equal(t, terminal, terminals.values[owner])
		})
	}
}

func TestCleanupTerminalExactTailUpgradeNeverReacquiresChangedGuard(t *testing.T) {
	for _, replace := range []bool{false, true} {
		name := "removed"
		if replace {
			name = "replaced"
		}
		t.Run(name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			terminal := terminalValue{
				Generation:          key.Generation,
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  testProcessIncarnation,
				Lifecycle:           lifecycleConsumed,
			}
			guard := generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  key.Generation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{lifecyclePublishing},
			}
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
			cleanup.maps.terminals.(*fakeBridgeMap).values[owner] = terminal
			claims := cleanup.maps.claims.(*fakeBridgeMap)
			guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
			claims.values[key] = exactMarkerTailClaimForTest(key, uint64(10*time.Second))
			guards.values[owner] = guard
			claims.afterLookup = func(count int) {
				if count != 1 {
					return
				}
				if replace {
					successor := guard
					successor.ProcessIncarnation++
					guards.values[owner] = successor
				} else {
					delete(guards.values, owner)
				}
			}

			stats, err := cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.True(t, validExactMarkerTailCleanupClaim(
				key, claims.values[key].(generationClaim),
			))
			assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
			assert.Zero(t, guards.updateCount)
			if replace {
				assert.NotEqual(t, guard, guards.values[owner])
			} else {
				assert.Empty(t, guards.values)
			}
		})
	}
}

func TestCleanupTerminalTailNeverRetiresCurrentSweepFenceParts(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	terminal := terminalValue{
		Generation:          key.Generation,
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}
	claim := generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  terminal.ProcessIncarnation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{terminal.Lifecycle},
	}
	guard := generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecyclePublishing},
	}

	t.Run("claim and guard", func(t *testing.T) {
		cleanup := testCleanup(testMapHandler(nil, nil, nil))
		cleanup.generationSnapshotComplete = true
		cleanup.stateSnapshotComplete = true
		cleanup.physicalGenerations = map[stateKey]struct{}{}
		cleanup.currentSweepClaims = map[stateKey]generationClaim{key: claim}
		cleanup.currentSweepGuards = map[Identity]generationClaim{owner: guard}
		cleanup.maps.terminals.(*fakeBridgeMap).values[owner] = terminal
		cleanup.maps.claims.(*fakeBridgeMap).values[key] = claim
		cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner] = guard

		released, err := cleanup.releaseTerminalClaimGuardTail(
			key, terminal, claim, guard, 100*time.Second,
		)
		require.NoError(t, err)
		assert.False(t, released)
		assert.Equal(t, claim, cleanup.maps.claims.(*fakeBridgeMap).values[key])
		assert.Equal(t, guard, cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner])
	})

	t.Run("guard only", func(t *testing.T) {
		cleanup := testCleanup(testMapHandler(nil, nil, nil))
		cleanup.generationSnapshotComplete = true
		cleanup.stateSnapshotComplete = true
		cleanup.physicalGenerations = map[stateKey]struct{}{}
		cleanup.currentSweepGuards = map[Identity]generationClaim{owner: guard}
		cleanup.maps.terminals.(*fakeBridgeMap).values[owner] = terminal
		cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner] = guard

		released, err := cleanup.releaseTerminalGuardTail(
			key, terminal, guard, 100*time.Second,
		)
		require.NoError(t, err)
		assert.False(t, released)
		assert.Equal(t, guard, cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner])
	})
}

func TestCleanupGuardedTerminalFenceNeverAdoptsCurrentSweepMarker(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
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
	markedAt := uint64(10 * time.Second)
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 100 * time.Second }
	cleanup.currentSweepAmbiguities = map[stateKey]uint64{key: markedAt}
	cleanup.maps.claims.(*fakeBridgeMap).values[key] = claim
	cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner] = guard
	cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = markedAt

	ownership, ready, err := cleanup.claimGenerationCleanupWithGuard(
		key, claim.ProcessIncarnation, claim.Reserved[0], guard, markedAt,
		func() (bool, error) { return true, nil },
	)
	require.NoError(t, err)
	assert.False(t, ready)
	assert.False(t, ownership.ready)
	assert.Equal(t, markedAt, cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
}

func TestCleanupTerminalClaimDeleteFailureRetainsGuardForNextSweep(t *testing.T) {
	for _, test := range []struct {
		name      string
		committed bool
	}{
		{name: "not committed"},
		{name: "committed with error", committed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			terminal := terminalValue{
				Generation:          key.Generation,
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  testProcessIncarnation,
				Lifecycle:           lifecycleConsumed,
			}
			claim := generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  terminal.ProcessIncarnation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{terminal.Lifecycle},
			}
			guard := generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  key.Generation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{lifecyclePublishing},
			}
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
			cleanup.maps.terminals.(*fakeBridgeMap).values[owner] = terminal
			claims := cleanup.maps.claims.(*fakeBridgeMap)
			guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
			claims.values[key] = claim
			guards.values[owner] = guard
			injected := errors.New("injected terminal claim deletion failure")
			if test.committed {
				claims.deleteCommitErr = injected
			} else {
				claims.deleteErr = injected
			}

			stats, err := cleanup.SweepWithStats()
			require.ErrorContains(t, err, injected.Error())
			assert.Equal(t, CleanupStats{}, stats)
			if test.committed {
				assert.NotContains(t, claims.values, key)
			} else {
				assert.Equal(t, claim, claims.values[key])
			}
			assert.Equal(t, guard, guards.values[owner])
			assert.Zero(t, guards.deleteCount)
			assert.Equal(t, terminal, cleanup.maps.terminals.(*fakeBridgeMap).values[owner])

			claims.deleteErr = nil
			claims.deleteCommitErr = nil
			stats, err = cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Empty(t, claims.values)
			assert.Empty(t, guards.values)
			assert.Equal(t, terminal, cleanup.maps.terminals.(*fakeBridgeMap).values[owner])
		})
	}
}

func TestCleanupTerminalMarkerDeleteFailureRetainsLaterFences(t *testing.T) {
	for _, test := range []struct {
		name      string
		committed bool
	}{
		{name: "not committed"},
		{name: "committed with error", committed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			terminal := terminalValue{
				Generation:          key.Generation,
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  testProcessIncarnation,
				Lifecycle:           lifecycleConsumed,
			}
			claim := generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  terminal.ProcessIncarnation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{terminal.Lifecycle},
			}
			guard := generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  key.Generation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{lifecyclePublishing},
			}
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
			cleanup.maps.terminals.(*fakeBridgeMap).values[owner] = terminal
			claims := cleanup.maps.claims.(*fakeBridgeMap)
			guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
			markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
			claims.values[key] = claim
			guards.values[owner] = guard
			markers.values[key] = uint64(10 * time.Second)
			injected := errors.New("injected terminal marker deletion failure")
			if test.committed {
				markers.deleteCommitErr = injected
			} else {
				markers.deleteErr = injected
			}

			stats, err := cleanup.SweepWithStats()
			require.ErrorContains(t, err, injected.Error())
			assert.Equal(t, CleanupStats{}, stats)
			if test.committed {
				assert.NotContains(t, markers.values, key)
			} else {
				assert.Equal(t, uint64(10*time.Second), markers.values[key])
			}
			assert.Equal(t, claim, claims.values[key])
			assert.Equal(t, guard, guards.values[owner])
			assert.Zero(t, claims.deleteCount)
			assert.Zero(t, guards.deleteCount)

			markers.deleteErr = nil
			markers.deleteCommitErr = nil
			stats, err = cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Empty(t, markers.values)
			assert.Empty(t, claims.values)
			assert.Empty(t, guards.values)
			assert.Equal(t, terminal, cleanup.maps.terminals.(*fakeBridgeMap).values[owner])
		})
	}
}

func TestCleanupTerminalGuardDeleteFailurePreservesTerminal(t *testing.T) {
	for _, test := range []struct {
		name      string
		committed bool
	}{
		{name: "not committed"},
		{name: "committed with error", committed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			terminal := terminalValue{
				Generation:          key.Generation,
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  testProcessIncarnation,
				Lifecycle:           lifecycleConsumed,
			}
			guard := generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  key.Generation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{lifecyclePublishing},
			}
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
			cleanup.maps.terminals.(*fakeBridgeMap).values[owner] = terminal
			guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
			guards.values[owner] = guard
			injected := errors.New("injected terminal guard deletion failure")
			if test.committed {
				guards.deleteCommitErr = injected
			} else {
				guards.deleteErr = injected
			}

			stats, err := cleanup.SweepWithStats()
			require.ErrorContains(t, err, injected.Error())
			assert.Equal(t, CleanupStats{}, stats)
			if test.committed {
				assert.Empty(t, guards.values)
			} else {
				assert.Equal(t, guard, guards.values[owner])
			}
			assert.Equal(t, terminal, cleanup.maps.terminals.(*fakeBridgeMap).values[owner])

			guards.deleteErr = nil
			guards.deleteCommitErr = nil
			stats, err = cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Empty(t, guards.values)
			assert.Equal(t, terminal, cleanup.maps.terminals.(*fakeBridgeMap).values[owner])
		})
	}
}

func TestCleanupTerminalClaimTailPinsAuthorityAfterClaimRelease(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	terminal := terminalValue{
		Generation:          key.Generation,
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}
	claim := generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  terminal.ProcessIncarnation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{terminal.Lifecycle},
	}
	guard := generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecyclePublishing},
	}
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	terminals := cleanup.maps.terminals.(*fakeBridgeMap)
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
	terminals.values[owner] = terminal
	claims.values[key] = claim
	guards.values[owner] = guard
	foreign := terminal
	foreign.ProcessIncarnation++
	claims.afterDelete = func(deleted any) {
		if deleted == key {
			terminals.values[owner] = foreign
		}
	}

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Empty(t, claims.values)
	assert.Equal(t, guard, guards.values[owner])
	assert.Zero(t, guards.deleteCount)
	assert.Equal(t, foreign, terminals.values[owner])

	claims.afterDelete = nil
	terminals.values[owner] = terminal
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Empty(t, claims.values)
	assert.Empty(t, guards.values)
	assert.Equal(t, terminal, terminals.values[owner])
}

func TestCleanupTerminalFenceRetirementUsesOnlyExactReplay(t *testing.T) {
	for _, test := range []struct {
		name         string
		replay       aliasReplayValue
		hasReplay    bool
		wantReleased bool
	}{
		{name: "missing", wantReleased: true},
		{
			name: "active finalized",
			replay: boundAliasReplayForTest(aliasReplayValue{
				TransitionMonotonicNS: uint64(10 * time.Second),
				References:            1,
				Lifecycle:             lifecycleActive,
			}),
			hasReplay:    true,
			wantReleased: true,
		},
		{
			name: "tagged publishing finalized",
			replay: boundAliasReplayForTest(aliasReplayValue{
				TransitionMonotonicNS: uint64(10 * time.Second),
				References:            1,
				Lifecycle:             lifecyclePublishing,
				DesiredLifecycle:      lifecycleConsumed,
				ProducerTag:           generationGoProducerTag,
			}),
			hasReplay:    true,
			wantReleased: true,
		},
		{
			name: "untagged publishing blocks",
			replay: boundAliasReplayForTest(aliasReplayValue{
				TransitionMonotonicNS: uint64(10 * time.Second),
				References:            1,
				Lifecycle:             lifecyclePublishing,
				DesiredLifecycle:      lifecycleConsumed,
			}),
			hasReplay: true,
		},
		{
			name: "wrong final lifecycle blocks",
			replay: boundAliasReplayForTest(aliasReplayValue{
				TransitionMonotonicNS: uint64(10 * time.Second),
				References:            1,
				Lifecycle:             lifecycleStale,
			}),
			hasReplay: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			terminal := terminalValue{
				Generation:          key.Generation,
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  testProcessIncarnation,
				Lifecycle:           lifecycleConsumed,
			}
			claim := generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  terminal.ProcessIncarnation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{terminal.Lifecycle},
			}
			guard := generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  key.Generation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{lifecyclePublishing},
			}
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
			cleanup.maps.terminals.(*fakeBridgeMap).values[owner] = terminal
			cleanup.maps.claims.(*fakeBridgeMap).values[key] = claim
			cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner] = guard
			cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(10 * time.Second)
			replayKey := aliasReplayKeyForTerminal(key, terminal)
			replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
			if test.hasReplay {
				replays.values[replayKey] = test.replay
			}
			unrelatedKey := replayKey
			unrelatedKey.ProcessIncarnation++
			unrelated := activeAliasReplayForTest()
			replays.values[unrelatedKey] = unrelated

			stats, err := cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Equal(t, terminal, cleanup.maps.terminals.(*fakeBridgeMap).values[owner])
			assert.Equal(t, unrelated, replays.values[unrelatedKey])
			if test.wantReleased {
				assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
				assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
				assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
				if test.hasReplay {
					final := replays.values[replayKey].(aliasReplayValue)
					assert.True(t, validAliasReplayFinal(final))
					assert.Equal(t, terminal.Lifecycle, final.Lifecycle)
				}
			} else {
				assert.Equal(t, claim, cleanup.maps.claims.(*fakeBridgeMap).values[key])
				assert.Equal(t, guard, cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner])
				assert.Equal(t, uint64(10*time.Second),
					cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
			}
		})
	}
}

func TestCleanupAgedTerminalMarkerTailRequiresMatchingGuard(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	terminal := terminalValue{
		Generation:          key.Generation,
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	cleanup.maps.terminals.(*fakeBridgeMap).values[owner] = terminal
	cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(10 * time.Second)

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, terminal, cleanup.maps.terminals.(*fakeBridgeMap).values[owner])
	assert.Equal(t, uint64(10*time.Second),
		cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
	assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)

	now = 72*time.Second + time.Nanosecond
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, terminal, cleanup.maps.terminals.(*fakeBridgeMap).values[owner])
	assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
	assert.Equal(t, uint64(10*time.Second),
		cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
}

func TestCleanupMarkerFreeExactTailRetainsTerminalAndNeverCreatesGuard(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	terminal := terminalValue{
		Generation:          key.Generation,
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}
	claim := exactMarkerTailClaimForTest(key, uint64(10*time.Second))
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	cleanup.maps.terminals.(*fakeBridgeMap).values[owner] = terminal
	cleanup.maps.claims.(*fakeBridgeMap).values[key] = claim
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, terminal, cleanup.maps.terminals.(*fakeBridgeMap).values[owner])
	assert.Equal(t, claim, cleanup.maps.claims.(*fakeBridgeMap).values[key])
	assert.Empty(t, guards.values)
	assert.Zero(t, guards.updateCount)
	assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
}

func TestCleanupExactTailReleasePreservesSuccessorReservation(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	oldClaim := exactMarkerTailClaimForTest(key, uint64(10*time.Second))
	successor := generationClaim{
		ObservedMonotonicNS: uint64(41 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
	claims.values[key] = oldClaim
	claims.afterDelete = func(deleted any) {
		if deleted == key {
			claims.values[key] = successor
			markers.values[key] = uint64(0)
		}
	}

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, successor, claims.values[key])
	assert.Equal(t, uint64(0), markers.values[key])
	assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
}

func TestCleanupExactTailConvergesAfterMarkerReleaseClaimFailure(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	claim := exactMarkerTailClaimForTest(key, uint64(10*time.Second))
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	cleanup.maps.claims.(*fakeBridgeMap).values[key] = claim
	cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(10 * time.Second)
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
	markers.deleteErr = errors.New("injected exact marker release failure")

	stats, err := cleanup.SweepWithStats()
	require.ErrorContains(t, err, "injected exact marker release failure")
	assert.Equal(t, CleanupStats{}, stats)
	refreshed, ok := claims.values[key].(generationClaim)
	require.True(t, ok)
	assert.Equal(t, uint64(now), refreshed.ObservedMonotonicNS)
	assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
	assert.Equal(t, uint64(10*time.Second), markers.values[key])

	markers.deleteErr = nil
	now = 72*time.Second + time.Nanosecond
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	refreshed, ok = claims.values[key].(generationClaim)
	require.True(t, ok)
	assert.Equal(t, uint64(now), refreshed.ObservedMonotonicNS)
	assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)

	now += 30*time.Second + time.Nanosecond
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Empty(t, claims.values)
	assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
}

func TestCleanupExactTailConvergesAfterClaimRefreshFailure(t *testing.T) {
	for _, test := range []struct {
		name      string
		committed bool
	}{
		{name: "not committed"},
		{name: "committed with error", committed: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			claim := exactMarkerTailClaimForTest(key, uint64(10*time.Second))
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			now := 41 * time.Second
			cleanup.monoTimeNow = func() time.Duration { return now }
			claims := cleanup.maps.claims.(*fakeBridgeMap)
			markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
			guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
			claims.values[key] = claim
			markers.values[key] = uint64(10 * time.Second)
			injected := errors.New("injected exact claim refresh failure")
			if test.committed {
				claims.updateCommitErr = injected
			} else {
				claims.updateErr = injected
			}

			stats, err := cleanup.SweepWithStats()
			require.ErrorContains(t, err, injected.Error())
			assert.Equal(t, CleanupStats{}, stats)
			retained, ok := claims.values[key].(generationClaim)
			require.True(t, ok)
			if test.committed {
				assert.Equal(t, uint64(now), retained.ObservedMonotonicNS)
			} else {
				assert.Equal(t, claim, retained)
			}
			assert.Equal(t, uint64(10*time.Second), markers.values[key])
			assert.Empty(t, guards.values)
			assert.Zero(t, guards.updateCount)

			claims.updateErr = nil
			claims.updateCommitErr = nil
			if test.committed {
				// A committed refresh starts a new strict grace interval even when
				// userspace observed an error.
				now += 30 * time.Second
				stats, err = cleanup.SweepWithStats()
				require.NoError(t, err)
				assert.Equal(t, CleanupStats{}, stats)
				assert.Equal(t, retained, claims.values[key])
				assert.Equal(t, uint64(10*time.Second), markers.values[key])
				now++
			}

			stats, err = cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			refreshed, ok := claims.values[key].(generationClaim)
			require.True(t, ok)
			assert.Equal(t, uint64(now), refreshed.ObservedMonotonicNS)
			assert.Empty(t, markers.values)
			assert.Empty(t, guards.values)
			assert.Zero(t, guards.updateCount)

			now += 30*time.Second + time.Nanosecond
			stats, err = cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Empty(t, claims.values)
			assert.Empty(t, markers.values)
			assert.Empty(t, guards.values)
			assert.Zero(t, guards.updateCount)
		})
	}
}

func TestCleanupMarkerFreeExactTailRetriesClaimDelete(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	claim := exactMarkerTailClaimForTest(key, uint64(10*time.Second))
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
	claims.values[key] = claim
	claims.deleteErr = errors.New("injected exact claim deletion failure")

	stats, err := cleanup.SweepWithStats()
	require.ErrorContains(t, err, claims.deleteErr.Error())
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, claim, claims.values[key])
	assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
	assert.Empty(t, guards.values)
	assert.Zero(t, guards.updateCount)

	claims.deleteErr = nil
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Empty(t, claims.values)
	assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
	assert.Empty(t, guards.values)
	assert.Zero(t, guards.updateCount)
}

func TestCleanupExactTailRetainsClaimWhenPhysicalPayloadAppearsAfterMarkerRelease(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	claim := exactMarkerTailClaimForTest(key, uint64(10*time.Second))
	handler := testMapHandler(nil, nil, nil)
	cleanup := testCleanup(handler)
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	cleanup.maps.claims.(*fakeBridgeMap).values[key] = claim
	cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(10 * time.Second)
	connectionKey := connectionInfoNS{
		Connection: connectionInfo{SourcePort: 3, DestinationPort: 10},
		NetNS:      owner.Namespace,
	}
	cleanup.maps.ambiguity.(*fakeBridgeMap).afterDelete = func(deleted any) {
		if deleted == key {
			seedConnectionClaim(handler, connectionKey, owner, key.Generation)
		}
	}

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	refreshed, ok := cleanup.maps.claims.(*fakeBridgeMap).values[key].(generationClaim)
	require.True(t, ok)
	assert.Equal(t, uint64(41*time.Second), refreshed.ObservedMonotonicNS)
	assert.Equal(t, key.Generation, refreshed.ProcessIncarnation)
	assert.Equal(t, lifecycleCleanup, refreshed.Lifecycle)
	assert.Equal(t, [7]byte{
		0: lifecycleAmbiguous,
		6: generationGoProducerTag,
	}, refreshed.Reserved)
	assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
	assert.Contains(t, cleanup.maps.connections.(*fakeBridgeMap).values, connectionKey)
	assert.NotEmpty(t, cleanup.maps.cookieConnections.(*fakeBridgeMap).values)

	// The newly published physical root upgrades exact-only E to a full-fence
	// claim without ever clearing E, and starts a fresh grace interval for G/E.
	now++
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	upgraded, ok := cleanup.maps.claims.(*fakeBridgeMap).values[key].(generationClaim)
	require.True(t, ok)
	assert.True(t, validGenerationCleanupClaim(upgraded))
	assert.False(t, validExactMarkerTailCleanupClaim(key, upgraded))
	assert.Equal(t, uint64(now), upgraded.ObservedMonotonicNS)
	assert.Equal(t, key.Generation, upgraded.ProcessIncarnation)
	assert.Equal(t, [7]byte{lifecycleAmbiguous}, upgraded.Reserved)
	guard, ok := cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner].(generationClaim)
	require.True(t, ok)
	assert.Equal(t, uint64(now), guard.ObservedMonotonicNS)
	assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
	assert.Contains(t, cleanup.maps.connections.(*fakeBridgeMap).values, connectionKey)
	assert.NotEmpty(t, cleanup.maps.cookieConnections.(*fakeBridgeMap).values)

	// A later sweep may publish M, but M itself must age before payload deletion.
	now += 30*time.Second + time.Nanosecond
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	markedAt, ok := cleanup.maps.ambiguity.(*fakeBridgeMap).values[key].(uint64)
	require.True(t, ok)
	assert.Equal(t, uint64(now), markedAt)
	assert.Contains(t, cleanup.maps.connections.(*fakeBridgeMap).values, connectionKey)
	assert.NotEmpty(t, cleanup.maps.cookieConnections.(*fakeBridgeMap).values)

	now += 30*time.Second + time.Nanosecond
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Empty(t, cleanup.maps.connections.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.cookieConnections.(*fakeBridgeMap).values)
	assert.Equal(t, upgraded, cleanup.maps.claims.(*fakeBridgeMap).values[key])
	assert.Equal(t, guard, cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner])
	assert.Equal(t, markedAt, cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])

	// The physical snapshot that authorized deletion remains fail-closed for the
	// rest of that sweep. A new complete snapshot can retire M -> E -> G.
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
}

func TestCleanupExactTailArtifactUpgradeFailureRemainsFailClosed(t *testing.T) {
	for _, test := range []struct {
		name      string
		committed bool
	}{
		{name: "not committed"},
		{name: "committed with error", committed: true},
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
			exact := exactMarkerTailClaimForTest(key, uint64(10*time.Second))
			claims := cleanup.maps.claims.(*fakeBridgeMap)
			guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
			markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
			claims.values[key] = exact
			markers.values[key] = uint64(10 * time.Second)
			injected := errors.New("injected exact-tail artifact upgrade failure")
			if test.committed {
				claims.updateCommitErr = injected
			} else {
				claims.updateErr = injected
			}

			stats, err := cleanup.SweepWithStats()
			require.ErrorContains(t, err, injected.Error())
			assert.Equal(t, CleanupStats{}, stats)
			assert.Len(t, cleanup.maps.connections.(*fakeBridgeMap).values, 1)
			assert.Len(t, cleanup.maps.cookieConnections.(*fakeBridgeMap).values, 1)
			assert.Equal(t, uint64(10*time.Second), markers.values[key])
			assert.Contains(t, guards.values, owner)
			retained := claims.values[key].(generationClaim)
			if test.committed {
				assert.True(t, validGenerationCleanupClaim(retained))
				assert.False(t, validExactMarkerTailCleanupClaim(key, retained))
				assert.Equal(t, uint64(41*time.Second), retained.ObservedMonotonicNS)
			} else {
				assert.Equal(t, exact, retained)
			}
		})
	}
}

func TestCleanupExactTailUnverifiableUpgradeStillStartsFreshGrace(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	connectionKey := connectionInfoNS{
		Connection: connectionInfo{SourcePort: 3, DestinationPort: 10},
		NetNS:      owner.Namespace,
	}
	handler := testMapHandler(nil, nil, nil)
	seedConnectionClaim(handler, connectionKey, owner, key.Generation)
	cleanup := testCleanup(handler)
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	cleanup.currentSweepClaims = make(map[stateKey]generationClaim)
	cleanup.currentSweepGuards = make(map[Identity]generationClaim)
	cleanup.currentSweepAmbiguities = make(map[stateKey]uint64)
	cleanup.retainedTerminalAuthorities = make(map[stateKey]terminalValue)
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	claims.values[key] = exactMarkerTailClaimForTest(key, uint64(10*time.Second))
	guard := generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecyclePublishing},
	}
	cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner] = guard
	cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(10 * time.Second)
	root := func() (bool, error) {
		connection := handler.connections.(*fakeBridgeMap).values[connectionKey].(connectionClaim)
		return cleanupExactMatches(cleanup.maps.connections, connectionKey, connection)
	}
	updateErr := errors.New("injected committed exact-tail upgrade error")
	lookupErr := errors.New("injected exact-tail upgrade readback error")
	claims.updateCommitErr = updateErr
	claims.afterUpdate = func(any, any) { claims.lookupErr = lookupErr }
	claims.afterLookupResult = func(_ any, err error) {
		if errors.Is(err, lookupErr) {
			claims.lookupErr = nil
		}
	}

	_, ready, err := cleanup.claimGenerationCleanupForArtifact(
		key, key.Generation, lifecycleAmbiguous, root,
	)
	require.ErrorContains(t, err, updateErr.Error())
	require.ErrorContains(t, err, lookupErr.Error())
	assert.False(t, ready)
	replacement := claims.values[key].(generationClaim)
	assert.True(t, validGenerationCleanupClaim(replacement))
	assert.Equal(t, uint64(now), replacement.ObservedMonotonicNS)
	assert.Equal(t, replacement, cleanup.currentSweepClaims[key])

	claims.updateCommitErr = nil
	claims.afterUpdate = nil
	claims.afterLookupResult = nil
	now = 100 * time.Second
	_, ready, err = cleanup.claimGenerationCleanupForArtifact(
		key, key.Generation, lifecycleAmbiguous, root,
	)
	require.NoError(t, err)
	assert.False(t, ready)
	assert.Equal(t, replacement, claims.values[key])
	assert.Equal(t, guard, cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner])
	assert.Equal(t, uint64(10*time.Second),
		cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
	assert.Len(t, cleanup.maps.connections.(*fakeBridgeMap).values, 1)
	assert.Len(t, cleanup.maps.cookieConnections.(*fakeBridgeMap).values, 1)
}

func TestCleanupExactTailUpgradeAbortUnwindsStrandedGuard(t *testing.T) {
	for _, markerPresent := range []bool{false, true} {
		for _, failUpdate := range []bool{false, true} {
			name := "root disappears after guard"
			if failUpdate {
				name = "noncommitted update and root disappears"
			}
			if markerPresent {
				name += " with marker"
			}
			t.Run(name, func(t *testing.T) {
				owner := Identity{TID: 3, PID: 2, Namespace: 1}
				key := stateKey{Owner: owner, Generation: 10}
				connectionKey := connectionInfoNS{
					Connection: connectionInfo{SourcePort: 3, DestinationPort: 10},
					NetNS:      owner.Namespace,
				}
				handler := testMapHandler(nil, nil, nil)
				seedConnectionClaim(handler, connectionKey, owner, key.Generation)
				cleanup := testCleanup(handler)
				now := 41 * time.Second
				cleanup.monoTimeNow = func() time.Duration { return now }
				claims := cleanup.maps.claims.(*fakeBridgeMap)
				guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
				markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
				connections := cleanup.maps.connections.(*fakeBridgeMap)
				cookies := cleanup.maps.cookieConnections.(*fakeBridgeMap)
				exact := exactMarkerTailClaimForTest(key, uint64(10*time.Second))
				claims.values[key] = exact
				if markerPresent {
					markers.values[key] = uint64(10 * time.Second)
				}
				disappeared := false
				disappear := func() {
					if disappeared {
						return
					}
					disappeared = true
					clear(connections.values)
					clear(cookies.values)
				}
				var injected error
				if failUpdate {
					injected = errors.New("injected exact-tail conversion failure")
					claims.updateErr = injected
					claims.afterFailedUpdate = disappear
				} else {
					guards.afterUpdate = func(any, any) { disappear() }
				}

				stats, err := cleanup.SweepWithStats()
				if injected != nil {
					require.ErrorContains(t, err, injected.Error())
				} else {
					require.NoError(t, err)
				}
				assert.Equal(t, CleanupStats{}, stats)
				require.True(t, disappeared)
				assert.Equal(t, exact, claims.values[key])
				assert.Contains(t, guards.values, owner)
				if markerPresent {
					assert.Equal(t, uint64(10*time.Second), markers.values[key])
				} else {
					assert.Empty(t, markers.values)
				}

				claims.updateErr = nil
				claims.afterFailedUpdate = nil
				guards.afterUpdate = nil
				now += 30*time.Second + time.Nanosecond
				stats, err = cleanup.SweepWithStats()
				require.NoError(t, err)
				assert.Equal(t, CleanupStats{}, stats)
				assert.Empty(t, guards.values)
				assert.Equal(t, exact, claims.values[key])

				stats, err = cleanup.SweepWithStats()
				require.NoError(t, err)
				assert.Equal(t, CleanupStats{}, stats)
				if markerPresent {
					refreshed := claims.values[key].(generationClaim)
					assert.True(t, validExactMarkerTailCleanupClaim(key, refreshed))
					assert.Empty(t, markers.values)
					now += 30*time.Second + time.Nanosecond
					stats, err = cleanup.SweepWithStats()
					require.NoError(t, err)
					assert.Equal(t, CleanupStats{}, stats)
				}
				assert.Empty(t, claims.values)
				assert.Empty(t, guards.values)
				assert.Empty(t, markers.values)
			})
		}
	}
}

func TestCleanupExactTailLateStateUsesArtifactReplayProvenance(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	state := stateValue{
		Lifecycle:           lifecycleActive,
		Aliases:             2,
		ObservedMonotonicNS: uint64(10 * time.Second),
		Connection: connectionInfo{
			SourcePort: 1234, DestinationPort: 443,
		},
		ConnectionNetNS:    42,
		ProcessIncarnation: testProcessIncarnation,
	}
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	states := cleanup.maps.states.(*fakeBridgeMap)
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
	markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	states.values[key] = state
	claims.values[key] = exactMarkerTailClaimForTest(key, uint64(10*time.Second))
	replayKey := aliasReplayKeyForState(key, state)
	replays.values[replayKey] = boundAliasReplayForTest(aliasReplayValue{
		TransitionMonotonicNS: uint64(10 * time.Second),
		References:            state.Aliases,
		Lifecycle:             lifecycleActive,
	})

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	upgraded := claims.values[key].(generationClaim)
	assert.True(t, validGenerationCleanupClaim(upgraded))
	assert.Equal(t, state.ProcessIncarnation, upgraded.ProcessIncarnation)
	assert.Equal(t, [7]byte{lifecycleStale}, upgraded.Reserved)
	assert.Contains(t, guards.values, owner)
	assert.Empty(t, markers.values)
	assert.Equal(t, state, states.values[key])
	assert.Equal(t, lifecycleActive, replays.values[replayKey].(aliasReplayValue).Lifecycle)

	now += 30*time.Second + time.Nanosecond
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Contains(t, markers.values, key)
	assert.Equal(t, state, states.values[key])

	now += 30*time.Second + time.Nanosecond
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{Cleaned: 1}, stats)
	assert.Empty(t, states.values)
	finalReplay := replays.values[replayKey].(aliasReplayValue)
	assert.True(t, validAliasReplayFinal(finalReplay))
	assert.Equal(t, lifecycleStale, finalReplay.Lifecycle)
	assert.Empty(t, claims.values)
	assert.Empty(t, guards.values)
	assert.Empty(t, markers.values)
}

func TestCleanupExactTailRetainsPostMarkerReleaseAuthority(t *testing.T) {
	for _, test := range []struct {
		name   string
		inject func(*Cleanup, stateKey)
		verify func(*testing.T, *Cleanup, stateKey)
	}{
		{
			name: "identical marker",
			inject: func(cleanup *Cleanup, key stateKey) {
				cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(10 * time.Second)
			},
			verify: func(t *testing.T, cleanup *Cleanup, key stateKey) {
				t.Helper()
				assert.Equal(t, uint64(10*time.Second),
					cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
			},
		},
		{
			name: "fresh marker",
			inject: func(cleanup *Cleanup, key stateKey) {
				cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(41 * time.Second)
			},
			verify: func(t *testing.T, cleanup *Cleanup, key stateKey) {
				t.Helper()
				assert.Equal(t, uint64(41*time.Second),
					cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
			},
		},
		{
			name: "guard",
			inject: func(cleanup *Cleanup, key stateKey) {
				cleanup.maps.ownerGuards.(*fakeBridgeMap).values[key.Owner] = generationClaim{
					ObservedMonotonicNS: uint64(41 * time.Second),
					ProcessIncarnation:  key.Generation,
					Lifecycle:           lifecycleCleanup,
					Reserved:            [7]byte{lifecyclePublishing},
				}
			},
			verify: func(t *testing.T, cleanup *Cleanup, key stateKey) {
				t.Helper()
				assert.Contains(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values, key.Owner)
			},
		},
		{
			name: "state",
			inject: func(cleanup *Cleanup, key stateKey) {
				cleanup.maps.states.(*fakeBridgeMap).values[key] = stateValue{
					ObservedMonotonicNS: uint64(41 * time.Second),
				}
			},
			verify: func(t *testing.T, cleanup *Cleanup, key stateKey) {
				t.Helper()
				assert.Contains(t, cleanup.maps.states.(*fakeBridgeMap).values, key)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			claim := exactMarkerTailClaimForTest(key, uint64(10*time.Second))
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
			cleanup.maps.claims.(*fakeBridgeMap).values[key] = claim
			cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(10 * time.Second)
			cleanup.maps.ambiguity.(*fakeBridgeMap).afterDelete = func(deleted any) {
				if deleted == key {
					test.inject(cleanup, key)
				}
			}

			stats, err := cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			refreshed, ok := cleanup.maps.claims.(*fakeBridgeMap).values[key].(generationClaim)
			require.True(t, ok)
			assert.Equal(t, uint64(41*time.Second), refreshed.ObservedMonotonicNS)
			assert.Equal(t, [7]byte{
				0: lifecycleAmbiguous,
				6: generationGoProducerTag,
			}, refreshed.Reserved)
			test.verify(t, cleanup, key)
		})
	}
}

func TestCleanupExactTerminalTailIgnoresUnrelatedReplayEpoch(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	terminal := terminalValue{
		Generation:          key.Generation,
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}
	claim := generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  terminal.ProcessIncarnation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{terminal.Lifecycle},
	}
	guard := generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecyclePublishing},
	}
	matchingKey := aliasReplayKey{
		Owner:               owner,
		Generation:          key.Generation,
		ObservedMonotonicNS: terminal.ObservedMonotonicNS,
		ProcessIncarnation:  terminal.ProcessIncarnation,
	}
	conflictingKey := matchingKey
	conflictingKey.ObservedMonotonicNS--
	conflictingKey.ProcessIncarnation++
	matchingReplay := boundAliasReplayForTest(aliasReplayValue{
		TransitionMonotonicNS: uint64(10 * time.Second),
		References:            1,
		Lifecycle:             lifecycleConsumed,
	})
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	cleanup.maps.terminals.(*fakeBridgeMap).values[owner] = terminal
	cleanup.maps.claims.(*fakeBridgeMap).values[key] = claim
	cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = uint64(10 * time.Second)
	cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner] = guard
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	replays.values[matchingKey] = matchingReplay
	replays.values[conflictingKey] = activeAliasReplayForTest()

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, terminal, cleanup.maps.terminals.(*fakeBridgeMap).values[owner])
	assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
	assert.Equal(t, matchingReplay, replays.values[matchingKey])
	assert.Equal(t, activeAliasReplayForTest(), replays.values[conflictingKey])
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
		assert.Equal(t, guard, guards.values[guardKey])
		assert.Equal(t, uint64(0), markers.values[key])
	})
}

func TestCleanupExactMarkerTailClaimRequiresStableAbsenceProof(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	markedAt := uint64(10 * time.Second)
	claim := exactMarkerTailClaimForTest(key, uint64(41*time.Second))
	newCleanup := func() *Cleanup {
		cleanup := testCleanup(testMapHandler(nil, nil, nil))
		cleanup.generationSnapshotComplete = true
		cleanup.stateSnapshotComplete = true
		cleanup.physicalGenerations = make(map[stateKey]struct{})
		cleanup.maps.ambiguity.(*fakeBridgeMap).values[key] = markedAt
		return cleanup
	}

	t.Run("complete", func(t *testing.T) {
		cleanup := newCleanup()
		claimed, err := cleanup.claimGenerationCleanupMarkerTail(key, claim, markedAt)
		require.NoError(t, err)
		assert.True(t, claimed)
		assert.Equal(t, markedAt, cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
		assert.Equal(t, claim, cleanup.maps.claims.(*fakeBridgeMap).values[key])
		assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
	})

	t.Run("incomplete snapshot", func(t *testing.T) {
		cleanup := newCleanup()
		cleanup.stateSnapshotComplete = false
		claimed, err := cleanup.claimGenerationCleanupMarkerTail(key, claim, markedAt)
		require.NoError(t, err)
		assert.False(t, claimed)
		assert.Equal(t, markedAt, cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
		assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
		assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
	})

	t.Run("generation artifact", func(t *testing.T) {
		cleanup := newCleanup()
		cleanup.maps.states.(*fakeBridgeMap).values[key] = stateValue{
			ObservedMonotonicNS: uint64(5 * time.Second),
		}
		claimed, err := cleanup.claimGenerationCleanupMarkerTail(key, claim, markedAt)
		require.NoError(t, err)
		assert.False(t, claimed)
		assert.Equal(t, markedAt, cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
		assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
		assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
	})

	t.Run("existing exact claim", func(t *testing.T) {
		cleanup := newCleanup()
		claims := cleanup.maps.claims.(*fakeBridgeMap)
		existing := generationClaim{
			ObservedMonotonicNS: uint64(40 * time.Second),
			ProcessIncarnation:  testProcessIncarnation,
			Lifecycle:           lifecycleConsumed,
		}
		claims.values[key] = existing
		claimed, err := cleanup.claimGenerationCleanupMarkerTail(key, claim, markedAt)
		require.NoError(t, err)
		assert.False(t, claimed)
		assert.Equal(t, markedAt, cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
		assert.Equal(t, existing, claims.values[key])
		assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
	})

	t.Run("marker replacement retains exact claim", func(t *testing.T) {
		cleanup := newCleanup()
		claims := cleanup.maps.claims.(*fakeBridgeMap)
		markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
		claims.afterUpdate = func(any, any) {
			markers.values[key] = uint64(40 * time.Second)
		}

		claimed, err := cleanup.claimGenerationCleanupMarkerTail(key, claim, markedAt)
		require.NoError(t, err)
		assert.True(t, claimed)
		assert.Equal(t, uint64(40*time.Second), markers.values[key])
		assert.Equal(t, claim, claims.values[key])
		assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
	})

	for _, test := range []struct {
		name   string
		inject func(*Cleanup)
	}{
		{
			name: "marker removal",
			inject: func(cleanup *Cleanup) {
				delete(cleanup.maps.ambiguity.(*fakeBridgeMap).values, key)
			},
		},
		{
			name: "guard publication",
			inject: func(cleanup *Cleanup) {
				cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner] = generationClaim{
					ObservedMonotonicNS: uint64(41 * time.Second),
					ProcessIncarnation:  key.Generation,
					Lifecycle:           lifecycleCleanup,
					Reserved:            [7]byte{lifecyclePublishing},
				}
			},
		},
		{
			name: "state publication",
			inject: func(cleanup *Cleanup) {
				cleanup.maps.states.(*fakeBridgeMap).values[key] = stateValue{
					ObservedMonotonicNS: uint64(41 * time.Second),
				}
			},
		},
		{
			name: "generation publication",
			inject: func(cleanup *Cleanup) {
				cleanup.maps.generations.(*fakeBridgeMap).values[key] = generationIndexValue{
					Process:             javaProcessIdentity(owner),
					ObservedMonotonicNS: uint64(41 * time.Second),
					ProcessIncarnation:  testProcessIncarnation,
				}
			},
		},
	} {
		t.Run("after exact claim/"+test.name, func(t *testing.T) {
			cleanup := newCleanup()
			claims := cleanup.maps.claims.(*fakeBridgeMap)
			guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
			claims.afterUpdate = func(any, any) { test.inject(cleanup) }

			claimed, err := cleanup.claimGenerationCleanupMarkerTail(key, claim, markedAt)
			require.NoError(t, err)
			assert.True(t, claimed)
			assert.Equal(t, claim, claims.values[key])
			assert.Zero(t, guards.updateCount)
		})
	}
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
	handler.remoteParents.(*fakeBridgeMap).values[owner] = validEncodedRecordObservedAt(t, 10, 40*time.Second)
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
	require.Error(t, err)
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
			now := 40 * time.Second
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
			assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
			if guardPresent {
				assert.Contains(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values, owner)
			} else {
				assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
			}
			assert.Equal(t, uint64(10*time.Second),
				cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])

			// Reconstruction starts only after the marker crosses the strict
			// retention boundary.
			now += time.Nanosecond
			stats, err = cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			claim, ok := cleanup.maps.claims.(*fakeBridgeMap).values[key].(generationClaim)
			require.True(t, ok)
			assert.Equal(t, uint64(now), claim.ObservedMonotonicNS)
			assert.Equal(t, key.Generation, claim.ProcessIncarnation)
			assert.Equal(t, lifecycleCleanup, claim.Lifecycle)
			expectedClaimMetadata := [7]byte{lifecycleAmbiguous}
			if !guardPresent {
				expectedClaimMetadata[6] = generationGoProducerTag
			}
			assert.Equal(t, expectedClaimMetadata, claim.Reserved)
			var guard generationClaim
			if guardPresent {
				guard, ok = cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner].(generationClaim)
				require.True(t, ok)
				assert.Equal(t, uint64(10*time.Second), guard.ObservedMonotonicNS)
			} else {
				assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
			}
			if guardPresent {
				assert.Equal(t, key.Generation, guard.ProcessIncarnation)
				assert.Equal(t, lifecycleCleanup, guard.Lifecycle)
				assert.Equal(t, [7]byte{lifecyclePublishing}, guard.Reserved)
			}
			assert.Equal(t, uint64(10*time.Second),
				cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])

			// The fresh synthetic E cannot be retired yet. Marker-only recovery
			// deliberately does not introduce G.
			now++
			stats, err = cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Equal(t, claim, cleanup.maps.claims.(*fakeBridgeMap).values[key])
			if guardPresent {
				assert.Equal(t, guard, cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner])
			} else {
				assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
			}
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
			now = 70*time.Second + 2*time.Nanosecond
			stats, err = cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			if guardPresent {
				assert.Equal(t, []string{"marker", "claim", "guard"}, retirementOrder)
				assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
				assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
				assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
				return
			}
			assert.Equal(t, []string{"marker"}, retirementOrder)
			refreshed, ok := cleanup.maps.claims.(*fakeBridgeMap).values[key].(generationClaim)
			require.True(t, ok)
			assert.Equal(t, uint64(now), refreshed.ObservedMonotonicNS)
			assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
			assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)

			now += 30 * time.Second
			stats, err = cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Equal(t, []string{"marker"}, retirementOrder)
			assert.Equal(t, refreshed, cleanup.maps.claims.(*fakeBridgeMap).values[key])

			now++
			stats, err = cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Equal(t, []string{"marker", "claim"}, retirementOrder)
			assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
			assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
			assert.Empty(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
		})
	}
}

func TestCleanupFreshMarkedTerminalDoesNotFenceSuccessor(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	oldKey := stateKey{Owner: owner, Generation: 10}
	markedAt := uint64(40 * time.Second)
	terminal := terminalValue{
		Generation:          oldKey.Generation,
		ObservedMonotonicNS: uint64(39 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}
	handler := testMapHandler(map[Identity]any{
		owner: validEncodedRecordObservedAt(t, 11, 40*time.Second),
	}, nil, nil)
	cleanup := testCleanup(handler)
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	cleanup.maps.terminals.(*fakeBridgeMap).values[owner] = terminal
	cleanup.maps.ambiguity.(*fakeBridgeMap).values[oldKey] = markedAt

	parentsBefore := maps.Clone(cleanup.maps.remoteParents.(*fakeBridgeMap).values)
	ownersBefore := maps.Clone(cleanup.maps.owners.(*fakeBridgeMap).values)
	statesBefore := maps.Clone(cleanup.maps.states.(*fakeBridgeMap).values)
	generationsBefore := maps.Clone(cleanup.maps.generations.(*fakeBridgeMap).values)
	connectionsBefore := maps.Clone(cleanup.maps.connections.(*fakeBridgeMap).values)
	cookiesBefore := maps.Clone(cleanup.maps.cookieConnections.(*fakeBridgeMap).values)
	terminalsBefore := maps.Clone(cleanup.maps.terminals.(*fakeBridgeMap).values)

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, parentsBefore, cleanup.maps.remoteParents.(*fakeBridgeMap).values)
	assert.Equal(t, ownersBefore, cleanup.maps.owners.(*fakeBridgeMap).values)
	assert.Equal(t, statesBefore, cleanup.maps.states.(*fakeBridgeMap).values)
	assert.Equal(t, generationsBefore, cleanup.maps.generations.(*fakeBridgeMap).values)
	assert.Equal(t, connectionsBefore, cleanup.maps.connections.(*fakeBridgeMap).values)
	assert.Equal(t, cookiesBefore, cleanup.maps.cookieConnections.(*fakeBridgeMap).values)
	assert.Equal(t, terminalsBefore, cleanup.maps.terminals.(*fakeBridgeMap).values)
	assert.Equal(t, markedAt, cleanup.maps.ambiguity.(*fakeBridgeMap).values[oldKey])
	assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
}

func TestCleanupAgedTerminalMarkerTailDoesNotFenceSuccessor(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	oldKey := stateKey{Owner: owner, Generation: 10}
	oldTerminal := terminalValue{
		Generation:          oldKey.Generation,
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}
	handler := testMapHandler(map[Identity]any{
		owner: validEncodedRecordObservedAt(t, 11, 40*time.Second),
	}, nil, nil)
	handler.incarnations.(*fakeBridgeMap).values[javaProcessIdentity(owner)] = testProcessIncarnation
	cleanup := testCleanup(handler)
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	cleanup.maps.terminals.(*fakeBridgeMap).values[owner] = oldTerminal
	cleanup.maps.ambiguity.(*fakeBridgeMap).values[oldKey] = uint64(10 * time.Second)
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
	successorKey := stateKey{Owner: owner, Generation: 11}
	refreshSuccessor := func(observed time.Duration) {
		t.Helper()
		encoded := validEncodedRecordObservedAt(t, successorKey.Generation, observed)
		cleanup.maps.remoteParents.(*fakeBridgeMap).values[owner] = encoded
		state := cleanup.maps.states.(*fakeBridgeMap).values[successorKey].(stateValue)
		state.ObservedMonotonicNS = uint64(observed)
		state.Response = encoded
		cleanup.maps.states.(*fakeBridgeMap).values[successorKey] = state
		index := cleanup.maps.generations.(*fakeBridgeMap).values[successorKey].(generationIndexValue)
		index.ObservedMonotonicNS = uint64(observed)
		cleanup.maps.generations.(*fakeBridgeMap).values[successorKey] = index
	}
	sweep := func() {
		t.Helper()
		refreshSuccessor(now)
		parentsBefore := maps.Clone(cleanup.maps.remoteParents.(*fakeBridgeMap).values)
		ownersBefore := maps.Clone(cleanup.maps.owners.(*fakeBridgeMap).values)
		statesBefore := maps.Clone(cleanup.maps.states.(*fakeBridgeMap).values)
		generationsBefore := maps.Clone(cleanup.maps.generations.(*fakeBridgeMap).values)
		connectionsBefore := maps.Clone(cleanup.maps.connections.(*fakeBridgeMap).values)
		cookiesBefore := maps.Clone(cleanup.maps.cookieConnections.(*fakeBridgeMap).values)
		terminalsBefore := maps.Clone(cleanup.maps.terminals.(*fakeBridgeMap).values)
		stats, err := cleanup.SweepWithStats()
		require.NoError(t, err)
		assert.Equal(t, CleanupStats{}, stats)
		assert.Equal(t, parentsBefore, cleanup.maps.remoteParents.(*fakeBridgeMap).values)
		assert.Equal(t, ownersBefore, cleanup.maps.owners.(*fakeBridgeMap).values)
		assert.Equal(t, statesBefore, cleanup.maps.states.(*fakeBridgeMap).values)
		assert.Equal(t, generationsBefore, cleanup.maps.generations.(*fakeBridgeMap).values)
		assert.Equal(t, connectionsBefore, cleanup.maps.connections.(*fakeBridgeMap).values)
		assert.Equal(t, cookiesBefore, cleanup.maps.cookieConnections.(*fakeBridgeMap).values)
		assert.Equal(t, terminalsBefore, cleanup.maps.terminals.(*fakeBridgeMap).values)
		assert.Empty(t, guards.values)
		assert.Zero(t, guards.updateCount)
	}

	sweep()
	assert.Equal(t, uint64(10*time.Second),
		cleanup.maps.ambiguity.(*fakeBridgeMap).values[oldKey])
	assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)

	now = 72*time.Second + time.Nanosecond
	sweep()
	assert.Equal(t, uint64(10*time.Second),
		cleanup.maps.ambiguity.(*fakeBridgeMap).values[oldKey])
	assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)

	now += 30*time.Second + time.Nanosecond
	sweep()
	assert.Equal(t, uint64(10*time.Second),
		cleanup.maps.ambiguity.(*fakeBridgeMap).values[oldKey])
	assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
}

func TestCleanupMarkerAgeRevalidatesSnapshot(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
	markers.values[key] = uint64(10 * time.Second)
	replaced := false
	markers.afterIterate = func() {
		replaced = true
		markers.values[key] = uint64(40 * time.Second)
	}

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	require.True(t, replaced)
	assert.Equal(t, uint64(40*time.Second), markers.values[key])
	assert.Empty(t, cleanup.maps.claims.(*fakeBridgeMap).values)
	assert.Empty(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
}

func TestCleanupMarkerFreeActiveReplayTailReconstructsFence(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
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
	replayKey := aliasReplayKey{
		Owner:               owner,
		Generation:          key.Generation,
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  claim.ProcessIncarnation,
	}
	activeReplay := activeAliasReplayForTest()
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
	markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	claims.values[key] = claim
	guards.values[owner] = guard
	replays.values[replayKey] = activeReplay

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, claim, claims.values[key])
	assert.Equal(t, guard, guards.values[owner])
	assert.Equal(t, uint64(now), markers.values[key])
	assert.Equal(t, activeReplay, replays.values[replayKey])

	now += 30*time.Second + time.Nanosecond
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Empty(t, claims.values)
	assert.Empty(t, guards.values)
	assert.Empty(t, markers.values)
	finalReplay := replays.values[replayKey].(aliasReplayValue)
	assert.True(t, validAliasReplayFinal(finalReplay))
	assert.Equal(t, lifecycleConsumed, finalReplay.Lifecycle)
}

func seedUnrelatedAliasReplaysForCleanupTest(replays *fakeBridgeMap) {
	const count = 32

	for i := uint32(0); i < count; i++ {
		replays.values[aliasReplayKey{
			Owner: Identity{
				TID: 1000 + i, PID: 1000 + i, Namespace: 2,
			},
			Generation:          20,
			ObservedMonotonicNS: uint64(20*time.Second) + uint64(i),
			ProcessIncarnation:  testProcessIncarnation + 1000 + uint64(i),
		}] = activeAliasReplayForTest()
	}
}

func TestCleanupMarkerFreeActiveReplayRecoveryIsBoundedAndFair(t *testing.T) {
	const tails = 8
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
	markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)

	for i := uint32(1); i <= tails; i++ {
		owner := Identity{TID: i, PID: i, Namespace: 1}
		key := stateKey{Owner: owner, Generation: 10}
		claim := generationClaim{
			ObservedMonotonicNS: uint64(10 * time.Second),
			ProcessIncarnation:  testProcessIncarnation + uint64(i),
			Lifecycle:           lifecycleCleanup,
			Reserved:            [7]byte{lifecycleConsumed},
		}
		claims.values[key] = claim
		guards.values[owner] = generationClaim{
			ObservedMonotonicNS: uint64(10 * time.Second),
			ProcessIncarnation:  key.Generation,
			Lifecycle:           lifecycleCleanup,
			Reserved:            [7]byte{lifecyclePublishing},
		}
		replays.values[aliasReplayKey{
			Owner:               owner,
			Generation:          key.Generation,
			ObservedMonotonicNS: uint64(10 * time.Second),
			ProcessIncarnation:  claim.ProcessIncarnation,
		}] = activeAliasReplayForTest()
	}
	seedUnrelatedAliasReplaysForCleanupTest(replays)

	replayIterations := 0
	replays.afterIterate = func() { replayIterations++ }
	maxFullScansPerSweep := 2 +
		5*int(javaRemoteParentMaxGenerationReplayScanAttemptsPerSweep)
	for sweep := 1; sweep <= tails; sweep++ {
		before := replayIterations
		stats, err := cleanup.SweepWithStats()
		require.NoError(t, err)
		assert.Equal(t, CleanupStats{}, stats)
		assert.LessOrEqual(t, replayIterations-before, maxFullScansPerSweep)
		assert.Len(t, markers.values, sweep)
		now++
	}
	assert.Len(t, claims.values, tails)
	assert.Len(t, guards.values, tails)
}

func TestCleanupMarkerFreeClaimGuardFallbackIsBoundedAndFair(t *testing.T) {
	const tails = 8
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
	markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)

	for i := uint32(1); i <= tails; i++ {
		owner := Identity{TID: i, PID: i, Namespace: 1}
		key := stateKey{Owner: owner, Generation: 10}
		claims.values[key] = generationClaim{
			ObservedMonotonicNS: uint64(10 * time.Second),
			ProcessIncarnation:  testProcessIncarnation + uint64(i),
			Lifecycle:           lifecycleCleanup,
			Reserved:            [7]byte{lifecycleConsumed},
		}
		guards.values[owner] = generationClaim{
			ObservedMonotonicNS: uint64(10 * time.Second),
			ProcessIncarnation:  key.Generation,
			Lifecycle:           lifecycleCleanup,
			Reserved:            [7]byte{lifecyclePublishing},
		}
	}
	seedUnrelatedAliasReplaysForCleanupTest(replays)

	replayIterations := 0
	replays.afterIterate = func() { replayIterations++ }
	maxFullScansPerSweep := 2 +
		3*int(javaRemoteParentMaxGenerationReplayScanAttemptsPerSweep)
	for sweep := 1; sweep <= tails; sweep++ {
		before := replayIterations
		stats, err := cleanup.SweepWithStats()
		require.NoError(t, err)
		assert.Equal(t, CleanupStats{}, stats)
		assert.LessOrEqual(t, replayIterations-before, maxFullScansPerSweep)
		assert.Len(t, claims.values, tails-sweep)
		assert.Len(t, guards.values, tails-sweep)
		assert.Empty(t, markers.values)
		now++
	}
}

func TestCleanupMarkerFreeEOnlyReplayProofIsBoundedAndFair(t *testing.T) {
	const tails = 8
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)

	for i := uint32(1); i <= tails; i++ {
		owner := Identity{TID: i, PID: i, Namespace: 1}
		claims.values[stateKey{Owner: owner, Generation: 10}] = generationClaim{
			ObservedMonotonicNS: uint64(10 * time.Second),
			ProcessIncarnation:  testProcessIncarnation + uint64(i),
			Lifecycle:           lifecycleCleanup,
			Reserved:            [7]byte{lifecycleConsumed},
		}
	}
	seedUnrelatedAliasReplaysForCleanupTest(replays)

	replayIterations := 0
	replays.afterIterate = func() { replayIterations++ }
	maxFullScansPerSweep := 2 +
		2*int(javaRemoteParentMaxGenerationReplayScanAttemptsPerSweep)
	for sweep := 1; sweep <= tails; sweep++ {
		before := replayIterations
		stats, err := cleanup.SweepWithStats()
		require.NoError(t, err)
		assert.Equal(t, CleanupStats{}, stats)
		assert.LessOrEqual(t, replayIterations-before, maxFullScansPerSweep)
		assert.Len(t, claims.values, tails-sweep)
		now++
	}
}

func TestCleanupPublishingZeroReservationReplayProofIsBoundedAndFair(t *testing.T) {
	const tails = 8
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
	markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)

	for i := uint32(1); i <= tails; i++ {
		owner := Identity{TID: i, PID: i, Namespace: 1}
		key := stateKey{Owner: owner, Generation: 10}
		claims.values[key] = generationClaim{
			ObservedMonotonicNS: uint64(10 * time.Second),
			ProcessIncarnation:  testProcessIncarnation + uint64(i),
			Lifecycle:           lifecycleCleanup,
			Reserved:            [7]byte{lifecyclePublishing},
		}
		guards.values[owner] = generationClaim{
			ObservedMonotonicNS: uint64(10 * time.Second),
			ProcessIncarnation:  key.Generation,
			Lifecycle:           lifecycleCleanup,
			Reserved:            [7]byte{lifecyclePublishing},
		}
		markers.values[key] = uint64(0)
	}
	seedUnrelatedAliasReplaysForCleanupTest(replays)

	replayIterations := 0
	replays.afterIterate = func() { replayIterations++ }
	maxFullScansPerSweep := 2 +
		4*int(javaRemoteParentMaxGenerationReplayScanAttemptsPerSweep)
	for sweep := 1; sweep <= tails; sweep++ {
		before := replayIterations
		stats, err := cleanup.SweepWithStats()
		require.NoError(t, err)
		assert.Equal(t, CleanupStats{}, stats)
		assert.LessOrEqual(t, replayIterations-before, maxFullScansPerSweep)
		assert.Len(t, claims.values, tails-sweep)
		assert.Len(t, guards.values, tails-sweep)
		assert.Len(t, markers.values, tails)
		now++
	}
}

func TestCleanupGuardOnlyReplayProofIsBoundedAndFair(t *testing.T) {
	const tails = 8
	for _, markerPresent := range []bool{false, true} {
		name := "marker free"
		if markerPresent {
			name = "zero reservation"
		}
		t.Run(name, func(t *testing.T) {
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			now := 41 * time.Second
			cleanup.monoTimeNow = func() time.Duration { return now }
			guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
			markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
			replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)

			for i := uint32(1); i <= tails; i++ {
				owner := Identity{TID: i, PID: i, Namespace: 1}
				key := stateKey{Owner: owner, Generation: 10}
				guards.values[owner] = generationClaim{
					ObservedMonotonicNS: uint64(10 * time.Second),
					ProcessIncarnation:  key.Generation,
					Lifecycle:           lifecycleCleanup,
					Reserved:            [7]byte{lifecyclePublishing},
				}
				if markerPresent {
					markers.values[key] = uint64(0)
				}
			}
			seedUnrelatedAliasReplaysForCleanupTest(replays)

			replayIterations := 0
			replays.afterIterate = func() { replayIterations++ }
			maxFullScansPerSweep := 2 +
				2*int(javaRemoteParentMaxGenerationReplayScanAttemptsPerSweep)
			for sweep := 1; sweep <= tails; sweep++ {
				before := replayIterations
				stats, err := cleanup.SweepWithStats()
				require.NoError(t, err)
				assert.Equal(t, CleanupStats{}, stats)
				assert.LessOrEqual(t, replayIterations-before, maxFullScansPerSweep)
				assert.Len(t, guards.values, tails-sweep)
				if markerPresent {
					assert.Len(t, markers.values, tails)
				} else {
					assert.Empty(t, markers.values)
				}
				now++
			}
		})
	}
}

func TestCleanupGenerationReplayScanSchedulerDoesNotStarveGuards(t *testing.T) {
	const tailsPerClass = 4
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)

	for i := uint32(0); i < tailsPerClass; i++ {
		claimOwner := Identity{TID: 2*i + 1, PID: 2*i + 1, Namespace: 1}
		claims.values[stateKey{Owner: claimOwner, Generation: 10}] = generationClaim{
			ObservedMonotonicNS: uint64(10 * time.Second),
			ProcessIncarnation:  testProcessIncarnation + uint64(i),
			Lifecycle:           lifecycleCleanup,
			Reserved:            [7]byte{lifecycleConsumed},
		}

		guardOwner := Identity{TID: 2*i + 2, PID: 2*i + 2, Namespace: 1}
		guards.values[guardOwner] = generationClaim{
			ObservedMonotonicNS: uint64(10 * time.Second),
			ProcessIncarnation:  10,
			Lifecycle:           lifecycleCleanup,
			Reserved:            [7]byte{lifecyclePublishing},
		}
	}
	seedUnrelatedAliasReplaysForCleanupTest(replays)

	for sweep := 1; sweep <= 2*tailsPerClass; sweep++ {
		stats, err := cleanup.SweepWithStats()
		require.NoError(t, err)
		assert.Equal(t, CleanupStats{}, stats)
		assert.Equal(t, 2*tailsPerClass-sweep, len(claims.values)+len(guards.values))
		if sweep%2 == 0 {
			assert.Len(t, claims.values, tailsPerClass-sweep/2)
			assert.Len(t, guards.values, tailsPerClass-sweep/2)
		}
		now++
	}
}

func TestCleanupMarkedFullFenceReplayProofIsBoundedAndFair(t *testing.T) {
	const tails = 8
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
	markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)

	for i := uint32(1); i <= tails; i++ {
		owner := Identity{TID: i, PID: i, Namespace: 1}
		key := stateKey{Owner: owner, Generation: 10}
		claims.values[key] = generationClaim{
			ObservedMonotonicNS: uint64(10 * time.Second),
			ProcessIncarnation:  testProcessIncarnation + uint64(i),
			Lifecycle:           lifecycleCleanup,
			Reserved:            [7]byte{lifecycleConsumed},
		}
		guards.values[owner] = generationClaim{
			ObservedMonotonicNS: uint64(10 * time.Second),
			ProcessIncarnation:  key.Generation,
			Lifecycle:           lifecycleCleanup,
			Reserved:            [7]byte{lifecyclePublishing},
		}
		markers.values[key] = uint64(10 * time.Second)
	}
	seedUnrelatedAliasReplaysForCleanupTest(replays)

	replayIterations := 0
	replays.afterIterate = func() { replayIterations++ }
	maxFullScansPerSweep := 2 +
		3*int(javaRemoteParentMaxGenerationReplayScanAttemptsPerSweep)
	for sweep := 1; sweep <= tails; sweep++ {
		before := replayIterations
		stats, err := cleanup.SweepWithStats()
		require.NoError(t, err)
		assert.Equal(t, CleanupStats{}, stats)
		assert.LessOrEqual(t, replayIterations-before, maxFullScansPerSweep)
		assert.Len(t, claims.values, tails-sweep)
		assert.Len(t, guards.values, tails-sweep)
		assert.Len(t, markers.values, tails-sweep)
		now++
	}
}

func TestCleanupExactTailBacklogDoesNotConsumeGenerationReplayScanAdmission(t *testing.T) {
	const exactTails = 32
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	for i := uint32(1); i <= exactTails; i++ {
		key := stateKey{
			Owner:      Identity{TID: i, PID: i, Namespace: 1},
			Generation: 10,
		}
		claims.values[key] = generationClaim{
			ObservedMonotonicNS: uint64(10 * time.Second),
			ProcessIncarnation:  key.Generation,
			Lifecycle:           lifecycleCleanup,
			Reserved: [7]byte{
				0: lifecycleAmbiguous,
				6: generationGoProducerTag,
			},
		}
	}
	ordinaryKey := stateKey{
		Owner:      Identity{TID: exactTails + 1, PID: exactTails + 1, Namespace: 1},
		Generation: 10,
	}
	claims.values[ordinaryKey] = generationClaim{
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecycleConsumed},
	}
	seedUnrelatedAliasReplaysForCleanupTest(replays)

	replayIterations := 0
	replays.afterIterate = func() { replayIterations++ }
	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Empty(t, claims.values)
	assert.LessOrEqual(t, replayIterations,
		2+2*int(javaRemoteParentMaxGenerationReplayScanAttemptsPerSweep))
}

func TestCleanupMarkerFreeReplayProofCursorSurvivesClaimChurn(t *testing.T) {
	for _, failFirst := range []bool{false, true} {
		name := "successful first proof"
		if failFirst {
			name = "failed first proof"
		}
		t.Run(name, func(t *testing.T) {
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			now := 41 * time.Second
			cleanup.monoTimeNow = func() time.Duration { return now }
			claims := cleanup.maps.claims.(*fakeBridgeMap)
			guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
			markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
			replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
			seed := func(owner Identity) (stateKey, aliasReplayKey) {
				key := stateKey{Owner: owner, Generation: 10}
				claim := generationClaim{
					ObservedMonotonicNS: uint64(10 * time.Second),
					ProcessIncarnation:  testProcessIncarnation + uint64(owner.TID),
					Lifecycle:           lifecycleCleanup,
					Reserved:            [7]byte{lifecycleConsumed},
				}
				claims.values[key] = claim
				guards.values[owner] = generationClaim{
					ObservedMonotonicNS: uint64(10 * time.Second),
					ProcessIncarnation:  key.Generation,
					Lifecycle:           lifecycleCleanup,
					Reserved:            [7]byte{lifecyclePublishing},
				}
				replayKey := aliasReplayKey{
					Owner:               owner,
					Generation:          key.Generation,
					ObservedMonotonicNS: uint64(10 * time.Second),
					ProcessIncarnation:  claim.ProcessIncarnation,
				}
				replays.values[replayKey] = activeAliasReplayForTest()
				return key, replayKey
			}

			leftOwner := Identity{TID: 1, PID: 1, Namespace: 1}
			targetOwner := Identity{TID: 2, PID: 2, Namespace: 1}
			highOwner := Identity{TID: 3, PID: 3, Namespace: 1}
			leftKey, leftReplayKey := seed(leftOwner)
			targetKey, _ := seed(targetOwner)
			injected := errors.New("injected first marker failure")
			if failFirst {
				markers.updateErr = injected
			}

			stats, err := cleanup.SweepWithStats()
			if failFirst {
				require.ErrorContains(t, err, injected.Error())
			} else {
				require.NoError(t, err)
				assert.Contains(t, markers.values, leftKey)
			}
			assert.Equal(t, CleanupStats{}, stats)
			assert.NotContains(t, markers.values, targetKey)

			markers.updateErr = nil
			delete(markers.values, leftKey)
			delete(claims.values, leftKey)
			delete(guards.values, leftOwner)
			delete(replays.values, leftReplayKey)
			highKey, _ := seed(highOwner)
			now++

			stats, err = cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Contains(t, markers.values, targetKey)
			assert.NotContains(t, markers.values, highKey)
		})
	}
}

func TestCleanupGenerationReplayScanCursorAdvancesAfterError(t *testing.T) {
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
	markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	seed := func(owner Identity) stateKey {
		key := stateKey{Owner: owner, Generation: 10}
		claim := generationClaim{
			ObservedMonotonicNS: uint64(10 * time.Second),
			ProcessIncarnation:  testProcessIncarnation + uint64(owner.TID),
			Lifecycle:           lifecycleCleanup,
			Reserved:            [7]byte{lifecycleConsumed},
		}
		claims.values[key] = claim
		guards.values[owner] = generationClaim{
			ObservedMonotonicNS: uint64(10 * time.Second),
			ProcessIncarnation:  key.Generation,
			Lifecycle:           lifecycleCleanup,
			Reserved:            [7]byte{lifecyclePublishing},
		}
		replays.values[aliasReplayKey{
			Owner:               owner,
			Generation:          key.Generation,
			ObservedMonotonicNS: uint64(10 * time.Second),
			ProcessIncarnation:  claim.ProcessIncarnation,
		}] = activeAliasReplayForTest()
		return key
	}
	left := seed(Identity{TID: 1, PID: 1, Namespace: 1})
	target := seed(Identity{TID: 2, PID: 2, Namespace: 1})

	injected := errors.New("injected marker publication failure")
	markers.updateErr = injected
	stats, err := cleanup.SweepWithStats()
	require.ErrorContains(t, err, injected.Error())
	assert.Equal(t, CleanupStats{}, stats)
	assert.NotContains(t, markers.values, left)
	assert.NotContains(t, markers.values, target)

	markers.updateErr = nil
	now++
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.NotContains(t, markers.values, left)
	assert.Contains(t, markers.values, target)

	now++
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Contains(t, markers.values, left)
	assert.Contains(t, markers.values, target)
}

func TestCleanupGenerationReplayScanIteratorErrorIsBoundedAndRotates(t *testing.T) {
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	keys := []stateKey{
		{Owner: Identity{TID: 1, PID: 1, Namespace: 1}, Generation: 10},
		{Owner: Identity{TID: 2, PID: 2, Namespace: 1}, Generation: 10},
	}
	for i, key := range keys {
		claims.values[key] = generationClaim{
			ObservedMonotonicNS: uint64(10 * time.Second),
			ProcessIncarnation:  testProcessIncarnation + uint64(i),
			Lifecycle:           lifecycleCleanup,
			Reserved:            [7]byte{lifecycleConsumed},
		}
	}
	seedUnrelatedAliasReplaysForCleanupTest(replays)

	injected := errors.New("injected generation replay iteration failure")
	iterations := 0
	replays.afterIterate = func() {
		iterations++
		switch iterations {
		case 1:
			replays.iterateErr = injected
		case 2:
			// Iterate captured the injected error before invoking this hook. Clear
			// it so only the admitted proof fails and the final refresh succeeds.
			replays.iterateErr = nil
		}
	}
	stats, err := cleanup.SweepWithStats()
	require.ErrorContains(t, err, injected.Error())
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, 3, iterations)
	assert.Contains(t, claims.values, keys[0])
	assert.Contains(t, claims.values, keys[1])

	replays.iterateErr = nil
	replays.afterIterate = nil
	now++
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Contains(t, claims.values, keys[0])
	assert.NotContains(t, claims.values, keys[1])
}

func TestCleanupMarkerFreeReplayProofCursorSerializesConcurrentSweeps(t *testing.T) {
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
	markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	for i := uint32(1); i <= 2; i++ {
		owner := Identity{TID: i, PID: i, Namespace: 1}
		key := stateKey{Owner: owner, Generation: 10}
		claim := generationClaim{
			ObservedMonotonicNS: uint64(10 * time.Second),
			ProcessIncarnation:  testProcessIncarnation + uint64(i),
			Lifecycle:           lifecycleCleanup,
			Reserved:            [7]byte{lifecycleConsumed},
		}
		claims.values[key] = claim
		guards.values[owner] = generationClaim{
			ObservedMonotonicNS: uint64(10 * time.Second),
			ProcessIncarnation:  key.Generation,
			Lifecycle:           lifecycleCleanup,
			Reserved:            [7]byte{lifecyclePublishing},
		}
		replays.values[aliasReplayKey{
			Owner:               owner,
			Generation:          key.Generation,
			ObservedMonotonicNS: uint64(10 * time.Second),
			ProcessIncarnation:  claim.ProcessIncarnation,
		}] = activeAliasReplayForTest()
	}

	firstInside := make(chan struct{})
	secondInside := make(chan struct{})
	releaseFirst := make(chan struct{})
	var releaseFirstOnce sync.Once
	releaseFirstSweep := func() { releaseFirstOnce.Do(func() { close(releaseFirst) }) }
	t.Cleanup(releaseFirstSweep)
	var generationScans atomic.Int32
	cleanup.maps.generations.(*fakeBridgeMap).afterIterate = func() {
		switch generationScans.Add(1) {
		case 1:
			close(firstInside)
			<-releaseFirst
		case 2:
			close(secondInside)
		}
	}

	errs := make(chan error, 2)
	go func() {
		_, err := cleanup.SweepWithStats()
		errs <- err
	}()
	require.Eventually(t, func() bool {
		select {
		case <-firstInside:
			return true
		default:
			return false
		}
	}, time.Second, time.Millisecond)

	secondAtPrelock := make(chan struct{})
	releaseSecondPrelock := make(chan struct{})
	var releaseSecondOnce sync.Once
	releaseSecondSweep := func() {
		releaseSecondOnce.Do(func() { close(releaseSecondPrelock) })
	}
	t.Cleanup(releaseSecondSweep)
	cleanup.maps.sslPrewriteConnectionAmbiguity.(*fakeBridgeMap).afterIterate = func() {
		close(secondAtPrelock)
		<-releaseSecondPrelock
	}
	go func() {
		_, err := cleanup.SweepWithStats()
		errs <- err
	}()
	require.Eventually(t, func() bool {
		select {
		case <-secondAtPrelock:
			return true
		default:
			return false
		}
	}, time.Second, time.Millisecond)
	releaseSecondSweep()
	assert.Never(t, func() bool {
		select {
		case <-secondInside:
			return true
		default:
			return false
		}
	}, 50*time.Millisecond, time.Millisecond)

	releaseFirstSweep()
	for range 2 {
		require.NoError(t, <-errs)
	}
	assert.Len(t, markers.values, 2)
}

func TestCleanupMarkerFreeActiveReplayTailFromLostArtifactConverges(t *testing.T) {
	for _, committedError := range []bool{false, true} {
		name := "successful claim"
		if committedError {
			name = "committed claim error"
		}
		t.Run(name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			state := stateValue{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  testProcessIncarnation,
				Lifecycle:           lifecycleActive,
			}
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			now := 41 * time.Second
			cleanup.monoTimeNow = func() time.Duration { return now }
			states := cleanup.maps.states.(*fakeBridgeMap)
			claims := cleanup.maps.claims.(*fakeBridgeMap)
			guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
			markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
			replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
			states.values[key] = state
			replayKey := aliasReplayKeyForState(key, state)
			replays.values[replayKey] = activeAliasReplayForTest()
			claims.afterUpdate = func(updatedKey, _ any) {
				if updatedKey == key {
					delete(states.values, key)
				}
			}
			injected := errors.New("injected committed artifact-claim failure")
			if committedError {
				claims.updateCommitErr = injected
			}

			cleaned, err := cleanup.quarantineMalformedState(key, state)
			assert.False(t, cleaned)
			if committedError {
				require.ErrorContains(t, err, injected.Error())
			} else {
				require.NoError(t, err)
			}
			assert.Empty(t, states.values)
			require.Len(t, claims.values, 1)
			require.Len(t, guards.values, 1)
			assert.Empty(t, markers.values)
			assert.Equal(t, activeAliasReplayForTest(), replays.values[replayKey])

			claims.updateCommitErr = nil
			claims.afterUpdate = nil
			now += 30*time.Second + time.Nanosecond
			stats, err := cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Equal(t, uint64(now), markers.values[key])
			assert.Equal(t, activeAliasReplayForTest(), replays.values[replayKey])

			now += 30*time.Second + time.Nanosecond
			stats, err = cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Empty(t, claims.values)
			assert.Empty(t, guards.values)
			assert.Empty(t, markers.values)
			finalReplay := replays.values[replayKey].(aliasReplayValue)
			assert.True(t, validAliasReplayFinal(finalReplay))
			assert.Equal(t, lifecycleStale, finalReplay.Lifecycle)
		})
	}
}

func TestCleanupMarkerFreeActiveReplayMarkerUncertaintyConverges(t *testing.T) {
	for _, mode := range []string{"not committed", "committed error", "committed unreadable"} {
		t.Run(mode, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
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
			replayKey := aliasReplayKey{
				Owner: owner, Generation: key.Generation,
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  claim.ProcessIncarnation,
			}
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			now := 41 * time.Second
			cleanup.monoTimeNow = func() time.Duration { return now }
			claims := cleanup.maps.claims.(*fakeBridgeMap)
			guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
			markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
			replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
			claims.values[key] = claim
			guards.values[owner] = guard
			replays.values[replayKey] = activeAliasReplayForTest()
			injected := errors.New("injected marker publication uncertainty")
			switch mode {
			case "not committed":
				markers.updateErr = injected
			case "committed error":
				markers.updateCommitErr = injected
			case "committed unreadable":
				markers.updateCommitErr = injected
				markers.afterUpdate = func(any, any) { markers.lookupErr = injected }
			}

			stats, err := cleanup.SweepWithStats()
			require.ErrorContains(t, err, injected.Error())
			assert.Equal(t, CleanupStats{}, stats)
			assert.Equal(t, claim, claims.values[key])
			assert.Equal(t, guard, guards.values[owner])
			assert.Equal(t, activeAliasReplayForTest(), replays.values[replayKey])
			assert.Zero(t, claims.deleteCount)
			assert.Zero(t, guards.deleteCount)
			if mode == "not committed" {
				assert.Empty(t, markers.values)
			} else {
				assert.Equal(t, uint64(now), markers.values[key])
			}

			markers.updateErr = nil
			markers.updateCommitErr = nil
			markers.lookupErr = nil
			markers.afterUpdate = nil
			if mode == "not committed" {
				now++
				stats, err = cleanup.SweepWithStats()
				require.NoError(t, err)
				assert.Equal(t, CleanupStats{}, stats)
				assert.Equal(t, uint64(now), markers.values[key])
			}
			now += 30*time.Second + time.Nanosecond
			stats, err = cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Empty(t, claims.values)
			assert.Empty(t, guards.values)
			assert.Empty(t, markers.values)
			assert.True(t, validAliasReplayFinal(replays.values[replayKey].(aliasReplayValue)))
		})
	}
}

func TestCleanupMarkerFreeReplayRecoveryRequiresUniqueOpeningActiveEpoch(t *testing.T) {
	for _, test := range []struct {
		name        string
		claimOrigin uint8
		replays     func(stateKey, generationClaim) map[aliasReplayKey]any
	}{
		{
			name:        "multiple active epochs",
			claimOrigin: lifecycleConsumed,
			replays: func(key stateKey, claim generationClaim) map[aliasReplayKey]any {
				first := aliasReplayKey{
					Owner: key.Owner, Generation: key.Generation,
					ObservedMonotonicNS: uint64(10 * time.Second),
					ProcessIncarnation:  claim.ProcessIncarnation,
				}
				second := first
				second.ObservedMonotonicNS++
				return map[aliasReplayKey]any{
					first: activeAliasReplayForTest(), second: activeAliasReplayForTest(),
				}
			},
		},
		{
			name:        "publishing claim target",
			claimOrigin: lifecyclePublishing,
			replays: func(key stateKey, claim generationClaim) map[aliasReplayKey]any {
				return map[aliasReplayKey]any{{
					Owner: key.Owner, Generation: key.Generation,
					ObservedMonotonicNS: uint64(10 * time.Second),
					ProcessIncarnation:  claim.ProcessIncarnation,
				}: activeAliasReplayForTest()}
			},
		},
		{
			name:        "untagged publishing replay",
			claimOrigin: lifecycleConsumed,
			replays: func(key stateKey, claim generationClaim) map[aliasReplayKey]any {
				return map[aliasReplayKey]any{{
					Owner: key.Owner, Generation: key.Generation,
					ObservedMonotonicNS: uint64(10 * time.Second),
					ProcessIncarnation:  claim.ProcessIncarnation,
				}: boundAliasReplayForTest(aliasReplayValue{
					TransitionMonotonicNS: uint64(10 * time.Second),
					Lifecycle:             lifecyclePublishing,
					DesiredLifecycle:      lifecycleConsumed,
				})}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			claim := generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  testProcessIncarnation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{test.claimOrigin},
			}
			guard := generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  key.Generation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{lifecyclePublishing},
			}
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
			cleanup.maps.claims.(*fakeBridgeMap).values[key] = claim
			cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner] = guard
			for replayKey, replay := range test.replays(key, claim) {
				cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey] = replay
			}

			stats, err := cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Equal(t, claim, cleanup.maps.claims.(*fakeBridgeMap).values[key])
			assert.Equal(t, guard, cleanup.maps.ownerGuards.(*fakeBridgeMap).values[owner])
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

func TestCleanupPhysicalOnlyTerminalFinalizesExactReplayBeforeDeletion(t *testing.T) {
	for _, test := range []struct {
		name          string
		replay        aliasReplayValue
		wantConverged bool
	}{
		{
			name:          "active",
			replay:        activeAliasReplayForTest(),
			wantConverged: true,
		},
		{
			name: "tagged publishing",
			replay: boundAliasReplayForTest(aliasReplayValue{
				TransitionMonotonicNS: uint64(10 * time.Second),
				References:            1,
				Lifecycle:             lifecyclePublishing,
				DesiredLifecycle:      lifecycleConsumed,
				ProducerTag:           generationGoProducerTag,
			}),
			wantConverged: true,
		},
		{
			name: "untagged publishing",
			replay: boundAliasReplayForTest(aliasReplayValue{
				TransitionMonotonicNS: uint64(10 * time.Second),
				References:            1,
				Lifecycle:             lifecyclePublishing,
				DesiredLifecycle:      lifecycleConsumed,
			}),
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
			terminal := terminalValue{
				Generation:          key.Generation,
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  testProcessIncarnation,
				Lifecycle:           lifecycleConsumed,
			}
			claim := generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  terminal.ProcessIncarnation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{terminal.Lifecycle},
			}
			guard := generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  key.Generation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{lifecyclePublishing},
			}
			terminals := cleanup.maps.terminals.(*fakeBridgeMap)
			claims := cleanup.maps.claims.(*fakeBridgeMap)
			guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
			markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
			connections := cleanup.maps.connections.(*fakeBridgeMap)
			cookies := cleanup.maps.cookieConnections.(*fakeBridgeMap)
			replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
			terminals.values[owner] = terminal
			claims.values[key] = claim
			guards.values[owner] = guard
			markers.values[key] = uint64(10 * time.Second)
			replayKey := aliasReplayKeyForTerminal(key, terminal)
			replays.values[replayKey] = test.replay

			stats, err := cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Equal(t, terminal, terminals.values[owner])
			assert.Equal(t, claim, claims.values[key])
			assert.Equal(t, guard, guards.values[owner])
			assert.Equal(t, uint64(10*time.Second), markers.values[key])
			if !test.wantConverged {
				assert.Len(t, connections.values, 1)
				assert.Len(t, cookies.values, 1)
				assert.Equal(t, test.replay, replays.values[replayKey])
				return
			}
			assert.Empty(t, connections.values)
			assert.Empty(t, cookies.values)
			final := replays.values[replayKey].(aliasReplayValue)
			assert.True(t, validAliasReplayFinal(final))
			assert.Equal(t, terminal.Lifecycle, final.Lifecycle)

			stats, err = cleanup.SweepWithStats()
			require.NoError(t, err)
			assert.Equal(t, CleanupStats{}, stats)
			assert.Equal(t, terminal, terminals.values[owner])
			assert.Empty(t, claims.values)
			assert.Empty(t, guards.values)
			assert.Empty(t, markers.values)
		})
	}
}

func TestCleanupExactTailPhysicalArtifactWithTerminalConverges(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	connectionKey := connectionInfoNS{
		Connection: connectionInfo{SourcePort: 3, DestinationPort: 10},
		NetNS:      owner.Namespace,
	}
	handler := testMapHandler(nil, nil, nil)
	seedConnectionClaim(handler, connectionKey, owner, key.Generation)
	cleanup := testCleanup(handler)
	now := 41 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	terminal := terminalValue{
		Generation:          key.Generation,
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}
	terminals := cleanup.maps.terminals.(*fakeBridgeMap)
	claims := cleanup.maps.claims.(*fakeBridgeMap)
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
	markers := cleanup.maps.ambiguity.(*fakeBridgeMap)
	connections := cleanup.maps.connections.(*fakeBridgeMap)
	cookies := cleanup.maps.cookieConnections.(*fakeBridgeMap)
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	terminals.values[owner] = terminal
	claims.values[key] = exactMarkerTailClaimForTest(key, uint64(10*time.Second))
	replayKey := aliasReplayKeyForTerminal(key, terminal)
	replays.values[replayKey] = activeAliasReplayForTest()

	stats, err := cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	upgraded := claims.values[key].(generationClaim)
	assert.True(t, validGenerationCleanupClaim(upgraded))
	assert.Equal(t, terminal.ProcessIncarnation, upgraded.ProcessIncarnation)
	assert.Equal(t, [7]byte{terminal.Lifecycle}, upgraded.Reserved)
	assert.Contains(t, guards.values, owner)
	assert.Empty(t, markers.values)
	assert.Len(t, connections.values, 1)
	assert.Len(t, cookies.values, 1)
	assert.Equal(t, activeAliasReplayForTest(), replays.values[replayKey])

	now += 30*time.Second + time.Nanosecond
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Contains(t, markers.values, key)
	assert.Len(t, connections.values, 1)
	assert.Len(t, cookies.values, 1)

	now += 30*time.Second + time.Nanosecond
	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Empty(t, connections.values)
	assert.Empty(t, cookies.values)
	finalReplay := replays.values[replayKey].(aliasReplayValue)
	assert.True(t, validAliasReplayFinal(finalReplay))
	assert.Equal(t, terminal.Lifecycle, finalReplay.Lifecycle)
	assert.Equal(t, terminal, terminals.values[owner])
	assert.Contains(t, claims.values, key)
	assert.Contains(t, guards.values, owner)
	assert.Contains(t, markers.values, key)

	stats, err = cleanup.SweepWithStats()
	require.NoError(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, terminal, terminals.values[owner])
	assert.Empty(t, claims.values)
	assert.Empty(t, guards.values)
	assert.Empty(t, markers.values)
}

func TestCleanupPhysicalFenceRevalidatesLateTerminalInsertion(t *testing.T) {
	for _, test := range []struct {
		name              string
		insertAfterLookup int
		wantCookieDeleted bool
		wantError         bool
	}{
		{name: "during first authorization", insertAfterLookup: 1},
		{
			name:              "between cookie and connection",
			insertAfterLookup: 2,
			wantCookieDeleted: true,
			wantError:         true,
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
			cleanup.monoTimeNow = func() time.Duration { return 100 * time.Second }
			seedAgedGenerationCleanupFence(t, cleanup, key, key.Generation)
			terminal := terminalValue{
				Generation:          key.Generation,
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  testProcessIncarnation,
				Lifecycle:           lifecycleConsumed,
			}
			terminals := cleanup.maps.terminals.(*fakeBridgeMap)
			injected := false
			terminalMisses := 0
			terminals.afterLookupResult = func(mapKey any, err error) {
				if mapKey == owner && errors.Is(err, ebpf.ErrKeyNotExist) {
					terminalMisses++
					if !injected && terminalMisses == test.insertAfterLookup {
						injected = true
						terminals.values[owner] = terminal
					}
				}
			}
			connections := cleanup.maps.connections.(*fakeBridgeMap)
			cookies := cleanup.maps.cookieConnections.(*fakeBridgeMap)
			connection := connections.values[connectionKey].(connectionClaim)
			claimsBefore := maps.Clone(cleanup.maps.claims.(*fakeBridgeMap).values)
			guardsBefore := maps.Clone(cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
			markersBefore := maps.Clone(cleanup.maps.ambiguity.(*fakeBridgeMap).values)

			deleted, err := cleanup.deleteConnectionIndexesFenced(
				key, connectionKey, connection, 100*time.Second,
			)
			require.True(t, injected)
			if test.wantError {
				require.ErrorContains(t, err, "fence changed after cookie delete")
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, test.wantCookieDeleted, deleted)
			assert.Contains(t, connections.values, connectionKey)
			if test.wantCookieDeleted {
				assert.Empty(t, cookies.values)
			} else {
				assert.Len(t, cookies.values, 1)
			}
			assert.Equal(t, claimsBefore, cleanup.maps.claims.(*fakeBridgeMap).values)
			assert.Equal(t, guardsBefore, cleanup.maps.ownerGuards.(*fakeBridgeMap).values)
			assert.Equal(t, markersBefore, cleanup.maps.ambiguity.(*fakeBridgeMap).values)
			assert.Equal(t, terminal, terminals.values[owner])
		})
	}
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
				cleanup.maps.cookieConnections.(*fakeBridgeMap).iterateErr = errors.New("injected scan failure")
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
