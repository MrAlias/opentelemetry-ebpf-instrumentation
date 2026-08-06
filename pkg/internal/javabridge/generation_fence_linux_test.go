// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javabridge

import (
	"errors"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerationProducerHandoffUsesStrictFreshTimestamp(t *testing.T) {
	key := stateKey{Owner: Identity{TID: 3, PID: 2, Namespace: 1}, Generation: 10}
	claim := generationClaim{
		ObservedMonotonicNS: 10,
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
		Reserved:            [7]byte{6: generationGoProducerTag},
	}
	claims := &fakeBridgeMap{values: map[any]any{key: claim}}
	local := claim

	handedOff, err := handoffGenerationProducerClaim(claims, key, &local, 0)
	require.NoError(t, err)
	require.True(t, handedOff)
	assert.Zero(t, local)
	assert.Equal(t, generationClaim{
		ObservedMonotonicNS: 11,
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecycleConsumed},
	}, claims.values[key])
}

func TestGenerationProducerHandoffRejectsNegativeTime(t *testing.T) {
	key := stateKey{Owner: Identity{TID: 3, PID: 2, Namespace: 1}, Generation: 10}
	claim := generationClaim{
		ObservedMonotonicNS: 10,
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
		Reserved:            [7]byte{6: generationGoProducerTag},
	}
	claims := &fakeBridgeMap{values: map[any]any{key: claim}}
	local := claim

	handedOff, err := handoffGenerationProducerClaim(claims, key, &local, -1)
	require.Error(t, err)
	assert.False(t, handedOff)
	assert.Zero(t, local)
	assert.Equal(t, claim, claims.values[key])
	assert.Zero(t, claims.updateCount)
}

func TestGenerationProducerHandoffSaturationFailsClosed(t *testing.T) {
	key := stateKey{Owner: Identity{TID: 3, PID: 2, Namespace: 1}, Generation: 10}
	claim := generationClaim{
		ObservedMonotonicNS: ^uint64(0),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
		Reserved:            [7]byte{6: generationGoProducerTag},
	}
	claims := &fakeBridgeMap{values: map[any]any{key: claim}}
	local := claim

	handedOff, err := handoffGenerationProducerClaim(claims, key, &local, time.Second)
	require.Error(t, err)
	assert.False(t, handedOff)
	assert.Zero(t, local)
	assert.Equal(t, claim, claims.values[key])
	assert.Zero(t, claims.updateCount)
}

func TestGenerationProducerHandoffRejectsZeroOwnerWithoutMutation(t *testing.T) {
	key := stateKey{Generation: 10}
	claim := generationClaim{
		ObservedMonotonicNS: 10,
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
		Reserved:            [7]byte{6: generationGoProducerTag},
	}
	claims := &fakeBridgeMap{values: map[any]any{key: claim}}
	localClaim := claim

	handedOff, err := handoffGenerationProducerClaim(claims, key, &localClaim, 20)
	require.Error(t, err)
	assert.False(t, handedOff)
	assert.Zero(t, localClaim)
	assert.Equal(t, claim, claims.values[key])
	assert.Zero(t, claims.updateCount)

	guard := generationClaim{
		ObservedMonotonicNS: 11,
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecyclePublishing,
		Reserved:            [7]byte{6: generationGoProducerTag},
	}
	guards := &fakeBridgeMap{values: map[any]any{key.Owner: guard}}
	localGuard := guard

	handedOff, err = handoffGenerationProducerGuard(guards, key, &localGuard, 20)
	require.Error(t, err)
	assert.False(t, handedOff)
	assert.Zero(t, localGuard)
	assert.Equal(t, guard, guards.values[key.Owner])
	assert.Zero(t, guards.updateCount)
}

func TestGenerationProducerPairDoesNotRetryFailedExactHandoff(t *testing.T) {
	key := stateKey{Owner: Identity{TID: 3, PID: 2, Namespace: 1}, Generation: 10}
	claim := generationClaim{
		ObservedMonotonicNS: 10,
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
		Reserved:            [7]byte{6: generationGoProducerTag},
	}
	guard := generationClaim{
		ObservedMonotonicNS: 11,
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecyclePublishing,
		Reserved:            [7]byte{6: generationGoProducerTag},
	}
	injected := errors.New("injected exact handoff failure")
	claims := &fakeBridgeMap{values: map[any]any{key: claim}, updateErr: injected}
	guards := &fakeBridgeMap{values: map[any]any{key.Owner: guard}}
	localClaim := claim
	localGuard := guard
	now := func() time.Duration { return 20 }

	require.ErrorIs(t, handoffGenerationProducerFencePair(
		claims, guards, key, &localClaim, &localGuard, now,
	), injected)
	assert.Zero(t, localClaim)
	assert.Zero(t, localGuard)
	assert.Equal(t, claim, claims.values[key])
	assert.Equal(t, guard, guards.values[key.Owner])
	assert.Equal(t, 1, claims.updateCount)
	assert.Zero(t, guards.updateCount)

	require.NoError(t, handoffGenerationProducerFencePair(
		claims, guards, key, &localClaim, &localGuard, now,
	))
	assert.Equal(t, 1, claims.updateCount)
	assert.Zero(t, guards.updateCount)
}

func TestGenerationProducerPairDoesNotRetryFailedGuardHandoff(t *testing.T) {
	key := stateKey{Owner: Identity{TID: 3, PID: 2, Namespace: 1}, Generation: 10}
	claim := generationClaim{
		ObservedMonotonicNS: 10,
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
		Reserved:            [7]byte{6: generationGoProducerTag},
	}
	guard := generationClaim{
		ObservedMonotonicNS: 11,
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecyclePublishing,
		Reserved:            [7]byte{6: generationGoProducerTag},
	}
	injected := errors.New("injected guard handoff failure")
	claims := &fakeBridgeMap{values: map[any]any{key: claim}}
	guards := &fakeBridgeMap{
		values:    map[any]any{key.Owner: guard},
		updateErr: injected,
	}
	localClaim := claim
	localGuard := guard
	now := func() time.Duration { return 20 }

	require.ErrorIs(t, handoffGenerationProducerFencePair(
		claims, guards, key, &localClaim, &localGuard, now,
	), injected)
	assert.Zero(t, localClaim)
	assert.Zero(t, localGuard)
	handedExact := claims.values[key].(generationClaim)
	assert.Equal(t, lifecycleCleanup, handedExact.Lifecycle)
	assert.Equal(t, lifecycleConsumed, handedExact.Reserved[0])
	assert.Equal(t, guard, guards.values[key.Owner])
	assert.Equal(t, 1, claims.updateCount)
	assert.Equal(t, 1, guards.updateCount)

	require.NoError(t, handoffGenerationProducerFencePair(
		claims, guards, key, &localClaim, &localGuard, now,
	))
	assert.Equal(t, 1, claims.updateCount)
	assert.Equal(t, 1, guards.updateCount)
}

func TestGenerationProducerPairHandsOffExactBeforeGuard(t *testing.T) {
	key := stateKey{Owner: Identity{TID: 3, PID: 2, Namespace: 1}, Generation: 10}
	claim := generationClaim{
		ObservedMonotonicNS: 10,
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
		Reserved:            [7]byte{6: generationGoProducerTag},
	}
	guard := generationClaim{
		ObservedMonotonicNS: 11,
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecyclePublishing,
		Reserved:            [7]byte{6: generationGoProducerTag},
	}
	updates := make([]string, 0, 2)
	claims := &fakeBridgeMap{
		values: map[any]any{key: claim},
		beforeUpdate: func(any, any, ebpf.MapUpdateFlags) {
			updates = append(updates, "exact")
		},
	}
	guards := &fakeBridgeMap{
		values: map[any]any{key.Owner: guard},
		beforeUpdate: func(any, any, ebpf.MapUpdateFlags) {
			updates = append(updates, "guard")
		},
	}
	localClaim := claim
	localGuard := guard

	require.NoError(t, handoffGenerationProducerFencePair(
		claims, guards, key, &localClaim, &localGuard, func() time.Duration { return 20 },
	))
	assert.Equal(t, []string{"exact", "guard"}, updates)
	assert.Zero(t, localClaim)
	assert.Zero(t, localGuard)
	assert.Equal(t, lifecycleCleanup, claims.values[key].(generationClaim).Lifecycle)
	assert.Equal(t, lifecycleConsumed, claims.values[key].(generationClaim).Reserved[0])
	assert.Equal(t, lifecycleCleanup, guards.values[key.Owner].(generationClaim).Lifecycle)
	assert.Equal(t, lifecyclePublishing, guards.values[key.Owner].(generationClaim).Reserved[0])
}

func TestGenerationProducerHandoffDoesNotRetryByteIdenticalSuccessor(t *testing.T) {
	key := stateKey{Owner: Identity{TID: 3, PID: 2, Namespace: 1}, Generation: 10}
	claim := generationClaim{
		ObservedMonotonicNS: 10,
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
		Reserved:            [7]byte{6: generationGoProducerTag},
	}
	claims := &fakeBridgeMap{values: map[any]any{key: claim}}
	claims.afterUpdate = func(updatedKey, _ any) {
		claims.mu.Lock()
		claims.values[updatedKey] = claim
		claims.mu.Unlock()
	}
	local := claim

	handedOff, err := handoffGenerationProducerClaim(claims, key, &local, 20)
	require.NoError(t, err)
	require.True(t, handedOff)
	assert.Zero(t, local)
	assert.Equal(t, claim, claims.values[key])
	assert.Equal(t, 1, claims.updateCount)

	handedOff, err = handoffGenerationProducerClaim(claims, key, &local, 30)
	require.NoError(t, err)
	require.True(t, handedOff)
	assert.Equal(t, 1, claims.updateCount)
}

func TestGenerationProducerReleaseDoesNotDeleteByteIdenticalSuccessor(t *testing.T) {
	key := stateKey{Owner: Identity{TID: 3, PID: 2, Namespace: 1}, Generation: 10}
	claim := generationClaim{
		ObservedMonotonicNS: 10,
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
		Reserved:            [7]byte{6: generationGoProducerTag},
	}
	claims := &fakeBridgeMap{values: map[any]any{key: claim}}
	claims.afterDelete = func(deletedKey any) {
		claims.mu.Lock()
		claims.values[deletedKey] = claim
		claims.mu.Unlock()
	}
	local := claim

	released, err := releaseGenerationProducerClaim(claims, key, &local)
	require.NoError(t, err)
	require.True(t, released)
	assert.Zero(t, local)
	assert.Equal(t, claim, claims.values[key])
	assert.Equal(t, 1, claims.deleteCount)

	released, err = releaseGenerationProducerClaim(claims, key, &local)
	require.NoError(t, err)
	require.True(t, released)
	assert.Equal(t, 1, claims.deleteCount)
}

func TestGenerationProducerReleaseRejectsBPFValues(t *testing.T) {
	key := stateKey{Owner: Identity{TID: 3, PID: 2, Namespace: 1}, Generation: 10}

	t.Run("claim", func(t *testing.T) {
		claim := generationClaim{
			ObservedMonotonicNS: 10,
			ProcessIncarnation:  testProcessIncarnation,
			Lifecycle:           lifecycleConsumed,
		}
		claims := &fakeBridgeMap{values: map[any]any{key: claim}}
		local := claim

		released, err := releaseGenerationProducerClaim(claims, key, &local)
		require.Error(t, err)
		assert.False(t, released)
		assert.Zero(t, local)
		assert.Equal(t, claim, claims.values[key])
		assert.Zero(t, claims.deleteCount)
	})

	t.Run("guard", func(t *testing.T) {
		guard := generationClaim{
			ObservedMonotonicNS: 10,
			ProcessIncarnation:  key.Generation,
			Lifecycle:           lifecyclePublishing,
		}
		guards := &fakeBridgeMap{values: map[any]any{key.Owner: guard}}
		local := guard

		released, err := releaseGenerationProducerGuard(guards, key, &local)
		require.Error(t, err)
		assert.False(t, released)
		assert.Zero(t, local)
		assert.Equal(t, guard, guards.values[key.Owner])
		assert.Zero(t, guards.deleteCount)
	})
}

func TestAcquireGenerationTeardownFenceRevokesFailedGuardToken(t *testing.T) {
	key := stateKey{Owner: Identity{TID: 3, PID: 2, Namespace: 1}, Generation: 10}
	claim := generationClaim{
		ObservedMonotonicNS: 9,
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
		Reserved:            [7]byte{6: generationGoProducerTag},
	}
	foreignGuard := generationClaim{
		ObservedMonotonicNS: 10,
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecyclePublishing,
	}
	claims := &fakeBridgeMap{values: map[any]any{key: claim}}
	guards := &fakeBridgeMap{values: map[any]any{key.Owner: foreignGuard}}
	ambiguity := &fakeBridgeMap{values: map[any]any{key: uint64(0)}}

	fence, acquired, err := acquireGenerationTeardownFence(
		claims, guards, ambiguity, key, claim, 10,
	)
	require.NoError(t, err)
	assert.False(t, acquired)
	assert.False(t, fence.guardOwned)
	assert.Zero(t, fence.guardClaim)
	assert.Equal(t, foreignGuard, guards.values[key.Owner])
}

func TestAcquireGenerationTeardownFenceRejectsInvalidInputWithoutMutation(t *testing.T) {
	validKey := stateKey{Owner: Identity{TID: 3, PID: 2, Namespace: 1}, Generation: 10}
	validClaim := generationClaim{
		ObservedMonotonicNS: 9,
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
		Reserved:            [7]byte{6: generationGoProducerTag},
	}
	for _, test := range []struct {
		name  string
		key   stateKey
		claim generationClaim
		now   time.Duration
	}{
		{name: "zero generation", key: stateKey{Owner: validKey.Owner}, claim: validClaim, now: 10},
		{name: "zero owner", key: stateKey{Generation: validKey.Generation}, claim: validClaim, now: 10},
		{name: "reserved key", key: func() stateKey {
			key := validKey
			key.Reserved = 1
			return key
		}(), claim: validClaim, now: 10},
		{name: "zero time", key: validKey, claim: validClaim},
		{name: "negative time", key: validKey, claim: validClaim, now: -1},
		{name: "invalid claim", key: validKey, claim: generationClaim{}, now: 10},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := &fakeBridgeMap{values: map[any]any{test.key: test.claim}}
			guards := &fakeBridgeMap{values: make(map[any]any)}
			ambiguity := &fakeBridgeMap{values: map[any]any{test.key: uint64(0)}}

			_, acquired, err := acquireGenerationTeardownFence(
				claims, guards, ambiguity, test.key, test.claim, test.now,
			)
			require.Error(t, err)
			assert.False(t, acquired)
			assert.Empty(t, guards.values)
			assert.Equal(t, uint64(0), ambiguity.values[test.key])
		})
	}
}

func TestAcquireGenerationTeardownFenceDetectsPostPublicationReplacement(t *testing.T) {
	key := stateKey{Owner: Identity{TID: 3, PID: 2, Namespace: 1}, Generation: 10}
	claim := generationClaim{
		ObservedMonotonicNS: 9,
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
		Reserved:            [7]byte{6: generationGoProducerTag},
	}

	t.Run("guard", func(t *testing.T) {
		claims := &fakeBridgeMap{values: map[any]any{key: claim}}
		guards := &fakeBridgeMap{values: make(map[any]any)}
		ambiguity := &fakeBridgeMap{values: map[any]any{key: uint64(0)}}
		foreign := testGenerationClaim(lifecyclePublishing)
		foreign.ProcessIncarnation = key.Generation + 1
		guards.afterUpdate = func(updatedKey, _ any) {
			guards.mu.Lock()
			guards.values[updatedKey] = foreign
			guards.mu.Unlock()
		}

		fence, acquired, err := acquireGenerationTeardownFence(
			claims, guards, ambiguity, key, claim, 10,
		)
		require.Error(t, err)
		assert.False(t, acquired)
		assert.True(t, fence.guardOwned)
		assert.Equal(t, foreign, guards.values[key.Owner])
		assert.Equal(t, uint64(0), ambiguity.values[key])
	})

	t.Run("claim", func(t *testing.T) {
		claims := &fakeBridgeMap{values: map[any]any{key: claim}}
		guards := &fakeBridgeMap{values: make(map[any]any)}
		ambiguity := &fakeBridgeMap{values: map[any]any{key: uint64(0)}}
		replacement := claim
		replacement.ObservedMonotonicNS++
		guards.afterLookup = func(count int) {
			if count == 1 {
				claims.mu.Lock()
				claims.values[key] = replacement
				claims.mu.Unlock()
			}
		}

		fence, acquired, err := acquireGenerationTeardownFence(
			claims, guards, ambiguity, key, claim, 10,
		)
		require.NoError(t, err)
		assert.False(t, acquired)
		assert.True(t, fence.guardOwned)
		assert.Equal(t, replacement, claims.values[key])
		assert.Equal(t, fence.guardClaim, guards.values[key.Owner])
		assert.Equal(t, uint64(0), ambiguity.values[key])
	})
}

func TestPromoteGenerationAmbiguityNeverRecreatesOrOverwritesFailure(t *testing.T) {
	key := stateKey{Owner: Identity{TID: 3, PID: 2, Namespace: 1}, Generation: 10}

	t.Run("absent", func(t *testing.T) {
		ambiguity := &fakeBridgeMap{values: make(map[any]any)}
		_, err := promoteGenerationAmbiguity(ambiguity, key, 10)
		require.Error(t, err)
		assert.NotContains(t, ambiguity.values, key)
		assert.Zero(t, ambiguity.updateCount)
	})

	t.Run("failed update", func(t *testing.T) {
		injected := errors.New("injected marker update failure")
		ambiguity := &fakeBridgeMap{
			values:    map[any]any{key: uint64(0)},
			updateErr: injected,
		}
		_, err := promoteGenerationAmbiguity(ambiguity, key, 10)
		require.ErrorIs(t, err, injected)
		assert.Equal(t, uint64(0), ambiguity.values[key])
		assert.Equal(t, 1, ambiguity.updateCount)
	})
}

func TestGenerationProducerGuardHandoffDoesNotRetryByteIdenticalSuccessor(t *testing.T) {
	key := stateKey{Owner: Identity{TID: 3, PID: 2, Namespace: 1}, Generation: 10}
	guard := generationClaim{
		ObservedMonotonicNS: 10,
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecyclePublishing,
		Reserved:            [7]byte{6: generationGoProducerTag},
	}
	guards := &fakeBridgeMap{values: map[any]any{key.Owner: guard}}
	guards.afterUpdate = func(updatedKey, _ any) {
		guards.mu.Lock()
		guards.values[updatedKey] = guard
		guards.mu.Unlock()
	}
	local := guard

	handedOff, err := handoffGenerationProducerGuard(guards, key, &local, 20)
	require.NoError(t, err)
	require.True(t, handedOff)
	assert.Zero(t, local)
	assert.Equal(t, guard, guards.values[key.Owner])
	assert.Equal(t, 1, guards.updateCount)

	handedOff, err = handoffGenerationProducerGuard(guards, key, &local, 30)
	require.NoError(t, err)
	require.True(t, handedOff)
	assert.Equal(t, 1, guards.updateCount)
}

func TestGenerationProducerGuardReleaseDoesNotDeleteByteIdenticalSuccessor(t *testing.T) {
	key := stateKey{Owner: Identity{TID: 3, PID: 2, Namespace: 1}, Generation: 10}
	guard := generationClaim{
		ObservedMonotonicNS: 10,
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecyclePublishing,
		Reserved:            [7]byte{6: generationGoProducerTag},
	}
	guards := &fakeBridgeMap{values: map[any]any{key.Owner: guard}}
	guards.afterDelete = func(deletedKey any) {
		guards.mu.Lock()
		guards.values[deletedKey] = guard
		guards.mu.Unlock()
	}
	local := guard

	released, err := releaseGenerationProducerGuard(guards, key, &local)
	require.NoError(t, err)
	require.True(t, released)
	assert.Zero(t, local)
	assert.Equal(t, guard, guards.values[key.Owner])
	assert.Equal(t, 1, guards.deleteCount)

	released, err = releaseGenerationProducerGuard(guards, key, &local)
	require.NoError(t, err)
	require.True(t, released)
	assert.Equal(t, 1, guards.deleteCount)
}

func TestStatusForGenerationCleanupClaim(t *testing.T) {
	base := generationClaim{
		ObservedMonotonicNS: 10,
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleCleanup,
	}
	for _, test := range []struct {
		name   string
		mutate func(*generationClaim)
		status Status
	}{
		{name: "consumed", mutate: func(c *generationClaim) { c.Reserved[0] = lifecycleConsumed }, status: StatusAlreadyConsumed},
		{name: "discarded", mutate: func(c *generationClaim) { c.Reserved[0] = lifecycleDiscarded }, status: StatusAlreadyConsumed},
		{name: "stale", mutate: func(c *generationClaim) { c.Reserved[0] = lifecycleStale }, status: StatusAlreadyConsumed},
		{name: "ambiguous", mutate: func(c *generationClaim) { c.Reserved[0] = lifecycleAmbiguous }, status: StatusAmbiguous},
		{name: "publishing", mutate: func(c *generationClaim) { c.Reserved[0] = lifecyclePublishing }, status: StatusOverload},
		{name: "zero origin", status: StatusAmbiguous},
		{name: "active origin", mutate: func(c *generationClaim) { c.Reserved[0] = lifecycleActive }, status: StatusAmbiguous},
		{name: "recursive origin", mutate: func(c *generationClaim) { c.Reserved[0] = lifecycleCleanup }, status: StatusAmbiguous},
		{name: "reserved metadata", mutate: func(c *generationClaim) {
			c.Reserved[0] = lifecycleConsumed
			c.Reserved[6] = 1
		}, status: StatusAmbiguous},
		{name: "zero timestamp", mutate: func(c *generationClaim) {
			c.Reserved[0] = lifecycleConsumed
			c.ObservedMonotonicNS = 0
		}, status: StatusAmbiguous},
		{name: "zero incarnation", mutate: func(c *generationClaim) {
			c.Reserved[0] = lifecycleConsumed
			c.ProcessIncarnation = 0
		}, status: StatusAmbiguous},
		{name: "wrong incarnation", mutate: func(c *generationClaim) {
			c.Reserved[0] = lifecycleConsumed
			c.ProcessIncarnation++
		}, status: StatusAmbiguous},
	} {
		t.Run(test.name, func(t *testing.T) {
			claim := base
			if test.mutate != nil {
				test.mutate(&claim)
			}
			assert.Equal(t, test.status, statusForGenerationClaim(
				claim, testProcessIncarnation,
			))
		})
	}
}
