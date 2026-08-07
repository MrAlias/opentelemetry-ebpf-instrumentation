// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javabridge

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func aliasReplayCleanupFixture(t *testing.T) (*Cleanup, stateKey, stateValue) {
	t.Helper()
	handler := testMapHandler(nil, nil, nil)
	if handler.aliasReplays == nil {
		handler.aliasReplays = &fakeBridgeMap{values: make(map[any]any)}
	}
	cleanup := testCleanup(handler)
	cleanup.ttl = 30 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return 100 * time.Second }
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	state := stateValue{
		Lifecycle:           lifecycleActive,
		Aliases:             2,
		ObservedMonotonicNS: uint64(90 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
	}
	return cleanup, key, state
}

func activeAliasReplayForTest() aliasReplayValue {
	return aliasReplayValue{
		TransitionMonotonicNS: uint64(90 * time.Second),
		References:            2,
		Lifecycle:             lifecycleActive,
	}
}

func TestCleanupFinalizesExactAliasReplayUnderFullFence(t *testing.T) {
	cleanup, key, state := aliasReplayCleanupFixture(t)
	ownership := seedAgedGenerationCleanupFence(
		t, cleanup, key, state.ProcessIncarnation,
	)
	replayKey := aliasReplayKeyForState(key, state)
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	replays.values[replayKey] = activeAliasReplayForTest()

	var transitions []aliasReplayValue
	replays.afterUpdate = func(_, value any) {
		transitions = append(transitions, value.(aliasReplayValue))
	}

	ready, err := cleanup.ensureStateAliasReplayFinal(ownership, key, state)
	require.NoError(t, err)
	require.True(t, ready)
	require.Len(t, transitions, 2)
	assert.Equal(t, lifecyclePublishing, transitions[0].Lifecycle)
	assert.Equal(t, ownership.claim.ObservedMonotonicNS, transitions[0].TransitionMonotonicNS)
	assert.Equal(t, lifecycleStale, transitions[0].DesiredLifecycle)
	assert.Equal(t, generationGoProducerTag, transitions[0].ProducerTag)
	assert.Equal(t, lifecycleStale, transitions[1].Lifecycle)
	assert.Zero(t, transitions[1].DesiredLifecycle)
	assert.Zero(t, transitions[1].ProducerTag)
	assert.Equal(t, uint32(2), transitions[1].References)
	assert.True(t, validAliasReplayFinal(replays.values[replayKey].(aliasReplayValue)))
}

func TestCleanupAliasReplayReconcilesTaggedPublishingToAuthoritativeClaim(t *testing.T) {
	for _, test := range []struct {
		name             string
		transitionOffset uint64
		desired          uint8
	}{
		{name: "matching cleanup transition", desired: lifecycleStale},
		{
			name:             "producer handoff retains original timestamp",
			transitionOffset: 1,
			desired:          lifecycleStale,
		},
		{
			name:    "retarget crash boundary retains old replay semantic",
			desired: lifecycleConsumed,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cleanup, key, state := aliasReplayCleanupFixture(t)
			ownership := seedAgedGenerationCleanupFence(
				t, cleanup, key, state.ProcessIncarnation,
			)
			replayKey := aliasReplayKeyForState(key, state)
			publishing := aliasReplayValue{
				TransitionMonotonicNS: ownership.claim.ObservedMonotonicNS + test.transitionOffset,
				References:            2,
				Lifecycle:             lifecyclePublishing,
				DesiredLifecycle:      test.desired,
				ProducerTag:           generationGoProducerTag,
			}
			cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey] = publishing

			ready, err := cleanup.ensureStateAliasReplayFinal(ownership, key, state)
			require.NoError(t, err)
			require.True(t, ready)
			current := cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey].(aliasReplayValue)
			assert.True(t, validAliasReplayFinal(current))
			assert.Equal(t, lifecycleStale, current.Lifecycle)
			assert.Equal(t, publishing.TransitionMonotonicNS, current.TransitionMonotonicNS)
		})
	}
}

func TestCleanupGenerationReplayRescansAfterSweepSnapshot(t *testing.T) {
	cleanup, key, state := aliasReplayCleanupFixture(t)
	ownership := seedAgedGenerationCleanupFence(
		t, cleanup, key, state.ProcessIncarnation,
	)
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	require.NoError(t, cleanup.snapshotAliasReplayState())
	assert.Empty(t, cleanup.aliasReplayEntries)

	replayKey := aliasReplayKeyForState(key, state)
	replays.values[replayKey] = activeAliasReplayForTest()
	ready, err := cleanup.ensureGenerationAliasReplaysFinal(ownership, key)
	require.NoError(t, err)
	require.True(t, ready)
	assert.True(t, validAliasReplayFinal(replays.values[replayKey].(aliasReplayValue)))
}

func TestCleanupMarkerFreeClaimTailRequiresMatchingFinalReplay(t *testing.T) {
	for _, test := range []struct {
		name      string
		value     aliasReplayValue
		wantReady bool
	}{
		{name: "active", value: activeAliasReplayForTest()},
		{
			name: "publishing",
			value: aliasReplayValue{
				TransitionMonotonicNS: uint64(60 * time.Second),
				References:            2,
				Lifecycle:             lifecyclePublishing,
				DesiredLifecycle:      lifecycleStale,
				ProducerTag:           generationGoProducerTag,
			},
		},
		{
			name: "conflicting final",
			value: aliasReplayValue{
				TransitionMonotonicNS: uint64(60 * time.Second),
				References:            2,
				Lifecycle:             lifecycleConsumed,
			},
		},
		{
			name: "matching final survives fence retirement",
			value: aliasReplayValue{
				TransitionMonotonicNS: uint64(60 * time.Second),
				References:            2,
				Lifecycle:             lifecycleStale,
			},
			wantReady: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cleanup, key, state := aliasReplayCleanupFixture(t)
			claim := generationClaim{
				ObservedMonotonicNS: uint64(60 * time.Second),
				ProcessIncarnation:  state.ProcessIncarnation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{lifecycleStale},
			}
			cleanup.maps.claims.(*fakeBridgeMap).values[key] = claim
			replayKey := aliasReplayKeyForState(key, state)
			cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey] = test.value
			require.NoError(t, cleanup.snapshotAliasReplayState())
			cleanup.generationSnapshotComplete = true
			cleanup.stateSnapshotComplete = true
			cleanup.physicalGenerations = make(map[stateKey]struct{})

			ready, err := cleanup.releaseGenerationCleanupClaimTail(
				key, claim, 100*time.Second,
			)
			require.NoError(t, err)
			assert.Equal(t, test.wantReady, ready)
			if test.wantReady {
				assert.NotContains(t, cleanup.maps.claims.(*fakeBridgeMap).values, key)
				assert.Equal(t, test.value,
					cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey])
			} else {
				assert.Contains(t, cleanup.maps.claims.(*fakeBridgeMap).values, key)
			}
		})
	}
}

func TestCleanupAliasReplayOwnerGenerationReuseUsesFullReplayIdentity(t *testing.T) {
	cleanup, key, state := aliasReplayCleanupFixture(t)
	ownership := seedAgedGenerationCleanupFence(
		t, cleanup, key, state.ProcessIncarnation,
	)
	currentKey := aliasReplayKeyForState(key, state)
	oldKey := currentKey
	oldKey.ObservedMonotonicNS--
	oldKey.ProcessIncarnation++
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	replays.values[currentKey] = activeAliasReplayForTest()
	oldReplay := activeAliasReplayForTest()
	oldReplay.References = 9
	replays.values[oldKey] = oldReplay
	require.NoError(t, cleanup.snapshotAliasReplayState())

	ready, err := cleanup.ensureStateAliasReplayFinal(ownership, key, state)
	require.NoError(t, err)
	require.True(t, ready)
	assert.True(t, validAliasReplayFinal(replays.values[currentKey].(aliasReplayValue)))
	assert.Equal(t, oldReplay, replays.values[oldKey])

	ready, err = cleanup.ensureGenerationAliasReplaysFinal(ownership, key)
	require.NoError(t, err)
	assert.True(t, ready)
	assert.Equal(t, oldReplay, replays.values[oldKey])
}

func TestCleanupClaimTailIgnoresUnrelatedIncarnationReplay(t *testing.T) {
	cleanup, key, state := aliasReplayCleanupFixture(t)
	claim := generationClaim{
		ObservedMonotonicNS: uint64(60 * time.Second),
		ProcessIncarnation:  state.ProcessIncarnation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecycleStale},
	}
	cleanup.maps.claims.(*fakeBridgeMap).values[key] = claim
	currentKey := aliasReplayKeyForState(key, state)
	currentFinal := aliasReplayValue{
		TransitionMonotonicNS: uint64(60 * time.Second),
		References:            2,
		Lifecycle:             lifecycleStale,
	}
	oldKey := currentKey
	oldKey.ObservedMonotonicNS--
	oldKey.ProcessIncarnation++
	oldActive := activeAliasReplayForTest()
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	replays.values[currentKey] = currentFinal
	replays.values[oldKey] = oldActive
	require.NoError(t, cleanup.snapshotAliasReplayState())
	cleanup.generationSnapshotComplete = true
	cleanup.stateSnapshotComplete = true
	cleanup.physicalGenerations = make(map[stateKey]struct{})

	ready, err := cleanup.releaseGenerationCleanupClaimTail(
		key, claim, 100*time.Second,
	)
	require.NoError(t, err)
	assert.True(t, ready)
	assert.NotContains(t, cleanup.maps.claims.(*fakeBridgeMap).values, key)
	assert.Equal(t, currentFinal, replays.values[currentKey])
	assert.Equal(t, oldActive, replays.values[oldKey])
}

func TestCleanupAliasReplayBlocksUnsafeStateDeletionShapes(t *testing.T) {
	for _, test := range []struct {
		name   string
		replay *aliasReplayValue
	}{
		{name: "missing replay with aliases"},
		{
			name: "zero references with aliases",
			replay: func() *aliasReplayValue {
				value := activeAliasReplayForTest()
				value.References = 0
				return &value
			}(),
		},
		{
			name: "untagged publishing",
			replay: &aliasReplayValue{
				TransitionMonotonicNS: uint64(90 * time.Second),
				References:            2,
				Lifecycle:             lifecyclePublishing,
				DesiredLifecycle:      lifecycleStale,
			},
		},
		{
			name: "conflicting final",
			replay: &aliasReplayValue{
				TransitionMonotonicNS: uint64(90 * time.Second),
				References:            2,
				Lifecycle:             lifecycleConsumed,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cleanup, key, state := aliasReplayCleanupFixture(t)
			ownership := seedAgedGenerationCleanupFence(
				t, cleanup, key, state.ProcessIncarnation,
			)
			replayKey := aliasReplayKeyForState(key, state)
			if test.replay != nil {
				cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey] = *test.replay
			}

			ready, err := cleanup.ensureStateAliasReplayFinal(ownership, key, state)
			require.NoError(t, err)
			assert.False(t, ready)
			assert.Contains(t, cleanup.maps.claims.(*fakeBridgeMap).values, key)
			assert.Contains(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values, key.Owner)
			assert.Contains(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values, key)
		})
	}
}

func TestCleanupAliasReplayTransitionStopsWhenFenceChanges(t *testing.T) {
	cleanup, key, state := aliasReplayCleanupFixture(t)
	ownership := seedAgedGenerationCleanupFence(
		t, cleanup, key, state.ProcessIncarnation,
	)
	replayKey := aliasReplayKeyForState(key, state)
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	replays.values[replayKey] = activeAliasReplayForTest()
	replays.afterUpdate = func(_, _ any) {
		delete(cleanup.maps.ambiguity.(*fakeBridgeMap).values, key)
	}

	ready, err := cleanup.ensureStateAliasReplayFinal(ownership, key, state)
	require.Error(t, err)
	assert.False(t, ready)
	assert.Equal(t, lifecyclePublishing, replays.values[replayKey].(aliasReplayValue).Lifecycle)
	assert.Contains(t, cleanup.maps.claims.(*fakeBridgeMap).values, key)
	assert.Contains(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values, key.Owner)
}

func prepareAliasReplayTailSweep(t *testing.T, cleanup *Cleanup) {
	t.Helper()
	require.NoError(t, cleanup.snapshotAliasReplayState())
	cleanup.generationSnapshotComplete = true
	cleanup.stateSnapshotComplete = true
	cleanup.physicalGenerations = make(map[stateKey]struct{})
}

func TestCleanupRetiresFinalAliasReplayAfterTwoCompleteNoCarrierSnapshots(t *testing.T) {
	cleanup, key, state := aliasReplayCleanupFixture(t)
	replayKey := aliasReplayKeyForState(key, state)
	final := aliasReplayValue{
		TransitionMonotonicNS: uint64(90 * time.Second),
		References:            7, // Conservative overcount after LRU carrier loss.
		Lifecycle:             lifecycleStale,
	}
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	replays.values[replayKey] = final
	now := 100 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }

	prepareAliasReplayTailSweep(t, cleanup)
	require.NoError(t, cleanup.sweepAliasReplayTails(nil))
	assert.Contains(t, replays.values, replayKey)

	now += javaRemoteParentMinimumFenceAge - time.Nanosecond
	prepareAliasReplayTailSweep(t, cleanup)
	require.NoError(t, cleanup.sweepAliasReplayTails(nil))
	assert.Contains(t, replays.values, replayKey)

	now += time.Nanosecond
	prepareAliasReplayTailSweep(t, cleanup)
	require.NoError(t, cleanup.sweepAliasReplayTails(nil))
	assert.NotContains(t, replays.values, replayKey)
}

func TestCleanupGuardOnlyTailAllowsFinalReplaysToOutliveFence(t *testing.T) {
	cleanup, key, state := aliasReplayCleanupFixture(t)
	replayKey := aliasReplayKeyForState(key, state)
	predecessorKey := replayKey
	predecessorKey.ObservedMonotonicNS--
	predecessorKey.ProcessIncarnation++
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	replays.values[replayKey] = aliasReplayValue{
		TransitionMonotonicNS: uint64(70 * time.Second),
		References:            2,
		Lifecycle:             lifecycleStale,
	}
	replays.values[predecessorKey] = aliasReplayValue{
		TransitionMonotonicNS: uint64(69 * time.Second),
		References:            1,
		Lifecycle:             lifecycleConsumed,
	}
	guard := generationClaim{
		ObservedMonotonicNS: uint64(60 * time.Second),
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecyclePublishing},
	}
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
	guards.values[key.Owner] = guard

	prepareAliasReplayTailSweep(t, cleanup)
	released, err := cleanup.releaseGenerationCleanupGuardTail(
		key.Owner, guard, cleanup.monoTimeNow(),
	)
	require.NoError(t, err)
	require.True(t, released)
	assert.NotContains(t, guards.values, key.Owner)
	assert.Contains(t, replays.values, replayKey)
	assert.Contains(t, replays.values, predecessorKey)

	now := 100 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	prepareAliasReplayTailSweep(t, cleanup)
	require.NoError(t, cleanup.sweepAliasReplayTails(nil))
	assert.Contains(t, replays.values, replayKey)
	assert.Contains(t, replays.values, predecessorKey)

	now += javaRemoteParentMinimumFenceAge
	prepareAliasReplayTailSweep(t, cleanup)
	require.NoError(t, cleanup.sweepAliasReplayTails(nil))
	assert.NotContains(t, replays.values, replayKey)
	assert.NotContains(t, replays.values, predecessorKey)
}

func TestCleanupAliasReplayCarrierAndIncompleteSnapshotsPreserve(t *testing.T) {
	for _, test := range []struct {
		name           string
		taskCarrier    bool
		handoffCarrier bool
		iterateErr     bool
	}{
		{name: "task carrier", taskCarrier: true},
		{name: "handoff carrier", handoffCarrier: true},
		{name: "incomplete task snapshot", iterateErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cleanup, key, state := aliasReplayCleanupFixture(t)
			replayKey := aliasReplayKeyForState(key, state)
			cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey] = aliasReplayValue{
				TransitionMonotonicNS: uint64(90 * time.Second),
				Lifecycle:             lifecycleStale,
			}
			tasks := cleanup.maps.tasks.(*fakeBridgeMap)
			carrierIdentity := Identity{TID: 4, PID: 2, Namespace: 1}
			link := taskLink{
				Owner:               key.Owner,
				Generation:          key.Generation,
				ObservedMonotonicNS: state.ObservedMonotonicNS,
			}
			if test.taskCarrier {
				tasks.values[carrierIdentity] = link
			}
			handoff := handoffKey{PID: 2, Namespace: 1, Token: 7}
			if test.handoffCarrier {
				cleanup.maps.handoffs.(*fakeBridgeMap).values[handoff] = link
			}
			if test.iterateErr {
				tasks.iterateErr = errors.New("incomplete")
			}

			for _, now := range []time.Duration{100 * time.Second, 102 * time.Second} {
				cleanup.monoTimeNow = func() time.Duration { return now }
				snapshotErr := cleanup.snapshotAliasReplayState()
				if test.iterateErr {
					require.Error(t, snapshotErr)
				} else {
					require.NoError(t, snapshotErr)
				}
				cleanup.generationSnapshotComplete = true
				cleanup.stateSnapshotComplete = true
				cleanup.physicalGenerations = make(map[stateKey]struct{})
				require.NoError(t, cleanup.sweepAliasReplayTails(nil))
			}
			assert.Contains(t, cleanup.maps.aliasReplays.(*fakeBridgeMap).values, replayKey)
			if test.taskCarrier {
				assert.Contains(t, tasks.values, carrierIdentity)
			}
			if test.handoffCarrier {
				assert.Contains(t, cleanup.maps.handoffs.(*fakeBridgeMap).values, handoff)
			}
		})
	}
}

func TestCleanupAliasReplayValueChangeRestartsGrace(t *testing.T) {
	cleanup, key, state := aliasReplayCleanupFixture(t)
	replayKey := aliasReplayKeyForState(key, state)
	initial := aliasReplayValue{
		TransitionMonotonicNS: uint64(90 * time.Second),
		References:            2,
		Lifecycle:             lifecycleStale,
	}
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	replays.values[replayKey] = initial
	now := 100 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	prepareAliasReplayTailSweep(t, cleanup)
	require.NoError(t, cleanup.sweepAliasReplayTails(nil))

	changed := initial
	changed.References++
	replays.values[replayKey] = changed
	now += javaRemoteParentMinimumFenceAge
	prepareAliasReplayTailSweep(t, cleanup)
	require.NoError(t, cleanup.sweepAliasReplayTails(nil))
	assert.Contains(t, replays.values, replayKey)

	now += javaRemoteParentMinimumFenceAge
	prepareAliasReplayTailSweep(t, cleanup)
	require.NoError(t, cleanup.sweepAliasReplayTails(nil))
	assert.NotContains(t, replays.values, replayKey)
}

func TestCleanupAliasReplayStrictArtifactAndPublishingRules(t *testing.T) {
	cleanup, key, state := aliasReplayCleanupFixture(t)
	replayKey := aliasReplayKeyForState(key, state)
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	untaggedPublishing := aliasReplayValue{
		TransitionMonotonicNS: uint64(99 * time.Second),
		References:            1,
		Lifecycle:             lifecyclePublishing,
		DesiredLifecycle:      lifecycleStale,
	}
	replays.values[replayKey] = untaggedPublishing
	now := 100 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }

	for range 2 {
		prepareAliasReplayTailSweep(t, cleanup)
		require.NoError(t, cleanup.sweepAliasReplayTails(nil))
		now += javaRemoteParentMinimumFenceAge
	}
	assert.Contains(t, replays.values, replayKey)

	activeZero := activeAliasReplayForTest()
	activeZero.References = 0
	replays.values[replayKey] = activeZero
	cleanup.maps.states.(*fakeBridgeMap).values[key] = state
	for range 2 {
		prepareAliasReplayTailSweep(t, cleanup)
		require.NoError(t, cleanup.sweepAliasReplayTails(nil))
		now += javaRemoteParentMinimumFenceAge
	}
	assert.Contains(t, replays.values, replayKey)

	delete(cleanup.maps.states.(*fakeBridgeMap).values, key)
	for range 2 {
		prepareAliasReplayTailSweep(t, cleanup)
		require.NoError(t, cleanup.sweepAliasReplayTails(nil))
		now += javaRemoteParentMinimumFenceAge
	}
	assert.NotContains(t, replays.values, replayKey)
}

func TestCleanupActiveAliasReplayNeedsZeroReferencesWhileLive(t *testing.T) {
	cleanup, key, state := aliasReplayCleanupFixture(t)
	replayKey := aliasReplayKeyForState(key, state)
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	replays.values[replayKey] = activeAliasReplayForTest()
	now := 100 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }

	for range 2 {
		prepareAliasReplayTailSweep(t, cleanup)
		require.NoError(t, cleanup.sweepAliasReplayTails(nil))
		now += javaRemoteParentMinimumFenceAge
	}
	assert.Contains(t, replays.values, replayKey)

	// Once strict retrieval TTL proves that no alias can resume, a stable
	// reference overcount is reclaimable under the same two-snapshot proof.
	now = time.Duration(replayKey.ObservedMonotonicNS) + cleanup.ttl + time.Nanosecond
	prepareAliasReplayTailSweep(t, cleanup)
	require.NoError(t, cleanup.sweepAliasReplayTails(nil))
	assert.Contains(t, replays.values, replayKey)
	now += javaRemoteParentMinimumFenceAge
	prepareAliasReplayTailSweep(t, cleanup)
	require.NoError(t, cleanup.sweepAliasReplayTails(nil))
	assert.NotContains(t, replays.values, replayKey)
}

func TestCleanupMalformedAliasReplayStillRequiresGenerationArtifactAbsence(t *testing.T) {
	cleanup, key, state := aliasReplayCleanupFixture(t)
	replayKey := aliasReplayKeyForState(key, state)
	replayKey.Reserved = 1
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	replays.values[replayKey] = aliasReplayValue{
		TransitionMonotonicNS: uint64(90 * time.Second),
		Lifecycle:             lifecycleStale,
	}
	cleanup.maps.states.(*fakeBridgeMap).values[key] = state
	now := 100 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }

	for range 2 {
		prepareAliasReplayTailSweep(t, cleanup)
		require.NoError(t, cleanup.sweepAliasReplayTails(nil))
		now += javaRemoteParentMinimumFenceAge
	}
	assert.Contains(t, replays.values, replayKey)

	delete(cleanup.maps.states.(*fakeBridgeMap).values, key)
	for range 2 {
		prepareAliasReplayTailSweep(t, cleanup)
		require.NoError(t, cleanup.sweepAliasReplayTails(nil))
		now += javaRemoteParentMinimumFenceAge
	}
	assert.NotContains(t, replays.values, replayKey)
}

func TestCleanupMalformedStateWithAliasAuthorityFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name    string
		aliases uint32
		replay  bool
	}{
		{name: "state alias count", aliases: 1},
		{name: "exact replay", replay: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			cleanup, key, state := aliasReplayCleanupFixture(t)
			key.Reserved = 1
			state.Aliases = test.aliases
			cleanup.maps.states.(*fakeBridgeMap).values[key] = state
			if test.replay {
				replayKey := aliasReplayKeyForState(key, state)
				cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey] =
					activeAliasReplayForTest()
			}

			cleaned, err := cleanup.quarantineMalformedState(key, state)
			require.NoError(t, err)
			assert.False(t, cleaned)
			assert.Contains(t, cleanup.maps.states.(*fakeBridgeMap).values, key)
		})
	}
}
