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
		Connection: connectionInfo{
			SourcePort: 1234, DestinationPort: 443,
		},
		ConnectionNetNS:    42,
		ProcessIncarnation: testProcessIncarnation,
	}
	return cleanup, key, state
}

func authorizeGenerationReplayScanForTest(cleanup *Cleanup, key stateKey) {
	cleanup.generationReplayScanKey = key
	cleanup.generationReplayScanKeySet = true
}

func seedAliasReplayBindingGenerationForTest(
	cleanup *Cleanup,
	key stateKey,
	state stateValue,
) {
	claim := connectionClaim{
		Owner:              key.Owner,
		Generation:         key.Generation,
		NetNSCookie:        84,
		IncomingGeneration: key.Generation + 1,
		SocketCookie:       86,
		NetNS:              state.ConnectionNetNS,
	}
	cleanup.maps.states.(*fakeBridgeMap).values[key] = state
	cleanup.maps.generations.(*fakeBridgeMap).values[key] = generationIndexValue{
		Process:             javaProcessIdentity(key.Owner),
		ProcessIncarnation:  state.ProcessIncarnation,
		ObservedMonotonicNS: state.ObservedMonotonicNS,
	}
	cleanup.maps.connections.(*fakeBridgeMap).values[connectionInfoNS{
		Connection: state.Connection,
		NetNS:      state.ConnectionNetNS,
	}] = claim
	cleanup.maps.cookieConnections.(*fakeBridgeMap).values[connectionInfoNetNSCookie{
		Connection:  state.Connection,
		NetNSCookie: claim.NetNSCookie,
	}] = claim
}

func activeAliasReplayForTest() aliasReplayValue {
	return boundAliasReplayForTest(aliasReplayValue{
		TransitionMonotonicNS: uint64(90 * time.Second),
		References:            2,
		Lifecycle:             lifecycleActive,
	})
}

func TestCleanupFinalizesExactAliasReplayUnderFullFence(t *testing.T) {
	cleanup, key, state := aliasReplayCleanupFixture(t)
	seedAliasReplayBindingGenerationForTest(cleanup, key, state)
	ownership := seedAgedGenerationCleanupFence(
		t, cleanup, key, state.ProcessIncarnation,
	)
	replayKey := aliasReplayKeyForState(key, state)
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	initialReplay := activeAliasReplayForTest()
	replays.values[replayKey] = initialReplay

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
	for _, transition := range transitions {
		assert.Equal(t, aliasReplayBindingOf(initialReplay), aliasReplayBindingOf(transition))
	}
	assert.True(t, validAliasReplayFinal(replays.values[replayKey].(aliasReplayValue)))
}

func TestCleanupFinalAliasReplayProofRejectsImmutableTimestampReplacement(t *testing.T) {
	cleanup, key, state := aliasReplayCleanupFixture(t)
	seedAliasReplayBindingGenerationForTest(cleanup, key, state)
	ownership := seedAgedGenerationCleanupFence(
		t, cleanup, key, state.ProcessIncarnation,
	)
	replayKey := aliasReplayKeyForState(key, state)
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	replays.values[replayKey] = activeAliasReplayForTest()

	ready, err := cleanup.ensureStateAliasReplayFinal(ownership, key, state)
	require.NoError(t, err)
	require.True(t, ready)
	proof := cleanup.aliasReplayCleanupProofs[key]
	require.NotNil(t, proof)
	require.True(t, proof.finalized)
	final := replays.values[replayKey].(aliasReplayValue)
	replacement := final
	replacement.TransitionMonotonicNS++
	replays.values[replayKey] = replacement

	fenced, err := cleanup.generationCleanupFenceMatches(ownership)
	require.NoError(t, err)
	assert.False(t, fenced)
	finalMatches, err := cleanup.aliasReplayCleanupFinalProofMatches(key)
	require.NoError(t, err)
	assert.False(t, finalMatches)
}

func TestCleanupFinalAliasReplayProofAcceptsReferenceDrift(t *testing.T) {
	cleanup, key, state := aliasReplayCleanupFixture(t)
	seedAliasReplayBindingGenerationForTest(cleanup, key, state)
	ownership := seedAgedGenerationCleanupFence(
		t, cleanup, key, state.ProcessIncarnation,
	)
	replayKey := aliasReplayKeyForState(key, state)
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	replays.values[replayKey] = activeAliasReplayForTest()

	ready, err := cleanup.ensureStateAliasReplayFinal(ownership, key, state)
	require.NoError(t, err)
	require.True(t, ready)
	final := replays.values[replayKey].(aliasReplayValue)
	require.Positive(t, final.References)
	final.References--
	replays.values[replayKey] = final

	fenced, err := cleanup.generationCleanupFenceMatches(ownership)
	require.NoError(t, err)
	assert.True(t, fenced)
	finalMatches, err := cleanup.aliasReplayCleanupFinalProofMatches(key)
	require.NoError(t, err)
	assert.True(t, finalMatches)
}

func TestCleanupFinalizesRetiredAliasReplayWithoutCurrentIncarnation(t *testing.T) {
	cleanup, key, state := aliasReplayCleanupFixture(t)
	seedAliasReplayBindingGenerationForTest(cleanup, key, state)
	delete(cleanup.maps.incarnations.(*fakeBridgeMap).values, javaProcessIdentity(key.Owner))
	ownership := seedAgedGenerationCleanupFence(
		t, cleanup, key, state.ProcessIncarnation,
	)
	replayKey := aliasReplayKeyForState(key, state)
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	replays.values[replayKey] = activeAliasReplayForTest()

	ready, err := cleanup.ensureStateAliasReplayFinal(ownership, key, state)
	require.NoError(t, err)
	assert.True(t, ready)
	final := replays.values[replayKey].(aliasReplayValue)
	assert.True(t, validAliasReplayFinal(final))
	assert.Equal(t, lifecycleStale, final.Lifecycle)
	assert.Contains(t, cleanup.maps.states.(*fakeBridgeMap).values, key)
	assert.Contains(t, cleanup.maps.generations.(*fakeBridgeMap).values, key)
}

func TestCleanupRetiredAliasReplayCannotAuthorizeLiveSameSocketSuccessor(t *testing.T) {
	cleanup, key, state := aliasReplayCleanupFixture(t)
	seedAliasReplayBindingGenerationForTest(cleanup, key, state)
	delete(cleanup.maps.incarnations.(*fakeBridgeMap).values, javaProcessIdentity(key.Owner))
	ownership := seedAgedGenerationCleanupFence(
		t, cleanup, key, state.ProcessIncarnation,
	)
	replayKey := aliasReplayKeyForState(key, state)
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	initial := activeAliasReplayForTest()
	replays.values[replayKey] = initial

	const successorGeneration = uint64(11)
	connectionKey := connectionInfoNS{
		Connection: state.Connection, NetNS: state.ConnectionNetNS,
	}
	connection := cleanup.maps.connections.(*fakeBridgeMap).values[connectionKey].(connectionClaim)
	connection.Generation = successorGeneration
	cookieKey := connectionInfoNetNSCookie{
		Connection: state.Connection, NetNSCookie: connection.NetNSCookie,
	}
	cleanup.maps.connections.(*fakeBridgeMap).values[connectionKey] = connection
	cleanup.maps.cookieConnections.(*fakeBridgeMap).values[cookieKey] = connection
	successorKey := stateKey{Owner: key.Owner, Generation: successorGeneration}
	fallback := validEncodedRecord(t, successorGeneration)
	cleanup.maps.owners.(*fakeBridgeMap).values[key.Owner] = ownerValue{
		Generation: successorGeneration, ProcessIncarnation: state.ProcessIncarnation,
		Lifecycle: lifecycleActive,
	}
	cleanup.maps.remoteParents.(*fakeBridgeMap).values[key.Owner] = fallback
	cleanup.maps.states.(*fakeBridgeMap).values[successorKey] = stateValue{
		Lifecycle: lifecycleActive, ObservedMonotonicNS: uint64(90 * time.Second),
		Connection: state.Connection, ConnectionNetNS: state.ConnectionNetNS,
		ProcessIncarnation: state.ProcessIncarnation, Response: fallback,
	}
	cleanup.maps.generations.(*fakeBridgeMap).values[successorKey] = generationIndexValue{
		Process: javaProcessIdentity(key.Owner), ProcessIncarnation: state.ProcessIncarnation,
		ObservedMonotonicNS: uint64(90 * time.Second),
	}
	cleanup.maps.ambiguity.(*fakeBridgeMap).values[successorKey] = uint64(0)

	ready, err := cleanup.ensureStateAliasReplayFinal(ownership, key, state)
	require.NoError(t, err)
	assert.False(t, ready)
	assert.Equal(t, initial, replays.values[replayKey])
	assert.Equal(t, state, cleanup.maps.states.(*fakeBridgeMap).values[key])
	assert.Contains(t, cleanup.maps.generations.(*fakeBridgeMap).values, key)
	assert.Contains(t, cleanup.maps.claims.(*fakeBridgeMap).values, key)
	assert.Contains(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values, key.Owner)
}

func cleanupSameSocketSuccessorFixture(
	t *testing.T,
) (*MapHandler, *Cleanup, stateKey, stateValue, aliasReplayKey, aliasReplayValue,
	sameSocketSuccessorSnapshot, terminalValue,
) {
	t.Helper()
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	oldKey := stateKey{Owner: owner, Generation: 10}
	handler := testMapHandler(
		map[Identity]any{owner: validEncodedRecord(t, oldKey.Generation)}, nil, nil,
	)
	oldState := handler.states.(*fakeBridgeMap).values[oldKey].(stateValue)
	oldState.Aliases = 2
	handler.states.(*fakeBridgeMap).values[oldKey] = oldState
	replayKey := aliasReplayKeyForState(oldKey, oldState)
	oldReplay := boundAliasReplayForStateForTest(
		handler, oldKey, oldState, aliasReplayValue{
			TransitionMonotonicNS: oldState.ObservedMonotonicNS,
			References:            oldState.Aliases,
			Lifecycle:             lifecycleActive,
		},
	)
	handler.aliasReplays.(*fakeBridgeMap).values[replayKey] = oldReplay

	successor := seedSameSocketSuccessorForTest(t, handler, oldKey, oldState)
	successor.fallback = validEncodedRecordObservedAt(t, 11, 40*time.Second)
	successor.state.ObservedMonotonicNS = uint64(40 * time.Second)
	successor.state.Response = successor.fallback
	successor.index.ObservedMonotonicNS = successor.state.ObservedMonotonicNS
	delete(handler.aliasReplays.(*fakeBridgeMap).values, successor.replayKey)
	successor.replayKey = aliasReplayKeyForState(successor.key, successor.state)
	successor.replay.TransitionMonotonicNS = successor.state.ObservedMonotonicNS
	handler.remoteParents.(*fakeBridgeMap).values[owner] = successor.fallback
	handler.states.(*fakeBridgeMap).values[successor.key] = successor.state
	handler.generations.(*fakeBridgeMap).values[successor.key] = successor.index
	handler.aliasReplays.(*fakeBridgeMap).values[successor.replayKey] = successor.replay

	oldTerminal := terminalValue{
		Generation:          oldKey.Generation,
		ObservedMonotonicNS: oldState.ObservedMonotonicNS,
		ProcessIncarnation:  oldState.ProcessIncarnation,
		Lifecycle:           lifecycleStale,
	}
	handler.terminals.(*fakeBridgeMap).values[owner] = oldTerminal
	cleanup := testCleanup(handler)
	cleanup.monoTimeNow = func() time.Duration { return 41 * time.Second }
	return handler, cleanup, oldKey, oldState, replayKey, oldReplay, successor, oldTerminal
}

func TestCleanupSameSocketSuccessorSurvivesOldAliasTeardown(t *testing.T) {
	handler, cleanup, oldKey, oldState, replayKey, oldReplay, successor, oldTerminal := cleanupSameSocketSuccessorFixture(t)
	seedAgedGenerationCleanupFence(t, cleanup, oldKey, oldState.ProcessIncarnation)

	var total CleanupStats
	for range 4 {
		stats, err := cleanup.SweepWithStats()
		require.NoError(t, err)
		total.Cleaned += stats.Cleaned
		total.Evicted += stats.Evicted
	}

	assert.Equal(t, CleanupStats{Cleaned: 1}, total)
	assert.NotContains(t, handler.states.(*fakeBridgeMap).values, oldKey)
	assert.NotContains(t, handler.generations.(*fakeBridgeMap).values, oldKey)
	assert.NotContains(t, handler.ambiguity.(*fakeBridgeMap).values, oldKey)
	assert.NotContains(t, handler.claims.(*fakeBridgeMap).values, oldKey)
	assert.NotContains(t, handler.ownerGuards.(*fakeBridgeMap).values, oldKey.Owner)
	assert.Equal(t, oldTerminal, handler.terminals.(*fakeBridgeMap).values[oldKey.Owner])
	finalReplay, present := handler.aliasReplays.(*fakeBridgeMap).values[replayKey].(aliasReplayValue)
	require.True(t, present)
	assert.True(t, validAliasReplayFinal(finalReplay))
	assert.Equal(t, lifecycleStale, finalReplay.Lifecycle)
	assert.Equal(t, oldReplay.References, finalReplay.References)
	assert.Equal(t, aliasReplayBindingOf(oldReplay), aliasReplayBindingOf(finalReplay))
	assertSameSocketSuccessorUnchanged(t, handler, successor)
}

func TestCleanupSameSocketSuccessorReplacementAfterReplayFinalizationRetainsOldFence(
	t *testing.T,
) {
	handler, cleanup, oldKey, oldState, replayKey, oldReplay, successor, oldTerminal := cleanupSameSocketSuccessorFixture(t)
	ownership := seedAgedGenerationCleanupFence(
		t, cleanup, oldKey, oldState.ProcessIncarnation,
	)
	replays := handler.aliasReplays.(*fakeBridgeMap)
	states := handler.states.(*fakeBridgeMap)
	updates := 0
	mutatedSuccessor := successor.state
	mutatedSuccessor.ObservedMonotonicNS++
	replays.afterUpdate = func(_, _ any) {
		updates++
		if updates != 2 {
			return
		}
		states.mu.Lock()
		states.values[successor.key] = mutatedSuccessor
		states.mu.Unlock()
	}

	stats, err := cleanup.SweepWithStats()
	require.Error(t, err)
	assert.Equal(t, CleanupStats{}, stats)
	assert.Equal(t, 2, updates)
	assert.Equal(t, oldState, handler.states.(*fakeBridgeMap).values[oldKey])
	assert.Contains(t, handler.generations.(*fakeBridgeMap).values, oldKey)
	assert.Equal(t, ownership.fence.markedAt,
		handler.ambiguity.(*fakeBridgeMap).values[oldKey])
	assert.Equal(t, ownership.claim, handler.claims.(*fakeBridgeMap).values[oldKey])
	assert.Equal(t, ownership.fence.guardClaim,
		handler.ownerGuards.(*fakeBridgeMap).values[oldKey.Owner])
	assert.Equal(t, oldTerminal,
		handler.terminals.(*fakeBridgeMap).values[oldKey.Owner])
	finalReplay := replays.values[replayKey].(aliasReplayValue)
	assert.True(t, validAliasReplayFinal(finalReplay))
	assert.Equal(t, aliasReplayBindingOf(oldReplay), aliasReplayBindingOf(finalReplay))
	successor.state = mutatedSuccessor
	assertSameSocketSuccessorUnchanged(t, handler, successor)
}

func TestCleanupAliasReplayProofFreezesExactReplayKeyAcrossSameSweepRoots(t *testing.T) {
	for _, test := range []struct {
		name         string
		replaceState bool
		replaceIndex bool
	}{
		{name: "old state replacement only", replaceState: true},
		{name: "old generation-index replacement only", replaceIndex: true},
		{name: "old state and generation-index replacement", replaceState: true, replaceIndex: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler, cleanup, oldKey, oldState, replayKey, _, _, _ := cleanupSameSocketSuccessorFixture(t)
			ownership := seedAgedGenerationCleanupFence(
				t, cleanup, oldKey, oldState.ProcessIncarnation,
			)
			ready, err := cleanup.ensureStateAliasReplayFinal(ownership, oldKey, oldState)
			require.NoError(t, err)
			require.True(t, ready)
			require.Equal(t, replayKey, cleanup.aliasReplayCleanupKeys[oldKey])
			require.Equal(t, replayKey, cleanup.aliasReplayCleanupProofs[oldKey].replayKey)

			replacementState := oldState
			replacementState.ObservedMonotonicNS++
			replacementState.Response = validEncodedRecordObservedAt(
				t, oldKey.Generation, time.Duration(replacementState.ObservedMonotonicNS),
			)
			replacementKey := aliasReplayKeyForState(oldKey, replacementState)
			require.NotEqual(t, replayKey, replacementKey)
			replacementReplay := handler.aliasReplays.(*fakeBridgeMap).values[replayKey].(aliasReplayValue)
			replacementReplay.TransitionMonotonicNS = replacementState.ObservedMonotonicNS
			handler.aliasReplays.(*fakeBridgeMap).values[replacementKey] = replacementReplay
			if test.replaceState {
				handler.states.(*fakeBridgeMap).values[oldKey] = replacementState
			}
			if test.replaceIndex {
				replacementIndex := handler.generations.(*fakeBridgeMap).values[oldKey].(generationIndexValue)
				replacementIndex.ObservedMonotonicNS = replacementState.ObservedMonotonicNS
				handler.generations.(*fakeBridgeMap).values[oldKey] = replacementIndex
			}

			ready, err = cleanup.ensureStateAliasReplayFinal(ownership, oldKey, replacementState)
			require.NoError(t, err)
			assert.False(t, ready)
			assert.Equal(t, replayKey, cleanup.aliasReplayCleanupKeys[oldKey])
			assert.Equal(t, replayKey, cleanup.aliasReplayCleanupProofs[oldKey].replayKey)
			assert.Contains(t, handler.aliasReplays.(*fakeBridgeMap).values, replacementKey)
			finalProof, err := cleanup.aliasReplayCleanupFinalProofMatches(oldKey)
			require.NoError(t, err)
			assert.True(t, finalProof, "the immutable K1 replay remains final")
			fenced, err := cleanup.generationCleanupFenceMatches(ownership)
			require.NoError(t, err)
			assert.False(t, fenced, "K2/S2 cannot authorize retirement under the cached K1 proof")
			assert.Contains(t, handler.claims.(*fakeBridgeMap).values, oldKey)
			assert.Contains(t, handler.ownerGuards.(*fakeBridgeMap).values, oldKey.Owner)
		})
	}
}

func TestCleanupRejectsAliasReplayBindingMismatchWithoutMutation(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*Cleanup, aliasReplayKey, stateValue)
	}{
		{name: "replay connection", mutate: func(cleanup *Cleanup, replayKey aliasReplayKey, _ stateValue) {
			replay := cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey].(aliasReplayValue)
			replay.Connection.SourcePort++
			cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey] = replay
		}},
		{name: "replay network namespace", mutate: func(cleanup *Cleanup, replayKey aliasReplayKey, _ stateValue) {
			replay := cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey].(aliasReplayValue)
			replay.ConnectionNetNS++
			cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey] = replay
		}},
		{name: "replay network namespace cookie", mutate: func(cleanup *Cleanup, replayKey aliasReplayKey, _ stateValue) {
			replay := cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey].(aliasReplayValue)
			replay.ConnectionNetNSCookie++
			cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey] = replay
		}},
		{name: "replay socket cookie", mutate: func(cleanup *Cleanup, replayKey aliasReplayKey, _ stateValue) {
			replay := cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey].(aliasReplayValue)
			replay.SocketCookie++
			cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey] = replay
		}},
		{name: "connection twins differ", mutate: func(cleanup *Cleanup, _ aliasReplayKey, state stateValue) {
			connectionKey := connectionInfoNS{Connection: state.Connection, NetNS: state.ConnectionNetNS}
			claim := cleanup.maps.connections.(*fakeBridgeMap).values[connectionKey].(connectionClaim)
			claim.SocketCookie++
			cleanup.maps.connections.(*fakeBridgeMap).values[connectionKey] = claim
		}},
		{name: "cookie twin missing", mutate: func(cleanup *Cleanup, replayKey aliasReplayKey, state stateValue) {
			replay := cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey].(aliasReplayValue)
			delete(cleanup.maps.cookieConnections.(*fakeBridgeMap).values, connectionInfoNetNSCookie{
				Connection: state.Connection, NetNSCookie: replay.ConnectionNetNSCookie,
			})
		}},
		{name: "malformed connection twins", mutate: func(cleanup *Cleanup, replayKey aliasReplayKey, state stateValue) {
			replay := cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey].(aliasReplayValue)
			connectionKey := connectionInfoNS{Connection: state.Connection, NetNS: state.ConnectionNetNS}
			cookieKey := connectionInfoNetNSCookie{
				Connection: state.Connection, NetNSCookie: replay.ConnectionNetNSCookie,
			}
			claim := cleanup.maps.connections.(*fakeBridgeMap).values[connectionKey].(connectionClaim)
			claim.Reserved = 1
			cleanup.maps.connections.(*fakeBridgeMap).values[connectionKey] = claim
			cleanup.maps.cookieConnections.(*fakeBridgeMap).values[cookieKey] = claim
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cleanup, key, state := aliasReplayCleanupFixture(t)
			seedAliasReplayBindingGenerationForTest(cleanup, key, state)
			ownership := seedAgedGenerationCleanupFence(
				t, cleanup, key, state.ProcessIncarnation,
			)
			replayKey := aliasReplayKeyForState(key, state)
			replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
			replays.values[replayKey] = activeAliasReplayForTest()
			test.mutate(cleanup, replayKey, state)
			mutatedReplay := replays.values[replayKey].(aliasReplayValue)
			updates := replays.updateCount

			ready, err := cleanup.ensureStateAliasReplayFinal(ownership, key, state)
			require.NoError(t, err)
			assert.False(t, ready)
			assert.Equal(t, updates, replays.updateCount)
			assert.Equal(t, mutatedReplay, replays.values[replayKey])
			assert.Equal(t, state, cleanup.maps.states.(*fakeBridgeMap).values[key])
			assert.Contains(t, cleanup.maps.claims.(*fakeBridgeMap).values, key)
			assert.Contains(t, cleanup.maps.ownerGuards.(*fakeBridgeMap).values, key.Owner)
			assert.NotZero(t, cleanup.maps.ambiguity.(*fakeBridgeMap).values[key])
		})
	}
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
			seedAliasReplayBindingGenerationForTest(cleanup, key, state)
			ownership := seedAgedGenerationCleanupFence(
				t, cleanup, key, state.ProcessIncarnation,
			)
			replayKey := aliasReplayKeyForState(key, state)
			publishing := boundAliasReplayForTest(aliasReplayValue{
				TransitionMonotonicNS: ownership.claim.ObservedMonotonicNS + test.transitionOffset,
				References:            2,
				Lifecycle:             lifecyclePublishing,
				DesiredLifecycle:      test.desired,
				ProducerTag:           generationGoProducerTag,
			})
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
	authorizeGenerationReplayScanForTest(cleanup, key)
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
			value: boundAliasReplayForTest(aliasReplayValue{
				TransitionMonotonicNS: uint64(60 * time.Second),
				References:            2,
				Lifecycle:             lifecyclePublishing,
				DesiredLifecycle:      lifecycleStale,
				ProducerTag:           generationGoProducerTag,
			}),
		},
		{
			name: "conflicting final",
			value: boundAliasReplayForTest(aliasReplayValue{
				TransitionMonotonicNS: uint64(60 * time.Second),
				References:            2,
				Lifecycle:             lifecycleConsumed,
			}),
		},
		{
			name: "matching final survives fence retirement",
			value: boundAliasReplayForTest(aliasReplayValue{
				TransitionMonotonicNS: uint64(60 * time.Second),
				References:            2,
				Lifecycle:             lifecycleStale,
			}),
			wantReady: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cleanup, key, state := aliasReplayCleanupFixture(t)
			authorizeGenerationReplayScanForTest(cleanup, key)
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

func TestCleanupMarkerFreeClaimTailSyntheticExemptionIsNarrow(t *testing.T) {
	for _, test := range []struct {
		name               string
		processIncarnation func(stateKey) uint64
		origin             uint8
		tagged             bool
		wantReleased       bool
		failReplayScan     bool
	}{
		{
			name: "synthetic ambiguous",
			processIncarnation: func(key stateKey) uint64 {
				return key.Generation
			},
			origin:         lifecycleAmbiguous,
			tagged:         true,
			wantReleased:   true,
			failReplayScan: true,
		},
		{
			name: "JVM ambiguous",
			processIncarnation: func(stateKey) uint64 {
				return testProcessIncarnation
			},
			origin: lifecycleAmbiguous,
		},
		{
			name: "synthetic non-ambiguous",
			processIncarnation: func(key stateKey) uint64 {
				return key.Generation
			},
			origin: lifecycleStale,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner := Identity{TID: 3, PID: 2, Namespace: 1}
			key := stateKey{Owner: owner, Generation: 10}
			processIncarnation := test.processIncarnation(key)
			claim := generationClaim{
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  processIncarnation,
				Lifecycle:           lifecycleCleanup,
				Reserved:            [7]byte{test.origin},
			}
			if test.tagged {
				claim.Reserved[6] = generationGoProducerTag
			}
			cleanup := testCleanup(testMapHandler(nil, nil, nil))
			cleanup.maps.claims.(*fakeBridgeMap).values[key] = claim
			replayKey := aliasReplayKey{
				Owner:               owner,
				Generation:          key.Generation,
				ObservedMonotonicNS: uint64(10 * time.Second),
				ProcessIncarnation:  processIncarnation,
			}
			replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
			replays.values[replayKey] = activeAliasReplayForTest()
			if test.failReplayScan {
				replays.iterateErr = errors.New("injected replay scan failure")
			} else {
				require.NoError(t, cleanup.snapshotAliasReplayState())
			}
			cleanup.generationSnapshotComplete = true
			cleanup.stateSnapshotComplete = true
			cleanup.physicalGenerations = make(map[stateKey]struct{})

			released, err := cleanup.releaseGenerationCleanupClaimTail(
				key, claim, 41*time.Second,
			)
			require.NoError(t, err)
			assert.Equal(t, test.wantReleased, released)
			if test.wantReleased {
				assert.NotContains(t, cleanup.maps.claims.(*fakeBridgeMap).values, key)
			} else {
				assert.Equal(t, claim, cleanup.maps.claims.(*fakeBridgeMap).values[key])
			}
			assert.Equal(t, activeAliasReplayForTest(), replays.values[replayKey])
		})
	}
}

func TestCleanupAliasReplayOwnerGenerationReuseUsesFullReplayIdentity(t *testing.T) {
	cleanup, key, state := aliasReplayCleanupFixture(t)
	seedAliasReplayBindingGenerationForTest(cleanup, key, state)
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
	authorizeGenerationReplayScanForTest(cleanup, key)
	currentKey := aliasReplayKeyForState(key, state)
	currentFinal := boundAliasReplayForTest(aliasReplayValue{
		TransitionMonotonicNS: uint64(60 * time.Second),
		References:            2,
		Lifecycle:             lifecycleStale,
	})
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
			replay: boundAliasReplayPointerForTest(aliasReplayValue{
				TransitionMonotonicNS: uint64(90 * time.Second),
				References:            2,
				Lifecycle:             lifecyclePublishing,
				DesiredLifecycle:      lifecycleStale,
			}),
		},
		{
			name: "conflicting final",
			replay: boundAliasReplayPointerForTest(aliasReplayValue{
				TransitionMonotonicNS: uint64(90 * time.Second),
				References:            2,
				Lifecycle:             lifecycleConsumed,
			}),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cleanup, key, state := aliasReplayCleanupFixture(t)
			seedAliasReplayBindingGenerationForTest(cleanup, key, state)
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
	seedAliasReplayBindingGenerationForTest(cleanup, key, state)
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

func seedAliasReplayRetirements(
	cleanup *Cleanup,
	retired map[retiredProcessKey]struct{},
) {
	for key := range retired {
		delete(cleanup.maps.incarnations.(*fakeBridgeMap).values, key.Process)
		cleanup.maps.retired.(*fakeBridgeMap).values[key] = uint64(time.Second)
	}
}

func TestCleanupRetiresFinalAliasReplayForRetiredProcessAfterTwoCompleteNoCarrierSnapshots(
	t *testing.T,
) {
	cleanup, key, state := aliasReplayCleanupFixture(t)
	replayKey := aliasReplayKeyForState(key, state)
	final := boundAliasReplayForTest(aliasReplayValue{
		TransitionMonotonicNS: uint64(90 * time.Second),
		References:            7, // Conservative overcount after LRU carrier loss.
		Lifecycle:             lifecycleStale,
	})
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	replays.values[replayKey] = final
	now := 100 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	retired := map[retiredProcessKey]struct{}{
		{
			Process:            javaProcessIdentity(key.Owner),
			ProcessIncarnation: replayKey.ProcessIncarnation,
		}: {},
	}
	seedAliasReplayRetirements(cleanup, retired)

	prepareAliasReplayTailSweep(t, cleanup)
	require.NoError(t, cleanup.sweepAliasReplayTails(retired))
	assert.Contains(t, replays.values, replayKey)

	now += javaRemoteParentMinimumFenceAge - time.Nanosecond
	prepareAliasReplayTailSweep(t, cleanup)
	require.NoError(t, cleanup.sweepAliasReplayTails(retired))
	assert.Contains(t, replays.values, replayKey)

	now += time.Nanosecond
	prepareAliasReplayTailSweep(t, cleanup)
	require.NoError(t, cleanup.sweepAliasReplayTails(retired))
	assert.NotContains(t, replays.values, replayKey)
}

func TestCleanupPreservesPositiveAliasReplayWithoutExactRetirementMarker(t *testing.T) {
	cleanup, key, state := aliasReplayCleanupFixture(t)
	replayKey := aliasReplayKeyForState(key, state)
	replay := boundAliasReplayForTest(aliasReplayValue{
		TransitionMonotonicNS: uint64(90 * time.Second),
		References:            3,
		Lifecycle:             lifecycleStale,
	})
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	replays.values[replayKey] = replay
	process := javaProcessIdentity(key.Owner)
	delete(cleanup.maps.incarnations.(*fakeBridgeMap).values, process)
	now := 100 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }

	for range 3 {
		prepareAliasReplayTailSweep(t, cleanup)
		require.NoError(t, cleanup.sweepAliasReplayTails(nil))
		now += javaRemoteParentMinimumFenceAge
	}
	assert.Equal(t, replay, replays.values[replayKey],
		"incarnation absence and P do not exclude a delayed direct CAPTURE retain")

	retiredKey := retiredProcessKey{
		Process: process, ProcessIncarnation: replayKey.ProcessIncarnation,
	}
	cleanup.maps.retired.(*fakeBridgeMap).values[retiredKey] = uint64(time.Second)
	retired := map[retiredProcessKey]struct{}{retiredKey: {}}
	prepareAliasReplayTailSweep(t, cleanup)
	require.NoError(t, cleanup.sweepAliasReplayTails(retired))
	now += javaRemoteParentMinimumFenceAge
	prepareAliasReplayTailSweep(t, cleanup)
	require.NoError(t, cleanup.sweepAliasReplayTails(retired))
	assert.NotContains(t, replays.values, replayKey)
}

func TestCleanupGuardOnlyTailAllowsFinalReplaysToOutliveFence(t *testing.T) {
	cleanup, key, state := aliasReplayCleanupFixture(t)
	replayKey := aliasReplayKeyForState(key, state)
	predecessorKey := replayKey
	predecessorKey.ObservedMonotonicNS--
	predecessorKey.ProcessIncarnation++
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	replays.values[replayKey] = boundAliasReplayForTest(aliasReplayValue{
		TransitionMonotonicNS: uint64(70 * time.Second),
		References:            2,
		Lifecycle:             lifecycleStale,
	})
	replays.values[predecessorKey] = boundAliasReplayForTest(aliasReplayValue{
		TransitionMonotonicNS: uint64(69 * time.Second),
		References:            1,
		Lifecycle:             lifecycleConsumed,
	})
	guard := generationClaim{
		ObservedMonotonicNS: uint64(60 * time.Second),
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecyclePublishing},
	}
	guards := cleanup.maps.ownerGuards.(*fakeBridgeMap)
	guards.values[key.Owner] = guard

	prepareAliasReplayTailSweep(t, cleanup)
	authorizeGenerationReplayScanForTest(cleanup, key)
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
	retired := map[retiredProcessKey]struct{}{
		{
			Process:            javaProcessIdentity(key.Owner),
			ProcessIncarnation: replayKey.ProcessIncarnation,
		}: {},
		{
			Process:            javaProcessIdentity(predecessorKey.Owner),
			ProcessIncarnation: predecessorKey.ProcessIncarnation,
		}: {},
	}
	seedAliasReplayRetirements(cleanup, retired)
	prepareAliasReplayTailSweep(t, cleanup)
	require.NoError(t, cleanup.sweepAliasReplayTails(retired))
	assert.Contains(t, replays.values, replayKey)
	assert.Contains(t, replays.values, predecessorKey)

	now += javaRemoteParentMinimumFenceAge
	prepareAliasReplayTailSweep(t, cleanup)
	require.NoError(t, cleanup.sweepAliasReplayTails(retired))
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
			cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey] = boundAliasReplayForTest(aliasReplayValue{
				TransitionMonotonicNS: uint64(90 * time.Second),
				Lifecycle:             lifecycleStale,
			})
			tasks := cleanup.maps.tasks.(*fakeBridgeMap)
			carrierIdentity := Identity{TID: 4, PID: 2, Namespace: 1}
			link := taskLink{
				Owner:               key.Owner,
				Generation:          key.Generation,
				ObservedMonotonicNS: state.ObservedMonotonicNS,
				ProcessIncarnation:  testProcessIncarnation,
			}
			if test.taskCarrier {
				tasks.values[carrierIdentity] = link
			}
			handoff := handoffKey{
				PID: 2, Namespace: 1, Token: 7,
				ProcessIncarnation: testProcessIncarnation,
			}
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

func TestCleanupCrossProcessCarrierDoesNotPreserveAliasReplay(t *testing.T) {
	for _, test := range []struct {
		name    string
		taskKey Identity
		handoff handoffKey
	}{
		{
			name:    "task PID mismatch",
			taskKey: Identity{TID: 4, PID: 9, Namespace: 1},
		},
		{
			name:    "task namespace mismatch",
			taskKey: Identity{TID: 4, PID: 2, Namespace: 9},
		},
		{
			name: "handoff PID mismatch",
			handoff: handoffKey{
				PID: 9, Namespace: 1, Token: 7,
				ProcessIncarnation: testProcessIncarnation,
			},
		},
		{
			name: "handoff namespace mismatch",
			handoff: handoffKey{
				PID: 2, Namespace: 9, Token: 7,
				ProcessIncarnation: testProcessIncarnation,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cleanup, key, state := aliasReplayCleanupFixture(t)
			replayKey := aliasReplayKeyForState(key, state)
			cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey] = boundAliasReplayForTest(aliasReplayValue{
				TransitionMonotonicNS: uint64(90 * time.Second),
				Lifecycle:             lifecycleStale,
			})
			link := taskLink{
				Owner:               key.Owner,
				Generation:          key.Generation,
				ObservedMonotonicNS: state.ObservedMonotonicNS,
				ProcessIncarnation:  testProcessIncarnation,
			}
			if test.taskKey != (Identity{}) {
				cleanup.maps.tasks.(*fakeBridgeMap).values[test.taskKey] = link
			} else {
				cleanup.maps.handoffs.(*fakeBridgeMap).values[test.handoff] = link
			}

			for _, now := range []time.Duration{100 * time.Second, 102 * time.Second} {
				cleanup.monoTimeNow = func() time.Duration { return now }
				require.NoError(t, cleanup.snapshotAliasReplayState())
				cleanup.generationSnapshotComplete = true
				cleanup.stateSnapshotComplete = true
				cleanup.physicalGenerations = make(map[stateKey]struct{})
				require.NoError(t, cleanup.sweepAliasReplayTails(nil))
			}
			assert.NotContains(t, cleanup.maps.aliasReplays.(*fakeBridgeMap).values, replayKey)
		})
	}
}

func TestCleanupAliasReplayValueChangeRestartsGrace(t *testing.T) {
	cleanup, key, state := aliasReplayCleanupFixture(t)
	replayKey := aliasReplayKeyForState(key, state)
	initial := boundAliasReplayForTest(aliasReplayValue{
		TransitionMonotonicNS: uint64(90 * time.Second),
		References:            2,
		Lifecycle:             lifecycleStale,
	})
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	replays.values[replayKey] = initial
	now := 100 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	retired := map[retiredProcessKey]struct{}{
		{
			Process:            javaProcessIdentity(key.Owner),
			ProcessIncarnation: replayKey.ProcessIncarnation,
		}: {},
	}
	seedAliasReplayRetirements(cleanup, retired)
	prepareAliasReplayTailSweep(t, cleanup)
	require.NoError(t, cleanup.sweepAliasReplayTails(retired))

	changed := initial
	changed.References++
	replays.values[replayKey] = changed
	now += javaRemoteParentMinimumFenceAge
	prepareAliasReplayTailSweep(t, cleanup)
	require.NoError(t, cleanup.sweepAliasReplayTails(retired))
	assert.Contains(t, replays.values, replayKey)

	now += javaRemoteParentMinimumFenceAge
	prepareAliasReplayTailSweep(t, cleanup)
	require.NoError(t, cleanup.sweepAliasReplayTails(retired))
	assert.NotContains(t, replays.values, replayKey)
}

func TestCleanupAliasReplayStrictArtifactAndPublishingRules(t *testing.T) {
	cleanup, key, state := aliasReplayCleanupFixture(t)
	replayKey := aliasReplayKeyForState(key, state)
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	untaggedPublishing := boundAliasReplayForTest(aliasReplayValue{
		TransitionMonotonicNS: uint64(99 * time.Second),
		References:            1,
		Lifecycle:             lifecyclePublishing,
		DesiredLifecycle:      lifecycleStale,
	})
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

	// Retrieval expiry is not publisher serialization: a live positive
	// reference remains preservation authority even after TTL.
	now = time.Duration(replayKey.ObservedMonotonicNS) + cleanup.ttl + time.Nanosecond
	prepareAliasReplayTailSweep(t, cleanup)
	require.NoError(t, cleanup.sweepAliasReplayTails(nil))
	assert.Contains(t, replays.values, replayKey)
	now += javaRemoteParentMinimumFenceAge
	prepareAliasReplayTailSweep(t, cleanup)
	require.NoError(t, cleanup.sweepAliasReplayTails(nil))
	assert.Contains(t, replays.values, replayKey)

	retired := map[retiredProcessKey]struct{}{
		{
			Process:            javaProcessIdentity(key.Owner),
			ProcessIncarnation: replayKey.ProcessIncarnation,
		}: {},
	}
	seedAliasReplayRetirements(cleanup, retired)
	prepareAliasReplayTailSweep(t, cleanup)
	require.NoError(t, cleanup.sweepAliasReplayTails(retired))
	now += javaRemoteParentMinimumFenceAge
	prepareAliasReplayTailSweep(t, cleanup)
	require.NoError(t, cleanup.sweepAliasReplayTails(retired))
	assert.NotContains(t, replays.values, replayKey)
}

func TestCleanupMalformedAliasReplayStillRequiresGenerationArtifactAbsence(t *testing.T) {
	cleanup, key, state := aliasReplayCleanupFixture(t)
	replayKey := aliasReplayKeyForState(key, state)
	replayKey.Reserved = 1
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	replays.values[replayKey] = boundAliasReplayForTest(aliasReplayValue{
		TransitionMonotonicNS: uint64(90 * time.Second),
		Lifecycle:             lifecycleStale,
	})
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

func TestCleanupMalformedAliasReplayKeyDoesNotImmortalizePositiveReferences(t *testing.T) {
	cleanup, key, state := aliasReplayCleanupFixture(t)
	replayKey := aliasReplayKeyForState(key, state)
	replayKey.Reserved = 1
	replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
	replays.values[replayKey] = boundAliasReplayForTest(aliasReplayValue{
		TransitionMonotonicNS: uint64(90 * time.Second),
		References:            1,
		Lifecycle:             lifecycleStale,
	})
	now := 100 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }

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
				cleanup.maps.aliasReplays.(*fakeBridgeMap).values[replayKey] = activeAliasReplayForTest()
			}

			cleaned, err := cleanup.quarantineMalformedState(key, state)
			require.NoError(t, err)
			assert.False(t, cleaned)
			assert.Contains(t, cleanup.maps.states.(*fakeBridgeMap).values, key)
		})
	}
}

func TestCleanupTerminalAliasReplayFenceRetirementSafe(t *testing.T) {
	owner := Identity{TID: 3, PID: 2, Namespace: 1}
	key := stateKey{Owner: owner, Generation: 10}
	terminal := terminalValue{
		Generation:          key.Generation,
		ObservedMonotonicNS: uint64(10 * time.Second),
		ProcessIncarnation:  testProcessIncarnation,
		Lifecycle:           lifecycleConsumed,
	}
	replayKey := aliasReplayKeyForTerminal(key, terminal)
	final := boundAliasReplayForTest(aliasReplayValue{
		TransitionMonotonicNS: uint64(10 * time.Second),
		References:            1,
		Lifecycle:             terminal.Lifecycle,
	})
	newCleanup := func() (*Cleanup, *fakeBridgeMap) {
		cleanup := testCleanup(testMapHandler(nil, nil, nil))
		replays := cleanup.maps.aliasReplays.(*fakeBridgeMap)
		return cleanup, replays
	}

	t.Run("exact key absent ignores unrelated replay and iteration failure", func(t *testing.T) {
		cleanup, replays := newCleanup()
		unrelated := replayKey
		unrelated.ProcessIncarnation++
		replays.values[unrelated] = activeAliasReplayForTest()
		replays.iterateErr = errors.New("unexpected iteration")
		misses := 0
		replays.afterLookupResult = func(lookedUp any, err error) {
			if lookedUp == replayKey && errors.Is(err, ebpf.ErrKeyNotExist) {
				misses++
			}
		}

		safe, err := cleanup.terminalAliasReplayFenceRetirementSafe(key, terminal)
		require.NoError(t, err)
		assert.True(t, safe)
		assert.Equal(t, 2, misses)
		assert.Equal(t, activeAliasReplayForTest(), replays.values[unrelated])
	})

	t.Run("matching final", func(t *testing.T) {
		cleanup, replays := newCleanup()
		replays.values[replayKey] = final

		safe, err := cleanup.terminalAliasReplayFenceRetirementSafe(key, terminal)
		require.NoError(t, err)
		assert.True(t, safe)
		assert.Equal(t, 2, replays.lookupCount)
	})

	t.Run("conflicting final lifecycle", func(t *testing.T) {
		cleanup, replays := newCleanup()
		conflicting := final
		conflicting.Lifecycle = lifecycleStale
		replays.values[replayKey] = conflicting

		safe, err := cleanup.terminalAliasReplayFenceRetirementSafe(key, terminal)
		require.NoError(t, err)
		assert.False(t, safe)
	})

	t.Run("active replay appears after first miss", func(t *testing.T) {
		cleanup, replays := newCleanup()
		misses := 0
		replays.afterLookupResult = func(lookedUp any, err error) {
			if lookedUp != replayKey || !errors.Is(err, ebpf.ErrKeyNotExist) {
				return
			}
			misses++
			if misses == 1 {
				replays.mu.Lock()
				replays.values[replayKey] = activeAliasReplayForTest()
				replays.mu.Unlock()
			}
		}

		safe, err := cleanup.terminalAliasReplayFenceRetirementSafe(key, terminal)
		require.NoError(t, err)
		assert.False(t, safe)
	})

	t.Run("matching final replaced after first hit", func(t *testing.T) {
		cleanup, replays := newCleanup()
		replays.values[replayKey] = final
		hits := 0
		replays.afterLookupResult = func(lookedUp any, err error) {
			if lookedUp != replayKey || err != nil {
				return
			}
			hits++
			if hits == 1 {
				replays.mu.Lock()
				replays.values[replayKey] = activeAliasReplayForTest()
				replays.mu.Unlock()
			}
		}

		safe, err := cleanup.terminalAliasReplayFenceRetirementSafe(key, terminal)
		require.NoError(t, err)
		assert.False(t, safe)
	})

	t.Run("lookup error", func(t *testing.T) {
		cleanup, replays := newCleanup()
		replays.lookupErr = errors.New("injected lookup failure")

		safe, err := cleanup.terminalAliasReplayFenceRetirementSafe(key, terminal)
		assert.False(t, safe)
		require.ErrorContains(t, err, "checking terminal alias replay")
		require.ErrorContains(t, err, "injected lookup failure")
	})
}
