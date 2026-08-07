// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javabridge

import (
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
)

type aliasReplayCarrierKey struct {
	Owner               Identity
	Generation          uint64
	ObservedMonotonicNS uint64
}

type aliasReplayNoCarrierObservation struct {
	Value      aliasReplayValue
	ObservedAt time.Duration
}

func aliasReplayGenerationKey(key aliasReplayKey) stateKey {
	return stateKey{Owner: key.Owner, Generation: key.Generation}
}

func aliasReplayCarrier(key aliasReplayKey) aliasReplayCarrierKey {
	return aliasReplayCarrierKey{
		Owner:               key.Owner,
		Generation:          key.Generation,
		ObservedMonotonicNS: key.ObservedMonotonicNS,
	}
}

func aliasReplayCarrierForLink(link taskLink) aliasReplayCarrierKey {
	return aliasReplayCarrierKey{
		Owner:               link.Owner,
		Generation:          link.Generation,
		ObservedMonotonicNS: link.ObservedMonotonicNS,
	}
}

func validAliasReplayKey(key aliasReplayKey) bool {
	return key.Owner != (Identity{}) && key.Reserved == 0 && key.Generation != 0 &&
		key.ObservedMonotonicNS != 0 && key.ProcessIncarnation != 0
}

func validAliasReplayDesiredLifecycle(lifecycle uint8) bool {
	return lifecycle >= lifecycleConsumed && lifecycle <= lifecycleAmbiguous
}

func validAliasReplayActive(value aliasReplayValue) bool {
	return value.TransitionMonotonicNS != 0 && value.Lifecycle == lifecycleActive &&
		value.DesiredLifecycle == 0 && value.ProducerTag == 0 && value.Reserved == 0
}

func validAliasReplayPublishing(value aliasReplayValue) bool {
	return value.TransitionMonotonicNS != 0 && value.Lifecycle == lifecyclePublishing &&
		validAliasReplayDesiredLifecycle(value.DesiredLifecycle) &&
		(value.ProducerTag == 0 || value.ProducerTag == generationGoProducerTag) &&
		value.Reserved == 0
}

func validTaggedAliasReplayPublishing(value aliasReplayValue) bool {
	return validAliasReplayPublishing(value) && value.ProducerTag == generationGoProducerTag
}

func validUntaggedAliasReplayPublishing(value aliasReplayValue) bool {
	return validAliasReplayPublishing(value) && value.ProducerTag == 0
}

func validAliasReplayFinal(value aliasReplayValue) bool {
	return value.TransitionMonotonicNS != 0 &&
		validAliasReplayDesiredLifecycle(value.Lifecycle) && value.DesiredLifecycle == 0 &&
		value.ProducerTag == 0 && value.Reserved == 0
}

func (c *Cleanup) recordAliasReplayCleanupKey(
	key stateKey,
	observedMonotonicNS uint64,
	processIncarnation uint64,
) {
	replayKey := aliasReplayKey{
		Owner:               key.Owner,
		Generation:          key.Generation,
		ObservedMonotonicNS: observedMonotonicNS,
		ProcessIncarnation:  processIncarnation,
	}
	if !validAliasReplayKey(replayKey) {
		return
	}
	if c.aliasReplayCleanupKeys == nil {
		c.aliasReplayCleanupKeys = make(map[stateKey]aliasReplayKey)
	}
	c.aliasReplayCleanupKeys[key] = replayKey
}

func (c *Cleanup) snapshotAliasReplayState() error {
	c.aliasReplayEntries = make(map[aliasReplayKey]aliasReplayValue)
	c.aliasReplayCarriers = make(map[aliasReplayCarrierKey]struct{})
	c.aliasReplaySnapshotComplete = false
	c.aliasCarrierSnapshotComplete = false
	replays, replayErr := cleanupMapEntries[aliasReplayKey, aliasReplayValue](c.maps.aliasReplays)
	c.aliasReplaySnapshotComplete = replayErr == nil
	if replayErr == nil {
		for _, entry := range replays {
			c.aliasReplayEntries[entry.key] = entry.value
		}
		for key := range c.aliasReplayNoCarrier {
			if _, present := c.aliasReplayEntries[key]; !present {
				delete(c.aliasReplayNoCarrier, key)
			}
		}
	}

	tasks, taskErr := cleanupMapEntries[Identity, taskLink](c.maps.tasks)
	handoffs, handoffErr := cleanupMapEntries[handoffKey, taskLink](c.maps.handoffs)
	c.aliasCarrierSnapshotComplete = taskErr == nil && handoffErr == nil
	if taskErr == nil {
		for _, entry := range tasks {
			c.aliasReplayCarriers[aliasReplayCarrierForLink(entry.value)] = struct{}{}
		}
	}
	if handoffErr == nil {
		for _, entry := range handoffs {
			c.aliasReplayCarriers[aliasReplayCarrierForLink(entry.value)] = struct{}{}
		}
	}

	var result error
	if replayErr != nil {
		result = errors.Join(result, fmt.Errorf("iterating Java alias replays: %w", replayErr))
	}
	if taskErr != nil {
		result = errors.Join(result, fmt.Errorf("iterating Java task alias carriers: %w", taskErr))
	}
	if handoffErr != nil {
		result = errors.Join(result, fmt.Errorf("iterating Java handoff alias carriers: %w", handoffErr))
	}
	return result
}

func (c *Cleanup) ensureStateAliasReplayFinal(
	ownership generationCleanupOwnership,
	key stateKey,
	state stateValue,
) (bool, error) {
	replayKey := aliasReplayKeyForState(key, state)
	c.recordAliasReplayCleanupKey(
		key, state.ObservedMonotonicNS, state.ProcessIncarnation,
	)
	var replay aliasReplayValue
	if err := c.maps.aliasReplays.Lookup(&replayKey, &replay); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return state.Aliases == 0, nil
		}
		return false, fmt.Errorf("looking up exact alias replay: %w", err)
	}
	if state.Aliases > 0 && replay.References == 0 {
		return false, nil
	}
	ready, err := c.ensureExactAliasReplayFinal(ownership, replayKey, replay)
	return ready, err
}

func (c *Cleanup) ensureGenerationAliasReplaysFinal(
	ownership generationCleanupOwnership,
	key stateKey,
) (bool, error) {
	if !c.aliasReplaySnapshotComplete {
		return false, nil
	}

	// Re-enumerate while the exact full fence is held. The sweep snapshot is
	// required as independent completeness authority, but it may predate fence
	// acquisition and therefore cannot be the only source of replay keys.
	for range 2 {
		entries, unambiguous, err := c.aliasReplayCandidates(
			key, ownership.claim.ProcessIncarnation,
		)
		if err != nil || !unambiguous {
			return false, err
		}
		for _, entry := range entries {
			ready, err := c.ensureExactAliasReplayFinal(ownership, entry.key, entry.value)
			if err != nil || !ready {
				return false, err
			}
		}
	}

	// A final complete pass is read-only: a newly discovered non-final replay
	// must keep E/G rather than being adopted at the edge of fence retirement.
	entries, unambiguous, err := c.aliasReplayCandidates(
		key, ownership.claim.ProcessIncarnation,
	)
	if err != nil || !unambiguous {
		return false, err
	}
	for _, entry := range entries {
		if !validAliasReplayFinal(entry.value) ||
			entry.value.Lifecycle != ownership.claim.Reserved[0] {
			return false, nil
		}
	}
	return true, nil
}

func (c *Cleanup) currentGenerationAliasReplays(
	key stateKey,
) ([]cleanupEntry[aliasReplayKey, aliasReplayValue], error) {
	entries, err := cleanupMapEntries[aliasReplayKey, aliasReplayValue](c.maps.aliasReplays)
	if err != nil {
		return nil, fmt.Errorf("iterating exact-generation alias replays: %w", err)
	}
	matching := make([]cleanupEntry[aliasReplayKey, aliasReplayValue], 0)
	for _, entry := range entries {
		if aliasReplayGenerationKey(entry.key) == key {
			matching = append(matching, entry)
		}
	}
	return matching, nil
}

func (c *Cleanup) aliasReplayCandidates(
	key stateKey,
	processIncarnation uint64,
) ([]cleanupEntry[aliasReplayKey, aliasReplayValue], bool, error) {
	if exact, ok := c.aliasReplayCleanupKeys[key]; ok {
		if !validAliasReplayKey(exact) || aliasReplayGenerationKey(exact) != key ||
			exact.ProcessIncarnation != processIncarnation {
			return nil, false, nil
		}
		var current aliasReplayValue
		if err := c.maps.aliasReplays.Lookup(&exact, &current); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return nil, true, nil
			}
			return nil, false, fmt.Errorf("looking up exact generation alias replay: %w", err)
		}
		return []cleanupEntry[aliasReplayKey, aliasReplayValue]{{
			key: exact, value: current,
		}}, true, nil
	}

	entries, err := c.currentGenerationAliasReplays(key)
	if err != nil {
		return nil, false, err
	}
	candidates := make([]cleanupEntry[aliasReplayKey, aliasReplayValue], 0, 1)
	for _, entry := range entries {
		if validAliasReplayKey(entry.key) &&
			entry.key.ProcessIncarnation == processIncarnation {
			candidates = append(candidates, entry)
		}
	}
	if len(candidates) > 1 {
		// Without a state/index observation, choosing between two exact replay
		// generations would make a wider {owner,generation} key an ABA hazard.
		return nil, false, nil
	}
	return candidates, true, nil
}

// aliasReplayFenceRetirementSafe checks replay state without treating it as a
// logical generation artifact. A coherent final replay deliberately survives
// E/G retirement so task and handoff carriers can still resolve the outcome.
// Any non-final or semantically conflicting replay keeps the fence tuple.
func (c *Cleanup) aliasReplayFenceRetirementSafe(
	key stateKey,
	claim *generationClaim,
) (bool, error) {
	if !c.aliasReplaySnapshotComplete {
		return false, nil
	}
	if claim == nil {
		entries, err := c.currentGenerationAliasReplays(key)
		if err != nil {
			return false, err
		}
		for _, entry := range entries {
			if !validAliasReplayKey(entry.key) || !validAliasReplayFinal(entry.value) {
				return false, nil
			}
		}
		return true, nil
	}
	if !validGenerationCleanupClaim(*claim) {
		return false, nil
	}
	entries, unambiguous, err := c.aliasReplayCandidates(key, claim.ProcessIncarnation)
	if err != nil || !unambiguous {
		return false, err
	}
	if len(entries) == 0 {
		return true, nil
	}
	if !validAliasReplayDesiredLifecycle(claim.Reserved[0]) {
		return false, nil
	}
	for _, entry := range entries {
		if !validAliasReplayFinal(entry.value) || entry.value.Lifecycle != claim.Reserved[0] {
			return false, nil
		}
	}
	return true, nil
}

func (c *Cleanup) ensureExactAliasReplayFinal(
	ownership generationCleanupOwnership,
	key aliasReplayKey,
	replay aliasReplayValue,
) (bool, error) {
	desired := ownership.claim.Reserved[0]
	if !validAliasReplayKey(key) || aliasReplayGenerationKey(key) != ownership.fence.key ||
		key.ProcessIncarnation != ownership.claim.ProcessIncarnation ||
		!validAliasReplayDesiredLifecycle(desired) {
		return false, nil
	}
	fenced, err := c.generationCleanupFenceMatches(ownership)
	if err != nil || !fenced {
		return false, err
	}

	if validAliasReplayFinal(replay) {
		return replay.Lifecycle == desired, nil
	}
	if validAliasReplayPublishing(replay) && !validTaggedAliasReplayPublishing(replay) {
		// An untagged producer may still resume. Cleanup never adopts it.
		return false, nil
	}
	if validTaggedAliasReplayPublishing(replay) {
		// Producer-to-cleanup handoff advances E's timestamp to transfer ABA
		// authority, while the already-published replay keeps the producer's
		// original timestamp. A stale retarget publishes E's new desired
		// semantic before updating the replay, so a producer death can also
		// leave the exact Go-tagged replay carrying the old semantic. Under the
		// full exact cleanup fence E is authoritative: reconcile only this
		// structurally valid, Go-owned publishing state before finalizing it.
		if replay.DesiredLifecycle != desired {
			replay.DesiredLifecycle = desired
			updated, err := c.updateAliasReplayFenced(
				ownership, key, replay, "alias replay publishing semantic reconciliation",
			)
			if err != nil || !updated {
				return false, err
			}
		}
		return c.finishTaggedAliasReplayPublishing(ownership, key, replay)
	}
	if !validAliasReplayActive(replay) {
		return false, nil
	}

	publishing := replay
	publishing.TransitionMonotonicNS = ownership.claim.ObservedMonotonicNS
	publishing.Lifecycle = lifecyclePublishing
	publishing.DesiredLifecycle = desired
	publishing.ProducerTag = generationGoProducerTag
	updated, err := c.updateAliasReplayFenced(
		ownership, key, publishing, "alias replay publishing transition",
	)
	if err != nil || !updated {
		return false, err
	}
	return c.finishTaggedAliasReplayPublishing(ownership, key, publishing)
}

func (c *Cleanup) finishTaggedAliasReplayPublishing(
	ownership generationCleanupOwnership,
	key aliasReplayKey,
	publishing aliasReplayValue,
) (bool, error) {
	if !validTaggedAliasReplayPublishing(publishing) ||
		publishing.DesiredLifecycle != ownership.claim.Reserved[0] {
		return false, nil
	}
	final := publishing
	final.Lifecycle = publishing.DesiredLifecycle
	final.DesiredLifecycle = 0
	final.ProducerTag = 0
	return c.updateAliasReplayFenced(
		ownership, key, final, "alias replay final transition",
	)
}

func (c *Cleanup) updateAliasReplayFenced(
	ownership generationCleanupOwnership,
	key aliasReplayKey,
	value aliasReplayValue,
	description string,
) (bool, error) {
	return c.mutateGenerationCleanupFenced(ownership, description, func() (bool, error) {
		updateErr := c.maps.aliasReplays.Update(&key, &value, ebpf.UpdateExist)
		var current aliasReplayValue
		lookupErr := c.maps.aliasReplays.Lookup(&key, &current)
		if lookupErr != nil {
			if updateErr != nil {
				return false, errors.Join(updateErr, lookupErr)
			}
			return false, lookupErr
		}
		if current != value {
			if updateErr != nil {
				return false, updateErr
			}
			return false, nil
		}
		// Exact readback is authoritative even if Update reported an unknown
		// outcome after the kernel had already committed the requested bytes.
		return true, nil
	})
}

func (c *Cleanup) aliasReplayGenerationArtifactsAbsent(
	key aliasReplayKey,
) (bool, error) {
	if !c.generationSnapshotComplete || !c.stateSnapshotComplete ||
		c.physicalGenerations == nil {
		return false, nil
	}
	generation := aliasReplayGenerationKey(key)
	absent, err := c.generationCleanupArtifactsAbsent(generation)
	if err != nil || !absent {
		return absent, err
	}
	var claim generationClaim
	if err := c.maps.claims.Lookup(&generation, &claim); err == nil {
		return false, nil
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking alias replay claim tail: %w", err)
	}
	var marker uint64
	if err := c.maps.ambiguity.Lookup(&generation, &marker); err == nil {
		return false, nil
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking alias replay marker tail: %w", err)
	}
	var guard generationClaim
	if err := c.maps.ownerGuards.Lookup(&generation.Owner, &guard); err == nil {
		return false, nil
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking alias replay guard tail: %w", err)
	}
	return true, nil
}

func (c *Cleanup) sweepAliasReplayTails(
	retired map[retiredProcessKey]struct{},
) error {
	if !c.aliasReplaySnapshotComplete || !c.aliasCarrierSnapshotComplete {
		return nil
	}
	// Refresh all three maps after generation cleanup. This keeps a carrier or
	// replay inserted during the sweep from being judged against an older
	// beginning-of-sweep snapshot. A failed refresh is preservation authority.
	if err := c.snapshotAliasReplayState(); err != nil {
		return err
	}
	if c.aliasReplayNoCarrier == nil {
		c.aliasReplayNoCarrier = make(map[aliasReplayKey]aliasReplayNoCarrierObservation)
	}
	now := c.monoTimeNow()
	if now <= 0 {
		return errors.New("reading monotonic time for alias replay cleanup")
	}

	var result error
	for key, snapshotted := range c.aliasReplayEntries {
		if _, carried := c.aliasReplayCarriers[aliasReplayCarrier(key)]; carried {
			delete(c.aliasReplayNoCarrier, key)
			continue
		}

		var current aliasReplayValue
		if err := c.maps.aliasReplays.Lookup(&key, &current); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				delete(c.aliasReplayNoCarrier, key)
				continue
			}
			result = errors.Join(result, fmt.Errorf("revalidating alias replay tail: %w", err))
			continue
		}
		if current != snapshotted {
			c.aliasReplayNoCarrier[key] = aliasReplayNoCarrierObservation{
				Value: current, ObservedAt: now,
			}
			continue
		}

		keyValid := validAliasReplayKey(key)
		valueFinal := validAliasReplayFinal(current)
		valueActiveZero := validAliasReplayActive(current) && current.References == 0
		valuePublishing := validAliasReplayPublishing(current)
		valueMalformed := !validAliasReplayActive(current) && !valueFinal && !valuePublishing
		processRetired := false
		if keyValid {
			var retirementErr error
			processRetired, retirementErr = c.processRetired(
				retired, javaProcessIdentity(key.Owner), key.ProcessIncarnation,
			)
			if retirementErr != nil {
				result = errors.Join(result, retirementErr)
				continue
			}
		}
		expired := keyValid && cleanupExpired(now, key.ObservedMonotonicNS, c.ttl)
		eligible := valueFinal || valueActiveZero || valueMalformed || !keyValid ||
			processRetired || expired
		if valuePublishing && !processRetired && !expired {
			// Tagged publishing requires its exact cleanup fence to finish. Untagged
			// publishing may be a preempted BPF producer. Neither is standalone
			// reclamation authority.
			eligible = false
		}
		if !eligible {
			delete(c.aliasReplayNoCarrier, key)
			continue
		}

		artifactsAbsent, artifactErr := c.aliasReplayGenerationArtifactsAbsent(key)
		if artifactErr != nil {
			result = errors.Join(result, artifactErr)
			continue
		}
		if !artifactsAbsent {
			delete(c.aliasReplayNoCarrier, key)
			continue
		}

		observed, seen := c.aliasReplayNoCarrier[key]
		if !seen || observed.Value != current || observed.ObservedAt <= 0 ||
			now < observed.ObservedAt {
			c.aliasReplayNoCarrier[key] = aliasReplayNoCarrierObservation{
				Value: current, ObservedAt: now,
			}
			continue
		}
		if now-observed.ObservedAt < javaRemoteParentMinimumFenceAge {
			continue
		}

		deleted, deleteErr := cleanupDeleteExact(c.maps.aliasReplays, key, current)
		if deleteErr != nil {
			result = errors.Join(result, fmt.Errorf("deleting carrier-free alias replay: %w", deleteErr))
			continue
		}
		if deleted {
			delete(c.aliasReplayNoCarrier, key)
			continue
		}
		// A replacement or concurrent mutation starts a fresh proof window.
		delete(c.aliasReplayNoCarrier, key)
	}
	return result
}
