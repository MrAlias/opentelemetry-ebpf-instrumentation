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

type aliasReplayCleanupProof struct {
	replayKey  aliasReplayKey
	state      stateValue
	binding    aliasReplayBinding
	generation aliasReplayGenerationProof
	finalized  bool
	finalValue aliasReplayValue // References is canonicalized to zero.
}

func aliasReplayGenerationKey(key aliasReplayKey) stateKey {
	return stateKey{Owner: key.Owner, Generation: key.Generation}
}

func (c *Cleanup) aliasReplayGenerationMaps() aliasReplayGenerationMaps {
	return aliasReplayGenerationMaps{
		remoteParents:     c.maps.remoteParents,
		incarnations:      c.maps.incarnations,
		connections:       c.maps.connections,
		cookieConnections: c.maps.cookieConnections,
		ambiguity:         c.maps.ambiguity,
		owners:            c.maps.owners,
		states:            c.maps.states,
		generations:       c.maps.generations,
		terminals:         c.maps.terminals,
		claims:            c.maps.claims,
		aliasReplays:      c.maps.aliasReplays,
		ownerGuards:       c.maps.ownerGuards,
	}
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
	return validAliasReplayBinding(value) && value.TransitionMonotonicNS != 0 &&
		value.Lifecycle == lifecycleActive &&
		value.DesiredLifecycle == 0 && value.ProducerTag == 0 && value.Reserved == 0
}

func validAliasReplayPublishing(value aliasReplayValue) bool {
	return validAliasReplayBinding(value) && value.TransitionMonotonicNS != 0 &&
		value.Lifecycle == lifecyclePublishing &&
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
	return validAliasReplayBinding(value) && value.TransitionMonotonicNS != 0 &&
		validAliasReplayDesiredLifecycle(value.Lifecycle) && value.DesiredLifecycle == 0 &&
		value.ProducerTag == 0 && value.Reserved == 0
}

func (c *Cleanup) recordAliasReplayCleanupKey(
	key stateKey,
	observedMonotonicNS uint64,
	processIncarnation uint64,
) bool {
	replayKey := aliasReplayKey{
		Owner:               key.Owner,
		Generation:          key.Generation,
		ObservedMonotonicNS: observedMonotonicNS,
		ProcessIncarnation:  processIncarnation,
	}
	if !validAliasReplayKey(replayKey) {
		// Malformed roots without a usable replay identity still need to reach
		// the ordinary aliases==0 cleanup path. Only an exact-key replacement is
		// a conflict that must stop a sweep.
		return true
	}
	if c.aliasReplayCleanupKeys == nil {
		c.aliasReplayCleanupKeys = make(map[stateKey]aliasReplayKey)
	}
	if current, present := c.aliasReplayCleanupKeys[key]; present {
		return current == replayKey
	}
	if proof, present := c.aliasReplayCleanupProofs[key]; present &&
		proof.replayKey != replayKey {
		return false
	}
	c.aliasReplayCleanupKeys[key] = replayKey
	return true
}

func (c *Cleanup) recordAliasReplayCleanupProof(
	key stateKey,
	replayKey aliasReplayKey,
	value aliasReplayValue,
	state stateValue,
	generation aliasReplayGenerationProof,
) bool {
	if c.aliasReplayCleanupProofs == nil {
		c.aliasReplayCleanupProofs = make(map[stateKey]*aliasReplayCleanupProof)
	}
	if current, present := c.aliasReplayCleanupProofs[key]; present {
		// A sweep may encounter the same generation through more than one root.
		// Once its full graph has been proved under E/G, a retry must not adopt a
		// replacement successor after any replay or payload mutation has begun.
		return current.replayKey == replayKey && current.state == state &&
			current.binding == aliasReplayBindingOf(value) &&
			current.generation == generation
	}
	c.aliasReplayCleanupProofs[key] = &aliasReplayCleanupProof{
		replayKey: replayKey, state: state, binding: aliasReplayBindingOf(value),
		generation: generation,
	}
	return true
}

func (c *Cleanup) aliasReplayCleanupProofMatches(
	ownership generationCleanupOwnership,
) (bool, error) {
	key := ownership.fence.key
	proof, present := c.aliasReplayCleanupProofs[key]
	if !present {
		return true, nil
	}
	replayKey := proof.replayKey
	var current aliasReplayValue
	if err := c.maps.aliasReplays.Lookup(&replayKey, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, err
	}
	if !validAliasReplayBinding(current) || aliasReplayBindingOf(current) != proof.binding {
		return false, nil
	}
	if proof.finalized &&
		(!validAliasReplayFinal(current) ||
			!aliasReplayProofValueEqual(current, proof.finalValue)) {
		return false, nil
	}
	return aliasReplayGenerationContinuityMatches(
		c.aliasReplayGenerationMaps(), aliasReplayGenerationAuthority{
			claimPresent: true,
			claim:        ownership.claim,
			guardPresent: true,
			guard:        ownership.fence.guardClaim,
			ambiguity:    ownership.fence.markedAt,
		}, key, proof.state, current, &proof.generation,
	)
}

func (c *Cleanup) markAliasReplayCleanupProofFinal(
	key stateKey,
	lifecycle uint8,
) bool {
	proof, present := c.aliasReplayCleanupProofs[key]
	if !present || !validAliasReplayTarget(lifecycle) {
		return false
	}
	replayKey := proof.replayKey
	var current aliasReplayValue
	if c.maps.aliasReplays.Lookup(&replayKey, &current) != nil ||
		!validAliasReplayFinal(current) || current.Lifecycle != lifecycle ||
		aliasReplayBindingOf(current) != proof.binding {
		return false
	}
	canonical := aliasReplayProofValue(current)
	if proof.finalized {
		return aliasReplayProofValueEqual(canonical, proof.finalValue)
	}
	proof.finalized = true
	proof.finalValue = canonical
	return true
}

func (c *Cleanup) aliasReplayCleanupFinalProofMatches(
	key stateKey,
) (bool, error) {
	proof, present := c.aliasReplayCleanupProofs[key]
	if !present {
		return true, nil
	}
	if !proof.finalized {
		return false, nil
	}
	replayKey := proof.replayKey
	var current aliasReplayValue
	if err := c.maps.aliasReplays.Lookup(&replayKey, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, err
	}
	return validAliasReplayFinal(current) &&
		aliasReplayProofValueEqual(current, proof.finalValue), nil
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

func aliasReplayKeyForTerminal(key stateKey, terminal terminalValue) aliasReplayKey {
	return aliasReplayKey{
		Owner:               key.Owner,
		Generation:          key.Generation,
		ObservedMonotonicNS: terminal.ObservedMonotonicNS,
		ProcessIncarnation:  terminal.ProcessIncarnation,
	}
}

// terminalAliasReplayFenceRetirementSafe checks only the replay epoch selected
// by exact terminal authority. Other replay keys for the same numeric generation
// carry a different observation or process incarnation and cannot authorize this
// terminal's payload or lifecycle. Shared HASH iteration is deliberately not
// used as absence authority: concurrent updates can make a successful iteration
// omit keys without reporting an error.
func (c *Cleanup) terminalAliasReplayFenceRetirementSafe(
	key stateKey,
	terminal terminalValue,
) (bool, error) {
	if key.Generation == 0 || key.Reserved != 0 || !validTerminalValue(terminal) ||
		terminal.Generation != key.Generation {
		return false, nil
	}
	replayKey := aliasReplayKeyForTerminal(key, terminal)
	if !validAliasReplayKey(replayKey) {
		return false, nil
	}
	for range 2 {
		var replay aliasReplayValue
		if err := c.maps.aliasReplays.Lookup(&replayKey, &replay); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return false, fmt.Errorf("checking terminal alias replay: %w", err)
		}
		// References are deliberately mutable and are not part of lifecycle
		// authority. Binding and transition metadata must be structurally final
		// for the terminal's exact lifecycle on every point read.
		if !validAliasReplayFinal(replay) || replay.Lifecycle != terminal.Lifecycle {
			return false, nil
		}
	}
	return true, nil
}

// ensureTerminalAliasReplayFinal prepares only T's exact replay epoch while the
// complete M/E/G fence still matches. The later retirement validator is
// deliberately read-only and never falls back to shared-map enumeration.
func (c *Cleanup) ensureTerminalAliasReplayFinal(
	ownership generationCleanupOwnership,
	key stateKey,
	terminal terminalValue,
) (bool, error) {
	if !validTerminalValue(terminal) || terminal.Generation != key.Generation ||
		ownership.claim.ProcessIncarnation != terminal.ProcessIncarnation ||
		ownership.claim.Reserved[0] != terminal.Lifecycle {
		return false, nil
	}
	replayKey := aliasReplayKeyForTerminal(key, terminal)
	if !validAliasReplayKey(replayKey) {
		return false, nil
	}
	terminalMatches, err := cleanupExactMatches(c.maps.terminals, key.Owner, terminal)
	if err != nil || !terminalMatches {
		return false, err
	}
	var replay aliasReplayValue
	if err := c.maps.aliasReplays.Lookup(&replayKey, &replay); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return cleanupExactMatches(c.maps.terminals, key.Owner, terminal)
		}
		return false, fmt.Errorf("looking up terminal alias replay: %w", err)
	}
	ready, err := c.ensureExactAliasReplayFinal(ownership, replayKey, replay)
	if err != nil || !ready {
		return false, err
	}
	terminalMatches, err = cleanupExactMatches(c.maps.terminals, key.Owner, terminal)
	if err != nil || !terminalMatches {
		return false, err
	}
	return c.terminalAliasReplayFenceRetirementSafe(key, terminal)
}

func (c *Cleanup) ensureStateAliasReplayFinal(
	ownership generationCleanupOwnership,
	key stateKey,
	state stateValue,
) (bool, error) {
	replayKey := aliasReplayKeyForState(key, state)
	if !c.recordAliasReplayCleanupKey(
		key, state.ObservedMonotonicNS, state.ProcessIncarnation,
	) {
		return false, nil
	}
	var replay aliasReplayValue
	if err := c.maps.aliasReplays.Lookup(&replayKey, &replay); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return state.Aliases == 0, nil
		}
		return false, fmt.Errorf("looking up exact alias replay: %w", err)
	}
	generationProof, bindingMatches, err := aliasReplayBindingMatchesGeneration(
		c.aliasReplayGenerationMaps(), aliasReplayGenerationAuthority{
			claimPresent: true,
			claim:        ownership.claim,
			guardPresent: true,
			guard:        ownership.fence.guardClaim,
			ambiguity:    ownership.fence.markedAt,
		}, key, state, replay,
	)
	if err != nil {
		return false, fmt.Errorf("validating exact alias replay binding: %w", err)
	}
	if !bindingMatches {
		return false, nil
	}
	if !c.recordAliasReplayCleanupProof(key, replayKey, replay, state, generationProof) {
		return false, nil
	}
	if state.Aliases > 0 && replay.References == 0 {
		return false, nil
	}
	ready, err := c.ensureExactAliasReplayFinal(ownership, replayKey, replay)
	if err != nil || !ready {
		return false, err
	}
	if !c.markAliasReplayCleanupProofFinal(key, ownership.claim.Reserved[0]) {
		return false, nil
	}
	return c.generationCleanupFenceMatches(ownership)
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
	// Rootless tails have no exact replay epoch to point-read. Bound their
	// generation-wide HASH enumeration under cleanup's exclusive coordinator.
	if !c.generationReplayScanAuthorized(key) {
		return nil, false, nil
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
	proofMatches, err := c.aliasReplayCleanupFinalProofMatches(key)
	if err != nil || !proofMatches {
		return false, err
	}
	if claim == nil {
		// G-only tails likewise lack an exact replay epoch. Deferral preserves G
		// as fail-closed authority until this generation receives admission.
		if !c.generationReplayScanAuthorized(key) {
			return false, nil
		}
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
