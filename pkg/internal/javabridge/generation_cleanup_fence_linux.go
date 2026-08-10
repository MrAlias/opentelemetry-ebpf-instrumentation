// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javabridge // import "go.opentelemetry.io/obi/pkg/internal/javabridge"

import (
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"
)

type generationTeardownFence struct {
	key        stateKey
	claim      generationClaim
	guardKey   Identity
	guardClaim generationClaim
	markedAt   uint64
	guardOwned bool
}

const generationGoProducerTag = uint8(0x47)

func validGenerationProducerClaim(claim generationClaim) bool {
	if claim.ObservedMonotonicNS == 0 || claim.ProcessIncarnation == 0 ||
		claim.Reserved[1] != 0 || claim.Reserved[2] != 0 ||
		claim.Reserved[3] != 0 || claim.Reserved[4] != 0 ||
		claim.Reserved[5] != 0 || claim.Reserved[6] != generationGoProducerTag {
		return false
	}
	if claim.Lifecycle == lifecyclePublishing {
		return validAliasReplayTarget(claim.Reserved[0])
	}
	return validAliasReplayTarget(claim.Lifecycle) && claim.Reserved[0] == 0
}

func validGenerationProducerGuard(key stateKey, guard generationClaim) bool {
	return key.Owner != (Identity{}) && key.Generation != 0 && key.Reserved == 0 &&
		guard.ObservedMonotonicNS != 0 && guard.ProcessIncarnation != 0 &&
		guard.Reserved == ([7]byte{6: generationGoProducerTag}) &&
		guard.ProcessIncarnation == key.Generation &&
		guard.Lifecycle == lifecyclePublishing
}

func generationProducerHandoffValue(
	claim generationClaim,
	now time.Duration,
) (generationClaim, error) {
	producerClaim := validGenerationProducerClaim(claim)
	producerGuard := claim.ObservedMonotonicNS != 0 && claim.ProcessIncarnation != 0 &&
		claim.Lifecycle == lifecyclePublishing &&
		claim.Reserved == ([7]byte{6: generationGoProducerTag})
	if (!producerClaim && !producerGuard) || claim.ObservedMonotonicNS == ^uint64(0) {
		return generationClaim{}, errors.New("invalid Java generation producer handoff")
	}
	if now < 0 {
		return generationClaim{}, errors.New("invalid Java generation producer handoff time")
	}
	observed := uint64(0)
	if now > 0 {
		observed = uint64(now)
	}
	if observed <= claim.ObservedMonotonicNS {
		observed = claim.ObservedMonotonicNS + 1
	}
	cleanup := claim
	cleanup.ObservedMonotonicNS = observed
	cleanup.Lifecycle = lifecycleCleanup
	cleanup.Reserved = [7]byte{}
	if claim.Lifecycle == lifecyclePublishing && producerClaim {
		cleanup.Reserved[0] = claim.Reserved[0]
	} else {
		cleanup.Reserved[0] = claim.Lifecycle
	}
	return cleanup, nil
}

// recoverGoGenerationProducerHandoffs converts interrupted userspace handoffs
// into the cleanup protocol while every Go handler for this map set is
// quiesced by GenerationCoordinator. The durable tag is deliberately not a
// BPF ownership token: untagged lifecycle 2-6 entries are always preserved.
//
// Recovery publishes or adopts G before converting E, then converts a tagged
// G only after E is cleanup-visible. Every attempted successor is recorded as
// current-sweep state so an update that succeeds despite returning an error
// cannot authorize payload mutation or a same-sweep retry.
func (c *Cleanup) recoverGoGenerationProducerHandoffs() error {
	claims, claimErr := cleanupMapEntries[stateKey, generationClaim](c.maps.claims)
	guards, guardErr := cleanupMapEntries[Identity, generationClaim](c.maps.ownerGuards)
	if claimErr != nil || guardErr != nil {
		return errors.Join(
			wrapGenerationProducerRecoveryError("iterating tagged generation claims", claimErr),
			wrapGenerationProducerRecoveryError("iterating tagged generation guards", guardErr),
		)
	}

	var result error
	for _, entry := range claims {
		if entry.key.Owner == (Identity{}) || entry.key.Generation == 0 ||
			entry.key.Reserved != 0 || !validGenerationProducerClaim(entry.value) {
			continue
		}
		c.recordKnownGeneration(entry.key)
		if err := c.recoverGoGenerationProducerClaim(entry.key, entry.value); err != nil {
			result = errors.Join(result, fmt.Errorf(
				"recovering tagged Java generation claim: %w", err,
			))
		}
	}

	for _, entry := range guards {
		key := stateKey{Owner: entry.key, Generation: entry.value.ProcessIncarnation}
		if !validGenerationProducerGuard(key, entry.value) {
			continue
		}
		c.recordKnownGeneration(key)
		if err := c.recoverGoGenerationProducerGuardTail(key, entry.value); err != nil {
			result = errors.Join(result, fmt.Errorf(
				"recovering tagged Java generation guard: %w", err,
			))
		}
	}
	return result
}

func wrapGenerationProducerRecoveryError(description string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", description, err)
}

func (c *Cleanup) recoverGoGenerationProducerClaim(
	key stateKey,
	producer generationClaim,
) error {
	matches, err := generationClaimMatches(c.maps.claims, key, producer)
	if err != nil {
		return fmt.Errorf("revalidating producer claim: %w", err)
	}
	if !matches {
		return nil
	}
	cleanupClaim, err := generationProducerHandoffValue(producer, c.monoTimeNow())
	if err != nil {
		return err
	}

	guard, taggedGuard, guarded, err := c.recoveryGuardForGoProducer(key, producer)
	if err != nil {
		return err
	}
	if !guarded {
		return nil
	}
	if taggedGuard {
		// Validate the second successor before making E cleanup-visible. A
		// saturated tagged G cannot be handed off and must keep the whole pair
		// producer-tagged for a later binary or explicit operator recovery.
		if _, err := generationProducerHandoffValue(guard, c.monoTimeNow()); err != nil {
			return err
		}
	}

	matches, err = generationClaimMatches(c.maps.claims, key, producer)
	if err != nil {
		return fmt.Errorf("revalidating producer claim after guard publication: %w", err)
	}
	if !matches {
		return nil
	}
	guardMatches, err := generationGuardMatches(c.maps.ownerGuards, key.Owner, guard)
	if err != nil {
		return fmt.Errorf("revalidating producer recovery guard: %w", err)
	}
	if !guardMatches {
		return nil
	}

	// Record before the syscall: UpdateExist is not a CAS, and a kernel error
	// does not prove that the map remained unchanged.
	c.recordCurrentSweepClaim(key, cleanupClaim)
	if err := c.maps.claims.Update(&key, &cleanupClaim, ebpf.UpdateExist); err != nil {
		return errors.Join(
			fmt.Errorf("converting producer claim: %w", err),
			c.recordLiveGenerationCleanupClaim(key),
		)
	}
	matches, err = c.recordAndMatchLiveGenerationCleanupClaim(key, cleanupClaim)
	if err != nil {
		return fmt.Errorf("revalidating converted producer claim: %w", err)
	}
	if !matches {
		return nil
	}

	if !taggedGuard {
		_, err = generationGuardMatches(c.maps.ownerGuards, key.Owner, guard)
		if err != nil {
			return fmt.Errorf("revalidating adopted cleanup guard: %w", err)
		}
		return nil
	}

	guardMatches, err = generationGuardMatches(c.maps.ownerGuards, key.Owner, guard)
	if err != nil {
		return fmt.Errorf("revalidating tagged producer guard: %w", err)
	}
	if !guardMatches {
		return nil
	}
	matches, err = generationClaimMatches(c.maps.claims, key, cleanupClaim)
	if err != nil {
		return fmt.Errorf("revalidating converted claim before guard conversion: %w", err)
	}
	if !matches {
		return nil
	}
	return c.convertGoGenerationProducerGuard(key, guard, &cleanupClaim)
}

func (c *Cleanup) recoveryGuardForGoProducer(
	key stateKey,
	producer generationClaim,
) (generationClaim, bool, bool, error) {
	var guard generationClaim
	if err := c.maps.ownerGuards.Lookup(&key.Owner, &guard); err == nil {
		switch {
		case validGenerationProducerGuard(key, guard):
			return guard, true, true, nil
		case validGenerationCleanupGuard(key.Owner, guard) &&
			guard.ProcessIncarnation == key.Generation:
			return guard, false, true, nil
		default:
			return generationClaim{}, false, false, nil
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return generationClaim{}, false, false,
			fmt.Errorf("checking producer recovery guard: %w", err)
	}

	matches, err := generationClaimMatches(c.maps.claims, key, producer)
	if err != nil {
		return generationClaim{}, false, false,
			fmt.Errorf("revalidating producer claim before guard publication: %w", err)
	}
	if !matches {
		return generationClaim{}, false, false, nil
	}
	// acquireOrAdoptGenerationCleanupGuard repeats the guard lookup and uses
	// BPF_NOEXIST. The caller revalidates its exact tagged E immediately after
	// publication, so a collision or replacement remains fail-closed.
	guard, _, guarded, err := c.acquireOrAdoptGenerationCleanupGuard(key)
	if err != nil {
		return generationClaim{}, false, false,
			fmt.Errorf("publishing producer recovery guard: %w", err)
	}
	return guard, false, guarded, nil
}

func (c *Cleanup) recoverGoGenerationProducerGuardTail(
	key stateKey,
	producer generationClaim,
) error {
	guardMatches, err := generationGuardMatches(c.maps.ownerGuards, key.Owner, producer)
	if err != nil {
		return fmt.Errorf("revalidating producer guard tail: %w", err)
	}
	if !guardMatches {
		return nil
	}

	var expectedClaim *generationClaim
	var claim generationClaim
	if err := c.maps.claims.Lookup(&key, &claim); err == nil {
		if !validGenerationCleanupClaim(claim) ||
			c.claimCreatedThisSweep(key, claim) {
			return nil
		}
		expectedClaim = &claim
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("checking producer guard tail claim: %w", err)
	}

	return c.convertGoGenerationProducerGuard(key, producer, expectedClaim)
}

func (c *Cleanup) convertGoGenerationProducerGuard(
	key stateKey,
	producer generationClaim,
	expectedClaim *generationClaim,
) error {
	if !validGenerationProducerGuard(key, producer) {
		return errors.New("invalid tagged Java generation producer guard")
	}
	guardMatches, err := generationGuardMatches(c.maps.ownerGuards, key.Owner, producer)
	if err != nil {
		return fmt.Errorf("revalidating producer guard before conversion: %w", err)
	}
	if !guardMatches {
		return nil
	}
	claimMatches, err := c.generationProducerGuardClaimMatches(key, expectedClaim)
	if err != nil {
		return fmt.Errorf("revalidating claim before producer guard conversion: %w", err)
	}
	if !claimMatches {
		return nil
	}

	cleanupGuard, err := generationProducerHandoffValue(producer, c.monoTimeNow())
	if err != nil {
		return err
	}
	if !validGenerationCleanupGuard(key.Owner, cleanupGuard) ||
		cleanupGuard.ProcessIncarnation != key.Generation {
		return errors.New("invalid Java generation cleanup guard successor")
	}
	claimMatches, err = c.generationProducerGuardClaimMatches(key, expectedClaim)
	if err != nil {
		return fmt.Errorf("revalidating claim at producer guard conversion: %w", err)
	}
	if !claimMatches {
		return nil
	}
	guardMatches, err = generationGuardMatches(c.maps.ownerGuards, key.Owner, producer)
	if err != nil {
		return fmt.Errorf("revalidating producer guard at conversion: %w", err)
	}
	if !guardMatches {
		return nil
	}
	c.recordCurrentSweepGuard(key.Owner, cleanupGuard)
	if err := c.maps.ownerGuards.Update(&key.Owner, &cleanupGuard, ebpf.UpdateExist); err != nil {
		return errors.Join(
			fmt.Errorf("converting producer guard: %w", err),
			c.recordLiveGenerationCleanupGuard(key),
		)
	}
	guardMatches, err = c.recordAndMatchLiveGenerationCleanupGuard(key, cleanupGuard)
	if err != nil {
		return fmt.Errorf("revalidating converted producer guard: %w", err)
	}
	if !guardMatches {
		return nil
	}
	claimMatches, err = c.generationProducerGuardClaimMatches(key, expectedClaim)
	if err != nil {
		return fmt.Errorf("revalidating claim after producer guard conversion: %w", err)
	}
	if !claimMatches {
		return errors.New("producer guard claim changed after conversion")
	}
	return nil
}

func (c *Cleanup) generationProducerGuardClaimMatches(
	key stateKey,
	expected *generationClaim,
) (bool, error) {
	if expected == nil {
		return generationClaimAbsent(c.maps.claims, key)
	}
	return generationClaimMatches(c.maps.claims, key, *expected)
}

func (c *Cleanup) recordLiveGenerationCleanupClaim(key stateKey) error {
	_, err := c.recordAndMatchLiveGenerationCleanupClaim(key, generationClaim{})
	return err
}

func (c *Cleanup) recordAndMatchLiveGenerationCleanupClaim(
	key stateKey,
	expected generationClaim,
) (bool, error) {
	var current generationClaim
	if err := c.maps.claims.Lookup(&key, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("looking up live generation cleanup claim: %w", err)
	}
	if validGenerationCleanupClaim(current) {
		c.recordCurrentSweepClaim(key, current)
	}
	return current == expected, nil
}

func (c *Cleanup) recordLiveGenerationCleanupGuard(key stateKey) error {
	_, err := c.recordAndMatchLiveGenerationCleanupGuard(key, generationClaim{})
	return err
}

func (c *Cleanup) recordAndMatchLiveGenerationCleanupGuard(
	key stateKey,
	expected generationClaim,
) (bool, error) {
	var current generationClaim
	if err := c.maps.ownerGuards.Lookup(&key.Owner, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("looking up live generation cleanup guard: %w", err)
	}
	if validGenerationCleanupGuard(key.Owner, current) &&
		current.ProcessIncarnation == key.Generation {
		c.recordCurrentSweepGuard(key.Owner, current)
	}
	return current == expected, nil
}

func validGenerationCleanupClaim(claim generationClaim) bool {
	return claim.ObservedMonotonicNS != 0 && claim.ProcessIncarnation != 0 &&
		claim.Lifecycle == lifecycleCleanup &&
		claim.Reserved[0] >= lifecycleConsumed && claim.Reserved[0] <= lifecyclePublishing &&
		claim.Reserved[1] == 0 && claim.Reserved[2] == 0 && claim.Reserved[3] == 0 &&
		claim.Reserved[4] == 0 && claim.Reserved[5] == 0 && claim.Reserved[6] == 0
}

func generationClaimMatches(
	claims bridgeMap,
	key stateKey,
	expected generationClaim,
) (bool, error) {
	var current generationClaim
	if err := claims.Lookup(&key, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, err
	}
	return current == expected, nil
}

func generationClaimAbsent(claims bridgeMap, key stateKey) (bool, error) {
	var current generationClaim
	if err := claims.Lookup(&key, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

func generationGuardMatches(
	guards bridgeMap,
	key Identity,
	expected generationClaim,
) (bool, error) {
	var current generationClaim
	if err := guards.Lookup(&key, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, err
	}
	return current == expected, nil
}

func generationGuardAbsent(guards bridgeMap, key Identity) (bool, error) {
	var current generationClaim
	if err := guards.Lookup(&key, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

func generationTeardownFenceMatches(
	claims bridgeMap,
	guards bridgeMap,
	ambiguity bridgeMap,
	fence generationTeardownFence,
) (bool, error) {
	claimMatches, err := generationClaimMatches(claims, fence.key, fence.claim)
	if err != nil || !claimMatches {
		return false, err
	}
	guardMatches, err := generationGuardMatches(guards, fence.guardKey, fence.guardClaim)
	if err != nil || !guardMatches {
		return false, err
	}
	var markedAt uint64
	if err := ambiguity.Lookup(&fence.key, &markedAt); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, err
	}
	// The timestamp is shared quarantine rather than exclusive ownership, but
	// its exact value is still part of this snapshot. A replacement may be a
	// freshly published fence and must age before it can authorize mutation.
	return markedAt != 0 && markedAt == fence.markedAt, nil
}
