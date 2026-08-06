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

func ownerDetachGuardPresent(guards bridgeMap, owner Identity) (bool, error) {
	var guard generationClaim
	if err := guards.Lookup(&owner, &guard); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func acquireGenerationTeardownFence(
	claims bridgeMap,
	guards bridgeMap,
	ambiguity bridgeMap,
	key stateKey,
	claim generationClaim,
	now time.Duration,
) (generationTeardownFence, bool, error) {
	fence := generationTeardownFence{
		key: key, claim: claim, guardKey: key.Owner,
	}
	if key.Owner == (Identity{}) || key.Generation == 0 || key.Reserved != 0 || now <= 0 ||
		!validGenerationProducerClaim(claim) {
		return fence, false, errors.New("invalid Java generation teardown fence")
	}
	claimMatches, err := generationClaimMatches(claims, key, claim)
	if err != nil || !claimMatches {
		return fence, false, err
	}
	fence.guardClaim = generationClaim{
		ObservedMonotonicNS: uint64(now),
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecyclePublishing,
		Reserved:            [7]byte{6: generationGoProducerTag},
	}
	if err := guards.Update(&fence.guardKey, &fence.guardClaim, ebpf.UpdateNoExist); err != nil {
		fence.guardClaim = generationClaim{}
		if errors.Is(err, ebpf.ErrKeyExist) {
			return fence, false, nil
		}
		return fence, false, fmt.Errorf("publishing java owner teardown guard: %w", err)
	}
	fence.guardOwned = true
	guardMatches, err := generationGuardMatches(guards, fence.guardKey, fence.guardClaim)
	if err != nil {
		return fence, false, fmt.Errorf("revalidating java owner teardown guard: %w", err)
	}
	if !guardMatches {
		return fence, false, errors.New("java owner teardown guard changed after publication")
	}
	claimMatches, err = generationClaimMatches(claims, key, claim)
	if err != nil || !claimMatches {
		return fence, false, err
	}
	markedAt, err := promoteGenerationAmbiguity(ambiguity, key, uint64(now))
	if err != nil {
		return fence, false, err
	}
	fence.markedAt = markedAt
	valid, err := generationTeardownFenceMatches(claims, guards, ambiguity, fence)
	if err != nil {
		return fence, false, err
	}
	if !valid {
		return fence, false, errors.New("java generation teardown fence changed after publication")
	}
	return fence, true, nil
}

func promoteGenerationAmbiguity(
	ambiguity bridgeMap,
	key stateKey,
	markedAt uint64,
) (uint64, error) {
	if key.Owner == (Identity{}) || key.Generation == 0 || key.Reserved != 0 || markedAt == 0 {
		return 0, errors.New("invalid java generation ambiguity promotion")
	}
	var current uint64
	if err := ambiguity.Lookup(&key, &current); err == nil {
		if current != 0 {
			return current, nil
		}
		if err := ambiguity.Update(&key, &markedAt, ebpf.UpdateExist); err != nil {
			return 0, fmt.Errorf("promoting java generation ambiguity: %w", err)
		}
	} else if errors.Is(err, ebpf.ErrKeyNotExist) {
		// A finish operation may only promote the exact zero-valued reservation
		// published by STAGE. Recreating an absent reservation would turn a
		// concurrent teardown into apparent ownership of the generation.
		return 0, errors.New("java generation ambiguity reservation is absent")
	} else {
		return 0, fmt.Errorf("checking java generation ambiguity: %w", err)
	}
	if err := ambiguity.Lookup(&key, &current); err != nil {
		return 0, fmt.Errorf("revalidating java generation ambiguity: %w", err)
	}
	if current == 0 {
		return 0, errors.New("java generation ambiguity remained reserved")
	}
	return current, nil
}

func ensureGenerationAmbiguity(
	ambiguity bridgeMap,
	key stateKey,
	markedAt uint64,
) error {
	if key.Owner == (Identity{}) || key.Generation == 0 || key.Reserved != 0 || markedAt == 0 {
		return errors.New("invalid java generation ambiguity restoration")
	}
	var current uint64
	if err := ambiguity.Lookup(&key, &current); err == nil {
		if current != 0 {
			return nil
		}
		if err := ambiguity.Update(&key, &markedAt, ebpf.UpdateExist); err != nil {
			return fmt.Errorf("restoring java generation ambiguity: %w", err)
		}
	} else if errors.Is(err, ebpf.ErrKeyNotExist) {
		if err := ambiguity.Update(&key, &markedAt, ebpf.UpdateNoExist); err != nil &&
			!errors.Is(err, ebpf.ErrKeyExist) {
			return fmt.Errorf("recreating java generation ambiguity: %w", err)
		}
	} else {
		return fmt.Errorf("checking java generation ambiguity restoration: %w", err)
	}
	if err := ambiguity.Lookup(&key, &current); err != nil {
		return fmt.Errorf("revalidating java generation ambiguity restoration: %w", err)
	}
	if current == 0 {
		return errors.New("java generation ambiguity restoration remained reserved")
	}
	return nil
}

func handoffGenerationProducerClaim(
	claims bridgeMap,
	key stateKey,
	local *generationClaim,
	now time.Duration,
) (bool, error) {
	if local == nil || local.ObservedMonotonicNS == 0 {
		return true, nil
	}
	expected := *local
	// Invocation-local authority is single-use. Move it out before any lookup
	// or update so no error path or outer defer can retry against a later
	// byte-identical successor.
	*local = generationClaim{}
	if key.Owner == (Identity{}) || key.Generation == 0 || key.Reserved != 0 ||
		!validGenerationProducerClaim(expected) {
		return false, errors.New("invalid Java generation claim handoff")
	}
	matches, err := generationClaimMatches(claims, key, expected)
	if err != nil {
		return false, fmt.Errorf("checking Java generation claim before handoff: %w", err)
	}
	if !matches {
		return true, nil
	}
	cleanup, err := generationProducerHandoffValue(expected, now)
	if err != nil {
		return false, err
	}
	updateErr := claims.Update(&key, &cleanup, ebpf.UpdateExist)
	// The UpdateExist attempt is terminal for this invocation. Success is the
	// handoff linearization point; failure retains the semantic map value fail
	// closed, but the caller must not retry and accidentally convert a later
	// byte-identical successor.
	if updateErr != nil {
		return false, fmt.Errorf("handing off Java generation claim: %w", updateErr)
	}
	return true, nil
}

func handoffGenerationProducerGuard(
	guards bridgeMap,
	key stateKey,
	local *generationClaim,
	now time.Duration,
) (bool, error) {
	if local == nil || local.ObservedMonotonicNS == 0 {
		return true, nil
	}
	expected := *local
	*local = generationClaim{}
	if !validGenerationProducerGuard(key, expected) {
		return false, errors.New("invalid Java generation guard handoff")
	}
	matches, err := generationGuardMatches(guards, key.Owner, expected)
	if err != nil {
		return false, fmt.Errorf("checking Java generation guard before handoff: %w", err)
	}
	if !matches {
		return true, nil
	}
	cleanup, err := generationProducerHandoffValue(expected, now)
	if err != nil {
		return false, err
	}
	updateErr := guards.Update(&key.Owner, &cleanup, ebpf.UpdateExist)
	// As with E, never carry invocation-local G authority beyond its one
	// terminal handoff attempt.
	if updateErr != nil {
		return false, fmt.Errorf("handing off Java generation guard: %w", updateErr)
	}
	return true, nil
}

func handoffGenerationProducerFencePair(
	claims bridgeMap,
	guards bridgeMap,
	key stateKey,
	claim *generationClaim,
	guard *generationClaim,
	now func() time.Duration,
) error {
	if claim != nil && claim.ObservedMonotonicNS != 0 {
		handedOff, err := handoffGenerationProducerClaim(claims, key, claim, now())
		if err != nil || !handedOff {
			if guard != nil {
				// E failed to become cleanup-visible. Revoke this invocation's G
				// token without touching the producer guard in the map so no outer
				// defer can expose a partial cleanup fence pair.
				*guard = generationClaim{}
			}
			return errors.Join(err, errors.New("java exact generation fence remained producer-owned"))
		}
	}
	if guard != nil && guard.ObservedMonotonicNS != 0 {
		handedOff, err := handoffGenerationProducerGuard(guards, key, guard, now())
		if err != nil || !handedOff {
			return errors.Join(err, errors.New("java owner generation guard remained producer-owned"))
		}
	}
	return nil
}

func releaseGenerationProducerClaim(
	claims bridgeMap,
	key stateKey,
	local *generationClaim,
) (bool, error) {
	if local == nil || local.ObservedMonotonicNS == 0 {
		return true, nil
	}
	if key.Owner == (Identity{}) || key.Generation == 0 || key.Reserved != 0 ||
		!validGenerationProducerClaim(*local) {
		*local = generationClaim{}
		return false, errors.New("invalid Java generation claim release")
	}
	matches, err := generationClaimMatches(claims, key, *local)
	if err != nil {
		return false, err
	}
	if !matches {
		*local = generationClaim{}
		return true, nil
	}
	deleted, deleteErr := cleanupDeleteExact(claims, key, *local)
	if deleted {
		*local = generationClaim{}
		return true, nil
	}
	matches, matchErr := generationClaimMatches(claims, key, *local)
	if matchErr == nil && !matches {
		*local = generationClaim{}
		return true, nil
	}
	return false, errors.Join(deleteErr, matchErr)
}

func releaseGenerationProducerGuard(
	guards bridgeMap,
	key stateKey,
	local *generationClaim,
) (bool, error) {
	if local == nil || local.ObservedMonotonicNS == 0 {
		return true, nil
	}
	if !validGenerationProducerGuard(key, *local) {
		*local = generationClaim{}
		return false, errors.New("invalid Java generation guard release")
	}
	matches, err := generationGuardMatches(guards, key.Owner, *local)
	if err != nil {
		return false, err
	}
	if !matches {
		*local = generationClaim{}
		return true, nil
	}
	deleted, deleteErr := cleanupDeleteExact(guards, key.Owner, *local)
	if deleted {
		*local = generationClaim{}
		return true, nil
	}
	matches, matchErr := generationGuardMatches(guards, key.Owner, *local)
	if matchErr == nil && !matches {
		*local = generationClaim{}
		return true, nil
	}
	return false, errors.Join(deleteErr, matchErr)
}
