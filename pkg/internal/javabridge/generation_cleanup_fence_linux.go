// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javabridge // import "go.opentelemetry.io/obi/pkg/internal/javabridge"

import (
	"errors"

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
