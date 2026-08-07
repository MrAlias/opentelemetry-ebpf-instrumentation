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

const sslPrewriteMinimumFenceAge = time.Second

const (
	sslPrewriteOwnerPublished uint32 = 1
	sslPrewriteOwnerBlocked   uint32 = 2
	sslPrewriteOwnerClosing   uint32 = 3
)

const (
	sslPrewriteAmbiguous uint8 = 1
	sslPrewriteClosing   uint8 = 2
)

type sslPrewriteKey struct {
	PIDTGID         uint64
	ThreadStartTime uint64
	HandoffID       uint64
}

type sslPrewriteConnectionOwner struct {
	Key                 sslPrewriteKey
	ObservedMonotonicNS uint64
	State               uint32
	Reserved            uint32
}

type sslPrewriteConnectionAmbiguity struct {
	ObservedMonotonicNS uint64
	State               uint8
	Reserved            [7]byte
}

type sslPrewriteValue [152]byte

type sslPrewriteRoot struct {
	owner        sslPrewriteConnectionOwner
	hasOwner     bool
	ambiguity    sslPrewriteConnectionAmbiguity
	hasAmbiguity bool
}

func (c *Cleanup) sweepSSLPrewrite() error {
	retention := c.ttl
	if retention < sslPrewriteMinimumFenceAge {
		retention = sslPrewriteMinimumFenceAge
	}

	var result error
	claims, err := cleanupMapEntries[connectionInfoNetNSCookie, sslPrewriteConnectionOwner](
		c.maps.sslPrewriteConnectionClaims,
	)
	if err != nil {
		result = errors.Join(result, fmt.Errorf("iterating SSL prewrite connection claims: %w", err))
	}
	claimsNow := c.monoTimeNow()
	for _, entry := range claims {
		if !sslPrewriteOwnerStale(claimsNow, retention, entry.value) {
			continue
		}
		if deleteErr := c.retireStaleSSLPrewriteClaim(entry.key, entry.value); deleteErr != nil {
			result = errors.Join(
				result, fmt.Errorf("deleting stale SSL prewrite connection claim: %w", deleteErr),
			)
		}
	}

	roots := make(map[connectionInfoNetNSCookie]sslPrewriteRoot)
	owners, err := cleanupMapEntries[connectionInfoNetNSCookie, sslPrewriteConnectionOwner](
		c.maps.sslPrewriteConnectionOwners,
	)
	if err != nil {
		result = errors.Join(result, fmt.Errorf("iterating SSL prewrite connection owners: %w", err))
	}
	for _, entry := range owners {
		root := roots[entry.key]
		root.owner = entry.value
		root.hasOwner = true
		roots[entry.key] = root
	}

	ambiguities, err := cleanupMapEntries[
		connectionInfoNetNSCookie,
		sslPrewriteConnectionAmbiguity,
	](c.maps.sslPrewriteConnectionAmbiguity)
	if err != nil {
		result = errors.Join(
			result, fmt.Errorf("iterating SSL prewrite connection ambiguity: %w", err),
		)
	}
	for _, entry := range ambiguities {
		root := roots[entry.key]
		root.ambiguity = entry.value
		root.hasAmbiguity = true
		roots[entry.key] = root
	}

	rootsNow := c.monoTimeNow()
	for key, root := range roots {
		if !sslPrewriteRootStale(rootsNow, retention, root) {
			continue
		}
		if cleanupErr := c.cleanupSSLPrewriteRoot(
			key, root, rootsNow, retention,
		); cleanupErr != nil {
			result = errors.Join(result, cleanupErr)
		}
	}
	return result
}

func sslPrewriteRootStale(
	now time.Duration,
	retention time.Duration,
	root sslPrewriteRoot,
) bool {
	if !root.hasOwner && !root.hasAmbiguity {
		return false
	}
	if root.hasOwner && !sslPrewriteOwnerStale(now, retention, root.owner) {
		return false
	}
	return !root.hasAmbiguity ||
		sslPrewriteAmbiguityStale(now, retention, root.ambiguity)
}

func sslPrewriteOwnerStale(
	now time.Duration,
	retention time.Duration,
	owner sslPrewriteConnectionOwner,
) bool {
	if owner.Reserved != 0 {
		return true
	}
	switch owner.State {
	case sslPrewriteOwnerPublished, sslPrewriteOwnerBlocked, sslPrewriteOwnerClosing:
	default:
		return true
	}
	return cleanupExpired(now, owner.ObservedMonotonicNS, retention)
}

func sslPrewriteAmbiguityStale(
	now time.Duration,
	retention time.Duration,
	ambiguity sslPrewriteConnectionAmbiguity,
) bool {
	if ambiguity.Reserved != ([7]byte{}) {
		return true
	}
	switch ambiguity.State {
	case sslPrewriteAmbiguous, sslPrewriteClosing:
	default:
		return true
	}
	return cleanupExpired(now, ambiguity.ObservedMonotonicNS, retention)
}

func (c *Cleanup) cleanupSSLPrewriteRoot(
	key connectionInfoNetNSCookie,
	root sslPrewriteRoot,
	now time.Duration,
	retention time.Duration,
) (result error) {
	claimNow := c.monoTimeNow()
	if claimNow <= 0 {
		return errors.New("reading monotonic time for SSL prewrite cleanup claim")
	}
	claim := sslPrewriteConnectionOwner{
		ObservedMonotonicNS: uint64(claimNow),
		State:               sslPrewriteOwnerClosing,
	}
	if err := c.maps.sslPrewriteConnectionClaims.Update(
		&key, &claim, ebpf.UpdateNoExist,
	); err != nil {
		if errors.Is(err, ebpf.ErrKeyExist) {
			return nil
		}
		return fmt.Errorf("claiming stale SSL prewrite connection: %w", err)
	}
	ensureClosingOnRelease := false
	releaseClaim := true
	defer func() {
		if !releaseClaim {
			return
		}
		result = errors.Join(
			result,
			c.releaseSSLPrewriteClaim(key, claim, ensureClosingOnRelease),
		)
	}()

	revalidated, ok, err := c.revalidateSSLPrewriteRoot(key, root, now, retention)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}

	expiredClosing := revalidated.hasAmbiguity &&
		revalidated.ambiguity.State == sslPrewriteClosing &&
		revalidated.ambiguity.Reserved == ([7]byte{})
	if !expiredClosing {
		ensureClosingOnRelease = true
		published, publishErr := c.publishSSLPrewriteClosing(key)
		if publishErr != nil {
			// The claim itself is a closing fence. Retain it when the stronger
			// ambiguity marker could not be atomically published; a later stale-
			// claim pass will retry the marker before removing this claim.
			releaseClaim = false
			return publishErr
		}
		if !published {
			return nil
		}
	}

	ownerDeleted, err := c.deleteSSLPrewriteOwner(key, revalidated)
	if err != nil {
		return err
	}
	if !ownerDeleted {
		return nil
	}
	if !expiredClosing {
		return nil
	}

	if _, err := cleanupDeleteExact(
		c.maps.sslPrewriteConnectionAmbiguity,
		key,
		revalidated.ambiguity,
	); err != nil {
		return fmt.Errorf("deleting expired SSL prewrite closing marker: %w", err)
	}
	return nil
}

func (c *Cleanup) revalidateSSLPrewriteRoot(
	key connectionInfoNetNSCookie,
	expected sslPrewriteRoot,
	now time.Duration,
	retention time.Duration,
) (sslPrewriteRoot, bool, error) {
	var current sslPrewriteRoot
	var owner sslPrewriteConnectionOwner
	if err := c.maps.sslPrewriteConnectionOwners.Lookup(&key, &owner); err == nil {
		current.owner = owner
		current.hasOwner = true
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return current, false, fmt.Errorf("revalidating SSL prewrite connection owner: %w", err)
	}
	if current.hasOwner != expected.hasOwner ||
		(current.hasOwner && current.owner != expected.owner) {
		return current, false, nil
	}

	var ambiguity sslPrewriteConnectionAmbiguity
	if err := c.maps.sslPrewriteConnectionAmbiguity.Lookup(&key, &ambiguity); err == nil {
		current.ambiguity = ambiguity
		current.hasAmbiguity = true
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return current, false, fmt.Errorf("revalidating SSL prewrite connection ambiguity: %w", err)
	}
	if current.hasAmbiguity != expected.hasAmbiguity ||
		(current.hasAmbiguity && current.ambiguity != expected.ambiguity) {
		return current, false, nil
	}
	if !sslPrewriteRootStale(now, retention, current) {
		return current, false, nil
	}
	return current, true, nil
}

func (c *Cleanup) publishSSLPrewriteClosing(key connectionInfoNetNSCookie) (bool, error) {
	now := c.monoTimeNow()
	if now <= 0 {
		return false, errors.New("reading monotonic time for SSL prewrite closing marker")
	}
	closing := sslPrewriteConnectionAmbiguity{
		ObservedMonotonicNS: uint64(now),
		State:               sslPrewriteClosing,
	}
	if err := c.maps.sslPrewriteConnectionAmbiguity.Update(
		&key, &closing, ebpf.UpdateAny,
	); err != nil {
		return false, fmt.Errorf("publishing SSL prewrite closing marker: %w", err)
	}
	exact, err := cleanupValueExact(c.maps.sslPrewriteConnectionAmbiguity, key, closing)
	if err != nil {
		return false, fmt.Errorf("revalidating SSL prewrite closing marker: %w", err)
	}
	return exact, nil
}

func (c *Cleanup) retireStaleSSLPrewriteClaim(
	key connectionInfoNetNSCookie,
	expected sslPrewriteConnectionOwner,
) error {
	now := c.monoTimeNow()
	if now <= 0 {
		return errors.New("reading monotonic time for stale SSL prewrite claim fence")
	}
	closing := sslPrewriteConnectionAmbiguity{
		ObservedMonotonicNS: uint64(now),
		State:               sslPrewriteClosing,
	}
	// HASH maps on the oldest supported kernels have no compare-and-delete.
	// Atomically replacing or inserting a closing marker first makes any claim
	// replacement fail closed: every BPF publisher checks this map before and
	// after publication, and BPF never removes an ambiguity entry.
	if err := c.maps.sslPrewriteConnectionAmbiguity.Update(
		&key, &closing, ebpf.UpdateAny,
	); err != nil {
		return fmt.Errorf("publishing stale-claim closing marker: %w", err)
	}
	fenced, err := cleanupValueExact(c.maps.sslPrewriteConnectionAmbiguity, key, closing)
	if err != nil {
		return fmt.Errorf("revalidating stale-claim closing marker: %w", err)
	}
	if !fenced {
		return nil
	}
	claimExact, err := cleanupValueExact(c.maps.sslPrewriteConnectionClaims, key, expected)
	if err != nil {
		return fmt.Errorf("revalidating stale SSL prewrite claim: %w", err)
	}
	if !claimExact {
		return nil
	}
	fenced, err = cleanupValueExact(c.maps.sslPrewriteConnectionAmbiguity, key, closing)
	if err != nil {
		return fmt.Errorf("revalidating stale-claim fence before deletion: %w", err)
	}
	if !fenced {
		return nil
	}
	_, err = cleanupDeleteExact(c.maps.sslPrewriteConnectionClaims, key, expected)
	return err
}

func (c *Cleanup) deleteSSLPrewriteOwner(
	key connectionInfoNetNSCookie,
	root sslPrewriteRoot,
) (bool, error) {
	if !root.hasOwner {
		return true, nil
	}
	if root.owner.Key != (sslPrewriteKey{}) {
		deleted, err := cleanupDeleteCaptured[
			sslPrewriteKey,
			sslPrewriteValue,
		](c.maps.sslPrewrite, root.owner.Key)
		if err != nil {
			return false, fmt.Errorf("deleting exact SSL prewrite value: %w", err)
		}
		if !deleted {
			var current sslPrewriteValue
			if err := c.maps.sslPrewrite.Lookup(&root.owner.Key, &current); err == nil {
				return false, nil
			} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
				return false, fmt.Errorf("revalidating exact SSL prewrite value: %w", err)
			}
		}
	}

	deleted, err := cleanupDeleteExact(c.maps.sslPrewriteConnectionOwners, key, root.owner)
	if err != nil {
		return false, fmt.Errorf("deleting SSL prewrite connection owner: %w", err)
	}
	return deleted, nil
}

func (c *Cleanup) releaseSSLPrewriteClaim(
	key connectionInfoNetNSCookie,
	expected sslPrewriteConnectionOwner,
	ensureClosing bool,
) error {
	var current sslPrewriteConnectionOwner
	if err := c.maps.sslPrewriteConnectionClaims.Lookup(&key, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return c.ensureSSLPrewriteClosing(key)
		}
		return fmt.Errorf("revalidating SSL prewrite cleanup claim: %w", err)
	}
	if current != expected {
		ensureClosing = true
	}
	if ensureClosing {
		if err := c.ensureSSLPrewriteClosing(key); err != nil {
			return err
		}
	}
	if current != expected && !sslPrewriteClosingClaim(current) {
		return nil
	}
	_, err := cleanupDeleteExact(c.maps.sslPrewriteConnectionClaims, key, current)
	if err != nil {
		return fmt.Errorf("releasing SSL prewrite cleanup claim: %w", err)
	}
	return nil
}

func sslPrewriteClosingClaim(claim sslPrewriteConnectionOwner) bool {
	return claim.Key == (sslPrewriteKey{}) &&
		claim.State == sslPrewriteOwnerClosing &&
		claim.Reserved == 0
}

func (c *Cleanup) ensureSSLPrewriteClosing(key connectionInfoNetNSCookie) error {
	var current sslPrewriteConnectionAmbiguity
	if err := c.maps.sslPrewriteConnectionAmbiguity.Lookup(&key, &current); err == nil {
		return nil
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("checking refreshed SSL prewrite closing marker: %w", err)
	}

	now := c.monoTimeNow()
	if now <= 0 {
		return errors.New("reading monotonic time for refreshed SSL prewrite closing marker")
	}
	closing := sslPrewriteConnectionAmbiguity{
		ObservedMonotonicNS: uint64(now),
		State:               sslPrewriteClosing,
	}
	if err := c.maps.sslPrewriteConnectionAmbiguity.Update(
		&key, &closing, ebpf.UpdateNoExist,
	); err != nil && !errors.Is(err, ebpf.ErrKeyExist) {
		return fmt.Errorf("restoring refreshed SSL prewrite closing marker: %w", err)
	}
	return nil
}

func cleanupDeleteCaptured[K, V comparable](m cleanupMap, key K) (bool, error) {
	var current V
	if err := m.Lookup(&key, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, err
	}
	return cleanupDeleteExact(m, key, current)
}

func cleanupValueExact[K, V comparable](m cleanupMap, key K, expected V) (bool, error) {
	var current V
	if err := m.Lookup(&key, &current); err != nil {
		return false, ignoreMissing(err)
	}
	if current != expected {
		return false, nil
	}
	var revalidated V
	if err := m.Lookup(&key, &revalidated); err != nil {
		return false, ignoreMissing(err)
	}
	return revalidated == expected, nil
}
