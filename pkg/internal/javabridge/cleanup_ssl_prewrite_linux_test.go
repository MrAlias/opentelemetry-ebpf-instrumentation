// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javabridge

import (
	"errors"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSLPrewriteCleanupKernelMapLayouts(t *testing.T) {
	assert.Equal(t, uintptr(24), unsafe.Sizeof(sslPrewriteKey{}))
	assert.Equal(t, uintptr(40), unsafe.Sizeof(sslPrewriteConnectionOwner{}))
	assert.Equal(t, uintptr(16), unsafe.Sizeof(sslPrewriteConnectionAmbiguity{}))
	assert.Equal(t, uintptr(152), unsafe.Sizeof(sslPrewriteValue{}))
}

func TestSSLPrewriteCleanupRetainsClosingMarkerForMinimumAge(t *testing.T) {
	cleanup := testSSLCleanup(2*time.Second, 100*time.Millisecond)
	key := testSSLConnectionKey(1)
	marker := sslPrewriteConnectionAmbiguity{
		ObservedMonotonicNS: uint64(1500 * time.Millisecond),
		State:               sslPrewriteClosing,
	}
	ambiguity := cleanup.maps.sslPrewriteConnectionAmbiguity.(*fakeBridgeMap)
	ambiguity.values[key] = marker

	require.NoError(t, cleanup.Sweep())
	assert.Equal(t, marker, ambiguity.values[key])
	assert.Empty(t, cleanup.maps.sslPrewriteConnectionClaims.(*fakeBridgeMap).values)
}

func TestSSLPrewriteCleanupDeletesExactSharedValueAndLeavesClosingFence(t *testing.T) {
	cleanup := testSSLCleanup(3*time.Second, time.Second)
	connectionKey := testSSLConnectionKey(1)
	prewriteKey := sslPrewriteKey{PIDTGID: 2, ThreadStartTime: 3, HandoffID: 4}
	otherKey := sslPrewriteKey{PIDTGID: 5, ThreadStartTime: 6, HandoffID: 7}
	owner := sslPrewriteConnectionOwner{
		Key:                 prewriteKey,
		ObservedMonotonicNS: uint64(time.Second),
		State:               sslPrewriteOwnerPublished,
	}
	var value, otherValue sslPrewriteValue
	value[0] = 1
	otherValue[0] = 2

	owners := cleanup.maps.sslPrewriteConnectionOwners.(*fakeBridgeMap)
	claims := cleanup.maps.sslPrewriteConnectionClaims.(*fakeBridgeMap)
	prewrites := cleanup.maps.sslPrewrite.(*fakeBridgeMap)
	ambiguity := cleanup.maps.sslPrewriteConnectionAmbiguity.(*fakeBridgeMap)
	owners.values[connectionKey] = owner
	prewrites.values[prewriteKey] = value
	prewrites.values[otherKey] = otherValue

	var orderMu sync.Mutex
	var order []string
	record := func(operation string) func(any) {
		return func(any) {
			orderMu.Lock()
			defer orderMu.Unlock()
			order = append(order, operation)
		}
	}
	prewrites.afterDelete = record("shared")
	owners.afterDelete = record("owner")
	claims.afterDelete = record("claim")

	require.NoError(t, cleanup.Sweep())
	assert.NotContains(t, prewrites.values, prewriteKey)
	assert.Equal(t, otherValue, prewrites.values[otherKey])
	assert.NotContains(t, owners.values, connectionKey)
	assert.Equal(t, sslPrewriteConnectionAmbiguity{
		ObservedMonotonicNS: uint64(3 * time.Second),
		State:               sslPrewriteClosing,
	}, ambiguity.values[connectionKey])
	assert.Empty(t, claims.values)
	assert.Equal(t, []string{"shared", "owner", "claim"}, order)
}

func TestSSLPrewriteCleanupDeletesExpiredOrphanFenceBeforeClaim(t *testing.T) {
	cleanup := testSSLCleanup(3*time.Second, time.Second)
	key := testSSLConnectionKey(1)
	marker := sslPrewriteConnectionAmbiguity{
		ObservedMonotonicNS: uint64(time.Second),
		State:               sslPrewriteClosing,
	}
	ambiguity := cleanup.maps.sslPrewriteConnectionAmbiguity.(*fakeBridgeMap)
	claims := cleanup.maps.sslPrewriteConnectionClaims.(*fakeBridgeMap)
	ambiguity.values[key] = marker

	var order []string
	ambiguity.afterDelete = func(any) { order = append(order, "marker") }
	claims.afterDelete = func(any) { order = append(order, "claim") }

	require.NoError(t, cleanup.Sweep())
	assert.Empty(t, ambiguity.values)
	assert.Empty(t, claims.values)
	assert.Equal(t, []string{"marker", "claim"}, order)
}

func TestSSLPrewriteCleanupPreservesRefreshedFence(t *testing.T) {
	cleanup := testSSLCleanup(3*time.Second, time.Second)
	key := testSSLConnectionKey(1)
	expired := sslPrewriteConnectionAmbiguity{
		ObservedMonotonicNS: uint64(time.Second),
		State:               sslPrewriteClosing,
	}
	refreshed := sslPrewriteConnectionAmbiguity{
		ObservedMonotonicNS: uint64(2500 * time.Millisecond),
		State:               sslPrewriteClosing,
	}
	ambiguity := cleanup.maps.sslPrewriteConnectionAmbiguity.(*fakeBridgeMap)
	ambiguity.values[key] = expired
	ambiguity.afterLookup = func(count int) {
		if count == 1 {
			ambiguity.mu.Lock()
			ambiguity.values[key] = refreshed
			ambiguity.mu.Unlock()
		}
	}

	require.NoError(t, cleanup.Sweep())
	assert.Equal(t, refreshed, ambiguity.values[key])
	assert.Empty(t, cleanup.maps.sslPrewriteConnectionClaims.(*fakeBridgeMap).values)
}

func TestSSLPrewriteCleanupLeavesRootWithOccupiedClaim(t *testing.T) {
	cleanup := testSSLCleanup(3*time.Second, time.Second)
	connectionKey := testSSLConnectionKey(1)
	prewriteKey := sslPrewriteKey{PIDTGID: 2, ThreadStartTime: 3, HandoffID: 4}
	owner := sslPrewriteConnectionOwner{
		Key:                 prewriteKey,
		ObservedMonotonicNS: uint64(time.Second),
		State:               sslPrewriteOwnerPublished,
	}
	claim := sslPrewriteConnectionOwner{
		Key:                 prewriteKey,
		ObservedMonotonicNS: uint64(2500 * time.Millisecond),
		State:               sslPrewriteOwnerPublished,
	}
	var value sslPrewriteValue
	value[0] = 1

	owners := cleanup.maps.sslPrewriteConnectionOwners.(*fakeBridgeMap)
	claims := cleanup.maps.sslPrewriteConnectionClaims.(*fakeBridgeMap)
	prewrites := cleanup.maps.sslPrewrite.(*fakeBridgeMap)
	owners.values[connectionKey] = owner
	claims.values[connectionKey] = claim
	prewrites.values[prewriteKey] = value

	require.NoError(t, cleanup.Sweep())
	assert.Equal(t, owner, owners.values[connectionKey])
	assert.Equal(t, claim, claims.values[connectionKey])
	assert.Equal(t, value, prewrites.values[prewriteKey])
	assert.Empty(t, cleanup.maps.sslPrewriteConnectionAmbiguity.(*fakeBridgeMap).values)
}

func TestSSLPrewriteCleanupSweepsStaleClaimsFirst(t *testing.T) {
	cleanup := testSSLCleanup(3*time.Second, time.Second)
	claims := cleanup.maps.sslPrewriteConnectionClaims.(*fakeBridgeMap)
	stale := []sslPrewriteConnectionOwner{
		{ObservedMonotonicNS: 0, State: sslPrewriteOwnerClosing},
		{ObservedMonotonicNS: uint64(4 * time.Second), State: sslPrewriteOwnerClosing},
		{ObservedMonotonicNS: uint64(time.Second), State: sslPrewriteOwnerBlocked},
	}
	for i, claim := range stale {
		claims.values[testSSLConnectionKey(uint64(i+1))] = claim
	}
	freshKey := testSSLConnectionKey(10)
	fresh := sslPrewriteConnectionOwner{
		ObservedMonotonicNS: uint64(2500 * time.Millisecond),
		State:               sslPrewriteOwnerClosing,
	}
	claims.values[freshKey] = fresh

	require.NoError(t, cleanup.Sweep())
	assert.Equal(t, map[any]any{freshKey: fresh}, claims.values)
}

func TestSSLPrewriteCleanupPreservesEntriesObservedDuringEnumeration(t *testing.T) {
	cleanup := testSSLCleanup(9*time.Second, 30*time.Second)
	now := 9 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }

	claimKey := testSSLConnectionKey(1)
	rootKey := testSSLConnectionKey(2)
	prewriteKey := sslPrewriteKey{PIDTGID: 3, ThreadStartTime: 4, HandoffID: 5}
	claim := sslPrewriteConnectionOwner{
		ObservedMonotonicNS: uint64(10 * time.Second),
		State:               sslPrewriteOwnerClosing,
	}
	owner := sslPrewriteConnectionOwner{
		Key:                 prewriteKey,
		ObservedMonotonicNS: uint64(20 * time.Second),
		State:               sslPrewriteOwnerPublished,
	}
	var value sslPrewriteValue
	value[0] = 1

	claims := cleanup.maps.sslPrewriteConnectionClaims.(*fakeBridgeMap)
	owners := cleanup.maps.sslPrewriteConnectionOwners.(*fakeBridgeMap)
	prewrites := cleanup.maps.sslPrewrite.(*fakeBridgeMap)
	ambiguity := cleanup.maps.sslPrewriteConnectionAmbiguity.(*fakeBridgeMap)
	claims.values[claimKey] = claim
	owners.values[rootKey] = owner
	prewrites.values[prewriteKey] = value
	claims.afterIterate = func() {
		now = 11 * time.Second
	}
	ambiguity.afterIterate = func() {
		now = 21 * time.Second
	}

	require.NoError(t, cleanup.Sweep())
	assert.Equal(t, claim, claims.values[claimKey])
	assert.Equal(t, owner, owners.values[rootKey])
	assert.Equal(t, value, prewrites.values[prewriteKey])
	assert.Empty(t, ambiguity.values)
}

func TestSSLPrewriteCleanupRestoresFenceWhenClaimSignalsClose(t *testing.T) {
	cleanup := testSSLCleanup(3*time.Second, time.Second)
	key := testSSLConnectionKey(1)
	ambiguity := cleanup.maps.sslPrewriteConnectionAmbiguity.(*fakeBridgeMap)
	claims := cleanup.maps.sslPrewriteConnectionClaims.(*fakeBridgeMap)
	ambiguity.values[key] = sslPrewriteConnectionAmbiguity{
		ObservedMonotonicNS: uint64(time.Second),
		State:               sslPrewriteClosing,
	}
	claims.afterUpdate = func(updatedKey, value any) {
		signaled := value.(sslPrewriteConnectionOwner)
		signaled.ObservedMonotonicNS++
		claims.mu.Lock()
		claims.values[updatedKey] = signaled
		claims.mu.Unlock()
	}

	require.NoError(t, cleanup.Sweep())
	assert.Equal(t, sslPrewriteConnectionAmbiguity{
		ObservedMonotonicNS: uint64(3 * time.Second),
		State:               sslPrewriteClosing,
	}, ambiguity.values[key])
	assert.Empty(t, claims.values)
}

func TestSSLPrewriteCleanupUsesPublicationTimeForClosingFence(t *testing.T) {
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.ttl = time.Second
	now := 3 * time.Second
	cleanup.monoTimeNow = func() time.Duration { return now }
	key := testSSLConnectionKey(1)
	owners := cleanup.maps.sslPrewriteConnectionOwners.(*fakeBridgeMap)
	claims := cleanup.maps.sslPrewriteConnectionClaims.(*fakeBridgeMap)
	owners.values[key] = sslPrewriteConnectionOwner{
		ObservedMonotonicNS: uint64(time.Second),
		State:               sslPrewriteOwnerBlocked,
	}
	claims.afterUpdate = func(any, any) {
		now = 5 * time.Second
	}

	require.NoError(t, cleanup.Sweep())
	assert.Equal(t, sslPrewriteConnectionAmbiguity{
		ObservedMonotonicNS: uint64(5 * time.Second),
		State:               sslPrewriteClosing,
	}, cleanup.maps.sslPrewriteConnectionAmbiguity.(*fakeBridgeMap).values[key])
}

func TestSSLPrewriteCleanupReportsMapErrors(t *testing.T) {
	t.Run("iteration", func(t *testing.T) {
		cleanup := testSSLCleanup(3*time.Second, time.Second)
		cleanup.maps.sslPrewriteConnectionOwners.(*fakeBridgeMap).iterateErr = errors.New("iteration failed")

		err := cleanup.Sweep()
		require.ErrorContains(t, err, "iterating SSL prewrite connection owners")
	})

	t.Run("claim", func(t *testing.T) {
		cleanup := testSSLCleanup(3*time.Second, time.Second)
		key := testSSLConnectionKey(1)
		owner := sslPrewriteConnectionOwner{
			ObservedMonotonicNS: uint64(time.Second),
			State:               sslPrewriteOwnerBlocked,
		}
		owners := cleanup.maps.sslPrewriteConnectionOwners.(*fakeBridgeMap)
		claims := cleanup.maps.sslPrewriteConnectionClaims.(*fakeBridgeMap)
		owners.values[key] = owner
		claims.updateErr = errors.New("claim failed")

		err := cleanup.Sweep()
		require.ErrorContains(t, err, "claiming stale SSL prewrite connection")
		assert.Equal(t, owner, owners.values[key])
	})

	t.Run("closing marker replacement", func(t *testing.T) {
		cleanup := testSSLCleanup(3*time.Second, time.Second)
		key := testSSLConnectionKey(1)
		ambiguity := cleanup.maps.sslPrewriteConnectionAmbiguity.(*fakeBridgeMap)
		claims := cleanup.maps.sslPrewriteConnectionClaims.(*fakeBridgeMap)
		ambiguity.values[key] = sslPrewriteConnectionAmbiguity{
			ObservedMonotonicNS: uint64(time.Second),
			State:               sslPrewriteAmbiguous,
		}
		ambiguity.updateErr = errors.New("replacement failed")

		err := cleanup.Sweep()
		require.ErrorContains(t, err, "publishing SSL prewrite closing marker")
		assert.Empty(t, ambiguity.values)
		assert.Equal(t, sslPrewriteConnectionOwner{
			ObservedMonotonicNS: uint64(3 * time.Second),
			State:               sslPrewriteOwnerClosing,
		}, claims.values[key])
	})
}

func testSSLCleanup(now, ttl time.Duration) *Cleanup {
	cleanup := testCleanup(testMapHandler(nil, nil, nil))
	cleanup.ttl = ttl
	cleanup.monoTimeNow = func() time.Duration { return now }
	return cleanup
}

func testSSLConnectionKey(cookie uint64) connectionInfoNetNSCookie {
	return connectionInfoNetNSCookie{
		Connection: connectionInfo{
			SourcePort:      uint16(cookie),
			DestinationPort: 443,
		},
		NetNSCookie: cookie,
	}
}
