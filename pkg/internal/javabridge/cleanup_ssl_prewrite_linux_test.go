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

	"github.com/cilium/ebpf"
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

func TestSSLPrewriteCleanupFencesStaleClaimsBeforeDelete(t *testing.T) {
	for _, test := range []struct {
		name   string
		marker *sslPrewriteConnectionAmbiguity
	}{
		{name: "absent marker"},
		{
			name: "expired ambiguous marker",
			marker: &sslPrewriteConnectionAmbiguity{
				ObservedMonotonicNS: uint64(time.Second),
				State:               sslPrewriteAmbiguous,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cleanup := testSSLCleanup(3*time.Second, time.Second)
			key := testSSLConnectionKey(1)
			stale := sslPrewriteConnectionOwner{
				ObservedMonotonicNS: uint64(time.Second),
				State:               sslPrewriteOwnerBlocked,
			}
			freshKey := testSSLConnectionKey(2)
			fresh := sslPrewriteConnectionOwner{
				ObservedMonotonicNS: uint64(2500 * time.Millisecond),
				State:               sslPrewriteOwnerClosing,
			}
			closing := sslPrewriteConnectionAmbiguity{
				ObservedMonotonicNS: uint64(3 * time.Second),
				State:               sslPrewriteClosing,
			}
			claims := cleanup.maps.sslPrewriteConnectionClaims.(*fakeBridgeMap)
			ambiguity := cleanup.maps.sslPrewriteConnectionAmbiguity.(*fakeBridgeMap)
			claims.values[key] = stale
			claims.values[freshKey] = fresh
			if test.marker != nil {
				ambiguity.values[key] = *test.marker
			}

			var order []string
			ambiguity.beforeUpdate = func(updatedKey, value any, flags ebpf.MapUpdateFlags) {
				require.Equal(t, key, updatedKey)
				require.Equal(t, closing, value)
				require.Equal(t, ebpf.UpdateAny, flags)
				require.Equal(t, stale, claims.values[key])
			}
			ambiguity.afterUpdate = func(any, any) { order = append(order, "marker") }
			ambiguity.afterDelete = func(any) { t.Fatal("fresh closing marker was deleted") }
			claims.afterDelete = func(deletedKey any) {
				require.Equal(t, key, deletedKey)
				require.Equal(t, closing, ambiguity.values[key])
				order = append(order, "claim")
			}

			require.NoError(t, cleanup.Sweep())
			assert.Equal(t, []string{"marker", "claim"}, order)
			assert.Equal(t, map[any]any{freshKey: fresh}, claims.values)
			assert.Equal(t, closing, ambiguity.values[key])
		})
	}
}

func TestSSLPrewriteCleanupPreservesStaleClaimWhenFencePublicationFails(t *testing.T) {
	cleanup := testSSLCleanup(3*time.Second, time.Second)
	key := testSSLConnectionKey(1)
	claim := sslPrewriteConnectionOwner{
		ObservedMonotonicNS: uint64(time.Second),
		State:               sslPrewriteOwnerBlocked,
	}
	marker := sslPrewriteConnectionAmbiguity{
		ObservedMonotonicNS: uint64(time.Second),
		State:               sslPrewriteAmbiguous,
	}
	claims := cleanup.maps.sslPrewriteConnectionClaims.(*fakeBridgeMap)
	ambiguity := cleanup.maps.sslPrewriteConnectionAmbiguity.(*fakeBridgeMap)
	claims.values[key] = claim
	ambiguity.values[key] = marker
	ambiguity.updateErr = errors.New("map full")
	deletes := 0
	claims.afterDelete = func(any) { deletes++ }

	err := cleanup.Sweep()
	require.ErrorContains(t, err, "publishing stale-claim closing marker")
	assert.Equal(t, claim, claims.values[key])
	assert.Equal(t, marker, ambiguity.values[key])
	assert.Zero(t, deletes)
}

func TestSSLPrewriteCleanupPreservesClaimWhenClosingFenceIsRefreshed(t *testing.T) {
	cleanup := testSSLCleanup(3*time.Second, time.Second)
	key := testSSLConnectionKey(1)
	claim := sslPrewriteConnectionOwner{
		ObservedMonotonicNS: uint64(time.Second),
		State:               sslPrewriteOwnerBlocked,
	}
	refreshed := sslPrewriteConnectionAmbiguity{
		ObservedMonotonicNS: uint64(4 * time.Second),
		State:               sslPrewriteClosing,
	}
	claims := cleanup.maps.sslPrewriteConnectionClaims.(*fakeBridgeMap)
	ambiguity := cleanup.maps.sslPrewriteConnectionAmbiguity.(*fakeBridgeMap)
	claims.values[key] = claim
	ambiguity.afterUpdate = func(updatedKey, _ any) {
		ambiguity.mu.Lock()
		ambiguity.values[updatedKey] = refreshed
		ambiguity.mu.Unlock()
	}

	require.NoError(t, cleanup.Sweep())
	assert.Equal(t, claim, claims.values[key])
	assert.Equal(t, refreshed, ambiguity.values[key])
}

func TestSSLPrewriteCleanupPreservesClaimReplacementBeforeFinalRead(t *testing.T) {
	cleanup := testSSLCleanup(3*time.Second, time.Second)
	key := testSSLConnectionKey(1)
	claim := sslPrewriteConnectionOwner{
		ObservedMonotonicNS: uint64(time.Second),
		State:               sslPrewriteOwnerBlocked,
	}
	replacement := sslPrewriteConnectionOwner{
		ObservedMonotonicNS: uint64(2500 * time.Millisecond),
		State:               sslPrewriteOwnerClosing,
	}
	claims := cleanup.maps.sslPrewriteConnectionClaims.(*fakeBridgeMap)
	claims.values[key] = claim
	claims.afterLookup = func(count int) {
		if count != 1 {
			return
		}
		claims.mu.Lock()
		claims.values[key] = replacement
		claims.mu.Unlock()
	}

	require.NoError(t, cleanup.Sweep())
	assert.Equal(t, replacement, claims.values[key])
	assert.Equal(t, sslPrewriteConnectionAmbiguity{
		ObservedMonotonicNS: uint64(3 * time.Second),
		State:               sslPrewriteClosing,
	}, cleanup.maps.sslPrewriteConnectionAmbiguity.(*fakeBridgeMap).values[key])
}

func TestSSLPrewriteCleanupKeepsFenceWhenFinalDeleteRemovesTransientSuccessor(t *testing.T) {
	cleanup := testSSLCleanup(3*time.Second, time.Second)
	key := testSSLConnectionKey(1)
	claim := sslPrewriteConnectionOwner{
		ObservedMonotonicNS: uint64(time.Second),
		State:               sslPrewriteOwnerBlocked,
	}
	successor := sslPrewriteConnectionOwner{
		ObservedMonotonicNS: uint64(4 * time.Second),
		State:               sslPrewriteOwnerPublished,
	}
	claims := cleanup.maps.sslPrewriteConnectionClaims.(*fakeBridgeMap)
	claims.values[key] = claim
	claims.afterLookup = func(count int) {
		if count != 4 {
			return
		}
		claims.mu.Lock()
		claims.values[key] = successor
		claims.mu.Unlock()
	}

	require.NoError(t, cleanup.Sweep())
	assert.NotContains(t, claims.values, key)
	assert.Equal(t, sslPrewriteConnectionAmbiguity{
		ObservedMonotonicNS: uint64(3 * time.Second),
		State:               sslPrewriteClosing,
	}, cleanup.maps.sslPrewriteConnectionAmbiguity.(*fakeBridgeMap).values[key])
}

func TestSSLPrewriteCleanupPreservesStaleClaimWhenFenceTimeFails(t *testing.T) {
	cleanup := testSSLCleanup(3*time.Second, time.Second)
	key := testSSLConnectionKey(1)
	claim := sslPrewriteConnectionOwner{
		ObservedMonotonicNS: uint64(time.Second),
		State:               sslPrewriteOwnerBlocked,
	}
	claims := cleanup.maps.sslPrewriteConnectionClaims.(*fakeBridgeMap)
	claims.values[key] = claim
	calls := 0
	cleanup.monoTimeNow = func() time.Duration {
		calls++
		if calls == 1 {
			return 3 * time.Second
		}
		return 0
	}

	err := cleanup.Sweep()
	require.ErrorContains(t, err, "reading monotonic time for stale SSL prewrite claim fence")
	assert.Equal(t, claim, claims.values[key])
	assert.Empty(t, cleanup.maps.sslPrewriteConnectionAmbiguity.(*fakeBridgeMap).values)
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
		assert.Equal(t, sslPrewriteConnectionAmbiguity{
			ObservedMonotonicNS: uint64(time.Second),
			State:               sslPrewriteAmbiguous,
		}, ambiguity.values[key])
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
