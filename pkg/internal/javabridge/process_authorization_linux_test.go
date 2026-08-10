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

func newProcessAuthorizationMaps() processAuthorizationMaps {
	newMap := func() cleanupMap { return &fakeBridgeMap{values: make(map[any]any)} }
	return processAuthorizationMaps{
		authorized: newMap(), incarnations: newMap(), claims: newMap(), retired: newMap(),
	}
}

func TestAuthorizeProcessCapabilityNeverInstallsMissingIncarnation(t *testing.T) {
	process := Identity{TID: 7, PID: 7, Namespace: 11}
	maps := newProcessAuthorizationMaps()

	authorized, err := authorizeProcessCapability(maps, process, 41, 2*time.Second)

	require.NoError(t, err)
	require.True(t, authorized)
	assert.Equal(t, uint64(41), maps.authorized.(*fakeBridgeMap).values[process])
	assert.NotContains(t, maps.incarnations.(*fakeBridgeMap).values, process)
	assert.NotContains(t, maps.claims.(*fakeBridgeMap).values, process)
}

func TestAuthorizeProcessCapabilityRejectsRetiredCapability(t *testing.T) {
	process := Identity{TID: 7, PID: 7, Namespace: 11}
	maps := newProcessAuthorizationMaps()
	marker := retiredProcessKey{Process: process, ProcessIncarnation: 41}
	maps.retired.(*fakeBridgeMap).values[marker] = uint64(0)
	maps.incarnations.(*fakeBridgeMap).values[process] = uint64(41)

	authorized, err := authorizeProcessCapability(maps, process, 41, 2*time.Second)

	require.ErrorIs(t, err, ErrProcessCapabilityRetired)
	assert.False(t, authorized)
	assert.Empty(t, maps.authorized.(*fakeBridgeMap).values)
	assert.Equal(t, uint64(41), maps.incarnations.(*fakeBridgeMap).values[process])
	assert.Equal(t, uint64(0), maps.retired.(*fakeBridgeMap).values[marker])
	assert.Empty(t, maps.claims.(*fakeBridgeMap).values)
}

func TestAuthorizeProcessCapabilityLeavesRotationToRegisteredAgent(t *testing.T) {
	process := Identity{TID: 7, PID: 7, Namespace: 11}
	maps := newProcessAuthorizationMaps()
	maps.authorized.(*fakeBridgeMap).values[process] = uint64(41)
	maps.incarnations.(*fakeBridgeMap).values[process] = uint64(41)

	authorized, err := authorizeProcessCapability(maps, process, 73, 2*time.Second)

	require.NoError(t, err)
	require.True(t, authorized)
	assert.Equal(t, uint64(73), maps.authorized.(*fakeBridgeMap).values[process])
	assert.Equal(t, uint64(41), maps.incarnations.(*fakeBridgeMap).values[process])
	assert.NotContains(t, maps.claims.(*fakeBridgeMap).values, process)
}

func TestAuthorizeProcessCapabilityForeignClaimIsRetryable(t *testing.T) {
	process := Identity{TID: 7, PID: 7, Namespace: 11}
	maps := newProcessAuthorizationMaps()
	foreign := threadMappingClaimValue{
		Child: Identity{TID: 9, PID: 7, Namespace: 11}, ProcessIncarnation: 41,
	}
	maps.claims.(*fakeBridgeMap).values[process] = foreign

	authorized, err := authorizeProcessCapability(maps, process, 41, 2*time.Second)

	require.ErrorIs(t, err, ErrProcessClaimContended)
	assert.False(t, authorized)
	assert.Empty(t, maps.authorized.(*fakeBridgeMap).values)
	assert.Empty(t, maps.incarnations.(*fakeBridgeMap).values)
	assert.Equal(t, foreign, maps.claims.(*fakeBridgeMap).values[process])
}

func TestAuthorizeProcessCapabilityAcceptsCommittedMapErrors(t *testing.T) {
	process := Identity{TID: 7, PID: 7, Namespace: 11}
	maps := newProcessAuthorizationMaps()
	maps.claims.(*fakeBridgeMap).updateCommitErr = errors.New("claim reported after commit")
	maps.authorized.(*fakeBridgeMap).updateCommitErr = errors.New("auth reported after commit")

	authorized, err := authorizeProcessCapability(maps, process, 41, 2*time.Second)

	require.True(t, authorized)
	require.Error(t, err)
	assert.Equal(t, uint64(41), maps.authorized.(*fakeBridgeMap).values[process])
	assert.NotContains(t, maps.incarnations.(*fakeBridgeMap).values, process)
	assert.NotContains(t, maps.claims.(*fakeBridgeMap).values, process)
}

func TestAuthorizeProcessCapabilityRollsBackWhenRetirementAppearsAfterAuthorization(t *testing.T) {
	process := Identity{TID: 7, PID: 7, Namespace: 11}
	maps := newProcessAuthorizationMaps()
	marker := retiredProcessKey{Process: process, ProcessIncarnation: 41}
	maps.authorized.(*fakeBridgeMap).afterUpdate = func(any, any) {
		retired := maps.retired.(*fakeBridgeMap)
		retired.mu.Lock()
		retired.values[marker] = uint64(time.Second)
		retired.mu.Unlock()
	}

	authorized, err := authorizeProcessCapability(maps, process, 41, 2*time.Second)

	require.ErrorIs(t, err, ErrProcessCapabilityRetired)
	assert.False(t, authorized)
	assert.NotContains(t, maps.authorized.(*fakeBridgeMap).values, process)
	assert.Equal(t, uint64(time.Second), maps.retired.(*fakeBridgeMap).values[marker])
	assert.Empty(t, maps.claims.(*fakeBridgeMap).values)
}

func TestAuthorizeProcessCapabilityDoesNotAdoptForeignTaggedClaim(t *testing.T) {
	process := Identity{TID: 7, PID: 7, Namespace: 11}
	maps := newProcessAuthorizationMaps()
	claim, valid := javaRemoteParentProcessCleanupClaim(2*time.Second, process, 41)
	require.True(t, valid)
	maps.claims.(*fakeBridgeMap).values[process] = claim

	authorized, err := authorizeProcessCapability(maps, process, 41, 3*time.Second)

	require.ErrorIs(t, err, ErrProcessClaimContended)
	assert.False(t, authorized)
	assert.Equal(t, claim, maps.claims.(*fakeBridgeMap).values[process])
}

func TestDeauthorizeProcessCapabilityRetainsCleanupAuthority(t *testing.T) {
	process := Identity{TID: 7, PID: 7, Namespace: 11}
	authorized := &fakeBridgeMap{values: map[any]any{process: uint64(41)}}
	incarnations := &fakeBridgeMap{values: map[any]any{process: uint64(41)}}

	err := deauthorizeProcessCapability(processAuthorizationMaps{
		authorized: authorized, incarnations: incarnations,
	}, process, 41, false)

	require.NoError(t, err)
	assert.NotContains(t, authorized.values, process)
	assert.Equal(t, uint64(41), incarnations.values[process])
}

func TestDeauthorizeProcessCapabilityDisabledBridgeDeletesOnlyExactIncarnation(t *testing.T) {
	process := Identity{TID: 7, PID: 7, Namespace: 11}
	authorized := &fakeBridgeMap{values: map[any]any{process: uint64(41)}}
	incarnations := &fakeBridgeMap{values: map[any]any{process: uint64(41)}}

	err := deauthorizeProcessCapability(processAuthorizationMaps{
		authorized: authorized, incarnations: incarnations,
	}, process, 41, true)

	require.NoError(t, err)
	assert.NotContains(t, authorized.values, process)
	assert.NotContains(t, incarnations.values, process)

	authorized.values[process] = uint64(41)
	incarnations.values[process] = uint64(73)
	require.NoError(t, deauthorizeProcessCapability(processAuthorizationMaps{
		authorized: authorized, incarnations: incarnations,
	}, process, 41, true))
	assert.NotContains(t, authorized.values, process)
	assert.Equal(t, uint64(73), incarnations.values[process])
}

func TestDeauthorizeProcessCapabilityAcceptsReplacementAuthorization(t *testing.T) {
	process := Identity{TID: 7, PID: 7, Namespace: 11}
	authorized := &fakeBridgeMap{values: map[any]any{process: uint64(73)}}
	incarnations := &fakeBridgeMap{values: map[any]any{process: uint64(41)}}

	err := deauthorizeProcessCapability(processAuthorizationMaps{
		authorized: authorized, incarnations: incarnations,
	}, process, 41, false)

	require.NoError(t, err)
	assert.Equal(t, uint64(73), authorized.values[process])
	assert.Equal(t, uint64(41), incarnations.values[process])
}

func TestDeauthorizeProcessCapabilityAcceptsCommittedDeletionError(t *testing.T) {
	process := Identity{TID: 7, PID: 7, Namespace: 11}
	authorized := &fakeBridgeMap{
		values:          map[any]any{process: uint64(41)},
		deleteCommitErr: errors.New("reported after commit"),
	}
	incarnations := &fakeBridgeMap{values: map[any]any{process: uint64(41)}}

	err := deauthorizeProcessCapability(processAuthorizationMaps{
		authorized: authorized, incarnations: incarnations,
	}, process, 41, false)

	require.NoError(t, err)
	assert.NotContains(t, authorized.values, process)
	assert.Equal(t, uint64(41), incarnations.values[process])
}
