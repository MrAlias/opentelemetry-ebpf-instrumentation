// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSyntheticKeysAreBoundedAndDeterministic(t *testing.T) {
	identity := processIdentity{pid: 101, namespace: 202, incarnation: 303}
	first := syntheticKey(identity, 700, 0)
	repeated := syntheticKey(identity, 700, 0)
	second := syntheticKey(identity, 700, 1)

	require.Len(t, first, targetKeySize)
	assert.Equal(t, first, repeated)
	assert.NotEqual(t, first, second)
	assert.Equal(t, identity.pid, binary.LittleEndian.Uint32(first[0:4]))
	assert.Equal(t, identity.namespace, binary.LittleEndian.Uint32(first[4:8]))
	assert.EqualValues(t, 700, binary.LittleEndian.Uint64(first[8:16]))
	assert.EqualValues(t, 701, binary.LittleEndian.Uint64(second[8:16]))
}

func TestTokenBaseIsNonzeroAndCannotOverflowEntryRange(t *testing.T) {
	base, err := newTokenBase(7, maxPressureEntries+1)
	require.NoError(t, err)
	assert.NotZero(t, base)
	assert.Greater(t, syntheticToken(base, maxPressureEntries), base)
}

func TestClaimValueUsesFreshTimeAndLiveIncarnation(t *testing.T) {
	value := claimValue(12345, 67890)

	require.Len(t, value, targetValueSize)
	assert.EqualValues(t, 12345, binary.LittleEndian.Uint64(value[0:8]))
	assert.EqualValues(t, 67890, binary.LittleEndian.Uint64(value[8:16]))
}

func TestDecodeProcessIdentityRequiresLiveProcessKey(t *testing.T) {
	key := make([]byte, processKeySize)
	value := make([]byte, processValueSize)
	binary.LittleEndian.PutUint32(key[0:4], 101)
	binary.LittleEndian.PutUint32(key[4:8], 101)
	binary.LittleEndian.PutUint32(key[8:12], 202)
	binary.LittleEndian.PutUint64(value, 303)

	identity, err := decodeProcessIdentity(key, value)
	require.NoError(t, err)
	assert.Equal(t, processIdentity{pid: 101, namespace: 202, incarnation: 303}, identity)

	binary.LittleEndian.PutUint32(key[0:4], 102)
	require.Error(t, func() error {
		_, decodeErr := decodeProcessIdentity(key, value)
		return decodeErr
	}())
}

func TestValidateTargetRequiresExactHandoffClaimMapShape(t *testing.T) {
	valid := &ebpf.MapInfo{
		Type:       ebpf.LRUHash,
		KeySize:    targetKeySize,
		ValueSize:  targetValueSize,
		MaxEntries: 64,
		Name:       "java_remote_par",
	}
	require.NoError(t, validateTarget(valid, 64))

	wrongType := *valid
	wrongType.Type = ebpf.Hash
	require.Error(t, validateTarget(&wrongType, 64))
	require.Error(t, validateTarget(valid, 63))
}

func TestMatchesProcessMapRequiresExactIncarnationMapShape(t *testing.T) {
	valid := &ebpf.MapInfo{
		Type:       ebpf.LRUHash,
		KeySize:    processKeySize,
		ValueSize:  processValueSize,
		MaxEntries: 64,
		Name:       processKernelName,
	}
	assert.True(t, matchesProcessMap(valid))

	wrongKey := *valid
	wrongKey.KeySize++
	assert.False(t, matchesProcessMap(&wrongKey))
}
