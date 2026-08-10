// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/binary"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeProcessIdentityRequiresProcessKey(t *testing.T) {
	key := make([]byte, processKeySize)
	value := make([]byte, processValueSize)
	binary.LittleEndian.PutUint32(key[0:4], 41)
	binary.LittleEndian.PutUint32(key[4:8], 41)
	binary.LittleEndian.PutUint32(key[8:12], 7)
	binary.LittleEndian.PutUint64(value, 99)

	identity, err := decodeProcessIdentity(key, value)
	require.NoError(t, err)
	assert.Equal(t, processIdentity{pid: 41, namespace: 7, incarnation: 99}, identity)

	badThread := append([]byte(nil), key...)
	binary.LittleEndian.PutUint32(badThread[0:4], 42)
	_, err = decodeProcessIdentity(badThread, value)
	assert.Error(t, err)

	zeroIncarnation := make([]byte, processValueSize)
	_, err = decodeProcessIdentity(key, zeroIncarnation)
	assert.Error(t, err)
}

func TestProcessKeyMatchRequiresNamespaceQualifiedPID(t *testing.T) {
	key := make([]byte, processKeySize)
	binary.LittleEndian.PutUint32(key[0:4], 41)
	binary.LittleEndian.PutUint32(key[4:8], 41)
	binary.LittleEndian.PutUint32(key[8:12], 7)

	assert.True(t, processKeyMatches(key, 41, 7))
	assert.False(t, processKeyMatches(key, 42, 7))
	assert.False(t, processKeyMatches(key, 41, 8))
	assert.False(t, processKeyMatches(key[:processKeySize-1], 41, 7))
}

func TestGenerationTupleValidationIsExact(t *testing.T) {
	identity := processIdentity{pid: 41, namespace: 7, incarnation: 99}
	generation := uint64(1234)
	observed := uint64(5678)
	key := make([]byte, stateKeySize)
	binary.LittleEndian.PutUint32(key[0:4], 43)
	binary.LittleEndian.PutUint32(key[4:8], identity.pid)
	binary.LittleEndian.PutUint32(key[8:12], identity.namespace)
	binary.LittleEndian.PutUint64(key[16:24], generation)
	state := make([]byte, stateValueSize)
	state[0] = activeLifecycle
	binary.LittleEndian.PutUint64(state[stateObservedOffset:stateObservedOffset+8], observed)
	binary.LittleEndian.PutUint32(
		state[stateConnectionNetnsOffset:stateConnectionNetnsOffset+4],
		17,
	)
	binary.LittleEndian.PutUint64(
		state[stateProcessIncarnationOffset:stateProcessIncarnationOffset+8],
		identity.incarnation,
	)
	copy(state[responseOffset:responseOffset+4], responseMagic)
	binary.LittleEndian.PutUint16(state[responseVersionOffset:responseVersionOffset+2], 1)
	binary.LittleEndian.PutUint16(state[responseSizeOffset:responseSizeOffset+2], responseSize)
	state[responseStatusOffset] = 1
	state[responseTraceIDOffset] = 1
	state[responseSpanIDOffset] = 2
	binary.LittleEndian.PutUint64(state[responseGenerationOffset:responseGenerationOffset+8], generation)
	binary.LittleEndian.PutUint64(state[responseObservedOffset:responseObservedOffset+8], observed)

	owner := make([]byte, ownerValueSize)
	binary.LittleEndian.PutUint64(owner[ownerGenerationOffset:ownerGenerationOffset+8], generation)
	binary.LittleEndian.PutUint64(
		owner[ownerProcessIncarnationOffset:ownerProcessIncarnationOffset+8],
		identity.incarnation,
	)
	owner[ownerLifecycleOffset] = activeLifecycle

	index := make([]byte, indexValueSize)
	binary.LittleEndian.PutUint32(index[0:4], identity.pid)
	binary.LittleEndian.PutUint32(index[4:8], identity.pid)
	binary.LittleEndian.PutUint32(index[8:12], identity.namespace)
	binary.LittleEndian.PutUint64(
		index[indexProcessIncarnationOffset:indexProcessIncarnationOffset+8],
		identity.incarnation,
	)
	binary.LittleEndian.PutUint64(index[indexObservedOffset:indexObservedOffset+8], observed)

	assert.True(t, validState(key, state, identity))
	assert.True(t, validOwner(owner, key, identity))
	assert.True(t, validIndex(index, state, identity))

	wrongGeneration := append([]byte(nil), state...)
	binary.LittleEndian.PutUint64(
		wrongGeneration[responseGenerationOffset:responseGenerationOffset+8],
		generation+1,
	)
	assert.False(t, validState(key, wrongGeneration, identity))

	wrongReserved := append([]byte(nil), state...)
	wrongReserved[responseReservedPrefixOffset] = 1
	assert.False(t, validState(key, wrongReserved, identity))

	zeroTraceID := append([]byte(nil), state...)
	for offset := responseTraceIDOffset; offset < responseSpanIDOffset; offset++ {
		zeroTraceID[offset] = 0
	}
	assert.False(t, validState(key, zeroTraceID, identity))

	aliasedState := append([]byte(nil), state...)
	binary.LittleEndian.PutUint32(
		aliasedState[stateAliasesOffset:stateAliasesOffset+4],
		1,
	)
	assert.False(t, validState(key, aliasedState, identity))

	wrongOwnerLifecycle := append([]byte(nil), owner...)
	wrongOwnerLifecycle[ownerLifecycleOffset] = 2
	assert.False(t, validOwner(wrongOwnerLifecycle, key, identity))

	wrongIndexObservation := append([]byte(nil), index...)
	binary.LittleEndian.PutUint64(
		wrongIndexObservation[indexObservedOffset:indexObservedOffset+8],
		observed+1,
	)
	assert.False(t, validIndex(wrongIndexObservation, state, identity))
}

func TestFaultGenerationIsDistinctAndNonzero(t *testing.T) {
	for _, original := range []uint64{1, faultGenerationMask, math.MaxUint64} {
		mutated, ok := faultGeneration(original)
		assert.True(t, ok)
		assert.NotZero(t, mutated)
		assert.NotEqual(t, original, mutated)
	}
}

func TestMapShapeIncludesTypeLayoutNameAndBound(t *testing.T) {
	processes := &ebpf.MapInfo{
		Type:       ebpf.Hash,
		KeySize:    processKeySize,
		ValueSize:  processValueSize,
		MaxEntries: 10_000,
		Name:       processMapName,
	}
	assert.True(t, matchesMap(
		processes,
		ebpf.Hash,
		processKeySize,
		processValueSize,
		processMapName,
	))

	evictingProcesses := *processes
	evictingProcesses.Type = ebpf.LRUHash
	assert.False(t, matchesMap(
		&evictingProcesses,
		ebpf.Hash,
		processKeySize,
		processValueSize,
		processMapName,
	))

	valid := &ebpf.MapInfo{
		Type:       ebpf.Hash,
		KeySize:    stateKeySize,
		ValueSize:  stateValueSize,
		MaxEntries: 10_000,
		Name:       kernelMapName,
	}
	assert.True(t, matchesMap(valid, ebpf.Hash, stateKeySize, stateValueSize, kernelMapName))

	wrongName := *valid
	wrongName.Name = "wrong"
	assert.False(t, matchesMap(&wrongName, ebpf.Hash, stateKeySize, stateValueSize, kernelMapName))

	unbounded := *valid
	unbounded.MaxEntries = maximumEntries + 1
	assert.False(t, matchesMap(&unbounded, ebpf.Hash, stateKeySize, stateValueSize, kernelMapName))
}

func TestControlDirectoryAndReleaseAreExact(t *testing.T) {
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, controlDirectoryMode))
	owner := uint32(os.Getuid())
	require.NoError(t, validateControlDirectory(directory, owner))
	assert.Error(t, validateControlDirectory(directory, owner+1))

	require.NoError(t, os.Chmod(directory, 0o750))
	assert.Error(t, validateControlDirectory(directory, owner))
	require.NoError(t, os.Chmod(directory, controlDirectoryMode))

	symlink := filepath.Join(filepath.Dir(directory), "generation-control-link")
	require.NoError(t, os.Symlink(directory, symlink))
	assert.Error(t, validateControlDirectory(symlink, owner))

	require.NoError(t, writeControlState(directory, "armed", owner))
	contents, err := os.ReadFile(filepath.Join(directory, "armed"))
	require.NoError(t, err)
	assert.Equal(t, "armed\n", string(contents))
	assert.Error(t, writeControlState(directory, "armed", owner))
	assert.NoFileExists(t, filepath.Join(directory, ".armed.tmp"))
	assert.Error(t, writeControlState(directory, "../escape", owner))

	require.NoError(t, os.Remove(filepath.Join(directory, "armed")))
	require.NoError(t, os.WriteFile(
		filepath.Join(directory, ".armed.tmp"),
		[]byte("stale\n"),
		controlFileMode,
	))
	assert.Error(t, writeControlState(directory, "armed", owner))
	assert.NoFileExists(t, filepath.Join(directory, "armed"))
	require.NoError(t, os.Remove(filepath.Join(directory, ".armed.tmp")))
	require.NoError(t, writeControlState(directory, "armed", owner))

	release := filepath.Join(directory, "release")
	require.NoError(t, os.WriteFile(release, []byte("release\n"), controlFileMode))
	require.NoError(t, waitForRelease(directory, owner, 50*time.Millisecond))
	require.NoError(t, os.WriteFile(release, []byte("wrong\n"), controlFileMode))
	assert.Error(t, waitForRelease(directory, owner, 50*time.Millisecond))

	require.NoError(t, os.Remove(release))
	require.NoError(t, os.Symlink(filepath.Join(directory, "armed"), release))
	assert.Error(t, waitForRelease(directory, owner, 50*time.Millisecond))

	require.NoError(t, os.Remove(release))
	require.NoError(t, syscall.Mkfifo(release, controlFileMode))
	assert.Error(t, waitForRelease(directory, owner, 50*time.Millisecond))

	require.NoError(t, os.Remove(release))
	hardlinkSource := filepath.Join(directory, "release-source")
	require.NoError(t, os.WriteFile(hardlinkSource, []byte("release\n"), controlFileMode))
	require.NoError(t, os.Link(hardlinkSource, release))
	assert.Error(t, waitForRelease(directory, owner, 50*time.Millisecond))
}

func TestMutationAlwaysRestoresAfterWaitFailure(t *testing.T) {
	var order []string
	waitErr := errors.New("wait failed")
	mutated, restored, err := executeRestoredMutation(
		func() (bool, error) {
			order = append(order, "mutate")
			return true, nil
		},
		func() error {
			order = append(order, "wait")
			return waitErr
		},
		func() error {
			order = append(order, "restore")
			return nil
		},
	)
	assert.True(t, mutated)
	assert.True(t, restored)
	assert.ErrorIs(t, err, waitErr)
	assert.Equal(t, "mutate,wait,restore", strings.Join(order, ","))
}

func TestMutationReportsRestoreFailure(t *testing.T) {
	restoreErr := errors.New("restore failed")
	mutated, restored, err := executeRestoredMutation(
		func() (bool, error) { return true, nil },
		func() error { return nil },
		func() error { return restoreErr },
	)
	assert.True(t, mutated)
	assert.False(t, restored)
	assert.ErrorIs(t, err, restoreErr)
}

func TestMutationRestoresAfterPostWriteVerificationFailure(t *testing.T) {
	var order []string
	mutationErr := errors.New("post-write verification failed")
	mutated, restored, err := executeRestoredMutation(
		func() (bool, error) {
			order = append(order, "mutate")
			return true, mutationErr
		},
		func() error {
			order = append(order, "wait")
			return nil
		},
		func() error {
			order = append(order, "restore")
			return nil
		},
	)
	assert.True(t, mutated)
	assert.True(t, restored)
	assert.ErrorIs(t, err, mutationErr)
	assert.Equal(t, "mutate,restore", strings.Join(order, ","))
}

func TestPreWriteMutationFailureDoesNotRestore(t *testing.T) {
	mutationErr := errors.New("pre-write validation failed")
	restoredCalled := false
	mutated, restored, err := executeRestoredMutation(
		func() (bool, error) { return false, mutationErr },
		func() error { return nil },
		func() error {
			restoredCalled = true
			return nil
		},
	)
	assert.False(t, mutated)
	assert.False(t, restored)
	assert.False(t, restoredCalled)
	assert.ErrorIs(t, err, mutationErr)
}
