// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeIterator struct {
	remaining int
	err       error
}

func (iterator *fakeIterator) Next(_, _ interface{}) bool {
	if iterator.remaining == 0 {
		return false
	}
	iterator.remaining--
	return true
}

func (iterator *fakeIterator) Err() error {
	return iterator.err
}

func TestValidateConfigRequiresBothExactRediscoveryIdentities(t *testing.T) {
	require.NoError(t, validateConfig(config{}))
	require.NoError(t, validateConfig(config{
		cursorMapID:        41,
		guardMapID:         42,
		expectedMaxEntries: targetMaxEntries,
	}))

	invalid := []struct {
		cfg config
		err string
	}{
		{config{cursorMapID: 41}, "cursor-map-id and guard-map-id must be provided together"},
		{config{guardMapID: 42}, "cursor-map-id and guard-map-id must be provided together"},
		{config{cursorMapID: 41, guardMapID: 41, expectedMaxEntries: targetMaxEntries}, "cursor-map-id and guard-map-id must be distinct"},
		{config{expectedMaxEntries: targetMaxEntries}, "expected-max-entries requires both map IDs"},
		{config{cursorMapID: 41, guardMapID: 42}, "both map IDs require expected-max-entries"},
		{config{cursorMapID: 41, guardMapID: 42, expectedMaxEntries: targetMaxEntries - 1}, "expected-max-entries must be 10000"},
	}
	for _, test := range invalid {
		require.EqualError(t, validateConfig(test.cfg), test.err)
	}
}

func TestValidateConfigRejectsValuesOutsideTheMapABI(t *testing.T) {
	if uint64(^uint(0)) <= uint64(^uint32(0)) {
		t.Skip("uint is not wider than the eBPF map ABI")
	}
	overflow := uint(uint64(^uint32(0)) + 1)
	require.EqualError(t, validateConfig(config{cursorMapID: overflow}), "cursor-map-id exceeds 32 bits")
	require.EqualError(t, validateConfig(config{guardMapID: overflow}), "guard-map-id exceeds 32 bits")
	require.EqualError(
		t,
		validateConfig(config{expectedMaxEntries: overflow}),
		"expected-max-entries exceeds 32 bits",
	)
}

func TestValidateTargetRequiresEachExactMapShape(t *testing.T) {
	for _, target := range []targetShape{cursorTarget, guardTarget} {
		valid := &ebpf.MapInfo{
			Type:       ebpf.Hash,
			KeySize:    targetKeySize,
			ValueSize:  targetValueSize,
			MaxEntries: targetMaxEntries,
			Name:       target.name,
		}
		require.NoError(t, validateTarget(valid, target, targetMaxEntries))

		mutations := []func(*ebpf.MapInfo){
			func(info *ebpf.MapInfo) { info.Type = ebpf.LRUHash },
			func(info *ebpf.MapInfo) { info.KeySize++ },
			func(info *ebpf.MapInfo) { info.ValueSize++ },
			func(info *ebpf.MapInfo) { info.MaxEntries-- },
			func(info *ebpf.MapInfo) { info.Name = "wrong" },
		}
		for _, mutate := range mutations {
			candidate := *valid
			mutate(&candidate)
			require.Error(t, validateTarget(&candidate, target, targetMaxEntries))
		}
		require.Error(t, validateTarget(valid, target, targetMaxEntries-1))
	}
}

func TestCountIteratorEntriesIsBoundedAndPropagatesErrors(t *testing.T) {
	entries, err := countIteratorEntries(&fakeIterator{remaining: 3}, cursorTarget, 4)
	require.NoError(t, err)
	assert.EqualValues(t, 3, entries)

	_, err = countIteratorEntries(&fakeIterator{remaining: 5}, guardTarget, 4)
	require.EqualError(t, err, "jrp_recv_guard map iteration exceeded declared capacity 4")

	iterationError := errors.New("iteration failed")
	_, err = countIteratorEntries(&fakeIterator{err: iterationError}, cursorTarget, 4)
	require.ErrorIs(t, err, iterationError)

	_, err = countIteratorEntries(&fakeIterator{}, cursorTarget, 0)
	require.Error(t, err)
	_, err = countIteratorEntries(&fakeIterator{}, cursorTarget, maximumSnapshotKeys+1)
	require.Error(t, err)
}

func TestResultJSONLocksBothMapEvidenceSchemas(t *testing.T) {
	encoded, err := json.Marshal(result{
		Status: "passed",

		CursorMapID:      41,
		CursorMapName:    cursorMapName,
		CursorKernelName: cursorMapName,
		CursorMapType:    ebpf.Hash.String(),
		CursorKeySize:    targetKeySize,
		CursorValueSize:  targetValueSize,
		CursorMaxEntries: targetMaxEntries,
		CursorEntries:    2,

		GuardMapID:      42,
		GuardMapName:    guardMapName,
		GuardKernelName: guardMapName,
		GuardMapType:    ebpf.Hash.String(),
		GuardKeySize:    targetKeySize,
		GuardValueSize:  targetValueSize,
		GuardMaxEntries: targetMaxEntries,
		GuardEntries:    1,
	})
	require.NoError(t, err)
	assert.Equal(
		t,
		`{"status":"passed","cursor_map_id":41,"cursor_map_name":"jrp_recv_cur","cursor_kernel_name":"jrp_recv_cur","cursor_map_type":"Hash","cursor_key_size":8,"cursor_value_size":56,"cursor_max_entries":10000,"cursor_entries":2,"guard_map_id":42,"guard_map_name":"jrp_recv_guard","guard_kernel_name":"jrp_recv_guard","guard_map_type":"Hash","guard_key_size":8,"guard_value_size":56,"guard_max_entries":10000,"guard_entries":1}`,
		string(encoded),
	)
}
