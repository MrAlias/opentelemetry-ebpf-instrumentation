// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
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
	const entryCount = uint32(maxPressureEntries + 1)
	base, err := newTokenBase(7, entryCount)
	require.NoError(t, err)
	require.NoError(t, validateTokenBase(base, entryCount))
	assert.NotZero(t, base)
	assert.Greater(t, syntheticToken(base, maxPressureEntries), base)

	maximumSafeBase := ^uint64(0) - uint64(entryCount-1)
	require.NoError(t, validateTokenBase(maximumSafeBase, entryCount))
	assert.Equal(t, ^uint64(0), syntheticToken(maximumSafeBase, entryCount-1))
	require.NoError(t, validateTokenBase((^uint64(0)>>1)+1, entryCount))
	require.Error(t, validateTokenBase(maximumSafeBase+1, entryCount))
	require.Error(t, validateTokenBase(0, entryCount))
	require.Error(t, validateTokenBase(1, 0))
	_, err = newTokenBase(7, 0)
	require.Error(t, err)
}

func TestValidateConfigRequiresModeSpecificIdentity(t *testing.T) {
	validFill := config{
		mode:                 "fill",
		mapID:                41,
		expectedMaxEntries:   10,
		expectedProcessMapID: 42,
		processPID:           101,
		processNamespace:     202,
		tokenBase:            700,
	}
	validCleanup := config{
		mode:               "cleanup",
		mapID:              41,
		expectedMaxEntries: 10,
		processPID:         101,
		processNamespace:   202,
		tokenBase:          700,
	}

	tests := []struct {
		name    string
		cfg     config
		wantErr bool
	}{
		{name: "prepare", cfg: config{mode: "prepare"}},
		{name: "fill", cfg: validFill},
		{name: "cleanup", cfg: validCleanup},
		{name: "invalid mode", cfg: config{mode: "invalid"}, wantErr: true},
		{name: "prepare map identity", cfg: config{mode: "prepare", mapID: 41}, wantErr: true},
		{name: "prepare process identity", cfg: config{mode: "prepare", processPID: 101}, wantErr: true},
		{name: "missing map ID", cfg: func() config { cfg := validFill; cfg.mapID = 0; return cfg }(), wantErr: true},
		{name: "missing capacity", cfg: func() config { cfg := validFill; cfg.expectedMaxEntries = 0; return cfg }(), wantErr: true},
		{name: "missing process map ID", cfg: func() config { cfg := validFill; cfg.expectedProcessMapID = 0; return cfg }(), wantErr: true},
		{name: "missing process PID", cfg: func() config { cfg := validFill; cfg.processPID = 0; return cfg }(), wantErr: true},
		{name: "missing process namespace", cfg: func() config { cfg := validFill; cfg.processNamespace = 0; return cfg }(), wantErr: true},
		{name: "missing token base", cfg: func() config { cfg := validFill; cfg.tokenBase = 0; return cfg }(), wantErr: true},
		{name: "cleanup process map ID", cfg: func() config { cfg := validCleanup; cfg.expectedProcessMapID = 42; return cfg }(), wantErr: true},
		{name: "capacity too large", cfg: config{mode: "prepare", expectedMaxEntries: maxPressureEntries + 1}, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateConfig(test.cfg)
			if test.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestValidateConfigRejectsValuesThatExceedMapABI(t *testing.T) {
	if uint64(^uint(0)) <= uint64(^uint32(0)) {
		t.Skip("uint is not wider than the eBPF map ABI")
	}
	maximumMapID := uint64(^uint32(0))
	overflow := uint(maximumMapID + 1)
	base := config{
		mode:                 "fill",
		mapID:                41,
		expectedMaxEntries:   10,
		expectedProcessMapID: 42,
		processPID:           101,
		processNamespace:     202,
		tokenBase:            700,
	}

	cfg := base
	cfg.mapID = overflow
	require.EqualError(t, validateConfig(cfg), "map-id exceeds 32 bits")
	cfg = base
	cfg.expectedProcessMapID = overflow
	require.EqualError(t, validateConfig(cfg), "expected-process-map-id exceeds 32 bits")
	cfg = base
	cfg.processPID = overflow
	require.EqualError(t, validateConfig(cfg), "process-pid exceeds 32 bits")
	cfg = base
	cfg.processNamespace = overflow
	require.EqualError(t, validateConfig(cfg), "process-namespace exceeds 32 bits")
}

func TestValidatePreparedProcessIdentityRequiresExactMatch(t *testing.T) {
	identity := processIdentity{pid: 101, namespace: 202, incarnation: 303}
	require.NoError(t, validatePreparedProcessIdentity(101, 202, identity))
	require.Error(t, validatePreparedProcessIdentity(102, 202, identity))
	require.Error(t, validatePreparedProcessIdentity(101, 203, identity))
}

func TestValidatePreparedProcessMapIDRequiresExactMatch(t *testing.T) {
	require.NoError(t, validatePreparedProcessMapID(42, 42))
	require.Error(t, validatePreparedProcessMapID(42, 43))
}

func TestResultJSONLocksModeSpecificEvidenceSchema(t *testing.T) {
	base := result{
		Status:           "passed",
		MapID:            41,
		MapName:          targetMapName,
		KernelName:       targetKernelName,
		MapType:          ebpf.LRUHash.String(),
		MaxEntries:       10,
		ProcessMapID:     42,
		ProcessPID:       101,
		ProcessNamespace: 202,
		TokenBase:        ^uint64(0) - 10,
	}
	tests := []struct {
		name string
		got  result
		want string
	}{
		{
			name: "prepare",
			got:  func() result { output := base; output.Mode = "prepare"; return output }(),
			want: `{"status":"passed","mode":"prepare","map_id":41,"map_name":"java_remote_parent_handoff_claims","kernel_name":"java_remote_par","map_type":"LRUHash","max_entries":10,"process_map_id":42,"process_pid":101,"process_namespace":202,"token_base":18446744073709551605,"touched":0}`,
		},
		{
			name: "fill",
			got: func() result {
				output := base
				output.Mode = "fill"
				output.Touched = 11
				output.EvictedEntries = 2
				return output
			}(),
			want: `{"status":"passed","mode":"fill","map_id":41,"map_name":"java_remote_parent_handoff_claims","kernel_name":"java_remote_par","map_type":"LRUHash","max_entries":10,"process_map_id":42,"process_pid":101,"process_namespace":202,"token_base":18446744073709551605,"touched":11,"evicted_entries":2}`,
		},
		{
			name: "cleanup",
			got: func() result {
				output := base
				output.Mode = "cleanup"
				output.ProcessMapID = 0
				output.Touched = 9
				output.CleanupVerified = true
				output.VerifiedAbsentEntries = 11
				return output
			}(),
			want: `{"status":"passed","mode":"cleanup","map_id":41,"map_name":"java_remote_parent_handoff_claims","kernel_name":"java_remote_par","map_type":"LRUHash","max_entries":10,"process_map_id":0,"process_pid":101,"process_namespace":202,"token_base":18446744073709551605,"touched":9,"cleanup_verified":true,"verified_absent_entries":11}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			encoded, err := json.Marshal(test.got)
			require.NoError(t, err)
			assert.Equal(t, test.want, string(encoded))
		})
	}
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

func TestAddRelatedMapIDsIncludesOnlyTargetPrograms(t *testing.T) {
	targetID := ebpf.MapID(41)
	processMapID := ebpf.MapID(42)
	unrelatedProcessMapID := ebpf.MapID(43)
	related := make(map[ebpf.MapID]struct{})

	assert.False(t, addRelatedMapIDs(targetID, []ebpf.MapID{44, unrelatedProcessMapID}, related))
	assert.True(t, addRelatedMapIDs(targetID, []ebpf.MapID{targetID, processMapID}, related))
	assert.Equal(t, map[ebpf.MapID]struct{}{targetID: {}, processMapID: {}}, related)
}

func TestSelectRelatedMapIDIgnoresUnrelatedProcessMaps(t *testing.T) {
	targetID := ebpf.MapID(41)
	processMapID := ebpf.MapID(42)
	unrelatedProcessMapID := ebpf.MapID(43)
	related := map[ebpf.MapID]struct{}{targetID: {}, processMapID: {}}

	selected, err := selectRelatedMapID(
		targetID,
		related,
		[]ebpf.MapID{unrelatedProcessMapID, processMapID},
	)

	require.NoError(t, err)
	assert.Equal(t, processMapID, selected)
}

func TestSelectRelatedMapIDRejectsAmbiguousProgramRelatedProcessMaps(t *testing.T) {
	targetID := ebpf.MapID(41)
	related := map[ebpf.MapID]struct{}{
		targetID:       {},
		ebpf.MapID(42): {},
		ebpf.MapID(43): {},
	}

	_, err := selectRelatedMapID(targetID, related, []ebpf.MapID{42, 43})

	require.EqualError(t, err, "multiple process maps are related to target map ID 41")
}

func TestSelectRelatedMapIDRejectsMissingProgramRelatedProcessMap(t *testing.T) {
	_, err := selectRelatedMapID(
		ebpf.MapID(41),
		map[ebpf.MapID]struct{}{ebpf.MapID(41): {}},
		[]ebpf.MapID{42},
	)

	require.EqualError(t, err, "no process map is related to target map ID 41")
}

func TestCountEvictedSyntheticEntriesAcceptsAnyMissingKey(t *testing.T) {
	identity := processIdentity{pid: 101, namespace: 202}
	tokenBase := uint64(700)

	evicted, err := countEvictedSyntheticEntries(
		identity,
		tokenBase,
		5,
		func(key []byte) error {
			token := binary.LittleEndian.Uint64(key[8:16])
			if token == tokenBase+2 || token == tokenBase+3 {
				return ebpf.ErrKeyNotExist
			}
			return nil
		},
	)

	require.NoError(t, err)
	assert.EqualValues(t, 2, evicted)
}

func TestCountEvictedSyntheticEntriesAcceptsWrappedMissingKey(t *testing.T) {
	evicted, err := countEvictedSyntheticEntries(
		processIdentity{pid: 101, namespace: 202},
		700,
		1,
		func([]byte) error { return fmt.Errorf("lookup: %w", ebpf.ErrKeyNotExist) },
	)

	require.NoError(t, err)
	assert.EqualValues(t, 1, evicted)
}

func TestCountEvictedSyntheticEntriesRequiresAnEviction(t *testing.T) {
	_, err := countEvictedSyntheticEntries(
		processIdentity{pid: 101, namespace: 202},
		700,
		4,
		func([]byte) error { return nil },
	)

	require.EqualError(t, err, "no synthetic entries were evicted")
}

func TestCountEvictedSyntheticEntriesRejectsLookupErrors(t *testing.T) {
	lookupErr := errors.New("lookup failed")
	lookupCount := 0
	_, err := countEvictedSyntheticEntries(
		processIdentity{pid: 101, namespace: 202},
		700,
		4,
		func([]byte) error {
			lookupCount++
			if lookupCount == 1 {
				return ebpf.ErrKeyNotExist
			}
			return lookupErr
		},
	)

	require.ErrorIs(t, err, lookupErr)
}

func TestVerifySyntheticEntriesAbsentRequiresEveryKeyMissing(t *testing.T) {
	identity := processIdentity{pid: 101, namespace: 202}
	verified, err := verifySyntheticEntriesAbsent(
		identity,
		700,
		3,
		func([]byte) error { return ebpf.ErrKeyNotExist },
	)
	require.NoError(t, err)
	assert.EqualValues(t, 3, verified)

	_, err = verifySyntheticEntriesAbsent(
		identity,
		700,
		3,
		func(key []byte) error {
			if binary.LittleEndian.Uint64(key[8:16]) == 701 {
				return nil
			}
			return ebpf.ErrKeyNotExist
		},
	)
	require.EqualError(t, err, "synthetic entry 1 remains after cleanup")
}

func TestVerifySyntheticEntriesAbsentRejectsLookupErrors(t *testing.T) {
	lookupErr := errors.New("lookup failed")
	_, err := verifySyntheticEntriesAbsent(
		processIdentity{pid: 101, namespace: 202},
		700,
		1,
		func([]byte) error { return lookupErr },
	)

	require.ErrorIs(t, err, lookupErr)
}
