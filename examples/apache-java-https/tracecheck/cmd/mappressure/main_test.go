// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"syscall"
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
	assert.Zero(t, binary.LittleEndian.Uint32(first[0:4]))
	assert.Zero(t, binary.LittleEndian.Uint32(first[4:8]))
	assert.EqualValues(t, 700, binary.LittleEndian.Uint64(first[8:16]))
	assert.EqualValues(t, 701, binary.LittleEndian.Uint64(second[8:16]))
	assert.Equal(t, identity.incarnation, binary.LittleEndian.Uint64(first[16:24]))
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
	validVerify := validFill
	validVerify.mode = "verify"
	validVerify.expectedContentSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	tests := []struct {
		name    string
		cfg     config
		wantErr bool
	}{
		{name: "prepare", cfg: config{mode: "prepare", processPID: 101, processNamespace: 202}},
		{name: "fill", cfg: validFill},
		{name: "verify", cfg: validVerify},
		{name: "cleanup", cfg: validCleanup},
		{name: "invalid mode", cfg: config{mode: "invalid"}, wantErr: true},
		{name: "prepare missing process identity", cfg: config{mode: "prepare"}, wantErr: true},
		{name: "prepare partial process identity", cfg: config{mode: "prepare", processPID: 101}, wantErr: true},
		{name: "prepare map identity", cfg: config{mode: "prepare", mapID: 41, processPID: 101, processNamespace: 202}, wantErr: true},
		{name: "missing map ID", cfg: func() config { cfg := validFill; cfg.mapID = 0; return cfg }(), wantErr: true},
		{name: "missing capacity", cfg: func() config { cfg := validFill; cfg.expectedMaxEntries = 0; return cfg }(), wantErr: true},
		{name: "missing process map ID", cfg: func() config { cfg := validFill; cfg.expectedProcessMapID = 0; return cfg }(), wantErr: true},
		{name: "missing process PID", cfg: func() config { cfg := validFill; cfg.processPID = 0; return cfg }(), wantErr: true},
		{name: "missing process namespace", cfg: func() config { cfg := validFill; cfg.processNamespace = 0; return cfg }(), wantErr: true},
		{name: "missing token base", cfg: func() config { cfg := validFill; cfg.tokenBase = 0; return cfg }(), wantErr: true},
		{name: "verify missing digest", cfg: func() config { cfg := validVerify; cfg.expectedContentSHA256 = ""; return cfg }(), wantErr: true},
		{name: "verify uppercase digest", cfg: func() config {
			cfg := validVerify
			cfg.expectedContentSHA256 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			return cfg
		}(), wantErr: true},
		{name: "fill unexpected digest", cfg: func() config {
			cfg := validFill
			cfg.expectedContentSHA256 = validVerify.expectedContentSHA256
			return cfg
		}(), wantErr: true},
		{name: "cleanup process map ID", cfg: func() config { cfg := validCleanup; cfg.expectedProcessMapID = 42; return cfg }(), wantErr: true},
		{name: "capacity too large", cfg: config{mode: "fill", mapID: 41, expectedMaxEntries: maxPressureEntries + 1, expectedProcessMapID: 42, processPID: 101, processNamespace: 202, tokenBase: 700}, wantErr: true},
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
		MapType:          ebpf.Hash.String(),
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
			want: `{"status":"passed","mode":"prepare","map_id":41,"map_name":"java_remote_parent_handoff_claims","kernel_name":"java_remote_par","map_type":"Hash","max_entries":10,"process_map_id":42,"process_pid":101,"process_namespace":202,"token_base":18446744073709551605,"synthetic_pid":0,"synthetic_namespace":0,"touched":0}`,
		},
		{
			name: "fill",
			got: func() result {
				output := base
				output.Mode = "fill"
				output.Touched = 10
				output.CapacityRejectedEntries = 1
				output.VerifiedPresentEntries = 10
				output.ContentSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				output.VerifiedAbsentEntries = 1
				return output
			}(),
			want: `{"status":"passed","mode":"fill","map_id":41,"map_name":"java_remote_parent_handoff_claims","kernel_name":"java_remote_par","map_type":"Hash","max_entries":10,"process_map_id":42,"process_pid":101,"process_namespace":202,"token_base":18446744073709551605,"synthetic_pid":0,"synthetic_namespace":0,"touched":10,"capacity_rejected_entries":1,"verified_present_entries":10,"content_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","verified_absent_entries":1}`,
		},
		{
			name: "verify",
			got: func() result {
				output := base
				output.Mode = "verify"
				output.VerifiedPresentEntries = 10
				output.ContentSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				output.VerifiedAbsentEntries = 1
				return output
			}(),
			want: `{"status":"passed","mode":"verify","map_id":41,"map_name":"java_remote_parent_handoff_claims","kernel_name":"java_remote_par","map_type":"Hash","max_entries":10,"process_map_id":42,"process_pid":101,"process_namespace":202,"token_base":18446744073709551605,"synthetic_pid":0,"synthetic_namespace":0,"touched":0,"verified_present_entries":10,"content_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","verified_absent_entries":1}`,
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
			want: `{"status":"passed","mode":"cleanup","map_id":41,"map_name":"java_remote_parent_handoff_claims","kernel_name":"java_remote_par","map_type":"Hash","max_entries":10,"process_map_id":0,"process_pid":101,"process_namespace":202,"token_base":18446744073709551605,"synthetic_pid":0,"synthetic_namespace":0,"touched":9,"cleanup_verified":true,"verified_absent_entries":11}`,
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
	assert.EqualValues(t, 12345, binary.LittleEndian.Uint64(value[0:8])&^handoffOpenTag)
	assert.NotZero(t, binary.LittleEndian.Uint64(value[0:8])&handoffOpenTag)
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
		Type:       ebpf.Hash,
		KeySize:    targetKeySize,
		ValueSize:  targetValueSize,
		MaxEntries: 64,
		Name:       "java_remote_par",
	}
	require.NoError(t, validateTarget(valid, 64))

	wrongType := *valid
	wrongType.Type = ebpf.LRUHash
	require.Error(t, validateTarget(&wrongType, 64))
	require.Error(t, validateTarget(valid, 63))
}

func TestMatchesProcessMapRequiresExactIncarnationMapShape(t *testing.T) {
	valid := &ebpf.MapInfo{
		Type:       ebpf.Hash,
		KeySize:    processKeySize,
		ValueSize:  processValueSize,
		MaxEntries: 64,
		Name:       processKernelName,
	}
	assert.True(t, matchesProcessMap(valid))
	wrongType := *valid
	wrongType.Type = ebpf.LRUHash
	assert.False(t, matchesProcessMap(&wrongType))

	wrongKey := *valid
	wrongKey.KeySize++
	assert.False(t, matchesProcessMap(&wrongKey))
}

func TestMatchesTargetRejectsSameShapeMutationMap(t *testing.T) {
	claims := &ebpf.MapInfo{
		Type:       ebpf.Hash,
		KeySize:    targetKeySize,
		ValueSize:  targetValueSize,
		MaxEntries: 64,
		Name:       targetKernelName,
	}
	assert.True(t, matchesTarget(claims))

	mutation := *claims
	mutation.Name = "jrp_handoff_mut"
	assert.False(t, matchesTarget(&mutation))
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

type fakePressureMap struct {
	info       *ebpf.MapInfo
	infoErr    error
	lookup     func(key, value interface{}) error
	update     func(key, value interface{}, flags ebpf.MapUpdateFlags) error
	deleteKey  func(key interface{}) error
	closeCalls int
}

func (m *fakePressureMap) Info() (*ebpf.MapInfo, error) {
	return m.info, m.infoErr
}

func (m *fakePressureMap) Lookup(key, value interface{}) error {
	if m.lookup == nil {
		return ebpf.ErrKeyNotExist
	}
	return m.lookup(key, value)
}

func (m *fakePressureMap) Update(key, value interface{}, flags ebpf.MapUpdateFlags) error {
	if m.update == nil {
		return errors.New("unexpected map update")
	}
	return m.update(key, value, flags)
}

func (m *fakePressureMap) Delete(key interface{}) error {
	if m.deleteKey == nil {
		return ebpf.ErrKeyNotExist
	}
	return m.deleteKey(key)
}

func (m *fakePressureMap) Iterate() *ebpf.MapIterator {
	return nil
}

func (m *fakePressureMap) Close() error {
	m.closeCalls++
	return nil
}

func TestRunFillResultCarriesExactPreparedProcessEvidence(t *testing.T) {
	const (
		targetMapID  = ebpf.MapID(41)
		processMapID = ebpf.MapID(42)
		processPID   = uint32(101)
		processNS    = uint32(202)
		incarnation  = uint64(303)
		tokenBase    = uint64(700)
	)
	processes := &fakePressureMap{lookup: processIdentityLookup(incarnation)}
	target := &fakePressureMap{info: &ebpf.MapInfo{
		Type:       ebpf.Hash,
		KeySize:    targetKeySize,
		ValueSize:  targetValueSize,
		MaxEntries: 1,
		Name:       targetKernelName,
	}}
	var insertedKey [targetKeySize]byte
	var insertedValue [targetValueSize]byte
	updateCalls := 0
	target.update = func(key, value interface{}, flags ebpf.MapUpdateFlags) error {
		updateCalls++
		assert.Equal(t, ebpf.UpdateNoExist, flags)
		if updateCalls == 2 {
			return syscall.E2BIG
		}
		copy(insertedKey[:], key.([]byte))
		copy(insertedValue[:], value.([]byte))
		return nil
	}
	target.lookup = func(key, value interface{}) error {
		if !bytes.Equal(insertedKey[:], key.([]byte)) {
			return ebpf.ErrKeyNotExist
		}
		copy(value.(*[targetValueSize]byte)[:], insertedValue[:])
		return nil
	}

	output, err := runWithDependencies(
		config{
			mode:                 "fill",
			mapID:                uint(targetMapID),
			expectedMaxEntries:   1,
			expectedProcessMapID: uint(processMapID),
			processPID:           uint(processPID),
			processNamespace:     uint(processNS),
			tokenBase:            tokenBase,
		},
		runDependencies{
			openTargetMap: func(id ebpf.MapID) (targetMapHandle, ebpf.MapID, error) {
				assert.Equal(t, targetMapID, id)
				return target, id, nil
			},
			openProcessMap: func(id ebpf.MapID) (pressureMapHandle, ebpf.MapID, error) {
				assert.Equal(t, targetMapID, id)
				return processes, processMapID, nil
			},
			monotonicNowNS: func() (uint64, error) { return 12345, nil },
		},
	)

	require.NoError(t, err)
	digestInput := append(append([]byte{}, insertedKey[:]...), insertedValue[:]...)
	expectedContentSHA256 := fmt.Sprintf("%x", sha256.Sum256(digestInput))
	assert.Equal(t, result{
		Status:                  "passed",
		Mode:                    "fill",
		MapID:                   uint(targetMapID),
		MapName:                 targetMapName,
		KernelName:              targetKernelName,
		MapType:                 ebpf.Hash.String(),
		MaxEntries:              1,
		ProcessMapID:            uint(processMapID),
		ProcessPID:              processPID,
		ProcessNamespace:        processNS,
		TokenBase:               tokenBase,
		Touched:                 1,
		CapacityRejectedEntries: 1,
		VerifiedPresentEntries:  1,
		ContentSHA256:           expectedContentSHA256,
		VerifiedAbsentEntries:   1,
	}, output)
	assert.NotZero(t, output.ProcessMapID)
	assert.NotZero(t, output.ProcessPID)
	assert.NotZero(t, output.ProcessNamespace)
	assert.Zero(t, binary.LittleEndian.Uint32(insertedKey[0:4]))
	assert.Zero(t, binary.LittleEndian.Uint32(insertedKey[4:8]))
	assert.Equal(t, incarnation, binary.LittleEndian.Uint64(insertedKey[16:24]))
	assert.Equal(t, 2, updateCalls)
	assert.Equal(t, 1, target.closeCalls)
	assert.Equal(t, 1, processes.closeCalls)
}

func TestDiscoverPressureMapsScopesToUniqueLiveControlledJVMSet(t *testing.T) {
	processInfo := &ebpf.MapInfo{
		Type: ebpf.Hash, KeySize: processKeySize, ValueSize: processValueSize,
		Name: processKernelName,
	}
	unrelatedInfo := &ebpf.MapInfo{Type: ebpf.Array, KeySize: 4, ValueSize: 8, Name: "other"}
	orphan := &fakePressureMap{info: processInfo}
	unrelated := &fakePressureMap{info: unrelatedInfo}
	selected := &fakePressureMap{info: processInfo}
	target := &fakePressureMap{info: &ebpf.MapInfo{
		Type: ebpf.Hash, KeySize: targetKeySize, ValueSize: targetValueSize,
		Name: targetKernelName,
	}}
	var lookedUpKeys [][processKeySize]byte
	lookup := func(key, value interface{}) error {
		gotKey := key.([processKeySize]byte)
		lookedUpKeys = append(lookedUpKeys, gotKey)
		binary.LittleEndian.PutUint64(value.(*[processValueSize]byte)[:], 303)
		return nil
	}
	orphan.lookup = lookup
	selected.lookup = lookup
	discovery := pressureMapDiscovery{
		nextMapID: mapIDSequence(10, 20, 30),
		openMap: func(id ebpf.MapID) (pressureMapHandle, error) {
			switch id {
			case 10:
				return orphan, nil
			case 20:
				return unrelated, nil
			case 30:
				return selected, nil
			default:
				return nil, os.ErrNotExist
			}
		},
		relatedTarget: func(id ebpf.MapID) (pressureMapHandle, ebpf.MapID, error) {
			if id == 10 {
				return nil, 0, fmt.Errorf("%w: map ID %d", errMapNotReferenced, id)
			}
			require.Equal(t, ebpf.MapID(30), id)
			return target, 31, nil
		},
	}

	processes, processID, claims, claimsID, identity, err :=
		discoverPressureMapsForIdentity(discovery, 101, 202)

	require.NoError(t, err)
	assert.Same(t, selected, processes)
	assert.Equal(t, ebpf.MapID(30), processID)
	assert.Same(t, target, claims)
	assert.Equal(t, ebpf.MapID(31), claimsID)
	assert.Equal(t, processIdentity{pid: 101, namespace: 202, incarnation: 303}, identity)
	require.Len(t, lookedUpKeys, 3)
	for _, key := range lookedUpKeys {
		assert.EqualValues(t, 101, binary.LittleEndian.Uint32(key[0:4]))
		assert.EqualValues(t, 101, binary.LittleEndian.Uint32(key[4:8]))
		assert.EqualValues(t, 202, binary.LittleEndian.Uint32(key[8:12]))
	}
	assert.Equal(t, 1, orphan.closeCalls)
	assert.Equal(t, 1, unrelated.closeCalls)
	assert.Zero(t, selected.closeCalls)
	assert.Zero(t, target.closeCalls)
	require.NoError(t, processes.Close())
	require.NoError(t, claims.Close())
}

func TestDiscoverPressureMapsRejectsMultipleLiveControlledJVMSets(t *testing.T) {
	processInfo := &ebpf.MapInfo{
		Type: ebpf.Hash, KeySize: processKeySize, ValueSize: processValueSize,
		Name: processKernelName,
	}
	first := &fakePressureMap{info: processInfo, lookup: processIdentityLookup(303)}
	second := &fakePressureMap{info: processInfo, lookup: processIdentityLookup(404)}
	firstTarget := &fakePressureMap{info: &ebpf.MapInfo{Name: targetKernelName}}
	secondTarget := &fakePressureMap{info: &ebpf.MapInfo{Name: targetKernelName}}
	discovery := pressureMapDiscovery{
		nextMapID: mapIDSequence(10, 20),
		openMap: func(id ebpf.MapID) (pressureMapHandle, error) {
			if id == 10 {
				return first, nil
			}
			return second, nil
		},
		relatedTarget: func(id ebpf.MapID) (pressureMapHandle, ebpf.MapID, error) {
			if id == 10 {
				return firstTarget, 11, nil
			}
			return secondTarget, 21, nil
		},
	}

	_, _, _, _, _, err := discoverPressureMapsForIdentity(discovery, 101, 202)

	require.EqualError(t, err, "multiple live map sets contain the controlled JVM")
	assert.Equal(t, 1, first.closeCalls)
	assert.Equal(t, 1, second.closeCalls)
	assert.Equal(t, 1, firstTarget.closeCalls)
	assert.Equal(t, 1, secondTarget.closeCalls)
}

func TestDiscoverPressureMapsRejectsIdentityChangeBeforeReturn(t *testing.T) {
	process := &fakePressureMap{info: &ebpf.MapInfo{
		Type: ebpf.Hash, KeySize: processKeySize, ValueSize: processValueSize,
		Name: processKernelName,
	}}
	lookupCalls := 0
	process.lookup = func(key, value interface{}) error {
		lookupCalls++
		incarnation := uint64(303)
		if lookupCalls > 1 {
			incarnation = 404
		}
		return processIdentityLookup(incarnation)(key, value)
	}
	target := &fakePressureMap{info: &ebpf.MapInfo{Name: targetKernelName}}
	discovery := pressureMapDiscovery{
		nextMapID: mapIDSequence(10),
		openMap: func(ebpf.MapID) (pressureMapHandle, error) {
			return process, nil
		},
		relatedTarget: func(ebpf.MapID) (pressureMapHandle, ebpf.MapID, error) {
			return target, 11, nil
		},
	}

	_, _, _, _, _, err := discoverPressureMapsForIdentity(discovery, 101, 202)

	require.EqualError(t, err, "controlled JVM identity changed during map discovery")
	assert.Equal(t, 1, process.closeCalls)
	assert.Equal(t, 1, target.closeCalls)
}

func mapIDSequence(ids ...ebpf.MapID) func(ebpf.MapID) (ebpf.MapID, error) {
	return func(current ebpf.MapID) (ebpf.MapID, error) {
		for _, id := range ids {
			if id > current {
				return id, nil
			}
		}
		return 0, os.ErrNotExist
	}
}

func processIdentityLookup(incarnation uint64) func(key, value interface{}) error {
	return func(key, value interface{}) error {
		got := key.([processKeySize]byte)
		if binary.LittleEndian.Uint32(got[0:4]) != 101 ||
			binary.LittleEndian.Uint32(got[4:8]) != 101 ||
			binary.LittleEndian.Uint32(got[8:12]) != 202 {
			return ebpf.ErrKeyNotExist
		}
		binary.LittleEndian.PutUint64(value.(*[processValueSize]byte)[:], incarnation)
		return nil
	}
}

func TestVerifySyntheticEntriesRequiresExactContentAndRejectedKeyAbsence(t *testing.T) {
	identity := processIdentity{pid: 101, namespace: 202, incarnation: 303}
	tokenBase := uint64(700)

	present, absent, digest, err := verifySyntheticEntries(
		identity,
		tokenBase,
		3,
		func(key []byte, value *[targetValueSize]byte) error {
			index := binary.LittleEndian.Uint64(key[8:16]) - tokenBase
			if index >= 3 {
				return ebpf.ErrKeyNotExist
			}
			copy(value[:], claimValue(12345+index, identity.incarnation))
			return nil
		},
	)

	require.NoError(t, err)
	assert.EqualValues(t, 3, present)
	assert.EqualValues(t, 1, absent)
	assert.Regexp(t, `^[0-9a-f]{64}$`, digest)

	_, _, _, err = verifySyntheticEntries(
		identity,
		tokenBase,
		3,
		func(key []byte, value *[targetValueSize]byte) error {
			if binary.LittleEndian.Uint64(key[8:16]) == tokenBase+1 {
				return fmt.Errorf("lookup: %w", ebpf.ErrKeyNotExist)
			}
			copy(value[:], claimValue(12345, identity.incarnation))
			return nil
		},
	)
	require.EqualError(t, err, "synthetic entry 1 was evicted")

	_, _, _, err = verifySyntheticEntries(
		identity,
		tokenBase,
		1,
		func(key []byte, value *[targetValueSize]byte) error {
			copy(value[:], claimValue(12345, identity.incarnation))
			return nil
		},
	)
	require.EqualError(t, err, "capacity-plus-one synthetic entry became present")

	_, _, _, err = verifySyntheticEntries(
		identity,
		tokenBase,
		1,
		func(key []byte, value *[targetValueSize]byte) error {
			if binary.LittleEndian.Uint64(key[8:16]) > tokenBase {
				return ebpf.ErrKeyNotExist
			}
			copy(value[:], claimValue(12345, 404))
			return nil
		},
	)
	require.EqualError(t, err, "synthetic entry 0 changed")
}

func TestVerifySyntheticEntriesRejectsLookupErrors(t *testing.T) {
	lookupErr := errors.New("lookup failed")
	lookupCount := 0
	_, _, _, err := verifySyntheticEntries(
		processIdentity{pid: 101, namespace: 202, incarnation: 303},
		700,
		4,
		func([]byte, *[targetValueSize]byte) error {
			lookupCount++
			return lookupErr
		},
	)

	require.ErrorIs(t, err, lookupErr)
}

func TestCapacityRejectionRecognizesOnlyKernelHashMapCapacityError(t *testing.T) {
	assert.True(t, isCapacityRejection(fmt.Errorf("update: %w", syscall.E2BIG)))
	assert.False(t, isCapacityRejection(fmt.Errorf("update: %w", syscall.ENOSPC)))
	assert.False(t, isCapacityRejection(ebpf.ErrKeyExist))
}

func TestCleanupSyntheticEntriesUsesFullLiveIncarnationKeys(t *testing.T) {
	identity := processIdentity{pid: 101, namespace: 202}
	matchingIdentity := processIdentity{pid: 101, namespace: 202, incarnation: 303}
	otherIncarnation := processIdentity{pid: 101, namespace: 202, incarnation: 404}
	realProcessEntry := targetEntryForTest(
		processIdentity{pid: 102, namespace: 202, incarnation: 303}, 700,
	)
	binary.LittleEndian.PutUint32(realProcessEntry.key[0:4], 102)
	binary.LittleEndian.PutUint32(realProcessEntry.key[4:8], 202)
	entries := []targetEntry{
		targetEntryForTest(matchingIdentity, 700),
		targetEntryForTest(otherIncarnation, 701),
		targetEntryForTest(otherIncarnation, 699),
		targetEntryForTest(otherIncarnation, 703),
		realProcessEntry,
	}
	deleted := make(map[[targetKeySize]byte]struct{})
	collect := func() ([]targetEntry, error) {
		remaining := make([]targetEntry, 0, len(entries))
		for _, entry := range entries {
			if _, found := deleted[entry.key]; !found {
				remaining = append(remaining, entry)
			}
		}
		return remaining, nil
	}

	touched, verified, err := cleanupSyntheticEntries(
		identity,
		700,
		3,
		collect,
		func(key []byte) error {
			var exact [targetKeySize]byte
			copy(exact[:], key)
			deleted[exact] = struct{}{}
			return nil
		},
	)

	require.NoError(t, err)
	assert.EqualValues(t, 2, touched)
	assert.EqualValues(t, 3, verified)
	assert.Len(t, deleted, 2)
	assert.NotContains(t, deleted, entries[2].key)
	assert.NotContains(t, deleted, entries[3].key)
	assert.NotContains(t, deleted, entries[4].key)
}

func TestCleanupSyntheticEntriesRemovesCorruptedOwnedEntry(t *testing.T) {
	identity := processIdentity{pid: 101, namespace: 202}
	valid := targetEntryForTest(
		processIdentity{pid: 101, namespace: 202, incarnation: 303}, 700,
	)
	tests := map[string]func(*targetEntry){
		"zero key incarnation": func(entry *targetEntry) {
			binary.LittleEndian.PutUint64(entry.key[16:24], 0)
		},
		"mismatched value incarnation": func(entry *targetEntry) {
			binary.LittleEndian.PutUint64(entry.value[8:16], 404)
		},
		"closed ticket": func(entry *targetEntry) {
			binary.LittleEndian.PutUint64(entry.value[0:8], 12345)
		},
		"open tag without monotime": func(entry *targetEntry) {
			binary.LittleEndian.PutUint64(entry.value[0:8], handoffOpenTag)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			invalid := valid
			mutate(&invalid)
			deleteCalled := false

			touched, verified, err := cleanupSyntheticEntries(
				identity,
				700,
				3,
				func() ([]targetEntry, error) {
					if deleteCalled {
						return nil, nil
					}
					return []targetEntry{invalid}, nil
				},
				func([]byte) error { deleteCalled = true; return nil },
			)

			require.NoError(t, err)
			assert.EqualValues(t, 1, touched)
			assert.EqualValues(t, 3, verified)
			assert.True(t, deleteCalled)
		})
	}
}

func targetEntryForTest(identity processIdentity, token uint64) targetEntry {
	var entry targetEntry
	copy(entry.key[:], syntheticKey(identity, token, 0))
	copy(entry.value[:], claimValue(12345, identity.incarnation))
	return entry
}
