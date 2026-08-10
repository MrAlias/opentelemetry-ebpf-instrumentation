// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	kernelMapName                 = "java_remote_par"
	processMapName                = "java_process_in"
	processKeySize                = 12
	processValueSize              = 8
	ownerKeySize                  = 12
	ownerValueSize                = 24
	stateKeySize                  = 24
	stateValueSize                = 128
	indexValueSize                = 32
	maximumEntries                = 50_000
	activeLifecycle               = 1
	responseOffset                = 64
	responseSize                  = 64
	responseVersionOffset         = responseOffset + 4
	responseSizeOffset            = responseOffset + 6
	responseStatusOffset          = responseOffset + 8
	responseReservedPrefixOffset  = responseOffset + 10
	responseTraceIDOffset         = responseOffset + 16
	responseSpanIDOffset          = responseOffset + 32
	responseGenerationOffset      = responseOffset + 40
	responseObservedOffset        = responseOffset + 48
	responseReservedSuffixOffset  = responseOffset + 56
	stateAliasesOffset            = 4
	stateObservedOffset           = 8
	stateConnectionNetnsOffset    = 52
	stateProcessIncarnationOffset = 56
	ownerGenerationOffset         = 0
	ownerProcessIncarnationOffset = 8
	ownerLifecycleOffset          = 16
	indexReservedOffset           = 12
	indexProcessIncarnationOffset = 16
	indexObservedOffset           = 24
	faultGenerationMask           = uint64(1) << 63
	controlFileMode               = 0o600
	controlDirectoryMode          = 0o700
	pollInterval                  = 10 * time.Millisecond
)

var responseMagic = []byte("OBIJ")

type config struct {
	processPID       uint
	processNamespace uint
	controlDir       string
	controlOwner     uint
	timeout          time.Duration
}

type output struct {
	Status   string `json:"status"`
	Mode     string `json:"mode"`
	Mutated  bool   `json:"mutated"`
	Restored bool   `json:"restored"`
}

type processIdentity struct {
	pid         uint32
	namespace   uint32
	incarnation uint64
}

type generationTarget struct {
	processMap    *ebpf.Map
	ownerMap      *ebpf.Map
	stateMap      *ebpf.Map
	indexMap      *ebpf.Map
	ownerKey      [ownerKeySize]byte
	stateKey      [stateKeySize]byte
	originalOwner [ownerValueSize]byte
	mutatedOwner  [ownerValueSize]byte
	stateValue    [stateValueSize]byte
	indexValue    [indexValueSize]byte
}

func main() {
	cfg, err := parseFlags()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	result, err := run(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fmt.Fprintln(os.Stderr, "encode bounded result")
		os.Exit(1)
	}
}

func parseFlags() (config, error) {
	var cfg config
	flag.UintVar(
		&cfg.processPID,
		"process-pid",
		0,
		"PID of the controlled JVM as seen in its PID namespace",
	)
	flag.UintVar(
		&cfg.processNamespace,
		"process-namespace",
		0,
		"kernel inode of the controlled JVM PID namespace",
	)
	flag.StringVar(&cfg.controlDir, "control-dir", "", "private mutation control directory")
	flag.UintVar(&cfg.controlOwner, "control-owner", 0, "numeric owner of the private control directory")
	flag.DurationVar(&cfg.timeout, "timeout", 60*time.Second, "bounded release timeout")
	flag.Parse()
	if flag.NArg() != 0 {
		return config{}, errors.New("unexpected positional arguments")
	}
	if cfg.processPID == 0 || uint64(cfg.processPID) > uint64(^uint32(0)) {
		return config{}, errors.New("process-pid must be a nonzero 32-bit value")
	}
	if cfg.processNamespace == 0 || uint64(cfg.processNamespace) > uint64(^uint32(0)) {
		return config{}, errors.New("process-namespace must be a nonzero 32-bit value")
	}
	if !filepath.IsAbs(cfg.controlDir) || filepath.Clean(cfg.controlDir) != cfg.controlDir {
		return config{}, errors.New("control-dir must be an absolute clean path")
	}
	if uint64(cfg.controlOwner) > uint64(^uint32(0)) {
		return config{}, errors.New("control-owner exceeds 32 bits")
	}
	if cfg.timeout < time.Second || cfg.timeout > 2*time.Minute {
		return config{}, errors.New("timeout must be between 1s and 2m")
	}
	return cfg, nil
}

func run(cfg config) (result output, returnedErr error) {
	if err := validateControlDirectory(cfg.controlDir, uint32(cfg.controlOwner)); err != nil {
		return output{}, err
	}
	target, err := discoverTarget(uint32(cfg.processPID), uint32(cfg.processNamespace))
	if err != nil {
		return output{}, err
	}
	defer target.close()

	mutated, restored, err := executeRestoredMutation(
		func() (bool, error) { return mutateTarget(target) },
		func() error {
			if err := writeControlState(cfg.controlDir, "armed", uint32(cfg.controlOwner)); err != nil {
				return err
			}
			return waitForRelease(cfg.controlDir, uint32(cfg.controlOwner), cfg.timeout)
		},
		func() error { return restoreTarget(target) },
	)
	if err != nil {
		return output{}, err
	}
	return output{
		Status:   "passed",
		Mode:     "generation-mismatch",
		Mutated:  mutated,
		Restored: restored,
	}, nil
}

func executeRestoredMutation(
	mutate func() (bool, error),
	wait func() error,
	restore func() error,
) (bool, bool, error) {
	mutated, mutateErr := mutate()
	if !mutated {
		return false, false, mutateErr
	}
	if mutateErr != nil {
		restoreErr := restore()
		if restoreErr != nil {
			return true, false, restoreErr
		}
		return true, true, mutateErr
	}
	waitErr := wait()
	restoreErr := restore()
	if restoreErr != nil {
		return true, false, restoreErr
	}
	if waitErr != nil {
		return true, true, waitErr
	}
	return true, true, nil
}

func (target *generationTarget) close() {
	for _, candidate := range []*ebpf.Map{
		target.processMap, target.ownerMap, target.stateMap, target.indexMap,
	} {
		if candidate != nil {
			candidate.Close()
		}
	}
}

func discoverTarget(processPID, processNamespace uint32) (*generationTarget, error) {
	processes, processMapID, identity, err := findProcessMap(processPID, processNamespace)
	if err != nil {
		return nil, err
	}
	related, err := mapsRelatedToTarget(processMapID)
	if err != nil {
		processes.Close()
		return nil, err
	}

	target := &generationTarget{processMap: processes}
	if err := findState(target, related, identity); err != nil {
		target.close()
		return nil, err
	}
	if err := findOwner(target, related, identity); err != nil {
		target.close()
		return nil, err
	}
	if err := findIndex(target, related, identity); err != nil {
		target.close()
		return nil, err
	}
	return target, nil
}

func findProcessMap(
	processPID, processNamespace uint32,
) (*ebpf.Map, ebpf.MapID, processIdentity, error) {
	var found *ebpf.Map
	var foundID ebpf.MapID
	var foundIdentity processIdentity
	for id := ebpf.MapID(0); ; {
		next, err := ebpf.MapGetNextID(id)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			closeMap(found)
			return nil, 0, processIdentity{}, errors.New("enumerate process maps")
		}
		id = next
		candidate, err := ebpf.NewMapFromID(id)
		if err != nil {
			continue
		}
		info, err := candidate.Info()
		if err != nil || !matchesMap(info, ebpf.Hash, processKeySize, processValueSize, processMapName) {
			candidate.Close()
			continue
		}
		identity, matched, err := lookupProcess(candidate, processPID, processNamespace)
		if err != nil {
			candidate.Close()
			closeMap(found)
			return nil, 0, processIdentity{}, err
		}
		if !matched {
			candidate.Close()
			continue
		}
		if found != nil {
			candidate.Close()
			found.Close()
			return nil, 0, processIdentity{}, errors.New("multiple process maps contain the controlled JVM")
		}
		found = candidate
		foundID = id
		foundIdentity = identity
	}
	if found == nil {
		return nil, 0, processIdentity{}, errors.New("controlled JVM process map was not found")
	}
	return found, foundID, foundIdentity, nil
}

func lookupProcess(
	processes *ebpf.Map, wantedPID, wantedNamespace uint32,
) (processIdentity, bool, error) {
	var key [processKeySize]byte
	var value [processValueSize]byte
	var found processIdentity
	iterator := processes.Iterate()
	for iterator.Next(&key, &value) {
		if !processKeyMatches(key[:], wantedPID, wantedNamespace) {
			continue
		}
		identity, err := decodeProcessIdentity(key[:], value[:])
		if err != nil {
			return processIdentity{}, false, err
		}
		if found.incarnation != 0 {
			return processIdentity{}, false, errors.New("controlled JVM has multiple process identities")
		}
		found = identity
	}
	if err := iterator.Err(); err != nil {
		return processIdentity{}, false, errors.New("iterate controlled JVM process map")
	}
	return found, found.incarnation != 0, nil
}

func processKeyMatches(key []byte, wantedPID, wantedNamespace uint32) bool {
	return len(key) == processKeySize &&
		binary.LittleEndian.Uint32(key[4:8]) == wantedPID &&
		binary.LittleEndian.Uint32(key[8:12]) == wantedNamespace
}

func decodeProcessIdentity(key, value []byte) (processIdentity, error) {
	if len(key) != processKeySize || len(value) != processValueSize {
		return processIdentity{}, errors.New("invalid process identity layout")
	}
	tid := binary.LittleEndian.Uint32(key[0:4])
	pid := binary.LittleEndian.Uint32(key[4:8])
	namespace := binary.LittleEndian.Uint32(key[8:12])
	incarnation := binary.LittleEndian.Uint64(value)
	if tid == 0 || tid != pid || namespace == 0 || incarnation == 0 {
		return processIdentity{}, errors.New("invalid controlled JVM process identity")
	}
	return processIdentity{pid: pid, namespace: namespace, incarnation: incarnation}, nil
}

func findState(target *generationTarget, related map[ebpf.MapID]struct{}, identity processIdentity) error {
	var found *ebpf.Map
	var foundKey [stateKeySize]byte
	var foundValue [stateValueSize]byte
	for id := range related {
		candidate, err := ebpf.NewMapFromID(id)
		if err != nil {
			continue
		}
		info, err := candidate.Info()
		if err != nil || !matchesMap(info, ebpf.Hash, stateKeySize, stateValueSize, kernelMapName) {
			candidate.Close()
			continue
		}
		var key [stateKeySize]byte
		var value [stateValueSize]byte
		matched := false
		iterator := candidate.Iterate()
		for iterator.Next(&key, &value) {
			if !validState(key[:], value[:], identity) {
				continue
			}
			if found != nil || matched {
				candidate.Close()
				closeMap(found)
				return errors.New("multiple active generations match the controlled JVM")
			}
			matched = true
			foundKey = key
			foundValue = value
		}
		if iterator.Err() != nil {
			closeMap(candidate)
			closeMap(found)
			return errors.New("iterate active generation state")
		}
		if matched {
			found = candidate
		} else {
			candidate.Close()
		}
	}
	if found == nil {
		return errors.New("active controlled generation was not found")
	}
	target.stateMap = found
	target.stateKey = foundKey
	target.stateValue = foundValue
	copy(target.ownerKey[:], foundKey[:ownerKeySize])
	return nil
}

func validState(key, value []byte, identity processIdentity) bool {
	if len(key) != stateKeySize || len(value) != stateValueSize ||
		binary.LittleEndian.Uint32(key[0:4]) == 0 ||
		binary.LittleEndian.Uint32(key[4:8]) != identity.pid ||
		binary.LittleEndian.Uint32(key[8:12]) != identity.namespace ||
		binary.LittleEndian.Uint32(key[12:16]) != 0 ||
		binary.LittleEndian.Uint64(key[16:24]) == 0 ||
		value[0] != activeLifecycle || !allZero(value[1:4]) ||
		binary.LittleEndian.Uint32(value[stateAliasesOffset:stateAliasesOffset+4]) != 0 ||
		binary.LittleEndian.Uint64(value[stateObservedOffset:stateObservedOffset+8]) == 0 ||
		binary.LittleEndian.Uint32(value[stateConnectionNetnsOffset:stateConnectionNetnsOffset+4]) == 0 ||
		binary.LittleEndian.Uint64(value[stateProcessIncarnationOffset:stateProcessIncarnationOffset+8]) != identity.incarnation ||
		!bytes.Equal(value[responseOffset:responseOffset+4], responseMagic) ||
		binary.LittleEndian.Uint16(value[responseVersionOffset:responseVersionOffset+2]) != 1 ||
		binary.LittleEndian.Uint16(value[responseSizeOffset:responseSizeOffset+2]) != responseSize ||
		value[responseStatusOffset] != 1 ||
		!allZero(value[responseReservedPrefixOffset:responseTraceIDOffset]) ||
		!anyNonzero(value[responseTraceIDOffset:responseSpanIDOffset]) ||
		!anyNonzero(value[responseSpanIDOffset:responseGenerationOffset]) ||
		binary.LittleEndian.Uint64(value[responseGenerationOffset:responseGenerationOffset+8]) != binary.LittleEndian.Uint64(key[16:24]) ||
		binary.LittleEndian.Uint64(value[responseObservedOffset:responseObservedOffset+8]) != binary.LittleEndian.Uint64(value[stateObservedOffset:stateObservedOffset+8]) ||
		!allZero(value[responseReservedSuffixOffset:responseOffset+responseSize]) {
		return false
	}
	return true
}

func findOwner(target *generationTarget, related map[ebpf.MapID]struct{}, identity processIdentity) error {
	var found *ebpf.Map
	for id := range related {
		candidate, err := ebpf.NewMapFromID(id)
		if err != nil {
			continue
		}
		info, err := candidate.Info()
		if err != nil || !matchesMap(info, ebpf.Hash, ownerKeySize, ownerValueSize, kernelMapName) {
			candidate.Close()
			continue
		}
		var value [ownerValueSize]byte
		if err := candidate.Lookup(target.ownerKey, &value); err != nil ||
			!validOwner(value[:], target.stateKey[:], identity) {
			candidate.Close()
			continue
		}
		if found != nil {
			candidate.Close()
			found.Close()
			return errors.New("multiple owner maps match the active generation")
		}
		found = candidate
		target.originalOwner = value
	}
	if found == nil {
		return errors.New("active generation owner was not found")
	}
	target.ownerMap = found
	target.mutatedOwner = target.originalOwner
	originalGeneration := binary.LittleEndian.Uint64(target.originalOwner[ownerGenerationOffset : ownerGenerationOffset+8])
	mutatedGeneration, ok := faultGeneration(originalGeneration)
	if !ok {
		return errors.New("could not select a distinct fault generation")
	}
	binary.LittleEndian.PutUint64(
		target.mutatedOwner[ownerGenerationOffset:ownerGenerationOffset+8],
		mutatedGeneration,
	)
	return nil
}

func faultGeneration(original uint64) (uint64, bool) {
	mutated := original ^ faultGenerationMask
	if mutated == 0 || mutated == original {
		mutated = original + 1
	}
	return mutated, mutated != 0 && mutated != original
}

func validOwner(value, stateKey []byte, identity processIdentity) bool {
	return len(value) == ownerValueSize && len(stateKey) == stateKeySize &&
		binary.LittleEndian.Uint64(value[ownerGenerationOffset:ownerGenerationOffset+8]) == binary.LittleEndian.Uint64(stateKey[16:24]) &&
		binary.LittleEndian.Uint64(value[ownerProcessIncarnationOffset:ownerProcessIncarnationOffset+8]) == identity.incarnation &&
		value[ownerLifecycleOffset] == activeLifecycle && allZero(value[ownerLifecycleOffset+1:])
}

func findIndex(target *generationTarget, related map[ebpf.MapID]struct{}, identity processIdentity) error {
	var found *ebpf.Map
	for id := range related {
		candidate, err := ebpf.NewMapFromID(id)
		if err != nil {
			continue
		}
		info, err := candidate.Info()
		if err != nil || !matchesMap(info, ebpf.Hash, stateKeySize, indexValueSize, kernelMapName) {
			candidate.Close()
			continue
		}
		var value [indexValueSize]byte
		if err := candidate.Lookup(target.stateKey, &value); err != nil ||
			!validIndex(value[:], target.stateValue[:], identity) {
			candidate.Close()
			continue
		}
		if found != nil {
			candidate.Close()
			found.Close()
			return errors.New("multiple generation indexes match the active generation")
		}
		found = candidate
		target.indexValue = value
	}
	if found == nil {
		return errors.New("active generation index was not found")
	}
	target.indexMap = found
	return nil
}

func validIndex(value, stateValue []byte, identity processIdentity) bool {
	return len(value) == indexValueSize && len(stateValue) == stateValueSize &&
		binary.LittleEndian.Uint32(value[0:4]) == identity.pid &&
		binary.LittleEndian.Uint32(value[4:8]) == identity.pid &&
		binary.LittleEndian.Uint32(value[8:12]) == identity.namespace &&
		binary.LittleEndian.Uint32(value[indexReservedOffset:indexReservedOffset+4]) == 0 &&
		binary.LittleEndian.Uint64(value[indexProcessIncarnationOffset:indexProcessIncarnationOffset+8]) == identity.incarnation &&
		binary.LittleEndian.Uint64(value[indexObservedOffset:indexObservedOffset+8]) == binary.LittleEndian.Uint64(stateValue[stateObservedOffset:stateObservedOffset+8])
}

func mutateTarget(target *generationTarget) (bool, error) {
	if err := verifyTargetUnchanged(target, target.originalOwner[:]); err != nil {
		return false, err
	}
	mutatedKey := target.stateKey
	copy(mutatedKey[16:24], target.mutatedOwner[ownerGenerationOffset:ownerGenerationOffset+8])
	var unexpected [stateValueSize]byte
	if err := target.stateMap.Lookup(mutatedKey, &unexpected); err == nil || !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, errors.New("fault generation already has state")
	}
	if err := target.ownerMap.Update(target.ownerKey, target.mutatedOwner, ebpf.UpdateExist); err != nil {
		return false, errors.New("apply owner generation mismatch")
	}
	var observed [ownerValueSize]byte
	if err := target.ownerMap.Lookup(target.ownerKey, &observed); err != nil || observed != target.mutatedOwner {
		return true, errors.New("owner generation mismatch was not retained")
	}
	return true, nil
}

func restoreTarget(target *generationTarget) error {
	if err := verifyTargetUnchanged(target, target.mutatedOwner[:]); err != nil {
		return err
	}
	if err := target.ownerMap.Update(target.ownerKey, target.originalOwner, ebpf.UpdateExist); err != nil {
		return errors.New("restore exact owner generation")
	}
	var observed [ownerValueSize]byte
	if err := target.ownerMap.Lookup(target.ownerKey, &observed); err != nil || observed != target.originalOwner {
		return errors.New("exact owner generation was not restored")
	}
	return nil
}

func verifyTargetUnchanged(target *generationTarget, expectedOwner []byte) error {
	var owner [ownerValueSize]byte
	if err := target.ownerMap.Lookup(target.ownerKey, &owner); err != nil || !bytes.Equal(owner[:], expectedOwner) {
		return errors.New("active owner changed during generation control")
	}
	var state [stateValueSize]byte
	if err := target.stateMap.Lookup(target.stateKey, &state); err != nil || state != target.stateValue {
		return errors.New("active state changed during generation control")
	}
	var index [indexValueSize]byte
	if err := target.indexMap.Lookup(target.stateKey, &index); err != nil || index != target.indexValue {
		return errors.New("generation index changed during generation control")
	}
	return nil
}

func matchesMap(info *ebpf.MapInfo, mapType ebpf.MapType, keySize, valueSize uint32, name string) bool {
	return info.Type == mapType && info.KeySize == keySize &&
		info.ValueSize == valueSize && info.Name == name &&
		info.MaxEntries > 0 && info.MaxEntries <= maximumEntries
}

func mapsRelatedToTarget(targetID ebpf.MapID) (map[ebpf.MapID]struct{}, error) {
	related := make(map[ebpf.MapID]struct{})
	available := false
	referenced := false
	for id := ebpf.ProgramID(0); ; {
		next, err := ebpf.ProgramGetNextID(id)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return nil, errors.New("enumerate live programs")
		}
		id = next
		program, err := ebpf.NewProgramFromID(id)
		if err != nil {
			continue
		}
		info, infoErr := program.Info()
		program.Close()
		if infoErr != nil {
			continue
		}
		mapIDs, ok := info.MapIDs()
		if !ok {
			continue
		}
		available = true
		if !containsMapID(mapIDs, targetID) {
			continue
		}
		referenced = true
		for _, mapID := range mapIDs {
			related[mapID] = struct{}{}
		}
	}
	if !available {
		return nil, errors.New("program map relationships are unavailable")
	}
	if !referenced {
		return nil, errors.New("controlled JVM process map is not referenced")
	}
	return related, nil
}

func containsMapID(ids []ebpf.MapID, target ebpf.MapID) bool {
	for _, id := range ids {
		if id == target {
			return true
		}
	}
	return false
}

func validateControlDirectory(path string, expectedOwner uint32) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != controlDirectoryMode {
		return errors.New("control directory is not private")
	}
	metadata, ok := info.Sys().(*syscall.Stat_t)
	if !ok || metadata.Uid != expectedOwner {
		return errors.New("control directory does not have its expected owner")
	}
	return nil
}

func writeControlState(directory, state string, owner uint32) error {
	if state != "armed" {
		return errors.New("invalid generation control state")
	}
	path := filepath.Join(directory, state)
	temporaryPath := filepath.Join(directory, ".armed.tmp")
	descriptor, err := syscall.Open(
		temporaryPath,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW,
		controlFileMode,
	)
	if err != nil {
		return errors.New("publish generation control state")
	}
	cleanupTemporary := true
	defer func() {
		if cleanupTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := syscall.Fchown(descriptor, int(owner), -1); err != nil {
		_ = syscall.Close(descriptor)
		return errors.New("set generation control state owner")
	}
	if err := syscall.Fchmod(descriptor, controlFileMode); err != nil {
		_ = syscall.Close(descriptor)
		return errors.New("set generation control state mode")
	}
	file := os.NewFile(uintptr(descriptor), temporaryPath)
	_, writeErr := file.WriteString(state + "\n")
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("write generation control state")
	}
	if err := unix.Renameat2(
		unix.AT_FDCWD,
		temporaryPath,
		unix.AT_FDCWD,
		path,
		unix.RENAME_NOREPLACE,
	); err != nil {
		return errors.New("publish generation control state")
	}
	cleanupTemporary = false
	return nil
}

func waitForRelease(directory string, expectedOwner uint32, timeout time.Duration) error {
	path := filepath.Join(directory, "release")
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ready, err := readPrivateRelease(path, expectedOwner)
		if err != nil {
			return err
		}
		if ready {
			return nil
		}
		time.Sleep(pollInterval)
	}
	return errors.New("timed out waiting for generation release")
}

func readPrivateRelease(path string, expectedOwner uint32) (bool, error) {
	descriptor, err := syscall.Open(
		path,
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,
		0,
	)
	if errors.Is(err, syscall.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("open generation release control")
	}
	file := os.NewFile(uintptr(descriptor), path)
	defer file.Close()

	var metadata syscall.Stat_t
	if err := syscall.Fstat(descriptor, &metadata); err != nil {
		return false, errors.New("inspect generation release control")
	}
	const contents = "release\n"
	if metadata.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		metadata.Mode&0o7777 != controlFileMode || metadata.Uid != expectedOwner ||
		metadata.Nlink != 1 || metadata.Size != int64(len(contents)) {
		return false, errors.New("release control is not a private regular file")
	}
	observed, err := io.ReadAll(io.LimitReader(file, int64(len(contents)+1)))
	if err != nil || string(observed) != contents {
		return false, errors.New("release control has invalid contents")
	}
	return true, nil
}

func allZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}

func anyNonzero(value []byte) bool {
	return !allZero(value)
}

func closeMap(candidate *ebpf.Map) {
	if candidate != nil {
		candidate.Close()
	}
}
