// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
)

const (
	targetMapName      = "java_remote_parent_handoff_claims"
	targetKernelName   = "java_remote_par"
	targetKeySize      = 16
	targetValueSize    = 16
	processMapName     = "java_process_incarnations"
	processKernelName  = "java_process_in"
	processKeySize     = 12
	processValueSize   = 8
	maxPressureEntries = 50_000
)

type config struct {
	mapID                uint
	expectedMaxEntries   uint
	expectedProcessMapID uint
	mode                 string
	seed                 uint
	processPID           uint
	processNamespace     uint
	tokenBase            uint64
}

type result struct {
	Status                string `json:"status"`
	Mode                  string `json:"mode"`
	MapID                 uint   `json:"map_id"`
	MapName               string `json:"map_name"`
	KernelName            string `json:"kernel_name"`
	MapType               string `json:"map_type"`
	MaxEntries            uint32 `json:"max_entries"`
	ProcessMapID          uint   `json:"process_map_id"`
	ProcessPID            uint32 `json:"process_pid"`
	ProcessNamespace      uint32 `json:"process_namespace"`
	TokenBase             uint64 `json:"token_base"`
	Touched               uint32 `json:"touched"`
	EvictedEntries        uint32 `json:"evicted_entries,omitempty"`
	CleanupVerified       bool   `json:"cleanup_verified,omitempty"`
	VerifiedAbsentEntries uint32 `json:"verified_absent_entries,omitempty"`
}

type processIdentity struct {
	pid         uint32
	namespace   uint32
	incarnation uint64
}

func main() {
	cfg, err := parseFlags()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	output, err := run(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func parseFlags() (config, error) {
	var cfg config
	flag.UintVar(&cfg.mapID, "map-id", 0, "live eBPF map ID")
	flag.UintVar(&cfg.expectedMaxEntries, "expected-max-entries", 0, "expected live map capacity")
	flag.UintVar(&cfg.expectedProcessMapID, "expected-process-map-id", 0, "prepared process map ID")
	flag.StringVar(&cfg.mode, "mode", "prepare", "prepare, fill, or cleanup")
	flag.UintVar(&cfg.seed, "seed", 1, "per-run synthetic token namespace seed")
	flag.UintVar(&cfg.processPID, "process-pid", 0, "prepared live JVM process ID")
	flag.UintVar(
		&cfg.processNamespace,
		"process-namespace",
		0,
		"prepared live JVM PID namespace",
	)
	flag.Uint64Var(&cfg.tokenBase, "token-base", 0, "prepared synthetic token base")
	flag.Parse()

	if flag.NArg() != 0 {
		return config{}, errors.New("unexpected positional arguments")
	}
	if err := validateConfig(cfg); err != nil {
		return config{}, err
	}
	return cfg, nil
}

func validateConfig(cfg config) error {
	if cfg.expectedMaxEntries > maxPressureEntries {
		return fmt.Errorf(
			"expected-max-entries must not exceed %d",
			maxPressureEntries,
		)
	}
	if uint64(cfg.mapID) > uint64(^uint32(0)) {
		return errors.New("map-id exceeds 32 bits")
	}
	if uint64(cfg.processPID) > uint64(^uint32(0)) {
		return errors.New("process-pid exceeds 32 bits")
	}
	if uint64(cfg.expectedProcessMapID) > uint64(^uint32(0)) {
		return errors.New("expected-process-map-id exceeds 32 bits")
	}
	if uint64(cfg.processNamespace) > uint64(^uint32(0)) {
		return errors.New("process-namespace exceeds 32 bits")
	}
	if cfg.mode != "prepare" && cfg.mode != "fill" && cfg.mode != "cleanup" {
		return errors.New("mode must be prepare, fill, or cleanup")
	}
	if cfg.mode == "prepare" &&
		(cfg.mapID != 0 || cfg.expectedMaxEntries != 0 || cfg.expectedProcessMapID != 0 ||
			cfg.processPID != 0 || cfg.processNamespace != 0 || cfg.tokenBase != 0) {
		return errors.New("map and process identity flags are not valid in prepare mode")
	}
	if cfg.mode == "fill" &&
		(cfg.mapID == 0 || cfg.expectedMaxEntries == 0 || cfg.expectedProcessMapID == 0 ||
			cfg.processPID == 0 || cfg.processNamespace == 0 || cfg.tokenBase == 0) {
		return errors.New(
			"fill requires map-id, expected-max-entries, expected-process-map-id, process-pid, process-namespace, and token-base",
		)
	}
	if cfg.mode == "cleanup" &&
		(cfg.mapID == 0 || cfg.expectedMaxEntries == 0 || cfg.processPID == 0 ||
			cfg.processNamespace == 0 || cfg.tokenBase == 0) {
		return errors.New(
			"cleanup requires map-id, expected-max-entries, process-pid, process-namespace, and token-base",
		)
	}
	if cfg.mode == "cleanup" && cfg.expectedProcessMapID != 0 {
		return errors.New("expected-process-map-id is not valid in cleanup mode")
	}
	return nil
}

func run(cfg config) (result, error) {
	if err := validateConfig(cfg); err != nil {
		return result{}, err
	}
	target, mapID, err := openTargetMap(ebpf.MapID(cfg.mapID))
	if err != nil {
		return result{}, err
	}
	defer target.Close()

	info, err := target.Info()
	if err != nil {
		return result{}, fmt.Errorf("inspect map ID %d: %w", cfg.mapID, err)
	}
	if err := validateTarget(info, uint32(cfg.expectedMaxEntries)); err != nil {
		return result{}, err
	}
	entryCount := info.MaxEntries + 1
	var identity processIdentity
	var processMapID ebpf.MapID
	tokenBase := cfg.tokenBase
	if cfg.mode == "prepare" || cfg.mode == "fill" {
		processes, discoveredMapID, openErr := openProcessMap(mapID)
		if openErr != nil {
			return result{}, openErr
		}
		defer processes.Close()
		if cfg.mode == "fill" {
			if err := validatePreparedProcessMapID(
				ebpf.MapID(cfg.expectedProcessMapID),
				discoveredMapID,
			); err != nil {
				return result{}, err
			}
		}
		identity, err = readProcessIdentity(processes)
		if err != nil {
			return result{}, err
		}
		processMapID = discoveredMapID
		if cfg.mode == "prepare" {
			tokenBase, err = newTokenBase(uint64(cfg.seed), entryCount)
			if err != nil {
				return result{}, err
			}
		} else if err := validatePreparedProcessIdentity(
			uint32(cfg.processPID),
			uint32(cfg.processNamespace),
			identity,
		); err != nil {
			return result{}, err
		}
	} else {
		identity.pid = uint32(cfg.processPID)
		identity.namespace = uint32(cfg.processNamespace)
	}
	if err := validateTokenBase(tokenBase, entryCount); err != nil {
		return result{}, err
	}

	output := result{
		Status:           "passed",
		Mode:             cfg.mode,
		MapID:            uint(mapID),
		MapName:          targetMapName,
		KernelName:       info.Name,
		MapType:          info.Type.String(),
		MaxEntries:       info.MaxEntries,
		ProcessMapID:     uint(processMapID),
		ProcessPID:       identity.pid,
		ProcessNamespace: identity.namespace,
		TokenBase:        tokenBase,
	}
	if cfg.mode == "prepare" {
		return output, nil
	}
	filledEntries := uint32(0)
	cleanupFailedFill := func() {
		for index := uint32(0); index < filledEntries; index++ {
			_ = target.Delete(syntheticKey(identity, tokenBase, index))
		}
	}
	for index := uint32(0); index < entryCount; index++ {
		key := syntheticKey(identity, tokenBase, index)
		switch cfg.mode {
		case "fill":
			observedMonotimeNS, monotimeErr := monotonicNowNS()
			if monotimeErr != nil {
				cleanupFailedFill()
				return result{}, monotimeErr
			}
			value := claimValue(observedMonotimeNS, identity.incarnation)
			if err := target.Update(key, value, ebpf.UpdateAny); err != nil {
				cleanupFailedFill()
				return result{}, fmt.Errorf("fill entry %d: %w", index, err)
			}
			output.Touched++
			filledEntries++
		case "cleanup":
			err := target.Delete(key)
			if err == nil {
				output.Touched++
			} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
				return result{}, fmt.Errorf("delete entry %d: %w", index, err)
			}
		}
	}

	if cfg.mode == "fill" {
		output.EvictedEntries, err = countEvictedSyntheticEntries(
			identity,
			tokenBase,
			entryCount,
			func(key []byte) error {
				var value [targetValueSize]byte
				return target.Lookup(key, &value)
			},
		)
		if err != nil {
			cleanupFailedFill()
			return result{}, err
		}
	} else {
		output.VerifiedAbsentEntries, err = verifySyntheticEntriesAbsent(
			identity,
			tokenBase,
			entryCount,
			func(key []byte) error {
				var value [targetValueSize]byte
				return target.Lookup(key, &value)
			},
		)
		if err != nil {
			return result{}, err
		}
		output.CleanupVerified = true
	}
	return output, nil
}

func countEvictedSyntheticEntries(
	identity processIdentity,
	tokenBase uint64,
	entryCount uint32,
	lookup func([]byte) error,
) (uint32, error) {
	evictedEntries := uint32(0)
	for index := uint32(0); index < entryCount; index++ {
		err := lookup(syntheticKey(identity, tokenBase, index))
		switch {
		case err == nil:
		case errors.Is(err, ebpf.ErrKeyNotExist):
			evictedEntries++
		default:
			return 0, fmt.Errorf("lookup synthetic entry %d: %w", index, err)
		}
	}
	if evictedEntries == 0 {
		return 0, errors.New("no synthetic entries were evicted")
	}
	return evictedEntries, nil
}

func verifySyntheticEntriesAbsent(
	identity processIdentity,
	tokenBase uint64,
	entryCount uint32,
	lookup func([]byte) error,
) (uint32, error) {
	absentEntries := uint32(0)
	for index := uint32(0); index < entryCount; index++ {
		err := lookup(syntheticKey(identity, tokenBase, index))
		switch {
		case errors.Is(err, ebpf.ErrKeyNotExist):
			absentEntries++
		case err == nil:
			return 0, fmt.Errorf("synthetic entry %d remains after cleanup", index)
		default:
			return 0, fmt.Errorf("verify synthetic entry %d cleanup: %w", index, err)
		}
	}
	return absentEntries, nil
}

func openProcessMap(targetID ebpf.MapID) (*ebpf.Map, ebpf.MapID, error) {
	relatedMapIDs, err := mapsRelatedToTarget(targetID)
	if err != nil {
		return nil, 0, err
	}

	candidates := make(map[ebpf.MapID]*ebpf.Map)
	candidateIDs := make([]ebpf.MapID, 0)
	for id := ebpf.MapID(0); ; {
		next, err := ebpf.MapGetNextID(id)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			closeMaps(candidates)
			return nil, 0, fmt.Errorf("enumerate process maps after ID %d: %w", id, err)
		}
		id = next
		if _, related := relatedMapIDs[id]; !related {
			continue
		}
		candidate, err := ebpf.NewMapFromID(id)
		if err != nil {
			continue
		}
		info, err := candidate.Info()
		if err != nil || !matchesProcessMap(info) {
			candidate.Close()
			continue
		}
		candidates[id] = candidate
		candidateIDs = append(candidateIDs, id)
	}

	foundID, err := selectRelatedMapID(targetID, relatedMapIDs, candidateIDs)
	if err != nil {
		closeMaps(candidates)
		return nil, 0, err
	}

	found := candidates[foundID]
	delete(candidates, foundID)
	closeMaps(candidates)
	return found, foundID, nil
}

func mapsRelatedToTarget(targetID ebpf.MapID) (map[ebpf.MapID]struct{}, error) {
	related := make(map[ebpf.MapID]struct{})
	mapIDsAvailable := false
	targetReferenced := false

	for id := ebpf.ProgramID(0); ; {
		next, err := ebpf.ProgramGetNextID(id)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("enumerate programs after ID %d: %w", id, err)
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
		mapIDs, available := info.MapIDs()
		if !available {
			continue
		}
		mapIDsAvailable = true
		if !addRelatedMapIDs(targetID, mapIDs, related) {
			continue
		}
		targetReferenced = true
	}

	if !targetReferenced {
		if !mapIDsAvailable {
			return nil, errors.New("program map relationships are unavailable")
		}
		return nil, fmt.Errorf("no live program references target map ID %d", targetID)
	}
	return related, nil
}

func containsMapID(mapIDs []ebpf.MapID, targetID ebpf.MapID) bool {
	for _, mapID := range mapIDs {
		if mapID == targetID {
			return true
		}
	}
	return false
}

func addRelatedMapIDs(
	targetID ebpf.MapID, mapIDs []ebpf.MapID, related map[ebpf.MapID]struct{},
) bool {
	if !containsMapID(mapIDs, targetID) {
		return false
	}
	for _, mapID := range mapIDs {
		related[mapID] = struct{}{}
	}
	return true
}

func selectRelatedMapID(
	targetID ebpf.MapID, relatedMapIDs map[ebpf.MapID]struct{}, candidates []ebpf.MapID,
) (ebpf.MapID, error) {
	var found ebpf.MapID
	for _, candidateID := range candidates {
		if _, related := relatedMapIDs[candidateID]; !related {
			continue
		}
		if found != 0 && found != candidateID {
			return 0, fmt.Errorf("multiple process maps are related to target map ID %d", targetID)
		}
		found = candidateID
	}
	if found == 0 {
		return 0, fmt.Errorf("no process map is related to target map ID %d", targetID)
	}
	return found, nil
}

func closeMaps(maps map[ebpf.MapID]*ebpf.Map) {
	for _, candidate := range maps {
		candidate.Close()
	}
}

func readProcessIdentity(processes *ebpf.Map) (processIdentity, error) {
	info, err := processes.Info()
	if err != nil {
		return processIdentity{}, fmt.Errorf("inspect %s: %w", processMapName, err)
	}
	if !matchesProcessMap(info) {
		return processIdentity{}, fmt.Errorf(
			"map does not match %s layout: type=%s key=%d value=%d",
			processMapName,
			info.Type,
			info.KeySize,
			info.ValueSize,
		)
	}

	var selected processIdentity
	var key [processKeySize]byte
	var value [processValueSize]byte
	iterator := processes.Iterate()
	for iterator.Next(&key, &value) {
		identity, decodeErr := decodeProcessIdentity(key[:], value[:])
		if decodeErr != nil {
			return processIdentity{}, decodeErr
		}
		if selected.incarnation != 0 {
			return processIdentity{}, fmt.Errorf("multiple live JVM identities found in %s", processMapName)
		}
		selected = identity
	}
	if err := iterator.Err(); err != nil {
		return processIdentity{}, fmt.Errorf("iterate %s: %w", processMapName, err)
	}
	if selected.incarnation == 0 {
		return processIdentity{}, fmt.Errorf("no live JVM identity found in %s", processMapName)
	}
	return selected, nil
}

func decodeProcessIdentity(key, value []byte) (processIdentity, error) {
	if len(key) != processKeySize || len(value) != processValueSize {
		return processIdentity{}, errors.New("invalid process-incarnation entry size")
	}
	tid := binary.LittleEndian.Uint32(key[0:4])
	pid := binary.LittleEndian.Uint32(key[4:8])
	namespace := binary.LittleEndian.Uint32(key[8:12])
	incarnation := binary.LittleEndian.Uint64(value)
	if tid == 0 || tid != pid || namespace == 0 || incarnation == 0 {
		return processIdentity{}, fmt.Errorf(
			"invalid live JVM identity: tid=%d pid=%d namespace=%d incarnation_nonzero=%t",
			tid,
			pid,
			namespace,
			incarnation != 0,
		)
	}
	return processIdentity{pid: pid, namespace: namespace, incarnation: incarnation}, nil
}

func matchesProcessMap(info *ebpf.MapInfo) bool {
	return info.Type == ebpf.LRUHash &&
		info.KeySize == processKeySize &&
		info.ValueSize == processValueSize &&
		info.Name == processKernelName
}

func openTargetMap(requested ebpf.MapID) (*ebpf.Map, ebpf.MapID, error) {
	if requested != 0 {
		target, err := ebpf.NewMapFromID(requested)
		if err != nil {
			return nil, 0, fmt.Errorf("open map ID %d: %w", requested, err)
		}
		return target, requested, nil
	}

	var found *ebpf.Map
	var foundID ebpf.MapID
	for id := ebpf.MapID(0); ; {
		next, err := ebpf.MapGetNextID(id)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			if found != nil {
				found.Close()
			}
			return nil, 0, fmt.Errorf("enumerate maps after ID %d: %w", id, err)
		}
		id = next
		candidate, err := ebpf.NewMapFromID(id)
		if err != nil {
			continue
		}
		info, err := candidate.Info()
		if err != nil || !matchesTarget(info) {
			candidate.Close()
			continue
		}
		if found != nil {
			candidate.Close()
			found.Close()
			return nil, 0, fmt.Errorf("multiple live maps match %s", targetMapName)
		}
		found = candidate
		foundID = id
	}
	if found == nil {
		return nil, 0, fmt.Errorf("live map %s was not found", targetMapName)
	}
	return found, foundID, nil
}

func matchesTarget(info *ebpf.MapInfo) bool {
	return info.Type == ebpf.LRUHash &&
		info.KeySize == targetKeySize &&
		info.ValueSize == targetValueSize &&
		info.Name == targetKernelName
}

func validateTarget(info *ebpf.MapInfo, expectedMaxEntries uint32) error {
	if !matchesTarget(info) {
		return fmt.Errorf(
			"map does not match %s layout: type=%s key=%d value=%d",
			targetMapName,
			info.Type,
			info.KeySize,
			info.ValueSize,
		)
	}
	if info.MaxEntries == 0 || info.MaxEntries > maxPressureEntries {
		return fmt.Errorf("map capacity %d is outside the bounded pressure range", info.MaxEntries)
	}
	if expectedMaxEntries != 0 && info.MaxEntries != expectedMaxEntries {
		return fmt.Errorf(
			"map capacity mismatch: expected %d, got %d",
			expectedMaxEntries,
			info.MaxEntries,
		)
	}
	return nil
}

func syntheticKey(identity processIdentity, tokenBase uint64, index uint32) []byte {
	key := make([]byte, targetKeySize)
	binary.LittleEndian.PutUint32(key[0:4], identity.pid)
	binary.LittleEndian.PutUint32(key[4:8], identity.namespace)
	binary.LittleEndian.PutUint64(key[8:16], syntheticToken(tokenBase, index))
	return key
}

func syntheticToken(tokenBase uint64, index uint32) uint64 {
	return tokenBase + uint64(index)
}

func validateTokenBase(tokenBase uint64, entryCount uint32) error {
	if tokenBase == 0 || entryCount == 0 {
		return errors.New("token-base is outside the bounded synthetic entry range")
	}
	lastIndex := uint64(entryCount - 1)
	if tokenBase > ^uint64(0)-lastIndex {
		return errors.New("token-base is outside the bounded synthetic entry range")
	}
	return nil
}

func newTokenBase(seed uint64, entryCount uint32) (uint64, error) {
	if entryCount == 0 {
		return 0, errors.New("synthetic entry count must be positive")
	}
	var source [8]byte
	if _, err := rand.Read(source[:]); err != nil {
		return 0, fmt.Errorf("generate synthetic token namespace: %w", err)
	}
	maximumBase := ^uint64(0) - uint64(entryCount-1)
	return (binary.LittleEndian.Uint64(source[:])^seed)%maximumBase + 1, nil
}

func validatePreparedProcessIdentity(
	expectedPID uint32,
	expectedNamespace uint32,
	identity processIdentity,
) error {
	if identity.pid != expectedPID || identity.namespace != expectedNamespace {
		return errors.New("prepared JVM process identity changed before fill")
	}
	return nil
}

func validatePreparedProcessMapID(expected, actual ebpf.MapID) error {
	if actual != expected {
		return errors.New("prepared JVM process map changed before fill")
	}
	return nil
}

func claimValue(observedMonotimeNS, incarnation uint64) []byte {
	value := make([]byte, targetValueSize)
	binary.LittleEndian.PutUint64(value[0:8], observedMonotimeNS)
	binary.LittleEndian.PutUint64(value[8:16], incarnation)
	return value
}
