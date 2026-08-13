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
	"syscall"

	"github.com/cilium/ebpf"
)

const (
	targetMapName      = "java_remote_parent_handoff_claims"
	targetKernelName   = "java_remote_par"
	targetKeySize      = 24
	targetValueSize    = 16
	processMapName     = "java_process_incarnations"
	processKernelName  = "java_process_in"
	processKeySize     = 12
	processValueSize   = 8
	maxPressureEntries = 50_000
	handoffOpenTag     = uint64(1) << 63
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
	Status                  string `json:"status"`
	Mode                    string `json:"mode"`
	MapID                   uint   `json:"map_id"`
	MapName                 string `json:"map_name"`
	KernelName              string `json:"kernel_name"`
	MapType                 string `json:"map_type"`
	MaxEntries              uint32 `json:"max_entries"`
	ProcessMapID            uint   `json:"process_map_id"`
	ProcessPID              uint32 `json:"process_pid"`
	ProcessNamespace        uint32 `json:"process_namespace"`
	TokenBase               uint64 `json:"token_base"`
	Touched                 uint32 `json:"touched"`
	CapacityRejectedEntries uint32 `json:"capacity_rejected_entries,omitempty"`
	VerifiedPresentEntries  uint32 `json:"verified_present_entries,omitempty"`
	CleanupVerified         bool   `json:"cleanup_verified,omitempty"`
	VerifiedAbsentEntries   uint32 `json:"verified_absent_entries,omitempty"`
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
			cfg.processPID == 0 || cfg.processNamespace == 0 || cfg.tokenBase != 0) {
		return errors.New("prepare requires only process-pid and process-namespace")
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

type runDependencies struct {
	openTargetMap               func(ebpf.MapID) (targetMapHandle, ebpf.MapID, error)
	openProcessMap              func(ebpf.MapID) (pressureMapHandle, ebpf.MapID, error)
	openPressureMapsForIdentity func(
		uint32, uint32,
	) (pressureMapHandle, ebpf.MapID, targetMapHandle, ebpf.MapID, processIdentity, error)
	monotonicNowNS func() (uint64, error)
}

func run(cfg config) (result, error) {
	return runWithDependencies(cfg, runDependencies{
		openTargetMap: func(id ebpf.MapID) (targetMapHandle, ebpf.MapID, error) {
			return openTargetMap(id)
		},
		openProcessMap: func(id ebpf.MapID) (pressureMapHandle, ebpf.MapID, error) {
			return openProcessMap(id)
		},
		openPressureMapsForIdentity: func(
			pid, namespace uint32,
		) (pressureMapHandle, ebpf.MapID, targetMapHandle, ebpf.MapID, processIdentity, error) {
			return openPressureMapsForIdentity(pid, namespace)
		},
		monotonicNowNS: monotonicNowNS,
	})
}

func runWithDependencies(cfg config, dependencies runDependencies) (result, error) {
	if err := validateConfig(cfg); err != nil {
		return result{}, err
	}
	var target targetMapHandle
	var mapID ebpf.MapID
	var processes pressureMapHandle
	var processMapID ebpf.MapID
	var identity processIdentity
	var err error
	if cfg.mode == "prepare" {
		processes, processMapID, target, mapID, identity, err = dependencies.openPressureMapsForIdentity(
			uint32(cfg.processPID),
			uint32(cfg.processNamespace),
		)
		if err != nil {
			return result{}, err
		}
		defer processes.Close()
	} else {
		target, mapID, err = dependencies.openTargetMap(ebpf.MapID(cfg.mapID))
	}
	if err != nil {
		return result{}, err
	}
	defer target.Close()
	if cfg.mode == "prepare" {
		confirmed, matched, confirmErr := readMatchingProcessIdentity(
			processes,
			uint32(cfg.processPID),
			uint32(cfg.processNamespace),
		)
		if confirmErr != nil {
			return result{}, confirmErr
		}
		if !matched || confirmed != identity {
			return result{}, errors.New("controlled JVM identity changed during map discovery")
		}
	}

	info, err := target.Info()
	if err != nil {
		return result{}, fmt.Errorf("inspect map ID %d: %w", mapID, err)
	}
	if err := validateTarget(info, uint32(cfg.expectedMaxEntries)); err != nil {
		return result{}, err
	}
	entryCount := info.MaxEntries + 1
	tokenBase := cfg.tokenBase
	if cfg.mode == "fill" {
		processes, discoveredMapID, openErr := dependencies.openProcessMap(mapID)
		if openErr != nil {
			return result{}, openErr
		}
		defer processes.Close()
		if err := validatePreparedProcessMapID(
			ebpf.MapID(cfg.expectedProcessMapID),
			discoveredMapID,
		); err != nil {
			return result{}, err
		}
		var matched bool
		identity, matched, err = readMatchingProcessIdentity(
			processes,
			uint32(cfg.processPID),
			uint32(cfg.processNamespace),
		)
		if err != nil {
			return result{}, err
		}
		if !matched {
			return result{}, errors.New("prepared JVM identity is absent from its process map")
		}
		processMapID = discoveredMapID
		if err := validatePreparedProcessIdentity(
			uint32(cfg.processPID),
			uint32(cfg.processNamespace),
			identity,
		); err != nil {
			return result{}, err
		}
	} else if cfg.mode == "prepare" {
		tokenBase, err = newTokenBase(uint64(cfg.seed), entryCount)
		if err != nil {
			return result{}, err
		}
	} else if cfg.mode == "cleanup" {
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
	if cfg.mode == "cleanup" {
		output.Touched, output.VerifiedAbsentEntries, err = cleanupSyntheticEntries(
			identity,
			tokenBase,
			entryCount,
			func() ([]targetEntry, error) { return collectTargetEntries(target) },
			func(key []byte) error { return target.Delete(key) },
		)
		if err != nil {
			return result{}, err
		}
		output.CleanupVerified = true
		return output, nil
	}
	for index := uint32(0); index < entryCount; index++ {
		key := syntheticKey(identity, tokenBase, index)
		switch cfg.mode {
		case "fill":
			observedMonotimeNS, monotimeErr := dependencies.monotonicNowNS()
			if monotimeErr != nil {
				cleanupFailedFill()
				return result{}, monotimeErr
			}
			value := claimValue(observedMonotimeNS, identity.incarnation)
			if err := target.Update(key, value, ebpf.UpdateNoExist); err != nil {
				if isCapacityRejection(err) {
					output.CapacityRejectedEntries++
					break
				}
				cleanupFailedFill()
				return result{}, fmt.Errorf("fill entry %d: %w", index, err)
			}
			output.Touched++
			filledEntries++
		}
		if output.CapacityRejectedEntries != 0 {
			break
		}
	}

	if cfg.mode == "fill" {
		if output.CapacityRejectedEntries != 1 {
			cleanupFailedFill()
			return result{}, errors.New("non-evicting map accepted capacity plus one entries")
		}
		if filledEntries == 0 {
			return result{}, errors.New("map reached capacity before admitting a synthetic ticket")
		}
		output.VerifiedPresentEntries, err = verifySyntheticEntriesPresent(
			identity,
			tokenBase,
			filledEntries,
			func(key []byte) error {
				var value [targetValueSize]byte
				return target.Lookup(key, &value)
			},
		)
		if err != nil {
			cleanupFailedFill()
			return result{}, err
		}
	}
	return output, nil
}

type targetEntry struct {
	key   [targetKeySize]byte
	value [targetValueSize]byte
}

func collectTargetEntries(target targetMapHandle) ([]targetEntry, error) {
	entries := make([]targetEntry, 0)
	var entry targetEntry
	iterator := target.Iterate()
	for iterator.Next(&entry.key, &entry.value) {
		entries = append(entries, entry)
	}
	if err := iterator.Err(); err != nil {
		return nil, fmt.Errorf("iterate %s: %w", targetMapName, err)
	}
	return entries, nil
}

func cleanupSyntheticEntries(
	identity processIdentity,
	tokenBase uint64,
	entryCount uint32,
	collect func() ([]targetEntry, error),
	deleteKey func([]byte) error,
) (uint32, uint32, error) {
	entries, err := collect()
	if err != nil {
		return 0, 0, err
	}
	keys := make([][targetKeySize]byte, 0)
	for _, entry := range entries {
		if !syntheticKeyInRange(entry.key, identity, tokenBase, entryCount) {
			continue
		}
		if !syntheticEntryValueMatchesKey(entry) {
			return 0, 0, errors.New("synthetic entry has an invalid incarnation or ticket")
		}
		if uint32(len(keys)) >= entryCount {
			return 0, 0, errors.New("synthetic entry scan exceeded its bounded token range")
		}
		keys = append(keys, entry.key)
	}
	for index := range keys {
		if err := deleteKey(keys[index][:]); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return uint32(index), 0, fmt.Errorf("delete synthetic entry %d: %w", index, err)
		}
	}
	remaining, err := collect()
	if err != nil {
		return uint32(len(keys)), 0, err
	}
	for _, entry := range remaining {
		if syntheticKeyInRange(entry.key, identity, tokenBase, entryCount) {
			return uint32(len(keys)), 0, errors.New("synthetic entry remains after cleanup")
		}
	}
	return uint32(len(keys)), entryCount, nil
}

func syntheticKeyInRange(
	key [targetKeySize]byte, identity processIdentity, tokenBase uint64, entryCount uint32,
) bool {
	if entryCount == 0 ||
		binary.LittleEndian.Uint32(key[0:4]) != identity.pid ||
		binary.LittleEndian.Uint32(key[4:8]) != identity.namespace {
		return false
	}
	token := binary.LittleEndian.Uint64(key[8:16])
	return token >= tokenBase && token-tokenBase < uint64(entryCount)
}

func syntheticEntryValueMatchesKey(entry targetEntry) bool {
	incarnation := binary.LittleEndian.Uint64(entry.key[16:24])
	valueTicket := binary.LittleEndian.Uint64(entry.value[0:8])
	valueIncarnation := binary.LittleEndian.Uint64(entry.value[8:16])
	return incarnation != 0 &&
		incarnation == valueIncarnation &&
		valueTicket&handoffOpenTag != 0 &&
		valueTicket&^handoffOpenTag != 0
}

func isCapacityRejection(err error) bool {
	return errors.Is(err, syscall.E2BIG) || errors.Is(err, syscall.ENOSPC)
}

func verifySyntheticEntriesPresent(
	identity processIdentity,
	tokenBase uint64,
	entryCount uint32,
	lookup func([]byte) error,
) (uint32, error) {
	presentEntries := uint32(0)
	for index := uint32(0); index < entryCount; index++ {
		err := lookup(syntheticKey(identity, tokenBase, index))
		switch {
		case err == nil:
			presentEntries++
		case errors.Is(err, ebpf.ErrKeyNotExist):
			return 0, fmt.Errorf("synthetic entry %d was evicted", index)
		default:
			return 0, fmt.Errorf("lookup synthetic entry %d: %w", index, err)
		}
	}
	return presentEntries, nil
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
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			closeMaps(candidates)
			return nil, 0, fmt.Errorf("open program-related map ID %d: %w", id, err)
		}
		info, err := candidate.Info()
		if err != nil {
			candidate.Close()
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			closeMaps(candidates)
			return nil, 0, fmt.Errorf("inspect program-related map ID %d: %w", id, err)
		}
		if !matchesProcessMap(info) {
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

type pressureMapHandle interface {
	Info() (*ebpf.MapInfo, error)
	Lookup(key, value interface{}) error
	Close() error
}

type targetMapHandle interface {
	pressureMapHandle
	Update(key, value interface{}, flags ebpf.MapUpdateFlags) error
	Delete(key interface{}) error
	Iterate() *ebpf.MapIterator
}

type pressureMapDiscovery struct {
	nextMapID     func(ebpf.MapID) (ebpf.MapID, error)
	openMap       func(ebpf.MapID) (pressureMapHandle, error)
	relatedTarget func(ebpf.MapID) (pressureMapHandle, ebpf.MapID, error)
}

func openPressureMapsForIdentity(
	wantedPID, wantedNamespace uint32,
) (*ebpf.Map, ebpf.MapID, *ebpf.Map, ebpf.MapID, processIdentity, error) {
	processes, processMapID, target, targetMapID, identity, err :=
		discoverPressureMapsForIdentity(
			pressureMapDiscovery{
				nextMapID: ebpf.MapGetNextID,
				openMap: func(id ebpf.MapID) (pressureMapHandle, error) {
					return ebpf.NewMapFromID(id)
				},
				relatedTarget: func(id ebpf.MapID) (pressureMapHandle, ebpf.MapID, error) {
					return openRelatedTargetMap(id)
				},
			},
			wantedPID,
			wantedNamespace,
		)
	if err != nil {
		return nil, 0, nil, 0, processIdentity{}, err
	}
	processMap, processOK := processes.(*ebpf.Map)
	targetMap, targetOK := target.(*ebpf.Map)
	if !processOK || !targetOK {
		_ = processes.Close()
		_ = target.Close()
		return nil, 0, nil, 0, processIdentity{}, errors.New("map discovery returned an invalid handle")
	}
	return processMap, processMapID, targetMap, targetMapID, identity, nil
}

func discoverPressureMapsForIdentity(
	discovery pressureMapDiscovery,
	wantedPID, wantedNamespace uint32,
) (pressureMapHandle, ebpf.MapID, pressureMapHandle, ebpf.MapID, processIdentity, error) {
	var foundProcess pressureMapHandle
	var foundProcessID ebpf.MapID
	var foundTarget pressureMapHandle
	var foundTargetID ebpf.MapID
	var foundIdentity processIdentity
	for id := ebpf.MapID(0); ; {
		next, err := discovery.nextMapID(id)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			closePressureMapPair(foundProcess, foundTarget)
			return nil, 0, nil, 0, processIdentity{}, fmt.Errorf("enumerate process maps after ID %d: %w", id, err)
		}
		id = next
		candidate, err := discovery.openMap(id)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			closePressureMapPair(foundProcess, foundTarget)
			return nil, 0, nil, 0, processIdentity{}, fmt.Errorf("open process map ID %d: %w", id, err)
		}
		info, err := candidate.Info()
		if err != nil {
			candidate.Close()
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			closePressureMapPair(foundProcess, foundTarget)
			return nil, 0, nil, 0, processIdentity{}, fmt.Errorf("inspect process map ID %d: %w", id, err)
		}
		if !matchesProcessMap(info) {
			candidate.Close()
			continue
		}
		identity, matched, err := readMatchingProcessIdentity(candidate, wantedPID, wantedNamespace)
		if err != nil {
			candidate.Close()
			closePressureMapPair(foundProcess, foundTarget)
			return nil, 0, nil, 0, processIdentity{}, err
		}
		if !matched {
			candidate.Close()
			continue
		}
		target, targetID, err := discovery.relatedTarget(id)
		if err != nil {
			candidate.Close()
			if errors.Is(err, errNoRelatedTargetMap) || errors.Is(err, errMapNotReferenced) {
				continue
			}
			closePressureMapPair(foundProcess, foundTarget)
			return nil, 0, nil, 0, processIdentity{}, err
		}
		if foundProcess != nil {
			candidate.Close()
			target.Close()
			closePressureMapPair(foundProcess, foundTarget)
			return nil, 0, nil, 0, processIdentity{}, errors.New("multiple live map sets contain the controlled JVM")
		}
		foundProcess = candidate
		foundProcessID = id
		foundTarget = target
		foundTargetID = targetID
		foundIdentity = identity
	}
	if foundProcess == nil {
		return nil, 0, nil, 0, processIdentity{}, errors.New("controlled JVM map set was not found")
	}
	confirmed, matched, err := readMatchingProcessIdentity(
		foundProcess,
		wantedPID,
		wantedNamespace,
	)
	if err != nil {
		closePressureMapPair(foundProcess, foundTarget)
		return nil, 0, nil, 0, processIdentity{}, err
	}
	if !matched || confirmed != foundIdentity {
		closePressureMapPair(foundProcess, foundTarget)
		return nil, 0, nil, 0, processIdentity{}, errors.New("controlled JVM identity changed during map discovery")
	}
	return foundProcess, foundProcessID, foundTarget, foundTargetID, foundIdentity, nil
}

var errNoRelatedTargetMap = errors.New("no related target map")
var errMapNotReferenced = errors.New("map is not referenced by a live program")

func closePressureMapPair(first, second pressureMapHandle) {
	if first != nil {
		_ = first.Close()
	}
	if second != nil {
		_ = second.Close()
	}
}

func openRelatedTargetMap(processMapID ebpf.MapID) (*ebpf.Map, ebpf.MapID, error) {
	related, err := mapsRelatedToTarget(processMapID)
	if err != nil {
		return nil, 0, err
	}
	var found *ebpf.Map
	var foundID ebpf.MapID
	for id := range related {
		candidate, err := ebpf.NewMapFromID(id)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if found != nil {
				found.Close()
			}
			return nil, 0, fmt.Errorf("open program-related map ID %d: %w", id, err)
		}
		info, err := candidate.Info()
		if err != nil {
			candidate.Close()
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if found != nil {
				found.Close()
			}
			return nil, 0, fmt.Errorf("inspect program-related map ID %d: %w", id, err)
		}
		if !matchesTarget(info) {
			candidate.Close()
			continue
		}
		if found != nil {
			candidate.Close()
			found.Close()
			return nil, 0, fmt.Errorf("multiple target maps are related to process map ID %d", processMapID)
		}
		found = candidate
		foundID = id
	}
	if found == nil {
		return nil, 0, fmt.Errorf("%w: process map ID %d", errNoRelatedTargetMap, processMapID)
	}
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
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, fmt.Errorf("open program ID %d: %w", id, err)
		}
		info, infoErr := program.Info()
		program.Close()
		if infoErr != nil {
			return nil, fmt.Errorf("inspect program ID %d: %w", id, infoErr)
		}
		mapIDs, available := info.MapIDs()
		if !available {
			return nil, fmt.Errorf("program map relationships are unavailable for program ID %d", id)
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
		return nil, fmt.Errorf("%w: map ID %d", errMapNotReferenced, targetID)
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

func readMatchingProcessIdentity(
	processes interface {
		Lookup(key, value interface{}) error
	},
	wantedPID, wantedNamespace uint32,
) (processIdentity, bool, error) {
	var key [processKeySize]byte
	var value [processValueSize]byte
	binary.LittleEndian.PutUint32(key[0:4], wantedPID)
	binary.LittleEndian.PutUint32(key[4:8], wantedPID)
	binary.LittleEndian.PutUint32(key[8:12], wantedNamespace)
	if err := processes.Lookup(key, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return processIdentity{}, false, nil
		}
		return processIdentity{}, false, fmt.Errorf("lookup controlled JVM in %s: %w", processMapName, err)
	}
	identity, err := decodeProcessIdentity(key[:], value[:])
	return identity, err == nil, err
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
	return info.Type == ebpf.Hash &&
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
	return info.Type == ebpf.Hash &&
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
	binary.LittleEndian.PutUint64(key[16:24], identity.incarnation)
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
	binary.LittleEndian.PutUint64(value[0:8], observedMonotimeNS|handoffOpenTag)
	binary.LittleEndian.PutUint64(value[8:16], incarnation)
	return value
}
