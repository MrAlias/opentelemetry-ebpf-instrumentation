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
	mapID              uint
	expectedMaxEntries uint
	mode               string
	seed               uint
	processPID         uint
	processNamespace   uint
	tokenBase          uint64
}

type result struct {
	Status           string `json:"status"`
	Mode             string `json:"mode"`
	MapID            uint   `json:"map_id"`
	MapName          string `json:"map_name"`
	KernelName       string `json:"kernel_name"`
	MapType          string `json:"map_type"`
	MaxEntries       uint32 `json:"max_entries"`
	ProcessMapID     uint   `json:"process_map_id"`
	ProcessPID       uint32 `json:"process_pid"`
	ProcessNamespace uint32 `json:"process_namespace"`
	TokenBase        uint64 `json:"token_base"`
	Touched          uint32 `json:"touched"`
	FirstEvicted     bool   `json:"first_evicted,omitempty"`
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
	flag.StringVar(&cfg.mode, "mode", "fill", "fill or cleanup")
	flag.UintVar(&cfg.seed, "seed", 1, "deterministic synthetic key seed")
	flag.UintVar(&cfg.processPID, "process-pid", 0, "captured live JVM process ID for cleanup")
	flag.UintVar(
		&cfg.processNamespace,
		"process-namespace",
		0,
		"captured live JVM PID namespace for cleanup",
	)
	flag.Uint64Var(&cfg.tokenBase, "token-base", 0, "captured synthetic token base for cleanup")
	flag.Parse()

	if flag.NArg() != 0 {
		return config{}, errors.New("unexpected positional arguments")
	}
	if cfg.expectedMaxEntries > maxPressureEntries {
		return config{}, fmt.Errorf(
			"expected-max-entries must not exceed %d",
			maxPressureEntries,
		)
	}
	if cfg.mode != "fill" && cfg.mode != "cleanup" {
		return config{}, errors.New("mode must be fill or cleanup")
	}
	if cfg.mode == "fill" &&
		(cfg.processPID != 0 || cfg.processNamespace != 0 || cfg.tokenBase != 0) {
		return config{}, errors.New("cleanup identity flags are only valid in cleanup mode")
	}
	if cfg.mode == "cleanup" &&
		(cfg.processPID == 0 || cfg.processNamespace == 0 || cfg.tokenBase == 0) {
		return config{}, errors.New("cleanup requires process-pid, process-namespace, and token-base")
	}
	return cfg, nil
}

func run(cfg config) (result, error) {
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
	var identity processIdentity
	var processMapID ebpf.MapID
	tokenBase := cfg.tokenBase
	if cfg.mode == "fill" {
		processes, discoveredMapID, openErr := openProcessMap()
		if openErr != nil {
			return result{}, openErr
		}
		defer processes.Close()
		identity, err = readProcessIdentity(processes)
		if err != nil {
			return result{}, err
		}
		processMapID = discoveredMapID
		tokenBase, err = newTokenBase(uint64(cfg.seed), info.MaxEntries+1)
		if err != nil {
			return result{}, err
		}
	} else {
		identity.pid = uint32(cfg.processPID)
		identity.namespace = uint32(cfg.processNamespace)
		if uint(identity.pid) != cfg.processPID || uint(identity.namespace) != cfg.processNamespace {
			return result{}, errors.New("cleanup process identity exceeds 32 bits")
		}
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
	entryCount := info.MaxEntries + 1
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
		_, firstErr := target.LookupBytes(syntheticKey(identity, tokenBase, 0))
		if !errors.Is(firstErr, ebpf.ErrKeyNotExist) {
			cleanupFailedFill()
			return result{}, fmt.Errorf("oldest synthetic entry was not evicted: %w", firstErr)
		}
		if _, err := target.LookupBytes(syntheticKey(identity, tokenBase, info.MaxEntries)); err != nil {
			cleanupFailedFill()
			return result{}, fmt.Errorf("newest synthetic entry is missing: %w", err)
		}
		output.FirstEvicted = true
	}
	return output, nil
}

func openProcessMap() (*ebpf.Map, ebpf.MapID, error) {
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
			return nil, 0, fmt.Errorf("enumerate process maps after ID %d: %w", id, err)
		}
		id = next
		candidate, err := ebpf.NewMapFromID(id)
		if err != nil {
			continue
		}
		info, err := candidate.Info()
		if err != nil || !matchesProcessMap(info) {
			candidate.Close()
			continue
		}
		if found != nil {
			candidate.Close()
			found.Close()
			return nil, 0, fmt.Errorf("multiple live maps match %s", processMapName)
		}
		found = candidate
		foundID = id
	}
	if found == nil {
		return nil, 0, fmt.Errorf("live map %s was not found", processMapName)
	}
	return found, foundID, nil
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

func newTokenBase(seed uint64, entryCount uint32) (uint64, error) {
	var source [8]byte
	if _, err := rand.Read(source[:]); err != nil {
		return 0, fmt.Errorf("generate synthetic token namespace: %w", err)
	}
	maximumBase := ^uint64(0) - uint64(entryCount)
	return (binary.LittleEndian.Uint64(source[:])^seed)%maximumBase + 1, nil
}

func claimValue(observedMonotimeNS, incarnation uint64) []byte {
	value := make([]byte, targetValueSize)
	binary.LittleEndian.PutUint64(value[0:8], observedMonotimeNS)
	binary.LittleEndian.PutUint64(value[8:16], incarnation)
	return value
}
