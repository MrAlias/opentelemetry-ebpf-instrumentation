// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
)

const (
	cursorMapName       = "jrp_recv_cur"
	guardMapName        = "jrp_recv_guard"
	targetKeySize       = 8
	targetValueSize     = 56
	targetMaxEntries    = 10_000
	maximumSnapshotKeys = targetMaxEntries
)

type targetShape struct {
	name string
}

var (
	cursorTarget = targetShape{name: cursorMapName}
	guardTarget  = targetShape{name: guardMapName}
)

type config struct {
	cursorMapID        uint
	guardMapID         uint
	expectedMaxEntries uint
}

type result struct {
	Status string `json:"status"`

	CursorMapID      uint   `json:"cursor_map_id"`
	CursorMapName    string `json:"cursor_map_name"`
	CursorKernelName string `json:"cursor_kernel_name"`
	CursorMapType    string `json:"cursor_map_type"`
	CursorKeySize    uint32 `json:"cursor_key_size"`
	CursorValueSize  uint32 `json:"cursor_value_size"`
	CursorMaxEntries uint32 `json:"cursor_max_entries"`
	CursorEntries    uint32 `json:"cursor_entries"`

	GuardMapID      uint   `json:"guard_map_id"`
	GuardMapName    string `json:"guard_map_name"`
	GuardKernelName string `json:"guard_kernel_name"`
	GuardMapType    string `json:"guard_map_type"`
	GuardKeySize    uint32 `json:"guard_key_size"`
	GuardValueSize  uint32 `json:"guard_value_size"`
	GuardMaxEntries uint32 `json:"guard_max_entries"`
	GuardEntries    uint32 `json:"guard_entries"`
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
	flag.UintVar(&cfg.cursorMapID, "cursor-map-id", 0, "previously discovered cursor map ID")
	flag.UintVar(&cfg.guardMapID, "guard-map-id", 0, "previously discovered guard map ID")
	flag.UintVar(
		&cfg.expectedMaxEntries,
		"expected-max-entries",
		0,
		"previously observed capacity shared by both maps",
	)
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
	if uint64(cfg.cursorMapID) > uint64(^uint32(0)) {
		return errors.New("cursor-map-id exceeds 32 bits")
	}
	if uint64(cfg.guardMapID) > uint64(^uint32(0)) {
		return errors.New("guard-map-id exceeds 32 bits")
	}
	if uint64(cfg.expectedMaxEntries) > uint64(^uint32(0)) {
		return errors.New("expected-max-entries exceeds 32 bits")
	}
	if (cfg.cursorMapID == 0) != (cfg.guardMapID == 0) {
		return errors.New("cursor-map-id and guard-map-id must be provided together")
	}
	if cfg.cursorMapID != 0 && cfg.cursorMapID == cfg.guardMapID {
		return errors.New("cursor-map-id and guard-map-id must be distinct")
	}
	if cfg.cursorMapID == 0 && cfg.expectedMaxEntries != 0 {
		return errors.New("expected-max-entries requires both map IDs")
	}
	if cfg.cursorMapID != 0 && cfg.expectedMaxEntries == 0 {
		return errors.New("both map IDs require expected-max-entries")
	}
	if cfg.expectedMaxEntries != 0 && cfg.expectedMaxEntries != targetMaxEntries {
		return fmt.Errorf("expected-max-entries must be %d", targetMaxEntries)
	}
	return nil
}

func run(cfg config) (result, error) {
	if err := validateConfig(cfg); err != nil {
		return result{}, err
	}

	cursor, cursorMapID, err := openTargetMap(cursorTarget, ebpf.MapID(cfg.cursorMapID))
	if err != nil {
		return result{}, err
	}
	defer cursor.Close()

	guard, guardMapID, err := openTargetMap(guardTarget, ebpf.MapID(cfg.guardMapID))
	if err != nil {
		return result{}, err
	}
	defer guard.Close()
	if cursorMapID == guardMapID {
		return result{}, fmt.Errorf("%s and %s resolved to the same map ID %d", cursorMapName, guardMapName, cursorMapID)
	}

	cursorInfo, err := cursor.Info()
	if err != nil {
		return result{}, fmt.Errorf("inspect %s map ID %d: %w", cursorMapName, cursorMapID, err)
	}
	if err := validateTarget(cursorInfo, cursorTarget, uint32(cfg.expectedMaxEntries)); err != nil {
		return result{}, err
	}
	guardInfo, err := guard.Info()
	if err != nil {
		return result{}, fmt.Errorf("inspect %s map ID %d: %w", guardMapName, guardMapID, err)
	}
	if err := validateTarget(guardInfo, guardTarget, uint32(cfg.expectedMaxEntries)); err != nil {
		return result{}, err
	}

	cursorEntries, err := countEntries(cursor, cursorTarget, cursorInfo.MaxEntries)
	if err != nil {
		return result{}, err
	}
	guardEntries, err := countEntries(guard, guardTarget, guardInfo.MaxEntries)
	if err != nil {
		return result{}, err
	}

	return result{
		Status: "passed",

		CursorMapID:      uint(cursorMapID),
		CursorMapName:    cursorMapName,
		CursorKernelName: cursorInfo.Name,
		CursorMapType:    cursorInfo.Type.String(),
		CursorKeySize:    cursorInfo.KeySize,
		CursorValueSize:  cursorInfo.ValueSize,
		CursorMaxEntries: cursorInfo.MaxEntries,
		CursorEntries:    cursorEntries,

		GuardMapID:      uint(guardMapID),
		GuardMapName:    guardMapName,
		GuardKernelName: guardInfo.Name,
		GuardMapType:    guardInfo.Type.String(),
		GuardKeySize:    guardInfo.KeySize,
		GuardValueSize:  guardInfo.ValueSize,
		GuardMaxEntries: guardInfo.MaxEntries,
		GuardEntries:    guardEntries,
	}, nil
}

func openTargetMap(target targetShape, requested ebpf.MapID) (*ebpf.Map, ebpf.MapID, error) {
	if requested != 0 {
		candidate, err := ebpf.NewMapFromID(requested)
		if err != nil {
			return nil, 0, fmt.Errorf("open %s map ID %d: %w", target.name, requested, err)
		}
		return candidate, requested, nil
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
		if err != nil || !matchesTarget(info, target) {
			candidate.Close()
			continue
		}
		if found != nil {
			candidate.Close()
			found.Close()
			return nil, 0, fmt.Errorf("multiple live maps match %s", target.name)
		}
		found = candidate
		foundID = id
	}
	if found == nil {
		return nil, 0, fmt.Errorf("live map %s was not found", target.name)
	}
	return found, foundID, nil
}

func matchesTarget(info *ebpf.MapInfo, target targetShape) bool {
	return info.Type == ebpf.Hash &&
		info.KeySize == targetKeySize &&
		info.ValueSize == targetValueSize &&
		info.MaxEntries == targetMaxEntries &&
		info.Name == target.name
}

func validateTarget(info *ebpf.MapInfo, target targetShape, expectedMaxEntries uint32) error {
	if !matchesTarget(info, target) {
		return fmt.Errorf(
			"map does not match %s layout: type=%s key=%d value=%d max_entries=%d name=%q",
			target.name,
			info.Type,
			info.KeySize,
			info.ValueSize,
			info.MaxEntries,
			info.Name,
		)
	}
	if expectedMaxEntries != 0 && info.MaxEntries != expectedMaxEntries {
		return fmt.Errorf(
			"%s map capacity mismatch: expected %d, got %d",
			target.name,
			expectedMaxEntries,
			info.MaxEntries,
		)
	}
	return nil
}

type entryIterator interface {
	Next(keyOut, valueOut any) bool
	Err() error
}

func countEntries(targetMap *ebpf.Map, target targetShape, maximum uint32) (uint32, error) {
	return countIteratorEntries(targetMap.Iterate(), target, maximum)
}

func countIteratorEntries(iterator entryIterator, target targetShape, maximum uint32) (uint32, error) {
	if maximum == 0 || maximum > maximumSnapshotKeys {
		return 0, fmt.Errorf("%s map capacity %d is outside the bounded snapshot range", target.name, maximum)
	}
	var key [targetKeySize]byte
	var value [targetValueSize]byte
	var entries uint32
	for iterator.Next(&key, &value) {
		if entries == maximum {
			return 0, fmt.Errorf("%s map iteration exceeded declared capacity %d", target.name, maximum)
		}
		entries++
	}
	if err := iterator.Err(); err != nil {
		return 0, fmt.Errorf("iterate %s: %w", target.name, err)
	}
	return entries, nil
}
