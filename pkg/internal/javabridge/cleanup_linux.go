// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javabridge // import "go.opentelemetry.io/obi/pkg/internal/javabridge"

import (
	"errors"
	"fmt"
	"time"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/ebpf/timing"
)

type cleanupIterator interface {
	Next(keyOut, valueOut any) bool
	Err() error
}

type lookupDeleteMap interface {
	Lookup(key, valueOut any) error
	Delete(key any) error
}

type cleanupMap interface {
	lookupDeleteMap
	Update(key, value any, flags ebpf.MapUpdateFlags) error
	Iterate() cleanupIterator
}

type kernelCleanupMap struct {
	*ebpf.Map
}

func (m kernelCleanupMap) Iterate() cleanupIterator {
	return m.Map.Iterate()
}

type cleanupMaps struct {
	remoteParents                  cleanupMap
	tasks                          cleanupMap
	virtualThreads                 cleanupMap
	vtIdentities                   cleanupMap
	incarnations                   cleanupMap
	connections                    cleanupMap
	cookieConnections              cleanupMap
	ambiguity                      cleanupMap
	owners                         cleanupMap
	states                         cleanupMap
	generations                    cleanupMap
	terminals                      cleanupMap
	claims                         cleanupMap
	handoffs                       cleanupMap
	handoffClaims                  cleanupMap
	retired                        cleanupMap
	sslPrewrite                    cleanupMap
	sslPrewriteConnectionAmbiguity cleanupMap
	sslPrewriteConnectionClaims    cleanupMap
	sslPrewriteConnectionOwners    cleanupMap
}

type Cleanup struct {
	maps        cleanupMaps
	ttl         time.Duration
	monoTimeNow func() time.Duration
	coordinator *GenerationCoordinator
}

// CleanupStats reports logical cleanup roots reclaimed by one sweep. Cleaned
// counts each generation once, using its index or an orphan state, owner, or
// fallback as the root, and counts standalone orphan records once. Records
// removed as part of the same generation cleanup are not counted again.
// Evicted is the subset of Cleaned generation indexes whose unexpired active
// generation had lost its exact fallback record.
type CleanupStats struct {
	Cleaned uint64
	Evicted uint64
}

type cleanupEntry[K, V any] struct {
	key   K
	value V
}

type handoffKey struct {
	PID       uint32
	Namespace uint32
	Token     uint64
}

type handoffClaimValue struct {
	ObservedMonotonicNS uint64
	ProcessIncarnation  uint64
}

type retiredProcessKey struct {
	Process            Identity
	Reserved           uint32
	ProcessIncarnation uint64
}

func NewCleanup(
	maps Maps,
	ttl time.Duration,
	coordinator *GenerationCoordinator,
) *Cleanup {
	if coordinator == nil {
		panic("nil Java generation coordinator")
	}
	wrap := func(m *ebpf.Map) cleanupMap {
		if m == nil {
			return nil
		}
		return kernelCleanupMap{Map: m}
	}

	return &Cleanup{
		maps: cleanupMaps{
			remoteParents:                  wrap(maps.RemoteParents),
			tasks:                          wrap(maps.Tasks),
			virtualThreads:                 wrap(maps.VirtualThreads),
			vtIdentities:                   wrap(maps.VTIdentities),
			incarnations:                   wrap(maps.Incarnations),
			connections:                    wrap(maps.Connections),
			cookieConnections:              wrap(maps.CookieConnections),
			ambiguity:                      wrap(maps.Ambiguity),
			owners:                         wrap(maps.Owners),
			states:                         wrap(maps.States),
			generations:                    wrap(maps.Generations),
			terminals:                      wrap(maps.Terminals),
			claims:                         wrap(maps.Claims),
			handoffs:                       wrap(maps.Handoffs),
			handoffClaims:                  wrap(maps.HandoffClaims),
			retired:                        wrap(maps.Retired),
			sslPrewrite:                    wrap(maps.SSLPrewriteTP),
			sslPrewriteConnectionAmbiguity: wrap(maps.SSLPrewriteConnectionAmbiguity),
			sslPrewriteConnectionClaims:    wrap(maps.SSLPrewriteConnectionClaims),
			sslPrewriteConnectionOwners:    wrap(maps.SSLPrewriteConnectionOwners),
		},
		ttl:         ttl,
		monoTimeNow: timing.MonoTimeNow,
		coordinator: coordinator,
	}
}

func (c *Cleanup) Sweep() error {
	_, err := c.SweepWithStats()
	return err
}

// SweepWithStats reclaims expired, retired, malformed, orphaned, and provably
// evicted bridge state. It reports successful reclamations even when another
// cleanup target returns an error during the same sweep.
func (c *Cleanup) SweepWithStats() (CleanupStats, error) {
	var stats CleanupStats
	if c == nil || !c.complete() {
		return stats, errors.New("java remote-parent cleanup maps are incomplete")
	}
	err := c.sweepSSLPrewrite()
	unlock := c.coordinator.lockCleanup()
	defer unlock()

	retiredEntries, retiredErr := cleanupMapEntries[retiredProcessKey, uint64](c.maps.retired)
	if retiredErr != nil {
		return stats, errors.Join(err, fmt.Errorf("iterating retired Java processes: %w", retiredErr))
	}
	retired := make(map[retiredProcessKey]struct{}, len(retiredEntries))
	for _, entry := range retiredEntries {
		if entry.key.Process == (Identity{}) || entry.key.Reserved != 0 ||
			entry.key.ProcessIncarnation == 0 || entry.value == 0 {
			deleted, deleteErr := cleanupDeleteExact(c.maps.retired, entry.key, entry.value)
			if deleted {
				stats.Cleaned++
			}
			if deleteErr != nil {
				err = errors.Join(err, fmt.Errorf("deleting malformed process retirement: %w", deleteErr))
			}
			continue
		}
		retired[entry.key] = struct{}{}
	}

	generationEntries, generationErr := cleanupMapEntries[stateKey, generationIndexValue](
		c.maps.generations,
	)
	if generationErr != nil {
		err = errors.Join(err, fmt.Errorf("iterating Java remote-parent generations: %w", generationErr))
	}
	generationNow := c.monoTimeNow()
	cleanedGenerations := make(map[stateKey]struct{})
	for _, entry := range generationEntries {
		processRetired, retirementErr := c.processRetired(
			retired, entry.value.Process, entry.value.ProcessIncarnation,
		)
		if retirementErr != nil {
			err = errors.Join(err, retirementErr)
			continue
		}
		expired := cleanupExpired(generationNow, entry.value.ObservedMonotonicNS, c.ttl)
		evicted := false
		if !processRetired && !expired {
			evicted, retirementErr = c.generationFallbackEvicted(entry.key, entry.value)
			if retirementErr != nil {
				err = errors.Join(err, retirementErr)
				continue
			}
			if !evicted {
				continue
			}
		}
		var cleaned bool
		var cleanupErr error
		if evicted {
			cleaned, cleanupErr = c.cleanupEvictedGeneration(entry.key, entry.value)
		} else {
			cleaned, cleanupErr = c.cleanupGeneration(entry.key, entry.value)
		}
		if cleaned {
			stats.recordGeneration(cleanedGenerations, entry.key, evicted)
		}
		if cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
			continue
		}
	}

	if sweepErr := c.sweepOrphans(retired, cleanedGenerations, &stats); sweepErr != nil {
		err = errors.Join(err, sweepErr)
	}
	if err != nil {
		return stats, err
	}

	for _, entry := range retiredEntries {
		if _, ok := retired[entry.key]; !ok {
			continue
		}
		deleted, deleteErr := cleanupDeleteExact(c.maps.retired, entry.key, entry.value)
		if deleted {
			stats.Cleaned++
		}
		if deleteErr != nil {
			err = errors.Join(err, fmt.Errorf("deleting process retirement: %w", deleteErr))
		}
	}
	return stats, err
}

func (s *CleanupStats) recordGeneration(
	cleaned map[stateKey]struct{},
	key stateKey,
	evicted bool,
) {
	if _, ok := cleaned[key]; ok {
		return
	}
	cleaned[key] = struct{}{}
	s.Cleaned++
	if evicted {
		s.Evicted++
	}
}

func (c *Cleanup) processRetired(
	retired map[retiredProcessKey]struct{},
	process Identity,
	processIncarnation uint64,
) (bool, error) {
	if _, ok := retired[retiredProcessKey{
		Process:            process,
		ProcessIncarnation: processIncarnation,
	}]; ok {
		return true, nil
	}
	var current uint64
	if err := c.maps.incarnations.Lookup(&process, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return true, nil
		}
		return false, fmt.Errorf("looking up Java process incarnation: %w", err)
	}
	return current != processIncarnation, nil
}

func (c *Cleanup) processCleanupSafe(
	process Identity,
	processIncarnation uint64,
) (bool, error) {
	var current uint64
	if err := c.maps.incarnations.Lookup(&process, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return true, nil
		}
		return false, fmt.Errorf("revalidating Java process incarnation: %w", err)
	}
	return current == processIncarnation, nil
}

func (c *Cleanup) complete() bool {
	return c.coordinator != nil && c.maps.remoteParents != nil && c.maps.tasks != nil &&
		c.maps.virtualThreads != nil && c.maps.vtIdentities != nil &&
		c.maps.incarnations != nil && c.maps.connections != nil &&
		c.maps.cookieConnections != nil &&
		c.maps.ambiguity != nil && c.maps.owners != nil && c.maps.states != nil &&
		c.maps.generations != nil && c.maps.terminals != nil && c.maps.claims != nil &&
		c.maps.handoffs != nil && c.maps.handoffClaims != nil && c.maps.retired != nil &&
		c.maps.sslPrewrite != nil && c.maps.sslPrewriteConnectionAmbiguity != nil &&
		c.maps.sslPrewriteConnectionClaims != nil && c.maps.sslPrewriteConnectionOwners != nil
}

func connectionCookieKey(
	connectionKey connectionInfoNS,
	connection connectionClaim,
) connectionInfoNetNSCookie {
	return connectionInfoNetNSCookie{
		Connection:  connectionKey.Connection,
		NetNSCookie: connection.NetNSCookie,
	}
}

func validConnectionClaim(
	connection connectionClaim,
	owner Identity,
	generation uint64,
	netns uint32,
) bool {
	return connection.Owner == owner && connection.Reserved == 0 &&
		connection.Generation == generation && connection.NetNSCookie != 0 &&
		connection.IncomingGeneration != 0 && connection.SocketCookie != 0 &&
		connection.NetNS == netns &&
		connection.Reserved2 == 0
}

func (c *Cleanup) deleteConnectionIndexes(
	connectionKey connectionInfoNS,
	connection connectionClaim,
) error {
	cookieKey := connectionCookieKey(connectionKey, connection)
	if _, err := cleanupDeleteExact(
		c.maps.cookieConnections, cookieKey, connection,
	); err != nil {
		return fmt.Errorf("deleting cookie connection: %w", err)
	}
	if _, err := cleanupDeleteExact(c.maps.connections, connectionKey, connection); err != nil {
		return fmt.Errorf("deleting connection: %w", err)
	}
	return nil
}

func (c *Cleanup) generationFallbackEvicted(
	key stateKey,
	index generationIndexValue,
) (bool, error) {
	if key.Generation == 0 || index.Process != javaProcessIdentity(key.Owner) ||
		index.Reserved != 0 || index.ProcessIncarnation == 0 ||
		index.ObservedMonotonicNS == 0 {
		return false, nil
	}

	var owner ownerValue
	if err := c.maps.owners.Lookup(&key.Owner, &owner); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("checking evicted generation owner: %w", err)
	}
	if owner.Generation != key.Generation ||
		owner.ProcessIncarnation != index.ProcessIncarnation ||
		owner.Lifecycle != lifecycleActive || owner.Reserved != ([7]byte{}) {
		return false, nil
	}

	var state stateValue
	if err := c.maps.states.Lookup(&key, &state); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("checking evicted generation state: %w", err)
	}
	if state.Lifecycle != lifecycleActive || state.Reserved != ([3]byte{}) ||
		state.ProcessIncarnation != index.ProcessIncarnation ||
		state.ObservedMonotonicNS != index.ObservedMonotonicNS {
		return false, nil
	}
	stateRecord, err := UnmarshalRecord(state.Response[:])
	if err != nil || !stateRecord.IsValidRemoteParent() ||
		stateRecord.Generation != key.Generation ||
		stateRecord.ObservedMonotonicNS != index.ObservedMonotonicNS {
		return false, nil
	}

	connectionKey := connectionInfoNS{
		Connection: state.Connection,
		NetNS:      state.ConnectionNetNS,
	}
	var connection connectionClaim
	if err := c.maps.connections.Lookup(&connectionKey, &connection); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("checking evicted generation connection: %w", err)
	}
	if !validConnectionClaim(connection, key.Owner, key.Generation, state.ConnectionNetNS) {
		return false, nil
	}
	var cookieConnection connectionClaim
	if err := c.maps.cookieConnections.Lookup(
		connectionCookieKey(connectionKey, connection), &cookieConnection,
	); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("checking evicted cookie connection: %w", err)
	}
	if cookieConnection != connection {
		return false, nil
	}
	if state.Aliases > 0 {
		return false, nil
	}

	var encoded [RecordSize]byte
	if err := c.maps.remoteParents.Lookup(&key.Owner, &encoded); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return true, nil
		}
		return false, fmt.Errorf("checking evicted generation fallback: %w", err)
	}
	record, err := UnmarshalRecord(encoded[:])
	if err != nil {
		return false, nil
	}
	return record.Generation != key.Generation, nil
}

func (c *Cleanup) cleanupGeneration(
	key stateKey,
	index generationIndexValue,
) (bool, error) {
	return c.cleanupGenerationChecked(key, index, false)
}

func (c *Cleanup) cleanupEvictedGeneration(
	key stateKey,
	index generationIndexValue,
) (bool, error) {
	return c.cleanupGenerationChecked(key, index, true)
}

func (c *Cleanup) cleanupGenerationChecked(
	key stateKey,
	index generationIndexValue,
	requireEvicted bool,
) (bool, error) {
	if key.Generation == 0 || index.Process != javaProcessIdentity(key.Owner) ||
		index.Reserved != 0 || index.ProcessIncarnation == 0 ||
		index.ObservedMonotonicNS == 0 {
		return cleanupDeleteExact(c.maps.generations, key, index)
	}

	var current generationIndexValue
	if lookupErr := c.maps.generations.Lookup(&key, &current); lookupErr != nil {
		if errors.Is(lookupErr, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("revalidating generation index: %w", lookupErr)
	}
	if current != index {
		return false, nil
	}
	claim, ok := c.newGenerationClaim(lifecycleStale, index.ProcessIncarnation)
	if !ok {
		return false, errors.New("reading monotonic time for generation cleanup claim")
	}
	claimed, claimErr := c.claimGenerationCleanup(key, claim)
	if claimErr != nil {
		return false, claimErr
	}
	if !claimed {
		return false, nil
	}
	defer func() {
		_, _ = cleanupDeleteExact(c.maps.claims, key, claim)
	}()

	preservedState, preserved, preservedErr := c.preservedGenerationWithoutCursor(key, index)
	if preservedErr != nil {
		return false, preservedErr
	}
	if requireEvicted && preserved && preservedState.Aliases > 0 {
		return false, nil
	}
	var owner ownerValue
	if !preserved {
		var locked bool
		var lockErr error
		owner, locked, lockErr = c.lockGenerationOwner(key, index.ProcessIncarnation)
		if lockErr != nil {
			return false, lockErr
		}
		if !locked {
			return false, nil
		}
	}
	if requireEvicted && !preserved {
		evicted, evictionErr := c.generationFallbackEvicted(key, index)
		if evictionErr != nil {
			return false, evictionErr
		}
		if !evicted {
			return false, nil
		}
	}

	var err error
	var state stateValue
	if lookupErr := c.maps.states.Lookup(&key, &state); lookupErr == nil {
		if state.ProcessIncarnation == index.ProcessIncarnation &&
			state.ObservedMonotonicNS == index.ObservedMonotonicNS {
			connectionKey := connectionInfoNS{
				Connection: state.Connection,
				NetNS:      state.ConnectionNetNS,
			}
			var connection connectionClaim
			if connectionErr := c.maps.connections.Lookup(&connectionKey, &connection); connectionErr == nil {
				if connection.Owner == key.Owner && connection.Generation == key.Generation {
					if deleteErr := c.deleteConnectionIndexes(
						connectionKey, connection,
					); deleteErr != nil {
						err = errors.Join(err, fmt.Errorf("deleting generation connection: %w", deleteErr))
					}
				}
			} else if !errors.Is(connectionErr, ebpf.ErrKeyNotExist) {
				err = errors.Join(err, fmt.Errorf("looking up generation connection: %w", connectionErr))
			}
			if _, deleteErr := cleanupDeleteExact(c.maps.states, key, state); deleteErr != nil {
				err = errors.Join(err, fmt.Errorf("deleting generation state: %w", deleteErr))
			}
		}
	} else if !errors.Is(lookupErr, ebpf.ErrKeyNotExist) {
		err = errors.Join(err, fmt.Errorf("looking up generation state: %w", lookupErr))
	}

	if deleteErr := c.deleteFallback(key); deleteErr != nil {
		err = errors.Join(err, deleteErr)
	}
	if deleteErr := c.deleteTerminal(key, index.ProcessIncarnation); deleteErr != nil {
		err = errors.Join(err, deleteErr)
	}
	if deleteErr := cleanupDeleteCurrent[stateKey, uint64](c.maps.ambiguity, key); deleteErr != nil {
		err = errors.Join(err, fmt.Errorf("deleting generation ambiguity marker: %w", deleteErr))
	}
	if err != nil {
		return false, err
	}

	deleted, deleteErr := cleanupDeleteExact(c.maps.generations, key, index)
	if deleteErr != nil {
		return false, fmt.Errorf("deleting generation index: %w", deleteErr)
	}
	if !deleted {
		return false, nil
	}
	if !preserved {
		if _, deleteErr := cleanupDeleteExact(c.maps.owners, key.Owner, owner); deleteErr != nil {
			return true, fmt.Errorf("deleting generation owner: %w", deleteErr)
		}
	}
	return deleted, nil
}

func (c *Cleanup) preservedGenerationWithoutCursor(
	key stateKey,
	index generationIndexValue,
) (stateValue, bool, error) {
	var state stateValue
	if err := c.maps.states.Lookup(&key, &state); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return stateValue{}, false, nil
		}
		return stateValue{}, false, fmt.Errorf("checking preserved generation state: %w", err)
	}
	if state.Lifecycle != lifecycleActive || state.Reserved != ([3]byte{}) ||
		state.ProcessIncarnation != index.ProcessIncarnation ||
		state.ObservedMonotonicNS != index.ObservedMonotonicNS {
		return stateValue{}, false, nil
	}

	var owner ownerValue
	if err := c.maps.owners.Lookup(&key.Owner, &owner); err == nil {
		if owner.Generation == key.Generation &&
			owner.ProcessIncarnation == index.ProcessIncarnation {
			return stateValue{}, false, nil
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return stateValue{}, false, fmt.Errorf("checking preserved generation owner: %w", err)
	}

	var encoded [RecordSize]byte
	if err := c.maps.remoteParents.Lookup(&key.Owner, &encoded); err == nil {
		record, decodeErr := UnmarshalRecord(encoded[:])
		if decodeErr != nil {
			return stateValue{}, false, nil
		}
		if record.Generation == key.Generation {
			return stateValue{}, false, nil
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return stateValue{}, false, fmt.Errorf("checking preserved generation fallback: %w", err)
	}

	return state, true, nil
}

func (c *Cleanup) claimGenerationCleanup(
	key stateKey,
	claim generationClaim,
) (bool, error) {
	if err := c.maps.claims.Update(&key, &claim, ebpf.UpdateNoExist); err == nil {
		return true, nil
	} else if !errors.Is(err, ebpf.ErrKeyExist) {
		return false, fmt.Errorf("claiming generation cleanup: %w", err)
	}

	var stale generationClaim
	if err := c.maps.claims.Lookup(&key, &stale); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("looking up stale generation claim: %w", err)
	}
	if stale.Reserved != ([7]byte{}) ||
		!cleanupExpired(c.monoTimeNow(), stale.ObservedMonotonicNS, c.ttl) {
		return false, nil
	}
	if _, err := cleanupDeleteExact(c.maps.claims, key, stale); err != nil {
		return false, fmt.Errorf("deleting stale generation claim: %w", err)
	}
	if err := c.maps.claims.Update(&key, &claim, ebpf.UpdateNoExist); err != nil {
		if errors.Is(err, ebpf.ErrKeyExist) {
			return false, nil
		}
		return false, fmt.Errorf("reclaiming generation cleanup: %w", err)
	}
	return true, nil
}

func (c *Cleanup) newGenerationClaim(
	lifecycle uint8,
	processIncarnation uint64,
) (generationClaim, bool) {
	now := c.monoTimeNow()
	if now <= 0 || processIncarnation == 0 {
		return generationClaim{}, false
	}
	return generationClaim{
		ObservedMonotonicNS: uint64(now),
		ProcessIncarnation:  processIncarnation,
		Lifecycle:           lifecycle,
	}, true
}

func (c *Cleanup) lockGenerationOwner(
	key stateKey,
	processIncarnation uint64,
) (ownerValue, bool, error) {
	var owner ownerValue
	if err := c.maps.owners.Lookup(&key.Owner, &owner); err == nil {
		if owner.Generation != key.Generation ||
			owner.ProcessIncarnation != processIncarnation {
			return ownerValue{}, false, nil
		}
		return owner, true, nil
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return ownerValue{}, false, fmt.Errorf("looking up generation owner: %w", err)
	}

	owner = ownerValue{
		Generation:         key.Generation,
		ProcessIncarnation: processIncarnation,
		Lifecycle:          lifecyclePublishing,
	}
	if err := c.maps.owners.Update(&key.Owner, &owner, ebpf.UpdateNoExist); err != nil {
		if errors.Is(err, ebpf.ErrKeyExist) {
			return ownerValue{}, false, nil
		}
		return ownerValue{}, false, fmt.Errorf("locking generation owner: %w", err)
	}
	return owner, true, nil
}

func (c *Cleanup) deleteFallback(key stateKey) error {
	var encoded [RecordSize]byte
	if err := c.maps.remoteParents.Lookup(&key.Owner, &encoded); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("looking up generation fallback: %w", err)
	}
	record, err := UnmarshalRecord(encoded[:])
	if err != nil || record.Generation != key.Generation {
		return nil
	}
	if _, err := cleanupDeleteExact(c.maps.remoteParents, key.Owner, encoded); err != nil {
		return fmt.Errorf("deleting generation fallback: %w", err)
	}
	return nil
}

func (c *Cleanup) deleteTerminal(key stateKey, processIncarnation uint64) error {
	var terminal terminalValue
	if err := c.maps.terminals.Lookup(&key.Owner, &terminal); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("looking up generation terminal: %w", err)
	}
	if terminal.Generation != key.Generation || terminal.ProcessIncarnation != processIncarnation {
		return nil
	}
	if _, err := cleanupDeleteExact(c.maps.terminals, key.Owner, terminal); err != nil {
		return fmt.Errorf("deleting generation terminal: %w", err)
	}
	return nil
}

func (c *Cleanup) sweepOrphans(
	retired map[retiredProcessKey]struct{},
	cleanedGenerations map[stateKey]struct{},
	stats *CleanupStats,
) error {
	var result error

	states, err := cleanupMapEntries[stateKey, stateValue](c.maps.states)
	if err != nil {
		result = errors.Join(result, fmt.Errorf("iterating generation states: %w", err))
	}
	statesNow := c.monoTimeNow()
	for _, entry := range states {
		processRetired, retirementErr := c.processRetired(
			retired,
			javaProcessIdentity(entry.key.Owner),
			entry.value.ProcessIncarnation,
		)
		if retirementErr != nil {
			result = errors.Join(result, retirementErr)
			continue
		}
		if !processRetired &&
			!cleanupExpired(statesNow, entry.value.ObservedMonotonicNS, c.ttl) {
			continue
		}
		cleaned, cleanupErr := c.cleanupOrphanState(entry.key, entry.value)
		if cleaned {
			stats.recordGeneration(cleanedGenerations, entry.key, false)
		}
		if cleanupErr != nil {
			result = errors.Join(result, cleanupErr)
			continue
		}
	}

	connections, err := cleanupMapEntries[connectionInfoNS, connectionClaim](c.maps.connections)
	if err != nil {
		result = errors.Join(result, fmt.Errorf("iterating generation connections: %w", err))
	}
	for _, entry := range connections {
		key := stateKey{Owner: entry.value.Owner, Generation: entry.value.Generation}
		if _, cleaned := cleanedGenerations[key]; !cleaned {
			continue
		}
		if deleteErr := c.deleteConnectionIndexes(entry.key, entry.value); deleteErr != nil {
			result = errors.Join(result, fmt.Errorf("deleting orphan connection: %w", deleteErr))
		}
	}
	cookieConnections, err := cleanupMapEntries[connectionInfoNetNSCookie, connectionClaim](
		c.maps.cookieConnections,
	)
	if err != nil {
		result = errors.Join(result, fmt.Errorf("iterating cookie generation connections: %w", err))
	}
	for _, entry := range cookieConnections {
		key := stateKey{Owner: entry.value.Owner, Generation: entry.value.Generation}
		if _, cleaned := cleanedGenerations[key]; !cleaned {
			continue
		}
		if _, deleteErr := cleanupDeleteExact(
			c.maps.cookieConnections, entry.key, entry.value,
		); deleteErr != nil {
			result = errors.Join(
				result, fmt.Errorf("deleting orphan cookie connection: %w", deleteErr),
			)
		}
	}

	// Task and handoff links are bounded by LRU maps, and BPF readers reject
	// stale generations. User space cannot conditionally delete these entries
	// without racing a BPF-side refresh of the same key.

	handoffClaims, err := cleanupMapEntries[handoffKey, handoffClaimValue](c.maps.handoffClaims)
	if err != nil {
		result = errors.Join(result, fmt.Errorf("iterating task handoff claims: %w", err))
	}
	handoffClaimsNow := c.monoTimeNow()
	for _, entry := range handoffClaims {
		process := Identity{
			TID:       entry.key.PID,
			PID:       entry.key.PID,
			Namespace: entry.key.Namespace,
		}
		processRetired, retirementErr := c.processRetired(
			retired, process, entry.value.ProcessIncarnation,
		)
		if retirementErr != nil {
			result = errors.Join(result, retirementErr)
			continue
		}
		if !processRetired &&
			!cleanupExpired(handoffClaimsNow, entry.value.ObservedMonotonicNS, c.ttl) {
			continue
		}
		cleanupSafe, safetyErr := c.processCleanupSafe(
			process, entry.value.ProcessIncarnation,
		)
		if safetyErr != nil {
			result = errors.Join(result, safetyErr)
			continue
		}
		if !cleanupSafe {
			continue
		}
		deleted, deleteErr := cleanupDeleteExact(
			c.maps.handoffClaims, entry.key, entry.value,
		)
		if deleted {
			stats.Cleaned++
		}
		if deleteErr != nil {
			result = errors.Join(result, fmt.Errorf("deleting task handoff claim: %w", deleteErr))
		}
	}

	terminals, err := cleanupMapEntries[Identity, terminalValue](c.maps.terminals)
	if err != nil {
		result = errors.Join(result, fmt.Errorf("iterating terminal generations: %w", err))
	}
	terminalsNow := c.monoTimeNow()
	for _, entry := range terminals {
		generation := stateKey{Owner: entry.key, Generation: entry.value.Generation}
		_, cleaned := cleanedGenerations[generation]
		processRetired, retirementErr := c.processRetired(
			retired,
			javaProcessIdentity(entry.key),
			entry.value.ProcessIncarnation,
		)
		if retirementErr != nil {
			result = errors.Join(result, retirementErr)
			continue
		}
		if !cleaned && !processRetired &&
			!cleanupExpired(terminalsNow, entry.value.ObservedMonotonicNS, c.ttl) {
			continue
		}
		cleaned, cleanupErr := c.cleanupOrphanOwner(entry.key, ownerValue{
			Generation:         entry.value.Generation,
			ProcessIncarnation: entry.value.ProcessIncarnation,
			Lifecycle:          entry.value.Lifecycle,
		})
		if cleaned {
			stats.recordGeneration(cleanedGenerations, generation, false)
		}
		if cleanupErr != nil {
			result = errors.Join(result, cleanupErr)
		}
	}

	ambiguity, err := cleanupMapEntries[stateKey, uint64](c.maps.ambiguity)
	if err != nil {
		result = errors.Join(result, fmt.Errorf("iterating ambiguity markers: %w", err))
	}
	ambiguityNow := c.monoTimeNow()
	for _, entry := range ambiguity {
		_, generationCleaned := cleanedGenerations[entry.key]
		if !generationCleaned && !cleanupExpired(ambiguityNow, entry.value, c.ttl) {
			continue
		}
		deleted, deleteErr := cleanupDeleteExact(c.maps.ambiguity, entry.key, entry.value)
		if deleted && !generationCleaned {
			stats.Cleaned++
		}
		if deleteErr != nil {
			result = errors.Join(result, fmt.Errorf("deleting ambiguity marker: %w", deleteErr))
		}
	}

	claims, err := cleanupMapEntries[stateKey, generationClaim](c.maps.claims)
	if err != nil {
		result = errors.Join(result, fmt.Errorf("iterating generation claims: %w", err))
	}
	claimsNow := c.monoTimeNow()
	for _, entry := range claims {
		if entry.value.Reserved != ([7]byte{}) ||
			!cleanupExpired(claimsNow, entry.value.ObservedMonotonicNS, c.ttl) {
			continue
		}
		_, generationCleaned := cleanedGenerations[entry.key]
		if !generationCleaned {
			var generation generationIndexValue
			lookupErr := c.maps.generations.Lookup(&entry.key, &generation)
			if lookupErr == nil {
				continue
			}
			if !errors.Is(lookupErr, ebpf.ErrKeyNotExist) {
				result = errors.Join(result, fmt.Errorf("checking claimed generation: %w", lookupErr))
				continue
			}
		}
		deleted, deleteErr := cleanupDeleteExact(c.maps.claims, entry.key, entry.value)
		if deleted && !generationCleaned {
			stats.Cleaned++
		}
		if deleteErr != nil {
			result = errors.Join(result, fmt.Errorf("deleting orphan generation claim: %w", deleteErr))
		}
	}

	owners, err := cleanupMapEntries[Identity, ownerValue](c.maps.owners)
	if err != nil {
		result = errors.Join(result, fmt.Errorf("iterating generation owners: %w", err))
	}
	for _, entry := range owners {
		generation := stateKey{Owner: entry.key, Generation: entry.value.Generation}
		_, cleaned := cleanedGenerations[generation]
		processRetired, retirementErr := c.processRetired(
			retired,
			javaProcessIdentity(entry.key),
			entry.value.ProcessIncarnation,
		)
		if retirementErr != nil {
			result = errors.Join(result, retirementErr)
			continue
		}
		if !cleaned && !processRetired {
			continue
		}
		cleaned, cleanupErr := c.cleanupOrphanOwner(entry.key, entry.value)
		if cleaned {
			stats.recordGeneration(cleanedGenerations, generation, false)
		}
		if cleanupErr != nil {
			result = errors.Join(result, cleanupErr)
		}
	}

	parents, err := cleanupMapEntries[Identity, [RecordSize]byte](c.maps.remoteParents)
	if err != nil {
		result = errors.Join(result, fmt.Errorf("iterating fallback parents: %w", err))
	}
	parentsNow := c.monoTimeNow()
	for _, entry := range parents {
		record, decodeErr := UnmarshalRecord(entry.value[:])
		if decodeErr != nil {
			var malformedGeneration stateKey
			var indexed ownerValue
			if ownerErr := c.maps.owners.Lookup(&entry.key, &indexed); ownerErr == nil &&
				indexed.Generation != 0 && indexed.ProcessIncarnation != 0 {
				malformedGeneration = stateKey{
					Owner: entry.key, Generation: indexed.Generation,
				}
			}
			cleaned, quarantineErr := c.quarantineMalformedFallback(entry.key, entry.value)
			if cleaned {
				if malformedGeneration != (stateKey{}) {
					stats.recordGeneration(cleanedGenerations, malformedGeneration, false)
				} else {
					stats.Cleaned++
				}
			}
			if quarantineErr != nil {
				result = errors.Join(result, quarantineErr)
			}
			continue
		}
		_, cleaned := cleanedGenerations[stateKey{
			Owner: entry.key, Generation: record.Generation,
		}]
		if cleaned || !cleanupExpired(parentsNow, record.ObservedMonotonicNS, c.ttl) {
			continue
		}
		key := stateKey{Owner: entry.key, Generation: record.Generation}
		var generation generationIndexValue
		if generationErr := c.maps.generations.Lookup(&key, &generation); generationErr == nil {
			generationCleaned, cleanupErr := c.cleanupGeneration(key, generation)
			if generationCleaned {
				stats.recordGeneration(cleanedGenerations, key, false)
			}
			if cleanupErr != nil {
				result = errors.Join(result, cleanupErr)
			}
			continue
		} else if !errors.Is(generationErr, ebpf.ErrKeyNotExist) {
			result = errors.Join(result, fmt.Errorf("looking up fallback generation: %w", generationErr))
			continue
		}
		var state stateValue
		if stateErr := c.maps.states.Lookup(&key, &state); stateErr == nil {
			stateCleaned, cleanupErr := c.cleanupOrphanState(key, state)
			if stateCleaned {
				stats.recordGeneration(cleanedGenerations, key, false)
			}
			if cleanupErr != nil {
				result = errors.Join(result, cleanupErr)
			}
			continue
		} else if !errors.Is(stateErr, ebpf.ErrKeyNotExist) {
			result = errors.Join(result, fmt.Errorf("looking up fallback state: %w", stateErr))
			continue
		}
		fallbackCleaned, cleanupErr := c.cleanupOrphanFallback(entry.key, entry.value, record)
		if fallbackCleaned {
			stats.recordGeneration(cleanedGenerations, key, false)
		}
		if cleanupErr != nil {
			result = errors.Join(result, cleanupErr)
		}
	}

	return result
}

func (c *Cleanup) cleanupOrphanOwner(
	owner Identity,
	indexed ownerValue,
) (bool, error) {
	if indexed.Generation == 0 || indexed.ProcessIncarnation == 0 {
		return false, nil
	}
	key := stateKey{Owner: owner, Generation: indexed.Generation}
	var generation generationIndexValue
	if err := c.maps.generations.Lookup(&key, &generation); err == nil {
		return c.cleanupGeneration(key, generation)
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("looking up orphan owner generation: %w", err)
	}
	var state stateValue
	if err := c.maps.states.Lookup(&key, &state); err == nil {
		return c.cleanupOrphanState(key, state)
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("looking up orphan owner state: %w", err)
	}

	claim, ok := c.newGenerationClaim(lifecycleStale, indexed.ProcessIncarnation)
	if !ok {
		return false, errors.New("reading monotonic time for orphan owner claim")
	}
	claimed, err := c.claimGenerationCleanup(key, claim)
	if err != nil || !claimed {
		return false, err
	}
	defer func() {
		_, _ = cleanupDeleteExact(c.maps.claims, key, claim)
	}()
	lockedOwner, locked, err := c.lockGenerationOwner(key, indexed.ProcessIncarnation)
	if err != nil || !locked {
		return false, err
	}
	if err := c.deleteFallback(key); err != nil {
		return false, err
	}
	if err := c.deleteTerminal(key, indexed.ProcessIncarnation); err != nil {
		return false, err
	}
	if err := cleanupDeleteCurrent[stateKey, uint64](c.maps.ambiguity, key); err != nil {
		return false, fmt.Errorf("deleting orphan owner ambiguity marker: %w", err)
	}
	deleted, err := cleanupDeleteExact(c.maps.owners, owner, lockedOwner)
	if err != nil {
		return false, fmt.Errorf("deleting orphan generation owner: %w", err)
	}
	return deleted, nil
}

func (c *Cleanup) cleanupOrphanFallback(
	owner Identity,
	encoded [RecordSize]byte,
	record Record,
) (bool, error) {
	key := stateKey{Owner: owner, Generation: record.Generation}
	var indexed ownerValue
	if err := c.maps.owners.Lookup(&owner, &indexed); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, fmt.Errorf("looking up orphan fallback owner: %w", err)
		}
		lock := ownerValue{Generation: record.Generation, Lifecycle: lifecyclePublishing}
		if lockErr := c.maps.owners.Update(&owner, &lock, ebpf.UpdateNoExist); lockErr != nil {
			if errors.Is(lockErr, ebpf.ErrKeyExist) {
				return false, nil
			}
			return false, fmt.Errorf("locking orphan fallback owner: %w", lockErr)
		}
		defer func() {
			_, _ = cleanupDeleteExact(c.maps.owners, owner, lock)
		}()
		return cleanupDeleteExact(c.maps.remoteParents, owner, encoded)
	}
	if indexed.Generation != record.Generation || indexed.ProcessIncarnation == 0 {
		return false, nil
	}
	claim, ok := c.newGenerationClaim(lifecycleStale, indexed.ProcessIncarnation)
	if !ok {
		return false, errors.New("reading monotonic time for orphan fallback claim")
	}
	claimed, err := c.claimGenerationCleanup(key, claim)
	if err != nil || !claimed {
		return false, err
	}
	defer func() {
		_, _ = cleanupDeleteExact(c.maps.claims, key, claim)
	}()
	var revalidated ownerValue
	if err := c.maps.owners.Lookup(&owner, &revalidated); err != nil {
		return false, ignoreMissing(err)
	}
	if revalidated != indexed {
		return false, nil
	}
	deleted, deleteErr := cleanupDeleteExact(c.maps.remoteParents, owner, encoded)
	if deleteErr != nil {
		return false, fmt.Errorf("deleting orphan fallback: %w", deleteErr)
	}
	if !deleted {
		return false, nil
	}
	if err := c.deleteTerminal(key, indexed.ProcessIncarnation); err != nil {
		return true, err
	}
	if err := cleanupDeleteCurrent[stateKey, uint64](c.maps.ambiguity, key); err != nil {
		return true, fmt.Errorf("deleting orphan fallback ambiguity marker: %w", err)
	}
	if _, err := cleanupDeleteExact(c.maps.owners, owner, indexed); err != nil {
		return true, fmt.Errorf("deleting orphan fallback owner: %w", err)
	}
	return true, nil
}

func (c *Cleanup) quarantineMalformedFallback(
	owner Identity,
	encoded [RecordSize]byte,
) (bool, error) {
	var indexed ownerValue
	if err := c.maps.owners.Lookup(&owner, &indexed); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, fmt.Errorf("looking up malformed fallback owner: %w", err)
		}
		lock := ownerValue{Lifecycle: lifecyclePublishing}
		if lockErr := c.maps.owners.Update(&owner, &lock, ebpf.UpdateNoExist); lockErr != nil {
			if errors.Is(lockErr, ebpf.ErrKeyExist) {
				return false, nil
			}
			return false, fmt.Errorf("locking malformed fallback owner: %w", lockErr)
		}
		defer func() {
			_, _ = cleanupDeleteExact(c.maps.owners, owner, lock)
		}()
		deleted, deleteErr := cleanupDeleteExact(c.maps.remoteParents, owner, encoded)
		if deleteErr != nil {
			return false, fmt.Errorf("deleting malformed fallback: %w", deleteErr)
		}
		return deleted, nil
	}
	if indexed.Generation == 0 || indexed.Reserved != ([7]byte{}) ||
		indexed.ProcessIncarnation == 0 {
		deleted, deleteErr := cleanupDeleteExact(c.maps.remoteParents, owner, encoded)
		if deleteErr != nil {
			return false, fmt.Errorf("deleting malformed fallback: %w", deleteErr)
		}
		if deleted {
			_, deleteErr = cleanupDeleteExact(c.maps.owners, owner, indexed)
		}
		return deleted, deleteErr
	}

	key := stateKey{Owner: owner, Generation: indexed.Generation}
	claim, ok := c.newGenerationClaim(lifecycleDiscarded, indexed.ProcessIncarnation)
	if !ok {
		return false, errors.New("reading monotonic time for malformed fallback claim")
	}
	if claimErr := c.maps.claims.Update(&key, &claim, ebpf.UpdateNoExist); claimErr != nil {
		if errors.Is(claimErr, ebpf.ErrKeyExist) {
			return false, nil
		}
		return false, fmt.Errorf("claiming malformed fallback generation: %w", claimErr)
	}
	claimed := true
	defer func() {
		if claimed {
			_, _ = cleanupDeleteExact(c.maps.claims, key, claim)
		}
	}()
	var revalidated ownerValue
	if ownerErr := c.maps.owners.Lookup(&owner, &revalidated); ownerErr != nil {
		if errors.Is(ownerErr, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("revalidating malformed fallback owner: %w", ownerErr)
	}
	if revalidated != indexed {
		return false, nil
	}

	var generation generationIndexValue
	generationErr := c.maps.generations.Lookup(&key, &generation)
	if generationErr != nil && !errors.Is(generationErr, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("looking up malformed fallback generation: %w", generationErr)
	}
	deleted, deleteErr := cleanupDeleteExact(c.maps.remoteParents, owner, encoded)
	if deleteErr != nil {
		return false, fmt.Errorf("deleting malformed fallback: %w", deleteErr)
	}
	if !deleted {
		return false, nil
	}
	if _, releaseErr := cleanupDeleteExact(c.maps.claims, key, claim); releaseErr != nil {
		return true, fmt.Errorf("releasing malformed fallback claim: %w", releaseErr)
	}
	claimed = false
	if generationErr == nil && generation.Process == javaProcessIdentity(owner) &&
		generation.Reserved == 0 &&
		generation.ProcessIncarnation == indexed.ProcessIncarnation {
		_, cleanupErr := c.cleanupGeneration(key, generation)
		return true, cleanupErr
	}

	var state stateValue
	if stateErr := c.maps.states.Lookup(&key, &state); stateErr == nil &&
		state.ProcessIncarnation == indexed.ProcessIncarnation {
		_, cleanupErr := c.cleanupOrphanState(key, state)
		return true, cleanupErr
	} else if stateErr != nil && !errors.Is(stateErr, ebpf.ErrKeyNotExist) {
		return true, fmt.Errorf("looking up malformed fallback state: %w", stateErr)
	}

	if claimErr := c.maps.claims.Update(&key, &claim, ebpf.UpdateNoExist); claimErr != nil {
		if errors.Is(claimErr, ebpf.ErrKeyExist) {
			return true, nil
		}
		return true, fmt.Errorf("claiming malformed fallback owner: %w", claimErr)
	}
	defer func() {
		_, _ = cleanupDeleteExact(c.maps.claims, key, claim)
	}()
	if err := c.deleteTerminal(key, indexed.ProcessIncarnation); err != nil {
		return true, err
	}
	if err := cleanupDeleteCurrent[stateKey, uint64](c.maps.ambiguity, key); err != nil {
		return true, fmt.Errorf("deleting malformed fallback ambiguity marker: %w", err)
	}
	_, deleteErr = cleanupDeleteExact(c.maps.owners, owner, indexed)
	return true, deleteErr
}

func (c *Cleanup) cleanupOrphanState(key stateKey, state stateValue) (bool, error) {
	var indexed generationIndexValue
	if err := c.maps.generations.Lookup(&key, &indexed); err == nil {
		return c.cleanupGeneration(key, indexed)
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("looking up orphan generation index: %w", err)
	}
	claim, ok := c.newGenerationClaim(lifecycleStale, state.ProcessIncarnation)
	if !ok {
		return false, errors.New("reading monotonic time for orphan generation claim")
	}
	claimed, claimErr := c.claimGenerationCleanup(key, claim)
	if claimErr != nil {
		return false, claimErr
	}
	if !claimed {
		return false, nil
	}
	defer func() {
		_, _ = cleanupDeleteExact(c.maps.claims, key, claim)
	}()
	_, preserved, preservedErr := c.preservedGenerationWithoutCursor(key, generationIndexValue{
		Process:             javaProcessIdentity(key.Owner),
		ProcessIncarnation:  state.ProcessIncarnation,
		ObservedMonotonicNS: state.ObservedMonotonicNS,
	})
	if preservedErr != nil {
		return false, preservedErr
	}
	var owner ownerValue
	if !preserved {
		var locked bool
		var lockErr error
		owner, locked, lockErr = c.lockGenerationOwner(key, state.ProcessIncarnation)
		if lockErr != nil {
			return false, lockErr
		}
		if !locked {
			return false, nil
		}
	}

	var result error
	connectionKey := connectionInfoNS{
		Connection: state.Connection,
		NetNS:      state.ConnectionNetNS,
	}
	var connection connectionClaim
	if err := c.maps.connections.Lookup(&connectionKey, &connection); err == nil {
		if connection.Owner == key.Owner && connection.Generation == key.Generation {
			if deleteErr := c.deleteConnectionIndexes(
				connectionKey, connection,
			); deleteErr != nil {
				result = errors.Join(result, fmt.Errorf("deleting orphan connection: %w", deleteErr))
			}
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		result = errors.Join(result, fmt.Errorf("looking up orphan connection: %w", err))
	}
	stateDeleted, stateDeleteErr := cleanupDeleteExact(c.maps.states, key, state)
	if stateDeleteErr != nil {
		result = errors.Join(result, fmt.Errorf("deleting orphan state: %w", stateDeleteErr))
	}
	if err := c.deleteFallback(key); err != nil {
		result = errors.Join(result, err)
	}
	if err := c.deleteTerminal(key, state.ProcessIncarnation); err != nil {
		result = errors.Join(result, err)
	}
	if err := cleanupDeleteCurrent[stateKey, uint64](c.maps.ambiguity, key); err != nil {
		result = errors.Join(result, fmt.Errorf("deleting orphan ambiguity marker: %w", err))
	}
	if result != nil {
		return stateDeleted, result
	}
	if !preserved {
		if _, err := cleanupDeleteExact(c.maps.owners, key.Owner, owner); err != nil {
			result = errors.Join(result, fmt.Errorf("deleting orphan generation owner: %w", err))
		}
	}
	return stateDeleted, result
}

func cleanupMapEntries[K, V any](m cleanupMap) ([]cleanupEntry[K, V], error) {
	iterator := m.Iterate()
	entries := make([]cleanupEntry[K, V], 0)
	var key K
	var value V
	for iterator.Next(&key, &value) {
		entries = append(entries, cleanupEntry[K, V]{key: key, value: value})
	}
	return entries, iterator.Err()
}

func cleanupDeleteCurrent[K, V comparable](m cleanupMap, key K) error {
	var current V
	if err := m.Lookup(&key, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return err
	}
	_, err := cleanupDeleteExact(m, key, current)
	return err
}

func cleanupDeleteExact[K, V comparable](m lookupDeleteMap, key K, expected V) (bool, error) {
	var current V
	if err := m.Lookup(&key, &current); err != nil {
		return false, ignoreMissing(err)
	}
	if current != expected {
		return false, nil
	}

	var revalidated V
	if err := m.Lookup(&key, &revalidated); err != nil {
		return false, ignoreMissing(err)
	}
	if revalidated != expected {
		return false, nil
	}
	if err := m.Delete(&key); err != nil {
		return false, ignoreMissing(err)
	}
	return true, nil
}

func ignoreMissing(err error) error {
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

func cleanupExpired(now time.Duration, observedMonotonicNS uint64, ttl time.Duration) bool {
	if now <= 0 || observedMonotonicNS == 0 || uint64(now) < observedMonotonicNS {
		return true
	}
	return ttl > 0 && time.Duration(uint64(now)-observedMonotonicNS) > ttl
}
