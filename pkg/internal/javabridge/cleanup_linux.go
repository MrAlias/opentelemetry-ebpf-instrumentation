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
	ownerGuards                    cleanupMap
	handoffs                       cleanupMap
	handoffClaims                  cleanupMap
	retired                        cleanupMap
	sslPrewrite                    cleanupMap
	sslPrewriteConnectionAmbiguity cleanupMap
	sslPrewriteConnectionClaims    cleanupMap
	sslPrewriteConnectionOwners    cleanupMap
}

type Cleanup struct {
	maps                        cleanupMaps
	ttl                         time.Duration
	monoTimeNow                 func() time.Duration
	physicalGenerations         map[stateKey]struct{}
	physicalGenerationsByOwner  map[Identity][]stateKey
	deferPhysicalGenerationScan bool
	currentSweepClaims          map[stateKey]generationClaim
	currentSweepGuards          map[Identity]generationClaim
	releasedSweepClaims         map[stateKey]generationClaim
	releasedSweepGuards         map[Identity]generationClaim
	releasedSweepAmbiguities    map[stateKey]uint64
	currentSweepAmbiguities     map[stateKey]uint64
	knownGenerations            map[stateKey]struct{}
	knownGenerationsByOwner     map[Identity][]stateKey
	knownLogicalKeys            map[stateKey]struct{}
	knownLogicalKeysByOwner     map[Identity][]stateKey
	generationSnapshotComplete  bool
	stateSnapshotComplete       bool
	coordinator                 *GenerationCoordinator
}

const javaRemoteParentMinimumFenceAge = time.Second

// CleanupStats reports logical cleanup roots reclaimed by one sweep. Cleaned
// counts each generation once, using its index or an orphan state, owner, or
// fallback as the root, and counts standalone orphan records once. Records
// removed as part of the same generation cleanup are not counted again.
// Evicted counts newly initiated cleanup fences for unexpired active
// generations that had lost their exact fallback record. Cleanup itself may
// complete in a later sweep after the fence ages, so Evicted is not required
// to coincide with Cleaned in the same call.
type CleanupStats struct {
	Cleaned uint64
	Evicted uint64
}

type cleanupEntry[K, V any] struct {
	key   K
	value V
}

type generationCleanupOwnership struct {
	claim          generationClaim
	inheritedFence bool
	ambiguity      uint64
	hasAmbiguity   bool
	fence          generationTeardownFence
	ready          bool
}

type generationCleanupRootRevalidator func() (bool, error)

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
			ownerGuards:                    wrap(maps.OwnerGuards),
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
	sweep := *c
	sweep.physicalGenerations = nil
	sweep.physicalGenerationsByOwner = nil
	sweep.deferPhysicalGenerationScan = false
	sweep.currentSweepClaims = make(map[stateKey]generationClaim)
	sweep.currentSweepGuards = make(map[Identity]generationClaim)
	sweep.releasedSweepClaims = make(map[stateKey]generationClaim)
	sweep.releasedSweepGuards = make(map[Identity]generationClaim)
	sweep.releasedSweepAmbiguities = make(map[stateKey]uint64)
	sweep.currentSweepAmbiguities = make(map[stateKey]uint64)
	sweep.knownGenerations = make(map[stateKey]struct{})
	sweep.knownGenerationsByOwner = make(map[Identity][]stateKey)
	sweep.knownLogicalKeys = make(map[stateKey]struct{})
	sweep.knownLogicalKeysByOwner = make(map[Identity][]stateKey)
	c = &sweep

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
	c.generationSnapshotComplete = generationErr == nil
	if generationErr != nil {
		err = errors.Join(err, fmt.Errorf("iterating Java remote-parent generations: %w", generationErr))
	}
	stateEntries, stateErr := cleanupMapEntries[stateKey, stateValue](c.maps.states)
	c.stateSnapshotComplete = stateErr == nil
	connectionEntries, connectionErr := cleanupMapEntries[connectionInfoNS, connectionClaim](
		c.maps.connections,
	)
	cookieConnectionEntries, cookieConnectionErr := cleanupMapEntries[
		connectionInfoNetNSCookie, connectionClaim,
	](c.maps.cookieConnections)
	c.deferPhysicalGenerationScan = connectionErr != nil || cookieConnectionErr != nil
	if !c.deferPhysicalGenerationScan {
		c.physicalGenerations = make(map[stateKey]struct{})
		c.physicalGenerationsByOwner = make(map[Identity][]stateKey)
		addPhysicalGeneration := func(key stateKey) {
			if _, exists := c.physicalGenerations[key]; exists {
				return
			}
			c.physicalGenerations[key] = struct{}{}
			c.physicalGenerationsByOwner[key.Owner] = append(
				c.physicalGenerationsByOwner[key.Owner], key,
			)
			c.recordKnownGeneration(key)
		}
		for _, entry := range connectionEntries {
			addPhysicalGeneration(stateKey{
				Owner: entry.value.Owner, Generation: entry.value.Generation,
			})
		}
		for _, entry := range cookieConnectionEntries {
			addPhysicalGeneration(stateKey{
				Owner: entry.value.Owner, Generation: entry.value.Generation,
			})
		}
	}
	for _, entry := range generationEntries {
		c.recordKnownLogicalKey(entry.key)
		c.recordKnownGeneration(entry.key)
	}
	for _, entry := range stateEntries {
		c.recordKnownLogicalKey(entry.key)
		c.recordKnownGeneration(entry.key)
	}
	if handoffErr := c.recoverGoGenerationProducerHandoffs(); handoffErr != nil {
		err = errors.Join(err, handoffErr)
	}

	generationNow := c.monoTimeNow()
	cleanedGenerations := make(map[stateKey]struct{})
	for _, entry := range generationEntries {
		if entry.key.Generation == 0 || entry.key.Reserved != 0 {
			cleaned, cleanupErr := c.cleanupMalformedGenerationKey(entry.key, entry.value)
			if cleaned {
				stats.recordGeneration(
					cleanedGenerations, canonicalGenerationKey(entry.key), false,
				)
			}
			if cleanupErr != nil {
				err = errors.Join(err, cleanupErr)
			}
			continue
		}
		processRetired, retirementErr := c.processRetired(
			retired, entry.value.Process, entry.value.ProcessIncarnation,
		)
		if retirementErr != nil {
			err = errors.Join(err, retirementErr)
			continue
		}
		if !processRetired {
			_, coherentReservation, reservationErr :=
				c.coherentGenerationPublishingReservation(entry.key)
			if reservationErr != nil {
				err = errors.Join(err, reservationErr)
				continue
			}
			if coherentReservation {
				continue
			}
		}
		expired := cleanupExpired(generationNow, entry.value.ObservedMonotonicNS, c.ttl)
		evicted := false
		if !processRetired && !expired {
			evicted, _, retirementErr = c.generationFallbackEvicted(entry.key, entry.value)
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
		if evicted {
			if claim, started := c.currentSweepClaims[entry.key]; started &&
				validGenerationCleanupClaim(claim) {
				stats.Evicted++
			}
		}
		if cleaned {
			stats.recordGeneration(cleanedGenerations, entry.key, false)
		}
		if cleanupErr != nil {
			err = errors.Join(err, cleanupErr)
			continue
		}
	}

	if sweepErr := c.sweepOrphans(
		retired, cleanedGenerations, &stats, stateEntries, stateErr,
		connectionEntries, connectionErr, cookieConnectionEntries, cookieConnectionErr,
	); sweepErr != nil {
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
		c.maps.ownerGuards != nil &&
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

func validGenerationConnection(connection connectionInfo) bool {
	// Match BPF's is_empty_connection_info predicate. Addresses may be zero for
	// valid endpoint shapes, but the producer never publishes both ports as zero.
	return connection.SourcePort != 0 || connection.DestinationPort != 0
}

func (c *Cleanup) deleteConnectionIndexesWithOwnership(
	ownership generationCleanupOwnership,
	connectionKey connectionInfoNS,
	connection connectionClaim,
) (bool, error) {
	cookieKey := connectionCookieKey(connectionKey, connection)
	cookieDeleted, err := c.mutateGenerationCleanupFenced(
		ownership, "cookie connection deletion", func() (bool, error) {
			return cleanupDeleteExact(c.maps.cookieConnections, cookieKey, connection)
		},
	)
	if err != nil {
		return cookieDeleted, fmt.Errorf("deleting owned cookie connection: %w", err)
	}
	connectionDeleted, err := c.mutateGenerationCleanupFenced(
		ownership, "netns connection deletion", func() (bool, error) {
			return cleanupDeleteExact(c.maps.connections, connectionKey, connection)
		},
	)
	if err != nil {
		return cookieDeleted || connectionDeleted,
			fmt.Errorf("deleting owned netns connection: %w", err)
	}
	return cookieDeleted || connectionDeleted, nil
}

func (c *Cleanup) deleteConnectionIndexesFenced(
	key stateKey,
	connectionKey connectionInfoNS,
	connection connectionClaim,
	now time.Duration,
) (bool, error) {
	authorized, err := c.generationCleanupPhysicalFenceAuthorizes(key, now)
	if err != nil || !authorized {
		return false, err
	}
	cookieKey := connectionCookieKey(connectionKey, connection)
	cookieDeleted, err := cleanupDeleteExact(c.maps.cookieConnections, cookieKey, connection)
	if err != nil {
		return cookieDeleted, fmt.Errorf("deleting fenced cookie connection: %w", err)
	}
	authorized, err = c.generationCleanupPhysicalFenceAuthorizes(key, now)
	if err != nil {
		return cookieDeleted, err
	}
	if !authorized {
		return cookieDeleted, errors.New("generation teardown fence changed after cookie delete")
	}
	connectionDeleted, err := cleanupDeleteExact(c.maps.connections, connectionKey, connection)
	if err != nil {
		return cookieDeleted || connectionDeleted,
			fmt.Errorf("deleting fenced connection: %w", err)
	}
	authorized, err = c.generationCleanupPhysicalFenceAuthorizes(key, now)
	if err != nil {
		return cookieDeleted || connectionDeleted, err
	}
	if !authorized {
		return cookieDeleted || connectionDeleted,
			errors.New("generation teardown fence changed after connection delete")
	}
	return cookieDeleted || connectionDeleted, nil
}

func (c *Cleanup) generationFallbackEvicted(
	key stateKey,
	index generationIndexValue,
) (bool, bool, error) {
	if key.Generation == 0 || index.Process != javaProcessIdentity(key.Owner) ||
		index.Reserved != 0 || index.ProcessIncarnation == 0 ||
		index.ObservedMonotonicNS == 0 {
		return false, false, nil
	}

	var owner ownerValue
	if err := c.maps.owners.Lookup(&key.Owner, &owner); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, false, nil
		}
		return false, false, fmt.Errorf("checking evicted generation owner: %w", err)
	}
	if owner.Generation != key.Generation ||
		owner.ProcessIncarnation != index.ProcessIncarnation ||
		owner.Lifecycle != lifecycleActive || owner.Reserved != ([7]byte{}) {
		return false, false, nil
	}

	var state stateValue
	if err := c.maps.states.Lookup(&key, &state); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, false, nil
		}
		return false, false, fmt.Errorf("checking evicted generation state: %w", err)
	}
	if state.Lifecycle != lifecycleActive || state.Reserved != ([3]byte{}) ||
		state.ProcessIncarnation != index.ProcessIncarnation ||
		state.ObservedMonotonicNS != index.ObservedMonotonicNS ||
		state.ConnectionNetNS == 0 || !validGenerationConnection(state.Connection) {
		return false, false, nil
	}
	stateRecord, err := UnmarshalRecord(state.Response[:])
	if err != nil || !stateRecord.IsValidRemoteParent() ||
		stateRecord.Generation != key.Generation ||
		stateRecord.ObservedMonotonicNS != index.ObservedMonotonicNS {
		return false, false, nil
	}

	connectionKey := connectionInfoNS{
		Connection: state.Connection,
		NetNS:      state.ConnectionNetNS,
	}
	var connection connectionClaim
	if err := c.maps.connections.Lookup(&connectionKey, &connection); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, false, nil
		}
		return false, false, fmt.Errorf("checking evicted generation connection: %w", err)
	}
	if !validConnectionClaim(connection, key.Owner, key.Generation, state.ConnectionNetNS) {
		return false, false, nil
	}
	var cookieConnection connectionClaim
	if err := c.maps.cookieConnections.Lookup(
		connectionCookieKey(connectionKey, connection), &cookieConnection,
	); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, false, nil
		}
		return false, false, fmt.Errorf("checking evicted cookie connection: %w", err)
	}
	if cookieConnection != connection {
		return false, false, nil
	}
	if state.Aliases > 0 {
		return false, false, nil
	}

	var encoded [RecordSize]byte
	if err := c.maps.remoteParents.Lookup(&key.Owner, &encoded); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return true, false, nil
		}
		return false, false, fmt.Errorf("checking evicted generation fallback: %w", err)
	}
	record, err := UnmarshalRecord(encoded[:])
	if err != nil {
		return false, false, nil
	}
	if record.Generation != key.Generation {
		return true, false, nil
	}
	if !record.IsValidRemoteParent() ||
		record.ObservedMonotonicNS != index.ObservedMonotonicNS {
		return false, false, nil
	}

	var current generationIndexValue
	if err := c.maps.generations.Lookup(&key, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, false, nil
		}
		return false, false, fmt.Errorf("checking coherent generation index: %w", err)
	}
	return false, current == index, nil
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
) (cleaned bool, result error) {
	if key.Generation == 0 || key.Reserved != 0 {
		return c.cleanupMalformedGenerationKey(key, index)
	}
	if index.Process != javaProcessIdentity(key.Owner) || index.Reserved != 0 ||
		index.ProcessIncarnation == 0 || index.ObservedMonotonicNS == 0 {
		ownership, ready, err := c.claimGenerationCleanupForArtifact(
			key, index.ProcessIncarnation, lifecycleStale,
			func() (bool, error) {
				return cleanupExactMatches(c.maps.generations, key, index)
			},
		)
		if err != nil || !ready {
			return false, err
		}
		deleted, deleteErr := c.mutateGenerationCleanupFenced(
			ownership, "malformed generation-index deletion", func() (bool, error) {
				return cleanupDeleteExact(c.maps.generations, key, index)
			},
		)
		if deleteErr != nil || !deleted {
			return false, deleteErr
		}
		complete, completeErr := c.generationCleanupLogicalComplete(key)
		if completeErr != nil {
			return false, fmt.Errorf("verifying malformed generation logical cleanup: %w", completeErr)
		}
		return complete, nil
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
	if requireEvicted {
		evicted, _, evictionErr := c.generationFallbackEvicted(key, index)
		if evictionErr != nil {
			return false, evictionErr
		}
		if !evicted {
			return false, nil
		}
	}
	ownership, claimed, claimErr := c.claimGenerationCleanupForArtifact(
		key, index.ProcessIncarnation, lifecycleStale, func() (bool, error) {
			return cleanupExactMatches(c.maps.generations, key, index)
		},
	)
	if claimErr != nil {
		return false, claimErr
	}
	if !claimed {
		return false, nil
	}
	if fenced, fenceErr := generationTeardownFenceMatches(
		c.maps.claims, c.maps.ownerGuards, c.maps.ambiguity, ownership.fence,
	); fenceErr != nil {
		return false, fmt.Errorf("revalidating generation cleanup fence: %w", fenceErr)
	} else if !fenced {
		return false, nil
	}
	mutationStarted := false
	releaseOwnership := false
	defer func() {
		if !mutationStarted && releaseOwnership && result == nil {
			releaseErr := c.releaseGenerationCleanupOwnership(key, ownership)
			if releaseErr != nil {
				result = errors.Join(result, fmt.Errorf("releasing generation cleanup claim: %w", releaseErr))
			}
		}
	}()

	preservedState, preserved, preservedErr := c.preservedGenerationWithoutCursor(key, index)
	if preservedErr != nil {
		return false, preservedErr
	}
	if requireEvicted && preserved && preservedState.Aliases > 0 {
		releaseOwnership = true
		return false, nil
	}
	var owner ownerValue
	detachedOwner := false
	if !preserved {
		var locked bool
		var ownerInserted bool
		var lockErr error
		owner, locked, ownerInserted, detachedOwner, lockErr = c.lockGenerationOwner(
			key, index.ProcessIncarnation, ownership,
		)
		mutationStarted = mutationStarted || ownerInserted
		if lockErr != nil {
			return false, lockErr
		}
		if fenced, fenceErr := c.generationCleanupFenceMatches(ownership); fenceErr != nil {
			return false, fmt.Errorf("revalidating generation fence after owner lock: %w", fenceErr)
		} else if !fenced {
			return false, errors.New("generation fence changed after owner lock")
		}
		if !locked {
			releaseOwnership = true
			return false, nil
		}
	}
	if requireEvicted && !preserved {
		evicted, coherent, evictionErr := c.generationFallbackEvicted(key, index)
		if evictionErr != nil {
			return false, evictionErr
		}
		if !evicted {
			releaseOwnership = coherent
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
					fenced, fenceErr := c.generationCleanupFenceMatches(ownership)
					if fenceErr != nil {
						return false, fenceErr
					}
					if !fenced {
						return false, errors.New("generation fence changed before connection deletion")
					}
					connectionDeleted, deleteErr := c.deleteConnectionIndexesWithOwnership(
						ownership, connectionKey, connection,
					)
					mutationStarted = mutationStarted || connectionDeleted
					if deleteErr != nil {
						err = errors.Join(err, fmt.Errorf("deleting generation connection: %w", deleteErr))
					}
				}
			} else if !errors.Is(connectionErr, ebpf.ErrKeyNotExist) {
				err = errors.Join(err, fmt.Errorf("looking up generation connection: %w", connectionErr))
			}
			fenced, fenceErr := c.generationCleanupFenceMatches(ownership)
			if fenceErr != nil {
				return false, errors.Join(err, fenceErr)
			}
			if !fenced {
				return false, errors.Join(
					err, errors.New("generation fence changed after connection deletion"),
				)
			}
			stateDeleted, deleteErr := c.mutateGenerationCleanupFenced(
				ownership, "state deletion", func() (bool, error) {
					return cleanupDeleteExact(c.maps.states, key, state)
				},
			)
			mutationStarted = mutationStarted || stateDeleted
			if deleteErr != nil {
				err = errors.Join(err, fmt.Errorf("deleting generation state: %w", deleteErr))
			}
		}
	} else if !errors.Is(lookupErr, ebpf.ErrKeyNotExist) {
		err = errors.Join(err, fmt.Errorf("looking up generation state: %w", lookupErr))
	}

	fenced, fenceErr := c.generationCleanupFenceMatches(ownership)
	if fenceErr != nil {
		return false, errors.Join(err, fenceErr)
	}
	if !fenced {
		return false, errors.Join(
			err, errors.New("generation fence changed after state deletion"),
		)
	}
	fallbackDeleted, deleteErr := c.mutateGenerationCleanupFenced(
		ownership, "fallback deletion", func() (bool, error) {
			return c.deleteFallback(key)
		},
	)
	mutationStarted = mutationStarted || fallbackDeleted
	if deleteErr != nil {
		err = errors.Join(err, deleteErr)
	}
	fenced, fenceErr = c.generationCleanupFenceMatches(ownership)
	if fenceErr != nil {
		return false, errors.Join(err, fenceErr)
	}
	if !fenced {
		return false, errors.Join(
			err, errors.New("generation fence changed after fallback deletion"),
		)
	}
	terminalDeleted, deleteErr := c.mutateGenerationCleanupFenced(
		ownership, "terminal deletion", func() (bool, error) {
			return c.deleteTerminal(key, index.ProcessIncarnation)
		},
	)
	mutationStarted = mutationStarted || terminalDeleted
	if deleteErr != nil {
		err = errors.Join(err, deleteErr)
	}
	if err != nil {
		return false, err
	}
	nonIndexAbsent, nonIndexErr := c.generationCleanupPayloadArtifactsAbsent(key)
	if nonIndexErr != nil {
		return false, nonIndexErr
	}
	if !nonIndexAbsent {
		// Keep the canonical index/owner roots until malformed or replaced
		// singleton artifacts have been handled under the same full fence.
		return false, nil
	}
	physicalAbsent, physicalErr := c.generationCleanupPhysicalArtifactsAbsent(key)
	if physicalErr != nil {
		return false, physicalErr
	}
	if !physicalAbsent {
		// Keep the generation index as the durable root until a complete
		// connection/cookie snapshot proves that every physical alias is gone.
		return false, nil
	}
	if fenced, fenceErr := generationTeardownFenceMatches(
		c.maps.claims, c.maps.ownerGuards, c.maps.ambiguity, ownership.fence,
	); fenceErr != nil {
		return false, fmt.Errorf("revalidating generation fence before index delete: %w", fenceErr)
	} else if !fenced {
		return false, nil
	}

	deleted, deleteErr := c.mutateGenerationCleanupFenced(
		ownership, "generation-index deletion", func() (bool, error) {
			return cleanupDeleteExact(c.maps.generations, key, index)
		},
	)
	mutationStarted = mutationStarted || deleted
	if deleteErr != nil {
		return false, fmt.Errorf("deleting generation index: %w", deleteErr)
	}
	if !deleted {
		releaseOwnership = true
		return false, nil
	}
	if !preserved && !detachedOwner {
		fenced, fenceErr := c.generationCleanupFenceMatches(ownership)
		if fenceErr != nil {
			return false, fenceErr
		}
		if !fenced {
			return false, errors.New("generation fence changed after generation-index deletion")
		}
		ownerDeleted, deleteErr := c.mutateGenerationCleanupFenced(
			ownership, "owner deletion", func() (bool, error) {
				return cleanupDeleteExact(c.maps.owners, key.Owner, owner)
			},
		)
		mutationStarted = mutationStarted || ownerDeleted
		if deleteErr != nil {
			return false, fmt.Errorf("deleting generation owner: %w", deleteErr)
		}
	}
	complete, completeErr := c.finishGenerationCleanup(key)
	if completeErr != nil {
		return false, fmt.Errorf("verifying generation cleanup: %w", completeErr)
	}
	if !complete {
		return false, nil
	}
	return true, nil
}

func (c *Cleanup) cleanupMalformedGenerationKey(
	key stateKey,
	index generationIndexValue,
) (bool, error) {
	if key.Generation != 0 && key.Reserved == 0 {
		return false, errors.New("refusing valid key in malformed generation-key cleanup")
	}
	// BPF never creates generation-zero or reserved-key entries. They do not
	// alias the canonical reusable key, so deleting the exact malformed entry
	// neither requires nor creates a canonical generation fence.
	deleted, err := cleanupDeleteExact(c.maps.generations, key, index)
	if err != nil {
		return false, fmt.Errorf("deleting malformed generation key: %w", err)
	}
	if !deleted {
		return false, nil
	}
	complete, completeErr := c.finishMalformedLogicalKeyCleanup(key)
	if completeErr != nil {
		return false, fmt.Errorf("verifying malformed generation-key cleanup: %w", completeErr)
	}
	return complete, nil
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

func (c *Cleanup) coherentDetachedAlias(
	key stateKey,
	index generationIndexValue,
) (bool, error) {
	if key.Generation == 0 || key.Reserved != 0 ||
		index.Process != javaProcessIdentity(key.Owner) || index.Reserved != 0 ||
		index.ProcessIncarnation == 0 || index.ObservedMonotonicNS == 0 {
		return false, nil
	}

	var state stateValue
	if err := c.maps.states.Lookup(&key, &state); err != nil {
		return false, ignoreMissing(err)
	}
	if state.Lifecycle != lifecycleActive || state.Reserved != ([3]byte{}) ||
		state.Aliases == 0 || state.ProcessIncarnation != index.ProcessIncarnation ||
		state.ObservedMonotonicNS != index.ObservedMonotonicNS || state.ConnectionNetNS == 0 ||
		!validGenerationConnection(state.Connection) {
		return false, nil
	}
	record, err := UnmarshalRecord(state.Response[:])
	if err != nil || !record.IsValidRemoteParent() ||
		record.Generation != key.Generation ||
		record.ObservedMonotonicNS != state.ObservedMonotonicNS {
		return false, nil
	}

	var owner ownerValue
	if err := c.maps.owners.Lookup(&key.Owner, &owner); err == nil {
		if owner.Generation == key.Generation {
			return false, nil
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking detached publishing-tail owner: %w", err)
	}

	var encoded [RecordSize]byte
	if err := c.maps.remoteParents.Lookup(&key.Owner, &encoded); err == nil {
		fallback, decodeErr := UnmarshalRecord(encoded[:])
		if decodeErr != nil || fallback.Generation == key.Generation {
			return false, nil
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking detached publishing-tail fallback: %w", err)
	}

	var terminal terminalValue
	if err := c.maps.terminals.Lookup(&key.Owner, &terminal); err == nil {
		if terminal.Generation == key.Generation {
			return false, nil
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking detached publishing-tail terminal: %w", err)
	}

	physicalAbsent, err := c.generationCleanupPhysicalArtifactsAbsent(key)
	if err != nil || !physicalAbsent {
		return false, err
	}
	connectionKey := connectionInfoNS{
		Connection: state.Connection,
		NetNS:      state.ConnectionNetNS,
	}
	var connection connectionClaim
	if err := c.maps.connections.Lookup(&connectionKey, &connection); err == nil {
		if connection.Owner == key.Owner && connection.Generation == key.Generation {
			return false, nil
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking detached publishing-tail connection: %w", err)
	}

	indexMatches, err := cleanupExactMatches(c.maps.generations, key, index)
	if err != nil || !indexMatches {
		return false, err
	}
	return cleanupExactMatches(c.maps.states, key, state)
}

func (c *Cleanup) claimGenerationCleanup(
	key stateKey,
	claim generationClaim,
	revalidateRoot ...generationCleanupRootRevalidator,
) (generationCleanupOwnership, bool, error) {
	if key.Generation == 0 || key.Reserved != 0 || !validGenerationCleanupClaim(claim) {
		return generationCleanupOwnership{}, false, errors.New("invalid generation cleanup claim")
	}
	if len(revalidateRoot) > 1 {
		return generationCleanupOwnership{}, false,
			errors.New("multiple generation cleanup root revalidators")
	}
	var rootRevalidator generationCleanupRootRevalidator
	if len(revalidateRoot) == 1 {
		rootRevalidator = revalidateRoot[0]
	}
	if rootRevalidator != nil {
		matches, err := rootRevalidator()
		if err != nil || !matches {
			return generationCleanupOwnership{}, false, err
		}
	}
	guard, guardCreated, guarded, err := c.acquireOrAdoptGenerationCleanupGuard(key)
	if err != nil || !guarded {
		return generationCleanupOwnership{}, false, err
	}
	if rootRevalidator != nil {
		matches, err := rootRevalidator()
		if err != nil || !matches {
			return generationCleanupOwnership{}, false, err
		}
	}
	guardMatches, err := generationGuardMatches(c.maps.ownerGuards, key.Owner, guard)
	if err != nil || !guardMatches {
		return generationCleanupOwnership{}, false, err
	}
	ownership := generationCleanupOwnership{claim: claim}
	if err := c.maps.claims.Update(&key, &claim, ebpf.UpdateNoExist); err == nil {
		c.recordCurrentSweepClaim(key, claim)
	} else if !errors.Is(err, ebpf.ErrKeyExist) {
		return generationCleanupOwnership{}, false, fmt.Errorf("claiming generation cleanup: %w", err)
	} else {
		var existing generationClaim
		if err := c.maps.claims.Lookup(&key, &existing); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return generationCleanupOwnership{}, false, nil
			}
			return generationCleanupOwnership{}, false,
				fmt.Errorf("looking up existing generation cleanup claim: %w", err)
		}
		if !validGenerationCleanupClaim(existing) {
			return generationCleanupOwnership{}, false, nil
		}
		ownership.claim = existing
		ownership.inheritedFence = true
	}

	completed, ready, err := c.acquireOrAdoptGenerationTeardownFence(
		key, ownership, guard, guardCreated, rootRevalidator,
	)
	if err != nil {
		return generationCleanupOwnership{}, false, err
	}
	if !ready {
		return completed, false, nil
	}
	completed.ready = true
	return completed, true, nil
}

func (c *Cleanup) acquireOrAdoptGenerationCleanupGuard(
	key stateKey,
) (generationClaim, bool, bool, error) {
	now := c.monoTimeNow()
	if key.Generation == 0 || key.Reserved != 0 || now <= 0 {
		return generationClaim{}, false, false,
			errors.New("invalid generation cleanup guard acquisition")
	}
	guardKey := key.Owner
	guard := generationClaim{
		ObservedMonotonicNS: uint64(now),
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecyclePublishing},
	}
	var current generationClaim
	if err := c.maps.ownerGuards.Lookup(&guardKey, &current); err == nil {
		if !validGenerationCleanupGuard(guardKey, current) ||
			current.ProcessIncarnation != key.Generation {
			return generationClaim{}, false, false, nil
		}
		return current, false, true, nil
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return generationClaim{}, false, false,
			fmt.Errorf("checking generation cleanup guard: %w", err)
	}
	if err := c.maps.ownerGuards.Update(&guardKey, &guard, ebpf.UpdateNoExist); err != nil {
		if errors.Is(err, ebpf.ErrKeyExist) {
			return generationClaim{}, false, false, nil
		}
		return generationClaim{}, false, false,
			fmt.Errorf("publishing generation cleanup guard: %w", err)
	}
	c.recordCurrentSweepGuard(guardKey, guard)
	return guard, true, true, nil
}

func (c *Cleanup) claimGenerationCleanupForArtifact(
	key stateKey,
	processIncarnation uint64,
	lifecycle uint8,
	revalidateRoot ...generationCleanupRootRevalidator,
) (generationCleanupOwnership, bool, error) {
	var existing generationClaim
	if err := c.maps.claims.Lookup(&key, &existing); err == nil {
		if !validGenerationCleanupClaim(existing) {
			return generationCleanupOwnership{}, false, nil
		}
		return c.claimGenerationCleanup(key, existing, revalidateRoot...)
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return generationCleanupOwnership{}, false,
			fmt.Errorf("checking retained generation cleanup claim: %w", err)
	}
	if processIncarnation == 0 {
		// Malformed artifacts can lose their producer incarnation. The claim's
		// incarnation is an opaque collision token, not deletion authority, so a
		// canonical generation is a safe synthetic token only while one exact,
		// independently revalidated artifact remains the cleanup root.
		if key.Generation == 0 || len(revalidateRoot) != 1 || revalidateRoot[0] == nil {
			return generationCleanupOwnership{}, false, nil
		}
		processIncarnation = key.Generation
	}
	claim, ok := c.newGenerationClaim(lifecycle, processIncarnation)
	if !ok {
		return generationCleanupOwnership{}, false,
			errors.New("reading monotonic time for generation artifact claim")
	}
	return c.claimGenerationCleanup(key, claim, revalidateRoot...)
}

func (c *Cleanup) acquireOrAdoptGenerationTeardownFence(
	key stateKey,
	ownership generationCleanupOwnership,
	guard generationClaim,
	guardCreated bool,
	revalidateRoot generationCleanupRootRevalidator,
) (generationCleanupOwnership, bool, error) {
	now := c.monoTimeNow()
	if now <= 0 {
		return ownership, false, errors.New("reading monotonic time for generation teardown fence")
	}
	claimMatches, err := generationClaimMatches(c.maps.claims, key, ownership.claim)
	if err != nil || !claimMatches {
		return ownership, false, err
	}

	guardKey := key.Owner
	guardMatches, err := generationGuardMatches(c.maps.ownerGuards, guardKey, guard)
	if err != nil || !guardMatches {
		return ownership, false, err
	}
	var currentAmbiguity uint64
	ambiguityErr := c.maps.ambiguity.Lookup(&key, &currentAmbiguity)
	needsAmbiguity := errors.Is(ambiguityErr, ebpf.ErrKeyNotExist) ||
		(ambiguityErr == nil && currentAmbiguity == 0)
	if ambiguityErr != nil && !errors.Is(ambiguityErr, ebpf.ErrKeyNotExist) {
		return ownership, false, fmt.Errorf("checking generation cleanup ambiguity: %w", ambiguityErr)
	}
	if needsAmbiguity {
		if revalidateRoot == nil {
			// E/G without M can be a producer handoff or release tail. Only an
			// independently selected, exactly revalidated root may create or
			// promote the destructive-cleanup marker.
			return ownership, false, nil
		}
		rootMatches, rootErr := revalidateRoot()
		if rootErr != nil || !rootMatches {
			return ownership, false, rootErr
		}
		claimMatches, claimErr := generationClaimMatches(c.maps.claims, key, ownership.claim)
		if claimErr != nil || !claimMatches {
			return ownership, false, claimErr
		}
		guardMatches, guardErr := generationGuardMatches(c.maps.ownerGuards, guardKey, guard)
		if guardErr != nil || !guardMatches {
			return ownership, false, guardErr
		}
	}

	ambiguity, touched, err := c.publishGenerationCleanupAmbiguity(
		key, uint64(now),
	)
	if err != nil {
		return ownership, false, err
	}
	ownership.ambiguity = ambiguity
	ownership.hasAmbiguity = true
	ownership.fence = generationTeardownFence{
		key: key, claim: ownership.claim, guardKey: guardKey, guardClaim: guard,
		markedAt: ambiguity, guardOwned: guardCreated,
	}
	valid, err := generationTeardownFenceMatches(
		c.maps.claims, c.maps.ownerGuards, c.maps.ambiguity, ownership.fence,
	)
	if err != nil || !valid {
		return ownership, false, err
	}

	ready := !c.claimCreatedThisSweep(key, ownership.claim) &&
		!c.guardCreatedThisSweep(guardKey, guard) && !touched &&
		c.generationCleanupFenceExpired(now, ownership.claim.ObservedMonotonicNS) &&
		c.generationCleanupFenceExpired(now, guard.ObservedMonotonicNS) &&
		c.generationCleanupFenceExpired(now, ambiguity)
	return ownership, ready, nil
}

func (c *Cleanup) generationCleanupFenceMatches(
	ownership generationCleanupOwnership,
) (bool, error) {
	if !ownership.ready {
		return false, nil
	}
	return generationTeardownFenceMatches(
		c.maps.claims, c.maps.ownerGuards, c.maps.ambiguity, ownership.fence,
	)
}

func (c *Cleanup) mutateGenerationCleanupFenced(
	ownership generationCleanupOwnership,
	description string,
	mutation func() (bool, error),
) (bool, error) {
	fenced, err := c.generationCleanupFenceMatches(ownership)
	if err != nil {
		return false, fmt.Errorf("revalidating generation fence before %s: %w", description, err)
	}
	if !fenced {
		return false, fmt.Errorf("generation fence changed before %s", description)
	}

	mutated, mutationErr := mutation()
	fenced, fenceErr := c.generationCleanupFenceMatches(ownership)
	if fenceErr != nil {
		fenceErr = fmt.Errorf("revalidating generation fence after %s: %w", description, fenceErr)
	} else if !fenced {
		fenceErr = fmt.Errorf("generation fence changed after %s", description)
	}
	return mutated, errors.Join(mutationErr, fenceErr)
}

func (c *Cleanup) publishGenerationCleanupAmbiguity(
	key stateKey,
	ambiguity uint64,
) (uint64, bool, error) {
	if ambiguity == 0 {
		return 0, false, errors.New("reading monotonic time for publishing-claim successor")
	}
	var current uint64
	if err := c.maps.ambiguity.Lookup(&key, &current); err == nil {
		if current != 0 {
			_, touched := c.currentSweepAmbiguities[key]
			return current, touched, nil
		}
		if err := c.maps.ambiguity.Update(&key, &ambiguity, ebpf.UpdateExist); err != nil {
			return 0, false, fmt.Errorf("promoting generation ambiguity reservation: %w", err)
		}
	} else if errors.Is(err, ebpf.ErrKeyNotExist) {
		if err := c.maps.ambiguity.Update(&key, &ambiguity, ebpf.UpdateNoExist); err != nil {
			return 0, false, fmt.Errorf("publishing generation ambiguity successor: %w", err)
		}
	} else {
		return 0, false, fmt.Errorf("checking generation ambiguity successor: %w", err)
	}
	if c.currentSweepAmbiguities != nil {
		// The key, rather than a timestamp equality, is the ownership evidence:
		// a concurrent BPF writer can replace our value after this non-CAS
		// promotion, but it cannot regress the slot back to zero.
		c.currentSweepAmbiguities[key] = ambiguity
	}
	if err := c.maps.ambiguity.Lookup(&key, &current); err != nil {
		return 0, true, fmt.Errorf("revalidating generation ambiguity successor: %w", err)
	}
	if current == 0 {
		return 0, true, errors.New("generation ambiguity successor remained reserved")
	}
	return current, true, nil
}

func (c *Cleanup) releaseGenerationCleanupOwnership(
	key stateKey,
	ownership generationCleanupOwnership,
) error {
	// A cleanup that loses validation after adopting an aged full fence cannot
	// prove that a paused producer is gone. Retain the complete tuple for a
	// later sweep; only finishGenerationCleanupFenced may retire it.
	_ = key
	_ = ownership
	return nil
}

func (c *Cleanup) recordCurrentSweepClaim(key stateKey, claim generationClaim) {
	if c.currentSweepClaims != nil {
		c.currentSweepClaims[key] = claim
	}
}

func (c *Cleanup) clearCurrentSweepClaim(key stateKey, claim generationClaim) {
	if current, ok := c.currentSweepClaims[key]; ok && current == claim {
		delete(c.currentSweepClaims, key)
	}
}

func (c *Cleanup) recordReleasedSweepClaim(key stateKey, claim generationClaim) {
	if c.releasedSweepClaims != nil {
		c.releasedSweepClaims[key] = claim
	}
}

func (c *Cleanup) recordReleasedSweepAmbiguity(key stateKey, markedAt uint64) {
	if c.releasedSweepAmbiguities != nil {
		c.releasedSweepAmbiguities[key] = markedAt
	}
}

func (c *Cleanup) recordCurrentSweepGuard(key Identity, guard generationClaim) {
	if c.currentSweepGuards != nil {
		c.currentSweepGuards[key] = guard
	}
}

func (c *Cleanup) clearCurrentSweepGuard(key Identity, guard generationClaim) {
	if current, ok := c.currentSweepGuards[key]; ok && current == guard {
		delete(c.currentSweepGuards, key)
	}
}

func (c *Cleanup) recordReleasedSweepGuard(key Identity, guard generationClaim) {
	if c.releasedSweepGuards != nil {
		c.releasedSweepGuards[key] = guard
	}
}

func (c *Cleanup) recordKnownGeneration(key stateKey) {
	if c.knownGenerations == nil || key.Generation == 0 || key.Reserved != 0 {
		return
	}
	if _, exists := c.knownGenerations[key]; exists {
		return
	}
	c.knownGenerations[key] = struct{}{}
	c.knownGenerationsByOwner[key.Owner] = append(c.knownGenerationsByOwner[key.Owner], key)
}

func (c *Cleanup) recordKnownLogicalKey(key stateKey) {
	if c.knownLogicalKeys == nil {
		return
	}
	if _, exists := c.knownLogicalKeys[key]; exists {
		return
	}
	c.knownLogicalKeys[key] = struct{}{}
	c.knownLogicalKeysByOwner[key.Owner] = append(c.knownLogicalKeysByOwner[key.Owner], key)
}

func canonicalGenerationKey(key stateKey) stateKey {
	return stateKey{Owner: key.Owner, Generation: key.Generation}
}

func (c *Cleanup) claimCreatedThisSweep(key stateKey, claim generationClaim) bool {
	created, ok := c.currentSweepClaims[key]
	return ok && created == claim
}

func (c *Cleanup) guardCreatedThisSweep(key Identity, guard generationClaim) bool {
	created, ok := c.currentSweepGuards[key]
	return ok && created == guard
}

func validGenerationCleanupGuard(_ Identity, claim generationClaim) bool {
	return claim.ObservedMonotonicNS != 0 && claim.ProcessIncarnation != 0 &&
		claim.Lifecycle == lifecycleCleanup &&
		claim.Reserved[0] == lifecyclePublishing && claim.Reserved[1] == 0 &&
		claim.Reserved[2] == 0 && claim.Reserved[3] == 0 && claim.Reserved[4] == 0 &&
		claim.Reserved[5] == 0 && claim.Reserved[6] == 0
}

func (c *Cleanup) generationCleanupFenceExpired(
	now time.Duration,
	observedMonotonicNS uint64,
) bool {
	if now <= 0 || observedMonotonicNS == 0 || uint64(now) < observedMonotonicNS {
		return false
	}
	retention := c.ttl
	if retention < javaRemoteParentMinimumFenceAge {
		retention = javaRemoteParentMinimumFenceAge
	}
	return time.Duration(uint64(now)-observedMonotonicNS) > retention
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
		Lifecycle:           lifecycleCleanup,
		Reserved:            [7]byte{lifecycle},
	}, true
}

func (c *Cleanup) generationCleanupLogicalArtifactsAbsent(key stateKey) (bool, error) {
	absent, err := c.generationCleanupNonIndexArtifactsAbsent(key)
	if err != nil || !absent {
		return absent, err
	}

	var generation generationIndexValue
	if err := c.maps.generations.Lookup(&key, &generation); err == nil {
		return false, nil
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking generation index cleanup: %w", err)
	}
	return true, nil
}

func (c *Cleanup) generationCleanupNonIndexArtifactsAbsent(key stateKey) (bool, error) {
	var owner ownerValue
	if err := c.maps.owners.Lookup(&key.Owner, &owner); err == nil {
		if owner.Generation == key.Generation {
			return false, nil
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking generation owner cleanup: %w", err)
	}
	return c.generationCleanupPayloadArtifactsAbsent(key)
}

func (c *Cleanup) generationCleanupPayloadArtifactsAbsent(key stateKey) (bool, error) {
	var state stateValue
	if err := c.maps.states.Lookup(&key, &state); err == nil {
		return false, nil
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking generation state cleanup: %w", err)
	}

	var encoded [RecordSize]byte
	if err := c.maps.remoteParents.Lookup(&key.Owner, &encoded); err == nil {
		record, decodeErr := UnmarshalRecord(encoded[:])
		if decodeErr != nil || record.Generation == key.Generation {
			return false, nil
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking generation fallback cleanup: %w", err)
	}

	var terminal terminalValue
	if err := c.maps.terminals.Lookup(&key.Owner, &terminal); err == nil {
		if terminal.Generation == key.Generation {
			return false, nil
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking generation terminal cleanup: %w", err)
	}

	return true, nil
}

func (c *Cleanup) generationConnectionArtifacts() (map[stateKey]struct{}, error) {
	artifacts := make(map[stateKey]struct{})
	connections, connectionErr := cleanupMapEntries[connectionInfoNS, connectionClaim](
		c.maps.connections,
	)
	for _, entry := range connections {
		artifacts[stateKey{
			Owner:      entry.value.Owner,
			Generation: entry.value.Generation,
		}] = struct{}{}
	}
	cookieConnections, cookieErr := cleanupMapEntries[connectionInfoNetNSCookie, connectionClaim](
		c.maps.cookieConnections,
	)
	for _, entry := range cookieConnections {
		artifacts[stateKey{
			Owner:      entry.value.Owner,
			Generation: entry.value.Generation,
		}] = struct{}{}
	}
	return artifacts, errors.Join(connectionErr, cookieErr)
}

func (c *Cleanup) generationCleanupPhysicalArtifactsAbsent(key stateKey) (bool, error) {
	if c.physicalGenerations != nil {
		_, present := c.physicalGenerations[key]
		return !present, nil
	}
	if c.deferPhysicalGenerationScan {
		return false, nil
	}

	artifacts, err := c.generationConnectionArtifacts()
	if err != nil {
		return false, fmt.Errorf("checking physical generation cleanup: %w", err)
	}
	_, present := artifacts[key]
	return !present, nil
}

func (c *Cleanup) generationCleanupArtifactsAbsent(key stateKey) (bool, error) {
	absent, err := c.generationCleanupLogicalArtifactsAbsent(key)
	if err != nil || !absent {
		return absent, err
	}
	return c.generationCleanupPhysicalArtifactsAbsent(key)
}

func (c *Cleanup) generationCleanupLogicalComplete(key stateKey) (bool, error) {
	// Claims, ambiguity markers, and detach guards are coordination fences, not
	// logical generation roots. Their later retirement is deliberately
	// stats-neutral, so logical completion must not wait for them to disappear.
	return c.generationCleanupLogicalArtifactsAbsent(key)
}

func (c *Cleanup) malformedLogicalKeyArtifactsAbsent(key stateKey) (bool, error) {
	var state stateValue
	if err := c.maps.states.Lookup(&key, &state); err == nil {
		return false, nil
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking malformed-key state cleanup: %w", err)
	}
	var generation generationIndexValue
	if err := c.maps.generations.Lookup(&key, &generation); err == nil {
		return false, nil
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking malformed-key generation cleanup: %w", err)
	}
	return true, nil
}

func (c *Cleanup) finishMalformedLogicalKeyCleanup(key stateKey) (bool, error) {
	absent, err := c.malformedLogicalKeyArtifactsAbsent(key)
	if err != nil || !absent {
		return absent, err
	}
	// A generation-zero or reserved-key entry is a standalone malformed root.
	// It never authorizes or waits for cleanup of the canonical generation.
	return true, nil
}

func (c *Cleanup) finishGenerationCleanup(key stateKey) (bool, error) {
	logicalAbsent, err := c.generationCleanupLogicalComplete(key)
	if err != nil || !logicalAbsent {
		return logicalAbsent, err
	}
	physicalAbsent, err := c.generationCleanupPhysicalArtifactsAbsent(key)
	if err != nil || !physicalAbsent {
		return false, err
	}
	return true, nil
}

func (c *Cleanup) snapshotProvesGenerationCleanupComplete(
	key stateKey,
) (bool, error) {
	if !c.generationSnapshotComplete || !c.stateSnapshotComplete ||
		c.physicalGenerations == nil {
		return false, nil
	}
	return c.generationCleanupArtifactsAbsent(key)
}

func (c *Cleanup) finishGenerationCleanupFenced(
	key stateKey,
	ownership generationCleanupOwnership,
) (bool, error) {
	complete, err := c.finishGenerationCleanup(key)
	if err != nil || !complete {
		return complete, err
	}
	valid, err := generationTeardownFenceMatches(
		c.maps.claims, c.maps.ownerGuards, c.maps.ambiguity, ownership.fence,
	)
	if err != nil || !valid {
		return false, err
	}

	// Fence retirement is the final mutation for this generation. From the
	// first delete onward, only the remaining fences may change, in the strict
	// marker -> exact claim -> owner guard order. Never recreate a released
	// component: partial tails are recoverable by a later cleanup sweep.
	var marker uint64
	if err := c.maps.ambiguity.Lookup(&key, &marker); err == nil {
		if marker != ownership.fence.markedAt {
			return false, nil
		}
		deleted, deleteErr := cleanupDeleteExact(
			c.maps.ambiguity, key, ownership.fence.markedAt,
		)
		if deleteErr != nil {
			return false, fmt.Errorf("deleting final generation ambiguity reservation: %w", deleteErr)
		}
		if !deleted {
			if err := c.maps.ambiguity.Lookup(&key, &marker); err == nil {
				return false, nil
			} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
				return false, fmt.Errorf("checking concurrently released generation marker: %w", err)
			}
		}
		if c.currentSweepAmbiguities != nil {
			delete(c.currentSweepAmbiguities, key)
		}
		c.recordReleasedSweepAmbiguity(key, ownership.fence.markedAt)
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking final generation ambiguity reservation: %w", err)
	}
	if err := c.maps.ambiguity.Lookup(&key, &marker); err == nil {
		return false, nil
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("verifying final generation ambiguity reservation: %w", err)
	}

	guardMatches, err := generationGuardMatches(
		c.maps.ownerGuards, ownership.fence.guardKey, ownership.fence.guardClaim,
	)
	if err != nil {
		return false, fmt.Errorf("checking generation guard before claim release: %w", err)
	}
	if !guardMatches {
		// Missing or replacement G=0 means another actor already linearized the
		// old guard release. Any surviving claim is a recoverable partial tail.
		c.recordReleasedSweepGuard(ownership.fence.guardKey, ownership.fence.guardClaim)
		return true, nil
	}
	if absent, absentErr := c.generationCleanupArtifactsAbsent(key); absentErr != nil || !absent {
		return false, errors.Join(
			absentErr, errors.New("generation reappeared before claim release"),
		)
	}

	claimMatches, err := generationClaimMatches(c.maps.claims, key, ownership.claim)
	if err != nil {
		return false, fmt.Errorf("checking generation claim before release: %w", err)
	}
	if claimMatches {
		deleted, deleteErr := cleanupDeleteExact(c.maps.claims, key, ownership.claim)
		if deleteErr != nil {
			return false, fmt.Errorf("deleting final generation claim: %w", deleteErr)
		}
		if !deleted {
			exactAbsent, absentErr := generationClaimAbsent(c.maps.claims, key)
			if absentErr != nil {
				return false, fmt.Errorf("checking concurrently released generation claim: %w", absentErr)
			}
			if !exactAbsent {
				return false, nil
			}
		}
		c.recordReleasedSweepClaim(key, ownership.claim)
		c.clearCurrentSweepClaim(key, ownership.claim)
	} else {
		exactAbsent, absentErr := generationClaimAbsent(c.maps.claims, key)
		if absentErr != nil {
			return false, fmt.Errorf("checking released generation claim: %w", absentErr)
		}
		if !exactAbsent {
			return false, nil
		}
	}

	guardMatches, err = generationGuardMatches(
		c.maps.ownerGuards, ownership.fence.guardKey, ownership.fence.guardClaim,
	)
	if err != nil {
		return false, fmt.Errorf("checking generation guard after claim release: %w", err)
	}
	if !guardMatches {
		c.recordReleasedSweepGuard(ownership.fence.guardKey, ownership.fence.guardClaim)
		return true, nil
	}
	exactAbsent, err := generationClaimAbsent(c.maps.claims, key)
	if err != nil || !exactAbsent {
		return false, err
	}
	if err := c.maps.ambiguity.Lookup(&key, &marker); err == nil {
		return false, nil
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, err
	}
	complete, err = c.snapshotProvesGenerationCleanupComplete(key)
	if err != nil || !complete {
		return false, err
	}

	deleted, err := cleanupDeleteExact(
		c.maps.ownerGuards, ownership.fence.guardKey, ownership.fence.guardClaim,
	)
	if err != nil {
		return false, fmt.Errorf("deleting final generation guard: %w", err)
	}
	if !deleted {
		// Absence or replacement means the old guard was already released. Do
		// not inspect or mark reusable keys after that linearization point.
		c.recordReleasedSweepGuard(ownership.fence.guardKey, ownership.fence.guardClaim)
		return true, nil
	}
	c.recordReleasedSweepGuard(ownership.fence.guardKey, ownership.fence.guardClaim)
	c.clearCurrentSweepGuard(ownership.fence.guardKey, ownership.fence.guardClaim)
	return true, nil
}

func (c *Cleanup) releaseGenerationCleanupClaimGuardTail(
	key stateKey,
	claim generationClaim,
	now time.Duration,
) (bool, error) {
	if key.Generation == 0 || key.Reserved != 0 || !validGenerationCleanupClaim(claim) ||
		c.claimCreatedThisSweep(key, claim) ||
		!c.generationCleanupFenceExpired(now, claim.ObservedMonotonicNS) {
		return false, nil
	}
	guardKey := key.Owner
	var guard generationClaim
	if err := c.maps.ownerGuards.Lookup(&guardKey, &guard); err != nil {
		return false, ignoreMissing(err)
	}
	if !validGenerationCleanupGuard(guardKey, guard) ||
		guard.ProcessIncarnation != key.Generation ||
		c.guardCreatedThisSweep(guardKey, guard) ||
		!c.generationCleanupFenceExpired(now, guard.ObservedMonotonicNS) {
		return false, nil
	}

	markerAbsent := func() (bool, error) {
		var marker uint64
		if err := c.maps.ambiguity.Lookup(&key, &marker); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return true, nil
			}
			return false, err
		}
		return false, nil
	}
	validate := func(requireExact bool) (bool, error) {
		absent, err := markerAbsent()
		if err != nil || !absent {
			return false, err
		}
		complete, err := c.snapshotProvesGenerationCleanupComplete(key)
		if err != nil || !complete {
			return false, err
		}
		guardMatches, err := generationGuardMatches(c.maps.ownerGuards, guardKey, guard)
		if err != nil || !guardMatches {
			return false, err
		}
		if !requireExact {
			return true, nil
		}
		return generationClaimMatches(c.maps.claims, key, claim)
	}

	// This is recovery of an already released marker, never acquisition of new
	// cleanup authority. Repeated live absence and complete-snapshot checks may
	// retire only E and then G=0; this path must not create or promote M.
	valid, err := validate(true)
	if err != nil || !valid {
		return false, err
	}
	valid, err = validate(true)
	if err != nil || !valid {
		return false, err
	}
	deleted, err := cleanupDeleteExact(c.maps.claims, key, claim)
	if err != nil {
		return false, fmt.Errorf("deleting marker-free generation claim: %w", err)
	}
	if !deleted {
		exactAbsent, absentErr := generationClaimAbsent(c.maps.claims, key)
		if absentErr != nil || !exactAbsent {
			return false, absentErr
		}
	}
	c.recordReleasedSweepClaim(key, claim)
	c.clearCurrentSweepClaim(key, claim)

	valid, err = validate(false)
	if err != nil || !valid {
		return false, err
	}
	exactAbsent, err := generationClaimAbsent(c.maps.claims, key)
	if err != nil || !exactAbsent {
		return false, err
	}
	deleted, err = cleanupDeleteExact(c.maps.ownerGuards, guardKey, guard)
	if err != nil {
		return false, fmt.Errorf("deleting marker-free generation guard: %w", err)
	}
	if !deleted {
		guardMatches, matchErr := generationGuardMatches(c.maps.ownerGuards, guardKey, guard)
		if matchErr != nil || guardMatches {
			return false, matchErr
		}
	}
	c.recordReleasedSweepGuard(guardKey, guard)
	c.clearCurrentSweepGuard(guardKey, guard)
	return true, nil
}

func (c *Cleanup) releaseGenerationCleanupClaimTail(
	key stateKey,
	claim generationClaim,
	now time.Duration,
) (bool, error) {
	if key.Generation == 0 || key.Reserved != 0 || !validGenerationCleanupClaim(claim) ||
		c.claimCreatedThisSweep(key, claim) ||
		!c.generationCleanupFenceExpired(now, claim.ObservedMonotonicNS) {
		return false, nil
	}
	validate := func() (bool, error) {
		var marker uint64
		if err := c.maps.ambiguity.Lookup(&key, &marker); err == nil {
			return false, nil
		} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, err
		}
		guardAbsent, err := generationGuardAbsent(c.maps.ownerGuards, key.Owner)
		if err != nil || !guardAbsent {
			return false, err
		}
		complete, err := c.snapshotProvesGenerationCleanupComplete(key)
		if err != nil || !complete {
			return false, err
		}
		return generationClaimMatches(c.maps.claims, key, claim)
	}
	valid, err := validate()
	if err != nil || !valid {
		return false, err
	}
	valid, err = validate()
	if err != nil || !valid {
		return false, err
	}
	deleted, err := cleanupDeleteExact(c.maps.claims, key, claim)
	if err != nil || !deleted {
		return false, err
	}
	c.recordReleasedSweepClaim(key, claim)
	c.clearCurrentSweepClaim(key, claim)
	return true, nil
}

func (c *Cleanup) publishingCleanupRootCoherent(
	key stateKey,
	claim generationClaim,
) (bool, error) {
	if !validGenerationCleanupClaim(claim) || claim.Reserved[0] != lifecyclePublishing {
		return false, nil
	}
	var terminal terminalValue
	if err := c.maps.terminals.Lookup(&key.Owner, &terminal); err == nil {
		if terminal.Generation == key.Generation {
			return false, nil
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking publishing-tail terminal: %w", err)
	}
	var owner ownerValue
	if err := c.maps.owners.Lookup(&key.Owner, &owner); err == nil {
		if owner.Generation == key.Generation {
			if owner.ProcessIncarnation != claim.ProcessIncarnation {
				return false, nil
			}
			return c.coherentActiveOwner(key.Owner, owner)
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking publishing-tail owner: %w", err)
	}

	var index generationIndexValue
	if err := c.maps.generations.Lookup(&key, &index); err != nil {
		return false, ignoreMissing(err)
	}
	if index.Process != javaProcessIdentity(key.Owner) || index.Reserved != 0 ||
		index.ProcessIncarnation != claim.ProcessIncarnation ||
		index.ObservedMonotonicNS == 0 {
		return false, nil
	}
	return c.coherentDetachedAlias(key, index)
}

func (c *Cleanup) coherentGenerationPublishingReservation(
	key stateKey,
) (generationClaim, bool, error) {
	var marker uint64
	if err := c.maps.ambiguity.Lookup(&key, &marker); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return generationClaim{}, false, nil
		}
		return generationClaim{}, false,
			fmt.Errorf("checking coherent publishing reservation: %w", err)
	}
	if marker != 0 {
		return generationClaim{}, false, nil
	}
	var claim generationClaim
	if err := c.maps.claims.Lookup(&key, &claim); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return generationClaim{}, false, nil
		}
		return generationClaim{}, false,
			fmt.Errorf("checking coherent publishing claim: %w", err)
	}
	if !validGenerationCleanupClaim(claim) || claim.Reserved[0] != lifecyclePublishing {
		return generationClaim{}, false, nil
	}
	coherent, err := c.publishingCleanupRootCoherent(key, claim)
	return claim, coherent, err
}

func (c *Cleanup) cleanupMarkerMatches(
	key stateKey,
	expected *uint64,
) (bool, error) {
	var current uint64
	err := c.maps.ambiguity.Lookup(&key, &current)
	if expected == nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return true, nil
		}
		return false, ignoreMissing(err)
	}
	if err != nil {
		return false, ignoreMissing(err)
	}
	return current == *expected, nil
}

func (c *Cleanup) releaseGenerationPublishingCleanupTail(
	key stateKey,
	claim generationClaim,
	marker *uint64,
	now time.Duration,
) (bool, error) {
	if !validGenerationCleanupClaim(claim) || claim.Reserved[0] != lifecyclePublishing ||
		marker == nil || *marker != 0 ||
		c.claimCreatedThisSweep(key, claim) ||
		!c.generationCleanupFenceExpired(now, claim.ObservedMonotonicNS) {
		return false, nil
	}
	var guard generationClaim
	guardPresent := true
	if err := c.maps.ownerGuards.Lookup(&key.Owner, &guard); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, err
		}
		guardPresent = false
	} else if !validGenerationCleanupGuard(key.Owner, guard) ||
		guard.ProcessIncarnation != key.Generation ||
		c.guardCreatedThisSweep(key.Owner, guard) ||
		!c.generationCleanupFenceExpired(now, guard.ObservedMonotonicNS) {
		return false, nil
	}
	validate := func() (bool, error) {
		markerMatches, err := c.cleanupMarkerMatches(key, marker)
		if err != nil || !markerMatches {
			return false, err
		}
		claimMatches, err := generationClaimMatches(c.maps.claims, key, claim)
		if err != nil || !claimMatches {
			return false, err
		}
		if guardPresent {
			guardMatches, guardErr := generationGuardMatches(c.maps.ownerGuards, key.Owner, guard)
			if guardErr != nil || !guardMatches {
				return false, guardErr
			}
		}
		coherent, err := c.publishingCleanupRootCoherent(key, claim)
		if err != nil || coherent {
			return coherent, err
		}
		// A crashed publisher may leave C6/G7/M0 after deleting no payload at
		// all, or cleanup may already have removed every artifact. Complete
		// snapshots are independent non-destructive authority for retiring E
		// and G while preserving the zero reservation.
		return c.snapshotProvesGenerationCleanupComplete(key)
	}
	valid, err := validate()
	if err != nil || !valid {
		return false, err
	}
	valid, err = validate()
	if err != nil || !valid {
		return false, err
	}
	deleted, err := cleanupDeleteExact(c.maps.claims, key, claim)
	if err != nil || !deleted {
		return false, err
	}
	c.recordReleasedSweepClaim(key, claim)
	c.clearCurrentSweepClaim(key, claim)
	if !guardPresent {
		return true, nil
	}
	exactAbsent, err := generationClaimAbsent(c.maps.claims, key)
	if err != nil || !exactAbsent {
		// A byte-identical successor may have appeared after E deletion. Retain G
		// so that successor cannot be mistaken for this release attempt.
		return true, err
	}
	markerMatches, err := c.cleanupMarkerMatches(key, marker)
	if err != nil || !markerMatches {
		return true, err
	}
	coherent, err := c.publishingCleanupRootCoherent(key, claim)
	if err != nil {
		return true, err
	}
	if !coherent {
		complete, completeErr := c.snapshotProvesGenerationCleanupComplete(key)
		if completeErr != nil || !complete {
			return true, completeErr
		}
	}
	guardMatches, err := generationGuardMatches(c.maps.ownerGuards, key.Owner, guard)
	if err != nil || !guardMatches {
		return true, err
	}
	exactAbsent, err = generationClaimAbsent(c.maps.claims, key)
	if err != nil || !exactAbsent {
		return true, err
	}
	markerMatches, err = c.cleanupMarkerMatches(key, marker)
	if err != nil || !markerMatches {
		return true, err
	}
	coherent, err = c.publishingCleanupRootCoherent(key, claim)
	if err != nil {
		return true, err
	}
	if !coherent {
		complete, completeErr := c.snapshotProvesGenerationCleanupComplete(key)
		if completeErr != nil || !complete {
			return true, completeErr
		}
	}
	deleted, err = cleanupDeleteExact(c.maps.ownerGuards, key.Owner, guard)
	if err != nil || !deleted {
		return true, err
	}
	c.recordReleasedSweepGuard(key.Owner, guard)
	c.clearCurrentSweepGuard(key.Owner, guard)
	return true, nil
}

func (c *Cleanup) releaseGenerationCleanupMarkerGuardTail(
	key stateKey,
	markedAt uint64,
	guard generationClaim,
	now time.Duration,
) (bool, error) {
	guardKey := key.Owner
	if key.Generation == 0 || key.Reserved != 0 || markedAt == 0 ||
		!validGenerationCleanupGuard(guardKey, guard) ||
		guard.ProcessIncarnation != key.Generation ||
		c.guardCreatedThisSweep(guardKey, guard) ||
		!c.generationCleanupFenceExpired(now, markedAt) ||
		!c.generationCleanupFenceExpired(now, guard.ObservedMonotonicNS) {
		return false, nil
	}
	if _, touched := c.currentSweepAmbiguities[key]; touched {
		return false, nil
	}
	// M+ without E can be a paused producer between the required G -> E -> M
	// acquisition steps. Neither M nor G is cleanup authority on its own, even
	// after they age and even when a snapshot currently sees no payload. Preserve
	// both until an independently selected generation root can fill E.
	return false, nil
}

func (c *Cleanup) releaseGenerationCleanupMarkerTail(
	key stateKey,
	markedAt uint64,
	now time.Duration,
) (bool, error) {
	if key.Generation == 0 || key.Reserved != 0 || markedAt == 0 ||
		!c.generationCleanupFenceExpired(now, markedAt) {
		return false, nil
	}
	// M+ alone can be a paused producer after marker publication or a partial
	// cleanup tail whose missing E/G cannot be distinguished without a durable
	// root. Preserve it; a root-driven pass may reconstruct the complete tuple.
	return false, nil
}

func (c *Cleanup) releaseGenerationCleanupReservedGuardTail(
	guardKey Identity,
	guard generationClaim,
	now time.Duration,
) (bool, error) {
	if !validGenerationCleanupGuard(guardKey, guard) ||
		c.guardCreatedThisSweep(guardKey, guard) ||
		!c.generationCleanupFenceExpired(now, guard.ObservedMonotonicNS) {
		return false, nil
	}
	key := stateKey{Owner: guardKey, Generation: guard.ProcessIncarnation}
	exactAbsent, err := generationClaimAbsent(c.maps.claims, key)
	if err != nil || !exactAbsent {
		return false, err
	}
	var marker uint64
	if err := c.maps.ambiguity.Lookup(&key, &marker); err != nil || marker != 0 {
		return false, ignoreMissing(err)
	}
	guardMatches, err := generationGuardMatches(c.maps.ownerGuards, guardKey, guard)
	if err != nil || !guardMatches {
		return false, err
	}
	// A zero reservation is the live publication gate, not cleanup authority.
	// Preserve it and every payload artifact; retire only an aged G=0 whose
	// exact E is absent, repeating all three fence checks immediately before the
	// compare-delete.
	exactAbsent, err = generationClaimAbsent(c.maps.claims, key)
	if err != nil || !exactAbsent {
		return false, err
	}
	if err := c.maps.ambiguity.Lookup(&key, &marker); err != nil || marker != 0 {
		return false, ignoreMissing(err)
	}
	guardMatches, err = generationGuardMatches(c.maps.ownerGuards, guardKey, guard)
	if err != nil || !guardMatches {
		return false, err
	}
	deleted, err := cleanupDeleteExact(c.maps.ownerGuards, guardKey, guard)
	if err != nil || !deleted {
		return false, err
	}
	c.recordReleasedSweepGuard(guardKey, guard)
	c.clearCurrentSweepGuard(guardKey, guard)
	return true, nil
}

func (c *Cleanup) releaseGenerationCleanupGuardTail(
	guardKey Identity,
	guard generationClaim,
	now time.Duration,
) (bool, error) {
	if !validGenerationCleanupGuard(guardKey, guard) ||
		c.guardCreatedThisSweep(guardKey, guard) ||
		!c.generationCleanupFenceExpired(now, guard.ObservedMonotonicNS) {
		return false, nil
	}
	key := stateKey{Owner: guardKey, Generation: guard.ProcessIncarnation}
	exactAbsent, err := generationClaimAbsent(c.maps.claims, key)
	if err != nil || !exactAbsent {
		return false, err
	}
	var marker uint64
	if err := c.maps.ambiguity.Lookup(&key, &marker); err == nil {
		return false, nil
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, err
	}
	complete, err := c.snapshotProvesGenerationCleanupComplete(key)
	if err != nil || !complete {
		return false, err
	}
	guardMatches, err := generationGuardMatches(c.maps.ownerGuards, guardKey, guard)
	if err != nil || !guardMatches {
		return false, err
	}
	// Repeat both absence checks immediately before the final reusable-owner
	// mutation. Successful exact guard deletion is the linearization point.
	exactAbsent, err = generationClaimAbsent(c.maps.claims, key)
	if err != nil || !exactAbsent {
		return false, err
	}
	if err := c.maps.ambiguity.Lookup(&key, &marker); err == nil {
		return false, nil
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, err
	}
	complete, err = c.snapshotProvesGenerationCleanupComplete(key)
	if err != nil || !complete {
		return false, err
	}
	deleted, err := cleanupDeleteExact(c.maps.ownerGuards, guardKey, guard)
	if err != nil || !deleted {
		return false, err
	}
	c.recordReleasedSweepGuard(guardKey, guard)
	c.clearCurrentSweepGuard(guardKey, guard)
	return true, nil
}

func (c *Cleanup) generationCleanupPhysicalFenceAuthorizes(
	key stateKey,
	now time.Duration,
) (bool, error) {
	if key.Generation == 0 || key.Reserved != 0 {
		return false, nil
	}
	var claim generationClaim
	if err := c.maps.claims.Lookup(&key, &claim); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("checking physical generation cleanup claim: %w", err)
	}
	if !validGenerationCleanupClaim(claim) || c.claimCreatedThisSweep(key, claim) ||
		!c.generationCleanupFenceExpired(now, claim.ObservedMonotonicNS) {
		return false, nil
	}
	var index generationIndexValue
	if err := c.maps.generations.Lookup(&key, &index); err == nil {
		if index.Process != javaProcessIdentity(key.Owner) || index.Reserved != 0 ||
			index.ProcessIncarnation == 0 ||
			index.ObservedMonotonicNS == 0 {
			return false, nil
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking physical generation index authority: %w", err)
	}

	var observedMonotonicNS uint64
	if err := c.maps.ambiguity.Lookup(&key, &observedMonotonicNS); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("checking physical generation ambiguity marker: %w", err)
	}
	_, touchedThisSweep := c.currentSweepAmbiguities[key]
	if observedMonotonicNS == 0 || touchedThisSweep ||
		!c.generationCleanupFenceExpired(now, observedMonotonicNS) {
		return false, nil
	}

	guardKey := key.Owner
	var guard generationClaim
	if err := c.maps.ownerGuards.Lookup(&guardKey, &guard); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("checking physical generation detach guard: %w", err)
	}
	if !validGenerationCleanupGuard(guardKey, guard) ||
		guard.ProcessIncarnation != key.Generation ||
		c.guardCreatedThisSweep(guardKey, guard) ||
		!c.generationCleanupFenceExpired(now, guard.ObservedMonotonicNS) {
		return false, nil
	}

	fence := generationTeardownFence{
		key: key, claim: claim, guardKey: guardKey, guardClaim: guard,
		markedAt: observedMonotonicNS,
	}
	valid, err := generationTeardownFenceMatches(
		c.maps.claims, c.maps.ownerGuards, c.maps.ambiguity, fence,
	)
	if err != nil {
		return false, fmt.Errorf("revalidating physical generation teardown fence: %w", err)
	}
	return valid, nil
}

func (c *Cleanup) lockGenerationOwner(
	key stateKey,
	processIncarnation uint64,
	ownership generationCleanupOwnership,
) (ownerValue, bool, bool, bool, error) {
	var owner ownerValue
	if err := c.maps.owners.Lookup(&key.Owner, &owner); err == nil {
		if owner.Generation != key.Generation {
			coherent, coherentErr := c.coherentActiveOwner(key.Owner, owner)
			if coherentErr != nil {
				return ownerValue{}, false, false, false, coherentErr
			}
			if !coherent {
				return ownerValue{}, false, false, false, nil
			}
			return owner, true, false, true, nil
		}
		if owner.ProcessIncarnation != processIncarnation || invalidGenerationOwner(owner) {
			return ownerValue{}, false, false, false, nil
		}
		return owner, true, false, false, nil
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return ownerValue{}, false, false, false,
			fmt.Errorf("looking up generation owner: %w", err)
	}

	owner = ownerValue{
		Generation:         key.Generation,
		ProcessIncarnation: processIncarnation,
		Lifecycle:          lifecyclePublishing,
	}
	fenced, err := c.generationCleanupFenceMatches(ownership)
	if err != nil {
		return ownerValue{}, false, false, false,
			fmt.Errorf("revalidating generation fence before owner lock: %w", err)
	}
	if !fenced {
		return ownerValue{}, false, false, false,
			errors.New("generation fence changed before owner lock")
	}
	if err := c.maps.owners.Update(&key.Owner, &owner, ebpf.UpdateNoExist); err != nil {
		if errors.Is(err, ebpf.ErrKeyExist) {
			return ownerValue{}, false, false, false, nil
		}
		return ownerValue{}, false, false, false,
			fmt.Errorf("locking generation owner: %w", err)
	}
	fenced, err = c.generationCleanupFenceMatches(ownership)
	if err != nil {
		return owner, false, true, false,
			fmt.Errorf("revalidating generation fence after owner insertion: %w", err)
	}
	if !fenced {
		return owner, false, true, false,
			errors.New("generation fence changed after owner insertion")
	}
	return owner, true, true, false, nil
}

func (c *Cleanup) coherentActiveOwner(identity Identity, owner ownerValue) (bool, error) {
	if invalidGenerationOwner(owner) || owner.Lifecycle != lifecycleActive {
		return false, nil
	}
	key := stateKey{Owner: identity, Generation: owner.Generation}
	var state stateValue
	if err := c.maps.states.Lookup(&key, &state); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("checking detached successor state: %w", err)
	}
	if state.Lifecycle != lifecycleActive || state.Reserved != ([3]byte{}) ||
		state.ProcessIncarnation != owner.ProcessIncarnation ||
		state.ObservedMonotonicNS == 0 || state.ConnectionNetNS == 0 ||
		!validGenerationConnection(state.Connection) {
		return false, nil
	}
	var generation generationIndexValue
	if err := c.maps.generations.Lookup(&key, &generation); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("checking detached successor index: %w", err)
	}
	if generation.Process != javaProcessIdentity(identity) || generation.Reserved != 0 ||
		generation.ProcessIncarnation != owner.ProcessIncarnation ||
		generation.ObservedMonotonicNS != state.ObservedMonotonicNS {
		return false, nil
	}
	var encoded [RecordSize]byte
	if err := c.maps.remoteParents.Lookup(&identity, &encoded); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("checking detached successor fallback: %w", err)
	}
	record, err := UnmarshalRecord(encoded[:])
	if err != nil || !record.IsValidRemoteParent() || record.Generation != owner.Generation ||
		record.ObservedMonotonicNS != state.ObservedMonotonicNS || encoded != state.Response {
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
		return false, fmt.Errorf("checking detached successor connection: %w", err)
	}
	if !validConnectionClaim(
		connection, identity, owner.Generation, state.ConnectionNetNS,
	) {
		return false, nil
	}
	cookieKey := connectionCookieKey(connectionKey, connection)
	var cookieConnection connectionClaim
	if err := c.maps.cookieConnections.Lookup(&cookieKey, &cookieConnection); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("checking detached successor cookie connection: %w", err)
	}
	if cookieConnection != connection {
		return false, nil
	}

	// Treat the successor as detached authority only after the complete BPF
	// publication graph is stable byte-for-byte across a second read.
	var currentOwner ownerValue
	if err := c.maps.owners.Lookup(&identity, &currentOwner); err != nil || currentOwner != owner {
		return false, ignoreMissing(err)
	}
	var currentState stateValue
	if err := c.maps.states.Lookup(&key, &currentState); err != nil || currentState != state {
		return false, ignoreMissing(err)
	}
	var currentGeneration generationIndexValue
	if err := c.maps.generations.Lookup(&key, &currentGeneration); err != nil ||
		currentGeneration != generation {
		return false, ignoreMissing(err)
	}
	var currentEncoded [RecordSize]byte
	if err := c.maps.remoteParents.Lookup(&identity, &currentEncoded); err != nil ||
		currentEncoded != encoded {
		return false, ignoreMissing(err)
	}
	var currentConnection connectionClaim
	if err := c.maps.connections.Lookup(&connectionKey, &currentConnection); err != nil ||
		currentConnection != connection {
		return false, ignoreMissing(err)
	}
	var currentCookieConnection connectionClaim
	if err := c.maps.cookieConnections.Lookup(
		&cookieKey, &currentCookieConnection,
	); err != nil || currentCookieConnection != connection {
		return false, ignoreMissing(err)
	}
	return true, nil
}

func (c *Cleanup) deleteFallback(key stateKey) (bool, error) {
	var encoded [RecordSize]byte
	if err := c.maps.remoteParents.Lookup(&key.Owner, &encoded); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("looking up generation fallback: %w", err)
	}
	record, err := UnmarshalRecord(encoded[:])
	if err != nil || record.Generation != key.Generation {
		return false, nil
	}
	deleted, err := cleanupDeleteExact(c.maps.remoteParents, key.Owner, encoded)
	if err != nil {
		return deleted, fmt.Errorf("deleting generation fallback: %w", err)
	}
	return deleted, nil
}

func (c *Cleanup) deleteTerminal(key stateKey, processIncarnation uint64) (bool, error) {
	var terminal terminalValue
	if err := c.maps.terminals.Lookup(&key.Owner, &terminal); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("looking up generation terminal: %w", err)
	}
	if terminal.Generation != key.Generation || terminal.ProcessIncarnation != processIncarnation {
		return false, nil
	}
	deleted, err := cleanupDeleteExact(c.maps.terminals, key.Owner, terminal)
	if err != nil {
		return deleted, fmt.Errorf("deleting generation terminal: %w", err)
	}
	return deleted, nil
}

type physicalGenerationCleanupRoot struct {
	kind          uint8
	connectionKey connectionInfoNS
	cookieKey     connectionInfoNetNSCookie
	claim         connectionClaim
}

const (
	physicalGenerationConnectionRoot = uint8(iota + 1)
	physicalGenerationCookieRoot
)

func validPhysicalGenerationConnectionRoot(
	key connectionInfoNS,
	claim connectionClaim,
) bool {
	return key.NetNS != 0 && validGenerationConnection(key.Connection) &&
		claim.Owner != (Identity{}) && claim.Generation != 0 &&
		validConnectionClaim(claim, claim.Owner, claim.Generation, key.NetNS)
}

func validPhysicalGenerationCookieRoot(
	key connectionInfoNetNSCookie,
	claim connectionClaim,
) bool {
	return key.Reserved == 0 && key.NetNSCookie != 0 &&
		validGenerationConnection(key.Connection) && claim.NetNS != 0 &&
		claim.Owner != (Identity{}) && claim.Generation != 0 &&
		key.NetNSCookie == claim.NetNSCookie &&
		validConnectionClaim(claim, claim.Owner, claim.Generation, claim.NetNS)
}

func (c *Cleanup) physicalGenerationCleanupRootMatches(
	key stateKey,
	roots []physicalGenerationCleanupRoot,
) (bool, error) {
	exactRootMatches := func(root physicalGenerationCleanupRoot) (bool, error) {
		switch root.kind {
		case physicalGenerationConnectionRoot:
			if !validPhysicalGenerationConnectionRoot(root.connectionKey, root.claim) ||
				root.claim.Owner != key.Owner || root.claim.Generation != key.Generation {
				return false, nil
			}
			return cleanupExactMatches(c.maps.connections, root.connectionKey, root.claim)
		case physicalGenerationCookieRoot:
			if !validPhysicalGenerationCookieRoot(root.cookieKey, root.claim) ||
				root.claim.Owner != key.Owner || root.claim.Generation != key.Generation {
				return false, nil
			}
			return cleanupExactMatches(c.maps.cookieConnections, root.cookieKey, root.claim)
		default:
			return false, nil
		}
	}
	for _, root := range roots {
		matches, err := exactRootMatches(root)
		if err != nil {
			return false, err
		}
		if !matches {
			continue
		}
		logicalAbsent, err := c.generationCleanupLogicalArtifactsAbsent(key)
		if err != nil || !logicalAbsent {
			return false, err
		}
		matches, err = exactRootMatches(root)
		if err != nil || !matches {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func (c *Cleanup) cleanupRetainedGenerationClaim(
	key stateKey,
) (bool, error) {
	var generation generationIndexValue
	if err := c.maps.generations.Lookup(&key, &generation); err == nil {
		return c.cleanupGeneration(key, generation)
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("looking up retained-claim generation: %w", err)
	}

	var state stateValue
	if err := c.maps.states.Lookup(&key, &state); err == nil {
		if state.ProcessIncarnation == 0 || state.ObservedMonotonicNS == 0 ||
			state.Reserved != ([3]byte{}) {
			return c.quarantineMalformedState(key, state)
		}
		return c.cleanupOrphanState(key, state)
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("looking up retained-claim state: %w", err)
	}

	var owner ownerValue
	if err := c.maps.owners.Lookup(&key.Owner, &owner); err == nil {
		if owner.Generation == key.Generation {
			return c.cleanupOrphanOwner(key.Owner, owner)
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("looking up retained-claim owner: %w", err)
	}

	var encoded [RecordSize]byte
	if err := c.maps.remoteParents.Lookup(&key.Owner, &encoded); err == nil {
		record, decodeErr := UnmarshalRecord(encoded[:])
		if decodeErr != nil || !record.IsValidRemoteParent() {
			// Malformed singleton bytes do not identify this retained exact
			// generation. Leave them to the owner-rooted quarantine pass.
			return false, nil
		}
		if record.Generation == key.Generation {
			return c.cleanupOrphanFallback(key.Owner, encoded, record)
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("looking up retained-claim fallback: %w", err)
	}

	var terminal terminalValue
	if err := c.maps.terminals.Lookup(&key.Owner, &terminal); err == nil {
		if terminal.Generation == key.Generation {
			return c.quarantineMalformedTerminal(key.Owner, terminal)
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("looking up retained-claim terminal: %w", err)
	}

	return false, nil
}

func (c *Cleanup) sweepOrphans(
	retired map[retiredProcessKey]struct{},
	cleanedGenerations map[stateKey]struct{},
	stats *CleanupStats,
	states []cleanupEntry[stateKey, stateValue],
	stateErr error,
	connections []cleanupEntry[connectionInfoNS, connectionClaim],
	connectionsErr error,
	cookieConnections []cleanupEntry[connectionInfoNetNSCookie, connectionClaim],
	cookieConnectionsErr error,
) error {
	var result error

	if stateErr != nil {
		result = errors.Join(result, fmt.Errorf("iterating generation states: %w", stateErr))
	}
	statesNow := c.monoTimeNow()
	for _, entry := range states {
		if entry.key.Generation == 0 || entry.key.Reserved != 0 ||
			entry.value.ProcessIncarnation == 0 || entry.value.ObservedMonotonicNS == 0 ||
			entry.value.Reserved != ([3]byte{}) {
			cleaned, cleanupErr := c.quarantineMalformedState(entry.key, entry.value)
			if cleaned {
				stats.recordGeneration(
					cleanedGenerations, canonicalGenerationKey(entry.key), false,
				)
			}
			if cleanupErr != nil {
				result = errors.Join(result, cleanupErr)
			}
			continue
		}
		processRetired, retirementErr := c.processRetired(
			retired,
			javaProcessIdentity(entry.key.Owner),
			entry.value.ProcessIncarnation,
		)
		if retirementErr != nil {
			result = errors.Join(result, retirementErr)
			continue
		}
		if !processRetired {
			_, coherentReservation, reservationErr :=
				c.coherentGenerationPublishingReservation(entry.key)
			if reservationErr != nil {
				result = errors.Join(result, reservationErr)
				continue
			}
			if coherentReservation {
				continue
			}
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

	if connectionsErr != nil {
		result = errors.Join(
			result, fmt.Errorf("iterating generation connections: %w", connectionsErr),
		)
	}
	physicalCleanupNow := c.monoTimeNow()
	physicalRoots := make(map[stateKey][]physicalGenerationCleanupRoot)
	if connectionsErr == nil && cookieConnectionsErr == nil {
		for _, entry := range connections {
			if !validPhysicalGenerationConnectionRoot(entry.key, entry.value) {
				continue
			}
			key := stateKey{Owner: entry.value.Owner, Generation: entry.value.Generation}
			physicalRoots[key] = append(physicalRoots[key], physicalGenerationCleanupRoot{
				kind:          physicalGenerationConnectionRoot,
				connectionKey: entry.key,
				claim:         entry.value,
			})
		}
		for _, entry := range cookieConnections {
			if !validPhysicalGenerationCookieRoot(entry.key, entry.value) {
				continue
			}
			key := stateKey{Owner: entry.value.Owner, Generation: entry.value.Generation}
			physicalRoots[key] = append(physicalRoots[key], physicalGenerationCleanupRoot{
				kind:      physicalGenerationCookieRoot,
				cookieKey: entry.key,
				claim:     entry.value,
			})
		}
		for key, roots := range physicalRoots {
			rootSnapshot := roots
			_, _, claimErr := c.claimGenerationCleanupForArtifact(
				key, key.Generation, lifecycleAmbiguous,
				func() (bool, error) {
					return c.physicalGenerationCleanupRootMatches(key, rootSnapshot)
				},
			)
			if claimErr != nil {
				result = errors.Join(
					result, fmt.Errorf("claiming physical-only generation cleanup: %w", claimErr),
				)
			}
		}
	}
	physicalCleanupAllowed := make(map[stateKey]bool)
	physicalCleanupChecked := make(map[stateKey]struct{})
	canCleanPhysical := func(key stateKey) bool {
		if _, checked := physicalCleanupChecked[key]; checked {
			return physicalCleanupAllowed[key]
		}
		physicalCleanupChecked[key] = struct{}{}
		logicalAbsent, logicalErr := c.generationCleanupPayloadArtifactsAbsent(key)
		if logicalErr != nil {
			result = errors.Join(result, logicalErr)
			return false
		}
		if !logicalAbsent {
			return false
		}
		fenced, fenceErr := c.generationCleanupPhysicalFenceAuthorizes(key, physicalCleanupNow)
		if fenceErr != nil {
			result = errors.Join(result, fenceErr)
			return false
		}
		physicalCleanupAllowed[key] = fenced
		return fenced
	}
	for _, entry := range connections {
		if !validPhysicalGenerationConnectionRoot(entry.key, entry.value) {
			continue
		}
		key := stateKey{Owner: entry.value.Owner, Generation: entry.value.Generation}
		if !canCleanPhysical(key) {
			continue
		}
		_, deleteErr := c.deleteConnectionIndexesFenced(
			key, entry.key, entry.value, physicalCleanupNow,
		)
		if deleteErr != nil {
			result = errors.Join(result, fmt.Errorf("deleting orphan connection: %w", deleteErr))
		}
	}
	if cookieConnectionsErr != nil {
		result = errors.Join(
			result,
			fmt.Errorf("iterating cookie generation connections: %w", cookieConnectionsErr),
		)
	}
	for _, entry := range cookieConnections {
		if !validPhysicalGenerationCookieRoot(entry.key, entry.value) {
			continue
		}
		key := stateKey{Owner: entry.value.Owner, Generation: entry.value.Generation}
		if !canCleanPhysical(key) {
			continue
		}
		authorized, fenceErr := c.generationCleanupPhysicalFenceAuthorizes(
			key, physicalCleanupNow,
		)
		if fenceErr != nil {
			result = errors.Join(result, fenceErr)
			continue
		}
		if !authorized {
			continue
		}
		if _, deleteErr := cleanupDeleteExact(
			c.maps.cookieConnections, entry.key, entry.value,
		); deleteErr != nil {
			result = errors.Join(
				result, fmt.Errorf("deleting orphan cookie connection: %w", deleteErr),
			)
		} else if authorized, fenceErr := c.generationCleanupPhysicalFenceAuthorizes(
			key, physicalCleanupNow,
		); fenceErr != nil {
			result = errors.Join(result, fenceErr)
		} else if !authorized {
			result = errors.Join(result, errors.New(
				"generation teardown fence changed after cookie cleanup",
			))
		}
	}
	// Task links, handoff links, and handoff claims are bounded by LRU maps.
	// Their presence is also a fail-closed protocol signal: deleting an aged
	// claim could re-enable a delayed token, and LRU eviction could replace the
	// enumerated value before a key-only userspace delete. Leave all three map
	// families to BPF and the kernel's capacity bound.

	terminals, err := cleanupMapEntries[Identity, terminalValue](c.maps.terminals)
	if err != nil {
		result = errors.Join(result, fmt.Errorf("iterating terminal generations: %w", err))
	}
	terminalsNow := c.monoTimeNow()
	for _, entry := range terminals {
		generation := stateKey{Owner: entry.key, Generation: entry.value.Generation}
		c.recordKnownGeneration(generation)
		if entry.value.Generation == 0 || entry.value.ProcessIncarnation == 0 ||
			entry.value.ObservedMonotonicNS == 0 || entry.value.Reserved != ([7]byte{}) {
			cleaned, cleanupErr := c.quarantineMalformedTerminal(entry.key, entry.value)
			if cleaned {
				if entry.value.Generation == 0 {
					stats.Cleaned++
				} else {
					stats.recordGeneration(cleanedGenerations, generation, false)
				}
			}
			if cleanupErr != nil {
				result = errors.Join(result, cleanupErr)
			}
			continue
		}
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
	for _, entry := range ambiguity {
		if entry.key.Generation == 0 || entry.key.Reserved != 0 {
			_, deleteErr := cleanupDeleteExact(c.maps.ambiguity, entry.key, entry.value)
			if deleteErr != nil {
				result = errors.Join(
					result, fmt.Errorf("deleting malformed ambiguity key: %w", deleteErr),
				)
			}
			continue
		}
		c.recordKnownGeneration(entry.key)
		// Valid generation reservations are retired only with their exact claim
		// and matching G=0 guard in the final fence pass below.
	}

	claims, err := cleanupMapEntries[stateKey, generationClaim](c.maps.claims)
	if err != nil {
		result = errors.Join(result, fmt.Errorf("iterating generation claims: %w", err))
	}
	guards, guardErr := cleanupMapEntries[Identity, generationClaim](c.maps.ownerGuards)
	if guardErr != nil {
		result = errors.Join(result, fmt.Errorf("iterating generation owner guards: %w", guardErr))
	}
	// Exact generation claims and owner guards are retained until the final
	// pass, after every possible logical or physical mutation.

	owners, err := cleanupMapEntries[Identity, ownerValue](c.maps.owners)
	if err != nil {
		result = errors.Join(result, fmt.Errorf("iterating generation owners: %w", err))
	}
	ownersNow := c.monoTimeNow()
	for _, entry := range owners {
		generation := stateKey{Owner: entry.key, Generation: entry.value.Generation}
		_, cleaned := cleanedGenerations[generation]
		recoverable, recoveryErr := c.generationOwnerRecoveryAllowed(
			generation, entry.value, ownersNow,
		)
		if recoveryErr != nil {
			result = errors.Join(result, recoveryErr)
			continue
		}
		processRetired, retirementErr := c.processRetired(
			retired,
			javaProcessIdentity(entry.key),
			entry.value.ProcessIncarnation,
		)
		if retirementErr != nil {
			result = errors.Join(result, retirementErr)
			continue
		}
		if !processRetired {
			_, coherentReservation, reservationErr :=
				c.coherentGenerationPublishingReservation(generation)
			if reservationErr != nil {
				result = errors.Join(result, reservationErr)
				continue
			}
			if coherentReservation {
				continue
			}
		}
		if !recoverable && !cleaned && !processRetired {
			continue
		}
		var cleanupErr error
		if invalidGenerationOwner(entry.value) {
			cleaned, cleanupErr = c.cleanupInvalidOwner(entry.key, entry.value)
		} else {
			cleaned, cleanupErr = c.cleanupOrphanOwner(entry.key, entry.value)
		}
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
		if decodeErr != nil || !record.IsValidRemoteParent() {
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
		key := stateKey{Owner: entry.key, Generation: record.Generation}
		var fallbackOwner ownerValue
		if ownerErr := c.maps.owners.Lookup(&entry.key, &fallbackOwner); ownerErr == nil {
			if invalidGenerationOwner(fallbackOwner) {
				fallbackCleaned, cleanupErr := c.cleanupInvalidOwnerFallback(
					entry.key, fallbackOwner, entry.value, record,
				)
				if fallbackCleaned {
					stats.recordGeneration(cleanedGenerations, key, false)
				}
				if cleanupErr != nil {
					result = errors.Join(result, cleanupErr)
				}
				continue
			}
		} else if !errors.Is(ownerErr, ebpf.ErrKeyNotExist) {
			result = errors.Join(
				result, fmt.Errorf("looking up fallback owner: %w", ownerErr),
			)
			continue
		}
		_, cleaned := cleanedGenerations[key]
		if cleaned || !cleanupExpired(parentsNow, record.ObservedMonotonicNS, c.ttl) {
			continue
		}
		publishingClaim, coherentReservation, reservationErr :=
			c.coherentGenerationPublishingReservation(key)
		if reservationErr != nil {
			result = errors.Join(result, reservationErr)
			continue
		}
		if coherentReservation {
			processRetired, retirementErr := c.processRetired(
				retired, javaProcessIdentity(entry.key), publishingClaim.ProcessIncarnation,
			)
			if retirementErr != nil {
				result = errors.Join(result, retirementErr)
				continue
			}
			if !processRetired {
				continue
			}
		}
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

	// This is the final mutation pass. Retire only a complete, aged exact
	// teardown tuple, and do not touch generation artifacts afterward.
	tailsNow := c.monoTimeNow()
	for _, entry := range claims {
		if entry.key.Generation == 0 || entry.key.Reserved != 0 ||
			!validGenerationCleanupClaim(entry.value) ||
			c.claimCreatedThisSweep(entry.key, entry.value) {
			continue
		}
		if released, ok := c.releasedSweepClaims[entry.key]; ok && released == entry.value {
			// An earlier artifact pass already linearized release of this
			// snapshotted exact claim. Never adopt a byte-identical successor in
			// the same sweep.
			continue
		}
		if _, markerReleased := c.releasedSweepAmbiguities[entry.key]; markerReleased {
			// A released M makes every earlier E snapshot stale, even when the old
			// finish path stopped before releasing that E.
			continue
		}
		claimMatches, matchErr := generationClaimMatches(c.maps.claims, entry.key, entry.value)
		if matchErr != nil {
			result = errors.Join(result, fmt.Errorf("revalidating snapshotted cleanup claim: %w", matchErr))
			continue
		}
		if !claimMatches {
			continue
		}
		var marker uint64
		markerErr := c.maps.ambiguity.Lookup(&entry.key, &marker)
		if errors.Is(markerErr, ebpf.ErrKeyNotExist) {
			complete, completeErr := c.snapshotProvesGenerationCleanupComplete(entry.key)
			if completeErr != nil {
				result = errors.Join(
					result, fmt.Errorf("checking marker-free cleanup completion: %w", completeErr),
				)
				continue
			}
			if complete {
				var guard generationClaim
				guardErr := c.maps.ownerGuards.Lookup(&entry.key.Owner, &guard)
				switch {
				case errors.Is(guardErr, ebpf.ErrKeyNotExist):
					_, guardErr = c.releaseGenerationCleanupClaimTail(
						entry.key, entry.value, tailsNow,
					)
				case guardErr == nil && validGenerationCleanupGuard(entry.key.Owner, guard) &&
					guard.ProcessIncarnation == entry.key.Generation:
					_, guardErr = c.releaseGenerationCleanupClaimGuardTail(
						entry.key, entry.value, tailsNow,
					)
				}
				if guardErr != nil {
					result = errors.Join(
						result, fmt.Errorf("releasing marker-free cleanup tail: %w", guardErr),
					)
				}
				continue
			}
			if entry.value.Reserved[0] == lifecyclePublishing {
				// M- cannot represent a coherent active or detached RESET result;
				// preserve C6 unless complete snapshots prove every artifact absent.
				continue
			}
			ownershipRoot := func() (bool, error) {
				claimMatches, err := generationClaimMatches(c.maps.claims, entry.key, entry.value)
				if err != nil || !claimMatches {
					return false, err
				}
				return c.cleanupMarkerMatches(entry.key, nil)
			}
			if _, _, claimErr := c.claimGenerationCleanup(
				entry.key, entry.value, ownershipRoot,
			); claimErr != nil {
				result = errors.Join(result, claimErr)
			}
			continue
		}
		if markerErr != nil {
			result = errors.Join(result, fmt.Errorf("checking generation cleanup marker: %w", markerErr))
			continue
		}
		if marker == 0 {
			zero := uint64(0)
			if entry.value.Reserved[0] == lifecyclePublishing {
				if _, releaseErr := c.releaseGenerationPublishingCleanupTail(
					entry.key, entry.value, &zero, tailsNow,
				); releaseErr != nil {
					result = errors.Join(
						result, fmt.Errorf("releasing publishing cleanup tail: %w", releaseErr),
					)
				}
				continue
			}
			ownershipRoot := func() (bool, error) {
				claimMatches, err := generationClaimMatches(c.maps.claims, entry.key, entry.value)
				if err != nil || !claimMatches {
					return false, err
				}
				return c.cleanupMarkerMatches(entry.key, &zero)
			}
			if _, _, claimErr := c.claimGenerationCleanup(
				entry.key, entry.value, ownershipRoot,
			); claimErr != nil {
				result = errors.Join(result, claimErr)
			}
			continue
		}
		expectedMarker := marker
		ownershipRoot := func() (bool, error) {
			claimMatches, err := generationClaimMatches(c.maps.claims, entry.key, entry.value)
			if err != nil || !claimMatches {
				return false, err
			}
			return c.cleanupMarkerMatches(entry.key, &expectedMarker)
		}
		ownership, ready, fenceErr := c.claimGenerationCleanup(
			entry.key, entry.value, ownershipRoot,
		)
		if fenceErr != nil {
			result = errors.Join(result, fenceErr)
			continue
		}
		if !ready {
			continue
		}
		cleaned, cleanupErr := c.cleanupRetainedGenerationClaim(entry.key)
		if cleanupErr != nil {
			result = errors.Join(result, cleanupErr)
			continue
		}
		if cleaned {
			stats.recordGeneration(cleanedGenerations, entry.key, false)
		}
		if _, finishErr := c.finishGenerationCleanupFenced(
			entry.key, ownership,
		); finishErr != nil {
			result = errors.Join(result, finishErr)
		}
	}

	// Recover crash/failure tails around the required G -> E -> M acquisition
	// and M -> E -> G retirement orders. A surviving M+ with no valid E may be
	// a paused producer, so preserve it while reconstructing the missing E/G
	// from that durable root; later sweeps age the completed tuple before any
	// payload cleanup or fence retirement.
	for _, entry := range ambiguity {
		if entry.key.Generation == 0 || entry.key.Reserved != 0 || entry.value == 0 {
			continue
		}
		if released, ok := c.releasedSweepAmbiguities[entry.key]; ok && released == entry.value {
			continue
		}
		markerMatches, markerErr := c.cleanupMarkerMatches(entry.key, &entry.value)
		if markerErr != nil {
			result = errors.Join(result, fmt.Errorf("revalidating partial cleanup marker: %w", markerErr))
			continue
		}
		if !markerMatches {
			continue
		}
		var claim generationClaim
		if err := c.maps.claims.Lookup(&entry.key, &claim); err == nil {
			// A valid E is handled by the claim pass; producer or malformed E is
			// an explicit fail-closed block on recovery.
			continue
		} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
			result = errors.Join(result, fmt.Errorf("checking partial cleanup claim: %w", err))
			continue
		}
		claim, ok := c.newGenerationClaim(lifecycleAmbiguous, entry.key.Generation)
		if !ok {
			result = errors.Join(result, errors.New("reading monotonic time for partial cleanup claim"))
			continue
		}
		expectedMarker := entry.value
		if _, _, claimErr := c.claimGenerationCleanup(
			entry.key, claim, func() (bool, error) {
				return c.cleanupMarkerMatches(entry.key, &expectedMarker)
			},
		); claimErr != nil {
			result = errors.Join(result, fmt.Errorf("completing partial cleanup fence: %w", claimErr))
		}
	}
	for _, entry := range guards {
		if released, ok := c.releasedSweepGuards[entry.key]; ok && released == entry.value {
			// An earlier final-fence path already linearized release of this
			// snapshotted guard. Never reuse the stale token against a later
			// byte-identical successor installed under the same owner key.
			continue
		}
		if _, markerReleased := c.releasedSweepAmbiguities[stateKey{
			Owner: entry.key, Generation: entry.value.ProcessIncarnation,
		}]; markerReleased {
			continue
		}
		released, releaseErr := c.releaseGenerationCleanupReservedGuardTail(
			entry.key, entry.value, tailsNow,
		)
		if releaseErr != nil {
			result = errors.Join(result, fmt.Errorf("releasing reserved owner-guard cleanup tail: %w", releaseErr))
			continue
		}
		if released {
			continue
		}
		if _, releaseErr := c.releaseGenerationCleanupGuardTail(
			entry.key, entry.value, tailsNow,
		); releaseErr != nil {
			result = errors.Join(result, fmt.Errorf("releasing owner-guard cleanup tail: %w", releaseErr))
		}
	}

	return result
}

func (c *Cleanup) cleanupOrphanOwner(
	owner Identity,
	indexed ownerValue,
) (cleaned bool, result error) {
	if indexed.Generation == 0 || indexed.ProcessIncarnation == 0 {
		return c.cleanupInvalidOwner(owner, indexed)
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

	ownership, claimed, err := c.claimGenerationCleanupForArtifact(
		key, indexed.ProcessIncarnation, lifecycleStale, func() (bool, error) {
			return cleanupExactMatches(c.maps.owners, owner, indexed)
		},
	)
	if err != nil || !claimed {
		return false, err
	}
	if fenced, fenceErr := c.generationCleanupFenceMatches(ownership); fenceErr != nil {
		return false, fenceErr
	} else if !fenced {
		return false, nil
	}
	mutationStarted := false
	releaseOwnership := false
	defer func() {
		if !mutationStarted && releaseOwnership && result == nil {
			releaseErr := c.releaseGenerationCleanupOwnership(key, ownership)
			if releaseErr != nil {
				result = errors.Join(
					result, fmt.Errorf("releasing orphan owner cleanup claim: %w", releaseErr),
				)
			}
		}
	}()
	lockedOwner, locked, ownerInserted, detachedOwner, err := c.lockGenerationOwner(
		key, indexed.ProcessIncarnation, ownership,
	)
	mutationStarted = mutationStarted || ownerInserted
	if err != nil {
		return false, err
	}
	if fenced, fenceErr := c.generationCleanupFenceMatches(ownership); fenceErr != nil {
		return false, fmt.Errorf("revalidating orphan-owner fence after owner lock: %w", fenceErr)
	} else if !fenced {
		return false, errors.New("orphan-owner fence changed after owner lock")
	}
	if !locked {
		releaseOwnership = true
		return false, nil
	}
	fallbackDeleted, err := c.mutateGenerationCleanupFenced(
		ownership, "orphan-owner fallback deletion", func() (bool, error) {
			return c.deleteFallback(key)
		},
	)
	mutationStarted = mutationStarted || fallbackDeleted
	if err != nil {
		return false, err
	}
	terminalDeleted, err := c.mutateGenerationCleanupFenced(
		ownership, "orphan-owner terminal deletion", func() (bool, error) {
			return c.deleteTerminal(key, indexed.ProcessIncarnation)
		},
	)
	mutationStarted = mutationStarted || terminalDeleted
	if err != nil {
		return false, err
	}
	deleted := false
	if !detachedOwner {
		deleted, err = c.mutateGenerationCleanupFenced(
			ownership, "orphan-owner deletion", func() (bool, error) {
				return cleanupDeleteExact(c.maps.owners, owner, lockedOwner)
			},
		)
		mutationStarted = mutationStarted || deleted
		if err != nil {
			return false, fmt.Errorf("deleting orphan generation owner: %w", err)
		}
	}
	if !deleted && !mutationStarted {
		releaseOwnership = true
		return false, nil
	}
	complete, completeErr := c.generationCleanupLogicalComplete(key)
	if completeErr != nil {
		return false, fmt.Errorf("verifying orphan owner logical cleanup: %w", completeErr)
	}
	if !complete {
		return false, nil
	}
	return true, nil
}

func (c *Cleanup) cleanupInvalidOwner(
	owner Identity,
	indexed ownerValue,
) (bool, error) {
	var encoded [RecordSize]byte
	if err := c.maps.remoteParents.Lookup(&owner, &encoded); err == nil {
		// The fallback quarantine path owns the ordered fallback/owner removal.
		return false, nil
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking invalid owner fallback: %w", err)
	}
	if indexed.Generation == 0 {
		return false, nil
	}
	key := stateKey{Owner: owner, Generation: indexed.Generation}
	ownership, ready, err := c.claimGenerationCleanupForArtifact(
		key, indexed.ProcessIncarnation, lifecycleStale,
		func() (bool, error) {
			return cleanupExactMatches(c.maps.owners, owner, indexed)
		},
	)
	if err != nil || !ready {
		return false, err
	}
	deleted, err := c.mutateGenerationCleanupFenced(
		ownership, "invalid-owner deletion", func() (bool, error) {
			return cleanupDeleteExact(c.maps.owners, owner, indexed)
		},
	)
	if err != nil {
		return false, fmt.Errorf("deleting invalid generation owner: %w", err)
	}
	if !deleted {
		return false, nil
	}
	complete, completeErr := c.generationCleanupLogicalComplete(key)
	if completeErr != nil {
		return false, fmt.Errorf("verifying invalid owner logical cleanup: %w", completeErr)
	}
	return complete, nil
}

func invalidGenerationOwner(owner ownerValue) bool {
	return owner.Generation == 0 || owner.ProcessIncarnation == 0 ||
		owner.Reserved != ([7]byte{}) ||
		(owner.Lifecycle != lifecycleActive && owner.Lifecycle != lifecyclePublishing)
}

func (c *Cleanup) generationNonOwnerLogicalArtifactsAbsent(key stateKey) (bool, error) {
	var state stateValue
	if err := c.maps.states.Lookup(&key, &state); err == nil {
		return false, nil
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking owner recovery state: %w", err)
	}
	var generation generationIndexValue
	if err := c.maps.generations.Lookup(&key, &generation); err == nil {
		return false, nil
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking owner recovery generation: %w", err)
	}
	var encoded [RecordSize]byte
	if err := c.maps.remoteParents.Lookup(&key.Owner, &encoded); err == nil {
		return false, nil
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking owner recovery fallback: %w", err)
	}
	var terminal terminalValue
	if err := c.maps.terminals.Lookup(&key.Owner, &terminal); err == nil {
		if terminal.Generation == key.Generation {
			return false, nil
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking owner recovery terminal: %w", err)
	}
	return true, nil
}

func (c *Cleanup) generationOwnerRecoveryAllowed(
	key stateKey,
	owner ownerValue,
	now time.Duration,
) (bool, error) {
	if key.Reserved != 0 {
		return false, nil
	}
	absent, err := c.generationNonOwnerLogicalArtifactsAbsent(key)
	if err != nil || !absent {
		return absent && invalidGenerationOwner(owner), err
	}
	if invalidGenerationOwner(owner) {
		return true, nil
	}
	var claim generationClaim
	if err := c.maps.claims.Lookup(&key, &claim); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, fmt.Errorf("checking owner recovery claim: %w", err)
		}
	} else if validGenerationCleanupClaim(claim) {
		if claim.ProcessIncarnation == owner.ProcessIncarnation &&
			(c.claimCreatedThisSweep(key, claim) ||
				c.generationCleanupFenceExpired(now, claim.ObservedMonotonicNS)) {
			return true, nil
		}
	}
	var ambiguity uint64
	if err := c.maps.ambiguity.Lookup(&key, &ambiguity); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("checking owner recovery ambiguity marker: %w", err)
	}
	return ambiguity != 0 &&
		c.generationCleanupFenceExpired(now, ambiguity), nil
}

func (c *Cleanup) quarantineMalformedState(
	key stateKey,
	state stateValue,
) (bool, error) {
	if key.Generation == 0 || key.Reserved != 0 {
		// BPF never publishes generation-zero or reserved state keys. Delete
		// only this noncanonical key and leave the canonical generation alone.
		deleted, err := cleanupDeleteExact(c.maps.states, key, state)
		if err != nil {
			return false, fmt.Errorf("deleting malformed state key: %w", err)
		}
		if !deleted {
			return false, nil
		}
		complete, completeErr := c.finishMalformedLogicalKeyCleanup(key)
		if completeErr != nil {
			return false, fmt.Errorf("verifying malformed state-key cleanup: %w", completeErr)
		}
		return complete, nil
	}
	ownership, ready, err := c.claimGenerationCleanupForArtifact(
		key, state.ProcessIncarnation, lifecycleStale,
		func() (bool, error) {
			return cleanupExactMatches(c.maps.states, key, state)
		},
	)
	if err != nil || !ready {
		return false, err
	}
	deleted, err := c.mutateGenerationCleanupFenced(
		ownership, "malformed state deletion", func() (bool, error) {
			return cleanupDeleteExact(c.maps.states, key, state)
		},
	)
	if err != nil || !deleted {
		return false, err
	}
	complete, completeErr := c.generationCleanupLogicalComplete(key)
	if completeErr != nil {
		return false, fmt.Errorf("verifying malformed state logical cleanup: %w", completeErr)
	}
	return complete, nil
}

func (c *Cleanup) quarantineMalformedTerminal(
	owner Identity,
	terminal terminalValue,
) (bool, error) {
	key := stateKey{Owner: owner, Generation: terminal.Generation}
	if terminal.Generation == 0 {
		// Terminal keys are owner-scoped and reusable. Without both generation
		// and retained exact claim no teardown fence can make deletion safe.
		return false, nil
	}
	ownership, ready, err := c.claimGenerationCleanupForArtifact(
		key, terminal.ProcessIncarnation, lifecycleStale,
		func() (bool, error) {
			return cleanupExactMatches(c.maps.terminals, owner, terminal)
		},
	)
	if err != nil || !ready {
		return false, err
	}
	deleted, err := c.mutateGenerationCleanupFenced(
		ownership, "malformed terminal deletion", func() (bool, error) {
			return cleanupDeleteExact(c.maps.terminals, owner, terminal)
		},
	)
	if err != nil || !deleted {
		return false, err
	}
	complete, completeErr := c.generationCleanupLogicalComplete(key)
	if completeErr != nil {
		return false, fmt.Errorf("verifying malformed terminal logical cleanup: %w", completeErr)
	}
	return complete, nil
}

func (c *Cleanup) cleanupInvalidOwnerFallback(
	owner Identity,
	indexed ownerValue,
	encoded [RecordSize]byte,
	record Record,
) (bool, error) {
	key := stateKey{Owner: owner, Generation: record.Generation}
	if !record.IsValidRemoteParent() || !invalidGenerationOwner(indexed) {
		return false, errors.New("refusing coherent fallback in invalid-owner quarantine")
	}
	if indexed.Generation != key.Generation {
		return false, nil
	}
	ownership, ready, err := c.claimGenerationCleanupForArtifact(
		key, indexed.ProcessIncarnation, lifecycleStale,
		func() (bool, error) {
			ownerMatches, matchErr := cleanupExactMatches(c.maps.owners, owner, indexed)
			if matchErr != nil || !ownerMatches {
				return false, matchErr
			}
			return cleanupExactMatches(c.maps.remoteParents, owner, encoded)
		},
	)
	if err != nil || !ready {
		return false, err
	}
	var revalidated ownerValue
	if err := c.maps.owners.Lookup(&owner, &revalidated); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("revalidating invalid fallback owner: %w", err)
	}
	if revalidated != indexed {
		return false, nil
	}
	deleted, err := c.mutateGenerationCleanupFenced(
		ownership, "invalid-owner fallback deletion", func() (bool, error) {
			return cleanupDeleteExact(c.maps.remoteParents, owner, encoded)
		},
	)
	if err != nil {
		return false, fmt.Errorf("deleting invalid-owner fallback: %w", err)
	}
	if !deleted {
		return false, nil
	}
	if _, err := c.mutateGenerationCleanupFenced(
		ownership, "invalid fallback owner deletion", func() (bool, error) {
			return cleanupDeleteExact(c.maps.owners, owner, indexed)
		},
	); err != nil {
		return false, fmt.Errorf("deleting fallback invalid owner: %w", err)
	}
	complete, completeErr := c.generationCleanupLogicalComplete(key)
	if completeErr != nil {
		return false, fmt.Errorf("verifying invalid-owner fallback logical cleanup: %w", completeErr)
	}
	return complete, nil
}

func (c *Cleanup) cleanupOrphanFallback(
	owner Identity,
	encoded [RecordSize]byte,
	record Record,
) (cleaned bool, result error) {
	key := stateKey{Owner: owner, Generation: record.Generation}
	var indexed ownerValue
	if err := c.maps.owners.Lookup(&owner, &indexed); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, fmt.Errorf("looking up orphan fallback owner: %w", err)
		}
		var retained generationClaim
		if err := c.maps.claims.Lookup(&key, &retained); err != nil ||
			!validGenerationCleanupClaim(retained) {
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return false, fmt.Errorf("checking ownerless fallback claim: %w", err)
			}
			return false, nil
		}
		ownership, ready, err := c.claimGenerationCleanup(
			key, retained, func() (bool, error) {
				return cleanupExactMatches(c.maps.remoteParents, owner, encoded)
			},
		)
		if err != nil || !ready {
			return false, err
		}
		deleted, err := c.mutateGenerationCleanupFenced(
			ownership, "ownerless fallback deletion", func() (bool, error) {
				return cleanupDeleteExact(c.maps.remoteParents, owner, encoded)
			},
		)
		if err != nil || !deleted {
			return false, err
		}
		complete, err := c.generationCleanupLogicalComplete(key)
		if err != nil {
			return false, fmt.Errorf("verifying ownerless fallback logical cleanup: %w", err)
		}
		return complete, nil
	}
	if invalidGenerationOwner(indexed) {
		return c.cleanupInvalidOwnerFallback(owner, indexed, encoded, record)
	}
	if indexed.Generation != record.Generation {
		coherent, err := c.coherentActiveOwner(owner, indexed)
		if err != nil || !coherent {
			return false, err
		}
		var retained generationClaim
		if err := c.maps.claims.Lookup(&key, &retained); err != nil ||
			!validGenerationCleanupClaim(retained) {
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return false, fmt.Errorf("checking detached fallback claim: %w", err)
			}
			return false, nil
		}
		ownership, ready, err := c.claimGenerationCleanup(
			key, retained, func() (bool, error) {
				ownerMatches, matchErr := cleanupExactMatches(c.maps.owners, owner, indexed)
				if matchErr != nil || !ownerMatches {
					return false, matchErr
				}
				return cleanupExactMatches(c.maps.remoteParents, owner, encoded)
			},
		)
		if err != nil || !ready {
			return false, err
		}
		deleted, err := c.mutateGenerationCleanupFenced(
			ownership, "detached fallback deletion", func() (bool, error) {
				return cleanupDeleteExact(c.maps.remoteParents, owner, encoded)
			},
		)
		if err != nil {
			return false, err
		}
		if deleted {
			return c.generationCleanupLogicalComplete(key)
		}
		return false, nil
	}
	if indexed.ProcessIncarnation == 0 {
		return false, nil
	}
	ownership, claimed, err := c.claimGenerationCleanupForArtifact(
		key, indexed.ProcessIncarnation, lifecycleStale, func() (bool, error) {
			ownerMatches, matchErr := cleanupExactMatches(c.maps.owners, owner, indexed)
			if matchErr != nil || !ownerMatches {
				return false, matchErr
			}
			return cleanupExactMatches(c.maps.remoteParents, owner, encoded)
		},
	)
	if err != nil || !claimed {
		return false, err
	}
	if fenced, fenceErr := c.generationCleanupFenceMatches(ownership); fenceErr != nil {
		return false, fenceErr
	} else if !fenced {
		return false, nil
	}
	mutationStarted := false
	releaseOwnership := false
	defer func() {
		if !mutationStarted && releaseOwnership && result == nil {
			releaseErr := c.releaseGenerationCleanupOwnership(key, ownership)
			if releaseErr != nil {
				result = errors.Join(
					result, fmt.Errorf("releasing orphan fallback cleanup claim: %w", releaseErr),
				)
			}
		}
	}()
	var revalidated ownerValue
	if err := c.maps.owners.Lookup(&owner, &revalidated); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			releaseOwnership = true
			return false, nil
		}
		return false, err
	}
	if revalidated != indexed {
		releaseOwnership = true
		return false, nil
	}
	deleted, deleteErr := c.mutateGenerationCleanupFenced(
		ownership, "orphan-fallback deletion", func() (bool, error) {
			return cleanupDeleteExact(c.maps.remoteParents, owner, encoded)
		},
	)
	mutationStarted = mutationStarted || deleted
	if deleteErr != nil {
		return false, fmt.Errorf("deleting orphan fallback: %w", deleteErr)
	}
	if !deleted {
		releaseOwnership = true
		return false, nil
	}
	terminalDeleted, err := c.mutateGenerationCleanupFenced(
		ownership, "orphan-fallback terminal deletion", func() (bool, error) {
			return c.deleteTerminal(key, indexed.ProcessIncarnation)
		},
	)
	mutationStarted = mutationStarted || terminalDeleted
	if err != nil {
		return false, err
	}
	ownerDeleted, err := c.mutateGenerationCleanupFenced(
		ownership, "orphan-fallback owner deletion", func() (bool, error) {
			return cleanupDeleteExact(c.maps.owners, owner, indexed)
		},
	)
	mutationStarted = mutationStarted || ownerDeleted
	if err != nil {
		return false, fmt.Errorf("deleting orphan fallback owner: %w", err)
	}
	complete, completeErr := c.generationCleanupLogicalComplete(key)
	if completeErr != nil {
		return false, fmt.Errorf("verifying orphan fallback logical cleanup: %w", completeErr)
	}
	if !complete {
		return false, nil
	}
	return true, nil
}

func (c *Cleanup) quarantineMalformedFallback(
	owner Identity,
	encoded [RecordSize]byte,
) (cleaned bool, result error) {
	var indexed ownerValue
	if err := c.maps.owners.Lookup(&owner, &indexed); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, fmt.Errorf("looking up malformed fallback owner: %w", err)
		}
		// Malformed bytes do not expose a generation or incarnation. Preserve
		// the reusable fallback key rather than inventing cleanup authority.
		return false, nil
	}
	if indexed.Generation == 0 {
		return false, nil
	}

	key := stateKey{Owner: owner, Generation: indexed.Generation}
	ownership, claimed, claimErr := c.claimGenerationCleanupForArtifact(
		key, indexed.ProcessIncarnation, lifecycleDiscarded,
		func() (bool, error) {
			ownerMatches, matchErr := cleanupExactMatches(c.maps.owners, owner, indexed)
			if matchErr != nil || !ownerMatches {
				return false, matchErr
			}
			return cleanupExactMatches(c.maps.remoteParents, owner, encoded)
		},
	)
	if claimErr != nil || !claimed {
		return false, claimErr
	}
	if fenced, fenceErr := c.generationCleanupFenceMatches(ownership); fenceErr != nil {
		return false, fenceErr
	} else if !fenced {
		return false, nil
	}
	mutationStarted := false
	releaseOwnership := false
	defer func() {
		if !mutationStarted && releaseOwnership && result == nil {
			releaseErr := c.releaseGenerationCleanupOwnership(key, ownership)
			if releaseErr != nil {
				result = errors.Join(
					result, fmt.Errorf("releasing malformed fallback cleanup claim: %w", releaseErr),
				)
			}
		}
	}()
	var revalidated ownerValue
	if ownerErr := c.maps.owners.Lookup(&owner, &revalidated); ownerErr != nil {
		if errors.Is(ownerErr, ebpf.ErrKeyNotExist) {
			releaseOwnership = true
			return false, nil
		}
		return false, fmt.Errorf("revalidating malformed fallback owner: %w", ownerErr)
	}
	if revalidated != indexed {
		releaseOwnership = true
		return false, nil
	}

	var generation generationIndexValue
	generationErr := c.maps.generations.Lookup(&key, &generation)
	if generationErr != nil && !errors.Is(generationErr, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("looking up malformed fallback generation: %w", generationErr)
	}
	deleted, deleteErr := c.mutateGenerationCleanupFenced(
		ownership, "malformed-fallback deletion", func() (bool, error) {
			return cleanupDeleteExact(c.maps.remoteParents, owner, encoded)
		},
	)
	mutationStarted = mutationStarted || deleted
	if deleteErr != nil {
		return false, fmt.Errorf("deleting malformed fallback: %w", deleteErr)
	}
	if !deleted {
		releaseOwnership = true
		return false, nil
	}
	// The discarded claim is the durable successor for the removed malformed
	// fallback. A later sweep takes it over after the quiescence interval.
	if generationErr == nil && generation.Process == javaProcessIdentity(owner) &&
		generation.Reserved == 0 &&
		generation.ProcessIncarnation == indexed.ProcessIncarnation {
		return false, nil
	}

	var state stateValue
	if stateErr := c.maps.states.Lookup(&key, &state); stateErr == nil &&
		state.ProcessIncarnation == indexed.ProcessIncarnation {
		return false, nil
	} else if stateErr != nil && !errors.Is(stateErr, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("looking up malformed fallback state: %w", stateErr)
	}

	terminalDeleted, err := c.mutateGenerationCleanupFenced(
		ownership, "malformed-fallback terminal deletion", func() (bool, error) {
			return c.deleteTerminal(key, indexed.ProcessIncarnation)
		},
	)
	mutationStarted = mutationStarted || terminalDeleted
	if err != nil {
		return false, err
	}
	ownerDeleted, deleteErr := c.mutateGenerationCleanupFenced(
		ownership, "malformed-fallback owner deletion", func() (bool, error) {
			return cleanupDeleteExact(c.maps.owners, owner, indexed)
		},
	)
	mutationStarted = mutationStarted || ownerDeleted
	if deleteErr != nil {
		return false, deleteErr
	}
	complete, completeErr := c.generationCleanupLogicalComplete(key)
	if completeErr != nil {
		return false, fmt.Errorf("verifying malformed fallback logical cleanup: %w", completeErr)
	}
	return complete, nil
}

func (c *Cleanup) cleanupOrphanState(
	key stateKey,
	state stateValue,
) (cleaned bool, result error) {
	var indexed generationIndexValue
	if err := c.maps.generations.Lookup(&key, &indexed); err == nil {
		return c.cleanupGeneration(key, indexed)
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("looking up orphan generation index: %w", err)
	}
	ownership, claimed, claimErr := c.claimGenerationCleanupForArtifact(
		key, state.ProcessIncarnation, lifecycleStale, func() (bool, error) {
			return cleanupExactMatches(c.maps.states, key, state)
		},
	)
	if claimErr != nil {
		return false, claimErr
	}
	if !claimed {
		return false, nil
	}
	if fenced, fenceErr := c.generationCleanupFenceMatches(ownership); fenceErr != nil {
		return false, fenceErr
	} else if !fenced {
		return false, nil
	}
	mutationStarted := false
	releaseOwnership := false
	defer func() {
		if !mutationStarted && releaseOwnership && result == nil {
			releaseErr := c.releaseGenerationCleanupOwnership(key, ownership)
			if releaseErr != nil {
				result = errors.Join(
					result, fmt.Errorf("releasing orphan state cleanup claim: %w", releaseErr),
				)
			}
		}
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
	detachedOwner := false
	if !preserved {
		var locked bool
		var ownerInserted bool
		var lockErr error
		owner, locked, ownerInserted, detachedOwner, lockErr = c.lockGenerationOwner(
			key, state.ProcessIncarnation, ownership,
		)
		mutationStarted = mutationStarted || ownerInserted
		if lockErr != nil {
			return false, lockErr
		}
		if fenced, fenceErr := c.generationCleanupFenceMatches(ownership); fenceErr != nil {
			return false, fmt.Errorf("revalidating orphan-state fence after owner lock: %w", fenceErr)
		} else if !fenced {
			return false, errors.New("orphan-state fence changed after owner lock")
		}
		if !locked {
			releaseOwnership = true
			return false, nil
		}
	}

	connectionKey := connectionInfoNS{
		Connection: state.Connection,
		NetNS:      state.ConnectionNetNS,
	}
	var connection connectionClaim
	if err := c.maps.connections.Lookup(&connectionKey, &connection); err == nil {
		if connection.Owner == key.Owner && connection.Generation == key.Generation {
			connectionDeleted, deleteErr := c.deleteConnectionIndexesWithOwnership(
				ownership, connectionKey, connection,
			)
			mutationStarted = mutationStarted || connectionDeleted
			if deleteErr != nil {
				result = errors.Join(result, fmt.Errorf("deleting orphan connection: %w", deleteErr))
			}
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		result = errors.Join(result, fmt.Errorf("looking up orphan connection: %w", err))
	}
	stateDeleted, stateDeleteErr := c.mutateGenerationCleanupFenced(
		ownership, "orphan-state deletion", func() (bool, error) {
			return cleanupDeleteExact(c.maps.states, key, state)
		},
	)
	mutationStarted = mutationStarted || stateDeleted
	if !stateDeleted && stateDeleteErr == nil {
		releaseOwnership = true
	}
	if stateDeleteErr != nil {
		result = errors.Join(result, fmt.Errorf("deleting orphan state: %w", stateDeleteErr))
	}
	fallbackDeleted, fallbackErr := c.mutateGenerationCleanupFenced(
		ownership, "orphan-state fallback deletion", func() (bool, error) {
			return c.deleteFallback(key)
		},
	)
	mutationStarted = mutationStarted || fallbackDeleted
	if fallbackErr != nil {
		result = errors.Join(result, fallbackErr)
	}
	terminalDeleted, terminalErr := c.mutateGenerationCleanupFenced(
		ownership, "orphan-state terminal deletion", func() (bool, error) {
			return c.deleteTerminal(key, state.ProcessIncarnation)
		},
	)
	mutationStarted = mutationStarted || terminalDeleted
	if terminalErr != nil {
		result = errors.Join(result, terminalErr)
	}
	if result != nil {
		return false, result
	}
	if !preserved && !detachedOwner {
		ownerDeleted, err := c.mutateGenerationCleanupFenced(
			ownership, "orphan-state owner deletion", func() (bool, error) {
				return cleanupDeleteExact(c.maps.owners, key.Owner, owner)
			},
		)
		mutationStarted = mutationStarted || ownerDeleted
		if err != nil {
			result = errors.Join(result, fmt.Errorf("deleting orphan generation owner: %w", err))
		}
	}
	if result != nil {
		return false, result
	}
	complete, completeErr := c.generationCleanupLogicalComplete(key)
	if completeErr != nil {
		return false, fmt.Errorf("verifying orphan state logical cleanup: %w", completeErr)
	}
	if !complete {
		return false, nil
	}
	return true, nil
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

func cleanupExactMatches[K, V comparable](
	m lookupDeleteMap,
	key K,
	expected V,
) (bool, error) {
	var current V
	if err := m.Lookup(&key, &current); err != nil {
		return false, ignoreMissing(err)
	}
	return current == expected, nil
}

func cleanupDeleteExact[K, V comparable](m lookupDeleteMap, key K, expected V) (bool, error) {
	// The oldest supported kernels expose only key-based deletion for HASH maps;
	// they do not provide compare-and-delete or lookup-and-delete. The second
	// read rejects replacements that arrived after enumeration, but it is not a
	// synchronization primitive. Callers must establish that the exact entry is
	// stable through Delete: generation-scoped keys are not reusable while their
	// fence tuple exists; reusable owner/connection deletions hold the exact
	// claim and G=0 guard so no competing actor can remove the old value; and
	// publishers use BPF_NOEXIST, so they cannot install a successor until this
	// Delete linearizes.
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
