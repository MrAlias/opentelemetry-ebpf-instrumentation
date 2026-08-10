// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javabridge // import "go.opentelemetry.io/obi/pkg/internal/javabridge"

import (
	"cmp"
	"errors"
	"fmt"
	"sort"
	"sync"
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
	authorized                     cleanupMap
	incarnations                   cleanupMap
	connections                    cleanupMap
	cookieConnections              cleanupMap
	ambiguity                      cleanupMap
	owners                         cleanupMap
	states                         cleanupMap
	generations                    cleanupMap
	terminals                      cleanupMap
	claims                         cleanupMap
	aliasReplays                   cleanupMap
	ownerGuards                    cleanupMap
	handoffs                       cleanupMap
	handoffClaims                  cleanupMap
	handoffMutations               cleanupMap
	taskClaims                     cleanupMap
	threadMappingClaims            cleanupMap
	retired                        cleanupMap
	sslPrewrite                    cleanupMap
	sslPrewriteConnectionAmbiguity cleanupMap
	sslPrewriteConnectionClaims    cleanupMap
	sslPrewriteConnectionOwners    cleanupMap
}

type Cleanup struct {
	maps                          cleanupMaps
	ttl                           time.Duration
	monoTimeNow                   func() time.Duration
	physicalGenerations           map[stateKey]struct{}
	physicalGenerationsByOwner    map[Identity][]stateKey
	deferPhysicalGenerationScan   bool
	currentSweepClaims            map[stateKey]generationClaim
	currentSweepGuards            map[Identity]generationClaim
	releasedSweepClaims           map[stateKey]generationClaim
	releasedSweepGuards           map[Identity]generationClaim
	releasedSweepAmbiguities      map[stateKey]uint64
	fenceRetirementAttempts       map[stateKey]struct{}
	currentSweepAmbiguities       map[stateKey]uint64
	knownGenerations              map[stateKey]struct{}
	knownGenerationsByOwner       map[Identity][]stateKey
	knownLogicalKeys              map[stateKey]struct{}
	knownLogicalKeysByOwner       map[Identity][]stateKey
	generationSnapshotComplete    bool
	stateSnapshotComplete         bool
	aliasReplaySnapshotComplete   bool
	aliasCarrierSnapshotComplete  bool
	aliasReplayEntries            map[aliasReplayKey]aliasReplayValue
	aliasReplayCarriers           map[aliasReplayCarrierKey]struct{}
	aliasReplayCleanupKeys        map[stateKey]aliasReplayKey
	aliasReplayCleanupProofs      map[stateKey]*aliasReplayCleanupProof
	retainedTerminalAuthorities   map[stateKey]terminalValue
	aliasReplayNoCarrier          map[aliasReplayKey]aliasReplayNoCarrierObservation
	generationReplayScanCursor    stateKey
	generationReplayScanCursorSet bool
	generationReplayScanKey       stateKey
	generationReplayScanKeySet    bool
	processClaims                 map[Identity]threadMappingClaimValue
	coordinator                   *GenerationCoordinator
}

const (
	javaRemoteParentMinimumFenceAge                         = time.Second
	javaRemoteParentMaxExactTailClaims                      = 1024
	javaRemoteParentMaxGenerationReplayScanAttemptsPerSweep = 1
	// Kernel monotonic nanoseconds cannot reach these bits within the supported
	// system lifetime. Tag userspace-owned T(execution) claims so an interrupted
	// sweep can finish or release its exact fence on a later pass. M(H) uses the
	// two tag bits as a small state machine: high-only is an ordinary cleanup M,
	// both bits identify a resolved-C sweep, and second-only records proof that a
	// terminal H is the sole remaining generation alias. This makes a partially
	// completed replay -> state -> H drain crash-recoverable without changing H
	// into a malformed carrier.
	javaRemoteParentTaskCleanupClaimTag       = uint64(1) << 63
	javaRemoteParentTerminalHandoffCleanupTag = uint64(1) << 62
	javaRemoteParentProcessCleanupClaimTag    = uint32(1) << 31
	// This E value is neither a producer handoff nor a generic generation
	// cleanup claim. Only the M-derived terminal-H recovery path may adopt it.
	javaRemoteParentTerminalHandoffGenerationClaimTag = uint8(0x48)
)

// Cleanup may recover a tagged userspace P(process) left by an interrupted
// authorization transition. Serialize that recovery snapshot with live Go
// authorization transactions so their finite claims are never adopted. A
// separate global sweep lock prevents Cleanup instances with distinct
// GenerationCoordinators from adopting the same recovered claim concurrently,
// without making every authorization wait behind a full multi-map sweep.
var (
	javaProcessClaimCoordinator sync.Mutex
	javaCleanupSweepCoordinator sync.Mutex
)

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
	claim                      generationClaim
	inheritedFence             bool
	ambiguity                  uint64
	hasAmbiguity               bool
	fence                      generationTeardownFence
	requireValidTerminalAbsent bool
	ready                      bool
}

type generationCleanupRootRevalidator func() (bool, error)

type generationCleanupCompletionValidator func(requireSnapshot bool) (bool, error)

type handoffKey struct {
	PID                uint32
	Namespace          uint32
	Token              uint64
	ProcessIncarnation uint64
}

type handoffClaimValue struct {
	ObservedMonotonicNS uint64
	ProcessIncarnation  uint64
}

// threadMappingClaimValue mirrors java_thread_mapping_claim_t. BPF publishers
// always publish Reserved == 0. Cleanup uses the high Reserved bit plus the
// remaining value bits as an exact, crash-recoverable userspace ownership
// token that BPF cannot adopt or release.
type threadMappingClaimValue struct {
	Child              Identity
	Reserved           uint32
	ProcessIncarnation uint64
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
			authorized:                     wrap(maps.Authorized),
			incarnations:                   wrap(maps.Incarnations),
			connections:                    wrap(maps.Connections),
			cookieConnections:              wrap(maps.CookieConnections),
			ambiguity:                      wrap(maps.Ambiguity),
			owners:                         wrap(maps.Owners),
			states:                         wrap(maps.States),
			generations:                    wrap(maps.Generations),
			terminals:                      wrap(maps.Terminals),
			claims:                         wrap(maps.Claims),
			aliasReplays:                   wrap(maps.AliasReplays),
			ownerGuards:                    wrap(maps.OwnerGuards),
			handoffs:                       wrap(maps.Handoffs),
			handoffClaims:                  wrap(maps.HandoffClaims),
			handoffMutations:               wrap(maps.HandoffMutations),
			taskClaims:                     wrap(maps.TaskClaims),
			threadMappingClaims:            wrap(maps.ThreadMappingClaims),
			retired:                        wrap(maps.Retired),
			sslPrewrite:                    wrap(maps.SSLPrewriteTP),
			sslPrewriteConnectionAmbiguity: wrap(maps.SSLPrewriteConnectionAmbiguity),
			sslPrewriteConnectionClaims:    wrap(maps.SSLPrewriteConnectionClaims),
			sslPrewriteConnectionOwners:    wrap(maps.SSLPrewriteConnectionOwners),
		},
		ttl:                  ttl,
		monoTimeNow:          timing.MonoTimeNow,
		aliasReplayNoCarrier: make(map[aliasReplayKey]aliasReplayNoCarrierObservation),
		coordinator:          coordinator,
	}
}

func (c *Cleanup) Sweep() error {
	_, err := c.SweepWithStats()
	return err
}

// SweepWithStats reclaims expired, retired, malformed, orphaned, and provably
// evicted bridge state. It reports successful reclamations even when another
// cleanup target returns an error during the same sweep.
func (c *Cleanup) SweepWithStats() (stats CleanupStats, err error) {
	if c == nil || !c.complete() {
		return stats, errors.New("java remote-parent cleanup maps are incomplete")
	}
	err = c.sweepSSLPrewrite()
	javaCleanupSweepCoordinator.Lock()
	defer javaCleanupSweepCoordinator.Unlock()
	unlock := c.coordinator.lockCleanup()
	defer unlock()
	persistent := c
	sweep := *c
	sweep.physicalGenerations = nil
	sweep.physicalGenerationsByOwner = nil
	sweep.deferPhysicalGenerationScan = false
	sweep.currentSweepClaims = make(map[stateKey]generationClaim)
	sweep.currentSweepGuards = make(map[Identity]generationClaim)
	sweep.releasedSweepClaims = make(map[stateKey]generationClaim)
	sweep.releasedSweepGuards = make(map[Identity]generationClaim)
	sweep.releasedSweepAmbiguities = make(map[stateKey]uint64)
	sweep.fenceRetirementAttempts = make(map[stateKey]struct{})
	sweep.currentSweepAmbiguities = make(map[stateKey]uint64)
	sweep.knownGenerations = make(map[stateKey]struct{})
	sweep.knownGenerationsByOwner = make(map[Identity][]stateKey)
	sweep.knownLogicalKeys = make(map[stateKey]struct{})
	sweep.knownLogicalKeysByOwner = make(map[Identity][]stateKey)
	sweep.aliasReplayEntries = make(map[aliasReplayKey]aliasReplayValue)
	sweep.aliasReplayCarriers = make(map[aliasReplayCarrierKey]struct{})
	sweep.aliasReplayCleanupKeys = make(map[stateKey]aliasReplayKey)
	sweep.aliasReplayCleanupProofs = make(map[stateKey]*aliasReplayCleanupProof)
	sweep.retainedTerminalAuthorities = make(map[stateKey]terminalValue)
	sweep.generationReplayScanKey = stateKey{}
	sweep.generationReplayScanKeySet = false
	sweep.processClaims = make(map[Identity]threadMappingClaimValue)
	defer func() {
		persistent.generationReplayScanCursor = sweep.generationReplayScanCursor
		persistent.generationReplayScanCursorSet = sweep.generationReplayScanCursorSet
	}()
	if sweep.aliasReplayNoCarrier == nil {
		sweep.aliasReplayNoCarrier = make(map[aliasReplayKey]aliasReplayNoCarrierObservation)
	}
	c = &sweep
	defer func() {
		err = errors.Join(err, c.releaseProcessCleanupClaims())
	}()
	if snapshotErr := c.snapshotAliasReplayState(); snapshotErr != nil {
		err = errors.Join(err, snapshotErr)
	}

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
	javaProcessClaimCoordinator.Lock()
	processClaimErr := c.recoverProcessCleanupClaims()
	javaProcessClaimCoordinator.Unlock()
	if processClaimErr != nil {
		err = errors.Join(err, processClaimErr)
	}
	if quiesceErr := c.quiesceRetiredProcessIncarnations(retired); quiesceErr != nil {
		err = errors.Join(err, quiesceErr)
	}
	unauthorizedRetirementErr := c.recoverUnauthorizedProcessRetirements(retired)
	defer func() {
		err = errors.Join(err, unauthorizedRetirementErr)
	}()
	if taskClaimErr := c.sweepRetiredTaskClaims(retired); taskClaimErr != nil {
		err = errors.Join(err, taskClaimErr)
	}
	if taskErr := c.sweepRetiredTasks(retired); taskErr != nil {
		err = errors.Join(err, taskErr)
	}
	// Recover an interrupted exact-key M before asking this non-evicting map
	// for another slot. Then reclaim resolved admission tickets before and
	// after retired H cleanup. Retired cleanup itself needs only P -> M and
	// never consumes C capacity.
	if mutationErr := c.sweepRetiredHandoffMutations(retired); mutationErr != nil {
		err = errors.Join(err, mutationErr)
	}
	if claimErr := c.sweepResolvedHandoffClaims(); claimErr != nil {
		err = errors.Join(err, claimErr)
	}
	if handoffErr := c.sweepRetiredHandoffs(retired); handoffErr != nil {
		err = errors.Join(err, handoffErr)
	}
	if claimErr := c.sweepResolvedHandoffClaims(); claimErr != nil {
		err = errors.Join(err, claimErr)
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
					cleanedGenerations, canonicalGenerationKey(entry.key),
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
			_, coherentReservation, reservationErr := c.coherentGenerationPublishingReservation(entry.key)
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
			stats.recordGeneration(cleanedGenerations, entry.key)
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
		processRetired, retirementErr := c.processRetired(
			retired, entry.key.Process, entry.key.ProcessIncarnation,
		)
		if retirementErr != nil {
			err = errors.Join(err, retirementErr)
			continue
		}
		if !processRetired {
			continue
		}
		referenced, referenceErr := c.processRetirementReferenced(
			entry.key.Process, entry.key.ProcessIncarnation,
		)
		if referenceErr != nil {
			err = errors.Join(err, referenceErr)
			continue
		}
		if referenced {
			continue
		}
		deleted, deleteErr := cleanupDeleteExact(c.maps.retired, entry.key, entry.value)
		if deleted {
			stats.Cleaned++
			// No exact carrier, replay, or subordinate cleanup reference remains.
			// Open this process slot now so the same sweep can use bounded P/R
			// capacity to publish a previously blocked retirement root below.
			err = errors.Join(err, c.releaseProcessCleanupClaim(entry.key.Process))
		}
		if deleteErr != nil {
			err = errors.Join(err, fmt.Errorf("deleting process retirement: %w", deleteErr))
		}
	}
	// A saturated R map may have gained capacity only after the finalization
	// loop above. Retry exact incarnation roots now; their carriers are handled
	// on the next sweep, while their already-allocated incarnation slot prevents
	// retirement authority from being lost in the meantime.
	unauthorizedRetirementErr = c.recoverUnauthorizedProcessRetirements(retired)
	return stats, err
}

func (s *CleanupStats) recordGeneration(
	cleaned map[stateKey]struct{},
	key stateKey,
) {
	if _, ok := cleaned[key]; ok {
		return
	}
	cleaned[key] = struct{}{}
	s.Cleaned++
}

func javaRemoteParentProcessCleanupClaim(
	now time.Duration,
	process Identity,
	processIncarnation uint64,
) (threadMappingClaimValue, bool) {
	observed := uint64(now)
	if now <= 0 || observed&javaRemoteParentTaskCleanupClaimTag != 0 ||
		process.PID == 0 || process.TID != process.PID || processIncarnation == 0 {
		return threadMappingClaimValue{}, false
	}
	return threadMappingClaimValue{
		Child: Identity{
			TID:       uint32(observed),
			PID:       process.PID,
			Namespace: process.Namespace,
		},
		Reserved:           javaRemoteParentProcessCleanupClaimTag | uint32(observed>>32),
		ProcessIncarnation: processIncarnation,
	}, true
}

func validJavaRemoteParentProcessCleanupClaim(
	process Identity,
	claim threadMappingClaimValue,
) bool {
	if process.PID == 0 || process.TID != process.PID ||
		claim.Reserved&javaRemoteParentProcessCleanupClaimTag == 0 ||
		claim.Child.PID != process.PID || claim.Child.Namespace != process.Namespace ||
		claim.ProcessIncarnation == 0 {
		return false
	}
	observed := uint64(claim.Reserved&^javaRemoteParentProcessCleanupClaimTag)<<32 |
		uint64(claim.Child.TID)
	return observed != 0
}

func (c *Cleanup) recoverProcessCleanupClaims() error {
	claims, err := cleanupMapEntries[Identity, threadMappingClaimValue](
		c.maps.threadMappingClaims,
	)
	if err != nil {
		return fmt.Errorf("iterating Java process cleanup claims: %w", err)
	}
	var result error
	for _, entry := range claims {
		if !validJavaRemoteParentProcessCleanupClaim(entry.key, entry.value) {
			continue
		}
		matches, matchErr := cleanupExactMatches(
			c.maps.threadMappingClaims, entry.key, entry.value,
		)
		if matchErr != nil {
			result = errors.Join(result, fmt.Errorf(
				"revalidating Java process cleanup claim: %w", matchErr,
			))
			continue
		}
		if matches {
			c.processClaims[entry.key] = entry.value
		}
	}
	return result
}

func (c *Cleanup) processAuthorizationRetires(
	process Identity,
	processIncarnation uint64,
) (bool, error) {
	var capability uint64
	if err := c.maps.authorized.Lookup(&process, &capability); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return true, nil
		}
		return false, err
	}
	// Q == A is the only live authorization for I == A. Missing, malformed
	// zero, and successor Q == B all make A quiescent: a delayed A publisher
	// either already owns P or fails its post-claim I(A) revalidation, while B
	// cannot publish until PROCESS_REGISTER installs I == B under the same P.
	return capability != processIncarnation, nil
}

func (c *Cleanup) recoverUnauthorizedProcessRetirements(
	retired map[retiredProcessKey]struct{},
) error {
	incarnations, err := cleanupMapEntries[Identity, uint64](c.maps.incarnations)
	if err != nil {
		return fmt.Errorf("iterating Java process incarnations for retirement: %w", err)
	}

	var result error
	for _, entry := range incarnations {
		process := entry.key
		processIncarnation := entry.value
		if process.PID == 0 || process.TID != process.PID ||
			processIncarnation == 0 || processIncarnation&(uint64(1)<<63) != 0 {
			continue
		}
		retiring, authorizationErr := c.processAuthorizationRetires(
			process, processIncarnation,
		)
		if authorizationErr != nil {
			result = errors.Join(result, fmt.Errorf(
				"looking up Java process authorization before retirement: %w",
				authorizationErr,
			))
			continue
		}
		if !retiring {
			continue
		}

		acquired, claimErr := c.acquireProcessCleanupClaim(process, processIncarnation)
		if claimErr != nil {
			result = errors.Join(result, claimErr)
			continue
		}
		if !acquired {
			continue
		}

		exactClaim, claimErr := c.processCleanupClaimExact(process)
		if claimErr != nil || !exactClaim {
			if claimErr != nil {
				result = errors.Join(result, fmt.Errorf(
					"revalidating Java process claim before retirement: %w", claimErr,
				))
			}
			continue
		}
		var current uint64
		if lookupErr := c.maps.incarnations.Lookup(&process, &current); lookupErr != nil {
			if !errors.Is(lookupErr, ebpf.ErrKeyNotExist) {
				result = errors.Join(result, fmt.Errorf(
					"revalidating Java process incarnation before retirement: %w", lookupErr,
				))
			}
			continue
		}
		if current != processIncarnation {
			continue
		}
		retiring, authorizationErr = c.processAuthorizationRetires(
			process, processIncarnation,
		)
		if authorizationErr != nil {
			result = errors.Join(result, fmt.Errorf(
				"revalidating Java process authorization before retirement: %w",
				authorizationErr,
			))
			continue
		}
		if !retiring {
			continue
		}

		retirement := retiredProcessKey{
			Process: process, ProcessIncarnation: processIncarnation,
		}
		observed := uint64(c.monoTimeNow())
		if observed == 0 || observed&(uint64(1)<<63) != 0 {
			result = errors.Join(result, errors.New(
				"creating Java process retirement observation",
			))
			continue
		}
		markerErr := c.maps.retired.Update(
			&retirement, &observed, ebpf.UpdateNoExist,
		)
		if markerErr != nil {
			var existing uint64
			lookupErr := c.maps.retired.Lookup(&retirement, &existing)
			if lookupErr != nil || existing == 0 {
				if lookupErr != nil && !errors.Is(lookupErr, ebpf.ErrKeyNotExist) {
					markerErr = errors.Join(markerErr, fmt.Errorf(
						"revalidating Java process retirement marker: %w", lookupErr,
					))
				}
				result = errors.Join(result, fmt.Errorf(
					"publishing Java process retirement marker: %w", markerErr,
				))
				// A full R map must not also fill P with roots that made no
				// progress. Releasing this exact idle claim lets the same sweep
				// acquire P for unreferenced old R entries, finalize them, and
				// retry publication after capacity has been recovered.
				result = errors.Join(result, c.releaseProcessCleanupClaim(process))
				continue
			}
		}
		retired[retirement] = struct{}{}

		exactClaim, claimErr = c.processCleanupClaimExact(process)
		if claimErr != nil || !exactClaim {
			if claimErr != nil {
				result = errors.Join(result, fmt.Errorf(
					"revalidating Java process claim after retirement: %w", claimErr,
				))
			}
			continue
		}
		if lookupErr := c.maps.incarnations.Lookup(&process, &current); lookupErr != nil {
			if !errors.Is(lookupErr, ebpf.ErrKeyNotExist) {
				result = errors.Join(result, fmt.Errorf(
					"revalidating Java process incarnation after retirement: %w", lookupErr,
				))
			}
			continue
		}
		if current != processIncarnation {
			continue
		}
		retiring, authorizationErr = c.processAuthorizationRetires(
			process, processIncarnation,
		)
		if authorizationErr != nil {
			result = errors.Join(result, fmt.Errorf(
				"revalidating Java process authorization after retirement: %w",
				authorizationErr,
			))
			continue
		}
		if !retiring {
			continue
		}
		if _, deleteErr := cleanupDeleteExactOrCommitted(
			c.maps.incarnations, process, processIncarnation,
		); deleteErr != nil {
			result = errors.Join(result, fmt.Errorf(
				"deleting retired Java process incarnation: %w", deleteErr,
			))
		}
	}
	return result
}

// R(A) is a permanent boundary for capability A, even before its carrier
// cleanup completes. Remove only an exact I(A) while holding P(process); a
// successor I(B) is preserved. PROCESS_REGISTER refuses R(target), so once P
// opens no ordinary packet can revive A through Q == I.
func (c *Cleanup) quiesceRetiredProcessIncarnations(
	retired map[retiredProcessKey]struct{},
) error {
	var result error
	for entry := range retired {
		acquired, claimErr := c.acquireProcessCleanupClaim(
			entry.Process, entry.ProcessIncarnation,
		)
		if claimErr != nil {
			result = errors.Join(result, fmt.Errorf(
				"acquiring P for retired Java process: %w", claimErr,
			))
			continue
		}
		if !acquired {
			continue
		}
		exact, claimErr := c.processCleanupClaimExact(entry.Process)
		if claimErr != nil || !exact {
			if claimErr != nil {
				result = errors.Join(result, fmt.Errorf(
					"revalidating P for retired Java process: %w", claimErr,
				))
			}
			continue
		}
		if _, deleteErr := cleanupDeleteExactOrCommitted(
			c.maps.incarnations, entry.Process, entry.ProcessIncarnation,
		); deleteErr != nil {
			result = errors.Join(result, fmt.Errorf(
				"quiescing retired Java process incarnation: %w", deleteErr,
			))
		}
	}
	return result
}

func (c *Cleanup) processCleanupClaimExact(process Identity) (bool, error) {
	claim, ok := c.processClaims[process]
	if !ok {
		return false, nil
	}
	var current threadMappingClaimValue
	if err := c.maps.threadMappingClaims.Lookup(&process, &current); err != nil {
		return false, ignoreMissing(err)
	}
	return current == claim, nil
}

func (c *Cleanup) acquireProcessCleanupClaim(
	process Identity,
	processIncarnation uint64,
) (bool, error) {
	if c.processClaims == nil {
		c.processClaims = make(map[Identity]threadMappingClaimValue)
	}
	if _, ok := c.processClaims[process]; ok {
		return c.processCleanupClaimExact(process)
	}
	claim, valid := javaRemoteParentProcessCleanupClaim(
		c.monoTimeNow(), process, processIncarnation,
	)
	if !valid {
		return false, errors.New("creating Java process cleanup claim")
	}
	updateErr := c.maps.threadMappingClaims.Update(
		&process, &claim, ebpf.UpdateNoExist,
	)
	if updateErr != nil && errors.Is(updateErr, ebpf.ErrKeyExist) {
		return false, nil
	}

	var installed threadMappingClaimValue
	lookupErr := c.maps.threadMappingClaims.Lookup(&process, &installed)
	if lookupErr != nil || installed != claim {
		if updateErr != nil {
			return false, fmt.Errorf("acquiring Java process cleanup claim: %w", updateErr)
		}
		if lookupErr != nil {
			return false, fmt.Errorf(
				"revalidating Java process cleanup claim acquisition: %w", lookupErr,
			)
		}
		return false, errors.New("revalidating acquired Java process cleanup claim")
	}
	c.processClaims[process] = claim
	if updateErr != nil {
		return true, fmt.Errorf("acquiring Java process cleanup claim: %w", updateErr)
	}
	return true, nil
}

func (c *Cleanup) processRetiredUnderClaim(
	process Identity,
	processIncarnation uint64,
) (bool, error) {
	exact, err := c.processCleanupClaimExact(process)
	if err != nil {
		return false, fmt.Errorf("revalidating Java process cleanup claim: %w", err)
	}
	if !exact {
		return false, errors.New("java process cleanup claim changed")
	}

	var current uint64
	if err := c.maps.incarnations.Lookup(&process, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return true, nil
		}
		return false, fmt.Errorf("revalidating Java process incarnation: %w", err)
	}
	// I(A) remains a live carrier root until quiesceRetiredProcessIncarnations
	// removes that exact value under P. PROCESS_REGISTER refuses R(A), so it can
	// neither clear the marker nor revive A while cleanup is converging.
	return current != processIncarnation, nil
}

func (c *Cleanup) exactProcessRetirementUnderClaim(
	process Identity,
	processIncarnation uint64,
) (bool, error) {
	exact, err := c.processCleanupClaimExact(process)
	if err != nil {
		return false, fmt.Errorf("revalidating Java process cleanup claim: %w", err)
	}
	if !exact {
		return false, errors.New("java process cleanup claim changed")
	}
	key := retiredProcessKey{
		Process: process, ProcessIncarnation: processIncarnation,
	}
	var observed uint64
	if err := c.maps.retired.Lookup(&key, &observed); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("revalidating exact Java process retirement: %w", err)
	}
	return observed != 0, nil
}

func (c *Cleanup) processRetired(
	retired map[retiredProcessKey]struct{},
	process Identity,
	processIncarnation uint64,
) (bool, error) {
	// Malformed roots do not expose a process capability that P can serialize.
	// Their dedicated quarantine paths must establish their own exact fences.
	if process.PID == 0 || process.TID != process.PID || processIncarnation == 0 {
		return false, nil
	}
	if _, held := c.processClaims[process]; held {
		isRetired, err := c.processRetiredUnderClaim(process, processIncarnation)
		if err != nil || isRetired {
			return isRetired, err
		}
		key := retiredProcessKey{
			Process: process, ProcessIncarnation: processIncarnation,
		}
		// sched_process_exit does not take P and publishes the retirement
		// marker before deauthorization removes the incarnation. Preserve the
		// kernel marker: current == A may be that legitimate exit window.
		delete(retired, key)
		return false, nil
	}

	candidate := false
	if _, ok := retired[retiredProcessKey{
		Process:            process,
		ProcessIncarnation: processIncarnation,
	}]; ok {
		candidate = true
	} else {
		var current uint64
		if err := c.maps.incarnations.Lookup(&process, &current); err != nil {
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				return false, fmt.Errorf("looking up Java process incarnation: %w", err)
			}
			candidate = true
		} else {
			candidate = current != processIncarnation
		}
	}
	if !candidate {
		return false, nil
	}

	acquired, err := c.acquireProcessCleanupClaim(process, processIncarnation)
	if err != nil || !acquired {
		return false, err
	}
	isRetired, retirementErr := c.processRetiredUnderClaim(process, processIncarnation)
	if retirementErr != nil || isRetired {
		return isRetired, retirementErr
	}
	key := retiredProcessKey{
		Process: process, ProcessIncarnation: processIncarnation,
	}
	delete(retired, key)
	return false, nil
}

// processExactlyRetired adds durable writer-death authority to the weaker
// quiescence proved by processRetired. P(process) serializes registration and
// every alias publisher while cleanup runs, but incarnation absence alone is
// not durable proof that the capability completed either last-thread exit or
// an admitted A->B rotation. Deleting a task or handoff without its normal BPF
// alias-release path therefore requires the exact retirement marker as well.
func (c *Cleanup) processExactlyRetired(
	retired map[retiredProcessKey]struct{},
	process Identity,
	processIncarnation uint64,
) (bool, error) {
	quiesced, err := c.processRetired(retired, process, processIncarnation)
	if err != nil || !quiesced {
		return false, err
	}
	return c.exactProcessRetirementUnderClaim(process, processIncarnation)
}

func (c *Cleanup) processCleanupSubordinateRemains(process Identity) (bool, error) {
	taskClaims, err := cleanupMapEntries[Identity, handoffClaimValue](c.maps.taskClaims)
	if err != nil {
		return true, fmt.Errorf("iterating Java task cleanup claims before P release: %w", err)
	}
	for _, entry := range taskClaims {
		if validJavaRemoteParentTaskCleanupClaim(entry.value) &&
			javaProcessIdentity(entry.key) == process {
			return true, nil
		}
	}

	mutations, err := cleanupMapEntries[handoffKey, handoffClaimValue](
		c.maps.handoffMutations,
	)
	if err != nil {
		return true, fmt.Errorf("iterating Java handoff cleanup mutations before P release: %w", err)
	}
	for _, entry := range mutations {
		if validJavaRemoteParentTaskCleanupClaim(entry.value) &&
			entry.key.PID == process.PID && entry.key.Namespace == process.Namespace {
			return true, nil
		}
	}
	return false, nil
}

func (c *Cleanup) processRetirementReferenced(
	process Identity,
	processIncarnation uint64,
) (bool, error) {
	tasks, err := cleanupMapEntries[Identity, taskLink](c.maps.tasks)
	if err != nil {
		return true, fmt.Errorf("iterating Java tasks before retirement release: %w", err)
	}
	for _, entry := range tasks {
		if javaProcessIdentity(entry.key) == process &&
			entry.value.ProcessIncarnation == processIncarnation {
			return true, nil
		}
	}

	handoffs, err := cleanupMapEntries[handoffKey, taskLink](c.maps.handoffs)
	if err != nil {
		return true, fmt.Errorf("iterating Java handoffs before retirement release: %w", err)
	}
	for _, entry := range handoffs {
		if entry.key.PID == process.PID && entry.key.Namespace == process.Namespace &&
			entry.key.ProcessIncarnation == processIncarnation {
			return true, nil
		}
	}

	replays, err := cleanupMapEntries[aliasReplayKey, aliasReplayValue](c.maps.aliasReplays)
	if err != nil {
		return true, fmt.Errorf("iterating Java alias replays before retirement release: %w", err)
	}
	for _, entry := range replays {
		if javaProcessIdentity(entry.key.Owner) == process &&
			entry.key.ProcessIncarnation == processIncarnation {
			return true, nil
		}
	}

	taskClaims, err := cleanupMapEntries[Identity, handoffClaimValue](c.maps.taskClaims)
	if err != nil {
		return true, fmt.Errorf("iterating Java task claims before retirement release: %w", err)
	}
	for _, entry := range taskClaims {
		if javaProcessIdentity(entry.key) == process &&
			entry.value.ProcessIncarnation == processIncarnation &&
			validJavaRemoteParentTaskCleanupClaim(entry.value) {
			return true, nil
		}
	}

	mutations, err := cleanupMapEntries[handoffKey, handoffClaimValue](
		c.maps.handoffMutations,
	)
	if err != nil {
		return true, fmt.Errorf(
			"iterating Java handoff mutations before retirement release: %w", err,
		)
	}
	for _, entry := range mutations {
		if entry.key.PID == process.PID && entry.key.Namespace == process.Namespace &&
			entry.key.ProcessIncarnation == processIncarnation &&
			validJavaRemoteParentTaskCleanupClaim(entry.value) {
			return true, nil
		}
	}
	return false, nil
}

func (c *Cleanup) releaseProcessCleanupClaims() error {
	processes := make([]Identity, 0, len(c.processClaims))
	for process := range c.processClaims {
		processes = append(processes, process)
	}
	sort.Slice(processes, func(i, j int) bool {
		if processes[i].Namespace != processes[j].Namespace {
			return processes[i].Namespace < processes[j].Namespace
		}
		return processes[i].PID < processes[j].PID
	})

	var result error
	for _, process := range processes {
		result = errors.Join(result, c.releaseProcessCleanupClaim(process))
	}
	return result
}

func (c *Cleanup) releaseProcessCleanupClaim(process Identity) error {
	claim, ok := c.processClaims[process]
	if !ok {
		return nil
	}
	remains, err := c.processCleanupSubordinateRemains(process)
	if err != nil {
		return err
	}
	if remains {
		return nil
	}
	deleted, err := cleanupDeleteExactOrCommitted(
		c.maps.threadMappingClaims, process, claim,
	)
	if err != nil {
		return fmt.Errorf("releasing Java process cleanup claim: %w", err)
	}
	if deleted {
		delete(c.processClaims, process)
	}
	return nil
}

func javaRemoteParentTaskCleanupClaim(
	now time.Duration,
	processIncarnation uint64,
) (handoffClaimValue, bool) {
	if now <= 0 || processIncarnation == 0 ||
		uint64(now)&(javaRemoteParentTaskCleanupClaimTag|
			javaRemoteParentTerminalHandoffCleanupTag) != 0 {
		return handoffClaimValue{}, false
	}
	return handoffClaimValue{
		ObservedMonotonicNS: uint64(now) | javaRemoteParentTaskCleanupClaimTag,
		ProcessIncarnation:  processIncarnation,
	}, true
}

func validJavaRemoteParentTaskCleanupClaim(claim handoffClaimValue) bool {
	tags := claim.ObservedMonotonicNS & (javaRemoteParentTaskCleanupClaimTag |
		javaRemoteParentTerminalHandoffCleanupTag)
	return tags != 0 && claim.ProcessIncarnation != 0
}

func validJavaRemoteParentResolvedHandoffCleanupClaim(claim handoffClaimValue) bool {
	tags := claim.ObservedMonotonicNS & (javaRemoteParentTaskCleanupClaimTag |
		javaRemoteParentTerminalHandoffCleanupTag)
	return tags == (javaRemoteParentTaskCleanupClaimTag|
		javaRemoteParentTerminalHandoffCleanupTag) && claim.ProcessIncarnation != 0
}

func validJavaRemoteParentTerminalHandoffCleanupClaim(claim handoffClaimValue) bool {
	tags := claim.ObservedMonotonicNS & (javaRemoteParentTaskCleanupClaimTag |
		javaRemoteParentTerminalHandoffCleanupTag)
	return tags == javaRemoteParentTerminalHandoffCleanupTag &&
		claim.ProcessIncarnation != 0
}

func (c *Cleanup) releaseRecoveredTaskClaim(
	key Identity,
	claim handoffClaimValue,
) error {
	if _, err := cleanupDeleteExact(c.maps.taskClaims, key, claim); err != nil {
		return fmt.Errorf("releasing recovered Java task claim: %w", err)
	}
	return nil
}

// Recover a userspace-owned T(execution) left by an interrupted sweep. The
// exact claim remains the serialization fence while a retired A task is
// removed. A live same-capability observation aborts task cleanup and releases
// the tagged userspace claim so it cannot permanently block that process. A
// successor B value is preserved. No task-map access is allowed after release.
func (c *Cleanup) sweepRetiredTaskClaims(
	retired map[retiredProcessKey]struct{},
) error {
	claims, err := cleanupMapEntries[Identity, handoffClaimValue](c.maps.taskClaims)
	if err != nil {
		return fmt.Errorf("iterating retired Java task claims: %w", err)
	}
	var result error
	for _, entry := range claims {
		if entry.key.PID == 0 || !validJavaRemoteParentTaskCleanupClaim(entry.value) {
			continue
		}
		process := javaProcessIdentity(entry.key)
		acquired, claimErr := c.acquireProcessCleanupClaim(
			process, entry.value.ProcessIncarnation,
		)
		if claimErr != nil {
			result = errors.Join(result, fmt.Errorf(
				"acquiring P for recovered Java task claim: %w", claimErr,
			))
			continue
		}
		if !acquired {
			continue
		}
		isRetired, retirementErr := c.processExactlyRetired(
			retired, process, entry.value.ProcessIncarnation,
		)
		if retirementErr != nil {
			result = errors.Join(result, fmt.Errorf(
				"checking claimed Java task process retirement: %w", retirementErr,
			))
			continue
		}
		if !isRetired {
			exact, claimErr := c.processCleanupClaimExact(process)
			if claimErr != nil {
				result = errors.Join(result, fmt.Errorf(
					"revalidating live Java process cleanup claim: %w", claimErr,
				))
				continue
			}
			if !exact {
				// A foreign PROCESS_REGISTER/TASK_LINK owns P. Do not open the
				// recovered T beneath it; the next sweep can adopt T after P clears.
				continue
			}
			result = errors.Join(
				result, c.releaseRecoveredTaskClaim(entry.key, entry.value),
			)
			continue
		}

		var linked taskLink
		lookupErr := c.maps.tasks.Lookup(&entry.key, &linked)
		switch {
		case lookupErr == nil && linked.ProcessIncarnation == entry.value.ProcessIncarnation:
			// The initial retirement check only justified inspecting this
			// userspace-owned fence. Revalidate after the exact task read and
			// immediately before its deletion, matching the normal claim path.
			isRetired, retirementErr = c.processExactlyRetired(
				retired, process, entry.value.ProcessIncarnation,
			)
			if retirementErr != nil {
				result = errors.Join(result, fmt.Errorf(
					"revalidating claimed Java task process retirement before deletion: %w",
					retirementErr,
				))
				continue
			}
			if !isRetired {
				result = errors.Join(
					result, c.releaseRecoveredTaskClaim(entry.key, entry.value),
				)
				continue
			}
			if _, deleteErr := cleanupDeleteExact(c.maps.tasks, entry.key, linked); deleteErr != nil {
				result = errors.Join(result, fmt.Errorf(
					"deleting task under recovered Java task claim: %w", deleteErr,
				))
			}
		case lookupErr != nil && !errors.Is(lookupErr, ebpf.ErrKeyNotExist):
			result = errors.Join(result, fmt.Errorf(
				"looking up task under recovered Java task claim: %w", lookupErr,
			))
			continue
		}

		// Revalidate after the task mutation and before opening T. A conclusive
		// same-capability registration is safe to release to because this path
		// performs no further task-map access; uncertainty keeps the claim closed.
		isRetired, retirementErr = c.processExactlyRetired(
			retired, process, entry.value.ProcessIncarnation,
		)
		if retirementErr != nil {
			result = errors.Join(result, fmt.Errorf(
				"revalidating claimed Java task process retirement: %w", retirementErr,
			))
			continue
		}
		if !isRetired {
			result = errors.Join(
				result, c.releaseRecoveredTaskClaim(entry.key, entry.value),
			)
			continue
		}
		result = errors.Join(
			result, c.releaseRecoveredTaskClaim(entry.key, entry.value),
		)
	}
	return result
}

// Reclaim task carriers for retired process capabilities under the same
// non-evicting T(execution) fence used by every BPF publisher. The task key is
// reusable across process incarnations, so retirement and the exact A value
// are both revalidated only after UpdateNoExist proves ownership of T. A BPF
// successor either publishes before this claim and is preserved, or observes
// the claim and cannot publish until the final exact release.
func (c *Cleanup) sweepRetiredTasks(
	retired map[retiredProcessKey]struct{},
) error {
	tasks, err := cleanupMapEntries[Identity, taskLink](c.maps.tasks)
	if err != nil {
		return fmt.Errorf("iterating retired Java tasks: %w", err)
	}
	var result error
	for _, entry := range tasks {
		if entry.key.PID == 0 || entry.value.ProcessIncarnation == 0 {
			continue
		}
		process := javaProcessIdentity(entry.key)
		isRetired, retirementErr := c.processExactlyRetired(
			retired, process, entry.value.ProcessIncarnation,
		)
		if retirementErr != nil {
			result = errors.Join(result, fmt.Errorf(
				"checking Java task process retirement: %w", retirementErr,
			))
			continue
		}
		if !isRetired {
			continue
		}

		claim, valid := javaRemoteParentTaskCleanupClaim(
			c.monoTimeNow(), entry.value.ProcessIncarnation,
		)
		if !valid {
			result = errors.Join(result, errors.New("creating Java task cleanup claim"))
			continue
		}
		if updateErr := c.maps.taskClaims.Update(
			&entry.key, &claim, ebpf.UpdateNoExist,
		); updateErr != nil {
			if !errors.Is(updateErr, ebpf.ErrKeyExist) {
				result = errors.Join(result, fmt.Errorf(
					"acquiring Java task claim: %w", updateErr,
				))
			}
			continue
		}

		var installed handoffClaimValue
		owned := c.maps.taskClaims.Lookup(&entry.key, &installed) == nil && installed == claim
		if owned {
			isRetired, retirementErr = c.processExactlyRetired(
				retired, process, entry.value.ProcessIncarnation,
			)
			if retirementErr != nil {
				result = errors.Join(result, fmt.Errorf(
					"revalidating Java task process retirement: %w", retirementErr,
				))
			} else if isRetired {
				if _, deleteErr := cleanupDeleteExact(
					c.maps.tasks, entry.key, entry.value,
				); deleteErr != nil {
					result = errors.Join(result, fmt.Errorf(
						"deleting retired Java task: %w", deleteErr,
					))
				}
			}
		} else {
			result = errors.Join(result, errors.New("revalidating acquired Java task claim"))
		}

		// This exact release is the final operation for the task key. Even an
		// uncertain task deletion must open T so later BPF cleanup can converge.
		if _, releaseErr := cleanupDeleteExact(c.maps.taskClaims, entry.key, claim); releaseErr != nil {
			result = errors.Join(result, fmt.Errorf(
				"releasing Java task claim: %w", releaseErr,
			))
		}
	}
	return result
}

func (c *Cleanup) acquireHandoffCleanupMutation(
	key handoffKey,
) (handoffClaimValue, bool, error) {
	claim, valid := javaRemoteParentTaskCleanupClaim(
		c.monoTimeNow(), key.ProcessIncarnation,
	)
	if !valid {
		return handoffClaimValue{}, false, errors.New("creating Java handoff cleanup mutation")
	}
	updateErr := c.maps.handoffMutations.Update(&key, &claim, ebpf.UpdateNoExist)
	if updateErr != nil && errors.Is(updateErr, ebpf.ErrKeyExist) {
		return handoffClaimValue{}, false, nil
	}
	var installed handoffClaimValue
	lookupErr := c.maps.handoffMutations.Lookup(&key, &installed)
	if lookupErr != nil || installed != claim {
		if updateErr != nil {
			return handoffClaimValue{}, false, fmt.Errorf(
				"acquiring Java handoff cleanup mutation: %w", updateErr,
			)
		}
		if lookupErr != nil {
			return handoffClaimValue{}, false, fmt.Errorf(
				"revalidating Java handoff cleanup mutation: %w", lookupErr,
			)
		}
		return handoffClaimValue{}, false, errors.New(
			"revalidating acquired Java handoff cleanup mutation",
		)
	}
	if updateErr != nil {
		return claim, true, fmt.Errorf("acquiring Java handoff cleanup mutation: %w", updateErr)
	}
	return claim, true, nil
}

func (c *Cleanup) releaseHandoffCleanupMutation(
	key handoffKey,
	claim handoffClaimValue,
) error {
	if _, err := cleanupDeleteExact(c.maps.handoffMutations, key, claim); err != nil {
		return fmt.Errorf("releasing Java handoff cleanup mutation: %w", err)
	}
	return nil
}

type terminalHandoffAliasSnapshot struct {
	stateKey      stateKey
	state         stateValue
	statePresent  bool
	index         generationIndexValue
	replayKey     aliasReplayKey
	replay        aliasReplayValue
	replayPresent bool
}

func validTerminalHandoffCarrier(key handoffKey, carrier taskLink) bool {
	return validAliasReplayCarrierLink(carrier) &&
		taskLinkOwnerMatchesProcess(carrier, key.PID, key.Namespace) &&
		carrier.ProcessIncarnation == key.ProcessIncarnation
}

func validTerminalHandoffState(
	key stateKey,
	carrier taskLink,
	state stateValue,
) bool {
	if key.Reserved != 0 || state.Lifecycle != lifecycleActive ||
		state.Reserved != ([3]byte{}) ||
		state.ObservedMonotonicNS != carrier.ObservedMonotonicNS ||
		state.ProcessIncarnation != carrier.ProcessIncarnation ||
		state.ConnectionNetNS == 0 || !validGenerationConnection(state.Connection) {
		return false
	}
	record, err := UnmarshalRecord(state.Response[:])
	return err == nil && record.IsValidRemoteParent() &&
		record.Generation == key.Generation &&
		record.ObservedMonotonicNS == carrier.ObservedMonotonicNS
}

func validTerminalHandoffReplay(replay aliasReplayValue) bool {
	return validAliasReplayActive(replay) || validAliasReplayPublishing(replay) ||
		validAliasReplayFinal(replay)
}

// terminalHandoffAliasSnapshot validates the exact generation carrier that H
// names. Before M is tagged, both counts must be one: with P blocking new
// retains and M stabilizing H, that proves no other carrier can still release
// either counter. Once M is tagged, zero and absent values are resumable
// completion states for an interrupted replay -> state drain.
func (c *Cleanup) terminalHandoffAliasSnapshot(
	carrier taskLink,
	prepared bool,
) (terminalHandoffAliasSnapshot, bool, error) {
	snapshot := terminalHandoffAliasSnapshot{
		stateKey: stateKey{Owner: carrier.Owner, Generation: carrier.Generation},
		replayKey: aliasReplayKey{
			Owner:               carrier.Owner,
			Generation:          carrier.Generation,
			ObservedMonotonicNS: carrier.ObservedMonotonicNS,
			ProcessIncarnation:  carrier.ProcessIncarnation,
		},
	}

	if err := c.maps.states.Lookup(&snapshot.stateKey, &snapshot.state); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return snapshot, false, fmt.Errorf("looking up terminal handoff state: %w", err)
		}
		if !prepared {
			return snapshot, false, nil
		}
	} else {
		snapshot.statePresent = true
		if !validTerminalHandoffState(snapshot.stateKey, carrier, snapshot.state) ||
			(prepared && snapshot.state.Aliases > 1) ||
			(!prepared && snapshot.state.Aliases != 1) {
			return snapshot, false, nil
		}
		if err := c.maps.generations.Lookup(&snapshot.stateKey, &snapshot.index); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return snapshot, false, nil
			}
			return snapshot, false, fmt.Errorf(
				"looking up terminal handoff generation index: %w", err,
			)
		}
		if !validFinishGenerationIndex(snapshot.stateKey, snapshot.index, snapshot.state) {
			return snapshot, false, nil
		}
	}

	if err := c.maps.aliasReplays.Lookup(&snapshot.replayKey, &snapshot.replay); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return snapshot, false, fmt.Errorf("looking up terminal handoff alias replay: %w", err)
		}
		if !prepared {
			return snapshot, false, nil
		}
	} else {
		snapshot.replayPresent = true
		if !validTerminalHandoffReplay(snapshot.replay) ||
			(prepared && snapshot.replay.References > 1) ||
			(!prepared && snapshot.replay.References != 1) {
			return snapshot, false, nil
		}
	}

	if snapshot.statePresent && snapshot.replayPresent &&
		!aliasReplayBindingMatchesState(snapshot.replay, snapshot.state) {
		return snapshot, false, nil
	}
	if prepared && !snapshot.statePresent && snapshot.replayPresent &&
		snapshot.replay.References != 0 {
		return snapshot, false, nil
	}
	return snapshot, true, nil
}

func (c *Cleanup) terminalHandoffAliasSnapshotExact(
	snapshot terminalHandoffAliasSnapshot,
) (bool, error) {
	exact, err := cleanupExactMatches(c.maps.states, snapshot.stateKey, snapshot.state)
	if err != nil || !exact {
		return exact, err
	}
	exact, err = cleanupExactMatches(c.maps.generations, snapshot.stateKey, snapshot.index)
	if err != nil || !exact {
		return exact, err
	}
	return cleanupExactMatches(c.maps.aliasReplays, snapshot.replayKey, snapshot.replay)
}

func (c *Cleanup) terminalHandoffClaimAbsent(key handoffKey) (bool, error) {
	var claim handoffClaimValue
	if err := c.maps.handoffClaims.Lookup(&key, &claim); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

// cleanupUpdateExactValue performs a whole-value transition only after two
// exact reads. Callers must hold the map-specific serialization fence. An exact
// replacement readback is authoritative even when Update reported an unknown
// outcome; counter callers may also treat absence as completed teardown.
func cleanupUpdateExactValue[K, V comparable](
	m cleanupMap,
	key K,
	expected V,
	replacement V,
	missingComplete bool,
) (bool, error) {
	for range 2 {
		var current V
		if err := m.Lookup(&key, &current); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return missingComplete, nil
			}
			return false, err
		}
		if current == replacement {
			return true, nil
		}
		if current != expected {
			return false, nil
		}
	}

	updateErr := m.Update(&key, &replacement, ebpf.UpdateExist)
	var current V
	lookupErr := m.Lookup(&key, &current)
	if lookupErr == nil && current == replacement {
		return true, nil
	}
	if errors.Is(lookupErr, ebpf.ErrKeyNotExist) && missingComplete {
		return true, nil
	}
	if updateErr != nil && lookupErr != nil {
		return false, errors.Join(updateErr, lookupErr)
	}
	if updateErr != nil {
		return false, updateErr
	}
	if lookupErr != nil {
		return false, lookupErr
	}
	return false, errors.New("exact cleanup value changed during update")
}

func (c *Cleanup) markResolvedHandoffCleanupMutation(
	key handoffKey,
	mutation *handoffClaimValue,
) (bool, error) {
	if validJavaRemoteParentResolvedHandoffCleanupClaim(*mutation) {
		return true, nil
	}
	if !validJavaRemoteParentTaskCleanupClaim(*mutation) ||
		mutation.ObservedMonotonicNS&javaRemoteParentTerminalHandoffCleanupTag != 0 {
		return false, nil
	}
	resolved := *mutation
	resolved.ObservedMonotonicNS |= javaRemoteParentTerminalHandoffCleanupTag
	updated, err := cleanupUpdateExactValue(
		c.maps.handoffMutations, key, *mutation, resolved, false,
	)
	if err != nil {
		return false, fmt.Errorf("marking resolved Java handoff cleanup mutation: %w", err)
	}
	if updated {
		*mutation = resolved
	}
	return updated, nil
}

func terminalHandoffGenerationCleanupClaim(
	mutation handoffClaimValue,
	carrier taskLink,
) (stateKey, generationClaim, bool) {
	key := stateKey{Owner: carrier.Owner, Generation: carrier.Generation}
	observed := mutation.ObservedMonotonicNS &^
		(javaRemoteParentTaskCleanupClaimTag | javaRemoteParentTerminalHandoffCleanupTag)
	claim := generationClaim{
		ObservedMonotonicNS: observed,
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecycleCleanup,
		Reserved: [7]byte{
			0: lifecycleAmbiguous,
			6: javaRemoteParentTerminalHandoffGenerationClaimTag,
		},
	}
	return key, claim, validTerminalHandoffGenerationCleanupClaim(key, claim)
}

func validTerminalHandoffGenerationCleanupClaim(
	key stateKey,
	claim generationClaim,
) bool {
	return key.Owner != (Identity{}) && key.Generation != 0 && key.Reserved == 0 &&
		claim.ObservedMonotonicNS != 0 && claim.ProcessIncarnation == key.Generation &&
		claim.Lifecycle == lifecycleCleanup &&
		claim.Reserved == ([7]byte{
			0: lifecycleAmbiguous,
			6: javaRemoteParentTerminalHandoffGenerationClaimTag,
		})
}

// A generation finalizer can whole-update replay lifecycle and references
// without P or M(H). Callers acquire this deterministic exact E claim after
// P -> M; E holders never acquire M. E serializes that writer with terminal-H
// counter updates, and its value is derived from durable M so a later sweep can
// adopt or release it after any interrupted outcome.
func (c *Cleanup) acquireTerminalHandoffGenerationClaim(
	mutation handoffClaimValue,
	carrier taskLink,
) (stateKey, generationClaim, bool, error) {
	key, claim, valid := terminalHandoffGenerationCleanupClaim(mutation, carrier)
	if !valid {
		return stateKey{}, generationClaim{}, false,
			errors.New("creating terminal Java handoff generation claim")
	}
	updateErr := c.maps.claims.Update(&key, &claim, ebpf.UpdateNoExist)
	var current generationClaim
	lookupErr := c.maps.claims.Lookup(&key, &current)
	if lookupErr == nil && current == claim {
		c.recordCurrentSweepClaim(key, claim)
		return key, claim, true, nil
	}
	if updateErr != nil && !errors.Is(updateErr, ebpf.ErrKeyExist) {
		if lookupErr != nil {
			return key, claim, false, errors.Join(updateErr, lookupErr)
		}
		return key, claim, false, updateErr
	}
	if lookupErr != nil && !errors.Is(lookupErr, ebpf.ErrKeyNotExist) {
		return key, claim, false, lookupErr
	}
	return key, claim, false, nil
}

func (c *Cleanup) releaseTerminalHandoffGenerationClaim(
	key stateKey,
	claim generationClaim,
) (bool, error) {
	deleted, err := cleanupDeleteExactOrCommitted(c.maps.claims, key, claim)
	if err != nil {
		return false, err
	}
	if deleted {
		c.clearCurrentSweepClaim(key, claim)
		c.recordReleasedSweepClaim(key, claim)
	}
	return deleted, nil
}

func (c *Cleanup) releaseResolvedHandoffGenerationClaim(
	key handoffKey,
	mutation handoffClaimValue,
) (bool, error) {
	var carrier taskLink
	if err := c.maps.handoffs.Lookup(&key, &carrier); err != nil {
		return false, ignoreMissing(err)
	}
	if !validTerminalHandoffCarrier(key, carrier) {
		return false, nil
	}
	generationKey, claim, valid := terminalHandoffGenerationCleanupClaim(mutation, carrier)
	if !valid {
		return false, nil
	}
	exact, err := cleanupExactMatches(c.maps.claims, generationKey, claim)
	if err != nil || !exact {
		return false, err
	}
	released, err := c.releaseTerminalHandoffGenerationClaim(generationKey, claim)
	return !released, err
}

func (c *Cleanup) terminalHandoffStructuralFenceExact(
	key handoffKey,
	mutation handoffClaimValue,
	carrier taskLink,
) (bool, error) {
	process := Identity{TID: key.PID, PID: key.PID, Namespace: key.Namespace}
	exact, err := c.processCleanupClaimExact(process)
	if err != nil || !exact {
		return false, err
	}
	exact, err = cleanupExactMatches(c.maps.handoffMutations, key, mutation)
	if err != nil || !exact {
		return false, err
	}
	exact, err = cleanupExactMatches(c.maps.handoffs, key, carrier)
	return exact, err
}

func (c *Cleanup) terminalHandoffFenceExact(
	key handoffKey,
	mutation handoffClaimValue,
	carrier taskLink,
) (bool, error) {
	exact, err := c.terminalHandoffStructuralFenceExact(key, mutation, carrier)
	if err != nil || !exact {
		return exact, err
	}
	absent, err := c.terminalHandoffClaimAbsent(key)
	if err != nil || !absent {
		return false, err
	}
	return true, nil
}

func (c *Cleanup) terminalHandoffGenerationFenceExact(
	key handoffKey,
	mutation handoffClaimValue,
	carrier taskLink,
	generationKey stateKey,
	claim generationClaim,
) (bool, error) {
	fenced, err := c.terminalHandoffStructuralFenceExact(key, mutation, carrier)
	if err != nil || !fenced {
		return fenced, err
	}
	return cleanupExactMatches(c.maps.claims, generationKey, claim)
}

func (c *Cleanup) terminalHandoffFullFenceExact(
	key handoffKey,
	mutation handoffClaimValue,
	carrier taskLink,
	generationKey stateKey,
	claim generationClaim,
) (bool, error) {
	fenced, err := c.terminalHandoffGenerationFenceExact(
		key, mutation, carrier, generationKey, claim,
	)
	if err != nil || !fenced {
		return fenced, err
	}
	absent, err := c.terminalHandoffClaimAbsent(key)
	if err != nil || !absent {
		return false, err
	}
	return true, nil
}

func (c *Cleanup) prepareTerminalHandoffCleanup(
	key handoffKey,
	mutation *handoffClaimValue,
) (bool, error) {
	if !validJavaRemoteParentResolvedHandoffCleanupClaim(*mutation) {
		return true, nil
	}
	var carrier taskLink
	if err := c.maps.handoffs.Lookup(&key, &carrier); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return true, fmt.Errorf("looking up terminal Java handoff: %w", err)
	}
	if !validTerminalHandoffCarrier(key, carrier) {
		return true, nil
	}

	fenced, err := c.terminalHandoffStructuralFenceExact(key, *mutation, carrier)
	if err != nil {
		return true, err
	}
	if !fenced {
		return true, nil
	}
	absent, err := c.terminalHandoffClaimAbsent(key)
	if err != nil {
		return true, err
	}
	if !absent {
		// Before the durable transition, a reappearing C means this was not the
		// terminal observation. H remains an ordinary valid carrier, so M may open.
		return false, nil
	}
	generationKey, generationClaim, claimed, err := c.acquireTerminalHandoffGenerationClaim(*mutation, carrier)
	if err != nil {
		return true, fmt.Errorf("acquiring terminal Java handoff generation claim: %w", err)
	}
	if !claimed {
		return true, nil
	}
	fenced, err = c.terminalHandoffGenerationFenceExact(
		key, *mutation, carrier, generationKey, generationClaim,
	)
	if err != nil || !fenced {
		return true, err
	}
	absent, err = c.terminalHandoffClaimAbsent(key)
	if err != nil {
		return true, err
	}
	if !absent {
		released, releaseErr := c.releaseTerminalHandoffGenerationClaim(
			generationKey, generationClaim,
		)
		if releaseErr != nil {
			return true, fmt.Errorf(
				"releasing false-positive terminal handoff generation claim: %w", releaseErr,
			)
		}
		return !released, nil
	}

	snapshot, ready, err := c.terminalHandoffAliasSnapshot(carrier, false)
	if err != nil || !ready {
		return true, err
	}
	exact, err := c.terminalHandoffAliasSnapshotExact(snapshot)
	if err != nil {
		return true, err
	}
	if !exact {
		return true, nil
	}
	fenced, err = c.terminalHandoffFullFenceExact(
		key, *mutation, carrier, generationKey, generationClaim,
	)
	if err != nil || !fenced {
		return true, err
	}

	prepared := *mutation
	prepared.ObservedMonotonicNS &^= javaRemoteParentTaskCleanupClaimTag
	updated, err := cleanupUpdateExactValue(
		c.maps.handoffMutations, key, *mutation, prepared, false,
	)
	if err != nil {
		return true, fmt.Errorf("preparing terminal Java handoff cleanup: %w", err)
	}
	if !updated {
		return true, nil
	}
	*mutation = prepared
	return c.finishTerminalHandoffCleanup(key, mutation)
}

func (c *Cleanup) finishTerminalHandoffCleanup(
	key handoffKey,
	mutation *handoffClaimValue,
) (bool, error) {
	if !validJavaRemoteParentTerminalHandoffCleanupClaim(*mutation) {
		return true, nil
	}
	var carrier taskLink
	if err := c.maps.handoffs.Lookup(&key, &carrier); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return true, fmt.Errorf("looking up prepared terminal Java handoff: %w", err)
	}
	if !validTerminalHandoffCarrier(key, carrier) {
		return true, nil
	}
	fenced, err := c.terminalHandoffFenceExact(key, *mutation, carrier)
	if err != nil || !fenced {
		return true, err
	}
	generationKey, generationClaim, claimed, err := c.acquireTerminalHandoffGenerationClaim(*mutation, carrier)
	if err != nil {
		return true, fmt.Errorf("acquiring prepared terminal handoff generation claim: %w", err)
	}
	if !claimed {
		return true, nil
	}
	fenced, err = c.terminalHandoffFullFenceExact(
		key, *mutation, carrier, generationKey, generationClaim,
	)
	if err != nil || !fenced {
		return true, err
	}

	snapshot, ready, err := c.terminalHandoffAliasSnapshot(carrier, true)
	if err != nil || !ready {
		return true, err
	}
	fenced, err = c.terminalHandoffFullFenceExact(
		key, *mutation, carrier, generationKey, generationClaim,
	)
	if err != nil || !fenced {
		return true, err
	}
	if snapshot.replayPresent && snapshot.replay.References == 1 {
		released := snapshot.replay
		released.References = 0
		updated, updateErr := cleanupUpdateExactValue(
			c.maps.aliasReplays, snapshot.replayKey, snapshot.replay, released, true,
		)
		if updateErr != nil {
			return true, fmt.Errorf("releasing terminal Java handoff replay reference: %w", updateErr)
		}
		if !updated {
			return true, nil
		}
	}

	fenced, err = c.terminalHandoffFullFenceExact(
		key, *mutation, carrier, generationKey, generationClaim,
	)
	if err != nil || !fenced {
		return true, err
	}
	if snapshot.statePresent && snapshot.state.Aliases == 1 {
		released := snapshot.state
		released.Aliases = 0
		updated, updateErr := cleanupUpdateExactValue(
			c.maps.states, snapshot.stateKey, snapshot.state, released, true,
		)
		if updateErr != nil {
			return true, fmt.Errorf("releasing terminal Java handoff state alias: %w", updateErr)
		}
		if !updated {
			return true, nil
		}
	}

	fenced, err = c.terminalHandoffFullFenceExact(
		key, *mutation, carrier, generationKey, generationClaim,
	)
	if err != nil || !fenced {
		return true, err
	}
	released, releaseErr := c.releaseTerminalHandoffGenerationClaim(
		generationKey, generationClaim,
	)
	if releaseErr != nil {
		return true, fmt.Errorf("releasing terminal handoff generation claim: %w", releaseErr)
	}
	if !released {
		return true, nil
	}
	fenced, err = c.terminalHandoffFenceExact(key, *mutation, carrier)
	if err != nil || !fenced {
		return true, err
	}
	deleted, deleteErr := cleanupDeleteExactOrCommitted(c.maps.handoffs, key, carrier)
	if deleteErr != nil {
		return true, fmt.Errorf("deleting terminal Java handoff: %w", deleteErr)
	}
	return !deleted, nil
}

func (c *Cleanup) recoverLiveHandoffMutation(
	key handoffKey,
	mutation *handoffClaimValue,
) (bool, error) {
	if validJavaRemoteParentTerminalHandoffCleanupClaim(*mutation) {
		return c.finishTerminalHandoffCleanup(key, mutation)
	}
	if !validJavaRemoteParentResolvedHandoffCleanupClaim(*mutation) {
		// Ordinary M may have come from an interrupted retired-H sweep that
		// revalidated live. Only resolved-C provenance authorizes interpreting
		// missing C as a terminal handoff observation.
		return false, nil
	}
	absent, err := c.terminalHandoffClaimAbsent(key)
	if err != nil {
		return true, fmt.Errorf("checking recovered Java handoff claim: %w", err)
	}
	if !absent {
		retain, releaseErr := c.releaseResolvedHandoffGenerationClaim(key, *mutation)
		if releaseErr != nil {
			return true, fmt.Errorf(
				"releasing recovered resolved-handoff generation claim: %w", releaseErr,
			)
		}
		return retain, nil
	}
	return c.prepareTerminalHandoffCleanup(key, mutation)
}

func (c *Cleanup) sweepRetiredHandoffMutations(
	retired map[retiredProcessKey]struct{},
) error {
	mutations, err := cleanupMapEntries[handoffKey, handoffClaimValue](
		c.maps.handoffMutations,
	)
	if err != nil {
		return fmt.Errorf("iterating retired Java handoff cleanup mutations: %w", err)
	}
	var result error
	for _, entry := range mutations {
		if entry.key.PID == 0 || entry.key.Token == 0 ||
			entry.key.ProcessIncarnation == 0 ||
			!validJavaRemoteParentTaskCleanupClaim(entry.value) ||
			entry.value.ProcessIncarnation != entry.key.ProcessIncarnation {
			continue
		}
		exact, exactErr := cleanupExactMatches(
			c.maps.handoffMutations, entry.key, entry.value,
		)
		if exactErr != nil {
			result = errors.Join(result, fmt.Errorf(
				"revalidating recovered Java handoff mutation: %w", exactErr,
			))
			continue
		}
		if !exact {
			continue
		}
		process := Identity{
			TID: entry.key.PID, PID: entry.key.PID, Namespace: entry.key.Namespace,
		}
		acquired, claimErr := c.acquireProcessCleanupClaim(
			process, entry.key.ProcessIncarnation,
		)
		if claimErr != nil {
			result = errors.Join(result, fmt.Errorf(
				"acquiring P for recovered Java handoff mutation: %w", claimErr,
			))
			continue
		}
		if !acquired {
			continue
		}
		mutation := entry.value
		if validJavaRemoteParentTerminalHandoffCleanupClaim(mutation) {
			retain, recoveryErr := c.finishTerminalHandoffCleanup(entry.key, &mutation)
			if recoveryErr != nil {
				result = errors.Join(result, recoveryErr)
			}
			if retain {
				continue
			}
			if releaseErr := c.releaseHandoffCleanupMutation(
				entry.key, mutation,
			); releaseErr != nil {
				result = errors.Join(result, releaseErr)
			}
			continue
		}
		processRetired, retirementErr := c.processExactlyRetired(
			retired, process, entry.key.ProcessIncarnation,
		)
		if retirementErr != nil {
			result = errors.Join(result, fmt.Errorf(
				"checking recovered Java handoff process retirement: %w", retirementErr,
			))
			continue
		}
		if processRetired {
			if validJavaRemoteParentResolvedHandoffCleanupClaim(mutation) {
				retain, releaseErr := c.releaseResolvedHandoffGenerationClaim(
					entry.key, mutation,
				)
				if releaseErr != nil {
					result = errors.Join(result, fmt.Errorf(
						"releasing retired resolved-handoff generation claim: %w", releaseErr,
					))
					continue
				}
				if retain {
					continue
				}
			}
			var handoff taskLink
			if lookupErr := c.maps.handoffs.Lookup(&entry.key, &handoff); lookupErr == nil {
				stillRetired, revalidateErr := c.processExactlyRetired(
					retired, process, entry.key.ProcessIncarnation,
				)
				if revalidateErr != nil {
					result = errors.Join(result, revalidateErr)
					continue
				}
				if stillRetired {
					if _, deleteErr := cleanupDeleteExact(
						c.maps.handoffs, entry.key, handoff,
					); deleteErr != nil {
						result = errors.Join(result, fmt.Errorf(
							"deleting handoff under recovered Java mutation: %w", deleteErr,
						))
						continue
					}
				}
			} else if !errors.Is(lookupErr, ebpf.ErrKeyNotExist) {
				result = errors.Join(result, fmt.Errorf(
					"looking up handoff under recovered Java mutation: %w", lookupErr,
				))
				continue
			}
		} else {
			exact, claimErr := c.processCleanupClaimExact(process)
			if claimErr != nil {
				result = errors.Join(result, fmt.Errorf(
					"revalidating live Java handoff cleanup claim: %w", claimErr,
				))
				continue
			}
			if !exact {
				// Preserve the recovered M beneath a foreign P owner.
				continue
			}
			retain, recoveryErr := c.recoverLiveHandoffMutation(entry.key, &mutation)
			if recoveryErr != nil {
				result = errors.Join(result, recoveryErr)
			}
			if retain {
				continue
			}
		}
		if releaseErr := c.releaseHandoffCleanupMutation(entry.key, mutation); releaseErr != nil {
			result = errors.Join(result, releaseErr)
		}
	}
	return result
}

func (c *Cleanup) sweepRetiredHandoffs(
	retired map[retiredProcessKey]struct{},
) error {
	handoffs, err := cleanupMapEntries[handoffKey, taskLink](c.maps.handoffs)
	if err != nil {
		return fmt.Errorf("iterating retired Java handoffs: %w", err)
	}
	var result error
	for _, entry := range handoffs {
		// Cooperative publishers never create a zero-PID, zero-token, or
		// capability-less key. Leave malformed keys to fail closed: they have no
		// exact process capability under which userspace can prove writer death.
		if entry.key.PID == 0 || entry.key.Token == 0 ||
			entry.key.ProcessIncarnation == 0 {
			continue
		}
		process := Identity{
			TID:       entry.key.PID,
			PID:       entry.key.PID,
			Namespace: entry.key.Namespace,
		}
		isRetired, retirementErr := c.processExactlyRetired(
			retired, process, entry.key.ProcessIncarnation,
		)
		if retirementErr != nil {
			result = errors.Join(result, fmt.Errorf(
				"checking Java handoff process retirement: %w", retirementErr,
			))
			continue
		}
		if !isRetired {
			continue
		}
		// P -> M(H). P proves that no positive publisher for this retired
		// incarnation can begin, while M makes the reusable handoff key stable
		// through the exact delete. Cleanup never inserts C(OPEN), so full C and
		// M maps cannot form a cross-capacity dependency cycle.
		mutation, acquired, mutationErr := c.acquireHandoffCleanupMutation(entry.key)
		if mutationErr != nil {
			result = errors.Join(result, mutationErr)
			continue
		}
		if !acquired {
			continue
		}
		isRetired, retirementErr = c.processExactlyRetired(
			retired, process, entry.key.ProcessIncarnation,
		)
		if retirementErr != nil {
			result = errors.Join(result, fmt.Errorf(
				"revalidating Java handoff process retirement: %w", retirementErr,
			))
			continue
		}
		if !isRetired {
			if releaseErr := c.releaseHandoffCleanupMutation(entry.key, mutation); releaseErr != nil {
				result = errors.Join(result, releaseErr)
			}
			continue
		}
		if _, deleteErr := cleanupDeleteExact(c.maps.handoffs, entry.key, entry.value); deleteErr != nil {
			result = errors.Join(result, fmt.Errorf(
				"deleting retired Java handoff: %w", deleteErr,
			))
			// Deletion uncertainty keeps M and P closed for exact recovery.
			continue
		}
		if releaseErr := c.releaseHandoffCleanupMutation(entry.key, mutation); releaseErr != nil {
			result = errors.Join(result, releaseErr)
		}
	}
	return result
}

// sweepResolvedHandoffClaims bounds the non-evicting C(OPEN) admission map to
// handoffs that still exist. P -> M(H) blocks new alias retains before making
// the reusable H key stable. C publishers use BPF_NOEXIST and revalidate their
// exact ticket beneath M before exposure, so an exact no-H C beneath both
// fences can be deleted without resurrecting H. If H exists, C is revalidated
// before M opens: terminal C disappearance switches M to durable drain intent.
func (c *Cleanup) sweepResolvedHandoffClaims() error {
	claims, err := cleanupMapEntries[handoffKey, handoffClaimValue](
		c.maps.handoffClaims,
	)
	if err != nil {
		return fmt.Errorf("iterating resolved Java handoff claims: %w", err)
	}

	var result error
	for _, entry := range claims {
		if entry.key.PID == 0 || entry.key.Token == 0 ||
			entry.key.ProcessIncarnation == 0 || entry.value.ObservedMonotonicNS == 0 ||
			entry.value.ProcessIncarnation != entry.key.ProcessIncarnation {
			continue
		}
		process := Identity{
			TID: entry.key.PID, PID: entry.key.PID, Namespace: entry.key.Namespace,
		}
		processAcquired, processErr := c.acquireProcessCleanupClaim(
			process, entry.key.ProcessIncarnation,
		)
		if processErr != nil {
			result = errors.Join(result, fmt.Errorf(
				"acquiring P for resolved Java handoff claim: %w", processErr,
			))
			continue
		}
		if !processAcquired {
			continue
		}

		mutation, acquired, mutationErr := c.acquireHandoffCleanupMutation(entry.key)
		if mutationErr != nil {
			result = errors.Join(result, mutationErr)
			// A committed-but-uncertain acquisition keeps M closed. The tagged
			// mutation is recoverable by sweepRetiredHandoffMutations.
			continue
		}
		if !acquired {
			continue
		}
		marked, markErr := c.markResolvedHandoffCleanupMutation(entry.key, &mutation)
		if markErr != nil {
			result = errors.Join(result, markErr)
			continue
		}
		if !marked {
			continue
		}

		retainMutation, reclaimErr := c.reclaimHandoffClaimUnderMutation(
			entry.key, entry.value, &mutation,
		)
		if reclaimErr != nil {
			result = errors.Join(result, reclaimErr)
		}
		if retainMutation {
			// A map error makes H/C state uncertain. Preserve M so no
			// cooperative publisher can cross that uncertainty; its tagged value
			// makes the fence recoverable on a later sweep.
			continue
		}
		if releaseErr := c.releaseHandoffCleanupMutation(entry.key, mutation); releaseErr != nil {
			result = errors.Join(result, releaseErr)
		}
	}
	return result
}

// reclaimHandoffClaimUnderMutation returns whether M must remain installed.
// The two exact C/H pairs are deliberately explicit: only their second pair
// authorizes deletion, and cleanupDeleteExact adds the final exact-value reads
// required before the kernel's key-only HASH delete.
func (c *Cleanup) reclaimHandoffClaimUnderMutation(
	key handoffKey,
	expected handoffClaimValue,
	mutation *handoffClaimValue,
) (bool, error) {
	for range 2 {
		exact, claimErr := cleanupExactMatches(c.maps.handoffClaims, key, expected)
		if claimErr != nil {
			return true, fmt.Errorf("revalidating resolved Java handoff claim: %w", claimErr)
		}
		if !exact {
			return false, nil
		}

		var handoff taskLink
		handoffErr := c.maps.handoffs.Lookup(&key, &handoff)
		if handoffErr == nil {
			absent, claimErr := c.terminalHandoffClaimAbsent(key)
			if claimErr != nil {
				return true, fmt.Errorf(
					"revalidating Java handoff claim after H observation: %w", claimErr,
				)
			}
			if !absent {
				return false, nil
			}
			return c.prepareTerminalHandoffCleanup(key, mutation)
		}
		if !errors.Is(handoffErr, ebpf.ErrKeyNotExist) {
			return true, fmt.Errorf(
				"revalidating resolved Java handoff absence: %w", handoffErr,
			)
		}
	}

	if _, deleteErr := cleanupDeleteExact(c.maps.handoffClaims, key, expected); deleteErr != nil {
		return true, fmt.Errorf("deleting resolved Java handoff claim: %w", deleteErr)
	}
	return false, nil
}

func (c *Cleanup) complete() bool {
	return c.coordinator != nil && c.maps.remoteParents != nil && c.maps.tasks != nil &&
		c.maps.virtualThreads != nil && c.maps.vtIdentities != nil &&
		c.maps.authorized != nil && c.maps.incarnations != nil && c.maps.connections != nil &&
		c.maps.cookieConnections != nil &&
		c.maps.ambiguity != nil && c.maps.owners != nil && c.maps.states != nil &&
		c.maps.generations != nil && c.maps.terminals != nil && c.maps.claims != nil &&
		c.maps.aliasReplays != nil && c.maps.ownerGuards != nil &&
		c.maps.handoffs != nil && c.maps.handoffClaims != nil &&
		c.maps.handoffMutations != nil && c.maps.taskClaims != nil &&
		c.maps.threadMappingClaims != nil &&
		c.maps.retired != nil &&
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
	if !c.recordAliasReplayCleanupKey(
		key, index.ObservedMonotonicNS, index.ProcessIncarnation,
	) {
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
			replayReady, replayErr := c.ensureStateAliasReplayFinal(ownership, key, state)
			if replayErr != nil {
				return false, fmt.Errorf("finalizing generation alias replay: %w", replayErr)
			}
			if !replayReady {
				return false, nil
			}
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
	} else {
		replayReady, replayErr := c.ensureGenerationAliasReplaysFinal(ownership, key)
		if replayErr != nil {
			return false, fmt.Errorf("finalizing detached generation alias replay: %w", replayErr)
		}
		if !replayReady {
			return false, nil
		}
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

func (c *Cleanup) upgradeExactMarkerTailClaimForArtifact(
	key stateKey,
	exact generationClaim,
	processIncarnation uint64,
	lifecycle uint8,
	requireValidTerminalAbsent bool,
	requiredGuard *generationClaim,
	revalidateRoot generationCleanupRootRevalidator,
) (generationCleanupOwnership, bool, error) {
	if !validExactMarkerTailCleanupClaim(key, exact) || revalidateRoot == nil {
		return generationCleanupOwnership{}, false, nil
	}
	validateRootAndClaim := func(expected generationClaim) (bool, error) {
		rootMatches, err := revalidateRoot()
		if err != nil || !rootMatches {
			return false, err
		}
		return generationClaimMatches(c.maps.claims, key, expected)
	}
	valid, err := validateRootAndClaim(exact)
	if err != nil || !valid {
		return generationCleanupOwnership{}, false, err
	}
	var guard generationClaim
	if requiredGuard != nil {
		guard = *requiredGuard
		if !validGenerationCleanupGuard(key.Owner, guard) ||
			guard.ProcessIncarnation != key.Generation {
			return generationCleanupOwnership{}, false, nil
		}
		guardMatches, err := generationGuardMatches(c.maps.ownerGuards, key.Owner, guard)
		if err != nil || !guardMatches {
			return generationCleanupOwnership{}, false, err
		}
	} else {
		var guarded bool
		var err error
		guard, _, guarded, err = c.acquireOrAdoptGenerationCleanupGuard(key)
		if err != nil || !guarded {
			return generationCleanupOwnership{}, false, err
		}
	}
	valid, err = validateRootAndClaim(exact)
	if err != nil || !valid {
		return generationCleanupOwnership{}, false, err
	}
	guardMatches, err := generationGuardMatches(c.maps.ownerGuards, key.Owner, guard)
	if err != nil || !guardMatches {
		return generationCleanupOwnership{}, false, err
	}

	// G blocks new owner-scoped producers before the exact-only E is atomically
	// replaced. E therefore remains continuously present, while the fresh
	// ordinary claim starts a new grace interval before M can complete the full
	// mutable-artifact fence.
	replacement, ok := c.newGenerationClaim(lifecycle, processIncarnation)
	if !ok {
		return generationCleanupOwnership{}, false,
			errors.New("reading monotonic time for exact-tail artifact upgrade")
	}
	// Record the intended bytes before UpdateExist. If the kernel commits but
	// both the syscall and immediate readback fail, no later root in this sweep
	// may mistake the fresh replacement for an aged inherited claim.
	c.recordCurrentSweepClaim(key, replacement)
	updateErr := c.maps.claims.Update(&key, &replacement, ebpf.UpdateExist)
	var current generationClaim
	lookupErr := c.maps.claims.Lookup(&key, &current)
	if lookupErr != nil {
		if updateErr != nil {
			return generationCleanupOwnership{}, false, errors.Join(
				fmt.Errorf("upgrading exact-tail artifact claim: %w", updateErr),
				fmt.Errorf("checking uncertain exact-tail artifact upgrade: %w", lookupErr),
			)
		}
		return generationCleanupOwnership{}, false,
			fmt.Errorf("checking exact-tail artifact upgrade: %w", lookupErr)
	}
	if current != replacement {
		if updateErr != nil {
			return generationCleanupOwnership{}, false,
				fmt.Errorf("upgrading exact-tail artifact claim: %w", updateErr)
		}
		return generationCleanupOwnership{}, false,
			errors.New("exact-tail artifact claim changed during upgrade")
	}
	ownership := generationCleanupOwnership{
		claim:                      replacement,
		requireValidTerminalAbsent: requireValidTerminalAbsent,
	}
	if updateErr != nil {
		return ownership, false,
			fmt.Errorf("upgrading exact-tail artifact claim: %w", updateErr)
	}
	valid, err = validateRootAndClaim(replacement)
	if err != nil || !valid {
		return ownership, false, err
	}
	guardMatches, err = generationGuardMatches(c.maps.ownerGuards, key.Owner, guard)
	if err != nil || !guardMatches {
		return ownership, false, err
	}
	return ownership, false, nil
}

func (c *Cleanup) claimGenerationCleanupForArtifact(
	key stateKey,
	processIncarnation uint64,
	lifecycle uint8,
	revalidateRoot ...generationCleanupRootRevalidator,
) (generationCleanupOwnership, bool, error) {
	if len(revalidateRoot) != 1 || revalidateRoot[0] == nil {
		return generationCleanupOwnership{}, false, nil
	}
	var terminal terminalValue
	if err := c.maps.terminals.Lookup(&key.Owner, &terminal); err == nil {
		if terminal.Generation == key.Generation && validTerminalValue(terminal) {
			if processIncarnation != terminal.ProcessIncarnation ||
				!c.recordAliasReplayCleanupKey(
					key, terminal.ObservedMonotonicNS, terminal.ProcessIncarnation,
				) {
				return generationCleanupOwnership{}, false, nil
			}
			if current, present := c.retainedTerminalAuthorities[key]; present && current != terminal {
				return generationCleanupOwnership{}, false, nil
			}
			if c.retainedTerminalAuthorities == nil {
				c.retainedTerminalAuthorities = make(map[stateKey]terminalValue)
			}
			c.retainedTerminalAuthorities[key] = terminal
			// T pins the exact replay status for any residual mutable-payload
			// cleanup. It remains in the LRU map while the ordinary full fence uses
			// T's lifecycle and provenance instead of deleting or retargeting it.
			lifecycle = terminal.Lifecycle
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return generationCleanupOwnership{}, false,
			fmt.Errorf("checking generation artifact terminal status: %w", err)
	}
	artifactRoot := revalidateRoot[0]
	requireValidTerminalAbsent := true
	if authority, present := c.retainedTerminalAuthorities[key]; present {
		requireValidTerminalAbsent = false
		revalidateRoot = []generationCleanupRootRevalidator{func() (bool, error) {
			terminalMatches, err := cleanupExactMatches(c.maps.terminals, key.Owner, authority)
			if err != nil || !terminalMatches {
				return false, err
			}
			artifactMatches, err := artifactRoot()
			if err != nil || !artifactMatches {
				return false, err
			}
			return cleanupExactMatches(c.maps.terminals, key.Owner, authority)
		}}
	} else {
		revalidateRoot = []generationCleanupRootRevalidator{func() (bool, error) {
			terminalAbsent, err := c.validGenerationTerminalAbsent(key)
			if err != nil || !terminalAbsent {
				return false, err
			}
			artifactMatches, err := artifactRoot()
			if err != nil || !artifactMatches {
				return false, err
			}
			return c.validGenerationTerminalAbsent(key)
		}}
	}
	var existing generationClaim
	if err := c.maps.claims.Lookup(&key, &existing); err == nil {
		if validExactMarkerTailCleanupClaim(key, existing) {
			upgradeProcessIncarnation := processIncarnation
			if upgradeProcessIncarnation == 0 {
				upgradeProcessIncarnation = key.Generation
			}
			return c.upgradeExactMarkerTailClaimForArtifact(
				key, existing, upgradeProcessIncarnation, lifecycle,
				requireValidTerminalAbsent, nil, revalidateRoot[0],
			)
		}
		if !validGenerationCleanupClaim(existing) {
			return generationCleanupOwnership{}, false, nil
		}
		if authority, present := c.retainedTerminalAuthorities[key]; present &&
			(existing.ProcessIncarnation != authority.ProcessIncarnation ||
				existing.Reserved[0] != authority.Lifecycle) {
			return generationCleanupOwnership{}, false, nil
		}
		ownership, ready, err := c.claimGenerationCleanup(key, existing, revalidateRoot...)
		ownership.requireValidTerminalAbsent = requireValidTerminalAbsent
		return ownership, ready, err
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
	ownership, ready, err := c.claimGenerationCleanup(key, claim, revalidateRoot...)
	ownership.requireValidTerminalAbsent = requireValidTerminalAbsent
	return ownership, ready, err
}

// claimGenerationCleanupWithGuard adopts an already-published exact owner
// guard without ever creating one. Valid terminal status may recover a matching
// teardown fence, but it is not payload authority and must not fence a newer
// generation merely because status outlived its producer.
func (c *Cleanup) claimGenerationCleanupWithGuard(
	key stateKey,
	processIncarnation uint64,
	lifecycle uint8,
	guard generationClaim,
	markedAt uint64,
	revalidateRoot generationCleanupRootRevalidator,
) (generationCleanupOwnership, bool, error) {
	if key.Generation == 0 || key.Reserved != 0 || processIncarnation == 0 ||
		revalidateRoot == nil || !validGenerationCleanupGuard(key.Owner, guard) ||
		guard.ProcessIncarnation != key.Generation || markedAt == 0 {
		return generationCleanupOwnership{}, false, nil
	}
	rootMatches, err := revalidateRoot()
	if err != nil || !rootMatches {
		return generationCleanupOwnership{}, false, err
	}
	markerMatches, err := c.cleanupMarkerMatches(key, &markedAt)
	if err != nil || !markerMatches {
		return generationCleanupOwnership{}, false, err
	}
	guardMatches, err := generationGuardMatches(c.maps.ownerGuards, key.Owner, guard)
	if err != nil || !guardMatches {
		return generationCleanupOwnership{}, false, err
	}

	claim, ok := c.newGenerationClaim(lifecycle, processIncarnation)
	if !ok {
		return generationCleanupOwnership{}, false,
			errors.New("reading monotonic time for guarded generation artifact claim")
	}
	ownership := generationCleanupOwnership{claim: claim}
	if err := c.maps.claims.Update(&key, &claim, ebpf.UpdateNoExist); err == nil {
		c.recordCurrentSweepClaim(key, claim)
	} else if !errors.Is(err, ebpf.ErrKeyExist) {
		return generationCleanupOwnership{}, false,
			fmt.Errorf("claiming guarded generation cleanup: %w", err)
	} else {
		var existing generationClaim
		if err := c.maps.claims.Lookup(&key, &existing); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return generationCleanupOwnership{}, false, nil
			}
			return generationCleanupOwnership{}, false,
				fmt.Errorf("looking up guarded generation cleanup claim: %w", err)
		}
		if !validGenerationCleanupClaim(existing) {
			return generationCleanupOwnership{}, false, nil
		}
		if existing.ProcessIncarnation != processIncarnation ||
			existing.Reserved[0] != lifecycle {
			return generationCleanupOwnership{}, false, nil
		}
		ownership.claim = existing
		ownership.inheritedFence = true
	}

	rootMatches, err = revalidateRoot()
	if err != nil || !rootMatches {
		return ownership, false, err
	}
	ownership.ambiguity = markedAt
	ownership.hasAmbiguity = true
	ownership.fence = generationTeardownFence{
		key: key, claim: ownership.claim, guardKey: key.Owner, guardClaim: guard,
		markedAt: markedAt,
	}
	valid, err := generationTeardownFenceMatches(
		c.maps.claims, c.maps.ownerGuards, c.maps.ambiguity, ownership.fence,
	)
	if err != nil || !valid {
		return ownership, false, err
	}
	now := c.monoTimeNow()
	_, markerTouchedThisSweep := c.currentSweepAmbiguities[key]
	ready := !c.claimCreatedThisSweep(key, ownership.claim) &&
		!c.guardCreatedThisSweep(key.Owner, guard) &&
		!markerTouchedThisSweep &&
		c.generationCleanupFenceExpired(now, ownership.claim.ObservedMonotonicNS) &&
		c.generationCleanupFenceExpired(now, guard.ObservedMonotonicNS) &&
		c.generationCleanupFenceExpired(now, markedAt)
	ownership.ready = ready
	return ownership, ready, nil
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
	fenced, err := generationTeardownFenceMatches(
		c.maps.claims, c.maps.ownerGuards, c.maps.ambiguity, ownership.fence,
	)
	if err != nil || !fenced {
		return false, err
	}
	terminalAuthorityMatches := func() (bool, error) {
		if terminal, present := c.retainedTerminalAuthorities[ownership.fence.key]; present {
			if ownership.requireValidTerminalAbsent ||
				ownership.claim.ProcessIncarnation != terminal.ProcessIncarnation ||
				ownership.claim.Reserved[0] != terminal.Lifecycle {
				return false, nil
			}
			return cleanupExactMatches(
				c.maps.terminals, ownership.fence.key.Owner, terminal,
			)
		}
		if ownership.requireValidTerminalAbsent {
			return c.validGenerationTerminalAbsent(ownership.fence.key)
		}
		return true, nil
	}
	terminalMatches, terminalErr := terminalAuthorityMatches()
	if terminalErr != nil || !terminalMatches {
		return false, terminalErr
	}
	replayMatches, replayErr := c.aliasReplayCleanupProofMatches(ownership)
	if replayErr != nil || !replayMatches {
		return false, replayErr
	}
	return terminalAuthorityMatches()
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

func (c *Cleanup) recordFenceRetirementAttempt(key stateKey) {
	if c.fenceRetirementAttempts != nil {
		c.fenceRetirementAttempts[key] = struct{}{}
	}
}

func (c *Cleanup) fenceRetirementAttempted(key stateKey) bool {
	_, attempted := c.fenceRetirementAttempts[key]
	return attempted
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

func (c *Cleanup) newExactMarkerTailClaim(key stateKey) (generationClaim, bool) {
	claim, ok := c.newGenerationClaim(lifecycleAmbiguous, key.Generation)
	if !ok {
		return generationClaim{}, false
	}
	claim.Reserved[6] = generationGoProducerTag
	return claim, true
}

func validExactMarkerTailCleanupClaim(key stateKey, claim generationClaim) bool {
	return key.Generation != 0 && key.Reserved == 0 &&
		claim.ObservedMonotonicNS != 0 && claim.ProcessIncarnation == key.Generation &&
		claim.Lifecycle == lifecycleCleanup &&
		claim.Reserved == ([7]byte{
			0: lifecycleAmbiguous,
			6: generationGoProducerTag,
		})
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

	authority, retained := c.retainedTerminalAuthorities[key]
	var terminal terminalValue
	if err := c.maps.terminals.Lookup(&key.Owner, &terminal); err == nil {
		if retained {
			if terminal != authority || !validTerminalValue(terminal) {
				return false, nil
			}
		} else if terminal.Generation == key.Generation {
			return false, nil
		}
	} else if errors.Is(err, ebpf.ErrKeyNotExist) {
		if retained {
			return false, nil
		}
	} else {
		return false, fmt.Errorf("checking generation terminal cleanup: %w", err)
	}

	return true, nil
}

func (c *Cleanup) generationTerminalAbsent(key stateKey) (bool, error) {
	var terminal terminalValue
	if err := c.maps.terminals.Lookup(&key.Owner, &terminal); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return true, nil
		}
		return false, fmt.Errorf("checking generation terminal absence: %w", err)
	}
	return terminal.Generation != key.Generation, nil
}

func (c *Cleanup) validGenerationTerminalAbsent(key stateKey) (bool, error) {
	var terminal terminalValue
	if err := c.maps.terminals.Lookup(&key.Owner, &terminal); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return true, nil
		}
		return false, fmt.Errorf("checking valid generation terminal absence: %w", err)
	}
	return terminal.Generation != key.Generation || !validTerminalValue(terminal), nil
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

func (c *Cleanup) snapshotProvesExactTailPayloadComplete(
	key stateKey,
) (bool, error) {
	if !c.generationSnapshotComplete || !c.stateSnapshotComplete ||
		c.physicalGenerations == nil {
		return false, nil
	}
	var generation generationIndexValue
	if err := c.maps.generations.Lookup(&key, &generation); err == nil {
		return false, nil
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking exact-tail generation index: %w", err)
	}
	var state stateValue
	if err := c.maps.states.Lookup(&key, &state); err == nil {
		return false, nil
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking exact-tail generation state: %w", err)
	}
	var owner ownerValue
	if err := c.maps.owners.Lookup(&key.Owner, &owner); err == nil {
		if owner.Generation == key.Generation {
			return false, nil
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking exact-tail generation owner: %w", err)
	}
	var encoded [RecordSize]byte
	if err := c.maps.remoteParents.Lookup(&key.Owner, &encoded); err == nil {
		record, decodeErr := UnmarshalRecord(encoded[:])
		if decodeErr != nil || record.Generation == key.Generation {
			return false, nil
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking exact-tail fallback: %w", err)
	}
	var terminal terminalValue
	if err := c.maps.terminals.Lookup(&key.Owner, &terminal); err == nil {
		if terminal.Generation == key.Generation && !validTerminalValue(terminal) {
			return false, nil
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking exact-tail terminal: %w", err)
	}
	if _, present := c.physicalGenerations[key]; present {
		return false, nil
	}
	// Acquisition never deletes payload, and every destructive phase first ages
	// E through a later sweep. The complete per-sweep physical snapshot therefore
	// observes publications from pre-E BPF critical sections without multiplying
	// full-map scans by the number of exact tails.
	return true, nil
}

func (c *Cleanup) terminalGenerationCleanupComplete(
	key stateKey,
	terminal terminalValue,
	ownership generationCleanupOwnership,
) (bool, error) {
	if !validTerminalValue(terminal) || terminal.Generation != key.Generation ||
		ownership.claim.ProcessIncarnation != terminal.ProcessIncarnation ||
		ownership.claim.Reserved[0] != terminal.Lifecycle {
		return false, nil
	}
	return c.exactTerminalGenerationCleanupComplete(key, terminal)
}

func (c *Cleanup) retainedTerminalGenerationCleanupComplete(
	key stateKey,
	terminal terminalValue,
	ownership generationCleanupOwnership,
	requireSnapshot bool,
) (bool, error) {
	if !validTerminalValue(terminal) || terminal.Generation != key.Generation ||
		ownership.claim.ProcessIncarnation != terminal.ProcessIncarnation ||
		ownership.claim.Reserved[0] != terminal.Lifecycle {
		return false, nil
	}
	terminalMatches, err := cleanupExactMatches(c.maps.terminals, key.Owner, terminal)
	if err != nil || !terminalMatches {
		return false, err
	}
	var complete bool
	if requireSnapshot {
		complete, err = c.snapshotProvesGenerationCleanupComplete(key)
	} else {
		complete, err = c.finishGenerationCleanup(key)
	}
	if err != nil || !complete {
		return false, err
	}
	replaySafe, err := c.terminalAliasReplayFenceRetirementSafe(key, terminal)
	if err != nil || !replaySafe {
		return false, err
	}
	return cleanupExactMatches(c.maps.terminals, key.Owner, terminal)
}

func (c *Cleanup) exactTerminalGenerationCleanupComplete(
	key stateKey,
	terminal terminalValue,
) (bool, error) {
	payloadComplete, err := c.exactTerminalGenerationPayloadComplete(key, terminal)
	if err != nil || !payloadComplete {
		return false, err
	}
	replaySafe, err := c.terminalAliasReplayFenceRetirementSafe(key, terminal)
	if err != nil || !replaySafe {
		return false, err
	}
	return cleanupExactMatches(c.maps.terminals, key.Owner, terminal)
}

func (c *Cleanup) exactTerminalGenerationPayloadComplete(
	key stateKey,
	terminal terminalValue,
) (bool, error) {
	if !validTerminalValue(terminal) || terminal.Generation != key.Generation {
		return false, nil
	}
	terminalMatches, err := cleanupExactMatches(c.maps.terminals, key.Owner, terminal)
	if err != nil || !terminalMatches {
		return false, err
	}
	complete, err := c.snapshotProvesExactTailPayloadComplete(key)
	if err != nil || !complete {
		return false, err
	}
	return cleanupExactMatches(c.maps.terminals, key.Owner, terminal)
}

func (c *Cleanup) terminalTailCleanupAuthority(
	key stateKey,
	claim *generationClaim,
	now time.Duration,
) (bool, error) {
	var terminal terminalValue
	if err := c.maps.terminals.Lookup(&key.Owner, &terminal); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("checking terminal fence tail: %w", err)
	}
	if terminal.Generation != key.Generation {
		return false, nil
	}
	if !validTerminalValue(terminal) ||
		!c.generationCleanupFenceExpired(now, terminal.ObservedMonotonicNS) {
		return true, nil
	}
	if claim != nil &&
		(claim.ProcessIncarnation != terminal.ProcessIncarnation ||
			claim.Reserved[0] != terminal.Lifecycle) {
		return true, nil
	}
	_, err := c.exactTerminalGenerationCleanupComplete(key, terminal)
	return true, err
}

func (c *Cleanup) finishGenerationCleanupFenced(
	key stateKey,
	ownership generationCleanupOwnership,
) (bool, error) {
	replayReady, replayErr := c.ensureGenerationAliasReplaysFinal(ownership, key)
	if replayErr != nil {
		return false, fmt.Errorf("checking alias replay before fence retirement: %w", replayErr)
	}
	if !replayReady {
		return false, nil
	}
	if terminal, present := c.retainedTerminalAuthorities[key]; present {
		return c.finishGenerationCleanupFencedValidated(
			key, ownership, func(requireSnapshot bool) (bool, error) {
				return c.retainedTerminalGenerationCleanupComplete(
					key, terminal, ownership, requireSnapshot,
				)
			},
		)
	}
	return c.finishGenerationCleanupFencedValidated(
		key, ownership, func(requireSnapshot bool) (bool, error) {
			if requireSnapshot {
				return c.snapshotProvesGenerationCleanupComplete(key)
			}
			return c.finishGenerationCleanup(key)
		},
	)
}

func (c *Cleanup) finishGenerationCleanupFencedValidated(
	key stateKey,
	ownership generationCleanupOwnership,
	complete generationCleanupCompletionValidator,
) (bool, error) {
	if complete == nil {
		return false, errors.New("missing generation cleanup completion validator")
	}
	completed, err := complete(false)
	if err != nil || !completed {
		return completed, err
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
		c.recordFenceRetirementAttempt(key)
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
	if completed, completeErr := complete(false); completeErr != nil || !completed {
		return false, errors.Join(
			completeErr, errors.New("generation reappeared before claim release"),
		)
	}

	claimMatches, err := generationClaimMatches(c.maps.claims, key, ownership.claim)
	if err != nil {
		return false, fmt.Errorf("checking generation claim before release: %w", err)
	}
	if claimMatches {
		c.recordFenceRetirementAttempt(key)
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
	completed, err = complete(true)
	if err != nil || !completed {
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
	terminalPresent, terminalErr := c.terminalTailCleanupAuthority(key, &claim, now)
	if terminalErr != nil || terminalPresent {
		return false, terminalErr
	}
	// Proving that a marker-free E/G tail contains exactly one unchanged replay
	// requires complete HASH enumeration: replay epochs are part of the key and
	// cannot be excluded with a point lookup. The unified claim/guard scheduler
	// admits only one generation-wide replay proof while the coordinator's
	// exclusive lock is held. A non-admitted tail remains fail closed.
	if !c.generationReplayScanAuthorized(key) {
		return false, nil
	}
	if handled, recoveryErr := c.recoverMarkerFreeActiveReplayTail(
		key, claim, guard, now,
	); recoveryErr != nil || handled {
		return false, recoveryErr
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
		replaySafe, err := c.aliasReplayFenceRetirementSafe(key, &claim)
		if err != nil || !replaySafe {
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
	c.recordFenceRetirementAttempt(key)
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

func generationCleanupTailKeyCompare(left, right stateKey) int {
	if left.Owner.TID != right.Owner.TID {
		return cmp.Compare(left.Owner.TID, right.Owner.TID)
	}
	if left.Owner.PID != right.Owner.PID {
		return cmp.Compare(left.Owner.PID, right.Owner.PID)
	}
	if left.Owner.Namespace != right.Owner.Namespace {
		return cmp.Compare(left.Owner.Namespace, right.Owner.Namespace)
	}
	if left.Reserved != right.Reserved {
		return cmp.Compare(left.Reserved, right.Reserved)
	}
	if left.Generation != right.Generation {
		return cmp.Compare(left.Generation, right.Generation)
	}
	return 0
}

func (c *Cleanup) orderedGenerationCleanupTailClaims(
	claims []cleanupEntry[stateKey, generationClaim],
) []cleanupEntry[stateKey, generationClaim] {
	if len(claims) == 0 {
		return nil
	}
	ordered := append([]cleanupEntry[stateKey, generationClaim](nil), claims...)
	sort.Slice(ordered, func(i, j int) bool {
		return generationCleanupTailKeyCompare(ordered[i].key, ordered[j].key) < 0
	})
	start := 0
	if c.generationReplayScanCursorSet {
		start = sort.Search(len(ordered), func(i int) bool {
			return generationCleanupTailKeyCompare(
				ordered[i].key, c.generationReplayScanCursor,
			) > 0
		})
		if start == len(ordered) {
			start = 0
		}
	}
	if start == 0 {
		return ordered
	}
	return append(ordered[start:], ordered[:start]...)
}

func (c *Cleanup) selectGenerationReplayScanKey(
	claims []cleanupEntry[stateKey, generationClaim],
	guards []cleanupEntry[Identity, generationClaim],
	now time.Duration,
	complete bool,
) {
	c.generationReplayScanKey = stateKey{}
	c.generationReplayScanKeySet = false
	if !complete || javaRemoteParentMaxGenerationReplayScanAttemptsPerSweep == 0 {
		return
	}

	// Select from a single ordered union. If claims consumed a shared token in
	// their earlier pass, a persistent claim backlog could starve the later
	// guard-only pass. Advancing the cursor at selection also prevents a stale
	// snapshot or repeated iterator error from pinning the scheduler.
	allClaimKeys := make(map[stateKey]struct{}, len(claims))
	candidates := make(map[stateKey]struct{}, len(claims)+len(guards))
	for _, entry := range claims {
		if entry.key.Generation != 0 && entry.key.Reserved == 0 {
			allClaimKeys[entry.key] = struct{}{}
		}
		if entry.key.Generation == 0 || entry.key.Reserved != 0 ||
			validExactMarkerTailCleanupClaim(entry.key, entry.value) ||
			!validGenerationCleanupClaim(entry.value) ||
			c.claimCreatedThisSweep(entry.key, entry.value) ||
			c.fenceRetirementAttempted(entry.key) ||
			!c.generationCleanupFenceExpired(now, entry.value.ObservedMonotonicNS) {
			continue
		}
		candidates[entry.key] = struct{}{}
	}
	for _, entry := range guards {
		key := stateKey{Owner: entry.key, Generation: entry.value.ProcessIncarnation}
		if _, claimPresent := allClaimKeys[key]; claimPresent {
			continue
		}
		if !validGenerationCleanupGuard(entry.key, entry.value) ||
			c.guardCreatedThisSweep(entry.key, entry.value) ||
			c.fenceRetirementAttempted(key) ||
			!c.generationCleanupFenceExpired(now, entry.value.ObservedMonotonicNS) {
			continue
		}
		candidates[key] = struct{}{}
	}
	if len(candidates) == 0 {
		return
	}

	ordered := make([]stateKey, 0, len(candidates))
	for key := range candidates {
		ordered = append(ordered, key)
	}
	sort.Slice(ordered, func(i, j int) bool {
		return generationCleanupTailKeyCompare(ordered[i], ordered[j]) < 0
	})
	selected := 0
	if c.generationReplayScanCursorSet {
		selected = sort.Search(len(ordered), func(i int) bool {
			return generationCleanupTailKeyCompare(
				ordered[i], c.generationReplayScanCursor,
			) > 0
		})
		if selected == len(ordered) {
			selected = 0
		}
	}
	c.generationReplayScanKey = ordered[selected]
	c.generationReplayScanKeySet = true
	c.generationReplayScanCursor = ordered[selected]
	c.generationReplayScanCursorSet = true
}

func (c *Cleanup) generationReplayScanAuthorized(key stateKey) bool {
	return c.generationReplayScanKeySet && c.generationReplayScanKey == key
}

func (c *Cleanup) recoverMarkerFreeActiveReplayTail(
	key stateKey,
	claim generationClaim,
	guard generationClaim,
	now time.Duration,
) (bool, error) {
	if !c.aliasReplaySnapshotComplete || !validGenerationCleanupClaim(claim) ||
		!validAliasReplayDesiredLifecycle(claim.Reserved[0]) ||
		!validGenerationCleanupGuard(key.Owner, guard) ||
		guard.ProcessIncarnation != key.Generation ||
		c.claimCreatedThisSweep(key, claim) || c.guardCreatedThisSweep(key.Owner, guard) ||
		c.fenceRetirementAttempted(key) ||
		!c.generationCleanupFenceExpired(now, claim.ObservedMonotonicNS) ||
		!c.generationCleanupFenceExpired(now, guard.ObservedMonotonicNS) {
		return false, nil
	}
	if released, ok := c.releasedSweepClaims[key]; ok && released == claim {
		return false, nil
	}
	if released, ok := c.releasedSweepGuards[key.Owner]; ok && released == guard {
		return false, nil
	}
	if _, released := c.releasedSweepAmbiguities[key]; released {
		return false, nil
	}
	if !c.generationReplayScanAuthorized(key) {
		return false, nil
	}

	// Successful full-fence retirement finalizes every matching replay before
	// deleting M. Exactly one unchanged active replay from the complete opening
	// snapshot is therefore positive evidence of an interrupted acquisition,
	// rather than authority to widen an arbitrary marker-free E/G tail.
	var replayKey aliasReplayKey
	var replay aliasReplayValue
	candidates := 0
	for candidateKey, candidate := range c.aliasReplayEntries {
		if candidateKey.Owner != key.Owner || candidateKey.Generation != key.Generation ||
			candidateKey.ProcessIncarnation != claim.ProcessIncarnation {
			continue
		}
		candidates++
		replayKey = candidateKey
		replay = candidate
	}
	if candidates != 1 || !validAliasReplayKey(replayKey) || !validAliasReplayActive(replay) {
		return false, nil
	}

	currentReplayMatches := func() (bool, error) {
		entries, err := c.currentGenerationAliasReplays(key)
		if err != nil {
			return false, err
		}
		matching := 0
		for _, entry := range entries {
			if entry.key.ProcessIncarnation != claim.ProcessIncarnation {
				continue
			}
			matching++
			if entry.key != replayKey || entry.value != replay {
				return false, nil
			}
		}
		if matching != 1 {
			return false, nil
		}
		return cleanupExactMatches(c.maps.aliasReplays, replayKey, replay)
	}
	for range 2 {
		matches, err := currentReplayMatches()
		if err != nil || !matches {
			// The opening active replay selected this recovery path. Any later
			// ambiguity preserves E/G instead of falling through to tail release.
			return true, err
		}
	}

	validate := func(expectedMarker *uint64) (bool, error) {
		claimMatches, err := generationClaimMatches(c.maps.claims, key, claim)
		if err != nil || !claimMatches {
			return false, err
		}
		guardMatches, err := generationGuardMatches(c.maps.ownerGuards, key.Owner, guard)
		if err != nil || !guardMatches {
			return false, err
		}
		terminalAbsent, err := c.generationTerminalAbsent(key)
		if err != nil || !terminalAbsent {
			return false, err
		}
		markerMatches, err := c.cleanupMarkerMatches(key, expectedMarker)
		if err != nil || !markerMatches {
			return false, err
		}
		complete, err := c.snapshotProvesGenerationCleanupComplete(key)
		if err != nil || !complete {
			return false, err
		}
		liveComplete, err := c.generationCleanupArtifactsAbsent(key)
		if err != nil || !liveComplete {
			return false, err
		}
		replayMatches, err := currentReplayMatches()
		if err != nil || !replayMatches {
			return false, err
		}
		return generationClaimMatches(c.maps.claims, key, claim)
	}
	err := c.publishFreshGenerationCleanupMarkerExact(
		key, now, "active-replay cleanup marker", validate,
	)
	return true, err
}

func (c *Cleanup) releaseGenerationCleanupClaimTail(
	key stateKey,
	claim generationClaim,
	now time.Duration,
) (bool, error) {
	if (!validGenerationCleanupClaim(claim) &&
		!validExactMarkerTailCleanupClaim(key, claim)) ||
		c.claimCreatedThisSweep(key, claim) ||
		!c.generationCleanupFenceExpired(now, claim.ObservedMonotonicNS) {
		return false, nil
	}
	validate := func() (bool, error) {
		return c.exactMarkerTailClaimMatches(key, claim, nil)
	}
	valid, err := validate()
	if err != nil || !valid {
		return false, err
	}
	valid, err = validate()
	if err != nil || !valid {
		return false, err
	}
	c.recordFenceRetirementAttempt(key)
	deleted, err := cleanupDeleteExact(c.maps.claims, key, claim)
	if err != nil || !deleted {
		return false, err
	}
	c.recordReleasedSweepClaim(key, claim)
	c.clearCurrentSweepClaim(key, claim)
	return true, nil
}

func (c *Cleanup) releaseExactMarkerTailGuardTail(
	key stateKey,
	claim generationClaim,
	guard generationClaim,
	now time.Duration,
	marker *uint64,
) error {
	if !validExactMarkerTailCleanupClaim(key, claim) ||
		!validGenerationCleanupGuard(key.Owner, guard) ||
		guard.ProcessIncarnation != key.Generation ||
		c.claimCreatedThisSweep(key, claim) ||
		c.guardCreatedThisSweep(key.Owner, guard) ||
		!c.generationCleanupFenceExpired(now, claim.ObservedMonotonicNS) ||
		!c.generationCleanupFenceExpired(now, guard.ObservedMonotonicNS) ||
		(marker != nil && (*marker == 0 ||
			!c.generationCleanupFenceExpired(now, *marker))) {
		return nil
	}
	validate := func() (bool, error) {
		terminalAbsent, err := c.generationTerminalAbsent(key)
		if err != nil || !terminalAbsent {
			return false, err
		}
		markerMatches, err := c.cleanupMarkerMatches(key, marker)
		if err != nil || !markerMatches {
			return false, err
		}
		complete, err := c.snapshotProvesExactTailPayloadComplete(key)
		if err != nil || !complete {
			return false, err
		}
		claimMatches, err := generationClaimMatches(c.maps.claims, key, claim)
		if err != nil || !claimMatches {
			return false, err
		}
		guardMatches, err := generationGuardMatches(c.maps.ownerGuards, key.Owner, guard)
		if err != nil || !guardMatches {
			return false, err
		}
		return c.exactMarkerTailReplaySafe(key, &claim)
	}
	for range 2 {
		valid, err := validate()
		if err != nil || !valid {
			return err
		}
	}
	c.recordFenceRetirementAttempt(key)
	deleted, err := cleanupDeleteExact(c.maps.ownerGuards, key.Owner, guard)
	if err != nil || !deleted {
		return err
	}
	c.recordReleasedSweepGuard(key.Owner, guard)
	c.clearCurrentSweepGuard(key.Owner, guard)
	return nil
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
		terminalAbsent, err := c.generationTerminalAbsent(key)
		if err != nil || !terminalAbsent {
			return false, err
		}
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
		complete, err := c.snapshotProvesGenerationCleanupComplete(key)
		if err != nil || !complete {
			return false, err
		}
		return c.aliasReplayFenceRetirementSafe(key, &claim)
	}
	valid, err := validate()
	if err != nil || !valid {
		return false, err
	}
	valid, err = validate()
	if err != nil || !valid {
		return false, err
	}
	c.recordFenceRetirementAttempt(key)
	deleted, err := cleanupDeleteExact(c.maps.claims, key, claim)
	if err != nil || !deleted {
		return false, err
	}
	c.recordReleasedSweepClaim(key, claim)
	c.clearCurrentSweepClaim(key, claim)
	if !guardPresent {
		return true, nil
	}
	terminalAbsent, err := c.generationTerminalAbsent(key)
	if err != nil || !terminalAbsent {
		return true, err
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
	replaySafe, replayErr := c.aliasReplayFenceRetirementSafe(key, &claim)
	if replayErr != nil || !replaySafe {
		return true, replayErr
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
	replaySafe, replayErr = c.aliasReplayFenceRetirementSafe(key, &claim)
	if replayErr != nil || !replaySafe {
		return true, replayErr
	}
	terminalAbsent, err = c.generationTerminalAbsent(key)
	if err != nil || !terminalAbsent {
		return true, err
	}
	deleted, err = cleanupDeleteExact(c.maps.ownerGuards, key.Owner, guard)
	if err != nil || !deleted {
		return true, err
	}
	c.recordReleasedSweepGuard(key.Owner, guard)
	c.clearCurrentSweepGuard(key.Owner, guard)
	return true, nil
}

func (c *Cleanup) exactMarkerTailReplaySafe(
	key stateKey,
	claim *generationClaim,
) (bool, error) {
	var terminal terminalValue
	if err := c.maps.terminals.Lookup(&key.Owner, &terminal); err == nil {
		if terminal.Generation == key.Generation {
			// T is retained status authority. Without matching owner-wide G, an
			// exact-only recovery tail may not collapse its lifecycle/provenance
			// into synthetic ambiguous E or retire the generation exclusion.
			return false, nil
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking exact-tail replay terminal: %w", err)
	}
	if claim != nil && !validExactMarkerTailCleanupClaim(key, *claim) {
		// Ordinary retained producer/full-fence claims carry JVM provenance and
		// committed status. Preserve their existing exact replay validation.
		return c.aliasReplayFenceRetirementSafe(key, claim)
	}
	// Only the recognizable synthetic ambiguous E has no JVM provenance or
	// committed non-ambiguous result. Other replay epochs are independent
	// carrier/status authority and must not be inferred from HASH enumeration.
	return true, nil
}

func (c *Cleanup) exactMarkerTailRootSafe(
	key stateKey,
	claim *generationClaim,
	expectedMarker *uint64,
) (bool, error) {
	markerMatches, err := c.cleanupMarkerMatches(key, expectedMarker)
	if err != nil || !markerMatches {
		return false, err
	}
	guardAbsent, err := generationGuardAbsent(c.maps.ownerGuards, key.Owner)
	if err != nil || !guardAbsent {
		return false, err
	}
	complete, err := c.snapshotProvesExactTailPayloadComplete(key)
	if err != nil || !complete {
		return false, err
	}
	return c.exactMarkerTailReplaySafe(key, claim)
}

func (c *Cleanup) exactMarkerTailClaimMatches(
	key stateKey,
	claim generationClaim,
	expectedMarker *uint64,
) (bool, error) {
	safe, err := c.exactMarkerTailRootSafe(key, &claim, expectedMarker)
	if err != nil || !safe {
		return false, err
	}
	return generationClaimMatches(c.maps.claims, key, claim)
}

func (c *Cleanup) claimGenerationCleanupMarkerTail(
	key stateKey,
	claim generationClaim,
	markedAt uint64,
) (bool, error) {
	if key.Generation == 0 || key.Reserved != 0 || markedAt == 0 ||
		!validExactMarkerTailCleanupClaim(key, claim) {
		return false, errors.New("invalid exact marker-tail cleanup claim")
	}
	safe, err := c.exactMarkerTailRootSafe(key, &claim, &markedAt)
	if err != nil || !safe {
		return false, err
	}
	if updateErr := c.maps.claims.Update(&key, &claim, ebpf.UpdateNoExist); updateErr != nil {
		if errors.Is(updateErr, ebpf.ErrKeyExist) {
			return false, nil
		}
		matches, matchErr := generationClaimMatches(c.maps.claims, key, claim)
		if matchErr != nil {
			return false, errors.Join(
				fmt.Errorf("claiming exact marker-tail cleanup: %w", updateErr),
				fmt.Errorf("checking uncertain exact marker-tail claim: %w", matchErr),
			)
		}
		if matches {
			// The kernel may have committed UpdateNoExist even though userspace
			// observed an error. Count and retain the exact exclusion so admission
			// remains bounded and this sweep cannot retire uncertain authority.
			c.recordCurrentSweepClaim(key, claim)
			return true, fmt.Errorf("claiming exact marker-tail cleanup: %w", updateErr)
		}
		return false, fmt.Errorf("claiming exact marker-tail cleanup: %w", updateErr)
	}
	c.recordCurrentSweepClaim(key, claim)
	for range 2 {
		matches, matchErr := c.exactMarkerTailClaimMatches(key, claim, &markedAt)
		if matchErr != nil || !matches {
			// E is exact-generation fail-closed authority. If M, G, payload, or
			// replay state changed after insertion, retain E for a later recovery
			// pass rather than handing authority back at the race boundary.
			return true, matchErr
		}
	}
	return true, nil
}

func (c *Cleanup) releaseGenerationCleanupClaimMarkerTail(
	key stateKey,
	claim generationClaim,
	markedAt uint64,
	now time.Duration,
) (bool, error) {
	if key.Generation == 0 || key.Reserved != 0 || markedAt == 0 ||
		!validExactMarkerTailCleanupClaim(key, claim) || c.claimCreatedThisSweep(key, claim) ||
		!c.generationCleanupFenceExpired(now, markedAt) ||
		!c.generationCleanupFenceExpired(now, claim.ObservedMonotonicNS) {
		return false, nil
	}
	valid, err := c.exactMarkerTailClaimMatches(key, claim, &markedAt)
	if err != nil || !valid {
		return false, err
	}
	valid, err = c.exactMarkerTailClaimMatches(key, claim, &markedAt)
	if err != nil || !valid {
		return false, err
	}

	// Refresh E before M deletion so the marker-free phase has a durable grace
	// epoch. E blocks exact numeric-generation reuse without blocking a different
	// generation for the owner; aging it again after M disappears lets the next
	// complete sweep observe any producer that passed a pre-E check before this
	// phase. Fence retention is the quiescence bound for those BPF critical
	// sections, just as it is for the full G/E/M protocol.
	refreshed := generationClaim{
		ObservedMonotonicNS: uint64(now),
		ProcessIncarnation:  key.Generation,
		Lifecycle:           lifecycleCleanup,
		Reserved: [7]byte{
			0: lifecycleAmbiguous,
			6: generationGoProducerTag,
		},
	}
	if updateErr := c.maps.claims.Update(&key, &refreshed, ebpf.UpdateExist); updateErr != nil {
		matches, matchErr := generationClaimMatches(c.maps.claims, key, refreshed)
		if matchErr != nil {
			return false, errors.Join(
				fmt.Errorf("refreshing exact marker-tail claim: %w", updateErr),
				fmt.Errorf("checking uncertain refreshed exact claim: %w", matchErr),
			)
		}
		if matches {
			c.recordCurrentSweepClaim(key, refreshed)
			return true, fmt.Errorf("refreshing exact marker-tail claim: %w", updateErr)
		}
		return false, fmt.Errorf("refreshing exact marker-tail claim: %w", updateErr)
	}
	c.recordCurrentSweepClaim(key, refreshed)
	for range 2 {
		matches, matchErr := c.exactMarkerTailClaimMatches(key, refreshed, &markedAt)
		if matchErr != nil || !matches {
			return true, matchErr
		}
	}

	c.recordFenceRetirementAttempt(key)
	deleted, err := cleanupDeleteExact(c.maps.ambiguity, key, markedAt)
	if err != nil || !deleted {
		return true, err
	}
	c.recordReleasedSweepAmbiguity(key, markedAt)
	// Refreshed E is deliberately the final remaining generation mutation. A
	// later sweep may release it only after another full retention interval and
	// a new complete snapshot proves the exact payload still absent.
	return true, nil
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
	terminalAbsent, err := c.generationTerminalAbsent(key)
	if err != nil || !terminalAbsent {
		return false, err
	}
	exactAbsent, err := generationClaimAbsent(c.maps.claims, key)
	if err != nil || !exactAbsent {
		return false, err
	}
	var marker uint64
	if err := c.maps.ambiguity.Lookup(&key, &marker); err != nil || marker != 0 {
		return false, ignoreMissing(err)
	}
	replaySafe, err := c.aliasReplayFenceRetirementSafe(key, nil)
	if err != nil || !replaySafe {
		return false, err
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
	replaySafe, err = c.aliasReplayFenceRetirementSafe(key, nil)
	if err != nil || !replaySafe {
		return false, err
	}
	guardMatches, err = generationGuardMatches(c.maps.ownerGuards, guardKey, guard)
	if err != nil || !guardMatches {
		return false, err
	}
	terminalAbsent, err = c.generationTerminalAbsent(key)
	if err != nil || !terminalAbsent {
		return false, err
	}
	c.recordFenceRetirementAttempt(key)
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
	terminalPresent, terminalErr := c.terminalTailCleanupAuthority(key, nil, now)
	if terminalErr != nil || terminalPresent {
		return false, terminalErr
	}
	complete, err := c.snapshotProvesGenerationCleanupComplete(key)
	if err != nil || !complete {
		return false, err
	}
	replaySafe, err := c.aliasReplayFenceRetirementSafe(key, nil)
	if err != nil || !replaySafe {
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
	replaySafe, err = c.aliasReplayFenceRetirementSafe(key, nil)
	if err != nil || !replaySafe {
		return false, err
	}
	terminalAbsent, err := c.generationTerminalAbsent(key)
	if err != nil || !terminalAbsent {
		return false, err
	}
	c.recordFenceRetirementAttempt(key)
	deleted, err := cleanupDeleteExact(c.maps.ownerGuards, guardKey, guard)
	if err != nil || !deleted {
		return false, err
	}
	c.recordReleasedSweepGuard(guardKey, guard)
	c.clearCurrentSweepGuard(guardKey, guard)
	return true, nil
}

func (c *Cleanup) retainedTerminalPhysicalFenceMatches(
	key stateKey,
	claim generationClaim,
) (bool, error) {
	terminal, retained := c.retainedTerminalAuthorities[key]
	if !retained {
		return c.validGenerationTerminalAbsent(key)
	}
	if !validTerminalValue(terminal) || terminal.Generation != key.Generation ||
		claim.ProcessIncarnation != terminal.ProcessIncarnation ||
		claim.Reserved[0] != terminal.Lifecycle {
		return false, nil
	}
	terminalMatches, err := cleanupExactMatches(c.maps.terminals, key.Owner, terminal)
	if err != nil || !terminalMatches {
		return false, err
	}
	replaySafe, err := c.terminalAliasReplayFenceRetirementSafe(key, terminal)
	if err != nil || !replaySafe {
		return false, err
	}
	return cleanupExactMatches(c.maps.terminals, key.Owner, terminal)
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
	terminalMatches, err := c.retainedTerminalPhysicalFenceMatches(key, claim)
	if err != nil || !terminalMatches {
		return false, err
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
	if !valid {
		return false, nil
	}
	return c.retainedTerminalPhysicalFenceMatches(key, claim)
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
	if validTerminalValue(terminal) {
		// Valid T is bounded status authority. Its LRU eviction policy, not
		// userspace generation cleanup, owns its eventual removal.
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

func (c *Cleanup) physicalGenerationCleanupProcessIncarnation(
	key stateKey,
) (uint64, error) {
	var terminal terminalValue
	if err := c.maps.terminals.Lookup(&key.Owner, &terminal); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return key.Generation, nil
		}
		return 0, fmt.Errorf("checking physical generation terminal provenance: %w", err)
	}
	if terminal.Generation == key.Generation && validTerminalValue(terminal) {
		return terminal.ProcessIncarnation, nil
	}
	return key.Generation, nil
}

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
			if validTerminalValue(terminal) {
				return false, nil
			}
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
				stats.recordGeneration(cleanedGenerations, canonicalGenerationKey(entry.key))
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
			_, coherentReservation, reservationErr := c.coherentGenerationPublishingReservation(entry.key)
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
			stats.recordGeneration(cleanedGenerations, entry.key)
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
	physicalCleanupOwnerships := make(map[stateKey]generationCleanupOwnership)
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
			processIncarnation, provenanceErr := c.physicalGenerationCleanupProcessIncarnation(key)
			if provenanceErr != nil {
				result = errors.Join(result, provenanceErr)
				continue
			}
			ownership, ready, claimErr := c.claimGenerationCleanupForArtifact(
				key, processIncarnation, lifecycleAmbiguous,
				func() (bool, error) {
					return c.physicalGenerationCleanupRootMatches(key, rootSnapshot)
				},
			)
			if ready {
				physicalCleanupOwnerships[key] = ownership
			}
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
		ownership, ready := physicalCleanupOwnerships[key]
		if !ready {
			return false
		}
		if terminal, retained := c.retainedTerminalAuthorities[key]; retained {
			replayReady, replayErr := c.ensureTerminalAliasReplayFinal(
				ownership, key, terminal,
			)
			if replayErr != nil {
				result = errors.Join(
					result,
					fmt.Errorf("finalizing physical-generation terminal replay: %w", replayErr),
				)
				return false
			}
			if !replayReady {
				return false
			}
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
	// Live task and handoff links remain protocol-owned. Retired task links were
	// reclaimed earlier while userspace held the exact T(execution) fence;
	// retired handoff keys embed their capability and were likewise converged.
	// Handoff admission tickets were reclaimed earlier only after exact no-H
	// observations under M; untagged rolling-version values are treated just as
	// conservatively. Foreign task mutation claims are synchronous BPF
	// serialization fences and are never age-deleted here.

	terminals, err := cleanupMapEntries[Identity, terminalValue](c.maps.terminals)
	if err != nil {
		result = errors.Join(result, fmt.Errorf("iterating terminal generations: %w", err))
	}
	for _, entry := range terminals {
		generation := stateKey{Owner: entry.key, Generation: entry.value.Generation}
		c.recordKnownGeneration(generation)
		if !validTerminalValue(entry.value) {
			cleaned, cleanupErr := c.quarantineMalformedTerminal(entry.key, entry.value)
			if cleaned {
				if entry.value.Generation == 0 {
					stats.Cleaned++
				} else {
					stats.recordGeneration(cleanedGenerations, generation)
				}
			}
			if cleanupErr != nil {
				result = errors.Join(result, cleanupErr)
			}
			continue
		}
		// Valid T is retained status authority. Its matching fence is considered
		// only in the final mutation pass, after every payload cleanup opportunity.
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

	claims, claimsErr := cleanupMapEntries[stateKey, generationClaim](c.maps.claims)
	if claimsErr != nil {
		result = errors.Join(result, fmt.Errorf("iterating generation claims: %w", claimsErr))
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
			_, coherentReservation, reservationErr := c.coherentGenerationPublishingReservation(generation)
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
			stats.recordGeneration(cleanedGenerations, generation)
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
					stats.recordGeneration(cleanedGenerations, malformedGeneration)
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
					stats.recordGeneration(cleanedGenerations, key)
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
		publishingClaim, coherentReservation, reservationErr := c.coherentGenerationPublishingReservation(key)
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
				stats.recordGeneration(cleanedGenerations, key)
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
				stats.recordGeneration(cleanedGenerations, key)
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
			stats.recordGeneration(cleanedGenerations, key)
		}
		if cleanupErr != nil {
			result = errors.Join(result, cleanupErr)
		}
	}

	tailsNow := c.monoTimeNow()
	orderedTailClaims := c.orderedGenerationCleanupTailClaims(claims)
	for _, entry := range terminals {
		if !validTerminalValue(entry.value) {
			continue
		}
		generation := stateKey{Owner: entry.key, Generation: entry.value.Generation}
		_, cleaned := cleanedGenerations[generation]
		processRetired, retirementErr := c.processRetired(
			retired, javaProcessIdentity(entry.key), entry.value.ProcessIncarnation,
		)
		if retirementErr != nil {
			result = errors.Join(result, retirementErr)
			continue
		}
		if !cleaned && !processRetired &&
			!cleanupExpired(tailsNow, entry.value.ObservedMonotonicNS, c.ttl) {
			continue
		}
		var guard generationClaim
		if guardErr := c.maps.ownerGuards.Lookup(&entry.key, &guard); guardErr != nil {
			if !errors.Is(guardErr, ebpf.ErrKeyNotExist) {
				result = errors.Join(
					result, fmt.Errorf("checking terminal cleanup guard: %w", guardErr),
				)
			}
			continue
		}
		if !validGenerationCleanupGuard(entry.key, guard) ||
			guard.ProcessIncarnation != generation.Generation {
			continue
		}
		// From this point, matching T exclusively owns every fence shape for the
		// generation. Record the attempt before any fallible operation so a failed
		// or committed-but-reported-failed release cannot fall through to a generic
		// path using stale M/E/G snapshots later in this sweep.
		c.recordFenceRetirementAttempt(generation)
		if _, cleanupErr := c.releaseTerminalGenerationFence(
			entry.key, entry.value, guard,
		); cleanupErr != nil {
			result = errors.Join(result, cleanupErr)
		}
	}
	c.selectGenerationReplayScanKey(
		claims, guards, tailsNow, claimsErr == nil && guardErr == nil,
	)

	// This is the final mutation pass. Retire only a complete, aged exact
	// teardown tuple, and do not touch generation artifacts afterward.
	for _, entry := range orderedTailClaims {
		if c.fenceRetirementAttempted(entry.key) {
			continue
		}
		exactMarkerTail := validExactMarkerTailCleanupClaim(entry.key, entry.value)
		if entry.key.Generation == 0 || entry.key.Reserved != 0 ||
			(!validGenerationCleanupClaim(entry.value) && !exactMarkerTail) ||
			c.claimCreatedThisSweep(entry.key, entry.value) {
			continue
		}
		terminalAbsent, terminalErr := c.generationTerminalAbsent(entry.key)
		if terminalErr != nil {
			result = errors.Join(result, terminalErr)
			continue
		}
		if !terminalAbsent {
			// T is status authority for M/E/G, including M=0. The terminal pass
			// either handled its exact tuple or deliberately preserved it.
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
			guardAbsent, guardErr := generationGuardAbsent(
				c.maps.ownerGuards, entry.key.Owner,
			)
			if guardErr != nil {
				result = errors.Join(
					result, fmt.Errorf("checking marker-free cleanup guard: %w", guardErr),
				)
				continue
			}
			if guardAbsent {
				complete, completeErr := c.snapshotProvesExactTailPayloadComplete(entry.key)
				if completeErr != nil {
					result = errors.Join(
						result,
						fmt.Errorf("checking marker-free exact-tail completion: %w", completeErr),
					)
					continue
				}
				if complete {
					// Synthetic exact tails use only point validation; ordinary
					// claims require a full replay-map exclusion proof.
					if !exactMarkerTail && !c.generationReplayScanAuthorized(entry.key) {
						continue
					}
					if _, releaseErr := c.releaseGenerationCleanupClaimTail(
						entry.key, entry.value, tailsNow,
					); releaseErr != nil {
						result = errors.Join(
							result,
							fmt.Errorf("releasing marker-free exact cleanup tail: %w", releaseErr),
						)
					}
				}
				// E without M/G is exact-generation fail-closed authority. Earlier
				// mutable roots may acquire the full fence when payload exists; this
				// rootless tail pass must never widen E into owner-wide G.
				continue
			}
			if exactMarkerTail {
				var guard generationClaim
				if guardErr := c.maps.ownerGuards.Lookup(&entry.key.Owner, &guard); guardErr != nil {
					if !errors.Is(guardErr, ebpf.ErrKeyNotExist) {
						result = errors.Join(
							result,
							fmt.Errorf("checking exact-tail owner guard: %w", guardErr),
						)
					}
					continue
				}
				if releaseErr := c.releaseExactMarkerTailGuardTail(
					entry.key, entry.value, guard, tailsNow, nil,
				); releaseErr != nil {
					result = errors.Join(
						result,
						fmt.Errorf("releasing exact-tail owner guard: %w", releaseErr),
					)
				}
				// Exact-only E is never widened into owner-wide G. A stranded G
				// acquired for a disappeared artifact is retired first; E remains
				// exact-generation authority for a later complete sweep.
				continue
			}
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
				if guardErr == nil && validGenerationCleanupGuard(entry.key.Owner, guard) &&
					guard.ProcessIncarnation == entry.key.Generation {
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
				terminalAbsent, err := c.generationTerminalAbsent(entry.key)
				if err != nil || !terminalAbsent {
					return false, err
				}
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
			if exactMarkerTail {
				// Synthetic exact-tail claims are created only behind M+. Any M=0
				// shape is foreign or corrupted and remains fail closed.
				continue
			}
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
				terminalAbsent, err := c.generationTerminalAbsent(entry.key)
				if err != nil || !terminalAbsent {
					return false, err
				}
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
		guardAbsent, guardErr := generationGuardAbsent(c.maps.ownerGuards, entry.key.Owner)
		if guardErr != nil {
			result = errors.Join(
				result, fmt.Errorf("checking marked exact-tail cleanup guard: %w", guardErr),
			)
			continue
		}
		complete, completeErr := c.snapshotProvesExactTailPayloadComplete(entry.key)
		if completeErr != nil {
			result = errors.Join(
				result, fmt.Errorf("checking marked exact-tail cleanup completion: %w", completeErr),
			)
			continue
		}
		if guardAbsent {
			if complete {
				if _, releaseErr := c.releaseGenerationCleanupClaimMarkerTail(
					entry.key, entry.value, marker, tailsNow,
				); releaseErr != nil {
					result = errors.Join(
						result, fmt.Errorf("releasing marked exact cleanup tail: %w", releaseErr),
					)
				}
			}
			continue
		}
		if exactMarkerTail {
			if complete {
				var guard generationClaim
				if guardErr := c.maps.ownerGuards.Lookup(&entry.key.Owner, &guard); guardErr != nil {
					if !errors.Is(guardErr, ebpf.ErrKeyNotExist) {
						result = errors.Join(
							result,
							fmt.Errorf("checking marked exact-tail guard: %w", guardErr),
						)
					}
					continue
				}
				if releaseErr := c.releaseExactMarkerTailGuardTail(
					entry.key, entry.value, guard, tailsNow, &marker,
				); releaseErr != nil {
					result = errors.Join(
						result,
						fmt.Errorf("releasing marked exact-tail guard: %w", releaseErr),
					)
				}
			}
			// Exact-only E never adopts an owner-wide guard. A stranded G is
			// retired first while exact M/E remain untouched.
			continue
		}
		expectedMarker := marker
		ownershipRoot := func() (bool, error) {
			terminalAbsent, err := c.generationTerminalAbsent(entry.key)
			if err != nil || !terminalAbsent {
				return false, err
			}
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
			stats.recordGeneration(cleanedGenerations, entry.key)
		}
		if _, finishErr := c.finishGenerationCleanupFenced(
			entry.key, ownership,
		); finishErr != nil {
			result = errors.Join(result, finishErr)
		}
	}

	// Exact-only retirement claims share the producer E map. Their Go-only tag
	// gives the complete claim snapshot durable provenance that concurrent BPF
	// writers cannot forge. Since GenerationCoordinator serializes every Go
	// cleanup admission, this bounds cleanup's discretionary contribution without
	// pretending HASH iteration can bound unrelated BPF claims.
	exactTailClaims := 0
	for _, entry := range claims {
		if validExactMarkerTailCleanupClaim(entry.key, entry.value) {
			exactTailClaims++
		}
	}
	exactTailClaimBudget := javaRemoteParentMaxExactTailClaims - min(
		exactTailClaims, javaRemoteParentMaxExactTailClaims,
	)
	if claimsErr != nil {
		exactTailClaimBudget = 0
	}

	// Recover crash/failure tails around exact marker publication and the full
	// G -> E -> M cleanup order. A fresh M+ remains exact fail-closed authority
	// without blocking a same-owner successor, so age it first. When complete
	// snapshots prove the exact generation has no payload, add only E and age
	// that exclusion before retiring M -> E. G remains necessary when cleanup
	// must serialize an owner-keyed or shared physical payload mutation.
	for _, entry := range ambiguity {
		if c.fenceRetirementAttempted(entry.key) {
			continue
		}
		if entry.key.Generation == 0 || entry.key.Reserved != 0 || entry.value == 0 {
			continue
		}
		if released, ok := c.releasedSweepAmbiguities[entry.key]; ok && released == entry.value {
			continue
		}
		if !c.generationCleanupFenceExpired(tailsNow, entry.value) {
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
		terminalAbsent, terminalErr := c.generationTerminalAbsent(entry.key)
		if terminalErr != nil {
			result = errors.Join(result, terminalErr)
			continue
		}
		if !terminalAbsent {
			// Matching T exclusively owns terminal fence recovery. This point
			// lookup also covers T inserted or omitted during HASH iteration.
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
		guardAbsent, guardErr := generationGuardAbsent(c.maps.ownerGuards, entry.key.Owner)
		if guardErr != nil {
			result = errors.Join(
				result, fmt.Errorf("checking partial cleanup guard: %w", guardErr),
			)
			continue
		}
		complete, completeErr := c.snapshotProvesExactTailPayloadComplete(entry.key)
		if completeErr != nil {
			result = errors.Join(
				result, fmt.Errorf("checking partial cleanup completion: %w", completeErr),
			)
			continue
		}
		if guardAbsent {
			if complete && exactTailClaimBudget > 0 {
				claim, ok := c.newExactMarkerTailClaim(entry.key)
				if !ok {
					result = errors.Join(
						result, errors.New("reading monotonic time for exact partial cleanup claim"),
					)
					continue
				}
				claimed, claimErr := c.claimGenerationCleanupMarkerTail(
					entry.key, claim, entry.value,
				)
				if claimed {
					exactTailClaimBudget--
				}
				if claimErr != nil {
					// An unverified UpdateNoExist outcome may have committed a tagged
					// claim even when readback also failed. Stop admission for this
					// sweep so uncertainty cannot exceed cleanup's fixed contribution.
					exactTailClaimBudget = 0
					result = errors.Join(
						result, fmt.Errorf("claiming exact marker-tail cleanup: %w", claimErr),
					)
				}
			}
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
				terminalAbsent, err := c.generationTerminalAbsent(entry.key)
				if err != nil || !terminalAbsent {
					return false, err
				}
				return c.cleanupMarkerMatches(entry.key, &expectedMarker)
			},
		); claimErr != nil {
			result = errors.Join(result, fmt.Errorf("completing partial cleanup fence: %w", claimErr))
		}
	}
	for _, entry := range guards {
		key := stateKey{Owner: entry.key, Generation: entry.value.ProcessIncarnation}
		if c.fenceRetirementAttempted(key) {
			continue
		}
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

	// Alias replay is status-only authority, not a logical or physical
	// generation artifact. Reclaim proven carrier-free tails only after every
	// generation mutation and fence-retirement pass has finished.
	if replayErr := c.sweepAliasReplayTails(retired); replayErr != nil {
		result = errors.Join(result, replayErr)
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
		// It cannot acquire a canonical full fence, so any alias counter or
		// exact replay is an explicit fail-closed block on direct deletion.
		if state.Aliases > 0 {
			return false, nil
		}
		replayKey := aliasReplayKeyForState(key, state)
		var replay aliasReplayValue
		if err := c.maps.aliasReplays.Lookup(&replayKey, &replay); err == nil {
			return false, nil
		} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, fmt.Errorf("checking malformed-key alias replay: %w", err)
		}
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
	replayReady, replayErr := c.ensureStateAliasReplayFinal(ownership, key, state)
	if replayErr != nil {
		return false, fmt.Errorf("finalizing malformed-state alias replay: %w", replayErr)
	}
	if !replayReady {
		return false, nil
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
	return c.cleanupTerminal(owner, terminal, lifecycleStale)
}

func (c *Cleanup) upgradeExactMarkerTailClaimForTerminal(
	key stateKey,
	terminal terminalValue,
	claim generationClaim,
	guard generationClaim,
	marker *uint64,
	now time.Duration,
) (bool, error) {
	if !validTerminalValue(terminal) || terminal.Generation != key.Generation ||
		!validExactMarkerTailCleanupClaim(key, claim) ||
		!validGenerationCleanupGuard(key.Owner, guard) ||
		guard.ProcessIncarnation != key.Generation ||
		!c.generationCleanupFenceExpired(now, terminal.ObservedMonotonicNS) ||
		!c.generationCleanupFenceExpired(now, claim.ObservedMonotonicNS) ||
		!c.generationCleanupFenceExpired(now, guard.ObservedMonotonicNS) ||
		(marker != nil && (*marker == 0 ||
			!c.generationCleanupFenceExpired(now, *marker))) {
		return false, nil
	}
	payloadComplete, err := c.exactTerminalGenerationPayloadComplete(key, terminal)
	if err != nil || !payloadComplete {
		return false, err
	}
	rootMatches := func() (bool, error) {
		terminalMatches, err := cleanupExactMatches(c.maps.terminals, key.Owner, terminal)
		if err != nil || !terminalMatches {
			return false, err
		}
		markerMatches, err := c.cleanupMarkerMatches(key, marker)
		if err != nil || !markerMatches {
			return false, err
		}
		return cleanupExactMatches(c.maps.terminals, key.Owner, terminal)
	}
	ownership, _, err := c.upgradeExactMarkerTailClaimForArtifact(
		key, claim, terminal.ProcessIncarnation, terminal.Lifecycle, false, &guard, rootMatches,
	)
	if err != nil || !validGenerationCleanupClaim(ownership.claim) {
		return false, err
	}
	if marker == nil {
		// Reconstruct M after the continuous-E upgrade so terminal replay can be
		// finalized only under a complete T/G/E/M fence on a later aged sweep.
		err = c.reconstructTerminalGenerationCleanupMarker(
			key, terminal, ownership.claim, guard, now,
		)
	}
	return false, err
}

func (c *Cleanup) releaseTerminalGenerationFence(
	owner Identity,
	terminal terminalValue,
	guard generationClaim,
) (bool, error) {
	key := stateKey{Owner: owner, Generation: terminal.Generation}
	if !validTerminalValue(terminal) ||
		!validGenerationCleanupGuard(owner, guard) ||
		guard.ProcessIncarnation != key.Generation ||
		!c.recordAliasReplayCleanupKey(
			key, terminal.ObservedMonotonicNS, terminal.ProcessIncarnation,
		) {
		return false, nil
	}
	now := c.monoTimeNow()
	var markedAt uint64
	if err := c.maps.ambiguity.Lookup(&key, &markedAt); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, fmt.Errorf("checking terminal cleanup marker: %w", err)
		}
		var claim generationClaim
		if claimErr := c.maps.claims.Lookup(&key, &claim); claimErr == nil {
			if validExactMarkerTailCleanupClaim(key, claim) {
				return c.upgradeExactMarkerTailClaimForTerminal(
					key, terminal, claim, guard, nil, now,
				)
			}
			return c.releaseTerminalClaimGuardTail(key, terminal, claim, guard, now)
		} else if !errors.Is(claimErr, ebpf.ErrKeyNotExist) {
			return false, fmt.Errorf("checking terminal cleanup claim tail: %w", claimErr)
		}
		return c.releaseTerminalGuardTail(key, terminal, guard, now)
	}
	if markedAt == 0 {
		// M=0 is a live publication reservation, not destructive authority.
		return false, nil
	}
	var exactClaim generationClaim
	if claimErr := c.maps.claims.Lookup(&key, &exactClaim); claimErr == nil {
		if validExactMarkerTailCleanupClaim(key, exactClaim) {
			return c.upgradeExactMarkerTailClaimForTerminal(
				key, terminal, exactClaim, guard, &markedAt, now,
			)
		}
	} else if !errors.Is(claimErr, ebpf.ErrKeyNotExist) {
		return false, fmt.Errorf("checking marked terminal exact-tail claim: %w", claimErr)
	}
	rootMatches := func() (bool, error) {
		return cleanupExactMatches(c.maps.terminals, owner, terminal)
	}
	ownership, ready, err := c.claimGenerationCleanupWithGuard(
		key, terminal.ProcessIncarnation, terminal.Lifecycle, guard, markedAt, rootMatches,
	)
	if err != nil || !ready {
		return false, err
	}
	replayReady, replayErr := c.ensureTerminalAliasReplayFinal(ownership, key, terminal)
	if replayErr != nil {
		return false, fmt.Errorf("checking terminal alias replay before fence retirement: %w", replayErr)
	}
	if !replayReady {
		return false, nil
	}
	payloadComplete, payloadErr := c.exactTerminalGenerationPayloadComplete(key, terminal)
	if payloadErr != nil || !payloadComplete {
		return false, payloadErr
	}
	return c.finishGenerationCleanupFencedValidated(
		key, ownership, func(bool) (bool, error) {
			return c.terminalGenerationCleanupComplete(key, terminal, ownership)
		},
	)
}

func (c *Cleanup) releaseTerminalClaimGuardTail(
	key stateKey,
	terminal terminalValue,
	claim generationClaim,
	guard generationClaim,
	now time.Duration,
) (bool, error) {
	if !validGenerationCleanupClaim(claim) ||
		claim.ProcessIncarnation != terminal.ProcessIncarnation ||
		claim.Reserved[0] != terminal.Lifecycle ||
		c.claimCreatedThisSweep(key, claim) ||
		c.guardCreatedThisSweep(key.Owner, guard) ||
		!c.generationCleanupFenceExpired(now, terminal.ObservedMonotonicNS) ||
		!c.generationCleanupFenceExpired(now, claim.ObservedMonotonicNS) ||
		!c.generationCleanupFenceExpired(now, guard.ObservedMonotonicNS) {
		return false, nil
	}
	payloadComplete, err := c.exactTerminalGenerationPayloadComplete(key, terminal)
	if err != nil || !payloadComplete {
		return false, err
	}
	replaySafe, err := c.terminalAliasReplayFenceRetirementSafe(key, terminal)
	if err != nil {
		return false, err
	}
	if !replaySafe {
		// A previous exact-tail promotion can leave T/E/G but no M when marker
		// publication fails. Reconstruct M only under the same exact T/E/G and
		// replay epoch; the fresh marker then receives its own grace interval in
		// the ordinary full-fence path.
		return false, c.reconstructTerminalGenerationCleanupMarker(
			key, terminal, claim, guard, now,
		)
	}
	validate := func(requireClaim bool) (bool, error) {
		markerAbsent, err := c.cleanupMarkerMatches(key, nil)
		if err != nil || !markerAbsent {
			return false, err
		}
		complete, err := c.exactTerminalGenerationCleanupComplete(key, terminal)
		if err != nil || !complete {
			return false, err
		}
		guardMatches, err := generationGuardMatches(c.maps.ownerGuards, key.Owner, guard)
		if err != nil || !guardMatches {
			return false, err
		}
		if requireClaim {
			return generationClaimMatches(c.maps.claims, key, claim)
		}
		return generationClaimAbsent(c.maps.claims, key)
	}
	for range 2 {
		valid, err := validate(true)
		if err != nil || !valid {
			return false, err
		}
	}
	c.recordFenceRetirementAttempt(key)
	deleted, err := cleanupDeleteExact(c.maps.claims, key, claim)
	if err != nil || !deleted {
		return false, err
	}
	c.recordReleasedSweepClaim(key, claim)
	c.clearCurrentSweepClaim(key, claim)
	valid, err := validate(false)
	if err != nil || !valid {
		return false, err
	}
	deleted, err = cleanupDeleteExact(c.maps.ownerGuards, key.Owner, guard)
	if err != nil || !deleted {
		return false, err
	}
	c.recordReleasedSweepGuard(key.Owner, guard)
	c.clearCurrentSweepGuard(key.Owner, guard)
	return true, nil
}

func (c *Cleanup) reconstructTerminalGenerationCleanupMarker(
	key stateKey,
	terminal terminalValue,
	claim generationClaim,
	guard generationClaim,
	now time.Duration,
) error {
	if now <= 0 || !validTerminalValue(terminal) || terminal.Generation != key.Generation ||
		!validGenerationCleanupClaim(claim) ||
		claim.ProcessIncarnation != terminal.ProcessIncarnation ||
		claim.Reserved[0] != terminal.Lifecycle ||
		!validGenerationCleanupGuard(key.Owner, guard) ||
		guard.ProcessIncarnation != key.Generation {
		return nil
	}
	replayKey := aliasReplayKeyForTerminal(key, terminal)
	var replay aliasReplayValue
	if err := c.maps.aliasReplays.Lookup(&replayKey, &replay); err != nil {
		return ignoreMissing(err)
	}
	if !validAliasReplayActive(replay) && !validTaggedAliasReplayPublishing(replay) {
		// Untagged publishing may still have a live producer, while malformed or
		// semantically conflicting final state is preservation authority.
		return nil
	}
	validate := func(expectedMarker *uint64) (bool, error) {
		terminalMatches, err := cleanupExactMatches(
			c.maps.terminals, key.Owner, terminal,
		)
		if err != nil || !terminalMatches {
			return false, err
		}
		claimMatches, err := generationClaimMatches(c.maps.claims, key, claim)
		if err != nil || !claimMatches {
			return false, err
		}
		guardMatches, err := generationGuardMatches(c.maps.ownerGuards, key.Owner, guard)
		if err != nil || !guardMatches {
			return false, err
		}
		markerMatches, err := c.cleanupMarkerMatches(key, expectedMarker)
		if err != nil || !markerMatches {
			return false, err
		}
		payloadComplete, err := c.exactTerminalGenerationPayloadComplete(key, terminal)
		if err != nil || !payloadComplete {
			return false, err
		}
		replayMatches, err := cleanupExactMatches(c.maps.aliasReplays, replayKey, replay)
		if err != nil || !replayMatches {
			return false, err
		}
		return cleanupExactMatches(c.maps.terminals, key.Owner, terminal)
	}
	err := c.publishFreshGenerationCleanupMarkerExact(
		key, now, "terminal cleanup marker", validate,
	)
	return err
}

func (c *Cleanup) publishFreshGenerationCleanupMarkerExact(
	key stateKey,
	now time.Duration,
	description string,
	validate func(*uint64) (bool, error),
) error {
	if key.Generation == 0 || key.Reserved != 0 || now <= 0 || validate == nil {
		return nil
	}
	for range 2 {
		valid, err := validate(nil)
		if err != nil || !valid {
			return err
		}
	}

	markedAt := uint64(now)
	if c.currentSweepAmbiguities != nil {
		// Record intent before the syscall. A committed update with an error and
		// failed readback must never be mistaken for an inherited aged marker.
		c.currentSweepAmbiguities[key] = markedAt
	}
	updateErr := c.maps.ambiguity.Update(&key, &markedAt, ebpf.UpdateNoExist)
	var current uint64
	lookupErr := c.maps.ambiguity.Lookup(&key, &current)
	if lookupErr != nil {
		if updateErr != nil {
			return errors.Join(
				fmt.Errorf("publishing %s: %w", description, updateErr),
				fmt.Errorf("checking uncertain %s: %w", description, lookupErr),
			)
		}
		return fmt.Errorf("checking published %s: %w", description, lookupErr)
	}
	if current != markedAt {
		if updateErr != nil {
			return fmt.Errorf("publishing %s: %w", description, updateErr)
		}
		return fmt.Errorf("%s changed during publication", description)
	}
	valid, validationErr := validate(&markedAt)
	if updateErr != nil {
		updateErr = fmt.Errorf("publishing %s: %w", description, updateErr)
	}
	if validationErr != nil {
		return errors.Join(updateErr, validationErr)
	}
	if !valid {
		return updateErr
	}
	return updateErr
}

func (c *Cleanup) releaseTerminalGuardTail(
	key stateKey,
	terminal terminalValue,
	guard generationClaim,
	now time.Duration,
) (bool, error) {
	if c.guardCreatedThisSweep(key.Owner, guard) ||
		!c.generationCleanupFenceExpired(now, terminal.ObservedMonotonicNS) ||
		!c.generationCleanupFenceExpired(now, guard.ObservedMonotonicNS) {
		return false, nil
	}
	validate := func() (bool, error) {
		markerAbsent, err := c.cleanupMarkerMatches(key, nil)
		if err != nil || !markerAbsent {
			return false, err
		}
		claimAbsent, err := generationClaimAbsent(c.maps.claims, key)
		if err != nil || !claimAbsent {
			return false, err
		}
		complete, err := c.exactTerminalGenerationCleanupComplete(key, terminal)
		if err != nil || !complete {
			return false, err
		}
		return generationGuardMatches(c.maps.ownerGuards, key.Owner, guard)
	}
	for range 2 {
		valid, err := validate()
		if err != nil || !valid {
			return false, err
		}
	}
	deleted, err := cleanupDeleteExact(c.maps.ownerGuards, key.Owner, guard)
	if err != nil || !deleted {
		return false, err
	}
	c.recordReleasedSweepGuard(key.Owner, guard)
	c.clearCurrentSweepGuard(key.Owner, guard)
	return true, nil
}

func (c *Cleanup) cleanupTerminal(
	owner Identity,
	terminal terminalValue,
	origin uint8,
) (bool, error) {
	if validTerminalValue(terminal) {
		return false, nil
	}
	key := stateKey{Owner: owner, Generation: terminal.Generation}
	if terminal.Generation == 0 {
		// Terminal keys are owner-scoped and reusable. Without both generation
		// and retained exact claim no teardown fence can make deletion safe.
		return false, nil
	}
	ownership, ready, err := c.claimGenerationCleanupForArtifact(
		key, terminal.ProcessIncarnation, origin,
		func() (bool, error) {
			return cleanupExactMatches(c.maps.terminals, owner, terminal)
		},
	)
	if err != nil || !ready {
		return false, err
	}
	deleted, err := c.mutateGenerationCleanupFenced(
		ownership, "terminal deletion", func() (bool, error) {
			return cleanupDeleteExact(c.maps.terminals, owner, terminal)
		},
	)
	if err != nil || !deleted {
		return false, err
	}
	complete, completeErr := c.generationCleanupLogicalComplete(key)
	if completeErr != nil {
		return false, fmt.Errorf("verifying terminal logical cleanup: %w", completeErr)
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
			(!validGenerationCleanupClaim(retained) &&
				!validExactMarkerTailCleanupClaim(key, retained)) {
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return false, fmt.Errorf("checking ownerless fallback claim: %w", err)
			}
			return false, nil
		}
		ownership, ready, err := c.claimGenerationCleanupForArtifact(
			key, retained.ProcessIncarnation, retained.Reserved[0], func() (bool, error) {
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
			(!validGenerationCleanupClaim(retained) &&
				!validExactMarkerTailCleanupClaim(key, retained)) {
			if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return false, fmt.Errorf("checking detached fallback claim: %w", err)
			}
			return false, nil
		}
		ownership, ready, err := c.claimGenerationCleanupForArtifact(
			key, retained.ProcessIncarnation, retained.Reserved[0], func() (bool, error) {
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
	replayReady, replayErr := c.ensureStateAliasReplayFinal(ownership, key, state)
	if replayErr != nil {
		return false, fmt.Errorf("finalizing orphan-state alias replay: %w", replayErr)
	}
	if !replayReady {
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
