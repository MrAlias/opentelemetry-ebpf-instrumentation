// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javabridge // import "go.opentelemetry.io/obi/pkg/internal/javabridge"

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/ebpf/timing"
)

const (
	maxConsumedIdentities = 4096
	virtualThreadTIDFlag  = uint32(0x80000000)
)

type bridgeMap interface {
	Lookup(key, valueOut any) error
	Update(key, value any, flags ebpf.MapUpdateFlags) error
	Delete(key any) error
}

type MapHandler struct {
	remoteParents     bridgeMap
	tasks             bridgeMap
	virtualThreads    bridgeMap
	vtIdentities      bridgeMap
	authorized        bridgeMap
	incarnations      bridgeMap
	connections       bridgeMap
	cookieConnections bridgeMap
	ambiguity         bridgeMap
	owners            bridgeMap
	states            bridgeMap
	generations       bridgeMap
	terminals         bridgeMap
	claims            bridgeMap
	aliasReplays      bridgeMap
	ownerGuards       bridgeMap
	coordinator       *GenerationCoordinator
	ttl               time.Duration
	monoTimeNow       func() time.Duration
	consumedMu        sync.Mutex
	consumed          map[consumedIdentity]time.Duration
}

type Maps struct {
	RemoteParents                  *ebpf.Map
	Tasks                          *ebpf.Map
	VirtualThreads                 *ebpf.Map
	VTIdentities                   *ebpf.Map
	Authorized                     *ebpf.Map
	Incarnations                   *ebpf.Map
	Connections                    *ebpf.Map
	CookieConnections              *ebpf.Map
	Ambiguity                      *ebpf.Map
	Owners                         *ebpf.Map
	States                         *ebpf.Map
	Generations                    *ebpf.Map
	Terminals                      *ebpf.Map
	Claims                         *ebpf.Map
	AliasReplays                   *ebpf.Map
	OwnerGuards                    *ebpf.Map
	Handoffs                       *ebpf.Map
	HandoffClaims                  *ebpf.Map
	Retired                        *ebpf.Map
	SSLPrewriteTP                  *ebpf.Map
	SSLPrewriteConnectionAmbiguity *ebpf.Map
	SSLPrewriteConnectionClaims    *ebpf.Map
	SSLPrewriteConnectionOwners    *ebpf.Map
}

type stateKey struct {
	Owner      Identity
	Reserved   uint32
	Generation uint64
}

type aliasReplayKey struct {
	Owner               Identity
	Reserved            uint32
	Generation          uint64
	ObservedMonotonicNS uint64
	ProcessIncarnation  uint64
}

type aliasReplayValue struct {
	TransitionMonotonicNS uint64
	References            uint32
	Lifecycle             uint8
	DesiredLifecycle      uint8
	ProducerTag           uint8
	Reserved              uint8
}

type taskLink struct {
	Owner               Identity
	Reserved            uint32
	Generation          uint64
	ObservedMonotonicNS uint64
}

type connectionInfo struct {
	SourceAddress      [16]byte
	DestinationAddress [16]byte
	SourcePort         uint16
	DestinationPort    uint16
}

type connectionInfoNS struct {
	Connection connectionInfo
	NetNS      uint32
}

type connectionInfoNetNSCookie struct {
	Connection  connectionInfo
	Reserved    uint32
	NetNSCookie uint64
}

type virtualThreadIdentity struct {
	VirtualThreadID    uint64
	ProcessIncarnation uint64
}

type connectionClaim struct {
	Owner              Identity
	Reserved           uint32
	Generation         uint64
	NetNSCookie        uint64
	IncomingGeneration uint64
	SocketCookie       uint64
	NetNS              uint32
	Reserved2          uint32
}

type stateValue struct {
	Lifecycle           uint8
	Reserved            [3]byte
	Aliases             uint32
	ObservedMonotonicNS uint64
	Connection          connectionInfo
	ConnectionNetNS     uint32
	ProcessIncarnation  uint64
	Response            [RecordSize]byte
}

type generationIndexValue struct {
	Process             Identity
	Reserved            uint32
	ProcessIncarnation  uint64
	ObservedMonotonicNS uint64
}

type resolvedCandidate struct {
	Owner              Identity
	Generation         uint64
	ProcessIncarnation uint64
	Lifecycle          uint8
	StateOnly          bool
	ClaimOnly          bool
	TaskSource         Identity
	TaskLink           taskLink
	TaskState          stateValue
	TaskTerminal       terminalValue
	Encoded            [RecordSize]byte
}

type ownerValue struct {
	Generation         uint64
	ProcessIncarnation uint64
	Lifecycle          uint8
	Reserved           [7]byte
}

type terminalValue struct {
	Generation          uint64
	ObservedMonotonicNS uint64
	ProcessIncarnation  uint64
	Lifecycle           uint8
	Reserved            [7]byte
}

type generationClaim struct {
	ObservedMonotonicNS uint64
	ProcessIncarnation  uint64
	Lifecycle           uint8
	Reserved            [7]byte
}

type consumedIdentity struct {
	Identity           Identity
	ProcessIncarnation uint64
}

const (
	lifecycleActive     = uint8(1)
	lifecycleConsumed   = uint8(2)
	lifecycleDiscarded  = uint8(3)
	lifecycleStale      = uint8(4)
	lifecycleAmbiguous  = uint8(5)
	lifecyclePublishing = uint8(6)
	lifecycleCleanup    = uint8(7)
)

func NewMapHandler(
	maps Maps,
	ttl time.Duration,
	coordinator *GenerationCoordinator,
) *MapHandler {
	if coordinator == nil {
		panic("nil Java generation coordinator")
	}
	return &MapHandler{
		remoteParents:     maps.RemoteParents,
		tasks:             maps.Tasks,
		virtualThreads:    maps.VirtualThreads,
		vtIdentities:      maps.VTIdentities,
		authorized:        maps.Authorized,
		incarnations:      maps.Incarnations,
		connections:       maps.Connections,
		cookieConnections: maps.CookieConnections,
		ambiguity:         maps.Ambiguity,
		owners:            maps.Owners,
		states:            maps.States,
		generations:       maps.Generations,
		terminals:         maps.Terminals,
		claims:            maps.Claims,
		aliasReplays:      maps.AliasReplays,
		ownerGuards:       maps.OwnerGuards,
		coordinator:       coordinator,
		ttl:               ttl,
		monoTimeNow:       timing.MonoTimeNow,
		consumed:          make(map[consumedIdentity]time.Duration),
	}
}

func (h *MapHandler) Handle(identity Identity, operation Operation) Record {
	return h.handle(
		context.Background(), identity, operation, LookupSourceDirect, 0, false,
	)
}

func (h *MapHandler) HandleTask(identity Identity, operation Operation) Record {
	return h.handle(
		context.Background(), identity, operation, LookupSourceTask, 0, false,
	)
}

func (h *MapHandler) HandleAuthenticated(
	ctx context.Context,
	identity Identity,
	operation Operation,
	lookupSource LookupSource,
	expectedProcessIncarnation uint64,
) Record {
	return h.handle(
		ctx, identity, operation, lookupSource, expectedProcessIncarnation, true,
	)
}

func (h *MapHandler) handle(
	ctx context.Context,
	identity Identity,
	operation Operation,
	lookupSource LookupSource,
	expectedProcessIncarnation uint64,
	authenticated bool,
) Record {
	if requestCanceled(ctx) {
		return Record{Status: StatusTimeout}
	}
	if h.remoteParents == nil || h.tasks == nil || h.virtualThreads == nil || h.vtIdentities == nil || h.authorized == nil || h.incarnations == nil ||
		h.connections == nil || h.cookieConnections == nil || h.ambiguity == nil ||
		h.owners == nil || h.states == nil || h.generations == nil || h.terminals == nil ||
		h.claims == nil || h.aliasReplays == nil || h.ownerGuards == nil {
		return Record{Status: StatusUnsupported}
	}
	if operation != OperationTake && operation != OperationDiscard && operation != OperationNegotiate {
		return Record{Status: StatusMalformed}
	}
	if lookupSource != LookupSourceDirect && lookupSource != LookupSourceTask {
		return Record{Status: StatusMalformed}
	}
	if operation == OperationNegotiate {
		_, status := h.authorizeProcess(identity, expectedProcessIncarnation, authenticated)
		if status != StatusValid {
			return Record{Status: status}
		}
		return Record{Status: StatusMissing}
	}

	unlock, locked := h.coordinator.tryLockHandler()
	if !locked {
		// Cleanup owns the userspace generation state. Fail open immediately
		// instead of spending the transport deadline behind an RWMutex.
		return Record{Status: StatusTimeout}
	}
	defer unlock()
	if requestCanceled(ctx) {
		return Record{Status: StatusTimeout}
	}
	processIncarnation, status := h.authorizeProcess(
		identity, expectedProcessIncarnation, authenticated,
	)
	if status != StatusValid {
		return Record{Status: status}
	}

	translated, status := h.translateVirtualThread(identity, processIncarnation)
	if status != StatusValid {
		return Record{Status: status}
	}
	identity = translated

	var candidates []resolvedCandidate
	var ambiguous, lookupFailed bool
	if lookupSource == LookupSourceTask {
		candidates, ambiguous, lookupFailed = h.resolveTask(identity, processIncarnation)
	} else {
		candidates, ambiguous, lookupFailed = h.resolveDirect(identity, processIncarnation)
	}
	if requestCanceled(ctx) {
		return Record{Status: StatusTimeout}
	}
	if lookupFailed {
		return Record{Status: StatusTransportError}
	}
	if ambiguous || len(candidates) > 1 {
		if ambiguous && len(candidates) == 1 {
			claimedStatus, claimed, claimFailed := h.claimedCandidateStatus(candidates[0])
			if claimFailed {
				return Record{Status: StatusTransportError}
			}
			if claimed {
				if claimedStatus == StatusAlreadyConsumed {
					h.markConsumed(identity, processIncarnation)
					h.markConsumed(candidates[0].Owner, processIncarnation)
				}
				return Record{Status: claimedStatus}
			}
		}
		committed, consumedStatus, consumeErr := h.consume(
			ctx, candidates, lifecycleAmbiguous,
		)
		if consumeErr != nil {
			return Record{Status: StatusTransportError}
		}
		if consumedStatus != StatusUnknown {
			if consumedStatus == StatusAlreadyConsumed {
				h.markConsumed(identity, processIncarnation)
				if len(candidates) == 1 {
					h.markConsumed(candidates[0].Owner, processIncarnation)
				}
			}
			return Record{Status: consumedStatus}
		}
		if !committed && requestCanceled(ctx) {
			return Record{Status: StatusTimeout}
		}
		if committed {
			h.markConsumed(identity, processIncarnation)
		}
		return Record{Status: StatusAmbiguous}
	}
	if len(candidates) == 0 {
		if h.wasConsumed(identity, processIncarnation) {
			return Record{Status: StatusAlreadyConsumed}
		}
		return Record{Status: StatusMissing}
	}

	candidate := candidates[0]
	owner := candidate.Owner
	if candidate.ClaimOnly {
		claimedStatus, claimed, claimFailed := h.claimedCandidateStatus(candidate)
		if claimFailed {
			return Record{Status: StatusTransportError}
		}
		if claimed {
			if claimedStatus == StatusAlreadyConsumed {
				h.markConsumed(identity, processIncarnation)
				h.markConsumed(owner, processIncarnation)
			}
			return Record{Status: claimedStatus}
		}
		if h.wasConsumed(identity, processIncarnation) {
			return Record{Status: StatusAlreadyConsumed}
		}
		return Record{Status: StatusMissing}
	}
	if candidate.Lifecycle != 0 {
		if status := h.candidateTaskAuthorityStatus(candidate); status != StatusValid {
			return Record{Status: status}
		}
		claimedStatus, claimed, claimFailed := h.claimedCandidateStatus(candidate)
		if claimFailed {
			return Record{Status: StatusTransportError}
		}
		if claimed {
			if claimedStatus == StatusAlreadyConsumed {
				h.markConsumed(identity, processIncarnation)
				h.markConsumed(owner, processIncarnation)
			}
			return Record{Status: claimedStatus}
		}
		return Record{Status: statusForLifecycle(candidate.Lifecycle)}
	}
	encoded, status := h.readCandidate(candidate)
	if status != StatusValid {
		// The task may have been rebound while the exact generation payload was
		// read. A missing old payload is authoritative only while the same task
		// link still names it; otherwise report the authority race, not a
		// terminal outcome for the successor execution.
		if authorityStatus := h.candidateTaskAuthorityStatus(candidate); authorityStatus != StatusValid {
			return Record{Status: authorityStatus}
		}
		return Record{Status: status}
	}

	record, err := UnmarshalRecord(encoded[:])
	if err != nil {
		if candidate.StateOnly {
			// A task-linked state snapshot can become malformed after resolution.
			// Quarantine only that exact generation: owner-scoped fallback cleanup
			// could otherwise select and tear down a legitimate successor.
			if authorityStatus := h.candidateTaskAuthorityStatus(candidate); authorityStatus != StatusValid {
				return Record{Status: authorityStatus}
			}
			if requestCanceled(ctx) {
				return Record{Status: StatusTimeout}
			}
			committed := false
			if now := h.monoTimeNow(); now > 0 {
				_, promoteErr := promoteGenerationAmbiguity(
					h.ambiguity,
					stateKey{Owner: candidate.Owner, Generation: candidate.Generation},
					uint64(now),
				)
				committed = promoteErr == nil
			}
			if authorityStatus := h.candidateTaskAuthorityStatus(candidate); authorityStatus != StatusValid {
				return Record{Status: authorityStatus}
			}
			if !committed && requestCanceled(ctx) {
				return Record{Status: StatusTimeout}
			}
			if errors.Is(err, ErrVersionMismatch) {
				return Record{Status: StatusVersionMismatch}
			}
			return Record{Status: StatusMalformed}
		}
		if errors.Is(err, ErrVersionMismatch) {
			return Record{Status: StatusVersionMismatch}
		}
		return Record{Status: StatusMalformed}
	}
	if record.Status != StatusValid {
		committed, consumedStatus, consumeErr := h.consume(
			ctx, []resolvedCandidate{candidate}, lifecycleForStatus(record.Status),
		)
		if consumeErr != nil {
			return Record{Status: StatusTransportError}
		}
		if consumedStatus != StatusUnknown {
			return Record{Status: consumedStatus}
		}
		if !committed && requestCanceled(ctx) {
			return Record{Status: StatusTimeout}
		}
		return Record{Status: record.Status}
	}
	if !record.IsValidRemoteParent() {
		committed, consumedStatus, consumeErr := h.consume(
			ctx, []resolvedCandidate{candidate}, lifecycleDiscarded,
		)
		if consumeErr != nil {
			return Record{Status: StatusTransportError}
		}
		if consumedStatus != StatusUnknown {
			return Record{Status: consumedStatus}
		}
		if !committed && requestCanceled(ctx) {
			return Record{Status: StatusTimeout}
		}
		return Record{Status: StatusMalformed}
	}
	if candidate.Generation == 0 {
		return Record{Status: StatusAmbiguous}
	}
	if record.Generation != candidate.Generation {
		return Record{Status: StatusStale}
	}
	if _, _, status := h.validatePublishedGeneration(
		candidate, record, encoded, StatusMissing, false,
	); status != StatusValid {
		return Record{Status: status}
	}

	lifecycle := lifecycleConsumed
	if operation == OperationDiscard {
		lifecycle = lifecycleDiscarded
	}
	key := stateKey{Owner: owner, Generation: record.Generation}
	if requestCanceled(ctx) {
		return Record{Status: StatusTimeout}
	}
	guarded, guardErr := ownerDetachGuardPresent(h.ownerGuards, owner)
	if guardErr != nil {
		return Record{Status: StatusTransportError}
	}
	if guarded {
		if status := h.candidateTaskAuthorityStatus(candidate); status != StatusValid {
			return Record{Status: status}
		}
		return Record{Status: StatusOverload}
	}
	if requestCanceled(ctx) {
		return Record{Status: StatusTimeout}
	}
	if status := h.candidateTaskAuthorityStatus(candidate); status != StatusValid {
		return Record{Status: status}
	}
	if requestCanceled(ctx) {
		return Record{Status: StatusTimeout}
	}
	preclaimState, _, status := h.validatePublishedGeneration(
		candidate, record, encoded, StatusMissing, false,
	)
	if status != StatusValid {
		return Record{Status: status}
	}
	now := h.monoTimeNow()
	if now <= 0 || preclaimState.ObservedMonotonicNS == 0 ||
		uint64(now) < preclaimState.ObservedMonotonicNS {
		return Record{Status: StatusTransportError}
	}
	if time.Duration(uint64(now)-preclaimState.ObservedMonotonicNS) > h.ttl {
		lifecycle = lifecycleStale
	}
	replayTransition, status := h.activeAliasReplay(candidate, key, preclaimState)
	if status != StatusValid {
		return Record{Status: status}
	}
	if status := h.candidateTaskAuthorityStatus(candidate); status != StatusValid {
		return Record{Status: status}
	}
	if requestCanceled(ctx) {
		return Record{Status: StatusTimeout}
	}
	claim, ok := h.newGenerationClaim(lifecycle, processIncarnation)
	if !ok {
		return Record{Status: StatusTransportError}
	}
	// E first publishes a reversible reservation. Only the exact promotion to
	// the target lifecycle below commits the one-shot operation.
	if err := h.claims.Update(&key, &claim, ebpf.UpdateNoExist); err != nil {
		if errors.Is(err, ebpf.ErrKeyExist) {
			claimedStatus, claimed, claimErr := h.existingGenerationClaimStatus(candidate)
			if claimErr != nil {
				return Record{Status: StatusTransportError}
			}
			if !claimed {
				return Record{Status: StatusOverload}
			}
			if claimedStatus == StatusAlreadyConsumed {
				h.markConsumed(identity, processIncarnation)
				h.markConsumed(owner, processIncarnation)
			}
			return Record{Status: claimedStatus}
		}
		if requestCanceled(ctx) {
			return Record{Status: StatusTimeout}
		}
		return Record{Status: StatusTransportError}
	}
	ownedClaim := claim
	claimCommitted := false
	rollbackAllowed := true
	defer func() {
		if !claimCommitted {
			if rollbackAllowed && h.rollbackPublishingClaim(
				key, &ownedClaim, replayTransition,
			) {
				return
			}
			_ = h.retainLocalClaim(key)
		}
		_ = handoffGenerationProducerFencePair(
			h.claims, h.ownerGuards, key, &ownedClaim, nil, h.monoTimeNow,
		)
	}()
	guarded, guardErr = ownerDetachGuardPresent(h.ownerGuards, owner)
	if guardErr != nil {
		rollbackAllowed = false
		return Record{Status: StatusTransportError}
	}
	if guarded {
		if status := h.candidateTaskAuthorityStatus(candidate); status != StatusValid {
			return Record{Status: status}
		}
		return Record{Status: StatusOverload}
	}
	if status := h.publishAliasReplayTransition(
		replayTransition, ownedClaim, lifecycle,
	); status != StatusValid {
		rollbackAllowed = false
		return Record{Status: status}
	}

	state, claimedRecord, status := h.validatePublishedGeneration(
		candidate, record, encoded, StatusAlreadyConsumed, false,
	)
	if status != StatusValid {
		if linkStatus := h.candidateTaskLinkStatus(candidate); linkStatus == StatusValid ||
			linkStatus == StatusTransportError {
			rollbackAllowed = false
		}
		return Record{Status: status}
	}
	if replayTransition == nil && state.Aliases > 0 {
		replayTransition, status = h.activeAliasReplay(candidate, key, state)
		if status != StatusValid {
			rollbackAllowed = false
			return Record{Status: status}
		}
		if status = h.publishAliasReplayTransition(
			replayTransition, ownedClaim, lifecycle,
		); status != StatusValid {
			rollbackAllowed = false
			return Record{Status: status}
		}
	}
	if replayTransition != nil {
		if aliasReplayKeyForState(key, state) != replayTransition.key {
			rollbackAllowed = false
			return Record{Status: StatusAmbiguous}
		}
		if status = h.revalidateAliasReplayTransition(replayTransition); status != StatusValid {
			rollbackAllowed = false
			return Record{Status: status}
		}
	}
	guarded, guardErr = ownerDetachGuardPresent(h.ownerGuards, owner)
	if guardErr != nil {
		rollbackAllowed = false
		return Record{Status: StatusTransportError}
	}
	if guarded {
		return Record{Status: StatusOverload}
	}
	if status = h.candidateTaskAuthorityStatus(candidate); status != StatusValid {
		if linkStatus := h.candidateTaskLinkStatus(candidate); linkStatus == StatusValid ||
			linkStatus == StatusTransportError {
			rollbackAllowed = false
		}
		return Record{Status: status}
	}
	if lifecycle != lifecycleStale {
		now = h.monoTimeNow()
		if now <= 0 || state.ObservedMonotonicNS == 0 ||
			uint64(now) < state.ObservedMonotonicNS {
			rollbackAllowed = false
			return Record{Status: StatusTransportError}
		}
		if time.Duration(uint64(now)-state.ObservedMonotonicNS) > h.ttl {
			if status = h.retargetPublishingClaimStale(
				key, &ownedClaim, replayTransition,
			); status != StatusValid {
				rollbackAllowed = false
				return Record{Status: status}
			}
			lifecycle = lifecycleStale
		}
	}
	if status = h.promoteGenerationClaim(key, &ownedClaim); status != StatusValid {
		rollbackAllowed = false
		return Record{Status: status}
	}
	claimCommitted = true
	record = claimedRecord
	h.markConsumed(identity, processIncarnation)
	h.markConsumed(owner, processIncarnation)

	if lifecycle == lifecycleStale {
		h.finishClaimedResult(
			owner, record, processIncarnation, lifecycleStale, &ownedClaim,
		)
		return Record{Status: StatusStale}
	}
	// The exact claim commits one-shot delivery. Cleanup is best-effort after
	// the validated response has been copied: an incomplete finish retains its
	// claim, ambiguity marker, and owner guard for the coordinated sweeper.
	h.finishClaimedResult(
		owner, record, processIncarnation, lifecycle, &ownedClaim,
	)
	if operation == OperationDiscard {
		return Record{Status: StatusMissing}
	}

	return record
}

func (h *MapHandler) readCandidate(candidate resolvedCandidate) ([RecordSize]byte, Status) {
	if candidate.StateOnly {
		key := stateKey{Owner: candidate.Owner, Generation: candidate.Generation}
		var state stateValue
		if err := h.states.Lookup(&key, &state); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return [RecordSize]byte{}, StatusAlreadyConsumed
			}
			return [RecordSize]byte{}, StatusTransportError
		}
		return state.Response, StatusValid
	}

	var encoded [RecordSize]byte
	if err := h.remoteParents.Lookup(&candidate.Owner, &encoded); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return [RecordSize]byte{}, StatusAlreadyConsumed
		}
		return [RecordSize]byte{}, StatusTransportError
	}
	return encoded, StatusValid
}

func (h *MapHandler) validatePublishedGeneration(
	candidate resolvedCandidate,
	record Record,
	encoded [RecordSize]byte,
	ownerMissingStatus Status,
	allowAmbiguous bool,
) (validatedState stateValue, validatedRecord Record, resultStatus Status) {
	if status := h.candidateTaskAuthorityStatus(candidate); status != StatusValid {
		return stateValue{}, Record{}, status
	}
	defer func() {
		if status := h.candidateTaskAuthorityStatus(candidate); status != StatusValid {
			validatedState = stateValue{}
			validatedRecord = Record{}
			resultStatus = status
		}
	}()
	owner := candidate.Owner
	processIncarnation := candidate.ProcessIncarnation
	stateOnly := candidate.StateOnly
	if current, status := h.processIncarnation(owner); status != StatusValid {
		return stateValue{}, Record{}, status
	} else if current != processIncarnation {
		return stateValue{}, Record{}, StatusAmbiguous
	}

	if !stateOnly {
		var indexed ownerValue
		if err := h.owners.Lookup(&owner, &indexed); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return stateValue{}, Record{}, ownerMissingStatus
			}
			return stateValue{}, Record{}, StatusTransportError
		}
		if indexed.Generation != record.Generation || indexed.Reserved != ([7]byte{}) {
			return stateValue{}, Record{}, StatusAlreadyConsumed
		}
		if indexed.ProcessIncarnation != processIncarnation {
			return stateValue{}, Record{}, StatusAmbiguous
		}
		if indexed.Lifecycle == lifecyclePublishing {
			return stateValue{}, Record{}, ownerMissingStatus
		}
		if indexed.Lifecycle != lifecycleActive {
			return stateValue{}, Record{}, StatusAlreadyConsumed
		}
	}

	key := stateKey{Owner: owner, Generation: record.Generation}
	var state stateValue
	if err := h.states.Lookup(&key, &state); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return stateValue{}, Record{}, StatusMissing
		}
		return stateValue{}, Record{}, StatusTransportError
	}
	if state.Lifecycle != lifecycleActive ||
		state.ProcessIncarnation != processIncarnation ||
		state.Reserved != ([3]byte{}) ||
		(stateOnly && state.Aliases == 0) ||
		state.ObservedMonotonicNS == 0 || state.ConnectionNetNS == 0 ||
		!validGenerationConnection(state.Connection) {
		return stateValue{}, Record{}, StatusAmbiguous
	}

	var generationIndex generationIndexValue
	if err := h.generations.Lookup(&key, &generationIndex); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return stateValue{}, Record{}, StatusMissing
		}
		return stateValue{}, Record{}, StatusTransportError
	}
	if generationIndex.Process != javaProcessIdentity(owner) || generationIndex.Reserved != 0 ||
		generationIndex.ProcessIncarnation != processIncarnation ||
		generationIndex.ObservedMonotonicNS != state.ObservedMonotonicNS {
		return stateValue{}, Record{}, StatusAmbiguous
	}

	var markedAt uint64
	if err := h.ambiguity.Lookup(&key, &markedAt); err == nil {
		if markedAt != 0 && !allowAmbiguous {
			return stateValue{}, Record{}, StatusAmbiguous
		}
	} else if errors.Is(err, ebpf.ErrKeyNotExist) {
		// Active and detached generations are valid only while their exact
		// zero-valued reservation remains present.
		return stateValue{}, Record{}, StatusAmbiguous
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return stateValue{}, Record{}, StatusTransportError
	}

	var connection connectionClaim
	connectionKey := connectionInfoNS{
		Connection: state.Connection,
		NetNS:      state.ConnectionNetNS,
	}
	connectionErr := h.connections.Lookup(&connectionKey, &connection)
	physicalDetached := false
	if connectionErr != nil && !errors.Is(connectionErr, ebpf.ErrKeyNotExist) {
		return stateValue{}, Record{}, StatusTransportError
	}
	if connectionErr != nil ||
		!validConnectionClaim(connection, owner, record.Generation, state.ConnectionNetNS) {
		if !stateOnly {
			return stateValue{}, Record{}, StatusAmbiguous
		}
		if connectionErr == nil && connection.Owner == owner &&
			connection.Generation == record.Generation {
			// RESET-detached state has no exact netns cursor. A malformed
			// cursor that still names this generation is corruption, not proof
			// that the physical indexes were detached.
			return stateValue{}, Record{}, StatusAmbiguous
		}
		var detachedStatus Status
		physicalDetached, detachedStatus = h.detachedTaskGeneration(key, state)
		if !physicalDetached {
			return stateValue{}, Record{}, detachedStatus
		}
	}
	if !physicalDetached {
		var cookieConnection connectionClaim
		if err := h.cookieConnections.Lookup(
			&connectionInfoNetNSCookie{
				Connection:  state.Connection,
				NetNSCookie: connection.NetNSCookie,
			},
			&cookieConnection,
		); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return stateValue{}, Record{}, StatusAmbiguous
			}
			return stateValue{}, Record{}, StatusTransportError
		}
		if cookieConnection != connection {
			return stateValue{}, Record{}, StatusAmbiguous
		}
	}

	claimed := state.Response
	if !stateOnly {
		if err := h.remoteParents.Lookup(&owner, &claimed); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return stateValue{}, Record{}, StatusAmbiguous
			}
			return stateValue{}, Record{}, StatusTransportError
		}
	}
	claimedRecord, err := UnmarshalRecord(claimed[:])
	if err != nil || claimed != encoded || claimed != state.Response ||
		claimedRecord.Generation != record.Generation ||
		claimedRecord.ObservedMonotonicNS != state.ObservedMonotonicNS ||
		!claimedRecord.IsValidRemoteParent() {
		return stateValue{}, Record{}, StatusAmbiguous
	}

	return state, claimedRecord, StatusValid
}

func (h *MapHandler) detachedTaskGeneration(
	key stateKey,
	state stateValue,
) (bool, Status) {
	if state.Aliases == 0 {
		return false, StatusAmbiguous
	}
	var owner ownerValue
	if err := h.owners.Lookup(&key.Owner, &owner); err == nil {
		if owner.Generation == key.Generation {
			return false, StatusAmbiguous
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, StatusTransportError
	}
	var fallback [RecordSize]byte
	if err := h.remoteParents.Lookup(&key.Owner, &fallback); err == nil {
		record, decodeErr := UnmarshalRecord(fallback[:])
		if decodeErr != nil || record.Generation == key.Generation {
			return false, StatusAmbiguous
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, StatusTransportError
	}
	var terminal terminalValue
	if err := h.terminals.Lookup(&key.Owner, &terminal); err == nil {
		if terminal.Generation == key.Generation {
			return false, StatusAlreadyConsumed
		}
		if !validTerminalValue(terminal) {
			return false, StatusAmbiguous
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false, StatusTransportError
	}
	return true, StatusValid
}

func (h *MapHandler) markConsumed(identity Identity, processIncarnation uint64) {
	now := h.monoTimeNow()
	if now <= 0 {
		return
	}

	h.consumedMu.Lock()
	defer h.consumedMu.Unlock()
	if h.consumed == nil {
		h.consumed = make(map[consumedIdentity]time.Duration)
	}
	if len(h.consumed) >= maxConsumedIdentities {
		for existing, consumedAt := range h.consumed {
			if now-consumedAt > h.ttl {
				delete(h.consumed, existing)
			}
		}
	}
	if len(h.consumed) >= maxConsumedIdentities {
		for existing := range h.consumed {
			delete(h.consumed, existing)
			break
		}
	}
	h.consumed[consumedIdentity{
		Identity:           identity,
		ProcessIncarnation: processIncarnation,
	}] = now
}

func (h *MapHandler) wasConsumed(identity Identity, processIncarnation uint64) bool {
	now := h.monoTimeNow()
	if now <= 0 {
		return false
	}

	h.consumedMu.Lock()
	defer h.consumedMu.Unlock()
	key := consumedIdentity{
		Identity:           identity,
		ProcessIncarnation: processIncarnation,
	}
	consumedAt, ok := h.consumed[key]
	if !ok {
		return false
	}
	if now-consumedAt > h.ttl {
		delete(h.consumed, key)
		return false
	}

	return true
}

func (h *MapHandler) resolveDirect(
	start Identity, processIncarnation uint64,
) ([]resolvedCandidate, bool, bool) {
	candidates := make([]resolvedCandidate, 0, 1)
	direct, directFound, lookupFailed := h.resolveOwner(
		start, 0, processIncarnation, true,
	)
	if lookupFailed {
		return nil, false, true
	}
	if directFound {
		candidates = append(candidates, direct)
		marked, failed := h.generationAmbiguous(direct)
		if failed {
			return nil, false, true
		}
		if marked {
			return candidates, true, false
		}
	}
	return candidates, false, false
}

func (h *MapHandler) resolveTask(
	start Identity, processIncarnation uint64,
) ([]resolvedCandidate, bool, bool) {
	var link taskLink
	if err := h.tasks.Lookup(&start, &link); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, false, false
		}
		return nil, false, true
	}
	current, expired := h.taskLinkFreshness(link)
	if !current && !expired {
		return nil, false, false
	}
	if expired {
		// An expired link can no longer authorize parent delivery. Preserve only
		// its exact identity long enough to consult the generation claim and
		// composite-key alias replay, both of which are revalidated against the
		// current task-map value before returning a terminal result.
		return []resolvedCandidate{{
			Owner:              link.Owner,
			Generation:         link.Generation,
			ProcessIncarnation: processIncarnation,
			ClaimOnly:          true,
			TaskSource:         start,
			TaskLink:           link,
		}}, false, false
	}
	linked, found, failed := h.resolveOwner(
		link.Owner, link.Generation, processIncarnation, true,
	)
	if failed {
		return nil, false, true
	}
	if !found {
		var current taskLink
		if err := h.tasks.Lookup(&start, &current); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return nil, true, false
			}
			return nil, false, true
		}
		if current != link {
			return nil, true, false
		}
		return []resolvedCandidate{{
			Owner:              link.Owner,
			Generation:         link.Generation,
			ProcessIncarnation: processIncarnation,
			ClaimOnly:          true,
			TaskSource:         start,
			TaskLink:           link,
		}}, false, false
	}
	if found {
		linked.TaskSource = start
		linked.TaskLink = link
		if linked.ClaimOnly {
			return []resolvedCandidate{linked}, false, false
		}
		matches, observationFailed := h.taskLinkObservationMatches(link, linked)
		if observationFailed {
			return nil, false, true
		}
		if !matches {
			return nil, true, false
		}
	}
	marked, lookupFailed := h.generationAmbiguous(linked)
	if lookupFailed {
		return nil, false, true
	}
	ambiguous := marked
	candidates := make([]resolvedCandidate, 0, 1)
	if found {
		candidates = append(candidates, linked)
	}

	return candidates, ambiguous, false
}

func (h *MapHandler) taskLinkObservationMatches(
	link taskLink,
	candidate resolvedCandidate,
) (bool, bool) {
	if candidate.StateOnly {
		var state stateValue
		key := stateKey{Owner: candidate.Owner, Generation: candidate.Generation}
		if err := h.states.Lookup(&key, &state); err != nil {
			return false, !errors.Is(err, ebpf.ErrKeyNotExist)
		}
		expected := candidate.TaskState
		if state.Aliases == 0 || expected.Aliases == 0 {
			return false, false
		}
		// Sibling task publication and release may legitimately change only the
		// alias count while this exact task link remains authoritative.
		state.Aliases = 0
		expected.Aliases = 0
		return state == expected &&
			state.ObservedMonotonicNS == link.ObservedMonotonicNS, false
	}
	if candidate.Lifecycle != 0 {
		var terminal terminalValue
		if err := h.terminals.Lookup(&candidate.Owner, &terminal); err != nil {
			return false, !errors.Is(err, ebpf.ErrKeyNotExist)
		}
		return terminal == candidate.TaskTerminal &&
			terminal.Generation == candidate.Generation &&
			terminal.ObservedMonotonicNS == link.ObservedMonotonicNS, false
	}
	record, err := UnmarshalRecord(candidate.Encoded[:])
	return err == nil && record.ObservedMonotonicNS == link.ObservedMonotonicNS, false
}

func (h *MapHandler) candidateTaskAuthorityStatus(candidate resolvedCandidate) Status {
	if status := h.candidateTaskLinkStatus(candidate); status != StatusValid {
		return status
	}
	if candidate.ClaimOnly || candidate.TaskLink.Generation == 0 {
		return StatusValid
	}
	matches, lookupFailed := h.taskLinkObservationMatches(candidate.TaskLink, candidate)
	if lookupFailed {
		return StatusTransportError
	}
	if !matches {
		return StatusAmbiguous
	}
	return StatusValid
}

func (h *MapHandler) candidateTaskLinkStatus(candidate resolvedCandidate) Status {
	if candidate.TaskLink.Generation == 0 {
		return StatusValid
	}
	if candidate.TaskSource == (Identity{}) ||
		candidate.TaskLink.Owner != candidate.Owner ||
		candidate.TaskLink.Generation != candidate.Generation ||
		candidate.TaskLink.Reserved != 0 {
		return StatusAmbiguous
	}
	var current taskLink
	if err := h.tasks.Lookup(&candidate.TaskSource, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return StatusAmbiguous
		}
		return StatusTransportError
	}
	if current != candidate.TaskLink {
		return StatusAmbiguous
	}
	return StatusValid
}

func (h *MapHandler) resolveOwner(
	owner Identity,
	expectedGeneration uint64,
	processIncarnation uint64,
	includeTerminal bool,
) (resolvedCandidate, bool, bool) {
	if expectedGeneration != 0 {
		return h.resolveTaskGeneration(
			owner, expectedGeneration, processIncarnation, includeTerminal,
		)
	}

	var encoded [RecordSize]byte
	if err := h.remoteParents.Lookup(&owner, &encoded); err == nil {
		generation := uint64(0)
		if record, decodeErr := UnmarshalRecord(encoded[:]); decodeErr == nil {
			generation = record.Generation
		}
		return resolvedCandidate{
			Owner:              owner,
			Generation:         generation,
			ProcessIncarnation: processIncarnation,
			Encoded:            encoded,
		}, true, false
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return resolvedCandidate{}, false, true
	}
	if !includeTerminal {
		return resolvedCandidate{}, false, false
	}

	var terminal terminalValue
	if err := h.terminals.Lookup(&owner, &terminal); err != nil {
		return resolvedCandidate{}, false, !errors.Is(err, ebpf.ErrKeyNotExist)
	}
	if terminal.Generation == 0 || terminal.Reserved != ([7]byte{}) ||
		(expectedGeneration != 0 && terminal.Generation != expectedGeneration) {
		return resolvedCandidate{}, false, false
	}
	if terminal.ProcessIncarnation != processIncarnation {
		return resolvedCandidate{
			Owner:              owner,
			Generation:         terminal.Generation,
			ProcessIncarnation: processIncarnation,
			Lifecycle:          lifecycleAmbiguous,
		}, true, false
	}
	return resolvedCandidate{
		Owner:              owner,
		Generation:         terminal.Generation,
		ProcessIncarnation: processIncarnation,
		Lifecycle:          terminal.Lifecycle,
	}, true, false
}

func (h *MapHandler) resolveTaskGeneration(
	owner Identity,
	expectedGeneration uint64,
	processIncarnation uint64,
	includeTerminal bool,
) (resolvedCandidate, bool, bool) {
	key := stateKey{Owner: owner, Generation: expectedGeneration}
	var state stateValue
	if err := h.states.Lookup(&key, &state); err == nil {
		if state.Lifecycle != lifecycleActive || state.Reserved != ([3]byte{}) ||
			state.Aliases == 0 || state.ProcessIncarnation != processIncarnation ||
			state.ObservedMonotonicNS == 0 {
			return resolvedCandidate{
				Owner:              owner,
				Generation:         expectedGeneration,
				ProcessIncarnation: processIncarnation,
				Lifecycle:          lifecycleAmbiguous,
			}, true, false
		}
		record, decodeErr := UnmarshalRecord(state.Response[:])
		if decodeErr != nil || record.Generation != expectedGeneration ||
			record.ObservedMonotonicNS != state.ObservedMonotonicNS ||
			!record.IsValidRemoteParent() {
			return resolvedCandidate{
				Owner:              owner,
				Generation:         expectedGeneration,
				ProcessIncarnation: processIncarnation,
				Lifecycle:          lifecycleAmbiguous,
			}, true, false
		}
		return resolvedCandidate{
			Owner:              owner,
			Generation:         expectedGeneration,
			ProcessIncarnation: processIncarnation,
			StateOnly:          true,
			TaskState:          state,
			Encoded:            state.Response,
		}, true, false
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return resolvedCandidate{}, false, true
	}
	if !includeTerminal {
		return resolvedCandidate{}, false, false
	}

	var terminal terminalValue
	if err := h.terminals.Lookup(&owner, &terminal); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return resolvedCandidate{
				Owner:              owner,
				Generation:         expectedGeneration,
				ProcessIncarnation: processIncarnation,
				ClaimOnly:          true,
			}, true, false
		}
		return resolvedCandidate{}, false, true
	}
	if terminal.Generation != expectedGeneration {
		return resolvedCandidate{
			Owner:              owner,
			Generation:         expectedGeneration,
			ProcessIncarnation: processIncarnation,
			ClaimOnly:          true,
		}, true, false
	}
	if !validTerminalValue(terminal) {
		return resolvedCandidate{
			Owner:              owner,
			Generation:         expectedGeneration,
			ProcessIncarnation: processIncarnation,
			ClaimOnly:          true,
		}, true, false
	}
	if terminal.ProcessIncarnation != processIncarnation {
		return resolvedCandidate{
			Owner:              owner,
			Generation:         terminal.Generation,
			ProcessIncarnation: processIncarnation,
			Lifecycle:          lifecycleAmbiguous,
			TaskTerminal:       terminal,
		}, true, false
	}
	return resolvedCandidate{
		Owner:              owner,
		Generation:         terminal.Generation,
		ProcessIncarnation: processIncarnation,
		Lifecycle:          terminal.Lifecycle,
		TaskTerminal:       terminal,
	}, true, false
}

func (h *MapHandler) generationAmbiguous(candidate resolvedCandidate) (bool, bool) {
	if candidate.Generation == 0 {
		return false, false
	}
	key := stateKey{Owner: candidate.Owner, Generation: candidate.Generation}
	var markedAt uint64
	if err := h.ambiguity.Lookup(&key, &markedAt); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, true
		}
		// Live state without its exact reservation is structurally ambiguous;
		// terminal-only state is complete only after the reservation is absent.
		return candidate.Lifecycle == 0, false
	}
	if candidate.Lifecycle == 0 {
		return markedAt != 0, false
	}
	return true, false
}

func (h *MapHandler) markAmbiguous(candidate resolvedCandidate) bool {
	if candidate.Generation == 0 {
		return true
	}
	now := h.monoTimeNow()
	if now <= 0 {
		return false
	}
	markedAt := uint64(now)
	key := stateKey{Owner: candidate.Owner, Generation: candidate.Generation}
	var current uint64
	if err := h.ambiguity.Lookup(&key, &current); err == nil {
		if current != 0 {
			return true
		}
		_ = h.ambiguity.Update(&key, &markedAt, ebpf.UpdateExist)
	} else if errors.Is(err, ebpf.ErrKeyNotExist) {
		_ = h.ambiguity.Update(&key, &markedAt, ebpf.UpdateNoExist)
	} else {
		return false
	}
	return h.ambiguity.Lookup(&key, &current) == nil && current != 0
}

func (h *MapHandler) authorizeProcess(
	identity Identity,
	expectedProcessIncarnation uint64,
	authenticated bool,
) (uint64, Status) {
	processCapability, status := h.processCapability(identity)
	if status != StatusValid {
		return 0, StatusUnauthorized
	}
	processIncarnation, status := h.processIncarnation(identity)
	if status != StatusValid {
		if authenticated {
			return 0, StatusUnauthorized
		}
		return 0, status
	}
	if processIncarnation != processCapability ||
		(authenticated && (expectedProcessIncarnation == 0 || processCapability != expectedProcessIncarnation)) {
		return 0, StatusUnauthorized
	}
	return processIncarnation, StatusValid
}

func (h *MapHandler) processIncarnation(identity Identity) (uint64, Status) {
	process := javaProcessIdentity(identity)
	var incarnation uint64
	if err := h.incarnations.Lookup(&process, &incarnation); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, StatusMissing
		}
		return 0, StatusTransportError
	}
	if incarnation == 0 {
		return 0, StatusAmbiguous
	}
	return incarnation, StatusValid
}

func (h *MapHandler) processCapability(identity Identity) (uint64, Status) {
	process := javaProcessIdentity(identity)
	var capability uint64
	if err := h.authorized.Lookup(&process, &capability); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, StatusMissing
		}
		return 0, StatusTransportError
	}
	if capability == 0 {
		return 0, StatusUnauthorized
	}
	return capability, StatusValid
}

func (h *MapHandler) translateVirtualThread(
	identity Identity,
	processIncarnation uint64,
) (Identity, Status) {
	var mounted virtualThreadIdentity
	if err := h.virtualThreads.Lookup(&identity, &mounted); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return identity, StatusValid
		}
		return Identity{}, StatusTransportError
	}
	if mounted.VirtualThreadID == 0 || mounted.ProcessIncarnation == 0 {
		return Identity{}, StatusAmbiguous
	}

	if processIncarnation != mounted.ProcessIncarnation {
		return Identity{}, StatusAmbiguous
	}

	translated := javaVirtualThreadOwner(identity, mounted.VirtualThreadID)
	var registered virtualThreadIdentity
	if err := h.vtIdentities.Lookup(&translated, &registered); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return Identity{}, StatusMissing
		}
		return Identity{}, StatusTransportError
	}
	if registered != mounted {
		return Identity{}, StatusAmbiguous
	}

	var revalidatedMount virtualThreadIdentity
	if err := h.virtualThreads.Lookup(&identity, &revalidatedMount); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return Identity{}, StatusMissing
		}
		return Identity{}, StatusTransportError
	}
	if revalidatedMount != mounted {
		return Identity{}, StatusAmbiguous
	}
	revalidatedIncarnation, status := h.processIncarnation(identity)
	if status != StatusValid {
		return Identity{}, status
	}
	if revalidatedIncarnation != processIncarnation {
		return Identity{}, StatusAmbiguous
	}
	var revalidatedIdentity virtualThreadIdentity
	if err := h.vtIdentities.Lookup(&translated, &revalidatedIdentity); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return Identity{}, StatusMissing
		}
		return Identity{}, StatusTransportError
	}
	if revalidatedIdentity != registered {
		return Identity{}, StatusAmbiguous
	}

	return translated, StatusValid
}

func javaProcessIdentity(identity Identity) Identity {
	identity.TID = identity.PID
	return identity
}

func javaVirtualThreadOwner(carrier Identity, virtualThreadID uint64) Identity {
	carrier.TID = virtualThreadTIDFlag |
		(uint32(virtualThreadID) &^ virtualThreadTIDFlag)
	return carrier
}

func (h *MapHandler) taskLinkFreshness(link taskLink) (current, expired bool) {
	now := h.monoTimeNow()
	if now <= 0 || link.Owner == (Identity{}) || link.Reserved != 0 ||
		link.Generation == 0 || link.ObservedMonotonicNS == 0 ||
		uint64(now) < link.ObservedMonotonicNS {
		return false, false
	}
	if time.Duration(uint64(now)-link.ObservedMonotonicNS) > h.ttl {
		return false, true
	}
	return true, false
}

func (h *MapHandler) consume(
	ctx context.Context,
	candidates []resolvedCandidate,
	lifecycle uint8,
) (bool, Status, error) {
	committed := false
	for _, candidate := range candidates {
		if !committed && requestCanceled(ctx) {
			return false, StatusUnknown, nil
		}
		if candidate.ProcessIncarnation == 0 {
			continue
		}
		encoded := candidate.Encoded
		record, err := UnmarshalRecord(encoded[:])
		if err != nil {
			continue
		}
		if candidate.Generation == 0 || record.Generation != candidate.Generation {
			continue
		}
		if _, _, status := h.validatePublishedGeneration(
			candidate,
			record,
			encoded,
			StatusMissing,
			true,
		); status != StatusValid {
			if status == StatusTransportError {
				return committed, StatusUnknown, errors.New("validating generation before claim")
			}
			continue
		}

		key := stateKey{Owner: candidate.Owner, Generation: candidate.Generation}
		claim, ok := h.newGenerationClaim(lifecycle, candidate.ProcessIncarnation)
		if !ok {
			continue
		}
		if !committed && requestCanceled(ctx) {
			return false, StatusUnknown, nil
		}
		guarded, guardErr := ownerDetachGuardPresent(h.ownerGuards, candidate.Owner)
		if guardErr != nil {
			return committed, StatusUnknown, guardErr
		}
		if guarded {
			continue
		}
		if !committed && requestCanceled(ctx) {
			return false, StatusUnknown, nil
		}
		if status := h.candidateTaskAuthorityStatus(candidate); status != StatusValid {
			if status == StatusTransportError {
				return committed, StatusUnknown, errors.New("revalidating task authority before claim")
			}
			continue
		}
		if !committed && requestCanceled(ctx) {
			return false, StatusUnknown, nil
		}
		preclaimState, _, status := h.validatePublishedGeneration(
			candidate,
			record,
			encoded,
			StatusMissing,
			true,
		)
		if status != StatusValid {
			if status == StatusTransportError {
				return committed, StatusUnknown, errors.New("revalidating generation before claim")
			}
			if len(candidates) == 1 {
				return committed, status, nil
			}
			continue
		}
		replayTransition, status := h.activeAliasReplay(candidate, key, preclaimState)
		if status != StatusValid {
			if status == StatusTransportError {
				return committed, StatusUnknown, errors.New("validating alias replay before claim")
			}
			if len(candidates) == 1 {
				return committed, status, nil
			}
			continue
		}
		if status := h.candidateTaskAuthorityStatus(candidate); status != StatusValid {
			if status == StatusTransportError {
				return committed, StatusUnknown, errors.New("revalidating task authority at claim")
			}
			if len(candidates) == 1 {
				return committed, status, nil
			}
			continue
		}
		if err := h.claims.Update(&key, &claim, ebpf.UpdateNoExist); err != nil {
			if !errors.Is(err, ebpf.ErrKeyExist) {
				return committed, StatusUnknown, err
			}
			claimedStatus, claimed, claimErr := h.existingGenerationClaimStatus(
				candidate,
			)
			if claimErr != nil {
				return committed, StatusUnknown, claimErr
			}
			if !claimed {
				if len(candidates) == 1 {
					return committed, StatusOverload, nil
				}
				continue
			}
			if len(candidates) == 1 {
				return committed, claimedStatus, nil
			}
			// A collision for one member of an ambiguous candidate set cannot
			// override the aggregate result or prevent the remaining members
			// from committing their one-shot discard. Keep consuming.
			continue
		}
		ownedClaim := new(generationClaim)
		*ownedClaim = claim
		ownedCommitted := new(bool)
		ownedRollbackAllowed := new(bool)
		*ownedRollbackAllowed = true
		ownedTransition := new(*aliasReplayTransition)
		*ownedTransition = replayTransition
		defer func(
			key stateKey,
			owned *generationClaim,
			claimCommitted *bool,
			rollbackAllowed *bool,
			transition **aliasReplayTransition,
		) {
			if !*claimCommitted {
				if *rollbackAllowed && h.rollbackPublishingClaim(key, owned, *transition) {
					return
				}
				_ = h.retainLocalClaim(key)
			}
			_ = handoffGenerationProducerFencePair(
				h.claims, h.ownerGuards, key, owned, nil, h.monoTimeNow,
			)
		}(key, ownedClaim, ownedCommitted, ownedRollbackAllowed, ownedTransition)
		guarded, guardErr = ownerDetachGuardPresent(h.ownerGuards, candidate.Owner)
		if guardErr != nil {
			*ownedRollbackAllowed = false
			return committed, StatusUnknown, guardErr
		}
		if guarded {
			if status := h.candidateTaskAuthorityStatus(candidate); status != StatusValid {
				if status == StatusTransportError {
					*ownedRollbackAllowed = false
					return committed, StatusUnknown,
						errors.New("revalidating guarded task authority after claim")
				}
				return committed, status, nil
			}
			if lifecycle == lifecycleAmbiguous {
				return committed, StatusUnknown, nil
			}
			return committed, StatusOverload, nil
		}
		if status := h.publishAliasReplayTransition(
			replayTransition, *ownedClaim, lifecycle,
		); status != StatusValid {
			*ownedRollbackAllowed = false
			if status == StatusTransportError {
				return committed, StatusUnknown, errors.New("publishing alias replay transition")
			}
			if len(candidates) == 1 {
				return committed, status, nil
			}
			continue
		}
		state, _, status := h.validatePublishedGeneration(
			candidate,
			record,
			encoded,
			StatusAlreadyConsumed,
			true,
		)
		if status != StatusValid {
			if linkStatus := h.candidateTaskLinkStatus(candidate); linkStatus == StatusValid ||
				linkStatus == StatusTransportError {
				*ownedRollbackAllowed = false
			}
			if status == StatusTransportError {
				return committed, StatusUnknown, errors.New("revalidating claimed generation")
			}
			if len(candidates) == 1 {
				return committed, status, nil
			}
			continue
		}
		if replayTransition == nil && state.Aliases > 0 {
			replayTransition, status = h.activeAliasReplay(candidate, key, state)
			*ownedTransition = replayTransition
			if status != StatusValid {
				*ownedRollbackAllowed = false
				if status == StatusTransportError {
					return committed, StatusUnknown, errors.New("revalidating alias replay after claim")
				}
				if len(candidates) == 1 {
					return committed, status, nil
				}
				continue
			}
			if status = h.publishAliasReplayTransition(
				replayTransition, *ownedClaim, lifecycle,
			); status != StatusValid {
				*ownedRollbackAllowed = false
				if status == StatusTransportError {
					return committed, StatusUnknown, errors.New("publishing late alias replay transition")
				}
				if len(candidates) == 1 {
					return committed, status, nil
				}
				continue
			}
		}
		if replayTransition != nil {
			if aliasReplayKeyForState(key, state) != replayTransition.key {
				*ownedRollbackAllowed = false
				if len(candidates) == 1 {
					return committed, StatusAmbiguous, nil
				}
				continue
			}
			if status = h.revalidateAliasReplayTransition(replayTransition); status != StatusValid {
				*ownedRollbackAllowed = false
				if status == StatusTransportError {
					return committed, StatusUnknown, errors.New("checking claimed alias replay")
				}
				if len(candidates) == 1 {
					return committed, status, nil
				}
				continue
			}
		}
		guarded, guardErr = ownerDetachGuardPresent(h.ownerGuards, candidate.Owner)
		if guardErr != nil {
			*ownedRollbackAllowed = false
			return committed, StatusUnknown, guardErr
		}
		if guarded {
			if len(candidates) == 1 {
				return committed, StatusOverload, nil
			}
			continue
		}
		if status = h.candidateTaskAuthorityStatus(candidate); status != StatusValid {
			if linkStatus := h.candidateTaskLinkStatus(candidate); linkStatus == StatusValid ||
				linkStatus == StatusTransportError {
				*ownedRollbackAllowed = false
			}
			if status == StatusTransportError {
				return committed, StatusUnknown, errors.New("revalidating task authority before commit")
			}
			if len(candidates) == 1 {
				return committed, status, nil
			}
			continue
		}
		if status = h.promoteGenerationClaim(key, ownedClaim); status != StatusValid {
			*ownedRollbackAllowed = false
			if status == StatusTransportError {
				return committed, StatusUnknown, errors.New("promoting generation claim")
			}
			if len(candidates) == 1 {
				return committed, status, nil
			}
			continue
		}
		*ownedCommitted = true
		committed = true
		if h.finishClaimed(
			candidate.Owner,
			record,
			candidate.ProcessIncarnation,
			lifecycle,
			ownedClaim,
		) {
			h.markConsumed(candidate.Owner, candidate.ProcessIncarnation)
		}
	}
	return committed, StatusUnknown, nil
}

func requestCanceled(ctx context.Context) bool {
	return ctx != nil && ctx.Err() != nil
}

func (h *MapHandler) newGenerationClaim(
	lifecycle uint8,
	processIncarnation uint64,
) (generationClaim, bool) {
	now := h.monoTimeNow()
	if now <= 0 || processIncarnation == 0 || !validAliasReplayTarget(lifecycle) {
		return generationClaim{}, false
	}
	return generationClaim{
		ObservedMonotonicNS: uint64(now),
		ProcessIncarnation:  processIncarnation,
		Lifecycle:           lifecyclePublishing,
		Reserved: [7]byte{
			0: lifecycle,
			6: generationGoProducerTag,
		},
	}, true
}

type generationFinishResult struct {
	complete        bool
	mutationStarted bool
}

type aliasReplayTransition struct {
	key            aliasReplayKey
	claimTimestamp uint64
	desired        uint8
}

type aliasReplayFinishProof struct {
	key                 aliasReplayKey
	transitionTimestamp uint64
	lifecycle           uint8
}

type connectionReleaseProof struct {
	connectionKey connectionInfoNS
	cookieKey     connectionInfoNetNSCookie
}

func (h *MapHandler) retainLocalClaim(key stateKey) error {
	now := h.monoTimeNow()
	if now <= 0 {
		return errors.New("reading monotonic time for retained Java generation claim")
	}
	return ensureGenerationAmbiguity(h.ambiguity, key, uint64(now))
}

func aliasReplayKeyForState(
	key stateKey,
	state stateValue,
) aliasReplayKey {
	return aliasReplayKey{
		Owner:               key.Owner,
		Generation:          key.Generation,
		ObservedMonotonicNS: state.ObservedMonotonicNS,
		ProcessIncarnation:  state.ProcessIncarnation,
	}
}

func validAliasReplayTarget(lifecycle uint8) bool {
	return lifecycle >= lifecycleConsumed && lifecycle <= lifecycleAmbiguous
}

func validActiveAliasReplay(value aliasReplayValue) bool {
	return value.TransitionMonotonicNS != 0 && value.Lifecycle == lifecycleActive &&
		value.DesiredLifecycle == 0 &&
		value.ProducerTag == 0 && value.Reserved == 0
}

func validPublishingAliasReplay(value aliasReplayValue) bool {
	return value.TransitionMonotonicNS != 0 && value.Lifecycle == lifecyclePublishing &&
		validAliasReplayTarget(value.DesiredLifecycle) &&
		(value.ProducerTag == 0 || value.ProducerTag == generationGoProducerTag) &&
		value.Reserved == 0
}

func validGoPublishingAliasReplay(
	value aliasReplayValue,
	claimTimestamp uint64,
	desired uint8,
) bool {
	return validPublishingAliasReplay(value) &&
		value.TransitionMonotonicNS == claimTimestamp &&
		value.DesiredLifecycle == desired && value.ProducerTag == generationGoProducerTag
}

func validFinalAliasReplay(value aliasReplayValue) bool {
	return value.TransitionMonotonicNS != 0 && validAliasReplayTarget(value.Lifecycle) &&
		value.DesiredLifecycle == 0 && value.ProducerTag == 0 && value.Reserved == 0
}

func statusForAliasReplay(value aliasReplayValue) Status {
	switch {
	case validActiveAliasReplay(value), validPublishingAliasReplay(value):
		return StatusOverload
	case validFinalAliasReplay(value):
		if value.Lifecycle == lifecycleAmbiguous {
			return StatusAmbiguous
		}
		return StatusAlreadyConsumed
	default:
		return StatusAmbiguous
	}
}

func (h *MapHandler) activeAliasReplay(
	candidate resolvedCandidate,
	key stateKey,
	state stateValue,
) (*aliasReplayTransition, Status) {
	replayKey := aliasReplayKeyForState(key, state)
	var current aliasReplayValue
	if err := h.aliasReplays.Lookup(&replayKey, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			if state.Aliases == 0 {
				return nil, StatusValid
			}
			return nil, StatusOverload
		}
		return nil, StatusTransportError
	}
	if !validActiveAliasReplay(current) {
		// A retained exact claim is the primary one-shot authority, including
		// while a final or interrupted publishing replay coexists with live
		// generation state. Only an exact task carrier may use a final replay
		// after that claim is absent; direct lookups never replay task outcomes.
		claimedStatus, claimed, claimErr := h.existingGenerationClaimStatus(candidate)
		if claimErr != nil {
			return nil, StatusTransportError
		}
		if claimed {
			return nil, claimedStatus
		}
		if validFinalAliasReplay(current) {
			if candidate.TaskSource != (Identity{}) && current.References == 0 {
				return nil, StatusAmbiguous
			}
			if candidate.TaskSource == (Identity{}) {
				return nil, StatusOverload
			}
		}
		return nil, statusForAliasReplay(current)
	}
	if state.Aliases > 0 && current.References == 0 {
		return nil, StatusAmbiguous
	}
	return &aliasReplayTransition{key: replayKey}, StatusValid
}

func (h *MapHandler) publishAliasReplayTransition(
	transition *aliasReplayTransition,
	claim generationClaim,
	desired uint8,
) Status {
	if transition == nil {
		return StatusValid
	}
	if (!validGoPublishingGenerationClaim(claim) && !validGoFinalGenerationClaim(claim)) ||
		!validAliasReplayTarget(desired) {
		return StatusAmbiguous
	}
	transition.claimTimestamp = claim.ObservedMonotonicNS
	transition.desired = desired

	var current aliasReplayValue
	if err := h.aliasReplays.Lookup(&transition.key, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return StatusOverload
		}
		return StatusTransportError
	}
	if validGoPublishingAliasReplay(current, transition.claimTimestamp, desired) {
		return StatusValid
	}
	if !validActiveAliasReplay(current) {
		return statusForAliasReplay(current)
	}

	publishing := current
	publishing.TransitionMonotonicNS = transition.claimTimestamp
	publishing.Lifecycle = lifecyclePublishing
	publishing.DesiredLifecycle = desired
	publishing.ProducerTag = generationGoProducerTag
	publishing.Reserved = 0
	updateErr := h.aliasReplays.Update(&transition.key, &publishing, ebpf.UpdateExist)
	if err := h.aliasReplays.Lookup(&transition.key, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return StatusOverload
		}
		return StatusTransportError
	}
	if validGoPublishingAliasReplay(current, transition.claimTimestamp, desired) {
		return StatusValid
	}
	if updateErr != nil {
		return StatusTransportError
	}
	return statusForAliasReplay(current)
}

func (h *MapHandler) revalidateAliasReplayTransition(
	transition *aliasReplayTransition,
) Status {
	if transition == nil {
		return StatusValid
	}
	var current aliasReplayValue
	if err := h.aliasReplays.Lookup(&transition.key, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return StatusOverload
		}
		return StatusTransportError
	}
	if validGoPublishingAliasReplay(
		current, transition.claimTimestamp, transition.desired,
	) {
		return StatusValid
	}
	return statusForAliasReplay(current)
}

func validGoPublishingGenerationClaim(claim generationClaim) bool {
	return claim.ObservedMonotonicNS != 0 && claim.ProcessIncarnation != 0 &&
		claim.Lifecycle == lifecyclePublishing && validAliasReplayTarget(claim.Reserved[0]) &&
		claim.Reserved[1] == 0 && claim.Reserved[2] == 0 && claim.Reserved[3] == 0 &&
		claim.Reserved[4] == 0 && claim.Reserved[5] == 0 &&
		claim.Reserved[6] == generationGoProducerTag
}

func validGoFinalGenerationClaim(claim generationClaim) bool {
	return claim.ObservedMonotonicNS != 0 && claim.ProcessIncarnation != 0 &&
		validAliasReplayTarget(claim.Lifecycle) && claim.Reserved[0] == 0 &&
		claim.Reserved[1] == 0 && claim.Reserved[2] == 0 && claim.Reserved[3] == 0 &&
		claim.Reserved[4] == 0 && claim.Reserved[5] == 0 &&
		claim.Reserved[6] == generationGoProducerTag
}

func (h *MapHandler) promoteGenerationClaim(
	key stateKey,
	claim *generationClaim,
) Status {
	if claim == nil || !validGoPublishingGenerationClaim(*claim) {
		return StatusAmbiguous
	}
	var current generationClaim
	if err := h.claims.Lookup(&key, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return StatusOverload
		}
		return StatusTransportError
	}
	if current != *claim {
		return statusForGenerationClaim(current, claim.ProcessIncarnation)
	}

	final := *claim
	final.Lifecycle = claim.Reserved[0]
	final.Reserved = [7]byte{6: generationGoProducerTag}
	updateErr := h.claims.Update(&key, &final, ebpf.UpdateExist)
	if err := h.claims.Lookup(&key, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return StatusOverload
		}
		return StatusTransportError
	}
	if current == final {
		*claim = final
		return StatusValid
	}
	if updateErr != nil {
		return StatusTransportError
	}
	return statusForGenerationClaim(current, claim.ProcessIncarnation)
}

func (h *MapHandler) retargetPublishingClaimStale(
	key stateKey,
	claim *generationClaim,
	transition *aliasReplayTransition,
) Status {
	if claim == nil || !validGoPublishingGenerationClaim(*claim) ||
		(claim.Reserved[0] != lifecycleConsumed &&
			claim.Reserved[0] != lifecycleDiscarded) {
		return StatusAmbiguous
	}

	var currentClaim generationClaim
	if err := h.claims.Lookup(&key, &currentClaim); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return StatusOverload
		}
		return StatusTransportError
	}
	if currentClaim != *claim {
		return statusForGenerationClaim(currentClaim, claim.ProcessIncarnation)
	}

	var staleReplay aliasReplayValue
	if transition != nil {
		if transition.desired != claim.Reserved[0] {
			return StatusAmbiguous
		}
		var currentReplay aliasReplayValue
		if err := h.aliasReplays.Lookup(&transition.key, &currentReplay); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				return StatusOverload
			}
			return StatusTransportError
		}
		if !validGoPublishingAliasReplay(
			currentReplay, transition.claimTimestamp, transition.desired,
		) {
			return statusForAliasReplay(currentReplay)
		}
		staleReplay = currentReplay
		staleReplay.DesiredLifecycle = lifecycleStale
	}

	// E is the durable semantic authority. Retarget it first so an interruption
	// between the two updates hands cleanup the stale outcome; cleanup can then
	// converge a still-tagged replay from its previous desired lifecycle.
	staleClaim := *claim
	staleClaim.Reserved[0] = lifecycleStale
	updateErr := h.claims.Update(&key, &staleClaim, ebpf.UpdateExist)
	if err := h.claims.Lookup(&key, &currentClaim); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return StatusOverload
		}
		return StatusTransportError
	}
	if currentClaim == staleClaim {
		*claim = staleClaim
	} else if updateErr != nil {
		return StatusTransportError
	} else {
		return statusForGenerationClaim(currentClaim, claim.ProcessIncarnation)
	}

	if transition == nil {
		return StatusValid
	}
	var currentReplay aliasReplayValue
	if err := h.aliasReplays.Lookup(&transition.key, &currentReplay); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return StatusOverload
		}
		return StatusTransportError
	}
	if !validGoPublishingAliasReplay(
		currentReplay, transition.claimTimestamp, transition.desired,
	) {
		return statusForAliasReplay(currentReplay)
	}
	// Preserve the freshest reference snapshot from the exact read immediately
	// before the whole-value update; Go never increments or decrements it.
	staleReplay.References = currentReplay.References
	updateErr = h.aliasReplays.Update(
		&transition.key, &staleReplay, ebpf.UpdateExist,
	)
	if err := h.aliasReplays.Lookup(&transition.key, &currentReplay); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return StatusOverload
		}
		return StatusTransportError
	}
	if currentReplay == staleReplay {
		transition.desired = lifecycleStale
		return StatusValid
	}
	if updateErr != nil {
		return StatusTransportError
	}
	return statusForAliasReplay(currentReplay)
}

func (h *MapHandler) rollbackPublishingClaim(
	key stateKey,
	claim *generationClaim,
	transition *aliasReplayTransition,
) bool {
	if claim == nil || !validGoPublishingGenerationClaim(*claim) {
		return false
	}
	if transition != nil {
		var current aliasReplayValue
		if err := h.aliasReplays.Lookup(&transition.key, &current); err != nil {
			return false
		}
		if validGoPublishingAliasReplay(
			current, transition.claimTimestamp, transition.desired,
		) {
			now := h.monoTimeNow()
			if now <= 0 {
				return false
			}
			active := current
			active.TransitionMonotonicNS = uint64(now)
			active.Lifecycle = lifecycleActive
			active.DesiredLifecycle = 0
			active.ProducerTag = 0
			active.Reserved = 0
			updateErr := h.aliasReplays.Update(&transition.key, &active, ebpf.UpdateExist)
			if err := h.aliasReplays.Lookup(&transition.key, &current); err != nil ||
				!validActiveAliasReplay(current) {
				return false
			}
			_ = updateErr
		} else if !validActiveAliasReplay(current) {
			return false
		}
	}
	deleted, err := cleanupDeleteExact(h.claims, key, *claim)
	if err != nil || !deleted {
		var current generationClaim
		if !errors.Is(h.claims.Lookup(&key, &current), ebpf.ErrKeyNotExist) {
			return false
		}
	}
	claim.ObservedMonotonicNS = 0
	return true
}

func (h *MapHandler) prepareAliasReplayFinish(
	key stateKey,
	state stateValue,
	claim generationClaim,
	lifecycle uint8,
) (*aliasReplayTransition, *aliasReplayFinishProof, Status) {
	if !validGoFinalGenerationClaim(claim) || claim.Lifecycle != lifecycle ||
		!validAliasReplayTarget(lifecycle) {
		return nil, nil, StatusAmbiguous
	}
	replayKey := aliasReplayKeyForState(key, state)
	var current aliasReplayValue
	if err := h.aliasReplays.Lookup(&replayKey, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			if state.Aliases == 0 {
				return nil, nil, StatusValid
			}
			return nil, nil, StatusOverload
		}
		return nil, nil, StatusTransportError
	}
	if state.Aliases > 0 && current.References == 0 {
		return nil, nil, StatusAmbiguous
	}
	if validFinalAliasReplay(current) {
		if current.Lifecycle != lifecycle {
			return nil, nil, StatusAmbiguous
		}
		return nil, &aliasReplayFinishProof{
			key:                 replayKey,
			transitionTimestamp: current.TransitionMonotonicNS,
			lifecycle:           lifecycle,
		}, StatusValid
	}

	transition := &aliasReplayTransition{key: replayKey}
	if validActiveAliasReplay(current) {
		if status := h.publishAliasReplayTransition(
			transition, claim, lifecycle,
		); status != StatusValid {
			return nil, nil, status
		}
		return transition, nil, StatusValid
	}
	if validGoPublishingAliasReplay(
		current, claim.ObservedMonotonicNS, lifecycle,
	) {
		transition.claimTimestamp = claim.ObservedMonotonicNS
		transition.desired = lifecycle
		return transition, nil, StatusValid
	}
	return nil, nil, statusForAliasReplay(current)
}

func (h *MapHandler) commitFinalAliasReplay(
	transition *aliasReplayTransition,
	existingProof *aliasReplayFinishProof,
	lifecycle uint8,
) (*aliasReplayFinishProof, Status) {
	if existingProof != nil {
		if h.aliasReplayFinishProofValid(existingProof) {
			return existingProof, StatusValid
		}
		return nil, StatusAmbiguous
	}
	if transition == nil {
		return nil, StatusValid
	}
	if !validAliasReplayTarget(lifecycle) {
		return nil, StatusAmbiguous
	}

	var current aliasReplayValue
	if err := h.aliasReplays.Lookup(&transition.key, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, StatusOverload
		}
		return nil, StatusTransportError
	}
	if validFinalAliasReplay(current) {
		if current.Lifecycle != lifecycle {
			return nil, StatusAmbiguous
		}
		return &aliasReplayFinishProof{
			key:                 transition.key,
			transitionTimestamp: current.TransitionMonotonicNS,
			lifecycle:           lifecycle,
		}, StatusValid
	}
	if !validGoPublishingAliasReplay(
		current, transition.claimTimestamp, transition.desired,
	) {
		return nil, statusForAliasReplay(current)
	}
	now := h.monoTimeNow()
	if now <= 0 {
		return nil, StatusTransportError
	}
	final := current
	final.TransitionMonotonicNS = uint64(now)
	final.Lifecycle = lifecycle
	final.DesiredLifecycle = 0
	final.ProducerTag = 0
	final.Reserved = 0
	updateErr := h.aliasReplays.Update(&transition.key, &final, ebpf.UpdateExist)
	if err := h.aliasReplays.Lookup(&transition.key, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, StatusOverload
		}
		return nil, StatusTransportError
	}
	if validFinalAliasReplay(current) && current.Lifecycle == lifecycle {
		return &aliasReplayFinishProof{
			key:                 transition.key,
			transitionTimestamp: current.TransitionMonotonicNS,
			lifecycle:           lifecycle,
		}, StatusValid
	}
	if updateErr != nil {
		return nil, StatusTransportError
	}
	return nil, statusForAliasReplay(current)
}

func (h *MapHandler) aliasReplayFinishProofValid(
	proof *aliasReplayFinishProof,
) bool {
	if proof == nil {
		return true
	}
	var current aliasReplayValue
	return h.aliasReplays.Lookup(&proof.key, &current) == nil &&
		validFinalAliasReplay(current) && current.Lifecycle == proof.lifecycle &&
		current.TransitionMonotonicNS == proof.transitionTimestamp
}

func (h *MapHandler) finishClaimed(
	owner Identity,
	record Record,
	processIncarnation uint64,
	lifecycle uint8,
	claim *generationClaim,
) bool {
	return h.finishClaimedResult(
		owner, record, processIncarnation, lifecycle, claim,
	).complete
}

func (h *MapHandler) finishClaimedResult(
	owner Identity,
	record Record,
	processIncarnation uint64,
	lifecycle uint8,
	claim *generationClaim,
) generationFinishResult {
	return h.finish(owner, record, processIncarnation, lifecycle, claim)
}

func (h *MapHandler) finish(
	owner Identity,
	record Record,
	processIncarnation uint64,
	lifecycle uint8,
	claim *generationClaim,
) (result generationFinishResult) {
	generation := record.Generation
	if generation == 0 || processIncarnation == 0 || claim == nil {
		return result
	}
	key := stateKey{Owner: owner, Generation: generation}
	ownedGuard := generationClaim{}
	defer func() {
		if !result.complete && claim.ObservedMonotonicNS != 0 {
			matches, err := generationClaimMatches(h.claims, key, *claim)
			now := h.monoTimeNow()
			if err == nil && matches && now > 0 &&
				ensureGenerationAmbiguity(h.ambiguity, key, uint64(now)) == nil {
				result.mutationStarted = true
			}
		}
		_ = handoffGenerationProducerFencePair(
			h.claims, h.ownerGuards, key, claim, &ownedGuard, h.monoTimeNow,
		)
	}()
	if current, status := h.processIncarnation(owner); status != StatusValid ||
		current != processIncarnation {
		return result
	}
	claimMatches, err := generationClaimMatches(h.claims, key, *claim)
	if err != nil || !claimMatches {
		return result
	}

	var state stateValue
	stateErr := h.states.Lookup(&key, &state)
	if errors.Is(stateErr, ebpf.ErrKeyNotExist) {
		return result
	}
	if stateErr != nil || !validFinishState(state, record, processIncarnation) {
		return result
	}
	var generationIndex generationIndexValue
	if indexErr := h.generations.Lookup(&key, &generationIndex); indexErr != nil {
		return result
	}
	if !validFinishGenerationIndex(key, generationIndex, state) {
		return result
	}
	if current, status := h.processIncarnation(owner); status != StatusValid ||
		current != processIncarnation {
		return result
	}
	replayTransition, existingReplayProof, replayStatus := h.prepareAliasReplayFinish(
		key, state, *claim, lifecycle,
	)
	if replayStatus != StatusValid {
		return result
	}

	now := h.monoTimeNow()
	fence, acquired, acquireErr := acquireGenerationTeardownFence(
		h.claims, h.ownerGuards, h.ambiguity, key, *claim, now,
	)
	if fence.guardOwned {
		ownedGuard = fence.guardClaim
	}
	if acquireErr != nil || !acquired {
		if fence.guardOwned {
			result.mutationStarted = true
		} else if matches, matchErr := generationClaimMatches(
			h.claims, key, *claim,
		); matchErr == nil && matches && now > 0 {
			// A foreign G=0 guard may have won after delivery committed. Keep
			// the invocation-local exact claim authoritative and turn the zero
			// reservation into durable recovery state, matching the BPF finish
			// wrapper's cleanup-failed path.
			if ensureGenerationAmbiguity(h.ambiguity, key, uint64(now)) == nil {
				result.mutationStarted = true
			}
		}
		return result
	}
	// Publishing the generation-zero guard and promoting the exact ambiguity
	// marker are teardown mutations. Every incomplete path from here retains
	// all remaining fences for the coordinated sweeper.
	result.mutationStarted = true

	var currentState stateValue
	if err := h.states.Lookup(&key, &currentState); err != nil || currentState != state ||
		!validFinishState(currentState, record, processIncarnation) {
		return result
	}
	var currentGenerationIndex generationIndexValue
	if err := h.generations.Lookup(&key, &currentGenerationIndex); err != nil ||
		currentGenerationIndex != generationIndex ||
		!validFinishGenerationIndex(key, currentGenerationIndex, currentState) {
		return result
	}

	var indexed ownerValue
	ownerErr := h.owners.Lookup(&owner, &indexed)
	if ownerErr != nil && !errors.Is(ownerErr, ebpf.ErrKeyNotExist) {
		return result
	}
	ownsGeneration := ownerErr == nil && generation == indexed.Generation &&
		processIncarnation == indexed.ProcessIncarnation &&
		indexed.Lifecycle == lifecycleActive && indexed.Reserved == ([7]byte{})
	if ownerErr == nil && indexed.Generation == generation && !ownsGeneration {
		return result
	}
	if !ownsGeneration && state.Aliases == 0 {
		return result
	}
	if valid, err := generationTeardownFenceMatches(
		h.claims, h.ownerGuards, h.ambiguity, fence,
	); err != nil || !valid {
		return result
	}

	observedMonotonicNS := state.ObservedMonotonicNS
	terminal := terminalValue{
		Generation:          generation,
		ObservedMonotonicNS: observedMonotonicNS,
		ProcessIncarnation:  processIncarnation,
		Lifecycle:           lifecycle,
	}
	if ownsGeneration {
		var currentOwner ownerValue
		if err := h.owners.Lookup(&owner, &currentOwner); err != nil {
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				return result
			}
			ownsGeneration = false
		} else if currentOwner != indexed {
			if currentOwner.Generation == generation {
				return result
			}
			ownsGeneration = false
		}
	}
	if !ownsGeneration && state.Aliases == 0 {
		return result
	}
	terminalBarrier := terminal
	if ownsGeneration {
		if !h.finishFenceValid(fence) {
			return result
		}
		if err := h.terminals.Update(&owner, &terminal, ebpf.UpdateAny); err != nil {
			return result
		}
	} else if !h.finishFenceValid(fence) {
		return result
	} else if err := h.terminals.Update(&owner, &terminal, ebpf.UpdateNoExist); err != nil {
		if !errors.Is(err, ebpf.ErrKeyExist) {
			return result
		}
		var current terminalValue
		if lookupErr := h.terminals.Lookup(&owner, &current); lookupErr != nil {
			return result
		}
		if current != terminal &&
			(current.Generation == generation || !validTerminalValue(current)) {
			return result
		}
		terminalBarrier = current
	}
	var publishedTerminal terminalValue
	if err := h.terminals.Lookup(&owner, &publishedTerminal); err != nil {
		return result
	}
	if publishedTerminal != terminalBarrier {
		return result
	}
	if !h.finishBarriersValid(fence, publishedTerminal) {
		return result
	}
	replayProof, replayStatus := h.commitFinalAliasReplay(
		replayTransition, existingReplayProof, lifecycle,
	)
	if replayStatus != StatusValid ||
		!h.finishBarriersValid(fence, publishedTerminal, replayProof) {
		return result
	}

	proof, released := h.releaseConnectionFenced(
		fence, publishedTerminal, replayProof, state.Connection, state.ConnectionNetNS,
	)
	if !released {
		return result
	}
	connectionProof := &proof
	if !h.finishBarriersValid(fence, publishedTerminal, replayProof) {
		return result
	}
	deleted, deleteErr := cleanupDeleteExact(h.states, key, state)
	if deleteErr != nil || !deleted ||
		!h.finishBarriersValid(fence, publishedTerminal, replayProof) {
		return result
	}
	if !h.finishBarriersValid(fence, publishedTerminal, replayProof) {
		return result
	}
	if !h.deleteRemoteParentGeneration(owner, generation, processIncarnation) {
		return result
	}
	if !h.finishBarriersValid(fence, publishedTerminal, replayProof) {
		return result
	}
	if !h.deleteGenerationIndex(key, generationIndex) {
		return result
	}
	if !h.finishBarriersValid(fence, publishedTerminal, replayProof) {
		return result
	}
	if ownsGeneration {
		if !h.deleteOwnerGeneration(owner, indexed) {
			return result
		}
	}
	if !h.generationFinishReady(
		fence, publishedTerminal, replayProof, connectionProof,
	) {
		return result
	}
	// All generation payload has been removed. Coordination-fence retirement is
	// best-effort from here, and any partial tail converges asynchronously. Mark
	// logical finish complete before observing mutable release state so an outer
	// caller can never resurrect a marker released by another actor.
	result.complete = true

	// Release the nonzero marker, exact claim, and owner guard in that order.
	// Once the marker is absent, logical finish is complete and partial claim or
	// guard tails converge asynchronously. Never recreate old fence state after
	// this point: another actor may already have linearized G=0 release.
	var currentMarker uint64
	if err := h.ambiguity.Lookup(&key, &currentMarker); err != nil ||
		currentMarker != fence.markedAt {
		return result
	}
	guardMatches, guardErr := generationGuardMatches(
		h.ownerGuards, fence.guardKey, fence.guardClaim,
	)
	if guardErr != nil || !guardMatches {
		return result
	}
	_, deleteErr = cleanupDeleteExact(h.ambiguity, key, fence.markedAt)
	var remaining uint64
	remainingErr := h.ambiguity.Lookup(&key, &remaining)
	if deleteErr != nil || remainingErr == nil ||
		!errors.Is(remainingErr, ebpf.ErrKeyNotExist) {
		return result
	}
	guardMatches, guardErr = generationGuardMatches(
		h.ownerGuards, fence.guardKey, fence.guardClaim,
	)
	if guardErr != nil || !guardMatches {
		return result
	}
	released, claimErr := releaseGenerationProducerClaim(h.claims, key, claim)
	if claimErr != nil || !released {
		return result
	}
	exactAbsent, claimErr := generationClaimAbsent(h.claims, key)
	if claimErr != nil || !exactAbsent {
		return result
	}
	if err := h.ambiguity.Lookup(&key, &remaining); !errors.Is(err, ebpf.ErrKeyNotExist) {
		return result
	}
	released, guardErr = releaseGenerationProducerGuard(h.ownerGuards, key, &ownedGuard)
	if guardErr != nil || !released {
		return result
	}
	// Exact guard deletion is the linearization point. A new generation may
	// reuse these keys immediately afterward, so post-release artifact checks
	// would observe legitimate successor state and must not re-mark old G.
	return result
}

func validFinishState(
	state stateValue,
	record Record,
	processIncarnation uint64,
) bool {
	stateRecord, err := UnmarshalRecord(state.Response[:])
	return err == nil && state.Lifecycle == lifecycleActive && state.Reserved == ([3]byte{}) &&
		state.ProcessIncarnation == processIncarnation && state.ObservedMonotonicNS != 0 &&
		state.ConnectionNetNS != 0 && validGenerationConnection(state.Connection) &&
		(record.ObservedMonotonicNS == 0 || state.ObservedMonotonicNS == record.ObservedMonotonicNS) &&
		stateRecord.Generation == record.Generation &&
		stateRecord.ObservedMonotonicNS == state.ObservedMonotonicNS &&
		stateRecord.IsValidRemoteParent()
}

func validFinishGenerationIndex(
	key stateKey,
	index generationIndexValue,
	state stateValue,
) bool {
	return index.Process == javaProcessIdentity(key.Owner) && index.Reserved == 0 &&
		index.ProcessIncarnation == state.ProcessIncarnation &&
		index.ObservedMonotonicNS == state.ObservedMonotonicNS
}

func (h *MapHandler) finishBarriersValid(
	fence generationTeardownFence,
	terminal terminalValue,
	replayProof ...*aliasReplayFinishProof,
) bool {
	if !h.finishFenceValid(fence) {
		return false
	}
	if len(replayProof) > 1 ||
		(len(replayProof) == 1 && !h.aliasReplayFinishProofValid(replayProof[0])) {
		return false
	}
	var current terminalValue
	return h.terminals.Lookup(&fence.key.Owner, &current) == nil && current == terminal
}

func (h *MapHandler) finishFenceValid(fence generationTeardownFence) bool {
	valid, err := generationTeardownFenceMatches(
		h.claims, h.ownerGuards, h.ambiguity, fence,
	)
	return err == nil && valid
}

func validTerminalValue(terminal terminalValue) bool {
	return terminal.Generation != 0 && terminal.ProcessIncarnation != 0 &&
		terminal.ObservedMonotonicNS != 0 && terminal.Reserved == ([7]byte{}) &&
		terminal.Lifecycle >= lifecycleConsumed && terminal.Lifecycle <= lifecycleAmbiguous
}

func (h *MapHandler) generationFinishReady(
	fence generationTeardownFence,
	terminal terminalValue,
	replayProof *aliasReplayFinishProof,
	connectionProof *connectionReleaseProof,
) bool {
	return h.finishBarriersValid(fence, terminal, replayProof) &&
		h.generationArtifactsAbsent(fence.key, terminal, connectionProof) &&
		h.finishBarriersValid(fence, terminal, replayProof)
}

func (h *MapHandler) generationArtifactsAbsent(
	key stateKey,
	terminal terminalValue,
	connectionProof *connectionReleaseProof,
) bool {
	if connectionProof == nil {
		return false
	}
	var currentTerminal terminalValue
	if err := h.terminals.Lookup(&key.Owner, &currentTerminal); err != nil ||
		currentTerminal != terminal {
		return false
	}
	var state stateValue
	if err := h.states.Lookup(&key, &state); err == nil {
		return false
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false
	}
	var generation generationIndexValue
	if err := h.generations.Lookup(&key, &generation); err == nil {
		return false
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false
	}
	var owner ownerValue
	if err := h.owners.Lookup(&key.Owner, &owner); err == nil {
		if owner.Generation == key.Generation {
			return false
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false
	}
	var encoded [RecordSize]byte
	if err := h.remoteParents.Lookup(&key.Owner, &encoded); err == nil {
		record, decodeErr := UnmarshalRecord(encoded[:])
		if decodeErr != nil || record.Generation == key.Generation {
			return false
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return false
	}
	return h.connectionGenerationReleased(
		h.connections, connectionProof.connectionKey, key.Owner, key.Generation,
	) && h.connectionGenerationReleased(
		h.cookieConnections, connectionProof.cookieKey, key.Owner, key.Generation,
	)
}

func (h *MapHandler) deleteGenerationIndex(
	key stateKey,
	expected generationIndexValue,
) bool {
	var current generationIndexValue
	if err := h.generations.Lookup(&key, &current); err != nil {
		return errors.Is(err, ebpf.ErrKeyNotExist)
	}
	if current != expected || current.Process != javaProcessIdentity(key.Owner) ||
		current.Reserved != 0 || current.ProcessIncarnation == 0 ||
		current.ObservedMonotonicNS == 0 {
		return false
	}

	deleted, err := cleanupDeleteExact(h.generations, key, current)
	return err == nil && deleted
}

func (h *MapHandler) deleteRemoteParentGeneration(
	owner Identity,
	generation uint64,
	processIncarnation uint64,
) bool {
	var current [RecordSize]byte
	if err := h.remoteParents.Lookup(&owner, &current); err != nil {
		return errors.Is(err, ebpf.ErrKeyNotExist)
	}
	currentRecord, currentErr := UnmarshalRecord(current[:])
	if currentErr != nil || currentRecord.Status != StatusValid {
		return false
	}
	if currentRecord.Generation != generation {
		return true
	}

	var indexed ownerValue
	if err := h.owners.Lookup(&owner, &indexed); err != nil {
		return errors.Is(err, ebpf.ErrKeyNotExist)
	}
	if indexed.Generation != generation || indexed.ProcessIncarnation != processIncarnation {
		return true
	}

	deleted, err := cleanupDeleteExact(h.remoteParents, owner, current)
	return err == nil && deleted
}

func (h *MapHandler) deleteOwnerGeneration(
	owner Identity,
	expected ownerValue,
) bool {
	var current ownerValue
	if err := h.owners.Lookup(&owner, &current); err != nil {
		return errors.Is(err, ebpf.ErrKeyNotExist)
	}
	if current.Generation != expected.Generation {
		return true
	}
	if current != expected || current.Generation == 0 || current.ProcessIncarnation == 0 ||
		current.Lifecycle != lifecycleActive || current.Reserved != ([7]byte{}) {
		return false
	}

	deleted, err := cleanupDeleteExact(h.owners, owner, current)
	if err != nil || deleted {
		return err == nil
	}
	if err := h.owners.Lookup(&owner, &current); err != nil {
		return errors.Is(err, ebpf.ErrKeyNotExist)
	}
	return current.Generation != expected.Generation
}

func (h *MapHandler) releaseConnectionFenced(
	fence generationTeardownFence,
	terminal terminalValue,
	replayProof *aliasReplayFinishProof,
	connection connectionInfo,
	connectionNetNS uint32,
) (connectionReleaseProof, bool) {
	connectionKey := connectionInfoNS{Connection: connection, NetNS: connectionNetNS}
	proof := connectionReleaseProof{connectionKey: connectionKey}
	var claim connectionClaim
	if err := h.connections.Lookup(&connectionKey, &claim); err != nil ||
		!validConnectionClaim(claim, fence.key.Owner, fence.key.Generation, connectionNetNS) {
		return proof, false
	}
	cookieKey := connectionInfoNetNSCookie{
		Connection:  connection,
		NetNSCookie: claim.NetNSCookie,
	}
	proof.cookieKey = cookieKey
	var cookieClaim connectionClaim
	if err := h.cookieConnections.Lookup(&cookieKey, &cookieClaim); err != nil ||
		cookieClaim != claim || !h.finishBarriersValid(fence, terminal, replayProof) {
		return proof, false
	}
	deleted, err := cleanupDeleteExact(h.cookieConnections, cookieKey, claim)
	if err != nil || !deleted ||
		!h.connectionGenerationReleased(
			h.cookieConnections, cookieKey, fence.key.Owner, fence.key.Generation,
		) || !h.finishBarriersValid(fence, terminal, replayProof) {
		return proof, false
	}
	var revalidated connectionClaim
	if err := h.connections.Lookup(&connectionKey, &revalidated); err != nil ||
		revalidated != claim || !h.finishBarriersValid(fence, terminal, replayProof) {
		return proof, false
	}
	deleted, err = cleanupDeleteExact(h.connections, connectionKey, claim)
	if err != nil || !deleted ||
		!h.connectionGenerationReleased(
			h.connections, connectionKey, fence.key.Owner, fence.key.Generation,
		) || !h.connectionGenerationReleased(
		h.cookieConnections, cookieKey, fence.key.Owner, fence.key.Generation,
	) || !h.finishBarriersValid(fence, terminal, replayProof) {
		return proof, false
	}
	return proof, true
}

func (h *MapHandler) connectionGenerationReleased(
	m bridgeMap,
	key any,
	owner Identity,
	generation uint64,
) bool {
	var current connectionClaim
	if err := m.Lookup(key, &current); err != nil {
		return errors.Is(err, ebpf.ErrKeyNotExist)
	}
	return current.Owner != owner || current.Generation != generation
}

func lifecycleForStatus(status Status) uint8 {
	switch status {
	case StatusStale:
		return lifecycleStale
	case StatusAmbiguous:
		return lifecycleAmbiguous
	default:
		return lifecycleDiscarded
	}
}

func statusForLifecycle(lifecycle uint8) Status {
	switch lifecycle {
	case lifecycleStale:
		return StatusStale
	case lifecycleAmbiguous:
		return StatusAmbiguous
	case lifecycleConsumed, lifecycleDiscarded:
		return StatusAlreadyConsumed
	default:
		return StatusMissing
	}
}

func statusForGenerationClaim(claim generationClaim, processIncarnation uint64) Status {
	if processIncarnation == 0 || claim.ObservedMonotonicNS == 0 ||
		claim.ProcessIncarnation != processIncarnation {
		return StatusAmbiguous
	}
	if validGoPublishingGenerationClaim(claim) {
		return StatusOverload
	}
	semanticLifecycle := claim.Lifecycle
	if claim.Lifecycle == lifecycleCleanup {
		if !validGenerationCleanupClaim(claim) {
			return StatusAmbiguous
		}
		semanticLifecycle = claim.Reserved[0]
	} else if claim.Reserved != ([7]byte{}) && !validGenerationProducerClaim(claim) {
		return StatusAmbiguous
	}
	switch semanticLifecycle {
	case lifecyclePublishing:
		return StatusOverload
	case lifecycleAmbiguous:
		return StatusAmbiguous
	case lifecycleConsumed, lifecycleDiscarded, lifecycleStale:
		return StatusAlreadyConsumed
	default:
		return StatusAmbiguous
	}
}

func (h *MapHandler) claimedCandidateStatus(
	candidate resolvedCandidate,
) (Status, bool, bool) {
	if candidate.Generation == 0 || candidate.ProcessIncarnation == 0 {
		return StatusAmbiguous, false, false
	}
	status, found, err := h.existingGenerationClaimStatus(candidate)
	return status, found, err != nil
}

func (h *MapHandler) displacedTaskAliasReplayStatus(
	candidate resolvedCandidate,
) (Status, bool, error) {
	if !candidate.ClaimOnly || candidate.TaskLink.Generation == 0 {
		return StatusUnknown, false, nil
	}
	if status := h.candidateTaskLinkStatus(candidate); status != StatusValid {
		if status == StatusTransportError {
			return status, false, errors.New("validating task link before alias replay lookup")
		}
		return status, true, nil
	}
	key := aliasReplayKey{
		Owner:               candidate.Owner,
		Generation:          candidate.Generation,
		ObservedMonotonicNS: candidate.TaskLink.ObservedMonotonicNS,
		ProcessIncarnation:  candidate.ProcessIncarnation,
	}
	var replay aliasReplayValue
	if err := h.aliasReplays.Lookup(&key, &replay); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return StatusTransportError, false, err
		}
		if status := h.candidateTaskLinkStatus(candidate); status != StatusValid {
			if status == StatusTransportError {
				return status, false, errors.New("revalidating task link after missing alias replay")
			}
			return status, true, nil
		}
		return StatusUnknown, false, nil
	}
	if status := h.candidateTaskLinkStatus(candidate); status != StatusValid {
		if status == StatusTransportError {
			return status, false, errors.New("revalidating task link after alias replay lookup")
		}
		return status, true, nil
	}
	if replay.References == 0 {
		// Active-zero reservations and final-zero cleanup tails are structurally
		// valid, but no zero-reference record can authorize a task carrier.
		return StatusAmbiguous, true, nil
	}
	return statusForAliasReplay(replay), true, nil
}

func (h *MapHandler) existingGenerationClaimStatus(
	candidate resolvedCandidate,
) (Status, bool, error) {
	if status := h.candidateTaskLinkStatus(candidate); status != StatusValid {
		if status == StatusTransportError {
			return status, false, errors.New("validating task link before claim lookup")
		}
		return status, true, nil
	}
	key := stateKey{Owner: candidate.Owner, Generation: candidate.Generation}
	var claim generationClaim
	if err := h.claims.Lookup(&key, &claim); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			if status := h.candidateTaskAuthorityStatus(candidate); status != StatusValid {
				if status == StatusTransportError {
					return status, false,
						errors.New("revalidating task target after missing claim lookup")
				}
				// The caller must propagate a changed task authority even though
				// the collided claim disappeared before it could be observed.
				return status, true, nil
			}
			if replayStatus, found, replayErr := h.displacedTaskAliasReplayStatus(
				candidate,
			); replayErr != nil || found {
				return replayStatus, found, replayErr
			}
			return StatusOverload, false, nil
		}
		return StatusTransportError, false, err
	}
	if status := h.candidateTaskLinkStatus(candidate); status != StatusValid {
		if status == StatusTransportError {
			return status, false, errors.New("revalidating task link after claim lookup")
		}
		return status, true, nil
	}
	return statusForGenerationClaim(claim, candidate.ProcessIncarnation), true, nil
}
