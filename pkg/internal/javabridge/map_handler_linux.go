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

type bridgeMapLookup interface {
	Lookup(key, valueOut any) error
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
	Connection            connectionInfo
	ConnectionNetNS       uint32
	ConnectionNetNSCookie uint64
	SocketCookie          uint64
}

type aliasReplayBinding struct {
	Connection            connectionInfo
	ConnectionNetNS       uint32
	ConnectionNetNSCookie uint64
	SocketCookie          uint64
}

func aliasReplayBindingOf(value aliasReplayValue) aliasReplayBinding {
	return aliasReplayBinding{
		Connection:            value.Connection,
		ConnectionNetNS:       value.ConnectionNetNS,
		ConnectionNetNSCookie: value.ConnectionNetNSCookie,
		SocketCookie:          value.SocketCookie,
	}
}

// References and Aliases are XADD-managed carrier counts. They may change
// while an exact generation claim and guard fence every immutable replay and
// state field. Canonicalize only those counters for authority proofs; payload
// compare-delete remains byte-exact so counter drift can defer physical
// cleanup without suppressing an already committed delivery.
func aliasReplayProofValue(value aliasReplayValue) aliasReplayValue {
	value.References = 0
	return value
}

func aliasReplayProofState(state stateValue) stateValue {
	state.Aliases = 0
	return state
}

func aliasReplayProofValueEqual(left, right aliasReplayValue) bool {
	return aliasReplayProofValue(left) == aliasReplayProofValue(right)
}

func aliasReplayProofStateEqual(left, right stateValue) bool {
	return aliasReplayProofState(left) == aliasReplayProofState(right)
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
	if status = h.revalidateAliasReplayGenerationTransition(
		key, state, ownedClaim, replayTransition,
	); status != StatusValid {
		rollbackAllowed = false
		return Record{Status: status}
	}
	if status = h.promoteGenerationClaim(key, &ownedClaim); status != StatusValid {
		rollbackAllowed = false
		return Record{Status: status}
	}
	if status = h.revalidateAliasReplayGenerationTransition(
		key, state, ownedClaim, replayTransition,
	); status != StatusValid {
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
	finishResult := h.finishClaimedResult(
		owner, record, processIncarnation, lifecycle, &ownedClaim,
	)
	if operation == OperationDiscard {
		return Record{Status: StatusMissing}
	}
	if finishResult.deliveryAuthorityFailed {
		return Record{Status: StatusOverload}
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
		if status = h.revalidateAliasReplayGenerationTransition(
			key, state, *ownedClaim, replayTransition,
		); status != StatusValid {
			*ownedRollbackAllowed = false
			if status == StatusTransportError {
				return committed, StatusUnknown,
					errors.New("revalidating alias replay generation proof before commit")
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
		if status = h.revalidateAliasReplayGenerationTransition(
			key, state, *ownedClaim, replayTransition,
		); status != StatusValid {
			*ownedRollbackAllowed = false
			if status == StatusTransportError {
				return committed, StatusUnknown,
					errors.New("revalidating alias replay generation proof after commit")
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
	complete                bool
	mutationStarted         bool
	successorRequired       bool
	deliveryAuthorityFailed bool
}

type aliasReplayTransition struct {
	key            aliasReplayKey
	binding        aliasReplayBinding
	generation     aliasReplayGenerationProof
	ambiguity      uint64
	claimTimestamp uint64
	desired        uint8
}

type aliasReplayFinishProof struct {
	key             aliasReplayKey
	value           aliasReplayValue
	generation      aliasReplayGenerationProof
	authorityFailed bool
}

func (transition *aliasReplayTransition) bindingMatches(value aliasReplayValue) bool {
	return transition != nil && transition.binding == aliasReplayBindingOf(value)
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

func validAliasReplayBinding(value aliasReplayValue) bool {
	return validGenerationConnection(value.Connection) && value.ConnectionNetNS != 0 &&
		value.ConnectionNetNSCookie != 0 && value.SocketCookie != 0
}

func aliasReplayBindingMatchesState(value aliasReplayValue, state stateValue) bool {
	return validAliasReplayBinding(value) && value.Connection == state.Connection &&
		value.ConnectionNetNS == state.ConnectionNetNS
}

type aliasReplayGenerationMaps struct {
	remoteParents     bridgeMapLookup
	incarnations      bridgeMapLookup
	connections       bridgeMapLookup
	cookieConnections bridgeMapLookup
	ambiguity         bridgeMapLookup
	owners            bridgeMapLookup
	states            bridgeMapLookup
	generations       bridgeMapLookup
	terminals         bridgeMapLookup
	claims            bridgeMapLookup
	aliasReplays      bridgeMapLookup
	ownerGuards       bridgeMapLookup
}

func (h *MapHandler) aliasReplayGenerationMaps() aliasReplayGenerationMaps {
	return aliasReplayGenerationMaps{
		remoteParents:     h.remoteParents,
		incarnations:      h.incarnations,
		connections:       h.connections,
		cookieConnections: h.cookieConnections,
		ambiguity:         h.ambiguity,
		owners:            h.owners,
		states:            h.states,
		generations:       h.generations,
		terminals:         h.terminals,
		claims:            h.claims,
		aliasReplays:      h.aliasReplays,
		ownerGuards:       h.ownerGuards,
	}
}

type aliasReplayGenerationAuthority struct {
	claimPresent          bool
	claim                 generationClaim
	guardPresent          bool
	guard                 generationClaim
	ambiguity             uint64
	requireOldIndex       bool
	requireOldIncarnation bool
}

type aliasReplaySuccessorGraph struct {
	binding            aliasReplayBinding
	oldState           stateValue
	oldIndexPresent    bool
	oldIndex           generationIndexValue
	oldIncarnation     uint64
	connection         connectionClaim
	owner              ownerValue
	fallback           [RecordSize]byte
	state              stateValue
	index              generationIndexValue
	processIncarnation uint64
}

type aliasReplayGenerationProof struct {
	successor             bool
	successorRequired     bool
	oldState              stateValue
	oldIndexPresent       bool
	oldIndex              generationIndexValue
	oldIncarnationPresent bool
	oldIncarnation        uint64
	binding               aliasReplayBinding
	connectionPresent     bool
	connection            connectionClaim
	graph                 aliasReplaySuccessorGraph
}

type aliasReplayGenerationSnapshot struct {
	replay                aliasReplayValue
	oldState              stateValue
	oldIndexPresent       bool
	oldIndex              generationIndexValue
	oldIncarnationPresent bool
	oldIncarnation        uint64
	ambiguity             uint64
	claimPresent          bool
	claim                 generationClaim
	guardPresent          bool
	guard                 generationClaim
	connectionPresent     bool
	connection            connectionClaim
	cookie                connectionClaim
	terminalPresent       bool
	terminal              terminalValue
	successor             bool
	successorOwner        ownerValue
	successorFallback     [RecordSize]byte
	successorState        stateValue
	successorIndex        generationIndexValue
	successorIncarnation  uint64
}

func aliasReplayLookup[K comparable, V any](
	m bridgeMapLookup,
	key K,
) (V, bool, error) {
	var value V
	if err := m.Lookup(&key, &value); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return value, false, nil
		}
		return value, false, err
	}
	return value, true, nil
}

func validAliasReplayAuthority(
	key stateKey,
	state stateValue,
	authority aliasReplayGenerationAuthority,
) bool {
	if authority.claimPresent {
		if authority.claim.ProcessIncarnation != state.ProcessIncarnation ||
			(!validGenerationProducerClaim(authority.claim) &&
				!validGenerationCleanupClaim(authority.claim)) {
			return false
		}
	}
	if authority.guardPresent {
		if !authority.claimPresent {
			return false
		}
		producerPair := validGenerationProducerClaim(authority.claim) &&
			validGenerationProducerGuard(key, authority.guard)
		cleanupPair := validGenerationCleanupClaim(authority.claim) &&
			authority.guard.ProcessIncarnation == key.Generation &&
			validGenerationCleanupGuard(key.Owner, authority.guard)
		if !producerPair && !cleanupPair {
			return false
		}
	}
	return true
}

func aliasReplayOldTerminalLifecycle(
	authority aliasReplayGenerationAuthority,
) (uint8, bool) {
	if !authority.claimPresent {
		return 0, false
	}
	if validGoFinalGenerationClaim(authority.claim) {
		return authority.claim.Lifecycle, true
	}
	if validGenerationCleanupClaim(authority.claim) &&
		validAliasReplayTarget(authority.claim.Reserved[0]) {
		return authority.claim.Reserved[0], true
	}
	return 0, false
}

func validAliasReplayTerminalForSuccessor(
	key stateKey,
	state stateValue,
	authority aliasReplayGenerationAuthority,
	terminal terminalValue,
) bool {
	lifecycle, ok := aliasReplayOldTerminalLifecycle(authority)
	return ok && validTerminalValue(terminal) && terminal.Generation == key.Generation &&
		terminal.ObservedMonotonicNS == state.ObservedMonotonicNS &&
		terminal.ProcessIncarnation == state.ProcessIncarnation &&
		terminal.Lifecycle == lifecycle
}

func aliasReplayConnectionMatchesBinding(
	value aliasReplayValue,
	connection connectionClaim,
	owner Identity,
) bool {
	return connection.Owner == owner && connection.Reserved == 0 &&
		connection.Reserved2 == 0 && connection.Generation != 0 &&
		connection.NetNS == value.ConnectionNetNS &&
		connection.NetNSCookie == value.ConnectionNetNSCookie &&
		connection.IncomingGeneration != 0 && connection.SocketCookie == value.SocketCookie
}

func aliasReplaySameBindingSuccessorRequired(
	maps aliasReplayGenerationMaps,
	key stateKey,
	value aliasReplayValue,
) (bool, error) {
	connectionKey := connectionInfoNS{
		Connection: value.Connection,
		NetNS:      value.ConnectionNetNS,
	}
	cookieKey := connectionInfoNetNSCookie{
		Connection:  value.Connection,
		NetNSCookie: value.ConnectionNetNSCookie,
	}
	connection, connectionPresent, err := aliasReplayLookup[connectionInfoNS, connectionClaim](
		maps.connections, connectionKey,
	)
	if err != nil {
		return false, err
	}
	cookie, cookiePresent, err := aliasReplayLookup[connectionInfoNetNSCookie, connectionClaim](
		maps.cookieConnections, cookieKey,
	)
	if err != nil {
		return false, err
	}
	if (connectionPresent && connection.Generation != 0 && connection.Generation != key.Generation) ||
		(cookiePresent && cookie.Generation != 0 && cookie.Generation != key.Generation) {
		return true, nil
	}

	owner, present, err := aliasReplayLookup[Identity, ownerValue](maps.owners, key.Owner)
	if err != nil || !present || owner.Generation == 0 || owner.Generation == key.Generation {
		return false, err
	}
	successorKey := stateKey{Owner: key.Owner, Generation: owner.Generation}
	state, present, err := aliasReplayLookup[stateKey, stateValue](maps.states, successorKey)
	if err != nil || !present {
		return false, err
	}
	return state.Connection == value.Connection &&
		state.ConnectionNetNS == value.ConnectionNetNS, nil
}

func readAliasReplayGenerationSnapshot(
	maps aliasReplayGenerationMaps,
	authority aliasReplayGenerationAuthority,
	key stateKey,
	state stateValue,
	value aliasReplayValue,
) (aliasReplayGenerationSnapshot, bool, error) {
	var snapshot aliasReplayGenerationSnapshot
	if !aliasReplayBindingMatchesState(value, state) ||
		!validAliasReplayAuthority(key, state, authority) {
		return snapshot, false, nil
	}
	replayKey := aliasReplayKeyForState(key, state)
	currentReplay, present, err := aliasReplayLookup[aliasReplayKey, aliasReplayValue](
		maps.aliasReplays, replayKey,
	)
	if err != nil || !present || !aliasReplayProofValueEqual(currentReplay, value) {
		return snapshot, false, err
	}
	currentState, present, err := aliasReplayLookup[stateKey, stateValue](maps.states, key)
	if err != nil || !present || !aliasReplayProofStateEqual(currentState, state) {
		return snapshot, false, err
	}
	oldIndex, oldIndexPresent, err := aliasReplayLookup[stateKey, generationIndexValue](
		maps.generations, key,
	)
	if err != nil || (oldIndexPresent &&
		!validFinishGenerationIndex(key, oldIndex, currentState)) ||
		(authority.requireOldIndex && !oldIndexPresent) {
		return snapshot, false, err
	}
	process := javaProcessIdentity(key.Owner)
	oldIncarnation, oldIncarnationPresent, err := aliasReplayLookup[Identity, uint64](
		maps.incarnations, process,
	)
	if err != nil || (authority.requireOldIncarnation &&
		(!oldIncarnationPresent || oldIncarnation != state.ProcessIncarnation)) {
		return snapshot, false, err
	}
	markedAt, present, err := aliasReplayLookup[stateKey, uint64](maps.ambiguity, key)
	if err != nil || !present || markedAt != authority.ambiguity {
		return snapshot, false, err
	}
	claim, claimPresent, err := aliasReplayLookup[stateKey, generationClaim](maps.claims, key)
	if err != nil || claimPresent != authority.claimPresent ||
		(claimPresent && claim != authority.claim) {
		return snapshot, false, err
	}
	guard, guardPresent, err := aliasReplayLookup[Identity, generationClaim](
		maps.ownerGuards, key.Owner,
	)
	if err != nil || guardPresent != authority.guardPresent ||
		(guardPresent && guard != authority.guard) {
		return snapshot, false, err
	}

	connectionKey := connectionInfoNS{
		Connection: value.Connection,
		NetNS:      value.ConnectionNetNS,
	}
	cookieKey := connectionInfoNetNSCookie{
		Connection:  value.Connection,
		NetNSCookie: value.ConnectionNetNSCookie,
	}
	connection, connectionPresent, err := aliasReplayLookup[connectionInfoNS, connectionClaim](
		maps.connections, connectionKey,
	)
	if err != nil {
		return snapshot, false, err
	}
	cookie, cookiePresent, err := aliasReplayLookup[connectionInfoNetNSCookie, connectionClaim](
		maps.cookieConnections, cookieKey,
	)
	if err != nil || connectionPresent != cookiePresent {
		return snapshot, false, err
	}

	terminal, terminalPresent, err := aliasReplayLookup[Identity, terminalValue](
		maps.terminals, key.Owner,
	)
	if err != nil {
		return snapshot, false, err
	}
	snapshot = aliasReplayGenerationSnapshot{
		replay:                aliasReplayProofValue(currentReplay),
		oldState:              aliasReplayProofState(currentState),
		oldIndexPresent:       oldIndexPresent,
		oldIndex:              oldIndex,
		oldIncarnationPresent: oldIncarnationPresent,
		oldIncarnation:        oldIncarnation,
		ambiguity:             markedAt,
		claimPresent:          claimPresent,
		claim:                 claim,
		guardPresent:          guardPresent,
		guard:                 guard,
		connectionPresent:     connectionPresent,
		connection:            connection,
		cookie:                cookie,
		terminalPresent:       terminalPresent,
		terminal:              terminal,
	}
	if terminalPresent && !validAliasReplayTerminalForSuccessor(
		key, state, authority, terminal,
	) {
		return snapshot, false, nil
	}
	if !connectionPresent {
		return snapshot, true, nil
	}
	if connection != cookie ||
		!aliasReplayConnectionMatchesBinding(value, connection, key.Owner) {
		return snapshot, false, nil
	}
	if connection.Generation == key.Generation {
		if !validConnectionClaim(
			connection, key.Owner, key.Generation, value.ConnectionNetNS,
		) {
			return snapshot, false, nil
		}
		return snapshot, true, nil
	}
	if !oldIncarnationPresent || oldIncarnation != state.ProcessIncarnation {
		// Cleanup may prove a retired old generation after its process-incarnation
		// entry has disappeared. That retirement authority can never prove a live
		// same-socket successor.
		return snapshot, false, nil
	}

	successorKey := stateKey{Owner: key.Owner, Generation: connection.Generation}
	owner, present, err := aliasReplayLookup[Identity, ownerValue](maps.owners, key.Owner)
	if err != nil || !present || owner.Generation != successorKey.Generation ||
		owner.ProcessIncarnation == 0 || owner.ProcessIncarnation != oldIncarnation ||
		owner.Lifecycle != lifecycleActive ||
		owner.Reserved != ([7]byte{}) {
		return snapshot, false, err
	}
	successorIncarnation, present, err := aliasReplayLookup[Identity, uint64](
		maps.incarnations, process,
	)
	if err != nil || !present || successorIncarnation != owner.ProcessIncarnation ||
		successorIncarnation != oldIncarnation {
		return snapshot, false, err
	}
	fallback, present, err := aliasReplayLookup[Identity, [RecordSize]byte](
		maps.remoteParents, key.Owner,
	)
	if err != nil || !present {
		return snapshot, false, err
	}
	successorState, present, err := aliasReplayLookup[stateKey, stateValue](maps.states, successorKey)
	if err != nil || !present || successorState.Lifecycle != lifecycleActive ||
		successorState.Reserved != ([3]byte{}) || successorState.ObservedMonotonicNS == 0 ||
		successorState.Connection != value.Connection ||
		successorState.ConnectionNetNS != value.ConnectionNetNS ||
		successorState.ProcessIncarnation != owner.ProcessIncarnation ||
		successorState.Response != fallback {
		return snapshot, false, err
	}
	record, decodeErr := UnmarshalRecord(fallback[:])
	if decodeErr != nil || record.Generation != successorKey.Generation ||
		record.ObservedMonotonicNS != successorState.ObservedMonotonicNS ||
		!record.IsValidRemoteParent() {
		return snapshot, false, nil
	}
	index, present, err := aliasReplayLookup[stateKey, generationIndexValue](
		maps.generations, successorKey,
	)
	if err != nil || !present || !validFinishGenerationIndex(successorKey, index, successorState) {
		return snapshot, false, err
	}
	successorMarkedAt, present, err := aliasReplayLookup[stateKey, uint64](
		maps.ambiguity, successorKey,
	)
	if err != nil || !present || successorMarkedAt != 0 {
		return snapshot, false, err
	}
	_, successorClaimPresent, err := aliasReplayLookup[stateKey, generationClaim](
		maps.claims, successorKey,
	)
	if err != nil || successorClaimPresent {
		return snapshot, false, err
	}
	snapshot.successor = true
	snapshot.successorOwner = owner
	snapshot.successorFallback = fallback
	snapshot.successorState = aliasReplayProofState(successorState)
	snapshot.successorIndex = index
	snapshot.successorIncarnation = successorIncarnation
	return snapshot, true, nil
}

type aliasReplaySuccessorContinuitySnapshot struct {
	oldStatePresent    bool
	oldState           stateValue
	oldIndexPresent    bool
	oldIndex           generationIndexValue
	connection         connectionClaim
	cookie             connectionClaim
	owner              ownerValue
	fallback           [RecordSize]byte
	state              stateValue
	index              generationIndexValue
	processIncarnation uint64
	ambiguity          uint64
	claim              generationClaim
	guard              generationClaim
	terminalPresent    bool
	terminal           terminalValue
}

// readAliasReplaySuccessorContinuitySnapshot permits the old generation's S/I
// payload to remain byte-identical or disappear during exact fenced teardown.
// A replacement must never be mistaken for teardown progress. The same-socket
// successor graph remains byte-identical throughout either old-payload shape.
func readAliasReplaySuccessorContinuitySnapshot(
	maps aliasReplayGenerationMaps,
	authority aliasReplayGenerationAuthority,
	key stateKey,
	state stateValue,
	value aliasReplayValue,
	graph aliasReplaySuccessorGraph,
) (aliasReplaySuccessorContinuitySnapshot, bool, error) {
	var snapshot aliasReplaySuccessorContinuitySnapshot
	if aliasReplayBindingOf(value) != graph.binding ||
		!aliasReplayProofStateEqual(graph.oldState, state) ||
		graph.connection.Generation == 0 || graph.connection.Generation == key.Generation ||
		!aliasReplayConnectionMatchesBinding(value, graph.connection, key.Owner) {
		return snapshot, false, nil
	}
	oldState, oldStatePresent, err := aliasReplayLookup[stateKey, stateValue](
		maps.states, key,
	)
	if err != nil || (oldStatePresent &&
		!aliasReplayProofStateEqual(oldState, graph.oldState)) {
		return snapshot, false, err
	}
	oldIndex, oldIndexPresent, err := aliasReplayLookup[stateKey, generationIndexValue](
		maps.generations, key,
	)
	if err != nil || (oldIndexPresent &&
		(!graph.oldIndexPresent || oldIndex != graph.oldIndex)) {
		return snapshot, false, err
	}
	connectionKey := connectionInfoNS{
		Connection: graph.binding.Connection,
		NetNS:      graph.binding.ConnectionNetNS,
	}
	cookieKey := connectionInfoNetNSCookie{
		Connection:  graph.binding.Connection,
		NetNSCookie: graph.binding.ConnectionNetNSCookie,
	}
	connection, present, err := aliasReplayLookup[connectionInfoNS, connectionClaim](
		maps.connections, connectionKey,
	)
	if err != nil || !present || connection != graph.connection {
		return snapshot, false, err
	}
	cookie, present, err := aliasReplayLookup[connectionInfoNetNSCookie, connectionClaim](
		maps.cookieConnections, cookieKey,
	)
	if err != nil || !present || cookie != graph.connection {
		return snapshot, false, err
	}
	successorKey := stateKey{Owner: key.Owner, Generation: graph.connection.Generation}
	owner, present, err := aliasReplayLookup[Identity, ownerValue](maps.owners, key.Owner)
	if err != nil || !present || owner != graph.owner {
		return snapshot, false, err
	}
	fallback, present, err := aliasReplayLookup[Identity, [RecordSize]byte](
		maps.remoteParents, key.Owner,
	)
	if err != nil || !present || fallback != graph.fallback {
		return snapshot, false, err
	}
	successorState, present, err := aliasReplayLookup[stateKey, stateValue](
		maps.states, successorKey,
	)
	if err != nil || !present || !aliasReplayProofStateEqual(successorState, graph.state) {
		return snapshot, false, err
	}
	index, present, err := aliasReplayLookup[stateKey, generationIndexValue](
		maps.generations, successorKey,
	)
	if err != nil || !present || index != graph.index {
		return snapshot, false, err
	}
	processIncarnation, present, err := aliasReplayLookup[Identity, uint64](
		maps.incarnations, javaProcessIdentity(key.Owner),
	)
	if err != nil || !present || processIncarnation != graph.processIncarnation {
		return snapshot, false, err
	}
	ambiguity, present, err := aliasReplayLookup[stateKey, uint64](maps.ambiguity, successorKey)
	if err != nil || !present || ambiguity != 0 {
		return snapshot, false, err
	}
	_, claimPresent, err := aliasReplayLookup[stateKey, generationClaim](maps.claims, successorKey)
	if err != nil || claimPresent {
		return snapshot, false, err
	}
	oldAmbiguity, present, err := aliasReplayLookup[stateKey, uint64](maps.ambiguity, key)
	if err != nil || !present || oldAmbiguity != authority.ambiguity {
		return snapshot, false, err
	}
	oldClaim, present, err := aliasReplayLookup[stateKey, generationClaim](maps.claims, key)
	if err != nil || !present || !authority.claimPresent || oldClaim != authority.claim {
		return snapshot, false, err
	}
	oldGuard, present, err := aliasReplayLookup[Identity, generationClaim](
		maps.ownerGuards, key.Owner,
	)
	if err != nil || !present || !authority.guardPresent || oldGuard != authority.guard {
		return snapshot, false, err
	}
	terminal, terminalPresent, err := aliasReplayLookup[Identity, terminalValue](
		maps.terminals, key.Owner,
	)
	if err != nil || (terminalPresent && !validAliasReplayTerminalForSuccessor(
		key, state, authority, terminal,
	)) {
		return snapshot, false, err
	}
	snapshot = aliasReplaySuccessorContinuitySnapshot{
		oldStatePresent:    oldStatePresent,
		oldState:           aliasReplayProofState(oldState),
		oldIndexPresent:    oldIndexPresent,
		oldIndex:           oldIndex,
		connection:         connection,
		cookie:             cookie,
		owner:              owner,
		fallback:           fallback,
		state:              aliasReplayProofState(successorState),
		index:              index,
		processIncarnation: processIncarnation,
		ambiguity:          oldAmbiguity,
		claim:              oldClaim,
		guard:              oldGuard,
		terminalPresent:    terminalPresent,
		terminal:           terminal,
	}
	return snapshot, true, nil
}

type aliasReplayOldGenerationContinuitySnapshot struct {
	statePresent       bool
	state              stateValue
	indexPresent       bool
	index              generationIndexValue
	incarnationPresent bool
	incarnation        uint64
	connectionPresent  bool
	connection         connectionClaim
	cookiePresent      bool
	cookie             connectionClaim
	ambiguity          uint64
	claim              generationClaim
	guard              generationClaim
	terminalPresent    bool
	terminal           terminalValue
}

// readAliasReplayOldGenerationContinuitySnapshot permits only the monotonic
// shapes produced by exact teardown: an old C/S/I/incarnation entry may remain
// byte-identical or become absent. It can never be replaced. A C successor is
// handled separately by rebuilding the complete successor proof while old S/I
// still provide authority.
func readAliasReplayOldGenerationContinuitySnapshot(
	maps aliasReplayGenerationMaps,
	authority aliasReplayGenerationAuthority,
	key stateKey,
	state stateValue,
	value aliasReplayValue,
	proof aliasReplayGenerationProof,
) (aliasReplayOldGenerationContinuitySnapshot, bool, error) {
	var snapshot aliasReplayOldGenerationContinuitySnapshot
	if aliasReplayBindingOf(value) != proof.binding ||
		!aliasReplayBindingMatchesState(value, state) {
		return snapshot, false, nil
	}
	currentState, statePresent, err := aliasReplayLookup[stateKey, stateValue](maps.states, key)
	if err != nil || (statePresent && !aliasReplayProofStateEqual(currentState, state)) {
		return snapshot, false, err
	}
	currentIndex, indexPresent, err := aliasReplayLookup[stateKey, generationIndexValue](
		maps.generations, key,
	)
	if err != nil || (indexPresent &&
		(!proof.oldIndexPresent || currentIndex != proof.oldIndex)) {
		return snapshot, false, err
	}
	currentIncarnation, incarnationPresent, err := aliasReplayLookup[Identity, uint64](
		maps.incarnations, javaProcessIdentity(key.Owner),
	)
	if err != nil || (incarnationPresent &&
		(!proof.oldIncarnationPresent || currentIncarnation != proof.oldIncarnation)) {
		return snapshot, false, err
	}
	connectionKey := connectionInfoNS{
		Connection: proof.binding.Connection,
		NetNS:      proof.binding.ConnectionNetNS,
	}
	cookieKey := connectionInfoNetNSCookie{
		Connection:  proof.binding.Connection,
		NetNSCookie: proof.binding.ConnectionNetNSCookie,
	}
	currentConnection, connectionPresent, err := aliasReplayLookup[connectionInfoNS, connectionClaim](
		maps.connections, connectionKey,
	)
	if err != nil || (connectionPresent &&
		(!proof.connectionPresent || currentConnection != proof.connection)) {
		return snapshot, false, err
	}
	currentCookie, cookiePresent, err := aliasReplayLookup[connectionInfoNetNSCookie, connectionClaim](
		maps.cookieConnections, cookieKey,
	)
	if err != nil || (cookiePresent &&
		(!proof.connectionPresent || currentCookie != proof.connection)) {
		return snapshot, false, err
	}
	ambiguity, present, err := aliasReplayLookup[stateKey, uint64](maps.ambiguity, key)
	if err != nil || !present || ambiguity != authority.ambiguity {
		return snapshot, false, err
	}
	claim, present, err := aliasReplayLookup[stateKey, generationClaim](maps.claims, key)
	if err != nil || !present || !authority.claimPresent || claim != authority.claim {
		return snapshot, false, err
	}
	guard, present, err := aliasReplayLookup[Identity, generationClaim](maps.ownerGuards, key.Owner)
	if err != nil || !present || !authority.guardPresent || guard != authority.guard {
		return snapshot, false, err
	}
	terminal, terminalPresent, err := aliasReplayLookup[Identity, terminalValue](
		maps.terminals, key.Owner,
	)
	if err != nil || (terminalPresent && !validAliasReplayTerminalForSuccessor(
		key, state, authority, terminal,
	)) {
		return snapshot, false, err
	}
	snapshot = aliasReplayOldGenerationContinuitySnapshot{
		statePresent:       statePresent,
		state:              aliasReplayProofState(currentState),
		indexPresent:       indexPresent,
		index:              currentIndex,
		incarnationPresent: incarnationPresent,
		incarnation:        currentIncarnation,
		connectionPresent:  connectionPresent,
		connection:         currentConnection,
		cookiePresent:      cookiePresent,
		cookie:             currentCookie,
		ambiguity:          ambiguity,
		claim:              claim,
		guard:              guard,
		terminalPresent:    terminalPresent,
		terminal:           terminal,
	}
	return snapshot, true, nil
}

func aliasReplayOldGenerationContinuityMatches(
	maps aliasReplayGenerationMaps,
	authority aliasReplayGenerationAuthority,
	key stateKey,
	state stateValue,
	value aliasReplayValue,
	proof aliasReplayGenerationProof,
) (bool, error) {
	first, valid, err := readAliasReplayOldGenerationContinuitySnapshot(
		maps, authority, key, state, value, proof,
	)
	if err != nil || !valid {
		return false, err
	}
	second, valid, err := readAliasReplayOldGenerationContinuitySnapshot(
		maps, authority, key, state, value, proof,
	)
	return err == nil && valid && first == second, err
}

func aliasReplayGenerationContinuityMatches(
	maps aliasReplayGenerationMaps,
	authority aliasReplayGenerationAuthority,
	key stateKey,
	state stateValue,
	value aliasReplayValue,
	proof *aliasReplayGenerationProof,
) (bool, error) {
	if proof == nil {
		return false, nil
	}
	if proof.successor {
		return aliasReplaySuccessorGraphMatches(
			maps, authority, key, state, value, proof.graph,
		)
	}
	successorRequired, err := aliasReplaySameBindingSuccessorRequired(maps, key, value)
	if err != nil {
		return false, err
	}
	proof.successorRequired = proof.successorRequired || successorRequired
	if !proof.successorRequired {
		oldMatches, err := aliasReplayOldGenerationContinuityMatches(
			maps, authority, key, state, value, *proof,
		)
		if err != nil || oldMatches {
			return oldMatches, err
		}
	}

	// A successor may have committed after the pre-guard proof but before old G
	// became visible. Adopt it only by rebuilding the full graph twice while old
	// S/I are still exact; an incomplete or malformed replacement fails closed.
	current, matches, err := aliasReplayBindingMatchesGeneration(
		maps, authority, key, state, value,
	)
	if err != nil || !matches || !current.successor {
		return false, err
	}
	*proof = current
	return aliasReplaySuccessorGraphMatches(
		maps, authority, key, state, value, proof.graph,
	)
}

func aliasReplaySuccessorGraphMatches(
	maps aliasReplayGenerationMaps,
	authority aliasReplayGenerationAuthority,
	key stateKey,
	state stateValue,
	value aliasReplayValue,
	graph aliasReplaySuccessorGraph,
) (bool, error) {
	first, valid, err := readAliasReplaySuccessorContinuitySnapshot(
		maps, authority, key, state, value, graph,
	)
	if err != nil || !valid {
		return false, err
	}
	second, valid, err := readAliasReplaySuccessorContinuitySnapshot(
		maps, authority, key, state, value, graph,
	)
	return err == nil && valid && first == second, err
}

// The replay binding is captured while the old generation has exact physical
// twins. A later same-socket successor is acceptable only when its complete
// logical publication graph is clean and byte-consistent. Read the entire
// proof twice so no single mixed-generation observation can authorize old E.
func aliasReplayBindingMatchesGeneration(
	maps aliasReplayGenerationMaps,
	authority aliasReplayGenerationAuthority,
	key stateKey,
	state stateValue,
	value aliasReplayValue,
) (aliasReplayGenerationProof, bool, error) {
	var proof aliasReplayGenerationProof
	successorRequired, err := aliasReplaySameBindingSuccessorRequired(maps, key, value)
	if err != nil {
		return proof, false, err
	}
	proof.successorRequired = successorRequired
	first, valid, err := readAliasReplayGenerationSnapshot(
		maps, authority, key, state, value,
	)
	if err != nil || !valid {
		return proof, false, err
	}
	second, valid, err := readAliasReplayGenerationSnapshot(
		maps, authority, key, state, value,
	)
	if err != nil || !valid || first != second {
		return proof, false, err
	}
	proof.oldState = second.oldState
	proof.oldIndexPresent = second.oldIndexPresent
	proof.oldIndex = second.oldIndex
	proof.oldIncarnationPresent = second.oldIncarnationPresent
	proof.oldIncarnation = second.oldIncarnation
	proof.binding = aliasReplayBindingOf(second.replay)
	proof.connectionPresent = second.connectionPresent
	proof.connection = second.connection
	if !second.successor {
		return proof, true, nil
	}
	proof.successor = true
	proof.successorRequired = true
	proof.graph = aliasReplaySuccessorGraph{
		binding:            aliasReplayBindingOf(second.replay),
		oldState:           second.oldState,
		oldIndexPresent:    second.oldIndexPresent,
		oldIndex:           second.oldIndex,
		oldIncarnation:     second.oldIncarnation,
		connection:         second.connection,
		owner:              second.successorOwner,
		fallback:           second.successorFallback,
		state:              second.successorState,
		index:              second.successorIndex,
		processIncarnation: second.successorIncarnation,
	}
	return proof, true, nil
}

func validActiveAliasReplay(value aliasReplayValue) bool {
	return validAliasReplayBinding(value) && value.TransitionMonotonicNS != 0 &&
		value.Lifecycle == lifecycleActive &&
		value.DesiredLifecycle == 0 &&
		value.ProducerTag == 0 && value.Reserved == 0
}

func validPublishingAliasReplay(value aliasReplayValue) bool {
	return validAliasReplayBinding(value) && value.TransitionMonotonicNS != 0 &&
		value.Lifecycle == lifecyclePublishing &&
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
	return validAliasReplayBinding(value) && value.TransitionMonotonicNS != 0 &&
		validAliasReplayTarget(value.Lifecycle) &&
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
	}
	markedAt, present, err := aliasReplayLookup[stateKey, uint64](h.ambiguity, key)
	if err != nil {
		return nil, StatusTransportError
	}
	if !present {
		return nil, StatusAmbiguous
	}
	generationProof, bindingMatches, err := aliasReplayBindingMatchesGeneration(
		h.aliasReplayGenerationMaps(), aliasReplayGenerationAuthority{
			ambiguity: markedAt, requireOldIndex: true, requireOldIncarnation: true,
		},
		key, state, current,
	)
	if err != nil {
		return nil, StatusTransportError
	}
	if !bindingMatches {
		claimedStatus, claimed, claimErr := h.existingGenerationClaimStatus(candidate)
		if claimErr != nil {
			return nil, StatusTransportError
		}
		if claimed {
			return nil, claimedStatus
		}
		if generationProof.successorRequired {
			return nil, StatusOverload
		}
		return nil, StatusAmbiguous
	}
	if !validActiveAliasReplay(current) {
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
	return &aliasReplayTransition{
		key:        replayKey,
		binding:    aliasReplayBindingOf(current),
		generation: generationProof,
		ambiguity:  markedAt,
	}, StatusValid
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
	if validGoPublishingAliasReplay(current, transition.claimTimestamp, desired) &&
		transition.bindingMatches(current) {
		return StatusValid
	}
	if !validActiveAliasReplay(current) || !transition.bindingMatches(current) {
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
	if validGoPublishingAliasReplay(current, transition.claimTimestamp, desired) &&
		transition.bindingMatches(current) {
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
	) && transition.bindingMatches(current) {
		return StatusValid
	}
	return statusForAliasReplay(current)
}

func (h *MapHandler) revalidateAliasReplayGenerationTransition(
	key stateKey,
	state stateValue,
	claim generationClaim,
	transition *aliasReplayTransition,
) Status {
	if transition == nil {
		if state.Aliases != 0 {
			return StatusAmbiguous
		}
		return StatusValid
	}
	if !validGenerationProducerClaim(claim) ||
		aliasReplayKeyForState(key, state) != transition.key {
		return StatusAmbiguous
	}
	desired := claim.Lifecycle
	if claim.Lifecycle == lifecyclePublishing {
		desired = claim.Reserved[0]
	}
	if !validAliasReplayTarget(desired) || transition.desired != desired {
		return StatusAmbiguous
	}
	var current aliasReplayValue
	if err := h.aliasReplays.Lookup(&transition.key, &current); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return StatusOverload
		}
		return StatusTransportError
	}
	if !validGoPublishingAliasReplay(
		current, transition.claimTimestamp, transition.desired,
	) || !transition.bindingMatches(current) {
		return StatusAmbiguous
	}
	proof, matches, err := aliasReplayBindingMatchesGeneration(
		h.aliasReplayGenerationMaps(), aliasReplayGenerationAuthority{
			claimPresent:          true,
			claim:                 claim,
			ambiguity:             transition.ambiguity,
			requireOldIndex:       true,
			requireOldIncarnation: true,
		}, key, state, current,
	)
	if err != nil {
		return StatusTransportError
	}
	if !matches {
		if proof.successorRequired {
			return StatusOverload
		}
		return StatusAmbiguous
	}
	transition.generation = proof
	return StatusValid
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
		) || !transition.bindingMatches(currentReplay) {
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
	) || !transition.bindingMatches(currentReplay) {
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
	if aliasReplayProofValueEqual(currentReplay, staleReplay) &&
		transition.bindingMatches(currentReplay) {
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
		) && transition.bindingMatches(current) {
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
				!validActiveAliasReplay(current) || !transition.bindingMatches(current) {
				return false
			}
			_ = updateErr
		} else if !validActiveAliasReplay(current) || !transition.bindingMatches(current) {
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
	markedAt, present, err := aliasReplayLookup[stateKey, uint64](h.ambiguity, key)
	if err != nil {
		return nil, nil, StatusTransportError
	}
	if !present {
		return nil, nil, StatusAmbiguous
	}
	generationProof, bindingMatches, err := aliasReplayBindingMatchesGeneration(
		h.aliasReplayGenerationMaps(), aliasReplayGenerationAuthority{
			claimPresent:          true,
			claim:                 claim,
			ambiguity:             markedAt,
			requireOldIndex:       true,
			requireOldIncarnation: true,
		}, key, state, current,
	)
	if err != nil {
		return nil, nil, StatusTransportError
	}
	if !bindingMatches {
		if generationProof.successorRequired {
			return nil, nil, StatusOverload
		}
		return nil, nil, StatusAmbiguous
	}
	// BPF releases a carrier by decrementing replay References before state
	// Aliases. Once the exact final claim is committed, that reachable
	// cross-map window is cleanup state rather than a loss of delivery
	// authority. The immutable generation proof below still fences every
	// binding and lifecycle field; pre-claim lookup continues to require a
	// nonzero reference in activeAliasReplay.
	if validFinalAliasReplay(current) {
		if current.Lifecycle != lifecycle {
			return nil, nil, StatusAmbiguous
		}
		return nil, &aliasReplayFinishProof{
			key:        replayKey,
			value:      aliasReplayProofValue(current),
			generation: generationProof,
		}, StatusValid
	}

	transition := &aliasReplayTransition{
		key:        replayKey,
		binding:    aliasReplayBindingOf(current),
		generation: generationProof,
		ambiguity:  markedAt,
	}
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
	) && transition.bindingMatches(current) {
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
		if h.aliasReplayFinishProofValueValid(existingProof) {
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
		if current.Lifecycle != lifecycle || !transition.bindingMatches(current) {
			return nil, StatusAmbiguous
		}
		return &aliasReplayFinishProof{
			key:        transition.key,
			value:      aliasReplayProofValue(current),
			generation: transition.generation,
		}, StatusValid
	}
	if !validGoPublishingAliasReplay(
		current, transition.claimTimestamp, transition.desired,
	) || !transition.bindingMatches(current) {
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
	if validFinalAliasReplay(current) && current.Lifecycle == lifecycle &&
		transition.bindingMatches(current) {
		return &aliasReplayFinishProof{
			key:        transition.key,
			value:      aliasReplayProofValue(current),
			generation: transition.generation,
		}, StatusValid
	}
	if updateErr != nil {
		return nil, StatusTransportError
	}
	return nil, statusForAliasReplay(current)
}

func (h *MapHandler) aliasReplayFinishProofValueValid(
	proof *aliasReplayFinishProof,
) bool {
	if proof == nil {
		return true
	}
	var current aliasReplayValue
	return h.aliasReplays.Lookup(&proof.key, &current) == nil &&
		validFinalAliasReplay(current) && aliasReplayProofValueEqual(current, proof.value)
}

func (h *MapHandler) aliasReplayFinishProofValid(
	fence generationTeardownFence,
	proof *aliasReplayFinishProof,
) bool {
	if proof == nil {
		return true
	}
	if !h.aliasReplayFinishProofValueValid(proof) {
		proof.authorityFailed = true
		return false
	}
	matches, err := aliasReplayGenerationContinuityMatches(
		h.aliasReplayGenerationMaps(), aliasReplayGenerationAuthority{
			claimPresent:          true,
			claim:                 fence.claim,
			guardPresent:          true,
			guard:                 fence.guardClaim,
			ambiguity:             fence.markedAt,
			requireOldIndex:       true,
			requireOldIncarnation: true,
		}, fence.key, proof.generation.oldState, proof.value, &proof.generation,
	)
	if err != nil || !matches {
		proof.authorityFailed = true
		return false
	}
	return true
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
	var replayTransitionForResult *aliasReplayTransition
	var replayProofForResult *aliasReplayFinishProof
	defer func() {
		if (replayTransitionForResult != nil &&
			(replayTransitionForResult.generation.successor ||
				replayTransitionForResult.generation.successorRequired)) ||
			(replayProofForResult != nil &&
				(replayProofForResult.generation.successor ||
					replayProofForResult.generation.successorRequired)) {
			result.successorRequired = true
		}
		if replayProofForResult != nil && replayProofForResult.authorityFailed {
			result.deliveryAuthorityFailed = true
		}
		if result.successorRequired && !result.complete {
			result.deliveryAuthorityFailed = true
		}
	}()
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
	replayTransitionForResult = replayTransition
	replayProofForResult = existingReplayProof
	if replayStatus != StatusValid {
		result.deliveryAuthorityFailed = state.Aliases > 0
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
	if err := h.states.Lookup(&key, &currentState); err != nil ||
		!aliasReplayProofStateEqual(currentState, state) ||
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
	replayProofForResult = replayProof
	if replayStatus != StatusValid ||
		!h.finishBarriersValid(fence, publishedTerminal, replayProof) {
		if replayStatus != StatusValid && (replayTransition != nil || existingReplayProof != nil) {
			result.deliveryAuthorityFailed = true
		}
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
		(len(replayProof) == 1 && !h.aliasReplayFinishProofValid(fence, replayProof[0])) {
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
	if replayProof != nil && replayProof.generation.successor {
		graph := replayProof.generation.graph
		if graph.binding.Connection != connection ||
			graph.binding.ConnectionNetNS != connectionNetNS {
			return proof, false
		}
		proof.cookieKey = connectionInfoNetNSCookie{
			Connection:  connection,
			NetNSCookie: graph.binding.ConnectionNetNSCookie,
		}
		// A same-socket successor owns both physical indexes. Preserve them and
		// prove their complete logical graph under old E/G instead of attempting
		// an old-generation delete against reusable C keys.
		if !h.finishBarriersValid(fence, terminal, replayProof) ||
			!h.connectionGenerationReleased(
				h.connections, proof.connectionKey, fence.key.Owner, fence.key.Generation,
			) || !h.connectionGenerationReleased(
			h.cookieConnections, proof.cookieKey, fence.key.Owner, fence.key.Generation,
		) || !h.finishBarriersValid(fence, terminal, replayProof) {
			return proof, false
		}
		return proof, true
	}
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
