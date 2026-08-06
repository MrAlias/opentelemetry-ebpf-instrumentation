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
		h.owners == nil || h.states == nil || h.generations == nil || h.terminals == nil || h.claims == nil {
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
		committed := h.consume(ctx, candidates, lifecycleAmbiguous)
		if !committed && requestCanceled(ctx) {
			return Record{Status: StatusTimeout}
		}
		h.markConsumed(identity, processIncarnation)
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
	if candidate.Lifecycle != 0 {
		return Record{Status: statusForLifecycle(candidate.Lifecycle)}
	}
	encoded, status := h.readCandidate(candidate)
	if status != StatusValid {
		return Record{Status: status}
	}

	record, err := UnmarshalRecord(encoded[:])
	if err != nil {
		committed, quarantineErr := h.quarantineMalformedFallback(
			ctx, owner, encoded, processIncarnation,
		)
		if quarantineErr != nil {
			return Record{Status: StatusTransportError}
		}
		if !committed && requestCanceled(ctx) {
			return Record{Status: StatusTimeout}
		}
		if errors.Is(err, ErrVersionMismatch) {
			return Record{Status: StatusVersionMismatch}
		}
		return Record{Status: StatusMalformed}
	}
	if record.Status != StatusValid {
		committed := h.consume(ctx, []resolvedCandidate{candidate}, lifecycleForStatus(record.Status))
		if !committed && requestCanceled(ctx) {
			return Record{Status: StatusTimeout}
		}
		return Record{Status: record.Status}
	}
	if !record.IsValidRemoteParent() {
		committed := h.consume(ctx, []resolvedCandidate{candidate}, lifecycleDiscarded)
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
		owner, record, encoded, processIncarnation, StatusMissing, false, candidate.StateOnly,
	); status != StatusValid {
		return Record{Status: status}
	}

	lifecycle := lifecycleConsumed
	if operation == OperationDiscard {
		lifecycle = lifecycleDiscarded
	}
	key := stateKey{Owner: owner, Generation: record.Generation}
	claim, ok := h.newGenerationClaim(lifecycle, processIncarnation)
	if !ok {
		return Record{Status: StatusTransportError}
	}
	if requestCanceled(ctx) {
		return Record{Status: StatusTimeout}
	}
	// Acquiring the claim commits the one-shot operation. Once it succeeds,
	// cleanup must finish and report the real outcome even if the deadline crosses.
	if err := h.claims.Update(&key, &claim, ebpf.UpdateNoExist); err != nil {
		if errors.Is(err, ebpf.ErrKeyExist) {
			var claimed generationClaim
			if lookupErr := h.claims.Lookup(&key, &claimed); lookupErr != nil {
				return Record{Status: StatusTransportError}
			}
			if claimed.Lifecycle == lifecycleAmbiguous {
				return Record{Status: StatusAmbiguous}
			}
			h.markConsumed(identity, processIncarnation)
			h.markConsumed(owner, processIncarnation)
			return Record{Status: StatusAlreadyConsumed}
		}
		if requestCanceled(ctx) {
			return Record{Status: StatusTimeout}
		}
		return Record{Status: StatusTransportError}
	}

	state, claimedRecord, status := h.validatePublishedGeneration(
		owner, record, encoded, processIncarnation, StatusAlreadyConsumed, false, candidate.StateOnly,
	)
	if status != StatusValid {
		if status == StatusAlreadyConsumed || status == StatusTransportError {
			_ = h.claims.Delete(&key)
			return Record{Status: status}
		}
		terminalLifecycle := lifecycleAmbiguous
		if status == StatusMissing {
			terminalLifecycle = lifecycleDiscarded
		}
		h.finish(owner, record, processIncarnation, terminalLifecycle)
		return Record{Status: status}
	}
	record = claimedRecord
	h.markConsumed(identity, processIncarnation)
	h.markConsumed(owner, processIncarnation)

	if now := h.monoTimeNow(); now <= 0 || state.ObservedMonotonicNS == 0 ||
		uint64(now) < state.ObservedMonotonicNS ||
		time.Duration(uint64(now)-state.ObservedMonotonicNS) > h.ttl {
		h.finish(owner, record, processIncarnation, lifecycleStale)
		return Record{Status: StatusStale}
	}
	if !h.finish(owner, record, processIncarnation, lifecycle) {
		return Record{Status: StatusTransportError}
	}
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
	owner Identity,
	record Record,
	encoded [RecordSize]byte,
	processIncarnation uint64,
	ownerMissingStatus Status,
	allowAmbiguous bool,
	stateOnly bool,
) (stateValue, Record, Status) {
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
		state.ObservedMonotonicNS == 0 {
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
	} else {
		return stateValue{}, Record{}, StatusTransportError
	}

	var connection connectionClaim
	connectionKey := connectionInfoNS{
		Connection: state.Connection,
		NetNS:      state.ConnectionNetNS,
	}
	if err := h.connections.Lookup(&connectionKey, &connection); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return stateValue{}, Record{}, StatusAmbiguous
		}
		return stateValue{}, Record{}, StatusTransportError
	}
	if !validConnectionClaim(connection, owner, record.Generation, state.ConnectionNetNS) {
		return stateValue{}, Record{}, StatusAmbiguous
	}
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
	if !h.currentTaskLink(link) {
		return nil, false, false
	}
	linked, found, failed := h.resolveOwner(
		link.Owner, link.Generation, processIncarnation, true,
	)
	if failed {
		return nil, false, true
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
		return resolvedCandidate{}, false, !errors.Is(err, ebpf.ErrKeyNotExist)
	}
	if terminal.Generation == 0 || terminal.Reserved != ([7]byte{}) ||
		terminal.Generation != expectedGeneration {
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

func (h *MapHandler) currentTaskLink(link taskLink) bool {
	now := h.monoTimeNow()
	return now > 0 && link.Owner != (Identity{}) && link.Reserved == 0 && link.Generation > 0 &&
		link.ObservedMonotonicNS > 0 &&
		uint64(now) >= link.ObservedMonotonicNS &&
		time.Duration(uint64(now)-link.ObservedMonotonicNS) <= h.ttl
}

func (h *MapHandler) consume(
	ctx context.Context,
	candidates []resolvedCandidate,
	lifecycle uint8,
) bool {
	committed := false
	for _, candidate := range candidates {
		if !committed && requestCanceled(ctx) {
			return false
		}
		if candidate.ProcessIncarnation == 0 {
			continue
		}
		encoded := candidate.Encoded
		record, err := UnmarshalRecord(encoded[:])
		if err != nil {
			quarantined, _ := h.quarantineMalformedFallback(
				ctx, candidate.Owner, encoded, candidate.ProcessIncarnation,
			)
			committed = committed || quarantined
			continue
		}
		if candidate.Generation == 0 || record.Generation != candidate.Generation {
			continue
		}
		if _, _, status := h.validatePublishedGeneration(
			candidate.Owner,
			record,
			encoded,
			candidate.ProcessIncarnation,
			StatusMissing,
			true,
			candidate.StateOnly,
		); status != StatusValid {
			continue
		}

		key := stateKey{Owner: candidate.Owner, Generation: candidate.Generation}
		claim, ok := h.newGenerationClaim(lifecycle, candidate.ProcessIncarnation)
		if !ok {
			continue
		}
		if !committed && requestCanceled(ctx) {
			return false
		}
		if err := h.claims.Update(&key, &claim, ebpf.UpdateNoExist); err != nil {
			continue
		}
		committed = true
		if _, _, status := h.validatePublishedGeneration(
			candidate.Owner,
			record,
			encoded,
			candidate.ProcessIncarnation,
			StatusAlreadyConsumed,
			true,
			candidate.StateOnly,
		); status != StatusValid {
			_ = h.claims.Delete(&key)
			continue
		}
		if h.finish(
			candidate.Owner,
			record,
			candidate.ProcessIncarnation,
			lifecycle,
		) {
			h.markConsumed(candidate.Owner, candidate.ProcessIncarnation)
		}
	}
	return committed
}

func (h *MapHandler) quarantineMalformedFallback(
	ctx context.Context,
	owner Identity,
	encoded [RecordSize]byte,
	processIncarnation uint64,
) (bool, error) {
	currentIncarnation, status := h.processIncarnation(owner)
	if status == StatusTransportError {
		return false, errors.New("looking up process incarnation")
	}
	if status != StatusValid || currentIncarnation != processIncarnation {
		return false, nil
	}

	var indexed ownerValue
	if err := h.owners.Lookup(&owner, &indexed); err != nil {
		if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, err
		}
		if requestCanceled(ctx) {
			return false, nil
		}
		deleted, deleteErr := cleanupDeleteExact(h.remoteParents, owner, encoded)
		return deleted, deleteErr
	}
	if indexed.Generation == 0 || indexed.Reserved != ([7]byte{}) ||
		indexed.ProcessIncarnation != processIncarnation {
		if requestCanceled(ctx) {
			return false, nil
		}
		deleted, deleteErr := cleanupDeleteExact(h.remoteParents, owner, encoded)
		if deleteErr != nil || !deleted {
			return false, deleteErr
		}
		_, deleteErr = cleanupDeleteExact(h.owners, owner, indexed)
		return true, deleteErr
	}

	key := stateKey{Owner: owner, Generation: indexed.Generation}
	claim, ok := h.newGenerationClaim(lifecycleDiscarded, processIncarnation)
	if !ok {
		return false, errors.New("reading monotonic time for malformed fallback claim")
	}
	if requestCanceled(ctx) {
		return false, nil
	}
	if err := h.claims.Update(&key, &claim, ebpf.UpdateNoExist); err != nil {
		if !errors.Is(err, ebpf.ErrKeyExist) {
			if requestCanceled(ctx) {
				return false, nil
			}
			return false, err
		}
		if requestCanceled(ctx) {
			return false, nil
		}
		deleted, deleteErr := cleanupDeleteExact(h.remoteParents, owner, encoded)
		return deleted, deleteErr
	}
	defer func() {
		_ = h.claims.Delete(&key)
	}()

	currentIncarnation, status = h.processIncarnation(owner)
	if status == StatusTransportError {
		return true, errors.New("revalidating process incarnation")
	}
	if status != StatusValid || currentIncarnation != processIncarnation {
		return true, nil
	}
	var revalidated ownerValue
	if err := h.owners.Lookup(&owner, &revalidated); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return true, nil
		}
		return true, err
	}
	if revalidated != indexed {
		return true, nil
	}

	deleted, err := cleanupDeleteExact(h.remoteParents, owner, encoded)
	if err != nil || !deleted {
		return true, err
	}

	observedMonotonicNS := uint64(0)
	var generation generationIndexValue
	if err := h.generations.Lookup(&key, &generation); err == nil {
		if generation.Process == javaProcessIdentity(owner) && generation.Reserved == 0 &&
			generation.ProcessIncarnation == processIncarnation {
			observedMonotonicNS = generation.ObservedMonotonicNS
		}
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return true, err
	}
	if observedMonotonicNS == 0 {
		now := h.monoTimeNow()
		if now > 0 {
			observedMonotonicNS = uint64(now)
		}
	}

	if !h.finish(owner, Record{
		Generation:          indexed.Generation,
		ObservedMonotonicNS: observedMonotonicNS,
	}, processIncarnation, lifecycleDiscarded) {
		return true, errors.New("cleaning malformed fallback generation")
	}
	h.markConsumed(owner, processIncarnation)
	return true, nil
}

func requestCanceled(ctx context.Context) bool {
	return ctx != nil && ctx.Err() != nil
}

func (h *MapHandler) newGenerationClaim(
	lifecycle uint8,
	processIncarnation uint64,
) (generationClaim, bool) {
	now := h.monoTimeNow()
	if now <= 0 || processIncarnation == 0 {
		return generationClaim{}, false
	}
	return generationClaim{
		ObservedMonotonicNS: uint64(now),
		ProcessIncarnation:  processIncarnation,
		Lifecycle:           lifecycle,
	}, true
}

func (h *MapHandler) finish(
	owner Identity,
	record Record,
	processIncarnation uint64,
	lifecycle uint8,
) bool {
	generation := record.Generation
	if generation == 0 || processIncarnation == 0 {
		return false
	}
	if current, status := h.processIncarnation(owner); status != StatusValid ||
		current != processIncarnation {
		return false
	}
	key := stateKey{Owner: owner, Generation: generation}
	defer func() {
		_ = h.claims.Delete(&key)
	}()

	var indexed ownerValue
	ownerErr := h.owners.Lookup(&owner, &indexed)
	if ownerErr != nil && !errors.Is(ownerErr, ebpf.ErrKeyNotExist) {
		return false
	}

	var state stateValue
	stateErr := h.states.Lookup(&key, &state)
	if stateErr != nil && !errors.Is(stateErr, ebpf.ErrKeyNotExist) {
		return false
	}
	ownsGeneration := ownerErr == nil && generation == indexed.Generation &&
		processIncarnation == indexed.ProcessIncarnation
	if ownerErr == nil && !ownsGeneration &&
		(stateErr != nil || state.ProcessIncarnation != processIncarnation ||
			state.Lifecycle != lifecycleActive || state.Reserved != ([3]byte{})) {
		return false
	}
	observedMonotonicNS := record.ObservedMonotonicNS
	if stateErr == nil {
		if state.ProcessIncarnation != processIncarnation {
			return false
		}
		observedMonotonicNS = state.ObservedMonotonicNS
		if !h.releaseConnection(owner, generation, state.Connection, state.ConnectionNetNS) {
			return false
		}
	}
	if current, status := h.processIncarnation(owner); status != StatusValid ||
		current != processIncarnation {
		return false
	}
	terminal := terminalValue{
		Generation:          generation,
		ObservedMonotonicNS: observedMonotonicNS,
		ProcessIncarnation:  processIncarnation,
		Lifecycle:           lifecycle,
	}
	if err := h.terminals.Update(&owner, &terminal, ebpf.UpdateAny); err != nil {
		return false
	}
	if deleteErr := h.states.Delete(&key); deleteErr != nil &&
		!errors.Is(deleteErr, ebpf.ErrKeyNotExist) {
		return false
	}
	if !h.deleteRemoteParentGeneration(owner, generation, processIncarnation) {
		return false
	}
	if deleteErr := h.ambiguity.Delete(&key); deleteErr != nil &&
		!errors.Is(deleteErr, ebpf.ErrKeyNotExist) {
		return false
	}
	if !h.deleteGenerationIndex(key, processIncarnation) {
		return false
	}
	if ownsGeneration {
		if !h.deleteOwnerGeneration(owner, generation, processIncarnation) {
			return false
		}
	}
	return true
}

func (h *MapHandler) deleteGenerationIndex(key stateKey, processIncarnation uint64) bool {
	var current generationIndexValue
	if err := h.generations.Lookup(&key, &current); err != nil {
		return errors.Is(err, ebpf.ErrKeyNotExist)
	}
	if current.Process != javaProcessIdentity(key.Owner) || current.Reserved != 0 ||
		current.ProcessIncarnation != processIncarnation {
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
	if currentErr != nil {
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

	_, err := cleanupDeleteExact(h.remoteParents, owner, current)
	return err == nil
}

func (h *MapHandler) deleteOwnerGeneration(
	owner Identity,
	generation uint64,
	processIncarnation uint64,
) bool {
	var current ownerValue
	if err := h.owners.Lookup(&owner, &current); err != nil {
		return errors.Is(err, ebpf.ErrKeyNotExist)
	}
	if current.Generation != generation || current.ProcessIncarnation != processIncarnation {
		return false
	}

	deleted, err := cleanupDeleteExact(h.owners, owner, current)
	return err == nil && deleted
}

func (h *MapHandler) releaseConnection(
	owner Identity,
	generation uint64,
	connection connectionInfo,
	connectionNetNS uint32,
) bool {
	connectionKey := connectionInfoNS{Connection: connection, NetNS: connectionNetNS}
	var claim connectionClaim
	if err := h.connections.Lookup(&connectionKey, &claim); err != nil {
		return errors.Is(err, ebpf.ErrKeyNotExist)
	}
	if claim.Owner != owner || claim.Generation != generation {
		return true
	}
	cookieKey := connectionInfoNetNSCookie{
		Connection:  connection,
		NetNSCookie: claim.NetNSCookie,
	}
	if _, err := cleanupDeleteExact(h.cookieConnections, cookieKey, claim); err != nil {
		return false
	}
	_, err := cleanupDeleteExact(h.connections, connectionKey, claim)
	return err == nil
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
