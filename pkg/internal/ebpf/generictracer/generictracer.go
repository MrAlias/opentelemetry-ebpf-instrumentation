// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	jvmruntime "go.opentelemetry.io/obi/pkg/appolly/app/runtime"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/config"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/internal/javabridge"
	"go.opentelemetry.io/obi/pkg/internal/netns"
	"go.opentelemetry.io/obi/pkg/internal/netolly/ifaces"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 Bpf ../../../../bpf/generictracer/generictracer.c -- -I../../../../bpf

type Tracer struct {
	pidsFilter               ebpfcommon.ServiceFilter
	cfg                      *obi.Config
	metrics                  imetrics.Reporter
	bpfObjects               BpfObjects
	closers                  []io.Closer
	log                      *slog.Logger
	qdiscs                   map[ifaces.Interface]*netlink.GenericQdisc
	egressFilters            map[ifaces.Interface]*netlink.BpfFilter
	ingressFilters           map[ifaces.Interface]*netlink.BpfFilter
	instrumentedLibs         ebpfcommon.InstrumentedLibsT
	libsMux                  sync.Mutex
	iters                    []*ebpfcommon.Iter
	eventCtx                 *ebpfcommon.EBPFEventContext
	jvmUSDTManager           ebpfcommon.USDTSpecManager
	javaLifecycleMu          sync.Mutex
	javaWorkersMu            sync.Mutex
	javaWorkersCtx           context.Context
	javaWorkersCancel        context.CancelFunc
	javaWorkersWG            sync.WaitGroup
	javaWorkersStopping      bool
	javaPendingWorkerStarted bool
	javaAuthMu               sync.Mutex
	javaAuthPublications     javaAuthorizationPublicationCoordinator
	javaAuthKeys             map[javaAuthorizationKey][]javaAuthorization
	javaDeauthPending        map[javaAuthorizationKey]map[javaAuthorization]struct{}
	javaAuthAttempts         map[javaAuthorizationKey]javaAuthorization
	javaAuthAttemptFiles     map[javaAuthorizationKey]*exec.FileInfo
	javaAuthAttemptEvents    map[javaAuthorizationKey]*javaAuthorizationEvent
	javaAuthFiles            map[javaAuthorizationKey]*exec.FileInfo
	javaAuthEvents           map[javaAuthorizationKey][]*javaAuthorizationEvent
	javaAuthLatest           map[javaAuthorizationKey]uint64
	javaAuthVersions         map[javaAuthorizationKey]uint64
	javaAuthSequence         uint64
	javaSuspendPending       map[javaAuthorizationKey]map[javaAuthorization]struct{}
	javaRemoteParentEnabled  bool
	javaDataHookAttached     bool
	javaCloseHookAttached    bool
	haveSockOpsNetnsCookie   func() error
}

type javaAuthorizationKey struct {
	pid app.PID
	ns  uint32
}

type javaAuthorization struct {
	identity   javabridge.Identity
	capability uint64
}

type javaAuthorizationPublicationCoordinator struct {
	mu    sync.Mutex
	locks map[javaAuthorizationKey]*javaAuthorizationPublicationLock
}

type javaAuthorizationPublicationLock struct {
	mu   sync.Mutex
	refs uint64
}

func (c *javaAuthorizationPublicationCoordinator) lock(
	key javaAuthorizationKey,
) func() {
	c.mu.Lock()
	if c.locks == nil {
		c.locks = make(map[javaAuthorizationKey]*javaAuthorizationPublicationLock)
	}
	publicationLock := c.locks[key]
	if publicationLock == nil {
		publicationLock = &javaAuthorizationPublicationLock{}
		c.locks[key] = publicationLock
	}
	publicationLock.refs++
	c.mu.Unlock()

	publicationLock.mu.Lock()
	return func() {
		publicationLock.mu.Unlock()
		c.mu.Lock()
		defer c.mu.Unlock()
		publicationLock.refs--
		if publicationLock.refs == 0 && c.locks[key] == publicationLock {
			delete(c.locks, key)
		}
	}
}

type orderedResourceCloser struct {
	once        sync.Once
	beforeClose func()
	closers     []io.Closer
	err         error
}

func newOrderedResourceCloser(beforeClose func(), closers ...io.Closer) *orderedResourceCloser {
	return &orderedResourceCloser{
		beforeClose: beforeClose,
		closers:     append([]io.Closer(nil), closers...),
	}
}

func (c *orderedResourceCloser) Close() error {
	c.once.Do(func() {
		if c.beforeClose != nil {
			c.beforeClose()
		}

		errs := make([]error, len(c.closers))
		var wg sync.WaitGroup
		for i, closer := range c.closers {
			if closer == nil {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = closer.Close()
			}()
		}
		wg.Wait()
		c.err = errors.Join(errs...)
	})
	return c.err
}

// javaAuthorizationEvent is one exact FileInfo process lifetime. Even an
// ineligible or failed Java authorization retains a tombstone until the BlockPID
// carrying that same FileInfo arrives. A reused pid/ns can therefore never make
// a delayed deletion consume or deauthorize its replacement.
type javaAuthorizationEvent struct {
	sequence            uint64
	requestedCapability uint64
	authorizationGens   []uint64
	authorization       javaAuthorization
	file                *exec.FileInfo
	prepared            bool
	authorizing         bool
	confirmed           bool
	canceled            bool
}

var (
	// Cleanup runs at most every ten seconds. A tagged userspace P(process)
	// left by an ambiguous map transaction must receive one complete recovery
	// sweep before a one-shot discovery lifetime gives up authorization.
	javaAuthorizationRetryTimeout    = 11 * time.Second
	javaAuthorizationRetryInterval   = 10 * time.Millisecond
	javaDeauthorizationRetryInterval = time.Second
)

var (
	findJavaNamespacedPIDs         = procs.FindNamespacedPids
	findJavaNamespacedPIDsForOwner = ebpfcommon.NamespacedPIDsForOwner
	validateJavaProcessOwner       = ebpfcommon.ValidateProcessOwner
)

var updateJavaRemoteParentDataHookReadiness = func(readiness *ebpf.Map, state uint32) error {
	key := uint32(0)
	return readiness.Update(&key, &state, ebpf.UpdateAny)
}

var updateJavaRemoteParentControlTailReadiness = func(readiness *ebpf.Map, state uint32) error {
	key := uint32(0)
	return readiness.Update(&key, &state, ebpf.UpdateAny)
}

var (
	authorizeJavaProcessCapability   = javabridge.AuthorizeProcessCapability
	deauthorizeJavaProcessCapability = javabridge.DeauthorizeProcessCapability
	suspendJavaProcessAuthorization  = javabridge.SuspendProcessAuthorization
	generateJavaProcessCapability    = newJavaProcessCapability
	updateJavaAuthorizedProcess      = func(
		m *ebpf.Map, identity javabridge.Identity, capability uint64,
	) error {
		return m.Update(&identity, capability, ebpf.UpdateAny)
	}
	lockJavaAuthorizationPublication = func(
		coordinator *javaAuthorizationPublicationCoordinator,
		key javaAuthorizationKey,
	) func() {
		return coordinator.lock(key)
	}
)

func tlog() *slog.Logger {
	return slog.With("component", "generic.Tracer")
}

func New(pidFilter ebpfcommon.ServiceFilter, cfg *obi.Config, metrics imetrics.Reporter) *Tracer {
	return &Tracer{
		log:                    tlog(),
		cfg:                    cfg,
		metrics:                metrics,
		pidsFilter:             pidFilter,
		qdiscs:                 map[ifaces.Interface]*netlink.GenericQdisc{},
		egressFilters:          map[ifaces.Interface]*netlink.BpfFilter{},
		ingressFilters:         map[ifaces.Interface]*netlink.BpfFilter{},
		instrumentedLibs:       make(ebpfcommon.InstrumentedLibsT),
		libsMux:                sync.Mutex{},
		iters:                  []*ebpfcommon.Iter{},
		javaAuthKeys:           make(map[javaAuthorizationKey][]javaAuthorization),
		javaDeauthPending:      make(map[javaAuthorizationKey]map[javaAuthorization]struct{}),
		javaAuthAttempts:       make(map[javaAuthorizationKey]javaAuthorization),
		javaAuthAttemptFiles:   make(map[javaAuthorizationKey]*exec.FileInfo),
		javaAuthAttemptEvents:  make(map[javaAuthorizationKey]*javaAuthorizationEvent),
		javaAuthFiles:          make(map[javaAuthorizationKey]*exec.FileInfo),
		javaAuthEvents:         make(map[javaAuthorizationKey][]*javaAuthorizationEvent),
		javaAuthLatest:         make(map[javaAuthorizationKey]uint64),
		javaAuthVersions:       make(map[javaAuthorizationKey]uint64),
		javaSuspendPending:     make(map[javaAuthorizationKey]map[javaAuthorization]struct{}),
		haveSockOpsNetnsCookie: javabridge.HaveSockOpsNetnsCookie,
	}
}

func (p *Tracer) startJavaWorker(worker func(context.Context)) bool {
	p.javaWorkersMu.Lock()
	defer p.javaWorkersMu.Unlock()
	if p.javaWorkersStopping {
		return false
	}
	if p.javaWorkersCtx == nil {
		p.javaWorkersCtx, p.javaWorkersCancel = context.WithCancel(context.Background())
	}
	ctx := p.javaWorkersCtx
	p.javaWorkersWG.Add(1)
	go func() {
		defer p.javaWorkersWG.Done()
		worker(ctx)
	}()
	return true
}

func (p *Tracer) startPendingJavaDeauthorizationWorker() bool {
	p.javaWorkersMu.Lock()
	defer p.javaWorkersMu.Unlock()
	if p.javaWorkersStopping || p.javaPendingWorkerStarted {
		return false
	}
	if p.javaWorkersCtx == nil {
		p.javaWorkersCtx, p.javaWorkersCancel = context.WithCancel(context.Background())
	}
	p.javaPendingWorkerStarted = true
	ctx := p.javaWorkersCtx
	p.javaWorkersWG.Add(1)
	go func() {
		defer p.javaWorkersWG.Done()
		p.runPendingJavaDeauthorizations(ctx)
	}()
	return true
}

func (p *Tracer) javaWorkersAreStopping() bool {
	p.javaWorkersMu.Lock()
	defer p.javaWorkersMu.Unlock()
	return p.javaWorkersStopping
}

func (p *Tracer) stopJavaWorkers() {
	p.javaLifecycleMu.Lock()
	p.javaWorkersMu.Lock()
	p.javaWorkersStopping = true
	cancel := p.javaWorkersCancel
	p.javaWorkersMu.Unlock()
	p.javaLifecycleMu.Unlock()

	if cancel != nil {
		cancel()
	}
	p.javaWorkersWG.Wait()
	// Authorization workers can record an exact cleanup after the periodic
	// worker observes cancellation. Reconcile once after every worker has joined.
	p.retryPendingJavaDeauthorizations()
}

func failJavaAuthorizationFile(fi *exec.FileInfo) {
	if fi == nil {
		return
	}
	_, generation := fi.BeginJavaAgentAuthorization()
	fi.CompleteJavaAgentAuthorization(generation, 0)
	fi.SetJavaAgentCapability(0)
}

// Keep in sync with the BPF side, which asserts the relation between both
// constants at compile time (bpf/pid/pid.h).
const (
	// mirrors k_max_concurrent_pids (bpf/pid/maps/map_sizing.h): estimate of
	// 1000 concurrent processes (including children) * 3 namespaces per pid
	maxConcurrentPids = 3001
	// mirrors k_prime_hash (bpf/pid/pid.h): closest prime below
	// maxConcurrentPids * 64; modulo by a prime distributes the hash evenly
	// across the segment bit array
	primeHash = 192053
)

func pidSegmentBit(k uint64) (uint32, uint32) {
	h := uint32(k % primeHash)
	segment := h / 64
	bit := h & 63

	return segment, bit
}

func (p *Tracer) buildPidFilter() []uint64 {
	result := make([]uint64, maxConcurrentPids)
	for nsid, pids := range p.pidsFilter.CurrentPIDs(ebpfcommon.PIDTypeKProbes) {
		for pid := range pids {
			// skip any pids that might've been added, but are not tracked by the kprobes
			p.log.Debug("Reallowing pid", "pid", pid, "namespace", nsid)

			k := (uint64(nsid) << 32) | uint64(pid)

			segment, bit := pidSegmentBit(k)

			v := result[segment]
			v |= (1 << bit)
			result[segment] = v
		}
	}

	return result
}

// validateValidPidsMap ensures the loaded map matches the index space written
// by rebuildValidPids: a smaller map makes pid_matches() lookups miss and fail
// open, while a larger one leaves segments unset, silently filtering out
// matching PIDs.
func (p *Tracer) validateValidPidsMap() error {
	if got := p.bpfObjects.ValidPids.MaxEntries(); got != maxConcurrentPids {
		return fmt.Errorf(
			"valid_pids BPF map holds %d entries, expected %d: BPF and userspace PID filter constants have diverged",
			got, maxConcurrentPids)
	}

	return nil
}

func (p *Tracer) rebuildValidPids() error {
	if p.bpfObjects.ValidPids == nil {
		return nil
	}

	v := p.buildPidFilter()

	p.log.Debug("number of segments in pid filter cache", "len", len(v))

	for i, segment := range v {
		if err := p.bpfObjects.ValidPids.Put(uint32(i), segment); err != nil {
			return fmt.Errorf("setting up pid segment %d in BPF space: %w", i, err)
		}
	}

	return nil
}

func (p *Tracer) AllowPID(
	pid app.PID,
	ns uint32,
	fi *exec.FileInfo,
	owner *exec.FileInfo,
) bool {
	if owner == nil {
		owner = fi
	}
	p.javaLifecycleMu.Lock()
	defer p.javaLifecycleMu.Unlock()
	if p.javaWorkersAreStopping() {
		if fi != nil && pid == fi.Pid() {
			failJavaAuthorizationFile(fi)
		}
		return false
	}
	if !p.pidsFilter.AllowPID(pid, ns, fi, owner, ebpfcommon.PIDTypeKProbes) {
		if fi != nil && pid == fi.Pid() {
			failJavaAuthorizationFile(fi)
		}
		return false
	}
	var event *javaAuthorizationEvent
	created := false
	if fi != nil && pid == fi.Pid() {
		event, created = p.beginJavaAuthorizationEvent(
			javaAuthorizationKey{pid: pid, ns: ns}, fi,
		)
		if created && !p.supersedeJavaAuthorizationEvent(
			javaAuthorizationKey{pid: pid, ns: ns}, event, fi,
		) {
			created = false
		}
	}
	if err := p.rebuildValidPids(); err != nil {
		p.log.Error("rebuilding the BPF PID filter", "error", err)
		if created {
			p.completeJavaAuthorizationEvent(fi, event, 0)
		}
		return true
	}
	// Invalidate either sign of a cached decision. Writing a positive entry here
	// would bypass the rebuilt valid_pids set even when exact-owner admission
	// failed during a PID-reuse race. The next BPF event recomputes and caches the
	// decision from the committed filter state.
	if p.bpfObjects.PidCache != nil {
		pidU32 := uint32(pid)
		_ = p.bpfObjects.PidCache.Delete(pidU32)
	}
	if created {
		started := p.startJavaWorker(func(ctx context.Context) {
			p.authorizeJavaProcessForEventContext(ctx, pid, ns, fi, event)
		})
		if !started {
			p.completeJavaAuthorizationEvent(fi, event, 0)
		}
	}
	return true
}

func (p *Tracer) BlockPID(
	pid app.PID,
	ns uint32,
	fi *exec.FileInfo,
	owner *exec.FileInfo,
) {
	if owner == nil {
		owner = fi
	}
	p.javaLifecycleMu.Lock()
	defer p.javaLifecycleMu.Unlock()
	if p.javaWorkersAreStopping() {
		if fi != nil && pid == fi.Pid() {
			failJavaAuthorizationFile(fi)
		}
		return
	}
	p.pidsFilter.BlockPID(pid, ns, fi, owner)
	if err := p.rebuildValidPids(); err != nil {
		p.log.Error("rebuilding the BPF PID filter", "error", err)
	}
	p.deauthorizeJavaProcess(pid, ns, fi)
	// Remove from cache so next access re-evaluates
	if p.bpfObjects.PidCache != nil {
		pidU32 := uint32(pid)
		_ = p.bpfObjects.PidCache.Delete(pidU32)
	}
}

func javaProcessIdentity(
	pid app.PID,
	ns uint32,
	owner *exec.FileInfo,
) (javabridge.Identity, error) {
	var namespacePIDs []app.PID
	var err error
	if owner == nil || owner.ProcessStartTime() == 0 {
		namespacePIDs, err = findJavaNamespacedPIDs(pid)
	} else {
		namespacePIDs, err = findJavaNamespacedPIDsForOwner(pid, owner)
	}
	if err != nil {
		return javabridge.Identity{}, err
	}
	if len(namespacePIDs) != 0 {
		pid = namespacePIDs[len(namespacePIDs)-1]
	}

	namespacePID := uint32(pid)
	return javabridge.Identity{TID: namespacePID, PID: namespacePID, Namespace: ns}, nil
}

func validateJavaProcessLifetime(pid app.PID, fi *exec.FileInfo) error {
	if fi == nil || fi.ProcessStartTime() == 0 {
		return nil
	}
	if err := validateJavaProcessOwner(pid, fi); err != nil {
		return fmt.Errorf("revalidating Java process lifetime: %w", err)
	}
	return nil
}

func waitJavaAuthorizationRetry(ctx context.Context, interval time.Duration) bool {
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (p *Tracer) ensureJavaAuthorizationStateLocked() {
	if p.javaAuthKeys == nil {
		p.javaAuthKeys = make(map[javaAuthorizationKey][]javaAuthorization)
	}
	if p.javaDeauthPending == nil {
		p.javaDeauthPending = make(
			map[javaAuthorizationKey]map[javaAuthorization]struct{},
		)
	}
	if p.javaAuthAttempts == nil {
		p.javaAuthAttempts = make(map[javaAuthorizationKey]javaAuthorization)
	}
	if p.javaAuthAttemptFiles == nil {
		p.javaAuthAttemptFiles = make(map[javaAuthorizationKey]*exec.FileInfo)
	}
	if p.javaAuthAttemptEvents == nil {
		p.javaAuthAttemptEvents = make(
			map[javaAuthorizationKey]*javaAuthorizationEvent,
		)
	}
	if p.javaAuthFiles == nil {
		p.javaAuthFiles = make(map[javaAuthorizationKey]*exec.FileInfo)
	}
	if p.javaAuthEvents == nil {
		p.javaAuthEvents = make(
			map[javaAuthorizationKey][]*javaAuthorizationEvent,
		)
	}
	if p.javaAuthLatest == nil {
		p.javaAuthLatest = make(map[javaAuthorizationKey]uint64)
	}
	if p.javaAuthVersions == nil {
		p.javaAuthVersions = make(map[javaAuthorizationKey]uint64)
	}
	if p.javaSuspendPending == nil {
		p.javaSuspendPending = make(
			map[javaAuthorizationKey]map[javaAuthorization]struct{},
		)
	}
}

func (p *Tracer) beginJavaAuthorizationEvent(
	key javaAuthorizationKey,
	fi *exec.FileInfo,
) (*javaAuthorizationEvent, bool) {
	p.javaAuthMu.Lock()
	defer p.javaAuthMu.Unlock()
	p.ensureJavaAuthorizationStateLocked()
	events := p.javaAuthEvents[key]
	for index, event := range events {
		if event.file != fi || event.canceled {
			continue
		}
		// One FileInfo is one discovery lifetime and receives one deletion.
		// Repeated AllowPID notifications must not allocate another deletion
		// reference, race a second authorization goroutine, or revive an older
		// lifetime after a pid/ns replacement was observed.
		if event.confirmed || index != len(events)-1 ||
			p.javaAuthLatest[key] != event.sequence {
			_, authorizationGen := fi.BeginJavaAgentAuthorization()
			completionCapability := uint64(0)
			if event.confirmed && index == len(events)-1 &&
				p.javaAuthLatest[key] == event.sequence {
				completionCapability = event.authorization.capability
			}
			fi.CompleteJavaAgentAuthorization(authorizationGen, completionCapability)
			return event, false
		}
		requestedCapability, authorizationGen := fi.BeginJavaAgentAuthorization()
		if event.authorizing {
			event.authorizationGens = appendJavaAuthorizationGeneration(
				event.authorizationGens, authorizationGen,
			)
			return event, false
		}
		// A completed but unconfirmed attempt did not publish the process
		// authorization. Reuse the same discovery-lifetime event and retry the
		// newly prepared capability instead of completing its readiness gate
		// with zero. The previous authorization goroutine has already cleared
		// authorizing while holding javaAuthMu, so replacing these attempt fields
		// cannot race that goroutine.
		if requestedCapability != 0 {
			event.requestedCapability = requestedCapability
			event.authorizationGens = []uint64{authorizationGen}
			event.authorizing = true
			return event, true
		}
		fi.CompleteJavaAgentAuthorization(authorizationGen, 0)
		return event, false
	}
	requestedCapability, authorizationGen := fi.BeginJavaAgentAuthorization()
	p.javaAuthSequence++
	if p.javaAuthSequence == 0 {
		p.javaAuthSequence++
	}
	event := &javaAuthorizationEvent{
		sequence:            p.javaAuthSequence,
		requestedCapability: requestedCapability,
		authorizationGens:   []uint64{authorizationGen},
		file:                fi,
		authorizing:         true,
	}
	p.javaAuthEvents[key] = append(p.javaAuthEvents[key], event)
	p.javaAuthLatest[key] = event.sequence
	return event, true
}

func appendJavaAuthorizationGeneration(generations []uint64, generation uint64) []uint64 {
	for _, current := range generations {
		if current == generation {
			return generations
		}
	}
	return append(generations, generation)
}

func (p *Tracer) completeJavaAuthorizationEvent(
	fi *exec.FileInfo,
	event *javaAuthorizationEvent,
	capability uint64,
) {
	p.javaAuthMu.Lock()
	defer p.javaAuthMu.Unlock()
	if event.canceled {
		capability = 0
	}
	generations := append([]uint64(nil), event.authorizationGens...)
	event.authorizationGens = nil
	event.authorizing = false
	for _, generation := range generations {
		fi.CompleteJavaAgentAuthorization(generation, capability)
	}
}

// authorizeJavaProcess is retained as a narrow test helper. Production
// AllowPID holds javaLifecycleMu across exact-owner filter admission and event
// enqueue, so a concurrent BlockPID cannot pass between those boundaries.
//
//nolint:unparam // Keep the explicit PID to exercise the FileInfo identity guard in tests.
func (p *Tracer) authorizeJavaProcess(pid app.PID, ns uint32, fi *exec.FileInfo) {
	if fi == nil || pid != fi.Pid() {
		return
	}
	authorizationKey := javaAuthorizationKey{pid: pid, ns: ns}
	event, created := p.beginJavaAuthorizationEvent(authorizationKey, fi)
	if !created {
		return
	}
	p.authorizeJavaProcessForEvent(pid, ns, fi, event)
}

func (p *Tracer) javaCapabilityReservedLocked(
	key javaAuthorizationKey,
	capability uint64,
) bool {
	if capability == 0 || capability&(uint64(1)<<63) != 0 {
		return true
	}
	for _, authorization := range p.javaAuthKeys[key] {
		if authorization.capability == capability {
			return true
		}
	}
	if attempt, ok := p.javaAuthAttempts[key]; ok && attempt.capability == capability {
		return true
	}
	for authorization := range p.javaSuspendPending[key] {
		if authorization.capability == capability {
			return true
		}
	}
	for authorization := range p.javaDeauthPending[key] {
		if authorization.capability == capability {
			return true
		}
	}
	return false
}

func (p *Tracer) generateUnreservedJavaCapabilityLocked(
	key javaAuthorizationKey,
) (uint64, error) {
	for range 4 {
		capability, err := generateJavaProcessCapability()
		if err != nil {
			return 0, err
		}
		if !p.javaCapabilityReservedLocked(key, capability) {
			return capability, nil
		}
	}
	return 0, errors.New("generating unreserved Java process capability")
}

func (p *Tracer) supersedeJavaAuthorizationEvent(
	key javaAuthorizationKey,
	event *javaAuthorizationEvent,
	fi *exec.FileInfo,
) bool {
	p.javaAuthMu.Lock()
	defer p.javaAuthMu.Unlock()
	p.ensureJavaAuthorizationStateLocked()
	events := p.javaAuthEvents[key]
	if event == nil || event.canceled || len(events) == 0 || events[len(events)-1] != event ||
		p.javaAuthLatest[key] != event.sequence {
		if fi != nil {
			fi.SetJavaAgentCapability(0)
		}
		return false
	}
	if event.prepared {
		return true
	}
	if previous, ok := p.javaAuthAttempts[key]; ok &&
		p.javaAuthAttemptEvents[key] != event {
		previousFile := p.javaAuthAttemptFiles[key]
		delete(p.javaAuthAttempts, key)
		delete(p.javaAuthAttemptFiles, key)
		delete(p.javaAuthAttemptEvents, key)
		p.javaAuthSequence++
		if p.javaAuthSequence == 0 {
			p.javaAuthSequence++
		}
		p.javaAuthVersions[key] = p.javaAuthSequence
		if previousFile != nil {
			previousFile.SetJavaAgentCapability(0)
		}
		if err := suspendJavaProcessAuthorization(
			p.javaProcessAuthorizationMaps(), previous.identity, previous.capability,
		); err != nil {
			p.recordPendingJavaSuspensionLocked(key, previous)
		} else {
			p.clearPendingJavaSuspensionLocked(key, previous)
		}
	}
	if previousFile := p.javaAuthFiles[key]; previousFile != nil {
		previousFile.SetJavaAgentCapability(0)
	}
	history := p.javaAuthKeys[key]
	if len(history) == 0 {
		event.prepared = true
		return true
	}
	predecessor := history[len(history)-1]
	if err := suspendJavaProcessAuthorization(
		p.javaProcessAuthorizationMaps(), predecessor.identity, predecessor.capability,
	); err != nil {
		p.recordPendingJavaSuspensionLocked(key, predecessor)
		if p.log != nil {
			p.log.Warn("unable to suspend predecessor Java process authorization",
				"pid", key.pid, "ns", key.ns, "error", err)
		}
	} else {
		p.clearPendingJavaSuspensionLocked(key, predecessor)
	}
	event.prepared = true
	return true
}

func (p *Tracer) authorizeJavaProcessForEvent(
	pid app.PID,
	ns uint32,
	fi *exec.FileInfo,
	event *javaAuthorizationEvent,
) {
	p.authorizeJavaProcessForEventContext(context.Background(), pid, ns, fi, event)
}

func (p *Tracer) authorizeJavaProcessForEventContext(
	ctx context.Context,
	pid app.PID,
	ns uint32,
	fi *exec.FileInfo,
	event *javaAuthorizationEvent,
) {
	authorizationKey := javaAuthorizationKey{pid: pid, ns: ns}
	if fi == nil || pid != fi.Pid() {
		return
	}
	if event == nil {
		fi.SetJavaAgentCapability(0)
		return
	}
	completionCapability := uint64(0)
	defer func() {
		p.completeJavaAuthorizationEvent(fi, event, completionCapability)
	}()
	// beginJavaAuthorizationEvent snapshots the prepared capability before
	// filter bookkeeping or a deauthorization retry can mutate the shared
	// FileInfo. That immutable value identifies this lifecycle transaction.
	capability := event.requestedCapability
	if !p.supersedeJavaAuthorizationEvent(authorizationKey, event, fi) {
		return
	}
	// FileInfo is the trace-attacher handoff gate. Close it before namespace
	// resolution or any map access and reopen it only after this exact event's Q
	// transaction has been confirmed.
	fi.SetJavaAgentCapability(0)
	if fi.SDKLanguage() != svc.InstrumentableJava || capability == 0 {
		return
	}
	if p.bpfObjects.JavaAuthorizedProcesses == nil {
		return
	}
	if lifetimeErr := validateJavaProcessLifetime(pid, fi); lifetimeErr != nil {
		if p.log != nil {
			p.log.Warn("Java process lifetime changed before authorization",
				"pid", pid, "ns", ns, "error", lifetimeErr)
		}
		return
	}

	identity, err := javaProcessIdentity(pid, ns, fi)
	if err != nil {
		fi.SetJavaAgentCapability(0)
		if p.log != nil {
			p.log.Warn("unable to resolve exact Java process identity",
				"pid", pid, "ns", ns, "error", err)
		}
		return
	}
	p.javaAuthMu.Lock()
	p.ensureJavaAuthorizationStateLocked()
	events := p.javaAuthEvents[authorizationKey]
	if event.canceled || len(events) == 0 || events[len(events)-1] != event ||
		p.javaAuthLatest[authorizationKey] != event.sequence {
		fi.SetJavaAgentCapability(0)
		p.pruneJavaAuthorizationStateLocked(authorizationKey)
		p.javaAuthMu.Unlock()
		return
	}
	if p.javaCapabilityReservedLocked(authorizationKey, capability) {
		capability, err = p.generateUnreservedJavaCapabilityLocked(authorizationKey)
		if err != nil {
			p.javaAuthMu.Unlock()
			return
		}
	}
	if previous, ok := p.javaAuthAttempts[authorizationKey]; ok {
		previousFile := p.javaAuthAttemptFiles[authorizationKey]
		delete(p.javaAuthAttempts, authorizationKey)
		delete(p.javaAuthAttemptFiles, authorizationKey)
		delete(p.javaAuthAttemptEvents, authorizationKey)
		if previousFile != nil {
			previousFile.SetJavaAgentCapability(0)
		}
		if suspendErr := suspendJavaProcessAuthorization(
			p.javaProcessAuthorizationMaps(), previous.identity, previous.capability,
		); suspendErr != nil {
			p.recordPendingJavaSuspensionLocked(authorizationKey, previous)
		}
	}
	p.javaAuthSequence++
	if p.javaAuthSequence == 0 {
		p.javaAuthSequence++
	}
	version := p.javaAuthSequence
	p.javaAuthVersions[authorizationKey] = version
	attempt := javaAuthorization{identity: identity, capability: capability}
	p.javaAuthAttempts[authorizationKey] = attempt
	p.javaAuthAttemptFiles[authorizationKey] = fi
	p.javaAuthAttemptEvents[authorizationKey] = event
	p.javaAuthMu.Unlock()

	authorized := false
	if p.javaRemoteParentEnabled {
		deadline := time.Now().Add(javaAuthorizationRetryTimeout)
		rotations := 0
	retryLoop:
		for ctx.Err() == nil {

			if lifetimeErr := validateJavaProcessLifetime(pid, fi); lifetimeErr != nil {
				err = errors.Join(err, lifetimeErr)
				break
			}
			p.javaAuthMu.Lock()
			owned := p.javaAuthorizationAttemptOwnedLocked(
				authorizationKey, version, attempt, event,
			)
			current := owned && ctx.Err() == nil && !event.canceled &&
				p.javaAuthLatest[authorizationKey] == event.sequence
			if !current {
				detached := false
				if owned {
					detached = p.detachJavaAuthorizationAttemptLocked(
						authorizationKey, version, attempt, event, fi,
					)
				}
				if p.javaAuthFiles[authorizationKey] != fi {
					fi.SetJavaAgentCapability(0)
				}
				p.javaAuthMu.Unlock()
				if detached {
					p.suspendDetachedJavaAuthorizationAttempt(authorizationKey, attempt)
				}
				return
			}
			p.javaAuthMu.Unlock()

			// Do not hold the process-wide lifecycle state mutex across a map
			// transaction or retry. BlockPID can cancel this exact event (and an
			// unrelated process can progress) while the kernel operation runs.
			// The post-call version check below converts any stale or ambiguous
			// completion into an exact suspension of this unique capability.
			authorized, err = authorizeJavaProcessCapability(
				p.javaProcessAuthorizationMaps(), attempt.identity, attempt.capability,
			)
			p.javaAuthMu.Lock()
			owned = p.javaAuthorizationAttemptOwnedLocked(
				authorizationKey, version, attempt, event,
			)
			current = owned && ctx.Err() == nil && !event.canceled &&
				p.javaAuthLatest[authorizationKey] == event.sequence
			if !current && owned {
				p.detachJavaAuthorizationAttemptLocked(
					authorizationKey, version, attempt, event, fi,
				)
			}
			if !current && p.javaAuthFiles[authorizationKey] != fi {
				fi.SetJavaAgentCapability(0)
			}
			p.javaAuthMu.Unlock()
			if !current {
				// The map transaction ran without javaAuthMu. BlockPID may have
				// suspended this capability before an in-flight transaction
				// committed it, so every stale completion needs a second exact
				// suspension even when Block already detached the attempt.
				p.suspendDetachedJavaAuthorizationAttempt(authorizationKey, attempt)
				return
			}
			if errors.Is(err, javabridge.ErrProcessCapabilityRetired) {
				if rotations == 4 {
					err = errors.Join(err, errors.New(
						"exhausted fresh Java process capability attempts",
					))
					break
				}
				p.javaAuthMu.Lock()
				current = p.javaAuthorizationAttemptOwnedLocked(
					authorizationKey, version, attempt, event,
				)
				if !current || ctx.Err() != nil || event.canceled ||
					p.javaAuthLatest[authorizationKey] != event.sequence {
					p.javaAuthMu.Unlock()
					continue
				}
				capability, generationErr := p.generateUnreservedJavaCapabilityLocked(authorizationKey)
				if generationErr != nil {
					p.javaAuthMu.Unlock()
					err = errors.Join(err, generationErr)
					break
				}
				rotations++
				attempt.capability = capability
				p.javaAuthAttempts[authorizationKey] = attempt
				p.javaAuthMu.Unlock()
				continue
			}
			if authorized || time.Now().After(deadline) {
				break
			}
			if !waitJavaAuthorizationRetry(ctx, javaAuthorizationRetryInterval) {
				break retryLoop
			}
		}
		if err != nil && ctx.Err() == nil {
			p.log.Warn("unable to complete Java process authorization",
				"pid", pid, "ns", ns, "error", err)
		}
	} else {
		// The disabled-mode direct map update participates in the same stale
		// completion protocol as enabled authorization.
		lifetimeErr := validateJavaProcessLifetime(pid, fi)
		p.javaAuthMu.Lock()
		owned := p.javaAuthorizationAttemptOwnedLocked(
			authorizationKey, version, attempt, event,
		)
		current := owned && ctx.Err() == nil && !event.canceled &&
			p.javaAuthLatest[authorizationKey] == event.sequence &&
			lifetimeErr == nil
		detached := false
		if !current && owned {
			detached = p.detachJavaAuthorizationAttemptLocked(
				authorizationKey, version, attempt, event, fi,
			)
		}
		p.javaAuthMu.Unlock()
		if !current {
			if detached {
				p.suspendDetachedJavaAuthorizationAttempt(authorizationKey, attempt)
			}
			return
		}

		// A newer attempt can supersede this one immediately after the optimistic
		// check above. Serialize the authoritative recheck, direct Q publication,
		// and the common confirmation/compensation boundary for this pid/ns. A
		// delayed predecessor can then observe a confirmed replacement, but can
		// never overwrite it before applying its stale compensation.
		unlockPublication := lockJavaAuthorizationPublication(
			&p.javaAuthPublications, authorizationKey,
		)
		defer unlockPublication()

		lifetimeErr = validateJavaProcessLifetime(pid, fi)
		p.javaAuthMu.Lock()
		owned = p.javaAuthorizationAttemptOwnedLocked(
			authorizationKey, version, attempt, event,
		)
		current = owned && ctx.Err() == nil && !event.canceled &&
			p.javaAuthLatest[authorizationKey] == event.sequence &&
			lifetimeErr == nil
		detached = false
		if !current && owned {
			detached = p.detachJavaAuthorizationAttemptLocked(
				authorizationKey, version, attempt, event, fi,
			)
		}
		p.javaAuthMu.Unlock()
		if !current {
			if detached {
				p.suspendDetachedJavaAuthorizationAttempt(authorizationKey, attempt)
			}
			return
		}

		err = updateJavaAuthorizedProcess(
			p.bpfObjects.JavaAuthorizedProcesses, identity, capability,
		)
		authorized = err == nil
		p.javaAuthMu.Lock()
		owned = p.javaAuthorizationAttemptOwnedLocked(
			authorizationKey, version, attempt, event,
		)
		current = owned && ctx.Err() == nil && !event.canceled &&
			p.javaAuthLatest[authorizationKey] == event.sequence
		if !current && owned {
			p.detachJavaAuthorizationAttemptLocked(
				authorizationKey, version, attempt, event, fi,
			)
		}
		p.javaAuthMu.Unlock()
		if !current {
			// Compensate a direct Q update that committed after BlockPID's
			// first exact suspension while the key remains publication-serialized.
			p.suspendDetachedJavaAuthorizationAttempt(authorizationKey, attempt)
			fi.SetJavaAgentCapability(0)
			return
		}
		if err != nil {
			p.log.Warn("unable to authorize Java process", "pid", pid, "ns", ns, "error", err)
		}
	}

	p.javaAuthMu.Lock()
	owned := p.javaAuthorizationAttemptOwnedLocked(
		authorizationKey, version, attempt, event,
	)
	if !owned || ctx.Err() != nil || event.canceled ||
		p.javaAuthLatest[authorizationKey] != event.sequence {
		if owned {
			p.detachJavaAuthorizationAttemptLocked(
				authorizationKey, version, attempt, event, fi,
			)
		}
		if p.javaAuthFiles[authorizationKey] != fi {
			fi.SetJavaAgentCapability(0)
		}
		p.javaAuthMu.Unlock()
		// Reaching this boundary means an authorization map transaction has
		// already run. Exact suspension is idempotent and cannot remove a
		// replacement capability, so compensate regardless of which goroutine
		// detached the attempt.
		p.suspendDetachedJavaAuthorizationAttempt(authorizationKey, attempt)
		return
	}
	defer p.javaAuthMu.Unlock()
	delete(p.javaAuthAttempts, authorizationKey)
	delete(p.javaAuthAttemptFiles, authorizationKey)
	delete(p.javaAuthAttemptEvents, authorizationKey)
	history := p.javaAuthKeys[authorizationKey]
	if authorized {
		if lifetimeErr := validateJavaProcessLifetime(pid, fi); lifetimeErr != nil {
			authorized = false
		}
	}
	if !authorized {
		// traceAttacher reads this value after AllowPID returns. Clearing it is
		// the attachment gate: a prepared agent never starts while Q is old or
		// an authorization commit is ambiguous. Exact suspension cannot delete
		// a concurrently confirmed replacement capability.
		if suspendErr := suspendJavaProcessAuthorization(
			p.javaProcessAuthorizationMaps(), attempt.identity, attempt.capability,
		); suspendErr != nil {
			p.recordPendingJavaSuspensionLocked(authorizationKey, attempt)
			p.log.Warn("unable to suspend unconfirmed Java process authorization",
				"pid", pid, "ns", ns, "error", suspendErr)
		} else {
			p.clearPendingJavaSuspensionLocked(authorizationKey, attempt)
		}
		if previousFile := p.javaAuthFiles[authorizationKey]; previousFile != nil &&
			previousFile != fi {
			previousFile.SetJavaAgentCapability(0)
		}
		fi.SetJavaAgentCapability(0)
		p.pruneJavaAuthorizationStateLocked(authorizationKey)
		return
	}
	capability = attempt.capability
	p.clearPendingJavaSuspensionLocked(authorizationKey, attempt)
	if previousFile := p.javaAuthFiles[authorizationKey]; previousFile != nil &&
		previousFile != fi {
		previousFile.SetJavaAgentCapability(0)
	}
	fi.SetJavaAgentCapability(capability)
	completionCapability = capability
	p.javaAuthFiles[authorizationKey] = fi
	event.authorization = javaAuthorization{identity: identity, capability: capability}
	event.file = fi
	event.confirmed = true
	event.requestedCapability = capability
	// Do not delete the registered incarnation while rotating authorization.
	// The new capability already fences subsequent ioctls, while an in-flight
	// ioctl that captured the old capability must be allowed to finish its
	// claimed ancestry transaction. PROCESS_REGISTER performs the serialized
	// incarnation transition when the replacement configuration arrives.
	p.javaAuthKeys[authorizationKey] = append(
		history,
		javaAuthorization{identity: identity, capability: capability},
	)
}

func (p *Tracer) javaAuthorizationAttemptOwnedLocked(
	key javaAuthorizationKey,
	version uint64,
	attempt javaAuthorization,
	event *javaAuthorizationEvent,
) bool {
	currentAttempt, exists := p.javaAuthAttempts[key]
	return exists && p.javaAuthVersions[key] == version && currentAttempt == attempt &&
		p.javaAuthAttemptEvents[key] == event
}

func (p *Tracer) detachJavaAuthorizationAttemptLocked(
	key javaAuthorizationKey,
	version uint64,
	attempt javaAuthorization,
	event *javaAuthorizationEvent,
	fi *exec.FileInfo,
) bool {
	if !p.javaAuthorizationAttemptOwnedLocked(key, version, attempt, event) {
		return false
	}
	delete(p.javaAuthAttempts, key)
	delete(p.javaAuthAttemptFiles, key)
	delete(p.javaAuthAttemptEvents, key)
	p.javaAuthSequence++
	if p.javaAuthSequence == 0 {
		p.javaAuthSequence++
	}
	p.javaAuthVersions[key] = p.javaAuthSequence
	if fi != nil && p.javaAuthFiles[key] != fi {
		fi.SetJavaAgentCapability(0)
	}
	return true
}

func (p *Tracer) suspendDetachedJavaAuthorizationAttempt(
	key javaAuthorizationKey,
	attempt javaAuthorization,
) {
	err := suspendJavaProcessAuthorization(
		p.javaProcessAuthorizationMaps(), attempt.identity, attempt.capability,
	)
	p.javaAuthMu.Lock()
	defer p.javaAuthMu.Unlock()
	if err != nil {
		p.recordPendingJavaSuspensionLocked(key, attempt)
		if p.log != nil {
			p.log.Warn("unable to suspend stale Java process authorization",
				"pid", key.pid, "ns", key.ns, "error", err)
		}
	} else {
		p.clearPendingJavaSuspensionLocked(key, attempt)
	}
	p.pruneJavaAuthorizationStateLocked(key)
}

func newJavaProcessCapability() (uint64, error) {
	for range 4 {
		var random [8]byte
		if _, err := rand.Read(random[:]); err != nil {
			return 0, fmt.Errorf("generating fresh Java process capability: %w", err)
		}
		capability := binary.LittleEndian.Uint64(random[:]) & (uint64(1<<63) - 1)
		if capability != 0 {
			return capability, nil
		}
	}
	return 0, errors.New("generating nonzero fresh Java process capability")
}

func (p *Tracer) recordPendingJavaSuspensionLocked(
	key javaAuthorizationKey,
	authorization javaAuthorization,
) {
	if p.javaSuspendPending == nil {
		p.javaSuspendPending = make(
			map[javaAuthorizationKey]map[javaAuthorization]struct{},
		)
	}
	pending := p.javaSuspendPending[key]
	if pending == nil {
		pending = make(map[javaAuthorization]struct{})
		p.javaSuspendPending[key] = pending
	}
	pending[authorization] = struct{}{}
}

func (p *Tracer) clearPendingJavaSuspensionLocked(
	key javaAuthorizationKey,
	authorization javaAuthorization,
) {
	pending := p.javaSuspendPending[key]
	delete(pending, authorization)
	if len(pending) == 0 {
		delete(p.javaSuspendPending, key)
	}
}

func (p *Tracer) recordPendingJavaDeauthorizationLocked(
	key javaAuthorizationKey,
	authorization javaAuthorization,
) {
	pending := p.javaDeauthPending[key]
	if pending == nil {
		pending = make(map[javaAuthorization]struct{})
		p.javaDeauthPending[key] = pending
	}
	pending[authorization] = struct{}{}
}

func (p *Tracer) clearPendingJavaDeauthorizationLocked(
	key javaAuthorizationKey,
	authorization javaAuthorization,
) {
	pending := p.javaDeauthPending[key]
	delete(pending, authorization)
	if len(pending) == 0 {
		delete(p.javaDeauthPending, key)
	}
}

func (p *Tracer) deauthorizeJavaProcess(pid app.PID, ns uint32, fi *exec.FileInfo) {
	p.javaAuthMu.Lock()
	defer p.javaAuthMu.Unlock()
	authorizationKey := javaAuthorizationKey{pid: pid, ns: ns}
	p.ensureJavaAuthorizationStateLocked()
	events := p.javaAuthEvents[authorizationKey]
	match := -1
	for index, event := range events {
		if event.file == fi && !event.canceled {
			match = index
			break
		}
	}
	if match < 0 {
		p.pruneJavaAuthorizationStateLocked(authorizationKey)
		return
	}
	event := events[match]
	if len(events) == 1 {
		delete(p.javaAuthEvents, authorizationKey)
	} else {
		p.javaAuthEvents[authorizationKey] = append(events[:match], events[match+1:]...)
	}
	event.canceled = true
	if event.file != nil {
		event.file.SetJavaAgentCapability(0)
		for _, generation := range event.authorizationGens {
			event.file.CompleteJavaAgentAuthorization(generation, 0)
		}
		event.authorizationGens = nil
		event.authorizing = false
	}

	if attempt, ok := p.javaAuthAttempts[authorizationKey]; ok &&
		p.javaAuthAttemptEvents[authorizationKey] == event {
		attemptFile := p.javaAuthAttemptFiles[authorizationKey]
		delete(p.javaAuthAttempts, authorizationKey)
		delete(p.javaAuthAttemptFiles, authorizationKey)
		delete(p.javaAuthAttemptEvents, authorizationKey)
		p.javaAuthSequence++
		if p.javaAuthSequence == 0 {
			p.javaAuthSequence++
		}
		p.javaAuthVersions[authorizationKey] = p.javaAuthSequence
		if attemptFile != nil {
			attemptFile.SetJavaAgentCapability(0)
		}
		if err := suspendJavaProcessAuthorization(
			p.javaProcessAuthorizationMaps(), attempt.identity, attempt.capability,
		); err != nil {
			p.recordPendingJavaSuspensionLocked(authorizationKey, attempt)
			if p.log != nil {
				p.log.Warn("unable to cancel pending Java process authorization",
					"pid", pid, "ns", ns, "error", err)
			}
		} else {
			p.clearPendingJavaSuspensionLocked(authorizationKey, attempt)
		}
	}
	if !event.confirmed {
		p.pruneJavaAuthorizationStateLocked(authorizationKey)
		return
	}
	if p.javaAuthFiles[authorizationKey] == event.file {
		delete(p.javaAuthFiles, authorizationKey)
	}

	history := p.javaAuthKeys[authorizationKey]
	historyMatch := -1
	for i, authorization := range history {
		if authorization == event.authorization {
			historyMatch = i
			break
		}
	}
	if historyMatch >= 0 {
		history = append(history[:historyMatch], history[historyMatch+1:]...)
	}
	if len(history) == 0 {
		delete(p.javaAuthKeys, authorizationKey)
	} else {
		p.javaAuthKeys[authorizationKey] = history
	}

	if p.bpfObjects.JavaAuthorizedProcesses != nil {
		if err := deauthorizeJavaProcessCapability(
			p.javaProcessAuthorizationMaps(),
			event.authorization.identity,
			event.authorization.capability,
			!p.javaRemoteParentEnabled,
		); err != nil {
			p.recordPendingJavaDeauthorizationLocked(authorizationKey, event.authorization)
			if p.log != nil {
				p.log.Warn("unable to deauthorize Java process",
					"pid", authorizationKey.pid, "ns", authorizationKey.ns, "error", err)
			}
		} else {
			p.clearPendingJavaDeauthorizationLocked(authorizationKey, event.authorization)
		}
	}
	p.pruneJavaAuthorizationStateLocked(authorizationKey)
}

func (p *Tracer) retryPendingJavaDeauthorizations() {
	p.javaAuthMu.Lock()
	defer p.javaAuthMu.Unlock()
	for key, pending := range p.javaSuspendPending {
		for authorization := range pending {
			if err := suspendJavaProcessAuthorization(
				p.javaProcessAuthorizationMaps(),
				authorization.identity,
				authorization.capability,
			); err != nil {
				if p.log != nil {
					p.log.Warn("unable to retry exact Java authorization suspension",
						"pid", key.pid, "ns", key.ns, "error", err)
				}
				continue
			}
			delete(pending, authorization)
		}
		if len(pending) == 0 {
			delete(p.javaSuspendPending, key)
			p.pruneJavaAuthorizationStateLocked(key)
		}
	}
	for key, pending := range p.javaDeauthPending {
		for authorization := range pending {
			if p.bpfObjects.JavaAuthorizedProcesses != nil {
				if err := deauthorizeJavaProcessCapability(
					p.javaProcessAuthorizationMaps(),
					authorization.identity,
					authorization.capability,
					!p.javaRemoteParentEnabled,
				); err != nil {
					if p.log != nil {
						p.log.Warn("unable to retry exact Java process deauthorization",
							"pid", key.pid, "ns", key.ns, "error", err)
					}
					continue
				}
			}
			delete(pending, authorization)
		}
		if len(pending) == 0 {
			delete(p.javaDeauthPending, key)
			p.pruneJavaAuthorizationStateLocked(key)
		}
	}
}

func (p *Tracer) pruneJavaAuthorizationStateLocked(key javaAuthorizationKey) {
	if len(p.javaAuthEvents[key]) != 0 {
		return
	}
	if len(p.javaAuthKeys[key]) != 0 {
		return
	}
	if _, ok := p.javaAuthAttempts[key]; ok {
		return
	}
	if len(p.javaDeauthPending[key]) != 0 {
		return
	}
	if len(p.javaSuspendPending[key]) != 0 {
		return
	}
	delete(p.javaAuthVersions, key)
	delete(p.javaAuthAttemptFiles, key)
	delete(p.javaAuthAttemptEvents, key)
	delete(p.javaAuthFiles, key)
	delete(p.javaAuthLatest, key)
}

func (p *Tracer) runPendingJavaDeauthorizations(ctx context.Context) {
	ticker := time.NewTicker(javaDeauthorizationRetryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.retryPendingJavaDeauthorizations()
		}
	}
}

func (p *Tracer) javaProcessAuthorizationMaps() javabridge.Maps {
	return javabridge.Maps{
		Authorized:          p.bpfObjects.JavaAuthorizedProcesses,
		Incarnations:        p.bpfObjects.JavaProcessIncarnations,
		ThreadMappingClaims: p.bpfObjects.JavaThreadMappingClaims,
		Retired:             p.bpfObjects.JavaRetiredProcesses,
	}
}

func (p *Tracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	if p.cfg.EBPF.TrackRequestHeaders ||
		p.cfg.EBPF.ContextPropagation.IsEnabled() {
		p.log.Info("Enabling trace information parsing", "bpf_loop_enabled", ebpfcommon.SupportsEBPFLoops(p.log, p.cfg.EBPF.OverrideBPFLoopEnabled))
	}

	spec, err := LoadBpf()
	if err != nil {
		return nil, fmt.Errorf("can't load bpf collection from reader: %w", err)
	}

	ebpfcommon.FixupSpec(spec, p.cfg.EBPF.OverrideBPFLoopEnabled)
	p.javaRemoteParentEnabled = p.cfg.Java.RemoteParent.Enabled() &&
		p.haveSockOpsNetnsCookie() == nil
	if !p.javaRemoteParentEnabled {
		javabridge.MinimizeDisabledMaps(spec)
	}

	return []*ebpfcommon.SpecBundle{{Spec: spec, Objects: &p.bpfObjects, Constants: p.constants()}}, nil
}

func (p *Tracer) tailCallPrograms() []*ebpf.Program {
	// Order must match the k_tail_* enum in bpf/generictracer/k_tracer_tailcall.h.
	return []*ebpf.Program{
		// HTTP/1
		p.bpfObjects.ObiProtocolHttp,           // 0  k_tail_protocol_http
		p.bpfObjects.ObiContinueProtocolHttp,   // 1  k_tail_continue_protocol_http
		p.bpfObjects.ObiContinue2ProtocolHttp,  // 2  k_tail_continue2_protocol_http
		p.bpfObjects.ObiContinueProtocolHttpTp, // 3  k_tail_continue_protocol_http_tp
		// TCP
		p.bpfObjects.ObiProtocolTcp, // 4  k_tail_protocol_tcp
		// generic
		p.bpfObjects.ObiHandleBufWithArgs, // 5  k_tail_handle_buf_with_args
		nil,                               // 6  k_tail_continue_netfd_read (gotracer-only)
		// HTTP/2 + gRPC
		p.bpfObjects.ObiProtocolHttp2,                                   // 7
		p.bpfObjects.ObiProtocolHttp2GrpcFrames,                         // 8
		p.bpfObjects.ObiProtocolHttp2GrpcHandleStartFrame,               // 9
		p.bpfObjects.ObiProtocolHttp2GrpcHandleEndFrame,                 // 10
		p.bpfObjects.ObiProtocolHttp2GrpcHandleStartFrameServer,         // 11
		p.bpfObjects.ObiProtocolHttp2GrpcHandleStartFrameServerFinalize, // 12
		// Large buffer multi-batch emission
		p.bpfObjects.ObiLargeBufEmitContinue,                            // 13  k_tail_large_buf_emit_continue
		p.bpfObjects.ObiProtocolHttp2GrpcHandleStartFrameServerCommit,   // 14
		p.bpfObjects.ObiProtocolHttp2GrpcHandleStartFrameServerHuffman,  // 15
		p.bpfObjects.ObiProtocolHttp2GrpcHandleStartFrameServerHuffscan, // 16
		// Traceparent validation
		p.bpfObjects.ObiContinueProtocolHttpTpValidate, // 17
		// Java remote-parent control carriers
		p.bpfObjects.ObiJavaTaskCaptureTail,      // 18 k_tail_java_task_capture
		p.bpfObjects.ObiJavaTaskRelayCaptureTail, // 19 k_tail_java_task_relay_capture
		p.bpfObjects.ObiJavaTaskLinkTail,         // 20 k_tail_java_task_link
		p.bpfObjects.ObiJavaControlCleanupTail,   // 21 k_tail_java_control_cleanup
		p.bpfObjects.ObiJavaThreadsTail,          // 22 k_tail_java_threads
		p.bpfObjects.ObiJavaLifecycleTail,        // 23 k_tail_java_lifecycle
	}
}

func (p *Tracer) SetupTailCalls() {
	javaControlTailCallsReady := true
	for i, prog := range p.tailCallPrograms() {
		if prog == nil {
			if i >= 18 {
				javaControlTailCallsReady = false
			}
			continue
		}
		p.log.Debug("loading program into tail call jump table", "index", i, "program", prog.String())
		if err := p.bpfObjects.JumpTable.Update(uint32(i), uint32(prog.FD()), ebpf.UpdateAny); err != nil {
			p.log.Error("error loading info tail call jump table", "error", err)
			if i >= 18 {
				javaControlTailCallsReady = false
			}
		}
	}
	p.setJavaRemoteParentControlTailReadiness(javaControlTailCallsReady)

	p.javaDataHookAttached = false
	p.javaCloseHookAttached = false
	p.setJavaRemoteParentDataHookReadiness(false)
}

func (p *Tracer) setJavaRemoteParentControlTailReadiness(ready bool) {
	readiness := p.bpfObjects.JavaRemoteParentControlTailReadiness
	if readiness == nil {
		return
	}

	state := uint32(0)
	if ready {
		state = 1
	}
	if err := updateJavaRemoteParentControlTailReadiness(readiness, state); err != nil {
		p.log.Warn("updating Java control tail-call readiness", "ready", ready, "error", err)
	}
}

func (p *Tracer) setJavaRemoteParentDataHookReadiness(ready bool) {
	readiness := p.bpfObjects.JavaRemoteParentDataHookReadiness
	if readiness == nil {
		return
	}

	state := uint32(0)
	if ready {
		state = 1
	}
	if err := updateJavaRemoteParentDataHookReadiness(readiness, state); err != nil {
		p.log.Warn("updating authoritative Java data-hook readiness", "ready", ready, "error", err)
	}
}

func (p *Tracer) recordJavaDataHookAttachResult(err error) {
	p.javaDataHookAttached = err == nil
	p.publishJavaRemoteParentDataHookReadiness()
}

func (p *Tracer) recordJavaCloseHookAttachResult(err error) {
	p.javaCloseHookAttached = err == nil
	p.publishJavaRemoteParentDataHookReadiness()
}

func (p *Tracer) publishJavaRemoteParentDataHookReadiness() {
	p.setJavaRemoteParentDataHookReadiness(p.javaDataHookAttached && p.javaCloseHookAttached)
}

func (p *Tracer) constants() map[string]any {
	m := make(map[string]any, 2)

	m["wakeup_data_bytes"] = uint32(p.cfg.EBPF.WakeupLen) * uint32(unsafe.Sizeof(ebpfcommon.HTTPRequestTrace{}))

	// The eBPF side does some basic filtering of events that do not belong to
	// processes which we monitor. We filter more accurately in the userspace, but
	// for performance reasons we enable the PID based filtering in eBPF.
	// This must match httpfltr.go, otherwise we get partial events in userspace.
	if p.cfg.Discovery.BPFPidFilterOff {
		m["filter_pids"] = int32(0)
	} else {
		m["filter_pids"] = int32(1)
	}

	if p.cfg.EBPF.TrackRequestHeaders ||
		p.cfg.EBPF.ContextPropagation.IsEnabled() {
		m["capture_header_buffer"] = int32(1)
	} else {
		m["capture_header_buffer"] = int32(0)
	}

	if p.cfg.EBPF.HighRequestVolume {
		m["high_request_volume"] = uint32(1)
	} else {
		m["high_request_volume"] = uint32(0)
	}

	if p.cfg.EBPF.DisableBlackBoxCP {
		m["disable_black_box_cp"] = uint32(1)
	} else {
		m["disable_black_box_cp"] = uint32(0)
	}

	// gates the bpf_loop paths; unset it defaults to false and const-DCE drops them
	m["g_bpf_loop_enabled"] = ebpfcommon.SupportsEBPFLoops(p.log, p.cfg.EBPF.OverrideBPFLoopEnabled)

	m["http_max_captured_bytes"] = p.cfg.EBPF.BufferSizes.HTTP
	m["tcp_max_captured_bytes"] = p.cfg.EBPF.BufferSizes.TCP
	m["mysql_max_captured_bytes"] = p.cfg.EBPF.BufferSizes.MySQL
	m["kafka_max_captured_bytes"] = p.cfg.EBPF.BufferSizes.Kafka
	m["postgres_max_captured_bytes"] = p.cfg.EBPF.BufferSizes.Postgres
	m["mssql_max_captured_bytes"] = p.cfg.EBPF.BufferSizes.MSSQL

	m["max_transaction_time"] = uint64(p.cfg.EBPF.MaxTransactionTime.Nanoseconds())

	m["g_bpf_debug"] = p.cfg.EBPF.BpfDebug
	m["g_bpf_traceparent_enabled"] = p.cfg.EBPF.TrackRequestHeaders || p.cfg.EBPF.ContextPropagation.IsEnabled()
	m["java_remote_parent_enabled"] = p.javaRemoteParentEnabled
	m["ssl_prewrite_max_age_ns"] = uint64(p.cfg.Java.RemoteParent.TTL.Nanoseconds())
	m["jvm_sampling_interval_ns"] = uint64(0)
	if p.cfg.AppRuntimeMetricsEnabled() {
		m["jvm_sampling_interval_ns"] = uint64(p.cfg.JVMRuntimeMetrics.SamplingInterval.Nanoseconds())
	}
	m["nodejs_runtime_metrics_enabled"] = uint64(0)
	if p.cfg.AppRuntimeMetricsEnabled() {
		m["nodejs_runtime_metrics_enabled"] = uint64(1)
	}

	return m
}

func (p *Tracer) RegisterOffsets(_ *exec.FileInfo, _ *goexec.Offsets) error { return nil }

func (p *Tracer) ProcessBinary(_ *exec.FileInfo) {}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Tracer) newResourceCloser() *orderedResourceCloser {
	closers := make([]io.Closer, 0, len(p.closers)+1)
	closers = append(closers, p.closers...)
	closers = append(closers, &p.bpfObjects)
	return newOrderedResourceCloser(p.stopJavaWorkers, closers...)
}

func (p *Tracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) KProbes() map[string]ebpfcommon.ProbeDesc {
	kp := map[string]ebpfcommon.ProbeDesc{
		// Both sys accept probes use the same kretprobe.
		// We could tap into __sys_accept4, but we might be more prone to
		// issues with the internal kernel code changing.
		"sys_accept": {
			Required: true,
			End:      p.bpfObjects.ObiKretprobeSysAccept4,
		},
		"sys_accept4": {
			Required: true,
			End:      p.bpfObjects.ObiKretprobeSysAccept4,
		},
		"security_socket_accept": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeSecuritySocketAccept,
		},
		// Tracking of HTTP client calls, by tapping into connect
		"sys_connect": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeSysConnect,
			End:      p.bpfObjects.ObiKretprobeSysConnect,
		},
		"sock_recvmsg": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeSockRecvmsg,
			End:      p.bpfObjects.ObiKretprobeSockRecvmsg,
		},
		"tcp_connect": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeTcpConnect,
		},
		"udp_sendmsg": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeUdpSendmsg,
		},
		"tcp_close": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeTcpClose,
		},
		"sock_def_error_report": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeSockDefErrorReport,
		},
		"tcp_sendmsg": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeTcpSendmsg,
			End:      p.bpfObjects.ObiKretprobeTcpSendmsg,
		},
		// Reading more than 160 bytes
		"tcp_recvmsg": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeTcpRecvmsg,
			End:      p.bpfObjects.ObiKretprobeTcpRecvmsg,
		},
		"tcp_cleanup_rbuf": {
			Start: p.bpfObjects.ObiKprobeTcpCleanupRbuf, // this kprobe runs the same code as recvmsg return, we use it because kretprobes can be unreliable.
		},
		"sys_clone": {
			Required: true,
			End:      p.bpfObjects.ObiKretprobeSysClone,
		},
		"sys_clone3": {
			Required: false,
			End:      p.bpfObjects.ObiKretprobeSysClone,
		},
		"sys_exit": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeSysExit,
		},
		"do_exit": {
			Required: false,
			Start:    p.bpfObjects.ObiKprobeSysExit,
		},
		"unix_stream_recvmsg": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeUnixStreamRecvmsg,
			End:      p.bpfObjects.ObiKretprobeUnixStreamRecvmsg,
		},
		"unix_stream_sendmsg": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeUnixStreamSendmsg,
			End:      p.bpfObjects.ObiKretprobeUnixStreamSendmsg,
		},
		"inet_csk_listen_stop": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeInetCskListenStop,
		},
		"sys_ioctl": {
			Required: true,
			Start:    p.bpfObjects.ObiKprobeSysIoctl,
		},
		"security_file_ioctl": {
			Required:     false,
			Start:        p.bpfObjects.ObiKprobeSecurityFileIoctl,
			AttachResult: p.recordJavaDataHookAttachResult,
		},
	}
	if p.javaRemoteParentEnabled {
		kp["tcp_close/java_remote_parent"] = ebpfcommon.ProbeDesc{
			Required:     true,
			KProbeTarget: "tcp_close",
			Start:        p.bpfObjects.ObiKprobeJavaRemoteParentTcpClose,
			AttachResult: p.recordJavaCloseHookAttachResult,
		}
	}

	if p.cfg.EBPF.ContextPropagation.IsEnabled() {
		// tcp_rate_check_app_limited and tcp_sendmsg_fastopen are backup
		// for tcp_sendmsg_locked which doesn't fire on certain kernels
		// if sk_msg is attached.
		kp["tcp_rate_check_app_limited"] = ebpfcommon.ProbeDesc{
			Required: false,
			Start:    p.bpfObjects.ObiKprobeTcpRateCheckAppLimited,
		}
		kp["tcp_sendmsg_fastopen"] = ebpfcommon.ProbeDesc{
			Required: false,
			Start:    p.bpfObjects.ObiKprobeTcpRateCheckAppLimited,
		}
	}

	if p.javaRemoteParentEnabled {
		kp["sk_psock_msg_verdict"] = ebpfcommon.ProbeDesc{
			Required: true,
			Start:    p.bpfObjects.ObiKprobeSkPsockMsgVerdict,
		}
	}

	return kp
}

func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return map[string]ebpfcommon.ProbeDesc{
		"sched/sched_process_exit": {
			Required: true,
			Start:    p.bpfObjects.ObiSslProcessExit,
		},
	}
}

func (p *Tracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc {
	m := map[string]map[string][]*ebpfcommon.ProbeDesc{
		"libssl.so": {
			"SSL_new": {{
				Required: false,
				End:      p.bpfObjects.ObiUretprobeSslNew,
			}},
			"SSL_read": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeSslRead,
				End:      p.bpfObjects.ObiUretprobeSslRead,
			}},
			"SSL_write": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeSslWrite,
				End:      p.bpfObjects.ObiUretprobeSslWrite,
			}},
			"SSL_read_ex": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeSslReadEx,
				End:      p.bpfObjects.ObiUretprobeSslReadEx,
			}},
			"SSL_write_ex2": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeSslWriteEx2,
				End:      p.bpfObjects.ObiUretprobeSslWriteEx2,
			}},
			"SSL_write_ex": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeSslWriteEx,
				End:      p.bpfObjects.ObiUretprobeSslWriteEx,
			}},
			"SSL_shutdown": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeSslShutdown,
				End:      p.bpfObjects.ObiUretprobeSslShutdown,
			}},
		},
		"libSystem.Security.Cryptography.Native.OpenSsl.so": {
			"CryptoNative_SslRead": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeSslRead,
				End:      p.bpfObjects.ObiUretprobeSslRead,
			}},
			"CryptoNative_SslWrite": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeCryptoNativeSslWrite,
				End:      p.bpfObjects.ObiUretprobeCryptoNativeSslWrite,
			}},
			"CryptoNative_SslShutdown": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeCryptoNativeSslShutdown,
				End:      p.bpfObjects.ObiUretprobeCryptoNativeSslShutdown,
			}},
		},
		"nginx": {
			"ngx_http_upstream_init": {{ // on upstream dispatch
				Required: false,
				Start:    p.bpfObjects.ObiNgxHttpUpstreamInit,
			}},
			"ngx_event_connect_peer": {{
				Required: false,
				End:      p.bpfObjects.ObiNgxEventConnectPeerRet,
			}},
		},
		"node": {
			"uv_fs_access": {{
				Required: false,
				Start:    p.bpfObjects.ObiUvFsAccess,
			}},
		},
		"libuv.so": {
			"uv_fs_access": {{
				Required: false,
				Start:    p.bpfObjects.ObiUvFsAccess,
			}},
		},
		"libruby": {
			"rb_ary_shift": {{
				Required: false,
				Start:    p.bpfObjects.ObiRbAryShift,
			}},
			"rb_obj_call_init_kw": {{
				Required: false,
				Start:    p.bpfObjects.ObiRbObjCallInitKw,
			}},
		},
		"libpython3.": {
			"context_run": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeContextRun,
				End:      p.bpfObjects.ObiUretprobeContextRun,
			}},
			"context_run.lto_priv.0": {{ // In Python 3.14, context_run has different symbols due to Link Time Optimization
				Required: false,
				Start:    p.bpfObjects.ObiUprobeContextRun,
				End:      p.bpfObjects.ObiUretprobeContextRun,
			}},
			"PyContext_CopyCurrent": {{
				Required: false,
				End:      p.bpfObjects.ObiUprobeCopyContext,
			}},
			"context_new_from_vars": {{ // In Docker, PyContext_CopyCurrent has Tail Recursion Optimization, so we need this function instead
				Required: false,
				End:      p.bpfObjects.ObiUprobeCopyContext,
			}},
		},
		"_asyncio": {
			"_asyncio_Task___init__": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeTaskInit,
				End:      p.bpfObjects.ObiUprobeTaskInitRet,
			}},
		},
		"_asyncio[< 3.12]": {
			"task_step": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeTaskStepLegacy,
				End:      p.bpfObjects.ObiUprobeTaskStepRet,
			}},
		},
		"_asyncio[>= 3.12]": {
			"task_step": {{
				Required: false,
				Start:    p.bpfObjects.ObiUprobeTaskStep,
				End:      p.bpfObjects.ObiUprobeTaskStepRet,
			}},
		},
	}
	return m
}

func (p *Tracer) USDTProbes() map[string][]*ebpfcommon.USDTProbeDesc {
	if !p.cfg.AppRuntimeMetricsEnabled() {
		return nil
	}
	return map[string][]*ebpfcommon.USDTProbeDesc{
		"libjvm.so": {
			{
				Provider:    "hotspot",
				Name:        "mem__pool__gc__begin",
				Program:     p.bpfObjects.ObiUsdtHotspotMemPoolGcBegin,
				SpecsMap:    p.bpfObjects.ObiUsdtSpecs,
				IPMap:       p.bpfObjects.ObiUsdtIpToSpecId,
				SpecManager: &p.jvmUSDTManager,
			},
			{
				Provider:    "hotspot",
				Name:        "mem__pool__gc__end",
				Program:     p.bpfObjects.ObiUsdtHotspotMemPoolGcEnd,
				SpecsMap:    p.bpfObjects.ObiUsdtSpecs,
				IPMap:       p.bpfObjects.ObiUsdtIpToSpecId,
				SpecManager: &p.jvmUSDTManager,
			},
		},
	}
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return []*ebpf.Program{p.bpfObjects.ObiSocketHttpFilter}
}

func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg { return nil }

func (p *Tracer) SockOps() []ebpfcommon.SockOps { return nil }

func (p *Tracer) Iters() []*ebpfcommon.Iter {
	if len(p.iters) == 0 {
		p.iters = []*ebpfcommon.Iter{
			{
				Program: p.bpfObjects.ObiIterTcp,
			},
		}
	}

	return p.iters
}

func (p *Tracer) runItersForPids() {
	iters := p.Iters()
	if len(iters) == 0 {
		return
	}

	seen := make(map[uint64]struct{})

	for _, pids := range p.pidsFilter.CurrentPIDs(ebpfcommon.PIDTypeKProbes) {
		for pid := range pids {
			info, err := os.Stat(fmt.Sprintf("/proc/%d/ns/net", pid))
			if err != nil {
				p.log.Debug("netns stat failed", "pid", pid, "error", err)
				continue
			}

			inode := info.Sys().(*syscall.Stat_t).Ino
			if _, ok := seen[inode]; ok {
				continue
			}
			seen[inode] = struct{}{}

			for _, it := range iters {
				if err := netns.WithNetNS(int(pid), func() error {
					return it.Run(p.log)
				}); err != nil {
					if errors.Is(err, os.ErrNotExist) {
						p.log.Debug("process gone before iterating its netns", "pid", pid)
						break
					}
					p.log.Error("error running iterator in netns", "pid", pid, "error", err)
				}
			}
		}
	}
}

func (p *Tracer) Tracing() []*ebpfcommon.Tracing { return nil }

func (p *Tracer) RecordInstrumentedLib(id exec.FileID, closers []io.Closer) {
	p.libsMux.Lock()
	defer p.libsMux.Unlock()

	module := p.instrumentedLibs.AddRef(id)

	if len(closers) > 0 {
		module.Closers = append(module.Closers, closers...)
	}

	p.log.Debug("Recorded instrumented Lib", "dev", id.Dev, "ino", id.Ino, "module", module)
}

func (p *Tracer) AddInstrumentedLibRef(id exec.FileID) {
	p.RecordInstrumentedLib(id, nil)
}

func (p *Tracer) UnlinkInstrumentedLib(id exec.FileID) {
	p.libsMux.Lock()
	defer p.libsMux.Unlock()

	module, err := p.instrumentedLibs.RemoveRef(id)

	p.log.Debug("Unlinking instrumented lib - before state", "dev", id.Dev, "ino", id.Ino, "module", module)

	if err != nil {
		p.log.Debug("Error unlinking instrumented lib", "dev", id.Dev, "ino", id.Ino, "error", err)
	}
}

func (p *Tracer) AlreadyInstrumentedLib(id exec.FileID) bool {
	p.libsMux.Lock()
	defer p.libsMux.Unlock()

	module := p.instrumentedLibs.Find(id)

	p.log.Debug("checking already instrumented Lib", "dev", id.Dev, "ino", id.Ino, "module", module)
	return module != nil
}

func (p *Tracer) Run(
	ctx context.Context,
	ebpfEventContext *ebpfcommon.EBPFEventContext,
	eventsChan *msg.Queue[[]request.Span],
) {
	p.eventCtx = ebpfEventContext
	resourceCloser := p.newResourceCloser()
	defer func() { _ = resourceCloser.Close() }()

	// At this point we now have loaded the bpf objects, which means we should insert any
	// pids that are allowed into the bpf map
	if p.bpfObjects.ValidPids != nil {
		if err := p.validateValidPidsMap(); err != nil {
			p.log.Error("BPF PID filter map sizing is invalid, discovery filtering may not be enforced", "error", err)
		}
		if err := p.rebuildValidPids(); err != nil {
			p.log.Error("setting up the BPF PID filter, discovery filtering may not be enforced", "error", err)
		}
	} else {
		p.log.Error("BPF Pids map is not created yet, this is a bug.")
	}

	timeoutTicker := time.NewTicker(2 * time.Second)
	parseContext := ebpfcommon.NewEBPFParseContext(&p.cfg.EBPF, eventsChan, p.pidsFilter)
	defer parseContext.Close()

	go p.watchForMisclassifedEvents(ctx)
	go p.lookForTimeouts(ctx, parseContext, timeoutTicker, eventsChan)
	p.startPendingJavaDeauthorizationWorker()
	defer timeoutTicker.Stop()

	p.runItersForPids()

	p.log.Info("Launching p.Tracer")

	cfg := &p.cfg.EBPF
	if p.cfg.AppRuntimeMetricsEnabled() {
		if p.runtimeMetricsSender() == nil {
			p.log.Warn("runtime metrics enabled without runtime metrics queue")
		} else {
			p.log.Debug("reading runtime metrics from shared ring buffer")
		}
	}

	ebpfcommon.SharedRingbuf(
		ebpfEventContext,
		cfg,
		p.bpfObjects.Events,
		func(record *ringbuf.Record) (request.Span, bool, error) {
			return p.processSharedRingbufRecord(ctx, parseContext, cfg, record)
		},
		p.pidsFilter.Filter,
		p.log,
		p.metrics,
	)(ctx, []io.Closer{resourceCloser}, eventsChan)
}

func (p *Tracer) processSharedRingbufRecord(
	ctx context.Context,
	parseContext *ebpfcommon.EBPFParseContext,
	cfg *config.EBPFTracer,
	record *ringbuf.Record,
) (request.Span, bool, error) {
	if handled, err := p.eventCtx.HandleInternalEvent(record); handled {
		return request.Span{}, true, err
	}

	if handled, err := ebpfcommon.HandleRuntimeMetricsRecord(
		ctx,
		p.eventCtx,
		record,
		p.pidsFilter,
		p.log,
		p.handleJVMRuntimeMetricsRecord,
	); handled {
		return request.Span{}, true, err
	}

	s, ignore, err := ebpfcommon.ReadBPFTraceAsSpan(parseContext, cfg, record, p.pidsFilter)
	if !ignore && err == nil && !s.IsValid() {
		return s, true, nil
	}
	return s, ignore, err
}

func (p *Tracer) handleJVMRuntimeMetricsRecord(
	ctx context.Context,
	record *ringbuf.Record,
) (bool, error) {
	if record == nil || len(record.RawSample) == 0 {
		return false, nil
	}

	eventType := record.RawSample[0]
	switch eventType {
	case ebpfcommon.EventTypeJVMMemoryPoolGC:
		if p.eventCtx == nil || p.eventCtx.RuntimeMetrics == nil {
			return true, nil
		}
		events, ignore, err := p.parseJVMMemoryPoolRecord(record)
		if err != nil || ignore || len(events) == 0 {
			return true, err
		}
		p.eventCtx.RuntimeMetrics.SendJVMRuntimeMetrics(ctx, events)
		return true, nil
	default:
		return false, nil
	}
}

func (p *Tracer) runtimeMetricsSender() ebpfcommon.RuntimeMetricSender {
	if p.eventCtx == nil {
		return nil
	}
	return p.eventCtx.RuntimeMetrics
}

func (p *Tracer) parseJVMMemoryPoolRecord(record *ringbuf.Record) ([]jvmruntime.JVMRuntimeEvent, bool, error) {
	raw, err := ebpfcommon.ReinterpretCast[BpfJvmMemPoolGcEvent](record.RawSample)
	if err != nil {
		return nil, false, err
	}

	events, err := jvmruntime.ParseJVMMemoryPoolEvent(
		raw.Timestamp,
		raw.NsPid,
		raw.PidNsId,
		jvmruntime.RawJVMGCWhenType(raw.GcWhenType),
		raw.Used,
		raw.Committed,
		raw.MaxSize,
		raw.Pool,
	)
	if err != nil {
		return nil, false, err
	}

	if len(events) == 0 {
		return nil, true, nil
	}

	// All events are fanned out from one raw sample and share PID identity.
	if !ebpfcommon.DecorateJVMRuntimeEvent(p.pidsFilter, &events[0]) {
		return nil, true, nil
	}
	for i := 1; i < len(events); i++ {
		events[i].Service = events[0].Service
	}

	if p.log != nil {
		p.log.Debug("received JVM memory pool event",
			"pid", events[0].PID,
			"service", events[0].Service.UID.Name,
			"namespace", events[0].Service.UID.Namespace,
			"pool", events[0].PoolName,
			"phase", events[0].GCPhase,
			"events", len(events),
		)
	}
	return events, false, nil
}

//nolint:cyclop
func (p *Tracer) lookForTimeouts(ctx context.Context, parseCtx *ebpfcommon.EBPFParseContext, ticker *time.Ticker, eventsChan *msg.Queue[[]request.Span]) {
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-ticker.C:
			if p.bpfObjects.OngoingHttp != nil {
				i := p.bpfObjects.OngoingHttp.Iterate()
				var k BpfPidConnectionInfoT
				var v BpfHttpInfoT
				for i.Next(&k, &v) {
					// Check if we have a lingering request which we've completed, as in it has EndMonotimeNs
					// but it hasn't been posted yet, likely missed by the logic that looks at finishing requests
					// where we track the full response. If we haven't updated the EndMonotimeNs in more than some
					// short interval, we are likely not going to finish this request from eBPF, so let's do it here.
					if v.EndMonotimeNs != 0 && v.Submitted == 0 && t.After(timing.KernelTime(v.EndMonotimeNs).Add(10*time.Second)) {
						// Must use unsafe here, the two bpfHttpInfoTs are the same but generated from different
						// ebpf2go outputs
						s, ignore, err := ebpfcommon.HTTPInfoEventToSpan(parseCtx, (*ebpfcommon.BPFHTTPInfo)(unsafe.Pointer(&v)))
						if !ignore && err == nil {
							eventsChan.SendCtx(ctx, p.pidsFilter.Filter([]request.Span{s}))
						}
						if err := p.bpfObjects.OngoingHttp.Delete(k); err != nil {
							p.log.Debug("Error deleting ongoing request", "error", err)
						}
					} else if v.EndMonotimeNs == 0 && p.cfg.EBPF.HTTPRequestTimeout.Milliseconds() > 0 && t.After(timing.KernelTime(v.StartMonotimeNs).Add(p.cfg.EBPF.HTTPRequestTimeout)) {
						// If we don't have a request finish with endTime by the configured request timeout, terminate the
						// waiting request with a timeout 408
						s, ignore, err := ebpfcommon.HTTPInfoEventToSpan(parseCtx, (*ebpfcommon.BPFHTTPInfo)(unsafe.Pointer(&v)))

						if !ignore && err == nil {
							s.Status = 408 // timeout
							if s.RequestStart == 0 {
								s.RequestStart = s.Start
							}
							s.End = s.Start + p.cfg.EBPF.HTTPRequestTimeout.Nanoseconds()

							eventsChan.SendCtx(ctx, p.pidsFilter.Filter([]request.Span{s}))
						}
						if err := p.bpfObjects.OngoingHttp.Delete(k); err != nil {
							p.log.Debug("Error deleting ongoing request", "error", err)
						}
					}
				}
			}
		}
	}
}

func (p *Tracer) watchForMisclassifedEvents(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-ebpfcommon.MisclassifiedEvents:
			if e.EventType == ebpfcommon.EventTypeKHTTP2 {
				if p.bpfObjects.OngoingHttp2Connections != nil {
					err := p.bpfObjects.OngoingHttp2Connections.Put(
						&BpfPidConnectionInfoT{Conn: bpfConnInfoT(e.TCPInfo.ConnInfo), Pid: e.TCPInfo.Pid.HostPid},
						BpfHttp2ConnInfoDataT{Flags: e.TCPInfo.Ssl, Id: 0}, // no new connection flag (0x3)
					)
					if err != nil {
						p.log.Debug("error writing HTTP2/gRPC connection info", "error", err)
					}
				}
			}
		}
	}
}

// Cilium 0.19.0+ is adding a new private field to all the BpfConnectionInfoT
// implementations, so we can't directly do a type cast
func bpfConnInfoT(src ebpfcommon.BpfConnectionInfoT) (dst BpfConnectionInfoT) {
	dst.D_port = src.D_port
	dst.D_addr = src.D_addr
	dst.S_addr = src.S_addr
	dst.S_port = src.S_port
	return
}

func (p *Tracer) SetEventContext(ctx *ebpfcommon.EBPFEventContext) { p.eventCtx = ctx }

func (p *Tracer) Capabilities() ebpfcommon.TracerCapability { return 0 }

func (p *Tracer) Required() bool {
	return true
}
