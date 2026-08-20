// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package logenricher // import "go.opentelemetry.io/obi/pkg/internal/ebpf/logenricher"

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/internal/shardedqueue"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -type log_event_t -type log_enricher_generation_t -target amd64,arm64 Bpf ../../../../bpf/logenricher/logenricher.c -- -I../../../../bpf -I../../../../bpf

type LogEvent struct {
	orig          BpfLogEventT
	logLine       string
	ownerIdentity logOwnerIdentity
	procDir       *os.File
	pinnedTarget  *os.File
}

type logOwnerIdentity struct {
	processInstanceID uint64
	lifecycleEpoch    uint64
	fallbackOwner     *exec.FileInfo
}

type logTargetKey struct {
	owner logOwnerIdentity
	dev   uint64
	ino   uint64
	fd    uint32
	path  string
}

type Tracer struct {
	ctx                             context.Context
	cfg                             *obi.Config
	bpfObjects                      BpfObjects
	closers                         []io.Closer
	log                             *slog.Logger
	asyncWriter                     *shardedqueue.ShardedQueue[LogEvent]
	asyncWriterWG                   sync.WaitGroup
	asyncWriterMU                   sync.Mutex
	asyncWriterClosed               bool
	formatter                       logFormatter
	pids                            map[uint64][]uint64                    // namespaced host PID key -> namespaced PID aliases
	pidServices                     map[uint64]*exec.FileInfo              // namespaced host PID key -> service info
	pidOwners                       map[uint64]*exec.FileInfo              // namespaced host PID key -> exact admission lifetime
	pidKeyOwners                    map[uint64]map[*exec.FileInfo]struct{} // BPF PID key -> live exact admission lifetimes
	pidKeysByHostPID                map[uint32]uint64                      // host PID -> current namespaced host PID key
	pidGenerations                  map[uint32]BpfLogEnricherGenerationT   // host PID -> published exact process lifetime
	addPIDOverride                  func(uint64) error
	removePIDOverride               func(uint64) error
	newPIDLifecycleEpochOverride    func() (uint64, error)
	lookupPIDLifecycleEpochOverride func(uint32) (uint64, error)
	putPIDLifecycleEpochOverride    func(uint32, uint64, ebpf.MapUpdateFlags) error
	removePIDLifecycleEpochOverride func(uint32) error
	lookupPIDGenerationOverride     func(uint32) (BpfLogEnricherGenerationT, error)
	putPIDGenerationOverride        func(uint32, BpfLogEnricherGenerationT) error
	removePIDGenerationOverride     func(uint32) error
	pidsMU                          sync.Mutex
}

func New(cfg *obi.Config) *Tracer {
	logger := slog.With("component", "logenricher")

	if !ebpfcommon.SupportsLogInjection(logger) {
		logger.Warn("log enrichment not supported on this system!")
		return nil
	}

	tr := &Tracer{
		log:              logger,
		cfg:              cfg,
		formatter:        newLogFormatter(cfg.EBPF.LogEnricher),
		pids:             make(map[uint64][]uint64),
		pidServices:      make(map[uint64]*exec.FileInfo),
		pidOwners:        make(map[uint64]*exec.FileInfo),
		pidKeyOwners:     make(map[uint64]map[*exec.FileInfo]struct{}),
		pidKeysByHostPID: make(map[uint32]uint64),
		pidGenerations:   make(map[uint32]BpfLogEnricherGenerationT),
	}

	workers := cfg.EBPF.LogEnricher.AsyncWriterWorkers
	tr.asyncWriterWG.Add(workers)
	asyncWriter := shardedqueue.NewShardedQueue[LogEvent](
		workers,
		cfg.EBPF.LogEnricher.AsyncWriterChannelLen,
		func(e LogEvent) string { return e.shardKey() },
		func(_ int, ch <-chan LogEvent) {
			defer tr.asyncWriterWG.Done()
			for e := range ch {
				tr.handle(e)
			}
		},
	)

	tr.asyncWriter = asyncWriter

	return tr
}

func (p *Tracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	spec, err := LoadBpf()
	if err != nil {
		return nil, err
	}
	return []*ebpfcommon.SpecBundle{{
		Spec:      spec,
		Objects:   &p.bpfObjects,
		Constants: p.constants(),
	}}, nil
}

func (p *Tracer) constants() map[string]any {
	return map[string]any{"g_bpf_debug": p.cfg.EBPF.BpfDebug}
}

func (p *Tracer) SetupTailCalls() {}

func (p *Tracer) RegisterOffsets(_ *exec.FileInfo, _ *goexec.Offsets) error { return nil }

func (p *Tracer) ProcessBinary(_ *exec.FileInfo) {}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Tracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) KProbes() map[string]ebpfcommon.ProbeDesc {
	m := map[string]ebpfcommon.ProbeDesc{
		"tty_write": {
			Start:    p.bpfObjects.ObiKprobeTtyWrite,
			Required: true,
		},
		"ksys_write": {
			Start:    p.bpfObjects.ObiKprobeKsysWrite,
			Required: true,
		},
	}

	hasDoWritev, err := ebpfcommon.KernelHasSymbol(ebpfcommon.KSymDoWritev)
	if err != nil {
		p.log.Error("error checking kernel symbol availability", "sym", ebpfcommon.KSymDoWritev, "error", err)
	}

	if hasDoWritev {
		m["do_writev"] = ebpfcommon.ProbeDesc{
			Start:    p.bpfObjects.ObiKprobeDoWritev,
			Required: false,
		}
	} else {
		p.log.Warn("do_writev kernel symbol not available; writev()-based log writes won't be enriched")
	}

	hasPipeWrite, err := ebpfcommon.KernelHasSymbol(ebpfcommon.KSymPipeWrite)
	if err != nil {
		p.log.Error("error checking kernel symbol availability", "sym", ebpfcommon.KSymPipeWrite, "error", err)
	}

	if hasPipeWrite {
		m["pipe_write"] = ebpfcommon.ProbeDesc{
			Start:    p.bpfObjects.ObiKprobePipeWrite,
			Required: true,
		}
	} else {
		hasAnonPipeWrite, err := ebpfcommon.KernelHasSymbol(ebpfcommon.KSymAnonPipeWrite)
		if err != nil {
			p.log.Error("error checking kernel symbol availability", "sym", ebpfcommon.KSymAnonPipeWrite, "error", err)
		}

		if hasAnonPipeWrite {
			m["anon_pipe_write"] = ebpfcommon.ProbeDesc{
				Start:    p.bpfObjects.ObiKprobePipeWrite,
				Required: true,
			}
		} else {
			p.log.Error("neither anon_pipe_write nor pipe_write kernel symbols are available; log enrichment may not work correctly")
		}
	}

	return m
}

func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	return map[string]ebpfcommon.ProbeDesc{
		"sched/sched_process_exec": {
			Start:    p.bpfObjects.ObiLogEnricherProcessExec,
			Required: true,
		},
		"sched/sched_process_exit": {
			Start:    p.bpfObjects.ObiLogEnricherProcessExit,
			Required: true,
		},
	}
}

func (p *Tracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc {
	return nil
}

func (p *Tracer) USDTProbes() map[string][]*ebpfcommon.USDTProbeDesc {
	return nil
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

func (p *Tracer) SockMsgs() []ebpfcommon.SockMsg {
	return nil
}

func (p *Tracer) SockOps() []ebpfcommon.SockOps {
	return nil
}

func (p *Tracer) Iters() []*ebpfcommon.Iter {
	return nil
}

func (p *Tracer) Tracing() []*ebpfcommon.Tracing { return nil }

func (p *Tracer) RecordInstrumentedLib(exec.FileID, []io.Closer) {}

func (p *Tracer) AddInstrumentedLibRef(exec.FileID) {}

func (p *Tracer) UnlinkInstrumentedLib(exec.FileID) {}

func (p *Tracer) AlreadyInstrumentedLib(exec.FileID) bool {
	return false
}

func (p *Tracer) pidKey(nsid, pid uint32) uint64 {
	return (uint64(nsid) << 32) | uint64(pid)
}

func (p *Tracer) shouldOmitSpanID(hostPID uint32) bool {
	if !p.cfg.Discovery.ExcludeOTelInstrumentedServices {
		return false
	}

	p.pidsMU.Lock()
	pidKey, tracked := p.pidKeysByHostPID[hostPID]
	s := p.pidServices[pidKey]
	p.pidsMU.Unlock()

	return tracked && s != nil && s.ExportsOTelTraces()
}

func (p *Tracer) addPID(key uint64) error {
	p.log.Debug("adding pid", "pid", uint32(key), "ns", key>>32)
	if p.addPIDOverride != nil {
		return p.addPIDOverride(key)
	}
	if p.bpfObjects.LogEnricherPids == nil {
		return fmt.Errorf("BPF objects not loaded, cannot add pid %d (ns=%d)", uint32(key), key>>32)
	}
	if err := p.bpfObjects.LogEnricherPids.Put(key, uint8(1)); err != nil {
		return fmt.Errorf("error adding pid %d (ns=%d) to bpf map: %w", uint32(key), key>>32, err)
	}
	return nil
}

func (p *Tracer) removePID(key uint64) error {
	p.log.Debug("removing pid", "pid", uint32(key), "ns", key>>32)
	if p.removePIDOverride != nil {
		return p.removePIDOverride(key)
	}
	if p.bpfObjects.LogEnricherPids == nil {
		return fmt.Errorf("BPF objects not loaded, cannot remove pid %d (ns=%d)", uint32(key), key>>32)
	}
	if err := p.bpfObjects.LogEnricherPids.Delete(key); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("error removing pid %d (ns=%d) from bpf map: %w", uint32(key), key>>32, err)
	}
	return nil
}

func (p *Tracer) newPIDLifecycleEpoch() (uint64, error) {
	if p.newPIDLifecycleEpochOverride != nil {
		return p.newPIDLifecycleEpochOverride()
	}

	var encoded [8]byte
	for {
		if _, err := rand.Read(encoded[:]); err != nil {
			return 0, fmt.Errorf("generate process lifecycle epoch: %w", err)
		}
		if epoch := binary.LittleEndian.Uint64(encoded[:]); epoch != 0 {
			return epoch, nil
		}
	}
}

func (p *Tracer) lookupPIDLifecycleEpoch(hostPID uint32) (uint64, error) {
	if p.lookupPIDLifecycleEpochOverride != nil {
		return p.lookupPIDLifecycleEpochOverride(hostPID)
	}
	if p.bpfObjects.LogEnricherLifecycleEpochs == nil {
		return 0, fmt.Errorf("BPF objects not loaded, cannot read lifecycle epoch for pid %d", hostPID)
	}

	var epoch uint64
	if err := p.bpfObjects.LogEnricherLifecycleEpochs.Lookup(hostPID, &epoch); err != nil {
		return 0, fmt.Errorf("read lifecycle epoch for pid %d from bpf map: %w", hostPID, err)
	}
	if epoch == 0 {
		return 0, fmt.Errorf("lifecycle epoch for pid %d is zero", hostPID)
	}
	return epoch, nil
}

func (p *Tracer) putPIDLifecycleEpoch(
	hostPID uint32,
	epoch uint64,
	flags ebpf.MapUpdateFlags,
) error {
	if epoch == 0 {
		return fmt.Errorf("cannot publish zero lifecycle epoch for pid %d", hostPID)
	}
	if p.putPIDLifecycleEpochOverride != nil {
		return p.putPIDLifecycleEpochOverride(hostPID, epoch, flags)
	}
	if p.bpfObjects.LogEnricherLifecycleEpochs == nil {
		return fmt.Errorf("BPF objects not loaded, cannot publish lifecycle epoch for pid %d", hostPID)
	}
	if err := p.bpfObjects.LogEnricherLifecycleEpochs.Update(hostPID, epoch, flags); err != nil {
		return fmt.Errorf("publish lifecycle epoch for pid %d to bpf map: %w", hostPID, err)
	}
	return nil
}

func (p *Tracer) removePIDLifecycleEpoch(hostPID uint32) error {
	if p.removePIDLifecycleEpochOverride != nil {
		return p.removePIDLifecycleEpochOverride(hostPID)
	}
	if p.bpfObjects.LogEnricherLifecycleEpochs == nil {
		return fmt.Errorf("BPF objects not loaded, cannot remove lifecycle epoch for pid %d", hostPID)
	}
	if err := p.bpfObjects.LogEnricherLifecycleEpochs.Delete(hostPID); err != nil &&
		!errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("remove lifecycle epoch for pid %d from bpf map: %w", hostPID, err)
	}
	return nil
}

// establishPIDLifecycleEpoch preserves the invariant that an absent epoch can
// never authorize leftover generation bytes. Callers hold pidsMU.
func (p *Tracer) establishPIDLifecycleEpoch(
	hostPID uint32,
	hasCurrentAdmission bool,
) (uint64, bool, error) {
	epoch, err := p.lookupPIDLifecycleEpoch(hostPID)
	if err == nil {
		if !hasCurrentAdmission {
			if removeErr := p.removePIDGeneration(hostPID); removeErr != nil {
				return 0, false, fmt.Errorf("disarm orphan generation before lifecycle validation: %w", removeErr)
			}
			epoch, err = p.lookupPIDLifecycleEpoch(hostPID)
			if err != nil {
				return 0, false, fmt.Errorf("re-read lifecycle epoch after disarming orphan generation: %w", err)
			}
		}
		return epoch, false, nil
	}
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return 0, false, err
	}
	if hasCurrentAdmission {
		if removeErr := p.removePIDGeneration(hostPID); removeErr != nil {
			return 0, false, errors.Join(
				fmt.Errorf("tracked pid %d has no lifecycle epoch", hostPID),
				removeErr,
			)
		}
		return 0, false, fmt.Errorf("tracked pid %d has no lifecycle epoch", hostPID)
	}
	if err := p.removePIDGeneration(hostPID); err != nil {
		return 0, false, fmt.Errorf("disarm generation before creating lifecycle epoch: %w", err)
	}

	epoch, err = p.newPIDLifecycleEpoch()
	if err != nil {
		return 0, false, err
	}
	if epoch == 0 {
		return 0, false, errors.New("generated process lifecycle epoch is zero")
	}
	if err := p.putPIDLifecycleEpoch(hostPID, epoch, ebpf.UpdateNoExist); err != nil {
		if !errors.Is(err, ebpf.ErrKeyExist) {
			return 0, false, err
		}
		current, lookupErr := p.lookupPIDLifecycleEpoch(hostPID)
		if lookupErr != nil {
			return 0, false, errors.Join(err, lookupErr)
		}
		return current, false, nil
	}
	return epoch, true, nil
}

func (p *Tracer) cleanupUncommittedPIDLifecycle(hostPID uint32, removeEpoch bool) error {
	generationErr := p.removePIDGeneration(hostPID)
	var epochErr error
	if removeEpoch {
		epochErr = p.removePIDLifecycleEpoch(hostPID)
	}
	return errors.Join(generationErr, epochErr)
}

func processGenerationForOwner(
	owner *exec.FileInfo,
	lifecycleEpoch uint64,
) (BpfLogEnricherGenerationT, error) {
	if owner == nil {
		return BpfLogEnricherGenerationT{}, errors.New("exact process owner is unavailable")
	}
	generation := BpfLogEnricherGenerationT{
		ProcessInstanceId: owner.ProcessInstanceID(),
		ProcessStartTicks: owner.ProcessStartTime(),
		ExecutableDevice:  owner.Dev(),
		ExecutableInode:   owner.Ino(),
		LifecycleEpoch:    lifecycleEpoch,
	}
	if err := validateProcessGeneration(generation); err != nil {
		return BpfLogEnricherGenerationT{}, err
	}
	return generation, nil
}

func validateProcessGeneration(generation BpfLogEnricherGenerationT) error {
	switch {
	case generation.ProcessInstanceId == 0:
		return errors.New("process instance ID is unavailable")
	case generation.ProcessStartTicks == 0:
		return errors.New("process start time is unavailable")
	case generation.ExecutableDevice == 0 || generation.ExecutableInode == 0:
		return errors.New("process executable identity is unavailable")
	case generation.LifecycleEpoch == 0:
		return errors.New("process lifecycle epoch is unavailable")
	default:
		return nil
	}
}

func processGenerationEqual(left, right BpfLogEnricherGenerationT) bool {
	return left.ProcessInstanceId == right.ProcessInstanceId &&
		left.ProcessStartTicks == right.ProcessStartTicks &&
		left.ExecutableDevice == right.ExecutableDevice &&
		left.ExecutableInode == right.ExecutableInode &&
		left.LifecycleEpoch == right.LifecycleEpoch
}

func processGenerationPresent(generation BpfLogEnricherGenerationT) bool {
	return generation.ProcessInstanceId != 0
}

func (p *Tracer) putPIDGeneration(
	hostPID uint32,
	generation BpfLogEnricherGenerationT,
) error {
	if err := validateProcessGeneration(generation); err != nil {
		return fmt.Errorf("cannot publish process generation for PID %d: %w", hostPID, err)
	}
	p.log.Debug(
		"publishing pid generation",
		"pid", hostPID,
		"generation", generation.ProcessInstanceId,
		"process_start_ticks", generation.ProcessStartTicks,
		"executable_device", generation.ExecutableDevice,
		"executable_inode", generation.ExecutableInode,
		"lifecycle_epoch", generation.LifecycleEpoch,
	)
	if p.putPIDGenerationOverride != nil {
		return p.putPIDGenerationOverride(hostPID, generation)
	}
	if p.bpfObjects.LogEnricherGenerations == nil {
		return fmt.Errorf("BPF objects not loaded, cannot publish generation for pid %d", hostPID)
	}
	if err := p.bpfObjects.LogEnricherGenerations.Update(hostPID, generation, ebpf.UpdateNoExist); err != nil {
		return fmt.Errorf("error publishing generation for pid %d to bpf map: %w", hostPID, err)
	}
	return nil
}

func (p *Tracer) lookupPIDGeneration(hostPID uint32) (BpfLogEnricherGenerationT, error) {
	if p.lookupPIDGenerationOverride != nil {
		return p.lookupPIDGenerationOverride(hostPID)
	}
	if p.bpfObjects.LogEnricherGenerations == nil {
		return BpfLogEnricherGenerationT{}, fmt.Errorf(
			"BPF objects not loaded, cannot read generation for pid %d",
			hostPID,
		)
	}

	var generation BpfLogEnricherGenerationT
	if err := p.bpfObjects.LogEnricherGenerations.Lookup(hostPID, &generation); err != nil {
		return BpfLogEnricherGenerationT{}, fmt.Errorf(
			"read generation for pid %d from bpf map: %w",
			hostPID,
			err,
		)
	}
	return generation, nil
}

func (p *Tracer) removePIDGeneration(hostPID uint32) error {
	p.log.Debug("removing pid generation", "pid", hostPID)
	if p.removePIDGenerationOverride != nil {
		return p.removePIDGenerationOverride(hostPID)
	}
	if p.bpfObjects.LogEnricherGenerations == nil {
		return fmt.Errorf("BPF objects not loaded, cannot remove generation for pid %d", hostPID)
	}
	if err := p.bpfObjects.LogEnricherGenerations.Delete(hostPID); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return fmt.Errorf("error removing generation for pid %d from bpf map: %w", hostPID, err)
	}
	return nil
}

func (p *Tracer) removePIDGenerationIfEqual(
	hostPID uint32,
	expected BpfLogEnricherGenerationT,
) error {
	current, err := p.lookupPIDGeneration(hostPID)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !processGenerationEqual(current, expected) {
		return fmt.Errorf(
			"generation for pid %d was replaced before disarm: got instance=%d epoch=%d, expected instance=%d epoch=%d",
			hostPID,
			current.ProcessInstanceId,
			current.LifecycleEpoch,
			expected.ProcessInstanceId,
			expected.LifecycleEpoch,
		)
	}
	return p.removePIDGeneration(hostPID)
}

func clonePIDOwnerSet(owners map[*exec.FileInfo]struct{}) map[*exec.FileInfo]struct{} {
	cloned := make(map[*exec.FileInfo]struct{}, len(owners))
	for owner := range owners {
		cloned[owner] = struct{}{}
	}
	return cloned
}

type pidGenerationChange struct {
	hostPID       uint32
	expected      BpfLogEnricherGenerationT
	expectedOwner *exec.FileInfo
	desired       BpfLogEnricherGenerationT
	desiredOwner  *exec.FileInfo
}

func (p *Tracer) validatePIDLifecycleEpoch(hostPID uint32, expected uint64) error {
	current, err := p.lookupPIDLifecycleEpoch(hostPID)
	if err != nil {
		return err
	}
	if current != expected {
		return fmt.Errorf(
			"process lifecycle epoch for pid %d changed: got %d, expected %d",
			hostPID,
			current,
			expected,
		)
	}
	return nil
}

func (p *Tracer) validatePublishedPIDGeneration(change *pidGenerationChange) error {
	if err := p.validatePIDLifecycleEpoch(
		change.hostPID,
		change.desired.LifecycleEpoch,
	); err != nil {
		return fmt.Errorf("validate lifecycle epoch after generation publication: %w", err)
	}
	if err := validateExactProcessOwner(app.PID(change.hostPID), change.desiredOwner); err != nil {
		return fmt.Errorf("validate exact owner after generation publication: %w", err)
	}
	if err := p.validatePIDLifecycleEpoch(
		change.hostPID,
		change.desired.LifecycleEpoch,
	); err != nil {
		return fmt.Errorf("revalidate lifecycle epoch after exact owner: %w", err)
	}
	return nil
}

// applyPIDOwnerChanges updates the BPF admission set before publishing the
// matching Go ownership. Callers hold pidsMU, so enqueue observes either the
// complete predecessor state or the complete replacement state.
func (p *Tracer) applyPIDOwnerChanges(
	desired map[uint64]map[*exec.FileInfo]struct{},
) error {
	return p.applyPIDAdmissionChanges(desired, nil)
}

// applyPIDAdmissionChanges disarms an existing host-TGID generation before
// changing namespace admission, then publishes the desired generation last.
// While disarmed, BPF leaves application writes untouched. This prevents a
// replacement process from having a write consumed under its predecessor's
// generation. Rollback restores the predecessor generation only after every
// namespace mutation has been undone; an incomplete rollback deliberately
// leaves the generation absent so logging remains fail-open.
func (p *Tracer) applyPIDAdmissionChanges(
	desired map[uint64]map[*exec.FileInfo]struct{},
	generation *pidGenerationChange,
) error {
	if generation != nil {
		current := p.pidGenerations[generation.hostPID]
		if !processGenerationEqual(current, generation.expected) {
			return fmt.Errorf(
				"process generation for PID %d changed: got instance=%d start=%d dev=%d inode=%d, expected instance=%d start=%d dev=%d inode=%d",
				generation.hostPID,
				current.ProcessInstanceId,
				current.ProcessStartTicks,
				current.ExecutableDevice,
				current.ExecutableInode,
				generation.expected.ProcessInstanceId,
				generation.expected.ProcessStartTicks,
				generation.expected.ExecutableDevice,
				generation.expected.ExecutableInode,
			)
		}
	}

	generationChanged := generation != nil &&
		!processGenerationEqual(generation.desired, generation.expected)
	generationDisarmed := false
	if generationChanged && processGenerationPresent(generation.expected) {
		if err := p.removePIDGenerationIfEqual(
			generation.hostPID,
			generation.expected,
		); err != nil {
			return fmt.Errorf("disarming predecessor process generation: %w", err)
		}
		generationDisarmed = true
	}

	addedBPFKeys := make([]uint64, 0, len(desired))
	removedBPFKeys := make([]uint64, 0, len(desired))
	generationPublished := false
	rollback := func(cause error) error {
		var rollbackErr error
		if generationPublished {
			if err := p.removePIDGenerationIfEqual(
				generation.hostPID,
				generation.desired,
			); err != nil {
				p.log.Error("failed to disarm uncommitted log enricher generation", "error", err)
				rollbackErr = errors.Join(rollbackErr, err)
			}
		}
		for i := len(removedBPFKeys) - 1; i >= 0; i-- {
			if err := p.addPID(removedBPFKeys[i]); err != nil {
				p.log.Error("failed to roll back removed log enricher PID", "error", err)
				rollbackErr = errors.Join(rollbackErr, err)
			}
		}
		for i := len(addedBPFKeys) - 1; i >= 0; i-- {
			if err := p.removePID(addedBPFKeys[i]); err != nil {
				p.log.Error("failed to roll back added log enricher PID", "error", err)
				rollbackErr = errors.Join(rollbackErr, err)
			}
		}
		if generationDisarmed && rollbackErr == nil {
			if err := p.validatePIDLifecycleEpoch(
				generation.hostPID,
				generation.expected.LifecycleEpoch,
			); err != nil {
				p.log.Debug(
					"not restoring retired predecessor log enricher generation",
					"pid", generation.hostPID,
					"error", err,
				)
				return errors.Join(cause, rollbackErr)
			}
			if err := validateExactProcessOwner(
				app.PID(generation.hostPID),
				generation.expectedOwner,
			); err != nil {
				p.log.Debug(
					"not restoring changed predecessor log enricher owner",
					"pid", generation.hostPID,
					"error", err,
				)
				return errors.Join(cause, rollbackErr)
			}
			if err := p.putPIDGeneration(generation.hostPID, generation.expected); err != nil {
				p.log.Error("failed to restore predecessor log enricher generation", "error", err)
				rollbackErr = errors.Join(rollbackErr, err)
			} else if err := p.validatePIDLifecycleEpoch(
				generation.hostPID,
				generation.expected.LifecycleEpoch,
			); err != nil {
				p.log.Debug(
					"predecessor lifecycle retired while its generation was restored",
					"pid", generation.hostPID,
					"error", err,
				)
			}
		}
		return errors.Join(cause, rollbackErr)
	}

	for key, owners := range desired {
		if len(p.pidKeyOwners[key]) != 0 || len(owners) == 0 {
			continue
		}
		if err := p.addPID(key); err != nil {
			return rollback(err)
		}
		addedBPFKeys = append(addedBPFKeys, key)
	}
	for key, owners := range desired {
		if len(p.pidKeyOwners[key]) == 0 || len(owners) != 0 {
			continue
		}
		if err := p.removePID(key); err != nil {
			return rollback(err)
		}
		removedBPFKeys = append(removedBPFKeys, key)
	}

	if generationChanged && processGenerationPresent(generation.desired) {
		if err := p.putPIDGeneration(generation.hostPID, generation.desired); err != nil {
			return rollback(err)
		}
		generationPublished = true
		if err := p.validatePublishedPIDGeneration(generation); err != nil {
			return rollback(err)
		}
	}

	if p.pidKeyOwners == nil {
		p.pidKeyOwners = make(map[uint64]map[*exec.FileInfo]struct{})
	}
	for key, owners := range desired {
		if len(owners) == 0 {
			delete(p.pidKeyOwners, key)
			continue
		}
		p.pidKeyOwners[key] = owners
	}
	if generation != nil {
		if p.pidGenerations == nil {
			p.pidGenerations = make(map[uint32]BpfLogEnricherGenerationT)
		}
		if !processGenerationPresent(generation.desired) {
			delete(p.pidGenerations, generation.hostPID)
		} else {
			p.pidGenerations[generation.hostPID] = generation.desired
		}
	}
	return nil
}

func (p *Tracer) addPIDOwner(key uint64, owner *exec.FileInfo) error {
	if owner == nil {
		return errors.New("exact log enricher PID owner is unavailable")
	}
	owners := clonePIDOwnerSet(p.pidKeyOwners[key])
	if _, exists := owners[owner]; exists {
		return nil
	}
	owners[owner] = struct{}{}
	return p.applyPIDOwnerChanges(map[uint64]map[*exec.FileInfo]struct{}{key: owners})
}

func (p *Tracer) removePIDOwner(key uint64, owner *exec.FileInfo) error {
	owners := p.pidKeyOwners[key]
	if len(owners) == 0 {
		// Preserve the legacy/test behavior for state created before owner
		// accounting was available.
		return p.removePID(key)
	}
	desired := clonePIDOwnerSet(owners)
	if owner == nil {
		clear(desired)
	} else if _, exists := desired[owner]; exists {
		delete(desired, owner)
	} else {
		return nil
	}
	return p.applyPIDOwnerChanges(
		map[uint64]map[*exec.FileInfo]struct{}{key: desired},
	)
}

func (p *Tracer) AllowPID(pid app.PID, ns uint32, fi, owner *exec.FileInfo) bool {
	p.pidsMU.Lock()
	defer p.pidsMU.Unlock()
	if owner == nil {
		owner = fi
	}
	if owner == nil {
		p.log.Error("allow pid: exact process owner is unavailable", "pid", pid)
		return false
	}

	hostPID := uint32(pid)
	previousKey, tracked := p.pidKeysByHostPID[hostPID]
	currentGeneration := p.pidGenerations[hostPID]
	hasCurrentAdmission := tracked || processGenerationPresent(currentGeneration)
	lifecycleEpoch, epochCreated, err := p.establishPIDLifecycleEpoch(hostPID, hasCurrentAdmission)
	if err != nil {
		p.log.Error("allow pid: cannot establish process lifecycle epoch", "pid", pid, "error", err)
		return false
	}
	lifecycleCommitted := hasCurrentAdmission
	defer func() {
		if lifecycleCommitted {
			return
		}
		if err := p.cleanupUncommittedPIDLifecycle(hostPID, epochCreated); err != nil {
			p.log.Error("allow pid: failed to clean uncommitted process lifecycle", "pid", pid, "error", err)
		}
	}()

	if processGenerationPresent(currentGeneration) &&
		currentGeneration.LifecycleEpoch != lifecycleEpoch &&
		currentGeneration.ProcessInstanceId == owner.ProcessInstanceID() {
		p.log.Error(
			"allow pid: discovery admission was retired by exec or exit",
			"pid", pid,
			"generation", currentGeneration.ProcessInstanceId,
			"generation_epoch", currentGeneration.LifecycleEpoch,
			"current_epoch", lifecycleEpoch,
		)
		return false
	}

	processGeneration, err := processGenerationForOwner(owner, lifecycleEpoch)
	if err != nil {
		p.log.Error("allow pid: exact process generation is unavailable", "pid", pid, "error", err)
		return false
	}

	pk := p.pidKey(ns, uint32(pid))
	nsPids, err := ebpfcommon.NamespacedPIDsForOwner(pid, owner)
	if err != nil {
		p.log.Error("allow pid: error finding namespaced pids", "error", err)
		return false
	}

	aliases := make([]uint64, 0, len(nsPids))
	for _, nsPid := range nsPids {
		if pid == nsPid {
			continue
		}
		aliases = append(aliases, p.pidKey(ns, uint32(nsPid)))
	}

	newKeys := make(map[uint64]struct{}, len(aliases)+1)
	newKeys[pk] = struct{}{}
	for _, alias := range aliases {
		newKeys[alias] = struct{}{}
	}

	type admission struct {
		key     uint64
		owner   *exec.FileInfo
		aliases []uint64
	}
	predecessors := make([]admission, 0, 2)
	seenPredecessor := make(map[uint64]struct{}, 2)
	addPredecessor := func(key uint64) bool {
		if _, seen := seenPredecessor[key]; seen {
			return true
		}
		previousOwner, registered := p.pidOwners[key]
		if !registered || previousOwner == nil {
			return false
		}
		seenPredecessor[key] = struct{}{}
		predecessors = append(predecessors, admission{
			key:     key,
			owner:   previousOwner,
			aliases: append([]uint64(nil), p.pids[key]...),
		})
		return true
	}
	if tracked {
		if !addPredecessor(previousKey) {
			p.log.Error("allow pid: current process admission has no exact owner", "pid", pid)
			return false
		}
		previousGeneration, generationErr := processGenerationForOwner(
			p.pidOwners[previousKey],
			currentGeneration.LifecycleEpoch,
		)
		if generationErr != nil || !processGenerationEqual(currentGeneration, previousGeneration) {
			p.log.Error(
				"allow pid: current process generation does not match its exact owner",
				"pid", pid,
				"generation", currentGeneration.ProcessInstanceId,
				"owner_generation", previousGeneration.ProcessInstanceId,
				"error", generationErr,
			)
			return false
		}
		if p.pidOwners[previousKey] != owner &&
			previousGeneration.ProcessInstanceId == processGeneration.ProcessInstanceId {
			p.log.Error(
				"allow pid: replacement reused the current process generation",
				"pid", pid,
				"generation", processGeneration.ProcessInstanceId,
			)
			return false
		}
	} else if processGenerationPresent(currentGeneration) {
		p.log.Error(
			"allow pid: process generation has no current exact owner",
			"pid", pid,
			"generation", currentGeneration.ProcessInstanceId,
		)
		return false
	}
	if _, registeredAtNewKey := p.pidOwners[pk]; registeredAtNewKey {
		if !addPredecessor(pk) {
			p.log.Error("allow pid: replacement key has no exact owner", "pid", pid, "ns", ns)
			return false
		}
	}

	desired := make(map[uint64]map[*exec.FileInfo]struct{}, len(newKeys)+len(predecessors)*2)
	desiredOwners := func(key uint64) map[*exec.FileInfo]struct{} {
		if owners, ok := desired[key]; ok {
			return owners
		}
		owners := clonePIDOwnerSet(p.pidKeyOwners[key])
		desired[key] = owners
		return owners
	}
	for _, predecessor := range predecessors {
		for _, oldKey := range append([]uint64{predecessor.key}, predecessor.aliases...) {
			delete(desiredOwners(oldKey), predecessor.owner)
		}
	}
	for key := range newKeys {
		desiredOwners(key)[owner] = struct{}{}
	}
	if err := p.applyPIDAdmissionChanges(desired, &pidGenerationChange{
		hostPID:       hostPID,
		expected:      currentGeneration,
		expectedOwner: p.pidOwners[previousKey],
		desired:       processGeneration,
		desiredOwner:  owner,
	}); err != nil {
		p.log.Error("allow pid: failed to update BPF PID admission", "pid", pid, "error", err)
		return false
	}

	for _, predecessor := range predecessors {
		if p.pidOwners[predecessor.key] != predecessor.owner {
			continue
		}
		delete(p.pids, predecessor.key)
		delete(p.pidServices, predecessor.key)
		delete(p.pidOwners, predecessor.key)
	}

	p.pids[pk] = aliases
	if fi != nil {
		p.pidServices[pk] = fi
	} else {
		delete(p.pidServices, pk)
	}
	p.pidOwners[pk] = owner
	p.pidKeysByHostPID[hostPID] = pk
	lifecycleCommitted = true
	return true
}

func (p *Tracer) BlockPID(pid app.PID, ns uint32, _ *exec.FileInfo, owner *exec.FileInfo) {
	p.pidsMU.Lock()
	defer p.pidsMU.Unlock()

	pk := p.pidKey(ns, uint32(pid))
	if owner != nil && p.pidOwners[pk] != owner {
		return
	}
	currentOwner := p.pidOwners[pk]
	if currentOwner != nil && owner == nil {
		p.log.Error("block pid: exact process owner is unavailable", "pid", pid)
		return
	}
	knownPids := append([]uint64(nil), p.pids[pk]...)
	keys := append([]uint64{pk}, knownPids...)
	if currentOwner != nil {
		desired := make(map[uint64]map[*exec.FileInfo]struct{}, len(keys))
		for _, key := range keys {
			owners := clonePIDOwnerSet(p.pidKeyOwners[key])
			delete(owners, currentOwner)
			desired[key] = owners
		}
		var generation *pidGenerationChange
		hostPID := uint32(pid)
		if p.pidKeysByHostPID[hostPID] == pk {
			currentGeneration := p.pidGenerations[hostPID]
			processGeneration, generationErr := processGenerationForOwner(
				currentOwner,
				currentGeneration.LifecycleEpoch,
			)
			if generationErr != nil ||
				!processGenerationEqual(currentGeneration, processGeneration) {
				p.log.Error(
					"block pid: current process generation does not match its exact owner",
					"pid", pid,
					"generation", p.pidGenerations[hostPID].ProcessInstanceId,
					"owner_generation", processGeneration.ProcessInstanceId,
					"error", generationErr,
				)
				return
			}
			generation = &pidGenerationChange{
				hostPID:       hostPID,
				expected:      processGeneration,
				expectedOwner: currentOwner,
			}
		}
		if err := p.applyPIDAdmissionChanges(desired, generation); err != nil {
			p.log.Error("block pid: failed to update BPF PID admission", "pid", pid, "error", err)
			return
		}
	} else {
		// Preserve cleanup of legacy/test state that predates exact owners.
		removed := make([]uint64, 0, len(keys))
		for _, key := range keys {
			if err := p.removePID(key); err != nil {
				for i := len(removed) - 1; i >= 0; i-- {
					if rollbackErr := p.addPID(removed[i]); rollbackErr != nil {
						p.log.Error("failed to roll back legacy log enricher PID", "error", rollbackErr)
					}
				}
				p.log.Error("block pid: failed to remove legacy BPF PID admission", "pid", pid, "error", err)
				return
			}
			removed = append(removed, key)
		}
	}

	delete(p.pidServices, pk)
	delete(p.pidOwners, pk)
	delete(p.pids, pk)
	if p.pidKeysByHostPID[uint32(pid)] == pk {
		delete(p.pidKeysByHostPID, uint32(pid))
		if err := p.removePIDLifecycleEpoch(uint32(pid)); err != nil {
			p.log.Error("block pid: failed to remove process lifecycle epoch", "pid", pid, "error", err)
		}
	}
	if len(knownPids) == 0 {
		p.log.Debug("block pid: namespaced pids not found in internal cache, removing only the given pid", "pid", pid, "ns", ns)
	}
}

func (p *Tracer) Run(ctx context.Context, _ *ebpfcommon.EBPFEventContext, _ *msg.Queue[[]request.Span]) {
	p.log.Debug("starting")

	p.ctx = ctx
	defer p.shutdownAsyncWriter()

	ebpfcommon.ForwardRingbuf(
		&p.cfg.EBPF,
		p.bpfObjects.LogEvents,
		p.handleLogEvent,
		nil,
		p.log,
		nil,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, nil)

	p.log.Debug("terminating")
}

func (p *Tracer) shutdownAsyncWriter() {
	p.asyncWriterMU.Lock()
	p.asyncWriterClosed = true
	if p.asyncWriter != nil {
		p.asyncWriter.Close()
	}
	p.asyncWriterMU.Unlock()
	p.asyncWriterWG.Wait()
}

func (p *Tracer) SetEventContext(_ *ebpfcommon.EBPFEventContext) {}

func (p *Tracer) Capabilities() ebpfcommon.TracerCapability { return 0 }

func (p *Tracer) Required() bool {
	return false
}

func (p *Tracer) handleLogEvent(record *ringbuf.Record) (request.Span, bool, error) {
	hdrSize := int(unsafe.Offsetof(BpfLogEventT{}.Log)) // Remove `log` placeholder.
	if len(record.RawSample) < hdrSize {
		// This should never happen -- if it does, we can't really recover
		// and the targeted process will miss his logs.
		return request.Span{}, true, nil
	}
	var event BpfLogEventT
	eventHeader := unsafe.Slice((*byte)(unsafe.Pointer(&event)), hdrSize)
	copy(eventHeader, record.RawSample[:hdrSize])
	if uint64(event.Len) > uint64(len(record.RawSample)-hdrSize) {
		return request.Span{}, true, nil
	}
	logEnd := hdrSize + int(event.Len)

	err := p.enqueueLogEvent(
		event,
		unix.ByteSliceToString(record.RawSample[hdrSize:logEnd]),
	)
	return request.Span{}, true, err
}

func (p *Tracer) enqueueLogEvent(orig BpfLogEventT, logLine string) error {
	event, err := p.bindLogEvent(orig, logLine)
	if err != nil {
		return err
	}
	p.asyncWriterMU.Lock()
	if p.asyncWriter == nil || p.asyncWriterClosed {
		p.asyncWriterMU.Unlock()
		return errors.Join(errors.New("async log writer is unavailable"), event.close())
	}
	ctx := p.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	err = p.asyncWriter.Enqueue(ctx, event)
	p.asyncWriterMU.Unlock()
	if err != nil {
		return errors.Join(err, event.close())
	}
	return nil
}

func (p *Tracer) bindLogEvent(orig BpfLogEventT, logLine string) (LogEvent, error) {
	p.pidsMU.Lock()
	defer p.pidsMU.Unlock()
	pidKey, tracked := p.pidKeysByHostPID[orig.Tgid]
	owner := p.pidOwners[pidKey]
	if !tracked || owner == nil {
		return LogEvent{}, fmt.Errorf("exact process owner for log PID %d is unavailable", orig.Tgid)
	}
	ownerGeneration := owner.ProcessInstanceID()
	publishedGeneration := p.pidGenerations[orig.Tgid]
	if orig.ProcessInstanceId == 0 || ownerGeneration == 0 ||
		orig.ProcessInstanceId != ownerGeneration ||
		orig.ProcessInstanceId != publishedGeneration.ProcessInstanceId ||
		orig.LifecycleEpoch == 0 ||
		orig.LifecycleEpoch != publishedGeneration.LifecycleEpoch {
		return LogEvent{}, fmt.Errorf(
			"log event generation for PID %d does not match current exact owner: event=%d/%d owner=%d published=%d/%d",
			orig.Tgid,
			orig.ProcessInstanceId,
			orig.LifecycleEpoch,
			ownerGeneration,
			publishedGeneration.ProcessInstanceId,
			publishedGeneration.LifecycleEpoch,
		)
	}
	if err := p.validateCurrentLogEventGeneration(orig); err != nil {
		return LogEvent{}, err
	}
	procDir, err := duplicateProcessHandle(owner)
	if err != nil {
		return LogEvent{}, fmt.Errorf("duplicate exact process handle for log PID %d: %w", orig.Tgid, err)
	}

	event := LogEvent{
		orig:          orig,
		logLine:       logLine,
		ownerIdentity: newLogOwnerIdentity(owner, orig.LifecycleEpoch),
		procDir:       procDir,
	}
	if err := validateBoundLogOwner(event, owner); err != nil {
		return LogEvent{}, errors.Join(err, event.close())
	}
	target, err := openLogTarget(event)
	if err != nil {
		return LogEvent{}, errors.Join(
			fmt.Errorf("open exact log target for PID %d: %w", orig.Tgid, err),
			event.close(),
		)
	}
	event.pinnedTarget = target
	if err := validatePinnedLogTarget(event); err != nil {
		return LogEvent{}, errors.Join(err, event.close())
	}
	if err := p.validateCurrentLogEventGeneration(orig); err != nil {
		return LogEvent{}, errors.Join(err, event.close())
	}
	return event, nil
}

func (p *Tracer) validateCurrentLogEventGeneration(orig BpfLogEventT) error {
	epoch, err := p.lookupPIDLifecycleEpoch(orig.Tgid)
	if err != nil {
		return fmt.Errorf("validate log event lifecycle epoch for PID %d: %w", orig.Tgid, err)
	}
	if orig.LifecycleEpoch == 0 || epoch != orig.LifecycleEpoch {
		return fmt.Errorf(
			"log event lifecycle epoch for PID %d is retired: event=%d current=%d",
			orig.Tgid,
			orig.LifecycleEpoch,
			epoch,
		)
	}
	generation, err := p.lookupPIDGeneration(orig.Tgid)
	if err != nil {
		return fmt.Errorf("validate current log event generation for PID %d: %w", orig.Tgid, err)
	}
	if generation.ProcessInstanceId != orig.ProcessInstanceId ||
		generation.LifecycleEpoch != orig.LifecycleEpoch {
		return fmt.Errorf(
			"log event generation for PID %d is no longer current: event=%d/%d current=%d/%d",
			orig.Tgid,
			orig.ProcessInstanceId,
			orig.LifecycleEpoch,
			generation.ProcessInstanceId,
			generation.LifecycleEpoch,
		)
	}
	return nil
}

func duplicateProcessHandle(owner *exec.FileInfo) (*os.File, error) {
	var duplicate *os.File
	err := owner.UseProcessHandle(func(fd int) error {
		duplicateFD, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return err
		}
		duplicate = os.NewFile(uintptr(duplicateFD), "exact-log-process")
		if duplicate == nil {
			_ = unix.Close(duplicateFD)
			return errors.New("create duplicated exact process handle")
		}
		return nil
	})
	return duplicate, err
}

func validateExactProcessOwner(pid app.PID, owner *exec.FileInfo) error {
	if owner == nil || owner.Pid() != pid || owner.ProcessStartTime() == 0 {
		return fmt.Errorf(
			"log PID %d does not have a matching exact process owner",
			pid,
		)
	}
	return owner.UseProcessHandle(func(fd int) error {
		return validateExactProcessOwnerFD(pid, owner, fd)
	})
}

func validateExactProcessOwnerFD(pid app.PID, owner *exec.FileInfo, fd int) error {
	currentPID, start, state, err := procs.ProcessIdentityFromProcFD(fd)
	if err != nil {
		return fmt.Errorf("validate exact log process PID %d: %w", pid, err)
	}
	if currentPID != owner.Pid() || start != owner.ProcessStartTime() ||
		state == 'Z' || state == 'X' || state == 'x' {
		return fmt.Errorf(
			"exact log process changed: got PID %d start %d state %q, expected PID %d start %d",
			currentPID, start, state, owner.Pid(), owner.ProcessStartTime(),
		)
	}
	dev, ino, err := procs.ExecutableIdentityFromProcFD(fd)
	if err != nil {
		return fmt.Errorf("validate exact log executable for PID %d: %w", pid, err)
	}
	if dev != owner.Dev() || ino != owner.Ino() {
		return fmt.Errorf(
			"exact log process executable changed: got dev=%d inode=%d, expected dev=%d inode=%d",
			dev, ino, owner.Dev(), owner.Ino(),
		)
	}
	return nil
}

func validateBoundLogOwner(event LogEvent, owner *exec.FileInfo) error {
	if event.procDir == nil {
		return fmt.Errorf("exact log process handle for PID %d is unavailable", event.orig.Tgid)
	}
	return validateExactProcessOwnerFD(app.PID(event.orig.Tgid), owner, int(event.procDir.Fd()))
}

func newLogOwnerIdentity(owner *exec.FileInfo, lifecycleEpoch uint64) logOwnerIdentity {
	if processInstanceID := owner.ProcessInstanceID(); processInstanceID != 0 {
		return logOwnerIdentity{
			processInstanceID: processInstanceID,
			lifecycleEpoch:    lifecycleEpoch,
		}
	}
	return logOwnerIdentity{lifecycleEpoch: lifecycleEpoch, fallbackOwner: owner}
}

func (e *LogEvent) closeProcessHandle() error {
	if e.procDir == nil {
		return nil
	}
	procDir := e.procDir
	e.procDir = nil
	return procDir.Close()
}

func (e *LogEvent) close() error {
	var targetErr error
	if e.pinnedTarget != nil {
		target := e.pinnedTarget
		e.pinnedTarget = nil
		targetErr = target.Close()
	}
	return errors.Join(targetErr, e.closeProcessHandle())
}

func (e LogEvent) target() (fd uint32, path string) {
	if e.orig.Fd != 0 {
		return e.orig.Fd, ""
	}

	path = unix.ByteSliceToString(e.orig.FilePath[:])
	if path == "" {
		// Fallback to the exact process's stdout when path resolution failed.
		return 1, ""
	}
	return 0, path
}

func (e LogEvent) targetKey() logTargetKey {
	fd, path := e.target()
	return logTargetKey{
		owner: e.ownerIdentity,
		dev:   e.orig.TargetDevice,
		ino:   e.orig.TargetInode,
		fd:    fd,
		path:  path,
	}
}

func (e LogEvent) shardKey() string {
	key := e.targetKey()
	return fmt.Sprintf(
		"%d:%d:%p:%d:%d:%d:%s",
		key.owner.processInstanceID,
		key.owner.lifecycleEpoch,
		key.owner.fallbackOwner,
		key.dev,
		key.ino,
		key.fd,
		key.path,
	)
}

func (e LogEvent) targetDescription() string {
	fd, path := e.target()
	if path != "" {
		return path
	}
	return "exact-process-fd/" + strconv.FormatUint(uint64(fd), 10)
}

func openLogTarget(e LogEvent) (*os.File, error) {
	fd, path := e.target()
	if path != "" {
		return os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	}
	if e.procDir == nil {
		return nil, errors.New("exact process handle is unavailable")
	}
	targetFD, err := unix.Openat(
		int(e.procDir.Fd()),
		"fd/"+strconv.FormatUint(uint64(fd), 10),
		unix.O_WRONLY|unix.O_APPEND|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return nil, err
	}
	target := os.NewFile(uintptr(targetFD), "exact-process-log-target")
	if target == nil {
		_ = unix.Close(targetFD)
		return nil, errors.New("create exact process log target")
	}
	return target, nil
}

func validatePinnedLogTarget(e LogEvent) error {
	if e.pinnedTarget == nil {
		return errors.New("exact log target is unavailable")
	}
	if e.orig.TargetDevice == 0 || e.orig.TargetInode == 0 {
		return fmt.Errorf("exact log target identity for PID %d is unavailable", e.orig.Tgid)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(e.pinnedTarget.Fd()), &stat); err != nil {
		return fmt.Errorf("validate exact log target for PID %d: %w", e.orig.Tgid, err)
	}
	if stat.Dev != e.orig.TargetDevice || stat.Ino != e.orig.TargetInode {
		return fmt.Errorf(
			"exact log target for PID %d changed: got dev=%d inode=%d, expected dev=%d inode=%d",
			e.orig.Tgid,
			stat.Dev,
			stat.Ino,
			e.orig.TargetDevice,
			e.orig.TargetInode,
		)
	}
	return nil
}

func (p *Tracer) handle(e LogEvent) {
	defer func() {
		if err := e.close(); err != nil {
			p.log.Error("failed to close exact log event resources", "error", err)
		}
	}()

	if err := validatePinnedLogTarget(e); err != nil {
		p.log.Error("invalid pinned log target", "target", e.targetDescription(), "error", err)
		return
	}
	if err := p.validateCurrentLogEventGeneration(e.orig); err != nil {
		p.log.Debug("discarding retired log event", "pid", e.orig.Tgid, "error", err)
		return
	}

	var (
		zeroTraceID [16]uint8
		zeroSpanID  [8]uint8
	)
	if e.orig.Ctx.TraceId == zeroTraceID || e.orig.Ctx.SpanId == zeroSpanID {
		// No trace context to inject, write original log line
		_, err := e.pinnedTarget.Write([]byte(e.logLine))
		if err != nil {
			p.log.Error("failed to write log line", "error", err)
		}
		return
	}

	spanID := trace.SpanID(e.orig.Ctx.SpanId)
	traceID := trace.TraceID(e.orig.Ctx.TraceId)
	includeSpan := !p.shouldOmitSpanID(e.orig.Tgid)

	out, err := p.formatter.format([]byte(e.logLine), traceID.String(), spanID.String(), includeSpan)
	if err != nil {
		p.log.Warn("failed to format enriched log line, writing original", "error", err)
		out = []byte(e.logLine)
	}

	_, err = e.pinnedTarget.Write(out)
	if err != nil {
		p.log.Error("failed to write enriched log line", "error", err)
	}
}
