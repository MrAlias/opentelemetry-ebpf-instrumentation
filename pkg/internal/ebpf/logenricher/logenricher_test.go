// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package logenricher

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/ebpf/ringbuf"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/internal/shardedqueue"
	"go.opentelemetry.io/obi/pkg/obi"
)

//go:embed bpf_x86_bpfel.o
var logEnricherBPFX86Object []byte

//go:embed bpf_arm64_bpfel.o
var logEnricherBPFARM64Object []byte

const (
	testPIDOTelService  uint32 = 33
	testPIDNonOTel      uint32 = 7
	testPIDFlagFlip     uint32 = 55
	testPIDDisabledGate uint32 = 42
	testPIDUntracked    uint32 = 99
)

func applyTestTraceContext(m map[string]any, includeSpan bool) {
	applyTraceContext(m, obi.DefaultConfig.EBPF.LogEnricher.FieldNames, testTraceID, testSpanID, includeSpan)
}

func newTestTracer(t *testing.T, exclude bool) *Tracer {
	t.Helper()
	return &Tracer{
		log: slog.With("component", "logenricher-test"),
		cfg: &obi.Config{
			Discovery: services.DiscoveryConfig{
				ExcludeOTelInstrumentedServices: exclude,
			},
		},
		pids:             map[uint64][]uint64{},
		pidServices:      map[uint64]*exec.FileInfo{},
		pidOwners:        map[uint64]*exec.FileInfo{},
		pidKeyOwners:     map[uint64]map[*exec.FileInfo]struct{}{},
		pidKeysByHostPID: map[uint32]uint64{},
		pidGenerations:   map[uint32]BpfLogEnricherGenerationT{},
		pidsMU:           sync.Mutex{},
	}
}

type testPIDMaps struct {
	pids        map[uint64]uint8
	epochs      map[uint32]uint64
	generations map[uint32]BpfLogEnricherGenerationT
	nextEpoch   uint64
}

func installTestPIDMap(tr *Tracer) *testPIDMaps {
	maps := &testPIDMaps{
		pids:        make(map[uint64]uint8),
		epochs:      make(map[uint32]uint64),
		generations: make(map[uint32]BpfLogEnricherGenerationT),
		nextEpoch:   1000,
	}
	tr.addPIDOverride = func(key uint64) error {
		maps.pids[key] = 1
		return nil
	}
	tr.removePIDOverride = func(key uint64) error {
		delete(maps.pids, key)
		return nil
	}
	tr.newPIDLifecycleEpochOverride = func() (uint64, error) {
		maps.nextEpoch++
		return maps.nextEpoch, nil
	}
	tr.lookupPIDLifecycleEpochOverride = func(hostPID uint32) (uint64, error) {
		epoch, ok := maps.epochs[hostPID]
		if !ok {
			return 0, ebpf.ErrKeyNotExist
		}
		return epoch, nil
	}
	tr.putPIDLifecycleEpochOverride = func(
		hostPID uint32,
		epoch uint64,
		flags ebpf.MapUpdateFlags,
	) error {
		_, exists := maps.epochs[hostPID]
		if flags == ebpf.UpdateNoExist && exists {
			return ebpf.ErrKeyExist
		}
		if flags == ebpf.UpdateExist && !exists {
			return ebpf.ErrKeyNotExist
		}
		maps.epochs[hostPID] = epoch
		return nil
	}
	tr.removePIDLifecycleEpochOverride = func(hostPID uint32) error {
		delete(maps.epochs, hostPID)
		return nil
	}
	tr.lookupPIDGenerationOverride = func(
		hostPID uint32,
	) (BpfLogEnricherGenerationT, error) {
		generation, ok := maps.generations[hostPID]
		if !ok {
			return BpfLogEnricherGenerationT{}, ebpf.ErrKeyNotExist
		}
		return generation, nil
	}
	tr.putPIDGenerationOverride = func(
		hostPID uint32,
		generation BpfLogEnricherGenerationT,
	) error {
		if err := validateProcessGeneration(generation); err != nil {
			return fmt.Errorf("invalid test process generation: %w", err)
		}
		if _, exists := maps.generations[hostPID]; exists {
			return ebpf.ErrKeyExist
		}
		maps.generations[hostPID] = generation
		return nil
	}
	tr.removePIDGenerationOverride = func(hostPID uint32) error {
		delete(maps.generations, hostPID)
		return nil
	}
	return maps
}

func (m *testPIDMaps) retire(hostPID uint32) {
	epoch, present := m.epochs[hostPID]
	if !present {
		return
	}
	epoch++
	if epoch == 0 {
		epoch++
	}
	m.epochs[hostPID] = epoch
	delete(m.generations, hostPID)
}

func (m *testPIDMaps) armed(hostPID uint32) bool {
	epoch, epochPresent := m.epochs[hostPID]
	generation, generationPresent := m.generations[hostPID]
	return epochPresent && epoch != 0 && generationPresent &&
		generation.LifecycleEpoch == epoch
}

func TestLifecycleEpochWrapSkipsZero(t *testing.T) {
	const hostPID = uint32(31)
	maps := &testPIDMaps{
		epochs: map[uint32]uint64{hostPID: ^uint64(0)},
		generations: map[uint32]BpfLogEnricherGenerationT{
			hostPID: {LifecycleEpoch: ^uint64(0)},
		},
	}

	maps.retire(hostPID)

	require.Equal(t, uint64(1), maps.epochs[hostPID])
	require.NotContains(t, maps.generations, hostPID)
	require.False(t, maps.armed(hostPID))
}

func setTestPIDService(tr *Tracer, hostPID uint32, fi *exec.FileInfo) {
	key := tr.pidKey(1, hostPID)
	tr.pidServices[key] = fi
	tr.pidKeysByHostPID[hostPID] = key
}

func TestLogEnricherGenerationABI(t *testing.T) {
	var generation BpfLogEnricherGenerationT
	require.Equal(t, uintptr(40), unsafe.Sizeof(generation))
	require.Equal(t, uintptr(0), unsafe.Offsetof(generation.ProcessInstanceId))
	require.Equal(t, uintptr(8), unsafe.Offsetof(generation.ProcessStartTicks))
	require.Equal(t, uintptr(16), unsafe.Offsetof(generation.ExecutableDevice))
	require.Equal(t, uintptr(24), unsafe.Offsetof(generation.ExecutableInode))
	require.Equal(t, uintptr(32), unsafe.Offsetof(generation.LifecycleEpoch))

	spec, err := LoadBpf()
	require.NoError(t, err)
	mapSpec := spec.Maps[BpfMapLogEnricherGenerations]
	require.NotNil(t, mapSpec)
	require.Equal(t, ebpf.Hash, mapSpec.Type)
	require.Equal(t, uint32(4), mapSpec.KeySize)
	require.Equal(t, uint32(40), mapSpec.ValueSize)
	require.Equal(t, uint32(1<<12), mapSpec.MaxEntries)

	epochMapSpec := spec.Maps[BpfMapLogEnricherLifecycleEpochs]
	require.NotNil(t, epochMapSpec)
	require.Equal(t, ebpf.Hash, epochMapSpec.Type)
	require.Equal(t, uint32(4), epochMapSpec.KeySize)
	require.Equal(t, uint32(8), epochMapSpec.ValueSize)
	require.Equal(t, uint32(1<<12), epochMapSpec.MaxEntries)

	var event BpfLogEventT
	require.Equal(t, uintptr(144), unsafe.Sizeof(event))
	require.Equal(t, uintptr(0), unsafe.Offsetof(event.Tgid))
	require.Equal(t, uintptr(8), unsafe.Offsetof(event.ProcessInstanceId))
	require.Equal(t, uintptr(16), unsafe.Offsetof(event.LifecycleEpoch))
	require.Equal(t, uintptr(24), unsafe.Offsetof(event.TargetDevice))
	require.Equal(t, uintptr(32), unsafe.Offsetof(event.TargetInode))
	require.Equal(t, uintptr(40), unsafe.Offsetof(event.Fd))
	require.Equal(t, uintptr(48), unsafe.Offsetof(event.Ctx))
	require.Equal(t, uintptr(72), unsafe.Offsetof(event.FilePath))
	require.Equal(t, uintptr(136), unsafe.Offsetof(event.Log))
}

func TestProcessLifecycleTracepointsAdvanceEpochBeforeDisarm(t *testing.T) {
	source, err := os.ReadFile("../../../../bpf/logenricher/logenricher.c")
	require.NoError(t, err)
	require.Contains(t, string(source), `SEC("tracepoint/sched/sched_process_exec")`)
	require.Contains(t, string(source), "int obi_log_enricher_process_exec(void *ctx)")
	require.Contains(t, string(source), `SEC("tracepoint/sched/sched_process_exit")`)
	require.Contains(t, string(source), "int obi_log_enricher_process_exit(void *ctx)")
	require.Contains(t, string(source), "BPF_CORE_READ(task, signal, live.counter) != 0")
	require.Contains(t, string(source), "if (*lifecycle_epoch == 0)")

	for _, object := range []struct {
		name string
		data []byte
	}{
		{name: "amd64", data: logEnricherBPFX86Object},
		{name: "arm64", data: logEnricherBPFARM64Object},
	} {
		t.Run(object.name, func(t *testing.T) {
			spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object.data))
			require.NoError(t, err)
			for _, programName := range []string{
				BpfProgObiLogEnricherProcessExec,
				BpfProgObiLogEnricherProcessExit,
			} {
				program := spec.Programs[programName]
				require.NotNil(t, program)
				require.Equal(t, ebpf.TracePoint, program.Type)
				requireLifecycleRetirementOrdering(t, program)
			}
		})
	}
}

func requireLifecycleRetirementOrdering(t *testing.T, program *ebpf.ProgramSpec) {
	t.Helper()
	lifecycleMapIndex := -1
	generationMapIndex := -1
	lookupIndex := -1
	deleteIndex := -1
	atomicIndices := make([]int, 0, 2)
	for index, instruction := range program.Instructions {
		switch instruction.Reference() {
		case BpfMapLogEnricherLifecycleEpochs:
			lifecycleMapIndex = index
		case BpfMapLogEnricherGenerations:
			generationMapIndex = index
		}
		if instruction.IsBuiltinCall() {
			switch instruction.Constant {
			case int64(asm.FnMapLookupElem):
				if lookupIndex == -1 {
					lookupIndex = index
				}
			case int64(asm.FnMapDeleteElem):
				require.Equal(t, -1, deleteIndex, "generation must be deleted at most once")
				deleteIndex = index
			}
		}
		atomicOp := instruction.OpCode.AtomicOp()
		require.NotEqual(t, asm.FetchAdd, atomicOp, "BPF XADD return values are unsupported")
		if atomicOp == asm.AddAtomic {
			require.Equal(t, asm.DWord, instruction.OpCode.Size())
			atomicIndices = append(atomicIndices, index)
		}
	}
	require.NotEqual(t, -1, lifecycleMapIndex)
	require.NotEqual(t, -1, generationMapIndex)
	require.NotEqual(t, -1, lookupIndex)
	require.NotEqual(t, -1, deleteIndex)
	require.NotEmpty(t, atomicIndices)
	require.Less(t, lifecycleMapIndex, lookupIndex)
	for _, atomicIndex := range atomicIndices {
		require.Greater(t, atomicIndex, lookupIndex)
		require.Less(t, atomicIndex, generationMapIndex)
		require.Less(t, atomicIndex, deleteIndex)
	}
	require.Less(t, generationMapIndex, deleteIndex)
}

func TestTracepointsRegistersRequiredProcessLifecycleRetirement(t *testing.T) {
	tr := newTestTracer(t, false)
	execProgram := &ebpf.Program{}
	exitProgram := &ebpf.Program{}
	tr.bpfObjects.ObiLogEnricherProcessExec = execProgram
	tr.bpfObjects.ObiLogEnricherProcessExit = exitProgram

	tracepoints := tr.Tracepoints()
	require.Len(t, tracepoints, 2)
	execDisarm, registered := tracepoints["sched/sched_process_exec"]
	require.True(t, registered)
	require.True(t, execDisarm.Required)
	require.Same(t, execProgram, execDisarm.Start)
	exitDisarm, registered := tracepoints["sched/sched_process_exit"]
	require.True(t, registered)
	require.True(t, exitDisarm.Required)
	require.Same(t, exitProgram, exitDisarm.Start)
}

func TestBPFGenerationMismatchReturnsBeforeUserBufferAccess(t *testing.T) {
	sourceBytes, err := os.ReadFile("../../../../bpf/logenricher/logenricher.c")
	require.NoError(t, err)
	source := string(sourceBytes)

	matcherStart := strings.Index(source, "log_enricher_generation_matches_task(")
	writeStart := strings.Index(source, "__write(struct kiocb")
	writeEnd := strings.Index(source, "SEC(\"kprobe/tty_write\")")
	require.NotEqual(t, -1, matcherStart)
	require.Greater(t, writeStart, matcherStart)
	require.Greater(t, writeEnd, writeStart)

	matcher := source[matcherStart:writeStart]
	lifecycleLookup := strings.Index(matcher, "bpf_map_lookup_elem(&log_enricher_lifecycle_epochs")
	startLookup := strings.Index(matcher, "process_start_ticks(leader")
	require.NotEqual(t, -1, lifecycleLookup)
	require.NotEqual(t, -1, startLookup)
	require.Less(t, lifecycleLookup, startLookup)
	require.Contains(t, matcher, "current_lifecycle_epoch != generation->lifecycle_epoch")
	require.Contains(t, matcher, "current_start_ticks != generation->process_start_ticks")
	require.NotContains(t, matcher, "BPF_CORE_READ(leader, start_time)")
	require.Contains(t, matcher, "log_enricher_encode_stat_device(raw_device)")
	require.Contains(t, matcher, "current_device == generation->executable_device")
	require.Contains(t, matcher, "current_inode == generation->executable_inode")

	writeBody := source[writeStart:writeEnd]
	guard := strings.Index(
		writeBody,
		"if (!log_enricher_generation_matches_task(generation, task))",
	)
	targetIdentity := strings.Index(writeBody, "const u64 target_device")
	iovecRead := strings.Index(writeBody, "get_iovec_ctx(")
	scratchReservation := strings.Index(writeBody, "log_event_mem(")
	userBufferRead := strings.Index(writeBody, "consume_ubuf(")
	userIovecRead := strings.Index(writeBody, "consume_iovec(")
	require.NotEqual(t, -1, guard)
	require.NotEqual(t, -1, targetIdentity)
	require.NotEqual(t, -1, iovecRead)
	require.NotEqual(t, -1, scratchReservation)
	require.NotEqual(t, -1, userBufferRead)
	require.NotEqual(t, -1, userIovecRead)
	require.Contains(t, writeBody[guard:iovecRead], "return 0;")
	require.Less(t, guard, iovecRead)
	require.Less(t, targetIdentity, iovecRead)
	require.Less(t, iovecRead, scratchReservation)
	require.Less(t, scratchReservation, userBufferRead)
	require.Less(t, scratchReservation, userIovecRead)
}

func TestBPFDeviceEncodingMatchesStatForWideMinor(t *testing.T) {
	const (
		major = uint32(0xabc)
		minor = uint32(0x54321) // Exercise bits above the legacy 8-bit minor.
	)
	kernelDevice := (major << 20) | minor
	encodedDevice := uint64(
		(minor & 0xff) | (major << 8) | ((minor &^ 0xff) << 12),
	)
	require.NotEqual(t, uint64(kernelDevice), encodedDevice)
	require.Equal(t, unix.Mkdev(major, minor), encodedDevice)

	source, err := os.ReadFile("../../../../bpf/logenricher/logenricher.c")
	require.NoError(t, err)
	require.Contains(t, string(source), "const u32 major = dev >> 20;")
	require.Contains(t, string(source), "const u32 minor = dev & ((1U << 20) - 1);")
	require.Contains(t, string(source), "log_enricher_encode_stat_device(raw_device)")
}

func TestAllowPIDPublishesExactProcessLifetime(t *testing.T) {
	const (
		pid      = app.PID(700014)
		ns       = uint32(43)
		start    = uint64(50505)
		instance = uint64(905)
		targetFD = uint32(16)
	)
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	owner := newFakeLogOwner(
		t, pid, start, instance, targetFD,
		newEmptyLogTarget(t, "published-lifetime.log"),
	)

	tr.AllowPID(pid, ns, exec.New(exec.Init{Pid: pid}), owner)

	generation, present := bpfMaps.generations[uint32(pid)]
	require.True(t, present)
	require.Equal(t, owner.ProcessInstanceID(), generation.ProcessInstanceId)
	require.Equal(t, owner.ProcessStartTime(), generation.ProcessStartTicks)
	require.Equal(t, owner.Dev(), generation.ExecutableDevice)
	require.Equal(t, owner.Ino(), generation.ExecutableInode)
	require.NotZero(t, generation.LifecycleEpoch)
	require.Equal(t, bpfMaps.epochs[uint32(pid)], generation.LifecycleEpoch)
}

func TestAllowPIDExecBeforeLateGenerationPutFailsOpen(t *testing.T) {
	const (
		pid      = app.PID(700020)
		ns       = uint32(44)
		start    = uint64(60606)
		targetFD = uint32(18)
	)
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	owner := newFakeLogOwner(
		t, pid, start, 920, targetFD,
		newEmptyLogTarget(t, "same-image-exec-before-put.log"),
	)
	originalPut := tr.putPIDGenerationOverride
	var published BpfLogEnricherGenerationT
	tr.putPIDGenerationOverride = func(
		hostPID uint32,
		generation BpfLogEnricherGenerationT,
	) error {
		published = generation
		bpfMaps.retire(hostPID)
		return originalPut(hostPID, generation)
	}

	tr.AllowPID(pid, ns, exec.New(exec.Init{Pid: pid}), owner)

	require.NotZero(t, published.LifecycleEpoch)
	require.False(t, bpfMaps.armed(uint32(pid)))
	require.NotContains(t, tr.pidKeysByHostPID, uint32(pid))
	require.NotContains(t, tr.pidGenerations, uint32(pid))
	require.Empty(t, bpfMaps.pids)
}

func TestAllowPIDLastExitAfterGenerationPutFailsOpenForSameTickSameFileReuse(t *testing.T) {
	const (
		pid      = app.PID(700021)
		ns       = uint32(45)
		start    = uint64(70707)
		targetFD = uint32(19)
	)
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	target := newEmptyLogTarget(t, "same-tick-same-file-reuse.log")
	oldOwner := newFakeLogOwner(t, pid, start, 921, targetFD, target)
	originalPut := tr.putPIDGenerationOverride
	var retiredEpoch uint64
	retireAfterPut := true
	tr.putPIDGenerationOverride = func(
		hostPID uint32,
		generation BpfLogEnricherGenerationT,
	) error {
		if err := originalPut(hostPID, generation); err != nil {
			return err
		}
		if retireAfterPut {
			retiredEpoch = generation.LifecycleEpoch
			bpfMaps.retire(hostPID)
		}
		return nil
	}

	tr.AllowPID(pid, ns, exec.New(exec.Init{Pid: pid}), oldOwner)

	require.NotZero(t, retiredEpoch)
	require.False(t, bpfMaps.armed(uint32(pid)))
	require.NotContains(t, tr.pidKeysByHostPID, uint32(pid))

	retireAfterPut = false
	reusedOwner := newFakeLogOwner(t, pid, start, 922, targetFD, target)
	tr.AllowPID(pid, ns, exec.New(exec.Init{Pid: pid}), reusedOwner)

	generation := bpfMaps.generations[uint32(pid)]
	require.True(t, bpfMaps.armed(uint32(pid)))
	require.Equal(t, reusedOwner.ProcessInstanceID(), generation.ProcessInstanceId)
	require.Equal(t, oldOwner.ProcessStartTime(), generation.ProcessStartTicks)
	require.Equal(t, oldOwner.Dev(), generation.ExecutableDevice)
	require.Equal(t, oldOwner.Ino(), generation.ExecutableInode)
	require.NotEqual(t, retiredEpoch, generation.LifecycleEpoch)
}

func TestPIDLifetimeReplacementResetsAliasesAndRejectsStaleBlock(t *testing.T) {
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	pid := app.PID(os.Getpid())
	const (
		ns       = uint32(17)
		targetFD = uint32(1)
	)
	service := exec.New(exec.Init{Pid: pid})
	predecessor := newFakeLogOwner(
		t, pid, 101, 11, targetFD, newEmptyLogTarget(t, "predecessor.log"),
	)
	replacement := newFakeLogOwner(
		t, pid, 102, 12, targetFD, newEmptyLogTarget(t, "replacement.log"),
	)
	pk := tr.pidKey(ns, uint32(pid))
	const staleAlias = uint64(0xfeedbeef)

	tr.AllowPID(pid, ns, service, predecessor)
	tr.pids[pk] = append(tr.pids[pk], staleAlias)
	require.NoError(t, tr.addPIDOwner(staleAlias, predecessor))
	require.Contains(t, bpfMaps.pids, staleAlias)

	tr.AllowPID(pid, ns, service, replacement)
	require.Same(t, service, tr.pidServices[pk])
	require.Same(t, replacement, tr.pidOwners[pk])
	require.NotContains(t, tr.pids[pk], staleAlias)
	require.NotContains(t, tr.pidKeyOwners, staleAlias)
	require.NotContains(t, bpfMaps.pids, staleAlias)

	tr.BlockPID(pid, ns, service, predecessor)
	require.Same(t, service, tr.pidServices[pk])
	require.Same(t, replacement, tr.pidOwners[pk])
	require.Contains(t, bpfMaps.pids, pk)
	require.Equal(t, replacement.ProcessInstanceID(), bpfMaps.generations[uint32(pid)].ProcessInstanceId)

	tr.BlockPID(pid, ns, service, replacement)
	require.NotContains(t, tr.pidOwners, pk)
	require.NotContains(t, tr.pidKeysByHostPID, uint32(pid))
	require.NotContains(t, tr.pidGenerations, uint32(pid))
	require.NotContains(t, bpfMaps.pids, pk)
	require.NotContains(t, bpfMaps.generations, uint32(pid))
	require.NotContains(t, bpfMaps.epochs, uint32(pid))
}

func TestAllowPIDPutFailureDoesNotPublishOwnership(t *testing.T) {
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	const (
		pid      = app.PID(700005)
		aliasPID = app.PID(7005)
		ns       = uint32(17)
		start    = uint64(51515)
		targetFD = uint32(5)
	)
	wantErr := errors.New("injected BPF put failure")
	bpfPIDs := make(map[uint64]uint8)
	putCalls := 0
	tr.addPIDOverride = func(key uint64) error {
		putCalls++
		if putCalls == 2 {
			return wantErr
		}
		bpfPIDs[key] = 1
		return nil
	}
	tr.removePIDOverride = func(key uint64) error {
		delete(bpfPIDs, key)
		return nil
	}
	service := exec.New(exec.Init{Pid: pid})
	target := newEmptyLogTarget(t, "failed-admission.log")
	owner := newFakeLogOwner(t, pid, start, 601, targetFD, target, aliasPID)
	pk := tr.pidKey(ns, uint32(pid))
	aliasKey := tr.pidKey(ns, uint32(aliasPID))

	tr.AllowPID(pid, ns, service, owner)

	require.Equal(t, 2, putCalls)
	require.Empty(t, bpfPIDs)
	require.NotContains(t, tr.pidServices, pk)
	require.NotContains(t, tr.pidOwners, pk)
	require.NotContains(t, tr.pids, pk)
	require.NotContains(t, tr.pidKeyOwners, pk)
	require.NotContains(t, tr.pidKeyOwners, aliasKey)
	require.NotContains(t, tr.pidKeysByHostPID, uint32(pid))
	require.NotContains(t, tr.pidGenerations, uint32(pid))
	require.NotContains(t, bpfMaps.epochs, uint32(pid))
	require.False(t, bpfMaps.armed(uint32(pid)))
}

func TestAllowPIDRejectsZeroProcessGeneration(t *testing.T) {
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	pid := app.PID(os.Getpid())
	const (
		ns       = uint32(17)
		targetFD = uint32(1)
	)
	service := exec.New(exec.Init{Pid: pid})
	owner := newFakeLogOwner(
		t, pid, 101, 0, targetFD, newEmptyLogTarget(t, "zero-generation.log"),
	)
	pk := tr.pidKey(ns, uint32(pid))

	tr.AllowPID(pid, ns, service, owner)

	require.Empty(t, bpfMaps.pids)
	require.Empty(t, bpfMaps.generations)
	require.NotContains(t, tr.pidServices, pk)
	require.NotContains(t, tr.pidOwners, pk)
	require.NotContains(t, tr.pidKeysByHostPID, uint32(pid))
	require.NotContains(t, tr.pidGenerations, uint32(pid))
	require.NotContains(t, bpfMaps.epochs, uint32(pid))
	require.False(t, bpfMaps.armed(uint32(pid)))
}

func TestFailedNewAdmissionPreservesPreexistingLifecycleEpoch(t *testing.T) {
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	pid := app.PID(os.Getpid())
	const (
		ns               = uint32(48)
		targetFD         = uint32(21)
		preexistingEpoch = uint64(0xabc123)
	)
	bpfMaps.epochs[uint32(pid)] = preexistingEpoch
	bpfMaps.generations[uint32(pid)] = BpfLogEnricherGenerationT{
		ProcessInstanceId: 1,
		ProcessStartTicks: 1,
		ExecutableDevice:  1,
		ExecutableInode:   1,
		LifecycleEpoch:    preexistingEpoch,
	}
	mismatchedOwner := newFakeLogOwner(
		t, pid+1, 1, 925, targetFD,
		newEmptyLogTarget(t, "preexisting-epoch-validation-failure.log"),
	)

	tr.AllowPID(pid, ns, exec.New(exec.Init{Pid: pid}), mismatchedOwner)

	require.Equal(t, preexistingEpoch, bpfMaps.epochs[uint32(pid)])
	require.NotContains(t, bpfMaps.generations, uint32(pid))
	require.False(t, bpfMaps.armed(uint32(pid)))
	require.Empty(t, bpfMaps.pids)
}

func TestAllowPIDEpochSeedErrorsFailBeforeAdmissionMutation(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*Tracer)
	}{
		{
			name: "random source error",
			configure: func(tr *Tracer) {
				tr.newPIDLifecycleEpochOverride = func() (uint64, error) {
					return 0, errors.New("injected random source failure")
				}
			},
		},
		{
			name: "zero random epoch",
			configure: func(tr *Tracer) {
				tr.newPIDLifecycleEpochOverride = func() (uint64, error) { return 0, nil }
			},
		},
		{
			name: "epoch map full",
			configure: func(tr *Tracer) {
				tr.putPIDLifecycleEpochOverride = func(
					uint32,
					uint64,
					ebpf.MapUpdateFlags,
				) error {
					return unix.ENOSPC
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const (
				pid      = app.PID(700023)
				ns       = uint32(49)
				targetFD = uint32(22)
			)
			tr := newTestTracer(t, false)
			bpfMaps := installTestPIDMap(tr)
			tc.configure(tr)
			owner := newFakeLogOwner(
				t, pid, 100001, 926, targetFD,
				newEmptyLogTarget(t, "epoch-seed-error.log"),
			)

			tr.AllowPID(pid, ns, exec.New(exec.Init{Pid: pid}), owner)

			require.Empty(t, bpfMaps.pids)
			require.Empty(t, bpfMaps.epochs)
			require.Empty(t, bpfMaps.generations)
			require.NotContains(t, tr.pidKeysByHostPID, uint32(pid))
		})
	}
}

func TestOrphanGenerationDeleteErrorPreventsEpochSeeding(t *testing.T) {
	const (
		pid      = app.PID(700030)
		ns       = uint32(54)
		targetFD = uint32(29)
	)
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	bpfMaps.generations[uint32(pid)] = BpfLogEnricherGenerationT{
		ProcessInstanceId: 1,
		ProcessStartTicks: 1,
		ExecutableDevice:  1,
		ExecutableInode:   1,
		LifecycleEpoch:    1,
	}
	tr.removePIDGenerationOverride = func(uint32) error {
		return errors.New("injected orphan generation delete failure")
	}
	owner := newFakeLogOwner(
		t, pid, 100008, 932, targetFD,
		newEmptyLogTarget(t, "orphan-generation-delete-error.log"),
	)

	tr.AllowPID(pid, ns, exec.New(exec.Init{Pid: pid}), owner)

	require.NotContains(t, bpfMaps.epochs, uint32(pid))
	require.False(t, bpfMaps.armed(uint32(pid)))
	require.Empty(t, bpfMaps.pids)
	require.NotContains(t, tr.pidKeysByHostPID, uint32(pid))
}

func TestAllowPIDEpochSeedCollisionReadsExistingFence(t *testing.T) {
	const (
		pid            = app.PID(700028)
		ns             = uint32(52)
		targetFD       = uint32(27)
		collidingEpoch = uint64(0xfeed1234)
	)
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	owner := newFakeLogOwner(
		t, pid, 100006, 931, targetFD,
		newEmptyLogTarget(t, "epoch-seed-collision.log"),
	)
	originalLookup := tr.lookupPIDLifecycleEpochOverride
	originalPut := tr.putPIDLifecycleEpochOverride
	firstLookup := true
	tr.lookupPIDLifecycleEpochOverride = func(hostPID uint32) (uint64, error) {
		if firstLookup {
			firstLookup = false
			return 0, ebpf.ErrKeyNotExist
		}
		return originalLookup(hostPID)
	}
	tr.putPIDLifecycleEpochOverride = func(
		hostPID uint32,
		epoch uint64,
		flags ebpf.MapUpdateFlags,
	) error {
		if flags == ebpf.UpdateNoExist {
			bpfMaps.epochs[hostPID] = collidingEpoch
			return ebpf.ErrKeyExist
		}
		return originalPut(hostPID, epoch, flags)
	}

	tr.AllowPID(pid, ns, exec.New(exec.Init{Pid: pid}), owner)

	require.True(t, bpfMaps.armed(uint32(pid)))
	require.Equal(t, collidingEpoch, bpfMaps.epochs[uint32(pid)])
	require.Equal(t, collidingEpoch, bpfMaps.generations[uint32(pid)].LifecycleEpoch)
}

func TestPostPublicationEpochReadErrorFailsOpen(t *testing.T) {
	const (
		pid      = app.PID(700024)
		ns       = uint32(50)
		targetFD = uint32(23)
	)
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	owner := newFakeLogOwner(
		t, pid, 100002, 927, targetFD,
		newEmptyLogTarget(t, "post-publication-epoch-read-error.log"),
	)
	originalLookup := tr.lookupPIDLifecycleEpochOverride
	lookupCalls := 0
	tr.lookupPIDLifecycleEpochOverride = func(hostPID uint32) (uint64, error) {
		lookupCalls++
		if lookupCalls == 2 {
			return 0, unix.EIO
		}
		return originalLookup(hostPID)
	}

	tr.AllowPID(pid, ns, exec.New(exec.Init{Pid: pid}), owner)

	require.GreaterOrEqual(t, lookupCalls, 2)
	require.False(t, bpfMaps.armed(uint32(pid)))
	require.Empty(t, bpfMaps.pids)
	require.NotContains(t, tr.pidKeysByHostPID, uint32(pid))
}

func TestFailedNewAdmissionEpochCleanupErrorLeavesNoArmedGeneration(t *testing.T) {
	const (
		pid      = app.PID(700029)
		ns       = uint32(53)
		targetFD = uint32(28)
	)
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	owner := newFakeLogOwner(
		t, pid, 100007, 0, targetFD,
		newEmptyLogTarget(t, "epoch-cleanup-error.log"),
	)
	tr.removePIDLifecycleEpochOverride = func(uint32) error {
		return errors.New("injected lifecycle epoch cleanup error")
	}

	tr.AllowPID(pid, ns, exec.New(exec.Init{Pid: pid}), owner)

	require.Contains(t, bpfMaps.epochs, uint32(pid))
	require.NotContains(t, bpfMaps.generations, uint32(pid))
	require.False(t, bpfMaps.armed(uint32(pid)))
	require.Empty(t, bpfMaps.pids)
	require.NotContains(t, tr.pidKeysByHostPID, uint32(pid))
}

func TestAllowPIDRejectsMismatchedStableOwner(t *testing.T) {
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	pid := app.PID(os.Getpid())
	const (
		ns       = uint32(17)
		targetFD = uint32(1)
	)
	service := exec.New(exec.Init{Pid: pid})
	mismatchedOwner := newFakeLogOwner(
		t, pid+1, 1, 13, targetFD, newEmptyLogTarget(t, "mismatched-owner.log"),
	)
	pk := tr.pidKey(ns, uint32(pid))

	tr.AllowPID(pid, ns, service, mismatchedOwner)

	require.NotContains(t, tr.pidServices, pk)
	require.NotContains(t, tr.pidOwners, pk)
	require.NotContains(t, tr.pids, pk)
	require.NotContains(t, tr.pidKeyOwners, pk)
	require.NotContains(t, tr.pidKeysByHostPID, uint32(pid))
	require.NotContains(t, bpfMaps.epochs, uint32(pid))
	require.False(t, bpfMaps.armed(uint32(pid)))
}

func TestPIDReuseAcrossNamespacesRetiresPredecessorWithoutBlock(t *testing.T) {
	tr := newTestTracer(t, true)
	bpfMaps := installTestPIDMap(tr)
	const (
		pid           = app.PID(700000)
		firstNS       = uint32(17)
		replacementNS = uint32(29)
		firstAliasPID = app.PID(7001)
		newAliasPID   = app.PID(7002)
		start         = uint64(91919)
		targetFD      = uint32(7)
	)
	firstKey := tr.pidKey(firstNS, uint32(pid))
	replacementKey := tr.pidKey(replacementNS, uint32(pid))
	firstAlias := tr.pidKey(firstNS, uint32(firstAliasPID))
	replacementAlias := tr.pidKey(replacementNS, uint32(newAliasPID))

	firstTarget := newEmptyLogTarget(t, "first.log")
	replacementTarget := newEmptyLogTarget(t, "replacement.log")
	firstService := exec.New(exec.Init{Pid: pid})
	firstService.EnsureExportsOTelTraces()
	replacementService := exec.New(exec.Init{Pid: pid})
	firstOwner := newFakeLogOwner(
		t, pid, start, 501, targetFD, firstTarget, firstAliasPID,
	)
	replacementOwner := newFakeLogOwner(
		t, pid, start, 502, targetFD, replacementTarget, newAliasPID,
	)

	tr.AllowPID(pid, firstNS, firstService, firstOwner)
	require.Same(t, firstOwner, tr.pidOwners[firstKey])
	require.Contains(t, tr.pidKeyOwners[firstKey], firstOwner)
	require.Contains(t, tr.pidKeyOwners[firstAlias], firstOwner)
	require.Contains(t, bpfMaps.pids, firstKey)
	require.Contains(t, bpfMaps.pids, firstAlias)
	require.Equal(t, firstOwner.ProcessInstanceID(), bpfMaps.generations[uint32(pid)].ProcessInstanceId)

	tr.AllowPID(pid, replacementNS, replacementService, replacementOwner)

	require.NotContains(t, tr.pidServices, firstKey)
	require.NotContains(t, tr.pidOwners, firstKey)
	require.NotContains(t, tr.pids, firstKey)
	require.NotContains(t, tr.pidKeyOwners, firstKey)
	require.NotContains(t, tr.pidKeyOwners, firstAlias)
	require.NotContains(t, bpfMaps.pids, firstKey)
	require.NotContains(t, bpfMaps.pids, firstAlias)
	require.Same(t, replacementService, tr.pidServices[replacementKey])
	require.Same(t, replacementOwner, tr.pidOwners[replacementKey])
	require.Contains(t, tr.pids[replacementKey], replacementAlias)
	require.Contains(t, tr.pidKeyOwners[replacementKey], replacementOwner)
	require.Contains(t, tr.pidKeyOwners[replacementAlias], replacementOwner)
	require.Contains(t, bpfMaps.pids, replacementKey)
	require.Contains(t, bpfMaps.pids, replacementAlias)
	require.Equal(t, replacementOwner.ProcessInstanceID(), bpfMaps.generations[uint32(pid)].ProcessInstanceId)
	require.Equal(t, replacementOwner.ProcessInstanceID(), tr.pidGenerations[uint32(pid)].ProcessInstanceId)
	require.Equal(t, replacementKey, tr.pidKeysByHostPID[uint32(pid)])
	require.False(t, tr.shouldOmitSpanID(uint32(pid)),
		"host PID lookup must use the replacement namespace's service")
	replacementEpoch := bpfMaps.epochs[uint32(pid)]

	// A predecessor delete arriving after replacement must be a no-op.
	tr.BlockPID(pid, firstNS, firstService, firstOwner)

	require.Same(t, replacementService, tr.pidServices[replacementKey])
	require.Same(t, replacementOwner, tr.pidOwners[replacementKey])
	require.Contains(t, tr.pids[replacementKey], replacementAlias)
	require.Contains(t, tr.pidKeyOwners[replacementKey], replacementOwner)
	require.Contains(t, tr.pidKeyOwners[replacementAlias], replacementOwner)
	require.Contains(t, bpfMaps.pids, replacementKey)
	require.Contains(t, bpfMaps.pids, replacementAlias)
	require.Equal(t, replacementOwner.ProcessInstanceID(), bpfMaps.generations[uint32(pid)].ProcessInstanceId)
	require.Equal(t, replacementOwner.ProcessInstanceID(), tr.pidGenerations[uint32(pid)].ProcessInstanceId)
	require.Equal(t, replacementKey, tr.pidKeysByHostPID[uint32(pid)])
	require.Equal(t, replacementEpoch, bpfMaps.epochs[uint32(pid)])

	replacementService.EnsureExportsOTelTraces()
	require.True(t, tr.shouldOmitSpanID(uint32(pid)),
		"stale namespace deletion must preserve replacement service lookup")
}

func TestCrossNamespaceReplacementDeleteFailurePreservesPredecessor(t *testing.T) {
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	const (
		pid         = app.PID(700006)
		oldAliasPID = app.PID(7006)
		newAliasPID = app.PID(7007)
		oldNS       = uint32(31)
		newNS       = uint32(32)
		start       = uint64(61616)
		targetFD    = uint32(6)
	)
	oldKey := tr.pidKey(oldNS, uint32(pid))
	oldAlias := tr.pidKey(oldNS, uint32(oldAliasPID))
	newKey := tr.pidKey(newNS, uint32(pid))
	newAlias := tr.pidKey(newNS, uint32(newAliasPID))
	oldService := exec.New(exec.Init{Pid: pid})
	newService := exec.New(exec.Init{Pid: pid})
	oldOwner := newFakeLogOwner(
		t, pid, start, 701, targetFD,
		newEmptyLogTarget(t, "old-delete-failure.log"), oldAliasPID,
	)
	newOwner := newFakeLogOwner(
		t, pid, start, 702, targetFD,
		newEmptyLogTarget(t, "new-delete-failure.log"), newAliasPID,
	)

	tr.AllowPID(pid, oldNS, oldService, oldOwner)
	require.Contains(t, bpfMaps.pids, oldKey)
	require.Contains(t, bpfMaps.pids, oldAlias)
	deleteErr := errors.New("injected BPF delete failure")
	tr.removePIDOverride = func(key uint64) error {
		if key == oldKey {
			return deleteErr
		}
		delete(bpfMaps.pids, key)
		return nil
	}

	tr.AllowPID(pid, newNS, newService, newOwner)

	require.Same(t, oldOwner, tr.pidOwners[oldKey])
	require.Same(t, oldService, tr.pidServices[oldKey])
	require.Contains(t, tr.pids[oldKey], oldAlias)
	require.Contains(t, tr.pidKeyOwners[oldKey], oldOwner)
	require.Contains(t, tr.pidKeyOwners[oldAlias], oldOwner)
	require.Contains(t, bpfMaps.pids, oldKey)
	require.Contains(t, bpfMaps.pids, oldAlias)
	require.NotContains(t, tr.pidOwners, newKey)
	require.NotContains(t, tr.pidKeyOwners, newKey)
	require.NotContains(t, tr.pidKeyOwners, newAlias)
	require.NotContains(t, bpfMaps.pids, newKey)
	require.NotContains(t, bpfMaps.pids, newAlias)
	require.Equal(t, oldKey, tr.pidKeysByHostPID[uint32(pid)])
	require.Equal(t, oldOwner.ProcessInstanceID(), bpfMaps.generations[uint32(pid)].ProcessInstanceId)
	require.Equal(t, oldOwner.ProcessInstanceID(), tr.pidGenerations[uint32(pid)].ProcessInstanceId)
}

func TestReplacementGenerationPutFailureRollsBackPIDAdmission(t *testing.T) {
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	const (
		pid         = app.PID(700007)
		oldAliasPID = app.PID(7008)
		newAliasPID = app.PID(7009)
		oldNS       = uint32(33)
		newNS       = uint32(34)
		targetFD    = uint32(8)
	)
	oldKey := tr.pidKey(oldNS, uint32(pid))
	oldAlias := tr.pidKey(oldNS, uint32(oldAliasPID))
	newKey := tr.pidKey(newNS, uint32(pid))
	newAlias := tr.pidKey(newNS, uint32(newAliasPID))
	oldService := exec.New(exec.Init{Pid: pid})
	newService := exec.New(exec.Init{Pid: pid})
	oldOwner := newFakeLogOwner(
		t, pid, 71717, 801, targetFD,
		newEmptyLogTarget(t, "old-generation-failure.log"), oldAliasPID,
	)
	newOwner := newFakeLogOwner(
		t, pid, 81818, 802, targetFD,
		newEmptyLogTarget(t, "new-generation-failure.log"), newAliasPID,
	)

	tr.AllowPID(pid, oldNS, oldService, oldOwner)
	require.Equal(t, oldOwner.ProcessInstanceID(), bpfMaps.generations[uint32(pid)].ProcessInstanceId)
	wantErr := errors.New("injected BPF generation put failure")
	tr.putPIDGenerationOverride = func(
		hostPID uint32,
		generation BpfLogEnricherGenerationT,
	) error {
		if generation.ProcessInstanceId == newOwner.ProcessInstanceID() {
			return wantErr
		}
		bpfMaps.generations[hostPID] = generation
		return nil
	}

	tr.AllowPID(pid, newNS, newService, newOwner)

	require.Same(t, oldOwner, tr.pidOwners[oldKey])
	require.Same(t, oldService, tr.pidServices[oldKey])
	require.Contains(t, tr.pids[oldKey], oldAlias)
	require.Contains(t, tr.pidKeyOwners[oldKey], oldOwner)
	require.Contains(t, tr.pidKeyOwners[oldAlias], oldOwner)
	require.Contains(t, bpfMaps.pids, oldKey)
	require.Contains(t, bpfMaps.pids, oldAlias)
	require.NotContains(t, tr.pidOwners, newKey)
	require.NotContains(t, tr.pidKeyOwners, newKey)
	require.NotContains(t, tr.pidKeyOwners, newAlias)
	require.NotContains(t, bpfMaps.pids, newKey)
	require.NotContains(t, bpfMaps.pids, newAlias)
	require.Equal(t, oldKey, tr.pidKeysByHostPID[uint32(pid)])
	require.Equal(t, oldOwner.ProcessInstanceID(), bpfMaps.generations[uint32(pid)].ProcessInstanceId)
	require.Equal(t, oldOwner.ProcessInstanceID(), tr.pidGenerations[uint32(pid)].ProcessInstanceId)
	require.True(t, bpfMaps.armed(uint32(pid)))
}

func TestReplacementRollbackNeverRestoresRetiredPredecessor(t *testing.T) {
	const (
		pid      = app.PID(700022)
		oldNS    = uint32(46)
		newNS    = uint32(47)
		targetFD = uint32(20)
	)
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	oldOwner := newFakeLogOwner(
		t, pid, 80808, 923, targetFD,
		newEmptyLogTarget(t, "retired-rollback-old.log"),
	)
	newOwner := newFakeLogOwner(
		t, pid, 90909, 924, targetFD,
		newEmptyLogTarget(t, "retired-rollback-new.log"),
	)
	oldKey := tr.pidKey(oldNS, uint32(pid))
	newKey := tr.pidKey(newNS, uint32(pid))
	tr.AllowPID(pid, oldNS, exec.New(exec.Init{Pid: pid}), oldOwner)
	require.True(t, bpfMaps.armed(uint32(pid)))

	originalPut := tr.putPIDGenerationOverride
	wantErr := errors.New("injected generation publication failure after retirement")
	failedOnce := false
	tr.putPIDGenerationOverride = func(
		hostPID uint32,
		generation BpfLogEnricherGenerationT,
	) error {
		if generation.ProcessInstanceId == newOwner.ProcessInstanceID() && !failedOnce {
			failedOnce = true
			bpfMaps.retire(hostPID)
			return wantErr
		}
		return originalPut(hostPID, generation)
	}

	tr.AllowPID(pid, newNS, exec.New(exec.Init{Pid: pid}), newOwner)

	require.True(t, failedOnce)
	require.False(t, bpfMaps.armed(uint32(pid)))
	require.NotContains(t, bpfMaps.generations, uint32(pid))
	require.Same(t, oldOwner, tr.pidOwners[oldKey])
	require.NotContains(t, tr.pidOwners, newKey)

	tr.AllowPID(pid, newNS, exec.New(exec.Init{Pid: pid}), newOwner)

	require.True(t, bpfMaps.armed(uint32(pid)))
	require.Same(t, newOwner, tr.pidOwners[newKey])
	require.NotContains(t, tr.pidOwners, oldKey)
	require.Equal(
		t,
		bpfMaps.epochs[uint32(pid)],
		bpfMaps.generations[uint32(pid)].LifecycleEpoch,
	)
}

func TestReplacementRollbackNeverRestoresEpochRetiredDuringGenerationDelete(t *testing.T) {
	const (
		pid      = app.PID(700031)
		oldNS    = uint32(55)
		newNS    = uint32(56)
		targetFD = uint32(30)
	)
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	oldOwner := newFakeLogOwner(
		t, pid, 100009, 933, targetFD,
		newEmptyLogTarget(t, "retire-during-delete-old.log"),
	)
	newOwner := newFakeLogOwner(
		t, pid, 100010, 934, targetFD,
		newEmptyLogTarget(t, "retire-during-delete-new.log"),
	)
	oldKey := tr.pidKey(oldNS, uint32(pid))
	newKey := tr.pidKey(newNS, uint32(pid))
	tr.AllowPID(pid, oldNS, exec.New(exec.Init{Pid: pid}), oldOwner)
	oldEpoch := bpfMaps.epochs[uint32(pid)]
	require.True(t, bpfMaps.armed(uint32(pid)))

	originalRemoveGeneration := tr.removePIDGenerationOverride
	retiredDuringDelete := false
	tr.removePIDGenerationOverride = func(hostPID uint32) error {
		if !retiredDuringDelete {
			retiredDuringDelete = true
			// The hook advances the epoch and deletes the generation after the
			// userspace equality lookup but before its delete completes.
			bpfMaps.retire(hostPID)
			return nil
		}
		return originalRemoveGeneration(hostPID)
	}
	tr.addPIDOverride = func(key uint64) error {
		if key == newKey {
			return errors.New("injected admission failure after lifecycle retirement")
		}
		bpfMaps.pids[key] = 1
		return nil
	}

	tr.AllowPID(pid, newNS, exec.New(exec.Init{Pid: pid}), newOwner)

	require.True(t, retiredDuringDelete)
	require.NotEqual(t, oldEpoch, bpfMaps.epochs[uint32(pid)])
	require.NotContains(t, bpfMaps.generations, uint32(pid))
	require.False(t, bpfMaps.armed(uint32(pid)))
	require.Same(t, oldOwner, tr.pidOwners[oldKey])
	require.NotContains(t, tr.pidOwners, newKey)
	require.Equal(t, oldOwner.ProcessInstanceID(), tr.pidGenerations[uint32(pid)].ProcessInstanceId)
}

func TestReplacementDisarmsGenerationBeforePublishingPIDAdmission(t *testing.T) {
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	const (
		pid      = app.PID(700012)
		oldNS    = uint32(36)
		newNS    = uint32(37)
		targetFD = uint32(12)
	)
	oldOwner := newFakeLogOwner(
		t, pid, 10101, 901, targetFD,
		newEmptyLogTarget(t, "old-disarm.log"), app.PID(7012),
	)
	newOwner := newFakeLogOwner(
		t, pid, 20202, 902, targetFD,
		newEmptyLogTarget(t, "new-disarm.log"), app.PID(7013),
	)
	oldKey := tr.pidKey(oldNS, uint32(pid))
	newKey := tr.pidKey(newNS, uint32(pid))
	tr.AllowPID(pid, oldNS, exec.New(exec.Init{Pid: pid}), oldOwner)
	require.Equal(t, oldOwner.ProcessInstanceID(), bpfMaps.generations[uint32(pid)].ProcessInstanceId)

	originalRemove := tr.removePIDOverride
	reachedMutation := make(chan struct{})
	releaseMutation := make(chan struct{})
	tr.removePIDOverride = func(key uint64) error {
		if key == oldKey {
			close(reachedMutation)
			<-releaseMutation
		}
		return originalRemove(key)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		tr.AllowPID(pid, newNS, exec.New(exec.Init{Pid: pid}), newOwner)
	}()

	<-reachedMutation
	_, generationPresent := bpfMaps.generations[uint32(pid)]
	require.False(t, generationPresent,
		"replacement writes must remain untouched while PID admission changes")
	require.Contains(t, bpfMaps.pids, newKey,
		"test must observe the former post-admission/pre-generation window")
	close(releaseMutation)
	<-done

	require.Equal(t, newOwner.ProcessInstanceID(), bpfMaps.generations[uint32(pid)].ProcessInstanceId)
	require.Same(t, newOwner, tr.pidOwners[newKey])
}

func TestReplacementRollbackFailureLeavesGenerationDisarmed(t *testing.T) {
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	const (
		pid      = app.PID(700013)
		oldNS    = uint32(38)
		newNS    = uint32(39)
		targetFD = uint32(14)
	)
	oldAliasPID := app.PID(7014)
	newAliasPID := app.PID(7015)
	oldOwner := newFakeLogOwner(
		t, pid, 30303, 903, targetFD,
		newEmptyLogTarget(t, "old-rollback-fence.log"), oldAliasPID,
	)
	newOwner := newFakeLogOwner(
		t, pid, 40404, 904, targetFD,
		newEmptyLogTarget(t, "new-rollback-fence.log"), newAliasPID,
	)
	oldKey := tr.pidKey(oldNS, uint32(pid))
	oldAlias := tr.pidKey(oldNS, uint32(oldAliasPID))
	newKey := tr.pidKey(newNS, uint32(pid))
	newAlias := tr.pidKey(newNS, uint32(newAliasPID))
	oldService := exec.New(exec.Init{Pid: pid})
	tr.AllowPID(pid, oldNS, oldService, oldOwner)

	forwardErr := errors.New("injected predecessor removal failure")
	rollbackErr := errors.New("injected replacement rollback failure")
	tr.removePIDOverride = func(key uint64) error {
		switch key {
		case oldKey, oldAlias:
			return forwardErr
		case newKey, newAlias:
			return rollbackErr
		default:
			delete(bpfMaps.pids, key)
			return nil
		}
	}

	tr.AllowPID(pid, newNS, exec.New(exec.Init{Pid: pid}), newOwner)

	_, generationPresent := bpfMaps.generations[uint32(pid)]
	require.False(t, generationPresent,
		"an incomplete admission rollback must not re-arm a generation")
	require.Same(t, oldOwner, tr.pidOwners[oldKey])
	require.Same(t, oldService, tr.pidServices[oldKey])
	require.Equal(t, oldOwner.ProcessInstanceID(), tr.pidGenerations[uint32(pid)].ProcessInstanceId,
		"userspace ownership remains uncommitted even though BPF is safely disarmed")
}

func TestBlockGenerationDeleteFailureRollsBackPIDAdmission(t *testing.T) {
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	const (
		pid      = app.PID(700011)
		aliasPID = app.PID(7011)
		ns       = uint32(35)
		targetFD = uint32(10)
	)
	pk := tr.pidKey(ns, uint32(pid))
	aliasKey := tr.pidKey(ns, uint32(aliasPID))
	service := exec.New(exec.Init{Pid: pid})
	owner := newFakeLogOwner(
		t, pid, 91919, 811, targetFD,
		newEmptyLogTarget(t, "block-generation-failure.log"), aliasPID,
	)

	tr.AllowPID(pid, ns, service, owner)
	require.Contains(t, bpfMaps.pids, pk)
	require.Contains(t, bpfMaps.pids, aliasKey)
	wantErr := errors.New("injected BPF generation delete failure")
	tr.removePIDGenerationOverride = func(uint32) error { return wantErr }

	tr.BlockPID(pid, ns, service, owner)

	require.Same(t, owner, tr.pidOwners[pk])
	require.Same(t, service, tr.pidServices[pk])
	require.Contains(t, tr.pids[pk], aliasKey)
	require.Contains(t, tr.pidKeyOwners[pk], owner)
	require.Contains(t, tr.pidKeyOwners[aliasKey], owner)
	require.Contains(t, bpfMaps.pids, pk)
	require.Contains(t, bpfMaps.pids, aliasKey)
	require.Equal(t, pk, tr.pidKeysByHostPID[uint32(pid)])
	require.Equal(t, owner.ProcessInstanceID(), bpfMaps.generations[uint32(pid)].ProcessInstanceId)
	require.Equal(t, owner.ProcessInstanceID(), tr.pidGenerations[uint32(pid)].ProcessInstanceId)
}

func TestBlockEpochCleanupFailureLeavesGenerationDisarmed(t *testing.T) {
	const (
		pid      = app.PID(700025)
		ns       = uint32(51)
		targetFD = uint32(24)
	)
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	owner := newFakeLogOwner(
		t, pid, 100003, 928, targetFD,
		newEmptyLogTarget(t, "block-epoch-cleanup-failure.log"),
	)
	service := exec.New(exec.Init{Pid: pid})
	tr.AllowPID(pid, ns, service, owner)
	epoch := bpfMaps.epochs[uint32(pid)]
	tr.removePIDLifecycleEpochOverride = func(uint32) error {
		return errors.New("injected lifecycle epoch cleanup failure")
	}

	tr.BlockPID(pid, ns, service, owner)

	require.Equal(t, epoch, bpfMaps.epochs[uint32(pid)])
	require.NotContains(t, bpfMaps.generations, uint32(pid))
	require.False(t, bpfMaps.armed(uint32(pid)))
	require.NotContains(t, tr.pidKeysByHostPID, uint32(pid))
	require.NotContains(t, tr.pidGenerations, uint32(pid))
	require.Empty(t, bpfMaps.pids)
}

func TestPIDAliasOwnerRefcountsPreserveSharedKey(t *testing.T) {
	tr := newTestTracer(t, false)
	installTestPIDMap(tr)
	first := exec.New(exec.Init{Pid: 1})
	second := exec.New(exec.Init{Pid: 2})
	const key = uint64(0x1234)

	require.NoError(t, tr.addPIDOwner(key, first))
	require.NoError(t, tr.addPIDOwner(key, second))
	require.Len(t, tr.pidKeyOwners[key], 2)

	require.NoError(t, tr.removePIDOwner(key, first))
	require.Contains(t, tr.pidKeyOwners[key], second)

	require.NoError(t, tr.removePIDOwner(key, second))
	require.NotContains(t, tr.pidKeyOwners, key)
}

func TestBlockPIDClearsNamespacedPIDCache(t *testing.T) {
	tr := newTestTracer(t, false)

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("removing memlock failed: %v", err)
	}

	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "le_pids_test",
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  1,
		MaxEntries: 4,
	})
	if err != nil {
		t.Skipf("ebpf map create failed: %v", err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Errorf("close eBPF map: %v", err)
		}
	})
	tr.bpfObjects.LogEnricherPids = m

	const (
		ns    = 1
		pid   = 12345
		nsPID = 2345
	)

	pk := tr.pidKey(ns, pid)
	nsPk := tr.pidKey(ns, nsPID)
	tr.pids[pk] = []uint64{nsPk}

	require.NoError(t, m.Put(pk, uint8(1)))
	require.NoError(t, m.Put(nsPk, uint8(1)))

	tr.BlockPID(pid, ns, nil, nil)

	_, ok := tr.pids[pk]
	assert.False(t, ok)

	var value uint8
	require.ErrorIs(t, m.Lookup(pk, &value), ebpf.ErrKeyNotExist)
	require.ErrorIs(t, m.Lookup(nsPk, &value), ebpf.ErrKeyNotExist)
}

func TestPIDOpsWithoutLoadedObjectsDoNotPanic(t *testing.T) {
	tr := newTestTracer(t, false)

	require.Error(t, tr.addPID(tr.pidKey(1, 42)))
	require.Error(t, tr.removePID(tr.pidKey(1, 42)))
}

func TestHandleWithoutTraceContextPreservesPlainText(t *testing.T) {
	file, err := os.CreateTemp("/tmp", "obi-log-enricher-")
	require.NoError(t, err)
	path := file.Name()
	require.NoError(t, file.Close())
	t.Cleanup(func() { _ = os.Remove(path) })
	require.Less(t, len(path), len(BpfLogEventT{}.FilePath))

	cfg := obi.DefaultConfig
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	tr.cfg = &cfg
	tr.formatter = newLogFormatter(cfg.EBPF.LogEnricher)

	const (
		hostPID           = uint32(901)
		processInstanceID = uint64(902)
		lifecycleEpoch    = uint64(903)
	)
	bpfMaps.epochs[hostPID] = lifecycleEpoch
	bpfMaps.generations[hostPID] = BpfLogEnricherGenerationT{
		ProcessInstanceId: processInstanceID,
		LifecycleEpoch:    lifecycleEpoch,
	}
	event := LogEvent{
		orig: BpfLogEventT{
			Tgid:              hostPID,
			ProcessInstanceId: processInstanceID,
			LifecycleEpoch:    lifecycleEpoch,
		},
		logLine: "request failed\n",
	}
	copy(event.orig.FilePath[:], path)
	event.orig.TargetDevice, event.orig.TargetInode = testLogTargetIdentity(t, path)
	event.pinnedTarget, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	require.NoError(t, err)

	tr.handle(event)

	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, event.logLine, string(got))
}

func TestHandleLogEventAcceptsPayloadShorterThanGoStructTailPadding(t *testing.T) {
	const (
		pid      = app.PID(700034)
		start    = uint64(100013)
		targetFD = uint32(33)
	)
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	target := newEmptyLogTarget(t, "short-ringbuf-payload.log")
	owner := newFakeLogOwner(t, pid, start, 937, targetFD, target)
	generation := setTestPIDOwner(tr, bpfMaps, pid, owner)
	orig := newTestBPFLogEvent(t, owner, generation, targetFD)
	orig.Len = 1
	headerSize := int(unsafe.Offsetof(orig.Log))
	require.Less(t, headerSize+int(orig.Len), int(unsafe.Sizeof(orig)))
	raw := append(
		[]byte(nil),
		unsafe.Slice((*byte)(unsafe.Pointer(&orig)), headerSize)...,
	)
	raw = append(raw, 'x')

	_, _, err := tr.handleLogEvent(&ringbuf.Record{RawSample: raw})
	require.ErrorContains(t, err, "async log writer is unavailable")

	contents, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Empty(t, contents)
}

func newFakeLogOwner(
	t *testing.T,
	pid app.PID,
	start, processInstanceID uint64,
	targetFD uint32,
	targetPath string,
	aliases ...app.PID,
) *exec.FileInfo {
	t.Helper()
	procRoot := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(procRoot, "fd"), 0o700))
	require.NoError(t, os.Symlink(
		targetPath,
		filepath.Join(procRoot, "fd", strconv.FormatUint(uint64(targetFD), 10)),
	))
	require.NoError(t, os.Symlink(targetPath, filepath.Join(procRoot, "exe")))
	var executableStat unix.Stat_t
	require.NoError(t, unix.Stat(targetPath, &executableStat))

	statFields := make([]string, 20)
	for i := range statFields {
		statFields[i] = "0"
	}
	statFields[0] = "S"
	statFields[1] = "1"
	statFields[19] = strconv.FormatUint(start, 10)
	stat := strconv.FormatInt(int64(pid), 10) + " (fake-log-process) " +
		strings.Join(statFields, " ") + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(procRoot, "stat"), []byte(stat), 0o600))
	namespacePIDs := append([]app.PID{pid}, aliases...)
	statusPIDs := make([]string, 0, len(namespacePIDs))
	for _, namespacePID := range namespacePIDs {
		statusPIDs = append(statusPIDs, strconv.FormatInt(int64(namespacePID), 10))
	}
	status := "Name:\tfake-log-process\nNSpid:\t" + strings.Join(statusPIDs, "\t") + "\n"
	require.NoError(t, os.WriteFile(filepath.Join(procRoot, "status"), []byte(status), 0o600))

	procDir, err := os.Open(procRoot)
	require.NoError(t, err)
	actualPID, actualStart, state, err := procs.ProcessIdentityFromProcFD(int(procDir.Fd()))
	require.NoError(t, err)
	require.Equal(t, pid, actualPID)
	require.Equal(t, start, actualStart)
	require.Equal(t, byte('S'), state)

	owner := exec.New(exec.Init{
		Pid:               pid,
		Dev:               executableStat.Dev,
		Ino:               executableStat.Ino,
		ProcessStart:      start,
		ProcessInstanceID: processInstanceID,
		ProcessHandle:     procDir,
	})
	t.Cleanup(func() { require.NoError(t, owner.CloseProcessHandle()) })
	return owner
}

func setTestPIDOwner(
	tr *Tracer,
	bpfMaps *testPIDMaps,
	pid app.PID,
	owner *exec.FileInfo,
) BpfLogEnricherGenerationT {
	key := tr.pidKey(1, uint32(pid))
	tr.pidOwners[key] = owner
	tr.pidKeysByHostPID[uint32(pid)] = key
	bpfMaps.nextEpoch++
	epoch := bpfMaps.nextEpoch
	bpfMaps.epochs[uint32(pid)] = epoch
	generation, err := processGenerationForOwner(owner, epoch)
	if err != nil {
		panic(err)
	}
	tr.pidGenerations[uint32(pid)] = generation
	bpfMaps.generations[uint32(pid)] = generation
	return generation
}

func newEmptyLogTarget(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, nil, 0o600))
	return path
}

func testLogTargetIdentity(t *testing.T, path string) (uint64, uint64) {
	t.Helper()
	var stat unix.Stat_t
	require.NoError(t, unix.Stat(path, &stat))
	require.NotZero(t, stat.Dev)
	require.NotZero(t, stat.Ino)
	return stat.Dev, stat.Ino
}

func newTestBPFLogEvent(
	t *testing.T,
	owner *exec.FileInfo,
	generation BpfLogEnricherGenerationT,
	targetFD uint32,
) BpfLogEventT {
	t.Helper()
	event := BpfLogEventT{
		Tgid:              uint32(owner.Pid()),
		ProcessInstanceId: owner.ProcessInstanceID(),
		LifecycleEpoch:    generation.LifecycleEpoch,
		Fd:                targetFD,
	}
	require.NoError(t, owner.UseProcessHandle(func(procFD int) error {
		fd, err := unix.Openat(
			procFD,
			"fd/"+strconv.FormatUint(uint64(targetFD), 10),
			unix.O_WRONLY|unix.O_APPEND|unix.O_CLOEXEC,
			0,
		)
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		var stat unix.Stat_t
		if err := unix.Fstat(fd, &stat); err != nil {
			return err
		}
		event.TargetDevice = stat.Dev
		event.TargetInode = stat.Ino
		return nil
	}))
	require.NotZero(t, event.TargetDevice)
	require.NotZero(t, event.TargetInode)
	return event
}

func replaceFakeLogTarget(t *testing.T, owner *exec.FileInfo, targetFD uint32, path string) {
	t.Helper()
	require.NoError(t, owner.UseProcessHandle(func(procFD int) error {
		name := "fd/" + strconv.FormatUint(uint64(targetFD), 10)
		if err := unix.Unlinkat(procFD, name, 0); err != nil {
			return err
		}
		return unix.Symlinkat(path, procFD, name)
	}))
}

func TestProcessGenerationTokenChangesAcrossExecve(t *testing.T) {
	const (
		pid      = app.PID(700015)
		start    = uint64(60606)
		instance = uint64(906)
		targetFD = uint32(17)
	)
	beforeExec := newFakeLogOwner(
		t, pid, start, instance, targetFD, newEmptyLogTarget(t, "before-exec"),
	)
	afterExec := newFakeLogOwner(
		t, pid, start, instance, targetFD, newEmptyLogTarget(t, "after-exec"),
	)

	beforeGeneration, err := processGenerationForOwner(beforeExec, 1)
	require.NoError(t, err)
	afterGeneration, err := processGenerationForOwner(afterExec, 1)
	require.NoError(t, err)
	require.Equal(t, beforeGeneration.ProcessInstanceId, afterGeneration.ProcessInstanceId)
	require.Equal(t, beforeGeneration.ProcessStartTicks, afterGeneration.ProcessStartTicks)
	require.NotEqual(t, beforeGeneration.ExecutableInode, afterGeneration.ExecutableInode)
	require.False(t, processGenerationEqual(beforeGeneration, afterGeneration),
		"an execve must invalidate the published executable identity")
}

func TestRingbufEventGenerationCannotBindReplacementLifetime(t *testing.T) {
	const (
		pid           = app.PID(700010)
		firstNS       = uint32(41)
		replacementNS = uint32(42)
		targetFD      = uint32(9)
	)
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	firstTarget := newEmptyLogTarget(t, "first-ringbuf.log")
	replacementTarget := newEmptyLogTarget(t, "replacement-ringbuf.log")
	firstService := exec.New(exec.Init{Pid: pid})
	replacementService := exec.New(exec.Init{Pid: pid})
	firstOwner := newFakeLogOwner(t, pid, 91001, 901, targetFD, firstTarget)
	replacementOwner := newFakeLogOwner(t, pid, 91002, 902, targetFD, replacementTarget)

	tr.AllowPID(pid, firstNS, firstService, firstOwner)
	require.Equal(t, firstOwner.ProcessInstanceID(), bpfMaps.generations[uint32(pid)].ProcessInstanceId)
	stale := newTestBPFLogEvent(
		t,
		firstOwner,
		bpfMaps.generations[uint32(pid)],
		targetFD,
	)

	// The event was emitted under the first lifetime but remained in ringbuf
	// until after the host PID's replacement lifetime was published.
	tr.AllowPID(pid, replacementNS, replacementService, replacementOwner)
	require.Equal(t, replacementOwner.ProcessInstanceID(), bpfMaps.generations[uint32(pid)].ProcessInstanceId)
	_, err := tr.bindLogEvent(stale, "stale\n")
	require.ErrorContains(t, err, "does not match current exact owner")

	firstContents, err := os.ReadFile(firstTarget)
	require.NoError(t, err)
	require.Empty(t, firstContents)
	replacementContents, err := os.ReadFile(replacementTarget)
	require.NoError(t, err)
	require.Empty(t, replacementContents)

	fresh, err := tr.bindLogEvent(
		newTestBPFLogEvent(
			t,
			replacementOwner,
			bpfMaps.generations[uint32(pid)],
			targetFD,
		),
		"fresh\n",
	)
	require.NoError(t, err)
	tr.handle(fresh)

	replacementContents, err = os.ReadFile(replacementTarget)
	require.NoError(t, err)
	require.Equal(t, "fresh\n", string(replacementContents))
}

func TestRingbufEventCannotBindOrWriteAfterLifecycleEpochAdvance(t *testing.T) {
	const (
		pid      = app.PID(700026)
		start    = uint64(100004)
		targetFD = uint32(25)
	)
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	target := newEmptyLogTarget(t, "retired-ringbuf-event.log")
	owner := newFakeLogOwner(t, pid, start, 929, targetFD, target)
	generation := setTestPIDOwner(tr, bpfMaps, pid, owner)
	orig := newTestBPFLogEvent(t, owner, generation, targetFD)
	bound, err := tr.bindLogEvent(orig, "retired\n")
	require.NoError(t, err)

	bpfMaps.retire(uint32(pid))

	_, err = tr.bindLogEvent(orig, "stale\n")
	require.Error(t, err)
	tr.handle(bound)
	contents, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Empty(t, contents)
}

func TestBindRejectsTargetReusedAfterKernelEvent(t *testing.T) {
	const (
		pid      = app.PID(700032)
		start    = uint64(100011)
		targetFD = uint32(31)
	)
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	oldTarget := newEmptyLogTarget(t, "pre-bind-reuse-old.log")
	newTarget := newEmptyLogTarget(t, "pre-bind-reuse-new.log")
	owner := newFakeLogOwner(t, pid, start, 935, targetFD, oldTarget)
	generation := setTestPIDOwner(tr, bpfMaps, pid, owner)
	orig := newTestBPFLogEvent(t, owner, generation, targetFD)

	// The event records the kernel file identity. Reusing the numeric FD before
	// userspace binds the event must not redirect the consumed log line.
	replaceFakeLogTarget(t, owner, targetFD, newTarget)
	_, err := tr.bindLogEvent(orig, "must-not-write\n")
	require.ErrorContains(t, err, "exact log target")

	oldContents, err := os.ReadFile(oldTarget)
	require.NoError(t, err)
	require.Empty(t, oldContents)
	newContents, err := os.ReadFile(newTarget)
	require.NoError(t, err)
	require.Empty(t, newContents)
}

func TestBoundEventPinsTargetAcrossFDReuse(t *testing.T) {
	const (
		pid      = app.PID(700033)
		start    = uint64(100012)
		targetFD = uint32(32)
	)
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	oldTarget := newEmptyLogTarget(t, "post-bind-reuse-old.log")
	newTarget := newEmptyLogTarget(t, "post-bind-reuse-new.log")
	owner := newFakeLogOwner(t, pid, start, 936, targetFD, oldTarget)
	generation := setTestPIDOwner(tr, bpfMaps, pid, owner)
	bound, err := tr.bindLogEvent(
		newTestBPFLogEvent(t, owner, generation, targetFD),
		"pinned\n",
	)
	require.NoError(t, err)
	pinnedFD := int(bound.pinnedTarget.Fd())

	// The queued event owns a duplicate of the original target, so subsequent
	// close/reuse of the process's numeric FD cannot redirect the write.
	replaceFakeLogTarget(t, owner, targetFD, newTarget)
	tr.handle(bound)

	oldContents, err := os.ReadFile(oldTarget)
	require.NoError(t, err)
	require.Equal(t, "pinned\n", string(oldContents))
	newContents, err := os.ReadFile(newTarget)
	require.NoError(t, err)
	require.Empty(t, newContents)
	_, err = unix.FcntlInt(uintptr(pinnedFD), unix.F_GETFD, 0)
	require.ErrorIs(t, err, unix.EBADF, "pinned target remained open: %v", err)
}

func TestQueuedLogEventNeverWritesReplacementLifetime(t *testing.T) {
	const (
		pid      = app.PID(700001)
		start    = uint64(12345)
		targetFD = uint32(9)
	)
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	oldTarget := newEmptyLogTarget(t, "old.log")
	replacementTarget := newEmptyLogTarget(t, "replacement.log")
	oldOwner := newFakeLogOwner(t, pid, start, 101, targetFD, oldTarget)
	replacementOwner := newFakeLogOwner(t, pid, start, 102, targetFD, replacementTarget)

	oldGeneration := setTestPIDOwner(tr, bpfMaps, pid, oldOwner)
	queued, err := tr.bindLogEvent(
		newTestBPFLogEvent(t, oldOwner, oldGeneration, targetFD),
		"old\n",
	)
	require.NoError(t, err)
	queuedProcFD := int(queued.procDir.Fd())

	setTestPIDOwner(tr, bpfMaps, pid, replacementOwner)
	require.NoError(t, oldOwner.CloseProcessHandle())
	tr.handle(queued)

	oldContents, err := os.ReadFile(oldTarget)
	require.NoError(t, err)
	require.Empty(t, oldContents)
	replacementContents, err := os.ReadFile(replacementTarget)
	require.NoError(t, err)
	require.Empty(t, replacementContents)
	_, err = unix.FcntlInt(uintptr(queuedProcFD), unix.F_GETFD, 0)
	require.ErrorIs(t, err, unix.EBADF, "queued process handle remained open: %v", err)
}

func TestPinnedLogTargetsSeparateExactLifetimes(t *testing.T) {
	const (
		pid      = app.PID(700002)
		start    = uint64(54321)
		targetFD = uint32(11)
	)
	tests := []struct {
		name        string
		oldInstance uint64
		newInstance uint64
	}{
		{name: "process instance IDs", oldInstance: 201, newInstance: 202},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr := newTestTracer(t, false)
			bpfMaps := installTestPIDMap(tr)
			oldTarget := newEmptyLogTarget(t, "old.log")
			newTarget := newEmptyLogTarget(t, "new.log")
			oldOwner := newFakeLogOwner(t, pid, start, tc.oldInstance, targetFD, oldTarget)
			newOwner := newFakeLogOwner(t, pid, start, tc.newInstance, targetFD, newTarget)

			oldGeneration := setTestPIDOwner(tr, bpfMaps, pid, oldOwner)
			oldEvent, err := tr.bindLogEvent(
				newTestBPFLogEvent(t, oldOwner, oldGeneration, targetFD),
				"old\n",
			)
			require.NoError(t, err)
			tr.handle(oldEvent)

			newGeneration := setTestPIDOwner(tr, bpfMaps, pid, newOwner)
			newEvent, err := tr.bindLogEvent(
				newTestBPFLogEvent(t, newOwner, newGeneration, targetFD),
				"new\n",
			)
			require.NoError(t, err)
			tr.handle(newEvent)

			oldContents, err := os.ReadFile(oldTarget)
			require.NoError(t, err)
			require.Equal(t, "old\n", string(oldContents))
			newContents, err := os.ReadFile(newTarget)
			require.NoError(t, err)
			require.Equal(t, "new\n", string(newContents))
		})
	}
}

func TestPinnedLogTargetsSeparateLifecycleEpochsForSameImageIdentity(t *testing.T) {
	const (
		pid      = app.PID(700027)
		start    = uint64(100005)
		targetFD = uint32(26)
	)
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	target := newEmptyLogTarget(t, "same-image-epoch-cache.log")
	owner := newFakeLogOwner(t, pid, start, 930, targetFD, target)
	firstGeneration := setTestPIDOwner(tr, bpfMaps, pid, owner)
	first, err := tr.bindLogEvent(
		newTestBPFLogEvent(t, owner, firstGeneration, targetFD),
		"first\n",
	)
	require.NoError(t, err)
	tr.handle(first)

	secondGeneration := setTestPIDOwner(tr, bpfMaps, pid, owner)
	require.NotEqual(t, firstGeneration.LifecycleEpoch, secondGeneration.LifecycleEpoch)
	second, err := tr.bindLogEvent(
		newTestBPFLogEvent(t, owner, secondGeneration, targetFD),
		"second\n",
	)
	require.NoError(t, err)
	tr.handle(second)

	contents, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, "first\nsecond\n", string(contents))
}

func TestLogEventEnqueueFailureDoesNotLeakProcessHandles(t *testing.T) {
	const (
		pid      = app.PID(700003)
		start    = uint64(77777)
		targetFD = uint32(13)
	)
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	target := newEmptyLogTarget(t, "target.log")
	owner := newFakeLogOwner(t, pid, start, 301, targetFD, target)
	generation := setTestPIDOwner(tr, bpfMaps, pid, owner)
	tr.ctx = context.Background()
	tr.asyncWriter = shardedqueue.NewShardedQueue[LogEvent](
		1,
		1,
		func(event LogEvent) string { return event.shardKey() },
		func(_ int, ch <-chan LogEvent) {
			for range ch {
				continue
			}
		},
	)
	tr.asyncWriter.Close()
	testEvent := newTestBPFLogEvent(t, owner, generation, targetFD)

	// Warm up all validation and error paths before taking the baseline.
	require.ErrorIs(t, tr.enqueueLogEvent(
		testEvent, "ignored\n",
	), shardedqueue.ErrQueueClosed)
	before, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)

	for range 32 {
		require.ErrorIs(t, tr.enqueueLogEvent(
			testEvent, "ignored\n",
		), shardedqueue.ErrQueueClosed)
	}
	after, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)
	require.Len(t, after, len(before))
}

func TestShutdownDrainsQueueAndClosesLogDescriptors(t *testing.T) {
	const (
		pid      = app.PID(700004)
		start    = uint64(88888)
		targetFD = uint32(15)
	)
	tr := newTestTracer(t, false)
	bpfMaps := installTestPIDMap(tr)
	target := newEmptyLogTarget(t, "target.log")
	owner := newFakeLogOwner(t, pid, start, 401, targetFD, target)
	generation := setTestPIDOwner(tr, bpfMaps, pid, owner)
	tr.ctx = context.Background()

	queuedFDs := make(chan [2]int)
	tr.asyncWriterWG.Add(1)
	tr.asyncWriter = shardedqueue.NewShardedQueue[LogEvent](
		1,
		1,
		func(event LogEvent) string { return event.shardKey() },
		func(_ int, ch <-chan LogEvent) {
			defer tr.asyncWriterWG.Done()
			for event := range ch {
				queuedFDs <- [2]int{int(event.procDir.Fd()), int(event.pinnedTarget.Fd())}
				tr.handle(event)
			}
		},
	)

	require.NoError(t, tr.enqueueLogEvent(
		newTestBPFLogEvent(t, owner, generation, targetFD),
		"drained\n",
	))
	queued := <-queuedFDs
	tr.shutdownAsyncWriter()

	contents, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, "drained\n", string(contents))
	_, err = unix.FcntlInt(uintptr(queued[0]), unix.F_GETFD, 0)
	require.ErrorIs(t, err, unix.EBADF, "queued process handle remained open: %v", err)
	_, err = unix.FcntlInt(uintptr(queued[1]), unix.F_GETFD, 0)
	require.ErrorIs(t, err, unix.EBADF, "pinned log target remained open: %v", err)
}

func TestShouldOmitSpanID_FeatureDisabled(t *testing.T) {
	tr := newTestTracer(t, false)

	fi := exec.New(exec.Init{Service: svc.Attrs{UID: svc.UID{Name: "scoring-engine"}}})
	fi.EnsureExportsOTelTraces()
	setTestPIDService(tr, testPIDDisabledGate, fi)

	assert.False(t, tr.shouldOmitSpanID(testPIDDisabledGate),
		"feature gate off: must not omit span_id even for OTel-exporting services")
}

func TestShouldOmitSpanID_UnknownPID(t *testing.T) {
	tr := newTestTracer(t, true)

	assert.False(t, tr.shouldOmitSpanID(testPIDUntracked),
		"unknown pid: fail-open, include span_id")
}

func TestShouldOmitSpanID_NonOTelService(t *testing.T) {
	tr := newTestTracer(t, true)

	setTestPIDService(tr, testPIDNonOTel, exec.New(exec.Init{Service: svc.Attrs{UID: svc.UID{Name: "regular"}}}))

	assert.False(t, tr.shouldOmitSpanID(testPIDNonOTel),
		"non-OTel-exporting service: include span_id")
}

func TestShouldOmitSpanID_OTelService(t *testing.T) {
	tr := newTestTracer(t, true)

	fi := exec.New(exec.Init{Service: svc.Attrs{UID: svc.UID{Name: "scoring-engine"}}})
	fi.EnsureExportsOTelTraces()
	setTestPIDService(tr, testPIDOTelService, fi)

	assert.True(t, tr.shouldOmitSpanID(testPIDOTelService),
		"OTel-exporting service with feature gate on: omit span_id")
}

func TestShouldOmitSpanID_ReflectsFlagFlip(t *testing.T) {
	tr := newTestTracer(t, true)

	fi := exec.New(exec.Init{Service: svc.Attrs{UID: svc.UID{Name: "scoring-engine"}}})
	setTestPIDService(tr, testPIDFlagFlip, fi)

	assert.False(t, tr.shouldOmitSpanID(testPIDFlagFlip),
		"before flag flip: include span_id")

	fi.EnsureExportsOTelTraces()

	assert.True(t, tr.shouldOmitSpanID(testPIDFlagFlip),
		"after flag flip via shared pointer: omit span_id")
}

const (
	sdkTraceID = "ffeeddccbbaa99887766554433221100"
	sdkSpanID  = "ffeeddccbbaa9988"
)

func TestApplyTraceContext_IncludeSpan(t *testing.T) {
	m := map[string]any{"message": "hello"}

	applyTestTraceContext(m, true)

	assert.Equal(t, testTraceID, m["trace_id"])
	assert.Equal(t, testSpanID, m["span_id"])
}

func TestApplyTraceContext_IncludeSpan_PreservesExisting(t *testing.T) {
	m := map[string]any{"trace_id": sdkTraceID, "span_id": sdkSpanID}

	applyTestTraceContext(m, true)

	assert.Equal(t, sdkTraceID, m["trace_id"], "existing trace_id is preserved")
	assert.Equal(t, sdkSpanID, m["span_id"], "existing span_id is preserved")
}

func TestApplyTraceContext_IncludeSpan_FillsMissingSpanID(t *testing.T) {
	m := map[string]any{"trace_id": sdkTraceID}

	applyTestTraceContext(m, true)

	assert.Equal(t, sdkTraceID, m["trace_id"], "existing trace_id is preserved")
	assert.Equal(t, testSpanID, m["span_id"], "missing span_id is filled")
}

func TestApplyTraceContext_OTelInstrumented_FillsMissingTraceID(t *testing.T) {
	m := map[string]any{"message": "hello"}

	applyTestTraceContext(m, false)

	assert.Equal(t, testTraceID, m["trace_id"])
	_, hasSpan := m["span_id"]
	assert.False(t, hasSpan, "OTel-instrumented: must not inject span_id")
}

func TestApplyTraceContext_OTelInstrumented_PreservesSDKTraceID(t *testing.T) {
	m := map[string]any{"trace_id": sdkTraceID, "span_id": sdkSpanID}

	applyTestTraceContext(m, false)

	assert.Equal(t, sdkTraceID, m["trace_id"], "SDK's trace_id is preserved")
	assert.Equal(t, sdkSpanID, m["span_id"], "SDK's span_id is preserved")
}

func TestApplyTraceContext_OTelInstrumented_FillsTraceIDOnlyWhenSpanIDPresent(t *testing.T) {
	m := map[string]any{"span_id": sdkSpanID}

	applyTestTraceContext(m, false)

	assert.Equal(t, testTraceID, m["trace_id"], "OBI fills missing trace_id")
	assert.Equal(t, sdkSpanID, m["span_id"], "SDK's span_id stays untouched")
}
