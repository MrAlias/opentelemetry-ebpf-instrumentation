// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/obi"
)

type lifecycleObjects struct {
	closes atomic.Int32
}

func (o *lifecycleObjects) Close() error {
	o.closes.Add(1)
	return nil
}

type lifecycleTracer struct {
	stubTracer
	bundles      []*ebpfcommon.SpecBundle
	loadErr      error
	required     bool
	capabilities ebpfcommon.TracerCapability
	closers      []io.Closer
	goProbes     map[string][]*ebpfcommon.ProbeDesc
	usdtProbes   map[string][]*ebpfcommon.USDTProbeDesc
	registerErr  error
	unlinked     []exec.FileID
	recorded     []exec.FileID
	already      bool
}

type admissionLifecycleTracer struct {
	stubTracer
	result        bool
	allowedOwners []*exec.FileInfo
	blockedOwners []*exec.FileInfo
}

type lifecycleUprobeTargetTracer struct {
	*lifecycleTracer
	dev uint64
	ino uint64
}

func (t *lifecycleUprobeTargetTracer) ResolveUprobeTarget(
	_ *link.Executable,
	_ uint64,
) (uint64, uint64, error) {
	return t.dev, t.ino, nil
}

func (t *admissionLifecycleTracer) AllowPID(
	_ app.PID,
	_ uint32,
	_ *exec.FileInfo,
	owner *exec.FileInfo,
) bool {
	t.allowedOwners = append(t.allowedOwners, owner)
	return t.result
}

func (t *admissionLifecycleTracer) BlockPID(
	_ app.PID,
	_ uint32,
	_ *exec.FileInfo,
	owner *exec.FileInfo,
) {
	t.blockedOwners = append(t.blockedOwners, owner)
}

func (t *lifecycleTracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	return t.bundles, t.loadErr
}

func (t *lifecycleTracer) AddCloser(closers ...io.Closer) {
	t.closers = append(t.closers, closers...)
}

func (t *lifecycleTracer) Required() bool { return t.required }

func (t *lifecycleTracer) Capabilities() ebpfcommon.TracerCapability {
	return t.capabilities
}

func (t *lifecycleTracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc {
	return t.goProbes
}

func (t *lifecycleTracer) USDTProbes() map[string][]*ebpfcommon.USDTProbeDesc {
	return t.usdtProbes
}

func (t *lifecycleTracer) RegisterOffsets(*exec.FileInfo, *goexec.Offsets) error {
	return t.registerErr
}

func (t *lifecycleTracer) RecordInstrumentedLib(id exec.FileID, _ []io.Closer) {
	t.recorded = append(t.recorded, id)
}

func (t *lifecycleTracer) AddInstrumentedLibRef(id exec.FileID) {
	t.recorded = append(t.recorded, id)
}

func (t *lifecycleTracer) UnlinkInstrumentedLib(id exec.FileID) {
	t.unlinked = append(t.unlinked, id)
}

func (t *lifecycleTracer) AlreadyInstrumentedLib(exec.FileID) bool { return t.already }

func emptySpecBundle(objects io.Closer) *ebpfcommon.SpecBundle {
	return &ebpfcommon.SpecBundle{
		Spec: &ebpf.CollectionSpec{
			Maps:      map[string]*ebpf.MapSpec{},
			Programs:  map[string]*ebpf.ProgramSpec{},
			Variables: map[string]*ebpf.VariableSpec{},
		},
		Objects: objects,
	}
}

func TestProcessTracerAdmissionIsOwnedByFirstProgram(t *testing.T) {
	owner := exec.New(exec.Init{Pid: 42})
	core := &admissionLifecycleTracer{result: true}
	rejectingOptional := &admissionLifecycleTracer{result: false}
	acceptingOptional := &admissionLifecycleTracer{result: true}
	tracer := &ProcessTracer{Programs: []Tracer{core, rejectingOptional, acceptingOptional}}

	assert.True(t, tracer.AllowPID(owner.Pid(), owner.Ns(), owner, owner))
	require.Equal(t, []*exec.FileInfo{owner}, core.allowedOwners)
	require.Equal(t, []*exec.FileInfo{owner}, rejectingOptional.allowedOwners)
	require.Equal(t, []*exec.FileInfo{owner}, acceptingOptional.allowedOwners)
	assert.Empty(t, core.blockedOwners)
	assert.Empty(t, rejectingOptional.blockedOwners)

	rejectingCore := &admissionLifecycleTracer{result: false}
	notInvoked := &admissionLifecycleTracer{result: true}
	rejected := &ProcessTracer{Programs: []Tracer{rejectingCore, notInvoked}}
	replacement := exec.New(exec.Init{Pid: owner.Pid()})

	assert.False(t, rejected.AllowPID(replacement.Pid(), replacement.Ns(), replacement, replacement))
	require.Equal(t, []*exec.FileInfo{replacement}, rejectingCore.allowedOwners)
	assert.Empty(t, notInvoked.allowedOwners,
		"supplementary programs must not run after core exact-owner rejection")
	assert.Empty(t, rejectingCore.blockedOwners,
		"the rejecting program owns its transaction rollback")
}

func testTracerConfig(t *testing.T) *obi.Config {
	t.Helper()
	cfg := obi.DefaultConfig
	cfg.EBPF.BPFFSPath = t.TempDir()
	return &cfg
}

func TestProcessTracerInitRollsBackAllBundlesInFailingTracer(t *testing.T) {
	firstObjects := &lifecycleObjects{}
	failingObjects := &lifecycleObjects{}
	firstBundle := emptySpecBundle(firstObjects)
	failingBundle := emptySpecBundle(failingObjects)
	failingBundle.Constants = map[string]any{"constant_missing_from_spec": uint32(1)}

	program := &lifecycleTracer{
		bundles:  []*ebpfcommon.SpecBundle{firstBundle, failingBundle},
		required: true,
	}
	ctx := &ebpfcommon.EBPFEventContext{EBPFMaps: map[string]*ebpf.Map{}}
	tracer := NewProcessTracer(Generic, []Tracer{program}, testTracerConfig(t), imetrics.NoopReporter{})

	require.Error(t, tracer.Init(ctx, testTracerConfig(t)))
	assert.Equal(t, int32(1), firstObjects.closes.Load())
	assert.Equal(t, int32(1), failingObjects.closes.Load())
	assert.Empty(t, ctx.EBPFMaps)
	require.NoError(t, tracer.Abort())
	assert.Equal(t, int32(1), firstObjects.closes.Load(), "Abort must remain idempotent")
	assert.Equal(t, int32(1), failingObjects.closes.Load(), "Abort must remain idempotent")
}

func TestProcessTracerInitRollsBackEarlierProgramAndCapabilities(t *testing.T) {
	objects := &lifecycleObjects{}
	loaded := &lifecycleTracer{
		bundles:      []*ebpfcommon.SpecBundle{emptySpecBundle(objects)},
		required:     true,
		capabilities: ebpfcommon.TracerCapability(2),
	}
	failing := &lifecycleTracer{loadErr: errors.New("load failed"), required: true}
	ctx := &ebpfcommon.EBPFEventContext{
		EBPFMaps:     map[string]*ebpf.Map{},
		Capabilities: ebpfcommon.TracerCapability(1),
	}
	tracer := NewProcessTracer(Generic, []Tracer{loaded, failing}, testTracerConfig(t), imetrics.NoopReporter{})

	require.Error(t, tracer.Init(ctx, testTracerConfig(t)))
	assert.Equal(t, int32(1), objects.closes.Load())
	assert.Equal(t, ebpfcommon.TracerCapability(1), ctx.Capabilities)
	assert.Empty(t, tracer.Programs)
}

func TestProcessTracerLoadFailureClosesObjectsReturnedWithError(t *testing.T) {
	objects := &lifecycleObjects{}
	program := &lifecycleTracer{
		bundles:  []*ebpfcommon.SpecBundle{emptySpecBundle(objects)},
		loadErr:  errors.New("load failed after allocating objects"),
		required: true,
	}
	ctx := &ebpfcommon.EBPFEventContext{EBPFMaps: map[string]*ebpf.Map{}}
	tracer := NewProcessTracer(Generic, []Tracer{program}, testTracerConfig(t), imetrics.NoopReporter{})

	require.Error(t, tracer.Init(ctx, testTracerConfig(t)))
	assert.Equal(t, int32(1), objects.closes.Load())
}

func TestProcessTracerAbortBeforeRunIsIdempotent(t *testing.T) {
	objects := &lifecycleObjects{}
	program := &lifecycleTracer{
		bundles:  []*ebpfcommon.SpecBundle{emptySpecBundle(objects)},
		required: true,
	}
	ctx := &ebpfcommon.EBPFEventContext{EBPFMaps: map[string]*ebpf.Map{}}
	tracer := NewProcessTracer(Generic, []Tracer{program}, testTracerConfig(t), imetrics.NoopReporter{})
	require.NoError(t, tracer.Init(ctx, testTracerConfig(t)))

	const aborters = 8
	errs := make(chan error, aborters)
	var wg sync.WaitGroup
	for range aborters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- tracer.Abort()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	assert.Equal(t, int32(1), objects.closes.Load())
	assert.Empty(t, tracer.Programs)
}

func TestTracerTransactionRollbackClosesAttachmentsAndUndoesModuleRefs(t *testing.T) {
	program := &lifecycleTracer{}
	first := &countingCloser{}
	second := &countingCloser{}
	txn := &tracerTransaction{Tracer: program}
	txn.AddCloser(first, second)
	txn.RecordInstrumentedLib(exec.FileID{Dev: 1, Ino: 41}, nil)
	txn.AddInstrumentedLibRef(exec.FileID{Dev: 2, Ino: 42})

	require.NoError(t, txn.rollback())
	assert.Equal(t, int32(1), first.closes.Load())
	assert.Equal(t, int32(1), second.closes.Load())
	assert.Equal(t, []exec.FileID{{Dev: 2, Ino: 42}, {Dev: 1, Ino: 41}}, program.unlinked)
	assert.Empty(t, program.closers, "rolled-back attachments must never reach Run ownership")
}

func TestNewExecutableRequiredFailureDoesNotPublishInstrumentable(t *testing.T) {
	sharedModule := &lifecycleTracer{
		stubTracer: stubTracer{
			uprobes: map[string]map[string][]*ebpfcommon.ProbeDesc{"": {}},
		},
		already: true,
	}
	requiredProbe := &ebpfcommon.ProbeDesc{Required: true}
	failingProgram := &lifecycleTracer{
		goProbes: map[string][]*ebpfcommon.ProbeDesc{"missing.required.symbol": {requiredProbe}},
	}
	tracer := NewProcessTracer(
		Generic,
		[]Tracer{sharedModule, failingProgram},
		testTracerConfig(t),
		imetrics.NoopReporter{},
	)
	fileInfo := exec.New(exec.Init{Pid: app.PID(os.Getpid()), Ino: 99})
	ie := &Instrumentable{
		FileInfo: fileInfo,
		Offsets:  &goexec.Offsets{Funcs: map[string][]goexec.FuncOffsets{}},
	}
	originalProcessMaps := processMaps
	processMaps = func(app.PID) ([]*procfs.ProcMap, error) { return []*procfs.ProcMap{{}}, nil }
	t.Cleanup(func() { processMaps = originalProcessMaps })

	err := tracer.NewExecutable((*link.Executable)(nil), ie)
	require.ErrorContains(t, err, "required symbol")
	assert.NotContains(t, tracer.Instrumentables, fileInfo.ID())
	assert.Len(t, sharedModule.recorded, 1)
	assert.Equal(t, sharedModule.recorded, sharedModule.unlinked, "module refs must roll back exactly")
}

func TestNewExecutableOffsetRegistrationFailureDoesNotPublishInstrumentable(t *testing.T) {
	program := &lifecycleTracer{registerErr: errors.New("offset map unavailable")}
	tracer := NewProcessTracer(
		Go,
		[]Tracer{program},
		testTracerConfig(t),
		imetrics.NoopReporter{},
	)
	fileInfo := exec.New(exec.Init{Pid: app.PID(os.Getpid()), Ino: 100})
	originalProcessMaps := processMaps
	processMaps = func(app.PID) ([]*procfs.ProcMap, error) { return nil, nil }
	t.Cleanup(func() { processMaps = originalProcessMaps })

	err := tracer.NewExecutable(nil, &Instrumentable{FileInfo: fileInfo})

	require.ErrorContains(t, err, "registering executable offsets")
	require.ErrorContains(t, err, "offset map unavailable")
	assert.NotContains(t, tracer.Instrumentables, fileInfo.ID())
}

func TestNewExecutableValidatesExactOwnerAfterProcDiscovery(t *testing.T) {
	pid := app.PID(os.Getpid())
	start, err := procs.ProcessStartTime(pid)
	require.NoError(t, err)
	handle, err := os.Open("/proc/self")
	require.NoError(t, err)
	owner := exec.New(exec.Init{
		Pid:           pid,
		Ino:           101,
		ProcessStart:  start,
		ProcessHandle: handle,
	})
	t.Cleanup(func() { _ = owner.CloseProcessHandle() })

	originalProcessMaps := processMaps
	processMaps = func(app.PID) ([]*procfs.ProcMap, error) {
		require.NoError(t, owner.CloseProcessHandle())
		return nil, nil
	}
	t.Cleanup(func() { processMaps = originalProcessMaps })

	tracer := NewProcessTracer(Generic, nil, testTracerConfig(t), imetrics.NoopReporter{})
	err = tracer.NewExecutable(nil, &Instrumentable{FileInfo: owner})
	require.ErrorContains(t, err, "after executable attach")
	assert.NotContains(t, tracer.Instrumentables, owner.ID())
}

func TestNewExecutableInstanceRollsBackOnlyAdditionsFromCall(t *testing.T) {
	sharedModule := &lifecycleTracer{
		stubTracer: stubTracer{
			uprobes: map[string]map[string][]*ebpfcommon.ProbeDesc{"": {}},
		},
		already: true,
	}
	failingProgram := &lifecycleTracer{
		usdtProbes: map[string][]*ebpfcommon.USDTProbeDesc{
			"": {{Required: true}},
		},
	}
	tracer := NewProcessTracer(
		Generic,
		[]Tracer{sharedModule, failingProgram},
		testTracerConfig(t),
		imetrics.NoopReporter{},
	)
	existingCloser := &countingCloser{}
	executableID := exec.FileID{Dev: 1, Ino: 111}
	existingModule := exec.FileID{Dev: 2, Ino: 222}
	inst := &instrumenter{
		closables: []io.Closer{existingCloser},
		modules:   map[exec.FileID]struct{}{existingModule: {}},
	}
	tracer.Instrumentables[executableID] = inst
	fileInfo := exec.New(exec.Init{Pid: app.PID(os.Getpid()), Dev: executableID.Dev, Ino: executableID.Ino})

	originalProcessMaps := processMaps
	processMaps = func(app.PID) ([]*procfs.ProcMap, error) { return []*procfs.ProcMap{{}}, nil }
	t.Cleanup(func() { processMaps = originalProcessMaps })

	err := tracer.NewExecutableInstance(&Instrumentable{FileInfo: fileInfo})
	require.ErrorContains(t, err, "USDT probe is missing")
	assert.Equal(t, int32(0), existingCloser.closes.Load(), "pre-existing attachments must survive rollback")
	assert.Equal(t, map[exec.FileID]struct{}{existingModule: {}}, inst.modules)
	assert.Len(t, sharedModule.recorded, 1)
	assert.Equal(t, sharedModule.recorded, sharedModule.unlinked, "new module refs must roll back exactly")
}

func TestPreparedExecutableInstanceAdmissionRollbackRestoresProbeSnapshot(t *testing.T) {
	sharedModule := &lifecycleTracer{
		stubTracer: stubTracer{
			uprobes: map[string]map[string][]*ebpfcommon.ProbeDesc{"": {}},
		},
		already: true,
	}
	tracer := NewProcessTracer(
		Generic,
		[]Tracer{sharedModule},
		testTracerConfig(t),
		imetrics.NoopReporter{},
	)
	existingCloser := &countingCloser{}
	executableID := exec.FileID{Dev: 1, Ino: 111}
	existingModule := exec.FileID{Dev: 2, Ino: 222}
	inst := &instrumenter{
		key:       executableID,
		closables: []io.Closer{existingCloser},
		modules:   map[exec.FileID]struct{}{existingModule: {}},
	}
	tracer.Instrumentables[executableID] = inst
	fileInfo := exec.New(exec.Init{Pid: app.PID(os.Getpid()), Dev: executableID.Dev, Ino: executableID.Ino})

	originalProcessMaps := processMaps
	processMaps = func(app.PID) ([]*procfs.ProcMap, error) { return []*procfs.ProcMap{{}}, nil }
	t.Cleanup(func() { processMaps = originalProcessMaps })

	transaction, err := tracer.PrepareExecutableInstance(&Instrumentable{FileInfo: fileInfo})
	require.NoError(t, err)
	require.Len(t, sharedModule.recorded, 1)
	require.NoError(t, transaction.Rollback())

	assert.Equal(t, int32(0), existingCloser.closes.Load())
	assert.Equal(t, map[exec.FileID]struct{}{existingModule: {}}, inst.modules)
	assert.Equal(t, sharedModule.recorded, sharedModule.unlinked)
}

func TestPreparedSharedUprobeExecutableRollbackPreservesPredecessor(t *testing.T) {
	const (
		targetDev = uint64(9)
		targetIno = uint64(99)
	)
	program := &lifecycleUprobeTargetTracer{
		lifecycleTracer: &lifecycleTracer{
			stubTracer: stubTracer{
				uprobes: map[string]map[string][]*ebpfcommon.ProbeDesc{"": {}},
			},
			already: true,
		},
		dev: targetDev,
		ino: targetIno,
	}
	tracer := NewProcessTracer(
		Go,
		[]Tracer{program},
		testTracerConfig(t),
		imetrics.NoopReporter{},
	)
	oldKey := exec.FileID{Dev: 1, Ino: 111}
	newKey := exec.FileID{Dev: 2, Ino: 222}
	existingModule := exec.FileID{Dev: 3, Ino: 333}
	existingCloser := &countingCloser{}
	inst := &instrumenter{
		key:       oldKey,
		uprobeKey: exec.FileID{Dev: targetDev, Ino: targetIno},
		closables: []io.Closer{existingCloser},
		modules:   map[exec.FileID]struct{}{existingModule: {}},
	}
	tracer.Instrumentables[oldKey] = inst
	fileInfo := exec.New(exec.Init{Pid: app.PID(os.Getpid()), Dev: newKey.Dev, Ino: newKey.Ino})
	ie := &Instrumentable{
		FileInfo: fileInfo,
		Offsets: &goexec.Offsets{Funcs: map[string][]goexec.FuncOffsets{
			goUprobeTargetProbeSymbol: {{Start: 123}},
		}},
	}
	originalProcessMaps := processMaps
	processMaps = func(app.PID) ([]*procfs.ProcMap, error) { return []*procfs.ProcMap{{}}, nil }
	t.Cleanup(func() { processMaps = originalProcessMaps })

	transaction, err := tracer.PrepareExecutable(nil, ie)
	require.NoError(t, err)
	assert.NotContains(t, tracer.Instrumentables, newKey,
		"a new executable key must remain private until exact admission commits")
	require.Len(t, program.recorded, 1)
	require.NoError(t, transaction.Rollback())

	require.Same(t, inst, tracer.Instrumentables[oldKey])
	assert.NotContains(t, tracer.Instrumentables, newKey)
	assert.Equal(t, int32(0), existingCloser.closes.Load())
	assert.Equal(t, map[exec.FileID]struct{}{existingModule: {}}, inst.modules)
	assert.Equal(t, program.recorded, program.unlinked)
}

func TestPreparedSharedUprobeSameKeyRollbackPreservesPredecessorGeneration(t *testing.T) {
	const (
		targetDev          = uint64(9)
		targetIno          = uint64(99)
		previousGeneration = uint64(17)
	)
	program := &lifecycleUprobeTargetTracer{
		lifecycleTracer: &lifecycleTracer{
			stubTracer: stubTracer{
				uprobes: map[string]map[string][]*ebpfcommon.ProbeDesc{"": {}},
			},
			already: true,
		},
		dev: targetDev,
		ino: targetIno,
	}
	tracer := NewProcessTracer(
		Go,
		[]Tracer{program},
		testTracerConfig(t),
		imetrics.NoopReporter{},
	)
	key := exec.FileID{Dev: 1, Ino: 111}
	existingModule := exec.FileID{Dev: 3, Ino: 333}
	existingCloser := &countingCloser{}
	inst := &instrumenter{
		key:       key,
		uprobeKey: exec.FileID{Dev: targetDev, Ino: targetIno},
		closables: []io.Closer{existingCloser},
		modules:   map[exec.FileID]struct{}{existingModule: {}},
	}
	tracer.Instrumentables[key] = inst
	tracer.instrumentableGenerations[key] = previousGeneration
	fileInfo := exec.New(exec.Init{Pid: app.PID(os.Getpid()), Dev: key.Dev, Ino: key.Ino})
	ie := &Instrumentable{
		FileInfo: fileInfo,
		Offsets: &goexec.Offsets{Funcs: map[string][]goexec.FuncOffsets{
			goUprobeTargetProbeSymbol: {{Start: 123}},
		}},
	}
	originalProcessMaps := processMaps
	processMaps = func(app.PID) ([]*procfs.ProcMap, error) { return []*procfs.ProcMap{{}}, nil }
	t.Cleanup(func() { processMaps = originalProcessMaps })

	transaction, err := tracer.PrepareExecutable(nil, ie)
	require.NoError(t, err)
	require.Same(t, inst, tracer.Instrumentables[key])
	assert.Equal(t, previousGeneration, tracer.instrumentableGenerations[key])
	assert.Zero(t, ie.ExecutableGeneration)
	require.Len(t, program.recorded, 1)
	require.NoError(t, transaction.Rollback())

	require.Same(t, inst, tracer.Instrumentables[key])
	assert.Equal(t, previousGeneration, tracer.instrumentableGenerations[key])
	assert.Equal(t, int32(0), existingCloser.closes.Load())
	assert.Equal(t, map[exec.FileID]struct{}{existingModule: {}}, inst.modules)
	assert.Equal(t, program.recorded, program.unlinked)
}

func TestPreparedGenericSameKeyRollbackPreservesPredecessor(t *testing.T) {
	const previousGeneration = uint64(23)
	tracer := NewProcessTracer(Generic, nil, testTracerConfig(t), imetrics.NoopReporter{})
	key := exec.FileID{Dev: 1, Ino: 111}
	existingCloser := &countingCloser{}
	predecessor := &instrumenter{
		key:       key,
		closables: []io.Closer{existingCloser},
		modules:   map[exec.FileID]struct{}{},
	}
	tracer.Instrumentables[key] = predecessor
	tracer.instrumentableGenerations[key] = previousGeneration
	ie := &Instrumentable{FileInfo: exec.New(exec.Init{
		Pid: app.PID(os.Getpid()),
		Dev: key.Dev,
		Ino: key.Ino,
	})}
	originalProcessMaps := processMaps
	processMaps = func(app.PID) ([]*procfs.ProcMap, error) { return nil, nil }
	t.Cleanup(func() { processMaps = originalProcessMaps })

	transaction, err := tracer.PrepareExecutable(nil, ie)
	require.NoError(t, err)
	require.Same(t, predecessor, tracer.Instrumentables[key],
		"same-key predecessor retirement must wait for exact admission")
	assert.Equal(t, previousGeneration, tracer.instrumentableGenerations[key])
	assert.Zero(t, ie.ExecutableGeneration)
	assert.Equal(t, int32(0), existingCloser.closes.Load())
	require.NoError(t, transaction.Rollback())

	require.Same(t, predecessor, tracer.Instrumentables[key])
	assert.Equal(t, previousGeneration, tracer.instrumentableGenerations[key])
	assert.Equal(t, int32(0), existingCloser.closes.Load())
}

func TestNewExecutableInstanceRejectsMissingInstrumenter(t *testing.T) {
	tracer := NewProcessTracer(Generic, nil, testTracerConfig(t), imetrics.NoopReporter{})
	fileInfo := exec.New(exec.Init{Pid: app.PID(os.Getpid()), Ino: 404})

	err := tracer.NewExecutableInstance(&Instrumentable{FileInfo: fileInfo})

	require.ErrorContains(t, err, "instrumenter for device 0 inode 404 does not exist")
}

func TestProcessTracerSeparatesSameInodeOnDifferentDevices(t *testing.T) {
	tracer := NewProcessTracer(Generic, nil, testTracerConfig(t), imetrics.NoopReporter{})
	first := exec.New(exec.Init{Pid: app.PID(os.Getpid()), Dev: 1, Ino: 404})
	second := exec.New(exec.Init{Pid: app.PID(os.Getpid()), Dev: 2, Ino: 404})
	originalProcessMaps := processMaps
	processMaps = func(app.PID) ([]*procfs.ProcMap, error) { return nil, nil }
	t.Cleanup(func() { processMaps = originalProcessMaps })

	firstInstrumentable := &Instrumentable{FileInfo: first}
	secondInstrumentable := &Instrumentable{FileInfo: second}
	require.NoError(t, tracer.NewExecutable(nil, firstInstrumentable))
	require.NoError(t, tracer.NewExecutable(nil, secondInstrumentable))

	require.Len(t, tracer.Instrumentables, 2)
	assert.Contains(t, tracer.Instrumentables, first.ID())
	assert.Contains(t, tracer.Instrumentables, second.ID())

	tracer.UnlinkExecutable(first, firstInstrumentable.ExecutableGeneration)
	assert.NotContains(t, tracer.Instrumentables, first.ID())
	assert.Contains(t, tracer.Instrumentables, second.ID())
}
