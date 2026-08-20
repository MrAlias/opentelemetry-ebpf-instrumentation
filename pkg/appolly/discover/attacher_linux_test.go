// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package discover

import (
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	execpkg "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/helpers/maps"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

type failingLoadTracer struct {
	recordingTracer
}

func (f *failingLoadTracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	return nil, errors.New("BPF load failure")
}

// After an optional common tracer fails during ProcessTracer.Init, it must be
// pruned from ta.commonTracers so that only successfully loaded common tracers
// receive AllowPID and BlockPID notifications.
func TestCommonTracersPrunedAfterLoadFailure(t *testing.T) {
	okTracer := &recordingTracer{}
	failedTracer := &failingLoadTracer{}

	cfg := &obi.Config{}
	cfg.EBPF.BPFFSPath = t.TempDir()
	tracer := ebpf.NewProcessTracer(ebpf.Generic, []ebpf.Tracer{okTracer, failedTracer}, cfg, imetrics.NoopReporter{})
	require.NoError(t, tracer.Init(&ebpfcommon.EBPFEventContext{}, cfg))
	require.Equal(t, []ebpf.Tracer{okTracer}, tracer.Programs)

	tracerEvents := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(10))
	ta := &traceAttacher{
		log:                slog.With("component", t.Name()),
		Metrics:            imetrics.NoopReporter{},
		commonTracers:      []ebpf.Tracer{okTracer, failedTracer},
		existingTracers:    map[execpkg.FileID]executableTracer{},
		processInstances:   maps.MultiCounter[execpkg.FileID]{},
		OutputTracerEvents: tracerEvents,
	}

	ta.dropUnloadedTracers(tracer.Programs)
	assert.Equal(t, []ebpf.Tracer{okTracer}, ta.commonTracers)

	fileInfo := execpkg.New(execpkg.Init{
		Service:    svc.Attrs{UID: svc.UID{Name: "svc", Namespace: "ns"}},
		CmdExePath: "/bin/test",
		Pid:        42,
		Ino:        1234,
		Ns:         17,
	})
	ie := &ebpf.Instrumentable{FileInfo: fileInfo}

	ta.monitorPIDs(tracer, ie)
	assert.NotEmpty(t, okTracer.allowed)
	assert.Empty(t, failedTracer.allowed)

	key := executableKey(fileInfo)
	ta.existingTracers[key] = executableTracer{tracer: tracer, generation: 1}
	recordTestProcessInstance(ta, key, fileInfo)

	ta.notifyProcessDeletion(ie)
	assert.NotEmpty(t, okTracer.blocked)
	assert.Empty(t, failedTracer.blocked)
}

func TestUpdateTracerProbesDoesNotDuplicatePIDAllow(t *testing.T) {
	program := &recordingTracer{}
	cfg := &obi.Config{}
	tracer := ebpf.NewProcessTracer(
		ebpf.Generic, []ebpf.Tracer{program}, cfg, imetrics.NoopReporter{},
	)
	fileInfo := execpkg.New(execpkg.Init{
		Service:    svc.Attrs{SDKLanguage: svc.InstrumentableJava},
		CmdExePath: "/proc/self/exe",
		Pid:        app.PID(os.Getpid()),
		Ino:        1234,
		Ns:         17,
	})
	ie := &ebpf.Instrumentable{FileInfo: fileInfo, Type: svc.InstrumentableJava}
	executable, err := link.OpenExecutable("/proc/self/exe")
	require.NoError(t, err)
	require.NoError(t, tracer.NewExecutable(executable, ie))

	attacher := &traceAttacher{log: slog.With("component", t.Name())}
	attacher.monitorPIDs(tracer, ie)
	require.True(t, attacher.updateTracerProbes(tracer, ie))

	assert.Equal(t, []blockedPID{{pid: fileInfo.Pid(), ns: fileInfo.Ns()}}, program.allowed,
		"one discovery event must create one Allow/Block lifecycle reference")
}

func TestExistingTracerAttachFailureDoesNotAdmitPID(t *testing.T) {
	attachErr := errors.New("required shared-library probe failed")
	program := &recordingTracer{}
	tracer := &ebpf.ProcessTracer{
		Type:     ebpf.Generic,
		Programs: []ebpf.Tracer{program},
	}
	fileInfo := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/test",
		Pid:        42,
		Ino:        1234,
		Ns:         17,
	})
	reporter := &instrumentationErrorRecorder{}
	attacher := &traceAttacher{
		log:     slog.With("component", t.Name()),
		Metrics: reporter,
		newExecutableInstanceFn: func(*ebpf.ProcessTracer, *ebpf.Instrumentable) error {
			return attachErr
		},
	}

	assert.False(t, attacher.activateExistingTracer(tracer, &ebpf.Instrumentable{
		FileInfo: fileInfo,
		Type:     svc.InstrumentableJava,
	}))
	assert.Empty(t, program.allowed, "a failed attach must not publish PID admission")
	require.Equal(t, []instrumentationErrorRecord{{
		processName: "test",
		errorType:   imetrics.InstrumentationErrorAttachingUprobe,
	}}, reporter.records)
}

func TestRejectedReplacementDeletionDoesNotRetireAdmittedInstance(t *testing.T) {
	attachErr := errors.New("required shared-library probe failed")
	program := &recordingTracer{}
	tracer := &ebpf.ProcessTracer{
		Type:     ebpf.Generic,
		Programs: []ebpf.Tracer{program},
	}
	const reusedPID = app.PID(42)
	first := execpkg.New(execpkg.Init{
		CmdExePath:        "/bin/test",
		Pid:               reusedPID,
		Dev:               7,
		Ino:               1234,
		Ns:                17,
		ProcessInstanceID: 1,
	})
	replacement := execpkg.New(execpkg.Init{
		CmdExePath:        "/bin/test",
		Pid:               reusedPID,
		Dev:               7,
		Ino:               1234,
		Ns:                17,
		ProcessInstanceID: 2,
	})
	reporter := &instrumentationErrorRecorder{}
	tracerEvents := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(1))
	events := tracerEvents.Subscribe()
	attacher := &traceAttacher{
		log:                slog.With("component", t.Name()),
		Metrics:            reporter,
		existingTracers:    map[execpkg.FileID]executableTracer{},
		OutputTracerEvents: tracerEvents,
		newExecutableInstanceFn: func(_ *ebpf.ProcessTracer, ie *ebpf.Instrumentable) error {
			if ie.FileInfo == replacement {
				return attachErr
			}
			return nil
		},
	}
	key := first.ID()
	attacher.existingTracers[key] = executableTracer{tracer: tracer, generation: 1}
	firstInstrumentable := &ebpf.Instrumentable{FileInfo: first, PIDOwner: first}
	replacementInstrumentable := &ebpf.Instrumentable{
		FileInfo: replacement,
		PIDOwner: replacement,
	}

	require.True(t, attacher.activateExistingTracer(tracer, firstInstrumentable))
	recordTestProcessInstance(attacher, key, first)
	require.False(t, attacher.activateExistingTracer(tracer, replacementInstrumentable))
	require.NotSame(t, first, replacement)
	require.Equal(t, first.ID(), replacement.ID())
	require.Equal(t, []string{"test"}, reporter.instrumented)

	attacher.notifyProcessDeletion(replacementInstrumentable)
	attacher.notifyProcessDeletion(replacementInstrumentable)
	require.Same(t, tracer, attacher.existingTracers[key].tracer)
	require.Equal(t, 1, *attacher.processInstances[key])
	require.Empty(t, reporter.uninstrumented)
	require.Contains(t, attacher.admittedProcessInstances, first)
	require.NotContains(t, attacher.admittedProcessInstances, replacement)
	require.Equal(t, []*execpkg.FileInfo{replacement, replacement}, program.blockedFiles)

	attacher.notifyProcessDeletion(firstInstrumentable)
	event := testutil.ReadChannel(t, events, testTimeout)
	require.Equal(t, EventDeleted, event.Type)
	require.Same(t, first, event.Obj.PIDOwnerFileInfo())
	require.Equal(t, []string{"test"}, reporter.uninstrumented)
	require.NotContains(t, attacher.existingTracers, key)
	require.Empty(t, attacher.processInstances)
	require.Empty(t, attacher.admittedProcessInstances)
	require.Equal(t, []*execpkg.FileInfo{replacement, replacement, first}, program.blockedFiles)
}

func TestNewTracerAttachFailureAbortsWithoutCommittingCommonState(t *testing.T) {
	attachErr := errors.New("required executable probe failed")
	program := &recordingTracer{}
	tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{program}}
	fileInfo := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/test",
		Pid:        42,
		Ino:        1234,
		Ns:         17,
	})
	ie := &ebpf.Instrumentable{FileInfo: fileInfo}
	reporter := &instrumentationErrorRecorder{}
	var lifecycle []string
	attacher := &traceAttacher{
		log:           slog.With("component", t.Name()),
		Metrics:       reporter,
		commonTracers: []ebpf.Tracer{program},
		newExecutableFn: func(*ebpf.ProcessTracer, *link.Executable, *ebpf.Instrumentable) error {
			lifecycle = append(lifecycle, "attach")
			return attachErr
		},
		abortProcessTracerFn: func(*ebpf.ProcessTracer) error {
			lifecycle = append(lifecycle, "abort")
			return nil
		},
	}

	assert.False(t, attacher.activateNewTracer(tracer, nil, ie))
	assert.Equal(t, []string{"attach", "abort"}, lifecycle)
	assert.False(t, attacher.commonTracersLoaded,
		"a rejected first tracer must not prevent common tracers from loading on retry")
	assert.Equal(t, []ebpf.Tracer{program}, attacher.commonTracers)
	assert.Nil(t, ie.Tracer, "a rejected tracer must not be handed to the run pipeline")
	require.Equal(t, []instrumentationErrorRecord{{
		processName: "test",
		errorType:   imetrics.InstrumentationErrorAttachingUprobe,
	}}, reporter.records)
}

func TestReusableTracerAttachFailureDoesNotPublishExecutableOrPID(t *testing.T) {
	program := &recordingTracer{}
	tracer := &ebpf.ProcessTracer{Type: ebpf.Generic, Programs: []ebpf.Tracer{program}}
	fileInfo := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/test",
		Pid:        42,
		Ino:        1234,
		Ns:         17,
	})
	attacher := &traceAttacher{
		log:             slog.With("component", t.Name()),
		Metrics:         &instrumentationErrorRecorder{},
		existingTracers: map[execpkg.FileID]executableTracer{},
		loadExecutableFn: func(*ebpf.Instrumentable) (*link.Executable, bool) {
			return nil, true
		},
		newExecutableFn: func(*ebpf.ProcessTracer, *link.Executable, *ebpf.Instrumentable) error {
			return errors.New("attach failed")
		},
	}

	assert.False(t, attacher.reuseTracer(tracer, &ebpf.Instrumentable{FileInfo: fileInfo}))
	assert.Empty(t, program.allowed)
	assert.NotContains(t, attacher.existingTracers, fileInfo.ID())
}

func TestMonitorPIDsRejectsClosedExactLifetimeBeforeSideEffects(t *testing.T) {
	pid := app.PID(os.Getpid())
	start, err := procs.ProcessStartTime(pid)
	require.NoError(t, err)
	handle, err := os.Open("/proc/self")
	require.NoError(t, err)
	owner := execpkg.New(execpkg.Init{
		Pid:           pid,
		Ino:           1234,
		Ns:            17,
		ProcessStart:  start,
		ProcessHandle: handle,
	})
	require.NoError(t, owner.CloseProcessHandle())

	program := &recordingTracer{}
	tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{program}}
	selector := NewDynamicPIDSelector()
	attacher := &traceAttacher{
		log:                slog.With("component", t.Name()),
		DynamicPIDSelector: selector,
		nodeInjector:       &recordingNodeInjector{},
	}

	prepared := attacher.prepareProcessSpecificInjection(&ebpf.Instrumentable{FileInfo: owner})
	require.Nil(t, prepared)
	require.Zero(t, attacher.nodeInjector.(*recordingNodeInjector).calls)
	attacher.monitorPIDs(tracer, &ebpf.Instrumentable{FileInfo: owner})

	require.Empty(t, program.allowed)
	require.Empty(t, selector.fileInfoByPID)
	require.Empty(t, selector.lifetimeOwnerByPID)
}
