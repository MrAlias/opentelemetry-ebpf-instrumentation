// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"

	cebpf "github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	execpkg "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/internal/helpers/maps"
	javaagent "go.opentelemetry.io/obi/pkg/internal/java"
	"go.opentelemetry.io/obi/pkg/internal/jvmtools"
	"go.opentelemetry.io/obi/pkg/internal/nodejs"
	"go.opentelemetry.io/obi/pkg/internal/testutil"
	"go.opentelemetry.io/obi/pkg/internal/transform/route"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

type blockedPID struct {
	pid app.PID
	ns  uint32
}

type recordingTracer struct {
	allowed         []blockedPID
	allowedServices []*execpkg.FileInfo
	allowedOwners   []*execpkg.FileInfo
	blocked         []blockedPID
	blockedServices []*execpkg.FileInfo
	blockedFiles    []*execpkg.FileInfo
	allow           func(app.PID, uint32, *execpkg.FileInfo, *execpkg.FileInfo) bool
}

type recordingNodeInjector struct {
	calls      int
	last       *ebpf.Instrumentable
	prepared   *recordingNodePrepared
	prepareErr error
}

type recordingNodePrepared struct {
	newCalls   int
	closeCalls int
	newErr     error
}

func (i *recordingNodeInjector) PrepareExecutable(
	ie *ebpf.Instrumentable,
) (nodejs.PreparedExecutable, error) {
	i.calls++
	i.last = ie
	if i.prepareErr != nil {
		return nil, i.prepareErr
	}
	if i.prepared == nil {
		i.prepared = &recordingNodePrepared{}
	}
	return i.prepared, nil
}

func (p *recordingNodePrepared) NewExecutable() error {
	p.newCalls++
	return p.newErr
}

func (p *recordingNodePrepared) Close() error {
	p.closeCalls++
	return nil
}

type instrumentationErrorRecord struct {
	processName string
	errorType   string
}

type instrumentationErrorRecorder struct {
	imetrics.NoopReporter
	records        []instrumentationErrorRecord
	instrumented   []string
	uninstrumented []string
}

type controlledJavaInjector struct {
	calls        chan context.Context
	firstRelease chan struct{}
	callCount    atomic.Uint32
}

type controlledJavaPrepared struct {
	injector   *controlledJavaInjector
	closeOnce  sync.Once
	closeCount atomic.Uint32
}

func (i *controlledJavaInjector) PrepareExecutable(
	*ebpf.Instrumentable,
) (javaagent.PreparedExecutable, error) {
	return &controlledJavaPrepared{injector: i}, nil
}

func (p *controlledJavaPrepared) NewExecutableContext(ctx context.Context) error {
	i := p.injector
	call := i.callCount.Add(1)
	i.calls <- ctx
	if call == 1 && i.firstRelease != nil {
		<-ctx.Done()
		<-i.firstRelease
	}
	return ctx.Err()
}

func (p *controlledJavaPrepared) Close() error {
	p.closeOnce.Do(func() { p.closeCount.Add(1) })
	return nil
}

func (r *instrumentationErrorRecorder) InstrumentationError(processName, errorType string) {
	r.records = append(r.records, instrumentationErrorRecord{
		processName: processName,
		errorType:   errorType,
	})
}

func (r *instrumentationErrorRecorder) InstrumentProcess(processName string) {
	r.instrumented = append(r.instrumented, processName)
}

func (r *instrumentationErrorRecorder) UninstrumentProcess(processName string) {
	r.uninstrumented = append(r.uninstrumented, processName)
}

func recordTestProcessInstance(
	ta *traceAttacher,
	executable execpkg.FileID,
	owner *execpkg.FileInfo,
) {
	ta.recordProcessInstance(owner, executable)
}

func (r *recordingTracer) AllowPID(
	pid app.PID,
	ns uint32,
	service, owner *execpkg.FileInfo,
) bool {
	r.allowed = append(r.allowed, blockedPID{pid: pid, ns: ns})
	r.allowedServices = append(r.allowedServices, service)
	r.allowedOwners = append(r.allowedOwners, owner)
	if r.allow != nil {
		return r.allow(pid, ns, service, owner)
	}
	return true
}

func (r *recordingTracer) BlockPID(
	pid app.PID,
	ns uint32,
	service, owner *execpkg.FileInfo,
) {
	r.blocked = append(r.blocked, blockedPID{pid: pid, ns: ns})
	r.blockedServices = append(r.blockedServices, service)
	r.blockedFiles = append(r.blockedFiles, owner)
}
func (r *recordingTracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error)           { return nil, nil }
func (r *recordingTracer) AddCloser(...io.Closer)                                 {}
func (r *recordingTracer) SetupTailCalls()                                        {}
func (r *recordingTracer) KProbes() map[string]ebpfcommon.ProbeDesc               { return nil }
func (r *recordingTracer) Tracepoints() map[string]ebpfcommon.ProbeDesc           { return nil }
func (r *recordingTracer) GoProbes() map[string][]*ebpfcommon.ProbeDesc           { return nil }
func (r *recordingTracer) UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc { return nil }
func (r *recordingTracer) USDTProbes() map[string][]*ebpfcommon.USDTProbeDesc     { return nil }
func (r *recordingTracer) SocketFilters() []*cebpf.Program                        { return nil }
func (r *recordingTracer) SockMsgs() []ebpfcommon.SockMsg                         { return nil }
func (r *recordingTracer) SockOps() []ebpfcommon.SockOps                          { return nil }
func (r *recordingTracer) Iters() []*ebpfcommon.Iter                              { return nil }
func (r *recordingTracer) Tracing() []*ebpfcommon.Tracing                         { return nil }
func (r *recordingTracer) RecordInstrumentedLib(execpkg.FileID, []io.Closer)      {}
func (r *recordingTracer) AddInstrumentedLibRef(execpkg.FileID)                   {}
func (r *recordingTracer) AlreadyInstrumentedLib(execpkg.FileID) bool             { return false }
func (r *recordingTracer) UnlinkInstrumentedLib(execpkg.FileID)                   {}
func (r *recordingTracer) RegisterOffsets(*execpkg.FileInfo, *goexec.Offsets) error {
	return nil
}
func (r *recordingTracer) ProcessBinary(*execpkg.FileInfo)              {}
func (r *recordingTracer) Required() bool                               { return false }
func (r *recordingTracer) SetEventContext(*ebpfcommon.EBPFEventContext) {}
func (r *recordingTracer) Capabilities() ebpfcommon.TracerCapability    { return 0 }
func (r *recordingTracer) Run(context.Context, *ebpfcommon.EBPFEventContext, *msg.Queue[[]request.Span]) {
}

func TestTraceAttacherReportsJavaAttachFailure(t *testing.T) {
	reporter := &instrumentationErrorRecorder{}
	attacher := &traceAttacher{
		log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Metrics: reporter,
	}
	instrumentable := &ebpf.Instrumentable{
		FileInfo: execpkg.New(execpkg.Init{
			CmdExePath: "/usr/bin/java",
			Pid:        42,
		}),
	}

	attacher.handleJavaAttachResult(instrumentable, nil)
	assert.Empty(t, reporter.records)

	attacher.handleJavaAttachResult(instrumentable, errors.New("dynamic agent loading disabled"))
	require.Equal(t, []instrumentationErrorRecord{{
		processName: "java",
		errorType:   imetrics.InstrumentationErrorAttachingJavaAgent,
	}}, reporter.records)
}

func TestJavaServiceMetadataUsesExactEventOwnerAndCommitsAfterAdmission(t *testing.T) {
	const (
		parentPID = app.PID(41)
		eventPID  = app.PID(42)
	)
	parent := execpkg.New(execpkg.Init{
		Pid: parentPID,
		Service: svc.Attrs{
			UID:      svc.UID{Namespace: "production", Instance: "parent-instance"},
			EnvVars:  map[string]string{"SOURCE": "parent"},
			Metadata: map[attr.Name]string{"existing": "preserved"},
		},
	})
	eventOwner := execpkg.New(execpkg.Init{
		Pid: eventPID,
		Service: svc.Attrs{
			EnvVars: map[string]string{"SOURCE": "event-owner"},
		},
	})
	ie := &ebpf.Instrumentable{
		Type:     svc.InstrumentableJava,
		FileInfo: parent,
		PIDOwner: eventOwner,
	}
	var validated []*execpkg.FileInfo
	attacher := &traceAttacher{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		validateMetadataOwnerFn: func(pid app.PID, owner *execpkg.FileInfo) error {
			assert.Equal(t, eventPID, pid)
			validated = append(validated, owner)
			return nil
		},
		readJavaServiceMetadataFn: func(pid app.PID, service svc.Attrs) (jvmtools.ServiceMetadata, error) {
			assert.Equal(t, eventPID, pid,
				"parent substitution must not redirect metadata reads to the parent PID")
			assert.Equal(t, "event-owner", service.EnvVars["SOURCE"])
			assert.Empty(t, service.UID.Name)
			assert.Equal(t, "preserved", service.Metadata["existing"])
			return jvmtools.ServiceMetadata{Name: "orders", Version: "1.2.3"}, nil
		},
	}

	update := attacher.resolveServiceMetadata(ie)

	require.NotNil(t, update)
	require.Len(t, validated, 3)
	for _, owner := range validated {
		assert.Same(t, eventOwner, owner)
	}
	provisional := parent.ServiceAttrs()
	assert.Equal(t, "orders", provisional.UID.Name)
	assert.Equal(t, "1.2.3", provisional.Metadata[jvmtools.ServiceVersionAttribute])
	assert.False(t, parent.AutoName(), "auto-name is an admission commit side effect")

	parent.SetSDKLanguage(svc.InstrumentableJava)
	update.Commit()

	committed := parent.ServiceAttrs()
	assert.Equal(t, "production", committed.UID.Namespace)
	assert.Equal(t, "parent-instance", committed.UID.Instance)
	assert.Equal(t, "preserved", committed.Metadata["existing"])
	assert.Equal(t, svc.InstrumentableJava, committed.SDKLanguage)
	assert.True(t, parent.AutoName())
}

func TestJavaServiceMetadataPIDReuseAfterPublicationRollsBackExactly(t *testing.T) {
	baselineMetadata := map[attr.Name]string{"existing": "preserved"}
	target := execpkg.New(execpkg.Init{
		Pid: 41,
		Service: svc.Attrs{
			UID:      svc.UID{Namespace: "production", Instance: "stable-instance"},
			Metadata: baselineMetadata,
		},
	})
	eventOwner := execpkg.New(execpkg.Init{Pid: 42})
	before := target.ServiceAttrs()
	validation := 0
	attacher := &traceAttacher{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		validateMetadataOwnerFn: func(pid app.PID, owner *execpkg.FileInfo) error {
			assert.Equal(t, app.PID(42), pid)
			assert.Same(t, eventOwner, owner)
			validation++
			if validation == 3 {
				return errors.New("exact owner exited and PID was reused")
			}
			return nil
		},
		readJavaServiceMetadataFn: func(pid app.PID, service svc.Attrs) (jvmtools.ServiceMetadata, error) {
			return jvmtools.ServiceMetadata{Name: "replacement", Version: "9.9.9"}, nil
		},
	}

	update := attacher.resolveServiceMetadata(&ebpf.Instrumentable{
		Type:     svc.InstrumentableJava,
		FileInfo: target,
		PIDOwner: eventOwner,
	})

	assert.Nil(t, update)
	assert.Equal(t, 3, validation)
	assert.Equal(t, before, target.ServiceAttrs(),
		"a lifetime change after provisional publication must restore UID and metadata")
	assert.False(t, target.AutoName())
}

func TestJavaServiceMetadataAtomicBeginPreservesResolverTimePublication(t *testing.T) {
	target := execpkg.New(execpkg.Init{Pid: 42})
	attacher := &traceAttacher{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		validateMetadataOwnerFn: func(app.PID, *execpkg.FileInfo) error {
			return nil
		},
		readJavaServiceMetadataFn: func(app.PID, svc.Attrs) (jvmtools.ServiceMetadata, error) {
			// Model a shared-parent updater publishing after the resolver took its
			// missing-field snapshot but before provisional apply.
			target.SetUID(svc.UID{Name: "runtime", Namespace: "runtime-ns"})
			target.SetMetadata(map[attr.Name]string{
				jvmtools.ServiceVersionAttribute: "runtime-version",
			})
			return jvmtools.ServiceMetadata{Name: "stale-derived", Version: "stale-version"}, nil
		},
	}

	receipt := attacher.resolveServiceMetadata(&ebpf.Instrumentable{
		Type: svc.InstrumentableJava, FileInfo: target, PIDOwner: target,
	})

	assert.Nil(t, receipt)
	got := target.ServiceAttrs()
	assert.Equal(t, "runtime", got.UID.Name)
	assert.Equal(t, "runtime-ns", got.UID.Namespace)
	assert.Equal(t, "runtime-version", got.Metadata[jvmtools.ServiceVersionAttribute])
}

func TestJavaServiceMetadataReceiptPreservesIntendedDynamicPIDFields(t *testing.T) {
	target := execpkg.New(execpkg.Init{Pid: 42})
	attacher := &traceAttacher{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		validateMetadataOwnerFn: func(app.PID, *execpkg.FileInfo) error {
			return nil
		},
		readJavaServiceMetadataFn: func(app.PID, svc.Attrs) (jvmtools.ServiceMetadata, error) {
			return jvmtools.ServiceMetadata{Name: "derived", Version: "1.2.3"}, nil
		},
	}
	receipt := attacher.resolveServiceMetadata(&ebpf.Instrumentable{
		Type: svc.InstrumentableJava, FileInfo: target, PIDOwner: target,
	})
	require.NotNil(t, receipt)

	require.True(t, applyDynamicPIDAttributes(target, dynamicPIDAttributes{
		serviceName:      "runtime-orders",
		serviceNamespace: "runtime-ns",
		resourceAttributes: map[string]string{
			"deployment.environment": "production",
		},
	}))
	receipt.Rollback()

	got := target.ServiceAttrs()
	assert.Equal(t, "runtime-orders", got.UID.Name)
	assert.Equal(t, "runtime-ns", got.UID.Namespace)
	assert.Equal(t, "production", got.Metadata["deployment.environment"])
	assert.NotContains(t, got.Metadata, jvmtools.ServiceVersionAttribute,
		"an unrelated dynamic metadata key must not adopt the provisional version")
	assert.False(t, target.AutoName())
}

func TestJavaServiceMetadataReceiptPreservesProcessContextAndUnrelatedUpdates(t *testing.T) {
	target := execpkg.New(execpkg.Init{Pid: 42})
	attacher := &traceAttacher{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		validateMetadataOwnerFn: func(app.PID, *execpkg.FileInfo) error {
			return nil
		},
		readJavaServiceMetadataFn: func(app.PID, svc.Attrs) (jvmtools.ServiceMetadata, error) {
			return jvmtools.ServiceMetadata{Name: "derived", Version: "1.2.3"}, nil
		},
	}
	receipt := attacher.resolveServiceMetadata(&ebpf.Instrumentable{
		Type: svc.InstrumentableJava, FileInfo: target, PIDOwner: target,
	})
	require.NotNil(t, receipt)

	(&processContextDecorator{}).addAttribute(target, attr.ServiceNamespace, "context-ns")
	matcher := route.NewMatcher([]string{"/orders/:id"})
	target.SetSDKLanguage(svc.InstrumentableJava)
	target.SetHarvestedRoutes(matcher)
	target.SetHostNameInstance("host-a", "instance-a")
	receipt.Rollback()

	got := target.ServiceAttrs()
	assert.Empty(t, got.UID.Name,
		"a namespace update must not adopt the provisional name")
	assert.Equal(t, "context-ns", got.UID.Namespace)
	assert.Equal(t, "context-ns", got.Metadata[attr.ServiceNamespace])
	assert.NotContains(t, got.Metadata, jvmtools.ServiceVersionAttribute,
		"a namespace metadata key must not adopt the provisional version")
	assert.Equal(t, svc.InstrumentableJava, got.SDKLanguage)
	assert.Equal(t, "host-a", got.HostName)
	assert.Equal(t, "instance-a", got.UID.Instance)
	assert.Same(t, matcher, got.HarvestedRouteMatcher)
}

func TestRejectedJavaServiceMetadataAdmissionPreservesUnrelatedDefaults(t *testing.T) {
	target := execpkg.New(execpkg.Init{
		Pid:        42,
		CmdExePath: "/usr/bin/java",
		Service: svc.Attrs{
			UID:      svc.UID{Namespace: "production", Instance: "stable-instance"},
			Metadata: nil,
		},
	})
	before := target.ServiceAttrs()
	attacher := &traceAttacher{
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		validateMetadataOwnerFn: func(app.PID, *execpkg.FileInfo) error {
			return nil
		},
		readJavaServiceMetadataFn: func(app.PID, svc.Attrs) (jvmtools.ServiceMetadata, error) {
			return jvmtools.ServiceMetadata{Version: "1.2.3"}, nil
		},
	}
	ie := &ebpf.Instrumentable{
		Type:     svc.InstrumentableJava,
		FileInfo: target,
		PIDOwner: target,
	}

	update := attacher.resolveServiceMetadata(ie)
	require.NotNil(t, update)
	require.NotEqual(t, before, target.ServiceAttrs())
	target.ApplyServiceDefaults(svc.InstrumentableJava)
	require.Equal(t, "java", target.ServiceAttrs().UID.Name)
	require.True(t, target.AutoName())

	// This is the same rollback edge used when getTracer rejects exact PID
	// admission after metadata and ordinary service defaults were visible to
	// tracer construction.
	update.Rollback()

	got := target.ServiceAttrs()
	assert.Equal(t, before.UID.Namespace, got.UID.Namespace)
	assert.Equal(t, before.UID.Instance, got.UID.Instance)
	assert.Equal(t, "java", got.UID.Name,
		"rollback must preserve the independent default-name publication")
	assert.Equal(t, svc.InstrumentableJava, got.SDKLanguage)
	assert.Nil(t, got.Metadata,
		"rollback must preserve nil-vs-empty metadata state")
	assert.True(t, target.AutoName())
}

func TestMonitorPIDsKeepsServiceMetadataSeparateFromExactLifetimes(t *testing.T) {
	const (
		parentPID = app.PID(41)
		childOne  = app.PID(42)
		childTwo  = app.PID(43)
	)
	service := execpkg.New(execpkg.Init{Pid: parentPID, Ns: 17})
	firstChild := execpkg.New(execpkg.Init{Pid: childOne, Ns: 18})
	secondChild := execpkg.New(execpkg.Init{Pid: childTwo, Ns: 19})
	ie := &ebpf.Instrumentable{
		FileInfo:  service,
		ChildPids: []app.PID{childOne, childTwo},
		PIDOwners: map[app.PID]*execpkg.FileInfo{
			parentPID: service,
			childOne:  firstChild,
			childTwo:  secondChild,
		},
	}
	program := &recordingTracer{}
	tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{program}}
	selector := NewDynamicPIDSelector()
	attacher := &traceAttacher{DynamicPIDSelector: selector}

	attacher.monitorPIDs(tracer, ie)

	require.Equal(t, []blockedPID{
		{pid: parentPID, ns: 17},
		{pid: childOne, ns: 18},
		{pid: childTwo, ns: 19},
	}, program.allowed)
	require.Equal(t, []*execpkg.FileInfo{service, service, service}, program.allowedServices)
	require.Equal(t, []*execpkg.FileInfo{service, firstChild, secondChild}, program.allowedOwners)
	require.Same(t, service, selector.fileInfoByPID[parentPID])
	require.Same(t, service, selector.fileInfoByPID[childOne])
	require.Same(t, service, selector.fileInfoByPID[childTwo])
	require.Same(t, service, selector.lifetimeOwnerByPID[parentPID])
	require.Same(t, firstChild, selector.lifetimeOwnerByPID[childOne])
	require.Same(t, secondChild, selector.lifetimeOwnerByPID[childTwo])
}

func TestWithCommonTracersKeepsCoreAdmissionProgramFirst(t *testing.T) {
	cfg := obi.DefaultConfig
	core := &recordingTracer{}
	attacher := &traceAttacher{
		Cfg:     &cfg,
		Metrics: imetrics.NoopReporter{},
		EbpfEventContext: &ebpfcommon.EBPFEventContext{
			CommonPIDsFilter: &ebpfcommon.IdentityPidsFilter{},
		},
	}

	programs := attacher.withCommonTracersGroup([]ebpf.Tracer{core})

	require.NotEmpty(t, programs)
	require.Same(t, core, programs[0],
		"ProcessTracer admission semantics require the Generic/Go core program first")
}

func TestMonitorPIDsCommitsOnlyAcceptedCandidatesAfterExactOwner(t *testing.T) {
	const (
		parentPID   = app.PID(41)
		eventPID    = app.PID(42)
		acceptedPID = app.PID(43)
	)
	service := execpkg.New(execpkg.Init{Pid: parentPID, Ns: 17})
	eventOwner := execpkg.New(execpkg.Init{Pid: eventPID, Ns: 18})
	acceptedOwner := execpkg.New(execpkg.Init{Pid: acceptedPID, Ns: 19})
	ie := &ebpf.Instrumentable{
		FileInfo:  service,
		PIDOwner:  eventOwner,
		ChildPids: []app.PID{eventPID, acceptedPID},
		PIDOwners: map[app.PID]*execpkg.FileInfo{
			parentPID:   service,
			eventPID:    eventOwner,
			acceptedPID: acceptedOwner,
		},
	}
	program := &recordingTracer{
		allow: func(pid app.PID, _ uint32, _, _ *execpkg.FileInfo) bool {
			return pid != parentPID
		},
	}
	tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{program}}
	selector := NewDynamicPIDSelector()
	signals := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(1))
	signalEvents := signals.Subscribe()
	attacher := &traceAttacher{
		DynamicPIDSelector:  selector,
		SpanSignalsShortcut: signals,
	}

	require.True(t, attacher.monitorPIDs(tracer, ie))

	require.Equal(t, []blockedPID{
		{pid: eventPID, ns: 18},
		{pid: parentPID, ns: 17},
		{pid: acceptedPID, ns: 19},
	}, program.allowed, "the exact discovery-event owner must be attempted first")
	assert.NotContains(t, selector.fileInfoByPID, parentPID)
	require.Same(t, eventOwner, selector.lifetimeOwnerByPID[eventPID])
	require.Same(t, acceptedOwner, selector.lifetimeOwnerByPID[acceptedPID])
	spans := testutil.ReadChannel(t, signalEvents, testTimeout)
	require.Len(t, spans, 2)
	assert.Equal(t, []app.PID{eventPID, acceptedPID}, []app.PID{
		spans[0].Service.ProcPID, spans[1].Service.ProcPID,
	})
}

func TestMonitorPIDsRejectedSamePIDReplacementPreservesSelectorOwner(t *testing.T) {
	const pid = app.PID(42)
	predecessor := execpkg.New(execpkg.Init{Pid: pid, Dev: 7, Ino: 11, Ns: 17})
	replacement := execpkg.New(execpkg.Init{Pid: pid, Dev: 7, Ino: 11, Ns: 17})
	program := &recordingTracer{
		allow: func(_ app.PID, _ uint32, _, owner *execpkg.FileInfo) bool {
			return owner != replacement
		},
	}
	tracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{program}}
	selector := NewDynamicPIDSelector()
	attacher := &traceAttacher{DynamicPIDSelector: selector}

	require.True(t, attacher.monitorPIDs(tracer, &ebpf.Instrumentable{
		FileInfo: predecessor,
		PIDOwner: predecessor,
	}))
	require.False(t, attacher.monitorPIDs(tracer, &ebpf.Instrumentable{
		FileInfo: replacement,
		PIDOwner: replacement,
	}))

	require.Same(t, predecessor, selector.fileInfoByPID[pid])
	require.Same(t, predecessor, selector.lifetimeOwnerByPID[pid])
	assert.Empty(t, program.blocked,
		"a rejected replacement must not Block an independently admitted owner")
}

func TestCommitNewTracerAdmissionRejectsAndAbortsWithoutPublication(t *testing.T) {
	owner := execpkg.New(execpkg.Init{Pid: 42, Dev: 7, Ino: 11, Ns: 17})
	program := &recordingTracer{allow: func(app.PID, uint32, *execpkg.FileInfo, *execpkg.FileInfo) bool {
		return false
	}}
	tracer := &ebpf.ProcessTracer{Type: ebpf.Generic, Programs: []ebpf.Tracer{program}}
	reporter := &instrumentationErrorRecorder{}
	aborted := 0
	rolledBack := 0
	attacher := &traceAttacher{
		log:             slog.With("component", t.Name()),
		Metrics:         reporter,
		nodeInjector:    &recordingNodeInjector{},
		existingTracers: map[execpkg.FileID]executableTracer{},
		abortProcessTracerFn: func(*ebpf.ProcessTracer) error {
			aborted++
			return nil
		},
	}
	ie := &ebpf.Instrumentable{FileInfo: owner, PIDOwner: owner, Tracer: tracer}

	admitted := attacher.commitNewTracerAdmission(
		tracer,
		ie,
		owner.ID(),
		func(commit bool) error {
			assert.False(t, commit)
			rolledBack++
			return nil
		},
	)

	assert.False(t, admitted)
	assert.Equal(t, 1, rolledBack)
	assert.Equal(t, 1, aborted)
	assert.Nil(t, ie.Tracer)
	assert.Empty(t, attacher.existingTracers)
	assert.Nil(t, attacher.reusableTracer)
	assert.Empty(t, reporter.instrumented)
	assert.Zero(t, attacher.nodeInjector.(*recordingNodeInjector).calls)
}

func TestNodeInjectionPreparedAfterAdmissionAlwaysCloses(t *testing.T) {
	prepared := &recordingNodePrepared{newErr: errors.New("injection failed")}
	injector := &recordingNodeInjector{prepared: prepared}
	owner := execpkg.New(execpkg.Init{Pid: 42})
	ie := &ebpf.Instrumentable{
		Type:     svc.InstrumentableNodejs,
		FileInfo: execpkg.New(execpkg.Init{Pid: 41}),
		PIDOwner: owner,
	}
	attacher := &traceAttacher{
		log:          slog.With("component", t.Name()),
		nodeInjector: injector,
	}

	attacher.injectNodeAfterAdmission(ie)

	assert.Equal(t, 1, injector.calls)
	assert.Same(t, ie, injector.last)
	assert.Same(t, owner, injector.last.PIDOwnerFileInfo())
	assert.Equal(t, 1, prepared.newCalls)
	assert.Equal(t, 1, prepared.closeCalls,
		"failed injection must deterministically release every prepared handle")
}

func TestTraceAttacherJavaDisabledKeepsInjectorInterfaceNil(t *testing.T) {
	originalRemoveMemlock := removeMemlock
	removeMemlock = func() error { return nil }
	t.Cleanup(func() { removeMemlock = originalRemoveMemlock })

	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()
	instrumentables := msg.NewQueue[[]Event[ebpf.Instrumentable]](msg.ChannelBufferLen(1))
	tracerEvents := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(1))
	attacher := &traceAttacher{
		Cfg:                  &obi.Config{},
		Metrics:              imetrics.NoopReporter{},
		InputInstrumentables: instrumentables,
		OutputTracerEvents:   tracerEvents,
		EbpfEventContext:     &ebpfcommon.EBPFEventContext{},
	}
	run, err := attacher.attacherLoop(ctx)
	require.NoError(t, err)
	require.Nil(t, attacher.javaInjector)

	done := make(chan struct{})
	go func() {
		defer close(done)
		run(ctx)
	}()
	instrumentables.Send([]Event[ebpf.Instrumentable]{{
		Type: EventCreated,
		Obj: ebpf.Instrumentable{
			Type: svc.InstrumentableJava,
			FileInfo: execpkg.New(execpkg.Init{
				CmdExePath: "/usr/bin/java",
				Pid:        9_999_991,
				Ino:        1234,
			}),
		},
	}})
	instrumentables.Close()

	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("trace attacher did not stop after the Java-disabled input closed")
	}
}

func TestRejectedExactAdmissionRollsBackJavaMetadataAndHasNoSideEffects(t *testing.T) {
	originalRemoveMemlock := removeMemlock
	removeMemlock = func() error { return nil }
	t.Cleanup(func() { removeMemlock = originalRemoveMemlock })

	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()
	instrumentables := msg.NewQueue[[]Event[ebpf.Instrumentable]](msg.ChannelBufferLen(1))
	tracerEvents := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(1))
	events := tracerEvents.Subscribe()
	attacher := &traceAttacher{
		Cfg:                  &obi.Config{},
		Metrics:              imetrics.NoopReporter{},
		InputInstrumentables: instrumentables,
		OutputTracerEvents:   tracerEvents,
		EbpfEventContext:     &ebpfcommon.EBPFEventContext{},
		validateMetadataOwnerFn: func(app.PID, *execpkg.FileInfo) error {
			return nil
		},
		readJavaServiceMetadataFn: func(app.PID, svc.Attrs) (jvmtools.ServiceMetadata, error) {
			return jvmtools.ServiceMetadata{Name: "provisional-orders", Version: "9.9.9"}, nil
		},
	}
	run, err := attacher.attacherLoop(ctx)
	require.NoError(t, err)
	const ino = uint64(9876)
	owner := execpkg.New(execpkg.Init{
		Pid: 42,
		Ino: ino,
		Service: svc.Attrs{
			UID:      svc.UID{Namespace: "production", Instance: "stable"},
			Metadata: map[attr.Name]string{"existing": "preserved"},
		},
		CmdExePath: "/bin/rejected",
	})
	beforeService := owner.ServiceAttrs()
	program := &recordingTracer{allow: func(app.PID, uint32, *execpkg.FileInfo, *execpkg.FileInfo) bool {
		return false
	}}
	attacher.existingTracers[owner.ID()] = executableTracer{
		tracer:     &ebpf.ProcessTracer{Type: ebpf.Go, Programs: []ebpf.Tracer{program}},
		generation: 1,
	}
	nodeInjector := &recordingNodeInjector{}
	attacher.nodeInjector = nodeInjector
	done := make(chan struct{})
	go func() {
		defer close(done)
		run(ctx)
	}()

	instrumentables.Send([]Event[ebpf.Instrumentable]{
		{
			Type: EventCreated,
			Obj: ebpf.Instrumentable{
				Type:     svc.InstrumentableJava,
				FileInfo: owner,
				PIDOwner: owner,
			},
		},
	})
	instrumentables.Close()
	testutil.ReadChannel(t, done, testTimeout)

	require.Len(t, program.allowed, 1)
	assert.Zero(t, nodeInjector.calls)
	require.NotContains(t, attacher.processInstances, execpkg.FileID{Ino: ino})
	assert.Empty(t, attacher.admittedProcessInstances)
	rolledBack := owner.ServiceAttrs()
	assert.Equal(t, beforeService.UID, rolledBack.UID)
	assert.Equal(t, beforeService.Metadata, rolledBack.Metadata)
	assert.Equal(t, svc.InstrumentableJava, rolledBack.SDKLanguage,
		"field-scoped rollback must preserve getTracer's unrelated SDK update")
	assert.False(t, owner.AutoName())
	retryReceipt := owner.BeginServiceMetadataAdmission(
		"retry", jvmtools.ServiceVersionAttribute, "2.0",
	)
	require.NotNil(t, retryReceipt, "rejected admission leaked provisional field ownership")
	retryReceipt.Rollback()
	if event, ok := <-events; ok {
		t.Fatalf("unexpected tracer event after rejected exact admission: %+v", event)
	}
}

func TestJavaAttachmentDeletionCancelsWithoutBlockingDiscovery(t *testing.T) {
	release := make(chan struct{})
	injector := &controlledJavaInjector{
		calls:        make(chan context.Context, 1),
		firstRelease: release,
	}
	attacher := &traceAttacher{
		javaInjector: injector,
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Metrics:      imetrics.NoopReporter{},
	}
	fileInfo := execpkg.New(execpkg.Init{Pid: 42})
	instrumentable := &ebpf.Instrumentable{
		FileInfo: fileInfo,
		Type:     svc.InstrumentableJava,
	}

	prepared, err := injector.PrepareExecutable(instrumentable)
	require.NoError(t, err)
	controlledPrepared := prepared.(*controlledJavaPrepared)
	attacher.startJavaAttachment(t.Context(), instrumentable, prepared)
	attachCtx := <-injector.calls
	attacher.stopJavaAttachment(fileInfo)

	select {
	case <-attachCtx.Done():
	default:
		t.Fatal("process deletion did not cancel the Java attachment")
	}
	close(release)
	attacher.stopJavaAttachments()
	assert.Equal(t, uint32(1), controlledPrepared.closeCount.Load())
}

func TestJavaAttachmentReplacementSerializesOutsideDiscoveryLoop(t *testing.T) {
	release := make(chan struct{})
	injector := &controlledJavaInjector{
		calls:        make(chan context.Context, 2),
		firstRelease: release,
	}
	attacher := &traceAttacher{
		javaInjector: injector,
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		Metrics:      imetrics.NoopReporter{},
	}
	fileInfo := execpkg.New(execpkg.Init{Pid: 42})
	instrumentable := &ebpf.Instrumentable{
		FileInfo: fileInfo,
		Type:     svc.InstrumentableJava,
	}

	firstPrepared, err := injector.PrepareExecutable(instrumentable)
	require.NoError(t, err)
	firstControlled := firstPrepared.(*controlledJavaPrepared)
	attacher.startJavaAttachment(t.Context(), instrumentable, firstPrepared)
	firstCtx := <-injector.calls
	secondPrepared, err := injector.PrepareExecutable(instrumentable)
	require.NoError(t, err)
	secondControlled := secondPrepared.(*controlledJavaPrepared)
	attacher.startJavaAttachment(t.Context(), instrumentable, secondPrepared)

	select {
	case <-firstCtx.Done():
	default:
		t.Fatal("replacement did not cancel the preceding Java attachment")
	}
	select {
	case <-injector.calls:
		t.Fatal("replacement ran before the preceding attachment exited")
	default:
	}

	close(release)
	secondCtx := <-injector.calls
	attacher.stopJavaAttachment(fileInfo)
	<-secondCtx.Done()
	attacher.stopJavaAttachments()
	assert.Equal(t, uint32(1), firstControlled.closeCount.Load())
	assert.Equal(t, uint32(1), secondControlled.closeCount.Load())
}

func TestExecutableKeySeparatesFilesystems(t *testing.T) {
	first := execpkg.New(execpkg.Init{Dev: 1, Ino: 42})
	second := execpkg.New(execpkg.Init{Dev: 2, Ino: 42})
	firstKey := executableKey(first)
	secondKey := executableKey(second)

	assert.NotEqual(t, firstKey, secondKey)

	tracers := map[ebpf.ExecutableKey]executableTracer{
		firstKey:  {tracer: &ebpf.ProcessTracer{Type: ebpf.Go}},
		secondKey: {tracer: &ebpf.ProcessTracer{Type: ebpf.Generic}},
	}
	require.Len(t, tracers, 2)
	assert.Equal(t, ebpf.Go, tracers[firstKey].tracer.Type)
	assert.Equal(t, ebpf.Generic, tracers[secondKey].tracer.Type)
}

func TestSyntheticDeletePath_TraceAttacherDeletesTracer(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	origRemoveMemlock := removeMemlock
	removeMemlock = func() error { return nil }
	defer func() { removeMemlock = origRemoveMemlock }()

	processMatches := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	instrumentables := msg.NewQueue[[]Event[ebpf.Instrumentable]](msg.ChannelBufferLen(10))
	tracerEventsQu := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(10))
	tracerEvents := tracerEventsQu.Subscribe()

	fileInfo := execpkg.New(execpkg.Init{
		Service:    svc.Attrs{UID: svc.UID{Name: "dyn-svc", Namespace: "ns"}},
		CmdExePath: "/bin/test",
		Pid:        42,
		Ino:        1234,
		Ns:         17,
	})
	startDeletedTyperPipeline(ctx, &typer{
		currentPids: map[app.PID]*execpkg.FileInfo{42: fileInfo},
	}, processMatches, instrumentables)

	ta := &traceAttacher{
		Cfg:                  &obi.Config{},
		Metrics:              imetrics.NoopReporter{},
		InputInstrumentables: instrumentables,
		OutputTracerEvents:   tracerEventsQu,
		EbpfEventContext:     &ebpfcommon.EBPFEventContext{},
	}
	run, err := ta.attacherLoop(ctx)
	require.NoError(t, err)

	prog := &recordingTracer{}
	tracer := &ebpf.ProcessTracer{Type: ebpf.Generic, Programs: []ebpf.Tracer{prog}}
	key := executableKey(fileInfo)
	ta.existingTracers[key] = executableTracer{tracer: tracer, generation: 1}
	recordTestProcessInstance(ta, key, fileInfo)

	go run(ctx)

	processMatches.Send([]Event[ProcessMatch]{{
		Type: EventDeleted,
		Obj: ProcessMatch{
			Process: &services.ProcessInfo{Pid: 42},
		},
	}})

	ev := testutil.ReadChannel(t, tracerEvents, testTimeout)
	require.Equal(t, EventDeleted, ev.Type)
	require.NotNil(t, ev.Obj)
	assert.Equal(t, app.PID(42), ev.Obj.FileInfo.Pid())
	assert.Same(t, tracer, ev.Obj.Tracer)
	assert.Equal(t, uint64(1), ev.Obj.ExecutableGeneration)
	assert.Equal(t, []blockedPID{{pid: 42, ns: 17}}, prog.blocked)
	require.Len(t, prog.blockedFiles, 1)
	assert.Same(t, fileInfo, prog.blockedFiles[0])
	_, exists := ta.existingTracers[key]
	assert.False(t, exists)
}

func TestTraceAttacherSeparatesSameInodeOnDifferentDevices(t *testing.T) {
	firstInfo := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/first", Pid: 41, Dev: 1, Ino: 1234, Ns: 17,
	})
	secondInfo := execpkg.New(execpkg.Init{
		CmdExePath: "/bin/second", Pid: 42, Dev: 2, Ino: 1234, Ns: 17,
	})
	firstProgram := &recordingTracer{}
	secondProgram := &recordingTracer{}
	firstTracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{firstProgram}}
	secondTracer := &ebpf.ProcessTracer{Programs: []ebpf.Tracer{secondProgram}}
	attacher := &traceAttacher{
		log:     slog.With("component", t.Name()),
		Metrics: imetrics.NoopReporter{},
		existingTracers: map[execpkg.FileID]executableTracer{
			firstInfo.ID():  {tracer: firstTracer, generation: 1},
			secondInfo.ID(): {tracer: secondTracer, generation: 1},
		},
		processInstances:   maps.MultiCounter[execpkg.FileID]{},
		OutputTracerEvents: msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(2)),
	}
	recordTestProcessInstance(attacher, firstInfo.ID(), firstInfo)
	recordTestProcessInstance(attacher, secondInfo.ID(), secondInfo)

	attacher.notifyProcessDeletion(&ebpf.Instrumentable{FileInfo: firstInfo})

	assert.NotContains(t, attacher.existingTracers, firstInfo.ID())
	assert.Same(t, secondTracer, attacher.existingTracers[secondInfo.ID()].tracer)
	assert.Equal(t, []blockedPID{{pid: firstInfo.Pid(), ns: firstInfo.Ns()}}, firstProgram.blocked)
	assert.Empty(t, secondProgram.blocked)
}

func TestSyntheticDeletePath_TraceAttacherDeletesInstance(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	origRemoveMemlock := removeMemlock
	removeMemlock = func() error { return nil }
	defer func() { removeMemlock = origRemoveMemlock }()

	processMatches := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	instrumentables := msg.NewQueue[[]Event[ebpf.Instrumentable]](msg.ChannelBufferLen(10))
	tracerEventsQu := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(10))
	tracerEvents := tracerEventsQu.Subscribe()

	fileInfo := execpkg.New(execpkg.Init{
		Service:    svc.Attrs{UID: svc.UID{Name: "dyn-svc", Namespace: "ns"}},
		CmdExePath: "/bin/test",
		Pid:        42,
		Ino:        1234,
		Ns:         17,
	})
	startDeletedTyperPipeline(ctx, &typer{
		currentPids: map[app.PID]*execpkg.FileInfo{42: fileInfo},
	}, processMatches, instrumentables)

	ta := &traceAttacher{
		Cfg:                  &obi.Config{},
		Metrics:              imetrics.NoopReporter{},
		InputInstrumentables: instrumentables,
		OutputTracerEvents:   tracerEventsQu,
		EbpfEventContext:     &ebpfcommon.EBPFEventContext{},
	}
	run, err := ta.attacherLoop(ctx)
	require.NoError(t, err)

	prog := &recordingTracer{}
	tracer := &ebpf.ProcessTracer{Type: ebpf.Generic, Programs: []ebpf.Tracer{prog}}
	key := executableKey(fileInfo)
	ta.existingTracers[key] = executableTracer{tracer: tracer, generation: 1}
	secondFileInfo := execpkg.New(execpkg.Init{
		Service:    svc.Attrs{UID: svc.UID{Name: "dyn-svc", Namespace: "ns"}},
		CmdExePath: "/bin/test",
		Pid:        43,
		Ino:        1234,
		Ns:         17,
	})
	recordTestProcessInstance(ta, key, fileInfo)
	recordTestProcessInstance(ta, key, secondFileInfo)

	go run(ctx)

	processMatches.Send([]Event[ProcessMatch]{{
		Type: EventDeleted,
		Obj: ProcessMatch{
			Process: &services.ProcessInfo{Pid: 42},
		},
	}})

	ev := testutil.ReadChannel(t, tracerEvents, testTimeout)
	require.Equal(t, EventInstanceDeleted, ev.Type)
	require.NotNil(t, ev.Obj)
	assert.Equal(t, app.PID(42), ev.Obj.FileInfo.Pid())
	assert.Nil(t, ev.Obj.Tracer)
	assert.Equal(t, []blockedPID{{pid: 42, ns: 17}}, prog.blocked)
	require.Len(t, prog.blockedFiles, 1)
	assert.Same(t, fileInfo, prog.blockedFiles[0])
	assert.Same(t, tracer, ta.existingTracers[key].tracer)
}

func TestParentSubstitutedChildDeleteUsesAdmissionOwner(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	origRemoveMemlock := removeMemlock
	removeMemlock = func() error { return nil }
	defer func() { removeMemlock = origRemoveMemlock }()

	processMatches := msg.NewQueue[[]Event[ProcessMatch]](msg.ChannelBufferLen(10))
	instrumentables := msg.NewQueue[[]Event[ebpf.Instrumentable]](msg.ChannelBufferLen(10))
	tracerEventsQu := msg.NewQueue[Event[*ebpf.Instrumentable]](msg.ChannelBufferLen(10))
	tracerEvents := tracerEventsQu.Subscribe()

	const (
		parentPID = app.PID(51)
		childPID  = app.PID(52)
	)
	parent := execpkg.New(execpkg.Init{
		Service: svc.Attrs{
			UID:                svc.UID{Name: "parent-svc", Namespace: "ns"},
			DynamicSelectorPID: parentPID,
		},
		CmdExePath: "/bin/test",
		Pid:        parentPID,
		Ino:        1235,
		Ns:         17,
	})
	child := execpkg.New(execpkg.Init{
		Service:    svc.Attrs{UID: svc.UID{Name: "parent-svc", Namespace: "ns"}},
		CmdExePath: "/bin/test",
		Pid:        childPID,
		Ppid:       parentPID,
		Ino:        1235,
		Ns:         17,
	})
	startDeletedTyperPipeline(ctx, &typer{
		currentPids:  map[app.PID]*execpkg.FileInfo{childPID: child},
		pidOwners:    map[app.PID]*execpkg.FileInfo{childPID: child},
		tracerOwners: map[app.PID]*execpkg.FileInfo{childPID: parent},
	}, processMatches, instrumentables)

	selector := NewDynamicPIDSelector()
	selector.RegisterFileInfo(parentPID, parent, parent)
	selector.RegisterFileInfo(childPID, parent, child)
	ta := &traceAttacher{
		Cfg:                  &obi.Config{},
		Metrics:              imetrics.NoopReporter{},
		InputInstrumentables: instrumentables,
		OutputTracerEvents:   tracerEventsQu,
		EbpfEventContext:     &ebpfcommon.EBPFEventContext{},
		DynamicPIDSelector:   selector,
	}
	run, err := ta.attacherLoop(ctx)
	require.NoError(t, err)

	prog := &recordingTracer{}
	tracer := &ebpf.ProcessTracer{Type: ebpf.Generic, Programs: []ebpf.Tracer{prog}}
	ta.existingTracers[parent.ID()] = executableTracer{tracer: tracer, generation: 1}
	recordTestProcessInstance(ta, parent.ID(), child)
	go run(ctx)

	processMatches.Send([]Event[ProcessMatch]{
		{
			Type: EventDeleted,
			Obj:  ProcessMatch{Process: &services.ProcessInfo{Pid: childPID}},
		},
	})

	ev := testutil.ReadChannel(t, tracerEvents, testTimeout)
	require.Equal(t, EventDeleted, ev.Type)
	require.Same(t, child, ev.Obj.FileInfo)
	require.Same(t, child, ev.Obj.PIDOwnerFileInfo())
	require.Same(t, parent, ev.Obj.TracerOwnerFileInfo())
	assert.Equal(t, []blockedPID{{pid: childPID, ns: 17}}, prog.blocked)
	require.Len(t, prog.blockedFiles, 1)
	assert.Same(t, child, prog.blockedFiles[0])
	require.Len(t, prog.blockedServices, 1)
	assert.Same(t, parent, prog.blockedServices[0])
	assert.NotContains(t, selector.fileInfoByPID, childPID)
	assert.Same(t, parent, selector.fileInfoByPID[parentPID],
		"child deletion must preserve the live dynamic selector owner")
	_, exists := ta.existingTracers[parent.ID()]
	assert.False(t, exists)
}

func startDeletedTyperPipeline(
	ctx context.Context,
	tp *typer,
	input *msg.Queue[[]Event[ProcessMatch]],
	output *msg.Queue[[]Event[ebpf.Instrumentable]],
) {
	in := input.Subscribe(msg.SubscriberName("testExecTyper"))
	go func() {
		defer output.Close()
		for {
			select {
			case <-ctx.Done():
				return
			case evs, ok := <-in:
				if !ok {
					return
				}
				if out := tp.FilterClassify(evs); len(out) > 0 {
					output.Send(out)
				}
			}
		}
	}()
}
