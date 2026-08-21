// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	discexec "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/helpers/maps"
	javaagent "go.opentelemetry.io/obi/pkg/internal/java"
	"go.opentelemetry.io/obi/pkg/internal/jvmtools"
	"go.opentelemetry.io/obi/pkg/internal/nodejs"
	"go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
	"go.opentelemetry.io/obi/pkg/runtimemetrics"
)

// Swappable in tests so attacher tests don't depend on memlock permissions.
var removeMemlock = rlimit.RemoveMemlock

// traceAttacher creates the available trace.Tracer implementations (Go HTTP tracer, GRPC tracer, Generic tracer...)
// for each received Instrumentable process and forwards an ebpf.ProcessTracer instance ready to run and start
// instrumenting the executable
type traceAttacher struct {
	log     *slog.Logger
	Cfg     *obi.Config
	Metrics imetrics.Reporter

	// processInstances keeps track of the instances of each process. This will help making sure
	// that we don't remove the BPF resources of an executable until all their instances are removed
	// are stopped
	processInstances maps.MultiCounter[discexec.FileID]
	// admittedProcessInstances binds each exact discovery-event lifetime to the
	// successful creation event that incremented processInstances. A rejected
	// creation can still be followed by a deletion from the discovery pipeline;
	// without this receipt that deletion could retire an unrelated live instance
	// of the same executable. This map is owned by the single attacher loop.
	admittedProcessInstances map[*discexec.FileInfo]discexec.FileID

	// keeps a copy of all the tracers for a given executable identity
	existingTracers     map[discexec.FileID]executableTracer
	nodeInjector        nodeExecutableInjector
	javaInjector        javaExecutableInjector
	javaAttachMu        sync.Mutex
	javaAttachments     map[*discexec.FileInfo]*javaAttachOperation
	reusableTracer      *ebpf.ProcessTracer
	reusableGoTracer    *ebpf.ProcessTracer
	commonTracers       []ebpf.Tracer
	commonTracersLoaded bool

	// Usually, only ebpf.Tracer implementations will send spans data to the read decorator.
	// But on each new process, we will send a "process alive" span type to the read decorator, whose
	// unique purpose is to notify other parts of the system that this process is active, even
	// if no spans are detected. This would allow, for example, to start instrumenting this process
	// from the Process metrics pipeline even before it starts to do/receive requests.
	SpanSignalsShortcut *msg.Queue[[]request.Span]
	RuntimeMetrics      *msg.Queue[[]runtimemetrics.RuntimeMetricSnapshot]

	// InputInstrumentables is the input channel for the traceAttacher, where it receives information
	// about the instrumentables that traversed the whole process discovery pipeline, so they need to
	// be instrumented.
	InputInstrumentables *msg.Queue[[]Event[ebpf.Instrumentable]]

	// OutputTracerEvents communicates the process discovery pipeline with the instrumentation pipeline.
	// This queue will forward any newly discovered process to the instrumentation pipeline.
	OutputTracerEvents *msg.Queue[Event[*ebpf.Instrumentable]]

	// EbpfEventContext allows to set the common PID filter that's used to filter out events we don't need
	EbpfEventContext *ebpfcommon.EBPFEventContext

	// Extracts HTTP routes from executables
	routeHarvester *harvest.RouteHarvester

	// Is able to find process lifetime duration
	processAgeFunc func(app.PID) time.Duration

	DynamicPIDSelector *DynamicPIDSelector

	// Process-tracer operation seams keep lifecycle rollback paths deterministic
	// in tests. Production always uses the concrete ProcessTracer methods.
	loadExecutableFn        func(*ebpf.Instrumentable) (*link.Executable, bool)
	newExecutableFn         func(*ebpf.ProcessTracer, *link.Executable, *ebpf.Instrumentable) error
	newExecutableInstanceFn func(*ebpf.ProcessTracer, *ebpf.Instrumentable) error
	abortProcessTracerFn    func(*ebpf.ProcessTracer) error

	// Java service metadata seams let tests model PID reuse between each
	// exact-owner bracket without changing process-global jvmtools hooks.
	readJavaServiceMetadataFn func(app.PID, svc.Attrs) (jvmtools.ServiceMetadata, error)
	validateMetadataOwnerFn   func(app.PID, *discexec.FileInfo) error
}

type javaAttachOperation struct {
	cancel context.CancelFunc
	done   chan struct{}
}

type javaExecutableInjector interface {
	PrepareExecutable(*ebpf.Instrumentable) (javaagent.PreparedExecutable, error)
}

type nodeExecutableInjector interface {
	PrepareExecutable(*ebpf.Instrumentable) (nodejs.PreparedExecutable, error)
}

type executableTracer struct {
	tracer     *ebpf.ProcessTracer
	generation uint64
}

func executableKey(fileInfo *discexec.FileInfo) ebpf.ExecutableKey {
	return ebpf.ExecutableKey{Dev: fileInfo.Dev(), Ino: fileInfo.Ino()}
}

func traceAttacherProvider(ta *traceAttacher) swarm.InstanceFunc {
	return ta.attacherLoop
}

func (ta *traceAttacher) attacherLoop(_ context.Context) (swarm.RunFunc, error) {
	ta.log = slog.With("component", "discover.traceAttacher")
	ta.existingTracers = map[discexec.FileID]executableTracer{}
	ta.nodeInjector = nodejs.NewNodeInjector(ta.Cfg)
	javaInjector, err := javaagent.NewJavaInjector(ta.Cfg)
	if err != nil {
		ta.log.Warn("unable to inject OBI java agent, Java TLS telemetry generation will not work", "error", err)
	} else if javaInjector != nil {
		ta.javaInjector = javaInjector
	}
	ta.processInstances = maps.MultiCounter[discexec.FileID]{}
	ta.admittedProcessInstances = map[*discexec.FileInfo]discexec.FileID{}
	ta.javaAttachments = make(map[*discexec.FileInfo]*javaAttachOperation)
	ta.EbpfEventContext.CommonPIDsFilter = ebpfcommon.NewPIDsFilter(&ta.Cfg.Discovery, slog.With("component", "ebpfCommon.CommonPIDsFilter"), ta.Metrics)
	if ta.RuntimeMetrics != nil {
		ta.EbpfEventContext.RuntimeMetrics = runtimemetrics.NewQueueSender(ta.RuntimeMetrics)
	}
	ta.routeHarvester = harvest.NewRouteHarvester(&ta.Cfg.Discovery.RouteHarvestConfig, ta.Cfg.Discovery.DisabledRouteHarvesters, ta.Cfg.Discovery.RouteHarvesterTimeout)
	ta.processAgeFunc = ProcessAgeFunc()

	if err := ta.init(); err != nil {
		ta.log.Error("cant start process tracer. Stopping it", "error", err)
		return nil, err
	}

	in := ta.InputInstrumentables.Subscribe(msg.SubscriberName("traceAttacher"))
	return func(ctx context.Context) {
		defer ta.OutputTracerEvents.Close()
		defer ta.stopJavaAttachments()
		swarms.ForEachInput(ctx, in, ta.log.Debug, func(instrumentables []Event[ebpf.Instrumentable]) {
			for _, instr := range instrumentables {
				ta.log.Debug("Instrumentable", "created", instr.Type, "type", instr.Obj.Type,
					"exec", instr.Obj.FileInfo.CmdExePath(), "pid", instr.Obj.FileInfo.Pid())
				switch instr.Type {
				case EventCreated:
					eventOwner := instr.Obj.PIDOwnerFileInfo()
					if eventOwner == nil || ebpfcommon.ValidateProcessOwner(eventOwner.Pid(), eventOwner) != nil {
						ta.log.Debug("no live exact process lifetime remains for created event",
							"pid", instr.Obj.FileInfo.Pid())
						if instr.Obj.FileInfo.ELF() != nil {
							_ = instr.Obj.FileInfo.ELF().Close()
						}
						continue
					}
					metadataUpdate := ta.resolveServiceMetadata(&instr.Obj)
					javaPrepared := ta.prepareProcessSpecificInjection(&instr.Obj)

					if ok := ta.getTracer(&instr.Obj); ok {
						if metadataUpdate != nil {
							metadataUpdate.Commit()
						}
						ta.injectNodeAfterAdmission(&instr.Obj)
						ta.recordProcessInstance(
							instr.Obj.PIDOwnerFileInfo(), instr.Obj.FileInfo.ID(),
						)
						if javaPrepared != nil {
							ta.startJavaAttachment(ctx, &instr.Obj, javaPrepared)
						}
						ta.OutputTracerEvents.Send(Event[*ebpf.Instrumentable]{Type: EventCreated, Obj: &instr.Obj})
					} else {
						if metadataUpdate != nil {
							metadataUpdate.Rollback()
						}
						if javaPrepared != nil {
							if err := javaPrepared.Close(); err != nil {
								ta.log.Warn("unable to close rejected prepared Java target", "pid", instr.Obj.FileInfo.Pid(), "error", err)
							}
						}
					}

					if instr.Obj.FileInfo.ELF() != nil {
						_ = instr.Obj.FileInfo.ELF().Close()
					}
				case EventDeleted:
					ta.stopJavaAttachment(instr.Obj.FileInfo)
					ta.notifyProcessDeletion(&instr.Obj)
				}
			}
		})
	}, nil
}

func (ta *traceAttacher) prepareProcessSpecificInjection(
	ie *ebpf.Instrumentable,
) javaagent.PreparedExecutable {
	if ie == nil || ie.FileInfo == nil {
		return nil
	}
	eventOwner := ie.PIDOwnerFileInfo()
	if eventOwner == nil {
		return nil
	}
	pid := eventOwner.Pid()
	if err := ebpfcommon.ValidateProcessOwner(pid, eventOwner); err != nil {
		if ta.log != nil {
			ta.log.Debug("process lifetime changed before process-specific injection",
				"pid", pid, "error", err)
		}
		return nil
	}
	if ta.javaInjector == nil {
		return nil
	}
	prepared, err := ta.javaInjector.PrepareExecutable(ie)
	if err != nil {
		if ta.log != nil {
			ta.log.Warn("unable to prepare Java process authorization, Java TLS telemetry will not work",
				"pid", pid, "error", err)
		}
		return nil
	}
	return prepared
}

// injectNodeAfterAdmission prepares the process-specific capability only after
// the exact discovery-event owner has passed the tracer admission gate. The
// prepared operation owns independent proc, pidfd, netns, and executable
// handles, so retiring FileInfo after this call cannot redirect its work.
func (ta *traceAttacher) injectNodeAfterAdmission(ie *ebpf.Instrumentable) {
	if ta.nodeInjector == nil || ie == nil {
		return
	}
	prepared, err := ta.nodeInjector.PrepareExecutable(ie)
	if err != nil {
		if ta.log != nil {
			ta.log.Warn("unable to prepare exact Node.js injection target", "error", err)
		}
		return
	}
	if prepared == nil {
		return
	}
	defer func() {
		if err := prepared.Close(); err != nil && ta.log != nil {
			ta.log.Warn("unable to close exact Node.js injection target", "error", err)
		}
	}()
	if err := prepared.NewExecutable(); err != nil && ta.log != nil {
		ta.log.Warn("unable to inject Node.js agent into exact admitted target", "error", err)
	}
}

func (ta *traceAttacher) startJavaAttachment(
	parent context.Context,
	ie *ebpf.Instrumentable,
	prepared javaagent.PreparedExecutable,
) {
	if prepared == nil {
		return
	}
	if ie == nil || ie.FileInfo == nil {
		_ = prepared.Close()
		return
	}
	ctx, cancel := context.WithCancel(parent)
	operation := &javaAttachOperation{cancel: cancel, done: make(chan struct{})}
	ta.javaAttachMu.Lock()
	if ta.javaAttachments == nil {
		ta.javaAttachments = make(map[*discexec.FileInfo]*javaAttachOperation)
	}
	previous := ta.javaAttachments[ie.FileInfo]
	ta.javaAttachments[ie.FileInfo] = operation
	if previous != nil {
		previous.cancel()
	}
	go func() {
		defer func() {
			_ = prepared.Close()
			cancel()
			close(operation.done)
			ta.finishJavaAttachment(ie.FileInfo, operation)
		}()
		if previous != nil {
			select {
			case <-ctx.Done():
				<-previous.done
				return
			case <-previous.done:
			}
		}
		if ctx.Err() != nil {
			return
		}
		err := prepared.NewExecutableContext(ctx)
		if ctx.Err() == nil {
			ta.handleJavaAttachResult(ie, err)
		}
	}()
	ta.javaAttachMu.Unlock()
}

func (ta *traceAttacher) finishJavaAttachment(
	fi *discexec.FileInfo,
	operation *javaAttachOperation,
) {
	ta.javaAttachMu.Lock()
	if ta.javaAttachments[fi] == operation {
		delete(ta.javaAttachments, fi)
	}
	ta.javaAttachMu.Unlock()
}

func (ta *traceAttacher) stopJavaAttachment(fi *discexec.FileInfo) {
	if fi == nil {
		return
	}
	ta.javaAttachMu.Lock()
	operation := ta.javaAttachments[fi]
	if operation != nil {
		operation.cancel()
	}
	ta.javaAttachMu.Unlock()
}

func (ta *traceAttacher) stopJavaAttachments() {
	ta.javaAttachMu.Lock()
	operations := make([]*javaAttachOperation, 0, len(ta.javaAttachments))
	for fi, operation := range ta.javaAttachments {
		delete(ta.javaAttachments, fi)
		operations = append(operations, operation)
	}
	ta.javaAttachMu.Unlock()
	for _, operation := range operations {
		operation.cancel()
	}
	for _, operation := range operations {
		<-operation.done
	}
}

func (ta *traceAttacher) handleJavaAttachResult(ie *ebpf.Instrumentable, err error) {
	if err == nil {
		return
	}

	ta.Metrics.InstrumentationError(
		ie.FileInfo.ExecutableName(),
		imetrics.InstrumentationErrorAttachingJavaAgent,
	)
	ta.log.Warn(
		"unable to attach java agent to process, Java TLS telemetry will not work",
		"pid", ie.FileInfo.Pid(),
		"error", err,
	)
}

// resolveServiceMetadata reads Java launch metadata from the exact discovery
// event owner. FileInfo can be a substituted parent used as a shared
// tracer/service bucket; reading that parent's numeric /proc path here would
// inspect an unadmitted or reused process. Derived fields are instead applied
// provisionally to FileInfo and committed only after exact PID admission.
func (ta *traceAttacher) resolveServiceMetadata(
	ie *ebpf.Instrumentable,
) *discexec.ServiceMetadataAdmission {
	if ie == nil || ie.Type != svc.InstrumentableJava || ie.FileInfo == nil {
		return nil
	}
	eventOwner := ie.PIDOwnerFileInfo()
	if eventOwner == nil {
		return nil
	}
	pid := eventOwner.Pid()
	validate := ebpfcommon.ValidateProcessOwner
	if ta.validateMetadataOwnerFn != nil {
		validate = ta.validateMetadataOwnerFn
	}
	if err := validate(pid, eventOwner); err != nil {
		if ta.log != nil {
			ta.log.Debug("process lifetime changed before Java service metadata resolution",
				"pid", pid, "error", err)
		}
		return nil
	}

	// Missing-field policy belongs to the tracer/service owner, while launch
	// arguments and placeholder environment belong to the exact event owner.
	service := ie.FileInfo.ServiceAttrs()
	service.EnvVars = eventOwner.ServiceAttrs().EnvVars
	read := jvmtools.ReadServiceMetadata
	if ta.readJavaServiceMetadataFn != nil {
		read = ta.readJavaServiceMetadataFn
	}
	metadata, err := read(pid, service)
	if err != nil {
		if ta.log != nil {
			ta.log.Debug("unable to resolve Java service metadata", "pid", pid, "error", err)
		}
		return nil
	}
	if err := validate(pid, eventOwner); err != nil {
		if ta.log != nil {
			ta.log.Debug("process lifetime changed during Java service metadata resolution",
				"pid", pid, "error", err)
		}
		return nil
	}

	update := ie.FileInfo.BeginServiceMetadataAdmission(
		metadata.Name,
		jvmtools.ServiceVersionAttribute,
		metadata.Version,
	)
	if update == nil {
		return nil
	}
	// Bracket publication as well as the numeric reads. If the process exits
	// between resolution and provisional publication, roll back each field this
	// receipt still owns. Independent setters intentionally supersede ownership.
	if err := validate(pid, eventOwner); err != nil {
		update.Rollback()
		if ta.log != nil {
			ta.log.Debug("process lifetime changed before Java service metadata publication",
				"pid", pid, "error", err)
		}
		return nil
	}
	return update
}

//nolint:cyclop
func (ta *traceAttacher) getTracer(ie *ebpf.Instrumentable) bool {
	key := ie.FileInfo.ID()
	if existing, ok := ta.existingTracers[key]; ok {
		tracer := existing.tracer
		ta.log.Debug("new process for already instrumented executable",
			"pid", ie.FileInfo.Pid(),
			"child", ie.ChildPids,
			"cmd", ie.FileInfo.CmdExePath())
		ie.FileInfo.SetSDKLanguage(ie.Type)
		// Must be called after we've set the SDKLanguage
		ta.harvestRoutes(ie, true)

		return ta.activateExistingTracer(tracer, ie)
	}

	snap := ie.FileInfo.ServiceAttrs()
	ta.log.Info("instrumenting process",
		"cmd", ie.FileInfo.CmdExePath(),
		"pid", ie.FileInfo.Pid(),
		"dev", ie.FileInfo.Dev(),
		"ino", ie.FileInfo.Ino(),
		"type", ie.Type,
		"service", snap.UID.Name,
		"logenricher", snap.LogEnricherEnabled,
	)

	// builds a tracer for that executable
	var programs []ebpf.Tracer
	tracerType := ebpf.Generic
	switch ie.Type {
	case svc.InstrumentableGolang:
		// gets all the possible supported tracers for a go program, and filters out
		// those whose symbols are not present in the ELF functions list
		if ta.Cfg.Discovery.SkipGoSpecificTracers || ie.InstrumentationError != nil || ie.Offsets == nil {
			if !ta.Cfg.Discovery.SkipGoSpecificTracers {
				if ie.InstrumentationError != nil {
					ta.log.Warn("Unsupported Go program detected, using generic instrumentation", "error", ie.InstrumentationError)
				} else if ie.Offsets == nil {
					ta.log.Warn("Go program with null offsets detected, using generic instrumentation")
				}
			}
			if ta.reusableTracer != nil {
				// We need to do more than monitor PIDs. It's possible that this new
				// instance of the executable has different DLLs loaded, e.g. libssl.so.
				return ta.reuseTracer(ta.reusableTracer, ie)
			} else {
				programs = ta.withCommonTracersGroup(newGenericTracersGroup(ta.EbpfEventContext.CommonPIDsFilter, ta.Cfg, ta.Metrics))
			}
		} else {
			if ta.reusableGoTracer != nil {
				return ta.reuseTracer(ta.reusableGoTracer, ie)
			}
			tracerType = ebpf.Go
			programs = ta.withCommonTracersGroup(newGoTracersGroup(
				ta.EbpfEventContext.CommonPIDsFilter,
				ta.Cfg,
				ta.Metrics,
			))
		}
	case svc.InstrumentableNodejs, svc.InstrumentableDeno, svc.InstrumentableJava, svc.InstrumentableJavaNative, svc.InstrumentableRuby, svc.InstrumentablePython, svc.InstrumentableDotnet, svc.InstrumentableGeneric, svc.InstrumentableRust, svc.InstrumentablePHP, svc.InstrumentableCPP:
		if ta.reusableTracer != nil {
			return ta.reuseTracer(ta.reusableTracer, ie)
		}
		programs = ta.withCommonTracersGroup(newGenericTracersGroup(ta.EbpfEventContext.CommonPIDsFilter, ta.Cfg, ta.Metrics))
	default:
		ta.log.Warn("unexpected instrumentable type. This is basically a bug", "type", ie.Type)
	}
	if len(programs) == 0 {
		ta.log.Warn("no instrumentable functions found. Ignoring", "pid", ie.FileInfo.Pid(), "cmd", ie.FileInfo.CmdExePath())
		ta.Metrics.InstrumentationError(ie.FileInfo.ExecutableName(), imetrics.InstrumentationErrorNoInstrumentableFunctionsFound)
		return false
	}

	ie.FileInfo.SetSDKLanguage(ie.Type)
	// Must be called after we've set the SDKLanguage
	ta.harvestRoutes(ie, false)

	// Instead of the executable file in the disk, we pass the /proc/<pid>/exec
	// to allow loading it from different container/pods in containerized environments
	exe, ok := ta.loadExecutable(ie)
	if !ok {
		ta.Metrics.InstrumentationError(ie.FileInfo.ExecutableName(), imetrics.InstrumentationErrorInspectionFailed)
		return false
	}

	tracer := ebpf.NewProcessTracer(tracerType, programs, ta.Cfg, ta.Metrics)

	if err := tracer.Init(ta.EbpfEventContext, ta.Cfg); err != nil {
		ta.log.Error("couldn't trace process. Stopping process tracer", "error", err)
		if abortErr := ta.abortProcessTracer(tracer); abortErr != nil {
			ta.log.Warn("couldn't fully abort failed process tracer", "error", abortErr)
		}
		ta.Metrics.InstrumentationError(ie.FileInfo.ExecutableName(), imetrics.InstrumentationErrorInspectionFailed)
		return false
	}

	finishExecutable, ok := ta.prepareNewTracerExecutable(tracer, exe, ie)
	if !ok {
		return false
	}

	ta.log.Debug("new executable for discovered process",
		"pid", ie.FileInfo.Pid(),
		"child", ie.ChildPids,
		"cmd", ie.FileInfo.CmdExePath(),
		"type", ie.Type)
	return ta.commitNewTracerAdmission(tracer, ie, key, finishExecutable)
}

func (ta *traceAttacher) commitNewTracerAdmission(
	tracer *ebpf.ProcessTracer,
	ie *ebpf.Instrumentable,
	key discexec.FileID,
	finishExecutable func(bool) error,
) bool {
	// Exact PID admission is the final commit point. Until it succeeds, the
	// ProcessTracer and common-tracer selection remain private to this attempt.
	additionalTracers := []*ebpf.ProcessTracer(nil)
	if tracer.Type == ebpf.Generic && ta.reusableTracer != nil {
		additionalTracers = append(additionalTracers, ta.reusableTracer)
	}
	if !ta.monitorPIDs(tracer, ie, additionalTracers...) {
		if err := finishExecutable(false); err != nil {
			ta.log.Warn("rolling back admission-rejected executable failed", "error", err)
		}
		if abortErr := ta.abortProcessTracer(tracer); abortErr != nil {
			ta.log.Warn("couldn't fully abort admission-rejected process tracer", "error", abortErr)
		}
		ie.Tracer = nil
		return false
	}
	_ = finishExecutable(true)
	ta.dropUnloadedTracers(tracer.Programs)
	ie.Tracer = tracer
	ta.existingTracers[key] = executableTracer{
		tracer:     tracer,
		generation: ie.ExecutableGeneration,
	}
	if tracer.Type == ebpf.Generic {
		if ta.reusableTracer == nil {
			ta.reusableTracer = tracer
		}
	} else {
		ta.reusableGoTracer = tracer
	}
	ta.Metrics.InstrumentProcess(ie.FileInfo.ExecutableName())
	ta.log.Debug(".done")
	return true
}

func (ta *traceAttacher) activateExistingTracer(
	tracer *ebpf.ProcessTracer,
	ie *ebpf.Instrumentable,
) bool {
	var finishProbes func(bool) error
	if tracer.Type == ebpf.Generic {
		// Generic tracers instrument shared libraries. A second process using the
		// same executable can have a different module set, so attach those probes
		// before publishing any PID admission for this process lifetime.
		var ok bool
		finishProbes, ok = ta.prepareTracerProbes(tracer, ie)
		if !ok {
			ta.log.Debug(".done", "success", false)
			return false
		}
	}

	// PID admission is the commit point: no tracer sees this process until every
	// required process-specific probe has attached successfully.
	additionalTracers := []*ebpf.ProcessTracer(nil)
	if tracer.Type != ebpf.Generic {
		additionalTracers = append(additionalTracers, ta.reusableGoTracer)
	}
	if !ta.monitorPIDs(tracer, ie, additionalTracers...) {
		if finishProbes != nil {
			if err := finishProbes(false); err != nil {
				ta.log.Warn("rolling back admission-rejected executable instance failed", "error", err)
			}
		}
		ta.log.Debug(".done", "success", false)
		return false
	}
	if finishProbes != nil {
		_ = finishProbes(true)
	}
	ta.Metrics.InstrumentProcess(ie.FileInfo.ExecutableName())
	ta.log.Debug(".done", "success", true)
	return true
}

func (ta *traceAttacher) activateNewTracer(
	tracer *ebpf.ProcessTracer,
	exe *link.Executable,
	ie *ebpf.Instrumentable,
) bool {
	finish, ok := ta.prepareNewTracerExecutable(tracer, exe, ie)
	if !ok {
		return false
	}
	_ = finish(true)
	return true
}

func (ta *traceAttacher) prepareNewTracerExecutable(
	tracer *ebpf.ProcessTracer,
	exe *link.Executable,
	ie *ebpf.Instrumentable,
) (func(bool) error, bool) {
	finish, err := ta.prepareExecutable(tracer, exe, ie)
	if err != nil {
		ta.log.Debug("failed to attach process-specific probes for new tracer",
			"pid", ie.FileInfo.Pid(), "error", err)
		ta.Metrics.InstrumentationError(
			ie.FileInfo.ExecutableName(),
			imetrics.InstrumentationErrorAttachingUprobe,
		)
		if abortErr := ta.abortProcessTracer(tracer); abortErr != nil {
			ta.log.Warn("couldn't fully abort rejected process tracer", "error", abortErr)
		}
		return nil, false
	}

	return finish, true
}

// dropUnloadedTracers keeps only the common tracers that survived ProcessTracer.Init in
// loadedPrograms, so PID notifications never reach a tracer without loaded BPF objects
func (ta *traceAttacher) dropUnloadedTracers(loadedPrograms []ebpf.Tracer) {
	if ta.commonTracersLoaded {
		return
	}
	ta.commonTracers = slices.DeleteFunc(ta.commonTracers, func(ct ebpf.Tracer) bool {
		return !slices.Contains(loadedPrograms, ct)
	})
	ta.commonTracersLoaded = true
}

func (ta *traceAttacher) withCommonTracersGroup(tracers []ebpf.Tracer) []ebpf.Tracer {
	if ta.commonTracersLoaded {
		return tracers
	}

	ta.commonTracers = newCommonTracersGroup(ta.Cfg, ta.Metrics, ta.EbpfEventContext.CommonPIDsFilter)

	// ProcessTracer.AllowPID treats Programs[0] as the exact admission owner;
	// common feature tracers must remain supplementary and therefore appended.
	return append(tracers, ta.commonTracers...)
}

func (ta *traceAttacher) harvestRoutesProcessor(ie *ebpf.Instrumentable, reused bool) {
	routes, err := ta.routeHarvester.HarvestRoutes(ie.FileInfo)
	if err != nil {
		ta.log.Info("encountered error harvesting routes", "error", err, "pid", ie.FileInfo.Pid(), "cmd", ie.FileInfo.CmdExePath())
	} else if routes != nil && len(routes.Routes) > 0 {
		ta.log.Debug("found routes in executable", "pid", ie.FileInfo.Pid(), "routes", routes, "reused", reused)
		m := harvest.RouteMatcherFromResult(*routes)
		ie.FileInfo.SetHarvestedRoutes(m)
	}
}

func (ta *traceAttacher) harvestRoutes(ie *ebpf.Instrumentable, reused bool) {
	if delay, delayTime := ta.routeHarvester.HarvestRoutesDelay(ie.FileInfo); delay {
		procAge := ta.processAgeFunc(ie.FileInfo.Pid())
		if procAge < delayTime {
			time.AfterFunc(delayTime-procAge, func() {
				// sanity check that the program is still up and running and it's the same command
				if exePath, ready := ExecutableReady(ie.FileInfo.Pid()); ready && exePath == ie.FileInfo.CmdExePath() {
					ta.harvestRoutesProcessor(ie, reused)
				}
			})

			return
		}
	}

	ta.harvestRoutesProcessor(ie, reused)
}

func (ta *traceAttacher) loadExecutable(ie *ebpf.Instrumentable) (*link.Executable, bool) {
	if ta.loadExecutableFn != nil {
		return ta.loadExecutableFn(ie)
	}

	// Instead of the executable file in the disk, we pass the /proc/<pid>/exec
	// to allow loading it from different container/pods in containerized environments
	exe, err := link.OpenExecutable(ie.FileInfo.ProExeLinkPath())
	if err != nil {
		ta.log.Debug("can't open executable. Ignoring",
			"error", err, "pid", ie.FileInfo.Pid(), "cmd", ie.FileInfo.CmdExePath())
		return nil, false
	}

	return exe, true
}

func (ta *traceAttacher) prepareExecutable(
	tracer *ebpf.ProcessTracer,
	exe *link.Executable,
	ie *ebpf.Instrumentable,
) (func(bool) error, error) {
	if ta.newExecutableFn != nil {
		if err := ta.newExecutableFn(tracer, exe, ie); err != nil {
			return nil, err
		}
		return func(bool) error { return nil }, nil
	}
	transaction, err := tracer.PrepareExecutable(exe, ie)
	if err != nil {
		return nil, err
	}
	return func(commit bool) error {
		if commit {
			transaction.Commit()
			return nil
		}
		return transaction.Rollback()
	}, nil
}

func (ta *traceAttacher) abortProcessTracer(tracer *ebpf.ProcessTracer) error {
	if ta.abortProcessTracerFn != nil {
		return ta.abortProcessTracerFn(tracer)
	}
	return tracer.Abort()
}

func (ta *traceAttacher) reuseTracer(tracer *ebpf.ProcessTracer, ie *ebpf.Instrumentable) bool {
	exe, ok := ta.loadExecutable(ie)
	if !ok {
		return false
	}

	finishExecutable, err := ta.prepareExecutable(tracer, exe, ie)
	if err != nil {
		ta.log.Debug("Failed to attach uprobes for new executable", "pid", ie.FileInfo.Pid(), "error", err)
		ta.Metrics.InstrumentationError(
			ie.FileInfo.ExecutableName(),
			imetrics.InstrumentationErrorAttachingUprobe,
		)
		return false
	}

	ta.log.Debug("reusing Generic tracer for",
		"pid", ie.FileInfo.Pid(),
		"child", ie.ChildPids,
		"cmd", ie.FileInfo.CmdExePath(),
		"language", ie.Type)

	if !ta.monitorPIDs(tracer, ie) {
		if rollbackErr := finishExecutable(false); rollbackErr != nil {
			ta.log.Warn("rolling back admission-rejected reusable executable failed", "error", rollbackErr)
		}
		return false
	}
	_ = finishExecutable(true)
	ta.existingTracers[ie.FileInfo.ID()] = executableTracer{
		tracer:     tracer,
		generation: ie.ExecutableGeneration,
	}
	ta.Metrics.InstrumentProcess(ie.FileInfo.ExecutableName())

	return true
}

func (ta *traceAttacher) prepareTracerProbes(
	tracer *ebpf.ProcessTracer,
	ie *ebpf.Instrumentable,
) (func(bool) error, bool) {
	var transaction ebpf.ExecutableInstanceTransaction
	var err error
	if ta.newExecutableInstanceFn != nil {
		err = ta.newExecutableInstanceFn(tracer, ie)
	} else {
		transaction, err = tracer.PrepareExecutableInstance(ie)
	}
	if err != nil {
		ta.log.Debug("Failed to attach uprobes", "pid", ie.FileInfo.Pid(), "error", err)
		ta.Metrics.InstrumentationError(
			ie.FileInfo.ExecutableName(),
			imetrics.InstrumentationErrorAttachingUprobe,
		)
		return nil, false
	}

	ta.log.Debug("reusing Generic tracer for",
		"pid", ie.FileInfo.Pid(),
		"child", ie.ChildPids,
		"cmd", ie.FileInfo.CmdExePath(),
		"language", ie.Type)

	return func(commit bool) error {
		if transaction == nil {
			return nil
		}
		if commit {
			transaction.Commit()
			return nil
		}
		return transaction.Rollback()
	}, true
}

func (ta *traceAttacher) updateTracerProbes(tracer *ebpf.ProcessTracer, ie *ebpf.Instrumentable) bool {
	finish, ok := ta.prepareTracerProbes(tracer, ie)
	if !ok {
		return false
	}
	_ = finish(true)
	return true
}

func (ta *traceAttacher) monitorPIDs(
	tracer *ebpf.ProcessTracer,
	ie *ebpf.Instrumentable,
	additionalTracers ...*ebpf.ProcessTracer,
) bool {
	ie.CopyToServiceAttributes()
	pids := ta.admissiblePIDs(ie)
	if len(pids) == 0 {
		return false
	}

	processTracers := make([]*ebpf.ProcessTracer, 0, len(additionalTracers)+1)
	seenProcessTracers := map[*ebpf.ProcessTracer]struct{}{}
	for _, candidate := range append([]*ebpf.ProcessTracer{tracer}, additionalTracers...) {
		if candidate == nil {
			continue
		}
		if _, seen := seenProcessTracers[candidate]; seen {
			continue
		}
		seenProcessTracers[candidate] = struct{}{}
		processTracers = append(processTracers, candidate)
	}

	programs := map[ebpf.Tracer]struct{}{}
	for _, processTracer := range processTracers {
		for _, program := range processTracer.Programs {
			programs[program] = struct{}{}
		}
	}
	commonTracers := make([]ebpf.Tracer, 0, len(ta.commonTracers))
	if ta.commonTracersLoaded {
		for _, commonTracer := range ta.commonTracers {
			if _, included := programs[commonTracer]; !included {
				commonTracers = append(commonTracers, commonTracer)
			}
		}
	}

	admitted := make([]admissiblePID, 0, len(pids))
	allow := func(process admissiblePID) bool {
		if len(processTracers) == 0 ||
			!processTracers[0].AllowPID(process.pid, process.ns, ie.FileInfo, process.owner) {
			return false
		}
		for _, processTracer := range processTracers[1:] {
			processTracer.AllowPID(process.pid, process.ns, ie.FileInfo, process.owner)
		}
		for _, commonTracer := range commonTracers {
			commonTracer.AllowPID(process.pid, process.ns, ie.FileInfo, process.owner)
		}
		admitted = append(admitted, process)
		return true
	}

	// admissiblePIDs always puts the exact discovery-event owner first. Do not
	// touch parent/child candidates until that owner has committed successfully:
	// BlockPID is owner-scoped, not reference-counted, so speculative ancillary
	// admissions could otherwise retire an independently live admission.
	if !allow(pids[0]) {
		return false
	}
	for _, process := range pids[1:] {
		allow(process)
	}

	if ta.DynamicPIDSelector != nil {
		for _, process := range admitted {
			ta.DynamicPIDSelector.RegisterFileInfo(process.pid, ie.FileInfo, process.owner)
		}
	}

	if ta.SpanSignalsShortcut != nil {
		snap := ie.FileInfo.ServiceAttrs()
		spans := make([]request.Span, 0, len(admitted))
		// the forwarded signal must include
		// - Service, which includes several metadata about the process
		// - PID namespace, to allow further kubernetes decoration
		for _, process := range admitted {
			service := snap
			service.ProcPID = process.pid
			spans = append(spans, request.Span{
				Type:    request.EventTypeProcessAlive,
				Service: service,
				Pid:     request.PidInfo{Namespace: process.ns},
			})
		}
		if len(spans) != 0 {
			ta.SpanSignalsShortcut.Send(spans)
		}
	}
	return true
}

type admissiblePID struct {
	pid   app.PID
	ns    uint32
	owner *discexec.FileInfo
}

func (ta *traceAttacher) admissiblePIDs(ie *ebpf.Instrumentable) []admissiblePID {
	if ie == nil || ie.FileInfo == nil {
		return nil
	}
	eventOwner := ie.PIDOwnerFileInfo()
	if eventOwner == nil {
		return nil
	}
	candidates := make([]app.PID, 0, len(ie.ChildPids)+2)
	candidates = append(candidates, eventOwner.Pid(), ie.FileInfo.Pid())
	candidates = append(candidates, ie.ChildPids...)
	admissible := make([]admissiblePID, 0, len(candidates))
	seen := map[app.PID]struct{}{}
	for _, pid := range candidates {
		if _, duplicate := seen[pid]; duplicate {
			continue
		}
		seen[pid] = struct{}{}
		owner := ie.PIDOwnerFor(pid)
		if pid == eventOwner.Pid() {
			owner = eventOwner
		}
		if err := ebpfcommon.ValidateProcessOwner(pid, owner); err != nil {
			if ta.log != nil {
				ta.log.Debug("process lifetime changed before PID admission",
					"pid", pid, "error", err)
			}
			if pid == eventOwner.Pid() {
				return nil
			}
			continue
		}
		admissible = append(admissible, admissiblePID{
			pid:   pid,
			ns:    owner.Ns(),
			owner: owner,
		})
	}
	return admissible
}

func (ta *traceAttacher) recordProcessInstance(
	owner *discexec.FileInfo,
	executable discexec.FileID,
) {
	if owner == nil {
		return
	}
	if ta.processInstances == nil {
		ta.processInstances = maps.MultiCounter[discexec.FileID]{}
	}
	if ta.admittedProcessInstances == nil {
		ta.admittedProcessInstances = map[*discexec.FileInfo]discexec.FileID{}
	}
	ta.admittedProcessInstances[owner] = executable
	ta.processInstances.Inc(executable)
}

func (ta *traceAttacher) takeProcessInstance(
	pidOwner *discexec.FileInfo,
	tracerOwner *discexec.FileInfo,
) (discexec.FileID, bool) {
	if pidOwner == nil || tracerOwner == nil {
		return discexec.FileID{}, false
	}
	executable, ok := ta.admittedProcessInstances[pidOwner]
	if !ok || executable != tracerOwner.ID() {
		return discexec.FileID{}, false
	}
	delete(ta.admittedProcessInstances, pidOwner)
	return executable, true
}

func (ta *traceAttacher) unregisterDynamicFileInfo(ie *ebpf.Instrumentable) {
	if ta.DynamicPIDSelector == nil {
		return
	}
	if pidOwner := ie.PIDOwnerFileInfo(); pidOwner != nil {
		ta.DynamicPIDSelector.UnregisterFileInfo(pidOwner.Pid(), pidOwner)
	}
	for _, pid := range ie.ChildPids {
		if owner := ie.PIDOwnerFor(pid); owner != nil {
			ta.DynamicPIDSelector.UnregisterFileInfo(pid, owner)
		}
	}
}

func (ta *traceAttacher) notifyProcessDeletion(ie *ebpf.Instrumentable) {
	ta.unregisterDynamicFileInfo(ie)
	pidOwner := ie.PIDOwnerFileInfo()
	if pidOwner == nil {
		return
	}
	tracerOwner := ie.TracerOwnerFileInfo()
	if tracerOwner == nil {
		return
	}
	deletedPID := pidOwner.Pid()
	key := tracerOwner.ID()
	if existing, ok := ta.existingTracers[key]; ok {
		tracer := existing.tracer
		// notifying the tracer to block any trace from that PID
		// to avoid that a new process reusing this PID could send traces
		// unless explicitly allowed
		tracer.BlockPID(deletedPID, pidOwner.Ns(), tracerOwner, pidOwner)
		for _, ct := range ta.commonTracers {
			ct.BlockPID(deletedPID, pidOwner.Ns(), tracerOwner, pidOwner)
		}
	}

	admittedKey, admitted := ta.takeProcessInstance(pidOwner, tracerOwner)
	if !admitted {
		return
	}
	if admittedKey != key {
		return
	}
	if existing, ok := ta.existingTracers[key]; ok {
		tracer := existing.tracer
		ie.ExecutableGeneration = existing.generation
		ta.log.Info("process ended for already instrumented executable",
			"cmd", tracerOwner.CmdExePath(),
			"pid", deletedPID,
			"dev", tracerOwner.Dev(),
			"ino", tracerOwner.Ino(),
			"type", ie.Type,
			"service", tracerOwner.ServiceAttrs().UID.Name,
		)
		ta.Metrics.UninstrumentProcess(tracerOwner.ExecutableName())

		// if there are no more trace instances for a program, we need to notify that
		// the tracer needs to be stopped and deleted.
		// We don't remove kernel-based traces as there is only one tracer per host
		if ta.processInstances.Dec(key) == 0 {
			delete(ta.existingTracers, key)
			ie.Tracer = tracer
			ta.OutputTracerEvents.Send(Event[*ebpf.Instrumentable]{Type: EventDeleted, Obj: ie})
		} else {
			ta.OutputTracerEvents.Send(Event[*ebpf.Instrumentable]{Type: EventInstanceDeleted, Obj: ie})
		}
	} else {
		ta.processInstances.Dec(key)
	}
}

func (ta *traceAttacher) init() error {
	if err := removeMemlock(); err != nil {
		return fmt.Errorf("removing memory lock: %w", err)
	}
	return nil
}
