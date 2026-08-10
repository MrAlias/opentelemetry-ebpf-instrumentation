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

	// keeps a copy of all the tracers for a given executable identity
	existingTracers     map[discexec.FileID]*ebpf.ProcessTracer
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
}

type javaAttachOperation struct {
	cancel context.CancelFunc
	done   chan struct{}
}

type javaExecutableInjector interface {
	PrepareExecutable(*ebpf.Instrumentable) (javaagent.PreparedExecutable, error)
}

type nodeExecutableInjector interface {
	NewExecutable(*ebpf.Instrumentable)
}

func traceAttacherProvider(ta *traceAttacher) swarm.InstanceFunc {
	return ta.attacherLoop
}

func (ta *traceAttacher) attacherLoop(_ context.Context) (swarm.RunFunc, error) {
	ta.log = slog.With("component", "discover.traceAttacher")
	ta.existingTracers = map[discexec.FileID]*ebpf.ProcessTracer{}
	ta.nodeInjector = nodejs.NewNodeInjector(ta.Cfg)
	javaInjector, err := javaagent.NewJavaInjector(ta.Cfg)
	if err != nil {
		ta.log.Warn("unable to inject OBI java agent, Java TLS telemetry generation will not work", "error", err)
	} else if javaInjector != nil {
		ta.javaInjector = javaInjector
	}
	ta.processInstances = maps.MultiCounter[discexec.FileID]{}
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
					if len(ta.admissiblePIDs(&instr.Obj)) == 0 {
						ta.log.Debug("no live exact process lifetime remains for created event",
							"pid", instr.Obj.FileInfo.Pid())
						if instr.Obj.FileInfo.ELF() != nil {
							_ = instr.Obj.FileInfo.ELF().Close()
						}
						continue
					}
					javaPrepared := ta.prepareProcessSpecificInjection(&instr.Obj)

					if ok := ta.getTracer(&instr.Obj); ok {
						ta.processInstances.Inc(instr.Obj.FileInfo.ID())
						if javaPrepared != nil {
							ta.startJavaAttachment(ctx, &instr.Obj, javaPrepared)
						}
						ta.OutputTracerEvents.Send(Event[*ebpf.Instrumentable]{Type: EventCreated, Obj: &instr.Obj})
					} else if javaPrepared != nil {
						if err := javaPrepared.Close(); err != nil {
							ta.log.Warn("unable to close rejected prepared Java target", "pid", instr.Obj.FileInfo.Pid(), "error", err)
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
	pid := ie.FileInfo.Pid()
	if err := ebpfcommon.ValidateProcessOwner(pid, ie.PIDOwnerFor(pid)); err != nil {
		if ta.log != nil {
			ta.log.Debug("process lifetime changed before process-specific injection",
				"pid", pid, "error", err)
		}
		return nil
	}
	if ta.nodeInjector != nil {
		ta.nodeInjector.NewExecutable(ie)
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

//nolint:cyclop
func (ta *traceAttacher) getTracer(ie *ebpf.Instrumentable) bool {
	if tracer, ok := ta.existingTracers[ie.FileInfo.ID()]; ok {
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
	case svc.InstrumentableNodejs, svc.InstrumentableJava, svc.InstrumentableJavaNative, svc.InstrumentableRuby, svc.InstrumentablePython, svc.InstrumentableDotnet, svc.InstrumentableGeneric, svc.InstrumentableRust, svc.InstrumentablePHP, svc.InstrumentableCPP:
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

	if !ta.activateNewTracer(tracer, exe, ie) {
		return false
	}

	ta.log.Debug("new executable for discovered process",
		"pid", ie.FileInfo.Pid(),
		"child", ie.ChildPids,
		"cmd", ie.FileInfo.CmdExePath(),
		"type", ie.Type)
	// allowing the tracer to forward traces from the discovered PID and its children processes
	ta.monitorPIDs(tracer, ie)
	ta.existingTracers[ie.FileInfo.ID()] = tracer
	if tracer.Type == ebpf.Generic {
		if ta.reusableTracer != nil {
			ta.monitorPIDs(ta.reusableTracer, ie)
		} else {
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
	if tracer.Type == ebpf.Generic {
		// Generic tracers instrument shared libraries. A second process using the
		// same executable can have a different module set, so attach those probes
		// before publishing any PID admission for this process lifetime.
		if !ta.updateTracerProbes(tracer, ie) {
			ta.log.Debug(".done", "success", false)
			return false
		}
	}

	// PID admission is the commit point: no tracer sees this process until every
	// required process-specific probe has attached successfully.
	ta.monitorPIDs(tracer, ie)
	if tracer.Type != ebpf.Generic {
		ta.monitorPIDs(ta.reusableGoTracer, ie)
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
	if err := ta.newExecutable(tracer, exe, ie); err != nil {
		ta.log.Debug("failed to attach process-specific probes for new tracer",
			"pid", ie.FileInfo.Pid(), "error", err)
		ta.Metrics.InstrumentationError(
			ie.FileInfo.ExecutableName(),
			imetrics.InstrumentationErrorAttachingUprobe,
		)
		if abortErr := ta.abortProcessTracer(tracer); abortErr != nil {
			ta.log.Warn("couldn't fully abort rejected process tracer", "error", abortErr)
		}
		return false
	}

	// Common tracer selection and downstream Run ownership become durable only
	// after the executable-specific attach transaction commits.
	ta.dropUnloadedTracers(tracer.Programs)
	ie.Tracer = tracer
	return true
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

func (ta *traceAttacher) newExecutable(
	tracer *ebpf.ProcessTracer,
	exe *link.Executable,
	ie *ebpf.Instrumentable,
) error {
	if ta.newExecutableFn != nil {
		return ta.newExecutableFn(tracer, exe, ie)
	}
	return tracer.NewExecutable(exe, ie)
}

func (ta *traceAttacher) newExecutableInstance(
	tracer *ebpf.ProcessTracer,
	ie *ebpf.Instrumentable,
) error {
	if ta.newExecutableInstanceFn != nil {
		return ta.newExecutableInstanceFn(tracer, ie)
	}
	return tracer.NewExecutableInstance(ie)
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

	if err := ta.newExecutable(tracer, exe, ie); err != nil {
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

	ta.monitorPIDs(tracer, ie)
	ta.existingTracers[ie.FileInfo.ID()] = tracer
	ta.Metrics.InstrumentProcess(ie.FileInfo.ExecutableName())

	return true
}

func (ta *traceAttacher) updateTracerProbes(tracer *ebpf.ProcessTracer, ie *ebpf.Instrumentable) bool {
	if err := ta.newExecutableInstance(tracer, ie); err != nil {
		ta.log.Debug("Failed to attach uprobes", "pid", ie.FileInfo.Pid(), "error", err)
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

	return true
}

func (ta *traceAttacher) monitorPIDs(tracer *ebpf.ProcessTracer, ie *ebpf.Instrumentable) {
	ie.CopyToServiceAttributes()
	pids := ta.admissiblePIDs(ie)

	if ta.DynamicPIDSelector != nil {
		for _, process := range pids {
			ta.DynamicPIDSelector.RegisterFileInfo(process.pid, ie.FileInfo, process.owner)
		}
	}

	// allowing the tracer to forward traces from the discovered PID and its children processes
	for _, process := range pids {
		tracer.AllowPID(process.pid, process.ns, ie.FileInfo, process.owner)
	}

	for _, ct := range ta.commonTracers {
		for _, process := range pids {
			ct.AllowPID(process.pid, process.ns, ie.FileInfo, process.owner)
		}
	}

	if ta.SpanSignalsShortcut != nil {
		snap := ie.FileInfo.ServiceAttrs()
		spans := make([]request.Span, 0, len(pids))
		// the forwarded signal must include
		// - Service, which includes several metadata about the process
		// - PID namespace, to allow further kubernetes decoration
		for _, process := range pids {
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
	candidates := make([]app.PID, 0, len(ie.ChildPids)+1)
	candidates = append(candidates, ie.FileInfo.Pid())
	candidates = append(candidates, ie.ChildPids...)
	admissible := make([]admissiblePID, 0, len(candidates))
	for _, pid := range candidates {
		owner := ie.PIDOwnerFor(pid)
		if err := ebpfcommon.ValidateProcessOwner(pid, owner); err != nil {
			if ta.log != nil {
				ta.log.Debug("process lifetime changed before PID admission",
					"pid", pid, "error", err)
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
	if tracer, ok := ta.existingTracers[tracerOwner.ID()]; ok {
		ta.log.Info("process ended for already instrumented executable",
			"cmd", tracerOwner.CmdExePath(),
			"pid", deletedPID,
			"dev", tracerOwner.Dev(),
			"ino", tracerOwner.Ino(),
			"type", ie.Type,
			"service", tracerOwner.ServiceAttrs().UID.Name,
		)
		// notifying the tracer to block any trace from that PID
		// to avoid that a new process reusing this PID could send traces
		// unless explicitly allowed
		ta.Metrics.UninstrumentProcess(tracerOwner.ExecutableName())
		tracer.BlockPID(deletedPID, pidOwner.Ns(), tracerOwner, pidOwner)
		for _, ct := range ta.commonTracers {
			ct.BlockPID(deletedPID, pidOwner.Ns(), tracerOwner, pidOwner)
		}

		// if there are no more trace instances for a program, we need to notify that
		// the tracer needs to be stopped and deleted.
		// We don't remove kernel-based traces as there is only one tracer per host
		if ta.processInstances.Dec(tracerOwner.ID()) == 0 {
			delete(ta.existingTracers, tracerOwner.ID())
			ie.Tracer = tracer
			ta.OutputTracerEvents.Send(Event[*ebpf.Instrumentable]{Type: EventDeleted, Obj: ie})
		} else {
			ta.OutputTracerEvents.Send(Event[*ebpf.Instrumentable]{Type: EventInstanceDeleted, Obj: ie})
		}
	}
}

func (ta *traceAttacher) init() error {
	if err := removeMemlock(); err != nil {
		return fmt.Errorf("removing memory lock: %w", err)
	}
	return nil
}
