// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"strings"

	lru "github.com/hashicorp/golang-lru/v2"

	"go.opentelemetry.io/otel/sdk/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/ebpf"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/gotracer"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/internal/transform/route/clusterurl"
	"go.opentelemetry.io/obi/pkg/kube"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
	"go.opentelemetry.io/obi/pkg/pipe/swarm"
	"go.opentelemetry.io/obi/pkg/pipe/swarm/swarms"
)

type cacheKey struct {
	Dev uint64
	Ino uint64
}

type instrumentedExecutable struct {
	Type                 svc.InstrumentableType
	Offsets              *goexec.Offsets
	InstrumentationError error
}

var currentProcessParentPID = liveProcessParentPID

// ExecTyperProvider classifies the discovered executables according to the
// executable type (Go, generic...), and filters these executables
// that are not instrumentable.
func ExecTyperProvider(
	cfg *obi.Config,
	metrics imetrics.Reporter,
	k8sInformer *kube.MetadataProvider,
	input *msg.Queue[[]Event[ProcessMatch]],
	output *msg.Queue[[]Event[ebpf.Instrumentable]],
) swarm.InstanceFunc {
	instrumentableCache, _ := lru.New[cacheKey, instrumentedExecutable](100)

	t := typer{
		cfg:                 cfg,
		metrics:             metrics,
		k8sInformer:         k8sInformer,
		log:                 slog.With("component", "discover.ExecTyper"),
		currentPids:         map[app.PID]*exec.FileInfo{},
		pidOwners:           map[app.PID]*exec.FileInfo{},
		tracerOwners:        map[app.PID]*exec.FileInfo{},
		processLifecycles:   map[uint64]processLifecycle{},
		instrumentableCache: instrumentableCache,
	}
	return func(_ context.Context) (swarm.RunFunc, error) {
		// TODO: do it per executable
		if !cfg.Discovery.SkipGoSpecificTracers {
			t.loadAllGoFunctionNames()
		}
		in := input.Subscribe(msg.SubscriberName("ExecTyper"))
		return func(ctx context.Context) {
			defer output.Close()
			defer t.closeProcessHandles()
			swarms.ForEachInput(ctx, in, t.log.Debug, func(i []Event[ProcessMatch]) {
				output.Send(t.FilterClassify(i))
			})
		}, nil
	}
}

func (t *typer) closeProcessHandles() {
	closed := map[*exec.FileInfo]struct{}{}
	for _, fi := range t.currentPids {
		closed[fi] = struct{}{}
		_ = fi.CloseProcessHandle()
	}
	for _, lifecycle := range t.processLifecycles {
		if _, ok := closed[lifecycle.fileInfo]; ok {
			continue
		}
		closed[lifecycle.fileInfo] = struct{}{}
		_ = lifecycle.fileInfo.CloseProcessHandle()
	}
}

func (t *typer) setCurrentPID(pid app.PID, fi *exec.FileInfo) {
	if previous := t.currentPids[pid]; previous != nil && previous != fi {
		_ = previous.CloseProcessHandle()
	}
	t.currentPids[pid] = fi
	delete(t.pidOwners, pid)
	delete(t.tracerOwners, pid)
	if instanceID := fi.ProcessInstanceID(); instanceID != 0 {
		if t.processLifecycles == nil {
			t.processLifecycles = map[uint64]processLifecycle{}
		}
		t.processLifecycles[instanceID] = processLifecycle{
			fileInfo:    fi,
			tracerOwner: fi,
		}
	}
}

func (t *typer) setPIDOwners(pid app.PID, owner, tracerOwner *exec.FileInfo) {
	if owner == nil {
		return
	}
	if tracerOwner == nil {
		tracerOwner = owner
	}
	if t.pidOwners == nil {
		t.pidOwners = map[app.PID]*exec.FileInfo{}
	}
	if t.tracerOwners == nil {
		t.tracerOwners = map[app.PID]*exec.FileInfo{}
	}
	t.pidOwners[pid] = owner
	t.tracerOwners[pid] = tracerOwner
	if instanceID := owner.ProcessInstanceID(); instanceID != 0 {
		if t.processLifecycles == nil {
			t.processLifecycles = map[uint64]processLifecycle{}
		}
		t.processLifecycles[instanceID] = processLifecycle{
			fileInfo:    owner,
			tracerOwner: tracerOwner,
		}
	}
}

type processLifecycle struct {
	fileInfo    *exec.FileInfo
	tracerOwner *exec.FileInfo
}

type typer struct {
	cfg         *obi.Config
	metrics     imetrics.Reporter
	k8sInformer *kube.MetadataProvider
	log         *slog.Logger
	currentPids map[app.PID]*exec.FileInfo
	// pidOwners records the FileInfo token used by monitorPIDs for each exact
	// discovered process. Parent substitution intentionally makes this differ
	// from currentPids[pid].
	pidOwners map[app.PID]*exec.FileInfo
	// tracerOwners records the executable tracer bucket independently from the
	// exact PID lifetime token in pidOwners.
	tracerOwners map[app.PID]*exec.FileInfo
	// processLifecycles retains exact identities across numeric PID reuse until
	// the corresponding deletion arrives. A stale deletion therefore cannot
	// retire the replacement's current PID entry.
	processLifecycles   map[uint64]processLifecycle
	allGoFunctions      []string
	instrumentableCache *lru.Cache[cacheKey, instrumentedExecutable]
}

func samplerFromConfig(s *services.SamplerConfig) trace.Sampler {
	if s != nil {
		return s.Implementation()
	}

	return nil
}

func (t *typer) makeServiceAttrs(processMatch *ProcessMatch) svc.Attrs {
	var name string
	var namespace string
	exportModes := services.ExportModeUnset
	var samplerConfig *services.SamplerConfig
	var routesConfig *services.CustomRoutesConfig
	svcFeatures := t.cfg.Metrics.Features
	var metadata map[attr.Name]string

	for _, s := range processMatch.Criteria {
		if n := s.GetName(); n != "" {
			name = n
		}

		if n := s.GetNamespace(); n != "" {
			namespace = n
		}

		if m := ResourceAttributesFromSelector(s); len(m) > 0 {
			if metadata == nil {
				metadata = make(map[attr.Name]string, len(m))
			}
			maps.Copy(metadata, m)
		}

		if m := s.GetExportModes(); m != services.ExportModeUnset {
			exportModes = m
		}

		if m := s.GetSamplerConfig(); m != nil {
			samplerConfig = m
		}

		if m := s.GetRoutesConfig(); m != nil {
			routesConfig = m
		}

		// if the matching service > instrument entry does not define features,
		// the globally defined features apply (and override any previous,
		// wider-scope match features)
		svcFeatures = s.MetricsConfig().Features
		if svcFeatures.Undefined() {
			svcFeatures = t.cfg.Metrics.Features
		}
	}

	routesCfg := t.cfg.Routes
	wildcard := byte('*')
	if routesCfg.WildcardChar != "" {
		wildcard = routesCfg.WildcardChar[0]
	}

	s := svc.Attrs{
		UID: svc.UID{
			Name:      name,
			Namespace: namespace,
		},
		Metadata:           metadata,
		ProcPID:            processMatch.Process.Pid,
		DynamicSelectorPID: processMatch.DynamicSelectorPID,
		ExportModes:        exportModes,
		Sampler:            samplerFromConfig(samplerConfig),
		PathTrie:           clusterurl.NewPathTrie(routesCfg.MaxPathSegmentCardinality, wildcard),
		Features:           svcFeatures,
		LogEnricherEnabled: processMatch.LogEnricherEnabled(),
	}

	if routesConfig != nil {
		s.SetCustomRoutes(routesConfig)
	}

	return s
}

// FilterClassify returns the Instrumentable types for each received ProcessMatch,
// and filters out the processes that can't be instrumented (e.g. because of the lack
// of instrumentation points)
func (t *typer) FilterClassify(evs []Event[ProcessMatch]) []Event[ebpf.Instrumentable] {
	var out []Event[ebpf.Instrumentable]

	elfs := make([]*exec.FileInfo, 0, len(evs))
	// Update first the PID map so we use only the parent processes
	// in case of multiple matches
	for i := range evs {
		ev := &evs[i]
		switch evs[i].Type {
		case EventCreated:
			svcID := t.makeServiceAttrs(&ev.Obj)

			if elfFile, err := findExecElf(ev.Obj.Process, &svcID); err != nil {
				t.log.Debug("error finding process ELF. Ignoring", "error", err)
			} else {
				t.setCurrentPID(ev.Obj.Process.Pid, elfFile)
				elfs = append(elfs, elfFile)
			}
		case EventDeleted:
			if deleted, ok := t.deletedInstrumentable(ev.Obj.Process); ok {
				out = append(out, Event[ebpf.Instrumentable]{
					Type: EventDeleted,
					Obj:  deleted,
				})
			}
		}
	}

	for i := range elfs {
		inst := t.classifyInstrumentable(elfs[i])
		t.log.Debug(
			"found an instrumentable process",
			"UID", inst.FileInfo.ServiceAttrs().UID,
			"type", inst.Type.String(),
			"exec", inst.FileInfo.CmdExePath(), "pid", inst.FileInfo.Pid())
		out = append(out, Event[ebpf.Instrumentable]{Type: EventCreated, Obj: inst})
	}
	return out
}

func (t *typer) classifyInstrumentable(discovered *exec.FileInfo) ebpf.Instrumentable {
	inst := t.asInstrumentable(discovered)
	inst.PIDOwners = make(map[app.PID]*exec.FileInfo, len(inst.ChildPids)+1)
	for _, pid := range append([]app.PID{inst.FileInfo.Pid()}, inst.ChildPids...) {
		owner := t.currentPids[pid]
		if owner == nil && pid == discovered.Pid() {
			owner = discovered
		}
		if owner == nil {
			continue
		}
		inst.PIDOwners[pid] = owner
		t.setPIDOwners(pid, owner, inst.FileInfo)
	}
	return inst
}

func (t *typer) deletedInstrumentable(process *services.ProcessInfo) (ebpf.Instrumentable, bool) {
	if process == nil {
		return ebpf.Instrumentable{}, false
	}
	pid := process.Pid
	var lifecycle processLifecycle
	if instanceID := process.ProcessInstanceID; instanceID != 0 {
		var ok bool
		lifecycle, ok = t.processLifecycles[instanceID]
		if !ok {
			current := t.currentPids[pid]
			if current == nil || current.ProcessInstanceID() != instanceID {
				return ebpf.Instrumentable{}, false
			}
			lifecycle = processLifecycle{
				fileInfo:    current,
				tracerOwner: t.tracerOwners[pid],
			}
		}
		delete(t.processLifecycles, instanceID)
	} else {
		lifecycle = processLifecycle{
			fileInfo:    t.currentPids[pid],
			tracerOwner: t.tracerOwners[pid],
		}
	}
	if lifecycle.fileInfo == nil {
		return ebpf.Instrumentable{}, false
	}
	if lifecycle.tracerOwner == nil {
		lifecycle.tracerOwner = lifecycle.fileInfo
	}

	if t.currentPids[pid] == lifecycle.fileInfo {
		delete(t.currentPids, pid)
		delete(t.pidOwners, pid)
		delete(t.tracerOwners, pid)
		if t.instrumentableCache != nil {
			t.instrumentableCache.Remove(cacheKey{
				Dev: lifecycle.fileInfo.Dev(),
				Ino: lifecycle.fileInfo.Ino(),
			})
		}
	}
	_ = lifecycle.fileInfo.CloseProcessHandle()

	return ebpf.Instrumentable{
		FileInfo:    lifecycle.fileInfo,
		PIDOwner:    lifecycle.fileInfo,
		TracerOwner: lifecycle.tracerOwner,
	}, true
}

// asInstrumentable classifies the type of executable (Go, generic...) and,
// in case of belonging to a forked process, returns its parent.
func (t *typer) asInstrumentable(execElf *exec.FileInfo) ebpf.Instrumentable {
	log := t.log.With("pid", execElf.Pid(), "comm", execElf.CmdExePath())
	if ic, ok := t.instrumentableCache.Get(cacheKey{Dev: execElf.Dev(), Ino: execElf.Ino()}); ok {
		log.Debug("new instance of existing executable", "type", ic.Type)
		var child []app.PID
		// A successful Go-offset classification intentionally instruments each
		// process directly. All generic/proxy classifications still need exact
		// parent selection even when their executable type came from the inode
		// cache.
		if ic.Offsets == nil || ic.InstrumentationError != nil {
			execElf, child = t.selectExecutableParent(execElf, log)
		}
		return ebpf.Instrumentable{
			Type:                 ic.Type,
			FileInfo:             execElf,
			ChildPids:            child,
			Offsets:              ic.Offsets,
			InstrumentationError: ic.InstrumentationError,
			LogEnricherEnabled:   execElf.LogEnricherEnabled(),
		}
	}

	log.Debug("getting instrumentable information")
	// look for suitable Go application first
	offsets, ok, err := t.inspectOffsets(execElf)
	if ok {
		// we found go offsets, let's see if this application is not a proxy
		if !isGoProxy(offsets) {
			log.Debug("identified as a Go service or client")
			t.instrumentableCache.Add(cacheKey{Dev: execElf.Dev(), Ino: execElf.Ino()}, instrumentedExecutable{Type: svc.InstrumentableGolang, Offsets: offsets})
			return ebpf.Instrumentable{Type: svc.InstrumentableGolang, FileInfo: execElf, Offsets: offsets}
		}

		if err == nil {
			err = errors.New("identified as a Go proxy")
		}

		log.Debug("identified as a Go proxy")
	} else {
		log.Debug("identified as a generic, non-Go executable")
	}

	execElf, child := t.selectExecutableParent(execElf, log)

	// Typer finds the executable type again. The language decorator can skip certain type detection,
	// for example, it will skip Linux system services. If the selection criteria brought us here on
	// executable path, open port, we respect that choice and find the language for the pipeline.
	detectedType := procs.FindProcLanguage(execElf.Pid())

	if !t.cfg.Discovery.SkipGoSpecificTracers && detectedType == svc.InstrumentableGolang && err == nil {
		log.Warn("ELF binary appears to be a Go program, but no offsets were found",
			"comm", execElf.CmdExePath(), "pid", execElf.Pid())

		err = fmt.Errorf("could not find any Go offsets in Go binary %s", execElf.CmdExePath())
	}

	log.Debug("instrumented", "comm", execElf.CmdExePath(), "pid", execElf.Pid(),
		"child", child, "language", detectedType.String())
	// Return the instrumentable without offsets, as it is identified as a generic
	// (or non-instrumentable Go proxy) executable
	t.instrumentableCache.Add(cacheKey{Dev: execElf.Dev(), Ino: execElf.Ino()}, instrumentedExecutable{Type: detectedType, Offsets: nil, InstrumentationError: err})

	return ebpf.Instrumentable{
		Type:                 detectedType,
		Offsets:              nil,
		FileInfo:             execElf,
		ChildPids:            child,
		InstrumentationError: err,
		LogEnricherEnabled:   execElf.LogEnricherEnabled(),
	}
}

func (t *typer) selectExecutableParent(
	discovered *exec.FileInfo,
	log *slog.Logger,
) (*exec.FileInfo, []app.PID) {
	execElf := discovered
	// On Linux, re-read each relationship through exact process handles. The
	// child is confirmed again after validating each candidate so a parent that
	// exited and reused its numeric PID between the two lookups cannot be adopted.
	// The visited set also makes malformed or synthetic ancestry cycles fail
	// closed.
	var child []app.PID
	visited := map[*exec.FileInfo]struct{}{execElf: {}}
	parentPID, parentPIDOK := currentProcessParentPID(execElf)
	for parentPIDOK && parentPID != execElf.Pid() {
		parent, ok := t.currentPids[parentPID]
		if !ok || parent == nil || !sameExecutableIdentity(parent, execElf) {
			break
		}
		if _, seen := visited[parent]; seen {
			break
		}
		if _, parentOK := currentProcessParentPID(parent); !parentOK {
			break
		}
		confirmedParentPID, childOK := currentProcessParentPID(execElf)
		if !childOK || confirmedParentPID != parentPID {
			break
		}
		nextParentPID, parentOK := currentProcessParentPID(parent)
		if !parentOK {
			break
		}

		log.Debug("replacing executable by its parent", "ppid", parentPID)
		child = append(child, execElf.Pid())
		execElf = parent
		visited[execElf] = struct{}{}
		parentPID, parentPIDOK = nextParentPID, true
	}
	if execElf != discovered && discovered.ELF() != nil {
		_ = discovered.ELF().Close()
	}
	return execElf, child
}

func sameExecutableIdentity(left, right *exec.FileInfo) bool {
	if left == nil || right == nil || left.CmdExePath() != right.CmdExePath() {
		return false
	}
	// Linux discovery always supplies the device/inode pair from a pinned
	// executable. Zero pairs remain only for synthetic/non-Linux compatibility.
	if left.Dev() == 0 && left.Ino() == 0 && right.Dev() == 0 && right.Ino() == 0 {
		return true
	}
	return left.Dev() != 0 && left.Ino() != 0 &&
		left.Dev() == right.Dev() && left.Ino() == right.Ino()
}

func (t *typer) inspectOffsets(execElf *exec.FileInfo) (*goexec.Offsets, bool, error) {
	if t.cfg.Discovery.SkipGoSpecificTracers {
		t.log.Debug("skipping inspection for Go functions", "pid", execElf.Pid(), "comm", execElf.CmdExePath())
		return nil, false, nil
	}
	t.log.Debug("inspecting", "pid", execElf.Pid(), "comm", execElf.CmdExePath())
	offsets, err := goexec.InspectOffsets(execElf, t.allGoFunctions)
	if err != nil {
		t.log.Debug("couldn't find go specific tracers", "error", err)
		return nil, false, err
	}
	return offsets, true, nil
}

func isGoProxy(offsets *goexec.Offsets) bool {
	for f := range offsets.Funcs {
		// if we find anything of interest other than the Go runtime, we consider this a valid application
		if !strings.HasPrefix(f, "runtime.") {
			return false
		}
	}

	return true
}

func (t *typer) loadAllGoFunctionNames() {
	uniqueFunctions := map[string]struct{}{}
	t.allGoFunctions = nil
	for _, p := range newGoTracersGroup(nil, t.cfg, t.metrics) {
		for symbolName := range p.GoProbes() {
			t.addGoFunctionName(uniqueFunctions, symbolName)
		}
	}

	for _, symbolName := range gotracer.GoChannelLinkProbeSymbols() {
		t.addGoFunctionName(uniqueFunctions, symbolName)
	}
	for _, symbolName := range gotracer.GoRuntimeMetricProbeSymbols() {
		t.addGoFunctionName(uniqueFunctions, symbolName)
	}
}

func (t *typer) addGoFunctionName(uniqueFunctions map[string]struct{}, symbolName string) {
	if _, ok := uniqueFunctions[symbolName]; ok {
		return
	}

	uniqueFunctions[symbolName] = struct{}{}
	t.allGoFunctions = append(t.allGoFunctions, symbolName)
}
