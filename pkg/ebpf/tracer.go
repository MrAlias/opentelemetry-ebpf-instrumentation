// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/ebpf"

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/ebpf/logenricher"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

type Instrumentable struct {
	Type                 svc.InstrumentableType
	InstrumentationError error

	// in some runtimes, like python gunicorn, we need to allow
	// tracing both the parent pid and all of its children pid
	ChildPids []app.PID

	FileInfo *exec.FileInfo
	// PIDOwner is the exact process-lifetime token for a deletion event.
	PIDOwner *exec.FileInfo
	// PIDOwners contains exact child-lifetime tokens for a creation event whose
	// executable/service classification is shared through FileInfo.
	PIDOwners map[app.PID]*exec.FileInfo
	// TracerOwner identifies the executable tracer/process-instance bucket used
	// by a deletion event. It can differ from PIDOwner after parent substitution.
	TracerOwner *exec.FileInfo
	Offsets     *goexec.Offsets
	Tracer      *ProcessTracer

	LogEnricherEnabled   bool
	ExecutableGeneration uint64
}

// PIDOwnerFor returns the exact lifetime token for pid on a creation event.
// Ordinary/self-owned PIDs fall back to FileInfo.
func (ie *Instrumentable) PIDOwnerFor(pid app.PID) *exec.FileInfo {
	if ie != nil && ie.PIDOwners != nil {
		if owner := ie.PIDOwners[pid]; owner != nil {
			return owner
		}
	}
	if ie == nil {
		return nil
	}
	return ie.FileInfo
}

// PIDOwnerFileInfo returns the exact FileInfo token used to admit this
// instrumentable's PID. Ordinary events are self-owned.
func (ie *Instrumentable) PIDOwnerFileInfo() *exec.FileInfo {
	if ie != nil && ie.PIDOwner != nil {
		return ie.PIDOwner
	}
	if ie == nil {
		return nil
	}
	return ie.FileInfo
}

// TracerOwnerFileInfo returns the executable ownership bucket used to locate
// and refcount the tracer handling this deletion.
func (ie *Instrumentable) TracerOwnerFileInfo() *exec.FileInfo {
	if ie != nil && ie.TracerOwner != nil {
		return ie.TracerOwner
	}
	if ie == nil {
		return nil
	}
	return ie.FileInfo
}

func (ie *Instrumentable) CopyToServiceAttributes() {
	ie.FileInfo.ApplyServiceDefaults(ie.Type)
}

type PIDsAccounter interface {
	// AllowPID notifies the tracer to accept traces from the given PID, sharing
	// the FileInfo so mutable service state (flags, harvested routes, k8s
	// metadata) goes through its synchronized API.
	// The result reports whether this exact process lifetime was admitted.
	AllowPID(app.PID, uint32, *exec.FileInfo, *exec.FileInfo) bool
	// BlockPID notifies the tracer to stop accepting traces from the process
	// lifetime identified by the provided FileInfo. After receiving them via
	// ringbuffer, it should discard them. The exact lifetime identity prevents
	// a delayed deletion for a reused PID from blocking its replacement.
	BlockPID(app.PID, uint32, *exec.FileInfo, *exec.FileInfo)
}

type CommonTracer interface {
	// LoadSpecs returns one SpecBundle per BPF collection. Each bundle contains
	// the collection spec, the object pointer to populate, and the constants to rewrite.
	LoadSpecs() ([]*ebpfcommon.SpecBundle, error)
	// AddCloser adds io.Closer instances that need to be invoked when the
	// Run function ends.
	AddCloser(c ...io.Closer)
	// SetupTailCalls sets up any tail call jump tables after all specs are loaded.
	SetupTailCalls()
}

type KprobesTracer interface {
	CommonTracer
	// KProbes returns a map with the name of the kernel probes that need to be
	// tapped into. Start matches kprobe, End matches kretprobe
	KProbes() map[string]ebpfcommon.ProbeDesc
	Tracepoints() map[string]ebpfcommon.ProbeDesc
}

// Tracer is an individual eBPF program (e.g. the net/http or the grpc tracers)
type Tracer interface {
	PIDsAccounter
	KprobesTracer
	// GoProbes returns a slice with the name of Go functions that need to be inspected
	// in the executable, as well as the eBPF programs that optionally need to be
	// inserted as the Go function start and end probes
	GoProbes() map[string][]*ebpfcommon.ProbeDesc
	// UProbes returns a map with the module name mapping to the uprobes that need to be
	// tapped into. Start matches uprobe, End matches uretprobe.
	// The module name key may carry a version constraint in square brackets, which causes
	// the entry to be selected only when the library's version satisfies the constraint.
	// See matchVersionedUprobeLibrary for how selection is performed.
	UProbes() map[string]map[string][]*ebpfcommon.ProbeDesc
	// USDTProbes returns a map with the module name mapping to USDT probes.
	USDTProbes() map[string][]*ebpfcommon.USDTProbeDesc
	// SocketFilters  returns a list of programs that need to be loaded as a
	// generic eBPF socket filter
	SocketFilters() []*ebpf.Program
	// SockMsgs returns a list of programs that need to be loaded as a
	// BPF_PROG_TYPE_SK_MSG eBPF programs
	SockMsgs() []ebpfcommon.SockMsg
	// SockOps returns a list of programs that need to be loaded as a
	// BPF_PROG_TYPE_SOCK_OPS eBPF programs
	SockOps() []ebpfcommon.SockOps
	// Iters returns a list of programs that need to be loaded as a
	// BPF_PROG_TYPE_TRACING with BPF_TRACE_ITER attach type
	Iters() []*ebpfcommon.Iter
	// Tracing() returns a list of programs that need to be loaded as a
	// BPF_PROG_TYPE_TRACING
	Tracing() []*ebpfcommon.Tracing
	// Probes can potentially instrument a shared library among multiple executables
	// These two functions alow programs to remember this and avoid duplicated instrumentations
	// The argument is the OS file id
	// Closers are the associated closable resources to this lib, that may be
	// closed when UnlinkInstrumentedLib() is called
	RecordInstrumentedLib(exec.FileID, []io.Closer)
	AddInstrumentedLibRef(exec.FileID)
	AlreadyInstrumentedLib(exec.FileID) bool
	UnlinkInstrumentedLib(exec.FileID)
	RegisterOffsets(*exec.FileInfo, *goexec.Offsets) error
	ProcessBinary(*exec.FileInfo)
	SetEventContext(*ebpfcommon.EBPFEventContext)
	Required() bool
	Capabilities() ebpfcommon.TracerCapability
	// Run will do the action of listening for eBPF traces and forward them
	// periodically to the output channel.
	Run(context.Context, *ebpfcommon.EBPFEventContext, *msg.Queue[[]request.Span])
}

// Subset of the above interface, which supports loading eBPF programs which
// are not tied to service monitoring
type UtilityTracer interface {
	KprobesTracer
	Run(context.Context)
}

type ProcessTracerType int

const (
	Go = ProcessTracerType(iota)
	Generic
)

// ExecutableKey identifies an executable across filesystems.
type ExecutableKey = exec.FileID

// ProcessTracer instruments an executable with eBPF and provides the eBPF readers
// that will forward the traces to later stages in the pipeline
// TODO: We need to pass the ELFInfo from this ProcessTracker to inside a Tracer
// so that the GPU kernel event listener can find symbols names from addresses
// in the ELF file.
type ProcessTracer struct {
	log                       *slog.Logger
	metrics                   imetrics.Reporter
	shutdownTimeout           time.Duration
	bpffsPath                 string
	lifecycleMu               sync.Mutex
	initializing              bool
	runStarted                bool
	aborted                   bool
	abortErr                  error
	abortFn                   func() error
	loadedClosers             []io.Closer
	loadContext               *ebpfcommon.EBPFEventContext
	loadMaps                  map[string]*ebpf.Map
	loadCapabilities          ebpfcommon.TracerCapability
	instrumentablesMu         sync.Mutex
	nextExecutableGeneration  uint64
	instrumentableGenerations map[ExecutableKey]uint64

	Type            ProcessTracerType
	Instrumentables map[ExecutableKey]*instrumenter
	Programs        []Tracer
}

// ExecutableInstanceTransaction keeps newly attached instance-specific probes
// provisional until exact process admission succeeds.
type ExecutableInstanceTransaction interface {
	Commit()
	Rollback() error
}

// ExecutableTransaction keeps a newly instrumented executable provisional
// until exact process admission succeeds.
type ExecutableTransaction interface {
	Commit()
	Rollback() error
}

var (
	errProcessTracerInitializing = errors.New("process tracer initialization is in progress")
	errProcessTracerRunning      = errors.New("process tracer has already started")
	errProcessTracerAborted      = errors.New("process tracer has been aborted")
)

// Abort releases a newly initialized ProcessTracer that will not be run. It is
// safe to call more than once; every caller observes the same cleanup result.
func (pt *ProcessTracer) Abort() error {
	if pt == nil {
		return nil
	}

	pt.lifecycleMu.Lock()
	defer pt.lifecycleMu.Unlock()

	if pt.aborted {
		return pt.abortErr
	}
	if pt.initializing {
		return errProcessTracerInitializing
	}
	if pt.runStarted {
		return errProcessTracerRunning
	}

	pt.aborted = true
	if pt.abortFn != nil {
		pt.abortErr = pt.abortFn()
	}
	return pt.abortErr
}

func (pt *ProcessTracer) beginInit() error {
	pt.lifecycleMu.Lock()
	defer pt.lifecycleMu.Unlock()
	if pt.aborted {
		return errProcessTracerAborted
	}
	if pt.initializing {
		return errProcessTracerInitializing
	}
	if pt.runStarted {
		return errProcessTracerRunning
	}
	pt.initializing = true
	return nil
}

func (pt *ProcessTracer) finishInit() {
	pt.lifecycleMu.Lock()
	pt.initializing = false
	pt.lifecycleMu.Unlock()
}

func (pt *ProcessTracer) beginRun() bool {
	pt.lifecycleMu.Lock()
	defer pt.lifecycleMu.Unlock()
	if pt.aborted || pt.initializing || pt.runStarted {
		return false
	}
	pt.runStarted = true
	return true
}

func (pt *ProcessTracer) AllowPID(
	pid app.PID,
	ns uint32,
	fi *exec.FileInfo,
	owner *exec.FileInfo,
) bool {
	logEnricherEnabled := fi.LogEnricherEnabled()
	for i := range pt.Programs {
		program := pt.Programs[i]
		if _, ok := program.(*logenricher.Tracer); ok && !logEnricherEnabled {
			continue
		}
		if !program.AllowPID(pid, ns, fi, owner) {
			// Tracer groups put their exact ServiceFilter-gated Generic/Go
			// program first. Its result owns process admission. Later programs are
			// optional feature-local accounters and roll back their own failed
			// transaction without undoing an independently live core admission.
			if i == 0 {
				return false
			}
		}
	}
	return true
}

func (pt *ProcessTracer) BlockPID(
	pid app.PID,
	ns uint32,
	fi *exec.FileInfo,
	owner *exec.FileInfo,
) {
	for i := range pt.Programs {
		pt.Programs[i].BlockPID(pid, ns, fi, owner)
	}
}
