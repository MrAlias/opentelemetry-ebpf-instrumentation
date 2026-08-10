// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf // import "go.opentelemetry.io/obi/pkg/ebpf"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	common "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func ptlog() *slog.Logger { return slog.With("component", "ebpf.ProcessTracer") }

type instrumenter struct {
	offsets     *goexec.Offsets
	exe         *link.Executable
	closables   []io.Closer
	modules     map[exec.FileID]struct{}
	metrics     imetrics.Reporter
	processName string
}

// tracerTransaction delays closer publication until an attach operation has
// fully succeeded. Shared-library reference changes are applied immediately so
// subsequent probes see a consistent view, but are recorded for exact rollback.
type tracerTransaction struct {
	Tracer
	closers    []io.Closer
	moduleRefs []exec.FileID
}

func (t *tracerTransaction) AddCloser(closers ...io.Closer) {
	t.closers = append(t.closers, closers...)
}

func (t *tracerTransaction) RecordInstrumentedLib(id exec.FileID, closers []io.Closer) {
	t.Tracer.RecordInstrumentedLib(id, closers)
	t.moduleRefs = append(t.moduleRefs, id)
}

func (t *tracerTransaction) AddInstrumentedLibRef(id exec.FileID) {
	t.Tracer.AddInstrumentedLibRef(id)
	t.moduleRefs = append(t.moduleRefs, id)
}

func (t *tracerTransaction) commit() {
	t.Tracer.AddCloser(t.closers...)
}

func (t *tracerTransaction) rollback() error {
	var rollbackErr error
	for idx := len(t.closers) - 1; idx >= 0; idx-- {
		if err := t.closers[idx].Close(); err != nil {
			rollbackErr = errors.Join(rollbackErr, err)
		}
	}
	for idx := len(t.moduleRefs) - 1; idx >= 0; idx-- {
		t.UnlinkInstrumentedLib(t.moduleRefs[idx])
	}
	return rollbackErr
}

func snapshotEventContextMaps(eventContext *common.EBPFEventContext) map[string]*ebpf.Map {
	eventContext.MapsLock.Lock()
	defer eventContext.MapsLock.Unlock()

	snapshot := make(map[string]*ebpf.Map, len(eventContext.EBPFMaps))
	for name, bpfMap := range eventContext.EBPFMaps {
		snapshot[name] = bpfMap
	}
	return snapshot
}

// rollbackEventContextMaps removes only maps introduced since snapshot. Maps
// already owned by another tracer are never closed or removed.
func rollbackEventContextMaps(eventContext *common.EBPFEventContext, snapshot map[string]*ebpf.Map) error {
	if eventContext == nil {
		return nil
	}

	eventContext.MapsLock.Lock()
	defer eventContext.MapsLock.Unlock()

	var rollbackErr error
	for name, current := range eventContext.EBPFMaps {
		previous, existed := snapshot[name]
		if existed && current == previous {
			continue
		}

		if existed {
			eventContext.EBPFMaps[name] = previous
		} else {
			delete(eventContext.EBPFMaps, name)
		}
		if current != nil {
			rollbackErr = errors.Join(rollbackErr, current.Close())
		}
	}
	for name, previous := range snapshot {
		if _, exists := eventContext.EBPFMaps[name]; !exists {
			eventContext.EBPFMaps[name] = previous
		}
	}
	return rollbackErr
}

func bundleClosers(bundles []*common.SpecBundle) []io.Closer {
	closers := make([]io.Closer, 0, len(bundles))
	for _, bundle := range bundles {
		if bundle == nil {
			continue
		}
		if closer, ok := bundle.Objects.(io.Closer); ok {
			closers = append(closers, closer)
		}
	}
	return closers
}

func closeClosers(closers []io.Closer) error {
	var closeErr error
	for idx := len(closers) - 1; idx >= 0; idx-- {
		if closers[idx] == nil {
			continue
		}
		closeErr = errors.Join(closeErr, closers[idx].Close())
	}
	return closeErr
}

func loadSpec(eventContext *common.EBPFEventContext, bundle *common.SpecBundle, otelBPFFSPath string, idx int, cache *btf.Cache) error {
	if err := ebpfconvenience.LoadSpec(
		bundle.Spec,
		bundle.Objects,
		bundle.Constants,
		eventContext.EBPFMaps,
		&eventContext.MapsLock,
		otelBPFFSPath,
		cache,
	); err != nil {
		return fmt.Errorf("loading spec %d: %w", idx, err)
	}

	return nil
}

func closeLoadedSpecs(bundles []*common.SpecBundle) {
	_ = closeClosers(bundleClosers(bundles))
}

func unloadInternalMaps(eventContext *common.EBPFEventContext) {
	eventContext.MapsLock.Lock()
	defer eventContext.MapsLock.Unlock()

	for _, v := range eventContext.EBPFMaps {
		v.Close()
	}

	eventContext.EBPFMaps = make(map[string]*ebpf.Map)
}

func NewProcessTracer(tracerType ProcessTracerType, programs []Tracer, cfg *obi.Config, metrics imetrics.Reporter) *ProcessTracer {
	pt := &ProcessTracer{
		log:             ptlog().With("type", tracerType),
		Programs:        programs,
		Type:            tracerType,
		Instrumentables: map[exec.FileID]*instrumenter{},
		shutdownTimeout: cfg.ShutdownTimeout,
		metrics:         metrics,
		bpffsPath:       cfg.EBPF.BPFFSPath,
	}
	pt.abortFn = pt.abortBeforeRun
	return pt
}

type tracerInstance struct {
	implType string
	done     atomic.Bool
}

func (pt *ProcessTracer) Run(
	ctx context.Context,
	ebpfEventContext *common.EBPFEventContext,
	out *msg.Queue[[]request.Span],
) {
	pt.log = ptlog().With("type", pt.Type)
	if !pt.beginRun() {
		pt.log.Debug("not starting unavailable process tracer")
		return
	}

	pt.log.Debug("starting process tracer")

	// Searches for traceable functions
	trcrs := pt.Programs
	wg := sync.WaitGroup{}
	runningTracers := make([]tracerInstance, 0, len(trcrs))
	for i := range trcrs {
		idx := i
		t := trcrs[idx]
		wg.Add(1)
		runningTracers = append(runningTracers, tracerInstance{
			implType: reflect.TypeOf(t).String(),
		})
		go func() {
			defer wg.Done()
			t.Run(ctx, ebpfEventContext, out)
			runningTracers[idx].done.Store(true)
		}()
	}

	<-ctx.Done()

	tracersEnded := make(chan struct{})
	go func() {
		wg.Wait()
		close(tracersEnded)
	}()
	unloadInternalMaps(ebpfEventContext)

	hasWarned := false
	for {
		select {
		// notifying before OBI times out on finish
		case <-time.After(3 * pt.shutdownTimeout / 4):
			pt.log.Warn("some process tracers did not finish", "tracers", runningTracers)
			hasWarned = true
		case <-tracersEnded:
			if hasWarned {
				pt.log.Info("all process tracers finished")
			}
			return
		}
	}
}

func (pt *ProcessTracer) abortBeforeRun() error {
	var abortErr error
	for ino, inst := range pt.Instrumentables {
		abortErr = errors.Join(abortErr, inst.close(pt.Programs))
		delete(pt.Instrumentables, ino)
	}

	abortErr = errors.Join(abortErr, closeClosers(pt.loadedClosers))
	pt.loadedClosers = nil
	if pt.loadContext != nil {
		abortErr = errors.Join(abortErr, rollbackEventContextMaps(pt.loadContext, pt.loadMaps))
		pt.loadContext.Capabilities = pt.loadCapabilities
	}
	for _, program := range pt.Programs {
		program.SetEventContext(nil)
	}
	pt.Programs = nil
	return abortErr
}

func (pt *ProcessTracer) makeOtelBPFFSPath() (string, error) {
	otelPath := path.Join(pt.bpffsPath, "otel")

	if err := os.MkdirAll(otelPath, 0o1700); err != nil {
		return "", fmt.Errorf("creating bpffs otel path: %w", err)
	}

	return otelPath, nil
}

func (pt *ProcessTracer) setupOtelBPFFSPath(bundles []*common.SpecBundle) string {
	// Set up BPF FS path once for all specs
	otelBPFFSPath, err := pt.makeOtelBPFFSPath()

	if err == nil {
		return otelBPFFSPath
	}

	log := ptlog()

	log.Warn("creating OTEL namespace in bpffs failed (is bpffs mounted?)",
		"bpffs_path", pt.bpffsPath, "err", err)

	log.Warn("OBI will still work, but features depending on pinned maps (e.g., log enricher, profile correlation) will be disabled")

	// disable pinning for ALL specs
	for _, bundle := range bundles {
		for _, v := range bundle.Spec.Maps {
			if v.Pinning == ebpf.PinByName {
				v.Pinning = ebpf.PinNone
				v.MaxEntries = 1
			}
		}
	}

	return ""
}

func setupBPFMapSizes(spec *ebpf.CollectionSpec, cfg *obi.Config) {
	ebpfconvenience.SetupMapSizes(spec, cfg.EBPF.MapsConfig.GlobalScaleFactor)
}

func (pt *ProcessTracer) loadAndAssign(eventContext *common.EBPFEventContext, p Tracer, cfg *obi.Config, cache *btf.Cache) ([]*common.SpecBundle, error) {
	p.SetEventContext(eventContext)

	bundles, err := p.LoadSpecs()
	if err != nil {
		return bundles, fmt.Errorf("loading eBPF program specs: %w", err)
	}

	otelBPFFSPath := pt.setupOtelBPFFSPath(bundles)

	for i, bundle := range bundles {
		// set max entries map using user defined values
		setupBPFMapSizes(bundle.Spec, cfg)

		if err := loadSpec(eventContext, bundle, otelBPFFSPath, i, cache); err != nil {
			return bundles, err
		}
	}

	return bundles, nil
}

func (pt *ProcessTracer) loadTracer(eventContext *common.EBPFEventContext, p Tracer, log *slog.Logger, cfg *obi.Config, cache *btf.Cache) ([]io.Closer, error) {
	plog := log.With("program", reflect.TypeOf(p))
	plog.Debug("loading eBPF program", "type", pt.Type)

	mapsBefore := snapshotEventContextMaps(eventContext)
	txn := &tracerTransaction{Tracer: p}

	bundles, err := pt.loadAndAssign(eventContext, txn, cfg, cache)

	if err != nil && (strings.Contains(err.Error(), "unknown func bpf_probe_write_user") ||
		strings.Contains(err.Error(), "cannot use helper bpf_probe_write_user")) {
		plog.Warn("Failed to enable Go write memory distributed tracing context-propagation " +
			"and/or log enricher on a Linux Kernel without write memory support. " +
			"To avoid seeing this message, please ensure you have correctly mounted /sys/kernel/security " +
			"and ensure OBI has the SYS_ADMIN linux capability. " +
			"For more details set OTEL_EBPF_LOG_LEVEL=DEBUG.")

		closeLoadedSpecs(bundles)
		_ = rollbackEventContextMaps(eventContext, mapsBefore)
		common.IntegrityModeOverride = true
		bundles, err = pt.loadAndAssign(eventContext, txn, cfg, cache)
	}

	if err != nil {
		closeLoadedSpecs(bundles)
		_ = rollbackEventContextMaps(eventContext, mapsBefore)
		p.SetEventContext(nil)
		printVerifierErrorInfo(err)
		return nil, fmt.Errorf("loading and assigning BPF objects: %w", err)
	}

	loadedClosers := bundleClosers(bundles)
	rollback := func(attachErr error) ([]io.Closer, error) {
		rollbackErr := txn.rollback()
		rollbackErr = errors.Join(rollbackErr, closeClosers(loadedClosers))
		rollbackErr = errors.Join(rollbackErr, rollbackEventContextMaps(eventContext, mapsBefore))
		p.SetEventContext(nil)
		return nil, errors.Join(attachErr, rollbackErr)
	}

	// Setup any tail call jump tables
	txn.SetupTailCalls()

	i := instrumenter{} // dummy instrumenter to setup the kprobes, socket filters and tracepoint probes

	// Kprobes to be used for native instrumentation points
	if err := i.kprobes(txn); err != nil {
		printVerifierErrorInfo(err)
		return rollback(err)
	}

	// Tracepoints support
	if err := i.tracepoints(txn); err != nil {
		printVerifierErrorInfo(err)
		return rollback(err)
	}

	// Sock filters support
	if err := i.sockfilters(txn); err != nil {
		printVerifierErrorInfo(err)
		return rollback(err)
	}

	// Sock_msg support
	if err := i.sockmsgs(txn); err != nil {
		printVerifierErrorInfo(err)
		return rollback(err)
	}

	// Sockops support
	i.sockops(txn)

	if err := i.iters(txn); err != nil {
		printVerifierErrorInfo(err)
		return rollback(err)
	}

	if err := i.tracing(txn); err != nil {
		printVerifierErrorInfo(err)
		return rollback(err)
	}

	txn.commit()
	return append(loadedClosers, txn.closers...), nil
}

func (pt *ProcessTracer) loadTracers(eventContext *common.EBPFEventContext, cfg *obi.Config) error {
	eventContext.LoadLock.Lock()
	defer eventContext.LoadLock.Unlock()

	log := ptlog()
	pt.loadContext = eventContext
	pt.loadMaps = snapshotEventContextMaps(eventContext)
	pt.loadCapabilities = eventContext.Capabilities

	loadedPrograms := make([]Tracer, 0, len(pt.Programs))

	cache := btf.NewCache()

	for _, p := range pt.Programs {
		closers, err := pt.loadTracer(eventContext, p, log, cfg, cache)
		if err != nil {
			log.Warn("couldn't load tracer", "error", err, "required", p.Required())
			if p.Required() {
				return err
			}
		} else {
			loadedPrograms = append(loadedPrograms, p)
			pt.loadedClosers = append(pt.loadedClosers, closers...)
			eventContext.Capabilities |= p.Capabilities()
		}
	}

	pt.Programs = loadedPrograms

	return nil
}

func (pt *ProcessTracer) Init(eventContext *common.EBPFEventContext, cfg *obi.Config) error {
	if err := pt.beginInit(); err != nil {
		return err
	}
	err := pt.loadTracers(eventContext, cfg)
	pt.finishInit()
	if err != nil {
		return errors.Join(err, pt.Abort())
	}
	return nil
}

func (pt *ProcessTracer) NewExecutableInstance(ie *Instrumentable) error {
	pt.lifecycleMu.Lock()
	defer pt.lifecycleMu.Unlock()
	if pt.aborted {
		return errProcessTracerAborted
	}
	if ie == nil || ie.FileInfo == nil {
		return errors.New("instrumentable process information is unavailable")
	}

	if i, ok := pt.Instrumentables[ie.FileInfo.ID()]; ok {
		pid := ie.FileInfo.Pid()
		owner := ie.PIDOwnerFor(pid)
		if err := common.ValidateProcessOwner(pid, owner); err != nil {
			return fmt.Errorf("validating process owner before executable-instance attach: %w", err)
		}

		maps, err := processMaps(pid)
		if err != nil {
			return err
		}

		closersBefore := len(i.closables)
		modulesBefore := cloneModules(i.modules)
		transactions := make([]*tracerTransaction, 0, len(pt.Programs))
		rollback := func(attachErr error) error {
			var rollbackErr error
			for idx := len(transactions) - 1; idx >= 0; idx-- {
				rollbackErr = errors.Join(rollbackErr, transactions[idx].rollback())
			}
			i.closables = i.closables[:closersBefore]
			i.modules = modulesBefore
			return errors.Join(attachErr, rollbackErr)
		}

		for _, p := range pt.Programs {
			txn := &tracerTransaction{Tracer: p}
			transactions = append(transactions, txn)
			// Uprobes to be used for native module instrumentation points
			if err := i.uprobes(pid, txn, maps); err != nil {
				printVerifierErrorInfo(err)
				return rollback(err)
			}
			if err := i.usdtProbes(pid, ie.FileInfo.Ns(), txn, maps); err != nil {
				printVerifierErrorInfo(err)
				return rollback(err)
			}
		}
		if err := common.ValidateProcessOwner(pid, owner); err != nil {
			return rollback(fmt.Errorf("validating process owner after executable-instance attach: %w", err))
		}
		for idx, txn := range transactions {
			pt.Programs[idx].ProcessBinary(ie.FileInfo)
			txn.commit()
		}
	} else {
		return fmt.Errorf(
			"updating executable instance %q (pid %d): instrumenter for device %d inode %d does not exist",
			ie.FileInfo.CmdExePath(),
			ie.FileInfo.Pid(),
			ie.FileInfo.Dev(),
			ie.FileInfo.Ino(),
		)
	}

	return nil
}

func (pt *ProcessTracer) NewExecutable(exe *link.Executable, ie *Instrumentable) error {
	pt.lifecycleMu.Lock()
	defer pt.lifecycleMu.Unlock()
	if pt.aborted {
		return errProcessTracerAborted
	}
	if ie == nil || ie.FileInfo == nil {
		return errors.New("instrumentable process information is unavailable")
	}

	pid := ie.FileInfo.Pid()
	owner := ie.PIDOwnerFor(pid)
	if err := common.ValidateProcessOwner(pid, owner); err != nil {
		return fmt.Errorf("validating process owner before executable attach: %w", err)
	}

	i := instrumenter{
		exe:         exe,
		offsets:     ie.Offsets, // this is needed for the function offsets, not fields
		modules:     map[exec.FileID]struct{}{},
		metrics:     pt.metrics,
		processName: ie.FileInfo.ExecutableName(),
	}

	maps, err := processMaps(pid)
	if err != nil {
		return err
	}

	transactions := make([]*tracerTransaction, 0, len(pt.Programs))
	rollback := func(attachErr error) error {
		var rollbackErr error
		for idx := len(transactions) - 1; idx >= 0; idx-- {
			rollbackErr = errors.Join(rollbackErr, transactions[idx].rollback())
		}
		return errors.Join(attachErr, rollbackErr)
	}

	for _, p := range pt.Programs {
		txn := &tracerTransaction{Tracer: p}
		transactions = append(transactions, txn)
		if err := p.RegisterOffsets(ie.FileInfo, ie.Offsets); err != nil {
			return rollback(fmt.Errorf("registering executable offsets: %w", err))
		}

		// Go style Uprobes
		if err := i.goprobes(txn); err != nil {
			printVerifierErrorInfo(err)
			return rollback(err)
		}

		// Uprobes to be used for native module instrumentation points
		if err := i.uprobes(pid, txn, maps); err != nil {
			printVerifierErrorInfo(err)
			return rollback(err)
		}

		if err := i.usdtProbes(pid, ie.FileInfo.Ns(), txn, maps); err != nil {
			printVerifierErrorInfo(err)
			return rollback(err)
		}
	}
	if err := common.ValidateProcessOwner(pid, owner); err != nil {
		return rollback(fmt.Errorf("validating process owner after executable attach: %w", err))
	}
	for _, txn := range transactions {
		txn.commit()
	}

	pt.Instrumentables[ie.FileInfo.ID()] = &i

	return nil
}

func (pt *ProcessTracer) UnlinkExecutable(info *exec.FileInfo) {
	pt.lifecycleMu.Lock()
	defer pt.lifecycleMu.Unlock()
	if info == nil {
		return
	}
	if i, ok := pt.Instrumentables[info.ID()]; ok {
		if err := i.close(pt.Programs); err != nil {
			pt.log.Debug("Unable to close on unlink", "error", err)
		}
		delete(pt.Instrumentables, info.ID())
	} else {
		pt.log.Warn("Unable to find executable to unlink",
			"path", info.CmdExePath(),
			"pid", info.Pid(),
			"device", info.Dev(), "inode", info.Ino())
	}
}

func cloneModules(modules map[exec.FileID]struct{}) map[exec.FileID]struct{} {
	clone := make(map[exec.FileID]struct{}, len(modules))
	for id := range modules {
		clone[id] = struct{}{}
	}
	return clone
}

func (i *instrumenter) close(programs []Tracer) error {
	closeErr := closeClosers(i.closables)
	i.closables = nil
	for id := range i.modules {
		for _, p := range programs {
			p.UnlinkInstrumentedLib(id)
		}
		delete(i.modules, id)
	}
	return closeErr
}

func printVerifierErrorInfo(err error) {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		_, _ = fmt.Fprintf(os.Stderr, "Error Log:\n %v\n", strings.Join(ve.Log, "\n"))
	}
}

func RunUtilityTracer(ctx context.Context, eventContext *common.EBPFEventContext, p UtilityTracer, cfg *obi.Config) error {
	i := instrumenter{}
	plog := ptlog()
	plog.Debug("loading independent eBPF program")

	bundles, err := p.LoadSpecs()
	if err != nil {
		return fmt.Errorf("loading eBPF program specs: %w", err)
	}

	for idx, bundle := range bundles {
		// Utility tracers don't pin maps (empty pin path), so no pinned
		// map conflicts are possible — the empty path is intentional.
		setupBPFMapSizes(bundle.Spec, cfg)
		if err := loadSpec(eventContext, bundle, "", idx, nil); err != nil {
			closeLoadedSpecs(bundles[:idx])
			printVerifierErrorInfo(err)
			return err
		}
	}

	if err := i.kprobes(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	if err := i.tracepoints(p); err != nil {
		printVerifierErrorInfo(err)
		return err
	}

	go p.Run(ctx)

	return nil
}
