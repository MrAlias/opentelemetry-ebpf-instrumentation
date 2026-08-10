// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tpinjector // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"

import (
	"context"
	"io"
	"log/slog"
	"sync"

	"github.com/cilium/ebpf"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/goexec"
	"go.opentelemetry.io/obi/pkg/internal/javabridge"
	"go.opentelemetry.io/obi/pkg/obi"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 Bpf ../../../../bpf/tpinjector/tpinjector.c -- -I../../../../bpf -I../../../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 BpfIter ../../../../bpf/tpinjector/sock_iter.c -- -I../../../../bpf -I../../../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 BpfFionreadFixup ../../../../bpf/tpinjector/fionread_fixup.c -- -I../../../../bpf -I../../../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 BpfJavaRemoteParent ../../../../bpf/javabridge/javabridge.c -- -I../../../../bpf -I../../../../bpf
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 BpfJavaRemoteParentMaps ../../../../bpf/javabridge/maps.c -- -I../../../../bpf -I../../../../bpf

type Tracer struct {
	cfg                        *obi.Config
	bpfObjects                 BpfObjects
	bpfIterObjects             BpfIterObjects
	bpfFionreadFixupObjects    BpfFionreadFixupObjects
	bpfJavaRemoteParent        BpfJavaRemoteParentObjects
	bpfJavaRemoteParentMaps    BpfJavaRemoteParentMapsObjects
	closers                    []io.Closer
	log                        *slog.Logger
	metrics                    imetrics.Reporter
	iters                      []*ebpfcommon.Iter
	fionreadOnce               sync.Once
	fionreadBroken             bool
	fionreadFixupEnabled       bool
	javaRemoteParentLoaded     bool
	javaRemoteParentMapsLoaded bool
	javaRemoteParentSpec       *ebpf.CollectionSpec
	javaRemoteParentMapsSpec   *ebpf.CollectionSpec
	javaRemoteParentError      error
	javaRemoteParentErrorStage javaRemoteParentAvailabilityStage
	javaRemoteParentMapsError  error
	javaRemoteParentSweep      chan struct{}
	javaRemoteParentEnabled    bool
	javaRemoteParentSupportErr error
	haveSockOpsNetnsCookie     func() error
}

func New(cfg *obi.Config, metrics imetrics.Reporter) *Tracer {
	log := slog.With("component", "tpinjector")

	return &Tracer{
		log:                    log,
		cfg:                    cfg,
		metrics:                metrics,
		javaRemoteParentSweep:  make(chan struct{}, 1),
		haveSockOpsNetnsCookie: javabridge.HaveSockOpsNetnsCookie,
	}
}

func (p *Tracer) AllowPID(app.PID, uint32, *exec.FileInfo, *exec.FileInfo) {}

func (p *Tracer) BlockPID(app.PID, uint32, *exec.FileInfo, *exec.FileInfo) {
	if p.cfg == nil || !p.javaRemoteParentEnabled {
		return
	}
	select {
	case p.javaRemoteParentSweep <- struct{}{}:
	default:
	}
}

func (p *Tracer) LoadSpecs() ([]*ebpfcommon.SpecBundle, error) {
	spec, err := LoadBpf()
	if err != nil {
		return nil, err
	}
	p.resolveJavaRemoteParentSupport()
	if !p.javaRemoteParentEnabled {
		javabridge.MinimizeDisabledMaps(spec)
	}

	bundles := []*ebpfcommon.SpecBundle{{
		Spec:      spec,
		Objects:   &p.bpfObjects,
		Constants: p.constants(),
	}}

	// BpfIter uses bpf_iter__tcp. The verifier needs bpf_iter_tcp_get_func_proto
	// to recognize the sock_iter ctx type; that landed in 5.11. Loading on older
	// kernels fails with "Unrecognized arg#0 type PTR". Iters() additionally
	// gates attach on >= 6.4 (RCU stall bug), so skipping the bundle below 5.11
	// is strictly an extension of that.
	if major, minor := ebpfcommon.KernelVersion(); major > 5 || (major == 5 && minor >= 11) {
		iterSpec, err := LoadBpfIter()
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, &ebpfcommon.SpecBundle{
			Spec:      iterSpec,
			Objects:   &p.bpfIterObjects,
			Constants: p.iterConstants(),
		})
	}

	// kernel lockdown rejects bpf_probe_write_user at load time
	if p.kernelBreaksFIONREAD() {
		fixupSpec, err := loadableFIONREADFixup()
		if err != nil {
			p.log.Error("kernel misreports FIONREAD for sockets in a sockhash and the BPF "+
				"compensation cannot be loaded (kernel lockdown?); applications sizing reads "+
				"via FIONREAD (nginx, Java, .NET) may stall or truncate transfers; "+
				"set context_propagation: disabled (OTEL_EBPF_BPF_CONTEXT_PROPAGATION=disabled) "+
				"to avoid impact", "error", err)
		} else {
			bundles = append(bundles, &ebpfcommon.SpecBundle{
				Spec:      fixupSpec,
				Objects:   &p.bpfFionreadFixupObjects,
				Constants: map[string]any{"g_bpf_debug": p.cfg.EBPF.BpfDebug},
			})
			p.fionreadFixupEnabled = true
		}
	}

	p.loadJavaRemoteParentSpecs()

	return bundles, nil
}

func (p *Tracer) resolveJavaRemoteParentSupport() {
	p.javaRemoteParentEnabled = false
	p.javaRemoteParentSupportErr = nil
	if p.cfg == nil || !p.cfg.Java.RemoteParent.Enabled() {
		return
	}
	if err := p.haveSockOpsNetnsCookie(); err != nil {
		p.javaRemoteParentSupportErr = err
		return
	}
	p.javaRemoteParentEnabled = true
}

func (p *Tracer) constants() map[string]any {
	flags := uint32(0)
	if p.cfg.EBPF.ContextPropagation.HasHeaders() {
		flags |= 1 // k_inject_http_headers
	}
	if p.cfg.EBPF.ContextPropagation.HasTCP() {
		flags |= 2 // k_inject_tcp_options
	}

	filterPids := int32(1)
	if p.cfg.Discovery.BPFPidFilterOff {
		filterPids = 0
	}

	return map[string]any{
		"filter_pids":                filterPids,
		"max_transaction_time":       uint64(p.cfg.EBPF.MaxTransactionTime.Nanoseconds()),
		"inject_flags":               flags,
		"g_bpf_debug":                p.cfg.EBPF.BpfDebug,
		"java_remote_parent_enabled": p.javaRemoteParentEnabled,
		"ssl_prewrite_max_age_ns":    uint64(p.cfg.Java.RemoteParent.TTL.Nanoseconds()),
	}
}

func (p *Tracer) iterConstants() map[string]any {
	return map[string]any{
		"g_bpf_debug": p.cfg.EBPF.BpfDebug,
	}
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
	return nil
}

func (p *Tracer) Tracepoints() map[string]ebpfcommon.ProbeDesc {
	tracepoints := map[string]ebpfcommon.ProbeDesc{}
	if p.fionreadFixupEnabled {
		tracepoints["syscalls/sys_enter_ioctl"] = ebpfcommon.ProbeDesc{
			Start: p.bpfFionreadFixupObjects.ObiFionreadFixupEnter,
		}
		tracepoints["syscalls/sys_exit_ioctl"] = ebpfcommon.ProbeDesc{
			Start: p.bpfFionreadFixupObjects.ObiFionreadFixupExit,
		}
	}
	if p.javaRemoteParentEnabled {
		tracepoints["sched/sched_process_exec"] = ebpfcommon.ProbeDesc{
			Start:    p.bpfObjects.ObiJavaRemoteParentProcessExec,
			Required: true,
		}
		tracepoints["sched/sched_process_exit"] = ebpfcommon.ProbeDesc{
			Start:    p.bpfObjects.ObiJavaRemoteParentProcessExit,
			Required: true,
		}
	}
	if len(tracepoints) == 0 {
		return nil
	}
	return tracepoints
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
	return []ebpfcommon.SockMsg{
		{
			Program:  p.bpfObjects.ObiPacketExtender,
			MapFD:    p.bpfObjects.SockDir.FD(),
			AttachAs: ebpf.AttachSkMsgVerdict,
		},
	}
}

func (p *Tracer) SockOps() []ebpfcommon.SockOps {
	return []ebpfcommon.SockOps{
		{
			Program:  p.bpfObjects.ObiSockmapTracker,
			AttachAs: ebpf.AttachCGroupSockOps,
		},
	}
}

func (p *Tracer) Iters() []*ebpfcommon.Iter {
	if p.iters != nil {
		return p.iters
	}

	major, minor := ebpfcommon.KernelVersion()

	if major < 6 || (major == 6 && minor < 4) {
		p.log.Warn("TCP socket iterator disabled: kernel versions < 6.4 have a locking bug " +
			"in iter/tcp + sockhash that can cause an RCU stall and kernel panic. " +
			"Existing connections at startup will not be tracked for context propagation.")
		p.iters = []*ebpfcommon.Iter{}
		return p.iters
	}

	// The ordering matters, we don't want to add passive listeners to
	// the map, so we first find the listening ports and then we discard
	// the established with those listening ports.
	p.iters = []*ebpfcommon.Iter{
		{Program: p.bpfIterObjects.ObiSkIterTcpListen},
		{Program: p.bpfIterObjects.ObiSkIterTcp},
	}

	return p.iters
}

func (p *Tracer) Tracing() []*ebpfcommon.Tracing {
	return nil
}

func (p *Tracer) RecordInstrumentedLib(exec.FileID, []io.Closer) {}

func (p *Tracer) AddInstrumentedLibRef(exec.FileID) {}

func (p *Tracer) UnlinkInstrumentedLib(exec.FileID) {}

func (p *Tracer) AlreadyInstrumentedLib(exec.FileID) bool {
	return false
}

func (p *Tracer) Run(ctx context.Context, eventContext *ebpfcommon.EBPFEventContext, _ *msg.Queue[[]request.Span]) {
	p.log.Debug("tpinjector started")
	p.loadJavaRemoteParentObjects(eventContext)
	stopJavaRemoteParent := p.runJavaRemoteParent(ctx)

	if p.fionreadFixupEnabled {
		p.verifyFIONREADFix()
	}

	for _, it := range p.Iters() {
		if err := it.Run(p.log); err != nil {
			p.log.Error("error running iterator", "error", err)
		}
	}

	<-ctx.Done()
	stopJavaRemoteParent()
	for _, closer := range p.closers {
		if err := closer.Close(); err != nil {
			p.log.Debug("closing tpinjector probe", "error", err)
		}
	}
	p.closers = nil

	p.bpfObjects.Close()
	p.bpfIterObjects.Close()
	p.bpfFionreadFixupObjects.Close()
	p.bpfJavaRemoteParent.Close()

	p.log.Debug("tpinjector terminated")
}

func (p *Tracer) SetEventContext(_ *ebpfcommon.EBPFEventContext) {}

func (p *Tracer) Capabilities() ebpfcommon.TracerCapability { return 0 }

func (p *Tracer) Required() bool {
	return false
}
