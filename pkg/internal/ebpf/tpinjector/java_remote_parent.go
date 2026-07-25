// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tpinjector // import "go.opentelemetry.io/obi/pkg/internal/ebpf/tpinjector"

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"

	obiebpf "go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	ebpfconvenience "go.opentelemetry.io/obi/pkg/internal/ebpf/convenience"
	"go.opentelemetry.io/obi/pkg/internal/javabridge"
	"go.opentelemetry.io/obi/pkg/obi"
)

const (
	javaRemoteParentStatCount               = 35
	javaRemoteParentStatStageValid          = 0
	javaRemoteParentStatTakeUnauthorized    = 8
	javaRemoteParentStatDiscardValid        = 12
	javaRemoteParentStatDiscardUnauthorized = 16
	javaRemoteParentStatHandoffValid        = 25
	javaRemoteParentStatInjectAmbiguous     = 31
	javaRemoteParentPollInterval            = 10 * time.Second
	javaRemoteParentReadinessPollInterval   = 100 * time.Millisecond
)

type javaRemoteParentAvailabilityStage string

const (
	javaRemoteParentAvailabilityOperation  = "availability"
	javaRemoteParentStatusLoadDenied       = "load_denied"
	javaRemoteParentStatusPermissionDenied = "permission_denied"
	javaRemoteParentStatusVerifierRejected = "verifier_rejected"

	javaRemoteParentStageProbe     javaRemoteParentAvailabilityStage = "probe"
	javaRemoteParentStageLoad      javaRemoteParentAvailabilityStage = "load"
	javaRemoteParentStageAttach    javaRemoteParentAvailabilityStage = "attach"
	javaRemoteParentStageReadiness javaRemoteParentAvailabilityStage = "readiness"
	javaRemoteParentStageListen    javaRemoteParentAvailabilityStage = "listen"
	javaRemoteParentStageServe     javaRemoteParentAvailabilityStage = "serve"
)

type javaRemoteParentFallbackServer interface {
	Serve(context.Context) error
	Close() error
}

var (
	haveCgroupSockopt = func() error {
		return features.HaveProgramType(ebpf.CGroupSockopt)
	}
	attachJavaRemoteParentCgroupLink = obiebpf.AttachCgroupSockOpsLink
	attachCgroupGetsockopt           = func(program *ebpf.Program) (io.Closer, error) {
		return attachJavaRemoteParentCgroupLink(program, ebpf.AttachCGroupGetsockopt)
	}
	attachCgroupSetsockopt = func(program *ebpf.Program) (io.Closer, error) {
		return attachJavaRemoteParentCgroupLink(program, ebpf.AttachCGroupSetsockopt)
	}
	validateCgroupSockoptSpec = func(spec *ebpf.CollectionSpec, constants map[string]any) error {
		testSpec := spec.Copy()
		if err := ebpfconvenience.RewriteConstants(testSpec, constants); err != nil {
			return err
		}
		for _, mapSpec := range testSpec.Maps {
			if mapSpec.Pinning == ebpfconvenience.PinInternal {
				mapSpec.Pinning = ebpf.PinNone
			}
		}
		collection, err := ebpf.NewCollection(testSpec)
		if err != nil {
			return err
		}
		collection.Close()
		return nil
	}
	readJavaRemoteParentDataHookReadiness = func(readiness *ebpf.Map) (bool, error) {
		key := uint32(0)
		var state uint32
		if err := readiness.Lookup(&key, &state); err != nil {
			return false, err
		}
		return state == 1, nil
	}
	newJavaRemoteParentFallbackServer = func(
		options javabridge.ServerOptions,
		handler javabridge.Handler,
	) (javaRemoteParentFallbackServer, error) {
		return javabridge.NewServer(options, handler)
	}
	javaRemoteParentRetryInitial = 100 * time.Millisecond
	javaRemoteParentRetryMax     = 5 * time.Second
)

type javaRemoteParentSockoptLinks struct {
	getsockopt io.Closer
	setsockopt io.Closer
}

type javaRemoteParentSockoptAttachError struct {
	attach   error
	rollback error
}

func (e *javaRemoteParentSockoptAttachError) Error() string {
	return errors.Join(e.attach, e.rollback).Error()
}

func (e *javaRemoteParentSockoptAttachError) Unwrap() []error {
	if e.rollback == nil {
		return []error{e.attach}
	}
	return []error{e.attach, e.rollback}
}

func (l javaRemoteParentSockoptLinks) Close() error {
	return errors.Join(l.getsockopt.Close(), l.setsockopt.Close())
}

func attachJavaRemoteParentSockopt(getsockopt, setsockopt *ebpf.Program) (io.Closer, error) {
	getLink, err := attachCgroupGetsockopt(getsockopt)
	if err != nil {
		return nil, err
	}

	setLink, err := attachCgroupSetsockopt(setsockopt)
	if err != nil {
		return nil, &javaRemoteParentSockoptAttachError{
			attach:   err,
			rollback: getLink.Close(),
		}
	}

	return javaRemoteParentSockoptLinks{getsockopt: getLink, setsockopt: setLink}, nil
}

type javaRemoteParentStatLabel struct {
	transport string
	operation string
	status    string
}

var javaRemoteParentStatLabels = [javaRemoteParentStatCount]javaRemoteParentStatLabel{
	{transport: "tcp", operation: "stage", status: "valid"},
	{transport: "tcp", operation: "stage", status: "ambiguous"},
	{transport: "tcp", operation: "stage", status: "malformed"},
	{transport: "tcp", operation: "stage", status: "overload"},
	{transport: "getsockopt", operation: "take", status: "valid"},
	{transport: "getsockopt", operation: "take", status: "missing"},
	{transport: "getsockopt", operation: "take", status: "stale"},
	{transport: "getsockopt", operation: "take", status: "ambiguous"},
	{transport: "getsockopt", operation: "take", status: "unauthorized"},
	{transport: "getsockopt", operation: "take", status: "already_consumed"},
	{transport: "getsockopt", operation: "take", status: "malformed"},
	{transport: "getsockopt", operation: "take", status: "overload"},
	{transport: "getsockopt", operation: "discard", status: "valid"},
	{transport: "getsockopt", operation: "discard", status: "missing"},
	{transport: "getsockopt", operation: "discard", status: "stale"},
	{transport: "getsockopt", operation: "discard", status: "ambiguous"},
	{transport: "getsockopt", operation: "discard", status: "unauthorized"},
	{transport: "getsockopt", operation: "discard", status: "already_consumed"},
	{transport: "getsockopt", operation: "discard", status: "malformed"},
	{transport: "getsockopt", operation: "discard", status: "overload"},
	{transport: "getsockopt", operation: "negotiate", status: "missing"},
	{transport: "getsockopt", operation: "negotiate", status: "unauthorized"},
	{transport: "getsockopt", operation: "negotiate", status: "overload"},
	{transport: "tcp", operation: "candidate", status: "ambiguous"},
	{transport: "tcp", operation: "candidate", status: "overload"},
	{transport: "tcp", operation: "handoff", status: "valid"},
	{transport: "tcp", operation: "candidate", status: "valid"},
	{transport: "tcp", operation: "candidate", status: "malformed"},
	{transport: "tcp", operation: "inject", status: "valid"},
	{transport: "tcp", operation: "inject", status: "missing"},
	{transport: "tcp", operation: "inject", status: "stale"},
	{transport: "tcp", operation: "inject", status: "ambiguous"},
	{transport: "tcp", operation: "inject", status: "malformed"},
	{transport: "tcp", operation: "inject", status: "overload"},
	{transport: "tcp", operation: "inject", status: "segmented"},
}

func (p *Tracer) loadJavaRemoteParentSpecs() {
	p.javaRemoteParentLoaded = false
	p.javaRemoteParentMapsLoaded = false
	p.javaRemoteParentSpec = nil
	p.javaRemoteParentMapsSpec = nil
	p.javaRemoteParentError = nil
	p.javaRemoteParentErrorStage = ""
	p.javaRemoteParentMapsError = nil

	transport := p.cfg.Java.RemoteParent.Transport
	if !p.javaRemoteParentEnabled {
		return
	}

	mapsSpec, err := LoadBpfJavaRemoteParentMaps()
	if err != nil {
		p.javaRemoteParentMapsError = err
		return
	}
	p.javaRemoteParentMapsSpec = mapsSpec
	if transport == obi.JavaRemoteParentUnix {
		return
	}

	if err := haveCgroupSockopt(); err != nil {
		p.javaRemoteParentError = err
		p.javaRemoteParentErrorStage = javaRemoteParentStageProbe
		return
	}

	spec, err := LoadBpfJavaRemoteParent()
	if err != nil {
		p.javaRemoteParentError = err
		p.javaRemoteParentErrorStage = javaRemoteParentStageLoad
		return
	}
	constants := p.javaRemoteParentConstants()
	if err := validateCgroupSockoptSpec(spec, constants); err != nil {
		p.javaRemoteParentError = err
		p.javaRemoteParentErrorStage = javaRemoteParentStageLoad
		return
	}

	p.javaRemoteParentSpec = spec
}

func (p *Tracer) loadJavaRemoteParentObjects(eventContext *ebpfcommon.EBPFEventContext) {
	if !p.javaRemoteParentEnabled || eventContext == nil ||
		p.javaRemoteParentMapsSpec == nil {
		return
	}

	ebpfconvenience.SetupMapSizes(
		p.javaRemoteParentMapsSpec,
		p.cfg.EBPF.MapsConfig.GlobalScaleFactor,
	)
	if err := ebpfconvenience.LoadSpec(
		p.javaRemoteParentMapsSpec,
		&p.bpfJavaRemoteParentMaps,
		nil,
		eventContext.EBPFMaps,
		&eventContext.MapsLock,
		"",
		nil,
	); err != nil {
		p.javaRemoteParentMapsError = err
		return
	}
	p.javaRemoteParentMapsLoaded = true

	if p.javaRemoteParentSpec == nil {
		return
	}
	ebpfconvenience.SetupMapSizes(
		p.javaRemoteParentSpec,
		p.cfg.EBPF.MapsConfig.GlobalScaleFactor,
	)
	if err := ebpfconvenience.LoadSpec(
		p.javaRemoteParentSpec,
		&p.bpfJavaRemoteParent,
		p.javaRemoteParentConstants(),
		eventContext.EBPFMaps,
		&eventContext.MapsLock,
		"",
		nil,
	); err != nil {
		p.javaRemoteParentError = err
		p.javaRemoteParentErrorStage = javaRemoteParentStageLoad
		return
	}
	p.javaRemoteParentLoaded = true
}

func (p *Tracer) javaRemoteParentConstants() map[string]any {
	filterPids := int32(1)
	if p.cfg.Discovery.BPFPidFilterOff {
		filterPids = 0
	}

	return map[string]any{
		"filter_pids":                   filterPids,
		"g_bpf_debug":                   p.cfg.EBPF.BpfDebug,
		"java_remote_parent_enabled":    p.javaRemoteParentEnabled,
		"java_remote_parent_max_age_ns": uint64(p.cfg.Java.RemoteParent.TTL.Nanoseconds()),
	}
}

func (p *Tracer) runJavaRemoteParent(ctx context.Context) func() {
	if !p.cfg.Java.RemoteParent.Enabled() {
		p.observeJavaRemoteParent("disabled", "select", javabridge.StatusDisabled, 1)
		return func() {}
	}
	if p.javaRemoteParentSupportErr != nil {
		p.reportJavaRemoteParentTransportsUnavailable(
			"Java remote-parent bridge unavailable",
			javaRemoteParentStageProbe,
			p.javaRemoteParentSupportErr,
		)
		return func() {}
	}

	if p.javaRemoteParentMapsError != nil || !p.javaRemoteParentMapsLoaded {
		p.reportJavaRemoteParentTransportsUnavailable(
			"Java remote-parent shared maps unavailable",
			javaRemoteParentStageLoad,
			p.javaRemoteParentMapsError,
		)
		return func() {}
	}
	maps := p.javaRemoteParentMaps()
	handler := javabridge.NewMapHandler(maps, p.cfg.Java.RemoteParent.TTL)
	cleanup := javabridge.NewCleanup(maps, p.cfg.Java.RemoteParent.TTL)
	lifecycleCtx, cancel := context.WithCancel(ctx)

	statsDone := make(chan struct{})
	go func() {
		defer close(statsDone)
		p.reportJavaRemoteParentStats(lifecycleCtx)
	}()
	cleanupDone := make(chan struct{})
	go func() {
		defer close(cleanupDone)
		p.runJavaRemoteParentCleanup(lifecycleCtx, cleanup)
	}()
	transportsDone := make(chan struct{})
	go func() {
		defer close(transportsDone)
		p.runJavaRemoteParentTransports(lifecycleCtx, handler)
	}()

	var stopOnce sync.Once
	return func() {
		stopOnce.Do(func() {
			cancel()
			<-transportsDone
			<-statsDone
			<-cleanupDone
			p.closeJavaRemoteParentObjects()
		})
	}
}

func (p *Tracer) reportJavaRemoteParentTransportsUnavailable(
	message string,
	stage javaRemoteParentAvailabilityStage,
	err error,
) {
	reason := p.logJavaRemoteParentUnavailable(message, stage, err)
	transport := p.cfg.Java.RemoteParent.Transport
	if transport == obi.JavaRemoteParentAuto || transport == obi.JavaRemoteParentGetsockopt {
		p.observeJavaRemoteParentResult(
			"getsockopt", javaRemoteParentAvailabilityOperation, reason, 1,
		)
	}
	if transport == obi.JavaRemoteParentAuto || transport == obi.JavaRemoteParentUnix {
		p.observeJavaRemoteParentResult(
			"unix", javaRemoteParentAvailabilityOperation, reason, 1,
		)
	}
}

func (p *Tracer) reportJavaRemoteParentTransportUnavailable(
	message string,
	transport string,
	stage javaRemoteParentAvailabilityStage,
	err error,
) {
	reason := p.logJavaRemoteParentUnavailable(message, stage, err)
	p.observeJavaRemoteParentResult(
		transport, javaRemoteParentAvailabilityOperation, reason, 1,
	)
}

func (p *Tracer) logJavaRemoteParentUnavailable(
	message string,
	stage javaRemoteParentAvailabilityStage,
	err error,
) string {
	reason := javaRemoteParentAvailabilityReason(stage, err)
	p.log.Warn(
		message,
		"stage", string(stage),
		"reason", reason,
		"error", err,
	)
	return reason
}

func (p *Tracer) runJavaRemoteParentTransports(
	ctx context.Context,
	handler *javabridge.MapHandler,
) {
	if !p.waitForJavaRemoteParentDataHook(ctx) {
		return
	}

	var primary io.Closer
	if p.javaRemoteParentLoaded {
		var err error
		primary, err = attachJavaRemoteParentSockopt(
			p.bpfJavaRemoteParent.ObiJavaRemoteParentGetsockopt,
			p.bpfJavaRemoteParent.ObiJavaRemoteParentSetsockopt,
		)
		if err != nil {
			p.javaRemoteParentError = err
			p.javaRemoteParentErrorStage = javaRemoteParentStageAttach
		}
	}

	if p.javaRemoteParentError != nil {
		p.reportJavaRemoteParentTransportUnavailable(
			"Java remote-parent getsockopt transport unavailable",
			"getsockopt",
			p.javaRemoteParentErrorStage,
			p.javaRemoteParentError,
		)
	}
	server, serverDone := p.startJavaRemoteParentFallback(ctx, handler)
	selected := obi.JavaRemoteParentUnix
	if primary != nil {
		selected = obi.JavaRemoteParentGetsockopt
	} else if server == nil && !p.javaRemoteParentFallbackEnabled() {
		return
	}
	if primary != nil || server != nil {
		p.reportJavaRemoteParentReady(selected)
	}

	retryDelay := javaRemoteParentRetryInitial
	recoveringFallback := server == nil && p.javaRemoteParentFallbackEnabled()
	for {
		var retry <-chan time.Time
		var retryTimer *time.Timer
		if server == nil && p.javaRemoteParentFallbackEnabled() {
			retryTimer = time.NewTimer(retryDelay)
			retry = retryTimer.C
		}

		select {
		case <-ctx.Done():
			if retryTimer != nil {
				retryTimer.Stop()
			}
			if primary != nil {
				if err := primary.Close(); err != nil {
					p.log.Debug("closing Java remote-parent getsockopt transport", "error", err)
				}
			}
			p.closeJavaRemoteParentFallback(server, serverDone)
			return
		case serveErr, ok := <-serverDone:
			if retryTimer != nil {
				retryTimer.Stop()
			}
			if ctx.Err() != nil {
				if primary != nil {
					if err := primary.Close(); err != nil {
						p.log.Debug("closing Java remote-parent getsockopt transport", "error", err)
					}
				}
				p.closeJavaRemoteParentFallback(server, nil)
				return
			}
			if !ok || serveErr == nil {
				serveErr = errors.New("java remote-parent fallback stopped unexpectedly")
			}
			p.closeJavaRemoteParentFallback(server, nil)
			server = nil
			serverDone = nil
			recoveringFallback = true
			p.reportJavaRemoteParentTransportUnavailable(
				"Java remote-parent fallback transport stopped",
				"unix",
				javaRemoteParentStageServe,
				serveErr,
			)
			retryDelay = nextJavaRemoteParentRetryDelay(retryDelay)
		case <-retry:
			server, serverDone = p.startJavaRemoteParentFallback(ctx, handler)
			if server == nil {
				recoveringFallback = true
				retryDelay = nextJavaRemoteParentRetryDelay(retryDelay)
				continue
			}
			if recoveringFallback {
				p.log.Info("Java remote-parent fallback transport recovered")
				p.observeJavaRemoteParent("unix", "select", javabridge.StatusValid, 1)
			}
			recoveringFallback = false
			retryDelay = javaRemoteParentRetryInitial
		}
	}
}

func javaRemoteParentAvailabilityReason(
	stage javaRemoteParentAvailabilityStage,
	err error,
) string {
	var attachErr *javaRemoteParentSockoptAttachError
	if errors.As(err, &attachErr) {
		err = attachErr.attach
	}

	var verifierErr *ebpf.VerifierError
	if errors.As(err, &verifierErr) && len(verifierErr.Log) > 0 {
		return javaRemoteParentStatusVerifierRejected
	}
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		if stage == javaRemoteParentStageLoad {
			return javaRemoteParentStatusLoadDenied
		}
		return javaRemoteParentStatusPermissionDenied
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, unix.ETIMEDOUT) {
		return javabridge.StatusTimeout.String()
	}
	if errors.Is(err, unix.ENOBUFS) || errors.Is(err, unix.ENOMEM) ||
		errors.Is(err, unix.ENOSPC) || errors.Is(err, unix.EMFILE) ||
		errors.Is(err, unix.ENFILE) {
		return javabridge.StatusOverload.String()
	}
	if errors.Is(err, ebpf.ErrNotSupported) || errors.Is(err, unix.ENOPROTOOPT) ||
		errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, unix.ENOSYS) {
		return javabridge.StatusUnsupported.String()
	}
	if err == nil || errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) {
		return javabridge.StatusMissing.String()
	}
	return javabridge.StatusTransportError.String()
}

func nextJavaRemoteParentRetryDelay(current time.Duration) time.Duration {
	if current >= javaRemoteParentRetryMax/2 {
		return javaRemoteParentRetryMax
	}
	return current * 2
}

func (p *Tracer) javaRemoteParentFallbackEnabled() bool {
	transport := p.cfg.Java.RemoteParent.Transport
	return transport == obi.JavaRemoteParentAuto || transport == obi.JavaRemoteParentUnix
}

func (p *Tracer) reportJavaRemoteParentReady(transport obi.JavaRemoteParentTransport) {
	p.log.Info(
		"Java remote parent bridge ready",
		"transport", transport,
		"socket_path", p.cfg.Java.RemoteParent.SocketPath,
	)
	p.observeJavaRemoteParent(string(transport), "select", javabridge.StatusValid, 1)
}

func (p *Tracer) closeJavaRemoteParentFallback(
	server javaRemoteParentFallbackServer,
	done <-chan error,
) {
	if server != nil {
		if err := server.Close(); err != nil {
			p.log.Debug("closing Java remote-parent fallback transport", "error", err)
		}
	}
	if done != nil {
		<-done
	}
}

func (p *Tracer) waitForJavaRemoteParentDataHook(ctx context.Context) bool {
	reportedUnavailable := false
	ticker := time.NewTicker(javaRemoteParentReadinessPollInterval)
	defer ticker.Stop()

	for {
		ready, err := p.javaRemoteParentDataHookReady()
		if ready {
			return true
		}
		if !reportedUnavailable {
			reportedUnavailable = true
			p.reportJavaRemoteParentTransportsUnavailable(
				"Java remote-parent transports waiting for authoritative data hook",
				javaRemoteParentStageReadiness,
				err,
			)
		}

		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}

func (p *Tracer) javaRemoteParentDataHookReady() (bool, error) {
	readiness := p.bpfJavaRemoteParentMaps.JavaRemoteParentDataHookReadiness
	if readiness == nil {
		return false, errors.New("java remote-parent data-hook readiness map is unavailable")
	}
	return readJavaRemoteParentDataHookReadiness(readiness)
}

func (p *Tracer) closeJavaRemoteParentObjects() {
	if p.javaRemoteParentLoaded {
		if err := p.bpfJavaRemoteParent.Close(); err != nil {
			p.log.Debug("closing Java remote-parent primary objects", "error", err)
		}
		p.javaRemoteParentLoaded = false
	}
	if p.javaRemoteParentMapsLoaded {
		if err := p.bpfJavaRemoteParentMaps.Close(); err != nil {
			p.log.Debug("closing Java remote-parent shared maps", "error", err)
		}
		p.javaRemoteParentMapsLoaded = false
	}
}

func (p *Tracer) startJavaRemoteParentFallback(
	ctx context.Context,
	handler javabridge.Handler,
) (javaRemoteParentFallbackServer, <-chan error) {
	transport := p.cfg.Java.RemoteParent.Transport
	if transport != obi.JavaRemoteParentAuto && transport != obi.JavaRemoteParentUnix {
		return nil, nil
	}
	ready, err := p.javaRemoteParentDataHookReady()
	if err != nil || !ready {
		p.reportJavaRemoteParentTransportUnavailable(
			"Java remote-parent fallback transport blocked by unavailable data hook",
			"unix",
			javaRemoteParentStageReadiness,
			err,
		)
		return nil, nil
	}
	server, err := newJavaRemoteParentFallbackServer(javabridge.ServerOptions{
		SocketPath: p.cfg.Java.RemoteParent.SocketPath,
		SocketGID:  p.cfg.Java.RemoteParent.SocketGroupID,
		Timeout:    p.cfg.Java.RemoteParent.Timeout,
		Log:        p.log,
		Observe: func(operation javabridge.Operation, status javabridge.Status) {
			p.observeJavaRemoteParent("unix", operation.String(), status, 1)
		},
	}, handler)
	if err != nil {
		p.reportJavaRemoteParentTransportUnavailable(
			"Java remote-parent fallback transport unavailable",
			"unix",
			javaRemoteParentStageListen,
			err,
		)
		return nil, nil
	}

	done := make(chan error, 1)
	go func() {
		done <- server.Serve(ctx)
		close(done)
	}()

	return server, done
}

func (p *Tracer) javaRemoteParentMaps() javabridge.Maps {
	return javabridge.Maps{
		RemoteParents:     p.bpfJavaRemoteParentMaps.JavaRemoteParentFallback,
		Tasks:             p.bpfJavaRemoteParentMaps.JavaRemoteParentTasks,
		VirtualThreads:    p.bpfJavaRemoteParentMaps.JavaVtThreads,
		VTIdentities:      p.bpfJavaRemoteParentMaps.JavaVtIdentities,
		Authorized:        p.bpfJavaRemoteParentMaps.JavaAuthorizedProcesses,
		Incarnations:      p.bpfJavaRemoteParentMaps.JavaProcessIncarnations,
		Connections:       p.bpfJavaRemoteParentMaps.JavaRemoteParentConnections,
		CookieConnections: p.bpfJavaRemoteParentMaps.JavaRemoteParentCookieConnections,
		Ambiguity:         p.bpfJavaRemoteParentMaps.JavaRemoteParentAmbiguity,
		Owners:            p.bpfJavaRemoteParentMaps.JavaRemoteParentOwners,
		States:            p.bpfJavaRemoteParentMaps.JavaRemoteParentState,
		Generations:       p.bpfJavaRemoteParentMaps.JavaRemoteParentGenerationIndex,
		Terminals:         p.bpfJavaRemoteParentMaps.JavaRemoteParentTerminal,
		Claims:            p.bpfJavaRemoteParentMaps.JavaRemoteParentClaims,
		Handoffs:          p.bpfJavaRemoteParentMaps.JavaRemoteParentHandoffs,
		HandoffClaims:     p.bpfJavaRemoteParentMaps.JavaRemoteParentHandoffClaims,
		Retired:           p.bpfJavaRemoteParentMaps.JavaRetiredProcesses,
		SSLPrewriteTP:     p.bpfJavaRemoteParentMaps.SslPrewriteTp,
		SSLPrewriteConnectionAmbiguity: p.bpfJavaRemoteParentMaps.
			SslPrewriteConnectionAmbiguity,
		SSLPrewriteConnectionClaims: p.bpfJavaRemoteParentMaps.SslPrewriteConnectionClaims,
		SSLPrewriteConnectionOwners: p.bpfJavaRemoteParentMaps.SslPrewriteConnectionOwners,
	}
}

func (p *Tracer) runJavaRemoteParentCleanup(ctx context.Context, cleanup *javabridge.Cleanup) {
	interval := p.cfg.Java.RemoteParent.TTL / 2
	if interval <= 0 || interval > javaRemoteParentPollInterval {
		interval = javaRemoteParentPollInterval
	}
	if interval < 100*time.Millisecond {
		interval = 100 * time.Millisecond
	}

	sweep := func() {
		stats, err := cleanup.SweepWithStats()
		p.reportJavaRemoteParentCleanup(stats, err)
	}
	sweep()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			sweep()
			return
		case <-ticker.C:
			sweep()
		case <-p.javaRemoteParentSweep:
			sweep()
		}
	}
}

func (p *Tracer) reportJavaRemoteParentCleanup(stats javabridge.CleanupStats, err error) {
	if stats.Cleaned != 0 {
		p.observeJavaRemoteParent("tcp", "cleanup", javabridge.StatusValid, stats.Cleaned)
	}
	if stats.Evicted != 0 {
		p.observeJavaRemoteParent("tcp", "evict", javabridge.StatusValid, stats.Evicted)
	}
	if err != nil {
		p.log.Debug("cleaning stale Java remote-parent state", "error", err)
		p.observeJavaRemoteParent("tcp", "cleanup", javabridge.StatusTransportError, 1)
	}
}

func (p *Tracer) reportJavaRemoteParentStats(ctx context.Context) {
	if p.metrics == nil || p.bpfJavaRemoteParentMaps.JavaRemoteParentStats == nil {
		return
	}

	var previous [javaRemoteParentStatCount]uint64
	report := func() {
		current, err := readJavaRemoteParentStats(p.bpfJavaRemoteParentMaps.JavaRemoteParentStats)
		if err != nil {
			p.log.Debug("reading Java remote-parent counters", "error", err)
			return
		}
		p.reportJavaRemoteParentStatDeltas(previous, current)
		previous = current
	}

	report()
	interval := p.javaRemoteParentMetricsPollInterval()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			report()
			return
		case <-ticker.C:
			report()
		}
	}
}

func (p *Tracer) javaRemoteParentMetricsPollInterval() time.Duration {
	interval := p.metrics.BpfInternalMetricsScrapeInterval()
	if interval <= 0 {
		return javaRemoteParentPollInterval
	}
	return interval
}

func (p *Tracer) reportJavaRemoteParentStatDeltas(
	previous, current [javaRemoteParentStatCount]uint64,
) {
	for index, value := range current {
		delta := value
		if value >= previous[index] {
			delta = value - previous[index]
		}
		if delta != 0 {
			label := javaRemoteParentStatLabels[index]
			p.metrics.JavaRemoteParent(
				label.transport, label.operation, label.status, delta,
			)
		}
	}
	// Publish the marker after every successful pass, including passes with no counter changes.
	p.metrics.JavaRemoteParent("tcp", "report", javabridge.StatusValid.String(), 1)
}

func readJavaRemoteParentStats(stats *ebpf.Map) ([javaRemoteParentStatCount]uint64, error) {
	var totals [javaRemoteParentStatCount]uint64
	possibleCPUs, err := ebpf.PossibleCPU()
	if err != nil {
		return totals, err
	}

	values := make([]uint64, possibleCPUs)
	for index := range totals {
		clear(values)
		key := uint32(index)
		if err := stats.Lookup(&key, &values); err != nil {
			return totals, err
		}
		for _, value := range values {
			totals[index] += value
		}
	}

	return totals, nil
}

func (p *Tracer) observeJavaRemoteParent(
	transport string,
	operation string,
	status javabridge.Status,
	count uint64,
) {
	p.observeJavaRemoteParentResult(transport, operation, status.String(), count)
}

func (p *Tracer) observeJavaRemoteParentResult(
	transport string,
	operation string,
	status string,
	count uint64,
) {
	if p.metrics != nil {
		p.metrics.JavaRemoteParent(transport, operation, status, count)
	}
}
