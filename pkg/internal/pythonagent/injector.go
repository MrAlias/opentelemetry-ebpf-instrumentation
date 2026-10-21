// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pythonagent // import "go.opentelemetry.io/obi/pkg/internal/pythonagent"

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf"
	ebpfcommon "go.opentelemetry.io/obi/pkg/ebpf/common"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/obi"
)

type Injector struct {
	log     *slog.Logger
	enabled bool
}

func NewInjector(cfg *obi.Config) *Injector {
	log := slog.With("component", "pythonagent.Injector")
	return &Injector{
		log: log,
		enabled: attachmentSupported && cfg.EBPF.ContextPropagation.HasHeaders() &&
			(cfg.Traces.Enabled() || cfg.TracePrinter.Enabled()) &&
			!ebpfcommon.IntegrityModeOverride && ebpfcommon.SupportsContextPropagationWithProbe(log),
	}
}

func (i *Injector) Enabled() bool {
	return i.enabled
}

func (i *Injector) Accepts(instrumentable *ebpf.Instrumentable) bool {
	return i.enabled && instrumentable.Type == svc.InstrumentablePython
}

// InjectionTarget keeps the discovered process incarnation pinned while queued.
type InjectionTarget struct {
	Pid     app.PID
	Process *procs.ProcessHandle
}

func InjectionTargetFrom(instrumentable *ebpf.Instrumentable) (InjectionTarget, error) {
	pid := instrumentable.FileInfo.Pid()
	process, err := procs.OpenProcessHandle(pid, instrumentable.FileInfo.StartTime())
	if err != nil {
		return InjectionTarget{}, err
	}
	return InjectionTarget{Pid: pid, Process: process}, nil
}

func (target InjectionTarget) PID() app.PID {
	return target.Pid
}

func (target InjectionTarget) Close() error {
	if target.Process == nil {
		return nil
	}
	return target.Process.Close()
}

func (i *Injector) Inject(ctx context.Context, target InjectionTarget) {
	if err := ctx.Err(); err != nil {
		return
	}
	if err := target.Process.Alive(); err != nil {
		i.log.Debug("Python process is gone, skipping requests instrumentation", "pid", target.Pid, "error", err)
		return
	}
	if err := attach(ctx, target.Process); err != nil {
		i.log.Warn("unable to load Python requests.Session instrumentation", "pid", target.Pid, "error", err)
		return
	}
	i.log.Info("Python requests.Session instrumentation loaded", "pid", target.Pid)
}
