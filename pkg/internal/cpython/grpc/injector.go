// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package grpc // import "go.opentelemetry.io/obi/pkg/internal/cpython/grpc"

import (
	"context"
	_ "embed"
	"log/slog"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/ebpf"
	cpython "go.opentelemetry.io/obi/pkg/internal/cpython/runtime"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

//go:embed agent.py
var agent string

type InjectionTarget struct {
	Process   *procs.ProcessHandle
	StartTime uint64
}

func InjectionTargetFrom(ie *ebpf.Instrumentable) (InjectionTarget, error) {
	process, err := procs.OpenProcessHandle(ie.FileInfo.Pid(), ie.FileInfo.StartTime())
	return InjectionTarget{Process: process, StartTime: ie.FileInfo.StartTime()}, err
}

func (t InjectionTarget) PID() app.PID { return t.Process.PID() }
func (t InjectionTarget) Close() error { return t.Process.Close() }

type Injector struct{ resolver *cpython.Resolver }

func NewInjector() *Injector { return &Injector{resolver: cpython.NewResolver()} }

func (i *Injector) Inject(ctx context.Context, target InjectionTarget) {
	if err := i.attach(ctx, target); err != nil {
		slog.Debug("unable to attach Python gRPC agent", "pid", target.PID(), "error", err)
		return
	}
	slog.Info("Python gRPC agent attached", "pid", target.PID())
}
