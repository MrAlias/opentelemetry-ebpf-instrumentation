// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer // import "go.opentelemetry.io/obi/pkg/internal/ebpf/generictracer"

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/cpython/agent"
)

type pythonAgentTarget struct {
	startTime uint64
	cancel    context.CancelFunc
}

type pythonAgentLoader struct {
	enabled bool
	inject  func(context.Context, app.PID, uint64) error
	mu      sync.Mutex
	targets map[app.PID]pythonAgentTarget
	closed  bool
	wg      sync.WaitGroup
}

func (l *pythonAgentLoader) allow(tracer *Tracer, pid app.PID, lifecycle, source *exec.FileInfo) {
	if !l.enabled || lifecycle == nil || source == nil || source.SDKLanguage() != svc.InstrumentablePython ||
		!tracer.cfg.EBPF.ContextPropagation.HasHeaders() || lifecycle.StartTime() == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	if target, ok := l.targets[pid]; ok {
		if target.startTime == lifecycle.StartTime() {
			return
		}
		target.cancel()
	}
	if l.targets == nil {
		l.targets = map[app.PID]pythonAgentTarget{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	l.targets[pid] = pythonAgentTarget{startTime: lifecycle.StartTime(), cancel: cancel}
	inject := l.inject
	if inject == nil {
		inject = agent.Inject
	}
	l.wg.Go(func() {
		defer cancel()
		if err := inject(ctx, pid, lifecycle.StartTime()); err != nil {
			tracer.log.Debug("Python HTTPX agent loading failed", "pid", pid, "error", err)
			return
		}
		tracer.log.Info("Python HTTPX asyncio HTTP/1.1 agent installed", "pid", pid)
	})
}

func (l *pythonAgentLoader) block(pid app.PID, lifecycle *exec.FileInfo) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if target, ok := l.targets[pid]; ok && lifecycle != nil && target.startTime == lifecycle.StartTime() {
		target.cancel()
		delete(l.targets, pid)
	}
}

func (l *pythonAgentLoader) close() {
	l.mu.Lock()
	l.closed = true
	for _, target := range l.targets {
		target.cancel()
	}
	l.mu.Unlock()
	l.wg.Wait()
}
