// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestPythonAgentLoaderLifecycle(t *testing.T) {
	tracer := &Tracer{log: tlog(), cfg: &obi.Config{EBPF: config.EBPFTracer{
		ContextPropagation: config.ContextPropagationHeaders,
	}}}
	started := make(chan uint64, 3)
	stopped := make(chan uint64, 3)
	loader := pythonAgentLoader{enabled: true, inject: func(ctx context.Context, _ app.PID, start uint64) error {
		started <- start
		<-ctx.Done()
		stopped <- start
		return ctx.Err()
	}}
	t.Cleanup(loader.close)
	first := pythonRuntimeTestFile(123, 100)
	loader.allow(tracer, 123, first, first)
	require.Equal(t, uint64(100), receivePythonAgentLifecycle(t, started))
	loader.allow(tracer, 123, first, first)
	require.Empty(t, started)
	second := pythonRuntimeTestFile(123, 200)
	loader.allow(tracer, 123, second, second)
	require.Equal(t, uint64(100), receivePythonAgentLifecycle(t, stopped))
	require.Equal(t, uint64(200), receivePythonAgentLifecycle(t, started))
	loader.block(123, first)
	require.Empty(t, stopped)
	loader.block(123, second)
	require.Equal(t, uint64(200), receivePythonAgentLifecycle(t, stopped))
	loader.close()
	loader.allow(tracer, 123, first, first)
	require.Empty(t, started)
}

func TestPythonAgentLoaderDisabled(t *testing.T) {
	tracer := &Tracer{log: tlog(), cfg: &obi.Config{}}
	loader := pythonAgentLoader{enabled: true, inject: func(context.Context, app.PID, uint64) error {
		t.Error("disabled propagation must not load the agent")
		return nil
	}}
	t.Cleanup(loader.close)
	target := pythonRuntimeTestFile(123, 100)
	loader.allow(tracer, 123, target, target)
	require.Empty(t, loader.targets)
	tracer.cfg.EBPF.ContextPropagation = config.ContextPropagationHeaders
	loader.enabled = false
	loader.allow(tracer, 123, target, target)
	require.Empty(t, loader.targets)
}

func receivePythonAgentLifecycle(t *testing.T, changes <-chan uint64) uint64 {
	t.Helper()
	select {
	case start := <-changes:
		return start
	case <-time.After(5 * time.Second):
		t.Fatal("Python agent lifecycle did not advance")
		return 0
	}
}
