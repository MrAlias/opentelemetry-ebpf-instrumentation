// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/config/configretry"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/exporter/otlpexporter"
	"go.opentelemetry.io/collector/exporter/otlphttpexporter"
	"go.opentelemetry.io/collector/pdata/ptrace"

	"go.opentelemetry.io/obi/pkg/export/otel/otelcfg"
)

type deadlineCapturingTracesExporter struct {
	deadlines chan time.Time
}

type retryDeadlineCapturingTracesExporter struct {
	deadlines chan time.Time
	attempts  atomic.Int32
}

type blockingDeadlineCapturingTracesExporter struct {
	deadlines chan time.Time
}

func traceExportTimeoutPointer(timeout time.Duration) *otelcfg.TraceExportTimeout {
	converted := otelcfg.TraceExportTimeout(timeout)
	return &converted
}

func (*deadlineCapturingTracesExporter) Start(context.Context, component.Host) error { return nil }

func (*deadlineCapturingTracesExporter) Shutdown(context.Context) error { return nil }

func (*deadlineCapturingTracesExporter) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{}
}

func (e *deadlineCapturingTracesExporter) ConsumeTraces(ctx context.Context, _ ptrace.Traces) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("export context has no deadline")
	}
	e.deadlines <- deadline
	return nil
}

func (*retryDeadlineCapturingTracesExporter) Start(context.Context, component.Host) error {
	return nil
}

func (*retryDeadlineCapturingTracesExporter) Shutdown(context.Context) error { return nil }

func (*retryDeadlineCapturingTracesExporter) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{}
}

func (e *retryDeadlineCapturingTracesExporter) ConsumeTraces(
	ctx context.Context,
	_ ptrace.Traces,
) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("export context has no deadline")
	}
	e.deadlines <- deadline
	if e.attempts.Add(1) != 1 {
		return nil
	}

	timer := time.NewTimer(200 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return errors.New("retry first attempt")
	}
}

func (*blockingDeadlineCapturingTracesExporter) Start(context.Context, component.Host) error {
	return nil
}

func (*blockingDeadlineCapturingTracesExporter) Shutdown(context.Context) error { return nil }

func (*blockingDeadlineCapturingTracesExporter) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{}
}

func (e *blockingDeadlineCapturingTracesExporter) ConsumeTraces(
	ctx context.Context,
	_ ptrace.Traces,
) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("export context has no deadline")
	}
	e.deadlines <- deadline
	<-ctx.Done()
	return ctx.Err()
}

func TestConfigureHTTPTraceClient(t *testing.T) {
	newConfig := func(t *testing.T) *otlphttpexporter.Config {
		t.Helper()
		config, ok := otlphttpexporter.NewFactory().CreateDefaultConfig().(*otlphttpexporter.Config)
		require.True(t, ok)
		return config
	}
	opts := otelcfg.OTLPOptions{
		Scheme:      "http",
		Endpoint:    "collector:4318",
		BaseURLPath: "/base",
		Insecure:    true,
	}

	t.Run("preserves existing effective default", func(t *testing.T) {
		config := newConfig(t)

		configureHTTPTraceClient(config, otelcfg.TracesConfig{}, opts)

		assert.Equal(t, "http://collector:4318/base", config.ClientConfig.Endpoint)
		assert.True(t, config.ClientConfig.TLS.Insecure)
		assert.Equal(t, 5*time.Second, config.ClientConfig.Timeout)
	})

	t.Run("overrides export timeout", func(t *testing.T) {
		config := newConfig(t)
		configureHTTPTraceClient(
			config,
			otelcfg.TracesConfig{ExportTimeout: traceExportTimeoutPointer(7 * time.Second)},
			opts,
		)
		assert.Equal(t, 7*time.Second, config.ClientConfig.Timeout)
	})
}

func TestConfigureGRPCTraceClient(t *testing.T) {
	newConfig := func(t *testing.T) *otlpexporter.Config {
		t.Helper()
		config, ok := otlpexporter.NewFactory().CreateDefaultConfig().(*otlpexporter.Config)
		require.True(t, ok)
		return config
	}
	opts := otelcfg.OTLPOptions{Insecure: true}

	t.Run("preserves existing effective default", func(t *testing.T) {
		config := newConfig(t)
		configureGRPCTraceClient(config, otelcfg.TracesConfig{}, opts, "collector:4317")

		assert.Equal(t, "collector:4317", config.ClientConfig.Endpoint)
		assert.True(t, config.ClientConfig.TLS.Insecure)
		assert.Equal(t, 5*time.Second, config.TimeoutConfig.Timeout)
	})

	t.Run("overrides export timeout", func(t *testing.T) {
		config := newConfig(t)
		configureGRPCTraceClient(
			config,
			otelcfg.TracesConfig{ExportTimeout: traceExportTimeoutPointer(7 * time.Second)},
			opts,
			"collector:4317",
		)
		assert.Equal(t, 7*time.Second, config.TimeoutConfig.Timeout)
	})
}

func TestQueueInstrumentedTracesUsesEffectiveTimeout(t *testing.T) {
	const effectiveTimeout = 8 * time.Second

	base := &deadlineCapturingTracesExporter{deadlines: make(chan time.Time, 1)}
	retryCfg := configretry.NewDefaultBackOffConfig()
	retryCfg.Enabled = false
	wrapped, err := queueInstrumentedTraces(
		t.Context(),
		getTraceSettings(component.MustNewType("timeouttest"), ""),
		otelcfg.TracesConfig{},
		nil,
		base,
		configoptional.None[exporterhelper.QueueBatchConfig](),
		retryCfg,
		exporterhelper.TimeoutConfig{Timeout: effectiveTimeout},
	)
	require.NoError(t, err)
	require.NoError(t, wrapped.Start(t.Context(), emptyHost{}))
	t.Cleanup(func() { require.NoError(t, wrapped.Shutdown(t.Context())) })

	started := time.Now()
	require.NoError(t, wrapped.ConsumeTraces(t.Context(), ptrace.NewTraces()))
	finished := time.Now()
	deadline := <-base.deadlines
	assert.False(t, deadline.Before(started.Add(effectiveTimeout)))
	assert.False(t, deadline.After(finished.Add(effectiveTimeout)))
}

func TestQueueInstrumentedTracesPreservesEarlierCallerDeadline(t *testing.T) {
	base := &deadlineCapturingTracesExporter{deadlines: make(chan time.Time, 1)}
	retryCfg := configretry.NewDefaultBackOffConfig()
	retryCfg.Enabled = false
	wrapped, err := queueInstrumentedTraces(
		t.Context(),
		getTraceSettings(component.MustNewType("timeoutcallertest"), ""),
		otelcfg.TracesConfig{},
		nil,
		base,
		configoptional.None[exporterhelper.QueueBatchConfig](),
		retryCfg,
		exporterhelper.TimeoutConfig{Timeout: 8 * time.Second},
	)
	require.NoError(t, err)
	require.NoError(t, wrapped.Start(t.Context(), emptyHost{}))
	t.Cleanup(func() { require.NoError(t, wrapped.Shutdown(t.Context())) })

	callerCtx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	callerDeadline, ok := callerCtx.Deadline()
	require.True(t, ok)
	require.NoError(t, wrapped.ConsumeTraces(callerCtx, ptrace.NewTraces()))
	assert.Equal(t, callerDeadline, <-base.deadlines)
}

func TestQueueInstrumentedTracesBoundsHungAttempt(t *testing.T) {
	base := &blockingDeadlineCapturingTracesExporter{deadlines: make(chan time.Time, 1)}
	retryCfg := configretry.NewDefaultBackOffConfig()
	retryCfg.Enabled = false
	wrapped, err := queueInstrumentedTraces(
		t.Context(),
		getTraceSettings(component.MustNewType("timeouthungtest"), ""),
		otelcfg.TracesConfig{},
		nil,
		base,
		configoptional.None[exporterhelper.QueueBatchConfig](),
		retryCfg,
		exporterhelper.TimeoutConfig{Timeout: 50 * time.Millisecond},
	)
	require.NoError(t, err)
	require.NoError(t, wrapped.Start(t.Context(), emptyHost{}))
	t.Cleanup(func() { require.NoError(t, wrapped.Shutdown(t.Context())) })

	callerCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	callerDeadline, ok := callerCtx.Deadline()
	require.True(t, ok)
	require.Error(t, wrapped.ConsumeTraces(callerCtx, ptrace.NewTraces()))
	assert.True(t, (<-base.deadlines).Before(callerDeadline))
}

func TestQueueInstrumentedTracesRenewsTimeoutForRetry(t *testing.T) {
	const effectiveTimeout = time.Second

	base := &retryDeadlineCapturingTracesExporter{
		deadlines: make(chan time.Time, 2),
	}
	retryCfg := configretry.NewDefaultBackOffConfig()
	retryCfg.InitialInterval = 10 * time.Millisecond
	retryCfg.RandomizationFactor = 0
	retryCfg.Multiplier = 1
	retryCfg.MaxInterval = 10 * time.Millisecond
	retryCfg.MaxElapsedTime = 2 * time.Second
	wrapped, err := queueInstrumentedTraces(
		t.Context(),
		getTraceSettings(component.MustNewType("timeoutretrytest"), ""),
		otelcfg.TracesConfig{},
		nil,
		base,
		configoptional.None[exporterhelper.QueueBatchConfig](),
		retryCfg,
		exporterhelper.TimeoutConfig{Timeout: effectiveTimeout},
	)
	require.NoError(t, err)
	require.NoError(t, wrapped.Start(t.Context(), emptyHost{}))
	t.Cleanup(func() { require.NoError(t, wrapped.Shutdown(t.Context())) })

	require.NoError(t, wrapped.ConsumeTraces(t.Context(), ptrace.NewTraces()))
	firstDeadline := <-base.deadlines
	secondDeadline := <-base.deadlines
	assert.Greater(t, secondDeadline.Sub(firstDeadline), 150*time.Millisecond)
}
