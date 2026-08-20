// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package imetrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/internal/avoidedsvc"
)

func TestIsBuiltinNoopReporter(t *testing.T) {
	t.Run("noop reporter value", func(t *testing.T) {
		assert.True(t, IsBuiltinNoopReporter(NoopReporter{}))
	})

	t.Run("noop reporter pointer", func(t *testing.T) {
		assert.True(t, IsBuiltinNoopReporter(&NoopReporter{}))
	})

	t.Run("prometheus reporter", func(t *testing.T) {
		reporter := NewPrometheusReporter(&InternalMetricsConfig{}, nil, prometheus.NewRegistry())
		assert.False(t, IsBuiltinNoopReporter(reporter))
	})

	t.Run("noop embedder is not builtin noop", func(t *testing.T) {
		reporter := &noopEmbeddingReporter{}
		assert.False(t, IsBuiltinNoopReporter(reporter))
	})

	t.Run("nil reporter", func(t *testing.T) {
		assert.False(t, IsBuiltinNoopReporter(nil))
	})
}

func TestPrometheusReporterQueueBufferUtilization(t *testing.T) {
	reporter := NewPrometheusReporter(&InternalMetricsConfig{}, nil, prometheus.NewRegistry())

	gaugeValue := func(subscriber string) float64 {
		var m dto.Metric
		require.NoError(t, reporter.queueCapacityRatio.WithLabelValues(subscriber).Write(&m))
		return m.GetGauge().GetValue()
	}

	reporter.QueueBufferUtilization("traces", 0.42)
	reporter.QueueBufferUtilization("metrics", 0.1)

	assert.InDelta(t, 0.42, gaugeValue("traces"), 0.001)
	assert.InDelta(t, 0.1, gaugeValue("metrics"), 0.001)

	// a later update overwrites the previous value for the same subscriber
	reporter.QueueBufferUtilization("traces", 0.9)
	assert.InDelta(t, 0.9, gaugeValue("traces"), 0.001)
}

func TestPrometheusReporterJavaRemoteParent(t *testing.T) {
	reporter := NewPrometheusReporter(&InternalMetricsConfig{}, nil, prometheus.NewRegistry())
	reporter.JavaRemoteParent("unix", "take", "valid", 2)

	var metric dto.Metric
	require.NoError(t, reporter.javaRemoteParent.WithLabelValues("unix", "take", "valid").Write(&metric))
	assert.InDelta(t, 2, metric.GetCounter().GetValue(), 0)
}

func TestPrometheusReporterBpfProbeCollection(t *testing.T) {
	reporter := NewPrometheusReporter(&InternalMetricsConfig{}, nil, prometheus.NewRegistry())

	reporter.BpfProbeCollection("7", "CGroupSockopt", "obi_test")
	reporter.BpfProbeCollection("7", "CGroupSockopt", "obi_test")

	labels := []string{"7", "CGroupSockopt", "obi_test"}
	var executions dto.Metric
	var runtime dto.Metric
	var passes dto.Metric
	require.NoError(t, reporter.bpfProbeExecutions.WithLabelValues(labels...).Write(&executions))
	require.NoError(t, reporter.bpfProbeLatencySum.WithLabelValues(labels...).Write(&runtime))
	require.NoError(t, reporter.bpfProbeCollectionPasses.WithLabelValues(labels...).Write(&passes))
	assert.Zero(t, executions.GetCounter().GetValue())
	assert.Zero(t, runtime.GetCounter().GetValue())
	assert.Equal(t, float64(2), passes.GetCounter().GetValue())
}

func TestPrometheusReporterBpfProbeLabelLeases(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := NewPrometheusReporter(&InternalMetricsConfig{}, nil, registry)
	labels := map[string]string{
		"probe_id": "7", "probe_type": "CGroupSockopt", "probe_name": "obi_test",
	}

	reporter.BpfProbeLabelsAcquire("7", "CGroupSockopt", "obi_test")
	reporter.BpfProbeLabelsAcquire("7", "CGroupSockopt", "obi_test")
	reporter.BpfProbeStats("7", "CGroupSockopt", "obi_test", 3, 0.5, nil)
	reporter.BpfProbeCollection("7", "CGroupSockopt", "obi_test")
	reporter.BpfProbeLabelsRelease("7", "CGroupSockopt", "obi_test")

	for _, name := range []string{
		"obi_bpf_probe_executions_total",
		"obi_bpf_probe_latency_seconds_total",
		"obi_bpf_probe_collection_passes_total",
	} {
		require.NotNil(t, gatheredInternalMetric(t, registry, name, labels), name)
	}

	// An unmatched release is idempotent and cannot affect another exact label set.
	reporter.BpfProbeLabelsRelease("8", "CGroupSockopt", "obi_other")
	reporter.BpfProbeLabelsRelease("7", "CGroupSockopt", "obi_test")
	reporter.BpfProbeLabelsRelease("7", "CGroupSockopt", "obi_test")
	for _, name := range []string{
		"obi_bpf_probe_executions_total",
		"obi_bpf_probe_latency_seconds_total",
		"obi_bpf_probe_collection_passes_total",
	} {
		assert.Nil(t, gatheredInternalMetric(t, registry, name, labels), name)
	}

	// A later acquisition recreates clean series rather than reviving stale counters.
	reporter.BpfProbeLabelsAcquire("7", "CGroupSockopt", "obi_test")
	reporter.BpfProbeCollection("7", "CGroupSockopt", "obi_test")
	executions := gatheredInternalMetric(t, registry, "obi_bpf_probe_executions_total", labels)
	runtime := gatheredInternalMetric(t, registry, "obi_bpf_probe_latency_seconds_total", labels)
	passes := gatheredInternalMetric(t, registry, "obi_bpf_probe_collection_passes_total", labels)
	require.NotNil(t, executions)
	require.NotNil(t, runtime)
	require.NotNil(t, passes)
	assert.Zero(t, executions.GetCounter().GetValue())
	assert.Zero(t, runtime.GetCounter().GetValue())
	assert.Equal(t, float64(1), passes.GetCounter().GetValue())
}

func TestPrometheusReporterBpfMapLabelLeases(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := NewPrometheusReporter(&InternalMetricsConfig{}, nil, registry)
	labels := map[string]string{
		"map_id": "11", "map_name": "java_remote_par", "map_type": "Hash",
	}

	reporter.BpfMapLabelsAcquire("11", "java_remote_par", "Hash")
	reporter.BpfMapLabelsAcquire("11", "java_remote_par", "Hash")
	reporter.BpfMapEntries("11", "java_remote_par", "Hash", 4)
	reporter.BpfMapMaxEntries("11", "java_remote_par", "Hash", 16)
	reporter.BpfMapLabelsRelease("11", "java_remote_par", "Hash")

	entries := gatheredInternalMetric(t, registry, "obi_bpf_map_entries", labels)
	maximum := gatheredInternalMetric(t, registry, "obi_bpf_map_max_entries", labels)
	require.NotNil(t, entries)
	require.NotNil(t, maximum)
	assert.Equal(t, float64(4), entries.GetGauge().GetValue())
	assert.Equal(t, float64(16), maximum.GetGauge().GetValue())

	// Unmatched and repeated releases cannot delete another exact label set.
	reporter.BpfMapLabelsRelease("12", "other", "Hash")
	reporter.BpfMapLabelsRelease("11", "java_remote_par", "Hash")
	reporter.BpfMapLabelsRelease("11", "java_remote_par", "Hash")
	assert.Nil(t, gatheredInternalMetric(t, registry, "obi_bpf_map_entries", labels))
	assert.Nil(t, gatheredInternalMetric(t, registry, "obi_bpf_map_max_entries", labels))

	// Reacquisition recreates both gauges without stale values.
	reporter.BpfMapLabelsAcquire("11", "java_remote_par", "Hash")
	reporter.BpfMapEntries("11", "java_remote_par", "Hash", 1)
	reporter.BpfMapMaxEntries("11", "java_remote_par", "Hash", 8)
	entries = gatheredInternalMetric(t, registry, "obi_bpf_map_entries", labels)
	maximum = gatheredInternalMetric(t, registry, "obi_bpf_map_max_entries", labels)
	require.NotNil(t, entries)
	require.NotNil(t, maximum)
	assert.Equal(t, float64(1), entries.GetGauge().GetValue())
	assert.Equal(t, float64(8), maximum.GetGauge().GetValue())
}

type noopEmbeddingReporter struct {
	NoopReporter
}

func (n *noopEmbeddingReporter) BpfProbeStats(_, _, _ string, _ uint64, _ float64, _ map[float64]uint64) {
}

func TestPrometheusReporterAvoidedServicesBounded(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := NewPrometheusReporter(&InternalMetricsConfig{
		AvoidedServices: AvoidedServicesConfig{Limit: 3},
	}, nil, registry)

	reporter.AvoidInstrumentationMetrics("svc-0", "ns-0", "inst-0")
	reporter.AvoidInstrumentationTraces("svc-0", "ns-0", "inst-0")
	reporter.AvoidInstrumentationMetrics("svc-1", "ns-1", "inst-1")
	reporter.AvoidInstrumentationTraces("svc-1", "ns-1", "inst-1")

	metrics := gatherAvoidedServices(t, registry)
	require.Len(t, metrics, 3)

	labelSets := map[string]struct{}{}
	overflowRecords := 0
	for _, metric := range metrics {
		labels := metricLabels(metric)
		if labels[avoidedsvc.PrometheusOverflowLabel] == "true" {
			overflowRecords++
			assert.Empty(t, labels["service_name"])
			assert.Empty(t, labels["service_namespace"])
			assert.Empty(t, labels["telemetry_type"])
			continue
		}

		assert.Equal(t, "false", labels[avoidedsvc.PrometheusOverflowLabel])
		labelSets[labels["service_name"]+"/"+
			labels["service_namespace"]+"/"+
			labels["telemetry_type"]] = struct{}{}
	}

	assert.Contains(t, labelSets, "svc-0/ns-0/metrics")
	assert.Contains(t, labelSets, "svc-0/ns-0/traces")
	assert.Equal(t, 1, overflowRecords)
}

func TestPrometheusReporterAvoidedServicesDisabled(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := NewPrometheusReporter(&InternalMetricsConfig{
		AvoidedServices: AvoidedServicesConfig{Disabled: true},
	}, nil, registry)

	reporter.AvoidInstrumentationMetrics("svc-0", "ns-0", "inst-0")

	mfs, err := registry.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		assert.NotEqual(t, attr.VendorPrefix+"_avoided_services", mf.GetName())
	}
}

func gatherAvoidedServices(t *testing.T, registry *prometheus.Registry) []*dto.Metric {
	t.Helper()

	mfs, err := registry.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() == attr.VendorPrefix+"_avoided_services" {
			return mf.GetMetric()
		}
	}
	require.Fail(t, "missing avoided services metric")
	return nil
}

func metricLabels(metric *dto.Metric) map[string]string {
	labels := map[string]string{}
	for _, pair := range metric.GetLabel() {
		labels[pair.GetName()] = pair.GetValue()
	}
	return labels
}

func gatheredInternalMetric(
	t *testing.T,
	registry *prometheus.Registry,
	name string,
	labels map[string]string,
) *dto.Metric {
	t.Helper()

	metricFamilies, err := registry.Gather()
	require.NoError(t, err)
	for _, family := range metricFamilies {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			if assert.ObjectsAreEqual(metricLabels(metric), labels) {
				return metric
			}
		}
	}
	return nil
}
