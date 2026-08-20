// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/export"
	"go.opentelemetry.io/obi/pkg/export/connector"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/export/otel/perapp"
	"go.opentelemetry.io/obi/pkg/pipe/global"
)

type blockingProbeCollectionReporter struct {
	*imetrics.PrometheusReporter
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

type blockingMapEntriesReporter struct {
	*imetrics.PrometheusReporter
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (r *blockingProbeCollectionReporter) BpfProbeCollection(probeID, probeType, probeName string) {
	r.once.Do(func() { close(r.started) })
	<-r.release
	r.PrometheusReporter.BpfProbeCollection(probeID, probeType, probeName)
}

func (r *blockingMapEntriesReporter) BpfMapEntries(mapID, mapName, mapType string, entriesTotal int) {
	r.once.Do(func() { close(r.started) })
	<-r.release
	r.PrometheusReporter.BpfMapEntries(mapID, mapName, mapType, entriesTotal)
}

func TestBPFCollectorEnabled(t *testing.T) {
	cfg := &PrometheusConfig{}
	mpCfg := &perapp.GlobalMetricsConfig{}

	t.Run("disabled without reporter", func(t *testing.T) {
		assert.False(t, bpfCollectorEnabled(cfg, mpCfg, nil))
	})

	t.Run("disabled with noop reporter", func(t *testing.T) {
		assert.False(t, bpfCollectorEnabled(cfg, mpCfg, imetrics.NoopReporter{}))
	})

	t.Run("disabled with noop reporter pointer", func(t *testing.T) {
		assert.False(t, bpfCollectorEnabled(cfg, mpCfg, &imetrics.NoopReporter{}))
	})

	t.Run("enabled with prometheus internal reporter", func(t *testing.T) {
		internalMetrics := imetrics.NewPrometheusReporter(
			&imetrics.InternalMetricsConfig{BpfMetricScrapeInterval: time.Millisecond},
			nil,
			prometheus.NewRegistry(),
		)

		assert.True(t, bpfCollectorEnabled(cfg, mpCfg, internalMetrics))
	})

	t.Run("enabled with prometheus manager-backed reporter", func(t *testing.T) {
		internalMetrics := imetrics.NewPrometheusReporter(
			&imetrics.InternalMetricsConfig{BpfMetricScrapeInterval: time.Millisecond},
			&connector.PrometheusManager{},
			nil,
		)

		assert.True(t, bpfCollectorEnabled(cfg, mpCfg, internalMetrics))
	})

	t.Run("disabled with zero-interval prometheus reporter", func(t *testing.T) {
		internalMetrics := imetrics.NewPrometheusReporter(
			&imetrics.InternalMetricsConfig{},
			nil,
			prometheus.NewRegistry(),
		)

		assert.False(t, bpfCollectorEnabled(cfg, mpCfg, internalMetrics))
	})
}

func TestCollectMapOccupancyIncludesNonEvictingAndLRUHashes(t *testing.T) {
	assert.True(t, collectMapOccupancy(ebpf.Hash, "java_remote_par"))
	assert.True(t, collectMapOccupancy(ebpf.LRUHash, "unrelated"))
	assert.False(t, collectMapOccupancy(ebpf.Hash, "unrelated"))
	assert.False(t, collectMapOccupancy(ebpf.Array, "java_remote_par"))
	assert.False(t, collectMapOccupancy(ebpf.LRUCPUHash, "java_remote_par"))
	assert.False(t, collectMapOccupancy(ebpf.PerCPUHash, "java_remote_par"))
}

func TestSupportedProgramTypeIncludesCGroupSockopt(t *testing.T) {
	for _, programType := range []ebpf.ProgramType{
		ebpf.Kprobe,
		ebpf.SocketFilter,
		ebpf.SchedCLS,
		ebpf.SkMsg,
		ebpf.SockOps,
		ebpf.CGroupSockopt,
	} {
		assert.True(t, supportedProgramType(programType), programType.String())
	}
	assert.False(t, supportedProgramType(ebpf.TracePoint))
}

func TestBPFMetricsCollectsInternalMetricsForPrometheusReporter(t *testing.T) {
	registry := prometheus.NewRegistry()
	internalMetrics := imetrics.NewPrometheusReporter(
		&imetrics.InternalMetricsConfig{BpfMetricScrapeInterval: time.Millisecond},
		nil,
		registry,
	)
	ctxInfo := &global.ContextInfo{Metrics: internalMetrics}

	originalNewBPFCollector := newBPFCollectorFn
	originalNewInternalBPFCollector := newInternalBPFCollectorFn
	t.Cleanup(func() {
		newBPFCollectorFn = originalNewBPFCollector
		newInternalBPFCollectorFn = originalNewInternalBPFCollector
	})

	newInternalBPFCollectorFn = func(ctxInfo *global.ContextInfo, cfg *PrometheusConfig, mpCfg *perapp.GlobalMetricsConfig) *BPFCollector {
		var collected bool
		return &BPFCollector{
			promCfg:         cfg,
			commonCfg:       mpCfg,
			internalMetrics: ctxInfo.Metrics,
			ctxInfo:         ctxInfo,
			probeMetrics: func() []ProbeMetrics {
				count := uint64(0)
				if !collected {
					count = 3
					collected = true
				}
				return []ProbeMetrics{{
					probeType: "kprobe",
					probeName: "tcp_connect",
					probeID:   "7",
					latency:   0.25,
					count:     count,
					program:   &BPFProgram{},
				}, {
					probeType: "CGroupSockopt",
					probeName: "obi_zero_delta",
					probeID:   "8",
					program:   &BPFProgram{},
				}}
			},
			mapMetrics: func() []BpfMapMetrics {
				return []BpfMapMetrics{{
					mapType:    "hash",
					mapName:    "connections",
					mapID:      "3",
					maxEntries: 16,
					entries:    4,
				}}
			},
		}
	}

	runFn, err := BPFMetrics(ctxInfo, &PrometheusConfig{}, &perapp.GlobalMetricsConfig{})(context.Background())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	runFn(ctx)

	require.Eventually(t, func() bool {
		probeExecutionsMetric := gatheredMetric(t, registry, "obi_bpf_probe_executions_total", map[string]string{
			"probe_id":   "7",
			"probe_type": "kprobe",
			"probe_name": "tcp_connect",
		})
		probeLatencySumMetric := gatheredMetric(t, registry, "obi_bpf_probe_latency_seconds_total", map[string]string{
			"probe_id":   "7",
			"probe_type": "kprobe",
			"probe_name": "tcp_connect",
		})
		probeCollectionMetric := gatheredMetric(t, registry, "obi_bpf_probe_collection_passes_total", map[string]string{
			"probe_id":   "7",
			"probe_type": "kprobe",
			"probe_name": "tcp_connect",
		})
		zeroExecutionsMetric := gatheredMetric(t, registry, "obi_bpf_probe_executions_total", map[string]string{
			"probe_id":   "8",
			"probe_type": "CGroupSockopt",
			"probe_name": "obi_zero_delta",
		})
		zeroLatencyMetric := gatheredMetric(t, registry, "obi_bpf_probe_latency_seconds_total", map[string]string{
			"probe_id":   "8",
			"probe_type": "CGroupSockopt",
			"probe_name": "obi_zero_delta",
		})
		zeroCollectionMetric := gatheredMetric(t, registry, "obi_bpf_probe_collection_passes_total", map[string]string{
			"probe_id":   "8",
			"probe_type": "CGroupSockopt",
			"probe_name": "obi_zero_delta",
		})
		mapEntriesMetric := gatheredMetric(t, registry, "obi_bpf_map_entries", map[string]string{
			"map_id":   "3",
			"map_name": "connections",
			"map_type": "hash",
		})
		mapMaxEntriesMetric := gatheredMetric(t, registry, "obi_bpf_map_max_entries", map[string]string{
			"map_id":   "3",
			"map_name": "connections",
			"map_type": "hash",
		})

		if probeExecutionsMetric == nil || probeLatencySumMetric == nil ||
			probeCollectionMetric == nil || zeroExecutionsMetric == nil ||
			zeroLatencyMetric == nil || zeroCollectionMetric == nil ||
			mapEntriesMetric == nil || mapMaxEntriesMetric == nil {
			return false
		}

		return probeExecutionsMetric.GetCounter().GetValue() == 3 &&
			probeLatencySumMetric.GetCounter().GetValue() == 0.75 &&
			probeCollectionMetric.GetCounter().GetValue() >= 2 &&
			zeroExecutionsMetric.GetCounter().GetValue() == 0 &&
			zeroLatencyMetric.GetCounter().GetValue() == 0 &&
			zeroCollectionMetric.GetCounter().GetValue() >= 2 &&
			mapEntriesMetric.GetGauge().GetValue() == 4 &&
			mapMaxEntriesMetric.GetGauge().GetValue() == 16
	}, time.Second, 10*time.Millisecond)
}

func TestInternalBPFCollectorProbeLabelLifecycle(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := imetrics.NewPrometheusReporter(&imetrics.InternalMetricsConfig{}, nil, registry)
	collector := testInternalProbeCollector(reporter)
	labels := testProbeLabels()

	collector.collectAndReportInternalMetrics()
	requireProbeMetricFamilies(t, registry, labels)

	collector.mu.Lock()
	// A complete walk that still sees the program retains its lease.
	collector.reconcileMissingPrograms(map[ebpf.ProgramID]struct{}{7: {}}, true)
	// An incomplete walk cannot prove absence and must retain the lease.
	collector.reconcileMissingPrograms(map[ebpf.ProgramID]struct{}{}, false)
	// A transient Stats failure still records the ID as seen and must retain it.
	collector.reconcileMissingPrograms(map[ebpf.ProgramID]struct{}{7: {}}, true)
	collector.mu.Unlock()
	requireProbeMetricFamilies(t, registry, labels)

	collector.mu.Lock()
	collector.reconcileMissingPrograms(map[ebpf.ProgramID]struct{}{}, true)
	collector.mu.Unlock()
	requireNoProbeMetricFamilies(t, registry, labels)

	// The same exact program can reappear after a complete eviction and obtains
	// a new lease with fresh CounterVec series.
	collector.mu.Lock()
	collector.programCache[7] = testCachedProgram()
	collector.progs[7] = &BPFProgram{}
	collector.mu.Unlock()
	collector.collectAndReportInternalMetrics()
	requireProbeMetricFamilies(t, registry, labels)
	assert.Equal(t, float64(3), gatheredMetric(
		t, registry, "obi_bpf_probe_executions_total", labels,
	).GetCounter().GetValue())
	assert.Equal(t, float64(1), gatheredMetric(
		t, registry, "obi_bpf_probe_collection_passes_total", labels,
	).GetCounter().GetValue())
}

func TestInternalBPFCollectorSharedReporterLabelOwnership(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := imetrics.NewPrometheusReporter(&imetrics.InternalMetricsConfig{}, nil, registry)
	first := testInternalProbeCollector(reporter)
	second := testInternalProbeCollector(reporter)
	nativeProm := testInternalProbeCollector(reporter)
	labels := testProbeLabels()

	first.collectAndReportInternalMetrics()
	second.collectAndReportInternalMetrics()
	requireProbeMetricFamilies(t, registry, labels)

	// A native Prometheus collector never acquired an internal-series lease, so
	// its shutdown must not change the shared reporter's refcount.
	nativeMetrics := make(chan prometheus.Metric, 1)
	nativeProm.Collect(nativeMetrics)
	require.Len(t, nativeMetrics, 1)
	nativeProm.close()
	requireProbeMetricFamilies(t, registry, labels)
	first.close()
	first.close()
	requireProbeMetricFamilies(t, registry, labels)
	second.close()
	requireNoProbeMetricFamilies(t, registry, labels)
}

func TestInternalBPFCollectorCloseSerializesWithReporting(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := &blockingProbeCollectionReporter{
		PrometheusReporter: imetrics.NewPrometheusReporter(
			&imetrics.InternalMetricsConfig{}, nil, registry,
		),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	collector := testInternalProbeCollector(reporter)
	labels := testProbeLabels()
	collectionDone := make(chan struct{})
	closeDone := make(chan struct{})

	go func() {
		collector.collectAndReportInternalMetrics()
		close(collectionDone)
	}()
	<-reporter.started
	go func() {
		collector.close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
		t.Fatal("collector shutdown overtook an in-flight internal report")
	case <-time.After(20 * time.Millisecond):
	}
	close(reporter.release)
	<-collectionDone
	<-closeDone

	requireNoProbeMetricFamilies(t, registry, labels)
	collector.collectAndReportInternalMetrics()
	collector.close()
	requireNoProbeMetricFamilies(t, registry, labels)
}

func TestInternalBPFCollectorMapLabelLifecycle(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := imetrics.NewPrometheusReporter(&imetrics.InternalMetricsConfig{}, nil, registry)
	labels := testMapLabels()

	// A supported map that has not completed entry iteration publishes no gauges
	// and owns no lease.
	unpublished := testInternalMapCollector(reporter)
	unpublished.mapMetrics = func() []BpfMapMetrics { return nil }
	unpublished.collectAndReportInternalMetrics()
	require.Empty(t, unpublished.ownedMapLabels)
	requireNoMapMetricFamilies(t, registry, labels)
	unpublished.close()

	collector := testInternalMapCollector(reporter)
	collector.collectAndReportInternalMetrics()
	requireMapMetricFamilies(t, registry, labels, 4, 16)

	collector.mu.Lock()
	// A complete walk that sees the ID retains the lease even when opening or
	// iterating that map fails and produces no metric for this pass.
	collector.reconcileMissingMaps(map[ebpf.MapID]struct{}{11: {}}, true)
	// An incomplete enumeration cannot prove absence and also retains the lease.
	collector.reconcileMissingMaps(map[ebpf.MapID]struct{}{}, false)
	collector.mu.Unlock()
	requireMapMetricFamilies(t, registry, labels, 4, 16)

	collector.mu.Lock()
	collector.reconcileMissingMaps(map[ebpf.MapID]struct{}{}, true)
	collector.mu.Unlock()
	requireNoMapMetricFamilies(t, registry, labels)

	// Reappearance after complete eviction gets a fresh lease and fresh gauges.
	collector.mu.Lock()
	collector.mapCache[11] = testCachedMap()
	collector.mapMetrics = func() []BpfMapMetrics {
		return []BpfMapMetrics{{
			mapID: "11", mapName: "java_remote_par", mapType: "Hash",
			entries: 1, maxEntries: 8,
		}}
	}
	collector.mu.Unlock()
	collector.collectAndReportInternalMetrics()
	requireMapMetricFamilies(t, registry, labels, 1, 8)
}

func TestInternalBPFCollectorSharedReporterMapLabelOwnership(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := imetrics.NewPrometheusReporter(&imetrics.InternalMetricsConfig{}, nil, registry)
	first := testInternalMapCollector(reporter)
	second := testInternalMapCollector(reporter)
	nativeProm := testInternalMapCollector(reporter)
	labels := testMapLabels()

	first.collectAndReportInternalMetrics()
	second.collectAndReportInternalMetrics()
	requireMapMetricFamilies(t, registry, labels, 4, 16)

	// The native Prometheus path publishes its own const metric without leasing
	// the internal reporter's GaugeVec labels.
	nativeMetrics := make(chan prometheus.Metric, 1)
	nativeProm.Collect(nativeMetrics)
	require.Len(t, nativeMetrics, 1)
	nativeProm.close()
	requireMapMetricFamilies(t, registry, labels, 4, 16)

	first.close()
	first.close()
	requireMapMetricFamilies(t, registry, labels, 4, 16)
	second.close()
	requireNoMapMetricFamilies(t, registry, labels)
}

func TestInternalBPFCollectorMapCloseSerializesWithReporting(t *testing.T) {
	registry := prometheus.NewRegistry()
	reporter := &blockingMapEntriesReporter{
		PrometheusReporter: imetrics.NewPrometheusReporter(
			&imetrics.InternalMetricsConfig{}, nil, registry,
		),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	collector := testInternalMapCollector(reporter)
	labels := testMapLabels()
	collectionDone := make(chan struct{})
	closeDone := make(chan struct{})

	go func() {
		collector.collectAndReportInternalMetrics()
		close(collectionDone)
	}()
	<-reporter.started
	go func() {
		collector.close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
		t.Fatal("collector shutdown overtook an in-flight map report")
	case <-time.After(20 * time.Millisecond):
	}
	close(reporter.release)
	<-collectionDone
	<-closeDone

	requireNoMapMetricFamilies(t, registry, labels)
	collector.collectAndReportInternalMetrics()
	collector.close()
	requireNoMapMetricFamilies(t, registry, labels)
}

func TestBPFMetricsCollectsInternalMetricsWhenPrometheusEndpointEnabled(t *testing.T) {
	registry := prometheus.NewRegistry()
	internalMetrics := imetrics.NewPrometheusReporter(
		&imetrics.InternalMetricsConfig{BpfMetricScrapeInterval: time.Millisecond},
		nil,
		registry,
	)
	ctxInfo := &global.ContextInfo{Metrics: internalMetrics}
	cfg := &PrometheusConfig{Port: 1}
	mpCfg := &perapp.GlobalMetricsConfig{Features: export.FeatureEBPF}

	originalNewBPFCollector := newBPFCollectorFn
	originalNewInternalBPFCollector := newInternalBPFCollectorFn
	t.Cleanup(func() {
		newBPFCollectorFn = originalNewBPFCollector
		newInternalBPFCollectorFn = originalNewInternalBPFCollector
	})

	var promCollector *BPFCollector
	newBPFCollectorFn = func(ctxInfo *global.ContextInfo, cfg *PrometheusConfig, mpCfg *perapp.GlobalMetricsConfig) *BPFCollector {
		var collected bool
		promCollector = &BPFCollector{
			promCfg:         cfg,
			commonCfg:       mpCfg,
			internalMetrics: ctxInfo.Metrics,
			promConnect:     &connector.PrometheusManager{},
			ctxInfo:         ctxInfo,
			log:             slog.With("component", "prom.BPFCollector"),
			probeLatencyDesc: prometheus.NewDesc(
				prometheus.BuildFQName("bpf", "probe", "latency_seconds"),
				"Latency of the probe in seconds",
				[]string{"probe_id", "probe_type", "probe_name"},
				nil,
			),
			mapSizeDesc: prometheus.NewDesc(
				prometheus.BuildFQName("bpf", "map", "entries_total"),
				"Number of entries in the map",
				[]string{"map_id", "map_name", "map_type", "max_entries"},
				nil,
			),
			probeMetrics: func() []ProbeMetrics {
				count := uint64(0)
				if !collected {
					count = 1
					collected = true
				}
				return []ProbeMetrics{{
					probeType: "kprobe",
					probeName: "tcp_connect",
					probeID:   "7",
					latency:   0.25,
					count:     count,
					program: &BPFProgram{
						runTime:  250 * time.Millisecond,
						runCount: 1,
					},
				}}
			},
			mapMetrics: func() []BpfMapMetrics {
				return []BpfMapMetrics{{
					mapType:    "hash",
					mapName:    "connections",
					mapID:      "3",
					maxEntries: 16,
					entries:    4,
				}}
			},
		}
		return promCollector
	}

	newInternalBPFCollectorFn = func(ctxInfo *global.ContextInfo, cfg *PrometheusConfig, mpCfg *perapp.GlobalMetricsConfig) *BPFCollector {
		var collected bool
		return &BPFCollector{
			promCfg:         cfg,
			commonCfg:       mpCfg,
			internalMetrics: ctxInfo.Metrics,
			ctxInfo:         ctxInfo,
			probeMetrics: func() []ProbeMetrics {
				count := uint64(0)
				if !collected {
					count = 1
					collected = true
				}
				return []ProbeMetrics{{
					probeType: "kprobe",
					probeName: "tcp_connect",
					probeID:   "7",
					latency:   0.25,
					count:     count,
					program:   &BPFProgram{},
				}}
			},
			mapMetrics: func() []BpfMapMetrics {
				return []BpfMapMetrics{{
					mapType:    "hash",
					mapName:    "connections",
					mapID:      "3",
					maxEntries: 16,
					entries:    4,
				}}
			},
		}
	}

	runFn, err := BPFMetrics(ctxInfo, cfg, mpCfg)(context.Background())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	runFn(ctx)

	promMetricsCh := make(chan prometheus.Metric, 4)
	promCollector.Collect(promMetricsCh)
	close(promMetricsCh)

	promProbeMetricFound := false
	for metric := range promMetricsCh {
		var promProbeMetric dto.Metric
		require.NoError(t, metric.Write(&promProbeMetric))
		if promProbeMetric.GetHistogram() == nil {
			continue
		}
		require.Equal(t, uint64(1), promProbeMetric.GetHistogram().GetSampleCount())
		promProbeMetricFound = true
	}
	require.True(t, promProbeMetricFound)

	require.Eventually(t, func() bool {
		probeExecutionsMetric := gatheredMetric(t, registry, "obi_bpf_probe_executions_total", map[string]string{
			"probe_id":   "7",
			"probe_type": "kprobe",
			"probe_name": "tcp_connect",
		})
		probeLatencySumMetric := gatheredMetric(t, registry, "obi_bpf_probe_latency_seconds_total", map[string]string{
			"probe_id":   "7",
			"probe_type": "kprobe",
			"probe_name": "tcp_connect",
		})
		mapEntriesMetric := gatheredMetric(t, registry, "obi_bpf_map_entries", map[string]string{
			"map_id":   "3",
			"map_name": "connections",
			"map_type": "hash",
		})
		mapMaxEntriesMetric := gatheredMetric(t, registry, "obi_bpf_map_max_entries", map[string]string{
			"map_id":   "3",
			"map_name": "connections",
			"map_type": "hash",
		})

		if probeExecutionsMetric == nil || probeLatencySumMetric == nil || mapEntriesMetric == nil || mapMaxEntriesMetric == nil {
			return false
		}

		return probeExecutionsMetric.GetCounter().GetValue() == 1 &&
			probeLatencySumMetric.GetCounter().GetValue() == 0.25 &&
			mapEntriesMetric.GetGauge().GetValue() == 4 &&
			mapMaxEntriesMetric.GetGauge().GetValue() == 16
	}, time.Second, 10*time.Millisecond)
}

func TestBPFMetricsDoesNotCreateInternalCollectorForZeroIntervalReporter(t *testing.T) {
	ctxInfo := &global.ContextInfo{
		Metrics: imetrics.NewPrometheusReporter(
			&imetrics.InternalMetricsConfig{},
			nil,
			prometheus.NewRegistry(),
		),
	}
	cfg := &PrometheusConfig{Port: 1}
	mpCfg := &perapp.GlobalMetricsConfig{Features: export.FeatureEBPF}

	originalNewBPFCollector := newBPFCollectorFn
	originalNewInternalBPFCollector := newInternalBPFCollectorFn
	t.Cleanup(func() {
		newBPFCollectorFn = originalNewBPFCollector
		newInternalBPFCollectorFn = originalNewInternalBPFCollector
	})

	newBPFCollectorFn = func(ctxInfo *global.ContextInfo, cfg *PrometheusConfig, mpCfg *perapp.GlobalMetricsConfig) *BPFCollector {
		return &BPFCollector{
			promCfg:         cfg,
			commonCfg:       mpCfg,
			internalMetrics: ctxInfo.Metrics,
			promConnect:     &connector.PrometheusManager{},
			ctxInfo:         ctxInfo,
		}
	}

	newInternalBPFCollectorFn = func(_ *global.ContextInfo, _ *PrometheusConfig, _ *perapp.GlobalMetricsConfig) *BPFCollector {
		t.Fatal("zero-interval reporter unexpectedly created an internal BPF collector")
		return nil
	}

	runFn, err := BPFMetrics(ctxInfo, cfg, mpCfg)(context.Background())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	require.NotPanics(t, func() {
		runFn(ctx)
	})
}

func TestBPFCollectorDoesNotCollectAfterContextCleanup(t *testing.T) {
	collector := newCollector(
		&global.ContextInfo{},
		&PrometheusConfig{},
		&perapp.GlobalMetricsConfig{},
		false,
	)
	collector.progs[ebpf.ProgramID(1)] = &BPFProgram{}

	var collectionCalls atomic.Int32
	collector.probeMetrics = func() []ProbeMetrics {
		collectionCalls.Add(1)
		return nil
	}
	collector.mapMetrics = func() []BpfMapMetrics {
		collectionCalls.Add(1)
		return nil
	}

	ctx, cancel := context.WithCancel(t.Context())
	collector.cleanupOnContext(ctx)
	cancel()

	require.Eventually(t, func() bool {
		collector.mu.Lock()
		defer collector.mu.Unlock()
		return len(collector.progs) == 0
	}, time.Second, 10*time.Millisecond)

	collector.collectMetrics()

	require.Zero(t, collectionCalls.Load())
}

func testCachedProgram() *cachedProgram {
	return &cachedProgram{
		supported: true,
		probeID:   "7",
		probeType: "CGroupSockopt",
		probeName: "obi_test",
	}
}

func testCachedMap() *cachedMap {
	return &cachedMap{
		supported:  true,
		mapID:      "11",
		mapName:    "java_remote_par",
		mapType:    "Hash",
		maxEntries: 16,
	}
}

func testProbeLabels() map[string]string {
	return map[string]string{
		"probe_id": "7", "probe_type": "CGroupSockopt", "probe_name": "obi_test",
	}
}

func testMapLabels() map[string]string {
	return map[string]string{
		"map_id": "11", "map_name": "java_remote_par", "map_type": "Hash",
	}
}

func testInternalProbeCollector(reporter imetrics.Reporter) *BPFCollector {
	collector := &BPFCollector{
		internalMetrics:  reporter,
		ctxInfo:          &global.ContextInfo{Metrics: reporter},
		log:              slog.Default(),
		progs:            map[ebpf.ProgramID]*BPFProgram{7: {}},
		programCache:     map[ebpf.ProgramID]*cachedProgram{7: testCachedProgram()},
		mapCache:         make(map[ebpf.MapID]*cachedMap),
		ownedProbeLabels: make(map[probeMetricLabels]struct{}),
		ownedMapLabels:   make(map[mapMetricLabels]struct{}),
		probeLatencyDesc: prometheus.NewDesc(
			"test_bpf_probe_latency_seconds",
			"test BPF probe latency",
			[]string{"probe_id", "probe_type", "probe_name"},
			nil,
		),
		mapMetrics: func() []BpfMapMetrics { return nil },
	}
	collector.probeMetrics = func() []ProbeMetrics {
		program := collector.progs[7]
		if program == nil {
			return nil
		}
		return []ProbeMetrics{{
			probeType: "CGroupSockopt",
			probeName: "obi_test",
			probeID:   "7",
			latency:   0.25,
			count:     3,
			program:   program,
		}}
	}
	return collector
}

func testInternalMapCollector(reporter imetrics.Reporter) *BPFCollector {
	collector := &BPFCollector{
		internalMetrics:  reporter,
		ctxInfo:          &global.ContextInfo{Metrics: reporter},
		log:              slog.Default(),
		progs:            make(map[ebpf.ProgramID]*BPFProgram),
		programCache:     make(map[ebpf.ProgramID]*cachedProgram),
		mapCache:         map[ebpf.MapID]*cachedMap{11: testCachedMap()},
		ownedProbeLabels: make(map[probeMetricLabels]struct{}),
		ownedMapLabels:   make(map[mapMetricLabels]struct{}),
		mapSizeDesc: prometheus.NewDesc(
			"test_bpf_map_entries_total",
			"test BPF map entries",
			[]string{"map_id", "map_name", "map_type", "max_entries"},
			nil,
		),
		probeMetrics: func() []ProbeMetrics { return nil },
	}
	collector.mapMetrics = func() []BpfMapMetrics {
		cached := collector.mapCache[11]
		if cached == nil {
			return nil
		}
		return []BpfMapMetrics{{
			mapID: cached.mapID, mapName: cached.mapName, mapType: cached.mapType,
			entries: 4, maxEntries: cached.maxEntries,
		}}
	}
	return collector
}

func requireProbeMetricFamilies(
	t *testing.T,
	registry *prometheus.Registry,
	labels map[string]string,
) {
	t.Helper()
	for _, name := range []string{
		"obi_bpf_probe_executions_total",
		"obi_bpf_probe_latency_seconds_total",
		"obi_bpf_probe_collection_passes_total",
	} {
		require.NotNil(t, gatheredMetric(t, registry, name, labels), name)
	}
}

func requireNoProbeMetricFamilies(
	t *testing.T,
	registry *prometheus.Registry,
	labels map[string]string,
) {
	t.Helper()
	for _, name := range []string{
		"obi_bpf_probe_executions_total",
		"obi_bpf_probe_latency_seconds_total",
		"obi_bpf_probe_collection_passes_total",
	} {
		assert.Nil(t, gatheredMetric(t, registry, name, labels), name)
	}
}

func requireMapMetricFamilies(
	t *testing.T,
	registry *prometheus.Registry,
	labels map[string]string,
	entriesValue float64,
	maximumValue float64,
) {
	t.Helper()
	entries := gatheredMetric(t, registry, "obi_bpf_map_entries", labels)
	maximum := gatheredMetric(t, registry, "obi_bpf_map_max_entries", labels)
	require.NotNil(t, entries, "obi_bpf_map_entries")
	require.NotNil(t, maximum, "obi_bpf_map_max_entries")
	assert.Equal(t, entriesValue, entries.GetGauge().GetValue())
	assert.Equal(t, maximumValue, maximum.GetGauge().GetValue())
}

func requireNoMapMetricFamilies(
	t *testing.T,
	registry *prometheus.Registry,
	labels map[string]string,
) {
	t.Helper()
	assert.Nil(t, gatheredMetric(t, registry, "obi_bpf_map_entries", labels))
	assert.Nil(t, gatheredMetric(t, registry, "obi_bpf_map_max_entries", labels))
}

func gatheredMetric(t *testing.T, registry *prometheus.Registry, name string, labels map[string]string) *dto.Metric {
	t.Helper()

	metrics, err := registry.Gather()
	require.NoError(t, err)

	for _, family := range metrics {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			if metricLabelsMatch(metric, labels) {
				return metric
			}
		}
	}

	return nil
}

func metricLabelsMatch(metric *dto.Metric, labels map[string]string) bool {
	if len(metric.GetLabel()) != len(labels) {
		return false
	}

	for _, label := range metric.GetLabel() {
		if labels[label.GetName()] != label.GetValue() {
			return false
		}
	}

	return true
}
