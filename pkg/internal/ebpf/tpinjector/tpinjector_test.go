// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tpinjector

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/javabridge"
	"go.opentelemetry.io/obi/pkg/obi"
)

// tpinjector has two BPF specs: the main tpinjector (spec 0) and the sock iterator (spec 1).
const expectedSpecCount = 2

func requireConnectionScopedSSLPrewriteMaps(t *testing.T, spec *ebpf.CollectionSpec) {
	t.Helper()

	require.NotContains(t, spec.Maps, "active_ssl_write_args")
	for name, sizes := range map[string][2]uint32{
		"ssl_prewrite_connection_ambiguity": {48, 16},
		"ssl_prewrite_connection_claims":    {48, 40},
		"ssl_prewrite_connection_owners":    {48, 40},
	} {
		mapSpec := spec.Maps[name]
		require.NotNil(t, mapSpec, name)
		require.Equal(t, ebpf.Hash, mapSpec.Type, name)
		require.Equal(t, sizes[0], mapSpec.KeySize, name+" key size")
		require.Equal(t, sizes[1], mapSpec.ValueSize, name+" value size")
	}
}

func TestPacketExtenderAvoidsUnsupportedNetnsCookieHelper(t *testing.T) {
	spec, err := LoadBpf()
	require.NoError(t, err)
	program := spec.Programs["obi_packet_extender"]
	require.NotNil(t, program)

	for _, instruction := range program.Instructions {
		if instruction.IsBuiltinCall() {
			require.NotEqual(t, asm.FnGetNetnsCookie, asm.BuiltinFunc(instruction.Constant))
		}
	}
}

func TestTracer_Constants(t *testing.T) {
	tests := []struct {
		name                string
		contextPropagation  string
		bpfPidFilterOff     bool
		expectedInjectFlags uint32
		expectedFilterPids  int32
	}{
		{
			name:                "all disabled, filter on",
			contextPropagation:  "disabled",
			bpfPidFilterOff:     false,
			expectedInjectFlags: 0,
			expectedFilterPids:  1,
		},
		{
			name:                "headers only",
			contextPropagation:  "headers",
			bpfPidFilterOff:     false,
			expectedInjectFlags: 1, // k_inject_http_headers
			expectedFilterPids:  1,
		},
		{
			name:                "tcp only",
			contextPropagation:  "tcp",
			bpfPidFilterOff:     false,
			expectedInjectFlags: 2, // k_inject_tcp_options
			expectedFilterPids:  1,
		},
		{
			name:                "headers and tcp",
			contextPropagation:  "headers,tcp",
			bpfPidFilterOff:     false,
			expectedInjectFlags: 3, // k_inject_http_headers | k_inject_tcp_options
			expectedFilterPids:  1,
		},
		{
			name:                "all",
			contextPropagation:  "all",
			bpfPidFilterOff:     false,
			expectedInjectFlags: 3, // k_inject_http_headers | k_inject_tcp_options
			expectedFilterPids:  1,
		},
		{
			name:                "filter off",
			contextPropagation:  "disabled",
			bpfPidFilterOff:     true,
			expectedInjectFlags: 0,
			expectedFilterPids:  0,
		},
		{
			name:                "headers, filter off",
			contextPropagation:  "headers",
			bpfPidFilterOff:     true,
			expectedInjectFlags: 1,
			expectedFilterPids:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &obi.Config{
				Discovery: services.DiscoveryConfig{
					BPFPidFilterOff: tt.bpfPidFilterOff,
				},
				EBPF: config.EBPFTracer{
					MaxTransactionTime: 10 * time.Second,
				},
			}
			err := cfg.EBPF.ContextPropagation.UnmarshalText([]byte(tt.contextPropagation))
			require.NoError(t, err)

			bundles, err := New(cfg, nil).LoadSpecs()
			require.NoError(t, err)
			require.Len(t, bundles, expectedSpecCount, "tpinjector bundle count must match")

			// Spec 0 (tpinjector) carries the main constants.
			c := bundles[0].Constants

			injectFlags, ok := c["inject_flags"]
			assert.True(t, ok, "inject_flags should be present")
			assert.Equal(t, tt.expectedInjectFlags, injectFlags)

			filterPids, ok := c["filter_pids"]
			assert.True(t, ok, "filter_pids should be present")
			assert.Equal(t, tt.expectedFilterPids, filterPids)

			_, ok = c["max_transaction_time"]
			assert.True(t, ok, "max_transaction_time should be present")

			_, ok = c["g_bpf_debug"]
			assert.True(t, ok, "g_bpf_debug should be present")

			// Spec 1 (sock_iter) carries only the debug flag.
			iterC := bundles[1].Constants
			_, ok = iterC["g_bpf_debug"]
			assert.True(t, ok, "iter g_bpf_debug should be present")
			assert.Len(t, iterC, 1, "iter spec should have only g_bpf_debug")
		})
	}
}

func TestTracerJavaRemoteParentSpecSelection(t *testing.T) {
	originalProbe := haveCgroupSockopt
	originalValidation := validateCgroupSockoptSpec
	haveCgroupSockopt = func() error { return nil }
	validateCgroupSockoptSpec = func(*ebpf.CollectionSpec, map[string]any) error { return nil }
	t.Cleanup(func() {
		haveCgroupSockopt = originalProbe
		validateCgroupSockoptSpec = originalValidation
	})

	unixConfig := obi.DefaultConfig
	require.NoError(t, unixConfig.EBPF.ContextPropagation.UnmarshalText([]byte("tcp")))
	unixConfig.Java.RemoteParent.Transport = obi.JavaRemoteParentUnix
	unixTracer := New(&unixConfig, nil)
	unixTracer.haveSockOpsNetnsCookie = func() error { return nil }
	unixBundles, err := unixTracer.LoadSpecs()
	require.NoError(t, err)
	requireConnectionScopedSSLPrewriteMaps(t, unixBundles[0].Spec)
	assert.NotNil(t, unixTracer.javaRemoteParentMapsSpec)
	assert.Nil(t, unixTracer.javaRemoteParentSpec)

	autoConfig := unixConfig
	autoConfig.Java.RemoteParent.Transport = obi.JavaRemoteParentAuto
	autoConfig.Java.RemoteParent.RetrievalTTL = time.Nanosecond
	autoTracer := New(&autoConfig, nil)
	autoTracer.haveSockOpsNetnsCookie = func() error { return nil }
	autoBundles, err := autoTracer.LoadSpecs()
	require.NoError(t, err)
	requireConnectionScopedSSLPrewriteMaps(t, autoBundles[0].Spec)
	require.Len(t, autoBundles, len(unixBundles))
	assert.NotNil(t, autoTracer.javaRemoteParentMapsSpec)
	assert.NotNil(t, autoTracer.javaRemoteParentSpec)
	assert.False(t, autoTracer.javaRemoteParentLoaded)

	constants := autoTracer.javaRemoteParentConstants()
	assert.Equal(t, uint64(time.Nanosecond), constants["java_remote_parent_max_age_ns"])
	assert.Equal(t, uint64(autoConfig.Java.RemoteParent.TTL.Nanoseconds()), autoTracer.constants()["ssl_prewrite_max_age_ns"])
	assert.Equal(t, int32(1), constants["filter_pids"])
	assert.Equal(t, true, constants["java_remote_parent_enabled"])
	assert.Contains(t, constants, "g_bpf_debug")
}

func TestJavaRemoteParentSpecFailurePreservesStage(t *testing.T) {
	originalProbe := haveCgroupSockopt
	originalValidation := validateCgroupSockoptSpec
	t.Cleanup(func() {
		haveCgroupSockopt = originalProbe
		validateCgroupSockoptSpec = originalValidation
	})

	cfg := obi.DefaultConfig
	require.NoError(t, cfg.EBPF.ContextPropagation.UnmarshalText([]byte("tcp")))
	cfg.Java.RemoteParent.Transport = obi.JavaRemoteParentAuto

	t.Run("program type probe", func(t *testing.T) {
		probeErr := errors.Join(errors.New("cgroup sockopt probe"), ebpf.ErrNotSupported)
		haveCgroupSockopt = func() error { return probeErr }

		tracer := New(&cfg, nil)
		tracer.haveSockOpsNetnsCookie = func() error { return nil }
		_, err := tracer.LoadSpecs()
		require.NoError(t, err)
		require.ErrorIs(t, tracer.javaRemoteParentError, probeErr)
		assert.Equal(t, javaRemoteParentStageProbe, tracer.javaRemoteParentErrorStage)
	})

	t.Run("program validation", func(t *testing.T) {
		verifierErr := &ebpf.VerifierError{
			Cause: unix.EACCES,
			Log:   []string{"R0 invalid verifier state"},
		}
		haveCgroupSockopt = func() error { return nil }
		validateCgroupSockoptSpec = func(*ebpf.CollectionSpec, map[string]any) error {
			return verifierErr
		}

		reporter := &javaRemoteParentRecordingReporter{}
		var logs bytes.Buffer
		tracer := New(&cfg, reporter)
		tracer.log = slog.New(slog.NewTextHandler(&logs, nil))
		tracer.haveSockOpsNetnsCookie = func() error { return nil }
		_, err := tracer.LoadSpecs()
		require.NoError(t, err)
		require.ErrorIs(t, tracer.javaRemoteParentError, verifierErr)
		assert.Equal(t, javaRemoteParentStageLoad, tracer.javaRemoteParentErrorStage)
		assert.Equal(
			t,
			javaRemoteParentStatusVerifierRejected,
			javaRemoteParentAvailabilityReason(
				tracer.javaRemoteParentErrorStage,
				tracer.javaRemoteParentError,
			),
		)
		tracer.reportJavaRemoteParentTransportUnavailable(
			"Java remote-parent getsockopt transport unavailable",
			"getsockopt",
			tracer.javaRemoteParentErrorStage,
			tracer.javaRemoteParentError,
		)
		assert.Equal(t, []javaRemoteParentObservation{{
			transport: "getsockopt",
			operation: javaRemoteParentAvailabilityOperation,
			status:    javaRemoteParentStatusVerifierRejected,
			count:     1,
		}}, reporter.observations)
		assert.Contains(t, logs.String(), "stage=load")
		assert.Contains(t, logs.String(), "reason=verifier_rejected")
		assert.NotContains(t, logs.String(), "reason=permission_denied")
	})
}

func TestJavaRemoteParentStatLabelsIdentifyTransport(t *testing.T) {
	assert.Equal(t, [javaRemoteParentStatCount]javaRemoteParentStatLabel{
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
	}, javaRemoteParentStatLabels)
	assert.Equal(t, javaRemoteParentStatLabel{
		transport: "tcp", operation: "stage", status: "valid",
	}, javaRemoteParentStatLabels[javaRemoteParentStatStageValid])
	assert.Equal(t, "unauthorized", javaRemoteParentStatLabels[javaRemoteParentStatTakeUnauthorized].status)
	assert.Equal(t, "valid", javaRemoteParentStatLabels[javaRemoteParentStatDiscardValid].status)
	assert.Equal(t, "unauthorized", javaRemoteParentStatLabels[javaRemoteParentStatDiscardUnauthorized].status)
	assert.Equal(t, javaRemoteParentStatLabel{
		transport: "tcp", operation: "inject", status: "ambiguous",
	}, javaRemoteParentStatLabels[javaRemoteParentStatInjectAmbiguous])
}

func TestJavaRemoteParentReportMetricCompletesStatPublication(t *testing.T) {
	reporter := &javaRemoteParentRecordingReporter{}
	tracer := &Tracer{metrics: reporter}
	var previous [javaRemoteParentStatCount]uint64
	var current [javaRemoteParentStatCount]uint64
	current[javaRemoteParentStatStageValid] = 1
	current[javaRemoteParentStatInjectAmbiguous] = 2

	tracer.reportJavaRemoteParentStatDeltas(previous, current)
	tracer.reportJavaRemoteParentStatDeltas(current, current)

	assert.Equal(t, []javaRemoteParentObservation{
		{transport: "tcp", operation: "stage", status: "valid", count: 1},
		{transport: "tcp", operation: "inject", status: "ambiguous", count: 2},
		{transport: "tcp", operation: "report", status: "valid", count: 1},
		{transport: "tcp", operation: "report", status: "valid", count: 1},
	}, reporter.observations)
}

func TestJavaRemoteParentMetricsUseConfiguredBPFInterval(t *testing.T) {
	reporter := &javaRemoteParentRecordingReporter{bpfMetricInterval: time.Second}
	tracer := &Tracer{metrics: reporter}
	assert.Equal(t, time.Second, tracer.javaRemoteParentMetricsPollInterval())

	reporter.bpfMetricInterval = 0
	assert.Equal(t, javaRemoteParentPollInterval, tracer.javaRemoteParentMetricsPollInterval())
}

func TestJavaRemoteParentMetricCardinalityContract(t *testing.T) {
	transports := map[string]struct{}{
		"tcp":        {},
		"getsockopt": {},
		"unix":       {},
		"disabled":   {},
	}
	operations := map[string]struct{}{
		"stage":        {},
		"candidate":    {},
		"handoff":      {},
		"take":         {},
		"discard":      {},
		"negotiate":    {},
		"availability": {},
		"cleanup":      {},
		"evict":        {},
		"inject":       {},
		"report":       {},
	}
	statuses := map[string]struct{}{}
	for status := javabridge.StatusUnknown; status <= javabridge.StatusDisabled; status++ {
		statuses[status.String()] = struct{}{}
	}
	statuses["segmented"] = struct{}{}
	statuses[javaRemoteParentStatusLoadDenied] = struct{}{}
	statuses[javaRemoteParentStatusPermissionDenied] = struct{}{}
	statuses[javaRemoteParentStatusVerifierRejected] = struct{}{}
	stages := map[javaRemoteParentAvailabilityStage]struct{}{
		javaRemoteParentStageProbe:     {},
		javaRemoteParentStageLoad:      {},
		javaRemoteParentStageAttach:    {},
		javaRemoteParentStageReadiness: {},
		javaRemoteParentStageListen:    {},
		javaRemoteParentStageServe:     {},
	}

	require.Len(t, transports, 4)
	require.Len(t, operations, 11)
	require.Len(t, statuses, 18)
	require.Len(t, stages, 6)
	assert.Equal(t, 792, len(transports)*len(operations)*len(statuses))

	seen := map[javaRemoteParentStatLabel]struct{}{}
	for _, label := range javaRemoteParentStatLabels {
		assert.Contains(t, transports, label.transport)
		assert.Contains(t, operations, label.operation)
		assert.Contains(t, statuses, label.status)
		assert.NotContains(t, seen, label)
		seen[label] = struct{}{}
	}
}

func TestDisabledJavaRemoteParentReportsAvailabilityOnce(t *testing.T) {
	reporter := &javaRemoteParentRecordingReporter{}
	var logs bytes.Buffer
	cfg := obi.DefaultConfig
	cfg.Java.RemoteParent.Transport = obi.JavaRemoteParentDisabled
	tracer := New(&cfg, reporter)
	tracer.haveSockOpsNetnsCookie = func() error {
		t.Fatal("disabled Java remote parent unexpectedly probed sockops helpers")
		return nil
	}
	bundles, err := tracer.LoadSpecs()
	require.NoError(t, err)
	requireConnectionScopedSSLPrewriteMaps(t, bundles[0].Spec)

	tracer.log = slog.New(slog.NewTextHandler(&logs, nil))
	stop := tracer.runJavaRemoteParent(context.Background())
	stop()

	assert.Equal(t, []javaRemoteParentObservation{{
		transport: "disabled",
		operation: javaRemoteParentAvailabilityOperation,
		status:    "disabled",
		count:     1,
	}}, reporter.observations)
	assert.Empty(t, logs.String())
}

func TestUnsupportedJavaRemoteParentKeepsTPInjectorLoadable(t *testing.T) {
	unsupported := errors.Join(
		errors.New("network namespace cookie helper unavailable"),
		ebpf.ErrNotSupported,
	)
	reporter := &javaRemoteParentRecordingReporter{}
	var logs bytes.Buffer
	cfg := obi.DefaultConfig
	require.NoError(t, cfg.EBPF.ContextPropagation.UnmarshalText([]byte("tcp")))
	cfg.Java.RemoteParent.Transport = obi.JavaRemoteParentAuto
	tracer := New(&cfg, reporter)
	tracer.log = slog.New(slog.NewTextHandler(&logs, nil))
	tracer.haveSockOpsNetnsCookie = func() error { return unsupported }

	bundles, err := tracer.LoadSpecs()
	require.NoError(t, err)
	require.NotEmpty(t, bundles)
	requireConnectionScopedSSLPrewriteMaps(t, bundles[0].Spec)
	assert.Equal(t, false, bundles[0].Constants["java_remote_parent_enabled"])
	require.ErrorIs(t, tracer.javaRemoteParentSupportErr, unsupported)
	assert.Nil(t, tracer.javaRemoteParentMapsSpec)
	assert.Nil(t, tracer.javaRemoteParentSpec)

	stop := tracer.runJavaRemoteParent(context.Background())
	stop()
	assert.ElementsMatch(t, []javaRemoteParentObservation{
		{
			transport: "getsockopt",
			operation: "availability",
			status:    "unsupported",
			count:     1,
		},
		{
			transport: "unix",
			operation: "availability",
			status:    "unsupported",
			count:     1,
		},
	}, reporter.observations)
	assert.Contains(t, logs.String(), "stage=probe")
	assert.Contains(t, logs.String(), "reason=unsupported")
}

func TestUnavailableJavaRemoteParentMapsReportSelectedTransports(t *testing.T) {
	for _, tt := range []struct {
		name         string
		transport    obi.JavaRemoteParentTransport
		observations []javaRemoteParentObservation
	}{
		{
			name:      "automatic",
			transport: obi.JavaRemoteParentAuto,
			observations: []javaRemoteParentObservation{
				{
					transport: "getsockopt",
					operation: "availability",
					status:    "missing",
					count:     1,
				},
				{
					transport: "unix",
					operation: "availability",
					status:    "missing",
					count:     1,
				},
			},
		},
		{
			name:      "getsockopt",
			transport: obi.JavaRemoteParentGetsockopt,
			observations: []javaRemoteParentObservation{{
				transport: "getsockopt",
				operation: "availability",
				status:    "missing",
				count:     1,
			}},
		},
		{
			name:      "unix",
			transport: obi.JavaRemoteParentUnix,
			observations: []javaRemoteParentObservation{{
				transport: "unix",
				operation: "availability",
				status:    "missing",
				count:     1,
			}},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reporter := &javaRemoteParentRecordingReporter{}
			var logs bytes.Buffer
			cfg := obi.DefaultConfig
			cfg.Java.RemoteParent.Transport = tt.transport
			tracer := New(&cfg, reporter)
			tracer.log = slog.New(slog.NewTextHandler(&logs, nil))

			stop := tracer.runJavaRemoteParent(context.Background())
			stop()

			assert.ElementsMatch(t, tt.observations, reporter.observations)
			assert.Contains(t, logs.String(), "stage=load")
			assert.Contains(t, logs.String(), "reason=missing")
		})
	}
}

func TestJavaRemoteParentCleanupStatsAreObserved(t *testing.T) {
	reporter := &javaRemoteParentRecordingReporter{}
	tracer := New(&obi.DefaultConfig, reporter)

	tracer.reportJavaRemoteParentCleanup(
		javabridge.CleanupStats{Cleaned: 3, Evicted: 1},
		errors.New("sweep failed"),
	)

	assert.Equal(t, []javaRemoteParentObservation{
		{
			transport: "tcp",
			operation: "cleanup",
			status:    "valid",
			count:     3,
		},
		{
			transport: "tcp",
			operation: "evict",
			status:    "valid",
			count:     1,
		},
		{
			transport: "tcp",
			operation: "cleanup",
			status:    "transport_error",
			count:     1,
		},
	}, reporter.observations)
}

func TestJavaRemoteParentWaitsForLateDataHookReadiness(t *testing.T) {
	originalReadiness := readJavaRemoteParentDataHookReadiness
	t.Cleanup(func() { readJavaRemoteParentDataHookReadiness = originalReadiness })

	reads := 0
	readJavaRemoteParentDataHookReadiness = func(_ *ebpf.Map) (bool, error) {
		reads++
		return reads >= 2, nil
	}

	cfg := obi.DefaultConfig
	tracer := New(&cfg, nil)
	tracer.bpfJavaRemoteParentMaps.JavaRemoteParentDataHookReadiness = &ebpf.Map{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	assert.True(t, tracer.waitForJavaRemoteParentDataHook(ctx))
	assert.Equal(t, 2, reads)
}

type javaRemoteParentTestCloser struct {
	closeCalls int
	err        error
}

func (c *javaRemoteParentTestCloser) Close() error {
	c.closeCalls++
	return c.err
}

func TestJavaRemoteParentPartialSockoptAttachClosesFirstLink(t *testing.T) {
	originalGet := attachCgroupGetsockopt
	originalSet := attachCgroupSetsockopt
	t.Cleanup(func() {
		attachCgroupGetsockopt = originalGet
		attachCgroupSetsockopt = originalSet
	})

	attachErr := errors.New("setsockopt attach failed")
	closeErr := errors.New("getsockopt close failed")
	getLink := &javaRemoteParentTestCloser{err: closeErr}
	attachCgroupGetsockopt = func(*ebpf.Program) (io.Closer, error) {
		return getLink, nil
	}
	attachCgroupSetsockopt = func(*ebpf.Program) (io.Closer, error) {
		return nil, attachErr
	}

	link, err := attachJavaRemoteParentSockopt(nil, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, attachErr)
	require.ErrorIs(t, err, closeErr)
	var partialErr *javaRemoteParentSockoptAttachError
	require.ErrorAs(t, err, &partialErr)
	assert.Same(t, attachErr, partialErr.attach)
	assert.Same(t, closeErr, partialErr.rollback)
	assert.Nil(t, link)
	assert.Equal(t, 1, getLink.closeCalls)
}

func TestJavaRemoteParentDefaultSockoptAttachersUseCgroupLinks(t *testing.T) {
	originalLink := attachJavaRemoteParentCgroupLink
	originalGet := attachCgroupGetsockopt
	originalSet := attachCgroupSetsockopt
	t.Cleanup(func() {
		attachJavaRemoteParentCgroupLink = originalLink
		attachCgroupGetsockopt = originalGet
		attachCgroupSetsockopt = originalSet
	})

	attachErr := errors.New("link attach attempted")
	var attachTypes []ebpf.AttachType
	attachJavaRemoteParentCgroupLink = func(
		_ *ebpf.Program,
		attach ebpf.AttachType,
	) (*link.RawLink, error) {
		attachTypes = append(attachTypes, attach)
		return nil, attachErr
	}

	_, err := originalGet(nil)
	require.ErrorIs(t, err, attachErr)
	_, err = originalSet(nil)
	require.ErrorIs(t, err, attachErr)
	require.Equal(t, []ebpf.AttachType{
		ebpf.AttachCGroupGetsockopt,
		ebpf.AttachCGroupSetsockopt,
	}, attachTypes)
}

func TestJavaRemoteParentFailedFirstAttachSkipsSecondAttach(t *testing.T) {
	originalGet := attachCgroupGetsockopt
	originalSet := attachCgroupSetsockopt
	t.Cleanup(func() {
		attachCgroupGetsockopt = originalGet
		attachCgroupSetsockopt = originalSet
	})

	attachErr := errors.New("getsockopt attach failed")
	attachCgroupGetsockopt = func(*ebpf.Program) (io.Closer, error) {
		return nil, attachErr
	}
	attachCgroupSetsockopt = func(*ebpf.Program) (io.Closer, error) {
		t.Fatal("setsockopt attach attempted after getsockopt attach failed")
		return nil, nil
	}

	link, err := attachJavaRemoteParentSockopt(nil, nil)
	require.ErrorIs(t, err, attachErr)
	assert.Nil(t, link)
}

func TestJavaRemoteParentSockoptCloseCombinesLinkErrors(t *testing.T) {
	originalGet := attachCgroupGetsockopt
	originalSet := attachCgroupSetsockopt
	t.Cleanup(func() {
		attachCgroupGetsockopt = originalGet
		attachCgroupSetsockopt = originalSet
	})

	getCloseErr := errors.New("getsockopt close failed")
	setCloseErr := errors.New("setsockopt close failed")
	getLink := &javaRemoteParentTestCloser{err: getCloseErr}
	setLink := &javaRemoteParentTestCloser{err: setCloseErr}
	attachCgroupGetsockopt = func(*ebpf.Program) (io.Closer, error) {
		return getLink, nil
	}
	attachCgroupSetsockopt = func(*ebpf.Program) (io.Closer, error) {
		return setLink, nil
	}

	links, err := attachJavaRemoteParentSockopt(nil, nil)
	require.NoError(t, err)
	require.NotNil(t, links)
	err = links.Close()
	require.ErrorIs(t, err, getCloseErr)
	require.ErrorIs(t, err, setCloseErr)
	assert.Equal(t, 1, getLink.closeCalls)
	assert.Equal(t, 1, setLink.closeCalls)
}

type javaRemoteParentRestartTestServer struct {
	serve func(context.Context) error
	close func() error
}

func (s *javaRemoteParentRestartTestServer) Serve(ctx context.Context) error {
	return s.serve(ctx)
}

func (s *javaRemoteParentRestartTestServer) Close() error {
	return s.close()
}

func TestJavaRemoteParentAvailabilityReason(t *testing.T) {
	for _, tt := range []struct {
		name     string
		stage    javaRemoteParentAvailabilityStage
		err      error
		expected string
	}{
		{
			name:     "BPF load denied",
			stage:    javaRemoteParentStageLoad,
			err:      unix.EPERM,
			expected: javaRemoteParentStatusLoadDenied,
		},
		{
			name:     "wrapped BPF load denied",
			stage:    javaRemoteParentStageLoad,
			err:      errors.Join(errors.New("loading maps"), unix.EACCES),
			expected: javaRemoteParentStatusLoadDenied,
		},
		{
			name:  "verifier rejection",
			stage: javaRemoteParentStageLoad,
			err: &ebpf.VerifierError{
				Cause: unix.EACCES,
				Log:   []string{"R0 invalid verifier state"},
			},
			expected: javaRemoteParentStatusVerifierRejected,
		},
		{
			name:  "probe denial without verifier output",
			stage: javaRemoteParentStageProbe,
			err: &ebpf.VerifierError{
				Cause: unix.EACCES,
			},
			expected: javaRemoteParentStatusPermissionDenied,
		},
		{
			name:  "load denial without verifier output",
			stage: javaRemoteParentStageLoad,
			err: &ebpf.VerifierError{
				Cause: unix.EPERM,
			},
			expected: javaRemoteParentStatusLoadDenied,
		},
		{
			name:     "attach operation not permitted",
			stage:    javaRemoteParentStageAttach,
			err:      unix.EPERM,
			expected: javaRemoteParentStatusPermissionDenied,
		},
		{
			name:     "wrapped attach permission denied",
			stage:    javaRemoteParentStageAttach,
			err:      errors.Join(errors.New("cgroup attach failed"), unix.EACCES),
			expected: javaRemoteParentStatusPermissionDenied,
		},
		{
			name:     "permission denial takes precedence over feature absence",
			stage:    javaRemoteParentStageAttach,
			err:      errors.Join(ebpf.ErrNotSupported, unix.EPERM),
			expected: javaRemoteParentStatusPermissionDenied,
		},
		{
			name:  "rollback denial does not mask unsupported attach",
			stage: javaRemoteParentStageAttach,
			err: &javaRemoteParentSockoptAttachError{
				attach:   ebpf.ErrNotSupported,
				rollback: unix.EACCES,
			},
			expected: javabridge.StatusUnsupported.String(),
		},
		{
			name:     "deadline exceeded",
			stage:    javaRemoteParentStageListen,
			err:      context.DeadlineExceeded,
			expected: javabridge.StatusTimeout.String(),
		},
		{
			name:     "system timeout",
			stage:    javaRemoteParentStageListen,
			err:      unix.ETIMEDOUT,
			expected: javabridge.StatusTimeout.String(),
		},
		{
			name:     "buffer exhaustion",
			stage:    javaRemoteParentStageListen,
			err:      unix.ENOBUFS,
			expected: javabridge.StatusOverload.String(),
		},
		{
			name:     "memory exhaustion",
			stage:    javaRemoteParentStageLoad,
			err:      unix.ENOMEM,
			expected: javabridge.StatusOverload.String(),
		},
		{
			name:     "capacity exhaustion",
			stage:    javaRemoteParentStageLoad,
			err:      unix.ENOSPC,
			expected: javabridge.StatusOverload.String(),
		},
		{
			name:     "process file descriptor exhaustion",
			stage:    javaRemoteParentStageListen,
			err:      unix.EMFILE,
			expected: javabridge.StatusOverload.String(),
		},
		{
			name:     "system file descriptor exhaustion",
			stage:    javaRemoteParentStageListen,
			err:      unix.ENFILE,
			expected: javabridge.StatusOverload.String(),
		},
		{
			name:     "unavailable without an error",
			stage:    javaRemoteParentStageReadiness,
			err:      nil,
			expected: javabridge.StatusMissing.String(),
		},
		{
			name:     "missing path",
			stage:    javaRemoteParentStageAttach,
			err:      unix.ENOENT,
			expected: javabridge.StatusMissing.String(),
		},
		{
			name:     "missing device",
			stage:    javaRemoteParentStageAttach,
			err:      unix.ENODEV,
			expected: javabridge.StatusMissing.String(),
		},
		{
			name:     "unsupported hierarchy takes precedence over probe path absence",
			stage:    javaRemoteParentStageAttach,
			err:      errors.Join(ebpf.ErrNotSupported, unix.ENOENT),
			expected: javabridge.StatusUnsupported.String(),
		},
		{
			name:     "kernel feature unavailable",
			stage:    javaRemoteParentStageProbe,
			err:      ebpf.ErrNotSupported,
			expected: javabridge.StatusUnsupported.String(),
		},
		{
			name:     "wrapped kernel feature unavailable",
			stage:    javaRemoteParentStageProbe,
			err:      errors.Join(errors.New("feature probe"), ebpf.ErrNotSupported),
			expected: javabridge.StatusUnsupported.String(),
		},
		{
			name:     "socket option unavailable",
			stage:    javaRemoteParentStageProbe,
			err:      unix.ENOPROTOOPT,
			expected: javabridge.StatusUnsupported.String(),
		},
		{
			name:     "operation unsupported",
			stage:    javaRemoteParentStageProbe,
			err:      unix.EOPNOTSUPP,
			expected: javabridge.StatusUnsupported.String(),
		},
		{
			name:     "system call unavailable",
			stage:    javaRemoteParentStageProbe,
			err:      unix.ENOSYS,
			expected: javabridge.StatusUnsupported.String(),
		},
		{
			name:     "inconclusive feature probe",
			stage:    javaRemoteParentStageProbe,
			err:      errors.New("kernel helper probe failed"),
			expected: javabridge.StatusTransportError.String(),
		},
		{
			name:  "opaque cgroup path permission failure",
			stage: javaRemoteParentStageAttach,
			err: errors.New(
				"can't open cgroup: open /sys/fs/cgroup: permission denied",
			),
			expected: javabridge.StatusTransportError.String(),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, javaRemoteParentAvailabilityReason(tt.stage, tt.err))
		})
	}
}

func TestJavaRemoteParentAutoFallsBackOnPrimaryPermissionFailure(t *testing.T) {
	originalGet := attachCgroupGetsockopt
	originalSet := attachCgroupSetsockopt
	originalReadiness := readJavaRemoteParentDataHookReadiness
	originalServer := newJavaRemoteParentFallbackServer
	t.Cleanup(func() {
		attachCgroupGetsockopt = originalGet
		attachCgroupSetsockopt = originalSet
		readJavaRemoteParentDataHookReadiness = originalReadiness
		newJavaRemoteParentFallbackServer = originalServer
	})

	for _, tt := range []struct {
		name string
		err  error
	}{
		{name: "operation not permitted", err: unix.EPERM},
		{name: "permission denied", err: unix.EACCES},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			setsockoptCalled := false
			attachCgroupGetsockopt = func(*ebpf.Program) (io.Closer, error) {
				return nil, tt.err
			}
			attachCgroupSetsockopt = func(*ebpf.Program) (io.Closer, error) {
				setsockoptCalled = true
				return nil, nil
			}
			readJavaRemoteParentDataHookReadiness = func(*ebpf.Map) (bool, error) {
				return true, nil
			}

			started := make(chan struct{})
			serverClosed := false
			newJavaRemoteParentFallbackServer = func(
				javabridge.ServerOptions,
				javabridge.Handler,
			) (javaRemoteParentFallbackServer, error) {
				return &javaRemoteParentRestartTestServer{
					serve: func(ctx context.Context) error {
						close(started)
						<-ctx.Done()
						return ctx.Err()
					},
					close: func() error {
						serverClosed = true
						return nil
					},
				}, nil
			}

			reporter := &javaRemoteParentRecordingReporter{}
			cfg := obi.DefaultConfig
			cfg.Java.RemoteParent.Transport = obi.JavaRemoteParentAuto
			tracer := New(&cfg, reporter)
			tracer.log = slog.New(slog.NewTextHandler(&logs, nil))
			tracer.javaRemoteParentLoaded = true
			tracer.bpfJavaRemoteParentMaps.JavaRemoteParentDataHookReadiness = &ebpf.Map{}

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				defer close(done)
				tracer.runJavaRemoteParentTransports(ctx, nil)
			}()

			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("fallback transport did not start")
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("transport shutdown did not complete")
			}

			assert.False(t, setsockoptCalled)
			assert.True(t, serverClosed)
			assert.Equal(t, []javaRemoteParentObservation{
				{
					transport: "getsockopt",
					operation: "availability",
					status:    "permission_denied",
					count:     1,
				},
				{
					transport: "unix",
					operation: javaRemoteParentAvailabilityOperation,
					status:    "valid",
					count:     1,
				},
			}, reporter.observations)
			assert.Contains(t, logs.String(), "stage=attach")
			assert.Contains(t, logs.String(), "reason=permission_denied")
		})
	}
}

func TestJavaRemoteParentFallbackRecoversAfterServeFailure(t *testing.T) {
	originalReadiness := readJavaRemoteParentDataHookReadiness
	originalServer := newJavaRemoteParentFallbackServer
	originalInitial := javaRemoteParentRetryInitial
	originalMax := javaRemoteParentRetryMax
	t.Cleanup(func() {
		readJavaRemoteParentDataHookReadiness = originalReadiness
		newJavaRemoteParentFallbackServer = originalServer
		javaRemoteParentRetryInitial = originalInitial
		javaRemoteParentRetryMax = originalMax
	})

	readJavaRemoteParentDataHookReadiness = func(_ *ebpf.Map) (bool, error) {
		return true, nil
	}
	javaRemoteParentRetryInitial = time.Millisecond
	javaRemoteParentRetryMax = 4 * time.Millisecond

	created := 0
	closed := 0
	recovered := make(chan struct{})
	newJavaRemoteParentFallbackServer = func(
		javabridge.ServerOptions,
		javabridge.Handler,
	) (javaRemoteParentFallbackServer, error) {
		created++
		if created == 1 {
			return &javaRemoteParentRestartTestServer{
				serve: func(context.Context) error { return errors.New("accept failed") },
				close: func() error {
					closed++
					return nil
				},
			}, nil
		}
		return &javaRemoteParentRestartTestServer{
			serve: func(ctx context.Context) error {
				close(recovered)
				<-ctx.Done()
				return nil
			},
			close: func() error {
				closed++
				return nil
			},
		}, nil
	}

	reporter := &javaRemoteParentRecordingReporter{}
	cfg := obi.DefaultConfig
	cfg.Java.RemoteParent.Transport = obi.JavaRemoteParentUnix
	tracer := New(&cfg, reporter)
	tracer.bpfJavaRemoteParentMaps.JavaRemoteParentDataHookReadiness = &ebpf.Map{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		tracer.runJavaRemoteParentTransports(ctx, nil)
	}()

	select {
	case <-recovered:
	case <-time.After(time.Second):
		t.Fatal("fallback transport did not recover")
	}
	cancel()
	<-done

	assert.Equal(t, 2, created)
	assert.Equal(t, 2, closed)
	assert.Contains(t, reporter.observations, javaRemoteParentObservation{
		transport: "unix",
		operation: "availability",
		status:    "transport_error",
		count:     1,
	})
	validTransitions := 0
	for _, observation := range reporter.observations {
		if observation.transport == "unix" &&
			observation.operation == javaRemoteParentAvailabilityOperation &&
			observation.status == "valid" {
			validTransitions++
		}
	}
	assert.Equal(t, 2, validTransitions)
}

type javaRemoteParentObservation struct {
	transport string
	operation string
	status    string
	count     uint64
}

type javaRemoteParentRecordingReporter struct {
	imetrics.NoopReporter
	bpfMetricInterval time.Duration
	observations      []javaRemoteParentObservation
}

func (r *javaRemoteParentRecordingReporter) BpfInternalMetricsScrapeInterval() time.Duration {
	return r.bpfMetricInterval
}

func (r *javaRemoteParentRecordingReporter) JavaRemoteParent(
	transport string,
	operation string,
	status string,
	count uint64,
) {
	r.observations = append(r.observations, javaRemoteParentObservation{
		transport: transport,
		operation: operation,
		status:    status,
		count:     count,
	})
}

func TestJavaRemoteParentProcessExitCleanupIsRequired(t *testing.T) {
	cfg := obi.DefaultConfig
	require.NoError(t, cfg.EBPF.ContextPropagation.UnmarshalText([]byte("tcp")))
	cfg.Java.RemoteParent.Transport = obi.JavaRemoteParentUnix

	tracer := New(&cfg, nil)
	tracer.haveSockOpsNetnsCookie = func() error { return nil }
	_, err := tracer.LoadSpecs()
	require.NoError(t, err)
	tracepoints := tracer.Tracepoints()
	require.Contains(t, tracepoints, "sched/sched_process_exit")
	assert.True(t, tracepoints["sched/sched_process_exit"].Required)

	disabledConfig := obi.DefaultConfig
	require.NoError(t, disabledConfig.EBPF.ContextPropagation.UnmarshalText([]byte("tcp")))
	disabled := New(&disabledConfig, nil)
	_, err = disabled.LoadSpecs()
	require.NoError(t, err)
	assert.NotContains(t, disabled.Tracepoints(), "sched/sched_process_exit")
}

func TestJavaRemoteParentBridgeModeProductionOrdering(t *testing.T) {
	source := readTPInjectorSource(t)

	packetExtender := sourceSection(
		t,
		source,
		"int obi_packet_extender(struct sk_msg_md *msg)",
		"int obi_packet_extender_write_msg_tp(struct sk_msg_md *msg)",
	)
	genericGate := sourcePosition(
		t,
		packetExtender,
		"if (!tcp_traceparent_generic_injection_allowed(java_remote_parent_enabled))",
	)
	genericGateExit := genericGate + sourcePosition(
		t,
		packetExtender[genericGate:],
		"return SK_PASS;",
	)
	legacyLookup := sourcePosition(t, packetExtender, "get_tp_info_pid(&e_key)")
	goGRPCHandling := sourcePosition(t, packetExtender, "is_go_grpc_client_conn")
	protocolDetection := sourcePosition(t, packetExtender, "protocol_detector(msg, id, &conn)")
	http2Handling := sourcePosition(t, packetExtender, "wrap_http2_traceparent")
	assert.Less(t, genericGate, legacyLookup)
	assert.Less(t, genericGate, goGRPCHandling)
	assert.Less(t, genericGate, protocolDetection)
	assert.Less(t, genericGate, http2Handling)
	genericDisabled := packetExtender[genericGate:genericGateExit]
	assert.Contains(t, genericDisabled, "monitored_pid || is_go_grpc_client_conn")
	assert.Contains(t, genericDisabled, "bpf_msg_pull_data(msg, 0, msg->size, 0)")
	assert.Contains(t, genericDisabled, "fill_msg_buffers(msg, &t_ctx->p_conn, &e_key)")
	assert.NotContains(t, genericDisabled, "protocol_detector")
	assert.NotContains(t, genericDisabled, "bpf_tail_call_static")
	assert.NotContains(t, genericDisabled, "bpf_msg_push_data")
	assert.NotContains(t, genericDisabled, "schedule_write_tcp_option")
	assert.NotContains(t, genericDisabled, "write_http_traceparent")

	prewriteHandling := sourceSection(
		t,
		source,
		"static __always_inline bool handle_ssl_prewrite",
		"// Sock_msg program which detects packets",
	)
	assert.Contains(t, prewriteHandling, "ssl_prewrite_connection_owners")
	assert.Contains(t, prewriteHandling, "ssl_prewrite_connection_ambiguity")
	assert.NotContains(t, prewriteHandling, "active_ssl_write_args")

	localCommit := sourceSection(
		t,
		source,
		"commit_ssl_prewrite_transport_local",
		"static __always_inline u8 ssl_prewrite_opt_len_matches_segment",
	)
	assert.Contains(
		t,
		localCommit,
		"info->ssl_prewrite_pending != k_ssl_prewrite_local_pending",
	)

	existingParent := sourceSection(
		t,
		source,
		"static __always_inline bool handle_existing_tp_pid",
		"static __always_inline bool handle_ssl_prewrite",
	)
	legacySchedule := sourcePosition(t, existingParent, "schedule_write_tcp_option(msg, tp_pid, 0)")
	invalidParent := sourcePosition(
		t,
		existingParent,
		"if (!(action & k_tcp_traceparent_existing_parent_continue_plaintext))",
	)
	assert.Less(t, legacySchedule, invalidParent)
	assert.Contains(
		t,
		existingParent[:invalidParent],
		"tcp_traceparent_existing_parent_action",
	)

	optionLength := sourceSection(
		t,
		source,
		"static __noinline void bpf_sock_ops_opt_len_cb",
		"static __noinline void bpf_sock_ops_write_hdr_cb",
	)
	legacyDecision := sourcePosition(
		t,
		optionLength,
		"tcp_traceparent_legacy_opt_len_action(java_remote_parent_enabled, tp_pid != NULL)",
	)
	legacyReservation := sourcePosition(
		t,
		optionLength,
		"bpf_reserve_hdr_opt(skops, option_size, 0);",
	)
	assert.Less(t, legacyDecision, legacyReservation)
	assert.NotContains(
		t,
		optionLength[legacyDecision:],
		"bpf_reserve_hdr_opt(skops, option_size, 0) != 0",
	)

	targetPosition := sourceSection(
		t,
		source,
		"static __always_inline enum tcp_traceparent_target_position ssl_prewrite_write_target_position",
		"static __noinline void bpf_sock_ops_opt_len_cb",
	)
	assert.Contains(t, targetPosition, "(const void *)(tcp + 1) > data_end")
	assert.Contains(t, targetPosition, "tcp_traceparent_write_packet_valid")
	assert.NotContains(t, targetPosition, "(const void *)tcp + tcp_header_len > data_end")

	optionWrite := sourceSection(
		t,
		source,
		"static __noinline void bpf_sock_ops_write_hdr_cb",
		"static __always_inline u8 tcp_sequence_from_sockops",
	)
	exactOwnerCheck := sourcePosition(
		t,
		optionWrite,
		"if (!ssl_prewrite_connection_has_exact_owner(prewrite, &owner->key))",
	)
	localCommitCall := sourcePosition(t, optionWrite, "commit_ssl_prewrite_transport_local(prewrite)")
	finalExactOwnerCheck := localCommitCall + sourcePosition(
		t,
		optionWrite[localCommitCall:],
		"if (!ssl_prewrite_connection_has_exact_owner(prewrite, &owner->key))",
	)
	prewriteStore := sourcePosition(t, optionWrite, "bpf_store_hdr_opt(skops, &opt, sizeof(opt), 0)")
	assert.Less(t, exactOwnerCheck, localCommitCall)
	assert.Less(t, localCommitCall, finalExactOwnerCheck)
	assert.Less(t, finalExactOwnerCheck, prewriteStore)
	writeGuard := sourcePosition(
		t,
		optionWrite,
		"if (!tcp_traceparent_legacy_option_allowed(java_remote_parent_enabled))",
	)
	legacyOption := sourcePosition(t, optionWrite, "tcp_traceparent_legacy_option_t opt")
	legacyStore := legacyOption + sourcePosition(
		t,
		optionWrite[legacyOption:],
		"bpf_store_hdr_opt(skops, &opt, sizeof(opt), 0)",
	)
	assert.Less(t, writeGuard, legacyOption)
	assert.Less(t, writeGuard, legacyStore)
}

func TestJavaRemoteParentLegacyCleanupHasNoInjectionOutcome(t *testing.T) {
	source := readTPInjectorSource(t)
	cleanup := sourceSection(
		t,
		source,
		"clear_legacy_ssl_parent(struct sk_msg_md *msg",
		"static __always_inline enum ssl_prewrite_transport_phase schedule_ssl_prewrite_tcp_option",
	)

	assert.Contains(t, cleanup, "clear_tp_info_pid(e_key)")
	assert.Contains(t, cleanup, "bpf_sk_storage_delete(&sk_tp_info_pid_map, sk)")
	assert.NotContains(t, cleanup, "java_remote_parent_stat_add")
	assert.NotContains(t, cleanup, "report_suppression")
}

func readTPInjectorSource(t *testing.T) string {
	t.Helper()
	_, testFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	path := filepath.Join(filepath.Dir(testFile), "../../../../bpf/tpinjector/tpinjector.c")
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(contents)
}

func sourceSection(t *testing.T, source, startMarker, endMarker string) string {
	t.Helper()
	start := sourcePosition(t, source, startMarker)
	endOffset := sourcePosition(t, source[start:], endMarker)
	require.Positive(t, endOffset)
	return source[start : start+endOffset]
}

func sourcePosition(t *testing.T, source, marker string) int {
	t.Helper()
	position := strings.Index(source, marker)
	require.NotEqualf(t, -1, position, "missing source marker %q", marker)
	return position
}
