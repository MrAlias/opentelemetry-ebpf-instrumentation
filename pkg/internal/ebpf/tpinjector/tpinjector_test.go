// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package tpinjector

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/export/imetrics"
	"go.opentelemetry.io/obi/pkg/internal/javabridge"
	"go.opentelemetry.io/obi/pkg/obi"
)

// tpinjector has two BPF specs: the main tpinjector (spec 0) and the sock iterator (spec 1).
const expectedSpecCount = 2

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
	assert.NotNil(t, unixTracer.javaRemoteParentMapsSpec)
	assert.Nil(t, unixTracer.javaRemoteParentSpec)

	autoConfig := unixConfig
	autoConfig.Java.RemoteParent.Transport = obi.JavaRemoteParentAuto
	autoTracer := New(&autoConfig, nil)
	autoTracer.haveSockOpsNetnsCookie = func() error { return nil }
	autoBundles, err := autoTracer.LoadSpecs()
	require.NoError(t, err)
	require.Len(t, autoBundles, len(unixBundles))
	assert.NotNil(t, autoTracer.javaRemoteParentMapsSpec)
	assert.NotNil(t, autoTracer.javaRemoteParentSpec)
	assert.False(t, autoTracer.javaRemoteParentLoaded)

	constants := autoTracer.javaRemoteParentConstants()
	assert.Equal(t, uint64(autoConfig.Java.RemoteParent.TTL.Nanoseconds()), constants["java_remote_parent_max_age_ns"])
	assert.Equal(t, int32(1), constants["filter_pids"])
	assert.Equal(t, true, constants["java_remote_parent_enabled"])
	assert.Contains(t, constants, "g_bpf_debug")
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
	}, javaRemoteParentStatLabels)
	assert.Equal(t, "unauthorized", javaRemoteParentStatLabels[javaRemoteParentStatTakeUnauthorized].status)
	assert.Equal(t, "valid", javaRemoteParentStatLabels[javaRemoteParentStatDiscardValid].status)
	assert.Equal(t, "unauthorized", javaRemoteParentStatLabels[javaRemoteParentStatDiscardUnauthorized].status)
}

func TestDisabledJavaRemoteParentReportsSelectionOnce(t *testing.T) {
	reporter := &javaRemoteParentRecordingReporter{}
	cfg := obi.DefaultConfig
	cfg.Java.RemoteParent.Transport = obi.JavaRemoteParentDisabled
	tracer := New(&cfg, reporter)
	tracer.haveSockOpsNetnsCookie = func() error {
		t.Fatal("disabled Java remote parent unexpectedly probed sockops helpers")
		return nil
	}
	_, err := tracer.LoadSpecs()
	require.NoError(t, err)

	stop := tracer.runJavaRemoteParent(context.Background())
	stop()

	assert.Equal(t, []javaRemoteParentObservation{{
		transport: "disabled",
		operation: "select",
		status:    "disabled",
		count:     1,
	}}, reporter.observations)
}

func TestUnsupportedJavaRemoteParentKeepsTPInjectorLoadable(t *testing.T) {
	unsupported := errors.New("network namespace cookie helper unavailable")
	reporter := &javaRemoteParentRecordingReporter{}
	cfg := obi.DefaultConfig
	require.NoError(t, cfg.EBPF.ContextPropagation.UnmarshalText([]byte("tcp")))
	cfg.Java.RemoteParent.Transport = obi.JavaRemoteParentAuto
	tracer := New(&cfg, reporter)
	tracer.haveSockOpsNetnsCookie = func() error { return unsupported }

	bundles, err := tracer.LoadSpecs()
	require.NoError(t, err)
	require.NotEmpty(t, bundles)
	assert.Equal(t, false, bundles[0].Constants["java_remote_parent_enabled"])
	require.ErrorIs(t, tracer.javaRemoteParentSupportErr, unsupported)
	assert.Nil(t, tracer.javaRemoteParentMapsSpec)
	assert.Nil(t, tracer.javaRemoteParentSpec)

	stop := tracer.runJavaRemoteParent(context.Background())
	stop()
	assert.ElementsMatch(t, []javaRemoteParentObservation{
		{
			transport: "getsockopt",
			operation: "negotiate",
			status:    "unsupported",
			count:     1,
		},
		{
			transport: "unix",
			operation: "negotiate",
			status:    "unsupported",
			count:     1,
		},
	}, reporter.observations)
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
	closed bool
}

func (c *javaRemoteParentTestCloser) Close() error {
	c.closed = true
	return nil
}

func TestJavaRemoteParentPartialSockoptAttachClosesFirstLink(t *testing.T) {
	originalGet := attachCgroupGetsockopt
	originalSet := attachCgroupSetsockopt
	t.Cleanup(func() {
		attachCgroupGetsockopt = originalGet
		attachCgroupSetsockopt = originalSet
	})

	getLink := &javaRemoteParentTestCloser{}
	attachCgroupGetsockopt = func(*ebpf.Program) (io.Closer, error) {
		return getLink, nil
	}
	attachCgroupSetsockopt = func(*ebpf.Program) (io.Closer, error) {
		return nil, errors.New("setsockopt attach failed")
	}

	link, err := attachJavaRemoteParentSockopt(nil, nil)
	require.Error(t, err)
	assert.Nil(t, link)
	assert.True(t, getLink.closed)
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
		operation: "negotiate",
		status:    "transport_error",
		count:     1,
	})
	validTransitions := 0
	for _, observation := range reporter.observations {
		if observation.transport == "unix" && observation.operation == "select" &&
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
	observations []javaRemoteParentObservation
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
}
