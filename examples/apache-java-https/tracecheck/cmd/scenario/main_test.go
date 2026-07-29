// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/examples/apache-java-https/tracecheck"
)

func TestMakeRequestsUsesTheRecordedSeed(t *testing.T) {
	cfg := config{scenario: "w3c", requestCount: 2, seed: 42}

	first, err := makeRequests(cfg)
	require.NoError(t, err)
	second, err := makeRequests(cfg)
	require.NoError(t, err)

	assert.Equal(t, first, second)
	assert.NotEqual(t, first[0].Marker, first[1].Marker)
	assert.Len(t, first[0].W3CTraceID, 32)
	assert.Len(t, first[0].W3CParentSpanID, 16)
	assert.Equal(t, "01", first[0].W3CTraceFlags)
	assert.Equal(t, "conflicting-valid-w3c-and-obi", first[0].W3CCase)
	assert.False(t, first[0].InvalidW3C)
	assert.True(t, first[1].InvalidW3C)
	assert.Equal(t, "malformed-w3c-valid-obi", first[1].W3CCase)
	assert.Empty(t, first[1].W3CTraceID)
}

func TestW3COnlyRequestRecordsNoOBIControl(t *testing.T) {
	requests, err := makeRequests(config{scenario: "w3c-only", seed: 42})
	require.NoError(t, err)
	require.Len(t, requests, 1)

	assert.Equal(t, "valid-w3c-no-obi", requests[0].W3CCase)
	assert.Equal(t, "01", requests[0].W3CTraceFlags)
	assert.False(t, requests[0].InvalidW3C)
}

func TestHelperAttachFailureUsesOneRequestWithoutW3C(t *testing.T) {
	cfg := config{scenario: "helper-attach-failure", seed: 42}
	requests, err := makeRequests(cfg)
	require.NoError(t, err)
	require.Len(t, requests, 1)

	assert.Empty(t, requests[0].W3CTraceID)
	assert.Empty(t, requests[0].W3CParentSpanID)
	assert.Empty(t, requests[0].W3CTraceFlags)
	assert.Empty(t, requests[0].W3CCase)
	assert.False(t, requests[0].InvalidW3C)
	assert.Equal(t, tracecheck.ModeHelperAttachFailure, expectationFor(cfg, requests[0]).Mode)

	_, err = makeRequests(config{scenario: "helper-attach-failure", requestCount: 2, seed: 42})
	require.ErrorContains(t, err, "requires exactly one request")
}

func TestW3CMatchSendsCanonicalStandardParent(t *testing.T) {
	requests, err := makeRequests(config{scenario: "w3c-match", seed: 42})
	require.NoError(t, err)
	require.Len(t, requests, 1)

	assert.Equal(t, "matching-w3c-and-obi", requests[0].W3CCase)
	assert.Equal(t, matchingW3CTraceID, requests[0].W3CTraceID)
	assert.Equal(t, matchingW3CParentSpanID, requests[0].W3CParentSpanID)
	assert.Equal(t, matchingW3CTraceFlags, requests[0].W3CTraceFlags)
	assert.Equal(t, tracecheck.ModeW3CMatch, expectationFor(
		config{scenario: "w3c-match"},
		requests[0],
	).Mode)

	request, err := newHTTPRequest(
		context.Background(),
		config{baseURL: "https://example.test"},
		requests[0],
	)
	require.NoError(t, err)
	assert.Equal(t,
		"00-"+matchingW3CTraceID+"-"+matchingW3CParentSpanID+"-"+matchingW3CTraceFlags,
		request.Header.Get("traceparent"),
	)
}

func TestPipeliningUsesFailClosedInboundPolicy(t *testing.T) {
	expectation := expectationFor(
		config{scenario: "pipelining"},
		requestCase{Marker: "pipeline", Endpoint: "/api/echo"},
	)

	assert.Equal(t, tracecheck.ModePipelinedBridge, expectation.Mode)
	assert.Equal(t, tracecheck.ModeBridge, expectationFor(
		config{scenario: "keepalive"},
		requestCase{Marker: "keepalive", Endpoint: "/api/echo"},
	).Mode)
}

func TestConcurrencyAssertionModesRetainOneWorkload(t *testing.T) {
	for _, test := range []struct {
		name          string
		assertionMode string
		wantMode      tracecheck.AssertionMode
		wantDistinct  bool
	}{
		{name: "bridge", wantMode: tracecheck.ModeBridge, wantDistinct: true},
		{name: "disabled", assertionMode: "disabled", wantMode: tracecheck.ModeDisabled, wantDistinct: true},
		{name: "uninstrumented", assertionMode: "uninstrumented", wantMode: tracecheck.ModeUninstrumented},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := config{scenario: "concurrency", assertionMode: test.assertionMode, seed: 42}
			requests, err := makeRequests(cfg)
			require.NoError(t, err)
			require.Len(t, requests, 16)
			assert.Equal(t, test.wantMode, expectationFor(cfg, requests[0]).Mode)
			assert.Equal(t, test.wantMode, concurrencyAssertionMode(cfg))
			assert.Equal(t, test.wantDistinct, requiresDistinctParents(cfg))
		})
	}

	assert.ErrorContains(t, validateAssertionMode(config{
		scenario:      "basic",
		assertionMode: "disabled",
	}), "requires concurrency")
	assert.ErrorContains(t, validateAssertionMode(config{
		scenario:      "concurrency",
		assertionMode: "bridge",
	}), "invalid --assertion-mode")
}

func TestConcurrencyResultEncodesItsAssertionMode(t *testing.T) {
	var output bytes.Buffer
	require.NoError(t, encodeRunResult(&output, &runResult{
		Scenario:      "concurrency",
		AssertionMode: tracecheck.ModeUninstrumented,
	}))
	assert.Contains(t, output.String(), "\"assertion_mode\": \"uninstrumented\"")
}

func TestPressureUsesReasonCodedParentPolicy(t *testing.T) {
	expectation := expectationFor(
		config{scenario: "pressure"},
		requestCase{Marker: "pressure", Endpoint: "/api/handoff"},
	)

	assert.Equal(t, tracecheck.ModePressure, expectation.Mode)
}

func TestRunResultEncodingKeepsPressureCountsOnSeparateLines(t *testing.T) {
	var output bytes.Buffer
	result := &runResult{
		Status: "failed",
		PressureCorrelation: &pressureCorrelationSummary{
			ExactHitCount:     7,
			ExplicitRootCount: 2,
			WrongParentCount:  1,
		},
	}

	require.NoError(t, encodeRunResult(&output, result))
	assert.Contains(t, output.String(), "\n    \"exact_hit_count\": 7,\n")
	assert.Contains(t, output.String(), "\n    \"explicit_root_count\": 2,\n")
	assert.Contains(t, output.String(), "\n    \"wrong_parent_count\": 1,\n")
}

func TestAwaitAssertionsFetchesMarkersAfterAnEarlierFailure(t *testing.T) {
	seen := map[string]int{}
	requests := []requestCase{{Marker: "first"}, {Marker: "second"}, {Marker: "third"}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	markerErrors := map[string]error{
		"first":  errors.New("first unavailable"),
		"second": errors.New("second unavailable"),
		"third":  errors.New("third unavailable"),
	}
	fetch := func(_ context.Context, _ string, marker string) (tracecheck.Snapshot, error) {
		seen[marker]++
		if marker == requests[len(requests)-1].Marker {
			cancel()
		}
		return tracecheck.Snapshot{}, markerErrors[marker]
	}

	_, err := awaitAssertionsWithFetcher(ctx, config{}, requests, fetch)

	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, err, markerErrors["first"])
	require.ErrorIs(t, err, markerErrors["third"])
	require.ErrorContains(t, err, "first result: marker first")
	require.ErrorContains(t, err, "last result: marker third")
	for _, request := range requests {
		assert.Equal(t, 1, seen[request.Marker], "marker %s fetch count", request.Marker)
	}
}

func TestAwaitAssertionsPreservesSemanticFailureAcrossFetchDeadline(t *testing.T) {
	wrong := pressureCase("wrong", "trace-wanted", "client-wanted", "trace-foreign", "foreign")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	fetches := 0
	fetch := func(_ context.Context, _ string, _ string) (tracecheck.Snapshot, error) {
		fetches++
		if fetches == 1 {
			return wrong.Trace, nil
		}
		cancel()
		return tracecheck.Snapshot{}, ctx.Err()
	}
	cfg := config{
		scenario:      "pressure",
		apacheService: "apache-proxy",
		javaService:   "java-backend",
	}

	snapshots, err := awaitAssertionsWithFetcher(ctx, cfg, []requestCase{wrong.Request}, fetch)

	require.ErrorIs(t, err, context.Canceled)
	require.ErrorContains(t, err, "current result: marker wrong: context canceled")
	require.ErrorContains(t, err, "active semantic result: marker wrong")
	require.ErrorContains(t, err, "identify Apache client span")
	assert.Equal(t, 2, fetches)
	require.Len(t, snapshots, 1)
	assert.Equal(t, tracecheck.Snapshot{}, snapshots[0])
}

func TestAwaitAssertionsClearsResolvedMarkerWithoutReusingFailedFetch(t *testing.T) {
	exactA := pressureCase("fresh-a", "trace-a", "client-a", "trace-a", "client-a")
	wrongA := pressureCase("fresh-a", "trace-a", "client-a", "trace-foreign", "foreign")
	exactB := pressureCase("fresh-b", "trace-b", "client-b", "trace-b", "client-b")
	cfg := config{
		scenario:      "pressure",
		apacheService: "apache-proxy",
		javaService:   "java-backend",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	fetches := 0
	receiverErr := errors.New("receiver unavailable")
	fetch := func(_ context.Context, _ string, _ string) (tracecheck.Snapshot, error) {
		fetches++
		switch fetches {
		case 1:
			return wrongA.Trace, nil
		case 2:
			return exactB.Trace, nil
		case 3:
			return exactA.Trace, nil
		default:
			cancel()
			return tracecheck.Snapshot{}, receiverErr
		}
	}

	requests := []requestCase{exactA.Request, exactB.Request}
	snapshots, err := awaitAssertionsWithFetcher(ctx, cfg, requests, fetch)

	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, err, receiverErr)
	require.NotContains(t, err.Error(), "identify Apache client span")
	require.NotContains(t, err.Error(), "%!w")
	assert.Equal(t, 4, fetches)
	require.Len(t, snapshots, 2)
	assert.Equal(t, exactA.Trace, snapshots[0])
	assert.Equal(t, tracecheck.Snapshot{}, snapshots[1])
	cases := []caseResult{
		{Request: exactA.Request, Trace: snapshots[0]},
		{Request: exactB.Request, Trace: snapshots[1]},
	}
	summary := summarizePressureCorrelation(cfg, cases)
	assert.Equal(t, pressureCorrelationSummary{ExactHitCount: 1, UnresolvedCount: 1}, summary)
	assert.Equal(t, tracecheck.PressureParentExactHit, cases[0].PressureParentOutcome)
	assert.Equal(t, tracecheck.PressureParentUnresolved, cases[1].PressureParentOutcome)

	var output bytes.Buffer
	require.NoError(t, encodeRunResult(&output, &runResult{
		Status:              "failed",
		PressureCorrelation: &summary,
		Cases:               cases,
	}))
	assert.Contains(t, output.String(), "\n    \"exact_hit_count\": 1,\n")
	assert.Contains(t, output.String(), "\n    \"unresolved_count\": 1\n")
	assert.Contains(t, output.String(), "\"pressure_parent_outcome\": \"unresolved\"")
	var decoded runResult
	require.NoError(t, json.Unmarshal(output.Bytes(), &decoded))
	require.NotNil(t, decoded.PressureCorrelation)
	assert.Equal(t, 1, decoded.PressureCorrelation.ExactHitCount)
	assert.Equal(t, 1, decoded.PressureCorrelation.UnresolvedCount)
	require.Len(t, decoded.Cases, 2)
	assert.Equal(t, tracecheck.PressureParentExactHit, decoded.Cases[0].PressureParentOutcome)
	assert.Equal(t, tracecheck.PressureParentUnresolved, decoded.Cases[1].PressureParentOutcome)
}

func TestAwaitAssertionsRejectsSnapshotFetchedAfterCancellation(t *testing.T) {
	exact := pressureCase("canceled", "trace-exact", "client-exact", "trace-exact", "client-exact")
	cfg := config{
		scenario:      "pressure",
		apacheService: "apache-proxy",
		javaService:   "java-backend",
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fetches := 0
	fetch := func(_ context.Context, _ string, _ string) (tracecheck.Snapshot, error) {
		fetches++
		cancel()
		return exact.Trace, nil
	}

	snapshots, err := awaitAssertionsWithFetcher(ctx, cfg, []requestCase{exact.Request}, fetch)

	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, fetches)
	require.Len(t, snapshots, 1)
	assert.Equal(t, tracecheck.Snapshot{}, snapshots[0])
}

func TestSnapshotsForAssertionDeadlineUsesAttemptedPassOnly(t *testing.T) {
	completed := []tracecheck.Snapshot{{Marker: "completed"}}
	current := []tracecheck.Snapshot{{Marker: "current"}}

	assert.Equal(t, completed, snapshotsForAssertionDeadline(completed, current, false))
	assert.Equal(t, current, snapshotsForAssertionDeadline(completed, current, true))
}

func TestTraceAssertionDeadlineErrorPreservesEqualMessageCauses(t *testing.T) {
	currentCause := errors.New("same message")
	semanticCause := errors.New("same message")
	currentErr := fmt.Errorf("marker: %w", currentCause)
	semanticErr := fmt.Errorf("marker: %w", semanticCause)

	err := traceAssertionDeadlineError(context.Canceled, currentErr, semanticErr)

	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, err, currentCause)
	require.ErrorIs(t, err, semanticCause)
	require.ErrorContains(t, err, "current result")
	require.ErrorContains(t, err, "active semantic result")
}

func TestAwaitAssertionsDoesNotFetchWithCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fetches := 0
	fetch := func(_ context.Context, _ string, _ string) (tracecheck.Snapshot, error) {
		fetches++
		return tracecheck.Snapshot{}, nil
	}

	_, err := awaitAssertionsWithFetcher(ctx, config{}, []requestCase{{Marker: "canceled"}}, fetch)

	require.ErrorIs(t, err, context.Canceled)
	require.NotContains(t, err.Error(), "current result")
	require.NotContains(t, err.Error(), "active semantic result")
	require.NotContains(t, err.Error(), "%!w")
	assert.Zero(t, fetches)
}

func TestOBIFlagsRequestsCoverSampledAndUnsampledParents(t *testing.T) {
	requests, err := makeRequests(config{scenario: "obi-flags", seed: 42})
	require.NoError(t, err)
	require.Len(t, requests, 2)

	assert.Equal(t, "/api/obi-flags", requests[0].Endpoint)
	assert.Equal(t, "00", requests[0].W3CTraceFlags)
	assert.Equal(t, "obi-only-00", requests[0].W3CCase)
	assert.Equal(t, "01", requests[1].W3CTraceFlags)
	assert.Equal(t, "obi-only-01", requests[1].W3CCase)
	assert.Equal(t, "01", expectationFor(config{scenario: "obi-flags"}, requests[0]).JavaTraceFlags)
}

func TestW3CFaultModeIsRequiredAndScenarioScoped(t *testing.T) {
	require.ErrorContains(t, validateFaultMode(config{scenario: "w3c-fault"}), "requires --fault-mode")
	require.ErrorContains(t, validateFaultMode(
		config{scenario: "w3c-fault", faultMode: "matching"},
	), "invalid --fault-mode")
	require.ErrorContains(t, validateFaultMode(
		config{scenario: "basic", faultMode: "timeout"},
	), "--fault-mode requires w3c-fault")
	require.NoError(t, validateFaultMode(config{scenario: "basic"}))

	for _, faultMode := range []string{
		"alternating",
		"timeout",
		"disconnect",
		"overload",
		"truncated",
		"bad-magic",
		"bad-size",
		"version-mismatch",
		"zero-trace-id",
		"zero-span-id",
	} {
		assert.NoError(t, validateFaultMode(
			config{scenario: "w3c-fault", faultMode: faultMode},
		), faultMode)
	}
}

func TestW3CFaultRequestsDescribeInjectedAndNormalizedOutcomes(t *testing.T) {
	tests := []struct {
		faultMode string
		statuses  []string
	}{
		{faultMode: "alternating", statuses: []string{"stale", "malformed"}},
		{faultMode: "timeout", statuses: []string{"timeout", "timeout"}},
		{faultMode: "disconnect", statuses: []string{"transport_error", "transport_error"}},
		{faultMode: "overload", statuses: []string{"overload", "overload"}},
		{faultMode: "truncated", statuses: []string{"transport_error", "transport_error"}},
		{faultMode: "bad-magic", statuses: []string{"malformed", "malformed"}},
		{faultMode: "bad-size", statuses: []string{"malformed", "malformed"}},
		{faultMode: "version-mismatch", statuses: []string{"version_mismatch", "version_mismatch"}},
		{faultMode: "zero-trace-id", statuses: []string{"malformed", "malformed"}},
		{faultMode: "zero-span-id", statuses: []string{"malformed", "malformed"}},
	}

	for _, test := range tests {
		t.Run(test.faultMode, func(t *testing.T) {
			cfg := config{scenario: "w3c-fault", faultMode: test.faultMode, seed: 42}
			requests, err := makeRequests(cfg)
			require.NoError(t, err)
			require.Len(t, requests, 2)

			for index, requestCase := range requests {
				assert.Equal(t, test.faultMode, requestCase.InjectedFaultMode)
				assert.Equal(t, test.statuses[index], requestCase.ExpectedJavaStatus)
				assert.Equal(
					t,
					"valid-w3c-injected-"+test.faultMode+"-java-"+test.statuses[index],
					requestCase.W3CCase,
				)
				assert.Equal(t, "01", requestCase.W3CTraceFlags)
				assert.Equal(t, tracecheck.ModeW3CNoOBI, expectationFor(cfg, requestCase).Mode)
				assert.Equal(t, index == len(requests)-1, requestCase.BridgeDiagnostics)

				request, requestErr := newHTTPRequest(
					context.Background(),
					config{baseURL: "https://example.test", scenario: "w3c-fault"},
					requestCase,
				)
				require.NoError(t, requestErr)
				expectedOptIn := ""
				if index == len(requests)-1 {
					expectedOptIn = "1"
				}
				assert.Equal(t, expectedOptIn, request.URL.Query().Get("bridge_diagnostics"))
			}
		})
	}
}

func TestPrimaryW3CStaleRequestUsesTheStandardParent(t *testing.T) {
	cfg := config{scenario: "primary-w3c-stale", seed: 42}
	requests, err := makeRequests(cfg)
	require.NoError(t, err)
	require.Len(t, requests, 1)

	requestCase := requests[0]
	assert.Equal(t, "stale", requestCase.ExpectedJavaStatus)
	assert.Equal(t, "valid-w3c-primary-stale", requestCase.W3CCase)
	assert.Equal(t, "01", requestCase.W3CTraceFlags)
	assert.True(t, requestCase.CloseConnection)
	assert.Equal(t, tracecheck.ModeW3C, expectationFor(cfg, requestCase).Mode)
	assert.NotEmpty(t, requestCase.W3CTraceID)
	assert.NotEmpty(t, requestCase.W3CParentSpanID)

	request, err := newHTTPRequest(
		context.Background(),
		config{baseURL: "https://example.test", scenario: "primary-w3c-stale"},
		requestCase,
	)
	require.NoError(t, err)
	assert.Empty(t, request.URL.Query().Get("bridge_diagnostics"))

	_, err = makeRequests(config{scenario: "primary-w3c-stale", requestCount: 2, seed: 42})
	require.ErrorContains(t, err, "requires exactly one request")
}

func TestPrimaryW3CFaultRequestUsesW3CPrecedenceAndDiagnostics(t *testing.T) {
	baseline := javaDiagnosticsSnapshot(t, 0)
	tests := []struct {
		faultMode string
		status    string
	}{
		{faultMode: "version-mismatch", status: "version_mismatch"},
		{faultMode: "zero-trace-id", status: "malformed"},
		{faultMode: "zero-span-id", status: "malformed"},
	}

	for _, test := range tests {
		t.Run(test.faultMode, func(t *testing.T) {
			cfg := config{
				scenario:              "primary-w3c-fault",
				faultMode:             test.faultMode,
				javaDiagnosticsBefore: baseline,
				seed:                  42,
			}
			requests, err := makeRequests(cfg)
			require.NoError(t, err)
			require.Len(t, requests, 1)

			requestCase := requests[0]
			assert.Equal(t, test.faultMode, requestCase.InjectedFaultMode)
			assert.Equal(t, test.status, requestCase.ExpectedJavaStatus)
			assert.Equal(
				t,
				"valid-w3c-primary-injected-"+test.faultMode+"-java-"+test.status,
				requestCase.W3CCase,
			)
			assert.Equal(t, "01", requestCase.W3CTraceFlags)
			assert.NotEmpty(t, requestCase.W3CTraceID)
			assert.NotEmpty(t, requestCase.W3CParentSpanID)
			assert.True(t, requestCase.BridgeDiagnostics)
			assert.True(t, requestCase.CloseConnection)
			assert.Equal(t, tracecheck.ModeW3C, expectationFor(cfg, requestCase).Mode)

			request, requestErr := newHTTPRequest(
				context.Background(),
				config{baseURL: "https://example.test", scenario: cfg.scenario},
				requestCase,
			)
			require.NoError(t, requestErr)
			assert.Equal(t, "1", request.URL.Query().Get("bridge_diagnostics"))
			assert.Equal(t, "1", request.URL.Query().Get("close"))

			requestCase.BridgeDiagnostics = false
			request, requestErr = newHTTPRequest(
				context.Background(),
				config{baseURL: "https://example.test", scenario: cfg.scenario},
				requestCase,
			)
			require.NoError(t, requestErr)
			assert.Empty(t, request.URL.Query().Get("bridge_diagnostics"))
		})
	}

	for _, faultMode := range []string{"", "alternating", "timeout", "bad-magic"} {
		require.Error(t, validateFaultMode(config{
			scenario:  "primary-w3c-fault",
			faultMode: faultMode,
		}), faultMode)
	}
	require.ErrorContains(t, validateJavaDiagnosticsBefore(config{
		scenario: "primary-w3c-fault",
	}), "requires --java-diagnostics-before")
	require.ErrorContains(t, validateJavaDiagnosticsBefore(config{
		scenario:              "basic",
		javaDiagnosticsBefore: baseline,
	}), "requires primary-w3c-fault")

	_, err := makeRequests(config{
		scenario:              "primary-w3c-fault",
		faultMode:             "zero-trace-id",
		javaDiagnosticsBefore: baseline,
		requestCount:          2,
		seed:                  42,
	})
	require.ErrorContains(t, err, "requires exactly one request")
}

func TestPrimaryFaultDiagnosticsRequireOneExpectedStatus(t *testing.T) {
	baseline := javaDiagnosticsSnapshot(t, 0)
	for _, test := range []struct {
		status string
	}{
		{status: "version_mismatch"},
		{status: "malformed"},
	} {
		t.Run(test.status, func(t *testing.T) {
			after := javaDiagnosticsSnapshotWithCounters(t, map[string]uint64{
				"t_" + test.status: 1,
			})
			require.NoError(t, assertPrimaryFaultDiagnostics(baseline, after, test.status))
			require.ErrorContains(
				t,
				assertPrimaryFaultDiagnostics(baseline, baseline, test.status),
				"expected one primary Java",
			)
		})
	}

	before := javaDiagnosticsSnapshotWithCounters(t, map[string]uint64{
		"t_malformed": 1,
	})
	require.ErrorContains(
		t,
		assertPrimaryFaultDiagnostics(before, javaDiagnosticsSnapshot(t, 0), "malformed"),
		"decreased",
	)
}

func TestBridgeDiagnosticsHeaderIsRequiredOnlyForOptedInRequest(t *testing.T) {
	snapshot := javaDiagnosticsSnapshot(t, 0)
	header := make(http.Header)

	diagnostics, err := javaDiagnosticsFromHeader(header, false)
	require.NoError(t, err)
	assert.Empty(t, diagnostics)
	_, err = javaDiagnosticsFromHeader(header, true)
	require.ErrorContains(t, err, "expected exactly one")

	header.Add(bridgeDiagnosticsHeader, snapshot)
	diagnostics, err = javaDiagnosticsFromHeader(header, true)
	require.NoError(t, err)
	assert.Equal(t, snapshot, diagnostics)
	_, err = javaDiagnosticsFromHeader(header, false)
	require.ErrorContains(t, err, "unexpected")

	header.Add(bridgeDiagnosticsHeader, snapshot)
	_, err = javaDiagnosticsFromHeader(header, true)
	require.ErrorContains(t, err, "expected exactly one")
}

func TestJavaDiagnosticsSnapshotValidationIsExactAndBounded(t *testing.T) {
	require.Len(t, javaDiagnosticsFieldNames, 50)
	valid := javaDiagnosticsSnapshot(t, maxJavaDiagnosticsCounter-1)
	sanitized, err := sanitizeJavaDiagnostics(valid)
	require.NoError(t, err)
	assert.Equal(t, valid, sanitized)
	assert.LessOrEqual(t, len(valid), maxJavaDiagnosticsSnapshotLength)

	fields := strings.Split(javaDiagnosticsSnapshot(t, 0), ",")
	duplicate := append([]string(nil), fields...)
	duplicate[1] = duplicate[0]
	reordered := append([]string(nil), fields...)
	reordered[0], reordered[1] = reordered[1], reordered[0]
	uppercase := append([]string(nil), fields...)
	uppercase[0] = javaDiagnosticsFieldNames[0] + "=A"
	leadingZero := append([]string(nil), fields...)
	leadingZero[0] = javaDiagnosticsFieldNames[0] + "=00"
	saturated := append([]string(nil), fields...)
	saturated[0] = javaDiagnosticsFieldNames[0] + "=" +
		strconv.FormatUint(maxJavaDiagnosticsCounter, 36)

	tests := []struct {
		name     string
		snapshot string
		want     string
	}{
		{name: "unavailable", snapshot: "unavailable", want: "unavailable"},
		{name: "newline", snapshot: strings.Join(fields, ",") + "\n", want: "newline"},
		{name: "carriage return", snapshot: strings.Join(fields, ",") + "\r", want: "newline"},
		{name: "missing", snapshot: strings.Join(fields[:len(fields)-1], ","), want: "expected 50 fields"},
		{name: "extra", snapshot: strings.Join(append(fields, "extra=0"), ","), want: "expected 50 fields"},
		{name: "duplicate", snapshot: strings.Join(duplicate, ","), want: "duplicated"},
		{name: "reordered", snapshot: strings.Join(reordered, ","), want: "expected"},
		{name: "uppercase", snapshot: strings.Join(uppercase, ","), want: "invalid base36"},
		{name: "leading zero", snapshot: strings.Join(leadingZero, ","), want: "invalid base36"},
		{name: "saturated", snapshot: strings.Join(saturated, ","), want: "saturation ceiling"},
		{
			name:     "oversized",
			snapshot: strings.Repeat("x", maxJavaDiagnosticsSnapshotLength+1),
			want:     "exceed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, validationErr := sanitizeJavaDiagnostics(test.snapshot)
			require.ErrorContains(t, validationErr, test.want)
		})
	}
}

func TestFaultDiagnosticsAreExposedOnlyAtTheTopLevel(t *testing.T) {
	snapshot := javaDiagnosticsSnapshot(t, 0)
	for _, scenario := range []string{"w3c-fault", "primary-w3c-fault"} {
		t.Run(scenario, func(t *testing.T) {
			var output bytes.Buffer
			require.NoError(t, encodeRunResult(&output, &runResult{
				Status:                "passed",
				Scenario:              scenario,
				FaultDiagnosticsAfter: snapshot,
				Cases: []caseResult{{
					Request: requestCase{
						Marker:            "fault",
						BridgeDiagnostics: true,
					},
					Response: backendResponse{BridgeDiagnostics: snapshot},
				}},
			}))

			assert.Contains(t, output.String(), `"fault_diagnostics_after": "`+snapshot+`"`)
			assert.Equal(t, 1, strings.Count(output.String(), snapshot))
			assert.NotContains(t, output.String(), `"bridge_diagnostics"`)
		})
	}
}

func TestNonFaultRequestCannotOptInToBridgeDiagnostics(t *testing.T) {
	request, err := newHTTPRequest(
		context.Background(),
		config{baseURL: "https://example.test", scenario: "basic"},
		requestCase{
			Marker:            "basic",
			Endpoint:          "/api/echo",
			BridgeDiagnostics: true,
		},
	)
	require.NoError(t, err)
	assert.Empty(t, request.URL.Query().Get("bridge_diagnostics"))
}

func TestRestartFaultRequestsUseStandardParents(t *testing.T) {
	requests, err := makeRequests(config{scenario: "restart-fault", seed: 42})
	require.NoError(t, err)
	require.Len(t, requests, 32)

	for index, request := range requests {
		assert.NotEmpty(t, request.W3CTraceID)
		assert.NotEmpty(t, request.W3CParentSpanID)
		assert.Equal(t, 75, request.DelayMillis)
		switch {
		case index < restartBeforeStopRequests:
			assert.Equal(t, restartPhaseBeforeStop, request.RestartPhase)
		case index < restartAfterStartRequestIndex:
			assert.Equal(t, restartPhaseWhileStopped, request.RestartPhase)
		default:
			assert.Equal(t, restartPhaseAfterRestart, request.RestartPhase)
		}
		assert.Equal(t, tracecheck.ModeW3CResilience, expectationFor(
			config{scenario: "restart-fault"},
			request,
		).Mode)
	}
}

func javaDiagnosticsSnapshot(t *testing.T, value uint64) string {
	counters := make(map[string]uint64, len(javaDiagnosticsFieldNames))
	for _, name := range javaDiagnosticsFieldNames {
		counters[name] = value
	}
	return javaDiagnosticsSnapshotWithCounters(t, counters)
}

func javaDiagnosticsSnapshotWithCounters(t *testing.T, counters map[string]uint64) string {
	t.Helper()
	fields := make([]string, len(javaDiagnosticsFieldNames))
	for index, name := range javaDiagnosticsFieldNames {
		fields[index] = name + "=" + strconv.FormatUint(counters[name], 36)
	}
	return strings.Join(fields, ",")
}

func TestRestartFaultRequiresTrafficAfterRestart(t *testing.T) {
	_, err := makeRequests(config{
		scenario:     "restart-fault",
		requestCount: restartAfterStartRequestIndex,
		seed:         42,
	})

	require.ErrorContains(t, err, "requires at least")
}

func TestStressScenarioRequestsHaveBoundedShapes(t *testing.T) {
	tests := []struct {
		scenario string
		count    int
		check    func(*testing.T, requestCase)
	}{
		{
			scenario: "keepalive",
			count:    10,
			check: func(t *testing.T, request requestCase) {
				assert.False(t, request.CloseConnection)
			},
		},
		{
			scenario: "connection-churn",
			count:    32,
			check: func(t *testing.T, request requestCase) {
				assert.True(t, request.CloseConnection)
			},
		},
		{
			scenario: "pipelining",
			count:    10,
			check: func(t *testing.T, request requestCase) {
				assert.False(t, request.CloseConnection)
			},
		},
		{
			scenario: "fd-port-reuse",
			count:    32,
			check: func(t *testing.T, request requestCase) {
				assert.True(t, request.CloseConnection)
				assert.True(t, request.ObserveSocket)
			},
		},
		{
			scenario: "slow-body",
			count:    8,
			check: func(t *testing.T, request requestCase) {
				assert.Equal(t, 64<<10, request.SlowBodyBytes)
			},
		},
		{
			scenario: "tls-boundary",
			count:    2,
			check: func(t *testing.T, request requestCase) {
				assert.Equal(t, "/api/tls-boundary", request.Endpoint)
				assert.Equal(t, "split", request.TLSBoundaryMode)
			},
		},
		{
			scenario: "pressure",
			count:    128,
			check: func(t *testing.T, request requestCase) {
				assert.Equal(t, "/api/handoff", request.Endpoint)
				assert.Equal(t, "none", request.HandoffFault)
			},
		},
		{
			scenario: "handoff",
			count:    4,
			check: func(t *testing.T, request requestCase) {
				assert.Equal(t, "/api/handoff", request.Endpoint)
				assert.Equal(t, 1, request.HandoffHops)
				assert.Equal(t, "none", request.HandoffFault)
			},
		},
		{
			scenario: "virtual-thread",
			count:    4,
			check: func(t *testing.T, request requestCase) {
				assert.Equal(t, "/api/virtual", request.Endpoint)
				assert.False(t, request.VirtualMixed)
				assert.False(t, request.VirtualCancel)
			},
		},
		{
			scenario: "netty",
			count:    4,
			check: func(t *testing.T, request requestCase) {
				assert.Equal(t, "/api/netty", request.Endpoint)
				assert.False(t, request.NettyCancel)
			},
		},
		{
			scenario: "netty-server",
			count:    4,
			check: func(t *testing.T, request requestCase) {
				assert.Equal(t, "/api/netty-server", request.Endpoint)
				assert.True(t, request.CloseConnection)
			},
		},
		{
			scenario: "dispatch",
			count:    4,
			check: func(t *testing.T, request requestCase) {
				assert.Equal(t, "/api/dispatch", request.Endpoint)
				assert.Equal(t, 1, request.DispatchRounds)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			requests, err := makeRequests(config{scenario: test.scenario, seed: 1})
			require.NoError(t, err)
			require.Len(t, requests, test.count)
			test.check(t, requests[0])
		})
	}
}

func TestIdentityReuseScenariosRequireMultipleRequests(t *testing.T) {
	_, err := makeRequests(config{scenario: "keepalive", requestCount: 2, seed: 1})
	require.Error(t, err)

	_, err = makeRequests(config{scenario: "pipelining", requestCount: 2, seed: 1})
	require.Error(t, err)

	_, err = makeRequests(config{scenario: "fd-port-reuse", requestCount: 1, seed: 1})
	require.Error(t, err)

	_, err = makeRequests(config{scenario: "slow-body", requestCount: 1, seed: 1})
	require.Error(t, err)

	_, err = makeRequests(config{scenario: "tls-boundary", requestCount: 1, seed: 1})
	require.Error(t, err)
}

func TestValidateTLSReadShapeRequiresSplitDecryptedReads(t *testing.T) {
	requests := []requestCase{{SlowBodyBytes: 64 << 10}, {SlowBodyBytes: 64 << 10}}
	responses := []backendResponse{
		{TLSReadEvents: 10, TLSReadBytes: 100_000},
		{TLSReadEvents: 14, TLSReadBytes: 170_000},
	}

	require.NoError(t, validateTLSReadShape("slow-body", requests, responses))
	require.NoError(t, validateTLSReadShape("basic", requests, nil))

	insufficientEvents := append([]backendResponse(nil), responses...)
	insufficientEvents[1].TLSReadEvents = 11
	require.Error(t, validateTLSReadShape("slow-body", requests, insufficientEvents))

	insufficientBytes := append([]backendResponse(nil), responses...)
	insufficientBytes[1].TLSReadBytes = 150_000
	require.Error(t, validateTLSReadShape("slow-body", requests, insufficientBytes))

	unavailable := append([]backendResponse(nil), responses...)
	unavailable[0].TLSReadEvents = -1
	require.Error(t, validateTLSReadShape("slow-body", requests, unavailable))
}

func TestRequestsCloseBackendConnectionsAfterEvidence(t *testing.T) {
	for _, scenario := range []string{"basic", "keepalive", "pipelining"} {
		requests, err := makeRequests(config{scenario: scenario, seed: 1})
		require.NoError(t, err)
		for i := range requests {
			terminal := i == len(requests)-1
			expectedCloseQuery := ""
			if terminal {
				expectedCloseQuery = "1"
			}
			assert.Equal(t, terminal, requests[i].CloseConnection, scenario)

			request, err := newHTTPRequest(
				context.Background(),
				config{baseURL: "https://example.test"},
				requests[i],
			)
			require.NoError(t, err)
			assert.Equal(t, terminal, request.Close, scenario)
			assert.Equal(t, expectedCloseQuery, request.URL.Query().Get("close"), scenario)
		}
	}

	for _, scenario := range []string{"concurrency", "pressure", "handoff", "virtual-thread", "netty", "netty-server", "dispatch"} {
		requests, err := makeRequests(config{scenario: scenario, seed: 1})
		require.NoError(t, err)
		for _, request := range requests {
			assert.True(t, request.CloseConnection, scenario)
		}
	}
}

func TestPacedReaderEmitsExactlyTheConfiguredBody(t *testing.T) {
	reader := &pacedReader{remaining: 129, chunkSize: 64}
	body, err := io.ReadAll(reader)

	require.NoError(t, err)
	assert.Len(t, body, 129)
	assert.Zero(t, reader.remaining)
}

func TestTimeoutCancellationReachesDelayedEchoEndpoint(t *testing.T) {
	type observedRequest struct {
		path   string
		delay  string
		marker string
	}

	observed := make(chan observedRequest, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/echo", func(_ http.ResponseWriter, request *http.Request) {
		observed <- observedRequest{
			path:   request.URL.Path,
			delay:  request.URL.Query().Get("delay_ms"),
			marker: request.Header.Get(tracecheck.MarkerHeader),
		}
		<-request.Context().Done()
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	fault, err := exerciseTimeoutCancellation(context.Background(), config{
		baseURL: server.URL,
		seed:    42,
	})

	require.NoError(t, err)
	assert.Equal(t, "client-timeout", fault.Kind)
	assert.Equal(t, "deadline-exceeded-as-expected", fault.Outcome)
	assert.Positive(t, fault.ElapsedNanos)
	var request observedRequest
	select {
	case request = <-observed:
	case <-time.After(time.Second):
		require.FailNow(t, "delayed echo endpoint did not observe the cancellation control")
	}
	assert.Equal(t, observedRequest{
		path:   "/api/echo",
		delay:  "500",
		marker: "timeout-retry-cancelled-42",
	}, request)
}

func TestTimeoutCancellationRejectsImmediateHTTPFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.NotFound(response, request)
	}))
	defer server.Close()

	fault, err := exerciseTimeoutCancellation(context.Background(), config{
		baseURL: server.URL,
		seed:    42,
	})

	require.ErrorContains(t, err, "cancellation control failed for the wrong reason")
	require.ErrorContains(t, err, "unexpected HTTP status 404")
	assert.Equal(t, "failed", fault.Outcome)
}

func TestNettyRequestsCoverCancelledAndUncancelledWork(t *testing.T) {
	requests, err := makeRequests(config{scenario: "netty", seed: 1})
	require.NoError(t, err)

	assert.False(t, requests[0].NettyCancel)
	assert.True(t, requests[1].NettyCancel)
}

func TestNettyServerResponseRequiresInboundNettyProof(t *testing.T) {
	request := requestCase{Endpoint: "/api/netty-server"}
	response := backendResponse{BackendKind: "netty"}

	require.NoError(t, validateWorkloadResponse(request, response))
	response.BackendKind = "jetty"
	assert.Error(t, validateWorkloadResponse(request, response))
}

func TestDispatchRequestsCoverRepeatedServletInvocations(t *testing.T) {
	requests, err := makeRequests(config{scenario: "dispatch", seed: 1})
	require.NoError(t, err)

	assert.Equal(t, 1, requests[0].DispatchRounds)
	assert.Equal(t, 4, requests[3].DispatchRounds)
}

func TestValidateDispatchResponseRequiresInvocationProof(t *testing.T) {
	request := requestCase{Endpoint: "/api/dispatch", DispatchRounds: 3}
	response := backendResponse{
		Workload:            "servlet-async-redispatch",
		DispatchRounds:      "3",
		DispatchInvocations: "4",
	}

	require.NoError(t, validateWorkloadResponse(request, response))
	response.DispatchInvocations = "3"
	assert.Error(t, validateWorkloadResponse(request, response))
}

func TestTLSBoundaryRequestsAndEvidenceCoverBothDeterministicModes(t *testing.T) {
	requests, err := makeRequests(config{scenario: "tls-boundary", seed: 42})
	require.NoError(t, err)
	require.Len(t, requests, 2)
	assert.Equal(t, "split", requests[0].TLSBoundaryMode)
	assert.Equal(t, "coalesced", requests[1].TLSBoundaryMode)

	for _, request := range requests {
		httpRequest, requestErr := newHTTPRequest(
			context.Background(),
			config{baseURL: "http://127.0.0.1:18080"},
			request,
		)
		require.NoError(t, requestErr)
		assert.Equal(t, request.TLSBoundaryMode, httpRequest.URL.Query().Get("mode"))
	}

	split := backendResponse{TLSBoundary: &tlsBoundaryEvidence{
		Mode:                             "split",
		Passed:                           true,
		ShapeExact:                       true,
		ExpectedPlaintextCallbackLengths: []int{3, 5},
		ActualPlaintextCallbackLengths:   []int{3, 5},
		RequestOrder:                     []int{1},
		ResponseOrder:                    []int{1},
		BuffersForwardedUnchanged:        true,
		HandoffBeforeParse:               true,
		ConnectionClosed:                 true,
	}}
	require.NoError(t, validateTLSBoundaryResponse(requests[0], split))

	coalesced := backendResponse{TLSBoundary: &tlsBoundaryEvidence{
		Mode:                             "coalesced",
		Passed:                           true,
		ShapeExact:                       true,
		ExpectedPlaintextCallbackLengths: []int{8},
		ActualPlaintextCallbackLengths:   []int{8},
		RequestOrder:                     []int{1, 2},
		ResponseOrder:                    []int{1, 2},
		BuffersForwardedUnchanged:        true,
		HandoffBeforeParse:               true,
		ConnectionClosed:                 true,
	}}
	require.NoError(t, validateTLSBoundaryResponse(requests[1], coalesced))
	coalesced.TLSBoundary.ActualPlaintextCallbackLengths = []int{4, 4}
	assert.Error(t, validateTLSBoundaryResponse(requests[1], coalesced))
}

func TestSummarizeLatenciesUsesNearestRank(t *testing.T) {
	summary := summarizeLatencies([]int64{100, 10, 50, 20, 90})

	assert.EqualValues(t, 50, summary.P50Nanos)
	assert.EqualValues(t, 100, summary.P95Nanos)
	assert.EqualValues(t, 100, summary.P99Nanos)
}

func TestWritePipelinedRequestsWritesEveryRequestBeforeResponses(t *testing.T) {
	cfg := config{
		baseURL:  "http://127.0.0.1:18080",
		scenario: "pipelining",
		seed:     42,
	}
	requests, err := makeRequests(cfg)
	require.NoError(t, err)

	var wire bytes.Buffer
	written, err := writePipelinedRequests(
		context.Background(),
		bufio.NewWriter(&wire),
		cfg,
		requests,
	)
	require.NoError(t, err)
	require.Len(t, written, len(requests))

	reader := bufio.NewReader(&wire)
	for i := range requests {
		request, readErr := http.ReadRequest(reader)
		require.NoError(t, readErr)
		assert.Equal(t, "HTTP/1.1", request.Proto)
		assert.Equal(t, requests[i].Marker, request.Header.Get(tracecheck.MarkerHeader))
		assert.Equal(t, i == len(requests)-1, request.Close)
		assert.Equal(t, i == len(requests)-1, request.URL.Query().Get("close") == "1")
	}
	assert.Zero(t, reader.Buffered())
}

func TestFDPortReuseEvidenceRequiresBothReusedIdentities(t *testing.T) {
	responses := []backendResponse{
		{BackendConnectionID: 1, BackendRemotePort: 41000, BackendSocketFD: 12},
		{BackendConnectionID: 2, BackendRemotePort: 41001, BackendSocketFD: 12},
		{BackendConnectionID: 3, BackendRemotePort: 41002, BackendSocketFD: 13},
	}
	observations := []socketObservation{
		{FileDescriptor: 7, LocalPort: 39000},
		{FileDescriptor: 7, LocalPort: 39000},
		{FileDescriptor: 8, LocalPort: 39000},
	}
	evidence := buildReuseEvidence(responses, observations)

	require.NoError(t, validateConnectionShape("fd-port-reuse", responses, evidence))
	assert.Equal(t, 39000, evidence.ReusedFrontendLocalPort)
	assert.Equal(t, 7, evidence.ReusedFrontendFileDescriptor)
	assert.Equal(t, 12, evidence.ReusedBackendFileDescriptor)
	assert.Equal(t, 3, evidence.DistinctBackendConnectionIDs)
	assert.Equal(t, 3, evidence.DistinctBackendRemotePorts)

	observations[2].LocalPort = 39001
	require.Error(t, validateConnectionShape(
		"fd-port-reuse",
		responses,
		buildReuseEvidence(responses, observations),
	))

	observations[2].LocalPort = 39000
	for i := range responses {
		responses[i].BackendSocketFD = 10 + i
	}
	require.Error(t, validateConnectionShape(
		"fd-port-reuse",
		responses,
		buildReuseEvidence(responses, observations),
	))
}

func TestConnectionShapeUsesStableBackendIdentifiers(t *testing.T) {
	const keepaliveCount = 10
	identity := backendResponse{
		BackendConnectionID: 1,
		BackendRemotePort:   41000,
		TLSProtocol:         "TLSv1.3",
		TLSCipher:           "TLS_AES_256_GCM_SHA384",
	}
	keepalive := make([]backendResponse, keepaliveCount)
	for index := range keepalive {
		keepalive[index] = identity
	}
	require.NoError(t, validateConnectionShape("keepalive", keepalive, nil))
	require.NoError(t, validateConnectionShape("keepalive", keepalive[:3], nil))
	require.Error(t, validateConnectionShape("keepalive", keepalive[:2], nil))

	tests := []struct {
		name   string
		mutate func([]backendResponse)
	}{
		{name: "connection ID", mutate: func(responses []backendResponse) {
			responses[4].BackendConnectionID++
		}},
		{name: "terminal remote port", mutate: func(responses []backendResponse) {
			responses[len(responses)-1].BackendRemotePort++
		}},
		{name: "terminal TLS protocol", mutate: func(responses []backendResponse) {
			responses[len(responses)-1].TLSProtocol = "TLSv1.2"
		}},
		{name: "terminal TLS cipher", mutate: func(responses []backendResponse) {
			responses[len(responses)-1].TLSCipher = "different"
		}},
		{name: "terminal connection", mutate: func(responses []backendResponse) {
			responses[len(responses)-1].BackendConnectionID++
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			broken := append([]backendResponse(nil), keepalive...)
			test.mutate(broken)
			require.Error(t, validateConnectionShape("keepalive", broken, nil))
		})
	}

	churn := []backendResponse{
		{BackendConnectionID: 1, BackendRemotePort: 41000},
		{BackendConnectionID: 2, BackendRemotePort: 41000},
	}
	require.NoError(t, validateConnectionShape("connection-churn", churn, nil))
	require.NoError(t, validateConnectionShape("concurrency", churn, nil))

	churn[1].BackendConnectionID = 1
	require.Error(t, validateConnectionShape("connection-churn", churn, nil))
}

func TestReuseAndPipelineScenariosRejectSharedParents(t *testing.T) {
	cases := []caseResult{
		{
			Request: requestCase{Marker: "one"},
			Trace: tracecheck.Snapshot{Spans: []tracecheck.Span{{
				ServiceName:  "java-backend",
				Kind:         "SERVER",
				TraceID:      "trace",
				ParentSpanID: "parent",
			}}},
		},
		{
			Request: requestCase{Marker: "two"},
			Trace: tracecheck.Snapshot{Spans: []tracecheck.Span{{
				ServiceName:  "java-backend",
				Kind:         "SERVER",
				TraceID:      "trace",
				ParentSpanID: "parent",
			}}},
		},
	}

	require.Error(t, validateDistinctParents("pipelining", "java-backend", cases))
	require.Error(t, validateDistinctParents("fd-port-reuse", "java-backend", cases))
	require.Error(t, validateDistinctParents("keepalive", "java-backend", cases))

	unique := make([]caseResult, 10)
	for index := range unique {
		unique[index] = caseResult{
			Request: requestCase{Marker: fmt.Sprintf("keepalive-%02d", index)},
			Trace: tracecheck.Snapshot{Spans: []tracecheck.Span{{
				ServiceName:  "java-backend",
				Kind:         "SERVER",
				TraceID:      fmt.Sprintf("trace-%02d", index),
				ParentSpanID: fmt.Sprintf("parent-%02d", index),
			}}},
		}
	}
	require.NoError(t, validateDistinctParents("keepalive", "java-backend", unique))

	unique[len(unique)-1].Trace.Spans[0].TraceID = unique[0].Trace.Spans[0].TraceID
	unique[len(unique)-1].Trace.Spans[0].ParentSpanID = unique[0].Trace.Spans[0].ParentSpanID
	require.Error(t, validateDistinctParents("keepalive", "java-backend", unique))
}

func TestPressureCorrelationCountsExactMissingWrongAndUnresolved(t *testing.T) {
	cfg := config{
		scenario:      "pressure",
		apacheService: "apache-proxy",
		javaService:   "java-backend",
	}
	cases := []caseResult{
		pressureCase("exact", "trace-exact", "client-exact", "trace-exact", "client-exact"),
		pressureCase("missing", "trace-candidate", "client-missing", "trace-root", ""),
		pressureCase("wrong", "trace-wanted", "client-wanted", "trace-foreign", "foreign"),
		{Request: requestCase{Marker: "unresolved", Endpoint: "/api/handoff"}},
	}

	summary := summarizePressureCorrelation(cfg, cases)

	assert.Equal(t, pressureCorrelationSummary{
		ExactHitCount:     1,
		ExplicitRootCount: 1,
		WrongParentCount:  1,
		UnresolvedCount:   1,
	}, summary)
	assert.Equal(t, tracecheck.PressureParentExactHit, cases[0].PressureParentOutcome)
	assert.Equal(t, tracecheck.PressureParentExplicitRoot, cases[1].PressureParentOutcome)
	assert.Equal(t, tracecheck.PressureParentWrong, cases[2].PressureParentOutcome)
	assert.Equal(t, tracecheck.PressureParentUnresolved, cases[3].PressureParentOutcome)
	require.Error(t, validatePressureCorrelation(summary, len(cases)))

	valid := pressureCorrelationSummary{ExactHitCount: 3, ExplicitRootCount: 1}
	require.NoError(t, validatePressureCorrelation(valid, 4))
	require.NoError(t, validatePressureCorrelation(
		pressureCorrelationSummary{ExplicitRootCount: 4},
		4,
	))
}

func pressureCase(
	marker string,
	candidateTraceID string,
	candidateSpanID string,
	javaTraceID string,
	javaParentSpanID string,
) caseResult {
	attributes := map[string]string{
		"http.request.header.x-obi-demo-id": marker,
		"http.route":                        "/api/handoff",
	}
	javaFlags := uint32(0x301)
	if javaParentSpanID == "" {
		javaFlags = 0x101
	}
	apacheServerSpanID := "server-" + marker
	return caseResult{
		Request: requestCase{Marker: marker, Endpoint: "/api/handoff"},
		Trace: tracecheck.Snapshot{Marker: marker, Spans: []tracecheck.Span{
			{
				ServiceName: "apache-proxy",
				Kind:        "SERVER",
				TraceID:     candidateTraceID,
				SpanID:      apacheServerSpanID,
				Attributes:  attributes,
			},
			{
				ServiceName:  "apache-proxy",
				Kind:         "CLIENT",
				TraceID:      candidateTraceID,
				SpanID:       candidateSpanID,
				ParentSpanID: apacheServerSpanID,
				Flags:        0x301,
				Attributes:   attributes,
			},
			{
				ServiceName:  "java-backend",
				Kind:         "SERVER",
				TraceID:      javaTraceID,
				SpanID:       "java-" + marker,
				ParentSpanID: javaParentSpanID,
				Flags:        javaFlags,
				Attributes:   attributes,
			},
		}},
	}
}
