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
	"net"
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

func TestRequestTimeoutDefaultsAndRemainsWithinScenarioDeadline(t *testing.T) {
	assert.Equal(t, defaultRequestTimeout, effectiveRequestTimeout(config{}))
	assert.Equal(t, 5*time.Second, effectiveRequestTimeout(config{
		timeout:        5 * time.Second,
		requestTimeout: defaultRequestTimeout,
	}))
	assert.Equal(t, 70*time.Second, effectiveRequestTimeout(config{
		timeout:        90 * time.Second,
		requestTimeout: 70 * time.Second,
	}))

	require.NoError(t, validateTimeouts(config{
		timeout:        90 * time.Second,
		requestTimeout: 70 * time.Second,
	}))
	require.ErrorContains(t, validateTimeouts(config{
		timeout:           90 * time.Second,
		requestTimeout:    91 * time.Second,
		requestTimeoutSet: true,
	}), "request-timeout")
	require.NoError(t, validateTimeouts(config{
		timeout:        5 * time.Second,
		requestTimeout: defaultRequestTimeout,
	}))
	assert.ErrorContains(t, validateTimeouts(config{
		timeout:        90 * time.Second,
		requestTimeout: 0,
	}), "request-timeout")
}

type deadlineRecordingConn struct {
	deadline time.Time
}

func (connection *deadlineRecordingConn) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (connection *deadlineRecordingConn) Write([]byte) (int, error) {
	return 0, io.EOF
}

func (connection *deadlineRecordingConn) Close() error {
	return nil
}

func (connection *deadlineRecordingConn) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

func (connection *deadlineRecordingConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}

func (connection *deadlineRecordingConn) SetDeadline(deadline time.Time) error {
	connection.deadline = deadline
	return nil
}

func (connection *deadlineRecordingConn) SetReadDeadline(time.Time) error {
	return nil
}

func (connection *deadlineRecordingConn) SetWriteDeadline(time.Time) error {
	return nil
}

func TestConnectionDeadlineHonorsRequestTimeout(t *testing.T) {
	connection := &deadlineRecordingConn{}
	startedAt := time.Now()
	require.NoError(t, setConnectionDeadline(context.Background(), connection, 70*time.Second))
	assert.WithinDuration(t, startedAt.Add(70*time.Second), connection.deadline, time.Second)

	contextDeadline := startedAt.Add(5 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), contextDeadline)
	defer cancel()
	require.NoError(t, setConnectionDeadline(ctx, connection, 70*time.Second))
	assert.WithinDuration(t, contextDeadline, connection.deadline, time.Second)
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
	assert.Equal(
		t,
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

	require.ErrorContains(t, validateAssertionMode(config{
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

func TestCoalescedBridgeCorrelationAcceptsOnlyReceiveAmbiguity(t *testing.T) {
	cfg := config{
		scenario:               "coalesced-bridge",
		apacheService:          "apache-proxy",
		coalescedSourceService: "coalesced-source",
		javaService:            "java-backend",
	}
	first := requestCase{Marker: "first", Endpoint: "/api/coalesced-bridge"}
	second := requestCase{Marker: "second", Endpoint: "/api/coalesced-bridge"}
	requests := []requestCase{first, second}
	snapshots := coalescedSnapshots(first.Marker, second.Marker)
	require.NoError(t, validateCoalescedSnapshotSet(cfg, requests, snapshots[:2], snapshots[2]))
	spans, err := coalescedSpanUnion(snapshots)
	require.NoError(t, err)
	summary, err := classifyCoalescedBridgeAmbiguity(cfg, requests, spans)
	require.NoError(t, err)
	summary.SourcePlaintextWriteBytes = 338
	summary.TLSReadDelta = 1
	summary.TLSBytesDelta = 338
	summary.TakeMissingDelta = 2
	summary.DiscardTotalDelta = 1
	summary.DiscardAmbiguousDelta = 1
	require.NoError(t, validateCoalescedBridgeCorrelation(&summary, 2))
	assert.Equal(t, "receive_ambiguous", summary.Outcome)
	assert.Equal(t, 2, summary.ExplicitRootCount)
	assert.Equal(t, 1, summary.SourceClientOperations)
	assert.Equal(t, "absent", summary.SourceClientMarker)
	assert.True(t, summary.ApacheTriggerChainProven)
	assert.True(t, summary.SourceOperationChainProven)

	for name, mutate := range map[string]func(*coalescedBridgeCorrelationSummary){
		"legacy exact outcome":      func(value *coalescedBridgeCorrelationSummary) { value.ExactHitCount = 2; value.ExplicitRootCount = 0 },
		"wrong parent":              func(value *coalescedBridgeCorrelationSummary) { value.WrongParentCount = 1 },
		"unresolved":                func(value *coalescedBridgeCorrelationSummary) { value.UnresolvedCount = 1 },
		"missing source operation":  func(value *coalescedBridgeCorrelationSummary) { value.SourceClientOperations = 0 },
		"marked source operation":   func(value *coalescedBridgeCorrelationSummary) { value.SourceClientMarker = "first" },
		"broken Apache path":        func(value *coalescedBridgeCorrelationSummary) { value.ApacheTriggerChainProven = false },
		"broken source path":        func(value *coalescedBridgeCorrelationSummary) { value.SourceOperationChainProven = false },
		"missing TLS read":          func(value *coalescedBridgeCorrelationSummary) { value.TLSReadDelta = 0 },
		"wrong TLS bytes":           func(value *coalescedBridgeCorrelationSummary) { value.TLSBytesDelta-- },
		"missing take observations": func(value *coalescedBridgeCorrelationSummary) { value.TakeMissingDelta = 1 },
		"missing ambiguity discard": func(value *coalescedBridgeCorrelationSummary) { value.DiscardTotalDelta = 0 },
		"wrong discard reason":      func(value *coalescedBridgeCorrelationSummary) { value.DiscardAmbiguousDelta = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := summary
			mutate(&candidate)
			require.Error(t, validateCoalescedBridgeCorrelation(&candidate, 2))
		})
	}
}

func TestCoalescedBridgeCorrelationRejectsInvalidTopology(t *testing.T) {
	cfg := config{
		apacheService:          "apache-proxy",
		coalescedSourceService: "coalesced-source",
		javaService:            "java-backend",
	}
	requests := []requestCase{
		{Marker: "first", Endpoint: "/api/coalesced-bridge"},
		{Marker: "second", Endpoint: "/api/coalesced-bridge"},
	}
	tests := map[string]func([]tracecheck.Span){
		"missing Apache server": func(spans []tracecheck.Span) {
			spans[coalescedSpanIndex(t, spans, "apache-proxy", "SERVER")].ServiceName = "other"
		},
		"missing Apache client": func(spans []tracecheck.Span) {
			spans[coalescedSpanIndex(t, spans, "apache-proxy", "CLIENT")].ServiceName = "other"
		},
		"duplicate Apache client": func(spans []tracecheck.Span) {
			index := coalescedSpanIndex(t, spans, "apache-proxy", "CLIENT")
			duplicate := spans[index]
			duplicate.SpanID = "apache-client-duplicate"
			spans[coalescedSpanIndex(t, spans, "apache-proxy", "INTERNAL")] = duplicate
		},
		"broken Apache ancestry": func(spans []tracecheck.Span) {
			spans[coalescedSpanIndex(t, spans, "apache-proxy", "CLIENT")].ParentSpanID = "foreign"
		},
		"source server has remote parent": func(spans []tracecheck.Span) {
			spans[coalescedSpanIndex(t, spans, "coalesced-source", "SERVER")].ParentSpanID = "apache-client"
		},
		"missing source server": func(spans []tracecheck.Span) {
			spans[coalescedSpanIndex(t, spans, "coalesced-source", "SERVER")].ServiceName = "other"
		},
		"missing source operation": func(spans []tracecheck.Span) {
			spans[coalescedSpanIndex(t, spans, "coalesced-source", "CLIENT")].ServiceName = "other"
		},
		"extra source operation": func(spans []tracecheck.Span) {
			index := coalescedSpanIndex(t, spans, "coalesced-source", "CLIENT")
			duplicate := spans[index]
			duplicate.SpanID = "source-client-duplicate"
			spans[coalescedSpanIndex(t, spans, "coalesced-source", "INTERNAL")] = duplicate
		},
		"broken source ancestry": func(spans []tracecheck.Span) {
			spans[coalescedSpanIndex(t, spans, "coalesced-source", "CLIENT")].ParentSpanID = "foreign"
		},
		"marked source operation": func(spans []tracecheck.Span) {
			spans[coalescedSpanIndex(t, spans, "coalesced-source", "CLIENT")].Attributes["http.request.header.x-obi-demo-id"] = "first"
		},
		"invalid source marker": func(spans []tracecheck.Span) {
			spans[coalescedSpanIndex(t, spans, "coalesced-source", "CLIENT")].Attributes["obi.related.marker.invalid"] = "true"
		},
		"Java retained parent": func(spans []tracecheck.Span) {
			spans[coalescedSpanIndex(t, spans, "java-backend", "SERVER")].ParentSpanID = "source-client"
		},
		"Java used wrong endpoint": func(spans []tracecheck.Span) {
			spans[coalescedSpanIndex(t, spans, "java-backend", "SERVER")].Attributes["url.path"] = "/wrong"
		},
		"Java parent locality unknown": func(spans []tracecheck.Span) {
			spans[coalescedSpanIndex(t, spans, "java-backend", "SERVER")].Flags = 0x003
		},
		"Java parent marked remote": func(spans []tracecheck.Span) {
			spans[coalescedSpanIndex(t, spans, "java-backend", "SERVER")].Flags = 0x303
		},
		"Java reused source trace": func(spans []tracecheck.Span) {
			spans[coalescedSpanIndex(t, spans, "java-backend", "SERVER")].TraceID = "source-trace"
		},
		"Java roots share trace": func(spans []tracecheck.Span) {
			first := coalescedSpanIndex(t, spans, "java-backend", "SERVER")
			for index := first + 1; index < len(spans); index++ {
				if spans[index].ServiceName == "java-backend" && spans[index].Kind == "SERVER" {
					spans[index].TraceID = spans[first].TraceID
					return
				}
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			spans := cloneCoalescedSpans(coalescedSnapshots("first", "second")[2].Spans)
			mutate(spans)
			_, err := classifyCoalescedBridgeAmbiguity(cfg, requests, spans)
			require.Error(t, err)
		})
	}

	t.Run("conflicting duplicate union identity", func(t *testing.T) {
		snapshots := coalescedSnapshots("first", "second")
		conflict := snapshots[2].Spans[coalescedSpanIndex(t, snapshots[2].Spans, "coalesced-source", "CLIENT")]
		conflict.ParentSpanID = "foreign"
		snapshots[0].Spans = append(snapshots[0].Spans, conflict)
		_, err := coalescedSpanUnion(snapshots)
		require.ErrorContains(t, err, "conflict")
	})
}

func TestCoalescedBridgeSnapshotsRequireContinuityAndNoLoss(t *testing.T) {
	cfg := config{
		apacheService:          "apache-proxy",
		coalescedSourceService: "coalesced-source",
		javaService:            "java-backend",
	}
	requests := []requestCase{
		{Marker: "first", Endpoint: "/api/coalesced-bridge"},
		{Marker: "second", Endpoint: "/api/coalesced-bridge"},
	}
	for name, mutate := range map[string]func([]tracecheck.Snapshot){
		"changed receiver":     func(value []tracecheck.Snapshot) { value[1].ReceiverInstanceID = "other" },
		"changed generation":   func(value []tracecheck.Snapshot) { value[2].ResetGeneration++ },
		"empty receiver":       func(value []tracecheck.Snapshot) { value[2].ReceiverInstanceID = "" },
		"marker mismatch":      func(value []tracecheck.Snapshot) { value[1].Marker = "other" },
		"dropped span":         func(value []tracecheck.Snapshot) { value[2].DroppedSpans = 1 },
		"omitted related span": func(value []tracecheck.Snapshot) { value[0].OmittedRelatedSpans = 1 },
		"counter regression":   func(value []tracecheck.Snapshot) { value[2].ReceivedSpans = 1 },
		"empty first marker view": func(value []tracecheck.Snapshot) {
			value[0].Spans = nil
		},
		"missing first marker trigger path": func(value []tracecheck.Snapshot) {
			value[0].Spans[coalescedSpanIndex(t, value[0].Spans, "apache-proxy", "CLIENT")].ServiceName = "other"
		},
		"wrong Java marker in marked view": func(value []tracecheck.Snapshot) {
			index := coalescedSpanIndex(t, value[1].Spans, "java-backend", "SERVER")
			value[1].Spans[index].Attributes["http.request.header.x-obi-demo-id"] = "first"
		},
		"Java boundary absent from unfiltered view": func(value []tracecheck.Snapshot) {
			for index := range value[2].Spans {
				if value[2].Spans[index].ServiceName == "java-backend" &&
					tracecheck.MatchesMarker(value[2].Spans[index], "second") {
					value[2].Spans = append(value[2].Spans[:index], value[2].Spans[index+1:]...)
					return
				}
			}
		},
		"source operation only in marked related view": func(value []tracecheck.Snapshot) {
			index := coalescedSpanIndex(t, value[2].Spans, "coalesced-source", "CLIENT")
			value[0].RelatedSpans = append(value[0].RelatedSpans, value[2].Spans[index])
			value[2].Spans = append(value[2].Spans[:index], value[2].Spans[index+1:]...)
		},
		"Apache trigger only in marked view": func(value []tracecheck.Snapshot) {
			index := coalescedSpanIndex(t, value[2].Spans, "apache-proxy", "CLIENT")
			value[2].Spans = append(value[2].Spans[:index], value[2].Spans[index+1:]...)
		},
		"duplicate identity": func(value []tracecheck.Snapshot) {
			value[2].Spans = append(value[2].Spans, value[2].Spans[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			snapshots := coalescedSnapshots("first", "second")
			mutate(snapshots)
			require.Error(t, validateCoalescedSnapshotSet(cfg, requests, snapshots[:2], snapshots[2]))
		})
	}
}

func TestCoalescedBridgeTrafficRequiresOneSourceWriteAndOneJavaReceive(t *testing.T) {
	baseline := javaDiagnosticsSnapshot(t, 0)
	requests, err := makeRequests(config{
		scenario:              "coalesced-bridge",
		javaDiagnosticsBefore: baseline,
		seed:                  42,
	})
	require.NoError(t, err)
	require.Len(t, requests, 2)
	assert.NotEqual(t, requests[0].Marker, requests[1].Marker)
	assert.Equal(t, "/api/coalesced-bridge", requests[0].Endpoint)
	assert.True(t, requests[1].BridgeDiagnostics)

	markers := []string{requests[0].Marker, requests[1].Marker}
	evidence := &coalescedBridgeEvidence{
		PlaintextCallbackCount:    1,
		PlaintextCallbackBytes:    512,
		PlaintextSHA256:           strings.Repeat("a", 64),
		ParserRequestCount:        2,
		ParserCallbackGenerations: []int{1, 1},
		ParserMarkers:             markers,
		RequestMarkersExact:       true,
		OnePlaintextReceive:       true,
		Passed:                    true,
		FailureReason:             "none",
	}
	responses := []backendResponse{
		{Marker: markers[0], Secure: true, Protocol: "HTTP/1.1", TLSProtocol: "TLSv1.3", TLSCipher: "cipher", BackendConnectionID: 1, BackendRemotePort: 2, BackendKind: "netty-coalesced-bridge", CoalescedBridge: evidence},
		{Marker: markers[1], Secure: true, Protocol: "HTTP/1.1", TLSProtocol: "TLSv1.3", TLSCipher: "cipher", BackendConnectionID: 1, BackendRemotePort: 2, BackendKind: "netty-coalesced-bridge", CoalescedBridge: evidence},
	}
	for index := range responses {
		require.NoError(t, validateCoalescedBackendResponse(
			config{expectedTLS: "TLSv1.3"},
			requests[index],
			responses[index],
			512,
			strings.Repeat("a", 64),
			markers,
		))
	}
	connection := &connectionEvidence{
		FrontendConnections:          1,
		FrontendProtocol:             "HTTP/1.1",
		SourceBackendTLSConnections:  1,
		SourcePlaintextWriteCalls:    1,
		SourcePlaintextWriteBytes:    512,
		SourcePlaintextSHA256:        strings.Repeat("a", 64),
		SourceRequestBoundaries:      2,
		SourceTraceparentHeaderCount: 0,
	}
	require.NoError(t, validateConnectionShape("coalesced-bridge", responses, connection))
	for name, digest := range map[string]string{
		"non-hex source digest":   strings.Repeat("z", 64),
		"different source digest": strings.Repeat("b", 64),
	} {
		t.Run(name, func(t *testing.T) {
			changed := *connection
			changed.SourcePlaintextSHA256 = digest
			require.Error(t, validateConnectionShape("coalesced-bridge", responses, &changed))
		})
	}

	evidence.ParserCallbackGenerations = []int{1, 2}
	require.ErrorContains(t, validateCoalescedBackendResponse(
		config{expectedTLS: "TLSv1.3"},
		requests[0],
		responses[0],
		512,
		strings.Repeat("a", 64),
		markers,
	), "one-plaintext")

	evidence.ParserCallbackGenerations = []int{1, 1}
	for name, test := range map[string]struct {
		plaintextBytes int
		digest         string
		mutate         func(*coalescedBridgeEvidence)
	}{
		"byte count mismatch": {
			plaintextBytes: 513,
			digest:         strings.Repeat("a", 64),
		},
		"non-hex digest": {
			plaintextBytes: 512,
			digest:         strings.Repeat("z", 64),
		},
		"wrong-length digest": {
			plaintextBytes: 512,
			digest:         strings.Repeat("a", 62),
		},
		"different backend digest": {
			plaintextBytes: 512,
			digest:         strings.Repeat("a", 64),
			mutate: func(value *coalescedBridgeEvidence) {
				value.PlaintextSHA256 = strings.Repeat("b", 64)
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := *evidence
			if test.mutate != nil {
				test.mutate(&changed)
			}
			response := responses[0]
			response.CoalescedBridge = &changed
			require.ErrorContains(t, validateCoalescedBackendResponse(
				config{expectedTLS: "TLSv1.3"},
				requests[0],
				response,
				test.plaintextBytes,
				test.digest,
				markers,
			), "one-plaintext")
		})
	}
}

func TestBoundedResponseReadsRejectOneByteOfOverflow(t *testing.T) {
	for name, test := range map[string]struct {
		size      int
		wantError bool
	}{
		"exact bound":   {size: 32},
		"one byte over": {size: 33, wantError: true},
	} {
		t.Run(name, func(t *testing.T) {
			body := bytes.Repeat([]byte("x"), test.size)
			read, err := readBoundedBody(bytes.NewReader(body), 32, "fixture")
			if test.wantError {
				require.ErrorContains(t, err, "exceeded")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, body, read)
		})
	}

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assert.Equal(t, "/api/coalesced-source", request.URL.Path)
		writer.Header().Set("X-OBI-Coalesced-Source", "live")
		body := append([]byte("{}"), bytes.Repeat(
			[]byte(" "),
			int(maximumCoalescedSourceBytes)-1,
		)...)
		_, err := writer.Write(body)
		assert.NoError(t, err)
	}))
	defer server.Close()

	_, _, _, _, err := sendCoalescedBridgeRequests(
		context.Background(),
		config{baseURL: server.URL, requestTimeout: time.Second},
		[]requestCase{{Marker: "first"}, {Marker: "second"}},
	)
	require.ErrorContains(t, err, "exceeded")
}

func TestCancellationReconciliationMakesWrongParentsFatal(t *testing.T) {
	cfg := config{apacheService: "apache-proxy", javaService: "java-backend"}
	noDrops := diagnosticDropSummary{}
	empty := tracecheck.Snapshot{Marker: "cancel"}
	outcome, err := classifyCancellationSnapshot(cfg, "cancel", empty, noDrops)
	assert.Equal(t, "unresolved", outcome)
	require.ErrorContains(t, err, "one marked Apache")

	missing := cancellationSnapshot("client")
	missing.Spans = missing.Spans[:1]
	outcome, err = classifyCancellationSnapshot(cfg, "cancel", missing, noDrops)
	require.NoError(t, err)
	assert.Equal(t, "missing", outcome)
	_, err = classifyCancellationSnapshot(cfg, "cancel", missing, diagnosticDrops("missing", 1))
	require.ErrorContains(t, err, "zero receive drops")

	exact := cancellationSnapshot("client")
	outcome, err = classifyCancellationSnapshot(cfg, "cancel", exact, noDrops)
	require.NoError(t, err)
	assert.Equal(t, "exact", outcome)
	_, err = classifyCancellationSnapshot(cfg, "cancel", exact, diagnosticDrops("timeout", 1))
	require.ErrorContains(t, err, "zero receive drops")

	flagsChanged := cancellationSnapshot("client")
	flagsChanged.Spans[1].Flags = 0x300
	outcome, err = classifyCancellationSnapshot(cfg, "cancel", flagsChanged, noDrops)
	assert.Equal(t, "wrong_parent", outcome)
	require.ErrorContains(t, err, "changed trace flags")

	root := cancellationSnapshot("")
	outcome, err = classifyCancellationSnapshot(cfg, "cancel", root, diagnosticDrops("missing", 1))
	require.NoError(t, err)
	assert.Equal(t, "reason_coded_drop", outcome)
	_, err = classifyCancellationSnapshot(cfg, "cancel", root, noDrops)
	require.ErrorContains(t, err, "exactly one allowed reason-coded")
	_, err = classifyCancellationSnapshot(cfg, "cancel", root, diagnosticDrops("missing", 2))
	require.ErrorContains(t, err, "exactly one allowed reason-coded")
	_, err = classifyCancellationSnapshot(cfg, "cancel", root, diagnosticDropSummary{
		Reasons: []string{"missing", "ambiguous"},
		Counts:  map[string]uint64{"missing": 1, "ambiguous": 1},
		Total:   2,
	})
	require.ErrorContains(t, err, "exactly one allowed reason-coded")
	_, err = classifyCancellationSnapshot(cfg, "cancel", root, diagnosticDrops("valid", 1))
	require.ErrorContains(t, err, "exactly one allowed reason-coded")

	wrong := cancellationSnapshot("foreign")
	outcome, err = classifyCancellationSnapshot(cfg, "cancel", wrong, noDrops)
	assert.Equal(t, "wrong_parent", outcome)
	require.ErrorContains(t, err, "did not identify")
}

func TestCancellationReconciliationRequiresOneExactApacheCandidate(t *testing.T) {
	cfg := config{apacheService: "apache-proxy", javaService: "java-backend"}
	for name, test := range map[string]struct {
		snapshot tracecheck.Snapshot
		drops    diagnosticDropSummary
	}{
		"missing": {
			snapshot: func() tracecheck.Snapshot {
				value := cancellationSnapshot("client")
				value.Spans = value.Spans[:1]
				return value
			}(),
		},
		"exact": {snapshot: cancellationSnapshot("client")},
		"root": {
			snapshot: cancellationSnapshot(""),
			drops:    diagnosticDrops("missing", 1),
		},
	} {
		t.Run(name+" missing Apache", func(t *testing.T) {
			candidate := test.snapshot
			candidate.Spans = append([]tracecheck.Span(nil), test.snapshot.Spans...)
			candidate.Spans[0].ServiceName = "other"
			outcome, err := classifyCancellationSnapshot(cfg, "cancel", candidate, test.drops)
			assert.Equal(t, "unresolved", outcome)
			require.ErrorContains(t, err, "one marked Apache")
		})
		t.Run(name+" duplicate Apache", func(t *testing.T) {
			candidate := test.snapshot
			candidate.Spans = append([]tracecheck.Span(nil), test.snapshot.Spans...)
			duplicate := candidate.Spans[0]
			duplicate.SpanID = "duplicate-client"
			candidate.Spans = append(candidate.Spans, duplicate)
			outcome, err := classifyCancellationSnapshot(cfg, "cancel", candidate, test.drops)
			assert.Equal(t, "unresolved", outcome)
			require.ErrorContains(t, err, "one marked Apache")
		})
	}
	wrongApacheEndpoint := cancellationSnapshot("client")
	wrongApacheEndpoint.Spans[0].Attributes = cloneStringMap(wrongApacheEndpoint.Spans[0].Attributes)
	wrongApacheEndpoint.Spans[0].Attributes["http.route"] = "/wrong"
	outcome, err := classifyCancellationSnapshot(
		cfg,
		"cancel",
		wrongApacheEndpoint,
		diagnosticDropSummary{},
	)
	assert.Equal(t, "unresolved", outcome)
	require.ErrorContains(t, err, "one marked Apache")

	wrongEndpoint := cancellationSnapshot("client")
	wrongEndpoint.Spans[1].Attributes = cloneStringMap(wrongEndpoint.Spans[1].Attributes)
	wrongEndpoint.Spans[1].Attributes["http.route"] = "/wrong"
	outcome, err = classifyCancellationSnapshot(cfg, "cancel", wrongEndpoint, diagnosticDropSummary{})
	assert.Equal(t, "unresolved", outcome)
	require.ErrorContains(t, err, "wrong endpoint")

	extraJava := cancellationSnapshot("client")
	duplicate := extraJava.Spans[1]
	duplicate.SpanID = "duplicate-java"
	duplicate.Attributes = cloneStringMap(duplicate.Attributes)
	duplicate.Attributes["http.route"] = "/wrong"
	extraJava.Spans = append(extraJava.Spans, duplicate)
	outcome, err = classifyCancellationSnapshot(cfg, "cancel", extraJava, diagnosticDropSummary{})
	assert.Equal(t, "unresolved", outcome)
	require.ErrorContains(t, err, "one marked Java")

	for name, related := range map[string]tracecheck.Span{
		"related wrong parent": {
			ServiceName:  "java-backend",
			Kind:         "SERVER",
			TraceID:      "trace",
			SpanID:       "related-java-wrong-parent",
			ParentSpanID: "foreign",
			Flags:        0x301,
		},
		"related changed flags": {
			ServiceName:  "java-backend",
			Kind:         "SERVER",
			TraceID:      "trace",
			SpanID:       "related-java-changed-flags",
			ParentSpanID: "client",
			Flags:        0x300,
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cancellationSnapshot("client")
			candidate.Spans = candidate.Spans[:1]
			candidate.RelatedSpans = []tracecheck.Span{related}
			outcome, err := classifyCancellationSnapshot(
				cfg,
				"cancel",
				candidate,
				diagnosticDropSummary{},
			)
			assert.Equal(t, "unresolved", outcome)
			require.ErrorContains(t, err, "unmatched Java")
		})
	}
}

func cancellationReconciliationFixture(t *testing.T) (
	config,
	string,
	tracecheck.Snapshot,
	tracecheck.Snapshot,
) {
	t.Helper()
	exact := cancellationSnapshot("client")
	incomplete := exact
	incomplete.Spans = append([]tracecheck.Span(nil), exact.Spans[1:]...)
	return config{
			apacheService:         "apache-proxy",
			javaService:           "java-backend",
			javaDiagnosticsBefore: javaDiagnosticsSnapshot(t, 0),
		}, javaDiagnosticsSnapshotWithCounters(t, map[string]uint64{
			"t_valid":      2,
			"take_sampled": 2,
		}), exact, incomplete
}

func TestCancellationReconciliationWaitsForLateExactApacheCandidate(t *testing.T) {
	const marker = "cancel"
	cfg, diagnosticsAfter, exact, incomplete := cancellationReconciliationFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	fetches := 0
	receiverErr := errors.New("receiver unavailable")
	fetch := func(_ context.Context, _ string, _ string) (tracecheck.Snapshot, error) {
		fetches++
		if fetches <= 2 {
			return tracecheck.Snapshot{}, receiverErr
		}
		if fetches <= 4 {
			return incomplete, nil
		}
		return exact, nil
	}

	snapshot, outcome, reasons, err := awaitCancellationReconciliationWithTiming(
		ctx,
		cfg,
		marker,
		diagnosticsAfter,
		fetch,
		5*time.Millisecond,
		5*time.Millisecond,
	)

	require.NoError(t, err)
	assert.Equal(t, "exact", outcome)
	assert.Empty(t, reasons)
	assert.Equal(t, exact, snapshot)
	assert.GreaterOrEqual(t, fetches, 6)
}

func TestCancellationReconciliationRejectsSnapshotFetchedAfterDeadline(t *testing.T) {
	cfg, diagnosticsAfter, exact, _ := cancellationReconciliationFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fetches := 0
	fetch := func(_ context.Context, _ string, _ string) (tracecheck.Snapshot, error) {
		fetches++
		cancel()
		return exact, nil
	}

	snapshot, outcome, _, err := awaitCancellationReconciliationWithTiming(
		ctx,
		cfg,
		"cancel",
		diagnosticsAfter,
		fetch,
		time.Nanosecond,
		time.Millisecond,
	)

	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, tracecheck.Snapshot{}, snapshot)
	assert.Empty(t, outcome)
	assert.Equal(t, 1, fetches)
}

func TestCancellationReconciliationDoesNotFetchAfterDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fetches := 0
	fetch := func(_ context.Context, _ string, _ string) (tracecheck.Snapshot, error) {
		fetches++
		return tracecheck.Snapshot{}, nil
	}

	_, _, _, err := awaitCancellationReconciliationWithTiming(
		ctx,
		config{
			javaDiagnosticsBefore: javaDiagnosticsSnapshot(t, 0),
		},
		"cancel",
		javaDiagnosticsSnapshot(t, 0),
		fetch,
		time.Millisecond,
		time.Millisecond,
	)

	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, fetches)
}

func TestCancellationReconciliationPreservesEvidenceAcrossFetchFailure(t *testing.T) {
	cfg, diagnosticsAfter, _, incomplete := cancellationReconciliationFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fetches := 0
	receiverErr := errors.New("receiver unavailable")
	fetch := func(_ context.Context, _ string, _ string) (tracecheck.Snapshot, error) {
		fetches++
		if fetches == 1 {
			return incomplete, nil
		}
		if fetches == 2 {
			return tracecheck.Snapshot{}, receiverErr
		}
		cancel()
		return tracecheck.Snapshot{}, receiverErr
	}

	snapshot, outcome, _, err := awaitCancellationReconciliationWithTiming(
		ctx,
		cfg,
		"cancel",
		diagnosticsAfter,
		fetch,
		time.Millisecond,
		time.Millisecond,
	)

	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, err, receiverErr)
	require.ErrorContains(t, err, "one marked Apache")
	assert.Equal(t, incomplete, snapshot)
	assert.Equal(t, "unresolved", outcome)
	assert.Equal(t, 3, fetches)
}

func TestCancellationReconciliationRetainsInvalidEvidenceUntilCancellation(t *testing.T) {
	cfg, diagnosticsAfter, _, incomplete := cancellationReconciliationFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fetches := 0
	fetch := func(_ context.Context, _ string, _ string) (tracecheck.Snapshot, error) {
		fetches++
		if fetches == 4 {
			cancel()
		}
		return incomplete, nil
	}

	snapshot, outcome, _, err := awaitCancellationReconciliationWithTiming(
		ctx,
		cfg,
		"cancel",
		diagnosticsAfter,
		fetch,
		0,
		time.Nanosecond,
	)

	require.ErrorIs(t, err, context.Canceled)
	require.ErrorContains(t, err, "one marked Apache")
	assert.Equal(t, incomplete, snapshot)
	assert.Equal(t, "unresolved", outcome)
	assert.Equal(t, 4, fetches)
}

type failOnErrCallContext struct {
	context.Context
	calls  int
	failAt int
}

func (ctx *failOnErrCallContext) Err() error {
	ctx.calls++
	if ctx.calls >= ctx.failAt {
		return context.Canceled
	}
	return nil
}

func TestCancellationReconciliationRejectsDeadlineDuringClassification(t *testing.T) {
	cfg, diagnosticsAfter, exact, _ := cancellationReconciliationFixture(t)
	ctx := &failOnErrCallContext{Context: context.Background(), failAt: 3}
	fetches := 0
	fetch := func(_ context.Context, _ string, _ string) (tracecheck.Snapshot, error) {
		fetches++
		return exact, nil
	}

	snapshot, outcome, _, err := awaitCancellationReconciliationWithTiming(
		ctx,
		cfg,
		"cancel",
		diagnosticsAfter,
		fetch,
		0,
		time.Millisecond,
	)

	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, exact, snapshot)
	assert.Equal(t, "exact", outcome)
	assert.Equal(t, 1, fetches)
	assert.Equal(t, 3, ctx.calls)
}

func TestCancellationReconciliationRejectsDeadlineBeforeMaturedSuccess(t *testing.T) {
	cfg, diagnosticsAfter, exact, _ := cancellationReconciliationFixture(t)
	ctx := &failOnErrCallContext{Context: context.Background(), failAt: 4}
	fetches := 0
	fetch := func(_ context.Context, _ string, _ string) (tracecheck.Snapshot, error) {
		fetches++
		return exact, nil
	}

	snapshot, outcome, _, err := awaitCancellationReconciliationWithTiming(
		ctx,
		cfg,
		"cancel",
		diagnosticsAfter,
		fetch,
		0,
		time.Millisecond,
	)

	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, exact, snapshot)
	assert.Equal(t, "exact", outcome)
	assert.Equal(t, 1, fetches)
	assert.Equal(t, 4, ctx.calls)
}

func TestCancellationReconciliationRestartsQuiescenceWhenValidOutcomeChanges(t *testing.T) {
	const quiescence = 5 * time.Millisecond
	cfg, diagnosticsAfter, exact, _ := cancellationReconciliationFixture(t)
	missing := exact
	missing.Spans = append([]tracecheck.Span(nil), exact.Spans[:1]...)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	fetches := 0
	fetch := func(_ context.Context, _ string, _ string) (tracecheck.Snapshot, error) {
		fetches++
		if fetches == 1 {
			return missing, nil
		}
		return exact, nil
	}

	snapshot, outcome, _, err := awaitCancellationReconciliationWithTiming(
		ctx,
		cfg,
		"cancel",
		diagnosticsAfter,
		fetch,
		quiescence,
		5*time.Millisecond,
	)

	require.NoError(t, err)
	assert.Equal(t, exact, snapshot)
	assert.Equal(t, "exact", outcome)
	assert.GreaterOrEqual(t, fetches, 3)
}

func TestDiagnosticDeltasPreserveEveryCounterAndDropMagnitude(t *testing.T) {
	before := javaDiagnosticsSnapshot(t, 0)
	after := javaDiagnosticsSnapshotWithCounters(t, map[string]uint64{
		"t_timeout": 3,
		"d_valid":   1,
		"d_missing": 2,
	})
	deltas, err := diagnosticCounterDeltas(before, after, "fixture")
	require.NoError(t, err)
	assert.EqualValues(t, 3, deltas["t_timeout"])
	drops := summarizeDiagnosticDrops(deltas)
	assert.Equal(t, []string{"valid", "missing"}, drops.Reasons)
	assert.EqualValues(t, 1, drops.Counts["valid"])
	assert.EqualValues(t, 2, drops.Counts["missing"])
	assert.EqualValues(t, 3, drops.Total)

	decreasedBefore := javaDiagnosticsSnapshotWithCounters(t, map[string]uint64{"t_valid": 2})
	decreasedAfter := javaDiagnosticsSnapshotWithCounters(t, map[string]uint64{"t_valid": 1})
	_, err = diagnosticCounterDeltas(decreasedBefore, decreasedAfter, "fixture")
	require.ErrorContains(t, err, "decreased")
}

func TestDeterministicDiagnosticsRejectContradictoryPassedOutcomes(t *testing.T) {
	ambiguous := deterministicDiagnosticDeltas(0, "ambiguous")
	ambiguous["t_missing"] = 2
	require.NoError(t, validateCoalescedDiagnosticDeltas(ambiguous, "receive_ambiguous"))

	for name, mutate := range map[string]func(map[string]uint64){
		"missing take status":    func(value map[string]uint64) { value["t_missing"] = 1 },
		"extra take status":      func(value map[string]uint64) { value["t_missing"] = 3 },
		"missing ambiguity":      func(value map[string]uint64) { value["d_ambiguous"] = 0 },
		"extra ambiguity":        func(value map[string]uint64) { value["d_ambiguous"] = 2 },
		"unexpected valid take":  func(value map[string]uint64) { value["t_valid"] = 1 },
		"unexpected drop status": func(value map[string]uint64) { value["d_timeout"] = 1 },
		"unexpected failure":     func(value map[string]uint64) { value["provider_reject"] = 1 },
		"unsampled take":         func(value map[string]uint64) { value["take_unsampled"] = 1 },
		"standard discard":       func(value map[string]uint64) { value["discard_standard"] = 1 },
		"sampled mismatch":       func(value map[string]uint64) { value["take_sampled"] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneUint64Map(ambiguous)
			mutate(candidate)
			require.Error(t, validateCoalescedDiagnosticDeltas(candidate, "receive_ambiguous"))
		})
	}
	for _, counter := range javaDeterministicFailureCounters {
		t.Run("failure counter "+counter, func(t *testing.T) {
			candidate := cloneUint64Map(ambiguous)
			candidate[counter] = 1
			require.Error(t, validateCoalescedDiagnosticDeltas(candidate, "receive_ambiguous"))
		})
	}
	for _, counter := range []string{"d_unknown", "d_valid"} {
		t.Run("unexpected "+counter, func(t *testing.T) {
			candidate := cloneUint64Map(ambiguous)
			candidate[counter] = 1
			require.Error(t, validateCoalescedDiagnosticDeltas(candidate, "receive_ambiguous"))
		})
	}
	require.Error(t, validateCoalescedDiagnosticDeltas(ambiguous, "supported_exact"))

	require.NoError(t, validateCancellationDiagnosticDeltas(
		deterministicDiagnosticDeltas(2, ""),
		"exact",
		diagnosticDropSummary{},
	))
	for _, valid := range []uint64{1, 2} {
		require.NoError(t, validateCancellationDiagnosticDeltas(
			deterministicDiagnosticDeltas(valid, ""),
			"missing",
			diagnosticDropSummary{},
		))
	}
	reasonCoded := deterministicDiagnosticDeltas(1, "missing")
	require.NoError(t, validateCancellationDiagnosticDeltas(
		reasonCoded,
		"reason_coded_drop",
		diagnosticDrops("missing", 1),
	))
	for _, valid := range []uint64{0, 3} {
		require.Error(t, validateCancellationDiagnosticDeltas(
			deterministicDiagnosticDeltas(valid, ""),
			"missing",
			diagnosticDropSummary{},
		))
	}
	doubleDrop := deterministicDiagnosticDeltas(1, "missing")
	doubleDrop["d_missing"] = 2
	require.Error(t, validateCancellationDiagnosticDeltas(
		doubleDrop,
		"reason_coded_drop",
		diagnosticDrops("missing", 2),
	))
	mixedDrop := deterministicDiagnosticDeltas(1, "missing")
	mixedDrop["d_ambiguous"] = 1
	require.Error(t, validateCancellationDiagnosticDeltas(
		mixedDrop,
		"reason_coded_drop",
		diagnosticDropSummary{
			Reasons: []string{"missing", "ambiguous"},
			Counts:  map[string]uint64{"missing": 1, "ambiguous": 1},
			Total:   2,
		},
	))
}

func TestFaultEncodingAlwaysEmitsDropReasonArrays(t *testing.T) {
	var output bytes.Buffer
	require.NoError(t, encodeRunResult(&output, &runResult{Faults: []faultResult{
		{ParentOutcome: "exact"},
		{ParentOutcome: "missing"},
		{ParentOutcome: "reason_coded_drop", DropReasons: []string{"timeout"}},
	}}))
	var decoded struct {
		Faults []struct {
			DropReasons []string `json:"drop_reasons"`
		} `json:"faults"`
	}
	require.NoError(t, json.Unmarshal(output.Bytes(), &decoded))
	require.Len(t, decoded.Faults, 3)
	assert.NotNil(t, decoded.Faults[0].DropReasons)
	assert.Empty(t, decoded.Faults[0].DropReasons)
	assert.NotNil(t, decoded.Faults[1].DropReasons)
	assert.Empty(t, decoded.Faults[1].DropReasons)
	assert.Equal(t, []string{"timeout"}, decoded.Faults[2].DropReasons)
}

func TestConcurrencyWorkloadCarriesBoundedBarrierEvidence(t *testing.T) {
	requests, err := makeRequests(config{scenario: "concurrency", requestCount: 4, seed: 42})
	require.NoError(t, err)
	for _, request := range requests {
		assert.Equal(t, "c000000000000002a", request.ConcurrencyBatch)
		assert.Equal(t, 4, request.ConcurrencyExpected)
		assert.Zero(t, request.DelayMillis)
	}
	responses := make([]backendResponse, 4)
	for index := range responses {
		responses[index] = backendResponse{
			BackendConnectionID:     uint64(index + 1),
			BackendWorkerID:         uint64(index + 11),
			ConcurrencyParticipants: 4,
			ConcurrencyMaxActive:    4,
			ConcurrencyArrival:      index + 1,
			ConcurrencyRelease:      7,
		}
	}
	evidence := buildConcurrencyEvidence(responses)
	assert.Equal(t, 4, evidence.DistinctBackendWorkers)
	assert.Equal(t, 4, evidence.DistinctConcurrencyArrivals)
	assert.Equal(t, 4, evidence.ConcurrencyParticipants)
	assert.Equal(t, 4, evidence.ConcurrencyMaxActive)
	assert.Equal(t, uint64(7), evidence.ConcurrencyRelease)
	require.NoError(t, validateConnectionShape("concurrency", responses, evidence))

	for name, mutate := range map[string]func([]backendResponse){
		"three of four workers": func(value []backendResponse) {
			value[3].BackendWorkerID = value[0].BackendWorkerID
		},
		"duplicate arrival": func(value []backendResponse) {
			value[3].ConcurrencyArrival = value[2].ConcurrencyArrival
		},
		"zero worker": func(value []backendResponse) {
			value[3].BackendWorkerID = 0
		},
		"mismatched release": func(value []backendResponse) {
			value[1].ConcurrencyRelease = 8
		},
		"zero release": func(value []backendResponse) {
			for index := range value {
				value[index].ConcurrencyRelease = 0
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := append([]backendResponse(nil), responses...)
			mutate(candidate)
			candidateEvidence := buildConcurrencyEvidence(candidate)
			require.ErrorContains(t, validateConnectionShape(
				"concurrency",
				candidate,
				candidateEvidence,
			), "worker overlap")
		})
	}
}

func TestConcurrencyWorkloadRequiresSupportedBarrierSize(t *testing.T) {
	for _, count := range []int{1, 65} {
		_, err := makeRequests(config{scenario: "concurrency", requestCount: count, seed: 42})
		require.ErrorContains(t, err, "requires between two and 64 requests")
	}
	for _, count := range []int{2, 64} {
		requests, err := makeRequests(
			config{scenario: "concurrency", requestCount: count, seed: 42},
		)
		require.NoError(t, err)
		require.Len(t, requests, count)
	}
}

func coalescedSnapshots(firstMarker, secondMarker string) []tracecheck.Snapshot {
	continuity := tracecheck.ReceiverContinuity{
		ReceiverInstanceID: "receiver-instance",
		ResetGeneration:    1,
	}
	triggerAttributes := map[string]string{
		"http.request.header.x-obi-demo-id": firstMarker,
		"http.route":                        "/api/coalesced-source",
	}
	spans := []tracecheck.Span{
		tracecheck.Span{
			ServiceName: "apache-proxy", Kind: "SERVER", TraceID: "apache-trace",
			SpanID: "apache-server", Flags: 0x001, Attributes: cloneStringMap(triggerAttributes),
		},
		tracecheck.Span{
			ServiceName: "apache-proxy", Kind: "INTERNAL", TraceID: "apache-trace",
			SpanID: "apache-processing", ParentSpanID: "apache-server",
		},
		tracecheck.Span{
			ServiceName: "apache-proxy", Kind: "CLIENT", TraceID: "apache-trace",
			SpanID: "apache-client", ParentSpanID: "apache-processing", Flags: 0x001,
			Attributes: cloneStringMap(triggerAttributes),
		},
		tracecheck.Span{
			ServiceName: "coalesced-source", Kind: "SERVER", TraceID: "source-trace",
			SpanID: "source-server", Flags: 0x001, Attributes: cloneStringMap(triggerAttributes),
		},
		tracecheck.Span{
			ServiceName: "coalesced-source", Kind: "INTERNAL", TraceID: "source-trace",
			SpanID: "source-processing", ParentSpanID: "source-server",
		},
		tracecheck.Span{
			ServiceName: "coalesced-source", Kind: "CLIENT", TraceID: "source-trace",
			SpanID: "source-client", ParentSpanID: "source-processing", Flags: 0x001,
			Attributes: map[string]string{"url.path": "/api/coalesced-bridge"},
		},
	}
	for index, marker := range []string{firstMarker, secondMarker} {
		spans = append(spans, tracecheck.Span{
			ServiceName: "java-backend", Kind: "SERVER",
			TraceID: fmt.Sprintf("java-root-trace-%d", index+1),
			SpanID:  fmt.Sprintf("java-server-%d", index+1), Flags: 0x103,
			Attributes: map[string]string{
				"http.request.header.x-obi-demo-id": marker,
				"url.path":                          "/api/coalesced-bridge",
			},
		})
	}
	return []tracecheck.Snapshot{
		{
			ReceiverContinuity: continuity, Marker: firstMarker, ReceivedBatches: 8, ReceivedSpans: 8,
			Spans: cloneCoalescedSpans([]tracecheck.Span{spans[0], spans[1], spans[2], spans[3], spans[6]}),
		},
		{
			ReceiverContinuity: continuity, Marker: secondMarker, ReceivedBatches: 8, ReceivedSpans: 8,
			Spans: cloneCoalescedSpans([]tracecheck.Span{spans[7]}),
		},
		{
			ReceiverContinuity: continuity, ReceivedBatches: 8, ReceivedSpans: 8,
			Spans: cloneCoalescedSpans(spans),
		},
	}
}

func cloneCoalescedSpans(source []tracecheck.Span) []tracecheck.Span {
	cloned := append([]tracecheck.Span(nil), source...)
	for index := range cloned {
		cloned[index].Attributes = cloneStringMap(cloned[index].Attributes)
	}
	return cloned
}

func coalescedSpanIndex(t *testing.T, spans []tracecheck.Span, service, kind string) int {
	t.Helper()
	return spanIndex(t, tracecheck.Snapshot{Spans: spans}, service, kind)
}

func spanIndex(t *testing.T, snapshot tracecheck.Snapshot, service, kind string) int {
	t.Helper()
	for index, span := range snapshot.Spans {
		if span.ServiceName == service && strings.EqualFold(span.Kind, kind) {
			return index
		}
	}
	t.Fatalf("missing %s %s span in %+v", service, kind, snapshot)
	return -1
}

func cloneStringMap(source map[string]string) map[string]string {
	cloned := make(map[string]string, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

func diagnosticDrops(status string, count uint64) diagnosticDropSummary {
	return diagnosticDropSummary{
		Reasons: []string{status},
		Counts:  map[string]uint64{status: count},
		Total:   count,
	}
}

func deterministicDiagnosticDeltas(valid uint64, discardStatus string) map[string]uint64 {
	deltas := make(map[string]uint64, len(javaDiagnosticsFieldNames))
	for _, counter := range javaDiagnosticsFieldNames {
		deltas[counter] = 0
	}
	deltas["t_valid"] = valid
	deltas["take_sampled"] = valid
	if discardStatus != "" {
		deltas["d_"+discardStatus] = 1
	}
	return deltas
}

func cloneUint64Map(source map[string]uint64) map[string]uint64 {
	cloned := make(map[string]uint64, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

func cancellationSnapshot(javaParent string) tracecheck.Snapshot {
	const (
		marker  = "cancel"
		traceID = "trace"
	)

	attributes := map[string]string{
		"http.request.header.x-obi-demo-id": marker,
		"http.route":                        "/api/echo",
	}
	javaTrace := traceID
	javaFlags := uint32(0x301)
	if javaParent == "" {
		javaTrace = "root-trace"
		javaFlags = 0x101
	}
	return tracecheck.Snapshot{Marker: marker, Spans: []tracecheck.Span{
		{ServiceName: "apache-proxy", Kind: "CLIENT", TraceID: traceID, SpanID: "client", Flags: 0x001, Attributes: attributes},
		{ServiceName: "java-backend", Kind: "SERVER", TraceID: javaTrace, SpanID: "java", ParentSpanID: javaParent, Flags: javaFlags, Attributes: attributes},
	}}
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

func TestW3CStaleRequestUsesTheStandardParent(t *testing.T) {
	tests := []struct {
		scenario string
		w3cCase  string
	}{
		{scenario: "primary-w3c-stale", w3cCase: "valid-w3c-primary-stale"},
		{scenario: "unix-w3c-stale", w3cCase: "valid-w3c-unix-stale"},
	}

	for _, test := range tests {
		t.Run(test.scenario, func(t *testing.T) {
			cfg := config{scenario: test.scenario, seed: 42}
			requests, err := makeRequests(cfg)
			require.NoError(t, err)
			require.Len(t, requests, 1)

			requestCase := requests[0]
			assert.Equal(t, "stale", requestCase.ExpectedJavaStatus)
			assert.Equal(t, test.w3cCase, requestCase.W3CCase)
			assert.Equal(t, "01", requestCase.W3CTraceFlags)
			assert.True(t, requestCase.CloseConnection)
			assert.Equal(t, tracecheck.ModeW3C, expectationFor(cfg, requestCase).Mode)
			assert.NotEmpty(t, requestCase.W3CTraceID)
			assert.NotEmpty(t, requestCase.W3CParentSpanID)

			request, err := newHTTPRequest(
				context.Background(),
				config{baseURL: "https://example.test", scenario: test.scenario},
				requestCase,
			)
			require.NoError(t, err)
			assert.True(t, requestCase.BridgeDiagnostics)
			assert.Equal(t, "1", request.URL.Query().Get("bridge_diagnostics"))

			requestCase.BridgeDiagnostics = false
			request, err = newHTTPRequest(
				context.Background(),
				config{baseURL: "https://example.test", scenario: test.scenario},
				requestCase,
			)
			require.NoError(t, err)
			assert.Empty(t, request.URL.Query().Get("bridge_diagnostics"))

			_, err = makeRequests(config{scenario: test.scenario, requestCount: 2, seed: 42})
			require.ErrorContains(t, err, "requires exactly one request")
		})
	}
}

func TestPrimaryW3CFaultRequestUsesW3CPrecedenceAndDiagnostics(t *testing.T) {
	baseline := javaDiagnosticsSnapshot(t, 0)
	tests := []struct {
		faultMode string
		status    string
	}{
		{faultMode: "version-mismatch", status: "version_mismatch"},
		{faultMode: "bad-size", status: "malformed"},
		{faultMode: "zero-trace-id", status: "malformed"},
		{faultMode: "zero-span-id", status: "malformed"},
		{faultMode: "generation-mismatch", status: "missing"},
	}

	for _, test := range tests {
		t.Run(test.faultMode, func(t *testing.T) {
			cfg := config{
				scenario:              "primary-w3c-fault",
				faultMode:             test.faultMode,
				javaDiagnosticsBefore: baseline,
				seed:                  42,
			}
			require.NoError(t, validateFaultMode(cfg))
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
			if test.faultMode == "generation-mismatch" {
				assert.Zero(t, requestCase.DelayMillis)
				assert.Equal(t, "/api/generation-fence", requestCase.Endpoint)
				assert.Equal(t, 20_000, requestCase.GenerationFenceHoldMillis)
			} else {
				assert.Equal(t, "/api/echo", requestCase.Endpoint)
				assert.Zero(t, requestCase.DelayMillis)
				assert.Zero(t, requestCase.GenerationFenceHoldMillis)
			}
			assert.Equal(t, tracecheck.ModeW3C, expectationFor(cfg, requestCase).Mode)

			request, requestErr := newHTTPRequest(
				context.Background(),
				config{baseURL: "https://example.test", scenario: cfg.scenario},
				requestCase,
			)
			require.NoError(t, requestErr)
			assert.Equal(t, "1", request.URL.Query().Get("bridge_diagnostics"))
			assert.Equal(t, "1", request.URL.Query().Get("close"))
			if test.faultMode == "generation-mismatch" {
				assert.Equal(t, "/api/generation-fence", request.URL.Path)
				assert.Equal(t, "20000", request.URL.Query().Get("generation_fence_hold_ms"))
			} else {
				assert.Empty(t, request.URL.Query().Get("generation_fence_hold_ms"))
			}

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
	require.Len(t, javaDiagnosticsFieldNames, 54)
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
		{name: "missing", snapshot: strings.Join(fields[:len(fields)-1], ","), want: "expected 54 fields"},
		{name: "extra", snapshot: strings.Join(append(fields, "extra=0"), ","), want: "expected 54 fields"},
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

func TestJavaDiagnosticsKeepsFrameworkAndTransportMissesDistinct(t *testing.T) {
	snapshot := javaDiagnosticsSnapshotWithCounters(t, map[string]uint64{
		"framework_depth":   2,
		"framework_cycle":   3,
		"framework_late":    4,
		"transport_missing": 5,
		"t_missing":         14,
	})

	counters, err := javaDiagnosticsCounters(snapshot)
	require.NoError(t, err)
	assert.Equal(t, uint64(2), counters["framework_depth"])
	assert.Equal(t, uint64(3), counters["framework_cycle"])
	assert.Equal(t, uint64(4), counters["framework_late"])
	assert.Equal(t, uint64(5), counters["transport_missing"])
	assert.Equal(t, uint64(14), counters["t_missing"])
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

func TestStaleDiagnosticsAreExposedOnlyAtTheTopLevel(t *testing.T) {
	snapshot := javaDiagnosticsSnapshot(t, 0)
	for _, scenario := range []string{"primary-w3c-stale", "unix-w3c-stale"} {
		t.Run(scenario, func(t *testing.T) {
			var output bytes.Buffer
			require.NoError(t, encodeRunResult(&output, &runResult{
				Status:               "passed",
				Scenario:             scenario,
				JavaDiagnosticsAfter: snapshot,
				Cases: []caseResult{{
					Request: requestCase{
						Marker:            "stale",
						BridgeDiagnostics: true,
					},
					Response: backendResponse{BridgeDiagnostics: snapshot},
				}},
			}))

			assert.Contains(t, output.String(), `"java_diagnostics_after": "`+snapshot+`"`)
			assert.Equal(t, 1, strings.Count(output.String(), snapshot))
			assert.NotContains(t, output.String(), `"bridge_diagnostics"`)
		})
	}
}

func TestNonDiagnosticRequestCannotOptInToBridgeDiagnostics(t *testing.T) {
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
			count:    3,
			check: func(t *testing.T, request requestCase) {
				assert.Equal(t, "/api/tls-boundary/split", request.Endpoint)
				assert.Equal(t, "split", request.TLSBoundaryMode)
				assert.True(t, request.CloseConnection)
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

func TestTLSBoundaryRequestsAndEvidenceCoverSplitAndCoalescedPair(t *testing.T) {
	requests, err := makeRequests(config{scenario: "tls-boundary", seed: 42})
	require.NoError(t, err)
	require.Len(t, requests, 3)
	assert.Equal(t, "/api/tls-boundary/split", requests[0].Endpoint)
	assert.Equal(t, "split", requests[0].TLSBoundaryMode)
	assert.Equal(t, 1, requests[0].TLSBoundarySequence)
	assert.Equal(t, "/api/tls-boundary/coalesced", requests[1].Endpoint)
	assert.Equal(t, "coalesced", requests[1].TLSBoundaryMode)
	assert.Equal(t, 1, requests[1].TLSBoundarySequence)
	assert.Equal(t, "/api/tls-boundary/coalesced", requests[2].Endpoint)
	assert.Equal(t, "coalesced", requests[2].TLSBoundaryMode)
	assert.Equal(t, 2, requests[2].TLSBoundarySequence)
	require.ErrorContains(t, func() error {
		_, requestErr := makeRequests(config{scenario: "tls-boundary", requestCount: 2, seed: 42})
		return requestErr
	}(), "requires exactly three requests")

	for index, request := range requests {
		httpRequest, requestErr := newHTTPRequest(
			context.Background(),
			config{baseURL: "http://127.0.0.1:18080"},
			request,
		)
		require.NoError(t, requestErr)
		assert.Equal(t, http.MethodPost, httpRequest.Method)
		assert.Equal(t, request.Endpoint, httpRequest.URL.Path)
		assert.Empty(t, httpRequest.URL.RawQuery)
		assert.Equal(t, index != 1, httpRequest.Close)
		assert.EqualValues(t, tlsBoundaryBodyBytes, httpRequest.ContentLength)
		assert.Equal(t, strconv.Itoa(request.TLSBoundarySequence), httpRequest.Header.Get(tlsBoundarySequenceHeader))
		body, readErr := io.ReadAll(httpRequest.Body)
		require.NoError(t, readErr)
		assert.Len(t, body, tlsBoundaryBodyBytes)
		for index := range tlsBoundaryPaddingHeaderCount {
			assert.Len(t, httpRequest.Header.Get(fmt.Sprintf("Z-OBI-Boundary-Pad-%d", index)), tlsBoundaryPaddingHeaderValueBytes)
		}
	}

	split := backendResponse{
		BackendKind: "netty-tls-boundary",
		TLSBoundary: validTLSBoundaryEvidence("split"),
	}
	require.NoError(t, validateTLSBoundaryResponse(requests[0], split))
	require.NoError(t, validateWorkloadResponse(requests[0], split))

	coalescedPartial := backendResponse{
		BackendKind: "netty-tls-boundary",
		TLSBoundary: validPartialTLSBoundaryEvidence(),
	}
	require.NoError(t, validateTLSBoundaryResponse(requests[1], coalescedPartial))
	require.NoError(t, validateWorkloadResponse(requests[1], coalescedPartial))

	coalescedFinal := backendResponse{
		BackendKind: "netty-tls-boundary",
		TLSBoundary: validTLSBoundaryEvidence("coalesced"),
	}
	require.NoError(t, validateTLSBoundaryResponse(requests[2], coalescedFinal))
	require.NoError(t, validateWorkloadResponse(requests[2], coalescedFinal))

	coalescedFinal.BackendKind = "netty"
	assert.Error(t, validateWorkloadResponse(requests[2], coalescedFinal))
}

func TestValidateTLSBoundaryResponseRejectsEveryEvidenceInvariant(t *testing.T) {
	request := requestCase{
		Endpoint:            "/api/tls-boundary/coalesced",
		TLSBoundaryMode:     "coalesced",
		TLSBoundarySequence: 2,
	}
	tests := map[string]func(*tlsBoundaryEvidence){
		"mode":                func(e *tlsBoundaryEvidence) { e.Mode = "split" },
		"delivery shape":      func(e *tlsBoundaryEvidence) { e.DeliveryShape = tlsBoundaryDeliveryParserCoalesced },
		"evidence phase":      func(e *tlsBoundaryEvidence) { e.EvidencePhase = tlsBoundaryEvidencePartial },
		"fallback reason":     func(e *tlsBoundaryEvidence) { e.FallbackReason = "none" },
		"grace lower bound":   func(e *tlsBoundaryEvidence) { e.CoalescingGraceMillis = 0 },
		"grace upper bound":   func(e *tlsBoundaryEvidence) { e.CoalescingGraceMillis = tlsBoundaryMaxCoalescingGraceMillis + 1 },
		"grace expiration":    func(e *tlsBoundaryEvidence) { e.CoalescingGraceExpired = false },
		"verification bytes":  func(e *tlsBoundaryEvidence) { e.VerificationBufferBytes-- },
		"verification bound":  func(e *tlsBoundaryEvidence) { e.VerificationBufferLimitBytes-- },
		"verification digest": func(e *tlsBoundaryEvidence) { e.VerificationPairDigestExact = false },
		"passed":              func(e *tlsBoundaryEvidence) { e.Passed = false },
		"failure":             func(e *tlsBoundaryEvidence) { e.FailureReason = "bounded_failure" },
		"request complete":    func(e *tlsBoundaryEvidence) { e.RequestComplete = false },
		"request count":       func(e *tlsBoundaryEvidence) { e.RequestCount = 1 },
		"request header cardinality": func(e *tlsBoundaryEvidence) {
			e.RequestHeaderBytes = e.RequestHeaderBytes[:1]
		},
		"request body cardinality": func(e *tlsBoundaryEvidence) {
			e.RequestBodyBytes = e.RequestBodyBytes[:1]
		},
		"request total cardinality": func(e *tlsBoundaryEvidence) {
			e.RequestTotalBytes = e.RequestTotalBytes[:1]
		},
		"header callback cardinality": func(e *tlsBoundaryEvidence) {
			e.RequestHeaderDecryptedCallbackCounts = e.RequestHeaderDecryptedCallbackCounts[:1]
		},
		"request order":            func(e *tlsBoundaryEvidence) { e.RequestOrder = []int{2, 1} },
		"emission order":           func(e *tlsBoundaryEvidence) { e.EmissionOrder = []int{2, 1} },
		"response order":           func(e *tlsBoundaryEvidence) { e.ResponseOrder = []int{2, 1} },
		"response close order":     func(e *tlsBoundaryEvidence) { e.ResponseConnectionClose = []bool{true, true} },
		"first response keepalive": func(e *tlsBoundaryEvidence) { e.FirstResponseKeepsAlive = false },
		"wire pairs":               func(e *tlsBoundaryEvidence) { e.WireDecryptedPairsExact = false },
		"header span":              func(e *tlsBoundaryEvidence) { e.HeadersSpannedRecords = false },
		"parser shape":             func(e *tlsBoundaryEvidence) { e.ParserShapeExact = false },
		"single parser emission":   func(e *tlsBoundaryEvidence) { e.RequestsEmittedFromSingleParserCallback = true },
		"byte preservation":        func(e *tlsBoundaryEvidence) { e.RequestBytesPreserved = false },
		"split forwarding flag":    func(e *tlsBoundaryEvidence) { e.SplitBuffersForwardedUnchanged = true },
		"handoff":                  func(e *tlsBoundaryEvidence) { e.HandoffBeforeParse = false },
		"forced close":             func(e *tlsBoundaryEvidence) { e.ResponseForcesConnectionClose = false },
		"header lower bound":       func(e *tlsBoundaryEvidence) { e.RequestHeaderBytes[0] = tlsBoundaryMinHeaderBytes - 1 },
		"header upper bound":       func(e *tlsBoundaryEvidence) { e.RequestHeaderBytes[0] = tlsBoundaryMaxHeaderBytes + 1 },
		"body size":                func(e *tlsBoundaryEvidence) { e.RequestBodyBytes[0]-- },
		"request byte equation":    func(e *tlsBoundaryEvidence) { e.RequestTotalBytes[0]++ },
		"callback lower bound":     func(e *tlsBoundaryEvidence) { setTLSBoundaryCallbacks(e, []int{e.DecryptedTotalBytes}) },
		"callback upper bound":     func(e *tlsBoundaryEvidence) { setTLSBoundaryCallbacks(e, make([]int, tlsBoundaryMaxCallbacks+1)) },
		"record version count": func(e *tlsBoundaryEvidence) {
			e.TLSApplicationRecordLegacyVersions = e.TLSApplicationRecordLegacyVersions[:6]
		},
		"record payload count": func(e *tlsBoundaryEvidence) {
			e.TLSApplicationRecordPayloadLengths = e.TLSApplicationRecordPayloadLengths[:6]
		},
		"plaintext lower bound": func(e *tlsBoundaryEvidence) { e.DecryptedCallbackLengths[0] = 0 },
		"plaintext upper bound": func(e *tlsBoundaryEvidence) { e.DecryptedCallbackLengths[0] = tlsBoundaryMaxPlaintextRecordBytes + 1 },
		"legacy version":        func(e *tlsBoundaryEvidence) { e.TLSApplicationRecordLegacyVersions[0] = 0x0302 },
		"record no overhead":    func(e *tlsBoundaryEvidence) { e.TLSApplicationRecordPayloadLengths[0] = e.DecryptedCallbackLengths[0] },
		"record excess overhead": func(e *tlsBoundaryEvidence) {
			e.TLSApplicationRecordPayloadLengths[0] = e.DecryptedCallbackLengths[0] + tlsBoundaryMaxRecordOverhead + 1
		},
		"record payload maximum": func(e *tlsBoundaryEvidence) {
			e.TLSApplicationRecordPayloadLengths[0] = tlsBoundaryMaxRecordPayload + 1
		},
		"decrypted byte total": func(e *tlsBoundaryEvidence) { e.DecryptedCallbackLengths[6]-- },
		"reported decrypted total": func(e *tlsBoundaryEvidence) {
			e.DecryptedTotalBytes--
		},
		"parser byte total":     func(e *tlsBoundaryEvidence) { e.ParserCallbackLengths[0]-- },
		"reported parser total": func(e *tlsBoundaryEvidence) { e.ParserTotalBytes-- },
		"reported parser count": func(e *tlsBoundaryEvidence) { e.ParserCallbackCount = 1 },
		"header callback lower": func(e *tlsBoundaryEvidence) { e.RequestHeaderDecryptedCallbackCounts[0] = 1 },
		"header callback mismatch": func(e *tlsBoundaryEvidence) {
			e.RequestHeaderDecryptedCallbackCounts[1]++
		},
		"parser facing flag": func(e *tlsBoundaryEvidence) { e.ParserFacingCoalesced = true },
		"serialized parser count": func(e *tlsBoundaryEvidence) {
			e.ParserCallbackLengths = []int{e.ParserTotalBytes}
			e.ParserCallbackCount = 1
		},
		"serialized parser bytes": func(e *tlsBoundaryEvidence) { e.ParserCallbackLengths[0]-- },
		"serialized emission order": func(e *tlsBoundaryEvidence) {
			e.EmissionParserCallbackOrder = []int{1, 1}
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			evidence := validTLSBoundaryEvidence("coalesced")
			mutate(evidence)
			assert.Error(t, validateTLSBoundaryResponse(request, backendResponse{TLSBoundary: evidence}))
		})
	}

	require.Error(t, validateTLSBoundaryResponse(request, backendResponse{}))
	unknown := validTLSBoundaryEvidence("coalesced")
	request.TLSBoundaryMode = "approximate"
	unknown.Mode = "approximate"
	require.Error(t, validateTLSBoundaryResponse(request, backendResponse{TLSBoundary: unknown}))
	request.TLSBoundaryMode = "coalesced"
	request.TLSBoundarySequence = 3
	assert.Error(t, validateTLSBoundaryResponse(request, backendResponse{TLSBoundary: validTLSBoundaryEvidence("coalesced")}))
}

func TestValidateTLSBoundaryResponseRequiresTruthfulPartialFallback(t *testing.T) {
	request := requestCase{
		Endpoint:            "/api/tls-boundary/coalesced",
		TLSBoundaryMode:     "coalesced",
		TLSBoundarySequence: 1,
	}
	tests := map[string]func(*tlsBoundaryEvidence){
		"delivery shape":      func(e *tlsBoundaryEvidence) { e.DeliveryShape = tlsBoundaryDeliveryParserCoalesced },
		"evidence phase":      func(e *tlsBoundaryEvidence) { e.EvidencePhase = tlsBoundaryEvidenceFinal },
		"fallback reason":     func(e *tlsBoundaryEvidence) { e.FallbackReason = "none" },
		"grace":               func(e *tlsBoundaryEvidence) { e.CoalescingGraceMillis = 0 },
		"grace expiration":    func(e *tlsBoundaryEvidence) { e.CoalescingGraceExpired = false },
		"passed":              func(e *tlsBoundaryEvidence) { e.Passed = true },
		"request complete":    func(e *tlsBoundaryEvidence) { e.RequestComplete = true },
		"request count":       func(e *tlsBoundaryEvidence) { e.RequestCount = 2 },
		"request order":       func(e *tlsBoundaryEvidence) { e.RequestOrder = []int{1, 2} },
		"parser order":        func(e *tlsBoundaryEvidence) { e.EmissionParserCallbackOrder = []int{1, 2} },
		"response order":      func(e *tlsBoundaryEvidence) { e.ResponseOrder = []int{1, 2} },
		"response close":      func(e *tlsBoundaryEvidence) { e.ResponseConnectionClose = []bool{false, true} },
		"parser facing":       func(e *tlsBoundaryEvidence) { e.ParserFacingCoalesced = true },
		"single parser":       func(e *tlsBoundaryEvidence) { e.RequestsEmittedFromSingleParserCallback = true },
		"byte preservation":   func(e *tlsBoundaryEvidence) { e.RequestBytesPreserved = true },
		"split forwarding":    func(e *tlsBoundaryEvidence) { e.SplitBuffersForwardedUnchanged = true },
		"forced close":        func(e *tlsBoundaryEvidence) { e.ResponseForcesConnectionClose = true },
		"verification bytes":  func(e *tlsBoundaryEvidence) { e.VerificationBufferBytes-- },
		"verification limit":  func(e *tlsBoundaryEvidence) { e.VerificationBufferLimitBytes-- },
		"verification digest": func(e *tlsBoundaryEvidence) { e.VerificationPairDigestExact = true },
		"parser bytes":        func(e *tlsBoundaryEvidence) { e.ParserCallbackLengths[0]-- },
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			evidence := validPartialTLSBoundaryEvidence()
			mutate(evidence)
			assert.Error(t, validateTLSBoundaryResponse(request, backendResponse{TLSBoundary: evidence}))
		})
	}
	require.NoError(t, validateTLSBoundaryResponse(
		request,
		backendResponse{TLSBoundary: validPartialTLSBoundaryEvidence()},
	))
}

func TestSerializedTLSBoundaryFinalEvidenceMonotonicallyExtendsPartial(t *testing.T) {
	require.NoError(t, validateSerializedTLSBoundaryExtension(
		validPartialTLSBoundaryEvidence(),
		validTLSBoundaryEvidence("coalesced"),
	))

	tests := map[string]func(*tlsBoundaryEvidence, *tlsBoundaryEvidence){
		"configuration": func(_ *tlsBoundaryEvidence, final *tlsBoundaryEvidence) {
			final.CoalescingGraceMillis++
		},
		"phase": func(partial *tlsBoundaryEvidence, _ *tlsBoundaryEvidence) {
			partial.EvidencePhase = tlsBoundaryEvidenceFinal
		},
		"request prefix": func(_ *tlsBoundaryEvidence, final *tlsBoundaryEvidence) {
			final.RequestHeaderBytes[0]++
		},
		"record prefix": func(_ *tlsBoundaryEvidence, final *tlsBoundaryEvidence) {
			final.TLSApplicationRecordPayloadLengths[0]++
		},
		"parser prefix": func(_ *tlsBoundaryEvidence, final *tlsBoundaryEvidence) {
			final.ParserCallbackLengths[0]++
		},
		"close prefix": func(_ *tlsBoundaryEvidence, final *tlsBoundaryEvidence) {
			final.ResponseConnectionClose[0] = true
		},
		"decrypted growth": func(partial *tlsBoundaryEvidence, final *tlsBoundaryEvidence) {
			final.DecryptedTotalBytes = partial.DecryptedTotalBytes
		},
		"parser growth": func(partial *tlsBoundaryEvidence, final *tlsBoundaryEvidence) {
			final.ParserTotalBytes = partial.ParserTotalBytes
		},
		"verification growth": func(partial *tlsBoundaryEvidence, final *tlsBoundaryEvidence) {
			final.VerificationBufferBytes = partial.VerificationBufferBytes
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			partial := validPartialTLSBoundaryEvidence()
			final := validTLSBoundaryEvidence("coalesced")
			mutate(partial, final)
			assert.Error(t, validateSerializedTLSBoundaryExtension(partial, final))
		})
	}
}

func TestValidateTLSBoundaryResponseRejectsInvalidSplitShape(t *testing.T) {
	request := requestCase{
		Endpoint:            "/api/tls-boundary/split",
		TLSBoundaryMode:     "split",
		TLSBoundarySequence: 1,
	}
	tests := map[string]func(*tlsBoundaryEvidence){
		"coalesced flag":          func(e *tlsBoundaryEvidence) { e.ParserFacingCoalesced = true },
		"changed buffers":         func(e *tlsBoundaryEvidence) { e.SplitBuffersForwardedUnchanged = false },
		"parser callback lengths": func(e *tlsBoundaryEvidence) { e.ParserCallbackLengths[0]-- },
		"parser callback count":   func(e *tlsBoundaryEvidence) { e.ParserCallbackCount-- },
		"emission parser order":   func(e *tlsBoundaryEvidence) { e.EmissionParserCallbackOrder = []int{1} },
		"response close order":    func(e *tlsBoundaryEvidence) { e.ResponseConnectionClose = []bool{false} },
		"first response keepalive": func(e *tlsBoundaryEvidence) {
			e.FirstResponseKeepsAlive = true
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			evidence := validTLSBoundaryEvidence("split")
			mutate(evidence)
			assert.Error(t, validateTLSBoundaryResponse(request, backendResponse{TLSBoundary: evidence}))
		})
	}
	request.TLSBoundarySequence = 2
	assert.Error(t, validateTLSBoundaryResponse(request, backendResponse{TLSBoundary: validTLSBoundaryEvidence("split")}))
}

func TestValidateTLSBoundaryResponseAcceptsDeferredSplitEmissionCallback(t *testing.T) {
	request := requestCase{
		Endpoint:            "/api/tls-boundary/split",
		TLSBoundaryMode:     "split",
		TLSBoundarySequence: 1,
	}
	evidence := validTLSBoundaryEvidence("split")
	evidence.EmissionParserCallbackOrder = []int{3}
	require.Equal(t, []int{2}, evidence.RequestHeaderDecryptedCallbackCounts)
	require.Equal(t, 4, evidence.ParserCallbackCount)
	require.NoError(t, validateTLSBoundaryResponse(
		request,
		backendResponse{TLSBoundary: evidence},
	))
}

func TestValidateTLSBoundaryResponseRejectsInvalidSplitEmissionCallback(t *testing.T) {
	request := requestCase{
		Endpoint:            "/api/tls-boundary/split",
		TLSBoundaryMode:     "split",
		TLSBoundarySequence: 1,
	}
	tests := []struct {
		name      string
		order     []int
		wantError string
	}{
		{name: "too early", order: []int{1}, wantError: "before its headers completed"},
		{name: "out of range lower", order: []int{0}, wantError: "out of range"},
		{name: "out of range upper", order: []int{5}, wantError: "out of range"},
		{name: "cardinality mismatch", order: []int{2, 2}, wantError: "cardinality does not match"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			evidence := validTLSBoundaryEvidence("split")
			evidence.EmissionParserCallbackOrder = test.order
			err := validateTLSBoundaryResponse(request, backendResponse{TLSBoundary: evidence})
			assert.ErrorContains(t, err, test.wantError)
		})
	}
}

func validTLSBoundaryEvidence(mode string) *tlsBoundaryEvidence {
	headerBytes := []int{18_100}
	requestBytes := []int{headerBytes[0] + tlsBoundaryBodyBytes}
	decrypted := []int{16_384, 16_384, 16_384, requestBytes[0] - 3*16_384}
	requestOrder := []int{1}
	responseClose := []bool{true}
	evidence := &tlsBoundaryEvidence{
		Mode:                                    mode,
		DeliveryShape:                           tlsBoundaryDeliverySplit,
		EvidencePhase:                           tlsBoundaryEvidenceFinal,
		FallbackReason:                          "none",
		Passed:                                  true,
		FailureReason:                           "none",
		RequestComplete:                         true,
		RequestCount:                            1,
		RequestHeaderBytes:                      headerBytes,
		RequestBodyBytes:                        []int{tlsBoundaryBodyBytes},
		RequestTotalBytes:                       requestBytes,
		RequestHeaderDecryptedCallbackCounts:    []int{2},
		RequestOrder:                            requestOrder,
		EmissionOrder:                           append([]int(nil), requestOrder...),
		EmissionParserCallbackOrder:             []int{2},
		ResponseOrder:                           append([]int(nil), requestOrder...),
		ResponseConnectionClose:                 responseClose,
		DecryptedCallbackLengths:                append([]int(nil), decrypted...),
		ParserCallbackLengths:                   append([]int(nil), decrypted...),
		DecryptedTotalBytes:                     sumInts(decrypted),
		ParserTotalBytes:                        sumInts(decrypted),
		ParserCallbackCount:                     len(decrypted),
		WireDecryptedPairsExact:                 true,
		HeadersSpannedRecords:                   true,
		ParserShapeExact:                        true,
		RequestsEmittedFromSingleParserCallback: true,
		RequestBytesPreserved:                   true,
		SplitBuffersForwardedUnchanged:          true,
		HandoffBeforeParse:                      true,
		ResponseForcesConnectionClose:           true,
	}
	if mode == "coalesced" {
		evidence.DeliveryShape = tlsBoundaryDeliverySerializedFallback
		evidence.FallbackReason = tlsBoundaryFallbackGraceExpired
		evidence.CoalescingGraceMillis = 150
		evidence.CoalescingGraceExpired = true
		evidence.VerificationBufferLimitBytes = tlsBoundaryMaxPairBytes
		evidence.RequestCount = 2
		evidence.RequestHeaderBytes = []int{18_100, 18_120}
		evidence.RequestBodyBytes = []int{tlsBoundaryBodyBytes, tlsBoundaryBodyBytes}
		evidence.RequestTotalBytes = []int{
			evidence.RequestHeaderBytes[0] + tlsBoundaryBodyBytes,
			evidence.RequestHeaderBytes[1] + tlsBoundaryBodyBytes,
		}
		firstCallbacks := []int{16_384, 16_384, 16_384, evidence.RequestTotalBytes[0] - 3*16_384}
		secondCallbacks := []int{16_384, 16_384, 16_384, evidence.RequestTotalBytes[1] - 3*16_384}
		decrypted = append([]int(nil), firstCallbacks...)
		decrypted = append(decrypted, secondCallbacks...)
		totalBytes := sumInts(evidence.RequestTotalBytes)
		evidence.RequestHeaderDecryptedCallbackCounts = []int{2, 2}
		evidence.RequestOrder = []int{1, 2}
		evidence.EmissionOrder = []int{1, 2}
		evidence.EmissionParserCallbackOrder = []int{1, 2}
		evidence.ResponseOrder = []int{1, 2}
		evidence.ResponseConnectionClose = []bool{false, true}
		evidence.DecryptedCallbackLengths = append([]int(nil), decrypted...)
		evidence.ParserCallbackLengths = append([]int(nil), evidence.RequestTotalBytes...)
		evidence.DecryptedTotalBytes = totalBytes
		evidence.ParserTotalBytes = totalBytes
		evidence.ParserCallbackCount = 2
		evidence.VerificationBufferBytes = totalBytes
		evidence.VerificationPairDigestExact = true
		evidence.RequestsEmittedFromSingleParserCallback = false
		evidence.SplitBuffersForwardedUnchanged = false
		evidence.FirstResponseKeepsAlive = true
	}
	setTLSBoundaryRecordEvidence(evidence)
	return evidence
}

func validPartialTLSBoundaryEvidence() *tlsBoundaryEvidence {
	evidence := validTLSBoundaryEvidence("coalesced")
	evidence.EvidencePhase = tlsBoundaryEvidencePartial
	evidence.Passed = false
	evidence.RequestComplete = false
	evidence.RequestCount = 1
	evidence.RequestHeaderBytes = evidence.RequestHeaderBytes[:1]
	evidence.RequestBodyBytes = evidence.RequestBodyBytes[:1]
	evidence.RequestTotalBytes = evidence.RequestTotalBytes[:1]
	evidence.RequestHeaderDecryptedCallbackCounts = evidence.RequestHeaderDecryptedCallbackCounts[:1]
	evidence.RequestOrder = []int{1}
	evidence.EmissionOrder = []int{1}
	evidence.EmissionParserCallbackOrder = []int{1}
	evidence.ResponseOrder = []int{1}
	evidence.ResponseConnectionClose = []bool{false}
	evidence.DecryptedCallbackLengths = evidence.DecryptedCallbackLengths[:4]
	evidence.ParserCallbackLengths = evidence.ParserCallbackLengths[:1]
	evidence.DecryptedTotalBytes = evidence.RequestTotalBytes[0]
	evidence.ParserTotalBytes = evidence.RequestTotalBytes[0]
	evidence.ParserCallbackCount = 1
	evidence.VerificationBufferBytes = evidence.RequestTotalBytes[0]
	evidence.VerificationPairDigestExact = false
	evidence.RequestBytesPreserved = false
	evidence.ResponseForcesConnectionClose = false
	setTLSBoundaryRecordEvidence(evidence)
	return evidence
}

func setTLSBoundaryCallbacks(evidence *tlsBoundaryEvidence, lengths []int) {
	evidence.DecryptedCallbackLengths = append([]int(nil), lengths...)
	setTLSBoundaryRecordEvidence(evidence)
}

func setTLSBoundaryRecordEvidence(evidence *tlsBoundaryEvidence) {
	lengths := evidence.DecryptedCallbackLengths
	evidence.TLSApplicationRecordLegacyVersions = make([]int, len(lengths))
	evidence.TLSApplicationRecordPayloadLengths = make([]int, len(lengths))
	for index, length := range lengths {
		evidence.TLSApplicationRecordLegacyVersions[index] = 0x0303
		evidence.TLSApplicationRecordPayloadLengths[index] = length + 17
	}
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

func TestSendSequentialRequestsReadsFirstResponseBeforeSecondWrite(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	cfg := config{
		baseURL:        "http://" + listener.Addr().String(),
		scenario:       "tls-boundary",
		seed:           42,
		expectedTLS:    "TLSv1.3",
		requestTimeout: 2 * time.Second,
	}
	requests, err := makeRequests(cfg)
	require.NoError(t, err)

	serverErr := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		defer connection.Close()
		reader := bufio.NewReader(connection)
		for index, requestCase := range requests[1:] {
			request, readErr := http.ReadRequest(reader)
			if readErr != nil {
				serverErr <- fmt.Errorf("read request %d: %w", index, readErr)
				return
			}
			body, bodyErr := io.ReadAll(request.Body)
			if bodyErr != nil {
				serverErr <- fmt.Errorf("read request %d body: %w", index, bodyErr)
				return
			}
			if request.Method != http.MethodPost || request.URL.Path != requestCase.Endpoint ||
				request.Header.Get(tlsBoundarySequenceHeader) != strconv.Itoa(index+1) ||
				request.Close != (index == 1) || len(body) != tlsBoundaryBodyBytes {
				serverErr <- fmt.Errorf("unexpected sequential request %d: method=%s path=%s sequence=%s close=%t body=%d", index, request.Method, request.URL.Path, request.Header.Get(tlsBoundarySequenceHeader), request.Close, len(body))
				return
			}
			if index == 0 {
				if deadlineErr := connection.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); deadlineErr != nil {
					serverErr <- deadlineErr
					return
				}
				if _, peekErr := reader.Peek(1); peekErr == nil {
					serverErr <- errors.New("second request arrived before the first response")
					return
				} else {
					var networkErr net.Error
					if !errors.As(peekErr, &networkErr) || !networkErr.Timeout() {
						serverErr <- fmt.Errorf("wait for premature second request: %w", peekErr)
						return
					}
				}
				if deadlineErr := connection.SetReadDeadline(time.Time{}); deadlineErr != nil {
					serverErr <- deadlineErr
					return
				}
			}

			evidence := validTLSBoundaryEvidence("coalesced")
			if index == 0 {
				evidence = validPartialTLSBoundaryEvidence()
			}
			responseBody, marshalErr := json.Marshal(backendResponse{
				Marker:              requestCase.Marker,
				Secure:              true,
				BackendKind:         "netty-tls-boundary",
				Protocol:            "HTTP/1.1",
				TLSProtocol:         cfg.expectedTLS,
				TLSCipher:           "TLS_AES_128_GCM_SHA256",
				BackendConnectionID: 7,
				BackendRemotePort:   41000,
				TLSBoundary:         evidence,
			})
			if marshalErr != nil {
				serverErr <- marshalErr
				return
			}
			response := &http.Response{
				StatusCode:    http.StatusOK,
				ProtoMajor:    1,
				ProtoMinor:    1,
				Header:        make(http.Header),
				Body:          io.NopCloser(bytes.NewReader(responseBody)),
				ContentLength: int64(len(responseBody)),
				Close:         index == 1,
			}
			if writeErr := response.Write(connection); writeErr != nil {
				serverErr <- fmt.Errorf("write response %d: %w", index, writeErr)
				return
			}
		}
		serverErr <- nil
	}()

	responses, latencies, evidence, err := sendSequentialRequests(
		context.Background(),
		cfg,
		requests[1:],
	)
	require.NoError(t, err)
	require.NoError(t, <-serverErr)
	require.Len(t, responses, 2)
	require.Len(t, latencies, 2)
	assert.Equal(t, 1, evidence.FrontendConnections)
	assert.Equal(t, 2, evidence.SequentialRequests)
	assert.Equal(t, 1, evidence.ResponsesReadBeforeNextWrite)
	assert.Zero(t, evidence.PipelinedRequests)
	assert.Zero(t, evidence.RequestsWrittenBeforeFirstRead)
}

func TestTLSBoundaryConnectionShapeRequiresOneCoalescedBackendConnection(t *testing.T) {
	partialEvidence := validPartialTLSBoundaryEvidence()
	finalEvidence := validTLSBoundaryEvidence("coalesced")
	responses := []backendResponse{
		{
			BackendConnectionID: 1,
			BackendRemotePort:   41001,
			TLSProtocol:         "TLSv1.3",
			TLSCipher:           "TLS_AES_256_GCM_SHA384",
			TLSBoundary:         validTLSBoundaryEvidence("split"),
		},
		{
			BackendConnectionID: 2,
			BackendRemotePort:   41001,
			TLSProtocol:         "TLSv1.3",
			TLSCipher:           "TLS_AES_256_GCM_SHA384",
			TLSBoundary:         partialEvidence,
		},
		{
			BackendConnectionID: 2,
			BackendRemotePort:   41001,
			TLSProtocol:         "TLSv1.3",
			TLSCipher:           "TLS_AES_256_GCM_SHA384",
			TLSBoundary:         finalEvidence,
		},
	}
	evidence := &connectionEvidence{
		FrontendConnections:          2,
		FrontendProtocol:             "HTTP/1.1",
		SequentialRequests:           2,
		ResponsesReadBeforeNextWrite: 1,
	}
	require.NoError(t, validateConnectionShape("tls-boundary", responses, evidence))

	for name, mutate := range map[string]func([]backendResponse, *connectionEvidence){
		"frontend evidence": func(_ []backendResponse, value *connectionEvidence) {
			value.ResponsesReadBeforeNextWrite = 0
		},
		"backend connection": func(value []backendResponse, _ *connectionEvidence) {
			value[2].BackendConnectionID = 3
		},
		"backend remote port": func(value []backendResponse, _ *connectionEvidence) {
			value[2].BackendRemotePort++
		},
		"backend TLS protocol": func(value []backendResponse, _ *connectionEvidence) {
			value[2].TLSProtocol = "TLSv1.2"
		},
		"final evidence": func(value []backendResponse, _ *connectionEvidence) {
			changed := *value[2].TLSBoundary
			changed.Passed = false
			value[2].TLSBoundary = &changed
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidateResponses := append([]backendResponse(nil), responses...)
			candidateEvidence := *evidence
			mutate(candidateResponses, &candidateEvidence)
			assert.Error(t, validateConnectionShape(
				"tls-boundary",
				candidateResponses,
				&candidateEvidence,
			))
		})
	}
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
		{BackendConnectionID: 1, BackendRemotePort: 41000, BackendWorkerID: 1, ConcurrencyArrival: 1, ConcurrencyParticipants: 2, ConcurrencyMaxActive: 2, ConcurrencyRelease: 1},
		{BackendConnectionID: 2, BackendRemotePort: 41000, BackendWorkerID: 2, ConcurrencyArrival: 2, ConcurrencyParticipants: 2, ConcurrencyMaxActive: 2, ConcurrencyRelease: 1},
	}
	require.NoError(t, validateConnectionShape("connection-churn", churn, nil))
	require.NoError(t, validateConnectionShape("concurrency", churn, &connectionEvidence{
		DistinctBackendWorkers:      2,
		DistinctConcurrencyArrivals: 2,
		ConcurrencyParticipants:     2,
		ConcurrencyMaxActive:        2,
		ConcurrencyRelease:          1,
	}))

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
