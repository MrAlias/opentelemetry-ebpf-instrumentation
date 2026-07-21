// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

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

func TestW3CMatchUsesInjectedHeadersWithoutClientContext(t *testing.T) {
	requests, err := makeRequests(config{scenario: "w3c-match", seed: 42})
	require.NoError(t, err)
	require.Len(t, requests, 1)

	assert.Equal(t, "matching-w3c-and-obi", requests[0].W3CCase)
	assert.Empty(t, requests[0].W3CTraceID)
	assert.Equal(t, tracecheck.ModeW3CMatch, expectationFor(
		config{scenario: "w3c-match"},
		requests[0],
	).Mode)
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

func TestW3CFaultRequestsAreValidStandardParents(t *testing.T) {
	requests, err := makeRequests(config{scenario: "w3c-fault", seed: 42})
	require.NoError(t, err)
	require.Len(t, requests, 2)

	assert.Equal(t, "valid-w3c-stale-obi", requests[0].W3CCase)
	assert.Equal(t, "valid-w3c-malformed-obi", requests[1].W3CCase)
	assert.Equal(t, tracecheck.ModeW3CNoOBI, expectationFor(
		config{scenario: "w3c-fault"},
		requests[0],
	).Mode)
}

func TestRestartFaultRequestsUseStandardParents(t *testing.T) {
	requests, err := makeRequests(config{scenario: "restart-fault", seed: 42})
	require.NoError(t, err)
	require.Len(t, requests, 32)

	for _, request := range requests {
		assert.NotEmpty(t, request.W3CTraceID)
		assert.NotEmpty(t, request.W3CParentSpanID)
		assert.Equal(t, 75, request.DelayMillis)
		assert.Equal(t, tracecheck.ModeW3CResilience, expectationFor(
			config{scenario: "restart-fault"},
			request,
		).Mode)
	}
}

func TestStressScenarioRequestsHaveBoundedShapes(t *testing.T) {
	tests := []struct {
		scenario string
		count    int
		check    func(*testing.T, requestCase)
	}{
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
				assert.Equal(t, 4096, request.SlowBodyBytes)
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
	_, err := makeRequests(config{scenario: "pipelining", requestCount: 1, seed: 1})
	require.Error(t, err)

	_, err = makeRequests(config{scenario: "fd-port-reuse", requestCount: 1, seed: 1})
	require.Error(t, err)
}

func TestPacedReaderEmitsExactlyTheConfiguredBody(t *testing.T) {
	reader := &pacedReader{remaining: 129, chunkSize: 64}
	body, err := io.ReadAll(reader)

	require.NoError(t, err)
	assert.Len(t, body, 129)
	assert.Zero(t, reader.remaining)
}

func TestNettyRequestsCoverCancelledAndUncancelledWork(t *testing.T) {
	requests, err := makeRequests(config{scenario: "netty", seed: 1})
	require.NoError(t, err)

	assert.False(t, requests[0].NettyCancel)
	assert.True(t, requests[1].NettyCancel)
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
	keepalive := []backendResponse{
		{BackendConnectionID: 1, BackendRemotePort: 41000},
		{BackendConnectionID: 1, BackendRemotePort: 41001},
	}
	require.NoError(t, validateConnectionShape("keepalive", keepalive, nil))

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
}
