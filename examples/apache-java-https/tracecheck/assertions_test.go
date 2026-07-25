// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracecheck

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testMarker          = "trace-flags"
	testEndpoint        = "/api/echo"
	testTraceID         = "00112233445566778899aabbccddeeff"
	testExternalSpanID  = "0011223344556677"
	testApacheServerID  = "1122334455667788"
	testProcessingID    = "1a2b3c4d5e6f7081"
	testApacheClientID  = "2233445566778899"
	testJavaServerID    = "33445566778899aa"
	testRemoteSpanFlags = uint32(0x301)
)

func TestAssertSnapshotRequiresExactBridgeTraceFlags(t *testing.T) {
	snapshot := bridgeSnapshot(testRemoteSpanFlags)
	snapshot.Spans[0].ParentSpanID = ""
	expectation := Expectation{
		Mode:          ModeBridge,
		ApacheService: "apache",
		JavaService:   "java",
		Endpoint:      testEndpoint,
		Marker:        testMarker,
	}

	require.NoError(t, AssertSnapshot(snapshot, expectation))
	snapshot.Spans[2].Flags = 0x300
	assert.ErrorContains(t, AssertSnapshot(snapshot, expectation), "match Apache candidate flags")
}

func TestAssertSnapshotPressureClassifiesOnlyExplicitRootsAsMisses(t *testing.T) {
	expectation := Expectation{
		Mode:          ModePressure,
		ApacheService: "apache",
		JavaService:   "java",
		Endpoint:      testEndpoint,
		Marker:        testMarker,
	}

	exact := bridgeSnapshot(testRemoteSpanFlags)
	exact.Spans[0].ParentSpanID = ""
	require.NoError(t, AssertSnapshot(exact, expectation))
	exactOutcome, err := ClassifyPressureParent(exact, expectation)
	require.NoError(t, err)
	assert.Equal(t, PressureParentExactHit, exactOutcome)

	missing := bridgeSnapshot(testRemoteSpanFlags)
	missing.Spans[0].ParentSpanID = ""
	missing.Spans[2].TraceID = "ffeeddccbbaa99887766554433221100"
	missing.Spans[2].ParentSpanID = ""
	missing.Spans[2].Flags = 0x103
	require.NoError(t, AssertSnapshot(missing, expectation))
	missingOutcome, err := ClassifyPressureParent(missing, expectation)
	require.NoError(t, err)
	assert.Equal(t, PressureParentExplicitRoot, missingOutcome)

	bridgeExpectation := expectation
	bridgeExpectation.Mode = ModeBridge
	require.Error(t, AssertSnapshot(missing, bridgeExpectation))

	sharedTraceRoot := missing
	sharedTraceRoot.Spans = append([]Span(nil), missing.Spans...)
	sharedTraceRoot.Spans[2].TraceID = testTraceID
	require.ErrorContains(t, AssertSnapshot(sharedTraceRoot, expectation), "distinct from Apache candidate trace")
	sharedOutcome, err := ClassifyPressureParent(sharedTraceRoot, expectation)
	require.Error(t, err)
	assert.Equal(t, PressureParentWrong, sharedOutcome)

	remoteRoot := missing
	remoteRoot.Spans = append([]Span(nil), missing.Spans...)
	remoteRoot.Spans[2].Flags = testRemoteSpanFlags
	require.ErrorContains(t, AssertSnapshot(remoteRoot, expectation), "root to be local")
	remoteOutcome, err := ClassifyPressureParent(remoteRoot, expectation)
	require.Error(t, err)
	assert.Equal(t, PressureParentWrong, remoteOutcome)

	wrong := bridgeSnapshot(testRemoteSpanFlags)
	wrong.Spans[0].ParentSpanID = ""
	wrong.Spans[2].ParentSpanID = testExternalSpanID
	require.ErrorContains(t, AssertSnapshot(wrong, expectation), "identify Apache client span")
	wrongOutcome, err := ClassifyPressureParent(wrong, expectation)
	require.Error(t, err)
	assert.Equal(t, PressureParentWrong, wrongOutcome)

	unresolved := exact
	unresolved.Spans = append([]Span(nil), exact.Spans...)
	unresolved.Spans = unresolved.Spans[:2]
	unresolvedOutcome, err := ClassifyPressureParent(unresolved, expectation)
	require.Error(t, err)
	assert.Equal(t, PressureParentUnresolved, unresolvedOutcome)
}

func TestAssertSnapshotRejectsAdditionalBridgeCandidate(t *testing.T) {
	snapshot := bridgeSnapshot(testRemoteSpanFlags)
	snapshot.Spans[0].ParentSpanID = ""
	extra := snapshot.Spans[1]
	extra.SpanID = "445566778899aabb"
	snapshot.Spans = append(snapshot.Spans, extra)
	expectation := Expectation{
		Mode:          ModeBridge,
		ApacheService: "apache",
		JavaService:   "java",
		Endpoint:      testEndpoint,
		Marker:        testMarker,
	}

	assert.ErrorContains(t, AssertSnapshot(snapshot, expectation), "exactly one Apache client candidate")
}

func TestAssertSnapshotRejectsConflictingBridgeCandidateMarker(t *testing.T) {
	snapshot := bridgeSnapshot(testRemoteSpanFlags)
	snapshot.Spans[0].ParentSpanID = ""
	snapshot.Spans[1].Attributes["http.request.header.x-obi-demo-id"] = "other-request"
	expectation := Expectation{
		Mode:          ModeBridge,
		ApacheService: "apache",
		JavaService:   "java",
		Endpoint:      testEndpoint,
		Marker:        testMarker,
	}

	assert.ErrorContains(t, AssertSnapshot(snapshot, expectation), "exactly one Apache client candidate")
}

func TestAssertSnapshotRequiresBridgeCandidateMarker(t *testing.T) {
	snapshot := bridgeSnapshot(testRemoteSpanFlags)
	snapshot.Spans[0].ParentSpanID = ""
	delete(snapshot.Spans[1].Attributes, "http.request.header.x-obi-demo-id")
	expectation := Expectation{
		Mode:          ModeBridge,
		ApacheService: "apache",
		JavaService:   "java",
		Endpoint:      testEndpoint,
		Marker:        testMarker,
	}

	assert.ErrorContains(t, AssertSnapshot(snapshot, expectation), "exactly one Apache client candidate")
}

func TestAssertSnapshotRequiresApacheRootWithoutValidW3C(t *testing.T) {
	snapshot := bridgeSnapshot(testRemoteSpanFlags)
	snapshot.Spans[0].ParentSpanID = ""
	expectation := Expectation{
		Mode:          ModeBridge,
		ApacheService: "apache",
		JavaService:   "java",
		Endpoint:      testEndpoint,
		Marker:        testMarker,
	}

	require.NoError(t, AssertSnapshot(snapshot, expectation))
	snapshot.Spans[0].ParentSpanID = testExternalSpanID
	assert.ErrorContains(t, AssertSnapshot(snapshot, expectation), "without valid W3C context to be a root")
}

func TestAssertSnapshotRequiresW3CCandidateGraphAndFlags(t *testing.T) {
	snapshot := bridgeSnapshot(testRemoteSpanFlags)
	snapshot.Spans[2].ParentSpanID = testExternalSpanID
	expectation := Expectation{
		Mode:            ModeW3C,
		ApacheService:   "apache",
		JavaService:     "java",
		Endpoint:        testEndpoint,
		Marker:          testMarker,
		W3CTraceID:      testTraceID,
		W3CParentSpanID: testExternalSpanID,
		W3CTraceFlags:   "01",
	}

	require.NoError(t, AssertSnapshot(snapshot, expectation))
	snapshot.Spans[1].ParentSpanID = testExternalSpanID
	require.ErrorContains(t, AssertSnapshot(snapshot, expectation), "descend from Apache inbound span")

	snapshot = bridgeSnapshot(testRemoteSpanFlags)
	snapshot.Spans[2].ParentSpanID = testExternalSpanID
	snapshot.Spans[1].Flags = 0x300
	assert.ErrorContains(t, AssertSnapshot(snapshot, expectation), "candidate span: expected trace flags 01")
}

func TestAssertSnapshotHelperAttachFailureRequiresLocalJavaRoot(t *testing.T) {
	expectation := Expectation{
		Mode:          ModeHelperAttachFailure,
		ApacheService: "apache",
		JavaService:   "java",
		Endpoint:      testEndpoint,
		Marker:        testMarker,
	}
	snapshot := bridgeSnapshot(testRemoteSpanFlags)
	snapshot.Spans[0].ParentSpanID = ""
	snapshot.Spans[2].TraceID = "ffeeddccbbaa99887766554433221100"
	snapshot.Spans[2].ParentSpanID = ""
	snapshot.Spans[2].Flags = 0x101

	require.NoError(t, AssertSnapshot(snapshot, expectation))

	withBridgeParent := snapshot
	withBridgeParent.Spans = append([]Span(nil), snapshot.Spans...)
	withBridgeParent.Spans[2].ParentSpanID = testApacheClientID
	require.ErrorContains(t, AssertSnapshot(withBridgeParent, expectation), "expected Java root span")

	remoteRoot := snapshot
	remoteRoot.Spans = append([]Span(nil), snapshot.Spans...)
	remoteRoot.Spans[2].Flags = testRemoteSpanFlags
	require.ErrorContains(t, AssertSnapshot(remoteRoot, expectation), "to be local")

	sharedTrace := snapshot
	sharedTrace.Spans = append([]Span(nil), snapshot.Spans...)
	sharedTrace.Spans[2].TraceID = testTraceID
	require.ErrorContains(t, AssertSnapshot(sharedTrace, expectation), "distinct from Apache candidate trace")

	orphanedCandidate := snapshot
	orphanedCandidate.Spans = append([]Span(nil), snapshot.Spans...)
	orphanedCandidate.Spans[1].ParentSpanID = testExternalSpanID
	require.ErrorContains(t, AssertSnapshot(orphanedCandidate, expectation), "descend from inbound span")

	duplicateCandidate := snapshot
	duplicateCandidate.Spans = append([]Span(nil), snapshot.Spans...)
	extra := duplicateCandidate.Spans[1]
	extra.SpanID = "445566778899aabb"
	duplicateCandidate.Spans = append(duplicateCandidate.Spans, extra)
	require.ErrorContains(t, AssertSnapshot(duplicateCandidate, expectation), "exactly one Apache client candidate")

	wrongEndpointCandidate := snapshot
	wrongEndpointCandidate.Spans = append([]Span(nil), snapshot.Spans...)
	extra = wrongEndpointCandidate.Spans[1]
	extra.SpanID = "445566778899aabb"
	extra.Attributes = map[string]string{
		"http.request.header.x-obi-demo-id": testMarker,
		"url.full":                          "https://java/api/other",
	}
	wrongEndpointCandidate.Spans = append(wrongEndpointCandidate.Spans, extra)
	require.ErrorContains(t, AssertSnapshot(wrongEndpointCandidate, expectation), "exactly one Apache client candidate")

	duplicateApacheServer := snapshot
	duplicateApacheServer.Spans = append([]Span(nil), snapshot.Spans...)
	extra = duplicateApacheServer.Spans[0]
	extra.SpanID = "5566778899aabbcc"
	duplicateApacheServer.Spans = append(duplicateApacheServer.Spans, extra)
	require.ErrorContains(t, AssertSnapshot(duplicateApacheServer, expectation), "exactly one Apache inbound server span")

	duplicateJavaServer := snapshot
	duplicateJavaServer.Spans = append([]Span(nil), snapshot.Spans...)
	extra = duplicateJavaServer.Spans[2]
	extra.SpanID = "66778899aabbccdd"
	duplicateJavaServer.Spans = append(duplicateJavaServer.Spans, extra)
	require.ErrorContains(t, AssertSnapshot(duplicateJavaServer, expectation), "exactly one Java server span")

	for _, testCase := range []struct {
		name   string
		index  int
		trace  string
		spanID string
		want   string
	}{
		{
			name:  "zero Apache server trace ID",
			index: 0,
			trace: "00000000000000000000000000000000",
			want:  "Apache inbound server span has a zero trace ID",
		},
		{
			name:   "zero Apache server span ID",
			index:  0,
			spanID: "0000000000000000",
			want:   "Apache inbound server span has a zero span ID",
		},
		{
			name:  "zero Apache client trace ID",
			index: 1,
			trace: "00000000000000000000000000000000",
			want:  "Apache client candidate has a zero trace ID",
		},
		{
			name:   "zero Apache client span ID",
			index:  1,
			spanID: "0000000000000000",
			want:   "Apache client candidate has a zero span ID",
		},
		{
			name:  "zero Java server trace ID",
			index: 2,
			trace: "00000000000000000000000000000000",
			want:  "Java server span has a zero trace ID",
		},
		{
			name:   "zero Java server span ID",
			index:  2,
			spanID: "0000000000000000",
			want:   "Java server span has a zero span ID",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			malformed := snapshot
			malformed.Spans = append([]Span(nil), snapshot.Spans...)
			if testCase.trace != "" {
				malformed.Spans[testCase.index].TraceID = testCase.trace
			}
			if testCase.spanID != "" {
				malformed.Spans[testCase.index].SpanID = testCase.spanID
			}
			require.ErrorContains(t, AssertSnapshot(malformed, expectation), testCase.want)
		})
	}
}

func TestAssertSnapshotCanProveUnsampledCandidateWithSampledJavaChild(t *testing.T) {
	snapshot := bridgeSnapshot(0x300)
	snapshot.Spans[0].Flags = 0x300
	expectation := Expectation{
		Mode:            ModeBridge,
		ApacheService:   "apache",
		JavaService:     "java",
		Endpoint:        testEndpoint,
		Marker:          testMarker,
		W3CTraceID:      testTraceID,
		W3CParentSpanID: testExternalSpanID,
		W3CTraceFlags:   "00",
		JavaTraceFlags:  "01",
	}

	require.NoError(t, AssertSnapshot(snapshot, expectation))
}

func TestAssertSnapshotRejectsBrokenApacheInternalAncestry(t *testing.T) {
	snapshot := bridgeSnapshot(testRemoteSpanFlags)
	snapshot.Spans[0].ParentSpanID = ""
	snapshot.Spans[3].ParentSpanID = testApacheClientID
	expectation := Expectation{
		Mode:          ModeBridge,
		ApacheService: "apache",
		JavaService:   "java",
		Endpoint:      testEndpoint,
		Marker:        testMarker,
	}

	require.ErrorContains(t, AssertSnapshot(snapshot, expectation), "descend from inbound span")
}

func TestAssertSnapshotAllowsFailClosedPipelinedInboundAmbiguity(t *testing.T) {
	snapshot := bridgeSnapshot(testRemoteSpanFlags)
	snapshot.Spans[1].ParentSpanID = ""
	snapshot.Spans = []Span{snapshot.Spans[1], snapshot.Spans[2]}
	expectation := Expectation{
		Mode:          ModePipelinedBridge,
		ApacheService: "apache",
		JavaService:   "java",
		Endpoint:      testEndpoint,
		Marker:        testMarker,
	}

	require.NoError(t, AssertSnapshot(snapshot, expectation))

	orphaned := snapshot
	orphaned.Spans = append([]Span(nil), snapshot.Spans...)
	orphaned.Spans[0].ParentSpanID = testExternalSpanID
	require.ErrorContains(t, AssertSnapshot(orphaned, expectation), "to be a root")

	wrongParent := snapshot
	wrongParent.Spans = append([]Span(nil), snapshot.Spans...)
	wrongParent.Spans[1].ParentSpanID = testExternalSpanID
	require.ErrorContains(t, AssertSnapshot(wrongParent, expectation), "to identify Apache client")

	normalExpectation := expectation
	normalExpectation.Mode = ModeBridge
	require.ErrorContains(t, AssertSnapshot(snapshot, normalExpectation), "exactly one Apache inbound")
}

func TestAssertSnapshotRejectsMultiplePipelinedInboundSpans(t *testing.T) {
	snapshot := bridgeSnapshot(testRemoteSpanFlags)
	snapshot.Spans[0].ParentSpanID = ""
	duplicate := snapshot.Spans[0]
	duplicate.SpanID = "445566778899aabb"
	snapshot.Spans = append(snapshot.Spans, duplicate)
	expectation := Expectation{
		Mode:          ModePipelinedBridge,
		ApacheService: "apache",
		JavaService:   "java",
		Endpoint:      testEndpoint,
		Marker:        testMarker,
	}

	require.ErrorContains(t, AssertSnapshot(snapshot, expectation), "at most one Apache inbound")
}

func TestSpanDescendsFromRejectsCyclesAndDuplicates(t *testing.T) {
	server := Span{TraceID: testTraceID, SpanID: testApacheServerID}
	client := Span{TraceID: testTraceID, SpanID: testApacheClientID, ParentSpanID: testProcessingID}
	processing := Span{
		TraceID:      testTraceID,
		SpanID:       testProcessingID,
		ParentSpanID: testApacheServerID,
	}

	server.ParentSpanID = testApacheClientID
	assert.False(t, spanDescendsFrom([]Span{server, processing, client}, client, server))

	server.ParentSpanID = ""
	duplicateProcessing := processing
	duplicateProcessing.ParentSpanID = testExternalSpanID
	assert.False(t, spanDescendsFrom(
		[]Span{server, processing, duplicateProcessing, client},
		client,
		server,
	))

	externalParent := Span{
		TraceID: testTraceID,
		SpanID:  testExternalSpanID,
	}
	conflictingExternalParent := externalParent
	conflictingExternalParent.ParentSpanID = "conflicting-parent"
	server.ParentSpanID = testExternalSpanID
	assert.False(t, spanDescendsFrom(
		[]Span{externalParent, conflictingExternalParent, server, processing, client},
		client,
		server,
	))
}

func TestSpanDescendsFromRejectsForeignServiceBoundary(t *testing.T) {
	snapshot := bridgeSnapshot(testRemoteSpanFlags)
	snapshot.Spans[0].ParentSpanID = ""
	snapshot.Spans[3].ServiceName = "foreign-service"
	expectation := Expectation{
		Mode:          ModeBridge,
		ApacheService: "apache",
		JavaService:   "java",
		Endpoint:      testEndpoint,
		Marker:        testMarker,
	}

	require.ErrorContains(t, AssertSnapshot(snapshot, expectation), "descend from inbound span")
}

func bridgeSnapshot(candidateFlags uint32) Snapshot {
	requestAttributes := map[string]string{
		"http.route":                        testEndpoint,
		"http.request.header.x-obi-demo-id": testMarker,
	}
	clientAttributes := map[string]string{
		"http.request.header.x-obi-demo-id": testMarker,
		"url.full":                          "https://java" + testEndpoint,
	}
	return Snapshot{
		Marker: testMarker,
		Spans: []Span{
			{
				TraceID:      testTraceID,
				SpanID:       testApacheServerID,
				ParentSpanID: testExternalSpanID,
				Flags:        testRemoteSpanFlags,
				ServiceName:  "apache",
				Kind:         "SERVER",
				Attributes:   requestAttributes,
			},
			{
				TraceID:      testTraceID,
				SpanID:       testApacheClientID,
				ParentSpanID: testProcessingID,
				Flags:        candidateFlags,
				ServiceName:  "apache",
				Kind:         "CLIENT",
				Attributes:   clientAttributes,
			},
			{
				TraceID:      testTraceID,
				SpanID:       testJavaServerID,
				ParentSpanID: testApacheClientID,
				Flags:        testRemoteSpanFlags,
				ServiceName:  "java",
				Kind:         "SERVER",
				Attributes:   requestAttributes,
			},
			{
				TraceID:      testTraceID,
				SpanID:       testProcessingID,
				ParentSpanID: testApacheServerID,
				ServiceName:  "apache",
				Kind:         "INTERNAL",
				Name:         "processing",
			},
		},
	}
}
