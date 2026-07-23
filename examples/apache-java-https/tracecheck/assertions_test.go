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

func TestAssertSnapshotRequiresApacheRootWithoutExternalW3C(t *testing.T) {
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
	assert.ErrorContains(t, AssertSnapshot(snapshot, expectation), "root without an external W3C parent")
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
		"url.full": "https://java" + testEndpoint,
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
