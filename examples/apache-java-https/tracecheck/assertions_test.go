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
	require.ErrorContains(t, AssertSnapshot(snapshot, expectation), "child of Apache inbound span")

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

func bridgeSnapshot(candidateFlags uint32) Snapshot {
	attributes := map[string]string{
		"http.route":                        testEndpoint,
		"http.request.header.x-obi-demo-id": testMarker,
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
				Attributes:   attributes,
			},
			{
				TraceID:      testTraceID,
				SpanID:       testApacheClientID,
				ParentSpanID: testApacheServerID,
				Flags:        candidateFlags,
				ServiceName:  "apache",
				Kind:         "CLIENT",
				Attributes:   attributes,
			},
			{
				TraceID:      testTraceID,
				SpanID:       testJavaServerID,
				ParentSpanID: testApacheClientID,
				Flags:        testRemoteSpanFlags,
				ServiceName:  "java",
				Kind:         "SERVER",
				Attributes:   attributes,
			},
		},
	}
}
