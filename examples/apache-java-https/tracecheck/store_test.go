// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracecheck

import (
	"testing"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

func TestStoreIsBoundedAndFiltersMarkers(t *testing.T) {
	store := NewStore(2, 1024, 4096)
	store.Add([]Span{
		{SpanID: "1", Attributes: map[string]string{"http.request.header.x_obi_demo_id": "first"}},
		{SpanID: "2", Attributes: map[string]string{"http.request.header.x_obi_demo_id": "second"}},
		{SpanID: "3", Attributes: map[string]string{"http.request.header.x_obi_demo_id": "third"}},
	})

	snapshot := store.Snapshot("second")
	if len(snapshot.Spans) != 1 || snapshot.Spans[0].SpanID != "2" {
		t.Fatalf("unexpected filtered spans: %#v", snapshot.Spans)
	}
	if snapshot.DroppedSpans != 1 {
		t.Fatalf("expected one dropped span, got %d", snapshot.DroppedSpans)
	}
	if snapshot.DroppedCountSpans != 1 {
		t.Fatalf("expected one count-limit drop, got %d", snapshot.DroppedCountSpans)
	}
}

func TestStoreMarkerSnapshotRetainsParentChain(t *testing.T) {
	const marker = "bridge-request"
	store := NewStore(10, 1024, 4096)
	store.Add([]Span{
		{TraceID: "trace", SpanID: "server"},
		{TraceID: "trace", SpanID: "processing", ParentSpanID: "server"},
		{
			TraceID:      "trace",
			SpanID:       "client",
			ParentSpanID: "processing",
			Attributes:   map[string]string{"http.request.header.x_obi_demo_id": marker},
		},
		{TraceID: "trace", SpanID: "unrelated", ParentSpanID: "server"},
	})

	snapshot := store.Snapshot(marker)
	if len(snapshot.Spans) != 3 {
		t.Fatalf("expected marker span and two ancestors, got %#v", snapshot.Spans)
	}
	for _, spanID := range []string{"server", "processing", "client"} {
		found := false
		for _, span := range snapshot.Spans {
			if span.SpanID == spanID {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing ancestor %q from %#v", spanID, snapshot.Spans)
		}
	}
}

func TestStoreMarkerSnapshotStopsAtDifferentRequestMarker(t *testing.T) {
	store := NewStore(10, 1024, 4096)
	store.Add([]Span{
		{
			TraceID:    "trace",
			SpanID:     "wrong-parent",
			Attributes: map[string]string{"http.request.header.x_obi_demo_id": "other"},
		},
		{
			TraceID:      "trace",
			SpanID:       "client",
			ParentSpanID: "wrong-parent",
			Attributes:   map[string]string{"http.request.header.x_obi_demo_id": "wanted"},
		},
	})

	snapshot := store.Snapshot("wanted")
	if len(snapshot.Spans) != 1 || snapshot.Spans[0].SpanID != "client" {
		t.Fatalf("different-request ancestor leaked into snapshot: %#v", snapshot.Spans)
	}
}

func TestStoreMarkerSnapshotRejectsConflictingDuplicateSeed(t *testing.T) {
	store := NewStore(10, 1024, 4096)
	store.Add([]Span{
		{
			TraceID:    "trace",
			SpanID:     "duplicate",
			Attributes: map[string]string{"http.request.header.x_obi_demo_id": "wanted"},
		},
		{
			TraceID:    "trace",
			SpanID:     "duplicate",
			Attributes: map[string]string{"http.request.header.x_obi_demo_id": "other"},
		},
	})

	snapshot := store.Snapshot("wanted")
	if len(snapshot.Spans) != 0 {
		t.Fatalf("conflicting duplicate leaked into marker snapshot: %#v", snapshot.Spans)
	}
}

func TestStoreRejectsOversizedStringValues(t *testing.T) {
	store := NewStore(10, 4, 1024)
	store.Add([]Span{{SpanID: "12345"}})

	snapshot := store.Snapshot("")
	if len(snapshot.Spans) != 0 || snapshot.DroppedSpans != 1 ||
		snapshot.DroppedValueLimitSpans != 1 {
		t.Fatalf("unexpected value-limit snapshot: %#v", snapshot)
	}
}

func TestStoreEvictsOldestSpanAtRetainedByteLimit(t *testing.T) {
	store := NewStore(10, 16, 6)
	store.Add([]Span{{SpanID: "1111"}, {SpanID: "2222"}})

	snapshot := store.Snapshot("")
	if len(snapshot.Spans) != 1 || snapshot.Spans[0].SpanID != "2222" {
		t.Fatalf("unexpected retained spans: %#v", snapshot.Spans)
	}
	if snapshot.RetainedBytes != 4 || snapshot.DroppedRetainedLimitSpans != 1 ||
		snapshot.DroppedSpans != 1 {
		t.Fatalf("unexpected retained-byte accounting: %#v", snapshot)
	}
}

func TestStoreRejectsSpanLargerThanAggregateLimit(t *testing.T) {
	store := NewStore(10, 16, 3)
	store.Add([]Span{{SpanID: "1234"}})

	snapshot := store.Snapshot("")
	if len(snapshot.Spans) != 0 || snapshot.RetainedBytes != 0 ||
		snapshot.DroppedRetainedLimitSpans != 1 {
		t.Fatalf("unexpected aggregate-limit snapshot: %#v", snapshot)
	}
}

func TestStoreRetainedAccountingCannotBeMutatedByCaller(t *testing.T) {
	attributes := map[string]string{"key": "value"}
	store := NewStore(10, 16, 32)
	store.Add([]Span{{SpanID: "one", Attributes: attributes}})
	attributes["key"] = "value-that-exceeds-the-configured-limit"

	snapshot := store.Snapshot("")
	if snapshot.RetainedBytes != 11 || snapshot.Spans[0].Attributes["key"] != "value" {
		t.Fatalf("caller mutation changed retained state: %#v", snapshot)
	}
	snapshot.Spans[0].Attributes["key"] = "changed-through-snapshot"
	if value := store.Snapshot("").Spans[0].Attributes["key"]; value != "value" {
		t.Fatalf("snapshot mutation changed retained state: %q", value)
	}
}

func TestStoreResetClearsRetainedByteDiagnostics(t *testing.T) {
	store := NewStore(1, 16, 16)
	store.Add([]Span{{SpanID: "one"}, {SpanID: "two"}})
	store.Reset()

	snapshot := store.Snapshot("")
	if snapshot.ReceivedBatches != 0 || snapshot.ReceivedSpans != 0 ||
		snapshot.DroppedSpans != 0 || snapshot.RetainedBytes != 0 || len(snapshot.Spans) != 0 {
		t.Fatalf("reset retained diagnostics: %#v", snapshot)
	}
}

func TestSaturatingAddDoesNotWrap(t *testing.T) {
	if got := saturatingAdd(^uint64(0)-1, 2); got != ^uint64(0) {
		t.Fatalf("saturating add wrapped: %d", got)
	}
}

func TestFlattenRetainsParentRemoteFlags(t *testing.T) {
	traces := ptrace.NewTraces()
	span := traces.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.SetFlags(spanFlagsParentRemoteKnown | spanFlagsParentRemote | 1)

	flattened := Flatten(traces)
	if len(flattened) != 1 {
		t.Fatalf("expected one flattened span, got %d", len(flattened))
	}
	remote, known := ParentRemote(flattened[0])
	if !known || !remote || flattened[0].Flags != span.Flags() {
		t.Fatalf("parent remote flags were not retained: %#v", flattened[0])
	}
}

func TestAssertSnapshotBridge(t *testing.T) {
	const marker = "basic-00-deadbeef"
	requestAttributes := map[string]string{
		"http.request.header.x_obi_demo_id": marker,
		"url.path":                          "/api/echo",
	}
	spans := []Span{
		{ServiceName: "apache-proxy", Kind: "SERVER", TraceID: "trace", SpanID: "apache-server", Attributes: requestAttributes},
		{ServiceName: "apache-proxy", Kind: "CLIENT", TraceID: "trace", SpanID: "parent", ParentSpanID: "apache-server", Attributes: map[string]string{"url.path": "/api/echo"}},
		{ServiceName: "java-backend", Kind: "SERVER", TraceID: "trace", SpanID: "server", ParentSpanID: "parent", Flags: spanFlagsParentRemoteKnown | spanFlagsParentRemote, Attributes: requestAttributes},
	}
	store := NewStore(10, 1024, 4096)
	store.Add(spans)
	snapshot := store.Snapshot(marker)

	err := AssertSnapshot(snapshot, Expectation{
		Mode:          ModeBridge,
		ApacheService: "apache-proxy",
		JavaService:   "java-backend",
		Endpoint:      "/api/echo",
		Marker:        marker,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAssertSnapshotBridgeDisabledKeepsOfficialAgentRoot(t *testing.T) {
	const marker = "disabled-00-deadbeef"
	requestAttributes := map[string]string{
		"http.request.header.x_obi_demo_id": marker,
		"url.path":                          "/api/echo",
	}
	snapshot := Snapshot{Marker: marker, Spans: []Span{
		{ServiceName: "apache-proxy", Kind: "SERVER", TraceID: "apache", SpanID: "apache-server", Attributes: requestAttributes},
		{ServiceName: "java-backend", Kind: "SERVER", TraceID: "java", SpanID: "java-server", Attributes: requestAttributes},
	}}

	err := AssertSnapshot(snapshot, Expectation{
		Mode:          ModeDisabled,
		ApacheService: "apache-proxy",
		JavaService:   "java-backend",
		Endpoint:      "/api/echo",
		Marker:        marker,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAssertSnapshotW3CWithoutOBI(t *testing.T) {
	const marker = "w3c-only-00-deadbeef"
	requestAttributes := map[string]string{
		"http.request.header.x_obi_demo_id": marker,
		"url.path":                          "/api/echo",
	}
	expectation := Expectation{
		Mode:            ModeW3CNoOBI,
		ApacheService:   "apache-proxy",
		JavaService:     "java-backend",
		Endpoint:        "/api/echo",
		Marker:          marker,
		W3CTraceID:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		W3CParentSpanID: "bbbbbbbbbbbbbbbb",
	}
	snapshot := Snapshot{Marker: marker, Spans: []Span{{
		ServiceName:  "java-backend",
		Kind:         "SERVER",
		TraceID:      expectation.W3CTraceID,
		SpanID:       "server",
		ParentSpanID: expectation.W3CParentSpanID,
		Flags:        spanFlagsParentRemoteKnown | spanFlagsParentRemote,
		Attributes:   requestAttributes,
	}}}

	if err := AssertSnapshot(snapshot, expectation); err != nil {
		t.Fatal(err)
	}

	snapshot.Spans = append(snapshot.Spans, Span{
		ServiceName: "apache-proxy",
		Kind:        "SERVER",
		SpanID:      "unexpected-apache",
		Attributes:  requestAttributes,
	})
	if err := AssertSnapshot(snapshot, expectation); err == nil {
		t.Fatal("expected an Apache span to invalidate the no-OBI control")
	}
}

func TestAssertSnapshotW3CResilienceAllowsChangingOBIAvailability(t *testing.T) {
	const marker = "restart-fault-00-deadbeef"
	requestAttributes := map[string]string{
		"http.request.header.x_obi_demo_id": marker,
		"url.path":                          "/api/echo",
	}
	expectation := Expectation{
		Mode:            ModeW3CResilience,
		ApacheService:   "apache-proxy",
		JavaService:     "java-backend",
		Endpoint:        "/api/echo",
		Marker:          marker,
		W3CTraceID:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		W3CParentSpanID: "bbbbbbbbbbbbbbbb",
	}
	javaSpan := Span{
		ServiceName:  "java-backend",
		Kind:         "SERVER",
		TraceID:      expectation.W3CTraceID,
		SpanID:       "server",
		ParentSpanID: expectation.W3CParentSpanID,
		Flags:        spanFlagsParentRemoteKnown | spanFlagsParentRemote,
		Attributes:   requestAttributes,
	}

	if err := AssertSnapshot(Snapshot{Marker: marker, Spans: []Span{javaSpan}}, expectation); err != nil {
		t.Fatal(err)
	}
	snapshot := Snapshot{Marker: marker, Spans: []Span{
		{
			ServiceName: "apache-proxy",
			Kind:        "SERVER",
			TraceID:     "different-obi-trace",
			SpanID:      "apache-server",
			Attributes:  requestAttributes,
		},
		javaSpan,
	}}
	if err := AssertSnapshot(snapshot, expectation); err != nil {
		t.Fatal(err)
	}
}

func TestAssertSnapshotW3CRequiresConflictingOBICandidate(t *testing.T) {
	const marker = "w3c-00-deadbeef"
	requestAttributes := map[string]string{
		"http.request.header.x_obi_demo_id": marker,
		"url.path":                          "/api/echo",
	}
	expectation := Expectation{
		Mode:            ModeW3C,
		ApacheService:   "apache-proxy",
		JavaService:     "java-backend",
		Endpoint:        "/api/echo",
		Marker:          marker,
		W3CTraceID:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		W3CParentSpanID: "bbbbbbbbbbbbbbbb",
	}
	snapshot := Snapshot{Marker: marker, Spans: []Span{
		{ServiceName: "apache-proxy", Kind: "SERVER", TraceID: expectation.W3CTraceID, SpanID: "apache-server", ParentSpanID: expectation.W3CParentSpanID, Flags: spanFlagsParentRemoteKnown | spanFlagsParentRemote, Attributes: requestAttributes},
		{ServiceName: "apache-proxy", Kind: "CLIENT", TraceID: expectation.W3CTraceID, SpanID: "obi-candidate", ParentSpanID: "apache-server", Attributes: requestAttributes},
		{ServiceName: "java-backend", Kind: "SERVER", TraceID: expectation.W3CTraceID, SpanID: "java-server", ParentSpanID: expectation.W3CParentSpanID, Flags: spanFlagsParentRemoteKnown | spanFlagsParentRemote, Attributes: requestAttributes},
	}}

	if err := AssertSnapshot(snapshot, expectation); err != nil {
		t.Fatal(err)
	}

	snapshot.Spans[1].SpanID = expectation.W3CParentSpanID
	if err := AssertSnapshot(snapshot, expectation); err == nil {
		t.Fatal("expected a matching OBI candidate to fail the conflict control")
	}
}

func TestAssertSnapshotRejectsCrossRequestParent(t *testing.T) {
	const marker = "basic-00-deadbeef"
	requestAttributes := map[string]string{
		"http.request.header.x_obi_demo_id": marker,
		"url.path":                          "/api/echo",
	}
	snapshot := Snapshot{Spans: []Span{
		{ServiceName: "apache-proxy", Kind: "SERVER", TraceID: "trace", SpanID: "apache-server", Attributes: requestAttributes},
		{ServiceName: "apache-proxy", Kind: "CLIENT", TraceID: "trace", SpanID: "other", ParentSpanID: "apache-server", Attributes: requestAttributes},
		{ServiceName: "java-backend", Kind: "SERVER", TraceID: "trace", SpanID: "server", ParentSpanID: "parent", Flags: spanFlagsParentRemoteKnown | spanFlagsParentRemote, Attributes: requestAttributes},
	}}
	snapshot.Marker = marker

	err := AssertSnapshot(snapshot, Expectation{
		Mode:          ModeBridge,
		ApacheService: "apache-proxy",
		JavaService:   "java-backend",
		Endpoint:      "/api/echo",
		Marker:        marker,
	})
	if err == nil {
		t.Fatal("expected mismatched parent to fail")
	}
}

func TestAssertSnapshotRejectsMissingApacheInboundSpan(t *testing.T) {
	const marker = "basic-00-deadbeef"
	requestAttributes := map[string]string{
		"http.request.header.x_obi_demo_id": marker,
		"url.path":                          "/api/echo",
	}
	snapshot := Snapshot{Marker: marker, Spans: []Span{
		{ServiceName: "apache-proxy", Kind: "CLIENT", TraceID: "trace", SpanID: "parent", Attributes: requestAttributes},
		{ServiceName: "java-backend", Kind: "SERVER", TraceID: "trace", SpanID: "server", ParentSpanID: "parent", Flags: spanFlagsParentRemoteKnown | spanFlagsParentRemote, Attributes: requestAttributes},
	}}

	err := AssertSnapshot(snapshot, Expectation{
		Mode:          ModeBridge,
		ApacheService: "apache-proxy",
		JavaService:   "java-backend",
		Endpoint:      "/api/echo",
		Marker:        marker,
	})
	if err == nil {
		t.Fatal("expected missing Apache inbound span to fail")
	}
}

func TestAssertSnapshotRejectsMarkerSubstringAndWrongEndpoint(t *testing.T) {
	const marker = "basic-00-deadbeef"
	snapshot := Snapshot{Marker: marker, Spans: []Span{
		{
			ServiceName: "java-backend",
			Kind:        "SERVER",
			Attributes: map[string]string{
				"http.request.header.x_obi_demo_id": "prefix-" + marker,
				"url.path":                          "/api/other",
			},
		},
	}}

	err := AssertSnapshot(snapshot, Expectation{
		Mode:          ModeBridge,
		ApacheService: "apache-proxy",
		JavaService:   "java-backend",
		Endpoint:      "/api/echo",
		Marker:        marker,
	})
	if err == nil {
		t.Fatal("expected inexact marker and endpoint to fail")
	}
}

func TestAssertSnapshotRejectsDuplicateJavaSpanWithWrongEndpoint(t *testing.T) {
	const marker = "basic-00-deadbeef"
	requestAttributes := map[string]string{
		"http.request.header.x_obi_demo_id": marker,
		"url.path":                          "/api/echo",
	}
	wrongEndpointAttributes := map[string]string{
		"http.request.header.x_obi_demo_id": marker,
		"url.path":                          "/api/other",
	}
	snapshot := Snapshot{Marker: marker, Spans: []Span{
		{ServiceName: "apache-proxy", Kind: "SERVER", TraceID: "trace", SpanID: "apache-server", Attributes: requestAttributes},
		{ServiceName: "apache-proxy", Kind: "CLIENT", TraceID: "trace", SpanID: "parent", ParentSpanID: "apache-server", Attributes: requestAttributes},
		{ServiceName: "java-backend", Kind: "SERVER", TraceID: "trace", SpanID: "server", ParentSpanID: "parent", Flags: spanFlagsParentRemoteKnown | spanFlagsParentRemote, Attributes: requestAttributes},
		{ServiceName: "java-backend", Kind: "SERVER", TraceID: "other", SpanID: "duplicate", Attributes: wrongEndpointAttributes},
	}}

	err := AssertSnapshot(snapshot, Expectation{
		Mode:          ModeBridge,
		ApacheService: "apache-proxy",
		JavaService:   "java-backend",
		Endpoint:      "/api/echo",
		Marker:        marker,
	})
	if err == nil {
		t.Fatal("expected duplicate Java server span to fail")
	}
}

func TestAssertSnapshotRejectsMissingRemoteParentFlag(t *testing.T) {
	const marker = "basic-00-deadbeef"
	requestAttributes := map[string]string{
		"http.request.header.x_obi_demo_id": marker,
		"url.path":                          "/api/echo",
	}
	snapshot := Snapshot{Marker: marker, Spans: []Span{
		{ServiceName: "apache-proxy", Kind: "SERVER", TraceID: "trace", SpanID: "apache-server", Attributes: requestAttributes},
		{ServiceName: "apache-proxy", Kind: "CLIENT", TraceID: "trace", SpanID: "parent", ParentSpanID: "apache-server", Attributes: requestAttributes},
		{ServiceName: "java-backend", Kind: "SERVER", TraceID: "trace", SpanID: "server", ParentSpanID: "parent", Flags: spanFlagsParentRemoteKnown, Attributes: requestAttributes},
	}}

	err := AssertSnapshot(snapshot, Expectation{
		Mode:          ModeBridge,
		ApacheService: "apache-proxy",
		JavaService:   "java-backend",
		Endpoint:      "/api/echo",
		Marker:        marker,
	})
	if err == nil {
		t.Fatal("expected a non-remote Java parent to fail")
	}
}

func TestAssertSnapshotUninstrumentedRequiresNoMarkerSpans(t *testing.T) {
	expectation := Expectation{Mode: ModeUninstrumented, Marker: "uninstrumented-00-deadbeef"}
	if err := AssertSnapshot(Snapshot{Marker: expectation.Marker}, expectation); err != nil {
		t.Fatal(err)
	}

	err := AssertSnapshot(Snapshot{
		Marker: expectation.Marker,
		Spans:  []Span{{ServiceName: "java-backend", SpanID: "unexpected"}},
	}, expectation)
	if err == nil {
		t.Fatal("expected an instrumented disabled-control span to fail")
	}
}

func TestMatchesEndpointAcceptsExactPathInClientURL(t *testing.T) {
	span := Span{Attributes: map[string]string{
		"url.full": "https://localhost:18443/api/echo?delay_ms=150",
	}}
	if !MatchesEndpoint(span, "/api/echo") {
		t.Fatal("expected exact URL path to match endpoint")
	}
	if MatchesEndpoint(span, "/api/ech") {
		t.Fatal("expected endpoint prefix to be rejected")
	}
}

func TestNormalizedMarkerRequiresOneExactStringValue(t *testing.T) {
	value := pcommon.NewValueSlice()
	value.Slice().AppendEmpty().SetStr("basic-00-deadbeef")
	marker, ok := normalizedAttributeValue("http.request.header.x-obi-demo-id", value)
	if !ok || marker != "basic-00-deadbeef" {
		t.Fatalf("unexpected normalized marker: %q, %v", marker, ok)
	}

	value.Slice().AppendEmpty().SetStr("other")
	if _, ok := normalizedAttributeValue("http.request.header.x-obi-demo-id", value); ok {
		t.Fatal("accepted a multi-value marker attribute")
	}

	span := Span{Attributes: map[string]string{"custom.x_obi_demo_id": "basic-00-deadbeef"}}
	if MatchesMarker(span, "basic-00-deadbeef") {
		t.Fatal("accepted a marker from an unexpected attribute")
	}
}
