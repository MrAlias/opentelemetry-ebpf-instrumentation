// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracecheck

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

func TestStoreRecordsProvidedReceiverArrivalMillisecond(t *testing.T) {
	store := NewStore(1, 1024, 4096)
	receivedAt := time.UnixMilli(123456)

	store.AddAt([]Span{{SpanID: "span"}}, receivedAt)

	snapshot := store.Snapshot("")
	if len(snapshot.Spans) != 1 {
		t.Fatalf("expected one retained span, got %#v", snapshot.Spans)
	}
	if got, want := snapshot.Spans[0].ReceivedUnixMilli, uint64(receivedAt.UnixMilli()); got != want {
		t.Fatalf("unexpected receiver arrival time: got %d, want %d", got, want)
	}
}

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

func TestStoreMarkerSnapshotAddsOnlyRedactedRelatedCandidates(t *testing.T) {
	const marker = "bridge-request"
	const traceID = "00112233445566778899aabbccddeeff"
	requestAttributes := map[string]string{
		"http.request.header.x_obi_demo_id": marker,
		"url.path":                          "/api/echo",
	}
	store := NewStore(16, 1024, 16384)
	store.Add([]Span{
		{
			TraceID:     traceID,
			SpanID:      "apache-server",
			ServiceName: "apache",
			Kind:        "SERVER",
			Attributes:  requestAttributes,
		},
		{
			TraceID:      traceID,
			SpanID:       "apache-client",
			ParentSpanID: "apache-server",
			ServiceName:  "apache",
			Kind:         "CLIENT",
			Attributes:   requestAttributes,
		},
		{
			TraceID:      traceID,
			SpanID:       "java-server",
			ParentSpanID: "apache-client",
			ServiceName:  "java",
			Kind:         "SERVER",
			Attributes:   requestAttributes,
		},
		{
			TraceID:      traceID,
			SpanID:       "duplicate-server",
			ParentSpanID: "apache-client",
			ServiceName:  "java",
			ScopeName:    "sensitive-scope",
			Name:         "sensitive-name",
			Kind:         "SERVER",
			Attributes: map[string]string{
				"url.path": "/api/echo",
				"url.full": "https://java/api/echo?secret=value",
				"http.url": "%",
				"custom":   "sensitive-value",
			},
		},
		{
			TraceID:      traceID,
			SpanID:       "downstream-server",
			ParentSpanID: "java-server",
			ServiceName:  "java",
			Kind:         "SERVER",
			Attributes:   map[string]string{"url.path": "/api/other"},
		},
		{
			TraceID:      traceID,
			SpanID:       "boundary-sibling",
			ParentSpanID: "apache-client",
			ServiceName:  "java",
			Name:         "sensitive-boundary-name",
			Kind:         "INTERNAL",
			Attributes:   map[string]string{"url.full": "https://java/private?secret=value"},
		},
		{
			TraceID:      traceID,
			SpanID:       "unrelated-internal",
			ParentSpanID: "apache-server",
			ServiceName:  "java",
			Kind:         "INTERNAL",
		},
	})

	snapshot := store.Snapshot(marker)
	if len(snapshot.Spans) != 3 {
		t.Fatalf("expected only marker spans and ancestors, got %#v", snapshot.Spans)
	}
	if len(snapshot.RelatedSpans) != 3 || snapshot.OmittedRelatedSpans != 0 {
		t.Fatalf("unexpected related candidates: %#v", snapshot)
	}
	for _, span := range snapshot.RelatedSpans {
		if span.Name != "" || span.ScopeName != "" || len(span.Attributes) != 0 {
			t.Fatalf("related span retained nonessential data: %#v", span)
		}
	}
}

func TestStoreMarkerSnapshotExcludesDifferentMarkerSubtree(t *testing.T) {
	const traceID = "00112233445566778899aabbccddeeff"
	store := NewStore(10, 1024, 4096)
	store.Add([]Span{
		{
			TraceID:     traceID,
			SpanID:      "wanted",
			ServiceName: "java",
			Kind:        "SERVER",
			Attributes:  map[string]string{"http.request.header.x_obi_demo_id": "wanted"},
		},
		{
			TraceID:      traceID,
			SpanID:       "other",
			ParentSpanID: "wanted",
			ServiceName:  "java",
			Kind:         "SERVER",
			Attributes:   map[string]string{"http.request.header.x_obi_demo_id": "other"},
		},
		{
			TraceID:      traceID,
			SpanID:       "other-child",
			ParentSpanID: "other",
			ServiceName:  "java",
			Kind:         "SERVER",
		},
	})

	snapshot := store.Snapshot("wanted")
	if len(snapshot.Spans) != 1 || snapshot.Spans[0].SpanID != "wanted" ||
		len(snapshot.RelatedSpans) != 0 {
		t.Fatalf("different-marker subtree leaked into snapshot: %#v", snapshot)
	}
}

func TestStoreMarkerSnapshotCapsRelatedCandidates(t *testing.T) {
	const traceID = "00112233445566778899aabbccddeeff"
	spans := []Span{{
		TraceID:     traceID,
		SpanID:      "wanted",
		ServiceName: "java",
		Kind:        "SERVER",
		Attributes:  map[string]string{"http.request.header.x_obi_demo_id": "wanted"},
	}}
	for index := 0; index < maxRelatedSpans+1; index++ {
		spans = append(spans, Span{
			TraceID:     traceID,
			SpanID:      fmt.Sprintf("related-%03d", index),
			ServiceName: "java",
			Kind:        "SERVER",
		})
	}
	store := NewStore(len(spans), 1024, 1<<20)
	store.Add(spans)

	snapshot := store.Snapshot("wanted")
	if len(snapshot.RelatedSpans) != maxRelatedSpans || snapshot.OmittedRelatedSpans != 1 {
		t.Fatalf("related candidate cap did not fail closed: %#v", snapshot)
	}
}

func TestStoreMarkerSnapshotBoundsRelatedCandidateValues(t *testing.T) {
	const traceID = "00112233445566778899aabbccddeeff"
	spans := []Span{{
		TraceID:     traceID,
		SpanID:      "wanted",
		ServiceName: "java",
		Kind:        "SERVER",
		Attributes:  map[string]string{"http.request.header.x_obi_demo_id": "wanted"},
	}}
	spans = append(spans, Span{
		TraceID:     traceID,
		SpanID:      "oversized-value",
		ServiceName: strings.Repeat("v", maxRelatedValueBytes+1),
		Kind:        "SERVER",
	})
	store := NewStore(len(spans), maxRelatedValueBytes+1, 1<<20)
	store.Add(spans)

	snapshot := store.Snapshot("wanted")
	if len(snapshot.RelatedSpans) != 0 || snapshot.OmittedRelatedSpans != 1 {
		t.Fatalf("related value limit did not fail closed: %#v", snapshot)
	}
}

func TestStoreMarkerSnapshotBoundsAggregateRelatedBytes(t *testing.T) {
	const traceID = "00112233445566778899aabbccddeeff"
	spans := []Span{{
		TraceID:     traceID,
		SpanID:      "wanted",
		ServiceName: "java",
		Kind:        "SERVER",
		Attributes:  map[string]string{"http.request.header.x_obi_demo_id": "wanted"},
	}}
	for index := 0; index < maxRelatedSpans; index++ {
		spans = append(spans, Span{
			TraceID:     traceID,
			SpanID:      fmt.Sprintf("aggregate-%03d", index),
			ServiceName: strings.Repeat("b", maxRelatedValueBytes),
			Kind:        "SERVER",
		})
	}
	store := NewStore(len(spans), maxRelatedValueBytes+1, 1<<20)
	store.Add(spans)

	snapshot := store.Snapshot("wanted")
	if snapshot.OmittedRelatedSpans == 0 {
		t.Fatalf("related aggregate limit did not fail closed: %#v", snapshot)
	}
	var retained uint64
	for _, span := range snapshot.RelatedSpans {
		spanBytes, valueLimitExceeded, ok := spanRetainedBytes(span, maxRelatedValueBytes)
		if valueLimitExceeded || !ok {
			t.Fatalf("retained an over-limit related span: %#v", span)
		}
		retained += spanBytes
	}
	if retained > maxRelatedRetainedBytes {
		t.Fatalf("retained %d related bytes, limit is %d", retained, maxRelatedRetainedBytes)
	}
}

func TestStoreMarkerSnapshotTaintsRelevantDuplicateIdentities(t *testing.T) {
	const traceID = "00112233445566778899aabbccddeeff"
	for _, testCase := range []struct {
		name  string
		spans []Span
	}{
		{
			name: "unmarked server peer",
			spans: []Span{
				{TraceID: traceID, SpanID: "duplicate", ServiceName: "java", Kind: "SERVER"},
				{TraceID: traceID, SpanID: "duplicate", ServiceName: "java", Kind: "SERVER"},
			},
		},
		{
			name: "exact marker seed",
			spans: []Span{
				{
					TraceID:     traceID,
					SpanID:      "duplicate",
					ServiceName: "java",
					Kind:        "SERVER",
					Attributes:  map[string]string{"http.request.header.x_obi_demo_id": "wanted"},
				},
				{
					TraceID:     traceID,
					SpanID:      "duplicate",
					ServiceName: "java",
					Kind:        "SERVER",
					Attributes:  map[string]string{"http.request.header.x_obi_demo_id": "wanted"},
				},
			},
		},
		{
			name: "zero trace exact marker seed",
			spans: []Span{
				{
					SpanID:      "duplicate",
					ServiceName: "java",
					Kind:        "SERVER",
					Attributes:  map[string]string{"http.request.header.x_obi_demo_id": "wanted"},
				},
				{
					SpanID:      "duplicate",
					ServiceName: "java",
					Kind:        "SERVER",
					Attributes:  map[string]string{"http.request.header.x_obi_demo_id": "wanted"},
				},
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			spans := []Span{{
				TraceID:     traceID,
				SpanID:      "wanted",
				ServiceName: "java",
				Kind:        "SERVER",
				Attributes:  map[string]string{"http.request.header.x_obi_demo_id": "wanted"},
			}}
			spans = append(spans, testCase.spans...)
			store := NewStore(len(spans), 1024, 4096)
			store.Add(spans)

			snapshot := store.Snapshot("wanted")
			if snapshot.AmbiguousRelatedSpans != 1 {
				t.Fatalf("relevant duplicate identity did not fail closed: %#v", snapshot)
			}
		})
	}
}

func TestRelationToMarkerMemoizesHighCardinalityChain(t *testing.T) {
	const (
		traceID = "00112233445566778899aabbccddeeff"
		count   = 10_000
	)
	byIdentity := make(map[spanIdentity]Span, count)
	identities := make([]spanIdentity, 0, count)
	parentID := ""
	for index := 0; index < count; index++ {
		spanID := fmt.Sprintf("node-%05d", index)
		span := Span{TraceID: traceID, SpanID: spanID, ParentSpanID: parentID}
		identity := makeSpanIdentity(traceID, spanID)
		byIdentity[identity] = span
		identities = append(identities, identity)
		parentID = spanID
	}
	relations := make(map[spanIdentity]markerRelation, count)
	duplicates := make(map[spanIdentity]struct{})

	if got := relationToMarker(identities[len(identities)-1], "wanted", byIdentity, duplicates, relations); got != markerRelationWanted {
		t.Fatalf("deep chain relation = %d, want %d", got, markerRelationWanted)
	}
	for _, identity := range identities {
		if got := relationToMarker(identity, "wanted", byIdentity, duplicates, relations); got != markerRelationWanted {
			t.Fatalf("memoized relation for %#v = %d, want %d", identity, got, markerRelationWanted)
		}
	}
	if len(relations) != count {
		t.Fatalf("memoized %d graph nodes, want %d", len(relations), count)
	}
}

func TestStoreMarkerSnapshotDoesNotCorrelateZeroTraceIDs(t *testing.T) {
	store := NewStore(2, 1024, 4096)
	store.Add([]Span{
		{
			SpanID:      "wanted",
			ServiceName: "java",
			Kind:        "SERVER",
			Attributes:  map[string]string{"http.request.header.x_obi_demo_id": "wanted"},
		},
		{SpanID: "unmarked", ServiceName: "java", Kind: "SERVER"},
	})

	snapshot := store.Snapshot("wanted")
	if len(snapshot.Spans) != 1 || len(snapshot.RelatedSpans) != 0 ||
		snapshot.AmbiguousRelatedSpans != 0 {
		t.Fatalf("zero trace IDs were correlated: %#v", snapshot)
	}
}

func TestStoreMarkerSnapshotTaintsGraphAmbiguousRelatedCandidate(t *testing.T) {
	const traceID = "00112233445566778899aabbccddeeff"
	for _, testCase := range []struct {
		name  string
		spans []Span
	}{
		{
			name: "missing parent",
			spans: []Span{{
				TraceID:      traceID,
				SpanID:       "candidate",
				ParentSpanID: "missing",
				ServiceName:  "java",
				Kind:         "SERVER",
			}},
		},
		{
			name: "duplicate parent",
			spans: []Span{
				{TraceID: traceID, SpanID: "duplicate", ServiceName: "java", Kind: "INTERNAL"},
				{TraceID: traceID, SpanID: "duplicate", ServiceName: "other", Kind: "INTERNAL"},
				{
					TraceID:      traceID,
					SpanID:       "candidate",
					ParentSpanID: "duplicate",
					ServiceName:  "java",
					Kind:         "SERVER",
				},
			},
		},
		{
			name: "cycle",
			spans: []Span{
				{
					TraceID:      traceID,
					SpanID:       "candidate",
					ParentSpanID: "cycle",
					ServiceName:  "java",
					Kind:         "SERVER",
				},
				{
					TraceID:      traceID,
					SpanID:       "cycle",
					ParentSpanID: "candidate",
					ServiceName:  "java",
					Kind:         "INTERNAL",
				},
			},
		},
		{
			name: "conflicting valid marker aliases",
			spans: []Span{{
				TraceID:     traceID,
				SpanID:      "candidate",
				ServiceName: "java",
				Kind:        "SERVER",
				Attributes: map[string]string{
					"http.request.header.x-obi-demo-id": "wanted",
					"http.request.header.x_obi_demo_id": "other",
				},
			}},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			spans := []Span{{
				TraceID:     traceID,
				SpanID:      "wanted",
				ServiceName: "java",
				Kind:        "SERVER",
				Attributes:  map[string]string{"http.request.header.x_obi_demo_id": "wanted"},
			}}
			spans = append(spans, testCase.spans...)
			store := NewStore(10, 1024, 4096)
			store.Add(spans)

			snapshot := store.Snapshot("wanted")
			if len(snapshot.RelatedSpans) != 0 || snapshot.AmbiguousRelatedSpans != 1 {
				t.Fatalf("graph ambiguity did not fail closed: %#v", snapshot)
			}
		})
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
	if len(snapshot.Spans) != 0 || len(snapshot.RelatedSpans) != 0 ||
		snapshot.OmittedRelatedSpans != 0 {
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
	continuity := store.Reset()

	snapshot := store.Snapshot("")
	if snapshot.ReceivedBatches != 0 || snapshot.ReceivedSpans != 0 ||
		snapshot.DroppedSpans != 0 || snapshot.RetainedBytes != 0 || len(snapshot.Spans) != 0 {
		t.Fatalf("reset retained diagnostics: %#v", snapshot)
	}
	if snapshot.ReceiverContinuity != continuity {
		t.Fatalf("reset continuity does not match snapshot: reset=%#v snapshot=%#v", continuity, snapshot)
	}
}

func TestStoreSnapshotReportsStableReceiverContinuity(t *testing.T) {
	store := NewStore(10, 16, 32)
	initial := store.Snapshot("")
	if initial.ReceiverInstanceID == "" || initial.ResetGeneration != 0 {
		t.Fatalf("invalid initial receiver continuity: %#v", initial.ReceiverContinuity)
	}

	store.Add([]Span{{SpanID: "one"}})
	afterAdd := store.Snapshot("")
	if afterAdd.ReceiverContinuity != initial.ReceiverContinuity {
		t.Fatalf("adding spans changed receiver continuity: before=%#v after=%#v",
			initial.ReceiverContinuity, afterAdd.ReceiverContinuity)
	}

	firstReset := store.Reset()
	if firstReset.ReceiverInstanceID != initial.ReceiverInstanceID ||
		firstReset.ResetGeneration != initial.ResetGeneration+1 {
		t.Fatalf("first reset did not advance continuity: before=%#v after=%#v",
			initial.ReceiverContinuity, firstReset)
	}
	secondReset := store.Reset()
	if secondReset.ReceiverInstanceID != initial.ReceiverInstanceID ||
		secondReset.ResetGeneration != firstReset.ResetGeneration+1 {
		t.Fatalf("second reset did not advance continuity: first=%#v second=%#v",
			firstReset, secondReset)
	}

	other := NewStore(10, 16, 32).Snapshot("")
	if other.ReceiverInstanceID == initial.ReceiverInstanceID {
		t.Fatalf("distinct stores reused receiver instance ID %q", other.ReceiverInstanceID)
	}
}

func TestStoreRejectsBatchAdmittedBeforeReset(t *testing.T) {
	store := NewStore(10, 16, 32)
	admission := store.Continuity()
	reset := store.Reset()

	if store.AddAtIfContinuity([]Span{{SpanID: "stale"}}, time.Now(), admission) {
		t.Fatal("accepted a batch admitted before reset")
	}
	afterStale := store.Snapshot("")
	if afterStale.ReceiverContinuity != reset || afterStale.ReceivedBatches != 0 ||
		afterStale.ReceivedSpans != 0 || len(afterStale.Spans) != 0 {
		t.Fatalf("stale batch changed reset epoch: %#v", afterStale)
	}

	if !store.AddAtIfContinuity([]Span{{SpanID: "current"}}, time.Now(), reset) {
		t.Fatal("rejected a batch admitted after reset")
	}
	afterCurrent := store.Snapshot("")
	if afterCurrent.ReceivedBatches != 1 || afterCurrent.ReceivedSpans != 1 ||
		len(afterCurrent.Spans) != 1 || afterCurrent.Spans[0].SpanID != "current" {
		t.Fatalf("current batch was not retained: %#v", afterCurrent)
	}
}

func TestStoreResetAlwaysChangesContinuityAtGenerationExhaustion(t *testing.T) {
	store := NewStore(10, 16, 32)
	store.mu.Lock()
	store.resetGeneration = math.MaxUint64
	store.mu.Unlock()
	before := store.Continuity()

	after := store.Reset()
	if after == before || after.ReceiverInstanceID == before.ReceiverInstanceID ||
		after.ResetGeneration != 0 {
		t.Fatalf("reset reused exhausted continuity: before=%#v after=%#v", before, after)
	}
	if store.AddAtIfContinuity([]Span{{SpanID: "stale"}}, time.Now(), before) {
		t.Fatal("accepted a batch from the exhausted continuity namespace")
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
		{ServiceName: "apache-proxy", Kind: "CLIENT", TraceID: "trace", SpanID: "parent", ParentSpanID: "apache-server", Attributes: requestAttributes},
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

func TestAssertSnapshotW3CMatchUsesExactParentWithoutApacheSpans(t *testing.T) {
	const marker = "w3c-match-00-deadbeef"
	requestAttributes := map[string]string{
		"http.request.header.x_obi_demo_id": marker,
		"url.path":                          "/api/echo",
	}
	expectation := Expectation{
		Mode:            ModeW3CMatch,
		ApacheService:   "apache-proxy",
		JavaService:     "java-backend",
		Endpoint:        "/api/echo",
		Marker:          marker,
		W3CTraceID:      "000102030405060708090a0b0c0d0e0f",
		W3CParentSpanID: "1011121314151617",
		W3CTraceFlags:   "01",
	}
	snapshot := Snapshot{Marker: marker, Spans: []Span{{
		ServiceName:  "java-backend",
		Kind:         "SERVER",
		TraceID:      expectation.W3CTraceID,
		SpanID:       "server",
		ParentSpanID: expectation.W3CParentSpanID,
		Flags:        spanFlagsParentRemoteKnown | spanFlagsParentRemote | 1,
		Attributes:   requestAttributes,
	}}}

	if err := AssertSnapshot(snapshot, expectation); err != nil {
		t.Fatal(err)
	}

	snapshot.Spans = append(snapshot.Spans, Span{
		ServiceName: "apache-proxy",
		Kind:        "CLIENT",
		SpanID:      "unexpected-apache",
		Attributes:  requestAttributes,
	})
	if err := AssertSnapshot(snapshot, expectation); err == nil {
		t.Fatal("expected an Apache span to invalidate the controlled matching fixture")
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

func TestFlattenMarksInvalidMarkerAliasesAsConflicting(t *testing.T) {
	const marker = "basic-00-deadbeef"
	traces := ptrace.NewTraces()
	span := traces.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.Attributes().PutStr("http.request.header.x-obi-demo-id", marker)
	invalid := span.Attributes().PutEmptySlice("http.request.header.x_obi_demo_id")
	invalid.AppendEmpty().SetStr(marker)
	invalid.AppendEmpty().SetStr("other")

	flattened := Flatten(traces)
	if len(flattened) != 1 {
		t.Fatalf("expected one flattened span, got %d", len(flattened))
	}
	if !hasInvalidMarkerAttribute(flattened[0]) || !markerConflicts(flattened[0], marker) {
		t.Fatalf("invalid marker alias was not retained as conflicting evidence: %#v", flattened[0])
	}
}

func TestFlattenMarksDisagreeingValidMarkerAliasesAsConflicting(t *testing.T) {
	const marker = "basic-00-deadbeef"
	traces := ptrace.NewTraces()
	span := traces.ResourceSpans().AppendEmpty().ScopeSpans().AppendEmpty().Spans().AppendEmpty()
	span.Attributes().PutStr("http.request.header.x-obi-demo-id", marker)
	span.Attributes().PutStr("http.request.header.x_obi_demo_id", "other")

	flattened := Flatten(traces)
	if len(flattened) != 1 {
		t.Fatalf("expected one flattened span, got %d", len(flattened))
	}
	if !hasInvalidMarkerAttribute(flattened[0]) || !markerConflicts(flattened[0], marker) {
		t.Fatalf("disagreeing marker aliases were not retained as conflicting evidence: %#v", flattened[0])
	}
}
