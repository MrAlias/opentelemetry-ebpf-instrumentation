// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracecheck

import (
	"crypto/rand"
	"math"
	"strings"
	"sync"
	"time"
)

const (
	maxRelatedSpans         = 256
	maxRelatedValueBytes    = 1024
	maxRelatedRetainedBytes = 256 * 1024
)

type storedSpan struct {
	span          Span
	retainedBytes uint64
}

type markerRelation uint8

const (
	markerRelationUnknown markerRelation = iota
	markerRelationVisiting
	markerRelationWanted
	markerRelationDifferent
	markerRelationAmbiguous
)

type duplicateMarkerInfo struct {
	relevant               bool
	exactMarker            bool
	allExplicitlyDifferent bool
}

type Store struct {
	mu                        sync.RWMutex
	receiverInstanceID        string
	resetGeneration           uint64
	maxSpans                  int
	maxValueBytes             uint64
	maxRetainedBytes          uint64
	spans                     []storedSpan
	retainedBytes             uint64
	receivedBatches           uint64
	receivedSpans             uint64
	droppedSpans              uint64
	droppedCountSpans         uint64
	droppedValueLimitSpans    uint64
	droppedRetainedLimitSpans uint64
}

func NewStore(maxSpans int, maxValueBytes, maxRetainedBytes uint64) *Store {
	if maxSpans < 1 {
		maxSpans = 1
	}
	if maxValueBytes < 1 {
		maxValueBytes = 1
	}
	if maxRetainedBytes < 1 {
		maxRetainedBytes = 1
	}
	return &Store{
		receiverInstanceID: rand.Text(),
		maxSpans:           maxSpans,
		maxValueBytes:      maxValueBytes,
		maxRetainedBytes:   maxRetainedBytes,
	}
}

func (s *Store) Add(spans []Span) {
	s.AddAt(spans, time.Now())
}

func (s *Store) AddAt(spans []Span, receivedAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.addAtLocked(spans, receivedAt)
}

// AddAtIfContinuity adds a batch only when the receiver has not reset since
// the caller captured expected. This fences a single request attempt admitted
// before a reset from repopulating the new receiver epoch after body decoding
// completes. A later HTTP retry is a new admission and needs a run-unique
// marker plus bounded settlement at the polling layer.
func (s *Store) AddAtIfContinuity(
	spans []Span,
	receivedAt time.Time,
	expected ReceiverContinuity,
) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.receiverContinuityLocked() != expected {
		return false
	}
	s.addAtLocked(spans, receivedAt)
	return true
}

func (s *Store) addAtLocked(spans []Span, receivedAt time.Time) {
	receivedUnixMilli := receivedAt.UnixMilli()
	if receivedUnixMilli < 0 {
		receivedUnixMilli = 0
	}

	s.receivedBatches = saturatingAdd(s.receivedBatches, 1)
	s.receivedSpans = saturatingAdd(s.receivedSpans, uint64(len(spans)))
	for _, span := range spans {
		span = cloneSpan(span)
		span.ReceivedUnixMilli = uint64(receivedUnixMilli)
		retainedBytes, valueLimitExceeded, ok := spanRetainedBytes(span, s.maxValueBytes)
		if valueLimitExceeded {
			s.recordDrop(&s.droppedValueLimitSpans)
			continue
		}
		if !ok || retainedBytes > s.maxRetainedBytes {
			s.recordDrop(&s.droppedRetainedLimitSpans)
			continue
		}

		for len(s.spans) > 0 && s.retainedBytes > s.maxRetainedBytes-retainedBytes {
			s.dropOldest(&s.droppedRetainedLimitSpans)
		}
		s.retainedBytes += retainedBytes
		s.spans = append(s.spans, storedSpan{span: span, retainedBytes: retainedBytes})
		for len(s.spans) > s.maxSpans {
			s.dropOldest(&s.droppedCountSpans)
		}
	}
}

func (s *Store) Continuity() ReceiverContinuity {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.receiverContinuityLocked()
}

func cloneSpan(span Span) Span {
	if span.Attributes == nil {
		return span
	}
	attributes := make(map[string]string, len(span.Attributes))
	for key, value := range span.Attributes {
		attributes[key] = value
	}
	span.Attributes = attributes
	return span
}

func (s *Store) Reset() ReceiverContinuity {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.advanceResetContinuityLocked()
	s.spans = nil
	s.retainedBytes = 0
	s.receivedBatches = 0
	s.receivedSpans = 0
	s.droppedSpans = 0
	s.droppedCountSpans = 0
	s.droppedValueLimitSpans = 0
	s.droppedRetainedLimitSpans = 0
	return s.receiverContinuityLocked()
}

func (s *Store) advanceResetContinuityLocked() {
	if s.resetGeneration < math.MaxUint64 {
		s.resetGeneration++
		return
	}

	// A reset must always change the continuity pair. Rotate the opaque
	// namespace before restarting the generation counter at exhaustion.
	previous := s.receiverInstanceID
	for s.receiverInstanceID == previous {
		s.receiverInstanceID = rand.Text()
	}
	s.resetGeneration = 0
}

func (s *Store) Snapshot(marker string) Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	retained := make([]Span, 0, len(s.spans))
	for _, stored := range s.spans {
		retained = append(retained, cloneSpan(stored.span))
	}
	spans, relatedSpans, omittedRelatedSpans, ambiguousRelatedSpans := spansForMarker(retained, marker)
	sortSpans(spans)

	return Snapshot{
		ReceiverContinuity:        s.receiverContinuityLocked(),
		Marker:                    marker,
		ReceivedBatches:           s.receivedBatches,
		ReceivedSpans:             s.receivedSpans,
		DroppedSpans:              s.droppedSpans,
		DroppedCountSpans:         s.droppedCountSpans,
		DroppedValueLimitSpans:    s.droppedValueLimitSpans,
		DroppedRetainedLimitSpans: s.droppedRetainedLimitSpans,
		RetainedBytes:             s.retainedBytes,
		MaxRetainedBytes:          s.maxRetainedBytes,
		MaxValueBytes:             s.maxValueBytes,
		Spans:                     spans,
		RelatedSpans:              relatedSpans,
		OmittedRelatedSpans:       omittedRelatedSpans,
		AmbiguousRelatedSpans:     ambiguousRelatedSpans,
	}
}

func (s *Store) receiverContinuityLocked() ReceiverContinuity {
	return ReceiverContinuity{
		ReceiverInstanceID: s.receiverInstanceID,
		ResetGeneration:    s.resetGeneration,
	}
}

func spansForMarker(spans []Span, marker string) ([]Span, []Span, uint64, uint64) {
	if marker == "" {
		return spans, nil, 0, 0
	}

	byIdentity := make(map[spanIdentity]Span, len(spans))
	duplicates := make(map[spanIdentity]struct{})
	for _, span := range spans {
		identity := makeSpanIdentity(span.TraceID, span.SpanID)
		if _, duplicate := duplicates[identity]; duplicate {
			continue
		}
		if _, exists := byIdentity[identity]; exists {
			delete(byIdentity, identity)
			duplicates[identity] = struct{}{}
			continue
		}
		byIdentity[identity] = span
	}

	included := make(map[spanIdentity]struct{}, len(spans))
	selectedTraces := make(map[string]struct{})
	boundaryParents := make(map[spanIdentity]struct{})
	for _, span := range spans {
		if hasInvalidMarkerAttribute(span) || !MatchesMarker(span, marker) {
			continue
		}
		identity := makeSpanIdentity(span.TraceID, span.SpanID)
		if !isZeroID(span.TraceID) {
			selectedTraces[identity.traceID] = struct{}{}
		}
		if !isZeroID(span.TraceID) && strings.EqualFold(span.Kind, "SERVER") &&
			!isZeroID(span.ParentSpanID) {
			boundaryParents[makeSpanIdentity(span.TraceID, span.ParentSpanID)] = struct{}{}
		}
		if _, duplicate := duplicates[identity]; duplicate {
			continue
		}

		current := span
		for {
			identity = makeSpanIdentity(current.TraceID, current.SpanID)
			if _, duplicate := duplicates[identity]; duplicate {
				break
			}
			if _, exists := included[identity]; exists {
				break
			}
			included[identity] = struct{}{}

			if isZeroID(current.ParentSpanID) {
				break
			}
			parent, exists := byIdentity[makeSpanIdentity(current.TraceID, current.ParentSpanID)]
			if !exists {
				break
			}
			if hasInvalidMarkerAttribute(parent) ||
				hasMarkerAttribute(parent) && !MatchesMarker(parent, marker) {
				break
			}
			current = parent
		}
	}

	selected := make([]Span, 0, len(included))
	for _, span := range spans {
		identity := makeSpanIdentity(span.TraceID, span.SpanID)
		if _, duplicate := duplicates[identity]; duplicate {
			continue
		}
		if _, exists := included[identity]; exists {
			selected = append(selected, span)
		}
	}

	ambiguousIdentities := make(map[spanIdentity]struct{})
	duplicateInfo := make(map[spanIdentity]duplicateMarkerInfo, len(duplicates))
	for identity := range duplicates {
		duplicateInfo[identity] = duplicateMarkerInfo{allExplicitlyDifferent: true}
	}
	for _, span := range spans {
		identity := makeSpanIdentity(span.TraceID, span.SpanID)
		info, duplicate := duplicateInfo[identity]
		if !duplicate {
			continue
		}
		_, sharesBoundaryParent := boundaryParents[makeSpanIdentity(span.TraceID, span.ParentSpanID)]
		info.relevant = info.relevant || strings.EqualFold(span.Kind, "SERVER") || sharesBoundaryParent
		if hasInvalidMarkerAttribute(span) || !hasMarkerAttribute(span) {
			info.allExplicitlyDifferent = false
		} else if MatchesMarker(span, marker) {
			info.exactMarker = true
			info.allExplicitlyDifferent = false
		}
		duplicateInfo[identity] = info
	}
	for identity, info := range duplicateInfo {
		if info.exactMarker {
			ambiguousIdentities[identity] = struct{}{}
			continue
		}
		if _, selectedTrace := selectedTraces[identity.traceID]; !selectedTrace {
			continue
		}
		if info.relevant && !info.allExplicitlyDifferent {
			ambiguousIdentities[identity] = struct{}{}
		}
	}

	relations := make(map[spanIdentity]markerRelation, len(byIdentity)+len(duplicates))
	related := make([]Span, 0)
	for _, span := range spans {
		identity := makeSpanIdentity(span.TraceID, span.SpanID)
		if _, duplicate := duplicates[identity]; duplicate {
			continue
		}
		if _, exists := included[identity]; exists {
			continue
		}
		if _, selectedTrace := selectedTraces[identity.traceID]; !selectedTrace {
			continue
		}
		_, sharesBoundaryParent := boundaryParents[makeSpanIdentity(span.TraceID, span.ParentSpanID)]
		if !strings.EqualFold(span.Kind, "SERVER") && !sharesBoundaryParent {
			continue
		}
		relation := relationToMarker(identity, marker, byIdentity, duplicates, relations)
		if relation == markerRelationAmbiguous {
			ambiguousIdentities[identity] = struct{}{}
			continue
		}
		if relation != markerRelationWanted {
			continue
		}
		related = append(related, redactedRelatedSpan(span))
	}
	sortSpans(related)
	boundedRelated := make([]Span, 0, min(len(related), maxRelatedSpans))
	omitted := uint64(0)
	retainedBytes := uint64(0)
	for _, span := range related {
		spanBytes, valueLimitExceeded, ok := spanRetainedBytes(span, maxRelatedValueBytes)
		if valueLimitExceeded || !ok || spanBytes > maxRelatedRetainedBytes-retainedBytes ||
			len(boundedRelated) == maxRelatedSpans {
			omitted = saturatingAdd(omitted, 1)
			continue
		}
		retainedBytes += spanBytes
		boundedRelated = append(boundedRelated, span)
	}
	return selected, boundedRelated, omitted, uint64(len(ambiguousIdentities))
}

func relationToMarker(
	start spanIdentity,
	marker string,
	byIdentity map[spanIdentity]Span,
	duplicates map[spanIdentity]struct{},
	relations map[spanIdentity]markerRelation,
) markerRelation {
	if relation := relations[start]; relation != markerRelationUnknown {
		if relation == markerRelationVisiting {
			return markerRelationAmbiguous
		}
		return relation
	}

	path := make([]spanIdentity, 0)
	current := start
	result := markerRelationAmbiguous
	for {
		relation := relations[current]
		if relation != markerRelationUnknown {
			if relation == markerRelationVisiting {
				result = markerRelationAmbiguous
			} else {
				result = relation
			}
			break
		}
		relations[current] = markerRelationVisiting
		path = append(path, current)

		if _, duplicate := duplicates[current]; duplicate {
			break
		}
		span, exists := byIdentity[current]
		if !exists || hasInvalidMarkerAttribute(span) {
			break
		}
		if hasMarkerAttribute(span) {
			if MatchesMarker(span, marker) {
				result = markerRelationWanted
			} else {
				result = markerRelationDifferent
			}
			break
		}
		if isZeroID(span.ParentSpanID) {
			result = markerRelationWanted
			break
		}
		current = makeSpanIdentity(span.TraceID, span.ParentSpanID)
	}
	for _, identity := range path {
		relations[identity] = result
	}
	return result
}

func redactedRelatedSpan(span Span) Span {
	return Span{
		TraceID:           span.TraceID,
		SpanID:            span.SpanID,
		ParentSpanID:      span.ParentSpanID,
		Flags:             span.Flags,
		ServiceName:       span.ServiceName,
		Kind:              span.Kind,
		StartUnixNano:     span.StartUnixNano,
		EndUnixNano:       span.EndUnixNano,
		ReceivedUnixMilli: span.ReceivedUnixMilli,
	}
}

func (s *Store) recordDrop(reason *uint64) {
	s.droppedSpans = saturatingAdd(s.droppedSpans, 1)
	*reason = saturatingAdd(*reason, 1)
}

func (s *Store) dropOldest(reason *uint64) {
	oldest := s.spans[0]
	if oldest.retainedBytes > s.retainedBytes {
		s.retainedBytes = 0
	} else {
		s.retainedBytes -= oldest.retainedBytes
	}
	copy(s.spans, s.spans[1:])
	s.spans[len(s.spans)-1] = storedSpan{}
	s.spans = s.spans[:len(s.spans)-1]
	s.recordDrop(reason)
}

func spanRetainedBytes(span Span, maxValueBytes uint64) (uint64, bool, bool) {
	values := []string{
		span.TraceID,
		span.SpanID,
		span.ParentSpanID,
		span.ServiceName,
		span.ScopeName,
		span.Name,
		span.Kind,
	}
	for key, value := range span.Attributes {
		values = append(values, key, value)
	}

	var total uint64
	for _, value := range values {
		valueBytes := uint64(len(value))
		if valueBytes > maxValueBytes {
			return 0, true, true
		}
		if math.MaxUint64-total < valueBytes {
			return 0, false, false
		}
		total += valueBytes
	}
	return total, false, true
}

func saturatingAdd(left, right uint64) uint64 {
	if math.MaxUint64-left < right {
		return math.MaxUint64
	}
	return left + right
}
