// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracecheck

import (
	"math"
	"sync"
	"time"
)

type storedSpan struct {
	span          Span
	retainedBytes uint64
}

type Store struct {
	mu                        sync.RWMutex
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
		maxSpans:         maxSpans,
		maxValueBytes:    maxValueBytes,
		maxRetainedBytes: maxRetainedBytes,
	}
}

func (s *Store) Add(spans []Span) {
	s.AddAt(spans, time.Now())
}

func (s *Store) AddAt(spans []Span, receivedAt time.Time) {
	receivedUnixMilli := receivedAt.UnixMilli()
	if receivedUnixMilli < 0 {
		receivedUnixMilli = 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()

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

func (s *Store) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.spans = nil
	s.retainedBytes = 0
	s.receivedBatches = 0
	s.receivedSpans = 0
	s.droppedSpans = 0
	s.droppedCountSpans = 0
	s.droppedValueLimitSpans = 0
	s.droppedRetainedLimitSpans = 0
}

func (s *Store) Snapshot(marker string) Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	retained := make([]Span, 0, len(s.spans))
	for _, stored := range s.spans {
		retained = append(retained, cloneSpan(stored.span))
	}
	spans := spansForMarker(retained, marker)
	sortSpans(spans)

	return Snapshot{
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
	}
}

func spansForMarker(spans []Span, marker string) []Span {
	if marker == "" {
		return spans
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
	for _, span := range spans {
		if !MatchesMarker(span, marker) {
			continue
		}
		identity := makeSpanIdentity(span.TraceID, span.SpanID)
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
			if hasMarkerAttribute(parent) && !MatchesMarker(parent, marker) {
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
	return selected
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
