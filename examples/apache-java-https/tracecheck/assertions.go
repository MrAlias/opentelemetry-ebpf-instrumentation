// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracecheck

import (
	"encoding/hex"
	"fmt"
	"strings"
)

type AssertionMode string

const (
	ModeBridge         AssertionMode = "bridge"
	ModeDisabled       AssertionMode = "disabled"
	ModeUninstrumented AssertionMode = "uninstrumented"
	ModeW3C            AssertionMode = "w3c"
	ModeW3CMatch       AssertionMode = "w3c-match"
	ModeW3CNoOBI       AssertionMode = "w3c-no-obi"
	ModeW3CResilience  AssertionMode = "w3c-resilience"
	ModeFailOpen       AssertionMode = "fail-open"
)

type Expectation struct {
	Mode            AssertionMode
	ApacheService   string
	JavaService     string
	Endpoint        string
	Marker          string
	W3CTraceID      string
	W3CParentSpanID string
	W3CTraceFlags   string
	JavaTraceFlags  string
}

func AssertSnapshot(snapshot Snapshot, expectation Expectation) error {
	if snapshot.Marker != expectation.Marker {
		return fmt.Errorf("expected snapshot marker %q, got %q", expectation.Marker, snapshot.Marker)
	}
	if snapshot.DroppedSpans != 0 {
		return fmt.Errorf(
			"receiver dropped %d spans before the assertion (count=%d value_limit=%d retained_limit=%d)",
			snapshot.DroppedSpans,
			snapshot.DroppedCountSpans,
			snapshot.DroppedValueLimitSpans,
			snapshot.DroppedRetainedLimitSpans,
		)
	}
	if expectation.Mode == ModeUninstrumented {
		if len(snapshot.Spans) != 0 {
			return fmt.Errorf(
				"expected no instrumented spans for marker %s, got %d",
				expectation.Marker,
				len(snapshot.Spans),
			)
		}
		return nil
	}

	javaSpans := selectMarkerServerSpans(
		snapshot.Spans,
		expectation.JavaService,
		expectation.Marker,
	)
	if len(javaSpans) != 1 {
		return fmt.Errorf(
			"expected exactly one Java server span for %s with marker %s, got %d",
			expectation.Endpoint,
			expectation.Marker,
			len(javaSpans),
		)
	}
	javaSpan := javaSpans[0]
	if !MatchesEndpoint(javaSpan, expectation.Endpoint) {
		return fmt.Errorf("java server span for marker %s did not match endpoint %s", expectation.Marker, expectation.Endpoint)
	}

	var apacheServer Span
	if expectation.Mode != ModeFailOpen &&
		expectation.Mode != ModeW3CNoOBI &&
		expectation.Mode != ModeW3CResilience {
		apacheServers := selectMarkerServerSpans(
			snapshot.Spans,
			expectation.ApacheService,
			expectation.Marker,
		)
		if len(apacheServers) != 1 {
			return fmt.Errorf(
				"expected exactly one Apache inbound server span for %s with marker %s, got %d",
				expectation.Endpoint,
				expectation.Marker,
				len(apacheServers),
			)
		}
		apacheServer = apacheServers[0]
		if !MatchesEndpoint(apacheServer, expectation.Endpoint) {
			return fmt.Errorf("apache server span for marker %s did not match endpoint %s", expectation.Marker, expectation.Endpoint)
		}
		if expectation.W3CTraceID == "" && !isZeroID(apacheServer.ParentSpanID) {
			return fmt.Errorf(
				"expected Apache inbound span to be a root without an external W3C parent, got parent %s",
				apacheServer.ParentSpanID,
			)
		}
	} else if expectation.Mode != ModeW3CResilience {
		for _, span := range snapshot.Spans {
			if span.ServiceName == expectation.ApacheService && MatchesMarker(span, expectation.Marker) {
				return fmt.Errorf(
					"expected no Apache spans without OBI for marker %s, got span %s",
					expectation.Marker,
					span.SpanID,
				)
			}
		}
	}

	switch expectation.Mode {
	case ModeBridge, ModeW3CMatch:
		if remote, known := ParentRemote(javaSpan); !known || !remote {
			return fmt.Errorf(
				"expected Java server span parent to be explicitly remote, flags=%d",
				javaSpan.Flags,
			)
		}
		if isZeroID(javaSpan.ParentSpanID) {
			return fmt.Errorf("java server span %s is a root span", javaSpan.SpanID)
		}
		apacheClients := selectRequestSpans(
			snapshot.Spans,
			expectation.ApacheService,
			"CLIENT",
			expectation.Endpoint,
			expectation.Marker,
		)
		if len(apacheClients) != 1 {
			return fmt.Errorf(
				"expected exactly one Apache client candidate for marker %s, got %d",
				expectation.Marker,
				len(apacheClients),
			)
		}
		matchingParent := apacheClients[0]
		if matchingParent.TraceID != javaSpan.TraceID || matchingParent.SpanID != javaSpan.ParentSpanID {
			return fmt.Errorf(
				"expected Java parent %s/%s to identify Apache client span %s/%s",
				javaSpan.TraceID,
				javaSpan.ParentSpanID,
				matchingParent.TraceID,
				matchingParent.SpanID,
			)
		}
		if apacheServer.TraceID != matchingParent.TraceID || matchingParent.ParentSpanID != apacheServer.SpanID {
			return fmt.Errorf(
				"expected Apache client %s/%s to be a child of inbound span %s/%s",
				matchingParent.TraceID,
				matchingParent.SpanID,
				apacheServer.TraceID,
				apacheServer.SpanID,
			)
		}
		if expectation.W3CTraceID != "" {
			if err := assertExternalParent(apacheServer, expectation); err != nil {
				return fmt.Errorf("apache inbound span: %w", err)
			}
		}
		if err := assertExpectedTraceFlags(matchingParent, expectation.W3CTraceFlags); err != nil {
			return fmt.Errorf("apache candidate span: %w", err)
		}
		if expectation.JavaTraceFlags != "" {
			if err := assertExpectedTraceFlags(javaSpan, expectation.JavaTraceFlags); err != nil {
				return fmt.Errorf("java server span: %w", err)
			}
		} else if TraceFlags(javaSpan) != TraceFlags(matchingParent) {
			return fmt.Errorf(
				"expected Java trace flags %02x to match Apache candidate flags %02x",
				TraceFlags(javaSpan),
				TraceFlags(matchingParent),
			)
		}
	case ModeDisabled, ModeFailOpen:
		if !isZeroID(javaSpan.ParentSpanID) {
			return fmt.Errorf("expected Java root span, got parent %s", javaSpan.ParentSpanID)
		}
	case ModeW3C, ModeW3CNoOBI, ModeW3CResilience:
		if remote, known := ParentRemote(javaSpan); !known || !remote {
			return fmt.Errorf(
				"expected W3C Java server parent to be explicitly remote, flags=%d",
				javaSpan.Flags,
			)
		}
		if !strings.EqualFold(javaSpan.TraceID, expectation.W3CTraceID) {
			return fmt.Errorf("expected W3C trace ID %s, got %s", expectation.W3CTraceID, javaSpan.TraceID)
		}
		if !strings.EqualFold(javaSpan.ParentSpanID, expectation.W3CParentSpanID) {
			return fmt.Errorf("expected W3C parent span ID %s, got %s", expectation.W3CParentSpanID, javaSpan.ParentSpanID)
		}
		if err := assertExpectedTraceFlags(javaSpan, expectation.W3CTraceFlags); err != nil {
			return fmt.Errorf("java server span with W3C parent: %w", err)
		}
		if expectation.Mode == ModeW3C {
			if err := assertExternalParent(apacheServer, expectation); err != nil {
				return fmt.Errorf("apache inbound span: %w", err)
			}
			apacheClients := selectRequestSpans(
				snapshot.Spans,
				expectation.ApacheService,
				"CLIENT",
				expectation.Endpoint,
				expectation.Marker,
			)
			if len(apacheClients) != 1 {
				return fmt.Errorf(
					"expected one conflicting OBI candidate for W3C marker %s, got %d",
					expectation.Marker,
					len(apacheClients),
				)
			}
			candidate := apacheClients[0]
			if !strings.EqualFold(candidate.TraceID, apacheServer.TraceID) ||
				!strings.EqualFold(candidate.ParentSpanID, apacheServer.SpanID) {
				return fmt.Errorf(
					"expected conflicting OBI candidate %s/%s to be a child of Apache inbound span %s/%s",
					candidate.TraceID,
					candidate.SpanID,
					apacheServer.TraceID,
					apacheServer.SpanID,
				)
			}
			if strings.EqualFold(candidate.SpanID, expectation.W3CParentSpanID) {
				return fmt.Errorf(
					"expected OBI candidate to conflict with W3C parent %s/%s",
					expectation.W3CTraceID,
					expectation.W3CParentSpanID,
				)
			}
			if err := assertExpectedTraceFlags(candidate, expectation.W3CTraceFlags); err != nil {
				return fmt.Errorf("conflicting OBI candidate span: %w", err)
			}
		}
	default:
		return fmt.Errorf("unsupported assertion mode %q", expectation.Mode)
	}

	return nil
}

func assertExternalParent(span Span, expectation Expectation) error {
	if !strings.EqualFold(span.TraceID, expectation.W3CTraceID) {
		return fmt.Errorf("expected trace ID %s, got %s", expectation.W3CTraceID, span.TraceID)
	}
	if !strings.EqualFold(span.ParentSpanID, expectation.W3CParentSpanID) {
		return fmt.Errorf("expected parent span ID %s, got %s", expectation.W3CParentSpanID, span.ParentSpanID)
	}
	return assertExpectedTraceFlags(span, expectation.W3CTraceFlags)
}

func assertExpectedTraceFlags(span Span, expected string) error {
	if expected == "" {
		return nil
	}
	decoded, err := hex.DecodeString(expected)
	if err != nil || len(decoded) != 1 {
		return fmt.Errorf("invalid expected trace flags %q", expected)
	}
	if actual := TraceFlags(span); actual != decoded[0] {
		return fmt.Errorf("expected trace flags %02x, got %02x", decoded[0], actual)
	}
	return nil
}

func selectMarkerServerSpans(spans []Span, serviceName, marker string) []Span {
	var selected []Span
	for _, span := range spans {
		if span.ServiceName == serviceName &&
			strings.EqualFold(span.Kind, "SERVER") &&
			MatchesMarker(span, marker) {
			selected = append(selected, span)
		}
	}
	return selected
}

func selectRequestSpans(spans []Span, serviceName, kind, endpoint, marker string) []Span {
	var selected []Span
	for _, span := range spans {
		if span.ServiceName == serviceName &&
			strings.EqualFold(span.Kind, kind) &&
			MatchesEndpoint(span, endpoint) &&
			MatchesMarker(span, marker) {
			selected = append(selected, span)
		}
	}
	return selected
}

func isZeroID(id string) bool {
	return id == "" || strings.Trim(id, "0") == ""
}
