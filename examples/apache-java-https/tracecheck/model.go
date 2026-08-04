// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracecheck

import (
	"net/url"
	"sort"
	"strings"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
)

const MarkerHeader = "x-obi-demo-id"

const invalidMarkerAttribute = "obi.related.marker.invalid"

const (
	spanFlagsParentRemoteKnown = uint32(1 << 8)
	spanFlagsParentRemote      = uint32(1 << 9)
	spanFlagsTraceMask         = uint32(0xff)
)

// Span is the deliberately small, machine-readable trace representation kept
// by the demo receiver. It excludes request bodies and arbitrary headers.
type Span struct {
	TraceID           string            `json:"trace_id"`
	SpanID            string            `json:"span_id"`
	ParentSpanID      string            `json:"parent_span_id,omitempty"`
	Flags             uint32            `json:"flags"`
	ServiceName       string            `json:"service_name"`
	ScopeName         string            `json:"scope_name,omitempty"`
	Name              string            `json:"name"`
	Kind              string            `json:"kind"`
	Attributes        map[string]string `json:"attributes,omitempty"`
	StartUnixNano     uint64            `json:"start_unix_nano"`
	EndUnixNano       uint64            `json:"end_unix_nano"`
	ReceivedUnixMilli uint64            `json:"received_unix_milli"`
}

type spanIdentity struct {
	traceID string
	spanID  string
}

// Snapshot contains all bounded receiver state relevant to an assertion.
type Snapshot struct {
	Marker                    string `json:"marker,omitempty"`
	ReceivedBatches           uint64 `json:"received_batches"`
	ReceivedSpans             uint64 `json:"received_spans"`
	DroppedSpans              uint64 `json:"dropped_spans"`
	DroppedCountSpans         uint64 `json:"dropped_count_spans"`
	DroppedValueLimitSpans    uint64 `json:"dropped_value_limit_spans"`
	DroppedRetainedLimitSpans uint64 `json:"dropped_retained_limit_spans"`
	RetainedBytes             uint64 `json:"retained_bytes"`
	MaxRetainedBytes          uint64 `json:"max_retained_bytes"`
	MaxValueBytes             uint64 `json:"max_value_bytes"`
	Spans                     []Span `json:"spans"`
	RelatedSpans              []Span `json:"related_spans,omitempty"`
	OmittedRelatedSpans       uint64 `json:"omitted_related_spans,omitempty"`
	AmbiguousRelatedSpans     uint64 `json:"ambiguous_related_spans,omitempty"`
}

func Flatten(traces ptrace.Traces) []Span {
	var result []Span
	for _, resourceSpans := range traces.ResourceSpans().All() {
		serviceName := attributeString(resourceSpans.Resource().Attributes(), "service.name")
		for _, scopeSpans := range resourceSpans.ScopeSpans().All() {
			scopeName := scopeSpans.Scope().Name()
			for _, source := range scopeSpans.Spans().All() {
				attributes := make(map[string]string)
				source.Attributes().Range(func(key string, value pcommon.Value) bool {
					if keepAttribute(key) {
						if normalized, ok := normalizedAttributeValue(key, value); ok {
							attributes[key] = normalized
						} else if isMarkerAttribute(key) {
							attributes[invalidMarkerAttribute] = "true"
						}
					}
					return true
				})
				if markerValuesConflict(attributes) {
					attributes[invalidMarkerAttribute] = "true"
				}

				result = append(result, Span{
					TraceID:       source.TraceID().String(),
					SpanID:        source.SpanID().String(),
					ParentSpanID:  source.ParentSpanID().String(),
					Flags:         source.Flags(),
					ServiceName:   serviceName,
					ScopeName:     scopeName,
					Name:          source.Name(),
					Kind:          strings.ToUpper(source.Kind().String()),
					Attributes:    attributes,
					StartUnixNano: uint64(source.StartTimestamp()),
					EndUnixNano:   uint64(source.EndTimestamp()),
				})
			}
		}
	}

	sortSpans(result)
	return result
}

func ParentRemote(span Span) (remote bool, known bool) {
	return span.Flags&spanFlagsParentRemote != 0,
		span.Flags&spanFlagsParentRemoteKnown != 0
}

func TraceFlags(span Span) byte {
	return byte(span.Flags & spanFlagsTraceMask)
}

func MatchesMarker(span Span, marker string) bool {
	if marker == "" {
		return true
	}
	matched := false
	for key, value := range span.Attributes {
		if !isMarkerAttribute(key) {
			continue
		}
		if value != marker {
			return false
		}
		matched = true
	}
	return matched
}

func hasMarkerAttribute(span Span) bool {
	for key := range span.Attributes {
		if isMarkerAttribute(key) {
			return true
		}
	}
	return false
}

func hasInvalidMarkerAttribute(span Span) bool {
	return span.Attributes[invalidMarkerAttribute] == "true" ||
		markerValuesConflict(span.Attributes)
}

func markerValuesConflict(attributes map[string]string) bool {
	var first string
	found := false
	for key, value := range attributes {
		if !isMarkerAttribute(key) {
			continue
		}
		if found && value != first {
			return true
		}
		first = value
		found = true
	}
	return false
}

func makeSpanIdentity(traceID, spanID string) spanIdentity {
	return spanIdentity{traceID: strings.ToLower(traceID), spanID: strings.ToLower(spanID)}
}

func MatchesEndpoint(span Span, endpoint string) bool {
	if endpoint == "" {
		return false
	}
	for _, key := range []string{"http.route", "url.path"} {
		if span.Attributes[key] == endpoint {
			return true
		}
	}
	for _, key := range []string{"http.target", "http.url", "url.full"} {
		value := span.Attributes[key]
		if value == "" {
			continue
		}
		parsed, err := url.Parse(value)
		if err == nil && parsed.Path == endpoint {
			return true
		}
	}
	return false
}

func sortSpans(spans []Span) {
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].TraceID != spans[j].TraceID {
			return spans[i].TraceID < spans[j].TraceID
		}
		if spans[i].StartUnixNano != spans[j].StartUnixNano {
			return spans[i].StartUnixNano < spans[j].StartUnixNano
		}
		return spans[i].SpanID < spans[j].SpanID
	})
}

func attributeString(attributes pcommon.Map, key string) string {
	value, ok := attributes.Get(key)
	if !ok {
		return ""
	}
	return value.AsString()
}

func normalizedAttributeValue(key string, value pcommon.Value) (string, bool) {
	if !isMarkerAttribute(key) {
		return value.AsString(), true
	}

	switch value.Type() {
	case pcommon.ValueTypeStr:
		return value.Str(), true
	case pcommon.ValueTypeSlice:
		values := value.Slice()
		if values.Len() == 1 && values.At(0).Type() == pcommon.ValueTypeStr {
			return values.At(0).Str(), true
		}
	}
	return "", false
}

func isMarkerAttribute(key string) bool {
	switch strings.ToLower(key) {
	case "http.request.header.x-obi-demo-id", "http.request.header.x_obi_demo_id":
		return true
	default:
		return false
	}
}

func keepAttribute(key string) bool {
	if isMarkerAttribute(key) {
		return true
	}

	switch key {
	case "http.request.method",
		"http.response.status_code",
		"http.route",
		"http.target",
		"http.url",
		"url.full",
		"url.path",
		"server.address",
		"server.port",
		"network.protocol.name",
		"network.protocol.version",
		"tls.protocol.version",
		"tls.cipher.name":
		return true
	default:
		return false
	}
}
