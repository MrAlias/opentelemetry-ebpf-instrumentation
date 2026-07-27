// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package tracesgen // import "go.opentelemetry.io/obi/pkg/export/otel/tracesgen"

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
)

// GroupSpans retains OBI's request-span grouping and sampling boundary for the
// native Windows frontend.
func GroupSpans(
	ctx context.Context,
	spans []request.Span,
	optionalAttrs map[attr.Name]struct{},
	sampler sdktrace.Sampler,
	_ instrumentations.InstrumentationSelection,
	redactKeys ...string,
) map[svc.UID][]TraceSpanAndAttributes {
	spanGroups := map[svc.UID][]TraceSpanAndAttributes{}
	redactSet := buildRedactSet(redactKeys)

	for index := range spans {
		span := &spans[index]
		if span.InternalSignal() || request.IgnoreTraces(span) || span.Service.ExportsOTelTraces() {
			continue
		}

		var attributes []attribute.KeyValue
		var kind trace.SpanKind
		switch span.Type {
		case request.EventTypeManualSpan:
			attributes = manualSpanAttributes(span)
			kind = trace.SpanKindInternal
		case request.EventTypeHTTP:
			attributes = httpServerTraceAttributes(span, optionalAttrs, redactSet)
			attributes = append(attributes, attribute.Int64("process.pid", int64(span.Pid.HostPID)))
			kind = trace.SpanKindServer
		default:
			continue
		}

		spanSampler := sampler
		if span.Service.Sampler != nil {
			spanSampler = span.Service.Sampler
		}
		samplingResult := spanSampler.ShouldSample(sdktrace.SamplingParameters{
			ParentContext: ctx,
			TraceID:       span.TraceID,
			Name:          span.TraceName(),
			Kind:          kind,
			Attributes:    attributes,
		})
		if samplingResult.Decision == sdktrace.Drop {
			continue
		}

		spanGroups[span.Service.UID] = append(
			spanGroups[span.Service.UID],
			TraceSpanAndAttributes{Span: span, Attributes: attributes},
		)
	}

	return spanGroups
}

func manualSpanAttributes(span *request.Span) []attribute.KeyValue {
	if span.Statement == "" {
		return nil
	}

	var encodedAttributes []SpanAttr
	if err := json.Unmarshal([]byte(span.Statement), &encodedAttributes); err != nil {
		fmt.Println(err)
		return nil
	}

	attributes := make([]attribute.KeyValue, 0, len(encodedAttributes))
	for _, encoded := range encodedAttributes {
		key := nullTerminatedString(encoded.Key[:])
		switch encoded.Vtype {
		case uint8(attribute.BOOL):
			attributes = append(attributes, attribute.Bool(key, encoded.Value[0] != 0))
		case uint8(attribute.INT64):
			value := binary.LittleEndian.Uint64(encoded.Value[:8])
			attributes = append(attributes, attribute.Int64(key, int64(value)))
		case uint8(attribute.FLOAT64):
			value := math.Float64frombits(binary.LittleEndian.Uint64(encoded.Value[:8]))
			attributes = append(attributes, attribute.Float64(key, value))
		case uint8(attribute.STRING):
			attributes = append(attributes, attribute.String(key, nullTerminatedString(encoded.Value[:])))
		}
	}
	return attributes
}

func nullTerminatedString(value []byte) string {
	if end := bytes.IndexByte(value, 0); end >= 0 {
		value = value[:end]
	}
	return string(value)
}
