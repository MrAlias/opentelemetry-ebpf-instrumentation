// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracesgen // import "go.opentelemetry.io/obi/pkg/export/otel/tracesgen"

import (
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
	oteltrace "go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/otel/idgen"
	"go.opentelemetry.io/obi/pkg/export/otel/resourceattrs"
)

// ReporterName is OBI's OTLP reporter identity. The current pdata path emits
// it as the resource attribute otel.scope.name.
const ReporterName = "go.opentelemetry.io/obi"

type TraceSpanAndAttributes struct {
	Span       *request.Span
	Attributes []attribute.KeyValue
}

type SpanAttr struct {
	ValLength uint16
	Vtype     uint8
	Reserved  uint8
	Key       [32]uint8
	Value     [128]uint8
}

// GenerateWindowsTraces uses OBI's shared resource and pdata trace
// construction after the Windows frontend has grouped native events.
func GenerateWindowsTraces(
	service *svc.Attrs,
	spans []TraceSpanAndAttributes,
) ptrace.Traces {
	return generateTracesFromResourceAttributes(
		resourceattrs.ForApp(service, semconv.OSTypeWindows, nil),
		nil,
		spans,
		ReporterName,
	)
}

// GenerateWindowsProcessTraces preserves the process-start proof-of-concept API.
func GenerateWindowsProcessTraces(
	service *svc.Attrs,
	spans []TraceSpanAndAttributes,
) ptrace.Traces {
	return GenerateWindowsTraces(service, spans)
}

func generateTracesFromResourceAttributes(
	resourceAttrs []attribute.KeyValue,
	extraResourceAttrs []attribute.KeyValue,
	spans []TraceSpanAndAttributes,
	reporterName string,
) ptrace.Traces {
	traces := ptrace.NewTraces()
	resourceSpans := traces.ResourceSpans().AppendEmpty()
	resourceAttrsMap := AttrsToMap(resourceAttrs)
	resourceAttrsMap.PutStr(string(semconv.OTelScopeNameKey), reporterName)
	addAttrsToMap(extraResourceAttrs, resourceAttrsMap)
	resourceAttrsMap.MoveTo(resourceSpans.Resource().Attributes())

	for _, spanWithAttributes := range spans {
		span := spanWithAttributes.Span
		attrs := spanWithAttributes.Attributes

		// OBI's current pdata format carries reporterName in the resource's
		// otel.scope.name and leaves instrumentation scope name/version empty.
		scopeSpans := resourceSpans.ScopeSpans().AppendEmpty()

		timings := span.Timings()
		start := spanStartTime(timings)
		hasSubSpans := timings.Start.After(start)

		traceID := pcommon.TraceID(span.TraceID)
		spanID := pcommon.SpanID(idgen.RandomSpanID())
		if traceID.IsEmpty() {
			traceID = pcommon.TraceID(idgen.RandomTraceID())
		}

		if hasSubSpans {
			createSubSpans(span, spanID, traceID, &scopeSpans, timings)
		} else if span.SpanID.IsValid() {
			spanID = pcommon.SpanID(span.SpanID)
		}

		otelSpan := scopeSpans.Spans().AppendEmpty()
		otelSpan.SetName(span.TraceName())
		otelSpan.SetKind(ptrace.SpanKind(spanKind(span)))
		otelSpan.SetStartTimestamp(pcommon.NewTimestampFromTime(start))
		otelSpan.SetSpanID(spanID)
		otelSpan.SetTraceID(traceID)
		if span.ParentSpanID.IsValid() {
			otelSpan.SetParentSpanID(pcommon.SpanID(span.ParentSpanID))
		}

		spanAttrs := AttrsToMap(attrs)
		var dbResponseError string
		if dbErr, ok := spanAttrs.Get(string(attr.DBResponseError.OTEL())); ok {
			dbResponseError = request.SpanDBStatusMessage(span, dbErr.AsString())
		}
		spanAttrs.Remove(string(attr.DBResponseError.OTEL()))
		spanAttrs.MoveTo(otelSpan.Attributes())

		otelSpan.Status().SetCode(CodeToStatusCode(request.SpanStatusCode(span)))
		var statusMessage string
		if span.IsDBSpan() {
			statusMessage = dbResponseError
		} else {
			statusMessage = request.SpanStatusMessage(span)
		}
		if statusMessage != "" {
			otelSpan.Status().SetMessage(statusMessage)
		}
		if !hasSubSpans {
			appendSpanLinks(otelSpan, span.Links)
		}
		otelSpan.SetEndTimestamp(pcommon.NewTimestampFromTime(timings.End))

		if toolCalls := getSpanToolCalls(span); len(toolCalls) > 0 {
			createToolCallSpans(toolCalls, spanID, traceID, &scopeSpans, start, timings.End)
		}
	}

	return traces
}

func createSubSpans(
	span *request.Span,
	parentSpanID pcommon.SpanID,
	traceID pcommon.TraceID,
	scopeSpans *ptrace.ScopeSpans,
	timings request.Timings,
) {
	queueSpan := scopeSpans.Spans().AppendEmpty()
	queueSpan.SetName("in queue")
	queueSpan.SetStartTimestamp(pcommon.NewTimestampFromTime(timings.RequestStart))
	queueSpan.SetKind(ptrace.SpanKindInternal)
	queueSpan.SetEndTimestamp(pcommon.NewTimestampFromTime(timings.Start))
	queueSpan.SetTraceID(traceID)
	queueSpan.SetSpanID(pcommon.SpanID(idgen.RandomSpanID()))
	queueSpan.SetParentSpanID(parentSpanID)

	processingSpan := scopeSpans.Spans().AppendEmpty()
	processingSpan.SetName("processing")
	processingSpan.SetStartTimestamp(pcommon.NewTimestampFromTime(timings.Start))
	processingSpan.SetKind(ptrace.SpanKindInternal)
	processingSpan.SetEndTimestamp(pcommon.NewTimestampFromTime(timings.End))
	processingSpan.SetTraceID(traceID)
	if span.SpanID.IsValid() {
		processingSpan.SetSpanID(pcommon.SpanID(span.SpanID))
	} else {
		processingSpan.SetSpanID(pcommon.SpanID(idgen.RandomSpanID()))
	}
	processingSpan.SetParentSpanID(parentSpanID)
	appendSpanLinks(processingSpan, span.Links)
}

func appendSpanLinks(destination ptrace.Span, links []request.SpanLink) {
	for _, spanLink := range links {
		if !spanLink.TraceID.IsValid() || !spanLink.SpanID.IsValid() {
			continue
		}

		link := destination.Links().AppendEmpty()
		link.SetTraceID(pcommon.TraceID(spanLink.TraceID))
		link.SetSpanID(pcommon.SpanID(spanLink.SpanID))
		link.SetFlags(uint32(spanLink.TraceFlags))
	}
}

// AttrsToMap converts a slice of attribute.KeyValue to a pcommon.Map.
func AttrsToMap(attrs []attribute.KeyValue) pcommon.Map {
	result := pcommon.NewMap()
	addAttrsToMap(attrs, result)
	return result
}

func addAttrsToMap(attrs []attribute.KeyValue, destination pcommon.Map) {
	destination.EnsureCapacity(destination.Len() + len(attrs))
	for _, attr := range attrs {
		switch value := attr.Value.AsInterface().(type) {
		case string:
			destination.PutStr(string(attr.Key), value)
		case int64:
			destination.PutInt(string(attr.Key), value)
		case float64:
			destination.PutDouble(string(attr.Key), value)
		case bool:
			destination.PutBool(string(attr.Key), value)
		case []string:
			slice := destination.PutEmptySlice(string(attr.Key))
			for _, element := range value {
				slice.AppendEmpty().SetStr(element)
			}
		}
	}
}

// CodeToStatusCode converts an OBI request status code to a pdata status code.
func CodeToStatusCode(code string) ptrace.StatusCode {
	switch code {
	case request.StatusCodeUnset:
		return ptrace.StatusCodeUnset
	case request.StatusCodeError:
		return ptrace.StatusCodeError
	case request.StatusCodeOk:
		return ptrace.StatusCodeOk
	default:
		return ptrace.StatusCodeUnset
	}
}

func getSpanToolCalls(span *request.Span) []request.ToolCall {
	if span.GenAI == nil {
		return nil
	}

	switch {
	case span.GenAI.OpenAI != nil:
		return span.GenAI.OpenAI.ToolCalls
	case span.GenAI.Anthropic != nil:
		return span.GenAI.Anthropic.ToolCalls
	case span.GenAI.Gemini != nil:
		return span.GenAI.Gemini.ToolCalls
	case span.GenAI.Qwen != nil:
		return span.GenAI.Qwen.ToolCalls
	case span.GenAI.Ollama != nil:
		return span.GenAI.Ollama.ToolCalls
	case span.GenAI.OpenAICompatible != nil:
		return span.GenAI.OpenAICompatible.ToolCalls
	default:
		return nil
	}
}

func createToolCallSpans(
	toolCalls []request.ToolCall,
	parentSpanID pcommon.SpanID,
	traceID pcommon.TraceID,
	scopeSpans *ptrace.ScopeSpans,
	start time.Time,
	end time.Time,
) {
	for _, toolCall := range toolCalls {
		if toolCall.Name == "" {
			continue
		}

		toolSpan := scopeSpans.Spans().AppendEmpty()
		toolSpan.SetName("execute_tool " + toolCall.Name)
		toolSpan.SetKind(ptrace.SpanKindInternal)
		toolSpan.SetTraceID(traceID)
		toolSpan.SetSpanID(pcommon.SpanID(idgen.RandomSpanID()))
		toolSpan.SetParentSpanID(parentSpanID)
		toolSpan.SetStartTimestamp(pcommon.NewTimestampFromTime(start))
		toolSpan.SetEndTimestamp(pcommon.NewTimestampFromTime(end))

		attrs := toolSpan.Attributes()
		attrs.PutStr(string(semconv.GenAIOperationNameKey), "execute_tool")
		attrs.PutStr(string(attr.GenAIToolName), toolCall.Name)
		if toolCall.ID != "" {
			attrs.PutStr(string(attr.GenAIToolCallID), toolCall.ID)
		}
	}
}

func spanKind(span *request.Span) oteltrace.SpanKind {
	switch span.Type {
	case request.EventTypeHTTP, request.EventTypeGRPC, request.EventTypeRedisServer,
		request.EventTypeKafkaServer, request.EventTypeMQTTServer, request.EventTypeNATSServer,
		request.EventTypeSunRPCServer, request.EventTypeMemcachedServer, request.EventTypeSQLServer:
		return oteltrace.SpanKindServer
	case request.EventTypeHTTPClient, request.EventTypeGRPCClient, request.EventTypeSQLClient,
		request.EventTypeRedisClient, request.EventTypeMongoClient, request.EventTypeCouchbaseClient,
		request.EventTypeMemcachedClient, request.EventTypeSunRPCClient, request.EventTypeAerospikeClient,
		request.EventTypeFailedConnect:
		return oteltrace.SpanKindClient
	case request.EventTypeKafkaClient, request.EventTypeMQTTClient, request.EventTypeNATSClient,
		request.EventTypeAMQPClient:
		switch span.Method {
		case request.MessagingPublish:
			return oteltrace.SpanKindProducer
		case request.MessagingProcess:
			return oteltrace.SpanKindConsumer
		}
	}

	return oteltrace.SpanKindInternal
}

func spanStartTime(timings request.Timings) time.Time {
	start := timings.RequestStart
	if timings.Start.Before(start) {
		start = timings.Start
	}
	return start
}
