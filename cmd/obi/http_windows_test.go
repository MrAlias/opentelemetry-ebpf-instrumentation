// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"

	"go.opentelemetry.io/collector/pdata/ptrace"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
)

const validTraceparent = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"

func TestWindowsHTTPRequiresOneShot(t *testing.T) {
	options := windowsProcessOptions{
		programPath:      "process.sys",
		flowProgramPath:  "flow.sys",
		targetExecutable: "target.exe",
		targetPort:       18080,
		otlpEndpoint:     "http://127.0.0.1:4318/v1/traces",
		once:             false,
	}

	if err := options.validate(); !errors.Is(err, errHTTPRequiresOneShot) {
		t.Fatalf("validate error = %v, want %v", err, errHTTPRequiresOneShot)
	}

	options.flowProgramPath = ""
	options.targetPort = 0
	if err := options.validate(); err != nil {
		t.Fatalf("process-only continuous mode validation failed: %v", err)
	}
}

func TestParseTraceparent(t *testing.T) {
	headers := http.Header{}
	headers.Add("traceparent", validTraceparent)

	traceID, parentSpanID, flags, err := parseTraceparent(headers)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := traceID.String(), "0123456789abcdef0123456789abcdef"; got != want {
		t.Fatalf("trace ID = %s, want %s", got, want)
	}
	if got, want := parentSpanID.String(), "0123456789abcdef"; got != want {
		t.Fatalf("parent span ID = %s, want %s", got, want)
	}
	if flags != 1 {
		t.Fatalf("trace flags = %d, want 1", flags)
	}
}

func TestParseTraceparentRejectsInvalidValues(t *testing.T) {
	tests := map[string][]string{
		"missing":         nil,
		"duplicate":       {validTraceparent, validTraceparent},
		"bad version":     {"01-0123456789abcdef0123456789abcdef-0123456789abcdef-01"},
		"all-zero trace":  {"00-00000000000000000000000000000000-0123456789abcdef-01"},
		"all-zero parent": {"00-0123456789abcdef0123456789abcdef-0000000000000000-01"},
		"bad flags":       {"00-0123456789abcdef0123456789abcdef-0123456789abcdef-03"},
		"bad hex":         {"00-0123456789abcdef0123456789abcdeg-0123456789abcdef-01"},
	}

	for name, values := range tests {
		t.Run(name, func(t *testing.T) {
			headers := http.Header{}
			for _, value := range values {
				headers.Add("Traceparent", value)
			}
			if _, _, _, err := parseTraceparent(headers); err == nil {
				t.Fatal("invalid traceparent was accepted")
			}
		})
	}
}

func TestDecodeFlowEvent(t *testing.T) {
	data := []byte("GET /ready HTTP/1.1\r\n")
	raw := encodeTestFlowEvent(flowEvent{
		processID:       4242,
		flowID:          91,
		sequence:        12,
		family:          2,
		localAddress:    net.ParseIP("127.0.0.1").To4(),
		remoteAddress:   net.ParseIP("127.0.0.2").To4(),
		localPort:       18080,
		remotePort:      55123,
		state:           flowStateEstablished,
		direction:       flowDirectionInbound,
		indicatedLength: uint32(len(data)),
		copiedLength:    uint32(len(data)),
		data:            data,
	})

	event, err := decodeFlowEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	if event.processID != 4242 || event.flowID != 91 || event.sequence != 12 {
		t.Fatalf("decoded identifiers = pid:%d flow:%d sequence:%d", event.processID, event.flowID, event.sequence)
	}
	if event.localAddress.String() != "127.0.0.1" || event.localPort != 18080 {
		t.Fatalf("decoded local tuple = %s:%d", event.localAddress, event.localPort)
	}
	if event.remoteAddress.String() != "127.0.0.2" || event.remotePort != 55123 {
		t.Fatalf("decoded remote tuple = %s:%d", event.remoteAddress, event.remotePort)
	}
	if string(event.data) != string(data) {
		t.Fatalf("decoded data = %q, want %q", event.data, data)
	}
}

func TestWindowsHTTPFlowProducesServerSpanWithIncomingContext(t *testing.T) {
	const (
		pid        = 4242
		generation = 133987654321000000
		flowID     = 91
	)
	tracer := windowsHTTPTracer{
		exporter: windowsProcessTracer{hostname: "windows-vm"},
		generations: map[uint64]processGeneration{
			pid: {pid: pid, creationTime: generation, executable: "obi-windows-http-target.exe"},
		},
		flows: map[httpFlowKey]*httpFlowState{},
	}
	baseEvent := flowEvent{
		processID:     pid,
		flowID:        flowID,
		family:        2,
		localAddress:  net.ParseIP("127.0.0.1").To4(),
		remoteAddress: net.ParseIP("127.0.0.2").To4(),
		localPort:     18080,
		remotePort:    55123,
	}

	newEvent := baseEvent
	newEvent.state = flowStateNew
	if _, complete, err := tracer.consumeFlowEvent(newEvent); err != nil || complete {
		t.Fatalf("new flow = complete:%v error:%v", complete, err)
	}

	requestBytes := []byte(
		"GET /ready?probe=1 HTTP/1.1\r\n" +
			"Host: 127.0.0.1:18080\r\n" +
			"tRaCePaReNt: " + validTraceparent + "\r\n" +
			"Connection: close\r\n\r\n")
	requestEvent := baseEvent
	requestEvent.state = flowStateEstablished
	requestEvent.direction = flowDirectionInbound
	requestEvent.indicatedLength = uint32(len(requestBytes))
	requestEvent.copiedLength = uint32(len(requestBytes))
	requestEvent.data = requestBytes
	if _, complete, err := tracer.consumeFlowEvent(requestEvent); err != nil || complete {
		t.Fatalf("request flow = complete:%v error:%v", complete, err)
	}

	responseBytes := []byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
	responseEvent := baseEvent
	responseEvent.state = flowStateEstablished
	responseEvent.direction = 1
	responseEvent.indicatedLength = uint32(len(responseBytes))
	responseEvent.copiedLength = uint32(len(responseBytes))
	responseEvent.data = responseBytes
	span, complete, err := tracer.consumeFlowEvent(responseEvent)
	if err != nil {
		t.Fatal(err)
	}
	if !complete {
		t.Fatal("response flow did not complete the span")
	}
	if span.Method != "GET" || span.FullPath != "/ready?probe=1" || span.Status != 204 {
		t.Fatalf("HTTP fields = %s %s status=%d", span.Method, span.FullPath, span.Status)
	}

	groups := tracesgen.GroupSpans(
		context.Background(),
		[]request.Span{span},
		map[attr.Name]struct{}{},
		sdktrace.AlwaysSample(),
		instrumentations.InstrumentationSelection(0),
	)
	group := groups[span.Service.UID]
	if len(group) != 1 {
		t.Fatalf("grouped spans = %d, want 1", len(group))
	}
	traces := tracesgen.GenerateWindowsTraces(&span.Service, group)
	exported := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)

	if exported.Kind() != ptrace.SpanKindServer {
		t.Fatalf("span kind = %s, want Server", exported.Kind())
	}
	if got, want := exported.TraceID().String(), "0123456789abcdef0123456789abcdef"; got != want {
		t.Fatalf("trace ID = %s, want %s", got, want)
	}
	if got, want := exported.ParentSpanID().String(), "0123456789abcdef"; got != want {
		t.Fatalf("parent span ID = %s, want %s", got, want)
	}
	if exported.SpanID().IsEmpty() || exported.SpanID() == exported.ParentSpanID() {
		t.Fatalf("server span ID = %s", exported.SpanID())
	}

	expected := map[string]any{
		"http.request.method":       "GET",
		"url.path":                  "/ready",
		"http.response.status_code": int64(204),
		"process.pid":               int64(pid),
	}
	for key, want := range expected {
		value, ok := exported.Attributes().Get(key)
		if !ok {
			t.Errorf("missing span attribute %s", key)
			continue
		}
		if got := value.AsRaw(); got != want {
			t.Errorf("span attribute %s = %#v, want %#v", key, got, want)
		}
	}

	resource := traces.ResourceSpans().At(0).Resource().Attributes()
	if value, ok := resource.Get("telemetry.sdk.name"); !ok || value.Str() != "opentelemetry" {
		t.Fatalf("telemetry.sdk.name = %v", value)
	}
	if value, ok := resource.Get("telemetry.distro.name"); !ok ||
		value.Str() != "opentelemetry-ebpf-instrumentation" {
		t.Fatalf("telemetry.distro.name = %v", value)
	}
}

func TestWindowsHTTPFlowRejectsTruncatedIndication(t *testing.T) {
	tracer := windowsHTTPTracer{
		generations: map[uint64]processGeneration{
			1: {pid: 1, creationTime: 2, executable: "target.exe"},
		},
		flows: map[httpFlowKey]*httpFlowState{},
	}
	newEvent := flowEvent{processID: 1, flowID: 3, state: flowStateNew}
	_, _, _ = tracer.consumeFlowEvent(newEvent)

	streamEvent := flowEvent{
		processID:       1,
		flowID:          3,
		state:           flowStateEstablished,
		direction:       flowDirectionInbound,
		indicatedLength: 600,
		copiedLength:    512,
		data:            []byte(strings.Repeat("A", 512)),
	}
	if _, _, err := tracer.consumeFlowEvent(streamEvent); err == nil {
		t.Fatal("truncated stream indication was accepted")
	}
}

func encodeTestFlowEvent(event flowEvent) []byte {
	raw := make([]byte, flowEventSize)
	binary.LittleEndian.PutUint16(raw[0:2], flowEventVersion)
	binary.LittleEndian.PutUint16(raw[2:4], flowEventSize)
	binary.LittleEndian.PutUint32(raw[4:8], event.flags)
	binary.LittleEndian.PutUint64(raw[8:16], event.processID)
	binary.LittleEndian.PutUint64(raw[16:24], event.processStartKey)
	binary.LittleEndian.PutUint64(raw[24:32], event.flowID)
	binary.LittleEndian.PutUint64(raw[32:40], event.sequence)
	binary.LittleEndian.PutUint64(raw[40:48], event.timestampNS)
	binary.LittleEndian.PutUint64(raw[48:56], event.interfaceLUID)
	binary.LittleEndian.PutUint32(raw[56:60], event.family)
	if event.family == 2 {
		copy(raw[60:64], event.localAddress.To4())
		copy(raw[64:68], event.remoteAddress.To4())
	} else {
		copy(raw[68:84], event.localAddress.To16())
		copy(raw[84:100], event.remoteAddress.To16())
	}
	binary.BigEndian.PutUint16(raw[100:102], event.localPort)
	binary.BigEndian.PutUint16(raw[104:106], event.remotePort)
	binary.LittleEndian.PutUint32(raw[108:112], event.state)
	binary.LittleEndian.PutUint32(raw[112:116], event.direction)
	binary.LittleEndian.PutUint32(raw[116:120], event.indicatedLength)
	binary.LittleEndian.PutUint32(raw[120:124], event.copiedLength)
	binary.LittleEndian.PutUint32(raw[124:128], event.missedBytes)
	binary.LittleEndian.PutUint16(raw[128:130], uint16(len(event.data)))
	copy(raw[flowEventHeaderSize:], event.data)
	return raw
}
