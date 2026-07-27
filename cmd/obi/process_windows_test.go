// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/binary"
	"testing"
	"time"
	"unicode/utf16"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
)

func TestDecodeProcessEvent(t *testing.T) {
	const (
		pid      = 4242
		filetime = 133987654321000000
	)
	imagePath := `C:\src\obi-windows-target.exe`
	pathUnits := utf16.Encode([]rune(imagePath))
	raw := make([]byte, processEventHeaderLen+len(pathUnits)*2)
	binary.LittleEndian.PutUint64(raw[0:8], pid)
	binary.LittleEndian.PutUint64(raw[8:16], filetime)
	binary.LittleEndian.PutUint32(raw[16:20], uint32(len(pathUnits)*2))
	raw[20] = 0
	for index, unit := range pathUnits {
		binary.LittleEndian.PutUint16(raw[processEventHeaderLen+index*2:], unit)
	}

	event, err := decodeProcessEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	if event.pid != pid {
		t.Fatalf("pid = %d, want %d", event.pid, pid)
	}
	if event.creationTime != filetime {
		t.Fatalf("creation time = %d, want %d", event.creationTime, filetime)
	}
	if event.imagePath != imagePath {
		t.Fatalf("image path = %q, want %q", event.imagePath, imagePath)
	}
}

func TestDecodeProcessEventRejectsOddPathLength(t *testing.T) {
	raw := make([]byte, processEventHeaderLen+1)
	binary.LittleEndian.PutUint32(raw[16:20], 1)
	if _, err := decodeProcessEvent(raw); err == nil {
		t.Fatal("expected an error for an odd UTF-16 path length")
	}
}

func TestTimeFromFiletime(t *testing.T) {
	got, ok := timeFromFiletime(windowsEpochOffset)
	if !ok {
		t.Fatal("Windows Unix-epoch FILETIME was rejected")
	}
	if !got.Equal(time.Unix(0, 0)) {
		t.Fatalf("converted time = %s, want Unix epoch", got)
	}
}

func TestProcessEventUsesOBITraceGeneration(t *testing.T) {
	const pid = 4242
	event := processEvent{
		pid:          pid,
		creationTime: windowsEpochOffset + uint64(time.Now().UnixNano()/100),
		imagePath:    `C:\src\obi-windows-target.exe`,
	}
	span, err := processEventSpan(event, "obi-windows-target.exe", "windows-vm")
	if err != nil {
		t.Fatal(err)
	}

	groups := tracesgen.GroupSpans(
		context.Background(),
		[]request.Span{span},
		map[attr.Name]struct{}{},
		sdktrace.AlwaysSample(),
		instrumentations.InstrumentationSelection(0),
	)
	group := groups[span.Service.UID]
	traces := tracesgen.GenerateWindowsProcessTraces(&span.Service, group)

	traceID, spanID, err := exportedIDs(traces)
	if err != nil {
		t.Fatal(err)
	}
	if traceID == "" || spanID == "" {
		t.Fatal("OBI generated an empty trace or span ID")
	}

	resourceAttributes := traces.ResourceSpans().At(0).Resource().Attributes()
	expectedResource := map[string]string{
		"service.name":             "obi-windows-target.exe",
		"service.instance.id":      "4242",
		"host.name":                "windows-vm",
		"os.type":                  "windows",
		"telemetry.sdk.language":   "generic",
		"telemetry.sdk.name":       "opentelemetry",
		"telemetry.sdk.version":    attr.VendorSDKVersion,
		"telemetry.distro.name":    "opentelemetry-ebpf-instrumentation",
		"telemetry.distro.version": attr.TelemetryDistroVersion,
		"otel.scope.name":          tracesgen.ReporterName,
	}
	for key, want := range expectedResource {
		value, ok := resourceAttributes.Get(key)
		if !ok || value.Str() != want {
			t.Errorf("resource %s = %v, want %q", key, value, want)
		}
	}
	if _, ok := resourceAttributes.Get("host.id"); ok {
		t.Error("Windows resource must omit host.id when no stable identifier is supplied")
	}
	if attr.VendorSDKVersion == "unknown" {
		t.Error("telemetry.sdk.version was not resolved from the embedded SDK dependency")
	}

	scope := traces.ResourceSpans().At(0).ScopeSpans().At(0).Scope()
	if scope.Name() != "" || scope.Version() != "" {
		t.Errorf(
			"instrumentation scope = %q %q, normal OBI leaves both fields empty",
			scope.Name(),
			scope.Version(),
		)
	}

	otelSpan := traces.ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0)
	if got, want := otelSpan.Name(), "process.start obi-windows-target.exe"; got != want {
		t.Fatalf("span name = %q, want %q", got, want)
	}
	pidAttribute, ok := otelSpan.Attributes().Get("process.pid")
	if !ok || pidAttribute.Int() != pid {
		t.Fatalf("process.pid = %v, want %d", pidAttribute, pid)
	}
	executableAttribute, ok := otelSpan.Attributes().Get("process.executable.name")
	if !ok || executableAttribute.Str() != "obi-windows-target.exe" {
		t.Fatalf("process.executable.name = %v", executableAttribute)
	}
}
