// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
	attr "go.opentelemetry.io/obi/pkg/export/attributes/names"
	"go.opentelemetry.io/obi/pkg/export/instrumentations"
	"go.opentelemetry.io/obi/pkg/export/otel/tracesgen"
)

const (
	processAttachTypeGUID = "{66e20687-9805-4458-a0db-38e220d31685}"
	processProgramName    = "obi_process_start"
	processEventsMapName  = "process_events"
	processEventHeaderLen = 24
	processEventPathLen   = 1024
	windowsEpochOffset    = 116444736000000000
	filetimeTicksPerSec   = 10000000
)

var (
	errMissingProcessProgram   = errors.New("-process-program or OTEL_EBPF_WINDOWS_PROCESS_PROGRAM is required")
	errMissingTargetExecutable = errors.New("-target-exe must not be empty")
	errInvalidOTLPEndpoint     = errors.New("-otlp-endpoint must be an absolute HTTP or HTTPS URL")
)

type windowsProcessOptions struct {
	programPath      string
	flowProgramPath  string
	targetExecutable string
	targetPort       int
	otlpEndpoint     string
	once             bool
	timeout          time.Duration
}

type processEvent struct {
	pid          uint64
	creationTime uint64
	operation    uint8
	imagePath    string
}

type windowsProcessTracer struct {
	options  windowsProcessOptions
	client   *http.Client
	hostname string
}

func runWindowsProcessTrace(ctx context.Context, opts windowsProcessOptions) error {
	collection, err := ebpf.LoadCollection(opts.programPath)
	if err != nil {
		return fmt.Errorf("load native eBPF process program %q: %w", opts.programPath, err)
	}
	defer collection.Close()

	program, ok := collection.Programs[processProgramName]
	if !ok {
		return fmt.Errorf("native eBPF collection has no program %q (available: %s)",
			processProgramName, strings.Join(sortedProgramNames(collection), ", "))
	}

	events, ok := collection.Maps[processEventsMapName]
	if !ok {
		return fmt.Errorf("native eBPF collection has no map %q (available: %s)",
			processEventsMapName, strings.Join(sortedMapNames(collection), ", "))
	}

	attachType, err := ebpf.WindowsAttachTypeForGUID(processAttachTypeGUID)
	if err != nil {
		return fmt.Errorf("resolve ntosebpfext process attach type %s: %w", processAttachTypeGUID, err)
	}

	processLink, err := link.AttachRawLink(link.RawLinkOptions{
		Program: program,
		Attach:  attachType,
	})
	if err != nil {
		return fmt.Errorf("attach native eBPF program to ntosebpfext process hook: %w", err)
	}
	defer processLink.Close()

	reader, err := ringbuf.NewReader(events)
	if err != nil {
		return fmt.Errorf("open process event ring buffer: %w", err)
	}
	defer reader.Close()

	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("read Windows host name: %w", err)
	}

	tracer := windowsProcessTracer{
		options: opts,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		hostname: hostname,
	}

	slog.Info("attached native eBPF program to Windows process hook",
		"program", processProgramName,
		"map", processEventsMapName,
		"target_executable", opts.targetExecutable,
		"otlp_endpoint", opts.otlpEndpoint)

	go func() {
		<-ctx.Done()
		_ = reader.Close()
	}()

	return tracer.readAndExport(ctx, reader)
}

func (t *windowsProcessTracer) readAndExport(ctx context.Context, reader *ringbuf.Reader) error {
	for {
		record, err := reader.Read()
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read process event: %w", err)
		}

		event, err := decodeProcessEvent(record.RawSample)
		if err != nil {
			slog.Warn("discarding malformed Windows process event", "error", err)
			continue
		}
		if event.operation != 0 {
			continue
		}

		executableName := filepath.Base(event.imagePath)
		if !strings.EqualFold(executableName, t.options.targetExecutable) {
			continue
		}

		span, err := processEventSpan(event, executableName, t.hostname)
		if err != nil {
			return err
		}
		traceID, spanID, err := t.export(ctx, span)
		if err != nil {
			return err
		}

		slog.Info("exported Windows process-start trace",
			"pid", event.pid,
			"executable", executableName,
			"image_path", event.imagePath,
			"trace_id", traceID,
			"span_id", spanID)

		if t.options.once {
			return nil
		}
	}
}

func (t *windowsProcessTracer) export(ctx context.Context, span request.Span) (string, string, error) {
	groups := tracesgen.GroupSpans(
		ctx,
		[]request.Span{span},
		map[attr.Name]struct{}{},
		sdktrace.AlwaysSample(),
		instrumentations.InstrumentationSelection(0),
	)
	group := groups[span.Service.UID]
	if len(group) != 1 {
		return "", "", fmt.Errorf("OBI trace grouping produced %d spans, expected 1", len(group))
	}

	groupedSpan := group[0].Span
	traces := tracesgen.GenerateWindowsTraces(&groupedSpan.Service, group)

	traceID, spanID, err := exportedIDs(traces)
	if err != nil {
		return "", "", err
	}

	payload, err := ptraceotlp.NewExportRequestFromTraces(traces).MarshalProto()
	if err != nil {
		return "", "", fmt.Errorf("marshal OBI trace as OTLP protobuf: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, t.options.otlpEndpoint, bytes.NewReader(payload))
	if err != nil {
		return "", "", fmt.Errorf("create OTLP request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-protobuf")

	response, err := t.client.Do(request)
	if err != nil {
		return "", "", fmt.Errorf("export OBI trace to %s: %w", t.options.otlpEndpoint, err)
	}
	defer response.Body.Close()

	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
	if readErr != nil {
		return "", "", fmt.Errorf("read OTLP response: %w", readErr)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return "", "", fmt.Errorf("OTLP endpoint returned %s: %s", response.Status, strings.TrimSpace(string(responseBody)))
	}

	return traceID, spanID, nil
}

func processEventSpan(event processEvent, executableName, hostname string) (request.Span, error) {
	encodedAttrs, err := encodeProcessSpanAttributes(event, executableName)
	if err != nil {
		return request.Span{}, fmt.Errorf("encode process span attributes: %w", err)
	}

	if event.pid > uint64(^app.PID(0)) {
		return request.Span{}, fmt.Errorf("Windows process ID %d exceeds the OBI PID representation", event.pid)
	}

	eventMonotime := eventMonoTime(event.creationTime)
	pid := app.PID(event.pid)

	return request.Span{
		Type:         request.EventTypeManualSpan,
		Method:       "process.start " + executableName,
		RequestStart: int64(eventMonotime),
		Start:        int64(eventMonotime),
		End:          int64(eventMonotime),
		Pid: request.PidInfo{
			HostPID: pid,
			UserPID: pid,
		},
		Service: svc.Attrs{
			UID: svc.UID{
				Name:     executableName,
				Instance: strconv.FormatUint(event.pid, 10),
			},
			SDKLanguage: svc.InstrumentableGeneric,
			ProcPID:     pid,
			HostName:    hostname,
		},
		Statement: encodedAttrs,
	}, nil
}

func encodeProcessSpanAttributes(event processEvent, executableName string) (string, error) {
	attributes := []tracesgen.SpanAttr{
		int64SpanAttribute("process.pid", event.pid),
		stringSpanAttribute("process.executable.name", executableName),
		stringSpanAttribute("process.executable.path", event.imagePath),
		int64SpanAttribute("obi.windows.creation_filetime", event.creationTime),
		stringSpanAttribute("obi.windows.process.event_source", "ntosebpfext/process"),
	}

	encoded, err := json.Marshal(attributes)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func int64SpanAttribute(key string, value uint64) tracesgen.SpanAttr {
	spanAttr := tracesgen.SpanAttr{
		ValLength: 8,
		Vtype:     uint8(attribute.INT64),
	}
	copy(spanAttr.Key[:], key)
	binary.LittleEndian.PutUint64(spanAttr.Value[:8], value)
	return spanAttr
}

func stringSpanAttribute(key, value string) tracesgen.SpanAttr {
	spanAttr := tracesgen.SpanAttr{Vtype: uint8(attribute.STRING)}
	copy(spanAttr.Key[:], key)
	length := copy(spanAttr.Value[:len(spanAttr.Value)-1], value)
	spanAttr.ValLength = uint16(length)
	return spanAttr
}

func decodeProcessEvent(raw []byte) (processEvent, error) {
	if len(raw) < processEventHeaderLen {
		return processEvent{}, fmt.Errorf("record is %d bytes, want at least %d", len(raw), processEventHeaderLen)
	}

	pathLength := int(int32(binary.LittleEndian.Uint32(raw[16:20])))
	if pathLength < 0 || pathLength > processEventPathLen || pathLength > len(raw)-processEventHeaderLen {
		return processEvent{}, fmt.Errorf("invalid UTF-16 image path length %d for %d-byte record", pathLength, len(raw))
	}
	if pathLength%2 != 0 {
		return processEvent{}, fmt.Errorf("UTF-16 image path length %d is not even", pathLength)
	}

	pathBytes := raw[processEventHeaderLen : processEventHeaderLen+pathLength]
	pathUnits := make([]uint16, len(pathBytes)/2)
	for index := range pathUnits {
		pathUnits[index] = binary.LittleEndian.Uint16(pathBytes[index*2:])
	}

	return processEvent{
		pid:          binary.LittleEndian.Uint64(raw[0:8]),
		creationTime: binary.LittleEndian.Uint64(raw[8:16]),
		operation:    raw[20],
		imagePath:    strings.TrimRight(string(utf16.Decode(pathUnits)), "\x00"),
	}, nil
}

func eventMonoTime(filetime uint64) time.Duration {
	receiptWallTime := time.Now()
	receiptMonotime := timing.MonoTimeNow()
	eventWallTime, ok := timeFromFiletime(filetime)
	if !ok {
		return receiptMonotime
	}

	delta := receiptWallTime.Sub(eventWallTime)
	if delta < 0 || delta > time.Minute {
		return receiptMonotime
	}
	return receiptMonotime - delta
}

func timeFromFiletime(filetime uint64) (time.Time, bool) {
	if filetime < windowsEpochOffset {
		return time.Time{}, false
	}
	unixTicks := filetime - windowsEpochOffset
	seconds := int64(unixTicks / filetimeTicksPerSec)
	nanoseconds := int64(unixTicks%filetimeTicksPerSec) * 100
	return time.Unix(seconds, nanoseconds), true
}

func exportedIDs(traces ptrace.Traces) (string, string, error) {
	if traces.ResourceSpans().Len() != 1 {
		return "", "", fmt.Errorf("OBI trace generation produced %d resource spans, expected 1", traces.ResourceSpans().Len())
	}
	scopeSpans := traces.ResourceSpans().At(0).ScopeSpans()
	if scopeSpans.Len() != 1 || scopeSpans.At(0).Spans().Len() != 1 {
		return "", "", errors.New("OBI trace generation did not produce exactly one span")
	}
	span := scopeSpans.At(0).Spans().At(0)
	if span.TraceID().IsEmpty() || span.SpanID().IsEmpty() {
		return "", "", errors.New("OBI trace generation produced an empty trace or span ID")
	}
	return span.TraceID().String(), span.SpanID().String(), nil
}

func sortedProgramNames(collection *ebpf.Collection) []string {
	names := make([]string, 0, len(collection.Programs))
	for name := range collection.Programs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sortedMapNames(collection *ebpf.Collection) []string {
	names := make([]string, 0, len(collection.Maps))
	for name := range collection.Maps {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
