// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/ebpf/timing"
)

const (
	flowAttachTypeGUID = "{e50cb9c1-606c-4b7d-81ad-af31f99fca47}"
	flowProgramName    = "obi_flow_classify"
	flowConfigMapName  = "flow_config"
	flowEventsMapName  = "flow_events"

	flowEventVersion    = 1
	flowEventHeaderSize = 132
	flowCaptureSize     = 512
	flowEventSize       = 648
	maxHTTPHeaderSize   = 8192

	flowStateNew         = 0
	flowStateEstablished = 1
	flowStateDeleted     = 2
	flowDirectionInbound = 0
)

var (
	errMissingFlowProgram  = errors.New("-flow-program or OTEL_EBPF_WINDOWS_FLOW_PROGRAM is required for HTTP tracing")
	errInvalidTargetPort   = errors.New("-target-port must be between 1 and 65535 for HTTP tracing")
	errHTTPRequiresOneShot = errors.New("native Windows HTTP tracing requires -once=true")
	errMalformedFlowEvent  = errors.New("malformed Flow Classify event")
)

type flowFilterConfig struct {
	TargetPID  uint64
	TargetPort uint16
	Reserved1  uint16
	Reserved2  uint32
}

type flowEvent struct {
	flags           uint32
	processID       uint64
	processStartKey uint64
	flowID          uint64
	sequence        uint64
	timestampNS     uint64
	interfaceLUID   uint64
	family          uint32
	localAddress    net.IP
	remoteAddress   net.IP
	localPort       uint16
	remotePort      uint16
	state           uint32
	direction       uint32
	indicatedLength uint32
	copiedLength    uint32
	missedBytes     uint32
	data            []byte
}

type processGeneration struct {
	pid          uint64
	creationTime uint64
	executable   string
}

type httpFlowKey struct {
	processID  uint64
	generation uint64
	flowID     uint64
}

type httpFlowState struct {
	key          httpFlowKey
	requestStart time.Duration
	lastEvent    flowEvent
	request      []byte
	response     []byte
}

type windowsHTTPTracer struct {
	exporter   windowsProcessTracer
	config     *ebpf.Map
	targetPort uint16

	mu          sync.Mutex
	generations map[uint64]processGeneration
	flows       map[httpFlowKey]*httpFlowState
}

type traceLoopResult struct {
	source string
	err    error
}

func runWindowsHTTPTrace(ctx context.Context, opts windowsProcessOptions) error {
	processCollection, err := ebpf.LoadCollection(opts.programPath)
	if err != nil {
		return fmt.Errorf("load native eBPF process program %q: %w", opts.programPath, err)
	}
	defer processCollection.Close()

	processProgram, processEvents, err := collectionProgramAndMap(
		processCollection, processProgramName, processEventsMapName)
	if err != nil {
		return fmt.Errorf("inspect native process collection: %w", err)
	}
	processAttachType, err := ebpf.WindowsAttachTypeForGUID(processAttachTypeGUID)
	if err != nil {
		return fmt.Errorf("resolve ntosebpfext process attach type %s: %w", processAttachTypeGUID, err)
	}
	processLink, err := link.AttachRawLink(link.RawLinkOptions{Program: processProgram, Attach: processAttachType})
	if err != nil {
		return fmt.Errorf("attach native eBPF program to ntosebpfext process hook: %w", err)
	}
	defer processLink.Close()

	flowCollection, err := ebpf.LoadCollection(opts.flowProgramPath)
	if err != nil {
		return fmt.Errorf("load native eBPF Flow Classify program %q: %w", opts.flowProgramPath, err)
	}
	defer flowCollection.Close()

	flowProgram, flowEvents, err := collectionProgramAndMap(flowCollection, flowProgramName, flowEventsMapName)
	if err != nil {
		return fmt.Errorf("inspect native Flow Classify collection: %w", err)
	}
	flowConfig, ok := flowCollection.Maps[flowConfigMapName]
	if !ok {
		return fmt.Errorf("native Flow Classify collection has no map %q (available: %s)",
			flowConfigMapName, strings.Join(sortedMapNames(flowCollection), ", "))
	}
	flowAttachType, err := ebpf.WindowsAttachTypeForGUID(flowAttachTypeGUID)
	if err != nil {
		return fmt.Errorf("resolve Flow Classify attach type %s: %w", flowAttachTypeGUID, err)
	}
	flowLink, err := link.AttachRawLink(link.RawLinkOptions{Program: flowProgram, Attach: flowAttachType})
	if err != nil {
		return fmt.Errorf("attach native eBPF program to Flow Classify hook: %w", err)
	}
	defer flowLink.Close()

	processReader, err := ringbuf.NewReader(processEvents)
	if err != nil {
		return fmt.Errorf("open process event ring buffer: %w", err)
	}
	defer processReader.Close()
	flowReader, err := ringbuf.NewReader(flowEvents)
	if err != nil {
		return fmt.Errorf("open Flow Classify event ring buffer: %w", err)
	}
	defer flowReader.Close()

	hostname, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("read Windows host name: %w", err)
	}

	tracer := &windowsHTTPTracer{
		exporter: windowsProcessTracer{
			options:  opts,
			client:   &http.Client{Timeout: 10 * time.Second},
			hostname: hostname,
		},
		config:      flowConfig,
		targetPort:  uint16(opts.targetPort),
		generations: map[uint64]processGeneration{},
		flows:       map[httpFlowKey]*httpFlowState{},
	}

	slog.Info("attached native eBPF programs for Windows HTTP tracing",
		"process_program", processProgramName,
		"flow_program", flowProgramName,
		"flow_map", flowEventsMapName,
		"target_executable", opts.targetExecutable,
		"target_port", opts.targetPort,
		"otlp_endpoint", opts.otlpEndpoint)

	runContext, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-runContext.Done()
		_ = processReader.Close()
		_ = flowReader.Close()
	}()

	results := make(chan traceLoopResult, 2)
	go func() {
		results <- traceLoopResult{source: "process", err: tracer.readTargetProcesses(runContext, processReader)}
	}()
	go func() {
		results <- traceLoopResult{source: "flow", err: tracer.readHTTPFlows(runContext, flowReader)}
	}()

	for completed := 0; completed < 2; completed++ {
		result := <-results
		if result.err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return fmt.Errorf("%s event loop: %w", result.source, result.err)
		}
		if result.source == "flow" && opts.once {
			return nil
		}
	}
	return nil
}

func collectionProgramAndMap(
	collection *ebpf.Collection,
	programName string,
	mapName string,
) (*ebpf.Program, *ebpf.Map, error) {
	program, ok := collection.Programs[programName]
	if !ok {
		return nil, nil, fmt.Errorf("collection has no program %q (available: %s)",
			programName, strings.Join(sortedProgramNames(collection), ", "))
	}
	eventMap, ok := collection.Maps[mapName]
	if !ok {
		return nil, nil, fmt.Errorf("collection has no map %q (available: %s)",
			mapName, strings.Join(sortedMapNames(collection), ", "))
	}
	return program, eventMap, nil
}

func (t *windowsHTTPTracer) readTargetProcesses(ctx context.Context, reader *ringbuf.Reader) error {
	for {
		record, err := reader.Read()
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil
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
		executable := filepath.Base(event.imagePath)
		if event.operation != 0 || !strings.EqualFold(executable, t.exporter.options.targetExecutable) {
			continue
		}

		config := flowFilterConfig{TargetPID: event.pid, TargetPort: t.targetPort}
		var key uint32
		if err := t.config.Update(&key, &config, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("configure Flow Classify target PID %d: %w", event.pid, err)
		}

		generation := processGeneration{
			pid:          event.pid,
			creationTime: event.creationTime,
			executable:   executable,
		}
		t.mu.Lock()
		t.generations[event.pid] = generation
		t.mu.Unlock()

		slog.Info("configured Windows HTTP target from native process event",
			"pid", event.pid,
			"creation_filetime", event.creationTime,
			"executable", executable,
			"target_port", t.targetPort)
	}
}

func (t *windowsHTTPTracer) readHTTPFlows(ctx context.Context, reader *ringbuf.Reader) error {
	for {
		record, err := reader.Read()
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil
			}
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read Flow Classify event: %w", err)
		}

		event, err := decodeFlowEvent(record.RawSample)
		if err != nil {
			slog.Warn("discarding malformed Windows Flow Classify event", "error", err)
			continue
		}
		slog.Info("captured Windows Flow Classify event",
			"pid", event.processID,
			"flow_id", event.flowID,
			"state", event.state,
			"direction", event.direction,
			"sequence", event.sequence,
			"local", net.JoinHostPort(event.localAddress.String(), strconv.Itoa(int(event.localPort))),
			"remote", net.JoinHostPort(event.remoteAddress.String(), strconv.Itoa(int(event.remotePort))),
			"indicated_length", event.indicatedLength,
			"copied_length", event.copiedLength,
			"missed_bytes", event.missedBytes,
			"data", strconv.QuoteToASCII(string(event.data)))

		span, complete, err := t.consumeFlowEvent(event)
		if err != nil {
			slog.Warn("discarding incomplete Windows HTTP flow",
				"pid", event.processID, "flow_id", event.flowID, "error", err)
			continue
		}
		if !complete {
			continue
		}

		traceID, spanID, err := t.exporter.export(ctx, span)
		if err != nil {
			return err
		}
		slog.Info("exported OBI Windows HTTP server trace",
			"pid", span.Pid.HostPID,
			"method", span.Method,
			"path", span.FullPath,
			"status", span.Status,
			"trace_id", traceID,
			"parent_span_id", span.ParentSpanID.String(),
			"span_id", spanID)
		if t.exporter.options.once {
			return nil
		}
	}
}

func (t *windowsHTTPTracer) consumeFlowEvent(event flowEvent) (request.Span, bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	generation, ok := t.generations[event.processID]
	if !ok {
		return request.Span{}, false, nil
	}
	if event.processStartKey != 0 {
		generation.creationTime = event.processStartKey
	}
	key := httpFlowKey{
		processID:  event.processID,
		generation: generation.creationTime,
		flowID:     event.flowID,
	}

	switch event.state {
	case flowStateNew:
		t.flows[key] = &httpFlowState{
			key:       key,
			lastEvent: event,
			request:   make([]byte, 0, 1024),
			response:  make([]byte, 0, 1024),
		}
		return request.Span{}, false, nil
	case flowStateDeleted:
		delete(t.flows, key)
		return request.Span{}, false, nil
	case flowStateEstablished:
	default:
		return request.Span{}, false, fmt.Errorf("unknown flow state %d", event.state)
	}

	state, ok := t.flows[key]
	if !ok {
		return request.Span{}, false, nil
	}
	state.lastEvent = event

	destination := &state.response
	if event.direction == flowDirectionInbound {
		destination = &state.request
		if state.requestStart == 0 {
			state.requestStart = timing.MonoTimeNow()
		}
	}
	if event.missedBytes != 0 || event.sequence != uint64(len(*destination)) {
		delete(t.flows, key)
		return request.Span{}, false, fmt.Errorf(
			"non-contiguous stream: direction=%d sequence=%d expected=%d missed=%d",
			event.direction, event.sequence, len(*destination), event.missedBytes)
	}
	if len(*destination)+len(event.data) > maxHTTPHeaderSize {
		delete(t.flows, key)
		return request.Span{}, false, fmt.Errorf("HTTP header exceeds %d bytes", maxHTTPHeaderSize)
	}
	*destination = append(*destination, event.data...)

	requestHeader, requestComplete := completeHeader(state.request)
	responseHeader, responseComplete := completeHeader(state.response)
	if !requestComplete || !responseComplete {
		if event.indicatedLength > uint32(len(event.data)) {
			delete(t.flows, key)
			return request.Span{}, false, fmt.Errorf(
				"stream indication truncated before complete headers: indicated=%d captured=%d",
				event.indicatedLength, len(event.data))
		}
		return request.Span{}, false, nil
	}

	span, err := windowsHTTPSpan(
		requestHeader,
		responseHeader,
		generation,
		state.lastEvent,
		state.requestStart,
		t.exporter.hostname)
	if err != nil {
		return request.Span{}, false, err
	}
	delete(t.flows, key)
	return span, true, nil
}

func completeHeader(data []byte) ([]byte, bool) {
	end := bytes.Index(data, []byte("\r\n\r\n"))
	if end < 0 {
		return nil, false
	}
	return data[:end+4], true
}

func windowsHTTPSpan(
	requestHeader []byte,
	responseHeader []byte,
	generation processGeneration,
	event flowEvent,
	requestStart time.Duration,
	hostname string,
) (request.Span, error) {
	parsedRequest, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(requestHeader)))
	if err != nil {
		return request.Span{}, fmt.Errorf("parse HTTP/1.1 request headers: %w", err)
	}
	defer parsedRequest.Body.Close()
	if parsedRequest.ProtoMajor != 1 || parsedRequest.ProtoMinor != 1 {
		return request.Span{}, fmt.Errorf("unsupported HTTP version %s", parsedRequest.Proto)
	}

	parsedResponse, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(responseHeader)), parsedRequest)
	if err != nil {
		return request.Span{}, fmt.Errorf("parse HTTP/1.1 response headers: %w", err)
	}
	defer parsedResponse.Body.Close()
	if parsedResponse.ProtoMajor != 1 || parsedResponse.ProtoMinor != 1 {
		return request.Span{}, fmt.Errorf("unsupported HTTP version %s", parsedResponse.Proto)
	}

	traceID, parentSpanID, traceFlags, err := parseTraceparent(parsedRequest.Header)
	if err != nil {
		return request.Span{}, err
	}
	if generation.pid > uint64(^app.PID(0)) {
		return request.Span{}, fmt.Errorf("Windows process ID %d exceeds the OBI PID representation", generation.pid)
	}
	if requestStart == 0 {
		requestStart = timing.MonoTimeNow()
	}
	end := timing.MonoTimeNow()
	if end < requestStart {
		end = requestStart
	}

	pid := app.PID(generation.pid)
	return request.Span{
		Type:         request.EventTypeHTTP,
		Method:       parsedRequest.Method,
		Path:         parsedRequest.URL.Path,
		FullPath:     parsedRequest.URL.RequestURI(),
		Peer:         event.remoteAddress.String(),
		PeerPort:     int(event.remotePort),
		Host:         event.localAddress.String(),
		HostPort:     int(event.localPort),
		Status:       parsedResponse.StatusCode,
		RequestStart: int64(requestStart),
		Start:        int64(requestStart),
		End:          int64(end),
		TraceID:      traceID,
		ParentSpanID: parentSpanID,
		TraceFlags:   uint8(traceFlags),
		Pid: request.PidInfo{
			HostPID: pid,
			UserPID: pid,
		},
		Service: svc.Attrs{
			UID: svc.UID{
				Name:     generation.executable,
				Instance: fmt.Sprintf("%d-%d", generation.pid, generation.creationTime),
			},
			SDKLanguage: svc.InstrumentableGeneric,
			ProcPID:     pid,
			HostName:    hostname,
		},
	}, nil
}

func parseTraceparent(headers http.Header) (trace.TraceID, trace.SpanID, trace.TraceFlags, error) {
	values := headers.Values("Traceparent")
	if len(values) != 1 {
		return trace.TraceID{}, trace.SpanID{}, 0,
			fmt.Errorf("traceparent header count is %d, want exactly 1", len(values))
	}

	value := strings.TrimSpace(values[0])
	if len(value) != 55 || value[2] != '-' || value[35] != '-' || value[52] != '-' {
		return trace.TraceID{}, trace.SpanID{}, 0, errors.New("malformed traceparent header")
	}
	if value[:2] != "00" {
		return trace.TraceID{}, trace.SpanID{}, 0, fmt.Errorf("unsupported traceparent version %q", value[:2])
	}

	traceID, err := trace.TraceIDFromHex(value[3:35])
	if err != nil || !traceID.IsValid() {
		return trace.TraceID{}, trace.SpanID{}, 0, errors.New("invalid traceparent trace ID")
	}
	parentSpanID, err := trace.SpanIDFromHex(value[36:52])
	if err != nil || !parentSpanID.IsValid() {
		return trace.TraceID{}, trace.SpanID{}, 0, errors.New("invalid traceparent parent span ID")
	}
	flagsValue, err := strconv.ParseUint(value[53:55], 16, 8)
	if err != nil || flagsValue > 1 {
		return trace.TraceID{}, trace.SpanID{}, 0, errors.New("invalid traceparent flags")
	}
	return traceID, parentSpanID, trace.TraceFlags(flagsValue), nil
}

func decodeFlowEvent(raw []byte) (flowEvent, error) {
	if len(raw) < flowEventSize {
		return flowEvent{}, fmt.Errorf("%w: record is %d bytes, want %d", errMalformedFlowEvent, len(raw), flowEventSize)
	}
	version := binary.LittleEndian.Uint16(raw[0:2])
	size := binary.LittleEndian.Uint16(raw[2:4])
	if version != flowEventVersion || int(size) != flowEventSize {
		return flowEvent{}, fmt.Errorf("%w: version=%d size=%d", errMalformedFlowEvent, version, size)
	}
	dataLength := int(binary.LittleEndian.Uint16(raw[128:130]))
	if dataLength > flowCaptureSize || flowEventHeaderSize+dataLength > len(raw) {
		return flowEvent{}, fmt.Errorf("%w: invalid data length %d", errMalformedFlowEvent, dataLength)
	}

	family := binary.LittleEndian.Uint32(raw[56:60])
	var localAddress, remoteAddress net.IP
	switch family {
	case 2:
		localAddress = append(net.IP(nil), raw[60:64]...)
		remoteAddress = append(net.IP(nil), raw[64:68]...)
	case 23:
		localAddress = append(net.IP(nil), raw[68:84]...)
		remoteAddress = append(net.IP(nil), raw[84:100]...)
	default:
		return flowEvent{}, fmt.Errorf("%w: unsupported address family %d", errMalformedFlowEvent, family)
	}

	return flowEvent{
		flags:           binary.LittleEndian.Uint32(raw[4:8]),
		processID:       binary.LittleEndian.Uint64(raw[8:16]),
		processStartKey: binary.LittleEndian.Uint64(raw[16:24]),
		flowID:          binary.LittleEndian.Uint64(raw[24:32]),
		sequence:        binary.LittleEndian.Uint64(raw[32:40]),
		timestampNS:     binary.LittleEndian.Uint64(raw[40:48]),
		interfaceLUID:   binary.LittleEndian.Uint64(raw[48:56]),
		family:          family,
		localAddress:    localAddress,
		remoteAddress:   remoteAddress,
		localPort:       binary.BigEndian.Uint16(raw[100:102]),
		remotePort:      binary.BigEndian.Uint16(raw[104:106]),
		state:           binary.LittleEndian.Uint32(raw[108:112]),
		direction:       binary.LittleEndian.Uint32(raw[112:116]),
		indicatedLength: binary.LittleEndian.Uint32(raw[116:120]),
		copiedLength:    binary.LittleEndian.Uint32(raw[120:124]),
		missedBytes:     binary.LittleEndian.Uint32(raw[124:128]),
		data:            append([]byte(nil), raw[flowEventHeaderSize:flowEventHeaderSize+dataLength]...),
	}, nil
}
