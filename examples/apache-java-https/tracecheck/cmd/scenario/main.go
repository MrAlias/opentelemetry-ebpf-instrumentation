// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	rand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/obi/examples/apache-java-https/tracecheck"
)

type config struct {
	baseURL       string
	receiverURL   string
	scenario      string
	requestCount  int
	timeout       time.Duration
	expectedTLS   string
	seed          int64
	apacheService string
	javaService   string
}

type requestCase struct {
	Marker          string `json:"marker"`
	Endpoint        string `json:"endpoint"`
	W3CTraceID      string `json:"w3c_trace_id,omitempty"`
	W3CParentSpanID string `json:"w3c_parent_span_id,omitempty"`
	W3CTraceFlags   string `json:"w3c_trace_flags,omitempty"`
	W3CCase         string `json:"w3c_case,omitempty"`
	InvalidW3C      bool   `json:"invalid_w3c,omitempty"`
	HandoffHops     int    `json:"handoff_hops,omitempty"`
	HandoffFault    string `json:"handoff_fault,omitempty"`
	VirtualMixed    bool   `json:"virtual_mixed,omitempty"`
	VirtualCancel   bool   `json:"virtual_cancel,omitempty"`
	NettyCancel     bool   `json:"netty_cancel,omitempty"`
	DispatchRounds  int    `json:"dispatch_rounds,omitempty"`
	TLSBoundaryMode string `json:"tls_boundary_mode,omitempty"`
	DelayMillis     int    `json:"-"`
	SlowBodyBytes   int    `json:"-"`
	CloseConnection bool   `json:"-"`
	ObserveSocket   bool   `json:"-"`
}

type backendResponse struct {
	Marker              string               `json:"marker"`
	Secure              bool                 `json:"secure"`
	Protocol            string               `json:"protocol"`
	TLSProtocol         string               `json:"tls_protocol"`
	TLSCipher           string               `json:"tls_cipher"`
	BackendConnectionID uint64               `json:"backend_connection_id"`
	BackendRemotePort   int                  `json:"backend_remote_port"`
	BackendSocketFD     int                  `json:"backend_socket_fd,omitempty"`
	TLSReadEvents       int64                `json:"tls_read_events"`
	TLSReadBytes        int64                `json:"tls_read_bytes"`
	Workload            string               `json:"workload,omitempty"`
	HandoffHops         string               `json:"handoff_hops,omitempty"`
	HandoffFault        string               `json:"handoff_fault,omitempty"`
	VirtualMixed        string               `json:"virtual_mixed,omitempty"`
	VirtualCancel       string               `json:"virtual_cancel,omitempty"`
	NettyCancel         string               `json:"netty_cancel,omitempty"`
	DispatchRounds      string               `json:"dispatch_rounds,omitempty"`
	DispatchInvocations string               `json:"dispatch_invocations,omitempty"`
	TLSBoundary         *tlsBoundaryEvidence `json:"tls_boundary,omitempty"`
}

type tlsBoundaryEvidence struct {
	Mode                             string `json:"mode"`
	Passed                           bool   `json:"passed"`
	ShapeExact                       bool   `json:"shape_exact"`
	ExpectedPlaintextCallbackLengths []int  `json:"expected_plaintext_callback_lengths"`
	ActualPlaintextCallbackLengths   []int  `json:"actual_plaintext_callback_lengths"`
	RequestOrder                     []int  `json:"request_order"`
	ResponseOrder                    []int  `json:"response_order"`
	BuffersForwardedUnchanged        bool   `json:"buffers_forwarded_unchanged"`
	HandoffBeforeParse               bool   `json:"handoff_before_parse"`
	ConnectionClosed                 bool   `json:"connection_closed"`
}

type caseResult struct {
	Request               requestCase                      `json:"request"`
	Response              backendResponse                  `json:"response"`
	LatencyNanos          int64                            `json:"latency_nanos"`
	PressureParentOutcome tracecheck.PressureParentOutcome `json:"pressure_parent_outcome,omitempty"`
	Trace                 tracecheck.Snapshot              `json:"trace"`
}

type pressureCorrelationSummary struct {
	ExactHitCount     int `json:"exact_hit_count"`
	ExplicitRootCount int `json:"explicit_root_count"`
	WrongParentCount  int `json:"wrong_parent_count"`
	UnresolvedCount   int `json:"unresolved_count"`
}

type latencySummary struct {
	P50Nanos int64 `json:"p50_nanos"`
	P95Nanos int64 `json:"p95_nanos"`
	P99Nanos int64 `json:"p99_nanos"`
}

type faultResult struct {
	Kind         string `json:"kind"`
	Outcome      string `json:"outcome"`
	ElapsedNanos int64  `json:"elapsed_nanos"`
}

type connectionEvidence struct {
	FrontendConnections            int    `json:"frontend_connections"`
	FrontendProtocol               string `json:"frontend_protocol"`
	PipelinedRequests              int    `json:"pipelined_requests,omitempty"`
	RequestsWrittenBeforeFirstRead int    `json:"requests_written_before_first_read,omitempty"`
	ReusedFrontendLocalPort        int    `json:"reused_frontend_local_port,omitempty"`
	ReusedFrontendFileDescriptor   int    `json:"reused_frontend_file_descriptor,omitempty"`
	DistinctFrontendLocalPorts     int    `json:"distinct_frontend_local_ports,omitempty"`
	BackendConnections             int    `json:"backend_connections,omitempty"`
	DistinctBackendConnectionIDs   int    `json:"distinct_backend_connection_ids,omitempty"`
	DistinctBackendRemotePorts     int    `json:"distinct_backend_remote_ports,omitempty"`
	ReusedBackendFileDescriptor    int    `json:"reused_backend_file_descriptor,omitempty"`
}

type socketObservation struct {
	FileDescriptor int
	LocalPort      int
}

type runResult struct {
	Status              string                      `json:"status"`
	Scenario            string                      `json:"scenario"`
	Seed                int64                       `json:"seed"`
	StartedAt           time.Time                   `json:"started_at"`
	FinishedAt          time.Time                   `json:"finished_at"`
	RequestCount        int                         `json:"request_count"`
	TrafficElapsedNanos int64                       `json:"traffic_elapsed_nanos"`
	ThroughputPerSecond float64                     `json:"throughput_per_second"`
	Latency             latencySummary              `json:"latency"`
	Faults              []faultResult               `json:"faults,omitempty"`
	ConnectionEvidence  *connectionEvidence         `json:"connection_evidence,omitempty"`
	PressureCorrelation *pressureCorrelationSummary `json:"pressure_correlation,omitempty"`
	Cases               []caseResult                `json:"cases"`
}

const (
	assertionQuiescence     = 6 * time.Second
	matchingW3CTraceID      = "000102030405060708090a0b0c0d0e0f"
	matchingW3CParentSpanID = "1011121314151617"
	matchingW3CTraceFlags   = "01"
)

func main() {
	os.Exit(mainExitCode())
}

func mainExitCode() int {
	cfg := parseFlags()
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	result, err := run(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scenario %s failed: %v\n", cfg.scenario, err)
		if result != nil {
			result.Status = "failed"
			result.FinishedAt = time.Now().UTC()
			_ = encodeRunResult(os.Stdout, result)
		}
		return 1
	}

	result.Status = "passed"
	result.FinishedAt = time.Now().UTC()
	if err := encodeRunResult(os.Stdout, result); err != nil {
		fmt.Fprintf(os.Stderr, "encode scenario result: %v\n", err)
		return 1
	}
	return 0
}

func encodeRunResult(writer io.Writer, result *runResult) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.baseURL, "base-url", "http://127.0.0.1:18080", "Apache base URL")
	flag.StringVar(&cfg.receiverURL, "receiver-url", "http://127.0.0.1:14318", "trace receiver base URL")
	flag.StringVar(&cfg.scenario, "scenario", "basic", "basic, keepalive, pipelining, concurrency, connection-churn, fd-port-reuse, slow-body, tls-boundary, timeout-retry, pressure, handoff, virtual-thread, netty, dispatch, w3c, w3c-match, obi-flags, w3c-fault, w3c-only, restart-fault, fail-open, restart, disabled, or uninstrumented")
	flag.IntVar(&cfg.requestCount, "requests", 0, "number of requests (zero selects a scenario default)")
	flag.DurationVar(&cfg.timeout, "timeout", 45*time.Second, "whole-scenario timeout")
	flag.StringVar(&cfg.expectedTLS, "expected-tls", "TLSv1.3", "backend TLS protocol")
	flag.Int64Var(&cfg.seed, "seed", 1, "deterministic request and W3C identifier seed")
	flag.StringVar(&cfg.apacheService, "apache-service", "apache-proxy", "Apache service.name")
	flag.StringVar(&cfg.javaService, "java-service", "java-backend", "Java service.name")
	flag.Parse()

	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}
	validScenarios := map[string]bool{
		"basic": true, "keepalive": true, "pipelining": true, "concurrency": true,
		"connection-churn": true, "fd-port-reuse": true,
		"slow-body": true, "tls-boundary": true, "timeout-retry": true,
		"pressure": true,
		"handoff":  true, "virtual-thread": true, "netty": true, "dispatch": true,
		"w3c": true, "w3c-match": true, "obi-flags": true, "w3c-fault": true,
		"w3c-only": true, "restart-fault": true,
		"disabled": true, "uninstrumented": true,
		"fail-open": true, "restart": true,
	}
	if !validScenarios[cfg.scenario] {
		fmt.Fprintf(os.Stderr, "invalid scenario %q\n", cfg.scenario)
		os.Exit(2)
	}
	if cfg.requestCount < 0 || cfg.requestCount > 1000 {
		fmt.Fprintln(os.Stderr, "requests must be between 0 and 1000")
		os.Exit(2)
	}
	if cfg.timeout <= 0 || cfg.timeout > 10*time.Minute {
		fmt.Fprintln(os.Stderr, "timeout must be positive and at most 10m")
		os.Exit(2)
	}
	return cfg
}

func run(ctx context.Context, cfg config) (*runResult, error) {
	result := &runResult{Scenario: cfg.scenario, Seed: cfg.seed, StartedAt: time.Now().UTC()}
	if err := waitForHealth(ctx, cfg.receiverURL+"/healthz"); err != nil {
		return result, fmt.Errorf("receiver readiness: %w", err)
	}
	if err := post(ctx, cfg.receiverURL+"/reset"); err != nil {
		return result, fmt.Errorf("reset receiver: %w", err)
	}
	if cfg.scenario == "timeout-retry" {
		fault, err := exerciseTimeoutCancellation(ctx, cfg)
		result.Faults = append(result.Faults, fault)
		if err != nil {
			return result, err
		}
	}

	requests, err := makeRequests(cfg)
	if err != nil {
		return result, err
	}
	result.RequestCount = len(requests)

	responses, latencies, elapsed, evidence, err := sendRequests(ctx, cfg, requests)
	result.ConnectionEvidence = evidence
	if err != nil {
		return result, err
	}
	result.TrafficElapsedNanos = elapsed.Nanoseconds()
	if elapsed > 0 {
		result.ThroughputPerSecond = float64(len(requests)) / elapsed.Seconds()
	}
	result.Latency = summarizeLatencies(latencies)
	for i := range requests {
		result.Cases = append(result.Cases, caseResult{
			Request: requests[i], Response: responses[i], LatencyNanos: latencies[i],
		})
	}
	if err := validateConnectionShape(cfg.scenario, responses, evidence); err != nil {
		return result, err
	}
	if err := validateTLSReadShape(cfg.scenario, requests, responses); err != nil {
		return result, err
	}

	snapshots, assertionErr := awaitAssertions(ctx, cfg, requests)
	for i := range snapshots {
		result.Cases[i].Trace = snapshots[i]
	}
	var pressureErr error
	if cfg.scenario == "pressure" {
		summary := summarizePressureCorrelation(cfg, result.Cases)
		result.PressureCorrelation = &summary
		pressureErr = validatePressureCorrelation(summary, len(requests))
	}
	if assertionErr != nil {
		return result, assertionErr
	}
	if pressureErr != nil {
		return result, pressureErr
	}
	if err := validateDistinctParents(cfg.scenario, cfg.javaService, result.Cases); err != nil {
		return result, err
	}

	return result, nil
}

func makeRequests(cfg config) ([]requestCase, error) {
	seed := uint64(cfg.seed)
	var randomSeed [32]byte
	for index := range 4 {
		binary.LittleEndian.PutUint64(
			randomSeed[index*8:],
			seed+uint64(index)*0x9e3779b97f4a7c15,
		)
	}
	random := rand.NewChaCha8(randomSeed)
	count := cfg.requestCount
	if count == 0 {
		switch cfg.scenario {
		case "keepalive", "pipelining":
			count = 10
		case "concurrency":
			count = 16
		case "connection-churn", "fd-port-reuse":
			count = 32
		case "restart-fault":
			count = 32
		case "slow-body":
			count = 8
		case "pressure":
			count = 128
		case "handoff", "virtual-thread", "netty", "dispatch":
			count = 4
		case "w3c", "obi-flags", "w3c-fault", "tls-boundary":
			count = 2
		default:
			count = 1
		}
	}
	if (cfg.scenario == "keepalive" || cfg.scenario == "pipelining") && count < 3 {
		return nil, fmt.Errorf("scenario %s requires at least three requests", cfg.scenario)
	}
	if cfg.scenario == "fd-port-reuse" && count < 2 {
		return nil, fmt.Errorf("scenario %s requires at least two requests", cfg.scenario)
	}
	if cfg.scenario == "slow-body" && count < 2 {
		return nil, fmt.Errorf("scenario %s requires at least two requests", cfg.scenario)
	}
	if cfg.scenario == "tls-boundary" && count != 2 {
		return nil, fmt.Errorf("scenario %s requires exactly two requests", cfg.scenario)
	}

	requests := make([]requestCase, count)
	for i := range requests {
		suffix, err := randomHex(random, 8)
		if err != nil {
			return nil, fmt.Errorf("generate request marker: %w", err)
		}
		requests[i].Marker = fmt.Sprintf("%s-%02d-%s", cfg.scenario, i, suffix)
		requests[i].Endpoint = "/api/echo"
		if cfg.scenario == "concurrency" {
			requests[i].DelayMillis = 150
		}
		if cfg.scenario == "connection-churn" || cfg.scenario == "fd-port-reuse" {
			requests[i].CloseConnection = true
		}
		if cfg.scenario == "fd-port-reuse" {
			requests[i].ObserveSocket = true
		}
		if cfg.scenario == "slow-body" {
			requests[i].SlowBodyBytes = 64 << 10
		}
		if cfg.scenario == "pressure" {
			requests[i].Endpoint = "/api/handoff"
			requests[i].HandoffHops = 2 + i%7
			requests[i].HandoffFault = "none"
		}
		if cfg.scenario == "handoff" {
			faults := [...]string{"none", "cancel", "reject", "timeout"}
			requests[i].Endpoint = "/api/handoff"
			requests[i].HandoffHops = 1 + i%8
			requests[i].HandoffFault = faults[i%len(faults)]
		}
		if cfg.scenario == "virtual-thread" {
			requests[i].Endpoint = "/api/virtual"
			requests[i].VirtualMixed = i&1 != 0
			requests[i].VirtualCancel = i&2 != 0
		}
		if cfg.scenario == "netty" {
			requests[i].Endpoint = "/api/netty"
			requests[i].NettyCancel = i&1 != 0
		}
		if cfg.scenario == "dispatch" {
			requests[i].Endpoint = "/api/dispatch"
			requests[i].DispatchRounds = 1 + i%8
		}
		if cfg.scenario == "tls-boundary" {
			requests[i].Endpoint = "/api/tls-boundary"
			if i == 0 {
				requests[i].TLSBoundaryMode = "split"
			} else {
				requests[i].TLSBoundaryMode = "coalesced"
			}
		}
		switch cfg.scenario {
		case "w3c":
			if i%2 == 0 {
				if err := addW3CContext(random, &requests[i], "01", "conflicting-valid-w3c-and-obi"); err != nil {
					return nil, err
				}
			} else {
				requests[i].InvalidW3C = true
				requests[i].W3CCase = "malformed-w3c-valid-obi"
			}
		case "w3c-match":
			requests[i].W3CTraceID = matchingW3CTraceID
			requests[i].W3CParentSpanID = matchingW3CParentSpanID
			requests[i].W3CTraceFlags = matchingW3CTraceFlags
			requests[i].W3CCase = "matching-w3c-and-obi"
		case "obi-flags":
			requests[i].Endpoint = "/api/obi-flags"
			flags := "00"
			if i%2 != 0 {
				flags = "01"
			}
			if err := addW3CContext(random, &requests[i], flags, "obi-only-"+flags); err != nil {
				return nil, err
			}
		case "w3c-fault":
			fault := "stale"
			if i%2 != 0 {
				fault = "malformed"
			}
			if err := addW3CContext(random, &requests[i], "01", "valid-w3c-"+fault+"-obi"); err != nil {
				return nil, err
			}
		case "w3c-only":
			if err := addW3CContext(random, &requests[i], "01", "valid-w3c-no-obi"); err != nil {
				return nil, err
			}
		case "restart-fault":
			requests[i].DelayMillis = 75
			if err := addW3CContext(random, &requests[i], "01", "valid-w3c-during-obi-restart"); err != nil {
				return nil, err
			}
		}
	}
	if parallelScenario(cfg.scenario) {
		for i := range requests {
			requests[i].CloseConnection = true
		}
	} else {
		requests[len(requests)-1].CloseConnection = true
	}
	return requests, nil
}

func addW3CContext(random io.Reader, request *requestCase, flags, caseName string) error {
	var err error
	request.W3CTraceID, err = randomHex(random, 16)
	if err != nil {
		return fmt.Errorf("generate W3C trace ID: %w", err)
	}
	request.W3CParentSpanID, err = randomHex(random, 8)
	if err != nil {
		return fmt.Errorf("generate W3C span ID: %w", err)
	}
	request.W3CTraceFlags = flags
	request.W3CCase = caseName
	return nil
}

func sendRequests(
	ctx context.Context,
	cfg config,
	requests []requestCase,
) ([]backendResponse, []int64, time.Duration, *connectionEvidence, error) {
	switch cfg.scenario {
	case "pipelining":
		return sendPipelinedRequests(ctx, cfg, requests)
	case "fd-port-reuse":
		return sendFDPortReuseRequests(ctx, cfg, requests)
	}

	maxConnections := len(requests)
	if cfg.scenario == "keepalive" {
		maxConnections = 1
	}
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        maxConnections,
		MaxIdleConnsPerHost: maxConnections,
		MaxConnsPerHost:     maxConnections,
		IdleConnTimeout:     30 * time.Second,
	}
	if cfg.scenario == "connection-churn" {
		transport.DisableKeepAlives = true
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}

	responses := make([]backendResponse, len(requests))
	latencies := make([]int64, len(requests))
	trafficStart := time.Now()
	if !parallelScenario(cfg.scenario) {
		for i := range requests {
			if cfg.scenario == "restart-fault" && i > 0 {
				select {
				case <-ctx.Done():
					return responses, latencies, time.Since(trafficStart), nil, ctx.Err()
				case <-time.After(50 * time.Millisecond):
				}
			}
			requestStart := time.Now()
			response, err := sendRequest(ctx, client, cfg, requests[i])
			latencies[i] = time.Since(requestStart).Nanoseconds()
			if err != nil {
				return responses, latencies, time.Since(trafficStart), nil, fmt.Errorf("request %d: %w", i, err)
			}
			responses[i] = response
		}
		return responses, latencies, time.Since(trafficStart), nil, nil
	}

	var waitGroup sync.WaitGroup
	errCh := make(chan error, len(requests))
	for i := range requests {
		waitGroup.Add(1)
		go func(index int) {
			defer waitGroup.Done()
			requestStart := time.Now()
			response, err := sendRequest(ctx, client, cfg, requests[index])
			latencies[index] = time.Since(requestStart).Nanoseconds()
			if err != nil {
				errCh <- fmt.Errorf("request %d: %w", index, err)
				return
			}
			responses[index] = response
		}(i)
	}
	waitGroup.Wait()
	close(errCh)
	if err := <-errCh; err != nil {
		return responses, latencies, time.Since(trafficStart), nil, err
	}
	return responses, latencies, time.Since(trafficStart), nil, nil
}

func sendPipelinedRequests(
	ctx context.Context,
	cfg config,
	requests []requestCase,
) ([]backendResponse, []int64, time.Duration, *connectionEvidence, error) {
	network, address, err := directTCPAddress(cfg.baseURL)
	if err != nil {
		return nil, nil, 0, nil, err
	}
	connection, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, address)
	if err != nil {
		return nil, nil, 0, nil, fmt.Errorf("dial Apache for HTTP/1.1 pipeline: %w", err)
	}
	defer connection.Close()
	if err := setConnectionDeadline(ctx, connection); err != nil {
		return nil, nil, 0, nil, err
	}

	trafficStart := time.Now()
	requestStart := make([]time.Time, len(requests))
	for i := range requestStart {
		requestStart[i] = trafficStart
	}
	requestWriter := bufio.NewWriter(connection)
	httpRequests, err := writePipelinedRequests(ctx, requestWriter, cfg, requests)
	if err != nil {
		return nil, nil, time.Since(trafficStart), nil, err
	}
	evidence := &connectionEvidence{
		FrontendConnections:            1,
		FrontendProtocol:               "HTTP/1.1",
		PipelinedRequests:              len(requests),
		RequestsWrittenBeforeFirstRead: len(requests),
	}

	responses := make([]backendResponse, len(requests))
	latencies := make([]int64, len(requests))
	responseReader := bufio.NewReader(connection)
	for i := range requests {
		response, readErr := http.ReadResponse(responseReader, httpRequests[i])
		latencies[i] = time.Since(requestStart[i]).Nanoseconds()
		if readErr != nil {
			return responses, latencies, time.Since(trafficStart), evidence, fmt.Errorf("read pipelined response %d: %w", i, readErr)
		}
		backend, decodeErr := decodeBackendResponse(response, cfg, requests[i])
		if decodeErr != nil {
			return responses, latencies, time.Since(trafficStart), evidence, fmt.Errorf("pipelined response %d: %w", i, decodeErr)
		}
		responses[i] = backend
	}

	return responses, latencies, time.Since(trafficStart), evidence, nil
}

func writePipelinedRequests(
	ctx context.Context,
	writer *bufio.Writer,
	cfg config,
	requests []requestCase,
) ([]*http.Request, error) {
	httpRequests := make([]*http.Request, len(requests))
	for i := range requests {
		request, err := newHTTPRequest(ctx, cfg, requests[i])
		if err != nil {
			return nil, fmt.Errorf("build pipelined request %d: %w", i, err)
		}
		if request.Method != http.MethodGet || request.Body != nil {
			return nil, fmt.Errorf("pipelined request %d must be a bodyless GET", i)
		}
		request.Proto = "HTTP/1.1"
		request.ProtoMajor = 1
		request.ProtoMinor = 1
		request.Close = i == len(requests)-1
		if err := request.Write(writer); err != nil {
			return nil, fmt.Errorf("write pipelined request %d: %w", i, err)
		}
		httpRequests[i] = request
	}
	if err := writer.Flush(); err != nil {
		return nil, fmt.Errorf("flush HTTP/1.1 pipeline: %w", err)
	}
	return httpRequests, nil
}

func sendFDPortReuseRequests(
	ctx context.Context,
	cfg config,
	requests []requestCase,
) ([]backendResponse, []int64, time.Duration, *connectionEvidence, error) {
	network, address, err := directTCPAddress(cfg.baseURL)
	if err != nil {
		return nil, nil, 0, nil, err
	}

	responses := make([]backendResponse, len(requests))
	latencies := make([]int64, len(requests))
	observations := make([]socketObservation, len(requests))
	var reusedLocalAddress *net.TCPAddr
	trafficStart := time.Now()
	for i := range requests {
		requestStart := time.Now()
		connection, dialErr := dialWithAddressReuse(ctx, network, address, reusedLocalAddress)
		if dialErr != nil {
			return responses, latencies, time.Since(trafficStart), nil, fmt.Errorf("request %d reused-port dial: %w", i, dialErr)
		}
		if deadlineErr := setConnectionDeadline(ctx, connection); deadlineErr != nil {
			_ = connection.Close()
			return responses, latencies, time.Since(trafficStart), nil, deadlineErr
		}
		if reusedLocalAddress == nil {
			localAddress, ok := connection.LocalAddr().(*net.TCPAddr)
			if !ok || localAddress.Port == 0 {
				_ = connection.Close()
				return responses, latencies, time.Since(trafficStart), nil, errors.New("first reused-port connection has no TCP local port")
			}
			reusedLocalAddress = cloneTCPAddress(localAddress)
		}
		descriptor, descriptorErr := connectionFileDescriptor(connection)
		if descriptorErr != nil {
			_ = connection.Close()
			return responses, latencies, time.Since(trafficStart), nil, fmt.Errorf("request %d frontend descriptor: %w", i, descriptorErr)
		}
		localAddress := connection.LocalAddr().(*net.TCPAddr)
		observations[i] = socketObservation{FileDescriptor: descriptor, LocalPort: localAddress.Port}

		response, requestErr := sendRequestOnConnection(ctx, connection, cfg, requests[i])
		latencies[i] = time.Since(requestStart).Nanoseconds()
		_ = connection.SetLinger(0)
		_ = connection.Close()
		if requestErr != nil {
			return responses, latencies, time.Since(trafficStart), nil, fmt.Errorf("request %d: %w", i, requestErr)
		}
		responses[i] = response
	}

	evidence := buildReuseEvidence(responses, observations)
	return responses, latencies, time.Since(trafficStart), evidence, nil
}

func sendRequestOnConnection(
	ctx context.Context,
	connection *net.TCPConn,
	cfg config,
	requestCase requestCase,
) (backendResponse, error) {
	request, err := newHTTPRequest(ctx, cfg, requestCase)
	if err != nil {
		return backendResponse{}, err
	}
	request.Proto = "HTTP/1.1"
	request.ProtoMajor = 1
	request.ProtoMinor = 1
	request.Close = true
	if err := request.Write(connection); err != nil {
		return backendResponse{}, err
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), request)
	if err != nil {
		return backendResponse{}, err
	}
	return decodeBackendResponse(response, cfg, requestCase)
}

func dialWithAddressReuse(
	ctx context.Context,
	network string,
	address string,
	localAddress *net.TCPAddr,
) (*net.TCPConn, error) {
	retryDeadline := time.Now().Add(time.Second)
	for {
		dialer := &net.Dialer{
			Timeout:   3 * time.Second,
			LocalAddr: localAddress,
			Control:   enableAddressReuse,
		}
		connection, err := dialer.DialContext(ctx, network, address)
		if err == nil {
			tcpConnection, ok := connection.(*net.TCPConn)
			if !ok {
				_ = connection.Close()
				return nil, fmt.Errorf("expected TCP connection, got %T", connection)
			}
			return tcpConnection, nil
		}
		if localAddress == nil || time.Now().After(retryDeadline) {
			return nil, err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func directTCPAddress(baseURL string) (string, string, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return "", "", err
	}
	if parsed.Scheme != "http" {
		return "", "", fmt.Errorf("raw HTTP/1.1 scenarios require an http base URL, got %q", parsed.Scheme)
	}
	hostname := parsed.Hostname()
	if hostname == "" {
		return "", "", errors.New("base URL has no hostname")
	}
	port := parsed.Port()
	if port == "" {
		port = "80"
	}
	resolved, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(hostname, port))
	if err != nil {
		return "", "", fmt.Errorf("resolve Apache address: %w", err)
	}
	network := "tcp6"
	if resolved.IP.To4() != nil {
		network = "tcp4"
	}
	return network, resolved.String(), nil
}

func setConnectionDeadline(ctx context.Context, connection net.Conn) error {
	deadline := time.Now().Add(10 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set connection deadline: %w", err)
	}
	return nil
}

func cloneTCPAddress(address *net.TCPAddr) *net.TCPAddr {
	return &net.TCPAddr{
		IP:   append(net.IP(nil), address.IP...),
		Port: address.Port,
		Zone: address.Zone,
	}
}

func buildReuseEvidence(
	responses []backendResponse,
	observations []socketObservation,
) *connectionEvidence {
	backendPorts := make(map[int]struct{})
	backendConnections := make(map[uint64]struct{})
	backendConnectionsByDescriptor := make(map[int]map[uint64]struct{})
	for _, response := range responses {
		backendPorts[response.BackendRemotePort] = struct{}{}
		backendConnections[response.BackendConnectionID] = struct{}{}
		connections := backendConnectionsByDescriptor[response.BackendSocketFD]
		if connections == nil {
			connections = make(map[uint64]struct{})
			backendConnectionsByDescriptor[response.BackendSocketFD] = connections
		}
		connections[response.BackendConnectionID] = struct{}{}
	}

	frontendDescriptors := make(map[int]int)
	frontendPorts := make(map[int]struct{})
	for _, observation := range observations {
		frontendDescriptors[observation.FileDescriptor]++
		frontendPorts[observation.LocalPort] = struct{}{}
	}
	evidence := &connectionEvidence{
		FrontendConnections:          len(observations),
		FrontendProtocol:             "HTTP/1.1",
		DistinctFrontendLocalPorts:   len(frontendPorts),
		BackendConnections:           len(responses),
		DistinctBackendConnectionIDs: len(backendConnections),
		DistinctBackendRemotePorts:   len(backendPorts),
	}
	if len(observations) > 0 {
		evidence.ReusedFrontendLocalPort = observations[0].LocalPort
	}
	for descriptor, count := range frontendDescriptors {
		if count > 1 && (evidence.ReusedFrontendFileDescriptor == 0 || descriptor < evidence.ReusedFrontendFileDescriptor) {
			evidence.ReusedFrontendFileDescriptor = descriptor
		}
	}
	for descriptor, connections := range backendConnectionsByDescriptor {
		if descriptor > 0 && len(connections) > 1 && (evidence.ReusedBackendFileDescriptor == 0 || descriptor < evidence.ReusedBackendFileDescriptor) {
			evidence.ReusedBackendFileDescriptor = descriptor
		}
	}
	return evidence
}

func summarizeLatencies(latencies []int64) latencySummary {
	if len(latencies) == 0 {
		return latencySummary{}
	}
	values := append([]int64(nil), latencies...)
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	percentile := func(fraction float64) int64 {
		index := int(math.Ceil(fraction*float64(len(values)))) - 1
		if index < 0 {
			index = 0
		}
		return values[index]
	}
	return latencySummary{
		P50Nanos: percentile(0.50),
		P95Nanos: percentile(0.95),
		P99Nanos: percentile(0.99),
	}
}

func newHTTPRequest(ctx context.Context, cfg config, requestCase requestCase) (*http.Request, error) {
	requestURL, err := url.Parse(cfg.baseURL + requestCase.Endpoint)
	if err != nil {
		return nil, err
	}
	if requestCase.DelayMillis > 0 {
		query := requestURL.Query()
		query.Set("delay_ms", strconv.Itoa(requestCase.DelayMillis))
		requestURL.RawQuery = query.Encode()
	}
	if requestCase.CloseConnection {
		query := requestURL.Query()
		query.Set("close", "1")
		requestURL.RawQuery = query.Encode()
	}
	if requestCase.ObserveSocket {
		query := requestURL.Query()
		query.Set("socket_identity", "1")
		requestURL.RawQuery = query.Encode()
	}
	if requestCase.HandoffHops > 0 {
		query := requestURL.Query()
		query.Set("hops", strconv.Itoa(requestCase.HandoffHops))
		query.Set("fault", requestCase.HandoffFault)
		requestURL.RawQuery = query.Encode()
	}
	if requestCase.Endpoint == "/api/virtual" {
		query := requestURL.Query()
		query.Set("mixed", boolFlag(requestCase.VirtualMixed))
		query.Set("cancel", boolFlag(requestCase.VirtualCancel))
		requestURL.RawQuery = query.Encode()
	}
	if requestCase.Endpoint == "/api/netty" {
		query := requestURL.Query()
		query.Set("cancel", boolFlag(requestCase.NettyCancel))
		requestURL.RawQuery = query.Encode()
	}
	if requestCase.Endpoint == "/api/dispatch" {
		query := requestURL.Query()
		query.Set("rounds", strconv.Itoa(requestCase.DispatchRounds))
		requestURL.RawQuery = query.Encode()
	}
	if requestCase.Endpoint == "/api/tls-boundary" {
		query := requestURL.Query()
		query.Set("mode", requestCase.TLSBoundaryMode)
		requestURL.RawQuery = query.Encode()
	}

	method := http.MethodGet
	var requestBody io.Reader
	if requestCase.SlowBodyBytes > 0 {
		method = http.MethodPost
		requestBody = &pacedReader{
			remaining: requestCase.SlowBodyBytes,
			chunkSize: 64,
			delay:     2 * time.Millisecond,
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), requestBody)
	if err != nil {
		return nil, err
	}
	request.Header.Set(tracecheck.MarkerHeader, requestCase.Marker)
	if requestCase.SlowBodyBytes > 0 {
		request.ContentLength = int64(requestCase.SlowBodyBytes)
		request.Header.Set("Content-Type", "application/octet-stream")
	}
	request.Close = requestCase.CloseConnection
	if requestCase.W3CTraceID != "" {
		request.Header.Set("traceparent", fmt.Sprintf(
			"00-%s-%s-%s",
			requestCase.W3CTraceID,
			requestCase.W3CParentSpanID,
			requestCase.W3CTraceFlags,
		))
	} else if requestCase.InvalidW3C {
		request.Header.Set("traceparent", "00-invalid")
	}
	return request, nil
}

func sendRequest(ctx context.Context, client *http.Client, cfg config, requestCase requestCase) (backendResponse, error) {
	request, err := newHTTPRequest(ctx, cfg, requestCase)
	if err != nil {
		return backendResponse{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return backendResponse{}, err
	}
	return decodeBackendResponse(response, cfg, requestCase)
}

func decodeBackendResponse(
	response *http.Response,
	cfg config,
	requestCase requestCase,
) (backendResponse, error) {
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return backendResponse{}, err
	}
	if response.StatusCode != http.StatusOK {
		return backendResponse{}, fmt.Errorf("unexpected HTTP status %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}

	var backend backendResponse
	if err := json.Unmarshal(body, &backend); err != nil {
		return backendResponse{}, fmt.Errorf("decode backend response: %w", err)
	}
	backend.Workload = response.Header.Get("X-OBI-Workload")
	backend.HandoffHops = response.Header.Get("X-OBI-Handoff-Hops")
	backend.HandoffFault = response.Header.Get("X-OBI-Handoff-Fault")
	backend.VirtualMixed = response.Header.Get("X-OBI-Virtual-Mixed")
	backend.VirtualCancel = response.Header.Get("X-OBI-Virtual-Cancel")
	backend.NettyCancel = response.Header.Get("X-OBI-Netty-Cancel")
	backend.DispatchRounds = response.Header.Get("X-OBI-Dispatch-Rounds")
	backend.DispatchInvocations = response.Header.Get("X-OBI-Dispatch-Invocations")
	if backend.Marker != requestCase.Marker {
		return backendResponse{}, fmt.Errorf("expected response marker %q, got %q", requestCase.Marker, backend.Marker)
	}
	if !backend.Secure {
		return backendResponse{}, errors.New("jetty reported an insecure backend request")
	}
	if backend.Protocol != "HTTP/1.1" {
		return backendResponse{}, fmt.Errorf("expected backend HTTP/1.1, got %q", backend.Protocol)
	}
	if backend.TLSProtocol != cfg.expectedTLS {
		return backendResponse{}, fmt.Errorf("expected backend %s, got %q", cfg.expectedTLS, backend.TLSProtocol)
	}
	if backend.TLSCipher == "" || backend.BackendConnectionID == 0 || backend.BackendRemotePort == 0 {
		return backendResponse{}, errors.New("backend omitted TLS, stable connection, or remote port diagnostics")
	}
	if requestCase.ObserveSocket && backend.BackendSocketFD <= 0 {
		return backendResponse{}, errors.New("backend omitted its accepted socket file descriptor")
	}
	if err := validateWorkloadResponse(requestCase, backend); err != nil {
		return backendResponse{}, err
	}
	return backend, nil
}

func boolFlag(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func validateWorkloadResponse(request requestCase, response backendResponse) error {
	switch request.Endpoint {
	case "/api/handoff":
		if response.Workload != "servlet-async-executor" ||
			response.HandoffHops != strconv.Itoa(request.HandoffHops) ||
			response.HandoffFault != request.HandoffFault {
			return fmt.Errorf(
				"handoff response did not prove requested workload: workload=%q hops=%q fault=%q",
				response.Workload,
				response.HandoffHops,
				response.HandoffFault,
			)
		}
	case "/api/virtual":
		if response.Workload != "virtual-thread" ||
			response.VirtualMixed != boolFlag(request.VirtualMixed) ||
			response.VirtualCancel != boolFlag(request.VirtualCancel) {
			return fmt.Errorf(
				"virtual-thread response did not prove requested workload: workload=%q mixed=%q cancel=%q",
				response.Workload,
				response.VirtualMixed,
				response.VirtualCancel,
			)
		}
	case "/api/netty":
		if response.Workload != "netty-eventloop-worker" ||
			response.NettyCancel != boolFlag(request.NettyCancel) {
			return fmt.Errorf(
				"netty response did not prove requested workload: workload=%q cancel=%q",
				response.Workload,
				response.NettyCancel,
			)
		}
	case "/api/dispatch":
		if response.Workload != "servlet-async-redispatch" ||
			response.DispatchRounds != strconv.Itoa(request.DispatchRounds) ||
			response.DispatchInvocations != strconv.Itoa(request.DispatchRounds+1) {
			return fmt.Errorf(
				"dispatch response did not prove requested workload: workload=%q rounds=%q invocations=%q",
				response.Workload,
				response.DispatchRounds,
				response.DispatchInvocations,
			)
		}
	case "/api/tls-boundary":
		return validateTLSBoundaryResponse(request, response)
	}
	return nil
}

func validateTLSBoundaryResponse(request requestCase, response backendResponse) error {
	evidence := response.TLSBoundary
	if evidence == nil {
		return errors.New("TLS boundary response omitted fixture evidence")
	}
	if evidence.Mode != request.TLSBoundaryMode || !evidence.Passed || !evidence.ShapeExact ||
		!equalInts(evidence.ExpectedPlaintextCallbackLengths, evidence.ActualPlaintextCallbackLengths) ||
		!evidence.BuffersForwardedUnchanged || !evidence.HandoffBeforeParse ||
		!evidence.ConnectionClosed {
		return fmt.Errorf("TLS boundary evidence failed for mode %s: %+v", request.TLSBoundaryMode, evidence)
	}

	expectedOrder := []int{1}
	expectedCallbacks := 2
	if request.TLSBoundaryMode == "coalesced" {
		expectedOrder = []int{1, 2}
		expectedCallbacks = 1
	}
	if len(evidence.ExpectedPlaintextCallbackLengths) != expectedCallbacks ||
		!equalInts(evidence.RequestOrder, expectedOrder) ||
		!equalInts(evidence.ResponseOrder, expectedOrder) {
		return fmt.Errorf("TLS boundary evidence had the wrong deterministic shape for mode %s: %+v", request.TLSBoundaryMode, evidence)
	}
	for _, length := range evidence.ExpectedPlaintextCallbackLengths {
		if length <= 0 || length > tlsBoundaryMaxHTTPBytes {
			return fmt.Errorf("TLS boundary callback length is out of bounds: %d", length)
		}
	}
	return nil
}

const tlsBoundaryMaxHTTPBytes = 16 * 1024

func equalInts(left, right []int) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func exerciseTimeoutCancellation(ctx context.Context, cfg config) (faultResult, error) {
	fault := faultResult{Kind: "client-timeout", Outcome: "failed"}
	transport := &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DialContext:       (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		ForceAttemptHTTP2: false,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	timedContext, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	request := requestCase{
		Marker:      fmt.Sprintf("timeout-retry-cancelled-%d", cfg.seed),
		Endpoint:    "/api/echo",
		DelayMillis: 500,
	}
	started := time.Now()
	_, err := sendRequest(timedContext, client, cfg, request)
	fault.ElapsedNanos = time.Since(started).Nanoseconds()
	if err == nil {
		return fault, errors.New("cancellation control unexpectedly completed")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		return fault, fmt.Errorf("cancellation control failed for the wrong reason: %w", err)
	}
	fault.Outcome = "deadline-exceeded-as-expected"
	return fault, nil
}

type pacedReader struct {
	remaining int
	chunkSize int
	delay     time.Duration
}

func (r *pacedReader) Read(buffer []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	if r.delay > 0 {
		time.Sleep(r.delay)
	}
	count := min(r.remaining, min(r.chunkSize, len(buffer)))
	for i := 0; i < count; i++ {
		buffer[i] = byte(i)
	}
	r.remaining -= count
	return count, nil
}

func expectationFor(cfg config, request requestCase) tracecheck.Expectation {
	mode := tracecheck.ModeBridge
	expectedTraceFlags := request.W3CTraceFlags
	javaTraceFlags := ""
	switch cfg.scenario {
	case "pipelining":
		mode = tracecheck.ModePipelinedBridge
	case "pressure":
		mode = tracecheck.ModePressure
	case "disabled":
		mode = tracecheck.ModeDisabled
	case "uninstrumented":
		mode = tracecheck.ModeUninstrumented
	case "fail-open":
		mode = tracecheck.ModeFailOpen
	case "w3c":
		if !request.InvalidW3C {
			mode = tracecheck.ModeW3C
		}
	case "w3c-match":
		mode = tracecheck.ModeW3CMatch
	case "obi-flags":
		javaTraceFlags = "01"
	case "w3c-fault":
		mode = tracecheck.ModeW3CNoOBI
	case "w3c-only":
		mode = tracecheck.ModeW3CNoOBI
	case "restart-fault":
		mode = tracecheck.ModeW3CResilience
	}
	return tracecheck.Expectation{
		Mode:            mode,
		ApacheService:   cfg.apacheService,
		JavaService:     cfg.javaService,
		Endpoint:        request.Endpoint,
		Marker:          request.Marker,
		W3CTraceID:      request.W3CTraceID,
		W3CParentSpanID: request.W3CParentSpanID,
		W3CTraceFlags:   expectedTraceFlags,
		JavaTraceFlags:  javaTraceFlags,
	}
}

func summarizePressureCorrelation(
	cfg config,
	cases []caseResult,
) pressureCorrelationSummary {
	var summary pressureCorrelationSummary
	for index := range cases {
		outcome, _ := tracecheck.ClassifyPressureParent(
			cases[index].Trace,
			expectationFor(cfg, cases[index].Request),
		)
		cases[index].PressureParentOutcome = outcome
		switch outcome {
		case tracecheck.PressureParentExactHit:
			summary.ExactHitCount++
		case tracecheck.PressureParentExplicitRoot:
			summary.ExplicitRootCount++
		case tracecheck.PressureParentWrong:
			summary.WrongParentCount++
		case tracecheck.PressureParentUnresolved:
			summary.UnresolvedCount++
		}
	}
	return summary
}

func validatePressureCorrelation(summary pressureCorrelationSummary, requestCount int) error {
	if summary.WrongParentCount != 0 || summary.UnresolvedCount != 0 ||
		summary.ExactHitCount+summary.ExplicitRootCount != requestCount {
		return fmt.Errorf(
			"pressure correlation expected exact hits plus explicit roots=%d with wrong=0 unresolved=0, got exact_hits=%d explicit_roots=%d wrong=%d unresolved=%d",
			requestCount,
			summary.ExactHitCount,
			summary.ExplicitRootCount,
			summary.WrongParentCount,
			summary.UnresolvedCount,
		)
	}
	return nil
}

type snapshotFetcher func(context.Context, string, string) (tracecheck.Snapshot, error)

func awaitAssertions(
	ctx context.Context,
	cfg config,
	requests []requestCase,
) ([]tracecheck.Snapshot, error) {
	return awaitAssertionsWithFetcher(ctx, cfg, requests, fetchSnapshot)
}

func awaitAssertionsWithFetcher(
	ctx context.Context,
	cfg config,
	requests []requestCase,
	fetch snapshotFetcher,
) ([]tracecheck.Snapshot, error) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	snapshots := make([]tracecheck.Snapshot, len(requests))
	var validSince time.Time
	var lastErr error

	for {
		valid := true
		var firstPassErr error
		var lastPassErr error
		failedMarkers := 0
		for i := range requests {
			snapshot, err := fetch(ctx, cfg.receiverURL, requests[i].Marker)
			if err == nil {
				snapshots[i] = snapshot
				err = tracecheck.AssertSnapshot(snapshot, expectationFor(cfg, requests[i]))
			}
			if err != nil {
				valid = false
				failedMarkers++
				markerErr := fmt.Errorf("marker %s: %w", requests[i].Marker, err)
				if firstPassErr == nil {
					firstPassErr = markerErr
				}
				lastPassErr = markerErr
			}
		}
		if firstPassErr != nil {
			lastErr = firstPassErr
			if failedMarkers > 1 {
				lastErr = fmt.Errorf("first result: %w; last result: %w", firstPassErr, lastPassErr)
			}
		}

		if valid {
			if validSince.IsZero() {
				validSince = time.Now()
			}
			if time.Since(validSince) >= assertionQuiescence {
				return snapshots, nil
			}
		} else {
			validSince = time.Time{}
		}

		select {
		case <-ctx.Done():
			return snapshots, fmt.Errorf("trace assertion deadline: %w (last result: %w)", ctx.Err(), lastErr)
		case <-ticker.C:
		}
	}
}

func fetchSnapshot(ctx context.Context, receiverURL, marker string) (tracecheck.Snapshot, error) {
	requestURL := receiverURL + "/snapshot?marker=" + url.QueryEscape(marker)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return tracecheck.Snapshot{}, err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return tracecheck.Snapshot{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return tracecheck.Snapshot{}, fmt.Errorf("snapshot HTTP status %d", response.StatusCode)
	}
	var snapshot tracecheck.Snapshot
	if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&snapshot); err != nil {
		return tracecheck.Snapshot{}, err
	}
	return snapshot, nil
}

func validateTLSReadShape(
	scenario string,
	requests []requestCase,
	responses []backendResponse,
) error {
	if scenario != "slow-body" {
		return nil
	}
	if len(requests) < 2 || len(responses) != len(requests) {
		return errors.New("slow-body TLS read evidence requires at least two complete requests")
	}

	for index := 1; index < len(responses); index++ {
		previous := responses[index-1]
		current := responses[index]
		if previous.TLSReadEvents < 0 || previous.TLSReadBytes < 0 ||
			current.TLSReadEvents < 0 || current.TLSReadBytes < 0 {
			return errors.New("backend TLS read diagnostics are unavailable")
		}
		readEvents := current.TLSReadEvents - previous.TLSReadEvents
		readBytes := current.TLSReadBytes - previous.TLSReadBytes
		if readEvents < 2 || readBytes < int64(requests[index].SlowBodyBytes) {
			return fmt.Errorf(
				"request %d did not prove split decrypted reads: events=%d bytes=%d body=%d",
				index,
				readEvents,
				readBytes,
				requests[index].SlowBodyBytes,
			)
		}
	}
	return nil
}

func validateConnectionShape(
	scenario string,
	responses []backendResponse,
	evidence *connectionEvidence,
) error {
	connectionIDs := make(map[uint64]struct{})
	for _, response := range responses {
		if response.BackendConnectionID == 0 {
			return errors.New("backend connection evidence contains a zero stable ID")
		}
		connectionIDs[response.BackendConnectionID] = struct{}{}
	}
	switch scenario {
	case "keepalive":
		if err := validateKeepaliveConnection(responses); err != nil {
			return err
		}
	case "concurrency":
		if len(responses) > 1 && len(connectionIDs) < 2 {
			return fmt.Errorf("expected parallel backend connections, observed backend connection IDs %v", sortedConnectionIDs(connectionIDs))
		}
	case "connection-churn":
		if len(responses) > 1 && len(connectionIDs) < 2 {
			return fmt.Errorf("expected backend connection churn, observed backend connection IDs %v", sortedConnectionIDs(connectionIDs))
		}
	case "pipelining":
		if evidence == nil || evidence.FrontendConnections != 1 ||
			evidence.PipelinedRequests != len(responses) ||
			evidence.RequestsWrittenBeforeFirstRead != len(responses) {
			return fmt.Errorf("pipeline evidence is incomplete: %+v", evidence)
		}
		if err := validateReuseBeforeTerminalClose(responses, connectionIDs); err != nil {
			return err
		}
	case "fd-port-reuse":
		if evidence == nil {
			return errors.New("fd/port reuse evidence is missing")
		}
		if evidence.FrontendConnections != len(responses) ||
			evidence.DistinctFrontendLocalPorts != 1 ||
			evidence.ReusedFrontendLocalPort == 0 {
			return fmt.Errorf("expected every reopened frontend connection to reuse one ephemeral port: %+v", evidence)
		}
		if evidence.ReusedFrontendFileDescriptor == 0 {
			return fmt.Errorf("expected frontend file-descriptor reuse: %+v", evidence)
		}
		if evidence.BackendConnections != len(responses) ||
			evidence.DistinctBackendConnectionIDs != len(responses) {
			return fmt.Errorf("expected closed and reopened Apache-to-Jetty connections: %+v", evidence)
		}
		if evidence.ReusedBackendFileDescriptor == 0 {
			return fmt.Errorf("expected one Jetty descriptor to be reused across distinct stable Jetty connections: %+v", evidence)
		}
	}
	return nil
}

func validateKeepaliveConnection(responses []backendResponse) error {
	if len(responses) < 3 {
		return errors.New("expected at least two requests before the terminal backend close")
	}

	expected := responses[0]
	for index, response := range responses[1:] {
		if response.BackendConnectionID == expected.BackendConnectionID &&
			response.BackendRemotePort == expected.BackendRemotePort &&
			response.TLSProtocol == expected.TLSProtocol &&
			response.TLSCipher == expected.TLSCipher {
			continue
		}
		return fmt.Errorf(
			"expected keepalive request %d to reuse backend TLS connection id=%d remote_port=%d protocol=%q cipher=%q, got id=%d remote_port=%d protocol=%q cipher=%q",
			index+1,
			expected.BackendConnectionID,
			expected.BackendRemotePort,
			expected.TLSProtocol,
			expected.TLSCipher,
			response.BackendConnectionID,
			response.BackendRemotePort,
			response.TLSProtocol,
			response.TLSCipher,
		)
	}
	return nil
}

func validateReuseBeforeTerminalClose(
	responses []backendResponse,
	connectionIDs map[uint64]struct{},
) error {
	if len(responses) < 3 {
		return errors.New("expected at least two requests before the terminal backend close")
	}

	reusedID := responses[0].BackendConnectionID
	for _, response := range responses[1 : len(responses)-1] {
		if response.BackendConnectionID != reusedID {
			return fmt.Errorf(
				"expected pre-terminal requests to reuse backend connection %d, observed backend connection IDs %v",
				reusedID,
				sortedConnectionIDs(connectionIDs),
			)
		}
	}
	if len(connectionIDs) > 2 {
		return fmt.Errorf(
			"expected at most one terminal backend connection, observed backend connection IDs %v",
			sortedConnectionIDs(connectionIDs),
		)
	}

	return nil
}

func validateDistinctParents(scenario, javaService string, cases []caseResult) error {
	if !distinctParentScenario(scenario) {
		return nil
	}
	parents := make(map[string]string)
	for _, result := range cases {
		javaSpans := make([]tracecheck.Span, 0, 1)
		for _, span := range result.Trace.Spans {
			if span.ServiceName == javaService && strings.EqualFold(span.Kind, "SERVER") {
				javaSpans = append(javaSpans, span)
			}
		}
		if len(javaSpans) != 1 {
			return fmt.Errorf(
				"expected exactly one Java server span for marker %s, got %d",
				result.Request.Marker,
				len(javaSpans),
			)
		}
		key := javaSpans[0].TraceID + "/" + javaSpans[0].ParentSpanID
		if previous, exists := parents[key]; exists {
			return fmt.Errorf("markers %s and %s shared parent %s", previous, result.Request.Marker, key)
		}
		parents[key] = result.Request.Marker
	}
	return nil
}

func distinctParentScenario(scenario string) bool {
	return parallelScenario(scenario) || scenario == "keepalive" || scenario == "pipelining" ||
		scenario == "fd-port-reuse" || scenario == "tls-boundary"
}

func parallelScenario(scenario string) bool {
	switch scenario {
	case "concurrency", "pressure", "handoff", "virtual-thread", "netty", "dispatch":
		return true
	default:
		return false
	}
}

func sortedConnectionIDs(ids map[uint64]struct{}) []uint64 {
	values := make([]uint64, 0, len(ids))
	for id := range ids {
		values = append(values, id)
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	return values
}

func waitForHealth(ctx context.Context, endpoint string) error {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err == nil {
			response, requestErr := http.DefaultClient.Do(request)
			if requestErr == nil {
				_ = response.Body.Close()
				if response.StatusCode == http.StatusOK {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func post(ctx context.Context, endpoint string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(nil))
	if err != nil {
		return err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
	}
	return nil
}

func randomHex(source io.Reader, byteCount int) (string, error) {
	buffer := make([]byte, byteCount)
	if _, err := io.ReadFull(source, buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}
