// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
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
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/obi/examples/apache-java-https/tracecheck"
)

const (
	defaultRequestTimeout              = 10 * time.Second
	maximumBackendResponseBytes  int64 = 64 << 10
	maximumCoalescedSourceBytes  int64 = 256 << 10
	maximumReceiverSnapshotBytes int64 = 4 << 20
)

type config struct {
	baseURL                string
	receiverURL            string
	scenario               string
	assertionMode          string
	faultMode              string
	javaDiagnosticsBefore  string
	requestCount           int
	timeout                time.Duration
	requestTimeout         time.Duration
	requestTimeoutSet      bool
	expectedTLS            string
	seed                   int64
	apacheService          string
	coalescedSourceService string
	javaService            string
	restartControlDir      string
}

type requestCase struct {
	Marker              string `json:"marker"`
	Endpoint            string `json:"endpoint"`
	W3CTraceID          string `json:"w3c_trace_id,omitempty"`
	W3CParentSpanID     string `json:"w3c_parent_span_id,omitempty"`
	W3CTraceFlags       string `json:"w3c_trace_flags,omitempty"`
	W3CCase             string `json:"w3c_case,omitempty"`
	InjectedFaultMode   string `json:"injected_fault_mode,omitempty"`
	ExpectedJavaStatus  string `json:"expected_java_status,omitempty"`
	RestartPhase        string `json:"restart_phase,omitempty"`
	InvalidW3C          bool   `json:"invalid_w3c,omitempty"`
	HandoffHops         int    `json:"handoff_hops,omitempty"`
	HandoffFault        string `json:"handoff_fault,omitempty"`
	VirtualMixed        bool   `json:"virtual_mixed,omitempty"`
	VirtualCancel       bool   `json:"virtual_cancel,omitempty"`
	NettyCancel         bool   `json:"netty_cancel,omitempty"`
	DispatchRounds      int    `json:"dispatch_rounds,omitempty"`
	TLSBoundaryMode     string `json:"tls_boundary_mode,omitempty"`
	TLSBoundarySequence int    `json:"tls_boundary_sequence,omitempty"`
	ConcurrencyBatch    string `json:"concurrency_batch,omitempty"`
	ConcurrencyExpected int    `json:"concurrency_expected,omitempty"`
	DelayMillis         int    `json:"-"`
	SlowBodyBytes       int    `json:"-"`
	CloseConnection     bool   `json:"-"`
	ObserveSocket       bool   `json:"-"`
	BridgeDiagnostics   bool   `json:"-"`
}

type backendResponse struct {
	Marker                  string                   `json:"marker"`
	Secure                  bool                     `json:"secure"`
	BackendKind             string                   `json:"backend_kind,omitempty"`
	Protocol                string                   `json:"protocol"`
	TLSProtocol             string                   `json:"tls_protocol"`
	TLSCipher               string                   `json:"tls_cipher"`
	BackendConnectionID     uint64                   `json:"backend_connection_id"`
	BackendRemotePort       int                      `json:"backend_remote_port"`
	BackendSocketFD         int                      `json:"backend_socket_fd,omitempty"`
	BackendWorkerID         uint64                   `json:"backend_worker_id,omitempty"`
	ConcurrencyBatch        string                   `json:"concurrency_batch,omitempty"`
	ConcurrencyParticipants int                      `json:"concurrency_participants,omitempty"`
	ConcurrencyMaxActive    int                      `json:"concurrency_max_active,omitempty"`
	ConcurrencyArrival      int                      `json:"concurrency_arrival,omitempty"`
	ConcurrencyRelease      uint64                   `json:"concurrency_release,omitempty"`
	TLSReadEvents           int64                    `json:"tls_read_events"`
	TLSReadBytes            int64                    `json:"tls_read_bytes"`
	Workload                string                   `json:"workload,omitempty"`
	HandoffHops             string                   `json:"handoff_hops,omitempty"`
	HandoffFault            string                   `json:"handoff_fault,omitempty"`
	VirtualMixed            string                   `json:"virtual_mixed,omitempty"`
	VirtualCancel           string                   `json:"virtual_cancel,omitempty"`
	NettyCancel             string                   `json:"netty_cancel,omitempty"`
	DispatchRounds          string                   `json:"dispatch_rounds,omitempty"`
	DispatchInvocations     string                   `json:"dispatch_invocations,omitempty"`
	TLSBoundary             *tlsBoundaryEvidence     `json:"tls_boundary,omitempty"`
	CoalescedBridge         *coalescedBridgeEvidence `json:"coalesced_bridge,omitempty"`
	BridgeDiagnostics       string                   `json:"-"`
}

type coalescedBridgeEvidence struct {
	PlaintextCallbackCount    int      `json:"plaintext_callback_count"`
	PlaintextCallbackBytes    int      `json:"plaintext_callback_bytes"`
	PlaintextSHA256           string   `json:"plaintext_sha256"`
	ParserRequestCount        int      `json:"parser_request_count"`
	ParserCallbackGenerations []int    `json:"parser_callback_generations"`
	ParserMarkers             []string `json:"parser_markers"`
	TraceparentHeaderCount    int      `json:"traceparent_header_count"`
	RequestMarkersExact       bool     `json:"request_markers_exact"`
	OnePlaintextReceive       bool     `json:"one_plaintext_receive"`
	Passed                    bool     `json:"passed"`
	FailureReason             string   `json:"failure_reason"`
}

type tlsBoundaryEvidence struct {
	Mode                                    string `json:"mode"`
	DeliveryShape                           string `json:"delivery_shape"`
	EvidencePhase                           string `json:"evidence_phase"`
	FallbackReason                          string `json:"fallback_reason"`
	CoalescingGraceMillis                   int64  `json:"coalescing_grace_millis"`
	CoalescingGraceExpired                  bool   `json:"coalescing_grace_expired"`
	VerificationBufferBytes                 int    `json:"verification_buffer_bytes"`
	VerificationBufferLimitBytes            int    `json:"verification_buffer_limit_bytes"`
	VerificationPairDigestExact             bool   `json:"verification_pair_digest_exact"`
	Passed                                  bool   `json:"passed"`
	FailureReason                           string `json:"failure_reason"`
	RequestComplete                         bool   `json:"request_complete"`
	RequestCount                            int    `json:"request_count"`
	RequestHeaderBytes                      []int  `json:"request_header_bytes"`
	RequestBodyBytes                        []int  `json:"request_body_bytes"`
	RequestTotalBytes                       []int  `json:"request_total_bytes"`
	RequestHeaderDecryptedCallbackCounts    []int  `json:"request_header_decrypted_callback_counts"`
	RequestOrder                            []int  `json:"request_order"`
	EmissionOrder                           []int  `json:"emission_order"`
	EmissionParserCallbackOrder             []int  `json:"emission_parser_callback_order"`
	ResponseOrder                           []int  `json:"response_order"`
	ResponseConnectionClose                 []bool `json:"response_connection_close"`
	TLSApplicationRecordLegacyVersions      []int  `json:"tls_application_record_legacy_versions"`
	TLSApplicationRecordPayloadLengths      []int  `json:"tls_application_record_payload_lengths"`
	DecryptedCallbackLengths                []int  `json:"decrypted_callback_lengths"`
	ParserCallbackLengths                   []int  `json:"parser_callback_lengths"`
	DecryptedTotalBytes                     int    `json:"decrypted_total_bytes"`
	ParserTotalBytes                        int    `json:"parser_total_bytes"`
	ParserCallbackCount                     int    `json:"parser_callback_count"`
	WireDecryptedPairsExact                 bool   `json:"wire_decrypted_pairs_exact"`
	HeadersSpannedRecords                   bool   `json:"headers_spanned_records"`
	ParserShapeExact                        bool   `json:"parser_shape_exact"`
	ParserFacingCoalesced                   bool   `json:"parser_facing_coalesced"`
	RequestsEmittedFromSingleParserCallback bool   `json:"requests_emitted_from_single_parser_callback"`
	RequestBytesPreserved                   bool   `json:"request_bytes_preserved"`
	SplitBuffersForwardedUnchanged          bool   `json:"split_buffers_forwarded_unchanged"`
	HandoffBeforeParse                      bool   `json:"handoff_before_parse"`
	FirstResponseKeepsAlive                 bool   `json:"first_response_keeps_alive"`
	ResponseForcesConnectionClose           bool   `json:"response_forces_connection_close"`
}

type caseResult struct {
	Request               requestCase                      `json:"request"`
	Response              backendResponse                  `json:"response"`
	LatencyNanos          int64                            `json:"latency_nanos"`
	PressureParentOutcome tracecheck.PressureParentOutcome `json:"pressure_parent_outcome,omitempty"`
	ParentOutcome         tracecheck.PressureParentOutcome `json:"parent_outcome,omitempty"`
	Trace                 tracecheck.Snapshot              `json:"trace"`
}

type pressureCorrelationSummary struct {
	ExactHitCount     int `json:"exact_hit_count"`
	ExplicitRootCount int `json:"explicit_root_count"`
	WrongParentCount  int `json:"wrong_parent_count"`
	UnresolvedCount   int `json:"unresolved_count"`
}

type coalescedBridgeCorrelationSummary struct {
	Outcome                string `json:"outcome"`
	ExactHitCount          int    `json:"exact_hit_count"`
	ExplicitRootCount      int    `json:"explicit_root_count"`
	WrongParentCount       int    `json:"wrong_parent_count"`
	UnresolvedCount        int    `json:"unresolved_count"`
	SourceClientCandidates int    `json:"source_client_candidates"`
	TriggerChainProven     bool   `json:"trigger_chain_proven"`
	DiscardTotalDelta      uint64 `json:"discard_total_delta"`
	DiscardAmbiguousDelta  uint64 `json:"discard_ambiguous_delta"`
}

type diagnosticDropSummary struct {
	Reasons []string
	Counts  map[string]uint64
	Total   uint64
}

type latencySummary struct {
	P50Nanos int64 `json:"p50_nanos"`
	P95Nanos int64 `json:"p95_nanos"`
	P99Nanos int64 `json:"p99_nanos"`
}

type faultResult struct {
	Kind          string              `json:"kind"`
	Outcome       string              `json:"outcome"`
	ElapsedNanos  int64               `json:"elapsed_nanos"`
	Marker        string              `json:"marker,omitempty"`
	ParentOutcome string              `json:"parent_outcome,omitempty"`
	DropReasons   []string            `json:"drop_reasons"`
	Trace         tracecheck.Snapshot `json:"trace,omitempty"`
}

type connectionEvidence struct {
	FrontendConnections            int    `json:"frontend_connections"`
	FrontendProtocol               string `json:"frontend_protocol"`
	PipelinedRequests              int    `json:"pipelined_requests,omitempty"`
	RequestsWrittenBeforeFirstRead int    `json:"requests_written_before_first_read,omitempty"`
	SequentialRequests             int    `json:"sequential_requests,omitempty"`
	ResponsesReadBeforeNextWrite   int    `json:"responses_read_before_next_write,omitempty"`
	ReusedFrontendLocalPort        int    `json:"reused_frontend_local_port,omitempty"`
	ReusedFrontendFileDescriptor   int    `json:"reused_frontend_file_descriptor,omitempty"`
	DistinctFrontendLocalPorts     int    `json:"distinct_frontend_local_ports,omitempty"`
	BackendConnections             int    `json:"backend_connections,omitempty"`
	DistinctBackendConnectionIDs   int    `json:"distinct_backend_connection_ids,omitempty"`
	DistinctBackendRemotePorts     int    `json:"distinct_backend_remote_ports,omitempty"`
	ReusedBackendFileDescriptor    int    `json:"reused_backend_file_descriptor,omitempty"`
	SourceBackendTLSConnections    int    `json:"source_backend_tls_connections,omitempty"`
	SourcePlaintextWriteCalls      int    `json:"source_plaintext_write_calls,omitempty"`
	SourcePlaintextWriteBytes      int    `json:"source_plaintext_write_bytes,omitempty"`
	SourcePlaintextSHA256          string `json:"source_plaintext_sha256,omitempty"`
	SourceRequestBoundaries        int    `json:"source_request_boundaries,omitempty"`
	SourceTraceparentHeaderCount   int    `json:"source_traceparent_header_count,omitempty"`
	DistinctBackendWorkers         int    `json:"distinct_backend_workers,omitempty"`
	DistinctConcurrencyArrivals    int    `json:"distinct_concurrency_arrivals,omitempty"`
	ConcurrencyParticipants        int    `json:"concurrency_participants,omitempty"`
	ConcurrencyMaxActive           int    `json:"concurrency_max_active,omitempty"`
	ConcurrencyRelease             uint64 `json:"concurrency_release,omitempty"`
}

type socketObservation struct {
	FileDescriptor int
	LocalPort      int
}

type coalescedSourceResponse struct {
	TriggerMarker          string            `json:"trigger_marker"`
	ChildMarkers           []string          `json:"child_markers"`
	BackendTLSConnections  int               `json:"backend_tls_connections"`
	PlaintextWriteCalls    int               `json:"plaintext_write_calls"`
	PlaintextWriteBytes    int               `json:"plaintext_write_bytes"`
	PlaintextSHA256        string            `json:"plaintext_sha256"`
	RequestBoundaries      int               `json:"request_boundaries"`
	TraceparentHeaderCount int               `json:"traceparent_header_count"`
	TLSProtocol            string            `json:"tls_protocol"`
	Responses              []json.RawMessage `json:"responses"`
	JavaDiagnosticsAfter   string            `json:"java_diagnostics_after"`
}

type runResult struct {
	Status                     string                             `json:"status"`
	Scenario                   string                             `json:"scenario"`
	AssertionMode              tracecheck.AssertionMode           `json:"assertion_mode,omitempty"`
	Seed                       int64                              `json:"seed"`
	StartedAt                  time.Time                          `json:"started_at"`
	FinishedAt                 time.Time                          `json:"finished_at"`
	RequestCount               int                                `json:"request_count"`
	TrafficElapsedNanos        int64                              `json:"traffic_elapsed_nanos"`
	ThroughputPerSecond        float64                            `json:"throughput_per_second"`
	Latency                    latencySummary                     `json:"latency"`
	Faults                     []faultResult                      `json:"faults,omitempty"`
	ConnectionEvidence         *connectionEvidence                `json:"connection_evidence,omitempty"`
	PressureCorrelation        *pressureCorrelationSummary        `json:"pressure_correlation,omitempty"`
	CoalescedBridgeCorrelation *coalescedBridgeCorrelationSummary `json:"coalesced_bridge_correlation,omitempty"`
	FaultDiagnosticsAfter      string                             `json:"fault_diagnostics_after,omitempty"`
	JavaDiagnosticsAfter       string                             `json:"java_diagnostics_after,omitempty"`
	Cases                      []caseResult                       `json:"cases"`
}

const (
	assertionQuiescence           = 6 * time.Second
	matchingW3CTraceID            = "000102030405060708090a0b0c0d0e0f"
	matchingW3CParentSpanID       = "1011121314151617"
	matchingW3CTraceFlags         = "01"
	restartBeforeStopRequests     = 1
	restartWhileStoppedRequests   = 7
	restartAfterStartRequestIndex = restartBeforeStopRequests + restartWhileStoppedRequests
	restartPhaseBeforeStop        = "before-stop"
	restartPhaseWhileStopped      = "obi-stopped"
	restartPhaseAfterRestart      = "after-restart"
	bridgeDiagnosticsHeader       = "X-OBI-Java-Diagnostics"
	maxJavaDiagnosticsCounter     = uint64(999_999_999)
)

var javaDiagnosticsFieldNames = [...]string{
	"cfg_on",
	"cfg_off",
	"provider_ok",
	"provider_reject",
	"provider_ver",
	"extension_reg",
	"lookup_ready",
	"lookup_missing",
	"lookup_version",
	"lookup_error",
	"record_version",
	"invoke_error",
	"discard_standard",
	"extract_fields",
	"extract_invalid",
	"extract_error",
	"registration_ok",
	"registration_fail",
	"take_sampled",
	"take_unsampled",
	"tls_reads",
	"tls_bytes",
	"t_unknown",
	"d_unknown",
	"t_valid",
	"d_valid",
	"t_missing",
	"d_missing",
	"t_stale",
	"d_stale",
	"t_unsupported",
	"d_unsupported",
	"t_malformed",
	"d_malformed",
	"t_version_mismatch",
	"d_version_mismatch",
	"t_ambiguous",
	"d_ambiguous",
	"t_unauthorized",
	"d_unauthorized",
	"t_already_consumed",
	"d_already_consumed",
	"t_timeout",
	"d_timeout",
	"t_overload",
	"d_overload",
	"t_transport_error",
	"d_transport_error",
	"t_disabled",
	"d_disabled",
}

var javaDiscardStatuses = [...]string{
	"missing",
	"stale",
	"unsupported",
	"malformed",
	"version_mismatch",
	"ambiguous",
	"unauthorized",
	"already_consumed",
	"timeout",
	"overload",
	"transport_error",
	"disabled",
}

var javaDeterministicFailureCounters = [...]string{
	"provider_reject",
	"provider_ver",
	"lookup_missing",
	"lookup_version",
	"lookup_error",
	"record_version",
	"invoke_error",
	"extract_fields",
	"extract_invalid",
	"extract_error",
	"registration_fail",
}

var maxJavaDiagnosticsSnapshotLength = func() int {
	length := len(javaDiagnosticsFieldNames) - 1
	maxValueLength := len(strconv.FormatUint(maxJavaDiagnosticsCounter, 36))
	for _, name := range javaDiagnosticsFieldNames {
		length += len(name) + 1 + maxValueLength
	}
	return length
}()

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
	for index := range result.Faults {
		if result.Faults[index].DropReasons == nil {
			result.Faults[index].DropReasons = []string{}
		}
	}
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.baseURL, "base-url", "http://127.0.0.1:18080", "Apache base URL")
	flag.StringVar(&cfg.receiverURL, "receiver-url", "http://127.0.0.1:14318", "trace receiver base URL")
	flag.StringVar(&cfg.scenario, "scenario", "basic", "basic, keepalive, pipelining, concurrency, connection-churn, fd-port-reuse, slow-body, tls-boundary, coalesced-bridge, timeout-retry, pressure, handoff, virtual-thread, netty, netty-server, dispatch, w3c, w3c-match, obi-flags, w3c-fault, primary-w3c-fault, primary-w3c-stale, unix-w3c-stale, w3c-only, helper-attach-failure, restart-fault, fail-open, restart, disabled, or uninstrumented")
	flag.StringVar(&cfg.assertionMode, "assertion-mode", "", "concurrency assertion override: disabled or uninstrumented")
	flag.StringVar(&cfg.faultMode, "fault-mode", "", "W3C fault mode")
	flag.StringVar(&cfg.javaDiagnosticsBefore, "java-diagnostics-before", "", "sanitized Java diagnostics baseline for reason-coded scenarios")
	flag.IntVar(&cfg.requestCount, "requests", 0, "number of requests (zero selects a scenario default)")
	flag.DurationVar(&cfg.timeout, "timeout", 45*time.Second, "whole-scenario timeout")
	flag.DurationVar(&cfg.requestTimeout, "request-timeout", defaultRequestTimeout, "per-request HTTP and raw-connection timeout")
	flag.StringVar(&cfg.expectedTLS, "expected-tls", "TLSv1.3", "backend TLS protocol")
	flag.Int64Var(&cfg.seed, "seed", 1, "deterministic request and W3C identifier seed")
	flag.StringVar(&cfg.apacheService, "apache-service", "apache-proxy", "Apache service.name")
	flag.StringVar(&cfg.coalescedSourceService, "coalesced-source-service", "coalesced-source", "coalesced source service.name")
	flag.StringVar(&cfg.javaService, "java-service", "java-backend", "Java service.name")
	flag.StringVar(&cfg.restartControlDir, "restart-control-dir", "", "shared restart-fault control directory")
	flag.Parse()
	flag.Visit(func(visited *flag.Flag) {
		if visited.Name == "request-timeout" {
			cfg.requestTimeoutSet = true
		}
	})

	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "unexpected positional arguments")
		os.Exit(2)
	}
	validScenarios := map[string]bool{
		"basic": true, "keepalive": true, "pipelining": true, "concurrency": true,
		"connection-churn": true, "fd-port-reuse": true,
		"slow-body": true, "tls-boundary": true, "coalesced-bridge": true, "timeout-retry": true,
		"pressure": true,
		"handoff":  true, "virtual-thread": true, "netty": true, "netty-server": true, "dispatch": true,
		"w3c": true, "w3c-match": true, "obi-flags": true, "w3c-fault": true,
		"primary-w3c-fault": true, "primary-w3c-stale": true, "unix-w3c-stale": true,
		"w3c-only": true, "helper-attach-failure": true, "restart-fault": true,
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
	if err := validateTimeouts(cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if cfg.scenario == "restart-fault" && cfg.restartControlDir == "" {
		fmt.Fprintln(os.Stderr, "restart-fault requires --restart-control-dir")
		os.Exit(2)
	}
	if cfg.scenario != "restart-fault" && cfg.restartControlDir != "" {
		fmt.Fprintln(os.Stderr, "--restart-control-dir requires restart-fault")
		os.Exit(2)
	}
	if err := validateAssertionMode(cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := validateFaultMode(cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := validateJavaDiagnosticsBefore(cfg); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	return cfg
}

func validateTimeouts(cfg config) error {
	if cfg.timeout <= 0 || cfg.timeout > 10*time.Minute {
		return errors.New("timeout must be positive and at most 10m")
	}
	if cfg.requestTimeout <= 0 || (cfg.requestTimeoutSet && cfg.requestTimeout > cfg.timeout) {
		return errors.New("request-timeout must be positive and no greater than timeout")
	}
	return nil
}

func validateAssertionMode(cfg config) error {
	switch cfg.assertionMode {
	case "":
		return nil
	case string(tracecheck.ModeDisabled), string(tracecheck.ModeUninstrumented):
		if cfg.scenario == "concurrency" {
			return nil
		}
		return errors.New("--assertion-mode requires concurrency")
	default:
		return fmt.Errorf("invalid --assertion-mode %q", cfg.assertionMode)
	}
}

func concurrencyAssertionMode(cfg config) tracecheck.AssertionMode {
	if cfg.assertionMode != "" {
		return tracecheck.AssertionMode(cfg.assertionMode)
	}
	return tracecheck.ModeBridge
}

func requiresDistinctParents(cfg config) bool {
	return cfg.assertionMode != string(tracecheck.ModeUninstrumented) &&
		distinctParentScenario(cfg.scenario)
}

func validateFaultMode(cfg config) error {
	if !isFaultScenario(cfg.scenario) {
		if cfg.faultMode != "" {
			return errors.New("--fault-mode requires w3c-fault or primary-w3c-fault")
		}
		return nil
	}
	if cfg.faultMode == "" {
		return fmt.Errorf("%s requires --fault-mode", cfg.scenario)
	}
	if cfg.scenario == "primary-w3c-fault" {
		if _, ok := expectedPrimaryJavaFaultStatus(cfg.faultMode); !ok {
			return fmt.Errorf("invalid --fault-mode %q", cfg.faultMode)
		}
		return nil
	}
	if _, ok := expectedJavaFaultStatus(cfg.faultMode, 0); !ok {
		return fmt.Errorf("invalid --fault-mode %q", cfg.faultMode)
	}
	return nil
}

func isFaultScenario(scenario string) bool {
	return scenario == "w3c-fault" || scenario == "primary-w3c-fault"
}

func isW3CStaleScenario(scenario string) bool {
	return scenario == "primary-w3c-stale" || scenario == "unix-w3c-stale"
}

func usesInBandJavaDiagnostics(scenario string) bool {
	return isFaultScenario(scenario) || isW3CStaleScenario(scenario) ||
		scenario == "coalesced-bridge" || scenario == "timeout-retry"
}

func validateJavaDiagnosticsBefore(cfg config) error {
	if cfg.scenario != "primary-w3c-fault" && cfg.scenario != "coalesced-bridge" &&
		cfg.scenario != "timeout-retry" {
		if cfg.javaDiagnosticsBefore != "" {
			return errors.New("--java-diagnostics-before requires primary-w3c-fault, coalesced-bridge, or timeout-retry")
		}
		return nil
	}
	if cfg.javaDiagnosticsBefore == "" {
		return fmt.Errorf("%s requires --java-diagnostics-before", cfg.scenario)
	}
	if _, err := javaDiagnosticsCounters(cfg.javaDiagnosticsBefore); err != nil {
		return errors.New("invalid --java-diagnostics-before")
	}
	return nil
}

func requestsBridgeDiagnostics(cfg config, request requestCase) bool {
	return usesInBandJavaDiagnostics(cfg.scenario) && request.BridgeDiagnostics
}

func expectedJavaFaultStatus(faultMode string, requestIndex int) (string, bool) {
	switch faultMode {
	case "alternating":
		if requestIndex%2 == 0 {
			return "stale", true
		}
		return "malformed", true
	case "timeout":
		return "timeout", true
	case "disconnect", "truncated":
		return "transport_error", true
	case "overload":
		return "overload", true
	case "bad-magic", "bad-size", "zero-trace-id", "zero-span-id":
		return "malformed", true
	case "version-mismatch":
		return "version_mismatch", true
	default:
		return "", false
	}
}

func expectedPrimaryJavaFaultStatus(faultMode string) (string, bool) {
	switch faultMode {
	case "version-mismatch":
		return "version_mismatch", true
	case "bad-size", "zero-trace-id", "zero-span-id":
		return "malformed", true
	default:
		return "", false
	}
}

func run(ctx context.Context, cfg config) (*runResult, error) {
	result := &runResult{Scenario: cfg.scenario, Seed: cfg.seed, StartedAt: time.Now().UTC()}
	if cfg.scenario == "concurrency" {
		result.AssertionMode = concurrencyAssertionMode(cfg)
	}
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
	if isFaultScenario(cfg.scenario) {
		result.FaultDiagnosticsAfter = responses[len(responses)-1].BridgeDiagnostics
	} else if isW3CStaleScenario(cfg.scenario) {
		result.JavaDiagnosticsAfter = responses[len(responses)-1].BridgeDiagnostics
	}
	if cfg.scenario == "primary-w3c-fault" {
		if err := assertPrimaryFaultDiagnostics(
			cfg.javaDiagnosticsBefore,
			result.FaultDiagnosticsAfter,
			requests[0].ExpectedJavaStatus,
		); err != nil {
			return result, err
		}
	}
	if cfg.scenario == "coalesced-bridge" || cfg.scenario == "timeout-retry" {
		result.JavaDiagnosticsAfter = responses[len(responses)-1].BridgeDiagnostics
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

	var snapshots []tracecheck.Snapshot
	var assertionErr error
	if cfg.scenario == "coalesced-bridge" {
		var summary coalescedBridgeCorrelationSummary
		var outcomes []tracecheck.PressureParentOutcome
		snapshots, outcomes, summary, assertionErr = awaitCoalescedBridgeAssertions(
			ctx,
			cfg,
			requests,
			result.JavaDiagnosticsAfter,
			fetchSnapshot,
		)
		result.CoalescedBridgeCorrelation = &summary
		for index := range outcomes {
			result.Cases[index].ParentOutcome = outcomes[index]
		}
	} else {
		snapshots, assertionErr = awaitAssertions(ctx, cfg, requests)
	}
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
	if cfg.scenario == "timeout-retry" {
		snapshot, outcome, reasons, cancellationErr := awaitCancellationReconciliation(
			ctx,
			cfg,
			result.Faults[0].Marker,
			result.JavaDiagnosticsAfter,
			fetchSnapshot,
		)
		result.Faults[0].Trace = snapshot
		result.Faults[0].ParentOutcome = outcome
		result.Faults[0].DropReasons = reasons
		if cancellationErr != nil {
			return result, cancellationErr
		}
	}
	if pressureErr != nil {
		return result, pressureErr
	}
	if requiresDistinctParents(cfg) {
		if err := validateDistinctParents(cfg.scenario, cfg.javaService, result.Cases); err != nil {
			return result, err
		}
	}

	return result, nil
}

func makeRequests(cfg config) ([]requestCase, error) {
	if err := validateAssertionMode(cfg); err != nil {
		return nil, err
	}
	if err := validateFaultMode(cfg); err != nil {
		return nil, err
	}
	if err := validateJavaDiagnosticsBefore(cfg); err != nil {
		return nil, err
	}

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
		case "handoff", "virtual-thread", "netty", "netty-server", "dispatch":
			count = 4
		case "w3c", "obi-flags", "w3c-fault":
			count = 2
		case "tls-boundary":
			count = 3
		case "coalesced-bridge":
			count = 2
		default:
			count = 1
		}
	}
	if (cfg.scenario == "keepalive" || cfg.scenario == "pipelining") && count < 3 {
		return nil, fmt.Errorf("scenario %s requires at least three requests", cfg.scenario)
	}
	if cfg.scenario == "concurrency" && (count < 2 || count > 64) {
		return nil, fmt.Errorf("scenario %s requires between two and 64 requests", cfg.scenario)
	}
	if cfg.scenario == "fd-port-reuse" && count < 2 {
		return nil, fmt.Errorf("scenario %s requires at least two requests", cfg.scenario)
	}
	if cfg.scenario == "slow-body" && count < 2 {
		return nil, fmt.Errorf("scenario %s requires at least two requests", cfg.scenario)
	}
	if cfg.scenario == "tls-boundary" && count != 3 {
		return nil, fmt.Errorf("scenario %s requires exactly three requests", cfg.scenario)
	}
	if cfg.scenario == "coalesced-bridge" && count != 2 {
		return nil, fmt.Errorf("scenario %s requires exactly two requests", cfg.scenario)
	}
	if cfg.scenario == "helper-attach-failure" && count != 1 {
		return nil, fmt.Errorf("scenario %s requires exactly one request", cfg.scenario)
	}
	if (cfg.scenario == "primary-w3c-stale" || cfg.scenario == "unix-w3c-stale") && count != 1 {
		return nil, fmt.Errorf("scenario %s requires exactly one request", cfg.scenario)
	}
	if cfg.scenario == "primary-w3c-fault" && count != 1 {
		return nil, fmt.Errorf("scenario %s requires exactly one request", cfg.scenario)
	}
	if cfg.scenario == "restart-fault" && count <= restartAfterStartRequestIndex {
		return nil, fmt.Errorf(
			"scenario %s requires at least %d requests",
			cfg.scenario,
			restartAfterStartRequestIndex+1,
		)
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
			requests[i].ConcurrencyBatch = fmt.Sprintf("c%016x", uint64(cfg.seed))
			requests[i].ConcurrencyExpected = count
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
		if cfg.scenario == "netty-server" {
			requests[i].Endpoint = "/api/netty-server"
		}
		if cfg.scenario == "dispatch" {
			requests[i].Endpoint = "/api/dispatch"
			requests[i].DispatchRounds = 1 + i%8
		}
		if cfg.scenario == "tls-boundary" {
			switch i {
			case 0:
				requests[i].TLSBoundaryMode = "split"
				requests[i].TLSBoundarySequence = 1
				requests[i].Endpoint = "/api/tls-boundary/split"
			case 1, 2:
				requests[i].TLSBoundaryMode = "coalesced"
				requests[i].TLSBoundarySequence = i
				requests[i].Endpoint = "/api/tls-boundary/coalesced"
			}
		}
		if cfg.scenario == "coalesced-bridge" {
			requests[i].Endpoint = "/api/coalesced-bridge"
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
			expectedStatus, ok := expectedJavaFaultStatus(cfg.faultMode, i)
			if !ok {
				return nil, fmt.Errorf("invalid --fault-mode %q", cfg.faultMode)
			}
			requests[i].InjectedFaultMode = cfg.faultMode
			requests[i].ExpectedJavaStatus = expectedStatus
			caseName := fmt.Sprintf(
				"valid-w3c-injected-%s-java-%s",
				cfg.faultMode,
				expectedStatus,
			)
			if err := addW3CContext(random, &requests[i], "01", caseName); err != nil {
				return nil, err
			}
		case "primary-w3c-stale", "unix-w3c-stale":
			requests[i].ExpectedJavaStatus = "stale"
			w3cCase := "valid-w3c-primary-stale"
			if cfg.scenario == "unix-w3c-stale" {
				w3cCase = "valid-w3c-unix-stale"
			}
			if err := addW3CContext(random, &requests[i], "01", w3cCase); err != nil {
				return nil, err
			}
		case "primary-w3c-fault":
			expectedStatus, ok := expectedPrimaryJavaFaultStatus(cfg.faultMode)
			if !ok {
				return nil, fmt.Errorf("invalid --fault-mode %q", cfg.faultMode)
			}
			requests[i].InjectedFaultMode = cfg.faultMode
			requests[i].ExpectedJavaStatus = expectedStatus
			caseName := fmt.Sprintf(
				"valid-w3c-primary-injected-%s-java-%s",
				cfg.faultMode,
				expectedStatus,
			)
			if err := addW3CContext(random, &requests[i], "01", caseName); err != nil {
				return nil, err
			}
		case "w3c-only":
			if err := addW3CContext(random, &requests[i], "01", "valid-w3c-no-obi"); err != nil {
				return nil, err
			}
		case "restart-fault":
			requests[i].DelayMillis = 75
			switch {
			case i < restartBeforeStopRequests:
				requests[i].RestartPhase = restartPhaseBeforeStop
			case i < restartAfterStartRequestIndex:
				requests[i].RestartPhase = restartPhaseWhileStopped
			default:
				requests[i].RestartPhase = restartPhaseAfterRestart
			}
			if err := addW3CContext(random, &requests[i], "01", "valid-w3c-during-obi-restart"); err != nil {
				return nil, err
			}
		}
	}
	if usesInBandJavaDiagnostics(cfg.scenario) {
		requests[len(requests)-1].BridgeDiagnostics = true
	}
	switch {
	case cfg.scenario == "tls-boundary":
		requests[0].CloseConnection = true
		requests[2].CloseConnection = true
	case parallelScenario(cfg.scenario):
		for i := range requests {
			requests[i].CloseConnection = true
		}
	default:
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
	case "coalesced-bridge":
		return sendCoalescedBridgeRequests(ctx, cfg, requests)
	case "tls-boundary":
		return sendTLSBoundaryRequests(ctx, cfg, requests)
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
	client := &http.Client{Transport: transport, Timeout: effectiveRequestTimeout(cfg)}

	responses := make([]backendResponse, len(requests))
	latencies := make([]int64, len(requests))
	var control *restartControl
	if cfg.scenario == "restart-fault" {
		var err error
		control, err = newRestartControl(cfg.restartControlDir)
		if err != nil {
			return responses, latencies, 0, nil, err
		}
	}
	trafficStart := time.Now()
	if !parallelScenario(cfg.scenario) {
		for i := range requests {
			if control != nil {
				switch i {
				case restartBeforeStopRequests:
					if err := control.checkpoint(
						ctx,
						restartSignalPreStopReady,
						restartReleaseOBIStopped,
					); err != nil {
						return responses, latencies, time.Since(trafficStart), nil, err
					}
				case restartAfterStartRequestIndex:
					if err := control.checkpoint(
						ctx,
						restartSignalStoppedTrafficComplete,
						restartReleaseOBIReady,
					); err != nil {
						return responses, latencies, time.Since(trafficStart), nil, err
					}
				}
			}
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
		if control != nil {
			if err := control.publish(restartSignalPostRestartTrafficComplete); err != nil {
				return responses, latencies, time.Since(trafficStart), nil, err
			}
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
	var evidence *connectionEvidence
	if cfg.scenario == "concurrency" {
		evidence = buildConcurrencyEvidence(responses)
	}
	return responses, latencies, time.Since(trafficStart), evidence, nil
}

func effectiveRequestTimeout(cfg config) time.Duration {
	requestTimeout := cfg.requestTimeout
	if requestTimeout == 0 {
		requestTimeout = defaultRequestTimeout
	}
	if cfg.timeout > 0 && requestTimeout > cfg.timeout {
		return cfg.timeout
	}
	return requestTimeout
}

func sendTLSBoundaryRequests(
	ctx context.Context,
	cfg config,
	requests []requestCase,
) ([]backendResponse, []int64, time.Duration, *connectionEvidence, error) {
	if len(requests) != 3 || requests[0].TLSBoundaryMode != "split" ||
		requests[1].TLSBoundaryMode != "coalesced" ||
		requests[2].TLSBoundaryMode != "coalesced" {
		return nil, nil, 0, nil, errors.New("TLS boundary traffic requires one split request and one coalesced pair")
	}

	responses := make([]backendResponse, len(requests))
	latencies := make([]int64, len(requests))
	trafficStart := time.Now()

	network, address, err := directTCPAddress(cfg.baseURL)
	if err != nil {
		return responses, latencies, 0, nil, err
	}
	connection, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, address)
	if err != nil {
		return responses, latencies, time.Since(trafficStart), nil, fmt.Errorf("dial Apache for split TLS boundary request: %w", err)
	}
	tcpConnection, ok := connection.(*net.TCPConn)
	if !ok {
		_ = connection.Close()
		return responses, latencies, time.Since(trafficStart), nil, fmt.Errorf("expected TCP connection, got %T", connection)
	}
	if err := setConnectionDeadline(ctx, tcpConnection, effectiveRequestTimeout(cfg)); err != nil {
		_ = tcpConnection.Close()
		return responses, latencies, time.Since(trafficStart), nil, err
	}
	splitStart := time.Now()
	responses[0], err = sendRequestOnConnection(ctx, tcpConnection, cfg, requests[0])
	latencies[0] = time.Since(splitStart).Nanoseconds()
	_ = tcpConnection.Close()
	if err != nil {
		return responses, latencies, time.Since(trafficStart), nil, fmt.Errorf("split TLS boundary request: %w", err)
	}

	coalescedResponses, coalescedLatencies, evidence, err := sendSequentialRequests(ctx, cfg, requests[1:])
	copy(responses[1:], coalescedResponses)
	copy(latencies[1:], coalescedLatencies)
	if evidence != nil {
		evidence.FrontendConnections++
	}
	if err != nil {
		return responses, latencies, time.Since(trafficStart), evidence, fmt.Errorf("coalesced TLS boundary pair: %w", err)
	}
	return responses, latencies, time.Since(trafficStart), evidence, nil
}

func sendCoalescedBridgeRequests(
	ctx context.Context,
	cfg config,
	requests []requestCase,
) ([]backendResponse, []int64, time.Duration, *connectionEvidence, error) {
	responses := make([]backendResponse, len(requests))
	latencies := make([]int64, len(requests))
	if len(requests) != 2 || requests[0].Marker == requests[1].Marker {
		return responses, latencies, 0, nil, errors.New("coalesced bridge traffic requires two distinct markers")
	}
	requestURL, err := url.Parse(cfg.baseURL + "/api/coalesced-source")
	if err != nil {
		return responses, latencies, 0, nil, err
	}
	query := requestURL.Query()
	query.Set("second_marker", requests[1].Marker)
	requestURL.RawQuery = query.Encode()
	trigger, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return responses, latencies, 0, nil, err
	}
	trigger.Header.Set(tracecheck.MarkerHeader, requests[0].Marker)
	trigger.Close = true
	client := &http.Client{Timeout: effectiveRequestTimeout(cfg)}
	started := time.Now()
	response, err := client.Do(trigger)
	elapsed := time.Since(started)
	for index := range latencies {
		latencies[index] = elapsed.Nanoseconds()
	}
	if err != nil {
		return responses, latencies, elapsed, nil, fmt.Errorf("coalesced source request: %w", err)
	}
	defer response.Body.Close()
	body, err := readBoundedBody(
		response.Body,
		maximumCoalescedSourceBytes,
		"coalesced source response",
	)
	if err != nil {
		return responses, latencies, elapsed, nil, err
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("X-OBI-Coalesced-Source") != "live" {
		return responses, latencies, elapsed, nil, fmt.Errorf("coalesced source did not prove live execution: status=%d", response.StatusCode)
	}
	var source coalescedSourceResponse
	if err := json.Unmarshal(body, &source); err != nil {
		return responses, latencies, elapsed, nil, fmt.Errorf("decode coalesced source response: %w", err)
	}
	wantMarkers := []string{requests[0].Marker, requests[1].Marker}
	if source.TriggerMarker != requests[0].Marker || !equalStrings(source.ChildMarkers, wantMarkers) ||
		source.BackendTLSConnections != 1 || source.PlaintextWriteCalls != 1 ||
		source.PlaintextWriteBytes <= 0 || source.PlaintextWriteBytes > 8<<10 ||
		source.RequestBoundaries != 2 || source.TraceparentHeaderCount != 0 ||
		source.TLSProtocol != cfg.expectedTLS || len(source.Responses) != 2 ||
		!canonicalSHA256(source.PlaintextSHA256) {
		return responses, latencies, elapsed, nil, fmt.Errorf("coalesced source evidence is incomplete: %+v", source)
	}
	diagnostics, err := sanitizeJavaDiagnostics(source.JavaDiagnosticsAfter)
	if err != nil {
		return responses, latencies, elapsed, nil, fmt.Errorf("coalesced source Java diagnostics: %w", err)
	}
	for index := range source.Responses {
		if err := json.Unmarshal(source.Responses[index], &responses[index]); err != nil {
			return responses, latencies, elapsed, nil, fmt.Errorf("decode coalesced backend response %d: %w", index+1, err)
		}
		if err := validateCoalescedBackendResponse(
			cfg,
			requests[index],
			responses[index],
			source.PlaintextWriteBytes,
			source.PlaintextSHA256,
			wantMarkers,
		); err != nil {
			return responses, latencies, elapsed, nil, fmt.Errorf("coalesced backend response %d: %w", index+1, err)
		}
	}
	responses[1].BridgeDiagnostics = diagnostics
	evidence := &connectionEvidence{
		FrontendConnections:          1,
		FrontendProtocol:             "HTTP/1.1",
		SourceBackendTLSConnections:  source.BackendTLSConnections,
		SourcePlaintextWriteCalls:    source.PlaintextWriteCalls,
		SourcePlaintextWriteBytes:    source.PlaintextWriteBytes,
		SourcePlaintextSHA256:        source.PlaintextSHA256,
		SourceRequestBoundaries:      source.RequestBoundaries,
		SourceTraceparentHeaderCount: source.TraceparentHeaderCount,
	}
	return responses, latencies, elapsed, evidence, nil
}

func validateCoalescedBackendResponse(
	cfg config,
	request requestCase,
	response backendResponse,
	plaintextBytes int,
	plaintextSHA256 string,
	markers []string,
) error {
	if response.Marker != request.Marker || !response.Secure || response.Protocol != "HTTP/1.1" ||
		response.TLSProtocol != cfg.expectedTLS || response.TLSCipher == "" ||
		response.BackendConnectionID == 0 || response.BackendRemotePort == 0 ||
		response.BackendKind != "netty-coalesced-bridge" || response.CoalescedBridge == nil {
		return fmt.Errorf("backend identity or protocol evidence is incomplete: %+v", response)
	}
	evidence := response.CoalescedBridge
	if !evidence.Passed || evidence.FailureReason != "none" ||
		evidence.PlaintextCallbackCount != 1 ||
		evidence.PlaintextCallbackBytes != plaintextBytes ||
		evidence.PlaintextCallbackBytes <= 0 || evidence.PlaintextCallbackBytes > 8<<10 ||
		!canonicalSHA256(plaintextSHA256) || !canonicalSHA256(evidence.PlaintextSHA256) ||
		evidence.PlaintextSHA256 != plaintextSHA256 ||
		evidence.ParserRequestCount != 2 || !equalInts(evidence.ParserCallbackGenerations, []int{1, 1}) ||
		!equalStrings(evidence.ParserMarkers, markers) || evidence.TraceparentHeaderCount != 0 ||
		!evidence.RequestMarkersExact || !evidence.OnePlaintextReceive {
		return fmt.Errorf("one-plaintext receive evidence failed: %+v", evidence)
	}
	return nil
}

func canonicalSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func sendSequentialRequests(
	ctx context.Context,
	cfg config,
	requests []requestCase,
) ([]backendResponse, []int64, *connectionEvidence, error) {
	network, address, err := directTCPAddress(cfg.baseURL)
	if err != nil {
		return nil, nil, nil, err
	}
	connection, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, address)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("dial Apache for sequential HTTP/1.1 requests: %w", err)
	}
	defer connection.Close()
	if err := setConnectionDeadline(ctx, connection, effectiveRequestTimeout(cfg)); err != nil {
		return nil, nil, nil, err
	}
	return sendSequentialRequestsOnConnection(ctx, connection, cfg, requests)
}

func sendSequentialRequestsOnConnection(
	ctx context.Context,
	connection net.Conn,
	cfg config,
	requests []requestCase,
) ([]backendResponse, []int64, *connectionEvidence, error) {
	if len(requests) < 2 {
		return nil, nil, nil, errors.New("sequential HTTP/1.1 traffic requires at least two requests")
	}

	responses := make([]backendResponse, len(requests))
	latencies := make([]int64, len(requests))
	evidence := &connectionEvidence{
		FrontendConnections: 1,
		FrontendProtocol:    "HTTP/1.1",
		SequentialRequests:  len(requests),
	}
	requestWriter := bufio.NewWriter(connection)
	responseReader := bufio.NewReader(connection)
	for index := range requests {
		requestStart := time.Now()
		request, buildErr := newHTTPRequest(ctx, cfg, requests[index])
		if buildErr != nil {
			return responses, latencies, evidence, fmt.Errorf("build sequential request %d: %w", index, buildErr)
		}
		request.Proto = "HTTP/1.1"
		request.ProtoMajor = 1
		request.ProtoMinor = 1
		if writeErr := request.Write(requestWriter); writeErr != nil {
			return responses, latencies, evidence, fmt.Errorf("write sequential request %d: %w", index, writeErr)
		}
		if flushErr := requestWriter.Flush(); flushErr != nil {
			return responses, latencies, evidence, fmt.Errorf("flush sequential request %d: %w", index, flushErr)
		}
		response, readErr := http.ReadResponse(responseReader, request)
		if readErr != nil {
			return responses, latencies, evidence, fmt.Errorf("read sequential response %d: %w", index, readErr)
		}
		backend, decodeErr := decodeBackendResponse(response, cfg, requests[index])
		latencies[index] = time.Since(requestStart).Nanoseconds()
		if decodeErr != nil {
			return responses, latencies, evidence, fmt.Errorf("sequential response %d: %w", index, decodeErr)
		}
		responses[index] = backend
		if index+1 < len(requests) {
			evidence.ResponsesReadBeforeNextWrite++
		}
	}

	return responses, latencies, evidence, nil
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
	if err := setConnectionDeadline(ctx, connection, effectiveRequestTimeout(cfg)); err != nil {
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
		if deadlineErr := setConnectionDeadline(ctx, connection, effectiveRequestTimeout(cfg)); deadlineErr != nil {
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

func setConnectionDeadline(
	ctx context.Context,
	connection net.Conn,
	requestTimeout time.Duration,
) error {
	deadline := time.Now().Add(requestTimeout)
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

func buildConcurrencyEvidence(responses []backendResponse) *connectionEvidence {
	workers := make(map[uint64]struct{}, len(responses))
	arrivals := make(map[int]struct{}, len(responses))
	evidence := &connectionEvidence{FrontendConnections: len(responses), FrontendProtocol: "HTTP/1.1"}
	var concurrencyRelease uint64
	var concurrencyReleaseSet bool
	concurrencyReleaseConsistent := true
	for _, response := range responses {
		if response.BackendWorkerID != 0 {
			workers[response.BackendWorkerID] = struct{}{}
		}
		if response.ConcurrencyArrival > 0 {
			arrivals[response.ConcurrencyArrival] = struct{}{}
		}
		if response.ConcurrencyParticipants > evidence.ConcurrencyParticipants {
			evidence.ConcurrencyParticipants = response.ConcurrencyParticipants
		}
		if response.ConcurrencyMaxActive > evidence.ConcurrencyMaxActive {
			evidence.ConcurrencyMaxActive = response.ConcurrencyMaxActive
		}
		if !concurrencyReleaseSet {
			concurrencyRelease = response.ConcurrencyRelease
			concurrencyReleaseSet = true
		} else if concurrencyRelease != response.ConcurrencyRelease {
			concurrencyReleaseConsistent = false
		}
	}
	if concurrencyReleaseConsistent {
		evidence.ConcurrencyRelease = concurrencyRelease
	}
	evidence.DistinctBackendWorkers = len(workers)
	evidence.DistinctConcurrencyArrivals = len(arrivals)
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
	if requestCase.ConcurrencyBatch != "" {
		query := requestURL.Query()
		query.Set("concurrency_batch", requestCase.ConcurrencyBatch)
		query.Set("concurrency_expected", strconv.Itoa(requestCase.ConcurrencyExpected))
		requestURL.RawQuery = query.Encode()
	}
	if requestCase.CloseConnection && requestCase.TLSBoundaryMode == "" {
		query := requestURL.Query()
		query.Set("close", "1")
		requestURL.RawQuery = query.Encode()
	}
	if requestCase.ObserveSocket {
		query := requestURL.Query()
		query.Set("socket_identity", "1")
		requestURL.RawQuery = query.Encode()
	}
	if requestsBridgeDiagnostics(cfg, requestCase) {
		query := requestURL.Query()
		query.Set("bridge_diagnostics", "1")
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
	method := http.MethodGet
	var requestBody io.Reader
	if requestCase.TLSBoundaryMode != "" {
		method = http.MethodPost
		requestBody = bytes.NewReader(make([]byte, tlsBoundaryBodyBytes))
	} else if requestCase.SlowBodyBytes > 0 {
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
	if requestCase.TLSBoundaryMode != "" {
		request.ContentLength = tlsBoundaryBodyBytes
		request.Header.Set("Content-Type", "application/octet-stream")
		request.Header.Set(tlsBoundarySequenceHeader, strconv.Itoa(requestCase.TLSBoundarySequence))
		padding := strings.Repeat("p", tlsBoundaryPaddingHeaderValueBytes)
		for index := range tlsBoundaryPaddingHeaderCount {
			request.Header.Set(fmt.Sprintf("Z-OBI-Boundary-Pad-%d", index), padding)
		}
	} else if requestCase.SlowBodyBytes > 0 {
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
	body, err := readBoundedBody(
		response.Body,
		maximumBackendResponseBytes,
		"backend response",
	)
	if err != nil {
		return backendResponse{}, err
	}
	if response.StatusCode != http.StatusOK {
		return backendResponse{}, fmt.Errorf("unexpected HTTP status %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
	}
	diagnostics, err := javaDiagnosticsFromHeader(
		response.Header,
		requestsBridgeDiagnostics(cfg, requestCase),
	)
	if err != nil {
		return backendResponse{}, err
	}

	var backend backendResponse
	if err := json.Unmarshal(body, &backend); err != nil {
		return backendResponse{}, fmt.Errorf("decode backend response: %w", err)
	}
	backend.BridgeDiagnostics = diagnostics
	backend.Workload = response.Header.Get("X-OBI-Workload")
	backend.HandoffHops = response.Header.Get("X-OBI-Handoff-Hops")
	backend.HandoffFault = response.Header.Get("X-OBI-Handoff-Fault")
	backend.VirtualMixed = response.Header.Get("X-OBI-Virtual-Mixed")
	backend.VirtualCancel = response.Header.Get("X-OBI-Virtual-Cancel")
	backend.NettyCancel = response.Header.Get("X-OBI-Netty-Cancel")
	backend.DispatchRounds = response.Header.Get("X-OBI-Dispatch-Rounds")
	backend.DispatchInvocations = response.Header.Get("X-OBI-Dispatch-Invocations")
	if workerID := response.Header.Get("X-OBI-Backend-Worker-ID"); workerID != "" {
		backend.BackendWorkerID, err = strconv.ParseUint(workerID, 10, 64)
		if err != nil || backend.BackendWorkerID == 0 {
			return backendResponse{}, errors.New("backend returned an invalid worker identity")
		}
	}
	backend.ConcurrencyBatch = response.Header.Get("X-OBI-Concurrency-Batch")
	for name, destination := range map[string]*int{
		"X-OBI-Concurrency-Participants": &backend.ConcurrencyParticipants,
		"X-OBI-Concurrency-Max-Active":   &backend.ConcurrencyMaxActive,
		"X-OBI-Concurrency-Arrival":      &backend.ConcurrencyArrival,
	} {
		raw := response.Header.Get(name)
		if raw == "" {
			continue
		}
		parsed, parseErr := strconv.Atoi(raw)
		if parseErr != nil || parsed <= 0 {
			return backendResponse{}, fmt.Errorf("backend returned invalid %s", name)
		}
		*destination = parsed
	}
	if release := response.Header.Get("X-OBI-Concurrency-Release"); release != "" {
		backend.ConcurrencyRelease, err = strconv.ParseUint(release, 10, 64)
		if err != nil || backend.ConcurrencyRelease == 0 {
			return backendResponse{}, errors.New("backend returned an invalid concurrency release")
		}
	}
	if backend.Marker != requestCase.Marker {
		return backendResponse{}, fmt.Errorf("expected response marker %q, got %q", requestCase.Marker, backend.Marker)
	}
	if !backend.Secure {
		return backendResponse{}, errors.New("backend reported an insecure request")
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

func javaDiagnosticsFromHeader(header http.Header, requested bool) (string, error) {
	values := header.Values(bridgeDiagnosticsHeader)
	if !requested {
		if len(values) != 0 {
			return "", fmt.Errorf("unexpected %s response header", bridgeDiagnosticsHeader)
		}
		return "", nil
	}
	if len(values) != 1 {
		return "", fmt.Errorf(
			"expected exactly one %s response header, got %d",
			bridgeDiagnosticsHeader,
			len(values),
		)
	}
	return sanitizeJavaDiagnostics(values[0])
}

func sanitizeJavaDiagnostics(snapshot string) (string, error) {
	if snapshot == "unavailable" {
		return "", errors.New("java bridge diagnostics are unavailable")
	}
	if len(snapshot) > maxJavaDiagnosticsSnapshotLength {
		return "", fmt.Errorf(
			"java bridge diagnostics exceed %d bytes",
			maxJavaDiagnosticsSnapshotLength,
		)
	}
	if strings.ContainsAny(snapshot, "\r\n") {
		return "", errors.New("java bridge diagnostics contain a newline")
	}

	fields := strings.Split(snapshot, ",")
	if len(fields) != len(javaDiagnosticsFieldNames) {
		return "", fmt.Errorf(
			"java bridge diagnostics expected %d fields, got %d",
			len(javaDiagnosticsFieldNames),
			len(fields),
		)
	}

	seen := make(map[string]struct{}, len(fields))
	sanitized := make([]string, len(fields))
	for index, field := range fields {
		name, value, ok := strings.Cut(field, "=")
		if !ok || name == "" || value == "" {
			return "", fmt.Errorf("java bridge diagnostics field %d is malformed", index)
		}
		if _, duplicate := seen[name]; duplicate {
			return "", fmt.Errorf("java bridge diagnostics field %q is duplicated", name)
		}
		seen[name] = struct{}{}
		if name != javaDiagnosticsFieldNames[index] {
			return "", fmt.Errorf(
				"java bridge diagnostics field %d expected %q, got %q",
				index,
				javaDiagnosticsFieldNames[index],
				name,
			)
		}
		counter, err := strconv.ParseUint(value, 36, 64)
		if err != nil || strconv.FormatUint(counter, 36) != value {
			return "", fmt.Errorf(
				"java bridge diagnostics field %q has invalid base36 value %q",
				name,
				value,
			)
		}
		if counter >= maxJavaDiagnosticsCounter {
			return "", fmt.Errorf(
				"java bridge diagnostics field %q reached the saturation ceiling %d",
				name,
				maxJavaDiagnosticsCounter,
			)
		}
		sanitized[index] = name + "=" + strconv.FormatUint(counter, 36)
	}
	return strings.Join(sanitized, ","), nil
}

func javaDiagnosticsCounters(snapshot string) (map[string]uint64, error) {
	sanitized, err := sanitizeJavaDiagnostics(snapshot)
	if err != nil {
		return nil, err
	}
	counters := make(map[string]uint64, len(javaDiagnosticsFieldNames))
	for _, field := range strings.Split(sanitized, ",") {
		name, value, _ := strings.Cut(field, "=")
		counter, err := strconv.ParseUint(value, 36, 64)
		if err != nil {
			return nil, err
		}
		counters[name] = counter
	}
	return counters, nil
}

func assertPrimaryFaultDiagnostics(before, after, expectedStatus string) error {
	beforeCounters, err := javaDiagnosticsCounters(before)
	if err != nil {
		return fmt.Errorf("parse primary Java diagnostics baseline: %w", err)
	}
	afterCounters, err := javaDiagnosticsCounters(after)
	if err != nil {
		return fmt.Errorf("parse primary Java diagnostics result: %w", err)
	}
	for name, beforeValue := range beforeCounters {
		if afterCounters[name] < beforeValue {
			return fmt.Errorf("primary Java diagnostics counter %q decreased", name)
		}
	}
	expectedCounter := "t_" + expectedStatus
	if afterCounters[expectedCounter]-beforeCounters[expectedCounter] != 1 {
		return fmt.Errorf("expected one primary Java %s result", expectedStatus)
	}
	return nil
}

func boolFlag(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

func validateWorkloadResponse(request requestCase, response backendResponse) error {
	if request.ConcurrencyBatch != "" {
		if response.BackendWorkerID == 0 || response.ConcurrencyBatch != request.ConcurrencyBatch ||
			response.ConcurrencyParticipants != request.ConcurrencyExpected ||
			response.ConcurrencyMaxActive != request.ConcurrencyExpected ||
			response.ConcurrencyArrival < 1 ||
			response.ConcurrencyArrival > request.ConcurrencyExpected ||
			response.ConcurrencyRelease == 0 {
			return fmt.Errorf("concurrency response did not prove its worker barrier: %+v", response)
		}
	}
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
	case "/api/netty-server":
		if response.BackendKind != "netty" {
			return fmt.Errorf("netty server response did not prove its backend: kind=%q", response.BackendKind)
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
	case "/api/tls-boundary/split", "/api/tls-boundary/coalesced":
		if response.BackendKind != "netty-tls-boundary" {
			return fmt.Errorf("TLS boundary response did not prove its backend: kind=%q", response.BackendKind)
		}
		return validateTLSBoundaryResponse(request, response)
	}
	return nil
}

func validateTLSBoundaryResponse(request requestCase, response backendResponse) error {
	evidence := response.TLSBoundary
	if evidence == nil {
		return errors.New("TLS boundary response omitted same-request evidence")
	}
	if evidence.Mode != request.TLSBoundaryMode || evidence.FailureReason != "none" {
		return fmt.Errorf("TLS boundary evidence failed for mode %s: %+v", request.TLSBoundaryMode, evidence)
	}

	var expectedCount int
	var expectedOrder, expectedEmissionParserOrder, expectedParserLengths []int
	var expectedResponseClose []bool
	var expectedFirstResponseKeepsAlive bool
	var expectedFinal, expectedSingleParserEmission, expectedParserFacingCoalesced bool
	switch request.TLSBoundaryMode {
	case "split":
		if request.TLSBoundarySequence != 1 {
			return fmt.Errorf("split TLS boundary request has invalid sequence %d", request.TLSBoundarySequence)
		}
		expectedCount = 1
		expectedOrder = []int{1}
		expectedResponseClose = []bool{true}
		expectedFinal = true
		expectedSingleParserEmission = true
		if evidence.DeliveryShape != tlsBoundaryDeliverySplit ||
			evidence.EvidencePhase != tlsBoundaryEvidenceFinal ||
			evidence.FallbackReason != "none" || evidence.CoalescingGraceMillis != 0 ||
			evidence.CoalescingGraceExpired || evidence.VerificationBufferBytes != 0 ||
			evidence.VerificationBufferLimitBytes != 0 || evidence.VerificationPairDigestExact {
			return fmt.Errorf("split TLS boundary delivery evidence is invalid: %+v", evidence)
		}
	case "coalesced":
		if request.TLSBoundarySequence < 1 || request.TLSBoundarySequence > 2 {
			return fmt.Errorf("coalesced TLS boundary request has invalid sequence %d", request.TLSBoundarySequence)
		}
		if evidence.CoalescingGraceMillis <= 0 ||
			evidence.CoalescingGraceMillis > tlsBoundaryMaxCoalescingGraceMillis ||
			evidence.VerificationBufferLimitBytes != tlsBoundaryMaxPairBytes {
			return fmt.Errorf("coalesced TLS boundary bounds are invalid: %+v", evidence)
		}
		expectedFirstResponseKeepsAlive = true
		switch evidence.DeliveryShape {
		case tlsBoundaryDeliverySerializedFallback:
			if evidence.FallbackReason != tlsBoundaryFallbackGraceExpired ||
				!evidence.CoalescingGraceExpired {
				return fmt.Errorf("serialized TLS boundary fallback evidence is invalid: %+v", evidence)
			}
			if request.TLSBoundarySequence == 1 {
				expectedCount = 1
				expectedOrder = []int{1}
				expectedResponseClose = []bool{false}
				if evidence.EvidencePhase != tlsBoundaryEvidencePartial {
					return fmt.Errorf("first serialized response is not partial: %+v", evidence)
				}
			} else {
				expectedCount = 2
				expectedOrder = []int{1, 2}
				expectedResponseClose = []bool{false, true}
				expectedFinal = true
				if evidence.EvidencePhase != tlsBoundaryEvidenceFinal {
					return fmt.Errorf("second serialized response is not final: %+v", evidence)
				}
			}
			expectedEmissionParserOrder = append([]int(nil), expectedOrder...)
		default:
			return fmt.Errorf("unsupported coalesced TLS boundary delivery shape %q", evidence.DeliveryShape)
		}
	default:
		return fmt.Errorf("unsupported TLS boundary mode %q", request.TLSBoundaryMode)
	}
	if evidence.Passed != expectedFinal || evidence.RequestComplete != expectedFinal ||
		evidence.RequestBytesPreserved != expectedFinal ||
		evidence.ResponseForcesConnectionClose != expectedFinal ||
		!evidence.WireDecryptedPairsExact || !evidence.HeadersSpannedRecords ||
		!evidence.ParserShapeExact || !evidence.HandoffBeforeParse ||
		evidence.RequestsEmittedFromSingleParserCallback != expectedSingleParserEmission ||
		evidence.ParserFacingCoalesced != expectedParserFacingCoalesced {
		return fmt.Errorf("TLS boundary evidence failed for mode %s: %+v", request.TLSBoundaryMode, evidence)
	}
	if evidence.RequestCount != expectedCount ||
		len(evidence.RequestHeaderBytes) != expectedCount ||
		len(evidence.RequestBodyBytes) != expectedCount ||
		len(evidence.RequestTotalBytes) != expectedCount ||
		len(evidence.RequestHeaderDecryptedCallbackCounts) != expectedCount ||
		!equalInts(evidence.RequestOrder, expectedOrder) ||
		!equalInts(evidence.EmissionOrder, expectedOrder) ||
		!equalInts(evidence.ResponseOrder, expectedOrder) ||
		!equalBools(evidence.ResponseConnectionClose, expectedResponseClose) ||
		evidence.FirstResponseKeepsAlive != expectedFirstResponseKeepsAlive {
		return fmt.Errorf("TLS boundary request/order evidence is invalid: %+v", evidence)
	}

	totalRequestBytes := 0
	for index := range expectedCount {
		headerBytes := evidence.RequestHeaderBytes[index]
		bodyBytes := evidence.RequestBodyBytes[index]
		requestBytes := evidence.RequestTotalBytes[index]
		if headerBytes < tlsBoundaryMinHeaderBytes ||
			headerBytes > tlsBoundaryMaxHeaderBytes ||
			bodyBytes != tlsBoundaryBodyBytes ||
			requestBytes != headerBytes+bodyBytes ||
			requestBytes > tlsBoundaryMaxRequestBytes {
			return fmt.Errorf("TLS boundary request %d byte accounting is invalid: %+v", index+1, evidence)
		}
		totalRequestBytes += requestBytes
	}
	if request.TLSBoundaryMode == "coalesced" {
		if evidence.VerificationBufferBytes != totalRequestBytes ||
			evidence.VerificationPairDigestExact != expectedFinal {
			return fmt.Errorf("TLS boundary pair verification evidence is invalid: %+v", evidence)
		}
	}

	callbackCount := len(evidence.DecryptedCallbackLengths)
	if callbackCount < 2 || callbackCount > tlsBoundaryMaxCallbacks ||
		len(evidence.TLSApplicationRecordLegacyVersions) != callbackCount ||
		len(evidence.TLSApplicationRecordPayloadLengths) != callbackCount {
		return fmt.Errorf("TLS boundary wire/decrypt callback cardinality is invalid: %+v", evidence)
	}
	for index, length := range evidence.DecryptedCallbackLengths {
		if length <= 0 || length > tlsBoundaryMaxPlaintextRecordBytes {
			return fmt.Errorf("TLS boundary callback length is out of bounds: %d", length)
		}
		legacyVersion := evidence.TLSApplicationRecordLegacyVersions[index]
		if legacyVersion != tlsBoundaryApplicationDataLegacyVersion {
			return fmt.Errorf(
				"TLS boundary application record legacy version is invalid: %d",
				legacyVersion,
			)
		}
		payloadLength := evidence.TLSApplicationRecordPayloadLengths[index]
		if payloadLength <= length || payloadLength > length+tlsBoundaryMaxRecordOverhead ||
			payloadLength > tlsBoundaryMaxRecordPayload {
			return fmt.Errorf(
				"TLS boundary application record length is out of bounds: plaintext=%d payload=%d",
				length,
				payloadLength,
			)
		}
	}
	if evidence.DecryptedTotalBytes != totalRequestBytes ||
		evidence.ParserTotalBytes != totalRequestBytes ||
		sumInts(evidence.DecryptedCallbackLengths) != evidence.DecryptedTotalBytes ||
		sumInts(evidence.ParserCallbackLengths) != evidence.ParserTotalBytes ||
		evidence.ParserCallbackCount != len(evidence.ParserCallbackLengths) {
		return fmt.Errorf("TLS boundary callback byte totals do not match the request set: %+v", evidence)
	}
	requestOffset := 0
	for index, headerBytes := range evidence.RequestHeaderBytes {
		reported := evidence.RequestHeaderDecryptedCallbackCounts[index]
		observed := countIntersectingCallbacks(
			evidence.DecryptedCallbackLengths,
			requestOffset,
			requestOffset+headerBytes,
		)
		if reported < 2 || reported > callbackCount || reported != observed {
			return fmt.Errorf("TLS boundary request %d header callback count is invalid: reported=%d observed=%d", index+1, reported, observed)
		}
		requestOffset += evidence.RequestTotalBytes[index]
	}

	switch request.TLSBoundaryMode {
	case "split":
		expectedParserLengths = evidence.DecryptedCallbackLengths
		headerCallbackCount := evidence.RequestHeaderDecryptedCallbackCounts[0]
		if len(evidence.EmissionParserCallbackOrder) != 1 {
			return fmt.Errorf(
				"split TLS boundary emission callback cardinality does not match the single request: %+v",
				evidence,
			)
		}
		emissionCallback := evidence.EmissionParserCallbackOrder[0]
		if emissionCallback < 1 || emissionCallback > callbackCount {
			return fmt.Errorf(
				"split TLS boundary emission callback is out of range: emission=%d callbacks=%d",
				emissionCallback,
				callbackCount,
			)
		}
		if emissionCallback < headerCallbackCount {
			return fmt.Errorf(
				"split TLS boundary request was emitted before its headers completed: emission=%d header_completion=%d",
				emissionCallback,
				headerCallbackCount,
			)
		}
		if evidence.ParserFacingCoalesced || !evidence.SplitBuffersForwardedUnchanged ||
			evidence.ParserCallbackCount != callbackCount {
			return fmt.Errorf("split TLS boundary parser shape is invalid: %+v", evidence)
		}
	case "coalesced":
		expectedParserLengths = append([]int(nil), evidence.RequestTotalBytes...)
		if evidence.SplitBuffersForwardedUnchanged ||
			evidence.ParserCallbackCount != len(expectedParserLengths) {
			return fmt.Errorf("coalesced TLS boundary parser shape is invalid: %+v", evidence)
		}
	}
	if !equalInts(evidence.ParserCallbackLengths, expectedParserLengths) ||
		(request.TLSBoundaryMode != "split" &&
			!equalInts(evidence.EmissionParserCallbackOrder, expectedEmissionParserOrder)) {
		return fmt.Errorf("TLS boundary parser delivery evidence is invalid: %+v", evidence)
	}
	return nil
}

const (
	tlsBoundaryDeliverySplit                = "split"
	tlsBoundaryDeliveryParserCoalesced      = "parser_coalesced"
	tlsBoundaryDeliverySerializedFallback   = "serialized_proxy_fallback"
	tlsBoundaryEvidencePartial              = "partial"
	tlsBoundaryEvidenceFinal                = "final"
	tlsBoundaryFallbackGraceExpired         = "coalescing_grace_expired"
	tlsBoundarySequenceHeader               = "X-OBI-Boundary-Sequence"
	tlsBoundaryMinHeaderBytes               = (1 << 14) + 1
	tlsBoundaryMaxHeaderBytes               = 32 * 1024
	tlsBoundaryBodyBytes                    = 32 * 1024
	tlsBoundaryMaxRequestBytes              = 72 * 1024
	tlsBoundaryPaddingHeaderCount           = 3
	tlsBoundaryPaddingHeaderValueBytes      = 6000
	tlsBoundaryMaxCallbacks                 = 32
	tlsBoundaryMaxPlaintextRecordBytes      = 1 << 14
	tlsBoundaryMaxRecordOverhead            = 256
	tlsBoundaryMaxRecordPayload             = (1 << 14) + 2048
	tlsBoundaryApplicationDataLegacyVersion = 0x0303
	tlsBoundaryMaxPairBytes                 = 2 * tlsBoundaryMaxRequestBytes
	tlsBoundaryMaxCoalescingGraceMillis     = 1000
)

func sumInts(values []int) int {
	total := 0
	for _, value := range values {
		total += value
	}
	return total
}

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

func equalStrings(left, right []string) bool {
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

func equalBools(left, right []bool) bool {
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

func countIntersectingCallbacks(lengths []int, start, end int) int {
	if start < 0 || end <= start {
		return 0
	}
	count := 0
	offset := 0
	for _, length := range lengths {
		callbackEnd := offset + length
		if callbackEnd > start && offset < end {
			count++
		}
		offset = callbackEnd
		if offset >= end {
			break
		}
	}
	return count
}

func validateSerializedTLSBoundaryExtension(
	partial *tlsBoundaryEvidence,
	final *tlsBoundaryEvidence,
) error {
	if partial == nil || final == nil {
		return errors.New("serialized TLS boundary evidence omitted a partial or final snapshot")
	}
	if partial.Mode != final.Mode ||
		partial.DeliveryShape != final.DeliveryShape ||
		partial.FallbackReason != final.FallbackReason ||
		partial.CoalescingGraceMillis != final.CoalescingGraceMillis ||
		partial.CoalescingGraceExpired != final.CoalescingGraceExpired ||
		partial.VerificationBufferLimitBytes != final.VerificationBufferLimitBytes {
		return fmt.Errorf("serialized TLS boundary configuration changed across snapshots: partial=%+v final=%+v", partial, final)
	}
	if partial.RequestCount != 1 || final.RequestCount != 2 ||
		len(partial.RequestTotalBytes) != 1 || len(final.RequestTotalBytes) != 2 ||
		partial.EvidencePhase != tlsBoundaryEvidencePartial ||
		final.EvidencePhase != tlsBoundaryEvidenceFinal ||
		partial.Passed || partial.RequestComplete || partial.VerificationPairDigestExact ||
		!final.Passed || !final.RequestComplete || !final.VerificationPairDigestExact {
		return fmt.Errorf("serialized TLS boundary phases are not partial then final: partial=%+v final=%+v", partial, final)
	}
	for name, values := range map[string]struct{ partial, final []int }{
		"request headers":   {partial.RequestHeaderBytes, final.RequestHeaderBytes},
		"request bodies":    {partial.RequestBodyBytes, final.RequestBodyBytes},
		"request totals":    {partial.RequestTotalBytes, final.RequestTotalBytes},
		"header callbacks":  {partial.RequestHeaderDecryptedCallbackCounts, final.RequestHeaderDecryptedCallbackCounts},
		"request order":     {partial.RequestOrder, final.RequestOrder},
		"emission order":    {partial.EmissionOrder, final.EmissionOrder},
		"parser order":      {partial.EmissionParserCallbackOrder, final.EmissionParserCallbackOrder},
		"response order":    {partial.ResponseOrder, final.ResponseOrder},
		"record versions":   {partial.TLSApplicationRecordLegacyVersions, final.TLSApplicationRecordLegacyVersions},
		"record payloads":   {partial.TLSApplicationRecordPayloadLengths, final.TLSApplicationRecordPayloadLengths},
		"decrypt callbacks": {partial.DecryptedCallbackLengths, final.DecryptedCallbackLengths},
		"parser callbacks":  {partial.ParserCallbackLengths, final.ParserCallbackLengths},
	} {
		if !isIntPrefix(values.partial, values.final) {
			return fmt.Errorf("serialized TLS boundary %s did not extend monotonically: partial=%v final=%v", name, values.partial, values.final)
		}
	}
	if !isBoolPrefix(partial.ResponseConnectionClose, final.ResponseConnectionClose) ||
		partial.DecryptedTotalBytes >= final.DecryptedTotalBytes ||
		partial.ParserTotalBytes >= final.ParserTotalBytes ||
		partial.VerificationBufferBytes >= final.VerificationBufferBytes ||
		partial.DecryptedTotalBytes+final.RequestTotalBytes[1] != final.DecryptedTotalBytes ||
		partial.ParserTotalBytes+final.RequestTotalBytes[1] != final.ParserTotalBytes {
		return fmt.Errorf("serialized TLS boundary cumulative evidence is not a strict extension: partial=%+v final=%+v", partial, final)
	}
	return nil
}

func isIntPrefix(prefix, values []int) bool {
	return len(prefix) <= len(values) && equalInts(prefix, values[:len(prefix)])
}

func isBoolPrefix(prefix, values []bool) bool {
	return len(prefix) <= len(values) && equalBools(prefix, values[:len(prefix)])
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
	fault.Marker = request.Marker
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
	case "helper-attach-failure":
		mode = tracecheck.ModeHelperAttachFailure
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
	case "primary-w3c-fault":
		mode = tracecheck.ModeW3C
	case "primary-w3c-stale", "unix-w3c-stale":
		mode = tracecheck.ModeW3C
	case "w3c-only":
		mode = tracecheck.ModeW3CNoOBI
	case "restart-fault":
		mode = tracecheck.ModeW3CResilience
	}
	if cfg.scenario == "concurrency" {
		mode = concurrencyAssertionMode(cfg)
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

func awaitCoalescedBridgeAssertions(
	ctx context.Context,
	cfg config,
	requests []requestCase,
	diagnosticsAfter string,
	fetch snapshotFetcher,
) ([]tracecheck.Snapshot, []tracecheck.PressureParentOutcome, coalescedBridgeCorrelationSummary, error) {
	diagnosticDeltas, err := diagnosticCounterDeltas(
		cfg.javaDiagnosticsBefore,
		diagnosticsAfter,
		"coalesced bridge",
	)
	if err != nil {
		return nil, nil, coalescedBridgeCorrelationSummary{}, err
	}
	drops := summarizeDiagnosticDrops(diagnosticDeltas)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	var snapshots []tracecheck.Snapshot
	var outcomes []tracecheck.PressureParentOutcome
	var summary coalescedBridgeCorrelationSummary
	var validSince time.Time
	var lastErr error
	for {
		passSnapshots := make([]tracecheck.Snapshot, len(requests))
		passOutcomes := make([]tracecheck.PressureParentOutcome, len(requests))
		passSummary := coalescedBridgeCorrelationSummary{
			DiscardTotalDelta:     drops.Total,
			DiscardAmbiguousDelta: drops.Counts["ambiguous"],
			TriggerChainProven:    true,
		}
		var passErrors markerErrorSummary
		for index := range requests {
			if err := ctx.Err(); err != nil {
				return snapshots, outcomes, summary, traceAssertionDeadlineError(err, lastErr, nil)
			}
			snapshot, fetchErr := fetch(ctx, cfg.receiverURL, requests[index].Marker)
			if fetchErr != nil {
				passErrors.add(fmt.Errorf("marker %s: %w", requests[index].Marker, fetchErr))
				continue
			}
			passSnapshots[index] = snapshot
		}
		if passErrors.count == 0 {
			spanUnion, unionErr := coalescedSpanUnion(passSnapshots)
			if unionErr != nil {
				passErrors.add(unionErr)
			}
			for index := range requests {
				if unionErr != nil {
					break
				}
				combined := passSnapshots[index]
				combined.Spans = spanUnion
				combined.RelatedSpans = nil
				outcome, candidates, triggerChain, classifyErr := classifyCoalescedBridgeSnapshot(
					cfg,
					requests[index],
					requests[0].Marker,
					combined,
				)
				passOutcomes[index] = outcome
				passSummary.SourceClientCandidates += candidates
				passSummary.TriggerChainProven = passSummary.TriggerChainProven && triggerChain
				switch outcome {
				case tracecheck.PressureParentExactHit:
					passSummary.ExactHitCount++
				case tracecheck.PressureParentExplicitRoot:
					passSummary.ExplicitRootCount++
				case tracecheck.PressureParentWrong:
					passSummary.WrongParentCount++
				default:
					passSummary.UnresolvedCount++
				}
				if classifyErr != nil {
					passErrors.add(fmt.Errorf("marker %s: %w", requests[index].Marker, classifyErr))
				}
			}
		} else {
			passSummary.TriggerChainProven = false
		}
		if correlationErr := validateCoalescedBridgeCorrelation(&passSummary, len(requests)); correlationErr != nil {
			passErrors.add(correlationErr)
		} else if diagnosticsErr := validateCoalescedDiagnosticDeltas(
			diagnosticDeltas,
			passSummary.Outcome,
		); diagnosticsErr != nil {
			passErrors.add(diagnosticsErr)
		}
		snapshots = passSnapshots
		outcomes = passOutcomes
		summary = passSummary
		lastErr = passErrors.err()
		if lastErr == nil {
			if validSince.IsZero() {
				validSince = time.Now()
			}
			if time.Since(validSince) >= assertionQuiescence {
				return snapshots, outcomes, summary, nil
			}
		} else {
			validSince = time.Time{}
		}
		select {
		case <-ctx.Done():
			return snapshots, outcomes, summary, traceAssertionDeadlineError(ctx.Err(), lastErr, nil)
		case <-ticker.C:
		}
	}
}

func diagnosticCounterDeltas(before, after, label string) (map[string]uint64, error) {
	beforeCounters, err := javaDiagnosticsCounters(before)
	if err != nil {
		return nil, fmt.Errorf("parse %s diagnostics baseline: %w", label, err)
	}
	afterCounters, err := javaDiagnosticsCounters(after)
	if err != nil {
		return nil, fmt.Errorf("parse %s diagnostics result: %w", label, err)
	}
	deltas := make(map[string]uint64, len(javaDiagnosticsFieldNames))
	for _, counter := range javaDiagnosticsFieldNames {
		beforeValue := beforeCounters[counter]
		afterValue := afterCounters[counter]
		if afterValue < beforeValue {
			return nil, fmt.Errorf("%s diagnostics counter %q decreased", label, counter)
		}
		deltas[counter] = afterValue - beforeValue
	}
	return deltas, nil
}

func summarizeDiagnosticDrops(deltas map[string]uint64) diagnosticDropSummary {
	summary := diagnosticDropSummary{Counts: make(map[string]uint64, len(javaDiscardStatuses)+2)}
	for _, counter := range javaDiagnosticsFieldNames {
		if !strings.HasPrefix(counter, "d_") {
			continue
		}
		status := strings.TrimPrefix(counter, "d_")
		count := deltas[counter]
		summary.Counts[status] = count
		if count > 0 {
			summary.Reasons = append(summary.Reasons, status)
		}
		summary.Total += count
	}
	return summary
}

func validateCoalescedBridgeCorrelation(
	summary *coalescedBridgeCorrelationSummary,
	requestCount int,
) error {
	if summary.WrongParentCount != 0 || summary.UnresolvedCount != 0 ||
		summary.SourceClientCandidates != requestCount || !summary.TriggerChainProven {
		return fmt.Errorf("coalesced bridge correlation is incomplete: %+v", summary)
	}
	switch {
	case summary.ExactHitCount == requestCount && summary.ExplicitRootCount == 0 &&
		summary.DiscardTotalDelta == 0 && summary.DiscardAmbiguousDelta == 0:
		summary.Outcome = "supported_exact"
		return nil
	case summary.ExactHitCount == 0 && summary.ExplicitRootCount == requestCount &&
		summary.DiscardTotalDelta == 1 && summary.DiscardAmbiguousDelta == 1:
		summary.Outcome = "ambiguous_drop"
		return nil
	default:
		return fmt.Errorf(
			"coalesced bridge expected all exact parents or two roots with one d_ambiguous drop, got %+v",
			summary,
		)
	}
}

func validateCoalescedDiagnosticDeltas(deltas map[string]uint64, outcome string) error {
	switch outcome {
	case "supported_exact":
		return validateDeterministicDiagnosticDeltas(deltas, "coalesced exact", 2, 2, "")
	case "ambiguous_drop":
		return validateDeterministicDiagnosticDeltas(deltas, "coalesced ambiguous", 0, 0, "ambiguous")
	default:
		return fmt.Errorf("coalesced diagnostics have an unsupported outcome %q", outcome)
	}
}

func validateCancellationDiagnosticDeltas(
	deltas map[string]uint64,
	outcome string,
	drops diagnosticDropSummary,
) error {
	switch outcome {
	case "exact":
		return validateDeterministicDiagnosticDeltas(deltas, "cancellation exact", 2, 2, "")
	case "missing":
		return validateDeterministicDiagnosticDeltas(deltas, "cancellation missing", 1, 2, "")
	case "reason_coded_drop":
		if drops.Total != 1 || len(drops.Reasons) != 1 ||
			!reasonCodedJavaDiscard(drops.Reasons[0]) {
			return fmt.Errorf("cancellation diagnostics have an invalid reason-coded drop: %+v", drops)
		}
		return validateDeterministicDiagnosticDeltas(
			deltas,
			"cancellation reason-coded drop",
			1,
			1,
			drops.Reasons[0],
		)
	default:
		return fmt.Errorf("cancellation diagnostics have an unsupported outcome %q", outcome)
	}
}

func validateDeterministicDiagnosticDeltas(
	deltas map[string]uint64,
	label string,
	minimumValid uint64,
	maximumValid uint64,
	discardStatus string,
) error {
	valid := deltas["t_valid"]
	if valid < minimumValid || valid > maximumValid {
		return fmt.Errorf("%s expected t_valid in [%d,%d], got %d", label, minimumValid, maximumValid, valid)
	}
	for _, counter := range javaDiagnosticsFieldNames {
		if !strings.HasPrefix(counter, "t_") && !strings.HasPrefix(counter, "d_") {
			continue
		}
		expected := uint64(0)
		if counter == "t_valid" {
			expected = valid
		} else if discardStatus != "" && counter == "d_"+discardStatus {
			expected = 1
		}
		if deltas[counter] != expected {
			return fmt.Errorf("%s expected %s=%d, got %d", label, counter, expected, deltas[counter])
		}
	}
	for _, counter := range javaDeterministicFailureCounters {
		if deltas[counter] != 0 {
			return fmt.Errorf("%s expected %s=0, got %d", label, counter, deltas[counter])
		}
	}
	if deltas["take_sampled"] != valid || deltas["take_unsampled"] != 0 ||
		deltas["discard_standard"] != 0 {
		return fmt.Errorf(
			"%s changed sampling or standard-parent precedence: t_valid=%d take_sampled=%d take_unsampled=%d discard_standard=%d",
			label,
			valid,
			deltas["take_sampled"],
			deltas["take_unsampled"],
			deltas["discard_standard"],
		)
	}
	return nil
}

func classifyCoalescedBridgeSnapshot(
	cfg config,
	request requestCase,
	triggerMarker string,
	snapshot tracecheck.Snapshot,
) (tracecheck.PressureParentOutcome, int, bool, error) {
	if snapshot.Marker != request.Marker || snapshot.DroppedSpans != 0 ||
		snapshot.OmittedRelatedSpans != 0 || snapshot.AmbiguousRelatedSpans != 0 {
		return tracecheck.PressureParentUnresolved, 0, false, errors.New("receiver snapshot is incomplete")
	}
	spans := append(append([]tracecheck.Span(nil), snapshot.Spans...), snapshot.RelatedSpans...)
	allJavaServers := selectServiceKindSpans(spans, cfg.javaService, "SERVER")
	allSourceClients := selectServiceKindSpans(spans, cfg.coalescedSourceService, "CLIENT")
	javaSpans := selectMarkedSpans(spans, cfg.javaService, "SERVER", request.Marker)
	sourceClients := selectExactSpans(
		spans,
		cfg.coalescedSourceService,
		"CLIENT",
		request.Endpoint,
		request.Marker,
	)
	if len(allJavaServers) != 2 || len(allSourceClients) != 2 ||
		len(javaSpans) != 1 || len(sourceClients) != 1 {
		return tracecheck.PressureParentUnresolved, len(sourceClients), false,
			fmt.Errorf(
				"expected two total Java servers and source clients with one exact candidate, got Java=%d/%d source=%d/%d",
				len(javaSpans),
				len(allJavaServers),
				len(sourceClients),
				len(allSourceClients),
			)
	}
	javaSpan := javaSpans[0]
	if !tracecheck.MatchesEndpoint(javaSpan, request.Endpoint) {
		return tracecheck.PressureParentUnresolved, 1, false,
			fmt.Errorf("marked Java span used the wrong endpoint: %+v", javaSpan)
	}
	triggerChainErr := validateCoalescedTriggerChain(
		cfg,
		spans,
		sourceClients[0],
		triggerMarker,
	)
	triggerChain := triggerChainErr == nil
	if triggerChainErr != nil {
		return tracecheck.PressureParentUnresolved, 1, false, triggerChainErr
	}
	if zeroSpanID(javaSpan.ParentSpanID) {
		if remote, _ := tracecheck.ParentRemote(javaSpan); remote {
			return tracecheck.PressureParentWrong, len(sourceClients), triggerChain, errors.New("java root is marked remote")
		}
		if len(sourceClients) == 1 && strings.EqualFold(javaSpan.TraceID, sourceClients[0].TraceID) {
			return tracecheck.PressureParentWrong, 1, triggerChain, errors.New("java root reused the source candidate trace")
		}
		return tracecheck.PressureParentExplicitRoot, len(sourceClients), triggerChain, nil
	}
	if len(sourceClients) != 1 {
		return tracecheck.PressureParentWrong, 0, triggerChain, errors.New("java span has a parent without one exact source candidate")
	}
	candidate := sourceClients[0]
	if strings.EqualFold(javaSpan.TraceID, candidate.TraceID) &&
		strings.EqualFold(javaSpan.ParentSpanID, candidate.SpanID) {
		if remote, known := tracecheck.ParentRemote(javaSpan); !known || !remote {
			return tracecheck.PressureParentWrong, 1, triggerChain, errors.New("exact Java parent is not marked remote")
		}
		if tracecheck.TraceFlags(javaSpan) != tracecheck.TraceFlags(candidate) {
			return tracecheck.PressureParentWrong, 1, triggerChain, errors.New("exact Java parent changed trace flags")
		}
		return tracecheck.PressureParentExactHit, 1, triggerChain, nil
	}
	return tracecheck.PressureParentWrong, 1, triggerChain, fmt.Errorf(
		"java parent %s/%s did not identify source client %s/%s",
		javaSpan.TraceID,
		javaSpan.ParentSpanID,
		candidate.TraceID,
		candidate.SpanID,
	)
}

func validateCoalescedTriggerChain(
	cfg config,
	spans []tracecheck.Span,
	sourceClient tracecheck.Span,
	triggerMarker string,
) error {
	allSourceServers := selectServiceKindSpans(spans, cfg.coalescedSourceService, "SERVER")
	allApacheClients := selectServiceKindSpans(spans, cfg.apacheService, "CLIENT")
	sourceServers := selectExactSpans(
		spans,
		cfg.coalescedSourceService,
		"SERVER",
		"/api/coalesced-source",
		triggerMarker,
	)
	apacheClients := selectExactSpans(
		spans,
		cfg.apacheService,
		"CLIENT",
		"/api/coalesced-source",
		triggerMarker,
	)
	if len(allSourceServers) != 1 || len(allApacheClients) != 1 ||
		len(sourceServers) != 1 || len(apacheClients) != 1 {
		return fmt.Errorf(
			"coalesced trigger requires one total and exact Apache client and source server, got Apache=%d/%d source=%d/%d",
			len(apacheClients),
			len(allApacheClients),
			len(sourceServers),
			len(allSourceServers),
		)
	}
	sourceServer := sourceServers[0]
	apacheClient := apacheClients[0]
	if !strings.EqualFold(sourceServer.TraceID, apacheClient.TraceID) ||
		!strings.EqualFold(sourceServer.ParentSpanID, apacheClient.SpanID) {
		return errors.New("coalesced source server did not use the Apache client as its parent")
	}
	if remote, known := tracecheck.ParentRemote(sourceServer); known && !remote {
		return errors.New("coalesced source server parent is explicitly marked local")
	}
	if tracecheck.TraceFlags(sourceServer) != tracecheck.TraceFlags(apacheClient) {
		return errors.New("coalesced source server changed the Apache trace flags")
	}
	if !spanDescendsFromLocal(spans, sourceClient, sourceServer) {
		return errors.New("coalesced source client does not descend from the triggered source server")
	}
	return nil
}

func selectExactSpans(
	spans []tracecheck.Span,
	service string,
	kind string,
	endpoint string,
	marker string,
) []tracecheck.Span {
	var selected []tracecheck.Span
	for _, span := range spans {
		if span.ServiceName == service && strings.EqualFold(span.Kind, kind) &&
			tracecheck.MatchesEndpoint(span, endpoint) && tracecheck.MatchesMarker(span, marker) {
			selected = append(selected, span)
		}
	}
	return selected
}

func selectMarkedSpans(
	spans []tracecheck.Span,
	service string,
	kind string,
	marker string,
) []tracecheck.Span {
	var selected []tracecheck.Span
	for _, span := range spans {
		if span.ServiceName == service && strings.EqualFold(span.Kind, kind) &&
			tracecheck.MatchesMarker(span, marker) {
			selected = append(selected, span)
		}
	}
	return selected
}

func selectServiceKindSpans(
	spans []tracecheck.Span,
	service string,
	kind string,
) []tracecheck.Span {
	var selected []tracecheck.Span
	for _, span := range spans {
		if span.ServiceName == service && strings.EqualFold(span.Kind, kind) {
			selected = append(selected, span)
		}
	}
	return selected
}

func coalescedSpanUnion(snapshots []tracecheck.Snapshot) ([]tracecheck.Span, error) {
	selected := make(map[string]tracecheck.Span)
	order := make([]string, 0)
	add := func(span tracecheck.Span, exact bool) error {
		if zeroSpanID(span.TraceID) || zeroSpanID(span.SpanID) {
			return errors.New("coalesced bridge snapshot contains a zero span identity")
		}
		key := strings.ToLower(span.TraceID) + "/" + strings.ToLower(span.SpanID)
		previous, exists := selected[key]
		if !exists {
			selected[key] = span
			order = append(order, key)
			return nil
		}
		if exact && !reflect.DeepEqual(previous, span) {
			return fmt.Errorf("coalesced bridge snapshots conflict for span identity %s", key)
		}
		if !sameCoalescedSpanLink(previous, span) {
			return fmt.Errorf("coalesced bridge snapshots conflict for related span identity %s", key)
		}
		return nil
	}
	for _, snapshot := range snapshots {
		for _, span := range snapshot.Spans {
			if err := add(span, true); err != nil {
				return nil, err
			}
		}
	}
	for _, snapshot := range snapshots {
		for _, span := range snapshot.RelatedSpans {
			if err := add(span, false); err != nil {
				return nil, err
			}
		}
	}
	spans := make([]tracecheck.Span, 0, len(order))
	for _, key := range order {
		spans = append(spans, selected[key])
	}
	return spans, nil
}

func sameCoalescedSpanLink(left, right tracecheck.Span) bool {
	return strings.EqualFold(left.TraceID, right.TraceID) &&
		strings.EqualFold(left.SpanID, right.SpanID) &&
		strings.EqualFold(left.ParentSpanID, right.ParentSpanID) &&
		left.Flags == right.Flags && left.ServiceName == right.ServiceName &&
		strings.EqualFold(left.Kind, right.Kind) &&
		left.StartUnixNano == right.StartUnixNano && left.EndUnixNano == right.EndUnixNano &&
		left.ReceivedUnixMilli == right.ReceivedUnixMilli
}

func spanDescendsFromLocal(spans []tracecheck.Span, descendant, ancestor tracecheck.Span) bool {
	if !strings.EqualFold(descendant.TraceID, ancestor.TraceID) || descendant.ServiceName != ancestor.ServiceName {
		return false
	}
	parents := make(map[string]tracecheck.Span, len(spans))
	duplicates := make(map[string]bool)
	for _, span := range spans {
		if !strings.EqualFold(span.TraceID, descendant.TraceID) {
			continue
		}
		key := strings.ToLower(span.SpanID)
		if _, exists := parents[key]; exists {
			delete(parents, key)
			duplicates[key] = true
		} else if !duplicates[key] {
			parents[key] = span
		}
	}
	wanted := strings.ToLower(ancestor.SpanID)
	seen := make(map[string]bool, len(parents))
	parentID := descendant.ParentSpanID
	for !zeroSpanID(parentID) {
		key := strings.ToLower(parentID)
		if duplicates[key] || seen[key] {
			return false
		}
		seen[key] = true
		if key == wanted {
			return true
		}
		parent, exists := parents[key]
		if !exists || parent.ServiceName != ancestor.ServiceName {
			return false
		}
		parentID = parent.ParentSpanID
	}
	return false
}

func zeroSpanID(value string) bool {
	return value == "" || strings.Trim(value, "0") == ""
}

func awaitCancellationReconciliation(
	ctx context.Context,
	cfg config,
	marker string,
	diagnosticsAfter string,
	fetch snapshotFetcher,
) (tracecheck.Snapshot, string, []string, error) {
	diagnosticDeltas, err := diagnosticCounterDeltas(
		cfg.javaDiagnosticsBefore,
		diagnosticsAfter,
		"cancellation",
	)
	if err != nil {
		return tracecheck.Snapshot{}, "", nil, err
	}
	drops := summarizeDiagnosticDrops(diagnosticDeltas)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	var lastSnapshot tracecheck.Snapshot
	var lastOutcome string
	var lastErr error
	var stableSince time.Time
	for {
		snapshot, fetchErr := fetch(ctx, cfg.receiverURL, marker)
		outcome := "unresolved"
		classificationErr := fetchErr
		if fetchErr == nil {
			outcome, classificationErr = classifyCancellationSnapshot(cfg, marker, snapshot, drops)
			if classificationErr == nil {
				classificationErr = validateCancellationDiagnosticDeltas(
					diagnosticDeltas,
					outcome,
					drops,
				)
			}
		}
		if outcome != lastOutcome || errorText(classificationErr) != errorText(lastErr) {
			stableSince = time.Now()
		}
		lastSnapshot = snapshot
		lastOutcome = outcome
		lastErr = classificationErr
		if time.Since(stableSince) >= assertionQuiescence {
			if classificationErr != nil {
				return snapshot, outcome, drops.Reasons, classificationErr
			}
			return snapshot, outcome, drops.Reasons, nil
		}
		select {
		case <-ctx.Done():
			return lastSnapshot, lastOutcome, drops.Reasons,
				traceAssertionDeadlineError(ctx.Err(), lastErr, nil)
		case <-ticker.C:
		}
	}
}

func classifyCancellationSnapshot(
	cfg config,
	marker string,
	snapshot tracecheck.Snapshot,
	drops diagnosticDropSummary,
) (string, error) {
	if snapshot.Marker != marker || snapshot.DroppedSpans != 0 ||
		snapshot.OmittedRelatedSpans != 0 || snapshot.AmbiguousRelatedSpans != 0 {
		return "unresolved", errors.New("cancellation snapshot is incomplete")
	}
	spans := append(append([]tracecheck.Span(nil), snapshot.Spans...), snapshot.RelatedSpans...)
	allJavaServers := selectServiceKindSpans(spans, cfg.javaService, "SERVER")
	allApacheClients := selectServiceKindSpans(spans, cfg.apacheService, "CLIENT")
	javaSpans := selectMarkedSpans(spans, cfg.javaService, "SERVER", marker)
	apacheClients := selectMarkedSpans(spans, cfg.apacheService, "CLIENT", marker)
	if len(allApacheClients) != 1 || len(apacheClients) != 1 ||
		!tracecheck.MatchesEndpoint(apacheClients[0], "/api/echo") {
		return "unresolved", fmt.Errorf(
			"cancellation correlation requires one marked Apache client at /api/echo, got %+v",
			apacheClients,
		)
	}
	if len(allJavaServers) != len(javaSpans) {
		return "unresolved", fmt.Errorf(
			"cancellation correlation contains unmatched Java servers: marked=%d total=%d",
			len(javaSpans),
			len(allJavaServers),
		)
	}
	if len(javaSpans) == 0 {
		if drops.Total != 0 {
			return "unresolved", fmt.Errorf("missing canceled Java span requires zero receive drops, got %+v", drops)
		}
		return "missing", nil
	}
	if len(javaSpans) != 1 {
		return "unresolved", fmt.Errorf("cancellation correlation requires at most one marked Java server, got Java=%d", len(javaSpans))
	}
	javaSpan := javaSpans[0]
	if !tracecheck.MatchesEndpoint(javaSpan, "/api/echo") {
		return "unresolved", fmt.Errorf("marked canceled Java server used the wrong endpoint: %+v", javaSpan)
	}
	if zeroSpanID(javaSpan.ParentSpanID) {
		if remote, _ := tracecheck.ParentRemote(javaSpan); remote {
			return "wrong_parent", errors.New("canceled Java root is marked remote")
		}
		if len(apacheClients) == 1 && strings.EqualFold(javaSpan.TraceID, apacheClients[0].TraceID) {
			return "wrong_parent", errors.New("canceled Java root reused the Apache candidate trace")
		}
		if drops.Total != 1 || len(drops.Reasons) != 1 ||
			!reasonCodedJavaDiscard(drops.Reasons[0]) {
			return "unresolved", fmt.Errorf(
				"canceled Java root requires exactly one allowed reason-coded receive drop, got %+v",
				drops,
			)
		}
		return "reason_coded_drop", nil
	}
	if len(apacheClients) != 1 {
		return "wrong_parent", errors.New("canceled Java span has a parent without one exact Apache candidate")
	}
	candidate := apacheClients[0]
	if !strings.EqualFold(javaSpan.TraceID, candidate.TraceID) ||
		!strings.EqualFold(javaSpan.ParentSpanID, candidate.SpanID) {
		return "wrong_parent", fmt.Errorf(
			"canceled Java parent %s/%s did not identify Apache client %s/%s",
			javaSpan.TraceID,
			javaSpan.ParentSpanID,
			candidate.TraceID,
			candidate.SpanID,
		)
	}
	if remote, known := tracecheck.ParentRemote(javaSpan); !known || !remote {
		return "wrong_parent", errors.New("canceled exact Java parent is not marked remote")
	}
	if tracecheck.TraceFlags(javaSpan) != tracecheck.TraceFlags(candidate) {
		return "wrong_parent", errors.New("canceled exact Java parent changed trace flags")
	}
	if drops.Total != 0 {
		return "unresolved", fmt.Errorf("canceled exact Java parent requires zero receive drops, got %+v", drops)
	}
	return "exact", nil
}

func reasonCodedJavaDiscard(status string) bool {
	for _, candidate := range javaDiscardStatuses {
		if status == candidate {
			return true
		}
	}
	return false
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

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
	semanticErrors := make([]error, len(requests))
	var validSince time.Time
	var lastErr error

	for {
		passSnapshots := make([]tracecheck.Snapshot, len(requests))
		passAttempted := false
		var passErrors markerErrorSummary
		for i := range requests {
			if err := ctx.Err(); err != nil {
				currentErr := lastErr
				if passAttempted {
					currentErr = passErrors.err()
				}
				return snapshotsForAssertionDeadline(
						snapshots,
						passSnapshots,
						passAttempted,
					), traceAssertionDeadlineError(
						err,
						currentErr,
						summarizeMarkerErrors(semanticErrors),
					)
			}
			passAttempted = true
			snapshot, fetchErr := fetch(ctx, cfg.receiverURL, requests[i].Marker)
			if ctxErr := ctx.Err(); ctxErr != nil {
				if fetchErr != nil {
					passErrors.add(fmt.Errorf("marker %s: %w", requests[i].Marker, fetchErr))
				}
				return passSnapshots, traceAssertionDeadlineError(
					ctxErr,
					passErrors.err(),
					summarizeMarkerErrors(semanticErrors),
				)
			}
			if fetchErr != nil {
				passErrors.add(fmt.Errorf("marker %s: %w", requests[i].Marker, fetchErr))
				continue
			}

			passSnapshots[i] = snapshot
			assertionErr := tracecheck.AssertSnapshot(snapshot, expectationFor(cfg, requests[i]))
			if assertionErr == nil {
				semanticErrors[i] = nil
				continue
			}
			markerErr := fmt.Errorf("marker %s: %w", requests[i].Marker, assertionErr)
			semanticErrors[i] = markerErr
			passErrors.add(markerErr)
		}
		snapshots = passSnapshots
		lastErr = passErrors.err()

		if lastErr == nil {
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
			return snapshots, traceAssertionDeadlineError(
				ctx.Err(),
				lastErr,
				summarizeMarkerErrors(semanticErrors),
			)
		case <-ticker.C:
		}
	}
}

func snapshotsForAssertionDeadline(
	completed []tracecheck.Snapshot,
	current []tracecheck.Snapshot,
	currentAttempted bool,
) []tracecheck.Snapshot {
	if currentAttempted {
		return current
	}
	return completed
}

type markerErrorSummary struct {
	first error
	last  error
	count int
}

func (summary *markerErrorSummary) add(err error) {
	if summary.first == nil {
		summary.first = err
	}
	summary.last = err
	summary.count++
}

func (summary markerErrorSummary) err() error {
	if summary.count <= 1 {
		return summary.first
	}
	return fmt.Errorf("first result: %w; last result: %w", summary.first, summary.last)
}

func summarizeMarkerErrors(errs []error) error {
	var summary markerErrorSummary
	for _, err := range errs {
		if err != nil {
			summary.add(err)
		}
	}
	return summary.err()
}

func traceAssertionDeadlineError(ctxErr, currentErr, semanticErr error) error {
	switch {
	case currentErr != nil && semanticErr != nil:
		return fmt.Errorf(
			"trace assertion deadline: %w (current result: %w; active semantic result: %w)",
			ctxErr,
			currentErr,
			semanticErr,
		)
	case currentErr != nil:
		return fmt.Errorf("trace assertion deadline: %w (current result: %w)", ctxErr, currentErr)
	case semanticErr != nil:
		return fmt.Errorf("trace assertion deadline: %w (active semantic result: %w)", ctxErr, semanticErr)
	default:
		return fmt.Errorf("trace assertion deadline: %w", ctxErr)
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
	body, err := readBoundedBody(
		response.Body,
		maximumReceiverSnapshotBytes,
		"receiver snapshot",
	)
	if err != nil {
		return tracecheck.Snapshot{}, err
	}
	var snapshot tracecheck.Snapshot
	if err := json.Unmarshal(body, &snapshot); err != nil {
		return tracecheck.Snapshot{}, err
	}
	return snapshot, nil
}

func readBoundedBody(reader io.Reader, maximum int64, label string) ([]byte, error) {
	if maximum <= 0 {
		return nil, fmt.Errorf("%s has an invalid byte bound", label)
	}
	body, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maximum {
		return nil, fmt.Errorf("%s exceeded %d bytes", label, maximum)
	}
	return body, nil
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
		if err := validateConcurrencyEvidence(responses, evidence); err != nil {
			return err
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
	case "coalesced-bridge":
		if len(responses) != 2 || len(connectionIDs) != 1 || evidence == nil ||
			evidence.FrontendConnections != 1 || evidence.FrontendProtocol != "HTTP/1.1" ||
			evidence.SourceBackendTLSConnections != 1 || evidence.SourcePlaintextWriteCalls != 1 ||
			evidence.SourcePlaintextWriteBytes <= 0 || evidence.SourcePlaintextWriteBytes > 8<<10 ||
			evidence.SourceRequestBoundaries != 2 || evidence.SourceTraceparentHeaderCount != 0 ||
			!canonicalSHA256(evidence.SourcePlaintextSHA256) ||
			responses[0].BackendConnectionID != responses[1].BackendConnectionID ||
			responses[0].BackendRemotePort != responses[1].BackendRemotePort {
			return fmt.Errorf("coalesced bridge connection evidence is incomplete: responses=%+v evidence=%+v", responses, evidence)
		}
		for _, response := range responses {
			if response.CoalescedBridge == nil ||
				response.CoalescedBridge.PlaintextCallbackBytes != evidence.SourcePlaintextWriteBytes ||
				response.CoalescedBridge.PlaintextSHA256 != evidence.SourcePlaintextSHA256 {
				return fmt.Errorf("coalesced bridge write/receive evidence disagrees: response=%+v evidence=%+v", response, evidence)
			}
		}
	case "tls-boundary":
		if len(responses) != 3 || evidence == nil ||
			evidence.FrontendConnections != 2 || evidence.FrontendProtocol != "HTTP/1.1" ||
			evidence.SequentialRequests != 2 || evidence.ResponsesReadBeforeNextWrite != 1 ||
			evidence.PipelinedRequests != 0 || evidence.RequestsWrittenBeforeFirstRead != 0 {
			return fmt.Errorf("TLS boundary connection evidence is incomplete: responses=%d evidence=%+v", len(responses), evidence)
		}
		first, second := responses[1], responses[2]
		if first.BackendConnectionID != second.BackendConnectionID ||
			first.BackendRemotePort != second.BackendRemotePort ||
			first.TLSProtocol != second.TLSProtocol || first.TLSCipher != second.TLSCipher {
			return fmt.Errorf("coalesced TLS boundary pair did not reuse one backend connection: first=%+v second=%+v", first, second)
		}
		if responses[0].BackendConnectionID == first.BackendConnectionID {
			return fmt.Errorf("split and coalesced TLS boundary modes shared backend connection identity: split=%+v coalesced=%+v", responses[0], first)
		}
		if err := validateSerializedTLSBoundaryExtension(first.TLSBoundary, second.TLSBoundary); err != nil {
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

func validateConcurrencyEvidence(
	responses []backendResponse,
	evidence *connectionEvidence,
) error {
	wanted := len(responses)
	if wanted < 2 || evidence == nil ||
		evidence.DistinctBackendWorkers != wanted ||
		evidence.DistinctConcurrencyArrivals != wanted ||
		evidence.ConcurrencyParticipants != wanted ||
		evidence.ConcurrencyMaxActive != wanted || evidence.ConcurrencyRelease == 0 {
		return fmt.Errorf("expected concurrent backend worker overlap, observed evidence %+v", evidence)
	}
	workers := make(map[uint64]struct{}, wanted)
	arrivals := make(map[int]struct{}, wanted)
	for _, response := range responses {
		if response.BackendWorkerID == 0 || response.ConcurrencyArrival < 1 ||
			response.ConcurrencyArrival > wanted ||
			response.ConcurrencyParticipants != wanted || response.ConcurrencyMaxActive != wanted ||
			response.ConcurrencyRelease != evidence.ConcurrencyRelease {
			return fmt.Errorf("expected concurrent backend worker overlap, observed response %+v", response)
		}
		workers[response.BackendWorkerID] = struct{}{}
		arrivals[response.ConcurrencyArrival] = struct{}{}
	}
	if len(workers) != wanted || len(arrivals) != wanted {
		return fmt.Errorf(
			"expected concurrent backend worker overlap, observed workers=%d arrivals=%d wanted=%d",
			len(workers),
			len(arrivals),
			wanted,
		)
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
	case "concurrency", "pressure", "handoff", "virtual-thread", "netty", "netty-server", "dispatch":
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
