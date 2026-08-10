// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultDuration        = 30 * time.Second
	defaultRequestTimeout  = 10 * time.Second
	maxDuration            = 10 * time.Minute
	maxConcurrency         = 1_024
	maxRequestLimit        = 1_000_000
	maxResponseBytes       = 1 << 20
	maxResponseHeaderBytes = 64 << 10
	maxTrustedCABytes      = 1 << 20

	tlsVerificationNotApplicable = "not_applicable"
	tlsVerificationCAFile        = "verified_ca_file"
)

type config struct {
	baseURL        string
	caFile         string
	path           string
	connectionMode string
	duration       time.Duration
	requestTimeout time.Duration
	concurrency    int
	requestLimit   uint64
	seed           uint64
	w3c            bool
}

type latencySummary struct {
	P50Nanos int64 `json:"p50_nanos"`
	P95Nanos int64 `json:"p95_nanos"`
	P99Nanos int64 `json:"p99_nanos"`
}

type runResult struct {
	Status              string         `json:"status"`
	StartedAt           time.Time      `json:"started_at"`
	FinishedAt          time.Time      `json:"finished_at"`
	BaseURL             string         `json:"base_url"`
	Path                string         `json:"path"`
	ConnectionMode      string         `json:"connection_mode"`
	TLSVerification     string         `json:"tls_verification"`
	W3C                 bool           `json:"w3c"`
	Seed                uint64         `json:"seed"`
	Concurrency         int            `json:"concurrency"`
	RequestedDurationNS int64          `json:"requested_duration_nanos"`
	RequestTimeoutNS    int64          `json:"request_timeout_nanos"`
	RequestLimit        uint64         `json:"request_limit"`
	RequestLimitReached bool           `json:"request_limit_reached"`
	Canceled            bool           `json:"canceled"`
	TrafficElapsedNanos int64          `json:"traffic_elapsed_nanos"`
	SuccessfulRequests  uint64         `json:"successful_requests"`
	FailedRequests      uint64         `json:"failed_requests"`
	ThroughputPerSecond float64        `json:"throughput_per_second"`
	Latency             latencySummary `json:"latency"`
	FirstFailure        string         `json:"first_failure,omitempty"`
}

type measurements struct {
	mu           sync.Mutex
	latencies    []int64
	successes    uint64
	failures     uint64
	firstFailure string
}

type requestAdmissions struct {
	mu       sync.Mutex
	deadline time.Time
	limit    uint64
	requests uint64
	now      func() time.Time
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	exitCode := mainExitCode(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(exitCode)
}

func mainExitCode(parent context.Context, arguments []string, stdout, stderr io.Writer) int {
	cfg, err := parseFlags(arguments)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	result, runErr := run(parent, cfg)
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if runErr != nil {
		fmt.Fprintln(stderr, runErr)
		return 1
	}
	return 0
}

func parseFlags(arguments []string) (config, error) {
	cfg := config{
		baseURL:        "http://127.0.0.1:18080",
		path:           "/api/echo?delay_ms=150",
		connectionMode: "close",
		duration:       defaultDuration,
		requestTimeout: defaultRequestTimeout,
		concurrency:    16,
		requestLimit:   maxRequestLimit,
	}
	flags := flag.NewFlagSet("trace-benchmark", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&cfg.baseURL, "base-url", cfg.baseURL, "Apache base URL")
	flags.StringVar(&cfg.caFile, "ca-file", "", "absolute PEM CA file required for an HTTPS base URL")
	flags.StringVar(&cfg.path, "path", cfg.path, "request path and query")
	flags.StringVar(&cfg.connectionMode, "connection-mode", cfg.connectionMode, "close or reuse")
	flags.DurationVar(&cfg.duration, "duration", cfg.duration, "fixed measurement duration")
	flags.DurationVar(&cfg.requestTimeout, "request-timeout", cfg.requestTimeout, "per-request timeout")
	flags.IntVar(&cfg.concurrency, "concurrency", cfg.concurrency, "number of closed-loop workers")
	flags.Uint64Var(&cfg.requestLimit, "request-limit", cfg.requestLimit, "maximum requests")
	flags.Uint64Var(&cfg.seed, "seed", 0, "deterministic W3C identifier seed")
	flags.BoolVar(&cfg.w3c, "w3c", false, "send a valid W3C traceparent on every request")
	if err := flags.Parse(arguments); err != nil {
		return config{}, err
	}
	if flags.NArg() != 0 {
		return config{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if err := validateConfig(cfg); err != nil {
		return config{}, err
	}
	return cfg, nil
}

func validateConfig(cfg config) error {
	if cfg.duration <= 0 || cfg.duration > maxDuration {
		return fmt.Errorf("--duration must be between 1ns and %s", maxDuration)
	}
	if cfg.requestTimeout <= 0 || cfg.requestTimeout > maxDuration {
		return fmt.Errorf("--request-timeout must be between 1ns and %s", maxDuration)
	}
	if cfg.concurrency < 1 || cfg.concurrency > maxConcurrency {
		return fmt.Errorf("--concurrency must be between 1 and %d", maxConcurrency)
	}
	if cfg.requestLimit == 0 || cfg.requestLimit > maxRequestLimit {
		return fmt.Errorf("--request-limit must be between 1 and %d", maxRequestLimit)
	}
	if cfg.connectionMode != "close" && cfg.connectionMode != "reuse" {
		return errors.New("--connection-mode must be close or reuse")
	}
	baseURL, err := parseBaseURL(cfg.baseURL)
	if err != nil {
		return err
	}
	switch baseURL.Scheme {
	case "http":
		if cfg.caFile != "" {
			return errors.New("--ca-file requires an https --base-url")
		}
	case "https":
		if cfg.caFile == "" {
			return errors.New("https --base-url requires --ca-file")
		}
		if !filepath.IsAbs(cfg.caFile) {
			return errors.New("--ca-file must be an absolute path")
		}
	}
	if _, err := requestURL(cfg); err != nil {
		return err
	}
	return nil
}

func requestURL(cfg config) (string, error) {
	baseURL, err := parseBaseURL(cfg.baseURL)
	if err != nil {
		return "", err
	}
	requestPath, err := url.Parse(cfg.path)
	if err != nil || requestPath.IsAbs() || requestPath.Host != "" || !strings.HasPrefix(requestPath.Path, "/") {
		return "", fmt.Errorf("invalid --path %q", cfg.path)
	}
	return baseURL.ResolveReference(requestPath).String(), nil
}

func parseBaseURL(raw string) (*url.URL, error) {
	baseURL, err := url.Parse(raw)
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" {
		return nil, fmt.Errorf("invalid --base-url %q", raw)
	}
	if baseURL.Scheme != "http" && baseURL.Scheme != "https" {
		return nil, errors.New("--base-url must use http or https")
	}
	if baseURL.User != nil || baseURL.RawQuery != "" || baseURL.Fragment != "" ||
		(baseURL.Path != "" && baseURL.Path != "/") {
		return nil, errors.New("--base-url must be an origin without credentials, query, or path")
	}
	return baseURL, nil
}

func trustedCAPool(caFile string) (*x509.CertPool, error) {
	file, err := os.OpenFile(caFile, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("open trusted CA file: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat trusted CA file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("trusted CA file must be a regular file")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxTrustedCABytes+1))
	if err != nil {
		return nil, fmt.Errorf("read trusted CA file: %w", err)
	}
	if len(contents) > maxTrustedCABytes {
		return nil, fmt.Errorf("trusted CA file exceeds %d bytes", maxTrustedCABytes)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(contents) {
		return nil, errors.New("trusted CA file contains no certificate")
	}
	return pool, nil
}

func newHTTPTransport(cfg config) (*http.Transport, string, error) {
	baseURL, err := parseBaseURL(cfg.baseURL)
	if err != nil {
		return nil, "", err
	}
	transport := &http.Transport{
		DisableKeepAlives:      cfg.connectionMode == "close",
		MaxIdleConns:           cfg.concurrency,
		MaxIdleConnsPerHost:    cfg.concurrency,
		MaxConnsPerHost:        cfg.concurrency,
		IdleConnTimeout:        30 * time.Second,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
	}
	if baseURL.Scheme == "http" {
		return transport, tlsVerificationNotApplicable, nil
	}
	pool, err := trustedCAPool(cfg.caFile)
	if err != nil {
		return nil, "", err
	}
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    pool,
	}
	return transport, tlsVerificationCAFile, nil
}

func run(parent context.Context, cfg config) (runResult, error) {
	if err := validateConfig(cfg); err != nil {
		return runResult{}, err
	}
	targetURL, err := requestURL(cfg)
	if err != nil {
		return runResult{}, err
	}
	transport, tlsVerification, err := newHTTPTransport(cfg)
	if err != nil {
		return runResult{}, err
	}

	result := runResult{
		Status:              "failed",
		BaseURL:             cfg.baseURL,
		Path:                cfg.path,
		ConnectionMode:      cfg.connectionMode,
		TLSVerification:     tlsVerification,
		W3C:                 cfg.w3c,
		Seed:                cfg.seed,
		Concurrency:         cfg.concurrency,
		RequestedDurationNS: cfg.duration.Nanoseconds(),
		RequestTimeoutNS:    cfg.requestTimeout.Nanoseconds(),
		RequestLimit:        cfg.requestLimit,
	}

	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	measurements := measurements{latencies: make([]int64, 0, 1_024)}
	start := make(chan struct{})
	var waitGroup sync.WaitGroup
	var ready sync.WaitGroup
	ready.Add(cfg.concurrency)
	var admissions *requestAdmissions
	var requestParent context.Context
	var cancelRequests context.CancelFunc
	for worker := 0; worker < cfg.concurrency; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			ready.Done()
			<-start
			for {
				if requestParent.Err() != nil {
					return
				}
				requestNumber, reserved := admissions.reserve()
				if !reserved {
					return
				}
				requestStartedAt := time.Now()
				err := sendRequest(requestParent, client, targetURL, cfg, requestNumber)
				elapsed := time.Since(requestStartedAt).Nanoseconds()
				if err != nil {
					if requestParent.Err() != nil {
						return
					}
					measurements.recordFailure(err)
					cancelRequests()
					return
				}
				measurements.recordSuccess(elapsed)
			}
		}()
	}
	ready.Wait()
	result.StartedAt = time.Now().UTC()
	startedAt := time.Now()
	requestParent, cancelRequests = context.WithCancel(parent)
	defer cancelRequests()
	admissions = newRequestAdmissions(startedAt.Add(cfg.duration), cfg.requestLimit)
	close(start)
	waitGroup.Wait()
	result.FinishedAt = time.Now().UTC()
	result.TrafficElapsedNanos = time.Since(startedAt).Nanoseconds()
	result.RequestLimitReached = admissions.count() == cfg.requestLimit
	result.SuccessfulRequests, result.FailedRequests, result.FirstFailure, result.Latency = measurements.summary()
	if result.TrafficElapsedNanos > 0 {
		result.ThroughputPerSecond = float64(result.SuccessfulRequests) /
			time.Duration(result.TrafficElapsedNanos).Seconds()
	}

	if err := parent.Err(); err != nil {
		result.Canceled = true
		result.FirstFailure = fmt.Sprintf("benchmark canceled: %v", err)
		return result, errors.New(result.FirstFailure)
	}
	if result.FirstFailure != "" {
		return result, errors.New(result.FirstFailure)
	}
	if result.SuccessfulRequests == 0 {
		return result, errors.New("benchmark completed without a successful request")
	}
	if result.RequestLimitReached {
		return result, errors.New("request limit reached before the configured duration")
	}
	result.Status = "passed"
	return result, nil
}

func newRequestAdmissions(deadline time.Time, limit uint64) *requestAdmissions {
	return &requestAdmissions{
		deadline: deadline,
		limit:    limit,
		now:      time.Now,
	}
}

func (a *requestAdmissions) reserve() (uint64, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.now().Before(a.deadline) || a.requests >= a.limit {
		return 0, false
	}
	a.requests++
	return a.requests, true
}

func (a *requestAdmissions) count() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.requests
}

func sendRequest(
	ctx context.Context,
	client *http.Client,
	targetURL string,
	cfg config,
	requestNumber uint64,
) error {
	requestContext, cancel := context.WithTimeout(ctx, cfg.requestTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, targetURL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("X-OBI-Demo-ID", "benchmark-load")
	request.Close = cfg.connectionMode == "close"
	if cfg.w3c {
		request.Header.Set("traceparent", traceparent(cfg.seed, requestNumber))
	}

	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected HTTP status %d", response.StatusCode)
	}
	bytesRead, err := io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if bytesRead > maxResponseBytes {
		return fmt.Errorf("response body exceeds %d bytes", maxResponseBytes)
	}
	return nil
}

func traceparent(seed, requestNumber uint64) string {
	return fmt.Sprintf("00-%016x%016x-%016x-01", seed, requestNumber, requestNumber)
}

func (m *measurements) recordSuccess(latencyNanos int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.successes++
	m.latencies = append(m.latencies, latencyNanos)
}

func (m *measurements) recordFailure(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failures++
	if m.firstFailure == "" {
		m.firstFailure = err.Error()
	}
}

func (m *measurements) summary() (uint64, uint64, string, latencySummary) {
	m.mu.Lock()
	defer m.mu.Unlock()
	latencies := append([]int64(nil), m.latencies...)
	sort.Slice(latencies, func(left, right int) bool { return latencies[left] < latencies[right] })
	return m.successes, m.failures, m.firstFailure, latencySummary{
		P50Nanos: percentile(latencies, 0.50),
		P95Nanos: percentile(latencies, 0.95),
		P99Nanos: percentile(latencies, 0.99),
	}
}

func percentile(values []int64, percentile float64) int64 {
	if len(values) == 0 {
		return 0
	}
	index := int(math.Ceil(float64(len(values))*percentile)) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(values) {
		index = len(values) - 1
	}
	return values[index]
}
