// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func trustedTLSServer(t *testing.T, dnsNames []string, ipAddresses []net.IP) (*httptest.Server, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificateTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "benchmark-test"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddresses,
	}
	certificateDER, err := x509.CreateCertificate(
		rand.Reader, certificateTemplate, certificateTemplate, &privateKey.PublicKey, privateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certificateDER},
			PrivateKey:  privateKey,
		}},
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	caFile := filepath.Join(t.TempDir(), "trusted-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return server, caFile
}

func TestRunMaintainsConfiguredConcurrency(t *testing.T) {
	var active atomic.Int64
	var maximum atomic.Int64
	var firstWave atomic.Int64
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		current := active.Add(1)
		defer active.Add(-1)
		for {
			previous := maximum.Load()
			if current <= previous || maximum.CompareAndSwap(previous, current) {
				break
			}
		}
		if firstWave.Add(1) <= 4 {
			entered <- struct{}{}
			<-release
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	releaseOnce := sync.Once{}
	releaseWorkers := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseWorkers()
	type outcome struct {
		result runResult
		err    error
	}
	completed := make(chan outcome, 1)
	go func() {
		result, err := run(context.Background(), config{
			baseURL:        server.URL,
			path:           "/api/echo",
			connectionMode: "close",
			duration:       100 * time.Millisecond,
			requestTimeout: time.Second,
			concurrency:    4,
			requestLimit:   maxRequestLimit,
		})
		completed <- outcome{result: result, err: err}
	}()
	for index := 0; index < 4; index++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			releaseWorkers()
			<-completed
			t.Fatalf("worker %d did not begin a request", index+1)
		}
	}
	releaseWorkers()
	finished := <-completed
	if finished.err != nil {
		t.Fatalf("run() error = %v", finished.err)
	}
	result := finished.result
	if result.Status != "passed" || result.SuccessfulRequests == 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.TLSVerification != tlsVerificationNotApplicable {
		t.Fatalf("TLS verification = %q, want %q", result.TLSVerification, tlsVerificationNotApplicable)
	}
	if maximum.Load() != 4 {
		t.Fatalf("maximum concurrent requests = %d, want 4", maximum.Load())
	}
	if result.Latency.P50Nanos <= 0 || result.Latency.P95Nanos < result.Latency.P50Nanos ||
		result.Latency.P99Nanos < result.Latency.P95Nanos {
		t.Fatalf("invalid latency summary: %+v", result.Latency)
	}
}

func TestRunSendsW3CHeaders(t *testing.T) {
	headers := make(chan http.Header, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		select {
		case headers <- request.Header.Clone():
		default:
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result, err := run(context.Background(), config{
		baseURL:        server.URL,
		path:           "/api/echo",
		connectionMode: "close",
		duration:       20 * time.Millisecond,
		requestTimeout: time.Second,
		concurrency:    1,
		requestLimit:   maxRequestLimit,
		seed:           42,
		w3c:            true,
	})
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if !result.W3C {
		t.Fatal("result did not record W3C mode")
	}
	select {
	case requestHeaders := <-headers:
		if got, want := requestHeaders.Get("traceparent"), "00-000000000000002a0000000000000001-0000000000000001-01"; got != want {
			t.Fatalf("traceparent = %q, want %q", got, want)
		}
		if got := requestHeaders.Get("X-Obi-Demo-Id"); got != "benchmark-load" {
			t.Fatalf("X-OBI-Demo-ID = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("server did not receive a request")
	}
}

func TestRunUsesExplicitTrustedCAForHTTPS(t *testing.T) {
	server, caFile := trustedTLSServer(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	result, err := run(context.Background(), config{
		baseURL:        server.URL,
		caFile:         caFile,
		path:           "/api/echo",
		connectionMode: "close",
		duration:       20 * time.Millisecond,
		requestTimeout: time.Second,
		concurrency:    1,
		requestLimit:   maxRequestLimit,
	})
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if result.Status != "passed" || result.SuccessfulRequests == 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.TLSVerification != tlsVerificationCAFile {
		t.Fatalf("TLS verification = %q, want %q", result.TLSVerification, tlsVerificationCAFile)
	}
}

func TestRunRejectsUntrustedHTTPSCertificate(t *testing.T) {
	server, _ := trustedTLSServer(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	_, wrongCAFile := trustedTLSServer(t, []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})

	result, err := run(context.Background(), config{
		baseURL:        server.URL,
		caFile:         wrongCAFile,
		path:           "/api/echo",
		connectionMode: "close",
		duration:       time.Second,
		requestTimeout: time.Second,
		concurrency:    1,
		requestLimit:   maxRequestLimit,
	})
	if err == nil {
		t.Fatal("run() error = nil, want TLS validation failure")
	}
	if result.Status != "failed" || result.TLSVerification != tlsVerificationCAFile {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestRunRejectsTrustedCertificateForWrongHostname(t *testing.T) {
	server, caFile := trustedTLSServer(t, []string{"localhost"}, nil)

	result, err := run(context.Background(), config{
		baseURL:        server.URL,
		caFile:         caFile,
		path:           "/api/echo",
		connectionMode: "close",
		duration:       time.Second,
		requestTimeout: time.Second,
		concurrency:    1,
		requestLimit:   maxRequestLimit,
	})
	if err == nil {
		t.Fatal("run() error = nil, want hostname validation failure")
	}
	if result.Status != "failed" || result.TLSVerification != tlsVerificationCAFile {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestTrustedCAPoolRejectsFIFOWithoutBlocking(t *testing.T) {
	caFile := filepath.Join(t.TempDir(), "trusted-ca")
	if err := syscall.Mkfifo(caFile, 0o600); err != nil {
		t.Fatal(err)
	}

	completed := make(chan error, 1)
	go func() {
		_, err := trustedCAPool(caFile)
		completed <- err
	}()
	select {
	case err := <-completed:
		if err == nil {
			t.Fatal("trustedCAPool() error = nil, want non-regular file rejection")
		}
	case <-time.After(time.Second):
		t.Fatal("trustedCAPool() blocked on FIFO")
	}
}

func TestValidateConfigRequiresCAOnlyForHTTPS(t *testing.T) {
	base := config{
		path:           "/api/echo",
		connectionMode: "close",
		duration:       time.Second,
		requestTimeout: time.Second,
		concurrency:    1,
		requestLimit:   1,
	}
	withBaseURL := func(baseURL, caFile string) config {
		cfg := base
		cfg.baseURL = baseURL
		cfg.caFile = caFile
		return cfg
	}
	for _, test := range []struct {
		name string
		cfg  config
		want bool
	}{
		{
			name: "http without CA",
			cfg:  withBaseURL("http://127.0.0.1:8080", ""),
			want: true,
		},
		{
			name: "http with CA",
			cfg:  withBaseURL("http://127.0.0.1:8080", "/trusted/ca.pem"),
		},
		{
			name: "https without CA",
			cfg:  withBaseURL("https://127.0.0.1:8443", ""),
		},
		{
			name: "https relative CA",
			cfg:  withBaseURL("https://127.0.0.1:8443", "ca.pem"),
		},
		{
			name: "https absolute CA",
			cfg:  withBaseURL("https://127.0.0.1:8443", "/trusted/ca.pem"),
			want: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateConfig(test.cfg)
			if (err == nil) != test.want {
				t.Fatalf("validateConfig() error = %v, want success=%t", err, test.want)
			}
		})
	}
}

func TestRunHonorsConnectionMode(t *testing.T) {
	for _, test := range []struct {
		name             string
		connectionMode   string
		wantRemoteCounts func(int) bool
	}{
		{
			name:           "close",
			connectionMode: "close",
			wantRemoteCounts: func(count int) bool {
				return count >= 2
			},
		},
		{
			name:           "reuse",
			connectionMode: "reuse",
			wantRemoteCounts: func(count int) bool {
				return count == 1
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			remoteAddresses := make(map[string]struct{})
			var mutex sync.Mutex
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				mutex.Lock()
				remoteAddresses[request.RemoteAddr] = struct{}{}
				mutex.Unlock()
				writer.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			result, err := run(context.Background(), config{
				baseURL:        server.URL,
				path:           "/api/echo",
				connectionMode: test.connectionMode,
				duration:       50 * time.Millisecond,
				requestTimeout: time.Second,
				concurrency:    1,
				requestLimit:   maxRequestLimit,
			})
			if err != nil {
				t.Fatalf("run() error = %v", err)
			}
			if result.SuccessfulRequests < 2 {
				t.Fatalf("successful requests = %d, want at least 2", result.SuccessfulRequests)
			}
			mutex.Lock()
			remoteCount := len(remoteAddresses)
			mutex.Unlock()
			if !test.wantRemoteCounts(remoteCount) {
				t.Fatalf("remote connection count = %d for mode %s", remoteCount, test.connectionMode)
			}
		})
	}
}

func TestRunReportsResponseFailures(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	result, err := run(context.Background(), config{
		baseURL:        server.URL,
		path:           "/api/echo",
		connectionMode: "reuse",
		duration:       time.Second,
		requestTimeout: time.Second,
		concurrency:    1,
		requestLimit:   maxRequestLimit,
	})
	if err == nil {
		t.Fatal("run() error = nil, want failure")
	}
	if result.Status != "failed" || result.FailedRequests != 1 || result.FirstFailure == "" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestRunDoesNotFollowRedirects(t *testing.T) {
	var redirectedRequests atomic.Int64
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		redirectedRequests.Add(1)
		writer.WriteHeader(http.StatusOK)
	}))
	defer redirectTarget.Close()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Location", redirectTarget.URL+"/unexpected")
		writer.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	result, err := run(context.Background(), config{
		baseURL:        server.URL,
		path:           "/api/echo",
		connectionMode: "close",
		duration:       time.Second,
		requestTimeout: time.Second,
		concurrency:    1,
		requestLimit:   maxRequestLimit,
	})
	if err == nil {
		t.Fatal("run() error = nil, want redirect failure")
	}
	if result.FailedRequests != 1 || redirectedRequests.Load() != 0 {
		t.Fatalf("result = %+v redirected_requests = %d", result, redirectedRequests.Load())
	}
}

func TestRunRejectsOversizedResponseHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("X-OBI-Benchmark-Fill", strings.Repeat("x", maxResponseHeaderBytes))
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	result, err := run(context.Background(), config{
		baseURL:        server.URL,
		path:           "/api/echo",
		connectionMode: "close",
		duration:       time.Second,
		requestTimeout: time.Second,
		concurrency:    1,
		requestLimit:   maxRequestLimit,
	})
	if err == nil {
		t.Fatal("run() error = nil, want response-header failure")
	}
	if result.FailedRequests != 1 || result.FirstFailure == "" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestRunReportsExternalCancellationAfterSuccess(t *testing.T) {
	secondRequestStarted := make(chan struct{})
	var requestCount atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if requestCount.Add(1) == 1 {
			writer.WriteHeader(http.StatusOK)
			return
		}
		close(secondRequestStarted)
		<-request.Context().Done()
	}))
	defer server.Close()

	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		result runResult
		err    error
	}
	completed := make(chan outcome, 1)
	go func() {
		result, err := run(parent, config{
			baseURL:        server.URL,
			path:           "/api/echo",
			connectionMode: "reuse",
			duration:       time.Second,
			requestTimeout: time.Second,
			concurrency:    1,
			requestLimit:   maxRequestLimit,
		})
		completed <- outcome{result: result, err: err}
	}()

	select {
	case <-secondRequestStarted:
		cancel()
	case <-time.After(time.Second):
		t.Fatal("benchmark did not start a second request")
	}
	finished := <-completed
	if finished.err == nil {
		t.Fatal("run() error = nil, want cancellation")
	}
	if !finished.result.Canceled || finished.result.SuccessfulRequests != 1 ||
		finished.result.FirstFailure == "" {
		t.Fatalf("unexpected result: %+v", finished.result)
	}
}

func TestRunDrainsInFlightRequestAfterDuration(t *testing.T) {
	requestStarted := make(chan struct{})
	allowResponse := make(chan struct{})
	requestCanceled := make(chan struct{})
	var serverRequests atomic.Uint64
	var startedOnce sync.Once
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got, want := request.Header.Get("traceparent"),
			"00-000000000000002a0000000000000001-0000000000000001-01"; got != want {
			t.Errorf("traceparent = %q, want %q", got, want)
		}
		serverRequests.Add(1)
		startedOnce.Do(func() { close(requestStarted) })
		select {
		case <-allowResponse:
			writer.WriteHeader(http.StatusOK)
		case <-request.Context().Done():
			close(requestCanceled)
		}
	}))
	defer server.Close()

	const duration = 200 * time.Millisecond
	type outcome struct {
		result runResult
		err    error
	}
	completed := make(chan outcome, 1)
	go func() {
		result, err := run(context.Background(), config{
			baseURL:        server.URL,
			path:           "/api/echo",
			connectionMode: "reuse",
			duration:       duration,
			requestTimeout: 5 * time.Second,
			concurrency:    1,
			requestLimit:   maxRequestLimit,
			seed:           42,
			w3c:            true,
		})
		completed <- outcome{result: result, err: err}
	}()

	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("benchmark did not start a request")
	}
	select {
	case <-requestCanceled:
		t.Fatal("measurement duration canceled an in-flight request")
	case <-completed:
		t.Fatal("benchmark completed before its in-flight request")
	case <-time.After(duration + 100*time.Millisecond):
	}
	close(allowResponse)

	select {
	case finished := <-completed:
		if finished.err != nil {
			t.Fatalf("run() error = %v", finished.err)
		}
		if finished.result.Status != "passed" || finished.result.SuccessfulRequests != 1 ||
			finished.result.FailedRequests != 0 || finished.result.Canceled ||
			finished.result.RequestLimitReached {
			t.Fatalf("unexpected result: %+v", finished.result)
		}
		if got := serverRequests.Load(); got != finished.result.SuccessfulRequests {
			t.Fatalf("server requests = %d, successful requests = %d", got, finished.result.SuccessfulRequests)
		}
	case <-time.After(time.Second):
		t.Fatal("benchmark did not finish after its in-flight request completed")
	}
}

func TestRequestAdmissionsEnforcesDeadlineAndLimit(t *testing.T) {
	deadline := time.Unix(100, 0)

	t.Run("deadline", func(t *testing.T) {
		now := deadline.Add(-time.Nanosecond)
		admissions := newRequestAdmissions(deadline, 2)
		admissions.now = func() time.Time { return now }
		if requestNumber, admitted := admissions.reserve(); !admitted || requestNumber != 1 {
			t.Fatalf("reserve() = (%d, %t), want (1, true)", requestNumber, admitted)
		}
		now = deadline
		if requestNumber, admitted := admissions.reserve(); admitted || requestNumber != 0 {
			t.Fatalf("reserve() = (%d, %t) at deadline, want (0, false)", requestNumber, admitted)
		}
		if got := admissions.count(); got != 1 {
			t.Fatalf("count() = %d, want 1", got)
		}
	})

	t.Run("limit", func(t *testing.T) {
		admissions := newRequestAdmissions(deadline, 1)
		admissions.now = func() time.Time { return deadline.Add(-time.Nanosecond) }
		if requestNumber, admitted := admissions.reserve(); !admitted || requestNumber != 1 {
			t.Fatalf("reserve() = (%d, %t), want (1, true)", requestNumber, admitted)
		}
		if requestNumber, admitted := admissions.reserve(); admitted || requestNumber != 0 {
			t.Fatalf("reserve() = (%d, %t) at limit, want (0, false)", requestNumber, admitted)
		}
		if got := admissions.count(); got != 1 {
			t.Fatalf("count() = %d, want 1", got)
		}
	})
}

func TestRunRejectsRequestLimitReachedBeforeDurationAfterDrain(t *testing.T) {
	requestStarted := make(chan struct{})
	allowResponse := make(chan struct{})
	var releaseResponse sync.Once
	release := func() { releaseResponse.Do(func() { close(allowResponse) }) }
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		close(requestStarted)
		<-allowResponse
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	defer release()

	const duration = 200 * time.Millisecond
	type outcome struct {
		result runResult
		err    error
	}
	completed := make(chan outcome, 1)
	go func() {
		result, err := run(context.Background(), config{
			baseURL:        server.URL,
			path:           "/api/echo",
			connectionMode: "reuse",
			duration:       duration,
			requestTimeout: 5 * time.Second,
			concurrency:    1,
			requestLimit:   1,
		})
		completed <- outcome{result: result, err: err}
	}()

	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("benchmark did not start a request")
	}
	select {
	case <-completed:
		t.Fatal("benchmark completed before its admitted request")
	case <-time.After(duration + 100*time.Millisecond):
	}
	release()

	select {
	case finished := <-completed:
		if finished.err == nil {
			t.Fatal("run() error = nil, want request-limit failure")
		}
		if finished.result.Status != "failed" || finished.result.SuccessfulRequests != 1 ||
			finished.result.FailedRequests != 0 || !finished.result.RequestLimitReached ||
			finished.result.Canceled {
			t.Fatalf("unexpected result: %+v", finished.result)
		}
	case <-time.After(time.Second):
		t.Fatal("benchmark did not report request-limit exhaustion after drain")
	}
}

func TestRunReportsInFlightTimeoutAfterDuration(t *testing.T) {
	requestStarted := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		close(requestStarted)
		<-request.Context().Done()
	}))
	defer server.Close()

	type outcome struct {
		result runResult
		err    error
	}
	completed := make(chan outcome, 1)
	go func() {
		result, err := run(context.Background(), config{
			baseURL:        server.URL,
			path:           "/api/echo",
			connectionMode: "reuse",
			duration:       200 * time.Millisecond,
			requestTimeout: 400 * time.Millisecond,
			concurrency:    1,
			requestLimit:   maxRequestLimit,
		})
		completed <- outcome{result: result, err: err}
	}()

	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("benchmark did not start a request")
	}
	select {
	case finished := <-completed:
		if finished.err == nil {
			t.Fatal("run() error = nil, want in-flight request timeout")
		}
		if finished.result.Status != "failed" || finished.result.SuccessfulRequests != 0 ||
			finished.result.FailedRequests != 1 || finished.result.Canceled ||
			finished.result.FirstFailure == "" {
			t.Fatalf("unexpected result: %+v", finished.result)
		}
	case <-time.After(time.Second):
		t.Fatal("benchmark did not report the in-flight request timeout")
	}
}

func TestParseFlagsRejectsUnsafeWorkloadSettings(t *testing.T) {
	for _, arguments := range [][]string{
		{"--duration=0s"},
		{"--concurrency=0"},
		{"--connection-mode=invalid"},
		{"--base-url=https://127.0.0.1:18080"},
		{"--path=https://example.com/"},
		{"--base-url=http://user:secret@127.0.0.1:18080"},
		{"--request-limit=0"},
		{"--request-limit=1000001"},
	} {
		if _, err := parseFlags(arguments); err == nil {
			t.Fatalf("parseFlags(%v) error = nil", arguments)
		}
	}
}
