// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRunMaintainsConfiguredConcurrency(t *testing.T) {
	var active atomic.Int64
	var maximum atomic.Int64
	var firstWave atomic.Int64
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
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
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
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
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		redirectedRequests.Add(1)
		writer.WriteHeader(http.StatusOK)
	}))
	defer redirectTarget.Close()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
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
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
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
