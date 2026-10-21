// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	json "github.com/goccy/go-json"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

type pythonGRPCObservation struct {
	Traceparents []string `json:"traceparents"`
	Users        []string `json:"users"`
	Binary       []string `json:"binary"`
	Case         []string `json:"case"`
	TraceID      string   `json:"trace_id"`
	SpanID       string   `json:"span_id"`
	Peer         string   `json:"peer"`
	MaxActive    int      `json:"max_active"`
}

const pythonGRPCJaegerURL = "http://localhost:18091/api/traces"

func TestSuite_PythonGRPCTLS(t *testing.T) {
	for _, propagation := range []string{"disabled", "headers"} {
		t.Run(propagation, func(t *testing.T) {
			require.NoError(t, os.MkdirAll(pathOutput, 0o755))
			compose, err := docker.ComposeSuite("docker-compose-python-grpc-tls.yml",
				filepath.Join(pathOutput, "python-grpc-tls-"+propagation+".log"))
			require.NoError(t, err)
			compose.Env = append(compose.Env, "PYTHON_GRPC_PROPAGATION="+propagation,
				"OTEL_EBPF_EXECUTABLE_PATH=", "COMPOSE_PROJECT_NAME=obi-python-grpc-tls")
			if !KernelLockdownMode() {
				compose.Env = append(compose.Env, "SECURITY_CONFIG_SUFFIX=_none")
			}
			t.Cleanup(func() { require.NoError(t, compose.Close()) })
			require.NoError(t, compose.Up())
			require.Eventually(t, func() bool {
				response, err := http.Get("http://localhost:18090/health")
				if err != nil {
					return false
				}
				var health struct {
					GRPCHookReady bool `json:"grpc_hook_ready"`
				}
				err = json.NewDecoder(response.Body).Decode(&health)
				response.Body.Close()
				if err != nil || (propagation == "headers" && !health.GRPCHookReady) {
					return false
				}
				traces, err := getJaeger(pythonGRPCJaegerURL + "?service=python-grpc-source&limit=1")
				if err != nil {
					return false
				}
				defer traces.Body.Close()
				var query jaeger.TracesQuery
				return json.NewDecoder(traces.Body).Decode(&query) == nil && len(query.Data) > 0
			}, 2*time.Minute, time.Second, "source must be instrumented before opening the channel")

			const callers = 8
			const appTP = "00-1234567890abcdef1234567890abcdef-1234567890abcdef-01"
			type result struct {
				traceID      string
				caseID       string
				appTP        string
				observations []pythonGRPCObservation
				err          error
			}
			results := make(chan result, callers+1)
			var workers sync.WaitGroup
			start := make(chan struct{})
			for caller := range callers + 1 {
				workers.Go(func() {
					<-start
					caseID := fmt.Sprintf("caller-%d", caller)
					traceID := fmt.Sprintf("%016x%016x", time.Now().UnixNano(), caller+1)
					ownedTP := ""
					if caller == callers {
						ownedTP = appTP
					}
					observations, err := callPythonGRPCTLS(traceID, caseID, ownedTP, 3)
					results <- result{traceID, caseID, ownedTP, observations, err}
				})
			}
			close(start)
			workers.Wait()
			close(results)
			multiplexed := false
			peer := ""
			for result := range results {
				require.NoError(t, result.err)
				require.Len(t, result.observations, 3)
				spanIDs := map[string]bool{}
				for _, observation := range result.observations {
					assertPythonGRPCMetadata(t, observation, result.caseID)
					if peer == "" {
						peer = observation.Peer
					}
					require.Equal(t, peer, observation.Peer, "all RPCs must share one upstream connection")
					multiplexed = multiplexed || observation.MaxActive > 1
					if result.appTP != "" {
						require.Equal(t, []string{appTP}, observation.Traceparents)
						require.Equal(t, "1234567890abcdef1234567890abcdef", observation.TraceID)
						continue
					}
					if propagation == "disabled" {
						require.Empty(t, observation.Traceparents)
						require.NotEqual(t, result.traceID, observation.TraceID)
						continue
					}
					require.Len(t, observation.Traceparents, 1, "%+v", observation)
					parts := strings.Split(observation.Traceparents[0], "-")
					require.Len(t, parts, 4)
					require.Equal(t, "00", parts[0])
					require.Equal(t, "01", parts[3])
					require.Len(t, parts[2], 16)
					require.Equal(t, result.traceID, parts[1])
					require.Equal(t, result.traceID, observation.TraceID)
					require.False(t, spanIDs[parts[2]], "repeated RPCs need distinct client spans")
					spanIDs[parts[2]] = true
					assertPythonGRPCParentage(t, observation, parts[2])
				}
			}
			require.True(t, multiplexed, "downstream must observe overlapping HTTP/2 streams")

			observations, err := callPythonGRPCTLS("abcdef1234567890abcdef1234567890", "application", appTP, 4)
			require.NoError(t, err)
			require.Len(t, observations, 4)
			for _, observation := range observations {
				assertPythonGRPCMetadata(t, observation, "application")
				require.Equal(t, []string{appTP}, observation.Traceparents)
				require.Equal(t, "1234567890abcdef1234567890abcdef", observation.TraceID)
			}
			// Reuse the channel after application metadata to expose stale ownership/context.
			observations, err = callPythonGRPCTLS("fedcba0987654321fedcba0987654321", "after-application", "", 1)
			require.NoError(t, err)
			require.Len(t, observations, 1)
			if propagation == "headers" {
				require.Len(t, observations[0].Traceparents, 1)
				require.Equal(t, "fedcba0987654321fedcba0987654321", observations[0].TraceID)
				parts := strings.Split(observations[0].Traceparents[0], "-")
				require.Len(t, parts, 4)
				assertPythonGRPCParentage(t, observations[0], parts[2])
			} else {
				require.Empty(t, observations[0].Traceparents)
			}
			t.Logf("verified 24 automatic RPCs, 7 application-owned RPCs and one later RPC on one TLS connection; propagation=%s", propagation)
		})
	}
}

func callPythonGRPCTLS(traceID, caseID, appTP string, repeat int) ([]pythonGRPCObservation, error) {
	query := url.Values{"case": {caseID}, "repeat": {strconv.Itoa(repeat)}}
	if appTP != "" {
		query.Set("app_tp", appTP)
	}
	req, err := http.NewRequest(http.MethodGet, "http://localhost:18090/call?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Traceparent", "00-"+traceID+"-fedcba0987654321-01")
	client := http.Client{Timeout: 60 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("source returned %s", response.Status)
	}
	var observations []pythonGRPCObservation
	err = json.NewDecoder(response.Body).Decode(&observations)
	return observations, err
}

func assertPythonGRPCMetadata(t *testing.T, observation pythonGRPCObservation, caseID string) {
	t.Helper()
	require.Equal(t, []string{caseID}, observation.Case)
	require.Equal(t, []string{"first", "second"}, observation.Users)
	require.Equal(t, []string{"00ff"}, observation.Binary)
	require.NotEmpty(t, observation.Peer)
}

func assertPythonGRPCParentage(t *testing.T, observation pythonGRPCObservation, clientID string) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		response, err := getJaeger(pythonGRPCJaegerURL + "/" + observation.TraceID)
		require.NoError(ct, err)
		defer response.Body.Close()
		var query jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(response.Body).Decode(&query))
		require.Len(ct, query.Data, 1)
		trace := query.Data[0]
		var downstream *jaeger.Span
		for _, span := range trace.Spans {
			if span.SpanID == observation.SpanID {
				downstream = &span
				break
			}
		}
		require.NotNil(ct, downstream)
		require.Equal(ct, "grpc-downstream", trace.Processes[downstream.ProcessID].ServiceName)
		kind, ok := jaeger.FindIn(downstream.Tags, "span.kind")
		require.True(ct, ok)
		require.Equal(ct, "server", kind.Value)
		client, ok := trace.ParentOf(downstream)
		require.True(ct, ok)
		require.Equal(ct, clientID, client.SpanID)
		require.Equal(ct, "python-grpc-source", trace.Processes[client.ProcessID].ServiceName)
		require.Contains(ct, []string{"regression.Echo/Call", "grpc"}, client.OperationName)
		kind, ok = jaeger.FindIn(client.Tags, "span.kind")
		require.True(ct, ok)
		require.Equal(ct, "client", kind.Value)
		ancestor, ok := trace.ParentOf(&client)
		require.True(ct, ok)
		for range len(trace.Spans) {
			require.Equal(ct, "python-grpc-source", trace.Processes[ancestor.ProcessID].ServiceName)
			kind, ok = jaeger.FindIn(ancestor.Tags, "span.kind")
			require.True(ct, ok)
			if kind.Value == "server" {
				require.Equal(ct, "GET /call", ancestor.OperationName)
				require.Contains(ct, ancestor.References, jaeger.Reference{
					RefType: "CHILD_OF", TraceID: observation.TraceID, SpanID: "fedcba0987654321",
				})
				return
			}
			require.Equal(ct, "internal", kind.Value)
			ancestor, ok = trace.ParentOf(&ancestor)
			require.True(ct, ok)
		}
		require.Fail(ct, "source HTTP server span is not an ancestor of the gRPC client")
	}, 30*time.Second, time.Second)
}
