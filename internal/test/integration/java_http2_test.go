// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

type javaHTTP2Observation struct {
	Path         string   `json:"path"`
	Traceparents []string `json:"traceparents"`
	Protocol     string   `json:"protocol"`
	ALPN         string   `json:"alpn"`
	RemoteAddr   string   `json:"remote_addr"`
	Concurrent   bool     `json:"concurrent"`
	TraceID      string   `json:"trace_id"`
	SpanID       string   `json:"span_id"`
	ParentID     string   `json:"parent_id"`
	JavaVersion  string   `json:"java_version"`
}

func TestJavaHTTP2Propagation(t *testing.T) {
	for _, mode := range []string{"headers", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			compose, err := docker.ComposeSuite("docker-compose-java-http2.yml", path.Join(pathOutput, "java-http2-"+mode+".log"))
			require.NoError(t, err)
			compose.Env = append(compose.Env, "JAVA_HTTP2_PROPAGATION="+mode)
			require.NoError(t, compose.Up())
			t.Cleanup(func() { require.NoError(t, compose.Close()) })
			// Wait for dynamic attachment using exported source telemetry, not a fixed sleep.
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				resp, err := http.Get("http://localhost:28181/health")
				require.NoError(ct, err)
				require.NoError(ct, resp.Body.Close())
				require.Equal(ct, http.StatusOK, resp.StatusCode)
				resp, err = getJaeger("http://localhost:28686/api/traces?service=java-http2-source")
				require.NoError(ct, err)
				defer resp.Body.Close()
				var query jaeger.TracesQuery
				require.NoError(ct, json.NewDecoder(resp.Body).Decode(&query))
				require.NotEmpty(ct, query.Data)
			}, 2*time.Minute, time.Second)

			// Warm one shared HttpClient/TLS connection before concurrent callers start.
			first, err := javaHTTP2Call("warm", "00000000000000000000000000000001", "")
			require.NoError(t, err)
			t.Logf("warm: %+v", first)
			requireJavaHTTP2Protocol(t, first)
			if mode == "headers" {
				require.Len(t, first.Traceparents, 1)
				require.Equal(t, "00000000000000000000000000000001", strings.Split(first.Traceparents[0], "-")[1])
				requireJavaHTTP2Parent(t, first)
			} else {
				require.Empty(t, first.Traceparents)
			}
			const callers = 8
			for round := range 2 {
				observations := make([]javaHTTP2Observation, callers)
				traceIDs := make([]string, callers)
				errors := make([]error, callers)
				var workers sync.WaitGroup
				for i := range callers {
					traceIDs[i] = fmt.Sprintf("%032x", 100+round*callers+i)
					workers.Go(func() {
						observations[i], errors[i] = javaHTTP2Call(fmt.Sprintf("r%d-c%d", round, i), traceIDs[i], "")
					})
				}
				workers.Wait()
				concurrent := false
				for i, result := range observations {
					require.NoError(t, errors[i])
					t.Logf("%s: %+v", result.Path, result)
					requireJavaHTTP2Protocol(t, result)
					require.Equal(t, first.RemoteAddr, result.RemoteAddr, "TLS connection must be reused")
					concurrent = concurrent || result.Concurrent
					if mode == "disabled" {
						require.Empty(t, result.Traceparents)
						continue
					}
					require.Len(t, result.Traceparents, 1, "%s", result.Path)
					require.True(t, http2TraceparentPattern.MatchString(result.Traceparents[0]))
					require.Equal(t, traceIDs[i], strings.Split(result.Traceparents[0], "-")[1])
					require.Equal(t, traceIDs[i], result.TraceID)
					requireJavaHTTP2Parent(t, result)
				}
				require.True(t, concurrent, "requests must overlap on the shared TLS connection")
			}

			owned, err := javaHTTP2Call("owned", "00000000000000000000000000000002", http2OwnedTraceparent)
			require.NoError(t, err)
			t.Logf("owned: %+v", owned)
			requireJavaHTTP2Protocol(t, owned)
			require.Equal(t, first.RemoteAddr, owned.RemoteAddr)
			require.Equal(t, []string{http2OwnedTraceparent}, owned.Traceparents)
			require.Equal(t, strings.Split(http2OwnedTraceparent, "-")[1], owned.TraceID)
			require.Equal(t, strings.Split(http2OwnedTraceparent, "-")[2], owned.ParentID)
		})
	}
}

func javaHTTP2Call(id, traceID, owned string) (javaHTTP2Observation, error) {
	req, err := http.NewRequest(http.MethodGet, "http://localhost:28181/call/"+id, nil)
	if err != nil {
		return javaHTTP2Observation{}, err
	}
	req.Header.Set("Traceparent", "00-"+traceID+"-1234567890abcdef-01")
	if owned != "" {
		req.Header.Set("X-Application-Traceparent", owned)
	}
	client := &http.Client{Timeout: 40 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return javaHTTP2Observation{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Source-HTTP-Version") != "HTTP_2" {
		return javaHTTP2Observation{}, fmt.Errorf("%s: status %d, source HTTP version %q", id, resp.StatusCode, resp.Header.Get("X-Source-HTTP-Version"))
	}
	var result javaHTTP2Observation
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return result, err
	}
	if result.Path != "/call/"+id {
		return result, fmt.Errorf("expected path /call/%s, got %s", id, result.Path)
	}
	result.JavaVersion = resp.Header.Get("X-Java-Version")
	return result, nil
}

func requireJavaHTTP2Protocol(t *testing.T, result javaHTTP2Observation) {
	t.Helper()
	require.Equal(t, "HTTP/2.0", result.Protocol)
	require.Equal(t, "h2", result.ALPN)
	require.NotEmpty(t, result.RemoteAddr)
}

func requireJavaHTTP2Parent(t *testing.T, result javaHTTP2Observation) {
	t.Helper()
	clientID := strings.Split(result.Traceparents[0], "-")[2]
	require.Equal(t, clientID, result.ParentID)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := getJaeger("http://localhost:28686/api/traces/" + result.TraceID)
		require.NoError(ct, err)
		defer resp.Body.Close()
		var query jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&query))
		require.Len(ct, query.Data, 1)
		trace := query.Data[0]
		var client, downstream *jaeger.Span
		for i := range trace.Spans {
			span := &trace.Spans[i]
			if span.SpanID == clientID && trace.Processes[span.ProcessID].ServiceName == "java-http2-source" {
				client = span
			}
			if span.SpanID == result.SpanID && trace.Processes[span.ProcessID].ServiceName == "java-http2-downstream" {
				downstream = span
			}
		}
		require.NotNil(ct, client, "injected parent must be the OBI client span")
		require.Empty(ct, client.Diff(jaeger.Tag{Key: "span.kind", Type: "string", Value: "client"}))
		require.NotNil(ct, downstream)
		require.Contains(ct, downstream.References, jaeger.Reference{RefType: "CHILD_OF", TraceID: result.TraceID, SpanID: clientID})
	}, time.Minute, time.Second)
}
