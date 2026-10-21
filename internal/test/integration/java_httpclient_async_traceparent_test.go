// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"fmt"
	"io"
	"net/http"
	"path"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

func TestJavaHTTPClientAsyncTraceparent(t *testing.T) {
	for _, mode := range []string{"headers", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			compose, err := docker.ComposeSuite("docker-compose-java-httpclient-traceparent.yml",
				path.Join(pathOutput, "test-suite-java-httpclient-async-"+mode+".log"))
			require.NoError(t, err)
			compose.Env = append(compose.Env, "COMPOSE_PROJECT_NAME=obi-java-httpclient-async", "JAVA_HTTPCLIENT_PROPAGATION="+mode,
				"JAVA_HTTPCLIENT_PORTS=8080", "JAVA_HTTPCLIENT_DOWNSTREAM_OPTIONS=-javaagent:/fixture/opentelemetry-javaagent.jar")
			t.Cleanup(func() { assert.NoError(t, compose.Close()) })
			require.NoError(t, compose.Up())
			for _, port := range []int{18080, 18086} {
				require.EventuallyWithT(t, func(ct *assert.CollectT) {
					response, err := http.Get(fmt.Sprintf("http://localhost:%d/health", port))
					require.NoError(ct, err)
					defer response.Body.Close()
					body, err := io.ReadAll(response.Body)
					require.NoError(ct, err)
					require.Equal(ct, http.StatusOK, response.StatusCode)
					if port == 18080 {
						require.NotEmpty(ct, body, "OBI agent must attach to source")
					} else {
						require.Empty(ct, body, "downstream must not have an OBI agent")
					}
				}, 2*time.Minute, time.Second)
			}
			run := fmt.Sprintf("async-%s-%d", mode, time.Now().UnixNano())
			waitForJavaHTTPClientTrace(t, run, mode)
			for _, testMode := range []string{"generated", "reuse", "owned"} {
				t.Run(testMode, func(t *testing.T) {
					testJavaHTTPClientAsync(t, run+"-"+testMode, mode, testMode)
				})
			}
			t.Run("pooled-distinct-parents", func(t *testing.T) {
				testJavaHTTPClientAsync(t, run+"-pool-first", mode, "generated")
				testJavaHTTPClientAsync(t, run+"-pool-second", mode, "generated")
				require.Equal(t, javaProxyObservations(t, run+"-pool-first")[0].Connection,
					javaProxyObservations(t, run+"-pool-second")[0].Connection, "exercise connection reuse with distinct incoming contexts")
			})
			t.Run("concurrent", func(t *testing.T) {
				for i := range 4 {
					t.Run(strconv.Itoa(i), func(t *testing.T) {
						t.Parallel()
						testJavaHTTPClientAsync(t, fmt.Sprintf("%s-concurrent-%d", run, i), mode, "generated")
					})
				}
			})
			t.Run("concurrent-same-trace", func(t *testing.T) {
				for i := range 4 {
					t.Run(strconv.Itoa(i), func(t *testing.T) {
						t.Parallel()
						testJavaHTTPClientAsync(t, fmt.Sprintf("%s-concurrent-same-trace-%d", run, i), mode, "generated",
							"cccccccccccccccccccccccccccccccc", fmt.Sprintf("%016x", 0x300+i))
					})
				}
			})
			t.Run("after-concurrent", func(t *testing.T) {
				testJavaHTTPClientAsync(t, run+"-after", mode, "generated")
			})
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				response, err := http.Get("http://localhost:18080/propagation-state")
				require.NoError(ct, err)
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				require.NoError(ct, err)
				require.Equal(ct, "0:0", string(body), "requests and reservations must be released")
			}, 10*time.Second, time.Second)
		})
	}
}

func testJavaHTTPClientAsync(t *testing.T, id, mode, testMode string, incomingContext ...string) {
	t.Helper()
	// Each request gets a distinct, reproducible context, including parallel requests.
	traceID := fmt.Sprintf("%032x", []byte(id[len(id)-16:]))
	incomingParent := traceID[16:]
	if len(incomingContext) == 2 {
		traceID, incomingParent = incomingContext[0], incomingContext[1]
	}
	req, err := http.NewRequest(http.MethodGet, "http://localhost:18080/call/"+id, nil)
	require.NoError(t, err)
	req.Header.Set("traceparent", "00-"+traceID+"-"+incomingParent+"-01")
	req.Header.Set("X-Async", "true")
	if testMode == "reuse" {
		req.Header.Set("X-Test-Mode", "reuse")
	}
	if testMode == "owned" {
		req.Header.Set("X-Application-Traceparent", javaApplicationTraceparent)
	}
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(response.Body)
	require.NoError(t, response.Body.Close())
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, response.StatusCode, string(body))
	records := javaProxyObservations(t, id)
	count := 1
	if testMode == "reuse" {
		count = 2
	}
	require.Len(t, records, count)
	for _, record := range records {
		require.Equal(t, 1, record.Protocol)
		require.Equal(t, "preserved", record.Application)
		require.Equal(t, "fixture=preserved", record.Tracestate)
		switch {
		case testMode == "owned":
			require.Equal(t, []string{javaApplicationTraceparent}, record.Headers)
		case mode == "disabled":
			require.Empty(t, record.Headers)
		default:
			require.Len(t, record.Headers, 1, "exactly one transmitted traceparent")
			require.Regexp(t, `^00-`+traceID+`-[0-9a-f]{16}-01$`, record.Headers[0])
		}
	}
	if count == 2 {
		require.Equal(t, records[0].Connection, records[1].Connection)
		if mode == "headers" {
			require.NotEqual(t, records[0].Headers, records[1].Headers)
		}
	}
	expectedTrace := traceID
	if testMode == "owned" {
		expectedTrace = strings.Split(javaApplicationTraceparent, "-")[1]
	}
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		source, err := fetchTrace(traceID)
		require.NoError(ct, err)
		require.Len(ct, source.Data, 1)
		trace := source.Data[0]
		require.Equal(ct, traceID, trace.TraceID)
		servers := trace.FindByOperationNameServiceAndKind("GET /call/"+id, "java-httpclient", "server")
		require.Len(ct, servers, 1)
		require.Contains(ct, servers[0].References, jaeger.Reference{RefType: "CHILD_OF", TraceID: traceID, SpanID: incomingParent})
		var downstream jaeger.Trace
		if mode == "headers" || testMode == "owned" {
			query, err := fetchTrace(expectedTrace)
			require.NoError(ct, err)
			require.Len(ct, query.Data, 1)
			downstream = query.Data[0]
		} else {
			downstream, err = latestTraceMatching("java-downstream", func(trace jaeger.Trace) bool {
				for _, span := range trace.Spans {
					if len(span.Diff(jaeger.Tag{Key: "url.path", Type: "string", Value: "/" + id})) == 0 {
						return true
					}
				}
				return false
			})
			require.NoError(ct, err)
			require.NotEmpty(ct, downstream.TraceID)
		}
		clients := trace.FindByOperationNameServiceAndKind("GET /"+id, "java-httpclient", "client")
		if testMode != "owned" {
			require.Len(ct, clients, count)
		}
		if mode == "disabled" && testMode != "owned" {
			require.NotEqual(ct, traceID, downstream.TraceID)
			return
		}
		require.Equal(ct, expectedTrace, downstream.TraceID)
		for _, record := range records {
			parent := strings.Split(record.Headers[0], "-")[2]
			if testMode != "owned" {
				found := false
				for _, client := range clients {
					if client.SpanID == parent {
						found = true
						require.True(ct, javaSpanDescendsFrom(trace, client, servers[0].SpanID))
					}
				}
				require.True(ct, found, "transmitted parent must match exported source client")
			}
			found := false
			for _, span := range downstream.Spans {
				if downstream.Processes[span.ProcessID].ServiceName == "java-downstream" &&
					len(span.Diff(
						jaeger.Tag{Key: "span.kind", Type: "string", Value: "server"},
						jaeger.Tag{Key: "url.path", Type: "string", Value: "/" + id})) == 0 {
					for _, ref := range span.References {
						found = found || ref == (jaeger.Reference{RefType: "CHILD_OF", TraceID: expectedTrace, SpanID: parent})
					}
				}
			}
			require.True(ct, found, "OTel downstream server must be a child of the transmitted client span")
		}
	}, time.Minute, time.Second)
}
