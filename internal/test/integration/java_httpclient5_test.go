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

type httpClient5Observation struct {
	Traceparents []string `json:"traceparents"`
	Connection   string   `json:"connection"`
	Protocol     string   `json:"protocol"`
	Method       string   `json:"method"`
	Path         string   `json:"path"`
	Token        string   `json:"token"`
	Body         string   `json:"body"`
	TraceID      string   `json:"trace_id"`
	SpanID       string   `json:"span_id"`
	ParentID     string   `json:"parent_id"`
}

func httpClient5Request(t require.TestingT, token, incoming, supplied string) httpClient5Observation {
	req, err := http.NewRequest(http.MethodGet, "http://localhost:18095/"+token, nil)
	require.NoError(t, err)
	req.Header.Set("traceparent", incoming)
	if supplied != "" {
		req.Header.Set("X-Supplied-Traceparent", supplied)
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var record httpClient5Observation
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&record))
	require.Equal(t, "HTTP/1.1", record.Protocol)
	require.Equal(t, "POST", record.Method)
	require.Equal(t, "/"+token, record.Path)
	require.Equal(t, token, record.Token)
	require.Equal(t, "payload:/"+token, record.Body)
	return record
}

func httpClient5Trace(t require.TestingT, traceID string) jaeger.Trace {
	resp, err := getJaeger("http://localhost:17695/api/traces/" + traceID)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var result jaeger.TracesQuery
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	require.Len(t, result.Data, 1)
	return result.Data[0]
}

func httpClient5Span(t require.TestingT, trace jaeger.Trace, service, kind string) jaeger.Span {
	var found []jaeger.Span
	for _, span := range trace.Spans {
		if trace.Processes[span.ProcessID].ServiceName != service {
			continue
		}
		tag, ok := jaeger.FindIn(span.Tags, "span.kind")
		if ok && tag.Value == kind {
			found = append(found, span)
		}
	}
	require.Len(t, found, 1, "service=%s kind=%s trace=%+v", service, kind, trace)
	return found[0]
}

func requireHTTPClient5Parent(t require.TestingT, span jaeger.Span, traceID, parentID string) {
	require.Equal(t, traceID, span.TraceID)
	require.Equal(t, []jaeger.Reference{{RefType: "CHILD_OF", TraceID: traceID, SpanID: parentID}}, span.References)
}

func TestJavaHTTPClient5Traceparent(t *testing.T) {
	for _, mode := range []string{"headers", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			compose, err := docker.ComposeSuite("docker-compose-java-httpclient5.yml", path.Join(pathOutput, "java-httpclient5-"+mode+".log"))
			require.NoError(t, err)
			compose.Env = append(compose.Env, "HTTPCLIENT5_PROPAGATION="+mode)
			t.Cleanup(func() { require.NoError(t, compose.Close()) })
			require.NoError(t, compose.Up())
			waitForTestComponentsNoMetrics(t, "http://localhost:18095/health")

			// Plain HTTP spans can appear before the Java agent attaches; wait for a TLS client span.
			id := fmt.Sprintf("%032x", time.Now().UnixNano())
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				httpClient5Request(ct, "warmup", "00-"+id+"-1234567890abcdef-01", "")
				trace := httpClient5Trace(ct, id)
				var clients []jaeger.Span
				for _, span := range trace.Spans {
					tag, ok := jaeger.FindIn(span.Tags, "span.kind")
					if ok && tag.Value == "client" && trace.Processes[span.ProcessID].ServiceName == "httpclient5-source" {
						clients = append(clients, span)
					}
				}
				require.NotEmpty(ct, clients)
			}, 2*time.Minute, 2*time.Second)

			check := func(t *testing.T, n int, supplied string) httpClient5Observation {
				traceID := fmt.Sprintf("ab%030x", n)
				parentID := fmt.Sprintf("cd%014x", n)
				incoming := "00-" + traceID + "-" + parentID + "-01"
				token := fmt.Sprintf("case-%d", n)
				record := httpClient5Request(t, token, incoming, supplied)
				t.Logf("%s: wire=%v connection=%s downstream=%s/%s parent=%s", token, record.Traceparents, record.Connection, record.TraceID, record.SpanID, record.ParentID)
				switch {
				case supplied != "":
					require.Equal(t, []string{supplied}, record.Traceparents)
					fields := strings.Split(supplied, "-")
					require.Equal(t, fields[1], record.TraceID)
					require.Equal(t, fields[2], record.ParentID)
				case mode == "disabled":
					require.Empty(t, record.Traceparents)
					require.NotEqual(t, traceID, record.TraceID)
					require.Equal(t, "0000000000000000", record.ParentID)
				default:
					require.Len(t, record.Traceparents, 1)
					require.Equal(t, traceID, record.TraceID)
				}
				require.EventuallyWithT(t, func(ct *assert.CollectT) {
					trace := httpClient5Trace(ct, traceID)
					server := httpClient5Span(ct, trace, "httpclient5-source", "server")
					requireHTTPClient5Parent(ct, server, traceID, parentID)
					// An explicit foreign context deliberately breaks the incoming trace.
					if supplied != "" {
						return
					}
					client := httpClient5Span(ct, trace, "httpclient5-source", "client")
					serverContext := server
					spanCount := 3
					processing := trace.FindByOperationNameAndService("processing", "httpclient5-source")
					if len(processing) != 0 {
						require.Len(ct, processing, 1)
						requireHTTPClient5Parent(ct, processing[0], traceID, server.SpanID)
						queued := trace.FindByOperationNameAndService("in queue", "httpclient5-source")
						require.Len(ct, queued, 1)
						requireHTTPClient5Parent(ct, queued[0], traceID, server.SpanID)
						serverContext = processing[0]
						spanCount += 2
					}
					requireHTTPClient5Parent(ct, client, traceID, serverContext.SpanID)
					if mode == "headers" {
						require.Equal(ct, "00-"+traceID+"-"+client.SpanID+"-01", record.Traceparents[0])
						require.Equal(ct, client.SpanID, record.ParentID)
						downstream := httpClient5Span(ct, trace, "httpclient5-downstream", "server")
						require.Equal(ct, record.SpanID, downstream.SpanID)
						requireHTTPClient5Parent(ct, downstream, traceID, client.SpanID)
						require.Len(ct, trace.Spans, spanCount)
						t.Logf("%s: incoming=%s source server=%s active server context=%s client=%s downstream=%s", token, parentID, server.SpanID, serverContext.SpanID, client.SpanID, downstream.SpanID)
					}
				}, time.Minute, time.Second)
				if supplied != "" || mode == "disabled" {
					require.EventuallyWithT(t, func(ct *assert.CollectT) {
						trace := httpClient5Trace(ct, record.TraceID)
						downstream := httpClient5Span(ct, trace, "httpclient5-downstream", "server")
						require.Equal(ct, record.SpanID, downstream.SpanID)
						if supplied != "" {
							requireHTTPClient5Parent(ct, downstream, record.TraceID, record.ParentID)
						} else {
							require.Empty(ct, downstream.References)
						}
					}, time.Minute, time.Second)
				}
				return record
			}

			t.Run("pooled", func(t *testing.T) {
				first := check(t, 1, "")
				second := check(t, 2, "")
				require.Equal(t, first.Connection, second.Connection, "requests must reuse a TLS connection")
			})
			t.Run("concurrent", func(t *testing.T) {
				var callers sync.WaitGroup
				start := make(chan struct{})
				for n := 3; n < 11; n++ {
					callers.Go(func() {
						t.Run(fmt.Sprintf("caller-%d", n), func(t *testing.T) { <-start; check(t, n, "") })
					})
				}
				close(start)
				callers.Wait()
			})
			t.Run("application-header", func(t *testing.T) {
				check(t, 11, "00-11111111111111111111111111111111-2222222222222222-01")
			})
		})
	}
}
