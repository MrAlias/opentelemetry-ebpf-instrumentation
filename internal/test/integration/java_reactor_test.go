// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

type reactorEcho struct {
	Traceparents []string `json:"traceparents"`
	TraceID      string   `json:"trace_id"`
	SpanID       string   `json:"span_id"`
	Peer         string   `json:"peer"`
	Path         string   `json:"path"`
	Active       int      `json:"active_subscriptions"`
}

func reactorCall(id, incoming, supplied string, handoff bool) (reactorEcho, error) {
	var echo reactorEcho
	req, err := http.NewRequest(http.MethodGet, "http://localhost:28380/call/"+id, http.NoBody)
	if err != nil {
		return echo, err
	}
	req.Header.Set("traceparent", incoming)
	if supplied != "" {
		req.Header.Set("X-Supplied-Traceparent", supplied)
	}
	if handoff {
		req.Header.Set("X-Handoff", "true")
	}
	client := http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	resp, err := client.Do(req)
	if err != nil {
		return echo, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return echo, fmt.Errorf("source returned %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(&echo); err != nil {
		return echo, err
	}
	if echo.Path != "/outbound" {
		return echo, fmt.Errorf("unexpected downstream path %q for request %q", echo.Path, id)
	}
	return echo, nil
}

func reactorTrace(t *testing.T, traceID string, check func(*assert.CollectT, jaeger.Trace)) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := jaeger.Get("http://localhost:28686/api/traces/" + traceID)
		require.NoError(ct, err)
		defer resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		var query jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&query))
		require.Len(ct, query.Data, 1)
		check(ct, query.Data[0])
	}, 2*time.Minute, time.Second)
}

func reactorSourceParent(ct *assert.CollectT, trace jaeger.Trace, parentID string) jaeger.Span {
	var server, client []jaeger.Span
	for _, span := range trace.Spans {
		if trace.Processes[span.ProcessID].ServiceName != "reactor-source" {
			continue
		}
		kind, _ := jaeger.FindIn(span.Tags, "span.kind")
		switch kind.Value {
		case "server":
			server = append(server, span)
		case "client":
			client = append(client, span)
		}
	}
	require.Len(ct, server, 1)
	require.Len(ct, client, 1)
	require.Len(ct, server[0].References, 1)
	require.Equal(ct, parentID, server[0].References[0].SpanID)
	require.Len(ct, client[0].References, 1)
	if client[0].References[0].SpanID == server[0].SpanID {
		return client[0]
	}
	// OBI may insert a processing span when work was queued before the handler ran.
	for _, span := range trace.Spans {
		if span.SpanID == client[0].References[0].SpanID {
			require.Equal(ct, "processing", span.OperationName)
			require.Len(ct, span.References, 1)
			require.Equal(ct, server[0].SpanID, span.References[0].SpanID)
			return client[0]
		}
	}
	require.Fail(ct, "client parent is not the source server or its processing span")
	return jaeger.Span{}
}

func TestJavaReactorTraceparent(t *testing.T) {
	for _, mode := range []string{"headers", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			compose, err := docker.ComposeSuite("docker-compose-java-reactor.yml", filepath.Join(t.TempDir(), "compose.log"))
			require.NoError(t, err)
			compose.Env = append(compose.Env, "COMPOSE_PROJECT_NAME=obi-java-reactor", "REACTOR_PROPAGATION="+mode)
			require.NoError(t, compose.Up())
			t.Cleanup(func() { require.NoError(t, compose.Close()) })
			require.Eventually(t, func() bool {
				resp, err := http.Get("http://localhost:28380/health")
				if err != nil {
					return false
				}
				defer resp.Body.Close()
				return resp.StatusCode == http.StatusOK
			}, time.Minute, time.Second)
			// Wait for dynamic Java attachment and an exported source client span.
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				client := http.Client{Timeout: 20 * time.Second}
				resp, err := client.Get("http://localhost:28380/call/warmup")
				require.NoError(ct, err)
				require.Equal(ct, http.StatusOK, resp.StatusCode)
				var echo reactorEcho
				require.NoError(ct, json.NewDecoder(resp.Body).Decode(&echo))
				resp.Body.Close()
				if mode == "headers" {
					require.Len(ct, echo.Traceparents, 1)
				} else {
					require.Empty(ct, echo.Traceparents)
				}
				resp, err = jaeger.Get("http://localhost:28686/api/traces?service=reactor-source")
				require.NoError(ct, err)
				defer resp.Body.Close()
				var query jaeger.TracesQuery
				require.NoError(ct, json.NewDecoder(resp.Body).Decode(&query))
				for _, trace := range query.Data {
					for _, span := range trace.Spans {
						kind, _ := jaeger.FindIn(span.Tags, "span.kind")
						if kind.Value == "client" {
							return
						}
					}
				}
				require.Fail(ct, "OBI source client span not exported")
			}, 2*time.Minute, 2*time.Second)

			peers := map[string]int{}
			maxActive := 0
			for round := range 8 {
				type callResult struct {
					id, traceID, parentID string
					echo                  reactorEcho
					err                   error
				}
				results := make(chan callResult, 2)
				for index := range 2 {
					go func() {
						id := fmt.Sprintf("%s-%d-%d-%d", mode, time.Now().UnixNano(), round, index)
						traceID := fmt.Sprintf("%032x", time.Now().UnixNano())
						parentID := fmt.Sprintf("%016x", round*2+index+1)
						echo, err := reactorCall(id, "00-"+traceID+"-"+parentID+"-01", "", index == 1)
						results <- callResult{id, traceID, parentID, echo, err}
					}()
				}
				for range 2 {
					result := <-results
					require.NoError(t, result.err)
					id, traceID, parentID, echo := result.id, result.traceID, result.parentID, result.echo
					t.Logf("%s transmitted=%v downstream=%s/%s peer=%s active=%d", id, echo.Traceparents, echo.TraceID, echo.SpanID, echo.Peer, echo.Active)
					require.NotEmpty(t, echo.Peer)
					peers[echo.Peer]++
					maxActive = max(maxActive, echo.Active)
					if mode == "disabled" {
						require.Empty(t, echo.Traceparents)
						require.NotEqual(t, traceID, echo.TraceID)
						reactorTrace(t, traceID, func(ct *assert.CollectT, trace jaeger.Trace) {
							reactorSourceParent(ct, trace, parentID)
						})
						continue
					}
					require.Len(t, echo.Traceparents, 1)
					parts := strings.Split(echo.Traceparents[0], "-")
					require.Len(t, parts, 4)
					require.Equal(t, traceID, parts[1])
					require.Equal(t, traceID, echo.TraceID)
					reactorTrace(t, traceID, func(ct *assert.CollectT, trace jaeger.Trace) {
						client := reactorSourceParent(ct, trace, parentID)
						var downstream []jaeger.Span
						for _, span := range trace.Spans {
							service := trace.Processes[span.ProcessID].ServiceName
							if service == "reactor-downstream" {
								downstream = append(downstream, span)
							}
						}
						require.Len(ct, downstream, 1)
						require.Equal(ct, client.SpanID, parts[2])
						require.Equal(ct, echo.SpanID, downstream[0].SpanID)
						require.Len(ct, downstream[0].References, 1)
						require.Equal(ct, client.SpanID, downstream[0].References[0].SpanID)
						t.Logf("%s client=%s downstream=%s", id, client.SpanID, downstream[0].SpanID)
					})
				}
			}
			require.LessOrEqual(t, len(peers), 2, "shared pool must reuse at most two TLS connections")
			require.GreaterOrEqual(t, maxActive, 2, "reactive subscriptions must overlap")
			supplied := "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"
			echo, err := reactorCall(mode+"-supplied", "00-cccccccccccccccccccccccccccccccc-dddddddddddddddd-01", supplied, true)
			require.NoError(t, err)
			require.Equal(t, []string{supplied}, echo.Traceparents)
			reactorTrace(t, echo.TraceID, func(ct *assert.CollectT, trace jaeger.Trace) {
				for _, span := range trace.Spans {
					if span.SpanID == echo.SpanID {
						require.Len(ct, span.References, 1)
						require.Equal(ct, "bbbbbbbbbbbbbbbb", span.References[0].SpanID)
						return
					}
				}
				require.Fail(ct, "SDK downstream span missing")
			})
		})
	}
}
