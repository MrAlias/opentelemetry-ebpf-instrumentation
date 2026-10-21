// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"cmp"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
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

const dotnetOwnedTraceparent = "00-33333333333333333333333333333333-4444444444444444-01"

type dotnetWireObservation struct {
	ID           string   `json:"id"`
	Traceparents []string `json:"traceparents"`
	Protocol     string   `json:"protocol"`
	ALPN         string   `json:"alpn"`
	Peer         string   `json:"peer"`
}

type dotnetProxyObservations struct {
	Requests  []dotnetWireObservation `json:"requests"`
	MaxActive int                     `json:"max_active"`
}

type dotnetCall struct {
	id       string
	traceID  string
	response struct {
		Downstream struct {
			TraceID string `json:"trace_id"`
			SpanID  string `json:"span_id"`
		} `json:"downstream"`
		RuntimeTraceparents []string `json:"runtime_traceparents"`
	}
}

func TestSuite_DotNetHTTPClientTraceparent(t *testing.T) {
	for _, mode := range []struct {
		name        string
		propagation string
		diagnostics bool
	}{
		{"headers", "headers", true},
		{"disabled", "disabled", true},
		{"headers-without-diagnostics", "headers", false},
		{"disabled-without-diagnostics", "disabled", false},
	} {
		t.Run(mode.name, func(t *testing.T) {
			compose, err := docker.ComposeSuite("docker-compose-dotnet-httpclient.yml",
				path.Join(pathOutput, "test-suite-dotnet-httpclient-"+mode.name+".log"))
			require.NoError(t, err)
			compose.Env = append(compose.Env,
				"COMPOSE_PROJECT_NAME=obi-dotnet-httpclient",
				"DOTNET_OBI_PROPAGATION="+mode.propagation,
				fmt.Sprintf("DOTNET_DIAGNOSTIC_PROPAGATION=%t", mode.diagnostics))
			t.Cleanup(func() { require.NoError(t, compose.Close()) })
			require.NoError(t, compose.Up())
			waitForTestComponentsNoMetrics(t, "http://"+dotnetSourceAddress()+"/health")
			if mode.propagation == "headers" {
				require.Eventually(t, func() bool {
					logs, err := compose.LogsTail(200, "obi")
					return err == nil && strings.Contains(logs, "started .NET HTTP Activity collection")
				}, time.Minute, time.Second, "OBI did not subscribe to .NET HTTP activities")
			}
			require.Eventually(t, func() bool {
				response, err := http.Get("http://" + dotnetSourceAddress() + "/health")
				if err == nil {
					_ = response.Body.Close()
				}
				traces, err := getJaeger(dotnetJaegerURL() + "?service=dotnet-httpclient-source&limit=1&lookback=5m")
				if err != nil {
					return false
				}
				defer traces.Body.Close()
				var result jaeger.TracesQuery
				return json.NewDecoder(traces.Body).Decode(&result) == nil && len(result.Data) > 0
			}, time.Minute, time.Second)

			calls := []*dotnetCall{newDotnetCall("serial-1"), newDotnetCall("serial-2")}
			for _, call := range calls {
				require.NoError(t, call.send(""))
			}
			var workers sync.WaitGroup
			failures := make(chan error, 8)
			for i := range 8 {
				call := newDotnetCall(fmt.Sprintf("concurrent-%d", i))
				calls = append(calls, call)
				workers.Go(func() { failures <- call.send("") })
			}
			workers.Wait()
			close(failures)
			for err := range failures {
				require.NoError(t, err)
			}

			cancelled := newDotnetCall("cancel")
			require.NoError(t, cancelled.send("?cancel=true"))
			afterCancel := newDotnetCall("after")
			require.NoError(t, afterCancel.send(""))
			calls = append(calls, afterCancel)
			owned := newDotnetCall("owned")
			require.NoError(t, owned.send("?owned="+url.QueryEscape(dotnetOwnedTraceparent)))

			observations := readDotnetProxyObservations(t)
			require.Len(t, observations.Requests, len(calls)+2)
			require.GreaterOrEqual(t, observations.MaxActive, 2, "requests did not overlap at the TLS proxy")
			byID := map[string]dotnetWireObservation{}
			for _, observation := range observations.Requests {
				_, duplicate := byID[observation.ID]
				require.False(t, duplicate, "request reached proxy more than once: %s", observation.ID)
				byID[observation.ID] = observation
				require.Equal(t, "HTTP/1.1", observation.Protocol)
				require.Contains(t, []string{"", "http/1.1"}, observation.ALPN)
				require.NotEmpty(t, observation.Peer)
			}
			require.Equal(t, byID[calls[0].id].Peer, byID[calls[1].id].Peer,
				"sequential requests did not reuse the pooled TLS connection")
			require.Equal(t, []string{dotnetOwnedTraceparent}, byID[owned.id].Traceparents)
			require.Equal(t, owned.response.RuntimeTraceparents, byID[owned.id].Traceparents)
			assertDotnetDownstream(t, owned, dotnetOwnedTraceparent)

			for _, call := range append(calls, cancelled) {
				wire := byID[call.id].Traceparents
				if !mode.diagnostics {
					require.Empty(t, wire, "application disabled System.Net.Http propagation: %s", call.id)
					continue
				}
				require.Len(t, wire, 1, call.id)
				require.Regexp(t, `^00-[0-9a-f]{32}-[0-9a-f]{16}-01$`, wire[0], call.id)
				require.Equal(t, call.traceID, strings.Split(wire[0], "-")[1], call.id)
				if call == cancelled {
					continue
				}
				if mode.diagnostics {
					require.Equal(t, call.response.RuntimeTraceparents, wire,
						"OBI modified a traceparent already supplied by System.Net.Http")
				}
				assertDotnetDownstream(t, call, wire[0])
				if mode.propagation == "headers" {
					assertDotnetParentage(t, call, wire[0])
				}
			}
		})
	}
}

func newDotnetCall(name string) *dotnetCall {
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	traceID := hex.EncodeToString(id)
	return &dotnetCall{id: name + "-" + traceID, traceID: traceID}
}

func (call *dotnetCall) send(query string) error {
	request, err := http.NewRequest(http.MethodGet, "http://"+dotnetSourceAddress()+"/send/"+call.id+query, nil)
	if err != nil {
		return err
	}
	request.Header.Set("traceparent", "00-"+call.traceID+"-1111111111111111-01")
	client := &http.Client{Timeout: 30 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if query == "?cancel=true" && response.StatusCode == http.StatusNoContent {
		return nil
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: unexpected source status %d", call.id, response.StatusCode)
	}
	return json.NewDecoder(response.Body).Decode(&call.response)
}

func readDotnetProxyObservations(t *testing.T) dotnetProxyObservations {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	response, err := client.Get("https://127.0.0.1:" + cmp.Or(os.Getenv("DOTNET_HTTPCLIENT_PROXY_PORT"), "18443") + "/observations")
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	var observations dotnetProxyObservations
	require.NoError(t, json.NewDecoder(response.Body).Decode(&observations))
	return observations
}

func dotnetTrace(t require.TestingT, traceID string) jaeger.Trace {
	response, err := getJaeger(dotnetJaegerURL() + "/" + traceID)
	require.NoError(t, err)
	defer response.Body.Close()
	var traces jaeger.TracesQuery
	require.NoError(t, json.NewDecoder(response.Body).Decode(&traces))
	require.Len(t, traces.Data, 1)
	return traces.Data[0]
}

func assertDotnetDownstream(t *testing.T, call *dotnetCall, traceparent string) {
	t.Helper()
	parts := strings.Split(traceparent, "-")
	require.Equal(t, parts[1], call.response.Downstream.TraceID)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		trace := dotnetTrace(ct, parts[1])
		spans := dotnetServiceSpans(trace, "dotnet-httpclient-downstream", "server")
		require.Len(ct, spans, 1)
		require.Equal(ct, call.response.Downstream.SpanID, spans[0].SpanID)
		require.Equal(ct, []jaeger.Reference{{RefType: "CHILD_OF", TraceID: parts[1], SpanID: parts[2]}}, spans[0].References)
	}, time.Minute, 250*time.Millisecond)
}

func assertDotnetParentage(t *testing.T, call *dotnetCall, traceparent string) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		trace := dotnetTrace(ct, call.traceID)
		servers := dotnetServiceSpans(trace, "dotnet-httpclient-source", "server")
		clients := dotnetServiceSpans(trace, "dotnet-httpclient-source", "client")
		require.Len(ct, servers, 1)
		require.Len(ct, clients, 1)
		require.Equal(ct, []jaeger.Reference{{RefType: "CHILD_OF", TraceID: call.traceID, SpanID: "1111111111111111"}}, servers[0].References)
		require.Equal(ct, strings.Split(traceparent, "-")[2], clients[0].SpanID)
		require.Equal(ct, []jaeger.Reference{{RefType: "CHILD_OF", TraceID: call.traceID, SpanID: servers[0].SpanID}}, clients[0].References)
		t.Logf("trace=%s incoming=1111111111111111 server=%s client=%s wire=%s downstream=%s",
			call.traceID, servers[0].SpanID, clients[0].SpanID, traceparent, call.response.Downstream.SpanID)
	}, time.Minute, 250*time.Millisecond)
}

func dotnetSourceAddress() string {
	return "127.0.0.1:" + cmp.Or(os.Getenv("DOTNET_HTTPCLIENT_SOURCE_PORT"), "18086")
}

func dotnetJaegerURL() string {
	return "http://127.0.0.1:" + cmp.Or(os.Getenv("DOTNET_HTTPCLIENT_JAEGER_PORT"), "16686") + "/api/traces"
}

func dotnetServiceSpans(tr jaeger.Trace, service, kind string) []jaeger.Span {
	var result []jaeger.Span
	for _, span := range tr.Spans {
		if tr.Processes[span.ProcessID].ServiceName != service {
			continue
		}
		for _, tag := range span.Tags {
			if tag.Key == "span.kind" && tag.Value == kind {
				result = append(result, span)
				break
			}
		}
	}
	return result
}
