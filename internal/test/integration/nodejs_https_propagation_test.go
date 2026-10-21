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

const nodeHTTPSOwned = "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"

type nodeHTTPSObservation struct {
	RawHeaders       []string `json:"rawHeaders"`
	Body             string   `json:"body"`
	Connection       int      `json:"connection"`
	DownstreamStatus int      `json:"downstreamStatus"`
	MaxActive        int      `json:"maxActive"`
}

func (o nodeHTTPSObservation) headers(name string) []string {
	var values []string
	for i := 0; i+1 < len(o.RawHeaders); i += 2 {
		if strings.EqualFold(o.RawHeaders[i], name) {
			values = append(values, o.RawHeaders[i+1])
		}
	}
	return values
}

func TestNodeHTTPSPropagation(t *testing.T) {
	if KernelLockdownMode() {
		t.Skip("Node HTTPS propagation requires bpf_probe_write_user")
	}
	for _, mode := range []string{"headers", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			compose, err := docker.ComposeSuite("docker-compose-nodejs-https-propagation.yml",
				path.Join(pathOutput, "test-suite-nodejs-https-"+mode+".log"))
			require.NoError(t, err)
			compose.Env = append(compose.Env, "NODE_HTTPS_PROPAGATION="+mode)
			require.NoError(t, compose.Up())
			t.Cleanup(func() { require.NoError(t, compose.Close()) })
			waitForTestComponentsNoMetrics(t, "http://localhost:8397/smoke")
			require.Eventually(t, func() bool {
				logs, err := compose.LogsTail(200, "obi")
				return err == nil && strings.Contains(logs, "Script successfully injected")
			}, testTimeout, 100*time.Millisecond, "Node agent was not injected")

			// Each call gets its own incoming connection; the source's HTTPS agent
			// deliberately reuses one outgoing TLS connection across these contexts.
			client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 15 * time.Second}
			t.Cleanup(client.CloseIdleConnections)
			connection := 0
			for i, overload := range []string{"options", "string", "url", "raw", "array-value", "url-only", "expect", "owned", "late-owned", "raw-owned", "invalid-owned"} {
				t.Run(overload, func(t *testing.T) {
					id := fmt.Sprintf("%s-%d", mode, i)
					traceID := fmt.Sprintf("%032x", i+1)
					if mode == "disabled" {
						traceID = fmt.Sprintf("%032x", i+100)
					}
					observation := requestNodeHTTPS(t, client, id, overload, traceID)
					if overload != "url-only" {
						require.Equal(t, []string{"preserved"}, observation.headers("x-unrelated"))
						require.Equal(t, "stream-"+id, observation.Body)
					} else {
						require.Empty(t, observation.Body)
					}
					if overload == "array-value" {
						require.Equal(t, []string{"traceparent", "untouched"}, observation.headers("x-values"))
					}
					if overload == "expect" {
						require.Equal(t, []string{"100-continue"}, observation.headers("expect"))
					}
					require.Equal(t, http.StatusOK, observation.DownstreamStatus)
					require.Positive(t, observation.Connection)
					if overload == "options" {
						connection = observation.Connection
					}
					if overload == "string" || overload == "url" {
						require.Equal(t, connection, observation.Connection, "TLS connection was not reused")
					}
					values := observation.headers("traceparent")
					if strings.Contains(overload, "owned") {
						expected := nodeHTTPSOwned
						if overload == "invalid-owned" {
							expected = "application-owned-invalid-value"
						}
						require.Equal(t, []string{expected}, values, "application header ownership is case-insensitive")
						return
					}
					if mode == "disabled" {
						require.Empty(t, values, "disabled propagation must transmit no traceparent")
						return
					}
					require.Len(t, values, 1, "raw TLS proxy headers must contain exactly one traceparent")
					assertNodeHTTPSParentage(t, traceID, id, values[0])
				})
			}

			t.Run("background request", func(t *testing.T) {
				incoming := "00000000000000000000000000008000"
				observation := requestNodeHTTPS(t, client, "background-"+mode, "background", incoming)
				values := observation.headers("traceparent")
				if mode == "disabled" {
					require.Empty(t, values)
					return
				}
				require.Len(t, values, 1)
				require.Regexp(t, `^00-[0-9a-f]{32}-[0-9a-f]{16}-01$`, values[0])
				traceID := strings.Split(values[0], "-")[1]
				require.NotEqual(t, incoming, traceID)
				assertNodeHTTPSParentage(t, traceID, "", values[0])
			})

			for callIndex, callMode := range []string{"overlap", "queued"} {
				t.Run(callMode+" contexts", func(t *testing.T) {
					var observations [2]nodeHTTPSObservation
					var errors [2]error
					var wg sync.WaitGroup
					offset := 1000 + callIndex*len(observations)
					for i := range observations {
						wg.Go(func() {
							observations[i], errors[i] = doNodeHTTPS(client, fmt.Sprintf("%s-%s-%d", callMode, mode, i), callMode, fmt.Sprintf("%032x", i+offset))
						})
					}
					wg.Wait()
					for _, err := range errors {
						require.NoError(t, err)
					}
					if callMode == "queued" {
						require.Equal(t, observations[0].Connection, observations[1].Connection, "queued calls must reuse a TLS socket")
					} else {
						require.NotEqual(t, observations[0].Connection, observations[1].Connection)
						require.Equal(t, 2, max(observations[0].MaxActive, observations[1].MaxActive), "proxy must observe concurrent calls")
					}
					for i, observation := range observations {
						id := fmt.Sprintf("%s-%s-%d", callMode, mode, i)
						require.Positive(t, observation.Connection)
						require.Equal(t, http.StatusOK, observation.DownstreamStatus)
						require.Equal(t, "stream-"+id, observation.Body)
						values := observation.headers("traceparent")
						if mode == "disabled" {
							require.Empty(t, values)
							continue
						}
						require.Len(t, values, 1)
						assertNodeHTTPSParentage(t, fmt.Sprintf("%032x", i+offset), id, values[0])
					}
				})
			}
		})
	}
}

func requestNodeHTTPS(t *testing.T, client *http.Client, id, mode, traceID string) nodeHTTPSObservation {
	t.Helper()
	observation, err := doNodeHTTPS(client, id, mode, traceID)
	require.NoError(t, err)
	return observation
}

func doNodeHTTPS(client *http.Client, id, mode, traceID string) (nodeHTTPSObservation, error) {
	var observation nodeHTTPSObservation
	req, err := http.NewRequest(http.MethodGet, "http://localhost:8397/call/"+id+"?mode="+mode, http.NoBody)
	if err != nil {
		return observation, err
	}
	req.Header.Set("traceparent", "00-"+traceID+"-1234567890abcdef-01")
	resp, err := client.Do(req)
	if err != nil {
		return observation, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return observation, fmt.Errorf("source status: %s", resp.Status)
	}
	err = json.NewDecoder(resp.Body).Decode(&observation)
	return observation, err
}

func assertNodeHTTPSParentage(t *testing.T, traceID, id, transmitted string) {
	t.Helper()
	require.Regexp(t, "^00-"+traceID+"-[0-9a-f]{16}-01$", transmitted)
	wireSpanID := strings.Split(transmitted, "-")[2]
	require.NotEqual(t, "0000000000000000", wireSpanID)
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := getJaeger("http://localhost:16697/api/traces?service=node-https-source")
		require.NoError(ct, err)
		defer resp.Body.Close()
		var query jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&query))
		var trace *jaeger.Trace
		for i := range query.Data {
			if query.Data[i].TraceID == traceID {
				trace = &query.Data[i]
				break
			}
		}
		require.NotNil(ct, trace)
		var servers, clients, downstream []jaeger.Span
		for _, span := range trace.Spans {
			kind, _ := jaeger.FindIn(span.Tags, "span.kind")
			service := trace.Processes[span.ProcessID].ServiceName
			if service == "node-https-source" && kind.Value == "server" {
				servers = append(servers, span)
			}
			if service == "node-https-source" && kind.Value == "client" {
				clients = append(clients, span)
			}
			if service == "dicer" && kind.Value == "server" {
				downstream = append(downstream, span)
			}
		}
		require.Len(ct, clients, 1)
		require.Equal(ct, wireSpanID, clients[0].SpanID)
		if id == "" {
			require.Empty(ct, servers)
			require.Empty(ct, clients[0].References)
		} else {
			require.Len(ct, servers, 1)
			pathTag, ok := jaeger.FindIn(servers[0].Tags, "url.path")
			require.True(ct, ok)
			require.Equal(ct, "/call/"+id, pathTag.Value)
			require.Contains(ct, servers[0].References, jaeger.Reference{RefType: "CHILD_OF", TraceID: traceID, SpanID: "1234567890abcdef"})
			parent, ok := trace.ParentOf(&clients[0])
			require.True(ct, ok)
			// OBI can export its request-processing span between server and client.
			if parent.OperationName == "processing" {
				parent, ok = trace.ParentOf(&parent)
				require.True(ct, ok)
			}
			require.Equal(ct, servers[0].SpanID, parent.SpanID)
		}
		require.Len(ct, downstream, 1)
		parent, ok := trace.ParentOf(&downstream[0])
		require.True(ct, ok)
		require.Equal(ct, clients[0].SpanID, parent.SpanID)
	}, testTimeout, 100*time.Millisecond)
}
