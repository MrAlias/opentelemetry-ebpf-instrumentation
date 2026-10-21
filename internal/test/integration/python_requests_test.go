// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

const (
	requestsOwnedTraceparent = "00-33333333333333333333333333333333-4444444444444444-01"
	requestsSourceURL        = "http://127.0.0.1:28086"
	requestsJaegerURL        = "http://127.0.0.1:28186/api/traces"
)

type requestsObservation struct {
	CaseID          string            `json:"case_id"`
	Traceparents    []string          `json:"traceparents"`
	Peer            string            `json:"peer"`
	Active          int               `json:"active"`
	BodyHex         string            `json:"body_hex"`
	PreparedBodyHex string            `json:"prepared_body_hex"`
	Method          string            `json:"method"`
	Path            string            `json:"path"`
	HTTPVersion     string            `json:"http_version"`
	Headers         map[string]string `json:"headers"`
	PreparedBefore  map[string]string `json:"prepared_before"`
	PreparedAfter   map[string]string `json:"prepared_after"`
	Downstream      struct {
		TraceID  string `json:"trace_id"`
		SpanID   string `json:"span_id"`
		ParentID string `json:"parent_id"`
	} `json:"downstream"`
}

func TestSuite_PythonRequestsTraceparent(t *testing.T) {
	for _, propagation := range []string{"headers", "disabled"} {
		t.Run(propagation, func(t *testing.T) {
			compose, err := docker.ComposeSuite("docker-compose-python-requests.yml",
				path.Join(pathOutput, "test-suite-python-requests-"+propagation+".log"))
			require.NoError(t, err)
			compose.Env = append(compose.Env, "REQUESTS_PROPAGATION="+propagation,
				"SECURITY_CONFIG_SUFFIX=_none")
			t.Cleanup(func() { require.NoError(t, compose.Close()) })
			require.NoError(t, compose.Up())
			waitForTestComponentsNoMetrics(t, requestsSourceURL+"/health")
			require.Eventually(t, func() bool {
				resp, err := http.Get(requestsSourceURL + "/health")
				if err == nil {
					_ = resp.Body.Close()
				}
				resp, err = getJaeger(requestsJaegerURL + "?service=requests-source&limit=1&lookback=5m")
				if err != nil {
					return false
				}
				defer resp.Body.Close()
				var result jaeger.TracesQuery
				return resp.StatusCode == http.StatusOK && json.NewDecoder(resp.Body).Decode(&result) == nil && len(result.Data) > 0
			}, time.Minute, time.Second, "source instrumentation did not become ready")
			if propagation == "headers" {
				client := &http.Client{Timeout: 10 * time.Second}
				require.Eventually(t, func() bool {
					observations, err := requestRequestsSource(client,
						fmt.Sprintf("%032x", time.Now().UnixNano()), "https", "", 1, false)
					return err == nil && len(observations) == 1 && len(observations[0].Traceparents) == 1
				}, time.Minute, time.Second, "Python Session header injection did not become ready")
			}
			versions, err := compose.ExecOutput("source", "python", "-c",
				"import sys,ssl,requests,urllib3; print(sys.version,ssl.OPENSSL_VERSION,requests.__version__,urllib3.__version__)")
			require.NoError(t, err)
			t.Logf("source versions: %s", versions)

			for _, scheme := range []string{"https", "http"} {
				t.Run(scheme, func(t *testing.T) {
					t.Run("reuse-across-incoming-requests", func(t *testing.T) {
						transport := &http.Transport{MaxConnsPerHost: 1}
						defer transport.CloseIdleConnections()
						client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
						peer := ""
						for range 3 {
							traceID := fmt.Sprintf("%032x", time.Now().UnixNano())
							observations, err := requestRequestsSource(client, traceID, scheme, "", 1, false)
							require.NoError(t, err)
							require.Len(t, observations, 1)
							observation := observations[0]
							if peer == "" {
								peer = observation.Peer
							}
							require.Equal(t, peer, observation.Peer, "Session connection changed between incoming requests")
							checkRequestsObservation(t, observation, propagation == "headers", "")
							if propagation == "headers" {
								checkRequestsParentage(t, traceID, observation)
							}
						}
					})
					t.Run("reuse", func(t *testing.T) {
						traceID := fmt.Sprintf("%032x", time.Now().UnixNano())
						observations := callRequestsSource(t, traceID, scheme, "", 3, false)
						require.Len(t, observations, 3)
						spans := map[string]bool{}
						for _, observation := range observations {
							require.Equal(t, observations[0].Peer, observation.Peer, "Session connection was not reused")
							checkRequestsObservation(t, observation, propagation == "headers", "")
							if propagation == "headers" {
								checkRequestsParentage(t, traceID, observation)
								require.False(t, spans[observation.Downstream.ParentID], "client span was reused")
								spans[observation.Downstream.ParentID] = true
							}
						}
					})
					for _, owned := range []string{"valid", "invalid"} {
						t.Run("application-"+owned, func(t *testing.T) {
							observations := callRequestsSource(t, fmt.Sprintf("%032x", time.Now().UnixNano()), scheme, owned, 2, false)
							require.Len(t, observations, 2)
							for _, observation := range observations {
								checkRequestsObservation(t, observation, propagation == "headers", owned)
							}
						})
					}
					t.Run("concurrent-incoming-requests", func(t *testing.T) {
						const count = 4
						var wg sync.WaitGroup
						observations := make([][]requestsObservation, count)
						errors := make([]error, count)
						traceIDs := make([]string, count)
						start := make(chan struct{})
						client := &http.Client{Timeout: 30 * time.Second}
						for index := range count {
							traceIDs[index] = fmt.Sprintf("%032x", time.Now().UnixNano()+int64(index))
							wg.Go(func() {
								<-start
								observations[index], errors[index] = requestRequestsSource(client, traceIDs[index], scheme, "", 2, true)
							})
						}
						close(start)
						wg.Wait()
						concurrent := false
						for index, result := range observations {
							require.NoError(t, errors[index])
							require.Len(t, result, 2)
							for _, observation := range result {
								concurrent = concurrent || observation.Active > 1
								checkRequestsObservation(t, observation, propagation == "headers", "")
								if propagation == "headers" {
									checkRequestsParentage(t, traceIDs[index], observation)
								}
							}
						}
						require.True(t, concurrent, "proxy did not observe overlapping incoming requests")
					})
				})
			}
		})
	}
}

func callRequestsSource(t *testing.T, traceID, scheme, owned string, count int, concurrent bool) []requestsObservation {
	t.Helper()
	client := &http.Client{Timeout: 30 * time.Second}
	observations, err := requestRequestsSource(client, traceID, scheme, owned, count, concurrent)
	require.NoError(t, err)
	return observations
}

func requestRequestsSource(client *http.Client, traceID, scheme, owned string, count int, concurrent bool) ([]requestsObservation, error) {
	query := url.Values{
		"case":       {traceID},
		"scheme":     {scheme},
		"owned":      {owned},
		"count":      {strconv.Itoa(count)},
		"concurrent": {strconv.FormatBool(concurrent)},
	}
	req, err := http.NewRequest(http.MethodGet, requestsSourceURL+"/call?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("traceparent", "00-"+traceID+"-eeeeeeeeeeeeeeee-01")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("source returned status %d: %s", resp.StatusCode, body)
	}
	var observations []requestsObservation
	err = json.NewDecoder(resp.Body).Decode(&observations)
	return observations, err
}

func checkRequestsObservation(t *testing.T, observation requestsObservation, enabled bool, owned string) {
	t.Helper()
	require.Equal(t, "HTTP/1.1", observation.HTTPVersion)
	require.Equal(t, "POST", observation.Method)
	require.Equal(t, "/observe?case="+url.QueryEscape(observation.CaseID), observation.Path)
	require.Equal(t, "70726570617265642d626f64793a00ff0d0a656e64", observation.BodyHex)
	require.Equal(t, observation.BodyHex, observation.PreparedBodyHex)
	headers := http.Header{}
	for name, value := range observation.Headers {
		headers.Set(name, value)
	}
	for _, name := range []string{"Authorization", "Cookie", "X-Session", "X-Unrelated", "X-Case-ID", "Content-Length"} {
		require.NotEmpty(t, observation.PreparedBefore[name], name)
		require.Equal(t, observation.PreparedBefore[name], observation.PreparedAfter[name], name)
		require.Equal(t, observation.PreparedBefore[name], headers.Get(name), name)
	}
	if owned != "" {
		expected := requestsOwnedTraceparent
		if owned == "invalid" {
			expected = "application-owned-invalid-value"
		}
		require.Equal(t, []string{expected}, observation.Traceparents)
		return
	}
	if !enabled {
		require.Empty(t, observation.Traceparents)
		require.Equal(t, "0000000000000000", observation.Downstream.ParentID)
		return
	}
	require.Len(t, observation.Traceparents, 1, "proxy must see exactly one transmitted traceparent")
	parts := strings.Split(observation.Traceparents[0], "-")
	require.Len(t, parts, 4)
	require.Equal(t, "00", parts[0])
	require.Equal(t, "01", parts[3])
	require.Equal(t, observation.Downstream.TraceID, parts[1])
	require.Equal(t, observation.Downstream.ParentID, parts[2])
}

func checkRequestsParentage(t *testing.T, traceID string, observation requestsObservation) {
	t.Helper()
	require.Equal(t, traceID, observation.Downstream.TraceID)
	var trace jaeger.Trace
	var server jaeger.Span
	var clientParent jaeger.Span
	var client, downstream *jaeger.Span
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := getJaeger(requestsJaegerURL + "/" + traceID)
		require.NoError(ct, err)
		defer resp.Body.Close()
		var result jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&result))
		require.Len(ct, result.Data, 1)
		trace = result.Data[0]
		servers := trace.FindByOperationNameServiceAndKind("GET /call", "requests-source", "server")
		require.Len(ct, servers, 1)
		server = servers[0]
		client, downstream = nil, nil
		for index := range trace.Spans {
			span := &trace.Spans[index]
			if span.SpanID == observation.Downstream.ParentID {
				client = span
			}
			if span.SpanID == observation.Downstream.SpanID {
				downstream = span
			}
		}
		require.NotNil(ct, client, "transmitted parent must be an exported OBI client span")
		require.NotNil(ct, downstream)
		var found bool
		clientParent, found = trace.ParentOf(client)
		require.True(ct, found, "source client parent must be exported")
	}, time.Minute, 250*time.Millisecond)
	assert.Equal(t, []jaeger.Reference{{RefType: "CHILD_OF", TraceID: traceID, SpanID: "eeeeeeeeeeeeeeee"}}, server.References)
	require.Equal(t, "requests-source", trace.Processes[client.ProcessID].ServiceName)
	kind, found := jaeger.FindIn(client.Tags, "span.kind")
	require.True(t, found)
	require.Equal(t, "client", kind.Value)
	assert.Equal(t, []jaeger.Reference{{RefType: "CHILD_OF", TraceID: traceID, SpanID: clientParent.SpanID}},
		client.References)
	if clientParent.SpanID != server.SpanID {
		require.Equal(t, "requests-source", trace.Processes[clientParent.ProcessID].ServiceName)
		require.Equal(t, "processing", clientParent.OperationName)
		kind, found := jaeger.FindIn(clientParent.Tags, "span.kind")
		require.True(t, found)
		require.Equal(t, "internal", kind.Value)
		assert.Equal(t, []jaeger.Reference{{RefType: "CHILD_OF", TraceID: traceID, SpanID: server.SpanID}},
			clientParent.References, "processing span must parent to source server")
	}
	require.Equal(t, "requests-downstream", trace.Processes[downstream.ProcessID].ServiceName)
	assert.Equal(t, []jaeger.Reference{{RefType: "CHILD_OF", TraceID: traceID, SpanID: client.SpanID}},
		downstream.References, "downstream server must parent to source client")
}
