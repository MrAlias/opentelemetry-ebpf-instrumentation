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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
	"go.opentelemetry.io/obi/internal/test/integration/components/jaeger"
)

const apacheConcurrentRequests = 4

func TestJavaApacheHTTPClientTraceparent(t *testing.T) {
	for _, mode := range []string{"headers", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			compose, err := docker.ComposeSuite("docker-compose-java-apache-httpclient.yml",
				path.Join(pathOutput, "test-suite-java-apache-httpclient-"+mode+".log"))
			require.NoError(t, err)
			compose.Env = append(compose.Env, "JAVA_HTTPCLIENT_PROPAGATION="+mode, "COMPOSE_PROJECT_NAME=obi-apache-httpclient", "OTEL_EBPF_EXECUTABLE_PATH=", "OTEL_EBPF_OPEN_PORT=")
			t.Cleanup(func() { assert.NoError(t, compose.Close()) })
			require.NoError(t, compose.Up())
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				response, err := http.Get("http://localhost:24180/health")
				require.NoError(ct, err)
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				require.NoError(ct, err)
				require.NotEmpty(ct, body, "OBI Java agent has not attached")
			}, 2*time.Minute, time.Second)

			run := fmt.Sprintf("apache-%s-%d", mode, time.Now().UnixNano())
			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				response, err := http.Post("http://localhost:24180/call/"+run+"-warmup-"+strconv.FormatInt(time.Now().UnixNano(), 10), "text/plain", strings.NewReader("warmup"))
				require.NoError(ct, err)
				require.NoError(ct, response.Body.Close())
				require.Equal(ct, http.StatusOK, response.StatusCode)
				trace, err := apacheHTTPClientTrace("java-apache-httpclient", "")
				require.NoError(ct, err)
				require.NotEmpty(ct, trace.TraceID, "Java TLS instrumentation is not ready")
			}, 2*time.Minute, time.Second)

			t.Run("generated", func(t *testing.T) {
				testJavaApacheTraceparent(t, run+"-generated", "11111111111111111111111111111111", "", mode)
			})
			t.Run("pooled-distinct-parents", func(t *testing.T) {
				first := testJavaApacheTraceparent(t, run+"-pool-first", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", mode)
				second := testJavaApacheTraceparent(t, run+"-pool-second", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "", mode)
				require.Equal(t, first.Connection, second.Connection, "requests must reuse the same TLS connection")
			})
			t.Run("application-owned", func(t *testing.T) {
				testJavaApacheTraceparent(t, run+"-owned", "22222222222222222222222222222222", javaApplicationTraceparent, mode)
			})
			t.Run("concurrent", func(t *testing.T) {
				testJavaApacheConcurrentContexts(t, run, mode)
			})
		})
	}
}

type apacheProxyObservation struct {
	javaProxyObservation
	Unrelated  string `json:"unrelated"`
	Tracestate string `json:"tracestate"`
}

func testJavaApacheTraceparent(t *testing.T, id, traceID, owned, mode string) apacheProxyObservation {
	t.Helper()
	require.NoError(t, sendJavaApacheRequest(id, traceID, owned))
	return assertJavaApacheTraceparent(t, id, traceID, owned, mode)
}

func testJavaApacheConcurrentContexts(t *testing.T, run, mode string) {
	t.Helper()
	results := make(chan error, apacheConcurrentRequests)
	for i := range apacheConcurrentRequests {
		go func() {
			results <- sendJavaApacheRequest(fmt.Sprintf("%s-concurrent-%d", run, i), fmt.Sprintf("%032x", 0x100+i), "")
		}()
	}
	for range apacheConcurrentRequests {
		require.NoError(t, <-results)
	}
	for i := range apacheConcurrentRequests {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			assertJavaApacheTraceparent(t, fmt.Sprintf("%s-concurrent-%d", run, i), fmt.Sprintf("%032x", 0x100+i), "", mode)
		})
	}
}

func apacheRequestBody(id string) string {
	return "body-preserved-" + id + "\r\ntraceparent: body-content\r\n\r\n"
}

func sendJavaApacheRequest(id, traceID, owned string) error {
	body := apacheRequestBody(id)
	request, err := http.NewRequest(http.MethodPost, "http://localhost:24180/call/"+id, strings.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("traceparent", "00-"+traceID+"-"+traceID[16:]+"-01")
	if owned != "" {
		request.Header.Set("X-Application-Traceparent", owned)
	}
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("apache source returned %d: %s", response.StatusCode, responseBody)
	}
	if string(responseBody) != body {
		return fmt.Errorf("request body was not preserved for %s: %q", id, responseBody)
	}
	return nil
}

func assertJavaApacheTraceparent(t *testing.T, id, traceID, owned, mode string) apacheProxyObservation {
	t.Helper()
	parentID := traceID[16:]
	response, err := http.Get("http://localhost:24182/records/" + id)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusOK, response.StatusCode)
	var records []apacheProxyObservation
	require.NoError(t, json.NewDecoder(response.Body).Decode(&records))
	require.Len(t, records, 1, "exactly one request must reach the TLS proxy")
	record := records[0]
	t.Logf("TLS proxy: path=/%s observation=%+v", id, record)
	require.Equal(t, 1, record.Protocol)
	require.Equal(t, apacheRequestBody(id), record.Body)
	require.Equal(t, "preserved", record.Unrelated)
	require.Equal(t, "vendor=value", record.Tracestate)
	switch {
	case owned != "":
		require.Equal(t, []string{owned}, record.Headers)
	case mode == "disabled":
		require.Empty(t, record.Headers)
	default:
		require.Len(t, record.Headers, 1, "exactly one traceparent must be transmitted")
		require.Regexp(t, `^00-[0-9a-f]{32}-[0-9a-f]{16}-01$`, record.Headers[0])
		require.Equal(t, traceID, strings.Split(record.Headers[0], "-")[1])
	}

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		source, err := apacheHTTPClientTrace("java-apache-httpclient", "POST /call/"+id)
		require.NoError(ct, err)
		require.Equal(ct, traceID, source.TraceID)
		servers := source.FindByOperationNameServiceAndKind("POST /call/"+id, "java-apache-httpclient", "server")
		require.Len(ct, servers, 1)
		require.Contains(ct, servers[0].References, jaeger.Reference{RefType: "CHILD_OF", TraceID: traceID, SpanID: parentID})
		downstream, err := apacheHTTPClientTrace("apache-downstream", "POST /"+id)
		require.NoError(ct, err)
		downstreamServers := downstream.FindByOperationNameServiceAndKind("POST /"+id, "apache-downstream", "server")
		require.Len(ct, downstreamServers, 1)
		if owned != "" {
			parts := strings.Split(owned, "-")
			require.Equal(ct, parts[1], downstream.TraceID)
			require.Contains(ct, downstreamServers[0].References, jaeger.Reference{RefType: "CHILD_OF", TraceID: parts[1], SpanID: parts[2]})
			return
		}
		clients := source.FindByOperationNameServiceAndKind("POST /"+id, "java-apache-httpclient", "client")
		require.Len(ct, clients, 1)
		parent, ok := source.ParentOf(&clients[0])
		require.True(ct, ok, "source client must have an exported parent")
		if parent.SpanID != servers[0].SpanID {
			require.Equal(ct, "processing", parent.OperationName)
			require.Equal(ct, servers[0].ProcessID, parent.ProcessID)
			kind, ok := jaeger.FindIn(parent.Tags, "span.kind")
			require.True(ct, ok)
			require.Equal(ct, "internal", kind.Value)
			require.Contains(ct, parent.References, jaeger.Reference{RefType: "CHILD_OF", TraceID: traceID, SpanID: servers[0].SpanID})
		}
		require.Contains(ct, clients[0].References, jaeger.Reference{RefType: "CHILD_OF", TraceID: traceID, SpanID: parent.SpanID})
		if mode == "disabled" {
			require.NotEqual(ct, traceID, downstream.TraceID)
			return
		}
		parts := strings.Split(record.Headers[0], "-")
		require.Equal(ct, clients[0].SpanID, parts[2])
		require.Equal(ct, traceID, downstream.TraceID)
		require.Contains(ct, downstreamServers[0].References, jaeger.Reference{RefType: "CHILD_OF", TraceID: traceID, SpanID: clients[0].SpanID})
		t.Logf("span chain: trace=%s server=%s client_parent=%s client=%s downstream=%s", traceID, servers[0].SpanID, parent.SpanID, clients[0].SpanID, downstreamServers[0].SpanID)
	}, time.Minute, time.Second)
	return record
}

func apacheHTTPClientTrace(service, operation string) (jaeger.Trace, error) {
	query := url.Values{"service": {service}, "limit": {"50"}}
	if operation != "" {
		query.Set("operation", operation)
	}
	response, err := getJaeger("http://localhost:24186/api/traces?" + query.Encode())
	if err != nil {
		return jaeger.Trace{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return jaeger.Trace{}, fmt.Errorf("jaeger query returned %d", response.StatusCode)
	}
	var traces jaeger.TracesQuery
	if err := json.NewDecoder(response.Body).Decode(&traces); err != nil {
		return jaeger.Trace{}, err
	}
	for _, trace := range traces.Data {
		if operation != "" || len(clientSpans(trace)) > 0 {
			return trace, nil
		}
	}
	return jaeger.Trace{}, nil
}
