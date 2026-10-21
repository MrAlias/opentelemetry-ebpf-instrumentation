// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
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

type undiciObservation struct {
	ID                     string            `json:"id"`
	Traceparents           []string          `json:"traceparents"`
	Connection             int               `json:"connection"`
	Protocol               string            `json:"protocol"`
	Preserved              string            `json:"preserved"`
	Body                   string            `json:"body"`
	DispatcherUnchanged    bool              `json:"dispatcherUnchanged"`
	DownstreamTraceID      string            `json:"downstreamTraceID"`
	DownstreamSpanID       string            `json:"downstreamSpanID"`
	DownstreamParentSpanID string            `json:"downstreamParentSpanID"`
	Versions               map[string]string `json:"versions"`
}

func TestNodeUndiciHTTPSPropagation(t *testing.T) {
	for _, propagation := range []string{"headers", "disabled"} {
		t.Run(propagation, func(t *testing.T) {
			require.NoError(t, runUndiciSuite(t, propagation))
		})
	}
}

func runUndiciSuite(t *testing.T, propagation string) error {
	t.Helper()
	compose, err := docker.ComposeSuite("docker-compose-node-undici.yml", path.Join(pathOutput, "node-undici-"+propagation+".log"))
	if err != nil {
		return err
	}
	compose.Env = append(compose.Env, "UNDICI_PROPAGATION="+propagation,
		"COMPOSE_PROJECT_NAME=obi-node-undici-"+propagation+"-"+strconv.Itoa(os.Getpid()))
	t.Cleanup(func() { assert.NoError(t, compose.Close()) })
	if err := compose.Up(); err != nil {
		return err
	}
	sourceURL := undiciPublishedURL(t, compose, "source", "8080")
	jaegerURL := undiciPublishedURL(t, compose, "jaeger", "16686")
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		request, err := http.NewRequest(http.MethodGet, sourceURL+"/smoke", nil)
		require.NoError(ct, err)
		request.Close = true
		resp, err := http.DefaultClient.Do(request)
		require.NoError(ct, err)
		defer resp.Body.Close()
		require.Equal(ct, http.StatusOK, resp.StatusCode)
		logs, err := compose.LogsTail(100, "obi")
		require.NoError(ct, err)
		require.Contains(ct, logs, "Script successfully injected")
	}, testTimeout, time.Second)

	// Sequential waves use the same global Agent, with overlapping request contexts
	// within each wave. No dispatcher override or replacement is installed by the app.
	connections := map[int]bool{}
	type traceExpectation struct {
		traceID, parentID, clientID, downstreamID string
	}
	var expected []traceExpectation
	headerModes := []string{"object", "flat", "iterable", "headers"}
	const waveSize = 8
	for wave := range 3 {
		observations := make([]undiciObservation, waveSize)
		traces := make([]string, waveSize)
		parents := make([]string, waveSize)
		t.Run(fmt.Sprintf("wave-%d", wave), func(t *testing.T) {
			for i := range waveSize {
				t.Run(strconv.Itoa(i), func(t *testing.T) {
					t.Parallel()
					id := wave*waveSize + i + 1
					traceID := fmt.Sprintf("%032x", id)
					parentID := fmt.Sprintf("%016x", id+100)
					traces[i], parents[i] = traceID, parentID
					mode := headerModes[i%len(headerModes)]
					observations[i] = callUndici(t, sourceURL, id, mode, "", traceID, parentID, (wave+i)%2 == 0)
				})
			}
		})
		for i, observed := range observations {
			connections[observed.Connection] = true
			t.Logf("%s wave=%d id=%s connection=%d headers=%v versions=%v", propagation, wave, observed.ID, observed.Connection, observed.Traceparents, observed.Versions)
			if propagation == "headers" {
				require.Len(t, observed.Traceparents, 1, "exactly one traceparent on the TLS wire")
				parts := strings.Split(observed.Traceparents[0], "-")
				require.Len(t, parts, 4)
				require.Equal(t, traces[i], parts[1])
				require.Equal(t, traces[i], observed.DownstreamTraceID)
				require.Equal(t, parts[2], observed.DownstreamParentSpanID)
				expected = append(expected, traceExpectation{traces[i], parents[i], parts[2], observed.DownstreamSpanID})
			} else {
				require.Empty(t, observed.Traceparents)
				require.NotEqual(t, traces[i], observed.DownstreamTraceID)
			}
		}
	}
	require.Less(t, len(connections), 3*waveSize, "the global dispatcher must reuse TLS connections")
	for _, trace := range expected {
		assertUndiciTrace(t, jaegerURL, trace.traceID, trace.parentID, trace.clientID, trace.downstreamID)
	}

	existing := "00-abcdefabcdefabcdefabcdefabcdefab-1234567890abcdef-01"
	for i, mode := range headerModes {
		observed := callUndici(t, sourceURL, 100+i, mode, existing, fmt.Sprintf("%032x", 100+i), "0123456789abcdef", false)
		require.Equal(t, []string{existing}, observed.Traceparents, "preserve an application's traceparent without duplication")
		require.Equal(t, "abcdefabcdefabcdefabcdefabcdefab", observed.DownstreamTraceID)
		require.Equal(t, "1234567890abcdef", observed.DownstreamParentSpanID)
	}
	t.Logf("verified %s: %d requests, %d pooled connections, %d existing-header cases", propagation, 3*waveSize, len(connections), len(headerModes))
	return nil
}

func callUndici(t *testing.T, sourceURL string, id int, mode, existing, traceID, parentID string, stream bool) undiciObservation {
	t.Helper()
	query := url.Values{"id": {strconv.Itoa(id)}, "headers": {mode}}
	if existing != "" {
		query.Set("existing", existing)
	}
	if stream {
		query.Set("stream", "1")
	}
	body := []byte("request-body-\x00-π-" + strconv.Itoa(id))
	req, err := http.NewRequest(http.MethodPost, sourceURL+"/request?"+query.Encode(), bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("traceparent", "00-"+traceID+"-"+parentID+"-01")
	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(data))
	var observed undiciObservation
	require.NoError(t, json.Unmarshal(data, &observed))
	require.Equal(t, strconv.Itoa(id), observed.ID)
	require.Equal(t, "1.1", observed.Protocol)
	require.Equal(t, "yes", observed.Preserved)
	require.Equal(t, base64.StdEncoding.EncodeToString(body), observed.Body)
	require.True(t, observed.DispatcherUnchanged)
	return observed
}

func assertUndiciTrace(t *testing.T, jaegerURL, traceID, incomingParent, clientID, downstreamID string) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		resp, err := getJaeger(jaegerURL + "/api/traces/" + traceID)
		require.NoError(ct, err)
		defer resp.Body.Close()
		var query jaeger.TracesQuery
		require.NoError(ct, json.NewDecoder(resp.Body).Decode(&query))
		require.Len(ct, query.Data, 1)
		trace := query.Data[0]
		servers := trace.FindByOperationNameServiceAndKind("POST /request", "undici-source", "server")
		require.Len(ct, servers, 1)
		require.Contains(ct, servers[0].References, jaeger.Reference{RefType: "CHILD_OF", TraceID: traceID, SpanID: incomingParent})
		clients := trace.FindByOperationNameServiceAndKind("POST /echo", "undici-source", "client")
		require.Len(ct, clients, 1)
		require.Equal(ct, clientID, clients[0].SpanID, "wire span ID must identify the source client span")
		parent, ok := trace.ParentOf(&clients[0])
		require.True(ct, ok)
		if parent.OperationName == "processing" {
			parent, ok = trace.ParentOf(&parent)
			require.True(ct, ok)
		}
		require.Equal(ct, servers[0].SpanID, parent.SpanID)
		var downstream []jaeger.Span
		for _, span := range trace.Spans {
			if span.SpanID == downstreamID {
				downstream = append(downstream, span)
			}
		}
		require.Len(ct, downstream, 1)
		require.Equal(ct, "undici-downstream", trace.Processes[downstream[0].ProcessID].ServiceName)
		parent, ok = trace.ParentOf(&downstream[0])
		require.True(ct, ok)
		require.Equal(ct, clients[0].SpanID, parent.SpanID)
		for _, process := range trace.Processes {
			require.NotEqual(ct, "proxy", process.ServiceName)
		}
	}, testTimeout, 100*time.Millisecond)
}

func undiciPublishedURL(t *testing.T, compose *docker.Compose, service, port string) string {
	t.Helper()
	command := exec.Command("docker", "compose", "-f", compose.Path, "port", service, port)
	command.Env = compose.Env
	output, err := command.CombinedOutput()
	require.NoError(t, err, "%s", output)
	return "http://" + strings.TrimSpace(string(output))
}
