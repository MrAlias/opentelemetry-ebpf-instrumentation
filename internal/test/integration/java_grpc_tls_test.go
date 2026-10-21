// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
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

type javaGRPCObservation struct {
	CaseID          string   `json:"case_id"`
	Traceparents    []string `json:"traceparents"`
	TraceID         string   `json:"trace_id"`
	SpanID          string   `json:"span_id"`
	ParentID        string   `json:"parent_id"`
	ProxyConnection []string `json:"proxy_connection"`
	MaxActive       int      `json:"max_active"`
}

func TestSuite_JavaGRPCTLS(t *testing.T) {
	if KernelLockdownMode() {
		t.Skip("Java metadata injection requires bpf_probe_write_user")
	}
	for _, enabled := range []bool{true, false} {
		t.Run(fmt.Sprintf("propagation=%t", enabled), func(t *testing.T) {
			compose, err := docker.ComposeSuite("docker-compose-java-grpc-tls.yml",
				path.Join(pathOutput, fmt.Sprintf("java-grpc-tls-%t.log", enabled)))
			require.NoError(t, err)
			propagation := "disabled"
			if enabled {
				propagation = "headers"
			}
			compose.Env = append(compose.Env, "JAVA_GRPC_PROPAGATION="+propagation)
			t.Cleanup(func() { require.NoError(t, compose.Close()) })
			require.NoError(t, compose.Up())
			waitForTestComponentsNoMetrics(t, "http://localhost:18086/health")
			require.Eventually(t, func() bool {
				resp, err := http.Get("http://localhost:18086/health")
				if err == nil {
					resp.Body.Close()
				}
				return hasSpansInJaeger("java-grpc-source")
			}, time.Minute, time.Second)

			// Establish the shared channel once before testing stream ownership.
			firstTraceID := strings.Repeat("1", 32)
			first, err := javaGRPCCall("first", firstTraceID, "")
			require.NoError(t, err)
			if enabled {
				require.Len(t, first.Traceparents, 1)
				require.Equal(t, firstTraceID, first.TraceID)
				assertJavaGRPCParentage(t, firstTraceID, first)
			} else {
				require.Empty(t, first.Traceparents)
			}
			var observations []javaGRPCObservation
			var traceIDs []string
			for i := range 3 {
				id := fmt.Sprintf("aabbccddeeff0011%016x", uint64(time.Now().UnixNano())+uint64(i))
				observed, err := javaGRPCCall(fmt.Sprintf("repeat-%d", i), id, "")
				require.NoError(t, err)
				observations = append(observations, observed)
				traceIDs = append(traceIDs, id)
			}
			for _, supplied := range []string{grpcOwnedTraceparent, grpcInvalidOwnedTraceparent, grpcOwnedTraceparent} {
				observed, err := javaGRPCCall("application", strings.Repeat("2", 32), supplied)
				require.NoError(t, err)
				require.Equal(t, []string{supplied}, observed.Traceparents)
				t.Logf("application metadata=%v downstream_trace=%s parent=%s", observed.Traceparents, observed.TraceID, observed.ParentID)
				if supplied == grpcOwnedTraceparent {
					require.Equal(t, strings.Repeat("3", 32), observed.TraceID)
					require.Equal(t, strings.Repeat("4", 16), observed.ParentID)
				} else {
					require.Equal(t, strings.Repeat("0", 16), observed.ParentID)
				}
			}
			// A supplied field must not disable propagation for other streams on this connection.
			const concurrent = 8
			batch := make([]javaGRPCObservation, concurrent)
			batchIDs := make([]string, concurrent)
			errors := make([]error, concurrent)
			var wg sync.WaitGroup
			start := make(chan struct{})
			base := uint64(time.Now().UnixNano())
			for i := range concurrent {
				batchIDs[i] = fmt.Sprintf("aabbccddeeff0022%016x", base+uint64(i))
				wg.Go(func() {
					<-start
					caseID := fmt.Sprintf("concurrent-%d", i)
					supplied := ""
					switch i % 4 {
					case 0:
						caseID = "owned-" + caseID
						supplied = grpcOwnedTraceparent
					case 1:
						caseID = "invalid-" + caseID
						supplied = grpcInvalidOwnedTraceparent
					}
					batch[i], errors[i] = javaGRPCCall(caseID, batchIDs[i], supplied)
				})
			}
			close(start)
			wg.Wait()
			for _, err := range errors {
				require.NoError(t, err)
			}
			observations = append(observations, batch...)
			traceIDs = append(traceIDs, batchIDs...)
			connection := observations[0].ProxyConnection
			require.Len(t, connection, 1)
			require.Equal(t, first.ProxyConnection, connection)
			maxActive := 0
			parents := map[string]bool{}
			for i, observed := range observations {
				t.Logf("metadata case=%s traceparents=%v proxy_connection=%v downstream_parent=%s", observed.CaseID, observed.Traceparents, observed.ProxyConnection, observed.ParentID)
				require.Equal(t, connection, observed.ProxyConnection, "all RPCs must reuse one TLS connection")
				maxActive = max(maxActive, observed.MaxActive)
				if strings.HasPrefix(observed.CaseID, "owned-") {
					require.Equal(t, []string{grpcOwnedTraceparent}, observed.Traceparents)
					require.Equal(t, strings.Repeat("3", 32), observed.TraceID)
					require.Equal(t, strings.Repeat("4", 16), observed.ParentID)
					continue
				}
				if strings.HasPrefix(observed.CaseID, "invalid-") {
					require.Equal(t, []string{grpcInvalidOwnedTraceparent}, observed.Traceparents)
					require.Equal(t, strings.Repeat("0", 16), observed.ParentID)
					continue
				}
				if !enabled {
					require.Empty(t, observed.Traceparents)
					require.NotEqual(t, traceIDs[i], observed.TraceID)
					require.Equal(t, strings.Repeat("0", 16), observed.ParentID)
					continue
				}
				require.Len(t, observed.Traceparents, 1)
				fields := strings.Split(observed.Traceparents[0], "-")
				require.Len(t, fields, 4)
				require.Equal(t, traceIDs[i], fields[1])
				require.Equal(t, traceIDs[i], observed.TraceID)
				require.Equal(t, fields[2], observed.ParentID)
				require.False(t, parents[observed.ParentID], "RPCs must own distinct client spans")
				parents[observed.ParentID] = true
				assertJavaGRPCParentage(t, traceIDs[i], observed)
			}
			require.Greater(t, maxActive, 1, "RPCs must overlap on the shared connection")
			logs, err := compose.LogsOutput("source")
			require.NoError(t, err)
			t.Log(logs)
		})
	}
}

func javaGRPCCall(caseID, traceID, supplied string) (javaGRPCObservation, error) {
	endpoint := "http://localhost:18086/call"
	if supplied != "" {
		endpoint += "?app=" + url.QueryEscape(supplied)
	}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return javaGRPCObservation{}, err
	}
	req.Header.Set("traceparent", "00-"+traceID+"-eeeeeeeeeeeeeeee-01")
	req.Header.Set("x-case-id", caseID)
	client := http.Client{Timeout: 70 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return javaGRPCObservation{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return javaGRPCObservation{}, fmt.Errorf("RPC HTTP status %d", resp.StatusCode)
	}
	var observation javaGRPCObservation
	err = json.NewDecoder(resp.Body).Decode(&observation)
	if err == nil && observation.CaseID != caseID {
		err = fmt.Errorf("response for %q, want %q", observation.CaseID, caseID)
	}
	return observation, err
}

func assertJavaGRPCParentage(t *testing.T, id string, observed javaGRPCObservation) {
	t.Helper()
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		traces, err := fetchTrace(id)
		require.NoError(ct, err)
		require.Len(ct, traces.Data, 1)
		tr := traces.Data[0]
		var downstream, client, server []jaeger.Span
		for _, span := range tr.Spans {
			service := tr.Processes[span.ProcessID].ServiceName
			kind, _ := jaeger.FindIn(span.Tags, "span.kind")
			if service == "java-grpc-downstream" && span.SpanID == observed.SpanID {
				downstream = append(downstream, span)
			}
			if service == "java-grpc-source" && kind.Value == "client" {
				client = append(client, span)
			}
			if service == "java-grpc-source" && kind.Value == "server" {
				server = append(server, span)
			}
		}
		require.Len(ct, downstream, 1)
		require.Len(ct, client, 1)
		require.Len(ct, server, 1)
		require.Equal(ct, observed.ParentID, client[0].SpanID)
		parent, ok := tr.ParentOf(&downstream[0])
		require.True(ct, ok)
		require.Equal(ct, client[0].SpanID, parent.SpanID)
		parent, ok = tr.ParentOf(&client[0])
		require.True(ct, ok)
		visited := map[string]bool{}
		for parent.SpanID != server[0].SpanID {
			require.False(ct, visited[parent.SpanID], "cycle in source span ancestry")
			visited[parent.SpanID] = true
			require.Equal(ct, "java-grpc-source", tr.Processes[parent.ProcessID].ServiceName)
			kind, _ := jaeger.FindIn(parent.Tags, "span.kind")
			require.Equal(ct, "internal", kind.Value)
			parent, ok = tr.ParentOf(&parent)
			require.True(ct, ok, "client must descend from the source server")
		}
		require.Contains(ct, server[0].References, jaeger.Reference{RefType: "CHILD_OF", TraceID: id, SpanID: "eeeeeeeeeeeeeeee"})
	}, testTimeout, time.Second)
}
