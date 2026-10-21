// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package appolly

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/pipe/msg"
)

func dotnetHTTPSpans() (request.Span, request.Span, request.Span, request.Span) {
	server := request.Span{
		Type: request.EventTypeHTTP, ProtoVersion: request.ProtoVersionHTTP11,
		Service: svc.Attrs{SDKLanguage: svc.InstrumentableDotnet},
		TraceID: testTrace, SpanID: parentSpan, ParentSpanID: trace.SpanID{9},
		Start: 100, RequestStart: 100, End: 200,
		Host: "127.0.0.1", HostPort: 8080, Peer: "127.0.0.1", PeerPort: 50000,
		Method: "GET", Path: "/send",
	}
	server.Service.SDKLanguage = svc.InstrumentableDotnet
	nativeServer := server
	nativeServer.DotnetHTTPContext = true
	nativeServer.SpanID = trace.SpanID{2}
	nativeServer.Start, nativeServer.RequestStart, nativeServer.End = 110, 110, 110
	nativeClient := nativeServer
	nativeClient.Type = request.EventTypeHTTPClient
	nativeClient.SpanID = trace.SpanID{3}
	nativeClient.ParentSpanID = nativeServer.SpanID
	client := server
	client.Type = request.EventTypeHTTPClient
	client.SpanID = childSpan
	client.ParentSpanID = trace.SpanID{}
	client.Statement = "https" + request.SchemeHostSeparator + "proxy:8443"
	client.WireTraceContext = trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: testTrace, SpanID: nativeClient.SpanID, TraceFlags: trace.FlagsSampled,
	})
	nativeClient.WireTraceContext = client.WireTraceContext
	nativeClient.Statement = client.Statement
	nativeClient.Start, nativeClient.RequestStart, nativeClient.End = 120, 120, 180
	nativeClient.TraceFlags = 1
	return server, nativeServer, client, nativeClient
}

func dotnetHTTPTestResolver() (*dotnetHTTPResolver, <-chan []request.Span) {
	output := msg.NewQueue[[]request.Span](msg.ChannelBufferLen(32))
	return newDotnetHTTPResolver(time.Second, time.Second, output), output.Subscribe()
}

func drainDotnetHTTP(out <-chan []request.Span) []request.Span {
	var result []request.Span
	for {
		select {
		case batch := <-out:
			for _, span := range batch {
				if !request.IgnoreTraces(&span) {
					result = append(result, span)
				}
			}
		default:
			return result
		}
	}
}

func TestDotnetHTTPAllArrivalOrders(t *testing.T) {
	server, nativeServer, client, nativeClient := dotnetHTTPSpans()
	spans := []request.Span{server, nativeServer, client, nativeClient}
	for a := range spans {
		for b := range spans {
			for c := range spans {
				for d := range spans {
					if a == b || a == c || a == d || b == c || b == d || c == d {
						continue
					}
					r, out := dotnetHTTPTestResolver()
					for _, index := range []int{a, b, c, d} {
						r.process(context.Background(), []request.Span{spans[index]})
					}
					got := drainDotnetHTTP(out)
					require.Len(t, got, 2, "%v", []int{a, b, c, d})
					for _, span := range got {
						if span.Type == request.EventTypeHTTP {
							require.Equal(t, server, span, "preserve server IDs and metrics")
						} else {
							require.Equal(t, nativeClient.SpanID, span.SpanID)
							require.Equal(t, server.SpanID, span.ParentSpanID)
							require.Equal(t, uint8(1), span.TraceFlags)
							require.False(t, span.ParentConditional)
						}
					}
					require.Empty(t, r.pending)
					require.Empty(t, r.parents)
				}
			}
		}
	}
}

func TestDotnetHTTPReusedConnectionUsesRequestInterval(t *testing.T) {
	server, nativeServer, client, nativeClient := dotnetHTTPSpans()
	r, out := dotnetHTTPTestResolver()
	// Same incoming trace, parent, path, and connection; the second request must
	// not be associated with the first request merely because these match.
	second := server
	second.Start, second.RequestStart, second.End = 300, 300, 400
	second.SpanID = trace.SpanID{4}
	nativeServer.Start, nativeServer.RequestStart = 310, 310
	r.process(context.Background(), []request.Span{server, client, nativeClient, second, nativeServer})
	got := drainDotnetHTTP(out)
	require.Len(t, got, 3)
	require.Equal(t, nativeClient.SpanID, got[2].SpanID)
	require.Equal(t, second.SpanID, got[2].ParentSpanID)
}

func TestDotnetHTTPQueuedServerKeepsProcessingID(t *testing.T) {
	server, nativeServer, client, nativeClient := dotnetHTTPSpans()
	server.Start = 120
	r, out := dotnetHTTPTestResolver()
	r.process(context.Background(), []request.Span{nativeServer, nativeClient, client, server})
	got := drainDotnetHTTP(out)
	require.Len(t, got, 2)
	child, parent := got[0], got[1]
	require.Equal(t, server.SpanID, parent.SpanID)
	require.Equal(t, server.Start, parent.Start)
	require.Equal(t, server.RequestStart, parent.RequestStart)
	require.True(t, parent.ServerSpanID.IsValid())
	require.NotEqual(t, parent.SpanID, parent.ServerSpanID)
	require.Equal(t, parent.ServerSpanID, child.ParentSpanID)
	require.Equal(t, nativeClient.SpanID, child.SpanID)
}

func TestDotnetHTTPDoesNotJoinMismatchedServer(t *testing.T) {
	for _, change := range []func(*request.Span){
		func(s *request.Span) { s.PeerPort++ },
		func(s *request.Span) { s.Pid.Namespace++ },
		func(s *request.Span) { s.Pid.UserPID++ },
		func(s *request.Span) { s.RequestStart = 201 },
		func(s *request.Span) { s.ParentSpanID = trace.SpanID{8} },
	} {
		server, nativeServer, client, nativeClient := dotnetHTTPSpans()
		change(&nativeServer)
		r, out := dotnetHTTPTestResolver()
		r.process(context.Background(), []request.Span{server, nativeServer, client, nativeClient})
		require.Len(t, drainDotnetHTTP(out), 1)
		require.Len(t, r.pending, 1)
		r.expire(context.Background(), time.Time{})
		got := drainDotnetHTTP(out)
		require.Len(t, got, 1)
		require.False(t, got[0].ParentSpanID.IsValid())
		require.Empty(t, r.pending)
		require.Empty(t, r.parents)
	}
}

func TestDotnetHTTPOwnedContextAndOtherProtocols(t *testing.T) {
	server, nativeServer, client, nativeClient := dotnetHTTPSpans()
	client.WireTraceContext = trace.NewSpanContext(trace.SpanContextConfig{TraceID: testTrace, SpanID: trace.SpanID{8}})
	nativeClient.WireTraceContext = client.WireTraceContext
	unrelated := client
	unrelated.Type = request.EventTypeSQLClient
	r, out := dotnetHTTPTestResolver()
	r.process(context.Background(), []request.Span{server, nativeServer, client, nativeClient, unrelated})
	got := drainDotnetHTTP(out)
	require.Len(t, got, 3)
	require.Equal(t, server, got[0])
	require.Equal(t, nativeClient.SpanID, got[1].SpanID)
	require.Equal(t, client.WireTraceContext, got[1].WireTraceContext)
	require.Equal(t, unrelated, got[2])
	r.expire(context.Background(), time.Time{})
	require.Empty(t, drainDotnetHTTP(out))
}

func TestDotnetHTTPEvictionDoesNotKeepUnprovenParent(t *testing.T) {
	_, _, client, nativeClient := dotnetHTTPSpans()
	client.ParentSpanID = trace.SpanID{7}
	r, out := dotnetHTTPTestResolver()
	r.process(context.Background(), []request.Span{nativeClient, client, client})
	got := drainDotnetHTTP(out)
	require.Empty(t, got)
	r.expire(context.Background(), time.Time{})
	got = drainDotnetHTTP(out)
	require.Len(t, got, 1)
	require.Equal(t, nativeClient.SpanID, got[0].SpanID)
	require.False(t, got[0].ParentSpanID.IsValid())
	require.Empty(t, r.pending)
	require.Empty(t, r.parents)
}

func TestDotnetHTTPClientWithoutTransportObservation(t *testing.T) {
	server, nativeServer, _, nativeClient := dotnetHTTPSpans()
	r, out := dotnetHTTPTestResolver()
	r.process(context.Background(), []request.Span{nativeClient, nativeServer, server})
	got := drainDotnetHTTP(out)
	require.Len(t, got, 2)
	require.Equal(t, nativeClient.SpanID, got[0].SpanID)
	require.Equal(t, server.SpanID, got[0].ParentSpanID)
	require.True(t, request.IgnoreMetrics(&got[0]))
	require.Equal(t, server, got[1])
}

func TestDotnetHTTPPreservesTransportMetrics(t *testing.T) {
	server, nativeServer, client, nativeClient := dotnetHTTPSpans()
	r, out := dotnetHTTPTestResolver()
	r.process(context.Background(), []request.Span{server, nativeServer, client, nativeClient})
	var metrics []request.Span
	for len(out) > 0 {
		for _, span := range <-out {
			if !request.IgnoreMetrics(&span) && span.Type == request.EventTypeHTTPClient {
				metrics = append(metrics, span)
				require.True(t, request.IgnoreTraces(&span))
			}
		}
	}
	require.Len(t, metrics, 1)
	require.Equal(t, client.Start, metrics[0].Start)
	require.Equal(t, client.End, metrics[0].End)
	require.Equal(t, nativeClient.SpanID, metrics[0].SpanID)
}

func TestDotnetHTTPLateNativeRecordDoesNotDuplicateFallback(t *testing.T) {
	_, _, client, nativeClient := dotnetHTTPSpans()
	r, out := dotnetHTTPTestResolver()
	r.process(context.Background(), []request.Span{client})
	r.expire(context.Background(), time.Time{})
	require.Equal(t, []request.Span{client}, drainDotnetHTTP(out))
	r.process(context.Background(), []request.Span{nativeClient})
	require.Empty(t, drainDotnetHTTP(out))
	require.Empty(t, r.pending)
}
