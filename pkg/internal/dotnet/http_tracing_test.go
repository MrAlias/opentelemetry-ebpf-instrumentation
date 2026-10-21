// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"compress/gzip"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

func TestHTTPActivitiesFromRuntime(t *testing.T) {
	// Linux .NET 8.0.0; four concurrent SendAsync calls with one incoming context.
	// The client IDs below were independently recorded from HttpRequestMessage headers.
	file, err := os.Open("testdata/httpclient-http11.nettrace.gz")
	require.NoError(t, err)
	defer file.Close()
	stream, err := gzip.NewReader(file)
	require.NoError(t, err)
	defer stream.Close()
	expectedClients := map[string]bool{
		"f6a2916814a6bad9": false, "3264fccfdcd9abc0": false,
		"7a315309c646b8db": false, "eb802da215805c60": false,
	}
	servers := map[string]string{}
	clients := map[string]string{}
	err = readNetTraceEvents(stream, 4130671, func(info netTraceInfo, event netTraceEvent) error {
		if event.Metadata.ProviderName != diagnosticSourceProviderName || event.Metadata.EventName != "Event" {
			return nil
		}
		arguments, err := diagnosticSourceArguments(event.Values)
		if err != nil {
			return err
		}
		span, err := decodeHTTPActivity(info, event)
		if err != nil {
			return err
		}
		switch event.Values["EventName"] {
		case "Microsoft.AspNetCore.Hosting.HttpRequestIn.Stop":
			require.NotNil(t, span)
			require.Equal(t, 200, span.Status)
			require.Equal(t, arguments["SpanId"], span.SpanID.String())
			require.Equal(t, "12345678901234567890123456789012", arguments["TraceId"])
			require.Equal(t, "1111111111111111", arguments["ParentSpanId"])
			require.Equal(t, "HTTP/1.1", arguments["Version"])
			servers[arguments["SpanId"]] = arguments["Path"]
		case "System.Net.Http.HttpRequestOut.Stop":
			require.NotNil(t, span)
			require.Equal(t, 200, span.Status)
			require.Equal(t, arguments["ParentSpanId"], span.ParentSpanID.String())
			require.Greater(t, span.End, span.Start)
			require.Equal(t, "12345678901234567890123456789012", arguments["TraceId"])
			require.Equal(t, "1.1", arguments["Version"])
			require.Equal(t, "GET", arguments["Method"])
			require.Equal(t, "OK", arguments["Status"])
			id := arguments["SpanId"]
			_, expected := expectedClients[id]
			require.True(t, expected, id)
			require.False(t, expectedClients[id], "duplicate native client: %s", id)
			expectedClients[id] = true
			clients[id] = arguments["ParentSpanId"]
		}
		return nil
	})
	require.NoError(t, err)
	require.Len(t, servers, 4)
	require.Len(t, clients, 4)
	for id, parent := range clients {
		require.True(t, expectedClients[id])
		require.Contains(t, servers, parent, "native client %s has no server parent", id)
	}
}

func TestHTTPActivityProvider(t *testing.T) {
	provider := httpActivityProvider()
	require.Equal(t, diagnosticSourceProviderName, provider.name)
	require.True(t, strings.HasPrefix(provider.arguments, `FilterAndPayloadSpecs="`))
	require.True(t, strings.HasSuffix(provider.arguments, `"`))
	require.Contains(t, provider.arguments, "Microsoft.AspNetCore.Hosting.HttpRequestIn.Start:-TraceId=")
	require.Contains(t, provider.arguments, "Address=Connection.LocalIpAddress")
	require.Contains(t, provider.arguments, "*Activity.ParentSpanId")
	_, err := encodeEventPipeProviders([]eventPipeProvider{provider})
	require.NoError(t, err)
}

func TestDiagnosticSourceArgumentsRejectAmbiguousContext(t *testing.T) {
	for _, arguments := range []any{
		nil,
		[]any{"not a pair"},
		[]any{map[string]any{"Key": "", "Value": "value"}},
		[]any{map[string]any{"Key": "TraceId", "Value": 42}},
		[]any{
			map[string]any{"Key": "TraceId", "Value": "first"},
			map[string]any{"Key": "TraceId", "Value": "second"},
		},
	} {
		_, err := diagnosticSourceArguments(map[string]any{"Arguments": arguments})
		require.Error(t, err)
	}
}

func TestHTTPActivityRequestHeaders(t *testing.T) {
	const parent = "00-12345678901234567890123456789012-1234567890123456-01"
	for _, headers := range []string{
		"traceparent: " + parent + "\r\n",
		"Traceparent: " + parent + "\n",
		"traceparent: " + parent + "\r\ntraceparent: " + parent + "\r\n",
		"traceparent: invalid\r\n",
		"",
	} {
		span := &request.Span{SpanID: [8]byte{2}, TraceID: [16]byte{1}}
		got, err := populateHTTPClientActivity(span, map[string]string{"Uri": "https://proxy:8443/case", "Headers": headers})
		require.NoError(t, err)
		require.Equal(t, strings.Count(headers, parent) == 1, got.WireTraceContext.IsValid())
		require.Equal(t, [8]byte{2}, [8]byte(got.SpanID), "application-supplied headers must not replace the native Activity")
		require.Equal(t, [16]byte{1}, [16]byte(got.TraceID))
	}
}
