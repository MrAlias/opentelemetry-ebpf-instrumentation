// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"go.opentelemetry.io/obi/pkg/appolly/app/request"
)

const (
	diagnosticSourceProviderName         = "Microsoft-Diagnostics-DiagnosticSource"
	diagnosticSourceEventsKeyword uint64 = 0x2
)

func httpActivityProvider() eventPipeProvider {
	const contextFields = "TraceId=*Activity.TraceId;SpanId=*Activity.SpanId;ParentSpanId=*Activity.ParentSpanId;Flags=*Activity.ActivityTraceFlags;Duration=*Activity.Duration.Ticks;"
	// ASP.NET emits its diagnostic stop event only when the start event is enabled.
	filters := []string{
		"Microsoft.AspNetCore/Microsoft.AspNetCore.Hosting.HttpRequestIn:-",
		"Microsoft.AspNetCore/Microsoft.AspNetCore.Hosting.HttpRequestIn.Start:-" + contextFields +
			"Method=Request.Method;Path=Request.Path.Value;Host=Request.Host.Value;Address=Connection.LocalIpAddress;Scheme=Request.Scheme;Version=Request.Protocol;Peer=Connection.RemoteIpAddress;PeerPort=Connection.RemotePort;Port=Connection.LocalPort",
		"Microsoft.AspNetCore/Microsoft.AspNetCore.Hosting.HttpRequestIn.Stop:-" + contextFields +
			"Method=Request.Method;Path=Request.Path.Value;Host=Request.Host.Value;Scheme=Request.Scheme;Version=Request.Protocol;Status=Response.StatusCode;Peer=Connection.RemoteIpAddress;PeerPort=Connection.RemotePort;Port=Connection.LocalPort",
		"HttpHandlerDiagnosticListener/System.Net.Http.HttpRequestOut:-",
		"HttpHandlerDiagnosticListener/System.Net.Http.HttpRequestOut.Stop:-" + contextFields +
			"Method=Request.Method.Method;Uri=Request.RequestUri;Version=Request.Version;Status=Response.StatusCode;Result=RequestTaskStatus;Headers=Request.Headers",
	}
	return eventPipeProvider{
		name: diagnosticSourceProviderName, keywords: diagnosticSourceEventsKeyword, level: eventLevelInformational,
		arguments: "FilterAndPayloadSpecs=\"" + strings.Join(filters, "\n") + "\"",
	}
}

func diagnosticSourceArguments(values map[string]any) (map[string]string, error) {
	arguments, ok := values["Arguments"].([]any)
	if !ok {
		return nil, errors.New("DiagnosticSource event has no arguments")
	}
	result := make(map[string]string, len(arguments))
	for _, argument := range arguments {
		pair, ok := argument.(map[string]any)
		if !ok {
			return nil, errors.New("invalid DiagnosticSource argument")
		}
		name, nameOK := pair["Key"].(string)
		value, valueOK := pair["Value"].(string)
		if !nameOK || !valueOK || name == "" {
			return nil, errors.New("invalid DiagnosticSource argument name or value")
		}
		if _, exists := result[name]; exists {
			return nil, fmt.Errorf("duplicate DiagnosticSource argument: %q", name)
		}
		result[name] = value
	}
	return result, nil
}

func decodeHTTPActivity(info netTraceInfo, event netTraceEvent) (*request.Span, error) {
	if event.Metadata.ProviderName != diagnosticSourceProviderName || event.Metadata.EventName != "Event" {
		return nil, nil
	}
	var kind request.EventType
	switch event.Values["EventName"] {
	case "Microsoft.AspNetCore.Hosting.HttpRequestIn.Start":
		kind = request.EventTypeHTTP
	case "Microsoft.AspNetCore.Hosting.HttpRequestIn.Stop":
		kind = request.EventTypeHTTP
	case "System.Net.Http.HttpRequestOut.Stop":
		kind = request.EventTypeHTTPClient
	default:
		return nil, nil
	}
	values, err := diagnosticSourceArguments(event.Values)
	if err != nil {
		return nil, err
	}
	if values["Version"] != "1.1" && values["Version"] != "HTTP/1.1" {
		return nil, nil
	}
	span := &request.Span{Type: kind, ProtoVersion: request.ProtoVersionHTTP11, Method: values["Method"]}
	span.TraceID, err = trace.TraceIDFromHex(values["TraceId"])
	if err != nil {
		return nil, err
	}
	span.SpanID, err = trace.SpanIDFromHex(values["SpanId"])
	if err != nil {
		return nil, err
	}
	if parent := values["ParentSpanId"]; parent != "" && parent != "0000000000000000" {
		span.ParentSpanID, err = trace.SpanIDFromHex(parent)
		if err != nil {
			return nil, err
		}
	}
	// CoreCLR on Linux uses CLOCK_MONOTONIC nanoseconds for QPC timestamps.
	if info.QPCFrequency != int64(time.Second) || event.Header.Timestamp <= 0 {
		return nil, fmt.Errorf("unsupported .NET HTTP clock frequency: %d", info.QPCFrequency)
	}
	const nanosecondsPerTick = int64(time.Second) / 10_000_000
	ticks, err := strconv.ParseInt(values["Duration"], 10, 64)
	if err != nil || ticks < 0 || ticks > math.MaxInt64/nanosecondsPerTick {
		return nil, fmt.Errorf("invalid .NET HTTP activity duration: %q", values["Duration"])
	}
	duration := ticks * nanosecondsPerTick
	if duration > event.Header.Timestamp {
		return nil, errors.New(".NET HTTP duration exceeds end timestamp")
	}
	span.End = event.Header.Timestamp
	span.Start = span.End - duration
	span.RequestStart = span.Start
	if values["Flags"] == "Recorded" {
		span.TraceFlags = 1
	}
	span.Status = dotnetHTTPStatus(values["Status"])
	if span.Status == 0 {
		span.ResponseObservation = request.ResponseSilent
	}
	if kind == request.EventTypeHTTPClient {
		return populateHTTPClientActivity(span, values)
	}
	address, err := url.Parse("//" + values["Host"])
	if err != nil {
		return nil, err
	}
	span.Host = values["Address"]
	if span.Host == "" {
		span.Host = address.Hostname()
	}
	span.HostPort, _ = strconv.Atoi(values["Port"])
	span.Peer = values["Peer"]
	span.PeerPort, _ = strconv.Atoi(values["PeerPort"])
	span.Path = values["Path"]
	span.FullPath = span.Path
	span.Statement = values["Scheme"] + request.SchemeHostSeparator + values["Host"]
	return span, nil
}

func populateHTTPClientActivity(span *request.Span, values map[string]string) (*request.Span, error) {
	address, err := url.Parse(values["Uri"])
	if err != nil {
		return nil, err
	}
	if address.Scheme != "https" {
		return nil, nil
	}
	span.Host = address.Hostname()
	if span.Host == "" {
		return nil, errors.New(".NET HTTP activity has no destination host")
	}
	const httpsPort = 443
	span.HostPort = httpsPort
	if port := address.Port(); port != "" {
		span.HostPort, err = strconv.Atoi(port)
		if err != nil {
			return nil, err
		}
	}
	span.Path = address.Path
	if span.Path == "" {
		span.Path = "/"
	}
	span.FullPath = address.RequestURI()
	span.Statement = address.Scheme + request.SchemeHostSeparator + net.JoinHostPort(span.Host, strconv.Itoa(span.HostPort))
	headers, err := textproto.NewReader(bufio.NewReader(strings.NewReader(values["Headers"] + "\r\n"))).ReadMIMEHeader()
	if err == nil && len(headers.Values("Traceparent")) == 1 {
		carrier := propagation.HeaderCarrier(http.Header(headers))
		span.WireTraceContext = trace.SpanContextFromContext(propagation.TraceContext{}.Extract(context.Background(), carrier))
	}
	return span, nil
}

var dotnetHTTPStatusCodes = func() map[string]int {
	aliases := map[string]int{
		"ambiguous":             http.StatusMultipleChoices,
		"moved":                 http.StatusMovedPermanently,
		"redirect":              http.StatusFound,
		"redirectmethod":        http.StatusSeeOther,
		"redirectkeepverb":      http.StatusTemporaryRedirect,
		"requestentitytoolarge": http.StatusRequestEntityTooLarge,
		"unprocessableentity":   http.StatusUnprocessableEntity,
		"unprocessablecontent":  http.StatusUnprocessableEntity,
	}
	for code := http.StatusContinue; code <= http.StatusNetworkAuthenticationRequired; code++ {
		text := http.StatusText(code)
		if text != "" {
			name := strings.NewReplacer(" ", "", "-", "", "'", "").Replace(text)
			aliases[strings.ToLower(name)] = code
		}
	}
	return aliases
}()

func dotnetHTTPStatus(value string) int {
	if code, err := strconv.Atoi(value); err == nil {
		return code
	}
	return dotnetHTTPStatusCodes[strings.ToLower(value)]
}
