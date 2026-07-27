// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
	"go.opentelemetry.io/otel/trace"
)

const (
	clientServiceName = "obi-windows-http-client"
	clientScopeName   = "go.opentelemetry.io/obi/examples/windows-http-client"
)

type options struct {
	endpoint string
	target   string
	timeout  time.Duration
}

type result struct {
	TraceID    string `json:"trace_id"`
	SpanID     string `json:"span_id"`
	Method     string `json:"method"`
	URL        string `json:"url"`
	StatusCode int    `json:"status_code"`
	SpanKind   string `json:"span_kind"`
	Service    string `json:"service_name"`
}

func main() {
	opts := options{}
	flag.StringVar(&opts.endpoint, "otlp-endpoint", "http://127.0.0.1:4318/v1/traces", "OTLP/HTTP traces endpoint")
	flag.StringVar(&opts.target, "url", "http://127.0.0.1:18080/linked", "HTTP target URL")
	flag.DurationVar(&opts.timeout, "timeout", 15*time.Second, "request and export timeout")
	flag.Parse()

	if err := opts.validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.timeout)
	defer cancel()

	output, err := run(ctx, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
		fmt.Fprintf(os.Stderr, "encode result: %v\n", err)
		os.Exit(1)
	}
}

func (o options) validate() error {
	if o.timeout <= 0 {
		return errors.New("-timeout must be positive")
	}
	for name, value := range map[string]string{
		"-otlp-endpoint": o.endpoint,
		"-url":           o.target,
	} {
		parsed, err := url.ParseRequestURI(value)
		if err != nil || parsed.Scheme != "http" || parsed.Host == "" {
			return fmt.Errorf("%s must be an absolute HTTP URL: %q", name, value)
		}
	}
	return nil
}

func run(ctx context.Context, opts options) (result, error) {
	exporter, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpointURL(opts.endpoint))
	if err != nil {
		return result{}, fmt.Errorf("create OTLP exporter: %w", err)
	}

	clientResource, err := resource.New(
		ctx,
		resource.WithTelemetrySDK(),
		resource.WithAttributes(
			semconv.ServiceName(clientServiceName),
			semconv.OSTypeWindows,
		),
	)
	if err != nil {
		return result{}, fmt.Errorf("create client resource: %w", err)
	}

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithResource(clientResource),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSyncer(exporter),
	)
	defer func() {
		_ = provider.Shutdown(context.Background())
	}()

	propagator := propagation.TraceContext{}
	otel.SetTextMapPropagator(propagator)
	tracer := provider.Tracer(clientScopeName)

	spanCtx, span := tracer.Start(
		ctx,
		http.MethodGet,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			semconv.HTTPRequestMethodKey.String(http.MethodGet),
			semconv.URLFullKey.String(opts.target),
			semconv.ServerAddressKey.String("127.0.0.1"),
		),
	)

	request, err := newRequest(spanCtx, opts.target, propagator)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.End()
		return result{}, err
	}

	response, err := sendRequest(spanCtx, request)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		span.End()
		return result{}, fmt.Errorf("send HTTP request: %w", err)
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()

	responseAttributes := []attribute.KeyValue{
		semconv.HTTPResponseStatusCode(response.StatusCode),
	}
	if port, err := strconv.Atoi(response.Request.URL.Port()); err == nil {
		responseAttributes = append(responseAttributes, semconv.ServerPortKey.Int(port))
	}
	span.SetAttributes(responseAttributes...)
	if response.StatusCode >= http.StatusBadRequest {
		span.SetStatus(codes.Error, response.Status)
	}

	contextValue := span.SpanContext()
	span.End()
	if err := provider.ForceFlush(ctx); err != nil {
		return result{}, fmt.Errorf("flush client span: %w", err)
	}
	if readErr != nil {
		return result{}, fmt.Errorf("read HTTP response: %w", readErr)
	}
	if closeErr != nil {
		return result{}, fmt.Errorf("close HTTP response: %w", closeErr)
	}

	return result{
		TraceID:    contextValue.TraceID().String(),
		SpanID:     contextValue.SpanID().String(),
		Method:     http.MethodGet,
		URL:        opts.target,
		StatusCode: response.StatusCode,
		SpanKind:   trace.SpanKindClient.String(),
		Service:    clientServiceName,
	}, nil
}

func sendRequest(ctx context.Context, request *http.Request) (*http.Response, error) {
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", request.URL.Host)
	if err != nil {
		return nil, fmt.Errorf("connect to HTTP target: %w", err)
	}
	defer connection.Close()

	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("set HTTP connection deadline: %w", err)
		}
	}

	var wire bytes.Buffer
	if err := request.Write(&wire); err != nil {
		return nil, fmt.Errorf("serialize HTTP request: %w", err)
	}
	for payload := wire.Bytes(); len(payload) > 0; {
		written, err := connection.Write(payload)
		if err != nil {
			return nil, fmt.Errorf("send HTTP request: %w", err)
		}
		if written == 0 {
			return nil, io.ErrShortWrite
		}
		payload = payload[written:]
	}

	response, err := http.ReadResponse(bufio.NewReader(connection), request)
	if err != nil {
		return nil, fmt.Errorf("read HTTP response headers: %w", err)
	}
	return response, nil
}

func newRequest(ctx context.Context, target string, propagator propagation.TextMapPropagator) (*http.Request, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("create HTTP request: %w", err)
	}
	request.Close = true
	propagator.Inject(ctx, propagation.HeaderCarrier(request.Header))
	return request, nil
}
