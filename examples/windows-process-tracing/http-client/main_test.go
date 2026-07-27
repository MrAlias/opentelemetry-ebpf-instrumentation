// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

func TestNewRequestInjectsActiveSpanContext(t *testing.T) {
	traceID, err := trace.TraceIDFromHex("0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	spanID, err := trace.SpanIDFromHex("0123456789abcdef")
	require.NoError(t, err)

	spanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), spanContext)

	request, err := newRequest(ctx, "http://127.0.0.1:18080/linked", propagation.TraceContext{})
	require.NoError(t, err)

	assert.True(t, request.Close)
	assert.Equal(
		t,
		"00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
		request.Header.Get("traceparent"),
	)
}

func TestSendRequestWritesInjectedTraceContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assert.Equal(
			t,
			"00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
			request.Header.Get("traceparent"),
		)
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)

	traceID, err := trace.TraceIDFromHex("0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	spanID, err := trace.SpanIDFromHex("0123456789abcdef")
	require.NoError(t, err)
	ctx := trace.ContextWithSpanContext(
		context.Background(),
		trace.NewSpanContext(trace.SpanContextConfig{
			TraceID:    traceID,
			SpanID:     spanID,
			TraceFlags: trace.FlagsSampled,
		}),
	)
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	t.Cleanup(cancel)

	request, err := newRequest(ctx, server.URL+"/linked", propagation.TraceContext{})
	require.NoError(t, err)
	response, err := sendRequest(ctx, request)
	require.NoError(t, err)
	t.Cleanup(func() { _ = response.Body.Close() })

	assert.Equal(t, http.StatusNoContent, response.StatusCode)
}

func TestOptionsValidate(t *testing.T) {
	valid := options{
		endpoint: "http://127.0.0.1:4318/v1/traces",
		target:   "http://127.0.0.1:18080/linked",
		timeout:  time.Second,
	}
	require.NoError(t, valid.validate())

	for name, mutate := range map[string]func(*options){
		"invalid endpoint": func(value *options) { value.endpoint = "not a URL" },
		"HTTPS target":     func(value *options) { value.target = "https://127.0.0.1/linked" },
		"zero timeout":     func(value *options) { value.timeout = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			value := valid
			mutate(&value)
			require.Error(t, value.validate())
		})
	}
}
