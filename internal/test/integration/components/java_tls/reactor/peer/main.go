// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

func main() {
	if os.Getenv("ROLE") == "proxy" {
		targetURL := os.Getenv("DOWNSTREAM_URL")
		if targetURL == "" {
			targetURL = "http://downstream:8086"
		}
		target, err := url.Parse(targetURL)
		if err != nil {
			log.Fatal(err)
		}
		proxy := httputil.NewSingleHostReverseProxy(target)
		// Echo the TLS peer's port so tests can prove pooled connection reuse.
		director := proxy.Director
		proxy.Director = func(r *http.Request) {
			r.Header.Set("X-TLS-Peer", r.RemoteAddr)
			director(r)
		}
		certDir := os.Getenv("CERT_DIR")
		if certDir == "" {
			certDir = "/cert"
		}
		log.Fatal(http.ListenAndServeTLS(listenAddress(":8443"), certDir+"/server.crt", certDir+"/server.key", proxy))
	}
	exporter, err := otlptracehttp.New(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter, sdktrace.WithBatchTimeout(100*time.Millisecond)),
		sdktrace.WithResource(resource.NewSchemaless(attribute.String("service.name", "reactor-downstream"))),
	)
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, serverSpan := provider.Tracer("reactor-downstream").Start(ctx, "downstream", trace.WithSpanKind(trace.SpanKindServer))
		defer serverSpan.End()
		time.Sleep(500 * time.Millisecond)
		span := trace.SpanContextFromContext(ctx)
		active, _ := strconv.Atoi(r.Header.Get("X-Active-Subscriptions"))
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"traceparents": r.Header.Values("Traceparent"),
			"trace_id":     span.TraceID().String(), "span_id": span.SpanID().String(),
			"peer": r.Header.Get("X-TLS-Peer"), "path": r.URL.Path,
			"active_subscriptions": active,
		}); err != nil {
			log.Print(err)
		}
	})
	log.Fatal(http.ListenAndServe(listenAddress(":8086"), handler))
}

func listenAddress(fallback string) string {
	if address := os.Getenv("LISTEN_ADDR"); address != "" {
		return address
	}
	return fallback
}
