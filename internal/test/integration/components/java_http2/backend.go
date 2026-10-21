// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

type observation struct {
	Path         string   `json:"path"`
	Traceparents []string `json:"traceparents"`
	Protocol     string   `json:"protocol"`
	ALPN         string   `json:"alpn"`
	RemoteAddr   string   `json:"remote_addr"`
	Concurrent   bool     `json:"concurrent"`
	TraceID      string   `json:"trace_id"`
	SpanID       string   `json:"span_id"`
	ParentID     string   `json:"parent_id"`
}

func main() {
	if os.Getenv("ROLE") == "proxy" {
		runProxy()
		return
	}
	exporter, err := otlptracehttp.New(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter), sdktrace.WithResource(
		resource.NewSchemaless(attribute.String("service.name", "java-http2-downstream"))))
	tracer := provider.Tracer("java-http2-regression")
	log.Fatal(http.ListenAndServe(envOr("LISTEN_ADDR", ":8080"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := propagation.TraceContext{}.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		parent := trace.SpanContextFromContext(ctx).SpanID().String()
		_, span := tracer.Start(ctx, r.URL.Path, trace.WithSpanKind(trace.SpanKindServer))
		sc := span.SpanContext()
		span.End()
		_ = json.NewEncoder(w).Encode(observation{Path: r.URL.Path, TraceID: sc.TraceID().String(), SpanID: sc.SpanID().String(), ParentID: parent})
	})))
}

func runProxy() {
	// This transport deliberately has no OpenTelemetry middleware or OBI instrumentation.
	client := &http.Client{Timeout: 20 * time.Second}
	var active atomic.Int32
	server := &http.Server{
		Addr:              envOr("LISTEN_ADDR", ":8443"),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate()}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			active.Add(1)
			defer active.Add(-1)
			time.Sleep(100 * time.Millisecond)
			concurrent := active.Load() > 1
			req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, envOr("DOWNSTREAM_URL", "http://downstream:8080")+r.URL.Path, nil)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			req.Header = r.Header.Clone()
			resp, err := client.Do(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			var result observation
			if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			result.Traceparents = r.Header.Values("Traceparent")
			result.Protocol = r.Proto
			result.ALPN = r.TLS.NegotiatedProtocol
			result.RemoteAddr = r.RemoteAddr
			result.Concurrent = concurrent
			_ = json.NewEncoder(w).Encode(result)
		}),
	}
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func certificate() tls.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "proxy"},
		DNSNames: []string{"proxy", "localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	if err != nil {
		log.Fatal(err)
	}
	return cert
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
