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
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

type observation struct {
	Traceparents []string `json:"traceparents"`
	Connection   string   `json:"connection"`
	Protocol     string   `json:"protocol"`
	Method       string   `json:"method"`
	Path         string   `json:"path"`
	Token        string   `json:"token"`
	Body         string   `json:"body"`
	TraceID      string   `json:"trace_id"`
	SpanID       string   `json:"span_id"`
	ParentID     string   `json:"parent_id"`
}

func serveDownstream() {
	exporter, err := otlptracehttp.New(context.Background())
	if err != nil {
		log.Fatal(err)
	}
	provider := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exporter), sdktrace.WithResource(resource.NewWithAttributes("", attribute.String("service.name", "httpclient5-downstream"))))
	defer func() { _ = provider.Shutdown(context.Background()) }()
	otel.SetTracerProvider(provider)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ctx := propagation.TraceContext{}.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		parent := trace.SpanContextFromContext(ctx)
		_, span := provider.Tracer("httpclient5-test").Start(ctx, "downstream", trace.WithSpanKind(trace.SpanKindServer))
		defer span.End()
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(observation{Method: r.Method, Path: r.URL.RequestURI(), Token: r.Header.Get("X-Request-Token"), Body: string(body), TraceID: span.SpanContext().TraceID().String(), SpanID: span.SpanContext().SpanID().String(), ParentID: parent.SpanID().String()})
	})
	log.Print(http.ListenAndServe(":8086", nil))
}

func main() {
	if os.Getenv("ROLE") == "downstream" {
		serveDownstream()
		return
	}
	// This process forwards headers without creating or propagating a tracing context.
	client := &http.Client{Timeout: 10 * time.Second}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, err := http.NewRequestWithContext(r.Context(), r.Method, "http://downstream:8086"+r.URL.RequestURI(), r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		req.Header = r.Header.Clone()
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		var record observation
		if err := json.NewDecoder(resp.Body).Decode(&record); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		record.Traceparents = r.Header.Values("traceparent")
		record.Connection = r.RemoteAddr
		record.Protocol = r.Proto
		encoded, err := json.Marshal(record)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Print(string(encoded))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(encoded)
	})
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "proxy"}, DNSNames: []string{"proxy"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: ":8443", Handler: handler, TLSConfig: &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}, TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}
	log.Fatal(server.ListenAndServeTLS("", ""))
}
