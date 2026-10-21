// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

type observation struct {
	ID           string   `json:"id"`
	Traceparents []string `json:"traceparents"`
	Protocol     string   `json:"protocol"`
	ALPN         string   `json:"alpn"`
	Peer         string   `json:"peer"`
}

type recorder struct {
	mu           sync.Mutex
	observations []observation
	active       atomic.Int32
	maxActive    atomic.Int32
}

func main() {
	if os.Getenv("ROLE") == "downstream" {
		log.Fatal(serveDownstream())
		return
	}
	serveProxy()
}

func serveDownstream() error {
	ctx := context.Background()
	exporter, err := otlptracehttp.New(ctx)
	if err != nil {
		return err
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithResource(resource.Default()),
		sdktrace.WithBatcher(exporter, sdktrace.WithBatchTimeout(100*time.Millisecond)),
	)
	defer func() { _ = provider.Shutdown(ctx) }()
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.TraceContext{})
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("/case/", otelhttp.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		span := trace.SpanContextFromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"trace_id": span.TraceID().String(),
			"span_id":  span.SpanID().String(),
		})
	}), "downstream"))
	return http.ListenAndServe(":8081", mux)
}

func serveProxy() {
	endpoint := os.Getenv("DOWNSTREAM_URL")
	if endpoint == "" {
		endpoint = "http://downstream:8081"
	}
	upstream, err := url.Parse(endpoint)
	if err != nil {
		log.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	records := &recorder{}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/observations", func(w http.ResponseWriter, _ *http.Request) {
		records.mu.Lock()
		defer records.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"requests": records.observations, "max_active": records.maxActive.Load(),
		})
	})
	mux.HandleFunc("/seen/", func(w http.ResponseWriter, r *http.Request) {
		records.mu.Lock()
		defer records.mu.Unlock()
		for _, observed := range records.observations {
			if observed.ID == strings.TrimPrefix(r.URL.Path, "/seen/") {
				w.WriteHeader(http.StatusOK)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/case/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/case/")
		observed := observation{
			ID: id, Traceparents: r.Header.Values("Traceparent"), Protocol: r.Proto,
			ALPN: r.TLS.NegotiatedProtocol, Peer: r.RemoteAddr,
		}
		records.mu.Lock()
		records.observations = append(records.observations, observed)
		records.mu.Unlock()
		active := records.active.Add(1)
		defer records.active.Add(-1)
		for previous := records.maxActive.Load(); active > previous; previous = records.maxActive.Load() {
			if records.maxActive.CompareAndSwap(previous, active) {
				break
			}
		}
		if strings.Contains(id, "cancel") {
			<-r.Context().Done()
			return
		}
		if strings.Contains(id, "concurrent") {
			time.Sleep(200 * time.Millisecond)
		}
		// This transport has no OTel middleware: preserve the received fields.
		proxy.ServeHTTP(w, r)
	})
	server := &http.Server{
		Addr: ":8443", Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"},
			Certificates: []tls.Certificate{testCertificate()},
		},
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func testCertificate() tls.Certificate {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"proxy"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}),
	)
	if err != nil {
		log.Fatal(err)
	}
	return cert
}
