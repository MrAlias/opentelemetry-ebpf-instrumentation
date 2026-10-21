// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	collector "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/protobuf/proto"
)

type span struct {
	TraceID  string `json:"traceId"`
	SpanID   string `json:"spanId"`
	ParentID string `json:"parentId"`
	Name     string `json:"name"`
	Kind     string `json:"kind"`
}

var mu sync.Mutex
var spans []span
var records []map[string]interface{}

type exporter struct{}

func (exporter) ExportSpans(_ context.Context, ss []sdktrace.ReadOnlySpan) error {
	mu.Lock()
	defer mu.Unlock()
	for _, s := range ss {
		spans = append(spans, span{s.SpanContext().TraceID().String(), s.SpanContext().SpanID().String(), s.Parent().SpanID().String(), s.Name(), s.SpanKind().String()})
	}
	return nil
}
func (exporter) Shutdown(context.Context) error { return nil }
func downstreamHandler() http.Handler {
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter{}))
	downstream := http.NewServeMux()
	downstream.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		ctx := propagation.TraceContext{}.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		_, s := tp.Tracer("okhttp-downstream").Start(ctx, "downstream/"+r.URL.Query().Get("id"), trace.WithSpanKind(trace.SpanKindServer))
		defer s.End()
		body, _ := io.ReadAll(r.Body)
		time.Sleep(20 * time.Millisecond)
		json.NewEncoder(w).Encode(map[string]interface{}{"body": string(body), "unrelated": r.Header.Get("X-Unrelated"), "traceparent": r.Header.Values("Traceparent")})
	})
	return downstream
}

func proxyHandler() http.Handler {
	target, _ := url.Parse("http://127.0.0.1:18081")
	proxy := httputil.NewSingleHostReverseProxy(target)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		mu.Lock()
		records = append(records, map[string]interface{}{"id": r.URL.Query().Get("id"), "traceparents": r.Header.Values("Traceparent"), "remote": r.RemoteAddr, "protocol": r.Proto, "body": string(body), "unrelated": r.Header.Get("X-Unrelated")})
		mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(body))
		proxy.ServeHTTP(w, r)
	})
}

func tlsListener() net.Listener {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	certTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour * 24), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, _ := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, &key.PublicKey, key)
	cert, _ := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	listener, err := tls.Listen("tcp", "127.0.0.1:18443", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	if err != nil {
		log.Fatal(err)
	}
	return listener
}

func collectorHandler() http.Handler {
	admin := http.NewServeMux()
	admin.HandleFunc("/records", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		json.NewEncoder(w).Encode(records)
	})
	admin.HandleFunc("/spans", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		json.NewEncoder(w).Encode(spans)
	})
	admin.HandleFunc("/v1/traces", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var req collector.ExportTraceServiceRequest
		if err := proto.Unmarshal(b, &req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		for _, rs := range req.ResourceSpans {
			for _, ss := range rs.ScopeSpans {
				for _, s := range ss.Spans {
					spans = append(spans, span{hex.EncodeToString(s.TraceId), hex.EncodeToString(s.SpanId), hex.EncodeToString(s.ParentSpanId), s.Name, s.Kind.String()})
				}
			}
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(200)
	})
	return admin
}

func main() {
	go func() { log.Fatal(http.ListenAndServe("127.0.0.1:18081", downstreamHandler())) }()
	listener := tlsListener()
	go func() { log.Fatal(http.Serve(listener, proxyHandler())) }()
	log.Print("observer ready")
	log.Fatal(http.ListenAndServe("127.0.0.1:18082", collectorHandler()))
}
