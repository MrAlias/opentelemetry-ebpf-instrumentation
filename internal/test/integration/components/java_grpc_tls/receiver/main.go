// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

type codec struct{}

func (codec) Name() string                    { return "proto" }
func (codec) Marshal(v any) ([]byte, error)   { return *v.(*[]byte), nil }
func (codec) Unmarshal(b []byte, v any) error { *v.(*[]byte) = append([]byte(nil), b...); return nil }

var (
	active    atomic.Int32
	maxActive atomic.Int32
)

func main() {
	ctx := context.Background()
	exporter, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpoint(env("OTLP_ENDPOINT", "jaeger:4318")), otlptracehttp.WithInsecure())
	if err != nil {
		log.Fatal(err)
	}
	provider := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exporter, sdktrace.WithBatchTimeout(100*time.Millisecond)),
		sdktrace.WithResource(resource.NewSchemaless(attribute.String("service.name", "java-grpc-downstream"))))
	tracer := provider.Tracer("fixture")
	server := grpc.NewServer(grpc.ForceServerCodec(codec{}))
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "fixture.Receiver", HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{{MethodName: "Call", Handler: func(_ any, ctx context.Context, decode func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
			var request []byte
			if err := decode(&request); err != nil {
				return nil, err
			}
			md, _ := metadata.FromIncomingContext(ctx)
			carrier := propagation.MapCarrier{}
			for key, values := range md {
				if len(values) > 0 {
					carrier[key] = values[0]
				}
			}
			ctx = propagation.TraceContext{}.Extract(ctx, carrier)
			parent := trace.SpanContextFromContext(ctx)
			ctx, span := tracer.Start(ctx, "fixture.Receiver/Call", trace.WithSpanKind(trace.SpanKindServer))
			defer span.End()
			current := active.Add(1)
			defer active.Add(-1)
			for old := maxActive.Load(); current > old; old = maxActive.Load() {
				if maxActive.CompareAndSwap(old, current) {
					break
				}
			}
			time.Sleep(200 * time.Millisecond)
			remote, _ := peer.FromContext(ctx)
			observation := struct {
				CaseID          string   `json:"case_id"`
				Traceparents    []string `json:"traceparents"`
				TraceID         string   `json:"trace_id"`
				SpanID          string   `json:"span_id"`
				ParentID        string   `json:"parent_id"`
				ProxyConnection []string `json:"proxy_connection"`
				Peer            string   `json:"peer"`
				MaxActive       int32    `json:"max_active"`
			}{string(request), md.Get("traceparent"), span.SpanContext().TraceID().String(), span.SpanContext().SpanID().String(), parent.SpanID().String(), md.Get("x-proxy-connection"), remote.Addr.String(), maxActive.Load()}
			data, err := json.Marshal(observation)
			fmt.Println(string(data))
			return &data, err
		}}},
	}, struct{}{})
	listener, err := net.Listen("tcp", env("GRPC_LISTEN", ":50051"))
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(server.Serve(listener))
}

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
