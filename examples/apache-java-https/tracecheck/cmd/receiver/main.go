// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"

	"go.opentelemetry.io/obi/examples/apache-java-https/tracecheck"
)

const (
	maxRequestBytes         = 16 << 20
	defaultMaxSpans         = 10_000
	maximumMaxSpans         = 100_000
	defaultMaxValueBytes    = 4 << 10
	maximumMaxValueBytes    = 64 << 10
	defaultMaxRetainedBytes = 64 << 20
	maximumMaxRetainedBytes = 256 << 20
)

type receiver struct {
	store *tracecheck.Store
}

func main() {
	os.Exit(mainExitCode())
}

func mainExitCode() int {
	address := envOrDefault("LISTEN_ADDRESS", "127.0.0.1:14318")
	maxSpans, err := envBoundedInt("MAX_SPANS", defaultMaxSpans, maximumMaxSpans)
	if err != nil {
		slog.Error("invalid receiver configuration", "error", err)
		return 2
	}
	maxValueBytes, err := envBoundedInt(
		"MAX_VALUE_BYTES",
		defaultMaxValueBytes,
		maximumMaxValueBytes,
	)
	if err != nil {
		slog.Error("invalid receiver configuration", "error", err)
		return 2
	}
	maxRetainedBytes, err := envBoundedInt(
		"MAX_RETAINED_BYTES",
		defaultMaxRetainedBytes,
		maximumMaxRetainedBytes,
	)
	if err != nil {
		slog.Error("invalid receiver configuration", "error", err)
		return 2
	}

	handler := &receiver{store: tracecheck.NewStore(
		maxSpans,
		uint64(maxValueBytes),
		uint64(maxRetainedBytes),
	)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handler.health)
	mux.HandleFunc("GET /snapshot", handler.snapshot)
	mux.HandleFunc("POST /reset", handler.reset)
	mux.HandleFunc("POST /v1/traces", handler.traces)

	server := &http.Server{
		Addr:              address,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("receiver shutdown failed", "error", err)
		}
	}()

	slog.Info(
		"OTLP trace receiver listening",
		"address", address,
		"max_spans", maxSpans,
		"max_value_bytes", maxValueBytes,
		"max_retained_bytes", maxRetainedBytes,
	)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("receiver failed", "error", err)
		return 1
	}
	return 0
}

func (r *receiver) health(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ready"})
}

func (r *receiver) snapshot(writer http.ResponseWriter, request *http.Request) {
	marker := request.URL.Query().Get("marker")
	if len(marker) > 128 {
		writeError(writer, http.StatusBadRequest, "marker exceeds 128 bytes")
		return
	}
	writeJSON(writer, http.StatusOK, r.store.Snapshot(marker))
}

func (r *receiver) reset(writer http.ResponseWriter, _ *http.Request) {
	r.store.Reset()
	writeJSON(writer, http.StatusOK, map[string]string{"status": "reset"})
}

func (r *receiver) traces(writer http.ResponseWriter, request *http.Request) {
	receivedAt := time.Now()

	if request.Header.Get("Content-Encoding") != "" {
		writeError(writer, http.StatusUnsupportedMediaType, "compressed OTLP payloads are not enabled")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(writer, request.Body, maxRequestBytes))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid or oversized OTLP request")
		return
	}

	exportRequest := ptraceotlp.NewExportRequest()
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(request.Header.Get("Content-Type"), ";")[0]))
	switch contentType {
	case "application/json":
		err = exportRequest.UnmarshalJSON(body)
	case "", "application/x-protobuf", "application/protobuf", "application/octet-stream":
		err = exportRequest.UnmarshalProto(body)
	default:
		writeError(writer, http.StatusUnsupportedMediaType, "unsupported OTLP content type")
		return
	}
	if err != nil {
		writeError(writer, http.StatusBadRequest, "could not decode OTLP traces")
		return
	}

	spans := tracecheck.Flatten(exportRequest.Traces())
	r.store.AddAt(spans, receivedAt)

	exportResponse := ptraceotlp.NewExportResponse()
	if contentType == "application/json" {
		payload, marshalErr := exportResponse.MarshalJSON()
		if marshalErr != nil {
			writeError(writer, http.StatusInternalServerError, "could not encode OTLP response")
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(payload)
		return
	}

	payload, err := exportResponse.MarshalProto()
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "could not encode OTLP response")
		return
	}
	writer.Header().Set("Content-Type", "application/x-protobuf")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(payload)
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envBoundedInt(name string, fallback, maximum int) (int, error) {
	raw := os.Getenv(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 || value > maximum {
		return 0, fmt.Errorf("%s must be an integer between 1 and %d", name, maximum)
	}
	return value, nil
}

func writeError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, map[string]string{"error": message})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		slog.Warn("could not write JSON response", "error", err)
	}
}
