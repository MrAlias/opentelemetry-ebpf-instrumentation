// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"flag"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/obi/pkg/buildinfo"
)

func main() {
	opts := windowsProcessOptions{}

	flag.StringVar(&opts.programPath, "process-program", os.Getenv("OTEL_EBPF_WINDOWS_PROCESS_PROGRAM"),
		"path to the bpf2c-generated native process eBPF .sys")
	flag.StringVar(&opts.flowProgramPath, "flow-program", os.Getenv("OTEL_EBPF_WINDOWS_FLOW_PROGRAM"),
		"path to the bpf2c-generated native Flow Classify eBPF .sys")
	flag.StringVar(&opts.targetExecutable, "target-exe", envOrDefault("OTEL_EBPF_WINDOWS_TARGET_EXE", "obi-windows-target.exe"),
		"executable name whose process-start event will be exported")
	flag.IntVar(&opts.targetPort, "target-port", envIntOrDefault("OTEL_EBPF_WINDOWS_TARGET_PORT", 0),
		"plaintext HTTP server port; nonzero enables native Flow Classify HTTP tracing")
	flag.StringVar(&opts.otlpEndpoint, "otlp-endpoint", defaultOTLPTracesEndpoint(),
		"OTLP/HTTP protobuf traces endpoint")
	flag.BoolVar(&opts.once, "once", true, "exit successfully after exporting the first matching event")
	flag.DurationVar(&opts.timeout, "timeout", 2*time.Minute, "maximum time to wait for a matching event; zero disables it")
	flag.Parse()

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))
	slog.Info("OpenTelemetry eBPF Instrumentation native Windows tracing proof of concept",
		"Version", buildinfo.Version,
		"Revision", buildinfo.Revision)

	if err := opts.validate(); err != nil {
		slog.Error("invalid Windows process tracing configuration", "error", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if opts.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.timeout)
		defer cancel()
	}

	run := runWindowsProcessTrace
	if opts.flowProgramPath != "" || opts.targetPort != 0 {
		run = runWindowsHTTPTrace
	}
	if err := run(ctx, opts); err != nil {
		slog.Error("Windows native tracing stopped with an error", "error", err)
		os.Exit(1)
	}

	slog.Info("OpenTelemetry eBPF Instrumentation successfully exiting")
}

func (o windowsProcessOptions) validate() error {
	if o.programPath == "" {
		return errMissingProcessProgram
	}
	if o.targetExecutable == "" {
		return errMissingTargetExecutable
	}
	if o.flowProgramPath != "" || o.targetPort != 0 {
		if o.flowProgramPath == "" {
			return errMissingFlowProgram
		}
		if o.targetPort < 1 || o.targetPort > 65535 {
			return errInvalidTargetPort
		}
		if !o.once {
			return errHTTPRequiresOneShot
		}
	}
	parsed, err := url.ParseRequestURI(o.otlpEndpoint)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return errInvalidOTLPEndpoint
	}
	return nil
}

func defaultOTLPTracesEndpoint() string {
	if endpoint := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	if endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); endpoint != "" {
		return strings.TrimRight(endpoint, "/") + "/v1/traces"
	}
	return "http://127.0.0.1:4318/v1/traces"
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
func envIntOrDefault(name string, fallback int) int {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}
