// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"
	"time"
)

func TestOptionsFromEnvironment(t *testing.T) {
	t.Setenv("OBI_WINDOWS_HTTP_PORT", "18081")
	t.Setenv("OBI_WINDOWS_HTTP_STATUS", "503")
	t.Setenv("OBI_WINDOWS_HTTP_LATENCY_MS", "125")

	opts, err := optionsFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if opts.port != 18081 || opts.statusCode != 503 ||
		opts.latency != 125*time.Millisecond {
		t.Fatalf("options = %#v", opts)
	}
}

func TestOptionsFromEnvironmentDefaults(t *testing.T) {
	t.Setenv("OBI_WINDOWS_HTTP_PORT", "")
	t.Setenv("OBI_WINDOWS_HTTP_STATUS", "")
	t.Setenv("OBI_WINDOWS_HTTP_LATENCY_MS", "")

	opts, err := optionsFromEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if opts.port != defaultPort || opts.statusCode != defaultStatusCode ||
		opts.latency != 0 {
		t.Fatalf("options = %#v", opts)
	}
}

func TestOptionsFromEnvironmentRejectsInvalidValues(t *testing.T) {
	tests := map[string]struct {
		name  string
		value string
	}{
		"port": {
			name:  "OBI_WINDOWS_HTTP_PORT",
			value: "0",
		},
		"status": {
			name:  "OBI_WINDOWS_HTTP_STATUS",
			value: "199",
		},
		"latency": {
			name:  "OBI_WINDOWS_HTTP_LATENCY_MS",
			value: "5001",
		},
		"latency overflow": {
			name:  "OBI_WINDOWS_HTTP_LATENCY_MS",
			value: "9223372036854775807",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Setenv(test.name, test.value)
			if _, err := optionsFromEnvironment(); err == nil {
				t.Fatal("invalid environment value was accepted")
			}
		})
	}
}
