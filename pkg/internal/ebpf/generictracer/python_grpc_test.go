// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package generictracer

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/config"
	"go.opentelemetry.io/obi/pkg/obi"
)

func TestPythonGRPCPropagationConstants(t *testing.T) {
	for _, mode := range []config.ContextPropagationMode{
		config.ContextPropagationDisabled, config.ContextPropagationTCP,
		config.ContextPropagationHeaders, config.ContextPropagationAll,
	} {
		name, err := mode.MarshalText()
		require.NoError(t, err)
		t.Run(string(name), func(t *testing.T) {
			cfg := obi.DefaultConfig
			cfg.EBPF.ContextPropagation = mode
			tracer := Tracer{cfg: &cfg, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
			constants := tracer.constants()
			require.Equal(t, mode.HasHeaders(), constants["g_bpf_header_propagation"],
				"the generic tracer must enable the caller-side Python metadata bridge")
			require.Contains(t, constants, "g_bpf_probe_write_user_enabled",
				"kernel capability checks must gate writes to the agent buffer")
		})
	}
}
