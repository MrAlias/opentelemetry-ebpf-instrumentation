// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"path"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

func TestPythonHTTPXHTTPSPropagation(t *testing.T) {
	if runtime.GOARCH != "amd64" || KernelLockdownMode() {
		t.Skip("Python agent loading requires amd64, ptrace and bpf_probe_write_user")
	}
	for _, mode := range []string{"headers", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			compose, err := docker.ComposeSuite("docker-compose-python-httpx.yml",
				path.Join(pathOutput, "python-httpx-"+mode+".log"))
			require.NoError(t, err)
			compose.Env = append(compose.Env, "HTTPX_PROPAGATION="+mode,
				"COMPOSE_PROJECT_NAME=obi-python-httpx-regression-"+mode)
			require.NoError(t, compose.Up())
			t.Cleanup(func() { require.NoError(t, compose.Close()) })
			expectation := "injected"
			if mode == "disabled" {
				expectation = "disabled"
			}
			output, err := compose.ExecOutput("source", "python", "check.py", "--expect", expectation)
			require.NoError(t, err, "%s", output)
		})
	}
}
