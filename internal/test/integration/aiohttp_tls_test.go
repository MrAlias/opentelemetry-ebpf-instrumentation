// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"path"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/internal/test/integration/components/docker"
)

func TestSuiteAiohttpTLSHeaders(t *testing.T) {
	for _, mode := range []string{"headers", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			compose, err := docker.ComposeSuite("docker-compose-aiohttp-tls.yml",
				path.Join(pathOutput, "test-suite-aiohttp-tls-"+mode+".log"))
			require.NoError(t, err)
			compose.Env = append(compose.Env, "PROPAGATION="+mode,
				"COMPOSE_PROJECT_NAME=obi-aiohttp-tls-"+mode)
			t.Cleanup(func() { require.NoError(t, compose.Close()) })
			require.NoError(t, compose.Run("check"))
		})
	}
}
