// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvBoundedIntUsesDefaultAndEnforcesMaximum(t *testing.T) {
	t.Setenv("RECEIVER_TEST_BOUND", "")
	value, err := envBoundedInt("RECEIVER_TEST_BOUND", 7, 10)
	require.NoError(t, err)
	assert.Equal(t, 7, value)

	t.Setenv("RECEIVER_TEST_BOUND", "10")
	value, err = envBoundedInt("RECEIVER_TEST_BOUND", 7, 10)
	require.NoError(t, err)
	assert.Equal(t, 10, value)

	for _, invalid := range []string{"0", "11", "invalid"} {
		t.Setenv("RECEIVER_TEST_BOUND", invalid)
		_, err = envBoundedInt("RECEIVER_TEST_BOUND", 7, 10)
		require.Error(t, err)
	}
}
