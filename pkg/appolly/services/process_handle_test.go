// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package services

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewProcessInstanceIDIsNonzeroAndUnique(t *testing.T) {
	first := NewProcessInstanceID()
	second := NewProcessInstanceID()

	require.NotZero(t, first)
	require.NotZero(t, second)
	require.NotEqual(t, first, second)
}
