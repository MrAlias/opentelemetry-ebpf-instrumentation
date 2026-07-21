// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMonotonicNowNSReturnsPositiveValue(t *testing.T) {
	observed, err := monotonicNowNS()

	require.NoError(t, err)
	assert.Positive(t, observed)
}
