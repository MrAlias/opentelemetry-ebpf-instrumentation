// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMonotonicNowNSRejectsUnsupportedPlatforms(t *testing.T) {
	observed, err := monotonicNowNS()

	assert.Zero(t, observed)
	assert.ErrorContains(t, err, "requires Linux CLOCK_MONOTONIC")
}
