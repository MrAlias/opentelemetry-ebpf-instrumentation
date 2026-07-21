// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package main

import (
	"fmt"
	"runtime"
)

func monotonicNowNS() (uint64, error) {
	return 0, fmt.Errorf(
		"map pressure requires Linux CLOCK_MONOTONIC; unsupported operating system: %s",
		runtime.GOOS,
	)
}
