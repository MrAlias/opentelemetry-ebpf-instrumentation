// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

func monotonicNowNS() (uint64, error) {
	var observed unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &observed); err != nil {
		return 0, fmt.Errorf("read CLOCK_MONOTONIC: %w", err)
	}
	value := observed.Nano()
	if value <= 0 {
		return 0, errors.New("CLOCK_MONOTONIC returned a non-positive value")
	}
	return uint64(value), nil
}
