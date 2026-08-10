// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import (
	"fmt"

	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

func validateRuntimeMetricOwner(procFD int, owner *exec.FileInfo) error {
	pid, start, state, err := procs.ProcessIdentityFromProcFD(procFD)
	if err != nil {
		return fmt.Errorf("reading exact process identity: %w", err)
	}
	if state == 'Z' || state == 'X' || state == 'x' {
		return fmt.Errorf("exact process PID %d is no longer live", pid)
	}
	if pid != owner.Pid() {
		return fmt.Errorf(
			"stable process handle identifies PID %d, not owner PID %d",
			pid, owner.Pid(),
		)
	}
	if start != owner.ProcessStartTime() {
		return fmt.Errorf(
			"stable process handle identifies PID %d start %d, not owner start %d",
			pid, start, owner.ProcessStartTime(),
		)
	}
	return nil
}
