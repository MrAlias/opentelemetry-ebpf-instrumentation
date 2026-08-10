// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"errors"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

var errStaleProcessIdentity = errors.New("stale process identity")

// liveProcessParentPID returns the current parent from the exact process
// directory represented by fi. Zero-start FileInfos are synthetic/legacy test
// inputs and retain the immutable-PPID behavior used on non-Linux platforms.
func liveProcessParentPID(fi *exec.FileInfo) (app.PID, bool) {
	if fi == nil {
		return 0, false
	}
	if fi.ProcessStartTime() == 0 {
		return fi.Ppid(), true
	}

	var parent app.PID
	err := fi.UseProcessHandle(func(fd int) error {
		pid, ppid, start, state, err := procs.ProcessStatFromProcFD(fd)
		if err != nil {
			return err
		}
		if pid != fi.Pid() || start != fi.ProcessStartTime() || processStateDead(state) {
			return errStaleProcessIdentity
		}
		parent = ppid
		return nil
	})
	return parent, err == nil
}
