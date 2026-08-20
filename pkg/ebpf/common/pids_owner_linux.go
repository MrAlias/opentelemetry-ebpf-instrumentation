// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"fmt"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

// PF_EXITING is set by exit_signals before sched_process_exit is emitted. An
// owner with this flag can still have a readable /proc directory and executable
// even though its last-thread lifecycle notification has already fired.
const linuxTaskFlagExiting uint64 = 0x00000004

func namespacedPIDsForOwner(pid app.PID, owner *exec.FileInfo) ([]app.PID, error) {
	if owner == nil || owner.ProcessStartTime() == 0 {
		return readNamespacePIDs(pid)
	}
	if owner.Pid() != pid {
		return nil, fmt.Errorf("exact process owner PID %d does not match %d", owner.Pid(), pid)
	}

	var aliases []app.PID
	err := owner.UseProcessHandle(func(fd int) error {
		if err := validateProcessOwnerFD(
			pid,
			owner.ProcessStartTime(),
			owner.Dev(),
			owner.Ino(),
			fd,
		); err != nil {
			return err
		}
		var err error
		aliases, err = procs.FindNamespacedPidsFromProcFD(fd)
		if err != nil {
			return err
		}
		if err := validateNamespacedPIDAliases(pid, aliases); err != nil {
			return err
		}
		return validateProcessOwnerFD(
			pid,
			owner.ProcessStartTime(),
			owner.Dev(),
			owner.Ino(),
			fd,
		)
	})
	if err != nil {
		return nil, err
	}
	return aliases, nil
}

func validateNamespacedPIDAliases(pid app.PID, aliases []app.PID) error {
	if len(aliases) == 0 {
		return fmt.Errorf("exact process PID %d has no namespace aliases", pid)
	}
	if aliases[0] != pid {
		return fmt.Errorf(
			"exact process PID %d has outer namespace alias %d",
			pid,
			aliases[0],
		)
	}
	return nil
}

func validateProcessOwner(pid app.PID, owner *exec.FileInfo) error {
	if owner.ProcessStartTime() == 0 {
		return nil
	}
	if owner.Pid() != pid {
		return fmt.Errorf("exact process owner PID %d does not match %d", owner.Pid(), pid)
	}
	return owner.UseProcessHandle(func(fd int) error {
		return validateProcessOwnerFD(
			pid,
			owner.ProcessStartTime(),
			owner.Dev(),
			owner.Ino(),
			fd,
		)
	})
}

func validateProcessOwnerFD(pid app.PID, start, dev, ino uint64, fd int) error {
	if dev == 0 || ino == 0 {
		return validateProcessIdentityFD(pid, start, fd)
	}

	if err := validateProcessExecutableFD(pid, dev, ino, fd); err != nil {
		return err
	}
	if err := validateProcessIdentityFD(pid, start, fd); err != nil {
		return err
	}
	return validateProcessExecutableFD(pid, dev, ino, fd)
}

func validateProcessIdentityFD(pid app.PID, start uint64, fd int) error {
	currentPID, _, currentStart, state, flags, err := procs.ProcessStatWithFlagsFromProcFD(fd)
	if err != nil {
		return fmt.Errorf("reading exact process identity for PID %d: %w", pid, err)
	}
	if currentPID != pid || currentStart != start || processStateDead(state) ||
		flags&linuxTaskFlagExiting != 0 {
		return fmt.Errorf(
			"exact process identity for PID %d is PID %d start %d state %q flags %#x, expected start %d",
			pid, currentPID, currentStart, state, flags, start,
		)
	}
	return nil
}

func validateProcessExecutableFD(pid app.PID, dev, ino uint64, fd int) error {
	currentDev, currentIno, err := procs.ExecutableIdentityFromProcFD(fd)
	if err != nil {
		return fmt.Errorf("reading exact process executable identity for PID %d: %w", pid, err)
	}
	if currentDev != dev || currentIno != ino {
		return fmt.Errorf(
			"exact process executable identity for PID %d is dev %d inode %d, expected dev %d inode %d",
			pid, currentDev, currentIno, dev, ino,
		)
	}
	return nil
}

func processStateDead(state byte) bool {
	return state == 'Z' || state == 'X' || state == 'x'
}
