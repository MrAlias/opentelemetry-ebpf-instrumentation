// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

var readProcessIdentityFromProcFD = procs.ProcessIdentityFromProcFD

func currentTime() uint64 {
	var ts unix.Timespec

	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return 0
	}

	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}

func processIdentityForPID(pid app.PID) (*processIdentityLease, error) {
	handle, err := os.Open(fmt.Sprintf("/proc/%d", pid))
	if err != nil {
		return nil, fmt.Errorf("opening stable process identity for PID %d: %w", pid, err)
	}
	keepHandle := false
	defer func() {
		if !keepHandle {
			_ = handle.Close()
		}
	}()

	exactPID, start, state, err := readProcessIdentityFromProcFD(int(handle.Fd()))
	if err != nil {
		return nil, fmt.Errorf("reading stable process identity for PID %d: %w", pid, err)
	}
	if exactPID != pid || processStateDead(state) {
		return nil, fmt.Errorf(
			"stable process identity for PID %d is PID %d state %q",
			pid, exactPID, state,
		)
	}
	info, err := handle.Stat()
	if err != nil {
		return nil, fmt.Errorf("stating stable process identity for PID %d: %w", pid, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Ino == 0 {
		return nil, fmt.Errorf("reading proc-directory inode for PID %d", pid)
	}
	// Fail closed if the process exited while its directory metadata was read.
	currentPID, currentStart, currentState, err := readProcessIdentityFromProcFD(int(handle.Fd()))
	if err != nil || currentPID != exactPID || currentStart != start || processStateDead(currentState) {
		return nil, fmt.Errorf("PID %d changed while capturing stable process identity", pid)
	}

	keepHandle = true
	return newProcessIdentityLease(handle, pid, start, stat.Dev, stat.Ino), nil
}

func duplicateProcessHandleFD(sourceFD uintptr) (*os.File, error) {
	fd, err := unix.FcntlInt(sourceFD, unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("duplicating stable process handle: %w", err)
	}
	duplicate := os.NewFile(uintptr(fd), "stable-process-identity")
	if duplicate == nil {
		_ = unix.Close(fd)
		return nil, errors.New("creating duplicated stable process handle")
	}
	return duplicate, nil
}

func validateProcessIdentity(identity *processIdentityLease) error {
	if identity == nil {
		return errors.New("stable process identity is unavailable")
	}
	expectedPID, expectedStart, _, _, ok := identity.metadata()
	if !ok {
		return errors.New("stable process identity is closed")
	}
	return identity.useFile(func(fd int) error {
		pid, start, state, err := readProcessIdentityFromProcFD(fd)
		if err != nil {
			return err
		}
		if pid != expectedPID || start != expectedStart || processStateDead(state) {
			return fmt.Errorf(
				"stable process identity for PID %d is PID %d start %d state %q",
				expectedPID, pid, start, state,
			)
		}
		return nil
	})
}

func processStateDead(state byte) bool {
	return state == 'Z' || state == 'X' || state == 'x'
}
