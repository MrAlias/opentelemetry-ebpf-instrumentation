// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

func readProcessInfo(pp ProcessAttrs) (*services.ProcessInfo, error) {
	if pp.processIdentity == nil {
		return nil, fmt.Errorf("stable watcher identity for PID %d is unavailable", pp.pid)
	}
	handle, err := pp.processIdentity.duplicateFile()
	if err != nil {
		return nil, fmt.Errorf("duplicating watcher identity for PID %d: %w", pp.pid, err)
	}
	keepHandle := false
	defer func() {
		if !keepHandle {
			_ = handle.Close()
		}
	}()

	pid, ppid, start, state, err := procs.ProcessStatFromProcFD(int(handle.Fd()))
	if err != nil {
		return nil, fmt.Errorf("reading watcher identity for PID %d: %w", pp.pid, err)
	}
	if pid != pp.pid || pp.processStart == 0 || start != pp.processStart || processStateDead(state) {
		return nil, fmt.Errorf(
			"watcher identity for PID %d is PID %d start %d state %q",
			pp.pid, pid, start, state,
		)
	}

	procRoot := fmt.Sprintf("/proc/self/fd/%d", handle.Fd())
	exePath, err := os.Readlink(procRoot + "/exe")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			exePath = "unknown"
		} else {
			return nil, fmt.Errorf("reading exact executable for PID %d: %w", pp.pid, err)
		}
	}
	var cmdLine string
	if data, cmdErr := os.ReadFile(procRoot + "/cmdline"); cmdErr == nil {
		cmdLine = strings.TrimSpace(string(bytes.ReplaceAll(data, []byte{0}, []byte{' '})))
		// The command line includes the process name; selectors match only args.
		_, cmdLine, _ = strings.Cut(cmdLine, " ")
	}

	currentPID, currentPPID, currentStart, currentState, err := procs.ProcessStatFromProcFD(int(handle.Fd()))
	if err != nil || currentPID != pid || currentPPID != ppid ||
		currentStart != start || processStateDead(currentState) {
		return nil, fmt.Errorf("PID %d changed while reading exact process information", pp.pid)
	}

	keepHandle = true
	return &services.ProcessInfo{
		Pid:               pid,
		PPid:              ppid,
		ExePath:           exePath,
		CmdArgs:           cmdLine,
		OpenPorts:         pp.openPorts,
		ProcessStart:      start,
		ProcessInstanceID: services.NewProcessInstanceID(),
		ProcessHandle:     services.NewProcessHandle(handle),
	}, nil
}
