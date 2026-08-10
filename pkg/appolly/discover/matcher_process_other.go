// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/shirou/gopsutil/v4/process"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/services"
)

func readProcessInfo(pp ProcessAttrs) (*services.ProcessInfo, error) {
	proc, err := process.NewProcess(int32(pp.pid))
	if err != nil {
		return nil, fmt.Errorf("can't read process: %w", err)
	}
	ppid, _ := proc.Ppid()
	exePath, err := proc.Exe()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			exePath = "unknown"
		} else {
			return nil, fmt.Errorf("can't read process information: %w", err)
		}
	}
	cmdLine, err := proc.Cmdline()
	if err == nil {
		_, cmdLine, _ = strings.Cut(cmdLine, " ")
	}
	return &services.ProcessInfo{
		Pid:               app.PID(proc.Pid),
		PPid:              app.PID(ppid),
		ExePath:           exePath,
		CmdArgs:           cmdLine,
		OpenPorts:         pp.openPorts,
		ProcessStart:      pp.processStart,
		ProcessInstanceID: services.NewProcessInstanceID(),
	}, nil
}
