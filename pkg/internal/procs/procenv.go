// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import (
	"fmt"
	"os"
	"strings"

	"github.com/prometheus/procfs"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

func envStrsToMap(varsStr []string) map[string]string {
	vars := make(map[string]string, len(varsStr))

	for _, s := range varsStr {
		keyVal := strings.SplitN(s, "=", 2)
		if len(keyVal) < 2 {
			continue
		}
		key := strings.TrimSpace(keyVal[0])
		val := strings.TrimSpace(keyVal[1])

		if key != "" && val != "" {
			vars[key] = val
		}
	}

	return vars
}

func EnvVars(pid app.PID) (map[string]string, error) {
	proc, err := procfs.NewProc(int(pid))
	if err != nil {
		return nil, err
	}

	varsStr, err := proc.Environ()
	if err != nil {
		return nil, err
	}

	m := envStrsToMap(varsStr)

	return m, nil
}

// EnvVarsFromProcFD reads the environment through a stable process-directory
// descriptor instead of a reusable numeric /proc path.
func EnvVarsFromProcFD(procFD int) (map[string]string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fd/%d/environ", procFD))
	if err != nil {
		return nil, err
	}
	data = []byte(strings.TrimSuffix(string(data), "\x00"))
	if len(data) == 0 {
		return map[string]string{}, nil
	}
	return envStrsToMap(strings.Split(string(data), "\x00")), nil
}
