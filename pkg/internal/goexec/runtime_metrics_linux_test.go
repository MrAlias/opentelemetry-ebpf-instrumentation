// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package goexec

import (
	"debug/elf"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

func TestRuntimeMetricLoadBiasUsesExactOwnerHandle(t *testing.T) {
	procDir, err := os.Open("/proc/self")
	require.NoError(t, err)
	pid, start, _, err := procs.ProcessIdentityFromProcFD(int(procDir.Fd()))
	require.NoError(t, err)
	dev, ino := currentExecutableDevIno(t)

	legacyOwner := exec.New(exec.Init{Pid: pid, Dev: dev, Ino: ino})
	legacy, err := runtimeMetricLoadBias(legacyOwner, dev, ino)
	require.NoError(t, err)

	exactOwner := exec.New(exec.Init{
		Pid:           pid,
		Dev:           dev,
		Ino:           ino,
		ProcessStart:  start,
		ProcessHandle: procDir,
	})
	t.Cleanup(func() { require.NoError(t, exactOwner.CloseProcessHandle()) })
	exact, err := runtimeMetricLoadBias(exactOwner, dev, ino)
	require.NoError(t, err)

	assert.Equal(t, legacy, exact)
}

func TestRuntimeMetricLoadBiasRejectsMismatchedExactOwner(t *testing.T) {
	procDir, err := os.Open("/proc/self")
	require.NoError(t, err)
	pid, start, _, err := procs.ProcessIdentityFromProcFD(int(procDir.Fd()))
	require.NoError(t, err)
	require.NoError(t, procDir.Close())
	dev, ino := currentExecutableDevIno(t)

	tests := []struct {
		name      string
		pid       app.PID
		start     uint64
		wantError string
	}{
		{
			name:      "PID",
			pid:       pid + 1,
			start:     start,
			wantError: "not owner PID",
		},
		{
			name:      "start time",
			pid:       pid,
			start:     start + 1,
			wantError: "not owner start",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handle, err := os.Open("/proc/self")
			require.NoError(t, err)
			owner := exec.New(exec.Init{
				Pid:           tc.pid,
				Dev:           dev,
				Ino:           ino,
				ProcessStart:  tc.start,
				ProcessHandle: handle,
			})
			t.Cleanup(func() { require.NoError(t, owner.CloseProcessHandle()) })

			_, err = runtimeMetricLoadBias(owner, dev, ino)
			require.ErrorContains(t, err, tc.wantError)
		})
	}
}

func TestRuntimeMetricLoadBiasDoesNotFallbackForExactOwnerWithoutHandle(t *testing.T) {
	dev, ino := currentExecutableDevIno(t)
	exactOwner := exec.New(exec.Init{
		Pid:          app.PID(os.Getpid()),
		Dev:          dev,
		Ino:          ino,
		ProcessStart: 1,
	})

	_, err := runtimeMetricLoadBias(exactOwner, dev, ino)
	require.ErrorContains(t, err, "stable process handle is unavailable")
}

func TestResolveRuntimeMetricSymbolsRejectsSymbolSourceOwnerMismatch(t *testing.T) {
	dev, ino := currentExecutableDevIno(t)
	symbolSource := exec.New(exec.Init{
		ELF: &elf.File{},
		Dev: dev,
		Ino: ino + 1,
	})
	exactOwner := exec.New(exec.Init{Dev: dev, Ino: ino})

	_, err := ResolveRuntimeMetricSymbols(symbolSource, exactOwner)
	require.ErrorContains(t, err, "does not match exact owner")
}

func currentExecutableDevIno(t *testing.T) (uint64, uint64) {
	t.Helper()
	info, err := os.Stat("/proc/self/exe")
	require.NoError(t, err)
	stat, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	return stat.Dev, stat.Ino
}
