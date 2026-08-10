// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package exec

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/procs"
)

func TestProcessHandleDuplicateSurvivesFileInfoRetirement(t *testing.T) {
	handle, err := os.Open("/proc/self")
	require.NoError(t, err)
	fi := New(Init{ProcessHandle: handle})

	duplicate := -1
	require.NoError(t, fi.UseProcessHandle(func(fd int) error {
		var duplicateErr error
		duplicate, duplicateErr = unix.FcntlInt(
			uintptr(fd), unix.F_DUPFD_CLOEXEC, 0,
		)
		return duplicateErr
	}))
	require.GreaterOrEqual(t, duplicate, 0)
	t.Cleanup(func() { require.NoError(t, unix.Close(duplicate)) })

	require.NoError(t, fi.CloseProcessHandle())
	require.NoError(t, fi.CloseProcessHandle(), "retirement must be idempotent")
	pid, _, state, err := procs.ProcessIdentityFromProcFD(duplicate)
	require.NoError(t, err)
	assert.EqualValues(t, os.Getpid(), pid)
	assert.NotContains(t, []byte{'Z', 'X', 'x'}, state)
	require.ErrorContains(t, fi.UseProcessHandle(func(int) error { return nil }),
		"stable process handle is unavailable")
}

func TestProcessHandleCloseWaitsForConcurrentUse(t *testing.T) {
	handle, err := os.Open("/proc/self")
	require.NoError(t, err)
	fi := New(Init{ProcessHandle: handle})

	entered := make(chan struct{})
	release := make(chan struct{})
	useResult := make(chan error, 1)
	go func() {
		useResult <- fi.UseProcessHandle(func(int) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	closeResult := make(chan error, 1)
	go func() { closeResult <- fi.CloseProcessHandle() }()
	select {
	case err := <-closeResult:
		t.Fatalf("process handle closed during active use: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	require.NoError(t, <-useResult)
	require.NoError(t, <-closeResult)
}
