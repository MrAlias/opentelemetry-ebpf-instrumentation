// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpfcommon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

func TestNamespacedPIDsForOwnerUsesExactProcessHandle(t *testing.T) {
	pid, owner := currentProcessOwner(t)

	aliases, err := NamespacedPIDsForOwner(pid, owner)
	require.NoError(t, err)
	require.NotEmpty(t, aliases)
	require.Equal(t, pid, aliases[0])
}

func TestValidateProcessOwnerUsesExecutableIdentity(t *testing.T) {
	pid, owner := currentProcessOwner(t)

	require.NoError(t, ValidateProcessOwner(pid, owner))
}

func TestValidateProcessOwnerRejectsExecutableMismatch(t *testing.T) {
	const (
		pid   = app.PID(42)
		start = uint64(1234)
	)
	owner, procDir, replacement := fakeProcessOwner(t, pid, start)
	replaceSymlink(t, filepath.Join(procDir, "exe"), replacement)

	err := ValidateProcessOwner(pid, owner)
	require.ErrorContains(t, err, "exact process executable identity")
}

func TestValidateProcessOwnerAllowsIncompleteExecutableIdentity(t *testing.T) {
	const (
		pid   = app.PID(42)
		start = uint64(1234)
	)
	_, procDir, replacement := fakeProcessOwner(t, pid, start)
	replaceSymlink(t, filepath.Join(procDir, "exe"), replacement)
	replacementDev, replacementIno := fileIdentity(t, replacement)

	for _, test := range []struct {
		name string
		dev  uint64
		ino  uint64
	}{
		{name: "zero device", ino: replacementIno + 1},
		{name: "zero inode", dev: replacementDev + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			handle, err := os.Open(procDir)
			require.NoError(t, err)
			owner := exec.New(exec.Init{
				Pid:           pid,
				ProcessStart:  start,
				Dev:           test.dev,
				Ino:           test.ino,
				ProcessHandle: handle,
			})
			t.Cleanup(func() { require.NoError(t, owner.CloseProcessHandle()) })

			require.NoError(t, ValidateProcessOwner(pid, owner))
		})
	}
}

func TestNamespacedPIDsForOwnerRejectsExecutableSwapDuringRead(t *testing.T) {
	const (
		pid   = app.PID(42)
		start = uint64(1234)
	)
	owner, procDir, replacement := fakeProcessOwner(t, pid, start)
	statusPath := filepath.Join(procDir, "status")
	require.NoError(t, unix.Mkfifo(statusPath, 0o600))

	type result struct {
		aliases []app.PID
		err     error
	}
	resultCh := make(chan result, 1)
	go func() {
		aliases, err := NamespacedPIDsForOwner(pid, owner)
		resultCh <- result{aliases: aliases, err: err}
	}()

	type writerResult struct {
		file *os.File
		err  error
	}
	writerCh := make(chan writerResult, 1)
	go func() {
		writer, err := os.OpenFile(statusPath, os.O_WRONLY, 0)
		writerCh <- writerResult{file: writer, err: err}
	}()

	var writer *os.File
	select {
	case got := <-resultCh:
		unblockFIFO(t, statusPath)
		opened := <-writerCh
		if opened.file != nil {
			require.NoError(t, opened.file.Close())
		}
		require.NoError(t, got.err)
		t.Fatal("namespaced PID lookup returned before opening status")
	case opened := <-writerCh:
		require.NoError(t, opened.err)
		writer = opened.file
	case <-time.After(5 * time.Second):
		unblockFIFO(t, statusPath)
		t.Fatal("timed out waiting for namespaced PID status read")
	}

	replaceSymlink(t, filepath.Join(procDir, "exe"), replacement)
	_, err := fmt.Fprintf(writer, "NSpid:\t%d\t7\n", pid)
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	select {
	case got := <-resultCh:
		require.Nil(t, got.aliases)
		require.ErrorContains(t, got.err, "exact process executable identity")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for namespaced PID lookup")
	}
}

func TestNamespacedPIDsForOwnerRejectsMismatchedExactHandle(t *testing.T) {
	pid := app.PID(os.Getpid())
	start, err := procs.ProcessStartTime(pid)
	require.NoError(t, err)
	handle, err := os.Open("/proc/self")
	require.NoError(t, err)
	owner := exec.New(exec.Init{Pid: pid + 1, ProcessStart: start, ProcessHandle: handle})
	t.Cleanup(func() { require.NoError(t, owner.CloseProcessHandle()) })

	_, err = NamespacedPIDsForOwner(pid+1, owner)
	require.ErrorContains(t, err, "exact process identity")
}

func TestValidateNamespacedPIDAliasesFailsClosed(t *testing.T) {
	const pid = app.PID(42)

	require.ErrorContains(t, validateNamespacedPIDAliases(pid, nil), "no namespace aliases")
	require.ErrorContains(t,
		validateNamespacedPIDAliases(pid, []app.PID{41, 7}),
		"outer namespace alias 41",
	)
	require.NoError(t, validateNamespacedPIDAliases(pid, []app.PID{pid, 7}))
}

func currentProcessOwner(t *testing.T) (app.PID, *exec.FileInfo) {
	t.Helper()
	pid := app.PID(os.Getpid())
	start, err := procs.ProcessStartTime(pid)
	require.NoError(t, err)
	handle, err := os.Open("/proc/self")
	require.NoError(t, err)
	dev, ino, err := procs.ExecutableIdentityFromProcFD(int(handle.Fd()))
	require.NoError(t, err)
	owner := exec.New(exec.Init{
		Pid:           pid,
		ProcessStart:  start,
		Dev:           dev,
		Ino:           ino,
		ProcessHandle: handle,
	})
	t.Cleanup(func() { require.NoError(t, owner.CloseProcessHandle()) })
	return pid, owner
}

func fakeProcessOwner(
	t *testing.T,
	pid app.PID,
	start uint64,
) (*exec.FileInfo, string, string) {
	t.Helper()
	procDir := t.TempDir()
	executable := filepath.Join(procDir, "executable")
	replacement := filepath.Join(procDir, "replacement")
	require.NoError(t, os.WriteFile(executable, []byte("first"), 0o600))
	require.NoError(t, os.WriteFile(replacement, []byte("second"), 0o600))
	require.NoError(t, os.Symlink(executable, filepath.Join(procDir, "exe")))
	stat := fmt.Sprintf(
		"%d (fake process) S 1%s %d\n",
		pid,
		strings.Repeat(" 0", 17),
		start,
	)
	require.NoError(t, os.WriteFile(filepath.Join(procDir, "stat"), []byte(stat), 0o600))
	handle, err := os.Open(procDir)
	require.NoError(t, err)
	dev, ino := fileIdentity(t, executable)
	owner := exec.New(exec.Init{
		Pid:           pid,
		ProcessStart:  start,
		Dev:           dev,
		Ino:           ino,
		ProcessHandle: handle,
	})
	t.Cleanup(func() { require.NoError(t, owner.CloseProcessHandle()) })
	return owner, procDir, replacement
}

func fileIdentity(t *testing.T, path string) (uint64, uint64) {
	t.Helper()
	var stat unix.Stat_t
	require.NoError(t, unix.Stat(path, &stat))
	return stat.Dev, stat.Ino
}

func replaceSymlink(t *testing.T, link, target string) {
	t.Helper()
	replacementLink := link + ".replacement"
	require.NoError(t, os.Symlink(target, replacementLink))
	require.NoError(t, os.Rename(replacementLink, link))
}

func unblockFIFO(t *testing.T, path string) {
	t.Helper()
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	require.NoError(t, err)
	require.NoError(t, unix.Close(fd))
}
