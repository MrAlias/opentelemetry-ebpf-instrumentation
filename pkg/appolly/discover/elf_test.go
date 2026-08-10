// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package discover

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

func TestFindINodeForPID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("skipping FindINodeForPID test on non-linux platform")
	}

	// Use our own PID — guaranteed to exist and have a valid /proc/<pid>/exe
	self := app.PID(os.Getpid())

	dev, ino, err := FindINodeForPID(self)
	if err != nil {
		t.Fatalf("FindINodeForPID(%d) returned error: %v", self, err)
	}
	if dev == 0 {
		t.Errorf("FindINodeForPID(%d) returned dev 0, expected a non-zero device", self)
	}
	if ino == 0 {
		t.Errorf("FindINodeForPID(%d) returned inode 0, expected a non-zero inode", self)
	}

	// A non-existent PID should return an error
	_, _, err = FindINodeForPID(app.PID(999999999))
	if err == nil {
		t.Error("FindINodeForPID with invalid PID should return an error")
	}
}

func TestFindExecElfPinsAuthoritativeProcessIdentity(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("stable proc-directory process handles are Linux-specific")
	}
	pid := app.PID(os.Getpid())
	start, err := procs.ProcessStartTime(pid)
	if err != nil {
		t.Fatalf("reading current process start: %v", err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("reading current executable: %v", err)
	}
	handle, err := os.Open(fmt.Sprintf("/proc/%d", pid))
	if err != nil {
		t.Fatalf("opening current process directory: %v", err)
	}
	handoff := services.NewProcessHandle(handle)
	const processInstanceID = uint64(0x1234)
	process := &services.ProcessInfo{
		Pid:               pid,
		PPid:              app.PID(os.Getppid()),
		ExePath:           executable,
		ProcessStart:      start,
		ProcessInstanceID: processInstanceID,
		ProcessHandle:     handoff,
	}
	fi, err := findExecElf(process, &svc.Attrs{})
	if err != nil {
		t.Fatalf("constructing pinned FileInfo: %v", err)
	}
	t.Cleanup(func() {
		if fi.ELF() != nil {
			_ = fi.ELF().Close()
		}
		_ = fi.CloseProcessHandle()
	})

	err = fi.UseProcessHandle(func(fd int) error {
		exactPID, exactStart, _, identityErr := procs.ProcessIdentityFromProcFD(fd)
		if identityErr != nil {
			return identityErr
		}
		if exactPID != pid || exactStart != start {
			t.Fatalf("pinned identity = (%d, %d), want (%d, %d)",
				exactPID, exactStart, pid, start)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("using pinned process handle: %v", err)
	}
	if _, err := handoff.TakeFile(); err == nil {
		t.Fatal("watcher handle handoff should be consumed exactly once")
	}
	if fi.ProcessInstanceID() != processInstanceID {
		t.Fatalf("process instance ID = %d, want %d", fi.ProcessInstanceID(), processInstanceID)
	}
}

func TestFindExecElfClosesConsumedHandleOnIdentityMismatch(t *testing.T) {
	pid := app.PID(os.Getpid())
	handle, err := os.Open(fmt.Sprintf("/proc/%d", pid))
	if err != nil {
		t.Fatalf("opening current process directory: %v", err)
	}
	_, err = findExecElf(&services.ProcessInfo{
		Pid:           pid,
		ProcessStart:  1,
		ProcessHandle: services.NewProcessHandle(handle),
	}, &svc.Attrs{})
	if err == nil {
		t.Fatal("expected watcher identity mismatch")
	}
	if _, statErr := handle.Stat(); statErr == nil {
		t.Fatal("rejected watcher handle remains open")
	}
}

func TestOpenExactProcessELFRejectsExecutableSwapAfterPin(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("reading current executable: %v", err)
	}
	alternative := "/bin/sh"
	selfInfo, err := os.Stat(self)
	if err != nil {
		t.Fatalf("stating current executable: %v", err)
	}
	alternativeInfo, err := os.Stat(alternative)
	if err != nil {
		t.Fatalf("stating alternative executable: %v", err)
	}
	if os.SameFile(selfInfo, alternativeInfo) {
		t.Skip("test needs two distinct executable files")
	}

	procDirPath := t.TempDir()
	exeLink := procDirPath + "/exe"
	if err := os.Symlink(self, exeLink); err != nil {
		t.Fatalf("creating initial executable link: %v", err)
	}
	procDir, err := os.Open(procDirPath)
	if err != nil {
		t.Fatalf("opening fake process directory: %v", err)
	}
	t.Cleanup(func() { _ = procDir.Close() })

	elfFile, _, _, err := openExactProcessELF(int(procDir.Fd()), func() {
		if removeErr := os.Remove(exeLink); removeErr != nil {
			t.Fatalf("removing initial executable link: %v", removeErr)
		}
		if linkErr := os.Symlink(alternative, exeLink); linkErr != nil {
			t.Fatalf("creating replacement executable link: %v", linkErr)
		}
	})
	if elfFile != nil {
		_ = elfFile.Close()
		t.Fatal("executable swap returned a mixed ELF identity")
	}
	if err == nil || !strings.Contains(err.Error(), "process executable changed") {
		t.Fatalf("executable swap error = %v", err)
	}
}
