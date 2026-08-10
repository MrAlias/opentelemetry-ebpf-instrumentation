// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/internal/procs"
)

func FindINodeForPID(pid app.PID) (dev uint64, ino uint64, err error) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	info, err := os.Stat(exePath)
	if err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return 0, 0, fmt.Errorf("couldn't cast stat into syscall.Stat_t for %s", exePath)
		}
		return stat.Dev, stat.Ino, nil
	}

	return 0, 0, err
}

func openExactProcessELF(
	procFD int,
	afterPinnedOpen func(),
) (*elf.File, uint64, uint64, error) {
	exeFD, err := unix.Openat(procFD, "exe", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("opening pinned process executable: %w", err)
	}
	pinned := os.NewFile(uintptr(exeFD), "exact-process-executable")
	if pinned == nil {
		_ = unix.Close(exeFD)
		return nil, 0, 0, errors.New("creating pinned process executable handle")
	}

	closeRejected := func(elfFile *elf.File, cause error) error {
		var elfCloseErr error
		if elfFile != nil {
			elfCloseErr = elfFile.Close()
		}
		return errors.Join(cause, elfCloseErr, pinned.Close())
	}

	var pinnedStat unix.Stat_t
	if err := unix.Fstat(exeFD, &pinnedStat); err != nil {
		return nil, 0, 0, closeRejected(nil, fmt.Errorf("stating pinned process executable: %w", err))
	}
	dev, ino := pinnedStat.Dev, pinnedStat.Ino
	if dev == 0 || ino == 0 {
		return nil, 0, 0, closeRejected(nil, fmt.Errorf(
			"pinned process executable identity is incomplete: dev=%d inode=%d",
			dev,
			ino,
		))
	}

	if afterPinnedOpen != nil {
		afterPinnedOpen()
	}
	// elf.Open owns a duplicate opened through the still-live pinned descriptor.
	// It therefore cannot switch to a later executable even if the process execs
	// between the open and the live-identity check below.
	elfFile, err := elf.Open(fmt.Sprintf("/proc/self/fd/%d", exeFD))
	if err != nil {
		return nil, 0, 0, closeRejected(nil, fmt.Errorf("opening pinned executable ELF: %w", err))
	}
	if err := validateLiveExecutableIdentity(procFD, dev, ino); err != nil {
		return nil, 0, 0, closeRejected(elfFile, err)
	}
	if err := pinned.Close(); err != nil {
		return nil, 0, 0, errors.Join(err, elfFile.Close())
	}
	return elfFile, dev, ino, nil
}

func validateLiveExecutableIdentity(procFD int, expectedDev, expectedIno uint64) error {
	var liveStat unix.Stat_t
	if err := unix.Fstatat(procFD, "exe", &liveStat, 0); err != nil {
		return fmt.Errorf("stating live process executable: %w", err)
	}
	if liveStat.Dev != expectedDev || liveStat.Ino != expectedIno {
		return fmt.Errorf(
			"process executable changed: live dev=%d inode=%d, pinned dev=%d inode=%d",
			liveStat.Dev,
			liveStat.Ino,
			expectedDev,
			expectedIno,
		)
	}
	return nil
}

func findExecElf(p *services.ProcessInfo, svcID *svc.Attrs) (*exec.FileInfo, error) {
	if p == nil {
		return nil, errors.New("process information is nil")
	}
	processHandle, err := p.TakeProcessHandle()
	if err != nil {
		return nil, fmt.Errorf("can't consume watcher identity for PID=%d: %w", p.Pid, err)
	}
	keepProcessHandle := false
	defer func() {
		if !keepProcessHandle {
			_ = processHandle.Close()
		}
	}()
	exactPID, processStart, state, err := procs.ProcessIdentityFromProcFD(
		int(processHandle.Fd()),
	)
	if err != nil {
		return nil, fmt.Errorf("can't read pinned process identity for PID=%d: %w", p.Pid, err)
	}
	if exactPID != p.Pid || state == 'Z' || state == 'X' || state == 'x' {
		return nil, fmt.Errorf(
			"pinned process identity for PID=%d is PID=%d state=%q",
			p.Pid, exactPID, state,
		)
	}
	if p.ProcessStart == 0 || p.ProcessStart != processStart {
		return nil, fmt.Errorf("PID=%d watcher identity changed before executable inspection", p.Pid)
	}
	// In container environments or K8s, we can't just open the executable exe path, because it might
	// be in the volume of another pod/container. We need to access it through the /proc/<pid>/exe symbolic link
	ns, err := procs.FindNamespaceFromProcFD(int(processHandle.Fd()))
	if err != nil {
		return nil, fmt.Errorf("can't find namespace for PID=%d: %w", p.Pid, err)
	}
	// TODO: allow overriding /proc root folder
	proExeLinkPath := fmt.Sprintf("/proc/self/fd/%d/exe", processHandle.Fd())
	elfFile, dev, ino, err := openExactProcessELF(int(processHandle.Fd()), nil)
	if err != nil {
		return nil, fmt.Errorf("can't open ELF file in %s: %w", proExeLinkPath, err)
	}
	keepELF := false
	defer func() {
		if !keepELF {
			_ = elfFile.Close()
		}
	}()

	envVars, err := procs.EnvVarsFromProcFD(int(processHandle.Fd()))
	if err != nil {
		return nil, err
	}
	currentPID, currentStart, currentState, err := procs.ProcessIdentityFromProcFD(
		int(processHandle.Fd()),
	)
	if err != nil || currentPID != p.Pid || currentStart != processStart ||
		currentState == 'Z' || currentState == 'X' || currentState == 'x' {
		return nil, fmt.Errorf("PID=%d changed during executable inspection", p.Pid)
	}
	if err := validateLiveExecutableIdentity(int(processHandle.Fd()), dev, ino); err != nil {
		return nil, fmt.Errorf("PID=%d changed executable during inspection: %w", p.Pid, err)
	}

	fi := exec.New(exec.Init{
		Service:           *svcID,
		CmdExePath:        p.ExePath,
		ProExeLinkPath:    proExeLinkPath,
		ELF:               elfFile,
		Pid:               p.Pid,
		Ppid:              p.PPid,
		Dev:               dev,
		Ino:               ino,
		Ns:                ns,
		ProcessStart:      processStart,
		ProcessInstanceID: p.ProcessInstanceID,
		ProcessHandle:     processHandle,
	})
	fi.ApplyEnvVariables(envVars)
	keepELF = true
	keepProcessHandle = true
	return fi, nil
}
