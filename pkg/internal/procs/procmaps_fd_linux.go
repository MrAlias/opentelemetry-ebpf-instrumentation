// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import (
	"bufio"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"
)

// FindExeLoadBiasFromProcFD returns the executable load bias through an open
// /proc/<pid> directory descriptor, preserving the exact process lifetime and
// requiring the live executable to match expectedDev and expectedIno.
func FindExeLoadBiasFromProcFD(
	procFD int,
	expectedDev, expectedIno uint64,
) (uint64, error) {
	return findExeLoadBiasFromProcFD(
		procFD,
		expectedDev,
		expectedIno,
		executableIdentityFromProcFD,
	)
}

type executableIdentity struct {
	dev uint64
	ino uint64
}

type executableIdentityLookup func(int) (executableIdentity, error)

func findExeLoadBiasFromProcFD(
	procFD int,
	expectedDev, expectedIno uint64,
	liveExecutableIdentity executableIdentityLookup,
) (loadBias uint64, resultErr error) {
	if expectedDev == 0 || expectedIno == 0 {
		return 0, fmt.Errorf(
			"expected executable identity is incomplete: dev=%d inode=%d",
			expectedDev, expectedIno,
		)
	}

	beforePID, beforeStart, beforeState, err := ProcessIdentityFromProcFD(procFD)
	if err != nil {
		return 0, fmt.Errorf("read process identity before load-bias resolution: %w", err)
	}
	if deadProcessState(beforeState) {
		return 0, fmt.Errorf("process %d is no longer live", beforePID)
	}
	beforeExecutable, err := liveExecutableIdentity(procFD)
	if err != nil {
		return 0, fmt.Errorf("read executable identity before load-bias resolution: %w", err)
	}
	if err := validateExecutableIdentity(
		"before load-bias resolution",
		beforeExecutable,
		expectedDev,
		expectedIno,
	); err != nil {
		return 0, err
	}

	exePath, err := readProcLinkAt(procFD, "exe")
	if err != nil {
		return 0, fmt.Errorf("read executable link: %w", err)
	}
	exeFileHandle, err := openProcFileAt(procFD, "exe")
	if err != nil {
		return 0, fmt.Errorf("open executable: %w", err)
	}
	pinnedExecutable, err := executableIdentityFromFile(exeFileHandle)
	if err != nil {
		return 0, fmt.Errorf(
			"read opened executable identity: %w",
			errors.Join(err, exeFileHandle.Close()),
		)
	}
	if err := validateExecutableIdentity(
		"after opening executable",
		pinnedExecutable,
		expectedDev,
		expectedIno,
	); err != nil {
		return 0, errors.Join(err, exeFileHandle.Close())
	}
	exeFile, err := elf.NewFile(exeFileHandle)
	if err != nil {
		return 0, fmt.Errorf(
			"open executable ELF: %w",
			errors.Join(err, exeFileHandle.Close()),
		)
	}
	defer func() {
		resultErr = errors.Join(resultErr, exeFile.Close(), exeFileHandle.Close())
	}()

	mapsFile, err := openProcFileAt(procFD, "maps")
	if err != nil {
		return 0, fmt.Errorf("open process maps: %w", err)
	}
	maps, err := readAndCloseProcMapsForLoadBias(mapsFile)
	if err != nil {
		return 0, err
	}

	loadBias, err = exeLoadBias(exePath, maps, exeFile.Progs)
	if err != nil {
		return 0, err
	}
	afterExecutable, err := liveExecutableIdentity(procFD)
	if err != nil {
		return 0, fmt.Errorf("read executable identity after load-bias resolution: %w", err)
	}
	if err := validateExecutableIdentity(
		"after load-bias resolution",
		afterExecutable,
		expectedDev,
		expectedIno,
	); err != nil {
		return 0, err
	}
	afterPID, afterStart, afterState, err := ProcessIdentityFromProcFD(procFD)
	if err != nil {
		return 0, fmt.Errorf("read process identity after load-bias resolution: %w", err)
	}
	if afterPID != beforePID || afterStart != beforeStart || deadProcessState(afterState) {
		return 0, errors.New("process identity changed during load-bias resolution")
	}

	return loadBias, nil
}

func executableIdentityFromProcFD(procFD int) (executableIdentity, error) {
	dev, ino, err := ExecutableIdentityFromProcFD(procFD)
	return executableIdentity{dev: dev, ino: ino}, err
}

// ExecutableIdentityFromProcFD returns the device and inode of the executable
// currently referenced by an open /proc/<pid> directory descriptor.
func ExecutableIdentityFromProcFD(procFD int) (dev, ino uint64, err error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(procFD, "exe", &stat, 0); err != nil {
		return 0, 0, err
	}
	return stat.Dev, stat.Ino, nil
}

func executableIdentityFromFile(file *os.File) (executableIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return executableIdentity{}, err
	}
	return executableIdentity{dev: stat.Dev, ino: stat.Ino}, nil
}

func validateExecutableIdentity(
	stage string,
	actual executableIdentity,
	expectedDev, expectedIno uint64,
) error {
	if actual.dev == expectedDev && actual.ino == expectedIno {
		return nil
	}
	return fmt.Errorf(
		"executable identity mismatch %s: dev=%d inode=%d, expected dev=%d inode=%d",
		stage,
		actual.dev,
		actual.ino,
		expectedDev,
		expectedIno,
	)
}

func openProcFileAt(procFD int, name string) (*os.File, error) {
	fd, err := unix.Openat(procFD, name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("create file for %s", name)
	}
	return file, nil
}

func readProcLinkAt(procFD int, name string) (string, error) {
	buf := make([]byte, unix.PathMax)
	n, err := unix.Readlinkat(procFD, name, buf)
	if err != nil {
		return "", err
	}
	if n == len(buf) {
		return "", fmt.Errorf("%s link target is too long", name)
	}
	return string(buf[:n]), nil
}

func readProcMapsForLoadBias(reader io.Reader) ([]*procfs.ProcMap, error) {
	var maps []*procfs.ProcMap
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			return nil, errors.New("truncated proc maps entry")
		}
		startText, _, ok := strings.Cut(fields[0], "-")
		if !ok {
			return nil, fmt.Errorf("invalid proc maps address %q", fields[0])
		}
		start, err := strconv.ParseUint(startText, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("parse proc maps start address: %w", err)
		}
		offset, err := strconv.ParseInt(fields[2], 16, 64)
		if err != nil {
			return nil, fmt.Errorf("parse proc maps offset: %w", err)
		}
		pathname := ""
		if len(fields) > 5 {
			pathname = strings.Join(fields[5:], " ")
		}
		maps = append(maps, &procfs.ProcMap{
			StartAddr: uintptr(start),
			Offset:    offset,
			Pathname:  pathname,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return maps, nil
}

func readAndCloseProcMapsForLoadBias(reader io.ReadCloser) ([]*procfs.ProcMap, error) {
	maps, readErr := readProcMapsForLoadBias(reader)
	if readErr != nil {
		readErr = fmt.Errorf("read process maps: %w", readErr)
	}
	closeErr := reader.Close()
	if closeErr != nil {
		closeErr = fmt.Errorf("close process maps: %w", closeErr)
	}
	return maps, errors.Join(readErr, closeErr)
}

func deadProcessState(state byte) bool {
	return state == 'Z' || state == 'X' || state == 'x'
}
