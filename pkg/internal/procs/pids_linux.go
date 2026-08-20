// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/prometheus/procfs"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

func FindNamespace(pid app.PID) (uint32, error) {
	pidPath := fmt.Sprintf("/proc/%d/ns/pid", pid)
	f, err := os.Open(pidPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open(/proc/%d/ns/pid): %w", pid, err)
	}

	defer f.Close()

	// read the value of the symbolic link
	buf := make([]byte, syscall.PathMax)
	n, err := syscall.Readlink(pidPath, buf)
	if err != nil {
		return 0, fmt.Errorf("failed to read symlink(/proc/%d/ns/pid): %w", pid, err)
	}

	return parsePIDNamespaceLink(string(buf[:n]))
}

// FindNamespaceFromProcFD reads the PID namespace through a stable process
// directory descriptor, so a reused numeric PID cannot redirect the lookup.
func FindNamespaceFromProcFD(procFD int) (uint32, error) {
	buf := make([]byte, syscall.PathMax)
	n, err := unix.Readlinkat(procFD, "ns/pid", buf)
	if err != nil {
		return 0, fmt.Errorf("reading stable PID namespace link: %w", err)
	}
	return parsePIDNamespaceLink(string(buf[:n]))
}

func parsePIDNamespaceLink(nsPid string) (uint32, error) {
	logger := slog.With("component", "pids.Tracer")
	// extract u32 from the format pid:[nnnnn]
	start := strings.LastIndex(nsPid, "[")
	end := strings.LastIndex(nsPid, "]")

	logger.Debug("Found namespace", "nsPid", nsPid)

	if start >= 0 && end >= 0 && end > start {
		npid, err := strconv.ParseUint(nsPid[start+1:end], 10, 32)
		if err != nil {
			return 0, fmt.Errorf("failed to parse ns pid %w", err)
		}

		return uint32(npid), nil
	}

	return 0, fmt.Errorf("couldn't find ns pid in the symlink [%s]", nsPid)
}

func FindNamespacedPids(pid app.PID) ([]app.PID, error) {
	statusPath := fmt.Sprintf("/proc/%d/status", pid)
	f, err := os.Open(statusPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open(/proc/%d/status): %w", pid, err)
	}
	defer f.Close()
	return findNamespacedPIDs(f)
}

// FindNamespacedPidsFromProcFD reads namespace aliases through a stable
// process-directory descriptor. It cannot be redirected by numeric PID reuse.
func FindNamespacedPidsFromProcFD(procFD int) (result []app.PID, resultErr error) {
	fd, err := unix.Openat(procFD, "status", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open stable process status: %w", err)
	}
	f := os.NewFile(uintptr(fd), "exact-process-status")
	if f == nil {
		_ = unix.Close(fd)
		return nil, errors.New("creating exact process status handle")
	}
	defer func() { resultErr = errors.Join(resultErr, f.Close()) }()
	return findNamespacedPIDs(f)
}

func findNamespacedPIDs(reader io.Reader) ([]app.PID, error) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "NSpid:") {
			l := line[6:]
			parts := strings.Split(l, "\t")
			result := make([]app.PID, 0)

			for _, p := range parts {
				if len(p) == 0 {
					continue
				}

				id, err := strconv.ParseUint(p, 10, 32)
				if err != nil {
					return nil, fmt.Errorf("failed to parse namespaced pid %w", err)
				}

				result = append(result, app.PID(id))
			}

			return result, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading namespaced pids: %w", err)
	}

	return nil, nil
}

// ProcessStartTime returns /proc/<pid>/stat field 22 in raw clock ticks. The
// raw value is stable for one process lifetime and is used only as an identity
// token; callers must not interpret it as wall-clock time.
func ProcessStartTime(pid app.PID) (uint64, error) {
	proc, err := procfs.NewProc(int(pid))
	if err != nil {
		return 0, fmt.Errorf("opening /proc/%d: %w", pid, err)
	}
	stat, err := proc.Stat()
	if err != nil {
		return 0, fmt.Errorf("reading /proc/%d/stat: %w", pid, err)
	}
	if stat.Starttime == 0 {
		return 0, fmt.Errorf("reading /proc/%d/stat: zero process start time", pid)
	}
	return stat.Starttime, nil
}

// ProcessIdentityFromProcFD reads identity from a stable /proc/<pid>
// directory descriptor. Unlike a numeric /proc path, the descriptor never
// follows a later process that reuses the PID.
func ProcessIdentityFromProcFD(
	procFD int,
) (pid app.PID, start uint64, state byte, resultErr error) {
	pid, _, start, state, resultErr = ProcessStatFromProcFD(procFD)
	return pid, start, state, resultErr
}

// ProcessStatFromProcFD reads the identity and parent relationship from a
// stable process-directory descriptor.
func ProcessStatFromProcFD(
	procFD int,
) (pid, ppid app.PID, start uint64, state byte, resultErr error) {
	pid, ppid, start, state, _, resultErr = ProcessStatWithFlagsFromProcFD(procFD)
	return
}

// ProcessStatWithFlagsFromProcFD reads the identity, parent relationship, and
// Linux task flags from a stable process-directory descriptor.
func ProcessStatWithFlagsFromProcFD(
	procFD int,
) (pid, ppid app.PID, start uint64, state byte, flags uint64, resultErr error) {
	fd, err := unix.Openat(procFD, "stat", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, 0, 0, 0, 0, err
	}
	file := os.NewFile(uintptr(fd), "exact-process-stat")
	if file == nil {
		_ = unix.Close(fd)
		return 0, 0, 0, 0, 0, errors.New("creating exact process stat handle")
	}
	defer func() { resultErr = errors.Join(resultErr, file.Close()) }()

	data, err := io.ReadAll(io.LimitReader(file, 64<<10))
	if err != nil {
		return 0, 0, 0, 0, 0, err
	}
	stat := string(data)
	firstSpace := strings.IndexByte(stat, ' ')
	closeParen := strings.LastIndexByte(stat, ')')
	if firstSpace <= 0 || closeParen < firstSpace || closeParen+1 >= len(stat) {
		return 0, 0, 0, 0, 0, errors.New("malformed exact process stat")
	}
	parsedPID, err := strconv.ParseUint(stat[:firstSpace], 10, 32)
	if err != nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("parsing exact process PID: %w", err)
	}
	if parsedPID == 0 {
		return 0, 0, 0, 0, 0, errors.New("exact process PID is zero")
	}
	fields := strings.Fields(stat[closeParen+1:])
	// fields begins with field 3 (state), so field 22 (starttime) is index 19.
	if len(fields) <= 19 || len(fields[0]) != 1 {
		return 0, 0, 0, 0, 0, errors.New("short exact process stat")
	}
	parsedPPID, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("parsing exact process parent PID: %w", err)
	}
	flags, err = strconv.ParseUint(fields[6], 10, 64)
	if err != nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("parsing exact process flags: %w", err)
	}
	start, err = strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, 0, 0, 0, 0, fmt.Errorf("parsing exact process start time: %w", err)
	}
	if start == 0 {
		return 0, 0, 0, 0, 0, errors.New("exact process start time is zero")
	}
	return app.PID(parsedPID), app.PID(parsedPPID), start, fields[0][0], flags, nil
}
