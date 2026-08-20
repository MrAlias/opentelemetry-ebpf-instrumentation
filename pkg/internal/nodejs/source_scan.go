// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/transform/route/harvest"
)

var sigusr1Quoted = []string{`"SIGUSR1"`, `'SIGUSR1'`, "`SIGUSR1`"}

// sourceHasSIGUSR1Reference scans the Node.js application's source files for
// references to "SIGUSR1", 'SIGUSR1', or `SIGUSR1`. This is a fallback
// detection method used when the symbol-based detection fails (e.g. stripped
// binaries with dynamic libuv).
func sourceHasSIGUSR1Reference(procFD int) bool {
	dir, err := exactNodeAppDir(procFD)
	if err != nil {
		return false
	}

	return dirHasSIGUSR1Reference(dir)
}

func exactNodeAppDir(procFD int) (string, error) {
	cmdline, err := readExactProcFile(procFD, "cmdline", 1<<20)
	if err != nil {
		return "", fmt.Errorf("read exact Node.js command line: %w", err)
	}
	components := bytes.Split(bytes.TrimSuffix(cmdline, []byte{0}), []byte{0})
	if len(components) == 0 || len(components[0]) == 0 {
		return "", fmt.Errorf("exact Node.js command line is empty")
	}
	args := make([]string, 0, len(components)-1)
	for _, component := range components[1:] {
		if len(component) != 0 {
			args = append(args, string(component))
		}
	}

	buffer := make([]byte, unix.PathMax)
	n, err := unix.Readlinkat(procFD, "cwd", buffer)
	if err != nil {
		return "", fmt.Errorf("read exact Node.js working directory: %w", err)
	}
	root := fmt.Sprintf("/proc/self/fd/%d/root", procFD)
	cwd := exactNodeRootPath(root, string(buffer[:n]))
	firstArg := harvest.FirstArg(args)
	if filepath.IsAbs(firstArg) {
		candidate := exactNodeRootPath(root, firstArg)
		if info, statErr := os.Stat(candidate); statErr == nil {
			if info.IsDir() {
				return candidate, nil
			}
			return filepath.Dir(candidate), nil
		}
	}
	return cwd, nil
}

func exactNodeRootPath(root, target string) string {
	cleaned := filepath.Clean(string(filepath.Separator) + target)
	return filepath.Join(root, strings.TrimPrefix(cleaned, string(filepath.Separator)))
}

func readExactProcFile(procFD int, name string, limit int64) ([]byte, error) {
	fd, err := unix.Openat(procFD, name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "exact-node-"+name)
	if file == nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("create exact Node.js %s file", name)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, limit))
	return data, errors.Join(readErr, file.Close())
}

func lineContainsSIGUSR1(line string) bool {
	for _, pattern := range sigusr1Quoted {
		if strings.Contains(line, pattern) {
			return true
		}
	}
	return false
}

func scanFileForSIGUSR1(path string) bool {
	found := false
	_ = harvest.ScanJSFileLines(path, func(line string) bool {
		if lineContainsSIGUSR1(line) {
			found = true
			return true
		}
		return false
	})
	return found
}

// dirHasSIGUSR1Reference scans JS/TS source files in the given directory for
// quoted SIGUSR1 references.
func dirHasSIGUSR1Reference(dir string) bool {
	found := false

	_ = harvest.WalkJSFiles(dir, func(path string) error {
		if scanFileForSIGUSR1(path) {
			found = true
			return filepath.SkipAll
		}
		return nil
	})

	return found
}
