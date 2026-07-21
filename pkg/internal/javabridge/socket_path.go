// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package javabridge // import "go.opentelemetry.io/obi/pkg/internal/javabridge"

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// canonicalSocketPath resolves symlinks in the existing path prefix and keeps
// any missing suffix components under that resolved directory.
func canonicalSocketPath(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("java bridge socket path must be absolute: %q", path)
	}

	existing := filepath.Clean(path)
	missing := make([]string, 0)
	for {
		_, err := os.Lstat(existing)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("inspect Java bridge socket path: %w", err)
		}
		next := filepath.Dir(existing)
		if next == existing {
			return "", fmt.Errorf("find existing Java bridge socket ancestor: %q", path)
		}
		missing = append(missing, filepath.Base(existing))
		existing = next
	}

	resolved, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return "", fmt.Errorf("resolve Java bridge socket path: %w", err)
	}
	for index := len(missing) - 1; index >= 0; index-- {
		resolved = filepath.Join(resolved, missing[index])
	}
	return resolved, nil
}
