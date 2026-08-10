// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import "errors"

func FindExeLoadBiasFromProcFD(_ int, _, _ uint64) (uint64, error) {
	return 0, errors.New("stable executable load-bias lookup is only supported on Linux")
}
