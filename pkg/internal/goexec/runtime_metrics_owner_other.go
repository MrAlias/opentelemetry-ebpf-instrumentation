// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package goexec // import "go.opentelemetry.io/obi/pkg/internal/goexec"

import "go.opentelemetry.io/obi/pkg/appolly/discover/exec"

func validateRuntimeMetricOwner(_ int, _ *exec.FileInfo) error {
	return nil
}
