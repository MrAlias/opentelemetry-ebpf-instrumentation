// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package ebpfcommon // import "go.opentelemetry.io/obi/pkg/ebpf/common"

import (
	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
)

func namespacedPIDsForOwner(pid app.PID, _ *exec.FileInfo) ([]app.PID, error) {
	return readNamespacePIDs(pid)
}

func validateProcessOwner(_ app.PID, _ *exec.FileInfo) error {
	return nil
}
