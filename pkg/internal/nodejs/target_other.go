// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package nodejs // import "go.opentelemetry.io/obi/pkg/internal/nodejs"

import (
	"errors"

	discexec "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/ebpf"
)

func (i *NodeInjector) prepareExactExecutable(
	_ *ebpf.Instrumentable,
	_ *discexec.FileInfo,
) (PreparedExecutable, error) {
	return nil, errors.New("exact Node.js process injection is only supported on Linux")
}
