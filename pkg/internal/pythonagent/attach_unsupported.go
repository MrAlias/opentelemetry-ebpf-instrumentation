// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux || !amd64

package pythonagent // import "go.opentelemetry.io/obi/pkg/internal/pythonagent"

import (
	"context"
	"errors"

	"go.opentelemetry.io/obi/pkg/internal/procs"
)

const attachmentSupported = false

func attach(context.Context, *procs.ProcessHandle) error {
	return errors.New("python requests attachment requires Linux amd64")
}
