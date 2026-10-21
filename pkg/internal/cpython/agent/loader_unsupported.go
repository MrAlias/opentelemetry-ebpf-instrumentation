// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux || !amd64

package agent // import "go.opentelemetry.io/obi/pkg/internal/cpython/agent"

import (
	"context"
	"errors"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

func Inject(context.Context, app.PID, uint64) error {
	return errors.New("Python HTTPX agent loading requires Linux amd64")
}
