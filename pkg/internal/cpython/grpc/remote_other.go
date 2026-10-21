// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package grpc // import "go.opentelemetry.io/obi/pkg/internal/cpython/grpc"

import (
	"context"
	"errors"
)

func (*Injector) attach(context.Context, InjectionTarget) error {
	return errors.New("CPython remote execution requires Linux")
}
