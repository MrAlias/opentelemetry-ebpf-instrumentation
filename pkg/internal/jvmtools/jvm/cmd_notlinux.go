// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package jvm // import "go.opentelemetry.io/obi/pkg/internal/jvmtools/jvm"

import (
	"context"
	"errors"
	"io"
	"log/slog"
)

var errUnsupported = errors.New("jvmtools attach is only supported on linux")

type JAttacher struct{}

func NewJAttacher(_ *slog.Logger, _ int64, _ func(int64, func() error) error) *JAttacher {
	return &JAttacher{}
}

func (*JAttacher) Init() {}

func (*JAttacher) Cleanup() error {
	return nil
}

func (*JAttacher) ConfigureAttachLifecycle(_ int64, _ func(int64, func() error) error) {}

func (*JAttacher) Terminate() error {
	return nil
}

func (*JAttacher) Attach(_ int, _ []string, _ bool) (io.ReadCloser, error) {
	return nil, errUnsupported
}

func (*JAttacher) AttachContext(context.Context, int, []string, bool) (io.ReadCloser, error) {
	return nil, errUnsupported
}
