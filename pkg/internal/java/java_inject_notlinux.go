// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package javaagent // import "go.opentelemetry.io/obi/pkg/internal/java"

import (
	"context"

	"go.opentelemetry.io/obi/pkg/ebpf"
)

// placeholder to avoid compilation errors in non-linux platforms

type JavaInjector struct{}

type PreparedExecutable interface {
	NewExecutableContext(context.Context) error
	Close() error
}

func NewJavaInjector(_ any) (*JavaInjector, error) { return nil, nil }
func (*JavaInjector) PrepareExecutable(_ *ebpf.Instrumentable) (PreparedExecutable, error) {
	return nil, nil
}
func (*JavaInjector) NewExecutable(_ *ebpf.Instrumentable) error { return nil }
func (*JavaInjector) NewExecutableContext(context.Context, *ebpf.Instrumentable) error {
	return nil
}
