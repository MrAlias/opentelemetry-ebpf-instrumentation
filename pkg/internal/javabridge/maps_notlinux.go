// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package javabridge // import "go.opentelemetry.io/obi/pkg/internal/javabridge"

import "github.com/cilium/ebpf"

// MinimizeDisabledMaps is a no-op outside Linux, where eBPF collection specs
// are never loaded but cross-platform tracer construction still references the
// shared helper.
func MinimizeDisabledMaps(_ *ebpf.CollectionSpec) {}
