// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javabridge // import "go.opentelemetry.io/obi/pkg/internal/javabridge"

import (
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
)

type programHelperProbe func(ebpf.ProgramType, asm.BuiltinFunc) error

func probeSockOpsNetnsCookie(probe programHelperProbe) error {
	return probe(ebpf.SockOps, asm.FnGetNetnsCookie)
}

var haveSockOpsNetnsCookie = sync.OnceValue(func() error {
	return probeSockOpsNetnsCookie(features.HaveProgramHelper)
})

func HaveSockOpsNetnsCookie() error {
	return haveSockOpsNetnsCookie()
}
