// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javabridge

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/require"
)

func TestProbeSockOpsNetnsCookie(t *testing.T) {
	wantErr := errors.New("injected helper probe failure")
	called := 0
	err := probeSockOpsNetnsCookie(func(programType ebpf.ProgramType, helper asm.BuiltinFunc) error {
		called++
		require.Equal(t, ebpf.SockOps, programType)
		require.Equal(t, asm.FnGetNetnsCookie, helper)
		return wantErr
	})

	require.ErrorIs(t, err, wantErr)
	require.Equal(t, 1, called)
}
