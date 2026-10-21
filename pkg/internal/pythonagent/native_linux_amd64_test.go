// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package pythonagent

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSyscallInstruction(t *testing.T) {
	for _, test := range []struct {
		name string
		code []byte
		want int
	}{
		{"glibc-cet", []byte{0xf3, 0x0f, 0x1e, 0xfa, 0x48, 0x89, 0xf8, 0x0f, 0x05, 0xc3}, 7},
		{"without-cet", []byte{0x48, 0x89, 0xf8, 0x0f, 0x05, 0xc3}, 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			offset, err := syscallInstruction(test.code)
			require.NoError(t, err)
			require.Equal(t, test.want, offset)
		})
	}
	// An immediate containing 0f 05 is not an executable syscall instruction.
	_, err := syscallInstruction([]byte{0x48, 0xb8, 0x0f, 0x05, 0, 0, 0, 0, 0, 0, 0xc3})
	require.Error(t, err)
	_, err = syscallInstruction([]byte{0xc3, 0x0f, 0x05})
	require.Error(t, err)
}
