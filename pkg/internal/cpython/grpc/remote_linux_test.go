// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package grpc // import "go.opentelemetry.io/obi/pkg/internal/cpython/grpc"

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func debugTable() []byte {
	data := make([]byte, debugWords*8)
	copy(data, "xdebugpy")
	words := map[int]uint64{
		1: 0x030e03f0, 3: 200000, 5: 800, 6: 50000, 10: 128,
		22: 4000, 89: 200, 90: 400, 91: 1200, 92: 0, 93: 8, 94: 1024,
	}
	for index, value := range words {
		binary.LittleEndian.PutUint64(data[index*8:], value)
	}
	return data
}

func TestRemoteLayout(t *testing.T) {
	layout, err := readRemoteLayout(bytes.NewReader(debugTable()), 0)
	require.NoError(t, err)
	require.Equal(t, uint64(128), layout.mainThread)
	for _, tc := range []struct {
		name  string
		index int
		value uint64
	}{
		{"old Python", 1, 0x030c03f0},
		{"prerelease", 1, 0x030e00b1},
		{"free threaded", 2, 1},
		{"interpreter overflow", 10, 50001},
		{"thread overflow", 90, 3999},
		{"oversized path", 94, 8192},
		{"path overflow", 93, ^uint64(0)},
		{"breaker overflow", 89, 3999},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := debugTable()
			binary.LittleEndian.PutUint64(data[tc.index*8:], tc.value)
			_, err := readRemoteLayout(bytes.NewReader(data), 0)
			require.Error(t, err)
		})
	}
	_, err = readRemoteLayout(bytes.NewReader([]byte("xdebugpy")), 0)
	require.Error(t, err)
}

func TestRequestExec(t *testing.T) {
	for _, tc := range []struct {
		name             string
		enabled, pending uint64
		path             string
		fails            bool
	}{
		{"publish", 1, 0, "/tmp/agent.py", false},
		{"disabled", 0, 0, "/tmp/agent.py", true},
		{"pending", 1, 1, "/tmp/agent.py", true},
		{"path too long", 1, 0, string(make([]byte, 1024)), true},
		{"embedded null", 1, 0, "/tmp/a\x00b", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			layout, err := readRemoteLayout(bytes.NewReader(debugTable()), 0)
			require.NoError(t, err)
			data := make([]byte, 20000)
			put := func(address, value uint64) { binary.LittleEndian.PutUint64(data[address:], value) }
			const runtimeAddress = 1000
			const interpreter = 3000
			const thread = 6000
			put(runtimeAddress+layout.interpreters, interpreter)
			put(interpreter+layout.mainThread, thread)
			put(interpreter+layout.enabled, tc.enabled)
			put(thread+layout.support+layout.pending, tc.pending)
			put(thread+layout.evalBreaker, 4)
			name := filepath.Join(t.TempDir(), "mem")
			require.NoError(t, os.WriteFile(name, data, 0o600))
			mem, err := os.OpenFile(name, os.O_RDWR, 0)
			require.NoError(t, err)
			defer mem.Close()
			published, err := requestExec(mem, runtimeAddress, layout, tc.path)
			require.Equal(t, !tc.fails, published)
			result, readErr := os.ReadFile(name)
			require.NoError(t, readErr)
			if tc.fails {
				require.Error(t, err)
				require.Equal(t, data, result, "refused requests must not alter target memory")
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.path+"\x00", string(result[thread+layout.support+layout.path:thread+layout.support+layout.path+uint64(len(tc.path))+1]))
			require.Equal(t, uint64(4|pleaseStopBit), binary.LittleEndian.Uint64(result[thread+layout.evalBreaker:]))
			require.Equal(t, uint32(1), binary.LittleEndian.Uint32(result[thread+layout.support+layout.pending:]))
		})
	}
}
