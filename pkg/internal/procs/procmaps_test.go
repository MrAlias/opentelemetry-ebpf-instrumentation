// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// some tests here rely on concrete values for os.GetPageSize() that might differ in non-Linux environments
//go:build linux

package procs

import (
	"debug/elf"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/prometheus/procfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

func TestModulePathMatching(t *testing.T) {
	maps := makeProcFSMaps([]string{"/something/something/libssl.so.3", "anon_inode:[io_uring]"})

	assert.Nil(t, LibPath("node", maps))
	assert.Equal(t, procPSFromPath("/something/something/libssl.so.3"), LibPath("libssl.so", maps))

	maps = makeProcFSMaps([]string{"libssl.so", "/node"})

	assert.Equal(t, procPSFromPath("/node"), LibPath("node", maps))
	assert.Nil(t, LibPath("libssl.so", maps))
}

func makeProcFSMaps(paths []string) []*procfs.ProcMap {
	res := []*procfs.ProcMap{}

	for _, path := range paths {
		p := procfs.ProcMap{Pathname: path, Perms: &procfs.ProcMapPermissions{Execute: true}}
		res = append(res, &p)
	}

	return res
}

func procPSFromPath(path string) *procfs.ProcMap {
	return &procfs.ProcMap{Pathname: path, Perms: &procfs.ProcMapPermissions{Execute: true}}
}

func TestExeLoadBias(t *testing.T) {
	maps := []*procfs.ProcMap{{
		StartAddr: 0x7f0000400000,
		Offset:    0,
		Pathname:  "/proc/123/exe",
	}}
	progs := []*elf.Prog{{
		ProgHeader: elf.ProgHeader{
			Type:  elf.PT_LOAD,
			Off:   0,
			Vaddr: 0x400000,
		},
	}}

	bias, err := exeLoadBias("/proc/123/exe", maps, progs)
	require.NoError(t, err)
	assert.Equal(t, uint64(0x7f0000000000), bias)
}

func TestExeLoadBiasETExec(t *testing.T) {
	maps := []*procfs.ProcMap{{
		StartAddr: 0x400000,
		Offset:    0,
		Pathname:  "/proc/123/exe",
	}}
	progs := []*elf.Prog{{
		ProgHeader: elf.ProgHeader{
			Type:  elf.PT_LOAD,
			Off:   0,
			Vaddr: 0x400000,
		},
	}}

	bias, err := exeLoadBias("/proc/123/exe", maps, progs)
	require.NoError(t, err)
	assert.Equal(t, uint64(0), bias)
}

func TestExeLoadBiasMatchesMappingOffset(t *testing.T) {
	maps := []*procfs.ProcMap{{
		StartAddr: 0x7f0000401000,
		Offset:    0x1000,
		Pathname:  "/proc/123/exe",
	}}
	progs := []*elf.Prog{{
		ProgHeader: elf.ProgHeader{
			Type:  elf.PT_LOAD,
			Off:   0x1000,
			Vaddr: 0x401000,
		},
	}}

	bias, err := exeLoadBias("/proc/123/exe", maps, progs)
	require.NoError(t, err)
	assert.Equal(t, uint64(0x7f0000000000), bias)
}

func TestFindExeLoadBiasFromProcFD(t *testing.T) {
	procDir, err := os.Open("/proc/self")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, procDir.Close()) })
	executable := currentExecutableIdentity(t, int(procDir.Fd()))

	fromPID, err := FindExeLoadBias(app.PID(os.Getpid()))
	require.NoError(t, err)
	fromFD, err := FindExeLoadBiasFromProcFD(
		int(procDir.Fd()),
		executable.dev,
		executable.ino,
	)
	require.NoError(t, err)

	assert.Equal(t, fromPID, fromFD)
}

func TestFindExeLoadBiasFromProcFDDoesNotLeakDescriptors(t *testing.T) {
	procDir, err := os.Open("/proc/self")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, procDir.Close()) })
	executable := currentExecutableIdentity(t, int(procDir.Fd()))

	_, err = FindExeLoadBiasFromProcFD(int(procDir.Fd()), executable.dev, executable.ino)
	require.NoError(t, err)
	before, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)

	for range 32 {
		_, err = FindExeLoadBiasFromProcFD(int(procDir.Fd()), executable.dev, executable.ino)
		require.NoError(t, err)
	}
	after, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)

	assert.Len(t, after, len(before))
}

func TestFindExeLoadBiasFromProcFDRejectsExpectedExecutableMismatch(t *testing.T) {
	procDir, err := os.Open("/proc/self")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, procDir.Close()) })
	executable := currentExecutableIdentity(t, int(procDir.Fd()))

	_, err = FindExeLoadBiasFromProcFD(
		int(procDir.Fd()),
		executable.dev,
		executable.ino+1,
	)
	require.ErrorContains(t, err, "executable identity mismatch before load-bias resolution")
}

func TestFindExeLoadBiasFromProcFDRejectsExecutableChangeDuringResolution(t *testing.T) {
	procDir, err := os.Open("/proc/self")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, procDir.Close()) })
	executable := currentExecutableIdentity(t, int(procDir.Fd()))
	lookups := 0

	_, err = findExeLoadBiasFromProcFD(
		int(procDir.Fd()),
		executable.dev,
		executable.ino,
		func(int) (executableIdentity, error) {
			lookups++
			if lookups == 1 {
				return executable, nil
			}
			return executableIdentity{dev: executable.dev, ino: executable.ino + 1}, nil
		},
	)
	require.ErrorContains(t, err, "executable identity mismatch after load-bias resolution")
	assert.Equal(t, 2, lookups)
}

func TestReadProcMapsForLoadBias(t *testing.T) {
	maps, err := readProcMapsForLoadBias(strings.NewReader(
		"7f0000400000-7f0000401000 r-xp 00001000 08:01 123 /tmp/exe with spaces (deleted)\n",
	))
	require.NoError(t, err)
	require.Len(t, maps, 1)
	assert.Equal(t, uintptr(0x7f0000400000), maps[0].StartAddr)
	assert.Equal(t, int64(0x1000), maps[0].Offset)
	assert.Equal(t, "/tmp/exe with spaces (deleted)", maps[0].Pathname)
}

func TestReadAndCloseProcMapsForLoadBiasJoinsErrors(t *testing.T) {
	readErr := errors.New("maps read failure")
	closeErr := errors.New("maps close failure")

	_, err := readAndCloseProcMapsForLoadBias(&failingReadCloser{
		readErr:  readErr,
		closeErr: closeErr,
	})

	require.Error(t, err)
	require.ErrorIs(t, err, readErr)
	require.ErrorIs(t, err, closeErr)
	require.ErrorContains(t, err, "read process maps")
	require.ErrorContains(t, err, "close process maps")
}

func currentExecutableIdentity(t *testing.T, procFD int) executableIdentity {
	t.Helper()
	identity, err := executableIdentityFromProcFD(procFD)
	require.NoError(t, err)
	return identity
}

type failingReadCloser struct {
	readErr  error
	closeErr error
}

func (r *failingReadCloser) Read([]byte) (int, error) {
	return 0, r.readErr
}

func (r *failingReadCloser) Close() error {
	return r.closeErr
}

var _ io.ReadCloser = (*failingReadCloser)(nil)
