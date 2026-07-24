// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf

import (
	"errors"
	"os"
	"testing"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestResolveCgroupV2(t *testing.T) {
	tests := []struct {
		name                string
		unified             bool
		unifiedErr          error
		hybrid              bool
		hybridErr           error
		mfd                 int
		mountErr            error
		expected            cgroupV2Result
		expectedHybridCall  bool
		expectedMountCall   bool
		expectedCauses      []error
		expectedUnsupported bool
	}{
		{
			name:     "unified hierarchy",
			unified:  true,
			expected: cgroupV2Result{path: cgroupFSRoot, mfd: -1},
		},
		{
			name:               "hybrid hierarchy",
			hybrid:             true,
			expected:           cgroupV2Result{path: cgroupV2Hybrid, mfd: -1},
			expectedHybridCall: true,
		},
		{
			name:               "hybrid hierarchy after unified probe failure",
			unifiedErr:         unix.EACCES,
			hybrid:             true,
			expected:           cgroupV2Result{path: cgroupV2Hybrid, mfd: -1},
			expectedHybridCall: true,
		},
		{
			name:               "anonymous self-mount",
			unifiedErr:         unix.EACCES,
			hybridErr:          unix.ENOENT,
			mfd:                42,
			expected:           cgroupV2Result{mfd: 42},
			expectedHybridCall: true,
			expectedMountCall:  true,
		},
		{
			name:                "missing hierarchy",
			hybridErr:           unix.ENOENT,
			mountErr:            unix.ENODEV,
			expected:            cgroupV2Result{mfd: -1},
			expectedHybridCall:  true,
			expectedMountCall:   true,
			expectedCauses:      []error{errNoCgroupV2, unix.ENOENT, unix.ENODEV},
			expectedUnsupported: true,
		},
		{
			name:               "permission failures",
			unifiedErr:         unix.EACCES,
			hybridErr:          unix.EACCES,
			mountErr:           unix.EPERM,
			expected:           cgroupV2Result{mfd: -1},
			expectedHybridCall: true,
			expectedMountCall:  true,
			expectedCauses:     []error{errNoCgroupV2, unix.EACCES, unix.EPERM},
		},
		{
			name:               "resource failure",
			hybridErr:          unix.ENOENT,
			mountErr:           unix.ENOMEM,
			expected:           cgroupV2Result{mfd: -1},
			expectedHybridCall: true,
			expectedMountCall:  true,
			expectedCauses:     []error{errNoCgroupV2, unix.ENOENT, unix.ENOMEM},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hybridCalled := false
			mountCalled := false
			result := resolveCgroupV2(
				func() (bool, error) {
					return tt.unified, tt.unifiedErr
				},
				func(path string) (bool, error) {
					hybridCalled = true
					assert.Equal(t, cgroupV2Hybrid, path)
					return tt.hybrid, tt.hybridErr
				},
				func() (int, error) {
					mountCalled = true
					return tt.mfd, tt.mountErr
				},
			)

			assert.Equal(t, tt.expected.path, result.path)
			assert.Equal(t, tt.expected.mfd, result.mfd)
			assert.Equal(t, tt.expectedHybridCall, hybridCalled)
			assert.Equal(t, tt.expectedMountCall, mountCalled)
			if len(tt.expectedCauses) == 0 {
				require.NoError(t, result.err)
			}
			for _, cause := range tt.expectedCauses {
				require.ErrorIs(t, result.err, cause)
			}
			assert.Equal(
				t,
				tt.expectedUnsupported,
				errors.Is(result.err, cebpf.ErrNotSupported),
			)
		})
	}
}

func TestAttachCgroupSockOpsLink(t *testing.T) {
	t.Run("resolver error", func(t *testing.T) {
		resolveErr := errors.New("resolve cgroup")
		openCalled := false
		attachCalled := false

		_, err := attachCgroupSockOpsLink(
			cgroupV2Result{mfd: -1, err: resolveErr},
			nil,
			cebpf.AttachCGroupGetsockopt,
			func(string) (*os.File, error) {
				openCalled = true
				return nil, nil
			},
			func(link.RawLinkOptions) (*link.RawLink, error) {
				attachCalled = true
				return nil, nil
			},
		)

		require.ErrorIs(t, err, resolveErr)
		assert.False(t, openCalled)
		assert.False(t, attachCalled)
	})

	t.Run("path", func(t *testing.T) {
		path := t.TempDir()
		program := new(cebpf.Program)
		var target int

		_, err := attachCgroupSockOpsLink(
			cgroupV2Result{path: path, mfd: -1},
			program,
			cebpf.AttachCGroupSetsockopt,
			os.Open,
			func(options link.RawLinkOptions) (*link.RawLink, error) {
				target = options.Target
				assert.Same(t, program, options.Program)
				assert.Equal(t, cebpf.AttachCGroupSetsockopt, options.Attach)
				_, err := unix.FcntlInt(uintptr(target), unix.F_GETFD, 0)
				require.NoError(t, err)
				return nil, nil
			},
		)

		require.NoError(t, err)
		_, err = unix.FcntlInt(uintptr(target), unix.F_GETFD, 0)
		require.ErrorIs(t, err, unix.EBADF)
	})

	t.Run("anonymous mount", func(t *testing.T) {
		const mountFD = 42
		program := new(cebpf.Program)
		openCalled := false

		_, err := attachCgroupSockOpsLink(
			cgroupV2Result{mfd: mountFD},
			program,
			cebpf.AttachCGroupGetsockopt,
			func(string) (*os.File, error) {
				openCalled = true
				return nil, nil
			},
			func(options link.RawLinkOptions) (*link.RawLink, error) {
				assert.Equal(t, mountFD, options.Target)
				assert.Same(t, program, options.Program)
				assert.Equal(t, cebpf.AttachCGroupGetsockopt, options.Attach)
				return nil, nil
			},
		)

		require.NoError(t, err)
		assert.False(t, openCalled)
	})

	t.Run("open error", func(t *testing.T) {
		_, err := attachCgroupSockOpsLink(
			cgroupV2Result{path: "/cgroup", mfd: -1},
			nil,
			cebpf.AttachCGroupGetsockopt,
			func(string) (*os.File, error) {
				return nil, unix.EPERM
			},
			func(link.RawLinkOptions) (*link.RawLink, error) {
				t.Fatal("attach called after open failure")
				return nil, nil
			},
		)

		require.ErrorIs(t, err, unix.EPERM)
	})

	t.Run("attach error", func(t *testing.T) {
		_, err := attachCgroupSockOpsLink(
			cgroupV2Result{mfd: 42},
			nil,
			cebpf.AttachCGroupGetsockopt,
			func(string) (*os.File, error) {
				t.Fatal("open called for anonymous mount")
				return nil, nil
			},
			func(link.RawLinkOptions) (*link.RawLink, error) {
				return nil, cebpf.ErrNotSupported
			},
		)

		require.ErrorIs(t, err, cebpf.ErrNotSupported)
	})
}
