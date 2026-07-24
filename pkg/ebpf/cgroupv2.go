// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package ebpf // import "go.opentelemetry.io/obi/pkg/ebpf"

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	v2 "github.com/containers/common/pkg/cgroupv2"
	"golang.org/x/sys/unix"
)

const (
	cgroupFSRoot   = "/sys/fs/cgroup"
	cgroupV2Hybrid = "/sys/fs/cgroup/unified"
	cgroup2Magic   = 0x63677270
)

var errNoCgroupV2 = errors.New("no cgroupv2 hierarchy found")

// cgroupV2Result holds either a path (tier 1/2) or an mfd (tier 3 anonymous
// mount). The mfd is kept open for the process lifetime by sync.OnceValue.
type cgroupV2Result struct {
	path string
	mfd  int
	err  error
}

var cgroupV2Once = sync.OnceValue(func() cgroupV2Result {
	log := slog.With("component", "ebpf.cgroupv2")
	result := resolveCgroupV2(v2.Enabled, isCgroup2Mount, fsmountCgroupV2)
	if result.err != nil {
		log.Warn("could not resolve cgroupv2", "error", result.err)
	} else if result.path == "" {
		log.Info("self-mounted cgroup2 hierarchy via fsmount", "mfd", result.mfd)
	}
	return result
})

func resolveCgroupV2(
	enabled func() (bool, error),
	isMount func(string) (bool, error),
	selfMount func() (int, error),
) cgroupV2Result {
	unified, unifiedErr := enabled()
	if unifiedErr == nil && unified {
		return cgroupV2Result{path: cgroupFSRoot, mfd: -1}
	}

	hybrid, hybridErr := isMount(cgroupV2Hybrid)
	if hybridErr == nil && hybrid {
		return cgroupV2Result{path: cgroupV2Hybrid, mfd: -1}
	}

	mfd, mountErr := selfMount()
	if mountErr == nil {
		return cgroupV2Result{mfd: mfd}
	}

	cause := errors.Join(unifiedErr, hybridErr, mountErr)
	resultErr := fmt.Errorf("%w: %w", errNoCgroupV2, cause)
	if errors.Is(cause, ebpf.ErrNotSupported) ||
		errors.Is(mountErr, unix.ENODEV) ||
		errors.Is(mountErr, unix.ENOSYS) ||
		errors.Is(mountErr, unix.EOPNOTSUPP) {
		resultErr = fmt.Errorf("%w: %w", resultErr, ebpf.ErrNotSupported)
	}
	return cgroupV2Result{
		mfd: -1,
		err: resultErr,
	}
}

func isCgroup2Mount(path string) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return false, err
	}
	return st.Type == cgroup2Magic, nil
}

// fsmountCgroupV2 creates an anonymous cgroupv2 mount via fsopen+fsmount.
// The returned fd must stay open for the lifetime of any BPF link attached
// to it. Works on read-only filesystems; leaves no entry in /proc/mounts.
func fsmountCgroupV2() (int, error) {
	fsfd, err := unix.Fsopen("cgroup2", unix.FSOPEN_CLOEXEC)
	if err != nil {
		return -1, err
	}
	defer unix.Close(fsfd)
	if err := unix.FsconfigCreate(fsfd); err != nil {
		return -1, err
	}
	return unix.Fsmount(fsfd, unix.FSMOUNT_CLOEXEC, 0)
}

// AttachCgroupSockOps attaches a sockops program to the cgroupv2 hierarchy,
// hiding the path-vs-fd distinction between tier 1/2 and tier 3.
func AttachCgroupSockOps(prog *ebpf.Program, attach ebpf.AttachType) (link.Link, error) {
	r := cgroupV2Once()
	if r.err != nil {
		return nil, r.err
	}
	if r.path != "" {
		return link.AttachCgroup(link.CgroupOptions{
			Path:    r.path,
			Program: prog,
			Attach:  attach,
		})
	}
	return link.AttachRawLink(link.RawLinkOptions{
		Target:  r.mfd,
		Program: prog,
		Attach:  attach,
	})
}

// AttachCgroupSockOpsLink attaches a sockops program using a cgroup BPF link.
// Unlike AttachCgroupSockOps, it does not fall back to a legacy program
// attachment that can outlive the process after an unclean shutdown.
func AttachCgroupSockOpsLink(
	prog *ebpf.Program,
	attach ebpf.AttachType,
) (*link.RawLink, error) {
	return attachCgroupSockOpsLink(
		cgroupV2Once(),
		prog,
		attach,
		os.Open,
		link.AttachRawLink,
	)
}

func attachCgroupSockOpsLink(
	r cgroupV2Result,
	prog *ebpf.Program,
	attach ebpf.AttachType,
	openCgroup func(string) (*os.File, error),
	attachLink func(link.RawLinkOptions) (*link.RawLink, error),
) (*link.RawLink, error) {
	if r.err != nil {
		return nil, r.err
	}

	target := r.mfd
	if r.path != "" {
		cgroup, err := openCgroup(r.path)
		if err != nil {
			return nil, fmt.Errorf("opening cgroup %q: %w", r.path, err)
		}
		defer cgroup.Close()
		target = int(cgroup.Fd())
	}

	cgroupLink, err := attachLink(link.RawLinkOptions{
		Target:  target,
		Program: prog,
		Attach:  attach,
	})
	if err != nil {
		return nil, fmt.Errorf("attaching cgroup sockops link: %w", err)
	}
	return cgroupLink, nil
}
