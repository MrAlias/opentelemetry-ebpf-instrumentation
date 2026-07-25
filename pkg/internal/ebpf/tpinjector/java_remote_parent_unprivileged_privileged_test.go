// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package tpinjector

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const (
	javaRemoteParentUnprivilegedLoadEnv = "OBI_JAVA_REMOTE_PARENT_UNPRIVILEGED_LOAD"
	javaRemoteParentPrivilegeDropPhase  = "drop"
	javaRemoteParentUnprivilegedPhase   = "load"
	javaRemoteParentUnprivilegedID      = 65534
	javaRemoteParentLoadDeniedEvidence  = "OBI_JAVA_REMOTE_PARENT_UNPRIVILEGED_LOAD_DENIED=EPERM"
)

func TestJavaRemoteParentBridgeLoadRequiresPrivileges(t *testing.T) {
	_ = requireJavaRemoteParentCgroupTopology(t)

	objects := loadJavaRemoteParentFixture(t)
	t.Cleanup(func() {
		require.NoError(t, objects.Close())
	})

	t.Setenv(
		javaRemoteParentUnprivilegedLoadEnv,
		javaRemoteParentPrivilegeDropPhase,
	)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	command := exec.CommandContext(
		ctx,
		os.Args[0],
		"-test.run=^TestJavaRemoteParentUnprivilegedLoadHelper$",
		"-test.v",
	)
	output, err := command.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("unprivileged Java bridge load timed out:\n%s", output)
	}
	require.NoErrorf(
		t,
		err,
		"unprivileged Java bridge load helper failed:\n%s",
		output,
	)
	require.Contains(t, string(output), javaRemoteParentLoadDeniedEvidence)
	t.Logf("unprivileged Java bridge load evidence:\n%s", output)
}

func TestJavaRemoteParentUnprivilegedLoadHelper(t *testing.T) {
	switch os.Getenv(javaRemoteParentUnprivilegedLoadEnv) {
	case "":
		return
	case javaRemoteParentPrivilegeDropPhase:
		dropJavaRemoteParentLoadPrivileges(t)
	case javaRemoteParentUnprivilegedPhase:
		requireJavaRemoteParentLoadDenied(t)
	default:
		t.Fatalf(
			"unknown unprivileged Java bridge load phase %q",
			os.Getenv(javaRemoteParentUnprivilegedLoadEnv),
		)
	}
}

func dropJavaRemoteParentLoadPrivileges(t *testing.T) {
	t.Helper()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	requireNoJavaRemoteParentBPFDescriptors(t)
	require.NoError(t, unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
	require.NoError(t, unix.Prctl(
		unix.PR_CAP_AMBIENT,
		unix.PR_CAP_AMBIENT_CLEAR_ALL,
		0,
		0,
		0,
	))
	require.NoError(t, syscall.Setgroups(nil))
	require.NoError(t, unix.Setresgid(
		javaRemoteParentUnprivilegedID,
		javaRemoteParentUnprivilegedID,
		javaRemoteParentUnprivilegedID,
	))
	require.NoError(t, unix.Setresuid(
		javaRemoteParentUnprivilegedID,
		javaRemoteParentUnprivilegedID,
		javaRemoteParentUnprivilegedID,
	))

	header := unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_3,
		Pid:     0,
	}
	var capabilities [2]unix.CapUserData
	require.NoError(t, unix.Capset(&header, &capabilities[0]))

	requireJavaRemoteParentUnprivilegedThread(t)
	requireNoJavaRemoteParentBPFDescriptors(t)
	require.NoError(t, os.Setenv(
		javaRemoteParentUnprivilegedLoadEnv,
		javaRemoteParentUnprivilegedPhase,
	))
	// Exec makes every Go runtime thread inherit the calling thread's
	// capability and no-new-privileges state.
	require.NoError(t, syscall.Exec(
		"/proc/self/exe",
		[]string{
			os.Args[0],
			"-test.run=^TestJavaRemoteParentUnprivilegedLoadHelper$",
			"-test.v",
		},
		os.Environ(),
	))
}

func requireJavaRemoteParentLoadDenied(t *testing.T) {
	t.Helper()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	requireJavaRemoteParentUnprivilegedThread(t)
	requireJavaRemoteParentUnprivilegedProcess(t)
	requireNoJavaRemoteParentBPFDescriptors(t)

	spec := javaRemoteParentFixtureSpec(t)
	var objects BpfJavaRemoteParentObjects
	err := spec.LoadAndAssign(&objects, nil)
	if err == nil {
		defer objects.Close()
	}
	require.ErrorIs(t, err, unix.EPERM)
	requireNoJavaRemoteParentBPFDescriptors(t)
	t.Log(javaRemoteParentLoadDeniedEvidence)
}

func requireJavaRemoteParentUnprivilegedThread(t *testing.T) {
	t.Helper()

	ruid, euid, suid := unix.Getresuid()
	require.Equal(t, javaRemoteParentUnprivilegedID, ruid)
	require.Equal(t, javaRemoteParentUnprivilegedID, euid)
	require.Equal(t, javaRemoteParentUnprivilegedID, suid)

	rgid, egid, sgid := unix.Getresgid()
	require.Equal(t, javaRemoteParentUnprivilegedID, rgid)
	require.Equal(t, javaRemoteParentUnprivilegedID, egid)
	require.Equal(t, javaRemoteParentUnprivilegedID, sgid)

	groups, err := unix.Getgroups()
	require.NoError(t, err)
	require.Empty(t, groups)

	header := unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_3,
		Pid:     0,
	}
	var capabilities [2]unix.CapUserData
	require.NoError(t, unix.Capget(&header, &capabilities[0]))
	for index, capability := range capabilities {
		require.Zero(t, capability.Effective, "effective capability word %d", index)
		require.Zero(t, capability.Permitted, "permitted capability word %d", index)
		require.Zero(t, capability.Inheritable, "inheritable capability word %d", index)
	}

	status, err := readJavaRemoteParentLinuxStatus("/proc/thread-self/status")
	require.NoError(t, err)
	requireJavaRemoteParentUnprivilegedStatus(
		t,
		"/proc/thread-self/status",
		status,
	)
}

func requireJavaRemoteParentUnprivilegedProcess(t *testing.T) {
	t.Helper()

	tasks, err := os.ReadDir("/proc/self/task")
	require.NoError(t, err)

	checked := 0
	for _, task := range tasks {
		if !task.IsDir() {
			continue
		}
		path := filepath.Join("/proc/self/task", task.Name(), "status")
		status, err := readJavaRemoteParentLinuxStatus(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		require.NoErrorf(t, err, "read Linux thread status %q", path)
		requireJavaRemoteParentUnprivilegedStatus(t, path, status)
		checked++
	}
	require.Positive(t, checked)
}

func requireJavaRemoteParentUnprivilegedStatus(
	t *testing.T,
	path string,
	status map[string][]string,
) {
	t.Helper()

	id := strconv.Itoa(javaRemoteParentUnprivilegedID)
	require.Equal(t, []string{id, id, id, id}, status["Uid"], path)
	require.Equal(t, []string{id, id, id, id}, status["Gid"], path)

	groups, ok := status["Groups"]
	require.Truef(t, ok, "%s has no Groups field", path)
	require.Empty(t, groups, path)

	for _, name := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
		values, ok := status[name]
		require.Truef(t, ok, "%s has no %s field", path, name)
		require.Len(t, values, 1, path)
		value, err := strconv.ParseUint(values[0], 16, 64)
		require.NoErrorf(t, err, "parse %s from %s", name, path)
		require.Zero(t, value, "%s in %s", name, path)
	}

	noNewPrivileges, ok := status["NoNewPrivs"]
	require.Truef(t, ok, "%s has no NoNewPrivs field", path)
	require.Equal(t, []string{"1"}, noNewPrivileges, path)
}

func readJavaRemoteParentLinuxStatus(path string) (map[string][]string, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	status := make(map[string][]string)
	for line := range strings.SplitSeq(string(contents), "\n") {
		name, value, found := strings.Cut(line, ":")
		if found {
			status[name] = strings.Fields(value)
		}
	}
	return status, nil
}

func requireNoJavaRemoteParentBPFDescriptors(t *testing.T) {
	t.Helper()

	descriptors, err := javaRemoteParentBPFDescriptors()
	require.NoError(t, err)
	require.Empty(t, descriptors, "open BPF descriptors: %v", descriptors)
}

func javaRemoteParentBPFDescriptors() ([]string, error) {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return nil, err
	}

	var descriptors []string
	for _, entry := range entries {
		fdPath := filepath.Join("/proc/self/fd", entry.Name())
		target, err := os.Readlink(fdPath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}

		isBPF, err := javaRemoteParentDescriptorIsBPF(entry.Name(), target)
		if err != nil {
			return nil, err
		}
		if isBPF {
			descriptors = append(
				descriptors,
				fmt.Sprintf("%s -> %s", entry.Name(), target),
			)
		}
	}
	return descriptors, nil
}

func javaRemoteParentDescriptorIsBPF(fd, target string) (bool, error) {
	lowerTarget := strings.ToLower(target)
	if strings.Contains(lowerTarget, "anon_inode") &&
		strings.Contains(lowerTarget, "bpf") {
		return true, nil
	}

	contents, err := os.ReadFile(filepath.Join("/proc/self/fdinfo", fd))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for line := range strings.SplitSeq(string(contents), "\n") {
		name, _, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		switch name {
		case "btf_id", "link_id", "map_id", "prog_id", "token_id":
			return true, nil
		}
	}
	return false, nil
}
