// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package tpinjector

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/javabridge"
)

const (
	javaRemoteParentCgroupHelperEnv     = "OBI_JAVA_REMOTE_PARENT_CGROUP_HELPER"
	javaRemoteParentCgroupCapability    = "OBI_JAVA_REMOTE_PARENT_CGROUP_CAPABILITY"
	javaRemoteParentCgroupAttached      = "OBI_JAVA_REMOTE_PARENT_CGROUP_ATTACHED"
	javaRemoteParentCgroupControllerEnv = "OBI_JAVA_REMOTE_PARENT_CGROUP_CONTROLLER"
	javaRemoteParentCgroupPathEnv       = "OBI_JAVA_REMOTE_PARENT_CGROUP_PATH"
	javaRemoteParentCgroupTestRequired  = "OBI_REQUIRE_CGROUP_TOPOLOGY"
	cgroup2FilesystemMagic              = 0x63677270

	javaRemoteParentControllerGetsockoptFD = 3
	javaRemoteParentControllerSetsockoptFD = 4
	javaRemoteParentControllerReadyFD      = 5
	javaRemoteParentControllerHoldFD       = 6
	javaRemoteParentCgroupSocketCookiesFD  = 5
)

type javaRemoteParentCgroupTopology struct {
	parent   string
	workload string
}

type javaRemoteParentMapIdentity struct {
	name string
	id   ebpf.MapID
}

type cgroupV2Mount struct {
	root       string
	mountPoint string
	writable   bool
}

type javaRemoteParentCgroupLinkController struct {
	command    *exec.Cmd
	holdWriter *os.File
	output     bytes.Buffer
	waited     bool
}

func TestJavaRemoteParentNestedCgroupLifecycle(t *testing.T) {
	current := requireJavaRemoteParentCgroupTopology(t)

	topology := newJavaRemoteParentCgroupTopology(t, current)
	require.Empty(t, queryCgroupProgramIDs(
		t, topology.parent, ebpf.AttachCGroupGetsockopt,
	))
	require.Empty(t, queryCgroupProgramIDs(
		t, topology.parent, ebpf.AttachCGroupSetsockopt,
	))

	const firstCapability = uint64(0x1029384756abcdef)
	runJavaRemoteParentCgroupGeneration(t, topology, firstCapability)

	const detachedCapability = uint64(0x23456789abcdef01)
	runJavaRemoteParentCgroupWorkload(
		t, topology, nil, detachedCapability, false,
	)

	const secondCapability = uint64(0xfedcba6547382910)
	runJavaRemoteParentCgroupGeneration(t, topology, secondCapability)
}

func TestJavaRemoteParentCgroupLinkProcessDeathCleanup(t *testing.T) {
	current := requireJavaRemoteParentCgroupTopology(t)
	topology := newJavaRemoteParentCgroupTopology(t, current)
	require.Empty(t, queryCgroupProgramIDs(
		t, topology.parent, ebpf.AttachCGroupGetsockopt,
	))
	require.Empty(t, queryCgroupProgramIDs(
		t, topology.parent, ebpf.AttachCGroupSetsockopt,
	))

	objects := loadJavaRemoteParentFixture(t)
	objectsOpen := true
	defer func() {
		if objectsOpen {
			assert.NoError(t, objects.Close())
		}
	}()
	setJavaRemoteParentDataHookReadiness(t, objects.JavaRemoteParentDataHookReadiness, true)
	mapIdentities := javaRemoteParentMapIdentities(
		t, &objects.BpfJavaRemoteParentMaps,
	)
	getID := javaRemoteParentProgramID(t, objects.ObiJavaRemoteParentGetsockopt)
	setID := javaRemoteParentProgramID(t, objects.ObiJavaRemoteParentSetsockopt)

	controller := startJavaRemoteParentCgroupLinkController(
		t, topology.parent, &objects.BpfJavaRemoteParentPrograms,
	)
	require.Equal(
		t,
		[]ebpf.ProgramID{getID},
		queryCgroupProgramIDs(t, topology.parent, ebpf.AttachCGroupGetsockopt),
	)
	require.Equal(
		t,
		[]ebpf.ProgramID{setID},
		queryCgroupProgramIDs(t, topology.parent, ebpf.AttachCGroupSetsockopt),
	)

	const firstCapability = uint64(0x3141592653589793)
	runJavaRemoteParentCgroupWorkload(
		t, topology, &objects.BpfJavaRemoteParentMaps, firstCapability, true,
	)

	controller.kill(t)
	requireCgroupProgramsDetached(t, topology.parent)
	require.Equal(t, getID, javaRemoteParentProgramID(
		t, objects.ObiJavaRemoteParentGetsockopt,
	))
	require.Equal(t, setID, javaRemoteParentProgramID(
		t, objects.ObiJavaRemoteParentSetsockopt,
	))
	requireJavaRemoteParentMapsPresent(t, mapIdentities)

	const detachedCapability = uint64(0x2718281828459045)
	runJavaRemoteParentCgroupWorkload(
		t, topology, nil, detachedCapability, false,
	)

	links, err := attachJavaRemoteParentFixtureAt(
		topology.parent, &objects.BpfJavaRemoteParentPrograms,
	)
	require.NoError(t, err)
	linksOpen := true
	defer func() {
		if linksOpen {
			assert.NoError(t, links.Close())
		}
	}()
	require.Equal(
		t,
		[]ebpf.ProgramID{getID},
		queryCgroupProgramIDs(t, topology.parent, ebpf.AttachCGroupGetsockopt),
	)
	require.Equal(
		t,
		[]ebpf.ProgramID{setID},
		queryCgroupProgramIDs(t, topology.parent, ebpf.AttachCGroupSetsockopt),
	)

	const secondCapability = uint64(0x1618033988749894)
	runJavaRemoteParentCgroupWorkload(
		t, topology, &objects.BpfJavaRemoteParentMaps, secondCapability, true,
	)

	require.NoError(t, links.Close())
	linksOpen = false
	requireCgroupProgramsDetached(t, topology.parent)

	require.NoError(t, objects.Close())
	objectsOpen = false
	requireJavaRemoteParentMapsReleased(t, mapIdentities)
}

func TestJavaRemoteParentCgroupPartialAttachRollback(t *testing.T) {
	current := requireJavaRemoteParentCgroupTopology(t)
	topology := newJavaRemoteParentCgroupTopology(t, current)

	objects := loadJavaRemoteParentFixture(t)
	objectsOpen := true
	defer func() {
		if objectsOpen {
			assert.NoError(t, objects.Close())
		}
	}()
	mapIdentities := javaRemoteParentMapIdentities(
		t, &objects.BpfJavaRemoteParentMaps,
	)
	getID := javaRemoteParentProgramID(t, objects.ObiJavaRemoteParentGetsockopt)
	setID := javaRemoteParentProgramID(t, objects.ObiJavaRemoteParentSetsockopt)

	cgroup, err := os.Open(topology.parent)
	require.NoError(t, err)
	defer cgroup.Close()
	target := int(cgroup.Fd())

	// A legacy single-program attachment conflicts with cgroup links'
	// multi-program mode and forces the second bridge attach to fail.
	require.NoError(t, link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  target,
		Program: objects.ObiJavaRemoteParentSetsockopt,
		Attach:  ebpf.AttachCGroupSetsockopt,
		Flags:   0,
	}))
	blockerAttached := true
	defer func() {
		if blockerAttached {
			assert.NoError(t, link.RawDetachProgram(link.RawDetachProgramOptions{
				Target:  target,
				Program: objects.ObiJavaRemoteParentSetsockopt,
				Attach:  ebpf.AttachCGroupSetsockopt,
			}))
		}
	}()

	require.Empty(t, queryCgroupProgramIDs(
		t, topology.parent, ebpf.AttachCGroupGetsockopt,
	))
	require.Equal(
		t,
		[]ebpf.ProgramID{setID},
		queryCgroupProgramIDs(t, topology.parent, ebpf.AttachCGroupSetsockopt),
	)

	originalGet := attachCgroupGetsockopt
	originalSet := attachCgroupSetsockopt
	defer func() {
		attachCgroupGetsockopt = originalGet
		attachCgroupSetsockopt = originalSet
	}()
	getAttachCalls := 0
	setAttachCalls := 0
	getAttachSucceeded := false
	var getIDsBeforeSet []ebpf.ProgramID
	var getQueryErr error
	var setAttachErr error
	attachCgroupGetsockopt = func(program *ebpf.Program) (io.Closer, error) {
		getAttachCalls++
		cgroupLink, err := link.AttachRawLink(link.RawLinkOptions{
			Target:  target,
			Program: program,
			Attach:  ebpf.AttachCGroupGetsockopt,
		})
		getAttachSucceeded = err == nil
		return cgroupLink, err
	}
	attachCgroupSetsockopt = func(program *ebpf.Program) (io.Closer, error) {
		setAttachCalls++
		getIDsBeforeSet, getQueryErr = cgroupProgramIDs(
			topology.parent, ebpf.AttachCGroupGetsockopt,
		)
		var cgroupLink *link.RawLink
		cgroupLink, setAttachErr = link.AttachRawLink(link.RawLinkOptions{
			Target:  target,
			Program: program,
			Attach:  ebpf.AttachCGroupSetsockopt,
		})
		return cgroupLink, setAttachErr
	}

	links, err := attachJavaRemoteParentSockopt(
		objects.ObiJavaRemoteParentGetsockopt,
		objects.ObiJavaRemoteParentSetsockopt,
	)
	if links != nil {
		defer func() {
			assert.NoError(t, links.Close())
		}()
	}
	require.Equal(t, 1, getAttachCalls)
	require.Equal(t, 1, setAttachCalls)
	require.True(t, getAttachSucceeded)
	require.NoError(t, getQueryErr)
	require.Equal(t, []ebpf.ProgramID{getID}, getIDsBeforeSet)
	require.ErrorIs(t, setAttachErr, unix.EPERM)
	require.ErrorIs(t, err, unix.EPERM)
	require.Nil(t, links)
	require.Empty(t, queryCgroupProgramIDs(
		t, topology.parent, ebpf.AttachCGroupGetsockopt,
	))
	require.Equal(
		t,
		[]ebpf.ProgramID{setID},
		queryCgroupProgramIDs(t, topology.parent, ebpf.AttachCGroupSetsockopt),
	)
	require.Equal(t, getID, javaRemoteParentProgramID(
		t, objects.ObiJavaRemoteParentGetsockopt,
	))

	require.NoError(t, link.RawDetachProgram(link.RawDetachProgramOptions{
		Target:  target,
		Program: objects.ObiJavaRemoteParentSetsockopt,
		Attach:  ebpf.AttachCGroupSetsockopt,
	}))
	blockerAttached = false
	require.Empty(t, queryCgroupProgramIDs(
		t, topology.parent, ebpf.AttachCGroupGetsockopt,
	))
	require.Empty(t, queryCgroupProgramIDs(
		t, topology.parent, ebpf.AttachCGroupSetsockopt,
	))

	require.NoError(t, objects.Close())
	objectsOpen = false
	requireJavaRemoteParentMapsReleased(t, mapIdentities)
}

func TestJavaRemoteParentCgroupV2MountPath(t *testing.T) {
	mounts, err := parseCgroupV2MountInfo(
		"36 30 0:30 /delegated /custom\\040cgroup rw,nosuid - cgroup2 cgroup2 rw\n",
	)
	require.NoError(t, err)
	require.Equal(t, []cgroupV2Mount{{
		root:       "/delegated",
		mountPoint: "/custom cgroup",
		writable:   true,
	}}, mounts)

	for _, test := range []struct {
		name       string
		mount      cgroupV2Mount
		membership string
		path       string
		ok         bool
	}{
		{
			name:       "unified root",
			mount:      cgroupV2Mount{root: "/", mountPoint: "/sys/fs/cgroup"},
			membership: "/user.slice/workload",
			path:       "/sys/fs/cgroup/user.slice/workload",
			ok:         true,
		},
		{
			name:       "delegated root",
			mount:      cgroupV2Mount{root: "/user.slice", mountPoint: "/delegated"},
			membership: "/user.slice/workload",
			path:       "/delegated/workload",
			ok:         true,
		},
		{
			name:       "outside mount root",
			mount:      cgroupV2Mount{root: "/other.slice", mountPoint: "/delegated"},
			membership: "/user.slice/workload",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path, ok := cgroupV2PathAtMount(test.mount, test.membership)
			require.Equal(t, test.ok, ok)
			require.Equal(t, test.path, path)
		})
	}
}

func TestJavaRemoteParentCgroupLinkControllerHelper(t *testing.T) {
	if os.Getenv(javaRemoteParentCgroupControllerEnv) != "1" {
		return
	}

	cgroupPath := os.Getenv(javaRemoteParentCgroupPathEnv)
	require.NotEmpty(t, cgroupPath)

	getsockopt, err := ebpf.NewProgramFromFD(
		javaRemoteParentControllerGetsockoptFD,
	)
	require.NoError(t, err)
	defer getsockopt.Close()
	setsockopt, err := ebpf.NewProgramFromFD(
		javaRemoteParentControllerSetsockoptFD,
	)
	require.NoError(t, err)
	defer setsockopt.Close()

	ready := os.NewFile(
		javaRemoteParentControllerReadyFD,
		"java-remote-parent-cgroup-controller-ready",
	)
	require.NotNil(t, ready)
	defer ready.Close()
	hold := os.NewFile(
		javaRemoteParentControllerHoldFD,
		"java-remote-parent-cgroup-controller-hold",
	)
	require.NotNil(t, hold)
	defer hold.Close()

	links, err := attachJavaRemoteParentFixtureAt(
		cgroupPath,
		&BpfJavaRemoteParentPrograms{
			ObiJavaRemoteParentGetsockopt: getsockopt,
			ObiJavaRemoteParentSetsockopt: setsockopt,
		},
	)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, links.Close())
	}()

	_, err = ready.Write([]byte{1})
	require.NoError(t, err)
	require.NoError(t, ready.Close())
	_, err = io.Copy(io.Discard, hold)
	require.NoError(t, err)
}

func TestJavaRemoteParentCgroupWorkloadHelper(t *testing.T) {
	if os.Getenv(javaRemoteParentCgroupHelperEnv) != "1" {
		return
	}

	capability, err := strconv.ParseUint(
		os.Getenv(javaRemoteParentCgroupCapability), 16, 64,
	)
	require.NoError(t, err)
	attached, err := strconv.ParseBool(os.Getenv(javaRemoteParentCgroupAttached))
	require.NoError(t, err)

	release := os.NewFile(3, "java-remote-parent-cgroup-release")
	result := os.NewFile(4, "java-remote-parent-cgroup-result")
	require.NotNil(t, release)
	require.NotNil(t, result)
	defer release.Close()
	defer result.Close()

	var signal [1]byte
	_, err = io.ReadFull(release, signal[:])
	require.NoError(t, err)

	listener := newTCPListener(t)
	defer unix.Close(listener)
	pair := connectTCP(t, listener)
	defer pair.close()

	if !attached {
		requireNativeSockoptUnsupported(t, rawSetsockoptUint64(
			pair.client,
			javabridge.SocketLevel,
			javabridge.SocketNegotiate,
			capability,
		))
		assertNativeSockoptMiss(
			t, pair.client, javabridge.SocketLevel, javabridge.SocketHealth,
		)
		require.NoError(t, binary.Write(result, binary.LittleEndian, uint64(0)))
		return
	}

	cookieStorage, err := ebpf.NewMapFromFD(javaRemoteParentCgroupSocketCookiesFD)
	require.NoError(t, err)
	defer cookieStorage.Close()
	seedJavaRemoteParentSocketCookie(t, cookieStorage, pair.client)

	require.NoError(t, rawSetsockoptUint64(
		pair.client,
		javabridge.SocketLevel,
		javabridge.SocketNegotiate,
		capability,
	))
	health := javaRemoteParentHealthValue(t, pair.client)
	require.Equal(t, capability, health)
	require.NoError(t, binary.Write(result, binary.LittleEndian, health))
}

func requireJavaRemoteParentCgroupTopology(t *testing.T) string {
	t.Helper()

	if os.Geteuid() != 0 {
		if os.Getenv(javaRemoteParentCgroupTestRequired) == "1" {
			t.Fatal("nested cgroup lifecycle test requires root")
		}
		t.Skip("nested cgroup lifecycle test requires root")
	}
	if err := javabridge.HaveSockOpsNetnsCookie(); err != nil {
		t.Skipf("sockops network namespace cookies unsupported: %v", err)
	}
	if err := features.HaveProgramType(ebpf.CGroupSockopt); err != nil {
		t.Skipf("cgroup sockopt BPF programs unsupported: %v", err)
	}
	if err := features.HaveMapType(ebpf.SkStorage); err != nil {
		t.Skipf("BPF socket-local storage unsupported: %v", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot remove the BPF memory lock limit: %v", err)
	}

	relative, err := processCgroupV2Membership("/proc/self/cgroup")
	if err != nil {
		javaRemoteParentCgroupTopologyUnavailable(
			t, "locate unified cgroup membership", err,
		)
	}
	mounts, err := readCgroupV2MountInfo("/proc/self/mountinfo")
	if err != nil {
		javaRemoteParentCgroupTopologyUnavailable(t, "locate cgroup v2 mount", err)
	}

	var unavailable []error
	for _, mount := range mounts {
		if !mount.writable {
			unavailable = append(
				unavailable,
				fmt.Errorf("%s: cgroup v2 mount is read-only", mount.mountPoint),
			)
			continue
		}
		current, ok := cgroupV2PathAtMount(mount, relative)
		if !ok {
			unavailable = append(
				unavailable,
				fmt.Errorf(
					"%s: membership %s is outside mount root %s",
					mount.mountPoint,
					relative,
					mount.root,
				),
			)
			continue
		}

		var stat unix.Statfs_t
		if err := unix.Statfs(current, &stat); err != nil {
			unavailable = append(unavailable, fmt.Errorf("%s: %w", current, err))
			continue
		}
		if stat.Type != int64(cgroup2FilesystemMagic) {
			unavailable = append(
				unavailable,
				fmt.Errorf("%s: not a cgroup v2 filesystem", current),
			)
			continue
		}
		containsSelf, err := cgroupContainsProcess(current, os.Getpid())
		if err != nil {
			unavailable = append(unavailable, fmt.Errorf("%s: %w", current, err))
			continue
		}
		if !containsSelf {
			unavailable = append(
				unavailable,
				fmt.Errorf("%s: current process is not a direct member", current),
			)
			continue
		}
		return current
	}

	javaRemoteParentCgroupTopologyUnavailable(
		t, "locate writable cgroup v2 mount", errors.Join(unavailable...),
	)
	return ""
}

func startJavaRemoteParentCgroupLinkController(
	t *testing.T,
	path string,
	programs *BpfJavaRemoteParentPrograms,
) *javaRemoteParentCgroupLinkController {
	t.Helper()

	getsockopt := duplicateJavaRemoteParentProgram(
		t, programs.ObiJavaRemoteParentGetsockopt, "getsockopt",
	)
	defer getsockopt.Close()
	setsockopt := duplicateJavaRemoteParentProgram(
		t, programs.ObiJavaRemoteParentSetsockopt, "setsockopt",
	)
	defer setsockopt.Close()

	readyReader, readyWriter, err := os.Pipe()
	require.NoError(t, err)
	defer readyReader.Close()
	defer readyWriter.Close()
	holdReader, holdWriter, err := os.Pipe()
	require.NoError(t, err)
	defer holdReader.Close()

	controller := &javaRemoteParentCgroupLinkController{
		holdWriter: holdWriter,
	}
	t.Cleanup(func() {
		controller.cleanup()
	})

	controller.command = exec.Command(
		os.Args[0],
		"-test.run=^TestJavaRemoteParentCgroupLinkControllerHelper$",
		"-test.v",
	)
	controller.command.Env = append(
		os.Environ(),
		javaRemoteParentCgroupControllerEnv+"=1",
		javaRemoteParentCgroupPathEnv+"="+path,
	)
	controller.command.ExtraFiles = []*os.File{
		getsockopt,
		setsockopt,
		readyWriter,
		holdReader,
	}
	controller.command.Stdout = &controller.output
	controller.command.Stderr = &controller.output

	require.NoError(t, controller.command.Start())
	require.NoError(t, getsockopt.Close())
	require.NoError(t, setsockopt.Close())
	require.NoError(t, readyWriter.Close())
	require.NoError(t, holdReader.Close())

	require.NoError(t, readyReader.SetReadDeadline(time.Now().Add(15*time.Second)))
	var ready [1]byte
	if _, err := io.ReadFull(readyReader, ready[:]); err != nil {
		_ = controller.command.Process.Kill()
		waitErr := controller.command.Wait()
		controller.waited = true
		t.Fatalf(
			"cgroup link controller did not become ready: %v (wait: %v)\n%s",
			err,
			waitErr,
			controller.output.String(),
		)
	}
	require.Equal(t, byte(1), ready[0])
	return controller
}

func duplicateJavaRemoteParentProgram(
	t *testing.T,
	program *ebpf.Program,
	name string,
) *os.File {
	t.Helper()

	duplicate, err := unix.FcntlInt(
		uintptr(program.FD()),
		unix.F_DUPFD_CLOEXEC,
		javaRemoteParentControllerGetsockoptFD,
	)
	require.NoError(t, err)
	file := os.NewFile(
		uintptr(duplicate),
		"java-remote-parent-"+name+"-program",
	)
	if file == nil {
		require.NoError(t, unix.Close(duplicate))
		t.Fatal("wrap duplicated Java remote-parent program fd")
	}
	return file
}

func (c *javaRemoteParentCgroupLinkController) kill(t *testing.T) {
	t.Helper()

	require.False(t, c.waited)
	require.NoError(t, c.command.Process.Kill())
	waitErr := c.command.Wait()
	c.waited = true
	require.NoError(t, c.holdWriter.Close())
	c.holdWriter = nil

	var exitError *exec.ExitError
	require.ErrorAsf(
		t,
		waitErr,
		&exitError,
		"cgroup link controller exited without SIGKILL:\n%s",
		c.output.String(),
	)
	status, ok := exitError.Sys().(syscall.WaitStatus)
	require.True(t, ok)
	require.True(t, status.Signaled())
	require.Equal(t, syscall.SIGKILL, status.Signal())
}

func (c *javaRemoteParentCgroupLinkController) cleanup() {
	if c.command != nil && c.command.Process != nil && !c.waited {
		_ = c.command.Process.Kill()
		_ = c.command.Wait()
		c.waited = true
	}
	if c.holdWriter != nil {
		_ = c.holdWriter.Close()
		c.holdWriter = nil
	}
}

func newJavaRemoteParentCgroupTopology(
	t *testing.T,
	current string,
) javaRemoteParentCgroupTopology {
	t.Helper()

	parent, err := os.MkdirTemp(current, "obi-java-remote-parent-")
	if err != nil {
		javaRemoteParentCgroupTopologyUnavailable(t, "create parent cgroup", err)
	}
	workload := filepath.Join(parent, "workload")
	workloadCreated := false
	t.Cleanup(func() {
		if workloadCreated {
			waitForJavaRemoteParentCgroupEmpty(t, workload)
			if err := unix.Rmdir(workload); err != nil {
				t.Errorf("remove workload cgroup %q: %v", workload, err)
			}
		}
		waitForJavaRemoteParentCgroupEmpty(t, parent)
		if err := unix.Rmdir(parent); err != nil {
			t.Errorf("remove parent cgroup %q: %v", parent, err)
		}
	})

	require.NoError(t, os.Mkdir(workload, 0o755))
	workloadCreated = true
	return javaRemoteParentCgroupTopology{
		parent:   parent,
		workload: workload,
	}
}

func javaRemoteParentCgroupTopologyUnavailable(t *testing.T, operation string, err error) {
	t.Helper()

	if os.Getenv(javaRemoteParentCgroupTestRequired) == "1" {
		t.Fatalf("%s: %v", operation, err)
	}
	t.Skipf("%s unavailable: %v", operation, err)
}

func waitForJavaRemoteParentCgroupEmpty(t *testing.T, path string) {
	t.Helper()

	if path == "" {
		return
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		contents, err := os.ReadFile(filepath.Join(path, "cgroup.events"))
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if err == nil && strings.Contains(string(contents), "populated 0") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("cgroup remained populated: %q", path)
}

func runJavaRemoteParentCgroupGeneration(
	t *testing.T,
	topology javaRemoteParentCgroupTopology,
	capability uint64,
) {
	t.Helper()

	objects := loadJavaRemoteParentFixture(t)
	objectsOpen := true
	defer func() {
		if objectsOpen {
			assert.NoError(t, objects.Close())
		}
	}()
	setJavaRemoteParentDataHookReadiness(t, objects.JavaRemoteParentDataHookReadiness, true)
	mapIdentities := javaRemoteParentMapIdentities(
		t, &objects.BpfJavaRemoteParentMaps,
	)

	links, err := attachJavaRemoteParentFixtureAt(
		topology.parent, &objects.BpfJavaRemoteParentPrograms,
	)
	require.NoError(t, err)
	defer func() {
		if links != nil {
			assert.NoError(t, links.Close())
		}
	}()

	getID := javaRemoteParentProgramID(t, objects.ObiJavaRemoteParentGetsockopt)
	setID := javaRemoteParentProgramID(t, objects.ObiJavaRemoteParentSetsockopt)
	require.Equal(
		t,
		[]ebpf.ProgramID{getID},
		queryCgroupProgramIDs(t, topology.parent, ebpf.AttachCGroupGetsockopt),
	)
	require.Equal(
		t,
		[]ebpf.ProgramID{setID},
		queryCgroupProgramIDs(t, topology.parent, ebpf.AttachCGroupSetsockopt),
	)

	runJavaRemoteParentCgroupWorkload(
		t, topology, &objects.BpfJavaRemoteParentMaps, capability, true,
	)

	require.NoError(t, links.Close())
	links = nil
	require.Empty(t, queryCgroupProgramIDs(
		t, topology.parent, ebpf.AttachCGroupGetsockopt,
	))
	require.Empty(t, queryCgroupProgramIDs(
		t, topology.parent, ebpf.AttachCGroupSetsockopt,
	))

	require.NoError(t, objects.Close())
	objectsOpen = false
	requireJavaRemoteParentMapsReleased(t, mapIdentities)
}

func attachJavaRemoteParentFixtureAt(
	path string,
	programs *BpfJavaRemoteParentPrograms,
) (io.Closer, error) {
	cgroup, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer cgroup.Close()

	getsockoptLink, err := link.AttachRawLink(link.RawLinkOptions{
		Target:  int(cgroup.Fd()),
		Attach:  ebpf.AttachCGroupGetsockopt,
		Program: programs.ObiJavaRemoteParentGetsockopt,
	})
	if err != nil {
		return nil, err
	}

	setsockoptLink, err := link.AttachRawLink(link.RawLinkOptions{
		Target:  int(cgroup.Fd()),
		Attach:  ebpf.AttachCGroupSetsockopt,
		Program: programs.ObiJavaRemoteParentSetsockopt,
	})
	if err != nil {
		return nil, errors.Join(err, getsockoptLink.Close())
	}

	return javaRemoteParentSockoptLinks{
		getsockopt: getsockoptLink,
		setsockopt: setsockoptLink,
	}, nil
}

func queryCgroupProgramIDs(
	t *testing.T,
	path string,
	attach ebpf.AttachType,
) []ebpf.ProgramID {
	t.Helper()

	ids, err := cgroupProgramIDs(path, attach)
	require.NoError(t, err)
	return ids
}

func cgroupProgramIDs(
	path string,
	attach ebpf.AttachType,
) ([]ebpf.ProgramID, error) {
	cgroup, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer cgroup.Close()

	result, err := link.QueryPrograms(link.QueryOptions{
		Target: int(cgroup.Fd()),
		Attach: attach,
	})
	if err != nil {
		return nil, err
	}

	ids := make([]ebpf.ProgramID, 0, len(result.Programs))
	for _, program := range result.Programs {
		ids = append(ids, program.ID)
	}
	return ids, nil
}

func requireCgroupProgramsDetached(
	t *testing.T,
	path string,
) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	var getsockopt []ebpf.ProgramID
	var setsockopt []ebpf.ProgramID
	for time.Now().Before(deadline) {
		getsockopt = queryCgroupProgramIDs(
			t, path, ebpf.AttachCGroupGetsockopt,
		)
		setsockopt = queryCgroupProgramIDs(
			t, path, ebpf.AttachCGroupSetsockopt,
		)
		if len(getsockopt) == 0 && len(setsockopt) == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf(
		"cgroup programs remained attached to %q: getsockopt=%v setsockopt=%v",
		path,
		getsockopt,
		setsockopt,
	)
}

func javaRemoteParentProgramID(t *testing.T, program *ebpf.Program) ebpf.ProgramID {
	t.Helper()

	info, err := program.Info()
	require.NoError(t, err)
	id, ok := info.ID()
	require.True(t, ok)
	return id
}

func javaRemoteParentMapID(t *testing.T, bridgeMap *ebpf.Map) ebpf.MapID {
	t.Helper()

	info, err := bridgeMap.Info()
	require.NoError(t, err)
	id, ok := info.ID()
	require.True(t, ok)
	return id
}

func javaRemoteParentMapIdentities(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
) []javaRemoteParentMapIdentity {
	t.Helper()

	value := reflect.ValueOf(maps).Elem()
	valueType := value.Type()
	identities := make([]javaRemoteParentMapIdentity, 0, value.NumField())
	seen := make(map[ebpf.MapID]string, value.NumField())
	for i := range value.NumField() {
		bridgeMap, ok := value.Field(i).Interface().(*ebpf.Map)
		require.True(t, ok)
		require.NotNil(t, bridgeMap)

		id := javaRemoteParentMapID(t, bridgeMap)
		name := valueType.Field(i).Tag.Get("ebpf")
		require.NotEmpty(t, name)
		if previous, exists := seen[id]; exists {
			t.Fatalf("maps %q and %q share ID %d", previous, name, id)
		}
		seen[id] = name
		identities = append(identities, javaRemoteParentMapIdentity{name: name, id: id})
	}
	return identities
}

func requireJavaRemoteParentMapsReleased(
	t *testing.T,
	identities []javaRemoteParentMapIdentity,
) {
	t.Helper()

	remaining := make(map[ebpf.MapID]string, len(identities))
	for _, identity := range identities {
		remaining[identity.id] = identity.name
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(remaining) != 0 && time.Now().Before(deadline) {
		for id := range remaining {
			bridgeMap, err := ebpf.NewMapFromID(id)
			if errors.Is(err, os.ErrNotExist) {
				delete(remaining, id)
				continue
			}
			require.NoError(t, err)
			require.NoError(t, bridgeMap.Close())
		}
		if len(remaining) == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	names := make([]string, 0, len(remaining))
	for _, name := range remaining {
		names = append(names, name)
	}
	sort.Strings(names)
	t.Fatalf("Java remote-parent maps remained open: %s", strings.Join(names, ", "))
}

func requireJavaRemoteParentMapsPresent(
	t *testing.T,
	identities []javaRemoteParentMapIdentity,
) {
	t.Helper()

	for _, identity := range identities {
		bridgeMap, err := ebpf.NewMapFromID(identity.id)
		require.NoErrorf(t, err, "open Java remote-parent map %q", identity.name)
		require.NoError(t, bridgeMap.Close())
	}
}

func runJavaRemoteParentCgroupWorkload(
	t *testing.T,
	topology javaRemoteParentCgroupTopology,
	maps *BpfJavaRemoteParentMaps,
	capability uint64,
	attached bool,
) {
	t.Helper()

	releaseReader, releaseWriter, err := os.Pipe()
	require.NoError(t, err)
	resultReader, resultWriter, err := os.Pipe()
	if err != nil {
		releaseReader.Close()
		releaseWriter.Close()
		require.NoError(t, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	command := exec.CommandContext(
		ctx,
		os.Args[0],
		"-test.run=^TestJavaRemoteParentCgroupWorkloadHelper$",
		"-test.v",
	)
	command.Env = append(
		os.Environ(),
		javaRemoteParentCgroupHelperEnv+"=1",
		javaRemoteParentCgroupCapability+"="+strconv.FormatUint(capability, 16),
		javaRemoteParentCgroupAttached+"="+strconv.FormatBool(attached),
	)
	extraFiles := []*os.File{releaseReader, resultWriter}
	var socketCookiesFile *os.File
	if maps != nil {
		duplicate, duplicateErr := unix.Dup(maps.JavaRemoteParentSocketCookies.FD())
		require.NoError(t, duplicateErr)
		socketCookiesFile = os.NewFile(
			uintptr(duplicate), "java-remote-parent-socket-cookies",
		)
		require.NotNil(t, socketCookiesFile)
		extraFiles = append(extraFiles, socketCookiesFile)
	}
	command.ExtraFiles = extraFiles
	var output bytes.Buffer
	command.Stdout = &output
	command.Stderr = &output

	started := false
	waited := false
	defer func() {
		releaseReader.Close()
		releaseWriter.Close()
		resultReader.Close()
		resultWriter.Close()
		if socketCookiesFile != nil {
			socketCookiesFile.Close()
		}
		if started && !waited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	}()

	require.NoError(t, command.Start())
	started = true
	require.NoError(t, releaseReader.Close())
	require.NoError(t, resultWriter.Close())

	require.NoError(t, os.WriteFile(
		filepath.Join(topology.workload, "cgroup.procs"),
		[]byte(strconv.Itoa(command.Process.Pid)),
		0,
	))
	requireCgroupContainsProcess(t, topology.workload, command.Process.Pid)

	if maps != nil {
		process := javaRemoteParentProcessKey(t, command.Process.Pid)
		require.NoError(t, maps.JavaAuthorizedProcesses.Update(
			process, capability, ebpf.UpdateAny,
		))
		require.NoError(t, maps.JavaProcessIncarnations.Update(
			process, capability, ebpf.UpdateAny,
		))
	}

	_, err = releaseWriter.Write([]byte{1})
	require.NoError(t, err)
	require.NoError(t, releaseWriter.Close())

	result, readErr := io.ReadAll(resultReader)
	waitErr := command.Wait()
	waited = true
	require.NoError(t, readErr)
	require.NoErrorf(t, waitErr, "workload helper failed:\n%s", output.String())
	require.Len(t, result, 8)

	health := binary.LittleEndian.Uint64(result)
	if attached {
		require.Equal(t, capability, health)
	} else {
		require.Zero(t, health)
	}
}

func readCgroupV2MountInfo(path string) ([]cgroupV2Mount, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseCgroupV2MountInfo(string(contents))
}

func parseCgroupV2MountInfo(contents string) ([]cgroupV2Mount, error) {
	var mounts []cgroupV2Mount
	for line := range strings.SplitSeq(strings.TrimSpace(contents), "\n") {
		fields := strings.Fields(line)
		separator := -1
		for i, field := range fields {
			if field == "-" {
				separator = i
				break
			}
		}
		if separator < 6 || separator+2 >= len(fields) || fields[separator+1] != "cgroup2" {
			continue
		}

		mounts = append(mounts, cgroupV2Mount{
			root:       unescapeMountInfoPath(fields[3]),
			mountPoint: unescapeMountInfoPath(fields[4]),
			writable:   mountInfoOption(fields[5], "rw"),
		})
	}
	if len(mounts) == 0 {
		return nil, errors.New("cgroup v2 mount unavailable")
	}
	return mounts, nil
}

func unescapeMountInfoPath(path string) string {
	return strings.NewReplacer(
		"\\040", " ",
		"\\011", "\t",
		"\\012", "\n",
		"\\134", "\\",
	).Replace(path)
}

func mountInfoOption(options string, expected string) bool {
	for option := range strings.SplitSeq(options, ",") {
		if option == expected {
			return true
		}
	}
	return false
}

func cgroupV2PathAtMount(mount cgroupV2Mount, membership string) (string, bool) {
	relative, err := filepath.Rel(
		filepath.Clean(mount.root),
		filepath.Clean(membership),
	)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return "", false
	}
	return filepath.Join(mount.mountPoint, relative), true
}

func requireCgroupContainsProcess(t *testing.T, path string, pid int) {
	t.Helper()

	contains, err := cgroupContainsProcess(path, pid)
	require.NoError(t, err)
	require.Truef(t, contains, "cgroup %q does not contain process %d", path, pid)
}

func cgroupContainsProcess(path string, pid int) (bool, error) {
	contents, err := os.ReadFile(filepath.Join(path, "cgroup.procs"))
	if err != nil {
		return false, err
	}
	expected := strconv.Itoa(pid)
	for process := range strings.FieldsSeq(string(contents)) {
		if process == expected {
			return true, nil
		}
	}
	return false, nil
}

func processCgroupV2Membership(path string) (string, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for line := range strings.SplitSeq(strings.TrimSpace(string(contents)), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || parts[0] != "0" || parts[1] != "" {
			continue
		}
		return filepath.Clean("/" + strings.TrimPrefix(parts[2], "/")), nil
	}
	return "", errors.New("unified cgroup v2 membership unavailable")
}

func javaRemoteParentProcessKey(t *testing.T, pid int) BpfJavaRemoteParentPidKeyT {
	t.Helper()

	require.Positive(t, pid)
	require.LessOrEqual(t, uint64(pid), uint64(^uint32(0)))
	processID := uint32(pid)
	namespace := currentNamespaceID(
		t, fmt.Sprintf("/proc/%d/ns/pid_for_children", pid),
	)
	return BpfJavaRemoteParentPidKeyT{
		Tid: processID,
		Pid: processID,
		Ns:  namespace,
	}
}
