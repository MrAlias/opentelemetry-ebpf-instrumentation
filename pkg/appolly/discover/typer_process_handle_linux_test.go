// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package discover

import (
	"log/slog"
	"os"
	"testing"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/app/svc"
	discexec "go.opentelemetry.io/obi/pkg/appolly/discover/exec"
	"go.opentelemetry.io/obi/pkg/appolly/services"
	"go.opentelemetry.io/obi/pkg/internal/procs"
	"go.opentelemetry.io/obi/pkg/obi"
)

func fileInfoWithProcessHandle(t *testing.T, pid, ppid app.PID) *discexec.FileInfo {
	return fileInfoWithProcessIdentity(t, pid, ppid, 0)
}

func fileInfoWithProcessIdentity(
	t *testing.T, pid, ppid app.PID, instanceID uint64,
) *discexec.FileInfo {
	t.Helper()
	handle, err := os.Open("/proc/self")
	require.NoError(t, err)
	fi := discexec.New(discexec.Init{
		Pid:               pid,
		Ppid:              ppid,
		CmdExePath:        "/bin/java",
		ProcessInstanceID: instanceID,
		ProcessHandle:     handle,
	})
	t.Cleanup(func() { require.NoError(t, fi.CloseProcessHandle()) })
	return fi
}

func TestTyperDelayedDeletionPreservesSamePIDReplacement(t *testing.T) {
	const (
		parentPID   = app.PID(70)
		childPID    = app.PID(71)
		oldInstance = uint64(101)
		newInstance = uint64(102)
	)
	parent := discexec.New(discexec.Init{Pid: parentPID, Ino: 700, CmdExePath: "/bin/java"})
	oldChild := fileInfoWithProcessIdentity(t, childPID, parentPID, oldInstance)
	replacement := fileInfoWithProcessIdentity(t, childPID, parentPID, newInstance)
	ty := typer{currentPids: map[app.PID]*discexec.FileInfo{}}

	ty.setCurrentPID(childPID, oldChild)
	ty.setPIDOwners(childPID, oldChild, parent)
	ty.setCurrentPID(childPID, replacement)
	ty.setPIDOwners(childPID, replacement, parent)

	oldDeletion := ty.FilterClassify([]Event[ProcessMatch]{{
		Type: EventDeleted,
		Obj: ProcessMatch{Process: &services.ProcessInfo{
			Pid:               childPID,
			ProcessInstanceID: oldInstance,
		}},
	}})
	require.Len(t, oldDeletion, 1)
	require.Same(t, oldChild, oldDeletion[0].Obj.PIDOwnerFileInfo())
	require.Same(t, parent, oldDeletion[0].Obj.TracerOwnerFileInfo())
	require.Same(t, replacement, ty.currentPids[childPID])
	require.Same(t, replacement, ty.pidOwners[childPID])
	require.Same(t, parent, ty.tracerOwners[childPID])
	require.NotContains(t, ty.processLifecycles, oldInstance)
	require.Contains(t, ty.processLifecycles, newInstance)
	requireProcessHandleClosed(t, oldChild)
	requireProcessHandleOpen(t, replacement)

	newDeletion := ty.FilterClassify([]Event[ProcessMatch]{{
		Type: EventDeleted,
		Obj: ProcessMatch{Process: &services.ProcessInfo{
			Pid:               childPID,
			ProcessInstanceID: newInstance,
		}},
	}})
	require.Len(t, newDeletion, 1)
	require.Same(t, replacement, newDeletion[0].Obj.PIDOwnerFileInfo())
	require.Empty(t, ty.currentPids)
	require.Empty(t, ty.pidOwners)
	require.Empty(t, ty.tracerOwners)
	requireProcessHandleClosed(t, replacement)
}

func requireProcessHandleOpen(t *testing.T, fi *discexec.FileInfo) {
	t.Helper()
	require.NoError(t, fi.UseProcessHandle(func(int) error { return nil }))
}

func requireProcessHandleClosed(t *testing.T, fi *discexec.FileInfo) {
	t.Helper()
	require.ErrorContains(t, fi.UseProcessHandle(func(int) error { return nil }),
		"stable process handle is unavailable")
}

func TestTyperRetiresProcessHandleOnDeletion(t *testing.T) {
	const pid = app.PID(41)
	fi := fileInfoWithProcessHandle(t, pid, 1)
	ty := typer{currentPids: map[app.PID]*discexec.FileInfo{pid: fi}}

	out := ty.FilterClassify([]Event[ProcessMatch]{{
		Type: EventDeleted,
		Obj:  ProcessMatch{Process: &services.ProcessInfo{Pid: pid}},
	}})

	require.Len(t, out, 1)
	requireProcessHandleClosed(t, fi)
}

func TestTyperRetiresSupersededAndShutdownProcessHandles(t *testing.T) {
	const pid = app.PID(42)
	old := fileInfoWithProcessHandle(t, pid, 1)
	replacement := fileInfoWithProcessHandle(t, pid, 1)
	ty := typer{currentPids: map[app.PID]*discexec.FileInfo{pid: old}}

	ty.setCurrentPID(pid, replacement)
	requireProcessHandleClosed(t, old)
	requireProcessHandleOpen(t, replacement)

	ty.closeProcessHandles()
	requireProcessHandleClosed(t, replacement)
}

func TestTyperRetainsExactChildHandleWhenParentIsSelected(t *testing.T) {
	const (
		parentPID = app.PID(50)
		childPID  = app.PID(51)
	)
	parent := fileInfoWithProcessHandle(t, parentPID, 1)
	child := fileInfoWithProcessHandle(t, childPID, parentPID)
	cache, err := lru.New[cacheKey, instrumentedExecutable](4)
	require.NoError(t, err)
	cfg := &obi.Config{}
	cfg.Discovery.SkipGoSpecificTracers = true
	ty := typer{
		cfg:                 cfg,
		log:                 slog.Default(),
		currentPids:         map[app.PID]*discexec.FileInfo{parentPID: parent},
		instrumentableCache: cache,
	}

	instrumentable := ty.classifyInstrumentable(child)

	require.Same(t, parent, instrumentable.FileInfo)
	require.Same(t, child, instrumentable.PIDOwnerFor(childPID))
	require.Same(t, child, ty.pidOwners[childPID])
	require.Same(t, parent, ty.tracerOwners[childPID])
	requireProcessHandleOpen(t, child)
	requireProcessHandleOpen(t, parent)
}

func TestTyperRecordsExactOwnersAcrossGrandparentSubstitution(t *testing.T) {
	const (
		grandparentPID = app.PID(54)
		parentPID      = app.PID(55)
		childPID       = app.PID(56)
	)
	grandparent := fileInfoWithProcessIdentity(t, grandparentPID, 1, 201)
	parent := fileInfoWithProcessIdentity(t, parentPID, grandparentPID, 202)
	child := fileInfoWithProcessIdentity(t, childPID, parentPID, 203)
	cache, err := lru.New[cacheKey, instrumentedExecutable](4)
	require.NoError(t, err)
	cfg := &obi.Config{}
	cfg.Discovery.SkipGoSpecificTracers = true
	ty := typer{
		cfg: cfg,
		log: slog.Default(),
		currentPids: map[app.PID]*discexec.FileInfo{
			grandparentPID: grandparent,
			parentPID:      parent,
			childPID:       child,
		},
		instrumentableCache: cache,
	}

	instrumentable := ty.classifyInstrumentable(child)

	require.Same(t, grandparent, instrumentable.FileInfo)
	require.Equal(t, []app.PID{childPID, parentPID}, instrumentable.ChildPids)
	for pid, owner := range map[app.PID]*discexec.FileInfo{
		grandparentPID: grandparent,
		parentPID:      parent,
		childPID:       child,
	} {
		require.Same(t, owner, instrumentable.PIDOwnerFor(pid))
		require.Same(t, owner, ty.pidOwners[pid])
		require.Same(t, grandparent, ty.tracerOwners[pid])
	}
	requireProcessHandleOpen(t, child)
	requireProcessHandleOpen(t, parent)
	requireProcessHandleOpen(t, grandparent)
}

func TestTyperStopsAtCyclicParentHistory(t *testing.T) {
	const (
		firstPID  = app.PID(100)
		secondPID = app.PID(200)
	)
	first := discexec.New(discexec.Init{Pid: firstPID, Ppid: secondPID, CmdExePath: "/bin/java"})
	second := discexec.New(discexec.Init{Pid: secondPID, Ppid: firstPID, CmdExePath: "/bin/java"})
	cache, err := lru.New[cacheKey, instrumentedExecutable](4)
	require.NoError(t, err)
	cfg := &obi.Config{}
	cfg.Discovery.SkipGoSpecificTracers = true
	ty := typer{
		cfg: cfg,
		log: slog.Default(),
		currentPids: map[app.PID]*discexec.FileInfo{
			firstPID:  first,
			secondPID: second,
		},
		instrumentableCache: cache,
	}

	instrumentable := ty.classifyInstrumentable(first)

	require.Same(t, second, instrumentable.FileInfo)
	require.Equal(t, []app.PID{firstPID}, instrumentable.ChildPids)
}

func TestTyperRejectsParentWhoseExactHandleHasAnotherPID(t *testing.T) {
	selfPID := app.PID(os.Getpid())
	start, err := procs.ProcessStartTime(selfPID)
	require.NoError(t, err)
	parentHandle, err := os.Open("/proc/self")
	require.NoError(t, err)
	parent := discexec.New(discexec.Init{
		Pid:           selfPID + 1,
		Ppid:          1,
		CmdExePath:    "/bin/java",
		ProcessStart:  start,
		ProcessHandle: parentHandle,
	})
	t.Cleanup(func() { require.NoError(t, parent.CloseProcessHandle()) })
	child := discexec.New(discexec.Init{
		Pid:        selfPID + 2,
		Ppid:       parent.Pid(),
		CmdExePath: "/bin/java",
	})
	cache, err := lru.New[cacheKey, instrumentedExecutable](4)
	require.NoError(t, err)
	cfg := &obi.Config{}
	cfg.Discovery.SkipGoSpecificTracers = true
	ty := typer{
		cfg:                 cfg,
		log:                 slog.Default(),
		currentPids:         map[app.PID]*discexec.FileInfo{parent.Pid(): parent},
		instrumentableCache: cache,
	}

	instrumentable := ty.classifyInstrumentable(child)

	require.Same(t, child, instrumentable.FileInfo)
	require.Empty(t, instrumentable.ChildPids)
}

func TestTyperRechecksChildAfterCandidateParentValidation(t *testing.T) {
	const (
		parentPID = app.PID(70)
		childPID  = app.PID(71)
	)
	parent := discexec.New(discexec.Init{Pid: parentPID, Ppid: 1, CmdExePath: "/bin/java"})
	child := discexec.New(discexec.Init{Pid: childPID, Ppid: parentPID, CmdExePath: "/bin/java"})
	originalParentPID := currentProcessParentPID
	t.Cleanup(func() { currentProcessParentPID = originalParentPID })
	childReads := 0
	currentProcessParentPID = func(fi *discexec.FileInfo) (app.PID, bool) {
		if fi == child {
			childReads++
			if childReads == 1 {
				return parentPID, true
			}
			// The exact child was reparented while the old numeric parent PID
			// became available for an unrelated replacement.
			return 1, true
		}
		return fi.Ppid(), true
	}
	cache, err := lru.New[cacheKey, instrumentedExecutable](4)
	require.NoError(t, err)
	cfg := &obi.Config{}
	cfg.Discovery.SkipGoSpecificTracers = true
	ty := typer{
		cfg:                 cfg,
		log:                 slog.Default(),
		currentPids:         map[app.PID]*discexec.FileInfo{parentPID: parent},
		instrumentableCache: cache,
	}

	instrumentable := ty.classifyInstrumentable(child)

	require.Same(t, child, instrumentable.FileInfo)
	require.Empty(t, instrumentable.ChildPids)
}

func TestTyperRejectsSamePathParentWithDifferentExecutableIdentity(t *testing.T) {
	const (
		parentPID = app.PID(75)
		childPID  = app.PID(76)
	)
	parent := discexec.New(discexec.Init{
		Pid: parentPID, Ppid: 1, Dev: 8, Ino: 100, CmdExePath: "/bin/java",
	})
	child := discexec.New(discexec.Init{
		Pid: childPID, Ppid: parentPID, Dev: 8, Ino: 200, CmdExePath: "/bin/java",
	})
	cache, err := lru.New[cacheKey, instrumentedExecutable](4)
	require.NoError(t, err)
	cfg := &obi.Config{}
	cfg.Discovery.SkipGoSpecificTracers = true
	ty := typer{
		cfg:                 cfg,
		log:                 slog.Default(),
		currentPids:         map[app.PID]*discexec.FileInfo{parentPID: parent},
		instrumentableCache: cache,
	}

	instrumentable := ty.classifyInstrumentable(child)

	require.Same(t, child, instrumentable.FileInfo)
	require.Empty(t, instrumentable.ChildPids)
}

func TestTyperCacheHitStillSelectsExactGenericParent(t *testing.T) {
	const (
		parentPID = app.PID(80)
		childPID  = app.PID(81)
	)
	parent := discexec.New(discexec.Init{
		Pid: parentPID, Ppid: 1, Dev: 8, Ino: 81, CmdExePath: "/bin/java",
	})
	child := discexec.New(discexec.Init{
		Pid: childPID, Ppid: parentPID, Dev: 8, Ino: 81, CmdExePath: "/bin/java",
	})
	cache, err := lru.New[cacheKey, instrumentedExecutable](4)
	require.NoError(t, err)
	cache.Add(cacheKey{Dev: child.Dev(), Ino: child.Ino()}, instrumentedExecutable{
		Type: svc.InstrumentableJava,
	})
	ty := typer{
		log:                 slog.Default(),
		currentPids:         map[app.PID]*discexec.FileInfo{parentPID: parent, childPID: child},
		instrumentableCache: cache,
	}

	instrumentable := ty.classifyInstrumentable(child)

	require.Same(t, parent, instrumentable.FileInfo)
	require.Equal(t, []app.PID{childPID}, instrumentable.ChildPids)
}

func TestTyperChildDeletionPreservesParentAdmissionOwner(t *testing.T) {
	const (
		parentPID = app.PID(60)
		childPID  = app.PID(61)
	)
	parent := fileInfoWithProcessHandle(t, parentPID, 1)
	child := fileInfoWithProcessHandle(t, childPID, parentPID)
	ty := typer{
		currentPids:  map[app.PID]*discexec.FileInfo{childPID: child},
		pidOwners:    map[app.PID]*discexec.FileInfo{childPID: child},
		tracerOwners: map[app.PID]*discexec.FileInfo{childPID: parent},
	}

	out := ty.FilterClassify([]Event[ProcessMatch]{
		{
			Type: EventDeleted,
			Obj:  ProcessMatch{Process: &services.ProcessInfo{Pid: childPID}},
		},
	})

	require.Len(t, out, 1)
	require.Same(t, child, out[0].Obj.FileInfo)
	require.Same(t, child, out[0].Obj.PIDOwnerFileInfo())
	require.Same(t, parent, out[0].Obj.TracerOwnerFileInfo())
	requireProcessHandleClosed(t, child)
	requireProcessHandleOpen(t, parent)
	require.NotContains(t, ty.currentPids, childPID)
	require.NotContains(t, ty.pidOwners, childPID)
	require.NotContains(t, ty.tracerOwners, childPID)
}
