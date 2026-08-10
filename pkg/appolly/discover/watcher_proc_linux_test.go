// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/obi"
)

func testProcessIdentity(
	t *testing.T,
	path string,
	pid app.PID,
	start uint64,
) (*processIdentityLease, *os.File) {
	t.Helper()
	handle, err := os.Open(path)
	require.NoError(t, err)
	info, err := handle.Stat()
	require.NoError(t, err)
	stat, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok)
	return newProcessIdentityLease(handle, pid, start, stat.Dev, stat.Ino), handle
}

func TestSnapshotDetectsSameTickPIDReuseByStableProcessDirectory(t *testing.T) {
	const (
		pid   = app.PID(42)
		start = uint64(100)
	)
	oldIdentity, oldHandle := testProcessIdentity(t, t.TempDir(), pid, start)
	replacementIdentity, replacementHandle := testProcessIdentity(t, t.TempDir(), pid, start)
	oldProcess := ProcessAttrs{pid: pid, processStart: start, processIdentity: oldIdentity}
	replacement := ProcessAttrs{pid: pid, processStart: start, processIdentity: replacementIdentity}
	acc := pollAccounter{
		cfg:      &obi.Config{},
		pids:     map[app.PID]ProcessAttrs{pid: oldProcess},
		pidPorts: map[pidPort]ProcessAttrs{},
		executableReady: func(app.PID) (string, bool) {
			return "", true
		},
	}

	events := acc.snapshot(map[app.PID]ProcessAttrs{pid: replacement})
	require.Len(t, events, 2)
	assert.Equal(t, EventDeleted, events[0].Type)
	assert.Nil(t, events[0].Obj.processIdentity)
	assert.Equal(t, EventCreated, events[1].Type)
	assert.NotNil(t, events[1].Obj.processIdentity)
	_, err := oldHandle.Stat()
	require.Error(t, err, "replaced watcher identity must be closed")
	_, err = replacementHandle.Stat()
	require.NoError(t, err, "replacement cache must retain its identity")

	_ = events[1].Obj.closeProcessIdentity()
	acc.closeTrackedProcessIdentities()
	_, err = replacementHandle.Stat()
	require.Error(t, err, "all replacement identity leases must be closed")
}

func TestSnapshotClosesSameLifetimeRefreshAndNotReadyIdentity(t *testing.T) {
	const (
		pid   = app.PID(43)
		start = uint64(101)
	)
	path := t.TempDir()
	oldIdentity, oldHandle := testProcessIdentity(t, path, pid, start)
	refreshIdentity, refreshHandle := testProcessIdentity(t, path, pid, start)
	acc := pollAccounter{
		cfg:      &obi.Config{},
		pids:     map[app.PID]ProcessAttrs{pid: {pid: pid, processStart: start, processIdentity: oldIdentity}},
		pidPorts: map[pidPort]ProcessAttrs{},
		executableReady: func(app.PID) (string, bool) {
			return "", true
		},
	}

	assert.Empty(t, acc.snapshot(map[app.PID]ProcessAttrs{
		pid: {pid: pid, processStart: start, processIdentity: refreshIdentity},
	}))
	_, err := refreshHandle.Stat()
	require.Error(t, err, "redundant refresh identity must be closed")
	_, err = oldHandle.Stat()
	require.NoError(t, err, "original watcher anchor must remain open")

	const notReadyPID = app.PID(44)
	notReadyIdentity, notReadyHandle := testProcessIdentity(t, t.TempDir(), notReadyPID, 102)
	acc.executableReady = func(app.PID) (string, bool) { return "", false }
	assert.Empty(t, acc.snapshot(map[app.PID]ProcessAttrs{
		pid: acc.pids[pid],
		notReadyPID: {
			pid: notReadyPID, processStart: 102, processIdentity: notReadyIdentity,
		},
	}))
	_, err = notReadyHandle.Stat()
	require.Error(t, err, "non-emitted identity must be closed")
	_, err = oldHandle.Stat()
	require.NoError(t, err, "tracked identity must remain open")
	acc.closeTrackedProcessIdentities()
	_, err = oldHandle.Stat()
	require.Error(t, err, "shutdown must close the tracked identity")
}

func TestKubeCacheReplacesReemittedPIDIdentity(t *testing.T) {
	const (
		pid         = app.PID(45)
		start       = uint64(103)
		containerID = "container-45"
	)
	firstIdentity, firstHandle := testProcessIdentity(t, t.TempDir(), pid, start)
	secondIdentity, secondHandle := testProcessIdentity(t, t.TempDir(), pid, start)
	wk := watcherKubeEnricher{
		processByContainer: map[string][]ProcessAttrs{},
	}

	first := ProcessAttrs{pid: pid, processStart: start, processIdentity: firstIdentity}
	require.True(t, wk.cacheProcess(containerID, first))
	require.NoError(t, first.closeProcessIdentity())
	_, err := firstHandle.Stat()
	require.NoError(t, err,
		"the first cached lease must keep its descriptor open")

	second := ProcessAttrs{pid: pid, processStart: start, processIdentity: secondIdentity}
	secondState := secondIdentity.state
	require.True(t, wk.cacheProcess(containerID, second))
	require.NoError(t, second.closeProcessIdentity())
	_, err = firstHandle.Stat()
	require.Error(t, err, "re-emission must retire the previous cached descriptor")
	require.Len(t, wk.processByContainer[containerID], 1)
	assert.Same(t, secondState,
		wk.processByContainer[containerID][0].processIdentity.state)
	_, err = secondHandle.Stat()
	require.NoError(t, err, "replacement cache must retain the new descriptor")

	wk.closeProcessIdentities()
	_, err = secondHandle.Stat()
	require.Error(t, err, "cache shutdown must close the replacement descriptor")
}

func TestFetchProcessPortsFailsClosedWhenIdentityReadFails(t *testing.T) {
	originalPIDs := processPidsFunc
	originalIdentityRead := readProcessIdentityFromProcFD
	originalCapture := processIdentityForPIDFunc
	originalValidation := validateProcessIdentityFunc
	t.Cleanup(func() {
		processPidsFunc = originalPIDs
		readProcessIdentityFromProcFD = originalIdentityRead
		processIdentityForPIDFunc = originalCapture
		validateProcessIdentityFunc = originalValidation
	})
	processPidsFunc = func() ([]int32, error) { return []int32{int32(os.Getpid())}, nil }
	readProcessIdentityFromProcFD = func(int) (app.PID, uint64, byte, error) {
		return 0, 0, 0, errors.New("injected start read failure")
	}
	processIdentityForPIDFunc = processIdentityForPID

	processes, err := fetchProcessPorts(false, nil)
	require.NoError(t, err)
	assert.Empty(t, processes, "an observation without exact identity must be skipped")
}

func TestFetchProcessPortsReusesTrackedProcessIdentity(t *testing.T) {
	const pid = app.PID(47)
	originalPIDs := processPidsFunc
	originalCapture := processIdentityForPIDFunc
	originalValidation := validateProcessIdentityFunc
	originalProcessAge := processAgeFunc
	t.Cleanup(func() {
		processPidsFunc = originalPIDs
		processIdentityForPIDFunc = originalCapture
		validateProcessIdentityFunc = originalValidation
		processAgeFunc = originalProcessAge
	})

	identity, handle := testProcessIdentity(t, t.TempDir(), pid, 103)
	hints := map[app.PID]*processIdentityLease{pid: identity}
	processPidsFunc = func() ([]int32, error) { return []int32{int32(pid)}, nil }
	captures := 0
	processIdentityForPIDFunc = func(app.PID) (*processIdentityLease, error) {
		captures++
		return nil, errors.New("unexpected replacement capture")
	}
	validateProcessIdentityFunc = func(*processIdentityLease) error { return nil }
	processAgeFunc = func(app.PID) time.Duration { return 0 }

	processes, err := fetchProcessPorts(false, hints)
	require.NoError(t, err)
	assert.Zero(t, captures, "an unchanged PID must keep using its retained proc-directory handle")
	assert.Empty(t, hints, "ownership of the retained identity must transfer to the observation")
	process, ok := processes[pid]
	require.True(t, ok)
	require.Same(t, identity, process.processIdentity)
	require.NoError(t, process.closeProcessIdentity())
	_, err = handle.Stat()
	require.Error(t, err, "closing the observation must release its transferred identity")
}

func TestParseProcStatField(t *testing.T) {
	// this has excessive whitespace on purpose
	const procPidStat = " 1197473 (foo bar) R   1494929 1197473 1494929 34817 1197473 4194304 91 " +
		"0 0 0 0 0 0 0 20 0 1 0 164004305 8724480 1364    18446744073709551615 93963828355072 " +
		"93963828373377 140721901331744 0 0 0 0 0 0 0 0 0    17 4 0 0 0 0 0 93963828386384 " +
		"93963828387944 93964083773440 140721901340217 140721901340237 140721901340237 " +
		"140721901342699 0"

	inParens := false

	f := func(c rune) bool {
		if c == '(' {
			inParens = true
			return true
		}

		if inParens {
			if c == ')' {
				inParens = false
				return true
			}

			return false
		}

		return c == ' '
	}

	expected := strings.FieldsFunc(procPidStat, f)

	for i := range expected {
		assert.Equal(t, expected[i], parseProcStatField(procPidStat, i+1))
	}

	// test a few fields explicitly to ensure whitespace is being handled
	// properly
	assert.Empty(t, parseProcStatField(procPidStat, 0))
	assert.Empty(t, parseProcStatField(procPidStat, 200))
	assert.Equal(t, "1197473", parseProcStatField(procPidStat, 1))
	assert.Equal(t, "foo bar", parseProcStatField(procPidStat, 2))
	assert.Equal(t, "R", parseProcStatField(procPidStat, 3))
	assert.Equal(t, "1494929", parseProcStatField(procPidStat, 4))

	// empty input
	assert.Empty(t, parseProcStatField("", 0))
	assert.Empty(t, parseProcStatField("", 1))
	assert.Empty(t, parseProcStatField("", 200))
	assert.Empty(t, parseProcStatField("", -1))
}

func TestGetProcStatField(t *testing.T) {
	r := procStatReader{}
	assert.Empty(t, r.getProcStatField(0, 0))
	assert.Empty(t, r.getProcStatField(0xFFFFFFFF, 0))

	pid := os.Getpid()

	exePath, err := os.Executable()

	require.NoError(t, err)

	exe := filepath.Base(exePath)

	assert.Equal(t, exe, r.getProcStatField(app.PID(pid), 2))
}

func TestNSToDuration(t *testing.T) {
	assert.Equal(t, time.Duration(math.MaxInt64), nsToDuration(math.MaxUint64))
	assert.Equal(t, time.Duration(0), nsToDuration(0))
}

func TestProcessAge(t *testing.T) {
	r := procStatReader{}

	assert.Zero(t, r.processAge(0))

	age := r.processAge(app.PID(os.Getpid()))

	require.NotZero(t, age)

	expected, err := time.ParseDuration("2m")

	require.NoError(t, err)

	assert.Less(t, age, expected)
}

func TestProcessAgeFuncConcurrent(t *testing.T) {
	processAge := ProcessAgeFunc()
	pid := app.PID(os.Getpid())

	const goroutines = 8
	const iterations = 100

	errCh := make(chan error, goroutines)
	var wg sync.WaitGroup

	for range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for range iterations {
				if age := processAge(pid); age <= 0 {
					errCh <- fmt.Errorf("expected positive process age for pid %d", pid)
					return
				}
			}
		}()
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		require.NoError(t, err)
	}
}
