// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && privileged_tests

package tpinjector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/obi/pkg/internal/javabridge"
)

const (
	javaRemoteParentBenchmarkEnv = "OBI_JAVA_REMOTE_PARENT_BENCHMARK"
	primaryBenchmarkWarmupRounds = 16
	primaryBenchmarkRounds       = 512
	unixBenchmarkWarmupRounds    = 8
	unixBenchmarkRounds          = 128
	benchmarkReplayActive        = uint8(1)
)

type bridgeBenchmarkTransport uint8

const (
	bridgeBenchmarkGetsockopt bridgeBenchmarkTransport = iota
	bridgeBenchmarkUnix
)

type bridgeBenchmarkWorker struct {
	index        int
	owner        BpfJavaRemoteParentPidKeyT
	namespaceTID uint32
	jobs         chan bridgeBenchmarkJob
}

type bridgeBenchmarkJob struct {
	transport        bridgeBenchmarkTransport
	getsockoptOption int
	fd               int
	socket           string
	request          []byte
	deadline         time.Duration
	ready            chan<- struct{}
	start            <-chan struct{}
	results          chan<- bridgeBenchmarkCall
}

type bridgeBenchmarkCall struct {
	worker      int
	duration    time.Duration
	completedAt time.Time
	record      javabridge.Record
	timedOut    bool
	err         error
}

type bridgeBenchmarkSeries struct {
	warmupRounds      int
	measurementRounds int
	transport         string
	outcome           string
	durations         []time.Duration
	batchElapsed      time.Duration
	valid             int
	missing           int
	alreadyConsumed   int
	timeouts          int
	errors            int
}

// TestJavaRemoteParentTransportBenchmark is opt-in because it loads and
// attaches the real cgroup programs. Run it on an otherwise idle host with the
// OBI_JAVA_REMOTE_PARENT_BENCHMARK environment variable set to 1.
func TestJavaRemoteParentTransportBenchmark(t *testing.T) {
	if os.Getenv(javaRemoteParentBenchmarkEnv) != "1" {
		t.Skip("set OBI_JAVA_REMOTE_PARENT_BENCHMARK=1 to run the privileged transport benchmark")
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

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	objects := loadJavaRemoteParentFixture(t)
	defer objects.Close()
	setJavaRemoteParentDataHookReadiness(t, objects.JavaRemoteParentDataHookReadiness, true)
	attachJavaRemoteParentFixture(t, &objects.BpfJavaRemoteParentPrograms)

	process, coordinator := currentBridgeIdentities(t)
	const capability = uint64(0x7d6c5b4a39281706)
	require.NoError(t, objects.JavaAuthorizedProcesses.Update(process, capability, ebpf.UpdateAny))
	require.NoError(t, objects.JavaProcessIncarnations.Update(process, capability, ebpf.UpdateAny))

	workers, stopWorkers := startBridgeBenchmarkWorkers(t, process)
	defer stopWorkers()

	listener := newTCPListener(t)
	defer unix.Close(listener)
	pairs := make([]tcpPair, len(workers))
	negotiations := make([]BpfJavaRemoteParentJavaRemoteParentNegotiationT, len(workers))
	for i := range workers {
		pairs[i] = connectTCP(t, listener)
		defer pairs[i].close()
		seedJavaRemoteParentSocketCookie(
			t, objects.JavaRemoteParentSocketCookies, pairs[i].client,
		)

		require.NoError(t, rawSetsockoptUint64(
			pairs[i].client, javabridge.SocketLevel, javabridge.SocketNegotiate, capability,
		))
		negotiations[i] = socketNegotiation(
			t, objects.JavaRemoteParentNegotiations, pairs[i].client,
		)
	}

	nextGeneration := uint64(1_000_000)
	primaryMiss := runPrimaryMissBenchmark(
		t, workers, pairs, negotiations, &objects.BpfJavaRemoteParentMaps,
		process, capability, &nextGeneration,
	)
	primaryHit := runPrimaryHitBenchmark(
		t, workers, pairs, negotiations, &objects.BpfJavaRemoteParentMaps,
		process, capability, &nextGeneration,
	)
	primaryOneShot := runPrimaryOneShotBenchmark(
		t, workers, pairs[0], negotiations[0], &objects.BpfJavaRemoteParentMaps,
		process, coordinator, capability, &nextGeneration,
	)

	for _, worker := range workers {
		deleteBenchmarkMapKey(t, objects.JavaRemoteParentTerminal, worker.owner)
	}
	unixMiss, unixHit, unixTimeout := runUnixBenchmark(
		t, workers, pairs, negotiations, &objects.BpfJavaRemoteParentMaps,
		process, capability, &nextGeneration,
	)

	summaries := make([]bridgeBenchmarkArtifactSeries, 0, 6)
	for _, series := range []*bridgeBenchmarkSeries{
		primaryMiss,
		primaryHit,
		primaryOneShot,
		unixMiss,
		unixHit,
		unixTimeout,
	} {
		summaries = append(summaries, series.report(t))
	}

	if artifactPath := os.Getenv(javaRemoteParentBenchmarkArtifactEnv); artifactPath != "" {
		require.NoError(t, writeBridgeBenchmarkArtifact(artifactPath, summaries))
	}
	for _, summary := range summaries {
		require.Truef(
			t,
			summary.LatencyGate.Passed,
			"bridge benchmark %s/%s failed latency gate %s",
			summary.Transport,
			summary.Outcome,
			summary.LatencyGate.Kind,
		)
	}
}

func startBridgeBenchmarkWorkers(
	t *testing.T,
	process BpfJavaRemoteParentPidKeyT,
) ([]*bridgeBenchmarkWorker, func()) {
	t.Helper()

	type workerInitialization struct {
		worker *bridgeBenchmarkWorker
		err    error
	}

	initializations := make(chan workerInitialization, bridgeBenchmarkConcurrency)
	var wait sync.WaitGroup
	for index := range bridgeBenchmarkConcurrency {
		wait.Add(1)
		go func() {
			defer wait.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()

			namespaceTID, err := currentNamespaceThreadID()
			worker := &bridgeBenchmarkWorker{
				index: index,
				owner: BpfJavaRemoteParentPidKeyT{
					Tid: uint32(unix.Gettid()),
					Pid: process.Pid,
					Ns:  process.Ns,
				},
				namespaceTID: namespaceTID,
				jobs:         make(chan bridgeBenchmarkJob),
			}
			initializations <- workerInitialization{worker: worker, err: err}
			if err != nil {
				return
			}

			for job := range worker.jobs {
				runBridgeBenchmarkJob(worker.index, job)
			}
		}()
	}

	workers := make([]*bridgeBenchmarkWorker, bridgeBenchmarkConcurrency)
	for range bridgeBenchmarkConcurrency {
		initialization := <-initializations
		require.NoError(t, initialization.err)
		require.Equal(t, initialization.worker.owner.Tid, initialization.worker.namespaceTID)
		workers[initialization.worker.index] = initialization.worker
	}

	return workers, func() {
		for _, worker := range workers {
			close(worker.jobs)
		}
		wait.Wait()
	}
}

func currentNamespaceThreadID() (uint32, error) {
	contents, err := os.ReadFile("/proc/thread-self/status")
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(string(contents), "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found || key != "NSpid" {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			break
		}
		id, parseErr := strconv.ParseUint(fields[len(fields)-1], 10, 32)
		if parseErr != nil {
			return 0, fmt.Errorf("parse namespace thread ID: %w", parseErr)
		}
		if id == 0 {
			break
		}
		return uint32(id), nil
	}

	return 0, errors.New("namespace thread ID unavailable")
}

func runBridgeBenchmarkJob(worker int, job bridgeBenchmarkJob) {
	value := make([]byte, javabridge.RecordSize)
	job.ready <- struct{}{}
	<-job.start

	startedAt := time.Now()
	timedOut := false
	var err error
	switch job.transport {
	case bridgeBenchmarkGetsockopt:
		var length int
		length, err = rawGetsockopt(
			job.fd, javabridge.SocketLevel, job.getsockoptOption, value,
		)
		if err == nil && length != len(value) {
			err = fmt.Errorf("getsockopt returned %d bytes, want %d", length, len(value))
		}
	case bridgeBenchmarkUnix:
		timedOut, err = unixBridgeRoundTrip(
			job.socket,
			job.request,
			value,
			job.deadline,
		)
	default:
		err = errors.New("unknown benchmark transport")
	}
	completedAt := time.Now()

	var record javabridge.Record
	if timedOut {
		record.Status = javabridge.StatusTimeout
	} else if err == nil {
		record, err = javabridge.UnmarshalRecord(value)
	}
	job.results <- bridgeBenchmarkCall{
		worker:      worker,
		duration:    completedAt.Sub(startedAt),
		completedAt: completedAt,
		record:      record,
		timedOut:    timedOut,
		err:         err,
	}
}

func runBridgeBenchmarkBatch(
	workers []*bridgeBenchmarkWorker,
	jobs []bridgeBenchmarkJob,
) ([]bridgeBenchmarkCall, time.Duration) {
	ready := make(chan struct{}, len(workers))
	start := make(chan struct{})
	results := make(chan bridgeBenchmarkCall, len(workers))
	for index, worker := range workers {
		job := jobs[index]
		job.ready = ready
		job.start = start
		job.results = results
		worker.jobs <- job
	}
	for range workers {
		<-ready
	}
	releasedAt := time.Now()
	close(start)

	calls := make([]bridgeBenchmarkCall, 0, len(workers))
	completedAt := releasedAt
	for range workers {
		call := <-results
		calls = append(calls, call)
		if call.completedAt.After(completedAt) {
			completedAt = call.completedAt
		}
	}
	return calls, completedAt.Sub(releasedAt)
}

func primaryBenchmarkJobs(
	workers []*bridgeBenchmarkWorker,
	pairs []tcpPair,
) []bridgeBenchmarkJob {
	jobs := make([]bridgeBenchmarkJob, len(workers))
	for index := range workers {
		jobs[index] = bridgeBenchmarkJob{
			transport:        bridgeBenchmarkGetsockopt,
			getsockoptOption: javabridge.SocketTake,
			fd:               pairs[index].client,
		}
	}
	return jobs
}

func runPrimaryMissBenchmark(
	t *testing.T,
	workers []*bridgeBenchmarkWorker,
	pairs []tcpPair,
	negotiations []BpfJavaRemoteParentJavaRemoteParentNegotiationT,
	maps *BpfJavaRemoteParentMaps,
	process BpfJavaRemoteParentPidKeyT,
	capability uint64,
	nextGeneration *uint64,
) *bridgeBenchmarkSeries {
	t.Helper()

	for index, worker := range workers {
		generation := stageBenchmarkGeneration(
			t, maps, process, worker.owner, capability,
			negotiations[index], pairs[index].client, nextGeneration,
		)
		removeBenchmarkGeneration(
			t, maps, worker.owner, negotiations[index], generation,
		)
	}

	series := newBridgeBenchmarkSeries(
		"getsockopt", "miss", primaryBenchmarkWarmupRounds, primaryBenchmarkRounds,
	)
	jobs := primaryBenchmarkJobs(workers, pairs)
	for round := range primaryBenchmarkWarmupRounds + primaryBenchmarkRounds {
		calls, elapsed := runBridgeBenchmarkBatch(workers, jobs)
		for _, call := range calls {
			require.NoError(t, call.err)
			require.Equal(t, javabridge.StatusMissing, call.record.Status)
		}
		if round >= primaryBenchmarkWarmupRounds {
			series.add(calls, elapsed)
		}
	}
	return series
}

func runPrimaryHitBenchmark(
	t *testing.T,
	workers []*bridgeBenchmarkWorker,
	pairs []tcpPair,
	negotiations []BpfJavaRemoteParentJavaRemoteParentNegotiationT,
	maps *BpfJavaRemoteParentMaps,
	process BpfJavaRemoteParentPidKeyT,
	capability uint64,
	nextGeneration *uint64,
) *bridgeBenchmarkSeries {
	t.Helper()

	series := newBridgeBenchmarkSeries(
		"getsockopt", "hit", primaryBenchmarkWarmupRounds, primaryBenchmarkRounds,
	)
	jobs := primaryBenchmarkJobs(workers, pairs)
	for round := range primaryBenchmarkWarmupRounds + primaryBenchmarkRounds {
		expected := make([]uint64, len(workers))
		for index, worker := range workers {
			expected[index] = stageBenchmarkGeneration(
				t, maps, process, worker.owner, capability,
				negotiations[index], pairs[index].client, nextGeneration,
			)
		}

		calls, elapsed := runBridgeBenchmarkBatch(workers, jobs)
		for _, call := range calls {
			require.NoError(t, call.err)
			require.Equal(t, javabridge.StatusValid, call.record.Status)
			require.Equal(t, expected[call.worker], call.record.Generation)
		}
		if round >= primaryBenchmarkWarmupRounds {
			series.add(calls, elapsed)
		}
	}
	return series
}

func runPrimaryOneShotBenchmark(
	t *testing.T,
	workers []*bridgeBenchmarkWorker,
	pair tcpPair,
	negotiation BpfJavaRemoteParentJavaRemoteParentNegotiationT,
	maps *BpfJavaRemoteParentMaps,
	process BpfJavaRemoteParentPidKeyT,
	owner BpfJavaRemoteParentPidKeyT,
	capability uint64,
	nextGeneration *uint64,
) *bridgeBenchmarkSeries {
	t.Helper()

	series := newBridgeBenchmarkSeries(
		"getsockopt", "one_shot", primaryBenchmarkWarmupRounds, primaryBenchmarkRounds,
	)
	jobs := make([]bridgeBenchmarkJob, len(workers))
	for index := range workers {
		jobs[index] = bridgeBenchmarkJob{
			transport:        bridgeBenchmarkGetsockopt,
			getsockoptOption: javabridge.SocketTaskTake,
			fd:               pair.client,
		}
	}

	for round := range primaryBenchmarkWarmupRounds + primaryBenchmarkRounds {
		generation := stageBenchmarkGeneration(
			t, maps, process, owner, capability, negotiation, pair.client, nextGeneration,
		)
		stateKey := BpfJavaRemoteParentJavaRemoteParentKeyT{
			Owner:      owner,
			Generation: generation,
		}
		var state BpfJavaRemoteParentJavaRemoteParentStateT
		require.NoError(t, maps.JavaRemoteParentState.Lookup(stateKey, &state))
		observed := state.ObservedMonotimeNs
		state.Aliases = uint32(len(workers))
		require.NoError(t, maps.JavaRemoteParentState.Update(stateKey, state, ebpf.UpdateExist))
		replayKey := BpfJavaRemoteParentJavaRemoteParentAliasReplayKeyT{
			Owner:                        owner,
			Generation:                   generation,
			GenerationObservedMonotimeNs: observed,
			ProcessIncarnation:           state.ProcessIncarnation,
		}
		require.NoError(t, maps.JavaRemoteParentAliasReplays.Update(
			replayKey,
			javaRemoteParentActiveReplay(t,
				observed,
				uint32(len(workers)),
				benchmarkReplayActive,
				negotiation.Connection,
				negotiation.ConnectionNetns,
				generation,
				pair.client,
			),
			ebpf.UpdateNoExist,
		))
		for _, worker := range workers {
			require.NoError(t, maps.JavaRemoteParentTasks.Update(
				worker.owner,
				BpfJavaRemoteParentJavaRemoteParentTaskT{
					Owner:              owner,
					Generation:         generation,
					ObservedMonotimeNs: observed,
				},
				ebpf.UpdateAny,
			))
		}

		calls, elapsed := runBridgeBenchmarkBatch(workers, jobs)
		valid := 0
		for _, call := range calls {
			require.NoError(t, call.err)
			switch call.record.Status {
			case javabridge.StatusValid:
				valid++
				require.Equal(t, generation, call.record.Generation)
			case javabridge.StatusAlreadyConsumed, javabridge.StatusMissing:
			default:
				require.Failf(t, "unexpected one-shot status", "status=%s", call.record.Status)
			}
		}
		require.Equal(t, 1, valid)
		for _, worker := range workers {
			deleteBenchmarkMapKey(t, maps.JavaRemoteParentTasks, worker.owner)
		}
		deleteBenchmarkMapKey(t, maps.JavaRemoteParentAliasReplays, replayKey)
		requireBenchmarkMapKeyAbsent(t, maps.JavaRemoteParentAliasReplays, replayKey)
		if round >= primaryBenchmarkWarmupRounds {
			series.add(calls, elapsed)
		}
	}
	return series
}

func runUnixBenchmark(
	t *testing.T,
	workers []*bridgeBenchmarkWorker,
	pairs []tcpPair,
	negotiations []BpfJavaRemoteParentJavaRemoteParentNegotiationT,
	maps *BpfJavaRemoteParentMaps,
	process BpfJavaRemoteParentPidKeyT,
	capability uint64,
	nextGeneration *uint64,
) (*bridgeBenchmarkSeries, *bridgeBenchmarkSeries, *bridgeBenchmarkSeries) {
	t.Helper()

	handler := javabridge.NewMapHandler(
		javaRemoteParentBenchmarkMaps(maps),
		30*time.Second,
		javabridge.NewGenerationCoordinator(),
	)
	socketDir := t.TempDir()
	require.NoError(t, os.Chmod(socketDir, 0o700))
	socketPath := filepath.Join(socketDir, "bridge.sock")
	server, err := javabridge.NewServer(javabridge.ServerOptions{
		SocketPath:    socketPath,
		SocketGID:     os.Getegid(),
		Timeout:       bridgeBenchmarkUnixDeadline,
		MaxConcurrent: bridgeBenchmarkConcurrency * 4,
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, handler)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- server.Serve(ctx)
	}()
	defer func() {
		cancel()
		require.NoError(t, server.Close())
		require.NoError(t, <-serveDone)
	}()

	negotiateJobs := unixBenchmarkJobs(
		t, workers, socketPath, javabridge.OperationNegotiate, capability,
	)
	calls, _ := runBridgeBenchmarkBatch(workers, negotiateJobs)
	for _, call := range calls {
		require.NoError(t, call.err)
		require.Equal(t, javabridge.StatusMissing, call.record.Status)
	}

	takeJobs := unixBenchmarkJobs(t, workers, socketPath, javabridge.OperationTake, capability)
	miss := newBridgeBenchmarkSeries(
		"unix", "miss", unixBenchmarkWarmupRounds, unixBenchmarkRounds,
	)
	for round := range unixBenchmarkWarmupRounds + unixBenchmarkRounds {
		calls, elapsed := runBridgeBenchmarkBatch(workers, takeJobs)
		for _, call := range calls {
			require.NoError(t, call.err)
			require.Equal(t, javabridge.StatusMissing, call.record.Status)
		}
		if round >= unixBenchmarkWarmupRounds {
			miss.add(calls, elapsed)
		}
	}

	hit := newBridgeBenchmarkSeries(
		"unix", "hit", unixBenchmarkWarmupRounds, unixBenchmarkRounds,
	)
	for round := range unixBenchmarkWarmupRounds + unixBenchmarkRounds {
		expected := make([]uint64, len(workers))
		for index, worker := range workers {
			expected[index] = stageBenchmarkGeneration(
				t, maps, process, worker.owner, capability,
				negotiations[index], pairs[index].client, nextGeneration,
			)
		}

		calls, elapsed := runBridgeBenchmarkBatch(workers, takeJobs)
		for _, call := range calls {
			require.NoError(t, call.err)
			require.Equal(t, javabridge.StatusValid, call.record.Status)
			require.Equal(t, expected[call.worker], call.record.Generation)
		}
		if round >= unixBenchmarkWarmupRounds {
			hit.add(calls, elapsed)
		}
	}

	timeoutSocketPath := filepath.Join(socketDir, "timeout.sock")
	fullTimeoutRequests, stopTimeoutServer := startUnixBenchmarkNonResponder(
		t,
		timeoutSocketPath,
	)
	defer stopTimeoutServer()
	timeoutJobs := unixBenchmarkJobs(
		t, workers, timeoutSocketPath, javabridge.OperationTake, capability,
	)
	timeout := newBridgeBenchmarkSeries(
		"unix", "timeout", unixBenchmarkWarmupRounds, unixBenchmarkRounds,
	)
	for round := range unixBenchmarkWarmupRounds + unixBenchmarkRounds {
		calls, elapsed := runBridgeBenchmarkBatch(workers, timeoutJobs)
		requireUnixBenchmarkFullRequests(
			t,
			fullTimeoutRequests,
			len(workers),
		)
		for _, call := range calls {
			require.NoError(t, call.err)
			require.True(t, call.timedOut, "Unix timeout control returned without a net timeout")
			require.Equal(t, javabridge.StatusTimeout, call.record.Status)
		}
		if round >= unixBenchmarkWarmupRounds {
			timeout.add(calls, elapsed)
		}
	}

	return miss, hit, timeout
}

func startUnixBenchmarkNonResponder(
	t *testing.T,
	socketPath string,
) (<-chan struct{}, func()) {
	t.Helper()

	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	require.NoError(t, err)
	listener.SetUnlinkOnClose(true)

	serveDone := make(chan error, 1)
	fullRequests := make(chan struct{}, bridgeBenchmarkConcurrency)
	var connections sync.WaitGroup
	go func() {
		for {
			connection, acceptErr := listener.AcceptUnix()
			if acceptErr != nil {
				serveDone <- acceptErr
				return
			}
			connections.Add(1)
			go func() {
				defer connections.Done()
				defer connection.Close()

				request := make([]byte, javabridge.RequestSize)
				if _, readErr := io.ReadFull(connection, request); readErr != nil {
					return
				}
				fullRequests <- struct{}{}
				// Deliberately send no response. A second read waits until the
				// benchmark client reaches its absolute deadline and closes.
				var untilClientClose [1]byte
				_, _ = connection.Read(untilClientClose[:])
			}()
		}
	}()

	return fullRequests, func() {
		require.NoError(t, listener.Close())
		require.ErrorIs(t, <-serveDone, net.ErrClosed)
		connections.Wait()
	}
}

func requireUnixBenchmarkFullRequests(
	t *testing.T,
	fullRequests <-chan struct{},
	want int,
) {
	t.Helper()

	timer := time.NewTimer(bridgeBenchmarkUnixTimeoutP99Limit)
	defer timer.Stop()
	for observed := range want {
		select {
		case <-fullRequests:
		case <-timer.C:
			require.Failf(
				t,
				"Unix benchmark non-responder did not read every request",
				"observed=%d want=%d",
				observed,
				want,
			)
		}
	}
	require.Zero(t, len(fullRequests), "Unix benchmark non-responder observed extra requests")
}

func unixBenchmarkJobs(
	t *testing.T,
	workers []*bridgeBenchmarkWorker,
	socket string,
	operation javabridge.Operation,
	capability uint64,
) []bridgeBenchmarkJob {
	t.Helper()

	jobs := make([]bridgeBenchmarkJob, len(workers))
	for index, worker := range workers {
		request, err := (javabridge.Request{
			Operation:          operation,
			NamespaceTID:       worker.namespaceTID,
			ProcessIncarnation: capability,
		}).MarshalBinary()
		require.NoError(t, err)
		jobs[index] = bridgeBenchmarkJob{
			transport: bridgeBenchmarkUnix,
			socket:    socket,
			request:   request,
			deadline:  bridgeBenchmarkUnixDeadline,
		}
	}
	return jobs
}

func javaRemoteParentBenchmarkMaps(maps *BpfJavaRemoteParentMaps) javabridge.Maps {
	return javabridge.Maps{
		RemoteParents:     maps.JavaRemoteParentFallback,
		Tasks:             maps.JavaRemoteParentTasks,
		VirtualThreads:    maps.JavaVtThreads,
		VTIdentities:      maps.JavaVtIdentities,
		Authorized:        maps.JavaAuthorizedProcesses,
		Incarnations:      maps.JavaProcessIncarnations,
		Connections:       maps.JavaRemoteParentConnections,
		CookieConnections: maps.JavaRemoteParentCookieConnections,
		Ambiguity:         maps.JavaRemoteParentAmbiguity,
		AliasReplays:      maps.JavaRemoteParentAliasReplays,
		Owners:            maps.JavaRemoteParentOwners,
		States:            maps.JavaRemoteParentState,
		Generations:       maps.JavaRemoteParentGenerationIndex,
		Terminals:         maps.JavaRemoteParentTerminal,
		Claims:            maps.JavaRemoteParentClaims,
		OwnerGuards:       maps.JavaRemoteParentOwnerGuards,
		Handoffs:          maps.JavaRemoteParentHandoffs,
		HandoffClaims:     maps.JavaRemoteParentHandoffClaims,
		Retired:           maps.JavaRetiredProcesses,
	}
}

func stageBenchmarkGeneration(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	process BpfJavaRemoteParentPidKeyT,
	owner BpfJavaRemoteParentPidKeyT,
	capability uint64,
	negotiation BpfJavaRemoteParentJavaRemoteParentNegotiationT,
	fd int,
	nextGeneration *uint64,
) uint64 {
	t.Helper()

	generation := *nextGeneration
	(*nextGeneration)++
	nonce := generation ^ uint64(0xa5a5a5a55a5a5a5a)
	stageRemoteParent(
		t,
		maps,
		process,
		owner,
		capability,
		negotiation.Connection,
		negotiation.ConnectionNetns,
		socketCookie(t, fd),
		generation,
		nonce,
	)
	require.NoError(t, acknowledgeRemoteParentData(fd, nonce))
	return generation
}

func removeBenchmarkGeneration(
	t *testing.T,
	maps *BpfJavaRemoteParentMaps,
	owner BpfJavaRemoteParentPidKeyT,
	negotiation BpfJavaRemoteParentJavaRemoteParentNegotiationT,
	generation uint64,
) {
	t.Helper()

	key := BpfJavaRemoteParentJavaRemoteParentKeyT{
		Owner:      owner,
		Generation: generation,
	}
	var state BpfJavaRemoteParentJavaRemoteParentStateT
	require.NoError(t, maps.JavaRemoteParentState.Lookup(key, &state))
	connectionKey := BpfJavaRemoteParentConnectionInfoNsT{
		Connection: negotiation.Connection,
		Netns:      negotiation.ConnectionNetns,
	}
	cookieConnectionKey := BpfJavaRemoteParentConnectionInfoNetnsCookieT{
		Connection: negotiation.Connection,
		NetnsCookie: remoteParentTestNetNSCookie(
			negotiation.ConnectionNetns, generation),
	}
	deleteBenchmarkMapKey(t, maps.JavaRemoteParentConnections, connectionKey)
	deleteBenchmarkMapKey(t, maps.JavaRemoteParentCookieConnections, cookieConnectionKey)
	replayKey := BpfJavaRemoteParentJavaRemoteParentAliasReplayKeyT{
		Owner:                        owner,
		Generation:                   generation,
		GenerationObservedMonotimeNs: state.ObservedMonotimeNs,
		ProcessIncarnation:           state.ProcessIncarnation,
	}
	deleteBenchmarkMapKey(t, maps.JavaRemoteParentAliasReplays, replayKey)
	requireBenchmarkMapKeyAbsent(t, maps.JavaRemoteParentAliasReplays, replayKey)
	deleteBenchmarkMapKey(t, maps.JavaRemoteParentState, key)
	deleteBenchmarkMapKey(t, maps.JavaRemoteParentFallback, owner)
	deleteBenchmarkMapKey(t, maps.JavaRemoteParentGenerationIndex, key)
	deleteBenchmarkMapKey(t, maps.JavaRemoteParentOwners, owner)
	deleteBenchmarkMapKey(t, maps.JavaRemoteParentTerminal, owner)
	deleteBenchmarkMapKey(t, maps.JavaRemoteParentAmbiguity, key)
	deleteBenchmarkMapKey(t, maps.JavaRemoteParentClaims, key)
	deleteBenchmarkMapKey(t, maps.JavaRemoteParentOwnerGuards, owner)
	requireBenchmarkMapKeyAbsent(t, maps.JavaRemoteParentAmbiguity, key)
	requireBenchmarkMapKeyAbsent(t, maps.JavaRemoteParentClaims, key)
	requireBenchmarkMapKeyAbsent(t, maps.JavaRemoteParentOwnerGuards, owner)
}

func deleteBenchmarkMapKey(t *testing.T, benchmarkMap *ebpf.Map, key any) {
	t.Helper()

	err := benchmarkMap.Delete(key)
	require.True(t, err == nil || errors.Is(err, ebpf.ErrKeyNotExist), "delete map key: %v", err)
}

func requireBenchmarkMapKeyAbsent(t *testing.T, benchmarkMap *ebpf.Map, key any) {
	t.Helper()

	value, err := benchmarkMap.LookupBytes(key)
	require.NoError(t, err)
	require.Nil(t, value)
}

func newBridgeBenchmarkSeries(
	transport string,
	outcome string,
	warmupRounds int,
	measurementRounds int,
) *bridgeBenchmarkSeries {
	return &bridgeBenchmarkSeries{
		warmupRounds:      warmupRounds,
		measurementRounds: measurementRounds,
		transport:         transport,
		outcome:           outcome,
		durations:         make([]time.Duration, 0, measurementRounds*bridgeBenchmarkConcurrency),
	}
}

func (s *bridgeBenchmarkSeries) add(calls []bridgeBenchmarkCall, elapsed time.Duration) {
	for _, call := range calls {
		s.durations = append(s.durations, call.duration)
		if call.err != nil {
			s.errors++
			continue
		}
		switch call.record.Status {
		case javabridge.StatusValid:
			s.valid++
		case javabridge.StatusMissing:
			s.missing++
		case javabridge.StatusAlreadyConsumed:
			s.alreadyConsumed++
		case javabridge.StatusTimeout:
			s.timeouts++
		}
	}
	s.batchElapsed += elapsed
}

func (s *bridgeBenchmarkSeries) report(t *testing.T) bridgeBenchmarkArtifactSeries {
	t.Helper()

	require.NotEmpty(t, s.durations)
	require.Positive(t, s.batchElapsed)
	durations := slices.Clone(s.durations)
	slices.Sort(durations)
	summary := bridgeBenchmarkArtifactSeries{
		Transport:           s.transport,
		Outcome:             s.outcome,
		WarmupRounds:        s.warmupRounds,
		MeasurementRounds:   s.measurementRounds,
		Samples:             len(durations),
		Concurrency:         bridgeBenchmarkConcurrency,
		BatchElapsedNS:      s.batchElapsed.Nanoseconds(),
		P50NS:               benchmarkPercentile(durations, 50).Nanoseconds(),
		P95NS:               benchmarkPercentile(durations, 95).Nanoseconds(),
		P99NS:               benchmarkPercentile(durations, 99).Nanoseconds(),
		OperationsPerSecond: float64(len(durations)) / s.batchElapsed.Seconds(),
		Valid:               s.valid,
		Missing:             s.missing,
		AlreadyConsumed:     s.alreadyConsumed,
		Timeout:             s.timeouts,
		Errors:              s.errors,
	}
	summary.Correct = summary.Valid+summary.Missing+summary.AlreadyConsumed+
		summary.Timeout+summary.Errors == summary.Samples && summary.Errors == 0
	summary.LatencyGate = expectedBridgeBenchmarkLatencyGate(s.transport, s.outcome)
	summary.LatencyGate.Passed = bridgeBenchmarkLatencyGatePassed(
		summary.LatencyGate,
		summary.P50NS,
		summary.P99NS,
	)
	require.True(t, summary.Correct)
	t.Logf(
		"bridge_benchmark transport=%s outcome=%s samples=%d concurrency=%d "+
			"p50_ns=%d p95_ns=%d p99_ns=%d ops_per_second=%.0f "+
			"valid=%d missing=%d already_consumed=%d timeout=%d errors=%d "+
			"correct=true gate=%s gate_passed=%t",
		summary.Transport,
		summary.Outcome,
		summary.Samples,
		summary.Concurrency,
		summary.P50NS,
		summary.P95NS,
		summary.P99NS,
		summary.OperationsPerSecond,
		summary.Valid,
		summary.Missing,
		summary.AlreadyConsumed,
		summary.Timeout,
		summary.Errors,
		summary.LatencyGate.Kind,
		summary.LatencyGate.Passed,
	)
	return summary
}

func benchmarkPercentile(sorted []time.Duration, percentile int) time.Duration {
	index := (len(sorted)*percentile + 99) / 100
	if index > 0 {
		index--
	}
	return sorted[index]
}
