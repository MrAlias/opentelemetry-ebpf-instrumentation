// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const (
	pidfdChildProcessEnv = "OBI_SECURITY_PROBE_PIDFD_CHILD"
	pidfdChildMarker     = byte(0x5e)
)

func TestRequestUsesCurrentDirectSourceAndVersionedNamespaceIdentity(t *testing.T) {
	request := marshalRequest(42, 99)

	require.Len(t, request, requestSize)
	assert.Equal(t, "OBIQ", string(request[:4]))
	assert.Equal(t, uint16(3), requestVersion)
	assert.Equal(t, uint16(3), binary.LittleEndian.Uint16(request[4:6]))
	assert.Equal(t, 24, requestSize)
	assert.EqualValues(t, requestSize, binary.LittleEndian.Uint16(request[6:8]))
	assert.Equal(t, byte(1), operationTake)
	assert.Equal(t, operationTake, request[8])
	assert.Equal(t, byte(1), sourceDirect)
	assert.Equal(t, byte(1), request[9])
	assert.Equal(t, []byte{0, 0}, request[10:12])
	assert.EqualValues(t, 42, binary.LittleEndian.Uint32(request[12:16]))
	assert.EqualValues(t, 99, binary.LittleEndian.Uint64(request[16:24]))
}

func TestAbuseIdentityRequestsEncodeOptionalLiveJavaTID(t *testing.T) {
	const peerTID = uint32(42)
	liveJavaTID := uint32(31337)
	for _, test := range []struct {
		name      string
		forgedTID *uint32
		want      []struct {
			name string
			tid  uint32
		}
	}{
		{
			name:      "default identities",
			forgedTID: nil,
			want: []struct {
				name string
				tid  uint32
			}{
				{name: "peer-identity", tid: peerTID},
				{name: "forged-identity", tid: ^uint32(0)},
			},
		},
		{
			name:      "live Java forgery",
			forgedTID: &liveJavaTID,
			want: []struct {
				name string
				tid  uint32
			}{
				{name: "peer-identity", tid: peerTID},
				{name: "forged-identity", tid: ^uint32(0)},
				{name: "forged-live-java-tid", tid: liveJavaTID},
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := abuseIdentityRequests(peerTID, test.forgedTID)
			require.Len(t, requests, len(test.want))
			for index, expected := range test.want {
				request := requests[index]
				assert.Equal(t, expected.name, request.name)
				require.Len(t, request.payload, requestSize)
				assert.Equal(t, "OBIQ", string(request.payload[:4]))
				assert.Equal(t, requestVersion, binary.LittleEndian.Uint16(request.payload[4:6]))
				assert.EqualValues(t, requestSize, binary.LittleEndian.Uint16(request.payload[6:8]))
				assert.Equal(t, operationTake, request.payload[8])
				assert.Equal(t, sourceDirect, request.payload[9])
				assert.Equal(t, []byte{0, 0}, request.payload[10:12])
				assert.Equal(t, expected.tid, binary.LittleEndian.Uint32(request.payload[12:16]))
				assert.Equal(t, uint64(0x5ec0000000000001), binary.LittleEndian.Uint64(request.payload[16:24]))
			}
		})
	}
}

func TestAbuseRaceProbeForwardsLiveJavaTID(t *testing.T) {
	liveJavaTID := uint32(31337)
	socketPath := filepath.Join(t.TempDir(), "bridge.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	require.NoError(t, err)
	defer listener.Close()
	require.NoError(t, listener.SetDeadline(time.Now().Add(time.Second)))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	type serverResult struct {
		tids [3]uint32
		err  error
	}
	serverDone := make(chan serverResult, 1)
	go func() {
		var result serverResult
		for index := range result.tids {
			connection, acceptErr := listener.AcceptUnix()
			if acceptErr != nil {
				result.err = acceptErr
				serverDone <- result
				return
			}
			request := make([]byte, requestSize)
			_, result.err = io.ReadFull(connection, request)
			if result.err == nil {
				result.tids[index] = binary.LittleEndian.Uint32(request[12:16])
				if index == len(result.tids)-1 {
					cancel()
				}
				_, result.err = connection.Write(statusRecord(statusUnauthorized))
			}
			closeErr := connection.Close()
			if result.err == nil {
				result.err = closeErr
			}
			if result.err != nil {
				serverDone <- result
				return
			}
		}
		serverDone <- result
	}()

	resume := make(chan os.Signal, 1)
	_, err = runAbuseRaceProbe(ctx, socketPath, &liveJavaTID, resume, func() {
		t.Error("abuse race reached its traffic barrier after cancellation")
	})
	require.ErrorIs(t, err, context.Canceled)
	result := <-serverDone
	require.NoError(t, result.err)
	assert.Equal(t, ^uint32(0), result.tids[1])
	assert.Equal(t, liveJavaTID, result.tids[2])
}

func TestReadStatusRejectsContextBearingOrMalformedRecords(t *testing.T) {
	validEnvelope := statusRecord(statusUnauthorized)
	status, err := readStatus(bytes.NewReader(validEnvelope))
	require.NoError(t, err)
	assert.Equal(t, statusUnauthorized, status)

	for _, mutate := range []func([]byte){
		func(record []byte) { record[0] = 'X' },
		func(record []byte) { binary.LittleEndian.PutUint16(record[4:6], recordVersion+1) },
		func(record []byte) { binary.LittleEndian.PutUint16(record[6:8], recordSize-1) },
		func(record []byte) { record[9] = 1 },
		func(record []byte) { record[10] = 1 },
		func(record []byte) { record[16] = 1 },
		func(record []byte) { record[40] = 1 },
		func(record []byte) { record[48] = 1 },
		func(record []byte) { record[56] = 1 },
	} {
		record := append([]byte(nil), validEnvelope...)
		mutate(record)
		_, err := readStatus(bytes.NewReader(record))
		assert.Error(t, err)
	}
}

func TestPrimaryProbeReportsNativeResultsAsUnverified(t *testing.T) {
	ready := make(chan struct{})
	resume := make(chan os.Signal, 1)
	completed := make(chan struct {
		result probeResult
		err    error
	}, 1)
	go func() {
		result, err := runPrimaryProbe(t.Context(), resume, func() {
			close(ready)
		})
		completed <- struct {
			result probeResult
			err    error
		}{result: result, err: err}
	}()

	select {
	case <-ready:
	case result := <-completed:
		require.NoError(t, result.err)
		t.Fatal("primary probe exited before the traffic barrier")
	case <-time.After(time.Second):
		t.Fatal("primary probe did not reach the traffic barrier")
	}
	resume <- os.Interrupt
	result := <-completed
	require.NoError(t, result.err)
	assert.Equal(t, "unverified", result.result.Status)
	assert.Equal(t, "primary", result.result.Mode)
	assert.Positive(t, result.result.Attempts)
	require.Len(t, result.result.Cases, 6)
	assert.Equal(t, probeCase{
		Name: "wrong-process-negotiation", Outcome: "native-unsupported",
	}, result.result.Cases[3])
	assert.Equal(t, probeCase{
		Name: "repeated-retrieval", Outcome: "native-unsupported",
	}, result.result.Cases[5])
}

func TestPrimaryLiveFDProbeUsesOneShotNativeResults(t *testing.T) {
	client, server, err := connectedTCPPair()
	require.NoError(t, err)
	defer client.Close()
	defer server.Close()

	raw, err := client.SyscallConn()
	require.NoError(t, err)
	result, err := exercisePrimaryLiveFDProbe(t.Context(), raw)
	require.NoError(t, err)
	assert.Equal(t, "unverified", result.Status)
	assert.Equal(t, "primary-live-fd", result.Mode)
	assert.EqualValues(t, 1, result.Attempts)
	assert.Equal(t, []probeCase{
		{Name: "standard-option", Outcome: "preserved"},
		{Name: "wrong-process-negotiation", Outcome: "native-unsupported"},
		{Name: "duplicated-fd-take", Outcome: "native-unsupported"},
	}, result.Cases)
}

func TestPrimaryLiveFDProbeReportsUnavailableDescriptorDuplication(t *testing.T) {
	result, err := runPrimaryLiveFDProbeWithDuplicator(
		t.Context(), 7, func(pid, targetFD int) (*os.File, error) {
			assert.Equal(t, javaProcessPID, pid)
			assert.Equal(t, 7, targetFD)
			return nil, unix.EPERM
		},
	)
	require.NoError(t, err)
	assert.Equal(t, probeResult{
		Status: "unsupported",
		Mode:   "primary-live-fd",
		Cases: []probeCase{{
			Name: "pidfd-duplicate", Outcome: "unavailable",
		}},
	}, result)
}

func TestDuplicateProcessFDDuplicatesSocket(t *testing.T) {
	client, server, err := connectedTCPPair()
	require.NoError(t, err)
	defer client.Close()
	defer server.Close()

	raw, err := client.SyscallConn()
	require.NoError(t, err)
	var targetFD int
	require.NoError(t, raw.Control(func(fd uintptr) {
		targetFD = int(fd)
	}))

	duplicate, err := duplicateProcessFD(os.Getpid(), targetFD)
	if pidfdDuplicationUnavailable(err) {
		t.Skipf("pidfd descriptor duplication is unavailable: %v", err)
	}
	require.NoError(t, err)

	duplicateRaw, err := duplicate.SyscallConn()
	require.NoError(t, err)
	socketType := make([]byte, 4)
	length, err := rawGetsockopt(duplicateRaw, unix.SOL_SOCKET, unix.SO_TYPE, socketType)
	require.NoError(t, err)
	assert.EqualValues(t, len(socketType), length)
	assert.Equal(t, uint32(unix.SOCK_STREAM), binary.NativeEndian.Uint32(socketType))
	require.NoError(t, duplicate.Close())

	length, err = rawGetsockopt(raw, unix.SOL_SOCKET, unix.SO_TYPE, socketType)
	require.NoError(t, err)
	assert.EqualValues(t, len(socketType), length)
	assert.Equal(t, uint32(unix.SOCK_STREAM), binary.NativeEndian.Uint32(socketType))
}

func TestDuplicateProcessFDDuplicatesCrossProcessSocket(t *testing.T) {
	command := exec.Command(os.Args[0], "-test.run=^TestPIDFDChildProcess$")
	command.Env = append(os.Environ(), pidfdChildProcessEnv+"=1")
	var stderr bytes.Buffer
	command.Stderr = &stderr
	stdout, err := command.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, command.Start())
	defer func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	}()

	targetFDLine, err := bufio.NewReader(stdout).ReadString('\n')
	require.NoError(t, err)
	targetFD, err := strconv.Atoi(strings.TrimSpace(targetFDLine))
	require.NoError(t, err)
	assert.NotEqual(t, os.Getpid(), command.Process.Pid)

	duplicate, err := duplicateProcessFD(command.Process.Pid, targetFD)
	if pidfdDuplicationUnavailable(err) {
		t.Skipf("cross-process pidfd descriptor duplication is unavailable: %v", err)
	}
	require.NoError(t, err)
	_, err = duplicate.Write([]byte{pidfdChildMarker})
	require.NoError(t, err)
	require.NoError(t, duplicate.Close())
	require.NoError(t, command.Wait(), stderr.String())
}

func TestPIDFDChildProcess(t *testing.T) {
	if os.Getenv(pidfdChildProcessEnv) != "1" {
		return
	}

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	require.NoError(t, err)
	target := os.NewFile(uintptr(fds[0]), "pidfd-child-target")
	peer := os.NewFile(uintptr(fds[1]), "pidfd-child-peer")
	require.NotNil(t, target)
	require.NotNil(t, peer)
	defer target.Close()
	defer peer.Close()

	_, err = fmt.Fprintln(os.Stdout, target.Fd())
	require.NoError(t, err)
	var received [1]byte
	_, err = io.ReadFull(peer, received[:])
	require.NoError(t, err)
	assert.Equal(t, pidfdChildMarker, received[0])
}

func TestDuplicateProcessFDRejectsInvalidIdentifiers(t *testing.T) {
	for _, test := range []struct {
		name string
		pid  int
		fd   int
	}{
		{name: "zero process", pid: 0, fd: 0},
		{name: "negative process", pid: -1, fd: 0},
		{name: "negative descriptor", pid: 1, fd: -1},
	} {
		t.Run(test.name, func(t *testing.T) {
			file, err := duplicateProcessFD(test.pid, test.fd)
			assert.Nil(t, file)
			assert.Error(t, err)
		})
	}
	if strconv.IntSize > 32 {
		overflowFD := int64(maxKernelFD)
		overflowFD++
		file, err := duplicateProcessFD(1, int(overflowFD))
		assert.Nil(t, file)
		assert.Error(t, err)
	}
}

func TestUnauthorizedRaceWaitsForReleaseAfterMakingAttempts(t *testing.T) {
	ready := make(chan struct{})
	resume := make(chan os.Signal, 1)
	completed := make(chan struct {
		attempts uint64
		err      error
	}, 1)
	go func() {
		attempts, err := runUnauthorizedRace(t.Context(), resume, func() {
			close(ready)
		}, func() error {
			return nil
		})
		completed <- struct {
			attempts uint64
			err      error
		}{attempts: attempts, err: err}
	}()

	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("unauthorized race did not reach its traffic barrier")
	}
	resume <- os.Interrupt
	result := <-completed
	require.NoError(t, result.err)
	assert.Positive(t, result.attempts)
}

func TestEndpointProbePreservesReplacementAndBoundsOldFD(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "bridge.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	require.NoError(t, err)
	defer listener.Close()

	serverDone := make(chan error, 1)
	go func() {
		connection, err := listener.AcceptUnix()
		if err != nil {
			serverDone <- err
			return
		}
		defer connection.Close()
		request := make([]byte, requestSize)
		_, err = io.ReadFull(connection, request)
		if err == nil {
			_, err = connection.Write(statusRecord(statusMalformed))
		}
		serverDone <- err
	}()

	ready := make(chan struct{})
	resume := make(chan os.Signal, 1)
	resultDone := make(chan struct {
		result probeResult
		err    error
	}, 1)
	go func() {
		result, err := runEndpointProbe(t.Context(), socketPath, resume, func() {
			close(ready)
		})
		resultDone <- struct {
			result probeResult
			err    error
		}{result: result, err: err}
	}()

	select {
	case <-ready:
	case <-time.After(time.Second):
		t.Fatal("endpoint probe did not reach replacement barrier")
	}
	contents, err := os.ReadFile(socketPath)
	require.NoError(t, err)
	assert.Equal(t, endpointSentinel, string(contents))
	resume <- os.Interrupt

	completed := <-resultDone
	require.NoError(t, completed.err)
	assert.Equal(t, "passed", completed.result.Status)
	assert.Equal(t, "malformed", completed.result.Cases[1].Outcome)
	require.NoError(t, <-serverDone)
	_, err = os.Lstat(socketPath)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestEndpointProbeDoesNotRemoveChangedReplacement(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "bridge.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	require.NoError(t, err)
	defer listener.Close()

	accepted := make(chan *net.UnixConn, 1)
	go func() {
		connection, _ := listener.AcceptUnix()
		accepted <- connection
	}()

	ready := make(chan struct{})
	resume := make(chan os.Signal, 1)
	resultDone := make(chan error, 1)
	go func() {
		_, err := runEndpointProbe(t.Context(), socketPath, resume, func() {
			close(ready)
		})
		resultDone <- err
	}()
	<-ready
	require.NoError(t, os.Remove(socketPath))
	require.NoError(t, os.WriteFile(socketPath, []byte("foreign replacement"), 0o600))
	resume <- os.Interrupt

	err = <-resultDone
	require.ErrorContains(t, err, "sentinel changed")
	contents, readErr := os.ReadFile(socketPath)
	require.NoError(t, readErr)
	assert.Equal(t, "foreign replacement", string(contents))
	connection := <-accepted
	if connection != nil {
		require.NoError(t, connection.Close())
	}
}

func TestSingleResponseRequiresTheServerToCloseTheConnection(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "bridge.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	require.NoError(t, err)
	defer listener.Close()

	release := make(chan struct{})
	serverDone := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer connection.Close()
		request := make([]byte, requestSize)
		if _, readErr := io.ReadFull(connection, request); readErr != nil {
			serverDone <- readErr
			return
		}
		if _, writeErr := connection.Write(statusRecord(statusUnauthorized)); writeErr != nil {
			serverDone <- writeErr
			return
		}
		<-release
		serverDone <- nil
	}()

	payload := append(marshalRequest(1, 1), marshalRequest(1, 1)...)
	_, err = expectSingleResponse(socketPath, payload, statusUnauthorized)
	close(release)
	serverErr := <-serverDone
	require.ErrorContains(t, err, "connection remained open")
	require.NoError(t, serverErr)
}

func TestMainRejectsUnboundedOrInvalidInvocation(t *testing.T) {
	for _, args := range [][]string{
		{"--socket", "relative.sock"},
		{"--mode", "unknown"},
		{"--mode", "primary-live-fd"},
		{"--mode", "primary-live-fd", "--fd=-1"},
		{"--mode", "primary-live-fd", "--fd=2147483648"},
		{"--forged-tid=0"},
		{"--forged-tid=-2"},
		{"--forged-tid=4294967296"},
		{"--mode", "endpoint", "--forged-tid=1"},
		{"--mode", "primary", "--forged-tid=1"},
		{"--mode", "primary-live-fd", "--fd=0", "--forged-tid=1"},
		{"--timeout", "999ms"},
		{"--timeout", "1h1s"},
		{"positional"},
	} {
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		assert.Equal(t, 2, mainExitCode(args, &stdout, &stderr), args)
		assert.Empty(t, stdout.String(), args)
		assert.NotEmpty(t, stderr.String(), args)
	}
}

func TestMainAcceptsMaximumForgedTIDForAbuseMode(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := mainExitCode([]string{
		"--socket", filepath.Join(t.TempDir(), "missing.sock"),
		"--forged-tid=4294967295",
	}, &stdout, &stderr)

	assert.Equal(t, 1, exitCode)
	assert.Empty(t, stdout.String())
	assert.Contains(t, stderr.String(), "security probe failed")
	assert.NotContains(t, stderr.String(), "--forged-tid must")
}

func TestMaxProbeTimeoutMatchesRunnerSafetyBound(t *testing.T) {
	if maxProbeTimeout != time.Hour {
		t.Fatalf("maxProbeTimeout = %s, want 1h", maxProbeTimeout)
	}
}

func TestProbeResultDoesNotExposePayloadCanary(t *testing.T) {
	result := probeResult{
		Status: "passed",
		Mode:   "abuse",
		Cases:  []probeCase{{Name: "oversized", Outcome: "unauthorized"}},
	}
	var output bytes.Buffer
	require.NoError(t, jsonEncode(&output, result))
	assert.NotContains(t, output.String(), payloadCanary)
	assert.NotContains(t, output.String(), endpointSentinel)
}

func statusRecord(status byte) []byte {
	record := make([]byte, recordSize)
	copy(record[:4], "OBIJ")
	binary.LittleEndian.PutUint16(record[4:6], recordVersion)
	binary.LittleEndian.PutUint16(record[6:8], recordSize)
	record[8] = status
	return record
}

func jsonEncode(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	return encoder.Encode(value)
}
