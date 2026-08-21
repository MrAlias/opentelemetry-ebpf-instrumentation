// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestFaultSequenceIsBoundedAndDeterministic(t *testing.T) {
	server := &faultServer{mode: defaultFaultMode}

	assert.Equal(t, "missing", server.response(operationProbe, sourceDirect).status)
	assert.Equal(t, "stale", server.response(operationTake, sourceDirect).status)
	assert.Equal(t, "malformed", server.response(operationTake, sourceDirect).status)
	assert.Equal(t, "stale", server.response(operationTake, sourceDirect).status)
	assert.EqualValues(t, 3, server.takes.Load())
}

func TestMatchingSequenceBracketsCanonicalDirectCandidates(t *testing.T) {
	server := &faultServer{mode: "matching", matchingValidTakes: 2}

	assert.Equal(t, "missing", server.response(operationProbe, sourceDirect).status)
	assert.Zero(t, server.takes.Load())
	assert.Equal(t, "missing", server.response(operationDrop, sourceDirect).status)
	assert.Zero(t, server.takes.Load())
	assert.Equal(t, "missing", server.response(operationTake, sourceDirect).status)
	first := server.response(operationTake, sourceDirect)
	second := server.response(operationTake, sourceDirect)
	assert.Equal(t, "missing", server.response(operationTake, sourceDirect).status)

	assert.Equal(t, "valid", first.status)
	assert.Equal(t, "valid", second.status)
	assert.Equal(t, statusValid, first.payload[8])
	assert.Equal(t, statusValid, second.payload[8])
	assert.EqualValues(t, 4, server.takes.Load())
}

func TestMatchingW3CDirectSequenceIsNegotiateMissingThenMissingValidMissing(t *testing.T) {
	server := &faultServer{mode: "matching", matchingValidTakes: 1}

	assert.Equal(t, "missing", server.response(operationProbe, sourceDirect).status)
	assert.Zero(t, server.takes.Load())
	assert.Equal(t, "missing", server.response(operationTake, sourceDirect).status)
	assert.Equal(t, "valid", server.response(operationTake, sourceDirect).status)
	assert.Equal(t, "missing", server.response(operationTake, sourceDirect).status)
	assert.EqualValues(t, 3, server.takes.Load())
}

func TestMatchingResponseCannotReturnTaskCandidate(t *testing.T) {
	server := &faultServer{mode: "matching", matchingValidTakes: 1}

	assert.Equal(t, "missing", server.response(operationTake, sourceDirect).status)
	assert.Equal(t, "missing", server.response(operationTake, sourceTask).status)
	assert.Equal(t, "missing", server.response(operationTake, sourceDirect).status)
	assert.EqualValues(t, 3, server.takes.Load())
}

func TestMatchingServeStopsOnInvalidScenarioRequest(t *testing.T) {
	const serverTimeout = 5 * time.Second

	for _, test := range []struct {
		name    string
		request []byte
		wantErr string
	}{
		{
			name:    "malformed envelope",
			request: make([]byte, requestSize),
			wantErr: "handle matching request: invalid request envelope",
		},
		{
			name:    "task source",
			request: validRequest(operationTake, sourceTask),
			wantErr: "handle matching request: matching request source must be direct, got task",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			require.NoError(t, os.Chmod(directory, 0o700))
			socketPath := filepath.Join(directory, "bridge.sock")
			done := make(chan faultServeResult, 1)
			server := &faultServer{
				mode:               "matching",
				matchingValidTakes: 1,
			}
			go func() {
				classification, err := serve(t.Context(), socketPath, server)
				done <- faultServeResult{classification: classification, err: err}
			}()

			var connection *net.UnixConn
			require.Eventually(t, func() bool {
				var err error
				connection, err = net.DialUnix(
					"unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"},
				)
				return err == nil
			}, serverTimeout, time.Millisecond)
			_, err := connection.Write(test.request)
			require.NoError(t, err)
			require.NoError(t, connection.Close())

			select {
			case result := <-done:
				require.ErrorContains(t, result.err, test.wantErr)
				require.Equal(t, exitMalformedRequest, result.classification)
				summary := snapshotFaultServer(t, server, result.classification)
				require.EqualValues(t, 1, summary.AcceptedRequests)
				require.EqualValues(t, 1, summary.MalformedRequests)
				require.Zero(t, summary.ParsedOperations.total())
				require.NoError(t, validateFaultSummary(summary))
			case <-time.After(serverTimeout):
				t.Fatal("matching fault bridge did not stop after an invalid scenario request")
			}
		})
	}
}

func TestFaultModesReturnDeterministicResponses(t *testing.T) {
	testCases := []struct {
		mode          string
		status        string
		payloadLength int
		decodedStatus byte
	}{
		{mode: "timeout", status: "timeout", payloadLength: 0},
		{mode: "missing", status: "missing", payloadLength: recordSize, decodedStatus: statusMissing},
		{mode: "disconnect", status: "disconnect", payloadLength: 0},
		{mode: "overload", status: "overload", payloadLength: recordSize, decodedStatus: statusOverload},
		{mode: "truncated", status: "truncated", payloadLength: recordSize / 2},
		{mode: "bad-magic", status: "bad-magic", payloadLength: recordSize, decodedStatus: statusMissing},
		{mode: "bad-size", status: "bad-size", payloadLength: recordSize, decodedStatus: statusMissing},
		{mode: "version-mismatch", status: "version-mismatch", payloadLength: recordSize, decodedStatus: statusMissing},
		{mode: "zero-trace-id", status: "zero-trace-id", payloadLength: recordSize, decodedStatus: statusValid},
		{mode: "zero-span-id", status: "zero-span-id", payloadLength: recordSize, decodedStatus: statusValid},
	}

	for _, testCase := range testCases {
		t.Run(testCase.mode, func(t *testing.T) {
			server := &faultServer{mode: testCase.mode}
			response := server.response(operationTake, sourceDirect)

			assert.Equal(t, testCase.status, response.status)
			assert.Len(t, response.payload, testCase.payloadLength)
			assert.EqualValues(t, 1, server.takes.Load())
			if len(response.payload) == recordSize {
				assert.Equal(t, testCase.decodedStatus, response.payload[8])
			}
			if testCase.mode == "timeout" {
				assert.Equal(t, timeoutDelay, response.delay)
			}
		})
	}
}

func TestMalformedRecordModesCorruptOneField(t *testing.T) {
	badMagic := (&faultServer{mode: "bad-magic"}).response(operationTake, sourceDirect).payload
	assert.Equal(t, "XBIJ", string(badMagic[:4]))

	badSize := (&faultServer{mode: "bad-size"}).response(operationTake, sourceDirect).payload
	assert.EqualValues(t, recordSize-1, binary.LittleEndian.Uint16(badSize[6:8]))

	versionMismatch := (&faultServer{mode: "version-mismatch"}).response(operationTake, sourceDirect).payload
	assert.Equal(t, recordVersion+1, binary.LittleEndian.Uint16(versionMismatch[4:6]))

	zeroTraceID := (&faultServer{mode: "zero-trace-id"}).response(operationTake, sourceDirect).payload
	assert.Equal(t, make([]byte, 16), zeroTraceID[16:32])
	assert.NotEqual(t, make([]byte, 8), zeroTraceID[32:40])

	zeroSpanID := (&faultServer{mode: "zero-span-id"}).response(operationTake, sourceDirect).payload
	assert.NotEqual(t, make([]byte, 16), zeroSpanID[16:32])
	assert.Equal(t, make([]byte, 8), zeroSpanID[32:40])
}

func TestFaultModeValidation(t *testing.T) {
	for _, mode := range []string{
		defaultFaultMode,
		"missing",
		"matching",
		"timeout",
		"disconnect",
		"overload",
		"truncated",
		"bad-magic",
		"bad-size",
		"version-mismatch",
		"zero-trace-id",
		"zero-span-id",
	} {
		assert.True(t, validFaultMode(mode), mode)
	}
	assert.False(t, validFaultMode("unknown"))
}

func TestPersistentMissingModeIsBoundedAndSummaryOnly(t *testing.T) {
	var stdout bytes.Buffer
	server := testFaultServer("missing", 3, 3)
	server.stdout = &stdout
	socketPath, done := startFaultServer(t.Context(), t, server)

	for _, operation := range []byte{operationTake, operationDrop, operationProbe} {
		response, err := exchangeFaultRequest(socketPath, validRequest(operation, sourceDirect), recordSize)
		require.NoError(t, err)
		require.Equal(t, statusMissing, response[8])
	}
	result := waitFaultServer(t, done)
	require.NoError(t, result.err)
	require.Equal(t, exitRequestLimitReached, result.classification)

	summary := snapshotFaultServer(t, server, result.classification)
	require.EqualValues(t, 3, summary.AcceptedRequests)
	require.Equal(t, faultOperationCounts{Discard: 1, Negotiate: 1, Take: 1}, summary.ParsedOperations)
	require.EqualValues(t, 3, summary.Responses.Missing)
	require.Zero(t, summary.Responses.total()-summary.Responses.Missing)
	require.EqualValues(t, 1, summary.MaxInflight)
	require.NotContains(t, stdout.String(), "operation=")
	require.NoError(t, validateFaultSummary(summary))
	requireSocketRemoved(t, socketPath)
}

func TestTimeoutHandlersRunConcurrently(t *testing.T) {
	const concurrentDelay = 250 * time.Millisecond
	server := testFaultServer("timeout", 2, 2)
	server.timeoutDelay = concurrentDelay
	socketPath, done := startFaultServer(t.Context(), t, server)

	clientErrors := make(chan error, 2)
	started := time.Now()
	for range 2 {
		go func() {
			response, err := exchangeFaultRequest(
				socketPath, validRequest(operationTake, sourceDirect), 0,
			)
			if err == nil && len(response) != 0 {
				err = fmt.Errorf("timeout response retained %d bytes", len(response))
			}
			clientErrors <- err
		}()
	}
	require.Eventually(t, func() bool {
		server.mu.Lock()
		defer server.mu.Unlock()
		return server.observedMaxInflight == 2
	}, time.Second, time.Millisecond)
	for range 2 {
		require.NoError(t, <-clientErrors)
	}
	require.Less(t, time.Since(started), 2*concurrentDelay)

	result := waitFaultServer(t, done)
	require.NoError(t, result.err)
	require.Equal(t, exitRequestLimitReached, result.classification)
	summary := snapshotFaultServer(t, server, result.classification)
	require.Equal(t, faultOperationCounts{Take: 2}, summary.ParsedOperations)
	require.EqualValues(t, 2, summary.Responses.Timeout)
	require.EqualValues(t, 2, summary.WithheldTimeouts)
	require.EqualValues(t, 2, summary.MaxInflight)
	require.NoError(t, validateFaultSummary(summary))
}

func TestInflightLimitRejectsBeforeSerializedTimeoutCompletes(t *testing.T) {
	const heldDelay = 500 * time.Millisecond
	server := testFaultServer("timeout", 2, 1)
	server.timeoutDelay = heldDelay
	server.requestTimeout = time.Second
	server.drainTimeout = time.Second
	socketPath, done := startFaultServer(t.Context(), t, server)

	firstDone := make(chan error, 1)
	go func() {
		response, err := exchangeFaultRequest(
			socketPath, validRequest(operationTake, sourceDirect), 0,
		)
		if err == nil && len(response) != 0 {
			err = fmt.Errorf("timeout response retained %d bytes", len(response))
		}
		firstDone <- err
	}()
	require.Eventually(t, func() bool {
		server.mu.Lock()
		defer server.mu.Unlock()
		return server.parsedOperations.Take == 1
	}, time.Second, time.Millisecond)

	second, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	require.NoError(t, err)
	defer second.Close()
	require.NoError(t, second.SetDeadline(time.Now().Add(time.Second)))
	rejectedAt := time.Now()
	_, writeErr := second.Write(validRequest(operationTake, sourceDirect))
	if writeErr == nil {
		_, err = second.Read(make([]byte, 1))
		require.Error(t, err)
	} else {
		require.True(
			t,
			errors.Is(writeErr, syscall.EPIPE) || errors.Is(writeErr, syscall.ECONNRESET),
			"unexpected prompt-rejection write error: %v",
			writeErr,
		)
	}
	require.Less(t, time.Since(rejectedAt), heldDelay/2)
	require.NoError(t, <-firstDone)

	result := waitFaultServer(t, done)
	require.ErrorContains(t, result.err, "concurrent request limit")
	require.Equal(t, exitInflightLimitExceeded, result.classification)
	summary := snapshotFaultServer(t, server, result.classification)
	require.EqualValues(t, 2, summary.AcceptedRequests)
	require.Equal(t, faultOperationCounts{Take: 1}, summary.ParsedOperations)
	require.EqualValues(t, 1, summary.AdmissionRejections)
	require.EqualValues(t, 1, summary.Responses.Timeout)
	require.EqualValues(t, 1, summary.WithheldTimeouts)
	require.EqualValues(t, 1, summary.MaxInflight)
	require.NoError(t, validateFaultSummary(summary))
}

func TestSignalStopsAdmissionAndDrainsTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	server := testFaultServer("timeout", 4, 2)
	server.timeoutDelay = 50 * time.Millisecond
	server.drainTimeout = 500 * time.Millisecond
	socketPath, done := startFaultServer(ctx, t, server)

	clientDone := make(chan error, 1)
	go func() {
		response, err := exchangeFaultRequest(
			socketPath, validRequest(operationTake, sourceDirect), 0,
		)
		if err == nil && len(response) != 0 {
			err = fmt.Errorf("timeout response retained %d bytes", len(response))
		}
		clientDone <- err
	}()
	require.Eventually(t, func() bool {
		server.mu.Lock()
		defer server.mu.Unlock()
		return server.parsedOperations.Take == 1
	}, time.Second, time.Millisecond)
	cancel()
	require.NoError(t, <-clientDone)

	result := waitFaultServer(t, done)
	require.NoError(t, result.err)
	require.Equal(t, exitSignalDrained, result.classification)
	summary := snapshotFaultServer(t, server, result.classification)
	require.EqualValues(t, 1, summary.AcceptedRequests)
	require.EqualValues(t, 1, summary.Responses.Timeout)
	require.EqualValues(t, 1, summary.WithheldTimeouts)
	require.Zero(t, summary.AdmissionRejections)
	require.NoError(t, validateFaultSummary(summary))
	requireSocketRemoved(t, socketPath)
}

func TestDrainTimeoutClosesActiveHandlers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	server := testFaultServer("timeout", 4, 1)
	server.timeoutDelay = time.Second
	server.requestTimeout = time.Second
	server.drainTimeout = 20 * time.Millisecond
	socketPath, done := startFaultServer(ctx, t, server)

	clientDone := make(chan error, 1)
	go func() {
		_, err := exchangeFaultRequest(socketPath, validRequest(operationTake, sourceDirect), 0)
		clientDone <- err
	}()
	require.Eventually(t, func() bool {
		server.mu.Lock()
		defer server.mu.Unlock()
		return server.parsedOperations.Take == 1
	}, time.Second, time.Millisecond)
	started := time.Now()
	cancel()
	result := waitFaultServer(t, done)
	require.Less(t, time.Since(started), 500*time.Millisecond)
	require.ErrorContains(t, result.err, "request drain exceeded")
	require.Equal(t, exitDrainTimeout, result.classification)
	<-clientDone

	summary := snapshotFaultServer(t, server, result.classification)
	require.EqualValues(t, 1, summary.AcceptedRequests)
	require.Equal(t, faultOperationCounts{Take: 1}, summary.ParsedOperations)
	require.Zero(t, summary.Responses.total())
	require.Zero(t, summary.WithheldTimeouts)
	require.EqualValues(t, 1, summary.DrainCancellations)
	require.Zero(t, summary.FinalInflight)
	require.NoError(t, validateFaultSummary(summary))
	requireSocketRemoved(t, socketPath)
}

func TestAcceptTransportErrorThenDrainTimeoutPublishesExactSummary(t *testing.T) {
	requireLinuxSummaryPublication(t)
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	socketPath := filepath.Join(directory, "bridge.sock")
	summaryPath := filepath.Join(directory, "summary.json")
	responsePlanned := make(chan struct{})
	done := make(chan int, 1)
	go func() {
		done <- runFaultBridgeWithHooks(
			t.Context(),
			[]string{
				"--socket", socketPath,
				"--summary", summaryPath,
				"--mode", "timeout",
				"--max-requests", "2",
				"--max-inflight", "1",
				"--drain-timeout", "10ms",
			},
			io.Discard,
			io.Discard,
			faultBridgeRunHooks{configureServer: func(server *faultServer) {
				server.timeoutDelay = time.Second
				server.afterResponsePlanned = func() { close(responsePlanned) }
				acceptCalls := 0
				server.acceptUnix = func(
					listener *net.UnixListener,
				) (*net.UnixConn, error) {
					acceptCalls++
					if acceptCalls == 1 {
						return listener.AcceptUnix()
					}
					<-responsePlanned
					return nil, syscall.EMFILE
				}
			}},
		)
	}()
	waitForFaultSocket(t, socketPath)
	response, err := exchangeFaultRequest(
		socketPath, validRequest(operationTake, sourceDirect), 0,
	)
	require.NoError(t, err)
	require.Empty(t, response)
	select {
	case exitCode := <-done:
		require.Equal(t, 1, exitCode)
	case <-time.After(time.Second):
		t.Fatal("accept transport failure did not complete its bounded drain")
	}

	payload, err := os.ReadFile(summaryPath)
	require.NoError(t, err)
	var summary faultSummary
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(payload), &summary))
	require.NoError(t, validateFaultSummary(summary))
	require.Equal(t, exitDrainTimeout, summary.ExitClassification)
	require.EqualValues(t, 1, summary.AcceptedRequests)
	require.Equal(t, faultOperationCounts{Take: 1}, summary.ParsedOperations)
	require.Zero(t, summary.Responses.total())
	require.EqualValues(t, 1, summary.TransportErrors)
	require.EqualValues(t, 1, summary.AcceptTransportErrors)
	require.EqualValues(t, 1, summary.DrainCancellations)
	require.Zero(t, summary.FinalInflight)
	require.Equal(t, faultUnresolvedRequests{}, summary.UnresolvedRequests)

	for _, mutate := range []func(*faultSummary){
		func(value *faultSummary) { value.AcceptTransportErrors = 0 },
		func(value *faultSummary) {
			value.AcceptTransportErrors = 2
			value.TransportErrors = 2
		},
		func(value *faultSummary) { value.TransportErrors = 0 },
		func(value *faultSummary) { value.TransportErrors = 2 },
		func(value *faultSummary) { value.ExitClassification = exitTransportError },
	} {
		mutated := summary
		mutate(&mutated)
		require.Error(t, validateFaultSummary(mutated))
	}
	requireSocketRemoved(t, socketPath)
}

func TestForcedDrainPublishesExactUnresolvedStages(t *testing.T) {
	for _, test := range []struct {
		name                  string
		configureStall        func(*faultServer, func())
		wantParsed            faultOperationCounts
		wantResponses         faultResponseCounts
		wantPreParse          uint64
		wantPendingResponses  faultResponseCounts
		mutateUnresolvedProof func(*faultSummary)
	}{
		{
			name: "pre-parse",
			configureStall: func(server *faultServer, stall func()) {
				server.beforeRequestParse = stall
			},
			wantPreParse: 1,
			mutateUnresolvedProof: func(summary *faultSummary) {
				summary.UnresolvedRequests.PreParse = 0
			},
		},
		{
			name: "post-parse response pending",
			configureStall: func(server *faultServer, stall func()) {
				server.afterResponsePlanned = stall
			},
			wantParsed:           faultOperationCounts{Take: 1},
			wantPendingResponses: faultResponseCounts{Missing: 1},
			mutateUnresolvedProof: func(summary *faultSummary) {
				summary.UnresolvedRequests.PendingResponses.Missing = 0
			},
		},
		{
			name: "terminal cleanup",
			configureStall: func(server *faultServer, stall func()) {
				server.beforeRequestRelease = stall
			},
			wantParsed:    faultOperationCounts{Take: 1},
			wantResponses: faultResponseCounts{Missing: 1},
			mutateUnresolvedProof: func(summary *faultSummary) {
				summary.UnresolvedRequests.Terminal = 0
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			require.NoError(t, os.Chmod(directory, 0o700))
			socketPath := filepath.Join(directory, "bridge.sock")
			summaryPath := filepath.Join(directory, "summary.json")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered := make(chan struct{})
			release := make(chan struct{})
			var releaseOnce sync.Once
			releaseStall := func() { releaseOnce.Do(func() { close(release) }) }
			t.Cleanup(releaseStall)
			var server *faultServer
			done := make(chan int, 1)
			go func() {
				done <- runFaultBridgeWithHooks(
					ctx,
					[]string{
						"--socket", socketPath,
						"--summary", summaryPath,
						"--mode", "missing",
						"--max-requests", "2",
						"--max-inflight", "1",
						"--drain-timeout", "5ms",
					},
					io.Discard,
					io.Discard,
					faultBridgeRunHooks{configureServer: func(configured *faultServer) {
						server = configured
						test.configureStall(configured, func() {
							close(entered)
							<-release
						})
					}},
				)
			}()
			waitForFaultSocket(t, socketPath)
			connection, err := net.DialUnix(
				"unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"},
			)
			require.NoError(t, err)
			t.Cleanup(func() { _ = connection.Close() })
			require.NoError(t, connection.SetDeadline(time.Now().Add(time.Second)))
			_, err = connection.Write(validRequest(operationTake, sourceDirect))
			require.NoError(t, err)
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("request did not reach forced stall")
			}
			cancel()
			select {
			case exitCode := <-done:
				require.Equal(t, 1, exitCode)
			case <-time.After(time.Second):
				t.Fatal("forced drain did not return within its bound")
			}

			payload, err := os.ReadFile(summaryPath)
			require.NoError(t, err)
			var summary faultSummary
			require.NoError(t, json.Unmarshal(bytes.TrimSpace(payload), &summary))
			require.NoError(t, validateFaultSummary(summary))
			require.Equal(t, exitDrainTimeout, summary.ExitClassification)
			require.EqualValues(t, 1, summary.AcceptedRequests)
			require.EqualValues(t, 1, summary.FinalInflight)
			require.Equal(t, test.wantParsed, summary.ParsedOperations)
			require.Equal(t, test.wantResponses, summary.Responses)
			require.Equal(t, test.wantPreParse, summary.UnresolvedRequests.PreParse)
			require.Equal(
				t,
				test.wantPendingResponses,
				summary.UnresolvedRequests.PendingResponses,
			)
			require.Zero(t, summary.DrainCancellations)

			mutated := summary
			test.mutateUnresolvedProof(&mutated)
			require.Error(t, validateFaultSummary(mutated))
			mutated = summary
			mutated.FinalInflight = 0
			require.Error(t, validateFaultSummary(mutated))
			mutated = summary
			mutated.ExitClassification = exitSignalDrained
			require.Error(t, validateFaultSummary(mutated))

			releaseStall()
			require.Eventually(t, func() bool {
				return server != nil && server.inflightCount() == 0
			}, time.Second, time.Millisecond)
			requireSocketRemoved(t, socketPath)
		})
	}
}

func TestHandlerLoggingCannotExtendRequestDrain(t *testing.T) {
	for _, test := range []struct {
		name           string
		mode           string
		request        []byte
		responseSize   int
		blockWrite     int
		useStderr      bool
		classification string
		wantError      string
		wantLog        string
	}{
		{
			name:           "ordinary stdout request log",
			mode:           defaultFaultMode,
			request:        validRequest(operationTake, sourceDirect),
			responseSize:   recordSize,
			blockWrite:     2,
			classification: exitRequestLimitReached,
			wantLog:        "operation=take status=stale",
		},
		{
			name:           "fatal stderr request log",
			mode:           "missing",
			request:        make([]byte, requestSize),
			blockWrite:     1,
			useStderr:      true,
			classification: exitMalformedRequest,
			wantError:      "invalid request envelope",
			wantLog:        "request rejected: invalid request envelope",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			writer := newBlockingWriter(test.blockWrite)
			t.Cleanup(writer.unblock)
			server := testFaultServer(test.mode, 1, 1)
			if test.useStderr {
				server.stderr = writer
			} else {
				server.stdout = writer
			}
			socketPath, done := startFaultServer(t.Context(), t, server)
			response, err := exchangeFaultRequest(socketPath, test.request, test.responseSize)
			require.NoError(t, err)
			if test.responseSize != 0 {
				require.Len(t, response, test.responseSize)
			}
			select {
			case <-writer.blocked:
			case <-time.After(time.Second):
				t.Fatal("handler log writer did not block")
			}

			started := time.Now()
			result := waitFaultServer(t, done)
			require.Less(t, time.Since(started), 500*time.Millisecond)
			require.Equal(t, test.classification, result.classification)
			if test.wantError == "" {
				require.NoError(t, result.err)
			} else {
				require.ErrorContains(t, result.err, test.wantError)
			}
			summary := snapshotFaultServer(t, server, result.classification)
			require.NoError(t, validateFaultSummary(summary))
			requireSocketRemoved(t, socketPath)

			writer.unblock()
			select {
			case <-writer.returned:
			case <-time.After(time.Second):
				t.Fatal("handler log writer did not unblock")
			}
			require.Contains(t, writer.String(), test.wantLog)
		})
	}
}

func TestLoggerStopAndHandlerEnqueueAreRaceSafe(_ *testing.T) {
	for range 100 {
		diagnostics := newFaultDiagnostics(io.Discard, io.Discard)
		start := make(chan struct{})
		var operations sync.WaitGroup
		operations.Add(2)
		go func() {
			defer operations.Done()
			<-start
			diagnostics.printf(diagnostics.stdout, "fault bridge request\n")
		}()
		go func() {
			defer operations.Done()
			<-start
			diagnostics.stop()
		}()
		close(start)
		operations.Wait()
	}
}

func TestDiagnosticsBoundMessageAndQueueMemory(t *testing.T) {
	var retained bytes.Buffer
	diagnostics := newFaultDiagnostics(&retained, io.Discard)
	payload := bytes.Repeat([]byte{'x'}, 2*maxLogMessageBytes)
	written, err := diagnostics.writer(diagnostics.stdout).Write(payload)
	require.NoError(t, err)
	require.Len(t, payload, written)
	diagnostics.stop()
	require.Len(t, retained.Bytes(), maxLogMessageBytes)

	blocked := newBlockingWriter(1)
	t.Cleanup(blocked.unblock)
	diagnostics = newFaultDiagnostics(blocked, io.Discard)
	diagnostics.printf(diagnostics.stdout, "first")
	select {
	case <-blocked.blocked:
	case <-time.After(time.Second):
		t.Fatal("diagnostic writer did not block")
	}
	for range maxLogEntries + 100 {
		diagnostics.enqueue(diagnostics.stdout, string(payload))
	}
	diagnostics.mu.Lock()
	require.Len(t, diagnostics.queue, maxLogEntries)
	diagnostics.mu.Unlock()
	diagnostics.stop()
	blocked.unblock()
	select {
	case <-diagnostics.done:
	case <-time.After(time.Second):
		t.Fatal("bounded diagnostic queue did not drain")
	}
}

func TestRunFaultBridgeDiagnosticsCannotBlockExit(t *testing.T) {
	const boundedExit = 500 * time.Millisecond
	waitBlocked := func(t *testing.T, writer *blockingWriter) {
		t.Helper()
		select {
		case <-writer.blocked:
		case <-time.After(time.Second):
			t.Fatal("diagnostic writer did not block")
		}
	}
	waitExit := func(t *testing.T, done <-chan int, expected int) {
		t.Helper()
		started := time.Now()
		select {
		case exitCode := <-done:
			require.Equal(t, expected, exitCode)
			require.Less(t, time.Since(started), boundedExit)
		case <-time.After(boundedExit):
			t.Fatal("blocked diagnostic prevented fault bridge exit")
		}
	}
	privateDirectory := func(t *testing.T) string {
		t.Helper()
		directory := t.TempDir()
		require.NoError(t, os.Chmod(directory, 0o700))
		return directory
	}

	t.Run("stdout ready diagnostic", func(t *testing.T) {
		requireLinuxSummaryPublication(t)
		directory := privateDirectory(t)
		socketPath := filepath.Join(directory, "bridge.sock")
		summaryPath := filepath.Join(directory, "summary.json")
		writer := newBlockingWriter(1)
		t.Cleanup(writer.unblock)
		done := make(chan int, 1)
		go func() {
			done <- runFaultBridge(t.Context(), []string{
				"--socket", socketPath,
				"--summary", summaryPath,
				"--mode", "missing",
				"--max-requests", "1",
				"--max-inflight", "1",
			}, writer, io.Discard)
		}()
		waitForFaultSocket(t, socketPath)
		waitBlocked(t, writer)
		response, err := exchangeFaultRequest(
			socketPath, validRequest(operationTake, sourceDirect), recordSize,
		)
		require.NoError(t, err)
		require.Equal(t, statusMissing, response[8])
		waitExit(t, done, 0)
		payload, err := os.ReadFile(summaryPath)
		require.NoError(t, err)
		var summary faultSummary
		require.NoError(t, json.Unmarshal(bytes.TrimSpace(payload), &summary))
		require.NoError(t, validateFaultSummary(summary))
	})

	t.Run("flag diagnostic", func(t *testing.T) {
		writer := newBlockingWriter(1)
		t.Cleanup(writer.unblock)
		done := make(chan int, 1)
		go func() {
			done <- runFaultBridge(
				t.Context(), []string{"--not-a-flag"}, io.Discard, writer,
			)
		}()
		waitBlocked(t, writer)
		waitExit(t, done, 2)
	})

	t.Run("startup diagnostic", func(t *testing.T) {
		directory := privateDirectory(t)
		socketPath := filepath.Join(directory, "bridge.sock")
		require.NoError(t, os.WriteFile(socketPath, []byte("foreign"), 0o600))
		writer := newBlockingWriter(1)
		t.Cleanup(writer.unblock)
		done := make(chan int, 1)
		go func() {
			done <- runFaultBridge(t.Context(), []string{
				"--socket", socketPath,
				"--mode", "missing",
				"--max-requests", "1",
				"--max-inflight", "1",
			}, io.Discard, writer)
		}()
		waitBlocked(t, writer)
		waitExit(t, done, 1)
	})

	t.Run("serve diagnostic", func(t *testing.T) {
		directory := privateDirectory(t)
		socketPath := filepath.Join(directory, "bridge.sock")
		writer := newBlockingWriter(1)
		t.Cleanup(writer.unblock)
		done := make(chan int, 1)
		go func() {
			done <- runFaultBridge(t.Context(), []string{
				"--socket", socketPath,
				"--mode", "missing",
				"--max-requests", "1",
				"--max-inflight", "1",
			}, io.Discard, writer)
		}()
		waitForFaultSocket(t, socketPath)
		_, err := exchangeFaultRequest(socketPath, make([]byte, requestSize), 0)
		require.NoError(t, err)
		waitBlocked(t, writer)
		waitExit(t, done, 1)
	})

	t.Run("summary diagnostic", func(t *testing.T) {
		directory := privateDirectory(t)
		socketPath := filepath.Join(directory, "bridge.sock")
		summaryPath := filepath.Join(directory, "summary.json")
		ctx, cancel := context.WithCancel(context.Background())
		writer := newBlockingWriter(1)
		t.Cleanup(writer.unblock)
		done := make(chan int, 1)
		go func() {
			done <- runFaultBridge(ctx, []string{
				"--socket", socketPath,
				"--summary", summaryPath,
				"--mode", "missing",
				"--max-requests", "1",
				"--max-inflight", "1",
			}, io.Discard, writer)
		}()
		waitForFaultSocket(t, socketPath)
		require.NoError(t, os.WriteFile(summaryPath, []byte("foreign"), 0o600))
		cancel()
		waitBlocked(t, writer)
		waitExit(t, done, 1)
		retained, err := os.ReadFile(summaryPath)
		require.NoError(t, err)
		require.Equal(t, []byte("foreign"), retained)
	})
}

func TestZeroHandlerNearZeroDrainReturnsCleanly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	server := testFaultServer("missing", 1, 1)
	server.drainTimeout = time.Nanosecond
	socketPath, done := startFaultServer(ctx, t, server)

	started := time.Now()
	cancel()
	result := waitFaultServer(t, done)
	require.Less(t, time.Since(started), 500*time.Millisecond)
	require.NoError(t, result.err)
	require.Equal(t, exitSignalDrained, result.classification)
	summary := snapshotFaultServer(t, server, result.classification)
	require.Zero(t, summary.AcceptedRequests)
	require.NoError(t, validateFaultSummary(summary))
	requireSocketRemoved(t, socketPath)
}

func TestMalformedAndPartialRequestsFailClosed(t *testing.T) {
	for _, test := range []struct {
		name              string
		request           []byte
		classification    string
		malformedRequests uint64
		partialRequests   uint64
		transportErrors   uint64
	}{
		{
			name:              "malformed",
			request:           make([]byte, requestSize),
			classification:    exitMalformedRequest,
			malformedRequests: 1,
		},
		{
			name:            "partial",
			request:         validRequest(operationTake, sourceDirect)[:requestSize/2],
			classification:  exitPartialRequest,
			partialRequests: 1,
			transportErrors: 1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := testFaultServer("missing", 1, 1)
			socketPath, done := startFaultServer(t.Context(), t, server)
			connection, err := net.DialUnix(
				"unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"},
			)
			require.NoError(t, err)
			_, err = connection.Write(test.request)
			require.NoError(t, err)
			require.NoError(t, connection.Close())

			result := waitFaultServer(t, done)
			require.Error(t, result.err)
			require.Equal(t, test.classification, result.classification)
			summary := snapshotFaultServer(t, server, result.classification)
			require.EqualValues(t, 1, summary.AcceptedRequests)
			require.Zero(t, summary.ParsedOperations.total())
			require.Equal(t, test.malformedRequests, summary.MalformedRequests)
			require.Equal(t, test.partialRequests, summary.PartialRequests)
			require.Equal(t, test.transportErrors, summary.TransportErrors)
			require.NoError(t, validateFaultSummary(summary))
			requireSocketRemoved(t, socketPath)
		})
	}
}

func TestRunFaultBridgePublishesCanonicalSignalSummary(t *testing.T) {
	requireLinuxSummaryPublication(t)
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	socketPath := filepath.Join(directory, "bridge.sock")
	summaryPath := filepath.Join(directory, "summary.json")
	ctx, cancel := context.WithCancel(context.Background())
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- runFaultBridge(ctx, []string{
			"--socket", socketPath,
			"--summary", summaryPath,
			"--mode", "missing",
			"--max-requests", "4",
			"--max-inflight", "2",
			"--drain-timeout", "500ms",
		}, &stdout, &stderr)
	}()
	waitForFaultSocket(t, socketPath)
	response, err := exchangeFaultRequest(
		socketPath, validRequest(operationTake, sourceDirect), recordSize,
	)
	require.NoError(t, err)
	require.Equal(t, statusMissing, response[8])
	cancel()
	select {
	case exitCode := <-done:
		require.Zero(t, exitCode, stderr.String())
	case <-time.After(5 * time.Second):
		t.Fatal("fault bridge did not exit after cancellation")
	}

	payload, err := os.ReadFile(summaryPath)
	require.NoError(t, err)
	require.LessOrEqual(t, len(payload), maxSummaryBytes)
	require.True(t, bytes.HasSuffix(payload, []byte{'\n'}))
	var summary faultSummary
	require.NoError(t, json.Unmarshal(bytes.TrimSuffix(payload, []byte{'\n'}), &summary))
	require.NoError(t, validateFaultSummary(summary))
	require.Equal(t, exitSignalDrained, summary.ExitClassification)
	require.Equal(t, "missing", summary.Mode)
	require.EqualValues(t, 4, summary.Limits.MaxRequests)
	require.EqualValues(t, 2, summary.Limits.MaxInflight)
	require.EqualValues(t, 1, summary.AcceptedRequests)
	require.EqualValues(t, 1, summary.ParsedOperations.Take)
	require.EqualValues(t, 1, summary.Responses.Missing)
	canonical, err := json.Marshal(summary)
	require.NoError(t, err)
	require.Equal(t, append(canonical, '\n'), payload)
	require.NotContains(t, stdout.String(), "operation=")
	require.Empty(t, stderr.String())
	info, err := os.Lstat(summaryPath)
	require.NoError(t, err)
	require.True(t, info.Mode().IsRegular())
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	requireSocketRemoved(t, socketPath)

	entries, err := os.ReadDir(directory)
	require.NoError(t, err)
	require.Equal(t, []string{"summary.json"}, directoryEntryNames(entries))
}

func TestSocketCleanupPreservesForeignReplacementAndPublishesFailure(t *testing.T) {
	requireLinuxSummaryPublication(t)
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	socketPath := filepath.Join(directory, "bridge.sock")
	summaryPath := filepath.Join(directory, "summary.json")
	foreign := []byte("foreign socket replacement")
	var hookErr error
	done := make(chan int, 1)
	go func() {
		done <- runFaultBridgeWithHooks(
			t.Context(),
			[]string{
				"--socket", socketPath,
				"--summary", summaryPath,
				"--mode", "missing",
				"--max-requests", "1",
				"--max-inflight", "1",
			},
			io.Discard,
			io.Discard,
			faultBridgeRunHooks{configureServer: func(server *faultServer) {
				server.beforeSocketCleanup = func() {
					if err := os.Remove(socketPath); err != nil {
						hookErr = err
						return
					}
					hookErr = os.WriteFile(socketPath, foreign, 0o600)
				}
			}},
		)
	}()
	waitForFaultSocket(t, socketPath)
	response, err := exchangeFaultRequest(
		socketPath, validRequest(operationTake, sourceDirect), recordSize,
	)
	require.NoError(t, err)
	require.Equal(t, statusMissing, response[8])
	select {
	case exitCode := <-done:
		require.Equal(t, 1, exitCode)
	case <-time.After(time.Second):
		t.Fatal("socket cleanup failure did not return")
	}
	require.NoError(t, hookErr)
	retained, err := os.ReadFile(socketPath)
	require.NoError(t, err)
	require.Equal(t, foreign, retained)

	payload, err := os.ReadFile(summaryPath)
	require.NoError(t, err)
	var summary faultSummary
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(payload), &summary))
	require.NoError(t, validateFaultSummary(summary))
	require.Equal(t, exitSocketCleanupError, summary.ExitClassification)
	require.EqualValues(t, 1, summary.SocketCleanupErrors)
	require.EqualValues(t, 1, summary.Responses.Missing)
	mutated := summary
	mutated.SocketCleanupErrors = 0
	require.Error(t, validateFaultSummary(mutated))
}

func TestSocketCleanupFailsExplicitlyAfterParentTrustLoss(t *testing.T) {
	requireLinuxSummaryPublication(t)
	root := t.TempDir()
	socketDirectory := filepath.Join(root, "socket")
	summaryDirectory := filepath.Join(root, "summary")
	require.NoError(t, os.Mkdir(socketDirectory, 0o700))
	require.NoError(t, os.Mkdir(summaryDirectory, 0o700))
	socketPath := filepath.Join(socketDirectory, "bridge.sock")
	summaryPath := filepath.Join(summaryDirectory, "summary.json")
	var hookErr error
	done := make(chan int, 1)
	go func() {
		done <- runFaultBridgeWithHooks(
			t.Context(),
			[]string{
				"--socket", socketPath,
				"--summary", summaryPath,
				"--mode", "missing",
				"--max-requests", "1",
				"--max-inflight", "1",
			},
			io.Discard,
			io.Discard,
			faultBridgeRunHooks{configureServer: func(server *faultServer) {
				server.beforeSocketCleanup = func() {
					hookErr = os.Chmod(socketDirectory, 0o770)
				}
			}},
		)
	}()
	waitForFaultSocket(t, socketPath)
	response, err := exchangeFaultRequest(
		socketPath, validRequest(operationTake, sourceDirect), recordSize,
	)
	require.NoError(t, err)
	require.Equal(t, statusMissing, response[8])
	select {
	case exitCode := <-done:
		require.Equal(t, 1, exitCode)
	case <-time.After(time.Second):
		t.Fatal("socket trust-loss cleanup failure did not return")
	}
	require.NoError(t, hookErr)
	info, err := os.Lstat(socketPath)
	require.NoError(t, err)
	require.NotZero(t, info.Mode()&os.ModeSocket)

	payload, err := os.ReadFile(summaryPath)
	require.NoError(t, err)
	var summary faultSummary
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(payload), &summary))
	require.NoError(t, validateFaultSummary(summary))
	require.Equal(t, exitSocketCleanupError, summary.ExitClassification)
	require.EqualValues(t, 1, summary.SocketCleanupErrors)

	require.NoError(t, os.Chmod(socketDirectory, 0o700))
	require.NoError(t, os.Remove(socketPath))
}

func TestSocketStaleCleanupUsesTrustedParentAndExactIdentity(t *testing.T) {
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o750))
	socketPath := filepath.Join(directory, "bridge.sock")
	listener, err := net.ListenUnix(
		"unix", &net.UnixAddr{Name: socketPath, Net: "unix"},
	)
	require.NoError(t, err)
	listener.SetUnlinkOnClose(false)
	require.NoError(t, listener.Close())
	lease, err := prepareSocketPath(socketPath)
	require.NoError(t, err)
	require.NoError(t, lease.closeDirectory())
	_, err = os.Lstat(socketPath)
	require.ErrorIs(t, err, os.ErrNotExist)

	listener, err = net.ListenUnix(
		"unix", &net.UnixAddr{Name: socketPath, Net: "unix"},
	)
	require.NoError(t, err)
	listener.SetUnlinkOnClose(false)
	require.NoError(t, listener.Close())

	directoryFile, err := os.Open(directory)
	require.NoError(t, err)
	defer directoryFile.Close()
	var stale unix.Stat_t
	require.NoError(t, unix.Fstatat(
		int(directoryFile.Fd()), filepath.Base(socketPath), &stale,
		unix.AT_SYMLINK_NOFOLLOW,
	))
	require.NoError(t, os.Remove(socketPath))
	foreign := []byte("foreign stale replacement")
	require.NoError(t, os.WriteFile(socketPath, foreign, 0o600))
	require.ErrorContains(
		t,
		unlinkSocketFile(int(directoryFile.Fd()), filepath.Base(socketPath), stale),
		"changed socket",
	)
	retained, err := os.ReadFile(socketPath)
	require.NoError(t, err)
	require.Equal(t, foreign, retained)
	require.ErrorContains(t, func() error {
		lease, prepareErr := prepareSocketPath(socketPath)
		if lease != nil {
			_ = lease.closeDirectory()
		}
		return prepareErr
	}(), "not a socket")
}

func TestSocketParentRejectsGroupOrOtherWriters(t *testing.T) {
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o770))
	socketPath := filepath.Join(directory, "bridge.sock")
	lease, err := prepareSocketPath(socketPath)
	if lease != nil {
		_ = lease.closeDirectory()
	}
	require.ErrorContains(t, err, "not group/other writable")
	_, statErr := os.Lstat(socketPath)
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

func TestSummaryPublicationIsNoClobberAndSymlinkSafe(t *testing.T) {
	requireLinuxSummaryPublication(t)
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	server := testFaultServer("missing", 1, 1)
	summary := snapshotFaultServer(t, server, exitSignalDrained)
	summaryPath := filepath.Join(directory, "summary.json")
	require.NoError(t, writeFaultSummary(summaryPath, summary))
	original, err := os.ReadFile(summaryPath)
	require.NoError(t, err)
	require.ErrorContains(t, writeFaultSummary(summaryPath, summary), "file exists")
	retained, err := os.ReadFile(summaryPath)
	require.NoError(t, err)
	require.Equal(t, original, retained)

	target := filepath.Join(directory, "target")
	require.NoError(t, os.WriteFile(target, []byte("sentinel"), 0o600))
	symlink := filepath.Join(directory, "summary-link.json")
	require.NoError(t, os.Symlink(target, symlink))
	require.ErrorContains(t, prepareSummaryPath(symlink), "refusing to replace existing")
	require.Error(t, writeFaultSummary(symlink, summary))
	targetContents, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, []byte("sentinel"), targetContents)
	entries, err := os.ReadDir(directory)
	require.NoError(t, err)
	for _, entry := range entries {
		require.NotContains(t, entry.Name(), ".tmp-")
	}
}

func TestSummaryPublicationRequiresPrivateOwnedParent(t *testing.T) {
	requireLinuxSummaryPublication(t)
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o750))
	summaryPath := filepath.Join(directory, "summary.json")
	server := testFaultServer("missing", 1, 1)
	summary := snapshotFaultServer(t, server, exitSignalDrained)

	require.ErrorContains(t, prepareSummaryPath(summaryPath), "private")
	require.ErrorContains(t, writeFaultSummary(summaryPath, summary), "private")
	entries, err := os.ReadDir(directory)
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestSummaryPublicationFailsClosedOffLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("non-Linux fail-closed policy")
	}
	directory := t.TempDir()
	summaryPath := filepath.Join(directory, "summary.json")
	server := testFaultServer("missing", 1, 1)
	summary := snapshotFaultServer(t, server, exitSignalDrained)
	require.ErrorContains(t, writeFaultSummary(summaryPath, summary), "requires Linux")

	var stderr bytes.Buffer
	require.Equal(t, 2, runFaultBridge(t.Context(), []string{
		"--socket", filepath.Join(directory, "bridge.sock"),
		"--summary", summaryPath,
		"--mode", "missing",
		"--max-requests", "1",
		"--max-inflight", "1",
	}, io.Discard, &stderr))
	require.Contains(t, stderr.String(), "requires Linux")
}

func TestSummaryRollbackPreservesForeignLeafReplacement(t *testing.T) {
	requireLinuxSummaryPublication(t)
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	summaryPath := filepath.Join(directory, "summary.json")
	server := testFaultServer("missing", 1, 1)
	summary := snapshotFaultServer(t, server, exitSignalDrained)
	replacement := []byte("foreign replacement")

	err := writeFaultSummaryWithHooks(summaryPath, summary, faultSummaryPublishHooks{
		afterLink: func() error {
			if err := os.Remove(summaryPath); err != nil {
				return err
			}
			return os.WriteFile(summaryPath, replacement, 0o600)
		},
	})
	require.Error(t, err)
	retained, readErr := os.ReadFile(summaryPath)
	require.NoError(t, readErr)
	require.Equal(t, replacement, retained)
	entries, readErr := os.ReadDir(directory)
	require.NoError(t, readErr)
	require.Equal(t, []string{"summary.json"}, directoryEntryNames(entries))
}

func TestSummaryRollbackRefusesCleanupAfterParentTrustIsLost(t *testing.T) {
	requireLinuxSummaryPublication(t)
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	summaryPath := filepath.Join(directory, "summary.json")
	server := testFaultServer("missing", 1, 1)
	summary := snapshotFaultServer(t, server, exitSignalDrained)

	err := writeFaultSummaryWithHooks(summaryPath, summary, faultSummaryPublishHooks{
		afterLink: func() error {
			if err := os.Chmod(directory, 0o770); err != nil {
				return err
			}
			return errors.New("injected failure after parent trust loss")
		},
	})
	require.ErrorContains(t, err, "no longer owned and private")
	entries, readErr := os.ReadDir(directory)
	require.NoError(t, readErr)
	require.Len(t, entries, 2)
	require.Contains(t, directoryEntryNames(entries), "summary.json")
	require.Condition(t, func() bool {
		for _, entry := range entries {
			if len(entry.Name()) > len(".faultbridge-summary.tmp-") &&
				entry.Name()[:len(".faultbridge-summary.tmp-")] == ".faultbridge-summary.tmp-" {
				return true
			}
		}
		return false
	})
}

func TestSummaryPublicationRollsBackEveryInjectedPostLinkFailure(t *testing.T) {
	requireLinuxSummaryPublication(t)
	for _, test := range []struct {
		name string
		hook func(string, string) func() error
	}{
		{
			name: "publisher failure",
			hook: func(_, summaryPath string) func() error {
				return func() error {
					if _, err := os.Lstat(summaryPath); err != nil {
						return err
					}
					return errors.New("injected post-link failure")
				}
			},
		},
		{
			name: "parent identity replacement",
			hook: func(directory, _ string) func() error {
				return func() error {
					moved := directory + "-moved"
					if err := os.Rename(directory, moved); err != nil {
						return err
					}
					return os.Mkdir(directory, 0o700)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			directory := filepath.Join(root, "summary-parent")
			require.NoError(t, os.Mkdir(directory, 0o700))
			summaryPath := filepath.Join(directory, "summary.json")
			server := testFaultServer("missing", 1, 1)
			summary := snapshotFaultServer(t, server, exitSignalDrained)
			err := writeFaultSummaryWithHooks(summaryPath, summary, faultSummaryPublishHooks{
				afterLink: test.hook(directory, summaryPath),
			})
			require.Error(t, err)

			for _, candidate := range []string{directory, directory + "-moved"} {
				entries, readErr := os.ReadDir(candidate)
				if errors.Is(readErr, os.ErrNotExist) {
					continue
				}
				require.NoError(t, readErr)
				require.Empty(t, entries, "post-link failure left residue in %s", candidate)
			}
		})
	}
}

func TestSummarySchemaAndCounterReconciliationAreExact(t *testing.T) {
	server := testFaultServer("missing", 2, 1)
	server.acceptedRequests = 2
	server.parsedOperations = faultOperationCounts{Take: 1}
	server.responses = faultResponseCounts{Missing: 1}
	server.admissionRejections = 1
	server.observedMaxInflight = 1
	summary := snapshotFaultServer(t, server, exitInflightLimitExceeded)
	require.NoError(t, validateFaultSummary(summary))

	payload, err := json.Marshal(summary)
	require.NoError(t, err)
	var root map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(payload, &root))
	require.ElementsMatch(t, []string{
		"accepted_requests", "accept_transport_errors", "admission_rejections", "exit_classification",
		"drain_cancellations", "final_inflight", "finished_at", "kind", "limits",
		"malformed_requests", "matching_valid_takes", "max_inflight", "mode",
		"parsed_operations", "partial_requests", "responses", "schema_version",
		"socket_cleanup_errors", "started_at", "transport_errors",
		"unresolved_requests", "withheld_timeouts",
	}, mapKeys(root))
	var limits map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(root["limits"], &limits))
	require.ElementsMatch(t, []string{
		"drain_timeout_ns", "max_inflight", "max_requests", "request_timeout_ns",
		"timeout_delay_ns",
	}, mapKeys(limits))
	var operations map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(root["parsed_operations"], &operations))
	require.ElementsMatch(t, []string{"discard", "negotiate", "take"}, mapKeys(operations))
	var responses map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(root["responses"], &responses))
	require.ElementsMatch(t, []string{
		"bad_magic", "bad_size", "disconnect", "malformed", "missing", "overload",
		"stale", "timeout", "truncated", "valid", "version_mismatch", "zero_span_id",
		"zero_trace_id",
	}, mapKeys(responses))
	var unresolved map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(root["unresolved_requests"], &unresolved))
	require.ElementsMatch(
		t,
		[]string{"pending_responses", "pre_parse", "terminal"},
		mapKeys(unresolved),
	)
	var pendingResponses map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(unresolved["pending_responses"], &pendingResponses))
	require.ElementsMatch(t, mapKeys(responses), mapKeys(pendingResponses))

	mutations := []func(*faultSummary){
		func(value *faultSummary) { value.AcceptedRequests++ },
		func(value *faultSummary) { value.WithheldTimeouts++ },
		func(value *faultSummary) { value.MaxInflight = value.Limits.MaxInflight + 1 },
		func(value *faultSummary) {
			value.Limits.RequestTimeoutNS = maxRequestTimeout.Nanoseconds() + 1
		},
		func(value *faultSummary) {
			value.Limits.TimeoutDelayNS = maxTimeoutDelay.Nanoseconds() + 1
		},
		func(value *faultSummary) { value.ExitClassification = exitRequestLimitReached },
		func(value *faultSummary) { value.ExitClassification = exitMalformedRequest },
		func(value *faultSummary) { value.ExitClassification = exitPartialRequest },
		func(value *faultSummary) { value.ExitClassification = exitTransportError },
		func(value *faultSummary) { value.ExitClassification = exitStartupError },
		func(value *faultSummary) {
			value.Responses.Missing--
			value.Responses.Valid++
		},
		func(value *faultSummary) { value.MatchingValidTakes++ },
		func(value *faultSummary) { value.StartedAt = "0001-01-01T00:00:00Z" },
		func(value *faultSummary) { value.StartedAt = "2026-08-21T00:00:00.000Z" },
		func(value *faultSummary) { value.FinishedAt = "not-a-time" },
		func(value *faultSummary) { value.FinalInflight = 1 },
		func(value *faultSummary) { value.UnresolvedRequests.PreParse = 1 },
		func(value *faultSummary) { value.UnresolvedRequests.PendingResponses.Missing = 1 },
		func(value *faultSummary) { value.UnresolvedRequests.Terminal = 1 },
		func(value *faultSummary) { value.UnresolvedRequests.Terminal = ^uint64(0) },
		func(value *faultSummary) { value.DrainCancellations = 1 },
		func(value *faultSummary) { value.AcceptTransportErrors = 1 },
		func(value *faultSummary) {
			value.AcceptTransportErrors = 1
			value.TransportErrors = 1
		},
		func(value *faultSummary) { value.SocketCleanupErrors = 2 },
	}
	for _, mutate := range mutations {
		mutated := summary
		mutate(&mutated)
		require.Error(t, validateFaultSummary(mutated))
	}
}

func TestSummaryOperationStatusReachabilityIsExact(t *testing.T) {
	valid := func(
		mode string,
		matchingValidTakes uint64,
		operations faultOperationCounts,
		responses faultResponseCounts,
	) faultSummary {
		accepted := operations.total()
		server := testFaultServer(mode, accepted, 1)
		server.matchingValidTakes = matchingValidTakes
		server.acceptedRequests = accepted
		server.parsedOperations = operations
		server.responses = responses
		server.withheldTimeouts = responses.Timeout
		server.observedMaxInflight = 1
		summary := snapshotFaultServer(t, server, exitRequestLimitReached)
		require.NoError(t, validateFaultSummary(summary), mode)
		return summary
	}

	timeoutSummary := valid(
		"timeout",
		1,
		faultOperationCounts{Discard: 1, Take: 1},
		faultResponseCounts{Missing: 1, Timeout: 1},
	)
	_ = valid(
		"matching",
		2,
		faultOperationCounts{Take: 4},
		faultResponseCounts{Missing: 2, Valid: 2},
	)
	alternatingSummary := valid(
		defaultFaultMode,
		1,
		faultOperationCounts{Discard: 1, Take: 3},
		faultResponseCounts{Malformed: 1, Missing: 1, Stale: 2},
	)
	_ = valid(
		"overload",
		1,
		faultOperationCounts{Negotiate: 1, Take: 2},
		faultResponseCounts{Missing: 1, Overload: 2},
	)
	matchingFirstTake := valid(
		"matching",
		2,
		faultOperationCounts{Take: 1},
		faultResponseCounts{Missing: 1},
	)
	for _, test := range []struct {
		mode      string
		responses faultResponseCounts
	}{
		{mode: "missing", responses: faultResponseCounts{Missing: 3}},
		{mode: "matching", responses: faultResponseCounts{Missing: 3}},
		{mode: defaultFaultMode, responses: faultResponseCounts{Missing: 2, Stale: 1}},
		{mode: "timeout", responses: faultResponseCounts{Missing: 2, Timeout: 1}},
		{mode: "disconnect", responses: faultResponseCounts{Disconnect: 1, Missing: 2}},
		{mode: "overload", responses: faultResponseCounts{Missing: 2, Overload: 1}},
		{mode: "truncated", responses: faultResponseCounts{Missing: 2, Truncated: 1}},
		{mode: "bad-magic", responses: faultResponseCounts{BadMagic: 1, Missing: 2}},
		{mode: "bad-size", responses: faultResponseCounts{BadSize: 1, Missing: 2}},
		{
			mode:      "version-mismatch",
			responses: faultResponseCounts{Missing: 2, VersionMismatch: 1},
		},
		{mode: "zero-trace-id", responses: faultResponseCounts{Missing: 2, ZeroTraceID: 1}},
		{mode: "zero-span-id", responses: faultResponseCounts{Missing: 2, ZeroSpanID: 1}},
	} {
		t.Run(test.mode+" exact status roster", func(_ *testing.T) {
			valid(
				test.mode,
				1,
				faultOperationCounts{Discard: 1, Negotiate: 1, Take: 1},
				test.responses,
			)
		})
	}

	for name, contradiction := range map[string]faultSummary{
		"timeout discard reported as timeout": func() faultSummary {
			value := timeoutSummary
			value.Responses.Missing--
			value.Responses.Timeout++
			value.WithheldTimeouts++
			return value
		}(),
		"matching first take reported as valid": func() faultSummary {
			value := matchingFirstTake
			value.Responses.Missing--
			value.Responses.Valid++
			return value
		}(),
		"alternating ordinal counts reversed": func() faultSummary {
			value := alternatingSummary
			value.Responses.Malformed--
			value.Responses.Stale++
			return value
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, validateFaultSummary(contradiction))
		})
	}
}

func TestSummaryExitClassificationsRequireReachableCounters(t *testing.T) {
	valid := func(classification string, configure func(*faultServer)) faultSummary {
		server := testFaultServer("missing", 2, 1)
		configure(server)
		summary := snapshotFaultServer(t, server, classification)
		require.NoError(t, validateFaultSummary(summary), classification)
		return summary
	}

	signalSummary := valid(exitSignalDrained, func(server *faultServer) {
		server.acceptedRequests = 1
		server.parsedOperations.Take = 1
		server.responses.Missing = 1
		server.observedMaxInflight = 1
	})
	requestLimitSummary := valid(exitRequestLimitReached, func(server *faultServer) {
		server.acceptedRequests = 2
		server.parsedOperations.Take = 2
		server.responses.Missing = 2
		server.observedMaxInflight = 1
	})
	inflightSummary := valid(exitInflightLimitExceeded, func(server *faultServer) {
		server.acceptedRequests = 2
		server.parsedOperations.Take = 1
		server.responses.Missing = 1
		server.admissionRejections = 1
		server.observedMaxInflight = 1
	})
	_ = valid(exitMalformedRequest, func(server *faultServer) {
		server.acceptedRequests = 1
		server.malformedRequests = 1
		server.observedMaxInflight = 1
	})
	partialSummary := valid(exitPartialRequest, func(server *faultServer) {
		server.acceptedRequests = 1
		server.partialRequests = 1
		server.transportErrors = 1
		server.observedMaxInflight = 1
	})
	_ = valid(exitTransportError, func(server *faultServer) {
		server.acceptedRequests = 1
		server.parsedOperations.Take = 1
		server.transportErrors = 1
		server.observedMaxInflight = 1
	})
	acceptTransportSummary := valid(exitTransportError, func(server *faultServer) {
		server.transportErrors = 1
		server.acceptTransportErrors = 1
	})
	mixedTransportSummary := valid(exitTransportError, func(server *faultServer) {
		server.acceptedRequests = 1
		server.parsedOperations.Take = 1
		server.transportErrors = 2
		server.acceptTransportErrors = 1
		server.observedMaxInflight = 1
	})
	drainServer := testFaultServer("timeout", 2, 1)
	drainServer.acceptedRequests = 1
	drainServer.parsedOperations.Take = 1
	drainServer.drainCancellations = 1
	drainServer.observedMaxInflight = 1
	drainSummary := snapshotFaultServer(t, drainServer, exitDrainTimeout)
	require.NoError(t, validateFaultSummary(drainSummary), exitDrainTimeout)
	cleanupServer := testFaultServer("missing", 2, 1)
	cleanupServer.acceptedRequests = 1
	cleanupServer.parsedOperations.Take = 1
	cleanupServer.responses.Missing = 1
	cleanupServer.socketCleanupErrors = 1
	cleanupServer.observedMaxInflight = 1
	cleanupSummary := snapshotFaultServer(t, cleanupServer, exitSocketCleanupError)
	require.NoError(t, validateFaultSummary(cleanupSummary), exitSocketCleanupError)
	startupSummary := valid(exitStartupError, func(*faultServer) {})

	contradictions := []faultSummary{
		func() faultSummary {
			value := inflightSummary
			value.Limits.MaxInflight++
			return value
		}(),
		func() faultSummary {
			value := partialSummary
			value.TransportErrors--
			return value
		}(),
		func() faultSummary {
			value := acceptTransportSummary
			value.AcceptTransportErrors--
			return value
		}(),
		func() faultSummary {
			value := acceptTransportSummary
			value.TransportErrors--
			return value
		}(),
		func() faultSummary {
			value := mixedTransportSummary
			value.AcceptTransportErrors--
			return value
		}(),
		func() faultSummary {
			value := mixedTransportSummary
			value.TransportErrors--
			return value
		}(),
		func() faultSummary {
			value := mixedTransportSummary
			value.Limits.MaxRequests = value.AcceptedRequests
			return value
		}(),
		func() faultSummary {
			value := inflightSummary
			value.Responses.Missing--
			return value
		}(),
		func() faultSummary {
			value := signalSummary
			value.ExitClassification = exitInflightLimitExceeded
			return value
		}(),
		func() faultSummary {
			value := signalSummary
			value.ExitClassification = exitMalformedRequest
			return value
		}(),
		func() faultSummary {
			value := signalSummary
			value.ExitClassification = exitPartialRequest
			return value
		}(),
		func() faultSummary {
			value := signalSummary
			value.ExitClassification = exitTransportError
			return value
		}(),
		func() faultSummary {
			value := startupSummary
			value.ExitClassification = exitDrainTimeout
			return value
		}(),
		func() faultSummary {
			value := requestLimitSummary
			value.AcceptedRequests--
			value.ParsedOperations.Take--
			value.Responses.Missing--
			return value
		}(),
		func() faultSummary {
			value := signalSummary
			value.ExitClassification = exitStartupError
			return value
		}(),
		func() faultSummary {
			value := cleanupSummary
			value.SocketCleanupErrors = 0
			return value
		}(),
		func() faultSummary {
			value := requestLimitSummary
			value.SocketCleanupErrors = 1
			return value
		}(),
	}
	for _, contradiction := range contradictions {
		require.Error(t, validateFaultSummary(contradiction), contradiction.ExitClassification)
	}
}

func TestRunFaultBridgeRejectsInvalidLimitsAndDoesNotEnableSummaryByDefault(t *testing.T) {
	directory := t.TempDir()
	socketPath := filepath.Join(directory, "bridge.sock")
	for _, arguments := range [][]string{
		{"--socket", socketPath, "--mode", "missing", "--max-requests", "0"},
		{"--socket", socketPath, "--mode", "missing", "--max-requests", "10001"},
		{"--socket", socketPath, "--mode", "missing", "--max-requests", "1", "--max-inflight", "2"},
		{"--socket", socketPath, "--mode", "missing", "--max-inflight", "0"},
		{"--socket", socketPath, "--mode", "missing", "--max-inflight", "1025"},
		{"--socket", socketPath, "--mode", "missing", "--drain-timeout", "0s"},
		{"--socket", socketPath, "--mode", "missing", "--drain-timeout", "31s"},
		{"--socket", socketPath, "--mode", "missing", "--matching-valid-takes", "0"},
		{"--socket", socketPath, "--mode", "missing", "--matching-valid-takes", "2"},
		{"--socket", socketPath, "--mode", "missing", "--matching-valid-takes", "18446744073709551615"},
		{"--socket", socketPath, "--mode", "matching", "--matching-valid-takes", "1001"},
		{"--socket", socketPath, "--mode", "missing", "--summary", "relative.json"},
		{"--socket", socketPath, "--mode", "missing", "--summary", directory + "/dirty/../summary.json"},
		{"--socket", socketPath, "--mode", "missing", "--summary", socketPath},
	} {
		var stderr bytes.Buffer
		require.Equal(t, 2, runFaultBridge(t.Context(), arguments, io.Discard, &stderr))
		require.NotEmpty(t, stderr.String())
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	require.Zero(t, runFaultBridge(cancelled, []string{
		"--socket", socketPath,
		"--mode", "missing",
		"--max-requests", "1",
		"--max-inflight", "1",
	}, io.Discard, io.Discard))
	_, err := os.Lstat(socketPath + ".summary.json")
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestRunFaultBridgeDefaultsRemainCompatibleAndDoNotPublishSummary(t *testing.T) {
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	socketPath := filepath.Join(directory, "bridge.sock")
	t.Setenv("FAULT_MODE", "missing")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() {
		done <- runFaultBridge(
			ctx, []string{"--socket", socketPath}, io.Discard, io.Discard,
		)
	}()
	waitForFaultSocket(t, socketPath)
	response, err := exchangeFaultRequest(
		socketPath, validRequest(operationTake, sourceDirect), recordSize,
	)
	require.NoError(t, err)
	require.Equal(t, statusMissing, response[8])
	cancel()
	select {
	case exitCode := <-done:
		require.Zero(t, exitCode)
	case <-time.After(time.Second):
		t.Fatal("default fault bridge did not stop")
	}
	requireSocketRemoved(t, socketPath)
	_, err = os.Lstat(socketPath + ".summary.json")
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestMatchingTakeCountValidation(t *testing.T) {
	assert.False(t, validMatchingTakeCount(defaultFaultMode, 0))
	assert.True(t, validMatchingTakeCount(defaultFaultMode, 1))
	assert.False(t, validMatchingTakeCount(defaultFaultMode, 2))
	assert.False(t, validMatchingTakeCount("matching", 0))
	assert.True(t, validMatchingTakeCount("matching", 1))
	assert.True(t, validMatchingTakeCount("matching", maxMatchingTakes))
	assert.False(t, validMatchingTakeCount("matching", maxMatchingTakes+1))
}

func TestParseRequestAcceptsCurrentVersionAndLookupSources(t *testing.T) {
	require.Equal(t, uint16(3), requestVersion)
	require.Equal(t, 24, requestSize)
	require.Equal(t, operationTake, byte(1))
	require.Equal(t, operationDrop, byte(2))
	require.Equal(t, operationProbe, byte(3))
	require.Equal(t, sourceDirect, byte(1))
	require.Equal(t, sourceTask, byte(2))

	for _, operation := range []byte{operationTake, operationDrop, operationProbe} {
		for _, source := range []byte{sourceDirect, sourceTask} {
			request := validRequest(operation, source)
			assert.Equal(t, requestVersion, binary.LittleEndian.Uint16(request[4:6]))
			assert.Equal(t, source, request[9])
			assert.Equal(t, []byte{0, 0}, request[10:12])

			parsedRequest, err := parseRequest(request)
			require.NoError(t, err)
			assert.Equal(t, operation, parsedRequest.operation)
			assert.Equal(t, source, parsedRequest.source)
		}
	}
}

func TestParseRequestRejectsLegacyVersion(t *testing.T) {
	const legacyRequestVersion = uint16(2)

	request := validRequest(operationTake, sourceDirect)
	binary.LittleEndian.PutUint16(request[4:6], legacyRequestVersion)

	_, err := parseRequest(request)
	assert.ErrorContains(t, err, "invalid request envelope")
}

func TestParseRequestRejectsZeroOrInvalidLookupSource(t *testing.T) {
	for _, source := range []byte{0, sourceTask + 1, 0xff} {
		request := validRequest(operationTake, source)

		_, err := parseRequest(request)
		assert.ErrorContains(t, err, "invalid request source")
	}
}

func TestParseRequestRejectsNonzeroReservedBytes(t *testing.T) {
	for _, offset := range []int{10, 11} {
		request := validRequest(operationTake, sourceDirect)
		request[offset] = 1

		_, err := parseRequest(request)
		assert.ErrorContains(t, err, "identity or reserved")
	}
}

func TestParseRequestRejectsZeroIdentity(t *testing.T) {
	for _, zeroIdentity := range []func([]byte){
		func(request []byte) { clear(request[12:16]) },
		func(request []byte) { clear(request[16:24]) },
	} {
		request := validRequest(operationTake, sourceDirect)
		zeroIdentity(request)

		_, err := parseRequest(request)
		assert.ErrorContains(t, err, "identity or reserved")
	}
}

func TestStatusRecordIsProtocolSized(t *testing.T) {
	record := statusRecord(statusStale)
	require.Len(t, record, recordSize)
	assert.Equal(t, "OBIJ", string(record[:4]))
	assert.Equal(t, recordVersion, binary.LittleEndian.Uint16(record[4:6]))
	assert.EqualValues(t, recordSize, binary.LittleEndian.Uint16(record[6:8]))
	assert.Equal(t, statusStale, record[8])
}

func TestValidRecordMatchesCanonicalSampledVector(t *testing.T) {
	const canonical = "4f42494a010040000101000000000000000102030405060708090a0b0c0d0e0f" +
		"1011121314151617080706050403020118171615141312110000000000000000"

	assert.Equal(t, canonical, hex.EncodeToString(validRecord()))
}

type faultServeResult struct {
	classification string
	err            error
}

type blockingWriter struct {
	mu          sync.Mutex
	contents    bytes.Buffer
	blockWrite  int
	writes      int
	blocked     chan struct{}
	release     chan struct{}
	returned    chan struct{}
	releaseOnce sync.Once
}

func newBlockingWriter(blockWrite int) *blockingWriter {
	return &blockingWriter{
		blockWrite: blockWrite,
		blocked:    make(chan struct{}),
		release:    make(chan struct{}),
		returned:   make(chan struct{}),
	}
}

func (w *blockingWriter) Write(payload []byte) (int, error) {
	w.mu.Lock()
	w.writes++
	shouldBlock := w.writes == w.blockWrite
	_, _ = w.contents.Write(payload)
	w.mu.Unlock()
	if shouldBlock {
		close(w.blocked)
		<-w.release
		close(w.returned)
	}
	return len(payload), nil
}

func (w *blockingWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.contents.String()
}

func (w *blockingWriter) unblock() {
	w.releaseOnce.Do(func() { close(w.release) })
}

func testFaultServer(mode string, maxRequests, maxInflight uint64) *faultServer {
	return &faultServer{
		mode:               mode,
		matchingValidTakes: 1,
		maxRequests:        maxRequests,
		maxInflight:        maxInflight,
		requestTimeout:     500 * time.Millisecond,
		timeoutDelay:       50 * time.Millisecond,
		drainTimeout:       time.Second,
		stdout:             io.Discard,
		stderr:             io.Discard,
		active:             make(map[*net.UnixConn]faultActiveRequest),
	}
}

func startFaultServer(
	ctx context.Context,
	t *testing.T,
	server *faultServer,
) (string, <-chan faultServeResult) {
	t.Helper()
	directory := t.TempDir()
	require.NoError(t, os.Chmod(directory, 0o700))
	socketPath := filepath.Join(directory, "bridge.sock")
	done := make(chan faultServeResult, 1)
	go func() {
		classification, err := serve(ctx, socketPath, server)
		done <- faultServeResult{classification: classification, err: err}
	}()
	var startupFailure *faultServeResult
	require.Eventually(t, func() bool {
		select {
		case result := <-done:
			startupFailure = &result
			return true
		default:
		}
		info, err := os.Lstat(socketPath)
		return err == nil && info.Mode()&os.ModeSocket != 0
	}, 5*time.Second, time.Millisecond)
	if startupFailure != nil {
		require.NoError(t, startupFailure.err, startupFailure.classification)
	}
	return socketPath, done
}

func waitForFaultSocket(t *testing.T, socketPath string) {
	t.Helper()
	require.Eventually(t, func() bool {
		info, err := os.Lstat(socketPath)
		return err == nil && info.Mode()&os.ModeSocket != 0
	}, 5*time.Second, time.Millisecond)
}

func waitFaultServer(t *testing.T, done <-chan faultServeResult) faultServeResult {
	t.Helper()
	select {
	case result := <-done:
		return result
	case <-time.After(5 * time.Second):
		t.Fatal("fault bridge did not stop")
		return faultServeResult{}
	}
}

func exchangeFaultRequest(socketPath string, request []byte, responseSize int) ([]byte, error) {
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := connection.Write(request); err != nil {
		return nil, err
	}
	if responseSize == 0 {
		return io.ReadAll(connection)
	}
	response := make([]byte, responseSize)
	if _, err := io.ReadFull(connection, response); err != nil {
		return nil, err
	}
	return response, nil
}

func snapshotFaultServer(t *testing.T, server *faultServer, classification string) faultSummary {
	t.Helper()
	server.setDefaults()
	startedAt := time.Date(2026, time.August, 21, 0, 0, 0, 0, time.UTC)
	return server.summary(startedAt, startedAt.Add(time.Second), classification)
}

func requireLinuxSummaryPublication(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("descriptor-bound summary publication requires Linux")
	}
}

func requireSocketRemoved(t *testing.T, socketPath string) {
	t.Helper()
	_, err := os.Lstat(socketPath)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func directoryEntryNames(entries []os.DirEntry) []string {
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.Name()
	}
	return names
}

func mapKeys(values map[string]json.RawMessage) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func validRequest(operation, source byte) []byte {
	request := make([]byte, requestSize)
	copy(request[:4], "OBIQ")
	binary.LittleEndian.PutUint16(request[4:6], requestVersion)
	binary.LittleEndian.PutUint16(request[6:8], requestSize)
	request[8] = operation
	request[9] = source
	binary.LittleEndian.PutUint32(request[12:16], 42)
	binary.LittleEndian.PutUint64(request[16:24], 99)
	return request
}
