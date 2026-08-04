// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
			socketPath := filepath.Join(t.TempDir(), "bridge.sock")
			done := make(chan error, 1)
			go func() {
				done <- serve(t.Context(), socketPath, &faultServer{
					mode:               "matching",
					matchingValidTakes: 1,
				})
			}()

			var connection *net.UnixConn
			require.Eventually(t, func() bool {
				var err error
				connection, err = net.DialUnix(
					"unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"},
				)
				return err == nil
			}, time.Second, time.Millisecond)
			_, err := connection.Write(test.request)
			require.NoError(t, err)
			require.NoError(t, connection.Close())

			select {
			case err := <-done:
				require.ErrorContains(t, err, test.wantErr)
			case <-time.After(time.Second):
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
	assert.True(t, validFaultMode(defaultFaultMode))
	assert.True(t, validFaultMode("matching"))
	assert.True(t, validFaultMode("timeout"))
	assert.False(t, validFaultMode("unknown"))
}

func TestMatchingTakeCountValidation(t *testing.T) {
	assert.True(t, validMatchingTakeCount(defaultFaultMode, 0))
	assert.False(t, validMatchingTakeCount("matching", 0))
	assert.True(t, validMatchingTakeCount("matching", 1))
	assert.True(t, validMatchingTakeCount("matching", maxMatchingTakes))
	assert.False(t, validMatchingTakeCount("matching", maxMatchingTakes+1))
}

func TestParseRequestAcceptsCurrentVersionAndLookupSources(t *testing.T) {
	require.Equal(t, uint16(3), requestVersion)
	require.Equal(t, 24, requestSize)
	require.Equal(t, byte(1), operationTake)
	require.Equal(t, byte(2), operationDrop)
	require.Equal(t, byte(3), operationProbe)
	require.Equal(t, byte(1), sourceDirect)
	require.Equal(t, byte(2), sourceTask)

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
