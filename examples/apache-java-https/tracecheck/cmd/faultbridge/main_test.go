// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFaultSequenceIsBoundedAndDeterministic(t *testing.T) {
	server := &faultServer{mode: defaultFaultMode}

	assert.Equal(t, "missing", server.response(operationProbe).status)
	assert.Equal(t, "stale", server.response(operationTake).status)
	assert.Equal(t, "malformed", server.response(operationTake).status)
	assert.Equal(t, "stale", server.response(operationTake).status)
	assert.EqualValues(t, 3, server.takes.Load())
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
			response := server.response(operationTake)

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
	badMagic := (&faultServer{mode: "bad-magic"}).response(operationTake).payload
	assert.Equal(t, "XBIJ", string(badMagic[:4]))

	badSize := (&faultServer{mode: "bad-size"}).response(operationTake).payload
	assert.EqualValues(t, recordSize-1, binary.LittleEndian.Uint16(badSize[6:8]))

	versionMismatch := (&faultServer{mode: "version-mismatch"}).response(operationTake).payload
	assert.Equal(t, recordVersion+1, binary.LittleEndian.Uint16(versionMismatch[4:6]))

	zeroTraceID := (&faultServer{mode: "zero-trace-id"}).response(operationTake).payload
	assert.Equal(t, make([]byte, 16), zeroTraceID[16:32])
	assert.NotEqual(t, make([]byte, 8), zeroTraceID[32:40])

	zeroSpanID := (&faultServer{mode: "zero-span-id"}).response(operationTake).payload
	assert.NotEqual(t, make([]byte, 16), zeroSpanID[16:32])
	assert.Equal(t, make([]byte, 8), zeroSpanID[32:40])
}

func TestFaultModeValidation(t *testing.T) {
	assert.True(t, validFaultMode(defaultFaultMode))
	assert.True(t, validFaultMode("timeout"))
	assert.False(t, validFaultMode("unknown"))
}

func TestParseRequestRejectsMalformedEnvelope(t *testing.T) {
	request := validRequest(operationTake)
	operation, err := parseRequest(request)
	require.NoError(t, err)
	assert.Equal(t, operationTake, operation)

	request[9] = 1
	_, err = parseRequest(request)
	assert.ErrorContains(t, err, "identity or reserved")
}

func TestStatusRecordIsProtocolSized(t *testing.T) {
	record := statusRecord(statusStale)
	require.Len(t, record, recordSize)
	assert.Equal(t, "OBIJ", string(record[:4]))
	assert.Equal(t, recordVersion, binary.LittleEndian.Uint16(record[4:6]))
	assert.EqualValues(t, recordSize, binary.LittleEndian.Uint16(record[6:8]))
	assert.Equal(t, statusStale, record[8])
}

func validRequest(operation byte) []byte {
	request := make([]byte, requestSize)
	copy(request[:4], "OBIQ")
	binary.LittleEndian.PutUint16(request[4:6], requestVersion)
	binary.LittleEndian.PutUint16(request[6:8], requestSize)
	request[8] = operation
	binary.LittleEndian.PutUint32(request[12:16], 42)
	binary.LittleEndian.PutUint64(request[16:24], 99)
	return request
}
