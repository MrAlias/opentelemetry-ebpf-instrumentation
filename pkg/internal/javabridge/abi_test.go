// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package javabridge

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordGoldenVector(t *testing.T) {
	record := Record{
		Status:              StatusValid,
		Flags:               1,
		TraceID:             [TraceIDSize]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
		SpanID:              [SpanIDSize]byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
		Generation:          0x0102030405060708,
		ObservedMonotonicNS: 0x1112131415161718,
	}

	encoded, err := record.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t,
		"4f42494a010040000101000000000000000102030405060708090a0b0c0d0e0f1011121314151617080706050403020118171615141312110000000000000000",
		hex.EncodeToString(encoded),
	)

	decoded, err := UnmarshalRecord(encoded)
	require.NoError(t, err)
	assert.Equal(t, record, decoded)
}

func TestRecordRejectsInvalidFraming(t *testing.T) {
	valid, err := (Record{Status: StatusMissing}).MarshalBinary()
	require.NoError(t, err)

	tests := map[string]func([]byte) []byte{
		"truncated": func(buf []byte) []byte { return buf[:len(buf)-1] },
		"magic": func(buf []byte) []byte {
			buf[0] = 0
			return buf
		},
		"version": func(buf []byte) []byte {
			buf[4] = 2
			return buf
		},
		"small size": func(buf []byte) []byte {
			buf[6] = 63
			return buf
		},
		"reserved": func(buf []byte) []byte {
			buf[10] = 1
			return buf
		},
		"status": func(buf []byte) []byte {
			buf[8] = 255
			return buf
		},
		"unknown status": func(buf []byte) []byte {
			buf[8] = byte(StatusUnknown)
			return buf
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := mutate(append([]byte(nil), valid...))
			_, err := UnmarshalRecord(candidate)
			require.Error(t, err)
		})
	}
}

func TestRecordDoesNotMarshalUnknownStatus(t *testing.T) {
	_, err := (Record{Status: StatusUnknown}).MarshalBinary()
	require.Error(t, err)
}

func TestRecordRejectsFutureLargerRecordInVersionOne(t *testing.T) {
	encoded, err := (Record{Status: StatusMissing}).MarshalBinary()
	require.NoError(t, err)
	encoded = append(encoded, make([]byte, 8)...)
	binary.LittleEndian.PutUint16(encoded[6:8], uint16(len(encoded)))

	_, err = UnmarshalRecord(encoded)
	require.Error(t, err)
}

func TestVersionMismatchIsTyped(t *testing.T) {
	record, err := (Record{Status: StatusMissing}).MarshalBinary()
	require.NoError(t, err)
	record[4] = 2
	_, err = UnmarshalRecord(record)
	require.ErrorIs(t, err, ErrVersionMismatch)

	request, err := (Request{Operation: OperationTake, NamespaceTID: 1}).MarshalBinary()
	require.NoError(t, err)
	request[4] = 3
	_, err = UnmarshalRequest(request)
	require.ErrorIs(t, err, ErrVersionMismatch)
}

func TestValidRemoteParentRejectsZeroIDs(t *testing.T) {
	record := Record{Status: StatusValid}
	assert.False(t, record.IsValidRemoteParent())

	record.TraceID[15] = 1
	assert.False(t, record.IsValidRemoteParent())

	record.SpanID[7] = 1
	assert.True(t, record.IsValidRemoteParent())

	record.Status = StatusMalformed
	assert.False(t, record.IsValidRemoteParent())
}

func TestRequestGoldenVector(t *testing.T) {
	request := Request{
		Operation:          OperationTake,
		NamespaceTID:       0x01020304,
		ProcessIncarnation: 0x0102030405060708,
	}

	encoded, err := request.MarshalBinary()
	require.NoError(t, err)
	assert.Equal(t, "4f4249510200180001000000040302010807060504030201", hex.EncodeToString(encoded))

	decoded, err := UnmarshalRequest(encoded)
	require.NoError(t, err)
	assert.Equal(t, request, decoded)
}

func TestSampledAndUnsampledRoundTrip(t *testing.T) {
	for _, flags := range []byte{0, 1} {
		t.Run(string(rune('0'+flags)), func(t *testing.T) {
			record := Record{Status: StatusValid, Flags: flags}
			record.TraceID[15] = 1
			record.SpanID[7] = 1

			encoded, err := record.MarshalBinary()
			require.NoError(t, err)
			decoded, err := UnmarshalRecord(encoded)
			require.NoError(t, err)
			assert.Equal(t, record, decoded)
		})
	}
}
