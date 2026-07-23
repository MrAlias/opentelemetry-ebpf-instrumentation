// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package javabridge

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	recordCorpusFormat  = "format|1"
	recordCorpusHeader  = "name|outcome|status_name|status|wire_hex"
	recordCorpusMaxSize = 80
)

type recordCorpusCase uint8

const (
	corpusValidSampled recordCorpusCase = iota
	corpusValidUnsampled
	corpusValidFutureFlags
	corpusStatusOnly
	corpusAllZeroIDs
	corpusZeroTraceID
	corpusZeroSpanID
	corpusZeroGeneration
	corpusZeroObservation
	corpusZeroLength
	corpusPreMagicTruncated
	corpusTruncated
	corpusBadMagic
	corpusDeclaredSmaller
	corpusDeclaredLarger
	corpusReservedPrefix
	corpusReservedSuffix
	corpusUnknownStatusZero
	corpusUnknownStatus14
	corpusUnknownVersion
	corpusUnknownVersionBadSize
	corpusFutureLargerV1
	corpusFutureLargerUnknownVersion
)

type recordCorpusSpec struct {
	accepted   bool
	statusName string
	status     Status
	wireSize   int
	kind       recordCorpusCase
}

type recordCorpusVector struct {
	name     string
	accepted bool
	status   Status
	wire     []byte
}

func TestRecordCorpus(t *testing.T) {
	vectors := loadRecordCorpus(t)
	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			record, err := UnmarshalRecord(vector.wire)
			if !vector.accepted {
				require.Error(t, err)
				if vector.status == StatusVersionMismatch {
					require.ErrorIs(t, err, ErrVersionMismatch)
				} else {
					require.NotErrorIs(t, err, ErrVersionMismatch)
				}
				return
			}

			require.NoError(t, err)
			assert.Equal(t, vector.status, record.Status)

			encoded, err := record.MarshalBinary()
			require.NoError(t, err)
			assert.Equal(t, vector.wire, encoded)

			if vector.status == StatusValid {
				assert.Equal(t, expectedCorpusRecord(vector.wire[9]), record)
			}
		})
	}
}

func loadRecordCorpus(t *testing.T) []recordCorpusVector {
	t.Helper()

	path := filepath.Join("..", "..", "..", "testdata", "java-remote-parent-v1-vectors.txt")
	contents, err := os.ReadFile(path)
	require.NoError(t, err)

	specs := recordCorpusSpecs()
	stage := 0
	seen := map[string]struct{}{}
	vectors := make([]recordCorpusVector, 0, len(specs))
	for index, rawLine := range strings.Split(string(contents), "\n") {
		lineNumber := index + 1
		line := strings.TrimSuffix(rawLine, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		switch stage {
		case 0:
			require.Equal(t, recordCorpusFormat, line, "line %d", lineNumber)
			stage++
			continue
		case 1:
			require.Equal(t, recordCorpusHeader, line, "line %d", lineNumber)
			stage++
			continue
		}

		fields := strings.Split(line, "|")
		require.Len(t, fields, 5, "line %d", lineNumber)
		name := fields[0]
		require.True(t, validCorpusName(name), "line %d has invalid name %q", lineNumber, name)
		spec, required := specs[name]
		require.True(t, required, "line %d has unknown vector %q", lineNumber, name)
		_, duplicate := seen[name]
		require.False(t, duplicate, "line %d duplicates %q", lineNumber, name)
		seen[name] = struct{}{}

		outcome := "reject"
		if spec.accepted {
			outcome = "accept"
		}
		require.Equal(t, outcome, fields[1], "line %d", lineNumber)
		require.Equal(t, spec.statusName, fields[2], "line %d", lineNumber)

		statusValue, err := strconv.ParseUint(fields[3], 10, 8)
		require.NoError(t, err, "line %d", lineNumber)
		require.Equal(t, spec.status, Status(statusValue), "line %d", lineNumber)

		wire := decodeCorpusHex(t, fields[4], lineNumber)
		require.Len(t, wire, spec.wireSize, "line %d", lineNumber)
		require.Equal(t, expectedCorpusWire(spec), wire, "line %d", lineNumber)

		vectors = append(vectors, recordCorpusVector{
			name:     name,
			accepted: spec.accepted,
			status:   spec.status,
			wire:     wire,
		})
	}

	require.Equal(t, 2, stage, "corpus format or header is missing")
	require.Len(t, seen, len(specs), "required corpus cases are missing")
	return vectors
}

func recordCorpusSpecs() map[string]recordCorpusSpec {
	const record = int(RecordSize)
	return map[string]recordCorpusSpec{
		"valid_sampled":                     {true, "valid", StatusValid, record, corpusValidSampled},
		"valid_unsampled":                   {true, "valid", StatusValid, record, corpusValidUnsampled},
		"valid_future_flags":                {true, "valid", StatusValid, record, corpusValidFutureFlags},
		"status_missing":                    {true, "missing", StatusMissing, record, corpusStatusOnly},
		"status_stale":                      {true, "stale", StatusStale, record, corpusStatusOnly},
		"status_unsupported":                {true, "unsupported", StatusUnsupported, record, corpusStatusOnly},
		"status_malformed":                  {true, "malformed", StatusMalformed, record, corpusStatusOnly},
		"status_version_mismatch":           {true, "version_mismatch", StatusVersionMismatch, record, corpusStatusOnly},
		"status_ambiguous":                  {true, "ambiguous", StatusAmbiguous, record, corpusStatusOnly},
		"status_unauthorized":               {true, "unauthorized", StatusUnauthorized, record, corpusStatusOnly},
		"status_already_consumed":           {true, "already_consumed", StatusAlreadyConsumed, record, corpusStatusOnly},
		"status_timeout":                    {true, "timeout", StatusTimeout, record, corpusStatusOnly},
		"status_overload":                   {true, "overload", StatusOverload, record, corpusStatusOnly},
		"status_transport_error":            {true, "transport_error", StatusTransportError, record, corpusStatusOnly},
		"status_disabled":                   {true, "disabled", StatusDisabled, record, corpusStatusOnly},
		"all_zero_ids":                      {false, "malformed", StatusMalformed, record, corpusAllZeroIDs},
		"zero_trace_id":                     {false, "malformed", StatusMalformed, record, corpusZeroTraceID},
		"zero_span_id":                      {false, "malformed", StatusMalformed, record, corpusZeroSpanID},
		"zero_generation":                   {false, "malformed", StatusMalformed, record, corpusZeroGeneration},
		"zero_observation_time":             {false, "malformed", StatusMalformed, record, corpusZeroObservation},
		"zero_length":                       {false, "malformed", StatusMalformed, 0, corpusZeroLength},
		"pre_magic_truncated":               {false, "malformed", StatusMalformed, 3, corpusPreMagicTruncated},
		"truncated":                         {false, "malformed", StatusMalformed, record - 1, corpusTruncated},
		"bad_magic":                         {false, "malformed", StatusMalformed, record, corpusBadMagic},
		"declared_smaller":                  {false, "malformed", StatusMalformed, record, corpusDeclaredSmaller},
		"declared_larger":                   {false, "malformed", StatusMalformed, record, corpusDeclaredLarger},
		"reserved_prefix":                   {false, "malformed", StatusMalformed, record, corpusReservedPrefix},
		"reserved_suffix":                   {false, "malformed", StatusMalformed, record, corpusReservedSuffix},
		"unknown_status_zero":               {false, "malformed", StatusMalformed, record, corpusUnknownStatusZero},
		"unknown_status_14":                 {false, "malformed", StatusMalformed, record, corpusUnknownStatus14},
		"unknown_version":                   {false, "version_mismatch", StatusVersionMismatch, record, corpusUnknownVersion},
		"unknown_version_bad_declared_size": {false, "version_mismatch", StatusVersionMismatch, record, corpusUnknownVersionBadSize},
		"future_larger_v1":                  {false, "malformed", StatusMalformed, recordCorpusMaxSize, corpusFutureLargerV1},
		"future_larger_unknown_version":     {false, "malformed", StatusMalformed, recordCorpusMaxSize, corpusFutureLargerUnknownVersion},
	}
}

func decodeCorpusHex(t *testing.T, encoded string, lineNumber int) []byte {
	t.Helper()
	require.NotEmpty(t, encoded, "line %d", lineNumber)
	if encoded == "-" {
		return nil
	}
	require.Equal(t, strings.ToLower(encoded), encoded, "line %d", lineNumber)
	wire, err := hex.DecodeString(encoded)
	require.NoError(t, err, "line %d", lineNumber)
	require.LessOrEqual(t, len(wire), recordCorpusMaxSize, "line %d", lineNumber)
	return wire
}

func expectedCorpusWire(spec recordCorpusSpec) []byte {
	if spec.kind == corpusStatusOnly {
		return corpusStatusWire(spec.status)
	}

	flags := byte(1)
	switch spec.kind {
	case corpusValidUnsampled:
		flags = 0
	case corpusValidFutureFlags:
		flags = 0x81
	}
	wire := corpusValidWire(flags)

	switch spec.kind {
	case corpusValidSampled, corpusValidUnsampled, corpusValidFutureFlags:
		return wire
	case corpusAllZeroIDs:
		clear(wire[16:40])
	case corpusZeroTraceID:
		clear(wire[16:32])
	case corpusZeroSpanID:
		clear(wire[32:40])
	case corpusZeroGeneration:
		clear(wire[40:48])
	case corpusZeroObservation:
		clear(wire[48:56])
	case corpusZeroLength:
		return nil
	case corpusPreMagicTruncated:
		return wire[:3]
	case corpusTruncated:
		return wire[:len(wire)-1]
	case corpusBadMagic:
		wire[0] = 'X'
	case corpusDeclaredSmaller:
		binary.LittleEndian.PutUint16(wire[6:8], 63)
	case corpusDeclaredLarger:
		binary.LittleEndian.PutUint16(wire[6:8], recordCorpusMaxSize)
	case corpusReservedPrefix:
		wire[10] = 1
	case corpusReservedSuffix:
		wire[56] = 1
	case corpusUnknownStatusZero, corpusUnknownStatus14:
		wire = corpusStatusWire(StatusMissing)
		if spec.kind == corpusUnknownStatus14 {
			wire[8] = 14
		} else {
			wire[8] = 0
		}
	case corpusUnknownVersion:
		binary.LittleEndian.PutUint16(wire[4:6], 2)
	case corpusUnknownVersionBadSize:
		binary.LittleEndian.PutUint16(wire[4:6], 2)
		binary.LittleEndian.PutUint16(wire[6:8], recordCorpusMaxSize)
	case corpusFutureLargerV1, corpusFutureLargerUnknownVersion:
		wire = append(wire, make([]byte, recordCorpusMaxSize-int(RecordSize))...)
		binary.LittleEndian.PutUint16(wire[6:8], recordCorpusMaxSize)
		if spec.kind == corpusFutureLargerUnknownVersion {
			binary.LittleEndian.PutUint16(wire[4:6], 2)
		}
	}
	return wire
}

func corpusValidWire(flags byte) []byte {
	wire := corpusStatusWire(StatusValid)
	wire[9] = flags
	for index := 0; index < TraceIDSize; index++ {
		wire[16+index] = byte(index)
	}
	for index := 0; index < SpanIDSize; index++ {
		wire[32+index] = byte(index + 16)
	}
	binary.LittleEndian.PutUint64(wire[40:48], 0x0102030405060708)
	binary.LittleEndian.PutUint64(wire[48:56], 0x1112131415161718)
	return wire
}

func corpusStatusWire(status Status) []byte {
	wire := make([]byte, RecordSize)
	copy(wire[0:4], "OBIJ")
	binary.LittleEndian.PutUint16(wire[4:6], Version)
	binary.LittleEndian.PutUint16(wire[6:8], RecordSize)
	wire[8] = byte(status)
	return wire
}

func validCorpusName(name string) bool {
	if name == "" || name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for _, value := range []byte(name) {
		if (value < 'a' || value > 'z') && (value < '0' || value > '9') && value != '_' {
			return false
		}
	}
	return true
}

func expectedCorpusRecord(flags byte) Record {
	record := Record{
		Status:              StatusValid,
		Flags:               flags,
		Generation:          0x0102030405060708,
		ObservedMonotonicNS: 0x1112131415161718,
	}
	for index := range record.TraceID {
		record.TraceID[index] = byte(index)
	}
	for index := range record.SpanID {
		record.SpanID[index] = byte(index + 16)
	}
	return record
}
