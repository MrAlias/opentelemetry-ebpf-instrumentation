// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Parameter metadata from .NET 8 DiagnosticSourceEventSource ActivityStop.
const diagnosticParametersV2 = "030000001e00000053006f0075007200630065004e0061006d00650000001200000022000000410063007400690076006900740079004e0061006d0065000000120000004800000041007200670075006d0065006e00740073000000130000000100000002000000100000004b006500790000001200000014000000560061006c0075006500000012000000"

func TestDiagnosticSourceParameters(t *testing.T) {
	wire, err := hex.DecodeString(diagnosticParametersV2)
	require.NoError(t, err)
	fields, err := readNetTraceFieldsV2(bytes.NewReader(wire), 0)
	require.NoError(t, err)
	require.Len(t, fields, 3)
	require.Equal(t, "Arguments", fields[2].Name)
	require.Equal(t, netTraceTypeArray, fields[2].Type)
	require.Equal(t, []netTraceField{{Name: "Key", Type: netTraceTypeString}, {Name: "Value", Type: netTraceTypeString}}, fields[2].Element.Fields)
	payload := []byte{}
	for _, s := range []string{"HttpHandlerDiagnosticListener", "System.Net.Http.HttpRequestOut.Stop"} {
		for _, r := range s + "\x00" {
			payload = binary.LittleEndian.AppendUint16(payload, uint16(r))
		}
	}
	payload = binary.LittleEndian.AppendUint16(payload, 2)
	for _, s := range []string{"TraceId", "12345678901234567890123456789012", "Version", "1.1"} {
		for _, r := range s + "\x00" {
			payload = binary.LittleEndian.AppendUint16(payload, uint16(r))
		}
	}
	reader := bytes.NewReader(payload)
	values, err := readNetTraceValues(reader, fields)
	require.NoError(t, err)
	require.Zero(t, reader.Len())
	require.Equal(t, []any{map[string]any{"Key": "TraceId", "Value": "12345678901234567890123456789012"}, map[string]any{"Key": "Version", "Value": "1.1"}}, values["Arguments"])
	for length := range len(payload) {
		_, err := readNetTraceValues(bytes.NewReader(payload[:length]), fields)
		require.Error(t, err, "truncated at byte %d", length)
	}
	for length := range len(wire) {
		_, err := readNetTraceFieldsV2(bytes.NewReader(wire[:length]), 0)
		require.Error(t, err, "truncated metadata at byte %d", length)
	}
}

func TestDiagnosticSourceMetadataExtensions(t *testing.T) {
	wire := binary.LittleEndian.AppendUint32(nil, 7)
	for _, s := range []string{"Microsoft-Diagnostics-DiagnosticSource", "ActivityStop"} {
		if s == "ActivityStop" {
			wire = binary.LittleEndian.AppendUint32(wire, 2)
		}
		for _, r := range s + "\x00" {
			wire = binary.LittleEndian.AppendUint16(wire, uint16(r))
		}
	}
	wire = binary.LittleEndian.AppendUint64(wire, 2)
	wire = binary.LittleEndian.AppendUint32(wire, 0)
	wire = binary.LittleEndian.AppendUint32(wire, 5)
	wire = binary.LittleEndian.AppendUint32(wire, 0)
	// Opcode tag followed by the v2 parameter payload tag.
	wire = append(wire, 1, 0, 0, 0, 1, 2)
	parameters, err := hex.DecodeString(diagnosticParametersV2)
	require.NoError(t, err)
	wire = binary.LittleEndian.AppendUint32(wire, uint32(len(parameters)))
	wire = append(wire, 2)
	wire = append(wire, parameters...)
	metadata, err := readNetTraceMetadata(bytes.NewReader(wire))
	require.NoError(t, err)
	require.Equal(t, "ActivityStop", metadata.Header.EventName)
	require.Len(t, metadata.Fields, 3)
	for _, suffix := range [][]byte{{1}, {0, 0, 0, 0}, {255, 255, 255, 255, 2}, {0, 0, 0, 0, 9}} {
		_, err := readNetTraceMetadata(bytes.NewReader(append(bytes.Clone(wire), suffix...)))
		require.Error(t, err)
	}
	_, err = readNetTraceFieldsV2(bytes.NewReader(parameters), maximumNetTraceFieldDepth)
	require.ErrorContains(t, err, "nesting exceeds")
}

func TestEventPipeProviderSelection(t *testing.T) {
	request, err := encodeEventPipeProviders([]eventPipeProvider{
		{name: "System.Runtime", arguments: "EventCounterIntervalSec=1", keywords: 2, level: 4},
		{name: "Microsoft-Diagnostics-DiagnosticSource", arguments: "FilterAndPayloadSpecs=[AS]System.Net.Http", keywords: 2, level: 5},
	})
	require.NoError(t, err)
	require.Equal(t, uint32(2), binary.LittleEndian.Uint32(request[29:33]))
	reader := bytes.NewReader(request[33:])
	for _, want := range []struct {
		name, args string
		level      uint32
	}{
		{"System.Runtime", "EventCounterIntervalSec=1", 4},
		{"Microsoft-Diagnostics-DiagnosticSource", "FilterAndPayloadSpecs=[AS]System.Net.Http", 5},
	} {
		var keywords uint64
		var level uint32
		require.NoError(t, binary.Read(reader, binary.LittleEndian, &keywords))
		require.NoError(t, binary.Read(reader, binary.LittleEndian, &level))
		require.Equal(t, uint64(2), keywords)
		require.Equal(t, want.level, level)
		name, err := readIPCString(reader)
		require.NoError(t, err)
		require.Equal(t, want.name, name)
		args, err := readIPCString(reader)
		require.NoError(t, err)
		require.Equal(t, want.args, args)
	}
	require.Zero(t, reader.Len())
	_, err = encodeEventPipeProviders(nil)
	require.Error(t, err)
	_, err = encodeEventPipeProviders([]eventPipeProvider{{name: strings.Repeat("x", 1<<16)}})
	require.ErrorContains(t, err, "message size limit")
}
