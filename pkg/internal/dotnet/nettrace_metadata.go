// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf16"
)

// netTraceEventAttributes is the fixed wire layout following the event name.
type netTraceEventAttributes struct {
	Keywords uint64
	Version  uint32
	Level    uint32
}

type netTraceMetadataHeader struct {
	MetadataID   uint32
	ProviderName string
	EventID      uint32
	EventName    string
	Keywords     uint64
	Version      uint32
	Level        uint32
}

const (
	netTraceTypeObject        uint32 = 1
	netTraceTypeBoolean       uint32 = 3
	netTraceTypeInt32         uint32 = 9
	netTraceTypeSingle        uint32 = 13
	netTraceTypeDouble        uint32 = 14
	netTraceTypeString        uint32 = 18
	netTraceTypeArray         uint32 = 19
	maximumNetTraceFields            = 256
	maximumNetTraceFieldDepth        = 32
	// Each field needs at least a uint32 type and a UTF-16 null terminator.
	minimumNetTraceFieldSize = 4 + 2
)

type netTraceField struct {
	Name    string
	Type    uint32
	Fields  []netTraceField
	Element *netTraceField
}

// Arrays use the v2 parameter tag emitted by DiagnosticSourceEventSource.
// https://github.com/dotnet/runtime/blob/v8.0.0/src/libraries/System.Private.CoreLib/src/System/Diagnostics/Tracing/EventPipeMetadataGenerator.cs
func readNetTraceMetadata(reader *bytes.Reader) (netTraceMetadata, error) {
	header, err := readNetTraceMetadataHeader(reader)
	if err != nil {
		return netTraceMetadata{}, err
	}
	var fields []netTraceField
	if reader.Len() > 0 {
		fields, err = readNetTraceFields(reader, 0)
		if err != nil {
			return netTraceMetadata{}, err
		}
	}
	seenV2 := false
	for reader.Len() > 0 {
		var size uint32
		if err := binary.Read(reader, binary.LittleEndian, &size); err != nil {
			return netTraceMetadata{}, fmt.Errorf("unsupported NetTrace metadata extension: %w", err)
		}
		tag, err := reader.ReadByte()
		if err != nil || uint64(size) > uint64(reader.Len()) {
			return netTraceMetadata{}, errors.New("invalid NetTrace metadata extension size")
		}
		data := make([]byte, size)
		_, _ = reader.Read(data)
		switch tag {
		case 1: // Opcode.
			if size != 1 {
				return netTraceMetadata{}, errors.New("invalid NetTrace opcode metadata")
			}
		case 2: // V2 parameter payload.
			if seenV2 || len(fields) != 0 {
				return netTraceMetadata{}, errors.New("duplicate NetTrace parameter metadata")
			}
			seenV2 = true
			parameters := bytes.NewReader(data)
			fields, err = readNetTraceFieldsV2(parameters, 0)
			if err != nil {
				return netTraceMetadata{}, err
			}
			if parameters.Len() != 0 {
				return netTraceMetadata{}, errors.New("trailing bytes in NetTrace v2 metadata")
			}
		default:
			return netTraceMetadata{}, fmt.Errorf("unsupported NetTrace metadata extension: %d", tag)
		}
	}
	return netTraceMetadata{Header: header, Fields: fields}, nil
}

func readNetTraceFieldsV2(reader *bytes.Reader, depth int) ([]netTraceField, error) {
	if depth >= maximumNetTraceFieldDepth {
		return nil, errors.New("NetTrace metadata field nesting exceeds decoder limit")
	}
	var count uint32
	if err := binary.Read(reader, binary.LittleEndian, &count); err != nil {
		return nil, err
	}
	if count > maximumNetTraceFields || uint64(count) > uint64(reader.Len()/minimumNetTraceFieldSize) {
		return nil, fmt.Errorf("invalid NetTrace v2 field count: %d", count)
	}
	fields := make([]netTraceField, count)
	for i := range fields {
		var size uint32
		if err := binary.Read(reader, binary.LittleEndian, &size); err != nil {
			return nil, err
		}
		if size < 4 || uint64(size-4) > uint64(reader.Len()) {
			return nil, errors.New("invalid NetTrace v2 field size")
		}
		data := make([]byte, size-4)
		_, _ = reader.Read(data)
		fieldReader := bytes.NewReader(data)
		var err error
		fields[i].Name, err = readNetTraceString(fieldReader)
		if err != nil {
			return nil, err
		}
		if err := readNetTraceTypeV2(fieldReader, &fields[i], depth); err != nil {
			return nil, err
		}
		if fieldReader.Len() != 0 {
			return nil, errors.New("trailing bytes in NetTrace v2 field")
		}
	}
	return fields, nil
}

func readNetTraceTypeV2(reader *bytes.Reader, field *netTraceField, depth int) error {
	if depth >= maximumNetTraceFieldDepth {
		return errors.New("NetTrace metadata field nesting exceeds decoder limit")
	}
	if err := binary.Read(reader, binary.LittleEndian, &field.Type); err != nil {
		return err
	}
	var err error
	switch field.Type {
	case netTraceTypeObject:
		field.Fields, err = readNetTraceFieldsV2(reader, depth+1)
	case netTraceTypeArray:
		field.Element = &netTraceField{}
		err = readNetTraceTypeV2(reader, field.Element, depth+1)
	default:
		if field.Type < netTraceTypeBoolean || field.Type > netTraceTypeString {
			return fmt.Errorf("unsupported NetTrace v2 field type: %d", field.Type)
		}
	}
	return err
}

// readNetTraceFields reads the base .NET metadata field layout. Object fields
// contain nested field lists; depth starts at zero for the event's field list.
func readNetTraceFields(reader *bytes.Reader, depth int) ([]netTraceField, error) {
	if depth < 0 || depth >= maximumNetTraceFieldDepth {
		return nil, errors.New("NetTrace metadata field nesting exceeds decoder limit")
	}
	var count uint32
	if err := binary.Read(reader, binary.LittleEndian, &count); err != nil {
		return nil, fmt.Errorf("reading NetTrace field count: %w", err)
	}
	if count > maximumNetTraceFields || uint64(count) > uint64(reader.Len()/minimumNetTraceFieldSize) {
		return nil, fmt.Errorf("invalid NetTrace field count: %d", count)
	}
	fields := make([]netTraceField, count)
	for i := range fields {
		field := &fields[i]
		if err := binary.Read(reader, binary.LittleEndian, &field.Type); err != nil {
			return nil, fmt.Errorf("reading NetTrace field %d type: %w", i, err)
		}
		if field.Type == netTraceTypeObject {
			var err error
			field.Fields, err = readNetTraceFields(reader, depth+1)
			if err != nil {
				return nil, fmt.Errorf("reading NetTrace field %d object: %w", i, err)
			}
		} else if field.Type < netTraceTypeBoolean || field.Type > netTraceTypeString {
			return nil, fmt.Errorf("unsupported NetTrace field type: %d", field.Type)
		}
		var err error
		field.Name, err = readNetTraceString(reader)
		if err != nil {
			return nil, fmt.Errorf("reading NetTrace field %d name: %w", i, err)
		}
	}
	return fields, nil
}

// readNetTraceMetadataHeader reads the .NET event identity associated with a
// metadata ID, leaving the reader at the event's field definitions.
func readNetTraceMetadataHeader(reader *bytes.Reader) (netTraceMetadataHeader, error) {
	var header netTraceMetadataHeader
	if err := binary.Read(reader, binary.LittleEndian, &header.MetadataID); err != nil {
		return netTraceMetadataHeader{}, fmt.Errorf("reading NetTrace metadata ID: %w", err)
	}
	if header.MetadataID == 0 {
		return netTraceMetadataHeader{}, errors.New("NetTrace metadata ID zero is reserved")
	}
	var err error
	header.ProviderName, err = readNetTraceString(reader)
	if err != nil {
		return netTraceMetadataHeader{}, fmt.Errorf("reading NetTrace provider name: %w", err)
	}
	if err := binary.Read(reader, binary.LittleEndian, &header.EventID); err != nil {
		return netTraceMetadataHeader{}, fmt.Errorf("reading NetTrace event ID: %w", err)
	}
	header.EventName, err = readNetTraceString(reader)
	if err != nil {
		return netTraceMetadataHeader{}, fmt.Errorf("reading NetTrace event name: %w", err)
	}
	var attributes netTraceEventAttributes
	if err := binary.Read(reader, binary.LittleEndian, &attributes); err != nil {
		return netTraceMetadataHeader{}, fmt.Errorf("reading NetTrace event attributes: %w", err)
	}
	header.Keywords = attributes.Keywords
	header.Version = attributes.Version
	header.Level = attributes.Level
	return header, nil
}

// readNetTraceString reads a null-terminated UTF-16LE string. The reader must be
// bounded to the current event payload so a missing terminator cannot cross events.
func readNetTraceString(reader *bytes.Reader) (string, error) {
	var result strings.Builder
	for {
		var unit uint16
		if err := binary.Read(reader, binary.LittleEndian, &unit); err != nil {
			return "", fmt.Errorf("reading NetTrace string: %w", err)
		}
		if unit == 0 {
			return result.String(), nil
		}
		character := rune(unit)
		if utf16.IsSurrogate(character) {
			var following uint16
			if err := binary.Read(reader, binary.LittleEndian, &following); err != nil {
				return "", fmt.Errorf("reading NetTrace surrogate pair: %w", err)
			}
			character = utf16.DecodeRune(character, rune(following))
			if character == unicode.ReplacementChar {
				return "", errors.New("NetTrace string contains an unpaired UTF-16 surrogate")
			}
		}
		result.WriteRune(character)
	}
}
