// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/obi/pkg/internal/dotnet"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// readNetTraceValues decodes the types used by .NET System.Runtime counters.
// Fields must come from readNetTraceFields, which bounds their count and nesting.
func readNetTraceValues(reader *bytes.Reader, fields []netTraceField) (map[string]any, error) {
	values := make(map[string]any, len(fields))
	for _, field := range fields {
		if _, exists := values[field.Name]; exists {
			return nil, fmt.Errorf("duplicate NetTrace field name: %q", field.Name)
		}
		var value any
		var err error
		switch field.Type {
		case netTraceTypeObject:
			value, err = readNetTraceValues(reader, field.Fields)
		case netTraceTypeArray:
			value, err = readNetTraceArray(reader, field.Element)
		case netTraceTypeString:
			value, err = readNetTraceString(reader)
		case netTraceTypeInt32:
			var number int32
			err = binary.Read(reader, binary.LittleEndian, &number)
			value = number
		case netTraceTypeSingle:
			var number float32
			err = binary.Read(reader, binary.LittleEndian, &number)
			value = number
		case netTraceTypeDouble:
			var number float64
			err = binary.Read(reader, binary.LittleEndian, &number)
			value = number
		default:
			return nil, fmt.Errorf("unsupported NetTrace value type: %d", field.Type)
		}
		if err != nil {
			return nil, fmt.Errorf("reading NetTrace field %q: %w", field.Name, err)
		}
		values[field.Name] = value
	}
	return values, nil
}

// DiagnosticSource arguments are a counted array of string key/value pairs.
func readNetTraceArray(reader *bytes.Reader, element *netTraceField) ([]any, error) {
	if element == nil || element.Type != netTraceTypeObject || len(element.Fields) != 2 ||
		element.Fields[0].Name != "Key" || element.Fields[0].Type != netTraceTypeString ||
		element.Fields[1].Name != "Value" || element.Fields[1].Type != netTraceTypeString {
		return nil, errors.New("unsupported NetTrace array element type")
	}
	var count uint16
	if err := binary.Read(reader, binary.LittleEndian, &count); err != nil {
		return nil, err
	}
	minimum := binary.Size(uint16(0)) * len(element.Fields)
	if count > maximumNetTraceFields || int(count) > reader.Len()/minimum {
		return nil, fmt.Errorf("invalid NetTrace array element count: %d", count)
	}
	items := make([]any, count)
	for i := range items {
		values, err := readNetTraceValues(reader, element.Fields)
		if err != nil {
			return nil, err
		}
		items[i] = values
	}
	return items, nil
}
