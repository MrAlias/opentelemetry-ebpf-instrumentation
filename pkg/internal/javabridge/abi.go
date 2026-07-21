// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package javabridge // import "go.opentelemetry.io/obi/pkg/internal/javabridge"

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	Version         = uint16(1)
	RequestVersion  = uint16(2)
	RecordSize      = uint16(64)
	RequestSize     = uint16(24)
	TraceIDSize     = 16
	SpanIDSize      = 8
	SocketLevel     = 0x4f42
	SocketTake      = 0x4a01
	SocketDiscard   = 0x4a02
	SocketNegotiate = 0x4a03
	SocketDataAck   = 0x4a04
	SocketHealth    = 0x4a05
)

func (o Operation) String() string {
	switch o {
	case OperationTake:
		return "take"
	case OperationDiscard:
		return "discard"
	case OperationNegotiate:
		return "negotiate"
	default:
		return "unknown"
	}
}

var (
	recordMagic        = [4]byte{'O', 'B', 'I', 'J'}
	requestMagic       = [4]byte{'O', 'B', 'I', 'Q'}
	ErrVersionMismatch = errors.New("java bridge ABI version mismatch")
)

type Status uint8

const (
	StatusUnknown Status = iota
	StatusValid
	StatusMissing
	StatusStale
	StatusUnsupported
	StatusMalformed
	StatusVersionMismatch
	StatusAmbiguous
	StatusUnauthorized
	StatusAlreadyConsumed
	StatusTimeout
	StatusOverload
	StatusTransportError
	StatusDisabled
)

func (s Status) String() string {
	switch s {
	case StatusValid:
		return "valid"
	case StatusMissing:
		return "missing"
	case StatusStale:
		return "stale"
	case StatusUnsupported:
		return "unsupported"
	case StatusMalformed:
		return "malformed"
	case StatusVersionMismatch:
		return "version_mismatch"
	case StatusAmbiguous:
		return "ambiguous"
	case StatusUnauthorized:
		return "unauthorized"
	case StatusAlreadyConsumed:
		return "already_consumed"
	case StatusTimeout:
		return "timeout"
	case StatusOverload:
		return "overload"
	case StatusTransportError:
		return "transport_error"
	case StatusDisabled:
		return "disabled"
	default:
		return "unknown"
	}
}

type Operation uint8

const (
	OperationTake Operation = iota + 1
	OperationDiscard
	OperationNegotiate
)

type Record struct {
	Status              Status
	Flags               byte
	TraceID             [TraceIDSize]byte
	SpanID              [SpanIDSize]byte
	Generation          uint64
	ObservedMonotonicNS uint64
}

func (r Record) MarshalBinary() ([]byte, error) {
	if r.Status < StatusValid || r.Status > StatusDisabled {
		return nil, fmt.Errorf("unknown Java bridge status %d", r.Status)
	}

	buf := make([]byte, RecordSize)
	copy(buf[0:4], recordMagic[:])
	binary.LittleEndian.PutUint16(buf[4:6], Version)
	binary.LittleEndian.PutUint16(buf[6:8], RecordSize)
	buf[8] = byte(r.Status)
	buf[9] = r.Flags
	copy(buf[16:32], r.TraceID[:])
	copy(buf[32:40], r.SpanID[:])
	binary.LittleEndian.PutUint64(buf[40:48], r.Generation)
	binary.LittleEndian.PutUint64(buf[48:56], r.ObservedMonotonicNS)

	return buf, nil
}

func UnmarshalRecord(buf []byte) (Record, error) {
	if len(buf) != int(RecordSize) {
		return Record{}, fmt.Errorf("invalid Java bridge record size %d", len(buf))
	}
	if [4]byte(buf[0:4]) != recordMagic {
		return Record{}, errors.New("java bridge record has invalid magic")
	}
	if version := binary.LittleEndian.Uint16(buf[4:6]); version != Version {
		return Record{}, fmt.Errorf("%w: record version %d", ErrVersionMismatch, version)
	}
	if size := binary.LittleEndian.Uint16(buf[6:8]); size != RecordSize {
		return Record{}, fmt.Errorf("invalid Java bridge record size %d", size)
	}
	if !allZero(buf[10:16]) || !allZero(buf[56:64]) {
		return Record{}, errors.New("java bridge record has nonzero reserved bytes")
	}

	status := Status(buf[8])
	if status < StatusValid || status > StatusDisabled {
		return Record{}, fmt.Errorf("unknown Java bridge status %d", status)
	}

	record := Record{
		Status:              status,
		Flags:               buf[9],
		Generation:          binary.LittleEndian.Uint64(buf[40:48]),
		ObservedMonotonicNS: binary.LittleEndian.Uint64(buf[48:56]),
	}
	copy(record.TraceID[:], buf[16:32])
	copy(record.SpanID[:], buf[32:40])

	return record, nil
}

func (r Record) IsValidRemoteParent() bool {
	return r.Status == StatusValid && !allZero(r.TraceID[:]) && !allZero(r.SpanID[:])
}

type Request struct {
	Operation          Operation
	NamespaceTID       uint32
	ProcessIncarnation uint64
}

func (r Request) MarshalBinary() ([]byte, error) {
	if r.Operation < OperationTake || r.Operation > OperationNegotiate {
		return nil, fmt.Errorf("unknown Java bridge operation %d", r.Operation)
	}

	buf := make([]byte, RequestSize)
	copy(buf[0:4], requestMagic[:])
	binary.LittleEndian.PutUint16(buf[4:6], RequestVersion)
	binary.LittleEndian.PutUint16(buf[6:8], RequestSize)
	buf[8] = byte(r.Operation)
	binary.LittleEndian.PutUint32(buf[12:16], r.NamespaceTID)
	binary.LittleEndian.PutUint64(buf[16:24], r.ProcessIncarnation)

	return buf, nil
}

func UnmarshalRequest(buf []byte) (Request, error) {
	if len(buf) != int(RequestSize) {
		return Request{}, fmt.Errorf("invalid Java bridge request size %d", len(buf))
	}
	if [4]byte(buf[0:4]) != requestMagic {
		return Request{}, errors.New("java bridge request has invalid magic")
	}
	if version := binary.LittleEndian.Uint16(buf[4:6]); version != RequestVersion {
		return Request{}, fmt.Errorf("%w: request version %d", ErrVersionMismatch, version)
	}
	if size := binary.LittleEndian.Uint16(buf[6:8]); size != RequestSize {
		return Request{}, fmt.Errorf("invalid Java bridge request record size %d", size)
	}
	if !allZero(buf[9:12]) {
		return Request{}, errors.New("java bridge request has nonzero reserved bytes")
	}

	operation := Operation(buf[8])
	if operation < OperationTake || operation > OperationNegotiate {
		return Request{}, fmt.Errorf("unknown Java bridge operation %d", operation)
	}

	return Request{
		Operation:          operation,
		NamespaceTID:       binary.LittleEndian.Uint32(buf[12:16]),
		ProcessIncarnation: binary.LittleEndian.Uint64(buf[16:24]),
	}, nil
}

func allZero(buf []byte) bool {
	for _, value := range buf {
		if value != 0 {
			return false
		}
	}

	return true
}
