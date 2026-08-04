// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	requestVersion   = uint16(3)
	requestSize      = 24
	recordVersion    = uint16(1)
	recordSize       = 64
	operationTake    = byte(1)
	operationDrop    = byte(2)
	operationProbe   = byte(3)
	sourceDirect     = byte(1)
	sourceTask       = byte(2)
	statusValid      = byte(1)
	statusMissing    = byte(2)
	statusStale      = byte(3)
	statusMalformed  = byte(5)
	statusOverload   = byte(11)
	requestTimeout   = 500 * time.Millisecond
	timeoutDelay     = 200 * time.Millisecond
	maxTakeRequests  = uint32(10_000)
	maxMatchingTakes = uint64(1_000)
	defaultFaultMode = "alternating"
)

type faultServer struct {
	mode               string
	matchingValidTakes uint32
	takes              atomic.Uint32
}

type faultResponse struct {
	payload []byte
	status  string
	delay   time.Duration
}

type faultRequest struct {
	operation byte
	source    byte
}

func main() {
	os.Exit(mainExitCode())
}

func mainExitCode() int {
	var socketPath string
	var mode string
	var matchingValidTakes uint64
	flag.StringVar(&socketPath, "socket", "/var/run/obi/java-remote-parent.sock", "Unix socket path")
	flag.StringVar(&mode, "mode", environmentOrDefault("FAULT_MODE", defaultFaultMode), "fault mode")
	flag.Uint64Var(&matchingValidTakes, "matching-valid-takes", 1, "valid takes returned by matching mode")
	flag.Parse()
	if flag.NArg() != 0 || !filepath.IsAbs(socketPath) {
		fmt.Fprintln(os.Stderr, "fault bridge requires an absolute --socket and no positional arguments")
		return 2
	}
	if !validFaultMode(mode) {
		fmt.Fprintf(os.Stderr, "fault bridge mode %q is unsupported\n", mode)
		return 2
	}
	if !validMatchingTakeCount(mode, matchingValidTakes) {
		fmt.Fprintf(
			os.Stderr,
			"fault bridge matching-valid-takes must be between 1 and %d in matching mode\n",
			maxMatchingTakes,
		)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx, socketPath, &faultServer{
		mode:               mode,
		matchingValidTakes: uint32(matchingValidTakes),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "fault bridge failed: %v\n", err)
		return 1
	}
	return 0
}

func serve(ctx context.Context, socketPath string, server *faultServer) error {
	if err := prepareSocketPath(socketPath); err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()
	if err := os.Chmod(socketPath, 0o660); err != nil {
		return fmt.Errorf("set socket permissions: %w", err)
	}

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-done:
		}
	}()
	defer close(done)
	fmt.Printf(
		"fault bridge ready socket=%s mode=%s matching_valid_takes=%d\n",
		socketPath,
		server.mode,
		server.matchingValidTakes,
	)

	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		if err := handle(connection, server); err != nil {
			if server.mode == "matching" {
				return fmt.Errorf("handle matching request: %w", err)
			}
			fmt.Fprintf(os.Stderr, "fault bridge request rejected: %v\n", err)
		}
	}
}

func prepareSocketPath(socketPath string) error {
	info, err := os.Lstat(socketPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect socket path: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to replace non-socket path %q", socketPath)
	}
	if err := os.Remove(socketPath); err != nil {
		return fmt.Errorf("remove stale socket: %w", err)
	}
	return nil
}

func handle(connection *net.UnixConn, server *faultServer) error {
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(requestTimeout)); err != nil {
		return err
	}
	payload := make([]byte, requestSize)
	if _, err := io.ReadFull(connection, payload); err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	request, err := parseRequest(payload)
	if err != nil {
		return err
	}
	if server.mode == "matching" && request.source != sourceDirect {
		return fmt.Errorf(
			"matching request source must be direct, got %s",
			sourceName(request.source),
		)
	}
	response := server.response(request.operation, request.source)
	fmt.Printf(
		"fault bridge operation=%s status=%s take_count=%d source=%s\n",
		operationName(request.operation),
		response.status,
		server.takes.Load(),
		sourceName(request.source),
	)
	if response.delay > 0 {
		time.Sleep(response.delay)
	}
	if len(response.payload) == 0 {
		return nil
	}
	if _, err := connection.Write(response.payload); err != nil {
		return fmt.Errorf("write response: %w", err)
	}
	return nil
}

func parseRequest(request []byte) (faultRequest, error) {
	if len(request) != requestSize || string(request[:4]) != "OBIQ" ||
		binary.LittleEndian.Uint16(request[4:6]) != requestVersion ||
		binary.LittleEndian.Uint16(request[6:8]) != requestSize {
		return faultRequest{}, errors.New("invalid request envelope")
	}
	if request[10] != 0 || request[11] != 0 ||
		binary.LittleEndian.Uint32(request[12:16]) == 0 ||
		binary.LittleEndian.Uint64(request[16:24]) == 0 {
		return faultRequest{}, errors.New("invalid request identity or reserved bytes")
	}
	switch request[9] {
	case sourceDirect, sourceTask:
	default:
		return faultRequest{}, errors.New("invalid request source")
	}
	switch request[8] {
	case operationTake, operationDrop, operationProbe:
		return faultRequest{operation: request[8], source: request[9]}, nil
	default:
		return faultRequest{}, errors.New("invalid request operation")
	}
}

func (s *faultServer) response(operation, source byte) faultResponse {
	if operation != operationTake {
		return responseWithStatus(statusMissing)
	}
	count := s.takes.Add(1)
	if count > maxTakeRequests {
		return responseWithStatus(statusOverload)
	}

	switch s.mode {
	case "matching":
		if source != sourceDirect || count == 1 || count > s.matchingValidTakes+1 {
			return responseWithStatus(statusMissing)
		}
		return faultResponse{payload: validRecord(), status: statusName(statusValid)}
	case defaultFaultMode:
		if count%2 != 0 {
			return responseWithStatus(statusStale)
		}
		return responseWithStatus(statusMalformed)
	case "timeout":
		return faultResponse{status: "timeout", delay: timeoutDelay}
	case "disconnect":
		return faultResponse{status: "disconnect"}
	case "overload":
		return responseWithStatus(statusOverload)
	case "truncated":
		return faultResponse{payload: statusRecord(statusMissing)[:recordSize/2], status: "truncated"}
	case "bad-magic":
		record := statusRecord(statusMissing)
		record[0] = 'X'
		return faultResponse{payload: record, status: "bad-magic"}
	case "bad-size":
		record := statusRecord(statusMissing)
		binary.LittleEndian.PutUint16(record[6:8], recordSize-1)
		return faultResponse{payload: record, status: "bad-size"}
	case "version-mismatch":
		record := statusRecord(statusMissing)
		binary.LittleEndian.PutUint16(record[4:6], recordVersion+1)
		return faultResponse{payload: record, status: "version-mismatch"}
	case "zero-trace-id":
		record := validRecord()
		clear(record[16:32])
		return faultResponse{payload: record, status: "zero-trace-id"}
	case "zero-span-id":
		record := validRecord()
		clear(record[32:40])
		return faultResponse{payload: record, status: "zero-span-id"}
	default:
		panic("validated fault mode became invalid")
	}
}

func responseWithStatus(status byte) faultResponse {
	return faultResponse{payload: statusRecord(status), status: statusName(status)}
}

func statusRecord(status byte) []byte {
	record := make([]byte, recordSize)
	copy(record[:4], "OBIJ")
	binary.LittleEndian.PutUint16(record[4:6], recordVersion)
	binary.LittleEndian.PutUint16(record[6:8], recordSize)
	record[8] = status
	return record
}

func validRecord() []byte {
	record := statusRecord(statusValid)
	record[9] = 1
	copy(record[16:32], []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	})
	copy(record[32:40], []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17})
	binary.LittleEndian.PutUint64(record[40:48], 0x0102030405060708)
	binary.LittleEndian.PutUint64(record[48:56], 0x1112131415161718)
	return record
}

func validFaultMode(mode string) bool {
	switch mode {
	case defaultFaultMode,
		"matching",
		"timeout",
		"disconnect",
		"overload",
		"truncated",
		"bad-magic",
		"bad-size",
		"version-mismatch",
		"zero-trace-id",
		"zero-span-id":
		return true
	default:
		return false
	}
}

func validMatchingTakeCount(mode string, count uint64) bool {
	return mode != "matching" || count >= 1 && count <= maxMatchingTakes
}

func environmentOrDefault(name, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}

func operationName(operation byte) string {
	switch operation {
	case operationTake:
		return "take"
	case operationDrop:
		return "discard"
	case operationProbe:
		return "negotiate"
	default:
		return "unknown"
	}
}

func sourceName(source byte) string {
	switch source {
	case sourceDirect:
		return "direct"
	case sourceTask:
		return "task"
	default:
		return "unknown"
	}
}

func statusName(status byte) string {
	switch status {
	case statusValid:
		return "valid"
	case statusMissing:
		return "missing"
	case statusStale:
		return "stale"
	case statusMalformed:
		return "malformed"
	case statusOverload:
		return "overload"
	default:
		return "unknown"
	}
}
