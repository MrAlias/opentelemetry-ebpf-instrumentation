// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	defaultSocketPath  = "/var/run/obi/java-remote-parent.sock"
	requestSize        = 24
	recordSize         = 64
	requestVersion     = uint16(2)
	recordVersion      = uint16(1)
	operationTake      = byte(1)
	statusValid        = byte(1)
	statusMalformed    = byte(5)
	statusMismatch     = byte(6)
	statusUnauthorized = byte(8)
	statusTimeout      = byte(10)
	statusOverload     = byte(11)
	obiSocketLevel     = 0x4f42
	obiTakeOption      = 0x4a01
	obiNegotiateOption = 0x4a03
	obiUnrelatedOption = 0x4aff
	requestDeadline    = 750 * time.Millisecond
	probeTimeout       = 60 * time.Second
	maxProbeTimeout    = time.Hour
	primaryInterval    = time.Millisecond
	javaProcessPID     = 1
	maxKernelFD        = (1 << 31) - 1
	maxNamespaceTID    = uint64(1<<32 - 1)
	heldConnections    = 48
	repeatedAttempts   = 16
	oversizedBytes     = 4096
	payloadCanary      = "OBI_SECURITY_PROBE_PAYLOAD_CANARY"
	endpointSentinel   = "obi-security-probe-endpoint-sentinel\n"
)

type probeCase struct {
	Name    string `json:"name"`
	Outcome string `json:"outcome"`
}

type probeResult struct {
	Status   string      `json:"status"`
	Mode     string      `json:"mode"`
	Attempts uint64      `json:"attempts,omitempty"`
	Cases    []probeCase `json:"cases"`
}

type abuseIdentityRequest struct {
	name    string
	payload []byte
}

func main() {
	os.Exit(mainExitCode(os.Args[1:], os.Stdout, os.Stderr))
}

func mainExitCode(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("security-probe", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var socketPath string
	var mode string
	var timeout time.Duration
	var targetFD int
	var forgedTID int64
	flags.StringVar(&socketPath, "socket", defaultSocketPath, "Unix socket path")
	flags.StringVar(&mode, "mode", "abuse", "probe mode: abuse, abuse-race, endpoint, primary, or primary-live-fd")
	flags.DurationVar(&timeout, "timeout", probeTimeout, "overall probe timeout")
	flags.IntVar(&targetFD, "fd", -1, "live Java socket descriptor for primary-live-fd mode")
	flags.Int64Var(&forgedTID, "forged-tid", -1, "forged namespace thread ID for abuse modes")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "security probe requires no positional arguments")
		return 2
	}
	if mode != "abuse" && mode != "abuse-race" && mode != "endpoint" && mode != "primary" && mode != "primary-live-fd" {
		fmt.Fprintf(stderr, "security probe mode %q is unsupported\n", mode)
		return 2
	}
	if mode != "primary-live-fd" && !filepath.IsAbs(socketPath) {
		fmt.Fprintln(stderr, "security probe requires an absolute --socket")
		return 2
	}
	if mode == "primary-live-fd" && (targetFD < 0 || targetFD > maxKernelFD) {
		fmt.Fprintln(stderr, "primary-live-fd requires a --fd in the kernel descriptor range")
		return 2
	}
	if forgedTID != -1 && (forgedTID < 1 || uint64(forgedTID) > maxNamespaceTID) {
		fmt.Fprintln(stderr, "--forged-tid must be a positive 32-bit thread ID")
		return 2
	}
	if forgedTID != -1 && mode != "abuse" && mode != "abuse-race" {
		fmt.Fprintln(stderr, "--forged-tid is only supported by abuse modes")
		return 2
	}
	if timeout < time.Second || timeout > maxProbeTimeout {
		fmt.Fprintln(stderr, "security probe timeout must be between 1s and 1h")
		return 2
	}

	baseCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(baseCtx, timeout)
	defer cancel()

	var forgedLiveTID *uint32
	if forgedTID != -1 {
		value := uint32(forgedTID)
		forgedLiveTID = &value
	}

	var (
		result probeResult
		err    error
	)
	switch mode {
	case "abuse":
		result, err = runAbuseProbe(ctx, socketPath, forgedLiveTID)
	case "abuse-race":
		resume := make(chan os.Signal, 1)
		signal.Notify(resume, syscall.SIGUSR1)
		defer signal.Stop(resume)
		result, err = runAbuseRaceProbe(ctx, socketPath, forgedLiveTID, resume, func() {
			fmt.Fprintln(stdout, "security probe abuse race ready")
		})
	case "endpoint":
		resume := make(chan os.Signal, 1)
		signal.Notify(resume, syscall.SIGUSR1)
		defer signal.Stop(resume)
		result, err = runEndpointProbe(ctx, socketPath, resume, func() {
			fmt.Fprintln(stdout, "security probe replacement ready")
		})
	case "primary":
		resume := make(chan os.Signal, 1)
		signal.Notify(resume, syscall.SIGUSR1)
		defer signal.Stop(resume)
		result, err = runPrimaryProbe(ctx, resume, func() {
			fmt.Fprintln(stdout, "security probe primary ready")
		})
	case "primary-live-fd":
		result, err = runPrimaryLiveFDProbe(ctx, targetFD)
	}
	if err != nil {
		fmt.Fprintf(stderr, "security probe failed: %v\n", err)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		fmt.Fprintf(stderr, "encode security probe result: %v\n", err)
		return 1
	}
	return 0
}

func runPrimaryLiveFDProbe(ctx context.Context, targetFD int) (probeResult, error) {
	return runPrimaryLiveFDProbeWithDuplicator(ctx, targetFD, duplicateProcessFD)
}

func runPrimaryLiveFDProbeWithDuplicator(
	ctx context.Context,
	targetFD int,
	duplicate func(int, int) (*os.File, error),
) (probeResult, error) {
	if err := ctx.Err(); err != nil {
		return probeResult{}, err
	}

	socket, err := duplicate(javaProcessPID, targetFD)
	if err != nil {
		if pidfdDuplicationUnavailable(err) {
			return probeResult{
				Status: "unsupported",
				Mode:   "primary-live-fd",
				Cases: []probeCase{{
					Name: "pidfd-duplicate", Outcome: "unavailable",
				}},
			}, nil
		}
		return probeResult{}, fmt.Errorf("duplicate Java live socket descriptor: %w", err)
	}
	defer socket.Close()

	raw, err := socket.SyscallConn()
	if err != nil {
		return probeResult{}, fmt.Errorf("access duplicated Java socket: %w", err)
	}
	result, err := exercisePrimaryLiveFDProbe(ctx, raw)
	if err != nil {
		return probeResult{}, err
	}
	result.Cases = append([]probeCase{{
		Name: "pidfd-duplicate", Outcome: "opened",
	}}, result.Cases...)
	return result, nil
}

func pidfdDuplicationUnavailable(err error) bool {
	return errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES)
}

func duplicateProcessFD(pid, targetFD int) (*os.File, error) {
	if pid <= 0 {
		return nil, errors.New("process identifier must be positive")
	}
	if targetFD < 0 || targetFD > maxKernelFD {
		return nil, errors.New("descriptor is outside the kernel range")
	}

	pidFD, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, fmt.Errorf("open process handle: %w", err)
	}
	defer func() { _ = unix.Close(pidFD) }()

	duplicatedFD, err := unix.PidfdGetfd(pidFD, targetFD, 0)
	if err != nil {
		return nil, fmt.Errorf("duplicate process descriptor: %w", err)
	}
	file := os.NewFile(uintptr(duplicatedFD), "pidfd-duplicate")
	if file == nil {
		_ = unix.Close(duplicatedFD)
		return nil, errors.New("wrap duplicated process descriptor")
	}
	return file, nil
}

func exercisePrimaryLiveFDProbe(ctx context.Context, raw syscall.RawConn) (probeResult, error) {
	result := probeResult{Status: "unverified", Mode: "primary-live-fd", Attempts: 1}

	socketType := make([]byte, 4)
	length, err := rawGetsockopt(raw, unix.SOL_SOCKET, unix.SO_TYPE, socketType)
	if err != nil {
		return probeResult{}, fmt.Errorf("read duplicated socket type: %w", err)
	}
	if length != uint32(len(socketType)) ||
		binary.NativeEndian.Uint32(socketType) != unix.SOCK_STREAM {
		return probeResult{}, errors.New("duplicated descriptor was not a stream socket")
	}
	result.Cases = append(result.Cases, probeCase{
		Name: "standard-option", Outcome: "preserved",
	})

	if err := ctx.Err(); err != nil {
		return probeResult{}, err
	}
	invalidCapability := make([]byte, 8)
	if err := rawSetsockopt(raw, obiSocketLevel, obiNegotiateOption, invalidCapability); !isUnsupportedSockopt(err) {
		return probeResult{}, fmt.Errorf("wrong-process negotiation: expected unsupported error, got %w", err)
	}
	result.Cases = append(result.Cases, probeCase{
		Name: "wrong-process-negotiation", Outcome: "native-unsupported",
	})

	if err := ctx.Err(); err != nil {
		return probeResult{}, err
	}
	outcome, err := safeTakeAttempt(raw, recordSize)
	if err != nil {
		return probeResult{}, fmt.Errorf("exact live descriptor retrieval: %w", err)
	}
	if outcome != "native-unsupported" {
		return probeResult{}, fmt.Errorf("exact live descriptor retrieval: expected native unsupported result, got %s", outcome)
	}
	result.Cases = append(result.Cases, probeCase{
		Name: "duplicated-fd-take", Outcome: outcome,
	})
	return result, nil
}

func runPrimaryProbe(
	ctx context.Context,
	resume <-chan os.Signal,
	ready func(),
) (probeResult, error) {
	client, server, err := connectedTCPPair()
	if err != nil {
		return probeResult{}, err
	}
	defer client.Close()
	defer server.Close()

	raw, err := client.SyscallConn()
	if err != nil {
		return probeResult{}, fmt.Errorf("access probe socket: %w", err)
	}
	result := probeResult{Status: "unverified", Mode: "primary"}

	socketType := make([]byte, 4)
	length, err := rawGetsockopt(raw, unix.SOL_SOCKET, unix.SO_TYPE, socketType)
	if err != nil {
		return probeResult{}, fmt.Errorf("read standard socket option: %w", err)
	}
	if length != uint32(len(socketType)) ||
		binary.NativeEndian.Uint32(socketType) != unix.SOCK_STREAM {
		return probeResult{}, errors.New("standard socket option was not preserved")
	}
	result.Cases = append(result.Cases, probeCase{
		Name: "standard-option", Outcome: "preserved",
	})

	if _, err := rawGetsockopt(
		raw, obiSocketLevel, obiUnrelatedOption, make([]byte, recordSize),
	); !isUnsupportedSockopt(err) {
		return probeResult{}, fmt.Errorf("same-level unrelated option: expected unsupported error, got %w", err)
	}
	result.Cases = append(result.Cases, probeCase{
		Name: "unrelated-name", Outcome: "not-intercepted",
	})

	if _, err := rawGetsockopt(
		raw, obiSocketLevel+1, obiTakeOption, make([]byte, recordSize),
	); !isUnsupportedSockopt(err) {
		return probeResult{}, fmt.Errorf("unrelated-level take option: expected unsupported error, got %w", err)
	}
	result.Cases = append(result.Cases, probeCase{
		Name: "unrelated-level", Outcome: "not-intercepted",
	})

	incarnation := make([]byte, 8)
	binary.LittleEndian.PutUint64(incarnation, 0x5ec0000000000001)
	if err := rawSetsockopt(raw, obiSocketLevel, obiNegotiateOption, incarnation); !isUnsupportedSockopt(err) {
		return probeResult{}, fmt.Errorf("wrong-process negotiation: expected unsupported error, got %w", err)
	}
	result.Cases = append(result.Cases, probeCase{
		Name: "wrong-process-negotiation", Outcome: "native-unsupported",
	})

	for _, size := range []int{0, 1, recordSize - 1, recordSize + 1} {
		if _, err := safeTakeAttempt(raw, size); err != nil {
			return probeResult{}, fmt.Errorf("retrieval size %d: %w", size, err)
		}
	}
	result.Cases = append(result.Cases, probeCase{
		Name: "retrieval-sizes", Outcome: "bounded",
	})

	retrievalOutcome, err := safeTakeAttempt(raw, recordSize)
	if err != nil {
		return probeResult{}, fmt.Errorf("initial repeated retrieval attempt: %w", err)
	}
	result.Attempts++
	ready()
	ticker := time.NewTicker(primaryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return probeResult{}, fmt.Errorf("wait for legitimate traffic: %w", ctx.Err())
		case <-resume:
			if result.Attempts == 0 {
				return probeResult{}, errors.New("primary probe made no repeated retrieval attempts")
			}
			result.Cases = append(result.Cases, probeCase{
				Name: "repeated-retrieval", Outcome: retrievalOutcome,
			})
			return result, nil
		case <-ticker.C:
			outcome, err := safeTakeAttempt(raw, recordSize)
			if err != nil {
				return probeResult{}, fmt.Errorf("repeated retrieval attempt: %w", err)
			}
			if outcome != retrievalOutcome {
				return probeResult{}, fmt.Errorf(
					"repeated retrieval result changed from %s to %s",
					retrievalOutcome,
					outcome,
				)
			}
			result.Attempts++
		}
	}
}

func connectedTCPPair() (*net.TCPConn, *net.TCPConn, error) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, nil, fmt.Errorf("listen on probe loopback socket: %w", err)
	}
	defer listener.Close()

	accepted := make(chan struct {
		connection *net.TCPConn
		err        error
	}, 1)
	go func() {
		connection, acceptErr := listener.AcceptTCP()
		accepted <- struct {
			connection *net.TCPConn
			err        error
		}{connection: connection, err: acceptErr}
	}()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		return nil, nil, fmt.Errorf("connect probe loopback socket: %w", err)
	}
	server := <-accepted
	if server.err != nil {
		_ = client.Close()
		return nil, nil, fmt.Errorf("accept probe loopback socket: %w", server.err)
	}
	return client, server.connection, nil
}

func safeTakeAttempt(raw syscall.RawConn, size int) (string, error) {
	response := make([]byte, size)
	length, err := rawGetsockopt(raw, obiSocketLevel, obiTakeOption, response)
	if isUnsupportedSockopt(err) {
		return "native-unsupported", nil
	}
	if err != nil {
		return "", err
	}
	if length != recordSize || length > uint32(len(response)) {
		return "", fmt.Errorf("unexpected successful response size %d", length)
	}
	status, err := readStatus(bytes.NewReader(response[:length]))
	if err != nil {
		return "", err
	}
	if status == statusValid {
		return "", errors.New("retrieval disclosed a remote parent")
	}
	return statusName(status), nil
}

func isUnsupportedSockopt(err error) bool {
	return errors.Is(err, unix.ENOPROTOOPT) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.ENOSYS)
}

func rawGetsockopt(
	raw syscall.RawConn,
	level int,
	option int,
	value []byte,
) (uint32, error) {
	length := uint32(len(value))
	var valuePointer unsafe.Pointer
	if len(value) != 0 {
		valuePointer = unsafe.Pointer(&value[0])
	}
	var callErr error
	controlErr := raw.Control(func(fd uintptr) {
		_, _, errno := unix.Syscall6(
			unix.SYS_GETSOCKOPT,
			fd,
			uintptr(level),
			uintptr(option),
			uintptr(valuePointer),
			uintptr(unsafe.Pointer(&length)),
			0,
		)
		if errno != 0 {
			callErr = errno
		}
	})
	if controlErr != nil {
		return 0, controlErr
	}
	return length, callErr
}

func rawSetsockopt(raw syscall.RawConn, level int, option int, value []byte) error {
	var valuePointer unsafe.Pointer
	if len(value) != 0 {
		valuePointer = unsafe.Pointer(&value[0])
	}
	var callErr error
	controlErr := raw.Control(func(fd uintptr) {
		_, _, errno := unix.Syscall6(
			unix.SYS_SETSOCKOPT,
			fd,
			uintptr(level),
			uintptr(option),
			uintptr(valuePointer),
			uintptr(len(value)),
			0,
		)
		if errno != 0 {
			callErr = errno
		}
	})
	if controlErr != nil {
		return controlErr
	}
	return callErr
}

func abuseIdentityRequests(peerTID uint32, forgedLiveTID *uint32) []abuseIdentityRequest {
	requests := []abuseIdentityRequest{
		{
			name:    "peer-identity",
			payload: marshalRequest(peerTID, 0x5ec0000000000001),
		},
		{
			name:    "forged-identity",
			payload: marshalRequest(^uint32(0), 0x5ec0000000000001),
		},
	}
	if forgedLiveTID != nil {
		requests = append(requests, abuseIdentityRequest{
			name:    "forged-live-java-tid",
			payload: marshalRequest(*forgedLiveTID, 0x5ec0000000000001),
		})
	}
	return requests
}

func runAbuseProbe(
	ctx context.Context,
	socketPath string,
	forgedLiveTID *uint32,
) (probeResult, error) {
	result := probeResult{Status: "passed", Mode: "abuse"}
	run := func(name string, probe func() (string, error)) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		outcome, err := probe()
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		result.Cases = append(result.Cases, probeCase{Name: name, Outcome: outcome})
		return nil
	}

	identityRequests := abuseIdentityRequests(uint32(syscall.Gettid()), forgedLiveTID)
	request := identityRequests[0].payload
	for _, identityRequest := range identityRequests {
		identityRequest := identityRequest
		if err := run(identityRequest.name, func() (string, error) {
			return expectRoundTripStatus(socketPath, identityRequest.payload, statusUnauthorized)
		}); err != nil {
			return probeResult{}, err
		}
	}
	if err := run("malformed", func() (string, error) {
		return expectRoundTripStatus(socketPath, make([]byte, requestSize), statusMalformed)
	}); err != nil {
		return probeResult{}, err
	}
	if err := run("truncated", func() (string, error) {
		return expectPartialStatus(socketPath, request[:requestSize-1], statusMalformed)
	}); err != nil {
		return probeResult{}, err
	}
	if err := run("version-mismatch", func() (string, error) {
		mismatched := append([]byte(nil), request...)
		binary.LittleEndian.PutUint16(mismatched[4:6], requestVersion+1)
		return expectRoundTripStatus(socketPath, mismatched, statusMismatch)
	}); err != nil {
		return probeResult{}, err
	}
	if err := run("oversized", func() (string, error) {
		payload := append([]byte(nil), request...)
		payload = append(payload, bytes.Repeat([]byte(payloadCanary), oversizedBytes/len(payloadCanary)+1)...)
		payload = payload[:requestSize+oversizedBytes]
		return expectSingleResponse(socketPath, payload, statusUnauthorized)
	}); err != nil {
		return probeResult{}, err
	}
	if err := run("repeated-frame", func() (string, error) {
		payload := append(append([]byte(nil), request...), request...)
		return expectSingleResponse(socketPath, payload, statusUnauthorized)
	}); err != nil {
		return probeResult{}, err
	}
	if err := run("repeated-unauthorized", func() (string, error) {
		for range repeatedAttempts {
			if _, err := expectRoundTripStatus(socketPath, request, statusUnauthorized); err != nil {
				return "", err
			}
		}
		return "bounded", nil
	}); err != nil {
		return probeResult{}, err
	}
	if err := run("high-rate-admission", func() (string, error) {
		return saturateAdmission(socketPath)
	}); err != nil {
		return probeResult{}, err
	}

	return result, nil
}

func runAbuseRaceProbe(
	ctx context.Context,
	socketPath string,
	forgedLiveTID *uint32,
	resume <-chan os.Signal,
	ready func(),
) (probeResult, error) {
	result, err := runAbuseProbe(ctx, socketPath, forgedLiveTID)
	if err != nil {
		return probeResult{}, err
	}
	result.Mode = "abuse-race"
	attempts, err := runUnauthorizedRace(ctx, resume, ready, func() error {
		request := marshalRequest(uint32(syscall.Gettid()), 0x5ec0000000000001)
		_, attemptErr := expectRoundTripStatus(socketPath, request, statusUnauthorized)
		return attemptErr
	})
	if err != nil {
		return probeResult{}, err
	}
	result.Attempts = attempts
	result.Cases = append(result.Cases, probeCase{
		Name: "concurrent-repeated-unauthorized", Outcome: "bounded",
	})
	return result, nil
}

func runUnauthorizedRace(
	ctx context.Context,
	resume <-chan os.Signal,
	ready func(),
	attempt func() error,
) (uint64, error) {
	if err := attempt(); err != nil {
		return 0, err
	}
	attempts := uint64(1)
	ready()
	ticker := time.NewTicker(primaryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("wait for legitimate traffic: %w", ctx.Err())
		case <-resume:
			return attempts, nil
		case <-ticker.C:
			if err := attempt(); err != nil {
				return 0, err
			}
			attempts++
		}
	}
}

func runEndpointProbe(
	ctx context.Context,
	socketPath string,
	resume <-chan os.Signal,
	ready func(),
) (probeResult, error) {
	oldConnection, err := dial(socketPath)
	if err != nil {
		return probeResult{}, fmt.Errorf("connect old endpoint: %w", err)
	}
	defer oldConnection.Close()

	if err := os.Remove(socketPath); err != nil {
		return probeResult{}, fmt.Errorf("unlink live endpoint: %w", err)
	}
	if err := os.WriteFile(socketPath, []byte(endpointSentinel), 0o600); err != nil {
		return probeResult{}, fmt.Errorf("install endpoint sentinel: %w", err)
	}
	sentinelInfo, err := os.Lstat(socketPath)
	if err != nil {
		return probeResult{}, fmt.Errorf("inspect endpoint sentinel: %w", err)
	}
	defer func() { _ = removeSentinelIfSame(socketPath, sentinelInfo) }()

	unexpected, dialErr := net.DialTimeout("unix", socketPath, 100*time.Millisecond)
	if dialErr == nil {
		_ = unexpected.Close()
		return probeResult{}, errors.New("replacement path accepted a new Unix connection")
	}
	ready()

	select {
	case <-ctx.Done():
		return probeResult{}, fmt.Errorf("wait for OBI restart: %w", ctx.Err())
	case <-resume:
	}
	contents, err := os.ReadFile(socketPath)
	if err != nil {
		return probeResult{}, fmt.Errorf("read endpoint sentinel after restart: %w", err)
	}
	if string(contents) != endpointSentinel {
		return probeResult{}, errors.New("endpoint sentinel changed during restart")
	}

	oldOutcome, err := exerciseOldConnection(oldConnection)
	if err != nil {
		return probeResult{}, err
	}
	if err := removeSentinelIfSame(socketPath, sentinelInfo); err != nil {
		return probeResult{}, err
	}

	return probeResult{
		Status: "passed",
		Mode:   "endpoint",
		Cases: []probeCase{
			{Name: "replacement-fail-closed", Outcome: "inaccessible"},
			{Name: "old-client-fd", Outcome: oldOutcome},
			{Name: "replacement-preserved", Outcome: "unchanged"},
		},
	}, nil
}

func marshalRequest(namespaceTID uint32, incarnation uint64) []byte {
	request := make([]byte, requestSize)
	copy(request[:4], "OBIQ")
	binary.LittleEndian.PutUint16(request[4:6], requestVersion)
	binary.LittleEndian.PutUint16(request[6:8], requestSize)
	request[8] = operationTake
	binary.LittleEndian.PutUint32(request[12:16], namespaceTID)
	binary.LittleEndian.PutUint64(request[16:24], incarnation)
	return request
}

func dial(socketPath string) (*net.UnixConn, error) {
	connection, err := net.DialUnix(
		"unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"},
	)
	if err != nil {
		return nil, err
	}
	if err := connection.SetDeadline(time.Now().Add(requestDeadline)); err != nil {
		_ = connection.Close()
		return nil, err
	}
	return connection, nil
}

func expectRoundTripStatus(socketPath string, payload []byte, expected byte) (string, error) {
	connection, err := dial(socketPath)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	if _, err := connection.Write(payload); err != nil {
		return "", err
	}
	status, err := readStatus(connection)
	if err != nil {
		return "", err
	}
	if status != expected {
		return "", fmt.Errorf("expected status %d, got %d", expected, status)
	}
	return statusName(status), nil
}

func expectPartialStatus(socketPath string, payload []byte, expected byte) (string, error) {
	connection, err := dial(socketPath)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	if _, err := connection.Write(payload); err != nil {
		return "", err
	}
	if err := connection.CloseWrite(); err != nil {
		return "", err
	}
	status, err := readStatus(connection)
	if err != nil {
		return "", err
	}
	if status != expected {
		return "", fmt.Errorf("expected status %d, got %d", expected, status)
	}
	return statusName(status), nil
}

func expectSingleResponse(socketPath string, payload []byte, expected byte) (string, error) {
	connection, err := dial(socketPath)
	if err != nil {
		return "", err
	}
	defer connection.Close()
	if _, err := connection.Write(payload); err != nil {
		return "", err
	}
	status, err := readStatus(connection)
	if err != nil {
		return "", err
	}
	if status != expected {
		return "", fmt.Errorf("expected status %d, got %d", expected, status)
	}
	var trailing [1]byte
	if _, err := connection.Read(trailing[:]); err == nil {
		return "", errors.New("connection accepted more than one request frame")
	} else if !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
		return "", fmt.Errorf("connection remained open after one request frame: %w", err)
	}
	return statusName(status), nil
}

func saturateAdmission(socketPath string) (string, error) {
	connections := make([]*net.UnixConn, 0, heldConnections)
	defer func() {
		for _, connection := range connections {
			_ = connection.Close()
		}
	}()
	for range heldConnections {
		connection, err := dial(socketPath)
		if err != nil {
			return "", err
		}
		connections = append(connections, connection)
	}

	overloads := 0
	closed := 0
	for _, connection := range connections {
		status, err := readStatus(connection)
		if err != nil {
			if isBoundedClose(err) {
				closed++
				continue
			}
			return "", err
		}
		if status == statusValid {
			return "", errors.New("admission saturation disclosed a remote parent")
		}
		if status == statusOverload {
			overloads++
		} else if status != statusTimeout {
			return "", fmt.Errorf("unexpected saturation status %d", status)
		}
	}
	if overloads == 0 {
		return "", errors.New("admission saturation produced no overload response")
	}
	if overloads+closed != len(connections) {
		return "", errors.New("admission saturation left an unclassified connection")
	}
	for _, connection := range connections {
		_ = connection.Close()
	}
	connections = connections[:0]

	if _, err := expectRoundTripStatus(
		socketPath, make([]byte, requestSize), statusMalformed,
	); err != nil {
		return "", fmt.Errorf("post-saturation recovery: %w", err)
	}
	return "overload-and-recovery", nil
}

func readStatus(reader io.Reader) (byte, error) {
	record := make([]byte, recordSize)
	if _, err := io.ReadFull(reader, record); err != nil {
		return 0, err
	}
	if string(record[:4]) != "OBIJ" ||
		binary.LittleEndian.Uint16(record[4:6]) != recordVersion ||
		binary.LittleEndian.Uint16(record[6:8]) != recordSize {
		return 0, errors.New("invalid Java bridge response envelope")
	}
	for _, value := range append(record[10:16:16], record[56:64]...) {
		if value != 0 {
			return 0, errors.New("java bridge response has nonzero reserved bytes")
		}
	}
	status := record[8]
	if status != statusValid {
		for _, value := range append(record[9:10:10], record[16:56]...) {
			if value != 0 {
				return 0, errors.New("java bridge denial exposed context-bearing bytes")
			}
		}
	}
	return status, nil
}

func exerciseOldConnection(connection *net.UnixConn) (string, error) {
	_ = connection.SetDeadline(time.Now().Add(requestDeadline))
	_, writeErr := connection.Write(make([]byte, requestSize))
	status, readErr := readStatus(connection)
	if readErr == nil {
		if status == statusValid {
			return "", errors.New("old client fd disclosed a remote parent")
		}
		return statusName(status), nil
	}
	if writeErr != nil || isBoundedClose(readErr) {
		return "closed", nil
	}
	return "", fmt.Errorf("read old client fd: %w", readErr)
}

func isBoundedClose(err error) bool {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func removeSentinelIfSame(path string, expected os.FileInfo) error {
	current, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect endpoint sentinel for cleanup: %w", err)
	}
	if !os.SameFile(expected, current) || !current.Mode().IsRegular() {
		return errors.New("refusing to remove a changed endpoint replacement")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read endpoint sentinel for cleanup: %w", err)
	}
	if string(contents) != endpointSentinel {
		return errors.New("refusing to remove a modified endpoint replacement")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove endpoint sentinel: %w", err)
	}
	return nil
}

func statusName(status byte) string {
	switch status {
	case statusMalformed:
		return "malformed"
	case statusMismatch:
		return "version_mismatch"
	case statusUnauthorized:
		return "unauthorized"
	case statusTimeout:
		return "timeout"
	case statusOverload:
		return "overload"
	default:
		return fmt.Sprintf("status_%d", status)
	}
}
