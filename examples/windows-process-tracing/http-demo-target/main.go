// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

const (
	defaultPort       = 18080
	defaultStatusCode = http.StatusNoContent
	maxLatency        = 5 * time.Second
)

type options struct {
	port       int
	statusCode int
	latency    time.Duration
}

func main() {
	opts, err := optionsFromEnvironment()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	listener, err := net.Listen(
		"tcp4",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(opts.port)),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Printf(
		"obi-windows-http-demo-target.exe PID=%d PORT=%d STATUS=%d LATENCY_MS=%d\n",
		os.Getpid(),
		opts.port,
		opts.statusCode,
		opts.latency.Milliseconds(),
	)
	connection, err := listener.Accept()
	if err != nil {
		fmt.Fprintf(os.Stderr, "accept: %v\n", err)
		os.Exit(1)
	}
	defer connection.Close()

	request, err := http.ReadRequest(bufio.NewReader(connection))
	if err != nil {
		fmt.Fprintf(os.Stderr, "read request: %v\n", err)
		os.Exit(1)
	}
	_ = request.Body.Close()

	time.Sleep(opts.latency)
	response := fmt.Sprintf(
		"HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		opts.statusCode,
		http.StatusText(opts.statusCode),
	)
	if _, err := connection.Write([]byte(response)); err != nil {
		fmt.Fprintf(os.Stderr, "write response: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf(
		"served %s %s status=%d latency_ms=%d\n",
		request.Method,
		request.URL.RequestURI(),
		opts.statusCode,
		opts.latency.Milliseconds(),
	)
}

func optionsFromEnvironment() (options, error) {
	port, err := integerEnvironment("OBI_WINDOWS_HTTP_PORT", defaultPort)
	if err != nil || port < 1 || port > 65535 {
		return options{}, fmt.Errorf(
			"invalid OBI_WINDOWS_HTTP_PORT %q",
			os.Getenv("OBI_WINDOWS_HTTP_PORT"),
		)
	}

	statusCode, err := integerEnvironment(
		"OBI_WINDOWS_HTTP_STATUS",
		defaultStatusCode,
	)
	if err != nil || statusCode < 200 || statusCode > 599 {
		return options{}, fmt.Errorf(
			"invalid OBI_WINDOWS_HTTP_STATUS %q",
			os.Getenv("OBI_WINDOWS_HTTP_STATUS"),
		)
	}

	latencyMilliseconds, err := integerEnvironment(
		"OBI_WINDOWS_HTTP_LATENCY_MS",
		0,
	)
	maxLatencyMilliseconds := int(maxLatency / time.Millisecond)
	if err != nil || latencyMilliseconds < 0 ||
		latencyMilliseconds > maxLatencyMilliseconds {
		return options{}, fmt.Errorf(
			"invalid OBI_WINDOWS_HTTP_LATENCY_MS %q",
			os.Getenv("OBI_WINDOWS_HTTP_LATENCY_MS"),
		)
	}

	return options{
		port:       port,
		statusCode: statusCode,
		latency:    time.Duration(latencyMilliseconds) * time.Millisecond,
	}, nil
}

func integerEnvironment(name string, fallback int) (int, error) {
	value := os.Getenv(name)
	if value == "" {
		return fallback, nil
	}
	return strconv.Atoi(value)
}
