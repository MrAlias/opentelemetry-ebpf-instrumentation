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
)

func main() {
	port := 18080
	if value := os.Getenv("OBI_WINDOWS_HTTP_PORT"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 1 || parsed > 65535 {
			fmt.Fprintf(os.Stderr, "invalid OBI_WINDOWS_HTTP_PORT %q\n", value)
			os.Exit(2)
		}
		port = parsed
	}

	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Printf("obi-windows-http-target.exe PID=%d PORT=%d\n", os.Getpid(), port)
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

	response := "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	if _, err := connection.Write([]byte(response)); err != nil {
		fmt.Fprintf(os.Stderr, "write response: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("served %s %s status=204\n", request.Method, request.URL.RequestURI())
}
