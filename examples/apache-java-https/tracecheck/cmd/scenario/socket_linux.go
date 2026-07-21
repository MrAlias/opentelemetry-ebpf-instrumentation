// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"fmt"
	"net"
	"syscall"
)

func enableAddressReuse(_ string, _ string, connection syscall.RawConn) error {
	var optionErr error
	if err := connection.Control(func(fileDescriptor uintptr) {
		optionErr = syscall.SetsockoptInt(
			int(fileDescriptor),
			syscall.SOL_SOCKET,
			syscall.SO_REUSEADDR,
			1,
		)
	}); err != nil {
		return err
	}
	return optionErr
}

func connectionFileDescriptor(connection *net.TCPConn) (int, error) {
	rawConnection, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	fileDescriptor := -1
	if err := rawConnection.Control(func(descriptor uintptr) {
		fileDescriptor = int(descriptor)
	}); err != nil {
		return 0, err
	}
	if fileDescriptor < 0 {
		return 0, fmt.Errorf("invalid TCP file descriptor %d", fileDescriptor)
	}
	return fileDescriptor, nil
}
