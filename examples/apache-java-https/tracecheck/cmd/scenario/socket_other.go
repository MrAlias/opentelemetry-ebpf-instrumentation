// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package main

import (
	"errors"
	"net"
	"syscall"
)

func enableAddressReuse(_ string, _ string, _ syscall.RawConn) error {
	return errors.New("fd-port-reuse requires Linux")
}

func connectionFileDescriptor(_ *net.TCPConn) (int, error) {
	return 0, errors.New("fd-port-reuse requires Linux")
}
