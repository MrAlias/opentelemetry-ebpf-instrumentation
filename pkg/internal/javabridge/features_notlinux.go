// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package javabridge // import "go.opentelemetry.io/obi/pkg/internal/javabridge"

import "errors"

func HaveSockOpsNetnsCookie() error {
	return errors.New("sockops network namespace cookies are unsupported")
}
