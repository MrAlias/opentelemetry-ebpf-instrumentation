// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs // import "go.opentelemetry.io/obi/pkg/internal/procs"

import (
	"errors"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

func FindNamespace(_ app.PID) (uint32, error) {
	// convenience method to allow unit tests compiling in Darwin
	return 0, nil
}

func FindNamespacedPids(_ app.PID) ([]app.PID, error) {
	return nil, nil
}

func FindNamespacedPidsFromProcFD(_ int) ([]app.PID, error) {
	return nil, errors.New("stable namespaced PID lookup is not supported on Darwin")
}

func ProcessStartTime(_ app.PID) (uint64, error) {
	return 0, errors.New("process start time is not supported on Darwin")
}
