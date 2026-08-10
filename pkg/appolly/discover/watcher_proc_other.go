// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"errors"
	"os"

	"go.opentelemetry.io/obi/pkg/appolly/app"
)

// placeholder files to allow local compilation/unit testing in non-linux environments

func currentTime() uint64 {
	return 0
}

func processIdentityForPID(_ app.PID) (*processIdentityLease, error) {
	// Stable proc-directory identities are Linux-specific. Other platforms keep
	// their existing numeric-process discovery behavior.
	return nil, nil
}

func duplicateProcessHandleFD(_ uintptr) (*os.File, error) {
	return nil, errors.New("stable process handles are not supported on this platform")
}

func validateProcessIdentity(_ *processIdentityLease) error {
	return nil
}
