// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package discover // import "go.opentelemetry.io/obi/pkg/appolly/discover"

import (
	"go.opentelemetry.io/obi/pkg/appolly/app"
	"go.opentelemetry.io/obi/pkg/appolly/discover/exec"
)

func liveProcessParentPID(fi *exec.FileInfo) (app.PID, bool) {
	if fi == nil {
		return 0, false
	}
	return fi.Ppid(), true
}
