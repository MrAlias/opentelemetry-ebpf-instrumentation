// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pythonagent // import "go.opentelemetry.io/obi/pkg/internal/pythonagent"

import (
	_ "embed"
	"strconv"
)

//go:embed session.py
var sessionAgent string

// Script returns the requests.Session instrumentation and its installation call.
func Script() string {
	return "exec(" + strconv.Quote(sessionAgent+"\nif not install():\n    raise ImportError('requests is unavailable')\n") + ", {'__name__': '_obi_requests'})\n"
}
