// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package timing // import "go.opentelemetry.io/obi/pkg/ebpf/timing"

import "time"

var processStart = time.Now()

// MonoTimeNow returns a process-local monotonic timestamp. Windows eBPF
// timestamps use a different clock, so Windows event sources must translate
// them before creating request spans.
func MonoTimeNow() time.Duration {
	return time.Since(processStart)
}
