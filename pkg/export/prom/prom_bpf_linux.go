// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package prom // import "go.opentelemetry.io/obi/pkg/export/prom"

import (
	"io"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func enableBPFStatsRuntime() (io.Closer, error) {
	return ebpf.EnableStats(unix.BPF_STATS_RUN_TIME)
}
