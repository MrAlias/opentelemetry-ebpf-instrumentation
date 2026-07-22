// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package javabridge // import "go.opentelemetry.io/obi/pkg/internal/javabridge"

import "github.com/cilium/ebpf"

var disabledBridgeMapNames = [...]string{
	"incoming_trace_ambiguity",
	"incoming_trace_candidates",
	"incoming_trace_claims",
	"incoming_trace_heads",
	"java_retired_processes",
	"java_remote_parent_ambiguity",
	"java_remote_parent_claims",
	"java_remote_parent_connections",
	"java_remote_parent_cookie_connections",
	"java_remote_parent_data_acks",
	"java_remote_parent_data_signals",
	"java_remote_parent_fallback",
	"java_remote_parent_generation_index",
	"java_remote_parent_handoff_claims",
	"java_remote_parent_handoffs",
	"java_remote_parent_owners",
	"java_remote_parent_state",
	"java_remote_parent_tasks",
	"java_remote_parent_terminal",
	"sk_ssl_prewrite_map",
	"ssl_prewrite_tp",
}

func MinimizeDisabledMaps(spec *ebpf.CollectionSpec) {
	for _, name := range disabledBridgeMapNames {
		if bridgeMap := spec.Maps[name]; bridgeMap != nil {
			if bridgeMap.Type == ebpf.SkStorage {
				continue
			}
			bridgeMap.MaxEntries = 1
		}
	}
}
