// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// One exact process-lifetime identity per host TGID. Keeping this separate
// from log_enricher_pids avoids ambiguity when namespace PID aliases collide.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32); // host TGID
    __type(value, log_enricher_generation_t);
    __uint(max_entries, 1 << 12);
    __uint(pinning, OBI_PIN_INTERNAL);
} log_enricher_generations SEC(".maps");
