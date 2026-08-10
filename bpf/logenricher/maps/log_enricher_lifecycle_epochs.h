// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// A separately authoritative lifecycle epoch prevents a late userspace map
// publication from undoing an exec/exit invalidation.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32); // host TGID
    __type(value, u64);
    __uint(max_entries, 1 << 12);
    __uint(pinning, OBI_PIN_INTERNAL);
} log_enricher_lifecycle_epochs SEC(".maps");
