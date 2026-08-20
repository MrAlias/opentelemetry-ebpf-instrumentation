// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// A separately authoritative kernel lifecycle epoch prevents a target written
// after an exit/exec notification from reviving stale process-scoped state.
// Missing/evicted entries fail closed; userspace seeds a fresh nonzero epoch
// from the exact discovery lifetime before publishing either target map.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u32); // host TGID
    __type(value, u64);
    __uint(max_entries, 1 << 12);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_process_lifecycle_epochs SEC(".maps");

static __always_inline bool go_process_lifecycle_epoch_matches(u32 host_pid, u64 expected) {
    if (!host_pid || !expected) {
        return false;
    }

    const u64 *current = bpf_map_lookup_elem(&go_process_lifecycle_epochs, &host_pid);
    return current && *current == expected;
}
