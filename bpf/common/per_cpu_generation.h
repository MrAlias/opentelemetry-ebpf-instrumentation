// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

enum {
    k_per_cpu_generation_cpu_bits = 16,
    k_per_cpu_generation_sequence_bits = 64 - k_per_cpu_generation_cpu_bits,
    k_per_cpu_generation_max_cpu = (1U << k_per_cpu_generation_cpu_bits) - 1,
};

static __always_inline u64 next_per_cpu_generation(u64 *sequence, u32 cpu) {
    if (!sequence || cpu > k_per_cpu_generation_max_cpu) {
        return 0;
    }

    const u64 sequence_mask = (1ULL << k_per_cpu_generation_sequence_bits) - 1;
    u64 next = (*sequence + 1) & sequence_mask;
    if (!next) {
        next = 1;
    }
    *sequence = next;

    return ((u64)cpu << k_per_cpu_generation_sequence_bits) | next;
}
