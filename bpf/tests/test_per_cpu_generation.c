// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>

#include <common/per_cpu_generation.h>

static void fail(const char *message) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

int main(void) {
    u64 first_cpu_sequence = 0;
    u64 second_cpu_sequence = 0;

    const u64 first = next_per_cpu_generation(&first_cpu_sequence, 0);
    const u64 second = next_per_cpu_generation(&first_cpu_sequence, 0);
    const u64 other_cpu = next_per_cpu_generation(&second_cpu_sequence, 1);
    if (!first || second == first || other_cpu == first || other_cpu == second) {
        fail("generations are not unique across calls and CPUs");
    }

    first_cpu_sequence = (1ULL << k_per_cpu_generation_sequence_bits) - 1;
    if (!next_per_cpu_generation(&first_cpu_sequence, 0) || first_cpu_sequence != 1) {
        fail("sequence wrap produced an invalid generation");
    }
    if (next_per_cpu_generation(&first_cpu_sequence, k_per_cpu_generation_max_cpu + 1U) != 0) {
        fail("an unencodable CPU produced a generation");
    }

    return 0;
}
