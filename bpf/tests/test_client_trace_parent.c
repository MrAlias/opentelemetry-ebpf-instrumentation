// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common/tp_info.h>

static void assert_bytes_equal(const unsigned char *expected,
                               const unsigned char *actual,
                               size_t size,
                               const char *message) {
    if (memcmp(expected, actual, size) != 0) {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void test_client_inherits_trace_flags(u8 flags) {
    tp_info_t parent = {
        .trace_id = {1, 2, 3, 4},
        .span_id = {5, 6, 7, 8},
        .flags = flags,
    };
    tp_info_t child = {
        .trace_id = {9},
        .parent_id = {9},
        .flags = flags ^ k_flag_sampled,
    };

    set_client_trace_parent(&child, &parent);

    assert_bytes_equal(parent.trace_id, child.trace_id, sizeof(child.trace_id), "trace ID");
    assert_bytes_equal(parent.span_id, child.parent_id, sizeof(child.parent_id), "parent span ID");
    if (child.flags != flags) {
        fprintf(stderr, "FAIL: trace flags: expected %u, got %u\n", flags, child.flags);
        exit(1);
    }
}

int main(void) {
    test_client_inherits_trace_flags(0);
    test_client_inherits_trace_flags(k_flag_sampled);
    return 0;
}
