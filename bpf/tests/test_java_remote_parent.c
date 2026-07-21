// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>

#include <common/java_remote_parent.h>
#include <common/tcp_traceparent.h>

enum { BPF_ANY = 0, BPF_NOEXIST = 1 };

static long
fallback_map_update(void *map, const void *key, const void *value, unsigned long long flags);

#define bpf_map_update_elem fallback_map_update
#include <maps/java_remote_parent_fallback.h>
#undef bpf_map_update_elem

static java_remote_parent_response_t fallback_value;
static int fallback_present;

static long
fallback_map_update(void *map, const void *key, const void *value, unsigned long long flags) {
    (void)key;
    if (map != &java_remote_parent_fallback || (flags == BPF_NOEXIST && fallback_present)) {
        return -1;
    }

    fallback_value = *(const java_remote_parent_response_t *)value;
    fallback_present = 1;
    return 0;
}

static void assert_byte(unsigned char expected, unsigned char actual, const char *field) {
    if (expected != actual) {
        fprintf(stderr, "%s: expected 0x%02x, got 0x%02x\n", field, expected, actual);
        exit(1);
    }
}

static void test_response_layout_and_zeroing(void) {
    java_remote_parent_response_t response;
    java_remote_parent_init_response(
        &response, k_java_remote_parent_status_valid, 0x0102030405060708ULL, 0x1112131415161718ULL);

    const unsigned char *bytes = (const unsigned char *)&response;
    assert_byte('O', bytes[0], "magic[0]");
    assert_byte('B', bytes[1], "magic[1]");
    assert_byte('I', bytes[2], "magic[2]");
    assert_byte('J', bytes[3], "magic[3]");
    assert_byte(1, bytes[4], "version low byte");
    assert_byte(0, bytes[5], "version high byte");
    assert_byte(64, bytes[6], "size low byte");
    assert_byte(0, bytes[7], "size high byte");
    assert_byte(k_java_remote_parent_status_valid, bytes[8], "status");

    for (u32 index = 9; index < 40; index++) {
        assert_byte(0, bytes[index], "zeroed context prefix");
    }
    for (u32 index = 0; index < 8; index++) {
        assert_byte(8 - index, bytes[40 + index], "generation");
        assert_byte(0x18 - index, bytes[48 + index], "observation");
        assert_byte(0, bytes[56 + index], "reserved suffix");
    }
}

static void test_valid_context_fields(void) {
    tp_info_t tp = {.flags = 0xa5};
    for (u32 index = 0; index < sizeof(tp.trace_id); index++) {
        tp.trace_id[index] = index + 1;
    }
    for (u32 index = 0; index < sizeof(tp.span_id); index++) {
        tp.span_id[index] = index + 0x21;
    }

    java_remote_parent_response_t response;
    java_remote_parent_init_response(&response, k_java_remote_parent_status_valid, 1, 2);
    java_remote_parent_set_context(&response, &tp);

    assert_byte(0xa5, response.flags, "W3C flags");
    for (u32 index = 0; index < sizeof(response.trace_id); index++) {
        assert_byte(index + 1, response.trace_id[index], "trace ID");
    }
    for (u32 index = 0; index < sizeof(response.span_id); index++) {
        assert_byte(index + 0x21, response.span_id[index], "span ID");
    }
}

static void test_tcp_option_carries_flags(void) {
    tcp_traceparent_legacy_option_t legacy = {};
    tcp_traceparent_option_t option = {.flags = 0x7f};
    assert_byte(26, sizeof(legacy), "legacy TCP option size");
    assert_byte(27, sizeof(option), "exact-flags TCP option size");
    assert_byte(0x7f, ((unsigned char *)&option)[26], "TCP option flags");
    assert_byte(1,
                k_tcp_common_syn_option_bytes + sizeof(option) <= k_tcp_header_option_bytes,
                "TCP option fits beside timestamps");
}

static void test_fallback_collision_does_not_overwrite(void) {
    const pid_key_t owner = {.tid = 1, .pid = 2, .ns = 3};
    java_remote_parent_response_t first;
    java_remote_parent_init_response(&first, k_java_remote_parent_status_valid, 1, 2);
    first.trace_id[0] = 1;
    first.span_id[0] = 2;

    fallback_present = 0;
    if (!java_remote_parent_stage_fallback(&owner, &first) ||
        fallback_value.status != k_java_remote_parent_status_valid) {
        fprintf(stderr, "fallback first insert failed\n");
        exit(1);
    }

    java_remote_parent_response_t conflicting = first;
    conflicting.span_id[0] = 3;
    if (java_remote_parent_stage_fallback(&owner, &conflicting) ||
        fallback_value.status != k_java_remote_parent_status_valid ||
        fallback_value.generation_le != first.generation_le ||
        fallback_value.trace_id[0] != first.trace_id[0] ||
        fallback_value.span_id[0] != first.span_id[0]) {
        fprintf(stderr, "fallback collision overwrote the reserved generation\n");
        exit(1);
    }
}

static void test_observation_age_fails_closed(void) {
    if (!java_remote_parent_observation_stale(99, 100, 30) ||
        !java_remote_parent_observation_stale(131, 100, 30) ||
        java_remote_parent_observation_stale(130, 100, 30) ||
        java_remote_parent_observation_stale(100, 100, 0)) {
        fprintf(stderr, "remote-parent observation age validation failed\n");
        exit(1);
    }
}

int main(void) {
    test_response_layout_and_zeroing();
    test_valid_context_fields();
    test_tcp_option_carries_flags();
    test_fallback_collision_does_not_overwrite();
    test_observation_age_fails_closed();
    return 0;
}
