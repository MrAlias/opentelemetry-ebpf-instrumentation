// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common/connection_info.h>

static void test_begin_data_receive(u64 process_capability);
static long test_probe_read_user(void *destination, unsigned int size, const void *source);

#define JAVA_REMOTE_PARENT_BEGIN_DATA_RECEIVE(process_capability)                                  \
    test_begin_data_receive(process_capability)

#include <generictracer/java_remote_parent_receive.h>

#undef JAVA_REMOTE_PARENT_BEGIN_DATA_RECEIVE

static int sequence;
static int begin_sequence;
static int read_sequence;
static int read_failure;
static u64 observed_process_capability;
static const void *expected_source;

static void fail(const char *message) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

static void reset(const void *source, int fail_read) {
    sequence = 0;
    begin_sequence = 0;
    read_sequence = 0;
    read_failure = fail_read;
    observed_process_capability = 0;
    expected_source = source;
}

static void test_begin_data_receive(u64 process_capability) {
    begin_sequence = ++sequence;
    observed_process_capability = process_capability;
}

static long test_probe_read_user(void *destination, unsigned int size, const void *source) {
    read_sequence = ++sequence;
    if (source != expected_source || size != sizeof(connection_info_t)) {
        fail("claimed connection read used the wrong source or size");
    }
    if (read_failure) {
        return -1;
    }
    memcpy(destination, source, size);
    return 0;
}

// Mirrors the production dispatch split: the lightweight boundary gate runs
// before the sibling data handler performs its first advisory tuple read.
static u8 test_receive_and_read_claimed(u8 enabled,
                                        u8 data_hook_ready,
                                        u8 registered,
                                        u8 op,
                                        const unsigned char *uarg,
                                        connection_info_t *claimed) {
    const u64 process_capability = 0x1020304050607080ULL;
    if (!java_remote_parent_begin_receive(
            enabled, data_hook_ready, registered, op == TCP_RECV, process_capability)) {
        return 0;
    }
    return test_probe_read_user(claimed, sizeof(*claimed), uarg + 1) == 0;
}

static void test_rejected_receive_detaches_before_the_failed_read(void) {
    unsigned char packet[1 + sizeof(connection_info_t)] = {0};
    connection_info_t claimed = {0};
    reset(packet + 1, 1);

    if (test_receive_and_read_claimed(1, 1, 1, TCP_RECV, packet, &claimed) || begin_sequence != 1 ||
        read_sequence != 2 || observed_process_capability != 0x1020304050607080ULL) {
        fail("rejected receive did not detach before its first failing validation");
    }
}

static void test_unregistered_receive_detaches_without_reading_the_claim(void) {
    unsigned char packet[1 + sizeof(connection_info_t)] = {0};
    connection_info_t claimed = {0};
    reset(packet + 1, 0);

    if (test_receive_and_read_claimed(1, 1, 0, TCP_RECV, packet, &claimed) || begin_sequence != 1 ||
        read_sequence != 0 || observed_process_capability != 0x1020304050607080ULL) {
        fail("unregistered receive did not detach before its registration rejection");
    }
}

static void test_valid_receive_detaches_before_copying_the_claim(void) {
    unsigned char packet[1 + sizeof(connection_info_t)] = {0};
    connection_info_t expected = {.s_port = 1234, .d_port = 443};
    connection_info_t claimed = {0};
    memcpy(packet + 1, &expected, sizeof(expected));
    reset(packet + 1, 0);

    if (!test_receive_and_read_claimed(1, 1, 1, TCP_RECV, packet, &claimed) ||
        begin_sequence != 1 || read_sequence != 2 ||
        observed_process_capability != 0x1020304050607080ULL ||
        memcmp(&claimed, &expected, sizeof(expected)) != 0) {
        fail("valid receive did not detach before copying its claimed connection");
    }
}

static void test_non_receives_and_disabled_bridges_do_not_detach(void) {
    unsigned char packet[1 + sizeof(connection_info_t)] = {0};
    connection_info_t claimed = {0};

    reset(packet + 1, 0);
    if (!test_receive_and_read_claimed(1, 1, 1, TCP_SEND, packet, &claimed) ||
        begin_sequence != 0 || read_sequence != 1) {
        fail("send operation detached receive state");
    }

    reset(packet + 1, 0);
    if (!test_receive_and_read_claimed(0, 1, 1, TCP_RECV, packet, &claimed) ||
        begin_sequence != 0 || read_sequence != 1) {
        fail("disabled bridge detached receive state");
    }

    reset(packet + 1, 0);
    if (!test_receive_and_read_claimed(1, 0, 1, TCP_RECV, packet, &claimed) ||
        begin_sequence != 0 || read_sequence != 1) {
        fail("unready data hook detached receive state");
    }
}

static u8 test_http1_boundary_and_maybe_read(u8 wire_operation,
                                             u8 registered,
                                             const unsigned char *uarg,
                                             connection_info_t *claimed) {
    const enum java_remote_parent_data_operation operation =
        java_remote_parent_decode_data_operation(wire_operation);
    const enum java_remote_parent_receive_action action =
        java_remote_parent_data_receive_action(operation);
    if (action != k_java_remote_parent_receive_action_http1_start &&
        action != k_java_remote_parent_receive_action_http1_continue &&
        action != k_java_remote_parent_receive_action_http1_reset) {
        return 0;
    }

    const u64 process_capability = 0x1020304050607080ULL;
    if (!java_remote_parent_begin_receive(
            1,
            1,
            registered,
            java_remote_parent_data_starts_receive_boundary(operation),
            process_capability)) {
        return 0;
    }
    if (action != k_java_remote_parent_receive_action_http1_start) {
        return 0;
    }
    return test_probe_read_user(claimed, sizeof(*claimed), uarg + 1) == 0;
}

static void test_http1_start_is_the_only_http1_receive_boundary(void) {
    unsigned char packet[1 + sizeof(connection_info_t)] = {0};
    connection_info_t claimed = {0};

    reset(packet + 1, 1);
    if (test_http1_boundary_and_maybe_read(14, 1, packet, &claimed) || begin_sequence != 1 ||
        read_sequence != 2 || observed_process_capability != 0x1020304050607080ULL) {
        fail("HTTP/1 START did not detach before its first failing advisory read");
    }

    reset(packet + 1, 0);
    if (test_http1_boundary_and_maybe_read(14, 0, packet, &claimed) || begin_sequence != 1 ||
        read_sequence != 0 || observed_process_capability != 0x1020304050607080ULL) {
        fail("unregistered HTTP/1 START did not detach before rejection");
    }

    reset(packet + 1, 0);
    if (test_http1_boundary_and_maybe_read(15, 1, packet, &claimed) || begin_sequence != 0 ||
        read_sequence != 0 || observed_process_capability != 0) {
        fail("HTTP/1 CONTINUE crossed a receive boundary or read state in the boundary gate");
    }

    reset(packet + 1, 0);
    if (test_http1_boundary_and_maybe_read(16, 1, packet, &claimed) || begin_sequence != 0 ||
        read_sequence != 0 || observed_process_capability != 0) {
        fail("HTTP/1 RESET crossed a receive boundary or probed a payload");
    }
}

static u8 test_telemetry_boundary_and_read(u8 registered,
                                           const unsigned char *uarg,
                                           connection_info_t *claimed) {
    const enum java_remote_parent_data_operation operation =
        java_remote_parent_decode_data_operation(17);
    if (java_remote_parent_data_receive_action(operation) !=
        k_java_remote_parent_receive_action_telemetry) {
        return 0;
    }
    const u64 process_capability = 0x1020304050607080ULL;
    if (!java_remote_parent_begin_receive(
            1,
            1,
            registered,
            java_remote_parent_data_starts_receive_boundary(operation),
            process_capability)) {
        return 0;
    }
    return test_probe_read_user(claimed, sizeof(*claimed), uarg + 1) == 0;
}

static void test_telemetry_receive_is_a_fail_closed_boundary(void) {
    unsigned char packet[1 + sizeof(connection_info_t)] = {0};
    connection_info_t expected = {.s_port = 1234, .d_port = 443};
    connection_info_t claimed = {0};
    memcpy(packet + 1, &expected, sizeof(expected));

    reset(packet + 1, 0);
    if (!test_telemetry_boundary_and_read(1, packet, &claimed) || begin_sequence != 1 ||
        read_sequence != 2 || observed_process_capability != 0x1020304050607080ULL ||
        memcmp(&claimed, &expected, sizeof(expected)) != 0) {
        fail("telemetry receive did not detach before reading its advisory tuple");
    }

    reset(packet + 1, 0);
    if (test_telemetry_boundary_and_read(0, packet, &claimed) || begin_sequence != 1 ||
        read_sequence != 0 || observed_process_capability != 0x1020304050607080ULL) {
        fail("unregistered telemetry receive did not detach before rejection");
    }
}

static void test_wire_operations_decode_without_direction_aliases(void) {
    struct operation_case {
        u8 wire;
        enum java_remote_parent_data_operation operation;
        u8 direction;
        enum java_remote_parent_receive_action action;
        u8 boundary;
    } cases[] = {
        {1,
         k_java_remote_parent_data_operation_send,
         TCP_SEND,
         k_java_remote_parent_receive_action_legacy,
         0},
        {2,
         k_java_remote_parent_data_operation_receive,
         TCP_RECV,
         k_java_remote_parent_receive_action_legacy,
         1},
        {14,
         k_java_remote_parent_data_operation_http1_receive_start,
         TCP_RECV,
         k_java_remote_parent_receive_action_http1_start,
         1},
        {15,
         k_java_remote_parent_data_operation_http1_receive_continue,
         TCP_RECV,
         k_java_remote_parent_receive_action_http1_continue,
         0},
        {16,
         k_java_remote_parent_data_operation_http1_receive_reset,
         k_java_remote_parent_parser_direction_invalid,
         k_java_remote_parent_receive_action_http1_reset,
         0},
        {17,
         k_java_remote_parent_data_operation_telemetry_receive,
         TCP_RECV,
         k_java_remote_parent_receive_action_telemetry,
         1},
        {0,
         k_java_remote_parent_data_operation_invalid,
         k_java_remote_parent_parser_direction_invalid,
         k_java_remote_parent_receive_action_invalid,
         0},
        {0xff,
         k_java_remote_parent_data_operation_invalid,
         k_java_remote_parent_parser_direction_invalid,
         k_java_remote_parent_receive_action_invalid,
         0},
    };

    for (size_t index = 0; index < sizeof(cases) / sizeof(cases[0]); index++) {
        const enum java_remote_parent_data_operation operation =
            java_remote_parent_decode_data_operation(cases[index].wire);
        if (operation != cases[index].operation ||
            java_remote_parent_data_parser_direction(operation) != cases[index].direction ||
            java_remote_parent_data_receive_action(operation) != cases[index].action ||
            java_remote_parent_data_starts_receive_boundary(operation) != cases[index].boundary ||
            java_remote_parent_receive_action_allows_incoming_claim(cases[index].action) !=
                (cases[index].action != k_java_remote_parent_receive_action_http1_continue &&
                 cases[index].action != k_java_remote_parent_receive_action_http1_reset &&
                 cases[index].action != k_java_remote_parent_receive_action_telemetry)) {
            fail("wire operation decode conflated parser direction and receive action");
        }
    }

    for (unsigned int wire = 0; wire <= 0xff; wire++) {
        const enum java_remote_parent_data_operation operation =
            java_remote_parent_decode_data_operation((u8)wire);
        const u8 known =
            wire == 1 || wire == 2 || wire == 14 || wire == 15 || wire == 16 || wire == 17;
        if ((operation != k_java_remote_parent_data_operation_invalid) != known) {
            fail("wire operation decoder accepted an unspecified operation byte");
        }
    }
}

static void test_wire_offsets_match_the_java_packet_abi(void) {
    if (sizeof(connection_info_t) != 36 || k_java_remote_parent_data_connection_offset != 1 ||
        k_java_remote_parent_data_length_offset != 37 ||
        k_java_remote_parent_data_signal_offset != 41 ||
        k_java_remote_parent_data_legacy_payload_offset != 49 ||
        k_java_remote_parent_data_http1_lifecycle_offset != 49 ||
        k_java_remote_parent_data_http1_request_sequence_offset != 57 ||
        k_java_remote_parent_data_http1_payload_offset != 65) {
        fail("BPF receive offsets diverged from the Java packet ABI");
    }
}

static void test_http1_prefix_validation_is_exact(void) {
    const enum java_remote_parent_data_operation start =
        k_java_remote_parent_data_operation_http1_receive_start;
    const enum java_remote_parent_data_operation continuation =
        k_java_remote_parent_data_operation_http1_receive_continue;
    const enum java_remote_parent_data_operation reset_operation =
        k_java_remote_parent_data_operation_http1_receive_reset;

    if (!java_remote_parent_http1_prefix_valid(start, 1, 3, 2, 1) ||
        !java_remote_parent_http1_prefix_valid(
            start, k_java_remote_parent_data_max_payload_len, 3, ~0ULL, ~0ULL) ||
        java_remote_parent_http1_prefix_valid(start, 0, 3, 2, 1) ||
        java_remote_parent_http1_prefix_valid(
            start, k_java_remote_parent_data_max_payload_len + 1, 3, 2, 1) ||
        java_remote_parent_http1_prefix_valid(start, 1, 0, 2, 1) ||
        java_remote_parent_http1_prefix_valid(start, 1, 3, 0, 1) ||
        java_remote_parent_http1_prefix_valid(start, 1, 3, 2, 0)) {
        fail("HTTP/1 START prefix validation accepted a malformed boundary");
    }

    if (!java_remote_parent_http1_prefix_valid(continuation, 1, 0, 2, 1) ||
        !java_remote_parent_http1_prefix_valid(
            continuation, k_java_remote_parent_data_max_payload_len, 0, 1, ~0ULL) ||
        java_remote_parent_http1_prefix_valid(continuation, 0, 0, 2, 1) ||
        java_remote_parent_http1_prefix_valid(
            continuation, k_java_remote_parent_data_max_payload_len + 1, 0, 2, 1) ||
        java_remote_parent_http1_prefix_valid(continuation, 1, 3, 2, 1) ||
        java_remote_parent_http1_prefix_valid(continuation, 1, 0, 0, 1) ||
        java_remote_parent_http1_prefix_valid(continuation, 1, 0, 2, 0)) {
        fail("HTTP/1 CONTINUE prefix validation accepted a malformed fragment");
    }

    if (!java_remote_parent_http1_prefix_valid(reset_operation, 0, 0, 2, 1) ||
        java_remote_parent_http1_prefix_valid(reset_operation, 1, 0, 2, 1) ||
        java_remote_parent_http1_prefix_valid(reset_operation, 0, 3, 2, 1) ||
        java_remote_parent_http1_prefix_valid(reset_operation, 0, 0, 0, 1) ||
        java_remote_parent_http1_prefix_valid(reset_operation, 0, 0, 2, 0) ||
        java_remote_parent_http1_prefix_valid(
            k_java_remote_parent_data_operation_receive, 1, 3, 2, 1) ||
        java_remote_parent_http1_prefix_valid(
            k_java_remote_parent_data_operation_invalid, 0, 0, 2, 1)) {
        fail("HTTP/1 RESET or non-HTTP prefix validation was not fail closed");
    }
}

static void test_http1_wire_nonce_composes_with_prepared_cursor(void) {
    const u64 committed_start_nonce = 0x4142434445464748ULL;
    const u64 lifecycle_id = 0x2122232425262728ULL;
    const u64 request_sequence = 1;

    if (!java_remote_parent_http1_prefix_valid(
            k_java_remote_parent_data_operation_http1_receive_start,
            1,
            committed_start_nonce,
            lifecycle_id,
            request_sequence) ||
        !java_remote_parent_http1_data_signal_exact(k_java_remote_parent_receive_action_http1_start,
                                                    committed_start_nonce,
                                                    committed_start_nonce)) {
        fail("HTTP/1 START wire nonce did not match its prepared cursor");
    }

    // A CONTINUE cursor retains the nonzero nonce committed by START, while
    // the CONTINUE packet itself must carry zero. Exercise both predicates
    // together so the two valid representations cannot reject each other.
    if (!java_remote_parent_http1_prefix_valid(
            k_java_remote_parent_data_operation_http1_receive_continue,
            1,
            0,
            lifecycle_id,
            request_sequence) ||
        !java_remote_parent_http1_data_signal_exact(
            k_java_remote_parent_receive_action_http1_continue, committed_start_nonce, 0)) {
        fail("HTTP/1 CONTINUE wire nonce did not compose with its committed START cursor");
    }

    if (java_remote_parent_http1_data_signal_exact(k_java_remote_parent_receive_action_http1_start,
                                                   committed_start_nonce,
                                                   committed_start_nonce + 1) ||
        java_remote_parent_http1_data_signal_exact(
            k_java_remote_parent_receive_action_http1_start, 0, 0) ||
        java_remote_parent_http1_data_signal_exact(
            k_java_remote_parent_receive_action_http1_continue, 0, 0) ||
        java_remote_parent_http1_data_signal_exact(
            k_java_remote_parent_receive_action_http1_continue,
            committed_start_nonce,
            committed_start_nonce) ||
        java_remote_parent_http1_data_signal_exact(
            k_java_remote_parent_receive_action_http1_reset, committed_start_nonce, 0) ||
        java_remote_parent_http1_data_signal_exact(
            k_java_remote_parent_receive_action_invalid, committed_start_nonce, 0)) {
        fail("HTTP/1 prepared cursor accepted a mismatched wire nonce");
    }
}

static void test_telemetry_prefix_validation_is_exact(void) {
    if (!java_remote_parent_telemetry_prefix_valid(1, 0) ||
        !java_remote_parent_telemetry_prefix_valid(k_java_remote_parent_data_max_payload_len, 0) ||
        java_remote_parent_telemetry_prefix_valid(0, 0) ||
        java_remote_parent_telemetry_prefix_valid(k_java_remote_parent_data_max_payload_len + 1,
                                                  0) ||
        java_remote_parent_telemetry_prefix_valid(1, 1)) {
        fail("telemetry receive prefix validation accepted an unsafe packet");
    }
}

static void test_http1_sys_ioctl_fallback_is_telemetry_only(void) {
    const enum java_remote_parent_data_operation start =
        k_java_remote_parent_data_operation_http1_receive_start;
    const enum java_remote_parent_data_operation continuation =
        k_java_remote_parent_data_operation_http1_receive_continue;
    const enum java_remote_parent_data_operation reset_operation =
        k_java_remote_parent_data_operation_http1_receive_reset;

    const enum java_remote_parent_data_dispatch start_fallback =
        java_remote_parent_select_data_dispatch(start, 0, 0);
    const enum java_remote_parent_data_dispatch continue_fallback =
        java_remote_parent_select_data_dispatch(continuation, 0, 0);
    const enum java_remote_parent_data_dispatch reset_fallback =
        java_remote_parent_select_data_dispatch(reset_operation, 0, 0);

    if (start_fallback != k_java_remote_parent_data_dispatch_http1_telemetry ||
        continue_fallback != k_java_remote_parent_data_dispatch_http1_telemetry ||
        !java_remote_parent_data_dispatch_parses_payload(start, start_fallback) ||
        !java_remote_parent_data_dispatch_parses_payload(continuation, continue_fallback) ||
        java_remote_parent_data_dispatch_has_bridge_authority(start_fallback) ||
        java_remote_parent_data_dispatch_has_bridge_authority(continue_fallback) ||
        !java_remote_parent_data_dispatch_detaches_owner(start, start_fallback, 0) ||
        java_remote_parent_data_dispatch_detaches_owner(continuation, continue_fallback, 0) ||
        java_remote_parent_effective_receive_action(start, start_fallback) !=
            k_java_remote_parent_receive_action_telemetry ||
        java_remote_parent_effective_receive_action(continuation, continue_fallback) !=
            k_java_remote_parent_receive_action_telemetry ||
        java_remote_parent_receive_action_allows_incoming_claim(
            java_remote_parent_effective_receive_action(start, start_fallback)) ||
        java_remote_parent_receive_action_allows_incoming_claim(
            java_remote_parent_effective_receive_action(continuation, continue_fallback)) ||
        java_remote_parent_data_payload_offset(start) !=
            k_java_remote_parent_data_http1_payload_offset ||
        java_remote_parent_data_payload_offset(continuation) !=
            k_java_remote_parent_data_http1_payload_offset ||
        !java_remote_parent_http1_prefix_valid(
            start, 1, 0x4142434445464748ULL, 0x2122232425262728ULL, 1)) {
        fail("hook-unavailable HTTP/1 fragments retained bridge authority or lost telemetry");
    }

    if (reset_fallback != k_java_remote_parent_data_dispatch_ignore ||
        java_remote_parent_data_dispatch_parses_payload(reset_operation, reset_fallback) ||
        java_remote_parent_data_dispatch_has_bridge_authority(reset_fallback)) {
        fail("hook-unavailable HTTP/1 RESET was not a state-free no-op");
    }

    for (size_t index = 0; index < 2; index++) {
        const u8 data_hook_ready = index == 0;
        const u8 file_available = index != 0;
        if (java_remote_parent_select_data_dispatch(start, data_hook_ready, file_available) !=
                k_java_remote_parent_data_dispatch_http1_telemetry ||
            java_remote_parent_select_data_dispatch(
                continuation, data_hook_ready, file_available) !=
                k_java_remote_parent_data_dispatch_http1_telemetry ||
            java_remote_parent_select_data_dispatch(
                reset_operation, data_hook_ready, file_available) !=
                k_java_remote_parent_data_dispatch_ignore) {
            fail("HTTP/1 bridge authority did not require both the hook and live file");
        }
    }

    const enum java_remote_parent_data_dispatch bridge =
        java_remote_parent_select_data_dispatch(start, 1, 1);
    if (bridge != k_java_remote_parent_data_dispatch_http1_bridge ||
        !java_remote_parent_data_dispatch_has_bridge_authority(bridge) ||
        java_remote_parent_effective_receive_action(start, bridge) !=
            k_java_remote_parent_receive_action_http1_start) {
        fail("file-bearing HTTP/1 START lost bridge authority");
    }

    unsigned char packet[1 + sizeof(connection_info_t)] = {0};
    reset(packet + 1, 0);
    if (!java_remote_parent_begin_receive(
            1,
            java_remote_parent_data_dispatch_detaches_owner(start, start_fallback, 0),
            1,
            java_remote_parent_data_starts_receive_boundary(start),
            0x1020304050607080ULL) ||
        begin_sequence != 1 || observed_process_capability != 0x1020304050607080ULL) {
        fail("hook-unavailable START did not detach the stale exact SDK owner");
    }
}

int main(void) {
    test_rejected_receive_detaches_before_the_failed_read();
    test_unregistered_receive_detaches_without_reading_the_claim();
    test_valid_receive_detaches_before_copying_the_claim();
    test_non_receives_and_disabled_bridges_do_not_detach();
    test_http1_start_is_the_only_http1_receive_boundary();
    test_telemetry_receive_is_a_fail_closed_boundary();
    test_wire_operations_decode_without_direction_aliases();
    test_wire_offsets_match_the_java_packet_abi();
    test_http1_prefix_validation_is_exact();
    test_http1_wire_nonce_composes_with_prepared_cursor();
    test_telemetry_prefix_validation_is_exact();
    test_http1_sys_ioctl_fallback_is_telemetry_only();
    return 0;
}
