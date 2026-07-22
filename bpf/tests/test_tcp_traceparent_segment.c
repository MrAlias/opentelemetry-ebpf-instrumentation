// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>

#include <common/tcp_traceparent.h>

static void assert_fit(u8 expected, u32 payload_len, u32 mss, const char *message) {
    const u8 actual = tcp_traceparent_fits_single_segment(payload_len, mss);
    if (actual != expected) {
        fprintf(stderr, "FAIL: %s: expected %u, got %u\n", message, expected, actual);
        exit(1);
    }
}

static void assert_legacy_allowed(u8 expected, u8 bridge_enabled, const char *message) {
    const u8 actual = tcp_traceparent_legacy_option_allowed(bridge_enabled);
    if (actual != expected) {
        fprintf(stderr, "FAIL: %s: expected %u, got %u\n", message, expected, actual);
        exit(1);
    }
}

static void assert_generic_allowed(u8 expected, u8 bridge_enabled, const char *message) {
    const u8 actual = tcp_traceparent_generic_injection_allowed(bridge_enabled);
    if (actual != expected) {
        fprintf(stderr, "FAIL: %s: expected %u, got %u\n", message, expected, actual);
        exit(1);
    }
}

static void
assert_option_size(u8 expected, u8 bridge_enabled, u8 exact_owner, const char *message) {
    const u8 actual = tcp_traceparent_option_size(bridge_enabled, exact_owner);
    if (actual != expected) {
        fprintf(stderr, "FAIL: %s: expected %u, got %u\n", message, expected, actual);
        exit(1);
    }
}

static void assert_existing_parent_action(u8 expected,
                                          u8 bridge_enabled,
                                          u8 tcp_options_enabled,
                                          u8 parent_valid,
                                          u8 identity_valid,
                                          const char *message) {
    const u8 actual = tcp_traceparent_existing_parent_action(
        bridge_enabled, tcp_options_enabled, parent_valid, identity_valid);
    if (actual != expected) {
        fprintf(stderr, "FAIL: %s: expected %u, got %u\n", message, expected, actual);
        exit(1);
    }
}

static void assert_legacy_opt_len_action(enum tcp_traceparent_legacy_opt_len_action expected,
                                         u8 bridge_enabled,
                                         u8 storage_present,
                                         const char *message) {
    const enum tcp_traceparent_legacy_opt_len_action actual =
        tcp_traceparent_legacy_opt_len_action(bridge_enabled, storage_present);
    if (actual != expected) {
        fprintf(stderr, "FAIL: %s: expected %u, got %u\n", message, expected, actual);
        exit(1);
    }
}

static void
assert_len_candidate(u8 expected, u32 snd_nxt, u32 packet_len, u32 target, const char *message) {
    const u8 actual = tcp_traceparent_len_may_contain_target(snd_nxt, packet_len, target);
    if (actual != expected) {
        fprintf(stderr, "FAIL: %s: expected %u, got %u\n", message, expected, actual);
        exit(1);
    }
}

static void assert_target_position(enum tcp_traceparent_target_position expected,
                                   u32 sequence,
                                   u32 payload_len,
                                   u32 target,
                                   const char *message) {
    const enum tcp_traceparent_target_position actual =
        tcp_traceparent_target_position(sequence, payload_len, target);
    if (actual != expected) {
        fprintf(stderr, "FAIL: %s: expected %u, got %u\n", message, expected, actual);
        exit(1);
    }
}

static void assert_write_action(enum tcp_traceparent_write_action expected,
                                enum tcp_traceparent_target_position position,
                                u32 packet_len,
                                u32 mss,
                                const char *message) {
    const enum tcp_traceparent_write_action actual =
        tcp_traceparent_write_action(position, packet_len, mss);
    if (actual != expected) {
        fprintf(stderr, "FAIL: %s: expected %u, got %u\n", message, expected, actual);
        exit(1);
    }
}

static void assert_packet_action(enum tcp_traceparent_write_action expected,
                                 enum tcp_traceparent_target_position position,
                                 u32 packet_len,
                                 u32 tcp_header_len,
                                 u32 mss,
                                 const char *message) {
    const enum tcp_traceparent_write_action actual =
        tcp_traceparent_write_packet_action(position, packet_len, tcp_header_len, mss);
    if (actual != expected) {
        fprintf(stderr, "FAIL: %s: expected %u, got %u\n", message, expected, actual);
        exit(1);
    }
}

static void
assert_write_packet_valid(u8 expected, u32 packet_len, u32 tcp_header_len, const char *message) {
    const u8 actual = tcp_traceparent_write_packet_valid(packet_len, tcp_header_len);
    if (actual != expected) {
        fprintf(stderr, "FAIL: %s: expected %u, got %u\n", message, expected, actual);
        exit(1);
    }
}

int main(void) {
    assert_legacy_allowed(1, 0, "bridge-disabled mode permits legacy TCP-option state");
    assert_legacy_allowed(0, 1, "bridge-enabled mode rejects unowned legacy TCP-option state");
    assert_generic_allowed(1, 0, "bridge-disabled mode permits generic payload injection");
    assert_generic_allowed(
        0, 1, "bridge-enabled mode rejects payload mutation without exact ownership");
    assert_option_size(sizeof(tcp_traceparent_legacy_option_t),
                       0,
                       0,
                       "bridge-disabled legacy reserve and write use 26 bytes");
    assert_option_size(0, 1, 0, "bridge-enabled legacy storage reserves and writes nothing");
    assert_option_size(sizeof(tcp_traceparent_option_t),
                       1,
                       1,
                       "bridge-enabled exact ownership reserves and writes 27 bytes");
    assert_existing_parent_action(k_tcp_traceparent_existing_parent_schedule_legacy,
                                  0,
                                  1,
                                  0,
                                  1,
                                  "bridge-disabled SSL marker schedules legacy before rejection");
    assert_existing_parent_action(
        k_tcp_traceparent_existing_parent_schedule_legacy |
            k_tcp_traceparent_existing_parent_continue_plaintext,
        0,
        1,
        1,
        1,
        "bridge-disabled valid non-HTTP reaches detection after scheduling");
    assert_existing_parent_action(k_tcp_traceparent_existing_parent_continue_plaintext,
                                  1,
                                  1,
                                  1,
                                  1,
                                  "bridge-enabled unowned state never schedules legacy");
    assert_existing_parent_action(k_tcp_traceparent_existing_parent_none,
                                  0,
                                  1,
                                  1,
                                  0,
                                  "foreign or malformed identity cannot schedule legacy");
    assert_existing_parent_action(k_tcp_traceparent_existing_parent_continue_plaintext,
                                  0,
                                  0,
                                  1,
                                  1,
                                  "disabled TCP options continue plaintext without scheduling");
    assert_legacy_opt_len_action(k_tcp_traceparent_legacy_opt_len_none,
                                 0,
                                 0,
                                 "missing legacy state performs no callback action");
    assert_legacy_opt_len_action(k_tcp_traceparent_legacy_opt_len_delete,
                                 1,
                                 1,
                                 "bridge-enabled unowned legacy state is deleted");
    assert_legacy_opt_len_action(
        k_tcp_traceparent_legacy_opt_len_reserve,
        0,
        1,
        "bridge-disabled legacy state reserves 26 bytes and remains retryable");

    assert_fit(1, 1420, 1460, "one segment at conservative MSS");
    assert_fit(0, 1421, 1460, "payload requiring another segment");
    assert_fit(0, 2920, 1460, "GSO payload spanning two MSS values");
    assert_fit(0, 0, 1460, "pure ACK");
    assert_fit(0, 1, 0, "missing MSS");
    assert_fit(0, 1, 40, "no payload capacity at maximum option size");
    assert_fit(1, 1, 41, "minimum provably single-segment payload");

    assert_len_candidate(1, 100, 60, 100, "exact next sequence is a candidate");
    assert_len_candidate(1, 100, 60, 120, "packet upper bound can contain a queued target");
    assert_len_candidate(0, 100, 60, 160, "target at the upper bound waits");
    assert_len_candidate(0, 100, 60, 90, "a passed target is not a candidate");
    assert_len_candidate(1, 0xfffffff0, 32, 0, "candidate comparison handles sequence wraparound");
    assert_len_candidate(
        0, 16, 32, 0xfffffff0, "passed-target comparison handles sequence wraparound");

    assert_target_position(
        k_tcp_traceparent_target_invalid, 100, 0, 100, "an empty packet has no target position");
    assert_target_position(k_tcp_traceparent_target_at_segment_start,
                           100,
                           20,
                           100,
                           "exact packet start can carry the parent");
    assert_target_position(
        k_tcp_traceparent_target_inside_segment, 100, 20, 110, "a coalesced target is ambiguous");
    assert_target_position(
        k_tcp_traceparent_target_after_segment, 100, 20, 120, "a target at the next byte waits");
    assert_target_position(
        k_tcp_traceparent_target_before_segment, 100, 20, 90, "a segment after the target misses");
    assert_target_position(k_tcp_traceparent_target_inside_segment,
                           0xfffffff0,
                           32,
                           0,
                           "interior comparison handles sequence wraparound");
    assert_target_position(k_tcp_traceparent_target_after_segment,
                           0xfffffff0,
                           16,
                           0,
                           "boundary comparison handles sequence wraparound");
    assert_target_position(k_tcp_traceparent_target_before_segment,
                           16,
                           16,
                           0xfffffff0,
                           "passed comparison handles sequence wraparound");

    assert_write_action(k_tcp_traceparent_write_retry,
                        k_tcp_traceparent_target_after_segment,
                        1460,
                        1460,
                        "a full-MSS retransmit retries before applying the size guard");
    assert_write_action(k_tcp_traceparent_write_segmented,
                        k_tcp_traceparent_target_at_segment_start,
                        1460,
                        1460,
                        "a full-MSS exact packet is rejected as segmented");
    assert_write_action(k_tcp_traceparent_write_emit,
                        k_tcp_traceparent_target_at_segment_start,
                        1420,
                        1460,
                        "a fitting exact packet emits");
    assert_write_action(k_tcp_traceparent_write_miss,
                        k_tcp_traceparent_target_inside_segment,
                        100,
                        1460,
                        "a coalesced target misses without emission");
    assert_write_action(k_tcp_traceparent_write_miss,
                        k_tcp_traceparent_target_before_segment,
                        100,
                        1460,
                        "a passed target misses without emission");
    assert_write_action(k_tcp_traceparent_write_miss,
                        k_tcp_traceparent_target_invalid,
                        100,
                        1460,
                        "an invalid header misses without emission");

    assert_packet_action(k_tcp_traceparent_write_emit,
                         k_tcp_traceparent_target_at_segment_start,
                         1440,
                         20,
                         1460,
                         "WRITE subtracts the TCP header before the MSS guard");
    assert_packet_action(k_tcp_traceparent_write_segmented,
                         k_tcp_traceparent_target_at_segment_start,
                         1441,
                         20,
                         1460,
                         "WRITE rejects payload beyond the conservative capacity");
    assert_packet_action(k_tcp_traceparent_write_retry,
                         k_tcp_traceparent_target_after_segment,
                         1480,
                         20,
                         1460,
                         "a full-MSS retransmit retries even with its TCP header");
    assert_packet_action(k_tcp_traceparent_write_miss,
                         k_tcp_traceparent_target_at_segment_start,
                         20,
                         20,
                         1460,
                         "a header-only packet cannot emit");
    assert_write_packet_valid(
        1, 332, 60, "a full TCP header remains valid when WRITE exposes only its prefix");
    assert_write_packet_valid(0, 100, 16, "a truncated TCP header is invalid");
    assert_write_packet_valid(0, 100, 64, "a TCP header beyond the option limit is invalid");
    assert_write_packet_valid(0, 60, 60, "a packet without payload is invalid");
    return 0;
}
