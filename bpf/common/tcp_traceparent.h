// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/tp_info.h>

typedef struct tcp_traceparent_legacy_option {
    u8 kind;
    u8 len;
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char span_id[SPAN_ID_SIZE_BYTES];
} tcp_traceparent_legacy_option_t;

typedef struct tcp_traceparent_option {
    u8 kind;
    u8 len;
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char span_id[SPAN_ID_SIZE_BYTES];
    u8 flags;
} tcp_traceparent_option_t;

enum {
    k_tcp_traceparent_option_kind = 25,
    k_tcp_base_header_bytes = 20,
    k_tcp_header_option_bytes = 40,
    k_tcp_common_syn_option_bytes = 12,
};

enum tcp_traceparent_target_position : u8 {
    k_tcp_traceparent_target_invalid = 0,
    k_tcp_traceparent_target_before_segment = 1,
    k_tcp_traceparent_target_at_segment_start = 2,
    k_tcp_traceparent_target_inside_segment = 3,
    k_tcp_traceparent_target_after_segment = 4,
};

enum tcp_traceparent_write_action : u8 {
    k_tcp_traceparent_write_miss = 0,
    k_tcp_traceparent_write_retry = 1,
    k_tcp_traceparent_write_emit = 2,
    k_tcp_traceparent_write_segmented = 3,
};

enum tcp_traceparent_existing_parent_action : u8 {
    k_tcp_traceparent_existing_parent_none = 0,
    k_tcp_traceparent_existing_parent_schedule_legacy = 1 << 0,
    k_tcp_traceparent_existing_parent_continue_plaintext = 1 << 1,
};

enum tcp_traceparent_legacy_opt_len_action : u8 {
    k_tcp_traceparent_legacy_opt_len_none = 0,
    k_tcp_traceparent_legacy_opt_len_delete = 1,
    k_tcp_traceparent_legacy_opt_len_reserve = 2,
};

_Static_assert(sizeof(tcp_traceparent_legacy_option_t) == 26,
               "legacy TCP traceparent option size mismatch");
_Static_assert(sizeof(tcp_traceparent_option_t) == 27, "TCP traceparent option size mismatch");
_Static_assert(offsetof(tcp_traceparent_option_t, flags) == 26,
               "TCP traceparent flags offset mismatch");
_Static_assert(k_tcp_common_syn_option_bytes + sizeof(tcp_traceparent_option_t) <=
                   k_tcp_header_option_bytes,
               "TCP traceparent option does not fit beside timestamps");

static __always_inline u8 tcp_traceparent_legacy_option_allowed(u8 remote_parent_bridge_enabled) {
    return remote_parent_bridge_enabled == 0;
}

static __always_inline u8
tcp_traceparent_generic_injection_allowed(u8 remote_parent_bridge_enabled) {
    return remote_parent_bridge_enabled == 0;
}

static __always_inline u8 tcp_traceparent_option_size(u8 remote_parent_bridge_enabled,
                                                      u8 exact_prewrite_owner) {
    if (exact_prewrite_owner) {
        return sizeof(tcp_traceparent_option_t);
    }
    return tcp_traceparent_legacy_option_allowed(remote_parent_bridge_enabled)
               ? sizeof(tcp_traceparent_legacy_option_t)
               : 0;
}

static __always_inline u8 tcp_traceparent_existing_parent_action(u8 remote_parent_bridge_enabled,
                                                                 u8 tcp_options_enabled,
                                                                 u8 parent_valid,
                                                                 u8 identity_valid) {
    u8 action = identity_valid && parent_valid
                    ? k_tcp_traceparent_existing_parent_continue_plaintext
                    : k_tcp_traceparent_existing_parent_none;
    if (identity_valid && tcp_options_enabled &&
        tcp_traceparent_legacy_option_allowed(remote_parent_bridge_enabled)) {
        action |= k_tcp_traceparent_existing_parent_schedule_legacy;
    }
    return action;
}

static __always_inline enum tcp_traceparent_legacy_opt_len_action
tcp_traceparent_legacy_opt_len_action(u8 remote_parent_bridge_enabled, u8 storage_present) {
    if (!storage_present) {
        return k_tcp_traceparent_legacy_opt_len_none;
    }
    return tcp_traceparent_legacy_option_allowed(remote_parent_bridge_enabled)
               ? k_tcp_traceparent_legacy_opt_len_reserve
               : k_tcp_traceparent_legacy_opt_len_delete;
}

static __always_inline u8 tcp_traceparent_fits_single_segment(u32 payload_len, u32 mss) {
    return payload_len > 0 && mss > k_tcp_header_option_bytes &&
           payload_len <= mss - k_tcp_header_option_bytes;
}

static __always_inline u8 tcp_traceparent_write_packet_valid(u32 packet_len, u32 tcp_header_len) {
    return tcp_header_len >= k_tcp_base_header_bytes &&
           tcp_header_len <= k_tcp_base_header_bytes + k_tcp_header_option_bytes &&
           packet_len > tcp_header_len;
}

static __always_inline u8 tcp_sequence_before(u32 first, u32 second) {
    return (s32)(first - second) < 0;
}

static __always_inline u8 tcp_traceparent_len_may_contain_target(u32 snd_nxt,
                                                                 u32 packet_len,
                                                                 u32 target) {
    return packet_len > 0 && !tcp_sequence_before(target, snd_nxt) && target - snd_nxt < packet_len;
}

static __always_inline enum tcp_traceparent_target_position
tcp_traceparent_target_position(u32 sequence, u32 payload_len, u32 target) {
    if (!payload_len) {
        return k_tcp_traceparent_target_invalid;
    }
    if (target == sequence) {
        return k_tcp_traceparent_target_at_segment_start;
    }
    if (tcp_sequence_before(sequence, target)) {
        return target - sequence < payload_len ? k_tcp_traceparent_target_inside_segment
                                               : k_tcp_traceparent_target_after_segment;
    }
    return k_tcp_traceparent_target_before_segment;
}

static __always_inline enum tcp_traceparent_write_action tcp_traceparent_write_action(
    enum tcp_traceparent_target_position position, u32 packet_len, u32 mss) {
    if (position == k_tcp_traceparent_target_after_segment) {
        return k_tcp_traceparent_write_retry;
    }
    if (position != k_tcp_traceparent_target_at_segment_start) {
        return k_tcp_traceparent_write_miss;
    }
    return tcp_traceparent_fits_single_segment(packet_len, mss) ? k_tcp_traceparent_write_emit
                                                                : k_tcp_traceparent_write_segmented;
}

static __always_inline enum tcp_traceparent_write_action tcp_traceparent_write_packet_action(
    enum tcp_traceparent_target_position position, u32 packet_len, u32 tcp_header_len, u32 mss) {
    if (!tcp_traceparent_write_packet_valid(packet_len, tcp_header_len)) {
        return k_tcp_traceparent_write_miss;
    }
    return tcp_traceparent_write_action(position, packet_len - tcp_header_len, mss);
}
