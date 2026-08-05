// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/protocol_defs.h>

enum java_remote_parent_data_operation : u8 {
    k_java_remote_parent_data_operation_invalid = 0,
    k_java_remote_parent_data_operation_send = 1,
    k_java_remote_parent_data_operation_receive = 2,
    k_java_remote_parent_data_operation_http1_receive_start = 14,
    k_java_remote_parent_data_operation_http1_receive_continue = 15,
    k_java_remote_parent_data_operation_http1_receive_reset = 16,
};

enum java_remote_parent_receive_action : u8 {
    k_java_remote_parent_receive_action_invalid = 0,
    k_java_remote_parent_receive_action_legacy = 1,
    k_java_remote_parent_receive_action_http1_start = 2,
    k_java_remote_parent_receive_action_http1_continue = 3,
    k_java_remote_parent_receive_action_http1_reset = 4,
};

enum {
    k_java_remote_parent_parser_direction_invalid = 0xff,
    k_java_remote_parent_data_operation_offset = 0,
    k_java_remote_parent_data_connection_offset = 1,
    k_java_remote_parent_data_length_offset = 37,
    k_java_remote_parent_data_signal_offset = 41,
    k_java_remote_parent_data_legacy_payload_offset = 49,
    k_java_remote_parent_data_http1_lifecycle_offset = 49,
    k_java_remote_parent_data_http1_request_sequence_offset = 57,
    k_java_remote_parent_data_http1_payload_offset = 65,
    k_java_remote_parent_data_max_payload_len = 1 << 16,
};

_Static_assert(sizeof(connection_info_t) == 36, "java remote-parent wire connection size mismatch");
_Static_assert(k_java_remote_parent_data_connection_offset == 1,
               "java remote-parent wire connection offset mismatch");
_Static_assert(k_java_remote_parent_data_length_offset == 37,
               "java remote-parent wire length offset mismatch");
_Static_assert(k_java_remote_parent_data_length_offset ==
                   k_java_remote_parent_data_connection_offset + sizeof(connection_info_t),
               "java remote-parent wire length offset mismatch");
_Static_assert(k_java_remote_parent_data_signal_offset == 41,
               "java remote-parent wire signal offset mismatch");
_Static_assert(k_java_remote_parent_data_signal_offset ==
                   k_java_remote_parent_data_length_offset + sizeof(u32),
               "java remote-parent wire signal offset mismatch");
_Static_assert(k_java_remote_parent_data_legacy_payload_offset == 49,
               "java remote-parent legacy payload offset mismatch");
_Static_assert(k_java_remote_parent_data_legacy_payload_offset ==
                   k_java_remote_parent_data_signal_offset + sizeof(u64),
               "java remote-parent legacy payload offset mismatch");
_Static_assert(k_java_remote_parent_data_http1_lifecycle_offset == 49,
               "java remote-parent HTTP/1 lifecycle offset mismatch");
_Static_assert(k_java_remote_parent_data_http1_request_sequence_offset == 57,
               "java remote-parent HTTP/1 request sequence offset mismatch");
_Static_assert(k_java_remote_parent_data_http1_request_sequence_offset ==
                   k_java_remote_parent_data_http1_lifecycle_offset + sizeof(u64),
               "java remote-parent HTTP/1 request sequence offset mismatch");
_Static_assert(k_java_remote_parent_data_http1_payload_offset == 65,
               "java remote-parent HTTP/1 payload offset mismatch");
_Static_assert(k_java_remote_parent_data_http1_payload_offset ==
                   k_java_remote_parent_data_http1_request_sequence_offset + sizeof(u64),
               "java remote-parent HTTP/1 payload offset mismatch");

static __always_inline enum java_remote_parent_data_operation
java_remote_parent_decode_data_operation(u8 wire_operation) {
    switch (wire_operation) {
    case k_java_remote_parent_data_operation_send:
        return k_java_remote_parent_data_operation_send;
    case k_java_remote_parent_data_operation_receive:
        return k_java_remote_parent_data_operation_receive;
    case k_java_remote_parent_data_operation_http1_receive_start:
        return k_java_remote_parent_data_operation_http1_receive_start;
    case k_java_remote_parent_data_operation_http1_receive_continue:
        return k_java_remote_parent_data_operation_http1_receive_continue;
    case k_java_remote_parent_data_operation_http1_receive_reset:
        return k_java_remote_parent_data_operation_http1_receive_reset;
    default:
        return k_java_remote_parent_data_operation_invalid;
    }
}

static __always_inline u8
java_remote_parent_data_parser_direction(enum java_remote_parent_data_operation operation) {
    switch (operation) {
    case k_java_remote_parent_data_operation_send:
        return TCP_SEND;
    case k_java_remote_parent_data_operation_receive:
    case k_java_remote_parent_data_operation_http1_receive_start:
    case k_java_remote_parent_data_operation_http1_receive_continue:
        return TCP_RECV;
    default:
        return k_java_remote_parent_parser_direction_invalid;
    }
}

static __always_inline enum java_remote_parent_receive_action
java_remote_parent_data_receive_action(enum java_remote_parent_data_operation operation) {
    switch (operation) {
    case k_java_remote_parent_data_operation_send:
    case k_java_remote_parent_data_operation_receive:
        return k_java_remote_parent_receive_action_legacy;
    case k_java_remote_parent_data_operation_http1_receive_start:
        return k_java_remote_parent_receive_action_http1_start;
    case k_java_remote_parent_data_operation_http1_receive_continue:
        return k_java_remote_parent_receive_action_http1_continue;
    case k_java_remote_parent_data_operation_http1_receive_reset:
        return k_java_remote_parent_receive_action_http1_reset;
    default:
        return k_java_remote_parent_receive_action_invalid;
    }
}

static __always_inline u8
java_remote_parent_data_starts_receive_boundary(enum java_remote_parent_data_operation operation) {
    return operation == k_java_remote_parent_data_operation_receive ||
           operation == k_java_remote_parent_data_operation_http1_receive_start;
}

static __always_inline u8
java_remote_parent_http1_prefix_valid(enum java_remote_parent_data_operation operation,
                                      u32 payload_len,
                                      u64 data_signal_nonce,
                                      u64 lifecycle_id,
                                      u64 request_sequence) {
    if (!lifecycle_id || !request_sequence) {
        return 0;
    }

    switch (operation) {
    case k_java_remote_parent_data_operation_http1_receive_start:
        return data_signal_nonce && payload_len &&
               payload_len <= k_java_remote_parent_data_max_payload_len;
    case k_java_remote_parent_data_operation_http1_receive_continue:
        return !data_signal_nonce && payload_len &&
               payload_len <= k_java_remote_parent_data_max_payload_len;
    case k_java_remote_parent_data_operation_http1_receive_reset:
        return !data_signal_nonce && !payload_len;
    default:
        return 0;
    }
}

#ifndef JAVA_REMOTE_PARENT_BEGIN_DATA_RECEIVE
#define JAVA_REMOTE_PARENT_BEGIN_DATA_RECEIVE(process_capability)                                  \
    java_remote_parent_begin_data_receive_for_capability(process_capability)
#define JAVA_REMOTE_PARENT_BEGIN_DATA_RECEIVE_DEFAULT
#endif

// Cross the request boundary before the registration gate. An authorized
// receive must detach even when its LRU registration disappeared. Callers
// must not inspect the advisory tuple unless this gate succeeds.
static __always_inline u8 java_remote_parent_begin_receive(
    u8 enabled, u8 data_hook_ready, u8 registered, u8 receive_boundary, u64 process_capability) {
    if (enabled && data_hook_ready && receive_boundary) {
        JAVA_REMOTE_PARENT_BEGIN_DATA_RECEIVE(process_capability);
    }
    return registered;
}

#ifdef JAVA_REMOTE_PARENT_BEGIN_DATA_RECEIVE_DEFAULT
#undef JAVA_REMOTE_PARENT_BEGIN_DATA_RECEIVE_DEFAULT
#undef JAVA_REMOTE_PARENT_BEGIN_DATA_RECEIVE
#endif
