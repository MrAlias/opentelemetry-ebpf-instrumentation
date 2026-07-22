// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/tp_info.h>

enum {
    k_java_remote_parent_abi_version = 1,
    k_java_remote_parent_response_size = 64,
    k_java_remote_parent_socket_level = 0x4f42,
    k_java_remote_parent_socket_take = 0x4a01,
    k_java_remote_parent_socket_discard = 0x4a02,
    k_java_remote_parent_socket_negotiate = 0x4a03,
    k_java_remote_parent_socket_data_ack = 0x4a04,
    k_java_remote_parent_socket_health = 0x4a05,
};

volatile const bool java_remote_parent_enabled;

enum java_remote_parent_status : u8 {
    k_java_remote_parent_status_unknown = 0,
    k_java_remote_parent_status_valid = 1,
    k_java_remote_parent_status_missing = 2,
    k_java_remote_parent_status_stale = 3,
    k_java_remote_parent_status_unsupported = 4,
    k_java_remote_parent_status_malformed = 5,
    k_java_remote_parent_status_version_mismatch = 6,
    k_java_remote_parent_status_ambiguous = 7,
    k_java_remote_parent_status_unauthorized = 8,
    k_java_remote_parent_status_already_consumed = 9,
    k_java_remote_parent_status_timeout = 10,
    k_java_remote_parent_status_overload = 11,
    k_java_remote_parent_status_transport_error = 12,
    k_java_remote_parent_status_disabled = 13,
};

typedef struct java_remote_parent_response {
    unsigned char magic[4];
    u16 version_le;
    u16 size_le;
    u8 status;
    u8 flags;
    unsigned char reserved0[6];
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char span_id[SPAN_ID_SIZE_BYTES];
    u64 generation_le;
    u64 observed_monotime_ns_le;
    unsigned char reserved1[8];
} java_remote_parent_response_t;

_Static_assert(sizeof(java_remote_parent_response_t) == k_java_remote_parent_response_size,
               "java remote-parent response size mismatch");
_Static_assert(offsetof(java_remote_parent_response_t, version_le) == 4,
               "java remote-parent version offset mismatch");
_Static_assert(offsetof(java_remote_parent_response_t, size_le) == 6,
               "java remote-parent size offset mismatch");
_Static_assert(offsetof(java_remote_parent_response_t, status) == 8,
               "java remote-parent status offset mismatch");
_Static_assert(offsetof(java_remote_parent_response_t, flags) == 9,
               "java remote-parent flags offset mismatch");
_Static_assert(offsetof(java_remote_parent_response_t, reserved0) == 10,
               "java remote-parent reserved prefix offset mismatch");
_Static_assert(offsetof(java_remote_parent_response_t, trace_id) == 16,
               "java remote-parent trace ID offset mismatch");
_Static_assert(offsetof(java_remote_parent_response_t, span_id) == 32,
               "java remote-parent span ID offset mismatch");
_Static_assert(offsetof(java_remote_parent_response_t, generation_le) == 40,
               "java remote-parent generation offset mismatch");
_Static_assert(offsetof(java_remote_parent_response_t, observed_monotime_ns_le) == 48,
               "java remote-parent observation offset mismatch");
_Static_assert(offsetof(java_remote_parent_response_t, reserved1) == 56,
               "java remote-parent reserved suffix offset mismatch");

static __always_inline u16 java_remote_parent_cpu_to_le16(u16 value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return value;
#else
    return __builtin_bswap16(value);
#endif
}

static __always_inline u64 java_remote_parent_cpu_to_le64(u64 value) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return value;
#else
    return __builtin_bswap64(value);
#endif
}

static __always_inline u64 java_remote_parent_le64_to_cpu(u64 value) {
    return java_remote_parent_cpu_to_le64(value);
}

static __always_inline u8 java_remote_parent_observation_stale(u64 now,
                                                               u64 observed_monotime_ns,
                                                               u64 max_age_ns) {
    return now < observed_monotime_ns || (max_age_ns && now - observed_monotime_ns > max_age_ns);
}

static __always_inline u8 java_remote_parent_incoming_claim_allowed(
    u8 process_registered, const tp_info_pid_t *incoming, const u64 *incoming_generation) {
    return !process_registered || (incoming && incoming_generation);
}

static __always_inline void
java_remote_parent_init_response(java_remote_parent_response_t *response,
                                 enum java_remote_parent_status status,
                                 u64 generation,
                                 u64 observed_monotime_ns) {
    __builtin_memset(response, 0, sizeof(*response));
    response->magic[0] = 'O';
    response->magic[1] = 'B';
    response->magic[2] = 'I';
    response->magic[3] = 'J';
    response->version_le = java_remote_parent_cpu_to_le16(k_java_remote_parent_abi_version);
    response->size_le = java_remote_parent_cpu_to_le16(k_java_remote_parent_response_size);
    response->status = status;
    response->generation_le = java_remote_parent_cpu_to_le64(generation);
    response->observed_monotime_ns_le = java_remote_parent_cpu_to_le64(observed_monotime_ns);
}

static __always_inline void java_remote_parent_set_context(java_remote_parent_response_t *response,
                                                           const tp_info_t *tp) {
    response->flags = tp->flags;
    __builtin_memcpy(response->trace_id, tp->trace_id, sizeof(response->trace_id));
    __builtin_memcpy(response->span_id, tp->span_id, sizeof(response->span_id));
}
