// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/java_remote_parent.h>
#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/sock_port_ns.h>

#include <maps/java_remote_parent_fallback.h>

#include <pid/types/pid_key.h>

enum java_remote_parent_lifecycle : u8 {
    k_java_remote_parent_lifecycle_active = 1,
    k_java_remote_parent_lifecycle_consumed = 2,
    k_java_remote_parent_lifecycle_discarded = 3,
    k_java_remote_parent_lifecycle_stale = 4,
    k_java_remote_parent_lifecycle_ambiguous = 5,
    k_java_remote_parent_lifecycle_publishing = 6,
};

typedef struct java_remote_parent_key {
    pid_key_t owner;
    u32 reserved;
    u64 generation;
} java_remote_parent_key_t;

typedef struct java_remote_parent_owner {
    u64 generation;
    u64 process_incarnation;
    u8 lifecycle;
    unsigned char reserved[7];
} java_remote_parent_owner_t;

typedef struct java_remote_parent_connection {
    pid_key_t owner;
    u32 reserved;
    u64 generation;
} java_remote_parent_connection_t;

typedef struct java_remote_parent_claim {
    u64 observed_monotime_ns;
    u64 process_incarnation;
    u8 lifecycle;
    unsigned char reserved[7];
} java_remote_parent_claim_t;

typedef struct java_remote_parent_data_signal_key {
    pid_key_t process;
    u32 reserved;
    u64 nonce;
} java_remote_parent_data_signal_key_t;

typedef struct java_remote_parent_data_ack {
    pid_key_t owner;
    u32 reserved;
    u64 generation;
    connection_info_t connection;
    u32 connection_netns;
    u32 reserved2;
    unsigned char reserved3[4];
} java_remote_parent_data_ack_t;

_Static_assert(sizeof(java_remote_parent_connection_t) == 24,
               "java remote-parent connection size mismatch");
_Static_assert(sizeof(java_remote_parent_owner_t) == 24, "java remote-parent owner size mismatch");
_Static_assert(sizeof(java_remote_parent_claim_t) == 24, "java remote-parent claim size mismatch");
_Static_assert(sizeof(java_remote_parent_data_signal_key_t) == 24,
               "java remote-parent data-signal key size mismatch");
_Static_assert(sizeof(java_remote_parent_data_ack_t) == 72,
               "java remote-parent data acknowledgement size mismatch");

enum java_remote_parent_data_hook_state : u32 {
    k_java_remote_parent_data_hook_unavailable = 0,
    k_java_remote_parent_data_hook_ready = 1,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 1);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_remote_parent_data_hook_readiness SEC(".maps");

static __always_inline u8 java_remote_parent_data_hook_is_ready() {
    const u32 key = 0;
    const u32 *state = bpf_map_lookup_elem(&java_remote_parent_data_hook_readiness, &key);
    return state && *state == k_java_remote_parent_data_hook_ready;
}

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_key_t);
    __type(value, u64);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_remote_parent_data_signals SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, java_remote_parent_data_signal_key_t);
    __type(value, java_remote_parent_data_ack_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_remote_parent_data_acks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, connection_info_ns_t);
    __type(value, java_remote_parent_connection_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_remote_parent_connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, java_remote_parent_key_t);
    __type(value, java_remote_parent_claim_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_remote_parent_claims SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, pid_key_t);
    __type(value, java_remote_parent_owner_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_remote_parent_owners SEC(".maps");

static __always_inline u8 java_remote_parent_connection_matches_in_netns(
    const connection_info_t *connection, u32 netns, const pid_key_t *owner, u64 generation) {
    const connection_info_ns_t key = connection_info_with_netns(connection, netns);
    const java_remote_parent_connection_t *staged =
        bpf_map_lookup_elem(&java_remote_parent_connections, &key);
    return staged && staged->generation == generation && staged->reserved == 0 &&
           staged->owner.tid == owner->tid && staged->owner.pid == owner->pid &&
           staged->owner.ns == owner->ns;
}

static __always_inline u8 java_remote_parent_connection_matches(const connection_info_t *connection,
                                                                const pid_key_t *owner,
                                                                u64 generation) {
    return java_remote_parent_connection_matches_in_netns(
        connection, task_netns(), owner, generation);
}

enum java_remote_parent_stat : u32 {
    k_java_remote_parent_stat_stage_valid = 0,
    k_java_remote_parent_stat_stage_ambiguous = 1,
    k_java_remote_parent_stat_stage_malformed = 2,
    k_java_remote_parent_stat_stage_overload = 3,
    k_java_remote_parent_stat_take_valid = 4,
    k_java_remote_parent_stat_take_missing = 5,
    k_java_remote_parent_stat_take_stale = 6,
    k_java_remote_parent_stat_take_ambiguous = 7,
    k_java_remote_parent_stat_take_unauthorized = 8,
    k_java_remote_parent_stat_take_already_consumed = 9,
    k_java_remote_parent_stat_take_malformed = 10,
    k_java_remote_parent_stat_take_overload = 11,
    k_java_remote_parent_stat_discard_valid = 12,
    k_java_remote_parent_stat_discard_missing = 13,
    k_java_remote_parent_stat_discard_stale = 14,
    k_java_remote_parent_stat_discard_ambiguous = 15,
    k_java_remote_parent_stat_discard_unauthorized = 16,
    k_java_remote_parent_stat_discard_already_consumed = 17,
    k_java_remote_parent_stat_discard_malformed = 18,
    k_java_remote_parent_stat_discard_overload = 19,
    k_java_remote_parent_stat_negotiate_missing = 20,
    k_java_remote_parent_stat_negotiate_unauthorized = 21,
    k_java_remote_parent_stat_negotiate_overload = 22,
    k_java_remote_parent_stat_max = 23,
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, java_remote_parent_key_t);
    __type(value, u64);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_remote_parent_ambiguity SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, k_java_remote_parent_stat_max);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_remote_parent_stats SEC(".maps");

static __always_inline void java_remote_parent_stat_add(enum java_remote_parent_stat stat) {
    const u32 key = stat;
    u64 *count = bpf_map_lookup_elem(&java_remote_parent_stats, &key);
    if (count) {
        (*count)++;
    }
}

static __always_inline void
java_remote_parent_negotiate_stat(enum java_remote_parent_status status) {
    if (status == k_java_remote_parent_status_missing) {
        java_remote_parent_stat_add(k_java_remote_parent_stat_negotiate_missing);
    } else if (status == k_java_remote_parent_status_overload) {
        java_remote_parent_stat_add(k_java_remote_parent_stat_negotiate_overload);
    } else {
        java_remote_parent_stat_add(k_java_remote_parent_stat_negotiate_unauthorized);
    }
}

static __always_inline void
java_remote_parent_retrieval_stat(u8 discard, enum java_remote_parent_status status) {
    if (discard) {
        switch (status) {
        case k_java_remote_parent_status_valid:
            java_remote_parent_stat_add(k_java_remote_parent_stat_discard_valid);
            return;
        case k_java_remote_parent_status_stale:
            java_remote_parent_stat_add(k_java_remote_parent_stat_discard_stale);
            return;
        case k_java_remote_parent_status_ambiguous:
            java_remote_parent_stat_add(k_java_remote_parent_stat_discard_ambiguous);
            return;
        case k_java_remote_parent_status_unauthorized:
            java_remote_parent_stat_add(k_java_remote_parent_stat_discard_unauthorized);
            return;
        case k_java_remote_parent_status_already_consumed:
            java_remote_parent_stat_add(k_java_remote_parent_stat_discard_already_consumed);
            return;
        case k_java_remote_parent_status_malformed:
            java_remote_parent_stat_add(k_java_remote_parent_stat_discard_malformed);
            return;
        case k_java_remote_parent_status_overload:
        case k_java_remote_parent_status_transport_error:
            java_remote_parent_stat_add(k_java_remote_parent_stat_discard_overload);
            return;
        default:
            java_remote_parent_stat_add(k_java_remote_parent_stat_discard_missing);
            return;
        }
    }

    switch (status) {
    case k_java_remote_parent_status_valid:
        java_remote_parent_stat_add(k_java_remote_parent_stat_take_valid);
        return;
    case k_java_remote_parent_status_stale:
        java_remote_parent_stat_add(k_java_remote_parent_stat_take_stale);
        return;
    case k_java_remote_parent_status_ambiguous:
        java_remote_parent_stat_add(k_java_remote_parent_stat_take_ambiguous);
        return;
    case k_java_remote_parent_status_unauthorized:
        java_remote_parent_stat_add(k_java_remote_parent_stat_take_unauthorized);
        return;
    case k_java_remote_parent_status_already_consumed:
        java_remote_parent_stat_add(k_java_remote_parent_stat_take_already_consumed);
        return;
    case k_java_remote_parent_status_malformed:
        java_remote_parent_stat_add(k_java_remote_parent_stat_take_malformed);
        return;
    case k_java_remote_parent_status_overload:
    case k_java_remote_parent_status_transport_error:
        java_remote_parent_stat_add(k_java_remote_parent_stat_take_overload);
        return;
    default:
        java_remote_parent_stat_add(k_java_remote_parent_stat_take_missing);
        return;
    }
}

static __always_inline u8 java_remote_parent_mark_generation_ambiguous(const pid_key_t *owner,
                                                                       u64 generation) {
    if (!generation) {
        return 0;
    }

    const java_remote_parent_key_t key = {
        .owner = *owner,
        .generation = generation,
    };
    const u64 observed_monotime_ns = bpf_ktime_get_ns();
    if (bpf_map_update_elem(&java_remote_parent_ambiguity, &key, &observed_monotime_ns, BPF_ANY) !=
        0) {
        return 0;
    }

    const java_remote_parent_owner_t *indexed =
        bpf_map_lookup_elem(&java_remote_parent_owners, owner);
    if (!indexed || indexed->generation != generation) {
        bpf_map_delete_elem(&java_remote_parent_ambiguity, &key);
        return 0;
    }
    return 1;
}

static __always_inline u8
java_remote_parent_generation_ambiguous(const java_remote_parent_key_t *key) {
    return bpf_map_lookup_elem(&java_remote_parent_ambiguity, key) != 0;
}

static __always_inline void
java_remote_parent_mark_connection_ambiguous_in_netns(const connection_info_t *connection,
                                                      u32 netns) {
    const connection_info_ns_t key = connection_info_with_netns(connection, netns);
    const java_remote_parent_connection_t *staged =
        bpf_map_lookup_elem(&java_remote_parent_connections, &key);
    if (!staged) {
        return;
    }

    const java_remote_parent_connection_t copy = *staged;
    bpf_map_delete_elem(&java_remote_parent_connections, &key);
    if (!java_remote_parent_mark_generation_ambiguous(&copy.owner, copy.generation)) {
        java_remote_parent_cleanup_fallback_generation(&copy.owner, copy.generation);
    }
}

static __always_inline void
java_remote_parent_mark_connection_ambiguous(const connection_info_t *connection) {
    java_remote_parent_mark_connection_ambiguous_in_netns(connection, task_netns());
}
