// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/java_remote_parent.h>
#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/scratch_mem.h>
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
    u64 netns_cookie;
    u64 incoming_generation;
    u64 socket_cookie;
    u32 netns;
    u32 reserved2;
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

_Static_assert(sizeof(java_remote_parent_connection_t) == 56,
               "java remote-parent connection size mismatch");
_Static_assert(sizeof(java_remote_parent_owner_t) == 24, "java remote-parent owner size mismatch");
_Static_assert(sizeof(java_remote_parent_claim_t) == 24, "java remote-parent claim size mismatch");
_Static_assert(sizeof(java_remote_parent_data_signal_key_t) == 24,
               "java remote-parent data-signal key size mismatch");
_Static_assert(sizeof(java_remote_parent_data_ack_t) == 72,
               "java remote-parent data acknowledgement size mismatch");

typedef struct java_remote_parent_connection_keys {
    connection_info_ns_t netns;
    connection_info_netns_cookie_t cookie;
} java_remote_parent_connection_keys_t;

SCRATCH_MEM_TYPED(java_remote_parent_connection_keys, java_remote_parent_connection_keys_t)
SCRATCH_MEM_TYPED(java_remote_parent_connection_value, java_remote_parent_connection_t)

static __always_inline java_remote_parent_connection_keys_t *java_remote_parent_connection_keys_for(
    const connection_info_t *connection, u32 netns, u64 netns_cookie) {
    java_remote_parent_connection_keys_t *keys = java_remote_parent_connection_keys_mem();
    if (!keys || (!netns && !netns_cookie)) {
        return NULL;
    }
    __builtin_memcpy(&keys->netns.connection, connection, sizeof(keys->netns.connection));
    keys->netns.netns = netns;
    __builtin_memcpy(&keys->cookie.connection, connection, sizeof(keys->cookie.connection));
    keys->cookie.reserved = 0;
    keys->cookie.netns_cookie = netns_cookie;
    return keys;
}

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
    __type(key, connection_info_netns_cookie_t);
    __type(value, java_remote_parent_connection_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_remote_parent_cookie_connections SEC(".maps");

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

static __always_inline u8
java_remote_parent_connection_matches_in_netns(const connection_info_t *connection,
                                               u32 netns,
                                               const pid_key_t *owner,
                                               u64 generation,
                                               u64 incoming_generation,
                                               u64 socket_cookie) {
    java_remote_parent_connection_keys_t *keys =
        java_remote_parent_connection_keys_for(connection, netns, 0);
    if (!keys) {
        return 0;
    }
    const java_remote_parent_connection_t *staged =
        bpf_map_lookup_elem(&java_remote_parent_connections, &keys->netns);
    if (!staged || staged->reserved != 0 || staged->reserved2 != 0 ||
        staged->generation != generation || staged->netns != netns || !staged->netns_cookie ||
        !staged->incoming_generation || !staged->socket_cookie ||
        (incoming_generation && staged->incoming_generation != incoming_generation) ||
        (socket_cookie && staged->socket_cookie != socket_cookie) ||
        staged->owner.tid != owner->tid || staged->owner.pid != owner->pid ||
        staged->owner.ns != owner->ns) {
        return 0;
    }

    __builtin_memcpy(&keys->cookie.connection, connection, sizeof(keys->cookie.connection));
    keys->cookie.reserved = 0;
    keys->cookie.netns_cookie = staged->netns_cookie;
    const java_remote_parent_connection_t *cookie_staged =
        bpf_map_lookup_elem(&java_remote_parent_cookie_connections, &keys->cookie);
    return cookie_staged && cookie_staged->generation == generation &&
           cookie_staged->reserved == 0 && cookie_staged->reserved2 == 0 &&
           cookie_staged->netns == netns && cookie_staged->netns_cookie == staged->netns_cookie &&
           cookie_staged->incoming_generation == staged->incoming_generation &&
           cookie_staged->socket_cookie == staged->socket_cookie &&
           cookie_staged->owner.tid == owner->tid && cookie_staged->owner.pid == owner->pid &&
           cookie_staged->owner.ns == owner->ns;
}

static __always_inline u8
java_remote_parent_connection_matches_socket_in_netns(const connection_info_t *connection,
                                                      u32 netns,
                                                      const pid_key_t *owner,
                                                      u64 generation,
                                                      u64 incoming_generation,
                                                      u64 socket_cookie) {
    return socket_cookie &&
           java_remote_parent_connection_matches_in_netns(
               connection, netns, owner, generation, incoming_generation, socket_cookie);
}

static __always_inline u8 java_remote_parent_connection_matches(const connection_info_t *connection,
                                                                const pid_key_t *owner,
                                                                u64 generation) {
    return java_remote_parent_connection_matches_in_netns(
        connection, task_netns(), owner, generation, 0, 0);
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
    k_java_remote_parent_stat_candidate_ambiguous = 23,
    k_java_remote_parent_stat_candidate_overload = 24,
    k_java_remote_parent_stat_handoff_valid = 25,
    k_java_remote_parent_stat_candidate_valid = 26,
    k_java_remote_parent_stat_candidate_malformed = 27,
    k_java_remote_parent_stat_inject_valid = 28,
    k_java_remote_parent_stat_inject_missing = 29,
    k_java_remote_parent_stat_inject_stale = 30,
    k_java_remote_parent_stat_inject_ambiguous = 31,
    k_java_remote_parent_stat_inject_malformed = 32,
    k_java_remote_parent_stat_inject_overload = 33,
    k_java_remote_parent_stat_inject_segmented = 34,
    k_java_remote_parent_stat_max = 35,
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
    if (bpf_map_lookup_elem(&java_remote_parent_claims, &key)) {
        return 1;
    }
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
java_remote_parent_delete_connection_indexes(const connection_info_t *connection,
                                             const java_remote_parent_connection_t *staged) {
    if (!staged || staged->reserved != 0 || staged->reserved2 != 0 || !staged->netns ||
        !staged->netns_cookie || !staged->incoming_generation || !staged->socket_cookie) {
        return;
    }

    java_remote_parent_connection_t *copy = java_remote_parent_connection_value_mem();
    if (!copy) {
        return;
    }
    if (copy != staged) {
        __builtin_memcpy(copy, staged, sizeof(*copy));
    }
    java_remote_parent_connection_keys_t *keys =
        java_remote_parent_connection_keys_for(connection, copy->netns, copy->netns_cookie);
    if (!keys) {
        return;
    }
    const java_remote_parent_connection_t *netns_staged =
        bpf_map_lookup_elem(&java_remote_parent_connections, &keys->netns);
    if (netns_staged && netns_staged->reserved == 0 && netns_staged->reserved2 == 0 &&
        netns_staged->generation == copy->generation && netns_staged->netns == copy->netns &&
        netns_staged->netns_cookie == copy->netns_cookie &&
        netns_staged->incoming_generation == copy->incoming_generation &&
        netns_staged->socket_cookie == copy->socket_cookie &&
        netns_staged->owner.tid == copy->owner.tid && netns_staged->owner.pid == copy->owner.pid &&
        netns_staged->owner.ns == copy->owner.ns) {
        bpf_map_delete_elem(&java_remote_parent_connections, &keys->netns);
    }

    const java_remote_parent_connection_t *cookie_staged =
        bpf_map_lookup_elem(&java_remote_parent_cookie_connections, &keys->cookie);
    if (cookie_staged && cookie_staged->reserved == 0 && cookie_staged->reserved2 == 0 &&
        cookie_staged->generation == copy->generation && cookie_staged->netns == copy->netns &&
        cookie_staged->netns_cookie == copy->netns_cookie &&
        cookie_staged->incoming_generation == copy->incoming_generation &&
        cookie_staged->socket_cookie == copy->socket_cookie &&
        cookie_staged->owner.tid == copy->owner.tid &&
        cookie_staged->owner.pid == copy->owner.pid && cookie_staged->owner.ns == copy->owner.ns) {
        bpf_map_delete_elem(&java_remote_parent_cookie_connections, &keys->cookie);
    }
}

static __always_inline void
java_remote_parent_invalidate_connection(const connection_info_t *connection,
                                         const java_remote_parent_connection_t *staged,
                                         u64 incoming_generation) {
    if (!staged || !staged->netns || !staged->netns_cookie) {
        return;
    }

    java_remote_parent_connection_t *copy = java_remote_parent_connection_value_mem();
    if (!copy) {
        return;
    }
    __builtin_memcpy(copy, staged, sizeof(*copy));
    if (incoming_generation && copy->incoming_generation != incoming_generation) {
        return;
    }
    const java_remote_parent_key_t key = {
        .owner = copy->owner,
        .generation = copy->generation,
    };
    const u8 marked = java_remote_parent_mark_generation_ambiguous(&copy->owner, copy->generation);
    if (marked && !java_remote_parent_generation_ambiguous(&key)) {
        return;
    }

    java_remote_parent_delete_connection_indexes(connection, copy);
    if (!marked) {
        java_remote_parent_cleanup_fallback_generation(&copy->owner, copy->generation);
    }
}

static __always_inline void
java_remote_parent_mark_connection_ambiguous_in_netns(const connection_info_t *connection,
                                                      u32 netns) {
    java_remote_parent_connection_keys_t *keys =
        java_remote_parent_connection_keys_for(connection, netns, 0);
    if (!keys) {
        return;
    }
    const java_remote_parent_connection_t *staged =
        bpf_map_lookup_elem(&java_remote_parent_connections, &keys->netns);
    java_remote_parent_invalidate_connection(connection, staged, 0);
}

static __always_inline void java_remote_parent_mark_connection_ambiguous_in_netns_cookie(
    const connection_info_t *connection, u64 netns_cookie, u64 incoming_generation) {
    if (!netns_cookie) {
        return;
    }
    java_remote_parent_connection_keys_t *keys =
        java_remote_parent_connection_keys_for(connection, 0, netns_cookie);
    if (!keys) {
        return;
    }
    const java_remote_parent_connection_t *staged =
        bpf_map_lookup_elem(&java_remote_parent_cookie_connections, &keys->cookie);
    java_remote_parent_invalidate_connection(connection, staged, incoming_generation);
}

static __always_inline void java_remote_parent_mark_connection_ambiguous_in_netns_for_socket(
    const connection_info_t *connection, u32 netns, u64 socket_cookie) {
    if (!netns || !socket_cookie) {
        return;
    }
    java_remote_parent_connection_keys_t *keys =
        java_remote_parent_connection_keys_for(connection, netns, 0);
    if (!keys) {
        return;
    }
    const java_remote_parent_connection_t *staged =
        bpf_map_lookup_elem(&java_remote_parent_connections, &keys->netns);
    if (staged && staged->socket_cookie == socket_cookie) {
        java_remote_parent_invalidate_connection(connection, staged, 0);
    }
}

static __always_inline void java_remote_parent_mark_connection_ambiguous_in_netns_cookie_for_socket(
    const connection_info_t *connection,
    u64 netns_cookie,
    u64 socket_cookie,
    u64 incoming_generation) {
    if (!netns_cookie || !socket_cookie) {
        return;
    }
    java_remote_parent_connection_keys_t *keys =
        java_remote_parent_connection_keys_for(connection, 0, netns_cookie);
    if (!keys) {
        return;
    }
    const java_remote_parent_connection_t *staged =
        bpf_map_lookup_elem(&java_remote_parent_cookie_connections, &keys->cookie);
    if (staged && staged->socket_cookie == socket_cookie) {
        java_remote_parent_invalidate_connection(connection, staged, incoming_generation);
    }
}

static __always_inline void
java_remote_parent_mark_connection_ambiguous(const connection_info_t *connection) {
    java_remote_parent_mark_connection_ambiguous_in_netns(connection, task_netns());
}
