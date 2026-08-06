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

typedef union java_remote_parent_connection_key {
    connection_info_ns_t netns;
    connection_info_netns_cookie_t cookie;
} java_remote_parent_connection_key_t;

_Static_assert(sizeof(java_remote_parent_connection_key_t) == 48,
               "java remote-parent reusable connection key size mismatch");
_Static_assert(offsetof(connection_info_ns_t, connection) == 0,
               "namespaced connection bytes must lead the reusable key");
_Static_assert(offsetof(connection_info_netns_cookie_t, connection) == 0,
               "cookie connection bytes must lead the reusable key");

static __always_inline u8
java_remote_parent_connection_keys_init(java_remote_parent_connection_keys_t *keys,
                                        const connection_info_t *connection,
                                        u32 netns,
                                        u64 netns_cookie) {
    if (!keys || !connection || (!netns && !netns_cookie)) {
        return 0;
    }
    __builtin_memset(keys, 0, sizeof(*keys));
    __builtin_memcpy(&keys->netns.connection, connection, sizeof(keys->netns.connection));
    keys->netns.netns = netns;
    __builtin_memcpy(&keys->cookie.connection, connection, sizeof(keys->cookie.connection));
    keys->cookie.netns_cookie = netns_cookie;
    return 1;
}

static __always_inline u8 java_remote_parent_connection_netns_key_init(
    java_remote_parent_connection_key_t *key, const connection_info_t *connection, u32 netns) {
    if (!key || !connection || !netns) {
        return 0;
    }
    __builtin_memset(key, 0, sizeof(*key));
    __builtin_memcpy(&key->netns.connection, connection, sizeof(key->netns.connection));
    key->netns.netns = netns;
    return 1;
}

static __always_inline u8
java_remote_parent_connection_cookie_key_init(java_remote_parent_connection_key_t *key,
                                              const connection_info_t *connection,
                                              u64 netns_cookie) {
    if (!key || !connection || !netns_cookie) {
        return 0;
    }
    __builtin_memset(key, 0, sizeof(*key));
    __builtin_memcpy(&key->cookie.connection, connection, sizeof(key->cookie.connection));
    key->cookie.netns_cookie = netns_cookie;
    return 1;
}

static __always_inline u8 java_remote_parent_connection_key_rekey_cookie(
    java_remote_parent_connection_key_t *key, u64 netns_cookie) {
    if (!key || !netns_cookie) {
        return 0;
    }
    __builtin_memset((unsigned char *)key + sizeof(connection_info_t),
                     0,
                     sizeof(*key) - sizeof(connection_info_t));
    key->cookie.netns_cookie = netns_cookie;
    return 1;
}

static __always_inline u8
java_remote_parent_connection_key_rekey_netns(java_remote_parent_connection_key_t *key, u32 netns) {
    if (!key || !netns) {
        return 0;
    }
    __builtin_memset((unsigned char *)key + sizeof(connection_info_t),
                     0,
                     sizeof(*key) - sizeof(connection_info_t));
    key->netns.netns = netns;
    return 1;
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

// Valid generations are nonzero. Generation zero in the claim map is an
// owner-scoped, non-terminal detach guard. Keeping these helpers in the shared
// header lets physical invalidation publish a cancellation fence even when an
// exact publishing claim already owns the generation.
static __always_inline java_remote_parent_key_t
java_remote_parent_detach_guard_key(const pid_key_t *owner) {
    return (java_remote_parent_key_t){
        .owner = *owner,
    };
}

static __always_inline u8 java_remote_parent_owner_detach_guarded(const pid_key_t *owner) {
    const java_remote_parent_key_t guard_key = java_remote_parent_detach_guard_key(owner);
    return bpf_map_lookup_elem(&java_remote_parent_claims, &guard_key) != NULL;
}

static __always_inline u8 java_remote_parent_detach_guard_matches_at(
    const java_remote_parent_key_t *expected, const java_remote_parent_key_t *guard_key) {
    const java_remote_parent_claim_t *guard =
        bpf_map_lookup_elem(&java_remote_parent_claims, guard_key);
    return guard && guard->observed_monotime_ns &&
           guard->process_incarnation == expected->generation &&
           guard->lifecycle == k_java_remote_parent_lifecycle_publishing;
}

static __always_inline u8
java_remote_parent_detach_guard_matches(const java_remote_parent_key_t *expected) {
    const java_remote_parent_key_t guard_key =
        java_remote_parent_detach_guard_key(&expected->owner);
    return java_remote_parent_detach_guard_matches_at(expected, &guard_key);
}

static __always_inline u8 java_remote_parent_delete_exact_detach_guard_at(
    const java_remote_parent_key_t *guard_key, const java_remote_parent_claim_t *local_guard) {
    const java_remote_parent_claim_t *guard =
        bpf_map_lookup_elem(&java_remote_parent_claims, guard_key);
    if (!guard || __builtin_memcmp(guard, local_guard, sizeof(*local_guard)) != 0) {
        // Absence or replacement means the old guard was already released.
        return 1;
    }
    if (bpf_map_delete_elem(&java_remote_parent_claims, guard_key) != 0) {
        guard = bpf_map_lookup_elem(&java_remote_parent_claims, guard_key);
        // Report failure only while the exact old guard demonstrably remains.
        return !guard || __builtin_memcmp(guard, local_guard, sizeof(*local_guard)) != 0;
    }
    // Successful exact deletion is the release linearization point. A new
    // owner operation may publish another guard immediately afterward; that
    // successor must not make this completed release look like a failure.
    return 1;
}

static __always_inline u8 java_remote_parent_exact_detach_guard_matches_at(
    const java_remote_parent_key_t *guard_key, const java_remote_parent_claim_t *local_guard) {
    const java_remote_parent_claim_t *guard =
        bpf_map_lookup_elem(&java_remote_parent_claims, guard_key);
    return guard && __builtin_memcmp(guard, local_guard, sizeof(*local_guard)) == 0;
}

static __always_inline u8
java_remote_parent_acquire_detach_guard_at(const java_remote_parent_key_t *expected,
                                           const java_remote_parent_key_t *guard_key,
                                           java_remote_parent_claim_t *local_guard) {
    *local_guard = (java_remote_parent_claim_t){
        .observed_monotime_ns = bpf_ktime_get_ns(),
        .process_incarnation = expected->generation,
        .lifecycle = k_java_remote_parent_lifecycle_publishing,
    };
    return local_guard->observed_monotime_ns &&
           bpf_map_update_elem(&java_remote_parent_claims, guard_key, local_guard, BPF_NOEXIST) ==
               0 &&
           java_remote_parent_detach_guard_matches_at(expected, guard_key) &&
           java_remote_parent_exact_detach_guard_matches_at(guard_key, local_guard);
}

static __always_inline u8
java_remote_parent_connection_matches_in_netns_with_key(java_remote_parent_connection_key_t *key,
                                                        const connection_info_t *connection,
                                                        u32 netns,
                                                        const pid_key_t *owner,
                                                        u64 generation,
                                                        u64 incoming_generation,
                                                        u64 socket_cookie) {
    if (!java_remote_parent_connection_netns_key_init(key, connection, netns)) {
        return 0;
    }
    const java_remote_parent_connection_t *staged =
        bpf_map_lookup_elem(&java_remote_parent_connections, &key->netns);
    if (!staged || staged->reserved != 0 || staged->reserved2 != 0 ||
        staged->generation != generation || staged->netns != netns || !staged->netns_cookie ||
        !staged->incoming_generation || !staged->socket_cookie ||
        (incoming_generation && staged->incoming_generation != incoming_generation) ||
        (socket_cookie && staged->socket_cookie != socket_cookie) ||
        staged->owner.tid != owner->tid || staged->owner.pid != owner->pid ||
        staged->owner.ns != owner->ns) {
        return 0;
    }

    if (!java_remote_parent_connection_cookie_key_init(key, connection, staged->netns_cookie)) {
        return 0;
    }
    const java_remote_parent_connection_t *cookie_staged =
        bpf_map_lookup_elem(&java_remote_parent_cookie_connections, &key->cookie);
    return cookie_staged && cookie_staged->generation == generation &&
           cookie_staged->reserved == 0 && cookie_staged->reserved2 == 0 &&
           cookie_staged->netns == netns && cookie_staged->netns_cookie == staged->netns_cookie &&
           cookie_staged->incoming_generation == staged->incoming_generation &&
           cookie_staged->socket_cookie == staged->socket_cookie &&
           cookie_staged->owner.tid == owner->tid && cookie_staged->owner.pid == owner->pid &&
           cookie_staged->owner.ns == owner->ns;
}

static __always_inline u8
java_remote_parent_connection_matches_in_netns(const connection_info_t *connection,
                                               u32 netns,
                                               const pid_key_t *owner,
                                               u64 generation,
                                               u64 incoming_generation,
                                               u64 socket_cookie) {
    java_remote_parent_connection_key_t key = {0};
    return java_remote_parent_connection_matches_in_netns_with_key(
        &key, connection, netns, owner, generation, incoming_generation, socket_cookie);
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

// Every published generation reserves an exact ambiguity entry with value zero.
// A nonzero value is the durable fail-closed marker. The reservation means an
// invalidator never needs a capacity-consuming insert after it has observed a
// physical record: it can update the existing map value in place.
static __always_inline u8
java_remote_parent_reserve_exact_ambiguity(const java_remote_parent_key_t *key) {
    const u64 reserved = 0;
    if (!key || !key->generation ||
        bpf_map_update_elem(&java_remote_parent_ambiguity, key, &reserved, BPF_NOEXIST) != 0) {
        return 0;
    }
    const u64 *value = bpf_map_lookup_elem(&java_remote_parent_ambiguity, key);
    return value && !*value;
}

static __always_inline u8
java_remote_parent_mark_exact_ambiguity(const java_remote_parent_key_t *key) {
    if (!key || !key->generation) {
        return 0;
    }

    u64 *marked = bpf_map_lookup_elem(&java_remote_parent_ambiguity, key);
    if (marked && *marked) {
        return 1;
    }

    const u64 observed_monotime_ns = bpf_ktime_get_ns();
    if (!observed_monotime_ns) {
        return 0;
    }
    if (marked) {
        // The exact slot was reserved before publication. Directly changing
        // zero to nonzero cannot fail because the hash map needs no new entry.
        // Concurrent nonzero writers are equivalent: every value is a fence.
        *marked = observed_monotime_ns;
    } else {
        // Legacy or already-detached state may predate reservation. Preserve a
        // concurrent foreign marker by inserting only into an absent slot.
        bpf_map_update_elem(&java_remote_parent_ambiguity, key, &observed_monotime_ns, BPF_NOEXIST);
    }
    marked = bpf_map_lookup_elem(&java_remote_parent_ambiguity, key);
    return marked && *marked;
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
    return java_remote_parent_mark_exact_ambiguity(&key);
}

static __always_inline u8
java_remote_parent_generation_ambiguous(const java_remote_parent_key_t *key) {
    const u64 *marked = bpf_map_lookup_elem(&java_remote_parent_ambiguity, key);
    return marked && *marked;
}

static __always_inline u8
java_remote_parent_generation_cleanly_reserved(const java_remote_parent_key_t *key) {
    const u64 *marked = bpf_map_lookup_elem(&java_remote_parent_ambiguity, key);
    return marked && !*marked;
}

static __always_inline u8
java_remote_parent_generation_ambiguity_absent(const java_remote_parent_key_t *key) {
    return bpf_map_lookup_elem(&java_remote_parent_ambiguity, key) == NULL;
}

static __always_inline void
java_remote_parent_delete_connection_indexes(const connection_info_t *connection,
                                             const java_remote_parent_connection_t *staged) {
    if (!staged || staged->reserved != 0 || staged->reserved2 != 0 || !staged->netns ||
        !staged->netns_cookie || !staged->incoming_generation || !staged->socket_cookie) {
        return;
    }

    java_remote_parent_connection_t copy = {0};
    __builtin_memcpy(&copy, staged, sizeof(copy));
    java_remote_parent_connection_keys_t keys = {0};
    if (!java_remote_parent_connection_keys_init(
            &keys, connection, copy.netns, copy.netns_cookie)) {
        return;
    }
    const java_remote_parent_connection_t *netns_staged =
        bpf_map_lookup_elem(&java_remote_parent_connections, &keys.netns);
    if (netns_staged && netns_staged->reserved == 0 && netns_staged->reserved2 == 0 &&
        netns_staged->generation == copy.generation && netns_staged->netns == copy.netns &&
        netns_staged->netns_cookie == copy.netns_cookie &&
        netns_staged->incoming_generation == copy.incoming_generation &&
        netns_staged->socket_cookie == copy.socket_cookie &&
        netns_staged->owner.tid == copy.owner.tid && netns_staged->owner.pid == copy.owner.pid &&
        netns_staged->owner.ns == copy.owner.ns) {
        bpf_map_delete_elem(&java_remote_parent_connections, &keys.netns);
    }

    const java_remote_parent_connection_t *cookie_staged =
        bpf_map_lookup_elem(&java_remote_parent_cookie_connections, &keys.cookie);
    if (cookie_staged && cookie_staged->reserved == 0 && cookie_staged->reserved2 == 0 &&
        cookie_staged->generation == copy.generation && cookie_staged->netns == copy.netns &&
        cookie_staged->netns_cookie == copy.netns_cookie &&
        cookie_staged->incoming_generation == copy.incoming_generation &&
        cookie_staged->socket_cookie == copy.socket_cookie &&
        cookie_staged->owner.tid == copy.owner.tid && cookie_staged->owner.pid == copy.owner.pid &&
        cookie_staged->owner.ns == copy.owner.ns) {
        bpf_map_delete_elem(&java_remote_parent_cookie_connections, &keys.cookie);
    }
}

static __always_inline void
java_remote_parent_invalidate_connection(const connection_info_t *connection,
                                         const java_remote_parent_connection_t *staged,
                                         u64 incoming_generation) {
    if (!staged || !staged->netns || !staged->netns_cookie) {
        return;
    }

    // The map-value pointer and every derived key must be invocation-local.
    // cgroup sockopt programs can be preempted under PREEMPT_RCU, and tracing
    // hooks can nest on the same CPU; shared per-CPU scratch is not authority.
    java_remote_parent_connection_t copy = {0};
    __builtin_memcpy(&copy, staged, sizeof(copy));
    if (incoming_generation && copy.incoming_generation != incoming_generation) {
        return;
    }
    const java_remote_parent_key_t key = {
        .owner = copy.owner,
        .generation = copy.generation,
    };

    // Mark before trying to own deletion. Published generations already hold a
    // zero-valued reservation, so capacity pressure cannot prevent this exact
    // conflict from becoming durable. A legacy missing reservation falls back
    // to an exact claim (or an owner guard when another claim already owns G).
    const u8 durable_ambiguity = java_remote_parent_mark_exact_ambiguity(&key);

    // Physical invalidation is also a generation cleanup. Own the exact claim
    // before deleting either physical index.
    // A stage reserves this claim before making a connection visible, so an
    // invalidator that loses BPF_NOEXIST must not mutate that stage's G.
    if (bpf_map_lookup_elem(&java_remote_parent_claims, &key)) {
        if (!durable_ambiguity) {
            const java_remote_parent_key_t guard_key =
                java_remote_parent_detach_guard_key(&key.owner);
            java_remote_parent_claim_t local_guard = {0};
            // Retain the guard. It is the cancellation fence for a legacy
            // publishing generation whose exact ambiguity slot is missing.
            java_remote_parent_acquire_detach_guard_at(&key, &guard_key, &local_guard);
        }
        return;
    }
    u64 process_incarnation = 0;
    const java_remote_parent_owner_t *owner =
        bpf_map_lookup_elem(&java_remote_parent_owners, &copy.owner);
    if (owner && owner->generation == copy.generation && owner->process_incarnation &&
        (owner->lifecycle == k_java_remote_parent_lifecycle_publishing ||
         owner->lifecycle == k_java_remote_parent_lifecycle_active)) {
        process_incarnation = owner->process_incarnation;
    }
    if (!process_incarnation) {
        // Detached physical state has no owner cursor. A nonzero quarantine
        // token remains a valid userspace-reapable claim without authorizing
        // deletion of logical state from a different process incarnation.
        process_incarnation = copy.generation;
    }
    java_remote_parent_claim_t local_claim = {
        .observed_monotime_ns = bpf_ktime_get_ns(),
        .process_incarnation = process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_ambiguous,
    };
    if (!local_claim.observed_monotime_ns ||
        bpf_map_update_elem(&java_remote_parent_claims, &key, &local_claim, BPF_NOEXIST) != 0) {
        return;
    }
    const java_remote_parent_claim_t *claim = bpf_map_lookup_elem(&java_remote_parent_claims, &key);
    if (!claim || __builtin_memcmp(claim, &local_claim, sizeof(local_claim)) != 0) {
        return;
    }

    java_remote_parent_delete_connection_indexes(connection, &copy);

    java_remote_parent_connection_keys_t keys = {0};
    if (!java_remote_parent_connection_keys_init(
            &keys, connection, copy.netns, copy.netns_cookie)) {
        return;
    }
    const java_remote_parent_connection_t *remaining =
        bpf_map_lookup_elem(&java_remote_parent_connections, &keys.netns);
    if (remaining && remaining->generation == copy.generation &&
        remaining->owner.tid == copy.owner.tid && remaining->owner.pid == copy.owner.pid &&
        remaining->owner.ns == copy.owner.ns) {
        return;
    }
    remaining = bpf_map_lookup_elem(&java_remote_parent_cookie_connections, &keys.cookie);
    if (remaining && remaining->generation == copy.generation &&
        remaining->owner.tid == copy.owner.tid && remaining->owner.pid == copy.owner.pid &&
        remaining->owner.ns == copy.owner.ns) {
        return;
    }

    // Retain the exact ambiguity claim with the marker. A stale invalidator can
    // resume while another actor is retiring this generation's fences; dropping
    // E here could otherwise leave a marker-only tail after G=0 is released.
    // The aged M+E tuple is intentionally left for userspace convergence.
    (void)durable_ambiguity;
}

static __always_inline void
java_remote_parent_mark_connection_ambiguous_in_netns(const connection_info_t *connection,
                                                      u32 netns) {
    java_remote_parent_connection_keys_t keys = {0};
    if (!java_remote_parent_connection_keys_init(&keys, connection, netns, 0)) {
        return;
    }
    const java_remote_parent_connection_t *staged =
        bpf_map_lookup_elem(&java_remote_parent_connections, &keys.netns);
    java_remote_parent_invalidate_connection(connection, staged, 0);
}

static __always_inline void java_remote_parent_mark_connection_ambiguous_in_netns_cookie(
    const connection_info_t *connection, u64 netns_cookie, u64 incoming_generation) {
    if (!netns_cookie) {
        return;
    }
    java_remote_parent_connection_keys_t keys = {0};
    if (!java_remote_parent_connection_keys_init(&keys, connection, 0, netns_cookie)) {
        return;
    }
    const java_remote_parent_connection_t *staged =
        bpf_map_lookup_elem(&java_remote_parent_cookie_connections, &keys.cookie);
    java_remote_parent_invalidate_connection(connection, staged, incoming_generation);
}

static __always_inline void java_remote_parent_mark_connection_ambiguous_in_netns_for_socket(
    const connection_info_t *connection, u32 netns, u64 socket_cookie) {
    if (!netns || !socket_cookie) {
        return;
    }
    java_remote_parent_connection_keys_t keys = {0};
    if (!java_remote_parent_connection_keys_init(&keys, connection, netns, 0)) {
        return;
    }
    const java_remote_parent_connection_t *staged =
        bpf_map_lookup_elem(&java_remote_parent_connections, &keys.netns);
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
    java_remote_parent_connection_keys_t keys = {0};
    if (!java_remote_parent_connection_keys_init(&keys, connection, 0, netns_cookie)) {
        return;
    }
    const java_remote_parent_connection_t *staged =
        bpf_map_lookup_elem(&java_remote_parent_cookie_connections, &keys.cookie);
    if (staged && staged->socket_cookie == socket_cookie) {
        java_remote_parent_invalidate_connection(connection, staged, incoming_generation);
    }
}

static __always_inline void
java_remote_parent_mark_connection_ambiguous(const connection_info_t *connection) {
    java_remote_parent_mark_connection_ambiguous_in_netns(connection, task_netns());
}
