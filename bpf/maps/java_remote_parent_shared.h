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
    // A producer changes only its own exact surviving fence to this state,
    // with a fresh timestamp, after its final possible payload mutation.
    // Userspace cleanup never adopts untagged lifecycle 1-6 because a
    // preempted BPF invocation may still resume and key-delete through an old
    // exact check. The coordinator-quiesced tagged Go exception is documented
    // below.
    k_java_remote_parent_lifecycle_cleanup = 7,
};

// Userspace handlers and cleanup share one agent-wide generation coordinator,
// while the internal maps can outlive an individual handler invocation. This
// reserved-byte tag gives cleanup durable Go provenance without granting BPF
// mutation authority: BPF producer helpers continue to require all reserved
// bytes to be zero.
#define k_java_remote_parent_go_producer_tag ((u8)0x47)

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
_Static_assert(__builtin_offsetof(java_remote_parent_owner_t, generation) == 0,
               "java remote-parent owner generation offset mismatch");
_Static_assert(__builtin_offsetof(java_remote_parent_owner_t, process_incarnation) == 8,
               "java remote-parent owner process-incarnation offset mismatch");
_Static_assert(__builtin_offsetof(java_remote_parent_owner_t, lifecycle) == 16,
               "java remote-parent owner lifecycle offset mismatch");
_Static_assert(__builtin_offsetof(java_remote_parent_owner_t, reserved) == 17,
               "java remote-parent owner reserved offset mismatch");
_Static_assert(sizeof(java_remote_parent_claim_t) == 24, "java remote-parent claim size mismatch");
_Static_assert(__builtin_offsetof(java_remote_parent_claim_t, observed_monotime_ns) == 0,
               "java remote-parent claim observation offset mismatch");
_Static_assert(__builtin_offsetof(java_remote_parent_claim_t, process_incarnation) == 8,
               "java remote-parent claim process-incarnation offset mismatch");
_Static_assert(__builtin_offsetof(java_remote_parent_claim_t, lifecycle) == 16,
               "java remote-parent claim lifecycle offset mismatch");
_Static_assert(__builtin_offsetof(java_remote_parent_claim_t, reserved) == 17,
               "java remote-parent claim reserved offset mismatch");
_Static_assert(sizeof(((java_remote_parent_claim_t *)0)->lifecycle) +
                       sizeof(((java_remote_parent_claim_t *)0)->reserved) ==
                   sizeof(u64),
               "java remote-parent claim tail size mismatch");
_Static_assert(sizeof(java_remote_parent_data_signal_key_t) == 24,
               "java remote-parent data-signal key size mismatch");
_Static_assert(sizeof(java_remote_parent_data_ack_t) == 72,
               "java remote-parent data acknowledgement size mismatch");

static __always_inline u64 java_remote_parent_lifecycle_tail_word(const u8 *tail) {
    u64 actual;
    const u8 *aligned_tail = __builtin_assume_aligned(tail, sizeof(actual));
    __builtin_memcpy(&actual, aligned_tail, sizeof(actual));
    return java_remote_parent_cpu_to_le64(actual);
}

static __always_inline u32 java_remote_parent_metadata_word(const u8 *metadata) {
    u32 actual;
    const u8 *aligned_metadata = __builtin_assume_aligned(metadata, sizeof(actual));
    __builtin_memcpy(&actual, aligned_metadata, sizeof(actual));
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    actual = __builtin_bswap32(actual);
#endif
    return actual;
}

// lifecycle followed by reserved[7] is an eight-byte ABI tail in claims,
// owners, and terminals. Compare it as one endian-correct word so every
// reserved byte remains required to be zero without multiplying verifier
// states for seven independent byte predicates.
static __always_inline u8 java_remote_parent_clean_lifecycle_tail(const u8 *tail, u8 lifecycle) {
    return java_remote_parent_lifecycle_tail_word(tail) == lifecycle;
}

// The finish-guard trailer starts with physical_detached, then the boolean
// replay_required flag and reserved[6]. Preserve the historical unconstrained
// physical byte while checking the rest of the trailer in one word.
static __always_inline u8 java_remote_parent_clean_boolean_second_byte_tail(const u8 *tail) {
    u64 actual;
    const u8 *aligned_tail = __builtin_assume_aligned(tail, sizeof(actual));
    __builtin_memcpy(&actual, aligned_tail, sizeof(actual));
    return (java_remote_parent_cpu_to_le64(actual) >> 8) <= 1;
}

// Compare all 24 bytes in three verifier-friendly words. The final word is
// copied from lifecycle plus reserved[7], so this remains byte-exact without
// expanding a fixed-size memcmp into 24 independent byte predicates.
static __always_inline u8 java_remote_parent_claim_equal_inline(
    const java_remote_parent_claim_t *left, const java_remote_parent_claim_t *right) {
    if (!left || !right) {
        return 0;
    }
    u64 left_tail;
    u64 right_tail;
    __builtin_memcpy(&left_tail, &left->lifecycle, sizeof(left_tail));
    __builtin_memcpy(&right_tail, &right->lifecycle, sizeof(right_tail));
    volatile u64 mismatch = (left->observed_monotime_ns ^ right->observed_monotime_ns) |
                            (left->process_incarnation ^ right->process_incarnation) |
                            (left_tail ^ right_tail);
    return mismatch == 0;
}

static __always_inline __attribute__((unused)) u8 java_remote_parent_claim_equal(
    const java_remote_parent_claim_t *left, const java_remote_parent_claim_t *right) {
    return java_remote_parent_claim_equal_inline(left, right);
}

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

// Owner-wide teardown guards are resource-partitioned from exact generation
// claims. Exact lifecycle-cleanup tails may accumulate while userspace is
// delayed; sharing one finite HASH would let E exhaust every slot and prevent
// the G acquisition required to recover any tail.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, pid_key_t);
    __type(value, java_remote_parent_claim_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_remote_parent_owner_guards SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, pid_key_t);
    __type(value, java_remote_parent_owner_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_remote_parent_owners SEC(".maps");

// Exact generation claims and owner-scoped non-terminal detach guards use
// separate maps so capacity pressure in one class cannot starve the other.
// Keeping these helpers in the shared header lets physical invalidation
// publish a cancellation fence even when an exact publishing claim already
// owns the generation.
static __always_inline java_remote_parent_key_t
java_remote_parent_detach_guard_key(const pid_key_t *owner) {
    return (java_remote_parent_key_t){
        .owner = *owner,
    };
}

static __always_inline u8 java_remote_parent_owner_detach_guarded(const pid_key_t *owner) {
    return bpf_map_lookup_elem(&java_remote_parent_owner_guards, owner) != NULL;
}

static __always_inline u8 java_remote_parent_detach_guard_matches_at(
    const java_remote_parent_key_t *expected, const java_remote_parent_key_t *guard_key) {
    const java_remote_parent_claim_t *guard =
        bpf_map_lookup_elem(&java_remote_parent_owner_guards, &guard_key->owner);
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
        bpf_map_lookup_elem(&java_remote_parent_owner_guards, &guard_key->owner);
    if (!java_remote_parent_claim_equal(guard, local_guard)) {
        // Absence or replacement means the old guard was already released.
        return 1;
    }
    if (bpf_map_delete_elem(&java_remote_parent_owner_guards, &guard_key->owner) != 0) {
        guard = bpf_map_lookup_elem(&java_remote_parent_owner_guards, &guard_key->owner);
        // Report failure only while the exact old guard demonstrably remains.
        return !java_remote_parent_claim_equal(guard, local_guard);
    }
    // Successful exact deletion is the release linearization point. A new
    // owner operation may publish another guard immediately afterward; that
    // successor must not make this completed release look like a failure.
    return 1;
}

static __always_inline u8 java_remote_parent_release_exact_detach_guard_at(
    const java_remote_parent_key_t *guard_key, java_remote_parent_claim_t *local_guard) {
    const u8 released = java_remote_parent_delete_exact_detach_guard_at(guard_key, local_guard);
    if (released) {
        // Clear invocation-local authority at the release linearization point.
        // A later byte-identical successor must never be handed to userspace.
        __builtin_memset(local_guard, 0, sizeof(*local_guard));
    }
    return released;
}

static __always_inline u8 java_remote_parent_exact_detach_guard_matches_at(
    const java_remote_parent_key_t *guard_key, const java_remote_parent_claim_t *local_guard) {
    const java_remote_parent_claim_t *guard =
        bpf_map_lookup_elem(&java_remote_parent_owner_guards, &guard_key->owner);
    return java_remote_parent_claim_equal(guard, local_guard);
}

static __always_inline u8 java_remote_parent_handoff_exact_fence(
    const java_remote_parent_key_t *key, const java_remote_parent_claim_t *local_fence) {
    if (!key || !key->generation || key->reserved || !local_fence ||
        !local_fence->observed_monotime_ns || !local_fence->process_incarnation ||
        local_fence->lifecycle < k_java_remote_parent_lifecycle_consumed ||
        local_fence->lifecycle > k_java_remote_parent_lifecycle_publishing ||
        __builtin_memcmp(local_fence->reserved,
                         (unsigned char[sizeof(local_fence->reserved)]){0},
                         sizeof(local_fence->reserved)) != 0) {
        return 0;
    }
    const java_remote_parent_claim_t *current =
        bpf_map_lookup_elem(&java_remote_parent_claims, key);
    if (!java_remote_parent_claim_equal(current, local_fence)) {
        // Absence or replacement means this invocation has no fence left to
        // hand off. Never update a value that is not exactly invocation-local.
        return 1;
    }

    java_remote_parent_claim_t cleanup = *local_fence;
    const u64 now = bpf_ktime_get_ns();
    if (local_fence->observed_monotime_ns == ~(u64)0) {
        // A cleanup timestamp must be strictly newer than the producer fence.
        // Saturation cannot meet that invariant, so retain the producer value
        // fail closed instead of publishing immediately-adoptable authority.
        return 0;
    }
    cleanup.observed_monotime_ns =
        now > local_fence->observed_monotime_ns ? now : local_fence->observed_monotime_ns + 1;
    cleanup.reserved[0] = local_fence->lifecycle;
    cleanup.lifecycle = k_java_remote_parent_lifecycle_cleanup;
    if (bpf_map_update_elem(&java_remote_parent_claims, key, &cleanup, BPF_EXIST) != 0) {
        return 0;
    }
    current = bpf_map_lookup_elem(&java_remote_parent_claims, key);
    return java_remote_parent_claim_equal(current, &cleanup);
}

static __always_inline u8 java_remote_parent_handoff_exact_detach_guard_at(
    const java_remote_parent_key_t *guard_key, const java_remote_parent_claim_t *local_guard) {
    if (!guard_key || guard_key->generation || guard_key->reserved || !local_guard ||
        !local_guard->observed_monotime_ns || !local_guard->process_incarnation ||
        !java_remote_parent_clean_lifecycle_tail(&local_guard->lifecycle,
                                                 k_java_remote_parent_lifecycle_publishing)) {
        return 0;
    }
    const java_remote_parent_claim_t *current =
        bpf_map_lookup_elem(&java_remote_parent_owner_guards, &guard_key->owner);
    if (!java_remote_parent_claim_equal(current, local_guard)) {
        return 1;
    }
    if (local_guard->observed_monotime_ns == ~(u64)0) {
        return 0;
    }

    java_remote_parent_claim_t cleanup = *local_guard;
    const u64 now = bpf_ktime_get_ns();
    cleanup.observed_monotime_ns =
        now > local_guard->observed_monotime_ns ? now : local_guard->observed_monotime_ns + 1;
    cleanup.reserved[0] = k_java_remote_parent_lifecycle_publishing;
    cleanup.lifecycle = k_java_remote_parent_lifecycle_cleanup;
    if (bpf_map_update_elem(
            &java_remote_parent_owner_guards, &guard_key->owner, &cleanup, BPF_EXIST) != 0) {
        return 0;
    }
    current = bpf_map_lookup_elem(&java_remote_parent_owner_guards, &guard_key->owner);
    return java_remote_parent_claim_equal(current, &cleanup);
}

static __always_inline u8
java_remote_parent_handoff_exact_fence_pair(const java_remote_parent_key_t *key,
                                            const java_remote_parent_claim_t *local_fence,
                                            const java_remote_parent_key_t *guard_key,
                                            const java_remote_parent_claim_t *local_guard) {
    // G may become userspace-visible only after E was released, converted, or
    // proven absent/replaced. If E conversion fails while the local semantic
    // value survives, retain G in producer state and fail closed.
    if (local_fence && local_fence->observed_monotime_ns &&
        !java_remote_parent_handoff_exact_fence(key, local_fence)) {
        return 0;
    }
    return java_remote_parent_handoff_exact_detach_guard_at(guard_key, local_guard);
}

static __always_inline u8
java_remote_parent_acquire_detach_guard_at(const java_remote_parent_key_t *expected,
                                           const java_remote_parent_key_t *guard_key,
                                           java_remote_parent_claim_t *local_guard) {
    if (!local_guard) {
        return 0;
    }
    __builtin_memset(local_guard, 0, sizeof(*local_guard));
    if (!expected || !expected->generation || expected->reserved || !guard_key ||
        guard_key->generation || guard_key->reserved ||
        __builtin_memcmp(&expected->owner, &guard_key->owner, sizeof(expected->owner)) != 0) {
        return 0;
    }
    *local_guard = (java_remote_parent_claim_t){
        .observed_monotime_ns = bpf_ktime_get_ns(),
        .process_incarnation = expected->generation,
        .lifecycle = k_java_remote_parent_lifecycle_publishing,
    };
    if (!local_guard->observed_monotime_ns ||
        bpf_map_update_elem(
            &java_remote_parent_owner_guards, &guard_key->owner, local_guard, BPF_NOEXIST) != 0) {
        // A failed BPF_NOEXIST result conveys no ownership even if a foreign
        // value happens to have identical timestamp bytes.
        __builtin_memset(local_guard, 0, sizeof(*local_guard));
        return 0;
    }
    return java_remote_parent_detach_guard_matches_at(expected, guard_key) &&
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

static __noinline __attribute__((unused)) void
java_remote_parent_delete_connection_indexes(const connection_info_t *connection,
                                             const java_remote_parent_connection_t *staged) {
    if (!staged || staged->reserved != 0 || staged->reserved2 != 0 || !staged->netns ||
        !staged->netns_cookie || !staged->incoming_generation || !staged->socket_cookie) {
        return;
    }

    java_remote_parent_connection_keys_t keys = {0};
    if (!java_remote_parent_connection_keys_init(
            &keys, connection, staged->netns, staged->netns_cookie)) {
        return;
    }
    const java_remote_parent_connection_t *netns_staged =
        bpf_map_lookup_elem(&java_remote_parent_connections, &keys.netns);
    if (netns_staged && netns_staged->reserved == 0 && netns_staged->reserved2 == 0 &&
        netns_staged->generation == staged->generation && netns_staged->netns == staged->netns &&
        netns_staged->netns_cookie == staged->netns_cookie &&
        netns_staged->incoming_generation == staged->incoming_generation &&
        netns_staged->socket_cookie == staged->socket_cookie &&
        netns_staged->owner.tid == staged->owner.tid &&
        netns_staged->owner.pid == staged->owner.pid &&
        netns_staged->owner.ns == staged->owner.ns) {
        bpf_map_delete_elem(&java_remote_parent_connections, &keys.netns);
    }

    const java_remote_parent_connection_t *cookie_staged =
        bpf_map_lookup_elem(&java_remote_parent_cookie_connections, &keys.cookie);
    if (cookie_staged && cookie_staged->reserved == 0 && cookie_staged->reserved2 == 0 &&
        cookie_staged->generation == staged->generation && cookie_staged->netns == staged->netns &&
        cookie_staged->netns_cookie == staged->netns_cookie &&
        cookie_staged->incoming_generation == staged->incoming_generation &&
        cookie_staged->socket_cookie == staged->socket_cookie &&
        cookie_staged->owner.tid == staged->owner.tid &&
        cookie_staged->owner.pid == staged->owner.pid &&
        cookie_staged->owner.ns == staged->owner.ns) {
        bpf_map_delete_elem(&java_remote_parent_cookie_connections, &keys.cookie);
    }
}

static __noinline __attribute__((unused)) void
java_remote_parent_observe_connection_indexes(const connection_info_t *connection,
                                              const java_remote_parent_connection_t *staged) {
    java_remote_parent_connection_keys_t keys = {0};
    if (!java_remote_parent_connection_keys_init(
            &keys, connection, staged->netns, staged->netns_cookie)) {
        return;
    }
    const java_remote_parent_connection_t *remaining =
        bpf_map_lookup_elem(&java_remote_parent_connections, &keys.netns);
    if (remaining && remaining->generation == staged->generation &&
        remaining->owner.tid == staged->owner.tid && remaining->owner.pid == staged->owner.pid &&
        remaining->owner.ns == staged->owner.ns) {
        return;
    }
    remaining = bpf_map_lookup_elem(&java_remote_parent_cookie_connections, &keys.cookie);
    if (remaining && remaining->generation == staged->generation &&
        remaining->owner.tid == staged->owner.tid && remaining->owner.pid == staged->owner.pid &&
        remaining->owner.ns == staged->owner.ns) {
        return;
    }
}

static __noinline __attribute__((unused)) void
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

    // Physical invalidation is owner-scoped because the connection indexes
    // are reusable singleton keys. Own G before E so a concurrent RESET,
    // STAGE rollback, userspace cleanup, or different generation cannot pass
    // a stale lookup and delete a replacement connection value.
    const java_remote_parent_key_t guard_key = java_remote_parent_detach_guard_key(&key.owner);
    java_remote_parent_claim_t local_guard = {0};
    if (!java_remote_parent_acquire_detach_guard_at(&key, &guard_key, &local_guard)) {
        return;
    }

    // A stage reserves E before making a connection visible. Losing E means
    // this invocation owns no payload mutation; hand off only its own G.
    if (bpf_map_lookup_elem(&java_remote_parent_claims, &key)) {
        java_remote_parent_handoff_exact_detach_guard_at(&guard_key, &local_guard);
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
    if (!local_claim.observed_monotime_ns) {
        java_remote_parent_handoff_exact_detach_guard_at(&guard_key, &local_guard);
        return;
    }
    if (bpf_map_update_elem(&java_remote_parent_claims, &key, &local_claim, BPF_NOEXIST) != 0) {
        __builtin_memset(&local_claim, 0, sizeof(local_claim));
        java_remote_parent_handoff_exact_detach_guard_at(&guard_key, &local_guard);
        return;
    }
    const java_remote_parent_claim_t *claim = bpf_map_lookup_elem(&java_remote_parent_claims, &key);
    if (!java_remote_parent_claim_equal(claim, &local_claim) ||
        !java_remote_parent_exact_detach_guard_matches_at(&guard_key, &local_guard)) {
        goto handoff;
    }

    java_remote_parent_delete_connection_indexes(connection, &copy);
    java_remote_parent_observe_connection_indexes(connection, &copy);

handoff:
    // Payload work is over. Publish E first; only a successful E handoff (or
    // demonstrated absence/replacement) permits G to become userspace-owned.
    // If E remains producer-owned after an update failure, retain G in its
    // producer lifecycle so cleanup cannot adopt a partial fence pair.
    java_remote_parent_handoff_exact_fence_pair(&key, &local_claim, &guard_key, &local_guard);
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
