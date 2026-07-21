// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/java_remote_parent.h>
#include <common/map_sizing.h>
#include <common/per_cpu_generation.h>
#include <common/pin_internal.h>
#include <common/scratch_mem.h>
#include <common/trace_helpers.h>

#include <maps/java_tasks.h>
#include <maps/incoming_trace_map.h>
#include <maps/java_remote_parent_shared.h>
#include <maps/java_vt_threads.h>

#include <pid/pid_helpers.h>
#include <pid/types/pid_key.h>

enum { k_java_remote_parent_max_ancestry = 3 };

typedef struct java_remote_parent_terminal {
    u64 generation;
    u64 observed_monotime_ns;
    u64 process_incarnation;
    u8 lifecycle;
    unsigned char reserved[7];
} java_remote_parent_terminal_t;

typedef struct java_remote_parent_state {
    u8 lifecycle;
    unsigned char reserved[7];
    u64 observed_monotime_ns;
    connection_info_t connection;
    u32 connection_netns;
    u64 process_incarnation;
    java_remote_parent_response_t response;
} java_remote_parent_state_t;

typedef struct java_remote_parent_task {
    pid_key_t owner;
    u32 reserved;
    u64 generation;
    u64 observed_monotime_ns;
} java_remote_parent_task_t;

typedef struct java_remote_parent_handoff_key {
    u32 pid;
    u32 ns;
    u64 token;
} java_remote_parent_handoff_key_t;

typedef struct java_remote_parent_generation_index {
    pid_key_t process;
    u32 reserved;
    u64 process_incarnation;
    u64 observed_monotime_ns;
} java_remote_parent_generation_index_t;

typedef struct java_remote_parent_handoff_claim {
    u64 observed_monotime_ns;
    u64 process_incarnation;
} java_remote_parent_handoff_claim_t;

typedef struct java_remote_parent_cleanup_scratch {
    java_remote_parent_owner_t indexed;
    java_remote_parent_key_t key;
    java_remote_parent_claim_t claim;
    connection_info_ns_t connection_key;
} java_remote_parent_cleanup_scratch_t;

_Static_assert(offsetof(java_remote_parent_key_t, generation) == 16,
               "java remote-parent key generation offset mismatch");
_Static_assert(sizeof(java_remote_parent_key_t) == 24, "java remote-parent key size mismatch");
_Static_assert(offsetof(java_remote_parent_state_t, connection) == 16,
               "java remote-parent state connection offset mismatch");
_Static_assert(offsetof(java_remote_parent_state_t, process_incarnation) == 56,
               "java remote-parent state process incarnation offset mismatch");
_Static_assert(offsetof(java_remote_parent_state_t, response) == 64,
               "java remote-parent state response offset mismatch");
_Static_assert(sizeof(java_remote_parent_state_t) == 128, "java remote-parent state size mismatch");
_Static_assert(sizeof(java_remote_parent_terminal_t) == 32,
               "java remote-parent terminal size mismatch");
_Static_assert(offsetof(java_remote_parent_task_t, generation) == 16,
               "java remote-parent task generation offset mismatch");
_Static_assert(sizeof(java_remote_parent_task_t) == 32, "java remote-parent task size mismatch");
_Static_assert(sizeof(java_remote_parent_handoff_key_t) == 16,
               "java remote-parent handoff key size mismatch");
_Static_assert(sizeof(java_remote_parent_generation_index_t) == 32,
               "java remote-parent generation index size mismatch");
_Static_assert(sizeof(java_remote_parent_handoff_claim_t) == 16,
               "java remote-parent handoff claim size mismatch");
_Static_assert(sizeof(java_remote_parent_cleanup_scratch_t) <= sizeof(java_remote_parent_state_t),
               "java remote-parent cleanup scratch exceeds stage scratch");

typedef struct java_remote_parent_incoming {
    tp_info_pid_t candidate;
    u64 generation;
} java_remote_parent_incoming_t;

SCRATCH_MEM_TYPED(java_remote_parent_stage_state, java_remote_parent_state_t)
SCRATCH_MEM_TYPED(java_remote_parent_incoming_snapshot, java_remote_parent_incoming_t)
SCRATCH_MEM_TYPED(java_remote_parent_connection_snapshot, connection_info_t)

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, java_remote_parent_key_t);
    __type(value, java_remote_parent_state_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_remote_parent_state SEC(".maps");

// Canonical enumeration index for every published generation. Claims and
// ambiguity markers remain non-evicting HASH maps; userspace removes them only
// after revalidating this exact owner, generation, and JVM incarnation.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, java_remote_parent_key_t);
    __type(value, java_remote_parent_generation_index_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_remote_parent_generation_index SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_key_t);
    __type(value, java_remote_parent_terminal_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_remote_parent_terminal SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_remote_parent_generation SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_key_t);
    __type(value, java_remote_parent_task_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_remote_parent_tasks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, java_remote_parent_handoff_key_t);
    __type(value, java_remote_parent_task_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_remote_parent_handoffs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, java_remote_parent_handoff_key_t);
    __type(value, java_remote_parent_handoff_claim_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_remote_parent_handoff_claims SEC(".maps");

static __always_inline u8 java_remote_parent_pid_key_equal(const pid_key_t *left,
                                                           const pid_key_t *right) {
    return left->tid == right->tid && left->pid == right->pid && left->ns == right->ns;
}

static __always_inline u64 java_remote_parent_next_generation() {
    const u32 zero = 0;
    u64 *generation = bpf_map_lookup_elem(&java_remote_parent_generation, &zero);
    return next_per_cpu_generation(generation, bpf_get_smp_processor_id());
}

static __always_inline pid_key_t java_remote_parent_current_owner() {
    pid_key_t owner = {0};
    task_tid(&owner);
    java_vt_translate_tid(&owner);
    return owner;
}

static __always_inline java_remote_parent_key_t java_remote_parent_state_key(const pid_key_t *owner,
                                                                             u64 generation) {
    java_remote_parent_key_t key = {
        .owner = *owner,
        .generation = generation,
    };
    return key;
}

static __always_inline u8
java_remote_parent_generation_in_use(const java_remote_parent_key_t *key) {
    if (bpf_map_lookup_elem(&java_remote_parent_state, key) ||
        bpf_map_lookup_elem(&java_remote_parent_generation_index, key) ||
        bpf_map_lookup_elem(&java_remote_parent_claims, key) ||
        bpf_map_lookup_elem(&java_remote_parent_ambiguity, key)) {
        return 1;
    }

    const java_remote_parent_terminal_t *terminal =
        bpf_map_lookup_elem(&java_remote_parent_terminal, &key->owner);
    return terminal && terminal->generation == key->generation;
}

static __always_inline u8 java_remote_parent_generation_index_matches(
    const java_remote_parent_key_t *key, u64 process_incarnation, u64 observed_monotime_ns) {
    const java_remote_parent_generation_index_t *indexed =
        bpf_map_lookup_elem(&java_remote_parent_generation_index, key);
    const pid_key_t process = java_process_key(&key->owner);
    return indexed && indexed->reserved == 0 &&
           java_remote_parent_pid_key_equal(&indexed->process, &process) &&
           indexed->process_incarnation == process_incarnation &&
           indexed->observed_monotime_ns == observed_monotime_ns;
}

static __always_inline u8 java_remote_parent_mark_ambiguous(const pid_key_t *owner) {
    const java_remote_parent_owner_t *indexed =
        bpf_map_lookup_elem(&java_remote_parent_owners, owner);
    if (!indexed) {
        return 0;
    }
    const u64 generation = indexed->generation;
    if (java_remote_parent_mark_generation_ambiguous(owner, generation)) {
        return 1;
    }

    java_remote_parent_cleanup_fallback_generation(owner, generation);
    return 0;
}

static __always_inline u8 java_remote_parent_guard_owner_reuse(const pid_key_t *owner) {
    const java_remote_parent_owner_t *indexed =
        bpf_map_lookup_elem(&java_remote_parent_owners, owner);
    if (!indexed) {
        return 0;
    }

    return java_remote_parent_mark_ambiguous(owner);
}

static __always_inline u8 java_remote_parent_task_mapping_would_cycle(const pid_key_t *child,
                                                                      const pid_key_t *parent) {
    pid_key_t current = *parent;

#pragma unroll
    for (u8 depth = 0; depth < k_java_remote_parent_max_ancestry; depth++) {
        if (java_remote_parent_pid_key_equal(child, &current)) {
            return 1;
        }

        const pid_key_t *next = bpf_map_lookup_elem(&java_tasks, &current);
        if (!next) {
            return 0;
        }
        current = *next;
    }

    return 1;
}

static __always_inline void
java_remote_parent_release_indexed_connection(const java_remote_parent_key_t *key,
                                              const connection_info_ns_t *connection_key) {
    const java_remote_parent_connection_t *staged =
        bpf_map_lookup_elem(&java_remote_parent_connections, connection_key);
    if (staged && staged->generation == key->generation &&
        java_remote_parent_pid_key_equal(&staged->owner, &key->owner)) {
        java_remote_parent_delete_connection_indexes(&connection_key->connection, staged);
    }
}

static __always_inline void
java_remote_parent_release_connection(const pid_key_t *owner,
                                      u64 generation,
                                      const connection_info_t *connection,
                                      u32 connection_netns);

static __noinline void java_remote_parent_cleanup(const pid_key_t *owner) {
    const java_remote_parent_owner_t *indexed =
        bpf_map_lookup_elem(&java_remote_parent_owners, owner);
    if (!indexed) {
        return;
    }

    java_remote_parent_cleanup_scratch_t *scratch = java_remote_parent_stage_state_mem();
    if (!scratch) {
        java_remote_parent_mark_ambiguous(owner);
        return;
    }

    scratch->indexed = *indexed;
    if (scratch->indexed.lifecycle == k_java_remote_parent_lifecycle_publishing) {
        java_remote_parent_mark_ambiguous(owner);
        indexed = bpf_map_lookup_elem(&java_remote_parent_owners, owner);
        if (!indexed || indexed->generation != scratch->indexed.generation ||
            indexed->lifecycle == k_java_remote_parent_lifecycle_publishing) {
            return;
        }
        scratch->indexed = *indexed;
    }

    scratch->key = java_remote_parent_state_key(owner, scratch->indexed.generation);
    scratch->claim = (java_remote_parent_claim_t){
        .observed_monotime_ns = bpf_ktime_get_ns(),
        .process_incarnation = scratch->indexed.process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_discarded,
    };
    if (bpf_map_update_elem(
            &java_remote_parent_claims, &scratch->key, &scratch->claim, BPF_NOEXIST) != 0) {
        java_remote_parent_mark_ambiguous(owner);
        return;
    }

    const java_remote_parent_state_t *state =
        bpf_map_lookup_elem(&java_remote_parent_state, &scratch->key);
    if (state) {
        __builtin_memcpy(&scratch->connection_key.connection,
                         &state->connection,
                         sizeof(scratch->connection_key.connection));
        scratch->connection_key.netns = state->connection_netns;
        java_remote_parent_release_indexed_connection(&scratch->key, &scratch->connection_key);
    }
    bpf_map_delete_elem(&java_remote_parent_state, &scratch->key);
    bpf_map_delete_elem(&java_remote_parent_terminal, owner);
    bpf_map_delete_elem(&java_remote_parent_ambiguity, &scratch->key);
    java_remote_parent_cleanup_fallback_generation(owner, scratch->key.generation);
    bpf_map_delete_elem(&java_remote_parent_tasks, owner);
    bpf_map_delete_elem(&java_remote_parent_generation_index, &scratch->key);
    const java_remote_parent_owner_t *current =
        bpf_map_lookup_elem(&java_remote_parent_owners, owner);
    if (current && current->generation == scratch->key.generation) {
        bpf_map_delete_elem(&java_remote_parent_owners, owner);
    }
    bpf_map_delete_elem(&java_remote_parent_claims, &scratch->key);
}

static __always_inline void java_remote_parent_cleanup_current() {
    const pid_key_t owner = java_remote_parent_current_owner();
    java_remote_parent_cleanup(&owner);
}

static __always_inline void java_remote_parent_begin_data_receive() {
    const pid_key_t owner = java_remote_parent_current_owner();
    java_remote_parent_cleanup(&owner);

    const u64 *previous_nonce = bpf_map_lookup_elem(&java_remote_parent_data_signals, &owner);
    if (previous_nonce && *previous_nonce) {
        const java_remote_parent_data_signal_key_t previous_key = {
            .process = java_process_key(&owner),
            .nonce = *previous_nonce,
        };
        bpf_map_delete_elem(&java_remote_parent_data_acks, &previous_key);
    }
    bpf_map_delete_elem(&java_remote_parent_data_signals, &owner);
}

static __always_inline void java_remote_parent_publish_data_signal(u64 nonce) {
    if (!nonce) {
        return;
    }
    const pid_key_t owner = java_remote_parent_current_owner();
    bpf_map_update_elem(&java_remote_parent_data_signals, &owner, &nonce, BPF_ANY);
}

static __always_inline void java_remote_parent_finish_data_signal(const pid_key_t *owner,
                                                                  u64 nonce) {
    const u64 *current_nonce = bpf_map_lookup_elem(&java_remote_parent_data_signals, owner);
    if (current_nonce && *current_nonce == nonce) {
        bpf_map_delete_elem(&java_remote_parent_data_signals, owner);
    }
}

static __always_inline void
java_remote_parent_release_connection(const pid_key_t *owner,
                                      u64 generation,
                                      const connection_info_t *connection,
                                      u32 connection_netns) {
    const connection_info_ns_t connection_key =
        connection_info_with_netns(connection, connection_netns);
    const java_remote_parent_connection_t *staged =
        bpf_map_lookup_elem(&java_remote_parent_connections, &connection_key);
    if (staged && staged->generation == generation &&
        java_remote_parent_pid_key_equal(&staged->owner, owner)) {
        java_remote_parent_delete_connection_indexes(connection, staged);
    }
}

static __always_inline void java_remote_parent_rollback_stage(const pid_key_t *owner,
                                                              const java_remote_parent_key_t *key,
                                                              const connection_info_t *connection,
                                                              u32 connection_netns) {
    java_remote_parent_release_connection(owner, key->generation, connection, connection_netns);
    java_remote_parent_cleanup_fallback_generation(owner, key->generation);
    bpf_map_delete_elem(&java_remote_parent_state, key);
    bpf_map_delete_elem(&java_remote_parent_ambiguity, key);
    bpf_map_delete_elem(&java_remote_parent_generation_index, key);
    const java_remote_parent_owner_t *indexed =
        bpf_map_lookup_elem(&java_remote_parent_owners, owner);
    if (indexed && indexed->generation == key->generation) {
        bpf_map_delete_elem(&java_remote_parent_owners, owner);
    }
}

static __always_inline u8
java_remote_parent_stage_is_consistent(const pid_key_t *owner,
                                       const java_remote_parent_key_t *key,
                                       const connection_info_t *connection,
                                       u32 connection_netns,
                                       u64 connection_netns_cookie,
                                       u64 incoming_generation,
                                       u64 process_incarnation,
                                       const tp_info_pid_t *incoming) {
    const java_remote_parent_owner_t *indexed =
        bpf_map_lookup_elem(&java_remote_parent_owners, owner);
    if (!indexed || indexed->generation != key->generation ||
        indexed->process_incarnation != process_incarnation ||
        indexed->lifecycle != k_java_remote_parent_lifecycle_publishing ||
        java_remote_parent_generation_ambiguous(key)) {
        return 0;
    }

    const java_remote_parent_state_t *state = bpf_map_lookup_elem(&java_remote_parent_state, key);
    if (!state || state->lifecycle != k_java_remote_parent_lifecycle_active ||
        state->process_incarnation != process_incarnation ||
        state->response.status != k_java_remote_parent_status_valid ||
        java_remote_parent_le64_to_cpu(state->response.generation_le) != key->generation ||
        !java_remote_parent_generation_index_matches(
            key, process_incarnation, state->observed_monotime_ns) ||
        !java_remote_parent_connection_matches_in_netns(
            connection, connection_netns, owner, key->generation, incoming_generation) ||
        !java_remote_parent_fallback_matches(owner, key->generation)) {
        return 0;
    }

    if (!incoming_trace_claimed_generation_matches_in_netns_cookie(
            connection, connection_netns_cookie, incoming_generation, incoming)) {
        return 0;
    }

    return !bpf_map_lookup_elem(&java_remote_parent_claims, key);
}

static __always_inline u64 java_remote_parent_stage(const connection_info_t *connection,
                                                    u32 connection_netns,
                                                    u64 connection_netns_cookie,
                                                    u64 incoming_generation,
                                                    const tp_info_pid_t *incoming) {
    if (!java_remote_parent_data_hook_is_ready() || !connection || !connection_netns ||
        !connection_netns_cookie || !incoming_generation || !incoming || !incoming->valid ||
        incoming->provenance != k_tp_provenance_tcp_exact_flags ||
        !valid_trace(incoming->tp.trace_id) || !valid_span(incoming->tp.span_id)) {
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_malformed);
        return 0;
    }
    if (!incoming_trace_claimed_generation_matches_in_netns_cookie(
            connection, connection_netns_cookie, incoming_generation, incoming)) {
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_ambiguous);
        return 0;
    }

    const pid_key_t owner = java_remote_parent_current_owner();
    const u64 process_incarnation = java_process_incarnation_for(&owner);
    if (!process_incarnation) {
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_malformed);
        return 0;
    }
    const java_remote_parent_owner_t *previous_owner =
        bpf_map_lookup_elem(&java_remote_parent_owners, &owner);
    if (previous_owner && previous_owner->process_incarnation != process_incarnation) {
        java_remote_parent_cleanup(&owner);
    }
    const u64 now = bpf_ktime_get_ns();
    const u64 generation = java_remote_parent_next_generation();
    if (!generation) {
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_overload);
        return 0;
    }
    const u64 observed_monotime_ns = incoming->tp.ts ? incoming->tp.ts : now;
    const java_remote_parent_key_t key = java_remote_parent_state_key(&owner, generation);
    if (java_remote_parent_generation_in_use(&key)) {
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_ambiguous);
        return 0;
    }

    java_remote_parent_owner_t publishing = {
        .generation = generation,
        .process_incarnation = process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_publishing,
    };
    if (bpf_map_update_elem(&java_remote_parent_owners, &owner, &publishing, BPF_NOEXIST) != 0) {
        java_remote_parent_guard_owner_reuse(&owner);
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_ambiguous);
        return 0;
    }
    bpf_map_delete_elem(&java_remote_parent_terminal, &owner);
    java_remote_parent_cleanup_fallback(&owner);

    java_remote_parent_state_t *state = java_remote_parent_stage_state_mem();
    if (!state) {
        java_remote_parent_rollback_stage(&owner, &key, connection, connection_netns);
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_overload);
        return 0;
    }
    __builtin_memset(state, 0, sizeof(*state));
    state->lifecycle = k_java_remote_parent_lifecycle_active;
    state->observed_monotime_ns = observed_monotime_ns;
    state->connection = *connection;
    state->connection_netns = connection_netns;
    state->process_incarnation = process_incarnation;
    java_remote_parent_init_response(
        &state->response, k_java_remote_parent_status_valid, generation, observed_monotime_ns);
    java_remote_parent_set_context(&state->response, &incoming->tp);

    if (bpf_map_update_elem(&java_remote_parent_state, &key, state, BPF_NOEXIST) != 0) {
        java_remote_parent_rollback_stage(&owner, &key, connection, connection_netns);
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_overload);
        return 0;
    }

    const java_remote_parent_generation_index_t generation_index = {
        .process = java_process_key(&owner),
        .process_incarnation = process_incarnation,
        .observed_monotime_ns = observed_monotime_ns,
    };
    if (bpf_map_update_elem(
            &java_remote_parent_generation_index, &key, &generation_index, BPF_NOEXIST) != 0) {
        java_remote_parent_rollback_stage(&owner, &key, connection, connection_netns);
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_overload);
        return 0;
    }

    java_remote_parent_connection_keys_t *connection_keys = java_remote_parent_connection_keys_for(
        connection, connection_netns, connection_netns_cookie);
    java_remote_parent_connection_t *handoff = java_remote_parent_connection_value_mem();
    if (!connection_keys || !handoff) {
        java_remote_parent_rollback_stage(&owner, &key, connection, connection_netns);
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_overload);
        return 0;
    }
    __builtin_memset(handoff, 0, sizeof(*handoff));
    handoff->owner = owner;
    handoff->netns = connection_netns;
    handoff->generation = generation;
    handoff->netns_cookie = connection_netns_cookie;
    handoff->incoming_generation = incoming_generation;
    if (bpf_map_update_elem(
            &java_remote_parent_connections, &connection_keys->netns, handoff, BPF_NOEXIST) != 0) {
        invalidate_incoming_trace_in_netns_cookie(connection, connection_netns_cookie, now);
        java_remote_parent_mark_connection_ambiguous_in_netns(connection, connection_netns);
        java_remote_parent_rollback_stage(&owner, &key, connection, connection_netns);
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_ambiguous);
        return 0;
    }

    if (bpf_map_update_elem(&java_remote_parent_cookie_connections,
                            &connection_keys->cookie,
                            handoff,
                            BPF_NOEXIST) != 0) {
        invalidate_incoming_trace_in_netns_cookie(connection, connection_netns_cookie, now);
        java_remote_parent_mark_connection_ambiguous_in_netns_cookie(
            connection, connection_netns_cookie, 0);
        java_remote_parent_rollback_stage(&owner, &key, connection, connection_netns);
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_ambiguous);
        return 0;
    }

    if (!incoming_trace_claimed_generation_matches_in_netns_cookie(
            connection, connection_netns_cookie, incoming_generation, incoming) ||
        !java_remote_parent_stage_fallback(&owner, &state->response) ||
        !java_remote_parent_stage_is_consistent(&owner,
                                                &key,
                                                connection,
                                                connection_netns,
                                                connection_netns_cookie,
                                                incoming_generation,
                                                process_incarnation,
                                                incoming)) {
        java_remote_parent_rollback_stage(&owner, &key, connection, connection_netns);
        java_remote_parent_guard_owner_reuse(&owner);
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_ambiguous);
        return 0;
    }

    java_remote_parent_owner_t active = {
        .generation = generation,
        .process_incarnation = process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_active,
    };
    if (bpf_map_update_elem(&java_remote_parent_owners, &owner, &active, BPF_EXIST) != 0) {
        java_remote_parent_rollback_stage(&owner, &key, connection, connection_netns);
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_ambiguous);
        return 0;
    }

    if (java_remote_parent_generation_ambiguous(&key) ||
        !incoming_trace_claimed_generation_matches_in_netns_cookie(
            connection, connection_netns_cookie, incoming_generation, incoming)) {
        java_remote_parent_cleanup(&owner);
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_ambiguous);
        return 0;
    }

    const u64 *data_signal = bpf_map_lookup_elem(&java_remote_parent_data_signals, &owner);
    if (data_signal && *data_signal) {
        const java_remote_parent_data_signal_key_t signal_key = {
            .process = java_process_key(&owner),
            .nonce = *data_signal,
        };
        const java_remote_parent_data_ack_t acknowledgement = {
            .owner = owner,
            .generation = generation,
            .connection = *connection,
            .connection_netns = connection_netns,
        };
        bpf_map_update_elem(&java_remote_parent_data_acks, &signal_key, &acknowledgement, BPF_ANY);
    }

    java_remote_parent_stat_add(k_java_remote_parent_stat_stage_valid);
    return generation;
}

typedef struct java_remote_parent_resolution {
    java_remote_parent_key_t key;
    java_remote_parent_owner_t indexed;
    u8 found;
    u8 ambiguous;
    unsigned char reserved[6];
} java_remote_parent_resolution_t;

static __always_inline void
java_remote_parent_resolve_exact(java_remote_parent_resolution_t *resolution,
                                 const pid_key_t *owner,
                                 u64 expected_generation,
                                 u8 include_terminal) {
    const u64 process_incarnation = java_current_process_incarnation();
    if (!process_incarnation) {
        return;
    }
    const java_remote_parent_owner_t *indexed =
        bpf_map_lookup_elem(&java_remote_parent_owners, owner);
    if (indexed && indexed->process_incarnation == process_incarnation &&
        (!expected_generation || indexed->generation == expected_generation)) {
        resolution->key = java_remote_parent_state_key(owner, indexed->generation);
        resolution->indexed = *indexed;
        resolution->found = 1;
        if (java_remote_parent_generation_ambiguous(&resolution->key)) {
            resolution->ambiguous = 1;
        }
        return;
    }
    if (!include_terminal) {
        return;
    }

    const java_remote_parent_terminal_t *terminal =
        bpf_map_lookup_elem(&java_remote_parent_terminal, owner);
    if (terminal && terminal->process_incarnation == process_incarnation &&
        (!expected_generation || terminal->generation == expected_generation)) {
        resolution->key = java_remote_parent_state_key(owner, terminal->generation);
        resolution->indexed.generation = terminal->generation;
        resolution->indexed.process_incarnation = terminal->process_incarnation;
        resolution->indexed.lifecycle = terminal->lifecycle;
        resolution->found = 1;
        if (java_remote_parent_generation_ambiguous(&resolution->key)) {
            resolution->ambiguous = 1;
        }
    }
}

static __always_inline java_remote_parent_resolution_t
java_remote_parent_resolve(const pid_key_t *start, u64 max_age_ns) {
    java_remote_parent_resolution_t resolution = {0};
    java_remote_parent_resolve_exact(&resolution, start, 0, 0);

    const java_remote_parent_task_t *task = bpf_map_lookup_elem(&java_remote_parent_tasks, start);
    if (task) {
        const java_remote_parent_task_t copy = *task;
        const u64 now = bpf_ktime_get_ns();
        if (!copy.generation || !copy.observed_monotime_ns || now < copy.observed_monotime_ns ||
            (max_age_ns && now - copy.observed_monotime_ns > max_age_ns)) {
            bpf_map_delete_elem(&java_remote_parent_tasks, start);
        } else if (resolution.found &&
                   (!java_remote_parent_pid_key_equal(&resolution.key.owner, &copy.owner) ||
                    resolution.key.generation != copy.generation)) {
            resolution.ambiguous = 1;
            java_remote_parent_mark_ambiguous(start);
            java_remote_parent_mark_ambiguous(&copy.owner);
        } else if (!resolution.found) {
            java_remote_parent_resolve_exact(&resolution, &copy.owner, copy.generation, 1);
        }
    } else if (!resolution.found) {
        java_remote_parent_resolve_exact(&resolution, start, 0, 1);
    }

    return resolution;
}

static __always_inline void java_remote_parent_unlink_task(const pid_key_t *child) {
    bpf_map_delete_elem(&java_remote_parent_tasks, child);
}

static __always_inline java_remote_parent_handoff_key_t
java_remote_parent_handoff_key(const pid_key_t *execution, u64 token) {
    const java_remote_parent_handoff_key_t key = {
        .pid = execution->pid,
        .ns = execution->ns,
        .token = token,
    };
    return key;
}

static __always_inline u8
java_remote_parent_exact_generation_active(const java_remote_parent_key_t *key) {
    const u64 process_incarnation = java_current_process_incarnation();
    if (!process_incarnation) {
        return 0;
    }
    const java_remote_parent_owner_t *indexed =
        bpf_map_lookup_elem(&java_remote_parent_owners, &key->owner);
    if (!indexed || indexed->generation != key->generation ||
        indexed->process_incarnation != process_incarnation ||
        indexed->lifecycle != k_java_remote_parent_lifecycle_active ||
        java_remote_parent_generation_ambiguous(key)) {
        return 0;
    }

    const java_remote_parent_state_t *state = bpf_map_lookup_elem(&java_remote_parent_state, key);
    return state && state->process_incarnation == process_incarnation &&
           state->lifecycle == k_java_remote_parent_lifecycle_active &&
           state->response.status == k_java_remote_parent_status_valid &&
           java_remote_parent_le64_to_cpu(state->response.generation_le) == key->generation &&
           java_remote_parent_generation_index_matches(
               key, process_incarnation, state->observed_monotime_ns) &&
           java_remote_parent_connection_matches_in_netns(
               &state->connection, state->connection_netns, &key->owner, key->generation, 0) &&
           java_remote_parent_fallback_matches(&key->owner, key->generation);
}

static __always_inline void java_remote_parent_capture_handoff(u64 token) {
    if (!token) {
        return;
    }

    const pid_key_t execution = java_remote_parent_current_owner();
    const java_remote_parent_resolution_t resolution = java_remote_parent_resolve(&execution, 0);
    if (resolution.ambiguous || !resolution.found ||
        resolution.indexed.lifecycle != k_java_remote_parent_lifecycle_active ||
        !java_remote_parent_exact_generation_active(&resolution.key)) {
        return;
    }

    const java_remote_parent_handoff_key_t key = java_remote_parent_handoff_key(&execution, token);
    if (bpf_map_lookup_elem(&java_remote_parent_handoff_claims, &key)) {
        java_remote_parent_mark_generation_ambiguous(&resolution.key.owner,
                                                     resolution.key.generation);
        return;
    }

    const java_remote_parent_task_t handoff = {
        .owner = resolution.key.owner,
        .generation = resolution.key.generation,
        .observed_monotime_ns = bpf_ktime_get_ns(),
    };
    if (bpf_map_update_elem(&java_remote_parent_handoffs, &key, &handoff, BPF_NOEXIST) != 0) {
        const java_remote_parent_task_t *existing =
            bpf_map_lookup_elem(&java_remote_parent_handoffs, &key);
        if (existing) {
            const java_remote_parent_task_t copy = *existing;
            bpf_map_delete_elem(&java_remote_parent_handoffs, &key);
            java_remote_parent_mark_generation_ambiguous(&copy.owner, copy.generation);
            java_remote_parent_mark_generation_ambiguous(&resolution.key.owner,
                                                         resolution.key.generation);
        } else {
            java_remote_parent_stat_add(k_java_remote_parent_stat_stage_overload);
        }
        return;
    }

    const java_remote_parent_task_t *published =
        bpf_map_lookup_elem(&java_remote_parent_handoffs, &key);
    if (!published || published->generation != resolution.key.generation ||
        !java_remote_parent_pid_key_equal(&published->owner, &resolution.key.owner) ||
        bpf_map_lookup_elem(&java_remote_parent_handoff_claims, &key) ||
        !java_remote_parent_exact_generation_active(&resolution.key)) {
        bpf_map_delete_elem(&java_remote_parent_handoffs, &key);
        java_remote_parent_mark_generation_ambiguous(&resolution.key.owner,
                                                     resolution.key.generation);
    }
}

static __always_inline void java_remote_parent_cancel_handoff(const pid_key_t *execution,
                                                              u64 token) {
    if (!token) {
        return;
    }
    const java_remote_parent_handoff_key_t key = java_remote_parent_handoff_key(execution, token);
    const java_remote_parent_handoff_claim_t claimed = {
        .observed_monotime_ns = bpf_ktime_get_ns(),
        .process_incarnation = java_process_incarnation_for(execution),
    };
    bpf_map_update_elem(&java_remote_parent_handoff_claims, &key, &claimed, BPF_NOEXIST);
    bpf_map_delete_elem(&java_remote_parent_handoffs, &key);
}

static __always_inline void java_remote_parent_fail_handoff(const pid_key_t *child) {
    java_remote_parent_unlink_task(child);
    java_remote_parent_mark_ambiguous(child);
}

static __always_inline void java_remote_parent_link_handoff(const pid_key_t *child, u64 token) {
    java_remote_parent_unlink_task(child);
    if (!token) {
        return;
    }

    const java_remote_parent_handoff_key_t key = java_remote_parent_handoff_key(child, token);
    const java_remote_parent_handoff_claim_t claimed = {
        .observed_monotime_ns = bpf_ktime_get_ns(),
        .process_incarnation = java_process_incarnation_for(child),
    };
    if (bpf_map_update_elem(&java_remote_parent_handoff_claims, &key, &claimed, BPF_NOEXIST) != 0) {
        java_remote_parent_fail_handoff(child);
        return;
    }

    const java_remote_parent_task_t *found =
        bpf_map_lookup_elem(&java_remote_parent_handoffs, &key);
    if (!found) {
        java_remote_parent_fail_handoff(child);
        return;
    }
    const java_remote_parent_task_t handoff = *found;
    bpf_map_delete_elem(&java_remote_parent_handoffs, &key);

    const java_remote_parent_key_t generation =
        java_remote_parent_state_key(&handoff.owner, handoff.generation);
    if (!handoff.generation || !java_remote_parent_exact_generation_active(&generation)) {
        java_remote_parent_fail_handoff(child);
        return;
    }

    java_remote_parent_task_t link = handoff;
    link.observed_monotime_ns = bpf_ktime_get_ns();
    if (bpf_map_update_elem(&java_remote_parent_tasks, child, &link, BPF_ANY) != 0 ||
        !java_remote_parent_exact_generation_active(&generation)) {
        java_remote_parent_fail_handoff(child);
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_overload);
    }
}

static __always_inline void java_remote_parent_capture_relay(const pid_key_t *execution,
                                                             u64 token) {
    if (!token) {
        return;
    }

    const java_remote_parent_task_t *linked =
        bpf_map_lookup_elem(&java_remote_parent_tasks, execution);
    if (!linked) {
        return;
    }
    const java_remote_parent_task_t relay = *linked;

    const java_remote_parent_key_t generation =
        java_remote_parent_state_key(&relay.owner, relay.generation);
    if (!relay.generation || !relay.observed_monotime_ns ||
        !java_remote_parent_exact_generation_active(&generation)) {
        return;
    }

    const java_remote_parent_handoff_key_t key = java_remote_parent_handoff_key(execution, token);
    if (bpf_map_lookup_elem(&java_remote_parent_handoff_claims, &key) ||
        bpf_map_update_elem(&java_remote_parent_handoffs, &key, &relay, BPF_NOEXIST) != 0) {
        const java_remote_parent_task_t *existing =
            bpf_map_lookup_elem(&java_remote_parent_handoffs, &key);
        if (existing) {
            const java_remote_parent_task_t copy = *existing;
            bpf_map_delete_elem(&java_remote_parent_handoffs, &key);
            java_remote_parent_mark_generation_ambiguous(&copy.owner, copy.generation);
        }
        java_remote_parent_mark_generation_ambiguous(&relay.owner, relay.generation);
        return;
    }

    const java_remote_parent_task_t *published =
        bpf_map_lookup_elem(&java_remote_parent_handoffs, &key);
    linked = bpf_map_lookup_elem(&java_remote_parent_tasks, execution);
    if (!published || published->generation != relay.generation ||
        published->observed_monotime_ns != relay.observed_monotime_ns ||
        !java_remote_parent_pid_key_equal(&published->owner, &relay.owner) || !linked ||
        linked->generation != relay.generation ||
        linked->observed_monotime_ns != relay.observed_monotime_ns ||
        !java_remote_parent_pid_key_equal(&linked->owner, &relay.owner) ||
        bpf_map_lookup_elem(&java_remote_parent_handoff_claims, &key) ||
        !java_remote_parent_exact_generation_active(&generation)) {
        bpf_map_delete_elem(&java_remote_parent_handoffs, &key);
        java_remote_parent_mark_generation_ambiguous(&relay.owner, relay.generation);
    }
}

static __always_inline enum java_remote_parent_status
java_remote_parent_status_for_lifecycle(enum java_remote_parent_lifecycle lifecycle) {
    switch (lifecycle) {
    case k_java_remote_parent_lifecycle_active:
        return k_java_remote_parent_status_valid;
    case k_java_remote_parent_lifecycle_publishing:
        return k_java_remote_parent_status_missing;
    case k_java_remote_parent_lifecycle_stale:
        return k_java_remote_parent_status_stale;
    case k_java_remote_parent_lifecycle_ambiguous:
        return k_java_remote_parent_status_ambiguous;
    case k_java_remote_parent_lifecycle_consumed:
    case k_java_remote_parent_lifecycle_discarded:
        return k_java_remote_parent_status_already_consumed;
    }
    return k_java_remote_parent_status_missing;
}

static __always_inline void
java_remote_parent_finish_generation(const java_remote_parent_resolution_t *resolution,
                                     enum java_remote_parent_lifecycle lifecycle,
                                     u64 observed_monotime_ns) {
    u64 process_incarnation = resolution->indexed.process_incarnation;
    const java_remote_parent_state_t *state =
        bpf_map_lookup_elem(&java_remote_parent_state, &resolution->key);
    if (state) {
        process_incarnation = state->process_incarnation;
        java_remote_parent_release_connection(&resolution->key.owner,
                                              resolution->key.generation,
                                              &state->connection,
                                              state->connection_netns);
    }

    java_remote_parent_terminal_t terminal = {
        .generation = resolution->key.generation,
        .observed_monotime_ns = observed_monotime_ns,
        .process_incarnation = process_incarnation,
        .lifecycle = lifecycle,
    };
    bpf_map_update_elem(&java_remote_parent_terminal, &resolution->key.owner, &terminal, BPF_ANY);

    const java_remote_parent_owner_t *indexed =
        bpf_map_lookup_elem(&java_remote_parent_owners, &resolution->key.owner);
    const u8 owns_generation = indexed && indexed->generation == resolution->key.generation;
    bpf_map_delete_elem(&java_remote_parent_state, &resolution->key);
    java_remote_parent_cleanup_fallback_generation(&resolution->key.owner,
                                                   resolution->key.generation);
    bpf_map_delete_elem(&java_remote_parent_ambiguity, &resolution->key);
    bpf_map_delete_elem(&java_remote_parent_generation_index, &resolution->key);
    if (owns_generation) {
        bpf_map_delete_elem(&java_remote_parent_owners, &resolution->key.owner);
    }
    bpf_map_delete_elem(&java_remote_parent_claims, &resolution->key);
}

static __always_inline enum java_remote_parent_status
java_remote_parent_claim(const java_remote_parent_resolution_t *resolution, u8 discard) {
    const java_remote_parent_claim_t claim = {
        .observed_monotime_ns = bpf_ktime_get_ns(),
        .process_incarnation = resolution->indexed.process_incarnation,
        .lifecycle = discard ? k_java_remote_parent_lifecycle_discarded
                             : k_java_remote_parent_lifecycle_consumed,
    };
    if (bpf_map_update_elem(&java_remote_parent_claims, &resolution->key, &claim, BPF_NOEXIST) ==
        0) {
        return k_java_remote_parent_status_valid;
    }

    const java_remote_parent_claim_t *claimed =
        bpf_map_lookup_elem(&java_remote_parent_claims, &resolution->key);
    if (claimed && claimed->lifecycle == k_java_remote_parent_lifecycle_ambiguous) {
        return k_java_remote_parent_status_ambiguous;
    }
    if (claimed) {
        return k_java_remote_parent_status_already_consumed;
    }
    return k_java_remote_parent_status_overload;
}

static __always_inline enum java_remote_parent_status
java_remote_parent_retrieve_for_connection(java_remote_parent_response_t *response,
                                           u8 discard,
                                           u64 max_age_ns,
                                           const connection_info_t *expected_connection,
                                           u32 expected_connection_netns,
                                           u64 expected_generation) {
    const pid_key_t start = java_remote_parent_current_owner();
    const java_remote_parent_resolution_t resolution =
        java_remote_parent_resolve(&start, max_age_ns);

    if (expected_connection && resolution.found && expected_generation &&
        resolution.key.generation != expected_generation) {
        java_remote_parent_init_response(
            response, k_java_remote_parent_status_missing, resolution.key.generation, 0);
        java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_missing);
        return k_java_remote_parent_status_missing;
    }
    if (expected_connection && resolution.found) {
        const java_remote_parent_state_t *bound_state =
            bpf_map_lookup_elem(&java_remote_parent_state, &resolution.key);
        if (!bound_state || bound_state->connection_netns != expected_connection_netns ||
            __builtin_memcmp(
                &bound_state->connection, expected_connection, sizeof(*expected_connection)) != 0) {
            java_remote_parent_init_response(
                response, k_java_remote_parent_status_missing, resolution.key.generation, 0);
            java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_missing);
            return k_java_remote_parent_status_missing;
        }
    }

    if (resolution.ambiguous) {
        u64 observed_monotime_ns = 0;
        if (resolution.found &&
            resolution.indexed.lifecycle != k_java_remote_parent_lifecycle_publishing &&
            java_remote_parent_claim(&resolution, 1) == k_java_remote_parent_status_valid) {
            const java_remote_parent_state_t *state =
                bpf_map_lookup_elem(&java_remote_parent_state, &resolution.key);
            if (state) {
                observed_monotime_ns = state->observed_monotime_ns;
            }
            java_remote_parent_finish_generation(
                &resolution, k_java_remote_parent_lifecycle_ambiguous, observed_monotime_ns);
        }
        java_remote_parent_init_response(response,
                                         k_java_remote_parent_status_ambiguous,
                                         resolution.found ? resolution.key.generation : 0,
                                         observed_monotime_ns);
        java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_ambiguous);
        return k_java_remote_parent_status_ambiguous;
    }
    if (!resolution.found) {
        java_remote_parent_init_response(response, k_java_remote_parent_status_missing, 0, 0);
        java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_missing);
        return k_java_remote_parent_status_missing;
    }

    if (resolution.indexed.lifecycle != k_java_remote_parent_lifecycle_active) {
        const java_remote_parent_terminal_t *terminal =
            bpf_map_lookup_elem(&java_remote_parent_terminal, &resolution.key.owner);
        const u64 observed_monotime_ns = terminal ? terminal->observed_monotime_ns : 0;
        const enum java_remote_parent_status status =
            java_remote_parent_status_for_lifecycle(resolution.indexed.lifecycle);
        java_remote_parent_init_response(
            response, status, resolution.key.generation, observed_monotime_ns);
        java_remote_parent_retrieval_stat(discard, status);
        return status;
    }

    const java_remote_parent_response_t *fallback =
        bpf_map_lookup_elem(&java_remote_parent_fallback, &resolution.key.owner);
    if (!fallback) {
        java_remote_parent_init_response(
            response, k_java_remote_parent_status_missing, resolution.key.generation, 0);
        java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_missing);
        return k_java_remote_parent_status_missing;
    }
    if (fallback->status != k_java_remote_parent_status_valid ||
        java_remote_parent_le64_to_cpu(fallback->generation_le) != resolution.key.generation) {
        java_remote_parent_init_response(
            response, k_java_remote_parent_status_ambiguous, resolution.key.generation, 0);
        java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_ambiguous);
        return k_java_remote_parent_status_ambiguous;
    }

    const enum java_remote_parent_status claim_status =
        java_remote_parent_claim(&resolution, discard);
    if (claim_status != k_java_remote_parent_status_valid) {
        java_remote_parent_init_response(response, claim_status, resolution.key.generation, 0);
        java_remote_parent_retrieval_stat(discard, claim_status);
        return claim_status;
    }

    java_remote_parent_state_t *state =
        bpf_map_lookup_elem(&java_remote_parent_state, &resolution.key);
    if (!state) {
        java_remote_parent_init_response(
            response, k_java_remote_parent_status_missing, resolution.key.generation, 0);
        java_remote_parent_finish_generation(
            &resolution, k_java_remote_parent_lifecycle_discarded, 0);
        java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_missing);
        return k_java_remote_parent_status_missing;
    }

    const java_remote_parent_response_t *claimed_fallback =
        bpf_map_lookup_elem(&java_remote_parent_fallback, &resolution.key.owner);
    if (state->process_incarnation != resolution.indexed.process_incarnation ||
        state->process_incarnation != java_current_process_incarnation() ||
        state->lifecycle != k_java_remote_parent_lifecycle_active ||
        java_remote_parent_generation_ambiguous(&resolution.key) ||
        !java_remote_parent_connection_matches_in_netns(&state->connection,
                                                        state->connection_netns,
                                                        &resolution.key.owner,
                                                        resolution.key.generation,
                                                        0) ||
        !claimed_fallback || claimed_fallback->status != k_java_remote_parent_status_valid ||
        java_remote_parent_le64_to_cpu(claimed_fallback->generation_le) !=
            resolution.key.generation) {
        java_remote_parent_init_response(
            response, k_java_remote_parent_status_ambiguous, resolution.key.generation, 0);
        java_remote_parent_finish_generation(
            &resolution, k_java_remote_parent_lifecycle_ambiguous, state->observed_monotime_ns);
        java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_ambiguous);
        return k_java_remote_parent_status_ambiguous;
    }

    const u64 now = bpf_ktime_get_ns();
    enum java_remote_parent_lifecycle lifecycle = state->lifecycle;
    const u64 observed_monotime_ns = state->observed_monotime_ns;
    u8 copied_valid = 0;

    if (lifecycle == k_java_remote_parent_lifecycle_active &&
        java_remote_parent_observation_stale(now, observed_monotime_ns, max_age_ns)) {
        lifecycle = k_java_remote_parent_lifecycle_stale;
    } else if (lifecycle == k_java_remote_parent_lifecycle_active) {
        if (discard) {
            lifecycle = k_java_remote_parent_lifecycle_discarded;
        } else {
            __builtin_memcpy(response, &state->response, sizeof(*response));
            copied_valid = 1;
            lifecycle = k_java_remote_parent_lifecycle_consumed;
        }
    }

    java_remote_parent_finish_generation(&resolution, lifecycle, observed_monotime_ns);

    if (copied_valid) {
        java_remote_parent_retrieval_stat(0, k_java_remote_parent_status_valid);
        return k_java_remote_parent_status_valid;
    }
    if (discard && lifecycle == k_java_remote_parent_lifecycle_discarded) {
        java_remote_parent_init_response(response,
                                         k_java_remote_parent_status_missing,
                                         resolution.key.generation,
                                         observed_monotime_ns);
        java_remote_parent_retrieval_stat(1, k_java_remote_parent_status_valid);
        return k_java_remote_parent_status_missing;
    }

    const enum java_remote_parent_status status =
        java_remote_parent_status_for_lifecycle(lifecycle);
    java_remote_parent_init_response(
        response, status, resolution.key.generation, observed_monotime_ns);
    java_remote_parent_retrieval_stat(discard, status);
    return status;
}

static __always_inline enum java_remote_parent_status
java_remote_parent_retrieve(java_remote_parent_response_t *response, u8 discard, u64 max_age_ns) {
    return java_remote_parent_retrieve_for_connection(response, discard, max_age_ns, NULL, 0, 0);
}
