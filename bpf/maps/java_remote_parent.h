// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/compiler.h>

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
    unsigned char reserved[3];
    u32 aliases;
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

// Task and handoff aliases outlive the singleton owner/terminal cursors. Keep
// their replay authority under the full immutable generation provenance so a
// reused owner/generation pair cannot adopt an older terminal outcome.
typedef struct java_remote_parent_alias_replay_key {
    pid_key_t owner;
    u32 reserved;
    u64 generation;
    u64 generation_observed_monotime_ns;
    u64 process_incarnation;
} java_remote_parent_alias_replay_key_t;

typedef struct java_remote_parent_alias_replay {
    u64 transition_monotime_ns;
    u32 references;
    u8 lifecycle;
    u8 desired_lifecycle;
    u8 producer_tag;
    u8 reserved;
} java_remote_parent_alias_replay_t;

typedef struct java_remote_parent_cleanup_scratch {
    union {
        java_remote_parent_owner_t indexed;
        java_remote_parent_claim_t guard_claim;
    };
    java_remote_parent_key_t key;
    java_remote_parent_claim_t claim;
    java_remote_parent_connection_key_t connection_key;
    java_remote_parent_key_t guard_key;
    u32 connection_netns;
    u32 reserved;
    u64 connection_netns_cookie;
    u64 incoming_generation;
    u64 socket_cookie;
} java_remote_parent_cleanup_scratch_t;

typedef struct java_remote_parent_cleanup_workspace {
    u32 busy;
    u32 reserved;
    java_remote_parent_cleanup_scratch_t scratch;
} java_remote_parent_cleanup_workspace_t;

typedef struct java_remote_parent_janitor_workspace {
    u32 busy;
    u32 reserved;
    java_remote_parent_key_t key;
    java_remote_parent_claim_t claim;
    java_remote_parent_connection_key_t connection_key;
} java_remote_parent_janitor_workspace_t;

typedef struct java_remote_parent_stage_transaction {
    java_remote_parent_key_t key;
    java_remote_parent_claim_t claim;
    u64 connection_netns_cookie;
    u64 incoming_generation;
    u64 socket_cookie;
} java_remote_parent_stage_transaction_t;

typedef struct java_remote_parent_finish_guard {
    java_remote_parent_key_t key;
    java_remote_parent_claim_t claim;
    u64 terminal_generation;
    u8 physical_detached;
    u8 replay_required;
    unsigned char reserved[6];
} java_remote_parent_finish_guard_t;

// These guard/claim tokens must remain invocation-local. This header is also
// reachable from preemptible cgroup sockopt programs, where a per-CPU scratch
// value can be overwritten by another task scheduled on the same CPU.
typedef struct java_remote_parent_receive_detach_scratch {
    java_remote_parent_key_t guard_key;
    java_remote_parent_claim_t guard_claim;
    java_remote_parent_claim_t generation_claim;
} java_remote_parent_receive_detach_scratch_t;

_Static_assert(offsetof(java_remote_parent_key_t, generation) == 16,
               "java remote-parent key generation offset mismatch");
_Static_assert(sizeof(java_remote_parent_key_t) == 24, "java remote-parent key size mismatch");
_Static_assert(offsetof(java_remote_parent_state_t, connection) == 16,
               "java remote-parent state connection offset mismatch");
_Static_assert(offsetof(java_remote_parent_state_t, lifecycle) == 0,
               "java remote-parent state lifecycle offset mismatch");
_Static_assert(offsetof(java_remote_parent_state_t, reserved) == 1,
               "java remote-parent state reserved offset mismatch");
_Static_assert(offsetof(java_remote_parent_state_t, aliases) == 4,
               "java remote-parent state aliases offset mismatch");
_Static_assert(offsetof(java_remote_parent_state_t, process_incarnation) == 56,
               "java remote-parent state process incarnation offset mismatch");
_Static_assert(offsetof(java_remote_parent_state_t, response) == 64,
               "java remote-parent state response offset mismatch");
_Static_assert(sizeof(java_remote_parent_state_t) == 128, "java remote-parent state size mismatch");
_Static_assert(sizeof(java_remote_parent_terminal_t) == 32,
               "java remote-parent terminal size mismatch");
_Static_assert(offsetof(java_remote_parent_terminal_t, generation) == 0,
               "java remote-parent terminal generation offset mismatch");
_Static_assert(offsetof(java_remote_parent_terminal_t, observed_monotime_ns) == 8,
               "java remote-parent terminal observation offset mismatch");
_Static_assert(offsetof(java_remote_parent_terminal_t, process_incarnation) == 16,
               "java remote-parent terminal process-incarnation offset mismatch");
_Static_assert(offsetof(java_remote_parent_terminal_t, lifecycle) == 24,
               "java remote-parent terminal lifecycle offset mismatch");
_Static_assert(offsetof(java_remote_parent_terminal_t, reserved) == 25,
               "java remote-parent terminal reserved offset mismatch");
_Static_assert(offsetof(java_remote_parent_task_t, generation) == 16,
               "java remote-parent task generation offset mismatch");
_Static_assert(sizeof(java_remote_parent_task_t) == 32, "java remote-parent task size mismatch");
_Static_assert(sizeof(java_remote_parent_handoff_key_t) == 16,
               "java remote-parent handoff key size mismatch");
_Static_assert(sizeof(java_remote_parent_generation_index_t) == 32,
               "java remote-parent generation index size mismatch");
_Static_assert(sizeof(java_remote_parent_handoff_claim_t) == 16,
               "java remote-parent handoff claim size mismatch");
_Static_assert(sizeof(java_remote_parent_alias_replay_key_t) == 40,
               "java remote-parent alias replay key size mismatch");
_Static_assert(offsetof(java_remote_parent_alias_replay_key_t, reserved) == 12,
               "java remote-parent alias replay key reserved offset mismatch");
_Static_assert(offsetof(java_remote_parent_alias_replay_key_t, generation) == 16,
               "java remote-parent alias replay key generation offset mismatch");
_Static_assert(offsetof(java_remote_parent_alias_replay_key_t, generation_observed_monotime_ns) ==
                   24,
               "java remote-parent alias replay key observation offset mismatch");
_Static_assert(offsetof(java_remote_parent_alias_replay_key_t, process_incarnation) == 32,
               "java remote-parent alias replay key incarnation offset mismatch");
_Static_assert(sizeof(java_remote_parent_alias_replay_t) == 16,
               "java remote-parent alias replay size mismatch");
_Static_assert(offsetof(java_remote_parent_alias_replay_t, transition_monotime_ns) == 0,
               "java remote-parent alias replay transition offset mismatch");
_Static_assert(offsetof(java_remote_parent_alias_replay_t, references) == 8,
               "java remote-parent alias replay references offset mismatch");
_Static_assert(offsetof(java_remote_parent_alias_replay_t, lifecycle) == 12,
               "java remote-parent alias replay lifecycle offset mismatch");
_Static_assert(offsetof(java_remote_parent_alias_replay_t, desired_lifecycle) == 13,
               "java remote-parent alias replay desired lifecycle offset mismatch");
_Static_assert(offsetof(java_remote_parent_alias_replay_t, producer_tag) == 14,
               "java remote-parent alias replay producer offset mismatch");
_Static_assert(offsetof(java_remote_parent_alias_replay_t, reserved) == 15,
               "java remote-parent alias replay reserved offset mismatch");
_Static_assert(sizeof(java_remote_parent_cleanup_scratch_t) == 176,
               "java remote-parent cleanup scratch size mismatch");
_Static_assert(sizeof(java_remote_parent_cleanup_workspace_t) == 184,
               "java remote-parent cleanup workspace size mismatch");
_Static_assert(sizeof(java_remote_parent_janitor_workspace_t) == 104,
               "java remote-parent janitor workspace size mismatch");
_Static_assert(sizeof(java_remote_parent_stage_transaction_t) == 72,
               "java remote-parent stage transaction size mismatch");
_Static_assert(sizeof(java_remote_parent_finish_guard_t) == 64,
               "java remote-parent finish guard size mismatch");
_Static_assert(offsetof(java_remote_parent_finish_guard_t, terminal_generation) == 48,
               "java remote-parent finish guard terminal offset mismatch");
_Static_assert(offsetof(java_remote_parent_finish_guard_t, physical_detached) == 56,
               "java remote-parent finish guard physical-detached offset mismatch");
_Static_assert(offsetof(java_remote_parent_finish_guard_t, replay_required) == 57,
               "java remote-parent finish guard replay-required offset mismatch");
_Static_assert(offsetof(java_remote_parent_finish_guard_t, reserved) == 58,
               "java remote-parent finish guard reserved offset mismatch");
_Static_assert(sizeof(java_remote_parent_data_ack_t) <= sizeof(java_remote_parent_state_t),
               "java remote-parent data acknowledgement exceeds stage state scratch");
_Static_assert(sizeof(java_remote_parent_receive_detach_scratch_t) <=
                   sizeof(java_remote_parent_state_t),
               "java remote-parent receive detach scratch size mismatch");

typedef struct java_remote_parent_incoming {
    tp_info_pid_t candidate;
    u64 generation;
} java_remote_parent_incoming_t;

SCRATCH_MEM_TYPED(java_remote_parent_stage_state, java_remote_parent_state_t)
SCRATCH_MEM_TYPED(java_remote_parent_incoming_snapshot, java_remote_parent_incoming_t)
SCRATCH_MEM_TYPED(java_remote_parent_connection_snapshot, connection_info_t)
SCRATCH_MEM_TYPED(java_remote_parent_cleanup_workspace, java_remote_parent_cleanup_workspace_t)
SCRATCH_MEM_TYPED(java_remote_parent_janitor_workspace, java_remote_parent_janitor_workspace_t)

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

// Alias replay capacity is deliberately partitioned from the one-shot claim
// pool. It is a non-evicting HASH: capacity pressure rejects a new alias before
// publication instead of silently evicting an older exact replay authority.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, java_remote_parent_alias_replay_key_t);
    __type(value, java_remote_parent_alias_replay_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_remote_parent_alias_replays SEC(".maps");

static __always_inline u8 java_remote_parent_pid_key_equal(const pid_key_t *left,
                                                           const pid_key_t *right) {
    volatile u32 mismatch =
        (left->tid ^ right->tid) | (left->pid ^ right->pid) | (left->ns ^ right->ns);
    return mismatch == 0;
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

static __always_inline java_remote_parent_alias_replay_key_t java_remote_parent_alias_replay_key(
    const java_remote_parent_key_t *key, u64 observed_monotime_ns, u64 process_incarnation) {
    return (java_remote_parent_alias_replay_key_t){
        .owner = key->owner,
        .generation = key->generation,
        .generation_observed_monotime_ns = observed_monotime_ns,
        .process_incarnation = process_incarnation,
    };
}

static __always_inline u8
java_remote_parent_alias_replay_key_valid(const java_remote_parent_alias_replay_key_t *key) {
    return key && !key->reserved && key->generation && key->generation_observed_monotime_ns &&
           key->process_incarnation;
}

static __always_inline u8 java_remote_parent_alias_replay_lifecycle_final(u8 lifecycle) {
    return lifecycle >= k_java_remote_parent_lifecycle_consumed &&
           lifecycle <= k_java_remote_parent_lifecycle_ambiguous;
}

static __always_inline u8 java_remote_parent_alias_replay_producer_valid(u8 producer_tag) {
    return !producer_tag || producer_tag == k_java_remote_parent_go_producer_tag;
}

static __always_inline u8
java_remote_parent_alias_replay_active_valid(const java_remote_parent_alias_replay_key_t *key,
                                             const java_remote_parent_alias_replay_t *replay,
                                             u8 require_reference) {
    return java_remote_parent_alias_replay_key_valid(key) && replay &&
           replay->transition_monotime_ns && (!require_reference || replay->references) &&
           java_remote_parent_metadata_word(&replay->lifecycle) ==
               k_java_remote_parent_lifecycle_active;
}

static __always_inline u8
java_remote_parent_alias_replay_publishing_valid(const java_remote_parent_alias_replay_key_t *key,
                                                 const java_remote_parent_alias_replay_t *replay,
                                                 u8 lifecycle) {
    if (!java_remote_parent_alias_replay_key_valid(key) || !replay ||
        !replay->transition_monotime_ns ||
        !java_remote_parent_alias_replay_lifecycle_final(lifecycle)) {
        return 0;
    }
    const u32 expected = k_java_remote_parent_lifecycle_publishing | ((u32)lifecycle << 8);
    const u32 metadata = java_remote_parent_metadata_word(&replay->lifecycle);
    return metadata == expected ||
           metadata == (expected | ((u32)k_java_remote_parent_go_producer_tag << 16));
}

static __always_inline u8
java_remote_parent_alias_replay_final_valid(const java_remote_parent_alias_replay_key_t *key,
                                            const java_remote_parent_alias_replay_t *replay,
                                            u8 lifecycle) {
    return java_remote_parent_alias_replay_key_valid(key) && replay &&
           replay->transition_monotime_ns &&
           java_remote_parent_alias_replay_lifecycle_final(lifecycle) &&
           java_remote_parent_metadata_word(&replay->lifecycle) == lifecycle;
}

static __always_inline u8
java_remote_parent_alias_replay_generation_fenced(const java_remote_parent_key_t *key) {
    return bpf_map_lookup_elem(&java_remote_parent_claims, key) ||
           java_remote_parent_detach_guard_matches(key);
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
    if (!indexed) {
        return 0;
    }
    const pid_key_t process = java_process_key(&key->owner);
    volatile u64 mismatch = indexed->reserved | (indexed->process.tid ^ process.tid) |
                            (indexed->process.pid ^ process.pid) |
                            (indexed->process.ns ^ process.ns) |
                            (indexed->process_incarnation ^ process_incarnation) |
                            (indexed->observed_monotime_ns ^ observed_monotime_ns);
    return mismatch == 0;
}

static __always_inline u8 java_remote_parent_generation_state_index_active_for_incarnation(
    const java_remote_parent_key_t *key, u64 process_incarnation) {
    if (!process_incarnation || !java_remote_parent_generation_cleanly_reserved(key)) {
        return 0;
    }

    const java_remote_parent_state_t *state = bpf_map_lookup_elem(&java_remote_parent_state, key);
    return state && state->process_incarnation == process_incarnation &&
           state->observed_monotime_ns &&
           state->lifecycle == k_java_remote_parent_lifecycle_active &&
           state->response.status == k_java_remote_parent_status_valid &&
           java_remote_parent_le64_to_cpu(state->response.generation_le) == key->generation &&
           java_remote_parent_generation_index_matches(
               key, process_incarnation, state->observed_monotime_ns);
}

static __always_inline u8 java_remote_parent_generation_state_active_for_incarnation(
    const java_remote_parent_key_t *key, u64 process_incarnation) {
    if (!java_remote_parent_generation_state_index_active_for_incarnation(key,
                                                                          process_incarnation)) {
        return 0;
    }
    const java_remote_parent_state_t *state = bpf_map_lookup_elem(&java_remote_parent_state, key);
    return state &&
           java_remote_parent_connection_matches_in_netns(
               &state->connection, state->connection_netns, &key->owner, key->generation, 0, 0);
}

static __always_inline u8
java_remote_parent_generation_state_active(const java_remote_parent_key_t *key) {
    return java_remote_parent_generation_state_active_for_incarnation(
        key, java_current_process_incarnation());
}

static __always_inline u8 java_remote_parent_generation_observation_matches(
    const java_remote_parent_key_t *key, u64 observed_monotime_ns) {
    if (!observed_monotime_ns) {
        return 0;
    }
    const java_remote_parent_state_t *state = bpf_map_lookup_elem(&java_remote_parent_state, key);
    return state && state->process_incarnation &&
           state->lifecycle == k_java_remote_parent_lifecycle_active &&
           state->observed_monotime_ns == observed_monotime_ns &&
           state->response.status == k_java_remote_parent_status_valid &&
           java_remote_parent_le64_to_cpu(state->response.generation_le) == key->generation &&
           java_remote_parent_le64_to_cpu(state->response.observed_monotime_ns_le) ==
               observed_monotime_ns &&
           java_remote_parent_generation_index_matches(
               key, state->process_incarnation, observed_monotime_ns);
}

// RESET removes an aliased generation's direct and physical cursors while its
// exact task/handoff aliases remain authoritative. A different-generation
// owner or connection may replace the singleton cursor after RESET.
static __always_inline u8 java_remote_parent_generation_state_detached_for_incarnation(
    const java_remote_parent_key_t *key, u64 process_incarnation) {
    if (!java_remote_parent_generation_state_index_active_for_incarnation(key,
                                                                          process_incarnation)) {
        return 0;
    }
    const java_remote_parent_state_t *state = bpf_map_lookup_elem(&java_remote_parent_state, key);
    if (!state || !state->aliases) {
        return 0;
    }
    const java_remote_parent_owner_t *owner =
        bpf_map_lookup_elem(&java_remote_parent_owners, &key->owner);
    if ((owner && owner->generation == key->generation) ||
        java_remote_parent_fallback_has_generation(&key->owner, key->generation)) {
        return 0;
    }
    const java_remote_parent_terminal_t *terminal =
        bpf_map_lookup_elem(&java_remote_parent_terminal, &key->owner);
    if (terminal && terminal->generation == key->generation) {
        return 0;
    }

    java_remote_parent_connection_key_t connection_key = {0};
    if (!java_remote_parent_connection_netns_key_init(
            &connection_key, &state->connection, state->connection_netns)) {
        return 0;
    }
    const java_remote_parent_connection_t *staged =
        bpf_map_lookup_elem(&java_remote_parent_connections, &connection_key.netns);
    return !staged || staged->generation != key->generation ||
           !java_remote_parent_pid_key_equal(&staged->owner, &key->owner);
}

static __always_inline u8
java_remote_parent_generation_alias_active(const java_remote_parent_key_t *key) {
    const u64 process_incarnation = java_current_process_incarnation();
    return java_remote_parent_generation_state_active_for_incarnation(key, process_incarnation) ||
           java_remote_parent_generation_state_detached_for_incarnation(key, process_incarnation);
}

static __always_inline u8
java_remote_parent_generation_live_cursor_active(const java_remote_parent_key_t *key) {
    const u64 process_incarnation = java_current_process_incarnation();
    if (!java_remote_parent_generation_state_active_for_incarnation(key, process_incarnation)) {
        return 0;
    }
    const java_remote_parent_owner_t *owner =
        bpf_map_lookup_elem(&java_remote_parent_owners, &key->owner);
    return owner && owner->generation == key->generation &&
           owner->process_incarnation == process_incarnation &&
           owner->lifecycle == k_java_remote_parent_lifecycle_active &&
           java_remote_parent_fallback_matches(&key->owner, key->generation);
}

static __always_inline void
java_remote_parent_release_generation_alias(const java_remote_parent_key_t *key,
                                            u64 observed_monotime_ns);
static __always_inline void java_remote_parent_cleanup_detached_zero_alias(
    const java_remote_parent_key_t *key, u64 process_incarnation, u64 observed_monotime_ns);

static __always_inline u8
java_remote_parent_alias_replay_reference_valid(const java_remote_parent_alias_replay_key_t *key,
                                                const java_remote_parent_alias_replay_t *replay) {
    return java_remote_parent_alias_replay_active_valid(key, replay, 0) ||
           (replay && java_remote_parent_alias_replay_publishing_valid(
                          key, replay, replay->desired_lifecycle)) ||
           (replay && java_remote_parent_alias_replay_final_valid(key, replay, replay->lifecycle));
}

static __always_inline void java_remote_parent_alias_replay_release_reference(
    const java_remote_parent_alias_replay_key_t *replay_key) {
    java_remote_parent_alias_replay_t *replay =
        bpf_map_lookup_elem(&java_remote_parent_alias_replays, replay_key);
    if (!java_remote_parent_alias_replay_reference_valid(replay_key, replay) ||
        !replay->references) {
        return;
    }

    // The minimum BPF target guarantees XADD, but not a returned subtract
    // value. Re-read after the decrement and delete only a stable final zero;
    // active zero records are durable reservations for a claim racing the last
    // carrier release.
    __sync_fetch_and_add(&replay->references, (u32)-1);
    replay = bpf_map_lookup_elem(&java_remote_parent_alias_replays, replay_key);
    if (replay && !replay->references &&
        java_remote_parent_alias_replay_final_valid(replay_key, replay, replay->lifecycle)) {
        const java_remote_parent_key_t generation =
            java_remote_parent_state_key(&replay_key->owner, replay_key->generation);
        if (!java_remote_parent_alias_replay_generation_fenced(&generation)) {
            bpf_map_delete_elem(&java_remote_parent_alias_replays, replay_key);
        }
    }
}

static __always_inline void java_remote_parent_alias_replay_unwind_failed_retain(
    const java_remote_parent_key_t *key, const java_remote_parent_alias_replay_key_t *replay_key) {
    // Once E or the exact G guard is visible, a finalizer may already have
    // copied the reference count into a whole-value publishing/final update.
    // A stale decrement could then undercount a real alias. Leave a harmless
    // overcount for coordinated cleanup instead.
    if (java_remote_parent_alias_replay_generation_fenced(key)) {
        return;
    }
    const java_remote_parent_alias_replay_t *replay =
        bpf_map_lookup_elem(&java_remote_parent_alias_replays, replay_key);
    if (!java_remote_parent_alias_replay_active_valid(replay_key, replay, 1)) {
        return;
    }
    barrier();
    if (java_remote_parent_alias_replay_generation_fenced(key)) {
        return;
    }
    java_remote_parent_alias_replay_release_reference(replay_key);
}

static __always_inline u8 java_remote_parent_alias_replay_retain(
    const java_remote_parent_key_t *key, const java_remote_parent_alias_replay_key_t *replay_key) {
    java_remote_parent_alias_replay_t *replay =
        bpf_map_lookup_elem(&java_remote_parent_alias_replays, replay_key);
    if (!replay) {
        const java_remote_parent_alias_replay_t created = {
            .transition_monotime_ns = bpf_ktime_get_ns(),
            .references = 1,
            .lifecycle = k_java_remote_parent_lifecycle_active,
        };
        if (!created.transition_monotime_ns) {
            return 0;
        }
        if (bpf_map_update_elem(
                &java_remote_parent_alias_replays, replay_key, &created, BPF_NOEXIST) == 0) {
            replay = bpf_map_lookup_elem(&java_remote_parent_alias_replays, replay_key);
            if (java_remote_parent_alias_replay_active_valid(replay_key, replay, 1)) {
                return 1;
            }
            java_remote_parent_alias_replay_unwind_failed_retain(key, replay_key);
            return 0;
        }
        replay = bpf_map_lookup_elem(&java_remote_parent_alias_replays, replay_key);
    }
    if (!java_remote_parent_alias_replay_active_valid(replay_key, replay, 0) ||
        replay->references == ~(u32)0) {
        return 0;
    }

    __sync_fetch_and_add(&replay->references, 1);
    replay = bpf_map_lookup_elem(&java_remote_parent_alias_replays, replay_key);
    if (!java_remote_parent_alias_replay_active_valid(replay_key, replay, 1)) {
        java_remote_parent_alias_replay_unwind_failed_retain(key, replay_key);
        return 0;
    }
    return 1;
}

static __always_inline void
java_remote_parent_release_state_alias(const java_remote_parent_key_t *key,
                                       u64 observed_monotime_ns) {
    java_remote_parent_state_t *state = bpf_map_lookup_elem(&java_remote_parent_state, key);
    if (!state || state->lifecycle != k_java_remote_parent_lifecycle_active || !state->aliases ||
        state->observed_monotime_ns != observed_monotime_ns ||
        state->response.status != k_java_remote_parent_status_valid ||
        java_remote_parent_le64_to_cpu(state->response.generation_le) != key->generation ||
        java_remote_parent_le64_to_cpu(state->response.observed_monotime_ns_le) !=
            observed_monotime_ns ||
        !java_remote_parent_generation_index_matches(
            key, state->process_incarnation, observed_monotime_ns)) {
        return;
    }
    const u64 process_incarnation = state->process_incarnation;
    __sync_fetch_and_add(&state->aliases, (u32)-1);

    state = bpf_map_lookup_elem(&java_remote_parent_state, key);
    if (state && !state->aliases && state->process_incarnation == process_incarnation &&
        state->observed_monotime_ns == observed_monotime_ns) {
        java_remote_parent_cleanup_detached_zero_alias(
            key, process_incarnation, observed_monotime_ns);
    }
}

static __always_inline u8 java_remote_parent_retain_generation_alias_with_authority(
    const java_remote_parent_key_t *key, u64 observed_monotime_ns, u8 allow_detached) {
    java_remote_parent_state_t *state = bpf_map_lookup_elem(&java_remote_parent_state, key);
    if (!state || !state->process_incarnation || state->aliases == ~(u32)0 ||
        state->observed_monotime_ns != observed_monotime_ns ||
        !java_remote_parent_generation_index_matches(
            key, state->process_incarnation, observed_monotime_ns)) {
        return 0;
    }
    const u64 process_incarnation = state->process_incarnation;
    const java_remote_parent_alias_replay_key_t replay_key =
        java_remote_parent_alias_replay_key(key, observed_monotime_ns, process_incarnation);
    // Reserve replay capacity and a reference before the first validation that
    // could permit publication. Capacity exhaustion therefore cannot consume
    // E or publish an alias without durable exact replay authority.
    if (!java_remote_parent_alias_replay_retain(key, &replay_key)) {
        return 0;
    }

    if (java_remote_parent_alias_replay_generation_fenced(key) ||
        !java_remote_parent_generation_observation_matches(key, observed_monotime_ns) ||
        (allow_detached ? !java_remote_parent_generation_alias_active(key)
                        : !java_remote_parent_generation_live_cursor_active(key))) {
        java_remote_parent_alias_replay_unwind_failed_retain(key, &replay_key);
        return 0;
    }
    state = bpf_map_lookup_elem(&java_remote_parent_state, key);
    if (!state || state->aliases == ~(u32)0 || state->process_incarnation != process_incarnation ||
        state->observed_monotime_ns != observed_monotime_ns ||
        !java_remote_parent_generation_index_matches(
            key, process_incarnation, observed_monotime_ns)) {
        java_remote_parent_alias_replay_unwind_failed_retain(key, &replay_key);
        return 0;
    }

    __sync_fetch_and_add(&state->aliases, 1);
    const java_remote_parent_alias_replay_t *replay =
        bpf_map_lookup_elem(&java_remote_parent_alias_replays, &replay_key);
    if (java_remote_parent_alias_replay_generation_fenced(key) ||
        !java_remote_parent_alias_replay_active_valid(&replay_key, replay, 1) ||
        !java_remote_parent_generation_observation_matches(key, observed_monotime_ns) ||
        (allow_detached ? !java_remote_parent_generation_alias_active(key)
                        : !java_remote_parent_generation_live_cursor_active(key))) {
        // This retain has not published an alias. RESET either observes the
        // unwind under its guard or userspace reaps a later zero state/index.
        java_remote_parent_release_state_alias(key, observed_monotime_ns);
        java_remote_parent_alias_replay_unwind_failed_retain(key, &replay_key);
        return 0;
    }
    return 1;
}

static __always_inline u8 java_remote_parent_retain_generation_alias(
    const java_remote_parent_key_t *key, u64 observed_monotime_ns) {
    return java_remote_parent_retain_generation_alias_with_authority(key, observed_monotime_ns, 0);
}

static __always_inline u8 java_remote_parent_retain_detached_generation_alias(
    const java_remote_parent_key_t *key, u64 observed_monotime_ns) {
    return java_remote_parent_retain_generation_alias_with_authority(key, observed_monotime_ns, 1);
}

static __always_inline u8
java_remote_parent_mark_exact_generation_ambiguous(const java_remote_parent_key_t *key) {
    return java_remote_parent_mark_exact_ambiguity(key);
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
    // Without a durable generation fence, a lookup-then-key-delete can race a
    // same-owner fallback successor. Leave the old value fail closed; a
    // fenced producer or lifecycle-cleanup handoff may converge it later.
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

// Cleanup-only validation accepts an explicit, already-authorized process
// capability so a missing LRU registration cannot force deletion of a live
// exact task alias. Ordinary capture and retrieval continue to use
// java_remote_parent_generation_state_active().
static __always_inline u8 java_remote_parent_exact_receive_claim_matches(
    const java_remote_parent_key_t *expected, const java_remote_parent_claim_t *local_claim);
static __always_inline u8 java_remote_parent_delete_exact_receive_claim(
    const java_remote_parent_key_t *expected, const java_remote_parent_claim_t *local_claim);
static __always_inline u8 java_remote_parent_release_exact_receive_claim(
    const java_remote_parent_key_t *expected, java_remote_parent_claim_t *local_claim);

static __always_inline u8
java_remote_parent_preserve_alias_barriers_valid(const java_remote_parent_key_t *key,
                                                 const java_remote_parent_claim_t *claim,
                                                 const java_remote_parent_key_t *guard_key,
                                                 const java_remote_parent_claim_t *guard_claim) {
    return java_remote_parent_exact_receive_claim_matches(key, claim) &&
           java_remote_parent_exact_detach_guard_matches_at(guard_key, guard_claim) &&
           java_remote_parent_generation_cleanly_reserved(key);
}

static __always_inline u8 java_remote_parent_preserve_authorized_aliased_generation(
    const pid_key_t *owner, u64 process_capability) {
    if (!process_capability) {
        return 0;
    }
    const java_remote_parent_owner_t *indexed =
        bpf_map_lookup_elem(&java_remote_parent_owners, owner);
    if (!indexed || indexed->process_incarnation != process_capability ||
        indexed->lifecycle != k_java_remote_parent_lifecycle_active) {
        return 0;
    }

    const java_remote_parent_owner_t expected = *indexed;
    const java_remote_parent_key_t key = java_remote_parent_state_key(owner, expected.generation);
    const java_remote_parent_state_t *state = bpf_map_lookup_elem(&java_remote_parent_state, &key);
    if (!state || !state->aliases || state->process_incarnation != expected.process_incarnation ||
        !java_remote_parent_generation_state_active_for_incarnation(&key, process_capability)) {
        return 0;
    }

    java_remote_parent_claim_t claim = {
        .observed_monotime_ns = bpf_ktime_get_ns(),
        .process_incarnation = process_capability,
        .lifecycle = k_java_remote_parent_lifecycle_publishing,
    };
    if (!claim.observed_monotime_ns) {
        return 0;
    }
    if (bpf_map_update_elem(&java_remote_parent_claims, &key, &claim, BPF_NOEXIST) != 0) {
        __builtin_memset(&claim, 0, sizeof(claim));
        return 0;
    }
    if (!java_remote_parent_exact_receive_claim_matches(&key, &claim)) {
        java_remote_parent_handoff_exact_fence(&key, &claim);
        return 0;
    }

    const java_remote_parent_key_t guard_key = java_remote_parent_detach_guard_key(owner);
    java_remote_parent_claim_t guard_claim = {0};
    if (!java_remote_parent_acquire_detach_guard_at(&key, &guard_key, &guard_claim)) {
        if (!java_remote_parent_release_exact_receive_claim(&key, &claim)) {
            java_remote_parent_mark_exact_ambiguity(&key);
        }
        java_remote_parent_handoff_exact_fence_pair(&key, &claim, &guard_key, &guard_claim);
        return 0;
    }

    indexed = bpf_map_lookup_elem(&java_remote_parent_owners, owner);
    state = bpf_map_lookup_elem(&java_remote_parent_state, &key);
    if (!indexed || indexed->generation != expected.generation ||
        indexed->process_incarnation != expected.process_incarnation ||
        indexed->lifecycle != k_java_remote_parent_lifecycle_active || !state || !state->aliases ||
        state->process_incarnation != expected.process_incarnation ||
        !java_remote_parent_preserve_alias_barriers_valid(&key, &claim, &guard_key, &guard_claim)) {
        goto failed;
    }

    bpf_map_delete_elem(&java_remote_parent_owners, owner);
    if (!java_remote_parent_preserve_alias_barriers_valid(&key, &claim, &guard_key, &guard_claim)) {
        goto failed;
    }
    java_remote_parent_cleanup_fallback_generation(owner, key.generation);

    indexed = bpf_map_lookup_elem(&java_remote_parent_owners, owner);
    state = bpf_map_lookup_elem(&java_remote_parent_state, &key);
    const u8 detached =
        (!indexed || indexed->generation != expected.generation) &&
        !java_remote_parent_fallback_has_generation(owner, key.generation) && state &&
        state->aliases &&
        java_remote_parent_generation_state_active_for_incarnation(&key, process_capability) &&
        java_remote_parent_preserve_alias_barriers_valid(&key, &claim, &guard_key, &guard_claim);
    if (!detached) {
        goto failed;
    }

    java_remote_parent_release_exact_receive_claim(&key, &claim);
    if (!bpf_map_lookup_elem(&java_remote_parent_claims, &key) &&
        java_remote_parent_generation_cleanly_reserved(&key)) {
        java_remote_parent_release_exact_detach_guard_at(&guard_key, &guard_claim);
    }
    java_remote_parent_handoff_exact_fence_pair(&key, &claim, &guard_key, &guard_claim);
    return 1;

failed:
    java_remote_parent_mark_exact_ambiguity(&key);
    java_remote_parent_handoff_exact_fence_pair(&key, &claim, &guard_key, &guard_claim);
    return 0;
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

static __always_inline u8
java_remote_parent_exact_receive_connections_absent(const java_remote_parent_key_t *expected,
                                                    const connection_info_t *connection,
                                                    u32 connection_netns,
                                                    u64 connection_netns_cookie,
                                                    u64 socket_cookie);
static __always_inline u8 java_remote_parent_exact_receive_connections_absent_reusing_key(
    const java_remote_parent_key_t *expected,
    java_remote_parent_connection_key_t *key,
    u32 connection_netns,
    u64 connection_netns_cookie,
    u64 socket_cookie);
static __always_inline u8 java_remote_parent_exact_receive_claim_matches(
    const java_remote_parent_key_t *expected, const java_remote_parent_claim_t *local_claim);
static __always_inline u8 java_remote_parent_delete_exact_receive_claim(
    const java_remote_parent_key_t *expected, const java_remote_parent_claim_t *local_claim);
static __always_inline u8 java_remote_parent_mark_exact_receive_cleanup_failed(
    const java_remote_parent_key_t *expected, const java_remote_parent_claim_t *local_claim);
static __always_inline void java_remote_parent_unlink_task(const pid_key_t *child);

static __always_inline u8
java_remote_parent_cleanup_barriers_valid(const java_remote_parent_cleanup_scratch_t *scratch) {
    return java_remote_parent_exact_receive_claim_matches(&scratch->key, &scratch->claim) &&
           java_remote_parent_exact_detach_guard_matches_at(&scratch->guard_key,
                                                            &scratch->guard_claim) &&
           java_remote_parent_generation_ambiguous(&scratch->key);
}

static __always_inline u8
java_remote_parent_cleanup_connection_matches(const java_remote_parent_cleanup_scratch_t *scratch,
                                              const java_remote_parent_connection_t *connection) {
    return connection && !(connection->reserved | connection->reserved2) &&
           connection->generation == scratch->key.generation &&
           java_remote_parent_pid_key_equal(&connection->owner, &scratch->key.owner) &&
           connection->netns == scratch->connection_netns &&
           connection->netns_cookie == scratch->connection_netns_cookie &&
           connection->incoming_generation == scratch->incoming_generation &&
           connection->socket_cookie == scratch->socket_cookie;
}

static __noinline __attribute__((unused)) u8 java_remote_parent_cleanup_acquire(
    const pid_key_t *owner, java_remote_parent_cleanup_scratch_t *scratch) {
    const java_remote_parent_owner_t *indexed =
        bpf_map_lookup_elem(&java_remote_parent_owners, owner);
    if (!indexed) {
        return 0;
    }
    scratch->indexed = *indexed;
    if (scratch->indexed.lifecycle == k_java_remote_parent_lifecycle_publishing) {
        java_remote_parent_mark_ambiguous(owner);
        indexed = bpf_map_lookup_elem(&java_remote_parent_owners, owner);
        if (!indexed || indexed->generation != scratch->indexed.generation ||
            indexed->lifecycle == k_java_remote_parent_lifecycle_publishing) {
            return 0;
        }
        scratch->indexed = *indexed;
    }

    scratch->key = java_remote_parent_state_key(owner, scratch->indexed.generation);
    scratch->claim = (java_remote_parent_claim_t){
        .observed_monotime_ns = bpf_ktime_get_ns(),
        .process_incarnation = scratch->indexed.process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_discarded,
    };
    if (!scratch->claim.observed_monotime_ns ||
        bpf_map_update_elem(
            &java_remote_parent_claims, &scratch->key, &scratch->claim, BPF_NOEXIST) != 0) {
        __builtin_memset(&scratch->claim, 0, sizeof(scratch->claim));
        java_remote_parent_mark_ambiguous(owner);
        return 0;
    }
    if (!java_remote_parent_exact_receive_claim_matches(&scratch->key, &scratch->claim) ||
        !java_remote_parent_mark_exact_ambiguity(&scratch->key)) {
        // The exact claim is already a durable fail-closed fence. Never begin
        // destructive cleanup unless the reserved ambiguity slot was also
        // promoted, because readers use that slot as the publication gate.
        return 0;
    }

    scratch->guard_key = java_remote_parent_detach_guard_key(owner);
    if (!java_remote_parent_acquire_detach_guard_at(
            &scratch->key, &scratch->guard_key, &scratch->guard_claim)) {
        return 0;
    }
    indexed = bpf_map_lookup_elem(&java_remote_parent_owners, owner);
    if (!indexed || indexed->generation != scratch->key.generation ||
        indexed->process_incarnation != scratch->claim.process_incarnation ||
        indexed->lifecycle != k_java_remote_parent_lifecycle_active ||
        __builtin_memcmp(indexed->reserved,
                         (unsigned char[sizeof(indexed->reserved)]){0},
                         sizeof(indexed->reserved)) != 0 ||
        !java_remote_parent_exact_receive_claim_matches(&scratch->key, &scratch->claim) ||
        !java_remote_parent_detach_guard_matches_at(&scratch->key, &scratch->guard_key)) {
        // No generation artifact was mutated. Retain the complete marker,
        // exact-claim, and owner-guard tuple for userspace recovery. Releasing
        // G=0 here would let the outer failure path re-mark an already released
        // generation after a concurrent cleanup completed.
        return 0;
    }

    return java_remote_parent_cleanup_barriers_valid(scratch);
}

static __noinline __attribute__((unused)) u8
java_remote_parent_cleanup_delete_physical(java_remote_parent_cleanup_scratch_t *scratch) {
    if (!java_remote_parent_cleanup_barriers_valid(scratch)) {
        return 0;
    }
    const java_remote_parent_state_t *state =
        bpf_map_lookup_elem(&java_remote_parent_state, &scratch->key);
    if (!state) {
        return 0;
    }
    __builtin_memcpy(&scratch->connection_key.netns.connection,
                     &state->connection,
                     sizeof(scratch->connection_key.netns.connection));
    scratch->connection_netns = state->connection_netns;
    scratch->connection_key.netns.netns = scratch->connection_netns;
    const java_remote_parent_connection_t *connection =
        bpf_map_lookup_elem(&java_remote_parent_connections, &scratch->connection_key.netns);
    if (!connection || connection->reserved || connection->reserved2 ||
        connection->generation != scratch->key.generation ||
        !java_remote_parent_pid_key_equal(&connection->owner, &scratch->key.owner) ||
        connection->netns != scratch->connection_netns || !connection->netns_cookie ||
        !connection->incoming_generation || !connection->socket_cookie) {
        return 0;
    }
    scratch->connection_netns_cookie = connection->netns_cookie;
    scratch->incoming_generation = connection->incoming_generation;
    scratch->socket_cookie = connection->socket_cookie;

    if (!java_remote_parent_cleanup_barriers_valid(scratch) ||
        !java_remote_parent_connection_key_rekey_cookie(&scratch->connection_key,
                                                        scratch->connection_netns_cookie)) {
        return 0;
    }
    connection = bpf_map_lookup_elem(&java_remote_parent_cookie_connections,
                                     &scratch->connection_key.cookie);
    if (!java_remote_parent_cleanup_connection_matches(scratch, connection)) {
        return 0;
    }
    bpf_map_delete_elem(&java_remote_parent_cookie_connections, &scratch->connection_key.cookie);
    connection = bpf_map_lookup_elem(&java_remote_parent_cookie_connections,
                                     &scratch->connection_key.cookie);
    if (connection && connection->generation == scratch->key.generation &&
        java_remote_parent_pid_key_equal(&connection->owner, &scratch->key.owner)) {
        return 0;
    }

    if (!java_remote_parent_cleanup_barriers_valid(scratch) ||
        !java_remote_parent_connection_key_rekey_netns(&scratch->connection_key,
                                                       scratch->connection_netns)) {
        return 0;
    }
    connection =
        bpf_map_lookup_elem(&java_remote_parent_connections, &scratch->connection_key.netns);
    if (!java_remote_parent_cleanup_connection_matches(scratch, connection)) {
        return 0;
    }
    bpf_map_delete_elem(&java_remote_parent_connections, &scratch->connection_key.netns);
    connection =
        bpf_map_lookup_elem(&java_remote_parent_connections, &scratch->connection_key.netns);
    return (!connection || connection->generation != scratch->key.generation ||
            !java_remote_parent_pid_key_equal(&connection->owner, &scratch->key.owner)) &&
           java_remote_parent_cleanup_barriers_valid(scratch);
}

static __always_inline u8 java_remote_parent_cleanup_unlink_deleted_state_task(
    java_remote_parent_cleanup_scratch_t *scratch, u64 observed_monotime_ns) {
    if (!observed_monotime_ns || !java_remote_parent_cleanup_barriers_valid(scratch) ||
        bpf_map_lookup_elem(&java_remote_parent_state, &scratch->key)) {
        return 0;
    }
    const java_remote_parent_task_t *linked =
        bpf_map_lookup_elem(&java_remote_parent_tasks, &scratch->key.owner);
    if (!linked) {
        return 1;
    }
    if (linked->reserved || linked->generation != scratch->key.generation ||
        linked->observed_monotime_ns != observed_monotime_ns ||
        !java_remote_parent_pid_key_equal(&linked->owner, &scratch->key.owner)) {
        // A foreign task binding is not this cleanup's alias. Retain the owner
        // guard and let userspace converge it without deleting another
        // generation's carrier under a reused owner key.
        return 0;
    }

    // The exact owner guard excludes every in-kernel publisher for this task
    // key. Revalidate both the guard and the value immediately before the
    // key-only delete so a replacement observed before this point is retained.
    if (!java_remote_parent_cleanup_barriers_valid(scratch) ||
        bpf_map_lookup_elem(&java_remote_parent_state, &scratch->key)) {
        return 0;
    }
    linked = bpf_map_lookup_elem(&java_remote_parent_tasks, &scratch->key.owner);
    if (!linked || linked->reserved || linked->generation != scratch->key.generation ||
        linked->observed_monotime_ns != observed_monotime_ns ||
        !java_remote_parent_pid_key_equal(&linked->owner, &scratch->key.owner)) {
        return linked == NULL;
    }
    const long deleted = bpf_map_delete_elem(&java_remote_parent_tasks, &scratch->key.owner);
    linked = bpf_map_lookup_elem(&java_remote_parent_tasks, &scratch->key.owner);
    if (linked) {
        return 0;
    }
    if (deleted == 0 && java_remote_parent_cleanup_barriers_valid(scratch) &&
        !bpf_map_lookup_elem(&java_remote_parent_state, &scratch->key)) {
        const java_remote_parent_alias_replay_key_t replay_key =
            java_remote_parent_alias_replay_key(
                &scratch->key, observed_monotime_ns, scratch->claim.process_incarnation);
        java_remote_parent_alias_replay_release_reference(&replay_key);
    }
    return java_remote_parent_cleanup_barriers_valid(scratch) &&
           !bpf_map_lookup_elem(&java_remote_parent_state, &scratch->key);
}

static __noinline __attribute__((unused)) u8
java_remote_parent_cleanup_delete_logical(java_remote_parent_cleanup_scratch_t *scratch) {
    if (!java_remote_parent_cleanup_barriers_valid(scratch)) {
        return 0;
    }
    const java_remote_parent_state_t *state =
        bpf_map_lookup_elem(&java_remote_parent_state, &scratch->key);
    if (!state || !state->observed_monotime_ns ||
        state->process_incarnation != scratch->claim.process_incarnation) {
        return 0;
    }
    const u64 observed_monotime_ns = state->observed_monotime_ns;
    bpf_map_delete_elem(&java_remote_parent_state, &scratch->key);
    const java_remote_parent_terminal_t *terminal =
        bpf_map_lookup_elem(&java_remote_parent_terminal, &scratch->key.owner);
    if (terminal && terminal->generation == scratch->key.generation) {
        bpf_map_delete_elem(&java_remote_parent_terminal, &scratch->key.owner);
    }
    java_remote_parent_cleanup_fallback_generation(&scratch->key.owner, scratch->key.generation);
    bpf_map_delete_elem(&java_remote_parent_generation_index, &scratch->key);
    const java_remote_parent_owner_t *current =
        bpf_map_lookup_elem(&java_remote_parent_owners, &scratch->key.owner);
    if (current && current->generation == scratch->key.generation) {
        bpf_map_delete_elem(&java_remote_parent_owners, &scratch->key.owner);
    }
    // Keep the owner guard through this owner-key deletion and unlink only the
    // exact task whose state was just removed. The ordinary unlink path must
    // conservatively consider a surviving state and invoke its zero-alias
    // janitor; that state is proven absent here under the exact cleanup fences.
    if (!java_remote_parent_cleanup_unlink_deleted_state_task(scratch, observed_monotime_ns)) {
        return 0;
    }
    current = bpf_map_lookup_elem(&java_remote_parent_owners, &scratch->key.owner);
    terminal = bpf_map_lookup_elem(&java_remote_parent_terminal, &scratch->key.owner);
    return java_remote_parent_cleanup_barriers_valid(scratch) &&
           !bpf_map_lookup_elem(&java_remote_parent_state, &scratch->key) &&
           !bpf_map_lookup_elem(&java_remote_parent_generation_index, &scratch->key) &&
           (!current || current->generation != scratch->key.generation) &&
           (!terminal || terminal->generation != scratch->key.generation) &&
           !bpf_map_lookup_elem(&java_remote_parent_tasks, &scratch->key.owner) &&
           !java_remote_parent_fallback_has_generation(&scratch->key.owner,
                                                       scratch->key.generation);
}

static __noinline __attribute__((unused)) u8
java_remote_parent_cleanup_release(java_remote_parent_cleanup_scratch_t *scratch) {
    if (!java_remote_parent_cleanup_barriers_valid(scratch) ||
        !java_remote_parent_exact_receive_connections_absent_reusing_key(
            &scratch->key,
            &scratch->connection_key,
            scratch->connection_netns,
            scratch->connection_netns_cookie,
            scratch->socket_cookie)) {
        return 0;
    }
    bpf_map_delete_elem(&java_remote_parent_ambiguity, &scratch->key);
    if (!java_remote_parent_generation_ambiguity_absent(&scratch->key)) {
        // Payload cleanup is complete. Preserve whichever marker survived the
        // retirement attempt and never let the outer wrapper re-mark old G.
        return 1;
    }
    // Marker deletion completes payload cleanup. Claim/guard retirement is
    // best-effort so a concurrent releaser can never make the outer wrapper
    // recreate an old marker after G=0 linearization.
    java_remote_parent_release_exact_receive_claim(&scratch->key, &scratch->claim);
    if (!bpf_map_lookup_elem(&java_remote_parent_claims, &scratch->key) &&
        java_remote_parent_generation_ambiguity_absent(&scratch->key)) {
        java_remote_parent_release_exact_detach_guard_at(&scratch->guard_key,
                                                         &scratch->guard_claim);
    }
    return 1;
}

static __noinline void java_remote_parent_cleanup(const pid_key_t *owner) {
    java_remote_parent_cleanup_workspace_t *workspace = java_remote_parent_cleanup_workspace_mem();
    if (!workspace || workspace->busy) {
        return;
    }
    workspace->busy = 1;
    barrier();
    java_remote_parent_cleanup_scratch_t *scratch = &workspace->scratch;
    __builtin_memset(scratch, 0, sizeof(*scratch));
    if (!java_remote_parent_cleanup_acquire(owner, scratch) ||
        !java_remote_parent_cleanup_delete_physical(scratch) ||
        !java_remote_parent_cleanup_delete_logical(scratch) ||
        !java_remote_parent_cleanup_release(scratch)) {
        if (scratch->key.generation && scratch->claim.observed_monotime_ns) {
            java_remote_parent_mark_exact_receive_cleanup_failed(&scratch->key, &scratch->claim);
        }
    }

    // This invocation performs no payload mutation after this point. Handoff
    // every exact surviving local fence, including success-path release tails,
    // with fresh timestamps that userspace must age independently.
    java_remote_parent_handoff_exact_fence_pair(
        &scratch->key, &scratch->claim, &scratch->guard_key, &scratch->guard_claim);

    __builtin_memset(scratch, 0, sizeof(*scratch));
    barrier();
    workspace->busy = 0;
}

static __always_inline void java_remote_parent_cleanup_current() {
    const pid_key_t owner = java_remote_parent_current_owner();
    java_remote_parent_cleanup(&owner);
}

static __always_inline void
java_remote_parent_discard_virtual_thread_owner(const pid_key_t *owner) {
    // A prior exact detach may already have removed the direct owner cursor
    // while preserving this synthetic owner's task-only alias. Authorized
    // virtual-thread teardown must unlink that alias even when cleanup has no
    // owner entry from which to discover the generation. Do this before
    // cleanup so no same-owner successor can be unlinked after cleanup releases
    // its final owner guard.
    java_remote_parent_unlink_task(owner);
    java_remote_parent_cleanup(owner);
    bpf_map_delete_elem(&java_tasks, owner);
}

static __always_inline enum java_vt_cleanup_translation_result
java_remote_parent_cleanup_exiting_task_for_capability(const pid_key_t *carrier,
                                                       u64 process_capability,
                                                       pid_key_t *logical_owner) {
    java_remote_parent_cleanup(carrier);
    *logical_owner = *carrier;
    const enum java_vt_cleanup_translation_result translation =
        java_vt_translate_tid_for_capability(logical_owner, process_capability);
    if (translation != k_java_vt_cleanup_translation_none) {
        java_remote_parent_discard_virtual_thread_owner(logical_owner);
    }
    return translation;
}

static __always_inline enum java_vt_cleanup_translation_result
java_remote_parent_cleanup_exiting_task(const pid_key_t *carrier, pid_key_t *logical_owner) {
    return java_remote_parent_cleanup_exiting_task_for_capability(
        carrier, java_process_capability_for(carrier), logical_owner);
}

static __always_inline void
java_remote_parent_discard_unregistered_virtual_thread_lifecycle(const pid_key_t *carrier,
                                                                 u64 process_capability) {
    pid_key_t logical_owner = *carrier;
    java_remote_parent_cleanup_exiting_task_for_capability(
        carrier, process_capability, &logical_owner);
    bpf_map_delete_elem(&java_vt_threads, carrier);
    // Rejected lifecycle events must not expose a stale physical carrier
    // mapping after removing its virtual-thread translation.
    bpf_map_delete_elem(&java_tasks, carrier);
}

static __always_inline void java_remote_parent_discard_unregistered_virtual_thread_id(
    const pid_key_t *carrier, u64 vt_id, u64 process_capability, u8 invalidate_identity) {
    java_remote_parent_discard_unregistered_virtual_thread_lifecycle(carrier, process_capability);

    pid_key_t requested_owner = {0};
    java_vt_identity_t expected_identity = {0};
    if (!java_vt_prepare_unregistered_cleanup(
            carrier, vt_id, process_capability, &requested_owner, &expected_identity)) {
        return;
    }

    // A parked virtual thread has no java_vt_threads entry, so derive its
    // synthetic owner from the authorized payload and discard that key too.
    java_remote_parent_discard_virtual_thread_owner(&requested_owner);
    if (invalidate_identity) {
        // Keep the reusable-key guard until every revivable state entry is
        // gone, and never delete a guard belonging to a low-31-bit collision.
        java_vt_delete_identity_if_matches(&requested_owner, &expected_identity);
    }
}

static __always_inline void
java_remote_parent_discard_unregistered_task_lifecycle(const pid_key_t *carrier,
                                                       u64 process_capability) {
    pid_key_t logical_owner = *carrier;
    const enum java_vt_cleanup_translation_result translation =
        java_vt_translate_tid_for_capability(&logical_owner, process_capability);
    java_remote_parent_unlink_task(carrier);
    if (translation == k_java_vt_cleanup_translation_exact &&
        !java_remote_parent_pid_key_equal(carrier, &logical_owner)) {
        java_remote_parent_unlink_task(&logical_owner);
    } else if (translation == k_java_vt_cleanup_translation_fallback) {
        java_remote_parent_discard_virtual_thread_owner(&logical_owner);
    }
}

static __always_inline void java_remote_parent_detach_data_receive_owner(const pid_key_t *owner,
                                                                         u8 preserve_task_alias,
                                                                         u64 process_capability) {
    if (!preserve_task_alias) {
        java_remote_parent_discard_virtual_thread_owner(owner);
    } else if (!java_remote_parent_preserve_authorized_aliased_generation(owner,
                                                                          process_capability)) {
        java_remote_parent_cleanup(owner);
    }

    const u64 *previous_nonce = bpf_map_lookup_elem(&java_remote_parent_data_signals, owner);
    if (previous_nonce && *previous_nonce) {
        const java_remote_parent_data_signal_key_t previous_key = {
            .process = java_process_key(owner),
            .nonce = *previous_nonce,
        };
        bpf_map_delete_elem(&java_remote_parent_data_acks, &previous_key);
    }
    bpf_map_delete_elem(&java_remote_parent_data_signals, owner);
}

static __noinline __attribute__((unused)) void
java_remote_parent_begin_data_receive_for_capability(u64 process_capability) {
    pid_key_t carrier = {0};
    task_tid(&carrier);
    pid_key_t owner = carrier;
    const enum java_vt_cleanup_translation_result translation =
        java_vt_translate_tid_for_capability(&owner, process_capability);
    if (translation != k_java_vt_cleanup_translation_none) {
        java_remote_parent_detach_data_receive_owner(
            &owner, translation == k_java_vt_cleanup_translation_exact, process_capability);
        if (!java_remote_parent_pid_key_equal(&owner, &carrier)) {
            // A mounted virtual thread must not leave a carrier cursor that can
            // become visible after unmount. Missing owners are a cheap no-op.
            java_remote_parent_detach_data_receive_owner(&carrier, 1, process_capability);
        }
        return;
    }
    java_remote_parent_detach_data_receive_owner(&carrier, 1, process_capability);
}

static __noinline __attribute__((unused)) void java_remote_parent_begin_data_receive() {
    pid_key_t carrier = {0};
    task_tid(&carrier);
    java_remote_parent_begin_data_receive_for_capability(java_process_capability_for(&carrier));
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

enum java_remote_parent_exact_receive_generation_mode : u8 {
    k_java_remote_parent_exact_receive_generation_invalid = 0,
    k_java_remote_parent_exact_receive_generation_direct = 1,
    k_java_remote_parent_exact_receive_generation_detached = 2,
};

static __always_inline u8
java_remote_parent_exact_receive_state_matches(const java_remote_parent_state_t *state,
                                               const java_remote_parent_key_t *expected,
                                               u64 process_incarnation,
                                               const connection_info_t *connection,
                                               u32 connection_netns) {
    return state &&
           java_remote_parent_metadata_word(&state->lifecycle) ==
               k_java_remote_parent_lifecycle_active &&
           state->observed_monotime_ns && state->process_incarnation == process_incarnation &&
           state->connection_netns == connection_netns &&
           __builtin_memcmp(&state->connection, connection, sizeof(*connection)) == 0 &&
           state->response.status == k_java_remote_parent_status_valid &&
           java_remote_parent_le64_to_cpu(state->response.generation_le) == expected->generation &&
           java_remote_parent_le64_to_cpu(state->response.observed_monotime_ns_le) ==
               state->observed_monotime_ns;
}

static __always_inline u8
java_remote_parent_exact_receive_owner_matches(const java_remote_parent_owner_t *owner,
                                               const java_remote_parent_key_t *expected,
                                               u64 process_incarnation) {
    return owner && owner->generation == expected->generation &&
           owner->process_incarnation == process_incarnation &&
           java_remote_parent_clean_lifecycle_tail(&owner->lifecycle,
                                                   k_java_remote_parent_lifecycle_active);
}

static __always_inline u8 java_remote_parent_exact_receive_fallback_matches(
    const java_remote_parent_response_t *fallback, const java_remote_parent_key_t *expected) {
    // Generation is the immutable ownership token for the singleton fallback.
    // RESET removes the exact generation even if its payload was corrupted;
    // another generation published at the same singleton key is preserved.
    return fallback && fallback->status == k_java_remote_parent_status_valid &&
           java_remote_parent_le64_to_cpu(fallback->generation_le) == expected->generation;
}

static __always_inline enum java_remote_parent_exact_receive_generation_mode
java_remote_parent_exact_receive_generation_matches(const java_remote_parent_key_t *expected,
                                                    u64 process_incarnation,
                                                    const connection_info_t *connection,
                                                    u32 connection_netns,
                                                    u64 socket_cookie) {
    if (!expected || expected->reserved || !expected->owner.tid || !expected->owner.pid ||
        !expected->owner.ns || !expected->generation || !process_incarnation || !connection ||
        !connection_netns || !socket_cookie || is_empty_connection_info(connection)) {
        return k_java_remote_parent_exact_receive_generation_invalid;
    }

    const java_remote_parent_state_t *state =
        bpf_map_lookup_elem(&java_remote_parent_state, expected);
    if (!java_remote_parent_exact_receive_state_matches(
            state, expected, process_incarnation, connection, connection_netns) ||
        !java_remote_parent_generation_index_matches(
            expected, process_incarnation, state->observed_monotime_ns)) {
        return k_java_remote_parent_exact_receive_generation_invalid;
    }

    const java_remote_parent_terminal_t *terminal =
        bpf_map_lookup_elem(&java_remote_parent_terminal, &expected->owner);
    if (terminal && terminal->generation == expected->generation) {
        return k_java_remote_parent_exact_receive_generation_invalid;
    }

    const java_remote_parent_owner_t *owner =
        bpf_map_lookup_elem(&java_remote_parent_owners, &expected->owner);
    const u8 owner_has_generation = owner && owner->generation == expected->generation;
    const u8 owner_exact =
        java_remote_parent_exact_receive_owner_matches(owner, expected, process_incarnation);
    const java_remote_parent_response_t *fallback =
        bpf_map_lookup_elem(&java_remote_parent_fallback, &expected->owner);
    const u8 fallback_has_generation =
        fallback && java_remote_parent_le64_to_cpu(fallback->generation_le) == expected->generation;
    const u8 fallback_exact = java_remote_parent_exact_receive_fallback_matches(fallback, expected);

    if ((owner_has_generation && !owner_exact) || (fallback_has_generation && !fallback_exact)) {
        return k_java_remote_parent_exact_receive_generation_invalid;
    }

    if (!java_remote_parent_generation_cleanly_reserved(expected) ||
        !java_remote_parent_connection_matches_socket_in_netns(connection,
                                                               connection_netns,
                                                               &expected->owner,
                                                               expected->generation,
                                                               0,
                                                               socket_cookie)) {
        return k_java_remote_parent_exact_receive_generation_invalid;
    }
    if (owner_exact && fallback_exact) {
        return k_java_remote_parent_exact_receive_generation_direct;
    }
    if (!owner_has_generation && !fallback_has_generation) {
        return k_java_remote_parent_exact_receive_generation_detached;
    }
    return k_java_remote_parent_exact_receive_generation_invalid;
}

static __always_inline u8 java_remote_parent_exact_receive_claim_matches(
    const java_remote_parent_key_t *expected, const java_remote_parent_claim_t *local_claim) {
    if (!expected || !expected->generation || expected->reserved || !local_claim) {
        return 0;
    }
    const java_remote_parent_claim_t *claim =
        bpf_map_lookup_elem(&java_remote_parent_claims, expected);
    return java_remote_parent_claim_equal(claim, local_claim);
}

static __always_inline u8 java_remote_parent_delete_exact_receive_claim(
    const java_remote_parent_key_t *expected, const java_remote_parent_claim_t *local_claim) {
    if (!expected || !expected->generation || expected->reserved || !local_claim) {
        return 0;
    }
    const java_remote_parent_claim_t *claim =
        bpf_map_lookup_elem(&java_remote_parent_claims, expected);
    if (!java_remote_parent_claim_equal(claim, local_claim)) {
        // Absence or replacement means the local claim was already released.
        return 1;
    }
    if (bpf_map_delete_elem(&java_remote_parent_claims, expected) != 0) {
        claim = bpf_map_lookup_elem(&java_remote_parent_claims, expected);
        // Report failure only while the exact local claim demonstrably remains.
        return !java_remote_parent_claim_equal(claim, local_claim);
    }
    // Successful deletion is the release linearization point. A consumer may
    // publish a successor claim immediately afterward.
    return 1;
}

static __always_inline u8 java_remote_parent_release_exact_receive_claim(
    const java_remote_parent_key_t *expected, java_remote_parent_claim_t *local_claim) {
    const u8 released = java_remote_parent_delete_exact_receive_claim(expected, local_claim);
    if (released) {
        // The timestamp is the invocation-local ownership bit used by the
        // handoff helper. Revoke that authority at the release linearization
        // point while retaining immutable transaction metadata needed by
        // post-commit observers such as the STAGE data acknowledgement.
        local_claim->observed_monotime_ns = 0;
    }
    return released;
}

static __always_inline u8
java_remote_parent_acquire_stage_claim(const java_remote_parent_key_t *expected,
                                       u64 process_incarnation,
                                       java_remote_parent_claim_t *local_claim) {
    if (local_claim->observed_monotime_ns &&
        local_claim->process_incarnation == process_incarnation &&
        java_remote_parent_clean_lifecycle_tail(&local_claim->lifecycle,
                                                k_java_remote_parent_lifecycle_publishing) &&
        java_remote_parent_exact_receive_claim_matches(expected, local_claim)) {
        return 1;
    }
    if (bpf_map_lookup_elem(&java_remote_parent_claims, expected)) {
        return 0;
    }

    *local_claim = (java_remote_parent_claim_t){
        .observed_monotime_ns = bpf_ktime_get_ns(),
        .process_incarnation = process_incarnation,
        // A publishing claim is a transaction fence, not a TAKE/DISCARD result.
        .lifecycle = k_java_remote_parent_lifecycle_publishing,
    };
    if (!local_claim->observed_monotime_ns || !process_incarnation ||
        bpf_map_update_elem(&java_remote_parent_claims, expected, local_claim, BPF_NOEXIST) != 0) {
        __builtin_memset(local_claim, 0, sizeof(*local_claim));
        return 0;
    }
    return java_remote_parent_exact_receive_claim_matches(expected, local_claim);
}

static __always_inline u8
java_remote_parent_ensure_exact_ambiguity(const java_remote_parent_key_t *expected) {
    return java_remote_parent_mark_exact_ambiguity(expected);
}

static __always_inline u8 java_remote_parent_exact_receive_claim_absent_or_matches(
    const java_remote_parent_key_t *expected, const java_remote_parent_claim_t *allowed_claim) {
    if (allowed_claim) {
        return java_remote_parent_exact_receive_claim_matches(expected, allowed_claim);
    }
    return bpf_map_lookup_elem(&java_remote_parent_claims, expected) == NULL;
}

static __always_inline u8
java_remote_parent_reset_fences_match(const java_remote_parent_key_t *expected,
                                      const java_remote_parent_receive_detach_scratch_t *scratch) {
    return java_remote_parent_exact_receive_claim_matches(expected, &scratch->generation_claim) &&
           java_remote_parent_exact_detach_guard_matches_at(&scratch->guard_key,
                                                            &scratch->guard_claim);
}

static __always_inline void java_remote_parent_handoff_reset_fences(
    const java_remote_parent_key_t *expected,
    const java_remote_parent_receive_detach_scratch_t *scratch) {
    java_remote_parent_handoff_exact_fence_pair(
        expected, &scratch->generation_claim, &scratch->guard_key, &scratch->guard_claim);
}

static __always_inline u8 java_remote_parent_delete_exact_receive_fallback(
    const java_remote_parent_key_t *expected,
    const java_remote_parent_receive_detach_scratch_t *scratch) {
#pragma unroll
    for (u8 attempt = 0; attempt < 2; attempt++) {
        const java_remote_parent_response_t *fallback =
            bpf_map_lookup_elem(&java_remote_parent_fallback, &expected->owner);
        if (!fallback ||
            java_remote_parent_le64_to_cpu(fallback->generation_le) != expected->generation) {
            return 1;
        }
        if (!java_remote_parent_exact_receive_fallback_matches(fallback, expected) ||
            !java_remote_parent_reset_fences_match(expected, scratch)) {
            return 0;
        }
        bpf_map_delete_elem(&java_remote_parent_fallback, &expected->owner);
    }
    return !java_remote_parent_fallback_has_generation(&expected->owner, expected->generation);
}

static __always_inline u8 java_remote_parent_delete_exact_receive_owner(
    const java_remote_parent_key_t *expected,
    u64 process_incarnation,
    const java_remote_parent_receive_detach_scratch_t *scratch) {
#pragma unroll
    for (u8 attempt = 0; attempt < 2; attempt++) {
        const java_remote_parent_owner_t *owner =
            bpf_map_lookup_elem(&java_remote_parent_owners, &expected->owner);
        if (!owner || owner->generation != expected->generation) {
            return 1;
        }
        if (!java_remote_parent_exact_receive_owner_matches(owner, expected, process_incarnation) ||
            !java_remote_parent_reset_fences_match(expected, scratch)) {
            return 0;
        }
        bpf_map_delete_elem(&java_remote_parent_owners, &expected->owner);
    }
    const java_remote_parent_owner_t *owner =
        bpf_map_lookup_elem(&java_remote_parent_owners, &expected->owner);
    return !owner || owner->generation != expected->generation;
}

static __always_inline u8 java_remote_parent_exact_receive_connection_value_matches(
    const java_remote_parent_connection_t *value, const java_remote_parent_connection_t *expected) {
    return value && value->reserved == 0 && value->reserved2 == 0 &&
           value->generation == expected->generation && value->netns == expected->netns &&
           value->netns_cookie == expected->netns_cookie &&
           value->incoming_generation == expected->incoming_generation &&
           value->socket_cookie == expected->socket_cookie &&
           java_remote_parent_pid_key_equal(&value->owner, &expected->owner);
}

static __always_inline u8 java_remote_parent_delete_exact_receive_connections(
    const java_remote_parent_key_t *expected,
    const connection_info_t *connection,
    u32 connection_netns,
    u64 socket_cookie,
    const java_remote_parent_receive_detach_scratch_t *scratch) {
    // The Java bridge serializes every receive lifecycle transition and
    // take/discard for one physical socket. BPF hash maps have key-only delete,
    // so this caller contract excludes a same-key replacement in the
    // lookup-to-delete window. The checks below still preserve replacements
    // published before a delete attempt or after that attempt completes.
    java_remote_parent_connection_keys_t keys = {0};
    if (!java_remote_parent_connection_keys_init(&keys, connection, connection_netns, 0)) {
        return 0;
    }
    const java_remote_parent_connection_t *netns_value =
        bpf_map_lookup_elem(&java_remote_parent_connections, &keys.netns);
    if (!netns_value || netns_value->reserved != 0 || netns_value->reserved2 != 0 ||
        netns_value->generation != expected->generation || netns_value->netns != connection_netns ||
        !netns_value->netns_cookie || !netns_value->incoming_generation ||
        netns_value->socket_cookie != socket_cookie ||
        !java_remote_parent_pid_key_equal(&netns_value->owner, &expected->owner)) {
        return 0;
    }

    java_remote_parent_connection_t copy = {0};
    __builtin_memcpy(&copy, netns_value, sizeof(copy));
    if (!java_remote_parent_connection_keys_init(
            &keys, connection, connection_netns, copy.netns_cookie)) {
        return 0;
    }
    const java_remote_parent_connection_t *cookie_value =
        bpf_map_lookup_elem(&java_remote_parent_cookie_connections, &keys.cookie);
    if (!java_remote_parent_exact_receive_connection_value_matches(cookie_value, &copy)) {
        return 0;
    }

#pragma unroll
    for (u8 attempt = 0; attempt < 2; attempt++) {
        cookie_value = bpf_map_lookup_elem(&java_remote_parent_cookie_connections, &keys.cookie);
        if (!java_remote_parent_exact_receive_connection_value_matches(cookie_value, &copy)) {
            break;
        }
        if (!java_remote_parent_reset_fences_match(expected, scratch)) {
            return 0;
        }
        bpf_map_delete_elem(&java_remote_parent_cookie_connections, &keys.cookie);
    }
    cookie_value = bpf_map_lookup_elem(&java_remote_parent_cookie_connections, &keys.cookie);
    if (java_remote_parent_exact_receive_connection_value_matches(cookie_value, &copy)) {
        return 0;
    }

    netns_value = bpf_map_lookup_elem(&java_remote_parent_connections, &keys.netns);
#pragma unroll
    for (u8 attempt = 0; attempt < 2 && netns_value; attempt++) {
        if (!java_remote_parent_exact_receive_connection_value_matches(netns_value, &copy)) {
            break;
        }
        if (!java_remote_parent_reset_fences_match(expected, scratch)) {
            return 0;
        }
        bpf_map_delete_elem(&java_remote_parent_connections, &keys.netns);
        netns_value = bpf_map_lookup_elem(&java_remote_parent_connections, &keys.netns);
        if (netns_value &&
            !java_remote_parent_exact_receive_connection_value_matches(netns_value, &copy)) {
            break;
        }
    }
    cookie_value = bpf_map_lookup_elem(&java_remote_parent_cookie_connections, &keys.cookie);
    const u8 netns_exact = netns_value && netns_value->generation == expected->generation &&
                           java_remote_parent_pid_key_equal(&netns_value->owner, &expected->owner);
    const u8 cookie_exact =
        cookie_value && cookie_value->generation == expected->generation &&
        java_remote_parent_pid_key_equal(&cookie_value->owner, &expected->owner);
    return !netns_exact && !cookie_exact;
}

static __always_inline u8 java_remote_parent_delete_exact_receive_state(
    const java_remote_parent_key_t *expected,
    u64 process_incarnation,
    const connection_info_t *connection,
    u32 connection_netns,
    u64 observed_monotime_ns,
    const java_remote_parent_receive_detach_scratch_t *scratch) {
#pragma unroll
    for (u8 attempt = 0; attempt < 2; attempt++) {
        const java_remote_parent_state_t *state =
            bpf_map_lookup_elem(&java_remote_parent_state, expected);
        if (!state) {
            return 1;
        }
        if (!java_remote_parent_exact_receive_state_matches(
                state, expected, process_incarnation, connection, connection_netns) ||
            state->observed_monotime_ns != observed_monotime_ns ||
            !java_remote_parent_reset_fences_match(expected, scratch)) {
            return 0;
        }
        bpf_map_delete_elem(&java_remote_parent_state, expected);
    }
    return !bpf_map_lookup_elem(&java_remote_parent_state, expected);
}

static __always_inline u8 java_remote_parent_delete_exact_receive_generation_index(
    const java_remote_parent_key_t *expected,
    u64 process_incarnation,
    u64 observed_monotime_ns,
    const java_remote_parent_receive_detach_scratch_t *scratch) {
#pragma unroll
    for (u8 attempt = 0; attempt < 2; attempt++) {
        if (!bpf_map_lookup_elem(&java_remote_parent_generation_index, expected)) {
            return 1;
        }
        if (!java_remote_parent_generation_index_matches(
                expected, process_incarnation, observed_monotime_ns) ||
            !java_remote_parent_reset_fences_match(expected, scratch)) {
            return 0;
        }
        bpf_map_delete_elem(&java_remote_parent_generation_index, expected);
    }
    return !bpf_map_lookup_elem(&java_remote_parent_generation_index, expected);
}

static __always_inline u8 java_remote_parent_mark_exact_receive_cleanup_failed(
    const java_remote_parent_key_t *expected, const java_remote_parent_claim_t *local_claim) {
    if (!java_remote_parent_mark_exact_ambiguity(expected)) {
        return 0;
    }
    // Destructive failures call this before releasing their exact claim. If a
    // later fence-release step has already removed that claim, the nonzero
    // marker and any retained owner guard remain the recovery authority.
    (void)local_claim;
    return java_remote_parent_generation_ambiguous(expected);
}

static __always_inline u8 java_remote_parent_exact_receive_connections_absent_with_key(
    const java_remote_parent_key_t *expected,
    java_remote_parent_connection_key_t *key,
    const connection_info_t *connection,
    u32 connection_netns,
    u64 connection_netns_cookie,
    u64 socket_cookie) {
    if (!socket_cookie ||
        !java_remote_parent_connection_netns_key_init(key, connection, connection_netns)) {
        return 0;
    }
    const java_remote_parent_connection_t *netns_value =
        bpf_map_lookup_elem(&java_remote_parent_connections, &key->netns);
    if (netns_value && netns_value->generation == expected->generation &&
        java_remote_parent_pid_key_equal(&netns_value->owner, &expected->owner)) {
        return 0;
    }
    if (!java_remote_parent_connection_cookie_key_init(key, connection, connection_netns_cookie)) {
        return 0;
    }
    const java_remote_parent_connection_t *cookie_value =
        bpf_map_lookup_elem(&java_remote_parent_cookie_connections, &key->cookie);
    return !cookie_value || cookie_value->generation != expected->generation ||
           !java_remote_parent_pid_key_equal(&cookie_value->owner, &expected->owner);
}

static __always_inline u8 java_remote_parent_exact_receive_connections_absent_reusing_key(
    const java_remote_parent_key_t *expected,
    java_remote_parent_connection_key_t *key,
    u32 connection_netns,
    u64 connection_netns_cookie,
    u64 socket_cookie) {
    if (!socket_cookie || !java_remote_parent_connection_key_rekey_netns(key, connection_netns)) {
        return 0;
    }
    const java_remote_parent_connection_t *netns_value =
        bpf_map_lookup_elem(&java_remote_parent_connections, &key->netns);
    if (netns_value && netns_value->generation == expected->generation &&
        java_remote_parent_pid_key_equal(&netns_value->owner, &expected->owner)) {
        return 0;
    }
    if (!java_remote_parent_connection_key_rekey_cookie(key, connection_netns_cookie)) {
        return 0;
    }
    const java_remote_parent_connection_t *cookie_value =
        bpf_map_lookup_elem(&java_remote_parent_cookie_connections, &key->cookie);
    return !cookie_value || cookie_value->generation != expected->generation ||
           !java_remote_parent_pid_key_equal(&cookie_value->owner, &expected->owner);
}

static __always_inline u8
java_remote_parent_exact_receive_connections_absent(const java_remote_parent_key_t *expected,
                                                    const connection_info_t *connection,
                                                    u32 connection_netns,
                                                    u64 connection_netns_cookie,
                                                    u64 socket_cookie) {
    java_remote_parent_connection_key_t key = {0};
    return java_remote_parent_exact_receive_connections_absent_with_key(
        expected, &key, connection, connection_netns, connection_netns_cookie, socket_cookie);
}

static __always_inline u8 java_remote_parent_exact_receive_cleanup_artifacts_absent_with_key(
    const java_remote_parent_key_t *expected,
    java_remote_parent_connection_key_t *key,
    const connection_info_t *connection,
    u32 connection_netns,
    u64 connection_netns_cookie,
    u64 socket_cookie) {
    if (bpf_map_lookup_elem(&java_remote_parent_state, expected) ||
        bpf_map_lookup_elem(&java_remote_parent_generation_index, expected) ||
        java_remote_parent_fallback_has_generation(&expected->owner, expected->generation)) {
        return 0;
    }
    const java_remote_parent_owner_t *owner =
        bpf_map_lookup_elem(&java_remote_parent_owners, &expected->owner);
    const java_remote_parent_terminal_t *terminal =
        bpf_map_lookup_elem(&java_remote_parent_terminal, &expected->owner);
    return (!owner || owner->generation != expected->generation) &&
           (!terminal || terminal->generation != expected->generation) &&
           java_remote_parent_exact_receive_connections_absent_with_key(
               expected, key, connection, connection_netns, connection_netns_cookie, socket_cookie);
}

static __always_inline u8
java_remote_parent_exact_receive_cleanup_artifacts_absent(const java_remote_parent_key_t *expected,
                                                          const connection_info_t *connection,
                                                          u32 connection_netns,
                                                          u64 connection_netns_cookie,
                                                          u64 socket_cookie) {
    java_remote_parent_connection_key_t key = {0};
    return java_remote_parent_exact_receive_cleanup_artifacts_absent_with_key(
        expected, &key, connection, connection_netns, connection_netns_cookie, socket_cookie);
}

static __always_inline u8 java_remote_parent_exact_receive_detached_state_matches_with_alias_mode(
    const java_remote_parent_key_t *expected,
    u64 process_incarnation,
    const connection_info_t *connection,
    u32 connection_netns,
    u64 observed_monotime_ns,
    u64 connection_netns_cookie,
    u64 socket_cookie,
    u8 require_alias) {
    const java_remote_parent_state_t *state =
        bpf_map_lookup_elem(&java_remote_parent_state, expected);
    if (!java_remote_parent_exact_receive_state_matches(
            state, expected, process_incarnation, connection, connection_netns) ||
        (require_alias && !state->aliases) || state->observed_monotime_ns != observed_monotime_ns ||
        !java_remote_parent_generation_index_matches(
            expected, process_incarnation, observed_monotime_ns) ||
        !java_remote_parent_generation_cleanly_reserved(expected)) {
        return 0;
    }
    const java_remote_parent_terminal_t *terminal =
        bpf_map_lookup_elem(&java_remote_parent_terminal, &expected->owner);
    const java_remote_parent_owner_t *owner =
        bpf_map_lookup_elem(&java_remote_parent_owners, &expected->owner);
    return (!terminal || terminal->generation != expected->generation) &&
           (!owner || owner->generation != expected->generation) &&
           !java_remote_parent_fallback_has_generation(&expected->owner, expected->generation) &&
           java_remote_parent_exact_receive_connections_absent(
               expected, connection, connection_netns, connection_netns_cookie, socket_cookie);
}

static __always_inline u8
java_remote_parent_exact_receive_detached_state_matches(const java_remote_parent_key_t *expected,
                                                        u64 process_incarnation,
                                                        const connection_info_t *connection,
                                                        u32 connection_netns,
                                                        u64 observed_monotime_ns,
                                                        u64 connection_netns_cookie,
                                                        u64 socket_cookie) {
    return java_remote_parent_exact_receive_detached_state_matches_with_alias_mode(
               expected,
               process_incarnation,
               connection,
               connection_netns,
               observed_monotime_ns,
               connection_netns_cookie,
               socket_cookie,
               1) &&
           java_remote_parent_exact_receive_claim_absent_or_matches(expected, NULL);
}

static __always_inline u8 java_remote_parent_exact_receive_completed_by_take_allowing_claim(
    const java_remote_parent_key_t *expected,
    u64 process_incarnation,
    u64 observed_monotime_ns,
    const connection_info_t *connection,
    u32 connection_netns,
    u64 connection_netns_cookie,
    u64 socket_cookie,
    const java_remote_parent_claim_t *allowed_claim) {
    const java_remote_parent_terminal_t *terminal =
        bpf_map_lookup_elem(&java_remote_parent_terminal, &expected->owner);
    if (!terminal || terminal->generation != expected->generation ||
        terminal->process_incarnation != process_incarnation || !observed_monotime_ns ||
        terminal->observed_monotime_ns != observed_monotime_ns ||
        !java_remote_parent_alias_replay_lifecycle_final(terminal->lifecycle) ||
        !java_remote_parent_clean_lifecycle_tail(&terminal->lifecycle, terminal->lifecycle) ||
        bpf_map_lookup_elem(&java_remote_parent_state, expected) ||
        bpf_map_lookup_elem(&java_remote_parent_generation_index, expected) ||
        !java_remote_parent_exact_receive_claim_absent_or_matches(expected, allowed_claim) ||
        !java_remote_parent_generation_ambiguity_absent(expected) ||
        java_remote_parent_fallback_has_generation(&expected->owner, expected->generation)) {
        return 0;
    }
    const java_remote_parent_owner_t *owner =
        bpf_map_lookup_elem(&java_remote_parent_owners, &expected->owner);
    if (owner && owner->generation == expected->generation) {
        return 0;
    }

    return java_remote_parent_exact_receive_connections_absent(
        expected, connection, connection_netns, connection_netns_cookie, socket_cookie);
}

static __always_inline u8
java_remote_parent_exact_receive_completed_by_take(const java_remote_parent_key_t *expected,
                                                   u64 process_incarnation,
                                                   u64 observed_monotime_ns,
                                                   const connection_info_t *connection,
                                                   u32 connection_netns,
                                                   u64 connection_netns_cookie,
                                                   u64 socket_cookie) {
    return java_remote_parent_exact_receive_completed_by_take_allowing_claim(
        expected,
        process_incarnation,
        observed_monotime_ns,
        connection,
        connection_netns,
        connection_netns_cookie,
        socket_cookie,
        NULL);
}

static __always_inline u8 java_remote_parent_exact_receive_completed_terminal_free_allowing_claim(
    const java_remote_parent_key_t *expected,
    const connection_info_t *connection,
    u32 connection_netns,
    u64 connection_netns_cookie,
    u64 socket_cookie,
    const java_remote_parent_claim_t *allowed_claim) {
    return java_remote_parent_generation_ambiguity_absent(expected) &&
           java_remote_parent_exact_receive_claim_absent_or_matches(expected, allowed_claim) &&
           java_remote_parent_exact_receive_cleanup_artifacts_absent(
               expected, connection, connection_netns, connection_netns_cookie, socket_cookie);
}

static __always_inline u8
java_remote_parent_exact_receive_completed_terminal_free(const java_remote_parent_key_t *expected,
                                                         const connection_info_t *connection,
                                                         u32 connection_netns,
                                                         u64 connection_netns_cookie,
                                                         u64 socket_cookie) {
    return java_remote_parent_exact_receive_completed_terminal_free_allowing_claim(
        expected, connection, connection_netns, connection_netns_cookie, socket_cookie, NULL);
}

static __noinline u8 java_remote_parent_cleanup_detached_zero_alias_once(
    const java_remote_parent_key_t *key, u64 process_incarnation, u64 observed_monotime_ns);

static __always_inline void java_remote_parent_cleanup_detached_zero_alias(
    const java_remote_parent_key_t *key, u64 process_incarnation, u64 observed_monotime_ns) {
    if (java_remote_parent_cleanup_detached_zero_alias_once(
            key, process_incarnation, observed_monotime_ns)) {
        java_remote_parent_cleanup_detached_zero_alias_once(
            key, process_incarnation, observed_monotime_ns);
    }
}

static __noinline u8
java_remote_parent_cleanup_exact_receive_zero_alias(const java_remote_parent_key_t *expected,
                                                    u64 process_incarnation,
                                                    const connection_info_t *connection,
                                                    u32 connection_netns,
                                                    u64 socket_cookie) {
    java_remote_parent_receive_detach_scratch_t scratch_value = {0};
    java_remote_parent_receive_detach_scratch_t *scratch = &scratch_value;
    enum java_remote_parent_exact_receive_generation_mode mode =
        java_remote_parent_exact_receive_generation_matches(
            expected, process_incarnation, connection, connection_netns, socket_cookie);
    const java_remote_parent_state_t *state =
        bpf_map_lookup_elem(&java_remote_parent_state, expected);
    if (!state || state->aliases ||
        (mode != k_java_remote_parent_exact_receive_generation_direct &&
         mode != k_java_remote_parent_exact_receive_generation_detached)) {
        return 0;
    }
    const u64 observed_monotime_ns = state->observed_monotime_ns;
    java_remote_parent_connection_keys_t connection_keys = {0};
    if (!java_remote_parent_connection_keys_init(
            &connection_keys, connection, connection_netns, 0)) {
        return 0;
    }
    const java_remote_parent_connection_t *staged =
        bpf_map_lookup_elem(&java_remote_parent_connections, &connection_keys.netns);
    if (!staged || staged->generation != expected->generation ||
        staged->socket_cookie != socket_cookie || !staged->netns_cookie ||
        !java_remote_parent_pid_key_equal(&staged->owner, &expected->owner)) {
        return 0;
    }
    const u64 connection_netns_cookie = staged->netns_cookie;

    scratch->generation_claim = (java_remote_parent_claim_t){
        .observed_monotime_ns = bpf_ktime_get_ns(),
        .process_incarnation = process_incarnation,
        // This claim serializes RESET cleanup; it is not a DISCARD outcome.
        .lifecycle = k_java_remote_parent_lifecycle_publishing,
    };
    if (!scratch->generation_claim.observed_monotime_ns) {
        return 0;
    }
    if (bpf_map_update_elem(
            &java_remote_parent_claims, expected, &scratch->generation_claim, BPF_NOEXIST) != 0) {
        __builtin_memset(&scratch->generation_claim, 0, sizeof(scratch->generation_claim));
        return 0;
    }
    if (!java_remote_parent_exact_receive_claim_matches(expected, &scratch->generation_claim)) {
        java_remote_parent_handoff_reset_fences(expected, scratch);
        return 0;
    }
    if (!java_remote_parent_generation_cleanly_reserved(expected)) {
        java_remote_parent_release_exact_receive_claim(expected, &scratch->generation_claim);
        java_remote_parent_handoff_reset_fences(expected, scratch);
        return 0;
    }

    scratch->guard_key = java_remote_parent_detach_guard_key(&expected->owner);
    if (!java_remote_parent_acquire_detach_guard_at(
            expected, &scratch->guard_key, &scratch->guard_claim)) {
        // Guard acquisition may have lost a replacement race. Release only the
        // exact G claim; never delete a guard we cannot prove is ours.
        java_remote_parent_release_exact_receive_claim(expected, &scratch->generation_claim);
        java_remote_parent_handoff_reset_fences(expected, scratch);
        return 0;
    }

    state = bpf_map_lookup_elem(&java_remote_parent_state, expected);
    const enum java_remote_parent_exact_receive_generation_mode claimed_mode =
        java_remote_parent_exact_receive_generation_matches(
            expected, process_incarnation, connection, connection_netns, socket_cookie);
    if (!state || state->aliases || claimed_mode != mode ||
        !java_remote_parent_exact_receive_state_matches(
            state, expected, process_incarnation, connection, connection_netns) ||
        state->observed_monotime_ns != observed_monotime_ns ||
        !java_remote_parent_generation_index_matches(
            expected, process_incarnation, observed_monotime_ns) ||
        !java_remote_parent_generation_cleanly_reserved(expected) ||
        !java_remote_parent_exact_receive_claim_matches(expected, &scratch->generation_claim) ||
        !java_remote_parent_reset_fences_match(expected, scratch)) {
        java_remote_parent_release_exact_receive_claim(expected, &scratch->generation_claim);
        if (!bpf_map_lookup_elem(&java_remote_parent_claims, expected) &&
            java_remote_parent_generation_cleanly_reserved(expected)) {
            java_remote_parent_release_exact_detach_guard_at(&scratch->guard_key,
                                                             &scratch->guard_claim);
        }
        java_remote_parent_handoff_reset_fences(expected, scratch);
        return 0;
    }

    u8 complete = 1;
    if (mode == k_java_remote_parent_exact_receive_generation_direct &&
        (!java_remote_parent_delete_exact_receive_fallback(expected, scratch) ||
         !java_remote_parent_delete_exact_receive_owner(expected, process_incarnation, scratch))) {
        complete = 0;
    }
    if (complete && !java_remote_parent_delete_exact_receive_connections(
                        expected, connection, connection_netns, socket_cookie, scratch)) {
        complete = 0;
    }
    if (complete && !java_remote_parent_delete_exact_receive_state(expected,
                                                                   process_incarnation,
                                                                   connection,
                                                                   connection_netns,
                                                                   observed_monotime_ns,
                                                                   scratch)) {
        complete = 0;
    }
    if (complete && !java_remote_parent_delete_exact_receive_generation_index(
                        expected, process_incarnation, observed_monotime_ns, scratch)) {
        complete = 0;
    }
    if (complete) {
        complete =
            java_remote_parent_reset_fences_match(expected, scratch) &&
            java_remote_parent_generation_cleanly_reserved(expected) &&
            java_remote_parent_exact_receive_cleanup_artifacts_absent(
                expected, connection, connection_netns, connection_netns_cookie, socket_cookie);
    }
    if (!complete) {
        // Destructive RESET failure retains the nonzero exact marker, exact G
        // claim, and generation-zero owner guard for userspace convergence.
        java_remote_parent_mark_exact_receive_cleanup_failed(expected, &scratch->generation_claim);
        java_remote_parent_handoff_reset_fences(expected, scratch);
        return 0;
    }

    // Zero-alias success has no remaining logical state. Release the exact
    // reservation, claim, and owner guard in that order; no destructive
    // operation follows any fence release.
    bpf_map_delete_elem(&java_remote_parent_ambiguity, expected);
    if (!java_remote_parent_generation_ambiguity_absent(expected)) {
        // Logical RESET is complete. Preserve whichever marker survived the
        // retirement attempt and never re-mark a possibly reused generation.
        java_remote_parent_handoff_reset_fences(expected, scratch);
        return 1;
    }
    // Marker deletion completes RESET. Retire the remaining fences only while
    // the exact claim is absent; otherwise leave the guard for asynchronous
    // convergence and never recreate the released marker.
    java_remote_parent_release_exact_receive_claim(expected, &scratch->generation_claim);
    if (!bpf_map_lookup_elem(&java_remote_parent_claims, expected) &&
        java_remote_parent_generation_ambiguity_absent(expected)) {
        java_remote_parent_release_exact_detach_guard_at(&scratch->guard_key,
                                                         &scratch->guard_claim);
    }
    // Exact guard deletion is the linearization point. A successor may reuse
    // the owner and generation keys immediately afterward, so no old-G
    // postcheck or cleanup-failed marker is valid beyond this point.
    java_remote_parent_handoff_reset_fences(expected, scratch);
    return 1;
}

// RESET is a receive-lifecycle correction, not a take/discard outcome. It
// removes only the cursor's exact generation and never writes or deletes a
// terminal record. Both aliased and zero-alias cleanup hold an exact publishing
// claim before the first destructive mutation; the owner guard closes the
// claim-release window and prevents same-owner staging.
static __noinline __attribute__((unused)) u8
java_remote_parent_detach_exact_receive_generation(const java_remote_parent_key_t *expected,
                                                   u64 process_incarnation,
                                                   const connection_info_t *connection,
                                                   u32 connection_netns,
                                                   u64 socket_cookie) {
    enum java_remote_parent_exact_receive_generation_mode mode =
        java_remote_parent_exact_receive_generation_matches(
            expected, process_incarnation, connection, connection_netns, socket_cookie);
    if (mode == k_java_remote_parent_exact_receive_generation_invalid) {
        return 0;
    }
    const java_remote_parent_state_t *state =
        bpf_map_lookup_elem(&java_remote_parent_state, expected);
    if (!state) {
        return 0;
    }
    if (!state->aliases) {
        return java_remote_parent_cleanup_exact_receive_zero_alias(
            expected, process_incarnation, connection, connection_netns, socket_cookie);
    }
    const u64 observed_monotime_ns = state->observed_monotime_ns;

    java_remote_parent_connection_keys_t connection_keys = {0};
    if (!java_remote_parent_connection_keys_init(
            &connection_keys, connection, connection_netns, 0)) {
        return 0;
    }
    const java_remote_parent_connection_t *staged =
        bpf_map_lookup_elem(&java_remote_parent_connections, &connection_keys.netns);
    if (!staged || staged->generation != expected->generation ||
        staged->socket_cookie != socket_cookie || !staged->netns_cookie ||
        !java_remote_parent_pid_key_equal(&staged->owner, &expected->owner)) {
        return 0;
    }
    const u64 connection_netns_cookie = staged->netns_cookie;

    java_remote_parent_receive_detach_scratch_t scratch_value = {0};
    java_remote_parent_receive_detach_scratch_t *scratch = &scratch_value;
    scratch->generation_claim = (java_remote_parent_claim_t){
        .observed_monotime_ns = bpf_ktime_get_ns(),
        .process_incarnation = process_incarnation,
        // Aliased RESET keeps state/index but serializes every destructive
        // direct-cursor mutation against TAKE/DISCARD.
        .lifecycle = k_java_remote_parent_lifecycle_publishing,
    };
    long claim_result = -1;
    if (scratch->generation_claim.observed_monotime_ns) {
        claim_result = bpf_map_update_elem(
            &java_remote_parent_claims, expected, &scratch->generation_claim, BPF_NOEXIST);
    }
    if (claim_result != 0 ||
        !java_remote_parent_exact_receive_claim_matches(expected, &scratch->generation_claim)) {
        if (claim_result != 0) {
            __builtin_memset(&scratch->generation_claim, 0, sizeof(scratch->generation_claim));
        }
        if ((java_remote_parent_exact_receive_completed_by_take(expected,
                                                                process_incarnation,
                                                                observed_monotime_ns,
                                                                connection,
                                                                connection_netns,
                                                                connection_netns_cookie,
                                                                socket_cookie) ||
             java_remote_parent_exact_receive_completed_terminal_free(
                 expected, connection, connection_netns, connection_netns_cookie, socket_cookie)) &&
            !java_remote_parent_owner_detach_guarded(&expected->owner)) {
            java_remote_parent_handoff_reset_fences(expected, scratch);
            return 1;
        }
        java_remote_parent_handoff_reset_fences(expected, scratch);
        return 0;
    }
    if (!java_remote_parent_generation_cleanly_reserved(expected)) {
        java_remote_parent_release_exact_receive_claim(expected, &scratch->generation_claim);
        java_remote_parent_handoff_reset_fences(expected, scratch);
        return 0;
    }

    scratch->guard_key = java_remote_parent_detach_guard_key(&expected->owner);
    if (!java_remote_parent_acquire_detach_guard_at(
            expected, &scratch->guard_key, &scratch->guard_claim)) {
        // Guard acquisition may have lost a replacement race. Release only the
        // exact G claim; never delete a guard we cannot prove is ours.
        java_remote_parent_release_exact_receive_claim(expected, &scratch->generation_claim);
        java_remote_parent_handoff_reset_fences(expected, scratch);
        return 0;
    }

    state = bpf_map_lookup_elem(&java_remote_parent_state, expected);
    mode = java_remote_parent_exact_receive_generation_matches(
        expected, process_incarnation, connection, connection_netns, socket_cookie);
    if (!state || !state->aliases || state->observed_monotime_ns != observed_monotime_ns ||
        (mode != k_java_remote_parent_exact_receive_generation_direct &&
         mode != k_java_remote_parent_exact_receive_generation_detached) ||
        !java_remote_parent_generation_cleanly_reserved(expected) ||
        !java_remote_parent_exact_receive_claim_matches(expected, &scratch->generation_claim) ||
        !java_remote_parent_reset_fences_match(expected, scratch)) {
        java_remote_parent_release_exact_receive_claim(expected, &scratch->generation_claim);
        if (!bpf_map_lookup_elem(&java_remote_parent_claims, expected) &&
            java_remote_parent_generation_cleanly_reserved(expected)) {
            java_remote_parent_release_exact_detach_guard_at(&scratch->guard_key,
                                                             &scratch->guard_claim);
        }
        // This attempt did not prove RESET completion. The successful guard
        // deletion still linearizes its release; do not classify or mutate
        // artifacts that may be published by a later owner operation.
        java_remote_parent_handoff_reset_fences(expected, scratch);
        return 0;
    }

    u8 complete = 1;
    if (mode == k_java_remote_parent_exact_receive_generation_direct &&
        (!java_remote_parent_delete_exact_receive_fallback(expected, scratch) ||
         !java_remote_parent_delete_exact_receive_owner(expected, process_incarnation, scratch))) {
        complete = 0;
    }
    if (complete && !java_remote_parent_delete_exact_receive_connections(
                        expected, connection, connection_netns, socket_cookie, scratch)) {
        complete = 0;
    }

    if (complete) {
        complete = java_remote_parent_reset_fences_match(expected, scratch) &&
                   java_remote_parent_generation_cleanly_reserved(expected) &&
                   java_remote_parent_exact_receive_detached_state_matches_with_alias_mode(
                       expected,
                       process_incarnation,
                       connection,
                       connection_netns,
                       observed_monotime_ns,
                       connection_netns_cookie,
                       socket_cookie,
                       1);
    }
    if (!complete) {
        // Destructive RESET failure retains the nonzero exact marker, exact G
        // claim, and generation-zero owner guard for userspace convergence.
        java_remote_parent_mark_exact_receive_cleanup_failed(expected, &scratch->generation_claim);
        java_remote_parent_handoff_reset_fences(expected, scratch);
        return 0;
    }

    // Aliased success preserves the zero reservation that keeps this detached
    // state enumerable. Release only the exact claim and then the owner guard;
    // no destructive operation follows either fence release.
    java_remote_parent_release_exact_receive_claim(expected, &scratch->generation_claim);
    if (!bpf_map_lookup_elem(&java_remote_parent_claims, expected) &&
        java_remote_parent_generation_cleanly_reserved(expected)) {
        java_remote_parent_release_exact_detach_guard_at(&scratch->guard_key,
                                                         &scratch->guard_claim);
    }
    // Exact guard deletion is the linearization point. The direct cursor has
    // been removed and the aliased state is intentionally detached. Later
    // alias convergence or successor publication belongs to another operation.
    java_remote_parent_handoff_reset_fences(expected, scratch);
    return 1;
}

static __always_inline u8 java_remote_parent_detached_zero_state_matches(
    const java_remote_parent_key_t *key,
    u64 process_incarnation,
    u64 observed_monotime_ns,
    java_remote_parent_connection_key_t *connection_key) {
    const java_remote_parent_state_t *state = bpf_map_lookup_elem(&java_remote_parent_state, key);
    if (!state || state->aliases || state->lifecycle != k_java_remote_parent_lifecycle_active ||
        __builtin_memcmp(state->reserved,
                         (unsigned char[sizeof(state->reserved)]){0},
                         sizeof(state->reserved)) != 0 ||
        state->process_incarnation != process_incarnation ||
        state->observed_monotime_ns != observed_monotime_ns ||
        state->response.status != k_java_remote_parent_status_valid ||
        java_remote_parent_le64_to_cpu(state->response.generation_le) != key->generation ||
        java_remote_parent_le64_to_cpu(state->response.observed_monotime_ns_le) !=
            observed_monotime_ns ||
        !java_remote_parent_generation_index_matches(
            key, process_incarnation, observed_monotime_ns) ||
        !java_remote_parent_generation_cleanly_reserved(key)) {
        return 0;
    }
    const java_remote_parent_owner_t *owner =
        bpf_map_lookup_elem(&java_remote_parent_owners, &key->owner);
    const java_remote_parent_terminal_t *terminal =
        bpf_map_lookup_elem(&java_remote_parent_terminal, &key->owner);
    if ((owner && owner->generation == key->generation) ||
        (terminal && terminal->generation == key->generation) ||
        java_remote_parent_fallback_has_generation(&key->owner, key->generation)) {
        return 0;
    }
    if (!java_remote_parent_connection_netns_key_init(
            connection_key, &state->connection, state->connection_netns)) {
        return 0;
    }
    const java_remote_parent_connection_t *staged =
        bpf_map_lookup_elem(&java_remote_parent_connections, &connection_key->netns);
    return !staged || staged->generation != key->generation ||
           !java_remote_parent_pid_key_equal(&staged->owner, &key->owner);
}

static __noinline u8 java_remote_parent_cleanup_detached_zero_alias_once(
    const java_remote_parent_key_t *key, u64 process_incarnation, u64 observed_monotime_ns) {
    java_remote_parent_janitor_workspace_t *workspace = java_remote_parent_janitor_workspace_mem();
    if (!workspace || workspace->busy) {
        return 0;
    }
    workspace->busy = 1;
    barrier();
    __builtin_memcpy(&workspace->key, key, sizeof(workspace->key));
    __builtin_memset(&workspace->claim, 0, sizeof(workspace->claim));
    __builtin_memset(&workspace->connection_key, 0, sizeof(workspace->connection_key));

    if (!java_remote_parent_detached_zero_state_matches(&workspace->key,
                                                        process_incarnation,
                                                        observed_monotime_ns,
                                                        &workspace->connection_key)) {
        goto release_workspace;
    }

    workspace->claim.observed_monotime_ns = bpf_ktime_get_ns();
    workspace->claim.process_incarnation = process_incarnation;
    // Cookie-index metadata is unavailable after the netns cursor was
    // detached, so BPF cannot prove that every physical G artifact is
    // absent. Fence the exact generation and defer the full-map proof to
    // userspace instead of treating a missing netns index as authority.
    workspace->claim.lifecycle = k_java_remote_parent_lifecycle_publishing;
    if (!workspace->claim.observed_monotime_ns) {
        goto release_workspace;
    }
    if (bpf_map_update_elem(
            &java_remote_parent_claims, &workspace->key, &workspace->claim, BPF_NOEXIST) != 0) {
        __builtin_memset(&workspace->claim, 0, sizeof(workspace->claim));
        goto release_workspace;
    }
    if (!java_remote_parent_exact_receive_claim_matches(&workspace->key, &workspace->claim)) {
        goto release_workspace;
    }
    java_remote_parent_mark_exact_receive_cleanup_failed(&workspace->key, &workspace->claim);

release_workspace:
    // No payload mutation follows this point. A surviving exact janitor claim
    // becomes cleanup-owned only through this fresh producer handoff.
    java_remote_parent_handoff_exact_fence(&workspace->key, &workspace->claim);
    __builtin_memset(&workspace->key, 0, sizeof(workspace->key));
    __builtin_memset(&workspace->claim, 0, sizeof(workspace->claim));
    __builtin_memset(&workspace->connection_key, 0, sizeof(workspace->connection_key));
    barrier();
    workspace->busy = 0;
    return 0;
}
static __always_inline void
java_remote_parent_release_generation_alias(const java_remote_parent_key_t *key,
                                            u64 observed_monotime_ns) {
    u64 process_incarnation = java_current_process_incarnation();
    const java_remote_parent_state_t *state = bpf_map_lookup_elem(&java_remote_parent_state, key);
    if (state && state->observed_monotime_ns == observed_monotime_ns &&
        state->process_incarnation) {
        process_incarnation = state->process_incarnation;
    }
    if (process_incarnation) {
        const java_remote_parent_alias_replay_key_t replay_key =
            java_remote_parent_alias_replay_key(key, observed_monotime_ns, process_incarnation);
        // Replay is decremented first. A concurrent finalizer can therefore
        // only copy an older (larger) count into its whole-value transition.
        java_remote_parent_alias_replay_release_reference(&replay_key);
    }
    java_remote_parent_release_state_alias(key, observed_monotime_ns);
}

enum java_remote_parent_stage_leaf_result : u8 {
    k_java_remote_parent_stage_leaf_failed = 0,
    k_java_remote_parent_stage_leaf_valid = 1,
    k_java_remote_parent_stage_leaf_owner_conflict = 2,
    k_java_remote_parent_stage_leaf_overload = 3,
};

static __always_inline u8 java_remote_parent_stage_owner_matches_transaction(
    const java_remote_parent_stage_transaction_t *transaction, u8 lifecycle) {
    const java_remote_parent_owner_t *owner =
        bpf_map_lookup_elem(&java_remote_parent_owners, &transaction->key.owner);
    return owner && owner->generation == transaction->key.generation &&
           owner->process_incarnation == transaction->claim.process_incarnation &&
           java_remote_parent_clean_lifecycle_tail(&owner->lifecycle, lifecycle);
}

static __always_inline u8 java_remote_parent_stage_state_matches_transaction(
    const java_remote_parent_stage_transaction_t *transaction,
    const java_remote_parent_state_t *state) {
    return state &&
           java_remote_parent_metadata_word(&state->lifecycle) ==
               k_java_remote_parent_lifecycle_active &&
           !state->aliases && state->observed_monotime_ns && state->connection_netns &&
           state->process_incarnation == transaction->claim.process_incarnation &&
           state->response.status == k_java_remote_parent_status_valid &&
           java_remote_parent_le64_to_cpu(state->response.generation_le) ==
               transaction->key.generation &&
           java_remote_parent_le64_to_cpu(state->response.observed_monotime_ns_le) ==
               state->observed_monotime_ns;
}

static __always_inline u8 java_remote_parent_stage_connection_matches_transaction(
    const java_remote_parent_connection_t *value,
    const java_remote_parent_key_t *expected,
    u32 connection_netns,
    u64 connection_netns_cookie,
    u64 incoming_generation,
    u64 socket_cookie) {
    return value && !(value->reserved | value->reserved2) &&
           value->generation == expected->generation && value->netns == connection_netns &&
           value->netns_cookie == connection_netns_cookie &&
           value->incoming_generation == incoming_generation &&
           value->socket_cookie == socket_cookie &&
           java_remote_parent_pid_key_equal(&value->owner, &expected->owner);
}

static __always_inline u8 java_remote_parent_stage_transaction_claimed_at(
    const java_remote_parent_stage_transaction_t *transaction,
    const java_remote_parent_key_t *guard_key) {
    return java_remote_parent_exact_receive_claim_matches(&transaction->key, &transaction->claim) &&
           java_remote_parent_generation_cleanly_reserved(&transaction->key) &&
           !bpf_map_lookup_elem(&java_remote_parent_owner_guards, &guard_key->owner);
}

static __noinline __attribute__((unused)) enum java_remote_parent_stage_leaf_result
java_remote_parent_stage_publish_logical(java_remote_parent_stage_transaction_t *transaction,
                                         const connection_info_t *connection,
                                         u32 connection_netns,
                                         const tp_info_pid_t *incoming,
                                         const java_remote_parent_key_t *guard_key) {
    if (!java_remote_parent_stage_transaction_claimed_at(transaction, guard_key)) {
        return k_java_remote_parent_stage_leaf_failed;
    }

    union {
        java_remote_parent_owner_t owner;
        java_remote_parent_generation_index_t generation_index;
    } value = {0};
    value.owner = (java_remote_parent_owner_t){
        .generation = transaction->key.generation,
        .process_incarnation = transaction->claim.process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_publishing,
    };
    if (bpf_map_update_elem(
            &java_remote_parent_owners, &transaction->key.owner, &value.owner, BPF_NOEXIST) != 0) {
        // Quarantine the generation that won the same-owner publication lock
        // before the caller releases this transaction's still-empty G.
        java_remote_parent_guard_owner_reuse(&transaction->key.owner);
        return k_java_remote_parent_stage_leaf_owner_conflict;
    }
    if (!java_remote_parent_stage_transaction_claimed_at(transaction, guard_key) ||
        !java_remote_parent_stage_owner_matches_transaction(
            transaction, k_java_remote_parent_lifecycle_publishing)) {
        return k_java_remote_parent_stage_leaf_failed;
    }

    bpf_map_delete_elem(&java_remote_parent_terminal, &transaction->key.owner);
    java_remote_parent_cleanup_fallback(&transaction->key.owner);

    java_remote_parent_state_t *state = java_remote_parent_stage_state_mem();
    if (!state) {
        return k_java_remote_parent_stage_leaf_overload;
    }
    __builtin_memset(state, 0, sizeof(*state));
    state->lifecycle = k_java_remote_parent_lifecycle_active;
    state->observed_monotime_ns =
        incoming->tp.ts ? incoming->tp.ts : transaction->claim.observed_monotime_ns;
    state->connection = *connection;
    state->connection_netns = connection_netns;
    state->process_incarnation = transaction->claim.process_incarnation;
    java_remote_parent_init_response(&state->response,
                                     k_java_remote_parent_status_valid,
                                     transaction->key.generation,
                                     state->observed_monotime_ns);
    java_remote_parent_set_context(&state->response, &incoming->tp);
    if (!incoming_trace_claimed_generation_matches_in_netns_cookie(
            connection,
            transaction->connection_netns_cookie,
            transaction->incoming_generation,
            incoming) ||
        !java_remote_parent_stage_transaction_claimed_at(transaction, guard_key)) {
        return k_java_remote_parent_stage_leaf_failed;
    }
    if (bpf_map_update_elem(&java_remote_parent_state, &transaction->key, state, BPF_NOEXIST) !=
        0) {
        return k_java_remote_parent_stage_leaf_overload;
    }

    value.generation_index = (java_remote_parent_generation_index_t){
        .process = java_process_key(&transaction->key.owner),
        .process_incarnation = transaction->claim.process_incarnation,
        .observed_monotime_ns = state->observed_monotime_ns,
    };
    if (bpf_map_update_elem(&java_remote_parent_generation_index,
                            &transaction->key,
                            &value.generation_index,
                            BPF_NOEXIST) != 0) {
        return k_java_remote_parent_stage_leaf_overload;
    }

    state = bpf_map_lookup_elem(&java_remote_parent_state, &transaction->key);
    return java_remote_parent_stage_state_matches_transaction(transaction, state) &&
                   java_remote_parent_generation_index_matches(
                       &transaction->key,
                       transaction->claim.process_incarnation,
                       state->observed_monotime_ns) &&
                   java_remote_parent_stage_transaction_claimed_at(transaction, guard_key) &&
                   java_remote_parent_stage_owner_matches_transaction(
                       transaction, k_java_remote_parent_lifecycle_publishing)
               ? k_java_remote_parent_stage_leaf_valid
               : k_java_remote_parent_stage_leaf_failed;
}

static __always_inline u8 java_remote_parent_stage_publish_connection_index(
    java_remote_parent_stage_transaction_t *transaction,
    const java_remote_parent_key_t *guard_key,
    u8 cookie_index) {
    java_remote_parent_connection_key_t connection_key = {0};
    java_remote_parent_connection_t value = {0};

    const java_remote_parent_state_t *state =
        bpf_map_lookup_elem(&java_remote_parent_state, &transaction->key);
    if (!java_remote_parent_stage_state_matches_transaction(transaction, state) ||
        !java_remote_parent_generation_index_matches(&transaction->key,
                                                     transaction->claim.process_incarnation,
                                                     state->observed_monotime_ns) ||
        !java_remote_parent_stage_transaction_claimed_at(transaction, guard_key) ||
        !java_remote_parent_stage_owner_matches_transaction(
            transaction, k_java_remote_parent_lifecycle_publishing)) {
        return 0;
    }
    if (cookie_index
            ? !java_remote_parent_connection_cookie_key_init(
                  &connection_key, &state->connection, transaction->connection_netns_cookie)
            : !java_remote_parent_connection_netns_key_init(
                  &connection_key, &state->connection, state->connection_netns)) {
        return 0;
    }

    value = (java_remote_parent_connection_t){
        .owner = transaction->key.owner,
        .generation = transaction->key.generation,
        .netns_cookie = transaction->connection_netns_cookie,
        .incoming_generation = transaction->incoming_generation,
        .socket_cookie = transaction->socket_cookie,
        .netns = state->connection_netns,
    };
    const long updated =
        cookie_index
            ? bpf_map_update_elem(&java_remote_parent_cookie_connections,
                                  &connection_key.cookie,
                                  &value,
                                  BPF_NOEXIST)
            : bpf_map_update_elem(
                  &java_remote_parent_connections, &connection_key.netns, &value, BPF_NOEXIST);
    if (updated != 0) {
        invalidate_incoming_trace_in_netns_cookie(cookie_index ? &connection_key.cookie.connection
                                                               : &connection_key.netns.connection,
                                                  transaction->connection_netns_cookie,
                                                  bpf_ktime_get_ns());
        return 0;
    }

    const java_remote_parent_connection_t *published =
        cookie_index
            ? bpf_map_lookup_elem(&java_remote_parent_cookie_connections, &connection_key.cookie)
            : bpf_map_lookup_elem(&java_remote_parent_connections, &connection_key.netns);
    return java_remote_parent_stage_connection_matches_transaction(
               published,
               &transaction->key,
               value.netns,
               transaction->connection_netns_cookie,
               transaction->incoming_generation,
               transaction->socket_cookie) &&
           java_remote_parent_exact_receive_claim_matches(&transaction->key, &transaction->claim) &&
           java_remote_parent_generation_cleanly_reserved(&transaction->key) &&
           java_remote_parent_stage_owner_matches_transaction(
               transaction, k_java_remote_parent_lifecycle_publishing);
}

static __always_inline void java_remote_parent_stage_quarantine_connection_conflict(
    java_remote_parent_stage_transaction_t *transaction, u8 cookie_index) {
    java_remote_parent_connection_key_t connection_key = {0};
    java_remote_parent_key_t conflict_key = {0};
    const java_remote_parent_state_t *state =
        bpf_map_lookup_elem(&java_remote_parent_state, &transaction->key);
    if (!java_remote_parent_stage_state_matches_transaction(transaction, state) ||
        (cookie_index
             ? !java_remote_parent_connection_cookie_key_init(
                   &connection_key, &state->connection, transaction->connection_netns_cookie)
             : !java_remote_parent_connection_netns_key_init(
                   &connection_key, &state->connection, state->connection_netns))) {
        return;
    }
    const java_remote_parent_connection_t *conflict =
        cookie_index
            ? bpf_map_lookup_elem(&java_remote_parent_cookie_connections, &connection_key.cookie)
            : bpf_map_lookup_elem(&java_remote_parent_connections, &connection_key.netns);
    if (!conflict || !conflict->generation) {
        return;
    }
    conflict_key = (java_remote_parent_key_t){
        .owner = conflict->owner,
        .generation = conflict->generation,
    };
    java_remote_parent_mark_exact_ambiguity(&conflict_key);
}

static __noinline __attribute__((unused)) void java_remote_parent_stage_quarantine_netns_conflict(
    java_remote_parent_stage_transaction_t *transaction) {
    java_remote_parent_stage_quarantine_connection_conflict(transaction, 0);
}

static __noinline __attribute__((unused)) void java_remote_parent_stage_quarantine_cookie_conflict(
    java_remote_parent_stage_transaction_t *transaction) {
    java_remote_parent_stage_quarantine_connection_conflict(transaction, 1);
}

static __noinline __attribute__((unused)) u8
java_remote_parent_stage_publish_netns_index(java_remote_parent_stage_transaction_t *transaction,
                                             const java_remote_parent_key_t *guard_key) {
    return java_remote_parent_stage_publish_connection_index(transaction, guard_key, 0);
}

static __noinline __attribute__((unused)) u8
java_remote_parent_stage_publish_cookie_index(java_remote_parent_stage_transaction_t *transaction,
                                              const java_remote_parent_key_t *guard_key) {
    return java_remote_parent_stage_publish_connection_index(transaction, guard_key, 1);
}

static __always_inline u8 java_remote_parent_stage_transaction_is_consistent(
    java_remote_parent_stage_transaction_t *transaction,
    const tp_info_pid_t *incoming,
    java_remote_parent_connection_key_t *connection_key,
    const connection_info_t *connection,
    u32 connection_netns,
    const java_remote_parent_key_t *guard_key,
    u8 owner_lifecycle,
    const java_remote_parent_claim_t *allowed_claim,
    u8 require_fallback) {
    const java_remote_parent_state_t *state =
        bpf_map_lookup_elem(&java_remote_parent_state, &transaction->key);
    if (!java_remote_parent_stage_state_matches_transaction(transaction, state) ||
        state->connection_netns != connection_netns ||
        __builtin_memcmp(&state->connection, connection, sizeof(*connection)) != 0) {
        return 0;
    }
    if (!java_remote_parent_generation_index_matches(&transaction->key,
                                                     transaction->claim.process_incarnation,
                                                     state->observed_monotime_ns) ||
        !java_remote_parent_connection_matches_in_netns_with_key(connection_key,
                                                                 connection,
                                                                 connection_netns,
                                                                 &transaction->key.owner,
                                                                 transaction->key.generation,
                                                                 transaction->incoming_generation,
                                                                 transaction->socket_cookie) ||
        (require_fallback && !java_remote_parent_fallback_matches(&transaction->key.owner,
                                                                  transaction->key.generation)) ||
        !incoming_trace_claimed_generation_matches_in_netns_cookie(
            connection,
            transaction->connection_netns_cookie,
            transaction->incoming_generation,
            incoming)) {
        return 0;
    }
    return java_remote_parent_exact_receive_claim_absent_or_matches(&transaction->key,
                                                                    allowed_claim) &&
           java_remote_parent_generation_cleanly_reserved(&transaction->key) &&
           !bpf_map_lookup_elem(&java_remote_parent_owner_guards, &guard_key->owner) &&
           java_remote_parent_stage_owner_matches_transaction(transaction, owner_lifecycle);
}

static __noinline __attribute__((unused)) u8
java_remote_parent_stage_finish_publication(java_remote_parent_stage_transaction_t *transaction,
                                            const tp_info_pid_t *incoming,
                                            const java_remote_parent_key_t *guard_key) {
    java_remote_parent_connection_key_t connection_key = {0};
    union {
        struct {
            connection_info_t connection;
            u32 reserved;
        } state;
        java_remote_parent_owner_t owner;
    } value = {0};

    const java_remote_parent_state_t *state =
        bpf_map_lookup_elem(&java_remote_parent_state, &transaction->key);
    if (!java_remote_parent_stage_state_matches_transaction(transaction, state)) {
        return 0;
    }
    value.state.connection = state->connection;
    const u32 connection_netns = state->connection_netns;
    if (!java_remote_parent_stage_transaction_is_consistent(
            transaction,
            incoming,
            &connection_key,
            &value.state.connection,
            connection_netns,
            guard_key,
            k_java_remote_parent_lifecycle_publishing,
            &transaction->claim,
            0)) {
        return 0;
    }

    state = bpf_map_lookup_elem(&java_remote_parent_state, &transaction->key);
    if (!java_remote_parent_stage_state_matches_transaction(transaction, state) ||
        !java_remote_parent_stage_fallback(&transaction->key.owner, &state->response)) {
        return 0;
    }
    state = bpf_map_lookup_elem(&java_remote_parent_state, &transaction->key);
    if (!java_remote_parent_stage_state_matches_transaction(transaction, state)) {
        return 0;
    }
    value.state.connection = state->connection;
    if (!java_remote_parent_stage_transaction_is_consistent(
            transaction,
            incoming,
            &connection_key,
            &value.state.connection,
            state->connection_netns,
            guard_key,
            k_java_remote_parent_lifecycle_publishing,
            &transaction->claim,
            1)) {
        return 0;
    }

    value.owner = (java_remote_parent_owner_t){
        .generation = transaction->key.generation,
        .process_incarnation = transaction->claim.process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_active,
    };
    if (bpf_map_update_elem(
            &java_remote_parent_owners, &transaction->key.owner, &value.owner, BPF_EXIST) != 0) {
        return 0;
    }
    state = bpf_map_lookup_elem(&java_remote_parent_state, &transaction->key);
    if (!java_remote_parent_stage_state_matches_transaction(transaction, state)) {
        return 0;
    }
    value.state.connection = state->connection;
    if (!java_remote_parent_stage_transaction_is_consistent(transaction,
                                                            incoming,
                                                            &connection_key,
                                                            &value.state.connection,
                                                            state->connection_netns,
                                                            guard_key,
                                                            k_java_remote_parent_lifecycle_active,
                                                            &transaction->claim,
                                                            1) ||
        !java_remote_parent_release_exact_receive_claim(&transaction->key, &transaction->claim)) {
        return 0;
    }
    // Releasing the publishing claim commits STAGE. A legitimate consumer can
    // install its own exact claim immediately afterward, so no graph or claim
    // observation beyond this point may turn the committed publication into a
    // rollback.
    return 1;
}

static __noinline __attribute__((unused)) void
java_remote_parent_stage_acknowledge(const java_remote_parent_stage_transaction_t *transaction) {
    const u64 *data_signal =
        bpf_map_lookup_elem(&java_remote_parent_data_signals, &transaction->key.owner);
    if (!data_signal || !*data_signal) {
        return;
    }
    const u64 nonce = *data_signal;
    const java_remote_parent_state_t *state =
        bpf_map_lookup_elem(&java_remote_parent_state, &transaction->key);
    if (!java_remote_parent_stage_state_matches_transaction(transaction, state) ||
        bpf_map_lookup_elem(&java_remote_parent_claims, &transaction->key) ||
        !java_remote_parent_generation_cleanly_reserved(&transaction->key) ||
        !java_remote_parent_stage_owner_matches_transaction(
            transaction, k_java_remote_parent_lifecycle_active)) {
        return;
    }

    const java_remote_parent_data_signal_key_t signal_key = {
        .process = java_process_key(&transaction->key.owner),
        .nonce = nonce,
    };
    java_remote_parent_data_ack_t *acknowledgement =
        (java_remote_parent_data_ack_t *)java_remote_parent_stage_state_mem();
    if (!acknowledgement) {
        return;
    }
    __builtin_memset(acknowledgement, 0, sizeof(*acknowledgement));
    *acknowledgement = (java_remote_parent_data_ack_t){
        .owner = transaction->key.owner,
        .generation = transaction->key.generation,
        .connection = state->connection,
        .connection_netns = state->connection_netns,
    };
    bpf_map_update_elem(&java_remote_parent_data_acks, &signal_key, acknowledgement, BPF_ANY);
}

static __always_inline u8 java_remote_parent_stage_rollback_transaction_authorized(
    const java_remote_parent_stage_transaction_t *transaction,
    const java_remote_parent_key_t *guard_key,
    const java_remote_parent_claim_t *guard_claim,
    u8 require_owner) {
    return java_remote_parent_exact_receive_claim_matches(&transaction->key, &transaction->claim) &&
           java_remote_parent_exact_detach_guard_matches_at(guard_key, guard_claim) &&
           (!require_owner ||
            java_remote_parent_stage_owner_matches_transaction(
                transaction, k_java_remote_parent_lifecycle_publishing) ||
            java_remote_parent_stage_owner_matches_transaction(
                transaction, k_java_remote_parent_lifecycle_active));
}

static __noinline __attribute__((unused)) u8 java_remote_parent_stage_acquire_rollback_guard(
    java_remote_parent_stage_transaction_t *transaction, java_remote_parent_claim_t *guard_claim) {
    if (!java_remote_parent_acquire_stage_claim(
            &transaction->key, transaction->claim.process_incarnation, &transaction->claim) ||
        !java_remote_parent_ensure_exact_ambiguity(&transaction->key)) {
        return 0;
    }
    const java_remote_parent_key_t guard_key =
        java_remote_parent_detach_guard_key(&transaction->key.owner);
    __builtin_memset(guard_claim, 0, sizeof(*guard_claim));
    return java_remote_parent_acquire_detach_guard_at(&transaction->key, &guard_key, guard_claim) &&
           java_remote_parent_stage_rollback_transaction_authorized(
               transaction, &guard_key, guard_claim, 1);
}

static __noinline __attribute__((unused)) u8 java_remote_parent_stage_rollback_connection_index(
    java_remote_parent_stage_transaction_t *transaction,
    const java_remote_parent_claim_t *guard_claim,
    u8 cookie_index) {
    const java_remote_parent_key_t guard_key =
        java_remote_parent_detach_guard_key(&transaction->key.owner);
    java_remote_parent_connection_key_t connection_key = {0};
    const java_remote_parent_state_t *state =
        bpf_map_lookup_elem(&java_remote_parent_state, &transaction->key);
    if (!java_remote_parent_stage_state_matches_transaction(transaction, state) ||
        !java_remote_parent_stage_rollback_transaction_authorized(
            transaction, &guard_key, guard_claim, 1) ||
        (cookie_index
             ? !java_remote_parent_connection_cookie_key_init(
                   &connection_key, &state->connection, transaction->connection_netns_cookie)
             : !java_remote_parent_connection_netns_key_init(
                   &connection_key, &state->connection, state->connection_netns))) {
        return 0;
    }

    const java_remote_parent_connection_t *published =
        cookie_index
            ? bpf_map_lookup_elem(&java_remote_parent_cookie_connections, &connection_key.cookie)
            : bpf_map_lookup_elem(&java_remote_parent_connections, &connection_key.netns);
    if (!published || published->generation != transaction->key.generation ||
        !java_remote_parent_pid_key_equal(&published->owner, &transaction->key.owner)) {
        return java_remote_parent_stage_rollback_transaction_authorized(
            transaction, &guard_key, guard_claim, 1);
    }
    if (!java_remote_parent_stage_connection_matches_transaction(
            published,
            &transaction->key,
            state->connection_netns,
            transaction->connection_netns_cookie,
            transaction->incoming_generation,
            transaction->socket_cookie) ||
        !java_remote_parent_stage_rollback_transaction_authorized(
            transaction, &guard_key, guard_claim, 1)) {
        return 0;
    }

    if (cookie_index) {
        bpf_map_delete_elem(&java_remote_parent_cookie_connections, &connection_key.cookie);
        published =
            bpf_map_lookup_elem(&java_remote_parent_cookie_connections, &connection_key.cookie);
    } else {
        bpf_map_delete_elem(&java_remote_parent_connections, &connection_key.netns);
        published = bpf_map_lookup_elem(&java_remote_parent_connections, &connection_key.netns);
    }
    return (!published || published->generation != transaction->key.generation ||
            !java_remote_parent_pid_key_equal(&published->owner, &transaction->key.owner)) &&
           java_remote_parent_stage_rollback_transaction_authorized(
               transaction, &guard_key, guard_claim, 1);
}

static __noinline __attribute__((unused)) u8
java_remote_parent_stage_rollback_logical(java_remote_parent_stage_transaction_t *transaction,
                                          const java_remote_parent_claim_t *guard_claim) {
    const java_remote_parent_key_t guard_key =
        java_remote_parent_detach_guard_key(&transaction->key.owner);
    if (!java_remote_parent_stage_rollback_transaction_authorized(
            transaction, &guard_key, guard_claim, 1)) {
        return 0;
    }

    const java_remote_parent_state_t *state =
        bpf_map_lookup_elem(&java_remote_parent_state, &transaction->key);
    u64 observed_monotime_ns = 0;
    if (state) {
        if (!java_remote_parent_stage_state_matches_transaction(transaction, state)) {
            return 0;
        }
        observed_monotime_ns = state->observed_monotime_ns;
    }
    const java_remote_parent_response_t *fallback =
        bpf_map_lookup_elem(&java_remote_parent_fallback, &transaction->key.owner);
    if (fallback &&
        java_remote_parent_le64_to_cpu(fallback->generation_le) == transaction->key.generation) {
        if (!java_remote_parent_exact_receive_fallback_matches(fallback, &transaction->key) ||
            !java_remote_parent_stage_rollback_transaction_authorized(
                transaction, &guard_key, guard_claim, 1)) {
            return 0;
        }
        bpf_map_delete_elem(&java_remote_parent_fallback, &transaction->key.owner);
    }
    fallback = bpf_map_lookup_elem(&java_remote_parent_fallback, &transaction->key.owner);
    if (fallback &&
        java_remote_parent_le64_to_cpu(fallback->generation_le) == transaction->key.generation) {
        return 0;
    }

    const java_remote_parent_generation_index_t *generation_index =
        bpf_map_lookup_elem(&java_remote_parent_generation_index, &transaction->key);
    if (generation_index) {
        if (!observed_monotime_ns ||
            !java_remote_parent_generation_index_matches(
                &transaction->key, transaction->claim.process_incarnation, observed_monotime_ns) ||
            !java_remote_parent_stage_rollback_transaction_authorized(
                transaction, &guard_key, guard_claim, 1)) {
            return 0;
        }
        bpf_map_delete_elem(&java_remote_parent_generation_index, &transaction->key);
    }
    if (bpf_map_lookup_elem(&java_remote_parent_generation_index, &transaction->key)) {
        return 0;
    }

    state = bpf_map_lookup_elem(&java_remote_parent_state, &transaction->key);
    if (state) {
        if (!java_remote_parent_stage_state_matches_transaction(transaction, state) ||
            state->observed_monotime_ns != observed_monotime_ns ||
            !java_remote_parent_stage_rollback_transaction_authorized(
                transaction, &guard_key, guard_claim, 1)) {
            return 0;
        }
        bpf_map_delete_elem(&java_remote_parent_state, &transaction->key);
    }
    if (bpf_map_lookup_elem(&java_remote_parent_state, &transaction->key)) {
        return 0;
    }

    const java_remote_parent_owner_t *owner =
        bpf_map_lookup_elem(&java_remote_parent_owners, &transaction->key.owner);
    if (owner && owner->generation == transaction->key.generation) {
        if (!java_remote_parent_stage_rollback_transaction_authorized(
                transaction, &guard_key, guard_claim, 1)) {
            return 0;
        }
        bpf_map_delete_elem(&java_remote_parent_owners, &transaction->key.owner);
    }
    owner = bpf_map_lookup_elem(&java_remote_parent_owners, &transaction->key.owner);
    const java_remote_parent_terminal_t *terminal =
        bpf_map_lookup_elem(&java_remote_parent_terminal, &transaction->key.owner);
    return (!owner || owner->generation != transaction->key.generation) &&
           (!terminal || terminal->generation != transaction->key.generation) &&
           !bpf_map_lookup_elem(&java_remote_parent_state, &transaction->key) &&
           !bpf_map_lookup_elem(&java_remote_parent_generation_index, &transaction->key) &&
           !java_remote_parent_fallback_has_generation(&transaction->key.owner,
                                                       transaction->key.generation) &&
           java_remote_parent_exact_receive_claim_matches(&transaction->key, &transaction->claim) &&
           java_remote_parent_exact_detach_guard_matches_at(&guard_key, guard_claim);
}

static __noinline __attribute__((unused)) u8 java_remote_parent_stage_release_rollback_fences(
    java_remote_parent_stage_transaction_t *transaction, java_remote_parent_claim_t *guard_claim) {
    const java_remote_parent_key_t guard_key =
        java_remote_parent_detach_guard_key(&transaction->key.owner);
    const java_remote_parent_owner_t *owner =
        bpf_map_lookup_elem(&java_remote_parent_owners, &transaction->key.owner);
    const java_remote_parent_terminal_t *terminal =
        bpf_map_lookup_elem(&java_remote_parent_terminal, &transaction->key.owner);
    if (!java_remote_parent_exact_receive_claim_matches(&transaction->key, &transaction->claim) ||
        !java_remote_parent_exact_detach_guard_matches_at(&guard_key, guard_claim) ||
        bpf_map_lookup_elem(&java_remote_parent_state, &transaction->key) ||
        bpf_map_lookup_elem(&java_remote_parent_generation_index, &transaction->key) ||
        (owner && owner->generation == transaction->key.generation) ||
        (terminal && terminal->generation == transaction->key.generation) ||
        java_remote_parent_fallback_has_generation(&transaction->key.owner,
                                                   transaction->key.generation)) {
        return 0;
    }

    // Exact claim ownership makes the caller's completed one-shot physical
    // absence proof stable. Release the reservation, exact claim, and owner
    // guard in order; no destructive operation follows either fence release.
    bpf_map_delete_elem(&java_remote_parent_ambiguity, &transaction->key);
    if (!java_remote_parent_generation_ambiguity_absent(&transaction->key)) {
        // Rollback payload is already absent. Preserve whichever marker
        // survived this attempt and suppress the outer old-G re-mark.
        return 1;
    }
    // M absence commits rollback. Retire E and G=0 best-effort, but never let
    // an exact-delete failure or a replacement fence make the outer caller
    // recreate the released marker.
    java_remote_parent_release_exact_receive_claim(&transaction->key, &transaction->claim);
    if (!bpf_map_lookup_elem(&java_remote_parent_claims, &transaction->key) &&
        java_remote_parent_generation_ambiguity_absent(&transaction->key)) {
        java_remote_parent_release_exact_detach_guard_at(&guard_key, guard_claim);
    }
    return 1;
}

static __always_inline void
java_remote_parent_stage_handoff_fences(const java_remote_parent_stage_transaction_t *transaction,
                                        const java_remote_parent_key_t *guard_key,
                                        const java_remote_parent_claim_t *guard_claim) {
    java_remote_parent_handoff_exact_fence_pair(
        &transaction->key, &transaction->claim, guard_key, guard_claim);
}

static __always_inline u64 java_remote_parent_stage(const connection_info_t *connection,
                                                    u32 connection_netns,
                                                    u64 connection_netns_cookie,
                                                    u64 socket_cookie,
                                                    u64 incoming_generation,
                                                    const tp_info_pid_t *incoming) {
    java_remote_parent_stage_transaction_t transaction = {
        .connection_netns_cookie = connection_netns_cookie,
        .incoming_generation = incoming_generation,
        .socket_cookie = socket_cookie,
    };
    struct {
        java_remote_parent_key_t key;
        java_remote_parent_claim_t claim;
    } rollback_guard = {0};

    if (!java_remote_parent_data_hook_is_ready() || !connection || !connection_netns ||
        !connection_netns_cookie || !socket_cookie || !incoming_generation || !incoming ||
        !incoming->valid || incoming->provenance != k_tp_provenance_tcp_exact_flags ||
        !valid_trace(incoming->tp.trace_id) || !valid_span(incoming->tp.span_id)) {
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_malformed);
        return 0;
    }
    if (!incoming_trace_claimed_generation_matches_in_netns_cookie(
            connection, connection_netns_cookie, incoming_generation, incoming)) {
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_ambiguous);
        return 0;
    }

    transaction.key.owner = java_remote_parent_current_owner();
    rollback_guard.key = java_remote_parent_detach_guard_key(&transaction.key.owner);
    const u64 process_incarnation = java_process_incarnation_for(&transaction.key.owner);
    if (!process_incarnation) {
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_malformed);
        return 0;
    }
    if (java_remote_parent_owner_detach_guarded(&transaction.key.owner)) {
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_ambiguous);
        return 0;
    }
    const java_remote_parent_owner_t *previous_owner =
        bpf_map_lookup_elem(&java_remote_parent_owners, &transaction.key.owner);
    if (previous_owner && previous_owner->process_incarnation != process_incarnation) {
        java_remote_parent_guard_owner_reuse(&transaction.key.owner);
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_ambiguous);
        return 0;
    }

    transaction.key.generation = java_remote_parent_next_generation();
    if (!transaction.key.generation) {
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_overload);
        return 0;
    }
    if (java_remote_parent_generation_in_use(&transaction.key)) {
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_ambiguous);
        return 0;
    }
    if (!java_remote_parent_acquire_stage_claim(
            &transaction.key, process_incarnation, &transaction.claim)) {
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_overload);
        return 0;
    }
    if (!java_remote_parent_reserve_exact_ambiguity(&transaction.key)) {
        // No marker was published. An exact-only failure tail is recoverable;
        // never synthesize M after a concurrently completed claim release.
        java_remote_parent_release_exact_receive_claim(&transaction.key, &transaction.claim);
        java_remote_parent_stage_handoff_fences(
            &transaction, &rollback_guard.key, &rollback_guard.claim);
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_overload);
        return 0;
    }

    enum java_remote_parent_stat rollback_stat = k_java_remote_parent_stat_stage_ambiguous;
    u8 netns_index_attempted = 0;
    u8 cookie_index_attempted = 0;
    const enum java_remote_parent_stage_leaf_result logical =
        java_remote_parent_stage_publish_logical(
            &transaction, connection, connection_netns, incoming, &rollback_guard.key);
    if (logical == k_java_remote_parent_stage_leaf_owner_conflict) {
        // No G artifact was published. Release only this empty transaction,
        // after the conflicting owner was quarantined by the leaf.
        if (java_remote_parent_generation_cleanly_reserved(&transaction.key) &&
            java_remote_parent_exact_receive_claim_matches(&transaction.key, &transaction.claim)) {
            bpf_map_delete_elem(&java_remote_parent_ambiguity, &transaction.key);
            if (java_remote_parent_generation_ambiguity_absent(&transaction.key)) {
                // No G artifact or owner guard exists in this branch. Once M
                // is absent, release E best-effort and never recreate M.
                java_remote_parent_release_exact_receive_claim(&transaction.key,
                                                               &transaction.claim);
            }
        }
        java_remote_parent_stage_handoff_fences(
            &transaction, &rollback_guard.key, &rollback_guard.claim);
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_ambiguous);
        return 0;
    }
    if (logical == k_java_remote_parent_stage_leaf_overload) {
        rollback_stat = k_java_remote_parent_stat_stage_overload;
    }
    if (logical != k_java_remote_parent_stage_leaf_valid) {
        goto rollback;
    }

    netns_index_attempted = 1;
    if (!java_remote_parent_stage_publish_netns_index(&transaction, &rollback_guard.key)) {
        java_remote_parent_stage_quarantine_netns_conflict(&transaction);
        goto rollback;
    }
    cookie_index_attempted = 1;
    if (!java_remote_parent_stage_publish_cookie_index(&transaction, &rollback_guard.key)) {
        java_remote_parent_stage_quarantine_cookie_conflict(&transaction);
        goto rollback;
    }
    if (!java_remote_parent_stage_finish_publication(&transaction, incoming, &rollback_guard.key)) {
        goto rollback;
    }

    java_remote_parent_stage_acknowledge(&transaction);
    java_remote_parent_stage_handoff_fences(
        &transaction, &rollback_guard.key, &rollback_guard.claim);
    java_remote_parent_stat_add(k_java_remote_parent_stat_stage_valid);
    return transaction.key.generation;

rollback:
    // Mark whichever same-owner cursor is now visible before any final G fence
    // can be released. This is idempotent for our publishing generation and
    // fail-closed for an unexpected replacement.
    java_remote_parent_guard_owner_reuse(&transaction.key.owner);
    if (!java_remote_parent_stage_acquire_rollback_guard(&transaction, &rollback_guard.claim)) {
        java_remote_parent_ensure_exact_ambiguity(&transaction.key);
        java_remote_parent_stage_handoff_fences(
            &transaction, &rollback_guard.key, &rollback_guard.claim);
        java_remote_parent_stat_add(rollback_stat);
        return 0;
    }

    u8 complete = 1;
    if (cookie_index_attempted && !java_remote_parent_stage_rollback_connection_index(
                                      &transaction, &rollback_guard.claim, 1)) {
        complete = 0;
    }
    if (netns_index_attempted && !java_remote_parent_stage_rollback_connection_index(
                                     &transaction, &rollback_guard.claim, 0)) {
        complete = 0;
    }
    if (complete &&
        !java_remote_parent_stage_rollback_logical(&transaction, &rollback_guard.claim)) {
        complete = 0;
    }
    if (complete &&
        !java_remote_parent_stage_release_rollback_fences(&transaction, &rollback_guard.claim)) {
        complete = 0;
    }
    if (!complete) {
        // Partial cleanup retains the exact claim and owner guard. The nonzero
        // marker makes every reader fail closed until userspace adopts them.
        java_remote_parent_ensure_exact_ambiguity(&transaction.key);
    }
    java_remote_parent_stage_handoff_fences(
        &transaction, &rollback_guard.key, &rollback_guard.claim);
    java_remote_parent_stat_add(rollback_stat);
    return 0;
}

static __always_inline u64
java_remote_parent_stage_incoming(const connection_info_t *connection,
                                  u32 connection_netns,
                                  u64 connection_netns_cookie,
                                  u64 socket_cookie,
                                  const java_remote_parent_incoming_t *incoming) {
    return java_remote_parent_stage(connection,
                                    connection_netns,
                                    connection_netns_cookie,
                                    socket_cookie,
                                    incoming->generation,
                                    &incoming->candidate);
}

typedef struct java_remote_parent_resolution {
    java_remote_parent_key_t key;
    java_remote_parent_owner_t indexed;
    u64 observed_monotime_ns;
    u8 found;
    u8 ambiguous;
    u8 via_task;
    u8 via_replay;
    unsigned char reserved[4];
} java_remote_parent_resolution_t;

static __noinline __attribute__((unused)) void
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
        const java_remote_parent_state_t *state =
            bpf_map_lookup_elem(&java_remote_parent_state, &resolution->key);
        if (state && state->process_incarnation == process_incarnation &&
            state->lifecycle == k_java_remote_parent_lifecycle_active &&
            state->response.status == k_java_remote_parent_status_valid &&
            java_remote_parent_le64_to_cpu(state->response.generation_le) == indexed->generation) {
            resolution->observed_monotime_ns = state->observed_monotime_ns;
        }
        resolution->found = 1;
        if (!java_remote_parent_generation_cleanly_reserved(&resolution->key)) {
            resolution->ambiguous = 1;
        }
        return;
    }

    if (expected_generation) {
        const java_remote_parent_key_t key =
            java_remote_parent_state_key(owner, expected_generation);
        const java_remote_parent_state_t *state =
            bpf_map_lookup_elem(&java_remote_parent_state, &key);
        if (state && state->aliases && state->process_incarnation == process_incarnation &&
            state->lifecycle == k_java_remote_parent_lifecycle_active &&
            state->response.status == k_java_remote_parent_status_valid &&
            java_remote_parent_le64_to_cpu(state->response.generation_le) == expected_generation &&
            java_remote_parent_generation_index_matches(
                &key, process_incarnation, state->observed_monotime_ns)) {
            resolution->key = key;
            resolution->indexed.generation = expected_generation;
            resolution->indexed.process_incarnation = process_incarnation;
            resolution->indexed.lifecycle = k_java_remote_parent_lifecycle_active;
            resolution->observed_monotime_ns = state->observed_monotime_ns;
            resolution->found = 1;
            if (!java_remote_parent_generation_cleanly_reserved(&key)) {
                resolution->ambiguous = 1;
            }
            return;
        }
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
        resolution->observed_monotime_ns = terminal->observed_monotime_ns;
        resolution->found = 1;
        if (!java_remote_parent_generation_ambiguity_absent(&resolution->key)) {
            resolution->ambiguous = 1;
        }
    }
}

static __noinline __attribute__((unused)) void
java_remote_parent_resolve_alias_replay(java_remote_parent_resolution_t *resolution,
                                        const java_remote_parent_task_t *task) {
    const u64 process_incarnation = java_current_process_incarnation();
    if (!resolution || !task || !process_incarnation || !task->generation ||
        !task->observed_monotime_ns) {
        return;
    }
    const java_remote_parent_key_t generation =
        java_remote_parent_state_key(&task->owner, task->generation);
    const java_remote_parent_alias_replay_key_t replay_key = java_remote_parent_alias_replay_key(
        &generation, task->observed_monotime_ns, process_incarnation);
    const java_remote_parent_alias_replay_t *replay =
        bpf_map_lookup_elem(&java_remote_parent_alias_replays, &replay_key);
    if (!replay) {
        return;
    }

    const u8 final = replay->references && java_remote_parent_alias_replay_final_valid(
                                               &replay_key, replay, replay->lifecycle);
    const u8 publishing = replay->references && java_remote_parent_alias_replay_publishing_valid(
                                                    &replay_key, replay, replay->desired_lifecycle);
    const u8 active = java_remote_parent_alias_replay_active_valid(&replay_key, replay, 1);
    const u8 generation_claimed = bpf_map_lookup_elem(&java_remote_parent_claims, &generation) != 0;
    const u8 active_claimed = active && generation_claimed;
    if ((active || publishing || final) && java_remote_parent_generation_observation_matches(
                                               &generation, task->observed_monotime_ns)) {
        // A matching state/claim binding is more specific than status-only
        // replay. Let that exact live state resolve; a differently observed
        // successor can never satisfy this check.
        return;
    }

    // This helper is reachable only through a task carrier. An exact replay
    // key therefore outranks a singleton successor that reused owner and
    // generation with a different observation. Direct-source resolution never
    // calls this helper and cannot consult replay authority.
    __builtin_memset(resolution, 0, sizeof(*resolution));
    resolution->key = generation;
    resolution->indexed.generation = task->generation;
    resolution->indexed.process_incarnation = process_incarnation;
    resolution->observed_monotime_ns = task->observed_monotime_ns;
    resolution->found = 1;
    resolution->via_replay = 1;

    if (final) {
        resolution->indexed.lifecycle = replay->lifecycle;
        return;
    }
    if (publishing) {
        resolution->indexed.lifecycle = k_java_remote_parent_lifecycle_publishing;
        resolution->ambiguous = 1;
        return;
    }
    if (active_claimed) {
        // E is the semantic authority while an active replay is transitioning.
        // Mark the structural resolution ambiguous so retrieval consults E
        // before attempting connection/state delivery.
        resolution->indexed.lifecycle = k_java_remote_parent_lifecycle_active;
        resolution->ambiguous = 1;
        return;
    }

    // An exact but malformed record must fail closed rather than degrading a
    // still-linked task to Missing or consulting a successor singleton.
    resolution->indexed.lifecycle = k_java_remote_parent_lifecycle_publishing;
    resolution->ambiguous = 1;
}

static __always_inline java_remote_parent_resolution_t
java_remote_parent_resolve(const pid_key_t *start, u64 max_age_ns) {
    java_remote_parent_resolution_t resolution = {0};
    java_remote_parent_resolve_exact(&resolution, start, 0, 0);
    const u8 resolved_direct = resolution.found;

    const java_remote_parent_task_t *task = bpf_map_lookup_elem(&java_remote_parent_tasks, start);
    if (task) {
        const java_remote_parent_task_t copy = *task;
        const u64 now = bpf_ktime_get_ns();
        if (!copy.generation || !copy.observed_monotime_ns || now < copy.observed_monotime_ns ||
            (max_age_ns && now - copy.observed_monotime_ns > max_age_ns)) {
            if (bpf_map_delete_elem(&java_remote_parent_tasks, start) == 0) {
                const java_remote_parent_key_t generation =
                    java_remote_parent_state_key(&copy.owner, copy.generation);
                java_remote_parent_release_generation_alias(&generation, copy.observed_monotime_ns);
            }
            return resolution;
        } else if (resolution.found &&
                   (!java_remote_parent_pid_key_equal(&resolution.key.owner, &copy.owner) ||
                    resolution.key.generation != copy.generation)) {
            resolution.ambiguous = 1;
            java_remote_parent_mark_exact_generation_ambiguous(&resolution.key);
            const java_remote_parent_key_t linked_generation =
                java_remote_parent_state_key(&copy.owner, copy.generation);
            java_remote_parent_mark_exact_generation_ambiguous(&linked_generation);
        } else if (!resolution.found) {
            java_remote_parent_resolve_alias_replay(&resolution, &copy);
            if (!resolution.found) {
                java_remote_parent_resolve_exact(&resolution, &copy.owner, copy.generation, 1);
            }
        }
        if (resolution.found && !resolution.ambiguous &&
            java_remote_parent_pid_key_equal(&resolution.key.owner, &copy.owner) &&
            resolution.key.generation == copy.generation &&
            resolution.observed_monotime_ns == copy.observed_monotime_ns) {
            resolution.via_task = 1;
        } else if (resolution.found &&
                   java_remote_parent_pid_key_equal(&resolution.key.owner, &copy.owner) &&
                   resolution.key.generation == copy.generation &&
                   resolution.observed_monotime_ns != copy.observed_monotime_ns) {
            if (bpf_map_delete_elem(&java_remote_parent_tasks, start) == 0) {
                const java_remote_parent_key_t generation =
                    java_remote_parent_state_key(&copy.owner, copy.generation);
                java_remote_parent_release_generation_alias(&generation, copy.observed_monotime_ns);
            }
            if (!resolved_direct) {
                __builtin_memset(&resolution, 0, sizeof(resolution));
            }
        }
    } else if (!resolution.found) {
        java_remote_parent_resolve_exact(&resolution, start, 0, 1);
    }

    return resolution;
}

static __noinline __attribute__((unused)) void
java_remote_parent_resolve_task_into(java_remote_parent_resolution_t *resolution,
                                     const pid_key_t *start,
                                     u64 max_age_ns,
                                     java_remote_parent_task_t *copy) {
    __builtin_memset(resolution, 0, sizeof(*resolution));
    const java_remote_parent_task_t *task = bpf_map_lookup_elem(&java_remote_parent_tasks, start);
    if (!task) {
        return;
    }

    *copy = *task;
    const u64 now = bpf_ktime_get_ns();
    if (copy->reserved != 0 || (!copy->owner.tid && !copy->owner.pid && !copy->owner.ns) ||
        !copy->generation || !copy->observed_monotime_ns || now < copy->observed_monotime_ns) {
        if (bpf_map_delete_elem(&java_remote_parent_tasks, start) == 0) {
            const java_remote_parent_key_t generation =
                java_remote_parent_state_key(&copy->owner, copy->generation);
            java_remote_parent_release_generation_alias(&generation, copy->observed_monotime_ns);
        }
        return;
    }

    if (max_age_ns && now - copy->observed_monotime_ns > max_age_ns) {
        // Expiry prevents a new delivery, but must not erase an already
        // committed exact one-shot result. Resolve terminal/replay authority
        // first so sibling tasks converge on the same status.
        java_remote_parent_resolve_alias_replay(resolution, copy);
        if (!resolution->found) {
            java_remote_parent_resolve_exact(resolution, &copy->owner, copy->generation, 1);
        }
        if (resolution->found &&
            java_remote_parent_alias_replay_lifecycle_final(resolution->indexed.lifecycle) &&
            java_remote_parent_pid_key_equal(&resolution->key.owner, &copy->owner) &&
            resolution->key.generation == copy->generation &&
            resolution->observed_monotime_ns == copy->observed_monotime_ns) {
            resolution->via_task = 1;
            return;
        }
        __builtin_memset(resolution, 0, sizeof(*resolution));
        if (bpf_map_delete_elem(&java_remote_parent_tasks, start) == 0) {
            const java_remote_parent_key_t generation =
                java_remote_parent_state_key(&copy->owner, copy->generation);
            java_remote_parent_release_generation_alias(&generation, copy->observed_monotime_ns);
        }
        return;
    }

    java_remote_parent_resolve_alias_replay(resolution, copy);
    if (!resolution->found) {
        java_remote_parent_resolve_exact(resolution, &copy->owner, copy->generation, 1);
    }
    if (resolution->found &&
        java_remote_parent_pid_key_equal(&resolution->key.owner, &copy->owner) &&
        resolution->key.generation == copy->generation &&
        resolution->observed_monotime_ns == copy->observed_monotime_ns) {
        // Keep the exact task provenance even when the generation is fenced.
        // A retained claim can then report the committed one-shot result while
        // the fence still prevents any new delivery.
        resolution->via_task = 1;
    } else if (resolution->found &&
               java_remote_parent_pid_key_equal(&resolution->key.owner, &copy->owner) &&
               resolution->key.generation == copy->generation &&
               resolution->observed_monotime_ns != copy->observed_monotime_ns) {
        if (bpf_map_delete_elem(&java_remote_parent_tasks, start) == 0) {
            const java_remote_parent_key_t generation =
                java_remote_parent_state_key(&copy->owner, copy->generation);
            java_remote_parent_release_generation_alias(&generation, copy->observed_monotime_ns);
        }
        __builtin_memset(resolution, 0, sizeof(*resolution));
    }
}

static __always_inline java_remote_parent_resolution_t
java_remote_parent_resolve_task(const pid_key_t *start, u64 max_age_ns) {
    java_remote_parent_resolution_t resolution = {0};
    java_remote_parent_task_t copy = {0};
    java_remote_parent_resolve_task_into(&resolution, start, max_age_ns, &copy);
    return resolution;
}

static __always_inline void java_remote_parent_unlink_task(const pid_key_t *child) {
    const java_remote_parent_task_t *linked = bpf_map_lookup_elem(&java_remote_parent_tasks, child);
    if (!linked) {
        return;
    }

    const java_remote_parent_task_t copy = *linked;
    if (bpf_map_delete_elem(&java_remote_parent_tasks, child) == 0) {
        const java_remote_parent_key_t generation =
            java_remote_parent_state_key(&copy.owner, copy.generation);
        java_remote_parent_release_generation_alias(&generation, copy.observed_monotime_ns);
    }
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

static __always_inline u8 java_remote_parent_exact_generation_active(
    const java_remote_parent_key_t *key, u64 observed_monotime_ns, u8 require_owner_cursor) {
    if (!java_remote_parent_generation_observation_matches(key, observed_monotime_ns)) {
        return 0;
    }
    if (!require_owner_cursor) {
        return java_remote_parent_generation_alias_active(key);
    }
    return java_remote_parent_generation_live_cursor_active(key);
}

static __always_inline u8 java_remote_parent_exact_generation_carrier_authoritative(
    const java_remote_parent_key_t *key, u64 observed_monotime_ns, u64 process_incarnation) {
    if (java_remote_parent_exact_generation_active(key, observed_monotime_ns, 0)) {
        return 1;
    }
    const java_remote_parent_alias_replay_key_t replay_key =
        java_remote_parent_alias_replay_key(key, observed_monotime_ns, process_incarnation);
    const java_remote_parent_alias_replay_t *replay =
        bpf_map_lookup_elem(&java_remote_parent_alias_replays, &replay_key);
    if (replay && replay->references &&
        java_remote_parent_alias_replay_final_valid(&replay_key, replay, replay->lifecycle)) {
        return 1;
    }
    const u8 transitioning = java_remote_parent_alias_replay_active_valid(&replay_key, replay, 1) ||
                             (replay && replay->references &&
                              java_remote_parent_alias_replay_publishing_valid(
                                  &replay_key, replay, replay->desired_lifecycle));
    return transitioning && bpf_map_lookup_elem(&java_remote_parent_claims, key);
}

static __always_inline void
java_remote_parent_capture_handoff_for_execution(const pid_key_t *execution, u64 token) {
    if (!token) {
        return;
    }

    java_remote_parent_resolution_t resolution = {0};
    // A handler submission may capture only the generation staged directly by
    // this execution's current receive. A task alias identifies an older exact
    // execution scope, not the request currently entering a TLS handler.
    java_remote_parent_resolve_exact(&resolution, execution, 0, 0);
    if (resolution.ambiguous || !resolution.found ||
        resolution.indexed.lifecycle != k_java_remote_parent_lifecycle_active ||
        !java_remote_parent_exact_generation_active(
            &resolution.key, resolution.observed_monotime_ns, 1)) {
        return;
    }

    const java_remote_parent_handoff_key_t key = java_remote_parent_handoff_key(execution, token);
    if (bpf_map_lookup_elem(&java_remote_parent_handoff_claims, &key)) {
        java_remote_parent_mark_exact_generation_ambiguous(&resolution.key);
        return;
    }

    const java_remote_parent_task_t handoff = {
        .owner = resolution.key.owner,
        .generation = resolution.key.generation,
        .observed_monotime_ns = resolution.observed_monotime_ns,
    };
    if (!java_remote_parent_retain_generation_alias(&resolution.key,
                                                    resolution.observed_monotime_ns)) {
        java_remote_parent_mark_exact_generation_ambiguous(&resolution.key);
        return;
    }
    if (bpf_map_update_elem(&java_remote_parent_handoffs, &key, &handoff, BPF_NOEXIST) != 0) {
        java_remote_parent_release_generation_alias(&resolution.key,
                                                    resolution.observed_monotime_ns);
        const java_remote_parent_task_t *existing =
            bpf_map_lookup_elem(&java_remote_parent_handoffs, &key);
        if (existing) {
            const java_remote_parent_task_t copy = *existing;
            const java_remote_parent_key_t existing_generation =
                java_remote_parent_state_key(&copy.owner, copy.generation);
            java_remote_parent_mark_exact_generation_ambiguous(&existing_generation);
            java_remote_parent_mark_exact_generation_ambiguous(&resolution.key);
        } else {
            java_remote_parent_stat_add(k_java_remote_parent_stat_stage_overload);
        }
        return;
    }

    const java_remote_parent_task_t *published =
        bpf_map_lookup_elem(&java_remote_parent_handoffs, &key);
    volatile u8 claimed = bpf_map_lookup_elem(&java_remote_parent_handoff_claims, &key) != NULL;
    if (!published || published->generation != resolution.key.generation ||
        published->observed_monotime_ns != resolution.observed_monotime_ns ||
        !java_remote_parent_pid_key_equal(&published->owner, &resolution.key.owner) || claimed ||
        !java_remote_parent_exact_generation_active(
            &resolution.key, resolution.observed_monotime_ns, 0)) {
        const long deleted = bpf_map_delete_elem(&java_remote_parent_handoffs, &key);
        if (deleted == 0) {
            java_remote_parent_release_generation_alias(&resolution.key,
                                                        resolution.observed_monotime_ns);
            java_remote_parent_mark_exact_generation_ambiguous(&resolution.key);
        }
    }
}

static __always_inline void java_remote_parent_capture_handoff(u64 token) {
    const pid_key_t execution = java_remote_parent_current_owner();
    java_remote_parent_capture_handoff_for_execution(&execution, token);
}

static __always_inline void java_remote_parent_cancel_handoff_for_capability(
    const pid_key_t *execution, u64 token, u64 process_capability) {
    if (!token || !process_capability) {
        return;
    }
    const java_remote_parent_handoff_key_t key = java_remote_parent_handoff_key(execution, token);
    const java_remote_parent_handoff_claim_t claimed = {
        .observed_monotime_ns = bpf_ktime_get_ns(),
        .process_incarnation = process_capability,
    };
    if (bpf_map_update_elem(&java_remote_parent_handoff_claims, &key, &claimed, BPF_NOEXIST) != 0) {
        return;
    }

    const java_remote_parent_task_t *found =
        bpf_map_lookup_elem(&java_remote_parent_handoffs, &key);
    if (!found) {
        return;
    }
    const java_remote_parent_task_t handoff = *found;
    if (bpf_map_delete_elem(&java_remote_parent_handoffs, &key) == 0) {
        const java_remote_parent_key_t generation =
            java_remote_parent_state_key(&handoff.owner, handoff.generation);
        java_remote_parent_release_generation_alias(&generation, handoff.observed_monotime_ns);
    }
}

static __always_inline void java_remote_parent_cancel_handoff(const pid_key_t *execution,
                                                              u64 token) {
    java_remote_parent_cancel_handoff_for_capability(
        execution, token, java_process_incarnation_for(execution));
}

static __always_inline void java_remote_parent_fail_handoff(const pid_key_t *child) {
    java_remote_parent_unlink_task(child);
    java_remote_parent_mark_ambiguous(child);
}

static __always_inline void java_remote_parent_link_handoff_for_capability(const pid_key_t *child,
                                                                           u64 token,
                                                                           u64 process_capability) {
    // RESET uses the owner-scoped guard to serialize the key-only task-map
    // delete. Do not remove or replace the guarded key from a concurrent
    // handoff publication.
    if (java_remote_parent_owner_detach_guarded(child)) {
        return;
    }
    java_remote_parent_unlink_task(child);
    if (!token || !process_capability) {
        return;
    }

    const java_remote_parent_handoff_key_t key = java_remote_parent_handoff_key(child, token);
    const java_remote_parent_handoff_claim_t claimed = {
        .observed_monotime_ns = bpf_ktime_get_ns(),
        .process_incarnation = process_capability,
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
    if (bpf_map_delete_elem(&java_remote_parent_handoffs, &key) != 0) {
        const java_remote_parent_key_t generation =
            java_remote_parent_state_key(&handoff.owner, handoff.generation);
        java_remote_parent_mark_exact_generation_ambiguous(&generation);
        java_remote_parent_fail_handoff(child);
        return;
    }

    const java_remote_parent_key_t generation =
        java_remote_parent_state_key(&handoff.owner, handoff.generation);
    if (!handoff.generation || !java_remote_parent_exact_generation_carrier_authoritative(
                                   &generation, handoff.observed_monotime_ns, process_capability)) {
        java_remote_parent_release_generation_alias(&generation, handoff.observed_monotime_ns);
        java_remote_parent_fail_handoff(child);
        return;
    }

    if (java_remote_parent_owner_detach_guarded(child)) {
        java_remote_parent_release_generation_alias(&generation, handoff.observed_monotime_ns);
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_overload);
        return;
    }
    // The old binding was explicitly unlinked above. NOEXIST prevents a
    // publisher that passed the guard check before RESET acquired it from
    // overwriting the exact value RESET subsequently revalidated.
    if (bpf_map_update_elem(&java_remote_parent_tasks, child, &handoff, BPF_NOEXIST) != 0) {
        java_remote_parent_release_generation_alias(&generation, handoff.observed_monotime_ns);
        if (java_remote_parent_owner_detach_guarded(child)) {
            java_remote_parent_stat_add(k_java_remote_parent_stat_stage_overload);
            return;
        }
        java_remote_parent_fail_handoff(child);
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_overload);
        return;
    }
    if (java_remote_parent_owner_detach_guarded(child) ||
        !java_remote_parent_exact_generation_carrier_authoritative(
            &generation, handoff.observed_monotime_ns, process_capability)) {
        java_remote_parent_fail_handoff(child);
        java_remote_parent_stat_add(k_java_remote_parent_stat_stage_overload);
    }
}

static __always_inline void java_remote_parent_link_handoff(const pid_key_t *child, u64 token) {
    java_remote_parent_link_handoff_for_capability(
        child, token, java_process_incarnation_for(child));
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
        !java_remote_parent_exact_generation_active(&generation, relay.observed_monotime_ns, 0)) {
        return;
    }

    const java_remote_parent_handoff_key_t key = java_remote_parent_handoff_key(execution, token);
    if (bpf_map_lookup_elem(&java_remote_parent_handoff_claims, &key)) {
        java_remote_parent_mark_exact_generation_ambiguous(&generation);
        return;
    }
    if (!java_remote_parent_retain_detached_generation_alias(&generation,
                                                             relay.observed_monotime_ns)) {
        java_remote_parent_mark_exact_generation_ambiguous(&generation);
        return;
    }
    if (bpf_map_update_elem(&java_remote_parent_handoffs, &key, &relay, BPF_NOEXIST) != 0) {
        java_remote_parent_release_generation_alias(&generation, relay.observed_monotime_ns);
        const java_remote_parent_task_t *existing =
            bpf_map_lookup_elem(&java_remote_parent_handoffs, &key);
        if (existing) {
            const java_remote_parent_task_t copy = *existing;
            const java_remote_parent_key_t existing_generation =
                java_remote_parent_state_key(&copy.owner, copy.generation);
            java_remote_parent_mark_exact_generation_ambiguous(&existing_generation);
        }
        java_remote_parent_mark_exact_generation_ambiguous(&generation);
        return;
    }

    const java_remote_parent_task_t *published =
        bpf_map_lookup_elem(&java_remote_parent_handoffs, &key);
    linked = bpf_map_lookup_elem(&java_remote_parent_tasks, execution);
    volatile u8 claimed = bpf_map_lookup_elem(&java_remote_parent_handoff_claims, &key) != NULL;
    if (!published || published->generation != relay.generation ||
        published->observed_monotime_ns != relay.observed_monotime_ns ||
        !java_remote_parent_pid_key_equal(&published->owner, &relay.owner) || !linked ||
        linked->generation != relay.generation ||
        linked->observed_monotime_ns != relay.observed_monotime_ns ||
        !java_remote_parent_pid_key_equal(&linked->owner, &relay.owner) || claimed ||
        !java_remote_parent_exact_generation_active(&generation, relay.observed_monotime_ns, 0)) {
        const long deleted = bpf_map_delete_elem(&java_remote_parent_handoffs, &key);
        if (deleted == 0) {
            java_remote_parent_release_generation_alias(&generation, relay.observed_monotime_ns);
            java_remote_parent_mark_exact_generation_ambiguous(&generation);
        }
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
    case k_java_remote_parent_lifecycle_cleanup:
        return k_java_remote_parent_status_ambiguous;
    case k_java_remote_parent_lifecycle_consumed:
    case k_java_remote_parent_lifecycle_discarded:
        return k_java_remote_parent_status_already_consumed;
    }
    return k_java_remote_parent_status_missing;
}

static __always_inline u8
java_remote_parent_finish_claim_shape_valid(const java_remote_parent_resolution_t *resolution,
                                            const java_remote_parent_claim_t *owned_claim) {
    return owned_claim && owned_claim->observed_monotime_ns &&
           owned_claim->process_incarnation == resolution->indexed.process_incarnation &&
           java_remote_parent_alias_replay_lifecycle_final(owned_claim->lifecycle) &&
           java_remote_parent_clean_lifecycle_tail(&owned_claim->lifecycle, owned_claim->lifecycle);
}

static __always_inline u8
java_remote_parent_finish_claim_shape_compact(const java_remote_parent_resolution_t *resolution,
                                              const java_remote_parent_claim_t *owned_claim,
                                              enum java_remote_parent_lifecycle lifecycle);

static __noinline __attribute__((unused)) u8
java_remote_parent_finish_claim_valid(const java_remote_parent_resolution_t *resolution,
                                      const java_remote_parent_claim_t *owned_claim) {
    if (!owned_claim || !java_remote_parent_finish_claim_shape_compact(
                            resolution, owned_claim, owned_claim->lifecycle)) {
        return 0;
    }
    const java_remote_parent_claim_t *current_claim =
        bpf_map_lookup_elem(&java_remote_parent_claims, &resolution->key);
    return java_remote_parent_claim_equal_inline(current_claim, owned_claim);
}

static __noinline __attribute__((unused)) u8 java_remote_parent_finish_reservation_valid(
    const java_remote_parent_key_t *key, enum java_remote_parent_lifecycle lifecycle) {
    return java_remote_parent_generation_cleanly_reserved(key) ||
           (lifecycle == k_java_remote_parent_lifecycle_ambiguous &&
            java_remote_parent_generation_ambiguous(key));
}

static __always_inline u8
java_remote_parent_finish_guard_shape_valid(const java_remote_parent_resolution_t *resolution,
                                            const java_remote_parent_finish_guard_t *guard) {
    return guard && !guard->key.generation && !guard->key.reserved &&
           java_remote_parent_pid_key_equal(&guard->key.owner, &resolution->key.owner) &&
           guard->claim.observed_monotime_ns &&
           guard->claim.process_incarnation == resolution->key.generation &&
           java_remote_parent_clean_lifecycle_tail(&guard->claim.lifecycle,
                                                   k_java_remote_parent_lifecycle_publishing) &&
           java_remote_parent_clean_boolean_second_byte_tail(&guard->physical_detached);
}

static __always_inline u64 java_remote_parent_nonzero_bit(u64 value) {
    return (value | (0 - value)) >> 63;
}

static __always_inline u8
java_remote_parent_finish_claim_shape_compact(const java_remote_parent_resolution_t *resolution,
                                              const java_remote_parent_claim_t *owned_claim,
                                              enum java_remote_parent_lifecycle lifecycle) {
    if (!owned_claim) {
        return 0;
    }
    const u64 lifecycle_word = (u8)lifecycle;
    const u64 tail = java_remote_parent_lifecycle_tail_word(&owned_claim->lifecycle);
    volatile u64 mismatch =
        (((lifecycle_word - k_java_remote_parent_lifecycle_consumed) |
          (k_java_remote_parent_lifecycle_ambiguous - lifecycle_word)) >>
         63) |
        (1 ^ java_remote_parent_nonzero_bit(owned_claim->observed_monotime_ns)) |
        (owned_claim->process_incarnation ^ resolution->indexed.process_incarnation) |
        (tail ^ lifecycle_word) | (1 ^ java_remote_parent_nonzero_bit(resolution->key.generation)) |
        resolution->key.reserved;
    return mismatch == 0;
}

static __always_inline u8
java_remote_parent_finish_guard_shape_compact(const java_remote_parent_resolution_t *resolution,
                                              const java_remote_parent_finish_guard_t *guard) {
    if (!guard) {
        return 0;
    }
    u64 guard_owner_prefix;
    u64 resolution_owner_prefix;
    __builtin_memcpy(&guard_owner_prefix, &guard->key.owner, sizeof(guard_owner_prefix));
    __builtin_memcpy(
        &resolution_owner_prefix, &resolution->key.owner, sizeof(resolution_owner_prefix));
    const u64 claim_tail = java_remote_parent_lifecycle_tail_word(&guard->claim.lifecycle);
    const u64 trailer = java_remote_parent_lifecycle_tail_word(&guard->physical_detached);
    volatile u64 mismatch =
        guard->key.generation | guard->key.reserved |
        (guard_owner_prefix ^ resolution_owner_prefix) |
        (guard->key.owner.ns ^ resolution->key.owner.ns) |
        (1 ^ java_remote_parent_nonzero_bit(guard->claim.observed_monotime_ns)) |
        (guard->claim.process_incarnation ^ resolution->key.generation) |
        (claim_tail ^ k_java_remote_parent_lifecycle_publishing) | (trailer & ~(u64)0x1ff);
    return mismatch == 0;
}

static __noinline __attribute__((unused)) u8
java_remote_parent_finish_guard_valid(const java_remote_parent_resolution_t *resolution,
                                      const java_remote_parent_finish_guard_t *guard) {
    return java_remote_parent_finish_guard_shape_valid(resolution, guard) &&
           java_remote_parent_exact_detach_guard_matches_at(&guard->key, &guard->claim);
}

// Paired finish barriers always revalidate E before G. Keep both fresh map
// lookups in one verifier boundary so their byte-exact shapes do not form a
// cross-product in every caller. The standalone pre-acquisition E check stays
// separate because G does not exist yet at that point.
static __noinline __attribute__((unused)) u8
java_remote_parent_finish_authority_valid(const java_remote_parent_resolution_t *resolution,
                                          const java_remote_parent_claim_t *owned_claim,
                                          const java_remote_parent_finish_guard_t *guard) {
    if (!owned_claim || !java_remote_parent_finish_claim_shape_compact(
                            resolution, owned_claim, owned_claim->lifecycle)) {
        return 0;
    }
    const java_remote_parent_claim_t *current_claim =
        bpf_map_lookup_elem(&java_remote_parent_claims, &resolution->key);
    if (!java_remote_parent_claim_equal_inline(current_claim, owned_claim) ||
        !java_remote_parent_finish_guard_shape_compact(resolution, guard)) {
        return 0;
    }
    const java_remote_parent_claim_t *current_guard =
        bpf_map_lookup_elem(&java_remote_parent_owner_guards, &guard->key.owner);
    return java_remote_parent_claim_equal_inline(current_guard, &guard->claim);
}

static __noinline __attribute__((unused)) u8
java_remote_parent_finish_state_valid(const java_remote_parent_resolution_t *resolution,
                                      const java_remote_parent_state_t *state,
                                      u64 observed_monotime_ns) {
    return state && state->process_incarnation == resolution->indexed.process_incarnation &&
           state->process_incarnation && state->observed_monotime_ns == observed_monotime_ns &&
           java_remote_parent_metadata_word(&state->lifecycle) ==
               k_java_remote_parent_lifecycle_active &&
           observed_monotime_ns && state->response.status == k_java_remote_parent_status_valid &&
           java_remote_parent_le64_to_cpu(state->response.generation_le) ==
               resolution->key.generation &&
           java_remote_parent_le64_to_cpu(state->response.observed_monotime_ns_le) ==
               observed_monotime_ns;
}

static __always_inline u8
java_remote_parent_finish_terminal_record_valid(const java_remote_parent_terminal_t *terminal) {
    return terminal && terminal->generation && terminal->observed_monotime_ns &&
           terminal->process_incarnation &&
           java_remote_parent_alias_replay_lifecycle_final(terminal->lifecycle) &&
           java_remote_parent_clean_lifecycle_tail(&terminal->lifecycle, terminal->lifecycle);
}

static __always_inline u8
java_remote_parent_finish_terminal_valid(const java_remote_parent_resolution_t *resolution,
                                         const java_remote_parent_terminal_t *terminal,
                                         enum java_remote_parent_lifecycle lifecycle,
                                         u64 observed_monotime_ns) {
    return terminal && terminal->generation == resolution->key.generation &&
           terminal->observed_monotime_ns == observed_monotime_ns &&
           terminal->process_incarnation == resolution->indexed.process_incarnation &&
           java_remote_parent_clean_lifecycle_tail(&terminal->lifecycle, lifecycle);
}

static __noinline __attribute__((unused)) u8
java_remote_parent_finish_terminal_matches_guard(const java_remote_parent_resolution_t *resolution,
                                                 const java_remote_parent_terminal_t *terminal,
                                                 enum java_remote_parent_lifecycle lifecycle,
                                                 u64 observed_monotime_ns,
                                                 const java_remote_parent_finish_guard_t *guard) {
    if (!java_remote_parent_finish_terminal_record_valid(terminal) || !guard ||
        !guard->terminal_generation || terminal->generation != guard->terminal_generation) {
        return 0;
    }
    return terminal->generation != resolution->key.generation ||
           java_remote_parent_finish_terminal_valid(
               resolution, terminal, lifecycle, observed_monotime_ns);
}

static __always_inline java_remote_parent_alias_replay_key_t
java_remote_parent_finish_alias_replay_key(const java_remote_parent_resolution_t *resolution) {
    return java_remote_parent_alias_replay_key(&resolution->key,
                                               resolution->observed_monotime_ns,
                                               resolution->indexed.process_incarnation);
}

static __noinline __attribute__((unused)) u8 java_remote_parent_finish_alias_replay_final_valid(
    const java_remote_parent_resolution_t *resolution,
    enum java_remote_parent_lifecycle lifecycle,
    const java_remote_parent_claim_t *owned_claim,
    const java_remote_parent_finish_guard_t *guard) {
    if (!guard || !guard->replay_required) {
        return guard != NULL;
    }
    const java_remote_parent_alias_replay_key_t replay_key =
        java_remote_parent_finish_alias_replay_key(resolution);
    const java_remote_parent_alias_replay_t *replay =
        bpf_map_lookup_elem(&java_remote_parent_alias_replays, &replay_key);
    return owned_claim && replay && !replay->producer_tag &&
           replay->transition_monotime_ns == owned_claim->observed_monotime_ns &&
           java_remote_parent_alias_replay_final_valid(&replay_key, replay, lifecycle);
}

typedef struct java_remote_parent_finish_barrier_options {
    u64 observed_monotime_ns;
    u32 lifecycle;
    u32 validate_final_replay;
} java_remote_parent_finish_barrier_options_t;

_Static_assert(sizeof(java_remote_parent_finish_barrier_options_t) == 16,
               "java remote-parent finish barrier options size mismatch");

static __always_inline u8 java_remote_parent_finish_terminal_authority_compact(
    const java_remote_parent_resolution_t *resolution,
    const java_remote_parent_terminal_t *terminal,
    enum java_remote_parent_lifecycle lifecycle,
    u64 observed_monotime_ns,
    const java_remote_parent_finish_guard_t *guard) {
    if (!terminal || !guard) {
        return 0;
    }
    const u64 terminal_tail = java_remote_parent_lifecycle_tail_word(&terminal->lifecycle);
    const u64 same_generation_mask =
        java_remote_parent_nonzero_bit(terminal->generation ^ resolution->key.generation) - 1;
    const u64 same_generation_mismatch =
        same_generation_mask &
        ((terminal->observed_monotime_ns ^ observed_monotime_ns) |
         (terminal->process_incarnation ^ resolution->indexed.process_incarnation) |
         (terminal_tail ^ (u64)lifecycle));
    volatile u64 mismatch = (1 ^ java_remote_parent_nonzero_bit(terminal->generation)) |
                            (1 ^ java_remote_parent_nonzero_bit(terminal->observed_monotime_ns)) |
                            (1 ^ java_remote_parent_nonzero_bit(terminal->process_incarnation)) |
                            (((terminal_tail - k_java_remote_parent_lifecycle_consumed) |
                              (k_java_remote_parent_lifecycle_ambiguous - terminal_tail)) >>
                             63) |
                            (1 ^ java_remote_parent_nonzero_bit(guard->terminal_generation)) |
                            (terminal->generation ^ guard->terminal_generation) |
                            same_generation_mismatch;
    return mismatch == 0;
}

static __noinline __attribute__((unused)) u8
java_remote_parent_finish_barrier_core(const java_remote_parent_resolution_t *resolution,
                                       const java_remote_parent_claim_t *owned_claim,
                                       const java_remote_parent_finish_guard_t *guard,
                                       const java_remote_parent_finish_barrier_options_t *options) {
    if (!options) {
        return 0;
    }
    const enum java_remote_parent_lifecycle lifecycle = (u8)options->lifecycle;
    const java_remote_parent_terminal_t *terminal =
        bpf_map_lookup_elem(&java_remote_parent_terminal, &resolution->key.owner);
    if (!java_remote_parent_finish_terminal_authority_compact(
            resolution, terminal, lifecycle, options->observed_monotime_ns, guard)) {
        return 0;
    }

    if (!java_remote_parent_finish_claim_shape_compact(resolution, owned_claim, lifecycle)) {
        return 0;
    }
    const java_remote_parent_claim_t *current_claim =
        bpf_map_lookup_elem(&java_remote_parent_claims, &resolution->key);
    if (!java_remote_parent_claim_equal_inline(current_claim, owned_claim) ||
        !java_remote_parent_finish_guard_shape_compact(resolution, guard)) {
        return 0;
    }
    const java_remote_parent_claim_t *current_guard =
        bpf_map_lookup_elem(&java_remote_parent_owner_guards, &guard->key.owner);
    if (!java_remote_parent_claim_equal_inline(current_guard, &guard->claim)) {
        return 0;
    }

    if (!options->validate_final_replay || !guard->replay_required) {
        return 1;
    }
    volatile u64 replay_key_mismatch =
        (1 ^ java_remote_parent_nonzero_bit(resolution->observed_monotime_ns)) |
        (1 ^ java_remote_parent_nonzero_bit(resolution->indexed.process_incarnation));
    if (replay_key_mismatch) {
        return 0;
    }
    const java_remote_parent_alias_replay_key_t replay_key =
        java_remote_parent_finish_alias_replay_key(resolution);
    const java_remote_parent_alias_replay_t *replay =
        bpf_map_lookup_elem(&java_remote_parent_alias_replays, &replay_key);
    if (!replay) {
        return 0;
    }
    volatile u64 replay_mismatch =
        (replay->transition_monotime_ns ^ owned_claim->observed_monotime_ns) |
        (java_remote_parent_metadata_word(&replay->lifecycle) ^ (u32)lifecycle);
    return replay_mismatch == 0;
}

static __noinline __attribute__((unused)) u8
java_remote_parent_finish_barriers_valid(const java_remote_parent_resolution_t *resolution,
                                         enum java_remote_parent_lifecycle lifecycle,
                                         u64 observed_monotime_ns,
                                         const java_remote_parent_claim_t *owned_claim,
                                         const java_remote_parent_finish_guard_t *guard) {
    const java_remote_parent_finish_barrier_options_t options = {
        .observed_monotime_ns = observed_monotime_ns,
        .lifecycle = lifecycle,
        .validate_final_replay = 1,
    };
    return java_remote_parent_finish_barrier_core(resolution, owned_claim, guard, &options);
}

typedef struct java_remote_parent_finish_connection {
    u64 netns_cookie;
    u64 incoming_generation;
    u64 socket_cookie;
    u32 netns;
    u32 reserved;
} java_remote_parent_finish_connection_t;

_Static_assert(sizeof(java_remote_parent_finish_connection_t) == 32,
               "java remote-parent finish connection size mismatch");

static __noinline __attribute__((unused)) u8 java_remote_parent_finish_connection_matches(
    const java_remote_parent_resolution_t *resolution,
    const java_remote_parent_connection_t *connection,
    const java_remote_parent_finish_connection_t *expected) {
    if (!connection) {
        return 0;
    }
    volatile u64 mismatch = connection->reserved | connection->reserved2 |
                            (connection->generation ^ resolution->key.generation) |
                            (connection->owner.tid ^ resolution->key.owner.tid) |
                            (connection->owner.pid ^ resolution->key.owner.pid) |
                            (connection->owner.ns ^ resolution->key.owner.ns) |
                            (connection->netns ^ expected->netns) |
                            (connection->netns_cookie ^ expected->netns_cookie) |
                            (connection->incoming_generation ^ expected->incoming_generation) |
                            (connection->socket_cookie ^ expected->socket_cookie);
    return mismatch == 0;
}

static __noinline __attribute__((unused)) u8
java_remote_parent_finish_acquire_guard(const java_remote_parent_resolution_t *resolution,
                                        enum java_remote_parent_lifecycle lifecycle,
                                        u64 observed_monotime_ns,
                                        const java_remote_parent_claim_t *owned_claim,
                                        java_remote_parent_finish_guard_t *guard) {
    if (!java_remote_parent_finish_claim_valid(resolution, owned_claim)) {
        return 0;
    }
    __builtin_memset(guard, 0, sizeof(*guard));
    guard->key.owner = resolution->key.owner;
    if (!java_remote_parent_acquire_detach_guard_at(&resolution->key, &guard->key, &guard->claim) ||
        !java_remote_parent_finish_authority_valid(resolution, owned_claim, guard)) {
        return 0;
    }

    const java_remote_parent_state_t *state =
        bpf_map_lookup_elem(&java_remote_parent_state, &resolution->key);
    if (!java_remote_parent_finish_state_valid(resolution, state, observed_monotime_ns)) {
        return 0;
    }
    const u64 state_process_incarnation = state->process_incarnation;
    const u8 state_has_aliases = state->aliases != 0;
    if (!java_remote_parent_generation_index_matches(
            &resolution->key, state_process_incarnation, observed_monotime_ns) ||
        !java_remote_parent_finish_reservation_valid(&resolution->key, lifecycle)) {
        return 0;
    }
    const java_remote_parent_alias_replay_key_t replay_key =
        java_remote_parent_finish_alias_replay_key(resolution);
    const java_remote_parent_alias_replay_t *replay =
        bpf_map_lookup_elem(&java_remote_parent_alias_replays, &replay_key);
    if (replay) {
        if (!java_remote_parent_alias_replay_active_valid(&replay_key, replay, 0)) {
            return 0;
        }
        guard->replay_required = 1;
    } else if (state_has_aliases || resolution->via_task) {
        return 0;
    }
    guard->physical_detached = java_remote_parent_generation_state_detached_for_incarnation(
        &resolution->key, resolution->indexed.process_incarnation);

    const java_remote_parent_owner_t *owner =
        bpf_map_lookup_elem(&java_remote_parent_owners, &resolution->key.owner);
    const u8 owner_has_generation = owner && owner->generation == resolution->key.generation;
    const u8 owns_generation = java_remote_parent_exact_receive_owner_matches(
        owner, &resolution->key, resolution->indexed.process_incarnation);
    if ((owner_has_generation && !owns_generation) ||
        (!owns_generation && !guard->physical_detached && !state_has_aliases) ||
        !java_remote_parent_finish_authority_valid(resolution, owned_claim, guard)) {
        return 0;
    }
    return 1;
}

static __noinline __attribute__((unused)) u8
java_remote_parent_finish_publish_terminal(const java_remote_parent_resolution_t *resolution,
                                           enum java_remote_parent_lifecycle lifecycle,
                                           u64 observed_monotime_ns,
                                           const java_remote_parent_claim_t *owned_claim,
                                           java_remote_parent_finish_guard_t *guard) {
    const java_remote_parent_state_t *state =
        bpf_map_lookup_elem(&java_remote_parent_state, &resolution->key);
    if (!java_remote_parent_finish_state_valid(resolution, state, observed_monotime_ns)) {
        return 0;
    }
    const u64 state_process_incarnation = state->process_incarnation;
    const u8 state_has_aliases = state->aliases != 0;
    if (!java_remote_parent_generation_index_matches(
            &resolution->key, state_process_incarnation, observed_monotime_ns) ||
        !java_remote_parent_finish_reservation_valid(&resolution->key, lifecycle) || !owned_claim ||
        owned_claim->lifecycle != lifecycle ||
        !java_remote_parent_finish_authority_valid(resolution, owned_claim, guard)) {
        return 0;
    }

    const java_remote_parent_owner_t *owner =
        bpf_map_lookup_elem(&java_remote_parent_owners, &resolution->key.owner);
    const u8 owner_has_generation = owner && owner->generation == resolution->key.generation;
    const u8 owns_generation = java_remote_parent_exact_receive_owner_matches(
        owner, &resolution->key, resolution->indexed.process_incarnation);
    if ((owner_has_generation && !owns_generation) ||
        (!owns_generation && !guard->physical_detached && !state_has_aliases) ||
        !java_remote_parent_finish_authority_valid(resolution, owned_claim, guard) ||
        !java_remote_parent_mark_exact_ambiguity(&resolution->key)) {
        return 0;
    }

    const java_remote_parent_terminal_t terminal = {
        .generation = resolution->key.generation,
        .observed_monotime_ns = observed_monotime_ns,
        .process_incarnation = resolution->indexed.process_incarnation,
        .lifecycle = lifecycle,
    };
    if (!java_remote_parent_finish_authority_valid(resolution, owned_claim, guard)) {
        return 0;
    }
    owner = bpf_map_lookup_elem(&java_remote_parent_owners, &resolution->key.owner);
    const u8 still_owns_generation = java_remote_parent_exact_receive_owner_matches(
        owner, &resolution->key, resolution->indexed.process_incarnation);
    if (still_owns_generation != owns_generation ||
        (owner && owner->generation == resolution->key.generation && !still_owns_generation)) {
        return 0;
    }

    const long updated = bpf_map_update_elem(&java_remote_parent_terminal,
                                             &resolution->key.owner,
                                             &terminal,
                                             owns_generation ? BPF_ANY : BPF_NOEXIST);
    const java_remote_parent_terminal_t *published =
        bpf_map_lookup_elem(&java_remote_parent_terminal, &resolution->key.owner);
    if (updated == 0) {
        guard->terminal_generation = resolution->key.generation;
    } else if (published && java_remote_parent_finish_terminal_valid(
                                resolution, published, lifecycle, observed_monotime_ns)) {
        guard->terminal_generation = resolution->key.generation;
    } else if (!owns_generation && java_remote_parent_finish_terminal_record_valid(published) &&
               published->generation != resolution->key.generation) {
        guard->terminal_generation = published->generation;
    } else {
        return 0;
    }
    const u8 terminal_valid = java_remote_parent_finish_terminal_matches_guard(
        resolution, published, lifecycle, observed_monotime_ns, guard);
    return terminal_valid &&
           java_remote_parent_finish_authority_valid(resolution, owned_claim, guard);
}

static __noinline __attribute__((unused)) u8 java_remote_parent_finish_pre_replay_barriers_valid(
    const java_remote_parent_resolution_t *resolution,
    enum java_remote_parent_lifecycle lifecycle,
    u64 observed_monotime_ns,
    const java_remote_parent_claim_t *owned_claim,
    const java_remote_parent_finish_guard_t *guard) {
    const java_remote_parent_finish_barrier_options_t options = {
        .observed_monotime_ns = observed_monotime_ns,
        .lifecycle = lifecycle,
    };
    return java_remote_parent_finish_barrier_core(resolution, owned_claim, guard, &options);
}

static __noinline __attribute__((unused)) u8
java_remote_parent_finish_publish_alias_replay(const java_remote_parent_resolution_t *resolution,
                                               enum java_remote_parent_lifecycle lifecycle,
                                               u64 observed_monotime_ns,
                                               const java_remote_parent_claim_t *owned_claim,
                                               const java_remote_parent_finish_guard_t *guard) {
    if (!guard || !guard->replay_required) {
        return java_remote_parent_finish_pre_replay_barriers_valid(
            resolution, lifecycle, observed_monotime_ns, owned_claim, guard);
    }
    if (!java_remote_parent_alias_replay_lifecycle_final(lifecycle) || !owned_claim ||
        !java_remote_parent_finish_pre_replay_barriers_valid(
            resolution, lifecycle, observed_monotime_ns, owned_claim, guard)) {
        return 0;
    }

    const java_remote_parent_alias_replay_key_t replay_key =
        java_remote_parent_finish_alias_replay_key(resolution);
    const java_remote_parent_alias_replay_t *replay =
        bpf_map_lookup_elem(&java_remote_parent_alias_replays, &replay_key);
    if (replay && !replay->producer_tag &&
        replay->transition_monotime_ns == owned_claim->observed_monotime_ns &&
        java_remote_parent_alias_replay_final_valid(&replay_key, replay, lifecycle)) {
        return 1;
    }

    if (java_remote_parent_alias_replay_active_valid(&replay_key, replay, 0)) {
        const u32 references = replay->references;
        const java_remote_parent_alias_replay_t publishing = {
            .transition_monotime_ns = owned_claim->observed_monotime_ns,
            .references = references,
            .lifecycle = k_java_remote_parent_lifecycle_publishing,
            .desired_lifecycle = lifecycle,
        };
        if (!java_remote_parent_finish_pre_replay_barriers_valid(
                resolution, lifecycle, observed_monotime_ns, owned_claim, guard) ||
            bpf_map_update_elem(
                &java_remote_parent_alias_replays, &replay_key, &publishing, BPF_EXIST) != 0) {
            return 0;
        }
        replay = bpf_map_lookup_elem(&java_remote_parent_alias_replays, &replay_key);
    }

    if (replay && !replay->producer_tag &&
        replay->transition_monotime_ns == owned_claim->observed_monotime_ns &&
        java_remote_parent_alias_replay_publishing_valid(&replay_key, replay, lifecycle)) {
        const u32 references = replay->references;
        const java_remote_parent_alias_replay_t completed = {
            .transition_monotime_ns = owned_claim->observed_monotime_ns,
            .references = references,
            .lifecycle = lifecycle,
        };
        if (!java_remote_parent_finish_pre_replay_barriers_valid(
                resolution, lifecycle, observed_monotime_ns, owned_claim, guard) ||
            bpf_map_update_elem(
                &java_remote_parent_alias_replays, &replay_key, &completed, BPF_EXIST) != 0) {
            return 0;
        }
    }
    return java_remote_parent_finish_alias_replay_final_valid(
               resolution, lifecycle, owned_claim, guard) &&
           java_remote_parent_finish_pre_replay_barriers_valid(
               resolution, lifecycle, observed_monotime_ns, owned_claim, guard);
}

static __noinline __attribute__((unused)) u8
java_remote_parent_finish_delete_physical(const java_remote_parent_resolution_t *resolution,
                                          const java_remote_parent_claim_t *owned_claim,
                                          u64 observed_monotime_ns,
                                          enum java_remote_parent_lifecycle lifecycle,
                                          const java_remote_parent_finish_guard_t *guard) {
    java_remote_parent_connection_key_t connection_key = {0};
    java_remote_parent_finish_connection_t published = {0};
    if (!java_remote_parent_finish_barriers_valid(
            resolution, lifecycle, observed_monotime_ns, owned_claim, guard)) {
        return 0;
    }
    const java_remote_parent_state_t *state =
        bpf_map_lookup_elem(&java_remote_parent_state, &resolution->key);
    if (!java_remote_parent_finish_state_valid(resolution, state, observed_monotime_ns) ||
        !java_remote_parent_connection_netns_key_init(
            &connection_key, &state->connection, state->connection_netns)) {
        return 0;
    }
    const u32 connection_netns = connection_key.netns.netns;
    const java_remote_parent_connection_t *netns_value =
        bpf_map_lookup_elem(&java_remote_parent_connections, &connection_key.netns);
    const u8 netns_has_generation =
        netns_value && netns_value->generation == resolution->key.generation &&
        java_remote_parent_pid_key_equal(&netns_value->owner, &resolution->key.owner);
    if (guard->physical_detached) {
        // Detached state no longer retains the network-namespace cookie, so
        // BPF cannot reconstruct and prove absence of the cookie-keyed index.
        // Keep every generation fence for userspace full-map convergence.
        return 0;
    }
    if (!netns_has_generation || (netns_value->reserved | netns_value->reserved2) ||
        netns_value->netns != connection_netns || !netns_value->netns_cookie ||
        !netns_value->incoming_generation || !netns_value->socket_cookie) {
        return 0;
    }
    published = (java_remote_parent_finish_connection_t){
        .netns_cookie = netns_value->netns_cookie,
        .incoming_generation = netns_value->incoming_generation,
        .socket_cookie = netns_value->socket_cookie,
        .netns = netns_value->netns,
    };

    if (!java_remote_parent_connection_key_rekey_cookie(&connection_key, published.netns_cookie)) {
        return 0;
    }
    const java_remote_parent_connection_t *cookie_value =
        bpf_map_lookup_elem(&java_remote_parent_cookie_connections, &connection_key.cookie);
    if (!java_remote_parent_finish_connection_matches(resolution, cookie_value, &published) ||
        !java_remote_parent_finish_barriers_valid(
            resolution, lifecycle, observed_monotime_ns, owned_claim, guard)) {
        return 0;
    }
    bpf_map_delete_elem(&java_remote_parent_cookie_connections, &connection_key.cookie);
    cookie_value =
        bpf_map_lookup_elem(&java_remote_parent_cookie_connections, &connection_key.cookie);
    if (cookie_value && cookie_value->generation == resolution->key.generation &&
        java_remote_parent_pid_key_equal(&cookie_value->owner, &resolution->key.owner)) {
        return 0;
    }

    if (!java_remote_parent_connection_key_rekey_netns(&connection_key, published.netns)) {
        return 0;
    }
    netns_value = bpf_map_lookup_elem(&java_remote_parent_connections, &connection_key.netns);
    if (!java_remote_parent_finish_connection_matches(resolution, netns_value, &published) ||
        !java_remote_parent_finish_barriers_valid(
            resolution, lifecycle, observed_monotime_ns, owned_claim, guard)) {
        return 0;
    }
    bpf_map_delete_elem(&java_remote_parent_connections, &connection_key.netns);
    netns_value = bpf_map_lookup_elem(&java_remote_parent_connections, &connection_key.netns);
    if (netns_value && netns_value->generation == resolution->key.generation &&
        java_remote_parent_pid_key_equal(&netns_value->owner, &resolution->key.owner)) {
        return 0;
    }

    if (!java_remote_parent_connection_key_rekey_cookie(&connection_key, published.netns_cookie)) {
        return 0;
    }
    cookie_value =
        bpf_map_lookup_elem(&java_remote_parent_cookie_connections, &connection_key.cookie);
    const u8 cookie_absent =
        !cookie_value || cookie_value->generation != resolution->key.generation ||
        !java_remote_parent_pid_key_equal(&cookie_value->owner, &resolution->key.owner);
    return cookie_absent && java_remote_parent_finish_barriers_valid(
                                resolution, lifecycle, observed_monotime_ns, owned_claim, guard);
}

static __noinline __attribute__((unused)) u8
java_remote_parent_finish_delete_logical(const java_remote_parent_resolution_t *resolution,
                                         enum java_remote_parent_lifecycle lifecycle,
                                         u64 observed_monotime_ns,
                                         const java_remote_parent_claim_t *owned_claim,
                                         const java_remote_parent_finish_guard_t *guard) {
    if (!java_remote_parent_finish_barriers_valid(
            resolution, lifecycle, observed_monotime_ns, owned_claim, guard)) {
        return 0;
    }

    const java_remote_parent_state_t *state =
        bpf_map_lookup_elem(&java_remote_parent_state, &resolution->key);
    if (state) {
        if (!java_remote_parent_finish_state_valid(resolution, state, observed_monotime_ns) ||
            !java_remote_parent_finish_barriers_valid(
                resolution, lifecycle, observed_monotime_ns, owned_claim, guard)) {
            return 0;
        }
        bpf_map_delete_elem(&java_remote_parent_state, &resolution->key);
    }
    if (bpf_map_lookup_elem(&java_remote_parent_state, &resolution->key)) {
        return 0;
    }

    const java_remote_parent_response_t *fallback =
        bpf_map_lookup_elem(&java_remote_parent_fallback, &resolution->key.owner);
    const u8 fallback_has_generation =
        fallback &&
        java_remote_parent_le64_to_cpu(fallback->generation_le) == resolution->key.generation;
    if (fallback_has_generation) {
        if (!java_remote_parent_exact_receive_fallback_matches(fallback, &resolution->key) ||
            !java_remote_parent_finish_barriers_valid(
                resolution, lifecycle, observed_monotime_ns, owned_claim, guard)) {
            return 0;
        }
        bpf_map_delete_elem(&java_remote_parent_fallback, &resolution->key.owner);
    }
    if (java_remote_parent_fallback_has_generation(&resolution->key.owner,
                                                   resolution->key.generation)) {
        return 0;
    }

    if (bpf_map_lookup_elem(&java_remote_parent_generation_index, &resolution->key)) {
        if (!java_remote_parent_generation_index_matches(
                &resolution->key, resolution->indexed.process_incarnation, observed_monotime_ns) ||
            !java_remote_parent_finish_barriers_valid(
                resolution, lifecycle, observed_monotime_ns, owned_claim, guard)) {
            return 0;
        }
        bpf_map_delete_elem(&java_remote_parent_generation_index, &resolution->key);
    }
    if (bpf_map_lookup_elem(&java_remote_parent_generation_index, &resolution->key)) {
        return 0;
    }

    const java_remote_parent_owner_t *owner =
        bpf_map_lookup_elem(&java_remote_parent_owners, &resolution->key.owner);
    const u8 owner_has_generation = owner && owner->generation == resolution->key.generation;
    if (owner_has_generation) {
        if (!java_remote_parent_exact_receive_owner_matches(
                owner, &resolution->key, resolution->indexed.process_incarnation) ||
            !java_remote_parent_finish_barriers_valid(
                resolution, lifecycle, observed_monotime_ns, owned_claim, guard)) {
            return 0;
        }
        bpf_map_delete_elem(&java_remote_parent_owners, &resolution->key.owner);
    }

    owner = bpf_map_lookup_elem(&java_remote_parent_owners, &resolution->key.owner);
    const u8 owner_absent = !owner || owner->generation != resolution->key.generation;
    if (!owner_absent || bpf_map_lookup_elem(&java_remote_parent_state, &resolution->key) ||
        bpf_map_lookup_elem(&java_remote_parent_generation_index, &resolution->key) ||
        java_remote_parent_fallback_has_generation(&resolution->key.owner,
                                                   resolution->key.generation)) {
        return 0;
    }
    return java_remote_parent_finish_barriers_valid(
        resolution, lifecycle, observed_monotime_ns, owned_claim, guard);
}

static __noinline __attribute__((unused)) u8
java_remote_parent_finish_release_claim(const java_remote_parent_resolution_t *resolution,
                                        enum java_remote_parent_lifecycle lifecycle,
                                        u64 observed_monotime_ns,
                                        java_remote_parent_claim_t *owned_claim,
                                        java_remote_parent_finish_guard_t *guard) {
    if (!java_remote_parent_finish_barriers_valid(
            resolution, lifecycle, observed_monotime_ns, owned_claim, guard)) {
        return 0;
    }
    const java_remote_parent_owner_t *owner =
        bpf_map_lookup_elem(&java_remote_parent_owners, &resolution->key.owner);
    const u8 owner_absent = !owner || owner->generation != resolution->key.generation;
    if (!owner_absent || bpf_map_lookup_elem(&java_remote_parent_state, &resolution->key) ||
        bpf_map_lookup_elem(&java_remote_parent_generation_index, &resolution->key) ||
        java_remote_parent_fallback_has_generation(&resolution->key.owner,
                                                   resolution->key.generation)) {
        return 0;
    }
    const u64 *ambiguity = bpf_map_lookup_elem(&java_remote_parent_ambiguity, &resolution->key);
    const u8 ambiguity_marked = ambiguity && *ambiguity;
    if (!ambiguity_marked || !java_remote_parent_finish_barriers_valid(
                                 resolution, lifecycle, observed_monotime_ns, owned_claim, guard)) {
        return 0;
    }
    // The sibling physical phase proved both indexes absent while this exact
    // invocation-local claim and owner guard excluded every legitimate writer.
    // Release the nonzero reservation, exact claim, and owner guard in order;
    // no destructive operation follows any fence release.
    bpf_map_delete_elem(&java_remote_parent_ambiguity, &resolution->key);
    if (!java_remote_parent_generation_ambiguity_absent(&resolution->key)) {
        // FINISH payload is complete. Preserve whichever marker survived the
        // retirement attempt and never re-mark a possibly reused generation.
        return 1;
    }
    const u64 replay_transition_monotime_ns = owned_claim->observed_monotime_ns;
    java_remote_parent_release_exact_receive_claim(&resolution->key, owned_claim);
    if (!bpf_map_lookup_elem(&java_remote_parent_claims, &resolution->key) &&
        java_remote_parent_generation_ambiguity_absent(&resolution->key)) {
        if (guard->replay_required) {
            const java_remote_parent_alias_replay_key_t replay_key =
                java_remote_parent_finish_alias_replay_key(resolution);
            const java_remote_parent_alias_replay_t *replay =
                bpf_map_lookup_elem(&java_remote_parent_alias_replays, &replay_key);
            if (replay && !replay->references && !replay->producer_tag &&
                replay->transition_monotime_ns == replay_transition_monotime_ns &&
                java_remote_parent_alias_replay_final_valid(&replay_key, replay, lifecycle)) {
                bpf_map_delete_elem(&java_remote_parent_alias_replays, &replay_key);
            }
        }
        java_remote_parent_release_exact_detach_guard_at(&guard->key, &guard->claim);
    }
    // Exact guard deletion is the linearization point. A successor may reuse
    // the owner and generation keys immediately afterward, so no old-G
    // postcheck or cleanup-failed marker is valid beyond this point.
    return 1;
}

static __noinline __attribute__((unused)) void
java_remote_parent_finish_generation_with_guard(const java_remote_parent_resolution_t *resolution,
                                                enum java_remote_parent_lifecycle lifecycle,
                                                u64 observed_monotime_ns,
                                                java_remote_parent_claim_t *owned_claim,
                                                java_remote_parent_finish_guard_t *guard) {
    __builtin_memset(guard, 0, sizeof(*guard));
    if (!owned_claim ||
        !java_remote_parent_finish_acquire_guard(
            resolution, lifecycle, observed_monotime_ns, owned_claim, guard) ||
        !java_remote_parent_finish_publish_terminal(
            resolution, lifecycle, observed_monotime_ns, owned_claim, guard) ||
        !java_remote_parent_finish_publish_alias_replay(
            resolution, lifecycle, observed_monotime_ns, owned_claim, guard) ||
        !java_remote_parent_finish_delete_physical(
            resolution, owned_claim, observed_monotime_ns, lifecycle, guard) ||
        !java_remote_parent_finish_delete_logical(
            resolution, lifecycle, observed_monotime_ns, owned_claim, guard) ||
        !java_remote_parent_finish_release_claim(
            resolution, lifecycle, observed_monotime_ns, owned_claim, guard)) {
        if (owned_claim) {
            java_remote_parent_mark_exact_receive_cleanup_failed(&resolution->key, owned_claim);
        }
    }
    // Payload work is over on both success and failure. Convert only exact
    // surviving invocation-local fences; fully released fences stay absent.
    java_remote_parent_handoff_exact_fence_pair(
        &resolution->key, owned_claim, &guard->key, &guard->claim);
}

static __noinline __attribute__((unused)) void
java_remote_parent_finish_generation(const java_remote_parent_resolution_t *resolution,
                                     enum java_remote_parent_lifecycle lifecycle,
                                     u64 observed_monotime_ns,
                                     java_remote_parent_claim_t *owned_claim) {
    java_remote_parent_finish_guard_t guard = {0};
    java_remote_parent_finish_generation_with_guard(
        resolution, lifecycle, observed_monotime_ns, owned_claim, &guard);
}

static __noinline __attribute__((unused)) enum java_remote_parent_status
java_remote_parent_claim_status(const java_remote_parent_resolution_t *resolution,
                                const java_remote_parent_claim_t *claimed) {
    if (!claimed || !claimed->observed_monotime_ns ||
        claimed->process_incarnation != resolution->indexed.process_incarnation) {
        return k_java_remote_parent_status_ambiguous;
    }
    const u64 tail = java_remote_parent_lifecycle_tail_word(&claimed->lifecycle);
    const u8 lifecycle = tail;
    const u8 desired_lifecycle = tail >> 8;
    const u8 producer_tag = tail >> 56;
    const u64 reserved_middle = (tail >> 16) & 0xffffffffffULL;
    if (reserved_middle) {
        return k_java_remote_parent_status_ambiguous;
    }

    if (lifecycle == k_java_remote_parent_lifecycle_publishing) {
        const u8 publishing_intent =
            java_remote_parent_alias_replay_lifecycle_final(desired_lifecycle) &&
            (!producer_tag || producer_tag == k_java_remote_parent_go_producer_tag);
        return (!desired_lifecycle && !producer_tag) || publishing_intent
                   ? k_java_remote_parent_status_overload
                   : k_java_remote_parent_status_ambiguous;
    }

    if (lifecycle == k_java_remote_parent_lifecycle_cleanup) {
        if (producer_tag) {
            return k_java_remote_parent_status_ambiguous;
        }
        if (desired_lifecycle == k_java_remote_parent_lifecycle_publishing) {
            return k_java_remote_parent_status_overload;
        }
        return desired_lifecycle >= k_java_remote_parent_lifecycle_consumed &&
                       desired_lifecycle <= k_java_remote_parent_lifecycle_stale
                   ? k_java_remote_parent_status_already_consumed
                   : k_java_remote_parent_status_ambiguous;
    }

    if (desired_lifecycle ||
        (producer_tag && producer_tag != k_java_remote_parent_go_producer_tag)) {
        return k_java_remote_parent_status_ambiguous;
    }
    return lifecycle >= k_java_remote_parent_lifecycle_consumed &&
                   lifecycle <= k_java_remote_parent_lifecycle_stale
               ? k_java_remote_parent_status_already_consumed
               : k_java_remote_parent_status_ambiguous;
}

static __noinline __attribute__((unused)) u8 java_remote_parent_retrieval_task_link_matches(
    const java_remote_parent_resolution_t *resolution, const pid_key_t *execution);
static __noinline __attribute__((unused)) u8
java_remote_parent_retrieval_connection_matches(const java_remote_parent_resolution_t *resolution,
                                                const java_remote_parent_state_t *state,
                                                const connection_info_t *expected_connection,
                                                u32 expected_connection_netns,
                                                u64 expected_socket_cookie);

typedef struct java_remote_parent_claim_options {
    u64 expected_socket_cookie;
    u64 max_age_ns;
    u32 expected_connection_netns;
    u32 desired_lifecycle;
} java_remote_parent_claim_options_t;

_Static_assert(sizeof(java_remote_parent_claim_options_t) == 24,
               "java remote-parent claim options size mismatch");

typedef struct java_remote_parent_retrieval_workspace {
    java_remote_parent_resolution_t resolution;
    java_remote_parent_claim_t owned_claim;
    java_remote_parent_claim_options_t claim_options;
    pid_key_t start;
    u8 claim_found;
    u8 raced_claim_found;
    u16 reserved;
    java_remote_parent_finish_guard_t finish_guard;
    java_remote_parent_task_t task;
} java_remote_parent_retrieval_workspace_t;

_Static_assert(sizeof(java_remote_parent_retrieval_workspace_t) == 224,
               "java remote-parent retrieval workspace size mismatch");
_Static_assert(__builtin_offsetof(java_remote_parent_retrieval_workspace_t, resolution) == 0,
               "java remote-parent retrieval resolution offset mismatch");
_Static_assert(__builtin_offsetof(java_remote_parent_retrieval_workspace_t, owned_claim) == 64,
               "java remote-parent retrieval claim offset mismatch");
_Static_assert(__builtin_offsetof(java_remote_parent_retrieval_workspace_t, claim_options) == 88,
               "java remote-parent retrieval options offset mismatch");
_Static_assert(__builtin_offsetof(java_remote_parent_retrieval_workspace_t, start) == 112,
               "java remote-parent retrieval start offset mismatch");
_Static_assert(__builtin_offsetof(java_remote_parent_retrieval_workspace_t, claim_found) == 124,
               "java remote-parent retrieval claim-found offset mismatch");
_Static_assert(__builtin_offsetof(java_remote_parent_retrieval_workspace_t, raced_claim_found) ==
                   125,
               "java remote-parent retrieval raced-claim offset mismatch");
_Static_assert(__builtin_offsetof(java_remote_parent_retrieval_workspace_t, finish_guard) == 128,
               "java remote-parent retrieval finish-guard offset mismatch");
_Static_assert(__builtin_offsetof(java_remote_parent_retrieval_workspace_t, task) == 192,
               "java remote-parent retrieval task offset mismatch");

static __noinline __attribute__((unused)) enum java_remote_parent_status
java_remote_parent_claim(const java_remote_parent_resolution_t *resolution,
                         const pid_key_t *execution,
                         const connection_info_t *expected_connection,
                         const java_remote_parent_claim_options_t *options,
                         java_remote_parent_claim_t *owned_claim) {
    if (!owned_claim || !options) {
        return k_java_remote_parent_status_overload;
    }
    __builtin_memset(owned_claim, 0, sizeof(*owned_claim));
    const enum java_remote_parent_lifecycle desired_lifecycle = options->desired_lifecycle;
    const u32 expected_connection_netns = options->expected_connection_netns;
    const u64 expected_socket_cookie = options->expected_socket_cookie;
    const u64 max_age_ns = options->max_age_ns;
    if (!java_remote_parent_alias_replay_lifecycle_final(desired_lifecycle)) {
        return k_java_remote_parent_status_ambiguous;
    }
    // RESET owns the exact physical receive transition while this guard is
    // present. A claimant that won before the guard remains authoritative;
    // callers arriving after it must retry/fail open rather than enter the
    // local-claim-release to guard-release window.
    if (java_remote_parent_owner_detach_guarded(&resolution->key.owner)) {
        return k_java_remote_parent_status_overload;
    }
    const java_remote_parent_state_t *preclaim_state =
        bpf_map_lookup_elem(&java_remote_parent_state, &resolution->key);
    const u8 carrier_requires_replay =
        resolution->via_task || (preclaim_state && preclaim_state->aliases);
    const java_remote_parent_alias_replay_key_t replay_key =
        java_remote_parent_finish_alias_replay_key(resolution);
    const java_remote_parent_alias_replay_t *preclaim_replay =
        bpf_map_lookup_elem(&java_remote_parent_alias_replays, &replay_key);
    const u8 replay_required = carrier_requires_replay || preclaim_replay;
    if (replay_required && !java_remote_parent_alias_replay_active_valid(
                               &replay_key, preclaim_replay, carrier_requires_replay)) {
        // Alias replay has its own bounded pool. Missing/capacity-conflicted
        // authority rejects the claim before E is inserted.
        return k_java_remote_parent_status_overload;
    }
    const java_remote_parent_claim_t publishing_claim = {
        .observed_monotime_ns = bpf_ktime_get_ns(),
        .process_incarnation = resolution->indexed.process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_publishing,
        .reserved = {desired_lifecycle},
    };
    if (!publishing_claim.observed_monotime_ns) {
        return k_java_remote_parent_status_overload;
    }
    if (bpf_map_update_elem(
            &java_remote_parent_claims, &resolution->key, &publishing_claim, BPF_NOEXIST) == 0) {
        if (java_remote_parent_owner_detach_guarded(&resolution->key.owner)) {
            java_remote_parent_claim_t rollback = publishing_claim;
            java_remote_parent_release_exact_receive_claim(&resolution->key, &rollback);
            return k_java_remote_parent_status_overload;
        }
        // E is still a nonterminal intent. Revalidate every delivery binding
        // before its one-shot semantic promotion.
        const java_remote_parent_state_t *state =
            bpf_map_lookup_elem(&java_remote_parent_state, &resolution->key);
        const java_remote_parent_alias_replay_t *replay =
            bpf_map_lookup_elem(&java_remote_parent_alias_replays, &replay_key);
        const u8 replay_still_required =
            replay_required || resolution->via_task || (state && state->aliases);
        const u8 replay_has_carrier = resolution->via_task || (state && state->aliases);
        if (state && state->lifecycle == k_java_remote_parent_lifecycle_active &&
            state->process_incarnation == resolution->indexed.process_incarnation &&
            state->observed_monotime_ns == resolution->observed_monotime_ns &&
            state->response.status == k_java_remote_parent_status_valid &&
            java_remote_parent_le64_to_cpu(state->response.generation_le) ==
                resolution->key.generation &&
            java_remote_parent_le64_to_cpu(state->response.observed_monotime_ns_le) ==
                resolution->observed_monotime_ns &&
            java_remote_parent_generation_index_matches(
                &resolution->key, state->process_incarnation, resolution->observed_monotime_ns) &&
            java_remote_parent_finish_reservation_valid(&resolution->key, desired_lifecycle) &&
            (!replay_still_required || java_remote_parent_alias_replay_active_valid(
                                           &replay_key, replay, replay_has_carrier)) &&
            (!resolution->via_task ||
             java_remote_parent_retrieval_task_link_matches(resolution, execution)) &&
            java_remote_parent_retrieval_connection_matches(resolution,
                                                            state,
                                                            expected_connection,
                                                            expected_connection_netns,
                                                            expected_socket_cookie)) {
            enum java_remote_parent_lifecycle commit_lifecycle = desired_lifecycle;
            if ((commit_lifecycle == k_java_remote_parent_lifecycle_consumed ||
                 commit_lifecycle == k_java_remote_parent_lifecycle_discarded) &&
                java_remote_parent_observation_stale(
                    bpf_ktime_get_ns(), state->observed_monotime_ns, max_age_ns)) {
                commit_lifecycle = k_java_remote_parent_lifecycle_stale;
            }
            const java_remote_parent_claim_t completed_claim = {
                .observed_monotime_ns = publishing_claim.observed_monotime_ns,
                .process_incarnation = publishing_claim.process_incarnation,
                .lifecycle = commit_lifecycle,
            };
            // This BPF_EXIST update is the one-shot semantic linearization
            // point. Any uncertainty after it is committed uncertainty and
            // must retain exact fences rather than rolling the outcome back.
            *owned_claim = completed_claim;
            const long promoted = bpf_map_update_elem(
                &java_remote_parent_claims, &resolution->key, &completed_claim, BPF_EXIST);
            const java_remote_parent_claim_t *published =
                bpf_map_lookup_elem(&java_remote_parent_claims, &resolution->key);
            if (java_remote_parent_claim_equal(published, &completed_claim)) {
                return k_java_remote_parent_status_valid;
            }
            if (promoted == 0) {
                java_remote_parent_mark_exact_receive_cleanup_failed(&resolution->key,
                                                                     &completed_claim);
                return k_java_remote_parent_status_overload;
            }
            const java_remote_parent_claim_t *intent =
                bpf_map_lookup_elem(&java_remote_parent_claims, &resolution->key);
            if (java_remote_parent_claim_equal(intent, &publishing_claim)) {
                java_remote_parent_claim_t rollback = publishing_claim;
                java_remote_parent_release_exact_receive_claim(&resolution->key, &rollback);
                java_remote_parent_ensure_exact_ambiguity(&resolution->key);
                __builtin_memset(owned_claim, 0, sizeof(*owned_claim));
                return k_java_remote_parent_status_overload;
            }
            java_remote_parent_mark_exact_receive_cleanup_failed(&resolution->key,
                                                                 &completed_claim);
            return k_java_remote_parent_status_ambiguous;
        }
        java_remote_parent_claim_t rollback = publishing_claim;
        java_remote_parent_release_exact_receive_claim(&resolution->key, &rollback);
        java_remote_parent_ensure_exact_ambiguity(&resolution->key);
        return k_java_remote_parent_status_missing;
    }

    const java_remote_parent_claim_t *claimed =
        bpf_map_lookup_elem(&java_remote_parent_claims, &resolution->key);
    if (claimed) {
        return java_remote_parent_claim_status(resolution, claimed);
    }
    return k_java_remote_parent_status_overload;
}

static __noinline __attribute__((unused)) enum java_remote_parent_status
java_remote_parent_existing_claim_status(const java_remote_parent_resolution_t *resolution,
                                         u8 *found) {
    *found = 0;
    const java_remote_parent_claim_t *claimed =
        bpf_map_lookup_elem(&java_remote_parent_claims, &resolution->key);
    if (!claimed) {
        return k_java_remote_parent_status_ambiguous;
    }
    *found = 1;
    return java_remote_parent_claim_status(resolution, claimed);
}

static __noinline __attribute__((unused)) u8 java_remote_parent_retrieval_state_metadata_matches(
    const java_remote_parent_resolution_t *resolution, const java_remote_parent_state_t *state) {
    return state && resolution->observed_monotime_ns && state->process_incarnation &&
           state->process_incarnation == resolution->indexed.process_incarnation &&
           java_remote_parent_metadata_word(&state->lifecycle) ==
               k_java_remote_parent_lifecycle_active &&
           state->observed_monotime_ns == resolution->observed_monotime_ns &&
           state->response.status == k_java_remote_parent_status_valid &&
           java_remote_parent_le64_to_cpu(state->response.generation_le) ==
               resolution->key.generation &&
           java_remote_parent_le64_to_cpu(state->response.observed_monotime_ns_le) ==
               resolution->observed_monotime_ns;
}

static __noinline __attribute__((unused)) u8 java_remote_parent_retrieval_task_link_matches(
    const java_remote_parent_resolution_t *resolution, const pid_key_t *execution) {
    if (!resolution->via_task) {
        return 0;
    }
    const java_remote_parent_task_t *linked =
        bpf_map_lookup_elem(&java_remote_parent_tasks, execution);
    return linked && !linked->reserved &&
           java_remote_parent_pid_key_equal(&linked->owner, &resolution->key.owner) &&
           linked->generation == resolution->key.generation &&
           linked->observed_monotime_ns == resolution->observed_monotime_ns;
}

static __noinline __attribute__((unused)) u8 java_remote_parent_retrieval_alias_replay_matches(
    const java_remote_parent_resolution_t *resolution) {
    if (!resolution->via_replay) {
        return 0;
    }
    const java_remote_parent_alias_replay_key_t replay_key =
        java_remote_parent_finish_alias_replay_key(resolution);
    const java_remote_parent_alias_replay_t *replay =
        bpf_map_lookup_elem(&java_remote_parent_alias_replays, &replay_key);
    if (!replay || !replay->references) {
        return 0;
    }
    if (java_remote_parent_alias_replay_final_valid(
            &replay_key, replay, resolution->indexed.lifecycle)) {
        return 1;
    }
    const u8 transitioning = java_remote_parent_alias_replay_active_valid(&replay_key, replay, 1) ||
                             java_remote_parent_alias_replay_publishing_valid(
                                 &replay_key, replay, replay->desired_lifecycle);
    return transitioning && bpf_map_lookup_elem(&java_remote_parent_claims, &resolution->key);
}

static __noinline __attribute__((unused)) u8
java_remote_parent_retrieval_socket_not_rebound(const java_remote_parent_resolution_t *resolution,
                                                const connection_info_t *expected_connection,
                                                u32 expected_connection_netns,
                                                u64 expected_socket_cookie) {
    if (!expected_connection) {
        return 1;
    }
    if (!expected_socket_cookie) {
        return 0;
    }
    java_remote_parent_connection_key_t connection_key = {0};
    if (!java_remote_parent_connection_netns_key_init(
            &connection_key, expected_connection, expected_connection_netns)) {
        return 0;
    }
    const java_remote_parent_connection_t *current =
        bpf_map_lookup_elem(&java_remote_parent_connections, &connection_key.netns);
    if (!current) {
        return 1;
    }
    // The sockopt caller has already bound expected_socket_cookie to its
    // socket-local negotiation. Once a successor replaces the singleton
    // cursor, reject that successor's cookie without requiring the old
    // physical index to outlive its completed one-shot claim.
    const u8 exact_generation =
        current->generation == resolution->key.generation &&
        java_remote_parent_pid_key_equal(&current->owner, &resolution->key.owner);
    return !((exact_generation && current->socket_cookie != expected_socket_cookie) ||
             (!exact_generation && current->socket_cookie == expected_socket_cookie));
}

static __always_inline u8 java_remote_parent_retrieval_claim_binding_matches(
    const java_remote_parent_resolution_t *resolution,
    const pid_key_t *execution,
    const java_remote_parent_state_t *state,
    const connection_info_t *expected_connection,
    u32 expected_connection_netns,
    u64 expected_socket_cookie) {
    if (!expected_socket_cookie || !state || !state->aliases ||
        !java_remote_parent_retrieval_state_metadata_matches(resolution, state) ||
        state->connection_netns != expected_connection_netns ||
        __builtin_memcmp(&state->connection, expected_connection, sizeof(*expected_connection)) !=
            0 ||
        !java_remote_parent_generation_index_matches(
            &resolution->key, state->process_incarnation, state->observed_monotime_ns) ||
        !java_remote_parent_retrieval_socket_not_rebound(
            resolution, expected_connection, expected_connection_netns, expected_socket_cookie)) {
        return 0;
    }
    return java_remote_parent_retrieval_task_link_matches(resolution, execution);
}

static __always_inline u8 java_remote_parent_retrieval_claim_terminal_matches(
    const java_remote_parent_resolution_t *resolution,
    const pid_key_t *execution,
    const java_remote_parent_state_t *state,
    const connection_info_t *expected_connection,
    u32 expected_connection_netns,
    u64 expected_socket_cookie) {
    const java_remote_parent_terminal_t *terminal =
        bpf_map_lookup_elem(&java_remote_parent_terminal, &resolution->key.owner);
    if (!java_remote_parent_finish_terminal_record_valid(terminal) ||
        terminal->generation != resolution->key.generation ||
        terminal->observed_monotime_ns != resolution->observed_monotime_ns ||
        terminal->process_incarnation != resolution->indexed.process_incarnation) {
        return 0;
    }
    // A completed finish can remove every connection artifact before a
    // compare-delete failure retains its exact claim. The cgroup sockopt caller
    // has already revalidated its socket-local negotiation, so the exact
    // terminal remains the durable binding for this status-only replay. Task
    // provenance additionally requires the exact task link to remain bound.
    return !resolution->via_task ||
           (!state && (java_remote_parent_retrieval_task_link_matches(resolution, execution) &&
                       java_remote_parent_retrieval_socket_not_rebound(resolution,
                                                                       expected_connection,
                                                                       expected_connection_netns,
                                                                       expected_socket_cookie)));
}

static __always_inline u8 java_remote_parent_retrieval_alias_replay_binding_matches(
    const java_remote_parent_resolution_t *resolution,
    const pid_key_t *execution,
    const connection_info_t *expected_connection,
    u32 expected_connection_netns,
    u64 expected_generation,
    u64 expected_socket_cookie) {
    return resolution->via_replay && expected_generation == resolution->key.generation &&
           java_remote_parent_retrieval_task_link_matches(resolution, execution) &&
           java_remote_parent_retrieval_alias_replay_matches(resolution) &&
           java_remote_parent_retrieval_socket_not_rebound(
               resolution, expected_connection, expected_connection_netns, expected_socket_cookie);
}

static __noinline __attribute__((unused)) u8
java_remote_parent_retrieval_connection_matches(const java_remote_parent_resolution_t *resolution,
                                                const java_remote_parent_state_t *state,
                                                const connection_info_t *expected_connection,
                                                u32 expected_connection_netns,
                                                u64 expected_socket_cookie) {
    if (!java_remote_parent_retrieval_state_metadata_matches(resolution, state)) {
        return 0;
    }
    const u8 detached_task =
        resolution->via_task && java_remote_parent_generation_state_detached_for_incarnation(
                                    &resolution->key, state->process_incarnation);
    if (expected_connection) {
        if (!expected_socket_cookie || state->connection_netns != expected_connection_netns ||
            __builtin_memcmp(
                &state->connection, expected_connection, sizeof(*expected_connection)) != 0) {
            return 0;
        }
        return detached_task ||
               java_remote_parent_connection_matches_socket_in_netns(expected_connection,
                                                                     expected_connection_netns,
                                                                     &resolution->key.owner,
                                                                     resolution->key.generation,
                                                                     0,
                                                                     expected_socket_cookie);
    }
    return detached_task ||
           java_remote_parent_connection_matches_in_netns(&state->connection,
                                                          state->connection_netns,
                                                          &resolution->key.owner,
                                                          resolution->key.generation,
                                                          0,
                                                          0);
}

static __always_inline enum java_remote_parent_status
java_remote_parent_retrieve_for_connection_with_workspace(
    java_remote_parent_response_t *response,
    u8 discard,
    u64 max_age_ns,
    enum java_remote_parent_source source,
    const connection_info_t *expected_connection,
    u32 expected_connection_netns,
    u64 expected_generation,
    u64 expected_socket_cookie,
    java_remote_parent_retrieval_workspace_t *workspace) {
    __builtin_memset(workspace, 0, sizeof(*workspace));
    pid_key_t *start = &workspace->start;
    *start = java_remote_parent_current_owner();
    java_remote_parent_resolution_t *resolution = &workspace->resolution;
    java_remote_parent_finish_guard_t *finish_guard = &workspace->finish_guard;
    if (source == k_java_remote_parent_source_direct) {
        java_remote_parent_resolve_exact(resolution, start, 0, 1);
    } else if (source == k_java_remote_parent_source_task) {
        java_remote_parent_resolve_task_into(resolution, start, max_age_ns, &workspace->task);
    } else {
        java_remote_parent_init_response(response, k_java_remote_parent_status_malformed, 0, 0);
        java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_malformed);
        return k_java_remote_parent_status_malformed;
    }

    if (expected_connection && !expected_socket_cookie) {
        java_remote_parent_init_response(response, k_java_remote_parent_status_missing, 0, 0);
        java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_missing);
        return k_java_remote_parent_status_missing;
    }
    if (expected_connection && resolution->found && expected_generation &&
        resolution->key.generation != expected_generation) {
        java_remote_parent_init_response(
            response, k_java_remote_parent_status_missing, resolution->key.generation, 0);
        java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_missing);
        return k_java_remote_parent_status_missing;
    }
    if (resolution->found && resolution->via_task &&
        !java_remote_parent_retrieval_task_link_matches(resolution, start)) {
        java_remote_parent_init_response(
            response, k_java_remote_parent_status_ambiguous, resolution->key.generation, 0);
        java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_ambiguous);
        return k_java_remote_parent_status_ambiguous;
    }
    if (resolution->found && resolution->via_replay &&
        !java_remote_parent_retrieval_alias_replay_matches(resolution)) {
        java_remote_parent_init_response(
            response, k_java_remote_parent_status_ambiguous, resolution->key.generation, 0);
        java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_ambiguous);
        return k_java_remote_parent_status_ambiguous;
    }
    u8 *claim_found = &workspace->claim_found;
    enum java_remote_parent_status existing_claim_status = k_java_remote_parent_status_ambiguous;
    if (resolution->found && (resolution->ambiguous || resolution->indexed.lifecycle !=
                                                           k_java_remote_parent_lifecycle_active)) {
        existing_claim_status = java_remote_parent_existing_claim_status(resolution, claim_found);
        // Ordered fence retirement can leave exact E after M is gone. Make any
        // exact claim the classification authority before connection binding:
        // final claims replay their terminal outcome, publishing claims
        // overload, and malformed claims fail closed as ambiguous.
        if (*claim_found) {
            resolution->ambiguous = 1;
        }
    }
    if (expected_connection && resolution->found) {
        const java_remote_parent_state_t *bound_state =
            bpf_map_lookup_elem(&java_remote_parent_state, &resolution->key);
        if (!java_remote_parent_retrieval_connection_matches(resolution,
                                                             bound_state,
                                                             expected_connection,
                                                             expected_connection_netns,
                                                             expected_socket_cookie) &&
            !((*claim_found &&
               (java_remote_parent_retrieval_claim_binding_matches(resolution,
                                                                   start,
                                                                   bound_state,
                                                                   expected_connection,
                                                                   expected_connection_netns,
                                                                   expected_socket_cookie) ||
                java_remote_parent_retrieval_claim_terminal_matches(resolution,
                                                                    start,
                                                                    bound_state,
                                                                    expected_connection,
                                                                    expected_connection_netns,
                                                                    expected_socket_cookie))) ||
              java_remote_parent_retrieval_alias_replay_binding_matches(resolution,
                                                                        start,
                                                                        expected_connection,
                                                                        expected_connection_netns,
                                                                        expected_generation,
                                                                        expected_socket_cookie))) {
            java_remote_parent_init_response(
                response, k_java_remote_parent_status_missing, resolution->key.generation, 0);
            java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_missing);
            return k_java_remote_parent_status_missing;
        }
    }

    if (resolution->ambiguous) {
        if (*claim_found) {
            if (resolution->via_task &&
                !java_remote_parent_retrieval_task_link_matches(resolution, start)) {
                existing_claim_status = k_java_remote_parent_status_ambiguous;
            }
            if (resolution->via_replay &&
                !java_remote_parent_retrieval_alias_replay_matches(resolution)) {
                existing_claim_status = k_java_remote_parent_status_ambiguous;
            }
            java_remote_parent_init_response(
                response, existing_claim_status, resolution->key.generation, 0);
            java_remote_parent_retrieval_stat(discard, existing_claim_status);
            return existing_claim_status;
        }
        u64 observed_monotime_ns = 0;
        java_remote_parent_claim_t *owned_claim = &workspace->owned_claim;
        if (resolution->found &&
            resolution->indexed.lifecycle != k_java_remote_parent_lifecycle_publishing) {
            java_remote_parent_claim_options_t *claim_options = &workspace->claim_options;
            *claim_options = (java_remote_parent_claim_options_t){
                .expected_socket_cookie = expected_socket_cookie,
                .max_age_ns = max_age_ns,
                .expected_connection_netns = expected_connection_netns,
                .desired_lifecycle = k_java_remote_parent_lifecycle_ambiguous,
            };
            const enum java_remote_parent_status claim_status = java_remote_parent_claim(
                resolution, start, expected_connection, claim_options, owned_claim);
            if (claim_status == k_java_remote_parent_status_valid) {
                const java_remote_parent_state_t *state =
                    bpf_map_lookup_elem(&java_remote_parent_state, &resolution->key);
                if (state) {
                    observed_monotime_ns = state->observed_monotime_ns;
                }
                java_remote_parent_finish_generation_with_guard(
                    resolution,
                    k_java_remote_parent_lifecycle_ambiguous,
                    observed_monotime_ns,
                    owned_claim,
                    finish_guard);
            } else if (!owned_claim->observed_monotime_ns) {
                u8 *raced_claim_found = &workspace->raced_claim_found;
                const enum java_remote_parent_status raced_claim_status =
                    java_remote_parent_existing_claim_status(resolution, raced_claim_found);
                if (*raced_claim_found) {
                    const enum java_remote_parent_status authoritative_status =
                        resolution->via_task &&
                                !java_remote_parent_retrieval_task_link_matches(resolution, start)
                            ? k_java_remote_parent_status_ambiguous
                            : raced_claim_status;
                    java_remote_parent_init_response(
                        response, authoritative_status, resolution->key.generation, 0);
                    java_remote_parent_retrieval_stat(discard, authoritative_status);
                    return authoritative_status;
                }
            }
        }
        java_remote_parent_init_response(response,
                                         k_java_remote_parent_status_ambiguous,
                                         resolution->found ? resolution->key.generation : 0,
                                         observed_monotime_ns);
        java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_ambiguous);
        return k_java_remote_parent_status_ambiguous;
    }
    if (!resolution->found) {
        java_remote_parent_init_response(response, k_java_remote_parent_status_missing, 0, 0);
        java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_missing);
        return k_java_remote_parent_status_missing;
    }

    if (resolution->indexed.lifecycle != k_java_remote_parent_lifecycle_active) {
        if ((resolution->via_task &&
             !java_remote_parent_retrieval_task_link_matches(resolution, start)) ||
            (resolution->via_replay &&
             !java_remote_parent_retrieval_alias_replay_matches(resolution))) {
            java_remote_parent_init_response(
                response, k_java_remote_parent_status_ambiguous, resolution->key.generation, 0);
            java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_ambiguous);
            return k_java_remote_parent_status_ambiguous;
        }
        const u64 observed_monotime_ns = resolution->observed_monotime_ns;
        const enum java_remote_parent_status status =
            resolution->via_replay &&
                    resolution->indexed.lifecycle == k_java_remote_parent_lifecycle_stale
                ? k_java_remote_parent_status_already_consumed
                : java_remote_parent_status_for_lifecycle(resolution->indexed.lifecycle);
        java_remote_parent_init_response(
            response, status, resolution->key.generation, observed_monotime_ns);
        java_remote_parent_retrieval_stat(discard, status);
        return status;
    }

    if (resolution->via_task) {
        if (!java_remote_parent_exact_generation_active(
                &resolution->key, resolution->observed_monotime_ns, 0)) {
            java_remote_parent_init_response(
                response, k_java_remote_parent_status_ambiguous, resolution->key.generation, 0);
            java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_ambiguous);
            return k_java_remote_parent_status_ambiguous;
        }
    } else {
        const java_remote_parent_response_t *fallback =
            bpf_map_lookup_elem(&java_remote_parent_fallback, &resolution->key.owner);
        if (!fallback) {
            java_remote_parent_init_response(
                response, k_java_remote_parent_status_missing, resolution->key.generation, 0);
            java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_missing);
            return k_java_remote_parent_status_missing;
        }
        if (fallback->status != k_java_remote_parent_status_valid ||
            java_remote_parent_le64_to_cpu(fallback->generation_le) != resolution->key.generation) {
            java_remote_parent_init_response(
                response, k_java_remote_parent_status_ambiguous, resolution->key.generation, 0);
            java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_ambiguous);
            return k_java_remote_parent_status_ambiguous;
        }
    }

    const java_remote_parent_state_t *preclaim_state =
        bpf_map_lookup_elem(&java_remote_parent_state, &resolution->key);
    enum java_remote_parent_lifecycle desired_lifecycle = k_java_remote_parent_lifecycle_ambiguous;
    if (preclaim_state && preclaim_state->lifecycle == k_java_remote_parent_lifecycle_active) {
        const u64 now = bpf_ktime_get_ns();
        desired_lifecycle = java_remote_parent_observation_stale(
                                now, preclaim_state->observed_monotime_ns, max_age_ns)
                                ? k_java_remote_parent_lifecycle_stale
                                : (discard ? k_java_remote_parent_lifecycle_discarded
                                           : k_java_remote_parent_lifecycle_consumed);
    }

    java_remote_parent_claim_t *owned_claim = &workspace->owned_claim;
    java_remote_parent_claim_options_t *claim_options = &workspace->claim_options;
    *claim_options = (java_remote_parent_claim_options_t){
        .expected_socket_cookie = expected_socket_cookie,
        .max_age_ns = max_age_ns,
        .expected_connection_netns = expected_connection_netns,
        .desired_lifecycle = desired_lifecycle,
    };
    const enum java_remote_parent_status claim_status = java_remote_parent_claim(
        resolution, start, expected_connection, claim_options, owned_claim);
    const enum java_remote_parent_lifecycle committed_lifecycle =
        owned_claim->observed_monotime_ns ? owned_claim->lifecycle : desired_lifecycle;
    if (resolution->via_task &&
        !java_remote_parent_retrieval_task_link_matches(resolution, start)) {
        if (owned_claim->observed_monotime_ns) {
            java_remote_parent_finish_generation_with_guard(resolution,
                                                            committed_lifecycle,
                                                            resolution->observed_monotime_ns,
                                                            owned_claim,
                                                            finish_guard);
        }
        java_remote_parent_init_response(
            response, k_java_remote_parent_status_ambiguous, resolution->key.generation, 0);
        java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_ambiguous);
        return k_java_remote_parent_status_ambiguous;
    }
    if (claim_status != k_java_remote_parent_status_valid) {
        java_remote_parent_init_response(response, claim_status, resolution->key.generation, 0);
        java_remote_parent_retrieval_stat(discard, claim_status);
        return claim_status;
    }

    java_remote_parent_state_t *state =
        bpf_map_lookup_elem(&java_remote_parent_state, &resolution->key);
    if (!state) {
        const u8 task_rebound = resolution->via_task &&
                                !java_remote_parent_retrieval_task_link_matches(resolution, start);
        const enum java_remote_parent_status status = task_rebound
                                                          ? k_java_remote_parent_status_ambiguous
                                                          : k_java_remote_parent_status_missing;
        java_remote_parent_init_response(response, status, resolution->key.generation, 0);
        java_remote_parent_finish_generation_with_guard(resolution,
                                                        committed_lifecycle,
                                                        resolution->observed_monotime_ns,
                                                        owned_claim,
                                                        finish_guard);
        java_remote_parent_retrieval_stat(discard, status);
        return status;
    }

    const java_remote_parent_response_t *claimed_fallback = NULL;
    if (!resolution->via_task) {
        claimed_fallback =
            bpf_map_lookup_elem(&java_remote_parent_fallback, &resolution->key.owner);
    }
    if (!java_remote_parent_retrieval_state_metadata_matches(resolution, state) ||
        state->process_incarnation != java_current_process_incarnation() ||
        !java_remote_parent_generation_index_matches(
            &resolution->key, state->process_incarnation, resolution->observed_monotime_ns) ||
        !java_remote_parent_generation_cleanly_reserved(&resolution->key) ||
        !java_remote_parent_retrieval_connection_matches(resolution,
                                                         state,
                                                         expected_connection,
                                                         expected_connection_netns,
                                                         expected_socket_cookie) ||
        (!resolution->via_task &&
         (!claimed_fallback || claimed_fallback->status != k_java_remote_parent_status_valid ||
          java_remote_parent_le64_to_cpu(claimed_fallback->generation_le) !=
              resolution->key.generation))) {
        java_remote_parent_init_response(
            response, k_java_remote_parent_status_ambiguous, resolution->key.generation, 0);
        java_remote_parent_finish_generation_with_guard(resolution,
                                                        committed_lifecycle,
                                                        state->observed_monotime_ns,
                                                        owned_claim,
                                                        finish_guard);
        java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_ambiguous);
        return k_java_remote_parent_status_ambiguous;
    }

    if (resolution->via_task &&
        !java_remote_parent_retrieval_task_link_matches(resolution, start)) {
        java_remote_parent_init_response(
            response, k_java_remote_parent_status_ambiguous, resolution->key.generation, 0);
        java_remote_parent_finish_generation_with_guard(resolution,
                                                        committed_lifecycle,
                                                        state->observed_monotime_ns,
                                                        owned_claim,
                                                        finish_guard);
        java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_ambiguous);
        return k_java_remote_parent_status_ambiguous;
    }

    const enum java_remote_parent_lifecycle lifecycle = committed_lifecycle;
    const u64 observed_monotime_ns = state->observed_monotime_ns;
    u8 copied_valid = 0;

    if (lifecycle == k_java_remote_parent_lifecycle_consumed && !discard) {
        __builtin_memcpy(response, &state->response, sizeof(*response));
        copied_valid = 1;
    }

    java_remote_parent_finish_generation_with_guard(
        resolution, lifecycle, observed_monotime_ns, owned_claim, finish_guard);

    if (copied_valid) {
        java_remote_parent_retrieval_stat(0, k_java_remote_parent_status_valid);
        if (resolution->via_task) {
            java_remote_parent_stat_add(k_java_remote_parent_stat_handoff_valid);
        }
        return k_java_remote_parent_status_valid;
    }
    if (discard && lifecycle == k_java_remote_parent_lifecycle_discarded) {
        java_remote_parent_init_response(response,
                                         k_java_remote_parent_status_missing,
                                         resolution->key.generation,
                                         observed_monotime_ns);
        java_remote_parent_retrieval_stat(1, k_java_remote_parent_status_valid);
        return k_java_remote_parent_status_missing;
    }

    const enum java_remote_parent_status status =
        java_remote_parent_status_for_lifecycle(lifecycle);
    java_remote_parent_init_response(
        response, status, resolution->key.generation, observed_monotime_ns);
    java_remote_parent_retrieval_stat(discard, status);
    return status;
}

static __always_inline enum java_remote_parent_status
java_remote_parent_retrieve_for_connection(java_remote_parent_response_t *response,
                                           u8 discard,
                                           u64 max_age_ns,
                                           enum java_remote_parent_source source,
                                           const connection_info_t *expected_connection,
                                           u32 expected_connection_netns,
                                           u64 expected_generation,
                                           u64 expected_socket_cookie) {
    java_remote_parent_retrieval_workspace_t workspace = {0};
    return java_remote_parent_retrieve_for_connection_with_workspace(response,
                                                                     discard,
                                                                     max_age_ns,
                                                                     source,
                                                                     expected_connection,
                                                                     expected_connection_netns,
                                                                     expected_generation,
                                                                     expected_socket_cookie,
                                                                     &workspace);
}

static __noinline __attribute__((unused)) enum java_remote_parent_status
java_remote_parent_retrieve(java_remote_parent_response_t *response,
                            u8 discard,
                            u64 max_age_ns,
                            enum java_remote_parent_source source) {
    return java_remote_parent_retrieve_for_connection(
        response, discard, max_age_ns, source, NULL, 0, 0, 0);
}
