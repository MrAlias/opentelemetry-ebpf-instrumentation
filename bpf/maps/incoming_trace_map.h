// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/java_remote_parent.h>
#include <common/map_sizing.h>
#include <common/per_cpu_generation.h>
#include <common/pin_internal.h>
#include <common/scratch_mem.h>
#include <common/sock_port_ns.h>
#include <common/tp_info.h>

// Keep the legacy map and its update/delete behavior intact while the Java
// remote-parent bridge is disabled.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, connection_info_t);
    __type(value, tp_info_pid_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} incoming_trace_map SEC(".maps");

typedef struct incoming_trace_candidate {
    tp_info_pid_t candidate;
    u32 tcp_sequence;
    u32 reserved;
} incoming_trace_candidate_t;

_Static_assert(offsetof(incoming_trace_candidate_t, tcp_sequence) == 56,
               "incoming trace TCP sequence offset mismatch");
_Static_assert(sizeof(incoming_trace_candidate_t) == 64, "incoming trace candidate size mismatch");

// A head publishes one immutable candidate generation. Consumers never
// mutate candidate bytes: they atomically insert a generation-specific claim.
// This avoids torn cross-CPU reads between sockops and tracing programs, where
// bpf_spin_lock is not permitted by the verifier.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, connection_info_netns_cookie_t);
    __type(value, u64);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} incoming_trace_heads SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, incoming_trace_candidate_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} incoming_trace_candidates SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u8);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} incoming_trace_claims SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, u8);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} incoming_trace_ambiguity SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1);
    __uint(pinning, OBI_PIN_INTERNAL);
} incoming_trace_generation SEC(".maps");

SCRATCH_MEM_TYPED(incoming_trace_snapshot, tp_info_pid_t)
SCRATCH_MEM_TYPED(incoming_trace_connection_key, connection_info_netns_cookie_t)
SCRATCH_MEM_TYPED(incoming_trace_candidate_value, incoming_trace_candidate_t)

enum incoming_trace_update_result : u8 {
    k_incoming_trace_inserted = 1,
    k_incoming_trace_duplicate = 2,
    k_incoming_trace_ambiguous = 3,
    k_incoming_trace_update_failed = 4,
};

static __always_inline u8 incoming_trace_same_candidate(const tp_info_pid_t *left,
                                                        const tp_info_pid_t *right) {
    return left->valid && right->valid && left->tp.flags == right->tp.flags &&
           left->provenance == right->provenance &&
           __builtin_memcmp(left->tp.trace_id, right->tp.trace_id, TRACE_ID_SIZE_BYTES) == 0 &&
           __builtin_memcmp(left->tp.span_id, right->tp.span_id, SPAN_ID_SIZE_BYTES) == 0;
}

static __always_inline s32 incoming_trace_sequence_order(u32 candidate, u32 reference) {
    return (s32)(candidate - reference);
}

static __always_inline connection_info_netns_cookie_t *
incoming_trace_connection_key_for(const connection_info_t *connection, u64 netns_cookie) {
    connection_info_netns_cookie_t *key =
        (connection_info_netns_cookie_t *)incoming_trace_connection_key_mem();
    if (!key || !netns_cookie) {
        return NULL;
    }
    __builtin_memcpy(&key->connection, connection, sizeof(key->connection));
    key->reserved = 0;
    key->netns_cookie = netns_cookie;
    return key;
}

static __always_inline u64 incoming_trace_next_generation() {
    const u32 zero = 0;
    u64 *counter = bpf_map_lookup_elem(&incoming_trace_generation, &zero);
    if (!counter) {
        return 0;
    }

    return next_per_cpu_generation(counter, bpf_get_smp_processor_id());
}

static __always_inline u8 incoming_trace_publish_candidate(const tp_info_pid_t *candidate,
                                                           u32 tcp_sequence,
                                                           u64 *generation_out) {
    const u64 generation = incoming_trace_next_generation();
    if (!generation) {
        return 0;
    }

    incoming_trace_candidate_t *value =
        (incoming_trace_candidate_t *)incoming_trace_candidate_value_mem();
    if (!value) {
        return 0;
    }
    __builtin_memset(value, 0, sizeof(*value));
    __builtin_memcpy(&value->candidate, candidate, sizeof(value->candidate));
    value->tcp_sequence = tcp_sequence;
    if (bpf_map_update_elem(&incoming_trace_candidates, &generation, value, BPF_NOEXIST) != 0) {
        return 0;
    }

    *generation_out = generation;
    return 1;
}

static __always_inline void
incoming_trace_poison_generation(connection_info_netns_cookie_t *connection_key, u64 generation) {
    u64 *head = bpf_map_lookup_elem(&incoming_trace_heads, connection_key);
    if (head && *head == generation) {
        const u64 tombstone = 0;
        bpf_map_update_elem(&incoming_trace_heads, connection_key, &tombstone, BPF_EXIST);
        bpf_map_delete_elem(&incoming_trace_heads, connection_key);
    }
    bpf_map_delete_elem(&incoming_trace_candidates, &generation);
    bpf_map_delete_elem(&incoming_trace_claims, &generation);
    bpf_map_delete_elem(&incoming_trace_ambiguity, &generation);
}

static __always_inline enum incoming_trace_update_result incoming_trace_mark_ambiguous(
    connection_info_netns_cookie_t *connection_key, u64 generation, u64 *ambiguous_generation) {
    if (ambiguous_generation) {
        *ambiguous_generation = generation;
    }
    const u8 ambiguous = 1;
    if (bpf_map_update_elem(&incoming_trace_ambiguity, &generation, &ambiguous, BPF_ANY) != 0) {
        incoming_trace_poison_generation(connection_key, generation);
        return k_incoming_trace_update_failed;
    }
    return k_incoming_trace_ambiguous;
}

static __always_inline enum incoming_trace_update_result
update_strict_incoming_trace_with_generation(const connection_info_t *connection,
                                             const tp_info_pid_t *candidate,
                                             u32 tcp_sequence,
                                             u64 netns_cookie,
                                             u64 *ambiguous_generation) {
    if (ambiguous_generation) {
        *ambiguous_generation = 0;
    }
    connection_info_netns_cookie_t *connection_key =
        incoming_trace_connection_key_for(connection, netns_cookie);
    if (!connection_key) {
        return k_incoming_trace_update_failed;
    }
    u64 *head = bpf_map_lookup_elem(&incoming_trace_heads, connection_key);
    if (!head) {
        u64 generation = 0;
        if (!incoming_trace_publish_candidate(candidate, tcp_sequence, &generation)) {
            return k_incoming_trace_update_failed;
        }
        if (bpf_map_update_elem(&incoming_trace_heads, connection_key, &generation, BPF_NOEXIST) ==
            0) {
            return k_incoming_trace_inserted;
        }
        bpf_map_delete_elem(&incoming_trace_candidates, &generation);
        head = bpf_map_lookup_elem(&incoming_trace_heads, connection_key);
        if (!head) {
            return k_incoming_trace_update_failed;
        }
    }

    const u64 current_generation = *head;
    if (!current_generation) {
        return k_incoming_trace_update_failed;
    }
    const incoming_trace_candidate_t *current =
        bpf_map_lookup_elem(&incoming_trace_candidates, &current_generation);
    if (!current || *head != current_generation) {
        return incoming_trace_mark_ambiguous(
            connection_key, current_generation, ambiguous_generation);
    }

    if (bpf_map_lookup_elem(&incoming_trace_ambiguity, &current_generation)) {
        if (ambiguous_generation) {
            *ambiguous_generation = current_generation;
        }
        return k_incoming_trace_ambiguous;
    }
    if (incoming_trace_same_candidate(&current->candidate, candidate) &&
        tcp_sequence == current->tcp_sequence) {
        return k_incoming_trace_duplicate;
    }
    if (!bpf_map_lookup_elem(&incoming_trace_claims, &current_generation)) {
        return incoming_trace_mark_ambiguous(
            connection_key, current_generation, ambiguous_generation);
    }
    if (incoming_trace_sequence_order(tcp_sequence, current->tcp_sequence) <= 0) {
        return incoming_trace_mark_ambiguous(
            connection_key, current_generation, ambiguous_generation);
    }

    u64 next_generation = 0;
    if (!incoming_trace_publish_candidate(candidate, tcp_sequence, &next_generation)) {
        return k_incoming_trace_update_failed;
    }

    if (bpf_map_update_elem(&incoming_trace_heads, connection_key, &next_generation, BPF_EXIST) !=
        0) {
        bpf_map_delete_elem(&incoming_trace_candidates, &next_generation);
        return k_incoming_trace_update_failed;
    }
    bpf_map_delete_elem(&incoming_trace_candidates, &current_generation);
    bpf_map_delete_elem(&incoming_trace_claims, &current_generation);
    bpf_map_delete_elem(&incoming_trace_ambiguity, &current_generation);
    return k_incoming_trace_inserted;
}

static __always_inline enum incoming_trace_update_result
update_strict_incoming_trace(const connection_info_t *connection,
                             const tp_info_pid_t *candidate,
                             u32 tcp_sequence,
                             u64 netns_cookie) {
    return update_strict_incoming_trace_with_generation(
        connection, candidate, tcp_sequence, netns_cookie, NULL);
}

static __always_inline enum incoming_trace_update_result
update_incoming_trace_with_generation(const connection_info_t *connection,
                                      const tp_info_pid_t *candidate,
                                      u32 tcp_sequence,
                                      u64 netns_cookie,
                                      u64 *ambiguous_generation) {
    if (!java_remote_parent_enabled) {
        if (ambiguous_generation) {
            *ambiguous_generation = 0;
        }
        return bpf_map_update_elem(&incoming_trace_map, connection, candidate, BPF_ANY) == 0
                   ? k_incoming_trace_inserted
                   : k_incoming_trace_update_failed;
    }
    return update_strict_incoming_trace_with_generation(
        connection, candidate, tcp_sequence, netns_cookie, ambiguous_generation);
}

static __always_inline enum incoming_trace_update_result
update_incoming_trace(const connection_info_t *connection,
                      const tp_info_pid_t *candidate,
                      u32 tcp_sequence,
                      u64 netns_cookie) {
    return update_incoming_trace_with_generation(
        connection, candidate, tcp_sequence, netns_cookie, NULL);
}

static __always_inline tp_info_pid_t *
legacy_consume_incoming_trace(const connection_info_t *connection) {
    const tp_info_pid_t *candidate = bpf_map_lookup_elem(&incoming_trace_map, connection);
    if (!candidate) {
        return NULL;
    }

    tp_info_pid_t *snapshot = (tp_info_pid_t *)incoming_trace_snapshot_mem();
    if (!snapshot) {
        return NULL;
    }
    __builtin_memcpy(snapshot, candidate, sizeof(*snapshot));
    bpf_map_delete_elem(&incoming_trace_map, connection);
    return snapshot;
}

static __always_inline tp_info_pid_t *
snapshot_strict_incoming_trace(const connection_info_t *connection, u64 netns_cookie) {
    connection_info_netns_cookie_t *connection_key =
        incoming_trace_connection_key_for(connection, netns_cookie);
    if (!connection_key) {
        return NULL;
    }
    const u64 *head = bpf_map_lookup_elem(&incoming_trace_heads, connection_key);
    if (!head || !*head) {
        return NULL;
    }

    const u64 generation = *head;
    if (bpf_map_lookup_elem(&incoming_trace_claims, &generation) ||
        bpf_map_lookup_elem(&incoming_trace_ambiguity, &generation)) {
        return NULL;
    }

    const incoming_trace_candidate_t *candidate =
        bpf_map_lookup_elem(&incoming_trace_candidates, &generation);
    if (!candidate || !candidate->candidate.valid) {
        return NULL;
    }
    tp_info_pid_t *snapshot = (tp_info_pid_t *)incoming_trace_snapshot_mem();
    if (!snapshot) {
        return NULL;
    }
    __builtin_memcpy(snapshot, &candidate->candidate, sizeof(*snapshot));

    head = bpf_map_lookup_elem(&incoming_trace_heads, connection_key);
    if (!head || *head != generation || bpf_map_lookup_elem(&incoming_trace_claims, &generation) ||
        bpf_map_lookup_elem(&incoming_trace_ambiguity, &generation)) {
        return NULL;
    }
    return snapshot;
}

static __always_inline tp_info_pid_t *
snapshot_incoming_trace_in_netns_cookie(const connection_info_t *connection, u64 netns_cookie) {
    if (!java_remote_parent_enabled) {
        return NULL;
    }
    return snapshot_strict_incoming_trace(connection, netns_cookie);
}

static __always_inline tp_info_pid_t *snapshot_incoming_trace(const connection_info_t *connection) {
    return snapshot_incoming_trace_in_netns_cookie(connection, task_netns_cookie());
}

static __always_inline u8
incoming_trace_claimed_generation_matches_in_netns_cookie(const connection_info_t *connection,
                                                          u64 netns_cookie,
                                                          u64 generation,
                                                          const tp_info_pid_t *candidate) {
    connection_info_netns_cookie_t *connection_key =
        incoming_trace_connection_key_for(connection, netns_cookie);
    if (!connection_key) {
        return 0;
    }
    const u64 *head = bpf_map_lookup_elem(&incoming_trace_heads, connection_key);
    if (!head || !generation || *head != generation) {
        return 0;
    }

    const incoming_trace_candidate_t *current =
        bpf_map_lookup_elem(&incoming_trace_candidates, &generation);
    if (!current || !incoming_trace_same_candidate(&current->candidate, candidate) ||
        !bpf_map_lookup_elem(&incoming_trace_claims, &generation) ||
        bpf_map_lookup_elem(&incoming_trace_ambiguity, &generation)) {
        return 0;
    }

    head = bpf_map_lookup_elem(&incoming_trace_heads, connection_key);
    return head && *head == generation;
}

static __always_inline tp_info_pid_t *consume_strict_incoming_trace_with_generation(
    const connection_info_t *connection, u64 netns_cookie, u64 *generation_out) {
    if (generation_out) {
        *generation_out = 0;
    }
    connection_info_netns_cookie_t *connection_key =
        incoming_trace_connection_key_for(connection, netns_cookie);
    if (!connection_key) {
        return NULL;
    }
    const u64 *head = bpf_map_lookup_elem(&incoming_trace_heads, connection_key);
    if (!head || !*head) {
        return NULL;
    }

    const u64 generation = *head;
    if (bpf_map_lookup_elem(&incoming_trace_ambiguity, &generation)) {
        return NULL;
    }
    const incoming_trace_candidate_t *candidate =
        bpf_map_lookup_elem(&incoming_trace_candidates, &generation);
    if (!candidate || !candidate->candidate.valid) {
        return NULL;
    }
    tp_info_pid_t *snapshot = (tp_info_pid_t *)incoming_trace_snapshot_mem();
    if (!snapshot) {
        return NULL;
    }
    __builtin_memcpy(snapshot, &candidate->candidate, sizeof(*snapshot));
    if (*head != generation) {
        return NULL;
    }

    const u8 claimed = 1;
    if (bpf_map_update_elem(&incoming_trace_claims, &generation, &claimed, BPF_NOEXIST) != 0) {
        return NULL;
    }
    head = bpf_map_lookup_elem(&incoming_trace_heads, connection_key);
    if (!head || *head != generation ||
        bpf_map_lookup_elem(&incoming_trace_ambiguity, &generation)) {
        bpf_map_delete_elem(&incoming_trace_claims, &generation);
        return NULL;
    }
    if (generation_out) {
        *generation_out = generation;
    }
    return snapshot;
}

static __always_inline tp_info_pid_t *
consume_strict_incoming_trace(const connection_info_t *connection, u64 netns_cookie) {
    return consume_strict_incoming_trace_with_generation(connection, netns_cookie, NULL);
}

static __always_inline tp_info_pid_t *consume_incoming_trace_in_netns_cookie_with_generation(
    const connection_info_t *connection, u64 netns_cookie, u64 *generation_out) {
    if (!java_remote_parent_enabled) {
        if (generation_out) {
            *generation_out = 0;
        }
        return legacy_consume_incoming_trace(connection);
    }
    return consume_strict_incoming_trace_with_generation(connection, netns_cookie, generation_out);
}

static __always_inline tp_info_pid_t *
consume_incoming_trace_in_netns_cookie(const connection_info_t *connection, u64 netns_cookie) {
    return consume_incoming_trace_in_netns_cookie_with_generation(connection, netns_cookie, NULL);
}

static __always_inline tp_info_pid_t *
consume_incoming_trace_with_generation(const connection_info_t *connection, u64 *generation_out) {
    return consume_incoming_trace_in_netns_cookie_with_generation(
        connection, task_netns_cookie(), generation_out);
}

static __always_inline tp_info_pid_t *consume_incoming_trace(const connection_info_t *connection) {
    return consume_incoming_trace_with_generation(connection, NULL);
}

static __always_inline void invalidate_strict_incoming_trace(const connection_info_t *connection,
                                                             u64 netns_cookie,
                                                             u64 observed_monotime_ns) {
    (void)observed_monotime_ns;
    connection_info_netns_cookie_t *connection_key =
        incoming_trace_connection_key_for(connection, netns_cookie);
    if (!connection_key) {
        return;
    }
    const u64 *head = bpf_map_lookup_elem(&incoming_trace_heads, connection_key);
    if (!head || !*head) {
        return;
    }
    const u64 generation = *head;
    if (incoming_trace_mark_ambiguous(connection_key, generation, NULL) !=
        k_incoming_trace_ambiguous) {
        return;
    }
    head = bpf_map_lookup_elem(&incoming_trace_heads, connection_key);
    if (!head || *head != generation) {
        bpf_map_delete_elem(&incoming_trace_ambiguity, &generation);
    }
}

static __always_inline void invalidate_incoming_trace_in_netns_cookie(
    const connection_info_t *connection, u64 netns_cookie, u64 observed_monotime_ns) {
    if (java_remote_parent_enabled) {
        invalidate_strict_incoming_trace(connection, netns_cookie, observed_monotime_ns);
    }
}

static __always_inline void invalidate_incoming_trace(const connection_info_t *connection,
                                                      u64 observed_monotime_ns) {
    invalidate_incoming_trace_in_netns_cookie(
        connection, task_netns_cookie(), observed_monotime_ns);
}

static __always_inline void delete_strict_incoming_trace(const connection_info_t *connection,
                                                         u64 netns_cookie) {
    connection_info_netns_cookie_t *connection_key =
        incoming_trace_connection_key_for(connection, netns_cookie);
    if (!connection_key) {
        return;
    }
    const u64 *head = bpf_map_lookup_elem(&incoming_trace_heads, connection_key);
    if (!head || !*head) {
        return;
    }
    const u64 generation = *head;

    bpf_map_delete_elem(&incoming_trace_heads, connection_key);
    bpf_map_delete_elem(&incoming_trace_candidates, &generation);
    bpf_map_delete_elem(&incoming_trace_claims, &generation);
    bpf_map_delete_elem(&incoming_trace_ambiguity, &generation);
}

static __always_inline void
delete_incoming_trace_in_netns_cookie(const connection_info_t *connection, u64 netns_cookie) {
    bpf_map_delete_elem(&incoming_trace_map, connection);
    delete_strict_incoming_trace(connection, netns_cookie);
}

static __always_inline void delete_incoming_trace(const connection_info_t *connection) {
    delete_incoming_trace_in_netns_cookie(connection, task_netns_cookie());
}
