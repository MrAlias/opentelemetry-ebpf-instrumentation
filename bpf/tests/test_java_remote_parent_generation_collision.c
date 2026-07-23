// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>

enum { BPF_ANY = 0, BPF_NOEXIST = 1, BPF_EXIST = 2 };

static void *test_map_lookup(void *map, const void *key);
static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags);
static long test_map_delete(void *map, const void *key);
static unsigned long long test_ktime_get_ns(void);
static unsigned int test_prandom_u32(void);

#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update
#define bpf_map_delete_elem test_map_delete
#define bpf_ktime_get_ns test_ktime_get_ns
#define bpf_get_prandom_u32 test_prandom_u32
#define bpf_loop(nr_loops, callback_fn, callback_ctx, flags)                                       \
    ((void)(nr_loops), (void)(callback_fn), (void)(callback_ctx), (void)(flags), 0)

#include <maps/java_remote_parent_shared.h>
#include <maps/java_vt_threads.h>
#include <pid/pid_helpers.h>

static void test_task_tid(pid_key_t *owner);
static u8 test_java_vt_translate_tid(pid_key_t *owner);
static u64 test_java_process_incarnation_for(const pid_key_t *owner);
static u8 test_java_remote_parent_data_hook_is_ready(void);

#define task_tid test_task_tid
#define java_vt_translate_tid test_java_vt_translate_tid
#define java_process_incarnation_for test_java_process_incarnation_for
#define java_remote_parent_data_hook_is_ready test_java_remote_parent_data_hook_is_ready

#include <maps/java_remote_parent.h>

#undef java_remote_parent_data_hook_is_ready
#undef java_process_incarnation_for
#undef java_vt_translate_tid
#undef task_tid
#undef bpf_loop
#undef bpf_get_prandom_u32
#undef bpf_ktime_get_ns
#undef bpf_map_delete_elem
#undef bpf_map_update_elem
#undef bpf_map_lookup_elem

static const pid_key_t test_owner = {.tid = 7, .pid = 5, .ns = 3};
static u64 generation_sequence;
static java_remote_parent_terminal_t terminal;
static connection_info_netns_cookie_t incoming_connection_key;
static incoming_trace_candidate_t incoming_candidate;
static u64 incoming_generation;
static u8 incoming_claim;
static u64 stats[k_java_remote_parent_stat_max];
static int update_calls;
static int delete_calls;

enum {
    test_connection_netns = 42,
    test_connection_netns_cookie = 84,
    test_incoming_generation = 21,
    test_trace_seed = 0x10,
    test_span_seed = 0x30,
};

enum invalid_stage_case {
    invalid_stage_valid_bit,
    invalid_stage_all_zero_ids,
    invalid_stage_zero_trace_id,
    invalid_stage_zero_span_id,
    invalid_stage_provenance,
    invalid_stage_case_count,
};

static void fail(const char *message) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

static void *test_map_lookup(void *map, const void *key) {
    if (map == &java_remote_parent_generation) {
        return &generation_sequence;
    }
    if (map == &incoming_trace_connection_key_storage) {
        return &incoming_connection_key;
    }
    if (map == &incoming_trace_heads) {
        return &incoming_generation;
    }
    if (map == &incoming_trace_candidates && *(const u64 *)key == incoming_generation) {
        return &incoming_candidate;
    }
    if (map == &incoming_trace_claims && *(const u64 *)key == incoming_generation) {
        return &incoming_claim;
    }
    if (map == &java_remote_parent_terminal) {
        const pid_key_t *owner = key;
        if (owner->tid == test_owner.tid && owner->pid == test_owner.pid &&
            owner->ns == test_owner.ns) {
            return &terminal;
        }
    }
    if (map == &java_remote_parent_stats) {
        const u32 index = *(const u32 *)key;
        return index < k_java_remote_parent_stat_max ? &stats[index] : NULL;
    }
    return NULL;
}

static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags) {
    (void)map;
    (void)key;
    (void)value;
    (void)flags;
    update_calls++;
    return 0;
}

static long test_map_delete(void *map, const void *key) {
    (void)map;
    (void)key;
    delete_calls++;
    return 0;
}

static unsigned long long test_ktime_get_ns(void) {
    return 100;
}

static unsigned int test_prandom_u32(void) {
    return 0;
}

static void test_task_tid(pid_key_t *owner) {
    *owner = test_owner;
}

static u8 test_java_vt_translate_tid(pid_key_t *owner) {
    (void)owner;
    return 0;
}

static u64 test_java_process_incarnation_for(const pid_key_t *owner) {
    (void)owner;
    return 9;
}

static u8 test_java_remote_parent_data_hook_is_ready(void) {
    return 1;
}

static tp_info_pid_t valid_incoming_parent(void) {
    tp_info_pid_t incoming = {
        .valid = 1,
        .provenance = k_tp_provenance_tcp_exact_flags,
    };
    for (u32 index = 0; index < sizeof(incoming.tp.trace_id); index++) {
        incoming.tp.trace_id[index] = test_trace_seed + index;
    }
    for (u32 index = 0; index < sizeof(incoming.tp.span_id); index++) {
        incoming.tp.span_id[index] = test_span_seed + index;
    }
    return incoming;
}

static void test_invalid_stage_inputs_fail_before_publication(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    for (enum invalid_stage_case invalid_case = invalid_stage_valid_bit;
         invalid_case < invalid_stage_case_count;
         invalid_case++) {
        tp_info_pid_t incoming = valid_incoming_parent();
        if (invalid_case == invalid_stage_valid_bit) {
            incoming.valid = 0;
        } else if (invalid_case == invalid_stage_all_zero_ids) {
            memset(incoming.tp.trace_id, 0, sizeof(incoming.tp.trace_id));
            memset(incoming.tp.span_id, 0, sizeof(incoming.tp.span_id));
        } else if (invalid_case == invalid_stage_zero_trace_id) {
            memset(incoming.tp.trace_id, 0, sizeof(incoming.tp.trace_id));
        } else if (invalid_case == invalid_stage_zero_span_id) {
            memset(incoming.tp.span_id, 0, sizeof(incoming.tp.span_id));
        } else {
            incoming.provenance = k_tp_provenance_tcp_legacy;
        }

        memset(stats, 0, sizeof(stats));
        generation_sequence = 0;
        update_calls = 0;
        delete_calls = 0;
        if (java_remote_parent_stage(&connection,
                                     test_connection_netns,
                                     test_connection_netns_cookie,
                                     test_incoming_generation,
                                     &incoming) != 0 ||
            generation_sequence != 0 || update_calls != 0 || delete_calls != 0 ||
            stats[k_java_remote_parent_stat_stage_malformed] != 1) {
            fail("invalid TCP parent reached Java publication");
        }
    }
}

static void test_wrapped_generation_does_not_replace_terminal(void) {
    memset(stats, 0, sizeof(stats));
    update_calls = 0;
    delete_calls = 0;
    generation_sequence = (1ULL << k_per_cpu_generation_sequence_bits) - 1;
    terminal = (java_remote_parent_terminal_t){
        .generation = 1,
        .observed_monotime_ns = 80,
        .process_incarnation = 9,
        .lifecycle = k_java_remote_parent_lifecycle_consumed,
    };
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const tp_info_pid_t incoming = valid_incoming_parent();
    incoming_generation = test_incoming_generation;
    incoming_claim = 1;
    incoming_candidate = (incoming_trace_candidate_t){.candidate = incoming};

    if (java_remote_parent_stage(&connection,
                                 test_connection_netns,
                                 test_connection_netns_cookie,
                                 test_incoming_generation,
                                 &incoming) != 0 ||
        generation_sequence != 1 || terminal.generation != 1 || update_calls != 0 ||
        delete_calls != 0 || stats[k_java_remote_parent_stat_stage_ambiguous] != 1) {
        fail("wrapped generation replaced an exact terminal tombstone");
    }
}

int main(void) {
    test_invalid_stage_inputs_fail_before_publication();
    test_wrapped_generation_does_not_replace_terminal();
    return 0;
}
