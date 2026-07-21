// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>

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
static u64 stats[k_java_remote_parent_stat_max];
static int update_calls;
static int delete_calls;

static void fail(const char *message) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

static void *test_map_lookup(void *map, const void *key) {
    if (map == &java_remote_parent_generation) {
        return &generation_sequence;
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

int main(void) {
    generation_sequence = (1ULL << k_per_cpu_generation_sequence_bits) - 1;
    terminal = (java_remote_parent_terminal_t){
        .generation = 1,
        .observed_monotime_ns = 80,
        .process_incarnation = 9,
        .lifecycle = k_java_remote_parent_lifecycle_consumed,
    };
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    tp_info_pid_t incoming = {
        .valid = 1,
        .provenance = k_tp_provenance_tcp_exact_flags,
    };
    incoming.tp.trace_id[0] = 1;
    incoming.tp.span_id[0] = 2;

    if (java_remote_parent_stage(&connection, 42, &incoming) != 0 || generation_sequence != 1 ||
        terminal.generation != 1 || update_calls != 0 || delete_calls != 0 ||
        stats[k_java_remote_parent_stat_stage_ambiguous] != 1) {
        fail("wrapped generation replaced an exact terminal tombstone");
    }

    return 0;
}
