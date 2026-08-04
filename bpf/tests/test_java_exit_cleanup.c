// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>
#include <bpfcore/vmlinux.h>

enum { BPF_ANY = 0, BPF_NOEXIST = 1, BPF_EXIST = 2 };

static void *test_map_lookup(void *map, const void *key);
static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags);
static long test_map_delete(void *map, const void *key);

#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update
#define bpf_map_delete_elem test_map_delete

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, u64);
    __uint(max_entries, 1);
} traces_ctx_v1;

#include <generictracer/java_exit_cleanup.h>

#undef bpf_map_lookup_elem
#undef bpf_map_update_elem
#undef bpf_map_delete_elem

static trace_key_t exiting_task;
static trace_key_t exiting_vt_task;
static trace_key_t sentinel_task;
static u64 exiting_id;
static u64 sentinel_id;

static int mount_present;
static int clone_present;
static int physical_trace_present;
static int virtual_trace_present;
static int context_present;
static int java_task_present;
static int sentinel_mount_present;
static int sentinel_clone_present;
static int sentinel_trace_present;
static int sentinel_context_present;
static int sentinel_java_task_present;
static int delete_count;
static int unexpected_delete;

static void fail(const char *message) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

static int same_key(const void *left, const void *right, size_t size) {
    return memcmp(left, right, size) == 0;
}

static void *present_value(int *present) {
    return *present ? present : NULL;
}

static void *test_map_lookup(void *map, const void *key) {
    if (map == &java_vt_threads) {
        if (same_key(key, &exiting_task.p_key, sizeof(exiting_task.p_key))) {
            return present_value(&mount_present);
        }
        if (same_key(key, &sentinel_task.p_key, sizeof(sentinel_task.p_key))) {
            return present_value(&sentinel_mount_present);
        }
    } else if (map == &clone_map) {
        if (same_key(key, &exiting_task.p_key, sizeof(exiting_task.p_key))) {
            return present_value(&clone_present);
        }
        if (same_key(key, &sentinel_task.p_key, sizeof(sentinel_task.p_key))) {
            return present_value(&sentinel_clone_present);
        }
    } else if (map == &server_traces) {
        if (same_key(key, &exiting_task, sizeof(exiting_task))) {
            return present_value(&physical_trace_present);
        }
        if (same_key(key, &exiting_vt_task, sizeof(exiting_vt_task))) {
            return present_value(&virtual_trace_present);
        }
        if (same_key(key, &sentinel_task, sizeof(sentinel_task))) {
            return present_value(&sentinel_trace_present);
        }
    } else if (map == &traces_ctx_v1) {
        if (same_key(key, &exiting_id, sizeof(exiting_id))) {
            return present_value(&context_present);
        }
        if (same_key(key, &sentinel_id, sizeof(sentinel_id))) {
            return present_value(&sentinel_context_present);
        }
    } else if (map == &java_tasks) {
        if (same_key(key, &exiting_task.p_key, sizeof(exiting_task.p_key))) {
            return present_value(&java_task_present);
        }
        if (same_key(key, &sentinel_task.p_key, sizeof(sentinel_task.p_key))) {
            return present_value(&sentinel_java_task_present);
        }
    }
    return NULL;
}

static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags) {
    (void)map;
    (void)key;
    (void)value;
    (void)flags;
    return -1;
}

static long delete_exact(void *map,
                         const void *key,
                         void *expected_map,
                         const void *expected_key,
                         size_t key_size,
                         int *present) {
    if (map != expected_map || !same_key(key, expected_key, key_size) || !*present) {
        return 0;
    }
    *present = 0;
    delete_count++;
    return 1;
}

static long test_map_delete(void *map, const void *key) {
    if (delete_exact(map,
                     key,
                     &java_vt_threads,
                     &exiting_task.p_key,
                     sizeof(exiting_task.p_key),
                     &mount_present) ||
        delete_exact(map,
                     key,
                     &clone_map,
                     &exiting_task.p_key,
                     sizeof(exiting_task.p_key),
                     &clone_present) ||
        delete_exact(map,
                     key,
                     &server_traces,
                     &exiting_task,
                     sizeof(exiting_task),
                     &physical_trace_present) ||
        delete_exact(map,
                     key,
                     &server_traces,
                     &exiting_vt_task,
                     sizeof(exiting_vt_task),
                     &virtual_trace_present) ||
        delete_exact(map, key, &traces_ctx_v1, &exiting_id, sizeof(exiting_id), &context_present) ||
        delete_exact(map,
                     key,
                     &java_tasks,
                     &exiting_task.p_key,
                     sizeof(exiting_task.p_key),
                     &java_task_present)) {
        return 0;
    }
    unexpected_delete = 1;
    return -1;
}

static void reset(void) {
    exiting_task = (trace_key_t){.p_key = {.tid = 6, .pid = 5, .ns = 3}};
    exiting_vt_task = exiting_task;
    exiting_vt_task.p_key.tid = JAVA_VT_TID_FLAG | 42;
    sentinel_task = (trace_key_t){.p_key = {.tid = 8, .pid = 5, .ns = 3}};
    exiting_id = ((u64)exiting_task.p_key.pid << 32) | exiting_task.p_key.tid;
    sentinel_id = ((u64)sentinel_task.p_key.pid << 32) | sentinel_task.p_key.tid;

    mount_present = 1;
    clone_present = 1;
    physical_trace_present = 1;
    virtual_trace_present = 1;
    context_present = 1;
    java_task_present = 1;
    sentinel_mount_present = 1;
    sentinel_clone_present = 1;
    sentinel_trace_present = 1;
    sentinel_context_present = 1;
    sentinel_java_task_present = 1;
    delete_count = 0;
    unexpected_delete = 0;
}

static void assert_target_state_present(void) {
    if (!test_map_lookup(&java_vt_threads, &exiting_task.p_key) ||
        !test_map_lookup(&clone_map, &exiting_task.p_key) ||
        !test_map_lookup(&server_traces, &exiting_task) ||
        !test_map_lookup(&server_traces, &exiting_vt_task) ||
        !test_map_lookup(&traces_ctx_v1, &exiting_id) ||
        !test_map_lookup(&java_tasks, &exiting_task.p_key)) {
        fail("exit state was unexpectedly absent");
    }
}

static void assert_sentinel_state_present(void) {
    if (!test_map_lookup(&java_vt_threads, &sentinel_task.p_key) ||
        !test_map_lookup(&clone_map, &sentinel_task.p_key) ||
        !test_map_lookup(&server_traces, &sentinel_task) ||
        !test_map_lookup(&traces_ctx_v1, &sentinel_id) ||
        !test_map_lookup(&java_tasks, &sentinel_task.p_key)) {
        fail("exit cleanup deleted another task's state");
    }
}

static void test_disabled_untraced_exit_is_not_admitted(void) {
    reset();
    if (java_exit_cleanup_required(0, 0)) {
        java_exit_cleanup_task_maps(&traces_ctx_v1, exiting_id, &exiting_task, &exiting_vt_task, 1);
    }
    assert_target_state_present();
    assert_sentinel_state_present();
    if (delete_count || unexpected_delete) {
        fail("disabled untraced exit mutated task state");
    }
}

static void test_enabled_untraced_exit_cannot_revive_after_tid_reuse(void) {
    reset();
    if (!java_exit_cleanup_required(0, 1)) {
        fail("enabled untraced exit was not admitted for cleanup");
    }
    java_exit_cleanup_task_maps(&traces_ctx_v1, exiting_id, &exiting_task, &exiting_vt_task, 1);

    // Reuse has the same map keys because none of these legacy maps carries a
    // process incarnation. Every lookup must miss after the exiting task was
    // cleaned, while unrelated exact keys remain present.
    if (test_map_lookup(&java_vt_threads, &exiting_task.p_key) ||
        test_map_lookup(&clone_map, &exiting_task.p_key) ||
        test_map_lookup(&server_traces, &exiting_task) ||
        test_map_lookup(&server_traces, &exiting_vt_task) ||
        test_map_lookup(&traces_ctx_v1, &exiting_id) ||
        test_map_lookup(&java_tasks, &exiting_task.p_key) || delete_count != 6 ||
        unexpected_delete) {
        fail("enabled untraced exit left task state revivable by TID reuse");
    }
    assert_sentinel_state_present();
}

int main(void) {
    test_disabled_untraced_exit_is_not_admitted();
    test_enabled_untraced_exit_cannot_revive_after_tid_reuse();
    return 0;
}
