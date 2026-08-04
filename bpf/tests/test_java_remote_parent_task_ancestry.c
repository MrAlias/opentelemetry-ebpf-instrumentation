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
static u8 test_java_vt_translate_tid_for_capability(pid_key_t *owner, u64 process_capability);
static u64 test_java_current_process_incarnation(void);
static u64 test_java_process_incarnation_for(const pid_key_t *owner);
static u64 test_java_process_capability_for(const pid_key_t *owner);
static u8 test_java_vt_prepare_unregistered_cleanup(const pid_key_t *carrier,
                                                    u64 vt_id,
                                                    u64 process_capability,
                                                    pid_key_t *synthetic_owner,
                                                    java_vt_identity_t *expected_identity);
static u8 test_java_vt_delete_identity_if_matches(const pid_key_t *synthetic_owner,
                                                  const java_vt_identity_t *expected_identity);

#define task_tid test_task_tid
#define java_vt_translate_tid test_java_vt_translate_tid
#define java_vt_translate_tid_for_capability test_java_vt_translate_tid_for_capability
#define java_current_process_incarnation test_java_current_process_incarnation
#define java_process_incarnation_for test_java_process_incarnation_for
#define java_process_capability_for test_java_process_capability_for
#define java_vt_prepare_unregistered_cleanup test_java_vt_prepare_unregistered_cleanup
#define java_vt_delete_identity_if_matches test_java_vt_delete_identity_if_matches

#include <maps/java_remote_parent.h>

#undef java_vt_delete_identity_if_matches
#undef java_vt_prepare_unregistered_cleanup
#undef java_process_capability_for
#undef java_process_incarnation_for
#undef java_current_process_incarnation
#undef java_vt_translate_tid_for_capability
#undef java_vt_translate_tid
#undef task_tid
#undef bpf_loop
#undef bpf_get_prandom_u32
#undef bpf_ktime_get_ns
#undef bpf_map_delete_elem
#undef bpf_map_update_elem
#undef bpf_map_lookup_elem

typedef struct task_mapping {
    pid_key_t child;
    pid_key_t parent;
} task_mapping_t;

enum { k_max_test_mappings = 8 };

static task_mapping_t mappings[k_max_test_mappings];
static size_t mapping_count;
static unsigned int lookup_count;
static pid_key_t lookup_keys[k_java_remote_parent_max_ancestry];
static pid_key_t current_task;

static void fail(const char *scenario, const char *message) {
    fprintf(stderr, "FAIL: %s: %s\n", scenario, message);
    exit(1);
}

static int same_key(const pid_key_t *left, const pid_key_t *right) {
    return memcmp(left, right, sizeof(*left)) == 0;
}

static pid_key_t task(u32 tid, u32 pid, u32 ns) {
    return (pid_key_t){.tid = tid, .pid = pid, .ns = ns};
}

static void reset(void) {
    memset(mappings, 0, sizeof(mappings));
    memset(lookup_keys, 0, sizeof(lookup_keys));
    mapping_count = 0;
    lookup_count = 0;
    current_task = (pid_key_t){0};
}

static void link_task(pid_key_t child, pid_key_t parent) {
    if (mapping_count >= k_max_test_mappings) {
        fail("setup", "too many task mappings");
    }
    mappings[mapping_count++] = (task_mapping_t){.child = child, .parent = parent};
}

static void expect_cycle_result(const char *scenario,
                                pid_key_t child,
                                pid_key_t parent,
                                u8 expected,
                                const pid_key_t *expected_lookups,
                                size_t expected_lookup_count) {
    lookup_count = 0;
    memset(lookup_keys, 0, sizeof(lookup_keys));
    const u8 actual = java_remote_parent_task_mapping_would_cycle(&child, &parent);
    if (actual != expected) {
        fail(scenario, expected ? "unsafe mapping was accepted" : "safe mapping was rejected");
    }
    if (lookup_count != expected_lookup_count) {
        fail(scenario, "unexpected ancestry lookup count");
    }
    if (lookup_count > k_java_remote_parent_max_ancestry) {
        fail(scenario, "ancestry lookup exceeded its hard bound");
    }
    for (size_t i = 0; i < expected_lookup_count; i++) {
        if (!same_key(&lookup_keys[i], &expected_lookups[i])) {
            fail(scenario, "ancestry lookup followed the wrong task");
        }
    }
}

static void test_empty_ancestry_is_accepted(void) {
    reset();
    const pid_key_t parent = task(2, 10, 20);
    const pid_key_t expected[] = {parent};
    expect_cycle_result("empty ancestry", task(1, 10, 20), parent, 0, expected, 1);
}

static void test_one_edge_is_accepted(void) {
    reset();
    const pid_key_t parent = task(2, 10, 20);
    const pid_key_t first = task(3, 10, 20);
    const pid_key_t expected[] = {parent, first};
    link_task(parent, first);
    expect_cycle_result("one edge", task(1, 10, 20), parent, 0, expected, 2);
}

static void test_maximum_bounded_ancestry_is_accepted(void) {
    reset();
    const pid_key_t parent = task(2, 10, 20);
    const pid_key_t first = task(3, 10, 20);
    const pid_key_t second = task(4, 10, 20);
    const pid_key_t expected[] = {parent, first, second};
    link_task(parent, first);
    link_task(first, second);
    expect_cycle_result("maximum bounded ancestry", task(1, 10, 20), parent, 0, expected, 3);
}

static void test_ancestry_beyond_bound_is_rejected(void) {
    reset();
    const pid_key_t parent = task(2, 10, 20);
    const pid_key_t first = task(3, 10, 20);
    const pid_key_t second = task(4, 10, 20);
    const pid_key_t expected[] = {parent, first, second};
    link_task(parent, first);
    link_task(first, second);
    link_task(second, task(5, 10, 20));
    expect_cycle_result("ancestry beyond bound", task(1, 10, 20), parent, 1, expected, 3);
}

static void test_self_mapping_is_rejected_without_lookup(void) {
    reset();
    const pid_key_t child = task(1, 10, 20);
    expect_cycle_result("self mapping", child, child, 1, NULL, 0);
}

static void test_cycle_reaching_child_is_rejected(void) {
    reset();
    const pid_key_t child = task(1, 10, 20);
    const pid_key_t parent = task(2, 10, 20);
    const pid_key_t direct_expected[] = {parent};
    link_task(parent, child);
    expect_cycle_result("two-node cycle", child, parent, 1, direct_expected, 1);

    reset();
    const pid_key_t intermediate = task(3, 10, 20);
    const pid_key_t deeper_expected[] = {parent, intermediate};
    link_task(parent, intermediate);
    link_task(intermediate, child);
    expect_cycle_result("deeper child cycle", child, parent, 1, deeper_expected, 2);

    reset();
    const pid_key_t second = task(4, 10, 20);
    const pid_key_t bounded_expected[] = {parent, intermediate, second};
    link_task(parent, intermediate);
    link_task(intermediate, second);
    link_task(second, child);
    expect_cycle_result("child cycle at lookup bound", child, parent, 1, bounded_expected, 3);
}

static void test_preexisting_cycle_is_rejected_with_bounded_lookups(void) {
    reset();
    const pid_key_t parent = task(2, 10, 20);
    const pid_key_t intermediate = task(3, 10, 20);
    const pid_key_t expected[] = {parent, intermediate, parent};
    link_task(parent, intermediate);
    link_task(intermediate, parent);
    expect_cycle_result("preexisting cycle", task(1, 10, 20), parent, 1, expected, 3);

    reset();
    const pid_key_t self_cycle_expected[] = {parent, parent, parent};
    link_task(parent, parent);
    expect_cycle_result(
        "preexisting self-cycle", task(1, 10, 20), parent, 1, self_cycle_expected, 3);
}

static void test_pid_key_identity_uses_tid_pid_and_namespace(void) {
    reset();
    const pid_key_t child = task(7, 10, 20);
    const pid_key_t different_pid = task(7, 11, 20);
    const pid_key_t different_namespace = task(7, 10, 21);
    const pid_key_t different_tid = task(8, 10, 20);
    const pid_key_t pid_expected[] = {different_pid};
    const pid_key_t namespace_expected[] = {different_namespace};
    const pid_key_t tid_expected[] = {different_tid};
    expect_cycle_result("different pid", child, different_pid, 0, pid_expected, 1);
    expect_cycle_result(
        "different namespace", child, different_namespace, 0, namespace_expected, 1);
    expect_cycle_result("different tid", child, different_tid, 0, tid_expected, 1);

    reset();
    const pid_key_t parent = different_tid;
    const pid_key_t pid_chain[] = {parent, different_pid};
    link_task(parent, different_pid);
    expect_cycle_result("ancestor with different pid", child, parent, 0, pid_chain, 2);

    reset();
    const pid_key_t namespace_chain[] = {parent, different_namespace};
    link_task(parent, different_namespace);
    expect_cycle_result("ancestor with different namespace", child, parent, 0, namespace_chain, 2);
}

static void *test_map_lookup(void *map, const void *key) {
    if (map != &java_tasks) {
        fail("map lookup", "unexpected map");
    }
    if (lookup_count >= k_java_remote_parent_max_ancestry) {
        fail("map lookup", "ancestry lookup exceeded its hard bound");
    }
    const pid_key_t *task_key = key;
    lookup_keys[lookup_count++] = *task_key;
    for (size_t i = 0; i < mapping_count; i++) {
        if (same_key(task_key, &mappings[i].child)) {
            return &mappings[i].parent;
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
    fail("map update", "ancestry check mutated a map");
    return -1;
}

static long test_map_delete(void *map, const void *key) {
    (void)map;
    (void)key;
    fail("map delete", "ancestry check mutated a map");
    return -1;
}

static unsigned long long test_ktime_get_ns(void) {
    return 1;
}

static unsigned int test_prandom_u32(void) {
    return 1;
}

static void test_task_tid(pid_key_t *owner) {
    *owner = current_task;
}

static u8 test_java_vt_translate_tid(pid_key_t *owner) {
    (void)owner;
    return 0;
}

static u8 test_java_vt_translate_tid_for_capability(pid_key_t *owner, u64 process_capability) {
    (void)owner;
    (void)process_capability;
    return k_java_vt_cleanup_translation_none;
}

static u64 test_java_current_process_incarnation(void) {
    return 1;
}

static u64 test_java_process_incarnation_for(const pid_key_t *owner) {
    (void)owner;
    return 1;
}

static u64 test_java_process_capability_for(const pid_key_t *owner) {
    (void)owner;
    return 1;
}

static u8 test_java_vt_prepare_unregistered_cleanup(const pid_key_t *carrier,
                                                    u64 vt_id,
                                                    u64 process_capability,
                                                    pid_key_t *synthetic_owner,
                                                    java_vt_identity_t *expected_identity) {
    (void)carrier;
    (void)vt_id;
    (void)process_capability;
    (void)synthetic_owner;
    (void)expected_identity;
    return 0;
}

static u8 test_java_vt_delete_identity_if_matches(const pid_key_t *synthetic_owner,
                                                  const java_vt_identity_t *expected_identity) {
    (void)synthetic_owner;
    (void)expected_identity;
    return 0;
}

int main(void) {
    test_empty_ancestry_is_accepted();
    test_one_edge_is_accepted();
    test_maximum_bounded_ancestry_is_accepted();
    test_ancestry_beyond_bound_is_rejected();
    test_self_mapping_is_rejected_without_lookup();
    test_cycle_reaching_child_is_rejected();
    test_preexisting_cycle_is_rejected_with_bounded_lookups();
    test_pid_key_identity_uses_tid_pid_and_namespace();
    puts("java remote-parent task ancestry tests passed");
    return 0;
}
