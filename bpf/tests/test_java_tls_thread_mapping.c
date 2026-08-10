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

#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update
#define bpf_map_delete_elem test_map_delete

#include <common/tp_info.h>
#include <common/trace_key.h>
#include <generictracer/java_ioctl.h>
#include <pid/types/pid_key.h>

static pid_key_t test_process_key(const pid_key_t *task);
static u32 test_tid_from_pid_tgid(u64 id);
static u64 test_process_incarnation(const pid_key_t *task);
static u8 test_register_process_incarnation(u64 incarnation);
static u8 test_process_retirement_pending(const pid_key_t *task, u64 incarnation);
static u8 test_pid_key_equal(const pid_key_t *left, const pid_key_t *right);
static u8 test_would_cycle(const pid_key_t *child, const pid_key_t *parent);
static void test_fail_handoff(const pid_key_t *child, u64 process_incarnation);
static void test_remote_parent_cleanup(const pid_key_t *owner);
static void test_unlink_task(const pid_key_t *owner);
static void test_unlink_task_for_capability(const pid_key_t *owner, u64 process_incarnation);
static u8
test_link_handoff_for_capability(const pid_key_t *owner, u64 token, u64 process_incarnation);
static void
test_cancel_handoff_for_capability(const pid_key_t *owner, u64 token, u64 process_incarnation);
static tp_info_pid_t *test_find_parent(trace_key_t *key);
static u64 test_extra_runtime_id(u64 id);
static long test_context_set(u64 id, const tp_info_t *info);
static long test_context_delete(u64 id);
static long test_probe_read_user(void *destination, u32 size, const void *source);

#define JAVA_THREAD_MAPPING_PROCESS_KEY test_process_key
#define JAVA_THREAD_MAPPING_TID_FROM_PID_TGID test_tid_from_pid_tgid
#define JAVA_THREAD_MAPPING_PROCESS_INCARNATION test_process_incarnation
#define JAVA_THREAD_MAPPING_REGISTER_PROCESS_INCARNATION test_register_process_incarnation
#define JAVA_THREAD_MAPPING_PROCESS_RETIREMENT_PENDING test_process_retirement_pending
#define JAVA_THREAD_MAPPING_PID_KEY_EQUAL test_pid_key_equal
#define JAVA_THREAD_MAPPING_WOULD_CYCLE test_would_cycle
#define JAVA_THREAD_MAPPING_FAIL_HANDOFF test_fail_handoff
#define JAVA_THREAD_MAPPING_REMOTE_PARENT_CLEANUP test_remote_parent_cleanup
#define JAVA_THREAD_MAPPING_UNLINK_TASK test_unlink_task
#define JAVA_THREAD_MAPPING_UNLINK_TASK_FOR_CAPABILITY test_unlink_task_for_capability
#define JAVA_THREAD_MAPPING_LINK_HANDOFF_FOR_CAPABILITY test_link_handoff_for_capability
#define JAVA_THREAD_MAPPING_CANCEL_HANDOFF_FOR_CAPABILITY test_cancel_handoff_for_capability
#define JAVA_THREAD_MAPPING_FIND_PARENT test_find_parent
#define JAVA_THREAD_MAPPING_EXTRA_RUNTIME_ID test_extra_runtime_id
#define JAVA_THREAD_MAPPING_CONTEXT_SET test_context_set
#define JAVA_THREAD_MAPPING_CONTEXT_DELETE test_context_delete
#define JAVA_THREAD_MAPPING_PROBE_READ_USER test_probe_read_user

#include <generictracer/java_thread_mapping.h>

#undef JAVA_THREAD_MAPPING_PROBE_READ_USER
#undef JAVA_THREAD_MAPPING_CONTEXT_DELETE
#undef JAVA_THREAD_MAPPING_CONTEXT_SET
#undef JAVA_THREAD_MAPPING_EXTRA_RUNTIME_ID
#undef JAVA_THREAD_MAPPING_FIND_PARENT
#undef JAVA_THREAD_MAPPING_FAIL_HANDOFF
#undef JAVA_THREAD_MAPPING_UNLINK_TASK_FOR_CAPABILITY
#undef JAVA_THREAD_MAPPING_UNLINK_TASK
#undef JAVA_THREAD_MAPPING_LINK_HANDOFF_FOR_CAPABILITY
#undef JAVA_THREAD_MAPPING_CANCEL_HANDOFF_FOR_CAPABILITY
#undef JAVA_THREAD_MAPPING_REMOTE_PARENT_CLEANUP
#undef JAVA_THREAD_MAPPING_WOULD_CYCLE
#undef JAVA_THREAD_MAPPING_PID_KEY_EQUAL
#undef JAVA_THREAD_MAPPING_PROCESS_INCARNATION
#undef JAVA_THREAD_MAPPING_REGISTER_PROCESS_INCARNATION
#undef JAVA_THREAD_MAPPING_PROCESS_RETIREMENT_PENDING
#undef JAVA_THREAD_MAPPING_TID_FROM_PID_TGID
#undef JAVA_THREAD_MAPPING_PROCESS_KEY
#undef bpf_map_delete_elem
#undef bpf_map_update_elem
#undef bpf_map_lookup_elem

typedef struct task_entry {
    pid_key_t child;
    pid_key_t parent;
    u8 present;
} task_entry_t;

typedef struct context_entry {
    u64 id;
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char span_id[SPAN_ID_SIZE_BYTES];
    u8 present;
} context_entry_t;

typedef struct claim_entry {
    pid_key_t key;
    java_thread_mapping_claim_t claim;
    u8 present;
} claim_entry_t;

enum injection_mode {
    k_inject_none = 0,
    k_inject_nested_contender = 1,
    k_inject_reverse_edge = 2,
    k_inject_replacement = 3,
    k_inject_incarnation_change = 4,
    k_inject_nested_other_process = 5,
    k_inject_incarnation_during_snapshot = 6,
};

enum event_type {
    k_event_claim_update = 1,
    k_event_cycle_check = 2,
    k_event_task_update = 3,
    k_event_unlink_task = 4,
    k_event_fail_handoff = 5,
    k_event_find_parent = 6,
    k_event_context_set = 7,
    k_event_context_delete = 8,
    k_event_claim_delete = 9,
};

enum {
    k_max_task_entries = 12,
    k_max_context_entries = 4,
    k_max_claim_entries = 4,
    k_max_events = 128,
};

static const u64 test_incarnation = 0x1111222233334444ULL;
static const u64 replacement_incarnation = 0x5555666677778888ULL;
static const u64 child_context_id = 0x0000000a00000001ULL;
static const u64 contender_context_id = 0x0000000a00000002ULL;
static const u64 sentinel_context_id = 0x0000000a00000009ULL;
static const pid_key_t child_a = {.tid = 1, .pid = 10, .ns = 20};
static const pid_key_t child_b = {.tid = 2, .pid = 10, .ns = 20};
static const pid_key_t child_c = {.tid = 3, .pid = 10, .ns = 20};
static const pid_key_t child_d = {.tid = 4, .pid = 10, .ns = 20};
static const pid_key_t logical_vt = {.tid = 0x8000002a, .pid = 10, .ns = 20};
static const pid_key_t sentinel_child = {.tid = 9, .pid = 10, .ns = 20};
static const pid_key_t other_child = {.tid = 1, .pid = 11, .ns = 21};
static const pid_key_t other_parent = {.tid = 2, .pid = 11, .ns = 21};

static task_entry_t task_entries[k_max_task_entries];
static context_entry_t context_entries[k_max_context_entries];
static claim_entry_t claim_entries[k_max_claim_entries];
static u64 current_incarnation;
static tp_info_pid_t parent_trace;
static pid_key_t parent_trace_key;
static u8 parent_trace_present;
static u8 fail_task_update;
static u8 fail_context_update;
static u8 fail_parent_read;
static u8 fail_process_registration;
static u8 retirement_pending;
static u8 replace_claim_after_update;
static u8 mutate_parent_trace_on_claim_delete;
static enum injection_mode injection;
static pid_key_t replacement_parent;
static u8 nested_ran;
static int events[k_max_events];
static size_t event_count;
static int task_update_count;
static int task_delete_count;
static int claim_update_count;
static int claim_delete_count;
static int cycle_check_count;
static int fail_handoff_count;
static int process_registration_count;
static int remote_cleanup_count;
static int unlink_task_count;
static int link_handoff_count;
static int cancel_handoff_count;
static int find_parent_count;
static int context_set_count;
static int context_delete_count;
static int probe_read_count;
static pid_key_t last_failed_handoff;
static pid_key_t cleaned_owners[k_max_claim_entries];
static pid_key_t last_unlinked_task;
static pid_key_t last_linked_task;
static u64 last_remote_parent_capability;
static u64 last_handoff_token;
static u64 last_cancelled_token;
static u8 register_during_link;
static u8 nested_registration_result;
static trace_key_t last_trace_key;
static u64 last_extra_runtime_id_input;

static void fail(const char *scenario, const char *message) {
    fprintf(stderr, "FAIL: %s: %s\n", scenario, message);
    exit(1);
}

static void require(int condition, const char *scenario, const char *message) {
    if (!condition) {
        fail(scenario, message);
    }
}

static void record_event(enum event_type event) {
    if (event_count >= k_max_events) {
        fail("event recorder", "too many events");
    }
    events[event_count++] = event;
}

static int same_key(const pid_key_t *left, const pid_key_t *right) {
    return memcmp(left, right, sizeof(*left)) == 0;
}

static task_entry_t *task_entry(const pid_key_t *child) {
    for (size_t i = 0; i < k_max_task_entries; i++) {
        if (task_entries[i].present && same_key(&task_entries[i].child, child)) {
            return &task_entries[i];
        }
    }
    return NULL;
}

static void store_task(pid_key_t child, pid_key_t parent) {
    task_entry_t *entry = task_entry(&child);
    if (entry) {
        entry->parent = parent;
        return;
    }
    for (size_t i = 0; i < k_max_task_entries; i++) {
        if (!task_entries[i].present) {
            task_entries[i] = (task_entry_t){.child = child, .parent = parent, .present = 1};
            return;
        }
    }
    fail("task map", "no free task entry");
}

static int remove_task(const pid_key_t *child) {
    task_entry_t *entry = task_entry(child);
    if (!entry) {
        return 0;
    }
    entry->present = 0;
    return 1;
}

static claim_entry_t *claim_entry(const pid_key_t *key) {
    for (size_t i = 0; i < k_max_claim_entries; i++) {
        if (claim_entries[i].present && same_key(&claim_entries[i].key, key)) {
            return &claim_entries[i];
        }
    }
    return NULL;
}

static size_t claim_count(void) {
    size_t count = 0;
    for (size_t i = 0; i < k_max_claim_entries; i++) {
        count += claim_entries[i].present;
    }
    return count;
}

static void store_claim(pid_key_t key, java_thread_mapping_claim_t claim) {
    claim_entry_t *entry = claim_entry(&key);
    if (entry) {
        entry->claim = claim;
        return;
    }
    for (size_t i = 0; i < k_max_claim_entries; i++) {
        if (!claim_entries[i].present) {
            claim_entries[i] = (claim_entry_t){.key = key, .claim = claim, .present = 1};
            return;
        }
    }
    fail("claim map", "no free claim entry");
}

static context_entry_t *context_entry(u64 id) {
    for (size_t i = 0; i < k_max_context_entries; i++) {
        if (context_entries[i].present && context_entries[i].id == id) {
            return &context_entries[i];
        }
    }
    return NULL;
}

static context_entry_t *context_slot(u64 id) {
    context_entry_t *entry = context_entry(id);
    if (entry) {
        return entry;
    }
    for (size_t i = 0; i < k_max_context_entries; i++) {
        if (!context_entries[i].present) {
            context_entries[i].id = id;
            return &context_entries[i];
        }
    }
    fail("context map", "no free context entry");
    return NULL;
}

static void seed_context(u64 id, unsigned char value) {
    context_entry_t *entry = context_slot(id);
    entry->present = 1;
    memset(entry->trace_id, value, sizeof(entry->trace_id));
    memset(entry->span_id, value, sizeof(entry->span_id));
}

static void seed_parent_trace(pid_key_t parent, u8 valid) {
    parent_trace_key = parent;
    memset(&parent_trace, 0, sizeof(parent_trace));
    for (size_t i = 0; i < sizeof(parent_trace.tp.trace_id); i++) {
        parent_trace.tp.trace_id[i] = (unsigned char)(0x20 + i);
    }
    for (size_t i = 0; i < sizeof(parent_trace.tp.span_id); i++) {
        parent_trace.tp.span_id[i] = (unsigned char)(0x60 + i);
    }
    parent_trace.valid = valid;
    parent_trace_present = 1;
}

static void reset(void) {
    memset(task_entries, 0, sizeof(task_entries));
    memset(context_entries, 0, sizeof(context_entries));
    memset(claim_entries, 0, sizeof(claim_entries));
    memset(&parent_trace, 0, sizeof(parent_trace));
    memset(&parent_trace_key, 0, sizeof(parent_trace_key));
    memset(events, 0, sizeof(events));
    memset(&last_failed_handoff, 0, sizeof(last_failed_handoff));
    memset(&last_trace_key, 0, sizeof(last_trace_key));
    current_incarnation = test_incarnation;
    parent_trace_present = 0;
    fail_task_update = 0;
    fail_context_update = 0;
    fail_parent_read = 0;
    fail_process_registration = 0;
    retirement_pending = 0;
    replace_claim_after_update = 0;
    mutate_parent_trace_on_claim_delete = 0;
    injection = k_inject_none;
    replacement_parent = child_c;
    nested_ran = 0;
    event_count = 0;
    task_update_count = 0;
    task_delete_count = 0;
    claim_update_count = 0;
    claim_delete_count = 0;
    cycle_check_count = 0;
    fail_handoff_count = 0;
    process_registration_count = 0;
    remote_cleanup_count = 0;
    unlink_task_count = 0;
    link_handoff_count = 0;
    cancel_handoff_count = 0;
    find_parent_count = 0;
    context_set_count = 0;
    context_delete_count = 0;
    probe_read_count = 0;
    last_extra_runtime_id_input = 0;
    last_remote_parent_capability = 0;
    last_handoff_token = 0;
    last_cancelled_token = 0;
    register_during_link = 0;
    nested_registration_result = 0;
    memset(cleaned_owners, 0, sizeof(cleaned_owners));
    memset(&last_unlinked_task, 0, sizeof(last_unlinked_task));
    memset(&last_linked_task, 0, sizeof(last_linked_task));
    store_task(sentinel_child, child_d);
    seed_context(sentinel_context_id, 0x7f);
}

static u64 parent_id(const pid_key_t *parent) {
    return ((u64)parent->pid << 32) | parent->tid;
}

static void run_mapping(const pid_key_t *child,
                        const pid_key_t *logical_child,
                        const pid_key_t *parent,
                        u64 context_id,
                        u8 remote_parent_enabled) {
    unsigned char packet[1 + sizeof(u64)] = {0};
    const u64 encoded_parent = parent_id(parent);
    memcpy(packet + 1, &encoded_parent, sizeof(encoded_parent));
    handle_java_thread_mapping_ioctl(
        packet, context_id, child, logical_child, test_incarnation, remote_parent_enabled);
}

static void require_task(const char *scenario, const pid_key_t *child, const pid_key_t *parent) {
    task_entry_t *entry = task_entry(child);
    require(entry != NULL, scenario, "expected task mapping is absent");
    require(same_key(&entry->parent, parent), scenario, "task mapping has the wrong parent");
}

static void require_no_task(const char *scenario, const pid_key_t *child) {
    require(task_entry(child) == NULL, scenario, "unexpected task mapping remains");
}

static void require_sentinel_state(const char *scenario) {
    require_task(scenario, &sentinel_child, &child_d);
    context_entry_t *sentinel = context_entry(sentinel_context_id);
    require(sentinel != NULL, scenario, "sentinel context was removed");
    for (size_t i = 0; i < sizeof(sentinel->trace_id); i++) {
        require(sentinel->trace_id[i] == 0x7f, scenario, "sentinel trace was changed");
    }
}

static int first_event(enum event_type event) {
    for (size_t i = 0; i < event_count; i++) {
        if (events[i] == event) {
            return (int)i;
        }
    }
    return -1;
}

static void require_claim_released(const char *scenario) {
    require(claim_count() == 0, scenario, "thread-mapping claim leaked");
    require(claim_update_count == 1, scenario, "claim was not acquired exactly once");
    require(claim_delete_count == 1, scenario, "owned claim was not released exactly once");
}

static void test_safe_mapping_commits_before_context(void) {
    const char *scenario = "safe mapping";
    reset();
    store_task(child_a, child_c);
    seed_context(child_context_id, 0x55);
    seed_parent_trace(child_b, 1);

    run_mapping(&child_a, &child_a, &child_b, child_context_id, 1);

    require_task(scenario, &child_a, &child_b);
    require_claim_released(scenario);
    require(cycle_check_count == 2, scenario, "mapping was not checked before and after publish");
    require(unlink_task_count == 1 && same_key(&last_unlinked_task, &child_a),
            scenario,
            "accepted mapping did not retire its exact task carrier");
    require(fail_handoff_count == 0,
            scenario,
            "accepted mapping poisoned an unrelated exact generation");
    require(find_parent_count == 1, scenario, "accepted mapping did not resolve its parent");
    require(same_key(&last_trace_key.p_key, &child_b), scenario, "resolver used wrong parent");
    require(last_extra_runtime_id_input == parent_id(&child_b),
            scenario,
            "resolver used wrong parent runtime id");
    context_entry_t *context = context_entry(child_context_id);
    require(context != NULL, scenario, "accepted mapping did not publish context");
    require(memcmp(context->trace_id, parent_trace.tp.trace_id, sizeof(context->trace_id)) == 0,
            scenario,
            "published trace id is wrong");
    require(memcmp(context->span_id, parent_trace.tp.span_id, sizeof(context->span_id)) == 0,
            scenario,
            "published span id is wrong");
    require(first_event(k_event_claim_update) < first_event(k_event_task_update) &&
                first_event(k_event_task_update) < first_event(k_event_find_parent) &&
                first_event(k_event_find_parent) < first_event(k_event_context_set) &&
                first_event(k_event_context_set) < first_event(k_event_unlink_task) &&
                first_event(k_event_unlink_task) < first_event(k_event_claim_delete),
            scenario,
            "publication side effects escaped the claim ordering");
    require_sentinel_state(scenario);
}

static void test_parent_context_is_published_before_claim_release(void) {
    const char *scenario = "context publication";
    reset();
    seed_parent_trace(child_b, 1);
    const tp_info_t expected = parent_trace.tp;
    mutate_parent_trace_on_claim_delete = 1;

    run_mapping(&child_a, &child_a, &child_b, child_context_id, 1);

    context_entry_t *context = context_entry(child_context_id);
    require(context != NULL, scenario, "copied parent context was not published");
    require(memcmp(context->trace_id, expected.trace_id, sizeof(context->trace_id)) == 0,
            scenario,
            "published trace id changed during claim release");
    require(memcmp(context->span_id, expected.span_id, sizeof(context->span_id)) == 0,
            scenario,
            "published span id changed during claim release");
    require(memcmp(parent_trace.tp.trace_id, expected.trace_id, sizeof(expected.trace_id)) != 0,
            scenario,
            "claim-release mutation did not run");
    require_claim_released(scenario);
    require_sentinel_state(scenario);
}

static void test_nested_reciprocal_contender_becomes_miss(void) {
    const char *scenario = "reciprocal contention";
    reset();
    seed_context(contender_context_id, 0x44);
    seed_parent_trace(child_b, 1);
    injection = k_inject_nested_contender;

    run_mapping(&child_a, &child_a, &child_b, child_context_id, 1);

    require(nested_ran, scenario, "nested contender did not execute");
    require_task(scenario, &child_a, &child_b);
    require_no_task(scenario, &child_b);
    require(
        context_entry(contender_context_id) == NULL, scenario, "contender retained stale context");
    require(context_entry(child_context_id) != NULL, scenario, "winner lost exact context");
    require(claim_update_count == 2, scenario, "both publishers did not attempt the claim");
    require(claim_delete_count == 1, scenario, "contender released the winner's claim");
    require(fail_handoff_count == 0 && unlink_task_count == 1,
            scenario,
            "winner or contender used the wrong handoff cleanup");
    require(cycle_check_count == 2, scenario, "winner did not complete both checks");
    require(claim_count() == 0, scenario, "winner claim leaked");
    require_sentinel_state(scenario);
}

static void test_different_process_publishers_do_not_contend(void) {
    const char *scenario = "different process claims";
    reset();
    seed_parent_trace(child_b, 1);
    injection = k_inject_nested_other_process;

    run_mapping(&child_a, &child_a, &child_b, child_context_id, 1);

    require(nested_ran, scenario, "other-process publisher did not execute");
    require_task(scenario, &child_a, &child_b);
    require_task(scenario, &other_child, &other_parent);
    require(context_entry(child_context_id) != NULL, scenario, "outer publisher lost its context");
    require(context_entry(contender_context_id) != NULL,
            scenario,
            "other-process publisher lost its context");
    require(claim_count() == 0 && claim_update_count == 2 && claim_delete_count == 2,
            scenario,
            "independent process claims were not acquired and released separately");
    require(fail_handoff_count == 0 && unlink_task_count == 2 && cycle_check_count == 4,
            scenario,
            "independent process publishers used the wrong commit side effects");
    require_sentinel_state(scenario);
}

static void test_sequential_reciprocal_mapping_is_rejected(void) {
    const char *scenario = "sequential reciprocal";
    reset();
    seed_parent_trace(child_b, 1);
    run_mapping(&child_a, &child_a, &child_b, child_context_id, 1);
    seed_context(contender_context_id, 0x66);
    seed_parent_trace(child_a, 1);

    run_mapping(&child_b, &child_b, &child_a, contender_context_id, 1);

    require_task(scenario, &child_a, &child_b);
    require_no_task(scenario, &child_b);
    require(context_entry(contender_context_id) == NULL,
            scenario,
            "rejected reciprocal mapping retained context");
    require(fail_handoff_count == 1 && same_key(&last_failed_handoff, &child_b) &&
                last_remote_parent_capability == test_incarnation,
            scenario,
            "cyclic ancestry did not retire only the logical task carrier");
    require(find_parent_count == 1, scenario, "rejected mapping reached parent resolution");
    require(claim_count() == 0 && claim_update_count == 2 && claim_delete_count == 2,
            scenario,
            "sequential claim lifecycle is wrong");
    require_sentinel_state(scenario);
}

static void test_rogue_reverse_edge_is_caught_after_publish(void) {
    const char *scenario = "post-publish reciprocal";
    reset();
    seed_context(child_context_id, 0x33);
    injection = k_inject_reverse_edge;

    run_mapping(&child_a, &child_a, &child_b, child_context_id, 1);

    require_no_task(scenario, &child_a);
    require_task(scenario, &child_b, &child_a);
    require(
        context_entry(child_context_id) == NULL, scenario, "postcheck rejection retained context");
    require(cycle_check_count == 2, scenario, "postpublication cycle check did not run");
    require(find_parent_count == 0 && context_set_count == 0,
            scenario,
            "postcheck rejection reached commit-only side effects");
    require(fail_handoff_count == 1 && same_key(&last_failed_handoff, &child_a) &&
                last_remote_parent_capability == test_incarnation,
            scenario,
            "postcheck rejection did not isolate logical carrier cleanup");
    require_claim_released(scenario);
    require_sentinel_state(scenario);
}

static void test_replacement_after_publish_is_not_deleted(void) {
    const char *scenario = "publication replacement";
    reset();
    seed_context(child_context_id, 0x22);
    replacement_parent = child_c;
    injection = k_inject_replacement;

    run_mapping(&child_a, &child_a, &child_b, child_context_id, 1);

    require_task(scenario, &child_a, &child_c);
    require(context_entry(child_context_id) == NULL,
            scenario,
            "superseded publication retained context");
    require(task_delete_count == 0, scenario, "superseding mapping was deleted");
    require(find_parent_count == 0,
            scenario,
            "superseded publication reached commit-only side effects");
    require(fail_handoff_count == 1, scenario, "superseded publication did not fail handoff");
    require_claim_released(scenario);
    require_sentinel_state(scenario);
}

static void test_update_failure_clears_prior_state(void) {
    const char *scenario = "task update failure";
    reset();
    store_task(child_a, child_c);
    seed_context(child_context_id, 0x11);
    fail_task_update = 1;

    run_mapping(&child_a, &child_a, &child_b, child_context_id, 1);

    require_no_task(scenario, &child_a);
    require(context_entry(child_context_id) == NULL, scenario, "stale context survived failure");
    require(find_parent_count == 0, scenario, "failed update reached commit-only side effects");
    require(fail_handoff_count == 1, scenario, "failed update did not fail handoff");
    require_claim_released(scenario);
    require_sentinel_state(scenario);
}

static void test_incarnation_change_rejects_publication(void) {
    const char *scenario = "incarnation change";
    reset();
    seed_context(child_context_id, 0x11);
    injection = k_inject_incarnation_change;

    run_mapping(&child_a, &child_a, &child_b, child_context_id, 1);

    require(current_incarnation == replacement_incarnation,
            scenario,
            "incarnation injection did not run");
    require_no_task(scenario, &child_a);
    require(context_entry(child_context_id) == NULL, scenario, "old incarnation kept context");
    require(fail_handoff_count == 1 && same_key(&last_failed_handoff, &child_a) &&
                last_remote_parent_capability == test_incarnation && find_parent_count == 0,
            scenario,
            "incarnation mismatch did not reject before commit effects");
    require_claim_released(scenario);
    require_sentinel_state(scenario);
}

static void test_incarnation_change_during_snapshot_rejects_publication(void) {
    const char *scenario = "snapshot incarnation change";
    reset();
    seed_context(child_context_id, 0x11);
    seed_parent_trace(child_b, 1);
    injection = k_inject_incarnation_during_snapshot;

    run_mapping(&child_a, &child_a, &child_b, child_context_id, 1);

    require(current_incarnation == replacement_incarnation,
            scenario,
            "snapshot incarnation injection did not run");
    require_no_task(scenario, &child_a);
    require(context_entry(child_context_id) == NULL,
            scenario,
            "late incarnation change retained context");
    require(find_parent_count == 1 && context_set_count == 0,
            scenario,
            "late incarnation change committed its context");
    require(fail_handoff_count == 1 && same_key(&last_failed_handoff, &child_a) &&
                last_remote_parent_capability == test_incarnation,
            scenario,
            "late incarnation change did not isolate logical carrier cleanup");
    require_claim_released(scenario);
    require_sentinel_state(scenario);
}

static void test_precheck_rejection_clears_outer_state(void) {
    const char *scenario = "precheck rejection";
    reset();
    store_task(child_a, child_c);
    store_task(child_b, child_a);
    seed_context(child_context_id, 0x11);

    run_mapping(&child_a, &child_a, &child_b, child_context_id, 1);

    require_no_task(scenario, &child_a);
    require_task(scenario, &child_b, &child_a);
    require(context_entry(child_context_id) == NULL,
            scenario,
            "rejected inner scope exposed outer context");
    require(task_update_count == 0 && find_parent_count == 0,
            scenario,
            "precheck rejection published or resolved a parent");
    require(fail_handoff_count == 1 && same_key(&last_failed_handoff, &child_a) &&
                last_remote_parent_capability == test_incarnation,
            scenario,
            "precheck rejection did not isolate logical carrier cleanup");
    require_claim_released(scenario);
    require_sentinel_state(scenario);
}

static void test_claim_contention_clears_only_contender_state(void) {
    const char *scenario = "claim contention";
    reset();
    store_task(child_a, child_c);
    seed_context(child_context_id, 0x11);
    const pid_key_t process = test_process_key(&child_a);
    store_claim(process,
                (java_thread_mapping_claim_t){
                    .child = child_b,
                    .process_incarnation = test_incarnation,
                });

    run_mapping(&child_a, &logical_vt, &child_b, child_context_id, 1);

    require_no_task(scenario, &child_a);
    require(context_entry(child_context_id) == NULL, scenario, "contender retained context");
    claim_entry_t *winner = claim_entry(&process);
    require(winner && same_key(&winner->claim.child, &child_b),
            scenario,
            "contender disturbed winner claim");
    require(claim_update_count == 1 && claim_delete_count == 0,
            scenario,
            "contender released a claim it did not own");
    require(fail_handoff_count == 0,
            scenario,
            "process-claim contender mutated the logical remote carrier");
    require(task_update_count == 0 && find_parent_count == 0,
            scenario,
            "contender reached publication side effects");
    require_sentinel_state(scenario);
}

static void test_claim_readback_replacement_is_not_released(void) {
    const char *scenario = "claim readback replacement";
    reset();
    store_task(child_a, child_c);
    seed_context(child_context_id, 0x11);
    replace_claim_after_update = 1;

    run_mapping(&child_a, &child_a, &child_b, child_context_id, 1);

    const pid_key_t process = test_process_key(&child_a);
    claim_entry_t *replacement = claim_entry(&process);
    require(replacement && same_key(&replacement->claim.child, &child_b),
            scenario,
            "mismatched replacement claim was removed");
    require_no_task(scenario, &child_a);
    require(context_entry(child_context_id) == NULL,
            scenario,
            "failed claim verification retained context");
    require(claim_update_count == 1 && claim_delete_count == 0,
            scenario,
            "claim verification released a value it did not own");
    require(task_update_count == 0 && fail_handoff_count == 0,
            scenario,
            "failed claim verification reached publication or remote cleanup");
    require_sentinel_state(scenario);
}

static void test_context_update_failure_deletes_stale_context(void) {
    const char *scenario = "context update failure";
    reset();
    seed_context(child_context_id, 0x11);
    seed_parent_trace(child_b, 1);
    fail_context_update = 1;

    run_mapping(&child_a, &child_a, &child_b, child_context_id, 1);

    require_task(scenario, &child_a, &child_b);
    require(context_entry(child_context_id) == NULL,
            scenario,
            "failed context update retained stale context");
    require(context_set_count == 1 && context_delete_count == 1,
            scenario,
            "context failure was not converted to a miss");
    require_claim_released(scenario);
    require_sentinel_state(scenario);
}

static void test_missing_parent_trace_deletes_stale_context(void) {
    const char *scenario = "missing parent trace";
    reset();
    seed_context(child_context_id, 0x11);

    run_mapping(&child_a, &child_a, &child_b, child_context_id, 1);

    require_task(scenario, &child_a, &child_b);
    require(
        context_entry(child_context_id) == NULL, scenario, "missing parent retained stale context");
    require(find_parent_count == 1 && context_set_count == 0 && context_delete_count == 1,
            scenario,
            "missing parent did not produce an explicit context miss");
    require_claim_released(scenario);
    require_sentinel_state(scenario);
}

static void test_parent_read_failure_and_balanced_self_restore(void) {
    const char *read_scenario = "parent read failure";
    reset();
    store_task(child_a, child_c);
    seed_context(child_context_id, 0x11);
    fail_parent_read = 1;
    run_mapping(&child_a, &child_a, &child_b, child_context_id, 1);
    require_no_task(read_scenario, &child_a);
    require(context_entry(child_context_id) == NULL,
            read_scenario,
            "read failure retained stale context");
    require(claim_update_count == 1 && claim_delete_count == 1 && fail_handoff_count == 1,
            read_scenario,
            "read failure did not fence handoff cleanup with the process claim");
    require(probe_read_count == 1, read_scenario, "parent payload was not read exactly once");
    require_sentinel_state(read_scenario);

    const char *self_scenario = "balanced self restore";
    reset();
    store_task(child_a, child_c);
    seed_context(child_context_id, 0x11);
    run_mapping(&child_a, &child_a, &child_a, child_context_id, 1);
    require_no_task(self_scenario, &child_a);
    require(context_entry(child_context_id) == NULL,
            self_scenario,
            "balanced self restore retained stale context");
    require(claim_update_count == 1 && claim_delete_count == 1 && task_update_count == 0 &&
                task_delete_count == 1 && context_delete_count == 1 && fail_handoff_count == 0 &&
                unlink_task_count == 1 && same_key(&last_unlinked_task, &child_a),
            self_scenario,
            "balanced self restore did not unlink without poisoning the exact generation");
    require(probe_read_count == 1, self_scenario, "self restore reread its parent payload");
    require_sentinel_state(self_scenario);
}

static void test_bridge_disabled_read_failure_preserves_legacy_state(void) {
    const char *scenario = "bridge-disabled read failure";
    reset();
    store_task(child_a, child_c);
    seed_context(child_context_id, 0x11);
    fail_parent_read = 1;

    run_mapping(&child_a, &child_a, &child_b, child_context_id, 0);

    require_task(scenario, &child_a, &child_c);
    require(context_entry(child_context_id) != NULL,
            scenario,
            "legacy context was removed after a failed read");
    require(probe_read_count == 1 && task_delete_count == 0 && context_delete_count == 0,
            scenario,
            "disabled read failure changed legacy state");
    require(claim_update_count == 0 && fail_handoff_count == 0,
            scenario,
            "disabled read failure entered bridge logic");
    require_sentinel_state(scenario);
}

static void test_bridge_disabled_self_restore_clears_legacy_state(void) {
    const char *scenario = "bridge-disabled self restore";
    reset();
    store_task(child_a, child_c);
    seed_context(child_context_id, 0x11);

    run_mapping(&child_a, &child_a, &child_a, child_context_id, 0);

    require_no_task(scenario, &child_a);
    require(context_entry(child_context_id) == NULL,
            scenario,
            "balanced legacy restore retained context");
    require(task_delete_count == 1 && context_delete_count == 1,
            scenario,
            "balanced legacy restore did not unlink task state");
    require(claim_update_count == 0 && fail_handoff_count == 0,
            scenario,
            "balanced legacy restore entered remote-parent logic");
    require_sentinel_state(scenario);
}

static void test_task_unlink_clears_physical_state_in_both_bridge_modes(void) {
    const char *disabled_scenario = "bridge-disabled task unlink";
    reset();
    store_task(child_a, child_c);
    seed_context(child_context_id, 0x11);

    java_thread_mapping_unlink_execution(
        &child_a, &logical_vt, child_context_id, test_incarnation, 0);

    require_no_task(disabled_scenario, &child_a);
    require(context_entry(child_context_id) == NULL,
            disabled_scenario,
            "fail-closed unlink retained legacy context");
    require(task_delete_count == 1 && context_delete_count == 1,
            disabled_scenario,
            "fail-closed unlink did not clear physical task state");
    require(unlink_task_count == 0,
            disabled_scenario,
            "disabled bridge attempted logical remote-parent cleanup");
    require_sentinel_state(disabled_scenario);

    const char *enabled_scenario = "bridge-enabled task unlink";
    reset();
    store_task(child_a, child_c);
    seed_context(child_context_id, 0x11);

    java_thread_mapping_unlink_execution(
        &child_a, &logical_vt, child_context_id, test_incarnation, 1);

    require_no_task(enabled_scenario, &child_a);
    require(context_entry(child_context_id) == NULL,
            enabled_scenario,
            "remote-parent unlink retained physical context");
    require(task_delete_count == 1 && context_delete_count == 1,
            enabled_scenario,
            "remote-parent unlink did not clear physical task state");
    require(unlink_task_count == 1 && same_key(&last_unlinked_task, &logical_vt),
            enabled_scenario,
            "remote-parent unlink did not target the logical execution");
    require_sentinel_state(enabled_scenario);
}

static void test_malformed_remote_task_link_clears_preceding_scope(void) {
    const char *scenario = "malformed remote task link";
    reset();
    store_task(child_a, child_c);
    seed_context(child_context_id, 0x11);

    java_thread_mapping_link_remote_execution(
        &child_a, &logical_vt, child_context_id, 0, test_incarnation);

    require_no_task(scenario, &child_a);
    require(context_entry(child_context_id) == NULL,
            scenario,
            "zero-token cleanup retained legacy context");
    require(link_handoff_count == 1 && same_key(&last_linked_task, &logical_vt) &&
                last_handoff_token == 0,
            scenario,
            "zero-token cleanup did not normalize the logical task slot");
    require(
        fail_handoff_count == 0, scenario, "successful zero-token cleanup poisoned its generation");
    require_claim_released(scenario);
    require_sentinel_state(scenario);

    const char *contention = "malformed remote task link contention";
    reset();
    store_task(child_a, child_c);
    seed_context(child_context_id, 0x22);
    const pid_key_t process = test_process_key(&child_a);
    store_claim(process,
                (java_thread_mapping_claim_t){
                    .child = child_b,
                    .process_incarnation = test_incarnation,
                });

    java_thread_mapping_link_remote_execution(
        &child_a, &logical_vt, child_context_id, 0, test_incarnation);

    require_no_task(contention, &child_a);
    require(context_entry(child_context_id) == NULL,
            contention,
            "contended zero-token cleanup retained legacy context");
    require(link_handoff_count == 0 && fail_handoff_count == 0,
            contention,
            "contended zero-token cleanup mutated the logical carrier");
    claim_entry_t *winner = claim_entry(&process);
    require(winner && same_key(&winner->claim.child, &child_b) && claim_update_count == 1 &&
                claim_delete_count == 0,
            contention,
            "contended zero-token cleanup disturbed the process-claim owner");
    require_sentinel_state(contention);
}

static void test_process_registration_serializes_with_mapping_claim(void) {
    const char *contention_scenario = "registration contention";
    reset();
    store_task(child_a, child_c);
    seed_context(child_context_id, 0x11);
    pid_key_t process = test_process_key(&child_a);
    store_claim(process,
                (java_thread_mapping_claim_t){
                    .child = child_b,
                    .process_incarnation = test_incarnation,
                });

    require(!java_thread_mapping_register_process(
                &child_a, &process, child_context_id, replacement_incarnation, 1),
            contention_scenario,
            "contending registration unexpectedly rotated the incarnation");

    require(current_incarnation == test_incarnation,
            contention_scenario,
            "contending registration changed the incarnation");
    require_no_task(contention_scenario, &child_a);
    require(context_entry(child_context_id) == NULL,
            contention_scenario,
            "contending registration retained context");
    claim_entry_t *winner = claim_entry(&process);
    require(winner && same_key(&winner->claim.child, &child_b),
            contention_scenario,
            "contending registration disturbed the active claim");
    require(claim_update_count == 1 && claim_delete_count == 0,
            contention_scenario,
            "contending registration released an unowned claim");
    require(process_registration_count == 0 && remote_cleanup_count == 0 &&
                unlink_task_count == 0 && fail_handoff_count == 0,
            contention_scenario,
            "contending registration mutated remote-parent state");
    require_sentinel_state(contention_scenario);

    const char *rotation_scenario = "registration rotation";
    reset();
    store_task(child_a, child_c);

    require(java_thread_mapping_register_process(
                &child_a, &process, child_context_id, replacement_incarnation, 1),
            rotation_scenario,
            "uncontended registration failed");

    require(current_incarnation == replacement_incarnation,
            rotation_scenario,
            "registration did not rotate the incarnation");
    require_no_task(rotation_scenario, &child_a);
    require(process_registration_count == 1 && remote_cleanup_count == 2 &&
                same_key(&cleaned_owners[0], &child_a) && same_key(&cleaned_owners[1], &process) &&
                unlink_task_count == 1,
            rotation_scenario,
            "rotation did not clean the replaced incarnation");
    require_claim_released(rotation_scenario);
    require_sentinel_state(rotation_scenario);

    const char *retired_scenario = "registration target retirement";
    reset();
    retirement_pending = 1;
    store_task(child_a, child_c);
    seed_context(child_context_id, 0x44);

    require(!java_thread_mapping_register_process(
                &child_a, &process, child_context_id, test_incarnation, 1),
            retired_scenario,
            "registration reopened a retired target capability");
    require(current_incarnation == test_incarnation && process_registration_count == 0 &&
                remote_cleanup_count == 0 && unlink_task_count == 0,
            retired_scenario,
            "retired target registration mutated process state");
    require_task(retired_scenario, &child_a, &child_c);
    require(context_entry(child_context_id) != NULL,
            retired_scenario,
            "retired target registration cleared operation-local state");
    require_claim_released(retired_scenario);
    require_sentinel_state(retired_scenario);

    const char *failure_scenario = "registration update failure";
    reset();
    fail_process_registration = 1;

    require(!java_thread_mapping_register_process(
                &child_a, &process, child_context_id, test_incarnation, 1),
            failure_scenario,
            "failed registration update reported success");
    require(
        process_registration_count == 1, failure_scenario, "registration update was not attempted");
    require_claim_released(failure_scenario);
    require_sentinel_state(failure_scenario);
}

static void test_userspace_process_claim_blocks_and_cannot_be_released_by_bpf(void) {
    const char *scenario = "userspace process claim";
    reset();
    store_task(child_a, child_c);
    seed_context(child_context_id, 0x33);
    pid_key_t process = test_process_key(&child_a);
    const java_thread_mapping_claim_t userspace = {
        .child =
            {
                .tid = 0x12345678,
                .pid = process.pid,
                .ns = process.ns,
            },
        .reserved = 0x80000001,
        .process_incarnation = test_incarnation,
    };
    store_claim(process, userspace);

    require(!java_thread_mapping_register_process(
                &child_a, &process, child_context_id, test_incarnation, 1),
            scenario,
            "PROCESS_REGISTER entered a userspace-owned P");
    java_thread_mapping_link_remote_execution(
        &child_a, &logical_vt, child_context_id, 0x1234, test_incarnation);
    java_thread_mapping_release_claim(&process, &child_a, test_incarnation);

    claim_entry_t *stored = claim_entry(&process);
    require(stored && memcmp(&stored->claim, &userspace, sizeof(userspace)) == 0,
            scenario,
            "BPF adopted or released a tagged userspace P");
    require_no_task(scenario, &child_a);
    require(context_entry(child_context_id) == NULL,
            scenario,
            "TASK_LINK contention retained stale operation-local context");
    require(claim_update_count == 2 && claim_delete_count == 0 && link_handoff_count == 0 &&
                fail_handoff_count == 0 && remote_cleanup_count == 0 && unlink_task_count == 0,
            scenario,
            "userspace P contention mutated process ownership or remote-parent state");
    require(cancel_handoff_count == 1 && same_key(&last_linked_task, &logical_vt) &&
                last_cancelled_token == 0x1234 && last_remote_parent_capability == test_incarnation,
            scenario,
            "contended LINK did not terminally cancel its exact handoff token");
    require_sentinel_state(scenario);
}

static void test_task_link_serializes_with_process_registration(void) {
    const char *link_first = "task link precedes registration";
    reset();
    register_during_link = 1;
    require(java_thread_mapping_link_handoff_for_capability(
                &child_a, &logical_vt, 0x1234, test_incarnation),
            link_first,
            "admitted task link failed");
    require(link_handoff_count == 1 && same_key(&last_linked_task, &logical_vt) &&
                last_handoff_token == 0x1234 && last_remote_parent_capability == test_incarnation,
            link_first,
            "task link did not execute under the process claim");
    require(cancel_handoff_count == 1 && last_cancelled_token == 0x1234,
            link_first,
            "successful task link did not perform its idempotent terminal cancel");
    require(!nested_registration_result && current_incarnation == test_incarnation &&
                process_registration_count == 0,
            link_first,
            "contending registration rotated the process during task link");
    require(claim_count() == 0 && claim_update_count == 2 && claim_delete_count == 1,
            link_first,
            "process fence ownership was not preserved across contention");
    require_sentinel_state(link_first);

    const char *registration_first = "registration precedes stale task link";
    reset();
    pid_key_t process = test_process_key(&child_a);
    require(java_thread_mapping_register_process(
                &child_a, &process, child_context_id, replacement_incarnation, 1),
            registration_first,
            "successor registration failed");
    require(!java_thread_mapping_link_handoff_for_capability(
                &child_a, &logical_vt, 0x5678, test_incarnation),
            registration_first,
            "stale task link was admitted after process rotation");
    require(current_incarnation == replacement_incarnation && link_handoff_count == 0,
            registration_first,
            "stale task link executed after process rotation");
    require(cancel_handoff_count == 1 && last_cancelled_token == 0x5678,
            registration_first,
            "stale task link did not terminally cancel its exact handoff token");
    require(claim_count() == 0 && claim_update_count == 2 && claim_delete_count == 2,
            registration_first,
            "registration/link process claims were not released exactly");
    require_sentinel_state(registration_first);
}

static void test_decoded_parent_path_does_not_reread_user_memory(void) {
    const char *scenario = "decoded parent";
    reset();
    seed_parent_trace(child_b, 1);

    handle_java_thread_mapping(
        parent_id(&child_b), child_context_id, &child_a, &child_a, test_incarnation, 0);

    require_task(scenario, &child_a, &child_b);
    require(context_entry(child_context_id) != NULL,
            scenario,
            "decoded parent did not publish legacy context");
    require(probe_read_count == 0, scenario, "decoded parent path reread user memory");
    require_sentinel_state(scenario);
}

static void test_zero_logical_tid_releases_admitted_process_claim(void) {
    const char *scenario = "zero logical tid";
    reset();
    seed_parent_trace(child_b, 1);
    pid_key_t malformed = child_a;
    malformed.tid = 0;

    run_mapping(&child_a, &malformed, &child_b, child_context_id, 1);

    require_task(scenario, &child_a, &child_b);
    require(context_entry(child_context_id) != NULL,
            scenario,
            "admitted mapping did not publish its operation-local context");
    require(fail_handoff_count == 0 && unlink_task_count == 0,
            scenario,
            "zero logical identity selected a remote carrier mutation");
    require_claim_released(scenario);
    require_sentinel_state(scenario);
}

static void test_bridge_disabled_legacy_mapping_is_preserved(void) {
    const char *scenario = "bridge disabled";
    reset();
    seed_parent_trace(child_b, 1);

    run_mapping(&child_a, &child_a, &child_b, child_context_id, 0);

    require_task(scenario, &child_a, &child_b);
    require(context_entry(child_context_id) != NULL,
            scenario,
            "legacy mapping did not publish context");
    require(claim_update_count == 0 && cycle_check_count == 0 && fail_handoff_count == 0,
            scenario,
            "disabled bridge entered remote-parent claim logic");
    require(probe_read_count == 1, scenario, "legacy mapping reread its parent payload");
    require(find_parent_count == 1, scenario, "legacy mapping did not resolve parent");
    require_sentinel_state(scenario);
}

static void *test_map_lookup(void *map, const void *key) {
    if (map == &java_tasks) {
        task_entry_t *entry = task_entry(key);
        return entry ? &entry->parent : NULL;
    }
    if (map == &java_thread_mapping_claims) {
        claim_entry_t *entry = claim_entry(key);
        return entry ? &entry->claim : NULL;
    }
    fail("map lookup", "unexpected map");
    return NULL;
}

static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags) {
    if (map == &java_thread_mapping_claims) {
        record_event(k_event_claim_update);
        claim_update_count++;
        require(flags == BPF_NOEXIST, "claim update", "claim did not use BPF_NOEXIST");
        if (claim_entry(key)) {
            return -1;
        }
        const pid_key_t claim_key = *(const pid_key_t *)key;
        store_claim(claim_key, *(const java_thread_mapping_claim_t *)value);
        if (replace_claim_after_update) {
            claim_entry_t *entry = claim_entry(&claim_key);
            entry->claim.child = child_b;
        }
        return 0;
    }
    if (map != &java_tasks) {
        fail("map update", "unexpected map");
    }
    record_event(k_event_task_update);
    task_update_count++;
    require(flags == BPF_ANY, "task update", "task mapping did not use BPF_ANY");
    if (fail_task_update) {
        return -1;
    }

    const pid_key_t child = *(const pid_key_t *)key;
    const pid_key_t parent = *(const pid_key_t *)value;
    store_task(child, parent);
    const enum injection_mode selected = injection;
    if (selected != k_inject_incarnation_during_snapshot) {
        injection = k_inject_none;
    }
    if (selected == k_inject_nested_contender) {
        nested_ran = 1;
        seed_parent_trace(child_a, 1);
        run_mapping(&child_b, &child_b, &child_a, contender_context_id, 1);
        seed_parent_trace(child_b, 1);
    } else if (selected == k_inject_reverse_edge) {
        store_task(parent, child);
    } else if (selected == k_inject_replacement) {
        store_task(child, replacement_parent);
    } else if (selected == k_inject_incarnation_change) {
        current_incarnation = replacement_incarnation;
    } else if (selected == k_inject_nested_other_process) {
        nested_ran = 1;
        seed_parent_trace(other_parent, 1);
        run_mapping(&other_child, &other_child, &other_parent, contender_context_id, 1);
        seed_parent_trace(child_b, 1);
    }
    return 0;
}

static long test_map_delete(void *map, const void *key) {
    if (map == &java_thread_mapping_claims) {
        claim_entry_t *entry = claim_entry(key);
        require(entry != NULL, "claim delete", "attempted to delete an unowned claim");
        record_event(k_event_claim_delete);
        claim_delete_count++;
        entry->present = 0;
        if (mutate_parent_trace_on_claim_delete) {
            memset(&parent_trace.tp, 0xee, sizeof(parent_trace.tp));
        }
        return 0;
    }
    if (map == &java_tasks) {
        task_delete_count++;
        remove_task(key);
        return 0;
    }
    fail("map delete", "unexpected map");
    return -1;
}

static pid_key_t test_process_key(const pid_key_t *task) {
    pid_key_t process = *task;
    process.tid = process.pid;
    return process;
}

static u32 test_tid_from_pid_tgid(u64 id) {
    return (u32)id;
}

static u64 test_process_incarnation(const pid_key_t *task) {
    (void)task;
    return current_incarnation;
}

static u8 test_register_process_incarnation(u64 incarnation) {
    process_registration_count++;
    if (fail_process_registration) {
        return 0;
    }
    current_incarnation = incarnation;
    return 1;
}

static u8 test_process_retirement_pending(const pid_key_t *task, u64 incarnation) {
    (void)task;
    (void)incarnation;
    return retirement_pending;
}

static u8 test_pid_key_equal(const pid_key_t *left, const pid_key_t *right) {
    return same_key(left, right);
}

static u8 test_would_cycle(const pid_key_t *child, const pid_key_t *parent) {
    record_event(k_event_cycle_check);
    cycle_check_count++;
    pid_key_t current = *parent;
    for (u8 depth = 0; depth < 3; depth++) {
        if (same_key(child, &current)) {
            return 1;
        }
        task_entry_t *entry = task_entry(&current);
        if (!entry) {
            return 0;
        }
        current = entry->parent;
    }
    return 1;
}

static void test_fail_handoff(const pid_key_t *child, u64 process_incarnation) {
    record_event(k_event_fail_handoff);
    fail_handoff_count++;
    last_failed_handoff = *child;
    last_remote_parent_capability = process_incarnation;
}

static void test_remote_parent_cleanup(const pid_key_t *owner) {
    if (remote_cleanup_count >= k_max_claim_entries) {
        fail("remote cleanup", "too many cleanup calls");
    }
    cleaned_owners[remote_cleanup_count++] = *owner;
}

static void test_unlink_task(const pid_key_t *owner) {
    record_event(k_event_unlink_task);
    unlink_task_count++;
    last_unlinked_task = *owner;
}

static void test_unlink_task_for_capability(const pid_key_t *owner, u64 process_incarnation) {
    test_unlink_task(owner);
    last_remote_parent_capability = process_incarnation;
}

static u8
test_link_handoff_for_capability(const pid_key_t *owner, u64 token, u64 process_incarnation) {
    link_handoff_count++;
    last_linked_task = *owner;
    last_handoff_token = token;
    last_remote_parent_capability = process_incarnation;
    if (register_during_link) {
        register_during_link = 0;
        pid_key_t process = test_process_key(&child_a);
        nested_registration_result = java_thread_mapping_register_process(
            &child_a, &process, child_context_id, replacement_incarnation, 1);
    }
    return 1;
}

static void
test_cancel_handoff_for_capability(const pid_key_t *owner, u64 token, u64 process_incarnation) {
    cancel_handoff_count++;
    last_linked_task = *owner;
    last_cancelled_token = token;
    last_remote_parent_capability = process_incarnation;
}

static tp_info_pid_t *test_find_parent(trace_key_t *key) {
    record_event(k_event_find_parent);
    find_parent_count++;
    last_trace_key = *key;
    if (injection == k_inject_incarnation_during_snapshot) {
        injection = k_inject_none;
        current_incarnation = replacement_incarnation;
    }
    return parent_trace_present && same_key(&key->p_key, &parent_trace_key) ? &parent_trace : NULL;
}

static u64 test_extra_runtime_id(u64 id) {
    last_extra_runtime_id_input = id;
    return id ^ 0xabcdefULL;
}

static long test_context_set(u64 id, const tp_info_t *info) {
    record_event(k_event_context_set);
    context_set_count++;
    if (fail_context_update) {
        return -1;
    }
    context_entry_t *entry = context_slot(id);
    entry->present = 1;
    memcpy(entry->trace_id, info->trace_id, sizeof(entry->trace_id));
    memcpy(entry->span_id, info->span_id, sizeof(entry->span_id));
    return 0;
}

static long test_context_delete(u64 id) {
    record_event(k_event_context_delete);
    context_delete_count++;
    context_entry_t *entry = context_entry(id);
    if (entry) {
        entry->present = 0;
    }
    return 0;
}

static long test_probe_read_user(void *destination, u32 size, const void *source) {
    probe_read_count++;
    if (fail_parent_read) {
        return -1;
    }
    memcpy(destination, source, size);
    return 0;
}

static void test_unavailable_control_workspace_requires_thread_cleanup(void) {
    require(java_control_tail_workspace_miss_requires_cleanup(k_ioctl_java_threads),
            "control workspace miss",
            "THREAD must clean stale execution ancestry");
    require(java_control_tail_workspace_miss_requires_cleanup(k_ioctl_java_task_link),
            "control workspace miss",
            "TASK_LINK must clean stale execution ancestry");
    require(!java_control_tail_workspace_miss_requires_cleanup(k_ioctl_java_task_capture),
            "control workspace miss",
            "TASK_CAPTURE must not be reclassified as an ancestry cleanup operation");
}

int main(void) {
    test_unavailable_control_workspace_requires_thread_cleanup();
    test_safe_mapping_commits_before_context();
    test_parent_context_is_published_before_claim_release();
    test_nested_reciprocal_contender_becomes_miss();
    test_different_process_publishers_do_not_contend();
    test_sequential_reciprocal_mapping_is_rejected();
    test_rogue_reverse_edge_is_caught_after_publish();
    test_replacement_after_publish_is_not_deleted();
    test_update_failure_clears_prior_state();
    test_incarnation_change_rejects_publication();
    test_incarnation_change_during_snapshot_rejects_publication();
    test_precheck_rejection_clears_outer_state();
    test_claim_contention_clears_only_contender_state();
    test_claim_readback_replacement_is_not_released();
    test_context_update_failure_deletes_stale_context();
    test_missing_parent_trace_deletes_stale_context();
    test_parent_read_failure_and_balanced_self_restore();
    test_bridge_disabled_read_failure_preserves_legacy_state();
    test_bridge_disabled_self_restore_clears_legacy_state();
    test_task_unlink_clears_physical_state_in_both_bridge_modes();
    test_malformed_remote_task_link_clears_preceding_scope();
    test_process_registration_serializes_with_mapping_claim();
    test_userspace_process_claim_blocks_and_cannot_be_released_by_bpf();
    test_task_link_serializes_with_process_registration();
    test_decoded_parent_path_does_not_reread_user_memory();
    test_zero_logical_tid_releases_admitted_process_claim();
    test_bridge_disabled_legacy_mapping_is_preserved();
    puts("Java TLS thread-mapping tests passed");
    return 0;
}
