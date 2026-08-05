// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/tp_info.h>
#include <common/trace_key.h>
#include <maps/java_tasks.h>
#include <pid/types/pid_key.h>

#ifndef JAVA_THREAD_MAPPING_PROCESS_KEY
#include <maps/java_vt_threads.h>
#define JAVA_THREAD_MAPPING_PROCESS_KEY java_process_key
#define OBI_JAVA_THREAD_MAPPING_UNDEF_PROCESS_KEY
#endif

#ifndef JAVA_THREAD_MAPPING_TID_FROM_PID_TGID
#include <pid/pid_helpers.h>
#define JAVA_THREAD_MAPPING_TID_FROM_PID_TGID tid_from_pid_tgid
#define OBI_JAVA_THREAD_MAPPING_UNDEF_TID_FROM_PID_TGID
#endif

#ifndef JAVA_THREAD_MAPPING_PROCESS_INCARNATION
#include <maps/java_vt_threads.h>
#define JAVA_THREAD_MAPPING_PROCESS_INCARNATION java_process_incarnation_for
#define OBI_JAVA_THREAD_MAPPING_UNDEF_PROCESS_INCARNATION
#endif

#ifndef JAVA_THREAD_MAPPING_REGISTER_PROCESS_INCARNATION
#include <maps/java_vt_threads.h>
#define JAVA_THREAD_MAPPING_REGISTER_PROCESS_INCARNATION java_register_process_incarnation
#define OBI_JAVA_THREAD_MAPPING_UNDEF_REGISTER_PROCESS_INCARNATION
#endif

#ifndef JAVA_THREAD_MAPPING_PID_KEY_EQUAL
#include <maps/java_remote_parent.h>
#define JAVA_THREAD_MAPPING_PID_KEY_EQUAL java_remote_parent_pid_key_equal
#define OBI_JAVA_THREAD_MAPPING_UNDEF_PID_KEY_EQUAL
#endif

#ifndef JAVA_THREAD_MAPPING_WOULD_CYCLE
#include <maps/java_remote_parent.h>
#define JAVA_THREAD_MAPPING_WOULD_CYCLE java_remote_parent_task_mapping_would_cycle
#define OBI_JAVA_THREAD_MAPPING_UNDEF_WOULD_CYCLE
#endif

#ifndef JAVA_THREAD_MAPPING_MARK_AMBIGUOUS
#include <maps/java_remote_parent.h>
#define JAVA_THREAD_MAPPING_MARK_AMBIGUOUS java_remote_parent_mark_ambiguous
#define OBI_JAVA_THREAD_MAPPING_UNDEF_MARK_AMBIGUOUS
#endif

#ifndef JAVA_THREAD_MAPPING_GUARD_OWNER_REUSE
#include <maps/java_remote_parent.h>
#define JAVA_THREAD_MAPPING_GUARD_OWNER_REUSE java_remote_parent_guard_owner_reuse
#define OBI_JAVA_THREAD_MAPPING_UNDEF_GUARD_OWNER_REUSE
#endif

#ifndef JAVA_THREAD_MAPPING_FAIL_HANDOFF
#include <maps/java_remote_parent.h>
#define JAVA_THREAD_MAPPING_FAIL_HANDOFF java_remote_parent_fail_handoff
#define OBI_JAVA_THREAD_MAPPING_UNDEF_FAIL_HANDOFF
#endif

#ifndef JAVA_THREAD_MAPPING_REMOTE_PARENT_CLEANUP
#include <maps/java_remote_parent.h>
#define JAVA_THREAD_MAPPING_REMOTE_PARENT_CLEANUP java_remote_parent_cleanup
#define OBI_JAVA_THREAD_MAPPING_UNDEF_REMOTE_PARENT_CLEANUP
#endif

#ifndef JAVA_THREAD_MAPPING_UNLINK_TASK
#include <maps/java_remote_parent.h>
#define JAVA_THREAD_MAPPING_UNLINK_TASK java_remote_parent_unlink_task
#define OBI_JAVA_THREAD_MAPPING_UNDEF_UNLINK_TASK
#endif

#ifndef JAVA_THREAD_MAPPING_FIND_PARENT
#include <common/trace_parent.h>
#define JAVA_THREAD_MAPPING_FIND_PARENT find_parent_java_trace
#define OBI_JAVA_THREAD_MAPPING_UNDEF_FIND_PARENT
#endif

#ifndef JAVA_THREAD_MAPPING_EXTRA_RUNTIME_ID
#include <common/runtime.h>
#define JAVA_THREAD_MAPPING_EXTRA_RUNTIME_ID extra_runtime_id_with_task_id
#define OBI_JAVA_THREAD_MAPPING_UNDEF_EXTRA_RUNTIME_ID
#endif

#ifndef JAVA_THREAD_MAPPING_CONTEXT_SET
#include <shared/obi_ctx.h>
#define JAVA_THREAD_MAPPING_CONTEXT_SET obi_ctx__set
#define OBI_JAVA_THREAD_MAPPING_UNDEF_CONTEXT_SET
#endif

#ifndef JAVA_THREAD_MAPPING_CONTEXT_DELETE
#include <shared/obi_ctx.h>
#define JAVA_THREAD_MAPPING_CONTEXT_DELETE obi_ctx__del
#define OBI_JAVA_THREAD_MAPPING_UNDEF_CONTEXT_DELETE
#endif

#ifndef JAVA_THREAD_MAPPING_PROBE_READ_USER
#define JAVA_THREAD_MAPPING_PROBE_READ_USER bpf_probe_read_user
#define OBI_JAVA_THREAD_MAPPING_UNDEF_PROBE_READ_USER
#endif

typedef struct java_thread_mapping_claim {
    pid_key_t child;
    u32 reserved;
    u64 process_incarnation;
} java_thread_mapping_claim_t;

_Static_assert(sizeof(java_thread_mapping_claim_t) == 24,
               "Java thread-mapping claim size mismatch");

// Current-agent publishers queue around their synchronous ioctl in Java. This
// process-scoped claim is the fail-closed backstop for stale, duplicate, or
// otherwise uncooperative callers. It is deliberately non-evicting: eviction
// while a publisher is active could admit a reciprocal publication and expose
// a transient cycle.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, pid_key_t);
    __type(value, java_thread_mapping_claim_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_thread_mapping_claims SEC(".maps");

static __always_inline u8 java_thread_mapping_claim_equal(
    const java_thread_mapping_claim_t *left, const java_thread_mapping_claim_t *right) {
    return left->reserved == 0 && right->reserved == 0 &&
           left->process_incarnation == right->process_incarnation &&
           JAVA_THREAD_MAPPING_PID_KEY_EQUAL(&left->child, &right->child);
}

static __always_inline void java_thread_mapping_release_claim(const pid_key_t *process,
                                                              const pid_key_t *child,
                                                              u64 process_incarnation);

static __always_inline u8 java_thread_mapping_acquire_claim(const pid_key_t *child,
                                                            u64 process_incarnation,
                                                            pid_key_t *process) {
    *process = JAVA_THREAD_MAPPING_PROCESS_KEY(child);
    const java_thread_mapping_claim_t claim = {
        .child = *child,
        .process_incarnation = process_incarnation,
    };
    if (bpf_map_update_elem(&java_thread_mapping_claims, process, &claim, BPF_NOEXIST) != 0) {
        return 0;
    }

    const java_thread_mapping_claim_t *published =
        bpf_map_lookup_elem(&java_thread_mapping_claims, process);
    if (published && java_thread_mapping_claim_equal(published, &claim)) {
        return 1;
    }
    java_thread_mapping_release_claim(process, child, process_incarnation);
    return 0;
}

static __always_inline void java_thread_mapping_release_claim(const pid_key_t *process,
                                                              const pid_key_t *child,
                                                              u64 process_incarnation) {
    const java_thread_mapping_claim_t expected = {
        .child = *child,
        .process_incarnation = process_incarnation,
    };
    const java_thread_mapping_claim_t *current =
        bpf_map_lookup_elem(&java_thread_mapping_claims, process);
    if (current && java_thread_mapping_claim_equal(current, &expected)) {
        bpf_map_delete_elem(&java_thread_mapping_claims, process);
    }
}

static __always_inline u8 java_thread_mapping_current_equals(const pid_key_t *child,
                                                             const pid_key_t *parent) {
    const pid_key_t *current = bpf_map_lookup_elem(&java_tasks, child);
    return current && JAVA_THREAD_MAPPING_PID_KEY_EQUAL(current, parent);
}

static __always_inline void java_thread_mapping_delete_if_current(const pid_key_t *child,
                                                                  const pid_key_t *parent) {
    if (java_thread_mapping_current_equals(child, parent)) {
        // Every publisher is admitted through the per-process claim and this
        // physical task is the sole writer for its own key. Lifecycle paths
        // only delete that key in task program order. Under those invariants,
        // the equality check cannot race a legitimate replacement writer.
        bpf_map_delete_elem(&java_tasks, child);
    }
}

static __always_inline void java_thread_mapping_clear_publication(const pid_key_t *child,
                                                                  const pid_key_t *attempted_parent,
                                                                  u8 attempted_publication) {
    if (attempted_publication) {
        java_thread_mapping_delete_if_current(child, attempted_parent);
    } else {
        bpf_map_delete_elem(&java_tasks, child);
    }
}

static __always_inline void java_thread_mapping_report_miss(const pid_key_t *child,
                                                            const pid_key_t *logical_child,
                                                            const pid_key_t *attempted_parent,
                                                            u64 id,
                                                            u8 remote_parent_enabled,
                                                            u8 ambiguous_child,
                                                            u8 ambiguous_parent) {
    JAVA_THREAD_MAPPING_CONTEXT_DELETE(id);
    if (remote_parent_enabled) {
        if (ambiguous_child) {
            JAVA_THREAD_MAPPING_MARK_AMBIGUOUS(child);
        }
        if (ambiguous_parent && !JAVA_THREAD_MAPPING_PID_KEY_EQUAL(child, attempted_parent)) {
            JAVA_THREAD_MAPPING_MARK_AMBIGUOUS(attempted_parent);
        }
        JAVA_THREAD_MAPPING_FAIL_HANDOFF(logical_child);
    }
}

static __always_inline void java_thread_mapping_fail_miss(const pid_key_t *child,
                                                          const pid_key_t *logical_child,
                                                          const pid_key_t *attempted_parent,
                                                          u64 id,
                                                          u8 remote_parent_enabled,
                                                          u8 attempted_publication,
                                                          u8 ambiguous_child,
                                                          u8 ambiguous_parent) {
    java_thread_mapping_clear_publication(child, attempted_parent, attempted_publication);
    java_thread_mapping_report_miss(child,
                                    logical_child,
                                    attempted_parent,
                                    id,
                                    remote_parent_enabled,
                                    ambiguous_child,
                                    ambiguous_parent);
}

static __always_inline u8 java_thread_mapping_snapshot_context(u64 parent_id,
                                                               const pid_key_t *parent,
                                                               tp_info_t *context) {
    trace_key_t trace_key = {
        .p_key = *parent,
        .extra_id = JAVA_THREAD_MAPPING_EXTRA_RUNTIME_ID(parent_id),
    };
    tp_info_pid_t *server_tp = JAVA_THREAD_MAPPING_FIND_PARENT(&trace_key);
    if (!server_tp || !server_tp->valid) {
        return 0;
    }
    *context = server_tp->tp;
    return 1;
}

static __always_inline void
java_thread_mapping_publish_context(u64 id, const tp_info_t *context, u8 context_found) {
    if (!context_found || JAVA_THREAD_MAPPING_CONTEXT_SET(id, context)) {
        JAVA_THREAD_MAPPING_CONTEXT_DELETE(id);
    }
}

static __always_inline void java_thread_mapping_unlink_execution(const pid_key_t *physical_task,
                                                                 const pid_key_t *logical_task,
                                                                 u64 id,
                                                                 u8 remote_parent_enabled) {
    // TASK_UNLINK is also the fail-closed cleanup for the legacy THREAD path.
    // Logical remote-parent state exists only when the bridge is enabled, but
    // physical ancestry and its copied trace context must always be removed.
    if (remote_parent_enabled) {
        JAVA_THREAD_MAPPING_UNLINK_TASK(logical_task);
    }
    bpf_map_delete_elem(&java_tasks, physical_task);
    JAVA_THREAD_MAPPING_CONTEXT_DELETE(id);
}

static __always_inline u8 java_thread_mapping_register_process(
    const pid_key_t *task, pid_key_t *process, u64 id, u64 incarnation, u8 remote_parent_enabled) {
    if (remote_parent_enabled && !java_thread_mapping_acquire_claim(task, incarnation, process)) {
        // A non-cooperating registration must not rotate the process under an
        // active ancestry publication. Current-agent registrations use the
        // same Java monitor as THREAD and therefore do not contend.
        JAVA_THREAD_MAPPING_REMOTE_PARENT_CLEANUP(task);
        JAVA_THREAD_MAPPING_UNLINK_TASK(task);
        bpf_map_delete_elem(&java_tasks, task);
        JAVA_THREAD_MAPPING_CONTEXT_DELETE(id);
        return 0;
    }

    const u64 previous_incarnation = JAVA_THREAD_MAPPING_PROCESS_INCARNATION(task);
    if (remote_parent_enabled && previous_incarnation && previous_incarnation != incarnation) {
        JAVA_THREAD_MAPPING_REMOTE_PARENT_CLEANUP(task);
        JAVA_THREAD_MAPPING_REMOTE_PARENT_CLEANUP(process);
        JAVA_THREAD_MAPPING_UNLINK_TASK(task);
        bpf_map_delete_elem(&java_tasks, task);
    }

    const u8 registered = JAVA_THREAD_MAPPING_REGISTER_PROCESS_INCARNATION(incarnation);
    if (remote_parent_enabled) {
        java_thread_mapping_release_claim(process, task, incarnation);
    }
    return registered;
}

static __always_inline int handle_java_thread_mapping(u64 parent_id,
                                                      u64 id,
                                                      const pid_key_t *child,
                                                      const pid_key_t *logical_child,
                                                      u64 process_incarnation,
                                                      u8 remote_parent_enabled) {
    pid_key_t parent = *child;
    parent.tid = JAVA_THREAD_MAPPING_TID_FROM_PID_TGID(parent_id);

    if (parent.tid == child->tid) {
        if (remote_parent_enabled) {
            java_thread_mapping_fail_miss(
                child, logical_child, &parent, id, remote_parent_enabled, 0, 0, 0);
        } else {
            // A balanced legacy task scope restores the physical worker as its
            // own parent. Treat that restore as an unlink so neither ancestry
            // nor trace context survives the completed task.
            bpf_map_delete_elem(&java_tasks, child);
            JAVA_THREAD_MAPPING_CONTEXT_DELETE(id);
        }
        return 0;
    }

    if (!remote_parent_enabled) {
        bpf_map_update_elem(&java_tasks, child, &parent, BPF_ANY);
        tp_info_t context = {0};
        const u8 context_found = java_thread_mapping_snapshot_context(parent_id, &parent, &context);
        java_thread_mapping_publish_context(id, &context, context_found);
        return 0;
    }

    pid_key_t process = {0};
    if (!java_thread_mapping_acquire_claim(child, process_incarnation, &process)) {
        java_thread_mapping_fail_miss(
            child, logical_child, &parent, id, remote_parent_enabled, 0, 0, 0);
        return 0;
    }

    pid_key_t previous_parent = {0};
    const pid_key_t *previous = bpf_map_lookup_elem(&java_tasks, child);
    const u8 had_previous = previous != NULL;
    if (previous) {
        previous_parent = *previous;
    }

    u8 attempted_publication = 0;
    u8 ambiguous_child = 0;
    u8 ambiguous_parent = 0;
    if (JAVA_THREAD_MAPPING_PROCESS_INCARNATION(child) != process_incarnation) {
        ambiguous_child = 1;
        goto reject;
    }
    if (JAVA_THREAD_MAPPING_WOULD_CYCLE(child, &parent)) {
        ambiguous_child = 1;
        ambiguous_parent = 1;
        goto reject;
    }
    if (bpf_map_update_elem(&java_tasks, child, &parent, BPF_ANY) != 0) {
        goto reject;
    }
    attempted_publication = 1;
    if (!java_thread_mapping_current_equals(child, &parent)) {
        goto reject;
    }
    if (JAVA_THREAD_MAPPING_PROCESS_INCARNATION(child) != process_incarnation) {
        ambiguous_child = 1;
        goto reject;
    }
    if (JAVA_THREAD_MAPPING_WOULD_CYCLE(child, &parent)) {
        ambiguous_child = 1;
        ambiguous_parent = 1;
        goto reject;
    }
    if (!java_thread_mapping_current_equals(child, &parent)) {
        goto reject;
    }

    // Copy the map-backed trace while the ancestry claim is still held. No
    // map-value pointer may survive the release below.
    tp_info_t context = {0};
    const u8 context_found = java_thread_mapping_snapshot_context(parent_id, &parent, &context);
    if (JAVA_THREAD_MAPPING_PROCESS_INCARNATION(child) != process_incarnation) {
        ambiguous_child = 1;
        goto reject;
    }
    if (!java_thread_mapping_current_equals(child, &parent)) {
        goto reject;
    }
    if (had_previous && !JAVA_THREAD_MAPPING_PID_KEY_EQUAL(&previous_parent, &parent)) {
        JAVA_THREAD_MAPPING_GUARD_OWNER_REUSE(child);
    }
    JAVA_THREAD_MAPPING_FAIL_HANDOFF(logical_child);
    java_thread_mapping_publish_context(id, &context, context_found);
    java_thread_mapping_release_claim(&process, child, process_incarnation);
    return 0;

reject:
    java_thread_mapping_clear_publication(child, &parent, attempted_publication);
    java_thread_mapping_release_claim(&process, child, process_incarnation);
    java_thread_mapping_report_miss(child,
                                    logical_child,
                                    &parent,
                                    id,
                                    remote_parent_enabled,
                                    ambiguous_child,
                                    ambiguous_parent);
    return 0;
}

static __always_inline int handle_java_thread_mapping_ioctl(unsigned char *uarg,
                                                            u64 id,
                                                            const pid_key_t *child,
                                                            const pid_key_t *logical_child,
                                                            u64 process_incarnation,
                                                            u8 remote_parent_enabled) {
    u64 parent_id = 0;
    if (JAVA_THREAD_MAPPING_PROBE_READ_USER(&parent_id, sizeof(parent_id), uarg + 1) != 0) {
        if (remote_parent_enabled) {
            java_thread_mapping_fail_miss(
                child, logical_child, child, id, remote_parent_enabled, 0, 0, 0);
        }
        return 0;
    }
    return handle_java_thread_mapping(
        parent_id, id, child, logical_child, process_incarnation, remote_parent_enabled);
}

#ifdef OBI_JAVA_THREAD_MAPPING_UNDEF_PROBE_READ_USER
#undef JAVA_THREAD_MAPPING_PROBE_READ_USER
#undef OBI_JAVA_THREAD_MAPPING_UNDEF_PROBE_READ_USER
#endif
#ifdef OBI_JAVA_THREAD_MAPPING_UNDEF_CONTEXT_DELETE
#undef JAVA_THREAD_MAPPING_CONTEXT_DELETE
#undef OBI_JAVA_THREAD_MAPPING_UNDEF_CONTEXT_DELETE
#endif
#ifdef OBI_JAVA_THREAD_MAPPING_UNDEF_CONTEXT_SET
#undef JAVA_THREAD_MAPPING_CONTEXT_SET
#undef OBI_JAVA_THREAD_MAPPING_UNDEF_CONTEXT_SET
#endif
#ifdef OBI_JAVA_THREAD_MAPPING_UNDEF_EXTRA_RUNTIME_ID
#undef JAVA_THREAD_MAPPING_EXTRA_RUNTIME_ID
#undef OBI_JAVA_THREAD_MAPPING_UNDEF_EXTRA_RUNTIME_ID
#endif
#ifdef OBI_JAVA_THREAD_MAPPING_UNDEF_FIND_PARENT
#undef JAVA_THREAD_MAPPING_FIND_PARENT
#undef OBI_JAVA_THREAD_MAPPING_UNDEF_FIND_PARENT
#endif
#ifdef OBI_JAVA_THREAD_MAPPING_UNDEF_FAIL_HANDOFF
#undef JAVA_THREAD_MAPPING_FAIL_HANDOFF
#undef OBI_JAVA_THREAD_MAPPING_UNDEF_FAIL_HANDOFF
#endif
#ifdef OBI_JAVA_THREAD_MAPPING_UNDEF_UNLINK_TASK
#undef JAVA_THREAD_MAPPING_UNLINK_TASK
#undef OBI_JAVA_THREAD_MAPPING_UNDEF_UNLINK_TASK
#endif
#ifdef OBI_JAVA_THREAD_MAPPING_UNDEF_REMOTE_PARENT_CLEANUP
#undef JAVA_THREAD_MAPPING_REMOTE_PARENT_CLEANUP
#undef OBI_JAVA_THREAD_MAPPING_UNDEF_REMOTE_PARENT_CLEANUP
#endif
#ifdef OBI_JAVA_THREAD_MAPPING_UNDEF_GUARD_OWNER_REUSE
#undef JAVA_THREAD_MAPPING_GUARD_OWNER_REUSE
#undef OBI_JAVA_THREAD_MAPPING_UNDEF_GUARD_OWNER_REUSE
#endif
#ifdef OBI_JAVA_THREAD_MAPPING_UNDEF_MARK_AMBIGUOUS
#undef JAVA_THREAD_MAPPING_MARK_AMBIGUOUS
#undef OBI_JAVA_THREAD_MAPPING_UNDEF_MARK_AMBIGUOUS
#endif
#ifdef OBI_JAVA_THREAD_MAPPING_UNDEF_WOULD_CYCLE
#undef JAVA_THREAD_MAPPING_WOULD_CYCLE
#undef OBI_JAVA_THREAD_MAPPING_UNDEF_WOULD_CYCLE
#endif
#ifdef OBI_JAVA_THREAD_MAPPING_UNDEF_PID_KEY_EQUAL
#undef JAVA_THREAD_MAPPING_PID_KEY_EQUAL
#undef OBI_JAVA_THREAD_MAPPING_UNDEF_PID_KEY_EQUAL
#endif
#ifdef OBI_JAVA_THREAD_MAPPING_UNDEF_PROCESS_INCARNATION
#undef JAVA_THREAD_MAPPING_PROCESS_INCARNATION
#undef OBI_JAVA_THREAD_MAPPING_UNDEF_PROCESS_INCARNATION
#endif
#ifdef OBI_JAVA_THREAD_MAPPING_UNDEF_REGISTER_PROCESS_INCARNATION
#undef JAVA_THREAD_MAPPING_REGISTER_PROCESS_INCARNATION
#undef OBI_JAVA_THREAD_MAPPING_UNDEF_REGISTER_PROCESS_INCARNATION
#endif
#ifdef OBI_JAVA_THREAD_MAPPING_UNDEF_PROCESS_KEY
#undef JAVA_THREAD_MAPPING_PROCESS_KEY
#undef OBI_JAVA_THREAD_MAPPING_UNDEF_PROCESS_KEY
#endif
#ifdef OBI_JAVA_THREAD_MAPPING_UNDEF_TID_FROM_PID_TGID
#undef JAVA_THREAD_MAPPING_TID_FROM_PID_TGID
#undef OBI_JAVA_THREAD_MAPPING_UNDEF_TID_FROM_PID_TGID
#endif
