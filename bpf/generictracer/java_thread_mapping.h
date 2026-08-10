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
#include <maps/java_thread_mapping_claims.h>
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

#ifndef JAVA_THREAD_MAPPING_PROCESS_RETIREMENT_PENDING
#include <maps/java_vt_threads.h>
#define JAVA_THREAD_MAPPING_PROCESS_RETIREMENT_PENDING java_process_retirement_pending_for
#define OBI_JAVA_THREAD_MAPPING_UNDEF_PROCESS_RETIREMENT_PENDING
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

#ifndef JAVA_THREAD_MAPPING_FAIL_HANDOFF
#include <maps/java_remote_parent.h>
#define JAVA_THREAD_MAPPING_FAIL_HANDOFF java_remote_parent_fail_task_carrier_for_capability
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

#ifndef JAVA_THREAD_MAPPING_UNLINK_TASK_FOR_CAPABILITY
#include <maps/java_remote_parent.h>
#define JAVA_THREAD_MAPPING_UNLINK_TASK_FOR_CAPABILITY java_remote_parent_unlink_task_for_capability
#define OBI_JAVA_THREAD_MAPPING_UNDEF_UNLINK_TASK_FOR_CAPABILITY
#endif

#ifndef JAVA_THREAD_MAPPING_LINK_HANDOFF_FOR_CAPABILITY
#include <maps/java_remote_parent.h>
#define JAVA_THREAD_MAPPING_LINK_HANDOFF_FOR_CAPABILITY                                            \
    java_remote_parent_link_handoff_for_capability
#define OBI_JAVA_THREAD_MAPPING_UNDEF_LINK_HANDOFF_FOR_CAPABILITY
#endif

#ifndef JAVA_THREAD_MAPPING_CANCEL_HANDOFF_FOR_CAPABILITY
#include <maps/java_remote_parent.h>
#define JAVA_THREAD_MAPPING_CANCEL_HANDOFF_FOR_CAPABILITY                                          \
    java_remote_parent_cancel_handoff_for_capability
#define OBI_JAVA_THREAD_MAPPING_UNDEF_CANCEL_HANDOFF_FOR_CAPABILITY
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

// PROCESS_REGISTER and TASK_LINK both hold P(process) from capability
// validation through their final mutation. A retiring registration therefore
// cannot install capability B while an admitted capability-A linker still has
// a chance to publish a persistent task carrier. Lock order is
// P -> T -> terminal-delete C(OPEN) -> M(H). Only the successful exact OPEN
// deletion may transfer H; every other terminal observation may only drain it.
static __always_inline u8 java_thread_mapping_link_handoff_for_capability(
    const pid_key_t *task, const pid_key_t *execution, u64 token, u64 process_incarnation) {
    pid_key_t process = {0};
    if (!java_thread_mapping_acquire_claim(task, process_incarnation, &process)) {
        JAVA_THREAD_MAPPING_CANCEL_HANDOFF_FOR_CAPABILITY(execution, token, process_incarnation);
        return 0;
    }
    const u8 linked =
        JAVA_THREAD_MAPPING_PROCESS_INCARNATION(task) == process_incarnation &&
        JAVA_THREAD_MAPPING_LINK_HANDOFF_FOR_CAPABILITY(execution, token, process_incarnation);
    // LINK consumes a one-shot token. The exact terminal cancel is a no-op
    // after a successful H->T transfer and drains H on every pre-/post-claim
    // failure, including process-claim contention.
    JAVA_THREAD_MAPPING_CANCEL_HANDOFF_FOR_CAPABILITY(execution, token, process_incarnation);
    if (!linked) {
        // P is still held. Failure handling may acquire T/C/M, but must not
        // mutate carrier state after exposing the process to another owner.
        JAVA_THREAD_MAPPING_FAIL_HANDOFF(execution, process_incarnation);
    }
    java_thread_mapping_release_claim(&process, task, process_incarnation);
    return linked;
}

static __always_inline void java_thread_mapping_link_remote_execution(
    const pid_key_t *task, const pid_key_t *execution, u64 id, u64 token, u64 process_incarnation) {
    // The physical task owns these operation-local keys in program order.
    // Clear the preceding scope even if P is contended, while leaving every
    // remote carrier/replay mutation to the P owner.
    bpf_map_delete_elem(&java_tasks, task);
    JAVA_THREAD_MAPPING_CONTEXT_DELETE(id);
    pid_key_t process = {0};
    if (!java_thread_mapping_acquire_claim(task, process_incarnation, &process)) {
        JAVA_THREAD_MAPPING_CANCEL_HANDOFF_FOR_CAPABILITY(execution, token, process_incarnation);
        return;
    }
    const u8 linked =
        JAVA_THREAD_MAPPING_PROCESS_INCARNATION(task) == process_incarnation &&
        JAVA_THREAD_MAPPING_LINK_HANDOFF_FOR_CAPABILITY(execution, token, process_incarnation);
    JAVA_THREAD_MAPPING_CANCEL_HANDOFF_FOR_CAPABILITY(execution, token, process_incarnation);
    if (!linked) {
        JAVA_THREAD_MAPPING_FAIL_HANDOFF(execution, process_incarnation);
    }
    java_thread_mapping_release_claim(&process, task, process_incarnation);
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

static __always_inline void java_thread_mapping_report_miss(u64 id) {
    JAVA_THREAD_MAPPING_CONTEXT_DELETE(id);
}

static __always_inline u64 java_thread_mapping_remote_action(u32 logical_tid, u8 failed) {
    return (u64)logical_tid | ((u64)1 << 62) | ((u64)(failed != 0) << 63);
}

static __always_inline u32 java_thread_mapping_action_tid(u64 action) {
    return (u32)action;
}

static __always_inline u8 java_thread_mapping_action_failed(u64 action) {
    return (u8)(action >> 63);
}

static __always_inline u8 java_thread_mapping_action_admitted(u64 action) {
    return (u8)((action >> 62) & 1);
}

// Remote actions are returned only while the exact BPF P(process) claim is
// still installed. Finish the lower T/carrier mutation first and release P as
// the final process operation. A zero action is either legacy mode or process
// contention and is deliberately side-effect free here.
static __always_inline void java_thread_mapping_finish_remote_action(u64 action,
                                                                     const pid_key_t *task,
                                                                     const pid_key_t *logical_child,
                                                                     u64 process_incarnation) {
    if (!java_thread_mapping_action_admitted(action)) {
        return;
    }
    const u32 logical_tid = java_thread_mapping_action_tid(action);
    if (logical_tid) {
        pid_key_t execution = *logical_child;
        execution.tid = logical_tid;
        if (java_thread_mapping_action_failed(action)) {
            JAVA_THREAD_MAPPING_FAIL_HANDOFF(&execution, process_incarnation);
        } else {
            JAVA_THREAD_MAPPING_UNLINK_TASK_FOR_CAPABILITY(&execution, process_incarnation);
        }
    }
    const pid_key_t process = JAVA_THREAD_MAPPING_PROCESS_KEY(task);
    java_thread_mapping_release_claim(&process, task, process_incarnation);
}

static __always_inline void java_thread_mapping_fail_miss(const pid_key_t *child,
                                                          const pid_key_t *attempted_parent,
                                                          u64 id,
                                                          u8 attempted_publication) {
    java_thread_mapping_clear_publication(child, attempted_parent, attempted_publication);
    java_thread_mapping_report_miss(id);
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
                                                                 u64 process_incarnation,
                                                                 u8 remote_parent_enabled) {
    // TASK_UNLINK is also the fail-closed cleanup for the legacy THREAD path.
    // Logical remote-parent state exists only when the bridge is enabled, but
    // physical ancestry and its copied trace context must always be removed.
    if (remote_parent_enabled) {
        JAVA_THREAD_MAPPING_UNLINK_TASK_FOR_CAPABILITY(logical_task, process_incarnation);
    }
    bpf_map_delete_elem(&java_tasks, physical_task);
    JAVA_THREAD_MAPPING_CONTEXT_DELETE(id);
}

static __always_inline u8 java_thread_mapping_register_process(
    const pid_key_t *task, pid_key_t *process, u64 id, u64 incarnation, u8 remote_parent_enabled) {
    (void)id;
    if (remote_parent_enabled && !java_thread_mapping_acquire_claim(task, incarnation, process)) {
        // A foreign P owner may be retiring this exact process capability.
        // Clear only this thread's operation-local legacy state; do not mutate
        // any remote carrier, replay, incarnation, or retirement state beneath
        // that owner's fence.
        bpf_map_delete_elem(&java_tasks, task);
        JAVA_THREAD_MAPPING_CONTEXT_DELETE(id);
        return 0;
    }

    if (remote_parent_enabled &&
        JAVA_THREAD_MAPPING_PROCESS_RETIREMENT_PENDING(task, incarnation)) {
        java_thread_mapping_release_claim(process, task, incarnation);
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

static __noinline u64 handle_java_thread_mapping_legacy(u64 parent_id,
                                                        u64 id,
                                                        const pid_key_t *child) {
    pid_key_t parent = *child;
    parent.tid = JAVA_THREAD_MAPPING_TID_FROM_PID_TGID(parent_id);

    if (parent.tid == child->tid) {
        bpf_map_delete_elem(&java_tasks, child);
        JAVA_THREAD_MAPPING_CONTEXT_DELETE(id);
        return 0;
    }

    bpf_map_update_elem(&java_tasks, child, &parent, BPF_ANY);
    tp_info_t context = {0};
    const u8 context_found = java_thread_mapping_snapshot_context(parent_id, &parent, &context);
    java_thread_mapping_publish_context(id, &context, context_found);
    return 0;
}

static __noinline u64 handle_java_thread_mapping_remote_core(u64 parent_id,
                                                             u64 id,
                                                             const pid_key_t *child,
                                                             const pid_key_t *logical_child,
                                                             u64 process_incarnation) {
    pid_key_t parent = *child;
    parent.tid = JAVA_THREAD_MAPPING_TID_FROM_PID_TGID(parent_id);

    pid_key_t process = {0};
    if (!java_thread_mapping_acquire_claim(child, process_incarnation, &process)) {
        java_thread_mapping_fail_miss(child, &parent, id, 0);
        return 0;
    }

    if (parent.tid == child->tid) {
        // A balanced legacy task scope restores the physical worker as its own
        // parent. Treat that restore as an unlink so neither ancestry nor trace
        // context survives the completed task. When the remote-parent bridge
        // is enabled, retire only this task carrier: completing a legacy scope
        // is not evidence that the owner's exact generation is ambiguous.
        bpf_map_delete_elem(&java_tasks, child);
        JAVA_THREAD_MAPPING_CONTEXT_DELETE(id);
        return java_thread_mapping_remote_action(logical_child->tid, 0);
    }

    u8 attempted_publication = 0;
    if (JAVA_THREAD_MAPPING_PROCESS_INCARNATION(child) != process_incarnation) {
        goto reject;
    }
    if (JAVA_THREAD_MAPPING_WOULD_CYCLE(child, &parent)) {
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
        goto reject;
    }
    if (JAVA_THREAD_MAPPING_WOULD_CYCLE(child, &parent)) {
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
        goto reject;
    }
    if (!java_thread_mapping_current_equals(child, &parent)) {
        goto reject;
    }
    java_thread_mapping_publish_context(id, &context, context_found);
    return java_thread_mapping_remote_action(logical_child->tid, 0);

reject:
    java_thread_mapping_clear_publication(child, &parent, attempted_publication);
    java_thread_mapping_report_miss(id);
    return java_thread_mapping_remote_action(logical_child->tid, 1);
}

static __always_inline u64 handle_java_thread_mapping_deferred(u64 parent_id,
                                                               u64 id,
                                                               const pid_key_t *child,
                                                               const pid_key_t *logical_child,
                                                               u64 process_incarnation,
                                                               u8 remote_parent_enabled) {
    if (!remote_parent_enabled) {
        return handle_java_thread_mapping_legacy(parent_id, id, child);
    }
    return handle_java_thread_mapping_remote_core(
        parent_id, id, child, logical_child, process_incarnation);
}

static __always_inline int handle_java_thread_mapping(u64 parent_id,
                                                      u64 id,
                                                      const pid_key_t *child,
                                                      const pid_key_t *logical_child,
                                                      u64 process_incarnation,
                                                      u8 remote_parent_enabled) {
    const u64 action = handle_java_thread_mapping_deferred(
        parent_id, id, child, logical_child, process_incarnation, remote_parent_enabled);
    java_thread_mapping_finish_remote_action(action, child, logical_child, process_incarnation);
    return 0;
}

static __always_inline u64 handle_java_thread_mapping_ioctl_deferred(unsigned char *uarg,
                                                                     u64 id,
                                                                     const pid_key_t *child,
                                                                     const pid_key_t *logical_child,
                                                                     u64 process_incarnation,
                                                                     u8 remote_parent_enabled) {
    u64 parent_id = 0;
    if (JAVA_THREAD_MAPPING_PROBE_READ_USER(&parent_id, sizeof(parent_id), uarg + 1) != 0) {
        if (remote_parent_enabled) {
            pid_key_t process = {0};
            if (!java_thread_mapping_acquire_claim(child, process_incarnation, &process)) {
                java_thread_mapping_fail_miss(child, child, id, 0);
                return 0;
            }
            java_thread_mapping_fail_miss(child, child, id, 0);
            return java_thread_mapping_remote_action(logical_child->tid, 1);
        }
        return 0;
    }
    return handle_java_thread_mapping_deferred(
        parent_id, id, child, logical_child, process_incarnation, remote_parent_enabled);
}

static __always_inline int handle_java_thread_mapping_ioctl(unsigned char *uarg,
                                                            u64 id,
                                                            const pid_key_t *child,
                                                            const pid_key_t *logical_child,
                                                            u64 process_incarnation,
                                                            u8 remote_parent_enabled) {
    const u64 action = handle_java_thread_mapping_ioctl_deferred(
        uarg, id, child, logical_child, process_incarnation, remote_parent_enabled);
    java_thread_mapping_finish_remote_action(action, child, logical_child, process_incarnation);
    return 0;
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
#ifdef OBI_JAVA_THREAD_MAPPING_UNDEF_UNLINK_TASK_FOR_CAPABILITY
#undef JAVA_THREAD_MAPPING_UNLINK_TASK_FOR_CAPABILITY
#undef OBI_JAVA_THREAD_MAPPING_UNDEF_UNLINK_TASK_FOR_CAPABILITY
#endif

#ifdef OBI_JAVA_THREAD_MAPPING_UNDEF_LINK_HANDOFF_FOR_CAPABILITY
#undef JAVA_THREAD_MAPPING_LINK_HANDOFF_FOR_CAPABILITY
#undef OBI_JAVA_THREAD_MAPPING_UNDEF_LINK_HANDOFF_FOR_CAPABILITY
#endif
#ifdef OBI_JAVA_THREAD_MAPPING_UNDEF_CANCEL_HANDOFF_FOR_CAPABILITY
#undef JAVA_THREAD_MAPPING_CANCEL_HANDOFF_FOR_CAPABILITY
#undef OBI_JAVA_THREAD_MAPPING_UNDEF_CANCEL_HANDOFF_FOR_CAPABILITY
#endif
#ifdef OBI_JAVA_THREAD_MAPPING_UNDEF_REMOTE_PARENT_CLEANUP
#undef JAVA_THREAD_MAPPING_REMOTE_PARENT_CLEANUP
#undef OBI_JAVA_THREAD_MAPPING_UNDEF_REMOTE_PARENT_CLEANUP
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
#ifdef OBI_JAVA_THREAD_MAPPING_UNDEF_PROCESS_RETIREMENT_PENDING
#undef JAVA_THREAD_MAPPING_PROCESS_RETIREMENT_PENDING
#undef OBI_JAVA_THREAD_MAPPING_UNDEF_PROCESS_RETIREMENT_PENDING
#endif
#ifdef OBI_JAVA_THREAD_MAPPING_UNDEF_PROCESS_KEY
#undef JAVA_THREAD_MAPPING_PROCESS_KEY
#undef OBI_JAVA_THREAD_MAPPING_UNDEF_PROCESS_KEY
#endif
#ifdef OBI_JAVA_THREAD_MAPPING_UNDEF_TID_FROM_PID_TGID
#undef JAVA_THREAD_MAPPING_TID_FROM_PID_TGID
#undef OBI_JAVA_THREAD_MAPPING_UNDEF_TID_FROM_PID_TGID
#endif
