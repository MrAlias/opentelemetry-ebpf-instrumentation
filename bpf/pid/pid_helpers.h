// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

#include <pid/types/pid_info.h>
#include <pid/types/pid_key.h>

#ifndef OBI_TEST_TASK_START_TIME_HELPERS
// Linux exposes /proc/<pid>/stat starttime in USER_HZ ticks. USER_HZ is 100
// on both supported BPF targets, and nsec_to_clock_t() therefore performs
// this exact division for task_struct's nanosecond start timestamp.
enum { k_nsec_per_process_start_tick = 10000000ULL };

// Kernels predating task_struct::start_boottime called the /proc starttime
// source real_start_time. The CO-RE flavor suffix maps this declaration back
// to task_struct without requiring the build kernel to contain the old field.
struct task_struct___real_start_time {
    u64 real_start_time;
} __attribute__((preserve_access_index));

static __always_inline bool process_start_ticks(const struct task_struct *leader, u64 *ticks) {
    if (!leader || !ticks) {
        return false;
    }

    u64 start_ns = 0;
    if (bpf_core_field_exists(((struct task_struct *)0)->start_boottime)) {
        start_ns = BPF_CORE_READ(leader, start_boottime);
    } else if (bpf_core_field_exists(
                   ((struct task_struct___real_start_time *)0)->real_start_time)) {
        start_ns =
            BPF_CORE_READ((const struct task_struct___real_start_time *)leader, real_start_time);
    } else {
        // start_time is intentionally not a fallback: unlike start_boottime
        // (and its old real_start_time name), it does not provably match the
        // starttime value exported by /proc/<pid>/stat across suspend.
        return false;
    }

    *ticks = start_ns / k_nsec_per_process_start_tick;
    return *ticks != 0;
}

static __always_inline bool current_process_start_ticks(u64 *ticks) {
    const struct task_struct *task = (const struct task_struct *)bpf_get_current_task();
    const struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    return process_start_ticks(leader, ticks);
}
#endif

// Good resource on this: https://mozillazg.com/2022/05/ebpf-libbpfgo-get-process-info-en.html
// Using bpf_get_ns_current_pid_tgid is too restrictive for us
static __always_inline void
ns_pid_ppid(const struct task_struct *task, int *pid, int *ppid, u32 *pid_ns_id) {
    struct upid upid;

    unsigned int level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
    struct pid *ns_pid = (struct pid *)BPF_CORE_READ(task, group_leader, thread_pid);
    bpf_probe_read_kernel(&upid, sizeof(upid), &ns_pid->numbers[level]);

    *pid = upid.nr;
    unsigned int p_level = BPF_CORE_READ(task, real_parent, nsproxy, pid_ns_for_children, level);

    struct pid *ns_ppid = (struct pid *)BPF_CORE_READ(task, real_parent, group_leader, thread_pid);
    bpf_probe_read_kernel(&upid, sizeof(upid), &ns_ppid->numbers[p_level]);
    *ppid = upid.nr;

    *pid_ns_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
}

// sets the pid_info value from the current task
static __always_inline void task_pid(pid_info *pid) {
    struct upid upid;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // set host-side PID
    pid->host_pid = (u32)BPF_CORE_READ(task, tgid);

    // set user-side PID
    unsigned int level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
    struct pid *ns_pid = (struct pid *)BPF_CORE_READ(task, group_leader, thread_pid);
    bpf_probe_read_kernel(&upid, sizeof(upid), &ns_pid->numbers[level]);
    pid->user_pid = (u32)upid.nr;

    // set PIDs namespace
    pid->ns = (u32)BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
}

static __always_inline u32 get_task_tid() {
    struct upid upid;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // https://github.com/torvalds/linux/blob/556e2d17cae620d549c5474b1ece053430cd50bc/kernel/pid.c#L324 (type is )
    // set user-side PID
    unsigned int level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
    struct pid *ns_pid = (struct pid *)BPF_CORE_READ(task, thread_pid);
    bpf_probe_read_kernel(&upid, sizeof(upid), &ns_pid->numbers[level]);

    return (u32)upid.nr;
}

#ifndef OBI_TEST_TASK_START_TIME_HELPERS
static __always_inline u64 task_process_start_time() {
    const struct task_struct *task = (const struct task_struct *)bpf_get_current_task();
    return BPF_CORE_READ(task, group_leader, start_time);
}

static __always_inline u64 task_thread_start_time() {
    const struct task_struct *task = (const struct task_struct *)bpf_get_current_task();
    return BPF_CORE_READ(task, start_time);
}
#endif

// TODO: merge pid_key_t and pid_info in a single struct returned by a single
// function replacing both task_pid and task_tid to avoid duplicate work
static __always_inline void task_tid(pid_key_t *tid) {
    struct upid upid;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // https://github.com/torvalds/linux/blob/556e2d17cae620d549c5474b1ece053430cd50bc/kernel/pid.c#L324 (type is )
    // set user-side PID
    unsigned int level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
    struct pid *ns_pid = (struct pid *)BPF_CORE_READ(task, thread_pid);
    bpf_probe_read_kernel(&upid, sizeof(upid), &ns_pid->numbers[level]);
    tid->tid = (u32)upid.nr;
    ns_pid = (struct pid *)BPF_CORE_READ(task, group_leader, thread_pid);
    bpf_probe_read_kernel(&upid, sizeof(upid), &ns_pid->numbers[level]);
    tid->pid = (u32)upid.nr;

    // set PIDs namespace
    tid->ns = (u32)BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
}

static __always_inline u32 pid_from_pid_tgid(u64 id) {
    return (u32)(id >> 32);
}

static __always_inline u32 tid_from_pid_tgid(u64 id) {
    return (u32)(id & 0x0ffffffff);
}

static __always_inline u64 to_pid_tgid(u32 pid, u32 tid) {
    return (u64)((u64)pid << 32) | tid;
}
