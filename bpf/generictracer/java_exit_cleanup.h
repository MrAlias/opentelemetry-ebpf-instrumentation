// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/trace_key.h>
#include <maps/clone_map.h>
#include <maps/java_tasks.h>
#include <maps/java_vt_threads.h>
#include <maps/server_traces.h>

static __always_inline u8 java_exit_cleanup_required(u32 traced_pid, u8 remote_parent_enabled) {
    return traced_pid || remote_parent_enabled;
}

static __always_inline void java_exit_cleanup_task_maps(
    void *context_map, u64 id, const trace_key_t *task, const trace_key_t *vt_task, u8 vt_keyed) {
    bpf_map_delete_elem(&java_vt_threads, &task->p_key);
    bpf_map_delete_elem(&clone_map, &task->p_key);
    bpf_map_delete_elem(&server_traces, task);
    if (vt_keyed) {
        bpf_map_delete_elem(&server_traces, vt_task);
    }
    bpf_map_delete_elem(context_map, &id);
    bpf_map_delete_elem(&java_tasks, &task->p_key);
}
