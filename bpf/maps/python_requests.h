// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_core_read.h>

#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/tp_info.h>

typedef struct python_request_context {
    tp_info_pid_t trace;
    u64 thread_id;
    u64 thread_start_time;
    u8 parent_status;
    u8 _pad[7];
} python_request_context_t;

// Armed only while the runtime wrapper sends one HTTP/1 header block.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_connection_info_t);
    __type(value, python_request_context_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} python_requests SEC(".maps");

static __always_inline u64 python_requests_thread_start_time(void) {
    const struct task_struct *task = (const struct task_struct *)bpf_get_current_task();
    return BPF_CORE_READ(task, start_time);
}

static __always_inline bool python_requests_owned_by(const python_request_context_t *context,
                                                     u64 id) {
    return context && context->thread_id == id && context->thread_start_time &&
           context->thread_start_time == python_requests_thread_start_time();
}
