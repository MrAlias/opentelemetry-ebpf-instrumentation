// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/globals.h>
#include <common/trace_parent.h>

typedef struct python_http_client_trace {
    tp_info_pid_t trace;
    u64 generation;
    u32 value_offset;
    u8 parent_status;
    u8 _pad[3];
} python_http_client_trace_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, python_addr_key_t);
    __type(value, python_http_client_trace_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} python_http_client_traces SEC(".maps");

typedef struct python_http_trace_scratch {
    python_task_state_t state;
    // bpf_memcmp reads words; keep both buffers aligned.
    unsigned char expected[TP_MAX_VAL_LENGTH];
    u8 _pad1;
    unsigned char transmitted[TP_MAX_VAL_LENGTH];
    u8 _pad2;
} python_http_trace_scratch_t;

SCRATCH_MEM_TYPED(python_http_trace_scratch, python_http_trace_scratch_t);

enum { k_python_http_max_ancestors = 4 };

static __always_inline u8 take_python_http_client_trace(const call_protocol_args_t *args,
                                                        tp_info_pid_t *trace) {
    if (!g_bpf_header_propagation || !g_bpf_probe_write_user_enabled) {
        return k_parent_status_none;
    }

    const u64 id = bpf_get_current_pid_tgid();
    trace_key_t trace_key = {};
    trace_key_from_pid_tid(&trace_key);
    python_task_ref_t task = {};
    if (resolve_python_current_task(&trace_key, id, &task) != PYTHON_TASK_RESOLVED) {
        return k_parent_status_none;
    }
    python_http_trace_scratch_t *scratch = python_http_trace_scratch_mem();
    if (!scratch) {
        return k_parent_status_none;
    }

    for (u8 depth = 0; depth < k_python_http_max_ancestors; ++depth) {
        if (!copy_python_task_state(id, &task, &scratch->state)) {
            return k_parent_status_none;
        }
        const python_addr_key_t key = python_addr_key(id, task.addr);
        const python_http_client_trace_t *pending =
            bpf_map_lookup_elem(&python_http_client_traces, &key);
        if (pending && pending->generation == task.generation &&
            pending->value_offset <= (u32)args->bytes_len &&
            (u32)args->bytes_len - pending->value_offset >= TP_MAX_VAL_LENGTH) {
            make_tp_string(scratch->expected, &pending->trace.tp);
            if (!bpf_probe_read_user(scratch->transmitted,
                                     sizeof(scratch->transmitted),
                                     (const void *)(args->u_buf + pending->value_offset)) &&
                !bpf_memcmp(scratch->expected, scratch->transmitted, sizeof(scratch->expected))) {
                *trace = pending->trace;
                const u8 status = pending->parent_status;
                bpf_map_delete_elem(&python_http_client_traces, &key);
                return status;
            }
        }
        if (!scratch->state.parent.addr) {
            break;
        }
        task = scratch->state.parent;
    }
    return k_parent_status_none;
}
