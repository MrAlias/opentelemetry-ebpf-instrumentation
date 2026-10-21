// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/common.h>
#include <common/globals.h>
#include <common/preempt_guard.h>
#include <common/ringbuf.h>
#include <common/scratch_mem.h>
#include <common/trace_helpers.h>
#include <common/trace_parent.h>
#include <pid/pid.h>

enum { k_python_grpc_ioctl = 0x0b10b2 };
enum { k_python_grpc_start = 1, k_python_grpc_end = 2 };

// ABI shared with pkg/internal/cpython/grpc/agent.py. State belongs to one
// blocking invocation; native gRPC worker threads never own this context.
typedef struct python_grpc_call {
    u32 op;
    u32 active;
    tp_info_t tp;
    u64 start;
    u32 status;
    unsigned char path[k_path_max_len];
    unsigned char host[k_host_max_len];
    unsigned char traceparent[k_traceparent_len];
    unsigned char _pad[5];
} python_grpc_call_t;

_Static_assert(__builtin_offsetof(python_grpc_call_t, status) == 64, "Python status ABI");
_Static_assert(__builtin_offsetof(python_grpc_call_t, path) == 68, "Python path ABI");
_Static_assert(__builtin_offsetof(python_grpc_call_t, host) == 168, "Python host ABI");
_Static_assert(__builtin_offsetof(python_grpc_call_t, traceparent) == 268,
               "Python traceparent ABI");

SCRATCH_MEM_TYPED(python_grpc_call, python_grpc_call_t)

static __always_inline int python_grpc_ioctl(void *arg) {
    if (!g_bpf_header_propagation || !g_bpf_probe_write_user_enabled || !arg) {
        return 0;
    }
    python_grpc_call_t *call = python_grpc_call_mem();
    if (!call || bpf_probe_read_user(call, sizeof(*call), arg)) {
        return 0;
    }
    if (call->op == k_python_grpc_start) {
        init_new_trace(&call->tp);
        trace_key_t key = {};
        trace_key_from_pid_tid(&key);
        const tp_info_pid_t *parent = bpf_map_lookup_elem(&server_traces, &key);
        if (parent && parent->valid && valid_trace(parent->tp.trace_id) &&
            should_be_in_same_transaction(&parent->tp, &call->tp)) {
            __builtin_memcpy(call->tp.trace_id, parent->tp.trace_id, sizeof(call->tp.trace_id));
            __builtin_memcpy(call->tp.parent_id, parent->tp.span_id, sizeof(call->tp.parent_id));
            urand_bytes(call->tp.span_id, sizeof(call->tp.span_id));
        }
        call->start = bpf_ktime_get_ns();
        call->tp.ts = call->start;
        make_tp_string(call->traceparent, &call->tp);
        call->active = 0;
        if (!bpf_probe_write_user(arg, call, sizeof(*call))) {
            const u32 active = 1;
            bpf_probe_write_user((unsigned char *)arg +
                                     __builtin_offsetof(python_grpc_call_t, active),
                                 &active,
                                 sizeof(active));
        }
        return 0;
    }
    if (call->op != k_python_grpc_end || call->active != 1 || !valid_trace(call->tp.trace_id)) {
        return 0;
    }
    http_request_trace_t *event = events_ringbuf_reserve(sizeof(*event), 0);
    if (!event) {
        return 0;
    }
    event->type = k_event_type_grpc_client;
    event->status = call->status;
    event->start_monotime_ns = call->start;
    event->end_monotime_ns = bpf_ktime_get_ns();
    event->go_start_monotime_ns = call->start;
    event->content_length = 0;
    event->response_length = 0;
    event->method[0] = '\0';
    event->scheme[0] = '\0';
    event->raw_query[0] = '\0';
    event->pattern[0] = '\0';
    event->is_jsonrpc = false;
    __builtin_memset(&event->conn, 0, sizeof(event->conn));
    event->tp = call->tp;
    __builtin_memcpy(event->path, call->path, sizeof(event->path));
    __builtin_memcpy(event->host, call->host, sizeof(event->host));
    task_pid(&event->pid);
    bpf_ringbuf_submit(event, get_flags());
    return 0;
}

SEC("kprobe")
int GUARDED_PROG(obi_python_grpc_ioctl, struct pt_regs *, ctx) {
    struct pt_regs *__ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    void *arg = 0;
    bpf_probe_read(&arg, sizeof(arg), (void *)&PT_REGS_PARM3(__ctx));
    return python_grpc_ioctl(arg);
}
