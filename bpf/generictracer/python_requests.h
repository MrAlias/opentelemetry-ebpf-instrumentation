// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/globals.h>
#include <common/http_types.h>
#include <common/trace_parent.h>
#include <common/tracing.h>

#include <maps/python_requests.h>

enum {
    k_python_requests_ioctl = 0x0b10b2,
    k_python_requests_version = 1,
    k_python_requests_prepare = 1,
    k_python_requests_clear = 2,
};

// Shared with pkg/internal/pythonagent/session.py.
typedef struct python_request_packet {
    u32 version;
    u32 operation;
    connection_info_t conn;
    unsigned char traceparent[TP_MAX_VAL_LENGTH + 1];
} python_request_packet_t;

_Static_assert(sizeof(python_request_packet_t) == 100, "Python requests bridge ABI");

static __always_inline int python_requests_ioctl(u64 id, void *arg) {
    if (!g_bpf_header_propagation || !g_bpf_probe_write_user_enabled || !arg) {
        return 0;
    }

    python_request_packet_t packet = {};
    if (bpf_probe_read_user(&packet, sizeof(packet), arg) ||
        packet.version != k_python_requests_version) {
        return 0;
    }

    pid_connection_info_t key = {
        .conn = packet.conn,
        .pid = pid_from_pid_tgid(id),
    };
    const u16 orig_dport = key.conn.d_port;
    sort_connection_info(&key.conn);

    if (packet.operation == k_python_requests_clear) {
        const python_request_context_t *context = bpf_map_lookup_elem(&python_requests, &key);
        if (context && context->thread_id == id) {
            bpf_map_delete_elem(&python_requests, &key);
        }
        return 0;
    }
    if (packet.operation != k_python_requests_prepare || is_empty_connection_info(&key.conn)) {
        return 0;
    }

    python_request_context_t context = {
        .trace =
            {
                .tp = {.ts = bpf_ktime_get_ns(), .flags = k_flag_sampled},
                .pid = key.pid,
                .valid = 1,
                .written = 1,
                .req_type = k_event_type_http_client,
            },
        .thread_id = id,
        .thread_start_time = python_requests_thread_start_time(),
    };
    if (!context.thread_start_time) {
        return 0;
    }
    urand_bytes(context.trace.tp.span_id, sizeof(context.trace.tp.span_id));
    context.parent_status =
        find_trace_for_client_request(&key, orig_dport, k_lw_thread_none, &context.trace.tp);
    if (!context.parent_status) {
        new_trace_id(&context.trace.tp);
    }
    make_tp_string(packet.traceparent, &context.trace.tp);

    if (bpf_map_update_elem(&python_requests, &key, &context, BPF_ANY)) {
        return 0;
    }
    if (bpf_probe_write_user(((python_request_packet_t *)arg)->traceparent,
                             packet.traceparent,
                             sizeof(packet.traceparent))) {
        bpf_map_delete_elem(&python_requests, &key);
    }
    return 0;
}
