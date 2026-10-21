// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/globals.h>
#include <common/scratch_mem.h>
#include <common/ssl_helpers.h>
#include <common/trace_parent.h>
#include <maps/python_httpx_requests.h>

enum { k_python_httpx_ioctl = 0x0b10b2, k_python_httpx_tp_length = 55 };
enum { k_python_httpx_begin = 1, k_python_httpx_end = 2 };

// Kept in sync with agent/httpx_agent.py. All writes target this agent-owned buffer.
typedef struct python_httpx_packet {
    u64 magic;
    u32 size;
    u8 operation;
    u8 status;
    u16 source_port;
    u16 destination_port;
    u8 _reserved[6];
    unsigned char source_address[IP_V6_ADDR_LEN];
    unsigned char destination_address[IP_V6_ADDR_LEN];
    unsigned char traceparent[k_python_httpx_tp_length];
    u8 _pad[1];
} python_httpx_packet_t;

_Static_assert(sizeof(python_httpx_packet_t) == 112, "Python HTTPX bridge ABI");

SCRATCH_MEM_TYPED(python_httpx_request, python_httpx_request_t);

static __always_inline void python_httpx_forget_task(const pid_connection_info_t *key,
                                                     const python_httpx_request_t *pending) {
    const python_addr_key_t task_key = {.pid = key->pid, .addr = pending->task.addr};
    const pid_connection_info_t *active = bpf_map_lookup_elem(&python_httpx_tasks, &task_key);
    if (active && !bpf_memcmp(active, key, sizeof(*key))) {
        bpf_map_delete_elem(&python_httpx_tasks, &task_key);
    }
}

static __always_inline void python_httpx_ioctl(void *arg, u64 id) {
    if (!g_bpf_header_propagation || !g_bpf_probe_write_user_enabled) {
        return;
    }
    python_httpx_packet_t packet = {};
    if (bpf_probe_read_user(&packet, sizeof(packet), arg) ||
        packet.magic != 0x4f42495059544831ULL || packet.size != sizeof(packet) ||
        !packet.source_port || !packet.destination_port) {
        return;
    }
    pid_connection_info_t key = {.pid = pid_from_pid_tgid(id)};
    key.conn.s_port = packet.source_port;
    key.conn.d_port = packet.destination_port;
    __builtin_memcpy(key.conn.s_addr, packet.source_address, IP_V6_ADDR_LEN);
    __builtin_memcpy(key.conn.d_addr, packet.destination_address, IP_V6_ADDR_LEN);
    sort_connection_info(&key.conn);
    if (packet.operation == k_python_httpx_end) {
        const python_httpx_request_t *pending = bpf_map_lookup_elem(&python_httpx_requests, &key);
        // Cleanup must also work after cancellation loses the probe-visible task context.
        if (pending) {
            unsigned char value[TP_MAX_VAL_LENGTH];
            make_tp_string(value, &pending->trace.tp);
            if (!bpf_memcmp(value, packet.traceparent, k_python_httpx_tp_length)) {
                python_httpx_forget_task(&key, pending);
                bpf_map_delete_elem(&python_httpx_requests, &key);
            }
        }
        return;
    }
    if (packet.operation != k_python_httpx_begin) {
        return;
    }
    trace_key_t thread_key = {};
    trace_key_from_pid_tid(&thread_key);
    python_task_ref_t task = {};
    if (resolve_python_current_task(&thread_key, id, &task) != PYTHON_TASK_RESOLVED) {
        return;
    }
    python_task_resolution_t resolution = PYTHON_TASK_NOT_FOUND;
    const tp_info_pid_t *parent = find_python_owning_server_trace(id, task, &resolution);
    if (!parent || !parent->valid || !valid_trace(parent->tp.trace_id)) {
        return;
    }
    python_httpx_request_t *pending = python_httpx_request_mem();
    if (!pending) {
        return;
    }
    __builtin_memset(pending, 0, sizeof(*pending));
    pending->trace.tp = parent->tp;
    pending->trace.tp.ts = bpf_ktime_get_ns();
    if (!should_be_in_same_transaction(&parent->tp, &pending->trace.tp)) {
        return;
    }
    __builtin_memcpy(pending->trace.tp.parent_id, parent->tp.span_id, SPAN_ID_SIZE_BYTES);
    urand_bytes(pending->trace.tp.span_id, SPAN_ID_SIZE_BYTES);
    pending->trace.pid = key.pid;
    pending->trace.req_type = k_event_type_http_client;
    pending->trace.valid = 1;
    pending->task = task;
    pending->connection.p_conn = key;
    pending->connection.orig_dport = packet.destination_port;
    pending->parent_status = parent_kind(parent);
    unsigned char value[TP_MAX_VAL_LENGTH];
    make_tp_string(value, &pending->trace.tp);
    if (bpf_map_update_elem(&python_httpx_requests, &key, pending, BPF_ANY)) {
        return;
    }
    const python_addr_key_t task_key = {.pid = key.pid, .addr = task.addr};
    if (bpf_map_update_elem(&python_httpx_tasks, &task_key, &key, BPF_ANY)) {
        bpf_map_delete_elem(&python_httpx_requests, &key);
        return;
    }
    const u8 status = 1;
    if (bpf_probe_write_user(
            &((python_httpx_packet_t *)arg)->traceparent, value, k_python_httpx_tp_length) ||
        bpf_probe_write_user(&((python_httpx_packet_t *)arg)->status, &status, sizeof(status))) {
        bpf_map_delete_elem(&python_httpx_requests, &key);
        bpf_map_delete_elem(&python_httpx_tasks, &task_key);
    }
}

static __always_inline u8 python_httpx_adopt(const pid_connection_info_t *connection,
                                             u8 *parent_status) {
    const python_httpx_request_t *pending = bpf_map_lookup_elem(&python_httpx_requests, connection);
    if (!pending) {
        return 0;
    }
    trace_key_t thread_key = {};
    trace_key_from_pid_tid(&thread_key);
    python_task_ref_t task = {};
    if (resolve_python_current_task(&thread_key, bpf_get_current_pid_tgid(), &task) !=
            PYTHON_TASK_RESOLVED ||
        pending->task.addr != task.addr || pending->task.generation != task.generation) {
        return 0;
    }
    *parent_status = pending->parent_status;
    set_trace_info_for_connection(&connection->conn, TRACE_TYPE_CLIENT, &pending->trace);
    python_httpx_forget_task(connection, pending);
    bpf_map_delete_elem(&python_httpx_requests, connection);
    return 1;
}

static __always_inline const python_httpx_request_t *python_httpx_current_request(u64 id) {
    trace_key_t thread_key = {};
    trace_key_from_pid_tid(&thread_key);
    python_task_ref_t task = {};
    if (resolve_python_current_task(&thread_key, id, &task) != PYTHON_TASK_RESOLVED) {
        return NULL;
    }
    const python_addr_key_t task_key = {.pid = pid_from_pid_tgid(id), .addr = task.addr};
    const pid_connection_info_t *key = bpf_map_lookup_elem(&python_httpx_tasks, &task_key);
    if (!key) {
        return NULL;
    }
    const python_httpx_request_t *pending = bpf_map_lookup_elem(&python_httpx_requests, key);
    if (!pending || pending->task.addr != task.addr ||
        pending->task.generation != task.generation) {
        return NULL;
    }
    return pending;
}

static __always_inline void python_httpx_bind_ssl(u64 id, void *ssl, const void *buf, size_t size) {
    if (!g_bpf_header_propagation || !g_bpf_probe_write_user_enabled) {
        return;
    }
    const python_httpx_request_t *pending = python_httpx_current_request(id);
    if (!pending) {
        return;
    }
    // The agent appends the final header. Match its token before binding an SSL object:
    // application trace callbacks can use other TLS connections on the same task.
    enum { k_header_terminator_size = 4 };
    if (size < k_python_httpx_tp_length + k_header_terminator_size) {
        return;
    }
    unsigned char observed[TP_MAX_VAL_LENGTH] = {};
    if (bpf_probe_read_user(observed,
                            k_python_httpx_tp_length,
                            (const unsigned char *)buf + size - k_header_terminator_size -
                                k_python_httpx_tp_length)) {
        return;
    }
    unsigned char expected[TP_MAX_VAL_LENGTH];
    make_tp_string(expected, &pending->trace.tp);
    if (bpf_memcmp(observed, expected, k_python_httpx_tp_length)) {
        return;
    }
    // MemoryBIO TLS can otherwise inherit another socket used by the asyncio thread.
    ssl_pid_connection_info_t connection = pending->connection;
    set_active_ssl_connection(&connection, ssl);
}
