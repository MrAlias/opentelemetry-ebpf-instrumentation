// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <stdbool.h>

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/event_defs.h>
#include <common/tp_info.h>

enum ssl_prewrite_local_state : u8 {
    k_ssl_prewrite_local_none = 0,
    k_ssl_prewrite_local_pending = 1,
    k_ssl_prewrite_local_blocked = 2,
};

typedef struct http_info {
    u8 type;
    u8 submitted;
    u8 delayed;
    u8 ssl;
    u8 direction;
    u16 status;
    u8 ssl_prewrite_pending;
    u64 extra_id;
    u64 start_monotime_ns;
    struct {
        u32 ns;
        u32 user_pid;
        u32 host_pid;
    } pid;
    u32 task_tid;
    tp_info_t tp;
} http_info_t;

extern struct bpf_test_map ongoing_http;
extern int test_finish_http_count;
extern int test_terminate_http_count;
extern pid_connection_info_t test_terminated_connection;
extern int test_http_info_available;
extern u8 test_http_will_complete;

static __always_inline u8 http_will_complete(http_info_t *info, unsigned char *buf, u32 len) {
    (void)info;
    (void)buf;
    (void)len;

    return test_http_will_complete;
}

static __always_inline u8 http_info_complete(http_info_t *info) {
    return info && info->start_monotime_ns != 0 && info->status != 0 && info->pid.host_pid != 0;
}

static __always_inline void finish_http(http_info_t *info, pid_connection_info_t *pid_conn) {
    (void)pid_conn;

    if (http_info_complete(info) && !info->submitted) {
        info->submitted = 1;
        test_finish_http_count++;
    }
}

#ifdef OBI_TEST_PROTOCOL_HTTP_SSL_LIFECYCLE
static __always_inline void cleanup_http_request_data(pid_connection_info_t *pid_conn,
                                                      http_info_t *info) {
    if (info && info->type == EVENT_HTTP_REQUEST) {
        trace_key_t key = {};
        key.extra_id = info->extra_id;
        key.p_key.ns = info->pid.ns;
        key.p_key.tid = info->task_tid;
        key.p_key.pid = info->pid.user_pid;
        delete_server_trace(pid_conn, &key);
    }
}

static __always_inline void cleanup_http_info(pid_connection_info_t *pid_conn) {
    bpf_map_delete_elem(&ongoing_http, pid_conn);
}

static __always_inline void terminate_http_request_if_needed(pid_connection_info_t *pid_conn) {
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, pid_conn);

    test_terminate_http_count++;
    test_terminated_connection = *pid_conn;
    cleanup_http_request_data(pid_conn, info);
    if (info && http_info_complete(info) && !info->submitted) {
        finish_http(info, pid_conn);
    }
    cleanup_http_info(pid_conn);
}
#endif
