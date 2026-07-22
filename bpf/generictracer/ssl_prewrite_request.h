// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/http_info.h>
#include <common/http_types.h>

#include <maps/java_remote_parent_shared.h>
#include <maps/ongoing_http.h>
#include <maps/ssl_prewrite_tp.h>

static __always_inline u8 prepare_ssl_prewrite_request(call_protocol_args_t *args) {
    http_info_t *old_info = bpf_map_lookup_elem(&ongoing_http, &args->pid_conn);
    const u64 now = bpf_ktime_get_ns();
    if (old_info && ssl_prewrite_local_owner_expired(old_info->ssl_prewrite_pending,
                                                     old_info->tp.ts,
                                                     old_info->req_monotime_ns,
                                                     now,
                                                     ssl_prewrite_max_age_ns)) {
        java_remote_parent_stat_add(k_java_remote_parent_stat_inject_stale);
        cleanup_http_request_data(&args->pid_conn, old_info);
        cleanup_http_info(&args->pid_conn);
        old_info = NULL;
    }
    if (old_info) {
        if (!http_info_complete(old_info) && !old_info->submitted) {
            const u8 newly_blocked = ssl_prewrite_mark_local_blocked(old_info);
            block_ssl_prewrite_connection(&args->pid_conn.conn, args->connection_netns_cookie, now);
            if (newly_blocked) {
                java_remote_parent_stat_add(k_java_remote_parent_stat_inject_ambiguous);
            }
            return 0;
        }
        finish_http(old_info, &args->pid_conn);
        cleanup_http_info(&args->pid_conn);
    }

    http_info_t *in = empty_http_info();
    if (!in || !now) {
        return 0;
    }
    __builtin_memcpy(&in->conn_info, &args->pid_conn.conn, sizeof(in->conn_info));
    in->ssl = args->ssl;
    in->direction = args->direction;
    in->ssl_prewrite_pending = k_ssl_prewrite_local_pending;
    in->req_monotime_ns = now;
    if (bpf_map_update_elem(&ongoing_http, &args->pid_conn, in, BPF_NOEXIST) != 0) {
        return 0;
    }
    return 1;
}
