// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/connection_info.h>
#include <common/event_source.h>
#include <common/tp_info.h>

#define FULL_BUF_SIZE 256

enum ssl_prewrite_local_state : u8 {
    k_ssl_prewrite_local_none = 0,
    k_ssl_prewrite_local_pending = 1,
    k_ssl_prewrite_local_blocked = 2,
};

// Here we keep the information that is sent on the ring buffer
typedef struct http_info {
    u8 flags; // Must be first, we use it to tell what kind of packet we have on the ring buffer
    u8 type;
    u8 ssl;
    u8 delayed;
    connection_info_t conn_info;
    u64 start_monotime_ns;
    u64 end_monotime_ns;
    u64 req_monotime_ns;
    u64 extra_id;
    tp_info_t tp;
    pid_info pid;
    u32 len;
    u32 resp_len;
    u32 task_tid;
    u32 lb_req_bytes;
    u32 lb_res_bytes;
    u16 status;
    unsigned char buf[FULL_BUF_SIZE];
    u8 has_large_buffers;
    u8 direction;
    u8 submitted;
    enum event_source_type event_source;
    u8 ssl_prewrite_pending;
    u8 _pad;
} http_info_t;

static __always_inline u8 http_info_begin_request(http_info_t *info, u8 packet_type, u8 direction) {
    if (!info || packet_type != PACKET_TYPE_REQUEST || info->status || info->start_monotime_ns) {
        return 0;
    }
    info->direction = direction;
    return 1;
}

static __always_inline u8 ssl_prewrite_mark_local_blocked(http_info_t *info) {
    if (!info || info->ssl_prewrite_pending == k_ssl_prewrite_local_blocked) {
        return 0;
    }
    info->ssl_prewrite_pending = k_ssl_prewrite_local_blocked;
    return 1;
}
