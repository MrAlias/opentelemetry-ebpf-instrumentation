// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/tp_info.h>

typedef struct java_http1_parent {
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char span_id[SPAN_ID_SIZE_BYTES];
    u8 flags;
    u8 parent_status;
} java_http1_parent_t;

_Static_assert(sizeof(java_http1_parent_t) == TRACE_ID_SIZE_BYTES + SPAN_ID_SIZE_BYTES + 2,
               "Java HTTP/1 parent context is a packed wire format");

typedef struct java_http1_request {
    tp_info_pid_t tp;
    u32 value_offset;
    u8 parent_status;
    u8 _pad[3];
} java_http1_request_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, pid_connection_info_t);
    __type(value, java_http1_request_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_http1_requests SEC(".maps");
