// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#define TRACE_ID_SIZE_BYTES 16
#define SPAN_ID_SIZE_BYTES 8

// Values from https://www.w3.org/TR/trace-context/
enum tp_flags : u8 {
    k_flag_sampled = 1,
};

enum tp_provenance : u8 {
    k_tp_provenance_unknown = 0,
    k_tp_provenance_tcp_legacy = 1,
    k_tp_provenance_tcp_exact_flags = 2,
    k_tp_provenance_ssl_prewrite = 3,
};

typedef struct tp_info {
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char span_id[SPAN_ID_SIZE_BYTES];
    unsigned char parent_id[SPAN_ID_SIZE_BYTES];
    u64 ts;
    u8 flags;
    u8 _pad[7];
} tp_info_t;

typedef struct tp_info_pid {
    tp_info_t tp;
    u32 pid;
    u8 valid;
    u8 written;
    u8 req_type;
    u8 provenance;
} tp_info_pid_t;

static __always_inline void set_client_trace_parent(tp_info_t *child, const tp_info_t *parent) {
    __builtin_memcpy(child->trace_id, parent->trace_id, sizeof(child->trace_id));
    __builtin_memcpy(child->parent_id, parent->span_id, sizeof(child->parent_id));
    child->flags = parent->flags;
}
