// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/tp_info.h>

typedef struct tcp_traceparent_legacy_option {
    u8 kind;
    u8 len;
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char span_id[SPAN_ID_SIZE_BYTES];
} tcp_traceparent_legacy_option_t;

typedef struct tcp_traceparent_option {
    u8 kind;
    u8 len;
    unsigned char trace_id[TRACE_ID_SIZE_BYTES];
    unsigned char span_id[SPAN_ID_SIZE_BYTES];
    u8 flags;
} tcp_traceparent_option_t;

enum {
    k_tcp_traceparent_option_kind = 25,
    k_tcp_header_option_bytes = 40,
    k_tcp_common_syn_option_bytes = 12,
};

_Static_assert(sizeof(tcp_traceparent_legacy_option_t) == 26,
               "legacy TCP traceparent option size mismatch");
_Static_assert(sizeof(tcp_traceparent_option_t) == 27, "TCP traceparent option size mismatch");
_Static_assert(offsetof(tcp_traceparent_option_t, flags) == 26,
               "TCP traceparent flags offset mismatch");
_Static_assert(k_tcp_common_syn_option_bytes + sizeof(tcp_traceparent_option_t) <=
                   k_tcp_header_option_bytes,
               "TCP traceparent option does not fit beside timestamps");
