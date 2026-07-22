// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#define FLAG_CONNECTED 0x01
#define FLAG_SSL_PREWRITE_PUBLISHED 0x02

// Temporary tracking of ssl_read/ssl_read_ex and ssl_write/ssl_write_ex arguments
typedef struct ssl_args {
    u64 ssl;     // SSL struct pointer
    u64 buf;     // pointer to the buffer we read into
    u64 len_ptr; // size_t pointer of the read/written bytes, used only by SSL_read_ex and SSL_write_ex
    u64 flags; // flags
    u64 handoff_id;
    u64 requested_len;
    u64 stack_pointer;
    u32 depth;
    u8 write_api;
    u8 nested_write_api;
    u8 unsafe_nested_write;
    u8 tail_wrapper;
} ssl_args_t;

static __always_inline u8 ssl_args_connected(ssl_args_t *args) {
    return args->flags & FLAG_CONNECTED;
}

static __always_inline void set_ssl_args_connected(ssl_args_t *args) {
    args->flags |= FLAG_CONNECTED;
}
