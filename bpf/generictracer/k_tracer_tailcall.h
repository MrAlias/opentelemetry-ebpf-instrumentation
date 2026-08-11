// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 21);
} jump_table SEC(".maps");

enum {
    // HTTP/1
    k_tail_protocol_http = 0,
    k_tail_continue_protocol_http = 1,
    k_tail_continue2_protocol_http = 2,
    k_tail_continue_protocol_http_tp = 3,
    // TCP
    k_tail_protocol_tcp = 4,
    // Generic
    k_tail_handle_buf_with_args = 5,
    k_tail_continue_netfd_read = 6,
    // HTTP/2 + gRPC
    k_tail_protocol_http2 = 7,
    k_tail_protocol_http2_grpc_frames = 8,
    k_tail_protocol_http2_grpc_handle_start_frame = 9,
    k_tail_protocol_http2_grpc_handle_end_frame = 10,
    k_tail_protocol_http2_grpc_handle_start_frame_server = 11,
    k_tail_protocol_http2_grpc_handle_start_frame_server_finalize = 12,
    // Large buffer multi-batch emission
    k_tail_large_buf_emit_continue = 13,
    // Traceparent validation
    k_tail_continue_protocol_http_tp_validate = 14,
    // Java remote-parent control carriers. These transactions are isolated
    // program roots so legacy kernels never accumulate the syscall parser's
    // stack with their replay/claim frames.
    k_tail_java_task_capture = 15,
    k_tail_java_task_relay_capture = 16,
    k_tail_java_task_link = 17,
    k_tail_java_control_cleanup = 18,
    k_tail_java_threads = 19,
    k_tail_java_lifecycle = 20,
};
