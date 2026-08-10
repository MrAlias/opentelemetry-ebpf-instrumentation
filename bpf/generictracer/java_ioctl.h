// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

enum { k_ioctl_magic_id = 0x0b10b1 };
enum {
    k_ioctl_java_send = 1,
    k_ioctl_java_recv = 2,
    k_ioctl_java_threads = 3,
    k_ioctl_java_vt_mount = 4,   // virtual thread mounted on this carrier
    k_ioctl_java_vt_unmount = 5, // virtual thread unmounted from this carrier
    k_ioctl_java_task_capture = 6,
    k_ioctl_java_task_cancel = 7,
    k_ioctl_java_task_link = 8,
    k_ioctl_java_task_relay_capture = 9,
    k_ioctl_java_process_register = 10,
    k_ioctl_java_vt_terminate = 11,
    k_ioctl_java_task_unlink = 12,
    k_ioctl_java_tls_connection = 13,
    k_ioctl_java_http1_receive_start = 14,
    k_ioctl_java_http1_receive_continue = 15,
    k_ioctl_java_http1_receive_reset = 16,
    k_ioctl_java_telemetry_receive = 17,
};

// A missing control-tail workspace must fail closed for operations that can
// leave execution ancestry behind. Their cleanup tail has a local-map fallback
// when its own workspace is also unavailable.
static __always_inline u8 java_control_tail_workspace_miss_requires_cleanup(u8 operation) {
    return operation == k_ioctl_java_task_link || operation == k_ioctl_java_threads;
}
