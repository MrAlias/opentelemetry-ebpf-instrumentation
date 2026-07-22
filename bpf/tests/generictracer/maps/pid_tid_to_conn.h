// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/bpf_helpers.h>

extern struct bpf_test_map pid_tid_to_conn;

static __always_inline ssl_pid_connection_info_t *lookup_pid_tid_connection(u64 pid_tgid,
                                                                            u64 thread_start_time) {
    if (!pid_tgid || !thread_start_time) {
        return NULL;
    }
    const ssl_thread_key_t key = ssl_thread_key(pid_tgid, thread_start_time);
    return bpf_map_lookup_elem(&pid_tid_to_conn, &key);
}

static __always_inline void delete_pid_tid_connection(u64 pid_tgid, u64 thread_start_time) {
    if (!pid_tgid || !thread_start_time) {
        return;
    }
    const ssl_thread_key_t key = ssl_thread_key(pid_tgid, thread_start_time);
    bpf_map_delete_elem(&pid_tid_to_conn, &key);
}
