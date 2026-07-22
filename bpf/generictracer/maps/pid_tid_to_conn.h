// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/map_sizing.h>

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, ssl_thread_key_t);
    __type(value, ssl_pid_connection_info_t); // the pointer to the file descriptor matching ssl
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
} pid_tid_to_conn SEC(".maps");

static __always_inline ssl_pid_connection_info_t *lookup_pid_tid_connection(u64 pid_tgid,
                                                                            u64 thread_start_time) {
    if (!pid_tgid || !thread_start_time) {
        return NULL;
    }
    const ssl_thread_key_t key = ssl_thread_key(pid_tgid, thread_start_time);
    return bpf_map_lookup_elem(&pid_tid_to_conn, &key);
}

static __always_inline long update_pid_tid_connection(u64 pid_tgid,
                                                      u64 thread_start_time,
                                                      const ssl_pid_connection_info_t *connection,
                                                      u64 flags) {
    if (!pid_tgid || !thread_start_time) {
        return -1;
    }
    const ssl_thread_key_t key = ssl_thread_key(pid_tgid, thread_start_time);
    return bpf_map_update_elem(&pid_tid_to_conn, &key, connection, flags);
}

static __always_inline void delete_pid_tid_connection(u64 pid_tgid, u64 thread_start_time) {
    if (!pid_tgid || !thread_start_time) {
        return;
    }
    const ssl_thread_key_t key = ssl_thread_key(pid_tgid, thread_start_time);
    bpf_map_delete_elem(&pid_tid_to_conn, &key);
}
