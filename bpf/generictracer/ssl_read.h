// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#ifndef OBI_SSL_READ_CONTEXT
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <generictracer/ssl_defs.h>

#include <generictracer/maps/ssl_to_pid_tid.h>

#include <maps/active_ssl_read_args.h>
#endif

static __always_inline int ssl_read_size_to_int(size_t size) {
    return size > (size_t)__INT_MAX__ ? __INT_MAX__ : (int)size;
}

static __always_inline void cleanup_ssl_owner(u64 id, u64 ssl, u64 process_start_time) {
    if (!id || !ssl || !process_start_time) {
        return;
    }
    const ssl_pid_key_t key = ssl_pid_key(ssl, pid_from_pid_tgid(id), process_start_time);
    bpf_map_delete_elem(&ssl_to_pid_tid, &key);
}

static __always_inline void cleanup_ssl_args_owner(u64 id, const ssl_args_t *args) {
    if (args) {
        cleanup_ssl_owner(id, args->ssl, task_process_start_time());
    }
}

static __always_inline int publish_ssl_read_args(u64 id,
                                                 u64 process_start_time,
                                                 u64 thread_start_time,
                                                 const ssl_args_t *args) {
    if (!id || !process_start_time || !thread_start_time || !args || !args->ssl) {
        return -1;
    }

    ssl_args_t previous = {};
    ssl_args_t *active = bpf_map_lookup_elem(&active_ssl_read_args, &id);
    const u8 had_previous = active != NULL;
    if (active) {
        __builtin_memcpy(&previous, active, sizeof(previous));
    }

    if (bpf_map_update_elem(&active_ssl_read_args, &id, args, BPF_ANY) != 0) {
        return -1;
    }

    const ssl_pid_key_t key = ssl_pid_key(args->ssl, pid_from_pid_tgid(id), process_start_time);
    const ssl_thread_key_t owner = ssl_thread_key(id, thread_start_time);
    if (!bpf_map_lookup_elem(&ssl_to_pid_tid, &key) &&
        bpf_map_update_elem(&ssl_to_pid_tid, &key, &owner, BPF_NOEXIST) != 0 &&
        !bpf_map_lookup_elem(&ssl_to_pid_tid, &key)) {
        if (!had_previous) {
            bpf_map_delete_elem(&active_ssl_read_args, &id);
        } else if (bpf_map_update_elem(&active_ssl_read_args, &id, &previous, BPF_ANY) != 0) {
            bpf_map_delete_elem(&active_ssl_read_args, &id);
            cleanup_ssl_owner(id, previous.ssl, process_start_time);
        }
        return -1;
    }

    if (had_previous && previous.ssl != args->ssl) {
        cleanup_ssl_owner(id, previous.ssl, process_start_time);
    }
    return 0;
}

static __always_inline void discard_ssl_read_result(u64 id) {
    ssl_args_t *args = bpf_map_lookup_elem(&active_ssl_read_args, &id);
    if (args) {
        cleanup_ssl_args_owner(id, args);
    }
    bpf_map_delete_elem(&active_ssl_read_args, &id);
}

static __always_inline void handle_ssl_read_result(void *ctx, u64 id, int ret) {
    ssl_args_t *args = bpf_map_lookup_elem(&active_ssl_read_args, &id);
    if (!args) {
        return;
    }

    ssl_args_t saved = {};
    __builtin_memcpy(&saved, args, sizeof(saved));
    bpf_map_delete_elem(&active_ssl_read_args, &id);

    handle_ssl_buf(ctx, id, &saved, ret, TCP_RECV);
}

static __always_inline void handle_ssl_read_ex_result(void *ctx, u64 id, int ret) {
    ssl_args_t *args = bpf_map_lookup_elem(&active_ssl_read_args, &id);
    if (!args) {
        bpf_map_delete_elem(&active_ssl_read_args, &id);
        return;
    }

    if (ret != 1) {
        cleanup_ssl_args_owner(id, args);
        bpf_map_delete_elem(&active_ssl_read_args, &id);
        return;
    }

    size_t read_len = 0;
    if (bpf_probe_read_user(&read_len, sizeof(read_len), (void *)args->len_ptr) != 0 ||
        read_len == 0) {
        cleanup_ssl_args_owner(id, args);
        bpf_map_delete_elem(&active_ssl_read_args, &id);
        return;
    }

    ssl_args_t saved = {};
    __builtin_memcpy(&saved, args, sizeof(saved));
    bpf_map_delete_elem(&active_ssl_read_args, &id);

    handle_ssl_buf(ctx, id, &saved, ssl_read_size_to_int(read_len), TCP_RECV);
}
