// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#ifndef OBI_SSL_OPERATION_CLEANUP_CONTEXT
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/ssl_args.h>

#include <generictracer/ssl_read.h>
#include <generictracer/ssl_write_lifecycle.h>

#include <maps/active_ssl_read_args.h>
#include <maps/active_ssl_shutdown_args.h>
#include <maps/active_ssl_write_args.h>
#endif

static __always_inline void cleanup_replaced_ssl_write_owner(u64 id,
                                                             enum ssl_wrapper_entry_action action,
                                                             const ssl_args_t *replaced,
                                                             u64 replacement_ssl) {
    if (action == k_ssl_wrapper_entry_recover_stale && replaced &&
        replaced->ssl != replacement_ssl) {
        cleanup_ssl_args_owner(id, replaced);
    }
}

static __always_inline void cleanup_returned_ssl_write_owner(u64 id,
                                                             enum ssl_write_return_state state,
                                                             const ssl_args_t *saved) {
    if (state == k_ssl_write_return_unsafe) {
        cleanup_ssl_args_owner(id, saved);
    }
}

static __always_inline void cleanup_failed_ssl_write_start(u64 id, const ssl_args_t *args) {
    cleanup_ssl_args_owner(id, args);
}

static __always_inline void cleanup_exited_ssl_operations(u64 id, u64 thread_start_time) {
    const u64 process_start_time = task_process_start_time();
    ssl_thread_key_t thread_key = {};
    if (thread_start_time) {
        thread_key = ssl_thread_key(id, thread_start_time);
    }

    u64 write_ssl = 0;
    ssl_args_t *write_args =
        thread_start_time ? bpf_map_lookup_elem(&active_ssl_write_args, &thread_key) : NULL;
    if (write_args) {
        write_ssl = write_args->ssl;
        if (write_args->flags & FLAG_SSL_PREWRITE_PUBLISHED) {
            cleanup_unwritten_ssl_prewrite(id, write_args, k_java_remote_parent_stat_inject_stale);
        }
        cleanup_ssl_owner(id, write_ssl, process_start_time);
    }
    if (thread_start_time) {
        bpf_map_delete_elem(&active_ssl_write_args, &thread_key);
    }

    u64 read_ssl = 0;
    ssl_args_t *read_args = bpf_map_lookup_elem(&active_ssl_read_args, &id);
    if (read_args) {
        read_ssl = read_args->ssl;
        if (read_ssl != write_ssl) {
            cleanup_ssl_owner(id, read_ssl, process_start_time);
        }
    }
    bpf_map_delete_elem(&active_ssl_read_args, &id);

    ssl_shutdown_args_t *shutdown_args =
        thread_start_time ? bpf_map_lookup_elem(&active_ssl_shutdown_args, &thread_key) : NULL;
    if (shutdown_args && shutdown_args->ssl != write_ssl && shutdown_args->ssl != read_ssl) {
        cleanup_ssl_owner(id, shutdown_args->ssl, process_start_time);
    }
    if (thread_start_time) {
        bpf_map_delete_elem(&active_ssl_shutdown_args, &thread_key);
        delete_pid_tid_connection(id, thread_start_time);
    }
}
