// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/compiler.h>

#include <common/ssl_args.h>
#include <common/trace_key.h>
#include <common/trace_lifecycle.h>

#include <generictracer/k_tracer_defs.h>
#include <generictracer/protocol_http.h>
#include <generictracer/ssl_connection.h>

#include <generictracer/maps/pid_tid_to_conn.h>
#include <generictracer/maps/ssl_to_pid_tid.h>
#include <maps/ssl_to_conn.h>

#include <logger/bpf_dbg.h>

static __always_inline void cleanup_ssl_trace_info(http_info_t *info,
                                                   pid_connection_info_t *pid_conn) {
    if (info->type == EVENT_HTTP_REQUEST) {
        trace_key_t t_key = {0};
        t_key.extra_id = info->extra_id;
        t_key.p_key.ns = info->pid.ns;
        t_key.p_key.tid = info->task_tid;
        t_key.p_key.pid = info->pid.user_pid;

        delete_server_trace(pid_conn, &t_key);
    }
}

static __always_inline void
cleanup_ssl_server_trace(http_info_t *info, pid_connection_info_t *pid_conn, void *buf, u32 len) {
    if (info && http_will_complete(info, (unsigned char *)buf, len)) {
        cleanup_ssl_trace_info(info, pid_conn);
    }
}

static __always_inline void cleanup_complete_ssl_server_trace(http_info_t *info,
                                                              pid_connection_info_t *pid_conn) {
    if (info && http_info_complete(info)) {
        cleanup_ssl_trace_info(info, pid_conn);
    }
}

static __always_inline void
finish_possible_delayed_tls_http_request(pid_connection_info_t *pid_conn) {
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
    if (info && info->submitted) {
        // we need to check for server request, the same thread
        // could be handling both client and server requests
        if (info->type == EVENT_HTTP_REQUEST) {
            cleanup_complete_ssl_server_trace(info, pid_conn);
        }
        finish_http(info, pid_conn);
    }
}

static __always_inline void finish_tls_http_request_on_shutdown(pid_connection_info_t *pid_conn) {
    terminate_http_request_if_needed(pid_conn);
}

static __always_inline void
cleanup_trace_info_for_delayed_trace(pid_connection_info_t *pid_conn, void *buf, u32 len) {
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
    cleanup_ssl_server_trace(info, pid_conn, buf, len);
}

static __always_inline u8 initialize_fallback_ssl_connection(ssl_pid_connection_info_t *fallback,
                                                             u64 id,
                                                             u64 ssl_ptr,
                                                             u64 process_start_time) {
    __builtin_memset(fallback, 0, sizeof(*fallback));
    if (!process_start_time) {
        return 0;
    }
    __builtin_memcpy(&fallback->p_conn.conn.s_addr, &ssl_ptr, sizeof(ssl_ptr));
    __builtin_memcpy(&fallback->p_conn.conn.s_addr[sizeof(ssl_ptr)],
                     &process_start_time,
                     sizeof(process_start_time));
    fallback->p_conn.pid = pid_from_pid_tgid(id);
    return 1;
}

static __always_inline void finish_fallback_tls_http_request_on_shutdown(u64 id, u64 ssl_ptr) {
    ssl_pid_connection_info_t fallback;
    if (!initialize_fallback_ssl_connection(&fallback, id, ssl_ptr, task_process_start_time())) {
        return;
    }
    finish_tls_http_request_on_shutdown(&fallback.p_conn);
}

static __always_inline void discard_fallback_ssl_http_request(
    u64 id, u64 ssl_ptr, u64 process_start_time, const pid_connection_info_t *real_connection) {
    ssl_pid_connection_info_t fallback;
    if (!initialize_fallback_ssl_connection(&fallback, id, ssl_ptr, process_start_time)) {
        return;
    }
    if (real_connection &&
        __builtin_memcmp(&fallback.p_conn, real_connection, sizeof(fallback.p_conn)) == 0) {
        return;
    }

    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, &fallback.p_conn);
    if (!info) {
        return;
    }

    cleanup_http_request_data(&fallback.p_conn, info);
    cleanup_http_info(&fallback.p_conn);
}

static __always_inline void finish_real_tls_http_request_on_shutdown(
    u64 id, u64 ssl_ptr, u64 process_start_time, pid_connection_info_t *real_connection) {
    discard_fallback_ssl_http_request(id, ssl_ptr, process_start_time, real_connection);
    finish_tls_http_request_on_shutdown(real_connection);
}

static __always_inline void retire_matching_ssl_thread_connection(
    u64 pid_tgid, u64 thread_start_time, const pid_connection_info_t *stale_connection) {
    if (!pid_tgid || !thread_start_time || !stale_connection ||
        pid_from_pid_tgid(pid_tgid) != stale_connection->pid) {
        return;
    }

    const ssl_pid_connection_info_t *thread_connection =
        lookup_pid_tid_connection(pid_tgid, thread_start_time);
    if (ssl_connection_mapping_matches(thread_connection, stale_connection)) {
        delete_pid_tid_connection(pid_tgid, thread_start_time);
    }
}

static __always_inline void
retire_ssl_pointer_generation(u64 ssl_ptr, u64 id, u64 process_start_time, u64 thread_start_time) {
    const u32 pid = pid_from_pid_tgid(id);
    if (!ssl_ptr || !pid || !process_start_time) {
        return;
    }

    // A successful allocation starts a new pointer generation. Preserve a
    // different thread hint because connect may have completed before SSL_new.
    const ssl_pid_key_t key = ssl_pid_key(ssl_ptr, pid, process_start_time);
    const ssl_pid_connection_info_t *cached =
        lookup_ssl_connection(ssl_ptr, pid, process_start_time);
    pid_connection_info_t stale_connection = {};
    const u8 had_cached = cached != NULL;
    if (cached) {
        bpf_probe_read(&stale_connection, sizeof(stale_connection), &cached->p_conn);
    }

    ssl_thread_key_t stale_owner = {};
    const ssl_thread_key_t *owner = bpf_map_lookup_elem(&ssl_to_pid_tid, &key);
    u8 had_owner = 0;
    if (owner && pid_from_pid_tgid(owner->pid_tgid) == pid && owner->thread_start_time) {
        bpf_probe_read(&stale_owner, sizeof(stale_owner), owner);
        had_owner = 1;
    }

    delete_ssl_connection(ssl_ptr, pid, process_start_time);
    bpf_map_delete_elem(&ssl_to_pid_tid, &key);

    if (!had_cached) {
        return;
    }

    retire_matching_ssl_thread_connection(id, thread_start_time, &stale_connection);
    if (had_owner &&
        (stale_owner.pid_tgid != id || stale_owner.thread_start_time != thread_start_time)) {
        retire_matching_ssl_thread_connection(
            stale_owner.pid_tgid, stale_owner.thread_start_time, &stale_connection);
    }

    const u64 *active_owner = is_ssl_connection(&stale_connection);
    if (active_owner && *active_owner == ssl_ptr) {
        bpf_map_delete_elem(&active_ssl_connections, &stale_connection);
    }
}

static __always_inline ssl_pid_connection_info_t *
ssl_connection_for_args(u64 id, ssl_args_t *args, u8 cleanup_thread_mapping) {
    const u64 ssl_ptr = args->ssl;
    const u32 pid = pid_from_pid_tgid(id);
    const u64 process_start_time = task_process_start_time();
    const u64 thread_start_time = task_thread_start_time();
    if (!process_start_time || !thread_start_time) {
        return NULL;
    }
    const ssl_pid_key_t key = ssl_pid_key(ssl_ptr, pid, process_start_time);
    ssl_pid_connection_info_t *cached = lookup_ssl_connection(ssl_ptr, pid, process_start_time);
    if (cached) {
        const u64 *active_owner = is_ssl_connection(&cached->p_conn);
        if (active_owner && *active_owner == ssl_ptr) {
            if (cleanup_thread_mapping) {
                bpf_map_delete_elem(&ssl_to_pid_tid, &key);
            }
            discard_fallback_ssl_http_request(id, ssl_ptr, process_start_time, &cached->p_conn);
            return cached;
        }
        delete_ssl_connection(ssl_ptr, pid, process_start_time);
    }

    ssl_pid_connection_info_t *source = lookup_pid_tid_connection(id, thread_start_time);
    u64 source_pid_tid = 0;
    u64 source_thread_start_time = 0;

    if (source) {
        source_pid_tid = id;
        source_thread_start_time = thread_start_time;
    }

    if (!source) {
        const ssl_thread_key_t *owner = bpf_map_lookup_elem(&ssl_to_pid_tid, &key);

        if (owner && pid_from_pid_tgid(owner->pid_tgid) == pid && owner->thread_start_time) {
            const u64 pid_tid = owner->pid_tgid;

            source = lookup_pid_tid_connection(pid_tid, owner->thread_start_time);
            if (source) {
                source_pid_tid = pid_tid;
                source_thread_start_time = owner->thread_start_time;
            }
            bpf_dbg_printk(
                "Separate pool lookup ssl=%llx, pid=%d, conn=%llx", ssl_ptr, pid_tid, source);
        } else {
            bpf_dbg_printk("Other thread lookup failed for ssl=%llx", ssl_ptr);
        }
    }

    ssl_pid_connection_info_t *conn = NULL;
    if (source) {
        ssl_pid_connection_info_t current = {};
        bpf_probe_read(&current, sizeof(current), source);
        if (update_ssl_connection(ssl_ptr, &current, process_start_time, BPF_ANY) != 0 ||
            bpf_map_update_elem(&active_ssl_connections, &current.p_conn, &ssl_ptr, BPF_ANY) != 0) {
            delete_ssl_connection(ssl_ptr, pid, process_start_time);
        } else {
            conn = lookup_ssl_connection(ssl_ptr, pid, process_start_time);
        }
        if (conn && source_pid_tid) {
            delete_pid_tid_connection(source_pid_tid, source_thread_start_time);
        }
    }

    if (cleanup_thread_mapping) {
        bpf_map_delete_elem(&ssl_to_pid_tid, &key);
    }

    if (conn) {
        discard_fallback_ssl_http_request(id, ssl_ptr, process_start_time, &conn->p_conn);
    }

    return conn;
}

static __always_inline void
handle_ssl_prewrite(void *ctx, u64 id, ssl_args_t *args, int bytes_len) {
    if (!args || !args->handoff_id || bytes_len <= 0) {
        return;
    }

    ssl_pid_connection_info_t *conn = ssl_connection_for_args(id, args, 0);
    if (!conn) {
        return;
    }

    handle_ssl_prewrite_with_connection(ctx,
                                        &conn->p_conn,
                                        (void *)args->buf,
                                        bytes_len,
                                        conn->orig_dport,
                                        args->ssl,
                                        args->handoff_id);
}

static __always_inline u8 ssl_prewrite_local_info_matches(const ssl_prewrite_value_t *value,
                                                          const http_info_t *info) {
    return value && info && info->ssl_prewrite_pending == k_ssl_prewrite_local_pending &&
           ssl_prewrite_postwrite_value_structurally_valid(value) &&
           ssl_prewrite_transport_local_fields_match(
               value, info->type, info->ssl, info->direction, info->start_monotime_ns, &info->tp);
}

static __always_inline void discard_ssl_prewrite_local(const ssl_prewrite_value_t *value) {
    if (!value) {
        return;
    }
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, &value->connection);
    if (ssl_prewrite_local_info_matches(value, info)) {
        cleanup_http_request_data((pid_connection_info_t *)&value->connection, info);
        cleanup_http_info((pid_connection_info_t *)&value->connection);
    }
}

static __always_inline void commit_ssl_prewrite_local(const ssl_prewrite_value_t *value) {
    if (!value) {
        return;
    }
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, &value->connection);
    if (ssl_prewrite_local_info_matches(value, info)) {
        info->ssl_prewrite_pending = k_ssl_prewrite_local_none;
    }
}

static __always_inline u8 finish_ssl_prewrite_impl(u64 id,
                                                   const ssl_args_t *args,
                                                   u8 write_succeeded,
                                                   u32 written_bytes,
                                                   enum java_remote_parent_stat failure_stat,
                                                   u8 report_failure) {
    const u64 thread_start_time = task_thread_start_time();
    if (!args || !thread_start_time || !args->handoff_id) {
        return 0;
    }
    const ssl_prewrite_key_t key = ssl_prewrite_key(id, thread_start_time, args->handoff_id);
    ssl_prewrite_value_t *value = bpf_map_lookup_elem(&ssl_prewrite_tp, &key);
    if (!value) {
        if (report_failure) {
            java_remote_parent_stat_add(k_java_remote_parent_stat_inject_missing);
        }
        return 1;
    }

    const u8 exact_value = ssl_prewrite_postwrite_value_structurally_valid(value) &&
                           value->trace.pid == pid_from_pid_tgid(id) && value->ssl == args->ssl &&
                           value->buffer == args->buf;
    if (!exact_value) {
        write_succeeded = 0;
        failure_stat = k_java_remote_parent_stat_inject_malformed;
    }

    if (write_succeeded &&
        !ssl_prewrite_postwrite_matches(value, args->ssl, args->buf, written_bytes)) {
        write_succeeded = 0;
        failure_stat = k_java_remote_parent_stat_inject_malformed;
    }

    u32 arbitration = value->arbitration;
    if (!write_succeeded) {
        ssl_prewrite_mark_write_failed(value);
        arbitration = ssl_prewrite_arbitration_state(value);
    }
    const enum ssl_prewrite_transport_phase phase = value->transport_phase;
    const u8 keep_local = write_succeeded || !ssl_prewrite_write_may_discard(arbitration);

    if (!write_succeeded || ssl_prewrite_transport_terminal(phase)) {
        if (keep_local) {
            commit_ssl_prewrite_local(value);
        } else {
            discard_ssl_prewrite_local(value);
        }
    }

    value->write_outcome =
        write_succeeded ? k_ssl_prewrite_write_succeeded : k_ssl_prewrite_write_failed;
    if (!write_succeeded && report_failure) {
        java_remote_parent_stat_add(arbitration > k_ssl_prewrite_arbitration_failed_transport
                                        ? k_java_remote_parent_stat_inject_ambiguous
                                        : failure_stat);
    }
    if (!write_succeeded) {
        block_ssl_prewrite_connection(
            &value->connection.conn, value->netns_cookie, bpf_ktime_get_ns());
    }
    return 1;
}

static __always_inline u8 finish_ssl_prewrite(u64 id,
                                              const ssl_args_t *args,
                                              u8 write_succeeded,
                                              u32 written_bytes,
                                              enum java_remote_parent_stat failure_stat) {
    return finish_ssl_prewrite_impl(id, args, write_succeeded, written_bytes, failure_stat, 1);
}

static __always_inline void
emit_ssl_prewrite_large_buffer_init(void *ctx, u64 id, const ssl_args_t *args, u32 written_bytes) {
    const u64 thread_start_time = task_thread_start_time();
    if (!args || !thread_start_time || !args->handoff_id) {
        return;
    }

    const ssl_prewrite_key_t key = ssl_prewrite_key(id, thread_start_time, args->handoff_id);
    ssl_prewrite_value_t *value = bpf_map_lookup_elem(&ssl_prewrite_tp, &key);
    if (!ssl_prewrite_postwrite_value_structurally_valid(value) ||
        value->write_outcome != k_ssl_prewrite_write_succeeded ||
        value->trace.pid != pid_from_pid_tgid(id) ||
        !ssl_prewrite_postwrite_matches(value, args->ssl, args->buf, written_bytes)) {
        return;
    }

    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, &value->connection);
    if (!info || info->ssl_prewrite_pending == k_ssl_prewrite_local_blocked ||
        !ssl_prewrite_transport_local_fields_match(
            value, info->type, info->ssl, info->direction, info->start_monotime_ns, &info->tp)) {
        return;
    }

    http_send_large_buffer(ctx,
                           info,
                           &value->connection,
                           (void *)args->buf,
                           written_bytes,
                           PACKET_TYPE_REQUEST,
                           TCP_SEND,
                           k_large_buf_action_init);
}

static __always_inline void
handle_ssl_buf(void *ctx, u64 id, ssl_args_t *args, int bytes_len, u8 direction) {
    if (!args) {
        return;
    }

    if (direction == TCP_SEND && args->unsafe_nested_write) {
        const u64 process_start_time = task_process_start_time();
        if (process_start_time) {
            const ssl_pid_key_t key =
                ssl_pid_key(args->ssl, pid_from_pid_tgid(id), process_start_time);
            bpf_map_delete_elem(&ssl_to_pid_tid, &key);
        }
        return;
    }

    if (direction == TCP_SEND && (args->flags & FLAG_SSL_PREWRITE_PUBLISHED)) {
        const u32 written_bytes = bytes_len > 0 ? (u32)bytes_len : 0;
        if (finish_ssl_prewrite(
                id, args, bytes_len > 0, written_bytes, k_java_remote_parent_stat_inject_stale)) {
            const u64 process_start_time = task_process_start_time();
            if (process_start_time) {
                const ssl_pid_key_t key =
                    ssl_pid_key(args->ssl, pid_from_pid_tgid(id), process_start_time);
                bpf_map_delete_elem(&ssl_to_pid_tid, &key);
            }
            if (bytes_len > 0) {
                emit_ssl_prewrite_large_buffer_init(ctx, id, args, written_bytes);
            }
            return;
        }
    }

    void *ssl = (void *)args->ssl;
    bpf_dbg_printk("SSL_buf id=%d ssl=%llx", id, ssl);

    if (bytes_len <= 0) {
        const u64 process_start_time = task_process_start_time();
        if (process_start_time) {
            const ssl_pid_key_t key =
                ssl_pid_key(args->ssl, pid_from_pid_tgid(id), process_start_time);
            bpf_map_delete_elem(&ssl_to_pid_tid, &key);
        }
        return;
    }

    ssl_pid_connection_info_t fallback;
    ssl_pid_connection_info_t *conn = ssl_connection_for_args(id, args, 1);
    if (!conn) {
        bpf_dbg_printk("setting fake connection info ssl=%llx", ssl);
        if (!initialize_fallback_ssl_connection(
                &fallback, id, (u64)ssl, task_process_start_time())) {
            return;
        }
        conn = &fallback;
    }

    bpf_dbg_printk("SSL conn");
    dbg_print_http_connection_info(&conn->p_conn.conn);

    cleanup_trace_info_for_delayed_trace(&conn->p_conn, (void *)args->buf, bytes_len);
    // must be last, doesn't return
    handle_buf_with_connection(
        ctx, &conn->p_conn, (void *)args->buf, bytes_len, WITH_SSL, direction, conn->orig_dport);
}
