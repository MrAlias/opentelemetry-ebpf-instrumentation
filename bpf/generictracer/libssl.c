// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/algorithm.h>

#include <generictracer/ssl_defs.h>

#include <logger/bpf_dbg.h>

#include <maps/active_ssl_read_args.h>
#include <maps/active_ssl_shutdown_args.h>
#include <maps/active_ssl_write_args.h>

#include <pid/pid.h>

#include <generictracer/ssl_write_lifecycle.h>

static __always_inline int ssl_size_to_int(size_t size) {
    return (int)min((size_t)__INT_MAX__, size);
}

#define OBI_SSL_READ_CONTEXT
#include <generictracer/ssl_read.h>
#undef OBI_SSL_READ_CONTEXT

static __always_inline void cleanup_unwritten_ssl_prewrite(
    u64 id, const ssl_args_t *args, enum java_remote_parent_stat failure_stat) {
    finish_ssl_prewrite(id, args, 0, 0, failure_stat);
}

#define OBI_SSL_OPERATION_CLEANUP_CONTEXT
#include <generictracer/ssl_operation_cleanup.h>
#undef OBI_SSL_OPERATION_CLEANUP_CONTEXT

static __always_inline void begin_ssl_write(void *ctx,
                                            u64 id,
                                            void *ssl,
                                            const void *buf,
                                            u64 len_ptr,
                                            int bytes_len,
                                            u64 requested_len,
                                            u64 api_flags,
                                            enum ssl_write_api write_api) {
    const u64 thread_start_time = task_thread_start_time();
    if (!thread_start_time) {
        return;
    }
    const ssl_thread_key_t key = ssl_thread_key(id, thread_start_time);
    ssl_args_t *active = bpf_map_lookup_elem(&active_ssl_write_args, &key);
    enum ssl_write_api wrapper_outer_api = k_ssl_write_api_unknown;
    u64 wrapper_handoff_id = 0;
    u64 wrapper_flags = 0;
    if (active) {
        const u64 stack_pointer = PT_REGS_SP((struct pt_regs *)ctx);
        const u64 now = bpf_ktime_get_ns();
        const enum ssl_wrapper_entry_action action =
            ssl_write_wrapper_entry_action(active,
                                           (u64)ssl,
                                           (u64)buf,
                                           len_ptr,
                                           requested_len,
                                           api_flags,
                                           write_api,
                                           stack_pointer,
                                           now,
                                           ssl_prewrite_max_age_ns);
        if (action == k_ssl_wrapper_entry_recover_stale ||
            action == k_ssl_wrapper_entry_replace_tail) {
            const ssl_args_t replaced = *active;
            if (action == k_ssl_wrapper_entry_recover_stale &&
                (replaced.flags & FLAG_SSL_PREWRITE_PUBLISHED)) {
                cleanup_unwritten_ssl_prewrite(
                    id, &replaced, k_java_remote_parent_stat_inject_stale);
            }
            if (action == k_ssl_wrapper_entry_replace_tail) {
                wrapper_outer_api = active->write_api;
                wrapper_handoff_id = replaced.handoff_id;
                wrapper_flags = replaced.flags;
            }
            cleanup_replaced_ssl_write_owner(id, action, &replaced, (u64)ssl);
            bpf_map_delete_elem(&active_ssl_write_args, &key);
        } else {
            if (active->flags & FLAG_SSL_PREWRITE_PUBLISHED) {
                cleanup_unwritten_ssl_prewrite(
                    id, active, k_java_remote_parent_stat_inject_ambiguous);
            }
            active->flags &= ~FLAG_SSL_PREWRITE_PUBLISHED;
            active->unsafe_nested_write = 1;
            const u32 max_depth = (u32)~0U;
            if (active->depth < max_depth) {
                active->depth++;
            }
            return;
        }
    }

    ssl_args_t args;
    initialize_ssl_write_args(&args,
                              (u64)ssl,
                              (u64)buf,
                              len_ptr,
                              bpf_ktime_get_ns(),
                              requested_len,
                              PT_REGS_SP((struct pt_regs *)ctx),
                              write_api,
                              wrapper_outer_api);
    if (wrapper_outer_api != k_ssl_write_api_unknown) {
        transfer_ssl_write_handoff(&args, wrapper_handoff_id, wrapper_flags);
    }
    if (!args.handoff_id ||
        bpf_map_update_elem(&active_ssl_write_args, &key, &args, BPF_NOEXIST) != 0) {
        if (args.flags & FLAG_SSL_PREWRITE_PUBLISHED) {
            cleanup_unwritten_ssl_prewrite(id, &args, k_java_remote_parent_stat_inject_overload);
        } else if (java_remote_parent_enabled) {
            java_remote_parent_stat_add(k_java_remote_parent_stat_inject_overload);
        }
        cleanup_failed_ssl_write_start(id, &args);
        return;
    }

    if (java_remote_parent_enabled && wrapper_outer_api == k_ssl_write_api_unknown) {
        handle_ssl_prewrite(ctx, id, &args, bytes_len);
    }
}

static __always_inline void
begin_ssl_shutdown(void *ctx, u64 id, void *ssl, enum ssl_shutdown_api api) {
    const u64 thread_start_time = task_thread_start_time();
    if (!thread_start_time) {
        return;
    }
    const ssl_thread_key_t key = ssl_thread_key(id, thread_start_time);
    ssl_shutdown_args_t *active = bpf_map_lookup_elem(&active_ssl_shutdown_args, &key);
    enum ssl_shutdown_api wrapper_outer_api = k_ssl_shutdown_api_unknown;
    if (active) {
        const u64 stack_pointer = PT_REGS_SP((struct pt_regs *)ctx);
        const enum ssl_wrapper_entry_action action =
            ssl_shutdown_wrapper_entry_action(active, (u64)ssl, api, stack_pointer);
        if (action == k_ssl_wrapper_entry_replace_tail) {
            wrapper_outer_api = active->api;
            bpf_map_delete_elem(&active_ssl_shutdown_args, &key);
        } else {
            active->unsafe_nested = 1;
            const u32 max_depth = (u32)~0U;
            if (active->depth < max_depth) {
                active->depth++;
            }
            return;
        }
    }

    ssl_shutdown_args_t args;
    initialize_ssl_shutdown_args(
        &args, (u64)ssl, PT_REGS_SP((struct pt_regs *)ctx), api, wrapper_outer_api);
    bpf_map_update_elem(&active_ssl_shutdown_args, &key, &args, BPF_NOEXIST);
}

static __always_inline u8 take_outer_ssl_write(u64 id,
                                               enum ssl_write_api returning_api,
                                               ssl_args_t *saved) {
    const enum ssl_write_return_state state =
        take_ssl_write_args(id, task_thread_start_time(), returning_api, saved);
    if (state == k_ssl_write_return_unsafe && (saved->flags & FLAG_SSL_PREWRITE_PUBLISHED)) {
        cleanup_unwritten_ssl_prewrite(id, saved, k_java_remote_parent_stat_inject_ambiguous);
    }
    cleanup_returned_ssl_write_owner(id, state, saved);
    return state == k_ssl_write_return_outer;
}

SEC("tracepoint/sched/sched_process_exit")
int obi_ssl_process_exit(void *ctx) {
    (void)ctx;

    const u64 id = bpf_get_current_pid_tgid();
    const u64 thread_start_time = task_thread_start_time();
    cleanup_exited_ssl_operations(id, thread_start_time);
    return 0;
}

SEC("uretprobe/libssl.so:SSL_new")
int BPF_URETPROBE(obi_uretprobe_ssl_new, void *ssl) {
    (void)ctx;

    const u64 id = bpf_get_current_pid_tgid();
    if (!ssl || !valid_pid(id)) {
        return 0;
    }

    retire_ssl_pointer_generation(
        (u64)ssl, id, task_process_start_time(), task_thread_start_time());
    return 0;
}

// SSL read and read_ex are more less the same, but some frameworks use one or the other.
// SSL_read_ex sets an argument pointer with the number of bytes read, while SSL_read returns
// the number of bytes read.
SEC("uprobe/libssl.so:SSL_read")
int BPF_UPROBE(obi_uprobe_ssl_read, void *ssl, const void *buf, int num) {
    (void)ctx;
    (void)num;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe SSL_read id=%d ssl=%llx ===", id, ssl);

    const u32 pid = pid_from_pid_tgid(id);
    const u64 process_start_time = task_process_start_time();
    if (!process_start_time) {
        return 0;
    }
    ssl_pid_connection_info_t *s_conn = lookup_ssl_connection((u64)ssl, pid, process_start_time);
    if (s_conn) {
        finish_possible_delayed_tls_http_request(&s_conn->p_conn);
    }

    ssl_args_t args = {};
    args.buf = (u64)buf;
    args.ssl = (u64)ssl;
    args.flags = 0;

    publish_ssl_read_args(id, process_start_time, task_thread_start_time(), &args);

    return 0;
}

SEC("uretprobe/libssl.so:SSL_read")
int BPF_URETPROBE(obi_uretprobe_ssl_read, int ret) {
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        discard_ssl_read_result(id);
        return 0;
    }

    bpf_dbg_printk("=== uretprobe SSL_read id=%d ===", id);

    handle_ssl_read_result(ctx, id, ret);
    return 0;
}

SEC("uprobe/libssl.so:SSL_read_ex")
int BPF_UPROBE(obi_uprobe_ssl_read_ex,
               void *ssl,
               const void *buf,
               int num,
               size_t *readbytes) { //NOLINT(readability-non-const-parameter)
    (void)ctx;
    (void)num;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== SSL_read_ex id=%d ssl=%llx ===", id, ssl);

    const u32 pid = pid_from_pid_tgid(id);
    const u64 process_start_time = task_process_start_time();
    if (!process_start_time) {
        return 0;
    }
    ssl_pid_connection_info_t *s_conn = lookup_ssl_connection((u64)ssl, pid, process_start_time);
    if (s_conn) {
        finish_possible_delayed_tls_http_request(&s_conn->p_conn);
    }

    ssl_args_t args = {};
    args.buf = (u64)buf;
    args.ssl = (u64)ssl;
    args.len_ptr = (u64)readbytes;
    args.flags = 0;

    publish_ssl_read_args(id, process_start_time, task_thread_start_time(), &args);

    return 0;
}

SEC("uretprobe/libssl.so:SSL_read_ex")
int BPF_URETPROBE(obi_uretprobe_ssl_read_ex, int ret) {
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        discard_ssl_read_result(id);
        return 0;
    }

    bpf_dbg_printk("=== uretprobe SSL_read_ex id=%d ===", id);

    handle_ssl_read_ex_result(ctx, id, ret);
    return 0;
}

// SSL write and write_ex are more less the same, but some frameworks use one or the other.
// SSL_write_ex sets an argument pointer with the number of bytes written, while SSL_write returns
// the number of bytes written.
SEC("uprobe/libssl.so:SSL_write")
int BPF_UPROBE(obi_uprobe_ssl_write, void *ssl, const void *buf, int num) {
    (void)ctx;
    (void)num;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== uprobe SSL_write id=%d ssl=%llx ===", id, ssl);

    begin_ssl_write(ctx, id, ssl, buf, 0, num, num > 0 ? (u64)num : 0, 0, k_ssl_write_api_write);

    return 0;
}

SEC("uretprobe/libssl.so:SSL_write")
int BPF_URETPROBE(obi_uretprobe_ssl_write, int ret) {
    const u64 id = bpf_get_current_pid_tgid();
    ssl_args_t saved = {};
    if (!take_outer_ssl_write(id, k_ssl_write_api_write, &saved)) {
        return 0;
    }
    if (!valid_pid(id) || ret <= 0) {
        handle_ssl_buf(ctx, id, &saved, 0, TCP_SEND);
        return 0;
    }

    // must be last in the function, doesn't return
    handle_ssl_buf(ctx, id, &saved, ret, TCP_SEND);
    return 0;
}

SEC("uretprobe/libSystem.Security.Cryptography.Native.OpenSsl.so:CryptoNative_SslWrite")
int BPF_URETPROBE(obi_uretprobe_crypto_native_ssl_write, int ret) {
    const u64 id = bpf_get_current_pid_tgid();
    ssl_args_t saved = {};
    if (!take_outer_ssl_write(id, k_ssl_write_api_crypto_native, &saved)) {
        return 0;
    }
    if (!valid_pid(id) || ret <= 0) {
        handle_ssl_buf(ctx, id, &saved, 0, TCP_SEND);
        return 0;
    }

    handle_ssl_buf(ctx, id, &saved, ret, TCP_SEND);
    return 0;
}

SEC("uprobe/libSystem.Security.Cryptography.Native.OpenSsl.so:CryptoNative_SslWrite")
int BPF_UPROBE(obi_uprobe_crypto_native_ssl_write, void *ssl, const void *buf, int num) {
    const u64 id = bpf_get_current_pid_tgid();
    if (!valid_pid(id)) {
        return 0;
    }
    begin_ssl_write(
        ctx, id, ssl, buf, 0, num, num > 0 ? (u64)num : 0, 0, k_ssl_write_api_crypto_native);
    return 0;
}

SEC("uprobe/libssl.so:SSL_write_ex")
int BPF_UPROBE(obi_uprobe_ssl_write_ex,
               void *ssl,
               const void *buf,
               size_t num,
               size_t *written) { //NOLINT(readability-non-const-parameter)
    (void)ctx;
    (void)num;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== SSL_write_ex id=%d ssl=%llx ===", id, ssl);

    begin_ssl_write(ctx,
                    id,
                    ssl,
                    buf,
                    (u64)written,
                    ssl_size_to_int(num),
                    (u64)num,
                    0,
                    k_ssl_write_api_write_ex);

    return 0;
}

SEC("uprobe/libssl.so:SSL_write_ex2")
int BPF_UPROBE(obi_uprobe_ssl_write_ex2,
               void *ssl,
               const void *buf,
               size_t num,
               u64 flags,
               size_t *written) { //NOLINT(readability-non-const-parameter)
    (void)ctx;
    (void)num;

    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== SSL_write_ex2 id=%d ssl=%llx ===", id, ssl);

    begin_ssl_write(ctx,
                    id,
                    ssl,
                    buf,
                    (u64)written,
                    ssl_size_to_int(num),
                    (u64)num,
                    flags,
                    k_ssl_write_api_write_ex2);

    return 0;
}

SEC("uretprobe/libssl.so:SSL_write_ex")
int BPF_URETPROBE(obi_uretprobe_ssl_write_ex, int ret) {
    const u64 id = bpf_get_current_pid_tgid();
    ssl_args_t saved = {};
    if (!take_outer_ssl_write(id, k_ssl_write_api_write_ex, &saved)) {
        return 0;
    }
    if (!valid_pid(id) || ret != 1) {
        handle_ssl_buf(ctx, id, &saved, 0, TCP_SEND);
        return 0;
    }

    size_t write_len = 0;
    if (bpf_probe_read_user(&write_len, sizeof(write_len), (void *)saved.len_ptr) != 0 ||
        write_len == 0) {
        handle_ssl_buf(ctx, id, &saved, 0, TCP_SEND);
        return 0;
    }

    // must be last in the function, doesn't return
    handle_ssl_buf(ctx, id, &saved, ssl_size_to_int(write_len), TCP_SEND);

    return 0;
}

SEC("uretprobe/libssl.so:SSL_write_ex2")
int BPF_URETPROBE(obi_uretprobe_ssl_write_ex2, int ret) {
    const u64 id = bpf_get_current_pid_tgid();
    ssl_args_t saved = {};
    if (!take_outer_ssl_write(id, k_ssl_write_api_write_ex2, &saved)) {
        return 0;
    }
    if (!valid_pid(id) || ret != 1) {
        handle_ssl_buf(ctx, id, &saved, 0, TCP_SEND);
        return 0;
    }

    size_t write_len = 0;
    if (bpf_probe_read_user(&write_len, sizeof(write_len), (void *)saved.len_ptr) != 0 ||
        write_len == 0) {
        handle_ssl_buf(ctx, id, &saved, 0, TCP_SEND);
        return 0;
    }

    // must be last in the function, doesn't return
    handle_ssl_buf(ctx, id, &saved, ssl_size_to_int(write_len), TCP_SEND);

    return 0;
}

SEC("uprobe/libssl.so:SSL_shutdown")
int BPF_UPROBE(obi_uprobe_ssl_shutdown, void *s) {
    const u64 id = bpf_get_current_pid_tgid();

    if (!valid_pid(id)) {
        return 0;
    }

    bpf_dbg_printk("=== SSL_shutdown id=%d ssl=%llx ===", id, s);

    begin_ssl_shutdown(ctx, id, s, k_ssl_shutdown_api_shutdown);
    return 0;
}

SEC("uprobe/libSystem.Security.Cryptography.Native.OpenSsl.so:CryptoNative_SslShutdown")
int BPF_UPROBE(obi_uprobe_crypto_native_ssl_shutdown, void *s) {
    const u64 id = bpf_get_current_pid_tgid();
    if (!valid_pid(id)) {
        return 0;
    }
    begin_ssl_shutdown(ctx, id, s, k_ssl_shutdown_api_crypto_native);
    return 0;
}

SEC("uretprobe/libssl.so:SSL_shutdown")
int BPF_URETPROBE(obi_uretprobe_ssl_shutdown, int ret) {
    (void)ctx;

    const u64 id = bpf_get_current_pid_tgid();
    ssl_shutdown_args_t saved = {};
    if (take_ssl_shutdown_args(id, task_thread_start_time(), k_ssl_shutdown_api_shutdown, &saved) !=
        k_ssl_write_return_outer) {
        return 0;
    }
    if (!valid_pid(id) || ret != 1) {
        return 0;
    }

    const u64 ssl = saved.ssl;
    const u32 pid = pid_from_pid_tgid(id);
    const u64 process_start_time = task_process_start_time();
    if (!process_start_time) {
        return 0;
    }
    ssl_pid_connection_info_t *s_conn = lookup_ssl_connection(ssl, pid, process_start_time);
    if (s_conn) {
        pid_connection_info_t pid_conn = {};
        bpf_probe_read(&pid_conn, sizeof(pid_conn), &s_conn->p_conn);
        finish_real_tls_http_request_on_shutdown(id, ssl, process_start_time, &pid_conn);
    } else {
        finish_fallback_tls_http_request_on_shutdown(id, ssl);
    }

    delete_ssl_connection(ssl, pid, process_start_time);
    const ssl_pid_key_t key = ssl_pid_key(ssl, pid, process_start_time);
    bpf_map_delete_elem(&ssl_to_pid_tid, &key);

    delete_pid_tid_connection(id, task_thread_start_time());

    return 0;
}

SEC("uretprobe/libSystem.Security.Cryptography.Native.OpenSsl.so:CryptoNative_SslShutdown")
int BPF_URETPROBE(obi_uretprobe_crypto_native_ssl_shutdown, int ret) {
    (void)ctx;

    const u64 id = bpf_get_current_pid_tgid();
    ssl_shutdown_args_t saved = {};
    if (take_ssl_shutdown_args(
            id, task_thread_start_time(), k_ssl_shutdown_api_crypto_native, &saved) !=
        k_ssl_write_return_outer) {
        return 0;
    }
    if (!valid_pid(id) || ret != 1) {
        return 0;
    }

    const u64 ssl = saved.ssl;
    const u32 pid = pid_from_pid_tgid(id);
    const u64 process_start_time = task_process_start_time();
    if (!process_start_time) {
        return 0;
    }
    ssl_pid_connection_info_t *s_conn = lookup_ssl_connection(ssl, pid, process_start_time);
    if (s_conn) {
        pid_connection_info_t pid_conn = {};
        bpf_probe_read(&pid_conn, sizeof(pid_conn), &s_conn->p_conn);
        finish_real_tls_http_request_on_shutdown(id, ssl, process_start_time, &pid_conn);
    } else {
        finish_fallback_tls_http_request_on_shutdown(id, ssl);
    }

    delete_ssl_connection(ssl, pid, process_start_time);
    const ssl_pid_key_t key = ssl_pid_key(ssl, pid, process_start_time);
    bpf_map_delete_elem(&ssl_to_pid_tid, &key);
    delete_pid_tid_connection(id, task_thread_start_time());
    return 0;
}
