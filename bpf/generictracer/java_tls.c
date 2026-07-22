// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include "pid/types/pid_key.h"
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/connection_info.h>
#include <common/protocol_defs.h>
#include <common/sock_port_ns.h>
#include <common/sockaddr.h>
#include <common/ssl_connection.h>
#include <common/trace_key.h>
#include <common/trace_parent.h>

#include <generictracer/k_tracer_defs.h>
#include <generictracer/maps/pid_tid_to_conn.h>

#include <logger/bpf_dbg.h>

#include <maps/active_ssl_connections.h>
#include <maps/java_remote_parent.h>
#include <maps/java_tasks.h>
#include <maps/java_vt_threads.h>

#include <pid/pid.h>

#include <shared/obi_ctx.h>

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
};

enum { k_ioctl_invalid_op = 0xff };
// Keep this ceiling aligned with the largest large-buffer capture limit in
// bpf/common/large_buffers.h.
enum { k_ioctl_max_payload_len = 1 << 16 };

static __always_inline u8 cmd_to_op(u8 cmd) {
    switch (cmd) {
    case k_ioctl_java_send:
        return TCP_SEND;
    case k_ioctl_java_recv:
        return TCP_RECV;
    default:
        return k_ioctl_invalid_op;
    }
}

static __always_inline u8 java_connection_from_file(struct file *file,
                                                    u8 op,
                                                    connection_info_t *connection,
                                                    u16 *orig_dport,
                                                    u32 *netns,
                                                    u64 *netns_cookie) {
    if (!file) {
        return 0;
    }

    struct socket *socket = BPF_CORE_READ(file, private_data);
    if (!socket || BPF_CORE_READ(socket, file) != file) {
        return 0;
    }
    struct sock *sk = BPF_CORE_READ(socket, sk);
    if (!sk || BPF_CORE_READ(sk, sk_protocol) != IPPROTO_TCP) {
        return 0;
    }
    const u8 state = BPF_CORE_READ(sk, __sk_common.skc_state);
    if ((state != TCP_ESTABLISHED && state != TCP_CLOSE_WAIT) || !parse_sock_info(sk, connection)) {
        return 0;
    }

    // parse_sock_info is local-to-remote. The receive ABI is
    // remote-to-local, so orient the kernel-derived tuple before comparing it
    // with the advisory Java copy and before feeding the shared parser.
    *orig_dport = connection->d_port;
    if (op == TCP_RECV) {
        swap_connection_info_order(connection);
    }
    *netns = sock_port_ns_from_sk(sk).netns;
    *netns_cookie = java_remote_parent_enabled ? sock_netns_cookie_from_sk(sk) : 0;
    return *netns != 0;
}

static __always_inline int handle_java_ioctl(
    struct pt_regs *ctx, struct file *file, u64 id, unsigned char *uarg, u8 data_only) {
    pid_key_t task = {0};
    task_tid(&task);
    if (!java_process_authorized_for(&task)) {
        return 0;
    }

    u8 op_cmd = 0;
    if (bpf_probe_read_user(&op_cmd, sizeof(op_cmd), uarg) != 0) {
        return 0;
    }
    const u8 op = cmd_to_op(op_cmd);
    const u8 data_operation = op != k_ioctl_invalid_op || op_cmd == k_ioctl_java_tls_connection;
    if (data_operation != data_only) {
        return 0;
    }
    if (op_cmd != k_ioctl_java_process_register && !java_process_registered_for(&task)) {
        return 0;
    }

    // Control opcodes each handle themselves and return; the data opcodes
    // (send/recv) fall through to the connection/payload path below.
    switch (op_cmd) {
    case k_ioctl_java_process_register: {
        u64 incarnation = 0;
        if (bpf_probe_read_user(&incarnation, sizeof(incarnation), uarg + 1) != 0 || !incarnation) {
            return 0;
        }

        const pid_key_t process = java_process_key(&task);
        if (java_process_capability_for(&process) != incarnation) {
            return 0;
        }
        const u64 *previous = bpf_map_lookup_elem(&java_process_incarnations, &process);
        if (java_remote_parent_enabled && previous && *previous != incarnation) {
            java_remote_parent_cleanup(&task);
            java_remote_parent_cleanup(&process);
            bpf_map_delete_elem(&java_remote_parent_tasks, &task);
            bpf_map_delete_elem(&java_tasks, &task);
        }
        java_register_process_incarnation(incarnation);
        return 0;
    }
    case k_ioctl_java_vt_mount: {
        // The agent reports, on every VirtualThread.mount(), the logical
        // thread id now mounted on this carrier; the current kernel thread
        // IS the carrier.
        u64 vt_id = 0;
        if (bpf_probe_read_user(&vt_id, sizeof(vt_id), uarg + 1) != 0) {
            return 0;
        }

        pid_key_t carrier = {0};
        task_tid(&carrier);
        pid_key_t synthetic_owner = {0};
        java_vt_identity_t mount_identity = {0};
        enum java_vt_mount_result mount_result =
            java_vt_prepare_mount(&carrier, vt_id, &synthetic_owner, &mount_identity);

        if (mount_result == k_java_vt_mount_collision ||
            mount_result == k_java_vt_mount_stale_incarnation) {
            if (java_remote_parent_enabled) {
                java_remote_parent_cleanup(&synthetic_owner);
                bpf_map_delete_elem(&java_remote_parent_tasks, &synthetic_owner);
                bpf_map_delete_elem(&java_tasks, &synthetic_owner);
            }
            if (mount_result == k_java_vt_mount_collision ||
                !java_vt_replace_stale_identity(&synthetic_owner, &mount_identity)) {
                bpf_map_delete_elem(&java_vt_threads, &carrier);
                return 0;
            }
        } else if (mount_result != k_java_vt_mount_success) {
            bpf_map_delete_elem(&java_vt_threads, &carrier);
            return 0;
        }

        if (java_remote_parent_enabled) {
            java_remote_parent_cleanup(&carrier);
            bpf_map_delete_elem(&java_tasks, &carrier);
        }

        bpf_dbg_printk("Java virtual thread mount observed");
        if (!java_vt_publish_mount(&carrier, &mount_identity)) {
            bpf_map_delete_elem(&java_vt_threads, &carrier);
        }

        return 0;
    }
    case k_ioctl_java_vt_terminate: {
        u64 vt_id = 0;
        if (bpf_probe_read_user(&vt_id, sizeof(vt_id), uarg + 1) != 0) {
            return 0;
        }

        pid_key_t carrier = {0};
        pid_key_t owner = {0};
        task_tid(&carrier);
        if (!java_vt_terminate_identity(&carrier, vt_id, &owner)) {
            return 0;
        }
        if (java_remote_parent_enabled) {
            java_remote_parent_cleanup(&owner);
            bpf_map_delete_elem(&java_remote_parent_tasks, &owner);
            bpf_map_delete_elem(&java_tasks, &owner);
        }
        return 0;
    }
    case k_ioctl_java_vt_unmount: {
        // The mounted VT left this carrier: delete the entry so a carrier
        // with no mounted VT is never translated. mount/unmount for a
        // carrier always execute ON that carrier thread, so write and
        // delete are in program order.
        pid_key_t carrier = {0};
        task_tid(&carrier);

        bpf_dbg_printk("Java virtual thread unmount observed");
        if (java_remote_parent_enabled) {
            java_remote_parent_cleanup(&carrier);
            bpf_map_delete_elem(&java_tasks, &carrier);
        }
        bpf_map_delete_elem(&java_vt_threads, &carrier);

        return 0;
    }
    case k_ioctl_java_task_capture: {
        u64 token = 0;
        if (bpf_probe_read_user(&token, sizeof(token), uarg + 1) != 0) {
            return 0;
        }
        if (java_remote_parent_enabled) {
            java_remote_parent_capture_handoff(token);
        }
        return 0;
    }
    case k_ioctl_java_task_cancel: {
        u64 token = 0;
        if (bpf_probe_read_user(&token, sizeof(token), uarg + 1) != 0) {
            return 0;
        }
        if (java_remote_parent_enabled) {
            const pid_key_t execution = java_remote_parent_current_owner();
            java_remote_parent_cancel_handoff(&execution, token);
        }
        return 0;
    }
    case k_ioctl_java_task_relay_capture: {
        u64 token = 0;
        if (bpf_probe_read_user(&token, sizeof(token), uarg + 1) != 0) {
            return 0;
        }
        if (java_remote_parent_enabled) {
            const pid_key_t execution = java_remote_parent_current_owner();
            java_remote_parent_capture_relay(&execution, token);
        }
        return 0;
    }
    case k_ioctl_java_task_unlink: {
        if (!java_remote_parent_enabled) {
            return 0;
        }

        pid_key_t child = {0};
        task_tid(&child);
        pid_key_t logical_child = child;
        java_vt_translate_tid(&logical_child);
        java_remote_parent_unlink_task(&logical_child);
        bpf_map_delete_elem(&java_tasks, &child);
        obi_ctx__del(id);
        return 0;
    }
    case k_ioctl_java_tls_connection: {
        if (!java_remote_parent_enabled) {
            return 0;
        }

        connection_info_t claimed = {0};
        if (bpf_probe_read_user(&claimed, sizeof(claimed), uarg + 1) != 0 ||
            is_empty_connection_info(&claimed)) {
            return 0;
        }

        pid_connection_info_t connection = {0};
        u16 orig_dport = 0;
        u32 connection_netns = 0;
        u64 connection_netns_cookie = 0;
        if (!java_connection_from_file(file,
                                       TCP_RECV,
                                       &connection.conn,
                                       &orig_dport,
                                       &connection_netns,
                                       &connection_netns_cookie)) {
            return 0;
        }
        mark_java_tls_connection(&claimed, &connection.conn, pid_from_pid_tgid(id));
        return 0;
    }
    case k_ioctl_java_threads:
    case k_ioctl_java_task_link: {
        u64 parent_id = 0;
        if (bpf_probe_read_user(&parent_id, sizeof(parent_id), uarg + 1) != 0) {
            return 0;
        }
        u64 token = 0;
        if (op_cmd == k_ioctl_java_task_link &&
            bpf_probe_read_user(&token, sizeof(token), uarg + 1 + sizeof(parent_id)) != 0) {
            return 0;
        }

        pid_key_t child = {0};
        task_tid(&child);
        pid_key_t logical_child = child;
        java_vt_translate_tid(&logical_child);
        pid_key_t parent = child;
        const u32 parent_tid = tid_from_pid_tgid(parent_id);
        parent.tid = parent_tid;

        if (java_remote_parent_enabled && op_cmd == k_ioctl_java_task_link) {
            bpf_map_delete_elem(&java_tasks, &child);
            obi_ctx__del(id);
            java_remote_parent_link_handoff(&logical_child, token);
            return 0;
        }

        if (parent.tid == child.tid) {
            if (java_remote_parent_enabled) {
                if (op_cmd == k_ioctl_java_threads) {
                    java_remote_parent_fail_handoff(&logical_child);
                }
                bpf_map_delete_elem(&java_tasks, &child);
                obi_ctx__del(id);
            }
            bpf_dbg_printk("self-referencing Java thread mapping ignored");
            return 0;
        }

        if (java_remote_parent_enabled && op_cmd == k_ioctl_java_threads &&
            java_remote_parent_task_mapping_would_cycle(&child, &parent)) {
            java_remote_parent_mark_ambiguous(&child);
            java_remote_parent_mark_ambiguous(&parent);
            java_remote_parent_cancel_handoff(&logical_child, token);
            java_remote_parent_unlink_task(&logical_child);
            bpf_dbg_printk("cyclic Java thread mapping ignored");
            return 0;
        }

        if (java_remote_parent_enabled && op_cmd == k_ioctl_java_threads) {
            const pid_key_t *previous_parent = bpf_map_lookup_elem(&java_tasks, &child);
            if (previous_parent && !java_remote_parent_pid_key_equal(previous_parent, &parent)) {
                java_remote_parent_guard_owner_reuse(&child);
            }
        }

        bpf_dbg_printk("Java thread mapping recorded");
        bpf_map_update_elem(&java_tasks, &child, &parent, BPF_ANY);
        if (java_remote_parent_enabled) {
            if (op_cmd == k_ioctl_java_threads) {
                java_remote_parent_fail_handoff(&logical_child);
            }
        }

        // Walk the java_tasks chain to find the parent's server trace and
        // refresh traces_ctx_v1 for this child thread.
        trace_key_t t_key = {.p_key = parent, .extra_id = extra_runtime_id_with_task_id(parent_id)};
        tp_info_pid_t *server_tp = find_parent_java_trace(&t_key);

        if (server_tp && server_tp->valid) {
            obi_ctx__set(id, &server_tp->tp);
        } else {
            obi_ctx__del(id);
        }

        return 0;
    }
    default:
        break;
    }

    if (op == k_ioctl_invalid_op) {
        bpf_dbg_printk("unknown cmd=%d", op_cmd);
        return 0;
    }

    bpf_dbg_printk("op=%d, cmd=%d", op, op_cmd);

    pid_connection_info_t p_conn = {0};
    u16 orig_dport = 0;
    u32 connection_netns = 0;
    u64 connection_netns_cookie = 0;
    connection_info_t claimed = {0};
    if (bpf_probe_read_user(&claimed, sizeof(claimed), uarg + 1) != 0) {
        return 0;
    }

    if (file) {
        if (!java_connection_from_file(
                file, op, &p_conn.conn, &orig_dport, &connection_netns, &connection_netns_cookie)) {
            return 0;
        }

        // The Java tuple is useful only as a stale-FD/mismatched-correlation
        // guard. The authoritative tuple and network namespace come from the
        // referenced live kernel socket.
        if (!is_empty_connection_info(&claimed) &&
            __builtin_memcmp(&claimed, &p_conn.conn, sizeof(claimed)) != 0) {
            return 0;
        }
        sort_connection_info(&p_conn.conn);
        p_conn.pid = pid_from_pid_tgid(id);
    } else {
        p_conn.conn = claimed;
        // The fallback preserves Java TLS telemetry when the file-bearing
        // hook is unavailable, but its user-claimed tuple is never eligible
        // to stage remote-parent bridge state.
        orig_dport = op == TCP_RECV ? p_conn.conn.s_port : p_conn.conn.d_port;
        sort_connection_info(&p_conn.conn);
        p_conn.pid = pid_from_pid_tgid(id);

        if (is_empty_connection_info(&p_conn.conn)) {
            const ssl_pid_connection_info_t *connection =
                lookup_pid_tid_connection(id, task_thread_start_time());
            if (connection) {
                p_conn = connection->p_conn;
            }
        }
    }
    d_print_http_connection_info(&p_conn.conn);

    if (java_remote_parent_enabled && java_remote_parent_data_hook_is_ready() && connection_netns &&
        op == TCP_RECV) {
        java_remote_parent_begin_data_receive();
    }

    u32 len = 0;
    if (bpf_probe_read_user(&len, sizeof(len), uarg + 1 + sizeof(connection_info_t)) != 0) {
        return 0;
    }
    u64 data_signal_nonce = 0;
    if (bpf_probe_read_user(&data_signal_nonce,
                            sizeof(data_signal_nonce),
                            uarg + 1 + sizeof(connection_info_t) + sizeof(len)) != 0 ||
        (connection_netns && !data_signal_nonce)) {
        return 0;
    }
    if (java_remote_parent_enabled && java_remote_parent_data_hook_is_ready() && connection_netns &&
        op == TCP_RECV) {
        java_remote_parent_publish_data_signal(data_signal_nonce);
    }

    // Bound the parser-visible payload length before we touch the payload
    // pointer or hand it to the shared protocol path.
    u32 max_len = len;
    bpf_clamp_umax(max_len, k_ioctl_max_payload_len);

    bpf_dbg_printk("payload len=%d", max_len);

    if (max_len > 0) {
        unsigned char *buf =
            uarg + 1 + sizeof(connection_info_t) + sizeof(u32) + sizeof(data_signal_nonce);
        // This path consumes one flat user pointer supplied from Java. The
        // security boundary here is "user memory vs. non-user memory", not
        // full range validation. We therefore verify that the claimed payload
        // starts and ends in user-readable memory before the generic tracer
        // consumes it, while keeping the rest of the generic buffer path
        // unchanged.
        unsigned char first = 0;
        if (bpf_probe_read_user(&first, sizeof(first), buf) != 0) {
            return 0;
        }
        unsigned char last = 0;
        if (bpf_probe_read_user(&last, sizeof(last), buf + max_len - 1) != 0) {
            return 0;
        }

        const u64 zero = 0;
        bpf_map_update_elem(&active_ssl_connections, &p_conn, &zero, BPF_NOEXIST);
        handle_java_buf_with_connection(
            ctx, &p_conn, buf, max_len, op, orig_dport, connection_netns, connection_netns_cookie);
    }

    return 0;
}

SEC("kprobe/sys_ioctl")
// unsigned int fd, unsigned int cmd, void *arg
int BPF_KPROBE(obi_kprobe_sys_ioctl) {
    const u64 id = bpf_get_current_pid_tgid();

    // sys_ioctl is retained for control packets and as a telemetry-only
    // fallback when the file-bearing hook could not be attached.
    struct pt_regs *__ctx = (struct pt_regs *)PT_REGS_PARM1(ctx);
    unsigned int cmd = 0;
    void *arg = NULL;
    bpf_probe_read(&cmd, sizeof(cmd), (void *)&PT_REGS_PARM2(__ctx));
    bpf_probe_read(&arg, sizeof(arg), (void *)&PT_REGS_PARM3(__ctx));
    if (cmd != k_ioctl_magic_id || !arg) {
        return 0;
    }

    handle_java_ioctl(ctx, NULL, id, arg, 0);
    if (!java_remote_parent_data_hook_is_ready()) {
        return handle_java_ioctl(ctx, NULL, id, arg, 1);
    }
    return 0;
}

SEC("kprobe/security_file_ioctl")
// struct file *file, unsigned int cmd, unsigned long arg
int BPF_KPROBE(obi_kprobe_security_file_ioctl,
               struct file *file,
               unsigned int cmd,
               unsigned long arg) {
    if (cmd != k_ioctl_magic_id || !arg) {
        return 0;
    }
    if (!java_remote_parent_data_hook_is_ready()) {
        return 0;
    }

    return handle_java_ioctl(ctx, file, bpf_get_current_pid_tgid(), (unsigned char *)arg, 1);
}
