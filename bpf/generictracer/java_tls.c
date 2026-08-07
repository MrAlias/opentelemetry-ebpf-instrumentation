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
#include <maps/java_remote_parent_receive_cursor.h>
#include <maps/java_tasks.h>
#include <maps/java_vt_threads.h>

#include <pid/pid.h>

#include <shared/obi_ctx.h>

#include <generictracer/java_remote_parent_receive.h>
#include <generictracer/java_remote_parent_close.h>
#include <generictracer/java_thread_mapping.h>

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

enum { k_java_control_cleanup_required = 1 };
enum java_ioctl_operation_mask : u8 {
    k_java_ioctl_control = 1 << 0,
    k_java_ioctl_data = 1 << 1,
};
// Keep this ceiling aligned with the largest large-buffer capture limit in
// bpf/common/large_buffers.h.
enum { k_ioctl_max_payload_len = 1 << 16 };

_Static_assert(k_ioctl_java_http1_receive_start ==
                   k_java_remote_parent_data_operation_http1_receive_start,
               "Java HTTP/1 START operation mismatch");
_Static_assert(k_ioctl_java_http1_receive_continue ==
                   k_java_remote_parent_data_operation_http1_receive_continue,
               "Java HTTP/1 CONTINUE operation mismatch");
_Static_assert(k_ioctl_java_http1_receive_reset ==
                   k_java_remote_parent_data_operation_http1_receive_reset,
               "Java HTTP/1 RESET operation mismatch");
_Static_assert(k_ioctl_java_telemetry_receive ==
                   k_java_remote_parent_data_operation_telemetry_receive,
               "Java telemetry RECEIVE operation mismatch");
_Static_assert(sizeof(connection_info_t) <=
                   offsetof(java_remote_parent_receive_context_t, generation),
               "Java advisory tuple overlaps deferred netns-cookie scratch");
_Static_assert(sizeof(connection_info_t) <= offsetof(java_remote_parent_receive_context_t, action),
               "Java advisory tuple overlaps deferred orig-dport scratch");
_Static_assert(offsetof(java_remote_parent_receive_context_t, generation) + sizeof(u64) <=
                   sizeof(java_remote_parent_receive_context_t),
               "Java deferred netns-cookie scratch exceeds receive context");
_Static_assert(offsetof(java_remote_parent_receive_context_t, action) + sizeof(u16) <=
                   sizeof(java_remote_parent_receive_context_t),
               "Java deferred orig-dport scratch exceeds receive context");

static __always_inline java_remote_parent_receive_cursor_t
java_remote_parent_cursor_from_context(const java_remote_parent_receive_context_t *context) {
    return (java_remote_parent_receive_cursor_t){
        .owner =
            {
                .tid = context->owner_tid,
                .pid = context->owner_pid,
                .ns = context->owner_ns,
            },
        .state = context->action == k_java_remote_parent_receive_action_http1_start &&
                         context->generation == 0
                     ? k_java_remote_parent_receive_cursor_publishing
                     : k_java_remote_parent_receive_cursor_valid,
        .process_incarnation = context->process_incarnation,
        .lifecycle_id = context->lifecycle_id,
        .request_sequence = context->request_sequence,
        .data_signal_nonce = context->data_signal_nonce,
        .generation = context->generation,
    };
}

static __always_inline void
java_remote_parent_context_from_cursor(const java_remote_parent_receive_cursor_t *cursor,
                                       enum java_remote_parent_receive_action action,
                                       java_remote_parent_receive_context_t *context) {
    *context = (java_remote_parent_receive_context_t){
        .owner_tid = cursor->owner.tid,
        .owner_pid = cursor->owner.pid,
        .owner_ns = cursor->owner.ns,
        .process_incarnation = cursor->process_incarnation,
        .lifecycle_id = cursor->lifecycle_id,
        .request_sequence = cursor->request_sequence,
        .data_signal_nonce = cursor->data_signal_nonce,
        .generation = cursor->generation,
        .action = action,
    };
}

static __always_inline u8
java_remote_parent_receive_context_exact(const java_remote_parent_receive_context_t *context,
                                         enum java_remote_parent_receive_action action,
                                         u64 socket_cookie) {
    if (!context || context->action != action || context->reserved ||
        __builtin_memcmp(context->reserved2,
                         (unsigned char[sizeof(context->reserved2)]){0},
                         sizeof(context->reserved2)) != 0) {
        return 0;
    }
    const java_remote_parent_receive_cursor_t expected =
        java_remote_parent_cursor_from_context(context);
    if (bpf_map_lookup_elem(&jrp_recv_guard, &socket_cookie)) {
        return 0;
    }
    const java_remote_parent_receive_cursor_t *stored =
        bpf_map_lookup_elem(&jrp_recv_cur, &socket_cookie);
    u8 exact = 0;
    if (action == k_java_remote_parent_receive_action_http1_start) {
        // This is the only path allowed to treat PUBLISHING as authority: the
        // exact identity and nonce carried synchronously by START's own
        // tail-call chain. Independent START/CONTINUE/RESET lookups use VALID
        // predicates and reject this generation-zero state.
        exact = java_remote_parent_receive_cursor_exact_publishing(stored, &expected);
    } else {
        exact = action == k_java_remote_parent_receive_action_http1_continue &&
                java_remote_parent_receive_cursor_is_valid(&expected) &&
                java_remote_parent_receive_cursor_equal(stored, &expected);
    }
    return exact && !bpf_map_lookup_elem(&jrp_recv_guard, &socket_cookie);
}

static __noinline u8
java_remote_parent_ack_receive_generation(const java_remote_parent_receive_cursor_t *pending,
                                          const connection_info_t *connection,
                                          u32 connection_netns,
                                          u64 socket_cookie,
                                          u64 generation) {
    (void)connection;
    (void)connection_netns;
    return java_remote_parent_receive_cursor_ack_generation(socket_cookie, pending, generation);
}

static __always_inline u8 java_connection_from_file(struct file *file,
                                                    u8 op,
                                                    connection_info_t *connection,
                                                    u16 *orig_dport,
                                                    u32 *netns,
                                                    u64 *netns_cookie,
                                                    u64 *socket_cookie) {
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
    *socket_cookie = BPF_CORE_READ(sk, __sk_common.skc_cookie.counter);
    return *netns != 0;
}

// Phase A prepares every socket-authoritative HTTP/1 cursor transition in the
// existing per-CPU scratch slots, but never performs generation detachment.
// The security-file hook invokes the exact fence only after this frame has
// returned, then phase C consumes the recorded transition.
static __noinline u8
handle_java_http1_bridge_prepare(struct file *file,
                                 u64 process_capability,
                                 unsigned char *uarg,
                                 enum java_remote_parent_data_operation operation) {
    const enum java_remote_parent_receive_action action =
        java_remote_parent_data_receive_action(operation);
    if (!file || (action != k_java_remote_parent_receive_action_http1_start &&
                  action != k_java_remote_parent_receive_action_http1_continue &&
                  action != k_java_remote_parent_receive_action_http1_reset)) {
        return k_java_remote_parent_receive_ioctl_transition_invalid;
    }

    java_remote_parent_state_t *cursor_scratch = java_remote_parent_stage_state_mem();
    java_remote_parent_incoming_t *context_scratch = java_remote_parent_incoming_snapshot_mem();
    connection_info_t *connection = java_remote_parent_connection_snapshot_mem();
    if (!cursor_scratch || !context_scratch || !connection) {
        return k_java_remote_parent_receive_ioctl_transition_invalid;
    }
    java_remote_parent_receive_ioctl_workspace_t *workspace =
        (java_remote_parent_receive_ioctl_workspace_t *)cursor_scratch;
    java_remote_parent_receive_context_t *context =
        (java_remote_parent_receive_context_t *)context_scratch;
    __builtin_memset(workspace, 0, sizeof(*workspace));
    __builtin_memset(context, 0, sizeof(*context));
    __builtin_memset(connection, 0, sizeof(*connection));

    // Reuse the not-yet-published context as short-lived preflight storage.
    // It is cleared before any receive context becomes visible to phase C.
    connection_info_t *claimed = (connection_info_t *)context;
    if (bpf_probe_read_user(
            claimed, sizeof(*claimed), uarg + k_java_remote_parent_data_connection_offset) != 0) {
        return k_java_remote_parent_receive_ioctl_transition_invalid;
    }
    // Keep helper outputs beyond the 36-byte advisory tuple. In particular,
    // context->reserved is inside connection_info_t's source-address bytes.
    u16 *orig_dport = (u16 *)&context->action;
    u64 *connection_netns_cookie = &context->generation;
    if (!java_connection_from_file(file,
                                   TCP_RECV,
                                   connection,
                                   orig_dport,
                                   &workspace->connection_netns,
                                   connection_netns_cookie,
                                   &workspace->socket_cookie) ||
        (!is_empty_connection_info(claimed) &&
         __builtin_memcmp(claimed, connection, sizeof(*claimed)) != 0)) {
        return k_java_remote_parent_receive_ioctl_transition_invalid;
    }
    sort_connection_info(connection);

    u32 len = 0;
    u64 data_signal_nonce = 0;
    u64 lifecycle_id = 0;
    u64 request_sequence = 0;
    if (bpf_probe_read_user(&len, sizeof(len), uarg + k_java_remote_parent_data_length_offset) !=
            0 ||
        bpf_probe_read_user(&data_signal_nonce,
                            sizeof(data_signal_nonce),
                            uarg + k_java_remote_parent_data_signal_offset) != 0 ||
        bpf_probe_read_user(&lifecycle_id,
                            sizeof(lifecycle_id),
                            uarg + k_java_remote_parent_data_http1_lifecycle_offset) != 0 ||
        bpf_probe_read_user(&request_sequence,
                            sizeof(request_sequence),
                            uarg + k_java_remote_parent_data_http1_request_sequence_offset) != 0) {
        return k_java_remote_parent_receive_ioctl_transition_invalid;
    }

    pid_key_t task = {0};
    task_tid(&task);
    const u64 process_incarnation = java_process_incarnation_for(&task);
    const pid_key_t process = java_process_key(&task);
    if (!workspace->connection_netns || !workspace->socket_cookie ||
        process_incarnation != process_capability) {
        return k_java_remote_parent_receive_ioctl_transition_invalid;
    }
    java_remote_parent_receive_ioctl_fence_context_init(context, *connection_netns_cookie);

    const u8 prefix_valid = java_remote_parent_http1_prefix_valid(
        operation, len, data_signal_nonce, lifecycle_id, request_sequence);
    if (!prefix_valid || action == k_java_remote_parent_receive_action_http1_reset) {
        // Malformed CONTINUE/RESET and normal RESET share the same deferred
        // terminal transition. This removes the old cleanup_identity -> full
        // fence edge from beneath the large payload frame.
        if (action == k_java_remote_parent_receive_action_http1_start || !lifecycle_id ||
            !request_sequence ||
            !java_remote_parent_receive_cursor_reset(workspace->socket_cookie,
                                                     &process,
                                                     process_incarnation,
                                                     lifecycle_id,
                                                     request_sequence,
                                                     &workspace->cursor)) {
            return k_java_remote_parent_receive_ioctl_transition_invalid;
        }
        const enum java_remote_parent_receive_guard_result guard =
            java_remote_parent_receive_cursor_guard_acquire(workspace->socket_cookie,
                                                            &workspace->cursor);
        if (guard == k_java_remote_parent_receive_guard_busy) {
            return k_java_remote_parent_receive_ioctl_transition_invalid;
        }
        workspace->guard = guard;
        if (guard == k_java_remote_parent_receive_guard_acquired) {
            workspace->transition = k_java_remote_parent_receive_ioctl_transition_fence_retire;
        } else {
            // ERROR still fences the exact observed generation but has no
            // cursor-mutation authority in phase C. fence_abort targets the
            // predecessor slot by construction.
            workspace->predecessor = workspace->cursor;
            workspace->transition = k_java_remote_parent_receive_ioctl_transition_fence_abort;
        }
        return workspace->transition;
    }

    if (action == k_java_remote_parent_receive_action_http1_continue) {
        if (!java_remote_parent_receive_cursor_continue(workspace->socket_cookie,
                                                        &process,
                                                        process_incarnation,
                                                        lifecycle_id,
                                                        request_sequence,
                                                        &workspace->cursor) ||
            !workspace->cursor.generation) {
            return k_java_remote_parent_receive_ioctl_transition_invalid;
        }
        java_remote_parent_context_from_cursor(&workspace->cursor, action, context);
        workspace->transition = k_java_remote_parent_receive_ioctl_transition_ready;
        return workspace->transition;
    }

    const pid_key_t owner = java_remote_parent_current_owner();
    workspace->cursor = java_remote_parent_receive_cursor_publishing_identity(
        &owner, process_incarnation, lifecycle_id, request_sequence, data_signal_nonce);
    if (!java_remote_parent_receive_cursor_snapshot_state(workspace->socket_cookie,
                                                          &workspace->predecessor)) {
        if (!java_remote_parent_receive_cursor_publish(workspace->socket_cookie,
                                                       &workspace->cursor)) {
            return k_java_remote_parent_receive_ioctl_transition_invalid;
        }
        java_remote_parent_publish_data_signal(data_signal_nonce);
        java_remote_parent_context_from_cursor(&workspace->cursor, action, context);
        workspace->transition = k_java_remote_parent_receive_ioctl_transition_ready;
        return workspace->transition;
    }
    if (!java_remote_parent_receive_cursor_is_valid(&workspace->predecessor)) {
        return k_java_remote_parent_receive_ioctl_transition_invalid;
    }
    const enum java_remote_parent_receive_guard_result guard =
        java_remote_parent_receive_cursor_guard_acquire(workspace->socket_cookie,
                                                        &workspace->predecessor);
    if (guard == k_java_remote_parent_receive_guard_busy) {
        return k_java_remote_parent_receive_ioctl_transition_invalid;
    }
    workspace->guard = guard;
    workspace->transition = guard == k_java_remote_parent_receive_guard_acquired
                                ? k_java_remote_parent_receive_ioctl_transition_fence_replace
                                : k_java_remote_parent_receive_ioctl_transition_fence_abort;
    return workspace->transition;
}

static __noinline u8 java_remote_parent_prepared_receive_exact(
    const java_remote_parent_receive_ioctl_workspace_t *workspace,
    const java_remote_parent_receive_context_t *context,
    const connection_info_t *prepared_connection,
    const connection_info_t *current_connection) {
    if (!workspace || !context || !prepared_connection || !current_connection ||
        !java_remote_parent_receive_ioctl_ready_context_exact(workspace, context) ||
        __builtin_memcmp(prepared_connection, current_connection, sizeof(*prepared_connection)) !=
            0 ||
        bpf_map_lookup_elem(&jrp_recv_guard, &workspace->socket_cookie)) {
        return 0;
    }
    const java_remote_parent_receive_cursor_t *stored =
        bpf_map_lookup_elem(&jrp_recv_cur, &workspace->socket_cookie);
    return java_remote_parent_receive_cursor_equal(stored, &workspace->cursor) &&
           !bpf_map_lookup_elem(&jrp_recv_guard, &workspace->socket_cookie);
}

// Keep the receive-boundary detach in a small sibling that returns before the
// large payload frame is entered. This preserves detach-before-registration-
// return and detach-before-advisory-read without nesting the 200-byte owner
// cleanup frame under handle_java_data_ioctl.
static __noinline u64 handle_java_data_authority(u8 *registered) {
    pid_key_t task = {0};
    task_tid(&task);
    const u64 process_capability = java_process_capability_for(&task);
    if (!process_capability) {
        return 0;
    }
    *registered = java_process_incarnation_for(&task) == process_capability;
    return process_capability;
}

static __noinline u64 handle_java_data_gate(struct file *file,
                                            enum java_remote_parent_data_operation operation) {
    const u8 data_hook_ready =
        java_remote_parent_enabled && java_remote_parent_data_hook_is_ready();
    const enum java_remote_parent_data_dispatch dispatch =
        java_remote_parent_select_data_dispatch(operation, data_hook_ready, file != NULL);
    if (dispatch == k_java_remote_parent_data_dispatch_invalid ||
        dispatch == k_java_remote_parent_data_dispatch_ignore) {
        return 0;
    }

    // Finish the stack-backed task/capability lookup before entering the deep
    // receive-boundary detach. Only its scalar result remains live here.
    u8 registered = 0;
    const u64 process_capability = handle_java_data_authority(&registered);
    if (!process_capability) {
        return 0;
    }
    const u8 boundary_hook_ready =
        java_remote_parent_data_dispatch_detaches_owner(operation, dispatch, data_hook_ready);
    return java_remote_parent_begin_receive(
               java_remote_parent_enabled,
               boundary_hook_ready,
               registered,
               java_remote_parent_data_starts_receive_boundary(operation),
               process_capability)
               ? process_capability
               : 0;
}

// Keep the payload path in a separate sibling so its connection and cursor
// locals never overlap the receive-boundary cleanup frame.
static __noinline int handle_java_data_ioctl(struct pt_regs *ctx,
                                             struct file *file,
                                             u64 process_capability,
                                             unsigned char *uarg,
                                             enum java_remote_parent_data_operation operation) {
    const u8 data_hook_ready =
        java_remote_parent_enabled && java_remote_parent_data_hook_is_ready();
    const enum java_remote_parent_data_dispatch dispatch =
        java_remote_parent_select_data_dispatch(operation, data_hook_ready, file != NULL);
    const enum java_remote_parent_receive_action wire_receive_action =
        java_remote_parent_data_receive_action(operation);
    const enum java_remote_parent_receive_action receive_action =
        java_remote_parent_effective_receive_action(operation, dispatch);
    const u8 parser_direction = java_remote_parent_data_parser_direction(operation);
    const u8 http1_receive =
        wire_receive_action == k_java_remote_parent_receive_action_http1_start ||
        wire_receive_action == k_java_remote_parent_receive_action_http1_continue ||
        wire_receive_action == k_java_remote_parent_receive_action_http1_reset;
    const u8 bridge_http1_receive = java_remote_parent_data_dispatch_has_bridge_authority(dispatch);
    const u8 wire_telemetry_receive =
        wire_receive_action == k_java_remote_parent_receive_action_telemetry;
    const u8 telemetry_receive = receive_action == k_java_remote_parent_receive_action_telemetry;
    if (dispatch == k_java_remote_parent_data_dispatch_invalid ||
        dispatch == k_java_remote_parent_data_dispatch_ignore ||
        receive_action == k_java_remote_parent_receive_action_invalid ||
        (parser_direction == k_java_remote_parent_parser_direction_invalid &&
         wire_receive_action != k_java_remote_parent_receive_action_http1_reset)) {
        return 0;
    }

    connection_info_t claimed = {0};
    if (bpf_probe_read_user(
            &claimed, sizeof(claimed), uarg + k_java_remote_parent_data_connection_offset) != 0) {
        return 0;
    }

    bpf_dbg_printk("op=%d", operation);

    pid_connection_info_t p_conn = {0};
    u16 orig_dport = 0;
    u32 connection_netns = 0;
    u64 connection_netns_cookie = 0;
    u64 socket_cookie = 0;
    const u64 id = bpf_get_current_pid_tgid();
    if (file) {
        if (!java_connection_from_file(file,
                                       http1_receive ? TCP_RECV : parser_direction,
                                       &p_conn.conn,
                                       &orig_dport,
                                       &connection_netns,
                                       &connection_netns_cookie,
                                       &socket_cookie)) {
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
        if (bridge_http1_receive) {
            return 0;
        }
        p_conn.conn = claimed;
        // The fallback preserves Java TLS telemetry when the file-bearing
        // hook is unavailable, but its user-claimed tuple is never eligible
        // to stage remote-parent bridge state.
        orig_dport = parser_direction == TCP_RECV ? p_conn.conn.s_port : p_conn.conn.d_port;
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

    u32 len = 0;
    if (bpf_probe_read_user(&len, sizeof(len), uarg + k_java_remote_parent_data_length_offset) !=
        0) {
        return 0;
    }
    u64 data_signal_nonce = 0;
    if (bpf_probe_read_user(&data_signal_nonce,
                            sizeof(data_signal_nonce),
                            uarg + k_java_remote_parent_data_signal_offset) != 0) {
        return 0;
    }

    u64 lifecycle_id = 0;
    u64 request_sequence = 0;
    if (http1_receive) {
        if (bpf_probe_read_user(&lifecycle_id,
                                sizeof(lifecycle_id),
                                uarg + k_java_remote_parent_data_http1_lifecycle_offset) != 0 ||
            bpf_probe_read_user(&request_sequence,
                                sizeof(request_sequence),
                                uarg + k_java_remote_parent_data_http1_request_sequence_offset) !=
                0) {
            return 0;
        }
        if (!java_remote_parent_http1_prefix_valid(
                operation, len, data_signal_nonce, lifecycle_id, request_sequence)) {
            return 0;
        }
    }
    if (wire_telemetry_receive &&
        !java_remote_parent_telemetry_prefix_valid(len, data_signal_nonce)) {
        return 0;
    }
    if (!http1_receive && !wire_telemetry_receive && connection_netns && !data_signal_nonce) {
        return 0;
    }

    // Bound the parser-visible payload length before we touch the payload
    // pointer or hand it to the shared protocol path.
    u32 max_len = len;
    bpf_clamp_umax(max_len, k_ioctl_max_payload_len);

    bpf_dbg_printk("payload len=%d", max_len);

    // These identities previously consumed 176 bytes in an already-large
    // ioctl frame. Reuse two lifecycle scratch slots only until the parser
    // tail call: the HTTP path copies receive_context into protocol_args before
    // it reuses either slot for incoming staging.
    java_remote_parent_state_t *cursor_scratch = java_remote_parent_stage_state_mem();
    java_remote_parent_incoming_t *context_scratch = java_remote_parent_incoming_snapshot_mem();
    connection_info_t *prepared_connection =
        bridge_http1_receive ? java_remote_parent_connection_snapshot_mem() : NULL;
    if (!cursor_scratch || !context_scratch || (bridge_http1_receive && !prepared_connection)) {
        return 0;
    }
    java_remote_parent_receive_ioctl_workspace_t *receive_workspace =
        (java_remote_parent_receive_ioctl_workspace_t *)cursor_scratch;
    java_remote_parent_receive_context_t *receive_context =
        (java_remote_parent_receive_context_t *)context_scratch;
    if (bridge_http1_receive) {
        if (wire_receive_action == k_java_remote_parent_receive_action_http1_reset ||
            receive_context->action != wire_receive_action ||
            receive_context->lifecycle_id != lifecycle_id ||
            receive_context->request_sequence != request_sequence ||
            !java_remote_parent_http1_data_signal_exact(
                wire_receive_action, receive_context->data_signal_nonce, data_signal_nonce) ||
            receive_context->process_incarnation != process_capability ||
            receive_workspace->socket_cookie != socket_cookie ||
            receive_workspace->connection_netns != connection_netns ||
            !java_remote_parent_prepared_receive_exact(
                receive_workspace, receive_context, prepared_connection, &p_conn.conn)) {
            return 0;
        }
    } else {
        __builtin_memset(receive_workspace, 0, sizeof(*receive_workspace));
        __builtin_memset(receive_context, 0, sizeof(*receive_context));
        if (telemetry_receive) {
            receive_context->action = receive_action;
        } else if (java_remote_parent_enabled && java_remote_parent_data_hook_is_ready() &&
                   connection_netns && parser_direction == TCP_RECV) {
            java_remote_parent_publish_data_signal(data_signal_nonce);
        }
    }

    if (max_len > 0) {
        unsigned char *buf = uarg + java_remote_parent_data_payload_offset(operation);
        // This path consumes one flat user pointer supplied from Java. The
        // security boundary here is "user memory vs. non-user memory", not
        // full range validation. We therefore verify that the claimed payload
        // starts and ends in user-readable memory before the generic tracer
        // consumes it, while keeping the rest of the generic buffer path
        // unchanged.
        unsigned char first = 0;
        if (bpf_probe_read_user(&first, sizeof(first), buf) != 0) {
            goto cleanup_http1_receive;
        }
        unsigned char last = 0;
        if (bpf_probe_read_user(&last, sizeof(last), buf + max_len - 1) != 0) {
            goto cleanup_http1_receive;
        }

        const u64 zero = 0;
        bpf_map_update_elem(&active_ssl_connections, &p_conn, &zero, BPF_NOEXIST);
        handle_java_buf_with_connection(
            ctx,
            &p_conn,
            buf,
            max_len,
            parser_direction,
            orig_dport,
            connection_netns,
            connection_netns_cookie,
            socket_cookie,
            (bridge_http1_receive || telemetry_receive) ? receive_context : NULL);
    }

cleanup_http1_receive:
    // A successful tail call does not return. The shallow outer phase owns
    // cleanup for every normal return, including preflight reread failures,
    // so this large payload frame has no generation-fence call edge.
    return 0;
}

static __noinline int handle_java_unregistered_lifecycle_ioctl(unsigned char *uarg,
                                                               u8 op_cmd,
                                                               const pid_key_t *task,
                                                               u64 process_capability);
static __noinline int handle_java_unregistered_control_ioctl(
    unsigned char *uarg, u64 id, u8 op_cmd, const pid_key_t *task, u64 process_capability);

static __noinline int handle_java_registered_lifecycle_ioctl(unsigned char *uarg,
                                                             u8 op_cmd,
                                                             const pid_key_t *task,
                                                             u64 process_capability) {
    switch (op_cmd) {
    case k_ioctl_java_process_register: {
        u64 incarnation = 0;
        if (bpf_probe_read_user(&incarnation, sizeof(incarnation), uarg + 1) != 0 || !incarnation) {
            return 0;
        }

        pid_key_t process = java_process_key(task);
        if (process_capability != incarnation ||
            java_process_capability_for(&process) != incarnation) {
            return 0;
        }
        java_thread_mapping_register_process(
            task, &process, bpf_get_current_pid_tgid(), incarnation, java_remote_parent_enabled);
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

        const pid_key_t carrier = *task;
        pid_key_t synthetic_owner = {0};
        java_vt_identity_t mount_identity = {0};
        enum java_vt_mount_result mount_result =
            java_vt_prepare_mount(&carrier, vt_id, &synthetic_owner, &mount_identity);

        if (mount_result == k_java_vt_mount_collision ||
            mount_result == k_java_vt_mount_stale_incarnation) {
            if (java_remote_parent_enabled) {
                java_remote_parent_discard_virtual_thread_owner(&synthetic_owner);
            }
            if (mount_result == k_java_vt_mount_collision ||
                !java_vt_replace_stale_identity(&synthetic_owner, &mount_identity)) {
                if (java_remote_parent_enabled) {
                    // Removing the carrier translation must also destroy the
                    // logical/physical cursors and legacy mapping it masked.
                    java_remote_parent_discard_unregistered_virtual_thread_lifecycle(
                        &carrier, process_capability);
                } else {
                    bpf_map_delete_elem(&java_vt_threads, &carrier);
                }
                return 0;
            }
        } else if (mount_result == k_java_vt_mount_new_identity) {
            if (java_remote_parent_enabled) {
                // A newly inserted LRU guard may replace an evicted full-width
                // identity. Discard the shared synthetic key before publishing
                // it, so neither the same nor a colliding VT can revive state.
                java_remote_parent_discard_virtual_thread_owner(&synthetic_owner);
            }
        } else if (mount_result != k_java_vt_mount_success) {
            if (java_remote_parent_enabled) {
                java_remote_parent_discard_unregistered_virtual_thread_id(
                    &carrier, vt_id, process_capability, 1);
            } else {
                bpf_map_delete_elem(&java_vt_threads, &carrier);
            }
            return 0;
        }

        if (java_remote_parent_enabled) {
            java_remote_parent_cleanup(&carrier);
            bpf_map_delete_elem(&java_tasks, &carrier);
        }

        bpf_dbg_printk("Java virtual thread mount observed");
        if (!java_vt_publish_mount(&carrier, &mount_identity)) {
            if (java_remote_parent_enabled) {
                java_remote_parent_discard_virtual_thread_owner(&synthetic_owner);
            }
            bpf_map_delete_elem(&java_vt_threads, &carrier);
        }

        return 0;
    }
    case k_ioctl_java_vt_terminate: {
        u64 vt_id = 0;
        if (bpf_probe_read_user(&vt_id, sizeof(vt_id), uarg + 1) != 0) {
            return 0;
        }

        const pid_key_t carrier = *task;
        pid_key_t owner = {0};
        if (!java_vt_terminate_identity(&carrier, vt_id, &owner)) {
            if (java_remote_parent_enabled) {
                java_remote_parent_discard_unregistered_virtual_thread_id(
                    &carrier, vt_id, process_capability, 1);
            } else {
                java_vt_identity_t expected_identity = {0};
                if (java_vt_prepare_unregistered_cleanup(
                        &carrier, vt_id, process_capability, &owner, &expected_identity)) {
                    java_vt_delete_identity_if_matches(&owner, &expected_identity);
                }
                bpf_map_delete_elem(&java_vt_threads, &carrier);
            }
            return 0;
        }
        if (java_remote_parent_enabled) {
            java_remote_parent_discard_virtual_thread_owner(&owner);
        }
        // Keep the full-width guard present until all state under its
        // synthetic key has been discarded.
        java_vt_identity_t expected_identity = {0};
        if (java_vt_prepare_unregistered_cleanup(
                &carrier, vt_id, process_capability, &owner, &expected_identity)) {
            java_vt_delete_identity_if_matches(&owner, &expected_identity);
        }
        return 0;
    }
    case k_ioctl_java_vt_unmount: {
        // The mounted VT left this carrier: delete the entry so a carrier
        // with no mounted VT is never translated. mount/unmount for a
        // carrier always execute ON that carrier thread, so write and
        // delete are in program order.
        const pid_key_t carrier = *task;

        bpf_dbg_printk("Java virtual thread unmount observed");
        if (java_remote_parent_enabled) {
            java_remote_parent_cleanup(&carrier);
            bpf_map_delete_elem(&java_tasks, &carrier);
        }
        bpf_map_delete_elem(&java_vt_threads, &carrier);

        return 0;
    }
    default:
        return 0;
    }
}

static __noinline int handle_java_lifecycle_ioctl(unsigned char *uarg,
                                                  u8 op_cmd,
                                                  const pid_key_t *task,
                                                  u64 process_capability) {
    if (op_cmd != k_ioctl_java_process_register &&
        java_process_incarnation_for(task) != process_capability) {
        return handle_java_unregistered_lifecycle_ioctl(uarg, op_cmd, task, process_capability);
    }
    return handle_java_registered_lifecycle_ioctl(uarg, op_cmd, task, process_capability);
}

static __noinline int handle_java_unregistered_lifecycle_ioctl(unsigned char *uarg,
                                                               u8 op_cmd,
                                                               const pid_key_t *task,
                                                               u64 process_capability) {
    if (op_cmd == k_ioctl_java_vt_unmount) {
        if (java_remote_parent_enabled) {
            java_remote_parent_discard_unregistered_virtual_thread_lifecycle(task,
                                                                             process_capability);
        } else {
            bpf_map_delete_elem(&java_vt_threads, task);
        }
        return 0;
    }

    u64 vt_id = 0;
    if (bpf_probe_read_user(&vt_id, sizeof(vt_id), uarg + 1) != 0) {
        if (java_remote_parent_enabled) {
            java_remote_parent_discard_unregistered_virtual_thread_lifecycle(task,
                                                                             process_capability);
        } else {
            bpf_map_delete_elem(&java_vt_threads, task);
        }
        return 0;
    }

    if (java_remote_parent_enabled) {
        java_remote_parent_discard_unregistered_virtual_thread_id(
            task, vt_id, process_capability, 1);
    } else {
        bpf_map_delete_elem(&java_vt_threads, task);
        if (op_cmd == k_ioctl_java_vt_mount || op_cmd == k_ioctl_java_vt_terminate) {
            pid_key_t owner = {0};
            java_vt_identity_t expected_identity = {0};
            if (java_vt_prepare_unregistered_cleanup(
                    task, vt_id, process_capability, &owner, &expected_identity)) {
                java_vt_delete_identity_if_matches(&owner, &expected_identity);
            }
        }
    }
    return 0;
}

static __noinline int handle_java_unregistered_control_ioctl(
    unsigned char *uarg, u64 id, u8 op_cmd, const pid_key_t *task, u64 process_capability) {
    const u8 token_operation =
        op_cmd == k_ioctl_java_task_capture || op_cmd == k_ioctl_java_task_cancel ||
        op_cmd == k_ioctl_java_task_relay_capture || op_cmd == k_ioctl_java_task_link;
    if (token_operation) {
        unsigned char *token_arg = uarg + 1;
        if (op_cmd == k_ioctl_java_task_link) {
            token_arg += sizeof(u64);
        }
        u64 token = 0;
        if (bpf_probe_read_user(&token, sizeof(token), token_arg) == 0 &&
            java_remote_parent_enabled) {
            java_remote_parent_cancel_handoff_for_capability(task, token, process_capability);
        }
    }

    const u8 execution_lifecycle = op_cmd == k_ioctl_java_threads ||
                                   op_cmd == k_ioctl_java_task_link ||
                                   op_cmd == k_ioctl_java_task_unlink;
    if (!execution_lifecycle) {
        return 0;
    }
    if (java_remote_parent_enabled) {
        java_remote_parent_discard_unregistered_task_lifecycle(task, process_capability);
    }
    bpf_map_delete_elem(&java_tasks, task);
    obi_ctx__del(id);
    return 0;
}

static __noinline int handle_java_tls_connection_ioctl(struct file *file, unsigned char *uarg) {
    pid_key_t task = {0};
    task_tid(&task);
    const u64 process_capability = java_process_capability_for(&task);
    if (!java_remote_parent_enabled || !process_capability ||
        java_process_incarnation_for(&task) != process_capability) {
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
    u64 socket_cookie = 0;
    if (!java_connection_from_file(file,
                                   TCP_RECV,
                                   &connection.conn,
                                   &orig_dport,
                                   &connection_netns,
                                   &connection_netns_cookie,
                                   &socket_cookie)) {
        return 0;
    }
    mark_java_tls_connection(
        &claimed, &connection.conn, pid_from_pid_tgid(bpf_get_current_pid_tgid()));
    return 0;
}

static __noinline int handle_java_task_capture_ioctl(unsigned char *uarg,
                                                     const pid_key_t *execution) {
    u64 token = 0;
    if (bpf_probe_read_user(&token, sizeof(token), uarg + 1) == 0 && java_remote_parent_enabled) {
        java_remote_parent_capture_handoff_for_execution(execution, token);
    }
    return 0;
}

static __noinline int handle_java_task_cancel_ioctl(unsigned char *uarg,
                                                    const pid_key_t *execution,
                                                    u64 process_capability) {
    u64 token = 0;
    if (bpf_probe_read_user(&token, sizeof(token), uarg + 1) == 0 && java_remote_parent_enabled) {
        java_remote_parent_cancel_handoff_for_capability(execution, token, process_capability);
    }
    return 0;
}

static __noinline int handle_java_task_relay_capture_ioctl(unsigned char *uarg,
                                                           const pid_key_t *execution) {
    u64 token = 0;
    if (bpf_probe_read_user(&token, sizeof(token), uarg + 1) == 0 && java_remote_parent_enabled) {
        java_remote_parent_capture_relay(execution, token);
    }
    return 0;
}

static __noinline int
handle_java_task_unlink_ioctl(const pid_key_t *task, const pid_key_t *execution, u64 id) {
    java_thread_mapping_unlink_execution(task, execution, id, java_remote_parent_enabled);
    return 0;
}

static __noinline int handle_java_threads_ioctl(unsigned char *uarg,
                                                u64 id,
                                                const pid_key_t *task,
                                                const pid_key_t *execution,
                                                u64 process_capability) {
    return handle_java_thread_mapping_ioctl(
        uarg, id, task, execution, process_capability, java_remote_parent_enabled);
}

static __noinline int handle_java_task_link_ioctl(unsigned char *uarg,
                                                  u64 id,
                                                  const pid_key_t *task,
                                                  const pid_key_t *execution,
                                                  u64 process_capability) {
    u64 parent_id = 0;
    if (bpf_probe_read_user(&parent_id, sizeof(parent_id), uarg + 1) != 0) {
        return 0;
    }
    u64 token = 0;
    if (bpf_probe_read_user(&token, sizeof(token), uarg + 1 + sizeof(parent_id)) != 0) {
        return 0;
    }

    if (java_remote_parent_enabled) {
        bpf_map_delete_elem(&java_tasks, task);
        obi_ctx__del(id);
        java_remote_parent_link_handoff_for_capability(execution, token, process_capability);
        return 0;
    }
    return handle_java_thread_mapping(parent_id, id, task, execution, process_capability, 0);
}

static __noinline int handle_java_control_ioctl(unsigned char *uarg,
                                                u8 op_cmd,
                                                const pid_key_t *task,
                                                u64 process_capability) {
    const u64 id = bpf_get_current_pid_tgid();
    if (java_process_incarnation_for(task) != process_capability) {
        return k_java_control_cleanup_required;
    }

    pid_key_t execution = *task;
    const enum java_vt_cleanup_translation_result translation =
        java_vt_translate_tid_for_capability(&execution, process_capability);
    if (translation == k_java_vt_cleanup_translation_fallback) {
        return k_java_control_cleanup_required;
    }

    switch (op_cmd) {
    case k_ioctl_java_task_capture:
        return handle_java_task_capture_ioctl(uarg, &execution);
    case k_ioctl_java_task_cancel:
        return handle_java_task_cancel_ioctl(uarg, &execution, process_capability);
    case k_ioctl_java_task_relay_capture:
        return handle_java_task_relay_capture_ioctl(uarg, &execution);
    case k_ioctl_java_task_unlink:
        return handle_java_task_unlink_ioctl(task, &execution, id);
    case k_ioctl_java_threads:
        return handle_java_threads_ioctl(uarg, id, task, &execution, process_capability);
    case k_ioctl_java_task_link:
        return handle_java_task_link_ioctl(uarg, id, task, &execution, process_capability);
    default:
        bpf_dbg_printk("unknown cmd=%d", op_cmd);
        return 0;
    }
}

static __always_inline int
handle_java_data_operation_ioctl(struct pt_regs *ctx,
                                 struct file *file,
                                 unsigned char *uarg,
                                 enum java_remote_parent_data_operation operation) {
    if (operation != k_java_remote_parent_data_operation_invalid) {
        const u64 process_capability = handle_java_data_gate(file, operation);
        if (!process_capability) {
            return 0;
        }
        const u8 data_hook_ready =
            java_remote_parent_enabled && java_remote_parent_data_hook_is_ready();
        const enum java_remote_parent_data_dispatch dispatch =
            java_remote_parent_select_data_dispatch(operation, data_hook_ready, file != NULL);
        if (!java_remote_parent_data_dispatch_has_bridge_authority(dispatch)) {
            return handle_java_data_ioctl(ctx, file, process_capability, uarg, operation);
        }

        const u8 transition =
            handle_java_http1_bridge_prepare(file, process_capability, uarg, operation);
        if (!java_remote_parent_receive_ioctl_transition_known(transition)) {
            return 0;
        }
        if (java_remote_parent_receive_ioctl_transition_needs_fence(transition)) {
            java_remote_parent_state_t *cursor_scratch = java_remote_parent_stage_state_mem();
            java_remote_parent_receive_ioctl_workspace_t *workspace =
                (java_remote_parent_receive_ioctl_workspace_t *)cursor_scratch;
            java_remote_parent_receive_cursor_t *fence_cursor =
                java_remote_parent_receive_ioctl_fence_cursor(workspace);
            if (!workspace || !fence_cursor || workspace->transition != transition ||
                !workspace->socket_cookie || !workspace->connection_netns ||
                !java_remote_parent_receive_ioctl_fence_authorized(workspace)) {
                return 0;
            }

            java_remote_parent_incoming_t *fence_context_scratch =
                java_remote_parent_incoming_snapshot_mem();
            const u64 connection_netns_cookie =
                java_remote_parent_receive_ioctl_fence_context_cookie(
                    (java_remote_parent_receive_context_t *)fence_context_scratch);
            connection_info_t *prepared_connection = java_remote_parent_connection_snapshot_mem();
            if (!connection_netns_cookie || !prepared_connection ||
                is_empty_connection_info(prepared_connection)) {
                return 0;
            }

            // The gate may already have completed exact terminal-free cleanup
            // or observed a strict completed TAKE. Recognize those final forms
            // without recreating M for a generation that no longer exists.
            java_remote_parent_cleanup_receive_cursor_signal(fence_cursor);
            u8 generation_fenced =
                java_remote_parent_receive_generation_already_fenced(fence_cursor,
                                                                     prepared_connection,
                                                                     workspace->connection_netns,
                                                                     connection_netns_cookie,
                                                                     workspace->socket_cookie);
            if (!generation_fenced) {
                const java_remote_parent_key_t generation_key =
                    java_remote_parent_state_key(&fence_cursor->owner, fence_cursor->generation);
                // Zero-alias generations are the normal sequential HTTP/1
                // case. Remove O/F/S/I/C before publishing the next cursor so
                // no BPF_NOEXIST key can reject its STAGE transaction.
                generation_fenced = java_remote_parent_cleanup_exact_receive_zero_alias(
                    &generation_key,
                    fence_cursor->process_incarnation,
                    prepared_connection,
                    workspace->connection_netns,
                    workspace->socket_cookie);
                if (!generation_fenced) {
                    // A preserved async/task alias keeps S/I and clean M0, but
                    // must detach O/F/C so both the old exact alias and the
                    // immediate next socket generation remain usable.
                    generation_fenced = java_remote_parent_detach_exact_receive_aliased(
                        &generation_key,
                        fence_cursor->process_incarnation,
                        prepared_connection,
                        workspace->connection_netns,
                        workspace->socket_cookie);
                }
            }
            // Any partial or destructive-fault form lands here. A nonzero
            // exact marker revokes SDK authority while close/userspace
            // convergence handles the retained graph.
            if (!generation_fenced) {
                generation_fenced = java_remote_parent_fence_receive_cursor_ambiguous(
                    fence_cursor, fence_cursor->generation);
            }
            if (!generation_fenced && fence_cursor->generation) {
                generation_fenced = java_remote_parent_fence_receive_cursor_ambiguous(
                    fence_cursor, fence_cursor->generation);
            }
            if (!java_remote_parent_complete_receive_ioctl_transition(workspace,
                                                                      generation_fenced)) {
                return 0;
            }
            java_remote_parent_incoming_t *context_scratch =
                java_remote_parent_incoming_snapshot_mem();
            java_remote_parent_receive_context_t *receive_context =
                (java_remote_parent_receive_context_t *)context_scratch;
            if (!receive_context) {
                java_remote_parent_cleanup_receive_cursor(
                    &workspace->cursor, workspace->socket_cookie, workspace->cursor.generation);
                return 0;
            }
            java_remote_parent_context_from_cursor(&workspace->cursor,
                                                   k_java_remote_parent_receive_action_http1_start,
                                                   receive_context);
        }
        const int result = handle_java_data_ioctl(ctx, file, process_capability, uarg, operation);
        // Tail-call success never returns. Any normal return means preflight
        // changed, the user payload became unreadable, or no parser accepted
        // it. Re-fetch the exact prepared transition and retire only that
        // cursor through the shallow M+ cleanup path.
        java_remote_parent_state_t *cursor_scratch = java_remote_parent_stage_state_mem();
        java_remote_parent_receive_ioctl_workspace_t *workspace =
            (java_remote_parent_receive_ioctl_workspace_t *)cursor_scratch;
        if (workspace &&
            workspace->transition == k_java_remote_parent_receive_ioctl_transition_ready &&
            workspace->socket_cookie && workspace->connection_netns && !workspace->reserved[0] &&
            !workspace->reserved[1]) {
            java_remote_parent_cleanup_receive_cursor(
                &workspace->cursor, workspace->socket_cookie, workspace->cursor.generation);
        }
        return result;
    }
    return handle_java_tls_connection_ioctl(file, uarg);
}

static __always_inline int handle_java_ioctl(struct pt_regs *ctx,
                                             struct file *file,
                                             u64 id,
                                             unsigned char *uarg,
                                             enum java_ioctl_operation_mask operation_mask) {
    u8 op_cmd = 0;
    if (bpf_probe_read_user(&op_cmd, sizeof(op_cmd), uarg) != 0) {
        return 0;
    }
    const enum java_remote_parent_data_operation operation =
        java_remote_parent_decode_data_operation(op_cmd);
    const u8 data_operation = operation != k_java_remote_parent_data_operation_invalid ||
                              op_cmd == k_ioctl_java_tls_connection;
    // Keep the file-bearing hook's linked call graph data-only. The literal
    // mask makes this branch compile-time separable, so security_file_ioctl
    // cannot inherit unreachable lifecycle/control stack frames.
    if (operation_mask == k_java_ioctl_data) {
        return data_operation ? handle_java_data_operation_ioctl(ctx, file, uarg, operation) : 0;
    }
    if (data_operation) {
        return (operation_mask & k_java_ioctl_data)
                   ? handle_java_data_operation_ioctl(ctx, file, uarg, operation)
                   : 0;
    }

    pid_key_t task = {0};
    task_tid(&task);
    const u64 process_capability = java_process_capability_for(&task);
    if (!process_capability) {
        return 0;
    }
    const u8 registered = op_cmd == k_ioctl_java_process_register ||
                          java_process_incarnation_for(&task) == process_capability;
    if (!registered) {
        if (op_cmd == k_ioctl_java_vt_mount || op_cmd == k_ioctl_java_vt_unmount ||
            op_cmd == k_ioctl_java_vt_terminate) {
            return handle_java_unregistered_lifecycle_ioctl(
                uarg, op_cmd, &task, process_capability);
        }
        return handle_java_unregistered_control_ioctl(uarg, id, op_cmd, &task, process_capability);
    }
    if (op_cmd == k_ioctl_java_process_register || op_cmd == k_ioctl_java_vt_mount ||
        op_cmd == k_ioctl_java_vt_unmount || op_cmd == k_ioctl_java_vt_terminate) {
        return handle_java_lifecycle_ioctl(uarg, op_cmd, &task, process_capability);
    }
    if (handle_java_control_ioctl(uarg, op_cmd, &task, process_capability) ==
        k_java_control_cleanup_required) {
        return handle_java_unregistered_control_ioctl(uarg, id, op_cmd, &task, process_capability);
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

    const enum java_ioctl_operation_mask operation_mask =
        k_java_ioctl_control | (java_remote_parent_data_hook_is_ready() ? 0 : k_java_ioctl_data);
    return handle_java_ioctl(ctx, NULL, id, arg, operation_mask);
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

    return handle_java_ioctl(
        ctx, file, bpf_get_current_pid_tgid(), (unsigned char *)arg, k_java_ioctl_data);
}
