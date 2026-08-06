// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_endian.h>
#include <bpfcore/bpf_helpers.h>

#include <common/java_remote_parent.h>
#include <common/connection_info.h>
#include <common/pin_internal.h>
#include <common/sock_port_ns.h>

#include <maps/java_remote_parent.h>
#include <maps/java_remote_parent_receive_cursor.h>
#include <maps/java_remote_parent_socket_cookie.h>

#include <pid/pid.h>

volatile const u64 java_remote_parent_max_age_ns = 30ULL * 1000 * 1000 * 1000;

typedef struct java_remote_parent_negotiation {
    pid_key_t process;
    u32 reserved;
    u64 process_incarnation;
    connection_info_t connection;
    u32 connection_netns;
    u64 generation;
} java_remote_parent_negotiation_t;

_Static_assert(sizeof(java_remote_parent_negotiation_t) == 72,
               "java remote-parent negotiation size mismatch");

typedef struct java_remote_parent_sockopt_scratch {
    java_remote_parent_negotiation_t negotiation;
    connection_info_t connection;
    u32 reserved;
    java_remote_parent_response_t response;
    java_remote_parent_data_signal_key_t signal_key;
    java_remote_parent_data_ack_t acknowledgement;
    pid_key_t acknowledged_process;
    u32 reserved2;
} java_remote_parent_sockopt_scratch_t;

// A per-CPU scratch value can be overwritten when a cgroup sockopt program is
// preempted on a PREEMPT_RCU kernel. Socket-local storage keeps concurrent
// operations on different sockets isolated; the cgroup sockopt runners hold
// the socket lock while executing programs, serializing same-socket access.
struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);
    __type(value, java_remote_parent_sockopt_scratch_t);
} javabridge_sockopt_scratch SEC(".maps");

static __always_inline java_remote_parent_sockopt_scratch_t *
java_remote_parent_sockopt_scratch_for(const struct bpf_sockopt *ctx) {
    if (!ctx->sk) {
        return NULL;
    }
    return bpf_sk_storage_get(
        &javabridge_sockopt_scratch, ctx->sk, NULL, BPF_SK_STORAGE_GET_F_CREATE);
}

// Socket-local storage is available to cgroup sockopt programs on the
// minimum supported kernel. The kernel frees it with the socket, so a reused
// struct sock address can never inherit an earlier negotiation.
struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);
    __type(value, java_remote_parent_negotiation_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_remote_parent_negotiations SEC(".maps");

static __always_inline u8 java_remote_parent_is_retrieval_option(const struct bpf_sockopt *ctx) {
    return ctx->level == k_java_remote_parent_socket_level &&
           java_remote_parent_socket_option_is_retrieval(ctx->optname);
}

static __always_inline u8 java_remote_parent_is_negotiate_option(const struct bpf_sockopt *ctx) {
    return ctx->level == k_java_remote_parent_socket_level &&
           ctx->optname == k_java_remote_parent_socket_negotiate;
}

static __always_inline u8 java_remote_parent_is_data_ack_option(const struct bpf_sockopt *ctx) {
    return ctx->level == k_java_remote_parent_socket_level &&
           ctx->optname == k_java_remote_parent_socket_data_ack;
}

static __always_inline u8 java_remote_parent_is_health_option(const struct bpf_sockopt *ctx) {
    return ctx->level == k_java_remote_parent_socket_level &&
           ctx->optname == k_java_remote_parent_socket_health;
}

static __always_inline void java_remote_parent_record_unauthorized_retrieval(u8 discard,
                                                                             u8 health) {
    if (!health) {
        java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_unauthorized);
    }
}

static __always_inline pid_key_t java_remote_parent_current_process() {
    pid_key_t task = {0};
    task_tid(&task);
    return java_process_key(&task);
}

static __always_inline u8 java_remote_parent_same_process(const pid_key_t *left,
                                                          const pid_key_t *right) {
    return left->tid == right->tid && left->pid == right->pid && left->ns == right->ns;
}

static __noinline void java_remote_parent_sockopt_connection_ip4(const struct bpf_sock *sk,
                                                                 connection_info_t *connection) {
    __builtin_memcpy(connection->s_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    __builtin_memcpy(connection->d_addr, ip4ip6_prefix, sizeof(ip4ip6_prefix));
    connection->s_ip[3] = sk->src_ip4;
    connection->d_ip[3] = sk->dst_ip4;
}

static __noinline void java_remote_parent_sockopt_connection_ip6(const struct bpf_sock *sk,
                                                                 connection_info_t *connection) {
    connection->s_ip[0] = sk->src_ip6[0];
    connection->s_ip[1] = sk->src_ip6[1];
    connection->s_ip[2] = sk->src_ip6[2];
    connection->s_ip[3] = sk->src_ip6[3];
    connection->d_ip[0] = sk->dst_ip6[0];
    connection->d_ip[1] = sk->dst_ip6[1];
    connection->d_ip[2] = sk->dst_ip6[2];
    connection->d_ip[3] = sk->dst_ip6[3];
}

static __always_inline u8 java_remote_parent_sockopt_connection(const struct bpf_sockopt *ctx,
                                                                connection_info_t *connection) {
    const struct bpf_sock *sk = ctx->sk;
    if (!sk || sk->type != SOCK_STREAM || sk->protocol != IPPROTO_TCP ||
        (sk->state != TCP_ESTABLISHED && sk->state != TCP_CLOSE_WAIT)) {
        return 0;
    }

    if (sk->family == AF_INET) {
        java_remote_parent_sockopt_connection_ip4(sk, connection);
    } else if (sk->family == AF_INET6) {
        java_remote_parent_sockopt_connection_ip6(sk, connection);
    } else {
        return 0;
    }
    connection->s_port = (u16)sk->src_port;
    connection->d_port = bpf_ntohs(sk->dst_port);
    if (!connection->s_port || !connection->d_port) {
        return 0;
    }
    sort_connection_info(connection);
    return 1;
}

static __always_inline int java_remote_parent_ack_data(struct bpf_sockopt *ctx) {
    if (!ctx->sk) {
        return 1;
    }

    java_remote_parent_negotiation_t *negotiated =
        bpf_sk_storage_get(&java_remote_parent_negotiations, ctx->sk, NULL, 0);
    if (!negotiated) {
        return 1;
    }
    java_remote_parent_sockopt_scratch_t *scratch = java_remote_parent_sockopt_scratch_for(ctx);
    if (!scratch) {
        return 1;
    }
    scratch->negotiation = *negotiated;
    const pid_key_t process = java_remote_parent_current_process();
    if (!java_remote_parent_same_process(&scratch->negotiation.process, &process)) {
        return 1;
    }
    const u64 process_capability = java_process_capability_for(&process);
    const u64 registered_incarnation = java_current_process_incarnation();
    if (!process_capability || !registered_incarnation || scratch->negotiation.reserved != 0 ||
        scratch->negotiation.process_incarnation != process_capability ||
        registered_incarnation != process_capability) {
        bpf_sk_storage_delete(&java_remote_parent_negotiations, ctx->sk);
        return 1;
    }

    __builtin_memset(&scratch->connection, 0, sizeof(scratch->connection));
    const u64 socket_cookie = java_remote_parent_socket_cookie(ctx->sk);
    if (!socket_cookie || !java_remote_parent_sockopt_connection(ctx, &scratch->connection) ||
        __builtin_memcmp(&scratch->connection,
                         &scratch->negotiation.connection,
                         sizeof(scratch->connection)) != 0) {
        return 1;
    }

    const unsigned char *optval = ctx->optval;
    const unsigned char *optval_end = ctx->optval_end;
    if (!optval || ctx->optlen != sizeof(u64) || optval + sizeof(u64) > optval_end) {
        return 1;
    }
    u64 nonce = 0;
    __builtin_memcpy(&nonce, optval, sizeof(nonce));
    nonce = java_remote_parent_le64_to_cpu(nonce);
    scratch->signal_key = (java_remote_parent_data_signal_key_t){
        .process = process,
        .nonce = nonce,
    };
    const java_remote_parent_data_ack_t *acknowledgement =
        bpf_map_lookup_elem(&java_remote_parent_data_acks, &scratch->signal_key);
    if (!acknowledgement) {
        return 1;
    }
    scratch->acknowledgement = *acknowledgement;
    scratch->acknowledged_process = java_process_key(&scratch->acknowledgement.owner);
    if (scratch->acknowledgement.reserved != 0 || !scratch->acknowledgement.generation ||
        !scratch->acknowledgement.connection_netns || scratch->acknowledgement.reserved2 != 0 ||
        __builtin_memcmp(scratch->acknowledgement.reserved3,
                         (unsigned char[sizeof(scratch->acknowledgement.reserved3)]){0},
                         sizeof(scratch->acknowledgement.reserved3)) != 0 ||
        scratch->acknowledgement.connection_netns != scratch->negotiation.connection_netns ||
        scratch->acknowledgement.connection_netns != task_netns() ||
        !java_remote_parent_same_process(&scratch->acknowledged_process, &process) ||
        __builtin_memcmp(&scratch->acknowledgement.connection,
                         &scratch->connection,
                         sizeof(scratch->connection)) != 0 ||
        !java_remote_parent_connection_matches_socket_in_netns(
            &scratch->acknowledgement.connection,
            scratch->acknowledgement.connection_netns,
            &scratch->acknowledgement.owner,
            scratch->acknowledgement.generation,
            0,
            socket_cookie)) {
        return 1;
    }

    negotiated->connection_netns = scratch->acknowledgement.connection_netns;
    negotiated->generation = scratch->acknowledgement.generation;
    java_remote_parent_finish_data_signal(&scratch->acknowledgement.owner, nonce);
    bpf_map_delete_elem(&java_remote_parent_data_acks, &scratch->signal_key);
    ctx->optlen = -1;
    return 1;
}

SEC("cgroup/setsockopt")
int obi_java_remote_parent_setsockopt(struct bpf_sockopt *ctx) {
    const u8 data_ack = java_remote_parent_is_data_ack_option(ctx);
    if (!java_remote_parent_is_negotiate_option(ctx) && !data_ack) {
        return 1;
    }
    if (!java_remote_parent_data_hook_is_ready()) {
        return 1;
    }
    if (data_ack) {
        return java_remote_parent_ack_data(ctx);
    }

    if (!ctx->sk) {
        return 1;
    }

    java_remote_parent_sockopt_scratch_t *scratch = java_remote_parent_sockopt_scratch_for(ctx);
    if (!scratch) {
        java_remote_parent_negotiate_stat(k_java_remote_parent_status_overload);
        return 1;
    }
    __builtin_memset(&scratch->connection, 0, sizeof(scratch->connection));
    const u64 socket_cookie = java_remote_parent_socket_cookie(ctx->sk);
    if (!socket_cookie || !java_remote_parent_sockopt_connection(ctx, &scratch->connection)) {
        java_remote_parent_negotiate_stat(k_java_remote_parent_status_overload);
        return 1;
    }

    const unsigned char *optval = ctx->optval;
    const unsigned char *optval_end = ctx->optval_end;
    if (!optval || ctx->optlen != sizeof(u64) || optval + sizeof(u64) > optval_end) {
        java_remote_parent_negotiate_stat(k_java_remote_parent_status_unauthorized);
        return 1;
    }

    u64 requested_incarnation = 0;
    __builtin_memcpy(&requested_incarnation, optval, sizeof(requested_incarnation));
    requested_incarnation = java_remote_parent_le64_to_cpu(requested_incarnation);

    const pid_key_t process = java_remote_parent_current_process();
    const u64 process_capability = java_process_capability_for(&process);
    const u64 registered_incarnation = java_current_process_incarnation();
    const u32 caller_netns = task_netns();
    if (!process_capability || !requested_incarnation ||
        requested_incarnation != process_capability ||
        registered_incarnation != process_capability || !caller_netns) {
        java_remote_parent_negotiate_stat(k_java_remote_parent_status_unauthorized);
        return 1;
    }

    scratch->negotiation = (java_remote_parent_negotiation_t){
        .process = process,
        .process_incarnation = registered_incarnation,
        .connection = scratch->connection,
        .connection_netns = caller_netns,
    };
    java_remote_parent_negotiation_t *stored = bpf_sk_storage_get(&java_remote_parent_negotiations,
                                                                  ctx->sk,
                                                                  &scratch->negotiation,
                                                                  BPF_SK_STORAGE_GET_F_CREATE);
    if (!stored) {
        java_remote_parent_negotiate_stat(k_java_remote_parent_status_overload);
        return 1;
    }
    *stored = scratch->negotiation;

    java_remote_parent_negotiate_stat(k_java_remote_parent_status_missing);
    ctx->optlen = -1;
    return 1;
}

SEC("cgroup/getsockopt")
int obi_java_remote_parent_getsockopt(struct bpf_sockopt *ctx) {
    const u8 health = java_remote_parent_is_health_option(ctx);
    if (!java_remote_parent_is_retrieval_option(ctx) && !health) {
        return 1;
    }
    if (!java_remote_parent_data_hook_is_ready()) {
        return 1;
    }

    const u8 discard = java_remote_parent_socket_option_is_discard(ctx->optname);
    const enum java_remote_parent_source source =
        java_remote_parent_socket_option_source(ctx->optname);
    if (!ctx->sk) {
        return 1;
    }

    java_remote_parent_negotiation_t *negotiated =
        bpf_sk_storage_get(&java_remote_parent_negotiations, ctx->sk, NULL, 0);
    if (!negotiated) {
        java_remote_parent_record_unauthorized_retrieval(discard, health);
        return 1;
    }
    java_remote_parent_sockopt_scratch_t *scratch = java_remote_parent_sockopt_scratch_for(ctx);
    if (!scratch) {
        java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_overload);
        return 1;
    }
    scratch->negotiation = *negotiated;
    const pid_key_t process = java_remote_parent_current_process();
    if (!java_remote_parent_same_process(&scratch->negotiation.process, &process)) {
        java_remote_parent_record_unauthorized_retrieval(discard, health);
        return 1;
    }
    const u64 process_capability = java_process_capability_for(&process);
    const u64 registered_incarnation = java_current_process_incarnation();
    if (!process_capability || !registered_incarnation || scratch->negotiation.reserved != 0 ||
        scratch->negotiation.process_incarnation != process_capability ||
        registered_incarnation != process_capability) {
        bpf_sk_storage_delete(&java_remote_parent_negotiations, ctx->sk);
        java_remote_parent_record_unauthorized_retrieval(discard, health);
        return 1;
    }

    __builtin_memset(&scratch->connection, 0, sizeof(scratch->connection));
    const u64 socket_cookie = java_remote_parent_socket_cookie(ctx->sk);
    if (!socket_cookie || !java_remote_parent_sockopt_connection(ctx, &scratch->connection) ||
        __builtin_memcmp(&scratch->connection,
                         &scratch->negotiation.connection,
                         sizeof(scratch->connection)) != 0) {
        java_remote_parent_record_unauthorized_retrieval(discard, health);
        return 1;
    }

    unsigned char *optval = ctx->optval;
    const unsigned char *optval_end = ctx->optval_end;
    if (!scratch->negotiation.connection_netns ||
        scratch->negotiation.connection_netns != task_netns()) {
        java_remote_parent_record_unauthorized_retrieval(discard, health);
        return 1;
    }
    if (health) {
        if (!optval || ctx->optlen < sizeof(u64) || optval + sizeof(u64) > optval_end) {
            return 1;
        }
        const u64 response =
            java_remote_parent_cpu_to_le64(scratch->negotiation.process_incarnation);
        __builtin_memcpy(optval, &response, sizeof(response));
        ctx->optlen = sizeof(response);
        ctx->retval = 0;
        return 1;
    }
    if (!scratch->negotiation.generation) {
        return 1;
    }
    if (!optval || ctx->optlen != k_java_remote_parent_response_size ||
        optval + k_java_remote_parent_response_size > optval_end) {
        java_remote_parent_retrieval_stat(discard, k_java_remote_parent_status_malformed);
        return 1;
    }

    java_remote_parent_retrieve_for_connection(&scratch->response,
                                               discard,
                                               java_remote_parent_max_age_ns,
                                               source,
                                               &scratch->negotiation.connection,
                                               scratch->negotiation.connection_netns,
                                               scratch->negotiation.generation,
                                               socket_cookie);

    __builtin_memcpy(optval, &scratch->response, sizeof(scratch->response));
    ctx->optlen = sizeof(scratch->response);
    ctx->retval = 0;
    return 1;
}

char __license[] SEC("license") = "Dual MIT/GPL";
