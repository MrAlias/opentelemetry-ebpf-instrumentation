// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/connection_info.h>

extern int test_parser_call_count;
extern int test_last_parser_bytes_len;
extern u8 test_last_ssl;
extern u8 test_last_direction;
extern u16 test_last_orig_dport;
extern pid_connection_info_t test_last_connection;
extern int test_prewrite_parser_call_count;

static __always_inline void handle_buf_with_connection(void *ctx,
                                                       pid_connection_info_t *pid_conn,
                                                       void *u_buf,
                                                       int bytes_len,
                                                       u8 ssl,
                                                       u8 direction,
                                                       u16 orig_dport) {
    (void)ctx;
    (void)u_buf;

    test_parser_call_count++;
    test_last_parser_bytes_len = bytes_len;
    test_last_ssl = ssl;
    test_last_direction = direction;
    test_last_orig_dport = orig_dport;
    test_last_connection = *pid_conn;
}

static __always_inline void handle_ssl_postwrite_with_connection(void *ctx,
                                                                 pid_connection_info_t *pid_conn,
                                                                 void *u_buf,
                                                                 int bytes_len,
                                                                 u16 orig_dport,
                                                                 u64 ssl_ptr,
                                                                 u64 handoff_id) {
    (void)ssl_ptr;
    (void)handoff_id;
    handle_buf_with_connection(ctx, pid_conn, u_buf, bytes_len, WITH_SSL, TCP_SEND, orig_dport);
}

static __always_inline void handle_ssl_prewrite_with_connection(void *ctx,
                                                                pid_connection_info_t *pid_conn,
                                                                void *u_buf,
                                                                int bytes_len,
                                                                u16 orig_dport,
                                                                u64 ssl_ptr,
                                                                u64 handoff_id) {
    (void)ctx;
    (void)u_buf;
    (void)ssl_ptr;
    (void)handoff_id;

    test_prewrite_parser_call_count++;
    test_last_parser_bytes_len = bytes_len;
    test_last_ssl = WITH_SSL;
    test_last_direction = TCP_SEND;
    test_last_orig_dport = orig_dport;
    test_last_connection = *pid_conn;
}
