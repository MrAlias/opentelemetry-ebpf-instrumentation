// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#ifndef OBI_HTTP_TERMINATION_CONTEXT
#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/ssl_connection.h>

#include <generictracer/ssl_connection.h>

#include <maps/ongoing_http.h>

static __always_inline u8 http_info_complete(http_info_t *info);
static __always_inline void cleanup_http_request_data(pid_connection_info_t *pid_conn,
                                                      http_info_t *info);
static __always_inline void cleanup_http_request_data_mode(pid_connection_info_t *pid_conn,
                                                           http_info_t *info,
                                                           const trace_key_t *current_key,
                                                           u8 cleanup_java_remote_parent);
static __always_inline void
finish_http(http_info_t *info, pid_connection_info_t *pid_conn, const trace_key_t *current_key);
static __always_inline void force_finish_http(http_info_t *info,
                                              pid_connection_info_t *pid_conn,
                                              const trace_key_t *current_key);
static __always_inline void cleanup_http_info(pid_connection_info_t *pid_conn);
#endif

#ifdef OBI_HTTP_TERMINATION_CURRENT_KEY
static __always_inline void terminate_http_request_if_needed_mode(pid_connection_info_t *pid_conn,
                                                                  const trace_key_t *current_key,
                                                                  u8 cleanup_java_remote_parent) {
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
    cleanup_http_request_data_mode(pid_conn, info, current_key, cleanup_java_remote_parent);
    cleanup_terminal_ssl_connection(pid_conn, task_process_start_time(), task_netns_cookie());
    if (info && http_info_complete(info) && !info->submitted) {
        finish_http(info, pid_conn, current_key);
    }
    cleanup_http_info(pid_conn);
}

static __always_inline void terminate_http_request_if_needed(pid_connection_info_t *pid_conn,
                                                             const trace_key_t *current_key) {
    terminate_http_request_if_needed_mode(pid_conn, current_key, 1);
}

static __always_inline void force_terminate_http_request_mode(pid_connection_info_t *pid_conn,
                                                              const trace_key_t *current_key,
                                                              u8 cleanup_java_remote_parent) {
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
    cleanup_http_request_data_mode(pid_conn, info, current_key, cleanup_java_remote_parent);
    cleanup_terminal_ssl_connection(pid_conn, task_process_start_time(), task_netns_cookie());
    if (info) {
        force_finish_http(info, pid_conn, current_key);
    }
    cleanup_http_info(pid_conn);
}

static __always_inline void force_terminate_http_request(pid_connection_info_t *pid_conn,
                                                         const trace_key_t *current_key) {
    force_terminate_http_request_mode(pid_conn, current_key, 1);
}
#else
static __always_inline void terminate_http_request_if_needed_mode(pid_connection_info_t *pid_conn,
                                                                  u8 cleanup_java_remote_parent) {
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
    (void)cleanup_java_remote_parent;
    cleanup_http_request_data(pid_conn, info);
    cleanup_terminal_ssl_connection(pid_conn, task_process_start_time(), task_netns_cookie());
    if (info && http_info_complete(info) && !info->submitted) {
        finish_http(info, pid_conn);
    }
    cleanup_http_info(pid_conn);
}

static __always_inline void terminate_http_request_if_needed(pid_connection_info_t *pid_conn) {
    terminate_http_request_if_needed_mode(pid_conn, 1);
}

static __always_inline void force_terminate_http_request_mode(pid_connection_info_t *pid_conn,
                                                              u8 cleanup_java_remote_parent) {
    http_info_t *info = bpf_map_lookup_elem(&ongoing_http, pid_conn);
    (void)cleanup_java_remote_parent;
    cleanup_http_request_data(pid_conn, info);
    cleanup_terminal_ssl_connection(pid_conn, task_process_start_time(), task_netns_cookie());
    if (info) {
        force_finish_http(info, pid_conn);
    }
    cleanup_http_info(pid_conn);
}

static __always_inline void force_terminate_http_request(pid_connection_info_t *pid_conn) {
    force_terminate_http_request_mode(pid_conn, 1);
}
#endif
