// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/ssl_connection.h>
#include <common/sock_port_ns.h>

#include <generictracer/maps/ssl_to_pid_tid.h>

static __always_inline void cleanup_terminal_ssl_connection(const pid_connection_info_t *connection,
                                                            u64 process_start_time,
                                                            u64 netns_cookie) {
    if (ssl_prewrite_connection_should_cleanup(connection, netns_cookie)) {
        cleanup_ssl_prewrite_connection(&connection->conn, netns_cookie);
    }

    const u64 *ssl = is_ssl_connection(connection);
    if (!ssl) {
        return;
    }

    const u64 ssl_ptr = *ssl;
    if (ssl_ptr) {
        const ssl_pid_connection_info_t *reverse =
            lookup_ssl_connection(ssl_ptr, connection->pid, process_start_time);
        if (reverse && __builtin_memcmp(&reverse->p_conn, connection, sizeof(*connection)) == 0) {
            const ssl_pid_key_t key = ssl_pid_key(ssl_ptr, connection->pid, process_start_time);
            bpf_map_delete_elem(&ssl_to_pid_tid, &key);
            delete_ssl_connection(ssl_ptr, connection->pid, process_start_time);
        }
    }

    bpf_map_delete_elem(&active_ssl_connections, connection);
}
