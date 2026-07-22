// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>

#include <common/connection_info.h>
#include <common/trace_key.h>

typedef struct http_info http_info_t;

extern int test_delete_server_trace_count;
extern pid_connection_info_t test_deleted_server_connection;
extern trace_key_t test_deleted_server_key;

static __always_inline void delete_server_trace(pid_connection_info_t *pid_conn, trace_key_t *key) {
    test_delete_server_trace_count++;
    test_deleted_server_connection = *pid_conn;
    test_deleted_server_key = *key;
}
