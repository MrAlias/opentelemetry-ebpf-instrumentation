// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/connection_info.h>
#include <common/pin_internal.h>
#include <common/python_addr_key.h>
#include <common/tp_info.h>

typedef struct python_httpx_request {
    tp_info_pid_t trace;
    python_task_ref_t task;
    ssl_pid_connection_info_t connection;
    u8 parent_status;
    u8 _pad[7];
} python_httpx_request_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_connection_info_t);
    __type(value, python_httpx_request_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} python_httpx_requests SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, python_addr_key_t);
    __type(value, pid_connection_info_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} python_httpx_tasks SEC(".maps");
