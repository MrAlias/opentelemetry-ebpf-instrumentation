// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

typedef struct ssl_shutdown_args {
    u64 ssl;
    u64 stack_pointer;
    u32 depth;
    u8 api;
    u8 nested_api;
    u8 unsafe_nested;
    u8 tail_wrapper;
} ssl_shutdown_args_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, ssl_thread_key_t);
    __type(value, ssl_shutdown_args_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} active_ssl_shutdown_args SEC(".maps");
