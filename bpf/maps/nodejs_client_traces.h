// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>
#include <common/tp_info.h>

typedef struct nodejs_client_trace {
    tp_info_t tp;
    u32 pid;
    u8 parent_status;
    u8 _pad[3];
} nodejs_client_trace_t;

// A request can serialize its headers before it has a socket. Carry its
// context by span id until SSL_write observes the serialized traceparent.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, nodejs_client_trace_t);
    __uint(max_entries, 1024);
    __uint(pinning, OBI_PIN_INTERNAL);
} nodejs_client_traces SEC(".maps");
