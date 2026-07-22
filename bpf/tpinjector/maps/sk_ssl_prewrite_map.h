// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/tp_info.h>

#include <maps/ssl_prewrite_tp.h>

typedef struct ssl_prewrite_socket_value {
    ssl_prewrite_key_t key;
    tp_info_pid_t trace;
} ssl_prewrite_socket_value_t;

SCRATCH_MEM_TYPED(ssl_prewrite_socket_value, ssl_prewrite_socket_value_t)

struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);
    __type(value, ssl_prewrite_socket_value_t);
    __uint(pinning, OBI_PIN_INTERNAL);
} sk_ssl_prewrite_map SEC(".maps");

static __always_inline u8
ssl_prewrite_socket_owner_matches(const ssl_prewrite_socket_value_t *owner,
                                  const ssl_prewrite_key_t *key,
                                  const tp_info_pid_t *trace) {
    return owner && __builtin_memcmp(&owner->key, key, sizeof(*key)) == 0 &&
           __builtin_memcmp(&owner->trace, trace, sizeof(*trace)) == 0;
}
