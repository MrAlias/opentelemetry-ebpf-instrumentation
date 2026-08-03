// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/pin_internal.h>

// Physical socket identity shared by the sockops candidate path and the
// cgroup sockopt authority path. Socket-local storage is released with the
// socket, so a reused tuple or struct sock address cannot inherit an earlier
// identity.
struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, u32);
    __type(value, u64);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_remote_parent_socket_cookies SEC(".maps");

static __always_inline u8 java_remote_parent_seed_socket_cookie(struct bpf_sock *sk,
                                                                u64 socket_cookie) {
    if (!sk || !socket_cookie) {
        return 0;
    }

    const u64 candidate = socket_cookie;
    const u64 *stored = bpf_sk_storage_get(
        &java_remote_parent_socket_cookies, sk, (void *)&candidate, BPF_SK_STORAGE_GET_F_CREATE);
    return stored && *stored == socket_cookie;
}

static __always_inline u64 java_remote_parent_socket_cookie(struct bpf_sock *sk) {
    if (!sk) {
        return 0;
    }

    const u64 *stored = bpf_sk_storage_get(&java_remote_parent_socket_cookies, sk, NULL, 0);
    return stored ? *stored : 0;
}
