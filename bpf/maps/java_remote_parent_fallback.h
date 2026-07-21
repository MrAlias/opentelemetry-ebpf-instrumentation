// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/java_remote_parent.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>

#include <pid/types/pid_key.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, pid_key_t);
    __type(value, java_remote_parent_response_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_remote_parent_fallback SEC(".maps");

static __always_inline u8 java_remote_parent_stage_fallback(
    const pid_key_t *owner, const java_remote_parent_response_t *response) {
    return bpf_map_update_elem(&java_remote_parent_fallback, owner, response, BPF_NOEXIST) == 0;
}

static __always_inline void java_remote_parent_cleanup_fallback(const pid_key_t *owner) {
    bpf_map_delete_elem(&java_remote_parent_fallback, owner);
}

static __always_inline u8 java_remote_parent_fallback_matches(const pid_key_t *owner,
                                                              u64 generation) {
    const java_remote_parent_response_t *fallback =
        bpf_map_lookup_elem(&java_remote_parent_fallback, owner);
    return fallback && fallback->status == k_java_remote_parent_status_valid &&
           java_remote_parent_le64_to_cpu(fallback->generation_le) == generation;
}

static __always_inline u8 java_remote_parent_fallback_has_generation(const pid_key_t *owner,
                                                                     u64 generation) {
    const java_remote_parent_response_t *fallback =
        bpf_map_lookup_elem(&java_remote_parent_fallback, owner);
    return fallback && java_remote_parent_le64_to_cpu(fallback->generation_le) == generation;
}

static __always_inline void java_remote_parent_cleanup_fallback_generation(const pid_key_t *owner,
                                                                           u64 generation) {
    if (java_remote_parent_fallback_has_generation(owner, generation)) {
        bpf_map_delete_elem(&java_remote_parent_fallback, owner);
    }
}
