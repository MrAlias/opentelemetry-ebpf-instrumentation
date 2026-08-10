// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <pid/types/pid_key.h>

typedef struct java_thread_mapping_claim {
    pid_key_t child;
    u32 reserved;
    u64 process_incarnation;
} java_thread_mapping_claim_t;

_Static_assert(sizeof(java_thread_mapping_claim_t) == 24,
               "Java thread-mapping claim size mismatch");
_Static_assert(offsetof(java_thread_mapping_claim_t, reserved) == 12,
               "Java thread-mapping claim reserved offset mismatch");
_Static_assert(offsetof(java_thread_mapping_claim_t, process_incarnation) == 16,
               "Java thread-mapping claim incarnation offset mismatch");

// Current-agent publishers queue around their synchronous ioctl in Java. This
// process-scoped claim is the fail-closed backstop for stale, duplicate, or
// otherwise uncooperative callers. It is deliberately non-evicting: eviction
// while a publisher is active could admit a reciprocal publication and expose
// a transient cycle. Userspace retirement cleanup shares this fence with BPF.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, pid_key_t);
    __type(value, java_thread_mapping_claim_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_thread_mapping_claims SEC(".maps");
