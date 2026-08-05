// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>

#include <pid/types/pid_key.h>

typedef struct java_remote_parent_receive_cursor {
    pid_key_t owner;
    u32 reserved;
    u64 process_incarnation;
    u64 lifecycle_id;
    u64 request_sequence;
    u64 data_signal_nonce;
    u64 generation;
} java_remote_parent_receive_cursor_t;

_Static_assert(offsetof(java_remote_parent_receive_cursor_t, owner) == 0,
               "java remote-parent receive cursor owner offset mismatch");
_Static_assert(offsetof(java_remote_parent_receive_cursor_t, reserved) == 12,
               "java remote-parent receive cursor reserved offset mismatch");
_Static_assert(offsetof(java_remote_parent_receive_cursor_t, process_incarnation) == 16,
               "java remote-parent receive cursor process incarnation offset mismatch");
_Static_assert(offsetof(java_remote_parent_receive_cursor_t, lifecycle_id) == 24,
               "java remote-parent receive cursor lifecycle offset mismatch");
_Static_assert(offsetof(java_remote_parent_receive_cursor_t, request_sequence) == 32,
               "java remote-parent receive cursor request sequence offset mismatch");
_Static_assert(offsetof(java_remote_parent_receive_cursor_t, data_signal_nonce) == 40,
               "java remote-parent receive cursor data signal nonce offset mismatch");
_Static_assert(offsetof(java_remote_parent_receive_cursor_t, generation) == 48,
               "java remote-parent receive cursor generation offset mismatch");
_Static_assert(sizeof(java_remote_parent_receive_cursor_t) == 56,
               "java remote-parent receive cursor size mismatch");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, java_remote_parent_receive_cursor_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_remote_parent_receive_cursors SEC(".maps");
