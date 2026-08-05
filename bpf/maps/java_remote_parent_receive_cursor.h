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

static __always_inline u8 java_remote_parent_receive_cursor_owner_equal(const pid_key_t *left,
                                                                        const pid_key_t *right) {
    return left->tid == right->tid && left->pid == right->pid && left->ns == right->ns;
}

static __always_inline u8
java_remote_parent_receive_cursor_valid(const java_remote_parent_receive_cursor_t *cursor) {
    return cursor && cursor->owner.tid && cursor->owner.pid && cursor->owner.ns &&
           cursor->reserved == 0 && cursor->process_incarnation && cursor->lifecycle_id &&
           cursor->request_sequence && cursor->data_signal_nonce;
}

// The owner TID identifies the exact state that START staged. CONTINUE and
// RESET authority is process-wide, so compare the owner's derived process key
// with the canonical registered process instead of requiring the current TID.
static __always_inline u8
java_remote_parent_receive_cursor_process_matches(const java_remote_parent_receive_cursor_t *cursor,
                                                  const pid_key_t *process,
                                                  u64 process_incarnation) {
    return java_remote_parent_receive_cursor_valid(cursor) && process &&
           process->tid == process->pid && cursor->owner.pid == process->pid &&
           cursor->owner.ns == process->ns && cursor->process_incarnation == process_incarnation;
}

static __always_inline u8
java_remote_parent_receive_cursor_exact_matches(const java_remote_parent_receive_cursor_t *cursor,
                                                const pid_key_t *owner,
                                                u64 process_incarnation,
                                                u64 lifecycle_id,
                                                u64 request_sequence,
                                                u64 data_signal_nonce,
                                                u64 generation) {
    return java_remote_parent_receive_cursor_valid(cursor) && owner &&
           java_remote_parent_receive_cursor_owner_equal(&cursor->owner, owner) &&
           cursor->process_incarnation == process_incarnation &&
           cursor->lifecycle_id == lifecycle_id && cursor->request_sequence == request_sequence &&
           cursor->data_signal_nonce == data_signal_nonce && cursor->generation == generation;
}

static __always_inline u8
java_remote_parent_receive_cursor_equal(const java_remote_parent_receive_cursor_t *left,
                                        const java_remote_parent_receive_cursor_t *right) {
    return java_remote_parent_receive_cursor_valid(left) &&
           java_remote_parent_receive_cursor_valid(right) &&
           java_remote_parent_receive_cursor_owner_equal(&left->owner, &right->owner) &&
           left->process_incarnation == right->process_incarnation &&
           left->lifecycle_id == right->lifecycle_id &&
           left->request_sequence == right->request_sequence &&
           left->data_signal_nonce == right->data_signal_nonce &&
           left->generation == right->generation;
}

static __always_inline u8 java_remote_parent_receive_cursor_start(u64 socket_cookie,
                                                                  const pid_key_t *owner,
                                                                  u64 process_incarnation,
                                                                  u64 lifecycle_id,
                                                                  u64 request_sequence,
                                                                  u64 data_signal_nonce) {
    if (!socket_cookie || !owner || !process_incarnation || !lifecycle_id || !request_sequence ||
        !data_signal_nonce) {
        return 0;
    }

    const java_remote_parent_receive_cursor_t pending = {
        .owner = *owner,
        .process_incarnation = process_incarnation,
        .lifecycle_id = lifecycle_id,
        .request_sequence = request_sequence,
        .data_signal_nonce = data_signal_nonce,
    };
    if (!java_remote_parent_receive_cursor_valid(&pending)) {
        return 0;
    }

    // Java serializes receive lifecycle operations per physical socket. BPF_ANY
    // atomically replaces the previous cursor, while a failed update leaves it
    // intact. Re-read the exact pending identity before any caller publishes
    // dependent state.
    if (bpf_map_update_elem(
            &java_remote_parent_receive_cursors, &socket_cookie, &pending, BPF_ANY) != 0) {
        return 0;
    }
    const java_remote_parent_receive_cursor_t *stored =
        bpf_map_lookup_elem(&java_remote_parent_receive_cursors, &socket_cookie);
    return java_remote_parent_receive_cursor_equal(stored, &pending);
}

static __always_inline u8 java_remote_parent_receive_cursor_lookup_for_process(
    u64 socket_cookie,
    const pid_key_t *process,
    u64 process_incarnation,
    u64 lifecycle_id,
    u64 request_sequence,
    java_remote_parent_receive_cursor_t *snapshot) {
    if (!socket_cookie || !process || !process_incarnation || !lifecycle_id || !request_sequence ||
        !snapshot) {
        return 0;
    }

    const java_remote_parent_receive_cursor_t *stored =
        bpf_map_lookup_elem(&java_remote_parent_receive_cursors, &socket_cookie);
    if (!java_remote_parent_receive_cursor_process_matches(stored, process, process_incarnation) ||
        stored->lifecycle_id != lifecycle_id || stored->request_sequence != request_sequence) {
        return 0;
    }
    *snapshot = *stored;
    return java_remote_parent_receive_cursor_process_matches(
               snapshot, process, process_incarnation) &&
           snapshot->lifecycle_id == lifecycle_id && snapshot->request_sequence == request_sequence;
}

static __always_inline u8
java_remote_parent_receive_cursor_continue(u64 socket_cookie,
                                           const pid_key_t *process,
                                           u64 process_incarnation,
                                           u64 lifecycle_id,
                                           u64 request_sequence,
                                           java_remote_parent_receive_cursor_t *snapshot) {
    // This resolves identity only. A live parser dispatch that requires an
    // acknowledged bridge generation must separately reject generation zero.
    return java_remote_parent_receive_cursor_lookup_for_process(
        socket_cookie, process, process_incarnation, lifecycle_id, request_sequence, snapshot);
}

static __always_inline u8
java_remote_parent_receive_cursor_reset(u64 socket_cookie,
                                        const pid_key_t *process,
                                        u64 process_incarnation,
                                        u64 lifecycle_id,
                                        u64 request_sequence,
                                        java_remote_parent_receive_cursor_t *snapshot) {
    return java_remote_parent_receive_cursor_lookup_for_process(
        socket_cookie, process, process_incarnation, lifecycle_id, request_sequence, snapshot);
}

static __always_inline u8 java_remote_parent_receive_cursor_delete_exact(
    u64 socket_cookie, const java_remote_parent_receive_cursor_t *expected) {
    if (!socket_cookie || !java_remote_parent_receive_cursor_valid(expected)) {
        return 0;
    }

    const java_remote_parent_receive_cursor_t *stored =
        bpf_map_lookup_elem(&java_remote_parent_receive_cursors, &socket_cookie);
    if (!java_remote_parent_receive_cursor_equal(stored, expected)) {
        return 0;
    }
    return bpf_map_delete_elem(&java_remote_parent_receive_cursors, &socket_cookie) == 0;
}

static __always_inline u8 java_remote_parent_receive_cursor_ack_generation(
    u64 socket_cookie,
    const java_remote_parent_receive_cursor_t *expected_pending,
    u64 generation) {
    if (!socket_cookie || !generation ||
        !java_remote_parent_receive_cursor_valid(expected_pending) ||
        expected_pending->generation != 0) {
        return 0;
    }

    const java_remote_parent_receive_cursor_t *stored =
        bpf_map_lookup_elem(&java_remote_parent_receive_cursors, &socket_cookie);
    if (!java_remote_parent_receive_cursor_equal(stored, expected_pending)) {
        return 0;
    }

    const java_remote_parent_receive_cursor_t committed = {
        .owner = expected_pending->owner,
        .process_incarnation = expected_pending->process_incarnation,
        .lifecycle_id = expected_pending->lifecycle_id,
        .request_sequence = expected_pending->request_sequence,
        .data_signal_nonce = expected_pending->data_signal_nonce,
        .generation = generation,
    };
    if (bpf_map_update_elem(
            &java_remote_parent_receive_cursors, &socket_cookie, &committed, BPF_EXIST) != 0) {
        return 0;
    }
    stored = bpf_map_lookup_elem(&java_remote_parent_receive_cursors, &socket_cookie);
    return java_remote_parent_receive_cursor_equal(stored, &committed);
}
