// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/map_sizing.h>
#include <common/pin_internal.h>

#include <pid/types/pid_key.h>

enum java_remote_parent_receive_cursor_state : u32 {
    // VALID is the only state that independent CONTINUE/RESET/SDK lookups may
    // consume. PUBLISHING belongs exclusively to the synchronous START
    // tail-call chain; RETIRING is a terminal, fail-closed tombstone.
    k_java_remote_parent_receive_cursor_valid = 0,
    k_java_remote_parent_receive_cursor_publishing = 1,
    k_java_remote_parent_receive_cursor_retiring = 2,
};

typedef struct java_remote_parent_receive_cursor {
    pid_key_t owner;
    u32 state;
    u64 process_incarnation;
    u64 lifecycle_id;
    u64 request_sequence;
    u64 data_signal_nonce;
    u64 generation;
} java_remote_parent_receive_cursor_t;

_Static_assert(offsetof(java_remote_parent_receive_cursor_t, owner) == 0,
               "java remote-parent receive cursor owner offset mismatch");
_Static_assert(offsetof(java_remote_parent_receive_cursor_t, state) == 12,
               "java remote-parent receive cursor state offset mismatch");
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

// These short ELF symbols are also the kernel-visible map names. Keep them
// distinct within Linux's 15-byte map-name limit so live map evidence can
// resolve the cursor and guard by exact name and ID, despite their identical
// key/value layouts.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, java_remote_parent_receive_cursor_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} jrp_recv_cur SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u64);
    __type(value, java_remote_parent_receive_cursor_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} jrp_recv_guard SEC(".maps");

enum java_remote_parent_receive_guard_result : u8 {
    k_java_remote_parent_receive_guard_error = 0,
    k_java_remote_parent_receive_guard_acquired = 1,
    k_java_remote_parent_receive_guard_busy = 2,
};

static __always_inline u8 java_remote_parent_receive_cursor_owner_equal(const pid_key_t *left,
                                                                        const pid_key_t *right) {
    return left->tid == right->tid && left->pid == right->pid && left->ns == right->ns;
}

static __always_inline u8 java_remote_parent_receive_cursor_identity_complete(
    const java_remote_parent_receive_cursor_t *cursor) {
    return cursor && cursor->owner.tid && cursor->owner.pid && cursor->owner.ns &&
           cursor->process_incarnation && cursor->lifecycle_id && cursor->request_sequence &&
           cursor->data_signal_nonce;
}

static __always_inline u8
java_remote_parent_receive_cursor_is_publishing(const java_remote_parent_receive_cursor_t *cursor) {
    return java_remote_parent_receive_cursor_identity_complete(cursor) &&
           cursor->state == k_java_remote_parent_receive_cursor_publishing &&
           cursor->generation == 0;
}

static __always_inline u8
java_remote_parent_receive_cursor_is_valid(const java_remote_parent_receive_cursor_t *cursor) {
    return java_remote_parent_receive_cursor_identity_complete(cursor) &&
           cursor->state == k_java_remote_parent_receive_cursor_valid && cursor->generation;
}

static __always_inline u8
java_remote_parent_receive_cursor_is_retiring(const java_remote_parent_receive_cursor_t *cursor) {
    return java_remote_parent_receive_cursor_identity_complete(cursor) &&
           cursor->state == k_java_remote_parent_receive_cursor_retiring;
}

static __always_inline u8
java_remote_parent_receive_cursor_state_known(const java_remote_parent_receive_cursor_t *cursor) {
    return java_remote_parent_receive_cursor_is_publishing(cursor) ||
           java_remote_parent_receive_cursor_is_valid(cursor) ||
           java_remote_parent_receive_cursor_is_retiring(cursor);
}

// Preserve the historical helper name for normal authority checks. It now
// deliberately means committed VALID only; generation-zero PUBLISHING and
// RETIRING tombstones are never general receive authority.
static __always_inline u8
java_remote_parent_receive_cursor_valid(const java_remote_parent_receive_cursor_t *cursor) {
    return java_remote_parent_receive_cursor_is_valid(cursor);
}

static __always_inline u8
java_remote_parent_receive_cursor_equal(const java_remote_parent_receive_cursor_t *left,
                                        const java_remote_parent_receive_cursor_t *right) {
    return java_remote_parent_receive_cursor_state_known(left) &&
           java_remote_parent_receive_cursor_state_known(right) &&
           java_remote_parent_receive_cursor_owner_equal(&left->owner, &right->owner) &&
           left->state == right->state && left->process_incarnation == right->process_incarnation &&
           left->lifecycle_id == right->lifecycle_id &&
           left->request_sequence == right->request_sequence &&
           left->data_signal_nonce == right->data_signal_nonce &&
           left->generation == right->generation;
}

static __always_inline u8 java_remote_parent_receive_cursor_retiring_identity_matches(
    const java_remote_parent_receive_cursor_t *stored,
    const java_remote_parent_receive_cursor_t *expected_identity) {
    // State is the only byte range that differs between a committed identity
    // and its RETIRING tombstone. The asserted cursor layout makes the owner
    // prefix and post-state suffix exact, padding-free byte ranges.
    return stored && expected_identity &&
           stored->state == k_java_remote_parent_receive_cursor_retiring &&
           __builtin_memcmp(
               &stored->owner, &expected_identity->owner, sizeof(expected_identity->owner)) == 0 &&
           __builtin_memcmp(
               &stored->process_incarnation,
               &expected_identity->process_incarnation,
               sizeof(*expected_identity) -
                   offsetof(java_remote_parent_receive_cursor_t, process_incarnation)) == 0;
}

static __always_inline u8 java_remote_parent_receive_cursor_exact_publishing(
    const java_remote_parent_receive_cursor_t *stored,
    const java_remote_parent_receive_cursor_t *tail_chain_identity) {
    return java_remote_parent_receive_cursor_is_publishing(stored) &&
           java_remote_parent_receive_cursor_is_publishing(tail_chain_identity) &&
           java_remote_parent_receive_cursor_equal(stored, tail_chain_identity);
}

static __always_inline java_remote_parent_receive_cursor_t
java_remote_parent_receive_cursor_publishing_identity(const pid_key_t *owner,
                                                      u64 process_incarnation,
                                                      u64 lifecycle_id,
                                                      u64 request_sequence,
                                                      u64 data_signal_nonce) {
    return (java_remote_parent_receive_cursor_t){
        .owner = *owner,
        .state = k_java_remote_parent_receive_cursor_publishing,
        .process_incarnation = process_incarnation,
        .lifecycle_id = lifecycle_id,
        .request_sequence = request_sequence,
        .data_signal_nonce = data_signal_nonce,
    };
}

static __always_inline java_remote_parent_receive_cursor_t
java_remote_parent_receive_cursor_retiring_identity(
    const java_remote_parent_receive_cursor_t *cursor) {
    java_remote_parent_receive_cursor_t retiring = *cursor;
    retiring.state = k_java_remote_parent_receive_cursor_retiring;
    return retiring;
}

static __noinline __attribute__((unused)) u8 java_remote_parent_receive_cursor_snapshot_state(
    u64 socket_cookie, java_remote_parent_receive_cursor_t *snapshot) {
    if (!socket_cookie || !snapshot) {
        return 0;
    }
    const java_remote_parent_receive_cursor_t *stored =
        bpf_map_lookup_elem(&jrp_recv_cur, &socket_cookie);
    if (!java_remote_parent_receive_cursor_state_known(stored)) {
        return 0;
    }
    *snapshot = *stored;
    stored = bpf_map_lookup_elem(&jrp_recv_cur, &socket_cookie);
    return java_remote_parent_receive_cursor_equal(stored, snapshot);
}

static __noinline __attribute__((unused)) u8 java_remote_parent_receive_cursor_snapshot_valid(
    u64 socket_cookie, java_remote_parent_receive_cursor_t *snapshot) {
    if (!java_remote_parent_receive_cursor_snapshot_state(socket_cookie, snapshot)) {
        return 0;
    }
    return java_remote_parent_receive_cursor_is_valid(snapshot);
}

static __noinline __attribute__((unused)) u8 java_remote_parent_receive_cursor_publish(
    u64 socket_cookie, const java_remote_parent_receive_cursor_t *publishing) {
    if (!socket_cookie || !java_remote_parent_receive_cursor_is_publishing(publishing)) {
        return 0;
    }
    if (bpf_map_update_elem(&jrp_recv_cur, &socket_cookie, publishing, BPF_NOEXIST) != 0) {
        return 0;
    }
    const java_remote_parent_receive_cursor_t *stored =
        bpf_map_lookup_elem(&jrp_recv_cur, &socket_cookie);
    return java_remote_parent_receive_cursor_equal(stored, publishing);
}

static __always_inline u8 java_remote_parent_receive_cursor_start(u64 socket_cookie,
                                                                  const pid_key_t *owner,
                                                                  u64 process_incarnation,
                                                                  u64 lifecycle_id,
                                                                  u64 request_sequence,
                                                                  u64 data_signal_nonce) {
    if (!owner) {
        return 0;
    }
    const java_remote_parent_receive_cursor_t publishing =
        java_remote_parent_receive_cursor_publishing_identity(
            owner, process_incarnation, lifecycle_id, request_sequence, data_signal_nonce);
    return java_remote_parent_receive_cursor_publish(socket_cookie, &publishing);
}

static __noinline __attribute__((unused)) u8 java_remote_parent_receive_cursor_guard_release(
    u64 socket_cookie, const java_remote_parent_receive_cursor_t *expected) {
    if (!socket_cookie || !java_remote_parent_receive_cursor_is_valid(expected)) {
        return 0;
    }
    const java_remote_parent_receive_cursor_t *guard =
        bpf_map_lookup_elem(&jrp_recv_guard, &socket_cookie);
    if (!java_remote_parent_receive_cursor_equal(guard, expected)) {
        return 0;
    }
    bpf_map_delete_elem(&jrp_recv_guard, &socket_cookie);
    // Success means the exact cookie has no guard at all. A different value is
    // still a live exclusion record and must never authorize cursor deletion.
    return !bpf_map_lookup_elem(&jrp_recv_guard, &socket_cookie);
}

static __noinline __attribute__((unused)) enum java_remote_parent_receive_guard_result
java_remote_parent_receive_cursor_guard_acquire(
    u64 socket_cookie, const java_remote_parent_receive_cursor_t *expected) {
    if (!socket_cookie || !java_remote_parent_receive_cursor_is_valid(expected)) {
        return k_java_remote_parent_receive_guard_error;
    }
    const java_remote_parent_receive_cursor_t *stored =
        bpf_map_lookup_elem(&jrp_recv_cur, &socket_cookie);
    if (!java_remote_parent_receive_cursor_equal(stored, expected)) {
        return bpf_map_lookup_elem(&jrp_recv_guard, &socket_cookie)
                   ? k_java_remote_parent_receive_guard_busy
                   : k_java_remote_parent_receive_guard_error;
    }
    if (bpf_map_update_elem(&jrp_recv_guard, &socket_cookie, expected, BPF_NOEXIST) != 0) {
        // Any exact-cookie guard is BUSY, even if it protects a different
        // predecessor identity. An absent key after failed insertion is a
        // capacity/update ERROR and must never be treated as handoff.
        return bpf_map_lookup_elem(&jrp_recv_guard, &socket_cookie)
                   ? k_java_remote_parent_receive_guard_busy
                   : k_java_remote_parent_receive_guard_error;
    }
    stored = bpf_map_lookup_elem(&jrp_recv_cur, &socket_cookie);
    if (java_remote_parent_receive_cursor_equal(stored, expected)) {
        return k_java_remote_parent_receive_guard_acquired;
    }
    // Roll back only the exact guard inserted above. Keep this byte-exact
    // validation, deletion, and absence/replacement recheck local: nesting the
    // general release helper here would retain both full cursor-comparison
    // frames and exceed the verifier stack from large parser/ioctl callers.
    const java_remote_parent_receive_cursor_t *inserted_guard =
        bpf_map_lookup_elem(&jrp_recv_guard, &socket_cookie);
    if (inserted_guard && __builtin_memcmp(inserted_guard, expected, sizeof(*expected)) == 0) {
        bpf_map_delete_elem(&jrp_recv_guard, &socket_cookie);
        inserted_guard = bpf_map_lookup_elem(&jrp_recv_guard, &socket_cookie);
        if (inserted_guard) {
            // A failed delete or post-delete successor remains live exclusion
            // evidence. Never retry deletion against that possibly foreign
            // value from this failed acquisition.
            return k_java_remote_parent_receive_guard_error;
        }
    }
    return k_java_remote_parent_receive_guard_error;
}

static __noinline __attribute__((unused)) u8 java_remote_parent_receive_cursor_replace_locked(
    u64 socket_cookie,
    const java_remote_parent_receive_cursor_t *expected_valid,
    const java_remote_parent_receive_cursor_t *publishing) {
    if (!socket_cookie || !java_remote_parent_receive_cursor_is_valid(expected_valid) ||
        !java_remote_parent_receive_cursor_is_publishing(publishing)) {
        return 0;
    }
    const java_remote_parent_receive_cursor_t *guard =
        bpf_map_lookup_elem(&jrp_recv_guard, &socket_cookie);
    const java_remote_parent_receive_cursor_t *stored =
        bpf_map_lookup_elem(&jrp_recv_cur, &socket_cookie);
    if (!java_remote_parent_receive_cursor_equal(guard, expected_valid) ||
        !java_remote_parent_receive_cursor_equal(stored, expected_valid)) {
        return 0;
    }
    if (bpf_map_update_elem(&jrp_recv_cur, &socket_cookie, publishing, BPF_EXIST) != 0) {
        return 0;
    }
    stored = bpf_map_lookup_elem(&jrp_recv_cur, &socket_cookie);
    return java_remote_parent_receive_cursor_equal(stored, publishing);
}

// The owner TID identifies the exact state that START staged. CONTINUE and
// RESET authority is process-wide, so compare the owner's derived process key
// with the canonical registered process instead of requiring the current TID.
static __always_inline u8
java_remote_parent_receive_cursor_process_matches(const java_remote_parent_receive_cursor_t *cursor,
                                                  const pid_key_t *process,
                                                  u64 process_incarnation) {
    return java_remote_parent_receive_cursor_is_valid(cursor) && process &&
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
    return java_remote_parent_receive_cursor_is_valid(cursor) && owner &&
           java_remote_parent_receive_cursor_owner_equal(&cursor->owner, owner) &&
           cursor->process_incarnation == process_incarnation &&
           cursor->lifecycle_id == lifecycle_id && cursor->request_sequence == request_sequence &&
           cursor->data_signal_nonce == data_signal_nonce && cursor->generation == generation;
}

static __noinline __attribute__((unused)) u8 java_remote_parent_receive_cursor_lookup_for_process(
    u64 socket_cookie,
    const pid_key_t *process,
    u64 process_incarnation,
    java_remote_parent_receive_cursor_t *snapshot) {
    if (!socket_cookie || !process || !process_incarnation || !snapshot ||
        !snapshot->lifecycle_id || !snapshot->request_sequence) {
        return 0;
    }
    const u64 lifecycle_id = snapshot->lifecycle_id;
    const u64 request_sequence = snapshot->request_sequence;
    const java_remote_parent_receive_cursor_t *stored =
        bpf_map_lookup_elem(&jrp_recv_cur, &socket_cookie);
    if (!java_remote_parent_receive_cursor_process_matches(stored, process, process_incarnation) ||
        stored->lifecycle_id != lifecycle_id || stored->request_sequence != request_sequence ||
        bpf_map_lookup_elem(&jrp_recv_guard, &socket_cookie)) {
        return 0;
    }
    *snapshot = *stored;
    stored = bpf_map_lookup_elem(&jrp_recv_cur, &socket_cookie);
    return java_remote_parent_receive_cursor_equal(stored, snapshot) &&
           java_remote_parent_receive_cursor_process_matches(
               snapshot, process, process_incarnation) &&
           snapshot->lifecycle_id == lifecycle_id &&
           snapshot->request_sequence == request_sequence &&
           !bpf_map_lookup_elem(&jrp_recv_guard, &socket_cookie);
}

static __always_inline u8
java_remote_parent_receive_cursor_continue(u64 socket_cookie,
                                           const pid_key_t *process,
                                           u64 process_incarnation,
                                           u64 lifecycle_id,
                                           u64 request_sequence,
                                           java_remote_parent_receive_cursor_t *snapshot) {
    if (!snapshot) {
        return 0;
    }
    snapshot->lifecycle_id = lifecycle_id;
    snapshot->request_sequence = request_sequence;
    return java_remote_parent_receive_cursor_lookup_for_process(
        socket_cookie, process, process_incarnation, snapshot);
}

static __always_inline u8
java_remote_parent_receive_cursor_reset(u64 socket_cookie,
                                        const pid_key_t *process,
                                        u64 process_incarnation,
                                        u64 lifecycle_id,
                                        u64 request_sequence,
                                        java_remote_parent_receive_cursor_t *snapshot) {
    if (!snapshot) {
        return 0;
    }
    snapshot->lifecycle_id = lifecycle_id;
    snapshot->request_sequence = request_sequence;
    return java_remote_parent_receive_cursor_lookup_for_process(
        socket_cookie, process, process_incarnation, snapshot);
}

static __noinline __attribute__((unused)) u8 java_remote_parent_receive_cursor_ack_generation(
    u64 socket_cookie,
    const java_remote_parent_receive_cursor_t *expected_publishing,
    u64 generation) {
    if (!socket_cookie || !generation ||
        !java_remote_parent_receive_cursor_is_publishing(expected_publishing)) {
        return 0;
    }
    const java_remote_parent_receive_cursor_t *stored =
        bpf_map_lookup_elem(&jrp_recv_cur, &socket_cookie);
    if (!java_remote_parent_receive_cursor_equal(stored, expected_publishing)) {
        return 0;
    }
    java_remote_parent_receive_cursor_t committed = *expected_publishing;
    committed.state = k_java_remote_parent_receive_cursor_valid;
    committed.generation = generation;
    if (bpf_map_update_elem(&jrp_recv_cur, &socket_cookie, &committed, BPF_EXIST) != 0) {
        return 0;
    }
    stored = bpf_map_lookup_elem(&jrp_recv_cur, &socket_cookie);
    return java_remote_parent_receive_cursor_equal(stored, &committed);
}

static __noinline __attribute__((unused)) u8
java_remote_parent_receive_cursor_mark_retiring_publishing(
    u64 socket_cookie, const java_remote_parent_receive_cursor_t *expected_publishing) {
    if (!socket_cookie || !java_remote_parent_receive_cursor_is_publishing(expected_publishing)) {
        return 0;
    }
    const java_remote_parent_receive_cursor_t *stored =
        bpf_map_lookup_elem(&jrp_recv_cur, &socket_cookie);
    // expected_publishing has already established the only admissible
    // generation-zero state. The cursor layout is asserted padding-free, so
    // exact bytes preserve the identity check without duplicating the
    // state-known comparison paths in this verifier-sensitive cleanup frame.
    if (!stored ||
        __builtin_memcmp(stored, expected_publishing, sizeof(*expected_publishing)) != 0) {
        return 0;
    }
    const java_remote_parent_receive_cursor_t retiring =
        java_remote_parent_receive_cursor_retiring_identity(expected_publishing);
    if (bpf_map_update_elem(&jrp_recv_cur, &socket_cookie, &retiring, BPF_EXIST) != 0) {
        return 0;
    }
    stored = bpf_map_lookup_elem(&jrp_recv_cur, &socket_cookie);
    return stored && __builtin_memcmp(stored, &retiring, sizeof(retiring)) == 0;
}

static __noinline __attribute__((unused)) u8 java_remote_parent_receive_cursor_mark_retiring_locked(
    u64 socket_cookie, const java_remote_parent_receive_cursor_t *expected_valid) {
    if (!socket_cookie || !java_remote_parent_receive_cursor_is_valid(expected_valid)) {
        return 0;
    }
    const java_remote_parent_receive_cursor_t *guard =
        bpf_map_lookup_elem(&jrp_recv_guard, &socket_cookie);
    const java_remote_parent_receive_cursor_t *stored =
        bpf_map_lookup_elem(&jrp_recv_cur, &socket_cookie);
    // expected_valid is already a fully validated identity, and the cursor's
    // asserted layout is contiguous with no padding. Exact byte equality here
    // avoids materializing two redundant state-known comparison paths in this
    // verifier-sensitive frame while preserving adjacent guard/cursor checks.
    if (!guard || __builtin_memcmp(guard, expected_valid, sizeof(*expected_valid)) != 0 ||
        !stored || __builtin_memcmp(stored, expected_valid, sizeof(*expected_valid)) != 0) {
        return 0;
    }
    const java_remote_parent_receive_cursor_t retiring =
        java_remote_parent_receive_cursor_retiring_identity(expected_valid);
    if (bpf_map_update_elem(&jrp_recv_cur, &socket_cookie, &retiring, BPF_EXIST) != 0) {
        return 0;
    }
    stored = bpf_map_lookup_elem(&jrp_recv_cur, &socket_cookie);
    return stored && __builtin_memcmp(stored, &retiring, sizeof(retiring)) == 0;
}

static __noinline __attribute__((unused)) u8 java_remote_parent_receive_cursor_delete_retiring(
    u64 socket_cookie, const java_remote_parent_receive_cursor_t *expected_identity) {
    if (!socket_cookie || !java_remote_parent_receive_cursor_state_known(expected_identity)) {
        return 0;
    }
    const java_remote_parent_receive_cursor_t *stored =
        bpf_map_lookup_elem(&jrp_recv_cur, &socket_cookie);
    if (!java_remote_parent_receive_cursor_retiring_identity_matches(stored, expected_identity)) {
        return 0;
    }
    return bpf_map_delete_elem(&jrp_recv_cur, &socket_cookie) == 0;
}

static __noinline __attribute__((unused)) u8
java_remote_parent_receive_cursor_finish_retiring_guarded(
    u64 socket_cookie, const java_remote_parent_receive_cursor_t *expected_valid) {
    if (!socket_cookie || !java_remote_parent_receive_cursor_is_valid(expected_valid)) {
        return 0;
    }
    const java_remote_parent_receive_cursor_t *stored =
        bpf_map_lookup_elem(&jrp_recv_cur, &socket_cookie);
    if (!java_remote_parent_receive_cursor_retiring_identity_matches(stored, expected_valid)) {
        return 0;
    }
    // Cursor deletion is strictly last. If exact guard deletion fails, retain
    // RETIRING so no persistent guard can become uncharged and no authority
    // can be consumed.
    if (!java_remote_parent_receive_cursor_guard_release(socket_cookie, expected_valid)) {
        return 0;
    }
    return java_remote_parent_receive_cursor_delete_retiring(socket_cookie, expected_valid);
}

static __noinline __attribute__((unused)) u8
java_remote_parent_receive_cursor_finish_retiring_publishing(
    u64 socket_cookie, const java_remote_parent_receive_cursor_t *expected_publishing) {
    return java_remote_parent_receive_cursor_delete_retiring(socket_cookie, expected_publishing);
}

static __noinline __attribute__((unused)) u8 java_remote_parent_receive_cursor_mark_retiring_close(
    u64 socket_cookie, const java_remote_parent_receive_cursor_t *expected) {
    if (!socket_cookie || !java_remote_parent_receive_cursor_state_known(expected)) {
        return 0;
    }
    const java_remote_parent_receive_cursor_t retiring =
        java_remote_parent_receive_cursor_retiring_identity(expected);
    const java_remote_parent_receive_cursor_t *stored =
        bpf_map_lookup_elem(&jrp_recv_cur, &socket_cookie);
    if (java_remote_parent_receive_cursor_equal(stored, &retiring)) {
        return 1;
    }
    if (!java_remote_parent_receive_cursor_equal(stored, expected) ||
        bpf_map_update_elem(&jrp_recv_cur, &socket_cookie, &retiring, BPF_EXIST) != 0) {
        return 0;
    }
    stored = bpf_map_lookup_elem(&jrp_recv_cur, &socket_cookie);
    return java_remote_parent_receive_cursor_equal(stored, &retiring);
}

// tcp_close is ordered after the final socket-file reference, so it has no
// same-cookie ioctl writer. It may therefore repair a stale exact-cookie guard
// and then delete the exact PUBLISHING/VALID/RETIRING cursor. The caller must
// perform external generation/signal fencing before invoking this helper.
static __noinline __attribute__((unused)) u8 java_remote_parent_receive_cursor_close_delete(
    u64 socket_cookie, const java_remote_parent_receive_cursor_t *expected) {
    if (!socket_cookie || !java_remote_parent_receive_cursor_state_known(expected)) {
        return 0;
    }
    bpf_map_delete_elem(&jrp_recv_guard, &socket_cookie);
    if (bpf_map_lookup_elem(&jrp_recv_guard, &socket_cookie)) {
        return 0;
    }
    const java_remote_parent_receive_cursor_t *stored =
        bpf_map_lookup_elem(&jrp_recv_cur, &socket_cookie);
    if (!stored) {
        return 1;
    }
    if (!java_remote_parent_receive_cursor_equal(stored, expected)) {
        return 0;
    }
    bpf_map_delete_elem(&jrp_recv_cur, &socket_cookie);
    return !bpf_map_lookup_elem(&jrp_recv_cur, &socket_cookie);
}

static __noinline __attribute__((unused)) u8
java_remote_parent_receive_cursor_close_stale_guard(u64 socket_cookie) {
    if (!socket_cookie) {
        return 0;
    }
    bpf_map_delete_elem(&jrp_recv_guard, &socket_cookie);
    return !bpf_map_lookup_elem(&jrp_recv_guard, &socket_cookie);
}
