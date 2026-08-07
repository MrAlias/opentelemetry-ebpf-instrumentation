// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <common/connection_info.h>
#include <common/http_types.h>

#include <generictracer/java_remote_parent_receive.h>
#include <maps/java_remote_parent.h>
#include <maps/java_remote_parent_receive_cursor.h>

enum java_remote_parent_receive_ioctl_transition : u8 {
    k_java_remote_parent_receive_ioctl_transition_invalid = 0,
    k_java_remote_parent_receive_ioctl_transition_ready = 1,
    k_java_remote_parent_receive_ioctl_transition_fence_abort = 2,
    k_java_remote_parent_receive_ioctl_transition_fence_replace = 3,
    k_java_remote_parent_receive_ioctl_transition_fence_retire = 4,
};

enum { k_java_remote_parent_receive_ioctl_fence_context_tag = 0x4a525046 };

// Fence transitions do not publish a parser context in phase A. Reuse that
// scratch for the live socket's netns cookie, with an explicit tag and a
// zero-tail check so phase B cannot adopt stale READY or payload bytes.
typedef struct java_remote_parent_receive_ioctl_fence_context {
    u64 connection_netns_cookie;
    u32 tag;
    u32 reserved;
    unsigned char zero_tail[48];
} java_remote_parent_receive_ioctl_fence_context_t;

_Static_assert(sizeof(java_remote_parent_receive_ioctl_fence_context_t) ==
                   sizeof(java_remote_parent_receive_context_t),
               "Java receive fence context size mismatch");
_Static_assert(offsetof(java_remote_parent_receive_ioctl_fence_context_t,
                        connection_netns_cookie) == 0,
               "Java receive fence context cookie offset mismatch");
_Static_assert(offsetof(java_remote_parent_receive_ioctl_fence_context_t, tag) == 8,
               "Java receive fence context tag offset mismatch");
_Static_assert(offsetof(java_remote_parent_receive_ioctl_fence_context_t, zero_tail) == 16,
               "Java receive fence context tail offset mismatch");

typedef struct java_remote_parent_receive_ioctl_workspace {
    java_remote_parent_receive_cursor_t cursor;
    java_remote_parent_receive_cursor_t predecessor;
    u64 socket_cookie;
    u32 connection_netns;
    u8 transition;
    u8 guard;
    unsigned char reserved[2];
} java_remote_parent_receive_ioctl_workspace_t;

typedef union java_remote_parent_close_key {
    java_remote_parent_data_signal_key_t signal;
    java_remote_parent_key_t generation;
} java_remote_parent_close_key_t;

// This workspace is private to the independently attached Java tcp_close
// kprobe. Regular perf-event kprobes suppress recursive tracing-BPF entry, but
// keep explicit ownership so preemptible per-CPU reuse fails closed if the
// attachment model ever changes. Reassess that invariant before sharing this
// map, crossing a tail call, or moving the hook to a runner without recursion
// suppression.
typedef struct java_remote_parent_close_workspace {
    u64 invocation_id;
    u64 socket_cookie;
    u64 connection_netns_cookie;
    java_remote_parent_receive_cursor_t cursor;
    java_remote_parent_close_key_t key;
    pid_connection_info_t process_connection;
    u64 generation_to_fence;
    u32 connection_netns;
    u8 connection_valid;
    unsigned char reserved[3];
} java_remote_parent_close_workspace_t;

_Static_assert(sizeof(java_remote_parent_close_key_t) == 24,
               "Java close reusable key size mismatch");
_Static_assert(sizeof(java_remote_parent_close_workspace_t) == 160,
               "Java close workspace size mismatch");
_Static_assert(offsetof(java_remote_parent_close_workspace_t, invocation_id) == 0,
               "Java close workspace invocation offset mismatch");
_Static_assert(offsetof(java_remote_parent_close_workspace_t, cursor) == 24,
               "Java close workspace cursor offset mismatch");
_Static_assert(offsetof(java_remote_parent_close_workspace_t, key) == 80,
               "Java close workspace key offset mismatch");
_Static_assert(offsetof(java_remote_parent_close_workspace_t, process_connection) == 104,
               "Java close workspace connection offset mismatch");
_Static_assert(offsetof(java_remote_parent_close_workspace_t, generation_to_fence) == 144,
               "Java close workspace generation offset mismatch");
_Static_assert(offsetof(java_remote_parent_close_workspace_t, connection_netns) == 152,
               "Java close workspace network namespace offset mismatch");
_Static_assert(offsetof(java_remote_parent_close_workspace_t, connection_valid) == 156,
               "Java close workspace validity offset mismatch");

SCRATCH_MEM_TYPED(java_remote_parent_close_workspace, java_remote_parent_close_workspace_t)

static __always_inline java_remote_parent_close_workspace_t *
java_remote_parent_close_workspace_acquire(u64 invocation_id) {
    java_remote_parent_close_workspace_t *workspace = java_remote_parent_close_workspace_mem();
    if (!workspace || !invocation_id || workspace->invocation_id) {
        return NULL;
    }

    // Publish exclusion before clearing payload bytes. Any competing reuse
    // must observe the workspace as busy throughout initialization.
    workspace->invocation_id = invocation_id;
    barrier();
    __builtin_memset(&workspace->socket_cookie,
                     0,
                     sizeof(*workspace) -
                         offsetof(java_remote_parent_close_workspace_t, socket_cookie));
    return workspace;
}

static __always_inline u8 java_remote_parent_close_workspace_owned(
    const java_remote_parent_close_workspace_t *workspace, u64 invocation_id) {
    return workspace && invocation_id && workspace->invocation_id == invocation_id;
}

static __always_inline void
java_remote_parent_close_workspace_release(java_remote_parent_close_workspace_t *workspace,
                                           u64 invocation_id) {
    if (!java_remote_parent_close_workspace_owned(workspace, invocation_id)) {
        return;
    }

    __builtin_memset(&workspace->socket_cookie,
                     0,
                     sizeof(*workspace) -
                         offsetof(java_remote_parent_close_workspace_t, socket_cookie));
    // Clear exclusion last so a new acquisition never observes partially
    // cleared payload as an available workspace.
    barrier();
    workspace->invocation_id = 0;
}

_Static_assert(sizeof(java_remote_parent_receive_ioctl_workspace_t) == 128,
               "Java receive cursor workspace size mismatch");
_Static_assert(sizeof(java_remote_parent_receive_ioctl_workspace_t) ==
                   sizeof(java_remote_parent_state_t),
               "Java receive cursor workspace must exactly overlay stage-state scratch");
_Static_assert(offsetof(java_remote_parent_receive_ioctl_workspace_t, cursor) == 0,
               "Java receive cursor workspace cursor offset mismatch");
_Static_assert(offsetof(java_remote_parent_receive_ioctl_workspace_t, predecessor) == 56,
               "Java receive cursor workspace predecessor offset mismatch");
_Static_assert(offsetof(java_remote_parent_receive_ioctl_workspace_t, socket_cookie) == 112,
               "Java receive cursor workspace socket offset mismatch");
_Static_assert(offsetof(java_remote_parent_receive_ioctl_workspace_t, connection_netns) == 120,
               "Java receive cursor workspace network namespace offset mismatch");
_Static_assert(offsetof(java_remote_parent_receive_ioctl_workspace_t, transition) == 124,
               "Java receive cursor workspace transition offset mismatch");
_Static_assert(offsetof(java_remote_parent_receive_ioctl_workspace_t, guard) == 125,
               "Java receive cursor workspace guard offset mismatch");
_Static_assert(offsetof(java_remote_parent_receive_ioctl_workspace_t, reserved) == 126,
               "Java receive cursor workspace reserved offset mismatch");
_Static_assert(sizeof(java_remote_parent_receive_context_t) <=
                   sizeof(java_remote_parent_incoming_t),
               "Java receive context exceeds incoming scratch");

static __always_inline void
java_remote_parent_receive_ioctl_fence_context_init(java_remote_parent_receive_context_t *context,
                                                    u64 connection_netns_cookie) {
    java_remote_parent_receive_ioctl_fence_context_t *fence_context =
        (java_remote_parent_receive_ioctl_fence_context_t *)context;
    *fence_context = (java_remote_parent_receive_ioctl_fence_context_t){
        .connection_netns_cookie = connection_netns_cookie,
        .tag = k_java_remote_parent_receive_ioctl_fence_context_tag,
    };
}

static __always_inline u64 java_remote_parent_receive_ioctl_fence_context_cookie(
    const java_remote_parent_receive_context_t *context) {
    const java_remote_parent_receive_ioctl_fence_context_t *fence_context =
        (const java_remote_parent_receive_ioctl_fence_context_t *)context;
    if (!fence_context || !fence_context->connection_netns_cookie ||
        fence_context->tag != k_java_remote_parent_receive_ioctl_fence_context_tag ||
        fence_context->reserved ||
        __builtin_memcmp(fence_context->zero_tail,
                         (unsigned char[sizeof(fence_context->zero_tail)]){0},
                         sizeof(fence_context->zero_tail)) != 0) {
        return 0;
    }
    return fence_context->connection_netns_cookie;
}

static __always_inline u8 java_remote_parent_receive_ioctl_transition_known(u8 transition) {
    return transition >= k_java_remote_parent_receive_ioctl_transition_ready &&
           transition <= k_java_remote_parent_receive_ioctl_transition_fence_retire;
}

static __always_inline u8 java_remote_parent_receive_ioctl_transition_needs_fence(u8 transition) {
    return transition >= k_java_remote_parent_receive_ioctl_transition_fence_abort &&
           transition <= k_java_remote_parent_receive_ioctl_transition_fence_retire;
}

static __always_inline u8 java_remote_parent_receive_ioctl_ready_context_exact(
    const java_remote_parent_receive_ioctl_workspace_t *workspace,
    const java_remote_parent_receive_context_t *context) {
    return workspace && context &&
           workspace->transition == k_java_remote_parent_receive_ioctl_transition_ready &&
           workspace->socket_cookie && workspace->connection_netns && !workspace->guard &&
           !workspace->reserved[0] && !workspace->reserved[1] && !context->reserved &&
           __builtin_memcmp(context->reserved2,
                            (unsigned char[sizeof(context->reserved2)]){0},
                            sizeof(context->reserved2)) == 0 &&
           context->owner_tid == workspace->cursor.owner.tid &&
           context->owner_pid == workspace->cursor.owner.pid &&
           context->owner_ns == workspace->cursor.owner.ns &&
           context->process_incarnation == workspace->cursor.process_incarnation &&
           context->lifecycle_id == workspace->cursor.lifecycle_id &&
           context->request_sequence == workspace->cursor.request_sequence &&
           context->data_signal_nonce == workspace->cursor.data_signal_nonce &&
           context->generation == workspace->cursor.generation &&
           ((context->action == k_java_remote_parent_receive_action_http1_start &&
             java_remote_parent_receive_cursor_is_publishing(&workspace->cursor)) ||
            (context->action == k_java_remote_parent_receive_action_http1_continue &&
             java_remote_parent_receive_cursor_is_valid(&workspace->cursor)));
}

static __always_inline java_remote_parent_receive_cursor_t *
java_remote_parent_receive_ioctl_fence_cursor(
    java_remote_parent_receive_ioctl_workspace_t *workspace) {
    if (!workspace ||
        !java_remote_parent_receive_ioctl_transition_needs_fence(workspace->transition) ||
        workspace->reserved[0] || workspace->reserved[1]) {
        return NULL;
    }
    return workspace->transition == k_java_remote_parent_receive_ioctl_transition_fence_retire
               ? &workspace->cursor
               : &workspace->predecessor;
}

static __noinline __attribute__((unused)) u8 java_remote_parent_receive_ioctl_fence_authorized(
    java_remote_parent_receive_ioctl_workspace_t *workspace) {
    java_remote_parent_receive_cursor_t *target =
        java_remote_parent_receive_ioctl_fence_cursor(workspace);
    if (!target || !workspace->socket_cookie || !workspace->connection_netns ||
        !java_remote_parent_receive_cursor_is_valid(target)) {
        return 0;
    }

    if (workspace->transition == k_java_remote_parent_receive_ioctl_transition_fence_abort) {
        // Guard acquisition failed. The immutable snapshot still authorizes
        // only its own exact owner/generation M key; it never names a
        // successor generation and phase C performs no cursor mutation.
        return workspace->guard == k_java_remote_parent_receive_guard_error;
    }
    if (workspace->guard != k_java_remote_parent_receive_guard_acquired) {
        return 0;
    }

    const java_remote_parent_receive_cursor_t *guard =
        bpf_map_lookup_elem(&jrp_recv_guard, &workspace->socket_cookie);
    const java_remote_parent_receive_cursor_t *stored =
        bpf_map_lookup_elem(&jrp_recv_cur, &workspace->socket_cookie);
    return java_remote_parent_receive_cursor_equal(guard, target) &&
           java_remote_parent_receive_cursor_equal(stored, target);
}

// Keep strict final-form recognition out of the phase-B caller frame. Its
// inlined connection-key checks otherwise increase the frame charged against
// the mutually exclusive 384-byte zero/aliased cleanup leaves.
static __noinline __attribute__((unused)) u8 java_remote_parent_receive_generation_already_fenced(
    const java_remote_parent_receive_cursor_t *cursor,
    const connection_info_t *connection,
    u32 connection_netns,
    u64 connection_netns_cookie,
    u64 socket_cookie) {
    if (!java_remote_parent_receive_cursor_state_known(cursor) || !cursor->generation ||
        !connection || is_empty_connection_info(connection) || !connection_netns ||
        !connection_netns_cookie || !socket_cookie) {
        return 0;
    }
    const java_remote_parent_key_t key =
        java_remote_parent_state_key(&cursor->owner, cursor->generation);
    return java_remote_parent_exact_receive_already_fenced(&key,
                                                           cursor->process_incarnation,
                                                           connection,
                                                           connection_netns,
                                                           connection_netns_cookie,
                                                           socket_cookie);
}

// Pre-ACK HTTP tail exits always retire a generation-zero PUBLISHING cursor.
// Keep that hot cleanup off the generic generation-fencing call chain: the
// HTTP continuation program already has a large frame, and nesting the generic
// cursor/fence helpers exceeds the verifier's combined 512-byte stack limit.
// One local cursor is reused by phase: first as the transient data-signal key,
// then as exact PUBLISHING, and finally as RETIRING. The shapes are never live
// simultaneously. This deliberately avoids per-CPU scratch because the
// lifecycle invariant should remain valid even if reused from a preemptible
// attachment in the future.
static __noinline __attribute__((unused)) void java_remote_parent_cleanup_unacked_receive_context(
    const java_remote_parent_receive_context_t *context, u64 socket_cookie) {
    if (!context || context->action != k_java_remote_parent_receive_action_http1_start ||
        context->generation || !socket_cookie) {
        return;
    }

    java_remote_parent_receive_cursor_t cursor_value = {0};
    java_remote_parent_receive_cursor_t *publishing = &cursor_value;

    java_remote_parent_data_signal_key_t *signal_key =
        (java_remote_parent_data_signal_key_t *)publishing;
    signal_key->process.tid = context->owner_pid;
    signal_key->process.pid = context->owner_pid;
    signal_key->process.ns = context->owner_ns;
    signal_key->nonce = context->data_signal_nonce;
    bpf_map_delete_elem(&java_remote_parent_data_acks, signal_key);

    __builtin_memset(publishing, 0, sizeof(*publishing));
    publishing->owner.tid = context->owner_tid;
    publishing->owner.pid = context->owner_pid;
    publishing->owner.ns = context->owner_ns;
    publishing->state = k_java_remote_parent_receive_cursor_publishing;
    publishing->process_incarnation = context->process_incarnation;
    publishing->lifecycle_id = context->lifecycle_id;
    publishing->request_sequence = context->request_sequence;
    publishing->data_signal_nonce = context->data_signal_nonce;
    java_remote_parent_finish_data_signal(&publishing->owner, publishing->data_signal_nonce);

    const java_remote_parent_receive_cursor_t *stored =
        bpf_map_lookup_elem(&jrp_recv_cur, &socket_cookie);
    if (!java_remote_parent_receive_cursor_exact_publishing(stored, publishing)) {
        return;
    }

    publishing->state = k_java_remote_parent_receive_cursor_retiring;
    if (bpf_map_update_elem(&jrp_recv_cur, &socket_cookie, publishing, BPF_EXIST) != 0) {
        return;
    }
    stored = bpf_map_lookup_elem(&jrp_recv_cur, &socket_cookie);
    if (!java_remote_parent_receive_cursor_equal(stored, publishing)) {
        return;
    }
    bpf_map_delete_elem(&jrp_recv_cur, &socket_cookie);
}

static __always_inline u8 java_remote_parent_fence_receive_cursor(
    java_remote_parent_close_workspace_t *workspace, u64 invocation_id) {
    if (!java_remote_parent_close_workspace_owned(workspace, invocation_id) ||
        !java_remote_parent_receive_cursor_state_known(&workspace->cursor)) {
        return 0;
    }

    workspace->key.signal = (java_remote_parent_data_signal_key_t){
        .process = java_process_key(&workspace->cursor.owner),
        .nonce = workspace->cursor.data_signal_nonce,
    };
    bpf_map_delete_elem(&java_remote_parent_data_acks, &workspace->key.signal);
    java_remote_parent_finish_data_signal(&workspace->cursor.owner,
                                          workspace->cursor.data_signal_nonce);

    u8 generation_fenced = 1;
    if (workspace->generation_to_fence && workspace->socket_cookie) {
        workspace->key.generation =
            java_remote_parent_state_key(&workspace->cursor.owner, workspace->generation_to_fence);
        if (workspace->connection_valid && workspace->connection_netns &&
            !is_empty_connection_info(&workspace->process_connection.conn)) {
            // Materialize leaf arguments after the mode lookup. Keeping them
            // live across this helper adds a spill slot to the close root on
            // legacy verifier targets.
            const java_remote_parent_state_t *state =
                bpf_map_lookup_elem(&java_remote_parent_state, &workspace->key.generation);
            if (!state) {
                generation_fenced = 0;
            } else if (state->aliases) {
                generation_fenced = java_remote_parent_detach_exact_receive_aliased(
                    &workspace->key.generation,
                    workspace->cursor.process_incarnation,
                    &workspace->process_connection.conn,
                    workspace->connection_netns,
                    workspace->socket_cookie);
            } else {
                generation_fenced = java_remote_parent_cleanup_exact_receive_zero_alias(
                    &workspace->key.generation,
                    workspace->cursor.process_incarnation,
                    &workspace->process_connection.conn,
                    workspace->connection_netns,
                    workspace->socket_cookie);
            }
            if (!generation_fenced) {
                generation_fenced =
                    java_remote_parent_mark_exact_generation_ambiguous(&workspace->key.generation);
            }
        } else {
            // Tuple parsing can fail during late socket teardown. The exact
            // owner/generation from the cursor is still sufficient to publish
            // a terminal ambiguity fence, so no future SDK lookup can consume
            // the generation while asynchronous cleanup converges its
            // connection-indexed artifacts.
            generation_fenced =
                java_remote_parent_mark_exact_generation_ambiguous(&workspace->key.generation);
        }
    }
    return generation_fenced;
}

// Complete only a transition that phase A recorded before the exact generation
// fence ran as a sibling of the large ioctl payload frame. Every cursor helper
// revalidates exact map identity, so replacement between phases fails closed.
static __noinline __attribute__((unused)) u8 java_remote_parent_complete_receive_ioctl_transition(
    java_remote_parent_receive_ioctl_workspace_t *workspace, u8 generation_fenced) {
    if (!workspace || !java_remote_parent_receive_ioctl_transition_known(workspace->transition) ||
        workspace->transition == k_java_remote_parent_receive_ioctl_transition_ready ||
        !workspace->socket_cookie || !workspace->connection_netns || workspace->reserved[0] ||
        workspace->reserved[1] || workspace->guard > k_java_remote_parent_receive_guard_busy) {
        return 0;
    }

    const u64 socket_cookie = workspace->socket_cookie;
    if (workspace->transition == k_java_remote_parent_receive_ioctl_transition_fence_abort) {
        // Guard acquisition failed before phase B. Fencing is still useful,
        // but no cursor transition is authorized by this invocation.
        if (workspace->guard != k_java_remote_parent_receive_guard_error) {
            return 0;
        }
        return 0;
    }

    if (workspace->guard != k_java_remote_parent_receive_guard_acquired) {
        return 0;
    }

    if (workspace->transition == k_java_remote_parent_receive_ioctl_transition_fence_retire) {
        if (!generation_fenced) {
            if (java_remote_parent_receive_cursor_mark_retiring_locked(socket_cookie,
                                                                       &workspace->cursor)) {
                java_remote_parent_receive_cursor_guard_release(socket_cookie, &workspace->cursor);
            }
            return 0;
        }
        if (java_remote_parent_receive_cursor_mark_retiring_locked(socket_cookie,
                                                                   &workspace->cursor)) {
            java_remote_parent_receive_cursor_finish_retiring_guarded(socket_cookie,
                                                                      &workspace->cursor);
        }
        return 0;
    }

    if (workspace->transition != k_java_remote_parent_receive_ioctl_transition_fence_replace) {
        return 0;
    }
    if (!generation_fenced) {
        if (java_remote_parent_receive_cursor_mark_retiring_locked(socket_cookie,
                                                                   &workspace->predecessor)) {
            java_remote_parent_receive_cursor_guard_release(socket_cookie, &workspace->predecessor);
        }
        return 0;
    }
    if (!java_remote_parent_receive_cursor_replace_locked(
            socket_cookie, &workspace->predecessor, &workspace->cursor)) {
        if (java_remote_parent_receive_cursor_mark_retiring_locked(socket_cookie,
                                                                   &workspace->predecessor)) {
            java_remote_parent_receive_cursor_finish_retiring_guarded(socket_cookie,
                                                                      &workspace->predecessor);
        }
        return 0;
    }
    if (!java_remote_parent_receive_cursor_guard_release(socket_cookie, &workspace->predecessor)) {
        // Never leave a new PUBLISHING cursor behind an old exact guard.
        if (java_remote_parent_receive_cursor_mark_retiring_publishing(socket_cookie,
                                                                       &workspace->cursor) &&
            java_remote_parent_receive_cursor_guard_release(socket_cookie,
                                                            &workspace->predecessor)) {
            java_remote_parent_receive_cursor_delete_retiring(socket_cookie, &workspace->cursor);
        }
        return 0;
    }
    java_remote_parent_publish_data_signal(workspace->cursor.data_signal_nonce);
    workspace->transition = k_java_remote_parent_receive_ioctl_transition_ready;
    workspace->guard = 0;
    return 1;
}

// Parser-tail failure needs to revoke SDK authority before it can retire the
// receive cursor, but it does not need to synchronously dismantle every G
// index. Normal staged generations pre-reserve M before publication. Mutating
// that exact reservation is therefore non-allocating and immediately
// fail-closed; the generation sweeper and baseline lifecycle cleanup converge
// the now-unreachable graph asynchronously. Keeping this leaf shallow also
// prevents the HTTP parser's existing frame from nesting the large exact
// detach workspace past the verifier's 512-byte call-stack limit.
static __noinline void java_remote_parent_cleanup_receive_cursor_signal(
    const java_remote_parent_receive_cursor_t *cursor) {
    const java_remote_parent_data_signal_key_t signal_key = {
        .process = java_process_key(&cursor->owner),
        .nonce = cursor->data_signal_nonce,
    };
    bpf_map_delete_elem(&java_remote_parent_data_acks, &signal_key);
    java_remote_parent_finish_data_signal(&cursor->owner, cursor->data_signal_nonce);
}

static __noinline u8 java_remote_parent_fence_receive_cursor_ambiguous(
    const java_remote_parent_receive_cursor_t *cursor, u64 generation) {
    if (!generation) {
        return 1;
    }
    const java_remote_parent_key_t key = java_remote_parent_state_key(&cursor->owner, generation);
    return java_remote_parent_mark_exact_generation_ambiguous(&key);
}

// Retire only the exact cursor authorized by the parser tail. A failed M
// mutation never restores SDK generation authority: either a durable M+
// fences it, RETIRING is published, or the exact guard remains held for
// close-time repair.
static __noinline u8 java_remote_parent_cleanup_receive_cursor(
    const java_remote_parent_receive_cursor_t *cursor, u64 socket_cookie, u64 generation) {
    if (!java_remote_parent_receive_cursor_state_known(cursor)) {
        return 0;
    }
    if (java_remote_parent_receive_cursor_is_publishing(cursor)) {
        // Complete the stack-backed signal-key phase before nesting the deep
        // exact-M mutation. Parser roots already carry large frames, so these
        // sibling calls must not overlap in the verifier call graph.
        java_remote_parent_cleanup_receive_cursor_signal(cursor);
        u8 fenced = java_remote_parent_fence_receive_cursor_ambiguous(cursor, generation);
        if (!fenced && generation) {
            fenced = java_remote_parent_fence_receive_cursor_ambiguous(cursor, generation);
        }
        if (!java_remote_parent_receive_cursor_mark_retiring_publishing(socket_cookie, cursor)) {
            return 0;
        }
        if (!fenced) {
            return 0;
        }
        return java_remote_parent_receive_cursor_finish_retiring_publishing(socket_cookie, cursor);
    }
    if (!java_remote_parent_receive_cursor_is_valid(cursor)) {
        return 0;
    }
    // VALID cursor authority is inseparable from its committed generation.
    // Only PUBLISHING cleanup may receive a separately staged generation
    // after ACK failed; never fence one G key while retiring another VALID
    // cursor identity.
    if (generation != cursor->generation) {
        return 0;
    }
    const enum java_remote_parent_receive_guard_result guard =
        java_remote_parent_receive_cursor_guard_acquire(socket_cookie, cursor);
    if (guard == k_java_remote_parent_receive_guard_busy) {
        return 0;
    }
    java_remote_parent_cleanup_receive_cursor_signal(cursor);
    u8 fenced = java_remote_parent_fence_receive_cursor_ambiguous(cursor, generation);
    if (!fenced && generation) {
        // A normal staged generation mutates its pre-reserved slot on the
        // first attempt. One bounded retry covers a legacy missing-slot
        // insertion/recheck race without nesting the heavyweight G detach.
        fenced = java_remote_parent_fence_receive_cursor_ambiguous(cursor, generation);
    }
    if (guard != k_java_remote_parent_receive_guard_acquired ||
        !java_remote_parent_receive_cursor_mark_retiring_locked(socket_cookie, cursor)) {
        return 0;
    }
    if (!fenced) {
        java_remote_parent_receive_cursor_guard_release(socket_cookie, cursor);
        return 0;
    }
    return java_remote_parent_receive_cursor_finish_retiring_guarded(socket_cookie, cursor);
}

// This is the receive-cursor portion of the independently attached Java
// tcp_close hook. Keeping the ordering branch here makes its host tests execute
// the same code as the loaded BPF program.
static __always_inline u8 java_remote_parent_close_receive_cursor(
    java_remote_parent_close_workspace_t *workspace, u64 invocation_id) {
    if (!java_remote_parent_close_workspace_owned(workspace, invocation_id) ||
        !workspace->socket_cookie) {
        return 0;
    }

    if (!java_remote_parent_receive_cursor_snapshot_state(workspace->socket_cookie,
                                                          &workspace->cursor)) {
        return java_remote_parent_receive_cursor_close_stale_guard(workspace->socket_cookie);
    }

    workspace->generation_to_fence = workspace->cursor.generation;
    if (workspace->cursor.generation && workspace->connection_valid &&
        workspace->connection_netns && workspace->connection_netns_cookie &&
        !is_empty_connection_info(&workspace->process_connection.conn) &&
        java_remote_parent_receive_generation_already_fenced(&workspace->cursor,
                                                             &workspace->process_connection.conn,
                                                             workspace->connection_netns,
                                                             workspace->connection_netns_cookie,
                                                             workspace->socket_cookie)) {
        // Generation payload is already final. Finish only the cursor's
        // data-signal side channel before deleting it.
        workspace->generation_to_fence = 0;
    }
    (void)java_remote_parent_fence_receive_cursor(workspace, invocation_id);
    // Cursor state is not SDK generation authority. Once final fput reaches
    // tcp_close there can be no later same-file Java ioctl, so terminally drain
    // the cursor even if legacy/malformed generation state could not publish a
    // fence. Normal staged generations have a pre-reserved M slot and mutate
    // it in place; generation claims, guards, M, and the generation sweeper are
    // independently responsible for any partial generation cleanup.
    if (java_remote_parent_receive_cursor_close_delete(workspace->socket_cookie,
                                                       &workspace->cursor)) {
        return 1;
    }

    // Hash-map delete of an existing exact key is non-allocating. Bounded
    // retries cover a transient helper failure while RETIRING prevents a
    // guard-free VALID tail between attempts. If the exact cursor disappeared,
    // close_delete treats that already-terminal state as success.
    const u8 retiring = java_remote_parent_receive_cursor_mark_retiring_close(
        workspace->socket_cookie, &workspace->cursor);
    if (retiring) {
        workspace->cursor.state = k_java_remote_parent_receive_cursor_retiring;
    }
    if (java_remote_parent_receive_cursor_close_delete(workspace->socket_cookie,
                                                       &workspace->cursor)) {
        return 1;
    }
    java_remote_parent_receive_cursor_close_stale_guard(workspace->socket_cookie);
    return java_remote_parent_receive_cursor_close_delete(workspace->socket_cookie,
                                                          &workspace->cursor);
}
