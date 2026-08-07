// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>

enum { BPF_ANY = 0, BPF_NOEXIST = 1, BPF_EXIST = 2 };

static void *test_map_lookup(void *map, const void *key);
static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags);
static long test_map_delete(void *map, const void *key);

#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update
#define bpf_map_delete_elem test_map_delete

#include <maps/java_remote_parent_receive_cursor.h>

#undef bpf_map_lookup_elem
#undef bpf_map_update_elem
#undef bpf_map_delete_elem

static const u64 test_socket_cookie = 0x1020304050607080ULL;
static const pid_key_t test_owner = {.tid = 101, .pid = 10, .ns = 7};
static const pid_key_t test_process = {.tid = 10, .pid = 10, .ns = 7};
static const u64 test_process_incarnation = 0x1112131415161718ULL;
static const u64 test_lifecycle_id = 0x2122232425262728ULL;
static const u64 test_request_sequence = 0x3132333435363738ULL;
static const u64 test_data_signal_nonce = 0x4142434445464748ULL;
static const pid_key_t replacement_owner = {.tid = 202, .pid = 10, .ns = 7};

static u64 cursor_cookie;
static java_remote_parent_receive_cursor_t cursor_value;
static int cursor_present;
static u64 guard_cookie;
static java_remote_parent_receive_cursor_t guard_value;
static int guard_present;
static int cursor_update_failure;
static int guard_update_failure;
static int cursor_delete_failure;
static int guard_delete_failure;
static int replace_guard_on_delete_failure;
static int cursor_update_calls;
static int guard_update_calls;
static int cursor_delete_calls;
static int guard_delete_calls;
static int cursor_lookup_calls;
static int corrupt_cursor_lookup;
static unsigned long long cursor_update_flags;
static unsigned long long guard_update_flags;

static void fail(const char *message) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

static int same_cursor(const java_remote_parent_receive_cursor_t *left,
                       const java_remote_parent_receive_cursor_t *right) {
    return memcmp(left, right, sizeof(*left)) == 0;
}

static java_remote_parent_receive_cursor_t
publishing_for(const pid_key_t *owner, u64 lifecycle_id, u64 request_sequence, u64 nonce) {
    return java_remote_parent_receive_cursor_publishing_identity(
        owner, test_process_incarnation, lifecycle_id, request_sequence, nonce);
}

static java_remote_parent_receive_cursor_t publishing(void) {
    return publishing_for(
        &test_owner, test_lifecycle_id, test_request_sequence, test_data_signal_nonce);
}

static java_remote_parent_receive_cursor_t committed(u64 generation) {
    java_remote_parent_receive_cursor_t value = publishing();
    value.state = k_java_remote_parent_receive_cursor_valid;
    value.generation = generation;
    return value;
}

static java_remote_parent_receive_cursor_t
retiring_from(const java_remote_parent_receive_cursor_t *value) {
    return java_remote_parent_receive_cursor_retiring_identity(value);
}

static void reset(void) {
    cursor_cookie = 0;
    memset(&cursor_value, 0, sizeof(cursor_value));
    cursor_present = 0;
    guard_cookie = 0;
    memset(&guard_value, 0, sizeof(guard_value));
    guard_present = 0;
    cursor_update_failure = 0;
    guard_update_failure = 0;
    cursor_delete_failure = 0;
    guard_delete_failure = 0;
    replace_guard_on_delete_failure = 0;
    cursor_update_calls = 0;
    guard_update_calls = 0;
    cursor_delete_calls = 0;
    guard_delete_calls = 0;
    cursor_lookup_calls = 0;
    corrupt_cursor_lookup = 0;
    cursor_update_flags = ~0ULL;
    guard_update_flags = ~0ULL;
}

static void seed_cursor(const java_remote_parent_receive_cursor_t *value) {
    cursor_cookie = test_socket_cookie;
    cursor_value = *value;
    cursor_present = 1;
}

static void seed_guard(const java_remote_parent_receive_cursor_t *value) {
    guard_cookie = test_socket_cookie;
    guard_value = *value;
    guard_present = 1;
}

static void *test_map_lookup(void *map, const void *key) {
    const u64 cookie = *(const u64 *)key;
    if (map == &jrp_recv_cur) {
        if (!cursor_present || cookie != cursor_cookie) {
            return NULL;
        }
        cursor_lookup_calls++;
        if (corrupt_cursor_lookup == cursor_lookup_calls) {
            cursor_value.request_sequence++;
        }
        return &cursor_value;
    }
    if (map == &jrp_recv_guard && guard_present && cookie == guard_cookie) {
        return &guard_value;
    }
    return NULL;
}

static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags) {
    const u64 cookie = *(const u64 *)key;
    if (map == &jrp_recv_cur) {
        cursor_update_calls++;
        cursor_update_flags = flags;
        if (cursor_update_failure ||
            (flags == BPF_NOEXIST && cursor_present && cookie == cursor_cookie) ||
            (flags == BPF_EXIST && (!cursor_present || cookie != cursor_cookie))) {
            return -1;
        }
        cursor_cookie = cookie;
        cursor_value = *(const java_remote_parent_receive_cursor_t *)value;
        cursor_present = 1;
        return 0;
    }
    if (map == &jrp_recv_guard) {
        guard_update_calls++;
        guard_update_flags = flags;
        if (guard_update_failure || flags != BPF_NOEXIST ||
            (guard_present && cookie == guard_cookie)) {
            return -1;
        }
        guard_cookie = cookie;
        guard_value = *(const java_remote_parent_receive_cursor_t *)value;
        guard_present = 1;
        return 0;
    }
    return -1;
}

static long test_map_delete(void *map, const void *key) {
    const u64 cookie = *(const u64 *)key;
    if (map == &jrp_recv_cur) {
        cursor_delete_calls++;
        if (cursor_delete_failure || !cursor_present || cookie != cursor_cookie) {
            return -1;
        }
        cursor_present = 0;
        return 0;
    }
    if (map == &jrp_recv_guard) {
        guard_delete_calls++;
        if (guard_delete_failure || !guard_present || cookie != guard_cookie) {
            if (guard_delete_failure && replace_guard_on_delete_failure && guard_present &&
                cookie == guard_cookie) {
                guard_value.request_sequence++;
            }
            return -1;
        }
        guard_present = 0;
        return 0;
    }
    return -1;
}

static void test_state_predicates_reject_non_authoritative_cursors(void) {
    const java_remote_parent_receive_cursor_t pending = publishing();
    const java_remote_parent_receive_cursor_t valid = committed(73);
    const java_remote_parent_receive_cursor_t retiring = retiring_from(&valid);

    if (sizeof(java_remote_parent_receive_cursor_t) != 56 ||
        offsetof(java_remote_parent_receive_cursor_t, state) != 12 ||
        !java_remote_parent_receive_cursor_is_publishing(&pending) ||
        java_remote_parent_receive_cursor_valid(&pending) ||
        !java_remote_parent_receive_cursor_valid(&valid) ||
        java_remote_parent_receive_cursor_valid(&retiring) ||
        java_remote_parent_receive_cursor_process_matches(
            &pending, &test_process, test_process_incarnation) ||
        java_remote_parent_receive_cursor_process_matches(
            &retiring, &test_process, test_process_incarnation) ||
        !java_remote_parent_receive_cursor_process_matches(
            &valid, &test_process, test_process_incarnation)) {
        fail("PUBLISHING/VALID/RETIRING authority predicates were not state exact");
    }

    java_remote_parent_receive_cursor_t malformed = pending;
    malformed.generation = 1;
    if (java_remote_parent_receive_cursor_state_known(&malformed)) {
        fail("generation-bearing PUBLISHING was accepted");
    }
    malformed = valid;
    malformed.generation = 0;
    if (java_remote_parent_receive_cursor_state_known(&malformed)) {
        fail("generation-zero VALID was accepted");
    }

    java_remote_parent_receive_cursor_t forged_context = pending;
    forged_context.data_signal_nonce++;
    if (!java_remote_parent_receive_cursor_exact_publishing(&pending, &pending) ||
        java_remote_parent_receive_cursor_exact_publishing(&pending, &forged_context) ||
        java_remote_parent_receive_cursor_exact_publishing(&valid, &pending)) {
        fail("forged or stale tail-chain context authorized another PUBLISHING cursor");
    }
}

static void test_absent_start_publishing_is_the_exclusive_lock(void) {
    reset();
    const java_remote_parent_receive_cursor_t pending = publishing();
    if (!java_remote_parent_receive_cursor_start(test_socket_cookie,
                                                 &test_owner,
                                                 test_process_incarnation,
                                                 test_lifecycle_id,
                                                 test_request_sequence,
                                                 test_data_signal_nonce) ||
        !cursor_present || !same_cursor(&cursor_value, &pending) ||
        cursor_update_flags != BPF_NOEXIST || guard_present || guard_update_calls != 0) {
        fail("absent START did not publish its exact generation-zero lock");
    }

    if (java_remote_parent_receive_cursor_start(test_socket_cookie,
                                                &replacement_owner,
                                                test_process_incarnation,
                                                test_lifecycle_id + 1,
                                                test_request_sequence + 1,
                                                test_data_signal_nonce + 1) ||
        java_remote_parent_receive_cursor_guard_acquire(test_socket_cookie, &pending) !=
            k_java_remote_parent_receive_guard_error ||
        guard_update_calls != 0 || !same_cursor(&cursor_value, &pending)) {
        fail("a rival START or guard adopted another owner's PUBLISHING cursor");
    }

    if (!java_remote_parent_receive_cursor_ack_generation(test_socket_cookie, &pending, 73) ||
        !java_remote_parent_receive_cursor_is_valid(&cursor_value) ||
        cursor_value.generation != 73) {
        fail("the exact PUBLISHING owner could not ACK after a rival was rejected");
    }

    reset();
    seed_cursor(&pending);
    if (!java_remote_parent_receive_cursor_mark_retiring_publishing(test_socket_cookie, &pending) ||
        !java_remote_parent_receive_cursor_finish_retiring_publishing(test_socket_cookie,
                                                                      &pending) ||
        cursor_present || guard_present) {
        fail("the exact PUBLISHING owner could not clean up a failed tail chain");
    }
}

static void test_ack_is_exact_and_update_failure_is_fail_closed(void) {
    const java_remote_parent_receive_cursor_t pending = publishing();

    reset();
    seed_cursor(&pending);
    java_remote_parent_receive_cursor_t forged = pending;
    forged.data_signal_nonce++;
    if (java_remote_parent_receive_cursor_ack_generation(test_socket_cookie, &forged, 73) ||
        java_remote_parent_receive_cursor_ack_generation(test_socket_cookie, &pending, 0) ||
        cursor_update_calls != 0 || !same_cursor(&cursor_value, &pending)) {
        fail("ACK accepted a forged identity, nonce, or zero generation");
    }

    cursor_update_failure = 1;
    if (java_remote_parent_receive_cursor_ack_generation(test_socket_cookie, &pending, 73) ||
        !same_cursor(&cursor_value, &pending) || cursor_update_calls != 1 ||
        cursor_update_flags != BPF_EXIST) {
        fail("failed ACK update changed or authorized PUBLISHING");
    }
    cursor_update_failure = 0;
    if (!java_remote_parent_receive_cursor_mark_retiring_publishing(test_socket_cookie, &pending) ||
        !java_remote_parent_receive_cursor_finish_retiring_publishing(test_socket_cookie,
                                                                      &pending) ||
        cursor_present) {
        fail("ACK failure could not converge through exact PUBLISHING cleanup");
    }
}

static void test_publishing_retirement_is_exact_and_fail_closed(void) {
    const java_remote_parent_receive_cursor_t pending = publishing();
    const java_remote_parent_receive_cursor_t retiring = retiring_from(&pending);
    java_remote_parent_receive_cursor_t successor = pending;
    successor.request_sequence++;

    reset();
    seed_cursor(&successor);
    if (java_remote_parent_receive_cursor_mark_retiring_publishing(test_socket_cookie, &pending) ||
        cursor_update_calls != 0 || !same_cursor(&cursor_value, &successor)) {
        fail("PUBLISHING retirement accepted or changed a mismatched successor");
    }

    reset();
    seed_cursor(&pending);
    cursor_update_failure = 1;
    if (java_remote_parent_receive_cursor_mark_retiring_publishing(test_socket_cookie, &pending) ||
        cursor_update_calls != 1 || cursor_update_flags != BPF_EXIST ||
        !same_cursor(&cursor_value, &pending)) {
        fail("PUBLISHING retirement update failure did not preserve its exact cursor");
    }

    reset();
    seed_cursor(&pending);
    corrupt_cursor_lookup = 2;
    if (java_remote_parent_receive_cursor_mark_retiring_publishing(test_socket_cookie, &pending) ||
        cursor_update_calls != 1 || cursor_lookup_calls != 2 ||
        same_cursor(&cursor_value, &retiring)) {
        fail("PUBLISHING retirement accepted a cursor changed during revalidation");
    }
}

static void test_guard_results_distinguish_busy_from_error(void) {
    const java_remote_parent_receive_cursor_t old = committed(73);

    reset();
    seed_cursor(&old);
    if (java_remote_parent_receive_cursor_guard_acquire(test_socket_cookie, &old) !=
            k_java_remote_parent_receive_guard_acquired ||
        !guard_present || !same_cursor(&guard_value, &old) || guard_update_flags != BPF_NOEXIST) {
        fail("exact VALID guard acquisition failed");
    }
    java_remote_parent_receive_cursor_t foreign_guard = old;
    foreign_guard.generation++;
    guard_value = foreign_guard;
    if (java_remote_parent_receive_cursor_guard_acquire(test_socket_cookie, &old) !=
            k_java_remote_parent_receive_guard_busy ||
        java_remote_parent_receive_cursor_guard_release(test_socket_cookie, &old) ||
        !guard_present) {
        fail("foreign exact-cookie guard was not BUSY or was released by a nonowner");
    }

    reset();
    seed_cursor(&old);
    seed_guard(&old);
    guard_delete_failure = 1;
    replace_guard_on_delete_failure = 1;
    if (java_remote_parent_receive_cursor_guard_release(test_socket_cookie, &old) ||
        !guard_present || same_cursor(&guard_value, &old)) {
        fail("guard release accepted a different guard left after delete failure");
    }

    reset();
    seed_cursor(&old);
    guard_update_failure = 1;
    if (java_remote_parent_receive_cursor_guard_acquire(test_socket_cookie, &old) !=
            k_java_remote_parent_receive_guard_error ||
        guard_present) {
        fail("absent-key guard capacity failure was mistaken for BUSY");
    }

    reset();
    java_remote_parent_receive_cursor_t successor = old;
    successor.request_sequence++;
    seed_cursor(&successor);
    if (java_remote_parent_receive_cursor_guard_acquire(test_socket_cookie, &old) !=
            k_java_remote_parent_receive_guard_error ||
        guard_update_calls != 0) {
        fail("mismatched cursor acquired an exact guard");
    }
    seed_guard(&foreign_guard);
    if (java_remote_parent_receive_cursor_guard_acquire(test_socket_cookie, &old) !=
        k_java_remote_parent_receive_guard_busy) {
        fail("mismatched cursor ignored an existing exact-cookie guard");
    }

    reset();
    seed_cursor(&old);
    corrupt_cursor_lookup = 2;
    if (java_remote_parent_receive_cursor_guard_acquire(test_socket_cookie, &old) !=
            k_java_remote_parent_receive_guard_error ||
        guard_present || guard_update_calls != 1 || guard_delete_calls != 1 ||
        cursor_lookup_calls != 2 || same_cursor(&cursor_value, &old)) {
        fail("post-insertion cursor mismatch did not roll back its exact guard");
    }

    reset();
    seed_cursor(&old);
    corrupt_cursor_lookup = 2;
    guard_delete_failure = 1;
    replace_guard_on_delete_failure = 1;
    if (java_remote_parent_receive_cursor_guard_acquire(test_socket_cookie, &old) !=
            k_java_remote_parent_receive_guard_error ||
        !guard_present || same_cursor(&guard_value, &old) || guard_update_calls != 1 ||
        guard_delete_calls != 1 || cursor_lookup_calls != 2) {
        fail("failed post-insertion rollback disturbed a replacement guard or granted authority");
    }
}

static void test_replacement_is_atomic_before_during_and_after_guard(void) {
    const java_remote_parent_receive_cursor_t old = committed(73);
    const java_remote_parent_receive_cursor_t next = publishing_for(&replacement_owner,
                                                                    test_lifecycle_id + 1,
                                                                    test_request_sequence + 1,
                                                                    test_data_signal_nonce + 1);

    reset();
    java_remote_parent_receive_cursor_t successor = old;
    successor.request_sequence++;
    seed_cursor(&successor);
    if (java_remote_parent_receive_cursor_guard_acquire(test_socket_cookie, &old) !=
            k_java_remote_parent_receive_guard_error ||
        java_remote_parent_receive_cursor_replace_locked(test_socket_cookie, &old, &next) ||
        !same_cursor(&cursor_value, &successor)) {
        fail("stale replacement mutated a successor before guard acquisition");
    }

    reset();
    seed_cursor(&old);
    if (java_remote_parent_receive_cursor_guard_acquire(test_socket_cookie, &old) !=
        k_java_remote_parent_receive_guard_acquired) {
        fail("replacement could not acquire predecessor guard");
    }
    cursor_value = successor;
    if (java_remote_parent_receive_cursor_replace_locked(test_socket_cookie, &old, &next) ||
        !java_remote_parent_receive_cursor_guard_release(test_socket_cookie, &old) ||
        !same_cursor(&cursor_value, &successor)) {
        fail("replacement overwrote a cursor changed during its exact guard");
    }

    reset();
    seed_cursor(&old);
    if (java_remote_parent_receive_cursor_guard_acquire(test_socket_cookie, &old) !=
            k_java_remote_parent_receive_guard_acquired ||
        !java_remote_parent_receive_cursor_replace_locked(test_socket_cookie, &old, &next) ||
        !same_cursor(&cursor_value, &next) || cursor_update_flags != BPF_EXIST ||
        !java_remote_parent_receive_cursor_guard_release(test_socket_cookie, &old) ||
        guard_present ||
        java_remote_parent_receive_cursor_guard_acquire(test_socket_cookie, &old) !=
            k_java_remote_parent_receive_guard_error ||
        !java_remote_parent_receive_cursor_ack_generation(test_socket_cookie, &next, 74) ||
        cursor_value.generation != 74 ||
        !java_remote_parent_receive_cursor_is_valid(&cursor_value)) {
        fail("replacement did not transition VALID->PUBLISHING->VALID exactly");
    }
}

static int terminal_valid(const java_remote_parent_receive_cursor_t *expected, int fence_success) {
    const enum java_remote_parent_receive_guard_result result =
        java_remote_parent_receive_cursor_guard_acquire(test_socket_cookie, expected);
    if (result != k_java_remote_parent_receive_guard_acquired) {
        return 0;
    }
    if (!java_remote_parent_receive_cursor_mark_retiring_locked(test_socket_cookie, expected)) {
        return 0;
    }
    if (!fence_success) {
        java_remote_parent_receive_cursor_guard_release(test_socket_cookie, expected);
        return 0;
    }
    return java_remote_parent_receive_cursor_finish_retiring_guarded(test_socket_cookie, expected);
}

static void test_reset_terminal_order_and_faults_are_fail_closed(void) {
    const java_remote_parent_receive_cursor_t old = committed(73);
    const java_remote_parent_receive_cursor_t retiring = retiring_from(&old);

    reset();
    seed_cursor(&old);
    if (!terminal_valid(&old, 1) || cursor_present || guard_present || guard_delete_calls != 1 ||
        cursor_delete_calls != 1) {
        fail("RESET did not delete guard before its RETIRING cursor");
    }

    reset();
    seed_cursor(&old);
    if (terminal_valid(&old, 0) || !cursor_present || !same_cursor(&cursor_value, &retiring) ||
        guard_present || cursor_delete_calls != 0) {
        fail("injected exact-fence failure did not retain a guard-free RETIRING tombstone");
    }

    reset();
    seed_cursor(&old);
    cursor_update_failure = 1;
    if (terminal_valid(&old, 1) || !same_cursor(&cursor_value, &old) || !guard_present ||
        guard_delete_calls != 0 || cursor_delete_calls != 0) {
        fail("RETIRING update failure exposed an already-fenced VALID state");
    }

    reset();
    seed_cursor(&old);
    guard_delete_failure = 1;
    if (terminal_valid(&old, 1) || !same_cursor(&cursor_value, &retiring) || !guard_present ||
        cursor_delete_calls != 0) {
        fail("guard-delete failure did not retain RETIRING before cursor deletion");
    }

    reset();
    seed_cursor(&old);
    cursor_delete_failure = 1;
    if (terminal_valid(&old, 1) || !same_cursor(&cursor_value, &retiring) || guard_present ||
        cursor_delete_calls != 1) {
        fail("cursor-delete failure did not leave a guard-free RETIRING tombstone");
    }
}

static void test_close_repairs_every_state_and_stale_guard(void) {
    const java_remote_parent_receive_cursor_t valid_guard = committed(73);
    const java_remote_parent_receive_cursor_t states[] = {
        publishing(),
        committed(73),
        retiring_from(&(java_remote_parent_receive_cursor_t){
            .owner = test_owner,
            .state = k_java_remote_parent_receive_cursor_valid,
            .process_incarnation = test_process_incarnation,
            .lifecycle_id = test_lifecycle_id,
            .request_sequence = test_request_sequence,
            .data_signal_nonce = test_data_signal_nonce,
            .generation = 73,
        }),
    };

    for (size_t index = 0; index < sizeof(states) / sizeof(states[0]); index++) {
        reset();
        seed_cursor(&states[index]);
        seed_guard(&valid_guard);
        if (!java_remote_parent_receive_cursor_close_delete(test_socket_cookie, &states[index]) ||
            cursor_present || guard_present || guard_delete_calls != 1 ||
            cursor_delete_calls != 1) {
            fail("tcp_close did not repair guard and delete an exact cursor state");
        }
    }

    reset();
    seed_guard(&valid_guard);
    if (!java_remote_parent_receive_cursor_close_stale_guard(test_socket_cookie) || guard_present ||
        cursor_present || guard_delete_calls != 1) {
        fail("absent-cursor close did not limit itself to stale-guard repair");
    }

    reset();
    seed_guard(&valid_guard);
    guard_delete_failure = 1;
    if (java_remote_parent_receive_cursor_close_stale_guard(test_socket_cookie) || !guard_present ||
        guard_delete_calls != 1) {
        fail("failed close guard repair reported success or lost exclusion evidence");
    }

    reset();
    const java_remote_parent_receive_cursor_t valid = committed(73);
    const java_remote_parent_receive_cursor_t retiring = retiring_from(&valid);
    seed_cursor(&valid);
    seed_guard(&valid);
    if (!java_remote_parent_receive_cursor_mark_retiring_close(test_socket_cookie, &valid) ||
        !same_cursor(&cursor_value, &retiring)) {
        fail("tuple/fence failure could not preserve exact RETIRING close evidence");
    }
    if (!java_remote_parent_receive_cursor_close_stale_guard(test_socket_cookie) ||
        !cursor_present || guard_present || cursor_delete_calls != 0) {
        fail("tuple/fence failure deleted RETIRING instead of retaining recovery evidence");
    }
    if (!java_remote_parent_receive_cursor_close_delete(test_socket_cookie, &retiring) ||
        cursor_present || guard_present) {
        fail("later close recovery could not drain retained RETIRING evidence");
    }
}

static void test_cursor_and_guard_capacity_fail_independently_and_recover(void) {
    const java_remote_parent_receive_cursor_t pending = publishing();
    const java_remote_parent_receive_cursor_t valid = committed(73);

    reset();
    cursor_update_failure = 1; // models N occupied cursor slots
    if (java_remote_parent_receive_cursor_publish(test_socket_cookie, &pending) ||
        guard_update_calls != 0 || cursor_present || guard_present) {
        fail("cursor saturation consumed or mutated guard capacity");
    }
    cursor_update_failure = 0;
    if (!java_remote_parent_receive_cursor_publish(test_socket_cookie, &pending)) {
        fail("cursor admission did not recover after cursor capacity returned");
    }

    reset();
    seed_cursor(&valid);
    guard_update_failure = 1; // models N occupied guard slots
    if (java_remote_parent_receive_cursor_guard_acquire(test_socket_cookie, &valid) !=
            k_java_remote_parent_receive_guard_error ||
        cursor_update_calls != 0 || !same_cursor(&cursor_value, &valid)) {
        fail("guard saturation consumed or mutated cursor capacity");
    }
    guard_update_failure = 0;
    if (java_remote_parent_receive_cursor_guard_acquire(test_socket_cookie, &valid) !=
            k_java_remote_parent_receive_guard_acquired ||
        !java_remote_parent_receive_cursor_guard_release(test_socket_cookie, &valid) ||
        guard_present) {
        fail("guard acquisition did not recover after guard capacity returned");
    }
}

static void test_snapshot_and_process_lookup_are_exact(void) {
    reset();
    const java_remote_parent_receive_cursor_t valid = committed(73);
    seed_cursor(&valid);
    java_remote_parent_receive_cursor_t snapshot = {0};
    if (!java_remote_parent_receive_cursor_snapshot_state(test_socket_cookie, &snapshot) ||
        !same_cursor(&snapshot, &valid) || cursor_lookup_calls != 2) {
        fail("state snapshot did not copy and revalidate exact bytes");
    }
    memset(&snapshot, 0, sizeof(snapshot));
    if (!java_remote_parent_receive_cursor_continue(test_socket_cookie,
                                                    &test_process,
                                                    test_process_incarnation,
                                                    test_lifecycle_id,
                                                    test_request_sequence,
                                                    &snapshot) ||
        !same_cursor(&snapshot, &valid)) {
        fail("CONTINUE rejected its exact committed process identity");
    }

    reset();
    seed_cursor(&valid);
    seed_guard(&valid);
    memset(&snapshot, 0, sizeof(snapshot));
    if (java_remote_parent_receive_cursor_continue(test_socket_cookie,
                                                   &test_process,
                                                   test_process_incarnation,
                                                   test_lifecycle_id,
                                                   test_request_sequence,
                                                   &snapshot)) {
        fail("CONTINUE consumed VALID while an exact transition guard was live");
    }

    reset();
    seed_cursor(&valid);
    corrupt_cursor_lookup = 2;
    if (java_remote_parent_receive_cursor_snapshot_state(test_socket_cookie, &snapshot) ||
        same_cursor(&cursor_value, &valid)) {
        fail("snapshot accepted a cursor replaced during revalidation");
    }

    reset();
    const java_remote_parent_receive_cursor_t pending = publishing();
    seed_cursor(&pending);
    if (java_remote_parent_receive_cursor_continue(test_socket_cookie,
                                                   &test_process,
                                                   test_process_incarnation,
                                                   test_lifecycle_id,
                                                   test_request_sequence,
                                                   &snapshot) ||
        java_remote_parent_receive_cursor_reset(test_socket_cookie,
                                                &test_process,
                                                test_process_incarnation,
                                                test_lifecycle_id,
                                                test_request_sequence,
                                                &snapshot)) {
        fail("CONTINUE/RESET adopted an independent PUBLISHING identity");
    }
}

int main(void) {
    test_state_predicates_reject_non_authoritative_cursors();
    test_absent_start_publishing_is_the_exclusive_lock();
    test_ack_is_exact_and_update_failure_is_fail_closed();
    test_publishing_retirement_is_exact_and_fail_closed();
    test_guard_results_distinguish_busy_from_error();
    test_replacement_is_atomic_before_during_and_after_guard();
    test_reset_terminal_order_and_faults_are_fail_closed();
    test_close_repairs_every_state_and_stale_guard();
    test_cursor_and_guard_capacity_fail_independently_and_recover();
    test_snapshot_and_process_lookup_are_exact();
    return 0;
}
