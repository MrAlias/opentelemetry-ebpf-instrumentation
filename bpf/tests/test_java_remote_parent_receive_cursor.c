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

static u64 stored_socket_cookie;
static java_remote_parent_receive_cursor_t stored_cursor;
static int cursor_present;
static int update_failure;
static int evict_on_update;
static int delete_failure;
static int update_calls;
static int delete_calls;
static int lookup_calls;
static int corrupt_on_lookup;
static unsigned long long observed_update_flags;

static void fail(const char *message) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

static int same_cursor(const java_remote_parent_receive_cursor_t *left,
                       const java_remote_parent_receive_cursor_t *right) {
    return memcmp(left, right, sizeof(*left)) == 0;
}

static java_remote_parent_receive_cursor_t
cursor(u64 lifecycle_id, u64 request_sequence, u64 generation) {
    return (java_remote_parent_receive_cursor_t){
        .owner = test_owner,
        .process_incarnation = test_process_incarnation,
        .lifecycle_id = lifecycle_id,
        .request_sequence = request_sequence,
        .data_signal_nonce = test_data_signal_nonce,
        .generation = generation,
    };
}

static void reset(void) {
    stored_socket_cookie = 0;
    memset(&stored_cursor, 0, sizeof(stored_cursor));
    cursor_present = 0;
    update_failure = 0;
    evict_on_update = 0;
    delete_failure = 0;
    update_calls = 0;
    delete_calls = 0;
    lookup_calls = 0;
    corrupt_on_lookup = 0;
    observed_update_flags = ~0ULL;
}

static void seed(const java_remote_parent_receive_cursor_t *value) {
    stored_socket_cookie = test_socket_cookie;
    stored_cursor = *value;
    cursor_present = 1;
}

static void *test_map_lookup(void *map, const void *key) {
    if (map != &java_remote_parent_receive_cursors || !cursor_present ||
        *(const u64 *)key != stored_socket_cookie) {
        return NULL;
    }
    lookup_calls++;
    if (corrupt_on_lookup == lookup_calls) {
        stored_cursor.request_sequence++;
    }
    return &stored_cursor;
}

static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags) {
    if (map != &java_remote_parent_receive_cursors) {
        return -1;
    }
    update_calls++;
    observed_update_flags = flags;
    if (evict_on_update) {
        cursor_present = 0;
        return -1;
    }
    if (update_failure) {
        return -1;
    }
    if (flags == BPF_EXIST && (!cursor_present || *(const u64 *)key != stored_socket_cookie)) {
        return -1;
    }
    stored_socket_cookie = *(const u64 *)key;
    stored_cursor = *(const java_remote_parent_receive_cursor_t *)value;
    cursor_present = 1;
    return 0;
}

static long test_map_delete(void *map, const void *key) {
    if (map != &java_remote_parent_receive_cursors) {
        return -1;
    }
    delete_calls++;
    if (delete_failure || !cursor_present || *(const u64 *)key != stored_socket_cookie) {
        return -1;
    }
    cursor_present = 0;
    return 0;
}

static void test_start_publishes_an_exact_pending_cursor(void) {
    reset();
    const java_remote_parent_receive_cursor_t old = cursor(~0ULL, ~0ULL, 99);
    seed(&old);

    if (!java_remote_parent_receive_cursor_start(test_socket_cookie,
                                                 &test_owner,
                                                 test_process_incarnation,
                                                 1,
                                                 1,
                                                 test_data_signal_nonce) ||
        update_calls != 1 || observed_update_flags != BPF_ANY || !cursor_present ||
        stored_cursor.reserved != 0 || stored_cursor.lifecycle_id != 1 ||
        stored_cursor.request_sequence != 1 || stored_cursor.generation != 0) {
        fail("START did not replace the socket cursor with an exact pending identity");
    }
}

static void test_start_failure_preserves_the_previous_cursor(void) {
    reset();
    const java_remote_parent_receive_cursor_t old = cursor(90, 80, 70);
    seed(&old);
    update_failure = 1;

    if (java_remote_parent_receive_cursor_start(test_socket_cookie,
                                                &test_owner,
                                                test_process_incarnation,
                                                test_lifecycle_id,
                                                test_request_sequence,
                                                test_data_signal_nonce) ||
        update_calls != 1 || !cursor_present || !same_cursor(&stored_cursor, &old)) {
        fail("failed START publication destroyed or changed the previous cursor");
    }
}

static void test_start_revalidates_the_pending_write(void) {
    reset();
    corrupt_on_lookup = 1;

    if (java_remote_parent_receive_cursor_start(test_socket_cookie,
                                                &test_owner,
                                                test_process_incarnation,
                                                test_lifecycle_id,
                                                test_request_sequence,
                                                test_data_signal_nonce) ||
        update_calls != 1 || lookup_calls != 1 || !cursor_present ||
        stored_cursor.request_sequence == test_request_sequence) {
        fail("START accepted a cursor replaced before post-write verification");
    }
}

static void test_start_rejects_incomplete_identities_without_writing(void) {
    reset();
    pid_key_t invalid_owner = test_owner;
    invalid_owner.tid = 0;
    if (java_remote_parent_receive_cursor_start(0,
                                                &test_owner,
                                                test_process_incarnation,
                                                test_lifecycle_id,
                                                test_request_sequence,
                                                test_data_signal_nonce) ||
        java_remote_parent_receive_cursor_start(test_socket_cookie,
                                                NULL,
                                                test_process_incarnation,
                                                test_lifecycle_id,
                                                test_request_sequence,
                                                test_data_signal_nonce) ||
        java_remote_parent_receive_cursor_start(test_socket_cookie,
                                                &test_owner,
                                                0,
                                                test_lifecycle_id,
                                                test_request_sequence,
                                                test_data_signal_nonce) ||
        java_remote_parent_receive_cursor_start(test_socket_cookie,
                                                &test_owner,
                                                test_process_incarnation,
                                                0,
                                                test_request_sequence,
                                                test_data_signal_nonce) ||
        java_remote_parent_receive_cursor_start(test_socket_cookie,
                                                &test_owner,
                                                test_process_incarnation,
                                                test_lifecycle_id,
                                                0,
                                                test_data_signal_nonce) ||
        java_remote_parent_receive_cursor_start(test_socket_cookie,
                                                &test_owner,
                                                test_process_incarnation,
                                                test_lifecycle_id,
                                                test_request_sequence,
                                                0) ||
        java_remote_parent_receive_cursor_start(test_socket_cookie,
                                                &invalid_owner,
                                                test_process_incarnation,
                                                test_lifecycle_id,
                                                test_request_sequence,
                                                test_data_signal_nonce) ||
        update_calls != 0 || cursor_present) {
        fail("START wrote an incomplete cursor identity");
    }

    invalid_owner = test_owner;
    invalid_owner.pid = 0;
    if (java_remote_parent_receive_cursor_start(test_socket_cookie,
                                                &invalid_owner,
                                                test_process_incarnation,
                                                test_lifecycle_id,
                                                test_request_sequence,
                                                test_data_signal_nonce)) {
        fail("START accepted an owner with no process ID");
    }
    invalid_owner = test_owner;
    invalid_owner.ns = 0;
    if (java_remote_parent_receive_cursor_start(test_socket_cookie,
                                                &invalid_owner,
                                                test_process_incarnation,
                                                test_lifecycle_id,
                                                test_request_sequence,
                                                test_data_signal_nonce)) {
        fail("START accepted an owner with no PID namespace");
    }
}

static void test_process_authority_ignores_owner_tid_only(void) {
    const java_remote_parent_receive_cursor_t value =
        cursor(test_lifecycle_id, test_request_sequence, 0);
    if (!java_remote_parent_receive_cursor_process_matches(
            &value, &test_process, test_process_incarnation)) {
        fail("same-process authority rejected a different exact owner TID");
    }

    pid_key_t different = test_process;
    different.pid++;
    different.tid = different.pid;
    if (java_remote_parent_receive_cursor_process_matches(
            &value, &different, test_process_incarnation)) {
        fail("process authority accepted a different PID");
    }
    different = test_process;
    different.ns++;
    if (java_remote_parent_receive_cursor_process_matches(
            &value, &different, test_process_incarnation)) {
        fail("process authority accepted a different PID namespace");
    }
    different = test_process;
    different.tid++;
    if (java_remote_parent_receive_cursor_process_matches(
            &value, &different, test_process_incarnation)) {
        fail("process authority accepted a noncanonical process key");
    }
    if (java_remote_parent_receive_cursor_process_matches(
            &value, &test_process, test_process_incarnation + 1)) {
        fail("process authority accepted a different JVM incarnation");
    }
}

static void test_continue_and_reset_require_exact_opaque_identity(void) {
    reset();
    const java_remote_parent_receive_cursor_t value = cursor(~0ULL, 1, 73);
    seed(&value);
    java_remote_parent_receive_cursor_t snapshot = {0};

    if (!java_remote_parent_receive_cursor_continue(
            test_socket_cookie, &test_process, test_process_incarnation, ~0ULL, 1, &snapshot) ||
        !same_cursor(&snapshot, &value)) {
        fail("CONTINUE rejected an exact opaque lifecycle identity");
    }

    stored_cursor.generation = 0;
    if (!java_remote_parent_receive_cursor_continue(
            test_socket_cookie, &test_process, test_process_incarnation, ~0ULL, 1, &snapshot) ||
        snapshot.generation != 0) {
        fail("identity lookup incorrectly imposed ACK readiness on CONTINUE");
    }
    stored_cursor.generation = value.generation;
    memset(&snapshot, 0, sizeof(snapshot));
    if (!java_remote_parent_receive_cursor_reset(
            test_socket_cookie, &test_process, test_process_incarnation, ~0ULL, 1, &snapshot) ||
        !same_cursor(&snapshot, &value)) {
        fail("RESET rejected an exact opaque lifecycle identity");
    }

    if (java_remote_parent_receive_cursor_continue(
            test_socket_cookie, &test_process, test_process_incarnation, ~0ULL - 1, 1, &snapshot) ||
        java_remote_parent_receive_cursor_continue(
            test_socket_cookie, &test_process, test_process_incarnation, ~0ULL, 2, &snapshot)) {
        fail("CONTINUE inferred ordering instead of requiring opaque equality");
    }

    stored_cursor.reserved = 1;
    if (java_remote_parent_receive_cursor_reset(
            test_socket_cookie, &test_process, test_process_incarnation, ~0ULL, 1, &snapshot)) {
        fail("RESET accepted a cursor with nonzero reserved data");
    }
    stored_cursor.reserved = 0;
    cursor_present = 0;
    if (java_remote_parent_receive_cursor_continue(
            test_socket_cookie, &test_process, test_process_incarnation, ~0ULL, 1, &snapshot)) {
        fail("CONTINUE accepted a missing cursor");
    }
}

static void test_exact_delete_never_removes_a_different_cursor(void) {
    reset();
    const java_remote_parent_receive_cursor_t value =
        cursor(test_lifecycle_id, test_request_sequence, 73);
    seed(&value);
    java_remote_parent_receive_cursor_t mismatches[] = {
        value,
        value,
        value,
        value,
    };
    mismatches[0].lifecycle_id++;
    mismatches[1].request_sequence++;
    mismatches[2].data_signal_nonce++;
    mismatches[3].generation++;
    for (size_t index = 0; index < sizeof(mismatches) / sizeof(mismatches[0]); index++) {
        if (java_remote_parent_receive_cursor_delete_exact(test_socket_cookie,
                                                           &mismatches[index]) ||
            delete_calls != 0 || !cursor_present) {
            fail("exact delete removed a cursor with a different identity");
        }
    }
    if (!java_remote_parent_receive_cursor_delete_exact(test_socket_cookie, &value) ||
        delete_calls != 1 || cursor_present) {
        fail("exact delete did not remove the matching cursor");
    }

    reset();
    seed(&value);
    delete_failure = 1;
    if (java_remote_parent_receive_cursor_delete_exact(test_socket_cookie, &value) ||
        delete_calls != 1 || !cursor_present) {
        fail("exact delete reported success after a failed map deletion");
    }
}

static void test_ack_commits_only_the_exact_pending_generation(void) {
    reset();
    const java_remote_parent_receive_cursor_t pending =
        cursor(test_lifecycle_id, test_request_sequence, 0);
    seed(&pending);

    if (!java_remote_parent_receive_cursor_ack_generation(test_socket_cookie, &pending, 73) ||
        stored_cursor.generation != 73 || lookup_calls != 2 || update_calls != 1 ||
        observed_update_flags != BPF_EXIST) {
        fail("ACK did not commit and revalidate the exact pending generation");
    }

    const java_remote_parent_receive_cursor_t committed = stored_cursor;
    if (java_remote_parent_receive_cursor_ack_generation(test_socket_cookie, &committed, 74) ||
        stored_cursor.generation != 73) {
        fail("ACK replaced a generation that was already committed");
    }

    reset();
    seed(&pending);
    java_remote_parent_receive_cursor_t mismatches[] = {
        pending,
        pending,
        pending,
        pending,
        pending,
    };
    mismatches[0].owner.tid++;
    mismatches[1].process_incarnation++;
    mismatches[2].lifecycle_id++;
    mismatches[3].request_sequence++;
    mismatches[4].data_signal_nonce++;
    for (size_t index = 0; index < sizeof(mismatches) / sizeof(mismatches[0]); index++) {
        if (java_remote_parent_receive_cursor_ack_generation(
                test_socket_cookie, &mismatches[index], 73) ||
            stored_cursor.generation != 0) {
            fail("ACK committed a mismatched pending identity");
        }
    }
    if (java_remote_parent_receive_cursor_ack_generation(test_socket_cookie, &pending, 0) ||
        stored_cursor.generation != 0) {
        fail("ACK committed a mismatched identity or zero generation");
    }

    reset();
    seed(&pending);
    update_failure = 1;
    if (java_remote_parent_receive_cursor_ack_generation(test_socket_cookie, &pending, 73) ||
        stored_cursor.generation != 0 || update_calls != 1 || observed_update_flags != BPF_EXIST) {
        fail("ACK changed a pending cursor after a failed generation update");
    }

    reset();
    seed(&pending);
    evict_on_update = 1;
    if (java_remote_parent_receive_cursor_ack_generation(test_socket_cookie, &pending, 73) ||
        cursor_present || update_calls != 1) {
        fail("ACK accepted a cursor evicted before its generation update");
    }

    reset();
    if (java_remote_parent_receive_cursor_ack_generation(test_socket_cookie, &pending, 73) ||
        update_calls != 0) {
        fail("ACK accepted an already-evicted pending cursor");
    }

    reset();
    seed(&pending);
    corrupt_on_lookup = 2;
    if (java_remote_parent_receive_cursor_ack_generation(test_socket_cookie, &pending, 73) ||
        lookup_calls != 2 || stored_cursor.request_sequence == pending.request_sequence) {
        fail("ACK accepted a cursor replaced before generation revalidation");
    }
}

int main(void) {
    test_start_publishes_an_exact_pending_cursor();
    test_start_failure_preserves_the_previous_cursor();
    test_start_revalidates_the_pending_write();
    test_start_rejects_incomplete_identities_without_writing();
    test_process_authority_ignores_owner_tid_only();
    test_continue_and_reset_require_exact_opaque_identity();
    test_exact_delete_never_removes_a_different_cursor();
    test_ack_commits_only_the_exact_pending_generation();
    return 0;
}
