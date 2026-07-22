// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OBI_TEST_TASK_START_TIME_HELPERS
#include <bpfcore/bpf_helpers.h>
#include <common/connection_info.h>
#include <common/protocol_defs.h>
#include <common/ssl_args.h>

enum { BPF_ANY = 0, BPF_NOEXIST = 1, BPF_EXIST = 2 };

struct bpf_test_map {
    int id;
};

static struct bpf_test_map active_ssl_read_args = {.id = 1};
static struct bpf_test_map ssl_to_pid_tid = {.id = 2};

static void *test_map_lookup(void *map, const void *key);
static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags);
static long test_map_delete(void *map, const void *key);
static long test_probe_read_user(void *dst, unsigned int size, const void *src);

#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update
#define bpf_map_delete_elem test_map_delete
#define bpf_probe_read_user test_probe_read_user

static ssl_args_t test_args;
static int test_args_available;
static int test_active_delete_count;
static int test_pid_tid_delete_count;
static ssl_pid_key_t test_deleted_key;
static ssl_pid_key_t test_owner_keys[2];
static ssl_thread_key_t test_owners[2];
static int test_owner_present[2];
static int test_active_update_count;
static int test_owner_update_count;
static int test_fail_active_update;
static int test_fail_active_restore;
static int test_fail_owner_update;
static int test_operation_sequence;
static int test_owner_update_sequence;
static int test_owner_delete_sequence;
static int test_handle_count;
static ssl_args_t test_handled_args;
static int test_handled_length;
static u8 test_handled_direction;

static u64 task_process_start_time(void) {
    return 77;
}

static ssl_pid_key_t ssl_pid_key(u64 ssl, u32 pid, u64 process_start_time) {
    return (ssl_pid_key_t){
        .ssl = ssl,
        .pid = pid,
        .process_start_time = process_start_time,
    };
}

static void handle_ssl_buf(void *ctx, u64 id, ssl_args_t *args, int length, u8 direction) {
    (void)ctx;
    (void)id;
    test_handle_count++;
    test_handled_args = *args;
    test_handled_length = length;
    test_handled_direction = direction;
}

#define OBI_SSL_READ_CONTEXT
#include <generictracer/ssl_read.h>
#undef OBI_SSL_READ_CONTEXT

#undef bpf_map_lookup_elem
#undef bpf_map_update_elem
#undef bpf_map_delete_elem
#undef bpf_probe_read_user

static void *test_map_lookup(void *map, const void *key) {
    if (map == &active_ssl_read_args && test_args_available) {
        return &test_args;
    }
    if (map == &ssl_to_pid_tid) {
        for (int i = 0; i < 2; i++) {
            if (test_owner_present[i] &&
                memcmp(key, &test_owner_keys[i], sizeof(test_owner_keys[i])) == 0) {
                return &test_owners[i];
            }
        }
    }
    return NULL;
}

static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags) {
    if (map == &active_ssl_read_args) {
        test_active_update_count++;
        if (test_fail_active_update || (test_fail_active_restore && test_active_update_count > 1)) {
            return -1;
        }
        test_args = *(const ssl_args_t *)value;
        test_args_available = 1;
        return 0;
    }
    if (map == &ssl_to_pid_tid) {
        test_owner_update_count++;
        test_owner_update_sequence = ++test_operation_sequence;
        if (test_fail_owner_update) {
            return -1;
        }
        for (int i = 0; i < 2; i++) {
            if (test_owner_present[i] &&
                memcmp(key, &test_owner_keys[i], sizeof(test_owner_keys[i])) == 0) {
                return flags == BPF_NOEXIST ? -1 : 0;
            }
        }
        for (int i = 0; i < 2; i++) {
            if (!test_owner_present[i]) {
                test_owner_keys[i] = *(const ssl_pid_key_t *)key;
                test_owners[i] = *(const ssl_thread_key_t *)value;
                test_owner_present[i] = 1;
                return 0;
            }
        }
        return -1;
    }
    return 0;
}

static long test_map_delete(void *map, const void *key) {
    if (map == &active_ssl_read_args) {
        test_active_delete_count++;
        test_args = (ssl_args_t){};
        test_args_available = 0;
    } else if (map == &ssl_to_pid_tid) {
        test_pid_tid_delete_count++;
        test_deleted_key = *(const ssl_pid_key_t *)key;
        test_owner_delete_sequence = ++test_operation_sequence;
        for (int i = 0; i < 2; i++) {
            if (test_owner_present[i] &&
                memcmp(key, &test_owner_keys[i], sizeof(test_owner_keys[i])) == 0) {
                test_owner_present[i] = 0;
            }
        }
    }
    return 0;
}

static long test_probe_read_user(void *dst, unsigned int size, const void *src) {
    memcpy(dst, src, size);
    return 0;
}

static void reset(void) {
    test_args = (ssl_args_t){
        .ssl = 0x1234,
        .buf = 0x5678,
    };
    test_args_available = 1;
    test_active_delete_count = 0;
    test_pid_tid_delete_count = 0;
    test_deleted_key = (ssl_pid_key_t){};
    memset(test_owner_keys, 0, sizeof(test_owner_keys));
    memset(test_owners, 0, sizeof(test_owners));
    memset(test_owner_present, 0, sizeof(test_owner_present));
    test_active_update_count = 0;
    test_owner_update_count = 0;
    test_fail_active_update = 0;
    test_fail_active_restore = 0;
    test_fail_owner_update = 0;
    test_operation_sequence = 0;
    test_owner_update_sequence = 0;
    test_owner_delete_sequence = 0;
    test_handle_count = 0;
    test_handled_args = (ssl_args_t){};
    test_handled_length = 0;
    test_handled_direction = 0;
}

static void seed_owner(int slot, u64 ssl, u64 pid_tgid, u64 thread_start_time) {
    test_owner_keys[slot] = ssl_pid_key(ssl, 42, 77);
    test_owners[slot] = ssl_thread_key(pid_tgid, thread_start_time);
    test_owner_present[slot] = 1;
}

static int owner_present(u64 ssl) {
    const ssl_pid_key_t key = ssl_pid_key(ssl, 42, 77);
    return test_map_lookup(&ssl_to_pid_tid, &key) != NULL;
}

static void assert_int_eq(int expected, int actual, const char *message) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected %d, got %d\n", message, expected, actual);
        exit(1);
    }
}

static void test_read_copies_args_before_delete(void) {
    reset();

    handle_ssl_read_result(NULL, 0x2a00000001ULL, 32);

    assert_int_eq(1, test_active_delete_count, "read args are deleted");
    assert_int_eq(1, test_handle_count, "successful read is handled");
    assert_int_eq(0x1234, (int)test_handled_args.ssl, "read retains SSL after map deletion");
    assert_int_eq(0x5678, (int)test_handled_args.buf, "read retains buffer after map deletion");
    assert_int_eq(32, test_handled_length, "read retains result length");
    assert_int_eq(TCP_RECV, test_handled_direction, "read remains inbound");
}

static void test_read_ex_copies_args_before_delete(void) {
    reset();
    size_t read_len = 64;
    test_args.len_ptr = (u64)&read_len;

    handle_ssl_read_ex_result(NULL, 0x2a00000001ULL, 1);

    assert_int_eq(1, test_active_delete_count, "read_ex args are deleted");
    assert_int_eq(1, test_handle_count, "successful read_ex is handled");
    assert_int_eq(0x1234, (int)test_handled_args.ssl, "read_ex retains SSL after deletion");
    assert_int_eq(64, test_handled_length, "read_ex retains reported length");
}

static void test_failed_read_ex_cleans_process_scoped_thread_key(void) {
    reset();

    handle_ssl_read_ex_result(NULL, 0x2a00000001ULL, 0);

    assert_int_eq(1, test_active_delete_count, "failed read_ex args are deleted");
    assert_int_eq(1, test_pid_tid_delete_count, "failed read_ex thread key is deleted");
    assert_int_eq(42, (int)test_deleted_key.pid, "failed read_ex cleanup is process scoped");
    assert_int_eq(0x1234, (int)test_deleted_key.ssl, "failed read_ex cleanup uses its SSL");
    assert_int_eq(0, test_handle_count, "failed read_ex is not parsed");
}

static void test_read_publication_failure_preserves_previous_state(void) {
    reset();
    seed_owner(0, test_args.ssl, 0x2a00000002ULL, 66);
    const ssl_args_t next = {.ssl = 0x2234, .buf = 0x6678};
    test_fail_active_update = 1;

    assert_int_eq(-1,
                  publish_ssl_read_args(0x2a00000001ULL, 77, 88, &next),
                  "a failed active update rejects the new read");
    assert_int_eq(0x1234, (int)test_args.ssl, "the previous active read is preserved");
    assert_int_eq(1, owner_present(0x1234), "the previous owner is preserved");
    assert_int_eq(0, owner_present(0x2234), "no new owner is published");
    assert_int_eq(0, test_pid_tid_delete_count, "the previous owner is not deleted");
}

static void test_owner_failure_rolls_back_previous_active_read(void) {
    reset();
    seed_owner(0, test_args.ssl, 0x2a00000002ULL, 66);
    const ssl_args_t next = {.ssl = 0x2234, .buf = 0x6678};
    test_fail_owner_update = 1;

    assert_int_eq(-1,
                  publish_ssl_read_args(0x2a00000001ULL, 77, 88, &next),
                  "a failed owner update rejects the new read");
    assert_int_eq(0x1234, (int)test_args.ssl, "owner failure restores the previous active read");
    assert_int_eq(2, test_active_update_count, "owner failure performs one exact rollback");
    assert_int_eq(1, owner_present(0x1234), "owner failure preserves the previous owner");
    assert_int_eq(0, owner_present(0x2234), "owner failure leaves no new owner");
    assert_int_eq(0, test_pid_tid_delete_count, "owner failure does not retire old ownership");
}

static void test_failed_active_rollback_retires_unrecoverable_owner(void) {
    reset();
    seed_owner(0, test_args.ssl, 0x2a00000002ULL, 66);
    const ssl_args_t next = {.ssl = 0x2234, .buf = 0x6678};
    test_fail_owner_update = 1;
    test_fail_active_restore = 1;

    assert_int_eq(-1,
                  publish_ssl_read_args(0x2a00000001ULL, 77, 88, &next),
                  "a failed rollback rejects the new read");
    assert_int_eq(0, test_args_available, "failed rollback removes ambiguous active state");
    assert_int_eq(1, test_active_delete_count, "failed rollback fails closed exactly once");
    assert_int_eq(0, owner_present(0x1234), "failed rollback retires the unrecoverable owner");
    assert_int_eq(0, owner_present(0x2234), "failed rollback leaves no new owner");
    assert_int_eq(1, test_pid_tid_delete_count, "failed rollback deletes the old owner once");
    assert_int_eq(0x1234, (int)test_deleted_key.ssl, "failed rollback deletes the old SSL key");
}

static void test_owner_failure_without_previous_read_removes_new_active_state(void) {
    reset();
    test_args_available = 0;
    const ssl_args_t next = {.ssl = 0x2234, .buf = 0x6678};
    test_fail_owner_update = 1;

    assert_int_eq(-1,
                  publish_ssl_read_args(0x2a00000001ULL, 77, 88, &next),
                  "owner failure rejects an unowned read");
    assert_int_eq(0, test_args_available, "the unowned active read is rolled back");
    assert_int_eq(1, test_active_delete_count, "rollback removes the new active read");
    assert_int_eq(0, owner_present(0x2234), "rollback leaves no owner");
}

static void test_distinct_ssl_replacement_publishes_before_retiring_old_owner(void) {
    reset();
    seed_owner(0, test_args.ssl, 0x2a00000002ULL, 66);
    const ssl_args_t next = {.ssl = 0x2234, .buf = 0x6678};

    assert_int_eq(0,
                  publish_ssl_read_args(0x2a00000001ULL, 77, 88, &next),
                  "a fully owned replacement succeeds");
    assert_int_eq(0x2234, (int)test_args.ssl, "the new read becomes active");
    assert_int_eq(0, owner_present(0x1234), "the previous SSL owner is retired");
    assert_int_eq(1, owner_present(0x2234), "the new SSL owner is published");
    assert_int_eq(1, test_pid_tid_delete_count, "the previous owner is deleted exactly once");
    assert_int_eq(1, test_owner_update_count, "the new owner is inserted exactly once");
    assert_int_eq(1,
                  test_owner_update_sequence < test_owner_delete_sequence,
                  "new ownership is established before old ownership is retired");
}

static void test_same_ssl_replacement_preserves_original_owner(void) {
    reset();
    seed_owner(0, test_args.ssl, 0x2a00000002ULL, 66);
    const ssl_args_t next = {.ssl = 0x1234, .buf = 0x6678};

    assert_int_eq(0,
                  publish_ssl_read_args(0x2a00000001ULL, 77, 88, &next),
                  "a same-SSL replacement succeeds");
    assert_int_eq(0x6678, (int)test_args.buf, "the active arguments are refreshed");
    assert_int_eq(1, owner_present(0x1234), "the original SSL owner remains present");
    assert_int_eq(0, test_owner_update_count, "the original owner is not overwritten");
    assert_int_eq(0, test_pid_tid_delete_count, "the original owner is not deleted");
    assert_int_eq(
        66, (int)test_owners[0].thread_start_time, "the original thread generation is unchanged");
}

static void test_existing_new_owner_is_preserved_before_old_owner_retires(void) {
    reset();
    seed_owner(0, test_args.ssl, 0x2a00000002ULL, 66);
    seed_owner(1, 0x2234, 0x2a00000003ULL, 55);
    const ssl_args_t next = {.ssl = 0x2234, .buf = 0x6678};

    assert_int_eq(0,
                  publish_ssl_read_args(0x2a00000001ULL, 77, 88, &next),
                  "a pre-owned SSL can replace the active read");
    assert_int_eq(0, owner_present(0x1234), "the old SSL owner is retired");
    assert_int_eq(1, owner_present(0x2234), "the existing new owner is retained");
    assert_int_eq(0, test_owner_update_count, "the existing new owner is not overwritten");
    assert_int_eq(55,
                  (int)test_owners[1].thread_start_time,
                  "the existing new owner keeps its thread generation");
}

int main(void) {
    test_read_copies_args_before_delete();
    test_read_ex_copies_args_before_delete();
    test_failed_read_ex_cleans_process_scoped_thread_key();
    test_read_publication_failure_preserves_previous_state();
    test_owner_failure_rolls_back_previous_active_read();
    test_failed_active_rollback_retires_unrecoverable_owner();
    test_owner_failure_without_previous_read_removes_new_active_state();
    test_distinct_ssl_replacement_publishes_before_retiring_old_owner();
    test_same_ssl_replacement_preserves_original_owner();
    test_existing_new_owner_is_preserved_before_old_owner_retires();
    return 0;
}
