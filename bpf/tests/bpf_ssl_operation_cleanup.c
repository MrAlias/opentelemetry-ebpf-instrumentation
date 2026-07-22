// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define OBI_TEST_TASK_START_TIME_HELPERS
#include <bpfcore/bpf_helpers.h>

#include <common/ssl_args.h>

#include <generictracer/ssl_write_lifecycle.h>

#include <maps/active_ssl_read_args.h>

enum java_remote_parent_stat {
    k_java_remote_parent_stat_inject_stale = 1,
};

enum operation {
    k_operation_prewrite_cleanup,
    k_operation_owner_cleanup,
    k_operation_write_delete,
    k_operation_read_delete,
    k_operation_shutdown_delete,
    k_operation_thread_delete,
};

static void *test_map_lookup(void *map, const void *key);
static long test_map_delete(void *map, const void *key);

#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_delete_elem test_map_delete

static ssl_args_t test_write_args;
static ssl_args_t test_read_args;
static ssl_shutdown_args_t test_shutdown_args;
static int test_write_present;
static int test_read_present;
static int test_shutdown_present;
static u64 test_id;
static u64 test_thread_start_time;
static u64 test_cleaned_ssl[4];
static int test_owner_cleanup_count;
static int test_prewrite_cleanup_count;
static int test_write_delete_count;
static int test_read_delete_count;
static int test_shutdown_delete_count;
static int test_thread_delete_count;
static enum operation test_operations[12];
static int test_operation_count;

static void record(enum operation operation) {
    if (test_operation_count >= (int)(sizeof(test_operations) / sizeof(test_operations[0]))) {
        fprintf(stderr, "FAIL: operation log overflow\n");
        exit(1);
    }
    test_operations[test_operation_count++] = operation;
}

static u64 task_process_start_time(void) {
    return 77;
}

static void cleanup_ssl_owner(u64 id, u64 ssl, u64 process_start_time) {
    if (id != test_id || process_start_time != 77 ||
        test_owner_cleanup_count >= (int)(sizeof(test_cleaned_ssl) / sizeof(test_cleaned_ssl[0]))) {
        fprintf(stderr, "FAIL: invalid owner cleanup identity\n");
        exit(1);
    }
    test_cleaned_ssl[test_owner_cleanup_count++] = ssl;
    record(k_operation_owner_cleanup);
}

static void cleanup_ssl_args_owner(u64 id, const ssl_args_t *args) {
    if (args) {
        cleanup_ssl_owner(id, args->ssl, task_process_start_time());
    }
}

static void cleanup_unwritten_ssl_prewrite(u64 id,
                                           const ssl_args_t *args,
                                           enum java_remote_parent_stat failure_stat) {
    if (id != test_id || args != &test_write_args ||
        failure_stat != k_java_remote_parent_stat_inject_stale) {
        fprintf(stderr, "FAIL: invalid prewrite cleanup identity\n");
        exit(1);
    }
    test_prewrite_cleanup_count++;
    record(k_operation_prewrite_cleanup);
}

static void delete_pid_tid_connection(u64 id, u64 thread_start_time) {
    if (id != test_id || thread_start_time != test_thread_start_time) {
        fprintf(stderr, "FAIL: invalid thread cleanup identity\n");
        exit(1);
    }
    test_thread_delete_count++;
    record(k_operation_thread_delete);
}

#define OBI_SSL_OPERATION_CLEANUP_CONTEXT
#include <generictracer/ssl_operation_cleanup.h>
#undef OBI_SSL_OPERATION_CLEANUP_CONTEXT

#undef bpf_map_lookup_elem
#undef bpf_map_delete_elem

static void *test_map_lookup(void *map, const void *key) {
    if (map == &active_ssl_read_args) {
        return test_read_present && *(const u64 *)key == test_id ? &test_read_args : NULL;
    }

    const ssl_thread_key_t *thread_key = key;
    if (thread_key->pid_tgid != test_id ||
        thread_key->thread_start_time != test_thread_start_time) {
        return NULL;
    }
    if (map == &active_ssl_write_args && test_write_present) {
        return &test_write_args;
    }
    if (map == &active_ssl_shutdown_args && test_shutdown_present) {
        return &test_shutdown_args;
    }
    return NULL;
}

static long test_map_delete(void *map, const void *key) {
    if (map == &active_ssl_read_args) {
        if (*(const u64 *)key == test_id) {
            test_read_present = 0;
            test_read_delete_count++;
            record(k_operation_read_delete);
        }
        return 0;
    }

    const ssl_thread_key_t *thread_key = key;
    if (thread_key->pid_tgid != test_id ||
        thread_key->thread_start_time != test_thread_start_time) {
        return 0;
    }
    if (map == &active_ssl_write_args) {
        test_write_present = 0;
        test_write_delete_count++;
        record(k_operation_write_delete);
    } else if (map == &active_ssl_shutdown_args) {
        test_shutdown_present = 0;
        test_shutdown_delete_count++;
        record(k_operation_shutdown_delete);
    }
    return 0;
}

static void reset(void) {
    test_write_args = (ssl_args_t){};
    test_read_args = (ssl_args_t){};
    test_shutdown_args = (ssl_shutdown_args_t){};
    test_write_present = 0;
    test_read_present = 0;
    test_shutdown_present = 0;
    test_id = 0x2a00000001ULL;
    test_thread_start_time = 88;
    for (int i = 0; i < 4; i++) {
        test_cleaned_ssl[i] = 0;
    }
    test_owner_cleanup_count = 0;
    test_prewrite_cleanup_count = 0;
    test_write_delete_count = 0;
    test_read_delete_count = 0;
    test_shutdown_delete_count = 0;
    test_thread_delete_count = 0;
    test_operation_count = 0;
}

static void assert_int_eq(int expected, int actual, const char *message) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected %d, got %d\n", message, expected, actual);
        exit(1);
    }
}

static void test_write_replacement_cleanup_is_exact(void) {
    reset();
    const ssl_args_t replaced = {.ssl = 0x1234};

    cleanup_replaced_ssl_write_owner(test_id, k_ssl_wrapper_entry_recover_stale, &replaced, 0x2234);
    assert_int_eq(1, test_owner_cleanup_count, "stale A-to-B replacement cleans A");
    assert_int_eq(0x1234, (int)test_cleaned_ssl[0], "stale replacement cleans the old SSL");

    cleanup_replaced_ssl_write_owner(
        test_id, k_ssl_wrapper_entry_recover_stale, &replaced, replaced.ssl);
    cleanup_replaced_ssl_write_owner(
        test_id, k_ssl_wrapper_entry_replace_tail, &replaced, replaced.ssl);
    assert_int_eq(1,
                  test_owner_cleanup_count,
                  "same-SSL stale and recognized wrapper replacements retain ownership");
}

static void test_unsafe_return_and_failed_start_clean_once(void) {
    reset();
    const ssl_args_t args = {.ssl = 0x1234};

    cleanup_returned_ssl_write_owner(test_id, k_ssl_write_return_outer, &args);
    assert_int_eq(0, test_owner_cleanup_count, "a valid return retains ownership for parsing");
    cleanup_returned_ssl_write_owner(test_id, k_ssl_write_return_unsafe, &args);
    assert_int_eq(1, test_owner_cleanup_count, "an unsafe return cleans ownership exactly once");

    reset();
    cleanup_failed_ssl_write_start(test_id, &args);
    assert_int_eq(1, test_owner_cleanup_count, "a failed active write start cleans ownership");
    assert_int_eq(0x1234, (int)test_cleaned_ssl[0], "failed start cleans its exact SSL");
}

static void test_process_exit_cleans_distinct_operations_in_order(void) {
    reset();
    test_write_args = (ssl_args_t){.ssl = 0x1234, .flags = FLAG_SSL_PREWRITE_PUBLISHED};
    test_read_args = (ssl_args_t){.ssl = 0x2234};
    test_shutdown_args = (ssl_shutdown_args_t){.ssl = 0x3234};
    test_write_present = 1;
    test_read_present = 1;
    test_shutdown_present = 1;

    cleanup_exited_ssl_operations(test_id, test_thread_start_time);

    assert_int_eq(1, test_prewrite_cleanup_count, "exit retires a published prewrite");
    assert_int_eq(3, test_owner_cleanup_count, "exit cleans every distinct SSL owner");
    assert_int_eq(0x1234, (int)test_cleaned_ssl[0], "write owner is cleaned first");
    assert_int_eq(0x2234, (int)test_cleaned_ssl[1], "read owner is cleaned second");
    assert_int_eq(0x3234, (int)test_cleaned_ssl[2], "shutdown owner is cleaned third");
    assert_int_eq(1, test_write_delete_count, "exit removes active write arguments");
    assert_int_eq(1, test_read_delete_count, "exit removes active read arguments");
    assert_int_eq(1, test_shutdown_delete_count, "exit removes active shutdown arguments");
    assert_int_eq(1, test_thread_delete_count, "exit removes the thread connection hint");
    assert_int_eq(k_operation_prewrite_cleanup,
                  test_operations[0],
                  "prewrite is retired before active write deletion");
    assert_int_eq(k_operation_write_delete,
                  test_operations[2],
                  "active write deletion follows owner cleanup");
}

static void test_process_exit_deduplicates_same_ssl_owner(void) {
    reset();
    test_write_args.ssl = 0x1234;
    test_read_args.ssl = 0x1234;
    test_shutdown_args.ssl = 0x1234;
    test_write_present = 1;
    test_read_present = 1;
    test_shutdown_present = 1;

    cleanup_exited_ssl_operations(test_id, test_thread_start_time);

    assert_int_eq(1, test_owner_cleanup_count, "same-SSL exit cleans ownership exactly once");
    assert_int_eq(1, test_write_delete_count, "same-SSL exit removes write arguments");
    assert_int_eq(1, test_read_delete_count, "same-SSL exit removes read arguments");
    assert_int_eq(1, test_shutdown_delete_count, "same-SSL exit removes shutdown arguments");
}

static void test_process_exit_cleans_read_without_thread_generation(void) {
    reset();
    test_read_args.ssl = 0x2234;
    test_read_present = 1;

    cleanup_exited_ssl_operations(test_id, 0);

    assert_int_eq(1, test_owner_cleanup_count, "exit cleans a readable process-scoped owner");
    assert_int_eq(1, test_read_delete_count, "exit removes readable active arguments");
    assert_int_eq(0, test_write_delete_count, "missing generation does not touch write keys");
    assert_int_eq(0, test_thread_delete_count, "missing generation does not delete thread hints");
}

int main(void) {
    test_write_replacement_cleanup_is_exact();
    test_unsafe_return_and_failed_start_clean_once();
    test_process_exit_cleans_distinct_operations_in_order();
    test_process_exit_deduplicates_same_ssl_owner();
    test_process_exit_cleans_read_without_thread_generation();
    return 0;
}
