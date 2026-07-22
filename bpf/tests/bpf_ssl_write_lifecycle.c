// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>

struct bpf_test_map {
    int id;
};

static void *test_map_lookup(void *map, const void *key);
static long test_map_delete(void *map, const void *key);

#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_delete_elem test_map_delete

#include <generictracer/ssl_write_lifecycle.h>

#undef bpf_map_lookup_elem
#undef bpf_map_delete_elem

static ssl_args_t test_write;
static ssl_shutdown_args_t test_shutdown;
static int test_write_present;
static int test_shutdown_present;
static int test_write_delete_count;
static int test_shutdown_delete_count;
static u64 test_id;
static u64 test_thread_start_time;

static void assert_int_eq(int expected, int actual, const char *message) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected %d, got %d\n", message, expected, actual);
        exit(1);
    }
}

static void *test_map_lookup(void *map, const void *key) {
    const ssl_thread_key_t *thread_key = key;
    if (thread_key->pid_tgid != test_id ||
        thread_key->thread_start_time != test_thread_start_time) {
        return NULL;
    }
    if (map == &active_ssl_write_args && test_write_present) {
        return &test_write;
    }
    if (map == &active_ssl_shutdown_args && test_shutdown_present) {
        return &test_shutdown;
    }
    return NULL;
}

static long test_map_delete(void *map, const void *key) {
    const ssl_thread_key_t *thread_key = key;
    if (thread_key->pid_tgid != test_id ||
        thread_key->thread_start_time != test_thread_start_time) {
        return 0;
    }
    if (map == &active_ssl_write_args) {
        test_write_present = 0;
        test_write_delete_count++;
    } else if (map == &active_ssl_shutdown_args) {
        test_shutdown_present = 0;
        test_shutdown_delete_count++;
    }
    return 0;
}

static void reset(void) {
    test_write = (ssl_args_t){};
    test_shutdown = (ssl_shutdown_args_t){};
    test_write_present = 0;
    test_shutdown_present = 0;
    test_write_delete_count = 0;
    test_shutdown_delete_count = 0;
    test_id = 0x2a00000001ULL;
    test_thread_start_time = 88;
}

static void seed_write(enum ssl_write_api api, u32 depth) {
    test_write = (ssl_args_t){
        .ssl = 0x1234,
        .buf = 0x5678,
        .flags = FLAG_SSL_PREWRITE_PUBLISHED,
        .handoff_id = 100,
        .requested_len = 64,
        .stack_pointer = 0x10000,
        .depth = depth,
        .write_api = api,
    };
    test_write_present = 1;
}

static void seed_shutdown(enum ssl_shutdown_api api, u32 depth) {
    test_shutdown = (ssl_shutdown_args_t){
        .ssl = 0x1234,
        .stack_pointer = 0x10000,
        .depth = depth,
        .api = api,
    };
    test_shutdown_present = 1;
}

static void test_normal_outer_write_return(void) {
    reset();
    seed_write(k_ssl_write_api_write, 1);
    ssl_args_t saved = {};

    assert_int_eq(
        k_ssl_write_return_outer,
        take_ssl_write_args(test_id, test_thread_start_time, k_ssl_write_api_write, &saved),
        "the matching outer write return is consumed");
    assert_int_eq(1, test_write_delete_count, "the completed outer write is deleted");
    assert_int_eq(0x1234, (int)saved.ssl, "the completed write arguments are returned");
}

static void test_approved_nested_write_returns_in_order(void) {
    reset();
    seed_write(k_ssl_write_api_write_ex, 2);
    test_write.nested_write_api = k_ssl_write_api_write_ex2;
    ssl_args_t saved = {};

    assert_int_eq(
        k_ssl_write_return_nested,
        take_ssl_write_args(test_id, test_thread_start_time, k_ssl_write_api_write_ex2, &saved),
        "the exact inner wrapper return is consumed first");
    assert_int_eq(1, (int)test_write.depth, "the inner return restores outer depth");
    assert_int_eq(
        0, (int)test_write.nested_write_api, "the consumed inner API identity is cleared");
    assert_int_eq(0, test_write_delete_count, "the inner return retains outer arguments");

    assert_int_eq(
        k_ssl_write_return_outer,
        take_ssl_write_args(test_id, test_thread_start_time, k_ssl_write_api_write_ex, &saved),
        "the exact outer wrapper return completes the write");
    assert_int_eq(1, test_write_delete_count, "the outer return deletes active arguments");
}

static void test_missed_inner_return_fails_closed(void) {
    reset();
    seed_write(k_ssl_write_api_write_ex, 2);
    test_write.nested_write_api = k_ssl_write_api_write_ex2;
    ssl_args_t saved = {};

    assert_int_eq(
        k_ssl_write_return_unsafe,
        take_ssl_write_args(test_id, test_thread_start_time, k_ssl_write_api_write_ex, &saved),
        "an outer return cannot consume an unreturned inner wrapper");
    assert_int_eq(1, test_write_delete_count, "unsafe nested state is deleted");
    assert_int_eq(FLAG_SSL_PREWRITE_PUBLISHED,
                  (int)(saved.flags & FLAG_SSL_PREWRITE_PUBLISHED),
                  "unsafe return preserves the published handoff for caller cleanup");
}

static void test_wrong_and_explicitly_unsafe_write_returns_fail_closed(void) {
    reset();
    seed_write(k_ssl_write_api_write, 1);
    ssl_args_t saved = {};
    assert_int_eq(
        k_ssl_write_return_unsafe,
        take_ssl_write_args(test_id, test_thread_start_time, k_ssl_write_api_write_ex, &saved),
        "another write API cannot consume active arguments");
    assert_int_eq(1, test_write_delete_count, "wrong-API state is deleted");

    reset();
    seed_write(k_ssl_write_api_write, 1);
    test_write.unsafe_nested_write = 1;
    assert_int_eq(
        k_ssl_write_return_unsafe,
        take_ssl_write_args(test_id, test_thread_start_time, k_ssl_write_api_write, &saved),
        "an explicitly unsafe nested write cannot complete");
    assert_int_eq(1, test_write_delete_count, "unsafe state is deleted once");
}

static void test_crypto_native_write_wrapper_uses_distinct_return_identity(void) {
    reset();
    seed_write(k_ssl_write_api_crypto_native, 2);
    test_write.nested_write_api = k_ssl_write_api_write;
    ssl_args_t saved = {};

    assert_int_eq(
        k_ssl_write_return_nested,
        take_ssl_write_args(test_id, test_thread_start_time, k_ssl_write_api_write, &saved),
        "the native wrapper's inner SSL_write return is consumed");
    assert_int_eq(
        k_ssl_write_return_outer,
        take_ssl_write_args(test_id, test_thread_start_time, k_ssl_write_api_crypto_native, &saved),
        "the dedicated native return completes the wrapper");
    assert_int_eq(1, test_write_delete_count, "the native wrapper deletes state once");
}

static void test_shutdown_wrapper_return_identity(void) {
    reset();
    seed_shutdown(k_ssl_shutdown_api_crypto_native, 2);
    test_shutdown.nested_api = k_ssl_shutdown_api_shutdown;
    ssl_shutdown_args_t saved = {};

    assert_int_eq(k_ssl_write_return_nested,
                  take_ssl_shutdown_args(
                      test_id, test_thread_start_time, k_ssl_shutdown_api_shutdown, &saved),
                  "the native shutdown wrapper consumes its inner return");
    assert_int_eq(k_ssl_write_return_outer,
                  take_ssl_shutdown_args(
                      test_id, test_thread_start_time, k_ssl_shutdown_api_crypto_native, &saved),
                  "the dedicated native shutdown return completes the wrapper");
    assert_int_eq(1, test_shutdown_delete_count, "shutdown state is deleted once");

    reset();
    seed_shutdown(k_ssl_shutdown_api_shutdown, 1);
    assert_int_eq(k_ssl_write_return_unsafe,
                  take_ssl_shutdown_args(
                      test_id, test_thread_start_time, k_ssl_shutdown_api_crypto_native, &saved),
                  "another shutdown API cannot consume active state");
    assert_int_eq(1, test_shutdown_delete_count, "wrong shutdown state is deleted");
}

static void test_stale_write_recovery_requires_age_and_unwound_stack(void) {
    reset();
    seed_write(k_ssl_write_api_write, 1);

    assert_int_eq(0,
                  ssl_write_args_recoverable(&test_write, 0x10000, 120, 20),
                  "a write at the exact TTL boundary remains live");
    assert_int_eq(1,
                  ssl_write_args_recoverable(&test_write, 0x10000, 121, 20),
                  "an expired write at the same stack depth is recoverable");
    assert_int_eq(1,
                  ssl_write_args_recoverable(&test_write, 0x10100, 121, 20),
                  "an expired write with an unwound stack is recoverable");
    assert_int_eq(0,
                  ssl_write_args_recoverable(&test_write, 0x0f000, 121, 20),
                  "a deeper nested stack cannot replace the active write");
    assert_int_eq(0,
                  ssl_write_args_recoverable(&test_write, 0x10000, 99, 20),
                  "a clock rollback cannot expire active state");
}

static void test_thread_generation_prevents_pid_tgid_reuse(void) {
    reset();
    seed_write(k_ssl_write_api_write_ex, 1);
    ssl_args_t saved = {};

    assert_int_eq(
        k_ssl_write_return_missing,
        take_ssl_write_args(test_id, test_thread_start_time + 1, k_ssl_write_api_write_ex2, &saved),
        "a reused pid_tgid cannot consume an older write generation");
    assert_int_eq(1, test_write_present, "the older generation remains isolated");

    seed_shutdown(k_ssl_shutdown_api_shutdown, 1);
    ssl_shutdown_args_t shutdown_saved = {};
    assert_int_eq(
        k_ssl_write_return_missing,
        take_ssl_shutdown_args(
            test_id, test_thread_start_time + 1, k_ssl_shutdown_api_crypto_native, &shutdown_saved),
        "a reused pid_tgid cannot consume an older shutdown generation");
    assert_int_eq(1, test_shutdown_present, "the older shutdown generation remains isolated");
}

static void test_wrapper_transitions_accept_tail_calls_and_bound_stack_growth(void) {
    assert_int_eq(1,
                  ssl_write_wrapper_transition(k_ssl_write_api_write_ex, k_ssl_write_api_write_ex2),
                  "SSL_write_ex may wrap SSL_write_ex2");
    assert_int_eq(
        1,
        ssl_write_wrapper_transition(k_ssl_write_api_crypto_native, k_ssl_write_api_write),
        "CryptoNative_SslWrite may wrap SSL_write");
    assert_int_eq(0,
                  ssl_write_wrapper_transition(k_ssl_write_api_write, k_ssl_write_api_write_ex),
                  "unapproved write APIs are not wrappers");
    assert_int_eq(1,
                  ssl_shutdown_wrapper_transition(k_ssl_shutdown_api_crypto_native,
                                                  k_ssl_shutdown_api_shutdown),
                  "CryptoNative_SslShutdown may wrap SSL_shutdown");

    assert_int_eq(1,
                  ssl_wrapper_stack_matches(0x10000, 0x10000),
                  "an optimized tail-call wrapper may keep the same stack pointer");
    assert_int_eq(1,
                  ssl_wrapper_stack_matches(0x10000, 0x0f000),
                  "a nested wrapper may grow the stack downward");
    assert_int_eq(0,
                  ssl_wrapper_stack_matches(0x10000, 0x20000),
                  "a return-unwound stack is not a nested wrapper");
    assert_int_eq(0,
                  ssl_wrapper_stack_matches(0x20000, 0x0ffff),
                  "unbounded stack movement is not a wrapper");

    ssl_args_t write = {
        .ssl = 0x1234,
        .buf = 0x5678,
        .len_ptr = 0x9abc,
        .requested_len = 64,
        .stack_pointer = 0x10000,
        .write_api = k_ssl_write_api_write_ex,
    };
    assert_int_eq(1,
                  ssl_write_wrapper_matches(&write,
                                            write.ssl,
                                            write.buf,
                                            write.len_ptr,
                                            write.requested_len,
                                            0,
                                            k_ssl_write_api_write_ex2,
                                            write.stack_pointer),
                  "an exact tail-call write wrapper is accepted at entry");
    assert_int_eq(0,
                  ssl_write_wrapper_matches(&write,
                                            write.ssl,
                                            write.buf + 1,
                                            write.len_ptr,
                                            write.requested_len,
                                            0,
                                            k_ssl_write_api_write_ex2,
                                            write.stack_pointer),
                  "a tail-call wrapper with different arguments is rejected");

    ssl_shutdown_args_t shutdown = {
        .ssl = 0x1234,
        .stack_pointer = 0x10000,
        .api = k_ssl_shutdown_api_crypto_native,
    };
    assert_int_eq(1,
                  ssl_shutdown_wrapper_matches(
                      &shutdown, shutdown.ssl, k_ssl_shutdown_api_shutdown, shutdown.stack_pointer),
                  "an exact tail-call shutdown wrapper is accepted at entry");

    write.flags = FLAG_SSL_PREWRITE_PUBLISHED;
    write.handoff_id = 100;
    assert_int_eq(k_ssl_wrapper_entry_replace_tail,
                  ssl_write_wrapper_entry_action(&write,
                                                 write.ssl,
                                                 write.buf,
                                                 write.len_ptr,
                                                 write.requested_len,
                                                 0,
                                                 k_ssl_write_api_write_ex2,
                                                 write.stack_pointer,
                                                 110,
                                                 20),
                  "an equal-stack wrapper replaces rather than reuses its handoff");
    assert_int_eq(k_ssl_wrapper_entry_replace_tail,
                  ssl_write_wrapper_entry_action(&write,
                                                 write.ssl,
                                                 write.buf,
                                                 write.len_ptr,
                                                 write.requested_len,
                                                 0,
                                                 k_ssl_write_api_write_ex2,
                                                 write.stack_pointer - 64,
                                                 110,
                                                 20),
                  "a deeper approved entry also replaces an ambiguous prior invocation");
    assert_int_eq(k_ssl_wrapper_entry_recover_stale,
                  ssl_write_wrapper_entry_action(&write,
                                                 write.ssl,
                                                 write.buf,
                                                 write.len_ptr,
                                                 write.requested_len,
                                                 0,
                                                 k_ssl_write_api_write_ex2,
                                                 write.stack_pointer,
                                                 121,
                                                 20),
                  "stale recovery takes precedence over wrapper classification");
}

static void test_replaced_wrapper_accepts_only_one_matching_return(void) {
    for (int outer_returns_first = 0; outer_returns_first <= 1; outer_returns_first++) {
        reset();
        seed_write(k_ssl_write_api_write_ex2, 1);
        test_write.nested_write_api = k_ssl_write_api_write_ex;
        test_write.tail_wrapper = 1;
        ssl_args_t saved = {};
        const enum ssl_write_api returning_api =
            outer_returns_first ? k_ssl_write_api_write_ex : k_ssl_write_api_write_ex2;

        assert_int_eq(k_ssl_write_return_outer,
                      take_ssl_write_args(test_id, test_thread_start_time, returning_api, &saved),
                      "either return probe may complete a replaced write wrapper");
        assert_int_eq(1, test_write_delete_count, "the wrapper result is consumed once");
        assert_int_eq(k_ssl_write_return_missing,
                      take_ssl_write_args(test_id,
                                          test_thread_start_time,
                                          returning_api == k_ssl_write_api_write_ex
                                              ? k_ssl_write_api_write_ex2
                                              : k_ssl_write_api_write_ex,
                                          &saved),
                      "the second wrapper return observes no reusable handoff");
    }

    reset();
    seed_shutdown(k_ssl_shutdown_api_shutdown, 1);
    test_shutdown.nested_api = k_ssl_shutdown_api_crypto_native;
    test_shutdown.tail_wrapper = 1;
    ssl_shutdown_args_t shutdown_saved = {};
    assert_int_eq(
        k_ssl_write_return_outer,
        take_ssl_shutdown_args(
            test_id, test_thread_start_time, k_ssl_shutdown_api_crypto_native, &shutdown_saved),
        "either return probe may complete a replaced shutdown wrapper");
    assert_int_eq(1, test_shutdown_delete_count, "the shutdown result is consumed once");
}

static void test_replaced_wrapper_transfers_its_exact_handoff(void) {
    reset();
    seed_write(k_ssl_write_api_write_ex, 1);
    const ssl_args_t abandoned = test_write;

    assert_int_eq(k_ssl_wrapper_entry_replace_tail,
                  ssl_write_wrapper_entry_action(&abandoned,
                                                 abandoned.ssl,
                                                 abandoned.buf,
                                                 abandoned.len_ptr,
                                                 abandoned.requested_len,
                                                 0,
                                                 k_ssl_write_api_write_ex2,
                                                 abandoned.stack_pointer,
                                                 abandoned.handoff_id + 10,
                                                 20),
                  "a later direct inner API entry replaces a missed outer return");

    ssl_args_t fresh;
    initialize_ssl_write_args(&fresh,
                              abandoned.ssl,
                              abandoned.buf,
                              abandoned.len_ptr,
                              abandoned.handoff_id + 10,
                              abandoned.requested_len,
                              abandoned.stack_pointer,
                              k_ssl_write_api_write_ex2,
                              k_ssl_write_api_write_ex);
    transfer_ssl_write_handoff(&fresh, abandoned.handoff_id, abandoned.flags);
    assert_int_eq(100, (int)fresh.handoff_id, "replacement preserves the outer handoff");
    assert_int_eq(FLAG_SSL_PREWRITE_PUBLISHED,
                  (int)(fresh.flags & FLAG_SSL_PREWRITE_PUBLISHED),
                  "replacement preserves the outer publication");
    assert_int_eq(
        k_ssl_write_api_write_ex2, fresh.write_api, "replacement owns the current entry API");
    assert_int_eq(k_ssl_write_api_write_ex,
                  fresh.nested_write_api,
                  "replacement records the approved outer alias");
    assert_int_eq(1, fresh.tail_wrapper, "replacement is consumed by only one wrapper return");

    test_write = fresh;
    test_write_present = 1;
    ssl_args_t saved = {};
    assert_int_eq(
        k_ssl_write_return_outer,
        take_ssl_write_args(test_id, test_thread_start_time, k_ssl_write_api_write_ex2, &saved),
        "the fresh invocation consumes its own handoff");
    assert_int_eq(100, (int)saved.handoff_id, "the wrapper returns the one published handoff");
}

int main(void) {
    test_normal_outer_write_return();
    test_approved_nested_write_returns_in_order();
    test_missed_inner_return_fails_closed();
    test_wrong_and_explicitly_unsafe_write_returns_fail_closed();
    test_crypto_native_write_wrapper_uses_distinct_return_identity();
    test_shutdown_wrapper_return_identity();
    test_stale_write_recovery_requires_age_and_unwound_stack();
    test_thread_generation_prevents_pid_tgid_reuse();
    test_wrapper_transitions_accept_tail_calls_and_bound_stack_growth();
    test_replaced_wrapper_accepts_only_one_matching_return();
    test_replaced_wrapper_transfers_its_exact_handoff();
    return 0;
}
