// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>

#include <common/event_defs.h>
#include <common/http_info.h>

enum { BPF_ANY = 0, BPF_NOEXIST = 1, BPF_EXIST = 2 };
#define BPF_F_NO_PREALLOC 1

struct bpf_test_map {
    int id;
};

struct bpf_test_map ssl_to_conn = {.id = 1};
struct bpf_test_map ssl_to_pid_tid = {.id = 2};

static void *test_map_lookup(void *map, const void *key);
static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags);
static long test_map_delete(void *map, const void *key);
static uint64_t test_ktime_get_ns(void);

#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update
#define bpf_map_delete_elem test_map_delete
#define bpf_ktime_get_ns test_ktime_get_ns

#include <generictracer/ssl_connection.h>

#undef bpf_map_lookup_elem
#undef bpf_map_update_elem
#undef bpf_map_delete_elem
#undef bpf_ktime_get_ns

static u64 test_ssl;
static int test_ssl_present;
static ssl_prewrite_value_t test_prewrite;
static ssl_prewrite_value_t test_prewrite_scratch;
static connection_info_netns_cookie_t test_connection_key_scratch;
static ssl_prewrite_connection_owner_t test_owner_candidate_scratch;
static ssl_prewrite_connection_owner_t test_claim_candidate_scratch;
static ssl_prewrite_connection_owner_t test_block_claim_scratch;
static ssl_prewrite_connection_owner_t test_cleanup_claim_scratch;
static ssl_prewrite_connection_ambiguity_t test_ambiguity_candidate_scratch;
static int test_prewrite_present;
static ssl_prewrite_key_t test_prewrite_key;
static connection_info_netns_cookie_t test_owner_connection_key;
static ssl_prewrite_connection_owner_t test_connection_owner;
static ssl_prewrite_connection_owner_t test_connection_claim;
static int test_connection_owner_present;
static int test_connection_claim_present;
static int test_connection_ambiguous;
static ssl_prewrite_connection_ambiguity_t test_connection_ambiguity;
static int test_prewrite_update_error;
static int test_prewrite_delete_error;
static int test_ambiguity_update_error;
static int test_prewrite_update_count;
static int test_prewrite_delete_count;
static pid_connection_info_t test_updated_connection;
static u64 test_updated_ssl;
static unsigned long long test_update_flags;
static int test_active_update_count;
static int test_ssl_delete_count;
static int test_reverse_delete_count;
static int test_thread_owner_delete_count;
static ssl_pid_connection_info_t test_reverse_connection;
static ssl_pid_key_t test_reverse_key;
static int test_reverse_present;
static u64 test_now_ns;
static int test_close_on_owner_update;
static int test_close_before_publisher_claim_update;
static int test_close_before_block_claim_update;
static int test_close_on_block_claim_delete;
static int test_block_on_cleanup_claim_delete;
static int test_record_delete_order;
static int test_delete_order[8];
static int test_delete_order_len;

static void *test_map_lookup(void *map, const void *key) {
    if (map == &ssl_prewrite_value_storage) {
        return &test_prewrite_scratch;
    }
    if (map == &prewrite_connection_key_storage) {
        return &test_connection_key_scratch;
    }
    if (map == &prewrite_connection_owner_candidate_storage) {
        return &test_owner_candidate_scratch;
    }
    if (map == &prewrite_connection_claim_candidate_storage) {
        return &test_claim_candidate_scratch;
    }
    if (map == &prewrite_connection_block_claim_storage) {
        return &test_block_claim_scratch;
    }
    if (map == &prewrite_connection_cleanup_claim_storage) {
        return &test_cleanup_claim_scratch;
    }
    if (map == &prewrite_connection_ambiguity_candidate_storage) {
        return &test_ambiguity_candidate_scratch;
    }
    if (map == &active_ssl_connections && test_ssl_present) {
        return &test_ssl;
    }
    if (map == &ssl_to_conn && test_reverse_present &&
        memcmp(key, &test_reverse_key, sizeof(test_reverse_key)) == 0) {
        return &test_reverse_connection;
    }
    if (map == &ssl_prewrite_tp && test_prewrite_present &&
        memcmp(key, &test_prewrite_key, sizeof(test_prewrite_key)) == 0) {
        return &test_prewrite;
    }
    if (map == &ssl_prewrite_connection_owners && test_connection_owner_present &&
        memcmp(key, &test_owner_connection_key, sizeof(test_owner_connection_key)) == 0) {
        return &test_connection_owner;
    }
    if (map == &ssl_prewrite_connection_claims && test_connection_claim_present &&
        memcmp(key, &test_owner_connection_key, sizeof(test_owner_connection_key)) == 0) {
        return &test_connection_claim;
    }
    if (map == &ssl_prewrite_connection_ambiguity && test_connection_ambiguous &&
        memcmp(key, &test_owner_connection_key, sizeof(test_owner_connection_key)) == 0) {
        return &test_connection_ambiguity;
    }
    return NULL;
}

static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags) {
    if (map == &ssl_prewrite_tp) {
        test_prewrite_update_count++;
        test_update_flags = flags;
        if (test_prewrite_update_error || (flags == BPF_NOEXIST && test_prewrite_present)) {
            return -1;
        }
        memcpy(&test_prewrite_key, key, sizeof(test_prewrite_key));
        memcpy(&test_prewrite, value, sizeof(test_prewrite));
        test_prewrite_present = 1;
        return 0;
    }
    if (map == &ssl_prewrite_connection_owners) {
        if ((flags == BPF_NOEXIST && test_connection_owner_present) ||
            (flags == BPF_EXIST && !test_connection_owner_present)) {
            return -1;
        }
        test_owner_connection_key = *(const connection_info_netns_cookie_t *)key;
        test_connection_owner = *(const ssl_prewrite_connection_owner_t *)value;
        test_connection_owner_present = 1;
        if (test_close_on_owner_update) {
            test_close_on_owner_update = 0;
            cleanup_ssl_prewrite_connection(&test_prewrite.connection.conn,
                                            test_prewrite.netns_cookie);
        }
        return 0;
    }
    if (map == &ssl_prewrite_connection_claims) {
        const ssl_prewrite_connection_owner_t *candidate = value;
        if (test_close_before_publisher_claim_update &&
            candidate->state == k_ssl_prewrite_connection_owner_published) {
            test_close_before_publisher_claim_update = 0;
            cleanup_ssl_prewrite_connection(&test_prewrite.connection.conn,
                                            test_prewrite.netns_cookie);
        }
        if (test_close_before_block_claim_update &&
            candidate->state == k_ssl_prewrite_connection_owner_blocked) {
            test_close_before_block_claim_update = 0;
            cleanup_ssl_prewrite_connection(&test_prewrite.connection.conn,
                                            test_prewrite.netns_cookie);
        }
        if ((flags == BPF_NOEXIST && test_connection_claim_present) ||
            (flags == BPF_EXIST && !test_connection_claim_present)) {
            return -1;
        }
        test_owner_connection_key = *(const connection_info_netns_cookie_t *)key;
        test_connection_claim = *(const ssl_prewrite_connection_owner_t *)value;
        test_connection_claim_present = 1;
        return 0;
    }
    if (map == &ssl_prewrite_connection_ambiguity) {
        if (test_ambiguity_update_error) {
            return -1;
        }
        if ((flags == BPF_NOEXIST && test_connection_ambiguous) ||
            (flags == BPF_EXIST && !test_connection_ambiguous)) {
            return -1;
        }
        test_owner_connection_key = *(const connection_info_netns_cookie_t *)key;
        test_connection_ambiguity = *(const ssl_prewrite_connection_ambiguity_t *)value;
        test_connection_ambiguous = 1;
        return 0;
    }
    if (map != &active_ssl_connections) {
        return 0;
    }

    test_active_update_count++;
    test_update_flags = flags;
    memcpy(&test_updated_connection, key, sizeof(test_updated_connection));
    memcpy(&test_updated_ssl, value, sizeof(test_updated_ssl));
    if (flags == BPF_NOEXIST && test_ssl_present) {
        return -1;
    }
    test_ssl = test_updated_ssl;
    test_ssl_present = 1;
    return 0;
}

static long test_map_delete(void *map, const void *key) {
    if (test_record_delete_order && test_delete_order_len < 8) {
        if (map == &ssl_prewrite_tp) {
            test_delete_order[test_delete_order_len++] = 1;
        } else if (map == &ssl_prewrite_connection_owners) {
            test_delete_order[test_delete_order_len++] = 2;
        } else if (map == &ssl_prewrite_connection_claims) {
            test_delete_order[test_delete_order_len++] = 3;
        } else if (map == &ssl_prewrite_connection_ambiguity) {
            test_delete_order[test_delete_order_len++] = 4;
        }
    }
    if (map == &active_ssl_connections) {
        test_ssl_delete_count++;
    } else if (map == &ssl_to_conn) {
        test_reverse_delete_count++;
    } else if (map == &ssl_to_pid_tid) {
        test_thread_owner_delete_count++;
    } else if (map == &ssl_prewrite_tp && test_prewrite_present &&
               memcmp(key, &test_prewrite_key, sizeof(test_prewrite_key)) == 0) {
        test_prewrite_delete_count++;
        if (test_prewrite_delete_error) {
            return -1;
        }
        test_prewrite_present = 0;
    } else if (map == &ssl_prewrite_connection_claims) {
        if (test_close_on_block_claim_delete) {
            test_close_on_block_claim_delete = 0;
            cleanup_ssl_prewrite_connection(&test_prewrite.connection.conn,
                                            test_prewrite.netns_cookie);
        }
        test_connection_claim_present = 0;
        if (test_block_on_cleanup_claim_delete) {
            test_block_on_cleanup_claim_delete = 0;
            block_ssl_prewrite_connection(
                &test_prewrite.connection.conn, test_prewrite.netns_cookie, test_now_ns);
        }
    } else if (map == &ssl_prewrite_connection_ambiguity) {
        test_connection_ambiguous = 0;
        test_connection_ambiguity = (ssl_prewrite_connection_ambiguity_t){};
    } else if (map == &ssl_prewrite_connection_owners) {
        test_connection_owner_present = 0;
    }
    return 0;
}

static uint64_t test_ktime_get_ns(void) {
    return test_now_ns;
}

static void fail(const char *message) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

static void assert_int_eq(int expected, int actual, const char *message) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected %d, got %d\n", message, expected, actual);
        exit(1);
    }
}

static void assert_u32_eq(u32 expected, u32 actual, const char *message) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected %u, got %u\n", message, expected, actual);
        exit(1);
    }
}

static void reset(void) {
    test_ssl = 0;
    test_ssl_present = 0;
    test_prewrite = (ssl_prewrite_value_t){};
    test_prewrite_scratch = (ssl_prewrite_value_t){};
    test_connection_key_scratch = (connection_info_netns_cookie_t){};
    test_owner_candidate_scratch = (ssl_prewrite_connection_owner_t){};
    test_claim_candidate_scratch = (ssl_prewrite_connection_owner_t){};
    test_block_claim_scratch = (ssl_prewrite_connection_owner_t){};
    test_cleanup_claim_scratch = (ssl_prewrite_connection_owner_t){};
    test_ambiguity_candidate_scratch = (ssl_prewrite_connection_ambiguity_t){};
    test_prewrite_present = 0;
    test_prewrite_key = (ssl_prewrite_key_t){};
    test_owner_connection_key = (connection_info_netns_cookie_t){};
    test_connection_owner = (ssl_prewrite_connection_owner_t){};
    test_connection_claim = (ssl_prewrite_connection_owner_t){};
    test_connection_owner_present = 0;
    test_connection_claim_present = 0;
    test_connection_ambiguous = 0;
    test_connection_ambiguity = (ssl_prewrite_connection_ambiguity_t){};
    test_prewrite_update_error = 0;
    test_prewrite_delete_error = 0;
    test_ambiguity_update_error = 0;
    test_prewrite_update_count = 0;
    test_prewrite_delete_count = 0;
    test_updated_connection = (pid_connection_info_t){};
    test_updated_ssl = 0;
    test_update_flags = 0;
    test_active_update_count = 0;
    test_ssl_delete_count = 0;
    test_reverse_delete_count = 0;
    test_thread_owner_delete_count = 0;
    test_reverse_connection = (ssl_pid_connection_info_t){};
    test_reverse_key = (ssl_pid_key_t){};
    test_reverse_present = 0;
    test_now_ns = 100;
    test_close_on_owner_update = 0;
    test_close_before_publisher_claim_update = 0;
    test_close_before_block_claim_update = 0;
    test_close_on_block_claim_delete = 0;
    test_block_on_cleanup_claim_delete = 0;
    test_record_delete_order = 0;
    memset(test_delete_order, 0, sizeof(test_delete_order));
    test_delete_order_len = 0;
}

static pid_connection_info_t connection(u32 pid) {
    pid_connection_info_t result = {
        .conn = {.s_addr = {10, 0, 0, 1}, .d_addr = {10, 0, 0, 2}, .s_port = 49152, .d_port = 443},
        .pid = pid,
    };
    sort_connection_info(&result.conn);
    return result;
}

static tp_info_pid_t trace(u32 pid) {
    tp_info_pid_t result = {
        .pid = pid,
        .valid = 1,
        .req_type = EVENT_HTTP_CLIENT,
        .state = TP_INFO_PID_STATE_PROVENANCE(k_tp_provenance_ssl_prewrite),
    };
    result.tp.trace_id[0] = 1;
    result.tp.span_id[0] = 2;
    result.tp.ts = 100;
    return result;
}

static void seed_reverse_connection(const pid_connection_info_t *conn, u64 ssl) {
    test_ssl = ssl;
    test_ssl_present = 1;
    test_reverse_connection.p_conn = *conn;
    test_reverse_key = ssl_pid_key(ssl, conn->pid, 77);
    test_reverse_present = 1;
}

static void seed_ssl_prewrite(u64 pid_tgid, u64 thread_start_time, u64 handoff_id) {
    const pid_connection_info_t conn = connection(42);
    test_prewrite_present = 1;
    test_prewrite_key = ssl_prewrite_key(pid_tgid, thread_start_time, handoff_id);
    test_prewrite.connection = conn;
    test_prewrite.netns_cookie = 7;
    test_prewrite.ssl = 0x1234;
    test_prewrite.buffer = 0x5678;
    test_prewrite.bytes_len = 64;
    test_prewrite.destination_port = 443;
    test_prewrite.observed_monotime_ns = 90;
    test_prewrite.trace = trace(conn.pid);
    const connection_info_netns_cookie_t *owner_key =
        ssl_prewrite_connection_key(&conn.conn, test_prewrite.netns_cookie);
    if (!owner_key) {
        fail("connection owner key scratch is unavailable");
    }
    test_owner_connection_key = *owner_key;
    test_connection_owner = (ssl_prewrite_connection_owner_t){
        .key = test_prewrite_key,
        .observed_monotime_ns = test_prewrite.observed_monotime_ns,
        .state = k_ssl_prewrite_connection_owner_published,
    };
    test_connection_owner_present = 1;
}

static ssl_prewrite_value_t valid_ssl_prewrite(void) {
    const pid_connection_info_t conn = connection(42);
    ssl_prewrite_value_t value = {
        .connection = conn,
        .netns_cookie = 7,
        .ssl = 0x1234,
        .buffer = 0x5678,
        .bytes_len = 64,
        .target_tcp_sequence = 123,
        .destination_port = 443,
        .target_tcp_sequence_valid = 1,
        .observed_monotime_ns = 90,
        .trace = trace(conn.pid),
    };
    return value;
}

static void test_terminal_cleanup_deletes_owned_reverse_mapping(void) {
    reset();
    pid_connection_info_t conn = connection(42);
    seed_reverse_connection(&conn, 0x1234);

    cleanup_terminal_ssl_connection(&conn, 77, 7);

    assert_int_eq(1, test_reverse_delete_count, "terminal cleanup deletes the owned reverse map");
    assert_int_eq(
        1, test_thread_owner_delete_count, "terminal cleanup deletes the owned thread mapping");
    assert_int_eq(1, test_ssl_delete_count, "terminal cleanup deletes native SSL state");
}

static void test_terminal_cleanup_preserves_foreign_reverse_mapping(void) {
    reset();
    pid_connection_info_t conn = connection(42);
    seed_reverse_connection(&conn, 0x1234);
    test_reverse_connection.p_conn.conn.s_port++;

    cleanup_terminal_ssl_connection(&conn, 77, 7);

    assert_int_eq(0, test_reverse_delete_count, "terminal cleanup preserves another connection");
    assert_int_eq(
        0, test_thread_owner_delete_count, "terminal cleanup preserves its thread mapping");
    assert_int_eq(1, test_ssl_delete_count, "terminal cleanup still deletes direct SSL state");
}

static void test_terminal_cleanup_ignores_same_pointer_from_another_process(void) {
    reset();
    pid_connection_info_t conn = connection(42);
    pid_connection_info_t foreign = connection(43);
    seed_reverse_connection(&foreign, 0x1234);

    cleanup_terminal_ssl_connection(&conn, 77, 7);

    assert_int_eq(0, test_reverse_delete_count, "terminal cleanup preserves another process");
    assert_int_eq(
        0, test_thread_owner_delete_count, "terminal cleanup preserves another process owner");
    assert_int_eq(1, test_ssl_delete_count, "terminal cleanup deletes only direct SSL state");
}

static void test_terminal_cleanup_deletes_java_tls_marker(void) {
    reset();
    pid_connection_info_t conn = connection(42);
    test_ssl_present = 1;

    cleanup_terminal_ssl_connection(&conn, 77, 7);

    assert_int_eq(0, test_reverse_delete_count, "Java TLS marker has no reverse mapping");
    assert_int_eq(0, test_thread_owner_delete_count, "Java TLS marker has no thread mapping");
    assert_int_eq(1, test_ssl_delete_count, "terminal cleanup deletes the Java TLS marker");
}

static void test_terminal_cleanup_ignores_plaintext_connection(void) {
    reset();
    const pid_connection_info_t conn = connection(42);

    cleanup_terminal_ssl_connection(&conn, 77, 7);

    assert_int_eq(0, test_connection_ambiguous, "plaintext cleanup creates no SSL close fence");
    assert_int_eq(0, test_connection_owner_present, "plaintext cleanup creates no SSL owner state");
    assert_int_eq(0, test_connection_claim_present, "plaintext cleanup creates no SSL claim state");
}

enum arbitration_operation {
    k_write_add,
    k_write_load,
    k_transport_add,
    k_transport_load,
};

static void assert_arbitration_interleaving(const enum arbitration_operation operations[4],
                                            int expected_discard,
                                            int expected_emit) {
    ssl_prewrite_value_t value = {};
    int discard = 0;
    int emit = 0;

    for (size_t i = 0; i < 4; i++) {
        switch (operations[i]) {
        case k_write_add:
            ssl_prewrite_mark_write_failed(&value);
            break;
        case k_write_load:
            discard = ssl_prewrite_write_may_discard(ssl_prewrite_arbitration_state(&value));
            break;
        case k_transport_add:
            ssl_prewrite_mark_transport_may_emit(&value);
            break;
        case k_transport_load:
            emit = ssl_prewrite_transport_may_emit(ssl_prewrite_arbitration_state(&value));
            break;
        }
    }

    assert_int_eq(expected_discard, discard, "write arbitration decision matches ordering");
    assert_int_eq(expected_emit, emit, "transport arbitration decision matches ordering");
    if (discard && emit) {
        fail("an interleaving both emitted a parent and discarded its local span");
    }
    assert_u32_eq(k_ssl_prewrite_arbitration_failed_transport,
                  value.arbitration,
                  "one write and one transport participant converge on state three");
}

static void test_arbitration_covers_all_legal_interleavings(void) {
    static const enum arbitration_operation orderings[][4] = {
        {k_write_add, k_write_load, k_transport_add, k_transport_load},
        {k_write_add, k_transport_add, k_write_load, k_transport_load},
        {k_write_add, k_transport_add, k_transport_load, k_write_load},
        {k_transport_add, k_transport_load, k_write_add, k_write_load},
        {k_transport_add, k_write_add, k_transport_load, k_write_load},
        {k_transport_add, k_write_add, k_write_load, k_transport_load},
    };
    static const int expected_discard[] = {1, 0, 0, 0, 0, 0};
    static const int expected_emit[] = {0, 0, 0, 1, 0, 0};

    for (size_t i = 0; i < sizeof(orderings) / sizeof(orderings[0]); i++) {
        assert_arbitration_interleaving(orderings[i], expected_discard[i], expected_emit[i]);
    }
}

static void test_arbitration_transitions_and_unexpected_states_fail_closed(void) {
    ssl_prewrite_value_t value = {};

    ssl_prewrite_mark_write_failed(&value);
    assert_u32_eq(k_ssl_prewrite_arbitration_write_failed,
                  value.arbitration,
                  "write failure transitions zero to one");

    value.arbitration = k_ssl_prewrite_arbitration_none;
    ssl_prewrite_mark_transport_may_emit(&value);
    assert_u32_eq(k_ssl_prewrite_arbitration_transport_may_emit,
                  value.arbitration,
                  "transport transitions zero to two");

    value.arbitration = k_ssl_prewrite_arbitration_write_failed;
    ssl_prewrite_mark_transport_may_emit(&value);
    assert_u32_eq(k_ssl_prewrite_arbitration_failed_transport,
                  value.arbitration,
                  "transport transitions one to three");

    value.arbitration = k_ssl_prewrite_arbitration_transport_may_emit;
    ssl_prewrite_mark_write_failed(&value);
    assert_u32_eq(k_ssl_prewrite_arbitration_failed_transport,
                  value.arbitration,
                  "write failure transitions two to three");

    value.arbitration = k_ssl_prewrite_arbitration_none;
    ssl_prewrite_mark_write_failed(&value);
    ssl_prewrite_mark_write_failed(&value);
    ssl_prewrite_mark_transport_may_emit(&value);
    assert_u32_eq(4, value.arbitration, "duplicate write participation is detectable");
    assert_int_eq(0,
                  ssl_prewrite_write_may_discard(value.arbitration),
                  "duplicate write participation retains local state");
    assert_int_eq(0,
                  ssl_prewrite_transport_may_emit(value.arbitration),
                  "duplicate write participation suppresses transport emission");

    value.arbitration = 7;
    assert_int_eq(0,
                  ssl_prewrite_write_may_discard(value.arbitration),
                  "unexpected state retains local state");
    assert_int_eq(0,
                  ssl_prewrite_transport_may_emit(value.arbitration),
                  "unexpected state suppresses transport emission");
}

static void test_prewrite_key_requires_handoff_identity(void) {
    const ssl_prewrite_key_t first = ssl_prewrite_key(101, 11, 1);
    const ssl_prewrite_key_t second = ssl_prewrite_key(101, 11, 2);

    if (memcmp(&first, &second, sizeof(first)) == 0) {
        fail("handoff ID is absent from the prewrite key");
    }
    assert_u32_eq(1, (u32)first.handoff_id, "first handoff ID is preserved");
    assert_u32_eq(2, (u32)second.handoff_id, "second handoff ID is preserved");
}

static void test_prewrite_reset_requires_exact_thread_and_handoff(void) {
    reset();
    seed_ssl_prewrite(101, 11, 7);

    reset_ssl_prewrite(102, 11, 7);
    reset_ssl_prewrite(101, 12, 7);
    reset_ssl_prewrite(101, 11, 8);
    assert_int_eq(0, test_prewrite_delete_count, "foreign identities preserve the handoff");

    reset_ssl_prewrite(101, 11, 7);
    assert_int_eq(1, test_prewrite_delete_count, "the exact handoff is reset");
}

static void test_prewrite_value_requires_exact_connection(void) {
    reset();
    seed_ssl_prewrite(101, 11, 7);
    pid_connection_info_t conn = connection(42);

    assert_int_eq(1,
                  ssl_prewrite_value_matches(&test_prewrite, &conn, 443, 7),
                  "exact connection and namespace match");

    pid_connection_info_t foreign = connection(43);
    assert_int_eq(0,
                  ssl_prewrite_value_matches(&test_prewrite, &foreign, 443, 7),
                  "another process cannot consume the handoff");

    foreign = conn;
    foreign.conn.d_addr[3]++;
    assert_int_eq(0,
                  ssl_prewrite_value_matches(&test_prewrite, &foreign, 443, 7),
                  "another tuple cannot consume the handoff");
    assert_int_eq(0,
                  ssl_prewrite_value_matches(&test_prewrite, &conn, 8443, 7),
                  "another destination port cannot consume the handoff");
    assert_int_eq(0,
                  ssl_prewrite_value_matches(&test_prewrite, &conn, 443, 8),
                  "another network namespace cannot consume the handoff");
}

static void test_prewrite_publication_is_exclusive_and_fails_when_full(void) {
    reset();
    const pid_connection_info_t conn = connection(42);
    const tp_info_pid_t parent = trace(conn.pid);

    assert_int_eq(0,
                  (int)update_ssl_prewrite(
                      &conn, 443, 7, 0x1234, 0x5678, 64, 11, 101, 9, parent.tp.ts, &parent),
                  "an empty map accepts a prewrite");
    assert_int_eq(1, test_prewrite_update_count, "publication performs one map update");
    assert_int_eq(BPF_NOEXIST, (int)test_update_flags, "publication cannot replace a handoff");
    assert_u32_eq(9, (u32)test_prewrite_key.handoff_id, "publication keeps the handoff ID");
    assert_u32_eq(
        100, (u32)test_prewrite.observed_monotime_ns, "publication records its observation time");

    assert_int_eq(k_ssl_prewrite_publish_overload,
                  (int)update_ssl_prewrite(
                      &conn, 443, 7, 0x1234, 0x5678, 64, 11, 101, 9, parent.tp.ts, &parent),
                  "an occupied handoff cannot be replaced");

    reset();
    test_prewrite_update_error = 1;
    assert_int_eq(k_ssl_prewrite_publish_overload,
                  (int)update_ssl_prewrite(
                      &conn, 443, 7, 0x1234, 0x5678, 64, 11, 101, 9, parent.tp.ts, &parent),
                  "map capacity failure is reported");
    assert_int_eq(0, test_prewrite_present, "map capacity failure publishes nothing");
}

static void test_target_sequence_is_written_once(void) {
    reset();
    seed_ssl_prewrite(101, 11, 7);
    const pid_connection_info_t conn = connection(42);
    assert_int_eq(1,
                  capture_ssl_prewrite_tcp_sequence(&conn, 443, 7, 100, 20, 1234),
                  "the exact handoff captures a TCP sequence");
    assert_u32_eq(1234, test_prewrite.target_tcp_sequence, "the first sequence is captured");
    assert_int_eq(1, test_prewrite.target_tcp_sequence_valid, "the sequence is published");

    assert_int_eq(1,
                  capture_ssl_prewrite_tcp_sequence(&conn, 443, 7, 101, 20, 5678),
                  "a repeated capture recognizes the existing sequence");
    assert_u32_eq(1234, test_prewrite.target_tcp_sequence, "the sequence is write-once");

    test_connection_owner.key.handoff_id++;
    assert_int_eq(0,
                  capture_ssl_prewrite_tcp_sequence(&conn, 443, 7, 101, 20, 9999),
                  "another handoff cannot alter the sequence");
}

static void test_completion_waits_for_both_outcomes(void) {
    reset();
    seed_ssl_prewrite(101, 11, 7);
    test_prewrite.transport_phase = k_ssl_prewrite_transport_accepted;
    cleanup_completed_ssl_prewrite(&test_prewrite_key);
    assert_int_eq(0, test_prewrite_delete_count, "transport completion waits for write outcome");
    test_prewrite.write_outcome = k_ssl_prewrite_write_succeeded;
    cleanup_completed_ssl_prewrite(&test_prewrite_key);
    assert_int_eq(0, test_prewrite_delete_count, "the connection owner retains accepted state");

    reset();
    seed_ssl_prewrite(101, 11, 7);
    test_prewrite.write_outcome = k_ssl_prewrite_write_succeeded;
    test_prewrite.transport_phase = k_ssl_prewrite_transport_scheduled;
    cleanup_completed_ssl_prewrite(&test_prewrite_key);
    assert_int_eq(0, test_prewrite_delete_count, "write completion waits for transport outcome");
    test_prewrite.transport_phase = k_ssl_prewrite_transport_overload;
    cleanup_completed_ssl_prewrite(&test_prewrite_key);
    assert_int_eq(0, test_prewrite_delete_count, "the connection owner retains terminal state");
}

static void test_completion_delete_can_be_retried(void) {
    reset();
    seed_ssl_prewrite(101, 11, 7);
    test_prewrite.write_outcome = k_ssl_prewrite_write_failed;
    test_prewrite.transport_phase = k_ssl_prewrite_transport_closed;
    test_connection_ambiguous = 1;
    test_connection_ambiguity.state = k_ssl_prewrite_connection_ambiguous;
    test_prewrite_delete_error = 1;

    cleanup_completed_ssl_prewrite(&test_prewrite_key);
    assert_int_eq(1, test_prewrite_delete_count, "completion attempts its delete");
    assert_int_eq(1, test_prewrite_present, "a failed delete leaves a retryable handoff");

    test_prewrite_delete_error = 0;
    cleanup_completed_ssl_prewrite(&test_prewrite_key);
    assert_int_eq(2, test_prewrite_delete_count, "completion retries a failed delete");
    assert_int_eq(0, test_prewrite_present, "the retry removes the handoff");
}

static void test_expiry_rejects_missing_zero_future_and_old_values(void) {
    ssl_prewrite_value_t value = {.observed_monotime_ns = 90};

    assert_int_eq(1, ssl_prewrite_expired(NULL, 100, 20), "a missing value is expired");
    assert_int_eq(1, ssl_prewrite_expired(&value, 0, 20), "a missing clock is expired");
    assert_int_eq(1, ssl_prewrite_expired(&value, 100, 0), "a missing TTL is expired");
    value.observed_monotime_ns = 0;
    assert_int_eq(1, ssl_prewrite_expired(&value, 100, 20), "a missing timestamp is expired");
    value.observed_monotime_ns = 101;
    assert_int_eq(1, ssl_prewrite_expired(&value, 100, 20), "a future timestamp is expired");
    value.observed_monotime_ns = 90;
    assert_int_eq(0, ssl_prewrite_expired(&value, 100, 20), "a live value is retained");
    assert_int_eq(1, ssl_prewrite_expired(&value, 111, 20), "an old value is expired");
}

static void test_prewrite_schedule_validation_classifies_every_failure_domain(void) {
    ssl_prewrite_value_t value = valid_ssl_prewrite();
    assert_int_eq(k_ssl_prewrite_validation_missing,
                  ssl_prewrite_schedule_validation(NULL, 100, 20),
                  "an evicted handoff is reported missing");
    assert_int_eq(k_ssl_prewrite_validation_ready,
                  ssl_prewrite_schedule_validation(&value, 100, 20),
                  "a complete fresh handoff is ready");

    value.target_tcp_sequence_valid = 0;
    assert_int_eq(k_ssl_prewrite_validation_missing,
                  ssl_prewrite_schedule_validation(&value, 100, 20),
                  "a missing capture is reported missing");
    value.target_tcp_sequence_valid = 2;
    assert_int_eq(k_ssl_prewrite_validation_malformed,
                  ssl_prewrite_schedule_validation(&value, 100, 20),
                  "an invalid capture marker is malformed");

    value = valid_ssl_prewrite();
    value.observed_monotime_ns = 79;
    assert_int_eq(k_ssl_prewrite_validation_stale,
                  ssl_prewrite_schedule_validation(&value, 100, 20),
                  "an expired handoff is stale");

    value = valid_ssl_prewrite();
    value.transport_phase = (enum ssl_prewrite_transport_phase)99;
    assert_int_eq(k_ssl_prewrite_validation_malformed,
                  ssl_prewrite_schedule_validation(&value, 100, 20),
                  "an out-of-domain phase is malformed");

    value = valid_ssl_prewrite();
    value.transport_phase = k_ssl_prewrite_transport_scheduled;
    assert_int_eq(k_ssl_prewrite_validation_ambiguous,
                  ssl_prewrite_schedule_validation(&value, 100, 20),
                  "an already scheduled handoff requires socket ownership");

    value.arbitration = k_ssl_prewrite_arbitration_write_failed;
    assert_int_eq(k_ssl_prewrite_validation_stale,
                  ssl_prewrite_schedule_validation(&value, 100, 20),
                  "a failed scheduled owner is stale");

    value = valid_ssl_prewrite();
    value.write_outcome = k_ssl_prewrite_write_failed;
    assert_int_eq(k_ssl_prewrite_validation_stale,
                  ssl_prewrite_schedule_validation(&value, 100, 20),
                  "a terminal write failure is stale");

    value = valid_ssl_prewrite();
    value.arbitration = k_ssl_prewrite_arbitration_failed_transport;
    assert_int_eq(k_ssl_prewrite_validation_stale,
                  ssl_prewrite_schedule_validation(&value, 100, 20),
                  "a failed transport arbitration is stale");
}

static void test_prewrite_structural_validation_rejects_malformed_trace_state(void) {
    ssl_prewrite_value_t value = valid_ssl_prewrite();
    assert_int_eq(1,
                  ssl_prewrite_shared_value_structurally_valid(&value),
                  "the complete shared value is structurally valid");

    value.target_tcp_sequence_valid = 0;
    assert_int_eq(1,
                  ssl_prewrite_postwrite_value_structurally_valid(&value),
                  "postwrite validation permits a handoff that transport has not observed");
    assert_int_eq(0,
                  ssl_prewrite_shared_value_structurally_valid(&value),
                  "transport validation requires an observed target sequence");
    value.target_tcp_sequence_valid = 2;
    assert_int_eq(0,
                  ssl_prewrite_postwrite_value_structurally_valid(&value),
                  "postwrite validation rejects a noncanonical target marker");

    value = valid_ssl_prewrite();
    value.trace.req_type = EVENT_HTTP_REQUEST;
    assert_int_eq(0,
                  ssl_prewrite_shared_value_structurally_valid(&value),
                  "a server trace cannot be injected as a client parent");
    value = valid_ssl_prewrite();
    memset(value.trace.tp.trace_id, 0, sizeof(value.trace.tp.trace_id));
    assert_int_eq(
        0, ssl_prewrite_shared_value_structurally_valid(&value), "a zero trace ID is malformed");
    value = valid_ssl_prewrite();
    memset(value.trace.tp.span_id, 0, sizeof(value.trace.tp.span_id));
    assert_int_eq(
        0, ssl_prewrite_shared_value_structurally_valid(&value), "a zero span ID is malformed");
    value = valid_ssl_prewrite();
    value.trace.pid++;
    assert_int_eq(0,
                  ssl_prewrite_shared_value_structurally_valid(&value),
                  "trace and connection processes must agree");
    value = valid_ssl_prewrite();
    value.reuse_state = k_ssl_prewrite_reuse_ready + 1;
    assert_int_eq(0,
                  ssl_prewrite_shared_value_structurally_valid(&value),
                  "a noncanonical reuse marker is malformed");

    value = valid_ssl_prewrite();
    value.trace.valid = 0;
    assert_int_eq(0,
                  ssl_prewrite_shared_value_structurally_valid(&value),
                  "a missing trace-valid marker is malformed");
    value.trace.valid = 2;
    assert_int_eq(0,
                  ssl_prewrite_shared_value_structurally_valid(&value),
                  "a noncanonical trace-valid marker is malformed");

    value = valid_ssl_prewrite();
    tp_info_pid_set_provenance(&value.trace, k_tp_provenance_tcp_exact_flags);
    assert_int_eq(0,
                  ssl_prewrite_shared_value_structurally_valid(&value),
                  "another trace provenance is malformed");

    value = valid_ssl_prewrite();
    value.write_outcome = (enum ssl_prewrite_write_outcome)3;
    assert_int_eq(0,
                  ssl_prewrite_shared_value_structurally_valid(&value),
                  "an out-of-domain write outcome is malformed");

    value = valid_ssl_prewrite();
    value.arbitration = 4;
    assert_int_eq(0,
                  ssl_prewrite_shared_value_structurally_valid(&value),
                  "an out-of-domain arbitration state is malformed");

    value = valid_ssl_prewrite();
    value.connection.pid = 0;
    assert_int_eq(0, ssl_prewrite_shared_value_structurally_valid(&value), "zero PID is malformed");
    value = valid_ssl_prewrite();
    value.connection.conn.s_port = 0;
    assert_int_eq(
        0, ssl_prewrite_shared_value_structurally_valid(&value), "zero source port is malformed");
    value = valid_ssl_prewrite();
    value.connection.conn.d_port = 0;
    assert_int_eq(0,
                  ssl_prewrite_shared_value_structurally_valid(&value),
                  "zero destination tuple port is malformed");
    value = valid_ssl_prewrite();
    value.netns_cookie = 0;
    assert_int_eq(0,
                  ssl_prewrite_shared_value_structurally_valid(&value),
                  "zero network namespace cookie is malformed");
    value = valid_ssl_prewrite();
    value.ssl = 0;
    assert_int_eq(0, ssl_prewrite_shared_value_structurally_valid(&value), "zero SSL is malformed");
    value = valid_ssl_prewrite();
    value.buffer = 0;
    assert_int_eq(
        0, ssl_prewrite_shared_value_structurally_valid(&value), "zero buffer is malformed");
    value = valid_ssl_prewrite();
    value.bytes_len = 0;
    assert_int_eq(
        0, ssl_prewrite_shared_value_structurally_valid(&value), "zero write length is malformed");
    value = valid_ssl_prewrite();
    value.destination_port = 0;
    assert_int_eq(0,
                  ssl_prewrite_shared_value_structurally_valid(&value),
                  "zero metadata destination port is malformed");
}

static void test_prewrite_transport_accepts_delayed_success_and_rejects_local_mismatch(void) {
    ssl_prewrite_value_t value = valid_ssl_prewrite();
    tp_info_t local_trace = value.trace.tp;

    value.write_outcome = k_ssl_prewrite_write_succeeded;
    assert_int_eq(1,
                  ssl_prewrite_ready_to_schedule(&value, 100, 20),
                  "delayed ciphertext can schedule after SSL_write returns");

    assert_int_eq(1,
                  ssl_prewrite_transport_local_fields_match(
                      &value, EVENT_HTTP_CLIENT, WITH_SSL, TCP_SEND, 10, &local_trace),
                  "transport matching does not depend on the cleared pending marker");
    assert_int_eq(0,
                  ssl_prewrite_transport_local_fields_match(
                      &value, EVENT_HTTP_REQUEST, WITH_SSL, TCP_SEND, 10, &local_trace),
                  "transport rejects a mismatched local request");
    assert_int_eq(0,
                  ssl_prewrite_transport_local_fields_match(
                      &value, EVENT_HTTP_CLIENT, NO_SSL, TCP_SEND, 10, &local_trace),
                  "transport rejects a non-TLS local owner");
    assert_int_eq(0,
                  ssl_prewrite_transport_local_fields_match(
                      &value, EVENT_HTTP_CLIENT, WITH_SSL, TCP_RECV, 10, &local_trace),
                  "transport rejects a receive-side local owner");
    assert_int_eq(0,
                  ssl_prewrite_transport_local_fields_match(
                      &value, EVENT_HTTP_CLIENT, WITH_SSL, TCP_SEND, 0, &local_trace),
                  "transport rejects an unstarted local owner");
    for (u8 pending = k_ssl_prewrite_local_none; pending <= k_ssl_prewrite_local_pending;
         pending++) {
        assert_int_eq(1,
                      ssl_prewrite_transport_local_fields_match(
                          &value, EVENT_HTTP_CLIENT, WITH_SSL, TCP_SEND, 10, &local_trace),
                      pending ? "postwrite pending owner matches"
                              : "transport-committed owner still matches");
    }
    local_trace.span_id[0]++;
    assert_int_eq(0,
                  ssl_prewrite_transport_local_fields_match(
                      &value, EVENT_HTTP_CLIENT, WITH_SSL, TCP_SEND, 10, &local_trace),
                  "transport rejects a mismatched local trace");
}

static void test_http_request_start_preserves_its_direction(void) {
    http_info_t info = {0};

    assert_int_eq(1,
                  http_info_begin_request(&info, PACKET_TYPE_REQUEST, TCP_SEND),
                  "a fresh request records its direction");
    assert_int_eq(TCP_SEND, info.direction, "an outbound request records send direction");

    info.start_monotime_ns = 10;
    assert_int_eq(0,
                  http_info_begin_request(&info, PACKET_TYPE_RESPONSE, TCP_RECV),
                  "a response does not start a request");
    assert_int_eq(TCP_SEND, info.direction, "a response preserves the initiating direction");
    assert_int_eq(0,
                  http_info_begin_request(&info, PACKET_TYPE_REQUEST, TCP_RECV),
                  "a continuation does not restart an active request");
    assert_int_eq(TCP_SEND, info.direction, "a continuation preserves the initiating direction");
}

static void test_http_response_status_requires_decimal_digits(void) {
    unsigned char response[] = "HTTP/1.1 200";
    const unsigned char invalid[][3] = {
        {'/', '0', '0'},
        {'2', ':', '0'},
        {'2', '0', '/'},
    };

    assert_int_eq(k_http_response_status_final_min,
                  parse_http_response_status(response),
                  "a valid final response status parses");
    assert_int_eq(1,
                  http_response_status_is_final(parse_http_response_status(response)),
                  "a valid success response is final");

    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        __builtin_memcpy(
            &response[k_http_response_status_position], invalid[i], sizeof(invalid[i]));
        assert_int_eq(0,
                      parse_http_response_status(response),
                      "every response status byte must be a decimal digit");
    }

    __builtin_memcpy(&response[k_http_response_status_position], "101", 3);
    assert_int_eq(0,
                  http_response_status_is_final(parse_http_response_status(response)),
                  "an upgrade response is not final for keepalive reuse");
    __builtin_memcpy(&response[k_http_response_status_position], "102", 3);
    assert_int_eq(0,
                  parse_http_response_status(response),
                  "an interim response keeps the request available for its final response");
    __builtin_memcpy(&response[k_http_response_status_position], "099", 3);
    assert_int_eq(
        0, parse_http_response_status(response), "a response below the valid range is rejected");
    __builtin_memcpy(&response[k_http_response_status_position], "600", 3);
    assert_int_eq(
        0, parse_http_response_status(response), "an out-of-range response status is rejected");
}

static void test_response_completion_is_required_for_connection_reuse(void) {
    enum { k_test_invalid_tcp_direction = TCP_SEND + 1 };
    const struct {
        u8 request_type;
        u8 ssl;
        u8 request_direction;
        u8 response_direction;
        u16 response_status;
        const char *message;
    } rejected[] = {
        {EVENT_HTTP_CLIENT,
         WITH_SSL,
         TCP_SEND,
         TCP_RECV,
         k_http_response_status_switching_protocols,
         "an informational upgrade response cannot enable reuse"},
        {EVENT_HTTP_CLIENT,
         WITH_SSL,
         TCP_SEND,
         TCP_SEND,
         k_http_response_status_final_min,
         "a send-side response cannot enable reuse"},
        {EVENT_HTTP_CLIENT,
         WITH_SSL,
         TCP_SEND,
         k_test_invalid_tcp_direction,
         k_http_response_status_final_min,
         "an invalid response direction cannot enable reuse"},
        {EVENT_HTTP_CLIENT,
         WITH_SSL,
         TCP_RECV,
         TCP_RECV,
         k_http_response_status_final_min,
         "a receive-side request cannot enable reuse"},
        {EVENT_HTTP_REQUEST,
         WITH_SSL,
         TCP_SEND,
         TCP_RECV,
         k_http_response_status_final_min,
         "a server response cannot enable client reuse"},
        {EVENT_HTTP_CLIENT,
         NO_SSL,
         TCP_SEND,
         TCP_RECV,
         k_http_response_status_final_min,
         "a plaintext response cannot enable TLS reuse"},
    };

    reset();
    seed_ssl_prewrite(101, 11, 7);
    test_prewrite.target_tcp_sequence = 123;
    test_prewrite.target_tcp_sequence_valid = 1;
    test_prewrite.transport_phase = k_ssl_prewrite_transport_accepted;
    test_prewrite.write_outcome = k_ssl_prewrite_write_succeeded;
    const tp_info_t trace = test_prewrite.trace.tp;

    mark_ssl_prewrite_connection_reusable(&test_prewrite.connection,
                                          test_prewrite.netns_cookie,
                                          EVENT_HTTP_CLIENT,
                                          WITH_SSL,
                                          TCP_SEND,
                                          TCP_RECV,
                                          k_http_response_status_final_min,
                                          10,
                                          &trace);
    assert_int_eq(k_ssl_prewrite_reuse_ready,
                  test_prewrite.reuse_state,
                  "the exact client response enables reuse");

    test_prewrite.reuse_state = k_ssl_prewrite_reuse_none;
    for (size_t i = 0; i < sizeof(rejected) / sizeof(rejected[0]); i++) {
        mark_ssl_prewrite_connection_reusable(&test_prewrite.connection,
                                              test_prewrite.netns_cookie,
                                              rejected[i].request_type,
                                              rejected[i].ssl,
                                              rejected[i].request_direction,
                                              rejected[i].response_direction,
                                              rejected[i].response_status,
                                              10,
                                              &trace);
        assert_int_eq(k_ssl_prewrite_reuse_none, test_prewrite.reuse_state, rejected[i].message);
    }

    tp_info_t foreign_trace = trace;
    foreign_trace.span_id[0]++;
    mark_ssl_prewrite_connection_reusable(&test_prewrite.connection,
                                          test_prewrite.netns_cookie,
                                          EVENT_HTTP_CLIENT,
                                          WITH_SSL,
                                          TCP_SEND,
                                          TCP_RECV,
                                          k_http_response_status_final_min,
                                          10,
                                          &foreign_trace);
    assert_int_eq(k_ssl_prewrite_reuse_none,
                  test_prewrite.reuse_state,
                  "a foreign response cannot enable reuse");

    test_connection_ambiguous = 1;
    test_connection_ambiguity.state = k_ssl_prewrite_connection_ambiguous;
    mark_ssl_prewrite_connection_reusable(&test_prewrite.connection,
                                          test_prewrite.netns_cookie,
                                          EVENT_HTTP_CLIENT,
                                          WITH_SSL,
                                          TCP_SEND,
                                          TCP_RECV,
                                          k_http_response_status_final_min,
                                          10,
                                          &trace);
    assert_int_eq(k_ssl_prewrite_reuse_none,
                  test_prewrite.reuse_state,
                  "an ambiguous connection cannot become reusable");
}

static void test_connection_replacement_requires_response_completion(void) {
    reset();
    seed_ssl_prewrite(101, 11, 7);
    test_prewrite.target_tcp_sequence = 123;
    test_prewrite.target_tcp_sequence_valid = 1;
    test_prewrite.transport_phase = k_ssl_prewrite_transport_accepted;
    test_prewrite.write_outcome = k_ssl_prewrite_write_succeeded;
    ssl_prewrite_value_t next = test_prewrite;
    next.observed_monotime_ns++;
    const ssl_prewrite_key_t next_key = ssl_prewrite_key(202, 22, 8);
    const tp_info_t trace = test_prewrite.trace.tp;

    mark_ssl_prewrite_connection_reusable(&test_prewrite.connection,
                                          test_prewrite.netns_cookie,
                                          EVENT_HTTP_CLIENT,
                                          WITH_SSL,
                                          TCP_SEND,
                                          TCP_RECV,
                                          k_http_response_status_final_min - 1,
                                          10,
                                          &trace);

    assert_int_eq(k_ssl_prewrite_publish_ambiguous,
                  publish_ssl_prewrite_connection_owner(&next_key, &next),
                  "a non-final response remains non-reusable");
    assert_int_eq(k_ssl_prewrite_connection_owner_blocked,
                  test_connection_owner.state,
                  "unsafe replacement blocks the connection");

    reset();
    seed_ssl_prewrite(101, 11, 7);
    test_prewrite.target_tcp_sequence = 123;
    test_prewrite.target_tcp_sequence_valid = 1;
    test_prewrite.transport_phase = k_ssl_prewrite_transport_accepted;
    test_prewrite.write_outcome = k_ssl_prewrite_write_succeeded;
    const tp_info_t prior_trace = test_prewrite.trace.tp;
    mark_ssl_prewrite_connection_reusable(&test_prewrite.connection,
                                          test_prewrite.netns_cookie,
                                          EVENT_HTTP_CLIENT,
                                          WITH_SSL,
                                          TCP_SEND,
                                          TCP_RECV,
                                          k_http_response_status_final_min,
                                          10,
                                          &prior_trace);
    assert_int_eq(k_ssl_prewrite_reuse_ready,
                  test_prewrite.reuse_state,
                  "an exact completed response makes the prior owner reusable");
    next = test_prewrite;
    next.observed_monotime_ns++;
    next.reuse_state = k_ssl_prewrite_reuse_none;
    next.trace.tp.span_id[0]++;
    const tp_info_t next_trace = next.trace.tp;

    assert_int_eq(k_ssl_prewrite_publish_valid,
                  publish_ssl_prewrite_connection_owner(&next_key, &next),
                  "an exact completed response permits keepalive replacement");
    assert_int_eq(1,
                  ssl_prewrite_connection_owner_matches(&test_connection_owner, &next_key),
                  "replacement publishes only the next exact owner");
    assert_int_eq(1, test_prewrite_delete_count, "replacement retires the previous shared value");

    test_prewrite = next;
    test_prewrite_key = next_key;
    test_prewrite_present = 1;
    mark_ssl_prewrite_connection_reusable(&test_prewrite.connection,
                                          test_prewrite.netns_cookie,
                                          EVENT_HTTP_CLIENT,
                                          WITH_SSL,
                                          TCP_SEND,
                                          TCP_RECV,
                                          k_http_response_status_final_min,
                                          10,
                                          &prior_trace);
    assert_int_eq(k_ssl_prewrite_reuse_none,
                  test_prewrite.reuse_state,
                  "a delayed prior response cannot complete the replacement owner");

    mark_ssl_prewrite_connection_reusable(&test_prewrite.connection,
                                          test_prewrite.netns_cookie,
                                          EVENT_HTTP_CLIENT,
                                          WITH_SSL,
                                          TCP_SEND,
                                          TCP_RECV,
                                          k_http_response_status_final_min,
                                          10,
                                          &next_trace);
    assert_int_eq(k_ssl_prewrite_reuse_ready,
                  test_prewrite.reuse_state,
                  "the replacement owner accepts only its exact response");
}

static void test_connection_tracking_requires_existing_bridge_state(void) {
    reset();
    const pid_connection_info_t conn = connection(42);

    assert_int_eq(0,
                  ssl_prewrite_connection_tracked(&conn.conn, 7),
                  "an unrelated socket has no SSL prewrite close state");
    assert_int_eq(0,
                  ssl_prewrite_connection_should_cleanup(&conn, 7),
                  "an unrelated non-TLS socket creates no SSL close fence");

    test_ssl = 0x1234;
    test_ssl_present = 1;
    assert_int_eq(1,
                  ssl_prewrite_connection_should_cleanup(&conn, 7),
                  "an active TLS socket is fenced before publication starts");
    test_ssl_present = 0;

    seed_ssl_prewrite(101, 11, 7);
    assert_int_eq(
        1,
        ssl_prewrite_connection_tracked(&test_prewrite.connection.conn, test_prewrite.netns_cookie),
        "an exact owner is tracked for close cleanup");
    assert_int_eq(1,
                  ssl_prewrite_connection_should_cleanup(&test_prewrite.connection,
                                                         test_prewrite.netns_cookie),
                  "published bridge state remains eligible for close cleanup");

    test_connection_owner_present = 0;
    test_connection_claim = (ssl_prewrite_connection_owner_t){
        .key = test_prewrite_key,
        .state = k_ssl_prewrite_connection_owner_published,
    };
    test_connection_claim_present = 1;
    assert_int_eq(
        1,
        ssl_prewrite_connection_tracked(&test_prewrite.connection.conn, test_prewrite.netns_cookie),
        "an in-flight publication claim is tracked for close cleanup");

    test_connection_claim_present = 0;
    test_connection_ambiguity.state = k_ssl_prewrite_connection_closing;
    test_connection_ambiguous = 1;
    assert_int_eq(
        1,
        ssl_prewrite_connection_tracked(&test_prewrite.connection.conn, test_prewrite.netns_cookie),
        "a durable close fence remains tracked for cleanup");
}

static void test_blocked_owner_is_cleaned_on_connection_close(void) {
    reset();
    seed_ssl_prewrite(101, 11, 7);
    block_ssl_prewrite_connection(
        &test_prewrite.connection.conn, test_prewrite.netns_cookie, test_now_ns);
    assert_int_eq(k_ssl_prewrite_connection_owner_blocked,
                  test_connection_owner.state,
                  "collision blocks the connection owner");
    assert_u32_eq(
        7, (u32)test_connection_owner.key.handoff_id, "blocking preserves the exact cleanup key");

    test_record_delete_order = 1;
    cleanup_ssl_prewrite_connection(&test_prewrite.connection.conn, test_prewrite.netns_cookie);
    test_record_delete_order = 0;
    assert_int_eq(0, test_connection_owner_present, "close removes the blocked owner");
    assert_int_eq(1, test_connection_ambiguous, "close retains its durable fence");
    assert_int_eq(k_ssl_prewrite_connection_closing,
                  test_connection_ambiguity.state,
                  "close records a closing fence");
    assert_int_eq(0, test_connection_claim_present, "close releases its cleanup claim");
    assert_int_eq(0, test_prewrite_present, "close removes the blocked shared handoff");
    assert_int_eq(3, test_delete_order_len, "close deletes all non-fence connection state");
    assert_int_eq(1, test_delete_order[0], "close deletes the exact shared handoff first");
    assert_int_eq(2, test_delete_order[1], "close deletes the owner before releasing its claim");
    assert_int_eq(3, test_delete_order[2], "close releases its claim after deleting the owner");
}

static void test_close_does_not_steal_an_active_publication_claim(void) {
    reset();
    seed_ssl_prewrite(101, 11, 7);
    test_connection_claim = test_connection_owner;
    test_connection_claim_present = 1;

    cleanup_ssl_prewrite_connection(&test_prewrite.connection.conn, test_prewrite.netns_cookie);
    assert_int_eq(1, test_connection_claim_present, "close preserves the active publisher claim");
    assert_int_eq(1, test_connection_owner_present, "contended close leaves blocked owner state");
    assert_int_eq(k_ssl_prewrite_connection_owner_closing,
                  test_connection_claim.state,
                  "contended close signals the active publisher");
    assert_int_eq(k_ssl_prewrite_connection_owner_closing,
                  test_connection_owner.state,
                  "contended close marks the published owner as closing");
    assert_int_eq(1, test_connection_ambiguous, "contended close retains a durable fence");
    assert_int_eq(k_ssl_prewrite_connection_closing,
                  test_connection_ambiguity.state,
                  "contended close records durable close intent");
    assert_int_eq(1, test_prewrite_present, "contended close leaves exact cleanup state");

    test_connection_claim_present = 0;
    cleanup_ssl_prewrite_connection(&test_prewrite.connection.conn, test_prewrite.netns_cookie);
    assert_int_eq(0, test_connection_owner_present, "a later close removes blocked owner state");
    assert_int_eq(0, test_prewrite_present, "a later close removes the exact shared handoff");
    assert_int_eq(1, test_connection_ambiguous, "the later close retains its durable fence");
}

static void test_close_falls_back_to_owner_and_claim_when_tombstones_are_full(void) {
    reset();
    seed_ssl_prewrite(101, 11, 7);
    test_ambiguity_update_error = 1;

    cleanup_ssl_prewrite_connection(&test_prewrite.connection.conn, test_prewrite.netns_cookie);
    assert_int_eq(0, test_connection_ambiguous, "a full tombstone map reports no false marker");
    assert_int_eq(1, test_connection_owner_present, "close retains a durable owner fallback");
    assert_int_eq(k_ssl_prewrite_connection_owner_closing,
                  test_connection_owner.state,
                  "the fallback owner fences new publication");
    assert_int_eq(1, test_connection_claim_present, "close retains a durable claim fallback");
    assert_int_eq(k_ssl_prewrite_connection_owner_closing,
                  test_connection_claim.state,
                  "the fallback claim fences paused publication");
    assert_int_eq(1, test_prewrite_present, "deferred cleanup preserves its exact shared key");
}

static void test_publisher_completes_a_contended_close_without_another_callback(void) {
    reset();
    seed_ssl_prewrite(101, 11, 7);
    test_close_on_owner_update = 1;

    assert_int_eq(k_ssl_prewrite_publish_ambiguous,
                  publish_ssl_prewrite_connection_owner(&test_prewrite_key, &test_prewrite),
                  "a close racing publication invalidates the handoff");
    assert_int_eq(0, test_close_on_owner_update, "the close race was exercised");
    assert_int_eq(0, test_connection_claim_present, "the publisher releases its claim");
    assert_int_eq(0, test_connection_owner_present, "the publisher completes close cleanup");
    assert_int_eq(1, test_connection_ambiguous, "completed cleanup retains close intent");
    assert_int_eq(0, test_prewrite_present, "completed cleanup removes the exact shared handoff");
}

static void test_durable_close_fences_a_publisher_paused_before_its_claim(void) {
    reset();
    seed_ssl_prewrite(101, 11, 7);
    test_close_before_publisher_claim_update = 1;

    assert_int_eq(k_ssl_prewrite_publish_ambiguous,
                  publish_ssl_prewrite_connection_owner(&test_prewrite_key, &test_prewrite),
                  "a pre-claim close invalidates the paused publisher");
    assert_int_eq(0, test_close_before_publisher_claim_update, "the pre-claim race was exercised");
    assert_int_eq(0, test_connection_claim_present, "the paused publisher releases its claim");
    assert_int_eq(0, test_connection_owner_present, "the paused publisher cannot restore an owner");
    assert_int_eq(1, test_connection_ambiguous, "the durable close fence remains published");
    assert_int_eq(k_ssl_prewrite_connection_closing,
                  test_connection_ambiguity.state,
                  "the paused publisher observes close intent");
    assert_int_eq(0, test_prewrite_present, "close removes the shared handoff");
}

static void test_durable_close_fences_a_blocker_paused_before_its_claim(void) {
    reset();
    seed_ssl_prewrite(101, 11, 7);
    test_close_before_block_claim_update = 1;

    block_ssl_prewrite_connection(
        &test_prewrite.connection.conn, test_prewrite.netns_cookie, test_now_ns);
    assert_int_eq(0, test_close_before_block_claim_update, "the pre-claim race was exercised");
    assert_int_eq(0, test_connection_claim_present, "the paused blocker releases its claim");
    assert_int_eq(0, test_connection_owner_present, "the paused blocker cannot restore an owner");
    assert_int_eq(1, test_connection_ambiguous, "the durable close fence remains published");
    assert_int_eq(k_ssl_prewrite_connection_closing,
                  test_connection_ambiguity.state,
                  "the paused blocker observes close intent");
    assert_int_eq(0, test_prewrite_present, "close removes the shared handoff");
}

static void test_block_during_close_release_cannot_resurrect_state(void) {
    reset();
    seed_ssl_prewrite(101, 11, 7);
    test_block_on_cleanup_claim_delete = 1;

    cleanup_ssl_prewrite_connection(&test_prewrite.connection.conn, test_prewrite.netns_cookie);
    assert_int_eq(0, test_block_on_cleanup_claim_delete, "the release race was exercised");
    assert_int_eq(0, test_connection_claim_present, "close releases its claim");
    assert_int_eq(0, test_connection_owner_present, "a racing block cannot restore the owner");
    assert_int_eq(1, test_connection_ambiguous, "close retains its durable fence");
    assert_int_eq(0, test_prewrite_present, "close still removes the shared handoff");
}

static void test_close_during_block_release_needs_no_later_callback(void) {
    reset();
    seed_ssl_prewrite(101, 11, 7);
    test_close_on_block_claim_delete = 1;

    block_ssl_prewrite_connection(
        &test_prewrite.connection.conn, test_prewrite.netns_cookie, test_now_ns);
    assert_int_eq(0, test_close_on_block_claim_delete, "the close race was exercised");
    assert_int_eq(0, test_connection_claim_present, "the transient block claim is released");
    assert_int_eq(0, test_connection_owner_present, "the blocker completes close cleanup");
    assert_int_eq(1, test_connection_ambiguous, "completed cleanup retains close intent");
    assert_int_eq(0, test_prewrite_present, "completed cleanup removes the shared handoff");
}

static void test_lru_eviction_fails_open_and_stale_local_owner_recovers(void) {
    assert_int_eq(k_ssl_prewrite_validation_missing,
                  ssl_prewrite_schedule_validation(NULL, 100, 20),
                  "an evicted shared handoff cannot emit a parent");

    http_info_t local = {
        .req_monotime_ns = 90,
        .ssl_prewrite_pending = k_ssl_prewrite_local_pending,
    };
    assert_int_eq(
        0,
        ssl_prewrite_local_owner_expired(
            local.ssl_prewrite_pending, local.start_monotime_ns, local.req_monotime_ns, 110, 20),
        "a provisional owner survives through the TTL boundary");
    assert_int_eq(
        1, ssl_prewrite_mark_local_blocked(&local), "the first collision is attributable");
    assert_int_eq(
        0, ssl_prewrite_mark_local_blocked(&local), "a repeated collision does not report again");
    assert_int_eq(
        1,
        ssl_prewrite_local_owner_expired(
            local.ssl_prewrite_pending, local.start_monotime_ns, local.req_monotime_ns, 111, 20),
        "an owner stranded by eviction becomes reclaimable");

    local = (http_info_t){
        .req_monotime_ns = 111,
        .ssl_prewrite_pending = k_ssl_prewrite_local_pending,
    };
    assert_int_eq(
        0,
        ssl_prewrite_local_owner_expired(
            local.ssl_prewrite_pending, local.start_monotime_ns, local.req_monotime_ns, 112, 20),
        "the next request can establish a fresh provisional owner");
}

static void test_failed_scheduled_owner_is_the_only_immediately_reclaimable_owner(void) {
    ssl_prewrite_value_t value = valid_ssl_prewrite();
    value.transport_phase = k_ssl_prewrite_transport_scheduled;
    value.arbitration = k_ssl_prewrite_arbitration_write_failed;
    assert_int_eq(1,
                  ssl_prewrite_owner_proven_failed(&value),
                  "a failed owner that has not reserved space is reclaimable");

    value.transport_phase = k_ssl_prewrite_transport_reserved;
    assert_int_eq(0,
                  ssl_prewrite_owner_proven_failed(&value),
                  "a reserved owner remains live until its callback resolves");
    value.transport_phase = k_ssl_prewrite_transport_scheduled;
    value.arbitration = k_ssl_prewrite_arbitration_failed_transport;
    assert_int_eq(0,
                  ssl_prewrite_owner_proven_failed(&value),
                  "an ambiguous cross-CPU outcome is retained fail closed");
}

static void test_connection_mapping_requires_exact_socket_owner(void) {
    pid_connection_info_t conn = connection(42);
    ssl_pid_connection_info_t stored = {.p_conn = conn};

    assert_int_eq(1,
                  ssl_connection_mapping_matches(&stored, &conn),
                  "exact socket owner can retain its mapping");

    pid_connection_info_t other = conn;
    other.conn.d_addr[3]++;
    assert_int_eq(0,
                  ssl_connection_mapping_matches(&stored, &other),
                  "another address cannot retain the mapping");
}

static void test_java_tls_marker_requires_exact_nonempty_tuple(void) {
    reset();
    connection_info_t authoritative = {.s_port = 443, .d_port = 49152};
    connection_info_t claimed = authoritative;

    mark_java_tls_connection(&claimed, &authoritative, 42);

    assert_int_eq(1, test_active_update_count, "matching tuple records a Java TLS marker");
    assert_int_eq(BPF_NOEXIST, (int)test_update_flags, "marker never overwrites SSL state");
    assert_int_eq(42, (int)test_updated_connection.pid, "marker records the current process");
    assert_int_eq(
        49152, test_updated_connection.conn.s_port, "marker sorts the authoritative tuple");
    assert_int_eq(
        443, test_updated_connection.conn.d_port, "marker keeps the server port after sorting");
    assert_int_eq(0, (int)test_updated_ssl, "marker uses the reserved zero SSL value");

    reset();
    claimed.d_port++;
    mark_java_tls_connection(&claimed, &authoritative, 42);
    assert_int_eq(0, test_active_update_count, "mismatched tuple is rejected");

    reset();
    claimed = (connection_info_t){};
    mark_java_tls_connection(&claimed, &authoritative, 42);
    assert_int_eq(0, test_active_update_count, "empty tuple is rejected");
}

static void test_java_tls_marker_does_not_replace_native_ssl(void) {
    reset();
    connection_info_t authoritative = {.s_port = 443, .d_port = 49152};
    test_ssl = 0x1234;
    test_ssl_present = 1;

    mark_java_tls_connection(&authoritative, &authoritative, 42);

    assert_int_eq(1, test_active_update_count, "existing state receives a guarded update");
    assert_int_eq(0x1234, (int)test_ssl, "native SSL pointer is not replaced");
}

int main(void) {
    test_terminal_cleanup_deletes_owned_reverse_mapping();
    test_terminal_cleanup_preserves_foreign_reverse_mapping();
    test_terminal_cleanup_ignores_same_pointer_from_another_process();
    test_terminal_cleanup_deletes_java_tls_marker();
    test_terminal_cleanup_ignores_plaintext_connection();
    test_arbitration_covers_all_legal_interleavings();
    test_arbitration_transitions_and_unexpected_states_fail_closed();
    test_prewrite_key_requires_handoff_identity();
    test_prewrite_reset_requires_exact_thread_and_handoff();
    test_prewrite_value_requires_exact_connection();
    test_prewrite_publication_is_exclusive_and_fails_when_full();
    test_target_sequence_is_written_once();
    test_completion_waits_for_both_outcomes();
    test_completion_delete_can_be_retried();
    test_expiry_rejects_missing_zero_future_and_old_values();
    test_prewrite_schedule_validation_classifies_every_failure_domain();
    test_prewrite_structural_validation_rejects_malformed_trace_state();
    test_prewrite_transport_accepts_delayed_success_and_rejects_local_mismatch();
    test_http_request_start_preserves_its_direction();
    test_http_response_status_requires_decimal_digits();
    test_response_completion_is_required_for_connection_reuse();
    test_connection_replacement_requires_response_completion();
    test_connection_tracking_requires_existing_bridge_state();
    test_blocked_owner_is_cleaned_on_connection_close();
    test_close_does_not_steal_an_active_publication_claim();
    test_close_falls_back_to_owner_and_claim_when_tombstones_are_full();
    test_publisher_completes_a_contended_close_without_another_callback();
    test_durable_close_fences_a_publisher_paused_before_its_claim();
    test_durable_close_fences_a_blocker_paused_before_its_claim();
    test_block_during_close_release_cannot_resurrect_state();
    test_close_during_block_release_needs_no_later_callback();
    test_lru_eviction_fails_open_and_stale_local_owner_recovers();
    test_failed_scheduled_owner_is_the_only_immediately_reclaimable_owner();
    test_connection_mapping_requires_exact_socket_owner();
    test_java_tls_marker_requires_exact_nonempty_tuple();
    test_java_tls_marker_does_not_replace_native_ssl();
    return 0;
}
