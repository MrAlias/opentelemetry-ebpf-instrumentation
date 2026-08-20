// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>

enum { BPF_ANY = 0, BPF_NOEXIST = 1, BPF_EXIST = 2 };
#define BPF_F_NO_PREALLOC 1

#define OBI_TEST_TASK_START_TIME_HELPERS
static inline uint64_t task_process_start_time(void) {
    return 77;
}

static inline uint64_t task_thread_start_time(void) {
    return 88;
}

struct bpf_test_map {
    int id;
};

static void *test_map_lookup(void *map, const void *key);
static long test_map_update(void *map, const void *key, const void *val, unsigned long long flags);
static long test_map_delete(void *map, const void *key);
static long test_probe_read(void *dst, unsigned int size, const void *src);
static uint64_t test_ktime_get_ns(void);

#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update
#define bpf_map_delete_elem test_map_delete
#define bpf_probe_read test_probe_read
#define bpf_ktime_get_ns test_ktime_get_ns

#define OBI_TEST_PROTOCOL_HTTP_SSL_LIFECYCLE
#include <generictracer/ssl_defs.h>
#undef OBI_TEST_PROTOCOL_HTTP_SSL_LIFECYCLE

#undef bpf_map_lookup_elem
#undef bpf_map_update_elem
#undef bpf_map_delete_elem
#undef bpf_probe_read
#undef bpf_ktime_get_ns

struct bpf_test_map ssl_to_conn = {.id = 1};
struct bpf_test_map pid_tid_to_conn = {.id = 2};
struct bpf_test_map ssl_to_pid_tid = {.id = 3};
struct bpf_test_map ongoing_http = {.id = 4};

int test_parser_call_count;
int test_last_parser_bytes_len;
u8 test_last_ssl;
u8 test_last_direction;
u16 test_last_orig_dport;
pid_connection_info_t test_last_connection;
int test_prewrite_parser_call_count;
int test_finish_http_count;
int test_terminate_http_count;
pid_connection_info_t test_terminated_connection;
int test_delete_server_trace_count;
pid_connection_info_t test_deleted_server_connection;
trace_key_t test_deleted_server_key;
u8 test_http_will_complete;
int test_large_buffer_init_count;
pid_connection_info_t test_large_buffer_connection;
u64 test_large_buffer_address;
u32 test_large_buffer_bytes_len;
u8 test_large_buffer_packet_type;
u8 test_large_buffer_direction;
u8 test_large_buffer_action;

static int ssl_pid_tid_delete_count;
static int pid_tid_delete_count;
static int ssl_to_conn_update_count;
static int ssl_to_conn_delete_count;
static int active_ssl_update_count;
static int active_ssl_delete_count;
static int operation_sequence;
static int ssl_to_conn_update_sequence;
static int pid_tid_delete_sequence;
static ssl_pid_connection_info_t test_ssl_conn;
static ssl_pid_connection_info_t test_pid_tid_conn;
static int test_ssl_conn_available;
static int test_ssl_conn_update_error;
static u64 test_ssl_ptr;
static ssl_pid_key_t test_updated_ssl_key;
static ssl_pid_key_t test_deleted_ssl_key;
static ssl_pid_key_t test_deleted_ssl_owner_key;
static pid_connection_info_t test_active_ssl_connection;
static u64 test_active_ssl_ptr;
static int test_active_ssl_available;
static int test_active_ssl_update_error;
static u64 test_mapped_pid_tid;
static u64 test_deleted_pid_tid;
static ssl_thread_key_t test_ssl_owner;
static int test_mapped_pid_tid_available;
static http_info_t test_http_info;
int test_http_info_available;
static pid_connection_info_t test_http_connection;
static int ongoing_http_delete_count;
static pid_connection_info_t test_deleted_http_connection;
static ssl_prewrite_value_t test_prewrite;
static connection_info_netns_cookie_t test_connection_key_scratch;
static ssl_prewrite_connection_owner_t test_owner_candidate_scratch;
static ssl_prewrite_connection_owner_t test_claim_candidate_scratch;
static ssl_prewrite_connection_owner_t test_block_claim_scratch;
static ssl_prewrite_connection_owner_t test_cleanup_claim_scratch;
static ssl_prewrite_connection_ambiguity_t test_ambiguity_candidate_scratch;
static ssl_prewrite_key_t test_prewrite_key;
static int test_prewrite_available;
static int test_prewrite_lookup_count;
static int test_prewrite_delete_count;
static ssl_prewrite_connection_owner_t test_connection_owner;
static int test_connection_owner_available;
static u64 test_java_stats[k_java_remote_parent_stat_max];

static void assert_int_eq(int expected, int actual, const char *message) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected %d, got %d\n", message, expected, actual);
        exit(1);
    }
}

static void assert_u16_eq(u16 expected, u16 actual, const char *message) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected %u, got %u\n", message, expected, actual);
        exit(1);
    }
}

static void assert_u64_eq(u64 expected, u64 actual, const char *message) {
    if (expected != actual) {
        fprintf(stderr,
                "FAIL: %s\n  expected %llu, got %llu\n",
                message,
                (unsigned long long)expected,
                (unsigned long long)actual);
        exit(1);
    }
}

static void *test_map_lookup(void *map, const void *key) {
    if (map == &java_remote_parent_stats) {
        const u32 stat = *(const u32 *)key;
        return stat < k_java_remote_parent_stat_max ? &test_java_stats[stat] : NULL;
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

    if (map == &ssl_prewrite_tp) {
        test_prewrite_lookup_count++;
        if (test_prewrite_available &&
            memcmp(key, &test_prewrite_key, sizeof(test_prewrite_key)) == 0) {
            return &test_prewrite;
        }
        return NULL;
    }

    if (map == &ssl_prewrite_connection_owners && test_connection_owner_available) {
        return &test_connection_owner;
    }

    if (map == &active_ssl_connections) {
        if (test_active_ssl_available &&
            memcmp(key, &test_active_ssl_connection, sizeof(test_active_ssl_connection)) == 0) {
            return &test_active_ssl_ptr;
        }
        return NULL;
    }

    if (map == &ssl_to_conn) {
        const ssl_pid_key_t *ssl_key = key;
        if (test_ssl_conn_available && ssl_key->ssl == test_ssl_ptr &&
            ssl_key->pid == test_ssl_conn.p_conn.pid && ssl_key->process_start_time == 77) {
            return &test_ssl_conn;
        }
        return NULL;
    }

    if (map == &pid_tid_to_conn) {
        const ssl_thread_key_t *thread_key = key;
        if (test_mapped_pid_tid_available && thread_key->pid_tgid == test_mapped_pid_tid &&
            thread_key->thread_start_time == 88) {
            return &test_pid_tid_conn;
        }
        return NULL;
    }

    if (map == &ssl_to_pid_tid) {
        const ssl_pid_key_t *ssl_key = key;
        if (test_mapped_pid_tid_available && ssl_key->ssl == test_ssl_ptr &&
            ssl_key->pid == (u32)(test_mapped_pid_tid >> 32) && ssl_key->process_start_time == 77) {
            test_ssl_owner = (ssl_thread_key_t){
                .pid_tgid = test_mapped_pid_tid,
                .thread_start_time = 88,
            };
            return &test_ssl_owner;
        }
        return NULL;
    }

    if (map == &ongoing_http && test_http_info_available &&
        memcmp(key, &test_http_connection, sizeof(test_http_connection)) == 0) {
        return &test_http_info;
    }

    return NULL;
}

static long test_map_update(void *map, const void *key, const void *val, unsigned long long flags) {
    (void)flags;

    if (map == &ssl_to_conn) {
        ssl_to_conn_update_count++;
        ssl_to_conn_update_sequence = ++operation_sequence;
        if (test_ssl_conn_update_error) {
            return -1;
        }
        __builtin_memcpy(&test_updated_ssl_key, key, sizeof(test_updated_ssl_key));
        __builtin_memcpy(&test_ssl_conn, val, sizeof(test_ssl_conn));
        test_ssl_conn_available = 1;
    } else if (map == &active_ssl_connections) {
        active_ssl_update_count++;
        if (test_active_ssl_update_error) {
            return -1;
        }
        __builtin_memcpy(&test_active_ssl_connection, key, sizeof(test_active_ssl_connection));
        __builtin_memcpy(&test_active_ssl_ptr, val, sizeof(test_active_ssl_ptr));
        test_active_ssl_available = 1;
    }

    return 0;
}

static long test_map_delete(void *map, const void *key) {
    if (map == &ssl_to_pid_tid) {
        ssl_pid_tid_delete_count++;
        __builtin_memcpy(&test_deleted_ssl_owner_key, key, sizeof(test_deleted_ssl_owner_key));
    } else if (map == &ssl_to_conn) {
        ssl_to_conn_delete_count++;
        __builtin_memcpy(&test_deleted_ssl_key, key, sizeof(test_deleted_ssl_key));
        test_ssl_conn_available = 0;
    } else if (map == &active_ssl_connections) {
        active_ssl_delete_count++;
        test_active_ssl_available = 0;
    } else if (map == &pid_tid_to_conn) {
        const ssl_thread_key_t *thread_key = key;
        pid_tid_delete_count++;
        pid_tid_delete_sequence = ++operation_sequence;
        test_deleted_pid_tid = thread_key->pid_tgid;
        test_pid_tid_conn = (ssl_pid_connection_info_t){};
        test_mapped_pid_tid_available = 0;
    } else if (map == &ongoing_http &&
               memcmp(key, &test_http_connection, sizeof(test_http_connection)) == 0) {
        ongoing_http_delete_count++;
        test_deleted_http_connection = *(const pid_connection_info_t *)key;
        test_http_info_available = 0;
    } else if (map == &ssl_prewrite_tp && test_prewrite_available &&
               memcmp(key, &test_prewrite_key, sizeof(test_prewrite_key)) == 0) {
        test_prewrite_delete_count++;
        test_prewrite_available = 0;
    }

    return 0;
}

static long test_probe_read(void *dst, unsigned int size, const void *src) {
    if (dst && src && size > 0) {
        __builtin_memcpy(dst, src, size);
    }
    return 0;
}

static uint64_t test_ktime_get_ns(void) {
    return 100;
}

static void reset(void) {
    test_parser_call_count = 0;
    test_last_parser_bytes_len = 0;
    test_last_ssl = 0;
    test_last_direction = 0;
    test_last_orig_dport = 0;
    test_last_connection = (pid_connection_info_t){};
    test_prewrite_parser_call_count = 0;
    test_finish_http_count = 0;
    test_terminate_http_count = 0;
    test_terminated_connection = (pid_connection_info_t){};
    test_delete_server_trace_count = 0;
    test_deleted_server_connection = (pid_connection_info_t){};
    test_deleted_server_key = (trace_key_t){};
    test_http_will_complete = 0;
    test_large_buffer_init_count = 0;
    test_large_buffer_connection = (pid_connection_info_t){};
    test_large_buffer_address = 0;
    test_large_buffer_bytes_len = 0;
    test_large_buffer_packet_type = 0;
    test_large_buffer_direction = 0;
    test_large_buffer_action = k_large_buf_action_init;
    ssl_pid_tid_delete_count = 0;
    pid_tid_delete_count = 0;
    ssl_to_conn_update_count = 0;
    ssl_to_conn_delete_count = 0;
    active_ssl_update_count = 0;
    active_ssl_delete_count = 0;
    operation_sequence = 0;
    ssl_to_conn_update_sequence = 0;
    pid_tid_delete_sequence = 0;
    test_ssl_conn = (ssl_pid_connection_info_t){};
    test_pid_tid_conn = (ssl_pid_connection_info_t){};
    test_ssl_conn_available = 0;
    test_ssl_conn_update_error = 0;
    test_ssl_ptr = 0x1234;
    test_updated_ssl_key = (ssl_pid_key_t){};
    test_deleted_ssl_key = (ssl_pid_key_t){};
    test_deleted_ssl_owner_key = (ssl_pid_key_t){};
    test_active_ssl_connection = (pid_connection_info_t){};
    test_active_ssl_ptr = 0;
    test_active_ssl_available = 0;
    test_active_ssl_update_error = 0;
    test_mapped_pid_tid = 0;
    test_deleted_pid_tid = 0;
    test_ssl_owner = (ssl_thread_key_t){};
    test_mapped_pid_tid_available = 0;
    test_http_info = (http_info_t){};
    test_http_info_available = 0;
    test_http_connection = (pid_connection_info_t){};
    ongoing_http_delete_count = 0;
    test_deleted_http_connection = (pid_connection_info_t){};
    test_prewrite = (ssl_prewrite_value_t){};
    test_connection_key_scratch = (connection_info_netns_cookie_t){};
    test_owner_candidate_scratch = (ssl_prewrite_connection_owner_t){};
    test_claim_candidate_scratch = (ssl_prewrite_connection_owner_t){};
    test_block_claim_scratch = (ssl_prewrite_connection_owner_t){};
    test_cleanup_claim_scratch = (ssl_prewrite_connection_owner_t){};
    test_ambiguity_candidate_scratch = (ssl_prewrite_connection_ambiguity_t){};
    test_prewrite_key = (ssl_prewrite_key_t){};
    test_prewrite_available = 0;
    test_prewrite_lookup_count = 0;
    test_prewrite_delete_count = 0;
    test_connection_owner = (ssl_prewrite_connection_owner_t){};
    test_connection_owner_available = 0;
    __builtin_memset(test_java_stats, 0, sizeof(test_java_stats));
}

static ssl_args_t ssl_args(void) {
    return (ssl_args_t){
        .ssl = test_ssl_ptr,
        .buf = 0x4321,
        .handoff_id = 99,
        .requested_len = 64,
    };
}

static void seed_existing_ssl_connection(u16 orig_dport) {
    test_ssl_conn_available = 1;
    test_ssl_conn.orig_dport = orig_dport;
    test_ssl_conn.p_conn.pid = 42;
    test_active_ssl_available = 1;
    test_active_ssl_connection = test_ssl_conn.p_conn;
    test_active_ssl_ptr = test_ssl_ptr;
}

static ssl_args_t seed_finish_prewrite(enum ssl_prewrite_transport_phase phase, u32 arbitration) {
    ssl_args_t args = ssl_args();
    args.flags = FLAG_SSL_PREWRITE_PUBLISHED;

    test_http_connection.pid = 42;
    test_http_connection.conn.s_port = 443;
    test_http_connection.conn.d_port = 49152;
    test_http_info_available = 1;
    test_http_info.type = EVENT_HTTP_CLIENT;
    test_http_info.ssl = WITH_SSL;
    test_http_info.direction = TCP_SEND;
    test_http_info.start_monotime_ns = 1;
    test_http_info.ssl_prewrite_pending = k_ssl_prewrite_local_pending;
    test_http_info.tp.trace_id[0] = 1;
    test_http_info.tp.span_id[0] = 2;

    test_prewrite_available = 1;
    test_prewrite_key = ssl_prewrite_key(0x2a00000001ULL, 88, args.handoff_id);
    test_connection_owner = (ssl_prewrite_connection_owner_t){
        .key = test_prewrite_key,
        .observed_monotime_ns = 90,
        .state = k_ssl_prewrite_connection_owner_published,
    };
    test_connection_owner_available = 1;
    test_prewrite.connection = test_http_connection;
    test_prewrite.netns_cookie = 7;
    test_prewrite.ssl = args.ssl;
    test_prewrite.buffer = args.buf;
    test_prewrite.bytes_len = 64;
    test_prewrite.destination_port = 443;
    test_prewrite.transport_phase = phase;
    test_prewrite.arbitration = arbitration;
    test_prewrite.trace.pid = 42;
    test_prewrite.trace.valid = 1;
    test_prewrite.trace.req_type = EVENT_HTTP_CLIENT;
    tp_info_pid_set_provenance(&test_prewrite.trace, k_tp_provenance_ssl_prewrite);
    test_prewrite.trace.tp = test_http_info.tp;
    return args;
}

static void test_successful_published_write_initializes_large_buffer(void) {
    reset();
    ssl_args_t args =
        seed_finish_prewrite(k_ssl_prewrite_transport_none, k_ssl_prewrite_arbitration_none);

    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 64, TCP_SEND);

    assert_int_eq(1, test_large_buffer_init_count, "successful prewrite initializes one buffer");
    assert_u64_eq(args.buf, test_large_buffer_address, "buffer init uses the staged header");
    assert_int_eq(64, (int)test_large_buffer_bytes_len, "buffer init uses the written length");
    assert_int_eq(
        PACKET_TYPE_REQUEST, test_large_buffer_packet_type, "buffer init records a request");
    assert_int_eq(TCP_SEND, test_large_buffer_direction, "buffer init records send direction");
    assert_int_eq(
        k_large_buf_action_init, test_large_buffer_action, "buffer init does not append an orphan");
    assert_int_eq(0, test_parser_call_count, "published write is not parsed a second time");
    if (memcmp(&test_large_buffer_connection,
               &test_http_connection,
               sizeof(test_http_connection)) != 0) {
        fprintf(stderr, "FAIL: buffer init uses the published connection\n");
        exit(1);
    }
}

static void test_terminal_transport_success_initializes_after_local_commit(void) {
    reset();
    ssl_args_t args = seed_finish_prewrite(k_ssl_prewrite_transport_accepted,
                                           k_ssl_prewrite_arbitration_transport_may_emit);

    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 64, TCP_SEND);

    assert_int_eq(0, test_http_info.ssl_prewrite_pending, "terminal transport commits local state");
    assert_int_eq(
        1, test_large_buffer_init_count, "committed prewrite still initializes its request buffer");
}

static void test_failed_published_writes_do_not_initialize_large_buffer(void) {
    reset();
    ssl_args_t args =
        seed_finish_prewrite(k_ssl_prewrite_transport_none, k_ssl_prewrite_arbitration_none);
    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 0, TCP_SEND);
    assert_int_eq(0, test_large_buffer_init_count, "failed write emits no buffer init");

    reset();
    args = seed_finish_prewrite(k_ssl_prewrite_transport_none, k_ssl_prewrite_arbitration_none);
    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 32, TCP_SEND);
    assert_int_eq(0, test_large_buffer_init_count, "short write emits no buffer init");

    reset();
    args = seed_finish_prewrite(k_ssl_prewrite_transport_none, k_ssl_prewrite_arbitration_none);
    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 65, TCP_SEND);
    assert_int_eq(0, test_large_buffer_init_count, "oversized write emits no buffer init");
}

static void test_foreign_or_missing_prewrite_does_not_initialize_large_buffer(void) {
    reset();
    ssl_args_t args =
        seed_finish_prewrite(k_ssl_prewrite_transport_none, k_ssl_prewrite_arbitration_none);
    test_http_info.tp.span_id[0]++;
    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 64, TCP_SEND);
    assert_int_eq(0, test_large_buffer_init_count, "foreign local request emits no buffer init");

    reset();
    args = seed_finish_prewrite(k_ssl_prewrite_transport_none, k_ssl_prewrite_arbitration_none);
    test_http_info.ssl_prewrite_pending = k_ssl_prewrite_local_blocked;
    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 64, TCP_SEND);
    assert_int_eq(0, test_large_buffer_init_count, "blocked local request emits no buffer init");

    reset();
    args = ssl_args();
    args.flags = FLAG_SSL_PREWRITE_PUBLISHED;
    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 64, TCP_SEND);
    assert_int_eq(0, test_large_buffer_init_count, "missing prewrite emits no buffer init");
}

static void test_successful_prewrite_waits_for_delayed_transport(void) {
    reset();
    ssl_args_t args =
        seed_finish_prewrite(k_ssl_prewrite_transport_none, k_ssl_prewrite_arbitration_none);

    assert_int_eq(
        1,
        finish_ssl_prewrite(0x2a00000001ULL, &args, 1, 64, k_java_remote_parent_stat_inject_stale),
        "a published write return is handled");
    assert_int_eq(k_ssl_prewrite_local_pending,
                  test_http_info.ssl_prewrite_pending,
                  "success retains local ownership until delayed transport");
    assert_int_eq(0, ongoing_http_delete_count, "success does not discard the local request");
    assert_int_eq(k_ssl_prewrite_write_succeeded,
                  test_prewrite.write_outcome,
                  "success records its write outcome");
    assert_int_eq(0, test_prewrite_delete_count, "success retains the connection handoff");
}

static void test_failed_prewrite_without_transport_discards_local_state(void) {
    reset();
    ssl_args_t args =
        seed_finish_prewrite(k_ssl_prewrite_transport_none, k_ssl_prewrite_arbitration_none);

    finish_ssl_prewrite(0x2a00000001ULL, &args, 0, 0, k_java_remote_parent_stat_inject_stale);

    assert_int_eq(1, ongoing_http_delete_count, "failure before transport discards local state");
    assert_int_eq(k_ssl_prewrite_write_failed,
                  test_prewrite.write_outcome,
                  "failure records its write outcome");
    assert_int_eq(k_ssl_prewrite_arbitration_write_failed,
                  (int)test_prewrite.arbitration,
                  "failure claims the write-only arbitration state");
    assert_int_eq(0, test_prewrite_delete_count, "failure is retained for close-path cleanup");
}

static void test_transport_first_failure_retains_and_commits_local_state(void) {
    reset();
    ssl_args_t args = seed_finish_prewrite(k_ssl_prewrite_transport_emitting,
                                           k_ssl_prewrite_arbitration_transport_may_emit);

    finish_ssl_prewrite(0x2a00000001ULL, &args, 0, 0, k_java_remote_parent_stat_inject_stale);

    assert_int_eq(0, ongoing_http_delete_count, "transport-first failure retains local state");
    assert_int_eq(0,
                  test_http_info.ssl_prewrite_pending,
                  "transport-first failure commits the local request");
    assert_int_eq(k_ssl_prewrite_arbitration_failed_transport,
                  (int)test_prewrite.arbitration,
                  "transport-first failure converges on state three");
    assert_int_eq(
        0, test_prewrite_delete_count, "nonterminal transport retains the shared handoff");
}

static void test_terminal_transport_failure_commits_then_cleans_shared_state(void) {
    reset();
    ssl_args_t args = seed_finish_prewrite(k_ssl_prewrite_transport_accepted,
                                           k_ssl_prewrite_arbitration_transport_may_emit);

    finish_ssl_prewrite(0x2a00000001ULL, &args, 0, 0, k_java_remote_parent_stat_inject_stale);

    assert_int_eq(0, ongoing_http_delete_count, "accepted transport retains local state");
    assert_int_eq(0, test_http_info.ssl_prewrite_pending, "accepted transport commits local state");
    assert_int_eq(0, test_prewrite_delete_count, "the connection owner retains terminal state");
}

static void test_oversized_success_is_treated_as_a_failed_write(void) {
    reset();
    ssl_args_t args =
        seed_finish_prewrite(k_ssl_prewrite_transport_none, k_ssl_prewrite_arbitration_none);

    finish_ssl_prewrite(0x2a00000001ULL,
                        &args,
                        1,
                        test_prewrite.bytes_len + 1,
                        k_java_remote_parent_stat_inject_stale);

    assert_int_eq(1, ongoing_http_delete_count, "an impossible write length discards local state");
    assert_int_eq(k_ssl_prewrite_write_failed,
                  test_prewrite.write_outcome,
                  "an impossible write length records failure");
    assert_int_eq(0, test_prewrite_delete_count, "an impossible write remains blocked until close");
    assert_int_eq(1,
                  (int)test_java_stats[k_java_remote_parent_stat_inject_malformed],
                  "an impossible write reports one malformed outcome");
}

static void test_short_positive_write_blocks_connection(void) {
    reset();
    ssl_args_t args =
        seed_finish_prewrite(k_ssl_prewrite_transport_none, k_ssl_prewrite_arbitration_none);

    finish_ssl_prewrite(0x2a00000001ULL,
                        &args,
                        1,
                        test_prewrite.bytes_len / 2,
                        k_java_remote_parent_stat_inject_stale);

    assert_int_eq(1, ongoing_http_delete_count, "a short write discards speculative local state");
    assert_int_eq(k_ssl_prewrite_write_failed,
                  test_prewrite.write_outcome,
                  "a short write records an ambiguous failure");
    assert_int_eq(0, test_prewrite_delete_count, "a short write remains blocked until close");
    assert_int_eq(1,
                  (int)test_java_stats[k_java_remote_parent_stat_inject_malformed],
                  "a short write reports one malformed outcome");
}

static void test_transport_first_short_write_retains_emitted_local_state(void) {
    reset();
    ssl_args_t args = seed_finish_prewrite(k_ssl_prewrite_transport_emitting,
                                           k_ssl_prewrite_arbitration_transport_may_emit);

    finish_ssl_prewrite(0x2a00000001ULL,
                        &args,
                        1,
                        test_prewrite.bytes_len / 2,
                        k_java_remote_parent_stat_inject_stale);

    assert_int_eq(
        0, ongoing_http_delete_count, "a parent already emitted by transport keeps its local span");
    assert_int_eq(0,
                  test_http_info.ssl_prewrite_pending,
                  "transport-first short write commits the unavoidable local span");
    assert_int_eq(k_ssl_prewrite_arbitration_failed_transport,
                  (int)test_prewrite.arbitration,
                  "transport-first short write is marked ambiguous");
    assert_int_eq(1,
                  (int)test_java_stats[k_java_remote_parent_stat_inject_malformed],
                  "transport-first short write reports malformed exactly once");
    assert_int_eq(0,
                  (int)test_java_stats[k_java_remote_parent_stat_inject_ambiguous],
                  "transport-first short write does not double-report ambiguity");
}

static void test_missing_prewrite_is_handled_without_touching_local_state(void) {
    reset();
    ssl_args_t args = ssl_args();
    args.flags = FLAG_SSL_PREWRITE_PUBLISHED;
    test_http_info_available = 1;
    test_http_info.ssl_prewrite_pending = 1;

    assert_int_eq(
        1,
        finish_ssl_prewrite(0x2a00000001ULL, &args, 0, 0, k_java_remote_parent_stat_inject_stale),
        "a missing published handoff is still handled");
    assert_int_eq(1, test_http_info.ssl_prewrite_pending, "missing state is not guessed locally");
    assert_int_eq(0, ongoing_http_delete_count, "missing state deletes no local request");
    assert_int_eq(1, test_prewrite_lookup_count, "missing state performs one exact lookup");
}

static void test_malformed_prewrite_discards_its_exact_provisional_owner(void) {
    reset();
    ssl_args_t args =
        seed_finish_prewrite(k_ssl_prewrite_transport_none, k_ssl_prewrite_arbitration_none);
    args.buf++;

    finish_ssl_prewrite(0x2a00000001ULL, &args, 0, 0, k_java_remote_parent_stat_inject_stale);

    assert_int_eq(1, ongoing_http_delete_count, "malformed state discards its exact local owner");
    assert_int_eq(0, test_prewrite_delete_count, "malformed state remains blocked until close");
    assert_int_eq(1,
                  (int)test_java_stats[k_java_remote_parent_stat_inject_malformed],
                  "malformed state reports one attributable failure");
    assert_int_eq(k_ssl_prewrite_arbitration_write_failed,
                  (int)test_prewrite.arbitration,
                  "malformed state poisons transport arbitration");
    ssl_prewrite_mark_transport_may_emit(&test_prewrite);
    assert_int_eq(0,
                  ssl_prewrite_transport_may_emit(ssl_prewrite_arbitration_state(&test_prewrite)),
                  "transport cannot emit a malformed handoff");
}

static void test_local_trace_mismatch_is_neither_committed_nor_discarded(void) {
    reset();
    ssl_args_t args =
        seed_finish_prewrite(k_ssl_prewrite_transport_none, k_ssl_prewrite_arbitration_none);
    test_http_info.tp.span_id[0]++;

    finish_ssl_prewrite(0x2a00000001ULL, &args, 1, 64, k_java_remote_parent_stat_inject_stale);

    assert_int_eq(1, test_http_info.ssl_prewrite_pending, "foreign local state is not committed");
    assert_int_eq(0, ongoing_http_delete_count, "foreign local state is not discarded");
    assert_int_eq(0, test_prewrite_delete_count, "delayed shared state remains owned");
}

static void test_local_shape_mismatch_is_neither_committed_nor_discarded(void) {
    static const char *const messages[] = {
        "foreign request type is not committed",
        "foreign SSL marker is not committed",
        "foreign direction is not committed",
        "uninitialized request is not committed",
    };

    for (u32 field = 0; field < sizeof(messages) / sizeof(messages[0]); field++) {
        reset();
        ssl_args_t args =
            seed_finish_prewrite(k_ssl_prewrite_transport_none, k_ssl_prewrite_arbitration_none);
        if (field == 0) {
            test_http_info.type = EVENT_HTTP_REQUEST;
        } else if (field == 1) {
            test_http_info.ssl = NO_SSL;
        } else if (field == 2) {
            test_http_info.direction = TCP_RECV;
        } else {
            test_http_info.start_monotime_ns = 0;
        }

        finish_ssl_prewrite(0x2a00000001ULL, &args, 1, 64, k_java_remote_parent_stat_inject_stale);

        assert_int_eq(
            k_ssl_prewrite_local_pending, test_http_info.ssl_prewrite_pending, messages[field]);
        assert_int_eq(0, ongoing_http_delete_count, "foreign local shape is not discarded");
        assert_int_eq(0, test_prewrite_delete_count, "delayed shared state remains owned");
    }
}

static void test_structurally_malformed_postwrite_is_reported(void) {
    reset();
    ssl_args_t args =
        seed_finish_prewrite(k_ssl_prewrite_transport_none, k_ssl_prewrite_arbitration_none);
    test_prewrite.trace.valid = 0;

    finish_ssl_prewrite(0x2a00000001ULL, &args, 1, 64, k_java_remote_parent_stat_inject_stale);

    assert_int_eq(k_ssl_prewrite_local_pending,
                  test_http_info.ssl_prewrite_pending,
                  "malformed shared state cannot commit a local owner");
    assert_int_eq(
        0, ongoing_http_delete_count, "malformed shared state cannot discard local state");
    assert_int_eq(0, test_prewrite_delete_count, "malformed shared state remains blocked");
    assert_int_eq(1,
                  (int)test_java_stats[k_java_remote_parent_stat_inject_malformed],
                  "malformed postwrite state is classified once");
    assert_int_eq(0,
                  (int)test_java_stats[k_java_remote_parent_stat_inject_missing],
                  "malformed postwrite state is not classified as missing");
}

static void test_failed_read_skips_parser_after_cleanup(void) {
    reset();
    seed_existing_ssl_connection(443);
    ssl_args_t args = ssl_args();

    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, -1, TCP_RECV);

    assert_int_eq(1, ssl_pid_tid_delete_count, "ssl_to_pid_tid entry is deleted on error");
    assert_int_eq(0, ssl_to_conn_update_count, "failed read does not create connection info");
    assert_int_eq(0, test_parser_call_count, "failed read does not enter protocol parsing");
}

static void test_eof_read_skips_parser_after_cleanup(void) {
    reset();
    seed_existing_ssl_connection(443);
    ssl_args_t args = ssl_args();

    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 0, TCP_RECV);

    assert_int_eq(1, ssl_pid_tid_delete_count, "ssl_to_pid_tid entry is deleted on EOF");
    assert_int_eq(0, ssl_to_conn_update_count, "EOF read does not create connection info");
    assert_int_eq(0, test_parser_call_count, "EOF read does not enter protocol parsing");
}

static void test_successful_read_still_parses(void) {
    reset();
    seed_existing_ssl_connection(443);
    ssl_args_t args = ssl_args();

    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 1, TCP_RECV);

    assert_int_eq(1, ssl_pid_tid_delete_count, "ssl_to_pid_tid entry is deleted on success");
    assert_int_eq(0, ssl_to_conn_update_count, "existing connection is reused");
    assert_int_eq(1, test_parser_call_count, "successful read enters protocol parsing");
    assert_int_eq(1, test_last_parser_bytes_len, "successful read forwards the read length");
    assert_int_eq(WITH_SSL, test_last_ssl, "successful read is marked as SSL");
    assert_int_eq(TCP_RECV, test_last_direction, "successful read preserves direction");
    assert_u16_eq(443, test_last_orig_dport, "successful read preserves original dport");
}

static void test_failed_write_skips_parser_after_cleanup(void) {
    reset();
    seed_existing_ssl_connection(443);
    ssl_args_t args = ssl_args();

    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 0, TCP_SEND);

    assert_int_eq(1, ssl_pid_tid_delete_count, "ssl_to_pid_tid entry is deleted on failed write");
    assert_int_eq(0, ssl_to_conn_update_count, "failed write does not create connection info");
    assert_int_eq(0, test_parser_call_count, "failed write does not enter protocol parsing");
}

static void test_successful_write_still_parses(void) {
    reset();
    seed_existing_ssl_connection(443);
    ssl_args_t args = ssl_args();

    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 32, TCP_SEND);

    assert_int_eq(1, ssl_pid_tid_delete_count, "ssl_to_pid_tid entry is deleted on write success");
    assert_int_eq(0, ssl_to_conn_update_count, "existing connection is reused");
    assert_int_eq(1, test_parser_call_count, "successful write enters protocol parsing");
    assert_int_eq(32, test_last_parser_bytes_len, "successful write forwards the written length");
    assert_int_eq(WITH_SSL, test_last_ssl, "successful write is marked as SSL");
    assert_int_eq(TCP_SEND, test_last_direction, "successful write preserves direction");
    assert_u16_eq(443, test_last_orig_dport, "successful write preserves original dport");
}

static void test_prewrite_uses_existing_connection_without_cleanup(void) {
    reset();
    seed_existing_ssl_connection(443);
    ssl_args_t args = ssl_args();

    handle_ssl_prewrite(NULL, 0x2a00000001ULL, &args, 32);

    assert_int_eq(1, test_prewrite_parser_call_count, "prewrite enters context parsing");
    assert_int_eq(32, test_last_parser_bytes_len, "prewrite forwards the requested length");
    assert_int_eq(WITH_SSL, test_last_ssl, "prewrite is marked as SSL");
    assert_int_eq(TCP_SEND, test_last_direction, "prewrite is outbound");
    assert_u16_eq(443, test_last_orig_dport, "prewrite preserves original dport");
    assert_int_eq(0, ssl_pid_tid_delete_count, "prewrite retains cross-thread SSL mapping");
}

static void test_valid_cached_connection_ignores_conflicting_thread_hint(void) {
    reset();
    seed_existing_ssl_connection(443);
    test_ssl_conn.p_conn.conn = (connection_info_t){.s_port = 49152, .d_port = 443};
    test_active_ssl_connection = test_ssl_conn.p_conn;
    test_mapped_pid_tid = 0x2a00000001ULL;
    test_mapped_pid_tid_available = 1;
    test_pid_tid_conn = (ssl_pid_connection_info_t){
        .p_conn = {.conn = {.s_port = 49153, .d_port = 8443}, .pid = 42},
        .orig_dport = 8443,
    };
    ssl_args_t args = ssl_args();

    handle_ssl_prewrite(NULL, 0x2a00000001ULL, &args, 32);

    assert_int_eq(1, test_prewrite_parser_call_count, "valid cached state enters parsing");
    assert_u16_eq(443, test_last_orig_dport, "valid cached state remains authoritative");
    assert_u16_eq(
        49152, test_last_connection.conn.s_port, "the unrelated thread tuple is not selected");
    assert_int_eq(0, ssl_to_conn_update_count, "the reverse cache is not overwritten");
    assert_int_eq(0, active_ssl_update_count, "the forward cache is not overwritten");
    assert_int_eq(0, ssl_to_conn_delete_count, "the valid reverse cache is retained");
    assert_int_eq(0, active_ssl_delete_count, "the valid forward cache is retained");
    assert_int_eq(0, pid_tid_delete_count, "the unrelated thread hint remains untouched");
}

static void test_invalid_cached_connection_falls_back_to_thread_hint(void) {
    reset();
    seed_existing_ssl_connection(443);
    test_active_ssl_available = 0;
    test_mapped_pid_tid = 0x2a00000001ULL;
    test_mapped_pid_tid_available = 1;
    test_pid_tid_conn = (ssl_pid_connection_info_t){
        .p_conn = {.conn = {.s_port = 49153, .d_port = 8443}, .pid = 42},
        .orig_dport = 8443,
    };
    ssl_args_t args = ssl_args();

    handle_ssl_prewrite(NULL, 0x2a00000001ULL, &args, 32);

    assert_int_eq(1, test_prewrite_parser_call_count, "a live thread hint replaces stale cache");
    assert_u16_eq(8443, test_last_orig_dport, "fallback uses the live thread hint");
    assert_int_eq(1, ssl_to_conn_delete_count, "the stale reverse cache is deleted");
    assert_int_eq(1, ssl_to_conn_update_count, "the live thread hint is cached");
    assert_int_eq(1, active_ssl_update_count, "the live tuple gains a forward owner");
    assert_int_eq(1, pid_tid_delete_count, "the promoted thread hint is consumed");
}

static void test_prewrite_does_not_reuse_another_process_connection(void) {
    reset();
    seed_existing_ssl_connection(443);
    test_ssl_conn.p_conn.pid = 43;
    ssl_args_t args = ssl_args();

    handle_ssl_prewrite(NULL, 0x2a00000001ULL, &args, 32);

    assert_int_eq(0, test_prewrite_parser_call_count, "foreign process SSL state is ignored");
    assert_int_eq(0, ssl_to_conn_update_count, "foreign process SSL state is not recached");
}

static void test_prewrite_requires_positive_length_and_connection(void) {
    reset();
    ssl_args_t args = ssl_args();

    handle_ssl_prewrite(NULL, 0x2a00000001ULL, &args, 0);
    handle_ssl_prewrite(NULL, 0x2a00000001ULL, &args, -1);
    handle_ssl_prewrite(NULL, 0x2a00000001ULL, &args, 32);

    assert_int_eq(0, test_prewrite_parser_call_count, "invalid prewrites skip context parsing");
    assert_int_eq(0, ssl_to_conn_update_count, "prewrite does not invent a connection");
}

static void test_prewrite_caches_and_releases_cross_thread_connection(void) {
    reset();
    test_mapped_pid_tid = 0x2a00000002ULL;
    test_mapped_pid_tid_available = 1;
    test_pid_tid_conn.orig_dport = 8443;
    test_pid_tid_conn.p_conn.pid = 42;
    ssl_args_t args = ssl_args();

    handle_ssl_prewrite(NULL, 0x2a00000001ULL, &args, 64);

    assert_int_eq(1, ssl_to_conn_update_count, "prewrite caches the cross-thread connection");
    assert_int_eq(1, active_ssl_update_count, "prewrite records the terminal cleanup owner");
    assert_int_eq(1, test_prewrite_parser_call_count, "cross-thread prewrite enters parsing");
    assert_int_eq(1, pid_tid_delete_count, "prewrite releases the promoted thread connection");
    assert_int_eq(0, ssl_pid_tid_delete_count, "prewrite retains the SSL thread mapping");
    assert_u16_eq(8443, test_last_orig_dport, "cross-thread prewrite preserves dport");
}

static void test_prewrite_then_write_return_does_not_leak_source_connection(void) {
    reset();
    test_mapped_pid_tid = 0x2a00000002ULL;
    test_mapped_pid_tid_available = 1;
    test_pid_tid_conn.orig_dport = 8443;
    test_pid_tid_conn.p_conn.pid = 42;
    ssl_args_t args = ssl_args();

    handle_ssl_prewrite(NULL, 0x2a00000001ULL, &args, 64);
    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 64, TCP_SEND);

    assert_int_eq(1, pid_tid_delete_count, "prewrite releases the source exactly once");
    assert_int_eq(1, ssl_pid_tid_delete_count, "write return releases the SSL thread mapping");
    assert_int_eq(1, ssl_to_conn_update_count, "write return reuses the promoted connection");
    assert_int_eq(1, test_prewrite_parser_call_count, "prewrite parses once");
    assert_int_eq(1, test_parser_call_count, "write return parses once");
}

static void test_promoted_connection_is_cleaned_before_pointer_reuse(void) {
    reset();
    test_mapped_pid_tid = 0x2a00000002ULL;
    test_mapped_pid_tid_available = 1;
    test_pid_tid_conn.orig_dport = 8443;
    test_pid_tid_conn.p_conn = (pid_connection_info_t){
        .conn = {.s_port = 49152, .d_port = 443},
        .pid = 42,
    };
    const pid_connection_info_t first_connection = test_pid_tid_conn.p_conn;
    ssl_args_t args = ssl_args();

    handle_ssl_prewrite(NULL, 0x2a00000001ULL, &args, 64);
    cleanup_terminal_ssl_connection(&first_connection, 77, 7);

    assert_int_eq(1, ssl_to_conn_delete_count, "terminal close deletes the promoted reverse map");
    assert_int_eq(1, ssl_pid_tid_delete_count, "terminal close deletes the promoted thread owner");
    assert_int_eq(1, active_ssl_delete_count, "terminal close deletes the forward owner map");

    test_pid_tid_conn.orig_dport = 9443;
    test_pid_tid_conn.p_conn = (pid_connection_info_t){
        .conn = {.s_port = 49153, .d_port = 443},
        .pid = 42,
    };
    test_mapped_pid_tid_available = 1;
    handle_ssl_prewrite(NULL, 0x2a00000001ULL, &args, 64);

    assert_int_eq(2, ssl_to_conn_update_count, "reused pointer caches the new reverse mapping");
    assert_int_eq(2, active_ssl_update_count, "reused pointer records the new forward owner");
    assert_int_eq(2, test_prewrite_parser_call_count, "reused pointer parses both connections");
    assert_u16_eq(9443, test_last_orig_dport, "reused pointer uses the new connection");
}

static void test_ssl_reallocation_promotes_fresh_thread_connection(void) {
    reset();
    seed_existing_ssl_connection(443);
    test_ssl_conn.p_conn.conn = (connection_info_t){.s_port = 49152, .d_port = 443};
    test_active_ssl_connection = test_ssl_conn.p_conn;
    test_mapped_pid_tid = 0x2a00000001ULL;
    test_mapped_pid_tid_available = 1;
    test_pid_tid_conn = (ssl_pid_connection_info_t){
        .p_conn = {.conn = {.s_port = 49153, .d_port = 443}, .pid = 42},
        .orig_dport = 8443,
    };

    retire_ssl_pointer_generation(test_ssl_ptr, 0x2a00000001ULL, 77, 88);

    assert_int_eq(1, ssl_to_conn_delete_count, "allocation retires the stale reverse cache");
    assert_int_eq(1, ssl_pid_tid_delete_count, "allocation retires the stale SSL thread owner");
    assert_int_eq(1, active_ssl_delete_count, "allocation retires the matching forward owner");
    assert_int_eq(0, pid_tid_delete_count, "allocation preserves the fresh connect hint");
    assert_u64_eq(test_ssl_ptr, test_deleted_ssl_key.ssl, "reverse deletion uses the SSL pointer");
    assert_int_eq(42, (int)test_deleted_ssl_key.pid, "reverse deletion uses the process ID");
    assert_u64_eq(77,
                  test_deleted_ssl_key.process_start_time,
                  "reverse deletion uses the process generation");
    assert_u64_eq(
        test_ssl_ptr, test_deleted_ssl_owner_key.ssl, "owner deletion uses the SSL pointer");
    assert_int_eq(42, (int)test_deleted_ssl_owner_key.pid, "owner deletion uses the process ID");
    assert_u64_eq(77,
                  test_deleted_ssl_owner_key.process_start_time,
                  "owner deletion uses the process generation");

    ssl_args_t args = ssl_args();
    handle_ssl_prewrite(NULL, 0x2a00000001ULL, &args, 64);

    assert_int_eq(1, test_prewrite_parser_call_count, "the reallocated SSL enters parsing");
    assert_int_eq(1, ssl_to_conn_update_count, "the fresh connection is promoted");
    assert_int_eq(1, pid_tid_delete_count, "promotion consumes the fresh connect hint");
    assert_u16_eq(49153, test_last_connection.conn.s_port, "the fresh tuple is selected");
    assert_u16_eq(8443, test_last_orig_dport, "the fresh destination port is preserved");
}

static void test_ssl_reallocation_discards_stale_current_thread_connection(void) {
    reset();
    seed_existing_ssl_connection(443);
    test_ssl_conn.p_conn.conn = (connection_info_t){.s_port = 49152, .d_port = 443};
    test_active_ssl_connection = test_ssl_conn.p_conn;
    test_mapped_pid_tid = 0x2a00000001ULL;
    test_mapped_pid_tid_available = 1;
    test_pid_tid_conn = test_ssl_conn;

    retire_ssl_pointer_generation(test_ssl_ptr, 0x2a00000001ULL, 77, 88);

    assert_int_eq(1, pid_tid_delete_count, "allocation retires the matching current hint");
    assert_u64_eq(
        0x2a00000001ULL, test_deleted_pid_tid, "allocation deletes the exact current thread hint");

    ssl_args_t args = ssl_args();
    handle_ssl_prewrite(NULL, 0x2a00000001ULL, &args, 64);

    assert_int_eq(0, ssl_to_conn_update_count, "a stale current hint is not republished");
    assert_int_eq(0, test_prewrite_parser_call_count, "a stale current hint is not parsed");
}

static void test_ssl_reallocation_discards_stale_recorded_owner_connection(void) {
    reset();
    seed_existing_ssl_connection(443);
    test_ssl_conn.p_conn.conn = (connection_info_t){.s_port = 49152, .d_port = 443};
    test_active_ssl_connection = test_ssl_conn.p_conn;
    test_mapped_pid_tid = 0x2a00000002ULL;
    test_mapped_pid_tid_available = 1;
    test_pid_tid_conn = test_ssl_conn;

    retire_ssl_pointer_generation(test_ssl_ptr, 0x2a00000001ULL, 77, 88);

    assert_int_eq(1, pid_tid_delete_count, "allocation retires the matching recorded owner hint");
    assert_u64_eq(0x2a00000002ULL,
                  test_deleted_pid_tid,
                  "allocation deletes the exact recorded owner thread hint");

    ssl_args_t args = ssl_args();
    handle_ssl_prewrite(NULL, 0x2a00000001ULL, &args, 64);

    assert_int_eq(0, ssl_to_conn_update_count, "a stale recorded owner hint is not republished");
    assert_int_eq(0, test_prewrite_parser_call_count, "a stale recorded owner hint is not parsed");
}

static void test_ssl_reallocation_preserves_foreign_forward_owner(void) {
    reset();
    seed_existing_ssl_connection(443);
    test_active_ssl_ptr = test_ssl_ptr + 1;

    retire_ssl_pointer_generation(test_ssl_ptr, 0x2a00000001ULL, 77, 88);

    assert_int_eq(1, ssl_to_conn_delete_count, "allocation retires the stale reverse cache");
    assert_int_eq(1, ssl_pid_tid_delete_count, "allocation retires the stale thread owner");
    assert_int_eq(0, active_ssl_delete_count, "allocation preserves another SSL forward owner");
    assert_int_eq(1, test_active_ssl_available, "the foreign forward owner remains available");
}

static void test_ssl_reallocation_without_reverse_is_idempotent(void) {
    reset();

    retire_ssl_pointer_generation(test_ssl_ptr, 0x2a00000001ULL, 77, 88);
    retire_ssl_pointer_generation(test_ssl_ptr, 0x2a00000001ULL, 77, 88);

    assert_int_eq(2, ssl_to_conn_delete_count, "exact missing reverse cleanup is idempotent");
    assert_int_eq(2, ssl_pid_tid_delete_count, "exact missing thread-owner cleanup is idempotent");
    assert_int_eq(
        0, active_ssl_delete_count, "missing reverse state cannot select a forward owner");
}

static void test_invalid_ssl_reallocation_noops(void) {
    reset();

    retire_ssl_pointer_generation(0, 0x2a00000001ULL, 77, 88);
    retire_ssl_pointer_generation(test_ssl_ptr, 0, 77, 88);
    retire_ssl_pointer_generation(test_ssl_ptr, 0x2a00000001ULL, 0, 88);

    assert_int_eq(0, ssl_to_conn_delete_count, "invalid allocation does not touch reverse state");
    assert_int_eq(
        0, ssl_pid_tid_delete_count, "invalid allocation does not touch thread ownership");
    assert_int_eq(0, active_ssl_delete_count, "invalid allocation does not touch forward state");
}

static void test_failed_promotion_preserves_source_connection(void) {
    reset();
    test_mapped_pid_tid = 0x2a00000002ULL;
    test_mapped_pid_tid_available = 1;
    test_pid_tid_conn.orig_dport = 8443;
    test_pid_tid_conn.p_conn.pid = 42;
    test_ssl_conn_update_error = 1;
    ssl_args_t args = ssl_args();

    ssl_pid_connection_info_t *connection = ssl_connection_for_args(0x2a00000001ULL, &args, 1);

    if (connection) {
        fprintf(stderr, "FAIL: failed promotion returned a destination connection\n");
        exit(1);
    }
    assert_int_eq(1, ssl_to_conn_update_count, "failed promotion attempts one destination update");
    assert_int_eq(0, active_ssl_update_count, "failed promotion does not publish a forward owner");
    assert_int_eq(0, pid_tid_delete_count, "failed promotion preserves its source connection");
    assert_int_eq(1, ssl_pid_tid_delete_count, "failed read releases the stale thread owner");
    assert_u16_eq(8443, test_pid_tid_conn.orig_dport, "failed promotion preserves source data");
}

static void test_failed_forward_publication_rolls_back_reverse_mapping(void) {
    reset();
    test_mapped_pid_tid = 0x2a00000002ULL;
    test_mapped_pid_tid_available = 1;
    test_pid_tid_conn.orig_dport = 8443;
    test_pid_tid_conn.p_conn.pid = 42;
    test_active_ssl_update_error = 1;
    ssl_args_t args = ssl_args();

    ssl_pid_connection_info_t *connection = ssl_connection_for_args(0x2a00000001ULL, &args, 1);

    if (connection) {
        fprintf(stderr, "FAIL: failed forward publication returned a connection\n");
        exit(1);
    }
    assert_int_eq(1, ssl_to_conn_update_count, "forward failure first publishes the reverse map");
    assert_int_eq(1, active_ssl_update_count, "forward failure attempts owner publication");
    assert_int_eq(1, ssl_to_conn_delete_count, "forward failure rolls back its reverse map");
    assert_int_eq(0, pid_tid_delete_count, "forward failure preserves its source connection");
    assert_int_eq(1, ssl_pid_tid_delete_count, "failed read releases the stale thread owner");
}

static void test_delayed_tls_request_stays_open_on_next_tls_operation(void) {
    reset();
    pid_connection_info_t connection = {};
    test_http_connection = connection;
    test_http_info_available = 1;
    test_http_info.delayed = 1;
    test_http_info.status = 200;
    test_http_info.start_monotime_ns = 1;
    test_http_info.pid.host_pid = 42;

    finish_possible_delayed_tls_http_request(&connection);

    assert_int_eq(0, test_finish_http_count, "ordinary TLS operations retain delayed requests");
}

static void test_delayed_tls_request_finishes_on_shutdown(void) {
    reset();
    pid_connection_info_t connection = {};
    test_http_connection = connection;
    test_http_info_available = 1;
    test_http_info.delayed = 1;
    test_http_info.status = 200;
    test_http_info.start_monotime_ns = 1;
    test_http_info.pid.host_pid = 42;

    finish_tls_http_request_on_shutdown(&connection);

    assert_int_eq(1, test_finish_http_count, "shutdown finishes a complete delayed request");
    assert_int_eq(1, test_terminate_http_count, "shutdown terminates the request lifecycle");
    assert_int_eq(0, test_http_info_available, "shutdown removes the request lifecycle");
}

static void test_incomplete_tls_request_is_removed_on_shutdown(void) {
    reset();
    pid_connection_info_t connection = {};
    test_http_connection = connection;
    test_http_info_available = 1;
    test_http_info.delayed = 1;

    finish_tls_http_request_on_shutdown(&connection);

    assert_int_eq(0, test_finish_http_count, "shutdown does not submit an incomplete request");
    assert_int_eq(1, test_terminate_http_count, "shutdown terminates the request lifecycle");
    assert_int_eq(0, test_http_info_available, "shutdown removes the incomplete request");
}

static void test_submitted_tls_request_is_not_resubmitted_on_shutdown(void) {
    reset();
    pid_connection_info_t connection = {};
    test_http_connection = connection;
    test_http_info_available = 1;
    test_http_info.submitted = 1;
    test_http_info.status = 200;
    test_http_info.start_monotime_ns = 1;
    test_http_info.pid.host_pid = 42;

    finish_tls_http_request_on_shutdown(&connection);

    assert_int_eq(0, test_finish_http_count, "shutdown does not resubmit a completed request");
    assert_int_eq(1, test_terminate_http_count, "shutdown terminates the submitted request");
    assert_int_eq(0, test_http_info_available, "shutdown removes the submitted request");
}

static void test_fallback_shutdown_uses_transient_connection(void) {
    reset();
    ssl_pid_connection_info_t fallback;
    initialize_fallback_ssl_connection(&fallback, 0x2a00000001ULL, test_ssl_ptr, 77);
    test_http_connection = fallback.p_conn;
    test_http_info_available = 1;
    test_http_info.delayed = 1;

    finish_fallback_tls_http_request_on_shutdown(0x2a00000001ULL, test_ssl_ptr);

    assert_int_eq(1, test_terminate_http_count, "fallback shutdown terminates the request");
    assert_int_eq(42, (int)test_terminated_connection.pid, "fallback shutdown uses current pid");
    assert_int_eq(
        0, test_terminated_connection.conn.s_port, "fallback shutdown has no source port");
    assert_int_eq(
        0, test_terminated_connection.conn.d_port, "fallback shutdown has no destination port");
}

static void test_successful_read_uses_transient_fake_connection(void) {
    reset();
    ssl_args_t args = ssl_args();

    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 128, TCP_RECV);

    assert_int_eq(1, ssl_pid_tid_delete_count, "ssl_to_pid_tid entry is deleted");
    assert_int_eq(0, ssl_to_conn_update_count, "transient fake connection is not persisted");
    assert_int_eq(42, (int)test_last_connection.pid, "fake connection uses current pid");
    assert_int_eq(0, test_last_connection.conn.s_port, "fake connection has no source port");
    assert_int_eq(0, test_last_connection.conn.d_port, "fake connection has no destination port");
    assert_int_eq(1, test_parser_call_count, "positive read enters protocol parsing");
    assert_int_eq(128, test_last_parser_bytes_len, "positive read forwards the read length");
}

static void test_transient_fake_retains_delayed_server_trace(void) {
    reset();
    ssl_pid_connection_info_t fallback;
    initialize_fallback_ssl_connection(&fallback, 0x2a00000001ULL, test_ssl_ptr, 77);
    test_http_connection = fallback.p_conn;
    test_http_info_available = 1;
    test_http_info.type = EVENT_HTTP_REQUEST;
    test_http_info.extra_id = 11;
    test_http_info.pid.ns = 12;
    test_http_info.pid.user_pid = 13;
    test_http_info.task_tid = 14;
    test_http_will_complete = 1;
    ssl_args_t args = ssl_args();

    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 128, TCP_RECV);

    assert_int_eq(
        0, test_delete_server_trace_count, "fallback read retains the delayed server trace");
}

static void seed_fallback_server_request(void) {
    ssl_pid_connection_info_t fallback;
    initialize_fallback_ssl_connection(&fallback, 0x2a00000001ULL, test_ssl_ptr, 77);
    test_http_connection = fallback.p_conn;
    test_http_info_available = 1;
    test_http_info.type = EVENT_HTTP_REQUEST;
    test_http_info.extra_id = 11;
    test_http_info.pid.ns = 12;
    test_http_info.pid.user_pid = 13;
    test_http_info.task_tid = 14;
}

static void assert_fallback_request_discarded(const char *message) {
    assert_int_eq(1, ongoing_http_delete_count, message);
    assert_int_eq(1, test_delete_server_trace_count, "fallback server trace is deleted");
    assert_int_eq(0, test_finish_http_count, "ambiguous fallback request is not emitted");
    if (memcmp(&test_deleted_http_connection,
               &test_http_connection,
               sizeof(test_deleted_http_connection)) != 0) {
        fprintf(stderr, "FAIL: fallback request was deleted with a different key\n");
        exit(1);
    }
}

static void test_existing_real_connection_discards_fallback_request(void) {
    reset();
    seed_fallback_server_request();
    seed_existing_ssl_connection(443);
    test_ssl_conn.p_conn.conn.s_port = 49152;
    test_ssl_conn.p_conn.conn.d_port = 443;
    test_active_ssl_connection = test_ssl_conn.p_conn;
    ssl_args_t args = ssl_args();

    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 128, TCP_RECV);

    assert_fallback_request_discarded("existing real connection discards fallback request");
    assert_u16_eq(49152, test_last_connection.conn.s_port, "response uses the real connection");
}

static void test_promoted_real_connection_discards_fallback_request(void) {
    reset();
    seed_fallback_server_request();
    test_mapped_pid_tid = 0x2a00000002ULL;
    test_mapped_pid_tid_available = 1;
    test_pid_tid_conn.orig_dport = 8443;
    test_pid_tid_conn.p_conn = (pid_connection_info_t){
        .conn = {.s_port = 49152, .d_port = 443},
        .pid = 42,
    };
    ssl_args_t args = ssl_args();

    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 128, TCP_RECV);

    assert_fallback_request_discarded("promoted real connection discards fallback request");
    assert_u16_eq(49152, test_last_connection.conn.s_port, "response uses promoted connection");
}

static void test_real_shutdown_discards_fallback_before_finishing_real(void) {
    reset();
    seed_fallback_server_request();
    pid_connection_info_t real_connection = {
        .conn = {.s_port = 49152, .d_port = 443},
        .pid = 42,
    };

    finish_real_tls_http_request_on_shutdown(0x2a00000001ULL, test_ssl_ptr, 77, &real_connection);

    assert_fallback_request_discarded("real shutdown discards fallback request");
    assert_int_eq(1, test_terminate_http_count, "real shutdown terminates the real connection");
    if (memcmp(&test_terminated_connection, &real_connection, sizeof(real_connection)) != 0) {
        fprintf(stderr, "FAIL: shutdown terminated the fallback instead of the real connection\n");
        exit(1);
    }
}

static void test_transient_fake_does_not_poison_pointer_reuse(void) {
    reset();
    ssl_args_t args = ssl_args();
    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 128, TCP_RECV);

    test_mapped_pid_tid = 0x2a00000002ULL;
    test_mapped_pid_tid_available = 1;
    test_pid_tid_conn.orig_dport = 8443;
    test_pid_tid_conn.p_conn = (pid_connection_info_t){
        .conn = {.s_port = 49152, .d_port = 443},
        .pid = 42,
    };

    handle_ssl_prewrite(NULL, 0x2a00000001ULL, &args, 64);

    assert_int_eq(1, ssl_to_conn_update_count, "reused pointer caches the real connection");
    assert_int_eq(1, active_ssl_update_count, "reused pointer publishes the real owner");
    assert_int_eq(
        1, test_prewrite_parser_call_count, "real prewrite is parsed after fake fallback");
    assert_u16_eq(8443, test_last_orig_dport, "real prewrite replaces the fake dport");
    assert_u16_eq(49152, test_last_connection.conn.s_port, "real prewrite uses the live tuple");
}

static void test_successful_read_can_reuse_mapped_pid_tid_connection(void) {
    reset();
    test_mapped_pid_tid = 0x2a00000002ULL;
    test_mapped_pid_tid_available = 1;
    test_pid_tid_conn.orig_dport = 8443;
    test_pid_tid_conn.p_conn.pid = 42;
    ssl_args_t args = ssl_args();

    handle_ssl_buf(NULL, 0x2a00000001ULL, &args, 64, TCP_RECV);

    assert_int_eq(1, ssl_pid_tid_delete_count, "ssl_to_pid_tid entry is deleted");
    assert_int_eq(1, pid_tid_delete_count, "current pid_tid mapping is removed after reuse");
    assert_int_eq(1, ssl_to_conn_update_count, "mapped pid_tid connection is cached by ssl");
    assert_int_eq(42, (int)test_updated_ssl_key.pid, "cached SSL state is process scoped");
    if (test_deleted_pid_tid != test_mapped_pid_tid) {
        fprintf(stderr,
                "FAIL: cross-thread lookup deleted the wrong pid-tid\n"
                "  expected %llu, got %llu\n",
                (unsigned long long)test_mapped_pid_tid,
                (unsigned long long)test_deleted_pid_tid);
        exit(1);
    }
    if (ssl_to_conn_update_sequence >= pid_tid_delete_sequence) {
        fprintf(stderr, "FAIL: SSL connection was cached after deleting its source mapping\n");
        exit(1);
    }
    assert_int_eq(1, test_parser_call_count, "mapped pid_tid connection enters protocol parsing");
    assert_int_eq(64, test_last_parser_bytes_len, "mapped pid_tid read forwards the read length");
    assert_u16_eq(8443, test_last_orig_dport, "mapped pid_tid connection preserves original dport");
}

static void test_missing_args_noops(void) {
    reset();

    handle_ssl_buf(NULL, 0x2a00000001ULL, NULL, 128, TCP_RECV);

    assert_int_eq(0, ssl_pid_tid_delete_count, "missing args do not touch ssl_to_pid_tid");
    assert_int_eq(0, ssl_to_conn_update_count, "missing args do not create connection info");
    assert_int_eq(0, test_parser_call_count, "missing args do not enter protocol parsing");
}

int main(void) {
    test_successful_published_write_initializes_large_buffer();
    test_terminal_transport_success_initializes_after_local_commit();
    test_failed_published_writes_do_not_initialize_large_buffer();
    test_foreign_or_missing_prewrite_does_not_initialize_large_buffer();
    test_successful_prewrite_waits_for_delayed_transport();
    test_failed_prewrite_without_transport_discards_local_state();
    test_transport_first_failure_retains_and_commits_local_state();
    test_terminal_transport_failure_commits_then_cleans_shared_state();
    test_oversized_success_is_treated_as_a_failed_write();
    test_short_positive_write_blocks_connection();
    test_transport_first_short_write_retains_emitted_local_state();
    test_missing_prewrite_is_handled_without_touching_local_state();
    test_malformed_prewrite_discards_its_exact_provisional_owner();
    test_local_trace_mismatch_is_neither_committed_nor_discarded();
    test_local_shape_mismatch_is_neither_committed_nor_discarded();
    test_structurally_malformed_postwrite_is_reported();
    test_failed_read_skips_parser_after_cleanup();
    test_eof_read_skips_parser_after_cleanup();
    test_successful_read_still_parses();
    test_failed_write_skips_parser_after_cleanup();
    test_successful_write_still_parses();
    test_prewrite_uses_existing_connection_without_cleanup();
    test_valid_cached_connection_ignores_conflicting_thread_hint();
    test_invalid_cached_connection_falls_back_to_thread_hint();
    test_prewrite_does_not_reuse_another_process_connection();
    test_prewrite_requires_positive_length_and_connection();
    test_prewrite_caches_and_releases_cross_thread_connection();
    test_prewrite_then_write_return_does_not_leak_source_connection();
    test_promoted_connection_is_cleaned_before_pointer_reuse();
    test_ssl_reallocation_promotes_fresh_thread_connection();
    test_ssl_reallocation_discards_stale_current_thread_connection();
    test_ssl_reallocation_discards_stale_recorded_owner_connection();
    test_ssl_reallocation_preserves_foreign_forward_owner();
    test_ssl_reallocation_without_reverse_is_idempotent();
    test_invalid_ssl_reallocation_noops();
    test_failed_promotion_preserves_source_connection();
    test_failed_forward_publication_rolls_back_reverse_mapping();
    test_delayed_tls_request_stays_open_on_next_tls_operation();
    test_delayed_tls_request_finishes_on_shutdown();
    test_incomplete_tls_request_is_removed_on_shutdown();
    test_submitted_tls_request_is_not_resubmitted_on_shutdown();
    test_fallback_shutdown_uses_transient_connection();
    test_successful_read_uses_transient_fake_connection();
    test_transient_fake_retains_delayed_server_trace();
    test_existing_real_connection_discards_fallback_request();
    test_promoted_real_connection_discards_fallback_request();
    test_real_shutdown_discards_fallback_before_finishing_real();
    test_transient_fake_does_not_poison_pointer_reuse();
    test_successful_read_can_reuse_mapped_pid_tid_connection();
    test_missing_args_noops();

    return 0;
}
