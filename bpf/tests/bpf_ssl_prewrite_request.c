// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>

#include <common/http_info.h>
#include <common/http_types.h>

enum { BPF_ANY = 0, BPF_NOEXIST = 1, BPF_EXIST = 2 };
#define BPF_F_NO_PREALLOC 1

static void *test_map_lookup(void *map, const void *key);
static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags);
static long test_map_delete(void *map, const void *key);
static uint64_t test_ktime_get_ns(void);

#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update
#define bpf_map_delete_elem test_map_delete
#define bpf_ktime_get_ns test_ktime_get_ns

volatile const u64 ssl_prewrite_max_age_ns = 20;

static __always_inline http_info_t *empty_http_info(void);
static __always_inline u8 http_info_complete(http_info_t *info);
static __always_inline void finish_http(http_info_t *info, pid_connection_info_t *connection);
static __always_inline void cleanup_http_request_data(pid_connection_info_t *connection,
                                                      http_info_t *info);
static __always_inline void cleanup_http_info(pid_connection_info_t *connection);

#include <common/ssl_connection.h>
#include <generictracer/ssl_prewrite_request.h>

#undef bpf_map_lookup_elem
#undef bpf_map_update_elem
#undef bpf_map_delete_elem
#undef bpf_ktime_get_ns

static http_info_t test_http_scratch;
static http_info_t test_http;
static pid_connection_info_t test_connection;
static int test_http_present;
static ssl_prewrite_value_t test_prewrite_scratch;
static connection_info_netns_cookie_t test_connection_key_scratch;
static ssl_prewrite_connection_owner_t test_owner_candidate_scratch;
static ssl_prewrite_connection_owner_t test_claim_candidate_scratch;
static ssl_prewrite_connection_owner_t test_block_claim_scratch;
static ssl_prewrite_connection_owner_t test_cleanup_claim_scratch;
static ssl_prewrite_connection_ambiguity_t test_ambiguity_candidate_scratch;
static ssl_prewrite_value_t test_prewrite;
static ssl_prewrite_key_t test_prewrite_key;
static int test_prewrite_present;
static connection_info_netns_cookie_t test_owner_connection_key;
static ssl_prewrite_connection_owner_t test_connection_owner;
static ssl_prewrite_connection_owner_t test_connection_claim;
static int test_connection_owner_present;
static int test_connection_claim_present;
static int test_connection_ambiguous;
static ssl_prewrite_connection_ambiguity_t test_connection_ambiguity;
static u64 test_stats[k_java_remote_parent_stat_max];
static u64 test_now;
static int test_http_delete_count;
static int test_http_cleanup_count;
static int test_http_update_count;
static int test_prewrite_update_count;

static void assert_int_eq(int expected, int actual, const char *message) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected %d, got %d\n", message, expected, actual);
        exit(1);
    }
}

static void *test_map_lookup(void *map, const void *key) {
    if (map == &java_remote_parent_stats) {
        const u32 stat = *(const u32 *)key;
        return stat < k_java_remote_parent_stat_max ? &test_stats[stat] : NULL;
    }
    if (map == &ongoing_http && test_http_present &&
        memcmp(key, &test_connection, sizeof(test_connection)) == 0) {
        return &test_http;
    }
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
    if (map == &ongoing_http) {
        if (flags == BPF_NOEXIST && test_http_present) {
            return -1;
        }
        test_http_update_count++;
        test_connection = *(const pid_connection_info_t *)key;
        test_http = *(const http_info_t *)value;
        test_http_present = 1;
        return 0;
    }
    if (map == &ssl_prewrite_tp) {
        if (flags == BPF_NOEXIST && test_prewrite_present) {
            return -1;
        }
        test_prewrite_update_count++;
        test_prewrite_key = *(const ssl_prewrite_key_t *)key;
        test_prewrite = *(const ssl_prewrite_value_t *)value;
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
        return 0;
    }
    if (map == &ssl_prewrite_connection_claims) {
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
        if ((flags == BPF_NOEXIST && test_connection_ambiguous) ||
            (flags == BPF_EXIST && !test_connection_ambiguous)) {
            return -1;
        }
        test_owner_connection_key = *(const connection_info_netns_cookie_t *)key;
        test_connection_ambiguity = *(const ssl_prewrite_connection_ambiguity_t *)value;
        test_connection_ambiguous = 1;
        return 0;
    }
    return 0;
}

static long test_map_delete(void *map, const void *key) {
    if (map == &ongoing_http && test_http_present &&
        memcmp(key, &test_connection, sizeof(test_connection)) == 0) {
        test_http_delete_count++;
        test_http_present = 0;
    } else if (map == &ssl_prewrite_tp && test_prewrite_present &&
               memcmp(key, &test_prewrite_key, sizeof(test_prewrite_key)) == 0) {
        test_prewrite_present = 0;
    } else if (map == &ssl_prewrite_connection_claims) {
        test_connection_claim_present = 0;
    } else if (map == &ssl_prewrite_connection_ambiguity) {
        test_connection_ambiguous = 0;
        test_connection_ambiguity = (ssl_prewrite_connection_ambiguity_t){};
    } else if (map == &ssl_prewrite_connection_owners) {
        test_connection_owner_present = 0;
    }
    return 0;
}

static uint64_t test_ktime_get_ns(void) {
    return test_now;
}

static __always_inline http_info_t *empty_http_info(void) {
    memset(&test_http_scratch, 0, sizeof(test_http_scratch));
    return &test_http_scratch;
}

static __always_inline u8 http_info_complete(http_info_t *info) {
    return info && info->start_monotime_ns && info->status;
}

static __always_inline void finish_http(http_info_t *info, pid_connection_info_t *connection) {
    (void)info;
    (void)connection;
}

static __always_inline void cleanup_http_request_data(pid_connection_info_t *connection,
                                                      http_info_t *info) {
    (void)connection;
    (void)info;
    test_http_cleanup_count++;
}

static __always_inline void cleanup_http_info(pid_connection_info_t *connection) {
    test_map_delete(&ongoing_http, connection);
}

static void reset(void) {
    test_http_scratch = (http_info_t){};
    test_http = (http_info_t){};
    test_connection = (pid_connection_info_t){
        .conn = {.s_port = 49152, .d_port = 443},
        .pid = 42,
    };
    test_http_present = 0;
    test_prewrite_scratch = (ssl_prewrite_value_t){};
    test_connection_key_scratch = (connection_info_netns_cookie_t){};
    test_owner_candidate_scratch = (ssl_prewrite_connection_owner_t){};
    test_claim_candidate_scratch = (ssl_prewrite_connection_owner_t){};
    test_block_claim_scratch = (ssl_prewrite_connection_owner_t){};
    test_cleanup_claim_scratch = (ssl_prewrite_connection_owner_t){};
    test_ambiguity_candidate_scratch = (ssl_prewrite_connection_ambiguity_t){};
    test_prewrite = (ssl_prewrite_value_t){};
    test_prewrite_key = (ssl_prewrite_key_t){};
    test_prewrite_present = 0;
    test_owner_connection_key = (connection_info_netns_cookie_t){};
    test_connection_owner = (ssl_prewrite_connection_owner_t){};
    test_connection_claim = (ssl_prewrite_connection_owner_t){};
    test_connection_owner_present = 0;
    test_connection_claim_present = 0;
    test_connection_ambiguous = 0;
    test_connection_ambiguity = (ssl_prewrite_connection_ambiguity_t){};
    memset(test_stats, 0, sizeof(test_stats));
    test_now = 100;
    test_http_delete_count = 0;
    test_http_cleanup_count = 0;
    test_http_update_count = 0;
    test_prewrite_update_count = 0;
}

static call_protocol_args_t prewrite_args(void) {
    return (call_protocol_args_t){
        .pid_conn = test_connection,
        .ssl = WITH_SSL,
        .direction = TCP_SEND,
        .orig_dport = 443,
        .connection_netns_cookie = 7,
        .ssl_ptr = 0x1234,
        .u_buf = 0x5678,
        .bytes_len = 64,
        .ssl_handoff_id = 9,
    };
}

static void seed_stranded_local_owner(void) {
    test_http_present = 1;
    test_http = (http_info_t){
        .type = EVENT_HTTP_CLIENT,
        .ssl = WITH_SSL,
        .direction = TCP_SEND,
        .req_monotime_ns = 90,
        .ssl_prewrite_pending = k_ssl_prewrite_local_pending,
    };
}

static void test_entry_path_keeps_collided_connection_blocked_after_handoff_ttl(void) {
    reset();
    seed_stranded_local_owner();
    call_protocol_args_t args = prewrite_args();

    test_now = 110;
    assert_int_eq(0,
                  prepare_ssl_prewrite_request(&args),
                  "a live stranded owner blocks replacement at the TTL boundary");
    assert_int_eq(k_ssl_prewrite_local_blocked,
                  test_http.ssl_prewrite_pending,
                  "the first blocked replacement is recorded on the live owner");
    assert_int_eq(1,
                  (int)test_stats[k_java_remote_parent_stat_inject_ambiguous],
                  "the first blocked replacement is attributable");

    assert_int_eq(
        0, prepare_ssl_prewrite_request(&args), "a repeated live collision remains blocked");
    assert_int_eq(1,
                  (int)test_stats[k_java_remote_parent_stat_inject_ambiguous],
                  "a repeated collision does not double count ambiguity");

    test_now = 111;
    assert_int_eq(1,
                  prepare_ssl_prewrite_request(&args),
                  "the first request after TTL replaces the stranded owner");
    assert_int_eq(1, test_http_cleanup_count, "stale local request data is cleaned");
    assert_int_eq(1, test_http_delete_count, "stale local ownership is deleted");
    assert_int_eq(1, test_http_update_count, "fresh provisional ownership is inserted");
    assert_int_eq(k_ssl_prewrite_local_pending,
                  test_http.ssl_prewrite_pending,
                  "fresh ownership starts provisional");
    assert_int_eq(111, (int)test_http.req_monotime_ns, "fresh ownership records the new time");
    assert_int_eq(1,
                  (int)test_stats[k_java_remote_parent_stat_inject_stale],
                  "stale-owner recovery is attributable");

    tp_info_pid_t trace = {
        .pid = test_connection.pid,
        .valid = 1,
        .req_type = EVENT_HTTP_CLIENT,
        .state = TP_INFO_PID_STATE_PROVENANCE(k_tp_provenance_ssl_prewrite),
    };
    trace.tp.trace_id[0] = 1;
    trace.tp.span_id[0] = 2;
    trace.tp.ts = 111;
    test_http.tp = trace.tp;
    assert_int_eq(k_ssl_prewrite_publish_ambiguous,
                  (int)update_ssl_prewrite(&test_connection,
                                           args.orig_dport,
                                           args.connection_netns_cookie,
                                           args.ssl_ptr,
                                           args.u_buf,
                                           (u32)args.bytes_len,
                                           88,
                                           0x2a00000001ULL,
                                           args.ssl_handoff_id,
                                           trace.tp.ts,
                                           &trace),
                  "local TTL cleanup cannot revive an ambiguous connection");
    assert_int_eq(1, test_prewrite_update_count, "one fresh shared handoff is published");
    assert_int_eq(0, test_prewrite_present, "the rejected shared handoff is removed");
    assert_int_eq(1, test_connection_ambiguous, "connection ambiguity survives local TTL cleanup");
}

static void test_published_owner_ttl_uses_fresh_handoff_observation(void) {
    reset();
    test_http_present = 1;
    test_http = (http_info_t){
        .type = EVENT_HTTP_CLIENT,
        .ssl = WITH_SSL,
        .direction = TCP_SEND,
        .start_monotime_ns = 1,
        .req_monotime_ns = 1,
        .ssl_prewrite_pending = k_ssl_prewrite_local_pending,
    };
    test_http.tp.ts = 90;
    call_protocol_args_t args = prewrite_args();

    test_now = 110;
    assert_int_eq(0,
                  prepare_ssl_prewrite_request(&args),
                  "an old connection with a fresh handoff stays live at the TTL boundary");
    assert_int_eq(0, test_http_cleanup_count, "fresh handoff ownership is not reclaimed early");
    assert_int_eq(0,
                  (int)test_stats[k_java_remote_parent_stat_inject_stale],
                  "fresh handoff ownership is not reported stale");

    test_now = 111;
    assert_int_eq(1,
                  prepare_ssl_prewrite_request(&args),
                  "published ownership expires relative to the handoff observation");
    assert_int_eq(1, test_http_cleanup_count, "expired published ownership is reclaimed");
    assert_int_eq(1,
                  (int)test_stats[k_java_remote_parent_stat_inject_stale],
                  "handoff-relative expiry is attributable");
}

static void test_incomplete_committed_local_request_blocks_connection(void) {
    reset();
    test_http_present = 1;
    test_http = (http_info_t){
        .type = EVENT_HTTP_CLIENT,
        .ssl = WITH_SSL,
        .direction = TCP_SEND,
        .start_monotime_ns = 1,
        .req_monotime_ns = test_now,
        .ssl_prewrite_pending = k_ssl_prewrite_local_none,
    };
    call_protocol_args_t args = prewrite_args();

    assert_int_eq(0,
                  prepare_ssl_prewrite_request(&args),
                  "a second buffered request is rejected before the response");
    assert_int_eq(k_ssl_prewrite_local_blocked,
                  test_http.ssl_prewrite_pending,
                  "the committed local request becomes permanently blocked");
    assert_int_eq(1, test_connection_ambiguous, "the connection records the collision");
    assert_int_eq(k_ssl_prewrite_connection_owner_blocked,
                  test_connection_owner.state,
                  "the connection cannot publish a later guessed owner");
}

int main(void) {
    test_entry_path_keeps_collided_connection_blocked_after_handoff_ttl();
    test_published_owner_ttl_uses_fresh_handoff_observation();
    test_incomplete_committed_local_request_blocks_connection();
    return 0;
}
