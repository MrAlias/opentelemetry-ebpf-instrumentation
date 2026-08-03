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
static unsigned long long test_ktime_get_ns(void);
static unsigned int test_prandom_u32(void);

#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update
#define bpf_map_delete_elem test_map_delete
#define bpf_ktime_get_ns test_ktime_get_ns
#define bpf_get_prandom_u32 test_prandom_u32
#define bpf_loop(nr_loops, callback_fn, callback_ctx, flags)                                       \
    ((void)(nr_loops), (void)(callback_fn), (void)(callback_ctx), (void)(flags), 0)

#include <maps/java_remote_parent_shared.h>
#include <maps/java_vt_threads.h>
#include <pid/pid_helpers.h>

static void test_task_tid(pid_key_t *owner);
static u8 test_java_vt_translate_tid(pid_key_t *owner);
static u64 test_java_process_incarnation_for(const pid_key_t *owner);
static u8 test_java_remote_parent_data_hook_is_ready(void);

#define task_tid test_task_tid
#define java_vt_translate_tid test_java_vt_translate_tid
#define java_process_incarnation_for test_java_process_incarnation_for
#define java_remote_parent_data_hook_is_ready test_java_remote_parent_data_hook_is_ready

#include <maps/java_remote_parent.h>

#undef java_remote_parent_data_hook_is_ready
#undef java_process_incarnation_for
#undef java_vt_translate_tid
#undef task_tid
#undef bpf_loop
#undef bpf_get_prandom_u32
#undef bpf_ktime_get_ns
#undef bpf_map_delete_elem
#undef bpf_map_update_elem
#undef bpf_map_lookup_elem

enum {
    test_connection_netns = 42,
    test_connection_netns_cookie = 84,
    test_socket_cookie = 86,
    test_incoming_generation = 21,
    test_process_incarnation = 9,
    test_trace_seed = 0x10,
    test_span_seed = 0x30,
    test_generated_span_seed = 0xd0,
    test_candidate_timestamp = 100,
    test_header_flags = 0x7e,
};

static const pid_key_t test_owner = {.tid = 7, .pid = 5, .ns = 3};
static const unsigned char header_trace_hex[] = "0123456789abcdeffedcba9876543210";
static const unsigned char header_span_hex[] = "8899aabbccddeeff";
static const unsigned char header_flags_hex[] = "7e";
static const unsigned char header_trace_id[] = {
    0x01,
    0x23,
    0x45,
    0x67,
    0x89,
    0xab,
    0xcd,
    0xef,
    0xfe,
    0xdc,
    0xba,
    0x98,
    0x76,
    0x54,
    0x32,
    0x10,
};
static const unsigned char header_span_id[] = {
    0x88,
    0x99,
    0xaa,
    0xbb,
    0xcc,
    0xdd,
    0xee,
    0xff,
};

static u64 generation_sequence;
static connection_info_netns_cookie_t incoming_connection_key_scratch;
static u64 incoming_generation;
static incoming_trace_candidate_t incoming_candidate;
static u8 incoming_claim;
static java_remote_parent_state_t stage_state_scratch;
static java_remote_parent_connection_keys_t connection_keys_scratch;
static java_remote_parent_connection_t connection_value_scratch;
static java_remote_parent_owner_t stored_owner;
static pid_key_t stored_owner_key;
static int owner_present;
static java_remote_parent_key_t stored_state_key;
static java_remote_parent_state_t stored_state;
static int state_present;
static java_remote_parent_key_t stored_generation_index_key;
static java_remote_parent_generation_index_t stored_generation_index;
static int generation_index_present;
static connection_info_ns_t stored_connection_key;
static java_remote_parent_connection_t stored_connection;
static int connection_present;
static connection_info_netns_cookie_t stored_cookie_connection_key;
static java_remote_parent_connection_t stored_cookie_connection;
static int cookie_connection_present;
static pid_key_t stored_fallback_key;
static java_remote_parent_response_t stored_fallback;
static int fallback_present;
static u64 stats[k_java_remote_parent_stat_max];
static int corrupt_cookie_socket_cookie;
static int unexpected_update;
static int unexpected_delete;

static void fail(const char *message) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

static int same_key(const void *left, const void *right, size_t size) {
    return memcmp(left, right, size) == 0;
}

static void *test_map_lookup(void *map, const void *key) {
    if (map == &java_remote_parent_generation) {
        return &generation_sequence;
    }
    if (map == &incoming_trace_connection_key_storage) {
        return &incoming_connection_key_scratch;
    }
    if (map == &incoming_trace_heads) {
        const connection_info_netns_cookie_t expected = {
            .connection = stored_connection_key.connection,
            .netns_cookie = test_connection_netns_cookie,
        };
        return same_key(key, &expected, sizeof(expected)) ? &incoming_generation : NULL;
    }
    if (map == &incoming_trace_candidates && *(const u64 *)key == incoming_generation) {
        return &incoming_candidate;
    }
    if (map == &incoming_trace_claims && *(const u64 *)key == incoming_generation) {
        return &incoming_claim;
    }
    if (map == &java_remote_parent_stage_state_storage) {
        return &stage_state_scratch;
    }
    if (map == &java_remote_parent_connection_keys_storage) {
        return &connection_keys_scratch;
    }
    if (map == &java_remote_parent_connection_value_storage) {
        return &connection_value_scratch;
    }
    if (map == &java_remote_parent_owners && owner_present &&
        same_key(key, &stored_owner_key, sizeof(stored_owner_key))) {
        return &stored_owner;
    }
    if (map == &java_remote_parent_state && state_present &&
        same_key(key, &stored_state_key, sizeof(stored_state_key))) {
        return &stored_state;
    }
    if (map == &java_remote_parent_generation_index && generation_index_present &&
        same_key(key, &stored_generation_index_key, sizeof(stored_generation_index_key))) {
        return &stored_generation_index;
    }
    if (map == &java_remote_parent_connections && connection_present &&
        same_key(key, &stored_connection_key, sizeof(stored_connection_key))) {
        return &stored_connection;
    }
    if (map == &java_remote_parent_cookie_connections && cookie_connection_present &&
        same_key(key, &stored_cookie_connection_key, sizeof(stored_cookie_connection_key))) {
        return &stored_cookie_connection;
    }
    if (map == &java_remote_parent_fallback && fallback_present &&
        same_key(key, &stored_fallback_key, sizeof(stored_fallback_key))) {
        return &stored_fallback;
    }
    if (map == &java_remote_parent_stats) {
        const u32 index = *(const u32 *)key;
        return index < k_java_remote_parent_stat_max ? &stats[index] : NULL;
    }
    return NULL;
}

static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags) {
    if (map == &java_remote_parent_owners) {
        if ((!owner_present && flags != BPF_NOEXIST) || (owner_present && flags != BPF_EXIST)) {
            unexpected_update = 1;
            return -1;
        }
        stored_owner_key = *(const pid_key_t *)key;
        stored_owner = *(const java_remote_parent_owner_t *)value;
        owner_present = 1;
        return 0;
    }
    if (map == &java_remote_parent_state && flags == BPF_NOEXIST && !state_present) {
        stored_state_key = *(const java_remote_parent_key_t *)key;
        stored_state = *(const java_remote_parent_state_t *)value;
        state_present = 1;
        return 0;
    }
    if (map == &java_remote_parent_generation_index && flags == BPF_NOEXIST &&
        !generation_index_present) {
        stored_generation_index_key = *(const java_remote_parent_key_t *)key;
        stored_generation_index = *(const java_remote_parent_generation_index_t *)value;
        generation_index_present = 1;
        return 0;
    }
    if (map == &java_remote_parent_connections && flags == BPF_NOEXIST && !connection_present) {
        stored_connection_key = *(const connection_info_ns_t *)key;
        stored_connection = *(const java_remote_parent_connection_t *)value;
        connection_present = 1;
        return 0;
    }
    if (map == &java_remote_parent_cookie_connections && flags == BPF_NOEXIST &&
        !cookie_connection_present) {
        stored_cookie_connection_key = *(const connection_info_netns_cookie_t *)key;
        stored_cookie_connection = *(const java_remote_parent_connection_t *)value;
        if (corrupt_cookie_socket_cookie) {
            stored_cookie_connection.socket_cookie++;
            corrupt_cookie_socket_cookie = 0;
        }
        cookie_connection_present = 1;
        return 0;
    }
    if (map == &java_remote_parent_fallback && flags == BPF_NOEXIST && !fallback_present) {
        stored_fallback_key = *(const pid_key_t *)key;
        stored_fallback = *(const java_remote_parent_response_t *)value;
        fallback_present = 1;
        return 0;
    }

    unexpected_update = 1;
    return -1;
}

static long test_map_delete(void *map, const void *key) {
    if (map == &java_remote_parent_terminal) {
        return 0;
    }
    if (map == &java_remote_parent_fallback) {
        if (fallback_present && same_key(key, &stored_fallback_key, sizeof(stored_fallback_key))) {
            fallback_present = 0;
        }
        return 0;
    }
    if (map == &java_remote_parent_connections && connection_present &&
        same_key(key, &stored_connection_key, sizeof(stored_connection_key))) {
        connection_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_cookie_connections && cookie_connection_present &&
        same_key(key, &stored_cookie_connection_key, sizeof(stored_cookie_connection_key))) {
        cookie_connection_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_state && state_present &&
        same_key(key, &stored_state_key, sizeof(stored_state_key))) {
        state_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_generation_index && generation_index_present &&
        same_key(key, &stored_generation_index_key, sizeof(stored_generation_index_key))) {
        generation_index_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_owners && owner_present &&
        same_key(key, &stored_owner_key, sizeof(stored_owner_key))) {
        owner_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_ambiguity) {
        return 0;
    }

    unexpected_delete = 1;
    return -1;
}

static unsigned long long test_ktime_get_ns(void) {
    return 1000;
}

static unsigned int test_prandom_u32(void) {
    return 0;
}

static void test_task_tid(pid_key_t *owner) {
    *owner = test_owner;
}

static u8 test_java_vt_translate_tid(pid_key_t *owner) {
    (void)owner;
    return 0;
}

static u64 test_java_process_incarnation_for(const pid_key_t *owner) {
    (void)owner;
    return test_process_incarnation;
}

static u8 test_java_remote_parent_data_hook_is_ready(void) {
    return 1;
}

static tp_info_pid_t raw_parent(unsigned char flags) {
    tp_info_pid_t incoming = {
        .tp = {.ts = test_candidate_timestamp, .flags = flags},
        .valid = 1,
        .provenance = k_tp_provenance_tcp_exact_flags,
    };
    for (u32 index = 0; index < sizeof(incoming.tp.trace_id); index++) {
        incoming.tp.trace_id[index] = test_trace_seed + index;
    }
    for (u32 index = 0; index < sizeof(incoming.tp.span_id); index++) {
        incoming.tp.span_id[index] = test_span_seed + index;
    }
    return incoming;
}

static void reset(const connection_info_t *connection, const tp_info_pid_t *incoming) {
    generation_sequence = 0;
    incoming_generation = test_incoming_generation;
    incoming_candidate = (incoming_trace_candidate_t){.candidate = *incoming};
    incoming_claim = 1;
    memset(&stage_state_scratch, 0, sizeof(stage_state_scratch));
    memset(&connection_keys_scratch, 0, sizeof(connection_keys_scratch));
    memset(&connection_value_scratch, 0, sizeof(connection_value_scratch));
    memset(&stored_owner, 0, sizeof(stored_owner));
    memset(&stored_state, 0, sizeof(stored_state));
    memset(&stored_generation_index, 0, sizeof(stored_generation_index));
    memset(&stored_connection, 0, sizeof(stored_connection));
    memset(&stored_cookie_connection, 0, sizeof(stored_cookie_connection));
    memset(&stored_fallback, 0, sizeof(stored_fallback));
    memset(stats, 0, sizeof(stats));
    stored_connection_key = connection_info_with_netns(connection, test_connection_netns);
    owner_present = 0;
    state_present = 0;
    generation_index_present = 0;
    connection_present = 0;
    cookie_connection_present = 0;
    fallback_present = 0;
    corrupt_cookie_socket_cookie = 0;
    unexpected_update = 0;
    unexpected_delete = 0;
}

static void test_inconsistent_physical_index_rolls_back_stage(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const tp_info_pid_t raw = raw_parent(k_flag_sampled);
    reset(&connection, &raw);
    java_remote_parent_incoming_t handoff = {.generation = test_incoming_generation};
    if (!apply_incoming_trace_candidate(
            &(tp_info_t){}, &raw, &handoff.candidate, &handoff.generation)) {
        fail("raw TCP parent was not prepared for inconsistent-index test");
    }
    corrupt_cookie_socket_cookie = 1;

    if (java_remote_parent_stage_incoming(&connection,
                                          test_connection_netns,
                                          test_connection_netns_cookie,
                                          test_socket_cookie,
                                          &handoff) != 0 ||
        owner_present || state_present || generation_index_present || connection_present ||
        fallback_present || !cookie_connection_present ||
        stored_cookie_connection.socket_cookie == test_socket_cookie ||
        stats[k_java_remote_parent_stat_stage_ambiguous] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("inconsistent physical connection index was published or deleted as current");
    }
}

static void test_raw_parent_is_published_before_w3c_override(void) {
    const unsigned char raw_flags[] = {0, k_flag_sampled, 0x81};

    for (size_t flag_index = 0; flag_index < sizeof(raw_flags) / sizeof(raw_flags[0]);
         flag_index++) {
        const connection_info_t connection = {.s_port = 1234, .d_port = 443};
        const tp_info_pid_t raw = raw_parent(raw_flags[flag_index]);
        reset(&connection, &raw);

        tp_info_t server = {.flags = 0x40};
        for (u32 index = 0; index < sizeof(server.span_id); index++) {
            server.span_id[index] = test_generated_span_seed + index;
        }
        const tp_info_t generated_server = server;
        java_remote_parent_incoming_t handoff = {.generation = test_incoming_generation};
        if (!apply_incoming_trace_candidate(
                &server, &raw, &handoff.candidate, &handoff.generation)) {
            fail("raw TCP parent was not prepared for Java handoff");
        }

        const u64 staged_generation = java_remote_parent_stage_incoming(
            &connection,
            test_connection_netns,
            test_connection_netns_cookie,
            test_socket_cookie,
            &handoff);
        if (!staged_generation || !state_present || !fallback_present || unexpected_update ||
            unexpected_delete || stats[k_java_remote_parent_stat_stage_valid] != 1 ||
            stored_state.response.status != k_java_remote_parent_status_valid ||
            stored_connection.socket_cookie != test_socket_cookie ||
            stored_cookie_connection.socket_cookie != test_socket_cookie ||
            memcmp(stored_state.response.trace_id,
                   raw.tp.trace_id,
                   sizeof(stored_state.response.trace_id)) != 0 ||
            memcmp(stored_state.response.span_id,
                   raw.tp.span_id,
                   sizeof(stored_state.response.span_id)) != 0 ||
            memcmp(stored_state.response.span_id,
                   generated_server.span_id,
                   sizeof(stored_state.response.span_id)) == 0 ||
            stored_state.response.flags != raw_flags[flag_index] ||
            memcmp(server.span_id, generated_server.span_id, sizeof(server.span_id)) != 0) {
            fail("Java stage did not publish the exact raw TCP parent");
        }

        decode_hex(server.trace_id, header_trace_hex, TRACE_ID_CHAR_LEN);
        decode_hex(&server.flags, header_flags_hex, FLAGS_CHAR_LEN);
        decode_hex(server.parent_id, header_span_hex, SPAN_ID_CHAR_LEN);
        if (memcmp(server.trace_id, header_trace_id, sizeof(server.trace_id)) != 0 ||
            memcmp(server.parent_id, header_span_id, sizeof(server.parent_id)) != 0 ||
            server.flags != test_header_flags ||
            memcmp(server.span_id, generated_server.span_id, sizeof(server.span_id)) != 0 ||
            memcmp(stored_state.response.trace_id,
                   raw.tp.trace_id,
                   sizeof(stored_state.response.trace_id)) != 0 ||
            memcmp(stored_state.response.span_id,
                   raw.tp.span_id,
                   sizeof(stored_state.response.span_id)) != 0 ||
            stored_state.response.flags != raw_flags[flag_index]) {
            fail("W3C header did not override only the OBI server trace parent");
        }
    }
}

int main(void) {
    test_raw_parent_is_published_before_w3c_override();
    test_inconsistent_physical_index_rolls_back_stage();
    return 0;
}
