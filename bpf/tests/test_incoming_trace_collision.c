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

#include <maps/incoming_trace_map.h>

#undef bpf_map_lookup_elem
#undef bpf_map_update_elem
#undef bpf_map_delete_elem

enum {
    test_netns = 7,
    other_netns = 8,
    max_slots = 12,
    test_source_port = 1234,
    test_destination_port = 443,
    test_trace_seed = 0x10,
    test_span_seed = 0x30,
    test_generated_flags = 0x40,
    test_generated_span_seed = 0xd0,
    test_future_sampled_flags = 0x81,
    test_candidate_timestamp = 100,
    test_tcp_sequence = 200,
    test_legacy_poison = 0xa5,
    test_staging_poison = 0x5a,
    test_server_poison = 0x6b,
};

enum invalid_parent_case {
    invalid_parent_valid_bit,
    invalid_parent_all_zero_ids,
    invalid_parent_zero_trace_id,
    invalid_parent_zero_span_id,
    invalid_parent_case_count,
};

typedef struct test_head {
    connection_info_netns_cookie_t key;
    u64 generation;
    int present;
} test_head_t;

typedef struct test_version {
    u64 generation;
    incoming_trace_candidate_t candidate;
    u8 claim;
    u8 ambiguous;
    int allocated;
    int candidate_present;
    int claim_present;
    int ambiguity_present;
} test_version_t;

static test_head_t heads[2];
static test_version_t versions[max_slots];
static tp_info_pid_t legacy_candidate;
static tp_info_pid_t snapshot;
static connection_info_netns_cookie_t connection_key_scratch;
static incoming_trace_candidate_t candidate_scratch;
static u64 generation_counter;
static int legacy_present;
static int fail_candidate_insert;
static int fail_ambiguity_insert;
static u64 publish_during_claim;
static u64 publish_during_ambiguity;
static int invalidate_during_claim;
static connection_info_t expected_legacy_connection;
static int check_legacy_connection;
static int legacy_connection_mismatch;
static int legacy_update_flags_mismatch;
static int legacy_lookup_calls;
static int legacy_update_calls;
static int legacy_delete_calls;
static int strict_head_delete_calls;
static int strict_candidate_delete_calls;
static int strict_claim_delete_calls;
static int strict_ambiguity_delete_calls;
static u64 expected_strict_delete_generation;
static int strict_delete_generation_mismatch;

static void fail(const char *message) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

static void check_legacy_key(const connection_info_t *connection) {
    if (check_legacy_connection &&
        memcmp(connection, &expected_legacy_connection, sizeof(*connection)) != 0) {
        legacy_connection_mismatch = 1;
    }
}

static int same_connection_ns(const connection_info_netns_cookie_t *left,
                              const connection_info_netns_cookie_t *right) {
    return memcmp(left, right, sizeof(*left)) == 0;
}

static test_head_t *find_head(const connection_info_netns_cookie_t *key) {
    for (size_t i = 0; i < sizeof(heads) / sizeof(heads[0]); i++) {
        if (heads[i].present && same_connection_ns(&heads[i].key, key)) {
            return &heads[i];
        }
    }
    return NULL;
}

static test_version_t *find_version(u64 generation) {
    for (size_t i = 0; i < max_slots; i++) {
        if (versions[i].allocated && versions[i].generation == generation) {
            return &versions[i];
        }
    }
    return NULL;
}

static test_version_t *allocate_version(u64 generation) {
    test_version_t *existing = find_version(generation);
    if (existing) {
        return existing;
    }
    for (size_t i = 0; i < max_slots; i++) {
        if (!versions[i].allocated) {
            versions[i].generation = generation;
            versions[i].allocated = 1;
            return &versions[i];
        }
    }
    return NULL;
}

static void release_version_if_empty(test_version_t *version) {
    if (!version->candidate_present && !version->claim_present && !version->ambiguity_present) {
        memset(version, 0, sizeof(*version));
    }
}

static void *test_map_lookup(void *map, const void *key) {
    if (map == &incoming_trace_generation) {
        return &generation_counter;
    }
    if (map == &incoming_trace_heads) {
        test_head_t *head = find_head(key);
        return head ? &head->generation : NULL;
    }
    if (map == &incoming_trace_candidates) {
        test_version_t *version = find_version(*(const u64 *)key);
        return version && version->candidate_present ? &version->candidate : NULL;
    }
    if (map == &incoming_trace_claims) {
        test_version_t *version = find_version(*(const u64 *)key);
        return version && version->claim_present ? &version->claim : NULL;
    }
    if (map == &incoming_trace_ambiguity) {
        test_version_t *version = find_version(*(const u64 *)key);
        return version && version->ambiguity_present ? &version->ambiguous : NULL;
    }
    if (map == &incoming_trace_map) {
        legacy_lookup_calls++;
        check_legacy_key(key);
        return legacy_present ? &legacy_candidate : NULL;
    }
    if (map == &incoming_trace_snapshot_storage) {
        return &snapshot;
    }
    if (map == &incoming_trace_connection_key_storage) {
        return &connection_key_scratch;
    }
    if (map == &incoming_trace_candidate_value_storage) {
        return &candidate_scratch;
    }
    return NULL;
}

static long test_update_head(const connection_info_netns_cookie_t *key,
                             const u64 *generation,
                             unsigned long long flags) {
    test_head_t *head = find_head(key);
    if ((flags == BPF_NOEXIST && head) || (flags == BPF_EXIST && !head)) {
        return -1;
    }
    if (!head) {
        for (size_t i = 0; i < sizeof(heads) / sizeof(heads[0]); i++) {
            if (!heads[i].present) {
                heads[i].key = *key;
                heads[i].generation = *generation;
                heads[i].present = 1;
                return 0;
            }
        }
        return -1;
    }
    head->generation = *generation;
    return 0;
}

static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags) {
    if (map == &incoming_trace_map) {
        legacy_update_calls++;
        check_legacy_key(key);
        if (flags != BPF_ANY) {
            legacy_update_flags_mismatch = 1;
        }
        if (flags == BPF_NOEXIST && legacy_present) {
            return -1;
        }
        legacy_candidate = *(const tp_info_pid_t *)value;
        legacy_present = 1;
        return 0;
    }
    if (map == &incoming_trace_heads) {
        return test_update_head(key, value, flags);
    }
    if (map == &incoming_trace_candidates) {
        const u64 generation = *(const u64 *)key;
        test_version_t *version = find_version(generation);
        if (fail_candidate_insert ||
            (flags == BPF_NOEXIST && version && version->candidate_present)) {
            return -1;
        }
        version = allocate_version(generation);
        if (!version) {
            return -1;
        }
        version->candidate = *(const incoming_trace_candidate_t *)value;
        version->candidate_present = 1;
        return 0;
    }
    if (map == &incoming_trace_claims) {
        test_version_t *version = find_version(*(const u64 *)key);
        if (!version || !version->candidate_present ||
            (flags == BPF_NOEXIST && version->claim_present)) {
            return -1;
        }
        if (publish_during_claim) {
            for (size_t i = 0; i < sizeof(heads) / sizeof(heads[0]); i++) {
                if (heads[i].present && heads[i].generation == version->generation) {
                    heads[i].generation = publish_during_claim;
                    break;
                }
            }
            publish_during_claim = 0;
        }
        if (invalidate_during_claim) {
            version->ambiguous = 1;
            version->ambiguity_present = 1;
            invalidate_during_claim = 0;
        }
        version->claim = *(const u8 *)value;
        version->claim_present = 1;
        return 0;
    }
    if (map == &incoming_trace_ambiguity) {
        if (fail_ambiguity_insert) {
            return -1;
        }
        test_version_t *version = find_version(*(const u64 *)key);
        if (!version) {
            return -1;
        }
        version->ambiguous = *(const u8 *)value;
        version->ambiguity_present = 1;
        if (publish_during_ambiguity) {
            for (size_t i = 0; i < sizeof(heads) / sizeof(heads[0]); i++) {
                if (heads[i].present && heads[i].generation == version->generation) {
                    heads[i].generation = publish_during_ambiguity;
                    break;
                }
            }
            publish_during_ambiguity = 0;
        }
        return 0;
    }
    return -1;
}

static long test_map_delete(void *map, const void *key) {
    if (map == &incoming_trace_map) {
        legacy_delete_calls++;
        check_legacy_key(key);
        legacy_present = 0;
        memset(&legacy_candidate, test_legacy_poison, sizeof(legacy_candidate));
        return 0;
    }
    if (map == &incoming_trace_heads) {
        strict_head_delete_calls++;
        test_head_t *head = find_head(key);
        if (head) {
            head->present = 0;
        }
        return 0;
    }
    if (map == &incoming_trace_candidates) {
        strict_candidate_delete_calls++;
    } else if (map == &incoming_trace_claims) {
        strict_claim_delete_calls++;
    } else if (map == &incoming_trace_ambiguity) {
        strict_ambiguity_delete_calls++;
    }

    const u64 generation = *(const u64 *)key;
    if (expected_strict_delete_generation && generation != expected_strict_delete_generation) {
        strict_delete_generation_mismatch = 1;
    }

    test_version_t *version = find_version(generation);
    if (!version) {
        return 0;
    }
    if (map == &incoming_trace_candidates) {
        version->candidate_present = 0;
    } else if (map == &incoming_trace_claims) {
        version->claim_present = 0;
    } else if (map == &incoming_trace_ambiguity) {
        version->ambiguity_present = 0;
    }
    release_version_if_empty(version);
    return 0;
}

static tp_info_pid_t candidate_with_flags(unsigned char trace_seed,
                                          unsigned char span_seed,
                                          unsigned char flags,
                                          u64 timestamp) {
    tp_info_pid_t value = {
        .tp =
            {
                .ts = timestamp,
                .flags = flags,
            },
        .valid = 1,
        .state = TP_INFO_PID_STATE_PROVENANCE(k_tp_provenance_tcp_exact_flags),
    };
    for (u32 index = 0; index < sizeof(value.tp.trace_id); index++) {
        value.tp.trace_id[index] = trace_seed + index;
    }
    for (u32 index = 0; index < sizeof(value.tp.span_id); index++) {
        value.tp.span_id[index] = span_seed + index;
    }
    return value;
}

static tp_info_pid_t candidate(unsigned char span_seed, u64 timestamp) {
    return candidate_with_flags(1, span_seed, k_flag_sampled, timestamp);
}

static void test_provenance_and_response_sent_share_state_without_aliasing(void) {
    tp_info_pid_t value = {
        .state = TP_INFO_PID_STATE_PROVENANCE(k_tp_provenance_tcp_exact_flags),
    };

    tp_info_pid_set_response_sent(&value, 1);
    if (!tp_info_pid_response_sent(&value) ||
        tp_info_pid_provenance(&value) != k_tp_provenance_tcp_exact_flags) {
        fail("response-sent state corrupted TCP provenance");
    }

    tp_info_pid_set_provenance(&value, k_tp_provenance_ssl_prewrite);
    if (!tp_info_pid_response_sent(&value) ||
        tp_info_pid_provenance(&value) != k_tp_provenance_ssl_prewrite) {
        fail("provenance update corrupted response-sent state");
    }

    tp_info_pid_set_response_sent(&value, 0);
    if (tp_info_pid_response_sent(&value) ||
        tp_info_pid_provenance(&value) != k_tp_provenance_ssl_prewrite) {
        fail("response-sent clear corrupted provenance");
    }
}

static void reset(void) {
    memset(heads, 0, sizeof(heads));
    memset(versions, 0, sizeof(versions));
    legacy_candidate = (tp_info_pid_t){};
    snapshot = (tp_info_pid_t){};
    connection_key_scratch = (connection_info_netns_cookie_t){};
    candidate_scratch = (incoming_trace_candidate_t){};
    generation_counter = 0;
    legacy_present = 0;
    fail_candidate_insert = 0;
    fail_ambiguity_insert = 0;
    publish_during_claim = 0;
    publish_during_ambiguity = 0;
    invalidate_during_claim = 0;
    expected_legacy_connection = (connection_info_t){};
    check_legacy_connection = 0;
    legacy_connection_mismatch = 0;
    legacy_update_flags_mismatch = 0;
    legacy_lookup_calls = 0;
    legacy_update_calls = 0;
    legacy_delete_calls = 0;
    strict_head_delete_calls = 0;
    strict_candidate_delete_calls = 0;
    strict_claim_delete_calls = 0;
    strict_ambiguity_delete_calls = 0;
    expected_strict_delete_generation = 0;
    strict_delete_generation_mismatch = 0;
}

static void test_duplicate_is_idempotent(void) {
    reset();
    connection_info_t connection = {};
    const tp_info_pid_t first = candidate(2, 10);
    tp_info_pid_t duplicate = first;
    duplicate.tp.ts = 20;

    if (update_strict_incoming_trace(&connection, &first, 100, test_netns) !=
        k_incoming_trace_inserted) {
        fail("first candidate was not inserted");
    }
    if (update_strict_incoming_trace(&connection, &duplicate, 100, test_netns) !=
        k_incoming_trace_duplicate) {
        fail("identical retransmission was not idempotent");
    }
    tp_info_pid_t *found = snapshot_strict_incoming_trace(&connection, test_netns);
    if (!found || found->tp.ts != first.tp.ts) {
        fail("identical retransmission replaced the original candidate");
    }
}

static void test_conflict_becomes_ambiguous(void) {
    reset();
    connection_info_t connection = {};
    const tp_info_pid_t first = candidate(2, 10);
    const tp_info_pid_t conflicting = candidate(3, 20);

    update_strict_incoming_trace(&connection, &first, 100, test_netns);
    if (update_strict_incoming_trace(&connection, &conflicting, 200, test_netns) !=
        k_incoming_trace_ambiguous) {
        fail("conflicting candidate was not marked ambiguous");
    }
    if (snapshot_strict_incoming_trace(&connection, test_netns)) {
        fail("ambiguous candidate remained selectable");
    }
    if (update_strict_incoming_trace(&connection, &first, 100, test_netns) !=
        k_incoming_trace_ambiguous) {
        fail("later candidate revived an ambiguous connection");
    }
}

static void test_identical_parent_on_newer_request_gets_new_generation(void) {
    reset();
    connection_info_t connection = {};
    const tp_info_pid_t first = candidate(2, 10);

    update_strict_incoming_trace(&connection, &first, 100, test_netns);
    tp_info_pid_t *taken = consume_strict_incoming_trace(&connection, test_netns);
    if (!taken || taken->tp.span_id[0] != 2) {
        fail("first candidate was not consumed");
    }
    if (update_strict_incoming_trace(&connection, &first, 200, test_netns) !=
        k_incoming_trace_inserted) {
        fail("new request with the same parent did not get a new generation");
    }
    taken = consume_strict_incoming_trace(&connection, test_netns);
    if (!taken || taken->tp.span_id[0] != 2) {
        fail("new request with the same parent was not selectable");
    }
}

static void test_newer_sequence_wrap_replaces_consumed_generation(void) {
    reset();
    connection_info_t connection = {};
    const tp_info_pid_t first = candidate(2, 10);

    update_strict_incoming_trace(&connection, &first, 0xfffffff0U, test_netns);
    if (!consume_strict_incoming_trace(&connection, test_netns)) {
        fail("sequence-wrap predecessor was not consumed");
    }
    if (update_strict_incoming_trace(&connection, &first, 0x10U, test_netns) !=
        k_incoming_trace_inserted) {
        fail("new request across TCP sequence wrap did not replace the tombstone");
    }
}

static void test_newer_candidate_replaces_consumed_tombstone(void) {
    reset();
    connection_info_t connection = {};
    const tp_info_pid_t first = candidate(2, 10);
    const tp_info_pid_t second = candidate(3, 20);

    update_strict_incoming_trace(&connection, &first, 100, test_netns);
    consume_strict_incoming_trace(&connection, test_netns);
    if (update_strict_incoming_trace(&connection, &second, 200, test_netns) !=
        k_incoming_trace_inserted) {
        fail("newer request did not replace the consumed tombstone");
    }
    tp_info_pid_t *taken = consume_strict_incoming_trace(&connection, test_netns);
    if (!taken || taken->tp.span_id[0] != 3) {
        fail("newer request did not retain its exact parent");
    }
}

static void test_late_old_candidate_makes_pending_new_request_ambiguous(void) {
    reset();
    connection_info_t connection = {};
    const tp_info_pid_t first = candidate(2, 10);
    const tp_info_pid_t second = candidate(3, 20);

    update_strict_incoming_trace(&connection, &first, 100, test_netns);
    consume_strict_incoming_trace(&connection, test_netns);
    update_strict_incoming_trace(&connection, &second, 200, test_netns);
    if (update_strict_incoming_trace(&connection, &first, 100, test_netns) !=
        k_incoming_trace_ambiguous) {
        fail("late predecessor did not invalidate the pending request");
    }
    if (consume_strict_incoming_trace(&connection, test_netns)) {
        fail("late predecessor left a selectable parent");
    }
}

static void test_map_pressure_fails_closed(void) {
    reset();
    connection_info_t connection = {};
    const tp_info_pid_t first = candidate(2, 10);
    fail_candidate_insert = 1;

    if (update_strict_incoming_trace(&connection, &first, 100, test_netns) !=
            k_incoming_trace_update_failed ||
        find_head(&(connection_info_netns_cookie_t){.netns_cookie = test_netns})) {
        fail("map pressure retained a selectable candidate");
    }
}

static void test_ambiguity_marker_pressure_fails_closed(void) {
    reset();
    connection_info_t connection = {};
    const tp_info_pid_t first = candidate(2, 10);
    const tp_info_pid_t conflicting = candidate(3, 20);

    update_strict_incoming_trace(&connection, &first, 100, test_netns);
    fail_ambiguity_insert = 1;
    u64 ambiguous_generation = 0;
    if (update_strict_incoming_trace_with_generation(
            &connection, &conflicting, 200, test_netns, &ambiguous_generation) !=
            k_incoming_trace_update_failed ||
        ambiguous_generation != 1 || snapshot_strict_incoming_trace(&connection, test_netns) ||
        find_head(&(connection_info_netns_cookie_t){.netns_cookie = test_netns}) ||
        find_version(ambiguous_generation)) {
        fail("ambiguity marker pressure left a selectable generation");
    }
}

static void test_conflict_after_claim_persists_ambiguity(void) {
    reset();
    connection_info_t connection = {};
    const tp_info_pid_t first = candidate(2, 10);
    const tp_info_pid_t conflicting = candidate(3, 20);

    update_strict_incoming_trace(&connection, &first, 100, test_netns);
    u64 generation = 0;
    if (!consume_strict_incoming_trace_with_generation(&connection, test_netns, &generation) ||
        !generation) {
        fail("candidate was not claimed before the conflict");
    }
    u64 ambiguous_generation = 0;
    if (update_strict_incoming_trace_with_generation(
            &connection, &conflicting, 100, test_netns, &ambiguous_generation) !=
            k_incoming_trace_ambiguous ||
        ambiguous_generation != generation ||
        incoming_trace_claimed_generation_matches_in_netns_cookie(
            &connection, test_netns, generation, &first)) {
        fail("conflict after claim did not persist exact-generation ambiguity");
    }
}

static void test_generation_collision_preserves_existing_candidate(void) {
    reset();
    connection_info_t connection = {};
    const tp_info_pid_t existing = candidate(2, 10);
    const tp_info_pid_t colliding = candidate(3, 20);
    test_version_t *reserved = allocate_version(1);
    reserved->candidate = (incoming_trace_candidate_t){
        .candidate = existing,
        .tcp_sequence = 50,
    };
    reserved->candidate_present = 1;

    if (update_strict_incoming_trace(&connection, &colliding, 100, test_netns) !=
            k_incoming_trace_update_failed ||
        reserved->candidate.candidate.tp.span_id[0] != existing.tp.span_id[0] ||
        find_head(&(connection_info_netns_cookie_t){.netns_cookie = test_netns})) {
        fail("generation collision overwrote an existing candidate");
    }
}

static void test_identical_tuple_is_isolated_by_network_namespace(void) {
    reset();
    connection_info_t connection = {};
    const tp_info_pid_t first = candidate(2, 10);
    const tp_info_pid_t second = candidate(3, 20);

    if (update_strict_incoming_trace(&connection, &first, 100, test_netns) !=
            k_incoming_trace_inserted ||
        snapshot_strict_incoming_trace(&connection, other_netns)) {
        fail("candidate crossed into another network namespace");
    }
    if (update_strict_incoming_trace(&connection, &second, 100, other_netns) !=
        k_incoming_trace_inserted) {
        fail("same tuple in another network namespace collided");
    }

    tp_info_pid_t *taken = consume_strict_incoming_trace(&connection, other_netns);
    if (!taken || taken->tp.span_id[0] != 3) {
        fail("other network namespace selected the wrong candidate");
    }
    taken = consume_strict_incoming_trace(&connection, test_netns);
    if (!taken || taken->tp.span_id[0] != 2) {
        fail("original network namespace lost its candidate");
    }
}

static void test_publication_during_claim_fails_closed(void) {
    reset();
    connection_info_t connection = {};
    const tp_info_pid_t first = candidate(2, 10);
    const tp_info_pid_t second = candidate(3, 20);
    update_strict_incoming_trace(&connection, &first, 100, test_netns);

    const u64 next_generation = ++generation_counter;
    test_version_t *next = allocate_version(next_generation);
    next->candidate = (incoming_trace_candidate_t){
        .candidate = second,
        .tcp_sequence = 200,
    };
    next->candidate_present = 1;
    publish_during_claim = next_generation;

    if (consume_strict_incoming_trace(&connection, test_netns)) {
        fail("consumer returned a candidate across a concurrent publication");
    }
    test_version_t *old = find_version(1);
    if (!old || old->claim_present) {
        fail("failed publication validation leaked an old-generation claim");
    }
    tp_info_pid_t *taken = consume_strict_incoming_trace(&connection, test_netns);
    if (!taken || taken->tp.span_id[0] != 3) {
        fail("consumer did not select the newly published immutable candidate");
    }
}

static void test_publication_during_invalidation_does_not_leak_marker(void) {
    reset();
    connection_info_t connection = {};
    const tp_info_pid_t first = candidate(2, 10);
    const tp_info_pid_t second = candidate(3, 20);
    update_strict_incoming_trace(&connection, &first, 100, test_netns);

    const u64 next_generation = ++generation_counter;
    test_version_t *next = allocate_version(next_generation);
    next->candidate = (incoming_trace_candidate_t){
        .candidate = second,
        .tcp_sequence = 200,
    };
    next->candidate_present = 1;
    publish_during_ambiguity = next_generation;
    invalidate_strict_incoming_trace(&connection, test_netns, 30);

    test_version_t *old = find_version(1);
    if (!old || old->ambiguity_present) {
        fail("concurrent invalidation leaked an old-generation marker");
    }
    tp_info_pid_t *taken = consume_strict_incoming_trace(&connection, test_netns);
    if (!taken || taken->tp.span_id[0] != 3) {
        fail("concurrent invalidation poisoned the newly published candidate");
    }
}

static void test_invalidation_during_claim_fails_closed(void) {
    reset();
    connection_info_t connection = {};
    const tp_info_pid_t first = candidate(2, 10);
    update_strict_incoming_trace(&connection, &first, 100, test_netns);
    invalidate_during_claim = 1;

    if (consume_strict_incoming_trace(&connection, test_netns)) {
        fail("consumer returned a candidate invalidated during its claim");
    }
}

static void test_disallowed_claim_preserves_candidate(void) {
    reset();
    connection_info_t connection = {};
    const tp_info_pid_t first = candidate(2, 10);
    update_strict_incoming_trace(&connection, &first, 100, test_netns);

    u64 generation = 99;
    if (consume_strict_incoming_trace_with_generation_if_allowed(
            &connection, test_netns, &generation, 0) ||
        generation || !snapshot_strict_incoming_trace(&connection, test_netns)) {
        fail("disallowed consumer changed the pending candidate");
    }

    tp_info_pid_t *taken = consume_strict_incoming_trace(&connection, test_netns);
    if (!taken || taken->tp.span_id[0] != first.tp.span_id[0]) {
        fail("lifecycle consumer could not claim the reserved candidate");
    }
}

static void test_zero_network_namespace_cookie_is_rejected(void) {
    reset();
    connection_info_t connection = {};
    const tp_info_pid_t first = candidate(2, 10);

    if (update_strict_incoming_trace(&connection, &first, 100, 0) !=
            k_incoming_trace_update_failed ||
        snapshot_strict_incoming_trace(&connection, 0) ||
        consume_strict_incoming_trace(&connection, 0)) {
        fail("zero network namespace cookie retained a selectable candidate");
    }
}

static void test_handoff_candidate_preserves_raw_tcp_parent(void) {
    const unsigned char exact_flags[] = {0, k_flag_sampled, test_future_sampled_flags};

    for (size_t flag_index = 0; flag_index < sizeof(exact_flags) / sizeof(exact_flags[0]);
         flag_index++) {
        reset();
        const connection_info_t connection = {
            .s_port = test_source_port,
            .d_port = test_destination_port,
        };
        const tp_info_pid_t raw = candidate_with_flags(
            test_trace_seed, test_span_seed, exact_flags[flag_index], test_candidate_timestamp);
        if (update_strict_incoming_trace(&connection, &raw, test_tcp_sequence, test_netns) !=
            k_incoming_trace_inserted) {
            fail("raw TCP parent was not published");
        }

        u64 incoming_generation = 0;
        tp_info_pid_t *consumed = consume_strict_incoming_trace_with_generation(
            &connection, test_netns, &incoming_generation);
        if (!consumed || !incoming_generation) {
            fail("raw TCP parent was not claimed for handoff");
        }
        const u64 claimed_generation = incoming_generation;

        tp_info_t server = {.flags = test_generated_flags};
        for (u32 index = 0; index < sizeof(server.span_id); index++) {
            server.span_id[index] = test_generated_span_seed + index;
        }
        const tp_info_t generated_server = server;
        tp_info_pid_t staged = {};
        if (!apply_incoming_trace_candidate(&server, consumed, &staged, &incoming_generation)) {
            fail("valid raw TCP parent was rejected for handoff");
        }
        if (memcmp(&staged, &raw, sizeof(staged)) != 0 ||
            memcmp(server.trace_id, raw.tp.trace_id, sizeof(server.trace_id)) != 0 ||
            memcmp(server.parent_id, raw.tp.span_id, sizeof(server.parent_id)) != 0 ||
            memcmp(server.span_id, generated_server.span_id, sizeof(server.span_id)) != 0 ||
            memcmp(staged.tp.span_id, generated_server.span_id, sizeof(staged.tp.span_id)) == 0 ||
            server.flags != exact_flags[flag_index]) {
            fail("handoff candidate did not preserve the exact raw TCP parent");
        }
        if (consume_strict_incoming_trace(&connection, test_netns)) {
            fail("raw TCP parent could be claimed more than once");
        }

        const connection_info_netns_cookie_t key = {
            .connection = connection,
            .netns_cookie = test_netns,
        };
        test_version_t *claimed = find_version(claimed_generation);
        if (!claimed || !claimed->candidate_present || !claimed->claim_present) {
            fail("claimed raw TCP parent lost independent map state");
        }
        claimed->ambiguous = 1;
        claimed->ambiguity_present = 1;
        expected_strict_delete_generation = claimed_generation;
        delete_strict_incoming_trace(&connection, test_netns);
        if (find_head(&key) || find_version(claimed_generation) || strict_head_delete_calls != 1 ||
            strict_candidate_delete_calls != 1 || strict_claim_delete_calls != 1 ||
            strict_ambiguity_delete_calls != 1 || strict_delete_generation_mismatch) {
            fail("raw TCP parent state survived explicit deletion");
        }
    }
}

static void test_legacy_tcp_parent_preserves_server_flags(void) {
    const tp_info_pid_t raw = candidate_with_flags(
        test_trace_seed, test_span_seed, test_future_sampled_flags, test_candidate_timestamp);
    tp_info_pid_t legacy = raw;
    tp_info_pid_set_provenance(&legacy, k_tp_provenance_tcp_legacy);
    tp_info_t server = {.flags = test_generated_flags};

    if (!apply_incoming_trace_candidate(&server, &legacy, NULL, NULL) ||
        memcmp(server.trace_id, legacy.tp.trace_id, sizeof(server.trace_id)) != 0 ||
        memcmp(server.parent_id, legacy.tp.span_id, sizeof(server.parent_id)) != 0 ||
        server.flags != test_generated_flags) {
        fail("legacy TCP parent changed OBI trace-parent behavior");
    }
}

static void test_invalid_tcp_parents_are_not_staged(void) {
    for (enum invalid_parent_case invalid_case = invalid_parent_valid_bit;
         invalid_case < invalid_parent_case_count;
         invalid_case++) {
        reset();
        const connection_info_t connection = {
            .s_port = test_source_port,
            .d_port = test_destination_port,
        };
        tp_info_pid_t raw = candidate_with_flags(
            test_trace_seed, test_span_seed, k_flag_sampled, test_candidate_timestamp);
        if (invalid_case == invalid_parent_valid_bit) {
            raw.valid = 0;
        } else if (invalid_case == invalid_parent_all_zero_ids) {
            memset(raw.tp.trace_id, 0, sizeof(raw.tp.trace_id));
            memset(raw.tp.span_id, 0, sizeof(raw.tp.span_id));
        } else if (invalid_case == invalid_parent_zero_trace_id) {
            memset(raw.tp.trace_id, 0, sizeof(raw.tp.trace_id));
        } else {
            memset(raw.tp.span_id, 0, sizeof(raw.tp.span_id));
        }
        if (update_strict_incoming_trace(&connection, &raw, test_tcp_sequence, test_netns) !=
            k_incoming_trace_inserted) {
            fail("invalid candidate setup failed");
        }

        u64 incoming_generation = 0;
        tp_info_pid_t *consumed = consume_strict_incoming_trace_with_generation(
            &connection, test_netns, &incoming_generation);
        const connection_info_netns_cookie_t key = {
            .connection = connection,
            .netns_cookie = test_netns,
        };
        const test_head_t *head = find_head(&key);
        if (!head) {
            fail("invalid candidate lost its cleanup key");
        }
        const u64 published_generation = head->generation;

        tp_info_t server;
        memset(&server, test_server_poison, sizeof(server));
        server.flags = test_generated_flags;
        const tp_info_t original_server = server;
        tp_info_pid_t staged;
        memset(&staged, test_staging_poison, sizeof(staged));
        const tp_info_pid_t original_staged = staged;
        u64 stage_generation = incoming_generation ? incoming_generation : published_generation;
        const tp_info_pid_t *stage_candidate = consumed ? consumed : &raw;
        if (apply_incoming_trace_candidate(&server, stage_candidate, &staged, &stage_generation) ||
            stage_generation || memcmp(&server, &original_server, sizeof(server)) != 0 ||
            memcmp(&staged, &original_staged, sizeof(staged)) != 0) {
            fail("invalid TCP parent was staged as valid");
        }

        expected_strict_delete_generation = published_generation;
        delete_strict_incoming_trace(&connection, test_netns);
        if (find_head(&key) || find_version(published_generation) ||
            strict_head_delete_calls != 1 || strict_candidate_delete_calls != 1 ||
            strict_claim_delete_calls != 1 || strict_ambiguity_delete_calls != 1 ||
            strict_delete_generation_mismatch) {
            fail("invalid TCP parent state survived explicit deletion");
        }
    }
}

static void test_disabled_path_retains_legacy_overwrite_and_delete(void) {
    reset();
    const connection_info_t connection = {
        .s_port = test_source_port,
        .d_port = test_destination_port,
    };
    const tp_info_pid_t first = candidate(2, 10);
    const tp_info_pid_t second = candidate(3, 20);
    expected_legacy_connection = connection;
    check_legacy_connection = 1;

    if (update_incoming_trace(&connection, &first, 100, test_netns) != k_incoming_trace_inserted ||
        update_incoming_trace(&connection, &second, 200, test_netns) != k_incoming_trace_inserted) {
        fail("legacy incoming parent update failed");
    }
    tp_info_pid_t *taken = consume_incoming_trace_in_netns_cookie(&connection, other_netns);
    if (taken != &snapshot || memcmp(taken, &second, sizeof(second)) != 0 || legacy_present ||
        legacy_update_calls != 2 || legacy_lookup_calls != 1 || legacy_delete_calls != 1 ||
        legacy_connection_mismatch || legacy_update_flags_mismatch) {
        fail("disabled bridge changed legacy overwrite/delete behavior");
    }
    if (consume_incoming_trace_in_netns_cookie(&connection, test_netns) ||
        legacy_lookup_calls != 2 || legacy_delete_calls != 1) {
        fail("legacy incoming parent was not deleted after one lookup");
    }
}

int main(void) {
    test_provenance_and_response_sent_share_state_without_aliasing();
    test_duplicate_is_idempotent();
    test_conflict_becomes_ambiguous();
    test_identical_parent_on_newer_request_gets_new_generation();
    test_newer_sequence_wrap_replaces_consumed_generation();
    test_newer_candidate_replaces_consumed_tombstone();
    test_late_old_candidate_makes_pending_new_request_ambiguous();
    test_map_pressure_fails_closed();
    test_ambiguity_marker_pressure_fails_closed();
    test_conflict_after_claim_persists_ambiguity();
    test_generation_collision_preserves_existing_candidate();
    test_identical_tuple_is_isolated_by_network_namespace();
    test_publication_during_claim_fails_closed();
    test_publication_during_invalidation_does_not_leak_marker();
    test_invalidation_during_claim_fails_closed();
    test_disallowed_claim_preserves_candidate();
    test_zero_network_namespace_cookie_is_rejected();
    test_handoff_candidate_preserves_raw_tcp_parent();
    test_legacy_tcp_parent_preserves_server_flags();
    test_invalid_tcp_parents_are_not_staged();
    test_disabled_path_retains_legacy_overwrite_and_delete();
    return 0;
}
