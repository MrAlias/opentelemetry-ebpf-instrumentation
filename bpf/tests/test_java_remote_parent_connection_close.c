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

#define bpf_map_lookup_elem test_map_lookup
#define bpf_map_update_elem test_map_update
#define bpf_map_delete_elem test_map_delete
#define bpf_ktime_get_ns test_ktime_get_ns

#include <maps/java_remote_parent_shared.h>

#undef bpf_map_lookup_elem
#undef bpf_map_update_elem
#undef bpf_map_delete_elem
#undef bpf_ktime_get_ns

static connection_info_ns_t staged_key;
static connection_info_netns_cookie_t cookie_staged_key;
static java_remote_parent_connection_t staged_connection;
static java_remote_parent_connection_t cookie_staged_connection;
static java_remote_parent_owner_t indexed_owner;
static java_remote_parent_key_t ambiguous_key;
static u64 ambiguity_observed_monotime_ns;
static java_remote_parent_key_t stored_claim_key;
static java_remote_parent_claim_t stored_claim;
static java_remote_parent_response_t fallback_record;
static int staged_present;
static int cookie_staged_present;
static int owner_present;
static int ambiguity_present;
static int fallback_present;
static int claim_present;
static int reject_claim_update;

static void fail(const char *message) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

static int same_owner(const pid_key_t *left, const pid_key_t *right) {
    return memcmp(left, right, sizeof(*left)) == 0;
}

static int ambiguity_reserved(void) {
    return ambiguity_present && !ambiguity_observed_monotime_ns;
}

static int ambiguity_marked(void) {
    return ambiguity_present && ambiguity_observed_monotime_ns;
}

static void *test_map_lookup(void *map, const void *key) {
    if (map == &java_remote_parent_connections && staged_present &&
        memcmp(key, &staged_key, sizeof(staged_key)) == 0) {
        return &staged_connection;
    }
    if (map == &java_remote_parent_cookie_connections && cookie_staged_present &&
        memcmp(key, &cookie_staged_key, sizeof(cookie_staged_key)) == 0) {
        return &cookie_staged_connection;
    }
    if (map == &java_remote_parent_owners && owner_present &&
        same_owner(key, &staged_connection.owner)) {
        return &indexed_owner;
    }
    if (map == &java_remote_parent_ambiguity && ambiguity_present &&
        memcmp(key, &ambiguous_key, sizeof(ambiguous_key)) == 0) {
        return &ambiguity_observed_monotime_ns;
    }
    if (map == &java_remote_parent_claims && claim_present &&
        memcmp(key, &stored_claim_key, sizeof(stored_claim_key)) == 0) {
        return &stored_claim;
    }
    if (map == &java_remote_parent_fallback && fallback_present &&
        same_owner(key, &staged_connection.owner)) {
        return &fallback_record;
    }
    return NULL;
}

static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags) {
    if (map == &java_remote_parent_claims && flags == BPF_NOEXIST && !claim_present &&
        !reject_claim_update) {
        stored_claim_key = *(const java_remote_parent_key_t *)key;
        stored_claim = *(const java_remote_parent_claim_t *)value;
        claim_present = 1;
        return 0;
    }
    if (map == &java_remote_parent_ambiguity && (flags == BPF_ANY || flags == BPF_NOEXIST) &&
        !(flags == BPF_NOEXIST && ambiguity_present)) {
        ambiguous_key = *(const java_remote_parent_key_t *)key;
        ambiguity_observed_monotime_ns = *(const u64 *)value;
        ambiguity_present = 1;
        return 0;
    }
    return -1;
}

static long test_map_delete(void *map, const void *key) {
    if (map == &java_remote_parent_connections && staged_present &&
        memcmp(key, &staged_key, sizeof(staged_key)) == 0) {
        staged_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_cookie_connections && cookie_staged_present &&
        memcmp(key, &cookie_staged_key, sizeof(cookie_staged_key)) == 0) {
        cookie_staged_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_ambiguity && ambiguity_present &&
        memcmp(key, &ambiguous_key, sizeof(ambiguous_key)) == 0) {
        ambiguity_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_fallback && fallback_present &&
        same_owner(key, &staged_connection.owner)) {
        fallback_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_claims && claim_present &&
        memcmp(key, &stored_claim_key, sizeof(stored_claim_key)) == 0) {
        claim_present = 0;
        return 0;
    }
    return -1;
}

static unsigned long long test_ktime_get_ns(void) {
    return 123;
}

static void reset_state(const connection_info_t *connection,
                        u32 netns,
                        u64 netns_cookie,
                        u64 incoming_generation) {
    memset(&staged_connection, 0, sizeof(staged_connection));
    memset(&indexed_owner, 0, sizeof(indexed_owner));
    memset(&ambiguous_key, 0, sizeof(ambiguous_key));
    ambiguity_observed_monotime_ns = 0;
    memset(&stored_claim_key, 0, sizeof(stored_claim_key));
    memset(&stored_claim, 0, sizeof(stored_claim));
    memset(&fallback_record, 0, sizeof(fallback_record));

    staged_key = connection_info_with_netns(connection, netns);
    cookie_staged_key = connection_info_with_netns_cookie(connection, netns_cookie);
    staged_connection.owner = (pid_key_t){.tid = 7, .pid = 5, .ns = 3};
    staged_connection.netns = netns;
    staged_connection.generation = 11;
    staged_connection.netns_cookie = netns_cookie;
    staged_connection.incoming_generation = incoming_generation;
    staged_connection.socket_cookie = 86;
    cookie_staged_connection = staged_connection;
    indexed_owner.generation = staged_connection.generation;
    indexed_owner.process_incarnation = 9;
    indexed_owner.lifecycle = k_java_remote_parent_lifecycle_active;
    ambiguous_key = (java_remote_parent_key_t){
        .owner = staged_connection.owner,
        .generation = staged_connection.generation,
    };
    java_remote_parent_init_response(
        &fallback_record, k_java_remote_parent_status_valid, staged_connection.generation, 1);
    staged_present = 1;
    cookie_staged_present = 1;
    owner_present = 1;
    ambiguity_present = 1;
    fallback_present = 1;
    claim_present = 0;
    reject_claim_update = 0;
}

static void test_connection_close_invalidates_staged_generation(void) {
    const connection_info_t connection = {
        .s_port = 1234,
        .d_port = 443,
    };
    reset_state(&connection, 42, 84, 21);

    java_remote_parent_mark_connection_ambiguous_in_netns_cookie_for_socket(&connection, 84, 86, 0);

    if (staged_present || cookie_staged_present) {
        fail("sockops close preserved a staged connection index");
    }
    if (!ambiguity_marked() || ambiguous_key.generation != staged_connection.generation ||
        !same_owner(&ambiguous_key.owner, &staged_connection.owner)) {
        fail("connection close did not invalidate the staged generation");
    }
    if (!fallback_present) {
        fail("valid invalidation removed fallback before retrieval cleanup");
    }
}

static void test_orphaned_connection_close_quarantines_and_cleans_indexes(void) {
    const connection_info_t connection = {
        .s_port = 1234,
        .d_port = 443,
    };
    reset_state(&connection, 42, 84, 21);
    owner_present = 0;

    java_remote_parent_mark_connection_ambiguous_in_netns_cookie_for_socket(&connection, 84, 86, 0);

    if (staged_present || cookie_staged_present || !ambiguity_marked() || !fallback_present ||
        claim_present) {
        fail("orphaned close did not quarantine and clean its physical indexes");
    }
}

static void test_other_incoming_generation_does_not_invalidate_stage(void) {
    const connection_info_t connection = {
        .s_port = 1234,
        .d_port = 443,
    };
    reset_state(&connection, 42, 84, 21);

    java_remote_parent_mark_connection_ambiguous_in_netns_cookie(&connection, 84, 22);

    if (!staged_present || !cookie_staged_present || !ambiguity_reserved()) {
        fail("another incoming generation invalidated the staged request");
    }
}

static void test_matching_incoming_generation_invalidates_stage(void) {
    const connection_info_t connection = {
        .s_port = 1234,
        .d_port = 443,
    };
    reset_state(&connection, 42, 84, 21);

    java_remote_parent_mark_connection_ambiguous_in_netns_cookie(&connection, 84, 21);

    if (staged_present || cookie_staged_present || !ambiguity_marked()) {
        fail("matching incoming generation did not invalidate the staged request");
    }
}

static void test_connection_match_requires_consistent_indexes(void) {
    const connection_info_t connection = {
        .s_port = 1234,
        .d_port = 443,
    };
    reset_state(&connection, 42, 84, 21);

    if (!java_remote_parent_connection_matches_in_netns(
            &connection, 42, &staged_connection.owner, staged_connection.generation, 21, 0)) {
        fail("consistent connection indexes did not match");
    }

    cookie_staged_connection.incoming_generation++;
    if (java_remote_parent_connection_matches_in_netns(
            &connection, 42, &staged_connection.owner, staged_connection.generation, 21, 0)) {
        fail("inconsistent connection indexes matched");
    }
    cookie_staged_connection = staged_connection;
    cookie_staged_connection.socket_cookie++;
    if (java_remote_parent_connection_matches_in_netns(
            &connection, 42, &staged_connection.owner, staged_connection.generation, 21, 0)) {
        fail("inconsistent socket cookie indexes matched");
    }
    cookie_staged_connection = staged_connection;
    if (java_remote_parent_connection_matches_socket_in_netns(&connection,
                                                              42,
                                                              &staged_connection.owner,
                                                              staged_connection.generation,
                                                              21,
                                                              staged_connection.socket_cookie +
                                                                  1)) {
        fail("a different physical socket matched the staged request");
    }
    if (java_remote_parent_connection_matches_socket_in_netns(
            &connection, 42, &staged_connection.owner, staged_connection.generation, 21, 0)) {
        fail("a zero physical socket identity matched the staged request");
    }
    if (!java_remote_parent_connection_matches_socket_in_netns(&connection,
                                                               42,
                                                               &staged_connection.owner,
                                                               staged_connection.generation,
                                                               21,
                                                               staged_connection.socket_cookie)) {
        fail("the exact physical socket did not match the staged request");
    }
    cookie_staged_present = 0;
    if (java_remote_parent_connection_matches_in_netns(
            &connection, 42, &staged_connection.owner, staged_connection.generation, 21, 0)) {
        fail("missing cookie connection index matched");
    }
}

static void test_delayed_cleanup_preserves_reused_physical_connection(void) {
    const connection_info_t connection = {
        .s_port = 1234,
        .d_port = 443,
    };
    reset_state(&connection, 42, 84, 21);
    const java_remote_parent_connection_t stale = staged_connection;
    staged_connection.socket_cookie++;
    cookie_staged_connection.socket_cookie++;

    java_remote_parent_delete_connection_indexes(&connection, &stale);

    if (!staged_present || !cookie_staged_present) {
        fail("delayed cleanup deleted a physically different replacement connection");
    }
}

static void test_delayed_close_preserves_reused_physical_connection(void) {
    const connection_info_t connection = {
        .s_port = 1234,
        .d_port = 443,
    };
    reset_state(&connection, 42, 84, 21);
    staged_connection.socket_cookie = 87;
    cookie_staged_connection.socket_cookie = 87;

    java_remote_parent_mark_connection_ambiguous_in_netns_cookie_for_socket(&connection, 84, 86, 0);
    if (!staged_present || !cookie_staged_present || !ambiguity_reserved() || !fallback_present) {
        fail("delayed close invalidated a physically different replacement connection");
    }

    java_remote_parent_mark_connection_ambiguous_in_netns_cookie_for_socket(&connection, 84, 87, 0);
    if (staged_present || cookie_staged_present || !ambiguity_marked() || !fallback_present) {
        fail("matching physical close did not invalidate its staged connection");
    }
}

static void test_full_width_network_namespace_cookie_is_required(void) {
    const connection_info_t connection = {
        .s_port = 1234,
        .d_port = 443,
    };
    const u64 staged_cookie = 0x10000002aULL;
    const u64 colliding_low_bits = 0x20000002aULL;
    reset_state(&connection, 42, staged_cookie, 21);

    java_remote_parent_mark_connection_ambiguous_in_netns_cookie(
        &connection, colliding_low_bits, 21);

    if (!staged_present || !cookie_staged_present || !ambiguity_reserved()) {
        fail("a low-32-bit namespace cookie collision invalidated the staged request");
    }
}

static void test_claimed_stage_owns_close_race(void) {
    const connection_info_t connection = {
        .s_port = 1234,
        .d_port = 443,
    };
    reset_state(&connection, 42, 84, 21);
    stored_claim_key = (java_remote_parent_key_t){
        .owner = staged_connection.owner,
        .generation = staged_connection.generation,
    };
    stored_claim = (java_remote_parent_claim_t){
        .observed_monotime_ns = 122,
        .process_incarnation = indexed_owner.process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_publishing,
    };
    claim_present = 1;

    java_remote_parent_mark_connection_ambiguous_in_netns_cookie_for_socket(&connection, 84, 86, 0);

    if (!staged_present || !cookie_staged_present || !ambiguity_marked() || !fallback_present ||
        !claim_present) {
        fail("close raced incorrectly with an owned Java retrieval");
    }
}

static void test_claim_pressure_preserves_ambiguous_physical_generation(void) {
    const connection_info_t connection = {
        .s_port = 1234,
        .d_port = 443,
    };
    reset_state(&connection, 42, 84, 21);
    reject_claim_update = 1;

    java_remote_parent_mark_connection_ambiguous_in_netns_cookie_for_socket(&connection, 84, 86, 0);

    if (!staged_present || !cookie_staged_present || !ambiguity_marked() || !fallback_present ||
        claim_present) {
        fail("claim pressure exposed or deleted an unowned physical generation");
    }
}

int main(void) {
    test_connection_close_invalidates_staged_generation();
    test_orphaned_connection_close_quarantines_and_cleans_indexes();
    test_other_incoming_generation_does_not_invalidate_stage();
    test_matching_incoming_generation_invalidates_stage();
    test_connection_match_requires_consistent_indexes();
    test_delayed_cleanup_preserves_reused_physical_connection();
    test_delayed_close_preserves_reused_physical_connection();
    test_full_width_network_namespace_cookie_is_required();
    test_claimed_stage_owns_close_race();
    test_claim_pressure_preserves_ambiguous_physical_generation();
    return 0;
}
