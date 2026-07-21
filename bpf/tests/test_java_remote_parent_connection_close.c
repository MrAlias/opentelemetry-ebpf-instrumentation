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
static java_remote_parent_connection_t staged_connection;
static java_remote_parent_owner_t indexed_owner;
static java_remote_parent_key_t ambiguous_key;
static java_remote_parent_response_t fallback_record;
static int staged_present;
static int owner_present;
static int ambiguity_present;
static int fallback_present;

static void fail(const char *message) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

static int same_owner(const pid_key_t *left, const pid_key_t *right) {
    return memcmp(left, right, sizeof(*left)) == 0;
}

static void *test_map_lookup(void *map, const void *key) {
    if (map == &java_remote_parent_connections && staged_present &&
        memcmp(key, &staged_key, sizeof(staged_key)) == 0) {
        return &staged_connection;
    }
    if (map == &java_remote_parent_owners && owner_present &&
        same_owner(key, &staged_connection.owner)) {
        return &indexed_owner;
    }
    if (map == &java_remote_parent_ambiguity && ambiguity_present &&
        memcmp(key, &ambiguous_key, sizeof(ambiguous_key)) == 0) {
        return &ambiguous_key.generation;
    }
    if (map == &java_remote_parent_fallback && fallback_present &&
        same_owner(key, &staged_connection.owner)) {
        return &fallback_record;
    }
    return NULL;
}

static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags) {
    (void)value;
    if (map != &java_remote_parent_ambiguity || flags != BPF_ANY) {
        return -1;
    }
    ambiguous_key = *(const java_remote_parent_key_t *)key;
    ambiguity_present = 1;
    return 0;
}

static long test_map_delete(void *map, const void *key) {
    if (map == &java_remote_parent_connections && staged_present &&
        memcmp(key, &staged_key, sizeof(staged_key)) == 0) {
        staged_present = 0;
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
    return -1;
}

static unsigned long long test_ktime_get_ns(void) {
    return 123;
}

static void reset_state(const connection_info_t *connection, u32 netns) {
    memset(&staged_connection, 0, sizeof(staged_connection));
    memset(&indexed_owner, 0, sizeof(indexed_owner));
    memset(&ambiguous_key, 0, sizeof(ambiguous_key));
    memset(&fallback_record, 0, sizeof(fallback_record));

    staged_key = connection_info_with_netns(connection, netns);
    staged_connection.owner = (pid_key_t){.tid = 7, .pid = 5, .ns = 3};
    staged_connection.generation = 11;
    indexed_owner.generation = staged_connection.generation;
    indexed_owner.lifecycle = k_java_remote_parent_lifecycle_active;
    java_remote_parent_init_response(
        &fallback_record, k_java_remote_parent_status_valid, staged_connection.generation, 1);
    staged_present = 1;
    owner_present = 1;
    ambiguity_present = 0;
    fallback_present = 1;
}

static void test_connection_close_invalidates_staged_generation(void) {
    const connection_info_t connection = {
        .s_port = 1234,
        .d_port = 443,
    };
    reset_state(&connection, 42);

    java_remote_parent_mark_connection_ambiguous_in_netns(&connection, 42);

    if (staged_present) {
        fail("connection close preserved its staged connection");
    }
    if (!ambiguity_present || ambiguous_key.generation != staged_connection.generation ||
        !same_owner(&ambiguous_key.owner, &staged_connection.owner)) {
        fail("connection close did not invalidate the staged generation");
    }
    if (!fallback_present) {
        fail("valid invalidation removed fallback before retrieval cleanup");
    }
}

static void test_orphaned_connection_close_removes_fallback(void) {
    const connection_info_t connection = {
        .s_port = 1234,
        .d_port = 443,
    };
    reset_state(&connection, 42);
    owner_present = 0;

    java_remote_parent_mark_connection_ambiguous_in_netns(&connection, 42);

    if (staged_present || ambiguity_present || fallback_present) {
        fail("orphaned close did not fail closed");
    }
}

int main(void) {
    test_connection_close_invalidates_staged_generation();
    test_orphaned_connection_close_removes_fallback();
    return 0;
}
