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
static u64 test_java_process_capability_for(const pid_key_t *owner);
static u64 test_java_process_incarnation_for(const pid_key_t *owner);
static u64 test_java_current_process_incarnation(void);
static u8 test_java_remote_parent_data_hook_is_ready(void);

#define task_tid test_task_tid
#define java_vt_translate_tid test_java_vt_translate_tid
#define java_process_capability_for test_java_process_capability_for
#define java_process_incarnation_for test_java_process_incarnation_for
#define java_current_process_incarnation test_java_current_process_incarnation
#define java_remote_parent_data_hook_is_ready test_java_remote_parent_data_hook_is_ready

#include <maps/java_remote_parent.h>

#undef java_remote_parent_data_hook_is_ready
#undef java_current_process_incarnation
#undef java_process_incarnation_for
#undef java_process_capability_for
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
    test_successor_generation = 0x55,
};

static const pid_key_t test_owner = {.tid = 7, .pid = 5, .ns = 3};
static const pid_key_t test_physical_successor_owner = {.tid = 17, .pid = 15, .ns = 13};
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
static java_remote_parent_owner_t stored_owner;
static pid_key_t stored_owner_key;
static int owner_present;
static java_remote_parent_key_t stored_state_key;
static java_remote_parent_state_t stored_state;
static int state_present;
static java_remote_parent_key_t replacement_state_key;
static java_remote_parent_state_t replacement_state;
static int replacement_state_present;
static java_remote_parent_key_t stored_generation_index_key;
static java_remote_parent_generation_index_t stored_generation_index;
static int generation_index_present;
static java_remote_parent_key_t replacement_generation_index_key;
static java_remote_parent_generation_index_t replacement_generation_index;
static int replacement_generation_index_present;
static connection_info_ns_t stored_connection_key;
static java_remote_parent_connection_t stored_connection;
static int connection_present;
static connection_info_netns_cookie_t stored_cookie_connection_key;
static java_remote_parent_connection_t stored_cookie_connection;
static int cookie_connection_present;
static pid_key_t stored_fallback_key;
static java_remote_parent_response_t stored_fallback;
static int fallback_present;
static pid_key_t stored_terminal_key;
static java_remote_parent_terminal_t stored_terminal;
static int terminal_present;
static java_remote_parent_key_t stored_detach_guard_key;
static java_remote_parent_claim_t stored_detach_guard;
static int detach_guard_present;
static int inject_detach_guard_after_owner_publish;
static int inject_malformed_claim_after_generation_check;
static java_remote_parent_key_t stored_exact_claim_key;
static java_remote_parent_claim_t stored_exact_claim;
static int exact_claim_present;
static int inject_consumed_claim_after_stage_claim_delete;
static int inject_exact_claim_after_cookie_publish;
static int inject_detach_guard_after_cookie_publish;
static int inject_ambiguity_after_cookie_publish;
static int invalidate_incoming_after_cookie_publish;
static int inject_exact_claim_after_owner_active;
static int inject_detach_guard_after_owner_active;
static int inject_ambiguity_after_owner_active;
static int invalidate_incoming_after_owner_active;
static int cleanup_claim_publications;
static int cleanup_claim_deletions;
static int stage_claim_publications;
static int stage_claim_deletions;
static int rollback_guard_publications;
static int rollback_guard_deletions;
static int attempt_external_physical_cleanup;
static int external_physical_cleanup_blocked;
static int inject_physical_successor_after_delete;
static int inject_owner_successor_after_guard_delete;
static int owner_successor_published;
static int fail_ambiguity_delete_with_successor_reservation;
static int fail_ambiguity_reservation;
static int inject_owner_conflict_after_ambiguity_reservation;
static int logical_owner_conflict_pending;
static int fail_stage_claim_delete_with_successor;
static int delete_after_guard_release;
static int rollback_delete_without_fences;
static int rollback_delete_step;
static int cookie_delete_step;
static int connection_delete_step;
static int fallback_delete_step;
static int state_delete_step;
static int generation_index_delete_step;
static int owner_delete_step;
static int exact_claim_delete_step;
static int guard_delete_step;
static int ambiguity_deleted_without_claim;
typedef struct ambiguity_entry {
    java_remote_parent_key_t key;
    u64 observed_monotime_ns;
    int present;
} ambiguity_entry_t;
static ambiguity_entry_t ambiguities[4];
static u64 stats[k_java_remote_parent_stat_max];
static int corrupt_cookie_socket_cookie;
static int unexpected_update;
static int unexpected_delete;
static u64 data_signal_nonce;
static int data_signal_present;
static java_remote_parent_data_signal_key_t stored_ack_key;
static java_remote_parent_data_ack_t stored_ack;
static int ack_present;

static void fail(const char *message) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

static int same_key(const void *left, const void *right, size_t size) {
    return memcmp(left, right, size) == 0;
}

static ambiguity_entry_t *find_ambiguity_entry(const java_remote_parent_key_t *key) {
    for (size_t i = 0; i < sizeof(ambiguities) / sizeof(ambiguities[0]); i++) {
        if (ambiguities[i].present && same_key(key, &ambiguities[i].key, sizeof(*key))) {
            return &ambiguities[i];
        }
    }
    return NULL;
}

static void set_ambiguity(const java_remote_parent_key_t *key, u64 observed_monotime_ns) {
    ambiguity_entry_t *entry = find_ambiguity_entry(key);
    if (!entry) {
        for (size_t i = 0; i < sizeof(ambiguities) / sizeof(ambiguities[0]); i++) {
            if (!ambiguities[i].present) {
                entry = &ambiguities[i];
                break;
            }
        }
    }
    if (!entry) {
        fail("ambiguity fixture capacity exhausted");
    }
    entry->key = *key;
    entry->observed_monotime_ns = observed_monotime_ns;
    entry->present = 1;
}

static int ambiguity_reserved(const java_remote_parent_key_t *key) {
    const ambiguity_entry_t *entry = find_ambiguity_entry(key);
    return entry && !entry->observed_monotime_ns;
}

static int ambiguity_marked(const java_remote_parent_key_t *key) {
    const ambiguity_entry_t *entry = find_ambiguity_entry(key);
    return entry && entry->observed_monotime_ns;
}

static size_t ambiguity_count(void) {
    size_t count = 0;
    for (size_t i = 0; i < sizeof(ambiguities) / sizeof(ambiguities[0]); i++) {
        count += ambiguities[i].present != 0;
    }
    return count;
}

static void inject_stage_exact_claim(void) {
    stored_exact_claim_key = stored_state_key;
    stored_exact_claim = (java_remote_parent_claim_t){
        .observed_monotime_ns = test_ktime_get_ns() + 1,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_publishing,
    };
    exact_claim_present = 1;
}

static void inject_stage_detach_guard(void) {
    stored_detach_guard_key = java_remote_parent_detach_guard_key(&test_owner);
    stored_detach_guard = (java_remote_parent_claim_t){
        .observed_monotime_ns = test_ktime_get_ns() + 2,
        .process_incarnation = stored_state_key.generation,
        .lifecycle = k_java_remote_parent_lifecycle_publishing,
    };
    detach_guard_present = 1;
}

static int rollback_fences_owned(void) {
    return exact_claim_present && detach_guard_present &&
           stored_exact_claim.lifecycle == k_java_remote_parent_lifecycle_publishing &&
           stored_detach_guard.lifecycle == k_java_remote_parent_lifecycle_publishing &&
           stored_detach_guard.process_incarnation == stored_exact_claim_key.generation;
}

static int record_rollback_delete(void) {
    if (owner_successor_published) {
        delete_after_guard_release = 1;
    }
    if (!rollback_fences_owned()) {
        rollback_delete_without_fences = 1;
    }
    return ++rollback_delete_step;
}

static java_remote_parent_connection_t physical_successor(void) {
    java_remote_parent_connection_t successor = stored_connection;
    successor.owner = test_physical_successor_owner;
    successor.generation = test_successor_generation;
    return successor;
}

static void publish_owner_successor(void) {
    stored_owner_key = test_owner;
    stored_owner = (java_remote_parent_owner_t){
        .generation = test_successor_generation,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_active,
    };
    owner_present = 1;
    stored_fallback_key = test_owner;
    java_remote_parent_init_response(&stored_fallback,
                                     k_java_remote_parent_status_valid,
                                     test_successor_generation,
                                     test_candidate_timestamp + 1);
    fallback_present = 1;
    stored_connection = physical_successor();
    stored_connection.owner = test_owner;
    stored_cookie_connection = stored_connection;
    connection_present = 1;
    cookie_connection_present = 1;
    const java_remote_parent_key_t successor_key =
        java_remote_parent_state_key(&test_owner, test_successor_generation);
    set_ambiguity(&successor_key, 0);
    owner_successor_published = 1;
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
    if (map == &java_remote_parent_owners && owner_present &&
        same_key(key, &stored_owner_key, sizeof(stored_owner_key))) {
        return &stored_owner;
    }
    if (map == &java_remote_parent_state && state_present &&
        same_key(key, &stored_state_key, sizeof(stored_state_key))) {
        return &stored_state;
    }
    if (map == &java_remote_parent_state && replacement_state_present &&
        same_key(key, &replacement_state_key, sizeof(replacement_state_key))) {
        return &replacement_state;
    }
    if (map == &java_remote_parent_generation_index && generation_index_present &&
        same_key(key, &stored_generation_index_key, sizeof(stored_generation_index_key))) {
        return &stored_generation_index;
    }
    if (map == &java_remote_parent_generation_index && replacement_generation_index_present &&
        same_key(
            key, &replacement_generation_index_key, sizeof(replacement_generation_index_key))) {
        return &replacement_generation_index;
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
    if (map == &java_remote_parent_terminal && terminal_present &&
        same_key(key, &stored_terminal_key, sizeof(stored_terminal_key))) {
        return &stored_terminal;
    }
    if (map == &java_remote_parent_claims && ((const java_remote_parent_key_t *)key)->generation &&
        inject_malformed_claim_after_generation_check) {
        inject_malformed_claim_after_generation_check = 0;
        stored_exact_claim_key = *(const java_remote_parent_key_t *)key;
        stored_exact_claim = (java_remote_parent_claim_t){0};
        exact_claim_present = 1;
        return NULL;
    }
    if (map == &java_remote_parent_claims && exact_claim_present &&
        same_key(key, &stored_exact_claim_key, sizeof(stored_exact_claim_key))) {
        return &stored_exact_claim;
    }
    if (map == &java_remote_parent_owner_guards && detach_guard_present &&
        same_key(key, &stored_detach_guard_key.owner, sizeof(stored_detach_guard_key.owner))) {
        return &stored_detach_guard;
    }
    if (map == &java_remote_parent_ambiguity) {
        ambiguity_entry_t *entry = find_ambiguity_entry(key);
        return entry ? &entry->observed_monotime_ns : NULL;
    }
    if (map == &java_remote_parent_data_signals && data_signal_present &&
        same_key(key, &test_owner, sizeof(test_owner))) {
        return &data_signal_nonce;
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
        if (owner_present && flags == BPF_NOEXIST && logical_owner_conflict_pending) {
            logical_owner_conflict_pending = 0;
            return -1;
        }
        if ((!owner_present && flags != BPF_NOEXIST) || (owner_present && flags != BPF_EXIST)) {
            unexpected_update = 1;
            return -1;
        }
        stored_owner_key = *(const pid_key_t *)key;
        stored_owner = *(const java_remote_parent_owner_t *)value;
        owner_present = 1;
        if (flags == BPF_NOEXIST && inject_detach_guard_after_owner_publish) {
            inject_detach_guard_after_owner_publish = 0;
            stored_detach_guard_key = java_remote_parent_detach_guard_key(&stored_owner_key);
            stored_detach_guard = (java_remote_parent_claim_t){
                .observed_monotime_ns = test_ktime_get_ns(),
                .process_incarnation = stored_owner.generation,
                .lifecycle = k_java_remote_parent_lifecycle_publishing,
            };
            detach_guard_present = 1;
        }
        if (flags == BPF_EXIST && stored_owner.lifecycle == k_java_remote_parent_lifecycle_active) {
            if (inject_exact_claim_after_owner_active) {
                inject_exact_claim_after_owner_active = 0;
                inject_stage_exact_claim();
            }
            if (inject_detach_guard_after_owner_active) {
                inject_detach_guard_after_owner_active = 0;
                inject_stage_detach_guard();
            }
            if (inject_ambiguity_after_owner_active) {
                inject_ambiguity_after_owner_active = 0;
                set_ambiguity(&stored_state_key, test_ktime_get_ns() + 3);
            }
            if (invalidate_incoming_after_owner_active) {
                invalidate_incoming_after_owner_active = 0;
                incoming_generation++;
            }
        }
        return 0;
    }
    if (map == &java_remote_parent_state && flags == BPF_NOEXIST) {
        if (!state_present) {
            stored_state_key = *(const java_remote_parent_key_t *)key;
            stored_state = *(const java_remote_parent_state_t *)value;
            state_present = 1;
            return 0;
        }
        if (!replacement_state_present &&
            !same_key(key, &stored_state_key, sizeof(stored_state_key))) {
            replacement_state_key = *(const java_remote_parent_key_t *)key;
            replacement_state = *(const java_remote_parent_state_t *)value;
            replacement_state_present = 1;
            return 0;
        }
        return -1;
    }
    if (map == &java_remote_parent_generation_index && flags == BPF_NOEXIST) {
        if (!generation_index_present) {
            stored_generation_index_key = *(const java_remote_parent_key_t *)key;
            stored_generation_index = *(const java_remote_parent_generation_index_t *)value;
            generation_index_present = 1;
            return 0;
        }
        if (!replacement_generation_index_present &&
            !same_key(key, &stored_generation_index_key, sizeof(stored_generation_index_key))) {
            replacement_generation_index_key = *(const java_remote_parent_key_t *)key;
            replacement_generation_index = *(const java_remote_parent_generation_index_t *)value;
            replacement_generation_index_present = 1;
            return 0;
        }
        return -1;
    }
    if (map == &java_remote_parent_connections && flags == BPF_NOEXIST) {
        if (connection_present) {
            return -1;
        }
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
        if (inject_exact_claim_after_cookie_publish) {
            inject_exact_claim_after_cookie_publish = 0;
            inject_stage_exact_claim();
        }
        if (inject_detach_guard_after_cookie_publish) {
            inject_detach_guard_after_cookie_publish = 0;
            inject_stage_detach_guard();
        }
        if (inject_ambiguity_after_cookie_publish) {
            inject_ambiguity_after_cookie_publish = 0;
            set_ambiguity(&stored_state_key, test_ktime_get_ns() + 3);
        }
        if (invalidate_incoming_after_cookie_publish) {
            invalidate_incoming_after_cookie_publish = 0;
            incoming_generation++;
        }
        return 0;
    }
    if (map == &java_remote_parent_fallback && flags == BPF_NOEXIST && !fallback_present) {
        stored_fallback_key = *(const pid_key_t *)key;
        stored_fallback = *(const java_remote_parent_response_t *)value;
        fallback_present = 1;
        return 0;
    }
    if (map == &java_remote_parent_owner_guards && flags == BPF_EXIST) {
        if (detach_guard_present &&
            same_key(key, &stored_detach_guard_key.owner, sizeof(stored_detach_guard_key.owner))) {
            stored_detach_guard = *(const java_remote_parent_claim_t *)value;
            return 0;
        }
        return -1;
    }
    if (map == &java_remote_parent_claims && flags == BPF_EXIST) {
        if (exact_claim_present &&
            same_key(key, &stored_exact_claim_key, sizeof(stored_exact_claim_key))) {
            stored_exact_claim = *(const java_remote_parent_claim_t *)value;
            return 0;
        }
        return -1;
    }
    if (map == &java_remote_parent_owner_guards && flags == BPF_NOEXIST) {
        const java_remote_parent_claim_t *claim = value;
        if (detach_guard_present || claim->lifecycle != k_java_remote_parent_lifecycle_publishing ||
            !claim->observed_monotime_ns || !claim->process_incarnation) {
            return -1;
        }
        stored_detach_guard_key = java_remote_parent_detach_guard_key(key);
        stored_detach_guard = *claim;
        detach_guard_present = 1;
        rollback_guard_publications++;
        return 0;
    }
    if (map == &java_remote_parent_claims && flags == BPF_NOEXIST) {
        const java_remote_parent_key_t *claim_key = key;
        const java_remote_parent_claim_t *claim = value;
        if (exact_claim_present || !claim->observed_monotime_ns || !claim->process_incarnation ||
            (claim->lifecycle != k_java_remote_parent_lifecycle_publishing &&
             claim->lifecycle != k_java_remote_parent_lifecycle_discarded)) {
            unexpected_update = 1;
            return -1;
        }
        stored_exact_claim_key = *claim_key;
        stored_exact_claim = *claim;
        exact_claim_present = 1;
        if (claim->lifecycle == k_java_remote_parent_lifecycle_publishing) {
            stage_claim_publications++;
        } else {
            cleanup_claim_publications++;
        }
        return 0;
    }
    if (map == &java_remote_parent_data_acks && flags == BPF_ANY) {
        stored_ack_key = *(const java_remote_parent_data_signal_key_t *)key;
        stored_ack = *(const java_remote_parent_data_ack_t *)value;
        ack_present = 1;
        return 0;
    }
    if (map == &java_remote_parent_ambiguity && (flags == BPF_ANY || flags == BPF_NOEXIST)) {
        ambiguity_entry_t *entry = find_ambiguity_entry(key);
        if (flags == BPF_NOEXIST && entry) {
            return -1;
        }
        if (flags == BPF_NOEXIST && fail_ambiguity_reservation) {
            fail_ambiguity_reservation = 0;
            return -1;
        }
        set_ambiguity(key, *(const u64 *)value);
        if (flags == BPF_NOEXIST && inject_owner_conflict_after_ambiguity_reservation) {
            inject_owner_conflict_after_ambiguity_reservation = 0;
            stored_owner_key = test_owner;
            stored_owner = (java_remote_parent_owner_t){
                .generation = test_successor_generation,
                .process_incarnation = test_process_incarnation,
                .lifecycle = k_java_remote_parent_lifecycle_active,
            };
            owner_present = 1;
            logical_owner_conflict_pending = 1;
        }
        return 0;
    }

    unexpected_update = 1;
    return -1;
}

static long test_map_delete(void *map, const void *key) {
    if (map == &java_remote_parent_terminal) {
        if (terminal_present && same_key(key, &stored_terminal_key, sizeof(stored_terminal_key))) {
            terminal_present = 0;
        }
        return 0;
    }
    if (map == &java_remote_parent_fallback) {
        if (fallback_present && same_key(key, &stored_fallback_key, sizeof(stored_fallback_key))) {
            if (rollback_fences_owned()) {
                fallback_delete_step = record_rollback_delete();
            }
            fallback_present = 0;
        }
        return 0;
    }
    if (map == &java_remote_parent_connections && connection_present &&
        same_key(key, &stored_connection_key, sizeof(stored_connection_key))) {
        if (attempt_external_physical_cleanup && rollback_fences_owned()) {
            attempt_external_physical_cleanup--;
            external_physical_cleanup_blocked++;
        }
        connection_delete_step = record_rollback_delete();
        connection_present = 0;
        if (inject_physical_successor_after_delete) {
            inject_physical_successor_after_delete--;
            stored_connection = physical_successor();
            connection_present = 1;
        }
        return 0;
    }
    if (map == &java_remote_parent_cookie_connections && cookie_connection_present &&
        same_key(key, &stored_cookie_connection_key, sizeof(stored_cookie_connection_key))) {
        if (attempt_external_physical_cleanup && rollback_fences_owned()) {
            attempt_external_physical_cleanup--;
            external_physical_cleanup_blocked++;
        }
        cookie_delete_step = record_rollback_delete();
        cookie_connection_present = 0;
        if (inject_physical_successor_after_delete) {
            inject_physical_successor_after_delete--;
            stored_cookie_connection = physical_successor();
            cookie_connection_present = 1;
        }
        return 0;
    }
    if (map == &java_remote_parent_state) {
        if (state_present && same_key(key, &stored_state_key, sizeof(stored_state_key))) {
            state_delete_step = record_rollback_delete();
            state_present = 0;
            return 0;
        }
        if (replacement_state_present &&
            same_key(key, &replacement_state_key, sizeof(replacement_state_key))) {
            replacement_state_present = 0;
            return 0;
        }
        return -1;
    }
    if (map == &java_remote_parent_generation_index) {
        if (generation_index_present &&
            same_key(key, &stored_generation_index_key, sizeof(stored_generation_index_key))) {
            generation_index_delete_step = record_rollback_delete();
            generation_index_present = 0;
            return 0;
        }
        if (replacement_generation_index_present &&
            same_key(
                key, &replacement_generation_index_key, sizeof(replacement_generation_index_key))) {
            replacement_generation_index_present = 0;
            return 0;
        }
        return -1;
    }
    if (map == &java_remote_parent_owners && owner_present &&
        same_key(key, &stored_owner_key, sizeof(stored_owner_key))) {
        if (rollback_fences_owned()) {
            owner_delete_step = record_rollback_delete();
        }
        owner_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_claims && exact_claim_present &&
        same_key(key, &stored_exact_claim_key, sizeof(stored_exact_claim_key))) {
        const u8 deleted_lifecycle = stored_exact_claim.lifecycle;
        if (fail_stage_claim_delete_with_successor &&
            deleted_lifecycle == k_java_remote_parent_lifecycle_publishing) {
            fail_stage_claim_delete_with_successor = 0;
            stored_exact_claim = (java_remote_parent_claim_t){
                .observed_monotime_ns = test_ktime_get_ns() + 1,
                .process_incarnation = test_process_incarnation,
                .lifecycle = k_java_remote_parent_lifecycle_consumed,
            };
            return -1;
        }
        if (detach_guard_present) {
            if (!rollback_fences_owned()) {
                rollback_delete_without_fences = 1;
            }
            exact_claim_delete_step = ++rollback_delete_step;
        }
        if (deleted_lifecycle == k_java_remote_parent_lifecycle_publishing) {
            stage_claim_deletions++;
        } else {
            cleanup_claim_deletions++;
        }
        exact_claim_present = 0;
        if (inject_consumed_claim_after_stage_claim_delete &&
            deleted_lifecycle == k_java_remote_parent_lifecycle_publishing) {
            inject_consumed_claim_after_stage_claim_delete = 0;
            stored_exact_claim = (java_remote_parent_claim_t){
                .observed_monotime_ns = test_ktime_get_ns(),
                .process_incarnation = test_process_incarnation,
                .lifecycle = k_java_remote_parent_lifecycle_consumed,
            };
            exact_claim_present = 1;
        }
        return 0;
    }
    if (map == &java_remote_parent_owner_guards && detach_guard_present &&
        same_key(key, &stored_detach_guard_key.owner, sizeof(stored_detach_guard_key.owner))) {
        guard_delete_step = ++rollback_delete_step;
        detach_guard_present = 0;
        rollback_guard_deletions++;
        if (inject_owner_successor_after_guard_delete) {
            inject_owner_successor_after_guard_delete = 0;
            publish_owner_successor();
        }
        return 0;
    }
    if (map == &java_remote_parent_ambiguity) {
        ambiguity_entry_t *entry = find_ambiguity_entry(key);
        if (entry) {
            if (fail_ambiguity_delete_with_successor_reservation) {
                fail_ambiguity_delete_with_successor_reservation = 0;
                entry->observed_monotime_ns = 0;
                return -1;
            }
            if (!exact_claim_present) {
                ambiguity_deleted_without_claim = 1;
            }
            entry->present = 0;
        }
        return 0;
    }
    if (map == &java_remote_parent_data_signals) {
        return -1;
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

static u64 test_java_process_capability_for(const pid_key_t *owner) {
    (void)owner;
    return test_process_incarnation;
}

static u64 test_java_process_incarnation_for(const pid_key_t *owner) {
    (void)owner;
    return test_process_incarnation;
}

static u64 test_java_current_process_incarnation(void) {
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
    memset(&stored_owner, 0, sizeof(stored_owner));
    memset(&stored_state, 0, sizeof(stored_state));
    memset(&replacement_state, 0, sizeof(replacement_state));
    memset(&stored_generation_index, 0, sizeof(stored_generation_index));
    memset(&replacement_generation_index, 0, sizeof(replacement_generation_index));
    memset(&stored_connection, 0, sizeof(stored_connection));
    memset(&stored_cookie_connection, 0, sizeof(stored_cookie_connection));
    memset(&stored_fallback, 0, sizeof(stored_fallback));
    memset(&stored_terminal, 0, sizeof(stored_terminal));
    memset(&stored_detach_guard_key, 0, sizeof(stored_detach_guard_key));
    memset(&stored_detach_guard, 0, sizeof(stored_detach_guard));
    memset(&stored_exact_claim_key, 0, sizeof(stored_exact_claim_key));
    memset(&stored_exact_claim, 0, sizeof(stored_exact_claim));
    memset(ambiguities, 0, sizeof(ambiguities));
    memset(stats, 0, sizeof(stats));
    stored_connection_key = connection_info_with_netns(connection, test_connection_netns);
    owner_present = 0;
    state_present = 0;
    replacement_state_present = 0;
    generation_index_present = 0;
    replacement_generation_index_present = 0;
    connection_present = 0;
    cookie_connection_present = 0;
    fallback_present = 0;
    terminal_present = 0;
    detach_guard_present = 0;
    inject_detach_guard_after_owner_publish = 0;
    inject_malformed_claim_after_generation_check = 0;
    exact_claim_present = 0;
    inject_consumed_claim_after_stage_claim_delete = 0;
    inject_exact_claim_after_cookie_publish = 0;
    inject_detach_guard_after_cookie_publish = 0;
    inject_ambiguity_after_cookie_publish = 0;
    invalidate_incoming_after_cookie_publish = 0;
    inject_exact_claim_after_owner_active = 0;
    inject_detach_guard_after_owner_active = 0;
    inject_ambiguity_after_owner_active = 0;
    invalidate_incoming_after_owner_active = 0;
    cleanup_claim_publications = 0;
    cleanup_claim_deletions = 0;
    stage_claim_publications = 0;
    stage_claim_deletions = 0;
    rollback_guard_publications = 0;
    rollback_guard_deletions = 0;
    attempt_external_physical_cleanup = 0;
    external_physical_cleanup_blocked = 0;
    inject_physical_successor_after_delete = 0;
    inject_owner_successor_after_guard_delete = 0;
    owner_successor_published = 0;
    fail_ambiguity_delete_with_successor_reservation = 0;
    fail_ambiguity_reservation = 0;
    inject_owner_conflict_after_ambiguity_reservation = 0;
    logical_owner_conflict_pending = 0;
    fail_stage_claim_delete_with_successor = 0;
    delete_after_guard_release = 0;
    rollback_delete_without_fences = 0;
    rollback_delete_step = 0;
    cookie_delete_step = 0;
    connection_delete_step = 0;
    fallback_delete_step = 0;
    state_delete_step = 0;
    generation_index_delete_step = 0;
    owner_delete_step = 0;
    exact_claim_delete_step = 0;
    guard_delete_step = 0;
    ambiguity_deleted_without_claim = 0;
    corrupt_cookie_socket_cookie = 0;
    unexpected_update = 0;
    unexpected_delete = 0;
    data_signal_nonce = 0;
    data_signal_present = 0;
    memset(&stored_ack_key, 0, sizeof(stored_ack_key));
    memset(&stored_ack, 0, sizeof(stored_ack));
    ack_present = 0;
}

static void test_ambiguity_reservation_failure_retires_or_preserves_exact_claim(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const tp_info_pid_t raw = raw_parent(k_flag_sampled);
    java_remote_parent_incoming_t handoff = {.generation = test_incoming_generation};

    reset(&connection, &raw);
    if (!apply_incoming_trace_candidate(
            &(tp_info_t){}, &raw, &handoff.candidate, &handoff.generation)) {
        fail("ambiguity-reservation failure parent was not prepared");
    }
    fail_ambiguity_reservation = 1;
    if (java_remote_parent_stage_incoming(&connection,
                                          test_connection_netns,
                                          test_connection_netns_cookie,
                                          test_socket_cookie,
                                          &handoff) ||
        fail_ambiguity_reservation || !generation_sequence || owner_present || state_present ||
        generation_index_present || connection_present || cookie_connection_present ||
        fallback_present || terminal_present || exact_claim_present || detach_guard_present ||
        ambiguity_count() || stage_claim_publications != 1 || stage_claim_deletions != 1 ||
        cleanup_claim_publications || cleanup_claim_deletions ||
        stats[k_java_remote_parent_stat_stage_overload] != 1 ||
        stats[k_java_remote_parent_stat_stage_ambiguous] ||
        stats[k_java_remote_parent_stat_stage_valid] || unexpected_update || unexpected_delete) {
        fail("failed ambiguity reservation did not retire its exact-only transaction");
    }

    reset(&connection, &raw);
    handoff.generation = test_incoming_generation;
    if (!apply_incoming_trace_candidate(
            &(tp_info_t){}, &raw, &handoff.candidate, &handoff.generation)) {
        fail("claim-successor reservation failure parent was not prepared");
    }
    fail_ambiguity_reservation = 1;
    fail_stage_claim_delete_with_successor = 1;
    if (java_remote_parent_stage_incoming(&connection,
                                          test_connection_netns,
                                          test_connection_netns_cookie,
                                          test_socket_cookie,
                                          &handoff) ||
        fail_ambiguity_reservation || fail_stage_claim_delete_with_successor ||
        !generation_sequence || owner_present || state_present || generation_index_present ||
        connection_present || cookie_connection_present || fallback_present || terminal_present ||
        !exact_claim_present || !stored_exact_claim_key.generation ||
        stored_exact_claim.observed_monotime_ns != test_ktime_get_ns() + 1 ||
        stored_exact_claim.process_incarnation != test_process_incarnation ||
        stored_exact_claim.lifecycle != k_java_remote_parent_lifecycle_consumed ||
        detach_guard_present || ambiguity_count() || stage_claim_publications != 1 ||
        stage_claim_deletions || cleanup_claim_publications || cleanup_claim_deletions ||
        stats[k_java_remote_parent_stat_stage_overload] != 1 ||
        stats[k_java_remote_parent_stat_stage_ambiguous] ||
        stats[k_java_remote_parent_stat_stage_valid] || unexpected_update || unexpected_delete) {
        fail("failed ambiguity reservation removed or re-marked a successor exact claim");
    }
}

static void test_logical_owner_conflict_retires_only_the_empty_transaction(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const tp_info_pid_t raw = raw_parent(k_flag_sampled);
    java_remote_parent_incoming_t handoff = {.generation = test_incoming_generation};
    const java_remote_parent_key_t successor_key =
        java_remote_parent_state_key(&test_owner, test_successor_generation);

    reset(&connection, &raw);
    if (!apply_incoming_trace_candidate(
            &(tp_info_t){}, &raw, &handoff.candidate, &handoff.generation)) {
        fail("logical owner-conflict parent was not prepared");
    }
    inject_owner_conflict_after_ambiguity_reservation = 1;
    if (java_remote_parent_stage_incoming(&connection,
                                          test_connection_netns,
                                          test_connection_netns_cookie,
                                          test_socket_cookie,
                                          &handoff)) {
        fail("logical owner conflict unexpectedly staged a generation");
    }
    const java_remote_parent_key_t failed_key = stored_exact_claim_key;
    if (inject_owner_conflict_after_ambiguity_reservation || logical_owner_conflict_pending ||
        !generation_sequence || !failed_key.generation || !owner_present ||
        stored_owner.generation != test_successor_generation ||
        stored_owner.lifecycle != k_java_remote_parent_lifecycle_active || state_present ||
        generation_index_present || connection_present || cookie_connection_present ||
        fallback_present || terminal_present || exact_claim_present || detach_guard_present ||
        find_ambiguity_entry(&failed_key) || !ambiguity_marked(&successor_key) ||
        ambiguity_count() != 1 || stage_claim_publications != 1 || stage_claim_deletions != 1 ||
        cleanup_claim_publications || cleanup_claim_deletions ||
        stats[k_java_remote_parent_stat_stage_ambiguous] != 1 ||
        stats[k_java_remote_parent_stat_stage_overload] ||
        stats[k_java_remote_parent_stat_stage_valid] || unexpected_update || unexpected_delete) {
        fail("logical owner conflict did not retire only its empty transaction");
    }

    reset(&connection, &raw);
    handoff.generation = test_incoming_generation;
    if (!apply_incoming_trace_candidate(
            &(tp_info_t){}, &raw, &handoff.candidate, &handoff.generation)) {
        fail("owner-conflict claim-successor parent was not prepared");
    }
    inject_owner_conflict_after_ambiguity_reservation = 1;
    fail_stage_claim_delete_with_successor = 1;
    if (java_remote_parent_stage_incoming(&connection,
                                          test_connection_netns,
                                          test_connection_netns_cookie,
                                          test_socket_cookie,
                                          &handoff)) {
        fail("owner-conflict claim-successor unexpectedly staged a generation");
    }
    const java_remote_parent_key_t claim_successor_key = stored_exact_claim_key;
    if (inject_owner_conflict_after_ambiguity_reservation || logical_owner_conflict_pending ||
        fail_stage_claim_delete_with_successor || !owner_present ||
        stored_owner.generation != test_successor_generation || !exact_claim_present ||
        stored_exact_claim.lifecycle != k_java_remote_parent_lifecycle_consumed ||
        stored_exact_claim.observed_monotime_ns != test_ktime_get_ns() + 1 ||
        find_ambiguity_entry(&claim_successor_key) || !ambiguity_marked(&successor_key) ||
        ambiguity_count() != 1 || state_present || generation_index_present || connection_present ||
        cookie_connection_present || fallback_present || terminal_present || detach_guard_present ||
        stage_claim_publications != 1 || stage_claim_deletions ||
        stats[k_java_remote_parent_stat_stage_ambiguous] != 1 ||
        stats[k_java_remote_parent_stat_stage_valid] || unexpected_update || unexpected_delete) {
        fail("logical owner conflict removed or re-marked a successor exact claim");
    }

    reset(&connection, &raw);
    handoff.generation = test_incoming_generation;
    if (!apply_incoming_trace_candidate(
            &(tp_info_t){}, &raw, &handoff.candidate, &handoff.generation)) {
        fail("owner-conflict marker-successor parent was not prepared");
    }
    inject_owner_conflict_after_ambiguity_reservation = 1;
    fail_ambiguity_delete_with_successor_reservation = 1;
    if (java_remote_parent_stage_incoming(&connection,
                                          test_connection_netns,
                                          test_connection_netns_cookie,
                                          test_socket_cookie,
                                          &handoff)) {
        fail("owner-conflict marker-successor unexpectedly staged a generation");
    }
    const java_remote_parent_key_t marker_successor_key = stored_exact_claim_key;
    if (inject_owner_conflict_after_ambiguity_reservation || logical_owner_conflict_pending ||
        fail_ambiguity_delete_with_successor_reservation || !owner_present ||
        stored_owner.generation != test_successor_generation || !exact_claim_present ||
        stored_exact_claim.lifecycle != k_java_remote_parent_lifecycle_cleanup ||
        !ambiguity_reserved(&marker_successor_key) || ambiguity_marked(&marker_successor_key) ||
        !ambiguity_marked(&successor_key) || ambiguity_count() != 2 || state_present ||
        generation_index_present || connection_present || cookie_connection_present ||
        fallback_present || terminal_present || detach_guard_present ||
        stage_claim_publications != 1 || stage_claim_deletions ||
        stats[k_java_remote_parent_stat_stage_ambiguous] != 1 ||
        stats[k_java_remote_parent_stat_stage_valid] || unexpected_update || unexpected_delete) {
        fail("logical owner conflict promoted or removed a successor reservation tail");
    }
}

static void test_preexisting_detach_guard_blocks_stage(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const tp_info_pid_t raw = raw_parent(k_flag_sampled);
    reset(&connection, &raw);
    stored_detach_guard_key = java_remote_parent_detach_guard_key(&test_owner);
    stored_detach_guard = (java_remote_parent_claim_t){
        .observed_monotime_ns = test_ktime_get_ns(),
        .process_incarnation = 0xdead,
        .lifecycle = k_java_remote_parent_lifecycle_publishing,
    };
    detach_guard_present = 1;

    java_remote_parent_incoming_t handoff = {.generation = test_incoming_generation};
    if (!apply_incoming_trace_candidate(
            &(tp_info_t){}, &raw, &handoff.candidate, &handoff.generation)) {
        fail("guarded stage parent was not prepared");
    }
    if (java_remote_parent_stage_incoming(&connection,
                                          test_connection_netns,
                                          test_connection_netns_cookie,
                                          test_socket_cookie,
                                          &handoff) ||
        generation_sequence || owner_present || state_present || generation_index_present ||
        connection_present || cookie_connection_present || fallback_present || terminal_present ||
        !detach_guard_present ||
        stored_detach_guard.lifecycle != k_java_remote_parent_lifecycle_publishing ||
        ambiguity_count() || stats[k_java_remote_parent_stat_stage_ambiguous] != 1 ||
        stats[k_java_remote_parent_stat_stage_valid] != 0 || unexpected_update ||
        unexpected_delete) {
        fail("pre-existing detach guard did not block stage without mutation");
    }
}

static void test_malformed_claim_race_is_not_adopted_as_stage_authority(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const tp_info_pid_t raw = raw_parent(k_flag_sampled);
    reset(&connection, &raw);
    inject_malformed_claim_after_generation_check = 1;

    java_remote_parent_incoming_t handoff = {.generation = test_incoming_generation};
    if (!apply_incoming_trace_candidate(
            &(tp_info_t){}, &raw, &handoff.candidate, &handoff.generation)) {
        fail("malformed-claim race parent was not prepared");
    }
    if (java_remote_parent_stage_incoming(&connection,
                                          test_connection_netns,
                                          test_connection_netns_cookie,
                                          test_socket_cookie,
                                          &handoff) ||
        inject_malformed_claim_after_generation_check || !generation_sequence || owner_present ||
        state_present || generation_index_present || connection_present ||
        cookie_connection_present || fallback_present || terminal_present || !exact_claim_present ||
        stored_exact_claim.observed_monotime_ns || stored_exact_claim.process_incarnation ||
        stored_exact_claim.lifecycle || stage_claim_publications || stage_claim_deletions ||
        rollback_guard_publications || rollback_guard_deletions || ambiguity_count() ||
        stats[k_java_remote_parent_stat_stage_overload] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("stage adopted or mutated through a malformed foreign claim");
    }
}

static void test_detach_guard_after_owner_publish_rolls_back_stage(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const tp_info_pid_t raw = raw_parent(k_flag_sampled);
    reset(&connection, &raw);
    inject_detach_guard_after_owner_publish = 1;

    java_remote_parent_incoming_t handoff = {.generation = test_incoming_generation};
    if (!apply_incoming_trace_candidate(
            &(tp_info_t){}, &raw, &handoff.candidate, &handoff.generation)) {
        fail("owner-publication guard race parent was not prepared");
    }
    if (java_remote_parent_stage_incoming(&connection,
                                          test_connection_netns,
                                          test_connection_netns_cookie,
                                          test_socket_cookie,
                                          &handoff) ||
        inject_detach_guard_after_owner_publish || !generation_sequence || !owner_present ||
        stored_owner.lifecycle != k_java_remote_parent_lifecycle_publishing || state_present ||
        replacement_state_present || generation_index_present ||
        replacement_generation_index_present || connection_present || cookie_connection_present ||
        fallback_present || terminal_present || !detach_guard_present ||
        stored_detach_guard.process_incarnation != stored_owner.generation ||
        stored_detach_guard.lifecycle != k_java_remote_parent_lifecycle_publishing ||
        !exact_claim_present || !ambiguity_marked(&stored_state_key) ||
        stage_claim_publications != 1 || stage_claim_deletions || rollback_guard_publications ||
        rollback_guard_deletions || stats[k_java_remote_parent_stat_stage_ambiguous] != 1 ||
        stats[k_java_remote_parent_stat_stage_valid] != 0 || unexpected_update ||
        unexpected_delete) {
        fail("detach guard appearing after owner publication was not quarantined");
    }
}

enum test_stage_fence_kind {
    test_stage_fence_exact_claim = 0,
    test_stage_fence_detach_guard = 1,
};

enum test_stage_fence_point {
    test_stage_fence_after_cookie = 0,
    test_stage_fence_after_owner_active = 1,
};

static void test_cleanup_fence_rolls_back_stage(enum test_stage_fence_kind kind,
                                                enum test_stage_fence_point point) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const tp_info_pid_t raw = raw_parent(k_flag_sampled);
    reset(&connection, &raw);

    if (kind == test_stage_fence_exact_claim && point == test_stage_fence_after_cookie) {
        inject_exact_claim_after_cookie_publish = 1;
    } else if (kind == test_stage_fence_detach_guard && point == test_stage_fence_after_cookie) {
        inject_detach_guard_after_cookie_publish = 1;
    } else if (kind == test_stage_fence_exact_claim &&
               point == test_stage_fence_after_owner_active) {
        inject_exact_claim_after_owner_active = 1;
    } else {
        inject_detach_guard_after_owner_active = 1;
    }

    java_remote_parent_incoming_t handoff = {.generation = test_incoming_generation};
    if (!apply_incoming_trace_candidate(
            &(tp_info_t){}, &raw, &handoff.candidate, &handoff.generation)) {
        fail("cleanup-fenced stage parent was not prepared");
    }
    if (java_remote_parent_stage_incoming(&connection,
                                          test_connection_netns,
                                          test_connection_netns_cookie,
                                          test_socket_cookie,
                                          &handoff) ||
        inject_exact_claim_after_cookie_publish || inject_detach_guard_after_cookie_publish ||
        inject_exact_claim_after_owner_active || inject_detach_guard_after_owner_active ||
        !owner_present || !state_present || replacement_state_present ||
        !generation_index_present || replacement_generation_index_present || !connection_present ||
        !cookie_connection_present ||
        fallback_present != (point == test_stage_fence_after_owner_active) || terminal_present ||
        !ambiguity_marked(&stored_state_key) || !exact_claim_present ||
        detach_guard_present != (kind == test_stage_fence_detach_guard) ||
        stored_owner.lifecycle != (point == test_stage_fence_after_owner_active
                                       ? k_java_remote_parent_lifecycle_active
                                       : k_java_remote_parent_lifecycle_publishing) ||
        stage_claim_publications != 1 || stage_claim_deletions || rollback_guard_publications ||
        rollback_guard_deletions || stats[k_java_remote_parent_stat_stage_ambiguous] != 1 ||
        stats[k_java_remote_parent_stat_stage_valid] != 0 || unexpected_update ||
        unexpected_delete) {
        fail("cleanup fence did not quarantine the staged generation");
    }

    const java_remote_parent_key_t failed_key = stored_state_key;
    if (!failed_key.generation ||
        (exact_claim_present &&
         (!same_key(&stored_exact_claim_key, &failed_key, sizeof(failed_key)) ||
          stored_exact_claim.process_incarnation != test_process_incarnation ||
          stored_exact_claim.lifecycle != (kind == test_stage_fence_exact_claim
                                               ? k_java_remote_parent_lifecycle_publishing
                                               : k_java_remote_parent_lifecycle_cleanup))) ||
        (detach_guard_present &&
         (stored_detach_guard_key.generation != 0 ||
          !java_remote_parent_pid_key_equal(&stored_detach_guard_key.owner, &test_owner) ||
          stored_detach_guard.process_incarnation != failed_key.generation ||
          stored_detach_guard.lifecycle != k_java_remote_parent_lifecycle_publishing))) {
        fail("exact rollback removed or rewrote its replacement cleanup fence");
    }
}

static void test_cleanup_fences_close_stage_publication_windows(void) {
    test_cleanup_fence_rolls_back_stage(test_stage_fence_exact_claim,
                                        test_stage_fence_after_cookie);
    test_cleanup_fence_rolls_back_stage(test_stage_fence_detach_guard,
                                        test_stage_fence_after_cookie);
    test_cleanup_fence_rolls_back_stage(test_stage_fence_exact_claim,
                                        test_stage_fence_after_owner_active);
    test_cleanup_fence_rolls_back_stage(test_stage_fence_detach_guard,
                                        test_stage_fence_after_owner_active);
}

static void test_rollback_claim_blocks_cleanup_and_preserves_physical_successors(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const tp_info_pid_t raw = raw_parent(k_flag_sampled);
    reset(&connection, &raw);
    inject_ambiguity_after_owner_active = 1;
    attempt_external_physical_cleanup = 2;
    inject_physical_successor_after_delete = 2;

    java_remote_parent_incoming_t handoff = {.generation = test_incoming_generation};
    if (!apply_incoming_trace_candidate(
            &(tp_info_t){}, &raw, &handoff.candidate, &handoff.generation)) {
        fail("replacement-race parent was not prepared");
    }
    if (java_remote_parent_stage_incoming(&connection,
                                          test_connection_netns,
                                          test_connection_netns_cookie,
                                          test_socket_cookie,
                                          &handoff) ||
        attempt_external_physical_cleanup || external_physical_cleanup_blocked != 2 ||
        inject_physical_successor_after_delete || owner_present || state_present ||
        generation_index_present || fallback_present || !connection_present ||
        !cookie_connection_present ||
        !java_remote_parent_pid_key_equal(&stored_connection.owner,
                                          &test_physical_successor_owner) ||
        !java_remote_parent_pid_key_equal(&stored_cookie_connection.owner,
                                          &test_physical_successor_owner) ||
        stored_connection.generation != test_successor_generation ||
        stored_cookie_connection.generation != test_successor_generation || exact_claim_present ||
        detach_guard_present || ambiguity_count() || rollback_delete_without_fences ||
        delete_after_guard_release ||
        !(cookie_delete_step < connection_delete_step &&
          connection_delete_step < fallback_delete_step &&
          fallback_delete_step < generation_index_delete_step &&
          generation_index_delete_step < state_delete_step &&
          state_delete_step < owner_delete_step && owner_delete_step < exact_claim_delete_step &&
          exact_claim_delete_step < guard_delete_step) ||
        stats[k_java_remote_parent_stat_stage_ambiguous] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("two-fence rollback deleted or exposed a physical successor");
    }
}

static void test_rollback_performs_no_delete_after_guard_release(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const tp_info_pid_t raw = raw_parent(k_flag_sampled);
    reset(&connection, &raw);
    inject_ambiguity_after_owner_active = 1;
    inject_owner_successor_after_guard_delete = 1;

    java_remote_parent_incoming_t handoff = {.generation = test_incoming_generation};
    if (!apply_incoming_trace_candidate(
            &(tp_info_t){}, &raw, &handoff.candidate, &handoff.generation)) {
        fail("post-guard successor parent was not prepared");
    }
    const java_remote_parent_key_t successor_key =
        java_remote_parent_state_key(&test_owner, test_successor_generation);
    if (java_remote_parent_stage_incoming(&connection,
                                          test_connection_netns,
                                          test_connection_netns_cookie,
                                          test_socket_cookie,
                                          &handoff) ||
        inject_owner_successor_after_guard_delete || !owner_successor_published ||
        delete_after_guard_release || rollback_delete_without_fences || !owner_present ||
        stored_owner.generation != test_successor_generation ||
        stored_owner.lifecycle != k_java_remote_parent_lifecycle_active || !fallback_present ||
        java_remote_parent_le64_to_cpu(stored_fallback.generation_le) !=
            test_successor_generation ||
        !connection_present || !cookie_connection_present ||
        stored_connection.generation != test_successor_generation ||
        stored_cookie_connection.generation != test_successor_generation || state_present ||
        generation_index_present || exact_claim_present || detach_guard_present ||
        !ambiguity_reserved(&successor_key) || ambiguity_count() != 1 ||
        !(owner_delete_step < exact_claim_delete_step &&
          exact_claim_delete_step < guard_delete_step) ||
        stats[k_java_remote_parent_stat_stage_ambiguous] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("rollback touched a successor published after exact guard release");
    }
}

static void test_cookie_publication_ambiguity_is_retired_after_serialized_rollback(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const tp_info_pid_t raw = raw_parent(k_flag_sampled);
    reset(&connection, &raw);
    inject_ambiguity_after_cookie_publish = 1;

    java_remote_parent_incoming_t handoff = {.generation = test_incoming_generation};
    if (!apply_incoming_trace_candidate(
            &(tp_info_t){}, &raw, &handoff.candidate, &handoff.generation)) {
        fail("cookie-publication ambiguity parent was not prepared");
    }
    if (java_remote_parent_stage_incoming(&connection,
                                          test_connection_netns,
                                          test_connection_netns_cookie,
                                          test_socket_cookie,
                                          &handoff) ||
        inject_ambiguity_after_cookie_publish || !generation_sequence || owner_present ||
        state_present || replacement_state_present || generation_index_present ||
        replacement_generation_index_present || connection_present || cookie_connection_present ||
        fallback_present || terminal_present || exact_claim_present || detach_guard_present ||
        ambiguity_count() || ambiguity_deleted_without_claim || cleanup_claim_publications ||
        cleanup_claim_deletions || stats[k_java_remote_parent_stat_stage_ambiguous] != 1 ||
        stats[k_java_remote_parent_stat_stage_valid] != 0 || unexpected_update ||
        unexpected_delete) {
        fail("serialized rollback did not retire the cookie-publication ambiguity marker");
    }

    const java_remote_parent_key_t failed_key = stored_state_key;
    const u64 clean_generation = java_remote_parent_stage_incoming(&connection,
                                                                   test_connection_netns,
                                                                   test_connection_netns_cookie,
                                                                   test_socket_cookie,
                                                                   &handoff);
    if (!clean_generation || clean_generation == failed_key.generation || !owner_present ||
        stored_owner.generation != clean_generation ||
        stored_owner.lifecycle != k_java_remote_parent_lifecycle_active || !state_present ||
        stored_state_key.generation != clean_generation || !generation_index_present ||
        stored_generation_index_key.generation != clean_generation || !connection_present ||
        stored_connection.generation != clean_generation || !cookie_connection_present ||
        stored_cookie_connection.generation != clean_generation || !fallback_present ||
        java_remote_parent_le64_to_cpu(stored_fallback.generation_le) != clean_generation ||
        terminal_present || exact_claim_present || detach_guard_present ||
        !ambiguity_reserved(&stored_state_key) || find_ambiguity_entry(&failed_key) ||
        ambiguity_count() != 1 || ambiguity_deleted_without_claim || cleanup_claim_publications ||
        cleanup_claim_deletions || stats[k_java_remote_parent_stat_stage_ambiguous] != 1 ||
        stats[k_java_remote_parent_stat_stage_valid] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("clean stage recovery did not reserve its new generation");
    }
}

static void test_cookie_publication_incoming_invalidation_rolls_back(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const tp_info_pid_t raw = raw_parent(k_flag_sampled);
    reset(&connection, &raw);
    invalidate_incoming_after_cookie_publish = 1;

    java_remote_parent_incoming_t handoff = {.generation = test_incoming_generation};
    if (!apply_incoming_trace_candidate(
            &(tp_info_t){}, &raw, &handoff.candidate, &handoff.generation)) {
        fail("cookie-publication incoming parent was not prepared");
    }
    if (java_remote_parent_stage_incoming(&connection,
                                          test_connection_netns,
                                          test_connection_netns_cookie,
                                          test_socket_cookie,
                                          &handoff) ||
        invalidate_incoming_after_cookie_publish ||
        incoming_generation != test_incoming_generation + 1 || !generation_sequence ||
        owner_present || state_present || replacement_state_present || generation_index_present ||
        replacement_generation_index_present || connection_present || cookie_connection_present ||
        fallback_present || terminal_present || exact_claim_present || detach_guard_present ||
        ambiguity_count() || ambiguity_deleted_without_claim || cleanup_claim_publications ||
        cleanup_claim_deletions || stats[k_java_remote_parent_stat_stage_ambiguous] != 1 ||
        stats[k_java_remote_parent_stat_stage_valid] != 0 || unexpected_update ||
        unexpected_delete) {
        fail("incoming invalidation did not roll back the publishing generation cleanly");
    }

    const java_remote_parent_key_t failed_key = stored_state_key;
    incoming_generation = test_incoming_generation;
    const u64 clean_generation = java_remote_parent_stage_incoming(&connection,
                                                                   test_connection_netns,
                                                                   test_connection_netns_cookie,
                                                                   test_socket_cookie,
                                                                   &handoff);
    if (!clean_generation || clean_generation == failed_key.generation || !owner_present ||
        stored_owner.generation != clean_generation ||
        stored_owner.lifecycle != k_java_remote_parent_lifecycle_active || !state_present ||
        stored_state_key.generation != clean_generation || !generation_index_present ||
        stored_generation_index_key.generation != clean_generation || !connection_present ||
        stored_connection.generation != clean_generation || !cookie_connection_present ||
        stored_cookie_connection.generation != clean_generation || !fallback_present ||
        java_remote_parent_le64_to_cpu(stored_fallback.generation_le) != clean_generation ||
        terminal_present || exact_claim_present || detach_guard_present ||
        !ambiguity_reserved(&stored_state_key) || find_ambiguity_entry(&failed_key) ||
        ambiguity_count() != 1 || ambiguity_deleted_without_claim || cleanup_claim_publications ||
        cleanup_claim_deletions || stats[k_java_remote_parent_stat_stage_ambiguous] != 1 ||
        stats[k_java_remote_parent_stat_stage_valid] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("clean stage did not recover after cookie-publication incoming invalidation");
    }
}

static void test_rollback_preserves_successor_reservation_after_failed_marker_delete(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const tp_info_pid_t raw = raw_parent(k_flag_sampled);
    reset(&connection, &raw);
    invalidate_incoming_after_cookie_publish = 1;
    fail_ambiguity_delete_with_successor_reservation = 1;

    java_remote_parent_incoming_t handoff = {.generation = test_incoming_generation};
    if (!apply_incoming_trace_candidate(
            &(tp_info_t){}, &raw, &handoff.candidate, &handoff.generation)) {
        fail("successor-reservation rollback parent was not prepared");
    }
    if (java_remote_parent_stage_incoming(&connection,
                                          test_connection_netns,
                                          test_connection_netns_cookie,
                                          test_socket_cookie,
                                          &handoff) ||
        invalidate_incoming_after_cookie_publish ||
        fail_ambiguity_delete_with_successor_reservation || owner_present || state_present ||
        generation_index_present || connection_present || cookie_connection_present ||
        fallback_present || terminal_present || !exact_claim_present ||
        stored_exact_claim.lifecycle != k_java_remote_parent_lifecycle_cleanup ||
        stored_exact_claim.reserved[0] != k_java_remote_parent_lifecycle_publishing ||
        !detach_guard_present ||
        stored_detach_guard.lifecycle != k_java_remote_parent_lifecycle_cleanup ||
        stored_detach_guard.reserved[0] != k_java_remote_parent_lifecycle_publishing ||
        !ambiguity_reserved(&stored_state_key) || ambiguity_count() != 1 ||
        stage_claim_publications != 1 || stage_claim_deletions ||
        rollback_guard_publications != 1 || rollback_guard_deletions ||
        stats[k_java_remote_parent_stat_stage_ambiguous] != 1 ||
        stats[k_java_remote_parent_stat_stage_valid] || unexpected_update || unexpected_delete) {
        fail("rollback promoted a successor reservation after failed marker deletion");
    }
}

static void test_final_ambiguity_uses_serialized_cleanup(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const tp_info_pid_t raw = raw_parent(k_flag_sampled);
    reset(&connection, &raw);
    inject_ambiguity_after_owner_active = 1;

    java_remote_parent_incoming_t handoff = {.generation = test_incoming_generation};
    if (!apply_incoming_trace_candidate(
            &(tp_info_t){}, &raw, &handoff.candidate, &handoff.generation)) {
        fail("final-ambiguity stage parent was not prepared");
    }
    if (java_remote_parent_stage_incoming(&connection,
                                          test_connection_netns,
                                          test_connection_netns_cookie,
                                          test_socket_cookie,
                                          &handoff) ||
        inject_ambiguity_after_owner_active || !generation_sequence || owner_present ||
        state_present || replacement_state_present || generation_index_present ||
        replacement_generation_index_present || connection_present || cookie_connection_present ||
        fallback_present || terminal_present || exact_claim_present || detach_guard_present ||
        ambiguity_count() || cleanup_claim_publications || cleanup_claim_deletions ||
        stage_claim_publications != 1 || stage_claim_deletions != 1 ||
        rollback_guard_publications != 1 || rollback_guard_deletions != 1 ||
        ambiguity_deleted_without_claim ||
        stored_exact_claim.lifecycle != k_java_remote_parent_lifecycle_publishing ||
        stored_exact_claim.process_incarnation != test_process_incarnation ||
        !same_key(&stored_exact_claim_key, &stored_state_key, sizeof(stored_state_key)) ||
        stats[k_java_remote_parent_stat_stage_ambiguous] != 1 ||
        stats[k_java_remote_parent_stat_stage_valid] != 0 || unexpected_update ||
        unexpected_delete) {
        fail("final ambiguity bypassed serialized exact-claim cleanup");
    }

    const java_remote_parent_key_t failed_key = stored_state_key;
    const u64 clean_generation = java_remote_parent_stage_incoming(&connection,
                                                                   test_connection_netns,
                                                                   test_connection_netns_cookie,
                                                                   test_socket_cookie,
                                                                   &handoff);
    if (!clean_generation || clean_generation == failed_key.generation || !owner_present ||
        stored_owner.generation != clean_generation ||
        stored_owner.lifecycle != k_java_remote_parent_lifecycle_active || !state_present ||
        stored_state_key.generation != clean_generation || !generation_index_present ||
        stored_generation_index_key.generation != clean_generation || !connection_present ||
        stored_connection.generation != clean_generation || !cookie_connection_present ||
        stored_cookie_connection.generation != clean_generation || !fallback_present ||
        java_remote_parent_le64_to_cpu(stored_fallback.generation_le) != clean_generation ||
        terminal_present || exact_claim_present || detach_guard_present ||
        !ambiguity_reserved(&stored_state_key) || find_ambiguity_entry(&failed_key) ||
        ambiguity_count() != 1 || cleanup_claim_publications || cleanup_claim_deletions ||
        stage_claim_publications != 2 || stage_claim_deletions != 2 ||
        rollback_guard_publications != 1 || rollback_guard_deletions != 1 ||
        ambiguity_deleted_without_claim || stats[k_java_remote_parent_stat_stage_ambiguous] != 1 ||
        stats[k_java_remote_parent_stat_stage_valid] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("clean stage did not recover after final-ambiguity cleanup");
    }
}

static void test_final_incoming_invalidation_uses_serialized_cleanup(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const tp_info_pid_t raw = raw_parent(k_flag_sampled);
    reset(&connection, &raw);
    invalidate_incoming_after_owner_active = 1;

    java_remote_parent_incoming_t handoff = {.generation = test_incoming_generation};
    if (!apply_incoming_trace_candidate(
            &(tp_info_t){}, &raw, &handoff.candidate, &handoff.generation)) {
        fail("final-incoming-invalidation stage parent was not prepared");
    }
    if (java_remote_parent_stage_incoming(&connection,
                                          test_connection_netns,
                                          test_connection_netns_cookie,
                                          test_socket_cookie,
                                          &handoff) ||
        invalidate_incoming_after_owner_active ||
        incoming_generation != test_incoming_generation + 1 || !generation_sequence ||
        owner_present || state_present || replacement_state_present || generation_index_present ||
        replacement_generation_index_present || connection_present || cookie_connection_present ||
        fallback_present || terminal_present || exact_claim_present || detach_guard_present ||
        ambiguity_count() || cleanup_claim_publications || cleanup_claim_deletions ||
        stage_claim_publications != 1 || stage_claim_deletions != 1 ||
        rollback_guard_publications != 1 || rollback_guard_deletions != 1 ||
        ambiguity_deleted_without_claim ||
        stored_exact_claim.lifecycle != k_java_remote_parent_lifecycle_publishing ||
        stored_exact_claim.process_incarnation != test_process_incarnation ||
        !same_key(&stored_exact_claim_key, &stored_state_key, sizeof(stored_state_key)) ||
        stats[k_java_remote_parent_stat_stage_ambiguous] != 1 ||
        stats[k_java_remote_parent_stat_stage_valid] != 0 || unexpected_update ||
        unexpected_delete) {
        fail("final incoming invalidation did not retain serialized cleanup behavior");
    }

    const java_remote_parent_key_t failed_key = stored_state_key;
    incoming_generation = test_incoming_generation;
    const u64 clean_generation = java_remote_parent_stage_incoming(&connection,
                                                                   test_connection_netns,
                                                                   test_connection_netns_cookie,
                                                                   test_socket_cookie,
                                                                   &handoff);
    if (!clean_generation || clean_generation == failed_key.generation || !owner_present ||
        stored_owner.generation != clean_generation ||
        stored_owner.lifecycle != k_java_remote_parent_lifecycle_active || !state_present ||
        stored_state_key.generation != clean_generation || !generation_index_present ||
        stored_generation_index_key.generation != clean_generation || !connection_present ||
        stored_connection.generation != clean_generation || !cookie_connection_present ||
        stored_cookie_connection.generation != clean_generation || !fallback_present ||
        java_remote_parent_le64_to_cpu(stored_fallback.generation_le) != clean_generation ||
        terminal_present || exact_claim_present || detach_guard_present ||
        !ambiguity_reserved(&stored_state_key) || find_ambiguity_entry(&failed_key) ||
        ambiguity_count() != 1 || cleanup_claim_publications || cleanup_claim_deletions ||
        stage_claim_publications != 2 || stage_claim_deletions != 2 ||
        rollback_guard_publications != 1 || rollback_guard_deletions != 1 ||
        ambiguity_deleted_without_claim || stats[k_java_remote_parent_stat_stage_ambiguous] != 1 ||
        stats[k_java_remote_parent_stat_stage_valid] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("clean stage did not recover after final incoming invalidation");
    }
}

static void test_inconsistent_physical_index_quarantines_stage(void) {
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
        !owner_present || stored_owner.lifecycle != k_java_remote_parent_lifecycle_publishing ||
        !state_present || !generation_index_present || connection_present || fallback_present ||
        !cookie_connection_present || stored_connection.socket_cookie != test_socket_cookie ||
        stored_cookie_connection.socket_cookie == test_socket_cookie || !exact_claim_present ||
        !detach_guard_present || !ambiguity_marked(&stored_state_key) ||
        rollback_guard_publications != 1 || rollback_guard_deletions || stage_claim_deletions ||
        stats[k_java_remote_parent_stat_stage_ambiguous] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("inconsistent physical connection indexes were not quarantined");
    }
}

static void test_aliased_generation_blocks_a_second_stage_on_the_same_socket(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const tp_info_pid_t raw = raw_parent(k_flag_sampled);
    reset(&connection, &raw);
    java_remote_parent_incoming_t first_handoff = {.generation = test_incoming_generation};
    if (!apply_incoming_trace_candidate(
            &(tp_info_t){}, &raw, &first_handoff.candidate, &first_handoff.generation)) {
        fail("first same-socket parent was not prepared");
    }

    const u64 first_generation = java_remote_parent_stage_incoming(&connection,
                                                                   test_connection_netns,
                                                                   test_connection_netns_cookie,
                                                                   test_socket_cookie,
                                                                   &first_handoff);
    if (!first_generation || !state_present || !generation_index_present || !connection_present ||
        !cookie_connection_present || !owner_present || !fallback_present) {
        fail("first same-socket generation was not staged");
    }

    stored_state.aliases = 1;
    java_remote_parent_begin_data_receive();
    java_remote_parent_resolution_t direct = {0};
    java_remote_parent_resolve_exact(&direct, &test_owner, 0, 0);
    java_remote_parent_resolution_t exact_task = {0};
    java_remote_parent_resolve_exact(&exact_task, &test_owner, first_generation, 1);
    if (owner_present || fallback_present || !state_present || !generation_index_present ||
        !connection_present || !cookie_connection_present || stored_state.aliases != 1 ||
        direct.found || !exact_task.found || exact_task.ambiguous ||
        exact_task.key.generation != first_generation) {
        fail("rejected receive kept direct access or lost the exact task generation");
    }

    incoming_generation++;
    incoming_candidate = (incoming_trace_candidate_t){.candidate = raw};
    incoming_claim = 1;
    java_remote_parent_incoming_t second_handoff = {.generation = incoming_generation};
    if (!apply_incoming_trace_candidate(
            &(tp_info_t){}, &raw, &second_handoff.candidate, &second_handoff.generation)) {
        fail("second same-socket parent was not prepared");
    }

    const u64 second_generation = java_remote_parent_stage_incoming(&connection,
                                                                    test_connection_netns,
                                                                    test_connection_netns_cookie,
                                                                    test_socket_cookie,
                                                                    &second_handoff);
    if (second_generation != 0 || owner_present || fallback_present || !state_present ||
        stored_state_key.generation != first_generation || stored_state.aliases != 1 ||
        !generation_index_present || replacement_state_present ||
        replacement_generation_index_present || !connection_present || !cookie_connection_present ||
        stored_connection.generation != first_generation ||
        stored_cookie_connection.generation != first_generation ||
        !ambiguity_marked(&stored_state_key) || ambiguity_count() != 1 ||
        stats[k_java_remote_parent_stat_stage_valid] != 1 ||
        stats[k_java_remote_parent_stat_stage_ambiguous] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("second same-socket stage did not fail closed behind the aliased generation");
    }
}

static void test_terminal_generation_is_replaced_without_ambiguity(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const tp_info_pid_t raw = raw_parent(k_flag_sampled);
    reset(&connection, &raw);
    stored_terminal_key = test_owner;
    stored_terminal = (java_remote_parent_terminal_t){
        .generation = 0xdead,
        .observed_monotime_ns = 50,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_consumed,
    };
    terminal_present = 1;

    java_remote_parent_incoming_t handoff = {.generation = test_incoming_generation};
    if (!apply_incoming_trace_candidate(
            &(tp_info_t){}, &raw, &handoff.candidate, &handoff.generation)) {
        fail("replacement parent was not prepared");
    }

    const u64 replacement_generation =
        java_remote_parent_stage_incoming(&connection,
                                          test_connection_netns,
                                          test_connection_netns_cookie,
                                          test_socket_cookie,
                                          &handoff);
    if (!replacement_generation || replacement_generation == stored_terminal.generation ||
        terminal_present || !owner_present || stored_owner.generation != replacement_generation ||
        !state_present || stored_state_key.generation != replacement_generation ||
        !generation_index_present ||
        stored_generation_index_key.generation != replacement_generation || !connection_present ||
        stored_connection.generation != replacement_generation || !cookie_connection_present ||
        stored_cookie_connection.generation != replacement_generation || !fallback_present ||
        java_remote_parent_le64_to_cpu(stored_fallback.generation_le) != replacement_generation ||
        !ambiguity_reserved(&stored_state_key) || ambiguity_count() != 1 ||
        replacement_state_present || replacement_generation_index_present ||
        stats[k_java_remote_parent_stat_stage_valid] != 1 ||
        stats[k_java_remote_parent_stat_stage_ambiguous] != 0 || unexpected_update ||
        unexpected_delete) {
        fail("terminal generation was not replaced by a clean active generation");
    }
}

static void test_stage_commit_preserves_immediate_consumer_claim(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const tp_info_pid_t raw = raw_parent(k_flag_sampled);
    reset(&connection, &raw);

    java_remote_parent_incoming_t handoff = {.generation = test_incoming_generation};
    if (!apply_incoming_trace_candidate(
            &(tp_info_t){}, &raw, &handoff.candidate, &handoff.generation)) {
        fail("consumer-claim stage parent was not prepared");
    }
    inject_consumed_claim_after_stage_claim_delete = 1;
    const u64 staged_generation = java_remote_parent_stage_incoming(&connection,
                                                                    test_connection_netns,
                                                                    test_connection_netns_cookie,
                                                                    test_socket_cookie,
                                                                    &handoff);

    if (!staged_generation || inject_consumed_claim_after_stage_claim_delete || !owner_present ||
        stored_owner.generation != staged_generation ||
        stored_owner.lifecycle != k_java_remote_parent_lifecycle_active || !state_present ||
        stored_state_key.generation != staged_generation || !generation_index_present ||
        stored_generation_index_key.generation != staged_generation || !connection_present ||
        stored_connection.generation != staged_generation || !cookie_connection_present ||
        stored_cookie_connection.generation != staged_generation || !fallback_present ||
        java_remote_parent_le64_to_cpu(stored_fallback.generation_le) != staged_generation ||
        terminal_present || replacement_state_present || replacement_generation_index_present ||
        !ambiguity_reserved(&stored_state_key) || ambiguity_count() != 1 || !exact_claim_present ||
        !same_key(&stored_exact_claim_key, &stored_state_key, sizeof(stored_state_key)) ||
        !stored_exact_claim.observed_monotime_ns ||
        stored_exact_claim.process_incarnation != test_process_incarnation ||
        stored_exact_claim.lifecycle != k_java_remote_parent_lifecycle_consumed ||
        memcmp(stored_exact_claim.reserved,
               (unsigned char[sizeof(stored_exact_claim.reserved)]){0},
               sizeof(stored_exact_claim.reserved)) != 0 ||
        detach_guard_present || stage_claim_publications != 1 || stage_claim_deletions != 1 ||
        cleanup_claim_publications || cleanup_claim_deletions || rollback_guard_publications ||
        rollback_guard_deletions || stats[k_java_remote_parent_stat_stage_valid] != 1 ||
        stats[k_java_remote_parent_stat_stage_ambiguous] ||
        stats[k_java_remote_parent_stat_stage_overload] ||
        stats[k_java_remote_parent_stat_stage_malformed] || unexpected_update ||
        unexpected_delete) {
        fail("committed stage rolled back an immediate consumer claim");
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

        const u64 staged_generation =
            java_remote_parent_stage_incoming(&connection,
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

static void test_stage_acknowledges_after_claim_release(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const tp_info_pid_t raw = raw_parent(k_flag_sampled);
    reset(&connection, &raw);
    data_signal_nonce = 0xfeedbeef;
    data_signal_present = 1;

    java_remote_parent_incoming_t handoff = {.generation = test_incoming_generation};
    if (!apply_incoming_trace_candidate(
            &(tp_info_t){}, &raw, &handoff.candidate, &handoff.generation)) {
        fail("acknowledged stage parent was not prepared");
    }
    const u64 generation = java_remote_parent_stage_incoming(&connection,
                                                             test_connection_netns,
                                                             test_connection_netns_cookie,
                                                             test_socket_cookie,
                                                             &handoff);
    const pid_key_t process = java_process_key(&test_owner);
    if (!generation || exact_claim_present || !owner_present || !state_present || !ack_present ||
        stored_ack_key.nonce != data_signal_nonce || stored_ack_key.reserved ||
        !same_key(&stored_ack_key.process, &process, sizeof(process)) || stored_ack.reserved ||
        !same_key(&stored_ack.owner, &test_owner, sizeof(test_owner)) ||
        stored_ack.generation != generation ||
        memcmp(&stored_ack.connection, &connection, sizeof(connection)) != 0 ||
        stored_ack.connection_netns != test_connection_netns || unexpected_update ||
        unexpected_delete || stats[k_java_remote_parent_stat_stage_valid] != 1) {
        fail("committed stage did not acknowledge after releasing its publishing claim");
    }
}

int main(void) {
    test_raw_parent_is_published_before_w3c_override();
    test_stage_acknowledges_after_claim_release();
    test_ambiguity_reservation_failure_retires_or_preserves_exact_claim();
    test_logical_owner_conflict_retires_only_the_empty_transaction();
    test_stage_commit_preserves_immediate_consumer_claim();
    test_preexisting_detach_guard_blocks_stage();
    test_malformed_claim_race_is_not_adopted_as_stage_authority();
    test_detach_guard_after_owner_publish_rolls_back_stage();
    test_cleanup_fences_close_stage_publication_windows();
    test_rollback_claim_blocks_cleanup_and_preserves_physical_successors();
    test_rollback_performs_no_delete_after_guard_release();
    test_cookie_publication_ambiguity_is_retired_after_serialized_rollback();
    test_cookie_publication_incoming_invalidation_rolls_back();
    test_rollback_preserves_successor_reservation_after_failed_marker_delete();
    test_final_ambiguity_uses_serialized_cleanup();
    test_final_incoming_invalidation_uses_serialized_cleanup();
    test_inconsistent_physical_index_quarantines_stage();
    test_aliased_generation_blocks_a_second_stage_on_the_same_socket();
    test_terminal_generation_is_replaced_without_ambiguity();
    return 0;
}
