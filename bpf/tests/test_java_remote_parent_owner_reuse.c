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
static u64 test_java_current_process_incarnation(void);
static u64 test_java_process_incarnation_for(const pid_key_t *owner);

#define task_tid test_task_tid
#define java_vt_translate_tid test_java_vt_translate_tid
#define java_current_process_incarnation test_java_current_process_incarnation
#define java_process_incarnation_for test_java_process_incarnation_for

#include <maps/java_remote_parent.h>

#undef java_process_incarnation_for
#undef java_current_process_incarnation
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
    test_process_incarnation = 9,
    test_trace_seed = 0x10,
    test_span_seed = 0x30,
};

static const u64 test_generation = 101;
static const u64 test_replacement_generation = 202;
static const u64 test_direct_child_generation = 303;
static const u64 test_observed_monotime_ns = 1000;
static const u64 test_now_ns = 2000;
static const u64 test_first_token = 1001;
static const u64 test_cancelled_token = 1002;
static const u64 test_capture_race_token = 2001;
static const u64 test_relay_race_token = 2002;
static const u64 test_capture_transfer_token = 3001;
static const u64 test_relay_transfer_token = 3002;
static const pid_key_t test_owner = {.tid = 7, .pid = 5, .ns = 3};
static const pid_key_t test_child = {.tid = 8, .pid = 5, .ns = 3};
static const pid_key_t test_relay_child = {.tid = 9, .pid = 5, .ns = 3};

typedef struct handoff_entry {
    java_remote_parent_handoff_key_t key;
    java_remote_parent_task_t value;
    int present;
} handoff_entry_t;

typedef struct handoff_claim_entry {
    java_remote_parent_handoff_key_t key;
    java_remote_parent_handoff_claim_t value;
    int present;
} handoff_claim_entry_t;

typedef struct ambiguity_entry {
    java_remote_parent_key_t key;
    u64 observed_monotime_ns;
    int present;
} ambiguity_entry_t;

static pid_key_t current_task;
static java_remote_parent_connection_keys_t connection_keys_scratch;
static java_remote_parent_connection_t connection_value_scratch;
static java_remote_parent_owner_t stored_owner;
static int owner_present;
static java_remote_parent_owner_t child_owner;
static int child_owner_present;
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
static connection_info_ns_t replacement_connection_key;
static java_remote_parent_connection_t replacement_connection;
static int replacement_connection_present;
static connection_info_netns_cookie_t stored_cookie_connection_key;
static java_remote_parent_connection_t stored_cookie_connection;
static int cookie_connection_present;
static connection_info_netns_cookie_t replacement_cookie_connection_key;
static java_remote_parent_connection_t replacement_cookie_connection;
static int replacement_cookie_connection_present;
static java_remote_parent_response_t stored_fallback;
static int fallback_present;
static handoff_entry_t handoffs[2];
static handoff_claim_entry_t handoff_claims[2];
static ambiguity_entry_t ambiguities[3];
static java_remote_parent_task_t stored_task;
static int task_present;
static pid_key_t transferred_task_key;
static java_remote_parent_task_t transferred_task;
static int transferred_task_present;
static java_remote_parent_key_t stored_claim_key;
static java_remote_parent_claim_t stored_claim;
static int claim_present;
static java_remote_parent_terminal_t stored_terminal;
static int terminal_present;
static u64 stats[k_java_remote_parent_stat_max];
static int handoff_claim_update_attempts;
static int handoff_claim_update_successes;
static int inject_handoff_claim_on_publish;
static int injected_handoff_claims;
static u32 aliases_at_handoff_publish;
static u32 aliases_at_handoff_delete;
static int transfer_handoff_on_publish;
static pid_key_t transfer_target;
static u32 aliases_at_task_transfer;
static int transfer_claim_publications;
static int transfer_task_publications;
static int transfer_handoff_deletes;
static int transfer_claim_evictions;
static int observe_alias_balance;
static int alias_zero_observed;
static int unexpected_update;
static int unexpected_delete;

static void fail(const char *message) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

static int same_key(const void *left, const void *right, size_t size) {
    return memcmp(left, right, size) == 0;
}

static handoff_entry_t *find_handoff(const java_remote_parent_handoff_key_t *key) {
    for (size_t i = 0; i < sizeof(handoffs) / sizeof(handoffs[0]); i++) {
        if (handoffs[i].present && same_key(key, &handoffs[i].key, sizeof(*key))) {
            return &handoffs[i];
        }
    }
    return NULL;
}

static handoff_claim_entry_t *find_handoff_claim(const java_remote_parent_handoff_key_t *key) {
    for (size_t i = 0; i < sizeof(handoff_claims) / sizeof(handoff_claims[0]); i++) {
        if (handoff_claims[i].present && same_key(key, &handoff_claims[i].key, sizeof(*key))) {
            return &handoff_claims[i];
        }
    }
    return NULL;
}

static ambiguity_entry_t *find_ambiguity(const java_remote_parent_key_t *key) {
    for (size_t i = 0; i < sizeof(ambiguities) / sizeof(ambiguities[0]); i++) {
        if (ambiguities[i].present && same_key(key, &ambiguities[i].key, sizeof(*key))) {
            return &ambiguities[i];
        }
    }
    return NULL;
}

static int inject_handoff_claim(const java_remote_parent_handoff_key_t *key) {
    if (!inject_handoff_claim_on_publish) {
        return 0;
    }
    inject_handoff_claim_on_publish = 0;

    if (find_handoff_claim(key)) {
        return -1;
    }
    for (size_t i = 0; i < sizeof(handoff_claims) / sizeof(handoff_claims[0]); i++) {
        if (!handoff_claims[i].present) {
            handoff_claims[i].key = *key;
            handoff_claims[i].value.observed_monotime_ns = test_now_ns;
            handoff_claims[i].value.process_incarnation = test_process_incarnation;
            handoff_claims[i].present = 1;
            injected_handoff_claims++;
            return 0;
        }
    }
    return -1;
}

static int transfer_published_handoff(handoff_entry_t *handoff) {
    if (!transfer_handoff_on_publish) {
        return 0;
    }
    transfer_handoff_on_publish = 0;

    handoff_claim_entry_t *claim = NULL;
    for (size_t i = 0; i < sizeof(handoff_claims) / sizeof(handoff_claims[0]); i++) {
        if (!handoff_claims[i].present) {
            claim = &handoff_claims[i];
            break;
        }
    }
    if (!claim) {
        return -1;
    }

    claim->key = handoff->key;
    claim->value.observed_monotime_ns = test_now_ns;
    claim->value.process_incarnation = test_process_incarnation;
    claim->present = 1;
    transfer_claim_publications++;

    transferred_task_key = transfer_target;
    transferred_task = handoff->value;
    transferred_task.observed_monotime_ns = test_now_ns;
    transferred_task_present = 1;
    aliases_at_task_transfer = stored_state.aliases;
    transfer_task_publications++;

    aliases_at_handoff_delete = stored_state.aliases;
    handoff->present = 0;
    transfer_handoff_deletes++;

    claim->present = 0;
    transfer_claim_evictions++;
    return 0;
}

static void *test_map_lookup(void *map, const void *key) {
    if (map == &java_remote_parent_connection_keys_storage) {
        return &connection_keys_scratch;
    }
    if (map == &java_remote_parent_connection_value_storage) {
        return &connection_value_scratch;
    }
    if (map == &java_remote_parent_owners && owner_present &&
        same_key(key, &test_owner, sizeof(test_owner))) {
        return &stored_owner;
    }
    if (map == &java_remote_parent_owners && child_owner_present &&
        same_key(key, &test_child, sizeof(test_child))) {
        return &child_owner;
    }
    if (map == &java_remote_parent_state && state_present &&
        same_key(key, &stored_state_key, sizeof(stored_state_key))) {
        if (observe_alias_balance && !stored_state.aliases) {
            alias_zero_observed = 1;
        }
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
    if (map == &java_remote_parent_connections && replacement_connection_present &&
        same_key(key, &replacement_connection_key, sizeof(replacement_connection_key))) {
        return &replacement_connection;
    }
    if (map == &java_remote_parent_cookie_connections && cookie_connection_present &&
        same_key(key, &stored_cookie_connection_key, sizeof(stored_cookie_connection_key))) {
        return &stored_cookie_connection;
    }
    if (map == &java_remote_parent_cookie_connections && replacement_cookie_connection_present &&
        same_key(
            key, &replacement_cookie_connection_key, sizeof(replacement_cookie_connection_key))) {
        return &replacement_cookie_connection;
    }
    if (map == &java_remote_parent_fallback && fallback_present &&
        same_key(key, &test_owner, sizeof(test_owner))) {
        return &stored_fallback;
    }
    if (map == &java_remote_parent_handoffs) {
        handoff_entry_t *entry = find_handoff(key);
        return entry ? &entry->value : NULL;
    }
    if (map == &java_remote_parent_handoff_claims) {
        handoff_claim_entry_t *entry = find_handoff_claim(key);
        return entry ? &entry->value : NULL;
    }
    if (map == &java_remote_parent_tasks && task_present &&
        same_key(key, &test_child, sizeof(test_child))) {
        return &stored_task;
    }
    if (map == &java_remote_parent_tasks && transferred_task_present &&
        same_key(key, &transferred_task_key, sizeof(transferred_task_key))) {
        return &transferred_task;
    }
    if (map == &java_remote_parent_claims && claim_present &&
        same_key(key, &stored_claim_key, sizeof(stored_claim_key))) {
        return &stored_claim;
    }
    if (map == &java_remote_parent_ambiguity) {
        ambiguity_entry_t *entry = find_ambiguity(key);
        return entry ? &entry->observed_monotime_ns : NULL;
    }
    if (map == &java_remote_parent_terminal && terminal_present &&
        same_key(key, &test_owner, sizeof(test_owner))) {
        return &stored_terminal;
    }
    if (map == &java_remote_parent_stats) {
        const u32 index = *(const u32 *)key;
        return index < k_java_remote_parent_stat_max ? &stats[index] : NULL;
    }
    return NULL;
}

static long update_handoff(const java_remote_parent_handoff_key_t *key,
                           const java_remote_parent_task_t *value,
                           unsigned long long flags) {
    if (find_handoff(key) || flags != BPF_NOEXIST) {
        return -1;
    }
    for (size_t i = 0; i < sizeof(handoffs) / sizeof(handoffs[0]); i++) {
        if (!handoffs[i].present) {
            handoffs[i].key = *key;
            handoffs[i].value = *value;
            handoffs[i].present = 1;
            aliases_at_handoff_publish = stored_state.aliases;
            if (inject_handoff_claim(key) != 0) {
                unexpected_update = 1;
            }
            if (transfer_published_handoff(&handoffs[i]) != 0) {
                unexpected_update = 1;
            }
            return 0;
        }
    }
    return -1;
}

static long update_handoff_claim(const java_remote_parent_handoff_key_t *key,
                                 const java_remote_parent_handoff_claim_t *value,
                                 unsigned long long flags) {
    handoff_claim_update_attempts++;
    if (find_handoff_claim(key) || flags != BPF_NOEXIST) {
        return -1;
    }
    for (size_t i = 0; i < sizeof(handoff_claims) / sizeof(handoff_claims[0]); i++) {
        if (!handoff_claims[i].present) {
            handoff_claims[i].key = *key;
            handoff_claims[i].value = *value;
            handoff_claims[i].present = 1;
            handoff_claim_update_successes++;
            return 0;
        }
    }
    return -1;
}

static long update_ambiguity(const java_remote_parent_key_t *key,
                             const u64 *observed_monotime_ns,
                             unsigned long long flags) {
    if (flags != BPF_ANY) {
        return -1;
    }
    ambiguity_entry_t *existing = find_ambiguity(key);
    if (existing) {
        existing->observed_monotime_ns = *observed_monotime_ns;
        return 0;
    }
    for (size_t i = 0; i < sizeof(ambiguities) / sizeof(ambiguities[0]); i++) {
        if (!ambiguities[i].present) {
            ambiguities[i].key = *key;
            ambiguities[i].observed_monotime_ns = *observed_monotime_ns;
            ambiguities[i].present = 1;
            return 0;
        }
    }
    return -1;
}

static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags) {
    if (map == &java_remote_parent_handoffs) {
        return update_handoff(key, value, flags);
    }
    if (map == &java_remote_parent_handoff_claims) {
        return update_handoff_claim(key, value, flags);
    }
    if (map == &java_remote_parent_ambiguity) {
        return update_ambiguity(key, value, flags);
    }
    if (map == &java_remote_parent_tasks && flags == BPF_ANY &&
        same_key(key, &test_child, sizeof(test_child))) {
        stored_task = *(const java_remote_parent_task_t *)value;
        task_present = 1;
        return 0;
    }
    if (map == &java_remote_parent_claims && flags == BPF_NOEXIST && !claim_present) {
        stored_claim_key = *(const java_remote_parent_key_t *)key;
        stored_claim = *(const java_remote_parent_claim_t *)value;
        claim_present = 1;
        return 0;
    }
    if (map == &java_remote_parent_terminal && flags == BPF_ANY &&
        same_key(key, &test_owner, sizeof(test_owner))) {
        stored_terminal = *(const java_remote_parent_terminal_t *)value;
        terminal_present = 1;
        return 0;
    }

    unexpected_update = 1;
    return -1;
}

static long delete_handoff(const java_remote_parent_handoff_key_t *key) {
    handoff_entry_t *entry = find_handoff(key);
    if (!entry) {
        return -1;
    }
    aliases_at_handoff_delete = stored_state.aliases;
    entry->present = 0;
    return 0;
}

static long test_map_delete(void *map, const void *key) {
    if (map == &java_remote_parent_owners && owner_present &&
        same_key(key, &test_owner, sizeof(test_owner))) {
        owner_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_fallback && fallback_present &&
        same_key(key, &test_owner, sizeof(test_owner))) {
        fallback_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_handoffs) {
        return delete_handoff(key);
    }
    if (map == &java_remote_parent_ambiguity) {
        ambiguity_entry_t *entry = find_ambiguity(key);
        if (!entry) {
            return -1;
        }
        entry->present = 0;
        return 0;
    }
    if (map == &java_remote_parent_tasks && task_present &&
        same_key(key, &test_child, sizeof(test_child))) {
        task_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_tasks && transferred_task_present &&
        same_key(key, &transferred_task_key, sizeof(transferred_task_key))) {
        transferred_task_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_connections && connection_present &&
        same_key(key, &stored_connection_key, sizeof(stored_connection_key))) {
        connection_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_connections && replacement_connection_present &&
        same_key(key, &replacement_connection_key, sizeof(replacement_connection_key))) {
        replacement_connection_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_cookie_connections && cookie_connection_present &&
        same_key(key, &stored_cookie_connection_key, sizeof(stored_cookie_connection_key))) {
        cookie_connection_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_cookie_connections && replacement_cookie_connection_present &&
        same_key(
            key, &replacement_cookie_connection_key, sizeof(replacement_cookie_connection_key))) {
        replacement_cookie_connection_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_state && state_present &&
        same_key(key, &stored_state_key, sizeof(stored_state_key))) {
        state_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_state && replacement_state_present &&
        same_key(key, &replacement_state_key, sizeof(replacement_state_key))) {
        replacement_state_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_generation_index && generation_index_present &&
        same_key(key, &stored_generation_index_key, sizeof(stored_generation_index_key))) {
        generation_index_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_generation_index && replacement_generation_index_present &&
        same_key(
            key, &replacement_generation_index_key, sizeof(replacement_generation_index_key))) {
        replacement_generation_index_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_claims && claim_present &&
        same_key(key, &stored_claim_key, sizeof(stored_claim_key))) {
        claim_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_data_signals) {
        return -1;
    }

    unexpected_delete = 1;
    return -1;
}

static unsigned long long test_ktime_get_ns(void) {
    return test_now_ns;
}

static unsigned int test_prandom_u32(void) {
    return 0;
}

static void test_task_tid(pid_key_t *owner) {
    *owner = current_task;
}

static u8 test_java_vt_translate_tid(pid_key_t *owner) {
    (void)owner;
    return 0;
}

static u64 test_java_current_process_incarnation(void) {
    return test_process_incarnation;
}

static u64 test_java_process_incarnation_for(const pid_key_t *owner) {
    const pid_key_t process = java_process_key(owner);
    const pid_key_t expected = java_process_key(&test_owner);
    return same_key(&process, &expected, sizeof(process)) ? test_process_incarnation : 0;
}

static void seed_generation(const connection_info_t *connection) {
    current_task = test_owner;
    memset(&connection_keys_scratch, 0, sizeof(connection_keys_scratch));
    memset(&connection_value_scratch, 0, sizeof(connection_value_scratch));
    memset(&stored_owner, 0, sizeof(stored_owner));
    memset(&child_owner, 0, sizeof(child_owner));
    memset(&stored_state, 0, sizeof(stored_state));
    memset(&replacement_state, 0, sizeof(replacement_state));
    memset(&stored_generation_index, 0, sizeof(stored_generation_index));
    memset(&replacement_generation_index, 0, sizeof(replacement_generation_index));
    memset(&stored_connection, 0, sizeof(stored_connection));
    memset(&replacement_connection, 0, sizeof(replacement_connection));
    memset(&stored_cookie_connection, 0, sizeof(stored_cookie_connection));
    memset(&replacement_cookie_connection, 0, sizeof(replacement_cookie_connection));
    memset(&stored_fallback, 0, sizeof(stored_fallback));
    memset(handoffs, 0, sizeof(handoffs));
    memset(handoff_claims, 0, sizeof(handoff_claims));
    memset(ambiguities, 0, sizeof(ambiguities));
    memset(&stored_task, 0, sizeof(stored_task));
    memset(&transferred_task_key, 0, sizeof(transferred_task_key));
    memset(&transferred_task, 0, sizeof(transferred_task));
    memset(&stored_claim, 0, sizeof(stored_claim));
    memset(&stored_terminal, 0, sizeof(stored_terminal));
    memset(stats, 0, sizeof(stats));

    owner_present = 1;
    child_owner_present = 0;
    state_present = 1;
    replacement_state_present = 0;
    generation_index_present = 1;
    replacement_generation_index_present = 0;
    connection_present = 1;
    replacement_connection_present = 0;
    cookie_connection_present = 1;
    replacement_cookie_connection_present = 0;
    fallback_present = 1;
    task_present = 0;
    transferred_task_present = 0;
    claim_present = 0;
    terminal_present = 0;
    handoff_claim_update_attempts = 0;
    handoff_claim_update_successes = 0;
    inject_handoff_claim_on_publish = 0;
    injected_handoff_claims = 0;
    aliases_at_handoff_publish = 0;
    aliases_at_handoff_delete = 0;
    transfer_handoff_on_publish = 0;
    transfer_target = (pid_key_t){0};
    aliases_at_task_transfer = 0;
    transfer_claim_publications = 0;
    transfer_task_publications = 0;
    transfer_handoff_deletes = 0;
    transfer_claim_evictions = 0;
    observe_alias_balance = 0;
    alias_zero_observed = 0;
    unexpected_update = 0;
    unexpected_delete = 0;

    stored_owner.generation = test_generation;
    stored_owner.process_incarnation = test_process_incarnation;
    stored_owner.lifecycle = k_java_remote_parent_lifecycle_active;

    stored_state_key = java_remote_parent_state_key(&test_owner, test_generation);
    stored_state.lifecycle = k_java_remote_parent_lifecycle_active;
    stored_state.observed_monotime_ns = test_observed_monotime_ns;
    stored_state.connection = *connection;
    stored_state.connection_netns = test_connection_netns;
    stored_state.process_incarnation = test_process_incarnation;
    java_remote_parent_init_response(&stored_state.response,
                                     k_java_remote_parent_status_valid,
                                     test_generation,
                                     test_observed_monotime_ns);
    for (u32 i = 0; i < sizeof(stored_state.response.trace_id); i++) {
        stored_state.response.trace_id[i] = test_trace_seed + i;
    }
    for (u32 i = 0; i < sizeof(stored_state.response.span_id); i++) {
        stored_state.response.span_id[i] = test_span_seed + i;
    }
    stored_state.response.flags = 1;
    stored_fallback = stored_state.response;

    stored_generation_index_key = stored_state_key;
    stored_generation_index.process = java_process_key(&test_owner);
    stored_generation_index.process_incarnation = test_process_incarnation;
    stored_generation_index.observed_monotime_ns = test_observed_monotime_ns;

    stored_connection_key = connection_info_with_netns(connection, test_connection_netns);
    stored_connection.owner = test_owner;
    stored_connection.generation = test_generation;
    stored_connection.netns_cookie = 84;
    stored_connection.incoming_generation = 21;
    stored_connection.netns = test_connection_netns;

    stored_cookie_connection_key.connection = *connection;
    stored_cookie_connection_key.netns_cookie = stored_connection.netns_cookie;
    stored_cookie_connection = stored_connection;
}

static java_remote_parent_response_t
seed_replacement_generation(const connection_info_t *connection) {
    stored_owner.generation = test_replacement_generation;
    stored_owner.process_incarnation = test_process_incarnation;
    stored_owner.lifecycle = k_java_remote_parent_lifecycle_active;
    owner_present = 1;

    replacement_state_key = java_remote_parent_state_key(&test_owner, test_replacement_generation);
    replacement_state.lifecycle = k_java_remote_parent_lifecycle_active;
    replacement_state.observed_monotime_ns = test_now_ns;
    replacement_state.connection = *connection;
    replacement_state.connection_netns = test_connection_netns;
    replacement_state.process_incarnation = test_process_incarnation;
    java_remote_parent_init_response(&replacement_state.response,
                                     k_java_remote_parent_status_valid,
                                     test_replacement_generation,
                                     test_now_ns);
    for (u32 i = 0; i < sizeof(replacement_state.response.trace_id); i++) {
        replacement_state.response.trace_id[i] = test_trace_seed + 0x40 + i;
    }
    for (u32 i = 0; i < sizeof(replacement_state.response.span_id); i++) {
        replacement_state.response.span_id[i] = test_span_seed + 0x40 + i;
    }
    replacement_state.response.flags = 0;
    replacement_state_present = 1;

    replacement_generation_index_key = replacement_state_key;
    replacement_generation_index.process = java_process_key(&test_owner);
    replacement_generation_index.process_incarnation = test_process_incarnation;
    replacement_generation_index.observed_monotime_ns = test_now_ns;
    replacement_generation_index_present = 1;

    replacement_connection_key = connection_info_with_netns(connection, test_connection_netns);
    replacement_connection.owner = test_owner;
    replacement_connection.generation = test_replacement_generation;
    replacement_connection.netns_cookie = 85;
    replacement_connection.incoming_generation = 22;
    replacement_connection.netns = test_connection_netns;
    replacement_connection_present = 1;

    replacement_cookie_connection_key.connection = *connection;
    replacement_cookie_connection_key.netns_cookie = replacement_connection.netns_cookie;
    replacement_cookie_connection = replacement_connection;
    replacement_cookie_connection_present = 1;

    stored_fallback = replacement_state.response;
    fallback_present = 1;
    return replacement_state.response;
}

static void test_capture_claim_race_releases_published_alias(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    const java_remote_parent_handoff_key_t handoff_key =
        java_remote_parent_handoff_key(&test_owner, test_capture_race_token);

    inject_handoff_claim_on_publish = 1;
    java_remote_parent_capture_handoff(test_capture_race_token);

    const handoff_claim_entry_t *claim = find_handoff_claim(&handoff_key);
    if (stored_state.aliases != 0 || find_handoff(&handoff_key) || !claim ||
        claim->value.observed_monotime_ns != test_now_ns ||
        claim->value.process_incarnation != test_process_incarnation ||
        injected_handoff_claims != 1 || inject_handoff_claim_on_publish ||
        aliases_at_handoff_publish != 1 || aliases_at_handoff_delete != 1 ||
        handoff_claim_update_attempts != 0 || !find_ambiguity(&stored_state_key) ||
        unexpected_update || unexpected_delete) {
        fail("capture publisher retained an alias after a concurrent claim");
    }
}

static void test_relay_claim_race_preserves_existing_task_alias(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    stored_state.aliases = 1;
    stored_task = (java_remote_parent_task_t){
        .owner = test_owner,
        .generation = test_generation,
        .observed_monotime_ns = test_now_ns,
    };
    task_present = 1;
    const java_remote_parent_handoff_key_t handoff_key =
        java_remote_parent_handoff_key(&test_child, test_relay_race_token);

    inject_handoff_claim_on_publish = 1;
    java_remote_parent_capture_relay(&test_child, test_relay_race_token);

    const handoff_claim_entry_t *claim = find_handoff_claim(&handoff_key);
    if (stored_state.aliases != 1 || !task_present || find_handoff(&handoff_key) || !claim ||
        claim->value.observed_monotime_ns != test_now_ns ||
        claim->value.process_incarnation != test_process_incarnation ||
        injected_handoff_claims != 1 || inject_handoff_claim_on_publish ||
        aliases_at_handoff_publish != 2 || aliases_at_handoff_delete != 2 ||
        handoff_claim_update_attempts != 0 || !find_ambiguity(&stored_state_key) ||
        unexpected_update || unexpected_delete) {
        fail("relay publisher disturbed its existing task alias after a concurrent claim");
    }
}

static void test_capture_transfer_survives_claim_eviction(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    const java_remote_parent_handoff_key_t handoff_key =
        java_remote_parent_handoff_key(&test_owner, test_capture_transfer_token);

    transfer_target = test_child;
    transfer_handoff_on_publish = 1;
    java_remote_parent_capture_handoff(test_capture_transfer_token);

    const java_remote_parent_resolution_t transferred = java_remote_parent_resolve(&test_child, 0);
    if (stored_state.aliases != 1 || aliases_at_handoff_publish != 1 ||
        aliases_at_task_transfer != 1 || aliases_at_handoff_delete != 1 ||
        find_handoff(&handoff_key) || find_handoff_claim(&handoff_key) ||
        !transferred_task_present ||
        !same_key(&transferred_task_key, &test_child, sizeof(test_child)) ||
        transferred_task.generation != test_generation ||
        !same_key(&transferred_task.owner, &test_owner, sizeof(test_owner)) ||
        transfer_handoff_on_publish || transfer_claim_publications != 1 ||
        transfer_task_publications != 1 || transfer_handoff_deletes != 1 ||
        transfer_claim_evictions != 1 || find_ambiguity(&stored_state_key) || !transferred.found ||
        transferred.ambiguous || !transferred.via_task ||
        !same_key(&transferred.key, &stored_state_key, sizeof(stored_state_key)) ||
        !java_remote_parent_exact_generation_active(&stored_state_key, 0) || unexpected_update ||
        unexpected_delete) {
        fail("capture publisher poisoned ownership after the claimant claim was evicted");
    }
}

static void test_relay_transfer_survives_claim_eviction(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    stored_state.aliases = 1;
    stored_task = (java_remote_parent_task_t){
        .owner = test_owner,
        .generation = test_generation,
        .observed_monotime_ns = test_now_ns,
    };
    task_present = 1;
    const java_remote_parent_handoff_key_t handoff_key =
        java_remote_parent_handoff_key(&test_child, test_relay_transfer_token);

    transfer_target = test_relay_child;
    transfer_handoff_on_publish = 1;
    java_remote_parent_capture_relay(&test_child, test_relay_transfer_token);

    const java_remote_parent_resolution_t transferred =
        java_remote_parent_resolve(&test_relay_child, 0);
    if (stored_state.aliases != 2 || aliases_at_handoff_publish != 2 ||
        aliases_at_task_transfer != 2 || aliases_at_handoff_delete != 2 || !task_present ||
        find_handoff(&handoff_key) || find_handoff_claim(&handoff_key) ||
        !transferred_task_present ||
        !same_key(&transferred_task_key, &test_relay_child, sizeof(test_relay_child)) ||
        transferred_task.generation != test_generation ||
        !same_key(&transferred_task.owner, &test_owner, sizeof(test_owner)) ||
        transfer_handoff_on_publish || transfer_claim_publications != 1 ||
        transfer_task_publications != 1 || transfer_handoff_deletes != 1 ||
        transfer_claim_evictions != 1 || find_ambiguity(&stored_state_key) || !transferred.found ||
        transferred.ambiguous || !transferred.via_task ||
        !same_key(&transferred.key, &stored_state_key, sizeof(stored_state_key)) ||
        !java_remote_parent_exact_generation_active(&stored_state_key, 0) || unexpected_update ||
        unexpected_delete) {
        fail("relay publisher poisoned transferred ownership after the claimant claim was evicted");
    }
}

static void test_direct_child_conflict_marks_exact_generations(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const connection_info_t replacement = {.s_port = 2345, .d_port = 8443};
    seed_generation(&connection);
    stored_state.aliases = 1;

    java_remote_parent_begin_data_receive();
    seed_replacement_generation(&replacement);

    stored_task = (java_remote_parent_task_t){
        .owner = test_owner,
        .generation = test_generation,
        .observed_monotime_ns = test_now_ns,
    };
    task_present = 1;
    child_owner = (java_remote_parent_owner_t){
        .generation = test_direct_child_generation,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_active,
    };
    child_owner_present = 1;

    const java_remote_parent_key_t direct_child_key =
        java_remote_parent_state_key(&test_child, test_direct_child_generation);
    const java_remote_parent_resolution_t conflict = java_remote_parent_resolve(&test_child, 0);
    if (!conflict.found || !conflict.ambiguous || conflict.via_task ||
        !same_key(&conflict.key, &direct_child_key, sizeof(direct_child_key)) ||
        !find_ambiguity(&direct_child_key) || !find_ambiguity(&stored_state_key) ||
        find_ambiguity(&replacement_state_key) ||
        stored_owner.generation != test_replacement_generation || !owner_present ||
        unexpected_update || unexpected_delete) {
        fail("direct-child conflict did not mark both exact generations");
    }

    java_remote_parent_resolution_t linked = {0};
    java_remote_parent_resolve_exact(&linked, &test_owner, test_generation, 0);
    if (!linked.found || !linked.ambiguous ||
        !same_key(&linked.key, &stored_state_key, sizeof(stored_state_key)) ||
        java_remote_parent_exact_generation_active(&stored_state_key, 0)) {
        fail("ambiguous detached generation remained valid after direct-child conflict");
    }
}

static void test_captured_generation_survives_owner_reuse(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const connection_info_t replacement = {.s_port = 2345, .d_port = 8443};
    seed_generation(&connection);
    const java_remote_parent_response_t expected = stored_state.response;
    const java_remote_parent_handoff_key_t first_handoff_key = {
        .pid = test_owner.pid,
        .ns = test_owner.ns,
        .token = test_first_token,
    };
    const java_remote_parent_handoff_key_t cancelled_handoff_key = {
        .pid = test_owner.pid,
        .ns = test_owner.ns,
        .token = test_cancelled_token,
    };

    java_remote_parent_capture_handoff(test_first_token);
    java_remote_parent_capture_handoff(test_cancelled_token);
    if (stored_state.aliases != 2 || !find_handoff(&first_handoff_key) ||
        !find_handoff(&cancelled_handoff_key)) {
        fail("sibling handoffs did not retain two generation aliases");
    }

    java_remote_parent_begin_data_receive();
    if (owner_present || fallback_present || !state_present || !generation_index_present ||
        !connection_present || !cookie_connection_present || stored_state.aliases != 2) {
        fail("begin data receive did not preserve the aliased generation without its cursor");
    }

    const java_remote_parent_response_t expected_replacement =
        seed_replacement_generation(&replacement);

    java_remote_parent_cancel_handoff(&test_owner, test_cancelled_token);
    java_remote_parent_cancel_handoff(&test_owner, test_cancelled_token);
    const handoff_claim_entry_t *cancelled_claim = find_handoff_claim(&cancelled_handoff_key);
    if (stored_state.aliases != 1 || find_handoff(&cancelled_handoff_key) || !cancelled_claim ||
        cancelled_claim->value.observed_monotime_ns != test_now_ns ||
        cancelled_claim->value.process_incarnation != test_process_incarnation ||
        handoff_claim_update_attempts != 2 || handoff_claim_update_successes != 1 ||
        !replacement_state_present || !replacement_generation_index_present ||
        !replacement_connection_present || !replacement_cookie_connection_present ||
        !owner_present || !fallback_present) {
        fail("cancelling a detached sibling did not release exactly one alias");
    }

    observe_alias_balance = 1;
    java_remote_parent_link_handoff(&test_child, test_first_token);
    observe_alias_balance = 0;
    const handoff_claim_entry_t *linked_claim = find_handoff_claim(&first_handoff_key);
    if (!task_present || stored_state.aliases != 1 || find_handoff(&first_handoff_key) ||
        !linked_claim || linked_claim->value.observed_monotime_ns != test_now_ns ||
        linked_claim->value.process_incarnation != test_process_incarnation ||
        handoff_claim_update_attempts != 3 || handoff_claim_update_successes != 2 ||
        stored_task.generation != test_generation ||
        !same_key(&stored_task.owner, &test_owner, sizeof(test_owner)) || alias_zero_observed) {
        fail("linking the preserved handoff did not transfer its generation alias");
    }

    current_task = test_child;
    java_remote_parent_response_t response = {0};
    enum java_remote_parent_status status = java_remote_parent_retrieve_for_connection(
        &response, 0, test_now_ns, &connection, test_connection_netns, test_replacement_generation);
    if (status != k_java_remote_parent_status_missing || !state_present || claim_present) {
        fail("wrong exact generation consumed the preserved generation");
    }

    status = java_remote_parent_retrieve_for_connection(
        &response, 0, test_now_ns, &replacement, test_connection_netns, test_generation);
    if (status != k_java_remote_parent_status_missing || !state_present || claim_present) {
        fail("wrong exact connection consumed the preserved generation");
    }

    status = java_remote_parent_retrieve_for_connection(
        &response, 0, test_now_ns, &connection, test_connection_netns, test_generation);
    if (status != k_java_remote_parent_status_valid ||
        java_remote_parent_le64_to_cpu(response.generation_le) != test_generation ||
        memcmp(response.trace_id, expected.trace_id, sizeof(response.trace_id)) != 0 ||
        memcmp(response.span_id, expected.span_id, sizeof(response.span_id)) != 0 ||
        response.flags != expected.flags || state_present || generation_index_present ||
        connection_present || cookie_connection_present || claim_present || !owner_present ||
        stored_owner.generation != test_replacement_generation || !fallback_present ||
        java_remote_parent_le64_to_cpu(stored_fallback.generation_le) !=
            test_replacement_generation ||
        !replacement_state_present || !replacement_generation_index_present ||
        !replacement_connection_present || !replacement_cookie_connection_present ||
        !terminal_present || stored_terminal.generation != test_generation ||
        stored_terminal.observed_monotime_ns != test_observed_monotime_ns ||
        stored_terminal.process_incarnation != test_process_incarnation ||
        stored_terminal.lifecycle != k_java_remote_parent_lifecycle_consumed ||
        stats[k_java_remote_parent_stat_take_valid] != 1 ||
        stats[k_java_remote_parent_stat_take_missing] != 2 ||
        stats[k_java_remote_parent_stat_handoff_valid] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("task-linked exact retrieval did not consume the preserved generation");
    }

    memset(&response, 0, sizeof(response));
    status = java_remote_parent_retrieve(&response, 0, test_now_ns);
    if (status != k_java_remote_parent_status_already_consumed ||
        java_remote_parent_le64_to_cpu(response.generation_le) != test_generation ||
        stats[k_java_remote_parent_stat_take_already_consumed] != 1 ||
        stats[k_java_remote_parent_stat_take_valid] != 1) {
        fail("a second task-linked retrieval was not rejected as already consumed");
    }

    java_remote_parent_unlink_task(&test_child);
    if (task_present || !replacement_state_present || !replacement_generation_index_present ||
        !replacement_connection_present || !replacement_cookie_connection_present ||
        !owner_present || !fallback_present) {
        fail("unlinking the consumed task disturbed the replacement generation");
    }

    current_task = test_owner;
    memset(&response, 0, sizeof(response));
    status = java_remote_parent_retrieve_for_connection(&response,
                                                        0,
                                                        test_now_ns,
                                                        &replacement,
                                                        test_connection_netns,
                                                        test_replacement_generation);
    if (status != k_java_remote_parent_status_valid ||
        java_remote_parent_le64_to_cpu(response.generation_le) != test_replacement_generation ||
        memcmp(response.trace_id, expected_replacement.trace_id, sizeof(response.trace_id)) != 0 ||
        memcmp(response.span_id, expected_replacement.span_id, sizeof(response.span_id)) != 0 ||
        response.flags != expected_replacement.flags || replacement_state_present ||
        replacement_generation_index_present || replacement_connection_present ||
        replacement_cookie_connection_present || owner_present || fallback_present ||
        claim_present || !terminal_present ||
        stored_terminal.generation != test_replacement_generation ||
        stored_terminal.observed_monotime_ns != test_now_ns ||
        stored_terminal.process_incarnation != test_process_incarnation ||
        stored_terminal.lifecycle != k_java_remote_parent_lifecycle_consumed ||
        stats[k_java_remote_parent_stat_take_valid] != 2 ||
        stats[k_java_remote_parent_stat_take_missing] != 2 ||
        stats[k_java_remote_parent_stat_handoff_valid] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("replacement generation did not remain directly retrievable");
    }
}

int main(void) {
    test_capture_claim_race_releases_published_alias();
    test_relay_claim_race_preserves_existing_task_alias();
    test_capture_transfer_survives_claim_eviction();
    test_relay_transfer_survives_claim_eviction();
    test_direct_child_conflict_marks_exact_generations();
    test_captured_generation_survives_owner_reuse();
    return 0;
}
