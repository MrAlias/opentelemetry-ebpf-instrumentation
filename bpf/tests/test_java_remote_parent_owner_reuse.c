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
static u8 test_java_vt_translate_authorized_tid(pid_key_t *owner);
static u8 test_java_vt_translate_tid_for_capability(pid_key_t *owner, u64 process_capability);
static u64 test_java_current_process_incarnation(void);
static u64 test_java_process_incarnation_for(const pid_key_t *owner);
static u64 test_java_process_capability_for(const pid_key_t *owner);
static u8 test_java_vt_prepare_unregistered_cleanup(const pid_key_t *carrier,
                                                    u64 vt_id,
                                                    u64 process_capability,
                                                    pid_key_t *synthetic_owner,
                                                    java_vt_identity_t *expected_identity);
static u8 test_java_vt_delete_identity_if_matches(const pid_key_t *synthetic_owner,
                                                  const java_vt_identity_t *expected_identity);

#define task_tid test_task_tid
#define java_vt_translate_tid test_java_vt_translate_tid
#define java_vt_translate_authorized_tid test_java_vt_translate_authorized_tid
#define java_vt_translate_tid_for_capability test_java_vt_translate_tid_for_capability
#define java_current_process_incarnation test_java_current_process_incarnation
#define java_process_incarnation_for test_java_process_incarnation_for
#define java_process_capability_for test_java_process_capability_for
#define java_vt_prepare_unregistered_cleanup test_java_vt_prepare_unregistered_cleanup
#define java_vt_delete_identity_if_matches test_java_vt_delete_identity_if_matches

#include <maps/java_remote_parent.h>

#undef java_process_capability_for
#undef java_process_incarnation_for
#undef java_current_process_incarnation
#undef java_vt_delete_identity_if_matches
#undef java_vt_prepare_unregistered_cleanup
#undef java_vt_translate_authorized_tid
#undef java_vt_translate_tid_for_capability
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
static const u64 test_task_only_capture_token = 4001;
static const u64 test_receive_boundary_capture_token = 4002;
static const u64 test_direct_over_task_capture_token = 4003;
static const u64 test_socket_cookie = 86;
static const u64 test_replacement_socket_cookie = 87;
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
static pid_key_t authorized_translation_owner;
static u8 authorized_translation_result;
static u64 current_process_incarnation;
static java_remote_parent_connection_keys_t connection_keys_scratch;
static java_remote_parent_connection_t connection_value_scratch;
static java_remote_parent_state_t stage_state_scratch;
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
static pid_key_t stored_task_key;
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
static int java_vt_thread_deletes;
static int java_vt_identity_deletes;
static pid_key_t expected_java_task_delete_key;
static int expect_java_task_delete;
static int java_task_deletes;
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
    if (map == &java_remote_parent_stage_state_storage) {
        return &stage_state_scratch;
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
        same_key(key, &stored_task_key, sizeof(stored_task_key))) {
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
        same_key(key, &stored_task_key, sizeof(stored_task_key))) {
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
        same_key(key, &stored_task_key, sizeof(stored_task_key))) {
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
    if (map == &java_remote_parent_terminal && same_key(key, &test_owner, sizeof(test_owner))) {
        if (terminal_present) {
            terminal_present = 0;
            return 0;
        }
        return -1;
    }
    if (map == &java_remote_parent_data_signals) {
        return -1;
    }
    if (map == &java_tasks) {
        if (expect_java_task_delete &&
            same_key(key, &expected_java_task_delete_key, sizeof(expected_java_task_delete_key))) {
            java_task_deletes++;
        }
        return 0;
    }
    if (map == &java_vt_threads) {
        java_vt_thread_deletes++;
        return 0;
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

static u8 test_java_vt_translate_authorized_tid(pid_key_t *owner) {
    if (authorized_translation_result == k_java_vt_cleanup_translation_none) {
        return 0;
    }
    *owner = authorized_translation_owner;
    return authorized_translation_result;
}

static u8 test_java_vt_translate_tid_for_capability(pid_key_t *owner, u64 process_capability) {
    if (process_capability != test_process_incarnation) {
        return k_java_vt_cleanup_translation_none;
    }
    return test_java_vt_translate_authorized_tid(owner);
}

static u64 test_java_current_process_incarnation(void) {
    return current_process_incarnation;
}

static u64 test_java_process_incarnation_for(const pid_key_t *owner) {
    const pid_key_t process = java_process_key(owner);
    const pid_key_t expected = java_process_key(&test_owner);
    return same_key(&process, &expected, sizeof(process)) ? test_process_incarnation : 0;
}

static u64 test_java_process_capability_for(const pid_key_t *owner) {
    const pid_key_t process = java_process_key(owner);
    const pid_key_t expected = java_process_key(&test_owner);
    return same_key(&process, &expected, sizeof(process)) ? test_process_incarnation : 0;
}

static u8 test_java_vt_prepare_unregistered_cleanup(const pid_key_t *carrier,
                                                    u64 vt_id,
                                                    u64 process_capability,
                                                    pid_key_t *synthetic_owner,
                                                    java_vt_identity_t *expected_identity) {
    (void)carrier;
    if (!vt_id || !process_capability) {
        return 0;
    }
    *synthetic_owner = test_owner;
    *expected_identity = (java_vt_identity_t){
        .virtual_thread_id = vt_id,
        .process_incarnation = process_capability,
    };
    return 1;
}

static u8 test_java_vt_delete_identity_if_matches(const pid_key_t *synthetic_owner,
                                                  const java_vt_identity_t *expected_identity) {
    if (!same_key(synthetic_owner, &test_owner, sizeof(test_owner)) ||
        expected_identity->virtual_thread_id != 42 ||
        expected_identity->process_incarnation != test_process_incarnation) {
        unexpected_delete = 1;
        return 0;
    }
    java_vt_identity_deletes++;
    return 1;
}

static void seed_generation(const connection_info_t *connection) {
    current_task = test_owner;
    memset(&connection_keys_scratch, 0, sizeof(connection_keys_scratch));
    memset(&connection_value_scratch, 0, sizeof(connection_value_scratch));
    memset(&stage_state_scratch, 0, sizeof(stage_state_scratch));
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
    stored_task_key = test_child;
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
    java_vt_thread_deletes = 0;
    java_vt_identity_deletes = 0;
    expected_java_task_delete_key = (pid_key_t){0};
    expect_java_task_delete = 0;
    java_task_deletes = 0;
    unexpected_update = 0;
    unexpected_delete = 0;
    authorized_translation_owner = (pid_key_t){0};
    authorized_translation_result = k_java_vt_cleanup_translation_none;
    current_process_incarnation = test_process_incarnation;

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
    stored_connection.socket_cookie = test_socket_cookie;
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
    replacement_connection.socket_cookie = test_replacement_socket_cookie;
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

static void test_direct_capture_rejects_a_task_only_generation(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    stored_state.aliases = 1;
    stored_task = (java_remote_parent_task_t){
        .owner = test_owner,
        .generation = test_generation,
        .observed_monotime_ns = test_now_ns,
    };
    task_present = 1;
    current_task = test_child;

    const java_remote_parent_handoff_key_t handoff_key =
        java_remote_parent_handoff_key(&test_child, test_task_only_capture_token);
    java_remote_parent_capture_handoff(test_task_only_capture_token);

    if (find_handoff(&handoff_key) || find_handoff_claim(&handoff_key) ||
        stored_state.aliases != 1 || !task_present || stored_task.generation != test_generation ||
        !same_key(&stored_task.owner, &test_owner, sizeof(test_owner)) ||
        find_ambiguity(&stored_state_key) || !owner_present || !state_present ||
        !generation_index_present || !connection_present || !cookie_connection_present ||
        !fallback_present || unexpected_update || unexpected_delete) {
        fail("direct capture accepted or mutated an inherited task-only generation");
    }
}

static void test_direct_retrieval_rejects_a_task_only_generation(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    stored_state.aliases = 1;
    stored_task = (java_remote_parent_task_t){
        .owner = test_owner,
        .generation = test_generation,
        .observed_monotime_ns = test_now_ns,
    };
    task_present = 1;
    current_task = test_child;
    java_remote_parent_response_t response = {0};

    const enum java_remote_parent_status status =
        java_remote_parent_retrieve(&response, 0, test_now_ns, k_java_remote_parent_source_direct);

    if (status != k_java_remote_parent_status_missing ||
        response.status != k_java_remote_parent_status_missing ||
        stats[k_java_remote_parent_stat_take_missing] != 1 || stored_state.aliases != 1 ||
        !task_present || stored_task.generation != test_generation ||
        !same_key(&stored_task.owner, &test_owner, sizeof(test_owner)) ||
        find_ambiguity(&stored_state_key) || !owner_present || !state_present ||
        !generation_index_present || !connection_present || !cookie_connection_present ||
        !fallback_present || claim_present || terminal_present || unexpected_update ||
        unexpected_delete) {
        fail("direct retrieval accepted or mutated an inherited task-only generation");
    }
}

static void test_task_retrieval_rejects_malformed_task_links(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    java_remote_parent_response_t response = {0};

    seed_generation(&connection);
    stored_state.aliases = 1;
    stored_task = (java_remote_parent_task_t){
        .owner = test_owner,
        .reserved = 1,
        .generation = test_generation,
        .observed_monotime_ns = test_now_ns,
    };
    task_present = 1;
    current_task = test_child;
    enum java_remote_parent_status status =
        java_remote_parent_retrieve(&response, 0, test_now_ns, k_java_remote_parent_source_task);
    if (status != k_java_remote_parent_status_missing || task_present ||
        stored_state.aliases != 0 || !owner_present || !state_present ||
        !generation_index_present || !connection_present || !cookie_connection_present ||
        !fallback_present || claim_present || terminal_present || unexpected_update ||
        unexpected_delete) {
        fail("task retrieval accepted a nonzero reserved task link");
    }

    seed_generation(&connection);
    stored_state.aliases = 1;
    stored_task = (java_remote_parent_task_t){
        .generation = test_generation,
        .observed_monotime_ns = test_now_ns,
    };
    task_present = 1;
    current_task = test_child;
    memset(&response, 0, sizeof(response));
    status =
        java_remote_parent_retrieve(&response, 0, test_now_ns, k_java_remote_parent_source_task);
    if (status != k_java_remote_parent_status_missing || task_present ||
        stored_state.aliases != 1 || !owner_present || !state_present ||
        !generation_index_present || !connection_present || !cookie_connection_present ||
        !fallback_present || claim_present || terminal_present || unexpected_update ||
        unexpected_delete) {
        fail("task retrieval accepted an empty task owner");
    }
}

static void test_direct_capture_rejects_a_generation_detached_at_a_receive_boundary(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    stored_state.aliases = 1;
    stored_task_key = test_owner;
    stored_task = (java_remote_parent_task_t){
        .owner = test_owner,
        .generation = test_generation,
        .observed_monotime_ns = test_now_ns,
    };
    task_present = 1;

    java_remote_parent_begin_data_receive();
    if (owner_present || fallback_present || !state_present || !generation_index_present ||
        !connection_present || !cookie_connection_present || !task_present ||
        stored_state.aliases != 1 || unexpected_update || unexpected_delete) {
        fail("receive boundary did not detach the inherited generation cursor");
    }

    const java_remote_parent_handoff_key_t handoff_key =
        java_remote_parent_handoff_key(&test_owner, test_receive_boundary_capture_token);
    java_remote_parent_capture_handoff(test_receive_boundary_capture_token);

    if (find_handoff(&handoff_key) || find_handoff_claim(&handoff_key) ||
        stored_state.aliases != 1 || !task_present || stored_task.generation != test_generation ||
        !same_key(&stored_task.owner, &test_owner, sizeof(test_owner)) ||
        find_ambiguity(&stored_state_key) || owner_present || fallback_present || !state_present ||
        !generation_index_present || !connection_present || !cookie_connection_present ||
        unexpected_update || unexpected_delete) {
        fail("direct capture revived a task alias detached by a receive boundary");
    }
}

static void test_registration_eviction_detaches_a_mounted_virtual_thread(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    stored_state.aliases = 1;
    stored_task_key = test_owner;
    stored_task = (java_remote_parent_task_t){
        .owner = test_owner,
        .generation = test_generation,
        .observed_monotime_ns = test_now_ns,
    };
    task_present = 1;

    current_task = (pid_key_t){.tid = 6, .pid = test_owner.pid, .ns = test_owner.ns};
    authorized_translation_owner = test_owner;
    authorized_translation_result = k_java_vt_cleanup_translation_exact;
    current_process_incarnation = 0;
    java_remote_parent_begin_data_receive();

    if (owner_present || fallback_present || !state_present || !generation_index_present ||
        !connection_present || !cookie_connection_present || !task_present ||
        stored_state.aliases != 1 || unexpected_update || unexpected_delete) {
        fail("registration eviction deleted an exact mounted virtual-thread alias");
    }

    current_process_incarnation = test_process_incarnation;
    java_remote_parent_resolution_t direct = {0};
    java_remote_parent_resolve_exact(&direct, &test_owner, 0, 0);
    java_remote_parent_resolution_t exact_task = {0};
    java_remote_parent_resolve_exact(&exact_task, &test_owner, test_generation, 1);
    if (direct.found || !exact_task.found || exact_task.ambiguous ||
        exact_task.key.generation != test_generation || unexpected_update || unexpected_delete) {
        fail("registration eviction left a mounted virtual thread's direct cursor visible");
    }

    // If the full-width guard then disappears, fallback cleanup must unlink
    // the already task-only alias even though its direct owner cursor is gone.
    authorized_translation_result = k_java_vt_cleanup_translation_fallback;
    current_process_incarnation = 0;
    java_remote_parent_begin_data_receive();
    if (!state_present || !generation_index_present || !connection_present ||
        !cookie_connection_present || task_present || stored_state.aliases != 0 || claim_present ||
        terminal_present || unexpected_update || unexpected_delete) {
        fail("identity-guard loss preserved an ownerless synthetic task alias");
    }
    current_process_incarnation = test_process_incarnation;
    direct = (java_remote_parent_resolution_t){0};
    java_remote_parent_resolve_exact(&direct, &test_owner, 0, 0);
    exact_task = (java_remote_parent_resolution_t){0};
    java_remote_parent_resolve_exact(&exact_task, &test_owner, test_generation, 1);
    if (direct.found || exact_task.found) {
        fail("identity-guard recovery revived a zero-alias orphan generation");
    }
}

static void test_missing_identity_guard_destroys_a_mounted_virtual_thread_generation(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    stored_state.aliases = 1;
    stored_task_key = test_owner;
    stored_task = (java_remote_parent_task_t){
        .owner = test_owner,
        .generation = test_generation,
        .observed_monotime_ns = test_now_ns,
    };
    task_present = 1;

    current_task = (pid_key_t){.tid = 6, .pid = test_owner.pid, .ns = test_owner.ns};
    authorized_translation_owner = test_owner;
    authorized_translation_result = k_java_vt_cleanup_translation_fallback;
    current_process_incarnation = 0;
    java_remote_parent_begin_data_receive();

    if (owner_present || fallback_present || state_present || generation_index_present ||
        connection_present || cookie_connection_present || task_present || claim_present ||
        terminal_present || unexpected_update || unexpected_delete) {
        fail("missing virtual-thread identity guard preserved a revivable generation");
    }

    current_process_incarnation = test_process_incarnation;
    java_remote_parent_resolution_t direct = {0};
    java_remote_parent_resolve_exact(&direct, &test_owner, 0, 0);
    java_remote_parent_resolution_t exact_task = {0};
    java_remote_parent_resolve_exact(&exact_task, &test_owner, test_generation, 1);
    if (direct.found || exact_task.found || unexpected_update || unexpected_delete) {
        fail("identity-guard recovery revived a destructively detached generation");
    }
}

static void test_recreated_identity_guard_discards_the_shared_synthetic_owner(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    stored_state.aliases = 1;
    stored_task_key = test_owner;
    stored_task = (java_remote_parent_task_t){
        .owner = test_owner,
        .generation = test_generation,
        .observed_monotime_ns = test_now_ns,
    };
    task_present = 1;

    // A successful BPF_NOEXIST insertion may be the first guard or a guard
    // recreated after eviction. Mount handling must discard the shared low-31
    // synthetic key before publishing either case.
    java_remote_parent_discard_virtual_thread_owner(&test_owner);
    if (owner_present || fallback_present || state_present || generation_index_present ||
        connection_present || cookie_connection_present || task_present || claim_present ||
        terminal_present || unexpected_update || unexpected_delete) {
        fail("recreated virtual-thread identity guard preserved old synthetic-owner state");
    }

    current_task = (pid_key_t){.tid = 6, .pid = test_owner.pid, .ns = test_owner.ns};
    authorized_translation_owner = test_owner;
    authorized_translation_result = k_java_vt_cleanup_translation_exact;
    java_remote_parent_begin_data_receive();
    java_remote_parent_resolution_t exact_task = {0};
    java_remote_parent_resolve_exact(&exact_task, &test_owner, test_generation, 1);
    if (exact_task.found || unexpected_update || unexpected_delete) {
        fail("colliding remount revived a discarded synthetic task alias");
    }
}

static void assert_carrier_exit_destroys_mounted_owner(u8 translation_result) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    stored_state.aliases = 1;
    stored_task_key = test_owner;
    stored_task = (java_remote_parent_task_t){
        .owner = test_owner,
        .generation = test_generation,
        .observed_monotime_ns = test_now_ns,
    };
    task_present = 1;

    const pid_key_t carrier = {.tid = 6, .pid = test_owner.pid, .ns = test_owner.ns};
    authorized_translation_owner = test_owner;
    authorized_translation_result = translation_result;
    current_process_incarnation = 0;
    pid_key_t logical_owner = {};
    if (java_remote_parent_cleanup_exiting_task(&carrier, &logical_owner) != translation_result ||
        !same_key(&logical_owner, &test_owner, sizeof(logical_owner)) || owner_present ||
        fallback_present || state_present || generation_index_present || connection_present ||
        cookie_connection_present || task_present || claim_present || terminal_present ||
        unexpected_update || unexpected_delete) {
        fail("carrier exit preserved a mounted synthetic generation after guard loss");
    }
}

static void test_carrier_exit_cleans_mounted_owner_after_lru_loss(void) {
    assert_carrier_exit_destroys_mounted_owner(k_java_vt_cleanup_translation_exact);
    assert_carrier_exit_destroys_mounted_owner(k_java_vt_cleanup_translation_fallback);
}

static void assert_unregistered_lifecycle_destroys_mounted_owner(u8 translation_result) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    stored_state.aliases = 1;
    stored_task_key = test_owner;
    stored_task = (java_remote_parent_task_t){
        .owner = test_owner,
        .generation = test_generation,
        .observed_monotime_ns = test_now_ns,
    };
    task_present = 1;

    const pid_key_t carrier = {.tid = 6, .pid = test_owner.pid, .ns = test_owner.ns};
    authorized_translation_owner = test_owner;
    authorized_translation_result = translation_result;
    current_process_incarnation = 0;
    expected_java_task_delete_key = carrier;
    expect_java_task_delete = 1;
    java_remote_parent_discard_unregistered_virtual_thread_lifecycle(&carrier,
                                                                     test_process_incarnation);

    if (owner_present || fallback_present || state_present || generation_index_present ||
        connection_present || cookie_connection_present || task_present || claim_present ||
        terminal_present || java_vt_thread_deletes != 1 || java_task_deletes != 1 ||
        unexpected_update || unexpected_delete) {
        fail("unregistered virtual-thread lifecycle preserved a mounted synthetic generation");
    }
}

static void test_unregistered_lifecycle_cleans_mounted_owner_after_registration_loss(void) {
    assert_unregistered_lifecycle_destroys_mounted_owner(k_java_vt_cleanup_translation_exact);
    assert_unregistered_lifecycle_destroys_mounted_owner(k_java_vt_cleanup_translation_fallback);
}

static void assert_unregistered_payload_destroys_parked_owner(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    stored_state.aliases = 1;
    stored_task_key = test_owner;
    stored_task = (java_remote_parent_task_t){
        .owner = test_owner,
        .generation = test_generation,
        .observed_monotime_ns = test_now_ns,
    };
    task_present = 1;

    const pid_key_t carrier = {.tid = 6, .pid = test_owner.pid, .ns = test_owner.ns};
    authorized_translation_result = k_java_vt_cleanup_translation_none;
    current_process_incarnation = 0;
    expected_java_task_delete_key = carrier;
    expect_java_task_delete = 1;
    java_remote_parent_discard_unregistered_virtual_thread_id(
        &carrier, 42, test_process_incarnation, 1);

    if (owner_present || fallback_present || state_present || generation_index_present ||
        connection_present || cookie_connection_present || task_present || claim_present ||
        terminal_present || java_vt_thread_deletes != 1 || java_vt_identity_deletes != 1 ||
        java_task_deletes != 1 || unexpected_update || unexpected_delete) {
        fail("unregistered payload cleanup preserved a parked virtual-thread generation");
    }

    // Model registration recovery and an exact remount. Neither direct nor
    // task lookup may revive the state that existed before the rejected event.
    current_process_incarnation = test_process_incarnation;
    authorized_translation_owner = test_owner;
    authorized_translation_result = k_java_vt_cleanup_translation_exact;
    java_remote_parent_resolution_t direct = {0};
    java_remote_parent_resolve_exact(&direct, &test_owner, 0, 0);
    const java_remote_parent_resolution_t task = java_remote_parent_resolve_task(&test_owner, 0);
    if (direct.found || task.found || unexpected_update || unexpected_delete) {
        fail("registration recovery revived a parked virtual-thread generation");
    }
}

static void test_unregistered_payload_cleans_parked_owner_after_registration_loss(void) {
    assert_unregistered_payload_destroys_parked_owner();
}

static void assert_unregistered_task_lifecycle_removes_stale_alias(u8 translation_result) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    stored_state.aliases = 1;
    const pid_key_t carrier = {.tid = 6, .pid = test_owner.pid, .ns = test_owner.ns};
    stored_task_key =
        translation_result == k_java_vt_cleanup_translation_none ? carrier : test_owner;
    stored_task = (java_remote_parent_task_t){
        .owner = test_owner,
        .generation = test_generation,
        .observed_monotime_ns = test_now_ns,
    };
    task_present = 1;
    authorized_translation_owner = test_owner;
    authorized_translation_result = translation_result;
    current_process_incarnation = 0;

    java_remote_parent_discard_unregistered_task_lifecycle(&carrier, test_process_incarnation);
    const u8 fallback_preserved_state =
        translation_result == k_java_vt_cleanup_translation_fallback &&
        (owner_present || fallback_present || state_present || generation_index_present ||
         connection_present || cookie_connection_present || claim_present || terminal_present);
    const u8 exact_alias_not_released =
        translation_result != k_java_vt_cleanup_translation_fallback && stored_state.aliases != 0;
    if (task_present || fallback_preserved_state || exact_alias_not_released || unexpected_update ||
        unexpected_delete) {
        fail("unregistered task lifecycle preserved an exact worker alias");
    }

    current_process_incarnation = test_process_incarnation;
    const java_remote_parent_resolution_t task = java_remote_parent_resolve_task(
        translation_result == k_java_vt_cleanup_translation_none ? &carrier : &test_owner, 0);
    if (task.found || unexpected_update || unexpected_delete) {
        fail("registration recovery revived a rejected task link");
    }
}

static void test_unregistered_task_lifecycle_cleans_worker_alias_after_registration_loss(void) {
    assert_unregistered_task_lifecycle_removes_stale_alias(k_java_vt_cleanup_translation_none);
    assert_unregistered_task_lifecycle_removes_stale_alias(k_java_vt_cleanup_translation_exact);
    assert_unregistered_task_lifecycle_removes_stale_alias(k_java_vt_cleanup_translation_fallback);
}

static void test_unregistered_token_cancellation_cannot_replay_after_registration_recovery(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    java_remote_parent_capture_handoff(test_cancelled_token);
    const java_remote_parent_handoff_key_t key =
        java_remote_parent_handoff_key(&test_owner, test_cancelled_token);
    if (!find_handoff(&key) || stored_state.aliases != 1) {
        fail("task handoff was not staged before registration loss");
    }

    current_process_incarnation = 0;
    const pid_key_t carrier = {.tid = 6, .pid = test_owner.pid, .ns = test_owner.ns};
    // Handoff authority is process-scoped: carrier and synthetic VT tids map
    // to the same {pid, namespace, token} cancellation key.
    java_remote_parent_cancel_handoff_for_capability(
        &carrier, test_cancelled_token, test_process_incarnation);
    const handoff_claim_entry_t *claim = find_handoff_claim(&key);
    if (find_handoff(&key) || !claim ||
        claim->value.process_incarnation != test_process_incarnation || stored_state.aliases != 0 ||
        unexpected_update || unexpected_delete) {
        fail("unregistered cancellation retained a replayable task handoff");
    }

    current_process_incarnation = test_process_incarnation;
    java_remote_parent_link_handoff(&test_child, test_cancelled_token);
    if (task_present || transferred_task_present || find_handoff(&key) || unexpected_update ||
        unexpected_delete) {
        fail("registration recovery replayed a cleanup-claimed task handoff");
    }
}

static void test_direct_capture_selects_a_new_receive_over_an_old_task_alias(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const connection_info_t replacement = {.s_port = 2345, .d_port = 8443};
    seed_generation(&connection);
    stored_state.aliases = 1;

    java_remote_parent_begin_data_receive();
    seed_replacement_generation(&replacement);
    stored_task_key = test_owner;
    stored_task = (java_remote_parent_task_t){
        .owner = test_owner,
        .generation = test_generation,
        .observed_monotime_ns = test_now_ns,
    };
    task_present = 1;

    const java_remote_parent_handoff_key_t handoff_key =
        java_remote_parent_handoff_key(&test_owner, test_direct_over_task_capture_token);
    java_remote_parent_capture_handoff(test_direct_over_task_capture_token);

    const handoff_entry_t *handoff = find_handoff(&handoff_key);
    if (!handoff || handoff->value.generation != test_replacement_generation ||
        !same_key(&handoff->value.owner, &test_owner, sizeof(test_owner)) ||
        stored_state.aliases != 1 || replacement_state.aliases != 1 || !task_present ||
        stored_task.generation != test_generation ||
        !same_key(&stored_task.owner, &test_owner, sizeof(test_owner)) ||
        find_ambiguity(&stored_state_key) || find_ambiguity(&replacement_state_key) ||
        !owner_present || stored_owner.generation != test_replacement_generation ||
        !state_present || !replacement_state_present || !generation_index_present ||
        !replacement_generation_index_present || !connection_present ||
        !replacement_connection_present || !cookie_connection_present ||
        !replacement_cookie_connection_present || unexpected_update || unexpected_delete) {
        fail("direct capture selected or mutated an old task alias instead of the new receive");
    }
}

static void test_retrieval_rejects_an_unknown_source_without_mutation(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    java_remote_parent_response_t response = {0};

    const enum java_remote_parent_status status =
        java_remote_parent_retrieve(&response, 0, test_now_ns, (enum java_remote_parent_source)0);

    if (status != k_java_remote_parent_status_malformed ||
        response.status != k_java_remote_parent_status_malformed ||
        stats[k_java_remote_parent_stat_take_malformed] != 1 || !owner_present || !state_present ||
        !generation_index_present || !connection_present || !cookie_connection_present ||
        !fallback_present || task_present || claim_present || terminal_present ||
        unexpected_update || unexpected_delete) {
        fail("unknown retrieval source did not fail malformed without mutation");
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

static void test_new_receive_cleans_unaliased_generation_with_the_same_socket_cookie(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);

    java_remote_parent_begin_data_receive();
    if (owner_present || fallback_present || state_present || generation_index_present ||
        connection_present || cookie_connection_present || task_present || claim_present ||
        terminal_present || unexpected_update || unexpected_delete) {
        fail("new receive retained an unaliased generation for the same physical socket");
    }

    java_remote_parent_capture_handoff(test_cancelled_token);
    const java_remote_parent_handoff_key_t handoff_key = {
        .pid = test_owner.pid,
        .ns = test_owner.ns,
        .token = test_cancelled_token,
    };
    if (find_handoff(&handoff_key) || stored_state.aliases != 0 || unexpected_update ||
        unexpected_delete) {
        fail("cleaned same-socket generation was revived by a later task capture");
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
    enum java_remote_parent_status status =
        java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_replacement_generation,
                                                   test_socket_cookie);
    if (status != k_java_remote_parent_status_missing || !state_present || claim_present) {
        fail("wrong exact generation consumed the preserved generation");
    }

    status = java_remote_parent_retrieve_for_connection(&response,
                                                        0,
                                                        test_now_ns,
                                                        k_java_remote_parent_source_task,
                                                        &replacement,
                                                        test_connection_netns,
                                                        test_generation,
                                                        test_replacement_socket_cookie);
    if (status != k_java_remote_parent_status_missing || !state_present || claim_present) {
        fail("wrong exact connection consumed the preserved generation");
    }

    status = java_remote_parent_retrieve_for_connection(&response,
                                                        0,
                                                        test_now_ns,
                                                        k_java_remote_parent_source_task,
                                                        &connection,
                                                        test_connection_netns,
                                                        test_generation,
                                                        test_replacement_socket_cookie);
    if (status != k_java_remote_parent_status_missing || !state_present || claim_present) {
        fail("wrong physical socket consumed the preserved generation");
    }

    status = java_remote_parent_retrieve_for_connection(&response,
                                                        0,
                                                        test_now_ns,
                                                        k_java_remote_parent_source_task,
                                                        &connection,
                                                        test_connection_netns,
                                                        test_generation,
                                                        test_socket_cookie);
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
        stats[k_java_remote_parent_stat_take_missing] != 3 ||
        stats[k_java_remote_parent_stat_handoff_valid] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("task-linked exact retrieval did not consume the preserved generation");
    }

    memset(&response, 0, sizeof(response));
    status =
        java_remote_parent_retrieve(&response, 0, test_now_ns, k_java_remote_parent_source_task);
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
                                                        k_java_remote_parent_source_direct,
                                                        &replacement,
                                                        test_connection_netns,
                                                        test_replacement_generation,
                                                        test_replacement_socket_cookie);
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
        stats[k_java_remote_parent_stat_take_missing] != 3 ||
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
    test_direct_capture_rejects_a_task_only_generation();
    test_direct_retrieval_rejects_a_task_only_generation();
    test_task_retrieval_rejects_malformed_task_links();
    test_direct_capture_rejects_a_generation_detached_at_a_receive_boundary();
    test_registration_eviction_detaches_a_mounted_virtual_thread();
    test_missing_identity_guard_destroys_a_mounted_virtual_thread_generation();
    test_recreated_identity_guard_discards_the_shared_synthetic_owner();
    test_carrier_exit_cleans_mounted_owner_after_lru_loss();
    test_unregistered_lifecycle_cleans_mounted_owner_after_registration_loss();
    test_unregistered_payload_cleans_parked_owner_after_registration_loss();
    test_unregistered_task_lifecycle_cleans_worker_alias_after_registration_loss();
    test_unregistered_token_cancellation_cannot_replay_after_registration_recovery();
    test_direct_capture_selects_a_new_receive_over_an_old_task_alias();
    test_retrieval_rejects_an_unknown_source_without_mutation();
    test_direct_child_conflict_marks_exact_generations();
    test_new_receive_cleans_unaliased_generation_with_the_same_socket_cookie();
    test_captured_generation_survives_owner_reuse();
    return 0;
}
