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
static java_remote_parent_state_t stage_state_scratch;
static java_remote_parent_cleanup_workspace_t cleanup_workspace;
static java_remote_parent_janitor_workspace_t janitor_workspace;
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
static int exact_claim_update_attempts;
static int exact_claim_present_at_guard_acquisition;
static int exact_claim_update_failures;
static int exact_claim_delete_failures;
static java_remote_parent_key_t stored_detach_guard_key;
static java_remote_parent_claim_t stored_detach_guard;
static int detach_guard_present;
static java_remote_parent_terminal_t stored_terminal;
static int terminal_present;
static int terminal_update_failures;
static int replace_terminal_after_update;
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
static int mutate_exact_receive_after_claim;
static int remove_state_index_after_claim;
static int replace_state_index_observation_after_claim;
static int inject_detach_guard_after_exact_claim;
static int replace_task_after_exact_claim;
static int replace_task_during_claim_lookup;
static int replace_task_during_detach_guard_lookup;
static int remove_claim_and_replace_task_during_claim_lookup;
static int arm_task_replacement_after_post_claim_check;
static int replace_task_on_next_state_lookup;
static int arm_task_replacement_and_state_loss_after_post_claim_check;
static int replace_task_and_drop_state_on_next_lookup;
static int replace_detach_guard_after_claim;
static int replace_detach_guard_token_after_claim;
static int increment_alias_after_cleanup_claim;
static int release_alias_before_cleanup_claim_delete;
static int cleanup_claim_delete_releases;
static int release_exact_receive_alias_after_fallback_delete;
static int attempt_exact_receive_retain_after_guard;
static int exact_receive_retain_after_guard_result;
static int inject_transient_alias_after_guard;
static int attempt_exact_receive_retain_during_connection_delete;
static int exact_receive_retain_during_connection_delete_result;
static int inject_exact_receive_task_take_after_guard;
static int discard_injected_exact_receive_task_take;
static int hide_detach_guard_once_for_injected_take;
static enum java_remote_parent_status exact_receive_task_take_status;
static java_remote_parent_response_t exact_receive_task_take_response;
static int fallback_delete_failures;
static int fallback_delete_absent_on_failure;
static int owner_delete_failures;
static int cookie_connection_delete_failures;
static int connection_delete_failures;
static int state_delete_failures;
static int generation_index_delete_failures;
static int replace_owner_after_delete;
static int replace_fallback_after_delete;
static int replace_cookie_connection_before_delete;
static int replace_connection_before_delete;
static int replace_cookie_connection_after_delete;
static int replace_connection_after_delete;
static int reinsert_exact_cookie_connection_after_delete;
static int reinsert_exact_connection_after_delete;
static int reinsert_exact_cookie_connection_after_netns_delete;
static int replace_netns_and_reinsert_exact_cookie_after_delete;
static int ambiguity_update_failures;
static int ambiguity_delete_failures;
static int replace_ambiguity_after_failed_delete;
static int replace_ambiguity_after_update;
static int exact_claim_delete_absent_on_failure;
static int replace_exact_claim_on_delete_failure;
static int inject_claim_after_detach_guard_delete;
static int inject_claim_before_exact_update;
static java_remote_parent_claim_t claim_before_exact_update;
static int inject_ambiguity_after_detach_guard_delete;
static int inject_zero_ambiguity_after_detach_guard_delete;
static int inject_connection_after_detach_guard_delete;
static int complete_take_after_detach_guard_delete;
static int publish_successor_after_detach_guard_delete;
static int inject_foreign_guard_after_detach_guard_delete;
static int replace_cleanup_owner_after_guard_acquisition;
static int detach_guard_delete_failures;
static int detach_guard_delete_absent_on_failure;
static int replace_detach_guard_on_delete_failure;
static int unexpected_update;
static int unexpected_delete;

static java_remote_parent_response_t
seed_replacement_generation(const connection_info_t *connection);

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

static ambiguity_entry_t *find_ambiguity_entry(const java_remote_parent_key_t *key) {
    for (size_t i = 0; i < sizeof(ambiguities) / sizeof(ambiguities[0]); i++) {
        if (ambiguities[i].present && same_key(key, &ambiguities[i].key, sizeof(*key))) {
            return &ambiguities[i];
        }
    }
    return NULL;
}

static ambiguity_entry_t *find_ambiguity(const java_remote_parent_key_t *key) {
    ambiguity_entry_t *entry = find_ambiguity_entry(key);
    return entry && entry->observed_monotime_ns ? entry : NULL;
}

static int exact_adoption_fence_retained(const java_remote_parent_key_t *key) {
    return claim_present && same_key(&stored_claim_key, key, sizeof(*key)) &&
           stored_claim.observed_monotime_ns &&
           stored_claim.process_incarnation == test_process_incarnation &&
           stored_claim.lifecycle == k_java_remote_parent_lifecycle_publishing &&
           find_ambiguity(key);
}

static int exact_reset_fences_retained(const java_remote_parent_key_t *key) {
    const java_remote_parent_key_t guard_key = {.owner = key->owner};
    return exact_adoption_fence_retained(key) && detach_guard_present &&
           same_key(&stored_detach_guard_key, &guard_key, sizeof(guard_key)) &&
           stored_detach_guard.observed_monotime_ns &&
           stored_detach_guard.process_incarnation == key->generation &&
           stored_detach_guard.lifecycle == k_java_remote_parent_lifecycle_publishing;
}

static int exact_finish_fences_retained(const java_remote_parent_key_t *key,
                                        enum java_remote_parent_lifecycle lifecycle) {
    const java_remote_parent_key_t guard_key = {.owner = key->owner};
    return claim_present && same_key(&stored_claim_key, key, sizeof(*key)) &&
           stored_claim.observed_monotime_ns &&
           stored_claim.process_incarnation == test_process_incarnation &&
           stored_claim.lifecycle == lifecycle && find_ambiguity(key) && detach_guard_present &&
           same_key(&stored_detach_guard_key, &guard_key, sizeof(guard_key)) &&
           stored_detach_guard.observed_monotime_ns &&
           stored_detach_guard.process_incarnation == key->generation &&
           stored_detach_guard.lifecycle == k_java_remote_parent_lifecycle_publishing;
}

static int exact_finish_claim_guard_tail(const java_remote_parent_key_t *key,
                                         enum java_remote_parent_lifecycle lifecycle) {
    const java_remote_parent_key_t guard_key = {.owner = key->owner};
    return claim_present && same_key(&stored_claim_key, key, sizeof(*key)) &&
           stored_claim.observed_monotime_ns &&
           stored_claim.process_incarnation == test_process_incarnation &&
           stored_claim.lifecycle == lifecycle && !find_ambiguity_entry(key) &&
           detach_guard_present &&
           same_key(&stored_detach_guard_key, &guard_key, sizeof(guard_key)) &&
           stored_detach_guard.observed_monotime_ns &&
           stored_detach_guard.process_incarnation == key->generation &&
           stored_detach_guard.lifecycle == k_java_remote_parent_lifecycle_publishing;
}

static int owner_cleanup_payload_absent(void) {
    return !owner_present && !fallback_present && !state_present && !generation_index_present &&
           !connection_present && !cookie_connection_present && !task_present && !terminal_present;
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
    if (map == &java_remote_parent_stage_state_storage) {
        return &stage_state_scratch;
    }
    if (map == &java_remote_parent_cleanup_workspace_storage) {
        return &cleanup_workspace;
    }
    if (map == &java_remote_parent_janitor_workspace_storage) {
        return &janitor_workspace;
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
        if (replace_task_and_drop_state_on_next_lookup) {
            replace_task_and_drop_state_on_next_lookup = 0;
            stored_task.generation = test_replacement_generation;
            stored_task.observed_monotime_ns = test_now_ns;
            state_present = 0;
            return NULL;
        }
        if (replace_task_on_next_state_lookup) {
            replace_task_on_next_state_lookup = 0;
            stored_task.generation = test_replacement_generation;
            stored_task.observed_monotime_ns = test_now_ns;
        }
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
        if (claim_present && arm_task_replacement_after_post_claim_check) {
            arm_task_replacement_after_post_claim_check = 0;
            replace_task_on_next_state_lookup = 1;
        }
        if (claim_present && arm_task_replacement_and_state_loss_after_post_claim_check) {
            arm_task_replacement_and_state_loss_after_post_claim_check = 0;
            replace_task_and_drop_state_on_next_lookup = 1;
        }
        return &stored_task;
    }
    if (map == &java_remote_parent_tasks && transferred_task_present &&
        same_key(key, &transferred_task_key, sizeof(transferred_task_key))) {
        return &transferred_task;
    }
    if (map == &java_remote_parent_claims && claim_present &&
        same_key(key, &stored_claim_key, sizeof(stored_claim_key))) {
        if (remove_claim_and_replace_task_during_claim_lookup) {
            remove_claim_and_replace_task_during_claim_lookup = 0;
            claim_present = 0;
            stored_task.generation = test_replacement_generation;
            stored_task.observed_monotime_ns = test_now_ns;
            return NULL;
        }
        if (replace_task_during_claim_lookup) {
            replace_task_during_claim_lookup = 0;
            stored_task.generation = test_replacement_generation;
            stored_task.observed_monotime_ns = test_now_ns;
        }
        return &stored_claim;
    }
    if (map == &java_remote_parent_claims && detach_guard_present &&
        same_key(key, &stored_detach_guard_key, sizeof(stored_detach_guard_key))) {
        if (replace_task_during_detach_guard_lookup) {
            replace_task_during_detach_guard_lookup = 0;
            stored_task.generation = test_replacement_generation;
            stored_task.observed_monotime_ns = test_now_ns;
        }
        if (hide_detach_guard_once_for_injected_take) {
            hide_detach_guard_once_for_injected_take = 0;
            return NULL;
        }
        return &stored_detach_guard;
    }
    if (map == &java_remote_parent_ambiguity) {
        ambiguity_entry_t *entry = find_ambiguity_entry(key);
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
    if (flags != BPF_ANY && flags != BPF_NOEXIST) {
        return -1;
    }
    if (ambiguity_update_failures) {
        ambiguity_update_failures--;
        return -1;
    }
    ambiguity_entry_t *existing = find_ambiguity_entry(key);
    if (existing && flags == BPF_NOEXIST) {
        return -1;
    }
    if (existing) {
        existing->observed_monotime_ns = *observed_monotime_ns;
        if (replace_ambiguity_after_update) {
            replace_ambiguity_after_update = 0;
            existing->observed_monotime_ns = *observed_monotime_ns + 1;
        }
        return 0;
    }
    for (size_t i = 0; i < sizeof(ambiguities) / sizeof(ambiguities[0]); i++) {
        if (!ambiguities[i].present) {
            ambiguities[i].key = *key;
            ambiguities[i].observed_monotime_ns = *observed_monotime_ns;
            ambiguities[i].present = 1;
            if (replace_ambiguity_after_update) {
                replace_ambiguity_after_update = 0;
                ambiguities[i].observed_monotime_ns = *observed_monotime_ns + 1;
            }
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
    if (map == &java_remote_parent_claims && flags == BPF_NOEXIST) {
        const java_remote_parent_key_t *claim_key = key;
        if (!claim_key->generation) {
            if (claim_present &&
                same_key(&stored_claim_key, &stored_state_key, sizeof(stored_state_key))) {
                exact_claim_present_at_guard_acquisition++;
            }
            if (detach_guard_present) {
                return -1;
            }
            stored_detach_guard_key = *claim_key;
            stored_detach_guard = *(const java_remote_parent_claim_t *)value;
            detach_guard_present = 1;
            if (replace_cleanup_owner_after_guard_acquisition) {
                replace_cleanup_owner_after_guard_acquisition = 0;
                stored_owner.generation = test_replacement_generation;
            }
            if (replace_detach_guard_after_claim) {
                replace_detach_guard_after_claim = 0;
                stored_detach_guard.process_incarnation = test_replacement_generation;
            }
            if (replace_detach_guard_token_after_claim) {
                replace_detach_guard_token_after_claim = 0;
                stored_detach_guard.observed_monotime_ns++;
            }
            if (inject_transient_alias_after_guard) {
                inject_transient_alias_after_guard = 0;
                stored_state.aliases++;
            }
            if (attempt_exact_receive_retain_after_guard) {
                attempt_exact_receive_retain_after_guard = 0;
                exact_receive_retain_after_guard_result =
                    java_remote_parent_retain_generation_alias(&stored_state_key,
                                                               stored_state.observed_monotime_ns);
            }
            if (inject_exact_receive_task_take_after_guard) {
                inject_exact_receive_task_take_after_guard = 0;
                const u8 discard = discard_injected_exact_receive_task_take;
                discard_injected_exact_receive_task_take = 0;
                const pid_key_t saved_task = current_task;
                current_task = test_child;
                exact_receive_task_take_status =
                    java_remote_parent_retrieve_for_connection(&exact_receive_task_take_response,
                                                               discard,
                                                               test_now_ns,
                                                               k_java_remote_parent_source_task,
                                                               &stored_state.connection,
                                                               stored_state.connection_netns,
                                                               test_generation,
                                                               test_socket_cookie);
                current_task = saved_task;
            }
            return 0;
        }
        if (inject_claim_before_exact_update) {
            inject_claim_before_exact_update = 0;
            stored_claim_key = *claim_key;
            stored_claim = claim_before_exact_update;
            claim_present = 1;
            exact_claim_update_attempts++;
            return -1;
        }
        if (claim_present && same_key(key, &stored_claim_key, sizeof(stored_claim_key))) {
            return -1;
        }
        exact_claim_update_attempts++;
        if (exact_claim_update_failures) {
            exact_claim_update_failures--;
            return -1;
        }
        stored_claim_key = *(const java_remote_parent_key_t *)key;
        stored_claim = *(const java_remote_parent_claim_t *)value;
        claim_present = 1;
        if (inject_detach_guard_after_exact_claim) {
            inject_detach_guard_after_exact_claim = 0;
            stored_detach_guard_key = java_remote_parent_state_key(&stored_state_key.owner, 0);
            stored_detach_guard = (java_remote_parent_claim_t){
                .observed_monotime_ns = test_now_ns,
                .process_incarnation = stored_state_key.generation,
                .lifecycle = k_java_remote_parent_lifecycle_publishing,
            };
            detach_guard_present = 1;
        }
        if (replace_task_after_exact_claim) {
            replace_task_after_exact_claim = 0;
            stored_task.generation = test_replacement_generation;
            stored_task.observed_monotime_ns = test_now_ns;
        }
        if (remove_state_index_after_claim) {
            remove_state_index_after_claim = 0;
            state_present = 0;
            generation_index_present = 0;
        }
        if (replace_state_index_observation_after_claim) {
            replace_state_index_observation_after_claim = 0;
            stored_state.observed_monotime_ns = test_now_ns;
            stored_state.response.observed_monotime_ns_le =
                java_remote_parent_cpu_to_le64(test_now_ns);
            stored_generation_index.observed_monotime_ns = test_now_ns;
        }
        if (increment_alias_after_cleanup_claim &&
            stored_claim.lifecycle == k_java_remote_parent_lifecycle_publishing) {
            increment_alias_after_cleanup_claim = 0;
            stored_state.aliases++;
        }
        if (mutate_exact_receive_after_claim) {
            mutate_exact_receive_after_claim = 0;
            stored_cookie_connection.socket_cookie++;
        }
        if (replace_cookie_connection_before_delete) {
            replace_cookie_connection_before_delete = 0;
            stored_cookie_connection.generation = test_replacement_generation;
            stored_cookie_connection.socket_cookie = test_replacement_socket_cookie;
        }
        if (replace_connection_before_delete) {
            replace_connection_before_delete = 0;
            stored_connection.generation = test_replacement_generation;
            stored_connection.socket_cookie = test_replacement_socket_cookie;
        }
        return 0;
    }
    if (map == &java_remote_parent_terminal && (flags == BPF_ANY || flags == BPF_NOEXIST) &&
        same_key(key, &test_owner, sizeof(test_owner))) {
        if (terminal_update_failures) {
            terminal_update_failures--;
            return -1;
        }
        if (flags == BPF_NOEXIST && terminal_present) {
            return -1;
        }
        stored_terminal = *(const java_remote_parent_terminal_t *)value;
        terminal_present = 1;
        if (replace_terminal_after_update) {
            replace_terminal_after_update = 0;
            stored_terminal.reserved[0] = 1;
        }
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
        if (owner_delete_failures) {
            owner_delete_failures--;
            return -1;
        }
        owner_present = 0;
        if (replace_owner_after_delete) {
            replace_owner_after_delete = 0;
            stored_owner.generation = test_replacement_generation;
            stored_owner.process_incarnation = test_process_incarnation;
            stored_owner.lifecycle = k_java_remote_parent_lifecycle_active;
            owner_present = 1;
        }
        return 0;
    }
    if (map == &java_remote_parent_fallback && fallback_present &&
        same_key(key, &test_owner, sizeof(test_owner))) {
        if (fallback_delete_failures) {
            fallback_delete_failures--;
            if (fallback_delete_absent_on_failure) {
                fallback_present = 0;
            }
            return -1;
        }
        fallback_present = 0;
        if (replace_fallback_after_delete) {
            replace_fallback_after_delete = 0;
            stored_fallback.generation_le =
                java_remote_parent_cpu_to_le64(test_replacement_generation);
            fallback_present = 1;
        }
        if (release_exact_receive_alias_after_fallback_delete) {
            release_exact_receive_alias_after_fallback_delete = 0;
            java_remote_parent_unlink_task(&stored_task_key);
        }
        return 0;
    }
    if (map == &java_remote_parent_handoffs) {
        return delete_handoff(key);
    }
    if (map == &java_remote_parent_ambiguity) {
        ambiguity_entry_t *entry = find_ambiguity_entry(key);
        if (!entry) {
            return -1;
        }
        if (ambiguity_delete_failures) {
            ambiguity_delete_failures--;
            if (replace_ambiguity_after_failed_delete) {
                replace_ambiguity_after_failed_delete = 0;
                entry->observed_monotime_ns = 0;
            }
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
        if (connection_delete_failures) {
            connection_delete_failures--;
            return -1;
        }
        connection_present = 0;
        if (replace_netns_and_reinsert_exact_cookie_after_delete) {
            replace_netns_and_reinsert_exact_cookie_after_delete = 0;
            stored_connection.generation = test_replacement_generation;
            stored_connection.socket_cookie = test_replacement_socket_cookie;
            connection_present = 1;
            cookie_connection_present = 1;
        } else if (reinsert_exact_connection_after_delete) {
            connection_present = 1;
        } else if (replace_connection_after_delete) {
            replace_connection_after_delete = 0;
            stored_connection.generation = test_replacement_generation;
            stored_connection.socket_cookie = test_replacement_socket_cookie;
            connection_present = 1;
        }
        if (reinsert_exact_cookie_connection_after_netns_delete) {
            cookie_connection_present = 1;
        }
        return 0;
    }
    if (map == &java_remote_parent_connections && replacement_connection_present &&
        same_key(key, &replacement_connection_key, sizeof(replacement_connection_key))) {
        replacement_connection_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_cookie_connections && cookie_connection_present &&
        same_key(key, &stored_cookie_connection_key, sizeof(stored_cookie_connection_key))) {
        if (cookie_connection_delete_failures) {
            cookie_connection_delete_failures--;
            return -1;
        }
        cookie_connection_present = 0;
        if (attempt_exact_receive_retain_during_connection_delete) {
            attempt_exact_receive_retain_during_connection_delete = 0;
            exact_receive_retain_during_connection_delete_result =
                java_remote_parent_retain_generation_alias(&stored_state_key,
                                                           stored_state.observed_monotime_ns);
        }
        if (reinsert_exact_cookie_connection_after_delete) {
            cookie_connection_present = 1;
        } else if (replace_cookie_connection_after_delete) {
            replace_cookie_connection_after_delete = 0;
            stored_cookie_connection.generation = test_replacement_generation;
            stored_cookie_connection.socket_cookie = test_replacement_socket_cookie;
            cookie_connection_present = 1;
        }
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
        if (state_delete_failures) {
            state_delete_failures--;
            return -1;
        }
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
        if (generation_index_delete_failures) {
            generation_index_delete_failures--;
            return -1;
        }
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
        if (exact_claim_delete_failures) {
            exact_claim_delete_failures--;
            if (exact_claim_delete_absent_on_failure) {
                exact_claim_delete_absent_on_failure = 0;
                claim_present = 0;
            } else if (replace_exact_claim_on_delete_failure) {
                replace_exact_claim_on_delete_failure = 0;
                stored_claim = (java_remote_parent_claim_t){
                    .observed_monotime_ns = test_now_ns + 1,
                    .process_incarnation = test_process_incarnation + 1,
                    .lifecycle = k_java_remote_parent_lifecycle_publishing,
                };
            }
            return -1;
        }
        if (release_alias_before_cleanup_claim_delete) {
            release_alias_before_cleanup_claim_delete = 0;
            java_remote_parent_release_generation_alias(&stored_state_key,
                                                        test_observed_monotime_ns);
            cleanup_claim_delete_releases++;
        }
        claim_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_claims && detach_guard_present &&
        same_key(key, &stored_detach_guard_key, sizeof(stored_detach_guard_key))) {
        if (detach_guard_delete_failures) {
            detach_guard_delete_failures--;
            if (detach_guard_delete_absent_on_failure) {
                detach_guard_delete_absent_on_failure = 0;
                detach_guard_present = 0;
            } else if (replace_detach_guard_on_delete_failure) {
                replace_detach_guard_on_delete_failure = 0;
                stored_detach_guard = (java_remote_parent_claim_t){
                    .observed_monotime_ns = test_now_ns + 1,
                    .process_incarnation = test_replacement_generation,
                    .lifecycle = k_java_remote_parent_lifecycle_publishing,
                };
            }
            return -1;
        }
        detach_guard_present = 0;
        if (inject_foreign_guard_after_detach_guard_delete) {
            inject_foreign_guard_after_detach_guard_delete = 0;
            stored_detach_guard = (java_remote_parent_claim_t){
                .observed_monotime_ns = test_now_ns + 1,
                .process_incarnation = test_replacement_generation,
                .lifecycle = k_java_remote_parent_lifecycle_publishing,
            };
            detach_guard_present = 1;
        }
        if (inject_claim_after_detach_guard_delete) {
            inject_claim_after_detach_guard_delete = 0;
            stored_claim_key = stored_state_key;
            stored_claim = (java_remote_parent_claim_t){
                .observed_monotime_ns = test_now_ns,
                .process_incarnation = test_process_incarnation,
                .lifecycle = k_java_remote_parent_lifecycle_publishing,
            };
            claim_present = 1;
        }
        if (inject_ambiguity_after_detach_guard_delete) {
            inject_ambiguity_after_detach_guard_delete = 0;
            ambiguities[0] = (ambiguity_entry_t){
                .key = stored_state_key,
                .observed_monotime_ns = test_now_ns,
                .present = 1,
            };
        }
        if (inject_zero_ambiguity_after_detach_guard_delete) {
            inject_zero_ambiguity_after_detach_guard_delete = 0;
            ambiguities[0] = (ambiguity_entry_t){
                .key = stored_state_key,
                .present = 1,
            };
        }
        if (inject_connection_after_detach_guard_delete) {
            inject_connection_after_detach_guard_delete = 0;
            connection_present = 1;
        }
        if (complete_take_after_detach_guard_delete) {
            complete_take_after_detach_guard_delete = 0;
            owner_present = 0;
            fallback_present = 0;
            state_present = 0;
            generation_index_present = 0;
            connection_present = 0;
            cookie_connection_present = 0;
            claim_present = 0;
            ambiguity_entry_t *entry = find_ambiguity_entry(&stored_state_key);
            if (entry) {
                entry->present = 0;
            }
            stored_terminal = (java_remote_parent_terminal_t){
                .generation = test_generation,
                .observed_monotime_ns = test_observed_monotime_ns,
                .process_incarnation = test_process_incarnation,
                .lifecycle = k_java_remote_parent_lifecycle_consumed,
            };
            terminal_present = 1;
        }
        if (publish_successor_after_detach_guard_delete) {
            publish_successor_after_detach_guard_delete = 0;
            seed_replacement_generation(&stored_state.connection);
        }
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
    memset(&stage_state_scratch, 0, sizeof(stage_state_scratch));
    memset(&cleanup_workspace, 0, sizeof(cleanup_workspace));
    memset(&janitor_workspace, 0, sizeof(janitor_workspace));
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
    memset(&stored_detach_guard_key, 0, sizeof(stored_detach_guard_key));
    memset(&stored_detach_guard, 0, sizeof(stored_detach_guard));
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
    exact_claim_update_attempts = 0;
    exact_claim_present_at_guard_acquisition = 0;
    exact_claim_update_failures = 0;
    exact_claim_delete_failures = 0;
    detach_guard_present = 0;
    terminal_present = 0;
    terminal_update_failures = 0;
    replace_terminal_after_update = 0;
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
    mutate_exact_receive_after_claim = 0;
    remove_state_index_after_claim = 0;
    replace_state_index_observation_after_claim = 0;
    inject_detach_guard_after_exact_claim = 0;
    replace_task_after_exact_claim = 0;
    replace_task_during_claim_lookup = 0;
    replace_task_during_detach_guard_lookup = 0;
    remove_claim_and_replace_task_during_claim_lookup = 0;
    arm_task_replacement_after_post_claim_check = 0;
    replace_task_on_next_state_lookup = 0;
    arm_task_replacement_and_state_loss_after_post_claim_check = 0;
    replace_task_and_drop_state_on_next_lookup = 0;
    replace_detach_guard_after_claim = 0;
    replace_detach_guard_token_after_claim = 0;
    increment_alias_after_cleanup_claim = 0;
    release_alias_before_cleanup_claim_delete = 0;
    cleanup_claim_delete_releases = 0;
    release_exact_receive_alias_after_fallback_delete = 0;
    attempt_exact_receive_retain_after_guard = 0;
    exact_receive_retain_after_guard_result = -1;
    inject_transient_alias_after_guard = 0;
    attempt_exact_receive_retain_during_connection_delete = 0;
    exact_receive_retain_during_connection_delete_result = -1;
    inject_exact_receive_task_take_after_guard = 0;
    discard_injected_exact_receive_task_take = 0;
    hide_detach_guard_once_for_injected_take = 0;
    exact_receive_task_take_status = k_java_remote_parent_status_unknown;
    memset(&exact_receive_task_take_response, 0, sizeof(exact_receive_task_take_response));
    fallback_delete_failures = 0;
    fallback_delete_absent_on_failure = 0;
    owner_delete_failures = 0;
    cookie_connection_delete_failures = 0;
    connection_delete_failures = 0;
    state_delete_failures = 0;
    generation_index_delete_failures = 0;
    replace_owner_after_delete = 0;
    replace_fallback_after_delete = 0;
    replace_cookie_connection_before_delete = 0;
    replace_connection_before_delete = 0;
    replace_cookie_connection_after_delete = 0;
    replace_connection_after_delete = 0;
    reinsert_exact_cookie_connection_after_delete = 0;
    reinsert_exact_connection_after_delete = 0;
    reinsert_exact_cookie_connection_after_netns_delete = 0;
    replace_netns_and_reinsert_exact_cookie_after_delete = 0;
    ambiguity_update_failures = 0;
    ambiguity_delete_failures = 0;
    replace_ambiguity_after_failed_delete = 0;
    replace_ambiguity_after_update = 0;
    exact_claim_delete_absent_on_failure = 0;
    replace_exact_claim_on_delete_failure = 0;
    inject_claim_after_detach_guard_delete = 0;
    inject_claim_before_exact_update = 0;
    memset(&claim_before_exact_update, 0, sizeof(claim_before_exact_update));
    inject_ambiguity_after_detach_guard_delete = 0;
    inject_zero_ambiguity_after_detach_guard_delete = 0;
    inject_connection_after_detach_guard_delete = 0;
    complete_take_after_detach_guard_delete = 0;
    publish_successor_after_detach_guard_delete = 0;
    inject_foreign_guard_after_detach_guard_delete = 0;
    replace_cleanup_owner_after_guard_acquisition = 0;
    detach_guard_delete_failures = 0;
    detach_guard_delete_absent_on_failure = 0;
    replace_detach_guard_on_delete_failure = 0;
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

    ambiguities[0] = (ambiguity_entry_t){
        .key = stored_state_key,
        .observed_monotime_ns = 0,
        .present = 1,
    };

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

    ambiguities[1] = (ambiguity_entry_t){
        .key = replacement_state_key,
        .observed_monotime_ns = 0,
        .present = 1,
    };

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
        .observed_monotime_ns = test_observed_monotime_ns,
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
        !java_remote_parent_exact_generation_active(
            &stored_state_key, test_observed_monotime_ns, 0) ||
        unexpected_update || unexpected_delete) {
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
        .observed_monotime_ns = test_observed_monotime_ns,
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
        !java_remote_parent_exact_generation_active(
            &stored_state_key, test_observed_monotime_ns, 0) ||
        unexpected_update || unexpected_delete) {
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
        .observed_monotime_ns = test_observed_monotime_ns,
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
        .observed_monotime_ns = test_observed_monotime_ns,
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
        .observed_monotime_ns = test_observed_monotime_ns,
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
        .observed_monotime_ns = test_observed_monotime_ns,
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
        .observed_monotime_ns = test_observed_monotime_ns,
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
        .observed_monotime_ns = test_observed_monotime_ns,
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
        .observed_monotime_ns = test_observed_monotime_ns,
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
        .observed_monotime_ns = test_observed_monotime_ns,
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
        .observed_monotime_ns = test_observed_monotime_ns,
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
        .observed_monotime_ns = test_observed_monotime_ns,
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
        .observed_monotime_ns = test_observed_monotime_ns,
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
        .observed_monotime_ns = test_observed_monotime_ns,
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
        .observed_monotime_ns = test_observed_monotime_ns,
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
        .observed_monotime_ns = test_observed_monotime_ns,
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
        java_remote_parent_exact_generation_active(
            &stored_state_key, test_observed_monotime_ns, 0)) {
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

static void seed_exact_receive_aliases(u32 aliases) {
    stored_state.aliases = aliases;
    if (!aliases) {
        return;
    }
    stored_task = (java_remote_parent_task_t){
        .owner = test_owner,
        .generation = test_generation,
        .observed_monotime_ns = test_observed_monotime_ns,
    };
    task_present = 1;
    if (aliases > 1) {
        handoffs[0] = (handoff_entry_t){
            .key = java_remote_parent_handoff_key(&test_owner, test_first_token),
            .value = stored_task,
            .present = 1,
        };
    }
}

static void test_alias_observation_rejects_same_generation_reuse(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const u64 stale_observation = test_observed_monotime_ns - 1;
    seed_generation(&connection);
    stored_state.aliases = 1;
    stored_task = (java_remote_parent_task_t){
        .owner = test_owner,
        .generation = test_generation,
        .observed_monotime_ns = stale_observation,
    };
    task_present = 1;
    current_task = test_child;

    java_remote_parent_response_t response = {0};
    const enum java_remote_parent_status status =
        java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie);
    if (status != k_java_remote_parent_status_missing || task_present ||
        stored_state.aliases != 1 || !owner_present || !fallback_present || !state_present ||
        !generation_index_present || !connection_present || !cookie_connection_present ||
        claim_present || terminal_present || find_ambiguity(&stored_state_key) ||
        stats[k_java_remote_parent_stat_take_missing] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("stale task alias adopted a reused owner/generation observation");
    }

    if (java_remote_parent_retain_generation_alias(&stored_state_key, stale_observation) ||
        java_remote_parent_retain_detached_generation_alias(&stored_state_key, stale_observation)) {
        fail("stale alias observation retained a reused generation");
    }
    java_remote_parent_release_generation_alias(&stored_state_key, stale_observation);
    if (stored_state.aliases != 1 ||
        !java_remote_parent_retain_generation_alias(&stored_state_key, test_observed_monotime_ns) ||
        stored_state.aliases != 2) {
        fail("observation-bound retain/release disturbed the reused generation");
    }
    java_remote_parent_release_generation_alias(&stored_state_key, test_observed_monotime_ns);
    if (stored_state.aliases != 1 || claim_present || terminal_present ||
        find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("valid observation did not balance exactly one retained alias");
    }
}

static int task_retrieval_rejects_authority(const java_remote_parent_response_t *stale_response,
                                            const connection_info_t *connection,
                                            u32 connection_netns,
                                            u64 generation,
                                            u64 socket_cookie,
                                            u64 response_generation) {
    java_remote_parent_response_t response = *stale_response;
    const enum java_remote_parent_status status =
        java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   connection,
                                                   connection_netns,
                                                   generation,
                                                   socket_cookie);
    java_remote_parent_response_t expected = {0};
    java_remote_parent_init_response(
        &expected, k_java_remote_parent_status_missing, response_generation, 0);
    return status == k_java_remote_parent_status_missing &&
           memcmp(&response, &expected, sizeof(response)) == 0;
}

static void test_detached_task_bridge_preserves_same_socket_replacement(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        owner_present || fallback_present || !state_present || !generation_index_present ||
        connection_present || cookie_connection_present || stored_state.aliases != 1 ||
        !task_present) {
        fail("aliased RESET did not establish a detached task generation");
    }

    current_task = test_owner;
    java_remote_parent_response_t response = {0};
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_direct,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_missing ||
        !state_present || stored_state.aliases != 1 || claim_present || terminal_present) {
        fail("direct retrieval revived a detached task generation");
    }

    const java_remote_parent_handoff_key_t direct_key =
        java_remote_parent_handoff_key(&test_owner, test_receive_boundary_capture_token);
    java_remote_parent_capture_handoff(test_receive_boundary_capture_token);
    if (find_handoff(&direct_key) || stored_state.aliases != 1) {
        fail("direct capture revived a detached task generation");
    }

    const java_remote_parent_handoff_key_t relay_key =
        java_remote_parent_handoff_key(&test_child, test_relay_transfer_token);
    java_remote_parent_capture_relay(&test_child, test_relay_transfer_token);
    const handoff_entry_t *relay = find_handoff(&relay_key);
    if (!relay || relay->value.observed_monotime_ns != test_observed_monotime_ns ||
        stored_state.aliases != 2 || !task_present || find_ambiguity(&stored_state_key)) {
        fail("relay capture could not retain the detached task generation");
    }
    java_remote_parent_cancel_handoff(&test_child, test_relay_transfer_token);
    if (find_handoff(&relay_key) || stored_state.aliases != 1 || !task_present) {
        fail("detached relay cancellation did not balance its alias");
    }

    const java_remote_parent_response_t replacement = seed_replacement_generation(&connection);
    current_task = test_child;
    memset(&response, 0, sizeof(response));
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_valid ||
        java_remote_parent_le64_to_cpu(response.generation_le) != test_generation ||
        !state_present || !generation_index_present || connection_present ||
        cookie_connection_present || !replacement_state_present ||
        !replacement_generation_index_present || !replacement_connection_present ||
        !replacement_cookie_connection_present || !owner_present || !fallback_present ||
        stored_owner.generation != test_replacement_generation ||
        memcmp(&stored_fallback, &replacement, sizeof(replacement)) != 0 ||
        !exact_finish_fences_retained(&stored_state_key, k_java_remote_parent_lifecycle_consumed) ||
        !terminal_present || stored_terminal.generation != test_generation ||
        stored_terminal.lifecycle != k_java_remote_parent_lifecycle_consumed || !task_present ||
        unexpected_update || unexpected_delete) {
        fail("detached task TAKE disturbed a same-socket replacement generation");
    }

    const java_remote_parent_response_t stale_response = response;
    connection_info_t wrong_connection = connection;
    wrong_connection.d_port++;
    if (!task_retrieval_rejects_authority(&stale_response,
                                          &connection,
                                          test_connection_netns,
                                          test_replacement_generation,
                                          test_socket_cookie,
                                          test_generation) ||
        !task_retrieval_rejects_authority(&stale_response,
                                          &wrong_connection,
                                          test_connection_netns,
                                          test_generation,
                                          test_socket_cookie,
                                          test_generation) ||
        !task_retrieval_rejects_authority(&stale_response,
                                          &connection,
                                          test_connection_netns + 1,
                                          test_generation,
                                          test_socket_cookie,
                                          test_generation) ||
        !task_retrieval_rejects_authority(&stale_response,
                                          &connection,
                                          test_connection_netns,
                                          test_generation,
                                          test_replacement_socket_cookie,
                                          test_generation) ||
        stats[k_java_remote_parent_stat_take_missing] != 5 ||
        !exact_finish_fences_retained(&stored_state_key, k_java_remote_parent_lifecycle_consumed) ||
        !replacement_state_present || !replacement_generation_index_present ||
        !replacement_connection_present || !replacement_cookie_connection_present ||
        unexpected_update || unexpected_delete) {
        fail("retained claim accepted mismatched task retrieval authority");
    }

    memset(&response, 0, sizeof(response));
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_already_consumed ||
        response.status != k_java_remote_parent_status_already_consumed ||
        java_remote_parent_le64_to_cpu(response.generation_le) != test_generation ||
        !exact_finish_fences_retained(&stored_state_key, k_java_remote_parent_lifecycle_consumed) ||
        !replacement_state_present || !replacement_generation_index_present ||
        !replacement_connection_present || !replacement_cookie_connection_present ||
        stats[k_java_remote_parent_stat_take_already_consumed] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("repeated detached task TAKE did not preserve an already-consumed claim");
    }

    memset(&response, 0, sizeof(response));
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   1,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_already_consumed ||
        response.status != k_java_remote_parent_status_already_consumed ||
        java_remote_parent_le64_to_cpu(response.generation_le) != test_generation ||
        !exact_finish_fences_retained(&stored_state_key, k_java_remote_parent_lifecycle_consumed) ||
        !replacement_state_present || !replacement_generation_index_present ||
        !replacement_connection_present || !replacement_cookie_connection_present ||
        stats[k_java_remote_parent_stat_discard_already_consumed] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("repeated detached task DISCARD did not preserve an already-consumed claim");
    }

    current_task = test_owner;
    memset(&response, 0, sizeof(response));
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_direct,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_replacement_generation,
                                                   test_replacement_socket_cookie) !=
            k_java_remote_parent_status_overload ||
        response.status != k_java_remote_parent_status_overload ||
        java_remote_parent_le64_to_cpu(response.generation_le) != test_replacement_generation ||
        !exact_finish_fences_retained(&stored_state_key, k_java_remote_parent_lifecycle_consumed) ||
        !replacement_state_present || !replacement_generation_index_present ||
        !replacement_connection_present || !replacement_cookie_connection_present ||
        stats[k_java_remote_parent_stat_take_overload] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("retained owner guard did not overload the replacement generation");
    }
}

static void test_task_claim_binding_rejects_reserved_state(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie)) {
        fail("could not detach task generation for metadata validation");
    }
    stored_state.reserved[2] = 1;
    stored_claim_key = stored_state_key;
    stored_claim = (java_remote_parent_claim_t){
        .observed_monotime_ns = test_now_ns,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_consumed,
    };
    claim_present = 1;
    ambiguities[0].key = stored_state_key;
    ambiguities[0].observed_monotime_ns = test_now_ns;
    ambiguities[0].present = 1;
    current_task = test_child;

    java_remote_parent_response_t response = stored_state.response;
    const enum java_remote_parent_status status =
        java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie);
    java_remote_parent_response_t expected = {0};
    java_remote_parent_init_response(
        &expected, k_java_remote_parent_status_missing, test_generation, 0);
    if (status != k_java_remote_parent_status_missing ||
        memcmp(&response, &expected, sizeof(response)) != 0 || !state_present ||
        stored_state.aliases != 1 || !generation_index_present || owner_present ||
        fallback_present || connection_present || cookie_connection_present || !task_present ||
        !claim_present || terminal_present || !find_ambiguity(&stored_state_key) ||
        stats[k_java_remote_parent_stat_take_missing] != 1 ||
        stats[k_java_remote_parent_stat_take_already_consumed] != 0 || unexpected_update ||
        unexpected_delete) {
        fail("reserved task state authorized a retained claim outcome");
    }
}

static void test_detached_zero_cleanup_quarantines_retain_race(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie)) {
        fail("could not seed a detached generation for cleanup retry");
    }
    task_present = 0;
    stored_state.aliases = 0;
    increment_alias_after_cleanup_claim = 1;

    java_remote_parent_cleanup_detached_zero_alias(
        &stored_state_key, test_process_incarnation, test_observed_monotime_ns);
    if (increment_alias_after_cleanup_claim || cleanup_claim_delete_releases || !state_present ||
        stored_state.aliases != 1 || !generation_index_present || owner_present ||
        fallback_present || connection_present || cookie_connection_present || !claim_present ||
        !same_key(&stored_claim_key, &stored_state_key, sizeof(stored_state_key)) ||
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_publishing ||
        stored_claim.process_incarnation != test_process_incarnation || detach_guard_present ||
        terminal_present || !find_ambiguity(&stored_state_key) ||
        exact_claim_update_attempts != 2 || unexpected_update || unexpected_delete) {
        fail("cleanup retain race was not fenced for userspace adoption");
    }
}

static void test_detached_zero_cleanup_retains_adoption_artifacts(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                       test_process_incarnation,
                                                       &connection,
                                                       test_connection_netns,
                                                       test_socket_cookie);
    task_present = 0;
    stored_state.aliases = 0;
    java_remote_parent_cleanup_detached_zero_alias(
        &stored_state_key, test_process_incarnation, test_observed_monotime_ns);
    if (!state_present || stored_state.aliases || !generation_index_present || !claim_present ||
        !same_key(&stored_claim_key, &stored_state_key, sizeof(stored_state_key)) ||
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_publishing ||
        stored_claim.process_incarnation != test_process_incarnation || terminal_present ||
        !find_ambiguity(&stored_state_key) || owner_present || fallback_present ||
        connection_present || cookie_connection_present || detach_guard_present ||
        exact_claim_update_attempts != 2 || unexpected_update || unexpected_delete) {
        fail("detached zero-alias cleanup did not retain userspace-adoption artifacts");
    }
}

static void test_cross_generation_guard_does_not_block_detached_cleanup(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie)) {
        fail("could not seed detached generation for cross-generation guard test");
    }
    const java_remote_parent_response_t replacement = seed_replacement_generation(&connection);
    stored_detach_guard_key = java_remote_parent_detach_guard_key(&test_owner);
    stored_detach_guard = (java_remote_parent_claim_t){
        .observed_monotime_ns = test_now_ns,
        .process_incarnation = test_replacement_generation,
        .lifecycle = k_java_remote_parent_lifecycle_publishing,
    };
    detach_guard_present = 1;

    java_remote_parent_unlink_task(&test_child);
    if (task_present || !state_present || stored_state.aliases || !generation_index_present ||
        !claim_present ||
        !same_key(&stored_claim_key, &stored_state_key, sizeof(stored_state_key)) ||
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_publishing ||
        !detach_guard_present || !owner_present || !fallback_present ||
        stored_owner.generation != test_replacement_generation ||
        memcmp(&stored_fallback, &replacement, sizeof(replacement)) != 0 ||
        !replacement_state_present || !replacement_generation_index_present ||
        !replacement_connection_present || !replacement_cookie_connection_present ||
        !find_ambiguity(&stored_state_key) || find_ambiguity(&replacement_state_key) ||
        !find_ambiguity_entry(&replacement_state_key) || exact_claim_update_attempts != 2 ||
        unexpected_update || unexpected_delete) {
        fail("different-generation RESET guard did not preserve exact adoption fences");
    }
}

static void test_cleanup_unlinks_and_cleans_a_different_detached_generation(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_replacement_generation(&connection);

    // Generation A remains the indexed generation being cleaned. Its owner task
    // link is the final alias of detached generation B.
    stored_owner.generation = test_generation;
    stored_fallback = stored_state.response;
    replacement_connection_present = 0;
    replacement_cookie_connection_present = 0;
    replacement_state.aliases = 1;
    stored_task_key = test_owner;
    stored_task = (java_remote_parent_task_t){
        .owner = test_owner,
        .generation = test_replacement_generation,
        .observed_monotime_ns = test_now_ns,
    };
    task_present = 1;

    java_remote_parent_cleanup(&test_owner);

    if (owner_present || state_present || !replacement_state_present || replacement_state.aliases ||
        generation_index_present || !replacement_generation_index_present || connection_present ||
        cookie_connection_present || fallback_present || task_present || !claim_present ||
        !same_key(&stored_claim_key, &replacement_state_key, sizeof(replacement_state_key)) ||
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_publishing ||
        !detach_guard_present || stored_detach_guard_key.generation ||
        stored_detach_guard.process_incarnation != test_generation ||
        stored_detach_guard.lifecycle != k_java_remote_parent_lifecycle_publishing ||
        terminal_present || !find_ambiguity(&stored_state_key) ||
        !find_ambiguity(&replacement_state_key) || exact_claim_update_attempts != 2 ||
        unexpected_update || unexpected_delete) {
        fail("owner cleanup did not quarantine the final alias of a detached generation");
    }
}

static void test_owner_cleanup_release_tails_are_recoverable(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    seed_generation(&connection);
    replace_cleanup_owner_after_guard_acquisition = 1;
    java_remote_parent_cleanup(&test_owner);
    if (replace_cleanup_owner_after_guard_acquisition ||
        stored_owner.generation != test_replacement_generation || !fallback_present ||
        !state_present || !generation_index_present || !connection_present ||
        !cookie_connection_present || !claim_present ||
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_discarded ||
        !detach_guard_present || !find_ambiguity(&stored_state_key) || unexpected_update ||
        unexpected_delete) {
        fail("owner cleanup did not retain its full fence after post-guard owner replacement");
    }

    seed_generation(&connection);
    ambiguity_delete_failures = 1;
    replace_ambiguity_after_failed_delete = 1;
    java_remote_parent_cleanup(&test_owner);
    if (ambiguity_delete_failures || replace_ambiguity_after_failed_delete ||
        !owner_cleanup_payload_absent() || !claim_present ||
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_discarded ||
        !detach_guard_present || !find_ambiguity_entry(&stored_state_key) ||
        find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("owner cleanup promoted a successor reservation after failed marker deletion");
    }

    seed_generation(&connection);
    exact_claim_delete_failures = 1;
    java_remote_parent_cleanup(&test_owner);
    if (exact_claim_delete_failures || !owner_cleanup_payload_absent() || !claim_present ||
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_discarded ||
        !detach_guard_present || find_ambiguity_entry(&stored_state_key) || unexpected_update ||
        unexpected_delete) {
        fail("owner cleanup lost its exact-claim/guard release tail");
    }

    seed_generation(&connection);
    exact_claim_delete_failures = 1;
    exact_claim_delete_absent_on_failure = 1;
    java_remote_parent_cleanup(&test_owner);
    if (exact_claim_delete_failures || exact_claim_delete_absent_on_failure ||
        !owner_cleanup_payload_absent() || claim_present || detach_guard_present ||
        find_ambiguity_entry(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("owner cleanup did not converge after an ambiguous absent exact-claim delete");
    }

    seed_generation(&connection);
    exact_claim_delete_failures = 1;
    replace_exact_claim_on_delete_failure = 1;
    java_remote_parent_cleanup(&test_owner);
    if (exact_claim_delete_failures || replace_exact_claim_on_delete_failure ||
        !owner_cleanup_payload_absent() || !claim_present ||
        stored_claim.observed_monotime_ns != test_now_ns + 1 ||
        stored_claim.process_incarnation != test_process_incarnation + 1 ||
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_publishing ||
        !detach_guard_present || find_ambiguity_entry(&stored_state_key) || unexpected_update ||
        unexpected_delete) {
        fail("owner cleanup removed a replacement claim after an ambiguous delete failure");
    }

    seed_generation(&connection);
    detach_guard_delete_failures = 1;
    java_remote_parent_cleanup(&test_owner);
    if (detach_guard_delete_failures || !owner_cleanup_payload_absent() || claim_present ||
        !detach_guard_present || find_ambiguity_entry(&stored_state_key) || unexpected_update ||
        unexpected_delete) {
        fail("owner cleanup lost its guard-only release tail");
    }

    seed_generation(&connection);
    detach_guard_delete_failures = 1;
    detach_guard_delete_absent_on_failure = 1;
    java_remote_parent_cleanup(&test_owner);
    if (detach_guard_delete_failures || detach_guard_delete_absent_on_failure ||
        !owner_cleanup_payload_absent() || claim_present || detach_guard_present ||
        find_ambiguity_entry(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("owner cleanup did not converge after an ambiguous absent guard delete");
    }

    seed_generation(&connection);
    detach_guard_delete_failures = 1;
    replace_detach_guard_on_delete_failure = 1;
    java_remote_parent_cleanup(&test_owner);
    if (detach_guard_delete_failures || replace_detach_guard_on_delete_failure ||
        !owner_cleanup_payload_absent() || claim_present || !detach_guard_present ||
        stored_detach_guard.observed_monotime_ns != test_now_ns + 1 ||
        stored_detach_guard.process_incarnation != test_replacement_generation ||
        stored_detach_guard.lifecycle != k_java_remote_parent_lifecycle_publishing ||
        find_ambiguity_entry(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("owner cleanup removed a replacement guard after an ambiguous delete failure");
    }

    seed_generation(&connection);
    inject_zero_ambiguity_after_detach_guard_delete = 1;
    java_remote_parent_cleanup(&test_owner);
    if (inject_zero_ambiguity_after_detach_guard_delete || !owner_cleanup_payload_absent() ||
        claim_present || detach_guard_present || !find_ambiguity_entry(&stored_state_key) ||
        find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("owner cleanup re-marked a successor reservation after final guard release");
    }
}

static void test_internal_cleanup_claim_is_transient(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    stored_claim_key = stored_state_key;
    stored_claim = (java_remote_parent_claim_t){
        .observed_monotime_ns = test_now_ns,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_publishing,
    };
    claim_present = 1;

    java_remote_parent_response_t response = {0};
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_direct,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_overload ||
        response.status != k_java_remote_parent_status_overload || !claim_present ||
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_publishing || !owner_present ||
        !fallback_present || !state_present || !generation_index_present || !connection_present ||
        !cookie_connection_present || terminal_present ||
        stats[k_java_remote_parent_stat_take_overload] != 1 ||
        stats[k_java_remote_parent_stat_take_already_consumed] != 0 || unexpected_update ||
        unexpected_delete) {
        fail("terminal-free cleanup claim surfaced as an already-consumed outcome");
    }
}

static void test_generation_claim_status_validation(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const struct {
        const char *name;
        java_remote_parent_claim_t claim;
        enum java_remote_parent_status status;
        enum java_remote_parent_stat take_stat;
        enum java_remote_parent_stat discard_stat;
    } cases[] = {
        {
            .name = "publishing claim was not overload",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_publishing,
                },
            .status = k_java_remote_parent_status_overload,
            .take_stat = k_java_remote_parent_stat_take_overload,
            .discard_stat = k_java_remote_parent_stat_discard_overload,
        },
        {
            .name = "ambiguous claim was not ambiguous",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_ambiguous,
                },
            .status = k_java_remote_parent_status_ambiguous,
            .take_stat = k_java_remote_parent_stat_take_ambiguous,
            .discard_stat = k_java_remote_parent_stat_discard_ambiguous,
        },
        {
            .name = "consumed claim was not already consumed",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_consumed,
                },
            .status = k_java_remote_parent_status_already_consumed,
            .take_stat = k_java_remote_parent_stat_take_already_consumed,
            .discard_stat = k_java_remote_parent_stat_discard_already_consumed,
        },
        {
            .name = "discarded claim was not already consumed",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_discarded,
                },
            .status = k_java_remote_parent_status_already_consumed,
            .take_stat = k_java_remote_parent_stat_take_already_consumed,
            .discard_stat = k_java_remote_parent_stat_discard_already_consumed,
        },
        {
            .name = "stale claim was not already consumed",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_stale,
                },
            .status = k_java_remote_parent_status_already_consumed,
            .take_stat = k_java_remote_parent_stat_take_already_consumed,
            .discard_stat = k_java_remote_parent_stat_discard_already_consumed,
        },
        {
            .name = "zero-timestamp claim was not ambiguous",
            .claim =
                {
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_consumed,
                },
            .status = k_java_remote_parent_status_ambiguous,
            .take_stat = k_java_remote_parent_stat_take_ambiguous,
            .discard_stat = k_java_remote_parent_stat_discard_ambiguous,
        },
        {
            .name = "foreign-incarnation claim was not ambiguous",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation + 1,
                    .lifecycle = k_java_remote_parent_lifecycle_consumed,
                },
            .status = k_java_remote_parent_status_ambiguous,
            .take_stat = k_java_remote_parent_stat_take_ambiguous,
            .discard_stat = k_java_remote_parent_stat_discard_ambiguous,
        },
        {
            .name = "reserved claim was not ambiguous",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_consumed,
                    .reserved = {[6] = 1},
                },
            .status = k_java_remote_parent_status_ambiguous,
            .take_stat = k_java_remote_parent_stat_take_ambiguous,
            .discard_stat = k_java_remote_parent_stat_discard_ambiguous,
        },
        {
            .name = "active claim was not ambiguous",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_active,
                },
            .status = k_java_remote_parent_status_ambiguous,
            .take_stat = k_java_remote_parent_stat_take_ambiguous,
            .discard_stat = k_java_remote_parent_stat_discard_ambiguous,
        },
        {
            .name = "unknown claim was not ambiguous",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                },
            .status = k_java_remote_parent_status_ambiguous,
            .take_stat = k_java_remote_parent_stat_take_ambiguous,
            .discard_stat = k_java_remote_parent_stat_discard_ambiguous,
        },
    };

    for (u32 i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        for (u8 discard = 0; discard < 2; discard++) {
            seed_generation(&connection);
            stored_claim_key = stored_state_key;
            stored_claim = cases[i].claim;
            claim_present = 1;

            java_remote_parent_response_t response = stored_state.response;
            const enum java_remote_parent_status status =
                java_remote_parent_retrieve_for_connection(&response,
                                                           discard,
                                                           test_now_ns,
                                                           k_java_remote_parent_source_direct,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_generation,
                                                           test_socket_cookie);
            const enum java_remote_parent_stat expected_stat =
                discard ? cases[i].discard_stat : cases[i].take_stat;
            java_remote_parent_response_t expected = {0};
            java_remote_parent_init_response(&expected, cases[i].status, test_generation, 0);
            if (status != cases[i].status || memcmp(&response, &expected, sizeof(response)) != 0 ||
                !claim_present ||
                memcmp(&stored_claim, &cases[i].claim, sizeof(stored_claim)) != 0 ||
                !owner_present || !fallback_present || !state_present ||
                !generation_index_present || !connection_present || !cookie_connection_present ||
                terminal_present || stats[expected_stat] != 1 || unexpected_update ||
                unexpected_delete) {
                fail(cases[i].name);
            }
        }
    }
}

static void test_ambiguity_claim_collision_reports_committed_status(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const struct {
        const char *name;
        java_remote_parent_claim_t claim;
        enum java_remote_parent_status status;
        enum java_remote_parent_stat take_stat;
        enum java_remote_parent_stat discard_stat;
    } cases[] = {
        {
            .name = "publishing claim collision was not overload",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_publishing,
                },
            .status = k_java_remote_parent_status_overload,
            .take_stat = k_java_remote_parent_stat_take_overload,
            .discard_stat = k_java_remote_parent_stat_discard_overload,
        },
        {
            .name = "ambiguous claim collision was not ambiguous",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_ambiguous,
                },
            .status = k_java_remote_parent_status_ambiguous,
            .take_stat = k_java_remote_parent_stat_take_ambiguous,
            .discard_stat = k_java_remote_parent_stat_discard_ambiguous,
        },
        {
            .name = "consumed claim collision lost its committed status",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_consumed,
                },
            .status = k_java_remote_parent_status_already_consumed,
            .take_stat = k_java_remote_parent_stat_take_already_consumed,
            .discard_stat = k_java_remote_parent_stat_discard_already_consumed,
        },
        {
            .name = "malformed claim collision was not ambiguous",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_consumed,
                    .reserved = {[0] = 1},
                },
            .status = k_java_remote_parent_status_ambiguous,
            .take_stat = k_java_remote_parent_stat_take_ambiguous,
            .discard_stat = k_java_remote_parent_stat_discard_ambiguous,
        },
    };

    for (u32 i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        for (u8 discard = 0; discard < 2; discard++) {
            seed_generation(&connection);
            ambiguities[0].observed_monotime_ns = test_now_ns;
            claim_before_exact_update = cases[i].claim;
            inject_claim_before_exact_update = 1;

            java_remote_parent_response_t response = stored_state.response;
            const enum java_remote_parent_status status =
                java_remote_parent_retrieve_for_connection(&response,
                                                           discard,
                                                           test_now_ns,
                                                           k_java_remote_parent_source_direct,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_generation,
                                                           test_socket_cookie);
            const enum java_remote_parent_stat expected_stat =
                discard ? cases[i].discard_stat : cases[i].take_stat;
            java_remote_parent_response_t expected = {0};
            java_remote_parent_init_response(&expected, cases[i].status, test_generation, 0);
            if (status != cases[i].status || memcmp(&response, &expected, sizeof(response)) != 0 ||
                inject_claim_before_exact_update || !claim_present ||
                memcmp(&stored_claim, &cases[i].claim, sizeof(stored_claim)) != 0 ||
                !owner_present || !fallback_present || !state_present ||
                !generation_index_present || !connection_present || !cookie_connection_present ||
                terminal_present || !find_ambiguity(&stored_state_key) ||
                exact_claim_update_attempts != 1 || stats[expected_stat] != 1 ||
                unexpected_update || unexpected_delete) {
                fail(cases[i].name);
            }
        }
    }
}

static void test_exact_receive_detach_removes_only_unaliased_generation(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    stored_task_key = test_owner;
    stored_task = (java_remote_parent_task_t){
        .owner = test_owner,
        .generation = test_replacement_generation,
        .observed_monotime_ns = test_now_ns,
    };
    task_present = 1;
    handoffs[0] = (handoff_entry_t){
        .key = java_remote_parent_handoff_key(&test_owner, test_first_token),
        .value = stored_task,
        .present = 1,
    };
    stored_terminal = (java_remote_parent_terminal_t){
        .generation = test_replacement_generation,
        .observed_monotime_ns = test_now_ns,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_consumed,
    };
    const java_remote_parent_terminal_t terminal = stored_terminal;
    terminal_present = 1;

    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        owner_present || state_present || generation_index_present || connection_present ||
        cookie_connection_present || fallback_present || claim_present || detach_guard_present ||
        !terminal_present || memcmp(&stored_terminal, &terminal, sizeof(terminal)) != 0 ||
        !task_present || stored_task.generation != test_replacement_generation ||
        !handoffs[0].present || handoffs[0].value.generation != test_replacement_generation ||
        find_ambiguity_entry(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("exact receive detach widened beyond an unaliased generation");
    }
}

static void test_exact_receive_detach_preserves_aliases(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_exact_receive_aliases(2);
    stored_terminal = (java_remote_parent_terminal_t){
        .generation = test_replacement_generation,
        .observed_monotime_ns = test_now_ns,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_consumed,
    };
    terminal_present = 1;

    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        owner_present || fallback_present || !state_present || !generation_index_present ||
        connection_present || cookie_connection_present || stored_state.aliases != 2 ||
        !task_present || !handoffs[0].present || claim_present || detach_guard_present ||
        exact_claim_update_attempts != 1 || !terminal_present ||
        stored_terminal.generation != test_replacement_generation ||
        !find_ambiguity_entry(&stored_state_key) || find_ambiguity(&stored_state_key) ||
        unexpected_update || unexpected_delete) {
        fail("exact receive detach did not preserve task and handoff aliases");
    }
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        !state_present || !generation_index_present || connection_present ||
        cookie_connection_present || stored_state.aliases != 2 || !task_present ||
        !handoffs[0].present || claim_present || detach_guard_present ||
        !find_ambiguity_entry(&stored_state_key) || find_ambiguity(&stored_state_key) ||
        unexpected_update || unexpected_delete) {
        fail("repeated detach revived or deleted a detached aliased generation");
    }
}

static void test_exact_receive_detach_quarantines_last_alias_release_race(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    release_exact_receive_alias_after_fallback_delete = 1;

    const u8 detached = java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                                           test_process_incarnation,
                                                                           &connection,
                                                                           test_connection_netns,
                                                                           test_socket_cookie);
    if (detached || release_exact_receive_alias_after_fallback_delete || owner_present ||
        fallback_present || !state_present || stored_state.aliases || !generation_index_present ||
        connection_present || cookie_connection_present || task_present || !claim_present ||
        !same_key(&stored_claim_key, &stored_state_key, sizeof(stored_state_key)) ||
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_publishing ||
        stored_claim.process_incarnation != test_process_incarnation ||
        !exact_reset_fences_retained(&stored_state_key) || terminal_present ||
        !find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete ||
        exact_claim_update_attempts != 1) {
        fail("last-alias release race was not retained for userspace adoption");
    }
}

static void test_exact_receive_detach_rejects_post_guard_retain(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    attempt_exact_receive_retain_during_connection_delete = 1;

    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        attempt_exact_receive_retain_during_connection_delete ||
        exact_receive_retain_during_connection_delete_result != 0 || owner_present ||
        fallback_present || state_present || generation_index_present || connection_present ||
        cookie_connection_present || claim_present || detach_guard_present || terminal_present ||
        find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("post-guard retain escaped exact receive cleanup fencing");
    }
}

static void test_exact_receive_detach_rejects_retain_at_guard_acquisition(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    attempt_exact_receive_retain_after_guard = 1;

    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        attempt_exact_receive_retain_after_guard || exact_receive_retain_after_guard_result != 0 ||
        owner_present || fallback_present || state_present || generation_index_present ||
        connection_present || cookie_connection_present || claim_present || detach_guard_present ||
        terminal_present || find_ambiguity(&stored_state_key) || exact_claim_update_attempts != 1 ||
        unexpected_update || unexpected_delete) {
        fail("retain racing guard acquisition published an exact receive alias");
    }
}

static void test_exact_receive_detach_handles_pre_guard_retain_increment(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    // A retain may pass its precheck before a zero-alias detacher publishes
    // the guard, then expose its transient increment under that guard. The
    // detacher must preserve the still-direct generation and report failure.
    seed_generation(&connection);
    inject_transient_alias_after_guard = 1;
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        inject_transient_alias_after_guard || stored_state.aliases != 1 || !owner_present ||
        !fallback_present || !state_present || !generation_index_present || !connection_present ||
        !cookie_connection_present || claim_present || detach_guard_present || terminal_present ||
        find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("zero-alias detach corrupted a pre-guard retain increment");
    }
    java_remote_parent_release_generation_alias(&stored_state_key, test_observed_monotime_ns);
    if (stored_state.aliases || !owner_present || !fallback_present || !state_present ||
        !generation_index_present || !connection_present || !cookie_connection_present ||
        claim_present || detach_guard_present || terminal_present ||
        find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("failed pre-guard retain unwind corrupted the direct generation");
    }
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie)) {
        fail("preserved direct generation could not be detached on retry");
    }

    // If an aliased detacher removes the direct cursors before that same
    // retain unwinds, the cleanup-aware release must janitor the new zero.
    seed_generation(&connection);
    stored_state.aliases = 1;
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        owner_present || fallback_present || !state_present || !generation_index_present ||
        connection_present || cookie_connection_present || detach_guard_present) {
        fail("aliased detach did not preserve a pre-guard retain increment");
    }
    java_remote_parent_release_generation_alias(&stored_state_key, test_observed_monotime_ns);
    if (owner_present || fallback_present || !state_present || stored_state.aliases ||
        !generation_index_present || connection_present || cookie_connection_present ||
        !claim_present ||
        !same_key(&stored_claim_key, &stored_state_key, sizeof(stored_state_key)) ||
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_publishing ||
        stored_claim.process_incarnation != test_process_incarnation || detach_guard_present ||
        terminal_present || !find_ambiguity(&stored_state_key) ||
        exact_claim_update_attempts != 2 || unexpected_update || unexpected_delete) {
        fail("post-guard retain unwind was not fenced for userspace adoption");
    }
}

static void test_exact_receive_detach_fences_task_take_after_guard(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    inject_exact_receive_task_take_after_guard = 1;

    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        inject_exact_receive_task_take_after_guard || discard_injected_exact_receive_task_take ||
        exact_receive_task_take_status != k_java_remote_parent_status_overload ||
        exact_receive_task_take_response.status != k_java_remote_parent_status_overload ||
        java_remote_parent_le64_to_cpu(exact_receive_task_take_response.generation_le) !=
            test_generation ||
        owner_present || fallback_present || !state_present || !generation_index_present ||
        connection_present || cookie_connection_present || claim_present || detach_guard_present ||
        terminal_present || !task_present || find_ambiguity(&stored_state_key) ||
        exact_claim_update_attempts != 1 || stats[k_java_remote_parent_stat_take_overload] != 1 ||
        stats[k_java_remote_parent_stat_take_valid] != 0 ||
        stats[k_java_remote_parent_stat_handoff_valid] != 0 || unexpected_update ||
        unexpected_delete) {
        fail("task TAKE escaped the exact receive detach guard");
    }
}

static void test_exact_receive_detach_fences_task_discard_after_guard(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    discard_injected_exact_receive_task_take = 1;
    inject_exact_receive_task_take_after_guard = 1;

    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        inject_exact_receive_task_take_after_guard || discard_injected_exact_receive_task_take ||
        exact_receive_task_take_status != k_java_remote_parent_status_overload ||
        exact_receive_task_take_response.status != k_java_remote_parent_status_overload ||
        java_remote_parent_le64_to_cpu(exact_receive_task_take_response.generation_le) !=
            test_generation ||
        owner_present || fallback_present || !state_present || !generation_index_present ||
        connection_present || cookie_connection_present || claim_present || detach_guard_present ||
        terminal_present || !task_present || find_ambiguity(&stored_state_key) ||
        exact_claim_update_attempts != 1 ||
        stats[k_java_remote_parent_stat_discard_overload] != 1 ||
        stats[k_java_remote_parent_stat_discard_valid] != 0 ||
        stats[k_java_remote_parent_stat_take_overload] != 0 || unexpected_update ||
        unexpected_delete) {
        fail("task DISCARD escaped the exact receive detach guard");
    }
}

static void test_exact_receive_detach_preclaims_generation_before_guard(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    // Hide the newly published owner guard from the injected TAKE's first
    // precheck. The already-owned exact G claim must still reject that TAKE.
    hide_detach_guard_once_for_injected_take = 1;
    inject_exact_receive_task_take_after_guard = 1;

    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        inject_exact_receive_task_take_after_guard || hide_detach_guard_once_for_injected_take ||
        exact_receive_task_take_status != k_java_remote_parent_status_overload ||
        exact_receive_task_take_response.status != k_java_remote_parent_status_overload ||
        owner_present || fallback_present || !state_present || !generation_index_present ||
        connection_present || cookie_connection_present || claim_present || detach_guard_present ||
        terminal_present || !task_present || find_ambiguity(&stored_state_key) ||
        exact_claim_update_attempts != 1 || exact_claim_present_at_guard_acquisition != 1 ||
        stats[k_java_remote_parent_stat_take_overload] != 1 ||
        stats[k_java_remote_parent_stat_take_already_consumed] != 0 || unexpected_update ||
        unexpected_delete) {
        fail("RESET acquired the owner guard before its exact generation claim");
    }

    current_task = test_child;
    java_remote_parent_response_t response = {0};
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_valid ||
        response.status != k_java_remote_parent_status_valid ||
        java_remote_parent_le64_to_cpu(response.generation_le) != test_generation ||
        owner_present || fallback_present || !state_present || !generation_index_present ||
        connection_present || cookie_connection_present ||
        !exact_finish_fences_retained(&stored_state_key, k_java_remote_parent_lifecycle_consumed) ||
        !terminal_present || stored_terminal.generation != test_generation ||
        stored_terminal.lifecycle != k_java_remote_parent_lifecycle_consumed || !task_present ||
        exact_claim_update_attempts != 2 || stats[k_java_remote_parent_stat_take_valid] != 1 ||
        stats[k_java_remote_parent_stat_handoff_valid] != 1 ||
        stats[k_java_remote_parent_stat_take_already_consumed] != 0 || unexpected_update ||
        unexpected_delete) {
        fail("task TAKE could not retry after the preclaimed RESET completed");
    }
}

static void test_exact_receive_detach_fences_task_take_during_delete_retry(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    inject_exact_receive_task_take_after_guard = 1;
    owner_delete_failures = 1;
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        inject_exact_receive_task_take_after_guard ||
        exact_receive_task_take_status != k_java_remote_parent_status_overload ||
        exact_receive_task_take_response.status != k_java_remote_parent_status_overload ||
        java_remote_parent_le64_to_cpu(exact_receive_task_take_response.generation_le) !=
            test_generation ||
        owner_delete_failures || owner_present || fallback_present || !state_present ||
        !generation_index_present || connection_present || cookie_connection_present ||
        claim_present || detach_guard_present || terminal_present || !task_present ||
        find_ambiguity(&stored_state_key) || exact_claim_update_attempts != 1 ||
        stats[k_java_remote_parent_stat_take_overload] != 1 ||
        stats[k_java_remote_parent_stat_take_valid] != 0 ||
        stats[k_java_remote_parent_stat_handoff_valid] != 0 || unexpected_update ||
        unexpected_delete) {
        fail("guarded task TAKE escaped a transient owner-delete retry");
    }

    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    inject_exact_receive_task_take_after_guard = 1;
    fallback_delete_failures = 1;
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        inject_exact_receive_task_take_after_guard ||
        exact_receive_task_take_status != k_java_remote_parent_status_overload ||
        exact_receive_task_take_response.status != k_java_remote_parent_status_overload ||
        java_remote_parent_le64_to_cpu(exact_receive_task_take_response.generation_le) !=
            test_generation ||
        fallback_delete_failures || owner_present || fallback_present || !state_present ||
        !generation_index_present || connection_present || cookie_connection_present ||
        claim_present || detach_guard_present || terminal_present || !task_present ||
        find_ambiguity(&stored_state_key) || exact_claim_update_attempts != 1 ||
        stats[k_java_remote_parent_stat_take_overload] != 1 ||
        stats[k_java_remote_parent_stat_take_valid] != 0 ||
        stats[k_java_remote_parent_stat_handoff_valid] != 0 || unexpected_update ||
        unexpected_delete) {
        fail("guarded task TAKE escaped a transient fallback-delete retry");
    }
}

static void test_aliased_reset_guard_release_failure_retains_tail(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    detach_guard_delete_failures = 1;
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        detach_guard_delete_failures || owner_present || fallback_present || !state_present ||
        !generation_index_present || connection_present || cookie_connection_present ||
        !task_present || claim_present || !detach_guard_present ||
        stored_detach_guard.process_incarnation != test_generation ||
        stored_detach_guard.lifecycle != k_java_remote_parent_lifecycle_publishing ||
        !find_ambiguity_entry(&stored_state_key) || find_ambiguity(&stored_state_key) ||
        terminal_present || exact_claim_update_attempts != 1 || unexpected_update ||
        unexpected_delete) {
        fail("aliased RESET did not retain its zero-reservation/guard release tail");
    }
}

static void test_take_claim_revalidates_state_and_generation_index(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    java_remote_parent_response_t response = {0};

    seed_generation(&connection);
    remove_state_index_after_claim = 1;
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   0,
                                                   k_java_remote_parent_source_direct,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_missing ||
        remove_state_index_after_claim || state_present || generation_index_present ||
        !claim_present || stored_claim.lifecycle != k_java_remote_parent_lifecycle_consumed ||
        terminal_present || !owner_present || !fallback_present || !connection_present ||
        !cookie_connection_present || exact_claim_update_attempts != 1 ||
        !find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("late TAKE claim published a terminal after state/index removal");
    }
    memset(&response, 0, sizeof(response));
    if (java_remote_parent_retrieve(
            &response, 0, test_now_ns, k_java_remote_parent_source_direct) !=
            k_java_remote_parent_status_already_consumed ||
        response.status != k_java_remote_parent_status_already_consumed || !claim_present) {
        fail("late TAKE state/index loss rolled back its visible final claim");
    }

    seed_generation(&connection);
    memset(&response, 0, sizeof(response));
    replace_state_index_observation_after_claim = 1;
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   0,
                                                   k_java_remote_parent_source_direct,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_missing ||
        replace_state_index_observation_after_claim || !state_present ||
        stored_state.observed_monotime_ns != test_now_ns || !generation_index_present ||
        stored_generation_index.observed_monotime_ns != test_now_ns || !claim_present ||
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_consumed || terminal_present ||
        !owner_present || !fallback_present || !connection_present || !cookie_connection_present ||
        !find_ambiguity(&stored_state_key) || exact_claim_update_attempts != 1 ||
        unexpected_update || unexpected_delete) {
        fail("late TAKE claim adopted a same-key replacement observation");
    }
    memset(&response, 0, sizeof(response));
    if (java_remote_parent_retrieve(
            &response, 0, test_now_ns, k_java_remote_parent_source_direct) !=
            k_java_remote_parent_status_already_consumed ||
        response.status != k_java_remote_parent_status_already_consumed || !claim_present) {
        fail("late TAKE observation replacement rolled back its visible final claim");
    }

    seed_generation(&connection);
    memset(&response, 0, sizeof(response));
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   0,
                                                   k_java_remote_parent_source_direct,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_valid ||
        java_remote_parent_le64_to_cpu(response.generation_le) != test_generation ||
        owner_present || fallback_present || state_present || generation_index_present ||
        connection_present || cookie_connection_present || claim_present || !terminal_present ||
        stored_terminal.generation != test_generation ||
        stored_terminal.lifecycle != k_java_remote_parent_lifecycle_consumed ||
        exact_claim_update_attempts != 1 || unexpected_update || unexpected_delete) {
        fail("post-publication claim revalidation changed a valid TAKE");
    }
}

static void test_visible_final_claim_survives_post_claim_guard(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    for (u8 discard = 0; discard < 2; discard++) {
        seed_generation(&connection);
        inject_detach_guard_after_exact_claim = 1;
        java_remote_parent_response_t response = {0};
        if (java_remote_parent_retrieve_for_connection(&response,
                                                       discard,
                                                       test_now_ns,
                                                       k_java_remote_parent_source_direct,
                                                       &connection,
                                                       test_connection_netns,
                                                       test_generation,
                                                       test_socket_cookie) !=
                k_java_remote_parent_status_overload ||
            response.status != k_java_remote_parent_status_overload ||
            inject_detach_guard_after_exact_claim || !claim_present ||
            stored_claim.lifecycle != (discard ? k_java_remote_parent_lifecycle_discarded
                                               : k_java_remote_parent_lifecycle_consumed) ||
            !detach_guard_present || !find_ambiguity(&stored_state_key) || !owner_present ||
            !fallback_present || !state_present || !generation_index_present ||
            !connection_present || !cookie_connection_present || terminal_present ||
            unexpected_update || unexpected_delete) {
            fail("post-claim owner guard rolled back a visible final claim");
        }

        memset(&response, 0, sizeof(response));
        if (java_remote_parent_retrieve(
                &response, discard, test_now_ns, k_java_remote_parent_source_direct) !=
                k_java_remote_parent_status_already_consumed ||
            response.status != k_java_remote_parent_status_already_consumed || !claim_present ||
            !detach_guard_present || !find_ambiguity(&stored_state_key)) {
            fail("post-claim owner guard did not preserve deterministic retry status");
        }
    }
}

static void test_task_link_is_revalidated_after_claim(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    current_task = test_child;
    replace_task_after_exact_claim = 1;

    java_remote_parent_response_t response = stored_state.response;
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_ambiguous ||
        response.status != k_java_remote_parent_status_ambiguous ||
        replace_task_after_exact_claim || !task_present ||
        stored_task.generation != test_replacement_generation ||
        stored_task.observed_monotime_ns != test_now_ns ||
        stats[k_java_remote_parent_stat_take_valid] != 0 ||
        stats[k_java_remote_parent_stat_handoff_valid] != 0 || unexpected_update ||
        unexpected_delete) {
        fail("task-link replacement after claim returned the old remote parent");
    }

    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    current_task = test_child;
    inject_detach_guard_after_exact_claim = 1;
    replace_task_after_exact_claim = 1;
    response = stored_state.response;
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_ambiguous ||
        response.status != k_java_remote_parent_status_ambiguous ||
        inject_detach_guard_after_exact_claim || replace_task_after_exact_claim || !claim_present ||
        !detach_guard_present || !find_ambiguity(&stored_state_key) || !task_present ||
        stored_task.generation != test_replacement_generation ||
        stored_task.observed_monotime_ns != test_now_ns ||
        stats[k_java_remote_parent_stat_take_overload] != 0 ||
        stats[k_java_remote_parent_stat_take_ambiguous] != 1 ||
        stats[k_java_remote_parent_stat_take_valid] != 0 || unexpected_update ||
        unexpected_delete) {
        fail("post-claim task replacement did not outrank the owner guard");
    }

    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    current_task = test_child;
    arm_task_replacement_after_post_claim_check = 1;
    response = stored_state.response;
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_ambiguous ||
        response.status != k_java_remote_parent_status_ambiguous ||
        arm_task_replacement_after_post_claim_check || replace_task_on_next_state_lookup ||
        !task_present || stored_task.generation != test_replacement_generation ||
        stored_task.observed_monotime_ns != test_now_ns ||
        stats[k_java_remote_parent_stat_take_valid] != 0 ||
        stats[k_java_remote_parent_stat_handoff_valid] != 0 || unexpected_update ||
        unexpected_delete) {
        fail("late post-claim task replacement returned the old remote parent");
    }

    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    current_task = test_child;
    arm_task_replacement_and_state_loss_after_post_claim_check = 1;
    response = stored_state.response;
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_ambiguous ||
        response.status != k_java_remote_parent_status_ambiguous ||
        arm_task_replacement_and_state_loss_after_post_claim_check ||
        replace_task_and_drop_state_on_next_lookup || state_present || !claim_present ||
        !find_ambiguity(&stored_state_key) || !task_present ||
        stored_task.generation != test_replacement_generation ||
        stored_task.observed_monotime_ns != test_now_ns ||
        stats[k_java_remote_parent_stat_take_missing] != 0 ||
        stats[k_java_remote_parent_stat_take_ambiguous] != 1 ||
        stats[k_java_remote_parent_stat_take_valid] != 0 || unexpected_update ||
        unexpected_delete) {
        fail("late task replacement plus state loss returned a terminal old status");
    }

    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    current_task = test_child;
    ambiguities[0] = (ambiguity_entry_t){
        .key = stored_state_key,
        .observed_monotime_ns = test_now_ns,
        .present = 1,
    };
    stored_claim_key = stored_state_key;
    stored_claim = (java_remote_parent_claim_t){
        .observed_monotime_ns = test_now_ns,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_consumed,
    };
    claim_present = 1;
    replace_task_during_claim_lookup = 1;
    memset(&response, 0, sizeof(response));
    if (java_remote_parent_retrieve(&response, 0, test_now_ns, k_java_remote_parent_source_task) !=
            k_java_remote_parent_status_ambiguous ||
        response.status != k_java_remote_parent_status_ambiguous ||
        replace_task_during_claim_lookup || !claim_present || !task_present ||
        stored_task.generation != test_replacement_generation ||
        stored_task.observed_monotime_ns != test_now_ns ||
        stats[k_java_remote_parent_stat_take_already_consumed] != 0 ||
        stats[k_java_remote_parent_stat_take_valid] != 0 || unexpected_update ||
        unexpected_delete) {
        fail("task-link replacement during retained-claim lookup returned the old status");
    }

    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    current_task = test_child;
    ambiguities[0] = (ambiguity_entry_t){
        .key = stored_state_key,
        .observed_monotime_ns = test_now_ns,
        .present = 1,
    };
    inject_claim_before_exact_update = 1;
    claim_before_exact_update = (java_remote_parent_claim_t){
        .observed_monotime_ns = test_now_ns,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_consumed,
    };
    replace_task_during_claim_lookup = 1;
    memset(&response, 0, sizeof(response));
    if (java_remote_parent_retrieve(&response, 0, test_now_ns, k_java_remote_parent_source_task) !=
            k_java_remote_parent_status_ambiguous ||
        response.status != k_java_remote_parent_status_ambiguous ||
        inject_claim_before_exact_update || replace_task_during_claim_lookup || !claim_present ||
        !task_present || stored_task.generation != test_replacement_generation ||
        stats[k_java_remote_parent_stat_take_already_consumed] != 0 ||
        stats[k_java_remote_parent_stat_take_ambiguous] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("task rebind during a raced ambiguous claim returned the old status");
    }

    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    current_task = test_child;
    stored_detach_guard_key = java_remote_parent_state_key(&test_owner, 0);
    stored_detach_guard = (java_remote_parent_claim_t){
        .observed_monotime_ns = test_now_ns,
        .process_incarnation = test_generation,
        .lifecycle = k_java_remote_parent_lifecycle_publishing,
    };
    detach_guard_present = 1;
    replace_task_during_detach_guard_lookup = 1;
    response = stored_state.response;
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_ambiguous ||
        response.status != k_java_remote_parent_status_ambiguous ||
        replace_task_during_detach_guard_lookup || claim_present || !detach_guard_present ||
        !task_present || stored_task.generation != test_replacement_generation ||
        stored_task.observed_monotime_ns != test_now_ns ||
        stats[k_java_remote_parent_stat_take_overload] != 0 ||
        stats[k_java_remote_parent_stat_take_ambiguous] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("task rebind did not outrank a pre-claim owner guard");
    }

    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    current_task = test_child;
    inject_claim_before_exact_update = 1;
    claim_before_exact_update = (java_remote_parent_claim_t){
        .observed_monotime_ns = test_now_ns,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_consumed,
    };
    remove_claim_and_replace_task_during_claim_lookup = 1;
    response = stored_state.response;
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_ambiguous ||
        response.status != k_java_remote_parent_status_ambiguous ||
        inject_claim_before_exact_update || remove_claim_and_replace_task_during_claim_lookup ||
        claim_present || !task_present || stored_task.generation != test_replacement_generation ||
        stored_task.observed_monotime_ns != test_now_ns ||
        stats[k_java_remote_parent_stat_take_overload] != 0 ||
        stats[k_java_remote_parent_stat_take_ambiguous] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("task rebind did not outrank a disappeared collided claim");
    }
}

static void seed_exact_receive_ambiguity(void) {
    ambiguities[0] = (ambiguity_entry_t){
        .key = stored_state_key,
        .observed_monotime_ns = test_now_ns,
        .present = 1,
    };
}

static void test_exact_receive_detach_verifies_fallback_and_owner_deletes(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    seed_generation(&connection);
    fallback_delete_failures = 1;
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        owner_present || fallback_present || state_present || generation_index_present ||
        connection_present || cookie_connection_present || claim_present || detach_guard_present ||
        find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("transient fallback delete failure was not retried exactly");
    }

    seed_generation(&connection);
    fallback_delete_failures = 1;
    fallback_delete_absent_on_failure = 1;
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        owner_present || fallback_present || state_present || generation_index_present ||
        connection_present || cookie_connection_present || claim_present || detach_guard_present ||
        find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("fallback absence after a failed delete was not accepted by postcondition");
    }

    seed_generation(&connection);
    fallback_delete_failures = 2;
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        !owner_present || !fallback_present || !state_present || !generation_index_present ||
        !connection_present || !cookie_connection_present ||
        !exact_reset_fences_retained(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("persistent fallback delete failure was reported as complete");
    }

    seed_generation(&connection);
    owner_delete_failures = 2;
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        !owner_present || fallback_present || !state_present || !generation_index_present ||
        !connection_present || !cookie_connection_present ||
        !exact_reset_fences_retained(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("owner delete half-state was not failed closed");
    }
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        !owner_present || fallback_present || !state_present || !generation_index_present ||
        !connection_present || !cookie_connection_present ||
        !exact_reset_fences_retained(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("fallback half-state or its ambiguity marker was retried in-kernel");
    }
}

static void test_exact_receive_detach_verifies_connection_half_states(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    seed_generation(&connection);
    cookie_connection_delete_failures = 2;
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        owner_present || fallback_present || !state_present || !generation_index_present ||
        !connection_present || !cookie_connection_present ||
        !exact_reset_fences_retained(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("cookie delete failure touched the authoritative netns index");
    }

    seed_generation(&connection);
    owner_present = 0;
    fallback_present = 0;
    cookie_connection_present = 0;
    seed_exact_receive_ambiguity();
    const u64 ambiguity_observation = find_ambiguity(&stored_state_key)->observed_monotime_ns;
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        !state_present || !generation_index_present || !connection_present ||
        cookie_connection_present || claim_present || detach_guard_present ||
        !find_ambiguity(&stored_state_key) ||
        find_ambiguity(&stored_state_key)->observed_monotime_ns != ambiguity_observation ||
        unexpected_update || unexpected_delete) {
        fail("cookie-absent half-state erased an external ambiguity marker");
    }

    seed_generation(&connection);
    connection_delete_failures = 2;
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        owner_present || fallback_present || !state_present || !generation_index_present ||
        !connection_present || cookie_connection_present ||
        !exact_reset_fences_retained(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("netns delete failure did not retain the retryable half-state");
    }
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        owner_present || fallback_present || !state_present || !generation_index_present ||
        !connection_present || cookie_connection_present ||
        !exact_reset_fences_retained(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("netns half-state or its ambiguity marker was retried in-kernel");
    }
}

static void test_exact_receive_detach_preserves_replacements(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    seed_generation(&connection);
    replace_owner_after_delete = 1;
    replace_fallback_after_delete = 1;
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        !owner_present || stored_owner.generation != test_replacement_generation ||
        !fallback_present ||
        java_remote_parent_le64_to_cpu(stored_fallback.generation_le) !=
            test_replacement_generation ||
        state_present || generation_index_present || connection_present ||
        cookie_connection_present || claim_present || detach_guard_present ||
        find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("owner/fallback replacement was removed by an exact delete retry");
    }

    seed_generation(&connection);
    replace_cookie_connection_after_delete = 1;
    replace_connection_after_delete = 1;
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        owner_present || fallback_present || state_present || generation_index_present ||
        !connection_present || stored_connection.generation != test_replacement_generation ||
        !cookie_connection_present ||
        stored_cookie_connection.generation != test_replacement_generation || claim_present ||
        detach_guard_present || find_ambiguity(&stored_state_key) || unexpected_update ||
        unexpected_delete) {
        fail("physical replacement after exact deletion was not preserved");
    }

    seed_generation(&connection);
    replace_cookie_connection_before_delete = 1;
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        !owner_present || !fallback_present || !state_present || !generation_index_present ||
        !connection_present || !cookie_connection_present ||
        stored_cookie_connection.generation != test_replacement_generation || claim_present ||
        detach_guard_present || find_ambiguity(&stored_state_key) || unexpected_update ||
        unexpected_delete) {
        fail("nonmatching cookie replacement was deleted");
    }

    seed_generation(&connection);
    replace_connection_before_delete = 1;
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        !owner_present || !fallback_present || !state_present || !generation_index_present ||
        !connection_present || stored_connection.generation != test_replacement_generation ||
        !cookie_connection_present || claim_present || detach_guard_present ||
        find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("nonmatching netns replacement was deleted");
    }
}

static void test_exact_receive_detach_detects_reinserted_and_failed_artifacts(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    seed_generation(&connection);
    reinsert_exact_cookie_connection_after_delete = 1;
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        owner_present || fallback_present || !state_present || !generation_index_present ||
        !connection_present || !cookie_connection_present ||
        !exact_reset_fences_retained(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("reinserted exact cookie artifact escaped the postcondition");
    }

    seed_generation(&connection);
    reinsert_exact_connection_after_delete = 1;
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        owner_present || fallback_present || !state_present || !generation_index_present ||
        !connection_present || cookie_connection_present ||
        !exact_reset_fences_retained(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("reinserted exact netns artifact escaped the postcondition");
    }

    seed_generation(&connection);
    reinsert_exact_cookie_connection_after_netns_delete = 1;
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        owner_present || fallback_present || !state_present || !generation_index_present ||
        connection_present || !cookie_connection_present ||
        !exact_reset_fences_retained(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("late exact cookie reinsert escaped the final physical postcondition");
    }

    seed_generation(&connection);
    state_delete_failures = 2;
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        owner_present || fallback_present || !state_present || !generation_index_present ||
        connection_present || cookie_connection_present ||
        !exact_reset_fences_retained(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("state delete failure was reported as complete");
    }

    seed_generation(&connection);
    generation_index_delete_failures = 2;
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        owner_present || fallback_present || state_present || !generation_index_present ||
        connection_present || cookie_connection_present ||
        !exact_reset_fences_retained(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("generation-index delete failure was reported as complete");
    }
}

static void test_stale_exact_receive_detach_preserves_newer_generation(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const connection_info_t replacement = {.s_port = 2345, .d_port = 8443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    const java_remote_parent_response_t expected_replacement =
        seed_replacement_generation(&replacement);

    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        !owner_present || stored_owner.generation != test_replacement_generation ||
        !fallback_present ||
        memcmp(&stored_fallback, &expected_replacement, sizeof(expected_replacement)) != 0 ||
        !state_present || !generation_index_present || connection_present ||
        cookie_connection_present || !replacement_state_present ||
        !replacement_generation_index_present || !replacement_connection_present ||
        !replacement_cookie_connection_present || !task_present || handoffs[0].present ||
        claim_present || detach_guard_present || terminal_present || unexpected_update ||
        unexpected_delete) {
        fail("stale exact receive detach disturbed a newer owner generation");
    }

    seed_generation(&connection);
    seed_replacement_generation(&replacement);
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        !owner_present || !fallback_present || state_present || generation_index_present ||
        connection_present || cookie_connection_present || !replacement_state_present ||
        !replacement_generation_index_present || !replacement_connection_present ||
        !replacement_cookie_connection_present || claim_present || detach_guard_present ||
        find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("unaliased stale receive cleanup disturbed the replacement generation");
    }
}

static void assert_exact_receive_rejected_without_cleanup(const char *message) {
    if (!owner_present || !state_present || !generation_index_present || !connection_present ||
        !cookie_connection_present || !fallback_present || claim_present || detach_guard_present ||
        terminal_present || unexpected_update || unexpected_delete) {
        fail(message);
    }
}

static void test_exact_receive_detach_rejects_wrong_authority(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    connection_info_t wrong_connection = connection;
    wrong_connection.s_port++;

    seed_generation(&connection);
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation + 1,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie)) {
        fail("exact receive detach accepted a wrong process incarnation");
    }
    assert_exact_receive_rejected_without_cleanup("wrong incarnation mutated state");

    seed_generation(&connection);
    java_remote_parent_key_t wrong_owner = stored_state_key;
    wrong_owner.owner.tid++;
    if (java_remote_parent_detach_exact_receive_generation(&wrong_owner,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie)) {
        fail("exact receive detach accepted a wrong owner");
    }
    assert_exact_receive_rejected_without_cleanup("wrong owner mutated state");

    seed_generation(&connection);
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &wrong_connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns + 1,
                                                           test_socket_cookie) ||
        java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie + 1)) {
        fail("exact receive detach accepted a wrong socket authority");
    }
    assert_exact_receive_rejected_without_cleanup("wrong socket mutated state");

    seed_generation(&connection);
    stored_generation_index.observed_monotime_ns++;
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie)) {
        fail("exact receive detach accepted a wrong generation index");
    }
    assert_exact_receive_rejected_without_cleanup("wrong index mutated state");

    seed_generation(&connection);
    stored_state.response.generation_le =
        java_remote_parent_cpu_to_le64(test_replacement_generation);
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie)) {
        fail("exact receive detach accepted a wrong state generation");
    }
    assert_exact_receive_rejected_without_cleanup("wrong state mutated maps");
}

static void test_exact_receive_detach_rejects_claim_ambiguity_and_terminal(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    stored_claim_key = stored_state_key;
    stored_claim = (java_remote_parent_claim_t){
        .observed_monotime_ns = test_now_ns,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_consumed,
    };
    claim_present = 1;
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        !claim_present || stored_claim.lifecycle != k_java_remote_parent_lifecycle_consumed ||
        !owner_present || !state_present || !generation_index_present || !connection_present ||
        !cookie_connection_present || !fallback_present || unexpected_update || unexpected_delete) {
        fail("existing generation claim was overwritten or cleaned");
    }

    seed_generation(&connection);
    ambiguities[0] = (ambiguity_entry_t){
        .key = stored_state_key,
        .observed_monotime_ns = test_now_ns,
        .present = 1,
    };
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        !find_ambiguity(&stored_state_key)) {
        fail("ambiguous generation was accepted or its marker removed");
    }
    assert_exact_receive_rejected_without_cleanup("ambiguity mutated exact state");

    seed_generation(&connection);
    stored_terminal = (java_remote_parent_terminal_t){
        .generation = test_generation,
        .observed_monotime_ns = test_now_ns,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_consumed,
    };
    terminal_present = 1;
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        !terminal_present || stored_terminal.generation != test_generation || claim_present ||
        detach_guard_present || !owner_present || !state_present || !generation_index_present ||
        !connection_present || !cookie_connection_present || !fallback_present ||
        unexpected_update || unexpected_delete) {
        fail("matching terminal/state collision was mutated");
    }
}

static void test_exact_receive_detach_revalidates_after_claim(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    mutate_exact_receive_after_claim = 1;
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        mutate_exact_receive_after_claim || claim_present || detach_guard_present ||
        !owner_present || !state_present || !generation_index_present || !connection_present ||
        !cookie_connection_present ||
        stored_cookie_connection.socket_cookie != test_socket_cookie + 1 || !fallback_present ||
        terminal_present || unexpected_update || unexpected_delete) {
        fail("post-claim socket mutation escaped exact revalidation");
    }

    seed_generation(&connection);
    replace_detach_guard_after_claim = 1;
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        replace_detach_guard_after_claim || claim_present || !detach_guard_present ||
        stored_detach_guard.process_incarnation != test_replacement_generation || !owner_present ||
        !state_present || !generation_index_present || !connection_present ||
        !cookie_connection_present || !fallback_present || terminal_present ||
        find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("replacement owner guard authorized an old-generation detach");
    }

    seed_generation(&connection);
    replace_detach_guard_token_after_claim = 1;
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        replace_detach_guard_token_after_claim || claim_present || !detach_guard_present ||
        stored_detach_guard.process_incarnation != test_generation ||
        stored_detach_guard.observed_monotime_ns != test_now_ns + 1 ||
        stored_detach_guard.lifecycle != k_java_remote_parent_lifecycle_publishing ||
        !owner_present || !state_present || !generation_index_present || !connection_present ||
        !cookie_connection_present || !fallback_present || terminal_present ||
        !find_ambiguity_entry(&stored_state_key) || find_ambiguity(&stored_state_key) ||
        exact_claim_present_at_guard_acquisition != 1 || unexpected_update || unexpected_delete) {
        fail("same-generation foreign owner-guard token authorized RESET deletion");
    }
}

static void test_exact_receive_detach_claim_failures_are_fail_closed(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    exact_claim_update_failures = 1;
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        exact_claim_update_failures || exact_claim_update_attempts != 1 || !owner_present ||
        !fallback_present || !state_present || !generation_index_present || !connection_present ||
        !cookie_connection_present || !task_present || claim_present || detach_guard_present ||
        terminal_present || find_ambiguity(&stored_state_key) || unexpected_update ||
        unexpected_delete) {
        fail("exact receive detach mutated state after exact-claim insertion failure");
    }

    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    owner_delete_failures = 2;
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        owner_delete_failures || !owner_present || fallback_present || !state_present ||
        !generation_index_present || !connection_present || !cookie_connection_present ||
        !task_present || !exact_reset_fences_retained(&stored_state_key) || terminal_present ||
        exact_claim_update_attempts != 1 || unexpected_update || unexpected_delete) {
        fail("partial RESET did not retain its pre-reserved ambiguity fence and exact claim");
    }
    current_task = test_child;
    java_remote_parent_response_t response = {0};
    const enum java_remote_parent_status fenced_status =
        java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   0,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie);
    if (fenced_status != k_java_remote_parent_status_overload ||
        response.status != k_java_remote_parent_status_overload || !claim_present ||
        terminal_present || !state_present || !generation_index_present ||
        stats[k_java_remote_parent_stat_take_overload] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("failed RESET publishing claim did not overload a later task TAKE");
    }

    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    exact_claim_delete_failures = 1;
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        exact_claim_delete_failures || owner_present || fallback_present || !state_present ||
        !generation_index_present || connection_present || cookie_connection_present ||
        !task_present || !claim_present || !detach_guard_present ||
        !find_ambiguity_entry(&stored_state_key) || find_ambiguity(&stored_state_key) ||
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_publishing || terminal_present ||
        exact_claim_update_attempts != 1 || unexpected_update || unexpected_delete) {
        fail("aliased RESET did not retain its recoverable claim/guard release tail");
    }
}

static void test_exact_receive_zero_alias_claim_failures_are_fail_closed(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    seed_generation(&connection);
    exact_claim_update_failures = 1;
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        exact_claim_update_failures || exact_claim_update_attempts != 1 || !owner_present ||
        !fallback_present || !state_present || !generation_index_present || !connection_present ||
        !cookie_connection_present || claim_present || detach_guard_present || terminal_present ||
        find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("zero-alias RESET mutated state after exact-claim insertion failure");
    }

    seed_generation(&connection);
    owner_delete_failures = 2;
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        owner_delete_failures || !owner_present || fallback_present || !state_present ||
        !generation_index_present || !connection_present || !cookie_connection_present ||
        !exact_reset_fences_retained(&stored_state_key) || terminal_present ||
        exact_claim_update_attempts != 1 || unexpected_update || unexpected_delete) {
        fail("partial zero-alias RESET did not retain its exact adoption fences");
    }

    seed_generation(&connection);
    exact_claim_delete_failures = 1;
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        exact_claim_delete_failures || owner_present || fallback_present || state_present ||
        generation_index_present || connection_present || cookie_connection_present ||
        !claim_present || !detach_guard_present || find_ambiguity_entry(&stored_state_key) ||
        terminal_present || stored_claim.lifecycle != k_java_remote_parent_lifecycle_publishing ||
        exact_claim_update_attempts != 1 || unexpected_update || unexpected_delete) {
        fail("zero-alias RESET did not retain its recoverable claim/guard release tail");
    }
}

static void seed_completed_exact_receive_take(const connection_info_t *connection) {
    seed_generation(connection);
    owner_present = 0;
    fallback_present = 0;
    state_present = 0;
    generation_index_present = 0;
    connection_present = 0;
    cookie_connection_present = 0;
    ambiguities[0].present = 0;
    stored_terminal = (java_remote_parent_terminal_t){
        .generation = test_generation,
        .observed_monotime_ns = test_observed_monotime_ns,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_consumed,
    };
    terminal_present = 1;
}

static u8 exact_receive_completed_by_take(const connection_info_t *connection) {
    return java_remote_parent_exact_receive_completed_by_take(&stored_state_key,
                                                              test_process_incarnation,
                                                              test_observed_monotime_ns,
                                                              connection,
                                                              test_connection_netns,
                                                              stored_connection.netns_cookie,
                                                              test_socket_cookie);
}

static void test_exact_receive_take_completion_requires_strict_postconditions(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    seed_completed_exact_receive_take(&connection);
    if (!exact_receive_completed_by_take(&connection)) {
        fail("fully completed task TAKE did not satisfy the exact postcondition");
    }

    terminal_present = 0;
    if (exact_receive_completed_by_take(&connection)) {
        fail("task TAKE completion did not require an exact terminal");
    }
    terminal_present = 1;

    stored_terminal.generation = test_replacement_generation;
    if (exact_receive_completed_by_take(&connection)) {
        fail("task TAKE completion adopted a different terminal generation");
    }
    stored_terminal.generation = test_generation;

    stored_terminal.process_incarnation++;
    if (exact_receive_completed_by_take(&connection)) {
        fail("task TAKE completion adopted a different process incarnation");
    }
    stored_terminal.process_incarnation = test_process_incarnation;

    stored_terminal.observed_monotime_ns++;
    if (exact_receive_completed_by_take(&connection)) {
        fail("task TAKE completion adopted a different observation");
    }
    stored_terminal.observed_monotime_ns = test_observed_monotime_ns;

    stored_terminal.lifecycle = k_java_remote_parent_lifecycle_active;
    if (exact_receive_completed_by_take(&connection)) {
        fail("task TAKE completion accepted a nonterminal lifecycle");
    }
    stored_terminal.lifecycle = k_java_remote_parent_lifecycle_consumed;

    stored_terminal.reserved[0] = 1;
    if (exact_receive_completed_by_take(&connection)) {
        fail("task TAKE completion accepted nonzero terminal reserved data");
    }
    stored_terminal.reserved[0] = 0;

    state_present = 1;
    if (exact_receive_completed_by_take(&connection)) {
        fail("task TAKE completion ignored an exact state artifact");
    }
    state_present = 0;

    generation_index_present = 1;
    if (exact_receive_completed_by_take(&connection)) {
        fail("task TAKE completion ignored an exact generation index");
    }
    generation_index_present = 0;

    owner_present = 1;
    if (exact_receive_completed_by_take(&connection)) {
        fail("task TAKE completion ignored an exact owner index");
    }
    stored_owner.generation = test_replacement_generation;
    if (!exact_receive_completed_by_take(&connection)) {
        fail("task TAKE completion rejected a different-generation owner replacement");
    }
    owner_present = 0;

    fallback_present = 1;
    if (exact_receive_completed_by_take(&connection)) {
        fail("task TAKE completion ignored an exact fallback index");
    }
    stored_fallback.generation_le = java_remote_parent_cpu_to_le64(test_replacement_generation);
    if (!exact_receive_completed_by_take(&connection)) {
        fail("task TAKE completion rejected a different-generation fallback replacement");
    }
    fallback_present = 0;

    stored_claim_key = stored_state_key;
    stored_claim = (java_remote_parent_claim_t){
        .observed_monotime_ns = test_now_ns,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_publishing,
    };
    claim_present = 1;
    if (exact_receive_completed_by_take(&connection)) {
        fail("task TAKE completion accepted an in-flight exact claim");
    }
    claim_present = 0;

    seed_exact_receive_ambiguity();
    if (exact_receive_completed_by_take(&connection)) {
        fail("task TAKE completion accepted an exact ambiguity marker");
    }
    ambiguities[0].present = 0;

    stored_connection.socket_cookie = test_replacement_socket_cookie;
    connection_present = 1;
    if (exact_receive_completed_by_take(&connection)) {
        fail("task TAKE completion ignored a same-generation netns artifact");
    }
    stored_connection.generation = test_replacement_generation;
    if (!exact_receive_completed_by_take(&connection)) {
        fail("task TAKE completion rejected a different-generation netns replacement");
    }
    connection_present = 0;

    stored_cookie_connection.socket_cookie = test_replacement_socket_cookie;
    cookie_connection_present = 1;
    if (exact_receive_completed_by_take(&connection)) {
        fail("task TAKE completion ignored a same-generation cookie artifact");
    }
    stored_cookie_connection.generation = test_replacement_generation;
    if (!exact_receive_completed_by_take(&connection)) {
        fail("task TAKE completion rejected a different-generation cookie replacement");
    }
}

static void test_exact_receive_detach_preserves_post_guard_successors(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    inject_claim_after_detach_guard_delete = 1;
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        inject_claim_after_detach_guard_delete || owner_present || fallback_present ||
        !state_present || !generation_index_present || connection_present ||
        cookie_connection_present || !task_present || !claim_present || detach_guard_present ||
        terminal_present || find_ambiguity(&stored_state_key) || unexpected_update ||
        unexpected_delete) {
        fail("aliased RESET disturbed a later exact claim after final guard release");
    }

    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    inject_ambiguity_after_detach_guard_delete = 1;
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        inject_ambiguity_after_detach_guard_delete || owner_present || fallback_present ||
        !state_present || !generation_index_present || connection_present ||
        cookie_connection_present || !task_present || claim_present || detach_guard_present ||
        terminal_present || !find_ambiguity(&stored_state_key) || unexpected_update ||
        unexpected_delete) {
        fail("aliased RESET disturbed a later ambiguity after final guard release");
    }

    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    inject_connection_after_detach_guard_delete = 1;
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        inject_connection_after_detach_guard_delete || owner_present || fallback_present ||
        !state_present || !generation_index_present || !connection_present ||
        cookie_connection_present || !task_present || claim_present || detach_guard_present ||
        terminal_present || find_ambiguity(&stored_state_key) || unexpected_update ||
        unexpected_delete) {
        fail("aliased RESET disturbed a later physical artifact after final guard release");
    }

    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    inject_foreign_guard_after_detach_guard_delete = 1;
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        inject_foreign_guard_after_detach_guard_delete || owner_present || fallback_present ||
        !state_present || !generation_index_present || connection_present ||
        cookie_connection_present || !task_present || claim_present || !detach_guard_present ||
        stored_detach_guard.process_incarnation != test_replacement_generation ||
        stored_detach_guard.lifecycle != k_java_remote_parent_lifecycle_publishing ||
        terminal_present || !find_ambiguity_entry(&stored_state_key) ||
        find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("aliased RESET disturbed a later owner guard after final guard release");
    }

    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    complete_take_after_detach_guard_delete = 1;
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        complete_take_after_detach_guard_delete || owner_present || fallback_present ||
        state_present || generation_index_present || connection_present ||
        cookie_connection_present || claim_present || detach_guard_present || !terminal_present ||
        stored_terminal.generation != test_generation ||
        stored_terminal.observed_monotime_ns != test_observed_monotime_ns ||
        stored_terminal.lifecycle != k_java_remote_parent_lifecycle_consumed ||
        find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("fully completed post-guard task TAKE was not accepted");
    }
}

static void test_zero_alias_reset_final_guard_release_preserves_successor(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    seed_generation(&connection);
    seed_exact_receive_aliases(0);
    publish_successor_after_detach_guard_delete = 1;
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie)) {
        fail("zero-alias RESET rejected success after its final guard release");
    }

    const ambiguity_entry_t *successor_reservation = find_ambiguity_entry(&replacement_state_key);
    if (publish_successor_after_detach_guard_delete || state_present || generation_index_present ||
        connection_present || cookie_connection_present || !owner_present ||
        stored_owner.generation != test_replacement_generation || !fallback_present ||
        java_remote_parent_le64_to_cpu(stored_fallback.generation_le) !=
            test_replacement_generation ||
        !replacement_state_present || !replacement_generation_index_present ||
        !replacement_connection_present || !replacement_cookie_connection_present ||
        !successor_reservation || successor_reservation->observed_monotime_ns || claim_present ||
        find_ambiguity_entry(&stored_state_key) || detach_guard_present || terminal_present ||
        unexpected_update || unexpected_delete) {
        fail("zero-alias RESET disturbed a successor after final guard release");
    }
}

static void test_aliased_reset_final_guard_release_preserves_successor(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    publish_successor_after_detach_guard_delete = 1;
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie)) {
        fail("aliased RESET rejected success after its final guard release");
    }

    const ambiguity_entry_t *old_reservation = find_ambiguity_entry(&stored_state_key);
    const ambiguity_entry_t *successor_reservation = find_ambiguity_entry(&replacement_state_key);
    if (publish_successor_after_detach_guard_delete || !state_present ||
        !generation_index_present || connection_present || cookie_connection_present ||
        !task_present || !owner_present || stored_owner.generation != test_replacement_generation ||
        !fallback_present ||
        java_remote_parent_le64_to_cpu(stored_fallback.generation_le) !=
            test_replacement_generation ||
        !replacement_state_present || !replacement_generation_index_present ||
        !replacement_connection_present || !replacement_cookie_connection_present ||
        !old_reservation || old_reservation->observed_monotime_ns || !successor_reservation ||
        successor_reservation->observed_monotime_ns || claim_present || detach_guard_present ||
        terminal_present || unexpected_update || unexpected_delete) {
        fail("aliased RESET disturbed a successor after final guard release");
    }
}

static void test_exact_receive_connection_delete_rechecks_late_cookie(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    stored_detach_guard_key = java_remote_parent_detach_guard_key(&test_owner);
    stored_detach_guard = (java_remote_parent_claim_t){
        .observed_monotime_ns = test_now_ns,
        .process_incarnation = test_generation,
        .lifecycle = k_java_remote_parent_lifecycle_publishing,
    };
    detach_guard_present = 1;
    stored_claim_key = stored_state_key;
    stored_claim = (java_remote_parent_claim_t){
        .observed_monotime_ns = test_now_ns,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_publishing,
    };
    claim_present = 1;
    const java_remote_parent_receive_detach_scratch_t reset = {
        .guard_key = stored_detach_guard_key,
        .guard_claim = stored_detach_guard,
        .generation_claim = stored_claim,
    };
    replace_netns_and_reinsert_exact_cookie_after_delete = 1;

    if (java_remote_parent_delete_exact_receive_connections(
            &stored_state_key, &connection, test_connection_netns, test_socket_cookie, &reset) ||
        replace_netns_and_reinsert_exact_cookie_after_delete || !connection_present ||
        stored_connection.generation != test_replacement_generation ||
        stored_connection.socket_cookie != test_replacement_socket_cookie ||
        !cookie_connection_present || stored_cookie_connection.generation != test_generation ||
        !detach_guard_present || unexpected_update || unexpected_delete) {
        fail("nonmatching netns replacement bypassed the final exact-cookie check");
    }
}

static java_remote_parent_resolution_t finish_resolution(void) {
    return (java_remote_parent_resolution_t){
        .key = stored_state_key,
        .indexed =
            {
                .generation = test_generation,
                .process_incarnation = test_process_incarnation,
                .lifecycle = k_java_remote_parent_lifecycle_active,
            },
        .observed_monotime_ns = test_observed_monotime_ns,
        .found = 1,
    };
}

static void seed_finish_claim(enum java_remote_parent_lifecycle lifecycle) {
    stored_claim_key = stored_state_key;
    stored_claim = (java_remote_parent_claim_t){
        .observed_monotime_ns = test_now_ns,
        .process_incarnation = test_process_incarnation,
        .lifecycle = lifecycle,
    };
    claim_present = 1;
}

static void finish_seeded_generation(enum java_remote_parent_lifecycle lifecycle) {
    const java_remote_parent_resolution_t resolution = finish_resolution();
    const java_remote_parent_claim_t owned_claim = stored_claim;
    java_remote_parent_finish_generation(
        &resolution, lifecycle, test_observed_monotime_ns, &owned_claim);
}

static int exact_finish_terminal_present(enum java_remote_parent_lifecycle lifecycle) {
    return terminal_present && stored_terminal.generation == test_generation &&
           stored_terminal.observed_monotime_ns == test_observed_monotime_ns &&
           stored_terminal.process_incarnation == test_process_incarnation &&
           stored_terminal.lifecycle == lifecycle && !stored_terminal.reserved[0] &&
           !stored_terminal.reserved[1] && !stored_terminal.reserved[2];
}

static int finish_generation_artifacts_present(void) {
    return owner_present && fallback_present && state_present && generation_index_present &&
           connection_present && cookie_connection_present;
}

static int finish_generation_artifacts_absent(void) {
    return !owner_present && !fallback_present && !state_present && !generation_index_present &&
           !connection_present && !cookie_connection_present;
}

static void test_finish_guard_and_terminal_failures_are_fenced(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    seed_generation(&connection);
    seed_finish_claim(k_java_remote_parent_lifecycle_consumed);
    stored_detach_guard_key = java_remote_parent_detach_guard_key(&test_owner);
    stored_detach_guard = (java_remote_parent_claim_t){
        .observed_monotime_ns = test_now_ns + 1,
        .process_incarnation = test_replacement_generation,
        .lifecycle = k_java_remote_parent_lifecycle_publishing,
    };
    detach_guard_present = 1;
    finish_seeded_generation(k_java_remote_parent_lifecycle_consumed);
    if (!finish_generation_artifacts_present() || terminal_present || !claim_present ||
        !find_ambiguity(&stored_state_key) || !detach_guard_present ||
        stored_detach_guard.process_incarnation != test_replacement_generation ||
        unexpected_update || unexpected_delete) {
        fail("finish guard-acquisition failure was not fenced");
    }

    seed_generation(&connection);
    seed_finish_claim(k_java_remote_parent_lifecycle_consumed);
    terminal_update_failures = 1;
    finish_seeded_generation(k_java_remote_parent_lifecycle_consumed);
    if (terminal_update_failures || !finish_generation_artifacts_present() || terminal_present ||
        !exact_finish_fences_retained(&stored_state_key, k_java_remote_parent_lifecycle_consumed) ||
        unexpected_update || unexpected_delete) {
        fail("finish terminal-update failure was not fenced");
    }

    seed_generation(&connection);
    seed_finish_claim(k_java_remote_parent_lifecycle_consumed);
    replace_terminal_after_update = 1;
    finish_seeded_generation(k_java_remote_parent_lifecycle_consumed);
    if (replace_terminal_after_update || !finish_generation_artifacts_present() ||
        !terminal_present || !stored_terminal.reserved[0] ||
        !exact_finish_fences_retained(&stored_state_key, k_java_remote_parent_lifecycle_consumed) ||
        unexpected_update || unexpected_delete) {
        fail("finish accepted a malformed replacement terminal");
    }
}

static void test_finish_physical_failures_are_fenced(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    seed_generation(&connection);
    seed_finish_claim(k_java_remote_parent_lifecycle_consumed);
    cookie_connection_delete_failures = 1;
    finish_seeded_generation(k_java_remote_parent_lifecycle_consumed);
    if (cookie_connection_delete_failures || !finish_generation_artifacts_present() ||
        !exact_finish_terminal_present(k_java_remote_parent_lifecycle_consumed) ||
        !exact_finish_fences_retained(&stored_state_key, k_java_remote_parent_lifecycle_consumed) ||
        unexpected_update || unexpected_delete) {
        fail("finish cookie-index delete failure was not fenced");
    }

    seed_generation(&connection);
    seed_finish_claim(k_java_remote_parent_lifecycle_consumed);
    connection_delete_failures = 1;
    finish_seeded_generation(k_java_remote_parent_lifecycle_consumed);
    if (connection_delete_failures || !owner_present || !fallback_present || !state_present ||
        !generation_index_present || !connection_present || cookie_connection_present ||
        !exact_finish_terminal_present(k_java_remote_parent_lifecycle_consumed) ||
        !exact_finish_fences_retained(&stored_state_key, k_java_remote_parent_lifecycle_consumed) ||
        unexpected_update || unexpected_delete) {
        fail("finish netns-index delete failure was not fenced");
    }
}

static void test_finish_logical_failures_are_fenced(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    seed_generation(&connection);
    seed_finish_claim(k_java_remote_parent_lifecycle_consumed);
    state_delete_failures = 1;
    finish_seeded_generation(k_java_remote_parent_lifecycle_consumed);
    if (state_delete_failures || !owner_present || !fallback_present || !state_present ||
        !generation_index_present || connection_present || cookie_connection_present ||
        !exact_finish_terminal_present(k_java_remote_parent_lifecycle_consumed) ||
        !exact_finish_fences_retained(&stored_state_key, k_java_remote_parent_lifecycle_consumed) ||
        unexpected_update || unexpected_delete) {
        fail("finish state delete failure was not fenced");
    }

    seed_generation(&connection);
    seed_finish_claim(k_java_remote_parent_lifecycle_consumed);
    fallback_delete_failures = 1;
    finish_seeded_generation(k_java_remote_parent_lifecycle_consumed);
    if (fallback_delete_failures || !owner_present || !fallback_present || state_present ||
        !generation_index_present || connection_present || cookie_connection_present ||
        !exact_finish_terminal_present(k_java_remote_parent_lifecycle_consumed) ||
        !exact_finish_fences_retained(&stored_state_key, k_java_remote_parent_lifecycle_consumed) ||
        unexpected_update || unexpected_delete) {
        fail("finish fallback delete failure was not fenced");
    }

    seed_generation(&connection);
    seed_finish_claim(k_java_remote_parent_lifecycle_consumed);
    generation_index_delete_failures = 1;
    finish_seeded_generation(k_java_remote_parent_lifecycle_consumed);
    if (generation_index_delete_failures || !owner_present || fallback_present || state_present ||
        !generation_index_present || connection_present || cookie_connection_present ||
        !exact_finish_terminal_present(k_java_remote_parent_lifecycle_consumed) ||
        !exact_finish_fences_retained(&stored_state_key, k_java_remote_parent_lifecycle_consumed) ||
        unexpected_update || unexpected_delete) {
        fail("finish generation-index delete failure was not fenced");
    }

    seed_generation(&connection);
    seed_finish_claim(k_java_remote_parent_lifecycle_consumed);
    owner_delete_failures = 1;
    finish_seeded_generation(k_java_remote_parent_lifecycle_consumed);
    if (owner_delete_failures || !owner_present || fallback_present || state_present ||
        generation_index_present || connection_present || cookie_connection_present ||
        !exact_finish_terminal_present(k_java_remote_parent_lifecycle_consumed) ||
        !exact_finish_fences_retained(&stored_state_key, k_java_remote_parent_lifecycle_consumed) ||
        unexpected_update || unexpected_delete) {
        fail("finish owner-index delete failure was not fenced");
    }
}

static void test_finish_release_failures_are_fenced(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    seed_generation(&connection);
    seed_finish_claim(k_java_remote_parent_lifecycle_consumed);
    ambiguity_delete_failures = 1;
    finish_seeded_generation(k_java_remote_parent_lifecycle_consumed);
    if (ambiguity_delete_failures || !finish_generation_artifacts_absent() ||
        !exact_finish_terminal_present(k_java_remote_parent_lifecycle_consumed) ||
        !exact_finish_fences_retained(&stored_state_key, k_java_remote_parent_lifecycle_consumed) ||
        unexpected_update || unexpected_delete) {
        fail("finish ambiguity-release failure was not fenced");
    }

    seed_generation(&connection);
    seed_finish_claim(k_java_remote_parent_lifecycle_consumed);
    ambiguity_delete_failures = 1;
    replace_ambiguity_after_failed_delete = 1;
    finish_seeded_generation(k_java_remote_parent_lifecycle_consumed);
    if (ambiguity_delete_failures || replace_ambiguity_after_failed_delete ||
        !finish_generation_artifacts_absent() ||
        !exact_finish_terminal_present(k_java_remote_parent_lifecycle_consumed) || !claim_present ||
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_consumed ||
        !detach_guard_present || !find_ambiguity_entry(&stored_state_key) ||
        find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("finish promoted a successor reservation after failed marker deletion");
    }

    seed_generation(&connection);
    seed_finish_claim(k_java_remote_parent_lifecycle_consumed);
    exact_claim_delete_failures = 1;
    finish_seeded_generation(k_java_remote_parent_lifecycle_consumed);
    if (exact_claim_delete_failures || !finish_generation_artifacts_absent() ||
        !exact_finish_terminal_present(k_java_remote_parent_lifecycle_consumed) ||
        !exact_finish_claim_guard_tail(&stored_state_key,
                                       k_java_remote_parent_lifecycle_consumed) ||
        unexpected_update || unexpected_delete) {
        fail("finish claim-release failure was not fenced");
    }
    java_remote_parent_response_t response = {0};
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_direct,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_already_consumed ||
        response.status != k_java_remote_parent_status_already_consumed ||
        java_remote_parent_retrieve_for_connection(&response,
                                                   1,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_direct,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_already_consumed ||
        response.status != k_java_remote_parent_status_already_consumed ||
        !finish_generation_artifacts_absent() ||
        !exact_finish_terminal_present(k_java_remote_parent_lifecycle_consumed) ||
        !exact_finish_claim_guard_tail(&stored_state_key,
                                       k_java_remote_parent_lifecycle_consumed) ||
        stats[k_java_remote_parent_stat_take_already_consumed] != 1 ||
        stats[k_java_remote_parent_stat_discard_already_consumed] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("retained direct finish claim did not preserve repeat status");
    }

    stored_terminal.observed_monotime_ns = 0;
    response = stored_state.response;
    const enum java_remote_parent_status malformed_terminal_status =
        java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_direct,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie);
    java_remote_parent_response_t expected_missing = {0};
    java_remote_parent_init_response(
        &expected_missing, k_java_remote_parent_status_missing, test_generation, 0);
    if (malformed_terminal_status != k_java_remote_parent_status_missing ||
        memcmp(&response, &expected_missing, sizeof(response)) != 0 ||
        stats[k_java_remote_parent_stat_take_missing] != 1 ||
        stats[k_java_remote_parent_stat_take_already_consumed] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("zero-observation terminal authorized a retained claim outcome");
    }
    stored_terminal.observed_monotime_ns = test_observed_monotime_ns;
    if (!exact_finish_claim_guard_tail(&stored_state_key,
                                       k_java_remote_parent_lifecycle_consumed)) {
        fail("terminal metadata validation disturbed retained finish fences");
    }

    seed_generation(&connection);
    seed_finish_claim(k_java_remote_parent_lifecycle_consumed);
    detach_guard_delete_failures = 1;
    finish_seeded_generation(k_java_remote_parent_lifecycle_consumed);
    if (detach_guard_delete_failures || !finish_generation_artifacts_absent() ||
        !exact_finish_terminal_present(k_java_remote_parent_lifecycle_consumed) || claim_present ||
        find_ambiguity_entry(&stored_state_key) || !detach_guard_present ||
        stored_detach_guard.process_incarnation != test_generation || unexpected_update ||
        unexpected_delete) {
        fail("finish owner-guard release failure was not fenced");
    }

    seed_generation(&connection);
    seed_finish_claim(k_java_remote_parent_lifecycle_consumed);
    inject_claim_after_detach_guard_delete = 1;
    finish_seeded_generation(k_java_remote_parent_lifecycle_consumed);
    if (inject_claim_after_detach_guard_delete || !finish_generation_artifacts_absent() ||
        !exact_finish_terminal_present(k_java_remote_parent_lifecycle_consumed) || !claim_present ||
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_publishing ||
        find_ambiguity_entry(&stored_state_key) || detach_guard_present || unexpected_update ||
        unexpected_delete) {
        fail("finish disturbed a later exact claim after final guard release");
    }

    seed_generation(&connection);
    seed_finish_claim(k_java_remote_parent_lifecycle_consumed);
    inject_ambiguity_after_detach_guard_delete = 1;
    finish_seeded_generation(k_java_remote_parent_lifecycle_consumed);
    if (inject_ambiguity_after_detach_guard_delete || !finish_generation_artifacts_absent() ||
        !exact_finish_terminal_present(k_java_remote_parent_lifecycle_consumed) || claim_present ||
        !find_ambiguity(&stored_state_key) || detach_guard_present || unexpected_update ||
        unexpected_delete) {
        fail("finish disturbed a later ambiguity marker after final guard release");
    }
}

static void test_finish_final_guard_release_preserves_successor(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    seed_generation(&connection);
    seed_finish_claim(k_java_remote_parent_lifecycle_consumed);
    publish_successor_after_detach_guard_delete = 1;
    finish_seeded_generation(k_java_remote_parent_lifecycle_consumed);

    const ambiguity_entry_t *successor_reservation = find_ambiguity_entry(&replacement_state_key);
    if (publish_successor_after_detach_guard_delete || state_present || generation_index_present ||
        connection_present || cookie_connection_present || !owner_present ||
        stored_owner.generation != test_replacement_generation || !fallback_present ||
        java_remote_parent_le64_to_cpu(stored_fallback.generation_le) !=
            test_replacement_generation ||
        !replacement_state_present || !replacement_generation_index_present ||
        !replacement_connection_present || !replacement_cookie_connection_present ||
        !successor_reservation || successor_reservation->observed_monotime_ns || claim_present ||
        find_ambiguity_entry(&stored_state_key) || detach_guard_present ||
        !exact_finish_terminal_present(k_java_remote_parent_lifecycle_consumed) ||
        unexpected_update || unexpected_delete) {
        fail("final finish guard release disturbed a coherent successor generation");
    }
}

static void test_live_task_finish_claim_release_preserves_repeat_status(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    seed_finish_claim(k_java_remote_parent_lifecycle_consumed);
    exact_claim_delete_failures = 1;
    finish_seeded_generation(k_java_remote_parent_lifecycle_consumed);
    if (exact_claim_delete_failures || !finish_generation_artifacts_absent() || !task_present ||
        !exact_finish_terminal_present(k_java_remote_parent_lifecycle_consumed) ||
        !exact_finish_claim_guard_tail(&stored_state_key,
                                       k_java_remote_parent_lifecycle_consumed) ||
        unexpected_update || unexpected_delete) {
        fail("live task finish claim-release failure was not fenced");
    }

    current_task = test_child;
    java_remote_parent_response_t response = {0};
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_already_consumed ||
        response.status != k_java_remote_parent_status_already_consumed ||
        java_remote_parent_le64_to_cpu(response.generation_le) != test_generation ||
        java_remote_parent_retrieve_for_connection(&response,
                                                   1,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_already_consumed ||
        response.status != k_java_remote_parent_status_already_consumed || !task_present ||
        !exact_finish_claim_guard_tail(&stored_state_key,
                                       k_java_remote_parent_lifecycle_consumed) ||
        stats[k_java_remote_parent_stat_take_already_consumed] != 1 ||
        stats[k_java_remote_parent_stat_discard_already_consumed] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("live task retry lost the retained finish outcome");
    }

    const java_remote_parent_response_t stale_response = stored_state.response;
    if (!task_retrieval_rejects_authority(&stale_response,
                                          &connection,
                                          test_connection_netns,
                                          test_replacement_generation,
                                          test_socket_cookie,
                                          test_generation) ||
        !task_present) {
        fail("retained task terminal accepted a mismatched generation");
    }

    stored_task.observed_monotime_ns++;
    response = stale_response;
    const enum java_remote_parent_status mismatched_link_status =
        java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie);
    java_remote_parent_response_t expected_missing = {0};
    java_remote_parent_init_response(&expected_missing, k_java_remote_parent_status_missing, 0, 0);
    if (mismatched_link_status != k_java_remote_parent_status_missing ||
        memcmp(&response, &expected_missing, sizeof(response)) != 0 || task_present ||
        !exact_finish_claim_guard_tail(&stored_state_key,
                                       k_java_remote_parent_lifecycle_consumed) ||
        stats[k_java_remote_parent_stat_take_missing] != 2 || unexpected_update ||
        unexpected_delete) {
        fail("retained task terminal accepted a mismatched task link");
    }
}

static void test_detached_finish_preserves_successor_terminal(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const connection_info_t replacement = {.s_port = 2345, .d_port = 8443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        owner_present || fallback_present || !state_present || !generation_index_present ||
        connection_present || cookie_connection_present || stored_state.aliases != 1 ||
        claim_present || detach_guard_present || find_ambiguity(&stored_state_key)) {
        fail("could not seed a valid detached predecessor generation");
    }
    seed_replacement_generation(&replacement);
    cookie_connection_present = 1;

    stored_terminal = (java_remote_parent_terminal_t){
        .generation = test_replacement_generation,
        .observed_monotime_ns = test_now_ns,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_consumed,
    };
    const java_remote_parent_terminal_t successor = stored_terminal;
    terminal_present = 1;
    stored_claim_key = stored_state_key;
    stored_claim = (java_remote_parent_claim_t){
        .observed_monotime_ns = test_now_ns,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_consumed,
    };
    claim_present = 1;

    const java_remote_parent_resolution_t resolution = {
        .key = stored_state_key,
        .indexed =
            {
                .generation = test_generation,
                .process_incarnation = test_process_incarnation,
                .lifecycle = k_java_remote_parent_lifecycle_active,
            },
        .observed_monotime_ns = test_observed_monotime_ns,
        .found = 1,
    };
    java_remote_parent_finish_generation(&resolution,
                                         k_java_remote_parent_lifecycle_consumed,
                                         test_observed_monotime_ns,
                                         &stored_claim);

    if (!terminal_present || memcmp(&stored_terminal, &successor, sizeof(successor)) != 0 ||
        !state_present || !generation_index_present || connection_present ||
        !cookie_connection_present || stored_cookie_connection.generation != test_generation ||
        !exact_finish_fences_retained(&stored_state_key, k_java_remote_parent_lifecycle_consumed) ||
        !owner_present || stored_owner.generation != test_replacement_generation ||
        !fallback_present ||
        java_remote_parent_le64_to_cpu(stored_fallback.generation_le) !=
            test_replacement_generation ||
        !replacement_state_present || !replacement_generation_index_present ||
        !replacement_connection_present || !replacement_cookie_connection_present ||
        !find_ambiguity_entry(&replacement_state_key) || find_ambiguity(&replacement_state_key) ||
        unexpected_update || unexpected_delete) {
        fail("detached old-generation finish overwrote a successor terminal");
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
    test_alias_observation_rejects_same_generation_reuse();
    test_detached_task_bridge_preserves_same_socket_replacement();
    test_task_claim_binding_rejects_reserved_state();
    test_detached_zero_cleanup_quarantines_retain_race();
    test_detached_zero_cleanup_retains_adoption_artifacts();
    test_cross_generation_guard_does_not_block_detached_cleanup();
    test_cleanup_unlinks_and_cleans_a_different_detached_generation();
    test_owner_cleanup_release_tails_are_recoverable();
    test_internal_cleanup_claim_is_transient();
    test_generation_claim_status_validation();
    test_ambiguity_claim_collision_reports_committed_status();
    test_exact_receive_detach_removes_only_unaliased_generation();
    test_exact_receive_detach_preserves_aliases();
    test_exact_receive_detach_quarantines_last_alias_release_race();
    test_exact_receive_detach_rejects_post_guard_retain();
    test_exact_receive_detach_rejects_retain_at_guard_acquisition();
    test_exact_receive_detach_handles_pre_guard_retain_increment();
    test_exact_receive_detach_fences_task_take_after_guard();
    test_exact_receive_detach_fences_task_discard_after_guard();
    test_exact_receive_detach_preclaims_generation_before_guard();
    test_exact_receive_detach_fences_task_take_during_delete_retry();
    test_aliased_reset_guard_release_failure_retains_tail();
    test_take_claim_revalidates_state_and_generation_index();
    test_visible_final_claim_survives_post_claim_guard();
    test_task_link_is_revalidated_after_claim();
    test_exact_receive_detach_verifies_fallback_and_owner_deletes();
    test_exact_receive_detach_verifies_connection_half_states();
    test_exact_receive_detach_preserves_replacements();
    test_exact_receive_detach_detects_reinserted_and_failed_artifacts();
    test_stale_exact_receive_detach_preserves_newer_generation();
    test_exact_receive_detach_rejects_wrong_authority();
    test_exact_receive_detach_rejects_claim_ambiguity_and_terminal();
    test_exact_receive_detach_revalidates_after_claim();
    test_exact_receive_detach_claim_failures_are_fail_closed();
    test_exact_receive_zero_alias_claim_failures_are_fail_closed();
    test_exact_receive_take_completion_requires_strict_postconditions();
    test_exact_receive_detach_preserves_post_guard_successors();
    test_zero_alias_reset_final_guard_release_preserves_successor();
    test_aliased_reset_final_guard_release_preserves_successor();
    test_exact_receive_connection_delete_rechecks_late_cookie();
    test_finish_guard_and_terminal_failures_are_fenced();
    test_finish_physical_failures_are_fenced();
    test_finish_logical_failures_are_fenced();
    test_finish_release_failures_are_fenced();
    test_finish_final_guard_release_preserves_successor();
    test_live_task_finish_claim_release_preserves_repeat_status();
    test_detached_finish_preserves_successor_terminal();
    return 0;
}
