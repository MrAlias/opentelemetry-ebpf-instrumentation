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

_Static_assert(k_java_remote_parent_go_producer_tag == (u8)0x47, "Go producer tag ABI changed");
_Static_assert(sizeof(java_remote_parent_claim_t) == 24, "generation claim ABI size changed");
_Static_assert(__builtin_offsetof(java_remote_parent_claim_t, reserved) + 6 == 23,
               "Go producer tag ABI offset changed");

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
#include <generictracer/java_remote_parent_close.h>

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
    test_connection_netns_cookie = 84,
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

typedef struct alias_replay_entry {
    java_remote_parent_alias_replay_key_t key;
    java_remote_parent_alias_replay_t value;
    int present;
} alias_replay_entry_t;

static pid_key_t current_task;
static pid_key_t authorized_translation_owner;
static u8 authorized_translation_result;
static u64 current_process_incarnation;
static u64 current_ktime_ns;
static java_remote_parent_state_t stage_state_scratch;
static u64 stage_generation_sequence;
static connection_info_netns_cookie_t stage_incoming_key_scratch;
static connection_info_netns_cookie_t stage_incoming_key;
static u64 stage_incoming_generation;
static incoming_trace_candidate_t stage_incoming_candidate;
static u8 stage_incoming_claim;
static u32 stage_data_hook_readiness;
static int stage_updates_enabled;
static java_remote_parent_data_signal_key_t stage_ack_key;
static java_remote_parent_data_ack_t stage_ack;
static int stage_ack_present;
static java_remote_parent_cleanup_workspace_t cleanup_workspace;
static java_remote_parent_janitor_workspace_t janitor_workspace;
static java_remote_parent_alias_replay_retain_workspace_t alias_replay_retain_workspace;
static java_remote_parent_handoff_capture_workspace_t handoff_capture_workspace;
static java_remote_parent_close_workspace_t close_workspace;
static java_remote_parent_receive_cursor_t last_close_workspace_cursor;
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
static alias_replay_entry_t alias_replays[4];
static int alias_replay_update_failures;
static int disable_alias_replay_autoseed;
static int replace_task_during_alias_replay_lookup;
static int replace_alias_replay_binding_during_finish_lookup;
static int increment_alias_replay_before_publishing_update;
static int advance_time_after_claim_task_validation;
static int zero_alias_replay_after_task_publish;
static int task_update_attempts;
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
static int exact_claim_handoff_failures;
static int exact_claim_delete_failures;
static java_remote_parent_key_t stored_detach_guard_key;
static java_remote_parent_claim_t stored_detach_guard;
static int detach_guard_present;
static java_remote_parent_terminal_t stored_terminal;
static int terminal_present;
static u64 receive_cursor_cookie;
static java_remote_parent_receive_cursor_t receive_cursor;
static int receive_cursor_present;
static u64 receive_guard_cookie;
static java_remote_parent_receive_cursor_t receive_guard;
static int receive_guard_present;
static int receive_guard_update_failures;
static int replace_receive_cursor_after_guard_update;
static int receive_cursor_update_failures;
static int receive_cursor_delete_failures;
static int receive_guard_delete_failures;
static pid_key_t receive_data_signal_owner;
static u64 receive_data_signal_nonce;
static int receive_data_signal_present;
static int receive_data_ack_delete_failures;
static int receive_data_signal_delete_failures;
static int receive_data_ack_delete_attempts;
static int receive_data_signal_delete_attempts;
static java_remote_parent_data_signal_key_t receive_deleted_ack_key;
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
static int inject_identical_foreign_detach_guard_on_update;
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
static int replace_successor_cookie_after_claim;
static int replace_successor_cookie_during_finish;
static int reinsert_exact_cookie_connection_after_delete;
static int reinsert_exact_connection_after_delete;
static int reinsert_exact_cookie_connection_after_netns_delete;
static int replace_netns_and_reinsert_exact_cookie_after_delete;
static int ambiguity_update_failures;
static int ambiguity_delete_failures;
static int replace_ambiguity_after_failed_delete;
static int replace_ambiguity_after_update;
static int drop_ambiguity_after_update;
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
static alias_replay_entry_t *exact_test_alias_replay(void);

static void fail(const char *message) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

static int alias_replay_retain_workspace_zero(void) {
    const java_remote_parent_alias_replay_retain_workspace_t zero = {0};
    return memcmp(&alias_replay_retain_workspace, &zero, sizeof(zero)) == 0;
}

static int handoff_capture_workspace_zero(void) {
    const java_remote_parent_handoff_capture_workspace_t zero = {0};
    return memcmp(&handoff_capture_workspace, &zero, sizeof(zero)) == 0;
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

static alias_replay_entry_t *find_alias_replay(const java_remote_parent_alias_replay_key_t *key) {
    for (size_t i = 0; i < sizeof(alias_replays) / sizeof(alias_replays[0]); i++) {
        if (alias_replays[i].present && same_key(key, &alias_replays[i].key, sizeof(*key))) {
            return &alias_replays[i];
        }
    }
    return NULL;
}

static alias_replay_entry_t *seed_alias_replay(const java_remote_parent_key_t *generation,
                                               u64 observed_monotime_ns,
                                               u64 process_incarnation,
                                               u32 references) {
    const java_remote_parent_alias_replay_key_t key =
        java_remote_parent_alias_replay_key(generation, observed_monotime_ns, process_incarnation);
    alias_replay_entry_t *entry = find_alias_replay(&key);
    if (!entry) {
        for (size_t i = 0; i < sizeof(alias_replays) / sizeof(alias_replays[0]); i++) {
            if (!alias_replays[i].present) {
                entry = &alias_replays[i];
                entry->key = key;
                entry->present = 1;
                break;
            }
        }
    }
    if (!entry) {
        fail("alias replay fixture capacity exhausted");
    }
    entry->value = (java_remote_parent_alias_replay_t){
        .transition_monotime_ns = test_now_ns,
        .references = references,
        .lifecycle = k_java_remote_parent_lifecycle_active,
        .connection = generation->generation == test_replacement_generation
                          ? replacement_state.connection
                          : stored_state.connection,
        .connection_netns = generation->generation == test_replacement_generation
                                ? replacement_state.connection_netns
                                : stored_state.connection_netns,
        .connection_netns_cookie = generation->generation == test_replacement_generation
                                       ? replacement_connection.netns_cookie
                                       : stored_connection.netns_cookie,
        .socket_cookie = generation->generation == test_replacement_generation
                             ? replacement_connection.socket_cookie
                             : stored_connection.socket_cookie,
    };
    return entry;
}

static java_remote_parent_alias_replay_t
test_alias_replay_value(u32 references, u8 lifecycle, u8 desired_lifecycle, u8 producer_tag) {
    return (java_remote_parent_alias_replay_t){
        .transition_monotime_ns = test_now_ns,
        .references = references,
        .lifecycle = lifecycle,
        .desired_lifecycle = desired_lifecycle,
        .producer_tag = producer_tag,
        .connection = {.s_port = 1234, .d_port = 443},
        .connection_netns = test_connection_netns,
        .connection_netns_cookie = test_connection_netns_cookie,
        .socket_cookie = test_socket_cookie,
    };
}

static int exact_adoption_fence_retained(const java_remote_parent_key_t *key) {
    return claim_present && same_key(&stored_claim_key, key, sizeof(*key)) &&
           stored_claim.observed_monotime_ns &&
           stored_claim.process_incarnation == test_process_incarnation &&
           stored_claim.lifecycle == k_java_remote_parent_lifecycle_cleanup &&
           stored_claim.reserved[0] == k_java_remote_parent_lifecycle_publishing &&
           find_ambiguity(key);
}

static int exact_reset_fences_retained(const java_remote_parent_key_t *key) {
    const java_remote_parent_key_t guard_key = {.owner = key->owner};
    return exact_adoption_fence_retained(key) && detach_guard_present &&
           same_key(&stored_detach_guard_key, &guard_key, sizeof(guard_key)) &&
           stored_detach_guard.observed_monotime_ns &&
           stored_detach_guard.process_incarnation == key->generation &&
           stored_detach_guard.lifecycle == k_java_remote_parent_lifecycle_cleanup &&
           stored_detach_guard.reserved[0] == k_java_remote_parent_lifecycle_publishing;
}

static int exact_finish_fences_retained(const java_remote_parent_key_t *key,
                                        enum java_remote_parent_lifecycle lifecycle) {
    const java_remote_parent_key_t guard_key = {.owner = key->owner};
    return claim_present && same_key(&stored_claim_key, key, sizeof(*key)) &&
           stored_claim.observed_monotime_ns &&
           stored_claim.process_incarnation == test_process_incarnation &&
           stored_claim.lifecycle == k_java_remote_parent_lifecycle_cleanup &&
           stored_claim.reserved[0] == lifecycle && find_ambiguity(key) && detach_guard_present &&
           same_key(&stored_detach_guard_key, &guard_key, sizeof(guard_key)) &&
           stored_detach_guard.observed_monotime_ns &&
           stored_detach_guard.process_incarnation == key->generation &&
           stored_detach_guard.lifecycle == k_java_remote_parent_lifecycle_cleanup &&
           stored_detach_guard.reserved[0] == k_java_remote_parent_lifecycle_publishing;
}

static int exact_finish_claim_guard_tail(const java_remote_parent_key_t *key,
                                         enum java_remote_parent_lifecycle lifecycle) {
    const java_remote_parent_key_t guard_key = {.owner = key->owner};
    return claim_present && same_key(&stored_claim_key, key, sizeof(*key)) &&
           stored_claim.observed_monotime_ns &&
           stored_claim.process_incarnation == test_process_incarnation &&
           stored_claim.lifecycle == k_java_remote_parent_lifecycle_cleanup &&
           stored_claim.reserved[0] == lifecycle && !find_ambiguity_entry(key) &&
           detach_guard_present &&
           same_key(&stored_detach_guard_key, &guard_key, sizeof(guard_key)) &&
           stored_detach_guard.observed_monotime_ns &&
           stored_detach_guard.process_incarnation == key->generation &&
           stored_detach_guard.lifecycle == k_java_remote_parent_lifecycle_cleanup &&
           stored_detach_guard.reserved[0] == k_java_remote_parent_lifecycle_publishing;
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
    if (map == &java_remote_parent_data_hook_readiness && *(const u32 *)key == 0) {
        return &stage_data_hook_readiness;
    }
    if (map == &java_remote_parent_generation) {
        return &stage_generation_sequence;
    }
    if (map == &incoming_trace_connection_key_storage) {
        return &stage_incoming_key_scratch;
    }
    if (map == &incoming_trace_heads &&
        same_key(key, &stage_incoming_key, sizeof(stage_incoming_key))) {
        return &stage_incoming_generation;
    }
    if (map == &incoming_trace_candidates && *(const u64 *)key == stage_incoming_generation) {
        return &stage_incoming_candidate;
    }
    if (map == &incoming_trace_claims && *(const u64 *)key == stage_incoming_generation) {
        return &stage_incoming_claim;
    }
    if (map == &java_remote_parent_data_acks && stage_ack_present &&
        same_key(key, &stage_ack_key, sizeof(stage_ack_key))) {
        return &stage_ack;
    }
    if (map == &jrp_recv_cur && receive_cursor_present &&
        *(const u64 *)key == receive_cursor_cookie) {
        return &receive_cursor;
    }
    if (map == &jrp_recv_guard && receive_guard_present &&
        *(const u64 *)key == receive_guard_cookie) {
        return &receive_guard;
    }
    if (map == &java_remote_parent_data_signals && receive_data_signal_present &&
        same_key(key, &receive_data_signal_owner, sizeof(receive_data_signal_owner))) {
        return &receive_data_signal_nonce;
    }
    if (map == &java_remote_parent_stage_state_storage) {
        return &stage_state_scratch;
    }
    if (map == &java_remote_parent_cleanup_workspace_storage) {
        return &cleanup_workspace;
    }
    if (map == &java_remote_parent_janitor_workspace_storage) {
        return &janitor_workspace;
    }
    if (map == &java_remote_parent_alias_replay_retain_workspace_storage) {
        return &alias_replay_retain_workspace;
    }
    if (map == &java_remote_parent_handoff_capture_workspace_storage) {
        return &handoff_capture_workspace;
    }
    if (map == &java_remote_parent_close_workspace_storage && *(const u32 *)key == 0) {
        return &close_workspace;
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
        if (claim_present && !terminal_present && replace_successor_cookie_after_claim) {
            replace_successor_cookie_after_claim = 0;
            replacement_cookie_connection.incoming_generation++;
        }
        if (claim_present && terminal_present && replace_successor_cookie_during_finish) {
            replace_successor_cookie_during_finish = 0;
            replacement_cookie_connection.incoming_generation++;
        }
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
        if (claim_present && stored_claim.lifecycle == k_java_remote_parent_lifecycle_publishing &&
            advance_time_after_claim_task_validation) {
            advance_time_after_claim_task_validation = 0;
            current_ktime_ns++;
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
    if (map == &java_remote_parent_owner_guards && detach_guard_present &&
        same_key(key, &stored_detach_guard_key.owner, sizeof(stored_detach_guard_key.owner))) {
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
    if (map == &java_remote_parent_alias_replays) {
        alias_replay_entry_t *entry = find_alias_replay(key);
        if (!entry && !disable_alias_replay_autoseed) {
            const java_remote_parent_alias_replay_key_t *replay_key = key;
            if (state_present && stored_state.aliases &&
                same_key(&replay_key->owner, &stored_state_key.owner, sizeof(replay_key->owner)) &&
                replay_key->generation == stored_state_key.generation &&
                replay_key->generation_observed_monotime_ns == stored_state.observed_monotime_ns &&
                replay_key->process_incarnation == stored_state.process_incarnation) {
                entry = seed_alias_replay(&stored_state_key,
                                          stored_state.observed_monotime_ns,
                                          stored_state.process_incarnation,
                                          stored_state.aliases);
            } else if (replacement_state_present && replacement_state.aliases &&
                       same_key(&replay_key->owner,
                                &replacement_state_key.owner,
                                sizeof(replay_key->owner)) &&
                       replay_key->generation == replacement_state_key.generation &&
                       replay_key->generation_observed_monotime_ns ==
                           replacement_state.observed_monotime_ns &&
                       replay_key->process_incarnation == replacement_state.process_incarnation) {
                entry = seed_alias_replay(&replacement_state_key,
                                          replacement_state.observed_monotime_ns,
                                          replacement_state.process_incarnation,
                                          replacement_state.aliases);
            }
        }
        if (entry && replace_task_during_alias_replay_lookup) {
            replace_task_during_alias_replay_lookup = 0;
            stored_task.generation = test_replacement_generation;
            stored_task.observed_monotime_ns = test_now_ns;
        }
        if (entry && replace_alias_replay_binding_during_finish_lookup && terminal_present &&
            claim_present &&
            java_remote_parent_alias_replay_lifecycle_final(entry->value.lifecycle)) {
            replace_alias_replay_binding_during_finish_lookup = 0;
            entry->value.socket_cookie++;
        }
        return entry ? &entry->value : NULL;
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
        if (drop_ambiguity_after_update) {
            drop_ambiguity_after_update--;
            existing->present = 0;
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
            if (drop_ambiguity_after_update) {
                drop_ambiguity_after_update--;
                ambiguities[i].present = 0;
            }
            return 0;
        }
    }
    return -1;
}

static long update_alias_replay(const java_remote_parent_alias_replay_key_t *key,
                                const java_remote_parent_alias_replay_t *value,
                                unsigned long long flags) {
    if (alias_replay_update_failures) {
        alias_replay_update_failures--;
        return -1;
    }
    alias_replay_entry_t *entry = find_alias_replay(key);
    if ((entry && flags == BPF_NOEXIST) || (!entry && flags == BPF_EXIST)) {
        return -1;
    }
    if (!entry) {
        for (size_t i = 0; i < sizeof(alias_replays) / sizeof(alias_replays[0]); i++) {
            if (!alias_replays[i].present) {
                entry = &alias_replays[i];
                entry->key = *key;
                entry->present = 1;
                break;
            }
        }
    }
    if (!entry) {
        return -1;
    }
    const int stale_retain = entry->present && increment_alias_replay_before_publishing_update &&
                             value->lifecycle == k_java_remote_parent_lifecycle_publishing;
    if (stale_retain) {
        increment_alias_replay_before_publishing_update = 0;
        entry->value.references++;
    }
    entry->value = *value;
    if (stale_retain) {
        const java_remote_parent_key_t generation =
            java_remote_parent_state_key(&key->owner, key->generation);
        java_remote_parent_alias_replay_unwind_failed_retain(&generation, key);
    }
    return 0;
}

static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags) {
    if (stage_updates_enabled && map == &java_remote_parent_data_acks && flags == BPF_ANY) {
        stage_ack_key = *(const java_remote_parent_data_signal_key_t *)key;
        stage_ack = *(const java_remote_parent_data_ack_t *)value;
        stage_ack_present = 1;
        return 0;
    }
    if (stage_updates_enabled && map == &java_remote_parent_owners &&
        same_key(key, &test_owner, sizeof(test_owner)) &&
        ((flags == BPF_NOEXIST && !owner_present) || (flags == BPF_EXIST && owner_present))) {
        stored_owner = *(const java_remote_parent_owner_t *)value;
        owner_present = 1;
        return 0;
    }
    if (stage_updates_enabled && map == &java_remote_parent_state && flags == BPF_NOEXIST &&
        !replacement_state_present && !same_key(key, &stored_state_key, sizeof(stored_state_key))) {
        replacement_state_key = *(const java_remote_parent_key_t *)key;
        replacement_state = *(const java_remote_parent_state_t *)value;
        replacement_state_present = 1;
        return 0;
    }
    if (stage_updates_enabled && map == &java_remote_parent_generation_index &&
        flags == BPF_NOEXIST && !replacement_generation_index_present &&
        !same_key(key, &stored_generation_index_key, sizeof(stored_generation_index_key))) {
        replacement_generation_index_key = *(const java_remote_parent_key_t *)key;
        replacement_generation_index = *(const java_remote_parent_generation_index_t *)value;
        replacement_generation_index_present = 1;
        return 0;
    }
    if (stage_updates_enabled && map == &java_remote_parent_connections && flags == BPF_NOEXIST &&
        !connection_present && !replacement_connection_present) {
        replacement_connection_key = *(const connection_info_ns_t *)key;
        replacement_connection = *(const java_remote_parent_connection_t *)value;
        replacement_connection_present = 1;
        return 0;
    }
    if (stage_updates_enabled && map == &java_remote_parent_cookie_connections &&
        flags == BPF_NOEXIST && !cookie_connection_present &&
        !replacement_cookie_connection_present) {
        replacement_cookie_connection_key = *(const connection_info_netns_cookie_t *)key;
        replacement_cookie_connection = *(const java_remote_parent_connection_t *)value;
        replacement_cookie_connection_present = 1;
        return 0;
    }
    if (stage_updates_enabled && map == &java_remote_parent_fallback && flags == BPF_NOEXIST &&
        same_key(key, &test_owner, sizeof(test_owner)) && !fallback_present) {
        stored_fallback = *(const java_remote_parent_response_t *)value;
        fallback_present = 1;
        return 0;
    }
    if (map == &java_remote_parent_data_signals && flags == BPF_ANY) {
        receive_data_signal_owner = *(const pid_key_t *)key;
        receive_data_signal_nonce = *(const u64 *)value;
        receive_data_signal_present = 1;
        return 0;
    }
    if (map == &jrp_recv_cur) {
        const u64 socket_cookie = *(const u64 *)key;
        if (receive_cursor_update_failures) {
            receive_cursor_update_failures--;
            return -1;
        }
        if ((flags == BPF_EXIST &&
             (!receive_cursor_present || receive_cursor_cookie != socket_cookie)) ||
            (flags == BPF_NOEXIST && receive_cursor_present &&
             receive_cursor_cookie == socket_cookie)) {
            return -1;
        }
        receive_cursor_cookie = socket_cookie;
        receive_cursor = *(const java_remote_parent_receive_cursor_t *)value;
        receive_cursor_present = 1;
        return 0;
    }
    if (map == &jrp_recv_guard) {
        const u64 socket_cookie = *(const u64 *)key;
        if (receive_guard_update_failures) {
            receive_guard_update_failures--;
            return -1;
        }
        if ((flags == BPF_EXIST &&
             (!receive_guard_present || receive_guard_cookie != socket_cookie)) ||
            (flags == BPF_NOEXIST && receive_guard_present &&
             receive_guard_cookie == socket_cookie)) {
            return -1;
        }
        receive_guard_cookie = socket_cookie;
        receive_guard = *(const java_remote_parent_receive_cursor_t *)value;
        receive_guard_present = 1;
        if (replace_receive_cursor_after_guard_update) {
            replace_receive_cursor_after_guard_update = 0;
            receive_cursor.request_sequence++;
            receive_cursor.generation = test_replacement_generation;
        }
        return 0;
    }
    if (map == &java_remote_parent_handoffs) {
        return update_handoff(key, value, flags);
    }
    if (map == &java_remote_parent_handoff_claims) {
        return update_handoff_claim(key, value, flags);
    }
    if (map == &java_remote_parent_ambiguity) {
        return update_ambiguity(key, value, flags);
    }
    if (map == &java_remote_parent_alias_replays) {
        return update_alias_replay(key, value, flags);
    }
    if (map == &java_remote_parent_tasks && flags == BPF_NOEXIST &&
        same_key(key, &stored_task_key, sizeof(stored_task_key))) {
        task_update_attempts++;
        if (task_present) {
            return -1;
        }
        stored_task = *(const java_remote_parent_task_t *)value;
        task_present = 1;
        if (zero_alias_replay_after_task_publish) {
            zero_alias_replay_after_task_publish = 0;
            const java_remote_parent_key_t generation =
                java_remote_parent_state_key(&stored_task.owner, stored_task.generation);
            const java_remote_parent_alias_replay_key_t replay_key =
                java_remote_parent_alias_replay_key(
                    &generation, stored_task.observed_monotime_ns, test_process_incarnation);
            alias_replay_entry_t *replay = find_alias_replay(&replay_key);
            if (replay) {
                replay->value.references = 0;
            } else {
                unexpected_update = 1;
            }
        }
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
        if (claim_present && same_key(key, &stored_claim_key, sizeof(stored_claim_key))) {
            if (exact_claim_handoff_failures) {
                exact_claim_handoff_failures--;
                return -1;
            }
            stored_claim = *(const java_remote_parent_claim_t *)value;
            return 0;
        }
        return -1;
    }
    if (map == &java_remote_parent_owner_guards && flags == BPF_NOEXIST) {
        if (inject_identical_foreign_detach_guard_on_update) {
            inject_identical_foreign_detach_guard_on_update = 0;
            stored_detach_guard_key = java_remote_parent_detach_guard_key(key);
            stored_detach_guard = *(const java_remote_parent_claim_t *)value;
            detach_guard_present = 1;
            return -1;
        }
        if (detach_guard_present) {
            return -1;
        }
        stored_detach_guard_key = java_remote_parent_detach_guard_key(key);
        stored_detach_guard = *(const java_remote_parent_claim_t *)value;
        detach_guard_present = 1;
        if (claim_present &&
            same_key(&stored_claim_key, &stored_state_key, sizeof(stored_state_key))) {
            exact_claim_present_at_guard_acquisition++;
        }
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
            exact_receive_retain_after_guard_result = java_remote_parent_retain_generation_alias(
                &stored_state_key, stored_state.observed_monotime_ns);
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
    if (map == &java_remote_parent_claims && flags == BPF_NOEXIST) {
        const java_remote_parent_key_t *claim_key = key;
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
    if (stage_updates_enabled && map == &java_remote_parent_fallback && !fallback_present &&
        same_key(key, &test_owner, sizeof(test_owner))) {
        return 0;
    }
    if (map == &jrp_recv_cur) {
        const u64 socket_cookie = *(const u64 *)key;
        if (!receive_cursor_present || receive_cursor_cookie != socket_cookie) {
            return -1;
        }
        if (receive_cursor_delete_failures) {
            receive_cursor_delete_failures--;
            return -1;
        }
        receive_cursor_present = 0;
        return 0;
    }
    if (map == &jrp_recv_guard) {
        const u64 socket_cookie = *(const u64 *)key;
        if (!receive_guard_present || receive_guard_cookie != socket_cookie) {
            return -1;
        }
        if (receive_guard_delete_failures) {
            receive_guard_delete_failures--;
            return -1;
        }
        receive_guard_present = 0;
        return 0;
    }
    if (map == &java_remote_parent_data_acks) {
        receive_data_ack_delete_attempts++;
        receive_deleted_ack_key = *(const java_remote_parent_data_signal_key_t *)key;
        if (receive_data_ack_delete_failures) {
            receive_data_ack_delete_failures--;
            return -1;
        }
        return 0;
    }
    if (map == &java_remote_parent_alias_replays) {
        alias_replay_entry_t *entry = find_alias_replay(key);
        if (!entry) {
            return -1;
        }
        entry->present = 0;
        return 0;
    }
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
    if (map == &java_remote_parent_owner_guards && detach_guard_present &&
        same_key(key, &stored_detach_guard_key.owner, sizeof(stored_detach_guard_key.owner))) {
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
        receive_data_signal_delete_attempts++;
        if (!receive_data_signal_present ||
            !same_key(key, &receive_data_signal_owner, sizeof(receive_data_signal_owner))) {
            return -1;
        }
        if (receive_data_signal_delete_failures) {
            receive_data_signal_delete_failures--;
            return -1;
        }
        receive_data_signal_present = 0;
        return 0;
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
    return current_ktime_ns;
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
    stage_generation_sequence = test_replacement_generation - 1;
    memset(&stage_incoming_key_scratch, 0, sizeof(stage_incoming_key_scratch));
    memset(&stage_incoming_key, 0, sizeof(stage_incoming_key));
    stage_incoming_generation = 0;
    memset(&stage_incoming_candidate, 0, sizeof(stage_incoming_candidate));
    stage_incoming_claim = 0;
    stage_data_hook_readiness = k_java_remote_parent_data_hook_ready;
    stage_updates_enabled = 0;
    memset(&stage_ack_key, 0, sizeof(stage_ack_key));
    memset(&stage_ack, 0, sizeof(stage_ack));
    stage_ack_present = 0;
    memset(&cleanup_workspace, 0, sizeof(cleanup_workspace));
    memset(&janitor_workspace, 0, sizeof(janitor_workspace));
    memset(&alias_replay_retain_workspace, 0, sizeof(alias_replay_retain_workspace));
    memset(&handoff_capture_workspace, 0, sizeof(handoff_capture_workspace));
    memset(&close_workspace, 0, sizeof(close_workspace));
    memset(&last_close_workspace_cursor, 0, sizeof(last_close_workspace_cursor));
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
    memset(alias_replays, 0, sizeof(alias_replays));
    memset(&stored_task, 0, sizeof(stored_task));
    stored_task_key = test_child;
    memset(&transferred_task_key, 0, sizeof(transferred_task_key));
    memset(&transferred_task, 0, sizeof(transferred_task));
    memset(&stored_claim, 0, sizeof(stored_claim));
    memset(&stored_detach_guard_key, 0, sizeof(stored_detach_guard_key));
    memset(&stored_detach_guard, 0, sizeof(stored_detach_guard));
    memset(&stored_terminal, 0, sizeof(stored_terminal));
    memset(&receive_cursor, 0, sizeof(receive_cursor));
    memset(&receive_guard, 0, sizeof(receive_guard));
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
    exact_claim_handoff_failures = 0;
    exact_claim_delete_failures = 0;
    detach_guard_present = 0;
    terminal_present = 0;
    receive_cursor_cookie = 0;
    receive_cursor_present = 0;
    receive_guard_cookie = 0;
    receive_guard_present = 0;
    receive_guard_update_failures = 0;
    replace_receive_cursor_after_guard_update = 0;
    receive_cursor_update_failures = 0;
    receive_cursor_delete_failures = 0;
    receive_guard_delete_failures = 0;
    memset(&receive_data_signal_owner, 0, sizeof(receive_data_signal_owner));
    receive_data_signal_nonce = 0;
    receive_data_signal_present = 0;
    receive_data_ack_delete_failures = 0;
    receive_data_signal_delete_failures = 0;
    receive_data_ack_delete_attempts = 0;
    receive_data_signal_delete_attempts = 0;
    memset(&receive_deleted_ack_key, 0, sizeof(receive_deleted_ack_key));
    terminal_update_failures = 0;
    replace_terminal_after_update = 0;
    alias_replay_update_failures = 0;
    disable_alias_replay_autoseed = 0;
    replace_task_during_alias_replay_lookup = 0;
    replace_alias_replay_binding_during_finish_lookup = 0;
    increment_alias_replay_before_publishing_update = 0;
    advance_time_after_claim_task_validation = 0;
    zero_alias_replay_after_task_publish = 0;
    task_update_attempts = 0;
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
    inject_identical_foreign_detach_guard_on_update = 0;
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
    replace_successor_cookie_after_claim = 0;
    replace_successor_cookie_during_finish = 0;
    reinsert_exact_cookie_connection_after_delete = 0;
    reinsert_exact_connection_after_delete = 0;
    reinsert_exact_cookie_connection_after_netns_delete = 0;
    replace_netns_and_reinsert_exact_cookie_after_delete = 0;
    ambiguity_update_failures = 0;
    ambiguity_delete_failures = 0;
    replace_ambiguity_after_failed_delete = 0;
    replace_ambiguity_after_update = 0;
    drop_ambiguity_after_update = 0;
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
    current_ktime_ns = test_now_ns;

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
    stored_connection.netns_cookie = test_connection_netns_cookie;
    stored_connection.incoming_generation = 21;
    stored_connection.socket_cookie = test_socket_cookie;
    stored_connection.netns = test_connection_netns;

    stored_cookie_connection_key.connection = *connection;
    stored_cookie_connection_key.netns_cookie = stored_connection.netns_cookie;
    stored_cookie_connection = stored_connection;
}

static void seed_receive_cursor(void) {
    receive_cursor_cookie = test_socket_cookie;
    receive_cursor = (java_remote_parent_receive_cursor_t){
        .owner = test_owner,
        .state = k_java_remote_parent_receive_cursor_valid,
        .process_incarnation = test_process_incarnation,
        .lifecycle_id = 0x1020304050607080ULL,
        .request_sequence = 0x1122334455667788ULL,
        .data_signal_nonce = 0x8877665544332211ULL,
        .generation = test_generation,
    };
    receive_cursor_present = 1;
    receive_guard_cookie = test_socket_cookie;
    receive_guard = receive_cursor;
    receive_guard_present = 1;
}

static java_remote_parent_incoming_t
prepare_exact_stage_incoming(const connection_info_t *connection) {
    tp_info_pid_t candidate = {
        .tp = {.ts = test_now_ns, .flags = 1},
        .valid = 1,
        .provenance = k_tp_provenance_tcp_exact_flags,
    };
    for (u32 i = 0; i < sizeof(candidate.tp.trace_id); i++) {
        candidate.tp.trace_id[i] = test_trace_seed + i;
    }
    for (u32 i = 0; i < sizeof(candidate.tp.span_id); i++) {
        candidate.tp.span_id[i] = test_span_seed + i;
    }
    stage_incoming_generation = stored_connection.incoming_generation + 1;
    stage_incoming_candidate = (incoming_trace_candidate_t){.candidate = candidate};
    stage_incoming_claim = 1;
    stage_incoming_key = (connection_info_netns_cookie_t){
        .connection = *connection,
        .netns_cookie = test_connection_netns_cookie,
    };
    return (java_remote_parent_incoming_t){
        .candidate = candidate,
        .generation = stage_incoming_generation,
    };
}

static java_remote_parent_receive_context_t seed_unacked_receive_cursor(void) {
    const java_remote_parent_receive_context_t context = {
        .owner_tid = test_owner.tid,
        .owner_pid = test_owner.pid,
        .owner_ns = test_owner.ns,
        .process_incarnation = test_process_incarnation,
        .lifecycle_id = 0x1020304050607080ULL,
        .request_sequence = 0x1122334455667788ULL,
        .data_signal_nonce = 0x8877665544332211ULL,
        .action = k_java_remote_parent_receive_action_http1_start,
    };
    receive_cursor_cookie = test_socket_cookie;
    receive_cursor = (java_remote_parent_receive_cursor_t){
        .owner = test_owner,
        .state = k_java_remote_parent_receive_cursor_publishing,
        .process_incarnation = context.process_incarnation,
        .lifecycle_id = context.lifecycle_id,
        .request_sequence = context.request_sequence,
        .data_signal_nonce = context.data_signal_nonce,
    };
    receive_cursor_present = 1;
    receive_guard_present = 0;
    receive_data_signal_owner = test_owner;
    receive_data_signal_nonce = context.data_signal_nonce;
    receive_data_signal_present = 1;
    return context;
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

static void test_claim_equality_is_byte_exact(void) {
    const java_remote_parent_claim_t expected = {
        .observed_monotime_ns = test_now_ns,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_publishing,
        .reserved = {1, 2, 3, 4, 5, 6, 7},
    };
    java_remote_parent_claim_t actual = expected;
    if (!java_remote_parent_claim_equal(&expected, &actual) ||
        java_remote_parent_claim_equal(NULL, &actual) ||
        java_remote_parent_claim_equal(&expected, NULL)) {
        fail("claim equality rejected identical bytes or accepted a null claim");
    }

    actual.observed_monotime_ns++;
    if (java_remote_parent_claim_equal(&expected, &actual)) {
        fail("claim equality ignored the observation timestamp");
    }
    actual = expected;
    actual.process_incarnation++;
    if (java_remote_parent_claim_equal(&expected, &actual)) {
        fail("claim equality ignored the process incarnation");
    }
    actual = expected;
    actual.lifecycle++;
    if (java_remote_parent_claim_equal(&expected, &actual)) {
        fail("claim equality ignored the lifecycle");
    }
    for (u32 i = 0; i < sizeof(actual.reserved); i++) {
        actual = expected;
        actual.reserved[i] ^= 0xff;
        if (java_remote_parent_claim_equal(&expected, &actual)) {
            fail("claim equality ignored reserved metadata");
        }
    }
}

static void test_pid_and_generation_index_equality_is_exact(void) {
    pid_key_t left = test_owner;
    const pid_key_t right = test_owner;
    if (!java_remote_parent_pid_key_equal(&left, &right)) {
        fail("pid-key equality rejected identical fields");
    }
    for (u32 bit = 0; bit < 32; bit++) {
        left = right;
        left.tid ^= (u32)1 << bit;
        if (java_remote_parent_pid_key_equal(&left, &right)) {
            fail("pid-key equality ignored a tid bit");
        }
        left = right;
        left.pid ^= (u32)1 << bit;
        if (java_remote_parent_pid_key_equal(&left, &right)) {
            fail("pid-key equality ignored a pid bit");
        }
        left = right;
        left.ns ^= (u32)1 << bit;
        if (java_remote_parent_pid_key_equal(&left, &right)) {
            fail("pid-key equality ignored a namespace bit");
        }
    }

    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    if (!java_remote_parent_generation_index_matches(
            &stored_state_key, test_process_incarnation, test_observed_monotime_ns)) {
        fail("generation-index equality rejected an exact record");
    }
    stored_generation_index.reserved = 1;
    if (java_remote_parent_generation_index_matches(
            &stored_state_key, test_process_incarnation, test_observed_monotime_ns)) {
        fail("generation-index equality ignored reserved metadata");
    }
    stored_generation_index.reserved = 0;
    stored_generation_index.process.tid ^= 1;
    if (java_remote_parent_generation_index_matches(
            &stored_state_key, test_process_incarnation, test_observed_monotime_ns)) {
        fail("generation-index equality ignored process tid");
    }
    stored_generation_index.process = java_process_key(&test_owner);
    stored_generation_index.process.pid ^= 1;
    if (java_remote_parent_generation_index_matches(
            &stored_state_key, test_process_incarnation, test_observed_monotime_ns)) {
        fail("generation-index equality ignored process pid");
    }
    stored_generation_index.process = java_process_key(&test_owner);
    stored_generation_index.process.ns ^= 1;
    if (java_remote_parent_generation_index_matches(
            &stored_state_key, test_process_incarnation, test_observed_monotime_ns)) {
        fail("generation-index equality ignored process namespace");
    }
    stored_generation_index.process = java_process_key(&test_owner);
    stored_generation_index.process_incarnation++;
    if (java_remote_parent_generation_index_matches(
            &stored_state_key, test_process_incarnation, test_observed_monotime_ns)) {
        fail("generation-index equality ignored process incarnation");
    }
    stored_generation_index.process_incarnation = test_process_incarnation;
    stored_generation_index.observed_monotime_ns++;
    if (java_remote_parent_generation_index_matches(
            &stored_state_key, test_process_incarnation, test_observed_monotime_ns)) {
        fail("generation-index equality ignored observation time");
    }
    stored_generation_index.observed_monotime_ns = test_observed_monotime_ns;
    generation_index_present = 0;
    if (java_remote_parent_generation_index_matches(
            &stored_state_key, test_process_incarnation, test_observed_monotime_ns)) {
        fail("generation-index equality accepted an absent record");
    }
}

static void test_abi_tail_validation_is_byte_exact(void) {
    java_remote_parent_claim_t claim = {
        .lifecycle = k_java_remote_parent_lifecycle_publishing,
    };
    if (!java_remote_parent_clean_lifecycle_tail(&claim.lifecycle,
                                                 k_java_remote_parent_lifecycle_publishing)) {
        fail("claim tail rejected clean publishing metadata");
    }
    claim.lifecycle = k_java_remote_parent_lifecycle_consumed;
    if (java_remote_parent_clean_lifecycle_tail(&claim.lifecycle,
                                                k_java_remote_parent_lifecycle_publishing)) {
        fail("claim tail ignored the lifecycle");
    }
    claim.lifecycle = k_java_remote_parent_lifecycle_publishing;
    for (u32 i = 0; i < sizeof(claim.reserved); i++) {
        claim.reserved[i] = 1;
        if (java_remote_parent_clean_lifecycle_tail(&claim.lifecycle,
                                                    k_java_remote_parent_lifecycle_publishing)) {
            fail("claim tail ignored reserved metadata");
        }
        claim.reserved[i] = 0;
    }

    java_remote_parent_owner_t owner = {
        .lifecycle = k_java_remote_parent_lifecycle_active,
    };
    if (!java_remote_parent_clean_lifecycle_tail(&owner.lifecycle,
                                                 k_java_remote_parent_lifecycle_active)) {
        fail("owner tail rejected clean active metadata");
    }
    for (u32 i = 0; i < sizeof(owner.reserved); i++) {
        owner.reserved[i] = 1;
        if (java_remote_parent_clean_lifecycle_tail(&owner.lifecycle,
                                                    k_java_remote_parent_lifecycle_active)) {
            fail("owner tail ignored reserved metadata");
        }
        owner.reserved[i] = 0;
    }

    java_remote_parent_terminal_t terminal = {
        .lifecycle = k_java_remote_parent_lifecycle_ambiguous,
    };
    if (!java_remote_parent_clean_lifecycle_tail(&terminal.lifecycle,
                                                 k_java_remote_parent_lifecycle_ambiguous)) {
        fail("terminal tail rejected clean final metadata");
    }
    for (u32 i = 0; i < sizeof(terminal.reserved); i++) {
        terminal.reserved[i] = 1;
        if (java_remote_parent_clean_lifecycle_tail(&terminal.lifecycle,
                                                    k_java_remote_parent_lifecycle_ambiguous)) {
            fail("terminal tail ignored reserved metadata");
        }
        terminal.reserved[i] = 0;
    }

    java_remote_parent_finish_guard_t guard = {
        .physical_detached = 0xff,
        .replay_required = 1,
    };
    if (!java_remote_parent_clean_boolean_second_byte_tail(&guard.physical_detached)) {
        fail("finish-guard tail constrained the physical byte");
    }
    guard.replay_required = 2;
    if (java_remote_parent_clean_boolean_second_byte_tail(&guard.physical_detached)) {
        fail("finish-guard tail accepted a non-boolean replay flag");
    }
    guard.replay_required = 0;
    for (u32 i = 0; i < sizeof(guard.reserved); i++) {
        guard.reserved[i] = 1;
        if (java_remote_parent_clean_boolean_second_byte_tail(&guard.physical_detached)) {
            fail("finish-guard tail ignored reserved metadata");
        }
        guard.reserved[i] = 0;
    }

    java_remote_parent_state_t state = {
        .lifecycle = k_java_remote_parent_lifecycle_active,
    };
    if (java_remote_parent_metadata_word(&state.lifecycle) !=
        k_java_remote_parent_lifecycle_active) {
        fail("state metadata rejected a clean active prefix");
    }
    for (u32 i = 0; i < sizeof(state.reserved); i++) {
        state.reserved[i] = 1;
        if (java_remote_parent_metadata_word(&state.lifecycle) ==
            k_java_remote_parent_lifecycle_active) {
            fail("state metadata ignored a reserved byte");
        }
        state.reserved[i] = 0;
    }
    state.lifecycle = k_java_remote_parent_lifecycle_publishing;
    if (java_remote_parent_metadata_word(&state.lifecycle) ==
        k_java_remote_parent_lifecycle_active) {
        fail("state metadata ignored the lifecycle");
    }

    const java_remote_parent_alias_replay_key_t replay_key = {
        .owner = test_owner,
        .generation = test_generation,
        .generation_observed_monotime_ns = test_observed_monotime_ns,
        .process_incarnation = test_process_incarnation,
    };
    java_remote_parent_alias_replay_t replay =
        test_alias_replay_value(1, k_java_remote_parent_lifecycle_active, 0, 0);
    if (!java_remote_parent_alias_replay_active_valid(&replay_key, &replay, 1)) {
        fail("replay metadata rejected a clean active record");
    }
    for (u32 i = 0; i < 4; i++) {
        replay = test_alias_replay_value(1, k_java_remote_parent_lifecycle_active, 0, 0);
        ((u8 *)&replay.lifecycle)[i] ^= 0xff;
        if (java_remote_parent_alias_replay_active_valid(&replay_key, &replay, 1)) {
            fail("active replay metadata ignored a metadata byte");
        }
    }
    replay = test_alias_replay_value(
        1, k_java_remote_parent_lifecycle_publishing, k_java_remote_parent_lifecycle_consumed, 0);
    if (!java_remote_parent_alias_replay_publishing_valid(
            &replay_key, &replay, k_java_remote_parent_lifecycle_consumed)) {
        fail("replay metadata rejected a clean publishing record");
    }
    for (u32 i = 0; i < 4; i++) {
        java_remote_parent_alias_replay_t mutated = replay;
        ((u8 *)&mutated.lifecycle)[i] ^= 0xff;
        if (java_remote_parent_alias_replay_publishing_valid(
                &replay_key, &mutated, k_java_remote_parent_lifecycle_consumed)) {
            fail("publishing replay metadata ignored a metadata byte");
        }
    }
    replay.producer_tag = k_java_remote_parent_go_producer_tag;
    if (!java_remote_parent_alias_replay_publishing_valid(
            &replay_key, &replay, k_java_remote_parent_lifecycle_consumed)) {
        fail("replay metadata rejected a tagged Go publishing record");
    }
    replay.producer_tag = 1;
    if (java_remote_parent_alias_replay_publishing_valid(
            &replay_key, &replay, k_java_remote_parent_lifecycle_consumed)) {
        fail("replay metadata accepted an unknown producer tag");
    }
    replay = test_alias_replay_value(1, k_java_remote_parent_lifecycle_consumed, 0, 0);
    if (!java_remote_parent_alias_replay_final_valid(
            &replay_key, &replay, k_java_remote_parent_lifecycle_consumed)) {
        fail("replay metadata rejected a clean final record");
    }
    for (u32 i = 0; i < 4; i++) {
        java_remote_parent_alias_replay_t mutated = replay;
        ((u8 *)&mutated.lifecycle)[i] ^= 0xff;
        if (java_remote_parent_alias_replay_final_valid(
                &replay_key, &mutated, k_java_remote_parent_lifecycle_consumed)) {
            fail("final replay metadata ignored a metadata byte");
        }
    }
    java_remote_parent_alias_replay_binding_t replay_binding = {0};
    java_remote_parent_alias_replay_binding_snapshot(&replay_binding, &replay);
    if (!java_remote_parent_alias_replay_binding_matches_snapshot(&replay, &replay_binding)) {
        fail("replay binding rejected its byte-exact snapshot");
    }
    for (u32 i = 0; i < sizeof(replay_binding); i++) {
        java_remote_parent_alias_replay_binding_t mutated = replay_binding;
        ((u8 *)&mutated)[i] ^= 1;
        if (java_remote_parent_alias_replay_binding_matches_snapshot(&replay, &mutated)) {
            fail("replay binding ignored a snapshot byte");
        }
    }

    const java_remote_parent_resolution_t resolution = {
        .key =
            {
                .owner = test_owner,
                .generation = test_generation,
            },
    };
    const java_remote_parent_finish_connection_t expected_connection = {
        .generation = test_generation,
        .netns_cookie = 84,
        .incoming_generation = 21,
        .socket_cookie = test_socket_cookie,
        .netns = test_connection_netns,
    };
    java_remote_parent_connection_t connection = {
        .owner = test_owner,
        .generation = test_generation,
        .netns_cookie = expected_connection.netns_cookie,
        .incoming_generation = expected_connection.incoming_generation,
        .socket_cookie = expected_connection.socket_cookie,
        .netns = expected_connection.netns,
    };
    if (!java_remote_parent_finish_connection_matches(
            &resolution, &connection, &expected_connection)) {
        fail("finish connection matcher rejected clean reserved fields");
    }
    connection.reserved = 1;
    if (java_remote_parent_finish_connection_matches(
            &resolution, &connection, &expected_connection)) {
        fail("finish connection matcher ignored reserved");
    }
    connection.reserved = 0;
    connection.reserved2 = 1;
    if (java_remote_parent_finish_connection_matches(
            &resolution, &connection, &expected_connection)) {
        fail("finish connection matcher ignored reserved2");
    }
}

static void test_finish_connection_matcher_is_field_exact(void) {
    java_remote_parent_resolution_t resolution = {
        .key =
            {
                .owner = test_owner,
                .reserved = ~(u32)0,
                .generation = test_generation,
            },
    };
    java_remote_parent_finish_connection_t expected = {
        .generation = test_generation,
        .netns_cookie = 0x0123456789abcdef,
        .incoming_generation = 0xfedcba9876543210,
        .socket_cookie = test_socket_cookie,
        .netns = test_connection_netns,
        .reserved = ~(u32)0,
    };
    java_remote_parent_connection_t connection = {
        .owner = test_owner,
        .generation = test_generation,
        .netns_cookie = expected.netns_cookie,
        .incoming_generation = expected.incoming_generation,
        .socket_cookie = expected.socket_cookie,
        .netns = expected.netns,
    };
    if (!java_remote_parent_finish_connection_matches(&resolution, &connection, &expected)) {
        fail("finish connection matcher constrained ignored input metadata");
    }
    if (java_remote_parent_finish_connection_matches(&resolution, 0, &expected)) {
        fail("finish connection matcher accepted an absent connection");
    }

#define ASSERT_FINISH_CONNECTION_FIELD_EXACT(field)                                                \
    do {                                                                                           \
        for (u32 bit = 0; bit < sizeof(connection.field) * 8; bit++) {                             \
            java_remote_parent_connection_t mutated = connection;                                  \
            ((u8 *)&mutated.field)[bit / 8] ^= (u8)(1U << (bit % 8));                              \
            if (java_remote_parent_finish_connection_matches(&resolution, &mutated, &expected))    \
                fail("finish connection matcher ignored a bit in " #field);                        \
        }                                                                                          \
    } while (0)

    ASSERT_FINISH_CONNECTION_FIELD_EXACT(owner.tid);
    ASSERT_FINISH_CONNECTION_FIELD_EXACT(owner.pid);
    ASSERT_FINISH_CONNECTION_FIELD_EXACT(owner.ns);
    ASSERT_FINISH_CONNECTION_FIELD_EXACT(reserved);
    ASSERT_FINISH_CONNECTION_FIELD_EXACT(generation);
    ASSERT_FINISH_CONNECTION_FIELD_EXACT(netns_cookie);
    ASSERT_FINISH_CONNECTION_FIELD_EXACT(incoming_generation);
    ASSERT_FINISH_CONNECTION_FIELD_EXACT(socket_cookie);
    ASSERT_FINISH_CONNECTION_FIELD_EXACT(netns);
    ASSERT_FINISH_CONNECTION_FIELD_EXACT(reserved2);
#undef ASSERT_FINISH_CONNECTION_FIELD_EXACT

    resolution = (java_remote_parent_resolution_t){
        .key.reserved = ~(u32)0,
    };
    expected = (java_remote_parent_finish_connection_t){
        .reserved = ~(u32)0,
    };
    connection = (java_remote_parent_connection_t){0};
    if (!java_remote_parent_finish_connection_matches(&resolution, &connection, &expected)) {
        fail("finish connection matcher added a nonzero or ignored-metadata requirement");
    }
}

static u8 reference_finish_claim_shape_compact(const java_remote_parent_resolution_t *resolution,
                                               const java_remote_parent_claim_t *owned_claim,
                                               enum java_remote_parent_lifecycle lifecycle) {
    return owned_claim && owned_claim->lifecycle == lifecycle &&
           java_remote_parent_finish_claim_shape_valid(resolution, owned_claim) &&
           resolution->key.generation && !resolution->key.reserved;
}

static void assert_compact_finish_claim_shape(const java_remote_parent_resolution_t *resolution,
                                              const java_remote_parent_claim_t *owned_claim,
                                              enum java_remote_parent_lifecycle lifecycle) {
    if (java_remote_parent_finish_claim_shape_compact(resolution, owned_claim, lifecycle) !=
        reference_finish_claim_shape_compact(resolution, owned_claim, lifecycle)) {
        fail("compact finish-claim shape changed authority");
    }
}

static void assert_compact_finish_guard_shape(const java_remote_parent_resolution_t *resolution,
                                              const java_remote_parent_finish_guard_t *guard) {
    if (java_remote_parent_finish_guard_shape_compact(resolution, guard) !=
        java_remote_parent_finish_guard_shape_valid(resolution, guard)) {
        fail("compact finish-guard shape changed authority");
    }
}

static void
assert_compact_finish_terminal_authority(const java_remote_parent_resolution_t *resolution,
                                         const java_remote_parent_terminal_t *terminal,
                                         enum java_remote_parent_lifecycle lifecycle,
                                         u64 observed_monotime_ns,
                                         const java_remote_parent_finish_guard_t *guard) {
    if (java_remote_parent_finish_terminal_authority_compact(
            resolution, terminal, lifecycle, observed_monotime_ns, guard) !=
        java_remote_parent_finish_terminal_matches_guard(
            resolution, terminal, lifecycle, observed_monotime_ns, guard)) {
        fail("compact finish-terminal authority changed semantics");
    }
}

static void test_compact_finish_shapes_match_reference(void) {
    java_remote_parent_resolution_t resolution = {
        .key =
            {
                .owner = test_owner,
                .generation = test_generation,
            },
        .indexed.process_incarnation = test_process_incarnation,
    };
    java_remote_parent_claim_t claim = {
        .observed_monotime_ns = test_now_ns,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_consumed,
    };
    for (u32 expected = 0; expected < 256; expected++) {
        for (u32 actual = 0; actual < 256; actual++) {
            claim.lifecycle = actual;
            assert_compact_finish_claim_shape(
                &resolution, &claim, (enum java_remote_parent_lifecycle)expected);
        }
    }
    claim.lifecycle = k_java_remote_parent_lifecycle_consumed;
    for (u32 i = 0; i < sizeof(claim.reserved); i++) {
        claim.reserved[i] = 1;
        assert_compact_finish_claim_shape(
            &resolution, &claim, k_java_remote_parent_lifecycle_consumed);
        claim.reserved[i] = 0;
    }
    claim.observed_monotime_ns = 0;
    assert_compact_finish_claim_shape(&resolution, &claim, k_java_remote_parent_lifecycle_consumed);
    claim.observed_monotime_ns = test_now_ns;
    claim.process_incarnation++;
    assert_compact_finish_claim_shape(&resolution, &claim, k_java_remote_parent_lifecycle_consumed);
    claim.process_incarnation = test_process_incarnation;
    resolution.key.generation = 0;
    assert_compact_finish_claim_shape(&resolution, &claim, k_java_remote_parent_lifecycle_consumed);
    resolution.key.generation = test_generation;
    resolution.key.reserved = 1;
    assert_compact_finish_claim_shape(&resolution, &claim, k_java_remote_parent_lifecycle_consumed);
    resolution.key.reserved = 0;

    java_remote_parent_finish_guard_t guard = {
        .key.owner = test_owner,
        .claim =
            {
                .observed_monotime_ns = test_now_ns,
                .process_incarnation = test_generation,
                .lifecycle = k_java_remote_parent_lifecycle_publishing,
            },
        .physical_detached = 0xff,
        .replay_required = 1,
    };
    assert_compact_finish_guard_shape(&resolution, &guard);
    guard.key.generation = 1;
    assert_compact_finish_guard_shape(&resolution, &guard);
    guard.key.generation = 0;
    guard.key.reserved = 1;
    assert_compact_finish_guard_shape(&resolution, &guard);
    guard.key.reserved = 0;
    guard.key.owner.tid++;
    assert_compact_finish_guard_shape(&resolution, &guard);
    guard.key.owner = test_owner;
    guard.key.owner.pid++;
    assert_compact_finish_guard_shape(&resolution, &guard);
    guard.key.owner = test_owner;
    guard.key.owner.ns++;
    assert_compact_finish_guard_shape(&resolution, &guard);
    guard.key.owner = test_owner;
    guard.claim.observed_monotime_ns = 0;
    assert_compact_finish_guard_shape(&resolution, &guard);
    guard.claim.observed_monotime_ns = test_now_ns;
    guard.claim.process_incarnation++;
    assert_compact_finish_guard_shape(&resolution, &guard);
    guard.claim.process_incarnation = test_generation;
    for (u32 lifecycle = 0; lifecycle < 256; lifecycle++) {
        guard.claim.lifecycle = lifecycle;
        assert_compact_finish_guard_shape(&resolution, &guard);
    }
    guard.claim.lifecycle = k_java_remote_parent_lifecycle_publishing;
    for (u32 i = 0; i < sizeof(guard.claim.reserved); i++) {
        guard.claim.reserved[i] = 1;
        assert_compact_finish_guard_shape(&resolution, &guard);
        guard.claim.reserved[i] = 0;
    }
    for (u32 physical_detached = 0; physical_detached < 256; physical_detached++) {
        guard.physical_detached = physical_detached;
        assert_compact_finish_guard_shape(&resolution, &guard);
    }
    guard.physical_detached = 0;
    for (u32 replay_required = 0; replay_required < 256; replay_required++) {
        guard.replay_required = replay_required;
        assert_compact_finish_guard_shape(&resolution, &guard);
    }
    guard.replay_required = 0;
    for (u32 i = 0; i < sizeof(guard.reserved); i++) {
        guard.reserved[i] = 1;
        assert_compact_finish_guard_shape(&resolution, &guard);
        guard.reserved[i] = 0;
    }

    java_remote_parent_terminal_t terminal = {
        .generation = test_generation,
        .observed_monotime_ns = test_observed_monotime_ns,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_consumed,
    };
    guard.terminal_generation = test_generation;
    for (u32 expected = 0; expected < 256; expected++) {
        for (u32 actual = 0; actual < 256; actual++) {
            terminal.lifecycle = actual;
            assert_compact_finish_terminal_authority(&resolution,
                                                     &terminal,
                                                     (enum java_remote_parent_lifecycle)expected,
                                                     test_observed_monotime_ns,
                                                     &guard);
        }
    }
    terminal.lifecycle = k_java_remote_parent_lifecycle_consumed;
    for (u32 i = 0; i < sizeof(terminal.reserved); i++) {
        terminal.reserved[i] = 1;
        assert_compact_finish_terminal_authority(&resolution,
                                                 &terminal,
                                                 k_java_remote_parent_lifecycle_consumed,
                                                 test_observed_monotime_ns,
                                                 &guard);
        terminal.reserved[i] = 0;
    }
    terminal.generation = 0;
    assert_compact_finish_terminal_authority(&resolution,
                                             &terminal,
                                             k_java_remote_parent_lifecycle_consumed,
                                             test_observed_monotime_ns,
                                             &guard);
    terminal.generation = test_generation;
    terminal.observed_monotime_ns = 0;
    assert_compact_finish_terminal_authority(&resolution,
                                             &terminal,
                                             k_java_remote_parent_lifecycle_consumed,
                                             test_observed_monotime_ns,
                                             &guard);
    terminal.observed_monotime_ns = test_observed_monotime_ns;
    terminal.process_incarnation = 0;
    assert_compact_finish_terminal_authority(&resolution,
                                             &terminal,
                                             k_java_remote_parent_lifecycle_consumed,
                                             test_observed_monotime_ns,
                                             &guard);
    terminal.process_incarnation = test_process_incarnation;
    guard.terminal_generation = 0;
    assert_compact_finish_terminal_authority(&resolution,
                                             &terminal,
                                             k_java_remote_parent_lifecycle_consumed,
                                             test_observed_monotime_ns,
                                             &guard);
    guard.terminal_generation = test_replacement_generation;
    assert_compact_finish_terminal_authority(&resolution,
                                             &terminal,
                                             k_java_remote_parent_lifecycle_consumed,
                                             test_observed_monotime_ns,
                                             &guard);
    guard.terminal_generation = test_generation;
    assert_compact_finish_terminal_authority(&resolution, NULL, 0, 0, &guard);
    assert_compact_finish_terminal_authority(
        &resolution, &terminal, k_java_remote_parent_lifecycle_consumed, 0, NULL);

    resolution.key.generation = test_replacement_generation;
    terminal.observed_monotime_ns++;
    terminal.process_incarnation++;
    terminal.lifecycle = k_java_remote_parent_lifecycle_ambiguous;
    for (u32 expected = 0; expected < 256; expected++) {
        assert_compact_finish_terminal_authority(
            &resolution, &terminal, (enum java_remote_parent_lifecycle)expected, 0, &guard);
    }
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

static void test_capture_workspaces_are_guarded_and_zeroized(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    alias_replay_retain_workspace.busy = 1;
    if (java_remote_parent_retain_generation_alias(&stored_state_key, test_observed_monotime_ns) ||
        stored_state.aliases || exact_test_alias_replay() ||
        alias_replay_retain_workspace.busy != 1) {
        fail("nested replay retain reused a busy per-CPU workspace");
    }
    alias_replay_retain_workspace.busy = 0;

    const java_remote_parent_handoff_key_t handoff_key =
        java_remote_parent_handoff_key(&test_owner, test_capture_race_token);
    handoff_capture_workspace.busy = 1;
    java_remote_parent_capture_handoff(test_capture_race_token);
    if (find_handoff(&handoff_key) || stored_state.aliases || exact_test_alias_replay() ||
        handoff_capture_workspace.busy != 1) {
        fail("nested handoff capture reused a busy per-CPU workspace");
    }
    handoff_capture_workspace.busy = 0;

    java_remote_parent_capture_handoff(test_capture_race_token);
    if (!find_handoff(&handoff_key) || stored_state.aliases != 1 || !exact_test_alias_replay() ||
        !alias_replay_retain_workspace_zero() || !handoff_capture_workspace_zero() ||
        unexpected_update || unexpected_delete) {
        fail("handoff capture did not zeroize and release its workspaces");
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
        !alias_replay_retain_workspace_zero() || !handoff_capture_workspace_zero() ||
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
    // The successor reuses the exact negotiated physical socket. Keep the
    // helper's distinct-cookie default for the negative cases elsewhere.
    replacement_connection.socket_cookie = test_socket_cookie;
    replacement_connection.netns_cookie = test_connection_netns_cookie;
    replacement_cookie_connection.socket_cookie = test_socket_cookie;
    replacement_cookie_connection.netns_cookie = test_connection_netns_cookie;
    replacement_cookie_connection_key.netns_cookie = test_connection_netns_cookie;
    current_task = test_child;
    memset(&response, 0, sizeof(response));
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_replacement_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_valid ||
        java_remote_parent_le64_to_cpu(response.generation_le) != test_generation ||
        state_present || generation_index_present || connection_present ||
        cookie_connection_present || !replacement_state_present ||
        !replacement_generation_index_present || !replacement_connection_present ||
        !replacement_cookie_connection_present || !owner_present || !fallback_present ||
        stored_owner.generation != test_replacement_generation ||
        memcmp(&stored_fallback, &replacement, sizeof(replacement)) != 0 || claim_present ||
        detach_guard_present || find_ambiguity_entry(&stored_state_key) || !terminal_present ||
        stored_terminal.generation != test_generation ||
        stored_terminal.lifecycle != k_java_remote_parent_lifecycle_consumed || !task_present ||
        unexpected_update || unexpected_delete) {
        fail("detached task TAKE disturbed a same-socket replacement generation");
    }

    const java_remote_parent_response_t stale_response = response;
    connection_info_t wrong_connection = connection;
    wrong_connection.d_port++;
    memset(&response, 0, sizeof(response));
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_replacement_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_already_consumed ||
        response.status != k_java_remote_parent_status_already_consumed ||
        !task_retrieval_rejects_authority(&stale_response,
                                          &wrong_connection,
                                          test_connection_netns,
                                          test_replacement_generation,
                                          test_socket_cookie,
                                          test_generation) ||
        !task_retrieval_rejects_authority(&stale_response,
                                          &connection,
                                          test_connection_netns + 1,
                                          test_replacement_generation,
                                          test_socket_cookie,
                                          test_generation) ||
        !task_retrieval_rejects_authority(&stale_response,
                                          &connection,
                                          test_connection_netns,
                                          test_replacement_generation,
                                          test_replacement_socket_cookie,
                                          test_generation) ||
        !task_retrieval_rejects_authority(&stale_response,
                                          &connection,
                                          test_connection_netns,
                                          test_direct_child_generation,
                                          test_socket_cookie,
                                          test_generation) ||
        stats[k_java_remote_parent_stat_take_missing] != 5 ||
        stats[k_java_remote_parent_stat_take_already_consumed] != 1 || claim_present ||
        detach_guard_present || find_ambiguity_entry(&stored_state_key) ||
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
                                                   test_replacement_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_already_consumed ||
        response.status != k_java_remote_parent_status_already_consumed ||
        java_remote_parent_le64_to_cpu(response.generation_le) != test_generation ||
        claim_present || detach_guard_present || find_ambiguity_entry(&stored_state_key) ||
        !replacement_state_present || !replacement_generation_index_present ||
        !replacement_connection_present || !replacement_cookie_connection_present ||
        stats[k_java_remote_parent_stat_take_already_consumed] != 2 || unexpected_update ||
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
                                                   test_replacement_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_already_consumed ||
        response.status != k_java_remote_parent_status_already_consumed ||
        java_remote_parent_le64_to_cpu(response.generation_le) != test_generation ||
        claim_present || detach_guard_present || find_ambiguity_entry(&stored_state_key) ||
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
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_valid ||
        response.status != k_java_remote_parent_status_valid ||
        java_remote_parent_le64_to_cpu(response.generation_le) != test_replacement_generation ||
        memcmp(response.trace_id, replacement.trace_id, sizeof(response.trace_id)) != 0 ||
        memcmp(response.span_id, replacement.span_id, sizeof(response.span_id)) != 0 ||
        response.flags != replacement.flags || owner_present || fallback_present ||
        replacement_state_present || replacement_generation_index_present ||
        replacement_connection_present || replacement_cookie_connection_present || claim_present ||
        detach_guard_present || find_ambiguity_entry(&replacement_state_key) || !terminal_present ||
        stored_terminal.generation != test_replacement_generation ||
        stored_terminal.lifecycle != k_java_remote_parent_lifecycle_consumed ||
        stats[k_java_remote_parent_stat_take_valid] != 2 || unexpected_update ||
        unexpected_delete) {
        fail("detached task TAKE blocked or disturbed the replacement generation");
    }
}

static void seed_detached_same_socket_successor(const connection_info_t *connection) {
    seed_generation(connection);
    seed_exact_receive_aliases(1);
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            connection,
                                                            test_connection_netns,
                                                            test_socket_cookie)) {
        fail("could not seed detached predecessor for successor proof testing");
    }
    seed_replacement_generation(connection);
    replacement_connection.netns_cookie = test_connection_netns_cookie;
    replacement_connection.socket_cookie = test_socket_cookie;
    replacement_cookie_connection_key.netns_cookie = test_connection_netns_cookie;
    replacement_cookie_connection = replacement_connection;
}

static void assert_detached_successor_fault_rejected(u32 fault) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_detached_same_socket_successor(&connection);
    switch (fault) {
    case 0:
        replacement_connection_present = 0;
        break;
    case 1:
        replacement_cookie_connection_present = 0;
        break;
    case 2:
        replacement_cookie_connection.incoming_generation++;
        break;
    case 3:
        replacement_connection.owner = test_child;
        replacement_cookie_connection.owner = test_child;
        break;
    case 4:
        replacement_connection.socket_cookie = test_replacement_socket_cookie;
        replacement_cookie_connection.socket_cookie = test_replacement_socket_cookie;
        break;
    case 5:
        replacement_connection.generation = test_direct_child_generation;
        replacement_cookie_connection.generation = test_direct_child_generation;
        break;
    case 6:
        replacement_connection.reserved = 1;
        replacement_cookie_connection.reserved = 1;
        break;
    case 7:
        owner_present = 0;
        break;
    case 8:
        fallback_present = 0;
        break;
    case 9:
        replacement_state_present = 0;
        break;
    case 10:
        replacement_generation_index_present = 0;
        break;
    case 11:
        ambiguities[1].present = 0;
        break;
    case 12:
        stored_claim_key = replacement_state_key;
        stored_claim = (java_remote_parent_claim_t){
            .observed_monotime_ns = test_now_ns,
            .process_incarnation = test_process_incarnation,
            .lifecycle = k_java_remote_parent_lifecycle_publishing,
            .reserved = {[0] = k_java_remote_parent_lifecycle_consumed},
        };
        claim_present = 1;
        break;
    case 13:
        stored_terminal = (java_remote_parent_terminal_t){
            .generation = test_replacement_generation,
            .observed_monotime_ns = test_now_ns,
            .process_incarnation = test_process_incarnation,
            .lifecycle = k_java_remote_parent_lifecycle_consumed,
        };
        terminal_present = 1;
        break;
    case 14:
        stored_detach_guard_key = java_remote_parent_state_key(&test_owner, 0);
        stored_detach_guard = (java_remote_parent_claim_t){
            .observed_monotime_ns = test_now_ns,
            .process_incarnation = test_replacement_generation,
            .lifecycle = k_java_remote_parent_lifecycle_publishing,
        };
        detach_guard_present = 1;
        break;
    case 15:
        stored_fallback.flags ^= 1;
        break;
    case 16:
        replacement_state.connection.d_port++;
        break;
    case 17:
        replacement_generation_index.observed_monotime_ns++;
        break;
    default:
        fail("unknown successor proof fault fixture");
    }
    const int claim_was_present = claim_present;
    const int guard_was_present = detach_guard_present;
    const int terminal_was_present = terminal_present;
    const u32 claim_attempts = exact_claim_update_attempts;
    current_task = test_child;
    java_remote_parent_response_t response = stored_state.response;
    const enum java_remote_parent_status status =
        java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_replacement_generation,
                                                   test_socket_cookie);
    if (status == k_java_remote_parent_status_valid ||
        response.status == k_java_remote_parent_status_valid ||
        exact_claim_update_attempts != claim_attempts || claim_present != claim_was_present ||
        detach_guard_present != guard_was_present || terminal_present != terminal_was_present ||
        !state_present || !generation_index_present || !task_present ||
        find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("malformed successor authority reached E promotion or parent delivery");
    }
}

static void test_detached_successor_full_proof_is_fail_closed(void) {
    for (u32 fault = 0; fault <= 17; fault++) {
        assert_detached_successor_fault_rejected(fault);
    }

    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_detached_same_socket_successor(&connection);
    replace_successor_cookie_after_claim = 1;
    const u32 preclaim_attempts = exact_claim_update_attempts;
    current_task = test_child;
    java_remote_parent_response_t response = stored_state.response;
    enum java_remote_parent_status status =
        java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_replacement_generation,
                                                   test_socket_cookie);
    if (status == k_java_remote_parent_status_valid ||
        response.status == k_java_remote_parent_status_valid ||
        replace_successor_cookie_after_claim || claim_present || detach_guard_present ||
        exact_claim_update_attempts != preclaim_attempts + 1 ||
        !find_ambiguity(&stored_state_key) || !state_present || !generation_index_present ||
        !task_present || unexpected_update || unexpected_delete) {
        fail("successor race after publishing E delivered a parent");
    }

    seed_detached_same_socket_successor(&connection);
    replace_successor_cookie_during_finish = 1;
    current_task = test_child;
    response = stored_state.response;
    status = java_remote_parent_retrieve_for_connection(&response,
                                                        0,
                                                        test_now_ns,
                                                        k_java_remote_parent_source_task,
                                                        &connection,
                                                        test_connection_netns,
                                                        test_replacement_generation,
                                                        test_socket_cookie);
    if (status != k_java_remote_parent_status_overload ||
        response.status != k_java_remote_parent_status_overload ||
        replace_successor_cookie_during_finish ||
        !exact_finish_fences_retained(&stored_state_key, k_java_remote_parent_lifecycle_consumed) ||
        !state_present || !generation_index_present || !task_present || unexpected_update ||
        unexpected_delete) {
        fail("successor race under the old owner guard escaped fail-closed fencing");
    }
}

static void test_detached_pre_ack_binding_and_successor_alias_are_live(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie)) {
        fail("could not seed detached pre-ACK task authority");
    }
    connection_info_t wrong_connection = connection;
    wrong_connection.d_port++;
    const java_remote_parent_response_t stale = stored_state.response;
    current_task = test_child;
    if (!task_retrieval_rejects_authority(&stale,
                                          &wrong_connection,
                                          test_connection_netns,
                                          test_generation,
                                          test_socket_cookie,
                                          test_generation) ||
        !task_retrieval_rejects_authority(&stale,
                                          &connection,
                                          test_connection_netns + 1,
                                          test_generation,
                                          test_socket_cookie,
                                          test_generation) ||
        !task_retrieval_rejects_authority(&stale,
                                          &connection,
                                          test_connection_netns,
                                          test_generation,
                                          test_replacement_socket_cookie,
                                          test_generation) ||
        claim_present || detach_guard_present || !state_present || !generation_index_present ||
        !task_present || find_ambiguity(&stored_state_key)) {
        fail("detached pre-ACK authority ignored durable replay binding");
    }
    // A partial successor publication is irrelevant while socket-local
    // negotiation still names the detached old generation.
    replacement_connection_key = connection_info_with_netns(&connection, test_connection_netns);
    replacement_connection = (java_remote_parent_connection_t){
        .owner = test_child,
        .generation = test_replacement_generation,
        .netns_cookie = test_connection_netns_cookie,
        .incoming_generation = 22,
        .socket_cookie = test_replacement_socket_cookie,
        .netns = test_connection_netns,
    };
    replacement_connection_present = 1;
    java_remote_parent_response_t response = stale;
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_valid ||
        response.status != k_java_remote_parent_status_valid || state_present ||
        generation_index_present || claim_present || detach_guard_present ||
        find_ambiguity_entry(&stored_state_key) || !task_present) {
        fail("detached pre-ACK exact binding did not finish independently of partial successor C");
    }

    seed_detached_same_socket_successor(&connection);
    if (!java_remote_parent_retain_generation_alias(&replacement_state_key,
                                                    replacement_state.observed_monotime_ns) ||
        replacement_state.aliases != 1) {
        fail("could not seed a legitimate aliased successor");
    }
    const java_remote_parent_alias_replay_key_t successor_replay_key =
        java_remote_parent_alias_replay_key(&replacement_state_key,
                                            replacement_state.observed_monotime_ns,
                                            replacement_state.process_incarnation);
    alias_replay_entry_t *successor_replay = find_alias_replay(&successor_replay_key);
    if (!successor_replay || !successor_replay->present ||
        memcmp(&successor_replay->key, &successor_replay_key, sizeof(successor_replay_key)) != 0) {
        fail("successor alias did not publish its exact replay key");
    }
    const java_remote_parent_alias_replay_t successor_replay_value = successor_replay->value;
    current_task = test_child;
    response = stored_state.response;
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_replacement_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_valid ||
        response.status != k_java_remote_parent_status_valid || !replacement_state_present ||
        replacement_state.aliases != 1 || !replacement_generation_index_present ||
        !replacement_connection_present || !replacement_cookie_connection_present ||
        !successor_replay->present ||
        memcmp(&successor_replay->key, &successor_replay_key, sizeof(successor_replay_key)) != 0 ||
        memcmp(&successor_replay->value, &successor_replay_value, sizeof(successor_replay_value)) !=
            0) {
        fail("a clean successor alias blocked the old post-ACK task bridge");
    }
}

static void test_direct_take_with_alias_publishes_bound_sibling_replay(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
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
            k_java_remote_parent_status_valid ||
        response.status != k_java_remote_parent_status_valid || state_present ||
        generation_index_present || connection_present || cookie_connection_present ||
        claim_present || detach_guard_present || !task_present || !exact_test_alias_replay() ||
        exact_test_alias_replay()->value.lifecycle != k_java_remote_parent_lifecycle_consumed) {
        fail("direct TAKE with a sibling alias did not publish bound replay authority");
    }
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
            k_java_remote_parent_status_already_consumed ||
        response.status != k_java_remote_parent_status_already_consumed || !task_present ||
        !exact_test_alias_replay() || unexpected_update || unexpected_delete) {
        fail("sibling task lost the direct TAKE's bound terminal replay");
    }
}

static void test_connection_bound_direct_take_requires_nonzero_generation(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    current_task = test_owner;
    java_remote_parent_response_t response = stored_state.response;
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_direct,
                                                   &connection,
                                                   test_connection_netns,
                                                   0,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_missing ||
        response.status != k_java_remote_parent_status_missing || !owner_present ||
        !fallback_present || !state_present || !generation_index_present || !connection_present ||
        !cookie_connection_present || claim_present || terminal_present ||
        find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("connection-bound direct TAKE accepted a zero expected generation");
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
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_cleanup ||
        stored_claim.reserved[0] != k_java_remote_parent_lifecycle_publishing ||
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
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_cleanup ||
        stored_claim.reserved[0] != k_java_remote_parent_lifecycle_publishing ||
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
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_cleanup ||
        stored_claim.reserved[0] != k_java_remote_parent_lifecycle_publishing ||
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

static void test_cleanup_unlinks_exact_task_and_releases_final_replay_reference(void) {
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
    alias_replay_entry_t *replay = seed_alias_replay(
        &stored_state_key, test_observed_monotime_ns, test_process_incarnation, 1);

    java_remote_parent_cleanup(&test_owner);

    if (!owner_cleanup_payload_absent() || claim_present || detach_guard_present ||
        terminal_present || find_ambiguity_entry(&stored_state_key) || !replay->present ||
        replay->value.references ||
        replay->value.lifecycle != k_java_remote_parent_lifecycle_active ||
        exact_claim_update_attempts != 1 || unexpected_update || unexpected_delete) {
        fail("owner cleanup did not unlink its exact task replay reference");
    }
}

static void test_cleanup_absent_task_is_idempotent(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);

    java_remote_parent_cleanup(&test_owner);

    if (!owner_cleanup_payload_absent() || claim_present || detach_guard_present ||
        terminal_present || find_ambiguity_entry(&stored_state_key) ||
        exact_claim_update_attempts != 1 || unexpected_update || unexpected_delete) {
        fail("owner cleanup did not accept an already-absent task link");
    }
}

static void test_cleanup_retains_foreign_generation_task_and_replay(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    const java_remote_parent_key_t foreign =
        java_remote_parent_state_key(&test_owner, test_replacement_generation);
    stored_task_key = test_owner;
    stored_task = (java_remote_parent_task_t){
        .owner = test_owner,
        .generation = test_replacement_generation,
        .observed_monotime_ns = test_now_ns,
    };
    task_present = 1;
    alias_replay_entry_t *replay =
        seed_alias_replay(&foreign, test_now_ns, test_process_incarnation, 1);

    java_remote_parent_cleanup(&test_owner);

    if (owner_present || state_present || generation_index_present || connection_present ||
        cookie_connection_present || fallback_present || !task_present ||
        stored_task.generation != test_replacement_generation ||
        stored_task.observed_monotime_ns != test_now_ns || !claim_present ||
        !same_key(&stored_claim_key, &stored_state_key, sizeof(stored_state_key)) ||
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_cleanup ||
        stored_claim.reserved[0] != k_java_remote_parent_lifecycle_discarded ||
        !detach_guard_present || stored_detach_guard_key.generation ||
        stored_detach_guard.process_incarnation != test_generation ||
        stored_detach_guard.lifecycle != k_java_remote_parent_lifecycle_cleanup ||
        stored_detach_guard.reserved[0] != k_java_remote_parent_lifecycle_publishing ||
        terminal_present || !find_ambiguity(&stored_state_key) || !replay->present ||
        replay->value.references != 1 || exact_claim_update_attempts != 1 || unexpected_update ||
        unexpected_delete) {
        fail("owner cleanup deleted or released a foreign-generation task carrier");
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
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_cleanup ||
        stored_claim.reserved[0] != k_java_remote_parent_lifecycle_discarded ||
        !detach_guard_present ||
        stored_detach_guard.lifecycle != k_java_remote_parent_lifecycle_cleanup ||
        stored_detach_guard.reserved[0] != k_java_remote_parent_lifecycle_publishing ||
        !find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("owner cleanup did not retain its full fence after post-guard owner replacement");
    }

    seed_generation(&connection);
    ambiguity_delete_failures = 1;
    replace_ambiguity_after_failed_delete = 1;
    java_remote_parent_cleanup(&test_owner);
    if (ambiguity_delete_failures || replace_ambiguity_after_failed_delete ||
        !owner_cleanup_payload_absent() || !claim_present ||
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_cleanup ||
        stored_claim.reserved[0] != k_java_remote_parent_lifecycle_discarded ||
        !detach_guard_present ||
        stored_detach_guard.lifecycle != k_java_remote_parent_lifecycle_cleanup ||
        stored_detach_guard.reserved[0] != k_java_remote_parent_lifecycle_publishing ||
        !find_ambiguity_entry(&stored_state_key) || find_ambiguity(&stored_state_key) ||
        unexpected_update || unexpected_delete) {
        fail("owner cleanup promoted a successor reservation after failed marker deletion");
    }

    seed_generation(&connection);
    exact_claim_delete_failures = 1;
    java_remote_parent_cleanup(&test_owner);
    if (exact_claim_delete_failures || !owner_cleanup_payload_absent() || !claim_present ||
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_cleanup ||
        stored_claim.reserved[0] != k_java_remote_parent_lifecycle_discarded ||
        !detach_guard_present ||
        stored_detach_guard.lifecycle != k_java_remote_parent_lifecycle_cleanup ||
        stored_detach_guard.reserved[0] != k_java_remote_parent_lifecycle_publishing ||
        find_ambiguity_entry(&stored_state_key) || unexpected_update || unexpected_delete) {
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
        !detach_guard_present ||
        stored_detach_guard.lifecycle != k_java_remote_parent_lifecycle_cleanup ||
        stored_detach_guard.reserved[0] != k_java_remote_parent_lifecycle_publishing ||
        find_ambiguity_entry(&stored_state_key) || unexpected_update || unexpected_delete) {
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

static enum java_remote_parent_status
reference_claim_status(const java_remote_parent_resolution_t *resolution,
                       const java_remote_parent_claim_t *claimed) {
    if (!claimed) {
        return k_java_remote_parent_status_ambiguous;
    }
    const u8 tagged_go_producer = claimed->lifecycle >= k_java_remote_parent_lifecycle_consumed &&
                                  claimed->lifecycle <= k_java_remote_parent_lifecycle_publishing &&
                                  claimed->reserved[6] == k_java_remote_parent_go_producer_tag;
    const u8 publishing_intent =
        claimed->lifecycle == k_java_remote_parent_lifecycle_publishing &&
        java_remote_parent_alias_replay_lifecycle_final(claimed->reserved[0]) &&
        !claimed->reserved[1] && !claimed->reserved[2] && !claimed->reserved[3] &&
        !claimed->reserved[4] && !claimed->reserved[5] &&
        (!claimed->reserved[6] || tagged_go_producer);
    if (!claimed->observed_monotime_ns ||
        claimed->process_incarnation != resolution->indexed.process_incarnation ||
        claimed->reserved[1] || claimed->reserved[2] || claimed->reserved[3] ||
        claimed->reserved[4] || claimed->reserved[5] ||
        (claimed->lifecycle == k_java_remote_parent_lifecycle_cleanup
             ? claimed->reserved[6]
             : (!publishing_intent && claimed->reserved[0]) ||
                   (claimed->reserved[6] && !tagged_go_producer) ||
                   (claimed->lifecycle == k_java_remote_parent_lifecycle_publishing &&
                    claimed->reserved[6] == k_java_remote_parent_go_producer_tag &&
                    !publishing_intent))) {
        return k_java_remote_parent_status_ambiguous;
    }
    if (publishing_intent) {
        return k_java_remote_parent_status_overload;
    }
    const u8 semantic_lifecycle = claimed->lifecycle == k_java_remote_parent_lifecycle_cleanup
                                      ? claimed->reserved[0]
                                      : claimed->lifecycle;
    switch (semantic_lifecycle) {
    case k_java_remote_parent_lifecycle_publishing:
        return k_java_remote_parent_status_overload;
    case k_java_remote_parent_lifecycle_ambiguous:
        return k_java_remote_parent_status_ambiguous;
    case k_java_remote_parent_lifecycle_consumed:
    case k_java_remote_parent_lifecycle_discarded:
    case k_java_remote_parent_lifecycle_stale:
        return k_java_remote_parent_status_already_consumed;
    default:
        return k_java_remote_parent_status_ambiguous;
    }
}

static void test_claim_status_packed_classifier_matches_reference(void) {
    const java_remote_parent_resolution_t resolution = {
        .indexed.process_incarnation = test_process_incarnation,
    };
    java_remote_parent_claim_t claim = {
        .observed_monotime_ns = test_now_ns,
        .process_incarnation = test_process_incarnation,
    };
    for (u32 lifecycle = 0; lifecycle < 256; lifecycle++) {
        claim.lifecycle = lifecycle;
        for (u32 desired_lifecycle = 0; desired_lifecycle < 256; desired_lifecycle++) {
            claim.reserved[0] = desired_lifecycle;
            for (u32 producer_tag = 0; producer_tag < 256; producer_tag++) {
                claim.reserved[6] = producer_tag;
                if (java_remote_parent_claim_status(&resolution, &claim) !=
                    reference_claim_status(&resolution, &claim)) {
                    fail("packed claim-status classifier changed a lifecycle tuple");
                }
            }
        }
    }

    claim = (java_remote_parent_claim_t){
        .observed_monotime_ns = test_now_ns,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_consumed,
    };
    for (u32 i = 1; i <= 5; i++) {
        claim.reserved[i] = 1;
        if (java_remote_parent_claim_status(&resolution, &claim) !=
            reference_claim_status(&resolution, &claim)) {
            fail("packed claim-status classifier ignored middle reserved metadata");
        }
        claim.reserved[i] = 0;
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
            .name = "BPF publishing intent was not overload",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_publishing,
                    .reserved = {[0] = k_java_remote_parent_lifecycle_consumed},
                },
            .status = k_java_remote_parent_status_overload,
            .take_stat = k_java_remote_parent_stat_take_overload,
            .discard_stat = k_java_remote_parent_stat_discard_overload,
        },
        {
            .name = "tagged Go publishing intent was not overload",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_publishing,
                    .reserved =
                        {
                            [0] = k_java_remote_parent_lifecycle_stale,
                            [6] = k_java_remote_parent_go_producer_tag,
                        },
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
            .name = "tag-only Go publishing exact claim was not ambiguous",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_publishing,
                    .reserved = {[6] = k_java_remote_parent_go_producer_tag},
                },
            .status = k_java_remote_parent_status_ambiguous,
            .take_stat = k_java_remote_parent_stat_take_ambiguous,
            .discard_stat = k_java_remote_parent_stat_discard_ambiguous,
        },
        {
            .name = "tagged Go ambiguous claim was not ambiguous",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_ambiguous,
                    .reserved = {[6] = k_java_remote_parent_go_producer_tag},
                },
            .status = k_java_remote_parent_status_ambiguous,
            .take_stat = k_java_remote_parent_stat_take_ambiguous,
            .discard_stat = k_java_remote_parent_stat_discard_ambiguous,
        },
        {
            .name = "tagged Go consumed claim lost its committed status",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_consumed,
                    .reserved = {[6] = k_java_remote_parent_go_producer_tag},
                },
            .status = k_java_remote_parent_status_already_consumed,
            .take_stat = k_java_remote_parent_stat_take_already_consumed,
            .discard_stat = k_java_remote_parent_stat_discard_already_consumed,
        },
        {
            .name = "tagged Go discarded claim lost its committed status",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_discarded,
                    .reserved = {[6] = k_java_remote_parent_go_producer_tag},
                },
            .status = k_java_remote_parent_status_already_consumed,
            .take_stat = k_java_remote_parent_stat_take_already_consumed,
            .discard_stat = k_java_remote_parent_stat_discard_already_consumed,
        },
        {
            .name = "tagged Go stale claim lost its committed status",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_stale,
                    .reserved = {[6] = k_java_remote_parent_go_producer_tag},
                },
            .status = k_java_remote_parent_status_already_consumed,
            .take_stat = k_java_remote_parent_stat_take_already_consumed,
            .discard_stat = k_java_remote_parent_stat_discard_already_consumed,
        },
        {
            .name = "cleanup-consumed claim lost its committed status",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_cleanup,
                    .reserved = {[0] = k_java_remote_parent_lifecycle_consumed},
                },
            .status = k_java_remote_parent_status_already_consumed,
            .take_stat = k_java_remote_parent_stat_take_already_consumed,
            .discard_stat = k_java_remote_parent_stat_discard_already_consumed,
        },
        {
            .name = "cleanup-discarded claim lost its committed status",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_cleanup,
                    .reserved = {[0] = k_java_remote_parent_lifecycle_discarded},
                },
            .status = k_java_remote_parent_status_already_consumed,
            .take_stat = k_java_remote_parent_stat_take_already_consumed,
            .discard_stat = k_java_remote_parent_stat_discard_already_consumed,
        },
        {
            .name = "cleanup-stale claim lost its committed status",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_cleanup,
                    .reserved = {[0] = k_java_remote_parent_lifecycle_stale},
                },
            .status = k_java_remote_parent_status_already_consumed,
            .take_stat = k_java_remote_parent_stat_take_already_consumed,
            .discard_stat = k_java_remote_parent_stat_discard_already_consumed,
        },
        {
            .name = "cleanup-ambiguous claim was not ambiguous",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_cleanup,
                    .reserved = {[0] = k_java_remote_parent_lifecycle_ambiguous},
                },
            .status = k_java_remote_parent_status_ambiguous,
            .take_stat = k_java_remote_parent_stat_take_ambiguous,
            .discard_stat = k_java_remote_parent_stat_discard_ambiguous,
        },
        {
            .name = "cleanup-publishing claim was not overload",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_cleanup,
                    .reserved = {[0] = k_java_remote_parent_lifecycle_publishing},
                },
            .status = k_java_remote_parent_status_overload,
            .take_stat = k_java_remote_parent_stat_take_overload,
            .discard_stat = k_java_remote_parent_stat_discard_overload,
        },
        {
            .name = "cleanup claim with zero origin was not ambiguous",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_cleanup,
                },
            .status = k_java_remote_parent_status_ambiguous,
            .take_stat = k_java_remote_parent_stat_take_ambiguous,
            .discard_stat = k_java_remote_parent_stat_discard_ambiguous,
        },
        {
            .name = "cleanup claim with active origin was not ambiguous",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_cleanup,
                    .reserved = {[0] = k_java_remote_parent_lifecycle_active},
                },
            .status = k_java_remote_parent_status_ambiguous,
            .take_stat = k_java_remote_parent_stat_take_ambiguous,
            .discard_stat = k_java_remote_parent_stat_discard_ambiguous,
        },
        {
            .name = "cleanup claim with recursive origin was not ambiguous",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_cleanup,
                    .reserved = {[0] = k_java_remote_parent_lifecycle_cleanup},
                },
            .status = k_java_remote_parent_status_ambiguous,
            .take_stat = k_java_remote_parent_stat_take_ambiguous,
            .discard_stat = k_java_remote_parent_stat_discard_ambiguous,
        },
        {
            .name = "cleanup claim with reserved metadata was not ambiguous",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_cleanup,
                    .reserved =
                        {
                            [0] = k_java_remote_parent_lifecycle_consumed,
                            [1] = 1,
                        },
                },
            .status = k_java_remote_parent_status_ambiguous,
            .take_stat = k_java_remote_parent_stat_take_ambiguous,
            .discard_stat = k_java_remote_parent_stat_discard_ambiguous,
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
            .name = "tagged Go claim with extra metadata was not ambiguous",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_consumed,
                    .reserved =
                        {
                            [1] = 1,
                            [6] = k_java_remote_parent_go_producer_tag,
                        },
                },
            .status = k_java_remote_parent_status_ambiguous,
            .take_stat = k_java_remote_parent_stat_take_ambiguous,
            .discard_stat = k_java_remote_parent_stat_discard_ambiguous,
        },
        {
            .name = "tagged cleanup claim was not ambiguous",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_cleanup,
                    .reserved =
                        {
                            [0] = k_java_remote_parent_lifecycle_consumed,
                            [6] = k_java_remote_parent_go_producer_tag,
                        },
                },
            .status = k_java_remote_parent_status_ambiguous,
            .take_stat = k_java_remote_parent_stat_take_ambiguous,
            .discard_stat = k_java_remote_parent_stat_discard_ambiguous,
        },
        {
            .name = "tagged Go claim with semantic metadata was not ambiguous",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_consumed,
                    .reserved =
                        {
                            [0] = k_java_remote_parent_lifecycle_consumed,
                            [6] = k_java_remote_parent_go_producer_tag,
                        },
                },
            .status = k_java_remote_parent_status_ambiguous,
            .take_stat = k_java_remote_parent_stat_take_ambiguous,
            .discard_stat = k_java_remote_parent_stat_discard_ambiguous,
        },
        {
            .name = "tagged active claim was not ambiguous",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_active,
                    .reserved = {[6] = k_java_remote_parent_go_producer_tag},
                },
            .status = k_java_remote_parent_status_ambiguous,
            .take_stat = k_java_remote_parent_stat_take_ambiguous,
            .discard_stat = k_java_remote_parent_stat_discard_ambiguous,
        },
        {
            .name = "tagged unknown claim was not ambiguous",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .reserved = {[6] = k_java_remote_parent_go_producer_tag},
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

static void test_tagged_go_guard_is_status_only(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    stored_detach_guard_key = java_remote_parent_detach_guard_key(&stored_state_key.owner);
    stored_detach_guard = (java_remote_parent_claim_t){
        .observed_monotime_ns = test_now_ns,
        .process_incarnation = test_generation,
        .lifecycle = k_java_remote_parent_lifecycle_publishing,
        .reserved = {[6] = k_java_remote_parent_go_producer_tag},
    };
    detach_guard_present = 1;

    java_remote_parent_response_t response = stored_state.response;
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_direct,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_overload ||
        response.status != k_java_remote_parent_status_overload || !detach_guard_present ||
        stored_detach_guard.reserved[6] != k_java_remote_parent_go_producer_tag || claim_present ||
        !owner_present || !fallback_present || !state_present || !generation_index_present ||
        !connection_present || !cookie_connection_present || terminal_present ||
        exact_claim_update_attempts || stats[k_java_remote_parent_stat_take_overload] != 1 ||
        unexpected_update || unexpected_delete) {
        fail("tagged Go guard granted BPF mutation authority");
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
            .name = "tag-only Go publishing claim collision was not ambiguous",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_publishing,
                    .reserved = {[6] = k_java_remote_parent_go_producer_tag},
                },
            .status = k_java_remote_parent_status_ambiguous,
            .take_stat = k_java_remote_parent_stat_take_ambiguous,
            .discard_stat = k_java_remote_parent_stat_discard_ambiguous,
        },
        {
            .name = "tagged Go ambiguous claim collision was not ambiguous",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_ambiguous,
                    .reserved = {[6] = k_java_remote_parent_go_producer_tag},
                },
            .status = k_java_remote_parent_status_ambiguous,
            .take_stat = k_java_remote_parent_stat_take_ambiguous,
            .discard_stat = k_java_remote_parent_stat_discard_ambiguous,
        },
        {
            .name = "tagged Go consumed claim collision lost its committed status",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_consumed,
                    .reserved = {[6] = k_java_remote_parent_go_producer_tag},
                },
            .status = k_java_remote_parent_status_already_consumed,
            .take_stat = k_java_remote_parent_stat_take_already_consumed,
            .discard_stat = k_java_remote_parent_stat_discard_already_consumed,
        },
        {
            .name = "tagged Go discarded claim collision lost its committed status",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_discarded,
                    .reserved = {[6] = k_java_remote_parent_go_producer_tag},
                },
            .status = k_java_remote_parent_status_already_consumed,
            .take_stat = k_java_remote_parent_stat_take_already_consumed,
            .discard_stat = k_java_remote_parent_stat_discard_already_consumed,
        },
        {
            .name = "tagged Go stale claim collision lost its committed status",
            .claim =
                {
                    .observed_monotime_ns = test_now_ns,
                    .process_incarnation = test_process_incarnation,
                    .lifecycle = k_java_remote_parent_lifecycle_stale,
                    .reserved = {[6] = k_java_remote_parent_go_producer_tag},
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
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_cleanup ||
        stored_claim.reserved[0] != k_java_remote_parent_lifecycle_publishing ||
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
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_cleanup ||
        stored_claim.reserved[0] != k_java_remote_parent_lifecycle_publishing ||
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
        owner_present || fallback_present || state_present || generation_index_present ||
        connection_present || cookie_connection_present || claim_present || detach_guard_present ||
        find_ambiguity_entry(&stored_state_key) || !terminal_present ||
        stored_terminal.generation != test_generation ||
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
        stored_detach_guard.lifecycle != k_java_remote_parent_lifecycle_cleanup ||
        stored_detach_guard.reserved[0] != k_java_remote_parent_lifecycle_publishing ||
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
        claim_present || terminal_present || !owner_present || !fallback_present ||
        !connection_present || !cookie_connection_present || exact_claim_update_attempts != 1 ||
        !find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("late TAKE claim published a terminal after state/index removal");
    }
    memset(&response, 0, sizeof(response));
    if (java_remote_parent_retrieve(
            &response, 0, test_now_ns, k_java_remote_parent_source_direct) !=
            k_java_remote_parent_status_ambiguous ||
        response.status != k_java_remote_parent_status_ambiguous || claim_present) {
        fail("late TAKE state/index loss escaped its precommit ambiguity fence");
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
        stored_generation_index.observed_monotime_ns != test_now_ns || claim_present ||
        terminal_present || !owner_present || !fallback_present || !connection_present ||
        !cookie_connection_present || !find_ambiguity(&stored_state_key) ||
        exact_claim_update_attempts != 1 || unexpected_update || unexpected_delete) {
        fail("late TAKE claim adopted a same-key replacement observation");
    }
    memset(&response, 0, sizeof(response));
    if (java_remote_parent_retrieve(
            &response, 0, test_now_ns, k_java_remote_parent_source_direct) !=
            k_java_remote_parent_status_ambiguous ||
        response.status != k_java_remote_parent_status_ambiguous || claim_present) {
        fail("late TAKE observation replacement escaped its precommit ambiguity fence");
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
            inject_detach_guard_after_exact_claim || claim_present || !detach_guard_present ||
            find_ambiguity(&stored_state_key) || !owner_present || !fallback_present ||
            !state_present || !generation_index_present || !connection_present ||
            !cookie_connection_present || terminal_present || unexpected_update ||
            unexpected_delete) {
            fail("precommit owner guard was not rolled back cleanly");
        }

        memset(&response, 0, sizeof(response));
        if (java_remote_parent_retrieve(
                &response, discard, test_now_ns, k_java_remote_parent_source_direct) !=
                k_java_remote_parent_status_overload ||
            response.status != k_java_remote_parent_status_overload || claim_present ||
            !detach_guard_present || find_ambiguity(&stored_state_key)) {
            fail("precommit owner guard did not preserve deterministic retry status");
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
        inject_detach_guard_after_exact_claim || replace_task_after_exact_claim || claim_present ||
        !detach_guard_present || find_ambiguity(&stored_state_key) || !task_present ||
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
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_cleanup ||
        stored_claim.reserved[0] != k_java_remote_parent_lifecycle_publishing ||
        stored_detach_guard.lifecycle != k_java_remote_parent_lifecycle_cleanup ||
        stored_detach_guard.reserved[0] != k_java_remote_parent_lifecycle_publishing ||
        terminal_present || exact_claim_update_attempts != 1 || unexpected_update ||
        unexpected_delete) {
        fail("aliased RESET did not retain its recoverable claim/guard release tail");
    }

    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    exact_claim_delete_failures = 1;
    exact_claim_handoff_failures = 1;
    if (!java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                            test_process_incarnation,
                                                            &connection,
                                                            test_connection_netns,
                                                            test_socket_cookie) ||
        exact_claim_delete_failures || exact_claim_handoff_failures || owner_present ||
        fallback_present || !state_present || !generation_index_present || connection_present ||
        cookie_connection_present || !task_present || !claim_present || !detach_guard_present ||
        !find_ambiguity_entry(&stored_state_key) || find_ambiguity(&stored_state_key) ||
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_publishing ||
        stored_claim.reserved[0] ||
        stored_detach_guard.lifecycle != k_java_remote_parent_lifecycle_publishing ||
        stored_detach_guard.reserved[0] || terminal_present || exact_claim_update_attempts != 1 ||
        unexpected_update || unexpected_delete) {
        fail("failed exact RESET handoff exposed a cleanup-owned guard without its exact fence");
    }
}

static void test_failed_guard_acquisition_preserves_identical_foreign_guard(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    seed_generation(&connection);
    inject_identical_foreign_detach_guard_on_update = 1;
    if (java_remote_parent_detach_exact_receive_generation(&stored_state_key,
                                                           test_process_incarnation,
                                                           &connection,
                                                           test_connection_netns,
                                                           test_socket_cookie) ||
        inject_identical_foreign_detach_guard_on_update || !owner_present || !fallback_present ||
        !state_present || !generation_index_present || !connection_present ||
        !cookie_connection_present || claim_present || !detach_guard_present ||
        stored_detach_guard.observed_monotime_ns != test_now_ns ||
        stored_detach_guard.process_incarnation != test_generation ||
        stored_detach_guard.lifecycle != k_java_remote_parent_lifecycle_publishing ||
        stored_detach_guard.reserved[0] || stored_detach_guard.reserved[1] ||
        stored_detach_guard.reserved[2] || stored_detach_guard.reserved[3] ||
        stored_detach_guard.reserved[4] || stored_detach_guard.reserved[5] ||
        stored_detach_guard.reserved[6] || terminal_present ||
        !find_ambiguity_entry(&stored_state_key) || find_ambiguity(&stored_state_key) ||
        exact_claim_update_attempts != 1 || unexpected_update || unexpected_delete) {
        fail("failed guard acquisition handed off a byte-identical foreign guard");
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
        terminal_present || stored_claim.lifecycle != k_java_remote_parent_lifecycle_cleanup ||
        stored_claim.reserved[0] != k_java_remote_parent_lifecycle_publishing ||
        stored_detach_guard.lifecycle != k_java_remote_parent_lifecycle_cleanup ||
        stored_detach_guard.reserved[0] != k_java_remote_parent_lifecycle_publishing ||
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

static int unacked_cleanup_left_generation_untouched(void) {
    const ambiguity_entry_t *reservation = find_ambiguity_entry(&stored_state_key);
    return owner_present && fallback_present && state_present && generation_index_present &&
           connection_present && cookie_connection_present && !claim_present &&
           !detach_guard_present && !terminal_present && reservation &&
           !reservation->observed_monotime_ns;
}

static void test_unacked_publishing_cleanup_is_shallow_and_exact(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const pid_key_t process = java_process_key(&test_owner);

    seed_generation(&connection);
    java_remote_parent_receive_context_t context = seed_unacked_receive_cursor();
    java_remote_parent_cleanup_unacked_receive_context(&context, test_socket_cookie);
    if (receive_cursor_present || receive_guard_present || receive_data_signal_present ||
        receive_data_ack_delete_attempts != 1 || receive_data_signal_delete_attempts != 1 ||
        !same_key(&receive_deleted_ack_key.process, &process, sizeof(process)) ||
        receive_deleted_ack_key.reserved ||
        receive_deleted_ack_key.nonce != context.data_signal_nonce ||
        !unacked_cleanup_left_generation_untouched() || unexpected_update || unexpected_delete) {
        fail("exact pre-ACK cleanup did not drain PUBLISHING without touching G/M");
    }

    seed_generation(&connection);
    context = seed_unacked_receive_cursor();
    receive_cursor.request_sequence++;
    java_remote_parent_cleanup_unacked_receive_context(&context, test_socket_cookie);
    if (!receive_cursor_present ||
        receive_cursor.state != k_java_remote_parent_receive_cursor_publishing ||
        receive_data_signal_present || !unacked_cleanup_left_generation_untouched() ||
        unexpected_update || unexpected_delete) {
        fail("mismatched pre-ACK cleanup mutated a foreign PUBLISHING cursor");
    }

    seed_generation(&connection);
    context = seed_unacked_receive_cursor();
    receive_cursor_update_failures = 1;
    java_remote_parent_cleanup_unacked_receive_context(&context, test_socket_cookie);
    if (!receive_cursor_present ||
        receive_cursor.state != k_java_remote_parent_receive_cursor_publishing ||
        receive_cursor_update_failures || !unacked_cleanup_left_generation_untouched() ||
        unexpected_update || unexpected_delete) {
        fail("failed pre-ACK RETIRING update was not left PUBLISHING fail closed");
    }

    seed_generation(&connection);
    context = seed_unacked_receive_cursor();
    receive_cursor_delete_failures = 1;
    java_remote_parent_cleanup_unacked_receive_context(&context, test_socket_cookie);
    if (!receive_cursor_present ||
        receive_cursor.state != k_java_remote_parent_receive_cursor_retiring ||
        receive_cursor_delete_failures || !unacked_cleanup_left_generation_untouched() ||
        unexpected_update || unexpected_delete) {
        fail("failed pre-ACK cursor delete did not leave RETIRING fail closed");
    }

    seed_generation(&connection);
    context = seed_unacked_receive_cursor();
    receive_data_ack_delete_failures = 1;
    receive_data_signal_delete_failures = 1;
    java_remote_parent_cleanup_unacked_receive_context(&context, test_socket_cookie);
    if (receive_cursor_present || !receive_data_signal_present ||
        receive_data_ack_delete_failures || receive_data_signal_delete_failures ||
        receive_data_ack_delete_attempts != 1 || receive_data_signal_delete_attempts != 1 ||
        !unacked_cleanup_left_generation_untouched() || unexpected_update || unexpected_delete) {
        fail("signal cleanup faults prevented terminal PUBLISHING cleanup");
    }

    seed_generation(&connection);
    context = seed_unacked_receive_cursor();
    context.generation = test_generation;
    java_remote_parent_cleanup_unacked_receive_context(&context, test_socket_cookie);
    if (!receive_cursor_present || !receive_data_signal_present ||
        receive_data_ack_delete_attempts || receive_data_signal_delete_attempts ||
        !unacked_cleanup_left_generation_untouched() || unexpected_update || unexpected_delete) {
        fail("pre-ACK cleanup adopted an ACKed context");
    }
}

static void test_parser_failure_uses_pre_reserved_ambiguity_fence(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    seed_generation(&connection);
    seed_receive_cursor();
    receive_guard_present = 0;
    receive_data_signal_owner = test_owner;
    receive_data_signal_nonce = receive_cursor.data_signal_nonce;
    receive_data_signal_present = 1;
    const java_remote_parent_receive_cursor_t expected = receive_cursor;
    if (!java_remote_parent_cleanup_receive_cursor(
            &expected, test_socket_cookie, test_generation) ||
        receive_cursor_present || receive_guard_present || receive_data_signal_present ||
        receive_data_ack_delete_attempts != 1 || receive_data_signal_delete_attempts != 1 ||
        !find_ambiguity(&stored_state_key) || !owner_present || !state_present ||
        !generation_index_present || !connection_present || !cookie_connection_present ||
        unexpected_update || unexpected_delete) {
        fail("parser failure did not fence M before draining its exact cursor");
    }
    java_remote_parent_response_t response = stored_state.response;
    const enum java_remote_parent_status parser_fence_status =
        java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_direct,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie);
    if (parser_fence_status != k_java_remote_parent_status_ambiguous ||
        response.status != k_java_remote_parent_status_ambiguous ||
        java_remote_parent_le64_to_cpu(response.generation_le) != test_generation ||
        owner_present || fallback_present || state_present || generation_index_present ||
        connection_present || cookie_connection_present || claim_present || detach_guard_present ||
        find_ambiguity_entry(&stored_state_key) || !terminal_present ||
        stored_terminal.generation != test_generation ||
        stored_terminal.process_incarnation != test_process_incarnation ||
        stored_terminal.lifecycle != k_java_remote_parent_lifecycle_ambiguous ||
        stats[k_java_remote_parent_stat_take_ambiguous] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("parser M fence remained consumable by SDK TAKE");
    }
    const java_remote_parent_terminal_t expected_terminal = stored_terminal;
    java_remote_parent_cleanup(&test_owner);
    if (owner_present || fallback_present || state_present || generation_index_present ||
        connection_present || cookie_connection_present || task_present || claim_present ||
        detach_guard_present || find_ambiguity_entry(&stored_state_key) || !terminal_present ||
        memcmp(&stored_terminal, &expected_terminal, sizeof(expected_terminal)) != 0 ||
        unexpected_update || unexpected_delete) {
        fail("baseline cleanup disturbed an SDK-converged ambiguous terminal");
    }

    seed_generation(&connection);
    seed_receive_cursor();
    receive_guard_present = 0;
    const java_remote_parent_receive_cursor_t baseline_fenced = receive_cursor;
    if (!java_remote_parent_cleanup_receive_cursor(
            &baseline_fenced, test_socket_cookie, test_generation) ||
        receive_cursor_present || receive_guard_present || !find_ambiguity(&stored_state_key)) {
        fail("could not seed parser-fenced generation for baseline cleanup");
    }
    java_remote_parent_cleanup(&test_owner);
    if (!owner_cleanup_payload_absent() || find_ambiguity_entry(&stored_state_key) ||
        claim_present || detach_guard_present || unexpected_update || unexpected_delete) {
        fail("baseline cleanup did not converge a parser-fenced generation");
    }

    seed_generation(&connection);
    seed_receive_cursor();
    receive_guard_present = 0;
    ambiguities[0].observed_monotime_ns = test_now_ns;
    const java_remote_parent_receive_cursor_t already_fenced = receive_cursor;
    if (!java_remote_parent_cleanup_receive_cursor(
            &already_fenced, test_socket_cookie, test_generation) ||
        receive_cursor_present || receive_guard_present || !find_ambiguity(&stored_state_key) ||
        unexpected_update || unexpected_delete) {
        fail("parser cleanup did not accept an already-fenced generation");
    }

    seed_generation(&connection);
    seed_receive_cursor();
    receive_guard_present = 0;
    const java_remote_parent_receive_cursor_t generation_mismatch = receive_cursor;
    if (java_remote_parent_cleanup_receive_cursor(
            &generation_mismatch, test_socket_cookie, test_replacement_generation) ||
        !receive_cursor_present ||
        receive_cursor.state != k_java_remote_parent_receive_cursor_valid ||
        receive_guard_present || find_ambiguity(&stored_state_key) ||
        receive_data_ack_delete_attempts || receive_data_signal_delete_attempts || !owner_present ||
        !state_present || !generation_index_present || !connection_present ||
        !cookie_connection_present || unexpected_update || unexpected_delete) {
        fail("parser cleanup retired a VALID cursor under mismatched G authority");
    }

    seed_generation(&connection);
    seed_receive_cursor();
    const java_remote_parent_receive_cursor_t busy = receive_cursor;
    if (java_remote_parent_cleanup_receive_cursor(&busy, test_socket_cookie, test_generation) ||
        !receive_cursor_present || !receive_guard_present || find_ambiguity(&stored_state_key) ||
        receive_data_ack_delete_attempts || receive_data_signal_delete_attempts ||
        unexpected_update || unexpected_delete) {
        fail("parser cleanup crossed an exact BUSY guard");
    }

    seed_generation(&connection);
    seed_receive_cursor();
    receive_guard.request_sequence++;
    const java_remote_parent_receive_cursor_t foreign_guard = receive_cursor;
    if (java_remote_parent_cleanup_receive_cursor(
            &foreign_guard, test_socket_cookie, test_generation) ||
        !receive_cursor_present || !receive_guard_present || find_ambiguity(&stored_state_key) ||
        unexpected_update || unexpected_delete) {
        fail("parser cleanup crossed a foreign BUSY guard");
    }

    seed_generation(&connection);
    seed_receive_cursor();
    receive_guard_present = 0;
    replace_receive_cursor_after_guard_update = 1;
    const java_remote_parent_receive_cursor_t predecessor = receive_cursor;
    if (java_remote_parent_cleanup_receive_cursor(
            &predecessor, test_socket_cookie, test_generation) ||
        replace_receive_cursor_after_guard_update || !receive_cursor_present ||
        receive_cursor.request_sequence == predecessor.request_sequence ||
        receive_cursor.generation != test_replacement_generation || receive_guard_present ||
        !find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("parser cleanup overwrote a successor observed after guard acquisition");
    }

    seed_generation(&connection);
    seed_receive_cursor();
    receive_guard_present = 0;
    ambiguities[0].present = 0;
    ambiguity_update_failures = 2;
    const java_remote_parent_receive_cursor_t update_failure = receive_cursor;
    if (java_remote_parent_cleanup_receive_cursor(
            &update_failure, test_socket_cookie, test_generation) ||
        ambiguity_update_failures || !receive_cursor_present ||
        receive_cursor.state != k_java_remote_parent_receive_cursor_retiring ||
        receive_guard_present || find_ambiguity_entry(&stored_state_key) || unexpected_update ||
        unexpected_delete) {
        fail("failed parser M update exposed a guard-free VALID cursor");
    }
    current_task = test_owner;
    java_remote_parent_response_t missing_marker_response = stored_state.response;
    enum java_remote_parent_status missing_marker_status =
        java_remote_parent_retrieve_for_connection(&missing_marker_response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_direct,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie);
    if (missing_marker_status == k_java_remote_parent_status_valid ||
        missing_marker_response.status == k_java_remote_parent_status_valid || !state_present ||
        !generation_index_present || !connection_present || !cookie_connection_present) {
        fail("SDK direct TAKE adopted a parser generation after both M updates failed");
    }

    seed_generation(&connection);
    seed_receive_cursor();
    receive_guard_present = 0;
    ambiguities[0].present = 0;
    drop_ambiguity_after_update = 2;
    const java_remote_parent_receive_cursor_t recheck_failure = receive_cursor;
    if (java_remote_parent_cleanup_receive_cursor(
            &recheck_failure, test_socket_cookie, test_generation) ||
        drop_ambiguity_after_update || !receive_cursor_present ||
        receive_cursor.state != k_java_remote_parent_receive_cursor_retiring ||
        receive_guard_present || find_ambiguity_entry(&stored_state_key) || unexpected_update ||
        unexpected_delete) {
        fail("failed parser M recheck exposed a guard-free VALID cursor");
    }
    current_task = test_owner;
    missing_marker_response = stored_state.response;
    missing_marker_status =
        java_remote_parent_retrieve_for_connection(&missing_marker_response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_direct,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie);
    if (missing_marker_status == k_java_remote_parent_status_valid ||
        missing_marker_response.status == k_java_remote_parent_status_valid || !state_present ||
        !generation_index_present || !connection_present || !cookie_connection_present) {
        fail("SDK direct TAKE adopted a parser generation after both M rechecks failed");
    }

    seed_generation(&connection);
    seed_receive_cursor();
    receive_guard_present = 0;
    receive_guard_update_failures = 1;
    ambiguities[0].present = 0;
    ambiguity_update_failures = 1;
    const java_remote_parent_receive_cursor_t double_fault = receive_cursor;
    if (java_remote_parent_cleanup_receive_cursor(
            &double_fault, test_socket_cookie, test_generation) ||
        receive_guard_update_failures || ambiguity_update_failures || !receive_cursor_present ||
        receive_cursor.state != k_java_remote_parent_receive_cursor_valid ||
        receive_guard_present || !find_ambiguity(&stored_state_key) || unexpected_update ||
        unexpected_delete) {
        fail("guard ERROR plus first M fault left SDK generation authority unfenced");
    }

    seed_generation(&connection);
    seed_receive_cursor();
    receive_guard_present = 0;
    receive_cursor_update_failures = 1;
    const java_remote_parent_receive_cursor_t retiring_update_failure = receive_cursor;
    if (java_remote_parent_cleanup_receive_cursor(
            &retiring_update_failure, test_socket_cookie, test_generation) ||
        receive_cursor_update_failures || !receive_cursor_present ||
        receive_cursor.state != k_java_remote_parent_receive_cursor_valid ||
        !receive_guard_present || !find_ambiguity(&stored_state_key) || unexpected_update ||
        unexpected_delete) {
        fail("failed parser RETIRING update released its exact guard");
    }

    seed_generation(&connection);
    seed_receive_cursor();
    receive_guard_present = 0;
    receive_guard_delete_failures = 1;
    const java_remote_parent_receive_cursor_t guard_release_failure = receive_cursor;
    if (java_remote_parent_cleanup_receive_cursor(
            &guard_release_failure, test_socket_cookie, test_generation) ||
        receive_guard_delete_failures || !receive_cursor_present ||
        receive_cursor.state != k_java_remote_parent_receive_cursor_retiring ||
        !receive_guard_present || !find_ambiguity(&stored_state_key) || unexpected_update ||
        unexpected_delete) {
        fail("failed parser guard release did not retain guarded RETIRING");
    }

    seed_generation(&connection);
    seed_receive_cursor();
    receive_guard_present = 0;
    receive_cursor_delete_failures = 1;
    const java_remote_parent_receive_cursor_t cursor_delete_failure = receive_cursor;
    if (java_remote_parent_cleanup_receive_cursor(
            &cursor_delete_failure, test_socket_cookie, test_generation) ||
        receive_cursor_delete_failures || !receive_cursor_present ||
        receive_cursor.state != k_java_remote_parent_receive_cursor_retiring ||
        receive_guard_present || !find_ambiguity(&stored_state_key) || unexpected_update ||
        unexpected_delete) {
        fail("failed parser cursor delete did not retain RETIRING after M+");
    }

    seed_generation(&connection);
    seed_receive_cursor();
    receive_guard_present = 0;
    receive_cursor.state = k_java_remote_parent_receive_cursor_retiring;
    const java_remote_parent_receive_cursor_t retiring = receive_cursor;
    if (java_remote_parent_cleanup_receive_cursor(&retiring, test_socket_cookie, test_generation) ||
        !receive_cursor_present || receive_guard_present || find_ambiguity(&stored_state_key) ||
        unexpected_update || unexpected_delete) {
        fail("parser cleanup adopted an independently RETIRING cursor");
    }

    seed_generation(&connection);
    java_remote_parent_receive_context_t context = seed_unacked_receive_cursor();
    const java_remote_parent_receive_cursor_t publishing = receive_cursor;
    if (!java_remote_parent_cleanup_receive_cursor(&publishing, test_socket_cookie, 0) ||
        receive_cursor_present || receive_guard_present || receive_data_signal_present ||
        receive_data_ack_delete_attempts != 1 || receive_data_signal_delete_attempts != 1 ||
        context.generation || !unacked_cleanup_left_generation_untouched() || unexpected_update ||
        unexpected_delete) {
        fail("generation-zero parser failure did not drain exact PUBLISHING state");
    }

    seed_generation(&connection);
    context = seed_unacked_receive_cursor();
    const java_remote_parent_receive_cursor_t staged_publishing = receive_cursor;
    if (!java_remote_parent_cleanup_receive_cursor(
            &staged_publishing, test_socket_cookie, test_generation) ||
        receive_cursor_present || receive_guard_present || !find_ambiguity(&stored_state_key) ||
        context.generation || !owner_present || !state_present || !generation_index_present ||
        !connection_present || !cookie_connection_present || unexpected_update ||
        unexpected_delete) {
        fail("ACK failure did not fence staged G before draining PUBLISHING");
    }

    seed_generation(&connection);
    seed_receive_cursor();
    receive_guard_present = 0;
    receive_data_signal_owner = test_owner;
    receive_data_signal_nonce = receive_cursor.data_signal_nonce;
    receive_data_signal_present = 1;
    receive_data_ack_delete_failures = 1;
    receive_data_signal_delete_failures = 1;
    const java_remote_parent_receive_cursor_t signal_failure = receive_cursor;
    if (!java_remote_parent_cleanup_receive_cursor(
            &signal_failure, test_socket_cookie, test_generation) ||
        receive_cursor_present || receive_guard_present || !receive_data_signal_present ||
        receive_data_ack_delete_failures || receive_data_signal_delete_failures ||
        receive_data_ack_delete_attempts != 1 || receive_data_signal_delete_attempts != 1 ||
        !find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("bounded signal faults blocked parser generation fencing");
    }
}

static java_remote_parent_receive_ioctl_workspace_t deferred_replace_workspace(void) {
    java_remote_parent_receive_ioctl_workspace_t workspace = {
        .predecessor = receive_cursor,
        .socket_cookie = test_socket_cookie,
        .connection_netns = test_connection_netns,
        .transition = k_java_remote_parent_receive_ioctl_transition_fence_replace,
        .guard = k_java_remote_parent_receive_guard_acquired,
    };
    workspace.cursor =
        java_remote_parent_receive_cursor_publishing_identity(&test_owner,
                                                              test_process_incarnation,
                                                              receive_cursor.lifecycle_id + 1,
                                                              receive_cursor.request_sequence + 1,
                                                              receive_cursor.data_signal_nonce + 1);
    return workspace;
}

static u8
run_deferred_ioctl_generation_fence(java_remote_parent_receive_ioctl_workspace_t *workspace,
                                    const connection_info_t *connection) {
    if (!java_remote_parent_receive_ioctl_fence_authorized(workspace)) {
        return 0;
    }
    java_remote_parent_receive_cursor_t *target =
        java_remote_parent_receive_ioctl_fence_cursor(workspace);
    java_remote_parent_cleanup_receive_cursor_signal(target);
    u8 fenced = java_remote_parent_receive_generation_already_fenced(target,
                                                                     connection,
                                                                     workspace->connection_netns,
                                                                     test_connection_netns_cookie,
                                                                     workspace->socket_cookie);
    if (!fenced) {
        const java_remote_parent_key_t generation_key =
            java_remote_parent_state_key(&target->owner, target->generation);
        fenced = java_remote_parent_cleanup_exact_receive_zero_alias(&generation_key,
                                                                     target->process_incarnation,
                                                                     connection,
                                                                     workspace->connection_netns,
                                                                     workspace->socket_cookie);
        if (!fenced) {
            fenced = java_remote_parent_detach_exact_receive_aliased(&generation_key,
                                                                     target->process_incarnation,
                                                                     connection,
                                                                     workspace->connection_netns,
                                                                     workspace->socket_cookie);
        }
    }
    if (!fenced) {
        fenced = java_remote_parent_fence_receive_cursor_ambiguous(target, target->generation);
    }
    if (!fenced && target->generation) {
        fenced = java_remote_parent_fence_receive_cursor_ambiguous(target, target->generation);
    }
    return fenced;
}

static void test_deferred_ioctl_transition_is_exact_and_fail_closed(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    java_remote_parent_receive_context_t fence_context = {0};
    java_remote_parent_receive_ioctl_fence_context_init(&fence_context,
                                                        test_connection_netns_cookie);
    if (java_remote_parent_receive_ioctl_fence_context_cookie(&fence_context) !=
        test_connection_netns_cookie) {
        fail("exact transition fence context rejected its live netns cookie");
    }
    java_remote_parent_receive_ioctl_fence_context_t *malformed_fence_context =
        (java_remote_parent_receive_ioctl_fence_context_t *)&fence_context;
    malformed_fence_context->tag ^= 1;
    if (java_remote_parent_receive_ioctl_fence_context_cookie(&fence_context)) {
        fail("transition fence context accepted a corrupt tag");
    }
    java_remote_parent_receive_ioctl_fence_context_init(&fence_context,
                                                        test_connection_netns_cookie);
    malformed_fence_context->reserved = 1;
    if (java_remote_parent_receive_ioctl_fence_context_cookie(&fence_context)) {
        fail("transition fence context accepted reserved metadata");
    }
    java_remote_parent_receive_ioctl_fence_context_init(&fence_context,
                                                        test_connection_netns_cookie);
    malformed_fence_context->zero_tail[sizeof(malformed_fence_context->zero_tail) - 1] = 1;
    if (java_remote_parent_receive_ioctl_fence_context_cookie(&fence_context)) {
        fail("transition fence context accepted a corrupt zero tail");
    }

    // The normal gate may finish a sequential zero-alias G before phase B.
    // Strict final-form recognition must not recreate a non-evicting M+.
    seed_generation(&connection);
    seed_receive_cursor();
    java_remote_parent_receive_ioctl_workspace_t workspace = deferred_replace_workspace();
    java_remote_parent_begin_data_receive();
    if (!owner_cleanup_payload_absent() || find_ambiguity_entry(&stored_state_key) ||
        claim_present || detach_guard_present || !receive_cursor_present ||
        !receive_guard_present) {
        fail("receive gate did not finish the old zero-alias generation");
    }
    if (!run_deferred_ioctl_generation_fence(&workspace, &connection) ||
        find_ambiguity_entry(&stored_state_key) ||
        !java_remote_parent_complete_receive_ioctl_transition(&workspace, 1) ||
        workspace.transition != k_java_remote_parent_receive_ioctl_transition_ready ||
        !receive_cursor_present || receive_guard_present ||
        memcmp(&receive_cursor, &workspace.cursor, sizeof(receive_cursor)) != 0) {
        fail("phase B recreated M after strict terminal-free gate cleanup");
    }

    seed_generation(&connection);
    seed_receive_cursor();
    workspace = deferred_replace_workspace();
    receive_data_signal_owner = test_owner;
    receive_data_signal_nonce = workspace.predecessor.data_signal_nonce;
    receive_data_signal_present = 1;
    if (!run_deferred_ioctl_generation_fence(&workspace, &connection) ||
        !java_remote_parent_complete_receive_ioctl_transition(&workspace, 1) ||
        workspace.transition != k_java_remote_parent_receive_ioctl_transition_ready ||
        workspace.guard || !receive_cursor_present || receive_guard_present ||
        memcmp(&receive_cursor, &workspace.cursor, sizeof(receive_cursor)) != 0 ||
        !receive_data_signal_present ||
        receive_data_signal_nonce != workspace.cursor.data_signal_nonce || owner_present ||
        fallback_present || state_present || generation_index_present || connection_present ||
        cookie_connection_present || claim_present || detach_guard_present ||
        find_ambiguity_entry(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("deferred START did not remove zero-alias G before exact cursor replacement");
    }
    java_remote_parent_receive_context_t prepared_context = {
        .owner_tid = workspace.cursor.owner.tid,
        .owner_pid = workspace.cursor.owner.pid,
        .owner_ns = workspace.cursor.owner.ns,
        .process_incarnation = workspace.cursor.process_incarnation,
        .lifecycle_id = workspace.cursor.lifecycle_id,
        .request_sequence = workspace.cursor.request_sequence,
        .data_signal_nonce = workspace.cursor.data_signal_nonce,
        .generation = workspace.cursor.generation,
        .action = k_java_remote_parent_receive_action_http1_start,
    };
    if (!java_remote_parent_receive_ioctl_ready_context_exact(&workspace, &prepared_context)) {
        fail("prepared START context did not match its exact READY scratch");
    }
    prepared_context.action = k_java_remote_parent_receive_action_http1_continue;
    if (java_remote_parent_receive_ioctl_ready_context_exact(&workspace, &prepared_context)) {
        fail("prepared payload adopted START scratch as CONTINUE");
    }
    prepared_context.action = k_java_remote_parent_receive_action_http1_start;
    prepared_context.reserved2[0] = 1;
    if (java_remote_parent_receive_ioctl_ready_context_exact(&workspace, &prepared_context)) {
        fail("prepared payload accepted corrupted reserved scratch");
    }
    java_remote_parent_receive_cursor_t snapshot = {0};
    const pid_key_t process = java_process_key(&test_owner);
    if (java_remote_parent_receive_cursor_continue(test_socket_cookie,
                                                   &process,
                                                   test_process_incarnation,
                                                   workspace.cursor.lifecycle_id,
                                                   workspace.cursor.request_sequence,
                                                   &snapshot) ||
        java_remote_parent_receive_cursor_start(test_socket_cookie,
                                                &test_owner,
                                                test_process_incarnation,
                                                workspace.cursor.lifecycle_id + 1,
                                                workspace.cursor.request_sequence + 1,
                                                workspace.cursor.data_signal_nonce + 1)) {
        fail("immediate next request adopted an unacknowledged replacement cursor");
    }
    java_remote_parent_cleanup(&test_owner);
    memset(&snapshot, 0, sizeof(snapshot));
    if (!owner_cleanup_payload_absent() || find_ambiguity_entry(&stored_state_key) ||
        !receive_cursor_present ||
        !java_remote_parent_receive_cursor_ack_generation(
            test_socket_cookie, &workspace.cursor, test_replacement_generation) ||
        !java_remote_parent_receive_cursor_continue(test_socket_cookie,
                                                    &process,
                                                    test_process_incarnation,
                                                    workspace.cursor.lifecycle_id,
                                                    workspace.cursor.request_sequence,
                                                    &snapshot) ||
        snapshot.generation != test_replacement_generation) {
        fail("zero-alias cleanup did not leave immediate successor recovery unblocked");
    }

    seed_generation(&connection);
    seed_receive_cursor();
    seed_exact_receive_aliases(1);
    workspace = deferred_replace_workspace();
    java_remote_parent_begin_data_receive();
    if (owner_present || fallback_present || !state_present || stored_state.aliases != 1 ||
        !generation_index_present || !connection_present || !cookie_connection_present ||
        !task_present || claim_present || detach_guard_present ||
        !find_ambiguity_entry(&stored_state_key) || find_ambiguity(&stored_state_key)) {
        fail("receive gate did not preserve the authorized aliased generation");
    }
    if (!run_deferred_ioctl_generation_fence(&workspace, &connection) ||
        !java_remote_parent_complete_receive_ioctl_transition(&workspace, 1) ||
        workspace.transition != k_java_remote_parent_receive_ioctl_transition_ready ||
        workspace.guard || !receive_cursor_present || receive_guard_present ||
        memcmp(&receive_cursor, &workspace.cursor, sizeof(receive_cursor)) != 0 || owner_present ||
        fallback_present || !state_present || stored_state.aliases != 1 ||
        !generation_index_present || connection_present || cookie_connection_present ||
        !task_present || claim_present || detach_guard_present ||
        !find_ambiguity_entry(&stored_state_key) || find_ambiguity(&stored_state_key) ||
        unexpected_update || unexpected_delete) {
        fail("aliased deferred START did not detach only its direct cursors");
    }
    java_remote_parent_resolution_t aliased_resolution = {0};
    java_remote_parent_resolve_exact(&aliased_resolution, &test_owner, test_generation, 1);
    if (!aliased_resolution.found || aliased_resolution.ambiguous ||
        !same_key(&aliased_resolution.key, &stored_state_key, sizeof(stored_state_key)) ||
        owner_present || fallback_present || !state_present || stored_state.aliases != 1 ||
        !generation_index_present || connection_present || cookie_connection_present ||
        !task_present || !find_ambiguity_entry(&stored_state_key) ||
        find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("aliased detach revoked exact SDK alias authority");
    }

    const java_remote_parent_incoming_t second_incoming = prepare_exact_stage_incoming(&connection);
    stage_updates_enabled = 1;
    const u64 second_generation = java_remote_parent_stage_incoming(&connection,
                                                                    test_connection_netns,
                                                                    test_connection_netns_cookie,
                                                                    test_socket_cookie,
                                                                    &second_incoming);
    stage_updates_enabled = 0;
    if (!second_generation || second_generation != test_replacement_generation || !owner_present ||
        stored_owner.generation != second_generation ||
        stored_owner.lifecycle != k_java_remote_parent_lifecycle_active || !fallback_present ||
        java_remote_parent_le64_to_cpu(stored_fallback.generation_le) != second_generation ||
        !state_present || stored_state.aliases != 1 || !generation_index_present ||
        connection_present || cookie_connection_present || !task_present ||
        !replacement_state_present || replacement_state_key.generation != second_generation ||
        !replacement_generation_index_present ||
        replacement_generation_index_key.generation != second_generation ||
        !replacement_connection_present || replacement_connection.generation != second_generation ||
        !replacement_cookie_connection_present ||
        replacement_cookie_connection.generation != second_generation || claim_present ||
        detach_guard_present || !find_ambiguity_entry(&stored_state_key) ||
        find_ambiguity(&stored_state_key) || !find_ambiguity_entry(&replacement_state_key) ||
        find_ambiguity(&replacement_state_key) || !stage_ack_present ||
        stage_ack_key.nonce != workspace.cursor.data_signal_nonce || stage_ack_key.reserved ||
        stage_ack.reserved || stage_ack.generation != second_generation ||
        memcmp(&stage_ack.connection, &connection, sizeof(connection)) != 0 ||
        stage_ack.connection_netns != test_connection_netns ||
        stats[k_java_remote_parent_stat_stage_valid] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("aliased detach did not admit a simultaneous second socket generation");
    }
    const java_remote_parent_response_t expected_second_response = replacement_state.response;
    const java_remote_parent_connection_t expected_second_connection = replacement_connection;
    const java_remote_parent_connection_t expected_second_cookie_connection =
        replacement_cookie_connection;
    if (!java_remote_parent_receive_cursor_ack_generation(
            test_socket_cookie, &workspace.cursor, stage_ack.generation)) {
        fail("real second STAGE acknowledgement did not commit its exact cursor generation");
    }
    current_task = test_child;
    java_remote_parent_response_t aliased_response = stored_state.response;
    const enum java_remote_parent_status aliased_status =
        java_remote_parent_retrieve_for_connection(&aliased_response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   second_generation,
                                                   test_socket_cookie);
    if (aliased_status != k_java_remote_parent_status_valid ||
        aliased_response.status != k_java_remote_parent_status_valid ||
        java_remote_parent_le64_to_cpu(aliased_response.generation_le) != test_generation ||
        state_present || generation_index_present || connection_present ||
        cookie_connection_present || !task_present || claim_present || detach_guard_present ||
        find_ambiguity_entry(&stored_state_key) || !owner_present ||
        stored_owner.generation != second_generation || !fallback_present ||
        java_remote_parent_le64_to_cpu(stored_fallback.generation_le) != second_generation ||
        !replacement_state_present ||
        memcmp(&replacement_state.response,
               &expected_second_response,
               sizeof(expected_second_response)) != 0 ||
        !replacement_generation_index_present || !replacement_connection_present ||
        memcmp(&replacement_connection,
               &expected_second_connection,
               sizeof(expected_second_connection)) != 0 ||
        !replacement_cookie_connection_present ||
        memcmp(&replacement_cookie_connection,
               &expected_second_cookie_connection,
               sizeof(expected_second_cookie_connection)) != 0 ||
        !find_ambiguity_entry(&replacement_state_key) || find_ambiguity(&replacement_state_key) ||
        !terminal_present || stored_terminal.generation != test_generation ||
        stored_terminal.lifecycle != k_java_remote_parent_lifecycle_consumed ||
        stats[k_java_remote_parent_stat_take_valid] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("aliased detach did not preserve one exact SDK task TAKE");
    }

    const pid_key_t aliased_process = java_process_key(&test_owner);
    java_remote_parent_receive_cursor_t continued = {0};
    if (!java_remote_parent_receive_cursor_continue(test_socket_cookie,
                                                    &aliased_process,
                                                    test_process_incarnation,
                                                    workspace.cursor.lifecycle_id,
                                                    workspace.cursor.request_sequence,
                                                    &continued) ||
        continued.generation != second_generation) {
        fail("real second STAGE ACK did not enable exact cursor CONTINUE");
    }

    current_task = test_owner;
    java_remote_parent_response_t second_response = expected_second_response;
    if (java_remote_parent_retrieve_for_connection(&second_response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_direct,
                                                   &connection,
                                                   test_connection_netns,
                                                   second_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_valid ||
        second_response.status != k_java_remote_parent_status_valid ||
        java_remote_parent_le64_to_cpu(second_response.generation_le) != second_generation ||
        memcmp(second_response.trace_id,
               expected_second_response.trace_id,
               sizeof(second_response.trace_id)) != 0 ||
        memcmp(second_response.span_id,
               expected_second_response.span_id,
               sizeof(second_response.span_id)) != 0 ||
        second_response.flags != expected_second_response.flags || owner_present ||
        fallback_present || replacement_state_present || replacement_generation_index_present ||
        replacement_connection_present || replacement_cookie_connection_present || claim_present ||
        detach_guard_present || find_ambiguity_entry(&replacement_state_key) || !terminal_present ||
        stored_terminal.generation != second_generation ||
        stored_terminal.lifecycle != k_java_remote_parent_lifecycle_consumed ||
        stats[k_java_remote_parent_stat_take_valid] != 2 || unexpected_update ||
        unexpected_delete) {
        fail("old alias TAKE disturbed the directly retrievable successor generation");
    }

    seed_generation(&connection);
    seed_receive_cursor();
    seed_exact_receive_aliases(1);
    workspace = deferred_replace_workspace();
    owner_delete_failures = 2;
    if (!run_deferred_ioctl_generation_fence(&workspace, &connection) || owner_delete_failures ||
        !java_remote_parent_complete_receive_ioctl_transition(&workspace, 1) ||
        workspace.transition != k_java_remote_parent_receive_ioctl_transition_ready ||
        !receive_cursor_present || receive_guard_present ||
        memcmp(&receive_cursor, &workspace.cursor, sizeof(receive_cursor)) != 0 || !owner_present ||
        fallback_present || !state_present || stored_state.aliases != 1 ||
        !generation_index_present || !connection_present || !cookie_connection_present ||
        !task_present || !claim_present || !detach_guard_present ||
        !find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("aliased destructive fault did not retain an exact M+/claim/guard fence");
    }
    current_task = test_child;
    java_remote_parent_response_t fault_response = stored_state.response;
    if (java_remote_parent_retrieve_for_connection(&fault_response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_overload ||
        fault_response.status != k_java_remote_parent_status_overload || !claim_present ||
        !detach_guard_present || !find_ambiguity(&stored_state_key) || !state_present ||
        !generation_index_present || stats[k_java_remote_parent_stat_take_overload] != 1 ||
        unexpected_update || unexpected_delete) {
        fail("aliased destructive fault exposed a wrong SDK parent");
    }

    seed_generation(&connection);
    seed_receive_cursor();
    workspace = deferred_replace_workspace();
    // Model a strict completed-by-TAKE predecessor between A and B. Phase B
    // recognizes the final form without recreating M, and phase C may replace
    // only the guarded old cursor; the completed terminal is untouched.
    owner_present = 0;
    fallback_present = 0;
    state_present = 0;
    generation_index_present = 0;
    connection_present = 0;
    cookie_connection_present = 0;
    ambiguities[0].present = 0;
    terminal_present = 1;
    stored_terminal = (java_remote_parent_terminal_t){
        .generation = test_generation,
        .observed_monotime_ns = test_observed_monotime_ns,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_consumed,
    };
    const java_remote_parent_terminal_t completed_terminal = stored_terminal;
    if (!run_deferred_ioctl_generation_fence(&workspace, &connection) ||
        !java_remote_parent_complete_receive_ioctl_transition(&workspace, 1) ||
        !receive_cursor_present || receive_guard_present ||
        memcmp(&receive_cursor, &workspace.cursor, sizeof(receive_cursor)) != 0 ||
        find_ambiguity_entry(&stored_state_key) || !terminal_present ||
        memcmp(&stored_terminal, &completed_terminal, sizeof(completed_terminal)) != 0) {
        fail("deferred START disturbed a predecessor completed by TAKE");
    }

    seed_generation(&connection);
    seed_receive_cursor();
    workspace = deferred_replace_workspace();
    java_remote_parent_receive_ioctl_workspace_t malformed = workspace;
    malformed.transition = 0xff;
    if (java_remote_parent_receive_ioctl_fence_authorized(&malformed)) {
        fail("deferred fence accepted an unknown transition");
    }
    malformed = workspace;
    malformed.reserved[0] = 1;
    if (java_remote_parent_receive_ioctl_fence_authorized(&malformed)) {
        fail("deferred fence accepted nonzero reserved scratch");
    }
    malformed = workspace;
    malformed.guard = k_java_remote_parent_receive_guard_error;
    if (java_remote_parent_receive_ioctl_fence_authorized(&malformed)) {
        fail("deferred replacement accepted missing guard authority");
    }

    seed_generation(&connection);
    seed_receive_cursor();
    workspace = deferred_replace_workspace();
    java_remote_parent_begin_data_receive();
    if (!owner_cleanup_payload_absent() || find_ambiguity_entry(&stored_state_key)) {
        fail("could not seed strict-final successor race");
    }
    if (!run_deferred_ioctl_generation_fence(&workspace, &connection)) {
        fail("could not seed deferred successor race fence");
    }
    java_remote_parent_receive_cursor_t successor = receive_cursor;
    successor.request_sequence++;
    successor.generation = test_replacement_generation;
    receive_cursor = successor;
    if (java_remote_parent_complete_receive_ioctl_transition(&workspace, 1) ||
        memcmp(&receive_cursor, &successor, sizeof(successor)) != 0 || !receive_guard_present ||
        owner_present || fallback_present || state_present || generation_index_present ||
        connection_present || cookie_connection_present ||
        find_ambiguity_entry(&stored_state_key)) {
        fail("phase C overwrote a foreign successor after strict-final recognition");
    }

    seed_generation(&connection);
    seed_receive_cursor();
    workspace = deferred_replace_workspace();
    seed_exact_receive_aliases(1);
    connection_present = 0;
    ambiguities[0].present = 0;
    ambiguity_update_failures = 2;
    if (run_deferred_ioctl_generation_fence(&workspace, &connection) || ambiguity_update_failures ||
        java_remote_parent_complete_receive_ioctl_transition(&workspace, 0) ||
        !receive_cursor_present ||
        receive_cursor.state != k_java_remote_parent_receive_cursor_retiring ||
        receive_guard_present || find_ambiguity_entry(&stored_state_key) || !owner_present ||
        !fallback_present || !state_present || stored_state.aliases != 1 ||
        !generation_index_present || connection_present || !cookie_connection_present) {
        fail("bounded deferred M failure exposed a guard-free VALID cursor");
    }
    current_task = test_child;
    java_remote_parent_response_t deferred_missing_marker_response = stored_state.response;
    enum java_remote_parent_status deferred_missing_marker_status =
        java_remote_parent_retrieve_for_connection(&deferred_missing_marker_response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie);
    if (deferred_missing_marker_status == k_java_remote_parent_status_valid ||
        deferred_missing_marker_response.status == k_java_remote_parent_status_valid ||
        !state_present || !generation_index_present || connection_present ||
        !cookie_connection_present || !task_present) {
        fail("SDK task TAKE adopted a partial deferred generation without M");
    }
    current_task = test_owner;
    deferred_missing_marker_response = stored_state.response;
    deferred_missing_marker_status =
        java_remote_parent_retrieve_for_connection(&deferred_missing_marker_response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_direct,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie);
    if (deferred_missing_marker_status == k_java_remote_parent_status_valid ||
        deferred_missing_marker_response.status == k_java_remote_parent_status_valid ||
        !state_present || !generation_index_present || connection_present ||
        !cookie_connection_present) {
        fail("SDK direct TAKE adopted a partial deferred generation without M");
    }

    seed_generation(&connection);
    seed_receive_cursor();
    workspace = deferred_replace_workspace();
    if (!run_deferred_ioctl_generation_fence(&workspace, &connection)) {
        fail("could not seed deferred replacement fault");
    }
    receive_cursor_update_failures = 1;
    if (java_remote_parent_complete_receive_ioctl_transition(&workspace, 1) ||
        receive_cursor_present || receive_guard_present || owner_present || fallback_present ||
        state_present || generation_index_present || connection_present ||
        cookie_connection_present || find_ambiguity_entry(&stored_state_key)) {
        fail("failed deferred replacement did not terminally drain its predecessor");
    }

    seed_generation(&connection);
    seed_receive_cursor();
    workspace = deferred_replace_workspace();
    if (!run_deferred_ioctl_generation_fence(&workspace, &connection)) {
        fail("could not seed deferred guard-release fault");
    }
    receive_guard_delete_failures = 2;
    if (java_remote_parent_complete_receive_ioctl_transition(&workspace, 1) ||
        !receive_cursor_present ||
        receive_cursor.state != k_java_remote_parent_receive_cursor_retiring ||
        !receive_guard_present || owner_present || fallback_present || state_present ||
        generation_index_present || connection_present || cookie_connection_present ||
        find_ambiguity_entry(&stored_state_key)) {
        fail("failed deferred guard release exposed a replacement PUBLISHING cursor");
    }

    seed_generation(&connection);
    seed_receive_cursor();
    workspace = (java_remote_parent_receive_ioctl_workspace_t){
        .cursor = receive_cursor,
        .socket_cookie = test_socket_cookie,
        .connection_netns = test_connection_netns,
        .transition = k_java_remote_parent_receive_ioctl_transition_fence_retire,
        .guard = k_java_remote_parent_receive_guard_acquired,
    };
    if (!run_deferred_ioctl_generation_fence(&workspace, &connection) ||
        java_remote_parent_complete_receive_ioctl_transition(&workspace, 1) ||
        receive_cursor_present || receive_guard_present || owner_present || fallback_present ||
        state_present || generation_index_present || connection_present ||
        cookie_connection_present || claim_present || detach_guard_present ||
        find_ambiguity_entry(&stored_state_key)) {
        fail("deferred RESET did not remove its exact zero-alias generation");
    }

    seed_generation(&connection);
    seed_receive_cursor();
    receive_guard_present = 0;
    workspace = (java_remote_parent_receive_ioctl_workspace_t){
        .predecessor = receive_cursor,
        .socket_cookie = test_socket_cookie,
        .connection_netns = test_connection_netns,
        .transition = k_java_remote_parent_receive_ioctl_transition_fence_abort,
        .guard = k_java_remote_parent_receive_guard_error,
    };
    const java_remote_parent_receive_cursor_t guard_error_cursor = receive_cursor;
    if (!run_deferred_ioctl_generation_fence(&workspace, &connection) ||
        java_remote_parent_complete_receive_ioctl_transition(&workspace, 1) ||
        !receive_cursor_present || receive_guard_present ||
        memcmp(&receive_cursor, &guard_error_cursor, sizeof(receive_cursor)) != 0 ||
        owner_present || fallback_present || state_present || generation_index_present ||
        connection_present || cookie_connection_present || claim_present || detach_guard_present ||
        find_ambiguity_entry(&stored_state_key)) {
        fail("guard-ERROR RESET failed to clean exact G without cursor mutation");
    }
}

static u8 run_close_receive_cursor(u64 socket_cookie,
                                   const connection_info_t *connection,
                                   u32 connection_netns,
                                   u64 connection_netns_cookie) {
    const u64 invocation_id = 0x7172737475767778ULL;
    java_remote_parent_close_workspace_t *workspace =
        java_remote_parent_close_workspace_acquire(invocation_id);
    if (!workspace) {
        return 0;
    }
    workspace->socket_cookie = socket_cookie;
    workspace->connection_netns_cookie = connection_netns_cookie;
    workspace->connection_netns = connection_netns;
    workspace->connection_valid = connection != NULL;
    if (connection) {
        workspace->process_connection.conn = *connection;
    }
    const u8 result = java_remote_parent_close_receive_cursor(workspace, invocation_id);
    last_close_workspace_cursor = workspace->cursor;
    java_remote_parent_close_workspace_release(workspace, invocation_id);
    return result;
}

static int close_workspace_payload_zero(void) {
    const java_remote_parent_close_workspace_t zero = {0};
    return memcmp(&close_workspace.socket_cookie,
                  &zero.socket_cookie,
                  sizeof(close_workspace) -
                      offsetof(java_remote_parent_close_workspace_t, socket_cookie)) == 0;
}

static void test_close_workspace_is_guarded_and_zeroized(void) {
    const u64 invocation_id = 0x1112131415161718ULL;
    const u64 foreign_invocation_id = 0x2122232425262728ULL;

    memset(&close_workspace, 0xa5, sizeof(close_workspace));
    close_workspace.invocation_id = 0;
    java_remote_parent_close_workspace_t *workspace =
        java_remote_parent_close_workspace_acquire(invocation_id);
    if (workspace != &close_workspace || workspace->invocation_id != invocation_id ||
        !close_workspace_payload_zero()) {
        fail("close workspace acquisition did not publish ownership before zeroizing payload");
    }

    memset(&workspace->socket_cookie,
           0x5a,
           sizeof(*workspace) - offsetof(java_remote_parent_close_workspace_t, socket_cookie));
    const java_remote_parent_close_workspace_t occupied = *workspace;
    if (java_remote_parent_close_workspace_acquire(invocation_id) ||
        memcmp(workspace, &occupied, sizeof(occupied)) != 0 ||
        java_remote_parent_close_workspace_acquire(foreign_invocation_id) ||
        memcmp(workspace, &occupied, sizeof(occupied)) != 0) {
        fail("close workspace allowed nested reuse or mutated the live owner payload");
    }
    java_remote_parent_close_workspace_release(workspace, foreign_invocation_id);
    if (memcmp(workspace, &occupied, sizeof(occupied)) != 0) {
        fail("foreign close workspace release mutated the live owner payload");
    }
    java_remote_parent_close_workspace_release(workspace, invocation_id);
    const java_remote_parent_close_workspace_t zero = {0};
    if (memcmp(&close_workspace, &zero, sizeof(zero)) != 0) {
        fail("close workspace owner release did not clear payload before ownership");
    }

    workspace = java_remote_parent_close_workspace_acquire(invocation_id);
    if (workspace != &close_workspace || workspace->invocation_id != invocation_id ||
        !close_workspace_payload_zero()) {
        fail("close workspace owner could not reacquire a clean slot");
    }
    workspace->socket_cookie = test_socket_cookie;
    java_remote_parent_close_workspace_release(workspace, invocation_id);
    if (memcmp(&close_workspace, &zero, sizeof(zero)) != 0) {
        fail("reacquired close workspace did not return to an all-zero state");
    }

    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_receive_cursor();
    memset(&close_workspace, 0x6b, sizeof(close_workspace));
    close_workspace.invocation_id = foreign_invocation_id;
    const java_remote_parent_close_workspace_t busy_workspace = close_workspace;
    const java_remote_parent_receive_cursor_t busy_cursor = receive_cursor;
    const java_remote_parent_receive_cursor_t busy_guard = receive_guard;
    const java_remote_parent_owner_t busy_owner = stored_owner;
    const java_remote_parent_state_t busy_state = stored_state;
    const java_remote_parent_generation_index_t busy_index = stored_generation_index;
    const java_remote_parent_connection_t busy_connection = stored_connection;
    const java_remote_parent_connection_t busy_cookie_connection = stored_cookie_connection;
    const java_remote_parent_response_t busy_fallback = stored_fallback;
    const ambiguity_entry_t busy_ambiguities[3] = {ambiguities[0], ambiguities[1], ambiguities[2]};
    if (run_close_receive_cursor(
            test_socket_cookie, &connection, test_connection_netns, test_connection_netns_cookie) ||
        memcmp(&close_workspace, &busy_workspace, sizeof(busy_workspace)) != 0 ||
        memcmp(&receive_cursor, &busy_cursor, sizeof(busy_cursor)) != 0 ||
        memcmp(&receive_guard, &busy_guard, sizeof(busy_guard)) != 0 ||
        memcmp(&stored_owner, &busy_owner, sizeof(busy_owner)) != 0 ||
        memcmp(&stored_state, &busy_state, sizeof(busy_state)) != 0 ||
        memcmp(&stored_generation_index, &busy_index, sizeof(busy_index)) != 0 ||
        memcmp(&stored_connection, &busy_connection, sizeof(busy_connection)) != 0 ||
        memcmp(&stored_cookie_connection,
               &busy_cookie_connection,
               sizeof(busy_cookie_connection)) != 0 ||
        memcmp(&stored_fallback, &busy_fallback, sizeof(busy_fallback)) != 0 ||
        memcmp(ambiguities, busy_ambiguities, sizeof(busy_ambiguities)) != 0 ||
        !receive_cursor_present || !receive_guard_present || !owner_present || !state_present ||
        !generation_index_present || !connection_present || !cookie_connection_present ||
        !fallback_present || unexpected_update || unexpected_delete) {
        fail("busy close workspace path mutated cursor or generation authority");
    }
    java_remote_parent_close_workspace_release(&close_workspace, foreign_invocation_id);
    if (memcmp(&close_workspace, &zero, sizeof(zero)) != 0) {
        fail("busy close workspace fixture did not release cleanly");
    }
}

static void test_close_final_form_rejects_zero_generation_cursors(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    owner_present = 0;
    state_present = 0;
    generation_index_present = 0;
    connection_present = 0;
    cookie_connection_present = 0;
    fallback_present = 0;
    claim_present = 0;
    detach_guard_present = 0;
    terminal_present = 0;
    memset(ambiguities, 0, sizeof(ambiguities));

    java_remote_parent_receive_cursor_t cursor =
        java_remote_parent_receive_cursor_publishing_identity(&test_owner,
                                                              test_process_incarnation,
                                                              0x1020304050607080ULL,
                                                              0x1122334455667788ULL,
                                                              0x8877665544332211ULL);
    if (java_remote_parent_receive_generation_already_fenced(&cursor,
                                                             &connection,
                                                             test_connection_netns,
                                                             test_connection_netns_cookie,
                                                             test_socket_cookie)) {
        fail("final-form recognition accepted generation-zero PUBLISHING");
    }
    cursor.state = k_java_remote_parent_receive_cursor_retiring;
    if (java_remote_parent_receive_generation_already_fenced(&cursor,
                                                             &connection,
                                                             test_connection_netns,
                                                             test_connection_netns_cookie,
                                                             test_socket_cookie)) {
        fail("final-form recognition accepted generation-zero RETIRING");
    }
}

static void test_close_retiring_retries_are_state_exact(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    // Baseline cleanup has already established terminal-free final form. A
    // pre-existing RETIRING cursor must be recognized and survive one cursor
    // delete fault without attempting a second state transition.
    seed_generation(&connection);
    seed_receive_cursor();
    java_remote_parent_cleanup(&test_owner);
    receive_cursor.state = k_java_remote_parent_receive_cursor_retiring;
    receive_guard.state = k_java_remote_parent_receive_cursor_retiring;
    receive_cursor_delete_failures = 1;
    if (!run_close_receive_cursor(
            test_socket_cookie, &connection, test_connection_netns, test_connection_netns_cookie) ||
        receive_cursor_present || receive_guard_present || receive_cursor_delete_failures ||
        last_close_workspace_cursor.state != k_java_remote_parent_receive_cursor_retiring ||
        find_ambiguity_entry(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("close did not recognize and retry an exact pre-existing RETIRING cursor");
    }

    // If RETIRING publication fails, the close caller must keep its immutable
    // VALID snapshot. Persistent guard-delete faults then leave both exact map
    // records byte-for-byte unchanged instead of inventing a RETIRING identity.
    seed_generation(&connection);
    seed_receive_cursor();
    const java_remote_parent_receive_cursor_t expected_cursor = receive_cursor;
    const java_remote_parent_receive_cursor_t expected_guard = receive_guard;
    receive_guard_delete_failures = 4;
    receive_cursor_update_failures = 1;
    if (run_close_receive_cursor(
            test_socket_cookie, &connection, test_connection_netns, test_connection_netns_cookie) ||
        !receive_cursor_present || !receive_guard_present || receive_guard_delete_failures ||
        receive_cursor_update_failures ||
        memcmp(&receive_cursor, &expected_cursor, sizeof(expected_cursor)) != 0 ||
        memcmp(&receive_guard, &expected_guard, sizeof(expected_guard)) != 0 ||
        memcmp(&last_close_workspace_cursor, &expected_cursor, sizeof(expected_cursor)) != 0 ||
        unexpected_update || unexpected_delete) {
        fail("failed close RETIRING publication mutated its immutable VALID identity");
    }
}

static void test_independent_close_hook_orders_are_exactly_fenced(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};

    // Java close first: execute the production close branch. RESET removes the
    // direct zero-alias generation and terminally deletes cursor plus guard.
    // The baseline close cleanup that follows is an idempotent no-op.
    seed_generation(&connection);
    seed_receive_cursor();
    if (!run_close_receive_cursor(test_socket_cookie,
                                  &connection,
                                  test_connection_netns,
                                  stored_connection.netns_cookie) ||
        receive_cursor_present || receive_guard_present || owner_present || fallback_present ||
        state_present || generation_index_present || connection_present ||
        cookie_connection_present || claim_present || detach_guard_present || terminal_present ||
        find_ambiguity_entry(&stored_state_key)) {
        fail("production Java-first close did not fence and delete cursor plus guard");
    }
    java_remote_parent_cleanup(&test_owner);
    if (receive_cursor_present || receive_guard_present || owner_present || fallback_present ||
        state_present || generation_index_present || connection_present ||
        cookie_connection_present || claim_present || detach_guard_present || terminal_present ||
        find_ambiguity_entry(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("baseline cleanup after Java-first close recreated generation state");
    }

    // Baseline close first: complete terminal-free cleanup is a strict
    // postcondition. The production Java branch must remove cursor plus guard
    // without recreating M+.
    seed_generation(&connection);
    seed_receive_cursor();
    java_remote_parent_cleanup(&test_owner);
    if (!run_close_receive_cursor(test_socket_cookie,
                                  &connection,
                                  test_connection_netns,
                                  stored_connection.netns_cookie) ||
        receive_cursor_present || receive_guard_present || owner_present || fallback_present ||
        state_present || generation_index_present || connection_present ||
        cookie_connection_present || claim_present || detach_guard_present || terminal_present ||
        find_ambiguity_entry(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("production Java close did not accept baseline-first terminal-free cleanup");
    }

    // A completed TAKE deliberately retains its exact terminal. The Java hook
    // must recognize that final form and delete cursor plus guard without M+.
    seed_completed_exact_receive_take(&connection);
    seed_receive_cursor();
    if (!run_close_receive_cursor(test_socket_cookie,
                                  &connection,
                                  test_connection_netns,
                                  stored_connection.netns_cookie) ||
        receive_cursor_present || receive_guard_present ||
        find_ambiguity_entry(&stored_state_key) || !terminal_present || unexpected_update ||
        unexpected_delete) {
        fail("production Java close did not accept baseline-first completed TAKE");
    }

    // An incomplete baseline cleanup is neither accepted final form. The
    // production branch must preserve its surviving connection under M+ while
    // still deleting cursor plus guard.
    seed_generation(&connection);
    seed_receive_cursor();
    owner_present = 0;
    fallback_present = 0;
    state_present = 0;
    generation_index_present = 0;
    cookie_connection_present = 0;
    ambiguities[0].present = 0;
    if (!run_close_receive_cursor(test_socket_cookie,
                                  &connection,
                                  test_connection_netns,
                                  stored_connection.netns_cookie) ||
        receive_cursor_present || receive_guard_present || !find_ambiguity(&stored_state_key) ||
        !connection_present || unexpected_update || unexpected_delete) {
        fail("production partial-close branch did not fence fail closed with M+");
    }

    // A malformed/legacy partial generation can lack the normal pre-reserved
    // M slot, and a saturated map can then reject insertion. The generation is
    // already non-authoritative without clean M reservation; final fput must
    // still reclaim cursor plus guard because they cannot protect SDK lookup.
    seed_generation(&connection);
    seed_receive_cursor();
    owner_present = 0;
    fallback_present = 0;
    state_present = 0;
    generation_index_present = 0;
    cookie_connection_present = 0;
    ambiguities[0].present = 0;
    ambiguity_update_failures = 1;
    if (!run_close_receive_cursor(test_socket_cookie,
                                  &connection,
                                  test_connection_netns,
                                  stored_connection.netns_cookie) ||
        receive_cursor_present || receive_guard_present || ambiguity_update_failures ||
        find_ambiguity_entry(&stored_state_key) || !connection_present || unexpected_update ||
        unexpected_delete) {
        fail("failed M insertion retained final-fput cursor resources");
    }

    // The production branch gives exact non-allocating hash deletes bounded
    // retries. Two injected guard failures are recovered after RETIRING.
    seed_generation(&connection);
    seed_receive_cursor();
    java_remote_parent_cleanup(&test_owner);
    receive_guard_delete_failures = 2;
    if (!run_close_receive_cursor(test_socket_cookie,
                                  &connection,
                                  test_connection_netns,
                                  stored_connection.netns_cookie) ||
        receive_cursor_present || receive_guard_present || receive_guard_delete_failures ||
        find_ambiguity_entry(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("bounded close retries did not recover guard-delete faults");
    }

    // Two injected cursor failures likewise converge without a userspace
    // cursor sweeper and without recreating a generation marker.
    seed_generation(&connection);
    seed_receive_cursor();
    java_remote_parent_cleanup(&test_owner);
    receive_cursor_delete_failures = 2;
    if (!run_close_receive_cursor(test_socket_cookie,
                                  &connection,
                                  test_connection_netns,
                                  stored_connection.netns_cookie) ||
        receive_cursor_present || receive_guard_present || receive_cursor_delete_failures ||
        find_ambiguity_entry(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("bounded close retries did not recover cursor-delete faults");
    }

    // If RETIRING publication itself faults after the first delete attempt,
    // retry the original exact cursor identity; final fput still drains both
    // resources without depending on a later socket event.
    seed_generation(&connection);
    seed_receive_cursor();
    java_remote_parent_cleanup(&test_owner);
    receive_guard_delete_failures = 1;
    receive_cursor_update_failures = 1;
    if (!run_close_receive_cursor(test_socket_cookie,
                                  &connection,
                                  test_connection_netns,
                                  stored_connection.netns_cookie) ||
        receive_cursor_present || receive_guard_present || receive_guard_delete_failures ||
        receive_cursor_update_failures || find_ambiguity_entry(&stored_state_key) ||
        unexpected_update || unexpected_delete) {
        fail("close retry did not recover a RETIRING update fault");
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
    java_remote_parent_resolution_t resolution = {
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
    const java_remote_parent_alias_replay_key_t replay_key = java_remote_parent_alias_replay_key(
        &stored_state_key, test_observed_monotime_ns, test_process_incarnation);
    const alias_replay_entry_t *replay = find_alias_replay(&replay_key);
    if (replay) {
        java_remote_parent_alias_replay_binding_snapshot(&resolution.replay_binding,
                                                         &replay->value);
        resolution.replay_binding_found = 1;
    }
    return resolution;
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
    if (state_present && stored_state.aliases) {
        const java_remote_parent_alias_replay_key_t replay_key =
            java_remote_parent_alias_replay_key(
                &stored_state_key, test_observed_monotime_ns, test_process_incarnation);
        if (!find_alias_replay(&replay_key)) {
            seed_alias_replay(&stored_state_key,
                              test_observed_monotime_ns,
                              test_process_incarnation,
                              stored_state.aliases);
        }
    }
    const java_remote_parent_resolution_t resolution = finish_resolution();
    java_remote_parent_claim_t owned_claim = stored_claim;
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
        stored_claim.lifecycle != k_java_remote_parent_lifecycle_cleanup ||
        stored_claim.reserved[0] != k_java_remote_parent_lifecycle_consumed ||
        !detach_guard_present ||
        stored_detach_guard.lifecycle != k_java_remote_parent_lifecycle_cleanup ||
        stored_detach_guard.reserved[0] != k_java_remote_parent_lifecycle_publishing ||
        !find_ambiguity_entry(&stored_state_key) || find_ambiguity(&stored_state_key) ||
        unexpected_update || unexpected_delete) {
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

static void test_partial_task_finish_uses_durable_replay_binding(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    seed_finish_claim(k_java_remote_parent_lifecycle_consumed);
    state_delete_failures = 1;
    finish_seeded_generation(k_java_remote_parent_lifecycle_consumed);
    if (state_delete_failures || !state_present || connection_present ||
        cookie_connection_present || !claim_present || !detach_guard_present || !task_present ||
        !exact_test_alias_replay() ||
        exact_test_alias_replay()->value.lifecycle != k_java_remote_parent_lifecycle_consumed) {
        fail("could not seed a partial aliased FINISH with durable replay binding");
    }
    current_task = test_child;
    java_remote_parent_response_t response = {0};
    const enum java_remote_parent_status exact_status =
        java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie);
    if (exact_status != k_java_remote_parent_status_already_consumed ||
        response.status != k_java_remote_parent_status_already_consumed) {
        fail("partial aliased FINISH lost exact bound repeat status");
    }
    const java_remote_parent_response_t stale = stored_state.response;
    connection_info_t wrong_connection = connection;
    wrong_connection.d_port++;
    if (!task_retrieval_rejects_authority(&stale,
                                          &wrong_connection,
                                          test_connection_netns,
                                          test_generation,
                                          test_socket_cookie,
                                          test_generation) ||
        !task_retrieval_rejects_authority(&stale,
                                          &connection,
                                          test_connection_netns + 1,
                                          test_generation,
                                          test_socket_cookie,
                                          test_generation) ||
        !task_retrieval_rejects_authority(&stale,
                                          &connection,
                                          test_connection_netns,
                                          test_generation,
                                          test_replacement_socket_cookie,
                                          test_generation) ||
        !state_present || !claim_present || !detach_guard_present || !task_present ||
        unexpected_update || unexpected_delete) {
        fail("partial aliased FINISH accepted authority outside durable replay binding");
    }
}

static alias_replay_entry_t *exact_test_alias_replay(void) {
    const java_remote_parent_alias_replay_key_t key = java_remote_parent_alias_replay_key(
        &stored_state_key, test_observed_monotime_ns, test_process_incarnation);
    return find_alias_replay(&key);
}

static alias_replay_entry_t *seed_retained_task_finish(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    seed_finish_claim(k_java_remote_parent_lifecycle_consumed);
    exact_claim_delete_failures = 1;
    finish_seeded_generation(k_java_remote_parent_lifecycle_consumed);
    alias_replay_entry_t *replay = exact_test_alias_replay();
    if (exact_claim_delete_failures || !finish_generation_artifacts_absent() || !task_present ||
        !exact_finish_terminal_present(k_java_remote_parent_lifecycle_consumed) ||
        !exact_finish_claim_guard_tail(&stored_state_key,
                                       k_java_remote_parent_lifecycle_consumed) ||
        !replay || !replay->value.references ||
        replay->value.lifecycle != k_java_remote_parent_lifecycle_consumed || unexpected_update ||
        unexpected_delete) {
        fail("could not seed retained task finish replay fixture");
    }
    return replay;
}

static void assert_malformed_retained_task_replay_rejected(alias_replay_entry_t *replay,
                                                           const char *message) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const java_remote_parent_alias_replay_t replay_before = replay->value;
    const java_remote_parent_claim_t claim_before = stored_claim;
    const java_remote_parent_claim_t guard_before = stored_detach_guard;
    const java_remote_parent_terminal_t terminal_before = stored_terminal;
    const java_remote_parent_task_t task_before = stored_task;
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
    if (status == k_java_remote_parent_status_valid ||
        status == k_java_remote_parent_status_already_consumed || response.status != status ||
        !replay->present || memcmp(&replay->value, &replay_before, sizeof(replay_before)) != 0 ||
        !claim_present || memcmp(&stored_claim, &claim_before, sizeof(claim_before)) != 0 ||
        !detach_guard_present ||
        memcmp(&stored_detach_guard, &guard_before, sizeof(guard_before)) != 0 ||
        !terminal_present ||
        memcmp(&stored_terminal, &terminal_before, sizeof(terminal_before)) != 0 || !task_present ||
        memcmp(&stored_task, &task_before, sizeof(task_before)) != 0 || unexpected_update ||
        unexpected_delete) {
        fail(message);
    }
}

static void test_retained_task_finish_requires_exact_final_replay(void) {
    alias_replay_entry_t *replay = seed_retained_task_finish();
    replay->value.references = 0;
    assert_malformed_retained_task_replay_rejected(
        replay, "zero-reference final replay authorized a retained task outcome");

    replay = seed_retained_task_finish();
    replay->value.lifecycle = k_java_remote_parent_lifecycle_active;
    assert_malformed_retained_task_replay_rejected(
        replay, "active replay authorized a retained task outcome");

    replay = seed_retained_task_finish();
    replay->value.lifecycle = k_java_remote_parent_lifecycle_publishing;
    replay->value.desired_lifecycle = k_java_remote_parent_lifecycle_consumed;
    assert_malformed_retained_task_replay_rejected(
        replay, "publishing replay authorized a retained task outcome");

    replay = seed_retained_task_finish();
    replay->value.lifecycle = k_java_remote_parent_lifecycle_discarded;
    assert_malformed_retained_task_replay_rejected(
        replay, "mismatched final replay lifecycle authorized a retained task outcome");

    replay = seed_retained_task_finish();
    stored_terminal.lifecycle = k_java_remote_parent_lifecycle_discarded;
    assert_malformed_retained_task_replay_rejected(
        replay, "mismatched terminal lifecycle authorized a retained task outcome");

    replay = seed_retained_task_finish();
    stored_claim.reserved[0] = k_java_remote_parent_lifecycle_discarded;
    assert_malformed_retained_task_replay_rejected(
        replay, "mismatched cleanup-claim lifecycle authorized a retained task outcome");
}

static void seed_two_task_aliases(const connection_info_t *connection) {
    seed_generation(connection);
    seed_exact_receive_aliases(1);
    stored_state.aliases = 2;
    transferred_task_key = test_relay_child;
    transferred_task = stored_task;
    transferred_task_present = 1;
    seed_alias_replay(&stored_state_key, test_observed_monotime_ns, test_process_incarnation, 2);
}

static void publish_replacement_terminal(void) {
    stored_terminal = (java_remote_parent_terminal_t){
        .generation = test_replacement_generation,
        .observed_monotime_ns = test_now_ns + 10,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_consumed,
    };
    terminal_present = 1;
}

static void test_sibling_task_replays_after_successor_terminal(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_two_task_aliases(&connection);

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
        !finish_generation_artifacts_absent() || claim_present || detach_guard_present ||
        !task_present || !transferred_task_present || unexpected_update || unexpected_delete) {
        fail("first sibling task did not commit the aliased generation");
    }
    alias_replay_entry_t *replay = exact_test_alias_replay();
    if (!replay || replay->value.references != 2 ||
        replay->value.lifecycle != k_java_remote_parent_lifecycle_consumed ||
        replay->value.desired_lifecycle || replay->value.producer_tag || replay->value.reserved) {
        fail("first sibling task did not publish exact consumed replay authority");
    }

    publish_replacement_terminal();
    const java_remote_parent_terminal_t successor = stored_terminal;
    current_task = test_relay_child;
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
        java_remote_parent_le64_to_cpu(response.observed_monotime_ns_le) !=
            test_observed_monotime_ns ||
        memcmp(&stored_terminal, &successor, sizeof(successor)) != 0 || claim_present ||
        !task_present || !transferred_task_present || replay != exact_test_alias_replay() ||
        replay->value.lifecycle != k_java_remote_parent_lifecycle_consumed || unexpected_update ||
        unexpected_delete) {
        fail("second sibling lost exact replay after successor terminal displacement");
    }
}

static void test_missing_alias_replay_overloads_before_exact_claim(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    disable_alias_replay_autoseed = 1;
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
            k_java_remote_parent_status_overload ||
        response.status != k_java_remote_parent_status_overload || claim_present ||
        exact_claim_update_attempts || !state_present || !generation_index_present ||
        !owner_present || !fallback_present || !connection_present || !cookie_connection_present ||
        !task_present || exact_test_alias_replay() ||
        stats[k_java_remote_parent_stat_take_overload] != 1 || unexpected_update ||
        unexpected_delete) {
        fail("missing alias replay consumed E instead of returning Overload");
    }
}

static void test_alias_replay_capacity_rejects_retain_before_publication(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    disable_alias_replay_autoseed = 1;
    alias_replay_update_failures = 1;
    const java_remote_parent_handoff_key_t handoff_key =
        java_remote_parent_handoff_key(&test_owner, test_capture_race_token);
    java_remote_parent_capture_handoff(test_capture_race_token);
    if (alias_replay_update_failures || stored_state.aliases || find_handoff(&handoff_key) ||
        exact_test_alias_replay() || claim_present || exact_claim_update_attempts ||
        !find_ambiguity(&stored_state_key) || unexpected_update || unexpected_delete) {
        fail("alias replay capacity failure published a carrier or consumed E");
    }
}

static void test_direct_successor_never_consults_old_alias_replay(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const connection_info_t replacement = {.s_port = 2345, .d_port = 8443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    seed_alias_replay(&stored_state_key, test_observed_monotime_ns, test_process_incarnation, 1);
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
        k_java_remote_parent_status_valid) {
        fail("could not seed predecessor replay for direct successor testing");
    }
    alias_replay_entry_t *old_replay = exact_test_alias_replay();
    const java_remote_parent_alias_replay_t old_value = old_replay->value;
    const java_remote_parent_response_t successor = seed_replacement_generation(&replacement);
    publish_replacement_terminal();
    current_task = test_owner;
    memset(&response, 0, sizeof(response));
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_direct,
                                                   &replacement,
                                                   test_connection_netns,
                                                   test_replacement_generation,
                                                   test_replacement_socket_cookie) !=
            k_java_remote_parent_status_valid ||
        response.status != k_java_remote_parent_status_valid ||
        java_remote_parent_le64_to_cpu(response.generation_le) != test_replacement_generation ||
        memcmp(response.trace_id, successor.trace_id, sizeof(response.trace_id)) != 0 ||
        !old_replay->present || memcmp(&old_replay->value, &old_value, sizeof(old_value)) != 0 ||
        unexpected_update || unexpected_delete) {
        fail("direct successor lookup consulted or mutated predecessor exact replay");
    }
}

static void test_tagged_final_alias_replay_fails_closed(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    alias_replay_entry_t *replay = seed_alias_replay(
        &stored_state_key, test_observed_monotime_ns, test_process_incarnation, 1);
    replay->value = test_alias_replay_value(
        1, k_java_remote_parent_lifecycle_consumed, 0, k_java_remote_parent_go_producer_tag);
    const java_remote_parent_alias_replay_t tagged_final = replay->value;
    owner_present = 0;
    state_present = 0;
    generation_index_present = 0;
    connection_present = 0;
    cookie_connection_present = 0;
    fallback_present = 0;
    terminal_present = 0;
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
            k_java_remote_parent_status_ambiguous ||
        response.status != k_java_remote_parent_status_ambiguous || !task_present ||
        !replay->present || memcmp(&replay->value, &tagged_final, sizeof(tagged_final)) != 0 ||
        claim_present || exact_claim_update_attempts || unexpected_update || unexpected_delete) {
        fail("tagged final alias replay was accepted as committed authority");
    }
}

static void test_zero_reference_publishing_replay_fails_closed(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    alias_replay_entry_t *replay = seed_alias_replay(
        &stored_state_key, test_observed_monotime_ns, test_process_incarnation, 0);
    replay->value = test_alias_replay_value(
        0, k_java_remote_parent_lifecycle_publishing, k_java_remote_parent_lifecycle_consumed, 0);
    const java_remote_parent_alias_replay_t zero_reference_publishing = replay->value;
    stored_claim_key = stored_state_key;
    stored_claim = (java_remote_parent_claim_t){
        .observed_monotime_ns = test_now_ns,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_publishing,
        .reserved = {[0] = k_java_remote_parent_lifecycle_consumed},
    };
    claim_present = 1;
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
            k_java_remote_parent_status_ambiguous ||
        response.status != k_java_remote_parent_status_ambiguous || !task_present ||
        !replay->present ||
        memcmp(&replay->value, &zero_reference_publishing, sizeof(zero_reference_publishing)) !=
            0 ||
        !claim_present || exact_claim_update_attempts || unexpected_update || unexpected_delete) {
        fail("zero-reference publishing replay authorized a task carrier");
    }
}

static alias_replay_entry_t *seed_publishing_handoff_replay(u32 references) {
    seed_generation(&(connection_info_t){.s_port = 1234, .d_port = 443});
    const java_remote_parent_handoff_key_t handoff_key =
        java_remote_parent_handoff_key(&test_child, test_first_token);
    handoffs[0] = (handoff_entry_t){
        .key = handoff_key,
        .value =
            {
                .owner = test_owner,
                .generation = test_generation,
                .observed_monotime_ns = test_observed_monotime_ns,
            },
        .present = 1,
    };
    state_present = 0;
    alias_replay_entry_t *replay = seed_alias_replay(
        &stored_state_key, test_observed_monotime_ns, test_process_incarnation, references);
    replay->value.lifecycle = k_java_remote_parent_lifecycle_publishing;
    replay->value.desired_lifecycle = k_java_remote_parent_lifecycle_consumed;
    stored_claim_key = stored_state_key;
    stored_claim = (java_remote_parent_claim_t){
        .observed_monotime_ns = test_now_ns,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_consumed,
    };
    claim_present = 1;
    return replay;
}

static void test_zero_reference_publishing_replay_rejects_handoff_transfer(void) {
    const java_remote_parent_handoff_key_t handoff_key =
        java_remote_parent_handoff_key(&test_child, test_first_token);
    alias_replay_entry_t *replay = seed_publishing_handoff_replay(0);
    const java_remote_parent_alias_replay_t publishing = replay->value;
    java_remote_parent_link_handoff(&test_child, test_first_token);
    if (find_handoff(&handoff_key) || task_present || task_update_attempts || !replay->present ||
        memcmp(&replay->value, &publishing, sizeof(publishing)) != 0 || !claim_present ||
        !find_handoff_claim(&handoff_key) || handoff_claim_update_successes != 1 ||
        unexpected_update || unexpected_delete) {
        fail("zero-reference publishing replay authorized pre-link handoff transfer");
    }

    replay = seed_publishing_handoff_replay(1);
    zero_alias_replay_after_task_publish = 1;
    java_remote_parent_link_handoff(&test_child, test_first_token);
    if (zero_alias_replay_after_task_publish || find_handoff(&handoff_key) || task_present ||
        task_update_attempts != 1 || !replay->present || replay->value.references ||
        replay->value.lifecycle != k_java_remote_parent_lifecycle_publishing ||
        replay->value.desired_lifecycle != k_java_remote_parent_lifecycle_consumed ||
        !claim_present || !find_handoff_claim(&handoff_key) ||
        handoff_claim_update_successes != 1 || unexpected_update || unexpected_delete) {
        fail("zero-reference publishing replay survived post-link authority validation");
    }
}

static void test_task_replay_outweighs_same_generation_successor_observation(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const connection_info_t successor_connection = {.s_port = 2345, .d_port = 8443};
    seed_two_task_aliases(&connection);

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
        k_java_remote_parent_status_valid) {
        fail("could not seed predecessor replay for same-generation reuse testing");
    }
    alias_replay_entry_t *replay = exact_test_alias_replay();
    if (!replay || replay->value.lifecycle != k_java_remote_parent_lifecycle_consumed ||
        replay->value.references != 2) {
        fail("predecessor did not publish exact replay before same-generation reuse");
    }
    const java_remote_parent_alias_replay_t replay_value = replay->value;

    // Simulate eviction of the narrow terminal cursor followed by a coherent
    // successor that reused its owner and generation but has a new observation.
    terminal_present = 0;
    stored_owner = (java_remote_parent_owner_t){
        .generation = test_generation,
        .process_incarnation = test_process_incarnation,
        .lifecycle = k_java_remote_parent_lifecycle_active,
    };
    owner_present = 1;
    memset(&stored_state, 0, sizeof(stored_state));
    stored_state.lifecycle = k_java_remote_parent_lifecycle_active;
    stored_state.observed_monotime_ns = test_now_ns;
    stored_state.connection = successor_connection;
    stored_state.connection_netns = test_connection_netns;
    stored_state.process_incarnation = test_process_incarnation;
    java_remote_parent_init_response(
        &stored_state.response, k_java_remote_parent_status_valid, test_generation, test_now_ns);
    state_present = 1;
    stored_generation_index = (java_remote_parent_generation_index_t){
        .process = java_process_key(&test_owner),
        .process_incarnation = test_process_incarnation,
        .observed_monotime_ns = test_now_ns,
    };
    generation_index_present = 1;
    ambiguities[0] = (ambiguity_entry_t){
        .key = stored_state_key,
        .present = 1,
    };
    stored_fallback = stored_state.response;
    fallback_present = 1;
    const java_remote_parent_state_t successor_state = stored_state;

    current_task = test_relay_child;
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
        java_remote_parent_le64_to_cpu(response.observed_monotime_ns_le) !=
            test_observed_monotime_ns ||
        !task_present || !transferred_task_present || !replay->present ||
        memcmp(&replay->value, &replay_value, sizeof(replay_value)) != 0 || !state_present ||
        memcmp(&stored_state, &successor_state, sizeof(successor_state)) != 0 || claim_present ||
        unexpected_update || unexpected_delete) {
        fail("same-generation successor masked the task's exact replay provenance");
    }
}

static void test_replay_binding_mismatch_is_missing_and_nonmutating(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    const connection_info_t replacement = {.s_port = 2345, .d_port = 8443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    seed_alias_replay(&stored_state_key, test_observed_monotime_ns, test_process_incarnation, 1);
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
        k_java_remote_parent_status_valid) {
        fail("could not seed predecessor replay for binding mismatch testing");
    }
    alias_replay_entry_t *replay = exact_test_alias_replay();
    const java_remote_parent_alias_replay_t replay_value = replay->value;
    seed_replacement_generation(&replacement);
    publish_replacement_terminal();

    memset(&response, 0, sizeof(response));
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_replacement_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_missing ||
        response.status != k_java_remote_parent_status_missing || !replay->present ||
        memcmp(&replay->value, &replay_value, sizeof(replay_value)) != 0 || !task_present ||
        claim_present || unexpected_update || unexpected_delete) {
        fail("expected-generation mismatch mutated exact replay authority");
    }

    memset(&response, 0, sizeof(response));
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &replacement,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_replacement_socket_cookie) !=
            k_java_remote_parent_status_missing ||
        response.status != k_java_remote_parent_status_missing || !replay->present ||
        memcmp(&replay->value, &replay_value, sizeof(replay_value)) != 0 || !task_present ||
        claim_present || unexpected_update || unexpected_delete) {
        fail("socket/connection rebound mismatch mutated exact replay authority");
    }
}

static void test_replay_task_rebind_fails_closed_without_retiring_authority(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    seed_alias_replay(&stored_state_key, test_observed_monotime_ns, test_process_incarnation, 1);
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
        k_java_remote_parent_status_valid) {
        fail("could not seed a completed task replay for rebind testing");
    }
    publish_replacement_terminal();
    replace_task_during_alias_replay_lookup = 1;
    memset(&response, 0, sizeof(response));
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
        replace_task_during_alias_replay_lookup || !task_present ||
        stored_task.generation != test_replacement_generation || claim_present ||
        !exact_test_alias_replay() ||
        exact_test_alias_replay()->value.lifecycle != k_java_remote_parent_lifecycle_consumed ||
        unexpected_update || unexpected_delete) {
        fail("task rebind during exact replay retired or returned old authority");
    }
}

static void test_replay_transition_failure_retains_finish_fences(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    alias_replay_entry_t *replay = seed_alias_replay(
        &stored_state_key, test_observed_monotime_ns, test_process_incarnation, 1);
    seed_finish_claim(k_java_remote_parent_lifecycle_consumed);
    alias_replay_update_failures = 1;
    finish_seeded_generation(k_java_remote_parent_lifecycle_consumed);
    if (alias_replay_update_failures || !finish_generation_artifacts_present() ||
        !exact_finish_terminal_present(k_java_remote_parent_lifecycle_consumed) ||
        !exact_finish_fences_retained(&stored_state_key, k_java_remote_parent_lifecycle_consumed) ||
        !replay->present || replay->value.references != 1 ||
        replay->value.lifecycle != k_java_remote_parent_lifecycle_active || unexpected_update ||
        unexpected_delete) {
        fail("failed replay transition released finish fences or payload");
    }
}

static void test_replay_binding_substitution_retains_finish_fences(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    alias_replay_entry_t *replay = seed_alias_replay(
        &stored_state_key, test_observed_monotime_ns, test_process_incarnation, 1);
    const u64 original_socket_cookie = replay->value.socket_cookie;
    seed_finish_claim(k_java_remote_parent_lifecycle_consumed);
    replace_alias_replay_binding_during_finish_lookup = 1;
    finish_seeded_generation(k_java_remote_parent_lifecycle_consumed);
    if (replace_alias_replay_binding_during_finish_lookup ||
        !finish_generation_artifacts_present() ||
        !exact_finish_terminal_present(k_java_remote_parent_lifecycle_consumed) ||
        !exact_finish_fences_retained(&stored_state_key, k_java_remote_parent_lifecycle_consumed) ||
        !replay->present || replay->value.references != 1 ||
        replay->value.lifecycle != k_java_remote_parent_lifecycle_consumed ||
        replay->value.transition_monotime_ns != test_now_ns ||
        replay->value.socket_cookie != original_socket_cookie + 1 || unexpected_update ||
        unexpected_delete) {
        fail("replay binding substitution crossed FINISH barriers");
    }
}

static void test_stale_retain_transition_is_overcount_only(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    alias_replay_entry_t *replay = seed_alias_replay(
        &stored_state_key, test_observed_monotime_ns, test_process_incarnation, 1);
    seed_finish_claim(k_java_remote_parent_lifecycle_consumed);
    increment_alias_replay_before_publishing_update = 1;
    finish_seeded_generation(k_java_remote_parent_lifecycle_consumed);
    if (increment_alias_replay_before_publishing_update || !finish_generation_artifacts_absent() ||
        claim_present || detach_guard_present || !task_present || !replay->present ||
        replay->value.references != 1 ||
        replay->value.lifecycle != k_java_remote_parent_lifecycle_consumed || unexpected_update ||
        unexpected_delete) {
        fail("stale retain/finalizer interleaving undercounted exact replay");
    }
    java_remote_parent_unlink_task(&stored_task_key);
    if (task_present || replay->present || unexpected_update || unexpected_delete) {
        fail("last final replay reference did not retire after E/G release");
    }
}

static void test_ambiguous_alias_commit_replays_ambiguous(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_generation(&connection);
    seed_exact_receive_aliases(1);
    seed_alias_replay(&stored_state_key, test_observed_monotime_ns, test_process_incarnation, 1);
    ambiguities[0].observed_monotime_ns = test_now_ns;
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
            k_java_remote_parent_status_ambiguous ||
        response.status != k_java_remote_parent_status_ambiguous || claim_present ||
        !finish_generation_artifacts_absent() || !exact_test_alias_replay() ||
        exact_test_alias_replay()->value.lifecycle != k_java_remote_parent_lifecycle_ambiguous ||
        unexpected_update || unexpected_delete) {
        fail("ambiguous task claim did not commit matching E/replay semantics");
    }
    publish_replacement_terminal();
    memset(&response, 0, sizeof(response));
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   test_now_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_ambiguous ||
        response.status != k_java_remote_parent_status_ambiguous || claim_present ||
        !exact_test_alias_replay() || unexpected_update || unexpected_delete) {
        fail("ambiguous exact replay did not preserve the committed semantic");
    }
}

static void test_ttl_boundary_promotes_stale_and_replays_consumed(void) {
    const connection_info_t connection = {.s_port = 1234, .d_port = 443};
    seed_two_task_aliases(&connection);
    advance_time_after_claim_task_validation = 1;
    current_task = test_child;
    java_remote_parent_response_t response = {0};
    const u64 max_age_ns = test_now_ns - test_observed_monotime_ns;
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   max_age_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_stale ||
        response.status != k_java_remote_parent_status_stale ||
        advance_time_after_claim_task_validation || claim_present ||
        !finish_generation_artifacts_absent() || !exact_test_alias_replay() ||
        exact_test_alias_replay()->value.lifecycle != k_java_remote_parent_lifecycle_stale ||
        unexpected_update || unexpected_delete) {
        fail("TTL boundary did not promote E and replay to stale");
    }
    publish_replacement_terminal();
    current_task = test_relay_child;
    memset(&response, 0, sizeof(response));
    if (java_remote_parent_retrieve_for_connection(&response,
                                                   0,
                                                   max_age_ns,
                                                   k_java_remote_parent_source_task,
                                                   &connection,
                                                   test_connection_netns,
                                                   test_generation,
                                                   test_socket_cookie) !=
            k_java_remote_parent_status_already_consumed ||
        response.status != k_java_remote_parent_status_already_consumed || claim_present ||
        !exact_test_alias_replay() ||
        exact_test_alias_replay()->value.lifecycle != k_java_remote_parent_lifecycle_stale ||
        unexpected_update || unexpected_delete) {
        fail("stale replay sibling did not classify the one-shot as consumed");
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
    test_claim_equality_is_byte_exact();
    test_pid_and_generation_index_equality_is_exact();
    test_abi_tail_validation_is_byte_exact();
    test_finish_connection_matcher_is_field_exact();
    test_compact_finish_shapes_match_reference();
    test_claim_status_packed_classifier_matches_reference();
    test_capture_workspaces_are_guarded_and_zeroized();
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
    test_detached_successor_full_proof_is_fail_closed();
    test_detached_pre_ack_binding_and_successor_alias_are_live();
    test_direct_take_with_alias_publishes_bound_sibling_replay();
    test_connection_bound_direct_take_requires_nonzero_generation();
    test_task_claim_binding_rejects_reserved_state();
    test_detached_zero_cleanup_quarantines_retain_race();
    test_detached_zero_cleanup_retains_adoption_artifacts();
    test_cross_generation_guard_does_not_block_detached_cleanup();
    test_cleanup_unlinks_exact_task_and_releases_final_replay_reference();
    test_cleanup_absent_task_is_idempotent();
    test_cleanup_retains_foreign_generation_task_and_replay();
    test_owner_cleanup_release_tails_are_recoverable();
    test_internal_cleanup_claim_is_transient();
    test_generation_claim_status_validation();
    test_tagged_go_guard_is_status_only();
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
    test_failed_guard_acquisition_preserves_identical_foreign_guard();
    test_exact_receive_zero_alias_claim_failures_are_fail_closed();
    test_exact_receive_take_completion_requires_strict_postconditions();
    test_unacked_publishing_cleanup_is_shallow_and_exact();
    test_parser_failure_uses_pre_reserved_ambiguity_fence();
    test_deferred_ioctl_transition_is_exact_and_fail_closed();
    test_close_workspace_is_guarded_and_zeroized();
    test_close_final_form_rejects_zero_generation_cursors();
    test_close_retiring_retries_are_state_exact();
    test_independent_close_hook_orders_are_exactly_fenced();
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
    test_partial_task_finish_uses_durable_replay_binding();
    test_retained_task_finish_requires_exact_final_replay();
    test_sibling_task_replays_after_successor_terminal();
    test_missing_alias_replay_overloads_before_exact_claim();
    test_alias_replay_capacity_rejects_retain_before_publication();
    test_direct_successor_never_consults_old_alias_replay();
    test_tagged_final_alias_replay_fails_closed();
    test_zero_reference_publishing_replay_fails_closed();
    test_zero_reference_publishing_replay_rejects_handoff_transfer();
    test_task_replay_outweighs_same_generation_successor_observation();
    test_replay_binding_mismatch_is_missing_and_nonmutating();
    test_replay_task_rebind_fails_closed_without_retiring_authority();
    test_replay_transition_failure_retains_finish_fences();
    test_replay_binding_substitution_retains_finish_fences();
    test_stale_retain_transition_is_overcount_only();
    test_ambiguous_alias_commit_replays_ambiguous();
    test_ttl_boundary_promotes_stale_and_replays_consumed();
    test_detached_finish_preserves_successor_terminal();
    return 0;
}
