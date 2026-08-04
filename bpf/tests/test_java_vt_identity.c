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

#include <maps/java_vt_threads.h>

#undef bpf_map_lookup_elem
#undef bpf_map_update_elem
#undef bpf_map_delete_elem

#ifndef TEST_JAVA_REMOTE_PARENT_ENABLED
#define TEST_JAVA_REMOTE_PARENT_ENABLED 1
#endif

volatile const bool java_remote_parent_enabled = TEST_JAVA_REMOTE_PARENT_ENABLED != 0;

enum { max_identities = 4 };

typedef struct identity_slot {
    pid_key_t key;
    java_vt_identity_t value;
    int present;
} identity_slot_t;

static pid_key_t process_key;
static u64 process_incarnation;
static int process_present;
static u64 process_capability;
static int authorization_present;
static pid_key_t mounted_key;
static java_vt_identity_t mounted_value;
static int mounted_present;
static int mount_update_failure;
static int registration_loss_after_mount_update;
static identity_slot_t identities[max_identities];

static void fail(const char *message) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

static int same_key(const pid_key_t *left, const pid_key_t *right) {
    return memcmp(left, right, sizeof(*left)) == 0;
}

static identity_slot_t *find_identity(const pid_key_t *key) {
    for (size_t i = 0; i < max_identities; i++) {
        if (identities[i].present && same_key(&identities[i].key, key)) {
            return &identities[i];
        }
    }
    return NULL;
}

static void *test_map_lookup(void *map, const void *key) {
    if (map == &java_authorized_processes) {
        return authorization_present && same_key(&process_key, key) ? &process_capability : NULL;
    }
    if (map == &java_process_incarnations) {
        return process_present && same_key(&process_key, key) ? &process_incarnation : NULL;
    }
    if (map == &java_vt_threads) {
        return mounted_present && same_key(&mounted_key, key) ? &mounted_value : NULL;
    }
    if (map == &java_vt_identities) {
        identity_slot_t *slot = find_identity(key);
        return slot ? &slot->value : NULL;
    }
    return NULL;
}

static long
test_map_update(void *map, const void *key, const void *value, unsigned long long flags) {
    if (map == &java_process_incarnations) {
        if (flags == BPF_NOEXIST && process_present) {
            return -1;
        }
        process_key = *(const pid_key_t *)key;
        process_incarnation = *(const u64 *)value;
        process_present = 1;
        return 0;
    }
    if (map == &java_vt_threads) {
        if (mount_update_failure) {
            return -1;
        }
        if (flags == BPF_NOEXIST && mounted_present) {
            return -1;
        }
        mounted_key = *(const pid_key_t *)key;
        mounted_value = *(const java_vt_identity_t *)value;
        mounted_present = 1;
        if (registration_loss_after_mount_update) {
            process_present = 0;
        }
        return 0;
    }
    if (map != &java_vt_identities) {
        return -1;
    }

    identity_slot_t *slot = find_identity(key);
    if (flags == BPF_NOEXIST && slot) {
        return -1;
    }
    if (!slot) {
        for (size_t i = 0; i < max_identities; i++) {
            if (!identities[i].present) {
                slot = &identities[i];
                slot->key = *(const pid_key_t *)key;
                slot->present = 1;
                break;
            }
        }
    }
    if (!slot) {
        return -1;
    }
    slot->value = *(const java_vt_identity_t *)value;
    return 0;
}

static long test_map_delete(void *map, const void *key) {
    if (map == &java_process_incarnations) {
        if (process_present && same_key(&process_key, key)) {
            process_present = 0;
        }
    } else if (map == &java_vt_threads) {
        if (mounted_present && same_key(&mounted_key, key)) {
            mounted_present = 0;
        }
    } else if (map == &java_vt_identities) {
        identity_slot_t *slot = find_identity(key);
        if (slot) {
            slot->present = 0;
        }
    }
    return 0;
}

static void reset(u64 incarnation) {
    memset(&process_key, 0, sizeof(process_key));
    memset(&mounted_key, 0, sizeof(mounted_key));
    memset(&mounted_value, 0, sizeof(mounted_value));
    memset(identities, 0, sizeof(identities));
    process_incarnation = incarnation;
    process_present = 1;
    process_capability = incarnation;
    authorization_present = 1;
    mounted_present = 0;
    mount_update_failure = 0;
    registration_loss_after_mount_update = 0;
}

static pid_key_t carrier(void) {
    const pid_key_t key = {
        .tid = 201,
        .pid = 200,
        .ns = 9,
    };
    process_key = java_process_key(&key);
    return key;
}

static void test_park_remount_preserves_full_identity(void) {
    reset(10);
    const pid_key_t thread = carrier();
    pid_key_t owner = {};
    java_vt_identity_t identity = {};
    if (java_vt_prepare_mount(&thread, 42, &owner, &identity) != k_java_vt_mount_new_identity ||
        !java_vt_publish_mount(&thread, &identity)) {
        fail("initial virtual-thread mount failed");
    }

    pid_key_t translated = thread;
    if (!java_vt_translate_tid(&translated) || !same_key(&translated, &owner)) {
        fail("mounted virtual thread did not translate");
    }
    test_map_delete(&java_vt_threads, &thread);
    pid_key_t remounted_owner = {};
    java_vt_identity_t remounted_identity = {};
    if (!find_identity(&owner) ||
        java_vt_prepare_mount(&thread, 42, &remounted_owner, &remounted_identity) !=
            k_java_vt_mount_success ||
        !same_key(&owner, &remounted_owner) ||
        !java_vt_identity_equal(&identity, &remounted_identity) ||
        !java_vt_publish_mount(&thread, &remounted_identity)) {
        fail("park removed the logical full-width identity");
    }
    translated = thread;
    if (!java_vt_translate_tid(&translated) || !same_key(&translated, &owner)) {
        fail("remounted virtual thread lost its logical owner");
    }
}

static void test_low_31_bit_collision_fails_closed(void) {
    reset(10);
    const pid_key_t thread = carrier();
    pid_key_t first_owner = {};
    java_vt_identity_t first = {};
    java_vt_prepare_mount(&thread, 1, &first_owner, &first);
    java_vt_publish_mount(&thread, &first);

    pid_key_t colliding_owner = {};
    java_vt_identity_t colliding = {};
    if (java_vt_prepare_mount(&thread, 0x80000001ULL, &colliding_owner, &colliding) !=
            k_java_vt_mount_collision ||
        !same_key(&first_owner, &colliding_owner)) {
        fail("low-31-bit alias was not detected");
    }

    java_vt_publish_mount(&thread, &colliding);
    pid_key_t translated = thread;
    if (java_vt_translate_tid(&translated)) {
        fail("colliding full virtual-thread id was translated");
    }
}

static void test_process_reuse_rejects_old_mount_and_replaces_guard(void) {
    reset(10);
    const pid_key_t thread = carrier();
    pid_key_t owner = {};
    java_vt_identity_t old_identity = {};
    java_vt_prepare_mount(&thread, 42, &owner, &old_identity);
    java_vt_publish_mount(&thread, &old_identity);

    process_incarnation = 11;
    process_capability = 11;
    pid_key_t translated = thread;
    if (java_vt_translate_tid(&translated)) {
        fail("PID reuse translated an earlier JVM's mounted identity");
    }

    pid_key_t reused_owner = {};
    java_vt_identity_t current = {};
    if (java_vt_prepare_mount(&thread, 42, &reused_owner, &current) !=
            k_java_vt_mount_stale_incarnation ||
        !java_vt_replace_stale_identity(&reused_owner, &current) ||
        !java_vt_publish_mount(&thread, &current)) {
        fail("new JVM incarnation could not replace a stale identity guard");
    }
    translated = thread;
    if (!java_vt_translate_tid(&translated) || !same_key(&translated, &reused_owner)) {
        fail("new JVM incarnation did not translate after guarded replacement");
    }
}

static void test_eviction_and_termination_fail_closed(void) {
    reset(10);
    const pid_key_t thread = carrier();
    pid_key_t owner = {};
    java_vt_identity_t identity = {};
    java_vt_prepare_mount(&thread, 42, &owner, &identity);
    java_vt_publish_mount(&thread, &identity);
    test_map_delete(&java_vt_identities, &owner);

    pid_key_t translated = thread;
    if (java_vt_translate_tid(&translated)) {
        fail("evicted full-width identity produced a translation");
    }

    java_vt_prepare_mount(&thread, 42, &owner, &identity);
    java_vt_publish_mount(&thread, &identity);
    pid_key_t terminated = {};
    if (!java_vt_terminate_identity(&thread, 42, &terminated) || !find_identity(&owner) ||
        mounted_present) {
        fail("virtual-thread termination removed its guard before owner cleanup");
    }
    test_map_delete(&java_vt_identities, &terminated);
    if (find_identity(&owner)) {
        fail("virtual-thread termination did not remove its identity guard after cleanup");
    }
}

static void test_disabled_bridge_termination_deletes_registered_identity(void) {
    reset(10);
    const pid_key_t thread = carrier();
    pid_key_t owner = {};
    java_vt_identity_t identity = {};
    if (java_vt_prepare_mount(&thread, 42, &owner, &identity) != k_java_vt_mount_new_identity ||
        !java_vt_publish_mount(&thread, &identity)) {
        fail("disabled-bridge virtual-thread mount failed");
    }

    pid_key_t terminated = {};
    if (!java_vt_terminate_identity(&thread, 42, &terminated) || mounted_present ||
        !find_identity(&owner)) {
        fail("disabled-bridge termination did not retain its guard for ordered cleanup");
    }

    java_vt_identity_t expected = {};
    if (!java_vt_prepare_unregistered_cleanup(
            &thread, 42, process_capability, &terminated, &expected) ||
        expected.process_incarnation != process_capability ||
        !java_vt_delete_identity_if_matches(&terminated, &expected) || find_identity(&owner)) {
        fail("disabled-bridge termination did not delete its registered identity guard");
    }
}

static void test_authorized_cleanup_translation_survives_registration_eviction(void) {
    reset(10);
    const pid_key_t thread = carrier();
    pid_key_t owner = {};
    java_vt_identity_t identity = {};
    java_vt_prepare_mount(&thread, 42, &owner, &identity);
    java_vt_publish_mount(&thread, &identity);
    process_present = 0;

    pid_key_t ordinary = thread;
    if (java_vt_translate_tid(&ordinary)) {
        fail("ordinary translation survived registration eviction");
    }
    pid_key_t cleanup = thread;
    if (java_vt_translate_authorized_tid(&cleanup) != k_java_vt_cleanup_translation_exact ||
        !same_key(&cleanup, &owner)) {
        fail("authorized cleanup could not recover the mounted owner");
    }

    test_map_delete(&java_vt_identities, &owner);
    cleanup = thread;
    if (java_vt_translate_authorized_tid(&cleanup) != k_java_vt_cleanup_translation_fallback ||
        !same_key(&cleanup, &owner)) {
        fail("authorized cleanup did not derive a conservative owner without its identity guard");
    }

    process_capability++;
    cleanup = thread;
    if (java_vt_translate_authorized_tid(&cleanup) != k_java_vt_cleanup_translation_none) {
        fail("authorized cleanup accepted a mismatched process capability");
    }
}

static void test_payload_cleanup_survives_registration_loss_and_preserves_collisions(void) {
    reset(10);
    const pid_key_t thread = carrier();
    pid_key_t owner = {};
    java_vt_identity_t identity = {};
    if (java_vt_prepare_mount(&thread, 42, &owner, &identity) != k_java_vt_mount_new_identity) {
        fail("virtual-thread identity was not prepared before registration loss");
    }

    // Model eviction after the dispatcher captured the non-evicting
    // authorization capability but before mount/terminate re-read the LRU
    // registration. There is deliberately no live carrier mount here: this is
    // the parked-VT case that carrier-only cleanup cannot discover.
    const u64 authorized_capability = process_capability;
    process_present = 0;
    pid_key_t requested_owner = {};
    java_vt_identity_t expected = {};
    if (java_vt_prepare_mount(&thread, 42, &requested_owner, &expected) !=
            k_java_vt_mount_overload ||
        !java_vt_prepare_unregistered_cleanup(
            &thread, 42, authorized_capability, &requested_owner, &expected) ||
        !same_key(&requested_owner, &owner) || expected.virtual_thread_id != 42 ||
        expected.process_incarnation != authorized_capability) {
        fail("stable authorization could not derive a parked owner after registration loss");
    }

    // Owner derivation itself keeps the guard so the lifecycle caller can
    // discard state first. Rejected mount and terminate then invalidate only
    // this exact guard and force a later mount through new-identity cleanup.
    if (!find_identity(&owner)) {
        fail("rejected mount unexpectedly removed the parked identity guard");
    }
    if (!java_vt_delete_identity_if_matches(&requested_owner, &expected) || find_identity(&owner)) {
        fail("exact parked identity was not deleted after payload cleanup");
    }

    process_present = 1;
    if (java_vt_prepare_mount(&thread, 42, &owner, &identity) != k_java_vt_mount_new_identity) {
        fail("exact identity guard could not be recreated for collision test");
    }
    process_present = 0;
    const u64 colliding_id = 42 + (1ULL << 31);
    if (!java_vt_prepare_unregistered_cleanup(
            &thread, colliding_id, authorized_capability, &requested_owner, &expected) ||
        !same_key(&requested_owner, &owner) ||
        java_vt_delete_identity_if_matches(&requested_owner, &expected) || !find_identity(&owner)) {
        fail("mismatched full-width identity deleted a colliding guard");
    }
}

static void test_mount_publication_revalidates_registration_and_authorization(void) {
    reset(10);
    const pid_key_t thread = carrier();
    pid_key_t owner = {};
    java_vt_identity_t identity = {};
    if (java_vt_prepare_mount(&thread, 42, &owner, &identity) != k_java_vt_mount_new_identity) {
        fail("virtual-thread mount identity was not prepared");
    }

    process_present = 0;
    if (java_vt_publish_mount(&thread, &identity) || mounted_present || find_identity(&owner)) {
        fail("failed unregistered mount publication retained cleanup authority");
    }

    process_present = 1;
    if (java_vt_prepare_mount(&thread, 42, &owner, &identity) != k_java_vt_mount_new_identity) {
        fail("unregistered publication did not invalidate the identity guard");
    }
    process_capability++;
    if (java_vt_publish_mount(&thread, &identity) || mounted_present || find_identity(&owner)) {
        fail("failed unauthorized mount publication retained cleanup authority");
    }

    process_capability = process_incarnation;
    if (java_vt_prepare_mount(&thread, 42, &owner, &identity) != k_java_vt_mount_new_identity) {
        fail("unauthorized publication did not invalidate the identity guard");
    }
    mount_update_failure = 1;
    if (java_vt_publish_mount(&thread, &identity) || mounted_present || find_identity(&owner)) {
        fail("failed full-map publication retained cleanup authority");
    }

    mount_update_failure = 0;
    if (java_vt_prepare_mount(&thread, 42, &owner, &identity) != k_java_vt_mount_new_identity) {
        fail("full-map failure did not invalidate the identity guard");
    }
    registration_loss_after_mount_update = 1;
    if (java_vt_publish_mount(&thread, &identity) || !mounted_present || find_identity(&owner)) {
        fail("post-publication registration loss retained cleanup authority");
    }
    test_map_delete(&java_vt_threads, &thread);

    registration_loss_after_mount_update = 0;
    process_present = 1;
    if (java_vt_prepare_mount(&thread, 42, &owner, &identity) != k_java_vt_mount_new_identity ||
        !java_vt_publish_mount(&thread, &identity) || !mounted_present) {
        fail("virtual-thread mount rejected matching registration and authorization");
    }

    pid_key_t translated = thread;
    if (!java_vt_translate_tid(&translated) || !same_key(&translated, &owner)) {
        fail("successfully published virtual-thread mount did not translate");
    }
}

int main(void) {
#if TEST_JAVA_REMOTE_PARENT_ENABLED
    test_park_remount_preserves_full_identity();
    test_low_31_bit_collision_fails_closed();
    test_process_reuse_rejects_old_mount_and_replaces_guard();
    test_eviction_and_termination_fail_closed();
    test_authorized_cleanup_translation_survives_registration_eviction();
    test_payload_cleanup_survives_registration_loss_and_preserves_collisions();
    test_mount_publication_revalidates_registration_and_authorization();
    if (0) {
        test_disabled_bridge_termination_deletes_registered_identity();
    }
#else
    // Keep the enabled-mode cases type-checked by this build without running
    // assertions whose semantics deliberately depend on bridge translation.
    if (0) {
        test_park_remount_preserves_full_identity();
        test_low_31_bit_collision_fails_closed();
        test_process_reuse_rejects_old_mount_and_replaces_guard();
        test_eviction_and_termination_fail_closed();
        test_authorized_cleanup_translation_survives_registration_eviction();
        test_payload_cleanup_survives_registration_loss_and_preserves_collisions();
        test_mount_publication_revalidates_registration_and_authorization();
    }
    test_disabled_bridge_termination_deletes_registered_identity();
#endif
    return 0;
}
