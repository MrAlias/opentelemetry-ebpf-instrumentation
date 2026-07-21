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

volatile const bool java_remote_parent_enabled = true;

enum { max_identities = 4 };

typedef struct identity_slot {
    pid_key_t key;
    java_vt_identity_t value;
    int present;
} identity_slot_t;

static pid_key_t process_key;
static u64 process_incarnation;
static int process_present;
static pid_key_t mounted_key;
static java_vt_identity_t mounted_value;
static int mounted_present;
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
        if (flags == BPF_NOEXIST && mounted_present) {
            return -1;
        }
        mounted_key = *(const pid_key_t *)key;
        mounted_value = *(const java_vt_identity_t *)value;
        mounted_present = 1;
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
    mounted_present = 0;
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
    if (java_vt_prepare_mount(&thread, 42, &owner, &identity) != k_java_vt_mount_success ||
        !java_vt_publish_mount(&thread, &identity)) {
        fail("initial virtual-thread mount failed");
    }

    pid_key_t translated = thread;
    if (!java_vt_translate_tid(&translated) || !same_key(&translated, &owner)) {
        fail("mounted virtual thread did not translate");
    }
    test_map_delete(&java_vt_threads, &thread);
    if (!find_identity(&owner) || !java_vt_publish_mount(&thread, &identity)) {
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
    if (!java_vt_terminate_identity(&thread, 42, &terminated) || find_identity(&owner) ||
        mounted_present) {
        fail("virtual-thread termination did not remove both identity records");
    }
}

int main(void) {
    test_park_remount_preserves_full_identity();
    test_low_31_bit_collision_fails_closed();
    test_process_reuse_rejects_old_mount_and_replaces_guard();
    test_eviction_and_termination_fail_closed();
    return 0;
}
