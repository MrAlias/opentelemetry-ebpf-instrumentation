// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/java_remote_parent.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <pid/pid_helpers.h>
#include <pid/types/pid_key.h>

// Synthetic-tid marker: real kernel tids never reach bit 31.
#define JAVA_VT_TID_FLAG 0x80000000u

typedef struct java_vt_identity {
    u64 virtual_thread_id;
    u64 process_incarnation;
} java_vt_identity_t;

typedef struct java_retired_process_key {
    pid_key_t process;
    u32 reserved;
    u64 process_incarnation;
} java_retired_process_key_t;

_Static_assert(sizeof(java_vt_identity_t) == 16, "Java VT identity size mismatch");
_Static_assert(sizeof(java_retired_process_key_t) == 24, "Java retired-process key size mismatch");

// Exact allowlist populated only by OBI userspace after Java discovery. This
// is the authorization boundary for every agent IOCTL; the probabilistic PID
// filter remains only an instrumentation performance filter.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, pid_key_t); // process key: tid == pid
    __type(value, u64);     // random nonzero capability known only to OBI and this JVM
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_authorized_processes SEC(".maps");

// The Java agent registers the random, nonzero capability OBI supplied when it
// attached. It is also the JVM incarnation in virtual-thread and remote-parent
// state so PID, TID, and low-31-bit virtual-thread reuse cannot select an
// earlier JVM's data.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_key_t); // process key: tid == pid
    __type(value, u64);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_process_incarnations SEC(".maps");

// Last-thread exit records are consumed by the userspace sweeper. Including
// the JVM incarnation in the key prevents a rapidly reused PID from replacing
// or being mistaken for the process that actually exited.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, java_retired_process_key_t);
    __type(value, u64);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_retired_processes SEC(".maps");

// Which full virtual-thread identity is currently mounted on a carrier OS
// thread. An entry exists only while the virtual thread is mounted.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_key_t);
    __type(value, java_vt_identity_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_vt_threads SEC(".maps");

// Full-width guard for a synthetic low-31-bit virtual-thread owner. LRU
// eviction only causes an explicit miss because every translation revalidates
// the full id and process incarnation through this map.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, pid_key_t);
    __type(value, java_vt_identity_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} java_vt_identities SEC(".maps");

enum java_vt_mount_result : u8 {
    k_java_vt_mount_success = 1,
    k_java_vt_mount_collision = 2,
    k_java_vt_mount_stale_incarnation = 3,
    k_java_vt_mount_overload = 4,
};

static __always_inline pid_key_t java_process_key(const pid_key_t *task) {
    pid_key_t process = *task;
    process.tid = process.pid;
    return process;
}

static __always_inline u64 java_process_incarnation_for(const pid_key_t *task) {
    const pid_key_t process = java_process_key(task);
    const u64 *incarnation = bpf_map_lookup_elem(&java_process_incarnations, &process);
    return incarnation ? *incarnation : 0;
}

static __always_inline u64 java_process_capability_for(const pid_key_t *task) {
    const pid_key_t process = java_process_key(task);
    const u64 *capability = bpf_map_lookup_elem(&java_authorized_processes, &process);
    return capability ? *capability : 0;
}

static __always_inline u8 java_process_authorized_for(const pid_key_t *task) {
    return java_process_capability_for(task) != 0;
}

static __always_inline u8 java_process_registered_for(const pid_key_t *task) {
    const u64 capability = java_process_capability_for(task);
    return capability && java_process_incarnation_for(task) == capability;
}

static __always_inline u8 java_current_process_authorized() {
    pid_key_t task = {0};
    task_tid(&task);
    return java_process_authorized_for(&task);
}

static __always_inline u64 java_current_process_incarnation() {
    pid_key_t task = {0};
    task_tid(&task);
    return java_process_incarnation_for(&task);
}

static __always_inline u8 java_register_process_incarnation(u64 incarnation) {
    if (!incarnation) {
        return 0;
    }
    pid_key_t task = {0};
    task_tid(&task);
    if (!incarnation || java_process_capability_for(&task) != incarnation) {
        return 0;
    }
    const pid_key_t process = java_process_key(&task);
    return bpf_map_update_elem(&java_process_incarnations, &process, &incarnation, BPF_ANY) == 0;
}

static __always_inline pid_key_t java_vt_synthetic_owner(const pid_key_t *carrier, u64 vt_id) {
    pid_key_t owner = *carrier;
    owner.tid = JAVA_VT_TID_FLAG | ((u32)vt_id & ~JAVA_VT_TID_FLAG);
    return owner;
}

static __always_inline u8 java_vt_identity_equal(const java_vt_identity_t *left,
                                                 const java_vt_identity_t *right) {
    return left->virtual_thread_id == right->virtual_thread_id &&
           left->process_incarnation == right->process_incarnation;
}

static __always_inline enum java_vt_mount_result
java_vt_prepare_mount(const pid_key_t *carrier,
                      u64 vt_id,
                      pid_key_t *synthetic_owner,
                      java_vt_identity_t *mount_identity) {
    u64 incarnation = java_process_incarnation_for(carrier);
    if (!vt_id || (java_remote_parent_enabled && !incarnation)) {
        return k_java_vt_mount_overload;
    }
    if (!incarnation) {
        incarnation = 1;
    }

    *synthetic_owner = java_vt_synthetic_owner(carrier, vt_id);
    mount_identity->virtual_thread_id = vt_id;
    mount_identity->process_incarnation = incarnation;

    const java_vt_identity_t *existing = bpf_map_lookup_elem(&java_vt_identities, synthetic_owner);
    if (existing) {
        if (java_vt_identity_equal(existing, mount_identity)) {
            return k_java_vt_mount_success;
        }
        return existing->process_incarnation == incarnation ? k_java_vt_mount_collision
                                                            : k_java_vt_mount_stale_incarnation;
    }

    if (bpf_map_update_elem(&java_vt_identities, synthetic_owner, mount_identity, BPF_NOEXIST) !=
        0) {
        existing = bpf_map_lookup_elem(&java_vt_identities, synthetic_owner);
        if (!existing) {
            return k_java_vt_mount_overload;
        }
        if (!java_vt_identity_equal(existing, mount_identity)) {
            return existing->process_incarnation == incarnation ? k_java_vt_mount_collision
                                                                : k_java_vt_mount_stale_incarnation;
        }
    }
    return k_java_vt_mount_success;
}

static __always_inline u8 java_vt_replace_stale_identity(const pid_key_t *synthetic_owner,
                                                         const java_vt_identity_t *mount_identity) {
    bpf_map_delete_elem(&java_vt_identities, synthetic_owner);
    if (bpf_map_update_elem(&java_vt_identities, synthetic_owner, mount_identity, BPF_NOEXIST) !=
        0) {
        return 0;
    }
    const java_vt_identity_t *published = bpf_map_lookup_elem(&java_vt_identities, synthetic_owner);
    return published && java_vt_identity_equal(published, mount_identity);
}

static __always_inline u8 java_vt_publish_mount(const pid_key_t *carrier,
                                                const java_vt_identity_t *mount_identity) {
    return bpf_map_update_elem(&java_vt_threads, carrier, mount_identity, BPF_ANY) == 0;
}

// Rewrites a mounted carrier only after full-id and process-incarnation
// validation. Missing/evicted/mismatched guards deliberately fail closed.
static __always_inline u8 java_vt_translate_tid(pid_key_t *p_key) {
    const java_vt_identity_t *mounted = bpf_map_lookup_elem(&java_vt_threads, p_key);
    if (!mounted) {
        return 0;
    }
    const java_vt_identity_t mounted_copy = *mounted;
    if (!mounted_copy.process_incarnation ||
        (java_remote_parent_enabled &&
         java_process_incarnation_for(p_key) != mounted_copy.process_incarnation)) {
        return 0;
    }

    const pid_key_t owner = java_vt_synthetic_owner(p_key, mounted_copy.virtual_thread_id);
    const java_vt_identity_t *identity = bpf_map_lookup_elem(&java_vt_identities, &owner);
    if (!identity || !java_vt_identity_equal(identity, &mounted_copy)) {
        return 0;
    }

    p_key->tid = owner.tid;
    return 1;
}

static __always_inline u8 java_vt_mounted(void) {
    pid_key_t p_key = {0};
    task_tid(&p_key);
    return java_vt_translate_tid(&p_key);
}

static __always_inline u8 java_vt_terminate_identity(const pid_key_t *carrier,
                                                     u64 vt_id,
                                                     pid_key_t *owner) {
    u64 incarnation = java_process_incarnation_for(carrier);
    if (!vt_id || (java_remote_parent_enabled && !incarnation)) {
        return 0;
    }
    if (!incarnation) {
        incarnation = 1;
    }
    *owner = java_vt_synthetic_owner(carrier, vt_id);
    const java_vt_identity_t expected = {
        .virtual_thread_id = vt_id,
        .process_incarnation = incarnation,
    };
    const java_vt_identity_t *identity = bpf_map_lookup_elem(&java_vt_identities, owner);
    if (!identity || !java_vt_identity_equal(identity, &expected)) {
        return 0;
    }

    const java_vt_identity_t *mounted = bpf_map_lookup_elem(&java_vt_threads, carrier);
    if (mounted && java_vt_identity_equal(mounted, &expected)) {
        bpf_map_delete_elem(&java_vt_threads, carrier);
    }
    bpf_map_delete_elem(&java_vt_identities, owner);
    return 1;
}
