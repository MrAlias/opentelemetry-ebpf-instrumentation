// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>

#include <bpfcore/bpf_helpers.h>

enum { BPF_ANY = 0, BPF_NOEXIST = 1, BPF_EXIST = 2 };

static void *test_map_lookup(void *map, const void *key);
static unsigned long long test_ktime_get_ns(void);

#define bpf_map_lookup_elem test_map_lookup
#define bpf_ktime_get_ns test_ktime_get_ns
#include <maps/java_remote_parent_shared.h>
#undef bpf_map_lookup_elem
#undef bpf_ktime_get_ns

#define ASSERT_STAT_ABI(name, index) _Static_assert((name) == (index), #name " ABI index changed")

ASSERT_STAT_ABI(k_java_remote_parent_stat_stage_valid, 0);
ASSERT_STAT_ABI(k_java_remote_parent_stat_stage_ambiguous, 1);
ASSERT_STAT_ABI(k_java_remote_parent_stat_stage_malformed, 2);
ASSERT_STAT_ABI(k_java_remote_parent_stat_stage_overload, 3);
ASSERT_STAT_ABI(k_java_remote_parent_stat_take_valid, 4);
ASSERT_STAT_ABI(k_java_remote_parent_stat_take_missing, 5);
ASSERT_STAT_ABI(k_java_remote_parent_stat_take_stale, 6);
ASSERT_STAT_ABI(k_java_remote_parent_stat_take_ambiguous, 7);
ASSERT_STAT_ABI(k_java_remote_parent_stat_take_unauthorized, 8);
ASSERT_STAT_ABI(k_java_remote_parent_stat_take_already_consumed, 9);
ASSERT_STAT_ABI(k_java_remote_parent_stat_take_malformed, 10);
ASSERT_STAT_ABI(k_java_remote_parent_stat_take_overload, 11);
ASSERT_STAT_ABI(k_java_remote_parent_stat_discard_valid, 12);
ASSERT_STAT_ABI(k_java_remote_parent_stat_discard_missing, 13);
ASSERT_STAT_ABI(k_java_remote_parent_stat_discard_stale, 14);
ASSERT_STAT_ABI(k_java_remote_parent_stat_discard_ambiguous, 15);
ASSERT_STAT_ABI(k_java_remote_parent_stat_discard_unauthorized, 16);
ASSERT_STAT_ABI(k_java_remote_parent_stat_discard_already_consumed, 17);
ASSERT_STAT_ABI(k_java_remote_parent_stat_discard_malformed, 18);
ASSERT_STAT_ABI(k_java_remote_parent_stat_discard_overload, 19);
ASSERT_STAT_ABI(k_java_remote_parent_stat_negotiate_missing, 20);
ASSERT_STAT_ABI(k_java_remote_parent_stat_negotiate_unauthorized, 21);
ASSERT_STAT_ABI(k_java_remote_parent_stat_negotiate_overload, 22);
ASSERT_STAT_ABI(k_java_remote_parent_stat_candidate_ambiguous, 23);
ASSERT_STAT_ABI(k_java_remote_parent_stat_candidate_overload, 24);
ASSERT_STAT_ABI(k_java_remote_parent_stat_handoff_valid, 25);
ASSERT_STAT_ABI(k_java_remote_parent_stat_candidate_valid, 26);
ASSERT_STAT_ABI(k_java_remote_parent_stat_candidate_malformed, 27);
ASSERT_STAT_ABI(k_java_remote_parent_stat_inject_valid, 28);
ASSERT_STAT_ABI(k_java_remote_parent_stat_inject_missing, 29);
ASSERT_STAT_ABI(k_java_remote_parent_stat_inject_stale, 30);
ASSERT_STAT_ABI(k_java_remote_parent_stat_inject_ambiguous, 31);
ASSERT_STAT_ABI(k_java_remote_parent_stat_inject_malformed, 32);
ASSERT_STAT_ABI(k_java_remote_parent_stat_inject_overload, 33);
ASSERT_STAT_ABI(k_java_remote_parent_stat_inject_segmented, 34);
ASSERT_STAT_ABI(k_java_remote_parent_stat_handoff_admission_overload, 35);
ASSERT_STAT_ABI(k_java_remote_parent_stat_handoff_admission_ambiguous, 36);
ASSERT_STAT_ABI(k_java_remote_parent_stat_max, 37);

#undef ASSERT_STAT_ABI

static u64 stats[k_java_remote_parent_stat_max];

static void *test_map_lookup(void *map, const void *key) {
    if (map != &java_remote_parent_stats) {
        return NULL;
    }
    const u32 index = *(const u32 *)key;
    return index < k_java_remote_parent_stat_max ? &stats[index] : NULL;
}

static unsigned long long test_ktime_get_ns(void) {
    return 1;
}

static void assert_counter(u32 index, u64 expected, const char *name) {
    if (stats[index] != expected) {
        fprintf(stderr,
                "%s: expected %llu, got %llu\n",
                name,
                (unsigned long long)expected,
                (unsigned long long)stats[index]);
        exit(1);
    }
}

int main(void) {
    java_remote_parent_retrieval_stat(0, k_java_remote_parent_status_unauthorized);
    java_remote_parent_retrieval_stat(1, k_java_remote_parent_status_unauthorized);
    java_remote_parent_stat_add(k_java_remote_parent_stat_candidate_ambiguous);
    java_remote_parent_stat_add(k_java_remote_parent_stat_candidate_overload);
    java_remote_parent_stat_add(k_java_remote_parent_stat_handoff_valid);
    java_remote_parent_stat_add(k_java_remote_parent_stat_candidate_valid);
    java_remote_parent_stat_add(k_java_remote_parent_stat_candidate_malformed);
    java_remote_parent_stat_add(k_java_remote_parent_stat_inject_valid);
    java_remote_parent_stat_add(k_java_remote_parent_stat_inject_missing);
    java_remote_parent_stat_add(k_java_remote_parent_stat_inject_stale);
    java_remote_parent_stat_add(k_java_remote_parent_stat_inject_ambiguous);
    java_remote_parent_stat_add(k_java_remote_parent_stat_inject_malformed);
    java_remote_parent_stat_add(k_java_remote_parent_stat_inject_overload);
    java_remote_parent_stat_add(k_java_remote_parent_stat_inject_segmented);
    java_remote_parent_stat_add(k_java_remote_parent_stat_handoff_admission_overload);
    java_remote_parent_stat_add(k_java_remote_parent_stat_handoff_admission_ambiguous);

    assert_counter(k_java_remote_parent_stat_take_unauthorized, 1, "take unauthorized");
    assert_counter(k_java_remote_parent_stat_discard_unauthorized, 1, "discard unauthorized");
    assert_counter(k_java_remote_parent_stat_take_missing, 0, "take missing");
    assert_counter(k_java_remote_parent_stat_discard_missing, 0, "discard missing");
    assert_counter(k_java_remote_parent_stat_candidate_ambiguous, 1, "candidate ambiguous");
    assert_counter(k_java_remote_parent_stat_candidate_overload, 1, "candidate overload");
    assert_counter(k_java_remote_parent_stat_handoff_valid, 1, "handoff valid");
    assert_counter(k_java_remote_parent_stat_candidate_valid, 1, "candidate valid");
    assert_counter(k_java_remote_parent_stat_candidate_malformed, 1, "candidate malformed");
    assert_counter(k_java_remote_parent_stat_inject_valid, 1, "inject valid");
    assert_counter(k_java_remote_parent_stat_inject_missing, 1, "inject missing");
    assert_counter(k_java_remote_parent_stat_inject_stale, 1, "inject stale");
    assert_counter(k_java_remote_parent_stat_inject_ambiguous, 1, "inject ambiguous");
    assert_counter(k_java_remote_parent_stat_inject_malformed, 1, "inject malformed");
    assert_counter(k_java_remote_parent_stat_inject_overload, 1, "inject overload");
    assert_counter(k_java_remote_parent_stat_inject_segmented, 1, "inject segmented");
    assert_counter(
        k_java_remote_parent_stat_handoff_admission_overload, 1, "handoff admission overload");
    assert_counter(
        k_java_remote_parent_stat_handoff_admission_ambiguous, 1, "handoff admission ambiguous");
    return 0;
}
