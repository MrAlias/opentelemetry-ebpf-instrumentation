// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>

#include <bpfcore/bpf_helpers.h>

#define BPF_MAP_TYPE_SK_STORAGE 24
#define BPF_F_NO_PREALLOC 1
#define BPF_SK_STORAGE_GET_F_CREATE 1

struct bpf_sock {
    int id;
};

static void *
test_sk_storage_get(void *map, struct bpf_sock *sk, void *value, unsigned long long flags);

#define bpf_sk_storage_get test_sk_storage_get

#include <maps/java_remote_parent_socket_cookie.h>

#undef bpf_sk_storage_get

typedef struct test_socket_storage {
    struct bpf_sock *sk;
    u64 value;
    int present;
} test_socket_storage_t;

static test_socket_storage_t storage[2];
static int helper_calls;
static int fail_create;

static void fail(const char *message) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

static void reset_storage(void) {
    storage[0] = (test_socket_storage_t){0};
    storage[1] = (test_socket_storage_t){0};
    helper_calls = 0;
    fail_create = 0;
}

static void *
test_sk_storage_get(void *map, struct bpf_sock *sk, void *value, unsigned long long flags) {
    helper_calls++;
    if (map != &java_remote_parent_socket_cookies || !sk) {
        fail("socket storage helper received an invalid map or socket");
    }

    for (size_t i = 0; i < sizeof(storage) / sizeof(storage[0]); i++) {
        if (storage[i].present && storage[i].sk == sk) {
            return &storage[i].value;
        }
    }

    if (!(flags & BPF_SK_STORAGE_GET_F_CREATE) || !value || fail_create) {
        return NULL;
    }
    for (size_t i = 0; i < sizeof(storage) / sizeof(storage[0]); i++) {
        if (!storage[i].present) {
            storage[i].sk = sk;
            storage[i].value = *(const u64 *)value;
            storage[i].present = 1;
            return &storage[i].value;
        }
    }
    return NULL;
}

static void test_invalid_identity_does_not_allocate(void) {
    struct bpf_sock socket = {.id = 1};
    reset_storage();

    if (java_remote_parent_seed_socket_cookie(NULL, 41) ||
        java_remote_parent_seed_socket_cookie(&socket, 0) || helper_calls != 0) {
        fail("an invalid physical identity reached socket-local storage");
    }
}

static void test_allocation_failure_rejects_identity(void) {
    struct bpf_sock socket = {.id = 1};
    reset_storage();
    fail_create = 1;

    if (java_remote_parent_seed_socket_cookie(&socket, 41) || helper_calls != 1 ||
        storage[0].present) {
        fail("socket-local storage allocation failure did not fail closed");
    }
}

static void test_identity_is_immutable_and_socket_local(void) {
    struct bpf_sock first = {.id = 1};
    struct bpf_sock second = {.id = 2};
    reset_storage();

    if (!java_remote_parent_seed_socket_cookie(&first, 41) ||
        java_remote_parent_socket_cookie(&first) != 41 ||
        !java_remote_parent_seed_socket_cookie(&first, 41)) {
        fail("an exact socket identity was not created and reused idempotently");
    }
    if (java_remote_parent_seed_socket_cookie(&first, 42) ||
        java_remote_parent_socket_cookie(&first) != 41) {
        fail("an existing socket identity was overwritten");
    }
    if (!java_remote_parent_seed_socket_cookie(&second, 51) ||
        java_remote_parent_socket_cookie(&second) != 51 ||
        java_remote_parent_socket_cookie(&first) != 41) {
        fail("physical socket identities were not isolated");
    }
}

static void test_zero_existing_identity_is_not_repaired(void) {
    struct bpf_sock socket = {.id = 1};
    reset_storage();
    storage[0] = (test_socket_storage_t){.sk = &socket, .present = 1};

    if (java_remote_parent_seed_socket_cookie(&socket, 41) || storage[0].value != 0) {
        fail("a malformed existing socket identity was overwritten");
    }
}

static void test_missing_lookup_returns_zero(void) {
    struct bpf_sock socket = {.id = 1};
    reset_storage();

    if (java_remote_parent_socket_cookie(NULL) != 0 || helper_calls != 0 ||
        java_remote_parent_socket_cookie(&socket) != 0 || helper_calls != 1) {
        fail("missing socket-local identity did not return zero");
    }
}

int main(void) {
    test_invalid_identity_does_not_allocate();
    test_allocation_failure_rejects_identity();
    test_identity_is_immutable_and_socket_local();
    test_zero_existing_identity_is_not_repaired();
    test_missing_lookup_returns_zero();
    return 0;
}
