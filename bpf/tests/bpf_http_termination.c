// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

typedef uint8_t u8;
typedef uint64_t u64;

typedef struct http_info {
    u8 complete;
    u8 submitted;
    struct {
        uint16_t d_port;
    } conn_info;
} http_info_t;

typedef struct pid_connection_info {
    uint32_t pid;
} pid_connection_info_t;

struct bpf_test_map {
    int id;
};

static struct bpf_test_map ongoing_http = {.id = 1};

enum operation {
    operation_lookup,
    operation_request_cleanup,
    operation_finish,
    operation_http_cleanup,
    operation_ssl_cleanup,
};

static enum operation operations[11];
static int operation_count;
static http_info_t test_info;
static int test_info_available;

static void record(enum operation operation) {
    if (operation_count >= (int)(sizeof(operations) / sizeof(operations[0]))) {
        fprintf(stderr, "FAIL: operation log overflow\n");
        exit(1);
    }
    operations[operation_count++] = operation;
}

static void *test_map_lookup(void *map, const void *key) {
    (void)key;
    record(operation_lookup);
    if (map == &ongoing_http && test_info_available) {
        return &test_info;
    }
    return NULL;
}

#define bpf_map_lookup_elem test_map_lookup

static u8 http_info_complete(http_info_t *info) {
    return info->complete;
}

static uint64_t task_process_start_time(void) {
    return 2;
}

static uint64_t task_netns_cookie(void) {
    return 3;
}

static void cleanup_http_request_data(pid_connection_info_t *connection, http_info_t *info) {
    (void)connection;
    (void)info;
    record(operation_request_cleanup);
}

static void cleanup_terminal_ssl_connection(const pid_connection_info_t *connection,
                                            uint64_t process_start_time,
                                            uint64_t netns_cookie) {
    (void)connection;
    (void)process_start_time;
    (void)netns_cookie;
    record(operation_ssl_cleanup);
}

static void finish_http(http_info_t *info, pid_connection_info_t *connection) {
    (void)info;
    (void)connection;
    record(operation_finish);
}

static void force_finish_http(http_info_t *info, pid_connection_info_t *connection) {
    finish_http(info, connection);
}

static void cleanup_http_info(pid_connection_info_t *connection) {
    (void)connection;
    record(operation_http_cleanup);
    test_info_available = 0;
}

#define OBI_HTTP_TERMINATION_CONTEXT
#include <generictracer/http_termination.h>
#undef OBI_HTTP_TERMINATION_CONTEXT

#undef bpf_map_lookup_elem

static void reset(u8 available, u8 complete, u8 submitted) {
    operation_count = 0;
    test_info = (http_info_t){.complete = complete, .submitted = submitted};
    test_info_available = available;
}

static void
assert_operations(const enum operation *expected, int expected_count, const char *name) {
    if (operation_count != expected_count) {
        fprintf(stderr,
                "FAIL: %s operation count\n  expected %d, got %d\n",
                name,
                expected_count,
                operation_count);
        exit(1);
    }
    for (int i = 0; i < expected_count; i++) {
        if (operations[i] != expected[i]) {
            fprintf(stderr,
                    "FAIL: %s operation %d\n  expected %d, got %d\n",
                    name,
                    i,
                    expected[i],
                    operations[i]);
            exit(1);
        }
    }
}

static void test_complete_unsubmitted_request_is_finished(void) {
    static const enum operation expected[] = {
        operation_lookup,
        operation_request_cleanup,
        operation_ssl_cleanup,
        operation_finish,
        operation_http_cleanup,
    };
    reset(1, 1, 0);
    pid_connection_info_t connection = {};

    terminate_http_request_if_needed(&connection);

    assert_operations(expected, (int)(sizeof(expected) / sizeof(expected[0])), __func__);
}

static void test_non_emitting_close_still_cleans_state(u8 available,
                                                       u8 complete,
                                                       u8 submitted,
                                                       const char *name) {
    static const enum operation expected_with_request[] = {
        operation_lookup,
        operation_request_cleanup,
        operation_ssl_cleanup,
        operation_http_cleanup,
    };
    static const enum operation expected_without_request[] = {
        operation_lookup,
        operation_request_cleanup,
        operation_ssl_cleanup,
        operation_http_cleanup,
    };
    reset(available, complete, submitted);
    pid_connection_info_t connection = {};

    terminate_http_request_if_needed(&connection);

    if (available) {
        assert_operations(expected_with_request,
                          (int)(sizeof(expected_with_request) / sizeof(expected_with_request[0])),
                          name);
    } else {
        assert_operations(
            expected_without_request,
            (int)(sizeof(expected_without_request) / sizeof(expected_without_request[0])),
            name);
    }
}

static void test_repeated_close_does_not_emit_twice(void) {
    static const enum operation expected[] = {
        operation_lookup,
        operation_request_cleanup,
        operation_ssl_cleanup,
        operation_finish,
        operation_http_cleanup,
        operation_lookup,
        operation_request_cleanup,
        operation_ssl_cleanup,
        operation_http_cleanup,
    };
    reset(1, 1, 0);
    pid_connection_info_t connection = {};

    terminate_http_request_if_needed(&connection);
    terminate_http_request_if_needed(&connection);

    assert_operations(expected, (int)(sizeof(expected) / sizeof(expected[0])), __func__);
}

int main(void) {
    test_complete_unsubmitted_request_is_finished();
    test_non_emitting_close_still_cleans_state(1, 1, 1, "submitted request");
    test_non_emitting_close_still_cleans_state(1, 0, 0, "incomplete request");
    test_non_emitting_close_still_cleans_state(0, 0, 0, "missing request");
    test_repeated_close_does_not_emit_twice();
    return 0;
}
