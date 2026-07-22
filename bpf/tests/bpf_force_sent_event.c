// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpfcore/bpf_helpers.h>

struct bpf_test_map {
    int id;
};

static void *test_map_lookup(void *map, const void *key);

#define bpf_map_lookup_elem test_map_lookup

#include <generictracer/protocol_http.h>
#include <common/send_args.h>

struct bpf_test_map ongoing_http = {.id = 1};

static const volatile u8 high_request_volume;
static send_args_t test_thread_args;
static send_args_t test_socket_args;
static int test_thread_args_available;
static int test_socket_args_available;
static http_info_t test_thread_info;
static http_info_t test_socket_info;
static http_info_t test_direct_info;
static int test_thread_cleanup_count;
static int test_socket_cleanup_count;
static int test_direct_cleanup_count;
static int test_thread_force_count;
static int test_socket_force_count;
static int test_direct_force_count;
static pid_connection_info_t test_direct_connection;

static int same_connection(const pid_connection_info_t *left, const pid_connection_info_t *right) {
    return memcmp(left, right, sizeof(*left)) == 0;
}

static void terminate_http_request_if_needed(pid_connection_info_t *connection) {
    if (same_connection(connection, &test_thread_args.p_conn)) {
        test_thread_cleanup_count++;
    } else if (same_connection(connection, &test_socket_args.p_conn)) {
        test_socket_cleanup_count++;
    } else if (same_connection(connection, &test_direct_connection)) {
        test_direct_cleanup_count++;
    }
}

static void force_terminate_http_request(pid_connection_info_t *connection) {
    terminate_http_request_if_needed(connection);
    if (same_connection(connection, &test_thread_args.p_conn)) {
        test_thread_force_count++;
    } else if (same_connection(connection, &test_socket_args.p_conn)) {
        test_socket_force_count++;
    } else if (same_connection(connection, &test_direct_connection)) {
        test_direct_force_count++;
    }
}

static void finish_possible_delayed_http_request(pid_connection_info_t *connection) {
    (void)connection;
}

#include <generictracer/k_send_receive.h>

#undef bpf_map_lookup_elem

static void *test_map_lookup(void *map, const void *key) {
    if (map == &active_send_args && test_thread_args_available) {
        return &test_thread_args;
    }
    if (map == &active_send_sock_args && test_socket_args_available) {
        return &test_socket_args;
    }
    if (map == &ongoing_http) {
        const pid_connection_info_t *connection = key;
        if (same_connection(connection, &test_thread_args.p_conn)) {
            return &test_thread_info;
        }
        if (same_connection(connection, &test_socket_args.p_conn)) {
            return &test_socket_info;
        }
        if (same_connection(connection, &test_direct_connection)) {
            return &test_direct_info;
        }
    }
    return NULL;
}

static pid_connection_info_t connection(u16 port, u32 pid) {
    return (pid_connection_info_t){
        .conn = {.s_port = port, .d_port = 443},
        .pid = pid,
    };
}

static http_info_t complete_info(void) {
    http_info_t info = {
        .status = 200,
        .start_monotime_ns = 1,
    };
    info.pid.host_pid = 42;
    return info;
}

static void reset(void) {
    test_thread_args = (send_args_t){.p_conn = connection(49152, 42)};
    test_socket_args = (send_args_t){.p_conn = connection(49153, 42)};
    test_direct_connection = connection(49154, 42);
    test_thread_args_available = 1;
    test_socket_args_available = 1;
    test_thread_info = (http_info_t){};
    test_socket_info = complete_info();
    test_direct_info = complete_info();
    test_thread_cleanup_count = 0;
    test_socket_cleanup_count = 0;
    test_direct_cleanup_count = 0;
    test_thread_force_count = 0;
    test_socket_force_count = 0;
    test_direct_force_count = 0;
}

static void assert_int_eq(int expected, int actual, const char *message) {
    if (expected != actual) {
        fprintf(stderr, "FAIL: %s\n  expected %d, got %d\n", message, expected, actual);
        exit(1);
    }
}

static void test_incomplete_thread_alias_does_not_stop_close_search(void) {
    reset();
    const u64 id = 0x2a00000001ULL;
    u64 socket = 0x1234;

    force_sent_event(id, &socket, &test_direct_connection, true);

    assert_int_eq(1, test_thread_cleanup_count, "incomplete thread alias is cleaned");
    assert_int_eq(0, test_thread_force_count, "incomplete thread alias is not emitted");
    assert_int_eq(1, test_socket_force_count, "socket alias is still examined");
    assert_int_eq(1, test_socket_cleanup_count, "completed socket alias is terminally cleaned");
    assert_int_eq(1, test_direct_force_count, "direct connection is still examined");
}

static void test_incomplete_socket_alias_does_not_stop_close_search(void) {
    reset();
    test_thread_args_available = 0;
    test_socket_info = (http_info_t){};
    const u64 id = 0x2a00000001ULL;
    u64 socket = 0x1234;

    force_sent_event(id, &socket, &test_direct_connection, true);

    assert_int_eq(1, test_socket_cleanup_count, "incomplete socket alias is cleaned");
    assert_int_eq(0, test_socket_force_count, "incomplete socket alias is not emitted");
    assert_int_eq(1, test_direct_force_count, "direct connection survives socket alias cleanup");
}

int main(void) {
    test_incomplete_thread_alias_does_not_stop_close_search();
    test_incomplete_socket_alias_does_not_stop_close_search();
    return 0;
}
