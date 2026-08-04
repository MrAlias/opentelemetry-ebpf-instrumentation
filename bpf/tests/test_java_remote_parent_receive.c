// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common/connection_info.h>

static void test_begin_data_receive(u64 process_capability);
static long test_probe_read_user(void *destination, unsigned int size, const void *source);

#define JAVA_REMOTE_PARENT_BEGIN_DATA_RECEIVE(process_capability)                                  \
    test_begin_data_receive(process_capability)

#include <generictracer/java_remote_parent_receive.h>

#undef JAVA_REMOTE_PARENT_BEGIN_DATA_RECEIVE

static int sequence;
static int begin_sequence;
static int read_sequence;
static int read_failure;
static u64 observed_process_capability;
static const void *expected_source;

static void fail(const char *message) {
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

static void reset(const void *source, int fail_read) {
    sequence = 0;
    begin_sequence = 0;
    read_sequence = 0;
    read_failure = fail_read;
    observed_process_capability = 0;
    expected_source = source;
}

static void test_begin_data_receive(u64 process_capability) {
    begin_sequence = ++sequence;
    observed_process_capability = process_capability;
}

static long test_probe_read_user(void *destination, unsigned int size, const void *source) {
    read_sequence = ++sequence;
    if (source != expected_source || size != sizeof(connection_info_t)) {
        fail("claimed connection read used the wrong source or size");
    }
    if (read_failure) {
        return -1;
    }
    memcpy(destination, source, size);
    return 0;
}

// Mirrors the production dispatch split: the lightweight boundary gate runs
// before the sibling data handler performs its first advisory tuple read.
static u8 test_receive_and_read_claimed(u8 enabled,
                                        u8 data_hook_ready,
                                        u8 registered,
                                        u8 op,
                                        const unsigned char *uarg,
                                        connection_info_t *claimed) {
    const u64 process_capability = 0x1020304050607080ULL;
    if (!java_remote_parent_begin_receive(
            enabled, data_hook_ready, registered, op, process_capability)) {
        return 0;
    }
    return test_probe_read_user(claimed, sizeof(*claimed), uarg + 1) == 0;
}

static void test_rejected_receive_detaches_before_the_failed_read(void) {
    unsigned char packet[1 + sizeof(connection_info_t)] = {0};
    connection_info_t claimed = {0};
    reset(packet + 1, 1);

    if (test_receive_and_read_claimed(1, 1, 1, TCP_RECV, packet, &claimed) || begin_sequence != 1 ||
        read_sequence != 2 || observed_process_capability != 0x1020304050607080ULL) {
        fail("rejected receive did not detach before its first failing validation");
    }
}

static void test_unregistered_receive_detaches_without_reading_the_claim(void) {
    unsigned char packet[1 + sizeof(connection_info_t)] = {0};
    connection_info_t claimed = {0};
    reset(packet + 1, 0);

    if (test_receive_and_read_claimed(1, 1, 0, TCP_RECV, packet, &claimed) || begin_sequence != 1 ||
        read_sequence != 0 || observed_process_capability != 0x1020304050607080ULL) {
        fail("unregistered receive did not detach before its registration rejection");
    }
}

static void test_valid_receive_detaches_before_copying_the_claim(void) {
    unsigned char packet[1 + sizeof(connection_info_t)] = {0};
    connection_info_t expected = {.s_port = 1234, .d_port = 443};
    connection_info_t claimed = {0};
    memcpy(packet + 1, &expected, sizeof(expected));
    reset(packet + 1, 0);

    if (!test_receive_and_read_claimed(1, 1, 1, TCP_RECV, packet, &claimed) ||
        begin_sequence != 1 || read_sequence != 2 ||
        observed_process_capability != 0x1020304050607080ULL ||
        memcmp(&claimed, &expected, sizeof(expected)) != 0) {
        fail("valid receive did not detach before copying its claimed connection");
    }
}

static void test_non_receives_and_disabled_bridges_do_not_detach(void) {
    unsigned char packet[1 + sizeof(connection_info_t)] = {0};
    connection_info_t claimed = {0};

    reset(packet + 1, 0);
    if (!test_receive_and_read_claimed(1, 1, 1, TCP_SEND, packet, &claimed) ||
        begin_sequence != 0 || read_sequence != 1) {
        fail("send operation detached receive state");
    }

    reset(packet + 1, 0);
    if (!test_receive_and_read_claimed(0, 1, 1, TCP_RECV, packet, &claimed) ||
        begin_sequence != 0 || read_sequence != 1) {
        fail("disabled bridge detached receive state");
    }

    reset(packet + 1, 0);
    if (!test_receive_and_read_claimed(1, 0, 1, TCP_RECV, packet, &claimed) ||
        begin_sequence != 0 || read_sequence != 1) {
        fail("unready data hook detached receive state");
    }
}

int main(void) {
    test_rejected_receive_detaches_before_the_failed_read();
    test_unregistered_receive_detaches_without_reading_the_claim();
    test_valid_receive_detaches_before_copying_the_claim();
    test_non_receives_and_disabled_bridges_do_not_detach();
    return 0;
}
