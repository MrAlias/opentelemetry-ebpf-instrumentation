/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include "getsockopt_fault_shim.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

enum {
  java_remote_parent_response_size = 64,
  java_remote_parent_abi_version = 1,
  java_remote_parent_socket_level = 0x4f42,
  java_remote_parent_socket_take = 0x4a01,
  java_remote_parent_socket_discard = 0x4a02,
  java_remote_parent_socket_health = 0x4a05,
  java_remote_parent_status_valid = 1,
  java_remote_parent_status_missing = 2,
  java_remote_parent_version_offset = 4,
  java_remote_parent_size_offset = 6,
  java_remote_parent_status_offset = 8,
  java_remote_parent_little_endian_high_byte_offset = 1,
  java_remote_parent_reserved_prefix_offset = 10,
  java_remote_parent_trace_id_offset = 16,
  java_remote_parent_trace_id_size = 16,
  java_remote_parent_span_id_offset = 32,
  java_remote_parent_span_id_size = 8,
  java_remote_parent_generation_offset = 40,
  java_remote_parent_observed_monotime_offset = 48,
  java_remote_parent_reserved_suffix_offset = 56,
  java_remote_parent_test_trace_id_byte = 0xa1,
  java_remote_parent_test_span_id_byte = 0xb2,
  java_remote_parent_fault_version = 2,
  java_remote_parent_fault_file_private_mode = 0600,
  java_remote_parent_fault_file_group_readable_mode = 0640,
  java_remote_parent_fault_file_group_writable_mode = 0620,
  java_remote_parent_concurrent_attempt_count = 8,
  java_remote_parent_live_fd_barrier_timeout_millis = 20,
  java_remote_parent_live_fd_barrier_non_matching_timeout_millis = 1000,
  java_remote_parent_live_fd_barrier_wait_attempts = 200,
  java_remote_parent_live_fd_barrier_wait_nanoseconds = 5000000,
  java_remote_parent_live_fd_barrier_non_matching_max_millis = 500,
  java_remote_parent_live_fd_barrier_max_timeout_millis = 1000,
  java_remote_parent_probe_native_unsupported = 1,
  java_remote_parent_probe_missing = 2,
  java_remote_parent_probe_unsafe = 3,
};

static const char fault_file_environment[] =
    "OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_FILE";
static const char java_remote_parent_magic[] = "OBIJ";
static const char java_remote_parent_live_fd_barrier_mode[] = "live-fd-barrier";
static const char java_remote_parent_auto_unavailable_mode[] =
    "auto-unavailable";
static const char java_remote_parent_unix_socket_path[] =
    "/var/run/obi/java-remote-parent.sock";
static const char java_remote_parent_live_fd_ready_prefix[] = "ready:";
static const char java_remote_parent_live_fd_release_prefix[] = "release:";
static char fault_file_path[] = "/tmp/obi-java-fault-shim.XXXXXX";
static char fault_directory_path[] = "/tmp/obi-java-fault-shim-dir.XXXXXX";
static char fault_hardlink_path[] = "/tmp/obi-java-fault-shim-hardlink.XXXXXX";
static char fault_symlink_path[] = "/tmp/obi-java-fault-shim-link.XXXXXX";

static void
valid_response(unsigned char response[java_remote_parent_response_size]) {
  memset(response, 0, java_remote_parent_response_size);
  memcpy(response, java_remote_parent_magic,
         sizeof(java_remote_parent_magic) - 1);
  response[java_remote_parent_version_offset] = java_remote_parent_abi_version;
  response[java_remote_parent_size_offset] = java_remote_parent_response_size;
  response[java_remote_parent_status_offset] = java_remote_parent_status_valid;
  memset(response + java_remote_parent_trace_id_offset,
         java_remote_parent_test_trace_id_byte,
         java_remote_parent_trace_id_size);
  memset(response + java_remote_parent_span_id_offset,
         java_remote_parent_test_span_id_byte, java_remote_parent_span_id_size);
  response[java_remote_parent_generation_offset] =
      java_remote_parent_abi_version;
  response[java_remote_parent_observed_monotime_offset] =
      java_remote_parent_abi_version;
}

static void
missing_response(unsigned char response[java_remote_parent_response_size]) {
  memset(response, 0, java_remote_parent_response_size);
  memcpy(response, java_remote_parent_magic,
         sizeof(java_remote_parent_magic) - 1);
  response[java_remote_parent_version_offset] = java_remote_parent_abi_version;
  response[java_remote_parent_size_offset] = java_remote_parent_response_size;
  response[java_remote_parent_status_offset] =
      java_remote_parent_status_missing;
}

static void set_fault_mode(const char *mode) {
  const int descriptor =
      open(fault_file_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
           java_remote_parent_fault_file_private_mode);
  assert(descriptor >= 0);
  if (mode != NULL) {
    const size_t mode_length = strlen(mode);
    assert(write(descriptor, mode, mode_length) == (ssize_t)mode_length);
  }
  assert(close(descriptor) == 0);
}

static void overwrite_fault_mode_in_place(const char *mode) {
  assert(mode != NULL);

  struct stat before;
  assert(lstat(fault_file_path, &before) == 0);
  const int descriptor =
      open(fault_file_path, O_WRONLY | O_TRUNC | O_CLOEXEC | O_NOFOLLOW);
  assert(descriptor >= 0);

  struct stat opened;
  assert(fstat(descriptor, &opened) == 0);
  assert(opened.st_dev == before.st_dev && opened.st_ino == before.st_ino);

  const size_t mode_length = strlen(mode);
  assert(write(descriptor, mode, mode_length) == (ssize_t)mode_length);
  assert(close(descriptor) == 0);

  struct stat after;
  assert(lstat(fault_file_path, &after) == 0);
  assert(after.st_dev == before.st_dev && after.st_ino == before.st_ino);
}

static bool fault_file_matches(const char *expected) {
  char value[64];
  const int descriptor = open(fault_file_path, O_RDONLY | O_CLOEXEC);
  assert(descriptor >= 0);
  const ssize_t length = read(descriptor, value, sizeof(value));
  assert(length >= 0);
  assert(close(descriptor) == 0);
  const size_t expected_length = strlen(expected);
  return (size_t)length == expected_length &&
         memcmp(value, expected, expected_length) == 0;
}

static void wait_for_fault_file(const char *expected) {
  const struct timespec delay = {
      .tv_sec = 0,
      .tv_nsec = java_remote_parent_live_fd_barrier_wait_nanoseconds,
  };
  for (unsigned int attempt = 0;
       attempt < java_remote_parent_live_fd_barrier_wait_attempts; attempt++) {
    if (fault_file_matches(expected)) {
      return;
    }
    assert(nanosleep(&delay, NULL) == 0);
  }
  assert(false);
}

static void release_live_fd_barrier(int socket) {
  char release[64];
  const int release_length =
      snprintf(release, sizeof(release), "%s%d\n",
               java_remote_parent_live_fd_release_prefix, socket);
  assert(release_length > 0 && (size_t)release_length < sizeof(release));
  overwrite_fault_mode_in_place(release);
}

static void wait_for_live_fd_barrier_release_observation(int socket) {
  const struct timespec delay = {
      .tv_sec = 0,
      .tv_nsec = java_remote_parent_live_fd_barrier_wait_nanoseconds,
  };
  for (unsigned int attempt = 0;
       attempt < java_remote_parent_live_fd_barrier_wait_attempts; attempt++) {
    if (obi_demo_java_remote_parent_live_fd_barrier_observed_release_for_test() ==
        socket) {
      return;
    }
    assert(nanosleep(&delay, NULL) == 0);
  }
  assert(false);
}

static int64_t monotonic_millis(void) {
  struct timespec value;
  assert(clock_gettime(CLOCK_MONOTONIC, &value) == 0);
  return (int64_t)value.tv_sec * 1000 + value.tv_nsec / 1000000;
}

static void test_missing_empty_and_invalid_controls_do_not_mutate(void) {
  unsigned char response[java_remote_parent_response_size];
  unsigned char expected[java_remote_parent_response_size];
  socklen_t length = java_remote_parent_response_size;

  valid_response(response);
  memcpy(expected, response, sizeof(expected));
  assert(unsetenv(fault_file_environment) == 0);
  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);
  assert(setenv(fault_file_environment, fault_file_path, 1) == 0);

  assert(unlink(fault_file_path) == 0);
  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);

  set_fault_mode(NULL);
  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);

  set_fault_mode("unexpected");
  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);

  set_fault_mode("zero-trace-id");
  assert(setenv(fault_file_environment, fault_directory_path, 1) == 0);
  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);

  assert(symlink(fault_file_path, fault_symlink_path) == 0);
  assert(setenv(fault_file_environment, fault_symlink_path, 1) == 0);
  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);
  assert(unlink(fault_symlink_path) == 0);
  assert(setenv(fault_file_environment, fault_file_path, 1) == 0);

  assert(chmod(fault_file_path,
               java_remote_parent_fault_file_group_writable_mode) == 0);
  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);
  assert(chmod(fault_file_path, java_remote_parent_fault_file_private_mode) ==
         0);

  assert(chmod(fault_file_path,
               java_remote_parent_fault_file_group_readable_mode) == 0);
  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);
  assert(chmod(fault_file_path, java_remote_parent_fault_file_private_mode) ==
         0);

  assert(link(fault_file_path, fault_hardlink_path) == 0);
  assert(setenv(fault_file_environment, fault_hardlink_path, 1) == 0);
  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);
  assert(unlink(fault_hardlink_path) == 0);
  assert(setenv(fault_file_environment, fault_file_path, 1) == 0);
}

static void test_version_mismatch_mode(void) {
  unsigned char response[java_remote_parent_response_size];
  socklen_t length = java_remote_parent_response_size;

  valid_response(response);
  set_fault_mode("version-mismatch\n");
  assert(obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(response[java_remote_parent_version_offset] ==
         java_remote_parent_fault_version);
  assert(response[java_remote_parent_version_offset + 1] == 0);
  assert(response[java_remote_parent_trace_id_offset] ==
         java_remote_parent_test_trace_id_byte);
  assert(response[java_remote_parent_span_id_offset] ==
         java_remote_parent_test_span_id_byte);
}

static void test_bad_size_mode(void) {
  unsigned char response[java_remote_parent_response_size];
  unsigned char expected[java_remote_parent_response_size];
  socklen_t length = java_remote_parent_response_size;

  valid_response(response);
  memcpy(expected, response, sizeof(expected));
  expected[java_remote_parent_size_offset] =
      java_remote_parent_response_size - 1;
  expected[java_remote_parent_size_offset +
           java_remote_parent_little_endian_high_byte_offset] = 0;
  set_fault_mode("bad-size");
  assert(obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(length == java_remote_parent_response_size);
  assert(memcmp(response, expected, sizeof(expected)) == 0);
}

static void test_zero_trace_id_mode(void) {
  unsigned char response[java_remote_parent_response_size];
  socklen_t length = java_remote_parent_response_size;

  valid_response(response);
  set_fault_mode("zero-trace-id");
  assert(obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  for (size_t index = 0; index < java_remote_parent_trace_id_size; index++) {
    assert(response[java_remote_parent_trace_id_offset + index] == 0);
  }
  assert(response[java_remote_parent_span_id_offset] ==
         java_remote_parent_test_span_id_byte);
}

static void test_zero_span_id_mode(void) {
  unsigned char response[java_remote_parent_response_size];
  socklen_t length = java_remote_parent_response_size;

  valid_response(response);
  set_fault_mode("zero-span-id\r\n");
  assert(obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  for (size_t index = 0; index < java_remote_parent_span_id_size; index++) {
    assert(response[java_remote_parent_span_id_offset + index] == 0);
  }
  assert(response[java_remote_parent_trace_id_offset] ==
         java_remote_parent_test_trace_id_byte);
}

static void test_eligible_response_consumes_control(void) {
  unsigned char response[java_remote_parent_response_size];
  unsigned char expected[java_remote_parent_response_size];
  socklen_t length = java_remote_parent_response_size;

  set_fault_mode("zero-trace-id");
  valid_response(response);
  assert(obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  for (size_t index = 0; index < java_remote_parent_trace_id_size; index++) {
    assert(response[java_remote_parent_trace_id_offset + index] == 0);
  }

  valid_response(response);
  memcpy(expected, response, sizeof(expected));
  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);
}

struct concurrent_attempt {
  pthread_barrier_t *barrier;
  unsigned char response[java_remote_parent_response_size];
  socklen_t length;
  bool applied;
};

static void *consume_control_concurrently(void *argument) {
  struct concurrent_attempt *const attempt = argument;
  const int barrier_result = pthread_barrier_wait(attempt->barrier);
  assert(barrier_result == 0 ||
         barrier_result == PTHREAD_BARRIER_SERIAL_THREAD);
  attempt->applied = obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      attempt->response, &attempt->length);
  return NULL;
}

static void test_concurrent_eligible_responses_consume_control_once(void) {
  pthread_barrier_t barrier;
  pthread_t threads[java_remote_parent_concurrent_attempt_count];
  struct concurrent_attempt
      attempts[java_remote_parent_concurrent_attempt_count];

  set_fault_mode("zero-trace-id");
  assert(pthread_barrier_init(
             &barrier, NULL, java_remote_parent_concurrent_attempt_count) == 0);
  for (size_t index = 0; index < java_remote_parent_concurrent_attempt_count;
       index++) {
    attempts[index].barrier = &barrier;
    valid_response(attempts[index].response);
    attempts[index].length = java_remote_parent_response_size;
    attempts[index].applied = false;
    assert(pthread_create(&threads[index], NULL, consume_control_concurrently,
                          &attempts[index]) == 0);
  }

  unsigned int applied_count = 0;
  for (size_t index = 0; index < java_remote_parent_concurrent_attempt_count;
       index++) {
    assert(pthread_join(threads[index], NULL) == 0);
    unsigned char expected[java_remote_parent_response_size];
    valid_response(expected);
    if (attempts[index].applied) {
      applied_count++;
      for (size_t trace_index = 0;
           trace_index < java_remote_parent_trace_id_size; trace_index++) {
        assert(attempts[index].response[java_remote_parent_trace_id_offset +
                                        trace_index] == 0);
      }
    } else {
      assert(memcmp(attempts[index].response, expected, sizeof(expected)) == 0);
    }
  }
  assert(applied_count == 1);
  assert(pthread_barrier_destroy(&barrier) == 0);
}

static void test_only_exact_successful_take_responses_mutate(void) {
  unsigned char response[java_remote_parent_response_size];
  unsigned char expected[java_remote_parent_response_size];
  socklen_t length = java_remote_parent_response_size;

  set_fault_mode("zero-trace-id");
  valid_response(response);
  memcpy(expected, response, sizeof(expected));
  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      -1, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);

  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, 0, java_remote_parent_socket_take, response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);

  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_discard,
      response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);

  length = java_remote_parent_response_size - 1;
  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);

  length = java_remote_parent_response_size;
  response[0] = 'X';
  memcpy(expected, response, sizeof(expected));
  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);

  valid_response(response);
  response[java_remote_parent_status_offset] =
      java_remote_parent_status_missing;
  memcpy(expected, response, sizeof(expected));
  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);

  valid_response(response);
  response[java_remote_parent_version_offset] =
      java_remote_parent_fault_version;
  memcpy(expected, response, sizeof(expected));
  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);

  valid_response(response);
  response[java_remote_parent_version_offset +
           java_remote_parent_little_endian_high_byte_offset] =
      java_remote_parent_abi_version;
  memcpy(expected, response, sizeof(expected));
  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);

  valid_response(response);
  response[java_remote_parent_size_offset]--;
  memcpy(expected, response, sizeof(expected));
  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);

  valid_response(response);
  response[java_remote_parent_size_offset +
           java_remote_parent_little_endian_high_byte_offset] =
      java_remote_parent_abi_version;
  memcpy(expected, response, sizeof(expected));
  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);

  valid_response(response);
  response[java_remote_parent_reserved_prefix_offset] = 1;
  memcpy(expected, response, sizeof(expected));
  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);

  valid_response(response);
  response[java_remote_parent_reserved_suffix_offset] = 1;
  memcpy(expected, response, sizeof(expected));
  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);

  valid_response(response);
  memset(response + java_remote_parent_trace_id_offset, 0,
         java_remote_parent_trace_id_size);
  memcpy(expected, response, sizeof(expected));
  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);

  valid_response(response);
  memset(response + java_remote_parent_span_id_offset, 0,
         java_remote_parent_span_id_size);
  memcpy(expected, response, sizeof(expected));
  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);

  valid_response(response);
  response[java_remote_parent_generation_offset] = 0;
  memcpy(expected, response, sizeof(expected));
  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);

  valid_response(response);
  response[java_remote_parent_observed_monotime_offset] = 0;
  memcpy(expected, response, sizeof(expected));
  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  assert(memcmp(response, expected, sizeof(response)) == 0);

  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take, NULL,
      &length));
  assert(!obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, NULL));

  valid_response(response);
  length = java_remote_parent_response_size;
  assert(obi_demo_java_remote_parent_apply_getsockopt_fault(
      0, java_remote_parent_socket_level, java_remote_parent_socket_take,
      response, &length));
  for (size_t index = 0; index < java_remote_parent_trace_id_size; index++) {
    assert(response[java_remote_parent_trace_id_offset + index] == 0);
  }
}

static void test_interposed_getsockopt_forwards_non_obi_calls(void) {
  int sockets[2];
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);

  int socket_type = 0;
  socklen_t length = sizeof(socket_type);
  set_fault_mode("zero-trace-id");
  assert(getsockopt(sockets[0], SOL_SOCKET, SO_TYPE, &socket_type, &length) ==
         0);
  assert(length == sizeof(socket_type));
  assert(socket_type == SOCK_STREAM);

  assert(close(sockets[0]) == 0);
  assert(close(sockets[1]) == 0);
}

static void test_same_fd_probe_requires_canonical_missing_response(void) {
  unsigned char response[java_remote_parent_response_size];
  missing_response(response);
  assert(obi_demo_java_remote_parent_classify_same_fd_probe_for_test(
             0, 0, response, sizeof(response)) ==
         java_remote_parent_probe_missing);

  response[java_remote_parent_generation_offset] = 1;
  assert(obi_demo_java_remote_parent_classify_same_fd_probe_for_test(
             0, 0, response, sizeof(response)) ==
         java_remote_parent_probe_unsafe);
  response[java_remote_parent_generation_offset] = 0;

  response[java_remote_parent_observed_monotime_offset] = 1;
  assert(obi_demo_java_remote_parent_classify_same_fd_probe_for_test(
             0, 0, response, sizeof(response)) ==
         java_remote_parent_probe_unsafe);
  response[java_remote_parent_observed_monotime_offset] = 0;

  response[java_remote_parent_reserved_prefix_offset] = 1;
  assert(obi_demo_java_remote_parent_classify_same_fd_probe_for_test(
             0, 0, response, sizeof(response)) ==
         java_remote_parent_probe_unsafe);
  response[java_remote_parent_reserved_prefix_offset] = 0;

  response[java_remote_parent_trace_id_offset] = 1;
  assert(obi_demo_java_remote_parent_classify_same_fd_probe_for_test(
             0, 0, response, sizeof(response)) ==
         java_remote_parent_probe_unsafe);
}

struct auto_unavailable_attempt {
  pthread_barrier_t *barrier;
  int socket;
  const struct sockaddr_un *address;
  socklen_t address_length;
  _Atomic bool complete;
  int health_result;
  int health_error;
  int connect_result;
  int connect_error;
};

static void *probe_auto_unavailable_concurrently(void *argument) {
  struct auto_unavailable_attempt *const attempt = argument;
  const int barrier_result = pthread_barrier_wait(attempt->barrier);
  assert(barrier_result == 0 ||
         barrier_result == PTHREAD_BARRIER_SERIAL_THREAD);

  uint64_t health = 0;
  socklen_t health_length = sizeof(health);
  attempt->health_result =
      getsockopt(attempt->socket, java_remote_parent_socket_level,
                 java_remote_parent_socket_health, &health, &health_length);
  attempt->health_error = errno;

  const int client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  assert(client >= 0);
  attempt->connect_result =
      connect(client, (const struct sockaddr *)attempt->address,
              attempt->address_length);
  attempt->connect_error = errno;
  assert(close(client) == 0);
  atomic_store_explicit(&attempt->complete, true, memory_order_release);
  return NULL;
}

static unsigned int
wait_for_auto_unavailable_attempts(struct auto_unavailable_attempt *attempts,
                                   size_t attempt_count) {
  const struct timespec delay = {
      .tv_sec = 0,
      .tv_nsec = java_remote_parent_live_fd_barrier_wait_nanoseconds,
  };
  for (unsigned int wait = 0;
       wait < java_remote_parent_live_fd_barrier_wait_attempts; wait++) {
    unsigned int completed = 0;
    for (size_t index = 0; index < attempt_count; index++) {
      if (atomic_load_explicit(&attempts[index].complete,
                               memory_order_acquire)) {
        completed++;
      }
    }
    if (completed == attempt_count) {
      return completed;
    }
    assert(nanosleep(&delay, NULL) == 0);
  }
  return 0;
}

static unsigned int run_auto_unavailable_attempts_while_exclusively_locked(
    int socket, const struct sockaddr_un *address, socklen_t address_length,
    struct auto_unavailable_attempt *attempts, pthread_t *threads,
    size_t attempt_count) {
  const int exclusive_reader =
      open(fault_file_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  assert(exclusive_reader >= 0);
  assert(flock(exclusive_reader, LOCK_EX | LOCK_NB) == 0);

  pthread_barrier_t barrier;
  assert(pthread_barrier_init(&barrier, NULL,
                              (unsigned int)attempt_count + 1) == 0);
  for (size_t index = 0; index < attempt_count; index++) {
    attempts[index] = (struct auto_unavailable_attempt){
        .barrier = &barrier,
        .socket = socket,
        .address = address,
        .address_length = address_length,
        .complete = false,
        .health_result = 0,
        .health_error = 0,
        .connect_result = 0,
        .connect_error = 0,
    };
    assert(pthread_create(&threads[index], NULL,
                          probe_auto_unavailable_concurrently,
                          &attempts[index]) == 0);
  }
  const int barrier_result = pthread_barrier_wait(&barrier);
  assert(barrier_result == 0 ||
         barrier_result == PTHREAD_BARRIER_SERIAL_THREAD);
  const unsigned int completed_while_locked =
      wait_for_auto_unavailable_attempts(attempts, attempt_count);
  assert(flock(exclusive_reader, LOCK_UN) == 0);
  assert(close(exclusive_reader) == 0);
  for (size_t index = 0; index < attempt_count; index++) {
    assert(pthread_join(threads[index], NULL) == 0);
  }
  assert(pthread_barrier_destroy(&barrier) == 0);
  return completed_while_locked;
}

static void test_auto_unavailable_is_exact_persistent_and_recoverable(void) {
  int sockets[2];
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
  set_fault_mode(java_remote_parent_auto_unavailable_mode);
  obi_demo_java_remote_parent_reset_auto_unavailable_counts_for_test();
  obi_demo_java_remote_parent_reset_real_getsockopt_call_count_for_test();

  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  assert(strlen(java_remote_parent_unix_socket_path) <
         sizeof(address.sun_path));
  memcpy(address.sun_path, java_remote_parent_unix_socket_path,
         sizeof(java_remote_parent_unix_socket_path));
  const socklen_t address_length =
      (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                  sizeof(java_remote_parent_unix_socket_path));

  pthread_t threads[java_remote_parent_concurrent_attempt_count];
  struct auto_unavailable_attempt
      attempts[java_remote_parent_concurrent_attempt_count];
  assert(run_auto_unavailable_attempts_while_exclusively_locked(
             sockets[0], &address, address_length, attempts, threads,
             java_remote_parent_concurrent_attempt_count) ==
         java_remote_parent_concurrent_attempt_count);
  for (size_t index = 0; index < java_remote_parent_concurrent_attempt_count;
       index++) {
    assert(attempts[index].health_result == -1);
    assert(attempts[index].health_error == ENOPROTOOPT);
    assert(attempts[index].connect_result == -1);
    assert(attempts[index].connect_error == ECONNREFUSED);
  }

  for (unsigned int attempt = 0; attempt < 2; attempt++) {
    uint64_t health = 0;
    socklen_t health_length = sizeof(health);
    assert(getsockopt(sockets[0], java_remote_parent_socket_level,
                      java_remote_parent_socket_health, &health,
                      &health_length) == -1);
    assert(errno == ENOPROTOOPT);

    const int client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    assert(client >= 0);
    assert(connect(client, (const struct sockaddr *)&address, address_length) ==
           -1);
    assert(errno == ECONNREFUSED);
    assert(close(client) == 0);
    assert(fault_file_matches(java_remote_parent_auto_unavailable_mode));
  }
  assert(obi_demo_java_remote_parent_auto_unavailable_health_count_for_test() ==
         java_remote_parent_concurrent_attempt_count + 2);
  assert(
      obi_demo_java_remote_parent_auto_unavailable_connect_count_for_test() ==
      java_remote_parent_concurrent_attempt_count + 2);
  assert(obi_demo_java_remote_parent_real_getsockopt_call_count_for_test() ==
         0);
  assert(obi_demo_java_remote_parent_real_connect_count_for_test() == 0);

  int socket_type = 0;
  socklen_t socket_type_length = sizeof(socket_type);
  assert(getsockopt(sockets[0], SOL_SOCKET, SO_TYPE, &socket_type,
                    &socket_type_length) == 0);
  assert(socket_type == SOCK_STREAM);
  assert(obi_demo_java_remote_parent_real_getsockopt_call_count_for_test() ==
         1);

  const int other = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  assert(other >= 0);
  struct sockaddr_un other_address;
  memset(&other_address, 0, sizeof(other_address));
  other_address.sun_family = AF_UNIX;
  assert(strlen(fault_symlink_path) < sizeof(other_address.sun_path));
  memcpy(other_address.sun_path, fault_symlink_path,
         strlen(fault_symlink_path) + 1);
  const socklen_t other_length =
      (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                  strlen(fault_symlink_path) + 1);
  assert(connect(other, (const struct sockaddr *)&other_address,
                 other_length) == -1);
  assert(errno == ENOENT);
  assert(
      obi_demo_java_remote_parent_auto_unavailable_connect_count_for_test() ==
      java_remote_parent_concurrent_attempt_count + 2);
  assert(obi_demo_java_remote_parent_real_connect_count_for_test() == 1);
  assert(close(other) == 0);

  const int trailing = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  assert(trailing >= 0);
  struct sockaddr_un trailing_address = address;
  trailing_address.sun_path[sizeof(java_remote_parent_unix_socket_path)] = 'x';
  const int trailing_connect = connect(
      trailing, (const struct sockaddr *)&trailing_address, address_length + 1);
  assert(trailing_connect == 0 || trailing_connect == -1);
  assert(
      obi_demo_java_remote_parent_auto_unavailable_connect_count_for_test() ==
      java_remote_parent_concurrent_attempt_count + 2);
  assert(obi_demo_java_remote_parent_real_connect_count_for_test() == 2);
  assert(close(trailing) == 0);

  assert(connect(-1, (const struct sockaddr *)&address, address_length) == -1);
  assert(errno == EBADF);
  assert(
      obi_demo_java_remote_parent_auto_unavailable_connect_count_for_test() ==
      java_remote_parent_concurrent_attempt_count + 2);
  assert(obi_demo_java_remote_parent_real_connect_count_for_test() == 3);

  const struct sockaddr *const invalid_address =
      (const struct sockaddr *)(uintptr_t)1;
  assert(connect(-1, invalid_address, address_length) == -1);
  assert(errno == EBADF);
  assert(
      obi_demo_java_remote_parent_auto_unavailable_connect_count_for_test() ==
      java_remote_parent_concurrent_attempt_count + 2);
  assert(obi_demo_java_remote_parent_real_connect_count_for_test() == 4);

  const int non_socket = open(fault_file_path, O_RDONLY | O_CLOEXEC);
  assert(non_socket >= 0);
  assert(connect(non_socket, invalid_address, address_length) == -1);
  assert(errno == ENOTSOCK || errno == EFAULT);
  assert(
      obi_demo_java_remote_parent_auto_unavailable_connect_count_for_test() ==
      java_remote_parent_concurrent_attempt_count + 2);
  assert(obi_demo_java_remote_parent_real_connect_count_for_test() == 5);
  assert(close(non_socket) == 0);

  const int inet = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  assert(inet >= 0);
  const int inet_connect =
      connect(inet, (const struct sockaddr *)&address, address_length);
  assert(inet_connect == 0 || inet_connect == -1);
  assert(
      obi_demo_java_remote_parent_auto_unavailable_connect_count_for_test() ==
      java_remote_parent_concurrent_attempt_count + 2);
  assert(obi_demo_java_remote_parent_real_connect_count_for_test() == 6);
  assert(close(inet) == 0);

  const int datagram = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  assert(datagram >= 0);
  const int datagram_connect =
      connect(datagram, (const struct sockaddr *)&address, address_length);
  assert(datagram_connect == 0 || datagram_connect == -1);
  assert(
      obi_demo_java_remote_parent_auto_unavailable_connect_count_for_test() ==
      java_remote_parent_concurrent_attempt_count + 2);
  assert(obi_demo_java_remote_parent_real_connect_count_for_test() == 7);
  assert(close(datagram) == 0);

  set_fault_mode(NULL);
  assert(fault_file_matches(""));

  uint64_t recovered_health = 0;
  socklen_t recovered_health_length = sizeof(recovered_health);
  assert(getsockopt(sockets[0], java_remote_parent_socket_level,
                    java_remote_parent_socket_health, &recovered_health,
                    &recovered_health_length) == -1);
  assert(obi_demo_java_remote_parent_real_getsockopt_call_count_for_test() ==
         2);
  assert(obi_demo_java_remote_parent_auto_unavailable_health_count_for_test() ==
         java_remote_parent_concurrent_attempt_count + 2);

  const int recovered_client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  assert(recovered_client >= 0);
  const int recovered_connect = connect(
      recovered_client, (const struct sockaddr *)&address, address_length);
  assert(recovered_connect == 0 || recovered_connect == -1);
  assert(obi_demo_java_remote_parent_real_connect_count_for_test() == 8);
  assert(
      obi_demo_java_remote_parent_auto_unavailable_connect_count_for_test() ==
      java_remote_parent_concurrent_attempt_count + 2);
  assert(close(recovered_client) == 0);

  assert(close(sockets[0]) == 0);
  assert(close(sockets[1]) == 0);
}

static void test_persistent_probe_does_not_wait_on_other_fault_modes(void) {
  int sockets[2];
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
  set_fault_mode(java_remote_parent_live_fd_barrier_mode);
  obi_demo_java_remote_parent_reset_auto_unavailable_counts_for_test();
  obi_demo_java_remote_parent_reset_real_getsockopt_call_count_for_test();

  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  memcpy(address.sun_path, java_remote_parent_unix_socket_path,
         sizeof(java_remote_parent_unix_socket_path));
  const socklen_t address_length =
      (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                  sizeof(java_remote_parent_unix_socket_path));

  pthread_t thread;
  struct auto_unavailable_attempt attempt;
  assert(run_auto_unavailable_attempts_while_exclusively_locked(
             sockets[0], &address, address_length, &attempt, &thread, 1) == 1);
  assert(obi_demo_java_remote_parent_auto_unavailable_health_count_for_test() ==
         0);
  assert(
      obi_demo_java_remote_parent_auto_unavailable_connect_count_for_test() ==
      0);
  assert(obi_demo_java_remote_parent_real_getsockopt_call_count_for_test() ==
         1);
  assert(obi_demo_java_remote_parent_real_connect_count_for_test() == 1);
  assert(fault_file_matches(java_remote_parent_live_fd_barrier_mode));

  set_fault_mode(NULL);
  assert(close(sockets[0]) == 0);
  assert(close(sockets[1]) == 0);
}

struct live_fd_barrier_attempt {
  int socket;
  _Atomic bool complete;
  int result;
  int error;
};

static void *wait_for_live_fd_barrier(void *argument) {
  struct live_fd_barrier_attempt *const attempt = argument;
  unsigned char response[java_remote_parent_response_size];
  socklen_t length = sizeof(response);
  attempt->result =
      getsockopt(attempt->socket, java_remote_parent_socket_level,
                 java_remote_parent_socket_take, response, &length);
  attempt->error = errno;
  atomic_store(&attempt->complete, true);
  return NULL;
}

static void test_live_fd_barrier_blocks_exact_take_until_release(void) {
  int sockets[2];
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
  const int alias = dup(sockets[0]);
  assert(alias >= 0);
  set_fault_mode(java_remote_parent_live_fd_barrier_mode);
  obi_demo_java_remote_parent_reset_real_getsockopt_call_count_for_test();
  obi_demo_java_remote_parent_reset_live_fd_barrier_observed_release_for_test();
  obi_demo_java_remote_parent_reset_wrong_live_socket_probe_for_test();
  obi_demo_java_remote_parent_reset_same_fd_probes_for_test();

  struct live_fd_barrier_attempt attempt = {
      .socket = sockets[0],
      .complete = false,
      .result = 0,
      .error = 0,
  };
  pthread_t thread;
  assert(pthread_create(&thread, NULL, wait_for_live_fd_barrier, &attempt) ==
         0);

  char ready[64];
  const int ready_length =
      snprintf(ready, sizeof(ready),
               "%s%d:task=native-unsupported:thread=native-unsupported\n",
               java_remote_parent_live_fd_ready_prefix, sockets[0]);
  assert(ready_length > 0 && (size_t)ready_length < sizeof(ready));
  wait_for_fault_file(ready);
  assert(!atomic_load(&attempt.complete));
  assert(obi_demo_java_remote_parent_real_getsockopt_call_count_for_test() ==
         0);
  assert(obi_demo_java_remote_parent_wrong_live_socket_probe_count_for_test() ==
         1);
  assert(obi_demo_java_remote_parent_same_fd_task_probe_count_for_test() == 1);
  assert(obi_demo_java_remote_parent_same_fd_task_probe_outcome_for_test() ==
         java_remote_parent_probe_native_unsupported);
  assert(obi_demo_java_remote_parent_same_fd_thread_probe_count_for_test() ==
         1);
  assert(obi_demo_java_remote_parent_same_fd_thread_probe_outcome_for_test() ==
         java_remote_parent_probe_native_unsupported);
  const int wrong_live_socket_errno =
      obi_demo_java_remote_parent_wrong_live_socket_probe_errno_for_test();
  assert(wrong_live_socket_errno == ENOPROTOOPT ||
         wrong_live_socket_errno == EOPNOTSUPP);

  release_live_fd_barrier(sockets[1]);
  wait_for_live_fd_barrier_release_observation(sockets[1]);
  assert(!atomic_load(&attempt.complete));
  assert(obi_demo_java_remote_parent_real_getsockopt_call_count_for_test() ==
         0);
  assert(obi_demo_java_remote_parent_wrong_live_socket_probe_count_for_test() ==
         1);
  assert(obi_demo_java_remote_parent_same_fd_task_probe_count_for_test() == 1);
  assert(obi_demo_java_remote_parent_same_fd_thread_probe_count_for_test() ==
         1);

  release_live_fd_barrier(alias);
  wait_for_live_fd_barrier_release_observation(alias);
  assert(!atomic_load(&attempt.complete));
  assert(obi_demo_java_remote_parent_real_getsockopt_call_count_for_test() ==
         0);

  release_live_fd_barrier(sockets[0]);
  assert(pthread_join(thread, NULL) == 0);
  assert(atomic_load(&attempt.complete));
  assert(attempt.result == -1);
  assert(attempt.error == ENOPROTOOPT || attempt.error == EOPNOTSUPP);
  assert(obi_demo_java_remote_parent_real_getsockopt_call_count_for_test() ==
         1);
  assert(obi_demo_java_remote_parent_wrong_live_socket_probe_count_for_test() ==
         1);
  assert(obi_demo_java_remote_parent_same_fd_task_probe_count_for_test() == 1);
  assert(obi_demo_java_remote_parent_same_fd_thread_probe_count_for_test() ==
         1);
  assert(fault_file_matches(""));

  assert(close(alias) == 0);
  assert(close(sockets[0]) == 0);
  assert(close(sockets[1]) == 0);
}

static void test_live_fd_barrier_ignores_non_matching_requests(void) {
  int sockets[2];
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
  unsigned char response[java_remote_parent_response_size];
  socklen_t short_length = sizeof(response) - 1;

  obi_demo_java_remote_parent_set_live_fd_barrier_timeout_for_test(
      java_remote_parent_live_fd_barrier_non_matching_timeout_millis);
  set_fault_mode(java_remote_parent_live_fd_barrier_mode);
  obi_demo_java_remote_parent_reset_real_getsockopt_call_count_for_test();

  int64_t start = monotonic_millis();
  assert(getsockopt(sockets[0], java_remote_parent_socket_level,
                    java_remote_parent_socket_take, response,
                    &short_length) == -1);
  assert(monotonic_millis() - start <
         java_remote_parent_live_fd_barrier_non_matching_max_millis);
  assert(obi_demo_java_remote_parent_real_getsockopt_call_count_for_test() ==
         1);
  assert(fault_file_matches(java_remote_parent_live_fd_barrier_mode));

  socklen_t length = sizeof(response);
  start = monotonic_millis();
  assert(getsockopt(sockets[0], java_remote_parent_socket_level,
                    java_remote_parent_socket_discard, response,
                    &length) == -1);
  assert(monotonic_millis() - start <
         java_remote_parent_live_fd_barrier_non_matching_max_millis);
  assert(obi_demo_java_remote_parent_real_getsockopt_call_count_for_test() ==
         2);
  assert(fault_file_matches(java_remote_parent_live_fd_barrier_mode));

  int socket_type = 0;
  length = sizeof(socket_type);
  start = monotonic_millis();
  assert(getsockopt(sockets[0], SOL_SOCKET, SO_TYPE, &socket_type, &length) ==
         0);
  assert(monotonic_millis() - start <
         java_remote_parent_live_fd_barrier_non_matching_max_millis);
  assert(socket_type == SOCK_STREAM);
  assert(obi_demo_java_remote_parent_real_getsockopt_call_count_for_test() ==
         3);
  assert(fault_file_matches(java_remote_parent_live_fd_barrier_mode));
  set_fault_mode(NULL);
  obi_demo_java_remote_parent_set_live_fd_barrier_timeout_for_test(
      java_remote_parent_live_fd_barrier_timeout_millis);

  assert(close(sockets[0]) == 0);
  assert(close(sockets[1]) == 0);
}

static void test_live_fd_barrier_times_out_boundedly(void) {
  int sockets[2];
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
  unsigned char response[java_remote_parent_response_size];
  socklen_t length = sizeof(response);

  obi_demo_java_remote_parent_set_live_fd_barrier_timeout_for_test(
      java_remote_parent_live_fd_barrier_timeout_millis);
  set_fault_mode(java_remote_parent_live_fd_barrier_mode);
  const int64_t start = monotonic_millis();
  assert(getsockopt(sockets[0], java_remote_parent_socket_level,
                    java_remote_parent_socket_take, response, &length) == -1);
  const int64_t elapsed = monotonic_millis() - start;
  assert(errno == ETIMEDOUT);
  assert(elapsed >= java_remote_parent_live_fd_barrier_timeout_millis);
  assert(elapsed < java_remote_parent_live_fd_barrier_max_timeout_millis);
  set_fault_mode(NULL);
  obi_demo_java_remote_parent_set_live_fd_barrier_timeout_for_test(
      java_remote_parent_live_fd_barrier_timeout_millis);

  assert(close(sockets[0]) == 0);
  assert(close(sockets[1]) == 0);
}

int main(void) {
  const char *const original_file = getenv(fault_file_environment);
  char *const saved_file = original_file == NULL ? NULL : strdup(original_file);
  assert(original_file == NULL || saved_file != NULL);
  const int descriptor = mkstemp(fault_file_path);
  assert(descriptor >= 0);
  assert(close(descriptor) == 0);
  assert(mkdtemp(fault_directory_path) != NULL);
  const int hardlink_descriptor = mkstemp(fault_hardlink_path);
  assert(hardlink_descriptor >= 0);
  assert(close(hardlink_descriptor) == 0);
  assert(unlink(fault_hardlink_path) == 0);
  const int symlink_descriptor = mkstemp(fault_symlink_path);
  assert(symlink_descriptor >= 0);
  assert(close(symlink_descriptor) == 0);
  assert(unlink(fault_symlink_path) == 0);
  assert(setenv(fault_file_environment, fault_file_path, 1) == 0);

  test_missing_empty_and_invalid_controls_do_not_mutate();
  test_version_mismatch_mode();
  test_bad_size_mode();
  test_zero_trace_id_mode();
  test_zero_span_id_mode();
  test_eligible_response_consumes_control();
  test_concurrent_eligible_responses_consume_control_once();
  test_only_exact_successful_take_responses_mutate();
  test_interposed_getsockopt_forwards_non_obi_calls();
  test_same_fd_probe_requires_canonical_missing_response();
  test_auto_unavailable_is_exact_persistent_and_recoverable();
  test_persistent_probe_does_not_wait_on_other_fault_modes();
  test_live_fd_barrier_blocks_exact_take_until_release();
  test_live_fd_barrier_ignores_non_matching_requests();
  test_live_fd_barrier_times_out_boundedly();

  assert(unlink(fault_file_path) == 0);
  assert(rmdir(fault_directory_path) == 0);
  if (saved_file == NULL) {
    assert(unsetenv(fault_file_environment) == 0);
  } else {
    assert(setenv(fault_file_environment, saved_file, 1) == 0);
  }
  free(saved_file);
  return 0;
}
