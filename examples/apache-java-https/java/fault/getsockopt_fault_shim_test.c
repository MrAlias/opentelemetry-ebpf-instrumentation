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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

enum {
  java_remote_parent_response_size = 64,
  java_remote_parent_abi_version = 1,
  java_remote_parent_socket_level = 0x4f42,
  java_remote_parent_socket_take = 0x4a01,
  java_remote_parent_socket_discard = 0x4a02,
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
};

static const char fault_file_environment[] =
    "OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_FILE";
static const char java_remote_parent_magic[] = "OBIJ";
static const char java_remote_parent_live_fd_barrier_mode[] = "live-fd-barrier";
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
      snprintf(ready, sizeof(ready), "%s%d\n",
               java_remote_parent_live_fd_ready_prefix, sockets[0]);
  assert(ready_length > 0 && (size_t)ready_length < sizeof(ready));
  wait_for_fault_file(ready);
  assert(!atomic_load(&attempt.complete));
  assert(obi_demo_java_remote_parent_real_getsockopt_call_count_for_test() ==
         0);

  release_live_fd_barrier(sockets[1]);
  wait_for_live_fd_barrier_release_observation(sockets[1]);
  assert(!atomic_load(&attempt.complete));
  assert(obi_demo_java_remote_parent_real_getsockopt_call_count_for_test() ==
         0);

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
