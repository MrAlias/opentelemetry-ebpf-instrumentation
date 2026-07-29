/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include "getsockopt_fault_shim.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
  java_remote_parent_response_size = 64,
  java_remote_parent_abi_version = 1,
  java_remote_parent_socket_level = 0x4f42,
  java_remote_parent_socket_take = 0x4a01,
  java_remote_parent_status_valid = 1,
  java_remote_parent_version_offset = 4,
  java_remote_parent_size_offset = 6,
  java_remote_parent_status_offset = 8,
  java_remote_parent_reserved_prefix_offset = 10,
  java_remote_parent_reserved_prefix_size = 6,
  java_remote_parent_trace_id_offset = 16,
  java_remote_parent_trace_id_size = 16,
  java_remote_parent_span_id_offset = 32,
  java_remote_parent_span_id_size = 8,
  java_remote_parent_generation_offset = 40,
  java_remote_parent_generation_size = 8,
  java_remote_parent_observed_monotime_offset = 48,
  java_remote_parent_observed_monotime_size = 8,
  java_remote_parent_reserved_suffix_offset = 56,
  java_remote_parent_reserved_suffix_size = 8,
  java_remote_parent_fault_version = 2,
  java_remote_parent_fault_mode_max_size = 32,
  java_remote_parent_fault_control_single_link_count = 1,
};

static const char java_remote_parent_fault_file_environment[] =
    "OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_FILE";
static const char java_remote_parent_magic[] = "OBIJ";

enum java_remote_parent_fault_mode {
  java_remote_parent_fault_disabled,
  java_remote_parent_fault_version_mismatch,
  java_remote_parent_fault_zero_trace_id,
  java_remote_parent_fault_zero_span_id,
};

typedef int (*getsockopt_fn)(int, int, int, void *, socklen_t *);

static getsockopt_fn real_getsockopt;
static pthread_once_t real_getsockopt_once = PTHREAD_ONCE_INIT;

_Static_assert(sizeof(real_getsockopt) == sizeof(void *),
               "dlsym function pointer size mismatch");

static bool java_remote_parent_fault_mode_matches(const char *value,
                                                  size_t value_length,
                                                  const char *mode) {
  const size_t mode_length = strlen(mode);
  if (value_length == mode_length) {
    return memcmp(value, mode, mode_length) == 0;
  }
  if (value_length == mode_length + 1 && value[mode_length] == '\n') {
    return memcmp(value, mode, mode_length) == 0;
  }
  return value_length == mode_length + 2 && value[mode_length] == '\r' &&
         value[mode_length + 1] == '\n' &&
         memcmp(value, mode, mode_length) == 0;
}

static bool java_remote_parent_bytes_are_zero(const unsigned char *value,
                                              size_t value_size) {
  for (size_t index = 0; index < value_size; index++) {
    if (value[index] != 0) {
      return false;
    }
  }
  return true;
}

/* The harness publishes a private single-link control file before each
 * intentional fault. */
static bool java_remote_parent_fault_control_is_trusted(int descriptor) {
  struct stat metadata;
  return fstat(descriptor, &metadata) == 0 && S_ISREG(metadata.st_mode) &&
         metadata.st_uid == geteuid() &&
         metadata.st_nlink ==
             java_remote_parent_fault_control_single_link_count &&
         (metadata.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

static enum java_remote_parent_fault_mode java_remote_parent_fault_mode(void) {
  const char *const path = getenv(java_remote_parent_fault_file_environment);
  if (path == NULL || path[0] == '\0') {
    return java_remote_parent_fault_disabled;
  }

  const int descriptor =
      open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (descriptor < 0) {
    return java_remote_parent_fault_disabled;
  }
  if (!java_remote_parent_fault_control_is_trusted(descriptor) ||
      flock(descriptor, LOCK_EX | LOCK_NB) != 0 ||
      !java_remote_parent_fault_control_is_trusted(descriptor)) {
    (void)close(descriptor);
    return java_remote_parent_fault_disabled;
  }

  char value[java_remote_parent_fault_mode_max_size];
  ssize_t value_length;
  do {
    value_length = read(descriptor, value, sizeof(value));
  } while (value_length < 0 && errno == EINTR);

  enum java_remote_parent_fault_mode mode = java_remote_parent_fault_disabled;
  if (value_length <= 0 ||
      value_length == java_remote_parent_fault_mode_max_size) {
    (void)close(descriptor);
    return mode;
  }
  if (java_remote_parent_fault_mode_matches(value, (size_t)value_length,
                                            "version-mismatch")) {
    mode = java_remote_parent_fault_version_mismatch;
  } else if (java_remote_parent_fault_mode_matches(value, (size_t)value_length,
                                                   "zero-trace-id")) {
    mode = java_remote_parent_fault_zero_trace_id;
  } else if (java_remote_parent_fault_mode_matches(value, (size_t)value_length,
                                                   "zero-span-id")) {
    mode = java_remote_parent_fault_zero_span_id;
  }
  if (mode != java_remote_parent_fault_disabled &&
      ftruncate(descriptor, 0) != 0) {
    mode = java_remote_parent_fault_disabled;
  }
  (void)close(descriptor);
  return mode;
}

static bool java_remote_parent_valid_take_response(int result, int level,
                                                   int option,
                                                   const void *optval,
                                                   const socklen_t *optlen) {
  if (result != 0 || level != java_remote_parent_socket_level ||
      option != java_remote_parent_socket_take || optval == NULL ||
      optlen == NULL || *optlen != java_remote_parent_response_size) {
    return false;
  }

  const unsigned char *const response = optval;
  if (memcmp(response, java_remote_parent_magic,
             sizeof(java_remote_parent_magic) - 1) != 0 ||
      response[java_remote_parent_version_offset] !=
          java_remote_parent_abi_version ||
      response[java_remote_parent_version_offset + 1] != 0 ||
      response[java_remote_parent_size_offset] !=
          java_remote_parent_response_size ||
      response[java_remote_parent_size_offset + 1] != 0 ||
      response[java_remote_parent_status_offset] !=
          java_remote_parent_status_valid ||
      !java_remote_parent_bytes_are_zero(
          response + java_remote_parent_reserved_prefix_offset,
          java_remote_parent_reserved_prefix_size) ||
      !java_remote_parent_bytes_are_zero(
          response + java_remote_parent_reserved_suffix_offset,
          java_remote_parent_reserved_suffix_size) ||
      java_remote_parent_bytes_are_zero(response +
                                            java_remote_parent_trace_id_offset,
                                        java_remote_parent_trace_id_size) ||
      java_remote_parent_bytes_are_zero(response +
                                            java_remote_parent_span_id_offset,
                                        java_remote_parent_span_id_size) ||
      java_remote_parent_bytes_are_zero(
          response + java_remote_parent_generation_offset,
          java_remote_parent_generation_size) ||
      java_remote_parent_bytes_are_zero(
          response + java_remote_parent_observed_monotime_offset,
          java_remote_parent_observed_monotime_size)) {
    return false;
  }
  return true;
}

bool obi_demo_java_remote_parent_apply_getsockopt_fault(
    int result, int level, int option, void *optval, const socklen_t *optlen) {
  if (!java_remote_parent_valid_take_response(result, level, option, optval,
                                              optlen)) {
    return false;
  }
  const enum java_remote_parent_fault_mode mode =
      java_remote_parent_fault_mode();
  if (mode == java_remote_parent_fault_disabled) {
    return false;
  }

  unsigned char *const response = optval;
  switch (mode) {
  case java_remote_parent_fault_version_mismatch:
    response[java_remote_parent_version_offset] =
        java_remote_parent_fault_version;
    response[java_remote_parent_version_offset + 1] = 0;
    return true;
  case java_remote_parent_fault_zero_trace_id:
    memset(response + java_remote_parent_trace_id_offset, 0,
           java_remote_parent_trace_id_size);
    return true;
  case java_remote_parent_fault_zero_span_id:
    memset(response + java_remote_parent_span_id_offset, 0,
           java_remote_parent_span_id_size);
    return true;
  case java_remote_parent_fault_disabled:
    return false;
  }

  return false;
}

static void resolve_real_getsockopt(void) {
  const void *const symbol = dlsym(RTLD_NEXT, "getsockopt");
  memcpy(&real_getsockopt, &symbol, sizeof(real_getsockopt));
}

int getsockopt(int socket, int level, int option, void *optval,
               socklen_t *optlen) {
  if (pthread_once(&real_getsockopt_once, resolve_real_getsockopt) != 0 ||
      real_getsockopt == NULL) {
    errno = ENOSYS;
    return -1;
  }

  const int result = real_getsockopt(socket, level, option, optval, optlen);
  const int saved_errno = errno;
  (void)obi_demo_java_remote_parent_apply_getsockopt_fault(
      result, level, option, optval, optlen);
  errno = saved_errno;
  return result;
}
