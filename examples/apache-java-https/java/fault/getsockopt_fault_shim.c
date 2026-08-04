/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include "getsockopt_fault_shim.h"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#if defined(OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_TESTING)
#include <limits.h>
#include <stdatomic.h>
#endif

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
  java_remote_parent_fault_mode_max_size = 64,
  java_remote_parent_fault_control_single_link_count = 1,
  java_remote_parent_fault_control_private_mode = 0600,
  /* The runner reserves a bounded 55-second proof window before release. */
  java_remote_parent_live_fd_barrier_timeout_millis = 90000,
  java_remote_parent_live_fd_barrier_poll_nanoseconds = 10000000,
  java_remote_parent_nanoseconds_per_millisecond = 1000000,
  java_remote_parent_nanoseconds_per_second = 1000000000,
};

static const char java_remote_parent_fault_file_environment[] =
    "OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_FILE";
static const char java_remote_parent_magic[] = "OBIJ";
static const char java_remote_parent_live_fd_barrier_mode[] = "live-fd-barrier";
static const char java_remote_parent_live_fd_ready_prefix[] = "ready:";
static const char java_remote_parent_live_fd_release_prefix[] = "release:";

enum java_remote_parent_fault_mode {
  java_remote_parent_fault_disabled,
  java_remote_parent_fault_version_mismatch,
  java_remote_parent_fault_bad_size,
  java_remote_parent_fault_zero_trace_id,
  java_remote_parent_fault_zero_span_id,
  java_remote_parent_fault_live_fd_barrier,
};

typedef int (*getsockopt_fn)(int, int, int, void *, socklen_t *);

static getsockopt_fn real_getsockopt;
static pthread_once_t real_getsockopt_once = PTHREAD_ONCE_INIT;

#if defined(OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_TESTING)
static int java_remote_parent_live_fd_barrier_timeout_for_test =
    java_remote_parent_live_fd_barrier_timeout_millis;
static _Atomic unsigned int
    java_remote_parent_real_getsockopt_call_count_for_test;
static _Atomic int java_remote_parent_live_fd_barrier_observed_release_for_test;
static _Atomic unsigned int
    java_remote_parent_wrong_live_socket_probe_count_for_test;
static _Atomic int java_remote_parent_wrong_live_socket_probe_errno_for_test;

void obi_demo_java_remote_parent_set_live_fd_barrier_timeout_for_test(
    int timeout_millis) {
  java_remote_parent_live_fd_barrier_timeout_for_test = timeout_millis;
}

void obi_demo_java_remote_parent_reset_real_getsockopt_call_count_for_test(
    void) {
  atomic_store_explicit(&java_remote_parent_real_getsockopt_call_count_for_test,
                        0, memory_order_relaxed);
}

unsigned int
obi_demo_java_remote_parent_real_getsockopt_call_count_for_test(void) {
  return atomic_load_explicit(
      &java_remote_parent_real_getsockopt_call_count_for_test,
      memory_order_relaxed);
}

void obi_demo_java_remote_parent_reset_live_fd_barrier_observed_release_for_test(
    void) {
  atomic_store_explicit(
      &java_remote_parent_live_fd_barrier_observed_release_for_test, -1,
      memory_order_relaxed);
}

int obi_demo_java_remote_parent_live_fd_barrier_observed_release_for_test(
    void) {
  return atomic_load_explicit(
      &java_remote_parent_live_fd_barrier_observed_release_for_test,
      memory_order_relaxed);
}

void obi_demo_java_remote_parent_reset_wrong_live_socket_probe_for_test(void) {
  atomic_store_explicit(
      &java_remote_parent_wrong_live_socket_probe_count_for_test, 0,
      memory_order_relaxed);
  atomic_store_explicit(
      &java_remote_parent_wrong_live_socket_probe_errno_for_test, 0,
      memory_order_relaxed);
}

unsigned int
obi_demo_java_remote_parent_wrong_live_socket_probe_count_for_test(void) {
  return atomic_load_explicit(
      &java_remote_parent_wrong_live_socket_probe_count_for_test,
      memory_order_relaxed);
}

int obi_demo_java_remote_parent_wrong_live_socket_probe_errno_for_test(void) {
  return atomic_load_explicit(
      &java_remote_parent_wrong_live_socket_probe_errno_for_test,
      memory_order_relaxed);
}
#endif

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
         (metadata.st_mode & 07777) ==
             java_remote_parent_fault_control_private_mode;
}

static int java_remote_parent_open_trusted_fault_control(void) {
  const char *const path = getenv(java_remote_parent_fault_file_environment);
  if (path == NULL || path[0] == '\0') {
    return -1;
  }

  const int descriptor =
      open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (descriptor < 0) {
    return -1;
  }
  if (!java_remote_parent_fault_control_is_trusted(descriptor) ||
      flock(descriptor, LOCK_EX | LOCK_NB) != 0 ||
      !java_remote_parent_fault_control_is_trusted(descriptor)) {
    (void)close(descriptor);
    return -1;
  }
  return descriptor;
}

static ssize_t java_remote_parent_read_fault_control(int descriptor,
                                                     char *value,
                                                     size_t value_size) {
  ssize_t value_length;
  do {
    if (lseek(descriptor, 0, SEEK_SET) < 0) {
      return -1;
    }
    value_length = read(descriptor, value, value_size);
  } while (value_length < 0 && errno == EINTR);
  return value_length;
}

static bool java_remote_parent_clear_fault_control(int descriptor) {
  return ftruncate(descriptor, 0) == 0;
}

static bool java_remote_parent_write_all(int descriptor, const char *value,
                                         size_t value_size) {
  size_t written_total = 0;
  while (written_total < value_size) {
    const ssize_t written =
        write(descriptor, value + written_total, value_size - written_total);
    if (written > 0) {
      written_total += (size_t)written;
      continue;
    }
    if (written < 0 && errno == EINTR) {
      continue;
    }
    return false;
  }
  return true;
}

static bool java_remote_parent_write_fault_control(int descriptor,
                                                   const char *value,
                                                   size_t value_size) {
  return java_remote_parent_clear_fault_control(descriptor) &&
         lseek(descriptor, 0, SEEK_SET) >= 0 &&
         java_remote_parent_write_all(descriptor, value, value_size);
}

static void java_remote_parent_close_preserving_errno(int descriptor) {
  const int saved_errno = errno;
  (void)close(descriptor);
  errno = saved_errno;
}

static int java_remote_parent_live_fd_barrier_timeout(void) {
#if defined(OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_TESTING)
  return java_remote_parent_live_fd_barrier_timeout_for_test;
#else
  return java_remote_parent_live_fd_barrier_timeout_millis;
#endif
}

static bool
java_remote_parent_timespec_at_or_after(const struct timespec *left,
                                        const struct timespec *right) {
  return left->tv_sec > right->tv_sec ||
         (left->tv_sec == right->tv_sec && left->tv_nsec >= right->tv_nsec);
}

static bool
java_remote_parent_live_fd_barrier_deadline(struct timespec *deadline) {
  const int timeout_millis = java_remote_parent_live_fd_barrier_timeout();
  if (timeout_millis <= 0 || clock_gettime(CLOCK_MONOTONIC, deadline) != 0) {
    return false;
  }
  deadline->tv_sec += timeout_millis / 1000;
  deadline->tv_nsec += (long)(timeout_millis % 1000) *
                       java_remote_parent_nanoseconds_per_millisecond;
  if (deadline->tv_nsec >= java_remote_parent_nanoseconds_per_second) {
    deadline->tv_sec++;
    deadline->tv_nsec -= java_remote_parent_nanoseconds_per_second;
  }
  return true;
}

static bool java_remote_parent_live_fd_barrier_release_matches(
    const char *value, size_t value_length, int socket) {
  char expected[java_remote_parent_fault_mode_max_size];
  const int expected_length =
      snprintf(expected, sizeof(expected), "%s%d",
               java_remote_parent_live_fd_release_prefix, socket);
  return expected_length > 0 && (size_t)expected_length < sizeof(expected) &&
         java_remote_parent_fault_mode_matches(value, value_length, expected);
}

#if defined(OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_TESTING)
static void
java_remote_parent_note_live_fd_barrier_release_for_test(const char *value,
                                                         size_t value_length) {
  const size_t prefix_length =
      sizeof(java_remote_parent_live_fd_release_prefix) - 1;
  if (value_length <= prefix_length ||
      memcmp(value, java_remote_parent_live_fd_release_prefix, prefix_length) !=
          0) {
    return;
  }

  unsigned int parsed_socket = 0;
  size_t index = prefix_length;
  for (; index < value_length; index++) {
    if (value[index] == '\n' && index + 1 == value_length) {
      break;
    }
    if (value[index] < '0' || value[index] > '9' ||
        parsed_socket > (unsigned int)(INT_MAX - (value[index] - '0')) / 10) {
      return;
    }
    parsed_socket = parsed_socket * 10 + (unsigned int)(value[index] - '0');
  }
  if (index == prefix_length) {
    return;
  }
  atomic_store_explicit(
      &java_remote_parent_live_fd_barrier_observed_release_for_test,
      (int)parsed_socket, memory_order_relaxed);
}
#endif

static bool java_remote_parent_is_exact_take_request(int socket, int level,
                                                     int option,
                                                     const void *optval,
                                                     const socklen_t *optlen) {
  return socket >= 0 && level == java_remote_parent_socket_level &&
         option == java_remote_parent_socket_take && optval != NULL &&
         optlen != NULL && *optlen == java_remote_parent_response_size;
}

static bool java_remote_parent_close_wrong_live_socket_pair(int client,
                                                            int server) {
  int close_error = 0;
  if (client >= 0 && close(client) != 0) {
    close_error = errno;
  }
  if (server >= 0 && close(server) != 0 && close_error == 0) {
    close_error = errno;
  }
  if (close_error != 0) {
    errno = close_error;
    return false;
  }
  return true;
}

/* Exercise a separate, established TCP socket from the same JVM process.
 * It deliberately has no OBI negotiation, so the BPF program must reject the
 * retrieval without reaching the held victim's socket-local state. Call the
 * resolved libc symbol directly to avoid recursing through this interposer. */
static bool java_remote_parent_probe_wrong_live_socket(void) {
  int listener = -1;
  int client = -1;
  int server = -1;
  struct sockaddr_in address;
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

  listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
  if (listener < 0 ||
      bind(listener, (const struct sockaddr *)&address, sizeof(address)) != 0) {
    goto failed;
  }
  socklen_t address_length = sizeof(address);
  if (getsockname(listener, (struct sockaddr *)&address, &address_length) !=
          0 ||
      address_length != sizeof(address) || listen(listener, 1) != 0) {
    goto failed;
  }

  client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
  if (client < 0 || connect(client, (const struct sockaddr *)&address,
                            sizeof(address)) != 0) {
    goto failed;
  }
  server = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
  if (server < 0) {
    goto failed;
  }
  /* A failed close leaves the descriptor state indeterminate, so do not retry
   * it from the generic cleanup path. */
  const int closing_listener = listener;
  listener = -1;
  if (close(closing_listener) != 0) {
    goto failed;
  }

  unsigned char response[java_remote_parent_response_size] = {0};
  socklen_t response_length = sizeof(response);
  const int result = real_getsockopt(client, java_remote_parent_socket_level,
                                     java_remote_parent_socket_take, response,
                                     &response_length);
  const int probe_errno = errno;
#if defined(OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_TESTING)
  atomic_fetch_add_explicit(
      &java_remote_parent_wrong_live_socket_probe_count_for_test, 1,
      memory_order_relaxed);
  atomic_store_explicit(
      &java_remote_parent_wrong_live_socket_probe_errno_for_test, probe_errno,
      memory_order_relaxed);
#endif
  const bool denied =
      result == -1 && (probe_errno == ENOPROTOOPT || probe_errno == EOPNOTSUPP);
  if (!java_remote_parent_close_wrong_live_socket_pair(client, server)) {
    return false;
  }
  if (!denied) {
    errno = probe_errno == 0 ? EPROTO : probe_errno;
    return false;
  }
  return true;

failed: {
  const int saved_errno = errno;
  (void)close(listener);
  (void)close(client);
  (void)close(server);
  errno = saved_errno;
}
  return false;
}

/* The private demo control intentionally pauses one live Java socket before
 * the real take consumes its one-shot BPF state. A same-container probe can
 * duplicate that exact descriptor during the bounded pause. The release
 * coordinator must truncate and write this already-open inode in place;
 * replacement is intentionally ignored after the trust check. */
static int
java_remote_parent_wait_for_live_fd_barrier(int socket, int level, int option,
                                            const void *optval,
                                            const socklen_t *optlen) {
  if (!java_remote_parent_is_exact_take_request(socket, level, option, optval,
                                                optlen)) {
    return 0;
  }

  const int descriptor = java_remote_parent_open_trusted_fault_control();
  if (descriptor < 0) {
    return 0;
  }

  char value[java_remote_parent_fault_mode_max_size];
  const ssize_t value_length =
      java_remote_parent_read_fault_control(descriptor, value, sizeof(value));
  if (value_length <= 0 ||
      value_length == java_remote_parent_fault_mode_max_size ||
      !java_remote_parent_fault_mode_matches(
          value, (size_t)value_length,
          java_remote_parent_live_fd_barrier_mode)) {
    (void)close(descriptor);
    return 0;
  }

  if (!java_remote_parent_probe_wrong_live_socket()) {
    java_remote_parent_close_preserving_errno(descriptor);
    return -1;
  }

  char ready[java_remote_parent_fault_mode_max_size];
  const int ready_length =
      snprintf(ready, sizeof(ready), "%s%d\n",
               java_remote_parent_live_fd_ready_prefix, socket);
  struct timespec deadline;
  if (ready_length <= 0 || (size_t)ready_length >= sizeof(ready)) {
    (void)close(descriptor);
    errno = EIO;
    return -1;
  }
  if (!java_remote_parent_write_fault_control(descriptor, ready,
                                              (size_t)ready_length)) {
    java_remote_parent_close_preserving_errno(descriptor);
    return -1;
  }
  if (!java_remote_parent_live_fd_barrier_deadline(&deadline)) {
    (void)close(descriptor);
    errno = ETIMEDOUT;
    return -1;
  }

  for (;;) {
    const ssize_t current_length =
        java_remote_parent_read_fault_control(descriptor, value, sizeof(value));
    if (current_length < 0) {
      java_remote_parent_close_preserving_errno(descriptor);
      return -1;
    }
#if defined(OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_TESTING)
    if (current_length > 0) {
      java_remote_parent_note_live_fd_barrier_release_for_test(
          value, (size_t)current_length);
    }
#endif
    if (current_length > 0 &&
        current_length < java_remote_parent_fault_mode_max_size &&
        java_remote_parent_live_fd_barrier_release_matches(
            value, (size_t)current_length, socket)) {
      const bool cleared = java_remote_parent_clear_fault_control(descriptor);
      if (!cleared) {
        java_remote_parent_close_preserving_errno(descriptor);
        return -1;
      }
      (void)close(descriptor);
      return 0;
    }

    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
        java_remote_parent_timespec_at_or_after(&now, &deadline)) {
      (void)close(descriptor);
      errno = ETIMEDOUT;
      return -1;
    }

    struct timespec poll_delay = {
        .tv_sec = 0,
        .tv_nsec = java_remote_parent_live_fd_barrier_poll_nanoseconds,
    };
    struct timespec remaining;
    while (nanosleep(&poll_delay, &remaining) != 0 && errno == EINTR) {
      poll_delay.tv_sec = remaining.tv_sec;
      poll_delay.tv_nsec = remaining.tv_nsec;
    }
  }
}

static enum java_remote_parent_fault_mode java_remote_parent_fault_mode(void) {
  const int descriptor = java_remote_parent_open_trusted_fault_control();
  if (descriptor < 0) {
    return java_remote_parent_fault_disabled;
  }

  char value[java_remote_parent_fault_mode_max_size];
  const ssize_t value_length =
      java_remote_parent_read_fault_control(descriptor, value, sizeof(value));

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
                                                   "bad-size")) {
    mode = java_remote_parent_fault_bad_size;
  } else if (java_remote_parent_fault_mode_matches(value, (size_t)value_length,
                                                   "zero-trace-id")) {
    mode = java_remote_parent_fault_zero_trace_id;
  } else if (java_remote_parent_fault_mode_matches(value, (size_t)value_length,
                                                   "zero-span-id")) {
    mode = java_remote_parent_fault_zero_span_id;
  } else if (java_remote_parent_fault_mode_matches(
                 value, (size_t)value_length,
                 java_remote_parent_live_fd_barrier_mode)) {
    mode = java_remote_parent_fault_live_fd_barrier;
  }
  if (mode != java_remote_parent_fault_disabled &&
      mode != java_remote_parent_fault_live_fd_barrier &&
      !java_remote_parent_clear_fault_control(descriptor)) {
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
  case java_remote_parent_fault_bad_size:
    response[java_remote_parent_size_offset] =
        java_remote_parent_response_size - 1;
    response[java_remote_parent_size_offset + 1] = 0;
    return true;
  case java_remote_parent_fault_zero_trace_id:
    memset(response + java_remote_parent_trace_id_offset, 0,
           java_remote_parent_trace_id_size);
    return true;
  case java_remote_parent_fault_zero_span_id:
    memset(response + java_remote_parent_span_id_offset, 0,
           java_remote_parent_span_id_size);
    return true;
  case java_remote_parent_fault_live_fd_barrier:
    return false;
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

  if (java_remote_parent_wait_for_live_fd_barrier(socket, level, option, optval,
                                                  optlen) != 0) {
    return -1;
  }

#if defined(OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_TESTING)
  atomic_fetch_add_explicit(
      &java_remote_parent_real_getsockopt_call_count_for_test, 1,
      memory_order_relaxed);
#endif
  const int result = real_getsockopt(socket, level, option, optval, optlen);
  const int saved_errno = errno;
  (void)obi_demo_java_remote_parent_apply_getsockopt_fault(
      result, level, option, optval, optlen);
  errno = saved_errno;
  return result;
}
