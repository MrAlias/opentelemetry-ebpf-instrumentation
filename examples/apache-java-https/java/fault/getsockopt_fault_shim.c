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

#if defined(OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_TESTING)
#include <limits.h>
#include <stdatomic.h>
#endif

enum {
  java_remote_parent_response_size = 64,
  java_remote_parent_abi_version = 1,
  java_remote_parent_socket_level = 0x4f42,
  java_remote_parent_socket_take = 0x4a01,
  java_remote_parent_socket_health = 0x4a05,
  java_remote_parent_socket_task_take = 0x4a06,
  java_remote_parent_status_valid = 1,
  java_remote_parent_status_missing = 2,
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
  java_remote_parent_fault_mode_max_size = 96,
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
static const char java_remote_parent_auto_unavailable_mode[] =
    "auto-unavailable";
static const char java_remote_parent_unix_socket_path[] =
    "/var/run/obi/java-remote-parent.sock";
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
typedef int (*connect_fn)(int, __CONST_SOCKADDR_ARG, socklen_t);

static getsockopt_fn real_getsockopt;
static pthread_once_t real_getsockopt_once = PTHREAD_ONCE_INIT;
static connect_fn real_connect;
static pthread_once_t real_connect_once = PTHREAD_ONCE_INIT;

#if defined(OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_TESTING)
static int java_remote_parent_live_fd_barrier_timeout_for_test =
    java_remote_parent_live_fd_barrier_timeout_millis;
static _Atomic unsigned int
    java_remote_parent_real_getsockopt_call_count_for_test;
static _Atomic int java_remote_parent_live_fd_barrier_observed_release_for_test;
static _Atomic unsigned int
    java_remote_parent_wrong_live_socket_probe_count_for_test;
static _Atomic int java_remote_parent_wrong_live_socket_probe_errno_for_test;
static _Atomic unsigned int
    java_remote_parent_same_fd_task_probe_count_for_test;
static _Atomic int java_remote_parent_same_fd_task_probe_outcome_for_test;
static _Atomic unsigned int
    java_remote_parent_same_fd_thread_probe_count_for_test;
static _Atomic int java_remote_parent_same_fd_thread_probe_outcome_for_test;
static _Atomic unsigned int
    java_remote_parent_auto_unavailable_health_count_for_test;
static _Atomic unsigned int
    java_remote_parent_auto_unavailable_connect_count_for_test;
static _Atomic unsigned int java_remote_parent_real_connect_count_for_test;

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

void obi_demo_java_remote_parent_reset_same_fd_probes_for_test(void) {
  atomic_store_explicit(&java_remote_parent_same_fd_task_probe_count_for_test,
                        0, memory_order_relaxed);
  atomic_store_explicit(&java_remote_parent_same_fd_task_probe_outcome_for_test,
                        0, memory_order_relaxed);
  atomic_store_explicit(&java_remote_parent_same_fd_thread_probe_count_for_test,
                        0, memory_order_relaxed);
  atomic_store_explicit(
      &java_remote_parent_same_fd_thread_probe_outcome_for_test, 0,
      memory_order_relaxed);
}

unsigned int
obi_demo_java_remote_parent_same_fd_task_probe_count_for_test(void) {
  return atomic_load_explicit(
      &java_remote_parent_same_fd_task_probe_count_for_test,
      memory_order_relaxed);
}

int obi_demo_java_remote_parent_same_fd_task_probe_outcome_for_test(void) {
  return atomic_load_explicit(
      &java_remote_parent_same_fd_task_probe_outcome_for_test,
      memory_order_relaxed);
}

unsigned int
obi_demo_java_remote_parent_same_fd_thread_probe_count_for_test(void) {
  return atomic_load_explicit(
      &java_remote_parent_same_fd_thread_probe_count_for_test,
      memory_order_relaxed);
}

int obi_demo_java_remote_parent_same_fd_thread_probe_outcome_for_test(void) {
  return atomic_load_explicit(
      &java_remote_parent_same_fd_thread_probe_outcome_for_test,
      memory_order_relaxed);
}

void obi_demo_java_remote_parent_reset_auto_unavailable_counts_for_test(void) {
  atomic_store_explicit(
      &java_remote_parent_auto_unavailable_health_count_for_test, 0,
      memory_order_relaxed);
  atomic_store_explicit(
      &java_remote_parent_auto_unavailable_connect_count_for_test, 0,
      memory_order_relaxed);
  atomic_store_explicit(&java_remote_parent_real_connect_count_for_test, 0,
                        memory_order_relaxed);
}

unsigned int
obi_demo_java_remote_parent_auto_unavailable_health_count_for_test(void) {
  return atomic_load_explicit(
      &java_remote_parent_auto_unavailable_health_count_for_test,
      memory_order_relaxed);
}

unsigned int
obi_demo_java_remote_parent_auto_unavailable_connect_count_for_test(void) {
  return atomic_load_explicit(
      &java_remote_parent_auto_unavailable_connect_count_for_test,
      memory_order_relaxed);
}

unsigned int obi_demo_java_remote_parent_real_connect_count_for_test(void) {
  return atomic_load_explicit(&java_remote_parent_real_connect_count_for_test,
                              memory_order_relaxed);
}
#endif

_Static_assert(sizeof(real_getsockopt) == sizeof(void *),
               "dlsym function pointer size mismatch");
_Static_assert(sizeof(real_connect) == sizeof(void *),
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

static int java_remote_parent_open_trusted_persistent_fault_control(void) {
  const char *const path = getenv(java_remote_parent_fault_file_environment);
  if (path == NULL || path[0] == '\0') {
    return -1;
  }

  const int descriptor =
      open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (descriptor < 0) {
    return -1;
  }
  if (!java_remote_parent_fault_control_is_trusted(descriptor)) {
    (void)close(descriptor);
    return -1;
  }
  return descriptor;
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
  if (!java_remote_parent_fault_control_is_trusted(descriptor)) {
    (void)close(descriptor);
    return -1;
  }
  int lock_result;
  do {
    lock_result = flock(descriptor, LOCK_EX | LOCK_NB);
  } while (lock_result != 0 && errno == EINTR);
  if (lock_result != 0 ||
      !java_remote_parent_fault_control_is_trusted(descriptor)) {
    (void)close(descriptor);
    return -1;
  }
  return descriptor;
}

static ssize_t java_remote_parent_read_fault_control(int descriptor,
                                                     char *value,
                                                     size_t value_size);

static bool java_remote_parent_persistent_fault_enabled(const char *mode) {
  const int descriptor =
      java_remote_parent_open_trusted_persistent_fault_control();
  if (descriptor < 0) {
    return false;
  }

  char value[java_remote_parent_fault_mode_max_size];
  ssize_t value_length;
  do {
    value_length = pread(descriptor, value, sizeof(value), 0);
  } while (value_length < 0 && errno == EINTR);
  const bool trusted_after_read =
      java_remote_parent_fault_control_is_trusted(descriptor);
  const bool enabled =
      value_length > 0 &&
      value_length < java_remote_parent_fault_mode_max_size &&
      trusted_after_read &&
      java_remote_parent_fault_mode_matches(value, (size_t)value_length, mode);
  (void)close(descriptor);
  return enabled;
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

enum java_remote_parent_probe_outcome {
  java_remote_parent_probe_not_run,
  java_remote_parent_probe_native_unsupported,
  java_remote_parent_probe_missing,
  java_remote_parent_probe_unsafe,
};

static enum java_remote_parent_probe_outcome
java_remote_parent_classify_same_fd_probe(int result, int probe_errno,
                                          const unsigned char *response,
                                          socklen_t response_length) {
  if (result == -1 &&
      (probe_errno == ENOPROTOOPT || probe_errno == EOPNOTSUPP)) {
    return java_remote_parent_probe_native_unsupported;
  }
  if (result == 0 && response_length == java_remote_parent_response_size &&
      memcmp(response, java_remote_parent_magic,
             sizeof(java_remote_parent_magic) - 1) == 0 &&
      response[java_remote_parent_version_offset] ==
          java_remote_parent_abi_version &&
      response[java_remote_parent_version_offset + 1] == 0 &&
      response[java_remote_parent_size_offset] ==
          java_remote_parent_response_size &&
      response[java_remote_parent_size_offset + 1] == 0 &&
      response[java_remote_parent_status_offset] ==
          java_remote_parent_status_missing &&
      response[java_remote_parent_status_offset + 1] == 0 &&
      java_remote_parent_bytes_are_zero(
          response + java_remote_parent_reserved_prefix_offset,
          java_remote_parent_reserved_prefix_size) &&
      java_remote_parent_bytes_are_zero(response +
                                            java_remote_parent_trace_id_offset,
                                        java_remote_parent_trace_id_size) &&
      java_remote_parent_bytes_are_zero(response +
                                            java_remote_parent_span_id_offset,
                                        java_remote_parent_span_id_size) &&
      java_remote_parent_bytes_are_zero(
          response + java_remote_parent_generation_offset,
          java_remote_parent_generation_size) &&
      java_remote_parent_bytes_are_zero(
          response + java_remote_parent_observed_monotime_offset,
          java_remote_parent_observed_monotime_size) &&
      java_remote_parent_bytes_are_zero(
          response + java_remote_parent_reserved_suffix_offset,
          java_remote_parent_reserved_suffix_size)) {
    return java_remote_parent_probe_missing;
  }
  return java_remote_parent_probe_unsafe;
}

#if defined(OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_TESTING)
int obi_demo_java_remote_parent_classify_same_fd_probe_for_test(
    int result, int probe_errno, const unsigned char *response,
    socklen_t response_length) {
  return (int)java_remote_parent_classify_same_fd_probe(
      result, probe_errno, response, response_length);
}
#endif

static bool java_remote_parent_same_fd_probe_is_acceptable(
    enum java_remote_parent_probe_outcome outcome) {
#if defined(OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_TESTING)
  return outcome == java_remote_parent_probe_missing ||
         outcome == java_remote_parent_probe_native_unsupported;
#else
  return outcome == java_remote_parent_probe_missing;
#endif
}

static const char *java_remote_parent_probe_outcome_name(
    enum java_remote_parent_probe_outcome outcome) {
  switch (outcome) {
  case java_remote_parent_probe_native_unsupported:
    return "native-unsupported";
  case java_remote_parent_probe_missing:
    return "missing";
  case java_remote_parent_probe_unsafe:
    return "unsafe";
  case java_remote_parent_probe_not_run:
    return "not-run";
  }
  return "unsafe";
}

static enum java_remote_parent_probe_outcome
java_remote_parent_probe_same_fd_option(int socket, int option) {
  unsigned char response[java_remote_parent_response_size] = {0};
  socklen_t response_length = sizeof(response);
  errno = 0;
  const int result = real_getsockopt(socket, java_remote_parent_socket_level,
                                     option, response, &response_length);
  const int probe_errno = errno;
  return java_remote_parent_classify_same_fd_probe(result, probe_errno,
                                                   response, response_length);
}

struct java_remote_parent_same_fd_thread_probe {
  int socket;
  enum java_remote_parent_probe_outcome outcome;
};

static void *java_remote_parent_probe_same_fd_from_thread(void *argument) {
  struct java_remote_parent_same_fd_thread_probe *const probe = argument;
  probe->outcome = java_remote_parent_probe_same_fd_option(
      probe->socket, java_remote_parent_socket_take);
  return NULL;
}

/* Challenge the held accepted socket without consuming the victim. The task
 * option runs on the request thread but asks for a logical-execution mapping
 * that was never published. The direct option runs on a distinct native
 * thread, so its current TID cannot name the accepted request owner. */
static bool java_remote_parent_probe_same_fd_executions(int socket) {
  const enum java_remote_parent_probe_outcome task_outcome =
      java_remote_parent_probe_same_fd_option(
          socket, java_remote_parent_socket_task_take);
#if defined(OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_TESTING)
  atomic_fetch_add_explicit(
      &java_remote_parent_same_fd_task_probe_count_for_test, 1,
      memory_order_relaxed);
  atomic_store_explicit(&java_remote_parent_same_fd_task_probe_outcome_for_test,
                        task_outcome, memory_order_relaxed);
#endif
  if (!java_remote_parent_same_fd_probe_is_acceptable(task_outcome)) {
    errno = EPROTO;
    return false;
  }

  struct java_remote_parent_same_fd_thread_probe probe = {
      .socket = socket,
      .outcome = java_remote_parent_probe_not_run,
  };
  pthread_t thread;
  const int create_result = pthread_create(
      &thread, NULL, java_remote_parent_probe_same_fd_from_thread, &probe);
  if (create_result != 0) {
    errno = create_result;
    return false;
  }
  const int join_result = pthread_join(thread, NULL);
  if (join_result != 0) {
    errno = join_result;
    return false;
  }
#if defined(OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_TESTING)
  atomic_fetch_add_explicit(
      &java_remote_parent_same_fd_thread_probe_count_for_test, 1,
      memory_order_relaxed);
  atomic_store_explicit(
      &java_remote_parent_same_fd_thread_probe_outcome_for_test, probe.outcome,
      memory_order_relaxed);
#endif
  if (!java_remote_parent_same_fd_probe_is_acceptable(probe.outcome)) {
    errno = EPROTO;
    return false;
  }
  return true;
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
  if (!java_remote_parent_probe_same_fd_executions(socket)) {
    java_remote_parent_close_preserving_errno(descriptor);
    return -1;
  }

  const enum java_remote_parent_probe_outcome task_outcome =
#if defined(OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_TESTING)
      (enum java_remote_parent_probe_outcome)atomic_load_explicit(
          &java_remote_parent_same_fd_task_probe_outcome_for_test,
          memory_order_relaxed);
  const enum java_remote_parent_probe_outcome thread_outcome =
      (enum java_remote_parent_probe_outcome)atomic_load_explicit(
          &java_remote_parent_same_fd_thread_probe_outcome_for_test,
          memory_order_relaxed);
#else
      java_remote_parent_probe_missing;
  const enum java_remote_parent_probe_outcome thread_outcome =
      java_remote_parent_probe_missing;
#endif
  char ready[java_remote_parent_fault_mode_max_size];
  const int ready_length =
      snprintf(ready, sizeof(ready), "%s%d:task=%s:thread=%s\n",
               java_remote_parent_live_fd_ready_prefix, socket,
               java_remote_parent_probe_outcome_name(task_outcome),
               java_remote_parent_probe_outcome_name(thread_outcome));
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

static void resolve_real_connect(void) {
  const void *const symbol = dlsym(RTLD_NEXT, "connect");
  memcpy(&real_connect, &symbol, sizeof(real_connect));
}

static bool java_remote_parent_is_unix_stream_socket(int socket) {
  if (socket < 0 ||
      pthread_once(&real_getsockopt_once, resolve_real_getsockopt) != 0 ||
      real_getsockopt == NULL) {
    return false;
  }

  int domain = 0;
  socklen_t domain_length = sizeof(domain);
  int type = 0;
  socklen_t type_length = sizeof(type);
  return real_getsockopt(socket, SOL_SOCKET, SO_DOMAIN, &domain,
                         &domain_length) == 0 &&
         domain_length == sizeof(domain) && domain == AF_UNIX &&
         real_getsockopt(socket, SOL_SOCKET, SO_TYPE, &type, &type_length) ==
             0 &&
         type_length == sizeof(type) && type == SOCK_STREAM;
}

static bool
java_remote_parent_is_exact_health_request(int socket, int level, int option,
                                           const void *optval,
                                           const socklen_t *optlen) {
  return socket >= 0 && level == java_remote_parent_socket_level &&
         option == java_remote_parent_socket_health && optval != NULL &&
         optlen != NULL && *optlen == sizeof(uint64_t);
}

static bool java_remote_parent_is_exact_unix_socket(
    int socket, const struct sockaddr *address, socklen_t address_length) {
  const size_t path_offset = offsetof(struct sockaddr_un, sun_path);
  const size_t expected_path_size = sizeof(java_remote_parent_unix_socket_path);
  if (address == NULL || address_length != path_offset + expected_path_size ||
      !java_remote_parent_is_unix_stream_socket(socket) ||
      address->sa_family != AF_UNIX) {
    return false;
  }
  const struct sockaddr_un *const unix_address =
      (const struct sockaddr_un *)address;
  return memcmp(unix_address->sun_path, java_remote_parent_unix_socket_path,
                expected_path_size) == 0;
}

int getsockopt(int socket, int level, int option, void *optval,
               socklen_t *optlen) {
  if (pthread_once(&real_getsockopt_once, resolve_real_getsockopt) != 0 ||
      real_getsockopt == NULL) {
    errno = ENOSYS;
    return -1;
  }

  if (java_remote_parent_is_exact_health_request(socket, level, option, optval,
                                                 optlen) &&
      java_remote_parent_persistent_fault_enabled(
          java_remote_parent_auto_unavailable_mode)) {
#if defined(OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_TESTING)
    atomic_fetch_add_explicit(
        &java_remote_parent_auto_unavailable_health_count_for_test, 1,
        memory_order_relaxed);
#endif
    errno = ENOPROTOOPT;
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

int connect(int socket, __CONST_SOCKADDR_ARG address,
            socklen_t address_length) {
  if (java_remote_parent_is_exact_unix_socket(socket, address.__sockaddr__,
                                              address_length) &&
      java_remote_parent_persistent_fault_enabled(
          java_remote_parent_auto_unavailable_mode)) {
#if defined(OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_TESTING)
    atomic_fetch_add_explicit(
        &java_remote_parent_auto_unavailable_connect_count_for_test, 1,
        memory_order_relaxed);
#endif
    errno = ECONNREFUSED;
    return -1;
  }
  if (pthread_once(&real_connect_once, resolve_real_connect) != 0 ||
      real_connect == NULL) {
    errno = ENOSYS;
    return -1;
  }
#if defined(OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_TESTING)
  atomic_fetch_add_explicit(&java_remote_parent_real_connect_count_for_test, 1,
                            memory_order_relaxed);
#endif
  return real_connect(socket, address, address_length);
}
