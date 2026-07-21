/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

enum {
  record_size = 64,
  request_size = 24,
  status_valid = 1,
  status_missing = 2,
  status_transport_error = 12,
  transport_getsockopt = 1,
  transport_unix = 2,
  obi_socket_level = 0x4f42,
  obi_socket_take = 0x4a01,
  obi_socket_negotiate = 0x4a03,
  obi_socket_data_ack = 0x4a04,
  obi_socket_health = 0x4a05,
};

enum benchmark_outcome {
  outcome_hit,
  outcome_miss,
  outcome_failure,
};

int obi_test_configure_remote_parent(int transport, const char *path,
                                     int timeout_millis, uid_t server_uid,
                                     uint64_t process_incarnation);
int obi_test_call_remote_parent_on_socket(int operation, int socket_fd,
                                          unsigned char *response);
void obi_test_close_remote_parent(void);

static enum benchmark_outcome getsockopt_outcome;
static int getsockopt_expected_fd = -1;
static int negotiated_fd = -1;
static unsigned char negotiated_incarnation[sizeof(uint64_t)];

static void write_u16_le(unsigned char *buffer, size_t offset, uint16_t value) {
  buffer[offset] = (unsigned char)(value & 0xff);
  buffer[offset + 1] = (unsigned char)(value >> 8);
}

static void write_u64_le(unsigned char *buffer, size_t offset, uint64_t value) {
  for (size_t index = 0; index < sizeof(value); index++) {
    buffer[offset + index] = (unsigned char)(value >> (index * 8));
  }
}

static void benchmark_response(unsigned char *response,
                               enum benchmark_outcome outcome) {
  memset(response, 0, record_size);
  memcpy(response, "OBIJ", 4);
  write_u16_le(response, 4, 1);
  write_u16_le(response, 6, record_size);
  if (outcome != outcome_hit) {
    response[8] = status_missing;
    return;
  }

  response[8] = status_valid;
  response[9] = 1;
  for (size_t index = 0; index < 16; index++) {
    response[16 + index] = (unsigned char)(index + 1);
  }
  for (size_t index = 0; index < 8; index++) {
    response[32 + index] = (unsigned char)(index + 17);
  }
  write_u64_le(response, 40, 1);
  write_u64_le(response, 48, 1);
}

int getsockopt(int fd, int level, int option, void *value, socklen_t *length) {
  if (level != obi_socket_level) {
    return (int)syscall(SYS_getsockopt, fd, level, option, value, length);
  }
  if (option == obi_socket_health) {
    assert(fd == negotiated_fd);
    assert(value != NULL);
    assert(length != NULL && *length >= sizeof(negotiated_incarnation));
    memcpy(value, negotiated_incarnation, sizeof(negotiated_incarnation));
    *length = sizeof(negotiated_incarnation);
    return 0;
  }
  assert(fd == getsockopt_expected_fd);
  assert(option == obi_socket_take);
  if (getsockopt_outcome == outcome_failure) {
    errno = EIO;
    return -1;
  }
  assert(*length >= record_size);
  benchmark_response(value, getsockopt_outcome);
  *length = record_size;
  return 0;
}

struct tcp_pair {
  int client;
  int accepted;
};

static int connected_tcp_pair(struct tcp_pair *pair) {
  pair->client = -1;
  pair->accepted = -1;
  int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listener < 0) {
    return -1;
  }

  struct sockaddr_in address = {
      .sin_family = AF_INET,
      .sin_port = 0,
      .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)},
  };
  socklen_t address_length = sizeof(address);
  if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
      listen(listener, 1) != 0 ||
      getsockname(listener, (struct sockaddr *)&address, &address_length) !=
          0) {
    close(listener);
    return -1;
  }

  pair->client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (pair->client < 0 || connect(pair->client, (struct sockaddr *)&address,
                                  sizeof(address)) != 0) {
    if (pair->client >= 0) {
      close(pair->client);
      pair->client = -1;
    }
    close(listener);
    return -1;
  }

  pair->accepted = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
  close(listener);
  if (pair->accepted < 0) {
    close(pair->client);
    pair->client = -1;
    return -1;
  }
  return 0;
}

static void close_tcp_pair(struct tcp_pair *pair) {
  assert(close(pair->accepted) == 0);
  assert(close(pair->client) == 0);
  pair->accepted = -1;
  pair->client = -1;
}

int setsockopt(int fd, int level, int option, const void *value,
               socklen_t length) {
  if (level == obi_socket_level) {
    assert(option == obi_socket_negotiate || option == obi_socket_data_ack);
    assert(value != NULL);
    assert(length == sizeof(uint64_t));
    if (option == obi_socket_negotiate) {
      negotiated_fd = fd;
      memcpy(negotiated_incarnation, value, sizeof(negotiated_incarnation));
    }
    return 0;
  }
  return (int)syscall(SYS_setsockopt, fd, level, option, value, length);
}

static void transfer_exact(int fd, unsigned char *buffer, size_t length,
                           int sending) {
  size_t offset = 0;
  while (offset < length) {
    ssize_t count =
        sending ? send(fd, buffer + offset, length - offset, MSG_NOSIGNAL)
                : recv(fd, buffer + offset, length - offset, 0);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    assert(count > 0);
    offset += (size_t)count;
  }
}

struct unix_server {
  int listener;
  size_t request_count;
  enum benchmark_outcome outcome;
};

static void *serve_unix(void *argument) {
  const struct unix_server *server = argument;
  for (size_t request_index = 0; request_index < server->request_count;
       request_index++) {
    int client = accept4(server->listener, NULL, NULL, SOCK_CLOEXEC);
    assert(client >= 0);

    unsigned char request[request_size];
    transfer_exact(client, request, sizeof(request), 0);

    unsigned char response[record_size];
    enum benchmark_outcome response_outcome =
        request_index == 0 ? outcome_miss : server->outcome;
    benchmark_response(response, response_outcome);
    transfer_exact(client, response, sizeof(response), 1);
    assert(close(client) == 0);
  }
  assert(close(server->listener) == 0);
  return NULL;
}

static int start_unix_server(struct unix_server *server, const char *path,
                             size_t request_count,
                             enum benchmark_outcome outcome,
                             pthread_t *thread) {
  server->listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (server->listener < 0) {
    return -1;
  }
  server->request_count = request_count;
  server->outcome = outcome;

  struct sockaddr_un address = {.sun_family = AF_UNIX};
  size_t name_length = strlen(path + 1);
  assert(path[0] == '@');
  assert(name_length < sizeof(address.sun_path) - 1);
  memcpy(address.sun_path + 1, path + 1, name_length);
  socklen_t address_length =
      (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + name_length);
  if (bind(server->listener, (struct sockaddr *)&address, address_length) !=
          0 ||
      listen(server->listener, 128) != 0 ||
      pthread_create(thread, NULL, serve_unix, server) != 0) {
    close(server->listener);
    return -1;
  }
  return 0;
}

static int64_t monotonic_nanos(void) {
  struct timespec now;
  assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
  return ((int64_t)now.tv_sec * 1000000000) + now.tv_nsec;
}

static const char *outcome_name(enum benchmark_outcome outcome) {
  switch (outcome) {
  case outcome_hit:
    return "hit";
  case outcome_miss:
    return "miss";
  case outcome_failure:
    return "failure";
  }
  abort();
}

static int expected_status(enum benchmark_outcome outcome) {
  switch (outcome) {
  case outcome_hit:
    return status_valid;
  case outcome_miss:
    return status_missing;
  case outcome_failure:
    return status_transport_error;
  }
  abort();
}

static int compare_u64(const void *left, const void *right) {
  uint64_t left_value = *(const uint64_t *)left;
  uint64_t right_value = *(const uint64_t *)right;
  return (left_value > right_value) - (left_value < right_value);
}

static uint64_t percentile(const uint64_t *sorted_samples, size_t count,
                           size_t percentage) {
  size_t rank = (count * percentage + 99) / 100;
  return sorted_samples[rank - 1];
}

static size_t warmup_iterations(size_t iterations) {
  enum { maximum_warmup_iterations = 1000 };
  return iterations < maximum_warmup_iterations ? iterations
                                                : maximum_warmup_iterations;
}

static void run_calls(const char *transport_name,
                      enum benchmark_outcome outcome, size_t iterations,
                      int socket_fd) {
  unsigned char response[record_size];
  int expected = expected_status(outcome);

  size_t warmup = warmup_iterations(iterations);
  for (size_t iteration = 0; iteration < warmup; iteration++) {
    assert(obi_test_call_remote_parent_on_socket(1, socket_fd, response) ==
           expected);
  }

  uint64_t *samples = calloc(iterations, sizeof(*samples));
  assert(samples != NULL);
  volatile unsigned int checksum = 0;
  int64_t start = monotonic_nanos();
  for (size_t iteration = 0; iteration < iterations; iteration++) {
    int64_t operation_start = monotonic_nanos();
    int status = obi_test_call_remote_parent_on_socket(1, socket_fd, response);
    int64_t operation_elapsed = monotonic_nanos() - operation_start;
    assert(status == expected);
    assert(operation_elapsed >= 0);
    samples[iteration] = (uint64_t)operation_elapsed;
    checksum += (unsigned int)status;
  }
  int64_t elapsed = monotonic_nanos() - start;
  double nanos_per_operation = (double)elapsed / (double)iterations;
  double operations_per_second = 1000000000.0 / nanos_per_operation;
  qsort(samples, iterations, sizeof(*samples), compare_u64);
  printf("transport=%s outcome=%s warmup_iterations=%zu iterations=%zu "
         "elapsed_ns=%lld ns_per_op=%.2f p50_ns=%llu p95_ns=%llu "
         "p99_ns=%llu ops_per_second=%.2f status=%d checksum=%u\n",
         transport_name, outcome_name(outcome), warmup, iterations,
         (long long)elapsed, nanos_per_operation,
         (unsigned long long)percentile(samples, iterations, 50),
         (unsigned long long)percentile(samples, iterations, 95),
         (unsigned long long)percentile(samples, iterations, 99),
         operations_per_second, expected, checksum);
  free(samples);
}

static void benchmark_getsockopt(enum benchmark_outcome outcome,
                                 size_t iterations) {
  struct tcp_pair pair;
  assert(connected_tcp_pair(&pair) == 0);
  getsockopt_outcome = outcome;
  getsockopt_expected_fd = pair.accepted;
  assert(obi_test_configure_remote_parent(transport_getsockopt, "", 1000,
                                          geteuid(), 1) == status_valid);
  run_calls("getsockopt", outcome, iterations, pair.accepted);
  obi_test_close_remote_parent();
  getsockopt_expected_fd = -1;
  negotiated_fd = -1;
  memset(negotiated_incarnation, 0, sizeof(negotiated_incarnation));
  close_tcp_pair(&pair);
}

static void benchmark_unix(enum benchmark_outcome outcome, size_t iterations,
                           unsigned int sequence) {
  char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
  int path_length = snprintf(path, sizeof(path), "@obi-jni-benchmark-%ld-%u",
                             (long)getpid(), sequence);
  assert(path_length > 1 && (size_t)path_length < sizeof(path));

  size_t server_requests = outcome == outcome_failure ? 1 : iterations + 1;
  if (outcome != outcome_failure) {
    server_requests += warmup_iterations(iterations);
  }
  struct unix_server server;
  pthread_t thread;
  assert(start_unix_server(&server, path, server_requests, outcome, &thread) ==
         0);
  assert(obi_test_configure_remote_parent(transport_unix, path, 1000, geteuid(),
                                          1) == status_valid);
  if (outcome == outcome_failure) {
    assert(pthread_join(thread, NULL) == 0);
  }

  run_calls("unix", outcome, iterations, -1);
  if (outcome != outcome_failure) {
    assert(pthread_join(thread, NULL) == 0);
  }
  obi_test_close_remote_parent();
}

static size_t parse_iterations(const char *text) {
  errno = 0;
  char *end = NULL;
  unsigned long long value = strtoull(text, &end, 10);
  if (errno != 0 || end == text || *end != '\0' || value == 0 ||
      value > 1000000) {
    fprintf(stderr, "iterations must be an integer from 1 through 1000000\n");
    exit(2);
  }
  return (size_t)value;
}

int main(int argc, char **argv) {
  if (argc > 2) {
    fprintf(stderr, "usage: %s [iterations]\n", argv[0]);
    return 2;
  }
  size_t iterations = argc == 2 ? parse_iterations(argv[1]) : 10000;

  printf("benchmark=obi_java_remote_parent_native "
         "getsockopt_backend=deterministic_syscall_shim\n");
  benchmark_getsockopt(outcome_hit, iterations);
  benchmark_getsockopt(outcome_miss, iterations);
  benchmark_getsockopt(outcome_failure, iterations);
  benchmark_unix(outcome_hit, iterations, 1);
  benchmark_unix(outcome_miss, iterations, 2);
  benchmark_unix(outcome_failure, iterations, 3);
  return 0;
}
