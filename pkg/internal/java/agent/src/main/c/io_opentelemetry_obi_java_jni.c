/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <errno.h>
#include <jni.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

enum {
  remote_parent_record_size = 64,
  remote_parent_request_size = 24,
  remote_parent_abi_version = 1,
  remote_parent_request_version = 3,
  remote_parent_status_unknown = 0,
  remote_parent_status_valid = 1,
  remote_parent_status_missing = 2,
  remote_parent_status_stale = 3,
  remote_parent_status_unsupported = 4,
  remote_parent_status_malformed = 5,
  remote_parent_status_version_mismatch = 6,
  remote_parent_status_ambiguous = 7,
  remote_parent_status_unauthorized = 8,
  remote_parent_status_already_consumed = 9,
  remote_parent_status_timeout = 10,
  remote_parent_status_overload = 11,
  remote_parent_status_transport_error = 12,
  remote_parent_status_disabled = 13,
  remote_parent_transport_auto = 0,
  remote_parent_transport_getsockopt = 1,
  remote_parent_transport_unix = 2,
  remote_parent_transport_disabled = 3,
  remote_parent_transport_none = 255,
  remote_parent_config_result_version = 2,
  remote_parent_config_result_magic = 0x4f,
  remote_parent_attempt_getsockopt = 1,
  remote_parent_attempt_unix = 2,
  remote_parent_operation_take = 1,
  remote_parent_operation_discard = 2,
  remote_parent_operation_negotiate = 3,
  remote_parent_source_direct = 1,
  remote_parent_source_task = 2,
  obi_socket_level = 0x4f42,
  obi_socket_take = 0x4a01,
  obi_socket_discard = 0x4a02,
  obi_socket_negotiate = 0x4a03,
  obi_socket_data_ack = 0x4a04,
  obi_socket_health = 0x4a05,
  obi_socket_task_take = 0x4a06,
  obi_socket_task_discard = 0x4a07,
  obi_ioctl_magic = 0x0b10b1,
};

struct remote_parent_config {
  int transport;
  int dummy_socket;
  int dummy_peer_socket;
  int timeout_millis;
  uid_t unix_server_uid;
  uint64_t process_incarnation;
  _Atomic unsigned int references;
  char unix_socket_path[sizeof(((struct sockaddr_un *)0)->sun_path)];
};

struct remote_parent_config_result {
  int status;
  unsigned char requested_transport;
  unsigned char selected_transport;
  unsigned char attempted_transports;
  unsigned char getsockopt_status;
  unsigned char unix_status;
};

static pthread_mutex_t remote_parent_lock = PTHREAD_MUTEX_INITIALIZER;
static struct remote_parent_config *remote_parent_current;
static _Atomic int remote_parent_timeout_millis = 50;
static _Atomic uint64_t next_data_signal_nonce = 1;

static void clear_jni_exception(JNIEnv *env) {
  if ((*env)->ExceptionCheck(env)) {
    (*env)->ExceptionClear(env);
  }
}

static int socket_file_descriptor(JNIEnv *env, jobject socket, int allow_self) {
  if (socket == NULL) {
    return -1;
  }

  jclass socket_class = (*env)->FindClass(env, "java/net/Socket");
  if (socket_class == NULL) {
    clear_jni_exception(env);
    return -1;
  }

  if (allow_self) {
    jclass object_class = (*env)->GetObjectClass(env, socket);
    if (object_class != NULL) {
      jfieldID self_field =
          (*env)->GetFieldID(env, object_class, "self", "Ljava/net/Socket;");
      if (self_field != NULL) {
        jobject self = (*env)->GetObjectField(env, socket, self_field);
        if (self != NULL && !(*env)->IsSameObject(env, socket, self)) {
          int fd = socket_file_descriptor(env, self, 0);
          (*env)->DeleteLocalRef(env, self);
          (*env)->DeleteLocalRef(env, object_class);
          (*env)->DeleteLocalRef(env, socket_class);
          return fd;
        }
        if (self != NULL) {
          (*env)->DeleteLocalRef(env, self);
        }
      }
      clear_jni_exception(env);
      (*env)->DeleteLocalRef(env, object_class);
    } else {
      clear_jni_exception(env);
    }
  }

  jmethodID get_impl = (*env)->GetMethodID(env, socket_class, "getImpl",
                                           "()Ljava/net/SocketImpl;");
  if (get_impl == NULL) {
    clear_jni_exception(env);
    (*env)->DeleteLocalRef(env, socket_class);
    return -1;
  }
  jobject impl = (*env)->CallObjectMethod(env, socket, get_impl);
  if (impl == NULL || (*env)->ExceptionCheck(env)) {
    clear_jni_exception(env);
    if (impl != NULL) {
      (*env)->DeleteLocalRef(env, impl);
    }
    (*env)->DeleteLocalRef(env, socket_class);
    return -1;
  }

  jclass impl_class = (*env)->FindClass(env, "java/net/SocketImpl");
  jclass descriptor_class = (*env)->FindClass(env, "java/io/FileDescriptor");
  if (impl_class == NULL || descriptor_class == NULL) {
    clear_jni_exception(env);
    if (impl_class != NULL) {
      (*env)->DeleteLocalRef(env, impl_class);
    }
    if (descriptor_class != NULL) {
      (*env)->DeleteLocalRef(env, descriptor_class);
    }
    (*env)->DeleteLocalRef(env, impl);
    (*env)->DeleteLocalRef(env, socket_class);
    return -1;
  }

  jmethodID get_descriptor = (*env)->GetMethodID(
      env, impl_class, "getFileDescriptor", "()Ljava/io/FileDescriptor;");
  jfieldID descriptor_value =
      (*env)->GetFieldID(env, descriptor_class, "fd", "I");
  int result = -1;
  if (get_descriptor != NULL && descriptor_value != NULL) {
    jobject descriptor = (*env)->CallObjectMethod(env, impl, get_descriptor);
    if (descriptor != NULL && !(*env)->ExceptionCheck(env)) {
      result = (*env)->GetIntField(env, descriptor, descriptor_value);
      (*env)->DeleteLocalRef(env, descriptor);
    }
  }
  clear_jni_exception(env);
  (*env)->DeleteLocalRef(env, descriptor_class);
  (*env)->DeleteLocalRef(env, impl_class);
  (*env)->DeleteLocalRef(env, impl);
  (*env)->DeleteLocalRef(env, socket_class);
  return result;
}

static void write_u16_le(unsigned char *buffer, size_t offset, uint16_t value) {
  buffer[offset] = (unsigned char)(value & 0xff);
  buffer[offset + 1] = (unsigned char)(value >> 8);
}

static void write_u32_le(unsigned char *buffer, size_t offset, uint32_t value) {
  for (size_t i = 0; i < sizeof(value); i++) {
    buffer[offset + i] = (unsigned char)(value >> (i * 8));
  }
}

static void write_u64_le(unsigned char *buffer, size_t offset, uint64_t value) {
  for (size_t i = 0; i < sizeof(value); i++) {
    buffer[offset + i] = (unsigned char)(value >> (i * 8));
  }
}

static uint16_t read_u16_le(const unsigned char *buffer, size_t offset) {
  return (uint16_t)(buffer[offset] | ((uint16_t)buffer[offset + 1] << 8));
}

static uint64_t read_u64_le(const unsigned char *buffer, size_t offset) {
  uint64_t value = 0;
  for (size_t i = 0; i < sizeof(value); i++) {
    value |= (uint64_t)buffer[offset + i] << (i * 8);
  }
  return value;
}

static int bytes_zero(const unsigned char *buffer, size_t start, size_t end) {
  for (size_t index = start; index < end; index++) {
    if (buffer[index] != 0) {
      return 0;
    }
  }
  return 1;
}

static void status_response(unsigned char *response, int status) {
  memset(response, 0, remote_parent_record_size);
  memcpy(response, "OBIJ", 4);
  write_u16_le(response, 4, remote_parent_abi_version);
  write_u16_le(response, 6, remote_parent_record_size);
  response[8] = (unsigned char)status;
}

static int response_status(unsigned char *response, size_t length) {
  if (length != remote_parent_record_size || memcmp(response, "OBIJ", 4) != 0) {
    status_response(response, remote_parent_status_malformed);
    return remote_parent_status_malformed;
  }
  if (read_u16_le(response, 4) != remote_parent_abi_version) {
    status_response(response, remote_parent_status_version_mismatch);
    return remote_parent_status_version_mismatch;
  }
  if (read_u16_le(response, 6) != remote_parent_record_size) {
    status_response(response, remote_parent_status_malformed);
    return remote_parent_status_malformed;
  }
  if (!bytes_zero(response, 10, 16) ||
      !bytes_zero(response, 56, remote_parent_record_size) ||
      response[8] == remote_parent_status_unknown ||
      response[8] > remote_parent_status_disabled) {
    status_response(response, remote_parent_status_malformed);
    return remote_parent_status_malformed;
  }
  if (response[8] == remote_parent_status_valid &&
      (bytes_zero(response, 16, 32) || bytes_zero(response, 32, 40) ||
       read_u64_le(response, 40) == 0 || read_u64_le(response, 48) == 0)) {
    status_response(response, remote_parent_status_malformed);
    return remote_parent_status_malformed;
  }
  return response[8];
}

static int probe_succeeded(int status) {
  return status == remote_parent_status_missing;
}

static int failed_probe_status(int status) {
  return status == remote_parent_status_valid ? remote_parent_status_malformed
                                              : status;
}

static int timeout_valid(int timeout_millis) { return timeout_millis > 0; }

static int peer_credentials_allowed(const struct ucred *credentials,
                                    uid_t expected_uid) {
  return credentials->uid == expected_uid;
}

static int errno_status(int error) {
  switch (error) {
  case EACCES:
  case EPERM:
    return remote_parent_status_unauthorized;
  case ETIMEDOUT:
  case EAGAIN:
    return remote_parent_status_timeout;
  case ENOBUFS:
  case ENOMEM:
  case EBUSY:
    return remote_parent_status_overload;
  case ENOPROTOOPT:
  case EOPNOTSUPP:
  case ENOSYS:
    return remote_parent_status_unsupported;
  default:
    return remote_parent_status_transport_error;
  }
}

static int call_getsockopt(int fd, int option, unsigned char *response) {
  status_response(response, 0);
  socklen_t length = remote_parent_record_size;
  if (getsockopt(fd, obi_socket_level, option, response, &length) != 0) {
    int status = errno_status(errno);
    status_response(response, status);
    return status;
  }
  return response_status(response, length);
}

static int call_setsockopt_negotiate(int fd, uint64_t process_incarnation,
                                     unsigned char *response) {
  unsigned char incarnation[sizeof(process_incarnation)];
  write_u64_le(incarnation, 0, process_incarnation);
  if (setsockopt(fd, obi_socket_level, obi_socket_negotiate, incarnation,
                 sizeof(incarnation)) != 0) {
    int status = errno_status(errno);
    status_response(response, status);
    return status;
  }
  status_response(response, remote_parent_status_missing);
  return remote_parent_status_missing;
}

static int call_getsockopt_health(int fd, uint64_t process_incarnation,
                                  unsigned char *response) {
  unsigned char observed[sizeof(process_incarnation)] = {0};
  socklen_t length = sizeof(observed);
  if (getsockopt(fd, obi_socket_level, obi_socket_health, observed, &length) !=
      0) {
    int status = errno_status(errno);
    status_response(response, status);
    return status;
  }
  if (length != sizeof(observed) ||
      read_u64_le(observed, 0) != process_incarnation) {
    status_response(response, remote_parent_status_malformed);
    return remote_parent_status_malformed;
  }
  status_response(response, remote_parent_status_missing);
  return remote_parent_status_missing;
}

static int call_setsockopt_data_ack(int fd, uint64_t nonce) {
  unsigned char acknowledgement[sizeof(nonce)];
  write_u64_le(acknowledgement, 0, nonce);
  return setsockopt(fd, obi_socket_level, obi_socket_data_ack, acknowledgement,
                    sizeof(acknowledgement));
}

static uint64_t next_data_signal(void) {
  uint64_t nonce = atomic_fetch_add_explicit(&next_data_signal_nonce, 1,
                                             memory_order_relaxed);
  if (nonce == 0) {
    nonce = atomic_fetch_add_explicit(&next_data_signal_nonce, 1,
                                      memory_order_relaxed);
  }
  return nonce;
}

static int connected_tcp_probe_pair(int *client, int *peer) {
  *client = -1;
  *peer = -1;
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

  int candidate = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (candidate < 0 ||
      connect(candidate, (struct sockaddr *)&address, sizeof(address)) != 0) {
    if (candidate >= 0) {
      close(candidate);
    }
    close(listener);
    return -1;
  }

  int accepted = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
  close(listener);
  if (accepted < 0) {
    close(candidate);
    return -1;
  }

  *client = candidate;
  *peer = accepted;
  return 0;
}

static int64_t monotonic_millis(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
    return -1;
  }
  return ((int64_t)now.tv_sec * 1000) + (now.tv_nsec / 1000000);
}

static int64_t deadline_after_millis(int64_t start, int timeout_millis) {
  if (start < 0 || timeout_millis <= 0 || start > INT64_MAX - timeout_millis) {
    return -1;
  }
  return start + timeout_millis;
}

static int mutex_lock_until(pthread_mutex_t *mutex, int64_t deadline) {
  while (1) {
    int result = pthread_mutex_trylock(mutex);
    if (result == 0) {
      return 0;
    }
    if (result != EBUSY) {
      errno = result;
      return -1;
    }

    int64_t now = monotonic_millis();
    if (now < 0 || now >= deadline) {
      errno = ETIMEDOUT;
      return -1;
    }
    int64_t remaining = deadline - now;
    struct timespec pause = {
        .tv_sec = 0,
        .tv_nsec = (remaining > 1 ? 1 : remaining) * 1000 * 1000,
    };
    while (nanosleep(&pause, &pause) != 0 && errno == EINTR) {
    }
  }
}

static int wait_for_fd(int fd, short events, int64_t deadline) {
  while (1) {
    int64_t now = monotonic_millis();
    if (now < 0 || now >= deadline) {
      errno = ETIMEDOUT;
      return -1;
    }
    int64_t remaining = deadline - now;
    int timeout = remaining > INT_MAX ? INT_MAX : (int)remaining;
    struct pollfd descriptor = {.fd = fd, .events = events, .revents = 0};
    int result = poll(&descriptor, 1, timeout);
    if (result > 0) {
      if ((descriptor.revents & events) != 0) {
        return 0;
      }
      if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
        errno = EIO;
        return -1;
      }
      continue;
    }
    if (result == 0) {
      errno = ETIMEDOUT;
      return -1;
    }
    if (errno != EINTR) {
      return -1;
    }
  }
}

static int transfer_all(int fd, unsigned char *buffer, size_t length,
                        int sending, int64_t deadline) {
  size_t offset = 0;
  while (offset < length) {
    int64_t now = monotonic_millis();
    if (now < 0 || now >= deadline) {
      errno = ETIMEDOUT;
      return -1;
    }

    ssize_t count;
    if (sending) {
      count = send(fd, buffer + offset, length - offset, MSG_NOSIGNAL);
    } else {
      count = recv(fd, buffer + offset, length - offset, 0);
    }
    if (count > 0) {
      offset += (size_t)count;
      continue;
    }
    if (count == 0) {
      errno = EPROTO;
      return -1;
    }
    if (errno == EINTR) {
      continue;
    }
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
      return -1;
    }
    if (wait_for_fd(fd, sending ? POLLOUT : POLLIN, deadline) != 0) {
      return -1;
    }
  }
  return 0;
}

static int exchange_unix_request(int fd, unsigned char *request,
                                 unsigned char *response, int64_t deadline) {
  int request_failed = 0;
  if (transfer_all(fd, request, remote_parent_request_size, 1, deadline) != 0) {
    if (errno != EPIPE && errno != ECONNRESET) {
      return -1;
    }
    request_failed = 1;
  }

  if (transfer_all(fd, response, remote_parent_record_size, 0, deadline) != 0) {
    return -1;
  }

  int status = response_status(response, remote_parent_record_size);
  if (!request_failed) {
    return status;
  }
  if (status == remote_parent_status_valid) {
    status = remote_parent_status_malformed;
  }
  status_response(response, status);
  return status;
}

static int unix_address(const struct remote_parent_config *config,
                        struct sockaddr_un *address, socklen_t *length) {
  size_t path_length =
      strnlen(config->unix_socket_path, sizeof(config->unix_socket_path));
  if (path_length == 0 || path_length >= sizeof(address->sun_path)) {
    errno = EINVAL;
    return -1;
  }

  memset(address, 0, sizeof(*address));
  address->sun_family = AF_UNIX;
  if (config->unix_socket_path[0] == '@') {
    if (path_length == 1) {
      errno = EINVAL;
      return -1;
    }
    memcpy(address->sun_path + 1, config->unix_socket_path + 1,
           path_length - 1);
    *length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + path_length);
  } else {
    memcpy(address->sun_path, config->unix_socket_path, path_length + 1);
    *length =
        (socklen_t)(offsetof(struct sockaddr_un, sun_path) + path_length + 1);
  }
  return 0;
}

static int verify_unix_path(const struct remote_parent_config *config) {
  if (config->unix_socket_path[0] == '@') {
    return 0;
  }

  struct stat metadata;
  if (lstat(config->unix_socket_path, &metadata) != 0) {
    return -1;
  }
  if (!S_ISSOCK(metadata.st_mode)) {
    errno = EINVAL;
    return -1;
  }
  if (metadata.st_uid != config->unix_server_uid) {
    errno = EACCES;
    return -1;
  }
  return 0;
}

static int verify_unix_peer(int fd, const struct remote_parent_config *config) {
  struct ucred credentials;
  socklen_t length = sizeof(credentials);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0 ||
      length != sizeof(credentials)) {
    return -1;
  }
  if (!peer_credentials_allowed(&credentials, config->unix_server_uid)) {
    errno = EACCES;
    return -1;
  }
  return 0;
}

static void build_unix_request(unsigned char *request, int operation,
                               int source, uint32_t namespace_tid,
                               uint64_t process_incarnation) {
  memset(request, 0, remote_parent_request_size);
  memcpy(request, "OBIQ", 4);
  write_u16_le(request, 4, remote_parent_request_version);
  write_u16_le(request, 6, remote_parent_request_size);
  request[8] = (unsigned char)operation;
  request[9] = (unsigned char)source;
  write_u32_le(request, 12, namespace_tid);
  write_u64_le(request, 16, process_incarnation);
}

static void build_task_context_packet(unsigned char *packet, int operation,
                                      uint64_t value, uint64_t token) {
  memset(packet, 0, 1 + (2 * sizeof(uint64_t)));
  packet[0] = (unsigned char)operation;
  write_u64_le(packet, 1, value);
  write_u64_le(packet, 1 + sizeof(uint64_t), token);
}

static int call_unix_socket(const struct remote_parent_config *config,
                            int operation, int source, unsigned char *response,
                            int64_t deadline) {
  status_response(response, 0);
  struct sockaddr_un address;
  socklen_t address_length;
  if (unix_address(config, &address, &address_length) != 0) {
    int status = errno_status(errno);
    status_response(response, status);
    return status;
  }
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
  if (fd < 0) {
    int status = errno_status(errno);
    status_response(response, status);
    return status;
  }

  int status = remote_parent_status_transport_error;
  int response_complete = 0;
  if (deadline < 0 || monotonic_millis() >= deadline) {
    status = remote_parent_status_timeout;
    goto done;
  }

  if (connect(fd, (struct sockaddr *)&address, address_length) != 0) {
    if (errno != EINPROGRESS || wait_for_fd(fd, POLLOUT, deadline) != 0) {
      status = errno_status(errno);
      goto done;
    }
    int socket_error = 0;
    socklen_t socket_error_length = sizeof(socket_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error,
                   &socket_error_length) != 0 ||
        socket_error != 0) {
      errno = socket_error == 0 ? errno : socket_error;
      status = errno_status(errno);
      goto done;
    }
  }
  if (verify_unix_peer(fd, config) != 0) {
    status = errno_status(errno);
    goto done;
  }

  unsigned char request[remote_parent_request_size];
  build_unix_request(request, operation, source, (uint32_t)syscall(SYS_gettid),
                     config->process_incarnation);

  status = exchange_unix_request(fd, request, response, deadline);
  if (status < 0) {
    status = errno_status(errno);
    goto done;
  }
  response_complete = 1;

done:
  close(fd);
  if (!response_complete) {
    status_response(response, status);
  }
  return status;
}

static void release_remote_parent_config(struct remote_parent_config *config) {
  if (config == NULL || atomic_fetch_sub_explicit(&config->references, 1,
                                                  memory_order_acq_rel) != 1) {
    return;
  }
  if (config->dummy_socket >= 0) {
    close(config->dummy_socket);
  }
  if (config->dummy_peer_socket >= 0) {
    close(config->dummy_peer_socket);
  }
  free(config);
}

static int swap_remote_parent_config(struct remote_parent_config *replacement,
                                     int timeout_millis, int64_t deadline) {
  if (mutex_lock_until(&remote_parent_lock, deadline) != 0) {
    return errno_status(errno);
  }
  struct remote_parent_config *previous = remote_parent_current;
  remote_parent_current = replacement;
  atomic_store_explicit(&remote_parent_timeout_millis, timeout_millis,
                        memory_order_release);
  pthread_mutex_unlock(&remote_parent_lock);
  release_remote_parent_config(previous);
  return remote_parent_status_valid;
}

static int acquire_remote_parent_config(struct remote_parent_config **config,
                                        int64_t deadline) {
  *config = NULL;
  if (mutex_lock_until(&remote_parent_lock, deadline) != 0) {
    return errno_status(errno);
  }

  struct remote_parent_config *current = remote_parent_current;
  if (current != NULL) {
    unsigned int references =
        atomic_load_explicit(&current->references, memory_order_relaxed);
    if (references == UINT_MAX) {
      pthread_mutex_unlock(&remote_parent_lock);
      return remote_parent_status_overload;
    }
    atomic_fetch_add_explicit(&current->references, 1, memory_order_relaxed);
  }
  pthread_mutex_unlock(&remote_parent_lock);
  *config = current;
  return remote_parent_status_valid;
}

static struct remote_parent_config *
new_remote_parent_config(const char *path, int timeout_millis, uid_t server_uid,
                         uint64_t process_incarnation) {
  struct remote_parent_config *config = calloc(1, sizeof(*config));
  if (config == NULL) {
    return NULL;
  }
  config->transport = remote_parent_transport_disabled;
  config->dummy_socket = -1;
  config->dummy_peer_socket = -1;
  config->timeout_millis = timeout_millis;
  config->unix_server_uid = server_uid;
  config->process_incarnation = process_incarnation;
  atomic_init(&config->references, 1);
  if (path != NULL) {
    size_t path_length = strnlen(path, sizeof(config->unix_socket_path));
    if (path_length >= sizeof(config->unix_socket_path)) {
      release_remote_parent_config(config);
      errno = EINVAL;
      return NULL;
    }
    memcpy(config->unix_socket_path, path, path_length + 1);
  }
  return config;
}

static struct remote_parent_config_result
new_remote_parent_config_result(int requested_transport) {
  struct remote_parent_config_result result = {
      .status = remote_parent_status_unknown,
      .requested_transport = remote_parent_transport_none,
      .selected_transport = remote_parent_transport_none,
      .attempted_transports = 0,
      .getsockopt_status = remote_parent_status_unknown,
      .unix_status = remote_parent_status_unknown,
  };
  if (requested_transport >= remote_parent_transport_auto &&
      requested_transport <= remote_parent_transport_disabled) {
    result.requested_transport = (unsigned char)requested_transport;
  }
  return result;
}

static uint64_t
pack_remote_parent_config_result(struct remote_parent_config_result result) {
  return ((uint64_t)(unsigned int)result.status & UINT64_C(0xff)) |
         ((uint64_t)result.requested_transport << 8) |
         ((uint64_t)result.selected_transport << 16) |
         ((uint64_t)result.attempted_transports << 24) |
         ((uint64_t)result.getsockopt_status << 32) |
         ((uint64_t)result.unix_status << 40) |
         ((uint64_t)remote_parent_config_result_version << 48) |
         ((uint64_t)remote_parent_config_result_magic << 56);
}

static struct remote_parent_config_result
configure_remote_parent_result(int requested_transport, const char *path,
                               int timeout_millis, uid_t server_uid,
                               uint64_t process_incarnation) {
  struct remote_parent_config_result result =
      new_remote_parent_config_result(requested_transport);

  int64_t start = monotonic_millis();
  int64_t deadline = deadline_after_millis(start, timeout_millis);
  if (deadline < 0) {
    result.status = remote_parent_status_transport_error;
    return result;
  }

  if (requested_transport == remote_parent_transport_disabled) {
    result.status = swap_remote_parent_config(NULL, timeout_millis, deadline);
    if (result.status == remote_parent_status_valid) {
      result.status = remote_parent_status_disabled;
      result.selected_transport = remote_parent_transport_disabled;
    }
    return result;
  }

  errno = 0;
  struct remote_parent_config *candidate = new_remote_parent_config(
      path, timeout_millis, server_uid, process_incarnation);
  if (candidate == NULL) {
    result.status = errno == EINVAL ? remote_parent_status_malformed
                                    : remote_parent_status_overload;
    return result;
  }

  if (requested_transport == remote_parent_transport_auto ||
      requested_transport == remote_parent_transport_getsockopt) {
    result.attempted_transports |= remote_parent_attempt_getsockopt;
    int probe = remote_parent_status_unsupported;
    if (connected_tcp_probe_pair(&candidate->dummy_socket,
                                 &candidate->dummy_peer_socket) == 0) {
      unsigned char response[remote_parent_record_size];
      probe = call_setsockopt_negotiate(
          candidate->dummy_socket, candidate->process_incarnation, response);
      if (probe_succeeded(probe)) {
        probe = call_getsockopt_health(
            candidate->dummy_socket, candidate->process_incarnation, response);
      }
      if (probe_succeeded(probe)) {
        candidate->transport = remote_parent_transport_getsockopt;
        result.getsockopt_status = remote_parent_status_valid;
        result.status =
            swap_remote_parent_config(candidate, timeout_millis, deadline);
        if (result.status != remote_parent_status_valid) {
          release_remote_parent_config(candidate);
        } else {
          result.selected_transport = remote_parent_transport_getsockopt;
        }
        return result;
      }
      close(candidate->dummy_socket);
      candidate->dummy_socket = -1;
      close(candidate->dummy_peer_socket);
      candidate->dummy_peer_socket = -1;
    } else {
      probe = errno_status(errno);
    }
    result.getsockopt_status = (unsigned char)failed_probe_status(probe);
    if (requested_transport == remote_parent_transport_getsockopt) {
      release_remote_parent_config(candidate);
      result.status = result.getsockopt_status;
      return result;
    }
  }

  if ((requested_transport == remote_parent_transport_auto ||
       requested_transport == remote_parent_transport_unix) &&
      candidate->unix_socket_path[0] != '\0') {
    result.attempted_transports |= remote_parent_attempt_unix;
    if (verify_unix_path(candidate) != 0) {
      result.unix_status = (unsigned char)errno_status(errno);
      result.status = result.unix_status;
      release_remote_parent_config(candidate);
      return result;
    }
    unsigned char response[remote_parent_record_size];
    int probe =
        call_unix_socket(candidate, remote_parent_operation_negotiate,
                         remote_parent_source_direct, response, deadline);
    if (!probe_succeeded(probe)) {
      result.unix_status = (unsigned char)failed_probe_status(probe);
      result.status = result.unix_status;
      release_remote_parent_config(candidate);
      return result;
    }
    result.unix_status = remote_parent_status_valid;
    candidate->transport = remote_parent_transport_unix;
    result.status =
        swap_remote_parent_config(candidate, timeout_millis, deadline);
    if (result.status != remote_parent_status_valid) {
      release_remote_parent_config(candidate);
    } else {
      result.selected_transport = remote_parent_transport_unix;
    }
    return result;
  }

  release_remote_parent_config(candidate);
  result.status = remote_parent_status_unsupported;
  return result;
}

static int call_remote_parent(int operation, int source, int socket_fd,
                              unsigned char *response) {
  if ((operation != remote_parent_operation_take &&
       operation != remote_parent_operation_discard) ||
      (source != remote_parent_source_direct &&
       source != remote_parent_source_task)) {
    status_response(response, remote_parent_status_malformed);
    return remote_parent_status_malformed;
  }

  int64_t start = monotonic_millis();
  int admission_timeout =
      atomic_load_explicit(&remote_parent_timeout_millis, memory_order_acquire);
  int64_t deadline = deadline_after_millis(start, admission_timeout);
  if (deadline < 0) {
    status_response(response, remote_parent_status_transport_error);
    return remote_parent_status_transport_error;
  }

  struct remote_parent_config *config = NULL;
  int status = acquire_remote_parent_config(&config, deadline);
  if (status != remote_parent_status_valid) {
    status_response(response, status);
    return status;
  }
  if (config == NULL) {
    status_response(response, remote_parent_status_disabled);
    return remote_parent_status_disabled;
  }

  int64_t config_deadline =
      deadline_after_millis(start, config->timeout_millis);
  if (config_deadline >= 0 && config_deadline < deadline) {
    deadline = config_deadline;
  }
  if (monotonic_millis() >= deadline) {
    status = remote_parent_status_timeout;
    status_response(response, status);
  } else if (config->transport == remote_parent_transport_getsockopt) {
    if (socket_fd < 0) {
      status = remote_parent_status_missing;
      status_response(response, status);
    } else {
      int option;
      if (source == remote_parent_source_task) {
        option = operation == remote_parent_operation_take
                     ? obi_socket_task_take
                     : obi_socket_task_discard;
      } else {
        option = operation == remote_parent_operation_take ? obi_socket_take
                                                           : obi_socket_discard;
      }
      status = call_getsockopt(socket_fd, option, response);
    }
  } else if (config->transport == remote_parent_transport_unix) {
    status = call_unix_socket(config, operation, source, response, deadline);
  } else {
    status = remote_parent_status_disabled;
    status_response(response, status);
  }
  release_remote_parent_config(config);
  return status;
}

static int emit_data_on_socket(int socket_fd, void *packet) {
  if (socket_fd < 0 || packet == NULL) {
    errno = EINVAL;
    return -1;
  }

  int timeout =
      atomic_load_explicit(&remote_parent_timeout_millis, memory_order_acquire);
  int64_t deadline = deadline_after_millis(monotonic_millis(), timeout);
  int primary_negotiated = 0;
  if (deadline >= 0) {
    struct remote_parent_config *config = NULL;
    int status = acquire_remote_parent_config(&config, deadline);
    if (status == remote_parent_status_valid) {
      if (config != NULL &&
          config->transport == remote_parent_transport_getsockopt) {
        unsigned char response[remote_parent_record_size];
        status = call_setsockopt_negotiate(
            socket_fd, config->process_incarnation, response);
        primary_negotiated = probe_succeeded(status);
      }
      release_remote_parent_config(config);
    }
  }

  uint64_t data_signal_nonce = next_data_signal();
  write_u64_le((unsigned char *)packet, 1 + 36 + sizeof(uint32_t),
               data_signal_nonce);

  if (ioctl(socket_fd, obi_ioctl_magic, packet) != 0 && errno != ENOTTY) {
    return -1;
  }
  if (primary_negotiated &&
      call_setsockopt_data_ack(socket_fd, data_signal_nonce) == 0) {
    return 1;
  }
  return 0;
}

static void close_remote_parent(void) {
  int timeout =
      atomic_load_explicit(&remote_parent_timeout_millis, memory_order_acquire);
  if (pthread_mutex_lock(&remote_parent_lock) != 0) {
    return;
  }
  struct remote_parent_config *previous = remote_parent_current;
  remote_parent_current = NULL;
  atomic_store_explicit(&remote_parent_timeout_millis, timeout,
                        memory_order_release);
  pthread_mutex_unlock(&remote_parent_lock);
  release_remote_parent_config(previous);
}

#ifdef OBI_JNI_TESTING
int obi_test_named_status(const char *name) {
  if (strcmp(name, "valid") == 0) {
    return remote_parent_status_valid;
  }
  if (strcmp(name, "missing") == 0) {
    return remote_parent_status_missing;
  }
  if (strcmp(name, "stale") == 0) {
    return remote_parent_status_stale;
  }
  if (strcmp(name, "unsupported") == 0) {
    return remote_parent_status_unsupported;
  }
  if (strcmp(name, "malformed") == 0) {
    return remote_parent_status_malformed;
  }
  if (strcmp(name, "version_mismatch") == 0) {
    return remote_parent_status_version_mismatch;
  }
  if (strcmp(name, "ambiguous") == 0) {
    return remote_parent_status_ambiguous;
  }
  if (strcmp(name, "unauthorized") == 0) {
    return remote_parent_status_unauthorized;
  }
  if (strcmp(name, "already_consumed") == 0) {
    return remote_parent_status_already_consumed;
  }
  if (strcmp(name, "timeout") == 0) {
    return remote_parent_status_timeout;
  }
  if (strcmp(name, "overload") == 0) {
    return remote_parent_status_overload;
  }
  if (strcmp(name, "transport_error") == 0) {
    return remote_parent_status_transport_error;
  }
  if (strcmp(name, "disabled") == 0) {
    return remote_parent_status_disabled;
  }
  return -1;
}

void obi_test_status_response(unsigned char *response, int status) {
  status_response(response, status);
}

int obi_test_response_status(unsigned char *response, size_t length) {
  return response_status(response, length);
}

int obi_test_errno_status(int error) { return errno_status(error); }

int obi_test_probe_succeeded(int status) { return probe_succeeded(status); }

int obi_test_timeout_valid(int timeout_millis) {
  return timeout_valid(timeout_millis);
}

int obi_test_peer_credentials_allowed(pid_t pid, uid_t uid,
                                      uid_t expected_uid) {
  const struct ucred credentials = {.pid = pid, .uid = uid, .gid = 0};
  return peer_credentials_allowed(&credentials, expected_uid);
}

void obi_test_build_unix_request(unsigned char *request, int operation,
                                 uint32_t namespace_tid,
                                 uint64_t process_incarnation) {
  build_unix_request(request, operation, remote_parent_source_direct,
                     namespace_tid, process_incarnation);
}

void obi_test_build_task_context_packet(unsigned char *packet, int operation,
                                        uint64_t value, uint64_t token) {
  build_task_context_packet(packet, operation, value, token);
}

int obi_test_configure_remote_parent(int transport, const char *path,
                                     int timeout_millis, uid_t server_uid,
                                     uint64_t process_incarnation) {
  return configure_remote_parent_result(transport, path, timeout_millis,
                                        server_uid, process_incarnation)
      .status;
}

uint64_t obi_test_configure_remote_parent_v2(int transport, const char *path,
                                             int timeout_millis,
                                             uid_t server_uid,
                                             uint64_t process_incarnation) {
  return pack_remote_parent_config_result(configure_remote_parent_result(
      transport, path, timeout_millis, server_uid, process_incarnation));
}

int obi_test_call_remote_parent(int operation, unsigned char *response) {
  return call_remote_parent(operation, remote_parent_source_direct, -1,
                            response);
}

int obi_test_call_remote_parent_on_socket(int operation, int socket_fd,
                                          unsigned char *response) {
  return call_remote_parent(operation, remote_parent_source_direct, socket_fd,
                            response);
}

int obi_test_call_remote_parent_task_on_socket(int operation, int socket_fd,
                                               unsigned char *response) {
  return call_remote_parent(operation, remote_parent_source_task, socket_fd,
                            response);
}

int obi_test_exchange_unix_request(int fd, unsigned char *response,
                                   int64_t deadline) {
  unsigned char request[remote_parent_request_size];
  build_unix_request(request, remote_parent_operation_take,
                     remote_parent_source_direct, (uint32_t)syscall(SYS_gettid),
                     1);
  return exchange_unix_request(fd, request, response, deadline);
}

int obi_test_emit_data_on_socket(int socket_fd, unsigned char *packet) {
  return emit_data_on_socket(socket_fd, packet);
}

void obi_test_close_remote_parent(void) { close_remote_parent(); }

int obi_test_lock_remote_parent(void) {
  return pthread_mutex_lock(&remote_parent_lock);
}

int obi_test_unlock_remote_parent(void) {
  return pthread_mutex_unlock(&remote_parent_lock);
}
#endif

/*
 * Class:     io_opentelemetry_obi_java_ebpf_NativeMemory
 * Method:    getDirectBufferAddress
 * Signature: (Ljava/nio/ByteBuffer;)J
 */
JNIEXPORT jlong JNICALL
Java_io_opentelemetry_obi_java_ebpf_NativeMemory_getDirectBufferAddress(
    JNIEnv *env, jclass clazz, jobject buffer) {
  return (jlong)(*env)->GetDirectBufferAddress(env, buffer);
}

/*
 * Class:     io_opentelemetry_obi_java_BootstrapNative
 * Method:    ioctl
 * Signature: (IIJ)I
 */
JNIEXPORT jint JNICALL Java_io_opentelemetry_obi_java_BootstrapNative_ioctl(
    JNIEnv *env, jclass clazz, jint fd, jint cmd, jlong argp) {
  return ioctl(fd, cmd, argp);
}

/*
 * Class:     io_opentelemetry_obi_java_BootstrapNative
 * Method:    gettid
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_io_opentelemetry_obi_java_BootstrapNative_gettid(
    JNIEnv *env, jclass clazz) {
  return (jint)syscall(SYS_gettid);
}

/*
 * Class:     io_opentelemetry_obi_java_BootstrapNative
 * Method:    socketFileDescriptor
 * Signature: (Ljava/net/Socket;)I
 */
JNIEXPORT jint JNICALL
Java_io_opentelemetry_obi_java_BootstrapNative_socketFileDescriptor(
    JNIEnv *env, jclass clazz, jobject socket) {
  return (jint)socket_file_descriptor(env, socket, 1);
}

/*
 * Class:     io_opentelemetry_obi_java_BootstrapNative
 * Method:    emitDataOnSocket
 * Signature: (IJ)I
 */
JNIEXPORT jint JNICALL
Java_io_opentelemetry_obi_java_BootstrapNative_emitDataOnSocket(JNIEnv *env,
                                                                jclass clazz,
                                                                jint socket_fd,
                                                                jlong argp) {
  return emit_data_on_socket(socket_fd, (void *)(uintptr_t)argp);
}

/*
 * Class:     io_opentelemetry_obi_java_BootstrapNative
 * Method:    emitVirtualThreadOp
 * Signature: (BJ)I
 */
JNIEXPORT jint JNICALL
Java_io_opentelemetry_obi_java_BootstrapNative_emitVirtualThreadOp(
    JNIEnv *env, jclass clazz, jbyte operation, jlong value) {
  unsigned char packet[1 + sizeof(uint64_t)] = {0};
  packet[0] = (unsigned char)operation;
  write_u64_le(packet, 1, (uint64_t)value);
  return ioctl(0, obi_ioctl_magic, packet);
}

/*
 * Class:     io_opentelemetry_obi_java_BootstrapNative
 * Method:    emitTaskContextOp
 * Signature: (BJJ)I
 */
JNIEXPORT jint JNICALL
Java_io_opentelemetry_obi_java_BootstrapNative_emitTaskContextOp(
    JNIEnv *env, jclass clazz, jbyte operation, jlong value, jlong token) {
  unsigned char packet[1 + (2 * sizeof(uint64_t))] = {0};
  build_task_context_packet(packet, operation, (uint64_t)value,
                            (uint64_t)token);
  return ioctl(0, obi_ioctl_magic, packet);
}

static struct remote_parent_config_result
configure_remote_parent_jni(JNIEnv *env, jclass clazz, jint transport,
                            jstring unix_path, jint timeout_millis,
                            jlong server_uid, jlong process_incarnation) {
  struct remote_parent_config_result result =
      new_remote_parent_config_result(transport);
  if (!timeout_valid(timeout_millis) || server_uid < 0 ||
      (uint64_t)(uid_t)server_uid != (uint64_t)server_uid ||
      process_incarnation == 0) {
    result.status = remote_parent_status_malformed;
    return result;
  }

  const char *path = NULL;
  if (unix_path != NULL) {
    path = (*env)->GetStringUTFChars(env, unix_path, NULL);
    if (path == NULL) {
      clear_jni_exception(env);
      result.status = remote_parent_status_transport_error;
      return result;
    }
  }
  result = configure_remote_parent_result(transport, path, timeout_millis,
                                          (uid_t)server_uid,
                                          (uint64_t)process_incarnation);
  if (path != NULL) {
    (*env)->ReleaseStringUTFChars(env, unix_path, path);
  }
  return result;
}

/*
 * Class:     io_opentelemetry_obi_java_BootstrapNative
 * Method:    configureRemoteParentTransport
 * Signature: (ILjava/lang/String;IJJ)I
 */
JNIEXPORT jint JNICALL
Java_io_opentelemetry_obi_java_BootstrapNative_configureRemoteParentTransport(
    JNIEnv *env, jclass clazz, jint transport, jstring unix_path,
    jint timeout_millis, jlong server_uid, jlong process_incarnation) {
  return configure_remote_parent_jni(env, clazz, transport, unix_path,
                                     timeout_millis, server_uid,
                                     process_incarnation)
      .status;
}

/*
 * Class:     io_opentelemetry_obi_java_BootstrapNative
 * Method:    configureRemoteParentTransportV2
 * Signature: (ILjava/lang/String;IJJ)J
 */
JNIEXPORT jlong JNICALL
Java_io_opentelemetry_obi_java_BootstrapNative_configureRemoteParentTransportV2(
    JNIEnv *env, jclass clazz, jint transport, jstring unix_path,
    jint timeout_millis, jlong server_uid, jlong process_incarnation) {
  return (jlong)pack_remote_parent_config_result(configure_remote_parent_jni(
      env, clazz, transport, unix_path, timeout_millis, server_uid,
      process_incarnation));
}

static jint remote_parent_response(JNIEnv *env, jbyteArray output,
                                   int operation, int source, int socket_fd) {
  if (output == NULL ||
      (*env)->GetArrayLength(env, output) != remote_parent_record_size) {
    return remote_parent_status_malformed;
  }

  unsigned char response[remote_parent_record_size];
  int status = call_remote_parent(operation, source, socket_fd, response);
  (*env)->SetByteArrayRegion(env, output, 0, remote_parent_record_size,
                             (const jbyte *)response);
  if ((*env)->ExceptionCheck(env)) {
    clear_jni_exception(env);
    return remote_parent_status_transport_error;
  }
  return status;
}

/*
 * Class:     io_opentelemetry_obi_java_BootstrapNative
 * Method:    takeRemoteParent
 * Signature: (I[B)I
 */
JNIEXPORT jint JNICALL
Java_io_opentelemetry_obi_java_BootstrapNative_takeRemoteParent(
    JNIEnv *env, jclass clazz, jint socket_fd, jbyteArray output) {
  return remote_parent_response(env, output, remote_parent_operation_take,
                                remote_parent_source_direct, socket_fd);
}

/*
 * Class:     io_opentelemetry_obi_java_BootstrapNative
 * Method:    discardRemoteParent
 * Signature: (I[B)I
 */
JNIEXPORT jint JNICALL
Java_io_opentelemetry_obi_java_BootstrapNative_discardRemoteParent(
    JNIEnv *env, jclass clazz, jint socket_fd, jbyteArray output) {
  return remote_parent_response(env, output, remote_parent_operation_discard,
                                remote_parent_source_direct, socket_fd);
}

JNIEXPORT jint JNICALL
Java_io_opentelemetry_obi_java_BootstrapNative_takeRemoteParentTask(
    JNIEnv *env, jclass clazz, jint socket_fd, jbyteArray output) {
  return remote_parent_response(env, output, remote_parent_operation_take,
                                remote_parent_source_task, socket_fd);
}

JNIEXPORT jint JNICALL
Java_io_opentelemetry_obi_java_BootstrapNative_discardRemoteParentTask(
    JNIEnv *env, jclass clazz, jint socket_fd, jbyteArray output) {
  return remote_parent_response(env, output, remote_parent_operation_discard,
                                remote_parent_source_task, socket_fd);
}

/*
 * Class:     io_opentelemetry_obi_java_BootstrapNative
 * Method:    closeRemoteParentTransport
 * Signature: ()V
 */
JNIEXPORT void JNICALL
Java_io_opentelemetry_obi_java_BootstrapNative_closeRemoteParentTransport(
    JNIEnv *env, jclass clazz) {
  close_remote_parent();
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved) {
  close_remote_parent();
}
