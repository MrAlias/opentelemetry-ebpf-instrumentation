/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

void obi_test_status_response(unsigned char *response, int status);
int obi_test_named_status(const char *name);
int obi_test_response_status(unsigned char *response, size_t length);
int obi_test_errno_status(int error);
int obi_test_probe_succeeded(int status);
int obi_test_timeout_valid(int timeout_millis);
int obi_test_peer_credentials_allowed(pid_t pid, uid_t uid, uid_t expected_uid);
void obi_test_build_unix_request(unsigned char *request, int operation,
                                 uint32_t namespace_tid,
                                 uint64_t process_incarnation);
void obi_test_build_task_context_packet(unsigned char *packet, int operation,
                                        uint64_t value, uint64_t token);
int obi_test_configure_remote_parent(int transport, const char *path,
                                     int timeout_millis, uid_t server_uid,
                                     uint64_t process_incarnation);
uint64_t obi_test_configure_remote_parent_v2(int transport, const char *path,
                                             int timeout_millis,
                                             uid_t server_uid,
                                             uint64_t process_incarnation);
int obi_test_call_remote_parent(int operation, unsigned char *response);
int obi_test_call_remote_parent_on_socket(int operation, int socket_fd,
                                          unsigned char *response);
int obi_test_call_remote_parent_task_on_socket(int operation, int socket_fd,
                                               unsigned char *response);
int obi_test_exchange_unix_request(int fd, unsigned char *response,
                                   int64_t deadline);
int obi_test_emit_data_on_socket(int socket_fd, unsigned char *packet);
unsigned int obi_test_remote_parent_config_acquisition_count(void);
void obi_test_reset_remote_parent_config_acquisition_count(void);
void obi_test_close_remote_parent(void);
int obi_test_lock_remote_parent(void);
int obi_test_unlock_remote_parent(void);

jint Java_io_opentelemetry_obi_java_BootstrapNative_configureRemoteParentTransport(
    JNIEnv *env, jclass clazz, jint transport, jstring unix_path,
    jint timeout_millis, jlong server_uid, jlong process_incarnation);
jlong Java_io_opentelemetry_obi_java_BootstrapNative_configureRemoteParentTransportV2(
    JNIEnv *env, jclass clazz, jint transport, jstring unix_path,
    jint timeout_millis, jlong server_uid, jlong process_incarnation);
jint Java_io_opentelemetry_obi_java_BootstrapNative_takeRemoteParent(
    JNIEnv *env, jclass clazz, jint socket_fd, jbyteArray output);
jint Java_io_opentelemetry_obi_java_BootstrapNative_discardRemoteParent(
    JNIEnv *env, jclass clazz, jint socket_fd, jbyteArray output);
jint Java_io_opentelemetry_obi_java_BootstrapNative_takeRemoteParentTask(
    JNIEnv *env, jclass clazz, jint socket_fd, jbyteArray output);
jint Java_io_opentelemetry_obi_java_BootstrapNative_discardRemoteParentTask(
    JNIEnv *env, jclass clazz, jint socket_fd, jbyteArray output);
jint Java_io_opentelemetry_obi_java_BootstrapNative_emitVirtualThreadOp(
    JNIEnv *env, jclass clazz, jbyte operation, jlong value);
jint Java_io_opentelemetry_obi_java_BootstrapNative_emitTaskContextOp(
    JNIEnv *env, jclass clazz, jbyte operation, jlong value, jlong token);
void Java_io_opentelemetry_obi_java_BootstrapNative_closeRemoteParentTransport(
    JNIEnv *env, jclass clazz);

static int fake_getsockopt_status = 2;
static socklen_t fake_getsockopt_length = 64;
static int fake_getsockopt_bad_magic;
static int fake_health_error;
static int fake_health_mismatch;
static int fake_setsockopt_error;
static int fake_data_ack_error;
static int fake_ioctl_error = ENOTTY;
static _Atomic int observed_getsockopt_level;
static _Atomic int observed_getsockopt_option;
static _Atomic int observed_getsockopt_fd;
static _Atomic int observed_getsockopt_calls;
static _Atomic int observed_setsockopt_level;
static _Atomic int observed_setsockopt_option;
static _Atomic int observed_setsockopt_fd;
static _Atomic int observed_setsockopt_calls;
static _Atomic int observed_ioctl_fd;
static _Atomic unsigned long observed_ioctl_request;
static _Atomic int observed_ioctl_calls;
static _Atomic uint64_t observed_ioctl_nonce;
static _Atomic int observed_peer_credential_lookups;
static struct stat denied_socket_identity;
static _Atomic int denied_socket_identity_set;
static _Atomic int observed_denied_socket_getsockopt_lookups;
static _Atomic uint64_t observed_negotiate_incarnation;
static _Atomic uint64_t observed_data_ack_nonce;
static _Atomic int observed_transport_event_count;
static int observed_transport_events[3];

enum {
  test_data_operation_send = 1,
  test_data_operation_receive = 2,
  test_data_operation_http1_receive_start = 14,
  test_data_operation_http1_receive_continue = 15,
  test_data_operation_http1_receive_reset = 16,
  test_data_operation_unknown = 0xff,
  test_data_signal_offset = 41,
};

static int operation_has_data_signal_nonce(unsigned char operation) {
  switch (operation) {
  case test_data_operation_send:
  case test_data_operation_receive:
  case test_data_operation_http1_receive_start:
  case test_data_operation_http1_receive_continue:
  case test_data_operation_http1_receive_reset:
    return 1;
  default:
    return 0;
  }
}

enum { fake_negotiation_capacity = 128 };
struct fake_negotiation {
  int fd;
  int used;
  uint64_t incarnation;
};
static pthread_mutex_t fake_negotiation_lock = PTHREAD_MUTEX_INITIALIZER;
static struct fake_negotiation fake_negotiations[fake_negotiation_capacity];

static uint64_t read_u64_le(const unsigned char *buffer, size_t offset);
static int64_t test_monotonic_millis(void);

static void remember_fake_negotiation(int fd, uint64_t incarnation) {
  assert(pthread_mutex_lock(&fake_negotiation_lock) == 0);
  struct fake_negotiation *available = NULL;
  for (size_t index = 0; index < fake_negotiation_capacity; index++) {
    if (fake_negotiations[index].used && fake_negotiations[index].fd == fd) {
      available = &fake_negotiations[index];
      break;
    }
    if (available == NULL && !fake_negotiations[index].used) {
      available = &fake_negotiations[index];
    }
  }
  assert(available != NULL);
  available->fd = fd;
  available->used = 1;
  available->incarnation = incarnation;
  assert(pthread_mutex_unlock(&fake_negotiation_lock) == 0);
}

static uint64_t fake_negotiation_for(int fd) {
  uint64_t incarnation = 0;
  assert(pthread_mutex_lock(&fake_negotiation_lock) == 0);
  for (size_t index = 0; index < fake_negotiation_capacity; index++) {
    if (fake_negotiations[index].used && fake_negotiations[index].fd == fd) {
      incarnation = fake_negotiations[index].incarnation;
      break;
    }
  }
  assert(pthread_mutex_unlock(&fake_negotiation_lock) == 0);
  return incarnation;
}

static int socket_fd_is_denied(int fd) {
  if (!atomic_load(&denied_socket_identity_set)) {
    return 0;
  }

  struct stat identity;
  assert(fstat(fd, &identity) == 0);
  return identity.st_dev == denied_socket_identity.st_dev &&
         identity.st_ino == denied_socket_identity.st_ino;
}

static void deny_socket_fd(int fd) {
  assert(fstat(fd, &denied_socket_identity) == 0);
  atomic_store(&denied_socket_identity_set, 1);
}

static void clear_denied_socket_fd(void) {
  atomic_store(&denied_socket_identity_set, 0);
  memset(&denied_socket_identity, 0, sizeof(denied_socket_identity));
}

int getsockopt(int fd, int level, int option, void *value, socklen_t *length) {
  if (socket_fd_is_denied(fd)) {
    atomic_fetch_add(&observed_denied_socket_getsockopt_lookups, 1);
    errno = EACCES;
    return -1;
  }
  if (level == SOL_SOCKET && option == SO_PEERCRED) {
    atomic_fetch_add(&observed_peer_credential_lookups, 1);
    assert(*length >= sizeof(struct ucred));
    struct ucred credentials = {
        .pid = getpid(), .uid = geteuid(), .gid = getegid()};
    memcpy(value, &credentials, sizeof(credentials));
    *length = sizeof(credentials);
    return 0;
  }

  atomic_store(&observed_getsockopt_fd, fd);
  atomic_store(&observed_getsockopt_level, level);
  atomic_store(&observed_getsockopt_option, option);
  atomic_fetch_add(&observed_getsockopt_calls, 1);
  if (level == 0x4f42 && option == 0x4a05) {
    if (fake_health_error != 0) {
      errno = fake_health_error;
      return -1;
    }
    assert(*length >= sizeof(uint64_t));
    uint64_t incarnation = fake_negotiation_for(fd);
    assert(incarnation != 0);
    if (fake_health_mismatch) {
      incarnation++;
    }
    unsigned char *health = value;
    for (size_t index = 0; index < sizeof(incarnation); index++) {
      health[index] = (unsigned char)(incarnation >> (index * 8));
    }
    *length = sizeof(incarnation);
    return 0;
  }
  if (fake_getsockopt_status < 0) {
    errno = -fake_getsockopt_status;
    return -1;
  }

  assert(*length >= 64);
  unsigned char *response = value;
  memset(response, 0, 64);
  memcpy(response, "OBIJ", 4);
  response[4] = 1;
  response[6] = 64;
  response[8] = (unsigned char)fake_getsockopt_status;
  if (fake_getsockopt_status == 1) {
    response[9] = 1;
    response[16] = 1;
    response[32] = 1;
    response[40] = 1;
    response[48] = 1;
  }
  if (fake_getsockopt_bad_magic) {
    response[0] = 'X';
  }
  *length = fake_getsockopt_length;
  return 0;
}

int setsockopt(int fd, int level, int option, const void *value,
               socklen_t length) {
  atomic_store(&observed_setsockopt_fd, fd);
  atomic_store(&observed_setsockopt_level, level);
  atomic_store(&observed_setsockopt_option, option);
  atomic_fetch_add(&observed_setsockopt_calls, 1);
  if (level == 0x4f42 && option == 0x4a03) {
    assert(length == sizeof(uint64_t));
    uint64_t incarnation = read_u64_le(value, 0);
    atomic_store(&observed_negotiate_incarnation, incarnation);
    remember_fake_negotiation(fd, incarnation);
    int event = atomic_fetch_add(&observed_transport_event_count, 1);
    if (event < 3) {
      observed_transport_events[event] = 1;
    }
  }
  if (level == 0x4f42 && option == 0x4a04) {
    assert(length == sizeof(uint64_t));
    atomic_store(&observed_data_ack_nonce, read_u64_le(value, 0));
    int event = atomic_fetch_add(&observed_transport_event_count, 1);
    if (event < 3) {
      observed_transport_events[event] = 3;
    }
    if (fake_data_ack_error != 0) {
      errno = fake_data_ack_error;
      return -1;
    }
  }
  if (fake_setsockopt_error != 0) {
    errno = fake_setsockopt_error;
    return -1;
  }
  return 0;
}

int ioctl(int fd, unsigned long request, ...) {
  va_list arguments;
  va_start(arguments, request);
  unsigned char *packet = va_arg(arguments, unsigned char *);
  va_end(arguments);
  assert(packet != NULL);

  atomic_store(&observed_ioctl_fd, fd);
  atomic_store(&observed_ioctl_request, request);
  uint64_t nonce = operation_has_data_signal_nonce(packet[0])
                       ? read_u64_le(packet, test_data_signal_offset)
                       : 0;
  atomic_store(&observed_ioctl_nonce, nonce);
  atomic_fetch_add(&observed_ioctl_calls, 1);
  int event = atomic_fetch_add(&observed_transport_event_count, 1);
  if (event < 3) {
    observed_transport_events[event] = 2;
  }
  if (fake_ioctl_error != 0) {
    errno = fake_ioctl_error;
    return -1;
  }
  return 0;
}

static uint16_t read_u16_le(const unsigned char *buffer, size_t offset) {
  return (uint16_t)(buffer[offset] | ((uint16_t)buffer[offset + 1] << 8));
}

static uint32_t read_u32_le(const unsigned char *buffer, size_t offset) {
  uint32_t value = 0;
  for (size_t i = 0; i < sizeof(value); i++) {
    value |= (uint32_t)buffer[offset + i] << (i * 8);
  }
  return value;
}

static uint64_t read_u64_le(const unsigned char *buffer, size_t offset) {
  uint64_t value = 0;
  for (size_t i = 0; i < sizeof(value); i++) {
    value |= (uint64_t)buffer[offset + i] << (i * 8);
  }
  return value;
}

static void reset_transport_observations(void) {
  atomic_store(&observed_getsockopt_level, 0);
  atomic_store(&observed_getsockopt_option, 0);
  atomic_store(&observed_getsockopt_fd, -1);
  atomic_store(&observed_getsockopt_calls, 0);
  atomic_store(&observed_setsockopt_level, 0);
  atomic_store(&observed_setsockopt_option, 0);
  atomic_store(&observed_setsockopt_fd, -1);
  atomic_store(&observed_setsockopt_calls, 0);
  atomic_store(&observed_ioctl_fd, -1);
  atomic_store(&observed_ioctl_request, 0);
  atomic_store(&observed_ioctl_calls, 0);
  atomic_store(&observed_ioctl_nonce, 0);
  atomic_store(&observed_peer_credential_lookups, 0);
  clear_denied_socket_fd();
  atomic_store(&observed_denied_socket_getsockopt_lookups, 0);
  atomic_store(&observed_data_ack_nonce, 0);
  atomic_store(&observed_transport_event_count, 0);
  memset(observed_transport_events, 0, sizeof(observed_transport_events));
  obi_test_reset_remote_parent_config_acquisition_count();
}

struct fake_jni_string {
  const char *value;
  int releases;
};

struct fake_jni_byte_array {
  jsize length;
  unsigned char bytes[64];
};

static int fake_jni_string_failure;
static int fake_jni_region_exception;
static jboolean fake_jni_exception_pending;
static int fake_jni_exception_clears;

static const char *JNICALL fake_get_string_utf_chars(JNIEnv *env, jstring value,
                                                     jboolean *is_copy) {
  (void)env;
  if (is_copy != NULL) {
    *is_copy = JNI_FALSE;
  }
  if (fake_jni_string_failure) {
    fake_jni_exception_pending = JNI_TRUE;
    return NULL;
  }
  return ((struct fake_jni_string *)value)->value;
}

static void JNICALL fake_release_string_utf_chars(JNIEnv *env, jstring value,
                                                  const char *characters) {
  (void)env;
  assert(characters == ((struct fake_jni_string *)value)->value);
  ((struct fake_jni_string *)value)->releases++;
}

static jsize JNICALL fake_get_array_length(JNIEnv *env, jarray value) {
  (void)env;
  return ((struct fake_jni_byte_array *)value)->length;
}

static void JNICALL fake_set_byte_array_region(JNIEnv *env, jbyteArray value,
                                               jsize start, jsize length,
                                               const jbyte *source) {
  (void)env;
  struct fake_jni_byte_array *array = (struct fake_jni_byte_array *)value;
  assert(start >= 0);
  assert(length >= 0);
  assert(start + length <= array->length);
  memcpy(array->bytes + start, source, (size_t)length);
  if (fake_jni_region_exception) {
    fake_jni_exception_pending = JNI_TRUE;
  }
}

static jboolean JNICALL fake_exception_check(JNIEnv *env) {
  (void)env;
  return fake_jni_exception_pending;
}

static void JNICALL fake_exception_clear(JNIEnv *env) {
  (void)env;
  fake_jni_exception_pending = JNI_FALSE;
  fake_jni_exception_clears++;
}

static const struct JNINativeInterface_ fake_jni_functions = {
    .GetStringUTFChars = fake_get_string_utf_chars,
    .ReleaseStringUTFChars = fake_release_string_utf_chars,
    .GetArrayLength = fake_get_array_length,
    .SetByteArrayRegion = fake_set_byte_array_region,
    .ExceptionCheck = fake_exception_check,
    .ExceptionClear = fake_exception_clear,
};
static JNIEnv fake_jni_environment = &fake_jni_functions;

static JNIEnv *fake_jni(void) { return &fake_jni_environment; }

enum {
  corpus_line_capacity = 512,
  corpus_wire_capacity = 80,
};

enum corpus_case {
  corpus_valid_sampled,
  corpus_valid_unsampled,
  corpus_valid_future_flags,
  corpus_status_only,
  corpus_all_zero_ids,
  corpus_zero_trace_id,
  corpus_zero_span_id,
  corpus_zero_generation,
  corpus_zero_observation,
  corpus_zero_length,
  corpus_pre_magic_truncated,
  corpus_truncated,
  corpus_bad_magic,
  corpus_declared_smaller,
  corpus_declared_larger,
  corpus_reserved_prefix,
  corpus_reserved_suffix,
  corpus_unknown_status_zero,
  corpus_unknown_status_14,
  corpus_unknown_version,
  corpus_unknown_version_bad_size,
  corpus_future_larger_v1,
  corpus_future_larger_unknown_version,
};

struct corpus_spec {
  const char *name;
  const char *status_name;
  int accepted;
  size_t wire_size;
  enum corpus_case kind;
};

static const struct corpus_spec corpus_specs[] = {
    {"valid_sampled", "valid", 1, 64, corpus_valid_sampled},
    {"valid_unsampled", "valid", 1, 64, corpus_valid_unsampled},
    {"valid_future_flags", "valid", 1, 64, corpus_valid_future_flags},
    {"status_missing", "missing", 1, 64, corpus_status_only},
    {"status_stale", "stale", 1, 64, corpus_status_only},
    {"status_unsupported", "unsupported", 1, 64, corpus_status_only},
    {"status_malformed", "malformed", 1, 64, corpus_status_only},
    {"status_version_mismatch", "version_mismatch", 1, 64, corpus_status_only},
    {"status_ambiguous", "ambiguous", 1, 64, corpus_status_only},
    {"status_unauthorized", "unauthorized", 1, 64, corpus_status_only},
    {"status_already_consumed", "already_consumed", 1, 64, corpus_status_only},
    {"status_timeout", "timeout", 1, 64, corpus_status_only},
    {"status_overload", "overload", 1, 64, corpus_status_only},
    {"status_transport_error", "transport_error", 1, 64, corpus_status_only},
    {"status_disabled", "disabled", 1, 64, corpus_status_only},
    {"all_zero_ids", "malformed", 0, 64, corpus_all_zero_ids},
    {"zero_trace_id", "malformed", 0, 64, corpus_zero_trace_id},
    {"zero_span_id", "malformed", 0, 64, corpus_zero_span_id},
    {"zero_generation", "malformed", 0, 64, corpus_zero_generation},
    {"zero_observation_time", "malformed", 0, 64, corpus_zero_observation},
    {"zero_length", "malformed", 0, 0, corpus_zero_length},
    {"pre_magic_truncated", "malformed", 0, 3, corpus_pre_magic_truncated},
    {"truncated", "malformed", 0, 63, corpus_truncated},
    {"bad_magic", "malformed", 0, 64, corpus_bad_magic},
    {"declared_smaller", "malformed", 0, 64, corpus_declared_smaller},
    {"declared_larger", "malformed", 0, 64, corpus_declared_larger},
    {"reserved_prefix", "malformed", 0, 64, corpus_reserved_prefix},
    {"reserved_suffix", "malformed", 0, 64, corpus_reserved_suffix},
    {"unknown_status_zero", "malformed", 0, 64, corpus_unknown_status_zero},
    {"unknown_status_14", "malformed", 0, 64, corpus_unknown_status_14},
    {"unknown_version", "version_mismatch", 0, 64, corpus_unknown_version},
    {"unknown_version_bad_declared_size", "version_mismatch", 0, 64,
     corpus_unknown_version_bad_size},
    {"future_larger_v1", "malformed", 0, 80, corpus_future_larger_v1},
    {"future_larger_unknown_version", "malformed", 0, 80,
     corpus_future_larger_unknown_version},
};

static _Noreturn void corpus_fail(const char *path, size_t line,
                                  const char *message) {
  fprintf(stderr, "%s:%zu: %s\n", path, line, message);
  exit(1);
}

static int corpus_name_valid(const char *name) {
  if (name[0] < 'a' || name[0] > 'z') {
    return 0;
  }
  for (size_t index = 1; name[index] != '\0'; index++) {
    char value = name[index];
    if ((value < 'a' || value > 'z') && (value < '0' || value > '9') &&
        value != '_') {
      return 0;
    }
  }
  return 1;
}

static int split_corpus_fields(char *line, char **fields, size_t field_count) {
  char *cursor = line;
  for (size_t index = 0; index + 1 < field_count; index++) {
    fields[index] = cursor;
    char *separator = strchr(cursor, '|');
    if (separator == NULL) {
      return 0;
    }
    *separator = '\0';
    cursor = separator + 1;
  }
  fields[field_count - 1] = cursor;
  return strchr(cursor, '|') == NULL;
}

static int corpus_hex_nibble(char value) {
  if (value >= '0' && value <= '9') {
    return value - '0';
  }
  if (value >= 'a' && value <= 'f') {
    return value - 'a' + 10;
  }
  return -1;
}

static size_t decode_corpus_wire(const char *path, size_t line,
                                 const char *encoded, unsigned char *decoded) {
  if (encoded[0] == '\0') {
    corpus_fail(path, line, "wire bytes are missing");
  }
  if (strcmp(encoded, "-") == 0) {
    return 0;
  }

  size_t encoded_length = strlen(encoded);
  if ((encoded_length & 1) != 0 || encoded_length > corpus_wire_capacity * 2) {
    corpus_fail(path, line, "invalid wire length");
  }

  size_t decoded_length = encoded_length / 2;
  for (size_t index = 0; index < decoded_length; index++) {
    int high = corpus_hex_nibble(encoded[index * 2]);
    int low = corpus_hex_nibble(encoded[index * 2 + 1]);
    if (high < 0 || low < 0) {
      corpus_fail(path, line, "wire bytes must be lower-case hexadecimal");
    }
    decoded[index] = (unsigned char)((high << 4) | low);
  }
  return decoded_length;
}

static int parse_corpus_status(const char *path, size_t line,
                               const char *encoded) {
  errno = 0;
  char *end = NULL;
  unsigned long value = strtoul(encoded, &end, 10);
  if (errno != 0 || end == encoded || *end != '\0' || value < 1 || value > 13) {
    corpus_fail(path, line, "invalid expected status");
  }
  return (int)value;
}

static size_t find_corpus_spec(const char *path, size_t line,
                               const char *name) {
  for (size_t index = 0; index < sizeof(corpus_specs) / sizeof(corpus_specs[0]);
       index++) {
    if (strcmp(corpus_specs[index].name, name) == 0) {
      return index;
    }
  }
  corpus_fail(path, line, "unknown vector name");
  return 0;
}

static void corpus_valid_wire(unsigned char *wire, unsigned char flags) {
  obi_test_status_response(wire, obi_test_named_status("valid"));
  wire[9] = flags;
  for (size_t index = 0; index < 16; index++) {
    wire[16 + index] = (unsigned char)index;
  }
  for (size_t index = 0; index < 8; index++) {
    wire[32 + index] = (unsigned char)(index + 16);
    wire[40 + index] =
        (unsigned char)(UINT64_C(0x0102030405060708) >> (index * 8));
    wire[48 + index] =
        (unsigned char)(UINT64_C(0x1112131415161718) >> (index * 8));
  }
}

static size_t expected_corpus_wire(const struct corpus_spec *spec,
                                   unsigned char *wire) {
  memset(wire, 0, corpus_wire_capacity);
  int status = obi_test_named_status(spec->status_name);
  if (status < 0) {
    return corpus_wire_capacity + 1;
  }
  if (spec->kind == corpus_status_only) {
    obi_test_status_response(wire, status);
    return spec->wire_size;
  }

  unsigned char flags = 0x01;
  if (spec->kind == corpus_valid_unsampled) {
    flags = 0x00;
  } else if (spec->kind == corpus_valid_future_flags) {
    flags = 0x81;
  }
  corpus_valid_wire(wire, flags);

  switch (spec->kind) {
  case corpus_valid_sampled:
  case corpus_valid_unsampled:
  case corpus_valid_future_flags:
    break;
  case corpus_all_zero_ids:
    memset(wire + 16, 0, 24);
    break;
  case corpus_zero_trace_id:
    memset(wire + 16, 0, 16);
    break;
  case corpus_zero_span_id:
    memset(wire + 32, 0, 8);
    break;
  case corpus_zero_generation:
    memset(wire + 40, 0, 8);
    break;
  case corpus_zero_observation:
    memset(wire + 48, 0, 8);
    break;
  case corpus_zero_length:
    return 0;
  case corpus_pre_magic_truncated:
  case corpus_truncated:
    break;
  case corpus_bad_magic:
    wire[0] = 'X';
    break;
  case corpus_declared_smaller:
    wire[6] = 63;
    break;
  case corpus_declared_larger:
    wire[6] = corpus_wire_capacity;
    break;
  case corpus_reserved_prefix:
    wire[10] = 1;
    break;
  case corpus_reserved_suffix:
    wire[56] = 1;
    break;
  case corpus_unknown_status_zero:
  case corpus_unknown_status_14:
    obi_test_status_response(wire, obi_test_named_status("missing"));
    wire[8] = spec->kind == corpus_unknown_status_14 ? 14 : 0;
    break;
  case corpus_unknown_version:
    wire[4] = 2;
    break;
  case corpus_unknown_version_bad_size:
    wire[4] = 2;
    wire[6] = corpus_wire_capacity;
    break;
  case corpus_future_larger_v1:
    wire[6] = corpus_wire_capacity;
    break;
  case corpus_future_larger_unknown_version:
    wire[4] = 2;
    wire[6] = corpus_wire_capacity;
    break;
  case corpus_status_only:
    break;
  }
  return spec->wire_size;
}

static void assert_corpus_wire(const char *path, size_t line,
                               const struct corpus_spec *spec,
                               const unsigned char *wire, size_t wire_length) {
  unsigned char expected[corpus_wire_capacity];
  size_t expected_length = expected_corpus_wire(spec, expected);
  if (expected_length != wire_length ||
      memcmp(expected, wire, wire_length) != 0) {
    corpus_fail(path, line, "wire bytes do not match the required case");
  }
}

static void test_remote_parent_corpus(const char *path) {
  FILE *file = fopen(path, "rb");
  if (file == NULL) {
    corpus_fail(path, 0, "cannot open corpus");
  }

  int seen[sizeof(corpus_specs) / sizeof(corpus_specs[0])] = {0};
  size_t vector_count = 0;
  size_t line_number = 0;
  int stage = 0;
  char line[corpus_line_capacity];
  while (fgets(line, sizeof(line), file) != NULL) {
    line_number++;
    size_t length = strlen(line);
    if (length == sizeof(line) - 1 && line[length - 1] != '\n' && !feof(file)) {
      corpus_fail(path, line_number, "line is too long");
    }
    while (length > 0 &&
           (line[length - 1] == '\n' || line[length - 1] == '\r')) {
      line[--length] = '\0';
    }
    if (length == 0 || line[0] == '#') {
      continue;
    }
    if (stage == 0) {
      if (strcmp(line, "format|1") != 0) {
        corpus_fail(path, line_number, "unsupported corpus format");
      }
      stage++;
      continue;
    }
    if (stage == 1) {
      if (strcmp(line, "name|outcome|status_name|status|wire_hex") != 0) {
        corpus_fail(path, line_number, "invalid corpus header");
      }
      stage++;
      continue;
    }

    char *fields[5];
    if (!split_corpus_fields(line, fields, 5)) {
      corpus_fail(path, line_number, "expected five fields");
    }
    if (!corpus_name_valid(fields[0])) {
      corpus_fail(path, line_number, "invalid vector name");
    }
    size_t spec_index = find_corpus_spec(path, line_number, fields[0]);
    const struct corpus_spec *spec = &corpus_specs[spec_index];
    if (seen[spec_index]) {
      corpus_fail(path, line_number, "duplicate vector name");
    }
    seen[spec_index] = 1;

    const char *outcome = spec->accepted ? "accept" : "reject";
    if (strcmp(fields[1], outcome) != 0) {
      corpus_fail(path, line_number, "unexpected outcome");
    }
    if (strcmp(fields[2], spec->status_name) != 0) {
      corpus_fail(path, line_number, "unexpected symbolic status");
    }
    int named_status = obi_test_named_status(spec->status_name);
    int expected_status = parse_corpus_status(path, line_number, fields[3]);
    if (named_status < 0 || expected_status != named_status) {
      corpus_fail(path, line_number, "symbolic and numeric status differ");
    }

    unsigned char response[corpus_wire_capacity] = {0};
    size_t response_length =
        decode_corpus_wire(path, line_number, fields[4], response);
    assert_corpus_wire(path, line_number, spec, response, response_length);

    unsigned char original[corpus_wire_capacity];
    memcpy(original, response, sizeof(original));
    int actual_status = obi_test_response_status(response, response_length);
    if (actual_status != expected_status) {
      corpus_fail(path, line_number, "unexpected response status");
    }
    if (spec->accepted) {
      if (memcmp(response, original, response_length) != 0) {
        corpus_fail(path, line_number, "accepted record was modified");
      }
    } else {
      unsigned char normalized[64];
      obi_test_status_response(normalized, expected_status);
      if (memcmp(response, normalized, sizeof(normalized)) != 0) {
        corpus_fail(path, line_number, "rejected record was not normalized");
      }
    }
    vector_count++;
  }

  if (ferror(file)) {
    corpus_fail(path, line_number, "error reading corpus");
  }
  if (fclose(file) != 0) {
    corpus_fail(path, line_number, "error closing corpus");
  }
  if (stage != 2 ||
      vector_count != sizeof(corpus_specs) / sizeof(corpus_specs[0])) {
    corpus_fail(path, line_number,
                "corpus format, header, or vectors are missing");
  }
  for (size_t index = 0; index < sizeof(seen) / sizeof(seen[0]); index++) {
    if (!seen[index]) {
      corpus_fail(path, line_number, "required vector is missing");
    }
  }
}

static void test_status_response(void) {
  unsigned char response[64];
  memset(response, 0xff, sizeof(response));
  obi_test_status_response(response, 10);

  assert(memcmp(response, "OBIJ", 4) == 0);
  assert(read_u16_le(response, 4) == 1);
  assert(read_u16_le(response, 6) == 64);
  assert(response[8] == 10);
  for (size_t i = 9; i < sizeof(response); i++) {
    assert(response[i] == 0);
  }
  assert(obi_test_response_status(response, sizeof(response)) == 10);
}

static void init_valid_response(unsigned char *response) {
  obi_test_status_response(response, 1);
  response[9] = 0xff;
  response[16] = 1;
  response[32] = 1;
  response[40] = 1;
  response[48] = 1;
}

static void test_response_validation(void) {
  unsigned char response[64];
  obi_test_status_response(response, 1);
  assert(obi_test_response_status(response, 63) == 5);

  obi_test_status_response(response, 1);
  response[0] = 'X';
  assert(obi_test_response_status(response, sizeof(response)) == 5);

  obi_test_status_response(response, 1);
  response[4] = 2;
  assert(obi_test_response_status(response, sizeof(response)) == 6);

  obi_test_status_response(response, 2);
  response[10] = 1;
  assert(obi_test_response_status(response, sizeof(response)) == 5);

  obi_test_status_response(response, 2);
  response[8] = 255;
  assert(obi_test_response_status(response, sizeof(response)) == 5);

  obi_test_status_response(response, 0);
  assert(obi_test_response_status(response, sizeof(response)) == 5);

  obi_test_status_response(response, 1);
  assert(obi_test_response_status(response, sizeof(response)) == 5);

  init_valid_response(response);
  assert(obi_test_response_status(response, sizeof(response)) == 1);

  init_valid_response(response);
  memset(response + 16, 0, 16);
  assert(obi_test_response_status(response, sizeof(response)) == 5);

  init_valid_response(response);
  memset(response + 32, 0, 8);
  assert(obi_test_response_status(response, sizeof(response)) == 5);

  init_valid_response(response);
  response[40] = 0;
  assert(obi_test_response_status(response, sizeof(response)) == 5);

  init_valid_response(response);
  response[48] = 0;
  assert(obi_test_response_status(response, sizeof(response)) == 5);
}

static void test_request_vector(void) {
  unsigned char request[24];
  memset(request, 0xff, sizeof(request));
  obi_test_build_unix_request(request, 2, 0x12345678,
                              UINT64_C(0x0102030405060708));

  assert(memcmp(request, "OBIQ", 4) == 0);
  assert(read_u16_le(request, 4) == 3);
  assert(read_u16_le(request, 6) == 24);
  assert(request[8] == 2);
  assert(request[9] == 1 && request[10] == 0 && request[11] == 0);
  assert(read_u32_le(request, 12) == 0x12345678);
  assert(read_u64_le(request, 16) == UINT64_C(0x0102030405060708));
}

static void test_task_context_packet_vectors(void) {
  unsigned char packet[17];
  memset(packet, 0xff, sizeof(packet));
  obi_test_build_task_context_packet(packet, 6, UINT64_C(0x0102030405060708),
                                     0);
  assert(packet[0] == 6);
  assert(read_u64_le(packet, 1) == UINT64_C(0x0102030405060708));
  assert(read_u64_le(packet, 9) == 0);

  obi_test_build_task_context_packet(packet, 8, UINT64_C(0x1112131415161718),
                                     UINT64_C(0x2122232425262728));
  assert(packet[0] == 8);
  assert(read_u64_le(packet, 1) == UINT64_C(0x1112131415161718));
  assert(read_u64_le(packet, 9) == UINT64_C(0x2122232425262728));

  obi_test_build_task_context_packet(packet, 9, UINT64_C(0x3132333435363738),
                                     0);
  assert(packet[0] == 9);
  assert(read_u64_le(packet, 1) == UINT64_C(0x3132333435363738));
  assert(read_u64_le(packet, 9) == 0);

  memset(packet, 0xff, sizeof(packet));
  obi_test_build_task_context_packet(packet, 12, 0, 0);
  assert(packet[0] == 12);
  assert(read_u64_le(packet, 1) == 0);
  assert(read_u64_le(packet, 9) == 0);
}

static void test_errno_mapping(void) {
  assert(obi_test_errno_status(EACCES) == 8);
  assert(obi_test_errno_status(ETIMEDOUT) == 10);
  assert(obi_test_errno_status(ENOMEM) == 11);
  assert(obi_test_errno_status(ENOPROTOOPT) == 4);
  assert(obi_test_errno_status(EIO) == 12);
}

static void test_probe_status(void) {
  assert(!obi_test_probe_succeeded(1));
  assert(obi_test_probe_succeeded(2));
  assert(!obi_test_probe_succeeded(4));
  assert(!obi_test_probe_succeeded(5));
  assert(!obi_test_probe_succeeded(6));
  assert(!obi_test_probe_succeeded(12));
}

static void test_timeout_validation(void) {
  assert(!obi_test_timeout_valid(0));
  assert(obi_test_timeout_valid(1));
  assert(obi_test_timeout_valid(1500));
  assert(obi_test_timeout_valid(INT32_MAX));
}

static void test_peer_credentials(void) {
  uid_t current_uid = geteuid();
  uid_t foreign_uid = current_uid == 0 ? 1 : current_uid + 1;

  assert(obi_test_peer_credentials_allowed(0, current_uid, current_uid));
  assert(obi_test_peer_credentials_allowed(123, current_uid, current_uid));
  assert(obi_test_peer_credentials_allowed(0, 0, 0));
  assert(!obi_test_peer_credentials_allowed(0, foreign_uid, current_uid));
  assert(!obi_test_peer_credentials_allowed(0, current_uid, foreign_uid));
}

static void test_configuration_result_layout(void) {
  fake_setsockopt_error = 0;
  fake_health_error = 0;
  fake_health_mismatch = 0;
  reset_transport_observations();

  uint64_t result =
      obi_test_configure_remote_parent_v2(0, "", 50, geteuid(), 1);
  assert(result == UINT64_C(0x4f02000101010001));
  assert(atomic_load(&observed_setsockopt_calls) == 1);
  assert(atomic_load(&observed_getsockopt_calls) == 1);
  obi_test_close_remote_parent();

  fake_setsockopt_error = EACCES;
  result = obi_test_configure_remote_parent_v2(1, "", 50, geteuid(), 1);
  assert(result == UINT64_C(0x4f02000801ff0108));
  fake_setsockopt_error = 0;

  result = obi_test_configure_remote_parent_v2(3, "", 50, geteuid(), 1);
  assert(result == UINT64_C(0x4f0200000003030d));

  result = obi_test_configure_remote_parent_v2(4, "", 50, geteuid(), 1);
  assert(result == UINT64_C(0x4f02000000ffff04));

  char overlong_path[sizeof(((struct sockaddr_un *)0)->sun_path) + 1];
  memset(overlong_path, 'x', sizeof(overlong_path) - 1);
  overlong_path[sizeof(overlong_path) - 1] = '\0';
  assert(obi_test_configure_remote_parent(4, "", 50, geteuid(), 1) == 4);
  assert(obi_test_configure_remote_parent(4, overlong_path, 50, geteuid(), 1) ==
         5);

  assert(obi_test_lock_remote_parent() == 0);
  result = obi_test_configure_remote_parent_v2(1, "", 1, geteuid(), 1);
  assert(result == UINT64_C(0x4f02000101ff010a));
  assert(obi_test_unlock_remote_parent() == 0);
  obi_test_close_remote_parent();
}

static void test_sockopt_negotiate_and_health_probe(void) {
  fake_setsockopt_error = 0;
  fake_health_error = 0;
  fake_health_mismatch = 0;
  reset_transport_observations();

  assert(obi_test_configure_remote_parent(1, "", 50, geteuid(), 1) == 1);
  assert(atomic_load(&observed_setsockopt_level) == 0x4f42);
  assert(atomic_load(&observed_setsockopt_option) == 0x4a03);
  assert(atomic_load(&observed_negotiate_incarnation) == 1);
  assert(atomic_load(&observed_getsockopt_level) == 0x4f42);
  assert(atomic_load(&observed_getsockopt_option) == 0x4a05);
  assert(atomic_load(&observed_getsockopt_calls) == 1);
  obi_test_close_remote_parent();
}

static void test_forced_setsockopt_preserves_failure(void) {
  fake_setsockopt_error = EACCES;

  assert(obi_test_configure_remote_parent(1, "", 50, geteuid(), 1) == 8);
  assert(atomic_load(&observed_setsockopt_option) == 0x4a03);
  obi_test_close_remote_parent();
  fake_setsockopt_error = 0;
}

static void test_forced_getsockopt_health_preserves_failure(void) {
  fake_setsockopt_error = 0;
  fake_health_error = EACCES;

  assert(obi_test_configure_remote_parent(1, "", 50, geteuid(), 2) == 8);
  assert(atomic_load(&observed_getsockopt_option) == 0x4a05);
  obi_test_close_remote_parent();

  fake_health_error = 0;
  fake_health_mismatch = 1;
  assert(obi_test_configure_remote_parent(1, "", 50, geteuid(), 2) == 5);
  obi_test_close_remote_parent();
  fake_health_mismatch = 0;
}

static void test_short_non_data_ioctl_packets_skip_nonce_snapshot(void) {
  fake_ioctl_error = 0;
  reset_transport_observations();

  assert(Java_io_opentelemetry_obi_java_BootstrapNative_emitVirtualThreadOp(
             NULL, NULL, 9, (jlong)UINT64_C(0x0102030405060708)) == 0);
  assert(atomic_load(&observed_ioctl_fd) == 0);
  assert(atomic_load(&observed_ioctl_request) == 0x0b10b1);
  assert(atomic_load(&observed_ioctl_calls) == 1);
  assert(atomic_load(&observed_ioctl_nonce) == 0);

  reset_transport_observations();
  assert(Java_io_opentelemetry_obi_java_BootstrapNative_emitTaskContextOp(
             NULL, NULL, 12, (jlong)UINT64_C(0x1112131415161718),
             (jlong)UINT64_C(0x2122232425262728)) == 0);
  assert(atomic_load(&observed_ioctl_fd) == 0);
  assert(atomic_load(&observed_ioctl_request) == 0x0b10b1);
  assert(atomic_load(&observed_ioctl_calls) == 1);
  assert(atomic_load(&observed_ioctl_nonce) == 0);

  fake_ioctl_error = ENOTTY;
}

static void test_acknowledged_data_operations_preserve_transport_order(void) {
  fake_setsockopt_error = 0;
  fake_data_ack_error = 0;
  fake_ioctl_error = ENOTTY;
  assert(obi_test_configure_remote_parent(1, "", 50, geteuid(), 77) == 1);

  const unsigned char operations[] = {
      test_data_operation_send,
      test_data_operation_receive,
      test_data_operation_http1_receive_start,
      test_data_operation_unknown,
  };
  for (size_t index = 0; index < sizeof(operations) / sizeof(operations[0]);
       index++) {
    reset_transport_observations();

    unsigned char packet[65] = {0};
    packet[0] = operations[index];
    memset(packet + test_data_signal_offset, 0xff, sizeof(uint64_t));
    int socket_fd = 55 + (int)index;
    assert(obi_test_emit_data_on_socket(socket_fd, packet) == 1);
    uint64_t nonce = read_u64_le(packet, test_data_signal_offset);
    assert(nonce != 0);
    assert(atomic_load(&observed_negotiate_incarnation) == 77);
    assert(atomic_load(&observed_setsockopt_fd) == socket_fd);
    assert(atomic_load(&observed_setsockopt_option) == 0x4a04);
    assert(atomic_load(&observed_setsockopt_calls) == 2);
    assert(atomic_load(&observed_ioctl_fd) == socket_fd);
    assert(atomic_load(&observed_ioctl_request) == 0x0b10b1);
    assert(atomic_load(&observed_ioctl_calls) == 1);
    if (operations[index] != test_data_operation_unknown) {
      assert(atomic_load(&observed_ioctl_nonce) == nonce);
    }
    assert(atomic_load(&observed_getsockopt_calls) == 0);
    assert(obi_test_remote_parent_config_acquisition_count() == 1);
    assert(atomic_load(&observed_data_ack_nonce) == nonce);
    assert(atomic_load(&observed_transport_event_count) == 3);
    assert(observed_transport_events[0] == 1);
    assert(observed_transport_events[1] == 2);
    assert(observed_transport_events[2] == 3);
  }
  obi_test_close_remote_parent();
}

static void test_http1_start_hard_ioctl_error_skips_acknowledgement(void) {
  fake_setsockopt_error = 0;
  fake_data_ack_error = 0;
  fake_ioctl_error = EIO;
  assert(obi_test_configure_remote_parent(1, "", 50, geteuid(), 81) == 1);
  reset_transport_observations();

  unsigned char packet[65] = {0};
  packet[0] = test_data_operation_http1_receive_start;
  memset(packet + test_data_signal_offset, 0xff, sizeof(uint64_t));
  assert(obi_test_emit_data_on_socket(59, packet) == -1);

  uint64_t nonce = read_u64_le(packet, test_data_signal_offset);
  assert(nonce != 0);
  assert(atomic_load(&observed_negotiate_incarnation) == 81);
  assert(atomic_load(&observed_setsockopt_fd) == 59);
  assert(atomic_load(&observed_setsockopt_option) == 0x4a03);
  assert(atomic_load(&observed_setsockopt_calls) == 1);
  assert(atomic_load(&observed_getsockopt_calls) == 0);
  assert(obi_test_remote_parent_config_acquisition_count() == 1);
  assert(atomic_load(&observed_ioctl_fd) == 59);
  assert(atomic_load(&observed_ioctl_request) == 0x0b10b1);
  assert(atomic_load(&observed_ioctl_calls) == 1);
  assert(atomic_load(&observed_ioctl_nonce) == nonce);
  assert(atomic_load(&observed_data_ack_nonce) == 0);
  assert(atomic_load(&observed_transport_event_count) == 2);
  assert(observed_transport_events[0] == 1);
  assert(observed_transport_events[1] == 2);
  assert(observed_transport_events[2] == 0);

  obi_test_close_remote_parent();
  fake_ioctl_error = ENOTTY;
}

static void test_http1_continue_and_reset_issue_only_ioctl(void) {
  fake_setsockopt_error = 0;
  fake_data_ack_error = ENOPROTOOPT;
  assert(obi_test_configure_remote_parent(1, "", 50, geteuid(), 82) == 1);

  const unsigned char operations[] = {
      test_data_operation_http1_receive_continue,
      test_data_operation_http1_receive_reset,
  };
  const int ioctl_errors[] = {ENOTTY, EIO};
  for (size_t operation_index = 0;
       operation_index < sizeof(operations) / sizeof(operations[0]);
       operation_index++) {
    for (size_t error_index = 0;
         error_index < sizeof(ioctl_errors) / sizeof(ioctl_errors[0]);
         error_index++) {
      reset_transport_observations();
      fake_ioctl_error = ioctl_errors[error_index];

      unsigned char packet[65] = {0};
      packet[0] = operations[operation_index];
      memset(packet + test_data_signal_offset, 0xff, sizeof(uint64_t));
      int socket_fd = 60 + (int)operation_index;
      int expected_result = fake_ioctl_error == ENOTTY ? 0 : -1;
      assert(obi_test_emit_data_on_socket(socket_fd, packet) == expected_result);
      assert(read_u64_le(packet, test_data_signal_offset) == 0);
      assert(atomic_load(&observed_setsockopt_calls) == 0);
      assert(atomic_load(&observed_getsockopt_calls) == 0);
      assert(atomic_load(&observed_data_ack_nonce) == 0);
      assert(obi_test_remote_parent_config_acquisition_count() == 0);
      assert(atomic_load(&observed_ioctl_fd) == socket_fd);
      assert(atomic_load(&observed_ioctl_request) == 0x0b10b1);
      assert(atomic_load(&observed_ioctl_calls) == 1);
      assert(atomic_load(&observed_ioctl_nonce) == 0);
      assert(atomic_load(&observed_transport_event_count) == 1);
      assert(observed_transport_events[0] == 2);
      assert(observed_transport_events[1] == 0);
      assert(observed_transport_events[2] == 0);
    }
  }

  obi_test_close_remote_parent();
  fake_data_ack_error = 0;
  fake_ioctl_error = ENOTTY;
}

static void test_data_emit_rejects_missing_acknowledgement(void) {
  fake_setsockopt_error = 0;
  fake_data_ack_error = ENOPROTOOPT;
  fake_ioctl_error = ENOTTY;
  assert(obi_test_configure_remote_parent(1, "", 50, geteuid(), 78) == 1);
  reset_transport_observations();

  unsigned char packet[50] = {2};
  assert(obi_test_emit_data_on_socket(56, packet) == 0);
  assert(read_u64_le(packet, 41) != 0);
  assert(atomic_load(&observed_setsockopt_calls) == 2);
  assert(atomic_load(&observed_ioctl_calls) == 1);
  assert(atomic_load(&observed_setsockopt_option) == 0x4a04);
  assert(atomic_load(&observed_getsockopt_calls) == 0);
  obi_test_close_remote_parent();
  fake_data_ack_error = 0;
}

static void test_data_emit_falls_back_when_socket_negotiation_fails(void) {
  fake_setsockopt_error = 0;
  assert(obi_test_configure_remote_parent(1, "", 50, geteuid(), 79) == 1);
  reset_transport_observations();
  fake_setsockopt_error = EACCES;

  unsigned char packet[50] = {2};
  assert(obi_test_emit_data_on_socket(57, packet) == 0);
  assert(read_u64_le(packet, 41) != 0);
  assert(atomic_load(&observed_setsockopt_calls) == 1);
  assert(atomic_load(&observed_ioctl_fd) == 57);
  assert(atomic_load(&observed_ioctl_request) == 0x0b10b1);
  assert(atomic_load(&observed_ioctl_calls) == 1);
  assert(atomic_load(&observed_getsockopt_calls) == 0);
  obi_test_close_remote_parent();
  fake_setsockopt_error = 0;
}

static void test_retrieval_never_renegotiates_socket(void) {
  fake_setsockopt_error = 0;
  fake_getsockopt_status = 2;
  assert(obi_test_configure_remote_parent(1, "", 50, geteuid(), 80) == 1);
  reset_transport_observations();

  unsigned char response[64];
  assert(obi_test_call_remote_parent_on_socket(1, 58, response) == 2);
  assert(atomic_load(&observed_setsockopt_calls) == 0);
  assert(atomic_load(&observed_getsockopt_fd) == 58);
  assert(atomic_load(&observed_getsockopt_option) == 0x4a01);
  assert(atomic_load(&observed_getsockopt_calls) == 1);

  reset_transport_observations();
  assert(obi_test_call_remote_parent_task_on_socket(1, 58, response) == 2);
  assert(atomic_load(&observed_setsockopt_calls) == 0);
  assert(atomic_load(&observed_getsockopt_fd) == 58);
  assert(atomic_load(&observed_getsockopt_option) == 0x4a06);
  assert(atomic_load(&observed_getsockopt_calls) == 1);

  reset_transport_observations();
  assert(obi_test_call_remote_parent_task_on_socket(2, 58, response) == 2);
  assert(atomic_load(&observed_setsockopt_calls) == 0);
  assert(atomic_load(&observed_getsockopt_fd) == 58);
  assert(atomic_load(&observed_getsockopt_option) == 0x4a07);
  assert(atomic_load(&observed_getsockopt_calls) == 1);
  obi_test_close_remote_parent();
}

static void test_exported_jni_transport_lifecycle(void) {
  JNIEnv *env = fake_jni();
  struct fake_jni_string path = {.value = ""};
  struct fake_jni_byte_array response = {.length = 64};

  fake_setsockopt_error = 0;
  fake_getsockopt_status = 2;
  fake_getsockopt_length = 64;
  fake_getsockopt_bad_magic = 0;
  fake_jni_string_failure = 0;
  fake_jni_region_exception = 0;
  fake_jni_exception_pending = JNI_FALSE;
  fake_jni_exception_clears = 0;
  Java_io_opentelemetry_obi_java_BootstrapNative_closeRemoteParentTransport(
      env, NULL);

  assert(
      Java_io_opentelemetry_obi_java_BootstrapNative_configureRemoteParentTransport(
          env, NULL, 3, NULL, 20, geteuid(), 42) == 13);
  assert(Java_io_opentelemetry_obi_java_BootstrapNative_takeRemoteParent(
             env, NULL, -1, (jbyteArray)&response) == 13);

  assert(
      Java_io_opentelemetry_obi_java_BootstrapNative_configureRemoteParentTransport(
          env, NULL, 1, (jstring)&path, 20, geteuid(), 42) == 1);
  assert(path.releases == 1);

  assert(
      (uint64_t)
          Java_io_opentelemetry_obi_java_BootstrapNative_configureRemoteParentTransportV2(
              env, NULL, 0, (jstring)&path, 20, geteuid(), 42) ==
      UINT64_C(0x4f02000101010001));
  assert(path.releases == 2);

  fake_getsockopt_status = 1;
  memset(response.bytes, 0xff, sizeof(response.bytes));
  assert(Java_io_opentelemetry_obi_java_BootstrapNative_takeRemoteParent(
             env, NULL, 59, (jbyteArray)&response) == 1);
  assert(atomic_load(&observed_getsockopt_option) == 0x4a01);
  assert(memcmp(response.bytes, "OBIJ", 4) == 0);
  assert(response.bytes[8] == 1);
  assert(response.bytes[16] == 1);
  assert(response.bytes[32] == 1);
  assert(response.bytes[40] == 1);
  assert(response.bytes[48] == 1);

  fake_getsockopt_status = 2;
  assert(Java_io_opentelemetry_obi_java_BootstrapNative_takeRemoteParent(
             env, NULL, 59, (jbyteArray)&response) == 2);
  assert(response.bytes[8] == 2);

  for (int status = 2; status <= 13; status++) {
    fake_getsockopt_status = status;
    assert(Java_io_opentelemetry_obi_java_BootstrapNative_takeRemoteParent(
               env, NULL, 59, (jbyteArray)&response) == status);
    assert(response.bytes[8] == status);
  }

  fake_getsockopt_status = 3;
  assert(Java_io_opentelemetry_obi_java_BootstrapNative_discardRemoteParent(
             env, NULL, 59, (jbyteArray)&response) == 3);
  assert(atomic_load(&observed_getsockopt_option) == 0x4a02);
  assert(response.bytes[8] == 3);

  fake_getsockopt_status = 1;
  assert(Java_io_opentelemetry_obi_java_BootstrapNative_takeRemoteParentTask(
             env, NULL, 59, (jbyteArray)&response) == 1);
  assert(atomic_load(&observed_getsockopt_option) == 0x4a06);
  assert(response.bytes[8] == 1);

  fake_getsockopt_status = 3;
  assert(Java_io_opentelemetry_obi_java_BootstrapNative_discardRemoteParentTask(
             env, NULL, 59, (jbyteArray)&response) == 3);
  assert(atomic_load(&observed_getsockopt_option) == 0x4a07);
  assert(response.bytes[8] == 3);

  fake_getsockopt_status = 2;
  fake_getsockopt_bad_magic = 1;
  assert(Java_io_opentelemetry_obi_java_BootstrapNative_takeRemoteParent(
             env, NULL, 59, (jbyteArray)&response) == 5);
  assert(memcmp(response.bytes, "OBIJ", 4) == 0);
  assert(response.bytes[8] == 5);
  fake_getsockopt_bad_magic = 0;

  fake_getsockopt_length = 63;
  assert(Java_io_opentelemetry_obi_java_BootstrapNative_takeRemoteParent(
             env, NULL, 59, (jbyteArray)&response) == 5);
  assert(response.bytes[8] == 5);
  fake_getsockopt_length = 64;

  struct fake_jni_byte_array short_response = {.length = 63};
  atomic_store(&observed_getsockopt_option, 0);
  assert(Java_io_opentelemetry_obi_java_BootstrapNative_takeRemoteParent(
             env, NULL, 59, (jbyteArray)&short_response) == 5);
  assert(atomic_load(&observed_getsockopt_option) == 0);
  assert(Java_io_opentelemetry_obi_java_BootstrapNative_takeRemoteParent(
             env, NULL, 59, NULL) == 5);

  fake_jni_region_exception = 1;
  assert(Java_io_opentelemetry_obi_java_BootstrapNative_takeRemoteParent(
             env, NULL, 59, (jbyteArray)&response) == 12);
  fake_jni_region_exception = 0;
  assert(fake_jni_exception_pending == JNI_FALSE);
  assert(fake_jni_exception_clears == 1);

  Java_io_opentelemetry_obi_java_BootstrapNative_closeRemoteParentTransport(
      env, NULL);
  assert(Java_io_opentelemetry_obi_java_BootstrapNative_takeRemoteParent(
             env, NULL, -1, (jbyteArray)&response) == 13);
  assert(response.bytes[8] == 13);
}

static void test_exported_jni_configuration_validation(void) {
  JNIEnv *env = fake_jni();
  struct fake_jni_string path = {.value = ""};

  fake_jni_exception_pending = JNI_FALSE;
  fake_jni_exception_clears = 0;

  assert(
      Java_io_opentelemetry_obi_java_BootstrapNative_configureRemoteParentTransport(
          env, NULL, 1, (jstring)&path, 0, geteuid(), 1) == 5);
  assert(
      Java_io_opentelemetry_obi_java_BootstrapNative_configureRemoteParentTransport(
          env, NULL, 1, (jstring)&path, 20, -1, 1) == 5);
  assert(
      Java_io_opentelemetry_obi_java_BootstrapNative_configureRemoteParentTransport(
          env, NULL, 1, (jstring)&path, 20, (jlong)UINT32_MAX + 1, 1) == 5);
  assert(
      Java_io_opentelemetry_obi_java_BootstrapNative_configureRemoteParentTransport(
          env, NULL, 1, (jstring)&path, 20, geteuid(), 0) == 5);
  assert(path.releases == 0);

  fake_jni_string_failure = 1;
  assert(
      Java_io_opentelemetry_obi_java_BootstrapNative_configureRemoteParentTransport(
          env, NULL, 1, (jstring)&path, 20, geteuid(), 1) == 12);
  fake_jni_string_failure = 0;
  assert(path.releases == 0);
  assert(fake_jni_exception_pending == JNI_FALSE);
  assert(fake_jni_exception_clears == 1);

  fake_setsockopt_error = EACCES;
  assert(
      Java_io_opentelemetry_obi_java_BootstrapNative_configureRemoteParentTransport(
          env, NULL, 1, NULL, 20, geteuid(), 1) == 8);
  fake_setsockopt_error = 0;

  Java_io_opentelemetry_obi_java_BootstrapNative_closeRemoteParentTransport(
      env, NULL);
}

struct trickle_server {
  int listener;
  _Atomic int accepted;
  _Atomic int result;
  char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
};

enum {
  test_remote_parent_transport_unix = 2,
  test_remote_parent_request_version = 3,
  test_remote_parent_request_size = 24,
  test_remote_parent_operation_take = 1,
  test_remote_parent_operation_negotiate = 3,
  test_remote_parent_source_direct = 1,
  test_remote_parent_source_task = 2,
  test_remote_parent_status_valid = 1,
  test_remote_parent_status_missing = 2,
  test_remote_parent_status_unauthorized = 8,
  test_remote_parent_timeout_millis = 100,
  test_unix_server_timeout_millis = 1000,
  test_remote_parent_process_incarnation = 1,
  test_unix_server_success = 1,
  test_unix_server_timeout = 2,
  test_unix_server_io_error = 3,
  test_unix_server_protocol_error = 4,
};

static void start_unix_test_server(struct trickle_server *server,
                                   const char *name) {
  snprintf(server->path, sizeof(server->path), "/tmp/obi-jni-%s-%ld.sock", name,
           (long)getpid());
  unlink(server->path);

  server->listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  assert(server->listener >= 0);
  struct sockaddr_un address = {.sun_family = AF_UNIX};
  memcpy(address.sun_path, server->path, strlen(server->path) + 1);
  assert(bind(server->listener, (struct sockaddr *)&address, sizeof(address)) ==
         0);
  assert(listen(server->listener, 1) == 0);
}

static void *run_probe_server(void *argument) {
  struct trickle_server *server = argument;
  int client = accept(server->listener, NULL, NULL);
  assert(client >= 0);

  unsigned char request[24];
  size_t received = 0;
  while (received < sizeof(request)) {
    ssize_t count =
        recv(client, request + received, sizeof(request) - received, 0);
    assert(count > 0);
    received += (size_t)count;
  }

  unsigned char response[64];
  obi_test_status_response(response, 2);
  assert(send(client, response, sizeof(response), MSG_NOSIGNAL) ==
         (ssize_t)sizeof(response));

  close(client);
  close(server->listener);
  unlink(server->path);
  return NULL;
}

static int wait_for_unix_test_fd(int fd, short events, int64_t deadline) {
  for (;;) {
    int64_t remaining = deadline - test_monotonic_millis();
    if (remaining <= 0) {
      return 0;
    }

    struct pollfd descriptor = {.fd = fd, .events = events};
    int result = poll(&descriptor, 1, (int)remaining);
    if (result == 0) {
      return 0;
    }
    if (result < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if ((descriptor.revents & events) != 0) {
      return 1;
    }
    return -1;
  }
}

static int receive_unix_test_request(int fd, unsigned char *request,
                                     int64_t deadline) {
  size_t received = 0;
  while (received < test_remote_parent_request_size) {
    int ready = wait_for_unix_test_fd(fd, POLLIN, deadline);
    if (ready != 1) {
      return ready;
    }

    ssize_t count = recv(fd, request + received,
                         test_remote_parent_request_size - received, 0);
    if (count > 0) {
      received += (size_t)count;
      continue;
    }
    if (count == 0) {
      return -1;
    }
    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
      continue;
    }
    return -1;
  }
  return 1;
}

static void *run_missing_then_unauthorized_server(void *argument) {
  struct trickle_server *server = argument;
  const int operations[] = {test_remote_parent_operation_negotiate,
                            test_remote_parent_operation_take};
  const int sources[] = {test_remote_parent_source_direct,
                         test_remote_parent_source_task};
  const int statuses[] = {test_remote_parent_status_missing,
                          test_remote_parent_status_unauthorized};
  int result = test_unix_server_success;
  int64_t deadline = test_monotonic_millis() + test_unix_server_timeout_millis;

  for (size_t index = 0; index < sizeof(operations) / sizeof(operations[0]);
       index++) {
    int client = -1;
    while (client < 0) {
      int ready = wait_for_unix_test_fd(server->listener, POLLIN, deadline);
      if (ready != 1) {
        result =
            ready == 0 ? test_unix_server_timeout : test_unix_server_io_error;
        goto done;
      }
      client =
          accept4(server->listener, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
      if (client < 0 && errno != EINTR && errno != EAGAIN &&
          errno != EWOULDBLOCK) {
        result = test_unix_server_io_error;
        goto done;
      }
    }

    unsigned char request[test_remote_parent_request_size];
    int received = receive_unix_test_request(client, request, deadline);
    if (received != 1) {
      close(client);
      result =
          received == 0 ? test_unix_server_timeout : test_unix_server_io_error;
      goto done;
    }
    if (memcmp(request, "OBIQ", 4) != 0 ||
        read_u16_le(request, 4) != test_remote_parent_request_version ||
        read_u16_le(request, 6) != sizeof(request) ||
        request[8] != operations[index] || request[9] != sources[index] ||
        request[10] != 0 || request[11] != 0) {
      close(client);
      result = test_unix_server_protocol_error;
      goto done;
    }

    unsigned char response[64];
    obi_test_status_response(response, statuses[index]);
    if (send(client, response, sizeof(response), MSG_NOSIGNAL) !=
        (ssize_t)sizeof(response)) {
      close(client);
      result = test_unix_server_io_error;
      goto done;
    }
    close(client);
  }

done:
  close(server->listener);
  unlink(server->path);
  atomic_store(&server->result, result);
  return NULL;
}

static void test_configuration_result_auto_fallback(void) {
  struct trickle_server server = {0};
  start_unix_test_server(&server, "fallback");

  fake_setsockopt_error = ENOPROTOOPT;
  pthread_t thread;
  assert(pthread_create(&thread, NULL, run_probe_server, &server) == 0);
  uint64_t result =
      obi_test_configure_remote_parent_v2(0, server.path, 50, geteuid(), 1);
  assert(result == UINT64_C(0x4f02010403020001));
  assert(pthread_join(thread, NULL) == 0);
  fake_setsockopt_error = 0;
  obi_test_close_remote_parent();
}

static void *run_trickle_server(void *argument) {
  struct trickle_server *server = argument;
  int client = accept(server->listener, NULL, NULL);
  assert(client >= 0);
  atomic_store_explicit(&server->accepted, 1, memory_order_release);

  unsigned char request[24];
  size_t received = 0;
  while (received < sizeof(request)) {
    ssize_t count =
        recv(client, request + received, sizeof(request) - received, 0);
    assert(count > 0);
    received += (size_t)count;
  }

  unsigned char response[64];
  memset(response, 0, sizeof(response));
  memcpy(response, "OBIJ", 4);
  response[4] = 1;
  response[6] = 64;
  response[8] = 2;
  struct timespec pause = {.tv_sec = 0, .tv_nsec = 5 * 1000 * 1000};
  for (size_t i = 0; i < sizeof(response); i++) {
    if (send(client, response + i, 1, MSG_NOSIGNAL) != 1) {
      break;
    }
    nanosleep(&pause, NULL);
  }

  close(client);
  close(server->listener);
  unlink(server->path);
  return NULL;
}

static void test_unix_trickle_response_obeys_deadline(void) {
  struct trickle_server server = {0};
  start_unix_test_server(&server, "trickle");

  pthread_t thread;
  assert(pthread_create(&thread, NULL, run_trickle_server, &server) == 0);
  assert(obi_test_configure_remote_parent(2, server.path, 20, geteuid(), 1) ==
         10);
  assert(pthread_join(thread, NULL) == 0);
  obi_test_close_remote_parent();
}

static void test_unix_transport_ignores_unrelated_duplicated_socket_fd(void) {
  struct trickle_server server = {0};
  start_unix_test_server(&server, "duplicate-fd");

  int unrelated[2];
  assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
                    unrelated) == 0);
  int duplicate = fcntl(unrelated[0], F_DUPFD_CLOEXEC, 0);
  assert(duplicate >= 0);
  assert(close(unrelated[0]) == 0);
  reset_transport_observations();
  deny_socket_fd(duplicate);
  int duplicate_alias = fcntl(duplicate, F_DUPFD_CLOEXEC, 0);
  assert(duplicate_alias >= 0);
  assert(socket_fd_is_denied(duplicate_alias));
  assert(close(duplicate_alias) == 0);

  pthread_t thread;
  assert(pthread_create(&thread, NULL, run_missing_then_unauthorized_server,
                        &server) == 0);
  assert(obi_test_configure_remote_parent(
             test_remote_parent_transport_unix, server.path,
             test_remote_parent_timeout_millis, geteuid(),
             test_remote_parent_process_incarnation) ==
         test_remote_parent_status_valid);

  unsigned char response[64];
  assert(obi_test_call_remote_parent_task_on_socket(
             test_remote_parent_operation_take, duplicate, response) ==
         test_remote_parent_status_unauthorized);
  assert(obi_test_response_status(response, sizeof(response)) ==
         test_remote_parent_status_unauthorized);
  assert(pthread_join(thread, NULL) == 0);
  assert(atomic_load(&server.result) == test_unix_server_success);
  assert(atomic_load(&observed_peer_credential_lookups) == 2);
  assert(atomic_load(&observed_denied_socket_getsockopt_lookups) == 0);
  clear_denied_socket_fd();

  unsigned char unexpected[24];
  assert(recv(unrelated[1], unexpected, sizeof(unexpected), MSG_DONTWAIT) ==
         -1);
  assert(errno == EAGAIN || errno == EWOULDBLOCK);

  assert(close(duplicate) == 0);
  assert(close(unrelated[1]) == 0);
  obi_test_close_remote_parent();
}

static void test_unix_server_first_failure_response(void) {
  int sockets[2];
  assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
                    sockets) == 0);

  unsigned char expected[64];
  obi_test_status_response(expected, 11);
  assert(send(sockets[1], expected, sizeof(expected), MSG_NOSIGNAL) ==
         (ssize_t)sizeof(expected));
  close(sockets[1]);

  unsigned char response[64];
  assert(obi_test_exchange_unix_request(sockets[0], response,
                                        test_monotonic_millis() + 100) == 11);
  assert(memcmp(response, expected, sizeof(response)) == 0);
  close(sockets[0]);
}

static void test_unix_server_first_valid_response_is_rejected(void) {
  int sockets[2];
  assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
                    sockets) == 0);

  unsigned char offered[64];
  obi_test_status_response(offered, 1);
  offered[16] = 1;
  offered[32] = 1;
  assert(send(sockets[1], offered, sizeof(offered), MSG_NOSIGNAL) ==
         (ssize_t)sizeof(offered));
  close(sockets[1]);

  unsigned char response[64];
  assert(obi_test_exchange_unix_request(sockets[0], response,
                                        test_monotonic_millis() + 100) == 5);
  unsigned char expected[64];
  obi_test_status_response(expected, 5);
  assert(memcmp(response, expected, sizeof(response)) == 0);
  close(sockets[0]);
}

static void test_unix_server_first_truncated_response_fails_closed(void) {
  int sockets[2];
  assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
                    sockets) == 0);

  unsigned char response[64];
  obi_test_status_response(response, 11);
  assert(send(sockets[1], response, sizeof(response) - 1, MSG_NOSIGNAL) ==
         (ssize_t)sizeof(response) - 1);
  close(sockets[1]);

  assert(obi_test_exchange_unix_request(sockets[0], response,
                                        test_monotonic_millis() + 100) == -1);
  assert(errno == EPROTO);
  close(sockets[0]);
}

static void test_unix_socket_owner_must_match_configured_uid(void) {
  char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
  snprintf(path, sizeof(path), "/tmp/obi-jni-owner-test-%ld.sock",
           (long)getpid());
  unlink(path);

  int listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  assert(listener >= 0);
  struct sockaddr_un address = {.sun_family = AF_UNIX};
  memcpy(address.sun_path, path, strlen(path) + 1);
  assert(bind(listener, (struct sockaddr *)&address, sizeof(address)) == 0);
  assert(listen(listener, 1) == 0);

  uid_t current_uid = geteuid();
  uid_t foreign_uid = current_uid == 0 ? 1 : current_uid + 1;
  assert(obi_test_configure_remote_parent(2, path, 20, foreign_uid, 1) == 8);

  close(listener);
  unlink(path);
  obi_test_close_remote_parent();
}

struct reconfigure_request {
  struct trickle_server *server;
  int status;
};

static void *run_reconfigure(void *argument) {
  struct reconfigure_request *request = argument;
  request->status = obi_test_configure_remote_parent(2, request->server->path,
                                                     200, geteuid(), 2);
  return NULL;
}

static int64_t test_monotonic_millis(void) {
  struct timespec now;
  assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
  return ((int64_t)now.tv_sec * 1000) + (now.tv_nsec / 1000000);
}

static int count_open_fds(void) {
  DIR *directory = opendir("/proc/self/fd");
  assert(directory != NULL);
  int count = 0;
  while (readdir(directory) != NULL) {
    count++;
  }
  assert(closedir(directory) == 0);
  return count;
}

static void test_reconfiguration_does_not_block_application_requests(void) {
  fake_setsockopt_error = 0;
  fake_getsockopt_status = 2;
  assert(obi_test_configure_remote_parent(1, "", 200, geteuid(), 1) == 1);

  struct trickle_server server = {0};
  snprintf(server.path, sizeof(server.path),
           "/tmp/obi-jni-reconfigure-test-%ld.sock", (long)getpid());
  unlink(server.path);
  server.listener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  assert(server.listener >= 0);
  struct sockaddr_un address = {.sun_family = AF_UNIX};
  memcpy(address.sun_path, server.path, strlen(server.path) + 1);
  assert(bind(server.listener, (struct sockaddr *)&address, sizeof(address)) ==
         0);
  assert(listen(server.listener, 1) == 0);

  pthread_t server_thread;
  assert(pthread_create(&server_thread, NULL, run_trickle_server, &server) ==
         0);
  struct reconfigure_request reconfigure = {.server = &server};
  pthread_t configure_thread;
  assert(pthread_create(&configure_thread, NULL, run_reconfigure,
                        &reconfigure) == 0);

  while (!atomic_load_explicit(&server.accepted, memory_order_acquire)) {
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000 * 1000};
    nanosleep(&pause, NULL);
  }

  unsigned char response[64];
  int64_t start = test_monotonic_millis();
  assert(obi_test_call_remote_parent(1, response) == 2);
  assert(test_monotonic_millis() - start < 100);

  assert(pthread_join(configure_thread, NULL) == 0);
  assert(reconfigure.status == 10);
  assert(pthread_join(server_thread, NULL) == 0);
  obi_test_close_remote_parent();
}

struct stress_worker {
  int operation;
  int iterations;
};

static void *run_transport_stress(void *argument) {
  const struct stress_worker *worker = argument;
  for (int iteration = 0; iteration < worker->iterations; iteration++) {
    if (worker->operation == 0) {
      int status = obi_test_configure_remote_parent(1, "", 50, geteuid(),
                                                    100 + iteration);
      assert(status == 1 || status == 10 || status == 11);
    } else if (worker->operation == 1) {
      unsigned char response[64];
      int status = obi_test_call_remote_parent(1, response);
      assert(status == 2 || status == 10 || status == 11 || status == 13);
    } else {
      obi_test_close_remote_parent();
    }
  }
  return NULL;
}

static void test_concurrent_configure_call_and_close_are_memory_safe(void) {
  enum { worker_count = 8, iterations = 500 };
  fake_setsockopt_error = 0;
  fake_getsockopt_status = 2;
  pthread_t threads[worker_count];
  struct stress_worker workers[worker_count];
  for (int index = 0; index < worker_count; index++) {
    workers[index].operation = index % 3;
    workers[index].iterations = iterations;
    assert(pthread_create(&threads[index], NULL, run_transport_stress,
                          &workers[index]) == 0);
  }
  for (int index = 0; index < worker_count; index++) {
    assert(pthread_join(threads[index], NULL) == 0);
  }
  obi_test_close_remote_parent();
  unsigned char response[64];
  assert(obi_test_call_remote_parent(1, response) == 13);
}

struct close_contention {
  _Atomic int locked;
};

static void *hold_remote_parent_lock(void *argument) {
  struct close_contention *contention = argument;
  assert(obi_test_lock_remote_parent() == 0);
  atomic_store_explicit(&contention->locked, 1, memory_order_release);
  struct timespec pause = {.tv_sec = 0, .tv_nsec = 20 * 1000 * 1000};
  nanosleep(&pause, NULL);
  assert(obi_test_unlock_remote_parent() == 0);
  return NULL;
}

struct emit_contention {
  _Atomic int locked;
  _Atomic int release;
};

static void *hold_remote_parent_lock_for_emit(void *argument) {
  struct emit_contention *contention = argument;
  assert(obi_test_lock_remote_parent() == 0);
  atomic_store_explicit(&contention->locked, 1, memory_order_release);
  while (!atomic_load_explicit(&contention->release, memory_order_acquire)) {
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000 * 1000};
    nanosleep(&pause, NULL);
  }
  assert(obi_test_unlock_remote_parent() == 0);
  return NULL;
}

static void test_data_emit_falls_back_on_config_contention(void) {
  fake_setsockopt_error = 0;
  assert(obi_test_configure_remote_parent(1, "", 1, geteuid(), 81) == 1);

  struct emit_contention contention = {0};
  pthread_t holder;
  assert(pthread_create(&holder, NULL, hold_remote_parent_lock_for_emit,
                        &contention) == 0);
  while (!atomic_load_explicit(&contention.locked, memory_order_acquire)) {
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000 * 1000};
    nanosleep(&pause, NULL);
  }

  reset_transport_observations();
  unsigned char packet[50] = {2};
  assert(obi_test_emit_data_on_socket(59, packet) == 0);
  assert(read_u64_le(packet, 41) != 0);
  assert(atomic_load(&observed_setsockopt_calls) == 0);
  assert(atomic_load(&observed_ioctl_fd) == 59);
  assert(atomic_load(&observed_ioctl_request) == 0x0b10b1);
  assert(atomic_load(&observed_ioctl_calls) == 1);

  atomic_store_explicit(&contention.release, 1, memory_order_release);
  assert(pthread_join(holder, NULL) == 0);
  obi_test_close_remote_parent();
}

static void test_final_close_waits_for_contention_and_releases_resources(void) {
  int baseline_fds = count_open_fds();
  fake_setsockopt_error = 0;
  fake_getsockopt_status = 2;
  assert(obi_test_configure_remote_parent(1, "", 1, geteuid(), 1) == 1);
  assert(count_open_fds() == baseline_fds + 2);

  struct close_contention contention = {0};
  pthread_t holder;
  assert(pthread_create(&holder, NULL, hold_remote_parent_lock, &contention) ==
         0);
  while (!atomic_load_explicit(&contention.locked, memory_order_acquire)) {
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 1000 * 1000};
    nanosleep(&pause, NULL);
  }

  obi_test_close_remote_parent();
  assert(pthread_join(holder, NULL) == 0);
  unsigned char response[64];
  assert(obi_test_call_remote_parent(1, response) == 13);
  assert(count_open_fds() == baseline_fds);
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s CORPUS\n", argv[0]);
    return 1;
  }
  test_remote_parent_corpus(argv[1]);
  test_status_response();
  test_response_validation();
  test_request_vector();
  test_task_context_packet_vectors();
  test_errno_mapping();
  test_probe_status();
  test_timeout_validation();
  test_peer_credentials();
  test_configuration_result_layout();
  test_sockopt_negotiate_and_health_probe();
  test_forced_setsockopt_preserves_failure();
  test_forced_getsockopt_health_preserves_failure();
  test_short_non_data_ioctl_packets_skip_nonce_snapshot();
  test_acknowledged_data_operations_preserve_transport_order();
  test_http1_start_hard_ioctl_error_skips_acknowledgement();
  test_http1_continue_and_reset_issue_only_ioctl();
  test_data_emit_rejects_missing_acknowledgement();
  test_data_emit_falls_back_when_socket_negotiation_fails();
  test_retrieval_never_renegotiates_socket();
  test_exported_jni_transport_lifecycle();
  test_exported_jni_configuration_validation();
  test_configuration_result_auto_fallback();
  test_unix_trickle_response_obeys_deadline();
  test_unix_transport_ignores_unrelated_duplicated_socket_fd();
  test_unix_server_first_failure_response();
  test_unix_server_first_valid_response_is_rejected();
  test_unix_server_first_truncated_response_fails_closed();
  test_unix_socket_owner_must_match_configured_uid();
  test_reconfiguration_does_not_block_application_requests();
  test_concurrent_configure_call_and_close_are_memory_safe();
  test_data_emit_falls_back_on_config_contention();
  test_final_close_waits_for_contention_and_releases_resources();
  return 0;
}
