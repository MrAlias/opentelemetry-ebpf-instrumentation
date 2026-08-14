/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <linux/sockios.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef SO_COOKIE
#define SO_COOKIE 57
#endif

#ifndef SO_NETNS_COOKIE
#define SO_NETNS_COOKIE 71
#endif

#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U << 0)
#endif

#define DEFAULT_CONTROL_DIR "/run/obi-demo/pid-reuse"
#define DEFAULT_TARGET_PID 4242U
#define DEFAULT_SOCKET_FD 198
#define CONTROL_TIMEOUT_SECONDS 120
#define MAX_CONTROL_FILE_BYTES 4096
#define PREPARE_PHASE "PREPARE"
#define PREPARE_MARKER_NAME "prepare-ready"
#define PREPARE_MARKER_CONTENTS "prepare-ready-v1\n"

struct supervisor_config {
  const char *control_dir;
  uint32_t target_pid;
  int socket_fd;
  char **child_argv;
};

struct child_identity {
  uint64_t pid_namespace_inode;
  uint32_t pid;
  uint32_t tid;
  uint64_t start_time_ticks;
  uint64_t socket_cookie;
  uint64_t network_namespace_inode;
  uint64_t network_namespace_cookie;
  uint16_t local_port;
  uint16_t peer_port;
};

static volatile sig_atomic_t termination_signal;
static volatile sig_atomic_t active_child = -1;

static void fail_errno(const char *message) {
  const int saved_errno = errno;
  (void)fprintf(stderr, "pid-reuse supervisor: %s: %s\n", message,
                strerror(saved_errno));
  exit(EXIT_FAILURE);
}

static void fail_message(const char *message) {
  (void)fprintf(stderr, "pid-reuse supervisor: %s\n", message);
  exit(EXIT_FAILURE);
}

static bool parse_u32(const char *input, uint32_t *output) {
  char *end = NULL;
  unsigned long long parsed;

  if (input == NULL || input[0] == '\0' || input[0] == '-' || output == NULL) {
    return false;
  }
  errno = 0;
  parsed = strtoull(input, &end, 10);
  if (errno != 0 || end == input || *end != '\0' || parsed == 0 ||
      parsed > UINT32_MAX) {
    return false;
  }
  *output = (uint32_t)parsed;
  return true;
}

static bool parse_fd(const char *input, int *output) {
  uint32_t parsed;
  if (!parse_u32(input, &parsed) || parsed > INT32_MAX || parsed < 3) {
    return false;
  }
  *output = (int)parsed;
  return true;
}

static bool clean_absolute_path(const char *path) {
  const char *cursor;
  size_t length;

  if (path == NULL || path[0] != '/') {
    return false;
  }
  length = strlen(path);
  if (length == 0 || length >= PATH_MAX ||
      (length > 1 && path[length - 1] == '/')) {
    return false;
  }
  for (cursor = path; *cursor != '\0'; cursor++) {
    if (*cursor == '\n' || *cursor == '\r') {
      return false;
    }
    if (cursor[0] == '/' && cursor[1] == '/') {
      return false;
    }
    if (cursor[0] == '/' && cursor[1] == '.' &&
        (cursor[2] == '/' || cursor[2] == '\0' ||
         (cursor[2] == '.' && (cursor[3] == '/' || cursor[3] == '\0')))) {
      return false;
    }
  }
  return true;
}

static struct supervisor_config parse_arguments(int argc, char **argv) {
  struct supervisor_config config = {
      .control_dir = DEFAULT_CONTROL_DIR,
      .target_pid = DEFAULT_TARGET_PID,
      .socket_fd = DEFAULT_SOCKET_FD,
      .child_argv = NULL,
  };
  int index = 1;

  while (index < argc) {
    if (strcmp(argv[index], "--") == 0) {
      index++;
      break;
    }
    if (index + 1 >= argc) {
      fail_message("option is missing a value or -- command delimiter");
    }
    if (strcmp(argv[index], "--control-dir") == 0) {
      config.control_dir = argv[index + 1];
    } else if (strcmp(argv[index], "--target-pid") == 0) {
      if (!parse_u32(argv[index + 1], &config.target_pid) ||
          config.target_pid < 2) {
        fail_message("target PID must be an integer from 2 through 4294967295");
      }
    } else if (strcmp(argv[index], "--socket-fd") == 0) {
      if (!parse_fd(argv[index + 1], &config.socket_fd)) {
        fail_message("socket fd must be an integer from 3 through 2147483647");
      }
    } else {
      fail_message("unknown option");
    }
    index += 2;
  }
  if (index >= argc || argv[index] == NULL || argv[index][0] == '\0') {
    fail_message("a child command is required after --");
  }
  if (!clean_absolute_path(config.control_dir)) {
    fail_message("control directory must be an absolute clean path");
  }
  config.child_argv = &argv[index];
  return config;
}

static bool control_directory_metadata_is_safe(const struct stat *metadata) {
  return S_ISDIR(metadata->st_mode) && !S_ISLNK(metadata->st_mode) &&
         metadata->st_uid == 0;
}

static void make_control_directory(const char *path) {
  struct stat metadata;
  char resolved[PATH_MAX];

  if (mkdir(path, 0700) != 0 && errno != EEXIST) {
    fail_errno("create control directory");
  }
  if (lstat(path, &metadata) != 0) {
    fail_errno("inspect control directory");
  }
  if (!control_directory_metadata_is_safe(&metadata)) {
    fail_message("control directory must be a root-owned real directory");
  }
  /* Docker creates a new named-volume root as 0755. Only normalize an already
   * verified, root-owned real directory; never chmod through a link. */
  if ((metadata.st_mode & 0777) != 0700 && chmod(path, 0700) != 0) {
    fail_errno("restrict control directory");
  }
  if (lstat(path, &metadata) != 0) {
    fail_errno("reinspect control directory");
  }
  if (!control_directory_metadata_is_safe(&metadata) ||
      (metadata.st_mode & 0777) != 0700) {
    fail_message("control directory must remain a root-owned real directory "
                 "with mode 0700");
  }
  if (realpath(path, resolved) == NULL) {
    fail_errno("resolve control directory");
  }
  if (strcmp(resolved, path) != 0) {
    fail_message("control directory path must be canonical");
  }
}

static int open_control_directory(const char *path) {
  const int descriptor =
      open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) {
    fail_errno("open control directory");
  }
  return descriptor;
}

static int rename_noreplace(int directory_fd, const char *source,
                            const char *destination) {
#ifdef SYS_renameat2
  if (syscall(SYS_renameat2, directory_fd, source, directory_fd, destination,
              RENAME_NOREPLACE) == 0) {
    return 0;
  }
  if (errno != ENOSYS && errno != EINVAL) {
    return -1;
  }
#endif
  if (linkat(directory_fd, source, directory_fd, destination, 0) != 0) {
    return -1;
  }
  if (unlinkat(directory_fd, source, 0) != 0) {
    const int saved_errno = errno;
    (void)unlinkat(directory_fd, destination, 0);
    errno = saved_errno;
    return -1;
  }
  return 0;
}

static void write_all(int descriptor, const char *contents, size_t length) {
  size_t written = 0;
  while (written < length) {
    const ssize_t result =
        write(descriptor, contents + written, length - written);
    if (result < 0 && errno == EINTR) {
      continue;
    }
    if (result <= 0) {
      fail_errno("write control file");
    }
    written += (size_t)result;
  }
}

static void publish_control_file(int directory_fd, const char *name,
                                 const char *contents) {
  static unsigned long sequence;
  char temporary[128];
  int descriptor;
  const size_t length = strlen(contents);

  if (strchr(name, '/') != NULL || name[0] == '\0' ||
      length > MAX_CONTROL_FILE_BYTES) {
    fail_message("invalid control file publication");
  }
  if (snprintf(temporary, sizeof(temporary), ".tmp-%ld-%lu", (long)getpid(),
               ++sequence) >= (int)sizeof(temporary)) {
    fail_message("control temporary name is too long");
  }
  descriptor =
      openat(directory_fd, temporary,
             O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (descriptor < 0) {
    fail_errno("create control temporary file");
  }
  write_all(descriptor, contents, length);
  if (fsync(descriptor) != 0) {
    fail_errno("sync control temporary file");
  }
  if (close(descriptor) != 0) {
    fail_errno("close control temporary file");
  }
  if (rename_noreplace(directory_fd, temporary, name) != 0) {
    const int saved_errno = errno;
    (void)unlinkat(directory_fd, temporary, 0);
    errno = saved_errno;
    fail_errno("publish control file");
  }
  if (fsync(directory_fd) != 0) {
    fail_errno("sync control directory");
  }
}

static bool control_contents_are_exact(const char *contents, size_t length,
                                       const char *expected) {
  const size_t expected_length = strlen(expected);
  return length == expected_length &&
         memcmp(contents, expected, expected_length) == 0;
}

static bool exact_control_file_present(int directory_fd, const char *name,
                                       const char *expected) {
  char contents[128];
  struct stat metadata;
  const size_t expected_length = strlen(expected);
  int descriptor;
  ssize_t length;

  descriptor = openat(directory_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) {
    if (errno == ENOENT) {
      return false;
    }
    fail_errno("open control command");
  }
  if (fstat(descriptor, &metadata) != 0) {
    fail_errno("inspect control command");
  }
  if (!S_ISREG(metadata.st_mode) || metadata.st_uid != 0 ||
      (metadata.st_mode & 0777) != 0600 || metadata.st_nlink != 1 ||
      metadata.st_size != (off_t)expected_length) {
    fail_message("control command has unsafe metadata");
  }
  length = read(descriptor, contents, sizeof(contents));
  if (length < 0) {
    fail_errno("read control command");
  }
  if (close(descriptor) != 0) {
    fail_errno("close control command");
  }
  if (!control_contents_are_exact(contents, (size_t)length, expected)) {
    fail_message("control command has unexpected contents");
  }
  return true;
}

static void remove_exact_control_file(int directory_fd, const char *name,
                                      const char *expected) {
  if (!exact_control_file_present(directory_fd, name, expected)) {
    fail_message("required control file is absent");
  }
  if (unlinkat(directory_fd, name, 0) != 0) {
    fail_errno("remove consumed control file");
  }
  if (fsync(directory_fd) != 0) {
    fail_errno("sync consumed control file removal");
  }
}

static void handle_termination(int signal_number) {
  termination_signal = signal_number;
  if (active_child > 0) {
    (void)kill(active_child, signal_number);
  }
}

static void install_signal_handlers(void) {
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = handle_termination;
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGTERM, &action, NULL) != 0 ||
      sigaction(SIGINT, &action, NULL) != 0 ||
      sigaction(SIGHUP, &action, NULL) != 0) {
    fail_errno("install signal handler");
  }
}

static void restore_child_signal_dispositions(void) {
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  action.sa_handler = SIG_DFL;
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGTERM, &action, NULL) != 0 ||
      sigaction(SIGINT, &action, NULL) != 0 ||
      sigaction(SIGHUP, &action, NULL) != 0) {
    fail_errno("restore child signal dispositions");
  }
  if (termination_signal != 0) {
    _exit(128 + termination_signal);
  }
}

static void wait_for_control_file(int directory_fd, const char *name,
                                  const char *expected) {
  struct timespec started;
  struct timespec now;
  const struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};

  if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
    fail_errno("read monotonic clock");
  }
  for (;;) {
    if (termination_signal != 0) {
      fail_message("terminated while waiting for control command");
    }
    if (exact_control_file_present(directory_fd, name, expected)) {
      return;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
      fail_errno("read monotonic clock");
    }
    if (now.tv_sec - started.tv_sec >= CONTROL_TIMEOUT_SECONDS) {
      fail_message("timed out waiting for control command");
    }
    if (nanosleep(&pause, NULL) != 0 && errno != EINTR) {
      fail_errno("pause for control command");
    }
  }
}

static void create_tcp_pair(int *client, int *peer) {
  int listener;
  struct sockaddr_in address;
  socklen_t length = sizeof(address);

  listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (listener < 0) {
    fail_errno("create TCP listener");
  }
  memset(&address, 0, sizeof(address));
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
      listen(listener, 1) != 0 ||
      getsockname(listener, (struct sockaddr *)&address, &length) != 0) {
    fail_errno("prepare TCP listener");
  }
  *client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (*client < 0 ||
      connect(*client, (struct sockaddr *)&address, sizeof(address)) != 0) {
    fail_errno("connect inherited TCP socket");
  }
  *peer = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
  if (*peer < 0) {
    fail_errno("accept inherited TCP socket");
  }
  if (close(listener) != 0) {
    fail_errno("close TCP listener");
  }
}

static uint64_t namespace_inode(const char *path) {
  struct stat metadata;
  if (stat(path, &metadata) != 0) {
    fail_errno("inspect namespace inode");
  }
  return (uint64_t)metadata.st_ino;
}

static uint64_t socket_u64_option(int descriptor, int option) {
  uint64_t value = 0;
  socklen_t size = sizeof(value);
  if (getsockopt(descriptor, SOL_SOCKET, option, &value, &size) != 0 ||
      size != sizeof(value) || value == 0) {
    fail_errno("read inherited socket identity");
  }
  return value;
}

static uint16_t socket_port(int descriptor, bool peer) {
  struct sockaddr_in address;
  socklen_t size = sizeof(address);
  int result;
  memset(&address, 0, sizeof(address));
  result = peer ? getpeername(descriptor, (struct sockaddr *)&address, &size)
                : getsockname(descriptor, (struct sockaddr *)&address, &size);
  if (result != 0 || size != sizeof(address) || address.sin_family != AF_INET ||
      address.sin_port == 0 ||
      address.sin_addr.s_addr != htonl(INADDR_LOOPBACK)) {
    fail_errno("read inherited socket endpoint");
  }
  return ntohs(address.sin_port);
}

static uint64_t process_start_time(pid_t pid) {
  char path[64];
  char buffer[4096];
  char *after_name;
  char *save = NULL;
  char *token;
  int descriptor;
  ssize_t length;
  unsigned int field = 3;

  if (snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid) >=
      (int)sizeof(path)) {
    fail_message("process stat path is too long");
  }
  descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) {
    fail_errno("open child process stat");
  }
  length = read(descriptor, buffer, sizeof(buffer) - 1);
  if (length <= 0) {
    fail_errno("read child process stat");
  }
  if (close(descriptor) != 0) {
    fail_errno("close child process stat");
  }
  buffer[length] = '\0';
  after_name = strrchr(buffer, ')');
  if (after_name == NULL || after_name[1] != ' ') {
    fail_message("child process stat is malformed");
  }
  token = strtok_r(after_name + 2, " ", &save);
  while (token != NULL && field < 22) {
    field++;
    token = strtok_r(NULL, " ", &save);
  }
  if (token == NULL || field != 22) {
    fail_message("child process stat lacks start time");
  }
  errno = 0;
  {
    char *end = NULL;
    const unsigned long long value = strtoull(token, &end, 10);
    if (errno != 0 || end == token || *end != '\0' || value == 0) {
      fail_message("child process start time is malformed");
    }
    return (uint64_t)value;
  }
}

static struct child_identity capture_child_identity(pid_t child,
                                                    int socket_fd) {
  struct child_identity identity = {
      .pid_namespace_inode = namespace_inode("/proc/self/ns/pid_for_children"),
      .pid = (uint32_t)child,
      .tid = (uint32_t)child,
      .start_time_ticks = process_start_time(child),
      .socket_cookie = socket_u64_option(socket_fd, SO_COOKIE),
      .network_namespace_inode = namespace_inode("/proc/self/ns/net"),
      .network_namespace_cookie = socket_u64_option(socket_fd, SO_NETNS_COOKIE),
      .local_port = socket_port(socket_fd, false),
      .peer_port = socket_port(socket_fd, true),
  };
  return identity;
}

static void publish_identity(int directory_fd, const char *name,
                             const struct child_identity *identity) {
  char contents[1024];
  const int length = snprintf(
      contents, sizeof(contents),
      "schema=obi-pid-reuse-private-v1\n"
      "pid_namespace_inode=%llu\n"
      "pid=%u\n"
      "tid=%u\n"
      "start_time_ticks=%llu\n"
      "socket_cookie=%llu\n"
      "network_namespace_inode=%llu\n"
      "network_namespace_cookie=%llu\n"
      "local_port=%u\n"
      "peer_port=%u\n",
      (unsigned long long)identity->pid_namespace_inode, identity->pid,
      identity->tid, (unsigned long long)identity->start_time_ticks,
      (unsigned long long)identity->socket_cookie,
      (unsigned long long)identity->network_namespace_inode,
      (unsigned long long)identity->network_namespace_cookie,
      (unsigned int)identity->local_port, (unsigned int)identity->peer_port);
  if (length <= 0 || length >= (int)sizeof(contents)) {
    fail_message("private identity record is too large");
  }
  publish_control_file(directory_fd, name, contents);
}

static void write_ns_last_pid(uint32_t target_pid) {
  char contents[32];
  int descriptor;
  int length;

  descriptor =
      open("/proc/sys/kernel/ns_last_pid", O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
  if (descriptor < 0) {
    fail_errno("open namespace PID allocator control");
  }
  length = snprintf(contents, sizeof(contents), "%u\n", target_pid - 1);
  if (length <= 0 || length >= (int)sizeof(contents)) {
    fail_message("namespace PID allocator value is too large");
  }
  write_all(descriptor, contents, (size_t)length);
  if (close(descriptor) != 0) {
    fail_errno("close namespace PID allocator control");
  }
}

static void drop_child_privileges(void) {
  struct __user_cap_header_struct header = {
      .version = _LINUX_CAPABILITY_VERSION_3,
      .pid = 0,
  };
  struct __user_cap_data_struct data[2];
  int capability;

  memset(data, 0, sizeof(data));
  for (capability = 0; capability <= CAP_LAST_CAP; capability++) {
    if (prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) != 0 && errno != EINVAL) {
      fail_errno("drop child capability bounding set");
    }
  }
  if (prctl(PR_SET_SECUREBITS,
            SECBIT_NOROOT | SECBIT_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP |
                SECBIT_NO_SETUID_FIXUP_LOCKED,
            0, 0, 0) != 0) {
    fail_errno("lock child securebits");
  }
  if (syscall(SYS_capset, &header, &data) != 0) {
    fail_errno("clear child capabilities");
  }
#ifdef PR_CAP_AMBIENT
  if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 &&
      errno != EINVAL) {
    fail_errno("clear child ambient capabilities");
  }
#endif
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    fail_errno("set child no-new-privileges");
  }
}

static bool preparation_child_pid_is_safe(pid_t child, uint32_t target_pid) {
  return child > 1 && (uint32_t)child != target_pid;
}

static bool controlled_phase_is_valid(const char *phase) {
  return phase != NULL && (strcmp(phase, "A") == 0 || strcmp(phase, "B") == 0);
}

static void
configure_preparation_environment(const struct supervisor_config *config) {
  if (unsetenv("OBI_PID_REUSE_SOCKET_FD") != 0 ||
      setenv("OBI_PID_REUSE_PHASE", PREPARE_PHASE, 1) != 0 ||
      setenv("OBI_PID_REUSE_CONTROL_DIR", config->control_dir, 1) != 0) {
    fail_errno("configure preparatory JVM environment");
  }
}

static void
configure_controlled_environment(const struct supervisor_config *config,
                                 const char *phase) {
  char descriptor[32];

  if (!controlled_phase_is_valid(phase)) {
    fail_message("controlled JVM phase is invalid");
  }
  if (setenv("OBI_PID_REUSE_PHASE", phase, 1) != 0 ||
      setenv("OBI_PID_REUSE_CONTROL_DIR", config->control_dir, 1) != 0 ||
      snprintf(descriptor, sizeof(descriptor), "%d", config->socket_fd) >=
          (int)sizeof(descriptor) ||
      setenv("OBI_PID_REUSE_SOCKET_FD", descriptor, 1) != 0) {
    fail_errno("configure controlled JVM environment");
  }
}

static pid_t start_preparation_child(const struct supervisor_config *config) {
  pid_t child = fork();

  if (child < 0) {
    fail_errno("fork preparatory JVM");
  }
  if (child == 0) {
    restore_child_signal_dispositions();
    if (!preparation_child_pid_is_safe(getpid(), config->target_pid) ||
        getpid() != (pid_t)syscall(SYS_gettid)) {
      fail_message("preparatory JVM received an unsafe process identity");
    }
    errno = 0;
    if (fcntl(config->socket_fd, F_GETFD) != -1 || errno != EBADF) {
      fail_message("preparatory JVM inherited the reserved probe descriptor");
    }
    configure_preparation_environment(config);
    drop_child_privileges();
    execvp(config->child_argv[0], config->child_argv);
    fail_errno("execute preparatory JVM");
  }
  if (!preparation_child_pid_is_safe(child, config->target_pid)) {
    (void)kill(child, SIGKILL);
    (void)waitpid(child, NULL, 0);
    fail_message("preparatory JVM collided with the controlled target PID");
  }
  active_child = child;
  if (termination_signal != 0) {
    (void)kill(child, termination_signal);
    fail_message("terminated while starting preparatory JVM");
  }
  return child;
}

static pid_t start_child(const struct supervisor_config *config,
                         const char *phase, int inherited_socket) {
  pid_t child;

  if (!controlled_phase_is_valid(phase)) {
    fail_message("controlled JVM phase is invalid");
  }
  write_ns_last_pid(config->target_pid);
  child = fork();
  if (child < 0) {
    fail_errno("fork controlled JVM");
  }
  if (child == 0) {
    restore_child_signal_dispositions();
    if ((uint32_t)getpid() != config->target_pid ||
        getpid() != (pid_t)syscall(SYS_gettid)) {
      fail_message(
          "controlled JVM child did not receive the requested numeric PID/TID");
    }
    if (inherited_socket != config->socket_fd) {
      if (dup3(inherited_socket, config->socket_fd, 0) < 0) {
        fail_errno("install inherited Java probe socket");
      }
      (void)close(inherited_socket);
    } else if (fcntl(config->socket_fd, F_SETFD, 0) != 0) {
      fail_errno("clear inherited Java probe socket close-on-exec flag");
    }
    configure_controlled_environment(config, phase);
    drop_child_privileges();
    execvp(config->child_argv[0], config->child_argv);
    fail_errno("execute controlled JVM");
  }
  if ((uint32_t)child != config->target_pid) {
    (void)kill(child, SIGKILL);
    (void)waitpid(child, NULL, 0);
    fail_message("namespace PID allocator did not provide the requested "
                 "numeric PID/TID");
  }
  active_child = child;
  if (termination_signal != 0) {
    (void)kill(child, termination_signal);
    fail_message("terminated while starting controlled JVM");
  }
  return child;
}

static int wait_for_child(pid_t child) {
  int status;
  pid_t result;
  do {
    result = waitpid(child, &status, 0);
  } while (result < 0 && errno == EINTR && termination_signal == 0);
  active_child = -1;
  if (result != child) {
    fail_errno("reap controlled JVM");
  }
  return status;
}

static bool child_exited_cleanly(int status) {
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static void wait_for_preparation_child(int directory_fd, pid_t child) {
  struct timespec started;
  struct timespec now;
  const struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};

  if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
    fail_errno("read preparatory JVM start time");
  }
  for (;;) {
    int status = 0;
    const pid_t result = waitpid(child, &status, WNOHANG);

    if (result < 0) {
      if (errno == EINTR) {
        continue;
      }
      active_child = -1;
      fail_errno("reap preparatory JVM");
    }
    const bool marker_present = exact_control_file_present(
        directory_fd, PREPARE_MARKER_NAME, PREPARE_MARKER_CONTENTS);
    if (result == child) {
      active_child = -1;
      if (termination_signal != 0) {
        fail_message("terminated while reaping preparatory JVM");
      }
      if (!child_exited_cleanly(status)) {
        fail_message("preparatory JVM did not exit successfully");
      }
      if (!marker_present) {
        fail_message("preparatory JVM exited without its readiness marker");
      }
      remove_exact_control_file(directory_fd, PREPARE_MARKER_NAME,
                                PREPARE_MARKER_CONTENTS);
      return;
    }
    if (termination_signal != 0) {
      (void)kill(child, SIGKILL);
      (void)wait_for_child(child);
      fail_message("terminated while waiting for preparatory JVM");
    }
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
      fail_errno("read preparatory JVM wait time");
    }
    if (now.tv_sec - started.tv_sec >= CONTROL_TIMEOUT_SECONDS) {
      (void)kill(child, SIGKILL);
      (void)wait_for_child(child);
      fail_message("timed out waiting for preparatory JVM");
    }
    if (nanosleep(&pause, NULL) != 0 && errno != EINTR) {
      fail_errno("pause for preparatory JVM");
    }
  }
}

static void require_clean_phase_exit(int status) {
  if (!child_exited_cleanly(status)) {
    fail_message("phase A controlled JVM did not exit successfully");
  }
}

static bool identity_is_exact_reuse(const struct child_identity *first,
                                    const struct child_identity *second) {
  return first->pid_namespace_inode == second->pid_namespace_inode &&
         first->pid == second->pid && first->tid == second->tid &&
         first->start_time_ticks != second->start_time_ticks &&
         first->socket_cookie == second->socket_cookie &&
         first->network_namespace_inode == second->network_namespace_inode &&
         first->network_namespace_cookie == second->network_namespace_cookie &&
         first->local_port == second->local_port &&
         first->peer_port == second->peer_port;
}

static void verify_reuse(const struct child_identity *first,
                         const struct child_identity *second) {
  if (first->pid_namespace_inode != second->pid_namespace_inode ||
      first->pid != second->pid || first->tid != second->tid ||
      first->socket_cookie != second->socket_cookie ||
      first->network_namespace_inode != second->network_namespace_inode ||
      first->network_namespace_cookie != second->network_namespace_cookie ||
      first->local_port != second->local_port ||
      first->peer_port != second->peer_port) {
    fail_message("phase B did not preserve the exact PID namespace and "
                 "inherited socket identity");
  }
  if (!identity_is_exact_reuse(first, second)) {
    fail_message("phase B did not establish a distinct process lifetime");
  }
}

#ifndef PID_REUSE_SUPERVISOR_TEST
int main(int argc, char **argv) {
  const struct supervisor_config config = parse_arguments(argc, argv);
  struct child_identity first;
  struct child_identity second;
  int control_directory;
  int client_socket;
  int peer_socket;
  pid_t child;
  int status;
  const struct timespec lifetime_gap = {.tv_sec = 0, .tv_nsec = 100000000};

  // A container cannot become PID 1 in the host namespace without replacing
  // the host init. The compose contract additionally asserts an isolated PID
  // namespace; this runtime check makes accidental shared/host PID mode fail.
  if (getpid() != 1) {
    fail_message("must run as PID 1 in a private PID namespace");
  }
  make_control_directory(config.control_dir);
  control_directory = open_control_directory(config.control_dir);
  install_signal_handlers();
  child = start_preparation_child(&config);
  wait_for_preparation_child(control_directory, child);
  if (termination_signal != 0) {
    fail_message("terminated after preparatory JVM readiness");
  }
  create_tcp_pair(&client_socket, &peer_socket);

  child = start_child(&config, "A", client_socket);
  first = capture_child_identity(child, client_socket);
  publish_identity(control_directory, "identity-a", &first);
  status = wait_for_child(child);
  require_clean_phase_exit(status);
  publish_control_file(control_directory, "a-reaped", "a-reaped-v1\n");

  wait_for_control_file(control_directory, "start-b", "start-b-v1\n");
  if (nanosleep(&lifetime_gap, NULL) != 0 && errno != EINTR) {
    fail_errno("wait for a distinct process lifetime");
  }
  child = start_child(&config, "B", client_socket);
  second = capture_child_identity(child, client_socket);
  verify_reuse(&first, &second);
  publish_identity(control_directory, "identity-b", &second);
  publish_control_file(control_directory, "reuse-proved", "reuse-proved-v1\n");

  status = wait_for_child(child);
  (void)close(client_socket);
  (void)close(peer_socket);
  (void)close(control_directory);
  if (termination_signal != 0) {
    return 128 + termination_signal;
  }
  if (WIFEXITED(status)) {
    return WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    return 128 + WTERMSIG(status);
  }
  return EXIT_FAILURE;
}
#endif
