/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

#define PID_REUSE_SUPERVISOR_TEST
#pragma GCC diagnostic ignored "-Wunused-function"
#include "pid_reuse_supervisor.c"

#include <assert.h>

static void test_numbers_and_paths(void) {
  uint32_t value = 0;
  int descriptor = 0;

  assert(parse_u32("4242", &value) && value == 4242U);
  assert(!parse_u32("0", &value));
  assert(!parse_u32("-1", &value));
  assert(!parse_u32("1x", &value));
  assert(parse_fd("198", &descriptor) && descriptor == 198);
  assert(!parse_fd("2", &descriptor));
  assert(clean_absolute_path("/run/obi-demo/pid-reuse"));
  assert(!clean_absolute_path("run/obi-demo/pid-reuse"));
  assert(!clean_absolute_path("/run//pid-reuse"));
  assert(!clean_absolute_path("/run/../pid-reuse"));
  assert(!clean_absolute_path("/run/pid-reuse/"));
}

static void test_identity_reuse_contract(void) {
  const struct child_identity first = {
      .pid_namespace_inode = 11,
      .pid = 4242,
      .tid = 4242,
      .start_time_ticks = 100,
      .socket_cookie = 12,
      .network_namespace_inode = 13,
      .network_namespace_cookie = 14,
      .local_port = 15000,
      .peer_port = 15001,
  };
  struct child_identity second = first;
  second.start_time_ticks = 101;
  assert(identity_is_exact_reuse(&first, &second));
  verify_reuse(&first, &second);

  second.pid_namespace_inode++;
  assert(!identity_is_exact_reuse(&first, &second));
  second = first;
  assert(!identity_is_exact_reuse(&first, &second));
  second.start_time_ticks++;
  second.pid++;
  assert(!identity_is_exact_reuse(&first, &second));
  second = first;
  second.start_time_ticks++;
  second.tid++;
  assert(!identity_is_exact_reuse(&first, &second));
  second = first;
  second.start_time_ticks++;
  second.socket_cookie++;
  assert(!identity_is_exact_reuse(&first, &second));
  second = first;
  second.start_time_ticks++;
  second.network_namespace_cookie++;
  assert(!identity_is_exact_reuse(&first, &second));
}

static void test_control_directory_metadata(void) {
  struct stat metadata = {.st_mode = S_IFDIR | 0755, .st_uid = 0};

  assert(control_directory_metadata_is_safe(&metadata));
  metadata.st_uid = 1;
  assert(!control_directory_metadata_is_safe(&metadata));
  metadata.st_uid = 0;
  metadata.st_mode = S_IFREG | 0700;
  assert(!control_directory_metadata_is_safe(&metadata));
  metadata.st_mode = S_IFLNK | 0700;
  assert(!control_directory_metadata_is_safe(&metadata));
}

static void test_preparation_contract(void) {
  const struct supervisor_config config = {
      .control_dir = "/run/obi-demo/pid-reuse",
      .target_pid = 4242,
      .socket_fd = 198,
      .child_argv = NULL,
  };

  assert(preparation_child_pid_is_safe(2, config.target_pid));
  assert(!preparation_child_pid_is_safe(1, config.target_pid));
  assert(!preparation_child_pid_is_safe(4242, config.target_pid));
  assert(controlled_phase_is_valid("A"));
  assert(controlled_phase_is_valid("B"));
  assert(!controlled_phase_is_valid(PREPARE_PHASE));
  assert(!controlled_phase_is_valid(NULL));

  assert(setenv("OBI_PID_REUSE_SOCKET_FD", "stale", 1) == 0);
  configure_preparation_environment(&config);
  assert(strcmp(getenv("OBI_PID_REUSE_PHASE"), PREPARE_PHASE) == 0);
  assert(strcmp(getenv("OBI_PID_REUSE_CONTROL_DIR"), config.control_dir) == 0);
  assert(getenv("OBI_PID_REUSE_SOCKET_FD") == NULL);

  configure_controlled_environment(&config, "A");
  assert(strcmp(getenv("OBI_PID_REUSE_PHASE"), "A") == 0);
  assert(strcmp(getenv("OBI_PID_REUSE_CONTROL_DIR"), config.control_dir) == 0);
  assert(strcmp(getenv("OBI_PID_REUSE_SOCKET_FD"), "198") == 0);

  assert(control_contents_are_exact(PREPARE_MARKER_CONTENTS,
                                    strlen(PREPARE_MARKER_CONTENTS),
                                    PREPARE_MARKER_CONTENTS));
  assert(!control_contents_are_exact(
      "prepare-ready-v1", strlen("prepare-ready-v1"), PREPARE_MARKER_CONTENTS));
  assert(!control_contents_are_exact("prepare-ready-v2\n",
                                     strlen("prepare-ready-v2\n"),
                                     PREPARE_MARKER_CONTENTS));
  assert(child_exited_cleanly(W_EXITCODE(0, 0)));
  assert(!child_exited_cleanly(W_EXITCODE(1, 0)));
  assert(!child_exited_cleanly(SIGKILL));

  assert(unsetenv("OBI_PID_REUSE_PHASE") == 0);
  assert(unsetenv("OBI_PID_REUSE_CONTROL_DIR") == 0);
  assert(unsetenv("OBI_PID_REUSE_SOCKET_FD") == 0);
}

int main(void) {
  test_numbers_and_paths();
  test_identity_reuse_contract();
  test_control_directory_metadata();
  test_preparation_contract();
  return 0;
}
