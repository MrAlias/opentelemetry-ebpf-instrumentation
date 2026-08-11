/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>
#include <sys/socket.h>

bool obi_demo_java_remote_parent_apply_getsockopt_fault(
    int result, int level, int option, void *optval, const socklen_t *optlen);

#if defined(OBI_DEMO_JAVA_REMOTE_PARENT_FAULT_TESTING)
void obi_demo_java_remote_parent_set_live_fd_barrier_timeout_for_test(
    int timeout_millis);
void obi_demo_java_remote_parent_reset_real_getsockopt_call_count_for_test(
    void);
unsigned int
obi_demo_java_remote_parent_real_getsockopt_call_count_for_test(void);
void obi_demo_java_remote_parent_reset_live_fd_barrier_observed_release_for_test(
    void);
int obi_demo_java_remote_parent_live_fd_barrier_observed_release_for_test(void);
void obi_demo_java_remote_parent_reset_wrong_live_socket_probe_for_test(void);
unsigned int
obi_demo_java_remote_parent_wrong_live_socket_probe_count_for_test(void);
int obi_demo_java_remote_parent_wrong_live_socket_probe_errno_for_test(void);
void obi_demo_java_remote_parent_reset_same_fd_probes_for_test(void);
unsigned int
obi_demo_java_remote_parent_same_fd_task_probe_count_for_test(void);
int obi_demo_java_remote_parent_same_fd_task_probe_outcome_for_test(void);
unsigned int
obi_demo_java_remote_parent_same_fd_thread_probe_count_for_test(void);
int obi_demo_java_remote_parent_same_fd_thread_probe_outcome_for_test(void);
int obi_demo_java_remote_parent_classify_same_fd_probe_for_test(
    int result, int probe_errno, const unsigned char *response,
    socklen_t response_length);
void obi_demo_java_remote_parent_reset_auto_unavailable_counts_for_test(void);
unsigned int
obi_demo_java_remote_parent_auto_unavailable_health_count_for_test(void);
unsigned int
obi_demo_java_remote_parent_auto_unavailable_connect_count_for_test(void);
unsigned int obi_demo_java_remote_parent_real_connect_count_for_test(void);
#endif
