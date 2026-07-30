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
#endif
