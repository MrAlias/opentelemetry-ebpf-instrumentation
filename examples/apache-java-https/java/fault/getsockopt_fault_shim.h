/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdbool.h>
#include <sys/socket.h>

bool obi_demo_java_remote_parent_apply_getsockopt_fault(
    int result, int level, int option, void *optval, const socklen_t *optlen);
