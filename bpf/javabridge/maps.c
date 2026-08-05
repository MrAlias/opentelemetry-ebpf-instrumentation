// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <maps/java_remote_parent.h>
#include <maps/java_remote_parent_receive_cursor.h>
#include <maps/ssl_prewrite_tp.h>

char __license[] SEC("license") = "Dual MIT/GPL";
