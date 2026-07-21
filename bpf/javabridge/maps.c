// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <maps/java_remote_parent.h>

char __license[] SEC("license") = "Dual MIT/GPL";
