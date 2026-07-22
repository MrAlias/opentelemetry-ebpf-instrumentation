// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/connection_info.h>
#include <common/map_sizing.h>

// LRU map which holds onto the mapping of an SSL pointer and owning process to
// pid-tid. It is cleaned up after lookup and supports frameworks that process
// SSL requests on separate thread pools, e.g. Ruby on Rails.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, ssl_pid_key_t);
    __type(value, ssl_thread_key_t);
    __uint(max_entries, MAX_CONCURRENT_REQUESTS);
} ssl_to_pid_tid SEC(".maps");
