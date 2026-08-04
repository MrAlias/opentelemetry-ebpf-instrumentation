// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/protocol_defs.h>

#ifndef JAVA_REMOTE_PARENT_BEGIN_DATA_RECEIVE
#define JAVA_REMOTE_PARENT_BEGIN_DATA_RECEIVE(process_capability)                                  \
    java_remote_parent_begin_data_receive_for_capability(process_capability)
#define JAVA_REMOTE_PARENT_BEGIN_DATA_RECEIVE_DEFAULT
#endif

// Cross the request boundary before the registration gate. An authorized
// receive must detach even when its LRU registration disappeared. Callers
// must not inspect the advisory tuple unless this gate succeeds.
static __always_inline u8 java_remote_parent_begin_receive(
    u8 enabled, u8 data_hook_ready, u8 registered, u8 op, u64 process_capability) {
    if (enabled && data_hook_ready && op == TCP_RECV) {
        JAVA_REMOTE_PARENT_BEGIN_DATA_RECEIVE(process_capability);
    }
    return registered;
}

#ifdef JAVA_REMOTE_PARENT_BEGIN_DATA_RECEIVE_DEFAULT
#undef JAVA_REMOTE_PARENT_BEGIN_DATA_RECEIVE_DEFAULT
#undef JAVA_REMOTE_PARENT_BEGIN_DATA_RECEIVE
#endif
