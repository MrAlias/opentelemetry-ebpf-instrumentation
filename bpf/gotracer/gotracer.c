// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore
// Copyright Grafana Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <bpfcore/utils.h>

#include <common/pin_internal.h>
#include <common/preempt_guard.h>

#include <gotracer/go_offsets.h>
#include <gotracer/maps/process_lifecycle_epochs.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, go_executable_key_t);
    __uint(max_entries, MAX_GO_PROGRAMS);
    __uint(pinning, OBI_PIN_INTERNAL);
} go_executable_identity_requests SEC(".maps");

SEC("kprobe/uprobe_register")
int GUARDED_PROG(obi_capture_go_executable_identity, struct pt_regs *, ctx) {
    const u32 tid = (u32)bpf_get_current_pid_tgid();
    go_executable_key_t *identity = bpf_map_lookup_elem(&go_executable_identity_requests, &tid);
    if (!identity) {
        return 0;
    }

    struct inode *inode = (struct inode *)PT_REGS_PARM1_CORE(ctx);
    go_executable_key(inode, identity);
    return 0;
}

#include "go_runtime.c"
#include "go_net.c"
#include "go_net_tls.c"
#include "go_nethttp.c"
#include "go_sql.c"
#include "go_grpc.c"
#include "go_redis.c"
#include "go_kafka_go.c"
#include "go_sarama.c"
#include "go_sdk.c"
#include "go_mongo.c"
//FIXME - move common code to common location
#include "generictracer/protocol_handler.c"

static __always_inline int go_retire_current_process_lifecycle(void) {
    const u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u64 *epoch = bpf_map_lookup_elem(&go_process_lifecycle_epochs, &tgid);
    if (!epoch) {
        return 0;
    }

    // Epoch zero is never valid. Skip it on wrap so an old target can never
    // become eligible through an ABA transition.
    __sync_fetch_and_add(epoch, 1);
    if (*epoch == 0) {
        __sync_fetch_and_add(epoch, 1);
    }
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int obi_go_process_exec(void *ctx) {
    (void)ctx;
    return go_retire_current_process_lifecycle();
}

SEC("tracepoint/sched/sched_process_exit")
int obi_go_process_exit(void *ctx) {
    (void)ctx;

    const struct task_struct *task = (const struct task_struct *)bpf_get_current_task();
    if (BPF_CORE_READ(task, signal, live.counter) != 0) {
        return 0;
    }
    return go_retire_current_process_lifecycle();
}

char __license[] SEC("license") = "Dual MIT/GPL";
