// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "ebpf_nethooks.h"
#include "net/ip.h"

#define OBI_FLOW_EVENT_VERSION 1
#define OBI_FLOW_CAPTURE_SIZE 512

typedef struct _obi_flow_config
{
    uint64_t target_pid;
    uint16_t target_port;
    uint16_t reserved_1;
    uint32_t reserved_2;
} obi_flow_config_t;

typedef struct _obi_flow_event
{
    uint16_t version;
    uint16_t size;
    uint32_t flags;
    uint64_t process_id;
    uint64_t process_start_key;
    uint64_t flow_id;
    uint64_t sequence;
    uint64_t timestamp_ns;
    uint64_t interface_luid;
    uint32_t family;
    uint32_t local_ip4;
    uint32_t remote_ip4;
    uint32_t local_ip6[4];
    uint32_t remote_ip6[4];
    uint32_t local_port;
    uint32_t remote_port;
    uint32_t state;
    uint32_t direction;
    uint32_t indicated_length;
    uint32_t copied_length;
    uint32_t missed_bytes;
    uint16_t data_length;
    uint16_t reserved;
    unsigned char data[OBI_FLOW_CAPTURE_SIZE];
    uint32_t reserved_3;
} obi_flow_event_t;

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, obi_flow_config_t);
} flow_config SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} flow_events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, obi_flow_event_t);
} flow_event_scratch SEC(".maps");

flow_classify_hook_t obi_flow_classify;

static inline int
is_target_flow(ebpf_flow_classify_t* context)
{
    uint32_t key = 0;
    obi_flow_config_t* config = bpf_map_lookup_elem(&flow_config, &key);
    if (config == 0 || config->target_pid == 0 || context->process_id != config->target_pid) {
        return 0;
    }
    return config->target_port == 0 || bpf_ntohs((uint16_t)context->local_port) == config->target_port;
}

SEC("flow_classify")
ebpf_flow_classify_action_t
obi_flow_classify(ebpf_flow_classify_t* context)
{
    uint32_t key = 0;

    if (context->state == EBPF_FLOW_STATE_NEW && !is_target_flow(context)) {
        return EBPF_FLOW_CLASSIFY_ALLOW;
    }

    obi_flow_event_t* event = bpf_map_lookup_elem(&flow_event_scratch, &key);
    if (event == 0) {
        return context->state == EBPF_FLOW_STATE_DELETED ? EBPF_FLOW_CLASSIFY_ALLOW
                                                        : EBPF_FLOW_CLASSIFY_NEED_MORE_DATA;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->version = OBI_FLOW_EVENT_VERSION;
    event->size = sizeof(*event);
    event->flags = context->flags;
    event->process_id = context->process_id;
    event->process_start_key = context->process_start_key;
    event->flow_id = context->flow_id;
    event->sequence = context->sequence;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->interface_luid = context->interface_luid;
    event->family = context->family;
    event->local_port = context->local_port;
    event->remote_port = context->remote_port;
    event->state = context->state;
    event->direction = context->direction;
    event->indicated_length = context->indicated_length;
    event->copied_length = context->copied_length;
    event->missed_bytes = context->missed_bytes;
    event->data_length = 0;
    event->reserved = 0;
    event->reserved_3 = 0;

    if (context->family == AF_INET) {
        event->local_ip4 = context->local_ip4;
        event->remote_ip4 = context->remote_ip4;
    } else {
        __builtin_memcpy(event->local_ip6, context->local_ip6, sizeof(event->local_ip6));
        __builtin_memcpy(event->remote_ip6, context->remote_ip6, sizeof(event->remote_ip6));
    }

    unsigned char* cursor = context->data_start;
#pragma unroll
    for (uint16_t index = 0; index < OBI_FLOW_CAPTURE_SIZE; index++) {
        if (cursor == 0 || cursor + 1 > context->data_end) {
            break;
        }
        event->data[index] = *cursor;
        event->data_length++;
        cursor++;
    }

    bpf_ringbuf_output(&flow_events, event, sizeof(*event), 0);
    return context->state == EBPF_FLOW_STATE_DELETED ? EBPF_FLOW_CLASSIFY_ALLOW
                                                    : EBPF_FLOW_CLASSIFY_NEED_MORE_DATA;
}
