// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include "bpf_helpers.h"
#include "ebpf_ntos_hooks.h"

#define IMAGE_PATH_SIZE 1024
#define PROCESS_RINGBUF_SIZE (64 * 1024)

typedef struct {
  uint64_t process_id;
  uint64_t creation_time;
  int32_t image_path_length;
  uint8_t operation;
  uint8_t reserved[3];
  uint8_t image_path[IMAGE_PATH_SIZE];
} obi_process_start_event_t;

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, uint32_t);
  __type(value, obi_process_start_event_t);
  __uint(max_entries, 1);
} event_scratch SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, PROCESS_RINGBUF_SIZE);
} process_events SEC(".maps");

process_hook_t obi_process_start;

SEC("process")
int obi_process_start(process_md_t *ctx) {
  uint32_t key = 0;
  obi_process_start_event_t *event;

  if (ctx->operation != PROCESS_OPERATION_CREATE) {
    return 0;
  }

  event = bpf_map_lookup_elem(&event_scratch, &key);
  if (event == NULL) {
    return 0;
  }

  memset(event, 0, sizeof(*event));
  event->process_id = ctx->process_id;
  event->creation_time = ctx->creation_time;
  event->operation = ctx->operation;
  event->image_path_length = bpf_process_get_image_path(
      ctx, event->image_path, sizeof(event->image_path));
  if (event->image_path_length < 0) {
    event->image_path_length = 0;
  }

  bpf_ringbuf_output(&process_events, event, sizeof(*event), 0);
  return 0;
}
