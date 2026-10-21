// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build obi_bpf_ignore

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/bpf_tracing.h>

#include <common/preempt_guard.h>
#include <generictracer/python_http.h>
#include <pid/pid.h>

// GIL-enabled, 64-bit CPython PyTypeObject and multidict 6.9 native layouts.
typedef struct aiohttp_python_type {
    u64 refcount;
    u64 type;
    s64 count;
    u64 name;
    s64 basicsize;
} aiohttp_python_type_t;

typedef struct aiohttp_headers {
    u64 refcount;
    u64 type;
    u64 state;
    s64 used;
    u64 version;
    u8 is_ci;
    u8 _pad[7];
    u64 keys;
} aiohttp_headers_t;

// The first three Writer fields are shared by aiohttp 3.12 and 3.13.
typedef struct aiohttp_writer {
    unsigned char *buf;
    s64 size;
    s64 pos;
} aiohttp_writer_t;

typedef struct aiohttp_serialize_state {
    u64 headers;
    u64 version;
    u64 writer;
    s64 field_start;
    python_task_ref_t task;
    u32 remaining;
    u16 depth;
    u8 disabled;
    u8 supplied;
} aiohttp_serialize_state_t;

enum {
    k_aiohttp_max_headers = 128,
    k_aiohttp_max_header_bytes = 65536,
    k_aiohttp_writer_block = 16 * 1024,
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, u64);
    __type(value, aiohttp_serialize_state_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} aiohttp_serializers SEC(".maps");

static __always_inline int aiohttp_serialize_start(u64 headers) {
    const u64 id = bpf_get_current_pid_tgid();
    if (!g_bpf_header_propagation || !g_bpf_probe_write_user_enabled || !valid_pid(id)) {
        return 0;
    }
    const python_thread_state_t *thread = bpf_map_lookup_elem(&python_thread_state, &id);
    aiohttp_serialize_state_t state = {.headers = headers, .depth = 1};
    if (!thread || !resolve_python_task_ref(id, thread->current_task, &state.task)) {
        return 0;
    }
    aiohttp_serialize_state_t *active = bpf_map_lookup_elem(&aiohttp_serializers, &id);
    if (active && active->task.addr == state.task.addr &&
        active->task.generation == state.task.generation) {
        active->disabled = 1;
        active->depth++;
        return 0;
    }
    bpf_map_delete_elem(&aiohttp_serializers, &id);
    const python_addr_key_t key = python_addr_key(id, state.task.addr);
    bpf_map_delete_elem(&python_http_client_traces, &key);

    aiohttp_headers_t dictionary = {};
    aiohttp_python_type_t type = {};
    const char type_name[] __attribute__((aligned(sizeof(u64)))) =
        "multidict._multidict.CIMultiDict";
    char name[sizeof(type_name)] __attribute__((aligned(sizeof(u64)))) = {};
    if (bpf_probe_read_user(&dictionary, sizeof(dictionary), (const void *)headers) ||
        bpf_probe_read_user(&type, sizeof(type), (const void *)dictionary.type) ||
        type.basicsize != sizeof(dictionary) || dictionary.is_ci != 1 || dictionary.used <= 0 ||
        dictionary.used > k_aiohttp_max_headers ||
        bpf_probe_read_user_str(name, sizeof(name), (const void *)type.name) != sizeof(name) ||
        bpf_memcmp(name, type_name, sizeof(name))) {
        return 0;
    }
    state.version = dictionary.version;
    state.remaining = (u32)dictionary.used * 2;
    bpf_map_update_elem(&aiohttp_serializers, &id, &state, BPF_ANY);
    return 0;
}

SEC("uprobe/_http_writer:serialize_headers")
int BPF_UPROBE_GUARDED(obi_aiohttp_serialize, void *self, void *line, void *headers) {
    (void)ctx;
    (void)self;
    (void)line;
    return aiohttp_serialize_start((u64)headers);
}

SEC("uprobe/_http_writer:serialize_headers_isra")
int BPF_UPROBE_GUARDED(obi_aiohttp_serialize_isra, void *line, void *headers) {
    (void)ctx;
    (void)line;
    return aiohttp_serialize_start((u64)headers);
}

SEC("uretprobe/_http_writer:serialize_headers")
int BPF_URETPROBE_GUARDED(obi_aiohttp_serialize_ret, void *result) {
    (void)ctx;
    (void)result;
    const u64 id = bpf_get_current_pid_tgid();
    aiohttp_serialize_state_t *state = bpf_map_lookup_elem(&aiohttp_serializers, &id);
    if (state && state->depth > 1) {
        state->depth--;
    } else {
        bpf_map_delete_elem(&aiohttp_serializers, &id);
    }
    return 0;
}

SEC("uprobe/_http_writer:write_str")
int BPF_UPROBE_GUARDED(obi_aiohttp_write_str, aiohttp_writer_t *writer, void *value) {
    (void)ctx;
    (void)value;
    if (!g_bpf_header_propagation || !g_bpf_probe_write_user_enabled) {
        return 0;
    }
    const u64 id = bpf_get_current_pid_tgid();
    if (!valid_pid(id)) {
        bpf_map_delete_elem(&aiohttp_serializers, &id);
        return 0;
    }
    aiohttp_serialize_state_t *state = bpf_map_lookup_elem(&aiohttp_serializers, &id);
    if (!state || state->disabled || !state->remaining) {
        return 0;
    }
    aiohttp_writer_t current = {};
    if (bpf_probe_read_user(&current, sizeof(current), writer) || current.pos < 0 ||
        current.pos > k_aiohttp_max_header_bytes || current.size < current.pos ||
        current.size % k_aiohttp_writer_block) {
        state->disabled = 1;
        return 0;
    }
    if (!state->writer) {
        unsigned char first[MIN_HTTP_REQ_SIZE];
        const unsigned char suffix[] __attribute__((aligned(sizeof(u64)))) = " HTTP/1.1\r\n";
        unsigned char end[sizeof(suffix) - 1] __attribute__((aligned(sizeof(u64))));
        if (current.pos < sizeof(end) || bpf_probe_read_user(first, sizeof(first), current.buf) ||
            !is_http_request_buf(first) ||
            bpf_probe_read_user(end, sizeof(end), current.buf + current.pos - sizeof(end)) ||
            bpf_memcmp(end, suffix, sizeof(end))) {
            state->disabled = 1;
            return 0;
        }
        state->writer = (u64)writer;
    } else if (state->writer != (u64)writer) {
        state->disabled = 1;
        return 0;
    }
    state->field_start = current.pos;
    return 0;
}

static __always_inline void aiohttp_append_traceparent(u64 id,
                                                       const aiohttp_serialize_state_t *state,
                                                       const aiohttp_writer_t *writer) {
    const unsigned char prefix[] = "\r\nTraceparent: ";
    const unsigned char terminators[] = "\r\n\r\n";
    unsigned char header[sizeof(prefix) - 1 + TP_MAX_VAL_LENGTH];
    if (writer->pos < 0 || writer->pos > k_aiohttp_max_header_bytes ||
        writer->size - writer->pos < sizeof(header) + sizeof(terminators) - 1) {
        return;
    }
    aiohttp_headers_t dictionary = {};
    if (bpf_probe_read_user(&dictionary, sizeof(dictionary), (const void *)state->headers) ||
        dictionary.version != state->version) {
        return;
    }
    python_task_resolution_t resolution = PYTHON_TASK_NOT_FOUND;
    const tp_info_pid_t *server = find_python_owning_server_trace(id, state->task, &resolution);
    if (!server || !server->valid) {
        return;
    }
    python_http_client_trace_t pending = {
        .generation = state->task.generation,
        .value_offset = (u32)writer->pos + sizeof(prefix) - 1,
        .parent_status = parent_kind(server),
        .trace =
            {
                .tp = server->tp,
                .pid = pid_from_pid_tgid(id),
                .valid = 1,
                .written = 1,
                .req_type = k_event_type_http_client,
            },
    };
    __builtin_memcpy(pending.trace.tp.parent_id, server->tp.span_id, SPAN_ID_SIZE_BYTES);
    urand_bytes(pending.trace.tp.span_id, SPAN_ID_SIZE_BYTES);
    pending.trace.tp.ts = bpf_ktime_get_ns();
    __builtin_memcpy(header, prefix, sizeof(prefix) - 1);
    make_tp_string(header + sizeof(prefix) - 1, &pending.trace.tp);
    const python_addr_key_t key = python_addr_key(id, state->task.addr);
    if (bpf_map_update_elem(&python_http_client_traces, &key, &pending, BPF_ANY)) {
        return;
    }

    const s64 pos = writer->pos + sizeof(header);
    // Write unused capacity first; publishing pos commits the new header.
    if (bpf_probe_write_user(writer->buf + writer->pos, header, sizeof(header)) ||
        bpf_probe_write_user(
            (void *)(state->writer + offsetof(aiohttp_writer_t, pos)), &pos, sizeof(pos))) {
        bpf_map_delete_elem(&python_http_client_traces, &key);
    }
}

SEC("uretprobe/_http_writer:write_str")
int BPF_URETPROBE_GUARDED(obi_aiohttp_write_str_ret, int result) {
    (void)ctx;
    // The verifier cannot infer this guard from state created by another program.
    if (!g_bpf_header_propagation || !g_bpf_probe_write_user_enabled) {
        return 0;
    }
    const u64 id = bpf_get_current_pid_tgid();
    if (!valid_pid(id)) {
        bpf_map_delete_elem(&aiohttp_serializers, &id);
        return 0;
    }
    aiohttp_serialize_state_t *state = bpf_map_lookup_elem(&aiohttp_serializers, &id);
    if (!state || state->disabled || !state->remaining || state->depth != 1) {
        return 0;
    }
    aiohttp_writer_t writer = {};
    if (result < 0 || bpf_probe_read_user(&writer, sizeof(writer), (const void *)state->writer) ||
        writer.pos < state->field_start || writer.pos > writer.size) {
        state->disabled = 1;
        return 0;
    }
    if (!(state->remaining & 1) && writer.pos - state->field_start == TP_MAX_KEY_LENGTH) {
        unsigned char key[TP_MAX_KEY_LENGTH];
        if (bpf_probe_read_user(key, sizeof(key), writer.buf + state->field_start) ||
            stricmp((const char *)key, "traceparent", sizeof(key))) {
            state->supplied = 1;
        }
    }
    state->remaining--;
    if (!state->remaining && !state->supplied) {
        aiohttp_append_traceparent(id, state, &writer);
    }
    return 0;
}
