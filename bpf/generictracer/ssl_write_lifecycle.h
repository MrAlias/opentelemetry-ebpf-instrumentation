// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/ssl_args.h>

#include <maps/active_ssl_shutdown_args.h>
#include <maps/active_ssl_write_args.h>

enum ssl_write_return_state : u8 {
    k_ssl_write_return_missing = 0,
    k_ssl_write_return_nested = 1,
    k_ssl_write_return_outer = 2,
    k_ssl_write_return_unsafe = 3,
};

enum ssl_wrapper_entry_action : u8 {
    k_ssl_wrapper_entry_nested = 1,
    k_ssl_wrapper_entry_replace_tail = 2,
    k_ssl_wrapper_entry_recover_stale = 3,
    k_ssl_wrapper_entry_unsafe = 4,
};

enum ssl_write_api : u8 {
    k_ssl_write_api_unknown = 0,
    k_ssl_write_api_write = 1,
    k_ssl_write_api_write_ex = 2,
    k_ssl_write_api_write_ex2 = 3,
    k_ssl_write_api_crypto_native = 4,
};

enum ssl_shutdown_api : u8 {
    k_ssl_shutdown_api_unknown = 0,
    k_ssl_shutdown_api_shutdown = 1,
    k_ssl_shutdown_api_crypto_native = 2,
};

enum : u32 {
    k_ssl_wrapper_max_stack_bytes = 64 * 1024,
};

static __always_inline void initialize_ssl_write_args(ssl_args_t *args,
                                                      u64 ssl,
                                                      u64 buffer,
                                                      u64 len_ptr,
                                                      u64 handoff_id,
                                                      u64 requested_len,
                                                      u64 stack_pointer,
                                                      enum ssl_write_api api,
                                                      enum ssl_write_api wrapper_outer_api) {
    if (!args) {
        return;
    }
    *args = (ssl_args_t){
        .ssl = ssl,
        .buf = buffer,
        .len_ptr = len_ptr,
        .handoff_id = handoff_id,
        .requested_len = requested_len,
        .stack_pointer = stack_pointer,
        .depth = 1,
        .write_api = api,
        .nested_write_api = wrapper_outer_api,
        .tail_wrapper = wrapper_outer_api != 0,
    };
}

static __always_inline void
transfer_ssl_write_handoff(ssl_args_t *replacement, u64 handoff_id, u64 flags) {
    if (!replacement) {
        return;
    }
    replacement->handoff_id = handoff_id;
    replacement->flags |= flags & (FLAG_CONNECTED | FLAG_SSL_PREWRITE_PUBLISHED);
}

static __always_inline void initialize_ssl_shutdown_args(ssl_shutdown_args_t *args,
                                                         u64 ssl,
                                                         u64 stack_pointer,
                                                         enum ssl_shutdown_api api,
                                                         enum ssl_shutdown_api wrapper_outer_api) {
    if (!args) {
        return;
    }
    *args = (ssl_shutdown_args_t){
        .ssl = ssl,
        .stack_pointer = stack_pointer,
        .depth = 1,
        .api = api,
        .nested_api = wrapper_outer_api,
        .tail_wrapper = wrapper_outer_api != 0,
    };
}

static __always_inline u8 ssl_wrapper_stack_matches(u64 outer_stack_pointer,
                                                    u64 nested_stack_pointer) {
    return outer_stack_pointer && nested_stack_pointer &&
           nested_stack_pointer <= outer_stack_pointer &&
           outer_stack_pointer - nested_stack_pointer <= k_ssl_wrapper_max_stack_bytes;
}

static __always_inline u8 ssl_write_wrapper_transition(enum ssl_write_api outer,
                                                       enum ssl_write_api nested) {
    return (outer == k_ssl_write_api_write_ex && nested == k_ssl_write_api_write_ex2) ||
           (outer == k_ssl_write_api_crypto_native && nested == k_ssl_write_api_write);
}

static __always_inline u8 ssl_shutdown_wrapper_transition(enum ssl_shutdown_api outer,
                                                          enum ssl_shutdown_api nested) {
    return outer == k_ssl_shutdown_api_crypto_native && nested == k_ssl_shutdown_api_shutdown;
}

static __always_inline u8 ssl_write_wrapper_matches(const ssl_args_t *active,
                                                    u64 ssl,
                                                    u64 buffer,
                                                    u64 len_ptr,
                                                    u64 requested_len,
                                                    u64 api_flags,
                                                    enum ssl_write_api nested_api,
                                                    u64 nested_stack_pointer) {
    return active && ssl_write_wrapper_transition(active->write_api, nested_api) &&
           active->ssl == ssl && active->buf == buffer && active->len_ptr == len_ptr &&
           active->requested_len == requested_len && api_flags == 0 &&
           ssl_wrapper_stack_matches(active->stack_pointer, nested_stack_pointer);
}

static __always_inline u8 ssl_shutdown_wrapper_matches(const ssl_shutdown_args_t *active,
                                                       u64 ssl,
                                                       enum ssl_shutdown_api nested_api,
                                                       u64 nested_stack_pointer) {
    return active && ssl_shutdown_wrapper_transition(active->api, nested_api) &&
           active->ssl == ssl &&
           ssl_wrapper_stack_matches(active->stack_pointer, nested_stack_pointer);
}

static __always_inline u8 ssl_write_args_recoverable(const ssl_args_t *active,
                                                     u64 stack_pointer,
                                                     u64 now,
                                                     u64 max_age_ns) {
    return active && active->handoff_id && active->stack_pointer && stack_pointer && now &&
           max_age_ns && now >= active->handoff_id && now - active->handoff_id > max_age_ns &&
           stack_pointer >= active->stack_pointer;
}

static __always_inline enum ssl_wrapper_entry_action
ssl_write_wrapper_entry_action(const ssl_args_t *active,
                               u64 ssl,
                               u64 buffer,
                               u64 len_ptr,
                               u64 requested_len,
                               u64 api_flags,
                               enum ssl_write_api nested_api,
                               u64 nested_stack_pointer,
                               u64 now,
                               u64 max_age_ns) {
    if (ssl_write_args_recoverable(active, nested_stack_pointer, now, max_age_ns)) {
        return k_ssl_wrapper_entry_recover_stale;
    }
    if (!ssl_write_wrapper_matches(active,
                                   ssl,
                                   buffer,
                                   len_ptr,
                                   requested_len,
                                   api_flags,
                                   nested_api,
                                   nested_stack_pointer)) {
        return k_ssl_wrapper_entry_unsafe;
    }
    return k_ssl_wrapper_entry_replace_tail;
}

static __always_inline enum ssl_wrapper_entry_action
ssl_shutdown_wrapper_entry_action(const ssl_shutdown_args_t *active,
                                  u64 ssl,
                                  enum ssl_shutdown_api nested_api,
                                  u64 nested_stack_pointer) {
    if (!ssl_shutdown_wrapper_matches(active, ssl, nested_api, nested_stack_pointer)) {
        return k_ssl_wrapper_entry_unsafe;
    }
    return k_ssl_wrapper_entry_replace_tail;
}

static __always_inline enum ssl_write_return_state take_ssl_write_args(
    u64 id, u64 thread_start_time, enum ssl_write_api returning_api, ssl_args_t *saved) {
    if (!id || !thread_start_time) {
        return k_ssl_write_return_missing;
    }
    const ssl_thread_key_t key = ssl_thread_key(id, thread_start_time);
    ssl_args_t *active = bpf_map_lookup_elem(&active_ssl_write_args, &key);
    if (!active || !saved) {
        return k_ssl_write_return_missing;
    }
    if (active->unsafe_nested_write) {
        *saved = *active;
        bpf_map_delete_elem(&active_ssl_write_args, &key);
        return k_ssl_write_return_unsafe;
    }
    if (active->tail_wrapper) {
        if (active->depth == 1 && active->nested_write_api &&
            (active->write_api == returning_api || active->nested_write_api == returning_api)) {
            *saved = *active;
            bpf_map_delete_elem(&active_ssl_write_args, &key);
            return k_ssl_write_return_outer;
        }

        *saved = *active;
        bpf_map_delete_elem(&active_ssl_write_args, &key);
        return k_ssl_write_return_unsafe;
    }
    if (active->depth > 1) {
        if (active->nested_write_api == returning_api) {
            active->depth--;
            if (active->depth == 1) {
                active->nested_write_api = 0;
            }
            return k_ssl_write_return_nested;
        }

        *saved = *active;
        bpf_map_delete_elem(&active_ssl_write_args, &key);
        return k_ssl_write_return_unsafe;
    }
    if (active->depth != 1 || active->write_api != returning_api) {
        *saved = *active;
        bpf_map_delete_elem(&active_ssl_write_args, &key);
        return k_ssl_write_return_unsafe;
    }

    *saved = *active;
    bpf_map_delete_elem(&active_ssl_write_args, &key);
    return k_ssl_write_return_outer;
}

static __always_inline enum ssl_write_return_state
take_ssl_shutdown_args(u64 id,
                       u64 thread_start_time,
                       enum ssl_shutdown_api returning_api,
                       ssl_shutdown_args_t *saved) {
    if (!id || !thread_start_time) {
        return k_ssl_write_return_missing;
    }
    const ssl_thread_key_t key = ssl_thread_key(id, thread_start_time);
    ssl_shutdown_args_t *active = bpf_map_lookup_elem(&active_ssl_shutdown_args, &key);
    if (!active || !saved) {
        return k_ssl_write_return_missing;
    }
    if (active->unsafe_nested) {
        *saved = *active;
        bpf_map_delete_elem(&active_ssl_shutdown_args, &key);
        return k_ssl_write_return_unsafe;
    }
    if (active->tail_wrapper) {
        if (active->depth == 1 && active->nested_api &&
            (active->api == returning_api || active->nested_api == returning_api)) {
            *saved = *active;
            bpf_map_delete_elem(&active_ssl_shutdown_args, &key);
            return k_ssl_write_return_outer;
        }

        *saved = *active;
        bpf_map_delete_elem(&active_ssl_shutdown_args, &key);
        return k_ssl_write_return_unsafe;
    }
    if (active->depth > 1) {
        if (active->nested_api == returning_api) {
            active->depth--;
            if (active->depth == 1) {
                active->nested_api = 0;
            }
            return k_ssl_write_return_nested;
        }

        *saved = *active;
        bpf_map_delete_elem(&active_ssl_shutdown_args, &key);
        return k_ssl_write_return_unsafe;
    }
    if (active->depth != 1 || active->api != returning_api) {
        *saved = *active;
        bpf_map_delete_elem(&active_ssl_shutdown_args, &key);
        return k_ssl_write_return_unsafe;
    }

    *saved = *active;
    bpf_map_delete_elem(&active_ssl_shutdown_args, &key);
    return k_ssl_write_return_outer;
}
