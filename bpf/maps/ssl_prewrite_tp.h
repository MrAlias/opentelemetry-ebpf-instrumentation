// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_core_read.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/compiler.h>

#include <common/connection_info.h>
#include <common/event_defs.h>
#include <common/map_sizing.h>
#include <common/pin_internal.h>
#include <common/protocol_defs.h>
#include <common/scratch_mem.h>
#include <common/tp_info.h>

#include <pid/pid_helpers.h>

#include <maps/java_remote_parent_shared.h>

typedef struct ssl_prewrite_key {
    u64 pid_tgid;
    u64 thread_start_time;
    u64 handoff_id;
} ssl_prewrite_key_t;

enum ssl_prewrite_connection_owner_state : u32 {
    k_ssl_prewrite_connection_owner_published = 1,
    k_ssl_prewrite_connection_owner_blocked = 2,
    k_ssl_prewrite_connection_owner_closing = 3,
};

enum ssl_prewrite_connection_ambiguity_state : u8 {
    k_ssl_prewrite_connection_ambiguous = 1,
    k_ssl_prewrite_connection_closing = 2,
};

typedef struct ssl_prewrite_connection_ambiguity {
    u64 observed_monotime_ns;
    enum ssl_prewrite_connection_ambiguity_state state;
    u8 reserved[7];
} ssl_prewrite_connection_ambiguity_t;

typedef struct ssl_prewrite_connection_owner {
    ssl_prewrite_key_t key;
    u64 observed_monotime_ns;
    enum ssl_prewrite_connection_owner_state state;
    u32 reserved;
} ssl_prewrite_connection_owner_t;

enum ssl_prewrite_transport_phase : u32 {
    k_ssl_prewrite_transport_none = 0,
    k_ssl_prewrite_transport_scheduled = 1,
    k_ssl_prewrite_transport_reserved = 2,
    k_ssl_prewrite_transport_emitting = 3,
    k_ssl_prewrite_transport_accepted = 4,
    k_ssl_prewrite_transport_occupied = 5,
    k_ssl_prewrite_transport_overload = 6,
    k_ssl_prewrite_transport_closed = 7,
};

enum ssl_prewrite_write_outcome : u32 {
    k_ssl_prewrite_write_pending = 0,
    k_ssl_prewrite_write_succeeded = 1,
    k_ssl_prewrite_write_failed = 2,
};

enum ssl_prewrite_arbitration : u32 {
    k_ssl_prewrite_arbitration_none = 0,
    k_ssl_prewrite_arbitration_write_failed = 1,
    k_ssl_prewrite_arbitration_transport_may_emit = 2,
    k_ssl_prewrite_arbitration_failed_transport = 3,
};

enum ssl_prewrite_validation_result : u8 {
    k_ssl_prewrite_validation_ready = 0,
    k_ssl_prewrite_validation_missing = 1,
    k_ssl_prewrite_validation_stale = 2,
    k_ssl_prewrite_validation_malformed = 3,
    k_ssl_prewrite_validation_ambiguous = 4,
};

enum ssl_prewrite_publish_result : u8 {
    k_ssl_prewrite_publish_valid = 0,
    k_ssl_prewrite_publish_overload = 1,
    k_ssl_prewrite_publish_ambiguous = 2,
};

enum ssl_prewrite_reuse_state : u8 {
    k_ssl_prewrite_reuse_none = 0,
    k_ssl_prewrite_reuse_ready = 1,
};

typedef struct ssl_prewrite_value {
    pid_connection_info_t connection;
    u64 netns_cookie;
    u64 ssl;
    u64 buffer;
    u32 bytes_len;
    u32 target_tcp_sequence;
    u16 destination_port;
    u8 target_tcp_sequence_valid;
    enum ssl_prewrite_reuse_state reuse_state;
    enum ssl_prewrite_transport_phase transport_phase;
    enum ssl_prewrite_write_outcome write_outcome;
    u32 arbitration;
    u64 observed_monotime_ns;
    tp_info_pid_t trace;
} ssl_prewrite_value_t;

_Static_assert(sizeof(ssl_prewrite_key_t) == 24, "SSL prewrite key size mismatch");
_Static_assert(sizeof(ssl_prewrite_connection_owner_t) == 40,
               "SSL prewrite connection owner size mismatch");
_Static_assert(sizeof(ssl_prewrite_connection_ambiguity_t) == 16,
               "SSL prewrite connection ambiguity size mismatch");
_Static_assert(offsetof(ssl_prewrite_value_t, netns_cookie) == 40,
               "SSL prewrite network namespace cookie offset mismatch");
_Static_assert(offsetof(ssl_prewrite_value_t, ssl) == 48,
               "SSL prewrite SSL pointer offset mismatch");
_Static_assert(offsetof(ssl_prewrite_value_t, buffer) == 56, "SSL prewrite buffer offset mismatch");
_Static_assert(offsetof(ssl_prewrite_value_t, bytes_len) == 64,
               "SSL prewrite byte length offset mismatch");
_Static_assert(offsetof(ssl_prewrite_value_t, target_tcp_sequence) == 68,
               "SSL prewrite target TCP sequence offset mismatch");
_Static_assert(offsetof(ssl_prewrite_value_t, destination_port) == 72,
               "SSL prewrite destination port offset mismatch");
_Static_assert(offsetof(ssl_prewrite_value_t, reuse_state) == 75,
               "SSL prewrite reuse state offset mismatch");
_Static_assert(offsetof(ssl_prewrite_value_t, transport_phase) == 76,
               "SSL prewrite transport phase offset mismatch");
_Static_assert(offsetof(ssl_prewrite_value_t, write_outcome) == 80,
               "SSL prewrite write outcome offset mismatch");
_Static_assert(offsetof(ssl_prewrite_value_t, arbitration) == 84,
               "SSL prewrite arbitration offset mismatch");
_Static_assert(offsetof(ssl_prewrite_value_t, observed_monotime_ns) == 88,
               "SSL prewrite observation time offset mismatch");
_Static_assert(offsetof(ssl_prewrite_value_t, trace) == 96, "SSL prewrite trace offset mismatch");
_Static_assert(sizeof(ssl_prewrite_value_t) == 152, "SSL prewrite value size mismatch");

SCRATCH_MEM_TYPED(ssl_prewrite_value, ssl_prewrite_value_t)
SCRATCH_MEM_TYPED(prewrite_connection_key, connection_info_netns_cookie_t)
SCRATCH_MEM_TYPED(prewrite_connection_owner_candidate, ssl_prewrite_connection_owner_t)
SCRATCH_MEM_TYPED(prewrite_connection_claim_candidate, ssl_prewrite_connection_owner_t)
SCRATCH_MEM_TYPED(prewrite_connection_block_claim, ssl_prewrite_connection_owner_t)
SCRATCH_MEM_TYPED(prewrite_connection_cleanup_claim, ssl_prewrite_connection_owner_t)
SCRATCH_MEM_TYPED(prewrite_connection_ambiguity_candidate, ssl_prewrite_connection_ambiguity_t)

static __always_inline ssl_prewrite_key_t ssl_prewrite_key(u64 pid_tgid,
                                                           u64 thread_start_time,
                                                           u64 handoff_id) {
    const ssl_prewrite_key_t key = {
        .pid_tgid = pid_tgid,
        .thread_start_time = thread_start_time,
        .handoff_id = handoff_id,
    };
    return key;
}

static __always_inline u8 ssl_prewrite_value_matches(const ssl_prewrite_value_t *value,
                                                     const pid_connection_info_t *connection,
                                                     u16 destination_port,
                                                     u64 netns_cookie) {
    return value && value->destination_port == destination_port &&
           value->netns_cookie == netns_cookie &&
           __builtin_memcmp(&value->connection, connection, sizeof(*connection)) == 0;
}

static __always_inline u8 ssl_prewrite_postwrite_matches(const ssl_prewrite_value_t *value,
                                                         u64 ssl,
                                                         u64 buffer,
                                                         u32 bytes_len) {
    return value && value->ssl == ssl && value->buffer == buffer && bytes_len > 0 &&
           bytes_len == value->bytes_len;
}

static __always_inline u8
ssl_prewrite_transport_local_fields_match(const ssl_prewrite_value_t *value,
                                          u8 request_type,
                                          u8 ssl,
                                          u8 direction,
                                          u64 start_monotime_ns,
                                          const tp_info_t *trace) {
    return value && trace && request_type == EVENT_HTTP_CLIENT && ssl == WITH_SSL &&
           direction == TCP_SEND && start_monotime_ns &&
           __builtin_memcmp(trace, &value->trace.tp, sizeof(*trace)) == 0;
}

static __always_inline u8 ssl_prewrite_transport_terminal(enum ssl_prewrite_transport_phase phase) {
    return phase == k_ssl_prewrite_transport_accepted ||
           phase == k_ssl_prewrite_transport_occupied ||
           phase == k_ssl_prewrite_transport_overload || phase == k_ssl_prewrite_transport_closed;
}

static __always_inline u8 ssl_prewrite_option_may_emit(enum ssl_prewrite_transport_phase phase) {
    return phase == k_ssl_prewrite_transport_emitting || phase == k_ssl_prewrite_transport_accepted;
}

static __always_inline void ssl_prewrite_mark_write_failed(ssl_prewrite_value_t *value) {
    __sync_fetch_and_add(&value->arbitration, k_ssl_prewrite_arbitration_write_failed);
}

static __always_inline void ssl_prewrite_mark_transport_may_emit(ssl_prewrite_value_t *value) {
    __sync_fetch_and_add(&value->arbitration, k_ssl_prewrite_arbitration_transport_may_emit);
}

static __always_inline u32 ssl_prewrite_arbitration_state(const ssl_prewrite_value_t *value) {
    barrier();
    return value->arbitration;
}

static __always_inline u8 ssl_prewrite_write_may_discard(u32 arbitration) {
    return arbitration == k_ssl_prewrite_arbitration_write_failed;
}

static __always_inline u8 ssl_prewrite_transport_may_emit(u32 arbitration) {
    return arbitration == k_ssl_prewrite_arbitration_transport_may_emit;
}

static __always_inline u8 ssl_prewrite_expired(const ssl_prewrite_value_t *value,
                                               u64 now,
                                               u64 max_age_ns) {
    return !value || !now || !max_age_ns || !value->observed_monotime_ns ||
           now < value->observed_monotime_ns || now - value->observed_monotime_ns > max_age_ns;
}

static __always_inline u8 ssl_prewrite_local_owner_expired(u8 pending,
                                                           u64 handoff_observed_monotime_ns,
                                                           u64 provisional_monotime_ns,
                                                           u64 now,
                                                           u64 max_age_ns) {
    if (!pending) {
        return 0;
    }
    const u64 observed =
        handoff_observed_monotime_ns ? handoff_observed_monotime_ns : provisional_monotime_ns;
    return !now || !max_age_ns || !observed || now < observed || now - observed > max_age_ns;
}

static __always_inline u8 ssl_prewrite_trace_valid(const tp_info_pid_t *trace, u32 pid) {
    return trace && trace->valid == 1 && trace->pid == pid &&
           trace->req_type == EVENT_HTTP_CLIENT &&
           tp_info_pid_provenance(trace) == k_tp_provenance_ssl_prewrite &&
           (*((const u64 *)trace->tp.trace_id) != 0 ||
            *((const u64 *)(trace->tp.trace_id + sizeof(u64))) != 0) &&
           *((const u64 *)trace->tp.span_id) != 0;
}

static __always_inline u8
ssl_prewrite_postwrite_value_structurally_valid(const ssl_prewrite_value_t *value) {
    return value && value->connection.pid && value->netns_cookie && value->ssl && value->buffer &&
           value->bytes_len && value->destination_port && value->connection.conn.s_port &&
           value->connection.conn.d_port && value->target_tcp_sequence_valid <= 1 &&
           value->reuse_state <= k_ssl_prewrite_reuse_ready &&
           ssl_prewrite_trace_valid(&value->trace, value->connection.pid) &&
           value->transport_phase <= k_ssl_prewrite_transport_closed &&
           value->write_outcome <= k_ssl_prewrite_write_failed &&
           value->arbitration <= k_ssl_prewrite_arbitration_failed_transport;
}

static __always_inline u8
ssl_prewrite_shared_value_structurally_valid(const ssl_prewrite_value_t *value) {
    return ssl_prewrite_postwrite_value_structurally_valid(value) &&
           value->target_tcp_sequence_valid == 1;
}

static __always_inline u8 ssl_prewrite_shared_value_valid(const ssl_prewrite_value_t *value,
                                                          u64 now,
                                                          u64 max_age_ns) {
    return ssl_prewrite_shared_value_structurally_valid(value) &&
           !ssl_prewrite_expired(value, now, max_age_ns);
}

static __always_inline u8 ssl_prewrite_ready_to_schedule(const ssl_prewrite_value_t *value,
                                                         u64 now,
                                                         u64 max_age_ns) {
    return ssl_prewrite_shared_value_valid(value, now, max_age_ns) &&
           value->reuse_state == k_ssl_prewrite_reuse_none &&
           value->transport_phase == k_ssl_prewrite_transport_none &&
           (value->write_outcome == k_ssl_prewrite_write_pending ||
            value->write_outcome == k_ssl_prewrite_write_succeeded) &&
           value->arbitration == k_ssl_prewrite_arbitration_none;
}

static __always_inline u8 ssl_prewrite_ready_to_reserve(const ssl_prewrite_value_t *value,
                                                        u64 now,
                                                        u64 max_age_ns) {
    return ssl_prewrite_shared_value_valid(value, now, max_age_ns) &&
           value->reuse_state == k_ssl_prewrite_reuse_none &&
           value->transport_phase == k_ssl_prewrite_transport_scheduled &&
           (value->write_outcome == k_ssl_prewrite_write_pending ||
            value->write_outcome == k_ssl_prewrite_write_succeeded) &&
           value->arbitration == k_ssl_prewrite_arbitration_none;
}

static __always_inline u8 ssl_prewrite_ready_to_emit(const ssl_prewrite_value_t *value,
                                                     u64 now,
                                                     u64 max_age_ns) {
    return ssl_prewrite_shared_value_valid(value, now, max_age_ns) &&
           value->reuse_state == k_ssl_prewrite_reuse_none &&
           value->transport_phase == k_ssl_prewrite_transport_reserved &&
           (value->write_outcome == k_ssl_prewrite_write_pending ||
            value->write_outcome == k_ssl_prewrite_write_succeeded) &&
           value->arbitration == k_ssl_prewrite_arbitration_none;
}

static __always_inline u8 ssl_prewrite_owner_proven_failed(const ssl_prewrite_value_t *value) {
    return value && value->transport_phase == k_ssl_prewrite_transport_scheduled &&
           value->arbitration == k_ssl_prewrite_arbitration_write_failed;
}

static __always_inline enum ssl_prewrite_validation_result
ssl_prewrite_schedule_validation(const ssl_prewrite_value_t *value, u64 now, u64 max_age_ns) {
    if (!value) {
        return k_ssl_prewrite_validation_missing;
    }
    if (ssl_prewrite_expired(value, now, max_age_ns)) {
        return k_ssl_prewrite_validation_stale;
    }
    if (value->target_tcp_sequence_valid == 0) {
        return k_ssl_prewrite_validation_missing;
    }
    if (!ssl_prewrite_shared_value_structurally_valid(value)) {
        return k_ssl_prewrite_validation_malformed;
    }
    if (value->write_outcome == k_ssl_prewrite_write_failed ||
        value->arbitration == k_ssl_prewrite_arbitration_write_failed ||
        value->arbitration == k_ssl_prewrite_arbitration_failed_transport) {
        return k_ssl_prewrite_validation_stale;
    }
    return ssl_prewrite_ready_to_schedule(value, now, max_age_ns)
               ? k_ssl_prewrite_validation_ready
               : k_ssl_prewrite_validation_ambiguous;
}

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, ssl_prewrite_key_t);
    __type(value, ssl_prewrite_value_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} ssl_prewrite_tp SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, connection_info_netns_cookie_t);
    __type(value, ssl_prewrite_connection_owner_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} ssl_prewrite_connection_owners SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, connection_info_netns_cookie_t);
    __type(value, ssl_prewrite_connection_owner_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} ssl_prewrite_connection_claims SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, connection_info_netns_cookie_t);
    __type(value, ssl_prewrite_connection_ambiguity_t);
    __uint(max_entries, MAX_CONCURRENT_SHARED_REQUESTS);
    __uint(pinning, OBI_PIN_INTERNAL);
} ssl_prewrite_connection_ambiguity SEC(".maps");

static __always_inline connection_info_netns_cookie_t *
ssl_prewrite_connection_key(const connection_info_t *connection, u64 netns_cookie) {
    connection_info_netns_cookie_t *key =
        (connection_info_netns_cookie_t *)prewrite_connection_key_mem();
    if (!key || !connection || !netns_cookie) {
        return NULL;
    }
    __builtin_memset(key, 0, sizeof(*key));
    key->connection = *connection;
    sort_connection_info(&key->connection);
    key->netns_cookie = netns_cookie;
    return key;
}

static __always_inline u8 ssl_prewrite_connection_owner_matches(
    const ssl_prewrite_connection_owner_t *owner, const ssl_prewrite_key_t *key) {
    return owner && key && owner->state == k_ssl_prewrite_connection_owner_published &&
           owner->reserved == 0 && __builtin_memcmp(&owner->key, key, sizeof(*key)) == 0;
}

static __always_inline u8 ssl_prewrite_connection_key_matches(
    const ssl_prewrite_connection_owner_t *owner, const ssl_prewrite_key_t *key) {
    return owner && key && owner->reserved == 0 &&
           __builtin_memcmp(&owner->key, key, sizeof(*key)) == 0;
}

static __always_inline u8
ssl_prewrite_connection_key_is_closing(const connection_info_netns_cookie_t *key) {
    const ssl_prewrite_connection_ambiguity_t *ambiguity =
        bpf_map_lookup_elem(&ssl_prewrite_connection_ambiguity, key);
    return ambiguity && ambiguity->state == k_ssl_prewrite_connection_closing;
}

static __always_inline u8 ssl_prewrite_connection_tracked(const connection_info_t *connection,
                                                          u64 netns_cookie) {
    if (!connection || !netns_cookie) {
        return 0;
    }
    connection_info_netns_cookie_t *key = ssl_prewrite_connection_key(connection, netns_cookie);
    if (!key) {
        return 0;
    }
    if (bpf_map_lookup_elem(&ssl_prewrite_connection_owners, key)) {
        return 1;
    }
    if (bpf_map_lookup_elem(&ssl_prewrite_connection_claims, key)) {
        return 1;
    }
    return bpf_map_lookup_elem(&ssl_prewrite_connection_ambiguity, key) != NULL;
}

static __noinline void cleanup_ssl_prewrite_connection(const connection_info_t *connection,
                                                       u64 netns_cookie);

static __always_inline u8 ssl_prewrite_connection_is_ambiguous(const connection_info_t *connection,
                                                               u64 netns_cookie) {
    if (!connection || !netns_cookie) {
        return 1;
    }
    connection_info_netns_cookie_t *key = ssl_prewrite_connection_key(connection, netns_cookie);
    if (!key) {
        return 1;
    }
    const ssl_prewrite_connection_owner_t *owner =
        bpf_map_lookup_elem(&ssl_prewrite_connection_owners, key);
    return bpf_map_lookup_elem(&ssl_prewrite_connection_ambiguity, key) != NULL ||
           (owner && owner->state != k_ssl_prewrite_connection_owner_published);
}

static __always_inline u8 ssl_prewrite_connection_has_exact_owner(
    const ssl_prewrite_value_t *value, const ssl_prewrite_key_t *prewrite_key) {
    if (!value || !prewrite_key || !value->netns_cookie) {
        return 0;
    }
    connection_info_netns_cookie_t *key =
        ssl_prewrite_connection_key(&value->connection.conn, value->netns_cookie);
    if (!key) {
        return 0;
    }
    const ssl_prewrite_connection_owner_t *owner =
        bpf_map_lookup_elem(&ssl_prewrite_connection_owners, key);
    return !bpf_map_lookup_elem(&ssl_prewrite_connection_ambiguity, key) &&
           ssl_prewrite_connection_owner_matches(owner, prewrite_key);
}

static __always_inline u8 block_ssl_prewrite_connection(const connection_info_t *connection,
                                                        u64 netns_cookie,
                                                        u64 now) {
    if (!connection || !netns_cookie) {
        return 0;
    }
    connection_info_netns_cookie_t *key = ssl_prewrite_connection_key(connection, netns_cookie);
    if (!key) {
        return 0;
    }
    if (ssl_prewrite_connection_key_is_closing(key)) {
        return 1;
    }

    ssl_prewrite_connection_owner_t *current_claim =
        bpf_map_lookup_elem(&ssl_prewrite_connection_claims, key);
    if (current_claim && current_claim->state == k_ssl_prewrite_connection_owner_closing) {
        return 1;
    }

    u8 owns_claim = 0;
    if (!current_claim) {
        ssl_prewrite_connection_owner_t *block_claim =
            (ssl_prewrite_connection_owner_t *)prewrite_connection_block_claim_mem();
        if (block_claim) {
            __builtin_memset(block_claim, 0, sizeof(*block_claim));
            block_claim->observed_monotime_ns = now;
            block_claim->state = k_ssl_prewrite_connection_owner_blocked;
            owns_claim = bpf_map_update_elem(
                             &ssl_prewrite_connection_claims, key, block_claim, BPF_NOEXIST) == 0;
        }
        current_claim = bpf_map_lookup_elem(&ssl_prewrite_connection_claims, key);
    }

    u8 closing = ssl_prewrite_connection_key_is_closing(key) ||
                 (current_claim && current_claim->state == k_ssl_prewrite_connection_owner_closing);
    if (closing) {
        if (owns_claim) {
            bpf_map_delete_elem(&ssl_prewrite_connection_claims, key);
            cleanup_ssl_prewrite_connection(connection, netns_cookie);
        }
        return 1;
    }

    ssl_prewrite_connection_ambiguity_t *ambiguity =
        (ssl_prewrite_connection_ambiguity_t *)prewrite_connection_ambiguity_candidate_mem();
    long ambiguity_result = -1;
    if (ambiguity) {
        __builtin_memset(ambiguity, 0, sizeof(*ambiguity));
        ambiguity->observed_monotime_ns = now;
        ambiguity->state = k_ssl_prewrite_connection_ambiguous;
        ambiguity_result =
            bpf_map_update_elem(&ssl_prewrite_connection_ambiguity, key, ambiguity, BPF_NOEXIST);
    }
    if (ambiguity_result != 0 && bpf_map_lookup_elem(&ssl_prewrite_connection_ambiguity, key)) {
        ambiguity_result = 0;
    }

    current_claim = bpf_map_lookup_elem(&ssl_prewrite_connection_claims, key);
    closing = ssl_prewrite_connection_key_is_closing(key) ||
              (current_claim && current_claim->state == k_ssl_prewrite_connection_owner_closing);
    if (closing) {
        if (owns_claim) {
            bpf_map_delete_elem(&ssl_prewrite_connection_claims, key);
            cleanup_ssl_prewrite_connection(connection, netns_cookie);
        }
        return 1;
    }

    ssl_prewrite_connection_owner_t *current_owner =
        bpf_map_lookup_elem(&ssl_prewrite_connection_owners, key);
    long owner_result = 0;
    if (current_owner) {
        if (current_owner->state == k_ssl_prewrite_connection_owner_closing) {
            closing = 1;
        } else {
            current_owner->state = k_ssl_prewrite_connection_owner_blocked;
            barrier();
        }
    } else {
        ssl_prewrite_connection_owner_t *blocked =
            (ssl_prewrite_connection_owner_t *)prewrite_connection_owner_candidate_mem();
        if (!blocked) {
            owner_result = -1;
        } else {
            __builtin_memset(blocked, 0, sizeof(*blocked));
            blocked->observed_monotime_ns = now;
            blocked->state = k_ssl_prewrite_connection_owner_blocked;
            owner_result =
                bpf_map_update_elem(&ssl_prewrite_connection_owners, key, blocked, BPF_NOEXIST);
            if (owner_result != 0) {
                current_owner = bpf_map_lookup_elem(&ssl_prewrite_connection_owners, key);
                if (current_owner) {
                    if (current_owner->state == k_ssl_prewrite_connection_owner_closing) {
                        closing = 1;
                    } else {
                        current_owner->state = k_ssl_prewrite_connection_owner_blocked;
                        barrier();
                        owner_result = 0;
                    }
                }
            }
        }
    }

    current_claim = bpf_map_lookup_elem(&ssl_prewrite_connection_claims, key);
    closing = closing || ssl_prewrite_connection_key_is_closing(key) ||
              (current_claim && current_claim->state == k_ssl_prewrite_connection_owner_closing);
    if (owns_claim) {
        bpf_map_delete_elem(&ssl_prewrite_connection_claims, key);
        current_owner = bpf_map_lookup_elem(&ssl_prewrite_connection_owners, key);
        closing =
            closing || ssl_prewrite_connection_key_is_closing(key) ||
            (current_owner && current_owner->state == k_ssl_prewrite_connection_owner_closing);
        if (closing) {
            cleanup_ssl_prewrite_connection(connection, netns_cookie);
        }
    }
    return ambiguity_result == 0 || owner_result == 0;
}

static __noinline void cleanup_ssl_prewrite_connection(const connection_info_t *connection,
                                                       u64 netns_cookie) {
    if (!connection || !netns_cookie) {
        return;
    }
    connection_info_netns_cookie_t *key = ssl_prewrite_connection_key(connection, netns_cookie);
    ssl_prewrite_connection_owner_t *cleanup_claim =
        (ssl_prewrite_connection_owner_t *)prewrite_connection_cleanup_claim_mem();
    if (!key || !cleanup_claim) {
        return;
    }
    __builtin_memset(cleanup_claim, 0, sizeof(*cleanup_claim));
    cleanup_claim->observed_monotime_ns = bpf_ktime_get_ns();
    cleanup_claim->state = k_ssl_prewrite_connection_owner_closing;
    ssl_prewrite_connection_ambiguity_t *closing =
        (ssl_prewrite_connection_ambiguity_t *)prewrite_connection_ambiguity_candidate_mem();
    if (!closing) {
        return;
    }
    __builtin_memset(closing, 0, sizeof(*closing));
    closing->observed_monotime_ns = cleanup_claim->observed_monotime_ns;
    closing->state = k_ssl_prewrite_connection_closing;
    const long closing_result =
        bpf_map_update_elem(&ssl_prewrite_connection_ambiguity, key, closing, BPF_ANY);
    ssl_prewrite_connection_owner_t *current_owner =
        bpf_map_lookup_elem(&ssl_prewrite_connection_owners, key);
    if (current_owner) {
        current_owner->observed_monotime_ns = cleanup_claim->observed_monotime_ns;
        current_owner->state = k_ssl_prewrite_connection_owner_closing;
        barrier();
    } else if (closing_result != 0) {
        bpf_map_update_elem(&ssl_prewrite_connection_owners, key, cleanup_claim, BPF_NOEXIST);
    }
    if (closing_result != 0) {
        ssl_prewrite_connection_owner_t *current_claim =
            bpf_map_lookup_elem(&ssl_prewrite_connection_claims, key);
        if (current_claim) {
            current_claim->observed_monotime_ns = cleanup_claim->observed_monotime_ns;
            current_claim->state = k_ssl_prewrite_connection_owner_closing;
            barrier();
        } else {
            bpf_map_update_elem(&ssl_prewrite_connection_claims, key, cleanup_claim, BPF_NOEXIST);
        }
        return;
    }

    long claim_result =
        bpf_map_update_elem(&ssl_prewrite_connection_claims, key, cleanup_claim, BPF_NOEXIST);
    if (claim_result != 0) {
        ssl_prewrite_connection_owner_t *current_claim =
            bpf_map_lookup_elem(&ssl_prewrite_connection_claims, key);
        if (current_claim) {
            current_claim->observed_monotime_ns = cleanup_claim->observed_monotime_ns;
            current_claim->state = k_ssl_prewrite_connection_owner_closing;
        }
        current_owner = bpf_map_lookup_elem(&ssl_prewrite_connection_owners, key);
        if (current_owner) {
            current_owner->observed_monotime_ns = cleanup_claim->observed_monotime_ns;
            current_owner->state = k_ssl_prewrite_connection_owner_closing;
        }
        barrier();
        claim_result =
            bpf_map_update_elem(&ssl_prewrite_connection_claims, key, cleanup_claim, BPF_NOEXIST);
        if (claim_result != 0) {
            return;
        }
    }
    if (bpf_map_update_elem(&ssl_prewrite_connection_ambiguity, key, closing, BPF_ANY) != 0) {
        return;
    }

    const ssl_prewrite_connection_owner_t *owner =
        bpf_map_lookup_elem(&ssl_prewrite_connection_owners, key);
    if (owner && owner->key.pid_tgid && owner->key.thread_start_time && owner->key.handoff_id) {
        cleanup_claim->key = owner->key;
        bpf_map_delete_elem(&ssl_prewrite_tp, &cleanup_claim->key);
    }
    bpf_map_delete_elem(&ssl_prewrite_connection_owners, key);
    bpf_map_delete_elem(&ssl_prewrite_connection_claims, key);
}
