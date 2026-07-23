// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>
#include <bpfcore/compiler.h>

#include <common/connection_info.h>
#include <common/http_status.h>
#include <common/ssl_args.h>
#include <common/tp_info.h>

#include <maps/active_ssl_connections.h>
#include <maps/ssl_prewrite_tp.h>
#include <maps/ssl_to_conn.h>

static __always_inline ssl_pid_key_t ssl_pid_key(u64 ssl, u32 pid, u64 process_start_time) {
    const ssl_pid_key_t key = {
        .ssl = ssl,
        .process_start_time = process_start_time,
        .pid = pid,
    };
    return key;
}

static __always_inline ssl_pid_connection_info_t *
lookup_ssl_connection(u64 ssl, u32 pid, u64 process_start_time) {
    if (!process_start_time) {
        return NULL;
    }
    const ssl_pid_key_t key = ssl_pid_key(ssl, pid, process_start_time);
    return bpf_map_lookup_elem(&ssl_to_conn, &key);
}

static __always_inline long update_ssl_connection(u64 ssl,
                                                  const ssl_pid_connection_info_t *connection,
                                                  u64 process_start_time,
                                                  u64 flags) {
    if (!process_start_time) {
        return -1;
    }
    const ssl_pid_key_t key = ssl_pid_key(ssl, connection->p_conn.pid, process_start_time);
    return bpf_map_update_elem(&ssl_to_conn, &key, connection, flags);
}

static __always_inline void delete_ssl_connection(u64 ssl, u32 pid, u64 process_start_time) {
    if (!process_start_time) {
        return;
    }
    const ssl_pid_key_t key = ssl_pid_key(ssl, pid, process_start_time);
    bpf_map_delete_elem(&ssl_to_conn, &key);
}

static __always_inline void
reset_ssl_prewrite(u64 pid_tgid, u64 thread_start_time, u64 handoff_id) {
    if (!thread_start_time || !pid_tgid || !handoff_id) {
        return;
    }
    const ssl_prewrite_key_t key = ssl_prewrite_key(pid_tgid, thread_start_time, handoff_id);
    bpf_map_delete_elem(&ssl_prewrite_tp, &key);
}

static __always_inline u64 *is_ssl_connection(const pid_connection_info_t *conn) {
    return (u64 *)bpf_map_lookup_elem(&active_ssl_connections, conn);
}

static __always_inline u8
ssl_prewrite_connection_should_cleanup(const pid_connection_info_t *connection, u64 netns_cookie) {
    return connection && netns_cookie &&
           (is_ssl_connection(connection) ||
            ssl_prewrite_connection_tracked(&connection->conn, netns_cookie));
}

static __always_inline bool
ssl_connection_mapping_matches(const ssl_pid_connection_info_t *stored,
                               const pid_connection_info_t *connection) {
    return stored && __builtin_memcmp(&stored->p_conn, connection, sizeof(*connection)) == 0;
}

static __always_inline enum ssl_prewrite_publish_result
publish_ssl_prewrite_connection_owner(const ssl_prewrite_key_t *prewrite_key,
                                      const ssl_prewrite_value_t *prewrite) {
    connection_info_netns_cookie_t *connection_key =
        ssl_prewrite_connection_key(&prewrite->connection.conn, prewrite->netns_cookie);
    ssl_prewrite_connection_owner_t *claim =
        (ssl_prewrite_connection_owner_t *)prewrite_connection_claim_candidate_mem();
    if (!connection_key || !claim) {
        return k_ssl_prewrite_publish_overload;
    }
    if (bpf_map_lookup_elem(&ssl_prewrite_connection_ambiguity, connection_key)) {
        return k_ssl_prewrite_publish_ambiguous;
    }

    __builtin_memset(claim, 0, sizeof(*claim));
    claim->key = *prewrite_key;
    claim->observed_monotime_ns = prewrite->observed_monotime_ns;
    claim->state = k_ssl_prewrite_connection_owner_published;
    if (bpf_map_update_elem(&ssl_prewrite_connection_claims, connection_key, claim, BPF_NOEXIST) !=
        0) {
        block_ssl_prewrite_connection(
            &prewrite->connection.conn, prewrite->netns_cookie, prewrite->observed_monotime_ns);
        return k_ssl_prewrite_publish_ambiguous;
    }

    enum ssl_prewrite_publish_result result = k_ssl_prewrite_publish_valid;
    u64 update_flags = BPF_NOEXIST;
    u8 replace_previous = 0;
    ssl_prewrite_key_t previous_key = {};
    const ssl_prewrite_connection_owner_t *previous =
        bpf_map_lookup_elem(&ssl_prewrite_connection_owners, connection_key);
    if (previous) {
        if (ssl_prewrite_connection_owner_matches(previous, prewrite_key)) {
            update_flags = BPF_EXIST;
        } else {
            previous_key = previous->key;
            const ssl_prewrite_value_t *previous_prewrite =
                previous->state == k_ssl_prewrite_connection_owner_published
                    ? bpf_map_lookup_elem(&ssl_prewrite_tp, &previous_key)
                    : NULL;
            const u8 reusable =
                previous_prewrite &&
                previous_prewrite->transport_phase == k_ssl_prewrite_transport_accepted &&
                previous_prewrite->write_outcome == k_ssl_prewrite_write_succeeded &&
                previous_prewrite->reuse_state == k_ssl_prewrite_reuse_ready;
            if (!reusable) {
                result = k_ssl_prewrite_publish_ambiguous;
                goto done;
            }
            update_flags = BPF_EXIST;
            replace_previous = 1;
        }
    }

    if (bpf_map_lookup_elem(&ssl_prewrite_connection_ambiguity, connection_key) ||
        bpf_map_update_elem(&ssl_prewrite_connection_owners, connection_key, claim, update_flags) !=
            0) {
        result = k_ssl_prewrite_publish_overload;
        goto done;
    }

    const ssl_prewrite_connection_owner_t *stored =
        bpf_map_lookup_elem(&ssl_prewrite_connection_owners, connection_key);
    const ssl_prewrite_connection_owner_t *stored_claim =
        bpf_map_lookup_elem(&ssl_prewrite_connection_claims, connection_key);
    if (!ssl_prewrite_connection_owner_matches(stored, prewrite_key) ||
        !ssl_prewrite_connection_owner_matches(stored_claim, prewrite_key) ||
        bpf_map_lookup_elem(&ssl_prewrite_connection_ambiguity, connection_key)) {
        result = k_ssl_prewrite_publish_ambiguous;
        goto done;
    }

    if (replace_previous) {
        bpf_map_delete_elem(&ssl_prewrite_tp, &previous_key);
    }

done:;
    const ssl_prewrite_connection_owner_t *final_claim =
        bpf_map_lookup_elem(&ssl_prewrite_connection_claims, connection_key);
    const ssl_prewrite_connection_ambiguity_t *ambiguity =
        bpf_map_lookup_elem(&ssl_prewrite_connection_ambiguity, connection_key);
    const ssl_prewrite_connection_owner_t *final_owner =
        bpf_map_lookup_elem(&ssl_prewrite_connection_owners, connection_key);
    u8 claim_owned = ssl_prewrite_connection_key_matches(final_claim, prewrite_key);
    u8 closing = (ambiguity && ambiguity->state == k_ssl_prewrite_connection_closing) ||
                 (final_claim && final_claim->state == k_ssl_prewrite_connection_owner_closing) ||
                 (final_owner && final_owner->state == k_ssl_prewrite_connection_owner_closing);
    if (!claim_owned || closing) {
        if (claim_owned) {
            bpf_map_delete_elem(&ssl_prewrite_connection_claims, connection_key);
        }
        if (closing) {
            cleanup_ssl_prewrite_connection(&prewrite->connection.conn, prewrite->netns_cookie);
        }
        return k_ssl_prewrite_publish_ambiguous;
    }

    if (result != k_ssl_prewrite_publish_valid) {
        block_ssl_prewrite_connection(
            &prewrite->connection.conn, prewrite->netns_cookie, prewrite->observed_monotime_ns);
    }
    final_claim = bpf_map_lookup_elem(&ssl_prewrite_connection_claims, connection_key);
    ambiguity = bpf_map_lookup_elem(&ssl_prewrite_connection_ambiguity, connection_key);
    final_owner = bpf_map_lookup_elem(&ssl_prewrite_connection_owners, connection_key);
    claim_owned = ssl_prewrite_connection_key_matches(final_claim, prewrite_key);
    closing = (ambiguity && ambiguity->state == k_ssl_prewrite_connection_closing) ||
              (final_claim && final_claim->state == k_ssl_prewrite_connection_owner_closing) ||
              (final_owner && final_owner->state == k_ssl_prewrite_connection_owner_closing);
    if (!claim_owned || closing) {
        if (claim_owned) {
            bpf_map_delete_elem(&ssl_prewrite_connection_claims, connection_key);
        }
        if (closing) {
            cleanup_ssl_prewrite_connection(&prewrite->connection.conn, prewrite->netns_cookie);
        }
        return k_ssl_prewrite_publish_ambiguous;
    }

    bpf_map_delete_elem(&ssl_prewrite_connection_claims, connection_key);
    ambiguity = bpf_map_lookup_elem(&ssl_prewrite_connection_ambiguity, connection_key);
    final_owner = bpf_map_lookup_elem(&ssl_prewrite_connection_owners, connection_key);
    closing = (ambiguity && ambiguity->state == k_ssl_prewrite_connection_closing) ||
              (final_owner && final_owner->state == k_ssl_prewrite_connection_owner_closing);
    if (closing) {
        cleanup_ssl_prewrite_connection(&prewrite->connection.conn, prewrite->netns_cookie);
        result = k_ssl_prewrite_publish_ambiguous;
    }
    if (result == k_ssl_prewrite_publish_valid &&
        (ambiguity || !ssl_prewrite_connection_owner_matches(final_owner, prewrite_key))) {
        result = k_ssl_prewrite_publish_ambiguous;
    }
    return result;
}

static __always_inline void
mark_ssl_prewrite_connection_reusable(const pid_connection_info_t *connection,
                                      u64 netns_cookie,
                                      u8 request_type,
                                      u8 ssl,
                                      u8 direction,
                                      u8 response_direction,
                                      u16 response_status,
                                      u64 start_monotime_ns,
                                      const tp_info_t *trace) {
    if (!connection || !netns_cookie || response_direction != TCP_RECV ||
        !http_response_status_is_final(response_status) ||
        ssl_prewrite_connection_is_ambiguous(&connection->conn, netns_cookie)) {
        return;
    }
    connection_info_netns_cookie_t *connection_key =
        ssl_prewrite_connection_key(&connection->conn, netns_cookie);
    if (!connection_key) {
        return;
    }
    const ssl_prewrite_connection_owner_t *owner =
        bpf_map_lookup_elem(&ssl_prewrite_connection_owners, connection_key);
    if (!owner || owner->state != k_ssl_prewrite_connection_owner_published) {
        return;
    }
    const ssl_prewrite_key_t key = owner->key;
    ssl_prewrite_value_t *value = bpf_map_lookup_elem(&ssl_prewrite_tp, &key);
    if (!value ||
        !ssl_prewrite_value_matches(value, connection, value->destination_port, netns_cookie) ||
        value->transport_phase != k_ssl_prewrite_transport_accepted ||
        value->write_outcome != k_ssl_prewrite_write_succeeded ||
        !ssl_prewrite_transport_local_fields_match(
            value, request_type, ssl, direction, start_monotime_ns, trace)) {
        return;
    }

    value->reuse_state = k_ssl_prewrite_reuse_ready;
    barrier();
    owner = bpf_map_lookup_elem(&ssl_prewrite_connection_owners, connection_key);
    if (!ssl_prewrite_connection_owner_matches(owner, &key) ||
        bpf_map_lookup_elem(&ssl_prewrite_connection_ambiguity, connection_key)) {
        value->reuse_state = k_ssl_prewrite_reuse_none;
    }
}

static __always_inline enum ssl_prewrite_publish_result
update_ssl_prewrite(const pid_connection_info_t *connection,
                    u16 destination_port,
                    u64 netns_cookie,
                    u64 ssl,
                    u64 buffer,
                    u32 bytes_len,
                    u64 thread_start_time,
                    u64 pid_tgid,
                    u64 handoff_id,
                    u64 observed_monotime_ns,
                    const tp_info_pid_t *trace) {
    if (!thread_start_time || !pid_tgid || !handoff_id || !netns_cookie || !observed_monotime_ns) {
        return k_ssl_prewrite_publish_overload;
    }
    ssl_prewrite_value_t *value = ssl_prewrite_value_mem();
    if (!value) {
        return k_ssl_prewrite_publish_overload;
    }
    __builtin_memset(value, 0, sizeof(*value));
    value->connection = *connection;
    sort_connection_info(&value->connection.conn);
    value->netns_cookie = netns_cookie;
    value->ssl = ssl;
    value->buffer = buffer;
    value->bytes_len = bytes_len;
    value->destination_port = destination_port;
    value->observed_monotime_ns = observed_monotime_ns;
    value->trace = *trace;

    const ssl_prewrite_key_t key = ssl_prewrite_key(pid_tgid, thread_start_time, handoff_id);
    if (bpf_map_update_elem(&ssl_prewrite_tp, &key, value, BPF_NOEXIST) != 0) {
        return k_ssl_prewrite_publish_overload;
    }
    const enum ssl_prewrite_publish_result result =
        publish_ssl_prewrite_connection_owner(&key, value);
    if (result != k_ssl_prewrite_publish_valid) {
        bpf_map_delete_elem(&ssl_prewrite_tp, &key);
    }
    return result;
}

static __always_inline ssl_prewrite_value_t *
lookup_ssl_prewrite(u64 pid_tgid, u64 thread_start_time, u64 handoff_id) {
    if (!pid_tgid || !thread_start_time || !handoff_id) {
        return NULL;
    }
    const ssl_prewrite_key_t key = ssl_prewrite_key(pid_tgid, thread_start_time, handoff_id);
    return bpf_map_lookup_elem(&ssl_prewrite_tp, &key);
}

static __always_inline u8 capture_ssl_prewrite_tcp_sequence(const pid_connection_info_t *connection,
                                                            u16 destination_port,
                                                            u64 netns_cookie,
                                                            u64 now,
                                                            u64 max_age_ns,
                                                            u32 tcp_sequence) {
    if (!connection || !netns_cookie ||
        ssl_prewrite_connection_is_ambiguous(&connection->conn, netns_cookie)) {
        return 0;
    }

    connection_info_netns_cookie_t *connection_key =
        ssl_prewrite_connection_key(&connection->conn, netns_cookie);
    if (!connection_key) {
        return 0;
    }
    const ssl_prewrite_connection_owner_t *owner =
        bpf_map_lookup_elem(&ssl_prewrite_connection_owners, connection_key);
    if (!owner || owner->state != k_ssl_prewrite_connection_owner_published) {
        return 0;
    }
    const ssl_prewrite_key_t key = owner->key;
    ssl_prewrite_value_t *value = bpf_map_lookup_elem(&ssl_prewrite_tp, &key);
    if (!value || ssl_prewrite_expired(value, now, max_age_ns) ||
        !ssl_prewrite_value_matches(value, connection, destination_port, netns_cookie) ||
        (value->write_outcome != k_ssl_prewrite_write_pending &&
         value->write_outcome != k_ssl_prewrite_write_succeeded) ||
        value->transport_phase != k_ssl_prewrite_transport_none) {
        return 0;
    }

    if (value->target_tcp_sequence_valid) {
        return 1;
    }

    value->target_tcp_sequence = tcp_sequence;
    barrier();
    value->target_tcp_sequence_valid = 1;
    return 1;
}

static __always_inline void cleanup_completed_ssl_prewrite(const ssl_prewrite_key_t *key) {
    ssl_prewrite_value_t *value = bpf_map_lookup_elem(&ssl_prewrite_tp, key);
    if (value && value->write_outcome != k_ssl_prewrite_write_pending &&
        ssl_prewrite_transport_terminal(value->transport_phase)) {
        connection_info_netns_cookie_t *connection_key =
            ssl_prewrite_connection_key(&value->connection.conn, value->netns_cookie);
        if (!connection_key) {
            return;
        }
        const ssl_prewrite_connection_owner_t *owner =
            bpf_map_lookup_elem(&ssl_prewrite_connection_owners, connection_key);
        if (!ssl_prewrite_connection_owner_matches(owner, key) ||
            bpf_map_lookup_elem(&ssl_prewrite_connection_ambiguity, connection_key)) {
            bpf_map_delete_elem(&ssl_prewrite_tp, key);
        }
    }
}

static __always_inline void mark_java_tls_connection(const connection_info_t *claimed,
                                                     const connection_info_t *authoritative,
                                                     u32 pid) {
    if (is_empty_connection_info(claimed) ||
        __builtin_memcmp(claimed, authoritative, sizeof(*claimed)) != 0) {
        return;
    }

    pid_connection_info_t connection = {.conn = *authoritative, .pid = pid};
    sort_connection_info(&connection.conn);

    const u64 java_tls = 0;
    bpf_map_update_elem(&active_ssl_connections, &connection, &java_tls, BPF_NOEXIST);
}
