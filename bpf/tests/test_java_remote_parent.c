// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common/java_remote_parent.h>
#include <common/tcp_traceparent.h>

enum { BPF_ANY = 0, BPF_NOEXIST = 1, BPF_EXIST = 2 };

static long
fallback_map_update(void *map, const void *key, const void *value, unsigned long long flags);

#define bpf_map_update_elem fallback_map_update
#include <maps/java_remote_parent_fallback.h>
#undef bpf_map_update_elem

static java_remote_parent_response_t fallback_value;
static int fallback_present;

static long
fallback_map_update(void *map, const void *key, const void *value, unsigned long long flags) {
    (void)key;
    if (map != &java_remote_parent_fallback || (flags == BPF_NOEXIST && fallback_present)) {
        return -1;
    }

    fallback_value = *(const java_remote_parent_response_t *)value;
    fallback_present = 1;
    return 0;
}

static void assert_byte(unsigned char expected, unsigned char actual, const char *field) {
    if (expected != actual) {
        fprintf(stderr, "%s: expected 0x%02x, got 0x%02x\n", field, expected, actual);
        exit(1);
    }
}

enum {
    corpus_line_capacity = 512,
    corpus_wire_capacity = 80,
};

enum corpus_case {
    corpus_valid_sampled,
    corpus_valid_unsampled,
    corpus_valid_future_flags,
    corpus_status_only,
    corpus_all_zero_ids,
    corpus_zero_trace_id,
    corpus_zero_span_id,
    corpus_zero_generation,
    corpus_zero_observation,
    corpus_zero_length,
    corpus_pre_magic_truncated,
    corpus_truncated,
    corpus_bad_magic,
    corpus_declared_smaller,
    corpus_declared_larger,
    corpus_reserved_prefix,
    corpus_reserved_suffix,
    corpus_unknown_status_zero,
    corpus_unknown_status_14,
    corpus_unknown_version,
    corpus_unknown_version_bad_size,
    corpus_future_larger_v1,
    corpus_future_larger_unknown_version,
};

struct corpus_spec {
    const char *name;
    const char *status_name;
    enum java_remote_parent_status status;
    int accepted;
    size_t wire_size;
    enum corpus_case kind;
};

static const struct corpus_spec corpus_specs[] = {
    {"valid_sampled", "valid", k_java_remote_parent_status_valid, 1, 64, corpus_valid_sampled},
    {"valid_unsampled", "valid", k_java_remote_parent_status_valid, 1, 64, corpus_valid_unsampled},
    {"valid_future_flags",
     "valid",
     k_java_remote_parent_status_valid,
     1,
     64,
     corpus_valid_future_flags},
    {"status_missing", "missing", k_java_remote_parent_status_missing, 1, 64, corpus_status_only},
    {"status_stale", "stale", k_java_remote_parent_status_stale, 1, 64, corpus_status_only},
    {"status_unsupported",
     "unsupported",
     k_java_remote_parent_status_unsupported,
     1,
     64,
     corpus_status_only},
    {"status_malformed",
     "malformed",
     k_java_remote_parent_status_malformed,
     1,
     64,
     corpus_status_only},
    {"status_version_mismatch",
     "version_mismatch",
     k_java_remote_parent_status_version_mismatch,
     1,
     64,
     corpus_status_only},
    {"status_ambiguous",
     "ambiguous",
     k_java_remote_parent_status_ambiguous,
     1,
     64,
     corpus_status_only},
    {"status_unauthorized",
     "unauthorized",
     k_java_remote_parent_status_unauthorized,
     1,
     64,
     corpus_status_only},
    {"status_already_consumed",
     "already_consumed",
     k_java_remote_parent_status_already_consumed,
     1,
     64,
     corpus_status_only},
    {"status_timeout", "timeout", k_java_remote_parent_status_timeout, 1, 64, corpus_status_only},
    {"status_overload",
     "overload",
     k_java_remote_parent_status_overload,
     1,
     64,
     corpus_status_only},
    {"status_transport_error",
     "transport_error",
     k_java_remote_parent_status_transport_error,
     1,
     64,
     corpus_status_only},
    {"status_disabled",
     "disabled",
     k_java_remote_parent_status_disabled,
     1,
     64,
     corpus_status_only},
    {"all_zero_ids",
     "malformed",
     k_java_remote_parent_status_malformed,
     0,
     64,
     corpus_all_zero_ids},
    {"zero_trace_id",
     "malformed",
     k_java_remote_parent_status_malformed,
     0,
     64,
     corpus_zero_trace_id},
    {"zero_span_id",
     "malformed",
     k_java_remote_parent_status_malformed,
     0,
     64,
     corpus_zero_span_id},
    {"zero_generation",
     "malformed",
     k_java_remote_parent_status_malformed,
     0,
     64,
     corpus_zero_generation},
    {"zero_observation_time",
     "malformed",
     k_java_remote_parent_status_malformed,
     0,
     64,
     corpus_zero_observation},
    {"zero_length", "malformed", k_java_remote_parent_status_malformed, 0, 0, corpus_zero_length},
    {"pre_magic_truncated",
     "malformed",
     k_java_remote_parent_status_malformed,
     0,
     3,
     corpus_pre_magic_truncated},
    {"truncated", "malformed", k_java_remote_parent_status_malformed, 0, 63, corpus_truncated},
    {"bad_magic", "malformed", k_java_remote_parent_status_malformed, 0, 64, corpus_bad_magic},
    {"declared_smaller",
     "malformed",
     k_java_remote_parent_status_malformed,
     0,
     64,
     corpus_declared_smaller},
    {"declared_larger",
     "malformed",
     k_java_remote_parent_status_malformed,
     0,
     64,
     corpus_declared_larger},
    {"reserved_prefix",
     "malformed",
     k_java_remote_parent_status_malformed,
     0,
     64,
     corpus_reserved_prefix},
    {"reserved_suffix",
     "malformed",
     k_java_remote_parent_status_malformed,
     0,
     64,
     corpus_reserved_suffix},
    {"unknown_status_zero",
     "malformed",
     k_java_remote_parent_status_malformed,
     0,
     64,
     corpus_unknown_status_zero},
    {"unknown_status_14",
     "malformed",
     k_java_remote_parent_status_malformed,
     0,
     64,
     corpus_unknown_status_14},
    {"unknown_version",
     "version_mismatch",
     k_java_remote_parent_status_version_mismatch,
     0,
     64,
     corpus_unknown_version},
    {"unknown_version_bad_declared_size",
     "version_mismatch",
     k_java_remote_parent_status_version_mismatch,
     0,
     64,
     corpus_unknown_version_bad_size},
    {"future_larger_v1",
     "malformed",
     k_java_remote_parent_status_malformed,
     0,
     80,
     corpus_future_larger_v1},
    {"future_larger_unknown_version",
     "malformed",
     k_java_remote_parent_status_malformed,
     0,
     80,
     corpus_future_larger_unknown_version},
};

static _Noreturn void corpus_fail(const char *path, size_t line, const char *message) {
    fprintf(stderr, "%s:%zu: %s\n", path, line, message);
    exit(1);
}

static int corpus_name_valid(const char *name) {
    if (name[0] < 'a' || name[0] > 'z') {
        return 0;
    }
    for (size_t index = 1; name[index] != '\0'; index++) {
        const char value = name[index];
        if ((value < 'a' || value > 'z') && (value < '0' || value > '9') && value != '_') {
            return 0;
        }
    }
    return 1;
}

static int split_corpus_fields(char *line, char **fields, size_t field_count) {
    char *cursor = line;
    for (size_t index = 0; index + 1 < field_count; index++) {
        fields[index] = cursor;
        char *separator = strchr(cursor, '|');
        if (separator == NULL) {
            return 0;
        }
        *separator = '\0';
        cursor = separator + 1;
    }
    fields[field_count - 1] = cursor;
    return strchr(cursor, '|') == NULL;
}

static int corpus_hex_nibble(char value) {
    if (value >= '0' && value <= '9') {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    return -1;
}

static size_t
decode_corpus_wire(const char *path, size_t line, const char *encoded, unsigned char *decoded) {
    if (encoded[0] == '\0') {
        corpus_fail(path, line, "wire bytes are missing");
    }
    if (strcmp(encoded, "-") == 0) {
        return 0;
    }

    const size_t encoded_length = strlen(encoded);
    if ((encoded_length & 1) != 0 || encoded_length > corpus_wire_capacity * 2) {
        corpus_fail(path, line, "invalid wire length");
    }

    const size_t decoded_length = encoded_length / 2;
    for (size_t index = 0; index < decoded_length; index++) {
        const int high = corpus_hex_nibble(encoded[index * 2]);
        const int low = corpus_hex_nibble(encoded[index * 2 + 1]);
        if (high < 0 || low < 0) {
            corpus_fail(path, line, "wire bytes must be lower-case hexadecimal");
        }
        decoded[index] = (unsigned char)((high << 4) | low);
    }
    return decoded_length;
}

static int parse_corpus_status(const char *path, size_t line, const char *encoded) {
    errno = 0;
    char *end = NULL;
    const unsigned long value = strtoul(encoded, &end, 10);
    if (errno != 0 || end == encoded || *end != '\0' || value < 1 || value > 13) {
        corpus_fail(path, line, "invalid expected status");
    }
    return (int)value;
}

static size_t find_corpus_spec(const char *path, size_t line, const char *name) {
    for (size_t index = 0; index < sizeof(corpus_specs) / sizeof(corpus_specs[0]); index++) {
        if (strcmp(corpus_specs[index].name, name) == 0) {
            return index;
        }
    }
    corpus_fail(path, line, "unknown vector name");
    return 0;
}

static void corpus_valid_wire(unsigned char *wire, unsigned char flags) {
    tp_info_t tp = {.flags = flags};
    for (u32 index = 0; index < sizeof(tp.trace_id); index++) {
        tp.trace_id[index] = index;
    }
    for (u32 index = 0; index < sizeof(tp.span_id); index++) {
        tp.span_id[index] = index + 16;
    }

    java_remote_parent_response_t response;
    java_remote_parent_init_response(
        &response, k_java_remote_parent_status_valid, 0x0102030405060708ULL, 0x1112131415161718ULL);
    java_remote_parent_set_context(&response, &tp);
    memcpy(wire, &response, sizeof(response));
}

static void corpus_status_wire(unsigned char *wire, enum java_remote_parent_status status) {
    java_remote_parent_response_t response;
    java_remote_parent_init_response(&response, status, 0, 0);
    memcpy(wire, &response, sizeof(response));
}

static size_t expected_corpus_wire(const struct corpus_spec *spec, unsigned char *wire) {
    memset(wire, 0, corpus_wire_capacity);
    if (spec->kind == corpus_status_only) {
        corpus_status_wire(wire, spec->status);
        return spec->wire_size;
    }

    unsigned char flags = 0x01;
    if (spec->kind == corpus_valid_unsampled) {
        flags = 0x00;
    } else if (spec->kind == corpus_valid_future_flags) {
        flags = 0x81;
    }
    corpus_valid_wire(wire, flags);

    switch (spec->kind) {
    case corpus_valid_sampled:
    case corpus_valid_unsampled:
    case corpus_valid_future_flags:
        break;
    case corpus_all_zero_ids:
        memset(wire + 16, 0, 24);
        break;
    case corpus_zero_trace_id:
        memset(wire + 16, 0, 16);
        break;
    case corpus_zero_span_id:
        memset(wire + 32, 0, 8);
        break;
    case corpus_zero_generation:
        memset(wire + 40, 0, 8);
        break;
    case corpus_zero_observation:
        memset(wire + 48, 0, 8);
        break;
    case corpus_zero_length:
        return 0;
    case corpus_pre_magic_truncated:
    case corpus_truncated:
        break;
    case corpus_bad_magic:
        wire[0] = 'X';
        break;
    case corpus_declared_smaller:
        wire[6] = 63;
        break;
    case corpus_declared_larger:
        wire[6] = corpus_wire_capacity;
        break;
    case corpus_reserved_prefix:
        wire[10] = 1;
        break;
    case corpus_reserved_suffix:
        wire[56] = 1;
        break;
    case corpus_unknown_status_zero:
    case corpus_unknown_status_14:
        corpus_status_wire(wire, k_java_remote_parent_status_missing);
        wire[8] = spec->kind == corpus_unknown_status_14 ? 14 : 0;
        break;
    case corpus_unknown_version:
        wire[4] = 2;
        break;
    case corpus_unknown_version_bad_size:
        wire[4] = 2;
        wire[6] = corpus_wire_capacity;
        break;
    case corpus_future_larger_v1:
        wire[6] = corpus_wire_capacity;
        break;
    case corpus_future_larger_unknown_version:
        wire[4] = 2;
        wire[6] = corpus_wire_capacity;
        break;
    case corpus_status_only:
        break;
    }
    return spec->wire_size;
}

static void assert_corpus_wire(const char *path,
                               size_t line,
                               const struct corpus_spec *spec,
                               const unsigned char *wire,
                               size_t wire_length) {
    unsigned char expected[corpus_wire_capacity];
    const size_t expected_length = expected_corpus_wire(spec, expected);
    if (wire_length != expected_length) {
        corpus_fail(path, line, "unexpected wire length");
    }

    for (size_t index = 0; index < wire_length; index++) {
        if (wire[index] != expected[index]) {
            fprintf(stderr,
                    "%s:%zu: %s differs at byte %zu: expected 0x%02x, got 0x%02x\n",
                    path,
                    line,
                    spec->name,
                    index,
                    expected[index],
                    wire[index]);
            exit(1);
        }
    }
}

static void test_response_corpus(const char *path) {
    FILE *file = fopen(path, "rb");
    if (file == NULL) {
        corpus_fail(path, 0, "cannot open corpus");
    }

    int seen[sizeof(corpus_specs) / sizeof(corpus_specs[0])] = {0};
    size_t vector_count = 0;
    size_t line_number = 0;
    int stage = 0;
    char line[corpus_line_capacity];
    while (fgets(line, sizeof(line), file) != NULL) {
        line_number++;
        size_t length = strlen(line);
        if (length == sizeof(line) - 1 && line[length - 1] != '\n' && !feof(file)) {
            corpus_fail(path, line_number, "line is too long");
        }
        while (length > 0 && (line[length - 1] == '\n' || line[length - 1] == '\r')) {
            line[--length] = '\0';
        }
        if (length == 0 || line[0] == '#') {
            continue;
        }
        if (stage == 0) {
            if (strcmp(line, "format|1") != 0) {
                corpus_fail(path, line_number, "unsupported corpus format");
            }
            stage++;
            continue;
        }
        if (stage == 1) {
            if (strcmp(line, "name|outcome|status_name|status|wire_hex") != 0) {
                corpus_fail(path, line_number, "invalid corpus header");
            }
            stage++;
            continue;
        }

        char *fields[5];
        if (!split_corpus_fields(line, fields, 5)) {
            corpus_fail(path, line_number, "expected five fields");
        }
        if (!corpus_name_valid(fields[0])) {
            corpus_fail(path, line_number, "invalid vector name");
        }
        const size_t spec_index = find_corpus_spec(path, line_number, fields[0]);
        const struct corpus_spec *spec = &corpus_specs[spec_index];
        if (seen[spec_index]) {
            corpus_fail(path, line_number, "duplicate vector name");
        }
        seen[spec_index] = 1;

        const char *outcome = spec->accepted ? "accept" : "reject";
        if (strcmp(fields[1], outcome) != 0) {
            corpus_fail(path, line_number, "unexpected outcome");
        }
        if (strcmp(fields[2], spec->status_name) != 0) {
            corpus_fail(path, line_number, "unexpected symbolic status");
        }
        const int expected_status = parse_corpus_status(path, line_number, fields[3]);
        if (expected_status != spec->status) {
            corpus_fail(path, line_number, "symbolic and numeric status differ");
        }

        unsigned char wire[corpus_wire_capacity] = {0};
        const size_t wire_length = decode_corpus_wire(path, line_number, fields[4], wire);
        assert_corpus_wire(path, line_number, spec, wire, wire_length);
        vector_count++;
    }

    if (ferror(file)) {
        corpus_fail(path, line_number, "error reading corpus");
    }
    if (fclose(file) != 0) {
        corpus_fail(path, line_number, "error closing corpus");
    }
    if (stage != 2 || vector_count != sizeof(corpus_specs) / sizeof(corpus_specs[0])) {
        corpus_fail(path, line_number, "corpus format, header, or vectors are missing");
    }
    for (size_t index = 0; index < sizeof(seen) / sizeof(seen[0]); index++) {
        if (!seen[index]) {
            corpus_fail(path, line_number, "required vector is missing");
        }
    }
}

static void test_response_layout_and_zeroing(void) {
    java_remote_parent_response_t response;
    java_remote_parent_init_response(
        &response, k_java_remote_parent_status_valid, 0x0102030405060708ULL, 0x1112131415161718ULL);

    const unsigned char *bytes = (const unsigned char *)&response;
    assert_byte('O', bytes[0], "magic[0]");
    assert_byte('B', bytes[1], "magic[1]");
    assert_byte('I', bytes[2], "magic[2]");
    assert_byte('J', bytes[3], "magic[3]");
    assert_byte(1, bytes[4], "version low byte");
    assert_byte(0, bytes[5], "version high byte");
    assert_byte(64, bytes[6], "size low byte");
    assert_byte(0, bytes[7], "size high byte");
    assert_byte(k_java_remote_parent_status_valid, bytes[8], "status");

    for (u32 index = 9; index < 40; index++) {
        assert_byte(0, bytes[index], "zeroed context prefix");
    }
    for (u32 index = 0; index < 8; index++) {
        assert_byte(8 - index, bytes[40 + index], "generation");
        assert_byte(0x18 - index, bytes[48 + index], "observation");
        assert_byte(0, bytes[56 + index], "reserved suffix");
    }
}

static void test_valid_context_fields(void) {
    tp_info_t tp = {.flags = 0xa5};
    for (u32 index = 0; index < sizeof(tp.trace_id); index++) {
        tp.trace_id[index] = index + 1;
    }
    for (u32 index = 0; index < sizeof(tp.span_id); index++) {
        tp.span_id[index] = index + 0x21;
    }

    java_remote_parent_response_t response;
    java_remote_parent_init_response(&response, k_java_remote_parent_status_valid, 1, 2);
    java_remote_parent_set_context(&response, &tp);

    assert_byte(0xa5, response.flags, "W3C flags");
    for (u32 index = 0; index < sizeof(response.trace_id); index++) {
        assert_byte(index + 1, response.trace_id[index], "trace ID");
    }
    for (u32 index = 0; index < sizeof(response.span_id); index++) {
        assert_byte(index + 0x21, response.span_id[index], "span ID");
    }
}

static void test_tcp_option_carries_flags(void) {
    tcp_traceparent_legacy_option_t legacy = {};
    tcp_traceparent_option_t option = {.flags = 0x7f};
    assert_byte(26, sizeof(legacy), "legacy TCP option size");
    assert_byte(27, sizeof(option), "exact-flags TCP option size");
    assert_byte(0x7f, ((unsigned char *)&option)[26], "TCP option flags");
    assert_byte(1,
                k_tcp_common_syn_option_bytes + sizeof(option) <= k_tcp_header_option_bytes,
                "TCP option fits beside timestamps");
}

static void test_fallback_collision_does_not_overwrite(void) {
    const pid_key_t owner = {.tid = 1, .pid = 2, .ns = 3};
    java_remote_parent_response_t first;
    java_remote_parent_init_response(&first, k_java_remote_parent_status_valid, 1, 2);
    first.trace_id[0] = 1;
    first.span_id[0] = 2;

    fallback_present = 0;
    if (!java_remote_parent_stage_fallback(&owner, &first) ||
        fallback_value.status != k_java_remote_parent_status_valid) {
        fprintf(stderr, "fallback first insert failed\n");
        exit(1);
    }

    java_remote_parent_response_t conflicting = first;
    conflicting.span_id[0] = 3;
    if (java_remote_parent_stage_fallback(&owner, &conflicting) ||
        fallback_value.status != k_java_remote_parent_status_valid ||
        fallback_value.generation_le != first.generation_le ||
        fallback_value.trace_id[0] != first.trace_id[0] ||
        fallback_value.span_id[0] != first.span_id[0]) {
        fprintf(stderr, "fallback collision overwrote the reserved generation\n");
        exit(1);
    }
}

static void test_observation_age_fails_closed(void) {
    if (!java_remote_parent_observation_stale(99, 100, 30) ||
        !java_remote_parent_observation_stale(131, 100, 30) ||
        java_remote_parent_observation_stale(130, 100, 30) ||
        java_remote_parent_observation_stale(100, 100, 0)) {
        fprintf(stderr, "remote-parent observation age validation failed\n");
        exit(1);
    }
}

static void test_registered_process_reserves_incoming_claim_for_lifecycle(void) {
    tp_info_pid_t incoming = {};
    u64 generation = 0;

    if (!java_remote_parent_incoming_claim_allowed(0, NULL, NULL) ||
        java_remote_parent_incoming_claim_allowed(1, NULL, NULL) ||
        java_remote_parent_incoming_claim_allowed(1, &incoming, NULL) ||
        java_remote_parent_incoming_claim_allowed(1, NULL, &generation) ||
        !java_remote_parent_incoming_claim_allowed(1, &incoming, &generation)) {
        fprintf(stderr, "registered process incoming-claim reservation failed\n");
        exit(1);
    }
}

static void test_socket_options_route_explicit_sources_and_operations(void) {
    if (!java_remote_parent_socket_option_is_retrieval(k_java_remote_parent_socket_take) ||
        !java_remote_parent_socket_option_is_retrieval(k_java_remote_parent_socket_discard) ||
        !java_remote_parent_socket_option_is_retrieval(k_java_remote_parent_socket_task_take) ||
        !java_remote_parent_socket_option_is_retrieval(k_java_remote_parent_socket_task_discard) ||
        java_remote_parent_socket_option_is_retrieval(k_java_remote_parent_socket_health) ||
        java_remote_parent_socket_option_is_discard(k_java_remote_parent_socket_take) ||
        !java_remote_parent_socket_option_is_discard(k_java_remote_parent_socket_discard) ||
        java_remote_parent_socket_option_is_discard(k_java_remote_parent_socket_task_take) ||
        !java_remote_parent_socket_option_is_discard(k_java_remote_parent_socket_task_discard) ||
        java_remote_parent_socket_option_source(k_java_remote_parent_socket_take) !=
            k_java_remote_parent_source_direct ||
        java_remote_parent_socket_option_source(k_java_remote_parent_socket_discard) !=
            k_java_remote_parent_source_direct ||
        java_remote_parent_socket_option_source(k_java_remote_parent_socket_task_take) !=
            k_java_remote_parent_source_task ||
        java_remote_parent_socket_option_source(k_java_remote_parent_socket_task_discard) !=
            k_java_remote_parent_source_task) {
        fprintf(stderr, "remote-parent socket option routing failed\n");
        exit(1);
    }
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s CORPUS\n", argv[0]);
        return 1;
    }
    test_response_corpus(argv[1]);
    test_response_layout_and_zeroing();
    test_valid_context_fields();
    test_tcp_option_carries_flags();
    test_fallback_collision_does_not_overwrite();
    test_observation_age_fails_closed();
    test_registered_process_reserves_incoming_claim_for_lifecycle();
    test_socket_options_route_explicit_sources_and_operations();
    return 0;
}
