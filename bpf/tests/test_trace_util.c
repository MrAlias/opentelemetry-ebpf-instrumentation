// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline unsigned int bpf_get_prandom_u32(void) {
    return 0;
}

static inline long bpf_loop(unsigned int nr_loops,
                            int (*callback_fn)(unsigned int, void *),
                            void *callback_ctx,
                            unsigned long long flags) {
    (void)flags;

    for (unsigned int i = 0; i < nr_loops; i++) {
        if (callback_fn(i, callback_ctx)) {
            break;
        }
    }

    return 0;
}

#include <common/trace_util.h>

static void assert_match_pos(u32 want, u32 got, const char *name) {
    if (want != got) {
        fprintf(stderr, "%s: got pos %u, want %u\n", name, got, want);
        exit(1);
    }
}

static void assert_scan_count(u32 want, u32 got, const char *name) {
    if (want != got) {
        fprintf(stderr, "%s: got scan count %u, want %u\n", name, got, want);
        exit(1);
    }
}

static void assert_valid_traceparent(bool want, const unsigned char *header, const char *name) {
    const bool got = is_valid_traceparent(header);
    if (want != got) {
        fprintf(stderr, "%s: got valid=%d, want %d\n", name, got, want);
        exit(1);
    }
}

static void assert_valid_traceparent_field_value(bool want,
                                                 const unsigned char *value,
                                                 u32 value_len,
                                                 const char *name) {
    const bool got = is_valid_traceparent_field_value(value, value_len);
    if (want != got) {
        fprintf(stderr, "%s: got field value valid=%d, want %d\n", name, got, want);
        exit(1);
    }
}

static u32
traceparent_pos_after_read(const unsigned char *stale, const unsigned char *fresh, u32 fresh_len) {
    unsigned char buf[TRACE_BUF_SIZE] = {};

    memcpy(buf, stale, strlen((const char *)stale));
    memcpy(buf, fresh, fresh_len);

    struct callback_ctx ctx = {.buf = buf, .pos = k_tp_pos_not_found, .line_start = true};

    bpf_loop(traceparent_scan_loop_count(fresh_len), tp_match, &ctx, 0);
    if (ctx.pos == k_tp_pos_not_found || !is_valid_traceparent(&buf[ctx.pos])) {
        return k_tp_pos_not_found;
    }
    return ctx.pos;
}

static u32 legacy_traceparent_pos_after_read(const unsigned char *fresh, u32 fresh_len) {
    unsigned char buf[TRACE_BUF_SIZE] = {};
    memcpy(buf, fresh, fresh_len);

    unsigned char *match = traceparent_find_legacy(buf, fresh_len);
    if (!match || !is_valid_traceparent(match)) {
        return k_tp_pos_not_found;
    }
    return match - buf;
}

static void test_stale_suffix_cannot_complete_traceparent_prefix(void) {
    const unsigned char stale[] =
        "xtraceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n";
    const unsigned char fresh[] = "xtrace";

    const u32 got = traceparent_pos_after_read(stale, fresh, sizeof(fresh) - 1);

    assert_match_pos(k_tp_pos_not_found, got, __func__);
}

static void test_stale_value_cannot_complete_traceparent_header(void) {
    const unsigned char stale[] =
        "xtraceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n";
    const unsigned char fresh[] = "xtraceparent: ";

    const u32 got = traceparent_pos_after_read(stale, fresh, sizeof(fresh) - 1);

    assert_match_pos(k_tp_pos_not_found, got, __func__);
}

static void test_fresh_traceparent_still_matches(void) {
    const unsigned char stale[] = "";
    const unsigned char fresh[] =
        "traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n";

    const u32 got = traceparent_pos_after_read(stale, fresh, sizeof(fresh) - 1);

    assert_match_pos(0, got, __func__);
    assert_match_pos(
        0, legacy_traceparent_pos_after_read(fresh, sizeof(fresh) - 1), "fresh legacy traceparent");
}

static void test_traceparent_requires_header_line(void) {
    const unsigned char stale[] = "";
    const unsigned char field_name[] =
        "xtraceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n";
    const unsigned char field_value[] =
        "x-debug: traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n";
    const unsigned char body[] =
        "POST / HTTP/1.1\r\nhost: example.test\r\n\r\n"
        "traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n";

    assert_match_pos(k_tp_pos_not_found,
                     traceparent_pos_after_read(stale, field_name, sizeof(field_name) - 1),
                     "traceparent substring in field name");
    assert_match_pos(k_tp_pos_not_found,
                     legacy_traceparent_pos_after_read(field_name, sizeof(field_name) - 1),
                     "legacy traceparent substring in field name");
    assert_match_pos(k_tp_pos_not_found,
                     traceparent_pos_after_read(stale, field_value, sizeof(field_value) - 1),
                     "traceparent substring in field value");
    assert_match_pos(k_tp_pos_not_found,
                     legacy_traceparent_pos_after_read(field_value, sizeof(field_value) - 1),
                     "legacy traceparent substring in field value");
    assert_match_pos(k_tp_pos_not_found,
                     traceparent_pos_after_read(stale, body, sizeof(body) - 1),
                     "traceparent text after end of headers");
    assert_match_pos(k_tp_pos_not_found,
                     legacy_traceparent_pos_after_read(body, sizeof(body) - 1),
                     "legacy traceparent text after end of headers");
}

static void test_malformed_traceparent_does_not_consume_following_headers(void) {
    const unsigned char stale[] = "";
    const unsigned char fresh[] = "GET / HTTP/1.1\r\n"
                                  "traceparent: 00-invalid\r\n"
                                  "x-obi-demo-id: w3c-01-102974141d8fb095\r\n"
                                  "host: example.test\r\n\r\n";

    const u32 got = traceparent_pos_after_read(stale, fresh, sizeof(fresh) - 1);

    assert_match_pos(k_tp_pos_not_found, got, __func__);
}

static void test_malformed_traceparent_masks_later_candidate(void) {
    const unsigned char stale[] = "";
    const unsigned char fresh[] =
        "GET / HTTP/1.1\r\n"
        "traceparent: 00-invalid\r\n"
        "traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n\r\n";

    const u32 got = traceparent_pos_after_read(stale, fresh, sizeof(fresh) - 1);

    assert_match_pos(k_tp_pos_not_found, got, __func__);
}

static void test_traceparent_scan_loop_bounds(void) {
    assert_scan_count(0, traceparent_scan_loop_count(69), "short modern buffer");
    assert_scan_count(0, traceparent_legacy_scan_loop_count(69), "short legacy buffer");
    assert_scan_count(1, traceparent_scan_loop_count(70), "exact modern buffer");
    assert_scan_count(1, traceparent_legacy_scan_loop_count(70), "exact legacy buffer");
    assert_scan_count(2, traceparent_scan_loop_count(71), "two modern candidates");
    assert_scan_count(2, traceparent_legacy_scan_loop_count(71), "two legacy candidates");
    assert_scan_count(350, traceparent_legacy_scan_loop_count(419), "legacy scan limit");
    assert_scan_count(350, traceparent_legacy_scan_loop_count(420), "legacy scan cap");
    if (traceparent_header_fits(69) || !traceparent_header_fits(70)) {
        fprintf(stderr, "traceparent buffer length check failed\n");
        exit(1);
    }
}

static void test_traceparent_hex_validation_all_bytes(void) {
    for (u16 value = 0; value <= 0xff; value++) {
        const unsigned char current = value;
        const bool want = (current >= '0' && current <= '9') || (current >= 'a' && current <= 'f');
        const bool got = invalid_traceparent_hex(current) == 0;
        if (want != got) {
            fprintf(stderr, "hex byte 0x%02x: got valid=%d, want %d\n", current, got, want);
            exit(1);
        }
    }
}

static void test_traceparent_value_validation(void) {
    const unsigned char valid[] =
        "traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n";
    const unsigned char bad_version[] =
        "traceparent: gg-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n";
    const unsigned char future_version[] =
        "traceparent: 01-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n";
    const unsigned char future_version_extension[] =
        "traceparent: 01-0123456789abcdef0123456789abcdef-0123456789abcdef-01-extra\r\n";
    const unsigned char empty_future_version_extension[] =
        "traceparent: 01-0123456789abcdef0123456789abcdef-0123456789abcdef-01-";
    const unsigned char empty_future_version_extension_line[] =
        "traceparent: 01-0123456789abcdef0123456789abcdef-0123456789abcdef-01-\r\n";
    const unsigned char forbidden_version[] =
        "traceparent: ff-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n";
    const unsigned char bad_trace_id[] =
        "traceparent: 00-g123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n";
    const unsigned char zero_trace_id[] =
        "traceparent: 00-00000000000000000000000000000000-0123456789abcdef-01\r\n";
    const unsigned char bad_span_id[] =
        "traceparent: 00-0123456789abcdef0123456789abcdef-g123456789abcdef-01\r\n";
    const unsigned char zero_span_id[] =
        "traceparent: 00-0123456789abcdef0123456789abcdef-0000000000000000-01\r\n";
    const unsigned char bad_flags[] =
        "traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-0g\r\n";
    const unsigned char bad_separator[] =
        "traceparent: 00_0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n";
    const unsigned char bad_second_separator[] =
        "traceparent: 00-0123456789abcdef0123456789abcdef_0123456789abcdef-01\r\n";
    const unsigned char bad_third_separator[] =
        "traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef_01\r\n";
    const unsigned char uppercase_hex[] =
        "traceparent: 00-0123456789ABCDEF0123456789abcdef-0123456789abcdef-01\r\n";
    const unsigned char uppercase_header[] =
        "TRACEPARENT: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01\r\n";
    const unsigned char trailing_value[] =
        "traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01-extra\r\n";

    assert_valid_traceparent(true, valid, "valid traceparent");
    assert_valid_traceparent(false, bad_version, "non-hex version");
    assert_valid_traceparent(true, future_version, "future version");
    assert_valid_traceparent(true, future_version_extension, "future version extension");
    assert_valid_traceparent(
        false, empty_future_version_extension, "empty future version extension");
    assert_valid_traceparent(false,
                             empty_future_version_extension_line,
                             "empty future version extension before line ending");
    assert_valid_traceparent(false, forbidden_version, "forbidden version");
    assert_valid_traceparent(false, bad_trace_id, "non-hex trace ID");
    assert_valid_traceparent(false, zero_trace_id, "zero trace ID");
    assert_valid_traceparent(false, bad_span_id, "non-hex span ID");
    assert_valid_traceparent(false, zero_span_id, "zero span ID");
    assert_valid_traceparent(false, bad_flags, "non-hex flags");
    assert_valid_traceparent(false, bad_separator, "invalid separator");
    assert_valid_traceparent(false, bad_second_separator, "invalid second separator");
    assert_valid_traceparent(false, bad_third_separator, "invalid third separator");
    assert_valid_traceparent(false, uppercase_hex, "uppercase hex");
    assert_valid_traceparent(true, uppercase_header, "uppercase header name");
    assert_valid_traceparent(false, trailing_value, "trailing version 00 value");
}

static void test_newline_stripped_traceparent_value_validation(void) {
    const unsigned char valid[] = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";
    const unsigned char malformed[] = "00-invalid";
    const unsigned char trailing[] =
        "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01-extra";
    const unsigned char future[] = "01-0123456789abcdef0123456789abcdef-0123456789abcdef-01";
    const unsigned char empty_future_extension[] =
        "01-0123456789abcdef0123456789abcdef-0123456789abcdef-01-";
    const unsigned char future_extension[] =
        "01-0123456789abcdef0123456789abcdef-0123456789abcdef-01-extra";

    assert_valid_traceparent_field_value(true, valid, sizeof(valid) - 1, "valid field value");
    assert_valid_traceparent_field_value(
        false, malformed, sizeof(malformed) - 1, "short malformed field value");
    assert_valid_traceparent_field_value(
        false, trailing, sizeof(trailing) - 1, "trailing version 00 field value");
    assert_valid_traceparent_field_value(true, future, sizeof(future) - 1, "future field value");
    assert_valid_traceparent_field_value(false,
                                         empty_future_extension,
                                         sizeof(empty_future_extension) - 1,
                                         "empty future field value extension");
    assert_valid_traceparent_field_value(
        true, future_extension, sizeof(future_extension) - 1, "future field value extension");
}

int main(void) {
    test_stale_suffix_cannot_complete_traceparent_prefix();
    test_stale_value_cannot_complete_traceparent_header();
    test_fresh_traceparent_still_matches();
    test_traceparent_requires_header_line();
    test_malformed_traceparent_does_not_consume_following_headers();
    test_malformed_traceparent_masks_later_candidate();
    test_traceparent_scan_loop_bounds();
    test_traceparent_hex_validation_all_bytes();
    test_traceparent_value_validation();
    test_newline_stripped_traceparent_value_validation();

    return 0;
}
