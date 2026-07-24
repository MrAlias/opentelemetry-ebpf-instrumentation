// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

#include <common/algorithm.h>
#include <common/globals.h>
#include <common/http_buf_size.h>

enum : u8 {
    k_ascii_lowercase_bit = 0x20,
    k_traceparent_header_prefix_len = 13,
    k_traceparent_version_len = 2,
    k_traceparent_trace_id_len = 32,
    k_traceparent_span_id_len = 16,
    k_traceparent_flags_len = 2,
    k_traceparent_value_dash1 = k_traceparent_version_len,
    k_traceparent_value_trace_id = k_traceparent_value_dash1 + 1,
    k_traceparent_value_dash2 = k_traceparent_value_trace_id + k_traceparent_trace_id_len,
    k_traceparent_value_span_id = k_traceparent_value_dash2 + 1,
    k_traceparent_value_dash3 = k_traceparent_value_span_id + k_traceparent_span_id_len,
    k_traceparent_value_flags = k_traceparent_value_dash3 + 1,
    k_traceparent_value_len = k_traceparent_value_flags + k_traceparent_flags_len,
    k_traceparent_header_cr = k_traceparent_header_prefix_len + k_traceparent_value_len,
    k_traceparent_header_lf = k_traceparent_header_cr + 1,
    k_traceparent_header_len = k_traceparent_header_lf + 1,
};

#define TRACE_PARENT_HEADER_LEN k_traceparent_header_len

struct callback_ctx {
    unsigned char *buf;
    u32 pos;
    u8 line_start;
    u8 _pad[3];
};

enum : u32 {
    k_tp_pos_not_found = 0xFFFFFFFFU,
    k_tp_max_scan_loops = TRACE_BUF_SIZE - TRACE_PARENT_HEADER_LEN,
    k_tp_legacy_max_scan_loops = 350,
};

enum : u16 {
    k_tp_pos_unset = 0xFFFF,
};

static unsigned char *hex = (unsigned char *)"0123456789abcdef";
static unsigned char *reverse_hex =
    (unsigned char *)"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\xff\xff\xff\xff\xff\xff"
                     "\xff\x0a\x0b\x0c\x0d\x0e\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\x0a\x0b\x0c\x0d\x0e\x0f\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                     "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";

static __always_inline void urand_bytes(unsigned char *buf, u32 size) {
    for (int i = 0; i < size; i += sizeof(u32)) {
        *((u32 *)&buf[i]) = bpf_get_prandom_u32();
    }
}

static __always_inline void decode_hex(unsigned char *dst, const unsigned char *src, u32 src_len) {
    for (u32 i = 1, j = 0; i < src_len; i += 2) {
        unsigned char p = *src++;
        unsigned char q = *src++;

        unsigned char a = reverse_hex[p & 0xff];
        unsigned char b = reverse_hex[q & 0xff];

        a = a & 0x0f;
        b = b & 0x0f;

        dst[j++] = ((a << 4) | b) & 0xff;
    }
}

static __always_inline void encode_hex(unsigned char *dst, const unsigned char *src, u32 src_len) {
    for (u32 i = 0, j = 0; i < src_len; i++) {
        unsigned char p = src[i];
        dst[j++] = hex[(p >> 4) & 0xff];
        dst[j++] = hex[p & 0x0f];
    }
}

static __always_inline bool is_traceparent(const unsigned char *p) {
    if (((p[0] | k_ascii_lowercase_bit) == 't') && ((p[1] | k_ascii_lowercase_bit) == 'r') &&
        ((p[2] | k_ascii_lowercase_bit) == 'a') && ((p[3] | k_ascii_lowercase_bit) == 'c') &&
        ((p[4] | k_ascii_lowercase_bit) == 'e') && ((p[5] | k_ascii_lowercase_bit) == 'p') &&
        ((p[6] | k_ascii_lowercase_bit) == 'a') && ((p[7] | k_ascii_lowercase_bit) == 'r') &&
        ((p[8] | k_ascii_lowercase_bit) == 'e') && ((p[9] | k_ascii_lowercase_bit) == 'n') &&
        ((p[10] | k_ascii_lowercase_bit) == 't') && (p[11] == ':') && (p[12] == ' ')) {
        return true;
    }

    return false;
}

static __always_inline u8 invalid_traceparent_hex(unsigned char value) {
    return (reverse_hex[value & 0xff] >> 4) |
           ((value & k_ascii_lowercase_bit) ^ k_ascii_lowercase_bit);
}

static __noinline bool is_valid_traceparent_value(const unsigned char *value) {
    if (value[0] == 'f' && value[1] == 'f') {
        return false;
    }

    u8 invalid_hex = invalid_traceparent_hex(value[0]) | invalid_traceparent_hex(value[1]) |
                     invalid_traceparent_hex(value[k_traceparent_value_flags]) |
                     invalid_traceparent_hex(value[k_traceparent_value_flags + 1]);
    invalid_hex |= value[k_traceparent_value_dash1] ^ '-';
    invalid_hex |= value[k_traceparent_value_dash2] ^ '-';
    invalid_hex |= value[k_traceparent_value_dash3] ^ '-';

    u8 trace_id_nonzero = 0;
#pragma clang loop unroll(disable)
    for (u8 i = 0; i < k_traceparent_trace_id_len; i++) {
        const unsigned char current = value[k_traceparent_value_trace_id + i];
        invalid_hex |= invalid_traceparent_hex(current);
        trace_id_nonzero |= current ^ '0';
    }

    u8 span_id_nonzero = 0;
#pragma clang loop unroll(disable)
    for (u8 i = 0; i < k_traceparent_span_id_len; i++) {
        const unsigned char current = value[k_traceparent_value_span_id + i];
        invalid_hex |= invalid_traceparent_hex(current);
        span_id_nonzero |= current ^ '0';
    }
    return invalid_hex == 0 && trace_id_nonzero != 0 && span_id_nonzero != 0;
}

static __always_inline bool is_valid_traceparent_field_value(const unsigned char *value,
                                                             const u32 value_len) {
    if (value_len < k_traceparent_value_len || !is_valid_traceparent_value(value)) {
        return false;
    }
    if (value[0] == '0' && value[1] == '0') {
        return value_len == k_traceparent_value_len;
    }
    return value_len == k_traceparent_value_len ||
           (value_len > k_traceparent_value_len + 1 && value[k_traceparent_value_len] == '-');
}

static __always_inline bool is_valid_traceparent(const unsigned char *header) {
    if (!is_traceparent(header)) {
        return false;
    }

    const unsigned char *value = &header[k_traceparent_header_prefix_len];
    if (!is_valid_traceparent_value(value)) {
        return false;
    }

    const bool line_ended =
        header[k_traceparent_header_cr] == '\r' && header[k_traceparent_header_lf] == '\n';
    if (value[0] == '0' && value[1] == '0') {
        return line_ended;
    }
    const unsigned char extension = header[k_traceparent_header_lf];
    return line_ended || (header[k_traceparent_header_cr] == '-' && extension != '\0' &&
                          extension != '\r' && extension != '\n');
}

static __always_inline bool is_eoh(const unsigned char *p) {
    return p[0] == '\r' && p[1] == '\n' && p[2] == '\r' && p[3] == '\n';
}

static int tp_match(u32 index, void *data) {
    if (index >= (TRACE_BUF_SIZE - TRACE_PARENT_HEADER_LEN)) {
        return 1;
    }

    struct callback_ctx *ctx = data;
    unsigned char *s = &(ctx->buf[index]);

    if (is_eoh(s)) {
        return 1;
    }

    if (ctx->line_start && is_traceparent(s)) {
        ctx->pos = index;
        return 1;
    }

    ctx->line_start = *s == '\n';
    return 0;
}

static __always_inline u32 traceparent_scan_loop_count(const u16 buf_len) {
    if (buf_len < TRACE_PARENT_HEADER_LEN) {
        return 0;
    }

    return min((u32)buf_len - TRACE_PARENT_HEADER_LEN + 1, k_tp_max_scan_loops);
}

static __always_inline bool traceparent_header_fits(const int buf_len) {
    return buf_len >= TRACE_PARENT_HEADER_LEN;
}

static __always_inline u16 traceparent_legacy_scan_loop_count(const u16 buf_len) {
    return min(traceparent_scan_loop_count(buf_len), k_tp_legacy_max_scan_loops);
}

static __always_inline unsigned char *bpf_strstr_tp_loop(unsigned char *buf, const u16 buf_len) {
    if (!g_bpf_traceparent_enabled) {
        return NULL;
    }

    const u32 nr_loops = traceparent_scan_loop_count(buf_len);

    if (nr_loops == 0) {
        return NULL;
    }

    struct callback_ctx data = {.buf = buf, .pos = k_tp_pos_not_found, .line_start = true};

    bpf_loop(nr_loops, tp_match, &data, 0);

    if (data.pos != k_tp_pos_not_found) {
        return (data.pos > (TRACE_BUF_SIZE - TRACE_PARENT_HEADER_LEN)) ? NULL : &buf[data.pos];
    }

    return NULL;
}

static __always_inline unsigned char *traceparent_find_legacy(unsigned char *buf,
                                                              const u16 buf_len) {
    if (buf_len < TRACE_PARENT_HEADER_LEN) {
        return NULL;
    }

    // Limited best-effort search to stay within insns limit
    const u16 nr_loops = traceparent_legacy_scan_loop_count(buf_len);
    bool line_start = true;

    for (u16 i = 0; i < k_tp_legacy_max_scan_loops; i++) {
        if (i >= nr_loops) {
            return NULL;
        }

        // buf is null terminated
        if (*buf == '\0') {
            return NULL;
        }

        if (is_eoh(buf)) {
            return NULL;
        }

        if (line_start && is_traceparent(buf)) {
            return buf;
        }

        line_start = *buf == '\n';
        ++buf;
    }

    return NULL;
}

static __always_inline unsigned char *bpf_strstr_tp_loop__legacy(unsigned char *buf,
                                                                 const u16 buf_len) {
    if (!g_bpf_traceparent_enabled) {
        return NULL;
    }

    return traceparent_find_legacy(buf, buf_len);
}
