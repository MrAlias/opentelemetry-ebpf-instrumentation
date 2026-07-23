// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <bpfcore/vmlinux.h>
#include <bpfcore/bpf_helpers.h>

enum {
    k_http_response_status_position = 9,
    k_http_response_status_min = 100,
    k_http_response_status_switching_protocols = 101,
    k_http_response_status_final_min = 200,
    k_http_response_status_max = 599,
};

static __always_inline u8 http_response_status_digit(unsigned char value) {
    return value >= '0' && value <= '9';
}

static __always_inline u16 parse_http_response_status(const unsigned char *buf) {
    const unsigned char hundreds = buf[k_http_response_status_position];
    const unsigned char tens = buf[k_http_response_status_position + 1];
    const unsigned char ones = buf[k_http_response_status_position + 2];
    if (!http_response_status_digit(hundreds) || !http_response_status_digit(tens) ||
        !http_response_status_digit(ones)) {
        return 0;
    }

    u16 status = (hundreds - '0') * 100;
    status += (tens - '0') * 10;
    status += ones - '0';
    if (status < k_http_response_status_min || status > k_http_response_status_max ||
        (status < k_http_response_status_final_min &&
         status != k_http_response_status_switching_protocols)) {
        return 0;
    }
    return status;
}

static __always_inline u8 http_response_status_is_final(u16 status) {
    return status >= k_http_response_status_final_min && status <= k_http_response_status_max;
}
