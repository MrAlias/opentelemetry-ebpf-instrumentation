#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
umask 077

: "${OBI_COMPATIBILITY_PROVIDER_RESULT:?provider result path is required}"

case "${OBI_COMPATIBILITY_BOUNDARY_FIXTURE_MODE:?fixture mode is required}" in
  malformed)
    printf '{"status":' >"$OBI_COMPATIBILITY_PROVIDER_RESULT"
    chmod 0600 -- "$OBI_COMPATIBILITY_PROVIDER_RESULT"
    exit 0
    ;;
  missing)
    exit 0
    ;;
  pass-exit-one)
    printf '{"status":"pass"}\n' >"$OBI_COMPATIBILITY_PROVIDER_RESULT"
    chmod 0600 -- "$OBI_COMPATIBILITY_PROVIDER_RESULT"
    exit 1
    ;;
  untested-exit-zero)
    printf '{"status":"untested"}\n' >"$OBI_COMPATIBILITY_PROVIDER_RESULT"
    chmod 0600 -- "$OBI_COMPATIBILITY_PROVIDER_RESULT"
    exit 0
    ;;
  *)
    printf 'unknown boundary fixture mode\n' >&2
    exit 2
    ;;
esac
