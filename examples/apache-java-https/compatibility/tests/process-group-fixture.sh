#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

mode="${1:?mode is required}"
pid_file="${2:?pid file is required}"

sleep 300 &
child=$!
printf '%s\n' "$child" >"$pid_file"

case "$mode" in
  leave-child)
    exit 0
    ;;
  wait-for-timeout)
    wait "$child"
    ;;
  *)
    exit 2
    ;;
esac
