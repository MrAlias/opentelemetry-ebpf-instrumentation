#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

mode="${1:?mode is required}"
pid_file="${2:?pid file is required}"
child=0

case "$mode" in
  leave-child)
    sleep 300 &
    child=$!
    printf '%s\n' "$child" >"$pid_file"
    exit 0
    ;;
  leave-setsid-child)
    python3 - "$pid_file" <<'PY' &
import os
import sys
import time


os.setsid()
with open(sys.argv[1], "w", encoding="ascii") as stream:
    stream.write(f"{os.getpid()}\n")
    stream.flush()
    os.fsync(stream.fileno())
time.sleep(300)
PY
    child=$!
    for _ in {1..100}; do
      [[ -s "$pid_file" ]] && exit 0
      kill -0 "$child" 2>/dev/null || exit 1
      sleep 0.01
    done
    exit 1
    ;;
  leave-delayed-double-fork-setsid-child)
    python3 - "$pid_file" <<'PY' &
import os
import sys
import time


time.sleep(0.2)
os.setsid()
time.sleep(0.2)
if os.fork() != 0:
    os._exit(0)
if os.fork() != 0:
    os._exit(0)
with open(sys.argv[1], "w", encoding="ascii") as stream:
    stream.write(f"{os.getpid()}\n")
    stream.flush()
    os.fsync(stream.fileno())
time.sleep(300)
PY
    child=$!
    for _ in {1..200}; do
      [[ -s "$pid_file" ]] && exit 0
      sleep 0.01
    done
    wait "$child" 2>/dev/null || true
    exit 1
    ;;
  wait-for-timeout)
    sleep 300 &
    child=$!
    printf '%s\n' "$child" >"$pid_file"
    wait "$child"
    ;;
  *)
    exit 2
    ;;
esac
