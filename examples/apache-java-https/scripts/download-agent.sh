#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"
readonly SCRIPT_NAME

DISTRIBUTION="otel"
OUTPUT_DIR=""
TMP_DIR=""

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME --distribution otel|splunk --output DIR

Download one official, unmodified Java agent from Maven Central and verify its
pinned SHA-256 digest. DIR must be named "artifacts".

Options:
  --distribution NAME  otel (default) or splunk.
  --output DIR         Destination directory (required).
  -h, --help           Show this help text.
EOF
}

log_info() {
  printf '[%(%Y-%m-%dT%H:%M:%SZ)T] INFO: %s\n' -1 "$*" >&2
}

log_error() {
  printf '[%(%Y-%m-%dT%H:%M:%SZ)T] ERROR: %s\n' -1 "$*" >&2
}

cleanup() {
  if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]]; then
    rm -rf -- "$TMP_DIR"
  fi
}

on_error() {
  local -r line="$1"
  log_error "agent preparation failed at line $line"
}

trap 'on_error "$LINENO"' ERR
trap cleanup EXIT

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --distribution)
        [[ $# -ge 2 ]] || {
          log_error "missing value for --distribution"
          exit 2
        }
        DISTRIBUTION="$2"
        shift 2
        ;;
      --output)
        [[ $# -ge 2 ]] || {
          log_error "missing value for --output"
          exit 2
        }
        OUTPUT_DIR="$2"
        shift 2
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        log_error "unknown argument: $1"
        usage >&2
        exit 2
        ;;
    esac
  done

  case "$DISTRIBUTION" in
    otel|splunk)
      ;;
    *)
      log_error "distribution must be otel or splunk"
      exit 2
      ;;
  esac
  [[ -n "$OUTPUT_DIR" ]] || {
    log_error "--output is required"
    exit 2
  }
  [[ "$(basename -- "$OUTPUT_DIR")" == "artifacts" ]] || {
    log_error "refusing output directory not named artifacts: $OUTPUT_DIR"
    exit 2
  }
}

check_dependencies() {
  local -a missing=()
  local command_name=""
  for command_name in curl dirname install mkdir mktemp mv pwd sha256sum; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
      missing+=("$command_name")
    fi
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    log_error "missing required commands: ${missing[*]}"
    return 1
  fi
}

prepare_output_directory() {
  local parent_dir=""

  [[ ! -L "$OUTPUT_DIR" ]] || {
    log_error "refusing symlink output directory: $OUTPUT_DIR"
    return 1
  }

  parent_dir="$(dirname -- "$OUTPUT_DIR")"
  mkdir -p -- "$parent_dir"
  [[ -d "$parent_dir" && ! -L "$parent_dir" ]] || {
    log_error "refusing non-directory or symlink output parent: $parent_dir"
    return 1
  }
  parent_dir="$(cd -- "$parent_dir" && pwd -P)"
  OUTPUT_DIR="$parent_dir/artifacts"

  if [[ -e "$OUTPUT_DIR" && ! -d "$OUTPUT_DIR" ]]; then
    log_error "refusing non-directory output target: $OUTPUT_DIR"
    return 1
  fi
  [[ ! -L "$OUTPUT_DIR" ]] || {
    log_error "refusing symlink output directory: $OUTPUT_DIR"
    return 1
  }
  mkdir -p -- "$OUTPUT_DIR"
  [[ -d "$OUTPUT_DIR" && ! -L "$OUTPUT_DIR" ]] || {
    log_error "output directory changed while preparing it: $OUTPUT_DIR"
    return 1
  }
}

resolve_release() {
  case "$DISTRIBUTION" in
    otel)
      VERSION="2.28.1"
      SHA256="faa89bdeebf9b1f52be4a4374689176717b02a59df2d8f8b6eb9aa39f9292589"
      URL="https://repo.maven.apache.org/maven2/io/opentelemetry/javaagent/opentelemetry-javaagent/${VERSION}/opentelemetry-javaagent-${VERSION}.jar"
      ;;
    splunk)
      VERSION="2.28.0"
      SHA256="70d177dd63a4bbdb153e65c962ff678ed98b5555ff5bb63afdb6e7fff05c1351"
      URL="https://repo.maven.apache.org/maven2/com/splunk/splunk-otel-javaagent/${VERSION}/splunk-otel-javaagent-${VERSION}.jar"
      ;;
  esac
  readonly VERSION SHA256 URL
}

existing_agent_is_valid() {
  [[ -f "$OUTPUT_DIR/official-javaagent.jar" && ! -L "$OUTPUT_DIR/official-javaagent.jar" ]] || return 1
  [[ -s "$OUTPUT_DIR/official-javaagent.jar" ]] || return 1
  printf '%s  %s\n' "$SHA256" "$OUTPUT_DIR/official-javaagent.jar" | sha256sum --check --status
}

publish_agent_metadata() {
  local -r staging_dir="$1"

  printf '{\n  "distribution": "%s",\n  "version": "%s",\n  "sha256": "%s",\n  "url": "%s"\n}\n' \
    "$DISTRIBUTION" "$VERSION" "$SHA256" "$URL" >"$staging_dir/official-javaagent.json"
  install -m 0644 \
    "$staging_dir/official-javaagent.json" \
    "$staging_dir/official-javaagent.json.ready"
  mv -fT -- \
    "$staging_dir/official-javaagent.json.ready" \
    "$OUTPUT_DIR/official-javaagent.json"
}

download_agent() {
  local -r parent_dir="$(dirname -- "$OUTPUT_DIR")"
  local downloaded=""

  mkdir -p -- "$parent_dir"
  TMP_DIR="$(mktemp -d "$parent_dir/.agent.XXXXXX")"
  downloaded="$TMP_DIR/official-javaagent.jar"
  curl \
    --fail \
    --location \
    --silent \
    --show-error \
    --retry 3 \
    --retry-all-errors \
    --connect-timeout 10 \
    --max-time 180 \
    --output "$downloaded" \
    "$URL"
  printf '%s  %s\n' "$SHA256" "$downloaded" | sha256sum --check --status

  install -m 0644 "$downloaded" "$TMP_DIR/official-javaagent.jar.ready"
  mv -fT -- "$TMP_DIR/official-javaagent.jar.ready" "$OUTPUT_DIR/official-javaagent.jar"
  publish_agent_metadata "$TMP_DIR"
}

main() {
  parse_args "$@"
  check_dependencies
  prepare_output_directory
  resolve_release

  if existing_agent_is_valid; then
    log_info "reusing verified $DISTRIBUTION Java agent $VERSION"
    TMP_DIR="$(mktemp -d "$(dirname -- "$OUTPUT_DIR")/.agent.XXXXXX")"
    publish_agent_metadata "$TMP_DIR"
    return 0
  fi

  download_agent
  log_info "downloaded and verified $DISTRIBUTION Java agent $VERSION"
}

main "$@"
