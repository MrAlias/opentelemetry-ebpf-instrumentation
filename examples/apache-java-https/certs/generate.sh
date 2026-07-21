#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"
readonly SCRIPT_DIR SCRIPT_NAME

OUTPUT_DIR=""
FORCE=false
TMP_DIR=""

usage() {
  cat <<EOF
Usage: $SCRIPT_NAME --output DIR [--force]

Generate a short-lived test CA, a localhost server certificate, and the
PKCS#12 keystore used by the Jetty backend. DIR must be named "certs".

Options:
  --output DIR  Destination directory (required).
  --force       Replace an existing valid certificate set.
  -h, --help    Show this help text.
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
  log_error "certificate generation failed at line $line"
}

trap 'on_error "$LINENO"' ERR
trap cleanup EXIT

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --output)
        [[ $# -ge 2 ]] || {
          log_error "missing value for --output"
          exit 2
        }
        OUTPUT_DIR="$2"
        shift 2
        ;;
      --force)
        FORCE=true
        shift
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

  [[ -n "$OUTPUT_DIR" ]] || {
    log_error "--output is required"
    exit 2
  }
  [[ "$(basename -- "$OUTPUT_DIR")" == "certs" ]] || {
    log_error "refusing output directory not named certs: $OUTPUT_DIR"
    exit 2
  }
}

check_dependencies() {
  local -a missing=()
  local command_name=""
  for command_name in chmod cut dirname mkdir mktemp mv openssl pwd rm sha256sum tr; do
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
  OUTPUT_DIR="$parent_dir/certs"

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

public_key_fingerprint_from_certificate() {
  local -r certificate="$1"
  openssl x509 -in "$certificate" -pubkey -noout 2>/dev/null \
    | openssl pkey -pubin -outform DER 2>/dev/null \
    | sha256sum \
    | cut -d ' ' -f 1
}

public_key_fingerprint_from_private_key() {
  local -r private_key="$1"
  openssl pkey -in "$private_key" -pubout -outform DER 2>/dev/null \
    | sha256sum \
    | cut -d ' ' -f 1
}

pkcs12_certificate_fingerprint() {
  local -r keystore="$1"
  local -r certificate_type="$2"
  openssl pkcs12 \
    -in "$keystore" \
    "$certificate_type" \
    -nokeys \
    -passin pass:changeit 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 2>/dev/null
}

pkcs12_private_key_fingerprint() {
  local -r keystore="$1"
  openssl pkcs12 \
    -in "$keystore" \
    -nocerts \
    -nodes \
    -passin pass:changeit 2>/dev/null \
    | openssl pkey -pubout -outform DER 2>/dev/null \
    | sha256sum \
    | cut -d ' ' -f 1
}

write_certificate_metadata() {
  local -r directory="$1"
  local ca_fingerprint=""
  local metadata_tmp=""
  local server_fingerprint=""
  local server_dates=""

  ca_fingerprint="$(openssl x509 -noout -fingerprint -sha256 -in "$directory/ca.crt")"
  server_fingerprint="$(openssl x509 -noout -fingerprint -sha256 -in "$directory/server.crt")"
  server_dates="$(openssl x509 -noout -dates -in "$directory/server.crt" | tr '\n' ';')"
  metadata_tmp="$(mktemp "$directory/.metadata.XXXXXX")"
  printf '{\n  "ca_sha256": "%s",\n  "server_sha256": "%s",\n  "server_dates": "%s",\n  "sans": ["DNS:localhost", "DNS:java-backend", "IP:127.0.0.1"]\n}\n' \
    "${ca_fingerprint#*=}" \
    "${server_fingerprint#*=}" \
    "$server_dates" >"$metadata_tmp"
  chmod 0644 "$metadata_tmp"
  mv -fT -- "$metadata_tmp" "$directory/metadata.json"
}

install_generated_file() {
  local -r source="$1"
  local -r mode="$2"
  local -r destination="$3"

  chmod "$mode" "$source"
  mv -fT -- "$source" "$destination"
}

certificate_set_is_valid() {
  local ca_cert_fingerprint=""
  local ca_cert_public_key=""
  local ca_private_key=""
  local normalized_sans=""
  local pkcs12_ca_fingerprint=""
  local pkcs12_cert_fingerprint=""
  local pkcs12_private_key=""
  local server_cert_fingerprint=""
  local server_cert_public_key=""
  local server_private_key=""

  [[ -f "$OUTPUT_DIR/ca.crt" && ! -L "$OUTPUT_DIR/ca.crt" ]] || return 1
  [[ -s "$OUTPUT_DIR/ca.crt" ]] || return 1
  [[ -f "$OUTPUT_DIR/ca.key" && ! -L "$OUTPUT_DIR/ca.key" ]] || return 1
  [[ -s "$OUTPUT_DIR/ca.key" ]] || return 1
  [[ -f "$OUTPUT_DIR/server.crt" && ! -L "$OUTPUT_DIR/server.crt" ]] || return 1
  [[ -s "$OUTPUT_DIR/server.crt" ]] || return 1
  [[ -f "$OUTPUT_DIR/server.key" && ! -L "$OUTPUT_DIR/server.key" ]] || return 1
  [[ -s "$OUTPUT_DIR/server.key" ]] || return 1
  [[ -f "$OUTPUT_DIR/server.p12" && ! -L "$OUTPUT_DIR/server.p12" ]] || return 1
  [[ -s "$OUTPUT_DIR/server.p12" ]] || return 1
  openssl x509 -checkend 3600 -noout -in "$OUTPUT_DIR/ca.crt" >/dev/null 2>&1 || return 1
  openssl x509 -checkend 3600 -noout -in "$OUTPUT_DIR/server.crt" >/dev/null 2>&1 || return 1
  openssl verify \
    -purpose sslserver \
    -verify_hostname localhost \
    -CAfile "$OUTPUT_DIR/ca.crt" \
    "$OUTPUT_DIR/server.crt" >/dev/null 2>&1 || return 1
  openssl verify -CAfile "$OUTPUT_DIR/ca.crt" "$OUTPUT_DIR/ca.crt" >/dev/null 2>&1 || return 1
  openssl x509 -checkhost localhost -noout -in "$OUTPUT_DIR/server.crt" >/dev/null 2>&1 || return 1
  openssl x509 -checkhost java-backend -noout -in "$OUTPUT_DIR/server.crt" >/dev/null 2>&1 || return 1
  openssl x509 -checkip 127.0.0.1 -noout -in "$OUTPUT_DIR/server.crt" >/dev/null 2>&1 || return 1

  normalized_sans="$(openssl x509 -noout -ext subjectAltName -in "$OUTPUT_DIR/server.crt" 2>/dev/null)"
  normalized_sans="${normalized_sans//$'\n'/}"
  normalized_sans="${normalized_sans//[[:space:]]/}"
  [[ "$normalized_sans" == "X509v3SubjectAlternativeName:DNS:localhost,DNS:java-backend,IPAddress:127.0.0.1" ]] || return 1

  ca_cert_public_key="$(public_key_fingerprint_from_certificate "$OUTPUT_DIR/ca.crt")" || return 1
  ca_private_key="$(public_key_fingerprint_from_private_key "$OUTPUT_DIR/ca.key")" || return 1
  [[ "$ca_cert_public_key" == "$ca_private_key" ]] || return 1

  server_cert_public_key="$(public_key_fingerprint_from_certificate "$OUTPUT_DIR/server.crt")" || return 1
  server_private_key="$(public_key_fingerprint_from_private_key "$OUTPUT_DIR/server.key")" || return 1
  [[ "$server_cert_public_key" == "$server_private_key" ]] || return 1

  openssl pkcs12 \
    -in "$OUTPUT_DIR/server.p12" \
    -info \
    -noout \
    -passin pass:changeit >/dev/null 2>&1 || return 1
  server_cert_fingerprint="$(openssl x509 -noout -fingerprint -sha256 -in "$OUTPUT_DIR/server.crt")" || return 1
  ca_cert_fingerprint="$(openssl x509 -noout -fingerprint -sha256 -in "$OUTPUT_DIR/ca.crt")" || return 1
  pkcs12_cert_fingerprint="$(pkcs12_certificate_fingerprint "$OUTPUT_DIR/server.p12" -clcerts)" || return 1
  pkcs12_ca_fingerprint="$(pkcs12_certificate_fingerprint "$OUTPUT_DIR/server.p12" -cacerts)" || return 1
  pkcs12_private_key="$(pkcs12_private_key_fingerprint "$OUTPUT_DIR/server.p12")" || return 1
  [[ "$pkcs12_cert_fingerprint" == "$server_cert_fingerprint" ]] || return 1
  [[ "$pkcs12_ca_fingerprint" == "$ca_cert_fingerprint" ]] || return 1
  [[ "$pkcs12_private_key" == "$server_cert_public_key" ]]
}

generate_certificates() {
  local parent_dir=""

  parent_dir="$(dirname -- "$OUTPUT_DIR")"

  mkdir -p -- "$parent_dir"
  TMP_DIR="$(mktemp -d "$parent_dir/.certs.XXXXXX")"

  openssl req \
    -x509 \
    -newkey rsa:2048 \
    -nodes \
    -sha256 \
    -days 2 \
    -set_serial 0x4f42494341 \
    -subj '/CN=OBI Apache Java HTTPS Demo CA/O=OpenTelemetry Test Only' \
    -config "$SCRIPT_DIR/openssl.cnf" \
    -extensions v3_ca \
    -keyout "$TMP_DIR/ca.key" \
    -out "$TMP_DIR/ca.crt"

  openssl req \
    -new \
    -newkey rsa:2048 \
    -nodes \
    -sha256 \
    -config "$SCRIPT_DIR/openssl.cnf" \
    -keyout "$TMP_DIR/server.key" \
    -out "$TMP_DIR/server.csr"

  openssl x509 \
    -req \
    -sha256 \
    -days 2 \
    -set_serial 0x4f4249535256 \
    -in "$TMP_DIR/server.csr" \
    -CA "$TMP_DIR/ca.crt" \
    -CAkey "$TMP_DIR/ca.key" \
    -extfile "$SCRIPT_DIR/openssl.cnf" \
    -extensions v3_server \
    -out "$TMP_DIR/server.crt"

  openssl pkcs12 \
    -export \
    -name java-backend \
    -passout pass:changeit \
    -inkey "$TMP_DIR/server.key" \
    -in "$TMP_DIR/server.crt" \
    -certfile "$TMP_DIR/ca.crt" \
    -out "$TMP_DIR/server.p12"

  openssl verify -CAfile "$TMP_DIR/ca.crt" "$TMP_DIR/server.crt"
  OUTPUT_DIR="$TMP_DIR" certificate_set_is_valid
  write_certificate_metadata "$TMP_DIR"

  install_generated_file "$TMP_DIR/ca.key" 0600 "$OUTPUT_DIR/ca.key"
  install_generated_file "$TMP_DIR/ca.crt" 0644 "$OUTPUT_DIR/ca.crt"
  install_generated_file "$TMP_DIR/server.key" 0600 "$OUTPUT_DIR/server.key"
  install_generated_file "$TMP_DIR/server.crt" 0644 "$OUTPUT_DIR/server.crt"
  install_generated_file "$TMP_DIR/server.p12" 0600 "$OUTPUT_DIR/server.p12"
  install_generated_file "$TMP_DIR/metadata.json" 0644 "$OUTPUT_DIR/metadata.json"
}

main() {
  parse_args "$@"
  check_dependencies
  prepare_output_directory

  if certificate_set_is_valid && [[ "$FORCE" == "false" ]]; then
    chmod 0600 "$OUTPUT_DIR/ca.key" "$OUTPUT_DIR/server.key" "$OUTPUT_DIR/server.p12"
    chmod 0644 "$OUTPUT_DIR/ca.crt" "$OUTPUT_DIR/server.crt"
    write_certificate_metadata "$OUTPUT_DIR"
    log_info "reusing valid certificate set in $OUTPUT_DIR"
    return 0
  fi

  generate_certificates
  log_info "generated test-only certificate set in $OUTPUT_DIR"
}

main "$@"
