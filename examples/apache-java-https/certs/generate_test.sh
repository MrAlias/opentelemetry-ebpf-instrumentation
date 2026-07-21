#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR

TMP_DIR=""

cleanup() {
  if [[ -n "${TMP_DIR:-}" && -d "$TMP_DIR" ]]; then
    rm -rf -- "$TMP_DIR"
  fi
}

trap cleanup EXIT

check_dependencies() {
  local -a missing=()
  local command_name=""
  for command_name in cut ln mktemp openssl rm sha256sum; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
      missing+=("$command_name")
    fi
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    printf 'missing required commands: %s\n' "${missing[*]}" >&2
    return 1
  fi
}

certificate_set_digest() {
  local -r directory="$1"
  (
    cd -- "$directory"
    sha256sum ca.crt ca.key metadata.json server.crt server.key server.p12
  ) | sha256sum | cut -d ' ' -f 1
}

generate() {
  "$SCRIPT_DIR/generate.sh" --output "$TMP_DIR/certs" >/dev/null 2>&1
}

assert_reuses_valid_set() {
  local before=""
  local after=""

  before="$(certificate_set_digest "$TMP_DIR/certs")"
  generate
  after="$(certificate_set_digest "$TMP_DIR/certs")"
  [[ "$after" == "$before" ]] || {
    printf 'certificate generator replaced a valid set\n' >&2
    return 1
  }
}

assert_replaces_tampered_set() {
  local -r description="$1"
  local before=""
  local after=""

  before="$(certificate_set_digest "$TMP_DIR/certs")"
  generate
  after="$(certificate_set_digest "$TMP_DIR/certs")"
  [[ "$after" != "$before" ]] || {
    printf 'certificate generator reused set with tampered %s\n' "$description" >&2
    return 1
  }
  assert_reuses_valid_set
}

main() {
  check_dependencies
  TMP_DIR="$(mktemp -d)"
  generate
  assert_reuses_valid_set

  printf 'tampered private key\n' >"$TMP_DIR/certs/server.key"
  assert_replaces_tampered_set "private key"

  printf 'outside sentinel\n' >"$TMP_DIR/outside-key"
  rm -f -- "$TMP_DIR/certs/server.key"
  ln -s -- "$TMP_DIR/outside-key" "$TMP_DIR/certs/server.key"
  assert_replaces_tampered_set "private-key symlink"
  [[ ! -L "$TMP_DIR/certs/server.key" ]] || {
    printf 'certificate generator retained a private-key symlink\n' >&2
    return 1
  }
  [[ "$(<"$TMP_DIR/outside-key")" == "outside sentinel" ]] || {
    printf 'certificate generator overwrote a symlink target\n' >&2
    return 1
  }

  mv -- "$TMP_DIR/certs" "$TMP_DIR/real-certs"
  ln -s -- "$TMP_DIR/real-certs" "$TMP_DIR/certs"
  if generate; then
    printf 'certificate generator accepted a symlink output directory\n' >&2
    return 1
  fi
  rm -- "$TMP_DIR/certs"
  mv -- "$TMP_DIR/real-certs" "$TMP_DIR/certs"

  printf 'tampered PKCS#12\n' >"$TMP_DIR/certs/server.p12"
  assert_replaces_tampered_set "PKCS#12 keystore"

  openssl req \
    -new \
    -key "$TMP_DIR/certs/server.key" \
    -subj '/CN=localhost/O=OpenTelemetry Test Only' \
    -out "$TMP_DIR/server-without-sans.csr" >/dev/null 2>&1
  openssl x509 \
    -req \
    -sha256 \
    -days 2 \
    -in "$TMP_DIR/server-without-sans.csr" \
    -CA "$TMP_DIR/certs/ca.crt" \
    -CAkey "$TMP_DIR/certs/ca.key" \
    -out "$TMP_DIR/certs/server.crt" >/dev/null 2>&1
  openssl pkcs12 \
    -export \
    -name java-backend \
    -passout pass:changeit \
    -inkey "$TMP_DIR/certs/server.key" \
    -in "$TMP_DIR/certs/server.crt" \
    -certfile "$TMP_DIR/certs/ca.crt" \
    -out "$TMP_DIR/certs/server.p12" >/dev/null 2>&1
  assert_replaces_tampered_set "certificate SANs"

  printf 'certificate generation tests passed\n'
}

main "$@"
