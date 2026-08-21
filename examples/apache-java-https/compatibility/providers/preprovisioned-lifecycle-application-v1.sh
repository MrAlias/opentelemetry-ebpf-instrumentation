#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
# shellcheck disable=SC1091  # Resolved from this script's physical directory.
source "$SCRIPT_DIRECTORY/provider-lib.sh"

readonly SOURCE_LIFECYCLE_DRIVER="$SCRIPT_DIRECTORY/lifecycle-application-driver-v1.sh"

main() {
  local executor_registry_snapshot=\
"${OBI_COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY_SNAPSHOT:-}"
  local executor_registry_snapshot_identity=\
"${OBI_COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY_SNAPSHOT_IDENTITY:-}"
  local executor_registry_source_identity=\
"${OBI_COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY_SOURCE_IDENTITY:-}"

  provider_require_environment
  export OBI_COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY="$COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY"
  if [[ -z "$executor_registry_snapshot" &&
    -z "$executor_registry_snapshot_identity" &&
    -z "$executor_registry_source_identity" ]]; then
    executor_registry_snapshot=\
"$OBI_COMPATIBILITY_PRIVATE_DIR/lifecycle-executor-registry.authority.json"
    executor_registry_source_identity="$(
      compatibility_prepare_lifecycle_executor_registry_snapshot \
        "$executor_registry_snapshot"
    )" || return
    executor_registry_snapshot_identity="$(compatibility_stable_file_identity \
      "$executor_registry_snapshot" 67108864)" || return
  else
    [[ -n "$executor_registry_snapshot" &&
      -n "$executor_registry_snapshot_identity" &&
      -n "$executor_registry_source_identity" ]] || return 2
  fi
  compatibility_validate_lifecycle_executor_registry \
    "$executor_registry_snapshot" "$executor_registry_snapshot_identity" || return
  [[ "$(compatibility_stable_file_identity \
      "$COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY" 67108864)" == \
      "$executor_registry_source_identity" ]] ||
    compatibility_die "lifecycle executor registry source authority changed" ||
    return
  export OBI_COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY_SNAPSHOT=\
"$executor_registry_snapshot"
  export OBI_COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY_SNAPSHOT_IDENTITY=\
"$executor_registry_snapshot_identity"
  export OBI_COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY_SOURCE_IDENTITY=\
"$executor_registry_source_identity"
  if [[ -z "${OBI_COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY_SHA256:-}" ]]; then
    export OBI_COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY_SHA256
    OBI_COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY_SHA256="$(
      compatibility_lifecycle_executor_registry_sha256 "$executor_registry_snapshot"
    )" || return
  fi
  [[ "$OBI_COMPATIBILITY_LIFECYCLE_EXECUTOR_REGISTRY_SHA256" == \
    "$(compatibility_lifecycle_executor_registry_sha256 \
      "$executor_registry_snapshot")" ]] ||
    compatibility_die "lifecycle executor registry digest changed" || return
  if [[ -z "${OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER:-}" &&
    -z "${OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER_SHA256:-}" ]]; then
    export OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER="$SOURCE_LIFECYCLE_DRIVER"
    export OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER_SHA256
    OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER_SHA256="$(
      compatibility_sha256 "$SOURCE_LIFECYCLE_DRIVER"
    )"
  fi
  provider_run_external_driver \
    preprovisioned-lifecycle-application-v1 \
    OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER \
    OBI_COMPATIBILITY_LIFECYCLE_APPLICATION_DRIVER_SHA256 \
    lifecycle-resource-gated-platform-unavailable
}

main "$@"
