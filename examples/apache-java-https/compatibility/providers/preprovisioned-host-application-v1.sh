#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
# shellcheck disable=SC1091  # Resolved from this script's physical directory.
source "$SCRIPT_DIRECTORY/provider-lib.sh"

main() {
  provider_require_environment
  provider_run_external_driver \
    preprovisioned-host-application-v1 \
    OBI_COMPATIBILITY_HOST_APPLICATION_DRIVER \
    OBI_COMPATIBILITY_HOST_APPLICATION_DRIVER_SHA256 \
    host-application-platform-unavailable
}

main "$@"
