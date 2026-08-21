#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

SCRIPT_DIRECTORY="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIRECTORY
# shellcheck disable=SC1091  # Resolved from this script's physical directory.
source "$SCRIPT_DIRECTORY/lib.sh"

usage() {
  cat <<'EOF'
Usage: validate-plan.sh compatibility|helper-lifecycle
EOF
}

main() {
  [[ $# -eq 1 ]] || {
    usage >&2
    return 2
  }
  compatibility_validate_plan "$1"
}

main "$@"
