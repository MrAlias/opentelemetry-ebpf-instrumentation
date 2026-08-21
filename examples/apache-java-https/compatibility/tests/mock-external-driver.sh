#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
umask 077

DRIVER_PATH="$(readlink -f -- "$0")"
readonly DRIVER_PATH
declare -a original_argv=("$DRIVER_PATH" "$@")
contract=""
campaign=""
campaign_revision=""
plan_sha256=""
cell=""
source_authority=""
source_authority_sha256=""
private_output=""

while (( $# > 0 )); do
  case "$1" in
    --contract) contract="${2:?}"; shift 2 ;;
    --campaign) campaign="${2:?}"; shift 2 ;;
    --campaign-revision) campaign_revision="${2:?}"; shift 2 ;;
    --plan-sha256) plan_sha256="${2:?}"; shift 2 ;;
    --cell) cell="${2:?}"; shift 2 ;;
    --source-authority) source_authority="${2:?}"; shift 2 ;;
    --source-authority-sha256) source_authority_sha256="${2:?}"; shift 2 ;;
    --private-output) private_output="${2:?}"; shift 2 ;;
    *) printf 'unexpected argument: %s\n' "$1" >&2; exit 2 ;;
  esac
done

[[ "$contract" == compatibility-external-provider-v1 ]]
[[ "$campaign" == compatibility || "$campaign" == helper-lifecycle ]]
[[ -n "$campaign_revision" ]]
[[ "$plan_sha256" =~ ^[0-9a-f]{64}$ ]]
[[ -f "$cell" && ! -L "$cell" ]]
[[ -f "$source_authority" && ! -L "$source_authority" ]]
[[ "$(sha256sum -- "$source_authority")" == "$source_authority_sha256  $source_authority" ]]
[[ -d "$private_output" && ! -L "$private_output" ]]

case "${OBI_COMPATIBILITY_MOCK_MODE:-malformed}" in
  malformed)
    printf '{"schema":"malformed-on-purpose"}\n' \
      >"$private_output/provider-result.json"
    chmod 0600 -- "$private_output/provider-result.json"
    ;;
  missing-assertions)
    jq -nS \
      --arg provider "$(jq -er '.provider' "$cell")" \
      --arg adapter_sha256 "$(sha256sum -- "$DRIVER_PATH" | awk '{print $1}')" \
      --argjson argv "$(printf '%s\0' "${original_argv[@]}" |
        jq -Rs 'split("\u0000")[:-1]')" '
        {
          schema: "compatibility-provider-result-v1",
          provider: $provider,
          status: "pass",
          command: {
            adapter_sha256: $adapter_sha256,
            exit_status: 0,
            argv: $argv
          },
          assertions: null
        }
      ' >"$private_output/provider-result.json"
    chmod 0600 -- "$private_output/provider-result.json"
    ;;
  missing)
    ;;
  lying-argv)
    jq -nS \
      --arg provider "$(jq -er '.provider' "$cell")" \
      --arg adapter_sha256 "$(sha256sum -- "$DRIVER_PATH" | awk '{print $1}')" '
        {
          schema: "compatibility-provider-result-v1",
          provider: $provider,
          status: "fail",
          command: {
            adapter_sha256: $adapter_sha256,
            exit_status: 0,
            argv: ["fabricated-driver-argv"]
          },
          assertions: {}
        }
      ' >"$private_output/provider-result.json"
    chmod 0600 -- "$private_output/provider-result.json"
    ;;
  untested)
    jq -nS \
      --arg campaign "$campaign" \
      --arg campaign_revision "$campaign_revision" \
      --arg plan_sha256 "$plan_sha256" \
      --arg provider "$(jq -er '.provider' "$cell")" \
      --arg adapter_sha256 "$(sha256sum -- "$DRIVER_PATH" | awk '{print $1}')" \
      --arg revision "$(jq -er '.revision' "$source_authority")" \
      --arg git_tree "$(jq -er '.git_tree' "$source_authority")" \
      --argjson requested "$(jq -cS . "$cell")" \
      --argjson argv "$(printf '%s\0' "${original_argv[@]}" |
        jq -Rs 'split("\u0000")[:-1]')" '
        {
          schema: "compatibility-provider-result-v1",
          campaign: $campaign,
          campaign_revision: $campaign_revision,
          plan_sha256: $plan_sha256,
          cell_id: $requested.id,
          provider: $provider,
          status: "untested",
          reason: "mock-external-infrastructure-unavailable",
          attempted: true,
          infrastructure_failure: true,
          requested: $requested,
          command: {
            adapter_sha256: $adapter_sha256,
            exit_status: 69,
            argv: $argv
          },
          source: {revision: $revision, git_tree: $git_tree, clean: true},
          runtime: null,
          artifacts: null,
          assertions: null,
          evidence_index: null,
          raw_evidence: null
        }
      ' >"$private_output/provider-result.json"
    chmod 0600 -- "$private_output/provider-result.json"
    exit 69
    ;;
  swap-driver)
    : "${OBI_COMPATIBILITY_MOCK_SWAP_TARGET:?swap target is required}"
    [[ -f "$OBI_COMPATIBILITY_MOCK_SWAP_TARGET" &&
      ! -L "$OBI_COMPATIBILITY_MOCK_SWAP_TARGET" ]]
    mv -- "$OBI_COMPATIBILITY_MOCK_SWAP_TARGET" \
      "$OBI_COMPATIBILITY_MOCK_SWAP_TARGET.before-swap"
    printf '#!/usr/bin/env bash\nexit 99\n' \
      >"$OBI_COMPATIBILITY_MOCK_SWAP_TARGET"
    chmod 0500 -- "$OBI_COMPATIBILITY_MOCK_SWAP_TARGET"
    ;;
  *)
    printf 'unknown mock mode\n' >&2
    exit 2
    ;;
esac
