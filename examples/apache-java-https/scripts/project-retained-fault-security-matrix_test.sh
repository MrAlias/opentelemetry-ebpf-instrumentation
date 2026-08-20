#!/usr/bin/env bash
# Copyright The OpenTelemetry Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECTOR="$SCRIPT_DIR/project-retained-fault-security-matrix.sh"
SOURCE_VERIFIER="$SCRIPT_DIR/verify-retained-evidence.sh"
readonly SCRIPT_DIR PROJECTOR SOURCE_VERIFIER
readonly REVISION='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
readonly TREE='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'

TEST_DIRECTORY=""

die() {
  printf 'project-retained-fault-security-matrix_test.sh: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  if [[ -n "${TEST_DIRECTORY:-}" && -d "$TEST_DIRECTORY" &&
    ! -L "$TEST_DIRECTORY" ]]; then
    chmod -R u+rwX -- "$TEST_DIRECTORY" >/dev/null 2>&1 || true
    rm -rf -- "$TEST_DIRECTORY"
  fi
}

trap cleanup EXIT

write_fake_verifier() {
  local -r output="$1"

  cat >"$output" <<'FAKE'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ $# == 3 && "$1" == --raw-v3 && -d "$3" && ! -L "$3" ]]
[[ "$(<"$3/.fixture-kind")" == "$2" ]]
FAKE
  chmod 0755 -- "$output"
}

write_environment() {
  local -r output="$1"
  local -r transport="$2"
  local -r scenario="$3"
  printf '%s\n' \
    "revision=$REVISION" \
    "source_tree_sha256=$TREE" \
    "transport=$transport" \
    "scenario=$scenario" \
    >"$output"
}

write_pid_reuse_result() {
  local -r output="$1"
  local -r transport="$2"
  local negative_status=unsupported

  [[ "$transport" == unix ]] && negative_status=ambiguous
  jq -cS -n --arg transport "$transport" --arg negative "$negative_status" '{
    schema: "obi-pid-reuse-public-v1",
    status: "passed",
    transport: $transport,
    private_pid_namespace: true,
    same_namespace_inode: true,
    same_numeric_pid: true,
    same_numeric_tid: true,
    a_reaped_before_b: true,
    different_lifetime: true,
    obi_capabilities_nonzero: true,
    obi_capabilities_distinct: true,
    authorization_maps_agree: true,
    jvm_a_privileges_dropped: true,
    jvm_b_privileges_dropped: true,
    normal_cleanup: "completed",
    residue: "injected_after_a_reap",
    same_primary_socket: true,
    negative_status: $negative,
    injected_residue_rejected: true,
    injected_residue_preserved: true,
    w3c_fail_open: true,
    recovery_status: "valid",
    recovery_parent_exact: true,
    private_artifacts_removed: true
  }' >"$output"
}

write_raw_fixture() {
  local -r root="$1"
  local -r role="$2"
  local kind=""
  local transport=""
  local selected=""
  local scenario=all
  local complete=28
  local not_applicable=4

  case "$role" in
    all-getsockopt)
      kind=acceptance-getsockopt
      transport=getsockopt
      selected=getsockopt
      ;;
    all-unix)
      kind=acceptance-unix
      transport=unix
      selected=unix
      ;;
    all-auto)
      kind=acceptance-auto
      transport=auto
      selected=getsockopt
      ;;
    pid-reuse-getsockopt)
      kind=pid-reuse-getsockopt
      transport=getsockopt
      selected=getsockopt
      scenario=pid-reuse
      complete=1
      not_applicable=0
      ;;
    pid-reuse-unix)
      kind=pid-reuse-unix
      transport=unix
      selected=unix
      scenario=pid-reuse
      complete=1
      not_applicable=0
      ;;
    *) return 1 ;;
  esac
  mkdir -m 0700 -- "$root/$role"
  printf '%s\n' "$kind" >"$root/$role/.fixture-kind"
  write_environment "$root/$role/environment.txt" "$transport" "$scenario"
  jq -cS -n --arg scenario "$scenario" --arg requested "$transport" \
    --arg selected "$selected" --argjson complete "$complete" \
    --argjson not_applicable "$not_applicable" '
      {
        schema: "obi-metric-boundary-index-v1",
        selection: {
          scenario: $scenario,
          requested_transport: $requested,
          selected_transport: $selected,
          repeat_count: 1
        },
        boundaries:
          ([range(0; $complete) | {
            id: ("complete-" + tostring), state: "complete"
          }] + [range(0; $not_applicable) | {
            id: ("not-applicable-" + tostring), state: "not_applicable"
          }])
      }
    ' >"$root/$role/obi-metric-boundary-index.json"
  if [[ "$scenario" == pid-reuse ]]; then
    write_pid_reuse_result \
      "$root/$role/pid-reuse-controller.json" "$transport"
  fi
  printf '%s\n' \
    'trace_id=11111111111111111111111111111111' \
    'span_id=2222222222222222' \
    'host_pid=424242' \
    'request_marker=PRIVATE_MATRIX_CANARY' \
    >"$root/$role/raw-private-identifiers.txt"
}

make_fixture_set() {
  local -r root="$1"
  local role=""
  local -a roles=(
    all-getsockopt all-unix all-auto pid-reuse-getsockopt pid-reuse-unix
  )

  mkdir -m 0700 -- "$root"
  for role in "${roles[@]}"; do
    write_raw_fixture "$root" "$role"
  done
}

run_projection() {
  local -r fixture_root="$1"
  local -r output="$2"
  local -r projector="$TEST_DIRECTORY/scripts/project-retained-fault-security-matrix.sh"

  "$projector" \
    "$fixture_root/all-getsockopt" \
    "$fixture_root/all-unix" \
    "$fixture_root/all-auto" \
    "$fixture_root/pid-reuse-getsockopt" \
    "$fixture_root/pid-reuse-unix" \
    "$output" >/dev/null
}

expect_projection_failure() {
  local -r description="$1"
  local -r fixture_root="$2"
  local -r output="$3"

  if run_projection "$fixture_root" "$output" >/dev/null 2>&1; then
    die "projector accepted $description"
  fi
  [[ ! -e "$output" && ! -L "$output" ]] ||
    die "failed projection published output for $description"
}

restore_fixtures() {
  local -r fixture_root="$1"
  local -r baseline="$2"

  chmod -R u+rwX -- "$fixture_root" >/dev/null 2>&1 || true
  rm -rf -- "$fixture_root"
  cp -a -- "$baseline" "$fixture_root"
}

main() {
  local fixtures=""
  local baseline=""
  local public_parent=""
  local output=""
  local verifier_hash=""
  local expected_hash=""
  local file_count=""

  [[ -x "$PROJECTOR" && -x "$SOURCE_VERIFIER" ]] ||
    die 'projector or verifier is not executable'
  TEST_DIRECTORY="$(mktemp -d)"
  chmod 0700 -- "$TEST_DIRECTORY"
  mkdir -m 0700 -- "$TEST_DIRECTORY/scripts"
  cp -- "$PROJECTOR" \
    "$TEST_DIRECTORY/scripts/project-retained-fault-security-matrix.sh"
  chmod 0755 -- \
    "$TEST_DIRECTORY/scripts/project-retained-fault-security-matrix.sh"
  write_fake_verifier \
    "$TEST_DIRECTORY/scripts/verify-retained-evidence.sh"
  fixtures="$TEST_DIRECTORY/fixtures"
  baseline="$TEST_DIRECTORY/baseline"
  public_parent="$TEST_DIRECTORY/public"
  output="$public_parent/matrix"
  make_fixture_set "$fixtures"
  cp -a -- "$fixtures" "$baseline"
  mkdir -m 0700 -- "$public_parent"

  run_projection "$fixtures" "$output"
  (CDPATH='' cd / && bash "$output/verify.sh" >/dev/null) ||
    die 'portable verifier rejected the valid projected matrix'
  "$SOURCE_VERIFIER" --fault-security-matrix-v1 "$output" >/dev/null ||
    die 'source verifier rejected the valid projected matrix'
  file_count="$(find -- "$output" -mindepth 1 -maxdepth 1 -type f \
    -printf '.\n' | awk 'END {print NR + 0}')"
  [[ "$file_count" == 6 &&
    "$(find -- "$output" -mindepth 1 -maxdepth 1 -type d -printf '.\n' |
      awk 'END {print NR + 0}')" == 0 ]] ||
    die 'projected matrix did not retain its exact six-file closure'
  if grep -R -E -q \
    'PRIVATE_MATRIX_CANARY|11111111111111111111111111111111|2222222222222222|424242' \
    "$output"; then
    die 'projected matrix leaked a private identifier canary'
  fi
  verifier_hash="$(sha256sum <"$output/verify.sh")"
  verifier_hash="${verifier_hash%% *}"
  expected_hash="$(awk \
    '/^[[:space:]]*cat >"\$output" <<'"'"'VERIFY'"'"'$/{inside=1; next} \
     /^VERIFY$/{inside=0} inside {print}' "$PROJECTOR" | sha256sum)"
  expected_hash="${expected_hash%% *}"
  [[ "$verifier_hash" == "$expected_hash" ]] ||
    die 'projected portable verifier bytes drifted from the source heredoc'

  chmod -R u+rwX -- "$output"
  jq '.profiles[3].pid_reuse.same_numeric_pid = false' \
    "$output/fault-security-matrix.json" >"$output/fault-security-matrix.json.tmp"
  mv -- "$output/fault-security-matrix.json.tmp" \
    "$output/fault-security-matrix.json"
  if (CDPATH='' cd / && bash "$output/verify.sh" >/dev/null 2>&1); then
    die 'portable verifier accepted a mutated PID-reuse claim'
  fi
  rm -rf -- "$output"

  restore_fixtures "$fixtures" "$baseline"
  jq '.status = "unsupported"' \
    "$fixtures/pid-reuse-getsockopt/pid-reuse-controller.json" \
    >"$fixtures/pid-reuse-getsockopt/pid-reuse-controller.json.tmp"
  mv -- "$fixtures/pid-reuse-getsockopt/pid-reuse-controller.json.tmp" \
    "$fixtures/pid-reuse-getsockopt/pid-reuse-controller.json"
  expect_projection_failure 'an unsupported PID-reuse result' "$fixtures" "$output"

  restore_fixtures "$fixtures" "$baseline"
  jq '.same_numeric_tid = false' \
    "$fixtures/pid-reuse-unix/pid-reuse-controller.json" \
    >"$fixtures/pid-reuse-unix/pid-reuse-controller.json.tmp"
  mv -- "$fixtures/pid-reuse-unix/pid-reuse-controller.json.tmp" \
    "$fixtures/pid-reuse-unix/pid-reuse-controller.json"
  expect_projection_failure 'a PID-reuse result without numeric TID reuse' \
    "$fixtures" "$output"

  restore_fixtures "$fixtures" "$baseline"
  sed -i 's/^revision=.*/revision=cccccccccccccccccccccccccccccccccccccccc/' \
    "$fixtures/all-auto/environment.txt"
  expect_projection_failure 'matrix cells from different revisions' \
    "$fixtures" "$output"

  restore_fixtures "$fixtures" "$baseline"
  jq '.selection.selected_transport = "unix"' \
    "$fixtures/all-auto/obi-metric-boundary-index.json" \
    >"$fixtures/all-auto/obi-metric-boundary-index.json.tmp"
  mv -- "$fixtures/all-auto/obi-metric-boundary-index.json.tmp" \
    "$fixtures/all-auto/obi-metric-boundary-index.json"
  expect_projection_failure 'an auto cell with the impossible successful selection' \
    "$fixtures" "$output"

  restore_fixtures "$fixtures" "$baseline"
  ln -s -- environment.txt "$fixtures/all-unix/symlink"
  expect_projection_failure 'a raw input symbolic link' "$fixtures" "$output"

  restore_fixtures "$fixtures" "$baseline"
  mkdir -- "$output"
  : >"$output/pre-existing-canary"
  if run_projection "$fixtures" "$output" >/dev/null 2>&1; then
    die 'projector accepted a pre-existing output target'
  fi
  [[ -f "$output/pre-existing-canary" ]] ||
    die 'failed projection replaced a pre-existing output target'
  rm -rf -- "$output"

  printf 'fault/security matrix projection mutation tests passed\n'
}

main "$@"
