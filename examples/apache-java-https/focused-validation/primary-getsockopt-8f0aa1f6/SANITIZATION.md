# Focused-validation sanitization

This directory is a derived, reviewer-facing summary of three ignored runtime
result directories. It intentionally retains control outcomes rather than raw
scenario graphs or operational records. The public directory name is derived
from the source revision, not a timestamp or process identifier.

The summary omits raw command logs, local checkout paths, timestamps,
hostnames, container IDs, host and namespace PIDs, cgroup paths, socket and
connection identifiers, BPF map/program IDs, trace/span IDs, marker values,
and fault-control paths. It also omits raw metric snapshots, response bodies,
and build artifacts. It retains only the three sanitized relative invocations
needed to reproduce the focused controls.

The retained JSON records only:

- clean source identity and allowlisted host/agent/transport facts;
- targeted-run status and the fact that each run is non-acceptance evidence;
- isolated `unauthorized` metric *deltas* for the primary security controls;
- bounded probe case classifications, attempt counts, and the allowlisted
  unprivileged UID/GID class without container, process, or namespace
  identities;
- expected Java status classes, W3C-precedence booleans, scenario/recovery pass
  results, and source-labeled OBI/Java diagnostic deltas; and
- the V2 fixed transport-selection snapshot.

The `native-unsupported` probe classification is retained as an explanation of
the primary transport contract, not as a security assertion. The runner's
isolated BPF metric deltas establish the observed unauthorized interception.

`primary-w3c-fail-open.json` names the delta source explicitly. The stale
case records both an OBI `take=stale` delta and its Java diagnostic delta. The
fault cases record an OBI `take=valid` delta because the shim changes a valid
primary reply after BPF retrieval, plus the distinct Java diagnostic delta for
the resulting fail-open classification.

The checksum manifest supports an integrity check when obtained from a
separately trusted checkout or commit. It does not claim that any file is a
byte-for-byte copy of an omitted raw result.

The summary remains outside `evidence/` because all three source runs are
targeted non-acceptance validation.
