# Focused forced-primary control validation

Result: **focused validation passed — not acceptance evidence**

This bounded, reviewer-facing record retains three clean, privileged targeted
`getsockopt` control runs from source revision
`8f0aa1f6a7a28af93875823e4cf41675221d3542`. Each raw run recorded
`acceptance_evidence=false` because it exercised one targeted scenario rather
than the complete `all` suite. Consequently, this directory does **not** add a
compatibility-matrix pass, replace a clean full acceptance run, or close an
unexecuted threat-matrix row.

The record makes the current behavior of three primary controls independently
reviewable without publishing operational identifiers from the raw runtime
bundles:

| Control | Result | Bounded proof |
| --- | --- | --- |
| Primary isolation | passed | The runner verified a sibling container with a distinct cgroup and isolated network/PID namespaces, and an unprivileged same-cgroup process. Each received isolated `unauthorized` primary-operation metric deltas while a legitimate exact-parent victim and post-abuse recovery both passed. |
| Primary stale entry | passed | A forced `1ns` retrieval TTL produced Java status `stale`; a valid standard W3C context remained the Java server parent; recovery then passed. |
| Primary malformed reply | passed | Private one-shot controls produced `version_mismatch`, `malformed` zero-trace-ID, and `malformed` zero-span-ID outcomes. Each retained the supplied W3C parent and the subsequent recovery passed. |

## Run identity

| Field | Value |
| --- | --- |
| Source revision | `8f0aa1f6a7a28af93875823e4cf41675221d3542` |
| Source state | clean |
| Source-tree SHA-256 | `b2b666ac5a1bb0aa7715ff2c0fbac2455e3eba1db5810d9b75e190ed8c79c27a` |
| Agent | official OpenTelemetry Java agent 2.28.1 |
| JVM | Java 21 |
| Transport | forced `getsockopt`; V2 configuration selected the primary transport |
| TLS | 1.3 |
| Host boundary | `x86_64`, Linux `7.0.0-1009-aws`, unified cgroup v2, readable vmlinux BTF |
| Acceptance mode | targeted scenarios only; `acceptance_evidence=false` |

[run-identity.json](run-identity.json) records the sanitized run identities,
and [java-selected-transport-configuration.txt](java-selected-transport-configuration.txt)
records the fixed V2 Java selection snapshot. The snapshot confirms
configuration selection only; the scenario assertions establish request-level
behavior.

## Retained summaries

- [security-primary-probes.json](security-primary-probes.json) records the two isolated
  authorization windows, their bounded primary metric deltas, and the passed
  victim and recovery assertions. A raw primary probe reports
  `native-unsupported` intentionally: unauthorized calls fall through to the
  native socket result after the BPF policy increments its reason-coded metric.
  The isolated metric deltas, not that native result, verify interception.
- [primary-w3c-fail-open.json](primary-w3c-fail-open.json) records stale
  rejection, returned-response faults, W3C precedence, Java diagnostic deltas,
  source-labeled OBI operation deltas, and recovery without retaining trace,
  socket, process, or container identifiers.
- [primary-w3c-fault-controls.json](primary-w3c-fault-controls.json) records
  the private one-shot control's sanitized ownership, mode, payload length,
  and post-consumption state.

## Not established here

- a full primary acceptance matrix cell or a broader kernel/JVM/agent claim;
- Unix fallback same-cgroup or sibling isolation;
- wrong-live-socket / duplicated-descriptor application-level evidence;
- a retained Unix stale-state result; or
- benchmark and compatibility outcomes.

Those limits are deliberate. See [SECURITY.md](../../SECURITY.md),
[COMPATIBILITY.md](../../COMPATIBILITY.md), and
[BENCHMARK.md](../../BENCHMARK.md) for the current matrix status.

## Integrity

From this directory:

```bash
sha256sum -c SHA256SUMS

jq -e '
  .kind == "focused-non-acceptance-validation" and
  all(.runs[]; .status == "passed" and .acceptance_evidence == false)
' run-identity.json

jq -e '
  .status == "passed" and
  .same_cgroup.metric_delta.take_unauthorized > 0 and
  .sibling.metric_delta.take_unauthorized > 0 and
  .legitimate_victim.status == "passed" and
  .post_abuse_recovery.status == "passed"
' security-primary-probes.json

jq -e '
  .status == "passed" and
  .stale.obi_operations_delta.take_stale == 1 and
  (.faults | length == 3) and
  all(.faults[]; .obi_operations_delta.take_valid == 1) and
  .fault_recovery.status == "passed"
' primary-w3c-fail-open.json
```

[SANITIZATION.md](SANITIZATION.md) explains the transformations. The checksum
manifest supports an integrity check against a separately trusted checkout or
commit; it does not authenticate the ignored raw runtime bundles.
