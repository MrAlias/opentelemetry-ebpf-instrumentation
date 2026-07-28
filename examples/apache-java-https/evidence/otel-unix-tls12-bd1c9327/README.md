# OpenTelemetry Unix RPC TLS 1.2 acceptance

Result: **pass**

This bounded, reviewer-facing subset comes from one clean full run. Its public
evidence ID derives from the tested matrix cell and source revision, not from
the original timestamp-and-process runtime directory. It proves only the exact
cell below; it does not make unexecuted transports, agents, kernels, cgroup
topologies, architectures, JVMs, or extraction boundaries pass.

## Run identity

| Field | Value |
| --- | --- |
| Public evidence ID | `otel-unix-tls12-bd1c9327` |
| Source revision | `bd1c932791791b910bba071e912de9455169c69d` |
| Source state | clean |
| Source-tree manifest SHA-256 | `4a388fc9d70492fd3dae99341f71bd31ae1db0172a9a1ca54570be6b387c596d` |
| Invocation | `./examples/apache-java-https/run.sh --transport unix --agent otel --tls TLSv1.2 --command-timeout 1800 --readiness-timeout 120` |
| Acceptance mode | full `all` suite |
| Transport | forced Unix RPC |
| Agent | official OpenTelemetry Java agent 2.28.1 |
| Agent SHA-256 | `faa89bdeebf9b1f52be4a4374689176717b02a59df2d8f8b6eb9aa39f9292589` |
| TLS | 1.2 |
| JVM | Temurin 21.0.10+7 |
| Architecture | `x86_64` |
| Kernel | Linux `7.0.0-1009-aws`; distribution not independently recorded |
| Cgroup | observed unified v2 |
| Runner result | 43 passed, 0 unsupported, 0 failed |

[environment.txt](environment.txt), [source-state.txt](source-state.txt),
[runtime-metadata.json](runtime-metadata.json),
[official-javaagent.json](official-javaagent.json), and
[bridge-artifacts.json](bridge-artifacts.json) retain bounded run and source
identity. [run-status.json](run-status.json) records `status=passed`, exit
status 0, and `acceptance_evidence=true`.

## Retained proof

| Claim | Primary artifacts |
| --- | --- |
| Verified Apache-to-Jetty HTTPS, HTTP/1.1, TLS 1.2 | [Apache/OpenSSL identity](apache-openssl-runtime.txt), [certificate metadata](certificates.json), [basic response and exact-parent graph](scenario-basic.json) |
| Forced Unix JVM-to-OBI retrieval RPC and exact remote parent | [basic graph](scenario-basic.json), [basic status](scenario-basic-status.json), and `phases/basic-after/{obi-metrics,java-diagnostics}.delta` |
| Pinned unmodified agent plus separate helper and extension | [official agent identity](official-javaagent.json), [bridge checksums](bridge-artifacts.json), [sanitized runtime metadata](runtime-metadata.json) |
| W3C precedence, matching parents, and sampled/unsampled take outcomes | [conflicting/invalid W3C](scenario-w3c.json), [matching W3C](scenario-w3c-match.json), [OBI record flags](scenario-obi-flags.json) |
| Unix fault classification and fail-open behavior | `scenario-w3c-fault-*.json`, matching status records, and matching `phases/w3c-fault-*-after/java-diagnostics.delta` |
| Unix peer, framing, admission, endpoint-replacement, and directory-permission abuse handling | [security status](scenario-security-status.json), [sanitized probe results](security-unix-probes.json), [legitimate concurrent traffic](scenario-concurrency-security-unix-victim.json), [post-abuse recovery](scenario-basic-security-recovery.json) |
| Keepalive, pipelining, parallelism, churn, descriptor/port reuse, slow body, and retry | [keepalive](scenario-keepalive.json), [pipelining](scenario-pipelining.json), [concurrency](scenario-concurrency.json), [churn](scenario-connection-churn.json), [reuse](scenario-fd-port-reuse.json), [slow body](scenario-slow-body.json), [retry](scenario-timeout-retry.json) |
| Live map pressure, exact-parent accounting, cleanup, and recovery | [pressure status](scenario-pressure-status.json), [pressure traces](scenario-pressure.json), [sanitized pressure summary](map-pressure-summary.json) |
| OBI restart, absence, late attach, helper failure, and recovery | [restart traffic](scenario-restart-fault.json), [restart states](restart-control/events.log), [late-attach recovery](scenario-restart-late-attach-recovery.json), [helper failure](scenario-helper-attach-failure-helper-unavailable.json), [helper recovery](scenario-basic-helper-attach-recovery.json) |
| Bridge/extension disabled and uninstrumented controls | [bridge disabled](scenario-disabled.json), [extension absent](scenario-w3c-only-extension-absent.json), [extension disabled](scenario-w3c-only-extension-disabled.json), [uninstrumented](scenario-uninstrumented.json) |
| Low-cardinality diagnostics and duplicate suppression | `phases/*/{java-diagnostics,obi-metrics}.delta`, [allowlisted suppression metric](duplicate-suppression.json), and every `scenario-*-status.json` |

The ten retained Unix fault modes cover alternating stale/malformed replies,
timeout, disconnect, overload, truncation, bad magic, bad size, version
mismatch, zero trace ID, and zero span ID. Each case preserves the Java
classification and a successful standard W3C fallback graph. Bad size and
malformed ABI length classify as `malformed`; the injected truncated reply
classifies as `transport_error`; only an ABI-version mismatch classifies as
`version_mismatch`.

The Unix server metrics record actual `take` requests with
`transport="unix"`. The current OBI `availability` metric is readiness
evidence only; it is not proof that a request used the selected transport.
Here `unix` labels the JVM-to-OBI remote-parent retrieval RPC. The
Apache-to-Java application path remains HTTPS over TCP, so upstream
candidate/stage/inject metrics retain `transport="tcp"` by design.

The pressure scenario records 127 exact parents and one explicit root across
128 requests, with zero wrong or unresolved parents. The Unix bridge reports
one `already_consumed` retrieval outcome, and Java records the matching
attributable absence. This exception is deliberate eviction accounting, not a
claim that every pressure request retained a remote parent.

Every retained scenario result contains sanitized synthetic traffic and the
bounded trace graph used by the assertion. The status records capture runner
and metric assertion results; references to intentionally omitted stderr logs
were removed. No private keys, request bodies, credentials, baggage,
tracestate, JVM-incarnation capability, or raw request headers are retained.
The only retained request-header attribute is the bounded synthetic
`x-obi-demo-id` marker used to join a test request to its trace graph.

The full `.runtime` bundle contained bulk metric snapshots and operational
logs. They are intentionally omitted. Retained OBI metric files contain only
bridge operation/status/transport labels and per-phase deltas; absolute
before/after values, numeric map identifiers, program identifiers, and
unrelated host metrics are excluded. Retained Java diagnostic deltas use the
fixed counter schema. The checksum manifest authenticates this public subset,
not the omitted raw bundle. [SANITIZATION.md](SANITIZATION.md) enumerates every
transformed or summarized record class.

## Integrity checks

From this directory:

```bash
sha256sum -c SHA256SUMS

test "$(sha256sum source-tree.manifest | cut -d' ' -f1)" = \
  4a388fc9d70492fd3dae99341f71bd31ae1db0172a9a1ca54570be6b387c596d

jq -e -s '
  (length == 43) and
  (map(select(.status == "passed")) | length == 43) and
  (map(select(.status != "passed")) | length == 0)
' scenario-*-status.json
```

`bpftool-feature-probe.txt` records that an unprivileged host-side full
feature probe was unavailable. The privileged OBI container nevertheless
loaded the programs and completed the forced Unix assertions. This artifact
does not establish compatibility with another kernel.

## Scope limits

- This run uses the OpenTelemetry Java agent, Java 21, `amd64`, one observed
  unified-cgroup-v2 host, and one kernel. Splunk, JVM 8/11/17, `arm64`, RHEL
  kernels, hybrid/delegated cgroups, and representative upstream kernels remain
  untested by this bundle.
- This run proves forced Unix RPC with TLS 1.2 only. `auto`,
  forced-`getsockopt`/TLS 1.2, and forced-Unix/TLS 1.3 remain untested.
  Forced-`getsockopt`/TLS 1.3 has separate retained evidence.
- The abuse matrix in this bundle is Unix-only. It does not establish the
  corresponding primary-transport cases, including wrong-socket and stale-TTL
  end-to-end cases, or a complete two-transport threat matrix.
- The `tls-boundary` scenario is an in-JVM TLS fixture reached after Jetty
  extraction; it is not evidence of a hook at the real Jetty connector's
  pre-extraction receive boundary.
- Executor, virtual-thread, Netty-executor, and redispatch scenarios exercise
  workload handoffs after the Jetty server span exists. They do not prove stock
  Netty server instrumentation before extraction.
- The unsampled OBI record is observed and counted, but this run does not claim
  that an exported child preserves the same sampled flag after the configured
  SDK sampler runs.
- The run covers bounded OBI/JVM absence and restart windows, not permanent
  process-lifetime absence or genuine PID/TID reuse. It exercises the ten
  injected fault modes listed above and observes six distinct Java
  classifications—`stale`, `malformed`, `transport_error`, `overload`,
  `timeout`, and `version_mismatch`—not every theoretical diagnostic category.
- Directory mode/ownership and peer rejection were asserted, but this public
  subset does not retain a live-socket `stat` record proving exact socket mode
  or ownership.
- The bundle is acceptance evidence, not a retained transport benchmark or a
  sustained overhead result.
