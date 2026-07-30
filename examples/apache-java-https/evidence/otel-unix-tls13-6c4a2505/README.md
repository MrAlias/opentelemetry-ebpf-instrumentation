# OpenTelemetry Unix RPC TLS 1.3 acceptance

Result: **pass**

This bounded, reviewer-facing subset comes from one clean full `all` run. Its
public evidence ID derives from the tested matrix cell and source revision, not
from the timestamp-and-process runtime directory. It proves only the exact
cell below; it does not make unexecuted transports, agents, kernels, cgroup
topologies, architectures, JVMs, or extraction boundaries pass.

## Run identity

| Field | Value |
| --- | --- |
| Public evidence ID | `otel-unix-tls13-6c4a2505` |
| Source revision | `6c4a2505b6a6d4e89d3aedd9952097ad42ce1457` |
| Source state | clean |
| Source-tree manifest SHA-256 | `7aa5d4e1b530dad3ac44f76e288d8a5e3a7d5a1d5b0dd83e1653ddd34f87cbf8` |
| Invocation | `./examples/apache-java-https/run.sh --transport unix --agent otel --tls TLSv1.3 --scenario all` |
| Acceptance mode | full `all` suite |
| Runner result | 48 passed, 2 expected unsupported, 0 failed |
| Transport | forced Unix RPC |
| Agent | official OpenTelemetry Java agent 2.28.1 |
| TLS | 1.3 |
| JVM | Temurin 21.0.10+7 |
| Architecture / cgroup | `x86_64` / unified v2 |
| Kernel | Linux `7.0.0-1009-aws`; distribution not independently recorded |

[environment.txt](environment.txt), [source-state.txt](source-state.txt),
[runtime-metadata.json](runtime-metadata.json),
[official-javaagent.json](official-javaagent.json), and
[bridge-artifacts.json](bridge-artifacts.json) retain bounded run and source
identity. [run-status.json](run-status.json) records `status=passed`, exit
status 0, and `acceptance_evidence=true`. The V2
[transport snapshot](java-selected-transport-configuration.txt) records that
Unix was requested, selected, and attempted while `getsockopt` was not used.

## Retained proof

| Claim | Primary artifacts |
| --- | --- |
| Verified Apache-to-Jetty HTTPS, HTTP/1.1, and TLS 1.3 | [Apache/OpenSSL identity](apache-openssl-runtime.txt), and the retained security-victim and recovery graphs, whose responses name TLS 1.3 and `TLS_AES_256_GCM_SHA384`. |
| Forced Unix JVM-to-OBI retrieval RPC | [V2 transport snapshot](java-selected-transport-configuration.txt), [runtime metadata](runtime-metadata.json), and the exact-parent graphs below. |
| Sibling Unix attacker cannot retrieve a parent | [sanitized sibling topology and metrics](security-unix-probes.json), [status](scenario-concurrency-security-unix-sibling-victim-status.json), and the [concurrent legitimate-victim graph](scenario-concurrency-security-unix-sibling-victim.json). |
| Same-cgroup Unix attacker cannot retrieve a parent | [sanitized same-cgroup topology and metrics](security-unix-probes.json), [status](scenario-concurrency-security-unix-same-cgroup-victim-status.json), and the [concurrent legitimate-victim graph](scenario-concurrency-security-unix-same-cgroup-victim.json). |
| Endpoint replacement and an unsafe directory fail closed without breaking the app | [sanitized endpoint and directory outcomes](security-unix-probes.json), [post-abuse recovery status](scenario-basic-security-recovery-status.json), and [recovery graph](scenario-basic-security-recovery.json). |
| A stale Unix retrieval is not used as a parent, and normal retrieval recovers | [stale summary](unix-w3c-stale.json), [stale status](scenario-unix-w3c-stale-status.json), [stale graph](scenario-unix-w3c-stale.json), [recovery status](scenario-basic-unix-w3c-stale-recovery-status.json), and [recovery graph](scenario-basic-unix-w3c-stale-recovery.json). |

The sibling fixture was a non-root `65534:65534` peer in a distinct cgroup and
private PID namespace, with no network, no capabilities, a read-only root
filesystem, `no-new-privileges`, and no writable socket mount. The same-cgroup
fixture was also `65534:65534`, capability-free, and in Java's PID namespace
and cgroup. Both intentional attacker fixtures reached the Unix protocol;
their peer/process identity controls were exercised rather than replaced by a
filesystem-denied connection.

The sibling probe recorded 21,967 attempts and the same-cgroup probe recorded
19,209. Every attacker retrieval case reported `unauthorized`, `malformed`,
`version_mismatch`, or a bounded admission outcome; no probe case returned a
valid parent. Their operation deltas contain 21,987 and 19,230 unauthorized
Unix takes respectively. The separate `take_valid=17` delta in each window is
17 legitimate operations: one pre-scenario metric-boundary health request and
the 16 concurrent victims retained in its matching graph. It is not an
attacker success.

The stale control force-recreated the Unix bridge with a 1ns retrieval TTL. It
recorded one OBI and one Java `stale` take delta, zero valid and missing take
deltas in that isolated phase, preserved the supplied exact W3C parent in the
passing graph, then restored the normal TTL and passed recovery. It uses the
real OBI Unix handler, not the synthetic fault responder.

## Scope limits

- This run uses the OpenTelemetry Java agent, Java 21, `amd64`, one observed
  unified-cgroup-v2 host, and one kernel. Splunk, JVM 8/11/17, `arm64`, RHEL
  kernels, hybrid/delegated cgroups, and representative upstream kernels remain
  untested by this bundle.
- This run proves forced Unix RPC with TLS 1.3 only. `auto`, forced
  `getsockopt`/TLS 1.3, and all TLS 1.2 cells have separate evidence or remain
  untested as the compatibility matrix states.
- The retained attacker controls do not prove rejection of a wrong live socket
  identity and do not close issue #40. They also do not replace the primary
  live-descriptor control, the VM-gated JNI fixture, or a complete two-
  transport threat matrix.
- This is acceptance evidence, not a retained transport benchmark or a
  sustained overhead result. The benchmark and external compatibility matrices
  remain open.

## Integrity checks

From the repository root:

```bash
( cd examples/apache-java-https/evidence/otel-unix-tls13-6c4a2505 && sha256sum -c SHA256SUMS )

./examples/apache-java-https/scripts/verify-retained-evidence.sh \
  examples/apache-java-https/evidence/otel-unix-tls13-6c4a2505

jq -e '
  .status == "passed" and
  .sibling.metric_delta.take_unauthorized == 21987 and
  .same_cgroup.metric_delta.take_unauthorized == 19230 and
  .endpoint_replacement.status == "passed" and
  .permissive_directory.listener_outcome == "refused"
' examples/apache-java-https/evidence/otel-unix-tls13-6c4a2505/security-unix-probes.json

jq -e '
  .status == "passed" and
  .retrieval_ttl == "1ns" and
  .bridge_delta.take_stale == 1 and
  .java_delta.take_stale == 1 and
  .recovery.status == "passed"
' examples/apache-java-https/evidence/otel-unix-tls13-6c4a2505/unix-w3c-stale.json
```

[SANITIZATION.md](SANITIZATION.md) lists the transformations and omitted raw
records. The checksum manifest authenticates this public subset, not the
ignored runtime bundle.
