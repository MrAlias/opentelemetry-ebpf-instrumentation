# Issue #34 TLS wire-boundary fixture evidence

Result: **bounded fixture pass; correlated application-path proof remains open**

This bounded public subset comes from a clean, fresh-build, full `all` run at
`8282d2ed9c3a3f6925902cd84f11f491bc4f4565`. It supplements the broader
primary acceptance bundle with a nested TLS wire-record fixture. The fixture's
traffic and the correlated Apache-to-Java trigger are separate paths, so this
bundle does not close issue #34, replace the broader bundle for unrelated
controls, or promote unretained matrix cells.

## Run identity

| Field | Value |
| --- | --- |
| Public evidence ID | `otel-getsockopt-tls13-8282d2ed` |
| Source revision | `8282d2ed9c3a3f6925902cd84f11f491bc4f4565` |
| Source state | clean |
| Source-tree manifest SHA-256 | `9ea74c0e02a25fe2df0a8fa94bb7a5017e1712446a205172cd485988bbbc075c` |
| Invocation | `./examples/apache-java-https/run.sh --transport getsockopt --agent otel --tls TLSv1.3` |
| Acceptance mode | fresh-build full `all` suite |
| Runner results | 44 passed, 2 expected unsupported, 0 failed |
| Agent | official OpenTelemetry Java agent 2.28.1 |
| Agent SHA-256 | `faa89bdeebf9b1f52be4a4374689176717b02a59df2d8f8b6eb9aa39f9292589` |
| Java feature version | 21 |
| Transport | forced `getsockopt` |
| TLS / backend HTTP | TLS 1.3 / HTTP/1.1 |
| Architecture | x86_64 |
| Kernel | Linux 7.0.0-1009-aws |

[run-status.json](run-status.json), [environment.txt](environment.txt),
[source-state.txt](source-state.txt), [runtime-metadata.json](runtime-metadata.json),
[official-javaagent.json](official-javaagent.json), and
[bridge-artifacts.json](bridge-artifacts.json) retain the bounded run and source
identity. The retained-evidence verifier regenerates
[source-tree.manifest](source-tree.manifest) from the recorded Git revision.
The two unsupported suite statuses were Unix-only controls that do not apply to
the forced `getsockopt` run; they are not reported as passes. Only the
TLS-boundary status and graph are retained from the 46 scenario records.

## Retained proof

[scenario-tls-boundary.json](scenario-tls-boundary.json) and its
[passing status](scenario-tls-boundary-status.json) record both planned cases:

| Case | Plaintext writes / Java callbacks | TLS application records | Ordering |
| --- | --- | --- | --- |
| split | `[26, 128]` / `[26, 128]` | legacy versions `[771, 771]`, encrypted payload lengths `[59, 161]` | the first decrypted callback gates the second write; one request and response complete as `[1]` |
| coalesced | `[313]` / `[313]` | legacy version `[771]`, encrypted payload length `[346]` | requests and responses `[1, 2]` remain ordered |

For both cases, the Java backend opens a separate JSSE client connection to a
loopback Netty server. That nested fixture records exact wire and
decrypted-callback cardinality, unchanged buffer forwarding,
receive-to-parse thread handoff, and connection closure. Every retained TLS
application-data record uses the TLS 1.3 legacy record version `0x0303` (`771`),
and each encrypted payload is 33 bytes larger than its corresponding plaintext
callback, inside the independently enforced `(0, 256]` overhead bound.

Each scenario case separately retains exactly one Apache client span and one
Java server span for the outer `/api/tls-boundary` trigger. Their trace IDs
match and the outer Java span's parent span ID is the Apache client span ID.
Those spans do not represent the nested loopback requests, which carry no
Apache context and have no retained server spans. The bundle therefore proves
the outer trigger's exact parent and the nested fixture's boundary shape, but
not their same-request conjunction. Synthetic markers select the expected
outer graph only; they are not a propagation mechanism. No TLS payload bytes
are retained or included in the evidence.

The broader full-suite controls for keepalive, pipelining, parallelism,
connection churn, fd/port reuse, slow bodies, timeout/retry, map pressure,
reason-coded misses, cleanup, and recovery passed in this same run. Their raw
records are deliberately omitted from this issue-specific subset; the
pre-existing full primary bundle remains the public proof for those controls
at its recorded revision.

## Integrity checks

From the repository root:

```bash
( cd examples/apache-java-https/evidence/otel-getsockopt-tls13-8282d2ed && \
  sha256sum --check --strict SHA256SUMS )

./examples/apache-java-https/scripts/verify-retained-evidence.sh \
  examples/apache-java-https/evidence/otel-getsockopt-tls13-8282d2ed

jq -e '
  .status == "passed" and
  .scenario == "tls-boundary" and
  [.cases[].request.tls_boundary_mode] == ["split", "coalesced"] and
  [.cases[].response.tls_boundary.actual_plaintext_callback_lengths] ==
    [[26, 128], [313]] and
  [.cases[].response.tls_boundary.tls_application_record_legacy_versions] ==
    [[771, 771], [771]] and
  [.cases[].response.tls_boundary.tls_application_record_payload_lengths] ==
    [[59, 161], [346]] and
  all(.cases[];
    .response.tls_boundary.passed and
    .response.tls_boundary.shape_exact and
    .response.tls_boundary.wire_tls_record_shape_exact and
    .response.tls_boundary.buffers_forwarded_unchanged and
    .response.tls_boundary.handoff_before_parse and
    .response.tls_boundary.connection_closed)
' examples/apache-java-https/evidence/otel-getsockopt-tls13-8282d2ed/scenario-tls-boundary.json
```

[SANITIZATION.md](SANITIZATION.md) enumerates every retained transformation and
omitted raw category. `SHA256SUMS` covers this public subset, not the ignored
operational bundle.

## Scope boundary

This bundle proves the nested fixture's TLS record/callback shape only for the
recorded TLS 1.3, Java 21, x86_64 environment. It does not prove that a
correlated Apache-to-Java bridge request remains exact when that same request
is split or coalesced at TLS and Java receive boundaries. It also does not
prove another TLS version, transport, agent, JVM, architecture, kernel, cgroup
topology, or arbitrary application write-to-record behavior. Those application
and compatibility dimensions remain open.
