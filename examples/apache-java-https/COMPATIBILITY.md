# Compatibility evidence matrix

Matrix revision: `apache-java-https-compatibility-v3`.
<!-- obi-compatibility-matrix-revision: apache-java-https-compatibility-v3 -->

V3 is a source-complete campaign definition, not an execution claim. All 45
required V3 cells and all seven helper-lifecycle cells remain **pending** until
their exact providers run and the resulting records are sealed. Existing
linked bundles below are historical evidence for their recorded revisions;
they do not populate, pass, or close a V3 cell.

Cells without a linked run artifact remain **untested**. Kernel or distribution
version inference is not evidence. Runtime feature detection must name the
selected transport in the JVM's fixed transport-configuration snapshot; OBI's
bridge-readiness log proves availability, not Java selection. This snapshot is
retained as `java-selected-transport-configuration.txt` and is required for new
evidence produced after the V2 diagnostics contract was introduced. Older
linked bundles remain historical results for their recorded revisions, but do
not establish V3 selection at the current revision. `auto` cannot stand in for
forced primary and fallback tests and is outside the exact 45-cell V3
aggregate.

Each result must be one of `pass`, `fail`, `unsupported`, or `untested` and
include revision, kernel, architecture, cgroup mode, JVM, agent, Apache,
OpenSSL, TLS, transport, command, and artifact link.

## V3 campaign source and pending status

The executable source is in [`compatibility/`](compatibility/README.md). The
45-cell plan is [`campaign-v3.json`](compatibility/campaign-v3.json), with an
independent frozen ID roster in
[`expected-v3-cell-ids.txt`](compatibility/expected-v3-cell-ids.txt). The
collector rejects anything other than these exact, unique IDs.

| V3 factorized slice | Exact cell count | Source status |
| --- | ---: | --- |
| Kernel, topology, and deployment: 17 rows × two forced transports | 34 | pending / no V3 executions retained |
| JVM 8/11/17/21 × two pinned agents on fixed `amd64` primary, excluding the baseline already counted above | 7 | pending / no V3 executions retained |
| Native `arm64`, Java 21, OpenTelemetry, both forced transports | 2 | pending / no V3 executions retained |
| TLS 1.2 baseline, both forced transports | 2 | pending / no V3 executions retained |
| **Exact V3 aggregate** | **45** | **pending / aggregate not materialized** |

RHEL 8 / 4.18 is not one of the 45 cells. It remains explicitly `untested`
and requires direct execution on the documented backport; a RHEL or kernel
version string is never substituted for feature evidence. Backend HTTP/2
remains a documented product `unsupported` exclusion. Neither exclusion may
be synthesized into a campaign cell.

Issue #23's application/helper coverage is separately frozen in
[`helper-lifecycle-v1.json`](compatibility/helper-lifecycle-v1.json) and
[`expected-helper-cell-ids.txt`](compatibility/expected-helper-cell-ids.txt).
Its seven cells are all pending. They do not change the 45-ID V3 count. A pass
requires blocking `SSLSocket`, `SSLEngine`/`SocketChannel`, Netty
`SslHandler`, normal extraction and fallback, platform/executor/cross-thread
behavior, Java 21 virtual threads where applicable, early/late helper attach,
absence/restart/version-mismatch/load-order controls, duplicate/stale and
cross-request isolation, and every repeated FD/thread/direct-buffer/
classloader/request/task/thread-local/same-process resource gate.
The unavailable-bridge control also requires byte-identical normal and
fallback application results, a separately retained passing normal-agent
extraction proof, and bounded diagnostics (at most 64 entries and 65,536
bytes); missing, changed, or unbounded evidence cannot pass.

The runner distinguishes infrastructure `untested` from product
`unsupported` and assertion `fail`. Missing providers remain untested. A
checksum-verified provider that runs but omits or malforms required assertions
fails its cell. Raw evidence remains private; the public aggregate contains
only sealed identities, assertions, digests, and safe relative evidence-index
bindings—never raw bytes, absolute paths, command arguments, or secrets. Every
public runtime/artifact/assertion digest must resolve through that index to one
unique regular raw file and exact manifest entry. No status from an `auto`,
component-test, historical, neighboring-kernel, or neighboring-architecture
execution is projected into V3.

The checked-in host and JVM external-provider approvals remain empty. The
lifecycle provider now pins one reviewed outer-driver path and digest. Its
separate production inner-executor registry remains empty, so all seven real
lifecycle cells stay infrastructure `untested` until a reviewed executor path,
digest, and exact cell roster land; an environment descriptor or outer-driver
approval alone materializes no pass. An
arbitrary self-matching path and digest cannot authorize execution. A
registry-approved driver that is actually invoked retains its exact ID and
digest even when it returns infrastructure `untested`; only a pre-execution
unavailable or unapproved boundary has no driver identity. The local Java 21
adapter separately needs
exact kernel-provenance and topology-attestation files for every execution. It
cross-binds the attested process-cgroup digest to live and retained `/proc`
bytes, and semantically validates successful `bpftool`, Compose project/
container/image, Java runtime, host topology, and Apache/OpenSSL evidence before
publishing an authoritative runtime identity. Its current production evidence
can prove supported forced selection, but cannot prove the campaign's
unsupported control, so it fails closed instead of synthesizing `unsupported`.
All matrix and helper statuses in this document remain pending.

Registry parsing and executor containment are fail-closed source boundaries,
not execution evidence. Registry bytes and bounded approved-entry rosters are
consumed from one transaction-retained provider/inner snapshot pair with exact
before/after identities; producer errors, partial output, and traversal
substitution reject validation. Private inputs remain below retained directory
descriptors. File publication keeps the candidate descriptor open through a
no-replace rename, while directory publication retains and re-hashes an exact
bounded recursive path/type/identity/content roster before and after its
no-replace rename. The
lifecycle executor runs beneath a child subreaper that authenticates PID,
start-time, session, and process-group identities and uses `pidfd` signalling;
PID reuse, missing kernel primitives, a detached survivor, or incomplete
cleanup fails the provider contract. Temporary campaign roots are atomically
moved whole into retained mode-0700 quarantine before identity/type validation;
no leaf is recursively removed, so a foreign or late replacement is preserved
and rejected rather than deleted. These controls add no pass,
unsupported, or executed status to either pending campaign.

## Kernel, deployment mode, cgroup, and transport inventory

For each named environment, host-process and container-process cells are
distinct. Use Java 21, one named official agent, `amd64`, and one fixed stack.
A container-process result does not establish the equivalent host-process
cell. Sibling-container topology has only a container-process cell. Record the
exact TLS version for each forced transport result.

| Environment | Deployment mode | Cgroup topology | `getsockopt` | `unix` | `auto` (#23 only) |
| --- | --- | --- | --- | --- | --- |
| RHEL 9 / kernel 5.14 | host process | unified v2 | untested | untested | untested |
| RHEL 9 / kernel 5.14 | container process | unified v2 | untested | untested | untested |
| upstream 5.10 | host process | unified v2 | untested | untested | untested |
| upstream 5.10 | container process | unified v2 | untested | untested | untested |
| upstream 5.15 | host process | unified v2 | untested | untested | untested |
| upstream 5.15 | container process | unified v2 | untested | untested | untested |
| upstream 6.1 | host process | unified v2 | untested | untested | untested |
| upstream 6.1 | container process | unified v2 | untested | untested | untested |
| upstream 6.6 | host process | unified v2 | untested | untested | untested |
| upstream 6.6 | container process | unified v2 | untested | untested | untested |
| upstream 6.12 | host process | unified v2 | untested | untested | untested |
| upstream 6.12 | container process | unified v2 | untested | untested | untested |
| RHEL 8 / 4.18 backport | host process | host default | untested | untested | untested |
| RHEL 8 / 4.18 backport | container process | container default | untested | untested | untested |
| supported kernel | host process | hybrid v1/v2 | untested | untested | untested |
| supported kernel | container process | hybrid v1/v2 | untested | untested | untested |
| supported kernel | host process | nested/delegated v2 | untested | untested | untested |
| supported kernel | container process | nested/delegated v2 | untested | untested | untested |
| supported kernel | container process | sibling containers | untested | untested | untested |

The following additional host kernel is directly observed through
container-process deployments. It is not a substitute for any representative
kernel row above.

| Environment | Deployment mode | Agent | Cgroup topology | TLS | `getsockopt` | `unix` | `auto` | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Linux 7.0.0-1009-aws (distribution not recorded) | container process | OpenTelemetry 2.28.1 | unified v2 | 1.3 | pass | untested | untested | [getsockopt/TLS 1.3](evidence/otel-getsockopt-tls13-e8db066a/README.md) |
| Linux 7.0.0-1009-aws (distribution not recorded) | container process | OpenTelemetry 2.28.1 | unified v2 | 1.2 | pass | untested | untested | [getsockopt/TLS 1.2](evidence/otel-getsockopt-tls12-c7209e43/README.md) |
| Linux 7.0.0-1009-aws (distribution not recorded) | container process | Splunk 2.28.0 | unified v2 | 1.3 | pass | untested | untested | [getsockopt/TLS 1.3](evidence/splunk-getsockopt-tls13-47237792/README.md) |
| Linux 7.0.0-1009-aws (distribution not recorded) | container process | OpenTelemetry 2.28.1 | unified v2 | 1.2 | untested | pass | untested | [Unix/TLS 1.2](evidence/otel-unix-tls12-bd1c9327/README.md) |
| Linux 7.0.0-1009-aws (distribution not recorded) | container process | OpenTelemetry 2.28.1 | unified v2 | 1.3 | untested | pass | untested | [Unix/TLS 1.3](evidence/otel-unix-tls13-6c4a2505/README.md) |

RHEL 8 support may only be reported from direct execution on the documented
backport. If a required cgroup hook is absent, report forced `getsockopt` as
`unsupported` with feature-detection evidence and test the Unix fallback.

## Primary live-descriptor isolation gate

This is a primary-transport security gate, not a substitute for a forced
`getsockopt` compatibility result and not a Unix fallback cell. Before the
held request publishes its accepted-descriptor barrier, the Java process creates
a separate established unnegotiated loopback TCP socket and attempts the raw
retrieval on it. The runner then starts a root probe in the Java container's
PID 1 cgroup and attempts to duplicate the held descriptor with `pidfd_getfd`.
The direct probe observation is `unverified`; enforcement is established only
by the ordered isolated metric windows, held legitimate victim, and post-abuse
recovery.

| Gate | Required topology and capability | Status | Required retained result |
| --- | --- | --- | --- |
| same-JVM wrong live socket plus accepted-descriptor duplication against forced `getsockopt` | clean Java container; separate live unnegotiated TCP decoy before `ready`; root probe pre-exec cgroup exactly equals Java PID 1 cgroup; `pidfd_getfd` permitted | pass | [clean full forced-primary `all` result](evidence/otel-getsockopt-tls13-e8db066a/README.md), with [sanitized probe, ordered aggregate metric summary](evidence/otel-getsockopt-tls13-e8db066a/security-primary-live-fd.json), barrier records, victim graph, and recovery graph |

The [retained clean full result](evidence/otel-getsockopt-tls13-e8db066a/README.md)
meets this gate: its security status reports `status: passed`,
`wrong_live_socket: metrics_verified`, and
`duplicated_fd_wrong_process: metrics_verified`; the pre-release aggregate has
zero valid and exactly two unauthorized bridge retrievals, the victim retains
its exact parent, and recovery passes. The metric label does not identify the
two attackers individually; the retained ordering record binds the first to the
same-JVM decoy and the second to the duplicated-FD probe. The standalone
`--scenario security` command is useful for diagnostics but is non-acceptance evidence. A
`pidfd-duplicate-unavailable` result retains barrier records, probe log,
held-victim JSON and stderr, baseline metric evidence, and unsupported status.
It does not produce probe/after metric phases or the explicit post-abuse
recovery scenario, and exits nonzero after its trap restores the base stack; it
is `unsupported` for this gate, not a pass and not permission to label forced
Unix fallback as tested.

## Historical architecture evidence (not V3 status)

Each observed row uses one observed Linux kernel, unified cgroup v2, Java 21,
and the named agent. A row records one forced transport/TLS pair; it does not
establish the other transport or TLS version.

| Architecture | Agent | TLS | `getsockopt` | `unix` | Evidence |
| --- | --- | --- | --- | --- | --- |
| `amd64` | OpenTelemetry 2.28.1 | 1.3 | pass | untested | [getsockopt/TLS 1.3](evidence/otel-getsockopt-tls13-e8db066a/README.md) |
| `amd64` | OpenTelemetry 2.28.1 | 1.2 | pass | untested | [getsockopt/TLS 1.2](evidence/otel-getsockopt-tls12-c7209e43/README.md) |
| `amd64` | Splunk 2.28.0 | 1.3 | pass | untested | [getsockopt/TLS 1.3](evidence/splunk-getsockopt-tls13-47237792/README.md) |
| `amd64` | OpenTelemetry 2.28.1 | 1.2 | untested | pass | [Unix/TLS 1.2](evidence/otel-unix-tls12-bd1c9327/README.md) |
| `amd64` | OpenTelemetry 2.28.1 | 1.3 | untested | pass | [Unix/TLS 1.3](evidence/otel-unix-tls13-6c4a2505/README.md) |
| `arm64` | untested | untested | untested | untested | not recorded |

## Historical JVM and official-agent evidence (not V3 status)

Use one fixed supported kernel/architecture and record the TLS/transport pair
in the linked evidence. The Compose backend is pinned to Java 21; Java 8, 11,
and 17 cells require a directly recorded backend image override or dedicated
CI fixture. Do not mark them from unit tests alone.

The external extension has a deliberately narrow runtime gate:

| Contract field | Accepted value |
| --- | --- |
| JVM feature version | 8, 11, 17, or 21 |
| OpenTelemetry Java agent | 2.28.1 |
| Splunk Java agent | 2.28.0 embedding OpenTelemetry 2.28.1 |
| OpenTelemetry API | 1.62.0 |
| OpenTelemetry autoconfigure SPI | 1.62.0 |

The retained [official-agent runtime record](focused-validation/official-agent-runtime-9b66f39e/README.md)
comes from one exact successful Java CI execution at source revision
`9b66f39eb0e5897b6b27d999e461267dfa85fd70`. For every JVM entry, the workflow
downloaded both unmodified official agents, verified their checksums, loaded
the separately built external extension, and ran the same startup and server
parentage tests.

Stock-agent CI matrix revision: `official-agent-runtime-v1`.

| JVM | Agent | Extension startup | Jetty 11.0.26 | Netty 4.1.135.Final | Java 21 concurrency | JUnit cell |
| --- | --- | --- | --- | --- | --- | --- |
| 8 | OpenTelemetry 2.28.1 | pass | unsupported | pass | skipped: requires Java 21 | 8 tests, 4 skipped, 0 failures/errors |
| 8 | Splunk 2.28.0 | pass | unsupported | pass | skipped: requires Java 21 | same Java 8 artifact cell |
| 11 | OpenTelemetry 2.28.1 | pass | pass | pass | skipped: requires Java 21 | 8 tests, 2 skipped, 0 failures/errors |
| 11 | Splunk 2.28.0 | pass | pass | pass | skipped: requires Java 21 | same Java 11 artifact cell |
| 17 | OpenTelemetry 2.28.1 | pass | pass | pass | skipped: requires Java 21 | 8 tests, 2 skipped, 0 failures/errors |
| 17 | Splunk 2.28.0 | pass | pass | pass | skipped: requires Java 21 | same Java 17 artifact cell |
| 21 | OpenTelemetry 2.28.1 | pass | pass | pass | pass | 8 tests, 0 skipped, 0 failures/errors |
| 21 | Splunk 2.28.0 | pass | pass | pass | pass | same Java 21 artifact cell |

Java 8's Jetty result is `unsupported`, not a failure or an inferred pass:
Jetty 11 requires Java 11 or newer. The Java 21 concurrency skips on Java 8,
11, and 17 are likewise exact expected fixture limits. All four cells ran on
Linux GitHub runners reporting `X64`, with `x86_64` from uname. No `arm64`
result follows. Boundary tests in the same successful jobs require adjacent
agent, API, SPI, and JVM versions to be rejected with a deterministic reason.

This stock-agent matrix establishes issue #27's declared runtime contract. It
does not replace a privileged Compose application run or expand issue #23 or
issue #38. The privileged Compose matrix therefore remains:

| JVM | OpenTelemetry 2.28.1 | Splunk 2.28.0 | Evidence |
| --- | --- | --- | --- |
| 8 | untested | untested | configured official-agent smoke; no privileged run recorded |
| 11 | untested | untested | configured official-agent smoke; no privileged run recorded |
| 17 | untested | untested | configured official-agent smoke; no privileged run recorded |
| 21 | pass | pass | [OpenTelemetry getsockopt/TLS 1.3](evidence/otel-getsockopt-tls13-e8db066a/README.md), [getsockopt/TLS 1.2](evidence/otel-getsockopt-tls12-c7209e43/README.md), [Unix/TLS 1.2](evidence/otel-unix-tls12-bd1c9327/README.md), [Unix/TLS 1.3](evidence/otel-unix-tls13-6c4a2505/README.md), and [Splunk getsockopt/TLS 1.3](evidence/splunk-getsockopt-tls13-47237792/README.md) privileged runs |

Additional agent releases must be selected deliberately, pinned by checksum,
and added as new rows. “Latest” is not a matrix cell.

## Historical Apache, OpenSSL, and TLS evidence (not V3 status)

| Apache / OpenSSL | `getsockopt`/TLS 1.2 | Unix/TLS 1.2 | `getsockopt`/TLS 1.3 | Unix/TLS 1.3 | Backend HTTP |
| --- | --- | --- | --- | --- | --- |
| `httpd:2.4.68-alpine` image pinned in Compose | [pass graph](evidence/otel-getsockopt-tls12-c7209e43/scenario-basic.json), [runtime](evidence/otel-getsockopt-tls12-c7209e43/apache-openssl-runtime.txt) | [pass graph](evidence/otel-unix-tls12-bd1c9327/scenario-basic.json), [runtime](evidence/otel-unix-tls12-bd1c9327/apache-openssl-runtime.txt) | [OpenTelemetry pass graph](evidence/otel-getsockopt-tls13-e8db066a/scenario-basic.json), [Splunk pass graph](evidence/splunk-getsockopt-tls13-47237792/scenario-basic.json), [runtime](evidence/splunk-getsockopt-tls13-47237792/apache-openssl-runtime.txt) | [OpenTelemetry pass graph](evidence/otel-unix-tls13-6c4a2505/scenario-basic-security-recovery.json), [runtime](evidence/otel-unix-tls13-6c4a2505/apache-openssl-runtime.txt) | HTTP/1.1 only |

Every run must produce `apache-openssl-version.txt` proving that Apache loaded
`ssl_module`, that `mod_ssl.so` links to `libssl.so.3` and `libcrypto.so.3`,
and that Alpine attributes those exact runtime libraries to the expected
OpenSSL packages. A public retained subset may publish the allowlisted result
as `apache-openssl-runtime.txt`, but the TLS pass also requires a linked
scenario response naming the negotiated protocol and cipher. Missing or
malformed runtime evidence fails the run.

Backend HTTP/2 is currently **unsupported**, not silently untested. If support
is later proposed, it needs a separate topology and exact concurrency evidence
before changing that status.

## Cell procedure

```bash
CAMPAIGN_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/obi-compatibility.XXXXXX")"
chmod 700 "$CAMPAIGN_ROOT"
mkdir -m 700 "$CAMPAIGN_ROOT/cells"

./examples/apache-java-https/compatibility/create-source-authority.sh \
  --output "$CAMPAIGN_ROOT/source-authority.json"

./examples/apache-java-https/compatibility/run-cell.sh \
  --campaign compatibility \
  --cell k-upstream612-container-v2-getsockopt \
  --source-authority "$CAMPAIGN_ROOT/source-authority.json" \
  --output "$CAMPAIGN_ROOT/cells/k-upstream612-container-v2-getsockopt"

# Run and retain one cell directory for every frozen ID before collecting.
./examples/apache-java-https/compatibility/collect.sh \
  --campaign compatibility \
  --input-root "$CAMPAIGN_ROOT/cells" \
  --source-authority "$CAMPAIGN_ROOT/source-authority.json" \
  --output "$CAMPAIGN_ROOT/public-aggregate-v3"
```

The authority generator and both output boundaries reject paths inside the
checkout. The generator requires a clean source tree and freezes the commit,
Git tree, source-tree manifest, tracked patch, and patch identity before any
cell runs. Preserve the mode-0700 campaign root; only the aggregate subdirectory
is public-safe.

The plan chooses a real adapter for every cell. The local Java 21 container
adapter invokes the production harness with `--scenario all --repeat 1
--seed 1`; it is not a targeted smoke alias. Other cells use checksum-pinned
preprovisioned host, JVM, or lifecycle drivers with an exact argv contract.
If their platform or driver is absent, the cell is retained as infrastructure
`untested`, never silently skipped. See the campaign README for the driver
contract, kernel/topology attestations, status rules, private/public boundary,
and focused mutation tests.

Transport attempt order is exact rather than set-like. A forced result attempts
only its requested transport. An `auto` pass selecting `getsockopt` records only
that primary attempt; an `auto` pass selecting Unix records `getsockopt` then
`unix`; and authoritative `auto` unsupported records both attempts and no
selection. Resource-gate baselines and finals are nonnegative snapshots; only
their recomputed delta may be signed.

A pass requires zero wrong parents. Under live map pressure, contract 2 and
`pressure-traffic-barrier-v2` require one deterministic W3C parent, at least one
explicit Java root, `H+R+W=N`, and zero wrong or unresolved parents. The
transport-aware bridge and Java layers must satisfy the corresponding `V/F/M`
retrieval, failure, and W3C-masked-candidate conservation while retaining the
actual reason counts. The live non-evicting `HASH` must also start empty, fill
to all 10,000 entries, reject one extra key with kernel `E2BIG`, keep that key
absent, and retain the same ordered-content digest after traffic. Other tests
may report a miss only when their expected outcome permits it. These source
requirements do not promote any pending matrix cell without retained evidence.

The narrowest directly demonstrated configurations are the exact Linux
7.0.0-1009-aws, unified-cgroup-v2, `amd64`, Temurin 21, Apache 2.4.68, and
OpenSSL 3.5.7 cells linked above: OpenTelemetry 2.28.1 on forced
`getsockopt`/TLS 1.3, `getsockopt`/TLS 1.2, and forced `unix`/TLS 1.2 and
TLS 1.3, and Splunk 2.28.0 on forced `getsockopt`/TLS 1.3. The distribution was not
recorded independently, and no broader compatibility claim follows from those
results.
