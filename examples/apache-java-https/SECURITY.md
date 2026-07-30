# Security and abuse-case matrix

Status: **partial — retained Unix and non-abuse primary scenarios passed;
clean focused primary attacker controls passed but are recorded separately as
non-acceptance validation; remaining primary and Unix cases and matrix cells
are untested**

The PoC crosses a kernel/JVM trust boundary and exposes a local Unix fallback.
Passing the happy path is insufficient. Every negative cell must preserve
application availability, avoid consuming another request's context, finish
within a bounded deadline, and produce a low-cardinality reason code without
logging trace IDs, headers, bodies, credentials, PID/TID labels, or socket
payloads. Primary and Unix `pass` entries below refer only to the exact
retained [OpenTelemetry/`getsockopt`/TLS 1.3](evidence/otel-getsockopt-tls13-c9d14356/README.md),
[OpenTelemetry/`getsockopt`/TLS 1.2](evidence/otel-getsockopt-tls12-c7209e43/README.md),
and [OpenTelemetry/Unix/TLS 1.2](evidence/otel-unix-tls12-bd1c9327/README.md) runs.

`untested (focused verification only)` denotes a clean targeted validation
record with `acceptance_evidence=false`. It is not an acceptance-matrix `pass`
and cannot close issue #40. The current primary record is
[focused validation](focused-validation/primary-getsockopt-8f0aa1f6/README.md).

A primary probe's `native-unsupported` result is only an `unverified`
observation. An unauthorized BPF call deliberately falls through to the native
`getsockopt` result after recording its metric, and an unattached system returns
the same result. A primary matrix pass therefore requires the runner's cgroup
topology, per-topology unauthorized-metric deltas, legitimate-victim, and
recovery gates; the raw probe cannot certify enforcement on its own.

A clean focused primary run at `8f0aa1f6` reached the current cgroup-topology,
per-topology unauthorized-metric, legitimate-victim, and recovery gates. Its
raw probes remain `native-unsupported` and `unverified`; the runner verifies
attribution through isolated unauthorized metric deltas. Because the run is
targeted and has `acceptance_evidence=false`, it is not a primary acceptance
matrix pass. A sanitized full acceptance run is still required before restoring
a primary attacker cell to `pass`.

Current source also contains a separate primary live-descriptor control. It
holds an actual accepted Java descriptor, executes a root probe in the Java
container's PID 1 cgroup, and attempts `pidfd_getfd` before the legitimate
request is released. It has no retained runtime artifact, so it is `untested`.
`pidfd-duplicate-unavailable` is an `unsupported` capability result, not an
authorization pass and not a reason to fall back silently to Unix.

| Abuse or fault | Required result | Primary `getsockopt` | Unix | Evidence or remaining work |
| --- | --- | --- | --- | --- |
| unrelated process in same cgroup calls take | denied; legitimate Java take still succeeds | untested (focused verification only) | untested | [current same-cgroup metric window, victim, and recovery](focused-validation/primary-getsockopt-8f0aa1f6/security-primary-probes.json) |
| sibling container/PID namespace calls take | denied by current identity/peer credentials | untested (focused verification only) | untested | [current sibling metric window, victim, and recovery](focused-validation/primary-getsockopt-8f0aa1f6/security-primary-probes.json) |
| forged caller PID/TID in Unix request | ignored; kernel peer identity is authoritative | not applicable | pass | [forged-peer probe](evidence/otel-unix-tls12-bd1c9327/security-unix-probes.json) |
| repeated unauthorized take attempts | bounded; context remains available | untested (focused verification only) | pass | [primary bounded probe windows](focused-validation/primary-getsockopt-8f0aa1f6/security-primary-probes.json) and [Unix bounded probes and recovery](evidence/otel-unix-tls12-bd1c9327/security-unix-probes.json) |
| root process in Java PID 1 cgroup duplicates a live accepted descriptor | raw probe is insufficient; isolated unauthorized metrics show zero valid retrievals, held victim keeps exact parent, recovery passes | untested | not applicable | a clean full forced-primary `all` run must retain barrier arm/release/consumed records, probe log, victim graph, phase metric deltas, and `scenario-primary-live-fd-security-status.json`; standalone `security` is diagnostic only, while a pidfd-unavailable result retains barrier/probe/victim/baseline/status evidence but not probe/after phases or the explicit recovery scenario, then exits nonzero after base-stack restoration |
| wrong socket identity | rejected without consuming another request's context | untested | untested | retain a targeted wrong-socket result |
| fd reuse | closed/reopened fixed-port traffic; reused Jetty fd across distinct stable Jetty connection IDs; distinct exact parents; zero wrong parents | pass | pass | [primary](evidence/otel-getsockopt-tls13-c9d14356/scenario-fd-port-reuse.json) and [Unix](evidence/otel-unix-tls12-bd1c9327/scenario-fd-port-reuse.json) reuse graphs |
| unrelated socket option/level | original kernel behavior preserved | pass | not applicable | [primary probe cases](evidence/otel-getsockopt-tls13-c9d14356/security-primary-probes.json) |
| Unix socket path replacement | startup fails closed or uses protected endpoint | not applicable | pass | [endpoint-replacement probes](evidence/otel-unix-tls12-bd1c9327/security-unix-probes.json) |
| permissive Unix directory mode | rejected or prominently diagnosed | not applicable | pass | [permission refusal and recovery](evidence/otel-unix-tls12-bd1c9327/security-unix-probes.json) |
| malformed/truncated versioned request | handled without crash or unintended parent | untested | pass | [Unix fault graphs and classifications](evidence/otel-unix-tls12-bd1c9327/README.md#retained-proof) |
| oversized/repeated/flooded Unix request | bounded admission/deadline and recovery; test-payload canary non-disclosure | not applicable | pass | [bounded admission probes](evidence/otel-unix-tls12-bd1c9327/security-unix-probes.json) |
| malformed/zero trace or span ID | discarded; Java request remains healthy | untested (focused verification only) | pass | [primary zero-ID controls](focused-validation/primary-getsockopt-8f0aa1f6/primary-w3c-fail-open.json) and [Unix zero-ID fault graphs](evidence/otel-unix-tls12-bd1c9327/README.md#retained-proof) |
| stale entry past TTL | miss; never a parent | untested (focused verification only) | untested | [primary `1ns` TTL, W3C precedence, and recovery](focused-validation/primary-getsockopt-8f0aa1f6/primary-w3c-fail-open.json); retain an actual Unix stale-state result |
| live handoff-map pressure/eviction | order-independent eviction; exact hits, explicit roots, and actual upstream/retrieval reason counts reconciled by transport; zero wrong or unresolved parents; exact-key cleanup and steady-baseline recovery | pass | pass | [primary summary](evidence/otel-getsockopt-tls13-c9d14356/map-pressure-summary.json) and [Unix summary](evidence/otel-unix-tls12-bd1c9327/map-pressure-summary.json) |
| OBI absent or delayed | Java root span and healthy response | pass | pass | [primary](evidence/otel-getsockopt-tls13-c9d14356/scenario-fail-open-obi-absent.json) and [Unix](evidence/otel-unix-tls12-bd1c9327/scenario-fail-open-obi-absent.json) absence graphs |
| OBI restart with old endpoint/fd | no stale parent; recovery only if claimed | pass | pass | [primary](evidence/otel-getsockopt-tls13-c9d14356/scenario-restart-fault.json) and [Unix](evidence/otel-unix-tls12-bd1c9327/scenario-restart-fault.json) restart traffic |
| helper absent/disabled | ordinary official-agent behavior | pass | pass | [Unix helper failure](evidence/otel-unix-tls12-bd1c9327/scenario-helper-attach-failure-helper-unavailable.json) and [bridge-disabled](evidence/otel-unix-tls12-bd1c9327/scenario-disabled.json) graphs |
| extension absent/disabled | ordinary official-agent behavior | pass | pass | [Unix extension absent](evidence/otel-unix-tls12-bd1c9327/scenario-w3c-only-extension-absent.json) and [disabled](evidence/otel-unix-tls12-bd1c9327/scenario-w3c-only-extension-disabled.json) graphs |
| both transports unavailable | bounded fail-open, no retry storm | pass | untested | [OBI-absent root](evidence/otel-getsockopt-tls13-c9d14356/scenario-fail-open-obi-absent.json) and [W3C-only](evidence/otel-getsockopt-tls13-c9d14356/scenario-w3c-only-obi-absent.json) |
| malformed ABI length | rejected with `malformed` reason | untested | pass | [bad-size fault graph](evidence/otel-unix-tls12-bd1c9327/README.md#retained-proof) |
| truncated Unix reply | fails open with `transport_error` reason | untested | pass | [truncation fault graph](evidence/otel-unix-tls12-bd1c9327/README.md#retained-proof) |
| ABI version mismatch | rejected with `version_mismatch` reason | untested (focused verification only) | pass | [primary response control](focused-validation/primary-getsockopt-8f0aa1f6/primary-w3c-fail-open.json) and [Unix version fault graph](evidence/otel-unix-tls12-bd1c9327/README.md#retained-proof) |
| valid W3C plus conflicting OBI context | W3C exact IDs win; OBI entry discarded | pass | pass | [primary](evidence/otel-getsockopt-tls13-c9d14356/scenario-w3c.json) and [Unix](evidence/otel-unix-tls12-bd1c9327/scenario-w3c.json) conflict graphs |
| valid W3C with no OBI state | exact W3C parent; bounded no-state lookup; no Apache span | pass | pass | [primary](evidence/otel-getsockopt-tls13-c9d14356/scenario-w3c-only-obi-absent.json) and [Unix](evidence/otel-unix-tls12-bd1c9327/scenario-w3c-only-obi-absent.json) W3C-only graphs |
| repeated async redispatch | one Java server span; one request-scoped parent | pass | pass | [primary](evidence/otel-getsockopt-tls13-c9d14356/scenario-dispatch.json) and [Unix](evidence/otel-unix-tls12-bd1c9327/scenario-dispatch.json) redispatch graphs |
| diagnostic endpoint/log scrape | no raw context/request data or scenario-counter contamination | pass | pass | retained fixed-schema phase deltas and [Unix public-bundle sanitization](evidence/otel-unix-tls12-bd1c9327/SANITIZATION.md) |

## Test topology

- Run an attacker process with `docker exec` in the Java container to share its
  cgroup but not its JVM helper state.
- For the primary live-descriptor control, hold a real victim request at the
  Java accepted-descriptor barrier, then execute the root probe in that same
  container. It clears fault-injection preload state and verifies before exec
  that its cgroup equals Java PID 1's cgroup. The proof requires permitted
  `pidfd_getfd`, an `unverified` raw observation, isolated unauthorized
  negotiate/take metric deltas with zero valid retrievals, the victim's exact
  parent, and a normal-stack recovery. A raw native result never certifies
  primary enforcement.
- Run a sibling container with the Unix directory mounted to test filesystem
  permissions and peer credentials.
- The Unix sibling fixture is deliberately `65534:65534` with no network,
  capabilities, writable root filesystem, or writable socket mount. The socket
  directory and socket use group `65534` solely so this non-root peer reaches
  OBI's credential and process-capability checks instead of failing at the
  filesystem boundary. Group membership is therefore an availability boundary,
  not authorization to retrieve a parent. Within the Unix control, the separate
  root `security-probe` fixture is restricted to endpoint-path replacement,
  which necessarily mutates the socket path; the primary-transport control
  reuses its image for native protocol checks. Source controls do not change an
  `untested` matrix cell until their retained runtime artifact is reviewed.
- Send fixed malformed, truncated, oversized, repeated, and wrong-version
  messages; never fuzz without a duration and size bound.
- Concurrent attacker probes use separate, repeat-aware deadlines derived from
  the runner's bounded scenario, publication, identity, and release work, with
  a hard one-hour ceiling. While they are active, phase capture is limited to
  the metrics needed for attribution. The runner signals and reaps both probes
  immediately after legitimate traffic settles. Repeat and readiness settings
  whose derived deadline exceeds the ceiling are rejected before startup.
- Keep a legitimate marked request pending while unauthorized consumers race,
  then require the legitimate exact parent assertion to pass.
- Fill the discovered live handoff-claim LRU to its reported capacity plus one,
  after retaining its exact map and JVM cleanup identity and arming cleanup.
  Derive synthetic keys and fresh values from the one unambiguous live JVM
  PID/namespace/incarnation, scan every synthetic key to prove at least one
  order-independent eviction, and monitor exact-map occupancy above its
  pre-fill baseline once per second through the exact aggregate TCP-inject
  outcome total, retaining the terminal metric sample independently of later
  trace polling. Remove only those deterministic keys, verify every one is
  absent, then retain two consecutive at-or-below-baseline samples within a
  bounded TTL-aware recovery deadline. Classify every nonzero Java parent as an
  exact hit and only a true Java root as an explicit root, then reconcile those
  outcomes with the actual bridge upstream/retrieval reasons and Java counts
  using transport-aware conservation. Promote canonical cleanup evidence only
  after that recovery gate passes. Evidence never records the incarnation
  capability.
- Restart only the `obi` service and preserve old descriptors long enough to
  test stale endpoint behavior.
- Run `fd-port-reuse` to reuse one client ephemeral port across reconnects,
  force every Apache-to-Jetty connection closed, and require a Jetty descriptor
  to recur across distinct stable Jetty connection IDs without sharing a Java
  parent. Remote ports are retained only as diagnostics.

The result bundle must include application response status/body equivalence,
elapsed time, reason-coded counter deltas, bounded logs, and the sanitized trace
graph. Mark a case unsupported if the environment cannot create its namespace
or credential topology; do not mark it pass.

## Local demo hardening

- OTLP and application listeners bind only to loopback.
- Apache denies proxied access to both Java diagnostic endpoints. The harness
  reads them directly over the loopback-only backend listener, and the
  transport endpoint returns either the fixed seven-field configuration
  snapshot or `unavailable` when the diagnostics facade cannot be loaded.
- The backend certificate is verified by a generated local CA and hostname.
- Runtime private keys and the Unix socket live under ignored `.runtime/`
  paths; every Docker build context excludes the certificate directory, and
  each service mounts only its required certificate file.
- Only the random test marker header is allowlisted for telemetry correlation.
- The OTLP receiver enforces a 16 MiB body limit, a maximum of 100,000 configured
  retained spans, a maximum configured retained string of 64 KiB, a maximum
  configured aggregate retained payload of 256 MiB, strict endpoints, short
  server timeouts, and sanitized attributes. The demo uses smaller 10,000-span,
  4 KiB-string, and 64 MiB aggregate limits. Count, value, and aggregate drops
  are reason-coded in assertion snapshots and fail the scenario.
- The pressure helper is an acceptance-only privileged container. It requires
  one exact live claim map and one unambiguous nonzero JVM-incarnation entry,
  matched by kernel-visible name, type, key/value shape, and optional map ID.
  It refuses ambiguous matches, bounds accepted capacity, uses fresh monotonic
  timestamps, and never emits the incarnation capability. Cleanup uses the
  captured non-secret PID, namespace, and random per-run token base to
  reconstruct only its synthetic keys, verifies each key is absent afterward,
  and remains possible after the JVM identity entry disappears.
- The Unix fault responder is an acceptance-only, single-request-at-a-time
  service with named stale/malformed, timeout, disconnect, overload,
  truncation, envelope, version, and zero-ID modes. It uses strict request ABI
  parsing, short I/O deadlines, a fixed counter, and no request identity
  logging.
- The primary response-fault shim is demo-only and runs only in the explicit
  `primary-w3c-fault` stack. It is enabled by a fixed preload library and a
  root-owned `0700` tmpfs directory; a root-owned `0600`, single-link regular
  control file is atomically armed, required to be empty after one use, and
  removed before normal-stack recovery. It is not a production transport or
  fault-injection interface.
- Java diagnostics are requested directly from the verified Jetty TLS endpoint
  before and after each ordinary non-stale bridge scenario. The runner stores
  snapshots separately from OBI metrics and accounts for exactly one
  post-snapshot `missing` self-lookup. The forced `1ns` stale controls instead
  use in-band snapshots on the existing bridge-boundary health request and the
  marked workload response, so their exact `stale` delta has no standalone
  diagnostics probe. Another result of the applicable status fails unless
  aggregate pressure trace evidence reports a corresponding explicit root and
  the bridge reason counts conserve the same request total. Diagnostics do not
  carry request markers, so this is an aggregate reconciliation. The serial fault-injection suite
  instead opts in to the same fixed, sanitized snapshot on the existing
  pre-control health response and each terminal scenario response after Java
  extraction. Exact chained deltas attribute the normalized Java fault status
  without issuing another request that could consume a synthetic response.
- Compose project names are restricted to the reserved demo namespace. Every
  container, volume, and network has an ownership sentinel, and the runner
  verifies all project-labeled resources before startup or destructive cleanup.

## Residual risk

A process that fully compromises the instrumented JVM can act with that JVM's
identity and observe or misuse contexts available to it. The bridge is not a
security boundary inside a compromised process. Production deployment also
needs deliberate Unix directory ownership, container namespace policy,
least-privilege OBI capabilities, and log/metric access controls; the
privileged Compose fixture is not production guidance.

The Unix fallback bounds total live requests, pre-authentication time, and
requests per peer PID. A coordinated set of processes with legitimate socket
connect permission can nevertheless fill the global admission pool and cause
temporary `overload` responses. Such saturation cannot consume a staged parent,
but fallback availability for other peers is not guaranteed; the configured
socket group must therefore remain an availability trust boundary.
