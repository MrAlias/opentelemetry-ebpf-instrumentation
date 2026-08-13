# Security and abuse-case matrix

Status: **partial — retained named primary/Unix isolation controls and public
bundle sanitization pass; explicit stale-generation, genuine TID/PID reuse,
primary wrong-current-TID/logical-execution, runtime diagnostic-side-channel,
and broader environment controls remain untested**

The PoC crosses a kernel/JVM trust boundary and exposes a local Unix fallback.
Passing the happy path is insufficient. Every negative cell must preserve
application availability, avoid consuming another request's context, finish
within a bounded deadline, and produce a low-cardinality reason code without
logging trace IDs, headers, bodies, credentials, PID/TID labels, or socket
payloads. Primary and Unix `pass` entries below refer only to the exact
retained [OpenTelemetry/`getsockopt`/TLS 1.3](evidence/otel-getsockopt-tls13-e8db066a/README.md),
[OpenTelemetry/`getsockopt`/TLS 1.2](evidence/otel-getsockopt-tls12-c7209e43/README.md),
and [OpenTelemetry/Unix/TLS 1.2](evidence/otel-unix-tls12-bd1c9327/README.md),
and [OpenTelemetry/Unix/TLS 1.3](evidence/otel-unix-tls13-6c4a2505/README.md)
runs. The current primary wrong-live-socket result is the exact
[OpenTelemetry/`getsockopt`/TLS 1.3 bundle](evidence/otel-getsockopt-tls13-e8db066a/README.md).

A primary probe's `native-unsupported` result is only an `unverified`
observation. An unauthorized BPF call deliberately falls through to the native
`getsockopt` result after recording its metric, and an unattached system returns
the same result. A primary matrix pass therefore requires the runner's cgroup
topology, per-topology unauthorized-metric deltas, legitimate-victim, and
recovery gates; the raw probe cannot certify enforcement on its own.

A prior focused primary run at `8f0aa1f6` remains historical targeted evidence.
The current full acceptance bundle independently reaches the cgroup-topology,
per-topology unauthorized-metric, exact-parent victim, and recovery gates.

The retained [primary wrong-live-socket acceptance bundle](evidence/otel-getsockopt-tls13-e8db066a/README.md)
first creates a separate, established, unnegotiated loopback TCP socket in the
Java process, then holds an actual accepted Java descriptor and executes a root
probe in the Java container's PID 1 cgroup. The ordered pre-release window
records zero valid takes, exactly two aggregate unauthorized takes, one
unauthorized negotiate, an exact-parent victim, and recovery. The reason-coded
metric label does not identify either attacker individually; the runner orders
the same-JVM socket before `ready` and the duplicated-FD probe after `ready`
but before release. `pidfd-duplicate-unavailable` remains an `unsupported`
capability result, not an authorization pass and not a reason to fall back
silently to Unix.

| Abuse or fault | Required result | Primary `getsockopt` | Unix | Evidence or remaining work |
| --- | --- | --- | --- | --- |
| unrelated process in same cgroup calls take | denied; legitimate Java take still succeeds | pass | pass | [current primary same-cgroup summary](evidence/otel-getsockopt-tls13-e8db066a/security-primary-probes.json) and [retained Unix same-cgroup topology, metrics, victim, and recovery](evidence/otel-unix-tls13-6c4a2505/README.md#retained-proof) |
| sibling container/PID namespace calls take | denied by current identity/peer credentials | pass | pass | [current primary sibling summary](evidence/otel-getsockopt-tls13-e8db066a/security-primary-probes.json) and [retained Unix sibling topology, metrics, victim, and recovery](evidence/otel-unix-tls13-6c4a2505/README.md#retained-proof) |
| forged caller PID/TID in Unix request | ignored; kernel peer identity is authoritative | not applicable | pass | [forged-peer probe](evidence/otel-unix-tls12-bd1c9327/security-unix-probes.json) |
| wrong current TID/logical-execution identity on primary retrieval | rejected without consuming the legitimate value | untested | not applicable | wrong-process and wrong-socket controls do not establish a wrong-current-TID primary call |
| repeated unauthorized take attempts | bounded; context remains available | pass | pass | [primary bounded probe summaries and exact-parent victim](evidence/otel-getsockopt-tls13-e8db066a/README.md#retained-proof) and [Unix bounded probes and recovery](evidence/otel-unix-tls12-bd1c9327/security-unix-probes.json) |
| root process in Java PID 1 cgroup duplicates a live accepted descriptor | raw probe is insufficient; isolated unauthorized metrics show zero valid retrievals, held victim keeps exact parent, recovery passes | pass | not applicable | [clean full primary acceptance bundle](evidence/otel-getsockopt-tls13-e8db066a/README.md) with [sanitized probe, topology, and metric summary](evidence/otel-getsockopt-tls13-e8db066a/security-primary-live-fd.json), barrier records, victim graph, and recovery graph; standalone `security` remains diagnostic only |
| wrong application-socket identity (primary only) | rejected without consuming another request's context | pass for a separate live unnegotiated TCP socket in the same JVM | not applicable | [clean full primary wrong-live-socket result](evidence/otel-getsockopt-tls13-e8db066a/README.md) with the [ordered aggregate metric summary](evidence/otel-getsockopt-tls13-e8db066a/security-primary-live-fd.json), held victim, and recovery; Unix opens a fresh broker socket and authorizes peer process, TID, and capability rather than accepting an application descriptor |
| fd reuse | closed/reopened fixed-port traffic; reused Jetty fd across distinct stable Jetty connection IDs; distinct exact parents; zero wrong parents | pass | pass | [primary](evidence/otel-getsockopt-tls13-e8db066a/scenario-fd-port-reuse.json) and [Unix](evidence/otel-unix-tls12-bd1c9327/scenario-fd-port-reuse.json) reuse graphs |
| unrelated socket option/level | original kernel behavior preserved | pass | not applicable | [primary probe cases](evidence/otel-getsockopt-tls13-e8db066a/security-primary-probes.json) |
| Unix socket path replacement and old client FD | replacement fails closed; the old client closes without consuming context; the replacement remains unchanged | not applicable | pass | [endpoint-replacement and old-client-FD probes](evidence/otel-unix-tls12-bd1c9327/security-unix-probes.json) |
| permissive Unix directory mode | rejected or prominently diagnosed | not applicable | pass | [permission refusal and recovery](evidence/otel-unix-tls12-bd1c9327/security-unix-probes.json) |
| malformed/truncated versioned request | handled without crash or unintended parent | not applicable | pass | [Unix fault graphs and classifications](evidence/otel-unix-tls12-bd1c9327/README.md#retained-proof); the primary syscall has no request frame |
| oversized/repeated/flooded Unix request | bounded admission/deadline and recovery; test-payload canary non-disclosure | not applicable | pass | [bounded admission probes](evidence/otel-unix-tls12-bd1c9327/security-unix-probes.json) |
| malformed/zero trace or span ID | discarded; Java request remains healthy | pass | pass | [retained primary zero-ID controls and recovery](evidence/otel-getsockopt-tls13-e8db066a/README.md#retained-proof) and [Unix zero-ID fault graphs](evidence/otel-unix-tls12-bd1c9327/README.md#retained-proof) |
| stale entry past TTL | miss; never a parent | pass | pass | [retained primary `1ns` TTL, W3C precedence, and recovery](evidence/otel-getsockopt-tls13-e8db066a/scenario-primary-w3c-stale.json) and [retained Unix `1ns` stale rejection, W3C precedence, and recovery](evidence/otel-unix-tls13-6c4a2505/unix-w3c-stale.json) |
| explicit stale-generation mismatch | miss; never a parent; valid W3C still wins | untested | untested | restart and TTL-stale controls do not inject a mismatched generation |
| live handoff-map capacity rejection | the non-evicting map rejects excess admission without evicting any admitted ticket; exact hits, explicit roots, and actual upstream/retrieval reason counts reconcile by transport; zero wrong or unresolved parents; exact-key cleanup and steady-baseline recovery | untested | untested | the retained summaries cover the superseded LRU-eviction design; a fresh HASH-capacity run is required |
| OBI absent at JVM start, followed by late attach | Java root span and healthy response while absent; exact-parent recovery after attach | pass | pass | [primary](evidence/otel-getsockopt-tls13-e8db066a/scenario-fail-open-obi-absent.json) and [Unix](evidence/otel-unix-tls12-bd1c9327/scenario-fail-open-obi-absent.json) bounded startup-absence graphs plus their late-attach recovery scenarios |
| OBI permanently absent for the JVM lifetime | ordinary Java-agent behavior remains healthy for the full process lifetime | untested | untested | retained late-attach sequences do not establish permanent process-lifetime absence |
| OBI stop/restart during traffic | no wrong parent while absent; recovery only if claimed | pass | pass | [primary](evidence/otel-getsockopt-tls13-e8db066a/scenario-restart-fault.json) and [Unix](evidence/otel-unix-tls12-bd1c9327/scenario-restart-fault.json) restart traffic; this row does not claim a primary descriptor survived into a new OBI generation |
| helper absent/disabled | ordinary official-agent behavior | pass | pass | [Unix helper failure](evidence/otel-unix-tls12-bd1c9327/scenario-helper-attach-failure-helper-unavailable.json) and [bridge-disabled](evidence/otel-unix-tls12-bd1c9327/scenario-disabled.json) graphs |
| extension absent/disabled | ordinary official-agent behavior | pass | pass | [Unix extension absent](evidence/otel-unix-tls12-bd1c9327/scenario-w3c-only-extension-absent.json) and [disabled](evidence/otel-unix-tls12-bd1c9327/scenario-w3c-only-extension-disabled.json) graphs |
| both transports unavailable under `auto` | bounded fail-open, no retry storm | untested | untested | the retained OBI-absent controls use a forced transport; no retained `auto` run attempts primary and fallback unavailability in one application control |
| malformed ABI length | rejected with `malformed` reason | pass | pass | [retained primary declared-size fault](evidence/otel-getsockopt-tls13-e8db066a/scenario-primary-w3c-fault-bad-size.json) and [Unix bad-size fault graph](evidence/otel-unix-tls12-bd1c9327/README.md#retained-proof) |
| truncated Unix reply | fails open with `transport_error` reason | not applicable | pass | [Unix truncation fault graph](evidence/otel-unix-tls12-bd1c9327/README.md#retained-proof) |
| ABI version mismatch | rejected with `version_mismatch` reason | pass | pass | [retained primary response control](evidence/otel-getsockopt-tls13-e8db066a/scenario-primary-w3c-fault-version-mismatch.json) and [Unix version fault graph](evidence/otel-unix-tls12-bd1c9327/README.md#retained-proof) |
| valid W3C plus conflicting OBI context | W3C exact IDs win; OBI entry discarded | pass | pass | [primary](evidence/otel-getsockopt-tls13-e8db066a/scenario-w3c.json) and [Unix](evidence/otel-unix-tls12-bd1c9327/scenario-w3c.json) conflict graphs |
| valid W3C with no OBI state | exact W3C parent; bounded no-state lookup; no Apache span | pass | pass | [primary](evidence/otel-getsockopt-tls13-e8db066a/scenario-w3c-only-obi-absent.json) and [Unix](evidence/otel-unix-tls12-bd1c9327/scenario-w3c-only-obi-absent.json) W3C-only graphs |
| repeated async redispatch | one Java server span; one request-scoped parent | pass | pass | [primary](evidence/otel-getsockopt-tls13-e8db066a/scenario-dispatch.json) and [Unix](evidence/otel-unix-tls12-bd1c9327/scenario-dispatch.json) redispatch graphs |
| genuine TID/PID reuse | no prior execution's value becomes a parent | untested | untested | descriptor/port reuse and forged-identity controls do not establish kernel TID/PID reuse |
| runtime diagnostic endpoint/log side channel | no raw context/request data; every negative remains diagnosable from bounded counters/logs | untested | untested | public-bundle sanitization proves only the publication boundary because raw runtime scrapes and operational logs are deliberately omitted |
| published evidence-bundle disclosure scan | no checkout paths, raw context payloads, credentials, or private operational identifiers | pass | pass | [primary sanitization](evidence/otel-getsockopt-tls13-e8db066a/SANITIZATION.md) and [Unix sanitization](evidence/otel-unix-tls12-bd1c9327/SANITIZATION.md) |

The Unix transport never receives or uses the application socket descriptor:
the [provider passes `-1` outside the primary path](../../pkg/internal/java/agent/src/main/java/io/opentelemetry/obi/java/bridge/NativeRemoteParentProvider.java),
[JNI opens a fresh Unix broker socket](../../pkg/internal/java/agent/src/main/c/io_opentelemetry_obi_java_jni.c),
and OBI authorizes the kernel-derived peer process, logical TID, and process
capability. A numeric application-socket mismatch is therefore not an
applicable Unix case. Its meaningful isolation analogues are the retained
same-cgroup, sibling, forged PID/TID, repeated-call, peer-credential,
endpoint-replacement, and stale-endpoint controls. The
[native regression test](../../pkg/internal/java/agent/src/test/c/remote_parent_jni_test.c)
also proves that an unrelated duplicated descriptor is ignored by the Unix
transport and remains untouched.

## Test topology

- Run an attacker process with `docker exec` in the Java container to share its
  cgroup but not its JVM helper state.
- For the primary live-descriptor control, hold a real victim request at the
  Java accepted-descriptor barrier. Before it publishes `ready`, the preload
  creates a separate established loopback TCP socket in that same Java process
  and directly calls the resolved native retrieval; it must be denied. The
  runner then executes the root duplicated-FD probe in that container after
  `ready` and before release. It clears fault-injection preload state and
  verifies before exec that its cgroup equals Java PID 1's cgroup. The proof
  requires permitted `pidfd_getfd`, an `unverified` raw observation, exactly
  two ordered aggregate unauthorized takes with zero valid retrievals, the
  victim's exact parent, and a normal-stack recovery. A raw native result never
  certifies primary enforcement.
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
- Fill the discovered live non-evicting handoff-claim `HASH` map until its first
  bounded capacity rejection, after retaining its exact map and JVM cleanup
  identity and arming cleanup. Derive synthetic keys and tagged `OPEN` values
  from the one unambiguous live JVM PID/namespace/incarnation, scan every
  successfully admitted synthetic key to prove that none was evicted, and
  monitor exact-map occupancy above its
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
- The pressure helper is an acceptance-only privileged container. Preparation
  point-lookups the controlled JVM's exact PID and PID-namespace identity, then
  requires one live program-related process-map and handoff-claim-map pair.
  Foreign and orphan map sets are ignored; multiple valid pairs fail closed.
  The harness binds that result to a stable Docker container identity and uses
  only the returned claim-map ID for host-global metric lookup. The helper
  bounds accepted capacity, uses fresh monotonic timestamps, and never emits
  the JVM incarnation capability. Cleanup instead scans only the captured PID,
  namespace, and random per-run token range, validates each matching key's
  incarnation and open ticket, deletes the exact full keys, and verifies that
  no key in that bounded range remains after the JVM identity entry disappears.
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
