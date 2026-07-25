# Security and abuse-case matrix

Status: **partial — retained primary scenarios passed; remaining primary and
Unix cases untested**

The PoC crosses a kernel/JVM trust boundary and exposes a local Unix fallback.
Passing the happy path is insufficient. Every negative cell must preserve
application availability, avoid consuming another request's context, finish
within a bounded deadline, and produce a low-cardinality reason code without
logging trace IDs, headers, bodies, credentials, PID/TID labels, or socket
payloads. Primary `pass` entries below refer only to the exact retained
[OpenTelemetry/`getsockopt`/TLS 1.3 run](evidence/otel-getsockopt-tls13-7482d908/README.md).

| Abuse or fault | Required result | Primary `getsockopt` | Unix | Evidence or remaining work |
| --- | --- | --- | --- | --- |
| unrelated process in same cgroup calls take | denied; legitimate Java take still succeeds | pass | untested | [sanitized probe topology and result](evidence/otel-getsockopt-tls13-7482d908/security-primary-probes.json) and [victim](evidence/otel-getsockopt-tls13-7482d908/scenario-concurrency-security-primary-victim.json) |
| sibling container/PID namespace calls take | denied by current identity/peer credentials | pass | untested | [sanitized sibling topology and result](evidence/otel-getsockopt-tls13-7482d908/security-primary-probes.json) and [recovery](evidence/otel-getsockopt-tls13-7482d908/scenario-basic-security-primary-recovery.json) |
| forged caller PID/TID in Unix request | ignored; kernel peer identity is authoritative | not applicable | untested | execute the Unix security suite |
| repeated unauthorized take attempts | bounded/rate-limited; context remains available | untested | untested | retained probes show bounded completion and recovery, but do not independently prove rate limiting |
| wrong socket identity | rejected without consuming another request's context | untested | untested | retain a targeted wrong-socket result |
| fd reuse | closed/reopened fixed-port traffic; reused Jetty fd across distinct stable Jetty connection IDs; distinct exact parents; zero wrong parents | pass | untested | [reuse graph and connection evidence](evidence/otel-getsockopt-tls13-7482d908/scenario-fd-port-reuse.json) |
| unrelated socket option/level | original kernel behavior preserved | pass | not applicable | [primary probe cases](evidence/otel-getsockopt-tls13-7482d908/security-primary-probes.json) |
| Unix socket path replacement | startup fails closed or uses protected endpoint | not applicable | untested | execute the Unix security suite |
| permissive Unix directory mode | rejected or prominently diagnosed | not applicable | untested | execute the Unix security suite |
| malformed/truncated versioned request | rejected without crash or parent | untested | untested | retain clean full transport-specific evidence |
| oversized/repeated/flooded Unix request | bounded CPU/memory/logging | not applicable | untested | execute the Unix security suite |
| malformed/zero trace or span ID | discarded; Java request remains healthy | untested | untested | retain clean full transport-specific evidence |
| stale entry past TTL | miss; never a parent | untested | untested | retain clean full transport-specific evidence |
| live handoff-map pressure/eviction | order-independent eviction; exact hits, explicit roots, and actual upstream/retrieval reason counts reconciled by transport; zero wrong or unresolved parents; exact-key cleanup and steady-baseline recovery | pass | untested | [pressure status](evidence/otel-getsockopt-tls13-7482d908/scenario-pressure-status.json) and [sanitized pressure summary](evidence/otel-getsockopt-tls13-7482d908/map-pressure-summary.json) |
| OBI absent or delayed | Java root span and healthy response | pass | untested | [OBI-absent](evidence/otel-getsockopt-tls13-7482d908/scenario-fail-open-obi-absent.json) and [late-attach recovery](evidence/otel-getsockopt-tls13-7482d908/scenario-restart-late-attach-recovery.json) |
| OBI restart with old endpoint/fd | no stale parent; recovery only if claimed | pass | untested | [restart traffic](evidence/otel-getsockopt-tls13-7482d908/scenario-restart-fault.json) and [events](evidence/otel-getsockopt-tls13-7482d908/restart-control/events.log) |
| helper absent/disabled | ordinary official-agent behavior | pass | untested | [helper failure](evidence/otel-getsockopt-tls13-7482d908/scenario-helper-attach-failure-helper-unavailable.json) and [bridge disabled](evidence/otel-getsockopt-tls13-7482d908/scenario-disabled.json) |
| extension absent/disabled | ordinary official-agent behavior | pass | untested | [extension absent](evidence/otel-getsockopt-tls13-7482d908/scenario-w3c-only-extension-absent.json) and [disabled](evidence/otel-getsockopt-tls13-7482d908/scenario-w3c-only-extension-disabled.json) |
| both transports unavailable | bounded fail-open, no retry storm | pass | untested | [OBI-absent root](evidence/otel-getsockopt-tls13-7482d908/scenario-fail-open-obi-absent.json) and [W3C-only](evidence/otel-getsockopt-tls13-7482d908/scenario-w3c-only-obi-absent.json) |
| ABI version/length mismatch | rejected with version reason | untested | untested | retain clean full transport-specific evidence |
| valid W3C plus conflicting OBI context | W3C exact IDs win; OBI entry discarded | pass | untested | [conflict graph and counters](evidence/otel-getsockopt-tls13-7482d908/scenario-w3c.json) |
| valid W3C with no OBI state | exact W3C parent; bounded no-state lookup; no Apache span | pass | untested | [W3C-only graph](evidence/otel-getsockopt-tls13-7482d908/scenario-w3c-only-obi-absent.json) |
| repeated async redispatch | one Java server span; one request-scoped parent | pass | untested | [redispatch graph](evidence/otel-getsockopt-tls13-7482d908/scenario-dispatch.json) |
| diagnostic endpoint/log scrape | no raw context/request data or scenario-counter contamination | pass | untested | retained fixed-schema `phases/*/{java-diagnostics,obi-metrics}.delta` and [public-bundle sanitization record](evidence/otel-getsockopt-tls13-7482d908/SANITIZATION.md) |

## Test topology

- Run an attacker process with `docker exec` in the Java container to share its
  cgroup but not its JVM helper state.
- Run a sibling container with the Unix directory mounted to test filesystem
  permissions and peer credentials.
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
- Java diagnostics are requested directly from the verified Jetty TLS endpoint
  before and after each ordinary bridge scenario. The runner stores snapshots
  separately from OBI metrics and accounts for exactly one self-observed
  missing lookup; another missing result fails unless aggregate pressure trace
  evidence reports a corresponding explicit root and the bridge reason counts
  conserve the same request total. Diagnostics do not carry request markers,
  so this is an aggregate reconciliation. The serial fault-injection suite
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
