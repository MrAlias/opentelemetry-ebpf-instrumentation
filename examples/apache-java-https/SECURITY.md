# Security and abuse-case matrix

Status: **untested**

The PoC crosses a kernel/JVM trust boundary and exposes a local Unix fallback.
Passing the happy path is insufficient. Every negative cell must preserve
application availability, avoid consuming another request's context, finish
within a bounded deadline, and produce a low-cardinality reason code without
logging trace IDs, headers, bodies, credentials, PID/TID labels, or socket
payloads.

| Abuse or fault | Required result | Status |
| --- | --- | --- |
| unrelated process in same cgroup calls take | denied; legitimate Java take still succeeds | untested |
| sibling container/PID namespace calls take | denied by current identity/peer credentials | untested |
| forged caller PID/TID in Unix request | ignored; kernel peer identity is authoritative | untested |
| repeated unauthorized take attempts | bounded/rate-limited; context remains available | untested |
| wrong socket identity or fd reuse | closed/reopened fixed-port traffic; reused Jetty fd across distinct stable Jetty connection IDs; distinct exact parents; zero wrong parents | untested |
| unrelated socket option/level | original kernel behavior preserved | untested |
| Unix socket path replacement | startup fails closed or uses protected endpoint | untested |
| permissive Unix directory mode | rejected or prominently diagnosed | untested |
| malformed/truncated versioned request | rejected without crash or parent | untested |
| oversized/repeated/flooded Unix request | bounded CPU/memory/logging | untested |
| malformed/zero trace or span ID | discarded; Java request remains healthy | untested |
| stale entry past TTL | miss; never a parent | untested |
| live handoff-map pressure/eviction | proven eviction; zero wrong parents; recovered occupancy | untested |
| OBI absent or delayed | Java root span and healthy response | untested |
| OBI restart with old endpoint/fd | no stale parent; recovery only if claimed | untested |
| helper absent/disabled | ordinary official-agent behavior | untested |
| extension absent/disabled | ordinary official-agent behavior | untested |
| both transports unavailable | bounded fail-open, no retry storm | untested |
| ABI version/length mismatch | rejected with version reason | untested |
| valid W3C plus conflicting OBI context | W3C exact IDs win; OBI entry discarded | untested |
| valid W3C with no OBI state | exact W3C parent; bounded no-state lookup; no Apache span | untested |
| repeated async redispatch | one Java server span; one request-scoped parent | untested |
| diagnostic endpoint/log scrape | no raw context/request data or scenario-counter contamination | untested |

## Test topology

- Run an attacker process with `docker exec` in the Java container to share its
  cgroup but not its JVM helper state.
- Run a sibling container with the Unix directory mounted to test filesystem
  permissions and peer credentials.
- Send fixed malformed, truncated, oversized, repeated, and wrong-version
  messages; never fuzz without a duration and size bound.
- Keep a legitimate marked request pending while unauthorized consumers race,
  then require the legitimate exact parent assertion to pass.
- Fill the discovered live handoff-claim LRU to its reported capacity plus one,
  derive synthetic keys and fresh values from the one unambiguous live JVM
  PID/namespace/incarnation, prove the oldest deterministic key was evicted,
  monitor exact-map occupancy once per second throughout marked async traffic,
  and remove only those deterministic keys afterward. Evidence never records
  the incarnation capability.
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
  reconstruct only its synthetic keys, including after the JVM identity entry
  disappears.
- The Unix fault responder is an acceptance-only, single-request-at-a-time
  service with named stale/malformed, timeout, disconnect, overload,
  truncation, envelope, version, and zero-ID modes. It uses strict request ABI
  parsing, short I/O deadlines, a fixed counter, and no request identity
  logging.
- Java diagnostics are requested directly from the verified Jetty TLS endpoint
  before and after each bridge scenario. The runner stores snapshots separately
  from OBI metrics and accounts for exactly one self-observed missing lookup;
  another missing result still fails the scenario. Fault-injection scenarios do
  not probe diagnostics because doing so would consume a fault response.
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
