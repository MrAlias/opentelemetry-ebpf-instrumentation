# Public-bundle sanitization

This directory is a reviewer-facing subset of an original ignored runtime
result directory. The public evidence ID is derived only from the tested matrix
cell and source revision, not the original timestamp-and-process run name. The
tested source revision and scenario results are retained, but the original
operational bundle is not published.

The public subset deliberately omits raw Compose commands and logs, local
checkout paths, hostnames, container and process identifiers, host-session
cgroup paths, map and program identifiers, Unix-socket runtime identities, and
the pressure helper's per-run cleanup inputs. It also omits built JARs, private
keys, security canaries, raw fault-responder logs, and filename-oriented
artifact checksum lists. Content hashes for the helper and extension remain in
`bridge-artifacts.json`.

The following bounded transformations were made before publication:

- `runtime-metadata.json`, `runtime-images.json`, and
  `apache-openssl-runtime.txt` retain allowlisted runtime facts without raw
  commands, timestamps, or runtime identities.
- `security-unix-probes.json` combines the Unix abuse-race, endpoint
  replacement, directory-permission, metric, legitimate-victim, and recovery
  outcomes without socket paths, host or container process IDs, raw logs, or
  probe payloads.
- `map-pressure-summary.json` retains capacity, eviction, trace accounting,
  cleanup, and recovery outcomes without map IDs, namespaces, process IDs,
  tokens, or synthetic-key reconstruction inputs.
- `phases/*/obi-metrics.delta` retains only allowlisted bridge
  operation/status/transport labels and their per-phase deltas. Absolute
  before/after values, BPF map and probe identifiers, and unrelated host
  activity metrics are omitted. Fault-responder phases contain no allowlisted
  production-OBI sample, so their retained OBI delta files are empty.
- `duplicate-suppression.json` retains only the required
  `obi_avoided_services` sample from the omitted full metrics scrape.
- `run-status.json` names the public evidence ID instead of its absolute local
  path or original process-derived run name.
- The omitted per-scenario stderr logs contained operational output. Their
  dangling `stderr` properties were removed from retained status records; all
  assertion, pressure-correlation, result, and phase references remain.
- `scenario-security-status.json` replaces references to omitted raw probe
  logs with `security-unix-probes.json`.

The checksum manifest authenticates this retained subset after transformation.
It does not claim that transformed records are byte-for-byte copies of the
omitted raw files. Scenario result JSON, Java diagnostic deltas, source
identity, agent identity, certificate metadata, normalized controls, restart
diagnostics, and restart-control events were retained without content changes.
The scenario graphs deliberately retain synthetic trace/span IDs, test
markers, workload-local connection IDs, ports, and file descriptors because
those relationships prove parent equality, connection reuse, and ordering.
They are generated only by this demo and are not host identities. This
includes the synthetic `x-obi-demo-id` request-header attribute; no
non-synthetic or sensitive request header is retained.

The runner checked canary non-disclosure against omitted raw logs. The public
security summary retains that pass/fail assertion but cannot independently
repeat the search without the intentionally unpublished logs.
