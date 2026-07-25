# Public-bundle sanitization

This directory is a reviewer-facing subset of an original ignored runtime
result directory. The public evidence ID is derived only from the tested matrix
cell and source revision, not the original timestamp-and-process run name. The
tested source revision and scenario results are retained, but the original
operational bundle is not published.

The public subset deliberately omits raw Compose commands and logs, local
checkout paths, hostnames, container and process identifiers, host-session
cgroup paths, and the pressure helper's per-run cleanup inputs. It also omits
the built JARs and their filename-oriented checksum list; their content hashes
remain in `bridge-artifacts.json`.

The following bounded transformations were made before publication:

- `runtime-metadata.json`, `runtime-images.json`, and
  `apache-openssl-runtime.txt` retain allowlisted runtime facts without raw
  commands, timestamps, or runtime identities.
- `security-primary-probes.json` combines the two primary probe results and
  retains the same-cgroup comparison, isolated sibling topology, case outcomes,
  and links to legitimate traffic without container or host process IDs.
- `map-pressure-summary.json` retains capacity, eviction, trace accounting,
  cleanup, and recovery outcomes without map IDs, namespaces, or synthetic-key
  reconstruction inputs.
- `phases/*/obi-metrics.delta` retains only allowlisted bridge
  operation/status/transport labels and their per-phase deltas. Absolute
  before/after values, BPF map and probe identifiers, and unrelated host
  activity metrics are omitted.
- `duplicate-suppression.json` retains only the required
  `obi_avoided_services` sample from the omitted full metrics scrape.
- `run-status.json` names the public evidence ID instead of its absolute local
  path or original process-derived run name.
- The omitted per-scenario stderr logs contained operational output. Their
  dangling `stderr` properties were removed from the retained status records;
  all assertion result and phase references remain.
- `scenario-security-status.json` replaces references to the two omitted raw
  probe logs with its retained `security-primary-probes.json` summary.

The checksum manifest authenticates this retained subset after transformation.
It does not claim that transformed records are byte-for-byte copies of the
omitted raw files. Scenario result JSON, Java diagnostic deltas, source
identity, agent identity, certificate metadata, and restart-control artifacts
were retained without content changes.
