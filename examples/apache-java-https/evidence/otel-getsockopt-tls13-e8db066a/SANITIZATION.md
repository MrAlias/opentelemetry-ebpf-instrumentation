# Public-bundle sanitization

This directory is a reviewer-facing subset of the ignored clean runtime result
for source revision `e8db066ac36748f17d8debd9098e9d1ddba67067`. Its public
evidence ID is derived from the tested matrix cell and source revision, not the
timestamp-and-process runtime directory.

The following records were copied unchanged from the clean result:

- source revision, source-tree manifest, clean source state, bounded environment
  record, bridge artifact checksums, official-agent identity, forced transport
  snapshot, certificate metadata, unprivileged feature-probe output, normalized
  instrumentation controls, and final receiver snapshot;
- bounded scenario result graphs, fixed-schema terminal Java diagnostics,
  one-shot fault arm/consumption records, and live-descriptor barrier records.

The following bounded transformations were made before publication:

- `run-status.json` replaces the original absolute evidence directory with the
  public evidence ID.
- `runtime-metadata.json`, `runtime-images.json`, and
  `apache-openssl-runtime.txt` retain allowlisted runtime facts without raw
  commands, paths, timestamps, or container identities.
- Scenario status records remove omitted stderr and private phase references.
  The security and restart statuses point to their public summaries instead of
  raw logs.
- `security-primary-probes.json` combines the same-cgroup and sibling probe
  results and their isolated unauthorized-operation deltas without absolute
  counters, container identities, or host process identifiers.
- `security-primary-live-fd-probe.json` reformats the raw single-line JSON probe
  log without changing its values or treating its native-fallthrough result as
  enforcement proof. `security-primary-live-fd.json` reduces the
  before/probe/after bridge metrics to valid and unauthorized negotiate/take
  values, states the aggregate attribution boundary, and records only the
  topology and ordering facts needed to interpret the two controls.
- `map-pressure-summary.json` retains capacity, eviction, trace accounting,
  cleanup, and recovery outcomes without map IDs, namespaces, process IDs, or
  synthetic-key reconstruction inputs.
- `duplicate-suppression.json` retains only the required avoided-services
  sample from the omitted full metrics scrape.
- `delayed-otlp-suppression.json` retains only relative export-boundary timing,
  bounded receiver counts, span-role inventory, suppression-signal state, and
  the post-detection decision. It omits markers, identifiers, and absolute
  start, export, and receipt timestamps.
- `restart-control/events.txt` strips timestamps and retains only the five
  ordered restart transitions.

The public subset deliberately omits raw Compose commands and resolved YAML,
source-snapshot paths, operational host/container/process identities outside
the bounded synthetic trace endpoint attributes, host-session cgroup paths,
BPF map and program identifiers, raw Prometheus scrapes, full phase/resource
snapshots, startup and operational logs, stderr logs, certificates and private
keys, built JARs, and pressure-helper cleanup inputs.

Every retained scenario result contains synthetic traffic and the bounded
trace graph used by the assertion. Graphs retain synthetic markers, trace/span
IDs, timestamps, latency/throughput, backend connection IDs and ports, and TLS
protocol/cipher/read diagnostics needed for exact-parent correlation. Endpoint
attributes are bounded to the demo fixtures. No private keys, credentials,
request bodies, baggage, tracestate, raw Linux capability masks, raw container
IDs, cgroup paths, socket payloads, BPF identifiers, or local checkout
paths are retained.

The checksum manifest covers this transformed public subset. It does not claim
that transformed records are byte-for-byte copies of the omitted raw bundle.
