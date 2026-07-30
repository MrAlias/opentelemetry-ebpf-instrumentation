# Public-bundle sanitization

This directory is a reviewer-facing subset of the ignored clean runtime result
for source revision `b678ce1e2415906d45df3bf0728e7ed9e92c52c9`. Its public
evidence ID is derived from the tested matrix cell and source revision, not the
timestamp-and-process runtime directory.

The public subset retains only:

- source identity, clean state, public acceptance status, agent identity, and
  forced-primary configuration;
- the bounded same-JVM wrong-live-socket and duplicated-FD control summary,
  probe record, barrier records, held-victim graph, and recovery graph.

The following records were deliberately omitted:

- raw Compose configuration and commands, snapshot paths, container IDs,
  process IDs, cgroup paths, namespaces, and runtime assertion output;
- raw Prometheus scrapes and phase deltas containing BPF map identifiers,
  unrelated metric series, or absolute counters;
- Docker logs, image inventories, raw certificates, stderr logs, request
  payloads, and operational traces outside the bounded scenario graphs.

The transformed records have these properties:

- `run-status.json` replaces the original absolute evidence directory with the
  public evidence ID.
- `runtime-metadata.json` retains allowlisted matrix and topology facts only.
- `security-primary-live-fd.json` reduces the raw before/probe/after metrics to
  valid and unauthorized negotiate/take values, states that unauthorized-take
  attribution is aggregate, and records only the topology/order facts needed
  to interpret the two controls.
- Scenario status records remove dangling stderr and private phase references.
- Barrier records retain phase and bounded file metadata, not private control
  paths or contents.

The retained traffic graphs still contain synthetic markers, trace/span IDs,
bounded endpoint attributes, timestamps, latency/throughput, backend connection
IDs and ports, and TLS protocol/cipher/read diagnostics. No private keys,
credentials, request bodies, baggage, tracestate, container identities, cgroup
paths, socket payloads, BPF identifiers, or local checkout paths are retained.
The checksum manifest covers transformed public files; it does not claim a
byte-for-byte copy of omitted raw material.
