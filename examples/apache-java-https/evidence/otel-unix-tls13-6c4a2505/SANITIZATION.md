# Public-bundle sanitization

This directory is a reviewer-facing subset of the ignored clean runtime result
for source revision `6c4a2505b6a6d4e89d3aedd9952097ad42ce1457`. Its public
evidence ID is derived from the tested matrix cell and source revision rather
than the original timestamp-and-process result directory.

The public subset retains only:

- source identity, clean-state, public acceptance status, agent identity, and
  forced-Unix configuration;
- allowlisted Apache/OpenSSL runtime identity;
- sanitized sibling and same-cgroup topology facts, bounded probe outcomes,
  and operation deltas;
- summarized endpoint-replacement, directory-refusal, stale-retrieval, and
  recovery outcomes; and
- synthetic traffic markers, trace/span identifiers, bounded endpoint
  attributes, exact-parent assertion graphs, run timestamps, bounded
  latency/throughput summaries, backend connection IDs and remote ports, TLS
  protocol/cipher/read diagnostics, and the fixed-schema Java diagnostics
  string retained by the stale scenario.

The following records were deliberately omitted:

- raw Compose configuration and commands, snapshot paths, container IDs,
  process IDs, cgroup paths, namespaces, socket paths, and runtime assertion
  output;
- raw Prometheus scrapes and phase deltas containing BPF map/program
  identifiers, unrelated metric series, or absolute counters;
- Docker logs, stderr logs, image inventories, raw certificates, request
  payloads, and operational traces outside the bounded scenario graphs; and
- the raw Unix probe logs, same-cgroup identity record, endpoint log, and
  permissive-directory response because they contain operational identifiers
  or response details beyond the facts needed to assess the control.

The transformed records have these properties:

- `run-status.json` replaces the original absolute evidence directory with the
  public evidence ID.
- `runtime-metadata.json` retains allowlisted matrix, host, and backend facts
  only.
- `security-unix-probes.json` retains bounded probe classifications and
  source-labelled operation deltas, without container/process/namespace,
  cgroup-path, BPF-map, or socket identifiers.
- `unix-w3c-stale.json` reduces raw OBI and Java before/after diagnostics to
  the stale, valid, and missing retrieval deltas required by the control. The
  retained stale scenario graph also contains its bounded fixed-schema
  `java_diagnostics_after` string for cross-checking that assertion.
- scenario status records remove dangling stderr and private phase-path
  references; graphs retain synthetic markers, trace/span identifiers,
  bounded endpoint attributes, exact-parent assertions, timestamps,
  latency/throughput summaries, backend connection IDs and remote ports, and
  TLS protocol/cipher/read diagnostics.

No private keys, credentials, request bodies, baggage, tracestate, container
identities, cgroup paths, socket payloads, BPF identifiers, or local checkout
paths are retained. The checksum manifest covers the transformed public files;
it does not claim a byte-for-byte copy of omitted raw material.
