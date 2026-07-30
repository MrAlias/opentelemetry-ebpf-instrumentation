# Public-bundle sanitization

This directory is a reviewer-facing subset of the ignored clean runtime result
for source revision '74576ec657056dc3f63cb90f4c95f6f362a2dd39'. Its public
evidence ID is derived from the tested matrix cell and source revision rather
than the original timestamp-and-process result directory.

The public subset retains only:

- source identity, clean-state, public acceptance status, agent identity, and
  forced-primary configuration;
- the bounded live-descriptor probe, barrier records, sanitized topology and
  metric summary, held-victim graph, and recovery graph.

The following records were deliberately omitted:

- raw Compose configuration and commands, snapshot paths, container IDs,
  process IDs, cgroup paths, namespaces, and runtime assertion output;
- raw Prometheus scrapes and phase deltas containing BPF map identifiers,
  unrelated metric series, or absolute counters;
- Docker logs, image inventories, raw certificates, stderr logs, request
  payloads, and operational traces outside the bounded scenario graphs.

The transformed records have these properties:

- run-status.json replaces the original absolute evidence directory with the
  public evidence ID.
- runtime-metadata.json retains allowlisted matrix and topology facts only.
- security-primary-live-fd.json reduces the raw before/probe/after metrics to
  the relevant valid and unauthorized negotiate/take values, and records only
  the runtime-topology booleans needed to interpret the control.
- scenario status records remove dangling stderr references; graphs retain only
  synthetic markers, trace/span identifiers, bounded endpoint attributes, and
  exact-parent assertions.
- barrier records retain their phase and bounded file metadata, not their
  private file locations or contents.

No private keys, credentials, request bodies, baggage, tracestate, container
identities, cgroup paths, socket payloads, BPF identifiers, or local checkout
paths are retained. The checksum manifest covers the transformed public files;
it does not claim a byte-for-byte copy of omitted raw material.
