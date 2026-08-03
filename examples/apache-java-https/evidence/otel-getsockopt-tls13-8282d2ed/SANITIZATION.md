# Public-bundle sanitization

This directory is an issue #34 nested-fixture reviewer subset of the ignored
clean runtime result for source revision
`8282d2ed9c3a3f6925902cd84f11f491bc4f4565`. Its public evidence ID is derived
from the tested matrix cell and source revision, not the private
timestamp-and-process runtime directory.

The following eleven records were copied byte-for-byte from the clean result:

- `bridge-artifacts.json`, `bridge-source-revision.txt`, and
  `bridge-source-tree.sha256`;
- `certificates.json`, `environment.txt`, `git-status.txt`,
  `java-selected-transport-configuration.txt`, and `official-javaagent.json`;
- `scenario-tls-boundary.json`, `source-state.txt`, and
  `source-tree.manifest`.

The following three bounded transformations were made before publication:

- `run-status.json` removes the private absolute evidence directory and adds
  the public evidence ID after confirming that the full run passed, exited
  zero, was acceptance-eligible, and recorded no failure stage or line.
- `scenario-tls-boundary-status.json` removes omitted stderr and private phase
  references after confirming the scenario and metric checks passed.
- `runtime-metadata.json` is a synthetic allowlist containing the public ID,
  source revision, tested matrix dimensions, full-suite result counts, and the
  retained issue-specific scope.

`README.md` and this file are authored reviewer guidance. `SHA256SUMS` is
generated after all other public files are final.

The public subset deliberately omits raw Compose commands and resolved YAML,
source-snapshot paths, host/container/process identities, cgroup paths, BPF map
and program identifiers, Prometheus scrapes, phase/resource snapshots,
startup and operational logs, stderr, certificates and private keys, built
JARs, unrelated scenario graphs, and pressure-helper reconstruction inputs.

The retained scenario contains synthetic markers, trace/span IDs, timestamps,
latency and throughput, bounded endpoint attributes, backend connection IDs and
ports, TLS protocol/cipher, plaintext callback lengths, and TLS record
version/length/count metadata needed for the outer-trigger exact-parent graph
and the separate nested boundary fixture. It contains no request body, TLS
payload, private key, credential, baggage, tracestate, cgroup path, raw
capability mask, or local checkout path.

The checksum manifest covers this transformed public subset. It does not claim
that transformed records are byte-for-byte copies of the omitted raw bundle.
