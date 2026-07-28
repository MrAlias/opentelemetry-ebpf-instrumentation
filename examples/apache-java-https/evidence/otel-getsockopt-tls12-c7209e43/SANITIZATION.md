# Public-bundle sanitization

This directory is a reviewer-facing subset of an original ignored runtime
result directory. The public evidence ID is derived only from the tested matrix
cell and source revision, not the original timestamp-and-process run name. The
tested source revision and scenario results are retained, but the original
operational bundle is not published.

The public subset deliberately omits raw Compose commands and logs, local
checkout paths, hostnames, container and process identifiers, cgroup records,
BPF map and program identifiers, and the pressure helper's per-run cleanup
inputs. It also omits built JARs and filename-oriented checksum lists; their
content hashes remain in bridge-artifacts.json.

The following bounded transformations were made before publication:

- runtime-metadata.json, runtime-images.json, and
  apache-openssl-runtime.txt retain allowlisted runtime facts without raw
  commands, timestamps, runtime identities, or library filesystem paths.
- environment.txt retains only the relative invocation, source identity,
  declared test inputs, and coarse host/runtime versions. It omits the Compose
  project, full uname-style kernel value, and host OpenSSL detail.
- security-primary-probes.json combines the two primary probe results and
  retains case outcomes, requested users, a boolean cgroup comparison, and
  generic topology descriptions without cgroup, container, namespace, or host
  process identifiers.
- map-pressure-summary.json retains capacity, eviction, trace accounting,
  cleanup, and recovery outcomes without map IDs, namespaces, or synthetic-key
  reconstruction inputs.
- OBI phase deltas retain only allowlisted bridge operation/status/transport
  labels and per-phase delta values. Absolute before/after values, BPF map and
  probe identifiers, and unrelated host activity metrics are omitted.
- duplicate-suppression.json retains only the required avoided-services sample
  from the omitted full metrics scrape.
- run-status.json names the public evidence ID instead of its absolute local
  path or original process-derived run name.
- restart-control/events.txt retains only the five ordered restart transitions;
  the restart scenario status refers to that public artifact rather than the
  ignored raw-log filename.
- java-selected-transport-configuration.txt is retained unchanged. It is a
  bounded V2 Java configuration result, not a request-level transport claim.
- Per-scenario stderr logs are omitted, and their dangling stderr properties
  are removed from retained status records. scenario-security-status.json
  replaces raw probe-log references with security-primary-probes.json.
- Status records whose after-phase artifacts were not needed for their scenario
  result and were omitted from this public subset have their dangling
  after_phase properties removed.

Scenario result JSON, fixed-schema Java diagnostic deltas, source identity,
agent identity, certificate metadata, control-response normalizations, and
restart-control artifacts were retained only after checking that they contain
synthetic traffic and no host identifiers. Scenario graphs retain synthetic
trace/span IDs, connection values, and timestamps needed for exact-parent
correlation. Their endpoint attributes are bounded to the demo's `localhost`,
`127.0.0.1`, or `apache-proxy` fixtures, including the inbound-Netty endpoint
on port 18444.

The checksum manifest authenticates this retained subset after transformation.
It does not claim that transformed records are byte-for-byte copies of the
omitted raw bundle.
