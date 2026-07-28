# Public-bundle sanitization

This directory is a reviewer-facing subset of an ignored runtime result
directory. The public evidence ID is derived from the tested matrix cell and
source revision, not the original timestamp-and-process run name. The tested
source revision and scenario results are retained, but the original
operational bundle is not published.

The public subset omits raw Compose commands and logs, local checkout paths,
real hostnames, runtime container and process identifiers, host-session cgroup
paths, Unix-socket runtime identities, capabilities, private keys, security
canaries, raw fault-responder logs, raw request payloads, and raw request
headers. It also omits runtime and numeric map identifiers, program
identifiers, and the pressure helper's per-run cleanup inputs. Content hashes
for the helper and extension remain in `bridge-artifacts.json`.

The following bounded transformations were made before publication:

- `environment.txt` replaces the full host `uname` with the kernel release and
  architecture. It retains the observed unified-cgroup-v2 topology but not the
  host distribution, hostname, session path, or BTF/privilege details.
- `runtime-metadata.json` retains only allowlisted kernel-release and
  architecture host facts. `runtime-images.json` retains role, reference, and
  image digest without container names, creation times, or local commands.
- `bpftool-feature-probe.txt` retains only the unavailable status and
  insufficient-privileges reason, without the original command or capability
  detail.
- `restart-control/events.log` retains only the five ordered state transitions;
  original timestamps are omitted.
- Scenario result JSON removes runner start/finish timestamps and span timing
  timestamps while retaining synthetic parent graphs, ordering, and latency
  measurements.
- `certificates.json` retains certificate fingerprints, subject alternative
  names, and the bounded validity duration, without certificate issuance or
  expiry timestamps.
- `security-unix-probes.json` combines the Unix abuse-race, endpoint
  replacement, directory-permission, metric, legitimate-victim, and recovery
  outcomes without socket paths, host or container process IDs, raw logs, or
  probe payloads.
- `map-pressure-summary.json` retains the static map name
  `java_remote_parent_handoff_claims`, capacity, eviction, trace accounting,
  cleanup, and recovery outcomes. Runtime and numeric map identifiers,
  namespaces, process IDs, tokens, and synthetic-key reconstruction inputs are
  omitted.
- `phases/*/obi-metrics.delta` retains only allowlisted bridge
  operation/status/transport labels and per-phase deltas. Absolute
  before/after values, BPF map and program identifiers, and unrelated host
  activity metrics are omitted. Fault-responder phases contain no allowlisted
  production-OBI sample, so their retained OBI delta files are empty.
- `duplicate-suppression.json` retains only the required
  `obi_avoided_services` sample from the omitted full metrics scrape.
- `run-status.json` names the public evidence ID instead of its absolute local
  path or original process-derived run name.
- Per-scenario stderr logs are omitted. Their dangling `stderr` properties
  were removed from retained status records; assertion, pressure-correlation,
  result, and phase references remain.
- `scenario-security-status.json` replaces references to omitted raw probe logs
  with `security-unix-probes.json`.

The checksum manifest authenticates this retained subset after transformation.
It does not claim that transformed records are byte-for-byte copies of the
omitted raw files. Java diagnostic deltas, source identity, agent identity,
certificate metadata, normalized controls, and restart diagnostics were retained
without content changes.

The scenario graphs deliberately retain synthetic trace/span IDs, test markers,
workload-local connection IDs, ports, and file descriptors because those
relationships prove parent equality, connection reuse, and ordering. They are
generated only by this demo and are not host identities. This includes the
synthetic `x-obi-demo-id` request-header attribute; no non-synthetic or
sensitive request header is retained.

The runner checked canary non-disclosure against omitted raw logs. The public
security summary retains that pass/fail assertion but cannot independently
repeat the search without the intentionally unpublished logs.
