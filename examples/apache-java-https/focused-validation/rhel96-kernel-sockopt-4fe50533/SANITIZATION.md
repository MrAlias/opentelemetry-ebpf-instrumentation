# Focused RHEL preflight sanitization

This directory is a derived, reviewer-facing summary of one ignored GitHub
Actions artifact and its producing workflow run at the exact source revision
recorded in `run-identity.json`. The public directory name is derived from the
kernel target and source revision, not from a workflow run, job, artifact,
timestamp, or process identifier.

## Retained transformations

- `run-identity.json` allowlists the exact source revision; bounded kernel,
  userspace, architecture, cgroup, BTF, Java-feature, transport, and
  evidence-scope facts; and the public repository, workflow-run URL, artifact
  name, and GitHub-reported archive digest needed to bind the summary to one
  execution.
- `preflight-results.json` converts required Go test pass markers and workflow
  platform gates into stable names, counts, statuses, and booleans. Test
  durations and raw output are not retained.
- `transport-benchmark.json` converts the raw schema-v2, single-line benchmark
  record into a formatted focused-evidence record. It retains exactly six
  aggregate series. Each series retains the original transport, outcome,
  fixed workload, batch duration, percentiles, throughput, outcome counts,
  correctness result, and latency gate. Aggregate nanosecond durations are
  measurements, not wall-clock timestamps.
- `SHA256SUMS` hashes only the five sanitized sibling files and does not hash
  itself.

The verifier profile values containing `/` are stable Go subtest labels, not
filesystem paths.

## Omitted raw material

The summary omits all raw console and test logs, the full bpftool feature dump,
kernel configuration and build information, BTF content and digest, Java and
BPF build artifacts, JARs, per-file raw artifact checksums,
dependency-download output, and complete command output. The sole retained raw
checksum is GitHub's public digest of the complete artifact archive.

It also omits local checkout and temporary paths, absolute timestamps,
hostnames, usernames and numeric user identifiers, job and numeric artifact
identifiers, container and process identifiers, thread identifiers, socket
descriptors and cookies, cgroup and namespace identities, trace and span IDs,
raw payloads, and other operational strings. The public workflow-run URL and
artifact name are deliberate provenance exceptions.

No raw file is copied byte-for-byte into this directory. The checksum manifest
covers only the sanitized public record. The GitHub-reported archive digest
binds the summary to a raw artifact but does not turn the artifact into
acceptance evidence or authenticate the semantic claims in this bundle.
