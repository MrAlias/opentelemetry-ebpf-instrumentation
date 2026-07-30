# Retained acceptance evidence

This directory contains bounded, sanitized artifacts from clean full demo runs.
Each evidence directory records the exact source revision and invocation,
contains a checksum manifest, and states which matrix cell it can support.

## Verify a retained bundle

Verify a published bundle before relying on it for a matrix cell:

```bash
./examples/apache-java-https/scripts/verify-retained-evidence.sh \
  examples/apache-java-https/evidence/otel-getsockopt-tls13-c9d14356
```

The verifier accepts only a published evidence directory tracked by the `HEAD`
commit captured when verification begins in the same Git checkout as the
verifier. It reads that immutable Git snapshot, requires an exact checksum file
set, a canonical public evidence identifier, and a passed clean full `all`
result. It rejects a supplied bundle path that differs from the captured commit
or contains extra working-tree files, and reports the pinned checkout commit on
success. Its immutable archive snapshot is created under the same fixed,
physically validated root-owned sticky `/tmp` boundary, not caller-controlled
`TMPDIR`, and sealed read-only before validation. It also regenerates
`source-tree.manifest` from the recorded source commit and compares it
byte-for-byte. The reviewed Git checkout and its available provenance history
are therefore the trust root; `SHA256SUMS` alone provides integrity checking,
not independent authenticity. A raw `.runtime` result, an untracked copied
bundle, or a targeted focused run cannot satisfy this acceptance-bundle
contract.

New clean runs record `source_tree_manifest_schema=git-tree-v2` in both source
metadata files. That schema canonically represents regular, executable,
symbolic-link, and gitlink tree entries from the recorded Git commit. Only the
seven named historical bundles below may omit the schema because their original
regular-file manifests are pinned to their exact recorded revisions.
Before a clean run invokes Docker, the runner materializes a private snapshot
from that pinned Git tree (recursively materializing initialized gitlinks at
their recorded commits), verifies its contents and executable modes, and uses
the snapshot's Dockerfiles, Compose build contexts, and source bind mounts.
The snapshot is a current-user-owned `0700` child of the fixed, physically
validated root-owned sticky `/tmp` directory; it never uses caller-controlled
`TMPDIR` or the working tree's runtime directory. Only generated runtime
certificates and checked bridge artifacts are added to that private snapshot.
The runner keeps Git-tree control records and Docker bridge-export intermediates
in a separate private `0700` child of that same boundary, so generated control
files are not part of the source-tree inventory or exposed through `.runtime`.
Consequently, ignored working-tree files, filters, and Git configuration such
as `core.fileMode=false` cannot alter the clean-run source inputs Docker
receives. Once its generated runtime inputs are present, the runner seals the
snapshot read-only before Compose builds or starts the stack. This requires a
local filesystem that honors POSIX ownership and sticky-directory semantics;
ACL or network filesystems that do not provide equivalent isolation are
unsupported. The boundary does not defend against another process running as
the same user and deliberately changing file permissions; that process is
within the local execution trust boundary. Dirty local runs remain
non-acceptance evidence.
The runner also fails a clean run if its source revision, index, working tree,
or nested gitlink state changes after capture.

## Historical metric schemas

The retained bundles are immutable evidence for their recorded revisions. The
two historical bundles `otel-getsockopt-tls13-7482d908` and
`otel-unix-tls12-acedb68a` predate the `availability` rename, so their OBI
metric deltas can contain `operation="select"`. In those historical revisions,
`select` means only OBI-side transport readiness or preference; it is neither
Java helper selection nor proof that a request used that transport. The current
`otel-getsockopt-tls13-c9d14356`, `otel-getsockopt-tls12-c7209e43`,
`otel-unix-tls12-bd1c9327`, and `splunk-getsockopt-tls13-47237792` bundles use
`operation="availability"` and retain V2 Java transport-configuration
snapshots. The prior
`otel-getsockopt-tls13-94221a91` bundle uses the same current schema. The
current schema has an
eleven-operation, 792-series upper bound, as documented in the [Java
remote-parent bridge guide](../../../devdocs/java-remote-parent-bridge.md).
Checksum verification preserves the checked-in artifact set; it does not
recast their historical schema.

| Evidence | Result | Matrix cell |
| --- | --- | --- |
| [splunk-getsockopt-tls13-47237792](splunk-getsockopt-tls13-47237792/README.md) | pass | Splunk 2.28.0, forced `getsockopt`, TLS 1.3, Java 21, `amd64`, unified cgroup v2; includes bounded primary-transport security controls |
| [otel-getsockopt-tls12-c7209e43](otel-getsockopt-tls12-c7209e43/README.md) | pass | OpenTelemetry 2.28.1, forced `getsockopt`, TLS 1.2, Java 21, `amd64`, unified cgroup v2; source-exact current V2 primary cell |
| [otel-getsockopt-tls13-c9d14356](otel-getsockopt-tls13-c9d14356/README.md) | pass | OpenTelemetry 2.28.1, forced `getsockopt`, TLS 1.3, Java 21, `amd64`, unified cgroup v2; includes the bounded inbound-Netty fixture |
| [otel-getsockopt-tls13-74576ec6](otel-getsockopt-tls13-74576ec6/README.md) | pass | OpenTelemetry 2.28.1, forced `getsockopt`, TLS 1.3, Java 21, `amd64`, unified cgroup v2; bounded root-in-PID-1-cgroup live-descriptor security control |
| [otel-getsockopt-tls13-94221a91](otel-getsockopt-tls13-94221a91/README.md) | pass | OpenTelemetry 2.28.1, forced `getsockopt`, TLS 1.3, Java 21, `amd64`, unified cgroup v2 |
| [otel-unix-tls12-bd1c9327](otel-unix-tls12-bd1c9327/README.md) | pass | OpenTelemetry 2.28.1, forced Unix RPC, TLS 1.2, Java 21, `amd64`, unified cgroup v2 |
| [otel-getsockopt-tls13-7482d908](otel-getsockopt-tls13-7482d908/README.md) | pass | OpenTelemetry 2.28.1, forced `getsockopt`, TLS 1.3, Java 21, `amd64`, unified cgroup v2 |
| [otel-unix-tls12-acedb68a](otel-unix-tls12-acedb68a/README.md) | pass | OpenTelemetry 2.28.1, forced Unix RPC, TLS 1.2, Java 21, `amd64`, unified cgroup v2 |

An omitted matrix cell remains `untested`. A targeted run whose
`acceptance_evidence` field is false is not retained here as acceptance
evidence. The separate [focused primary-control record](../focused-validation/primary-getsockopt-8f0aa1f6/README.md)
contains such current targeted validation and states its non-acceptance scope.
