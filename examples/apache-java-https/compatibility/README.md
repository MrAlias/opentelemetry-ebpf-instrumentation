# Application compatibility campaigns

This directory defines two execution campaigns. It contains no recorded pass:
results exist only after a provider runs a frozen cell and the sealer accepts
its evidence.

- `campaign-v3.json` is the exact 45-cell compatibility campaign. Its frozen
  roster is `expected-v3-cell-ids.txt`: 34 kernel/topology/deployment cells,
  seven additional JVM/agent cells, two native `arm64` cells, and two TLS 1.2
  cells. `auto` is deliberately absent. RHEL 8 / 4.18 is an explicit untested
  exclusion that requires direct execution; no kernel-version inference is
  permitted.
- `helper-lifecycle-v1.json` is a separate seven-cell helper campaign. It must
  not be added to, or used to change the count of, the 45-cell aggregate.
  Every pass covers blocking `SSLSocket`, `SSLEngine`/`SocketChannel`, and
  Netty `SslHandler`; normal extraction and unavailable-context fallback;
  platform, executor, cross-thread, duplicate, stale, and cross-request
  behavior; early/late helper attach; OBI absence/restart; unsupported
  transport; version mismatch; both extension load orders; and all repeated
  resource gates named in the plan. Virtual threads pass only on Java 21 and
  are recorded as product `unsupported` with evidence on older JVMs.

The plans pin OpenTelemetry Java agent 2.28.1 and Splunk Java agent 2.28.0.
They describe application executions, not the packaged-JVM component tests in
the Java CI workflow.

## Run and collect

Run one cell into a new private directory:

```bash
CAMPAIGN_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/obi-compatibility.XXXXXX")"
chmod 700 "$CAMPAIGN_ROOT"
mkdir -m 700 "$CAMPAIGN_ROOT/cells"

./examples/apache-java-https/compatibility/create-source-authority.sh \
  --output "$CAMPAIGN_ROOT/source-authority.json"

./examples/apache-java-https/compatibility/run-cell.sh \
  --campaign compatibility \
  --cell k-upstream612-container-v2-getsockopt \
  --source-authority "$CAMPAIGN_ROOT/source-authority.json" \
  --output "$CAMPAIGN_ROOT/cells/k-upstream612-container-v2-getsockopt"
```

The command exits 0 for `pass`, 1 for `fail`, 78 for product `unsupported`,
and 69 for infrastructure `untested`. Every exit publishes a sealed record
unless the harness itself cannot safely publish evidence. A caller must retain
the directory even when the exit is nonzero.

After all exact IDs have a directory, create an aggregate:

```bash
./examples/apache-java-https/compatibility/collect.sh \
  --campaign compatibility \
  --input-root "$CAMPAIGN_ROOT/cells" \
  --source-authority "$CAMPAIGN_ROOT/source-authority.json" \
  --output "$CAMPAIGN_ROOT/public-aggregate-v3"
```

The collector accepts exactly one unique record for every frozen ID. It
re-seals each cell from its private provider result, checks both manifests and
the public-record digest, rejects missing/foreign/stale/cross-cell evidence,
requires every nonempty cell source identity to match the explicit authority,
and then copies only `cell.json` into the public aggregate. `aggregate.json`
is `incomplete-untested` while any cell is untested. A fail or unsupported
cell closes only that exact cell; neither status is inferred for another row.
Both the runner and collector recompute the canonical clean source-tree,
tracked-patch, and patch-identity tuple before publication. Any tracked or
untracked checkout change after authority capture rejects the operation.

Raw outer command arguments, logs, container identities, and raw application
evidence stay under each cell's mode-0700 `private/` directory. Public cell
records contain requested dimensions, source/config/runtime identities,
assertions, and cryptographic digests, but no absolute host/private path. A
lifecycle cell also retains the exact fixed inner argv: its only absolute token
is the stable descriptor alias `/proc/self/fd/9`, and every other path is a
canonical private basename. A canonical `evidence_index` binds every digest-valued runtime,
artifact, and assertion leaf to one unique safe relative file under that
cell's raw-evidence root. The sealer requires exact raw-manifest membership and
re-hashes the named regular file; an unbound digest, duplicate binding, path
alias, secret-bearing public value, or substituted file rejects the cell.
Public index paths are at most 512 ASCII characters, use slash-separated
components of at most 128 characters beginning with an alphanumeric character,
and otherwise contain only alphanumerics, dot, underscore, or hyphen. Dot and
hidden components, traversal, controls, duplicate aliases, and case-insensitive
secret words bounded by any non-alphanumeric character are rejected. The same
nondisclosure scan covers the path emitted in the public cell, independently
of its exact field/digest/raw-manifest binding.
Private evidence is capped at 4,096 files and 2 GiB per sealed directory;
external execution also has a two-hour timeout and a shell file-size limit.

## Provider adapters

Provider selection comes from the immutable cell object. A plan value cannot
silently turn into an unused environment parameter.

| Adapter | Exact execution |
| --- | --- |
| `runsh-java21-container-v1` | production `run.sh --transport VALUE --agent VALUE --tls VALUE --scenario all --repeat 1 --seed 1`; only container-process Java 21 forced-transport cells |
| `preprovisioned-host-application-v1` | registry-approved driver from `OBI_COMPATIBILITY_HOST_APPLICATION_DRIVER` and `OBI_COMPATIBILITY_HOST_APPLICATION_DRIVER_SHA256` |
| `preprovisioned-jvm-application-v1` | registry-approved driver from `OBI_COMPATIBILITY_JVM_APPLICATION_DRIVER` and `OBI_COMPATIBILITY_JVM_APPLICATION_DRIVER_SHA256` |
| `preprovisioned-lifecycle-application-v1` | source-controlled `providers/lifecycle-application-driver-v1.sh`; any override must resolve to that exact registry path and digest |

An external driver must also have an exact `{id, path, sha256}` entry for its
provider in the source-controlled `provider-registry-v1.json`. The production
registry approves one lifecycle outer driver and still has no approved host or
JVM application driver. The separate source-controlled
`lifecycle-executor-registry-v1.json` has no production approvals. Outer-driver
approval is not an execution or pass claim: until a real inner executor is
reviewed with an exact canonical path, digest, and allowed-cell roster, all
seven helper cells remain infrastructure `untested`. A supplied but unapproved self-matching
path/checksum is not executed. An approved path must resolve to the exact
regular executable under this source tree; a same-byte copy at a foreign path
is not approved. The wrapper copies it to a mode-0500 private snapshot,
verifies the original and snapshot identities before and after execution, and
executes the snapshot with this exact interface:

```text
DRIVER \
  --contract compatibility-external-provider-v1 \
  --campaign CAMPAIGN \
  --campaign-revision REVISION \
  --plan-sha256 SHA256 \
  --cell ABSOLUTE_REQUESTED_CELL_JSON \
  --source-authority ABSOLUTE_SOURCE_AUTHORITY_JSON \
  --source-authority-sha256 SHA256 \
  --private-output ABSOLUTE_PRIVATE_OUTPUT_DIRECTORY
```

The driver writes `provider-result.json` in the private output directory and
must echo that exact constructed argv plus its own checksum in `command`; a
lie is a provider-contract failure. The wrapper records the authoritative
argv, registry identity, and snapshot digest itself. The result follows
`schemas/provider-result.schema.json`; `seal-cell.sh` adds stronger semantic
validation that JSON Schema alone cannot express. An unavailable or
unapproved driver is not attempted and has no driver identity. Once an
approved snapshot is executed, its exact registry ID and digest remain bound
even when the driver honestly returns infrastructure `untested`. In
particular, a claimed pass must attest all of the following from the observed
runtime:

- clean source revision, source-tree/patch identity, BPF objects, JNI entry,
  helper, extension, and runtime configuration;
- kernel source provenance, observed release and BTF, native architecture,
  deployment and cgroup topology, JVM runtime, official agent checksum,
  image identities, Apache/OpenSSL identity, and negotiated TLS;
- production provider load/attach and authoritative requested, attempted, and
  selected transport state. Forced transports attempt exactly that transport;
  `auto` selecting primary records only `getsockopt`, selecting fallback records
  `getsockopt` then `unix`, and authoritative unsupported records both attempts;
- a nonzero, exact-size, unique-marker request/case roster with exactly one
  Apache client and Java server span per case; both nodes require canonical
  nonzero lowercase 32-hex trace IDs and 16-hex span IDs, and the Java server
  requires a canonical nonzero parent ID equal to the distinct Apache client
  span ID. Wrong parents are derived from the observed case roster, alongside
  application success and cleanup;
- for the helper campaign, every exact framework/lifecycle key and at least
  three measured cycles for every resource gate, with nonnegative integer
  baseline/final snapshots, a signed integer delta equal to final minus
  baseline, and an observed trend no greater than its declared bound;
  no untested leak gate may pass; the unavailable-bridge control additionally
  requires byte-identical normal/unavailable results, a passing normal-agent
  extraction proof, and no more than 64 diagnostics or 65,536 diagnostic
  bytes.

### Reviewed helper-lifecycle driver

The source-controlled lifecycle driver is selected automatically when both
legacy driver override variables are absent. If either override is supplied,
both must still name the exact outer registry path and digest; they are not an
escape from source approval. The checked-in inner registry is empty, so the
following descriptor remains a future interface rather than current execution
authority. Actual platform execution requires both a reviewed inner-registry
entry and an explicit, mode-safe environment descriptor:

```bash
export OBI_COMPATIBILITY_LIFECYCLE_ENVIRONMENT=/absolute/path/environment.json
export OBI_COMPATIBILITY_LIFECYCLE_ENVIRONMENT_SHA256="$({
  sha256sum -- "$OBI_COMPATIBILITY_LIFECYCLE_ENVIRONMENT"
} | awk '{print $1}')"
```

The descriptor has this exact shape. Its `cell` is exactly JSON-equal to the
selected object in `helper-lifecycle-v1.json`; a real descriptor
does not abbreviate the object shown here.

```json
{
  "schema": "compatibility-helper-lifecycle-environment-v1",
  "id": "upstream612-jdk21-amd64-lifecycle-v1",
  "cell": {
    "id": "h-jdk21-amd64-otel-getsockopt",
    "kernel": "upstream-6.12",
    "deployment": "container-process",
    "cgroup_topology": "unified-v2",
    "architecture": "amd64",
    "jvm_feature": 21,
    "agent_distribution": "otel",
    "agent_version": "2.28.1",
    "tls": "TLSv1.3",
    "transport": "getsockopt",
    "provider": "preprovisioned-lifecycle-application-v1"
  },
  "executor": {
    "id": "reviewed-helper-lifecycle-executor-v1",
    "path": "providers/lifecycle-executors/run-helper-lifecycle-cell",
    "sha256": "0000000000000000000000000000000000000000000000000000000000000000"
  }
}
```

The descriptor is a regular, single-link, root- or caller-owned file with no
group/world write bit. Its executor object must exactly match one source-bound
inner-registry entry, including the canonical compatibility-relative path,
digest, and permission for the selected cell ID. The approved executor has the
same ownership/link/mode constraints. The driver snapshots all authority
inputs, opens the executor snapshot once, checks path and open-descriptor
inode/digest equality before and after execution, and invokes that inherited
descriptor with this exact path-free argument vector from its private working
directory:

```text
/proc/self/fd/9 \
  --contract compatibility-helper-lifecycle-environment-v1 \
  --campaign-revision apache-java-https-helper-lifecycle-v1 \
  --plan-sha256 SHA256 \
  --cell requested-cell.snapshot.json \
  --source-authority source-authority.snapshot.json \
  --source-authority-sha256 SHA256 \
  --environment lifecycle-environment.snapshot.json \
  --environment-sha256 SHA256 \
  --output environment-output
```

The executor writes `result.json` following
`schemas/lifecycle-environment-result.schema.json`, plus `raw/` and
`raw.sha256` for any attempted product status. The observation echoes its
exact argv, executor digest, environment identity, requested cell, and exit
status. The execution runs under a Linux child-subreaper supervisor; a timeout
or any descendant still live when the executor exits is terminated and reaped,
then fails the provider contract without publishing an executor result. The
supervisor authenticates its leader and every observed descendant by exact
PID, start time, session, and process-group identity and signals only through
`pidfd`; a platform without those primitives fails closed. Detached `setsid`
descendants remain children of the subreaper and are included. PID reuse or an
identity mismatch is a containment failure and is never resolved by signalling
a saved numeric process group. The driver independently checks the seven-cell
roster, all exact
framework/lifecycle/resource keys, resource arithmetic and trends, the full
digest-to-file index, byte-identical normal/unavailable results, normal-agent
extraction, and diagnostic count/byte caps. It then constructs the provider
envelope itself. A sanitized receipt binds the inner-registry digest, complete
approval object, environment ID/digest, exact safe argv, executable digest,
exit status, and successful containment result. Its digest is a required raw
evidence-index entry. The provider result and public cell retain that typed
inner authority. The outer adapter overwrites outer command/driver identity
with its observed snapshot values, `seal-cell.sh` reapproves the inner identity
and cell permission, and `collect.sh` rejects unapproved or mixed inner
identities before aggregation.

Missing or invalid environment identity, an empty inner registry, or an
unapproved executor is infrastructure `untested`;
the reviewed driver was attempted and remains identified. Once the executor
runs, a missing, malformed, argv-lying, cross-cell, contradictory, unsafe, or
unbounded observation produces a provider-contract `fail`, never `untested`,
`unsupported`, or `pass`. A valid executor-reported `untested` remains
infrastructure-only. No checked-in record materializes any of these statuses.

Each run-cell or collector transaction retains one provider/inner-executor
registry snapshot pair and passes that exact pair, its source identities, and
its snapshot identities through plan validation, selection, sealing, and
collector reapproval; nested consumers do not take an independent snapshot.
The registries are copied through stable regular-file descriptors before
parsing. Their approved-entry rosters are materialized into bounded private
files through already-open descriptors, checked for exact count and byte caps,
and consumed from those same identities. A producer's nonzero status is
propagated unchanged; partial output, source/snapshot/roster substitution, or
an A-to-B-to-A traversal fails validation. Private scratch roots remain open as
directory descriptors, so source/cell/provider/raw descendants are consumed
through the retained root even if an ancestor pathname is replaced and later
restored. Final files use retained-candidate, no-replace publication. Final
directories retain every bounded child directory and regular-file descriptor,
recompute the exact recursive path/type/identity/content manifest immediately
before and after no-replace rename, and reject any roster or byte change.
Temporary roots are
never recursively removed. Cleanup atomically moves the whole entry into a
randomized, mode-0700 retained quarantine and checks the exact
device/inode/owner/type boundary without traversing any leaf. A foreign or late
replacement—including a symlink, special file, reused directory, or post-check
leaf—is preserved and causes failure; no cleanup path applies `rm -rf`,
`unlink`, or `rmdir` to potentially foreign bytes.

The external driver's raw evidence uses safe relative `directory` and
`manifest` names under the cell's private directory. The manifest must list
every regular file in that directory exactly once. Symlinks, hard links,
foreign ownership, group/world-writable files, excess files, or excess bytes
fail sealing.

Public runtime strings are validated by field: deployment proof,
feature-probe kind, and load/attach reasons use the bounded lowercase reason
grammar; kernel and JVM identities use their own grammars; and the official
agent URL is one of two complete pinned Maven URLs. There is no general URL
prefix exception that can smuggle a path or secret through another field.
The top-level reason and every other public runtime/artifact/assertion string
also reject exact secret words case-insensitively when bounded by the start or
end of the string or by any non-alphanumeric character. Longer nonsensitive
words such as `passwordless` and `tokenizer` remain valid.

## Status boundaries

- `untested` is infrastructure-only: a missing driver/tool/platform, an
  architecture/kernel/topology mismatch, missing direct provenance, or a
  provider failure before a product assertion. Runtime, artifact, and
  assertion fields are null. It never implies support or lack of support. An
  approved driver that was actually invoked retains its exact identity;
  pre-execution unavailable/unapproved boundaries retain no identity.
- `unsupported` requires an executed production provider, authoritative
  feature detection reporting unsupported, retained artifact/runtime
  identities, safe no-mutation/no-crash behavior, and a passing exact-parent
  control. Missing infrastructure cannot produce this status.
- `fail` is either a product/application assertion failure with full observed
  identities, or a `provider-contract` failure. A checksum-verified external
  driver that executes but omits/malforms its result or required assertions is
  a retained contract fail, not untested and never unsupported.
- `pass` requires every applicable assertion. A skipped required cell or an
  untested resource gate cannot pass.

## Local Java 21 adapter attestations

The local adapter additionally requires a clean checkout and a provenance JSON
file via `OBI_COMPATIBILITY_KERNEL_PROVENANCE`:

```json
{
  "schema": "compatibility-kernel-provenance-v1",
  "selector": "upstream-6.12",
  "observed_release": "6.12.0",
  "source_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "version_inference": false
}
```

Every local cell also requires `OBI_COMPATIBILITY_TOPOLOGY_ATTESTATION`. It
names the requested topology, sets `runtime_observed: true`, and sets
`process_cgroups_sha256` to the SHA-256 of the exact bytes of
`/proc/self/cgroup` including its final newline. The adapter checks that digest
before snapshotting, again after the bounded run, and against the exact
`/proc/self/cgroup` section retained in `host-topology.txt`. Nested delegation
or sibling topology additionally needs the exact topology-specific boolean.
Before execution, the adapter snapshots both attestation files. After its
bounded process group has terminated, it revalidates the originals and
snapshots and copies the exact snapshots into raw evidence. Kernel provenance
and topology-attestation digests are published separately from the generic
host-topology digest. A missing, changed, deleted, substituted, or
cross-process attestation is never a pass.

The local adapter also parses the command envelopes and semantics before it
publishes runtime identity: `bpftool feature probe` must exit zero and report
exactly one canonical `eBPF program_type cgroup_sockopt is available` row,
with no duplicate, negative, or otherwise contradictory row; the container roster must belong to the
cell-derived Compose project and cross-bind the five required services, PID/
network modes, configured image references, and inspected immutable image
IDs; the four inspected images must resolve the exact pinned/tagged roster;
the Java 21 version command must use the exact ordered global-option roster,
one cell-derived project name, its absolute project directory and matching
`docker-compose.yml`, and the fixed Java service command; and the
host topology, cgroup mounts, BTF, Apache SSL module, OpenSSL paths and package
owners must match their exact contracts. A present file or syntactically valid
digest alone is not authoritative evidence.

The current production `run.sh` evidence proves supported forced selection,
but does not emit the exact-parent/no-mutation/no-crash unsupported control
required by this campaign. The local adapter therefore fails closed rather
than manufacturing an `unsupported` result; adding that retained production
control is an explicit remaining source dependency.

## Source validation

The focused test creates only temporary synthetic fixtures. The production
inner registry stays empty; setup modifies only a clean test-owned repository
copy to approve its synthetic executor for the seven exact cells. Pass-shaped
fixtures exercise sealing but remain only inside a mode-0700 retained test
quarantine and are never published or presented as application execution:

```bash
./examples/apache-java-https/compatibility/tests/campaign_test.sh
```

For the reviewed lifecycle-driver boundary alone:

```bash
OBI_COMPATIBILITY_TEST_SCOPE=lifecycle-driver \
  ./examples/apache-java-https/compatibility/tests/campaign_test.sh
```

For the registry, quarantine, and process-identity boundaries alone:

```bash
OBI_COMPATIBILITY_TEST_SCOPE=authority-boundaries \
  ./examples/apache-java-https/compatibility/tests/campaign_test.sh
```

It covers exact counts, aggregate closure, missing/foreign/duplicate/stale IDs,
public and private cross-cell substitution, cross-provider substitution,
unbound/aliased/duplicate evidence-index entries, topology/provenance changes,
status and forced-selection boundaries, malformed/missing or argv-lying
external results, unapproved and swapped drivers, exact-parent failures,
helper fallback-result/diagnostic/extraction mutations, and claimed passes
containing an untested resource gate. It also mutates tracked and untracked
source after authority capture, provider/command exit codes, integer request/
resource counters, bounded slopes, non-finite numeric encodings, process-group
cleanup, PID/start/session/process-group reuse, delayed session change plus
double-fork containment, registry producer failures/partial rosters/selection
and reapproval ABA, in-place byte/mode ABA, retained quarantine replacement
types, and private-manifest entry types and limits. The lifecycle-driver
scope executes synthetic contracts for all seven exact cells, mutates every
lifecycle and repeated-resource gate, and covers missing or mismatched
environment identity, cell/transport/JDK/architecture mismatch,
path/digest/open-snapshot/argv boundaries, nonblocking FIFO/symlink/regular
pre-open rejection, inner-registry cell permission and
collector reapproval, unavailable-result equivalence, diagnostic caps, leak
deltas and trends, malformed output, setsid and delayed double-fork descendant
containment, and the
prohibition on inferred passes. Focused adapter fixtures
also mutate exact-parent case rosters, `bpftool` semantics, container/project
identity, image resolution, Java runtime/project identity, host `/proc` cgroup
bytes, topology cross-binding, Apache/OpenSSL ownership, and duplicate command
envelopes.
