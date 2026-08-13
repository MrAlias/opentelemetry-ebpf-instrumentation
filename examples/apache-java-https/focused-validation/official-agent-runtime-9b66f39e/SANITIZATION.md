# Official-agent runtime sanitization

This directory is a derived, reviewer-facing summary of four GitHub Actions
artifacts from the exact workflow run and source revision recorded in
`run-identity.json`. The raw archives were downloaded into a private mode-0700
temporary directory. Their byte sizes and SHA-256 values were checked against
GitHub's artifact metadata before their contents were inspected. No raw file is
copied into this directory.

## Retained transformations

- `run-identity.json` allowlists the public repository, workflow, run, source
  revision, run attempt, terminal result, four artifact names, archive sizes,
  and GitHub-reported archive digests.
- The same file retains both official Maven artifact coordinates, versions,
  and SHA-256 pins. The metadata was identical in all four CI artifacts, the
  runtime tests compared the downloaded JAR bytes with those pins, and a
  separate Maven re-download reproduced both digests.
- `matrix-summary.json` converts the four property files, JVM version files,
  and sixteen JUnit XML suites into exact stable counts and the versioned
  agent/JVM/application-server matrix. It retains only `Linux`, GitHub's `X64`
  runner label, the `x86_64` uname machine, and allowlisted Temurin versions.
- Expected JUnit skips retain stable reasons and counts, not stack traces.
- `verify.sh` requires the exact regular-file manifest, rejects symlinked or
  noncanonical/duplicate-key JSON evidence, validates the exact claim-bearing
  schema and values, and binds every matrix cell to its raw archive metadata.
- `SHA256SUMS` hashes the five sanitized sibling files and does not hash
  itself.

## Omitted raw material

The summary omits the raw ZIP archives, Gradle binary results, JUnit XML,
system output, console logs, Java-agent and extension JARs, full Java and uname
output, hostnames, runner names, kernel versions and build strings, timestamps,
numeric job and artifact identifiers, temporary and checkout paths, process and
thread identifiers, stack traces, trace and span identifiers, payloads, and
other operational strings. The public workflow run ID and run-derived artifact
names are deliberate provenance exceptions.

The raw official-agent artifacts are stock-agent CI evidence. They are not a
privileged Apache-to-Java Compose run, do not add a privileged matrix cell, and
do not establish `arm64`, the broader issue #23 helper lifecycle matrix, or the
broader issue #38 environment matrix. Existing Java 21 privileged Compose
evidence remains separately retained under `evidence/`.

The checksum manifest provides integrity for this sanitized record when read
from a separately trusted checkout. The workflow URL and GitHub archive
digests bind the summary to its public raw provenance but do not make the raw
archives part of Git.
