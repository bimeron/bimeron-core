# ADR 0003: Publish prepared release bytes

Status: accepted, October 22, 2026.

## Context

The previous tag workflow rebuilt ZIP archives immediately before publishing.
Their hashes could differ from a locally reviewed GUI update candidate because
the binaries embed the commit revision and ZIP metadata can vary between builds.
The GUI needs final archive hashes from a signed manifest, and operators need
to review those exact assets before publication.

## Decision

Tag CI continues to run tests and distribution builds but does not publish a
release. An operator builds the complete release directory from one clean
commit, signs the manifest after all seven ZIPs and SHA256SUMS exist, and runs
the prepared-release command in dry-run mode. After explicit approval, the
operator pushes the commit and tag, waits for successful tag CI, then invokes
the command with `--publish`. It checks the signed manifest and local assets,
uploads those same bytes to a draft release, compares GitHub's asset digests
and sizes, and only then publishes the draft. No existing release assets are
replaced. The private signing key stays outside the repository; publication
requires only the pinned public key.

## Tradeoffs

- The reviewed ZIP hashes remain valid through publication because the
  publisher does not rebuild or repackage them.
- Release preparation is an explicit operator step and must preserve the
  prepared directory until publication. A lost or changed directory requires
  a new review and signature.
- CI validates the tagged source and its distributions independently, but
  does not itself produce the published byte stream. The local signature,
  checksum, executable revision, and remote digest checks bind publication
  to the reviewed files. A future artifact-promotion workflow could move this
  preparation into CI without changing the manifest format.
