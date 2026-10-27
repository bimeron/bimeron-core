# Signed service update releases

The prepared release contains the existing seven ZIPs and `SHA256SUMS`, plus
`update-manifest.json` and `update-manifest.json.sig`. The four desktop service
targets in the manifest are Windows and Linux on amd64 and arm64. macOS and
Android packages remain in the release but are outside this service updater.

## Reviewed compatibility values

Before tagging, review `release/compatibility.json`: `ipc_min`, `ipc_max`,
`gui_min`, `gui_max_exclusive`, and `profile_format`. Published `v0.1.0-beta.4`
supports GUI `[0.1.0, 0.1.3)`. For `v0.1.0-beta.5`, GUI 0.1.5 was reviewed
with IPC 1 and profile format 1; the range is `[0.1.5, 0.1.6)` and
`gui_reviewed` is `true`. The Windows amd64 VM verified the GUI package upgrade,
an existing VPN connection, the trusted `service update -source` helper,
IPC health after update, profile validation and reconnection through the Core CLI, and rejection of
a wrong digest before service stop. The GUI's signed release discovery and
installation of `beta.5` remains a post-publication check.
The prepared-release publisher and backfill uploads refuse to publish if the review flag is `false`.
These are explicit product
rules; do not derive them from SemVer. `schema` is the manifest format revision.
The tag supplies `core_version` and stable/beta channel. File names, sizes, and
SHA-256 values come from completed ZIPs. A tag with a prerelease suffix uses
the beta channel. The manifest contains a `key_id` equal to the first eight
bytes of SHA-256 of the Ed25519 public key, rendered as 16 lowercase hex digits.

The signed bytes are the exact UTF-8 contents of `update-manifest.json`, including
the final LF. `update-manifest.json.sig` is standard base64 of a 64-byte Ed25519
signature followed by one LF. A consumer must verify the signature against a
pinned public key selected by `key_id` before using any manifest values.
It must reject unknown schema, missing or duplicate targets, unsafe asset names,
unsupported compatibility, or a mismatch of downloaded ZIP size or SHA-256.

Generate the Ed25519 key outside the repository. The local signing step reads
`BIMERON_RELEASE_ED25519_KEY`, standard base64 of the 64-byte private key, and
checks it against `BIMERON_RELEASE_ED25519_PUBLIC_KEY`, standard base64 of the
32-byte public key pinned by the GUI. Keep the private key in a protected vault
with an offline backup; do not commit it or place it in shell history or logs.
The publisher verifies using only the public key. A key ID alone does not
establish trust. Protect release tags with GitHub rulesets. To rotate, first
release GUI trusting both keys, then switch the signer, then retire the old key
after the supported update window.

## Documentation for each version

The README and linked guides describe the source revision that contains them.
Update protocol support, platform status, configuration examples, and requirements
alongside the corresponding implementation changes, before creating a release tag.
The default branch can be ahead of a release; do not maintain a second feature
matrix for the latest release in its README.

Before tagging, check the quick start against the release candidate and review
the README and linked guides at that exact commit. The prepared-release publisher
adds a link to `README.md` at the release tag to the release notes. Keep that
version-specific link when editing the notes; it also gives readers the matching
configuration and integration guides. For older releases without the link, open
the release tag in GitHub and navigate to `README.md`.

## Publish prepared bytes

The tag CI builds and tests distributions but never creates a release. Build
the seven ZIPs once from a clean commit, calculate `SHA256SUMS` over those exact
files, then generate and verify the signed manifest from the completed ZIPs.
The Android build is separate from `build-dist.go`. Keep all ten assets in one
directory and do not change them after signing. With the matching public key in
the environment, run the default dry-run:

```sh
scripts/publish-prepared-release.sh v0.1.0-beta.3 /absolute/path/to/release
```

The command checks the exact asset set, all seven ZIP checksums and ZIP
structure, executable build revisions, signed manifest, archive sizes, and
compatibility policy. After approval, push the reviewed commit and its tag,
wait for successful tag CI, and run the same command with `--publish`. It
requires both local and remote tags to point to the prepared commit. It creates
a draft release, uploads the prepared files without rebuilding, compares every
remote asset's size and SHA-256 with the local file, and publishes the draft
only if all ten match. An existing release is never overwritten. If upload
verification fails, the release stays a draft for investigation.

## GUI selection and installation

List public releases from `bimeron/bimeron-core`. For each candidate, download
both metadata assets, verify the signature using the GUI's pinned public keys,
then check channel, OS/architecture, installed IPC protocol, GUI version, and
profile format. Reject `gui_reviewed: false` or null GUI bounds, which mark a
local preview without an available GUI updater.
Select a suitable version under the GUI's update policy.
Download its named ZIP and verify the exact size and SHA-256. Extract only the
expected `<os>-<arch>/bimeron[.exe]` entry to a private temporary directory;
reject duplicate entries and paths that escape that directory. Compute the
executable SHA-256. Elevate only the core executable bundled in an installed,
administrator-owned GUI package, and pass it the downloaded file as data:

```text
<trusted-bundled-core> service update -source <absolute-downloaded-executable-path> -version <core_version> -sha256 <executable-sha256>
```

The bundled updater must be in a directory ordinary users cannot write. A
portable GUI or a custom installation in a user-writable directory cannot safely
elevate its adjacent core executable for this operation. The elevated updater
opens the downloaded file only as data, copies it into the protected service
directory, then checks the staged digest, Go identity, and architecture before
stopping the old service. It never executes downloaded bytes before those checks.
A running replacement must answer
IPC `hello` with the expected core version and protocol. Failure triggers rollback
and restoration of the prior running state. A stopped service stays stopped.
The core updater itself does not reconnect VPN. After a successful update,
GUI 0.1.2 verifies the new service through IPC and reconnects the same profile
if a VPN connection was active before the update. It does not reconnect after
failure or rollback, or if the profile was removed.

An already installed older service does not need to understand this new command:
the trusted updater is the new core bundled by an updated GUI package. If that
package still bundles a core without `-source`, update the GUI package first;
do not elevate a downloaded release executable as a bootstrap shortcut.

## Backfill existing releases

With `gh` authenticated and both `BIMERON_RELEASE_ED25519_KEY` and
`BIMERON_RELEASE_ED25519_PUBLIC_KEY` in the environment, run:

```sh
scripts/backfill-update-manifest.sh v0.1.0-beta.2
```

The command downloads existing ZIPs and SHA256SUMS, verifies checksums, builds
and checks metadata locally, and reports what it would add. Repeat runs compare
existing metadata byte-for-byte. The `--upload` flag uploads only the two missing
metadata assets; obtain project approval before using it. It never replaces ZIPs
or SHA256SUMS. A partial or divergent existing metadata pair is an error.

The GUI must not accept backfilled metadata until the signing public key is pinned
in a released GUI. Keep the private key out of shell history and logs.
