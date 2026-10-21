# Signed service update releases

The release workflow publishes the existing seven ZIPs and `SHA256SUMS`, plus
`update-manifest.json` and `update-manifest.json.sig`. The four desktop service
targets in the manifest are Windows and Linux on amd64 and arm64. macOS and
Android packages remain in the release but are outside this service updater.

## Reviewed compatibility values

Before tagging, review `release/compatibility.json`: `ipc_min`, `ipc_max`,
`gui_min`, `gui_max_exclusive`, and `profile_format`. GUI 0.1.1 packages and
their updater tests were reviewed with IPC 1 and profile format 1. The reviewed
GUI range is `>=0.1.0, <0.1.2`; `gui_reviewed` is `true` for this release
candidate. A live installed-service update remains a post-publication check.
Release CI and backfill uploads refuse to publish if the review flag is `false`.
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

The release job requires `BIMERON_RELEASE_ED25519_KEY`, a GitHub Actions secret
containing standard base64 of the 64-byte Ed25519 private key. Generate and store
it outside the repository. Export the matching 32-byte public key to the GUI's
trusted key set and to the GitHub Actions variable
`BIMERON_RELEASE_ED25519_PUBLIC_KEY` as standard base64. The signing step
checks that the two keys match; the verification step uses only the public key.
A key ID alone does not establish trust. The workflow fails if
the secret is missing or signing/verification fails. Restrict who can edit release
workflow files and who can manage that secret; protect release tags with GitHub
rulesets. To rotate, first release GUI trusting both keys, then switch the secret,
then retire the old key after the supported update window.

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
Updating never reconnects VPN automatically.

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
