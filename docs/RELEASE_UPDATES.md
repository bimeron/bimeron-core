# Signed service update releases

The release workflow publishes the existing seven ZIPs and `SHA256SUMS`, plus
`update-manifest.json` and `update-manifest.json.sig`. The four desktop service
targets in the manifest are Windows and Linux on amd64 and arm64. macOS and
Android packages remain in the release but are outside this service updater.

## Reviewed compatibility values

Before tagging, review `release/compatibility.json`: `ipc_min`, `ipc_max`,
`gui_min`, `gui_max_exclusive`, and `profile_format`. These are explicit product
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
profile format. Select a suitable version under the GUI's update policy.
Download its named ZIP and verify the exact size and SHA-256. Extract only the
expected `<os>-<arch>/bimeron[.exe]` entry to a private temporary directory;
reject duplicate entries and paths that escape that directory. Compute the
executable SHA-256. Pass that
digest and `core_version` to elevated `service update`:

```text
bimeron service update -version <core_version> -sha256 <executable-sha256>
```

The elevated updater copies the binary into its protected installation directory,
rechecks the digest, then changes the service. A running replacement must answer
IPC `hello` with the expected core version and protocol. Failure triggers rollback
and restoration of the prior running state. A stopped service stays stopped.
Updating never reconnects VPN automatically.

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
