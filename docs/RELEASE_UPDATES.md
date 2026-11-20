# Signed service update releases

The prepared release contains the existing seven ZIPs and `SHA256SUMS`, plus
`update-manifest.json` and `update-manifest.json.sig`. The four desktop service
targets in the manifest are Windows and Linux on amd64 and arm64. macOS and
Android packages remain in the release but are outside this service updater.

## Reviewed compatibility values

Before tagging, review `release/compatibility.json`: `ipc_min`, `ipc_max`,
`gui_min`, `gui_max_exclusive`, and `profile_format`. The current file allows GUI
`[0.3.1, 0.3.3)` with IPC 1 and profile format 1, and sets `gui_reviewed` to
`true`. For the stable v0.4.0 release, Desktop 0.3.1 and the 0.3.2 release branch pin the hardware keys and accept IPC 1 and profile format 1. The added Core capabilities extend the existing JSON object. For `v0.4.0-beta.2`, Desktop reviewed `[0.3.0, 0.3.2)`: Desktop 0.3.0 accepts
the release as a service update, and Desktop 0.3.1 bundles it. `v0.4.0-beta.1`
supports GUI `[0.3.0, 0.3.1)`.

Earlier reviews, for reference: published `v0.1.0-beta.4` supports GUI
`[0.1.0, 0.1.3)`. For `v0.1.0-beta.5`, GUI 0.1.5 was reviewed
with IPC 1 and profile format 1; the range is `[0.1.5, 0.1.6)` and
`gui_reviewed` is `true`. The Windows amd64 VM verified the GUI package upgrade,
an existing VPN connection, the trusted `service update -source` helper,
IPC health after update, profile validation and reconnection through the Core CLI, and rejection of
a wrong digest before service stop. The GUI's signed release discovery and
installation of `beta.5` remains a post-publication check.
The prepared-release publisher refuses to publish if the review flag is `false`.
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

[RELEASE_KEYS.md](RELEASE_KEYS.md) lists the pinned public keys and which
releases each one signs. Releases after `v0.4.0-beta.2` are signed with a
hardware key held in a YubiKey's OpenPGP application. On Windows, with the
YubiKey connected by USB, run the signing step with the card serial and its
pinned public key:

```powershell
$env:BIMERON_RELEASE_CARD_SERIAL = "22337246"
$env:BIMERON_RELEASE_ED25519_PUBLIC_KEY = "lRcnhdj4yU4TrinOa4U177FG7wrwUPv/v9zxA/WiJMI="
./scripts/release-go.ps1 run scripts/release-manifest.go -tag <tag> -dir <release-dir>
```

The signer checks that the card holds exactly the configured public key before
it asks for the card's OpenPGP PIN, then asks for a touch, and verifies the
returned signature before writing it. It needs a real console: run it in
PowerShell or cmd, not Git Bash's mintty. Use the
backup key B (`19344964`, see RELEASE_KEYS.md) only when key A is unavailable.
Every signer refuses a manifest larger than 2560 bytes, below the YubiKey's
3070-byte signature input limit; a test keeps the current manifest well under
that bound.

Without `BIMERON_RELEASE_CARD_SERIAL`, the signing step reads
`BIMERON_RELEASE_ED25519_KEY`, standard base64 of the 64-byte software private
key, and checks it against `BIMERON_RELEASE_ED25519_PUBLIC_KEY` when set. Only
tests use this path, with an unpinned key: it refuses every pinned key, and the
retired software key `7370a2d8cf890e5e` only verifies. The publisher verifies
using only the public key. A key ID alone does not establish trust. Protect release tags with
GitHub rulesets.

Signing and `-verify` (also used by the prepared-release publisher) accept a key
only for its release range, so a release that Desktop or Core repair would
reject cannot be published: `7370a2d8cf890e5e` only to verify
the published releases up to `v0.4.0-beta.2`, the hardware keys for every new
tag, which must sort after `v0.4.0-beta.2`. The release scripts refuse to run
while the test-only `BIMERON_RELEASE_TEST_UNPINNED_KEY` is set. A hardware-signed
manifest must set `gui_min` to at least `0.3.1`.

To rotate, first release a GUI trusting both keys, then switch the signer, then
retire the old key after the supported update window. Desktop 0.3.0 and earlier
pin only `7370a2d8cf890e5e`: they cannot verify a release signed by a hardware
key. Desktop 0.3.1 is planned to pin all three keys; publish the first
hardware-signed Core release only after Desktop 0.3.1 is released, with
`gui_min` of at least `0.3.1`.

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

If the release changes the Go minor version, the GeoSite regex estimator or its
limits, or the GeoSite dataset a GUI bundles or recommends, re-measure the regex
budgets as described in [GEODATA.MD](GEODATA.MD#regex-budgets) before tagging
and update the recorded figures.

## Publish prepared bytes

The tag CI builds and tests distributions but never creates a release. Build
the seven ZIPs once from a clean commit and name them
`bimeron-<tag>-<target>.zip`, where `<target>` is `android`, `linux-amd64`,
`linux-arm64`, `macos-amd64`, `macos-arm64`, `windows-amd64`, or `windows-arm64`.
Each desktop ZIP holds its `dist/` directory, so the executable is at
`<target>/bimeron` (`<target>/bimeron.exe` on Windows). Calculate `SHA256SUMS`
over those exact files, then generate and verify the signed manifest from the
completed ZIPs. The Android build is separate from `build-dist.go`. The
publisher requires a clean source checkout. Keep all ten assets in one
directory and do not change them after signing. With the matching public key in
the environment, run the default dry-run:

```sh
scripts/publish-prepared-release.sh v0.1.0-beta.3 /absolute/path/to/release
```

The command checks the exact asset set, all seven ZIP checksums and ZIP
structure, build provenance, signed manifest, archive sizes, and compatibility
policy. `scripts/check-release-provenance.go` reads the Go build information of
every packaged binary. Each CLI executable must record the release commit as
`vcs.revision`, `vcs.modified=false`, `-trimpath`, `CGO_ENABLED=0`, the GOOS and
GOARCH of its ZIP and the default architecture level, with no other build
settings such as `-tags`, `-gcflags` or `GOEXPERIMENT`, and its executable
format must match the target. The Android ZIP must hold
`android/bimeron-core.aar`, whose `libgojni.so` for each of the four ABIs must
be a `-trimpath` gomobile build for that ABI without extra settings, built from
the fixed source path of `scripts/build-android.sh` or a drive root
(`scripts/build-android.ps1`); see [BUILDING.md](BUILDING.md#android-aar).
gomobile builds from a generated module, so Go records no revision for the
libraries. The allow-list is strict on purpose: if a new Go release records a
new default setting, the gate refuses the build until the list is reviewed.

Go does not record every build input. With `-trimpath` it omits `-ldflags`, so
the embedded Core version is not checked, and options such as `-toolexec`,
`-overlay` or `-modfile` leave no trace. Build and publish with empty
`GOFLAGS` and `GOEXPERIMENT`, including values saved with `go env -w`. The release
launchers, Android builds and publisher require a successful lookup before running
Go release tools. CI uses the same launchers.

After approval, push the reviewed commit and its tag, wait for successful tag CI, and run the same command with `--publish`. It
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

Pass the extracted file itself. The updater refuses a file larger than 256 MiB
and a symbolic link or junction as the final path component. On Windows the
source must be a plain drive-letter path (`C:\...`) on a fixed local drive:
UNC, device and `\\?\` paths are refused, and so is an opened file that
resolves to a network share or to a volume that is not a fixed drive, for
example through a linked directory or a removable volume mounted in a folder.
The drive type is the one the volume reports, so a RAM disk is refused only
if it reports `DRIVE_RAMDISK`; one that reports a fixed drive is accepted. A
volume without a volume GUID path is refused. AF_UNIX sockets and WSL FIFOs
and device files are refused. Other reparse
points, such as cloud-file placeholders, are read as data. Extract to a local
directory whose path contains no links: content that is not available locally
may fail to read or be fetched on access, the staged digest check rejects any
mismatch, and opening a file through a directory linked to a network share
contacts that server before the updater refuses it.

The bundled updater must be in a directory ordinary users cannot write. A
portable GUI or a custom installation in a user-writable directory cannot safely
elevate its adjacent core executable for this operation. The elevated updater
opens the downloaded file only as data, copies it into the protected service
directory as a file only administrators or root can read, then checks the
staged digest, Go identity, and architecture before stopping the old service.
A staged copy left by an interrupted update is replaced. The updater never
executes downloaded bytes before those checks.
A running replacement must answer
IPC `hello` with the expected core version and protocol. Failure triggers rollback
and restoration of the prior running state. A stopped service stays stopped.
A failed or unconfirmed stop also restarts a previously running service with the
original executable before reporting the error. A service that has not started
since boot (`ERROR_SERVICE_NEVER_STARTED`) counts as cleanly stopped.
The core updater itself does not reconnect VPN. After a successful update,
GUI 0.1.2 verifies the new service through IPC and reconnects the same profile
if a VPN connection was active before the update. It does not reconnect after
failure or rollback, or if the profile was removed.

An already installed older service does not need to understand this new command:
the trusted updater is the new core bundled by an updated GUI package. If that
package still bundles a core without `-source`, update the GUI package first;
do not elevate a downloaded release executable as a bootstrap shortcut.


## Existing releases without metadata

`v0.1.0-beta.1` and `v0.1.0-beta.2` have no update manifest and stay that way.
Metadata is never signed afterwards from the assets of a published release: those
assets cannot prove which commit built them. Every later release carries the
manifest that was signed before publication.
