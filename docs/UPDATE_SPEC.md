# Signed desktop service updates: specification and acceptance criteria

Status: design baseline, recorded before implementation. Applies to Windows and Linux amd64/arm64 releases.

## Current contract

The release job builds seven ZIP assets and SHA256SUMS. Desktop ZIPs contain one CLI/service executable, licenses, and, on Windows, Wintun and its license. The core version comes from the tag through `BIMERON_VERSION`; IPC protocol is currently 1. `hello` returns protocol version, core build details, and capabilities. Profile format is `.conf`. `service update` runs with Administrator/root privileges, copies its own executable into the protected installation directory, stops the service, swaps executable and backup, then restarts only if previously running. It currently treats process startup as success. Owner and boot settings remain in SCM/systemd; VPN does not reconnect.

## Release metadata

Each release has `update-manifest.json` and `update-manifest.json.sig` in addition to the existing assets. The manifest carries a schema version, tag-derived core version and stable/beta channel, explicit IPC and GUI compatibility bounds, profile format revision, and four target records (Windows/Linux, amd64/arm64). Each target has its existing ZIP asset name, exact byte size, and lowercase SHA-256 derived from the finished ZIP. Compatibility bounds are maintained in a reviewed repository file, not inferred from SemVer. The initial GUI range is provisional and publication requires an explicit review flag. Generation fails for missing or unexpected target archives.

The signature is Ed25519 over the exact UTF-8 bytes of `update-manifest.json`, including its terminal newline. The detached signature asset contains base64 of the 64-byte signature followed by one newline. Verifiers reject unknown schema, unknown signing key, malformed signature, duplicate targets, unsafe asset names, or digest/size mismatch. The manifest names its key ID. A GUI pins trusted public keys in its own release, adds a successor key while retaining the prior key, then the publisher switches to the successor; removal of the old key follows after old releases leave the supported update window. The private key is stored outside this repository. Local verification uses the public key only.

## Selection and installation

GUI fetches release metadata from the public `bimeron/bimeron-core` repository, verifies the manifest before trusting any fields, checks channel, OS/architecture, installed IPC protocol, GUI version and profile format, then downloads the selected ZIP and checks its size and SHA-256. It extracts the executable to a private temporary location. At the privilege boundary, `service update` verifies the expected digest of the executable again after copying it into the protected installation directory; it must reject a mismatch before stopping the old service. Privileged code must not trust a path or a previously checked unprivileged file alone.

For a running service, success requires an IPC `hello` response from the service endpoint, with matching expected core version and protocol, within a bounded deadline. A started process alone is insufficient. On failure, stop the new service, restore the old executable, and restore the prior running state. If the service was stopped, preserve that state and check the staged executable before replacement; the next start remains explicit. Owner, boot/recovery settings, and disconnected VPN state must be preserved. A failed rollback keeps the backup and reports its location.

## Backfill

An operator command reads each existing release's original ZIPs and SHA256SUMS, builds and signs only the two new metadata assets, and compares them against existing assets. Dry-run is the default. Identical existing metadata is a no-op; divergent metadata is an error. Upload requires a separate explicit flag and authorization. Existing ZIPs and SHA256SUMS are never uploaded, replaced, or deleted.

## Acceptance criteria

1. Release CI builds all existing packages, hashes completed ZIPs, creates and verifies the signed manifest, and fails before publication if signing or verification fails.
2. Tests cover deterministic manifest bytes, tag/channel parsing, compatibility configuration, missing/duplicate archives, signature tampering, and key rotation verification.
3. Tests cover IPC version mismatch, wrong core version, unreachable service, successful update, and rollback to both prior running and stopped states.
4. Service update rechecks staged executable identity and digest under elevation before stopping the old service. Existing owner and startup configuration is unchanged; VPN remains disconnected.
5. Backfill dry-run inspects real release assets without writing to GitHub; repeat execution is idempotent. Upload cannot replace existing ZIPs or SHA256SUMS.
6. `go test ./...`, Windows and Linux amd64/arm64 builds, and distribution checks pass in CI or any failure is diagnosed and reported.
