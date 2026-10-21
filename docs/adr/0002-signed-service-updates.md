# ADR 0002: Signed manifests and service update health checks

Status: amended, October 21, 2026.

## Context

The public release contains architecture-specific ZIP files and SHA256SUMS, but no authenticated compatibility policy. SemVer cannot state IPC, GUI, or profile compatibility. A process that reaches SCM/systemd's running state may still expose an unusable IPC endpoint. The GUI and installed service run across a privilege boundary.

## Decision

Publish a JSON manifest and detached Ed25519 signature. Sign the exact UTF-8 file bytes, including its final newline. The manifest includes a key identifier derived from the public key's SHA-256 and archive hashes computed after ZIP creation. Compatibility values live in `release/compatibility.json` and require review on every release. The GUI pins public keys and checks the signature, compatibility, ZIP size and hash. It elevates a trusted core bundled in its installed, administrator-owned package and passes the downloaded executable's path, SHA-256, and expected version as arguments. The privileged updater copies the untrusted file as data into the protected directory, checks staged SHA-256, Go identity, and architecture before stopping the service, then requires IPC `hello` with the expected version and protocol after restart. It never elevates a downloaded executable before checking it. Existing old services can be updated only after the GUI package bundles this new updater.

Rotate keys by shipping a GUI version that trusts both old and new public keys before changing the release signing key. Later remove the old public key after its supported release window. Old GUI versions must update before they can trust releases signed only by the successor key. A compromised signing key still requires a separate incident response and GUI trust-store release; rotation alone does not revoke an already installed trust anchor.

Backfill downloads and verifies existing archives, generates only metadata assets, and defaults to dry-run. Existing archives and SHA256SUMS stay byte-for-byte unchanged.

## Alternatives and tradeoffs

- GitHub asset digests alone depend on GitHub as the sole trust root and do not authenticate the compatibility policy outside its API. Ed25519 lets the GUI verify downloaded metadata independently.
- An embedded signing key in the core would make rotation depend on core updates and would put the trust decision inside a privileged executable. The GUI owns update selection and a pinned public key; the private key stays in GitHub Actions secrets.
- Automatically reconnecting VPN after update would need persistent secrets and recovery of session intent. Explicit reconnection preserves current service behavior.
- A stopped service cannot answer IPC without changing its prior state. It stays stopped; executable identity and staged digest are checked before replacement, and the first later start is user initiated.
- Elevating the downloaded executable would allow a same-user file swap between the GUI's verification and process launch. Elevating the bundled updater avoids this race, but requires the GUI package directory to be protected against ordinary-user writes. Portable or user-writable GUI installations must disable this update route.
