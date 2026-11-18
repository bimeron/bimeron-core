# ADR 0039: Signed versioned core store and anti-rollback floor

Status: proposed draft, revision 3, November 18, 2026. Not accepted. This
record authorizes no implementation. It amends
[ADR 0002](0002-signed-service-updates.md) and the explicit-repair
replacement policy of #140 in [REPAIR_SESSION.md](../REPAIR_SESSION.md).
Tracked by Core issue #155 and bimeron/bimeron-desktop#58.

## Context

On Windows and Linux, Core is a single Go executable (`bimeron[.exe]`) that
serves as CLI, service and repair broker. Desktop packages carry two copies of
it:

- the CLI, at `C:\Program Files\Bimeron\bimeron-core.exe` or
  `/usr/bin/bimeron-core`;
- the repair broker, at `...\Bimeron\repair\bimeron-repair.exe` or
  `/usr/libexec/bimeron/repair/bimeron-repair`.

The service runs a third copy from `%ProgramFiles%\Bimeron Core\bimeron.exe`
or `/usr/local/lib/bimeron/bimeron-core`. The foreground IKEv2 daemon is a
fourth elevated use of the same binary.

A signed core update (ADR 0002) replaces only the service copy. Desktop
verifies the manifest, then elevates its bundled CLI with
`service update -source <path> -version <v> -sha256 <hex>`. Under the ADR 0002
design, Desktop decides publisher authenticity and version selection and passes
the results to the elevated command as arguments. The bundled CLI and broker
stay at the package version.

Explicit repair (#140) compares the installed service's SHA-256 with the
broker's own running image and replaces a byte-different service with the
broker image. After a signed update, the service is byte-different by
construction, so repair returns it to the package version. Missing-service
installation also installs the broker's version.

Core updates can carry security fixes, so returning to an older version can
reintroduce a fixed problem. The package installer action that updates the
service from the package raises the same ordering question. No component
records the highest version or security floor that a machine has trusted.

This design moves the trust decision for everything that runs or is installed
with elevation into the privileged Core process. It applies one set of rules
to every privileged operation on the new store:

- Untrusted bytes:
  - signature verification over the exact bytes before any parsing;
  - fixed size bounds;
  - no privileged process opens a path that a caller chose.
- Files the privileged process writes:
  - private staging;
  - atomic publication under versioned names;
  - final permissions applied only after verification;
  - an explicit owner and a protected DACL on every created object;
  - ancestor checks.
- Contention:
  - locks that non-administrators cannot create, pre-create or open;
  - tolerance of foreign open handles: no fixed file names that a busy file
    can block, garbage collection, and failures reported visibly.
- Running:
  - installation from a verified handle or store entry, never by re-resolving
    a path;
  - a restricted DLL search, and companion DLLs verified by digest at load;
  - a sanitized environment.
- Release artifacts:
  - canonical, strictly decoded metadata;
  - signed artifacts provably bound to the tag commit and its reviewed build
    settings.

Security is the primary goal; implementation complexity is secondary.

## Decision

### Summary

1. A core update streams a complete signed bundle into the privileged Core
   process over an authenticated session. Core verifies the bundle, switches
   the service to it, and only then promotes it into an immutable, versioned,
   machine-protected **core store**.
2. Signature verification, version order and the anti-rollback **security
   floor** are enforced inside the privileged process, using keys embedded in
   Core. Desktop repeats the checks as defense in depth, never as the only
   gate.
3. Desktop runs the CLI and the repair broker from the newest committed store
   version that it supports. Bundled package copies are bootstrap material
   only.
4. Every launch of a Core executable is bound to a verified file. Elevation is
   never requested for an unverified file.
5. Repair restores from the store, never from its own image. It never lowers
   the installed version or goes below the floor.
6. The first store-era switch re-registers the service, so that pre-store
   tools refuse to manage it instead of rolling it back.
7. A security floor never blocks VPN connectivity through the installed
   service. It blocks installing and elevating below-floor code.

### Terms

- **Core version**: a string in exactly one grammar, `X.Y.Z` or
  `X.Y.Z-beta.N`, with no leading zeros, lowercase only and no build metadata
  (the grammar `repair_acquire.go` already enforces). Ordering is SemVer 2.0
  precedence. The publisher refuses any other tag. Go and C++ share one
  test-vector file (`release/testdata/version-order.json`) that includes
  rejected forms. Store directory names must byte-equal the canonical string,
  so NTFS case collisions cannot occur. Version order is used only for the
  "never below active" rule and for update selection.
- **Security level** (proposed, pending confirmation): a non-negative integer
  that every release carries in its signed manifest and embedded
  `compatibility.json`. It is shared by the stable and beta channels. The
  publisher refuses a release whose level is lower than the level of any
  earlier published release. A release that fixes a security problem raises
  the level when the fix must never be undone. Integers avoid any version
  grammar or channel ambiguity in floor decisions.
- **Security floor**: the minimum security level allowed for installation,
  switching or use as a repair source. Each manifest states it as
  `min_security_level`, which is at most its own `security_level`. It is a
  publisher statement, never user input or local inference.
- **Elevation floor**: the minimum security level allowed to run elevated in
  any role, including as the installer of a newer release
  (`min_elevation_level`). It is normally at or below the security floor, and
  is raised when updater or broker code itself is affected.
- **Floor epoch**: an integer that is normally 0. Only a release with the
  stronger signature policy (see Trust and keys) can raise it. Floors from a
  lower epoch are ignored; this is the only way floors can go down, and it
  exists for key-compromise recovery.
- **Committed version**: a store version that passed a service switch with
  readiness on this machine, or that repair republished for the committed
  target. Only committed versions live in `versions/`.
- **Active version**: the version the service was last switched to and
  committed.
- **Usable version** (Desktop selection): a committed version whose signed
  manifest and members verify, whose level meets the effective security
  floor, and whose signed GUI range includes the running Desktop.

### Store location and protection

Windows (decided): `%ProgramFiles%\Bimeron Core\store\`, a Core-owned
directory beside the service that MSI does not own. The alternative,
`%ProgramData%\Bimeron\core\`, was rejected for two reasons:

- Its default DACL lets `Users` create subdirectories, and `CREATOR OWNER` then
  gives the creator full control, so the directory can be squatted.
- Default AppLocker/SRP executable rules let standard users run binaries only
  from `%ProgramFiles%` and `%WINDIR%`. Every Desktop CLI launch would then be
  blocked on machines that enforce such rules.

Under Program Files, any unexpected pre-existing object under the store root is
an error, because only administrators could have created it. No rename-aside
or adoption logic is needed.

Linux (decided): `/usr/local/lib/bimeron/store/`. It shares the service's trust domain, and it
avoids `noexec` mounts of `/var` and `var_lib_t` SELinux labeling. Pre-store
`service uninstall` removes `/usr/local/lib/bimeron` only if it is empty, so the
store survives. `/var/lib/bimeron/core/` was rejected because of `noexec` and MAC-policy
risk.

```text
<root>/
  versions/<version>/          committed, immutable
    bimeron[.exe]
    wintun.dll, WINTUN-LICENSE.txt          (Windows)
    LICENSE, THIRD_PARTY_NOTICES.txt
    update-manifest.json                    exact signed bytes
    update-manifest.json.sig
  staging/<random>/            privileged only
  trash/<random>/              privileged only, pending deletion
  state/                       privileged only
    floor-<seq>.json           append-only floor evidence
    active-<seq>.json          append-only active records
    lock                       store lock
```

**Permissions**

- **Windows.** Every directory gets its own protected DACL (no inheritance
  from the parent). The owner is `SYSTEM`; `SYSTEM` and `Administrators` have
  full control. `Users` get read and execute only on `versions/` and its
  contents, never on `staging/`, `trash/` or `state/`. The inheritable
  read-and-execute ACE for `Users` on `versions/` must not flow into the other
  directories.
- **Service directory files.** In store-capable builds, the service-directory
  files (`bimeron.exe`, `wintun.dll`) also get a DACL for `SYSTEM` and
  `Administrators` only. An ordinary user then cannot open them at all, so a
  sharing-mode handle cannot block a switch.
- **Directory protection** must reapply the store root's protected DACL by
  handle, never reapply a parent descriptor by path.
- **Linux.** Everything is owned by root. `versions/` is 0755 (members 0755
  or 0644); `staging/`, `trash/` and `state/` are 0700, and `lock` is 0600.
- **Floor and active copies for Desktop.** Desktop cannot read `state/`. It
  reads a SYSTEM-written copy of the latest floor evidence and active record:
  a protected HKLM value under `SOFTWARE\Bimeron\Core` on Windows, and
  `/etc/bimeron/core-state.json` (root-owned, 0644) on Linux. Registry values
  have no sharing modes, so a reader cannot block a writer. This copy is also
  the second location of the floor evidence, and the effective floor is the
  maximum of both locations.

**Opening and creating store objects**

- Every privileged open walks from a held root handle and refuses reparse
  points or symlinks on every component.
  - Windows: `NtCreateFile` with a `RootDirectory` handle and
    `FILE_OPEN_REPARSE_POINT`, with each opened component checked through
    `FileAttributeTagInfo`.
  - Linux: `openat2` with
    `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV`,
    falling back to per-component `O_NOFOLLOW` walks on kernels without
    `openat2`.
- Creation is relative to a held parent handle with create-new semantics.
  - Windows applies an explicit security descriptor atomically at creation:
    specific file rights, no generic bits and no `CREATOR OWNER` ACE.
  - Linux uses `mkdirat`/`openat` with `O_EXCL`.
- Owner and DACL are set only by handle (`SetSecurityInfo`), never by path.
- A link-count check (`NumberOfLinks == 1`, `st_nlink == 1`) applies before
  privileged code writes, re-ACLs or deletes a file. It does not apply when
  reading or launching: that would turn into a denial of service wherever a
  user can hard-link store files.
- Same-file comparisons use `FileIdInfo` or `st_dev`/`st_ino`.
- On Windows 11 builds that provide it, the privileged process opts in to
  `ProcessRedirectionTrustPolicy` (RedirectionGuard) as additional hardening.
  Failure is not fatal; on Windows 10 the handle-relative walk is the control.
- The store lock is an exclusive no-share handle on `state/lock` on Windows, or
  an `flock` on a 0600 file in a 0700 directory on Linux. Non-administrators
  cannot open it. No named object in `Global\` is used for store operations.
- Durability: every file is flushed before rename, and the containing
  directory is flushed after rename on Linux. The Windows equivalent is
  write-through renames and flushing the handles.

### Manifest schema 2 and signatures

`update-manifest.json` stays the release metadata file, with `schema: 2`.

**Per-target files.** Each target gains `files`: every ZIP member with `name`,
`size`, `sha256` and `role`. The roles are `core` (executable), `sidecar`
(Wintun) and `notice` (license texts). The target keeps its ZIP `name`,
`size` and `sha256`.

**Security fields.** Top-level `security_level`, `min_security_level`,
`min_elevation_level` and `floor_epoch` (see Terms). All come from the
reviewed `release/compatibility.json`. The publisher refuses a level
regression and a floor above the release's own level.

**Store contract.** A top-level `store_contract` integer, initially 1. A
binary that meets a higher contract than it implements treats the store as
read-only and reports that a newer component is required.

**Provenance.** A top-level `source_revision` (full tag commit) and a `build`
record: Go version, `-trimpath`, `CGO_ENABLED`, `GOOS`/`GOARCH`, and no
ambient `GOFLAGS`. The publisher signs an archive only if its executable's
embedded build information matches the tag commit, shows
`vcs.modified=false`, and matches the reviewed settings. The archive must come
from the same prepared-release build. This is the gate the Apple path already
enforces. An independent reproducible rebuild is planned later.

**Signed statement.** Every signature, from any key, is a raw Ed25519
signature (PureEdDSA, RFC 8032) over the same short, domain-separated
statement:

```text
bimeron-update-manifest-v2\n<lowercase hex SHA-256 of the exact manifest bytes>\n
```

A short statement fits the input limit of hardware tokens. Domain separation
prevents a signature made for any other purpose from being accepted.
Verifiers compute the digest of the exact bytes, build the statement, and
verify before parsing any JSON.

**Signature file.** `update-manifest.json.sig` holds one line per signature,
`<key_id> <base64-signature>`. A verifier tries only keys that it trusts and
that are listed in the file. It evaluates the signature policy over the keys
that verified, and finally requires the manifest's own `key_id` list to equal
the verified set.

**Strict decoding (Go and C++).** A token-level pre-pass runs before struct
decoding. It requires a byte-exact key allowlist per object and rejects
duplicates by byte equality. It also rejects invalid UTF-8, escapes in keys,
non-integers, numbers above 2^53 and trailing data. Case-insensitive field
matching (Go) and last-key-wins duplicates (Qt) therefore cannot matter.

**Publishing rules.** Backfill is retired: nothing signs metadata for an
existing release from its current assets or with today's
`compatibility.json`. The publisher never signs a schema 1 manifest for a
store-era version. Desktop 0.3.x accepts only `schema: 1` and single-line
signatures, so it fails closed on every store-era release.

### Trust and keys inside Core

This amends ADR 0002, which kept signing trust out of the privileged
executable. Repair acquisition already embeds one public key in Core, so this
generalizes existing practice. It does not raise compromise impact over ADR
0002: a key that Desktop trusts could already authorize SYSTEM installation
through the elevated updater.

#### Key roles

| Role | Keys | Where the private key lives | Use |
| --- | --- | --- | --- |
| Release | `R` (one active, rotated) | Generated on an offline maintainer machine; encrypted offline backups; never in CI, GitHub secrets or online storage | Every release |
| Hardware | `H1`, `H2` | Generated on two YubiKeys; not exportable | Every release; `H2` is the spare, stored separately |
| Freshness index (proposed, see Release freshness) | `F` | Scheduled job | Signs only the freshness index; never trusted for code or floors |

Core and Desktop embed the same reviewed trust file (`release/trust.json`). It
lists the public keys with their key IDs, their roles, and the YubiKey
attestation material described below.

#### Signature policy

- **Ordinary release**: valid signatures from `R` **and** from at least one of
  `H1`, `H2`.
- **Floor-epoch raise** (key-compromise recovery only): `R` **and** both `H1`
  and `H2`.

Verifiers enforce the policy on the verified key set. Without both a release
key and a hardware key, nothing can be installed. No single stolen secret or
lost device can lower a floor.

#### YubiKey requirements

- **Supported models.** Use YubiKey 5 Series devices (5 NFC, 5C, 5C NFC,
  5Ci, 5 Nano, 5C Nano) or the 5 FIPS equivalents. Security Key Series and Bio
  Series devices have no OpenPGP or PIV application and cannot be used.
  Firmware cannot be upgraded, so check each device with `ykman info`.
- **Firmware 5.7.0 or later (preferred).** Use the PIV Ed25519 key in a
  dedicated slot (for example `9c`), generated on the device. PIV attestation
  is available. Firmware 5.7+ is also outside the scope of the Infineon ECDSA
  side-channel advisory (YSA-2024-03).
- **Firmware 5.2.3 to 5.6.x.** Use the OpenPGP application's Ed25519
  signature key, generated on the device (`gpg --card-edit` →
  `generate`, or `ykman openpgp`). It is attested with
  `ykman openpgp keys attest sig`. That advisory concerns ECDSA; Ed25519 is
  Yubico's stated mitigation, and the attack also needs physical possession.
- **Firmware below 5.2.3** has no Ed25519 support and cannot be used.
- **Raw signing.** Both applications must produce a raw PureEdDSA signature
  over the statement above. Before first production use, the key ceremony
  checks this with a test vector against `crypto/ed25519.Verify` and the
  Desktop verifier. If an application can only sign through OpenPGP packet
  framing, it is not used; signatures must not require OpenPGP parsing in
  privileged code.
- **Device policy.** Each YubiKey key is used only for Bimeron release
  signing, never for git commits, SSH or email. Set touch policy to always,
  PIN required, non-default PIN, PUK and management key, and PIN retry
  counters left at their defaults.

#### Key ceremony

The ceremony is recorded in `release/trust/CEREMONY.md`, which contains public
data only.

1. Record each device's model, firmware and serial number.
2. Generate the signing key on the device, then export the public key and the
   attestation certificate, together with the Yubico attestation chain.
3. Verify the attestation offline: chain to the Yubico root, serial number,
   and an origin of "generated on device".
4. Generate the new release key `R2` on an offline machine. Store two
   encrypted offline backups, in separate places.
5. Sign a test statement with each key and verify it in Go and C++.
6. Commit `trust.json` and the attestation files through a reviewed change.
   Store `H2` in a different physical location from `H1`.

#### Planned rotation of the current release key

Treat the current release key `R1` (key ID `7370a2d8cf890e5e`) as possibly
exposed. Store-era builds do not trust it at all. Their trust set is `{R2, H1,
H2}` from the first store-era release onward. `R1` stays only in pre-store
clients and is used, if at all, solely for schema 1 releases to pre-store
Desktops until those leave support.

Exposure of `R1` alone cannot authorize anything for store-era clients. Its
residual impact on pre-store Desktops is ended by upgrading the package. This
is a separate incident-response decision, outside this ADR.

Later rotations of `R` follow the same pattern:

1. A release adds `R(n+1)` to the trust set while it is still signed with
   `R(n)` and a hardware key.
2. Once the minimum supported store-era Core and Desktop trust `R(n+1)`,
   signing switches to it.
3. `R(n)` is removed from the trust set in the next release.

#### Lost or compromised YubiKey

- **Losing one YubiKey** does not stop releases. They continue with `R` plus
  the remaining device. A thief also needs the PIN, which locks after three
  attempts, and the release key `R`.
- **Revocation:**
  1. Prepare a replacement device `H3` through the ceremony.
  2. Publish a release, signed with `R` and the remaining device, whose trust
     set drops the lost key and adds `H3`.
  3. Raise `min_elevation_level` to that release's level. Every machine then
     stops elevating builds that still trust the lost key, as soon as it
     learns of the release.
- **Until a machine updates**, its current broker still trusts the lost key.
  This is acceptable, because a forgery also requires `R`.
- **Losing both YubiKeys** means no new release can be signed until a release
  with a new trust set is shipped. It must be signed by a policy the old
  builds accept, which is not possible. In that case, a Desktop package
  release (installer-delivered trust) is the only recovery. This is why the
  spare is stored separately.
- **If `R` and a YubiKey are compromised together**, do the following:
  1. Release a new trust set signed with `R` and **both** hardware keys,
     raising the floor epoch, levels and elevation floor.
  2. Rotate `R`.
  3. Accept that machines are protected only after they receive that release.

#### Freeze resistance and Core trust

Core itself never fetches trust updates. Changes to the trust set ship only
inside new signed binaries, so there is no online key-set document with a
freshness or rollback problem of its own.

### Effective floor

Each effective floor (security and elevation) is computed in the same way.
First find the highest floor epoch among the available evidence. Within that
epoch, the floor is the maximum level over these sources:

1. The floors compiled into the verifying binary. Core embeds
   `release/compatibility.json`; Desktop embeds the floors of its pinned Core.
2. The floors in the verified manifest of every committed version in
   `versions/`.
3. The newest valid `state/floor-<seq>.json`. It contains the exact manifest
   bytes and signatures that established the floor, so it verifies itself. The
   same evidence is kept in the HKLM or `/etc` copy.
4. Floors from freshly fetched signed manifests. They are used for selection
   and warnings only (see Enforcement).

Only a privileged Core process writes floor records. A floor is appended only
after a switch to a version that meets it has committed. A record that fails
verification is ignored and reported; the remaining evidence still applies.
Deleting or reverting one record or one location cannot lower the floor while
other evidence remains. No command deletes or lowers floor or active evidence.

A whole-machine or VM-snapshot restore reverts all sources together. That is
outside the local-attacker model, and source 4 bounds it at the next online
check.

**Enforcement**

- **Locally committed floors (sources 1–3).**
  - No release below the security floor is installed, switched to or used as a
    repair source.
  - No elevated process runs below the elevation floor.
  - A binary below the security floor may run elevated only to install a
    release that meets the floor, and only if the binary itself meets the
    elevation floor.
- **Fresh floors (source 4).**
  - They never block IPC with the installed service, VPN connections through
    it, or diagnostics.
  - They show a persistent "security update required" state.
  - They block elevation of below-floor code for any purpose other than
    installing a release that meets them.
  - Below a fresh elevation floor, Desktop requires a package upgrade.
- **Below-floor service (decided).** An installed service below the committed
  security floor does not block the VPN. The service and Desktop report
  `below_security_floor`, and Desktop offers repair.

### Elevated maintenance session (replaces caller-trusted `service update -source`)

All elevated store operations use one authenticated transport, generalizing
`repair-session`:

```text
bimeron maintenance-session <128-bit-nonce> <caller-pid>
```

**Elevation and authentication**

- Desktop elevates the selected binary (see Elevated entry points) with only
  these two arguments. No elevated store operation accepts a file path, a
  digest, a version or a key from its caller.
- The broker authenticates the peer exactly as `repair-session` does today: a
  pipe DACL, a client PID bound to a retained handle, and a session ID on
  Windows; `SO_PEERCRED` plus pidfd on Linux.

**Request**

The first request names one operation: `update`, `repair` or `import-check`.
It also carries the consent flags.

**Streaming an update**

1. Desktop streams `manifest` (up to 64 KiB) and `signature` (up to 4 KiB) as
   length-prefixed frames.
2. The broker verifies the signatures over the raw manifest bytes, then
   decodes the manifest strictly.
3. Desktop then streams `archive`. The broker accepts exactly the size that
   the signed target declares, writes it into a fresh `staging/<random>/` as
   it arrives, and hashes it on the way.

No byte is parsed before its authentication; the archive is authenticated by
its signed size and digest.

**Why streamed bytes instead of paths**

- It removes every attack in which a privileged process opens a caller-chosen
  path, such as UNC or WebDAV credential capture, device or pipe paths that
  block indefinitely, or junction and object-manager redirection of
  intermediate path components.
- It removes Desktop's temporary staging.
- Downloads use Desktop's network stack and proxy settings. The privileged
  process makes no network requests, so the Wintun-only signed download in
  `repair_acquire.go` is replaced by Desktop-streamed bundles.

**Checks inside the broker**

- Ordering and floors:
  - the broker's own security level must meet the effective elevation floor;
  - the new release's security level must meet the effective security floor;
  - the new `core_version` must be at least the maximum of the active version
    and the verified installed version.
- Equal versions are accepted only when the bytes are identical (republishing).
- The archive is checked against its target: OS and architecture, ZIP size and
  SHA-256, and structure (no traversal, symlinks or duplicates; exactly the
  expected members).
- Each member is checked for size and SHA-256, and the executable's Go module
  and machine identity are verified.

**Switch and commit**

1. The broker keeps open handles to the verified staging members for the whole
   switch.
2. It replaces the service executable through the existing transaction: stop,
   backup, rename, start, readiness, rollback. The source is the verified
   staging handle, never the broker's own image and never a re-resolved path.
   The backup and staged names in the service directory carry a random
   suffix, so a leftover file never blocks a later attempt. A stopped service
   is activated and verified before commit.
3. Readiness uses the restricted readiness channel. Its pipe name carries a
   per-start 128-bit nonce, passed through the `StartService` arguments, so it
   cannot be pre-created.
4. After readiness, the broker promotes `staging/<random>` to
   `versions/<version>` with one rename.
5. It appends the active and floor records, then writes the HKLM or `/etc`
   copy.
6. It cleans up.

A failed state write after readiness never rolls back the service. Instead,
the broker reports the failure and reconciliation repeats the write. A failed
switch deletes the staging entry, so a release that never committed is
neither floor evidence nor usable.

**Crash points**

On the next privileged run, a leftover staging directory or a service-directory
backup is reconciled against the installed service digest, under these rules:

- **Installed digest equals a staging member** whose manifest verifies: the
  broker completes promotion and appends the records.
- **Installed digest equals the backup**: the broker removes the staging
  directory and the backup.
- **Anything else**: the broker treats the service as damaged and repair takes
  over.

**Wintun**

The store keeps the signed sidecar. The service-directory copy is checked
against its signed or pinned digest at every service start, before loading.
Each elevated mode and the service call
`SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` and load Wintun by its
verified full path.

**Legacy command**

The legacy `service update -source` command is refused by store-capable builds,
with a message naming the maintenance session.

### Re-registration that disables pre-store tools

The first switch to a store-era version changes the service registration in
the same transaction as the executable, and the change is rolled back with it.
Every pre-store validator then fails closed instead of rolling the service
back.

- **Windows.** `BinaryPathName` gains a fifth argument, for example
  `service run <SID> store1`. Pre-store `service update`, pre-store repair
  inspection and the 0.3.x installer action all require exactly the
  four-argument form, so they refuse to act.
- **Linux.** The unit text changes and the service executable moves, for
  example to `/usr/local/lib/bimeron/service/bimeron-core`. Pre-store repair
  compares the unit byte for byte, the 0.3.x installer matches the exact
  `ExecStart`, and pre-store `service update` checks the fixed old path.
- **Store-capable Desktop and Core** treat an installed service that matches no
  committed signed member as damaged, and repair restores the committed
  version. This covers pre-store, below-floor and unknown images.

**Residual risk.** An old binary can still uninstall and reinstall the
service. That takes two explicit elevations, and the next store-capable repair
heals it.

### Elevated entry points

| Entry point | Binary | Verification | Inputs |
| --- | --- | --- | --- |
| Maintenance session: update, repair | Newest committed store version at or above the elevation floor. On bootstrap, the bundled copy at or above the elevation floor, verified against the signed manifest shipped with the package. | Desktop: handle-bound digest. Broker: self-check. | Nonce, PID, streamed bytes |
| Installer action (MSI, DEB) | `bimeron-core` in the package directory, run directly as SYSTEM or root | Self-check against the shipped signed manifest | None; fixed package-relative paths |
| Foreground IKEv2 daemon | Same as the maintenance session | Same | Existing foreground contract; per-installation policy outside the store |
| Service | Service directory copy | Committed digest; Wintun digest at load | SCM or systemd only |
| RepairBootstrap (Desktop) | Retired once the installer seeds the store | n/a | n/a |

**Foreground policy file**

The foreground policy file (`bimeron-foreground.json`) is per installation and
cannot live in an immutable signed version directory. It moves to a protected
location outside the store. Core and Desktop agree on that location; see the
work split.

**Elevated self-check**

Every elevated Core process checks itself at startup, before any mutation:

1. It locks its own image by handle.
2. It hashes the image and requires a matching member in a verified signed
   manifest: its own `versions/` directory, or the package-shipped manifest
   during bootstrap.
3. It requires its own security level to meet the effective elevation floor.
4. It refuses to run if non-allowlisted environment variables are present:
   `GO*`, `GODEBUG`, `ZONEINFO` and the like. Under admin-approval elevation,
   `HKCU\Environment` is inherited, and the Go runtime reads some of these
   variables before `main` runs.
5. It sets the current directory to the system directory.
6. It resolves locations only through `GetSystemDirectoryW`,
   `SHGetKnownFolderPath` and handle-derived paths.

The broker acts only at machine scope. With over-the-shoulder credentials, all
per-user state belongs to another account.

**Not elevated: the installed service image.** The installed service image is
never used as the elevated binary. It would have to lock its own image and
then could not be replaced.

### Launch verification in Desktop

**Desktop verification is not the security boundary**

Desktop-side verification does not protect against malware that runs as the
Desktop user. Such malware can patch the Desktop process, skip the check, or
launch anything it likes. For a user in the Administrators group,
admin-approval mode is not a security boundary either: same-user malware can
elevate silently. Most protections against same-user malware therefore hold
only for standard accounts.

The real boundaries are:

1. the store ACL and owner rules;
2. the self-check and the narrow, data-only session of every elevated Core
   process;
3. service-side IPC authorization.

**What Desktop verification still provides**

- It detects misconfiguration, partial publication and corruption.
- An honest Desktop never asks the user to approve an unverified file.
- The binding to the launched file is cheap.

**Windows** (unelevated CLI, and the binary that gets elevated)

1. Open the executable with `GENERIC_READ`, share mode `FILE_SHARE_READ` only,
   and `FILE_FLAG_OPEN_REPARSE_POINT`.
2. Run the existing `protectedExecutable` owner and ACL policy on the file and
   its ancestors.
3. Confirm with `GetFinalPathNameByHandleW` that the file lies inside the
   store.
4. Hash it through the handle and compare with the signed member hash.
5. Keep the handle open while calling `CreateProcessW` or `ShellExecuteExW`
   (`runas`) on the same canonical path. Close it after the process exists.

While the handle is held, no writer, rename or delete can succeed. The image
loader and the AppInfo service need only read and execute access, which are
compatible with this share mode; acceptance verifies this on the VM.

**Linux**

- **Unelevated CLI:**
  1. Open the executable with `openat2` beneath the store root,
     `O_RDONLY | O_CLOEXEC`.
  2. Run `fstat` to check that it is a regular file, owned by root, and not
     group- or other-writable.
  3. Hash it through the fd.
  4. Execute it as `/proc/self/fd/<n>`. For ELF, the kernel resolves the path
     before close-on-exec takes effect, so the fd is not leaked into the
     child.
  5. Go launchers use `ExtraFiles` the same way.
- **What the fd binding guarantees:** it binds the inode, not the content.
  Write access restricted to root keeps the content.
- **Elevated broker:**
  - Use `/usr/bin/pkexec` from that fixed path, after checking that it is
    protected. pkexec is never resolved from `PATH`, and the WSL route is
    removed, for every elevated command.
  - Pass it the verified store path. pkexec takes a path, so the root-owned
    store and the self-check are the binding.
  - The default `org.freedesktop.policykit.exec` action requires
    administrator authentication. No pinned or relaxed polkit action is added.
  - pkexec sanitizes the environment, and the broker still applies its own
    environment allowlist.

**Cost**

Every CLI launch is hashed. A Desktop benchmark measures the cost on a
low-end ARM64 machine as well, because Qt uses software SHA-256. A cache keyed
by file ID and change time is allowed only if the benchmark shows a need, and
never for elevation.

**Rejected binding techniques**

- **Section-based process creation** (`NtCreateSection` plus
  `NtCreateProcessEx`): undocumented, and it is the process-ghosting primitive
  that endpoint security flags.
- **A suspended-process identity check**: it reopens the image by path, so it
  adds nothing over the held handle.

### Repair

- **Target version.** `Inspect` takes the maximum of the active version and the
  installed version, counting the installed version only when its digest
  equals a committed signed member. The broker's own version never matters.
- **Intact service.** An installed image that equals the committed member of
  the target version is intact, so the #140 rule that a byte-different
  compatible release must be replaced is withdrawn.
- **Damaged service.** #140 corruption detection is kept: a missing,
  unreadable or non-matching image is damaged. So is an image of a lower
  version.
- **Replacement source.**
  - The source is `versions/<target>/`, opened and verified by handle and held
    through the switch.
  - If an open is blocked, for example by a foreign handle, or the store copy is
    missing or damaged, the repair session asks Desktop to stream the signed
    bundle for exactly the target version. That bundle goes through staging, as
    for an update, and is then republished.
  - The same applies to Wintun.
- **Fail-closed rule.** If no verified source for the target is available,
  repair fails closed with `store-unavailable`. It never falls back to a lower
  version, to its own image, or to a bundled copy that is not exactly the
  target or higher.
- **Missing-service installation** installs the active version, or the newest
  committed version if no active record exists. If nothing is committed, it
  installs the verified package bootstrap version, which must meet the
  floor. It never installs `os.Executable()` bytes.
- **Unchanged rules.** The existing consent, ownership, readiness and rollback
  rules stay in force. The repair request still carries no paths, versions or
  digests.

### Release discovery

Desktop treats a newer release tag whose metadata is missing, cannot be
verified or is inconsistent as a visible update error that names the tag. It
does not skip the tag silently. Missing metadata would otherwise let anyone
who can delete release assets keep users on an older signed release.

### Release freshness index (proposed, pending confirmation)

Visible errors do not reveal a release that was never visible, for example
when the release listing is hidden or replayed. The proposed addition below
must also keep working if the maintainer is unavailable for a long time.

- **The index.** A small signed file is published with every release and
  re-signed on a schedule. Its name is `freshness-index.json` plus
  `freshness-index.json.sig`. It contains, per channel, the newest version,
  the SHA-256 of its manifest and its security level, plus `issued` and
  `expires` timestamps. The expiry is about 90 days after issue.
- **Signing.** A dedicated freshness key `F` signs the index, in the same
  statement format with the domain `bimeron-freshness-index-v1`.
  - The verifiers' trust file grants `F` a single role. A signature by `F` is
    never accepted for a manifest, a trust change or a floor.
  - `F` therefore cannot authorize code. The most a stolen `F` can do is claim
    a release that does not exist, which shows up as a visible error, or keep
    re-signing an old "latest", which is the freeze that the index cannot stop
    either way.
- **Unattended re-signing.** A scheduled job re-signs the index, for example
  monthly, using only `F`. It runs without the maintainer, so a long absence
  does not let the index expire. `F` may live in CI because its power is
  narrow. It is rotated like `R`, through the trust set.
- **Client behavior.**
  - Desktop fetches the index. If the index names a newer version than
    discovery found, or its manifest digest does not match, Desktop shows a
    visible error.
  - An expired or missing index produces only a warning such as "update
    information is stale". It never blocks the VPN, the CLI or repair.
  - The index level is used as a fresh floor hint (source 4): a warning only.
- **If the job stops** (the maintainer is absent and CI is down), users see a
  stale warning after the expiry. Nothing else changes.

### Cleanup

After a commit, the privileged process keeps the active version and the
previous committed version.

- It moves to `trash/` and deletes versions below the floor, versions nothing
  references, and leftover staging directories. All of this happens by handle,
  inside the store only.
- A sharing violation (a running CLI or a foreign handle) leaves the entry in
  `trash/` for the next privileged run. The update still succeeds, and the
  diagnostic names the blocking process through Restart Manager.
- Leftover service-directory backups are reconciled as described under Crash
  points.

### Interfaces

**Configuration and capabilities**

- `release/compatibility.json` gains `security_level`,
  `min_security_level`, `min_elevation_level`, `floor_epoch` (all reviewed)
  and `store_contract`.
- `hello.capabilities` gains `core_store: <contract>` and the service's
  effective floors.
- `version -json` reports the binary's compiled contract and floors without
  contacting a service.

**Commands**

- **Unelevated:** `bimeron store status -json` lists committed versions,
  verification results, the active version and the effective floors. It is
  diagnostic only; Desktop verifies the store itself.
- **Elevated:**
  - `maintenance-session` as described above.
  - `store import-package` (installer action only; fixed package-relative
    inputs).
  - `store purge`, which removes `versions/` and keeps all floor and active
    evidence.
  - No command lowers or deletes floor or active evidence. There is no
    `-forget-floor`. Resetting a floor requires an epoch raise signed with the release key and both hardware keys.
    An administrator who deletes `state/` by hand is out of scope.
- **`service install` (store-capable builds)** installs only from the store or
  from the verified package bootstrap, never `os.Executable()`.

**Session codes and protocol version**

- `repair-session` becomes a mode of the maintenance session. New terminal
  codes: `below-floor`, `below-elevation-floor`, `store-unavailable`,
  `newer-store-contract`.
- IPC protocol stays 1. All changes are additive and gated on the capability.

### Package installer action

The installer action is reworked; it is not extended in place.

- It becomes a commit-time action, not a deferred action that runs before
  install finalization. It runs `bimeron-core store import-package` directly,
  with no Qt GUI process running as SYSTEM or root and no window.
- It works only upward:
  1. It verifies the bundled Core against the package-shipped signed manifest
     using Core's embedded keys.
  2. If the bundled version is newer than the committed version, it performs a
     normal switch from staging.
  3. Otherwise it does nothing.
- There is no rollback action, because a rollback action would itself be a
  downgrade path running as SYSTEM.
- The condition excludes MSI repair and maintenance modes, unless the action
  is proven safe under an unsolicited repair started by a standard user.
- Commit actions do not run when rollback is disabled by policy, so
  acceptance must verify that case.
- **Fallback:** on first launch, Desktop detects an unseeded store or a
  bundled version newer than the committed one, and offers the normal elevated
  maintenance session.
- **Linux:** DEB `postinst` calls the same command.

### Authenticode (deferred)

Authenticode signing is a later decision. This ADR reserves the following
constraints for it:

- Only store-capable builds, which refuse `-source`, may ever be signed. Older
  builds are never signed retroactively. A signed build that still accepts
  caller-trusted installation would be a permanent, publisher-signed tool for
  installing arbitrary services.
- The Authenticode certificate is a separate trust chain. Store and floor
  decisions never depend on it.
- When it is adopted, the self-check additionally verifies the signature with
  `WinVerifyTrust`, and Windows publisher rules (App Control, AppLocker)
  become possible.

### Related decisions recorded separately

- **"Always VPN" at boot** (approved, separate ADR). The service connects a
  kill-switch profile at boot and blocks traffic until the connection is up.
  Intersections with this record:
  - The service needs a service-owned profile store. That store is separate
    from the core store: the core store holds immutable signed code only, and
    profiles never live in `versions/`.
  - Fresh or committed floors must never block that boot connection either.
- **Service reading of profile files** (separate ADR). This ADR's streamed,
  authenticated session pattern can carry profile content from client to
  service, so the service never opens a path the user chose.

### Platform scope

Windows and Linux amd64/arm64 only. macOS and Android are outside this updater
(ADR 0031 and ADR 0032 keep Apple separate; Android ships inside the app). No
store, floor or repair change applies to them. Desktop's updater already
reports no platform on them.

## Threat model

**In scope.** A local unprivileged user, and malware running as the Desktop
user. On a standard account, such an attacker can:

- write the user's TEMP, profile and HKCU;
- start processes and inject into the Desktop process;
- create junctions, mount points and object-manager links;
- open handles to any readable file;
- pre-create names in `ProgramData` and in `Global\`;
- invoke UAC or `pkexec` on any binary with any arguments.

The network is also in scope: malicious mirrors, deleted or withheld release
assets, and replayed old signed metadata.

**Out of scope.**

- An attacker who already has administrator or root rights, including through
  admin-approval mode on an administrator account.
- Kernel compromise.
- Simultaneous compromise of the release key and a hardware key, including its PIN.

| Threat | Mitigation |
| --- | --- |
| Replace store files or directories | Admin-only DACL and owner; handle-relative walk; immutable versions |
| Pre-create the store or its children | Program Files location; any unexpected object fails closed |
| Junction, symlink or hardlink redirection of privileged writes | No-follow opens on every component beneath a held root; link-count check before writes and deletes |
| Make a privileged process open an attacker path (UNC, WebDAV, device, link) | No privileged path inputs; bytes are streamed over the authenticated session |
| TOCTOU between verify and execute | Windows: deny-write/delete handle held across process creation. Linux: exec of the verified fd. Elevated self-check |
| Swap the bundle after Desktop verification | The broker verifies the streamed bytes itself |
| Failed floor-raising update bricks the service | Only committed versions are floor evidence or usable; failed switches delete staging |
| Rollback through repair | Target is the maximum of active and verified installed versions; the source is the store |
| Rollback through installing an older signed release | Order and floor checks inside the broker |
| Rollback through pre-store tools or old Desktop | Re-registration makes them fail closed; store-capable repair heals unknown images |
| Rollback by deleting or reverting floor records | Maximum over embedded, manifest, record and registry or `/etc` evidence; no deleting command |
| Rollback through a damaged store | Republish the exact target from streamed signed bytes; never fall back lower |
| Confused deputy (crafted elevation) | Only nonce, PID and streamed signed bytes; no floor deletion; `service install` only from the store |
| Malware elevates an old Bimeron binary | Old tools refuse the re-registered service; store-capable Desktop never elevates below the elevation floor |
| DLL planting or environment injection into elevated processes | `SetDefaultDllDirectories`; admin-only directories; Wintun digest at load; environment allowlist |
| Squatting of locks and pipes | Lock file in admin-only `state/`; readiness pipe name with a per-start nonce |
| Foreign handle blocking update or repair | Users cannot open service or state files; held staging handles; random backup names; streamed fallback source; deferred trash |
| Release-key or hardware-key compromise | Every release needs the release key and a YubiKey; an epoch reset needs the release key and both YubiKeys; planned rotation of the current release key |
| Freeze or withholding | Visible error for missing or invalid metadata; proposed freshness index with expiry (Q5) |
| Fresh floor locks a user out of the VPN | Fresh floors never block connectivity; only elevation is gated |
| Unsolicited MSI repair as a standard user | Installer action excluded from repair modes, upward-only, no rollback action |
| Alternate administrator approves UAC | Machine paths only; the readiness channel; caller identity from the authenticated transport, as in #140 |

**Residual risks**

- An old binary that uninstalls and reinstalls the service takes two explicit
  elevations; the next store-capable repair heals it.
- Same-user malware can always ask the user to approve elevation of its own
  binary. Authenticode (Q7) makes the publisher visible, but it is not a
  defense on its own.
- Restoring a whole disk or VM reverts store and floor together. Only fresh
  online floors (source 4) bound it.
- A foreign handle can delay cleanup indefinitely. Cleanup never blocks
  updates.

## Compatibility and migration

- **Desktop 0.3.0/0.3.1.** These versions have no store support. Store-era
  releases have schema 2, multi-line signatures and `gui_min` set to the first
  store-capable Desktop, so these versions are never offered them. If a
  store-era service reaches such a machine anyway, through package
  uninstall/reinstall or the CLI distribution, the re-registration makes their
  repair, update and installer action refuse it. They report failure instead
  of rolling the service back. Upgrading the Desktop package fixes this.
- **First store-capable Desktop.** It bundles its pinned Core together with
  that release's signed schema 2 manifest and signatures. The installer action
  seeds the store and switches the service upward, as described above.
- **Existing installs whose service is newer than the package.** These were
  updated through the pre-store updater. The service stays in place. The next
  update or repair streams a signed bundle at or above the installed version
  and commits it. Nothing installed is adopted without its full signed member
  set.
- **Desktop uninstall.** The store belongs to Core and appears in no MSI or DEB
  file list, so it persists, together with the floor evidence. Uninstalling the
  service remains an explicit action. `store purge` keeps all evidence.
- **Older Desktop package after a store-era one.** Pre-store tools refuse the
  re-registered service. Desktop should also block MSI downgrades.
- **Linux package management.** DEB remains the only Linux package. The store
  survives upgrade, removal and purge.

## Work split

**Core**

- Manifest and publishing:
  - schema 2 producer and verifier, with the build-provenance gate;
  - multi-signature format and the release-key-and-YubiKey policy;
  - strict JSON pre-pass;
  - version grammar and test vectors;
  - retirement of backfill.
- Embedded key set; floor epochs; the security and elevation floor policy in
  `compatibility.json`; publisher refusal of floor regressions.
- Store module:
  - handle-relative create and open, staging, promotion;
  - append-only records, the HKLM or `/etc` copy, the lock;
  - reconciliation and cleanup.
- Maintenance session: streamed frames, the update, repair and import
  operations, and the elevated self-check with its environment allowlist.
- Service changes:
  - re-registration in the switch transaction;
  - the readiness pipe nonce;
  - Wintun pin at load and `SetDefaultDllDirectories`;
  - DACLs on service-directory files;
  - `service install` from the store;
  - refusal of `-source`.
- Repair:
  - target computation;
  - store source;
  - streamed fallback, replacing network acquisition in the broker.
- Relocation of the foreground policy file, coordinated with Desktop.
- Documentation: UPDATE_SPEC, RELEASE_UPDATES, REPAIR_SESSION, SERVICE,
  GUI_INTEGRATION, CONTROL, and the ADR 0002 status.

**Desktop**

The Desktop part is implemented in the bimeron-desktop repository
(bimeron/bimeron-desktop#58). Core publishes the contract for it: the schema 2
format, the signature policy and trust file, the maintenance-session protocol,
and the test vectors.

- Verification:
  - schema 2 and multi-signature verification;
  - strict JSON pre-pass;
  - pinned key set;
  - version vectors.
- Store use:
  - discovery and usable-version selection;
  - effective floors from the embedded value and the HKLM or `/etc` copy.
- Launching:
  - handle- or fd-bound launches for every CLI run and every elevation;
  - fixed protected `pkexec`;
  - removal of the `PATH` and WSL elevation routes.
- Maintenance-session client:
  - streams bundles for update and repair;
  - shows a visible error for missing or invalid metadata.
- Packaging:
  - ship the signed manifest of the bundled Core;
  - rework the installer action (commit-time, `store import-package`, no
    rollback action, repair excluded);
  - block MSI downgrades;
  - retire RepairBootstrap.
- Relocation of the foreground policy file.
- UX for the below-floor, update-required, store-unavailable and
  newer-store-contract states.
- `docs/core-updates.md`.
- Launch-verification benchmark, including ARM64.

## Acceptance plan

Testing runs on a disposable clone of the Windows 10 STD VM and on an Ubuntu
22.04 VM, never on the host. Each case records binary hashes and the service
and store state before and after.

1. **Fresh install.** A fresh install of the store-capable Desktop seeds the
   store, installs the service from it and re-registers it. It shows one UAC
   prompt.
2. **Update A to B.** B is committed and the service runs B. The floor rises
   only if B raises it. The CLI and the broker now run from B.
3. **Failed update.** B raises the floor but fails readiness. The service
   returns to A and the floor is unchanged. B is not in `versions/` and is not
   used. The VPN connects.
4. **Repair after an update.** A healthy B service is left as B. A damaged B
   (XOR at 0x1000, zeroed header, missing file) is restored to B, never to the
   bundled A.
5. **Damaged or blocked store B.** Cases: a deleted file, a modified member, an
   extra hardlink, a junction in place of a directory, and a foreign handle with
   share mode 0 on a member. Repair streams B again from Desktop. Offline,
   repair fails with `store-unavailable` and never installs A.
6. **Rollback attempts.** These must be refused, or must leave B and the floor
   in place:
   - a maintenance session streaming a validly signed older release;
   - reverted or deleted floor records;
   - a reverted HKLM or `/etc` copy;
   - crafted arguments for `store purge`, `service uninstall` and
     `service install`.
7. **Pre-store tools against a store-era service.** Cases: Desktop 0.3.1
   repair; the legacy update command of a pre-store build; the 0.3.x
   installer action after uninstall and reinstall. Each fails closed. Then
   store-capable repair heals an image replaced by hand.
8. **Path and contention attacks** by a standard user:
   - pre-create the readiness pipe, `Global\BimeronCoreUpdate` and the
     maintenance pipe;
   - hold share-0 handles on service, state and store files during update and
     repair;
   - pre-create the store root (ProgramData variant only).
9. **UAC, alternate administrator and pkexec.** A standard user approves with
   alternate administrator credentials, and update and repair succeed with the
   owner preserved. A malicious `HKCU\Environment` (`GODEBUG`, `ZONEINFO`) is
   refused. Linux uses pkexec with polkit and alternate credentials.
10. **Fresh-floor and censored network.** A machine below a freshly announced
    floor still connects through the installed service and shows a persistent
    warning. Below a fresh elevation floor, Desktop requires a package upgrade.
11. **Installer behavior.** Cases: `msiexec /fa` by a standard user; an MSI
    rollback in mid-transaction; `DisableRollback` policy; a DEB upgrade,
    removal and purge. The store and floor persist; no downgrade happens.
12. **Crash injection** at every commit step (after the switch, after
    promotion, after the records). Reconciliation reaches a consistent state.
13. **Keys.**
    - A release signed only by `R`, or only by YubiKeys, is refused.
    - `R` plus either YubiKey is accepted.
    - A store-era build refuses `R1` signatures.
    - Rotation of `R` works with old and new brokers.
    - An epoch raise needs `R` plus both YubiKeys.
    - YubiKey signatures from the ceremony test vectors verify in Go and
      C++.
    - The freshness key is refused for manifests.
    - An expired freshness index only warns.
14. **Version grammar.** Rejected forms, the NTFS case-collision attempt, and
    beta-to-stable transitions.
15. **Foreground IKEv2** on a store-era Desktop, with the relocated policy file.
16. **Platforms and performance.** ARM64 runtime on both operating systems; the
    `openat2` fallback on an older kernel, if supported; the hashing benchmark
    on low-end hardware.

## Alternatives considered

- **Overwrite the Desktop package files in Program Files with the updated
  CLI/broker.** Rejected. The files belong to the MSI or DEB, and MSI
  self-heal, repair or upgrade would silently restore the old bytes, which is a
  rollback. It falsifies the package manager's integrity metadata, mixes two
  update channels on one set of files, and still needs a separate
  anti-rollback record.
- **Keep the bundled broker, but make repair compare the service with a signed
  record and skip replacement of a newer intact service.** This change is
  smaller and fixes the visible rollback. Rejected as the end state:
  - a damaged newer service could then be repaired only with older bytes, or
    not at all;
  - the CLI keeps validating profiles with old code;
  - the elevated updater remains old code that trusts caller digests.

  Its comparison rule is adopted inside this design.
- **Release a Desktop package for every Core patch.** This keeps one trust root
  (the package) and needs no store. Rejected:
  - it ties security response time to the Desktop release pipeline, its
    review, and MSI/DEB rollout;
  - every Core fix waits for Desktop QA;
  - users who update Core but not Desktop still hit the rollback.
- **Path-based elevated `store install -manifest -signature -archive`.** This
  was the first draft. Rejected because a privileged process would open
  caller-chosen paths. Even with no-follow opens, intermediate components,
  object-manager links, UNC/WebDAV credential exposure and blocking devices
  stay reachable. The streamed session removes the whole class.
- **Network download inside the privileged process** (extending
  `repair_acquire.go`). Rejected: it adds TLS and HTTP surface to SYSTEM/root,
  ignores user proxies, and fails on slow or censored links within the session
  deadline. Desktop downloads, and the broker authenticates.
- **Run the service directly from the store** (ImagePath or `ExecStart` pointing
  into `versions/<version>/`). Deferred. It changes the canonical service path,
  interacts with SELinux labels, and puts the store directory into the
  service's DLL search and recovery path. The re-registration step could later
  absorb it.
- **Have the running service perform updates without UAC.** Deferred. It puts
  archive handling into the always-on privileged process, and updates would
  depend on a healthy service, while repair exists precisely for an unhealthy
  one.
- **Fixed package-owned elevation trampoline** that verifies and launches the
  newest committed store version inside the boundary. It would give a stable
  UAC and polkit target, and would allow polkit `exec.path` pinning. Deferred:
  it is package-versioned elevated code that must understand future store
  contracts. The self-check already provides the binding.
- **Online, root-signed key-set document (TUF-style root).** Rejected for now.
  It adds a second freshness and rollback problem. Threshold signing combined
  with key sets embedded in binaries and dual-signed rotation covers the
  realistic threats with less state.
- **Locally signed or HMAC-protected floor record** (machine key, DPAPI, TPM).
  Rejected. An attacker able to write the admin-only state is already out of
  scope, and a machine key adds secrets without stopping whole-disk rollback.
- **Version floors instead of integer security levels.** This was the second
  draft. Rejected in favor of levels (pending Q6). Version floors depend on
  precedence and grammar across channels. A beta floor cannot be satisfied by
  a stable-only user, and "floors are always stable versions" was an extra
  rule. A level is one integer, shared by all channels and compared the same
  way in Go and C++.
- **Online, root-signed key-set document combined with a threshold of
  software keys.** Hardware-backed keys that cannot be exported, plus key sets
  embedded in binaries, protect against the realistic threat of a copied
  signing secret without adding online trust state.

## Decisions and pending confirmations

Decided by the user (November 18, 2026):

| # | Decision |
| --- | --- |
| Q1 | Windows store: `%ProgramFiles%\Bimeron Core\store` |
| Q2 | Linux store: `/usr/local/lib/bimeron/store` |
| Q3 | Two-key policy for every release: release key and one of two YubiKeys; planned rotation of the current release key (see Trust and keys) |
| Q4 | A below-floor service does not block the VPN |
| Q7 | Authenticode is deferred; constraints are reserved |
| Q8 | "Never below active" is strict; no manual downgrade |
| Q9 | Pre-store tools are intentionally unable to manage store-era services |

Proposed, pending confirmation:

- **Q5**: the release freshness index with a narrow freshness key, an expiry of
  about 90 days, unattended re-signing, and a warning only on expiry.
- **Q6**: integer security levels for floors, instead of version floors.
- **Hardware details**: which signing path each YubiKey uses, either PIV
  Ed25519 (firmware 5.7+) or OpenPGP Ed25519 (firmware 5.2.3+). This depends
  on `ykman info` for both devices.

