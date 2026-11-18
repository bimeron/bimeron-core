# ADR 0039: Signed versioned core store and anti-rollback floor

Status: proposed draft, revision 9, November 18, 2026. Follow-up questions
Q10, Q11 and Q12 await the owner; the rest is decided. Not accepted. This
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

- **Core version**: the project's existing version style, `X.Y.Z` or
  `X.Y.Z-beta.N`, defined exactly under Version comparison rules. Versions
  order update selection, the "never below active" rule and both floors.
- **Security floor**: the lowest core version allowed for installation,
  switching or use as a repair source. A manifest states it as
  `security_floor: {"epoch": E, "version": V}`. It is a publisher statement,
  never user input or local inference.
- **Elevation floor**: the lowest core version allowed to run elevated in any
  role, including as the installer of a newer release (`elevation_floor`,
  same shape). It must be at or below the security floor. It is raised only
  when updater or broker code itself is affected. Every raise requires a
  Desktop package that bundles a Core at or above it (see Effective floor).
- **Floor epoch**: an integer that is normally 0. Only a release with the
  stronger signature policy (see Trust and keys) can raise it. Floors from a
  lower epoch are ignored, which is the only way floors can go down. Epochs
  exist only for key-compromise recovery.
- **Committed version**: a store version that passed a service switch with
  readiness on this machine, or that repair republished for the committed
  target. Only committed versions live in `versions/`.
- **Active version**: the version the service was last switched to and
  committed.
- **Usable version** (Desktop selection): a committed version whose signed
  manifest and members verify, whose version is at or above the committed
  security floor, and whose signed GUI range includes the running Desktop.

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
    switch.json                write-ahead switch journal
    promote-pending.json       open promotion debt, if any
    switch-abandoned-<seq>.json  abandoned journals, kept for diagnostics
    lock                       store lock
```

**Permissions**

- **Windows.** Every directory gets its own protected DACL (no inheritance
  from the parent). The owner is `SYSTEM`; `SYSTEM` and `Administrators` have
  full control. `Users` get read and execute only on `versions/` and its
  contents, never on `staging/`, `trash/` or `state/`. The inheritable
  read-and-execute ACE for `Users` on `versions/` must not flow into the other
  directories.
- **Service directory files.** In store-capable builds, the service
  directory grants `Users` no inheritable file access. Every member, including
  `WINTUN-LICENSE.txt`, and every temporary and backup name carries a DACL for
  `SYSTEM` and `Administrators` only. An ordinary user then cannot open them,
  so a sharing-mode handle cannot block a switch (see the `copy` step).
- **Directory protection** must reapply the store root's protected DACL by
  handle, never reapply a parent descriptor by path.
- **Linux.** Everything is owned by root. `versions/` is 0755 (members 0755
  or 0644); `staging/`, `trash/` and `state/` are 0700, and `lock` is 0600.
- **Floor and active copies for Desktop.** Desktop cannot read `state/`. It
  reads a SYSTEM-written copy of the latest floor evidence and active record:
  a protected HKLM value under `SOFTWARE\Bimeron\Core` on Windows, and
  `/etc/bimeron/core-state.json` (root-owned, 0644) on Linux. Registry values
  have no sharing modes, so a reader cannot block a writer. This copy is also
  the second location of the floor evidence, and the committed floor is the
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

**Security fields.** Top-level `security_floor` and `elevation_floor`, each
`{"epoch": E, "version": V}` (see Terms and Version comparison rules). Both
come from the reviewed `release/compatibility.json`. Each floor version must
be at or below the manifest's own `core_version`, and the elevation floor must
be at or below the security floor.

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

**Signed message.** Every signature, from any key, is a raw Ed25519
signature (PureEdDSA, RFC 8032) over a 32-byte message `M`:

```text
S = "bimeron-update-manifest-v2\n" || lowercase-hex(SHA-256(manifest bytes)) || "\n"
M = SHA-256(S)
```

`M` is digest-sized, so every token signing path accepts it. GnuPG's
smartcard path, for example, limits raw input to 64 bytes. Domain separation is
kept inside the hash, so a signature made for any other purpose is not
accepted. The freshness index uses the same construction with the domain
`bimeron-freshness-index-v1`. Verifiers compute `M` from the exact bytes and
verify before parsing any JSON. Ed25519 verification follows RFC 8032 strictly
(canonical `S`, rejection of small-order public keys) in both Go and C++.
Shared vectors cover these edge cases.

**Signature file.** `update-manifest.json.sig` holds one line per signature,
`<key_id> <base64-signature>`.

- **Format.** Lines end with LF only. Base64 is canonical standard base64.
  Each key ID appears at most once, and the file has at most 8 lines and at
  most 4 KiB.
- **Verification.** Every listed key that the verifier trusts must verify.
  Listed keys that the verifier does not trust are ignored, so a dual-signed
  rotation release stays verifiable by old and new verifiers alike. The policy
  is evaluated over the trusted keys that verified.
- **Manifest key list.** The manifest's own `key_id` list must equal the set
  of listed keys, which binds the signer set into the signed bytes.

**Strict decoding (Go and C++).** A token-level pre-pass runs before struct
decoding. It requires a byte-exact key allowlist per object and rejects
duplicates by byte equality. It also rejects invalid UTF-8, escapes in keys,
non-integers, numbers above 2^53 and trailing data. Case-insensitive field
matching (Go) and last-key-wins duplicates (Qt) therefore cannot matter.

**Publishing rules.** Backfill is retired: nothing signs metadata for an
existing release from its current assets or with today's
`compatibility.json`. The publisher never signs a schema 1 manifest for a
store-era version. Desktop 0.3.x accepts only `schema: 1` and single-line
signatures, so it fails closed on every store-era release. The first store-era
version must be higher than every pre-store release. The publisher also bounds
version jumps: a new release may raise the major or minor component by at most
one step above the newest published release. A larger jump is refused, because
"never below active" makes a mistaken tag such as `v4.0.0` permanent on every
machine that installs it.

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
| Freshness | `F` | Scheduled job | Signs only the freshness index; never trusted for code, trust or gating floors |
| Historical | Retired `R` and hardware keys | Not used for signing | Re-verifying evidence already stored in admin-only `state/` and `versions/`; never accepted for streamed bytes, fetched manifests or elevation |

Core and Desktop embed the same reviewed trust file, `release/trust.json`. It
lists public keys, key IDs, roles and the YubiKey attestation material.

#### Signature policy

- **Ordinary release**: valid signatures from `R` **and** from at least one
  hardware key in the current trust set.
- **Floor-epoch raise** (key-compromise recovery only): `R` **and** every
  hardware key in the current trust set.
- **Epoch comparison**: a verifier requires the epoch policy whenever the
  manifest's floor epoch is higher than its own committed epoch.

Verifiers enforce the policy over the trusted keys that verified. Without both
a release key and a hardware key, nothing can be installed, and no single
stolen secret or lost device can lower a floor.

#### Bridge releases and update selection

- **Bridge releases.** Trust-set changes and epoch raises ship only in a
  bridge release.
  - The bridge's signer set must satisfy two policies. Under the previous
    trust set, it must meet the ordinary policy, or the epoch policy for an
    epoch raise. Under the trust set embedded in the bridge itself, it must
    meet the ordinary policy. Each count uses only active release and
    hardware keys.
  - A bridge that rotates `R` is therefore signed by both the old and the new
    `R`. This lets a committed bridge pass its own self-check, and lets it be
    repaired from a streamed bundle.
  - The publisher checks both policies before it publishes.
  - Bridge releases are never deleted.
  - Every manifest names the previous bridge's tag and manifest digest, so
    Desktop can fetch the bridge chain directly, even when old releases have
    dropped off the release listing.
- **Update selection.** It repeats the following, for at most 8 hops: pick the
  newest release that the current broker's trust set and epoch can verify,
  then install it.
  - Each hop must be strictly above the active version. Otherwise selection
    stops; it never re-prompts without progress.
  - If no verifiable path exists within the hop limit, Desktop reports that a
    package upgrade is required.
  - A release that cannot be verified is an update error only when no
    verifiable path to it exists. A post-bridge release that is merely not yet
    reachable is not an error.
  - A machine that is several releases behind therefore crosses rotations,
    revocations and epoch raises in order.
- **Choosing the hop.** `version -json` reports a binary's trust key IDs and
  roles, and the session `status` reports the committed epoch. Desktop selects
  hops from that data and from verified manifests only. Marks in the freshness
  index are hints that do not affect the choice.
- **Which keys count, by context.**
  - For streamed bytes, fetched manifests and self-checks, only active release
    and hardware keys are trusted.
  - Historical keys count only when re-verifying evidence already stored in
    admin-only `state/` and `versions/`, with the ordinary policy.
  - `F` counts only for the freshness index.
  - Historical keys are never removed, except by an epoch reset, so stored
    evidence keeps verifying.
- **Desktop trust (Q10, recommended, pending).** Desktop accepts a manifest
  that verifies under its embedded trust set, or under the trust set of the
  newest committed store Core. That store Core was itself verified through
  the bridge chain. Desktop is not the security boundary, so this widening is
  acceptable, and trust changes then need no Desktop package release.
  - If Q10 is adopted, Desktop uses one trust set rather than the union of the
    two: the set of the higher-versioned binary among its pinned Core and the
    newest committed store Core. A union would keep accepting keys that the
    newer set has retired.
  - Desktop obtains that trust set from `version -json`, never by parsing the
    binary.

#### YubiKey requirements

- **Supported models.** YubiKey 5 Series devices (5 NFC, 5C, 5C NFC, 5Ci,
  5 Nano, 5C Nano), their FIPS equivalents, or the Bio Series Multi-protocol
  Edition with PIV. Security Key Series and FIDO-only Bio devices cannot be
  used. Firmware cannot be upgraded, so check each device with `ykman info`.
- **Firmware 5.7.0 or later (preferred).** Use a PIV Ed25519 key in a
  dedicated slot (for example `9c`), generated on the device. A PIV
  attestation certificate exists only for keys generated on the device. The
  ceremony checks its PIN and touch-policy extension
  (`1.3.6.1.4.1.41482.3.8`) and the GET METADATA origin. Signing uses
  `yubico-piv-tool`, `ykcs11` (`CKM_EDDSA`) or yubikit; `ykman` has no raw PIV
  sign command. Firmware 5.7+ is also outside the scope of the Infineon ECDSA
  side-channel advisory (YSA-2024-03).
- **Firmware 5.2.3 to 5.6.x.** Use the OpenPGP application's Ed25519 signing
  key, generated on the device. Attest it with
  `ykman openpgp keys attest sig`. Signing uses a direct `PSO:COMPUTE DIGITAL
  SIGNATURE` over the 32-byte message, sent through yubikit or PC/SC. The
  advisory concerns ECDSA; Ed25519 is Yubico's stated mitigation, and the
  attack also needs physical possession.
- **Firmware below 5.2.3** has no Ed25519 support and cannot be used.
- **Raw signing.** Each applet must produce a raw PureEdDSA signature over the
  32-byte message. Before the format is frozen in Go, C++ and the publisher,
  the ceremony checks this on the actual devices against a test vector, using
  `crypto/ed25519.Verify` and the Desktop verifier. A path that can sign only
  through OpenPGP packet framing is not used.
- **Device policy.**
  - Each key is used only for Bimeron release signing, never for git, SSH or
    email.
  - Touch policy is `always` for PIV and `fixed` for OpenPGP.
  - PIN, PUK and management key are non-default.
  - The PUK may be deliberately blocked on these signing-only devices, so a
    thief gets only the PIN attempts.

#### Key ceremony

The ceremony record, `release/trust/CEREMONY.md`, contains public data only.

1. Record each device's model, firmware and serial number.
2. Generate the signing key on the device. Export the public key and the
   attestation certificate, together with the Yubico attestation chain.
3. Verify the attestation offline: the chain to the Yubico root, the serial
   number, and the policy extension or origin for the applet used.
4. Generate the new release key `R2` on an offline machine. Make two
   encrypted offline backups, stored in separate places.
5. Sign the test message with each key and verify it in Go and C++, including
   strict-verification edge cases.
6. Commit `trust.json` and the attestation files in a reviewed change. Store
   `H2` in a different place from `H1`.

#### Planned rotation of the current release key

Treat the current release key `R1` (key ID `7370a2d8cf890e5e`) as possibly
exposed. Store-era builds never trust it. Their trust set is `{R2, H1, H2}`
from the first store-era release onward. `R1` remains only in pre-store
clients and is used, if at all, solely for schema 1 releases to pre-store
Desktops until those leave support.

Exposure of `R1` alone cannot authorize anything for store-era clients. Its
residual impact on pre-store Desktops ends when the package is upgraded; that
is a separate incident-response decision.

Later rotations of `R` use bridge releases:

1. A bridge release, signed with `R(n)` and a hardware key, adds `R(n+1)`.
2. Releases are dual-signed by `R(n)` and `R(n+1)`, plus a hardware key,
   until the minimum supported store-era Core and Desktop trust `R(n+1)`.
3. A later bridge release moves `R(n)` to the historical role.

#### Lost or compromised YubiKey

- **Losing one YubiKey** does not stop releases: they continue with `R` and
  the remaining device. A thief also needs the PIN and the release key `R`.
- **Revocation:**
  1. Enroll a replacement device `H3` through the ceremony.
  2. Publish a bridge release, signed with `R` and the remaining device. It
     moves the lost key to the historical role, adds `H3`, and raises the
     **security** floor to its own version.
  3. Machines stop installing builds that trust the lost key as soon as they
     reach this release.
  4. The elevation floor is not raised. Raising it would force a package
     upgrade everywhere, and a forgery with the lost key alone would still need
     `R`.
- **Losing both YubiKeys**, or having one physically stolen when a full epoch
  raise is needed, leaves no signing policy that old builds accept. The only
  recovery is a Desktop package release whose bundled Core carries the new
  trust set. The trust root is then the administrator who installs the
  package. This is why the spare is stored separately.
- **If `R` and a YubiKey are compromised together**, take these steps:
  1. Publish a bridge release signed with the old `R`, the new `R`, and every
     hardware key still held, meeting the bridge rule above. It raises the floor epoch and both floors, and rotates `R`.
  2. If a compromised hardware key is not in the maintainer's possession, the
     epoch policy cannot be met, and only the package-release path remains.
  3. Machines are protected only after they reach the bridge release or the
     new package.
- **Compromised machines.** An administrator can reset the store of a machine
  by deleting `state/` and `versions/`. That is an administrator action
  outside the threat model, and it is documented in `SERVICE.MD`.

#### Freeze resistance and Core trust

Core never fetches trust updates. Trust changes ship only inside new signed
binaries delivered by bridge releases. There is no online key-set document with
a freshness or rollback problem of its own.

### Version comparison rules

**Grammar.** One grammar, already enforced by `repair_acquire.go`, applies to
every Core version everywhere: tags without the leading `v`, manifests,
floors, store directory names, `hello`, and `version -json`.

```text
version    = core [ "-beta." number ]
core       = number "." number "." number
number     = "0" | nonzero *digit        ; ASCII digits only, no leading zeros
```

- Each number is at most `2147483647`. Longer or larger values are rejected,
  not truncated.
- The whole string is ASCII, at most 64 bytes, with no surrounding whitespace
  and no trailing newline.
- `beta` is the only prerelease identifier, always lowercase and always
  followed by exactly one number (`-beta.0` is valid).
- Everything else is rejected: build metadata (`+...`), other identifiers
  (`-rc.1`, `-alpha.1`, `-Beta.1`), extra dot-separated fields (`-beta.1.2`),
  and a bare `-beta`.
- Tags are `v` followed by a version. The publisher refuses any other tag.
- A store directory name must equal the canonical string byte for byte, so
  NTFS case folding cannot alias two versions.

**Precedence.** These are the SemVer 2.0 rules restricted to this grammar:

1. Compare `X`, `Y` and `Z` numerically, in that order.
2. If the cores are equal, a beta version is lower than the release without
   the suffix: `1.2.3-beta.7 < 1.2.3`.
3. If both are betas of the same core, compare `N` numerically:
   `1.2.3-beta.2 < 1.2.3-beta.10`.
4. Two versions are equal only if their strings are byte-identical, which the
   grammar makes equivalent to rule-equality.

Comparison is numeric, never lexicographic. Implementations parse into
integers and never compare strings.

**Floors and channels**

- **A release's channel is derived from its version**: `beta` exactly when
  the version has a `-beta.N` suffix, otherwise `stable`. The manifest's
  `channel` must equal that. The unsigned GitHub `prerelease` flag is never
  trusted.
- A stable-channel manifest's floors must be stable versions. A beta-channel
  manifest's floors may be betas.
- A floor applies machine-wide once it is committed (sources 1–3). A machine
  that committed a beta, for example the bundled bootstrap, also committed that
  beta's floors. A beta floor therefore binds only machines that have run a
  beta.
- A machine follows the union of the user's update channel and the channel of
  its active version. A machine running a beta, including a stable-preference
  machine whose bundled Core is a beta, therefore keeps receiving beta updates,
  announced floors and freshness entries until it reaches a stable release.
- Announced floors come only from manifests of the followed
  channels.
- The publisher refuses a floor lower than the previous release's floor in the
  same channel, unless the floor epoch increases. It also refuses a stable
  floor higher than the newest stable release including this one, so stable
  users can always satisfy it.
- Moving from beta to stable remains subject to "never below active": a
  machine on `0.5.0-beta.3` moves to stable only with `0.5.0` or later.
- **Fix ancestry (Q11, recommended).** A version floor claims that every
  version at or above it contains the fix. `compatibility.json` records the
  fixing commit or commits for each floor. The publisher refuses to publish a
  floor, or any later release at or above it, unless every published tag at
  or above the floor contains those commits (`git merge-base --is-ancestor`).
  As a consequence, a maintenance line below a raised floor can no longer
  publish releases.

**Tests (shared by Core and Desktop)**

`release/testdata/version-order.json` is the single conformance file. Go and
C++ tests, both run in CI, must agree on all of it:

- **Valid ordered sequence.** Every adjacent pair is strictly increasing. The
  sequence includes at least:

  ```text
  0.0.0 < 0.0.1-beta.0 < 0.0.1-beta.1 < 0.0.1-beta.2 < 0.0.1-beta.10
        < 0.0.1 < 0.1.0-beta.1 < 0.1.0 < 0.9.0 < 0.10.0 < 1.0.0-beta.1
        < 1.0.0 < 1.0.1 < 2147483647.2147483647.2147483647
  ```

  It also contains every published tag: `0.1.0-beta.1` through
  `0.4.0-beta.1`, and each later release.
- **Equality.** Every valid entry equals itself and nothing else. Parsing and
  then formatting returns the input bytes unchanged.
- **Rejected forms**, each with a reason code:
  - zero padding: `01.2.3`, `1.02.3`, `1.2.03`, `1.2.3-beta.01`;
  - other prerelease forms: `1.2.3-beta`, `1.2.3-Beta.1`, `1.2.3-BETA.1`,
    `1.2.3-rc.1`, `1.2.3-alpha.1`, `1.2.3-beta.1.2`, `1.2.3-beta.-1`;
  - build metadata: `1.2.3+build`, `1.2.3-beta.1+x`;
  - wrong shape: `v1.2.3` as a version, `1.2`, `1.2.3.4`, empty string;
  - whitespace: leading or trailing space, trailing LF or CRLF, NUL;
  - non-ASCII digits: Arabic-Indic and full-width;
  - overflow: `2147483648.0.0`, `1.2.3-beta.2147483648`;
  - more than 64 bytes.
- **Properties.** A Go property test checks total order over generated valid
  versions: antisymmetry, transitivity, and agreement with a reference
  implementation that sorts parsed integer tuples. A Go fuzz test checks that
  the parser never accepts a string whose canonical form differs from it.
- **Floor rules.**
  - A floor above the manifest's own version is rejected, and so is a beta
    floor in a stable-channel manifest.
  - A publisher regression without an epoch raise is rejected.
  - With an epoch raise signed under the epoch policy, a lower floor is
    accepted.
  - Stable-only machines ignore beta announced floors, except while their
    active version is a beta.
  - Channel derivation is tested, including a beta manifest that claims
    `stable`, and a stable-preference machine running a bundled beta.
  - Epochs are integers from 0 to 2147483647. `security_floor.epoch` must
    equal `elevation_floor.epoch`.

### Effective floor

There are two kinds of floor, and they are never mixed.

**Committed floors** come from local, signed evidence. For each floor kind
(security and elevation), find the highest epoch among the evidence. Within
that epoch, the committed floor is the highest version over these sources:

1. The floors compiled into the verifying binary. Core embeds
   `release/compatibility.json`; Desktop embeds the floors of its pinned Core.
2. The floors in the verified manifests of all committed versions in
   `versions/`.
3. All valid `state/floor-<seq>.json` records. Each one holds the exact
   manifest bytes and signatures that established it, so it verifies itself.
   The same evidence is kept in the HKLM or `/etc` copy.

Evidence in sources 2 and 3 is re-verified with the current trust set,
including keys in the `historical` role (see Trust and keys). A key rotation
or revocation therefore never discards floors that were already established.

**Evidence a verifier cannot evaluate.** Some evidence an older binary cannot
evaluate:

- a `versions/` entry, active record, floor record or HKLM//etc copy that
  names a version above the verifier's own version;
- evidence that lists key IDs absent from the verifier's trust set;
- evidence with an epoch the verifier cannot verify.

When a privileged process finds such evidence, it does not ignore it. It
treats the store as read-only, refuses every elevated role except `status`,
and reports `newer-component-required`. The only exception is finishing the
post-`ready` steps of, paying the promotion debt of, or republishing, the
active version itself, which lifts only the "version above own" trigger (see
Finishing the active version with an older broker; pending owner decision
Q12). "Ignored and
reported" applies only to records whose signatures fail under keys the verifier
knows. An older package
copy elevated after a rotation therefore cannot evade a newer elevation floor
or the active version.

**Active records are not publisher-signed.** They are local, admin-only state,
trusted through the store ACL, and they carry the version and manifest digest
of the active release. "Never below active" therefore uses the active record
directly, whatever keys the verifier knows.

**Announced floors** come from freshly fetched signed manifests of the followed
channels, and from the freshness index. They never gate repair to the
committed target, the foreground daemon, the unelevated CLI, or IPC and VPN
connections through the installed service.

- An announced floor causes a persistent "security update required" state, and
  it ranks updates.
- An announced elevation floor from a manifest signed by the release key and
  a hardware key additionally gates the `update` operation only.
  - It never gates `install`, `repair` or missing-service installation; those
    show a warning instead.
  - Below it, Desktop requires a package upgrade before updating.
- A floor that comes only from the freshness key `F` never gates anything.
- **Epochs.** Announced floors from an epoch below the committed epoch are
  ignored. Announced floors from a higher epoch count only if their manifest
  meets the epoch policy.

Only a privileged Core process writes floor records. It appends a floor only
after a switch to a version at or above that floor has committed. A record
that fails verification is ignored and reported; the remaining evidence still
applies. Deleting or reverting one record, or one location, cannot lower a
committed floor while other evidence remains. No command deletes or lowers
floor or active evidence.

A whole-machine or VM-snapshot restore reverts all sources together. That is
outside the local-attacker model. Announced floors then show the
"security update required" state at the next online check, but they do not
restore the lost floors.

**Enforcement of committed floors**

- No version below the security floor is installed, switched to, or used as a
  repair source.
- No elevated process runs below the elevation floor.
- A binary below the security floor may run elevated only to install or repair
  to a release at or above that floor, and only if it is itself at or above
  the elevation floor.
- Each raise of the elevation floor requires a Desktop package that bundles a
  Core at or above it. Machines whose broker is below the raised floor must
  upgrade the package. The release process plans such a raise as a coordinated
  Core and Desktop release.

**Below-floor service (decided).** A service below the committed security floor
does not block the VPN. The service and Desktop report `below_security_floor`,
and Desktop offers repair.

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

The first request names one operation: `update`, `repair`, `install` or `status`
(see Session operations).
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
  - the broker's own version must be at or above the committed elevation floor;
  - the new `core_version` must be at or above the committed security floor;
  - the new `core_version` must be at least the maximum of the active version
    and the verified installed version.
- Equal versions are accepted only when the bytes are identical (republishing).
- The archive is checked against its target: OS and architecture, ZIP size and
  SHA-256, and structure (no traversal, symlinks or duplicates; exactly the
  expected members).
- Each member is checked for size and SHA-256, and the executable's Go module
  and machine identity are verified.

**Switch and commit**

**Scope of the store lock.** A mutating session (`update`, `repair`, `install`
or the installer action) acquires the store lock right after it reads the
request, and holds it until it exits. Staging is created and streamed only
under the lock, so no other session's cleanup can touch it.

- The lock is released by the kernel when its holder dies (logoff, kill), and
  it never survives a reboot. No stale-lock recovery is needed.
- A process that cannot acquire the lock does not touch the journal or the
  service. It reports `store-busy`. `status` probes the lock without blocking
  and reports `switch-in-progress` or `switch-pending`.
- The installer action does not wait. On `store-busy` it leaves the work to
  the Desktop fallback.

**Other locks.** The session still holds the existing installation
transaction, which excludes the foreground daemon. An abandoned pre-store
mutex combined with a pending journal goes to reconciliation, not to manual
review.

**Compare before every mutation.** Pre-store writers never take the store lock,
so every mutation first re-reads the registration and member identities.

- In a live session, the compare expects exactly the state the session itself
  produced.
- In reconciliation, it accepts every state reachable from the journal:
  - each member at its target, backup, temporary or trash name;
  - the old or the new registration;
  - any run state;
  - recovery suspended or canonical.
- Any other state is a deviation. In a live session, a deviation aborts with
  `concurrent-change`. In reconciliation, it means `journal-unrecoverable`,
  which has the `abandon-switch` exit.

**Refusals before `begin`.**

- A disabled Windows start type or a masked Linux unit is refused with
  `service-disabled`.
- Any blocking handle on a service-directory member is refused with
  `service-file-busy` (see the `copy` step).

**Journal rules**

- **R1 Write-ahead.** `state/switch.json` holds a journal ID, the operation, the
  store contract and `next: <step>`.
  - **Atomic replacement.** Windows uses `SetFileInformationByHandle` with
    `FileRenameInfoEx`, `FILE_RENAME_FLAG_POSIX_SEMANTICS` and
    `FILE_RENAME_FLAG_REPLACE_IF_EXISTS`, which can replace a file that
    readers hold open; this is verified on the VM. Linux uses `rename` plus a
    directory fsync.
  - **Write order.** Before each step's effect, the broker durably writes
    `next` together with every name that step will use. After a crash, the
    step named in `next` may or may not have happened. Nothing changes before
    `begin` is durable.
  - **Readers.** Only lock holders read the journal. The service, the
    foreground daemon and Desktop read only the `switch_pending` marker in the
    HKLM or `/etc` copy.
- **R2 Observation-guarded and idempotent.**
  - Every forward action and every undo first observes the actual state: the
    identity of the objects at the target, backup, temporary and trash names;
    the loaded registration (`QueryServiceConfig`, `systemctl show`); and the
    recovery configuration. It acts only if needed.
  - Renames of service-directory members use no-replace semantics:
    `MoveFileEx` without `REPLACE_EXISTING` and with `WRITE_THROUGH`, or
    `renameat2(RENAME_NOREPLACE)` plus a directory fsync. Journal and unit
    replacement follow R1 and R5.
  - "Remove" always means a rename into `trash/` on the same volume, never a
    delete that could leave a delete-pending name.
- **R3 Old-image safety.** Before `ready`, no action deletes, overwrites or
  moves an object whose file ID was journaled at `begin` as an old member. The
  only exception is renaming it between its target name and its journaled
  backup name. From `ready` on, `finish` may move it to `trash/`.
- **R4 Commit point and direction.** `ready` is a record with no effect. It is
  written only after the `start` step has passed readiness and restored the
  recorded run state.
  - **Per-journal direction.** Direction is decided for the whole journal,
    never per member. Before `ready`, reconciliation goes backward.
  - **The one forward exception** applies only when some old member was
    journaled absent at `begin` (repair of a missing image) and the operation
    is not `install`. Then all members move forward together. The source is
    only the journaled source with the journaled new digest, re-verified
    under the reconciler's trust, floors and never-below-active. The package
    bootstrap is never substituted.
  - **A failed forward attempt** goes backward to the journaled pre-switch
    state and closes the journal as a failed repair.
  - **From `ready` on,** reconciliation goes forward only.
- **R5 Configuration durability.**
  - **Windows.** After every SCM change (`ChangeServiceConfig`,
    `ChangeServiceConfig2`, `CreateService`), call `RegFlushKey` on the
    service key. After `DeleteService`, flush the parent `Services` key. Both
    happen before the next journal write or the journal's deletion.
  - **Linux.** After every unit change, fsync the file and its directory, run
    `daemon-reload`, and verify `FragmentPath`, `ExecStart` and
    `DropInPaths`.
  - **Reconciliation** reads the actual configuration and never assumes it
    from the journal.
- **R6 Once per journal.** Each step runs at most once per journal ID in a
  session.
- **Undo-side stop.** Every undo that stops the service treats "stopped, with
  no process left" (`ProcessId 0`, `MainPID 0`) as stopped, whatever the exit
  code. An unclean exit is not an undo failure.
  - **Hung service.** If the service does not stop within the stop budget (for
    example, it hangs in start-pending without accepting a stop), Windows
    terminates the identity-checked service process through a retained
    `PROCESS_TERMINATE` handle and waits for `ProcessId 0`. Linux relies on
    `TimeoutStopSec` and the systemd kill. Either way, the result counts as an
    unclean exit.
- **Network cleanup before starting the old image.** Cleanup is required when
  owned markers are pending (Windows: the WFP and NRPT markers; Linux: the
  write-ahead cleanup journal) or when the last exit was unclean. Marker
  absence after an unclean exit is not cleanup proof.
  - With network-recovery consent, the undo runs the existing `Recover` path.
    A successful `Recover` in the same session is the cleanup proof.
  - Without that consent, the undo never starts the old image. It restores
    the members and the registration, leaves the service stopped, and closes
    with `rollback-incomplete`. A later repair runs `Recover`.
  - The installer action's package-operation consent covers disruption only,
    never network recovery.
- **Undo failure accounting.**
  - Before reporting `rollback-failed`, the broker durably records the failing
    step in the journal (under R1). The in-session failure counts as the
    first.
  - Any failure of the same step in a later session, whatever the error,
    means `journal-unrecoverable`.
  - Failures to restore the run state or the recovery settings never count.
    They yield `rollback-incomplete`, in the session and in reconciliation
    alike.

**Member set.** The journal covers every member of the service directory:
`bimeron.exe`, `wintun.dll` and `WINTUN-LICENSE.txt` on Windows, and the
executable on Linux. For each member it records:

- the old file ID and digest, or "absent";
- the new digest;
- the target, backup and temporary names.

A member whose old and new digests are equal is journaled `unchanged`. It is
neither copied nor swapped, but its ACL is still reset (see `copy`). A backward
run therefore never leaves the old executable with the new DLL.

**Service-directory protection.** In store-capable builds, the service
directory's DACL grants `Users` no inheritable file access. Every member,
temporary name and backup name has a DACL that grants access only to `SYSTEM`
and `Administrators`. Temporary names get that DACL atomically at creation.

**Steps.** Each row is preceded by its durable `next` record. Backward undos are
applied in reverse order.

| `next` | Forward effect | Backward undo (guarded) |
| --- | --- | --- |
| `begin` | Create the journal: operation, ID, contract, per-member records, the full old and new registration, the run state, and the source (`staging/<r>` or `versions/<v>`). Write and flush the display-only `switch_pending` marker (journal ID, operation, time) in the HKLM or `/etc` copy | Remove staging (unless the source is in `versions/`), clear the marker, delete the journal |
| `copy` | 1. Open each existing old member with `DELETE \| WRITE_DAC` and share mode `FILE_SHARE_READ \| FILE_SHARE_DELETE`, which is compatible with the running image's mapping. A sharing violation means a handle that would block a rename: refuse with `service-file-busy`, naming the process through Restart Manager. Otherwise apply the admin-only DACL through the handle. 2. Copy each changed new member from the held staging handle to its temporary name (create-new, flush). This happens before any disruption, so a full disk fails harmlessly | Remove the temporary names |
| `suspend` | Turn recovery off. Windows: no SCM failure actions. Linux: a runtime drop-in, `/run/systemd/system/bimeron-core.service.d/50-bimeron-switch.conf`, with `Restart=no`, which a reboot clears | Set the canonical recovery settings |
| `stop` | Stop the service, with the existing stop and cleanup proof | Restore the recorded run state, after the old members and registration are back and after network cleanup (above) |
| `register` | Windows: `ChangeServiceConfig` with only `BinaryPathName` changed (`SERVICE_NO_CHANGE` for the rest), or `CreateService` for `install`. Linux: write the new unit atomically, then `daemon-reload`. Then apply R5 and verify the loaded configuration | Restore the old registration only after every old member is back. For `install`, delete the registration only if it equals the journaled new one. If `DeleteService` leaves the service marked for deletion, report `install-cleanup-pending`, never retry `CreateService`, and let the next session finish the deletion. The install undo also removes, by guarded rename, the event-log source and the service directories that the journal records as created |
| `swap-out` | For each changed member: rename target → backup (no-replace) | For each changed member: if the target is absent and the backup holds the journaled old file ID, rename backup → target |
| `swap-in` | For each changed member: rename temporary → target (no-replace). On Linux the target is the new executable path | For each changed member: if the target holds the new digest, move it to `trash/`. On Linux this includes the new-path executable |
| `start` | If the service is running (for example a boot start), stop it. Start it with a fresh readiness nonce and wait for readiness. Then restore the recorded run state, stopping the service again if it was stopped | Undo-side stop |
| `ready` | No effect: the commit record | (commit point) |
| `resume` | Canonical recovery settings | — |
| `record` | Active and floor records; the HKLM or `/etc` copy without the marker; flush | — |
| `promote` | See Promotion | — |
| `finish` | Move the backups to `trash/`, then delete the journal | — |

**Readiness nonce.**

- Windows: the nonce is passed in the `StartService` arguments, and the
  service names its readiness pipe after it.
- Linux: `systemctl start` takes no arguments. Before the start, the broker
  writes the nonce to a 0600 root-owned file in `/run/bimeron/`. The service
  reads and deletes it, then binds the readiness socket under that name. The
  broker also checks that the socket's peer PID equals `MainPID`.
- A start without a nonce (boot or recovery) opens no readiness channel.

**Recovery settings.** The canonical recovery settings are constants: today,
restarts after 5 s and 15 s, then none, with a reset after 86400 s on Windows;
`Restart=on-failure` with `RestartSec=5s` on Linux. They are not journaled
originals, so a lost journal cannot lose them. Store-era inspection treats
non-canonical recovery settings, or a leftover switch drop-in without a
journal, as a repairable defect. While recovery is suspended, the service
reports `recovery-suspended`, and Desktop prompts the user to reconcile.

**Promotion**

- **Absent.** If `versions/<v>` is absent, the broker renames staging into
  place. Before the rename, it reopens the staging handles with
  `FILE_SHARE_DELETE` (still denying write), so it does not block its own
  rename.
- **Final permissions.** Promotion ends by applying the `versions/`
  descriptor (Linux: modes) by handle to the directory and every member.
- **Exists.** `versions/<v>` counts as existing and intact only if its
  manifest digest equals the journaled one, every member verifies, and its
  owner, DACL and mode are those of `versions/`. Otherwise the broker repairs
  it in place: it replaces damaged members one by one, by handle, and resets
  the permissions.
- **Blocked or missing.** If promotion is blocked (for example by a foreign
  handle, or by the broker's own image in the target directory), or if the
  staging entry is missing, the broker reports `store-copy-pending`. It then
  runs `finish` and closes the switch journal.
  - **Promotion debt.** The open promotion is recorded separately in
    `state/promote-pending.json`, with the manifest digest and the staging
    name. Cleanup never removes the staging entry it names.
  - **Paying the debt.** Every mutating session tries to pay the debt first,
    by promoting from the verified staging entry. A failure never blocks the
    requested operation when the broker is at or above the active version.
  - **Missing store copy.** If the staging entry is missing or does not
    verify, the debt becomes "store copy missing". Repair resolves it by
    asking Desktop to stream the active bundle (the republish branch below).
  - Floor records carry the exact manifest bytes, so they do not depend on
    `versions/`.
- **Re-verification failure.** If re-verification fails after `ready` (for
  example, the reconciler is a newer package with a higher compiled floor),
  the broker closes the journal without promotion. The installed image is
  then handled by the Repair rules.

**Finishing the active version with an older broker (pending owner decision
Q12).** After a commit, the only binary for the active version may sit in
staging, or it may have been quarantined from `versions/<active>`. In that
case, every remaining broker may be below the active version. Under Effective
floor, such a broker makes the store read-only.

As an exception, that broker may run exactly one operation per session:

1. finish the post-`ready` forward steps (`record`, `promote`, `finish`) of a
   pending switch journal;
2. pay a promotion debt;
3. republish `versions/<active>` from a streamed bundle.

Each operation is allowed only if all of these hold:

- **Floor.** The broker is at or above the committed elevation floor. All
  floor evidence, including the active manifest's epoch, must verify under the
  broker's own trust set and epoch rules. The exception lifts only the
  "names a version above its own" trigger, and none of the others.
- **Manifest.** The journaled or streamed manifest decodes under the broker's
  own schema, its digest equals the one in the journal and the active record,
  and the broker's trust set verifies it.
- **Staging.** Staging members are re-verified by handle before any rename.
- **Store contract.** The broker's store contract covers the journal and the
  store.

The exception has strict limits:

- **Evidence.** The broker never writes evidence other than the pending
  journal's own `record` set, taken from the journaled manifest. It never
  changes the service or the registration.
- **Journals before `ready`.** The broker never reconciles a journal that has
  not reached `ready`. Its only possible operation there is a republish.
- **Session end.** The session ends with `broker-changed`, and Desktop re-runs
  broker selection, which now finds the active version in `versions/`.
- **Package upgrade.** If any condition fails (for example, the active release
  raised the elevation floor above every remaining broker, or added keys or a
  schema the broker cannot verify), the result is "package upgrade required".

The alternative under Q12 is to have no exception: losing the active store
copy then always requires a Desktop package release. That would tie Core
recovery to Desktop releases again.

**"Installed"** always means the image at the path the current registration
names.

**Failure before `ready` within the session** runs the backward procedure
immediately. Once every old member and the old registration are restored, the
journal closes in a fixed order: remove the temporary names and staging,
clear the `switch_pending` marker, then delete the journal. The run state and
recovery settings are restored before closing where possible.

- A failure to restore the run state or the recovery settings is reported as
  `rollback-incomplete`, and it does not keep the journal.
- If restoring a member or the registration fails, the journal is kept, the
  service is stopped where possible, and the result is `rollback-failed`.

**Crash points**

Only `update`, `repair`, `install` and the installer action reconcile. They do
so under the store lock and after reading the request:

- **Consent.** Reconciliation runs under the existing disruption consent. For
  the installer action, the package operation itself is the consent. If the
  user refuses, nothing changes and the session reports `switch-pending`.
- **Scope.** If reconciliation changed the service or the images, the session
  ends with `reconciled`, and Desktop restarts the requested operation. That
  means a second prompt, and only after a crash. Forward bookkeeping after
  `ready` needs no disruption consent, so the session continues.
- **Read-only processes.** `status`, the foreground daemon and the service
  only report a pending journal. Desktop reads the `switch_pending` marker and
  shows a pending switch, not damage.
- **Budgets.** Each transaction (reconciliation, then the requested operation)
  has its own deadline. The rollback budget is at least the platform's stop
  timeout.

From the observed state and `next`:

- **Before `ready`:** a backward run first applies the undo-side stop when
  `next` is after `stop`, or when the running image's file ID is not the
  journaled old member, if the service is running or start-pending. A crash
  at `copy` or `suspend` therefore does not interrupt a healthy old image. The
  run then goes backward through the table, guarded by observation, whatever
  image is present or missing.
  - R4's single forward exception still applies.
  - `install` journals always go backward.
  - Restoring the journaled pre-switch image is not an installation. It is
    allowed below the committed security floor (Q4), and it reports
    `below_security_floor`.
- **From `ready` on:** the broker goes forward through `resume`, `record`,
  `promote` and `finish`.
- **`journal-unrecoverable`.** An old member whose journaled file ID is found
  under none of its journaled names means `journal-unrecoverable`. So does an
  undo that fails the same way in two reconciliations, and so does a state that
  no journaled step can reach.

**Unreadable or unrecoverable journals**

- A journal that cannot be parsed blocks every mutating operation with
  `journal-corrupt`. It is never deleted automatically.
- A journal from a higher store contract makes the store read-only.
- The only exit for `journal-corrupt` and `journal-unrecoverable` is an explicit
  repair with an additional consent, `abandon-switch`. It runs at most once per
  session:
  1. Verify that a source exists for step 4: the committed target, or the
     verified package bootstrap if nothing is committed. Otherwise refuse with
     `store-unavailable`, and change nothing.
  2. Rename the journal to `state/switch-abandoned-<seq>.json` (kept for
     diagnostics, never read by reconcilers), and clear the `switch_pending`
     marker.
  3. Restore the canonical recovery settings.
  4. Run an ordinary repair transaction under a new journal. It keeps the
     owner read from the actual registration, and uses `install` only when
     nothing is registered. Floors and never-below-active apply.
  5. Only after the new switch commits, move leftover random-suffix files in
     the service directory to `trash/`.

**Boot during a pending journal.** A boot or recovery start of a
not-yet-committed image is acceptable. That image is verified, it is at or
above both the floors and the active version, and the floors have not
changed. Such a start opens no readiness channel. The next reconciliation stops
it first and reverts it, with one disruption. While a journal is pending, every
service-side persistent format must stay readable by the old image.

**Registration order.** The registration changes before the image moves, and it
is restored only after the old image is back. An intermediate state, an old
image under the new registration, fails closed: a pre-store image refuses to
run with the extra argument, and pre-store tools refuse the new registration.
A store-era image is never left under the four-argument registration.

**Wintun**

The store keeps the signed sidecar. The service-directory copy is checked
against its signed or pinned digest at every service start, before loading.
Each elevated mode and the service call
`SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` and load Wintun by its
verified full path.

**Legacy command**

The legacy `service update -source` command is refused by store-capable builds,
with a message naming the maintenance session.

**Session operations**

- **`update`** streams a newer release and switches to it.
- **`repair`** restores the committed target. If no local source verifies, it
  asks Desktop to stream the target bundle.
- **`install`** handles first installation, with no service registered:
  1. It takes the service owner from the authenticated caller.
  2. It switches from the verified package bootstrap, or from a streamed
     bundle, through the same journaled path.
  3. After readiness, it promotes the bundle and writes the records.
- **`status`** is read-only. It reports the store, journal and registration
  state, and the committed floors, to the authenticated caller.

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
| Maintenance session (`update`, `repair`, `install`, `status`) | The highest-version verified binary among all committed versions present in `versions/` and the bundled package copy, at or above the committed elevation floor. If the newest candidate does not verify (missing, damaged, quarantined), Desktop falls back to the next one. A newer package copy therefore steps in after a package upgrade, even when commit actions did not run | Desktop: handle-bound digest. Broker: self-check | Nonce, PID, streamed bytes |
| Installer action (MSI, DEB) | `bimeron-core` in the package directory, run directly as SYSTEM or root | Self-check against the package-shipped signed manifest | None; fixed package-relative paths |
| Foreground IKEv2 daemon | Same as the maintenance session | Self-check | Existing foreground contract; policy file at a fixed location (below) |
| Service | Service directory copy | No self-check (see below); Wintun pin at load | SCM or systemd only |
| RepairBootstrap (Desktop) | Retired | n/a | n/a |

**Foreground policy file**

The per-installation `bimeron-foreground.json` moves to a fixed admin-only
location under the Core root: `%ProgramFiles%\Bimeron Core\policy\` or
`/usr/local/lib/bimeron/policy/`. Only privileged processes write it. It is
never read from the executable's own directory.

**Elevated self-check** (maintenance session, installer action and foreground
daemon only)

1. It locks its own image by handle. The handle path and file ID must lie under
   the fixed store root, or under the fixed package directory, reached by the
   handle-relative walk. A genuine binary copied or linked anywhere else
   refuses to run.
2. It hashes the image and requires a matching member in a verified signed
   manifest. That manifest is the one in the image's own `versions/<v>/`
   directory, or the package-shipped manifest for the package copy.
3. It requires its own version to be at or above the committed elevation
   floor.
4. It refuses to run when environment variables are present that the Go
   runtime reads before `main` and that change security-relevant behavior:
   `GODEBUG`, `GOTRACEBACK`, `GOMAXPROCS`, `GOGC`, `GOMEMLIMIT`, `ZONEINFO`.
   It clears every other variable that is not on a small allowlist at the start
   of `main`. Under admin-approval elevation, `HKCU\Environment` is inherited,
   so this matters on Windows.
5. It sets the current directory to the system directory.
6. It resolves locations only through `GetSystemDirectoryW`,
   `SHGetKnownFolderPath` and handle-derived paths.

The broker acts only at machine scope. With over-the-shoulder credentials, all
per-user state belongs to another account.

**The service does not self-check.** During a switch its image is still in
staging, and Q4 requires a below-floor service to keep running. The service
checks only the compiled-in Wintun pin before loading the DLL. It also reports
`below_security_floor`. The broker, not the service, verifies the installed
digest against committed evidence.

**The installed service image is never used as the elevated binary.** It
would have to lock its own image, and then could not be replaced.

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

While the handle is held, no writer, rename or delete can succeed.

**Residual risk: share-mode locks.** `Users` can read and execute `versions/`
and the package copies. Any logged-in user can therefore open a Core
executable with share mode 0, which blocks Desktop's open, `CreateProcess` and
AppInfo for every user while the handle exists. This is a local denial of
service, not an integrity risk. Desktop reports it as `store-unavailable` and
names the blocking process through Restart Manager. The broker never relies on
`Users` lacking that ability. The image
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
  5. Go launchers do the same through `/proc/self/fd/<n>` of the held
     close-on-exec descriptor. `ExtraFiles` is not needed.
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
- **Missing-service installation** uses the session `install` operation. It
  installs the active version, or the newest committed version if no active
  record exists. If nothing is committed, it installs the verified package
  bootstrap or a streamed bundle, either of which must meet the floor. It
  promotes the bundle and writes records only after readiness. It never
  installs `os.Executable()` bytes.
- **Unchanged rules.** The existing consent, ownership, readiness and rollback
  rules stay in force. The repair request still carries no paths, versions or
  digests.

### Release discovery

Desktop treats a newer release tag whose metadata is missing, cannot be
verified or is inconsistent as a visible update error that names the tag. It
does not skip the tag silently. Missing metadata would otherwise let anyone
who can delete release assets keep users on an older signed release.

### Release freshness index (decided)

Visible errors do not reveal a release that was never visible, for example
when the release listing is hidden or replayed. This addition must keep
working while the maintainer is unavailable for a long time.

- **Content.** A small signed file, `freshness-index.json` plus
  `freshness-index.json.sig`, is published with every release and re-signed on
  a schedule. For each channel it holds the newest version, the SHA-256 of that
  version's manifest and its security floor. An empty channel, such as stable
  before the first stable release, is an explicit `null` entry. The file also
  carries `issued` and `expires` timestamps. The expiry is 180 days after
  issue.
- **Signing key.** A dedicated freshness key `F` signs the index, with the
  message construction above.
  - The trust file grants `F` a single role. A signature by `F` is never
    accepted for a manifest, a trust change or a floor that gates anything.
  - At worst, a stolen `F` can claim a release that does not exist (a visible
    error), or keep re-signing an old "latest", which is the same freeze the
    index exists to detect.
- **Validity rules.**
  - `expires - issued` must not exceed 180 days.
  - `issued` may not lie in the future by more than the allowed clock skew.
  - Desktop stores the highest `issued` value it has seen and rejects older
    indexes, so a replayed index cannot hide a release seen before.
  - Together, these rules stop a stolen `F` from suppressing staleness
    warnings indefinitely.
- **Unattended re-signing.** A scheduled job re-signs the index, at least
  monthly, using only `F`. A long absence of the maintainer therefore does not
  let the index expire. `F` may live in CI because its power is narrow. It is
  rotated like `R`, through the trust set.
- **Client behavior.**
  - If the index names a newer version than discovery found, or a different
    manifest digest, Desktop shows a visible error.
  - A mismatch never blocks installing a release verified by the release key
    and a hardware key.
  - An expired or missing index produces only a warning such as "update
    information is stale". It never blocks the VPN, the CLI, repair or
    updates.
  - The floor in the index is an announced floor from `F`, so it never gates
    anything.
- **If the job stops** (the maintainer is absent and CI is down), users see a
  stale warning after expiry. Nothing else changes.

### Cleanup

After a commit, the privileged process keeps the active version and the
previous committed version.

- It moves to `trash/` and deletes versions below the floor, versions nothing
  references, and leftover staging directories, except a staging entry named by
  `state/promote-pending.json`. All of this happens by handle,
  inside the store only.
- A sharing violation (a running CLI or a foreign handle) leaves the entry in
  `trash/` for the next privileged run. The update still succeeds, and the
  diagnostic names the blocking process through Restart Manager.
- Leftover service-directory backup and temporary names are reconciled
  through the journal (see the step table). They are never removed without
  one.

### Interfaces

**Configuration and capabilities**

- `release/compatibility.json` gains `security_floor` and `elevation_floor`
  (each `{epoch, version}`, reviewed) and `store_contract`.
- `hello.capabilities` gains `core_store: <contract>` and the service's
  committed floors.
- `version -json` reports the binary's compiled contract and floors without
  contacting a service.

**Commands**

- **Unelevated:** `bimeron store status -json` lists committed versions,
  verification results, the active version and the committed and announced floors. It is
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

The installer action is reworked, not extended in place.

- **Execution.** It is a commit-time action, not a deferred action that runs
  before install finalization. It runs `bimeron-core store import-package`
  directly, as SYSTEM or root, with no Qt GUI process and no window.
- **Upgrades only.** It acts only on an existing, owned service:
  1. It verifies the bundled Core against the package-shipped signed manifest
     using Core's embedded keys.
  2. It computes a lower bound: the maximum of the committed version and the
     build version of the installed admin-only image. That image may be a
     pre-store service.
  3. It switches through the journaled path only if the bundled version is
     above that bound. The existing owner and registration are kept and
     upgraded to the store-era registration.
- **Fresh machines.** With no registered service, the action does nothing.
  The service is installed by Desktop's first elevated maintenance session
  (`install`), which takes the owner from the authenticated caller. A fresh
  installation therefore shows the MSI elevation prompt and then one Desktop
  elevation prompt, as today.
- **No rollback action.** A rollback action would itself be a downgrade path
  running as SYSTEM.
- **Conditions.** The action's condition excludes MSI repair and maintenance
  modes, unless it is proven safe under an unsolicited repair started by a
  standard user. Commit actions do not run when rollback is disabled by
  policy, so acceptance must verify that case.
- **Package file mapping.** Package files map to signed members by content,
  not by name. `bimeron-core.exe` and `repair/bimeron-repair.exe` must
  byte-equal the signed `core` member. The package's `wintun.dll` and license
  texts must byte-equal the signed `sidecar` and `notice` members.
- **Fallback.** On first launch, Desktop detects a bundled version above the
  committed one and offers the normal elevated session.
- **Linux.** DEB `postinst` calls the same command. The package declares
  `Depends: pkexec | policykit-1`, because Debian 12 split `pkexec` into its
  own package.
- **MSI rules.**
  - `HKLM\SOFTWARE\Bimeron\Core` must never appear in the MSI Registry
    table, so MSI repair and uninstall cannot touch it.
  - The MSI must block downgrades.

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
| Freeze or withholding | Visible error for missing or invalid metadata; signed freshness index with a 180-day expiry (Q5) |
| Announced floor or stolen freshness key locks users out | Announced floors never gate repair, the foreground daemon, the CLI or connectivity; only a hardware-signed announced elevation floor gates updates; `F` gates nothing |
| Unsolicited MSI repair as a standard user | Installer action excluded from repair modes, upward-only, no rollback action |
| Alternate administrator approves UAC | Machine paths only; the readiness channel; caller identity from the authenticated transport, as in #140 |

**Residual risks**

- An old binary that uninstalls and reinstalls the service takes two explicit
  elevations; the next store-capable repair heals it.
- Same-user malware can always ask the user to approve elevation of its own
  binary. Authenticode (Q7) makes the publisher visible, but it is not a
  defense on its own.
- Restoring a whole disk or VM reverts store and floor together. Announced
  floors only warn about it at the next online check.
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
  switches the existing service upward through the journaled path and commits
  the bundled release only after readiness, as described above. It never places
  a release in `versions/` without a switch.
- **Existing installs whose service is newer than the package.** These were
  updated through the pre-store updater. The installer action's lower bound
  includes the installed image's build version, so the service stays in place. The next
  update or repair streams a signed bundle at or above the installed version
  and commits it. Nothing installed is adopted without its full signed member
  set.
- **Desktop uninstall.** The store belongs to Core and appears in no MSI or DEB
  file list, so it persists, together with the floor evidence. Uninstalling the
  service remains an explicit action. `store purge` keeps all evidence.
- **Older Desktop package after a store-era one.** Pre-store tools refuse the
  re-registered service. The MSI must block downgrades.
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
  - committed floors from the embedded value and the HKLM or `/etc` copy.
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

1. **Fresh install.** The MSI prompt is followed by one Desktop prompt, whose
   `install` session installs the service from the verified bootstrap with the
   store-era registration and the caller as owner. After readiness, the
   bootstrap is committed.
2. **Update A to B.** B is committed and the service runs B. The floor rises
   only if B raises it. The CLI and the broker now run from B.
3. **Failed update.** B raises the floor but fails readiness. The service
   returns to A and the floor is unchanged. B is not in `versions/` and is not
   used, and the VPN connects. Variant: the broker is killed between start and
   readiness, through logoff or reboot, with a B that never becomes ready.
   Reconciliation restores A and the old registration, and the floor is
   unchanged.
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
8. **Path and contention attacks** by a standard user. Update and repair
   succeed despite these, except where noted:
   - pre-create the readiness pipe, `Global\BimeronCoreUpdate` and the
     maintenance pipe;
   - hold share-0 handles on state files and on non-executable store files
     during update and repair;
   - hold share-0 handles on store executables: the result is
     `store-unavailable` with the blocking process named, and no corruption;
   - pre-create the store root (ProgramData variant only).
9. **UAC, alternate administrator and pkexec.** A standard user approves with
   alternate administrator credentials, and update and repair succeed with the
   owner preserved. A malicious `HKCU\Environment` (`GODEBUG`, `ZONEINFO`) is
   refused. Linux uses pkexec with polkit and alternate credentials.
10. **Announced floors and censored network.**
    - A machine below an announced floor still connects and shows a persistent
      warning.
    - With an announced floor, a damaged service and an archive that cannot be
      downloaded, repair to the committed target still succeeds.
    - The foreground IKEv2 daemon works under an announced floor.
    - An `F`-signed index with a maximal floor produces a warning only.
    - Below an announced, hardware-signed elevation floor, update requires a
      package upgrade, but repair still works.
11. **Installer behavior.** Cases: `msiexec /fa` by a standard user; an MSI
    rollback in mid-transaction; `DisableRollback` policy; a DEB upgrade,
    removal and purge. The store and floor persist; no downgrade happens.
12. **Crash injection** before and after every durable `next` record, and
    inside every effect (journal replace, member copy, each rename, SCM change
    before `RegFlushKey`, unit write before `daemon-reload`, recovery
    suspend and restore, the HKLM or `/etc` write, promotion), on both
    operating systems,
    for the first pre-store-to-store-era switch and for later switches. The
    cases include:
    - a crash between the two renames;
    - a crash between rollback's remove and rename;
    - a crash between the Linux unit switch and the executable move;
    - a crash between start and readiness, including a release that never
      becomes ready.

    Reconciliation must reach a consistent state, commit only a ready release,
    and leave the registration matching the image. Further cases:
    - a corrupt journal, which must yield `journal-corrupt` and never be
      deleted automatically;
    - concurrent sessions and the installer action, which must yield
      `store-busy` and never reconcile a live journal;
    - a boot start or SCM recovery start of an uncommitted image, which Desktop
      must show as a pending switch;
    - suspended recovery settings, which must be restored on commit and on
      rollback;
    - a crash during stop, or during an in-session rollback after the backup
      was renamed back but before the registration was restored, which must
      never overwrite the old image;
    - a sidecar (Wintun) change rolled back together with the executable;
    - promotion blocked by a foreign handle, which must yield
      `store-copy-pending` with recovery resumed;
    - `abandon-switch` from `journal-corrupt` and from
      `journal-unrecoverable`;
    - a disabled service, which must be refused before `begin`;
    - a crash after `ready` in a stopped-service switch, which must leave the
      service stopped;
    - a release that crashes at start (non-zero exit): the old image is
      restored, network recovery runs if markers require it, and the journal
      closes;
    - a boot start of the new image after a crash at `swap-in`: reconciliation
      stops it before reverting;
    - an unchanged Wintun member during an update;
    - a standard user holding `WINTUN-LICENSE.txt` or a backup name open, which
      must yield `service-file-busy` before `begin`;
    - promotion blocked after `record`, recorded as a promotion debt and
      paid later; a crash inside `record` finished by an older broker (Q12);
      a quarantined `versions/<active>/bimeron.exe` republished from a stream;
      an older broker refusing when an epoch raise added keys it does not
      know;
    - an unclean old-service crash without markers: `Recover` runs with
      consent, and without consent the service stays stopped with
      `rollback-incomplete`;
    - a release hung in start-pending: terminated and reverted;
    - a second-session undo failure of the same step, which must yield
      `journal-unrecoverable`;
    - a pre-store uninstall and reinstall while a journal is pending, which
      must yield `journal-unrecoverable` and then `abandon-switch`;
    - a masked Linux unit, and `install` undo with the service marked for
      deletion.
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
    - A replayed older index is rejected, and so is one with more than 180 days
      of validity.
    - A machine several releases behind updates across an `R` rotation, a
      YubiKey revocation and an epoch raise, through bridge releases.
    - Floor evidence survives the rotation and the revocation.
    - After a rotation, an elevated older package copy refuses with
      `newer-component-required`.
    - A committed bridge passes its own self-check and can be repaired from a
      streamed bundle.
    - Hop selection stops without progress, and reports that a package upgrade
      is required beyond 8 hops.
14. **Version grammar.** The shared conformance file passes in Go and C++. Rejected forms, the NTFS case-collision attempt, and
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
- **An integer security level instead of a version floor.** Rejected (Q6).
  Floors stay in the project's own version style, so release notes, users and
  tooling read them directly. The precedence risk is handled by one strict
  grammar, numeric comparison, the channel rules, and shared conformance
  vectors.
- **Online, root-signed key-set document combined with a threshold of
  software keys.** Hardware-backed keys that cannot be exported, plus key sets
  embedded in binaries, protect against the realistic threat of a copied
  signing secret without adding online trust state.

## Decisions

All decided by the user on November 18, 2026:

| # | Decision |
| --- | --- |
| Q1 | Windows store: `%ProgramFiles%\Bimeron Core\store` |
| Q2 | Linux store: `/usr/local/lib/bimeron/store` |
| Q3 | Every release is signed by the release key and one of two YubiKeys. An epoch raise needs the release key and both. The current release key is rotated as planned (see Trust and keys) |
| Q4 | A below-floor service does not block the VPN |
| Q5 | Signed freshness index with a narrow key, unattended re-signing, a 180-day expiry, and a warning only on expiry |
| Q6 | Floors are core versions in the project's existing style, compared under the strict rules above |
| Q7 | Authenticode is deferred; constraints are reserved |
| Q8 | "Never below active" is strict; there is no manual downgrade |
| Q9 | Pre-store tools are intentionally unable to manage store-era services |

Follow-up questions raised by the second adversarial review, with
recommended defaults already written into this draft:

- **Q10. Trust-set changes reaching Desktop.** Recommended: Desktop accepts a
  manifest that verifies under its embedded trust set or under the trust set of
  the newest committed store Core, which is itself verified through bridge
  releases. Rotations and revocations then do not need a Desktop package
  release. The alternative is to require a Desktop package release for every
  trust change, which re-couples Core security updates to Desktop releases.
- **Q11. Fix ancestry for version floors.** Recommended: the publisher refuses
  a floor unless every published tag at or above it contains the recorded
  fixing commits. The consequence is that maintenance lines below a raised
  floor cannot publish. The alternative is a documented single-line release
  model without the check. If the check is adopted, it is based on the
  publisher's own record of signed releases, not on the tags in the remote
  repository; otherwise anyone who can push a tag could block publication.

- **Q12. Finishing the active version's store copy with an older broker.**
  Recommended: a broker below the active version may only finish the
  post-`ready` steps of a pending switch journal, pay a promotion debt, or
  republish `versions/<active>` from a stream whose manifest digest equals the
  active record's. All floor evidence must still verify under its own trust and
  epoch rules. It must be at or above the committed
  elevation floor. It never changes the service, the registration, or floor or
  active evidence. The alternative is that losing the active store copy always
  requires a Desktop package release.

The remaining hardware detail is settled during the key ceremony. Each
YubiKey uses PIV Ed25519 (firmware 5.7+) or OpenPGP Ed25519 (firmware
5.2.3+), according to `ykman info`.
