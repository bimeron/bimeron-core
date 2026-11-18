# ADR 0039: Signed versioned core store and anti-rollback floor

Status: proposed draft, November 18, 2026. Not accepted; no implementation is
authorized by this record. Amends [ADR 0002](0002-signed-service-updates.md)
and the explicit-repair replacement policy of #140 in
[REPAIR_SESSION.md](../REPAIR_SESSION.md). Tracked by Core issue #155 and
bimeron/bimeron-desktop#58.

## Context

The Windows/Linux Core is one Go executable (`bimeron[.exe]`) that acts as CLI,
service and repair broker. Desktop packages carry two copies of it: the CLI
(`C:\Program Files\Bimeron\bimeron-core.exe`, `/usr/bin/bimeron-core`) and the
repair broker (`...\Bimeron\repair\bimeron-repair.exe`,
`/usr/libexec/bimeron/repair/bimeron-repair`). The service runs a third copy from
`%ProgramFiles%\Bimeron Core\bimeron.exe` or `/usr/local/lib/bimeron/bimeron-core`.

A signed core update (ADR 0002) replaces only that third copy. Desktop verifies
the manifest and elevates its bundled CLI with
`service update -source <path> -version <v> -sha256 <hex>`; by the ADR 0002
design, publisher authenticity and version selection are decided in Desktop,
and the elevated command receives their results as arguments. The bundled CLI
and broker stay at the package version.

Explicit repair (#140) compares the installed service's SHA-256 with the
broker's own running image and replaces a byte-different service with the
broker image (documented in [REPAIR_SESSION.md](../REPAIR_SESSION.md)). After a
signed update the service is byte-different by construction, so repair returns
it to the package version. Missing-service installation also installs the
broker's version. Core updates can carry security fixes; returning to an older
version would reintroduce a fixed problem. The package installer action that
updates the service from the package has the same ordering question, and no
component records the highest version or security floor a machine has
trusted.

This design moves the trust decision for anything that runs or is installed
with elevation into the privileged Core process, and applies uniform rules to
every privileged file operation in the new store:

- signature, size and digest verification of untrusted inputs before any byte
  is published, with fixed size bounds;
- untrusted inputs opened once, without following links, and read through one
  handle;
- private staging, atomic publication under versioned names, and final
  permissions applied only after verification;
- explicit owner and protected DACL on every created directory, with ancestor
  checks;
- locks that non-administrators cannot create or pre-create;
- tolerance of foreign open handles (no fixed file names that a busy file can
  block, garbage collection, visible failure);
- installation from a verified handle or store entry, never by re-resolving a
  path;
- restricted DLL search and digest-verified companion DLLs at load time;
- canonical, strictly decoded metadata;
- signed artifacts provably bound to the tag commit and its reviewed build
  settings.

Security is the primary goal. Implementation complexity is secondary.

## Decision

### Summary

1. A core update downloads, verifies and installs a complete signed bundle into
   an immutable, versioned, machine-protected **core store**. The service is
   then switched from that store.
2. Signature verification and the anti-rollback **security floor** are enforced
   inside the privileged process with keys embedded in Core. Desktop repeats
   the checks as defense in depth, never as the only gate.
3. Desktop runs the CLI and the repair broker from the newest usable store
   version. Bundled package copies are bootstrap material only.
4. Every launch of a store or bundled executable is preceded by a digest check
   bound to the executed file. Elevation is never requested for an unverified
   file.
5. Repair restores from the store, never from its own image, and never lowers
   the installed version or goes below the floor.

### Terms

- **Core version**: the tag-derived `core_version` (SemVer 2.0 precedence).
  Ordering is implemented identically in Go and C++ and pinned by a shared
  test-vector file (`release/testdata/version-order.json`) consumed by both
  repositories.
- **Security floor**: the lowest core version a machine may install, run as the
  service, or execute as CLI/broker. It is a publisher statement carried in
  signed manifests, never typed by a user or computed from local state alone.
- **Active version**: the version the service was last switched to and
  committed by a privileged Core process.
- **Usable version**: a store version whose signed manifest and every member
  verify, which is at least the effective floor, and (for Desktop selection)
  whose signed GUI range includes the running Desktop.

### Store layout and protection

Windows (recommended, pending Q1): `%ProgramFiles%\Bimeron Core\store\`, a
Core-owned directory beside the service that MSI does not own. The initially
proposed `%ProgramData%\Bimeron\core\` has two drawbacks. Its default DACL lets
`Users` create subdirectories, and `CREATOR OWNER` then gives the creator full
control, so the directory can be squatted. And default AppLocker and SRP
executable rules allow standard users to run binaries only from
`%ProgramFiles%` and `%WINDIR%`, which would block every Desktop CLI launch on
machines that enforce such rules. ProgramData remains viable for a SYSTEM
service (Defender uses
`ProgramData\Microsoft\Windows Defender\Platform\<version>`) if the squatting
defenses below are implemented. Linux: `/var/lib/bimeron/core/` (pending Q2).
`/var/lib` is root-owned 0755, so it cannot be squatted. Flatpak executes from
`/var/lib/flatpak`, so there is precedent.

```text
<root>/
  versions/<version>/          immutable after publication
    bimeron[.exe]
    wintun.dll, WINTUN-LICENSE.txt          (Windows)
    LICENSE, THIRD_PARTY_NOTICES.txt
    update-manifest.json                    exact signed bytes
    update-manifest.json.sig
  state/
    active.json                             active version and executable digest
    floor.json                              highest floor evidence (see below)
  staging/                                  privileged-only, not user-readable
  trash/                                    pending deletion
  lock                                      store mutex (Linux flock target)
```

- `<version>` must match the strict release version grammar; it is never taken
  from a path supplied by a caller.
- Windows DACL: protected (no inheritance), owner `SYSTEM` or `Administrators`,
  `SYSTEM` and `Administrators` full control, `Users` read and execute on
  `versions/` and `state/`. `staging/` and `trash/` grant no access to `Users`.
  Linux: owner root, mode 0755 on `versions/` and `state/`, 0700 on
  `staging/` and `trash/`, no group/other write anywhere.
- Every privileged open walks from a held handle of the store root and refuses
  reparse points/symlinks on every component (Windows:
  `FILE_FLAG_OPEN_REPARSE_POINT` with `FileAttributeTagInfo`; Linux: `openat2`
  with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`, falling
  back to per-component `O_NOFOLLOW` walks on kernels without `openat2`).
- Pre-existing root, parent or child directories are not trusted.
  - **Windows creation**: relative to a held parent handle, with an explicit
    protected security descriptor applied atomically at creation. Use specific
    file rights, not generic bits:
    `O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)`, and
    no `CREATOR OWNER` ACE.
  - **Linux creation**: `mkdirat` relative to a held parent fd.
  - **An object that already existed** is validated through the opened
    handle. It must not be a reparse point or symlink, its owner must be
    `SYSTEM`, `Administrators` or `TrustedInstaller` (root on Linux), and its
    DACL must be protected and grant write-class rights to no other principal.
  - **An untrusted existing object is never "fixed in place"**: its creator may
    still hold write or `WRITE_DAC` handles opened before the reset. It is
    renamed aside by handle (`FileRenameInfo` to
    `<name>.untrusted-<random>` within the trusted parent) and recreated with
    create-new semantics.
  - **If that rename fails** (for example, the attacker holds a handle without
    `FILE_SHARE_DELETE`), the operation fails closed. It is a denial of service
    only.
  - **Privileged code never deletes an untrusted tree recursively by path**;
    that is the ProgramData arbitrary-delete class (for example CVE-2025-58074
    and CVE-2023-0652).
  - Owner and DACL are always set by handle (`SetSecurityInfo`), never by
    path.
- Untrusted inputs (downloaded manifest, signature, archive) are opened once,
  without following links, must be regular files, and are bounded in size.
  They are read only into private staging; nothing is user-readable inside the
  store until verification passes and the final permissions are applied at
  publication.
- On Windows 11, the privileged process opts in to the redirection trust
  mitigation (`ProcessRedirectionTrustPolicy`, RedirectionGuard), so junctions
  created by non-administrators are not followed. A failure on Windows 10 is
  not fatal. Privileged temporary files never use `%TEMP%`; staging lives inside
  the store.
- Store files have exactly one link (`NumberOfLinks == 1`, `st_nlink == 1`).
  Same-file comparisons use `FileIdInfo` (volume serial and 128-bit file ID) or
  `st_dev`/`st_ino`.
- On Linux, installed store files may optionally be sealed with fs-verity
  where the filesystem supports it. This makes them immutable even to root
  until deletion, and gives a cheap measured digest. It is not required; root
  ownership is the requirement.
- A version directory is published by renaming a fully verified staging
  directory. It is never modified afterwards; a damaged version is moved to
  `trash/` and republished from verified bytes.
- Mutual exclusion uses a lock file inside the administrator-only store
  (`state/lock`): an exclusive no-share open on Windows, `flock` on Linux.
  Non-administrators cannot create, pre-create or open it. No fixed name in the
  `Global\` kernel namespace is used for store operations; if a kernel object
  is ever needed, it lives in a private namespace with an administrator-only
  boundary descriptor.

### Manifest schema 2

The release keeps one `update-manifest.json` plus detached Ed25519 signature,
with `schema: 2`:

- Each target gains `files`: every ZIP member with `name`, `size`, `sha256` and
  `role` (`core` for the executable, `sidecar` for Wintun, `notice` for license
  texts). The ZIP record keeps its `name`, `size` and `sha256`.
- A top-level `security_floor` (core version). It must be at most the
  manifest's own `core_version`. It comes from the reviewed
  `release/compatibility.json`, so raising it is an explicit release decision.
- A top-level `store_contract` integer (initially 1).
- A top-level `source_revision`: the full tag commit. The publisher signs an
  archive only if its executable's embedded build information matches the tag
  commit and the reviewed build settings: `vcs.revision` equal to the tag
  commit, `vcs.modified=false`, `-trimpath`, the expected `GOOS`/`GOARCH`, and
  no ambient `GOFLAGS`. This is the same gate the Apple path already enforces.
- Backfill is retired. No tool signs metadata for an existing release from
  whatever assets the release currently holds, or with today's
  `compatibility.json` for an old tag. Schema 2 metadata is produced only by
  the prepared-release publisher at tag time.
- Parsing is strict in both Go and C++: exact field names with case-sensitive
  matching, duplicate-key rejection after case folding, unknown fields
  rejected, bounded sizes.

Desktop 0.3.x requires `schema: 1` exactly and therefore fails closed on every
schema 2 release. This is intended (see Compatibility).

### Trust and keys inside Core

This amends ADR 0002, which kept signing trust out of the privileged
executable. Repair acquisition already embeds one public key
(`repair_acquire.go`); this decision generalizes it.

- Core embeds a key set (key ID to Ed25519 public key) generated from a
  reviewed repository file. Desktop pins the same set. Both sides select by
  `key_id` and reject unknown IDs.
- Rotation: a release adds the successor key to both trust sets; signing
  switches only after the store-capable Desktop and Core that trust it are the
  minimum supported versions; the old key is retired later.
- Key compromise handling is open question Q3. Recommended: a two-tier scheme
  with an offline root key that signs a versioned key-set document, and online
  release keys that sign manifests. Root-signed documents can revoke a release
  key and are the only way to lower a floor.

### Effective floor and its storage

The floor must be monotonic, and its local file must not be the single source
of truth. The effective floor is the maximum over all available signed
evidence:

1. The `security_floor` compiled into the verifying binary (Core embeds
   `release/compatibility.json`; Desktop embeds the value from its pinned Core
   release).
2. The `security_floor` of every verified manifest in `versions/*/`.
3. `state/floor.json`, which stores the exact bytes and signature of the
   manifest that established the highest floor, so the record is
   self-verifying rather than a bare number. A copy of the same evidence is kept
   in a second administrator-only location, and the floor is the maximum of the
   two. On Windows this is a protected HKLM value under
   `SOFTWARE\Bimeron\Core`; on Linux, `/etc/bimeron/core-floor.json`. A partial
   restore of one location therefore does not lower the floor.
4. For selection and UX only, floors in freshly fetched signed manifests.

Only a privileged Core process writes `state/floor.json`. It raises the floor
after the service switch to a version that is at least that floor has
committed, never before. A floor record that fails verification is ignored and
reported, and the remaining evidence still applies. Reverting or deleting the
file alone therefore cannot lower the floor while any newer signed manifest
remains in the store or in a running binary. Restoring the whole machine or
volume from an older backup or VM snapshot reverts everything; that is outside
the local-attacker model. It is bounded by item 4 at the next online check,
which forces an update before Desktop proceeds.

A newly announced floor (item 4) does not stop a usable but older store broker
from installing the release that raises the floor; otherwise no update could
ever happen. It does block all other use of below-floor executables. If a
security fix concerns the updater or broker code itself, the release must say
so, and Desktop must require a package upgrade instead.

`state/active.json` holds `{version, executable_sha256}`. It is written by
handle, atomically (temp file in `state/`, flush, rename), after readiness
succeeds. It is advisory: it only ever names a version that is at least the
effective floor, and it is never trusted to lower anything.

### Privileged store installation (replaces caller-trusted `service update -source`)

New elevated command (shape, not final syntax):

```text
bimeron store install -manifest <path> -signature <path> -archive <path>
```

- The command accepts no digest, version or key from the caller.
- Inputs are data. Each is opened once without following links (Windows
  `FILE_FLAG_OPEN_REPARSE_POINT`, no-reparse check, regular file; Linux
  `O_NOFOLLOW | O_NONBLOCK`, `S_ISREG` via `fstat`). Reads have fixed upper
  bounds (manifest 64 KiB, signature 89 bytes, archive 100 MiB, member 64 MiB).
  Bytes are read through that one handle.
- The process verifies the signature with the embedded key set, then schema 2,
  its own OS and architecture target, ZIP size and SHA-256, and ZIP structure
  (no traversal, symlinks or duplicates; exactly the expected members). Then it
  checks every member's size and SHA-256 and the Go module and machine
  identity.
- It requires `core_version >= effective floor` and
  `core_version >= max(active version, verified installed version)`.
  Equal versions are allowed only for republishing identical bytes.
- Members are extracted into a fresh `staging/<random>/` that only `SYSTEM`/root
  can read. Each file is re-verified by handle, then the directory is renamed to
  `versions/<version>/`. If the version already exists with identical verified
  bytes, the operation is a no-op. Differing bytes for an existing version are
  an error.
- The service switch then uses the existing transactional replacement
  (stop, backup, rename, start, readiness, rollback). The source is the
  verified store file, read by handle, not the running image. Readiness
  uses the restricted readiness pipe. A stopped service is activated and
  verified before commit, as repair mode already does. The legacy stopped-update
  exception (commit without verifying the version) is removed.
- Commit order: service readiness, then `state/active.json`, then
  `state/floor.json`, then cleanup.
- Wintun follows the existing policy. The store keeps the signed sidecar for
  repair, and the service directory copy is checked against the pinned hash at
  every service start before it is loaded. The process calls
  `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` and loads Wintun by
  verified full path.

The legacy `service update -source` command is kept only in Desktop-compatible
pre-store builds. Store-capable builds refuse it with a message naming the
store command, so no elevated path accepts a caller digest.

### Which binary is elevated

Desktop selects the elevated executable in this order, and stops at the first
that verifies:

1. The newest usable store version.
2. The installed service image, if its digest equals a member hash in a
   verified signed manifest for its version and that version is at least the
   effective floor. Desktop fetches that manifest if the store lacks it.
3. The bundled package copy, if its version is at least the effective floor and
   its bytes match the signed manifest that Desktop ships for its pinned Core.
4. Otherwise Desktop does not elevate. It explains that a package upgrade or a
   network fetch is required.

Independently, the elevated Core process checks itself at startup before any
mutation. It locks its own image by handle, hashes it, and requires a matching
member in a verified signed manifest (its own store directory, or the manifest
carried by the package for bootstrap) whose version is at least the effective
floor. It refuses otherwise. A swapped binary would not run this check, but
swapping requires write access that only administrators have (see Threat
model).

### Launch verification in Desktop

Desktop-side verification is not the security boundary against malware that
runs as the Desktop user. Such malware can patch the Desktop process, skip the
check, or launch anything it likes. The boundaries are:

1. The store ACL and owner rules, so no non-administrator can change a byte
   between check and use.
2. The self-check and narrow, data-only interface of every elevated Core
   process.
3. Service-side IPC authorization.

Desktop verification still matters. It detects ACL misconfiguration, partial
publication and corruption. It also guarantees that an honest Desktop never
asks the user to approve elevation of an unverified file. And the binding below
costs little.

- Windows, unelevated CLI:
  1. Open the executable with `GENERIC_READ`, share mode `FILE_SHARE_READ`
     only, and `FILE_FLAG_OPEN_REPARSE_POINT`.
  2. Reject reparse points, more than one link, a foreign owner or writable
     ACEs (the existing `protectedExecutable` policy).
  3. Confirm with `GetFinalPathNameByHandleW` that the path lies inside the
     store.
  4. Hash through the handle and compare with the signed member hash.
  5. Keep the handle open while calling `CreateProcessW` on the same canonical
     path, and close it after the process is created. While the handle is held,
     no writer or rename can succeed. The image loader needs only read and
     execute access, so it is compatible with this share mode; acceptance
     verifies this on the VM. The handle also defeats herpaderping-style
     substitution, which needs a writable handle open before the section is
     created.
  6. Optional binding: create the process suspended, open its image through
     `QueryFullProcessImageNameW`, compare its `FileIdInfo` with the held
     handle, then resume it, or terminate it on a mismatch.

  Creating the process from a verified image section (`NtCreateSection` plus
  `NtCreateProcessEx`) is rejected. It is undocumented, and it is the primitive
  behind process doppelganging and ghosting, so endpoint security flags it.
- Windows, elevated broker: the same handle-held verification across
  `ShellExecuteExW` with `runas`. The elevated process then performs its own
  self-check (above). The command line carries only the session nonce, the
  caller PID and data-file paths; nothing in it selects trust.
- Linux, unelevated CLI:
  1. Open with `openat2` beneath the store root, `O_RDONLY | O_CLOEXEC`.
  2. Check with `fstat` that the file is regular, root-owned, has a single
     link and is not group- or other-writable.
  3. Hash through the fd.
  4. Execute that fd, as the existing bootstrap already does with `fexecve`.
     For `QProcess`, the program is `/proc/self/fd/<n>`, and the child
     modifier clears `FD_CLOEXEC` on `<n>` only in that child. If the child
     closes descriptors, the lowest descriptor it closes is set above `<n>`.

  `fexecve` binds the inode, not the content: root-only write access (or
  fs-verity) keeps the bytes unchanged. ETXTBSY write denial is not relied
  on. Only ELF images are executed this way. Go code that launches the store
  executable uses `ExtraFiles` with `/proc/self/fd/3`.
- Linux, elevated broker: run `/usr/bin/pkexec` from its fixed path, after
  checking it is protected (`pkexec` is never resolved from `PATH`, for any
  elevated command), with the verified store path. The root broker performs the
  same self-check. A verified-fd handoff through `pkexec` is not possible,
  because `pkexec` takes a path, so the root-owned store and the self-check are
  the binding. The default `org.freedesktop.policykit.exec` action requires
  administrator authentication. A polkit `exec.path` pin cannot name versioned
  paths, so no pinned or relaxed action is added. pkexec sanitizes the
  environment, and the broker still ignores the environment and uses absolute
  paths.

  Later hardening, not part of this decision: a fixed, hardened systemd
  oneshot unit started over D-Bus, authorized by a polkit rule for that unit
  only. It removes the setuid helper and user-controlled argv (the PwnKit
  class).
- Elevated processes on Windows ignore inherited `PATH`, `TEMP`, `windir`,
  `SystemRoot` and `ProgramData`, which `HKCU\Environment` can influence. They
  resolve locations through `GetSystemDirectoryW`/`SHGetKnownFolderPath` and the
  handle-derived store path, set the current directory to the system directory,
  and never act on the requesting user's per-user state. With
  over-the-shoulder credentials, the per-user state belongs to another account.
- Every CLI launch is hashed. The cost (tens of milliseconds for about 30 MB)
  is measured by a Desktop benchmark. A cache keyed by file ID and change time
  is allowed only after the benchmark shows a need, and never for elevation.

### Repair

- `Inspect` computes the **target version**: the maximum of the active version
  and the installed service version when the installed digest equals a signed
  member hash. It never uses the broker's version.
- An installed image that matches a signed member hash for a version at least
  the target and the floor is intact, so the #140 rule "byte-different
  compatible release must be replaced" is withdrawn. #140 corruption detection
  is kept: missing, unreadable, or not matching any verified signed hash means
  damaged.
- The replacement source is `versions/<target>/` after full verification by
  handle. The same applies to Wintun.
- If the store copy of the target is missing or damaged, the broker acquires
  exactly that version in the same authenticated elevated session. It extends
  `repair_acquire.go` from Wintun-only to the full bundle, verifies with the
  embedded key set, republishes the store entry and continues.
- If acquisition is impossible, repair fails closed with a specific code.
  It never falls back to a lower version, its own image, or the bundled copy
  unless that copy is exactly the target or higher and at least the floor.
- Missing-service installation installs the active version, or the newest
  usable store version if no active record exists, never a version below the
  floor.
- Repair keeps the existing consent, ownership, readiness and rollback rules.
  The request still carries no paths, versions or digests.

### Service-side floor check

A store-capable service reads the effective floor at startup. If its own
version is below the floor, it reports `below_security_floor` (SCM error and
event log, journal on Linux) and refuses to start the VPN engine. A
below-floor service can only appear after a rollback outside the store path
(an old broker or a manual install), because the floor is raised only after a
committed switch. Availability versus security here is open question Q4.

### Release discovery

Desktop treats a newer release tag whose metadata is missing, unverifiable or
inconsistent as a visible update error that names the tag, rather than
skipping it silently. Missing metadata otherwise lets anyone who can delete
release assets keep users on an older signed release. Q5 decides whether a
signed index with an expiry is added on top.

### Cleanup

After a commit, the privileged process keeps the active version and the
previous usable version. It moves versions below the floor, unreferenced
versions and leftover staging directories to `trash/` and deletes them. A
sharing violation (a running CLI, or a foreign read handle without
`FILE_SHARE_DELETE`) leaves the entry in `trash/` for the next
privileged run. The update still succeeds and the condition is reported.
Leftover `.update-old`/`.repair-old` sidecars are reconciled against the store
instead of blocking all future updates.

### Interfaces

- `release/compatibility.json` gains `security_floor` (reviewed) and
  `store_contract`.
- `hello.capabilities` gains `core_store: <contract>` and `security_floor`.
  `version -json` reports the same for an unlaunched binary.
- `bimeron store status -json` (unelevated) lists versions, verification
  results, the active version and the effective floor. It is diagnostic only:
  Desktop verifies the store itself before trusting any launch.
- `bimeron store install`, `store import-package`, `store purge` are elevated.
  `repair-session` is unchanged on the wire, apart from new terminal codes
  (`below-floor`, `store-unavailable`, `acquisition-failed`).
- IPC protocol stays 1. Every change is additive and gated on the capability.

### Platform scope

Windows and Linux amd64/arm64 only. macOS and Android are outside this updater
(ADR 0031 and ADR 0032 keep Apple separate; Android ships inside the app). No
store, floor or repair change applies to them. Desktop's updater already
returns no platform on them.

## Threat model

In scope: a local unprivileged user and malware running as the Desktop user.
That attacker can write the user's TEMP, profile and HKCU, start processes,
create junctions, mount points and object-manager links, open handles to
readable files, pre-create names in `ProgramData` and `Global\`, inject into
the Desktop process, and invoke UAC or `pkexec` on any binary. The attacker can
also be the network: a malicious mirror, withheld releases, or replayed old
signed metadata. Out of scope: an attacker who already has administrator or
root rights, kernel compromise, and theft of an offline root key.

| Threat | Mitigation |
| --- | --- |
| Replace store files or directories | Admin-only DACL and owner, `NumberOfLinks == 1`, handle-based walk, immutable versions |
| Pre-create `ProgramData\Bimeron` or store children | Explicit SD on create, owner/DACL validation of existing objects, fail closed or quarantine |
| Junction, symlink or hardlink redirection of privileged writes | No-follow opens on every component, writes only beneath the held root handle, rename inside one directory, link-count check |
| TOCTOU between verify and execute | Windows deny-write/delete handle held across process creation; Linux exec of the verified fd; elevated self-check |
| Swap the input bundle after Desktop verification | Elevated process verifies the signature itself and reads through one handle |
| Rollback through repair | Target = max(active, installed verified); repair source is the store; no own-image source |
| Rollback through installing an older signed release | Order and floor checks inside the privileged process |
| Rollback by deleting or reverting `floor.json` | Floor is the maximum over embedded and store-manifest evidence; the file is self-verifying |
| Rollback through a damaged store | Republish the exact target from signed bytes; never fall back lower |
| Confused deputy: malware elevates our signed broker with chosen arguments | Arguments are data; worst case is a forced upgrade to a signed version or a DoS |
| Malware elevates an old Bimeron binary | Old binaries fail the protected-ancestry check outside Program Files; store-capable Desktop never elevates below-floor code; residual for admin-installed old packages (below) |
| DLL planting for the elevated process | `SetDefaultDllDirectories`, admin-only application directory, Wintun hash at load |
| Squatting of mutex and pipe names | Restrictive DACL on create, owner check, fail closed with diagnostic |
| Foreign handle blocking rename | Bounded retry, transaction rollback, deferred trash |
| Release-key compromise | Q3 (root key and revocation); floor lowering only by root |
| Freeze or withholding (deleted or withheld metadata for newer releases) | A newer tag with missing or invalid metadata is a visible error in Desktop, never a silent skip; optional signed index with expiry (Q5) |
| Alternate administrator approves UAC | Machine paths only; readiness pipe; caller identity from the authenticated transport, as in #140 |

Residual risks:

- An administrator who installs a pre-store Desktop package (0.3.x or older)
  regains its old broker, and that broker's repair can still roll the service
  back. Desktop must block MSI downgrades. The store-capable service refuses to
  start below the floor only when the rolled-back binary itself is
  store-capable.
- Same-user malware can always ask the user to approve its own elevation. UAC
  shows publisher information only for Authenticode-signed binaries; signing
  Core with Authenticode is a separate, recommended decision.
- A full disk or VM rollback reverts the store and floor together. Online floor
  evidence (floor source 4) is the only bound.

## Compatibility and migration

- **Desktop 0.3.0/0.3.1**: no store support. Schema 2 manifests fail their
  `schema == 1` check, and store-capable Core releases set `gui_min` to the
  first store-capable Desktop. Old Desktops are not offered these releases and
  are told to upgrade the package. Their own repair keeps today's behavior for
  pre-store versions. Core cannot fix that retroactively.
- **First store-capable Desktop package**: bundles its pinned Core together with
  that release's signed schema 2 manifest and signature. The existing MSI
  deferred custom action and DEB `postinst` (`InstallerCore`) run
  `store import-package` as SYSTEM/root. It verifies the bundled bytes with
  Core's embedded keys and publishes them into the store, then performs the
  existing never-downgrade service update from the store. The MSI action gains
  a rollback action, or becomes a commit-time action, so a failed transaction
  cannot leave the service newer than the store without a record.
- **Existing installs whose service is newer than the package**: the service
  is left in place. On the next update or repair, Desktop fetches the signed
  bundle for the installed version (or newer), and the elevated store import
  adopts it. No installed binary is imported without its full signed member
  set.
- **Desktop uninstall**: the store is owned by Core, not by the MSI or DEB file
  lists, so it persists. Service uninstall stays explicit. A new
  `store purge` removes `versions/`, but keeps `state/floor.json` unless the
  user passes an explicit `-forget-floor`, so reinstalling an older package
  cannot silently roll back.
- **Reinstall of an older Desktop package**: blocked by MSI downgrade rules. If
  forced, the store-capable Desktop logic is gone, which is the residual risk
  above.
- **Linux package managers**: DEB stays the only Linux package. The store lives
  under `/var/lib`, is not in the dpkg file list, and survives upgrades and
  removal; `purge` does not delete it implicitly. A `noexec` `/var` mount or
  SELinux/AppArmor policy that forbids executing from `/var/lib` breaks Desktop
  CLI launches from the store. In that case Desktop reports an explicit
  diagnostic and uses the bundled copy only if it is a usable version (Q2).

## Work split

Core:

- Schema 2 producer and verifier, the `security_floor` policy, and source
  revision binding. Strict JSON for both manifest kinds.
- Embedded key set and the version-order test vectors.
- Store module: protected create and open, staging, publish, verify, the
  floor and active records, cleanup, and locks.
- `store install`, `store import-package`, `store status`, `store purge`, and
  the refusal of the legacy `-source` path.
- Repair source switch, target-version computation, and full-bundle signed
  acquisition.
- Service-side floor check, Wintun pin at load, `SetDefaultDllDirectories`.
- Documentation updates: UPDATE_SPEC, RELEASE_UPDATES, REPAIR_SESSION,
  SERVICE, GUI_INTEGRATION, CONTROL.

Desktop:

- Schema 2 verification, the pinned key set, and the version-order vectors.
- Store discovery, usable-version selection, and the effective floor.
- Handle- or fd-bound launch for every CLI run and for elevation.
- Fixed `pkexec`, and removal of the `PATH`/WSL elevation route.
- The elevation-source ladder, the shipped signed manifest for the bundled
  Core, the MSI/DEB `store import-package`, MSI downgrade blocking and the
  rollback action.
- UX for below-floor, mandatory-update and store-unavailable states.
- Benchmarks for launch verification.

## Acceptance plan

Run on a disposable clone of the Windows 10 STD VM and a Linux (Ubuntu 22.04)
VM, never on the host. Each case records the binary hashes and the
service/store state before and after.

1. Fresh install of the store-capable Desktop: the store is seeded, the service
   is installed from the store, and there is one UAC prompt.
2. Update A to B: store B is published, the service runs B, the floor is raised
   only if B raises it, the CLI and broker now run from B.
3. Repair after update: a healthy B service stays B. A damaged B service (XOR
   at 0x1000, zeroed header, missing file) is restored to B, not to the bundled
   A.
4. Damaged store B (deleted file, modified member, extra hardlink, junction in
   place of the version directory): repair re-acquires B through signed
   acquisition. Without network, repair fails with `store-unavailable`; it
   never installs A.
5. Rollback attempts: elevate `store install` with a validly signed older
   release, with release B and a reverted `floor.json`, and with a deleted
   `floor.json`. All are refused, or keep B and the floor.
6. Same-user substitution: replace the downloaded ZIP after Desktop
   verification. Race a swap of the store path during launch, as a standard
   user; it must be denied. Pre-create `C:\ProgramData\Bimeron` as a standard
   user before the first install; it must be detected and handled. Pre-create
   the mutex and pipe names, and hold a foreign read handle on a store file
   during update.
7. UAC path: a standard user approves with alternate administrator
   credentials; repair and update succeed and preserve the owner. Malware-style
   elevation of the store broker with crafted arguments gains nothing beyond a
   signed upgrade.
8. Old binaries: an old broker copied into a user directory and elevated must
   refuse to run. A below-floor service started manually reports
   `below_security_floor`.
9. Desktop 0.3.1 against a schema 2 release: no update is offered and no
   repair downgrade happens for store-era versions.
10. Uninstall and reinstall Desktop: the store and floor persist; a downgrade
    MSI is blocked.
11. Linux: pkexec with alternate administrator credentials (polkit), fd-bound
    CLI launch, and a `noexec` `/var` diagnostic.

## Alternatives considered

- **Overwrite the Desktop package files in Program Files with the updated
  CLI/broker.** Rejected. The files belong to the MSI or DEB, whose
  repair/self-heal or upgrade would silently restore the old bytes (a
  rollback). It also makes the package manager's integrity metadata lie, and
  mixes two update channels on one set of files. It still needs a separate
  anti-rollback record.
- **Keep the bundled broker, but make repair compare the service with a signed
  record and skip replacement of a newer intact service.** This is a smaller
  change and fixes the visible rollback. Rejected as the end state, because a
  damaged newer service can then only be repaired with older bytes or not at
  all. The CLI keeps validating profiles with old code, and the elevated
  updater remains old code that trusts caller digests. Its comparison rule is
  still adopted inside this design.
- **Release a Desktop package for every Core patch.** This keeps one trust root
  (the package) and needs no store. Rejected: it couples security response
  time to the Desktop release and review pipeline and to the MSI or DEB
  rollout, and makes every Core fix wait for Desktop QA. Users who update Core
  but not Desktop still hit the rollback.
- **Run the service directly from the store** (SCM ImagePath or `ExecStart`
  pointing into `versions/<version>/`). This is attractive because switching
  versions becomes an atomic re-point. Deferred, for three reasons. It changes
  the canonical service path that #140 ownership checks, older Desktops and the
  installer rely on. It interacts with SELinux labels for `/var/lib`. And it
  makes the store directory part of the service's DLL search and recovery
  path. It can be revisited later.
- **Have the running service perform updates itself without UAC.** This
  removes the UAC prompt and the caller-file surface. Deferred, because it puts
  network download and archive parsing into the always-on LocalSystem/root
  process and makes updates depend on a healthy service. Repair exists exactly
  for the unhealthy case.
- **Locally signed or HMAC-protected floor record** (machine key, DPAPI,
  TPM). Rejected: an attacker able to write the admin-only state file is
  already out of scope, and a machine-held key adds secrets without stopping
  whole-disk rollback. Publisher-signed evidence and the maximum rule are
  sufficient.
- **Integer rollback index instead of a version floor.** It avoids SemVer
  precedence subtleties. It is kept as an option (Q6); the version floor is
  chosen because users and release notes reason in versions, and shared test
  vectors control the precedence risk.

## Open questions for the user

- Q1. Windows store location. The recommendation is
  `%ProgramFiles%\Bimeron Core\store`: Program Files has safe default ACLs, so
  users cannot pre-create it, and default AppLocker/SRP path rules allow
  standard users to run binaries from it. The alternative is
  `%ProgramData%\Bimeron\core`, as initially proposed. It requires the
  squatting defenses described above, and it blocks Desktop CLI launches under
  default AppLocker rules unless a publisher rule (which needs Authenticode,
  Q7) is deployed.
- Q2. Linux: keep `/var/lib/bimeron/core`, or use
  `/usr/local/lib/bimeron/store` next to the service. What should happen with
  `noexec` or MAC policies?
- Q3. Keys: introduce an offline root key and a key-set document now, or keep a
  single release key with an embedded set and accept the compromise impact.
- Q4. Should a below-floor service refuse to start (security), or start with a
  persistent warning (availability)?
- Q5. Freeze protection: should manifests gain a signed expiry or timestamp,
  and should Desktop warn when metadata is stale?
- Q6. Version floor or integer rollback index?
- Q7. Authenticode-sign the Windows Core (and Desktop) executables. This is a
  separate decision, but it strongly affects UAC.
  - Without signing, the consent prompt shows "Unknown publisher", which
    malware can imitate.
  - App Control publisher rules and the "only elevate signed executables"
    policy cannot be used.
  - Signing does not stop elevation of an old signed binary. The data-only
    broker interface and the protected-ancestry check handle that.
