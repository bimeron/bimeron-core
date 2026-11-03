# Privileged repair session

## Durable developer identity extension (implementation acceptance)

Current boundaries: Windows recovery requires protected image ancestry and the
daemon's actual SID/session. An alternate-administrator launch is not attributed
to the original GUI user. Writable Windows development images can still launch,
but cannot be adopted by this recovery path. Optional record failures are reported
without blocking ordinary daemon startup or changing successful cleanup to failure.
Linux retains an executable descriptor and revalidates the live executable on
authenticated connections; this is not an atomic prohibition on a privileged
peer executing another image after validation.

New elevated developer daemons persist a machine-protected launch record before
serving requests. Recovery must match authenticated caller UID/SID, session where
applicable, PID and OS process creation identity, and live executable digest. A
retained process handle/pidfd and authenticated endpoint prevent PID reuse. Only
explicit disruption consent permits stop/shutdown; clean daemon completion and
process exit must both precede service restoration. Legacy or malformed records
fail closed. Records are not executable paths supplied by the Desktop journal.
Fixtures must cover mismatched identity, PID reuse, missing cleanup proof and
consent denial; real elevated lifecycle remains disposable-guest acceptance.

This implementation extends the approved Desktop compact repair contract. It is
not release acceptance: privileged VM sequences remain untested.

## Boundary and scope

`repair-session <128-bit-lowercase-hex-session> <caller-pid>` accepts exactly one
bounded request over a private local endpoint. Windows binds the actual pipe
client to a retained process handle, SID and session; Linux binds SO_PEERCRED to
the expected PID and UID. The platform factory receives that authenticated
identity, not identity fields supplied in JSON. The request allows only protocol
version and disruption/network-recovery consent booleans. No command, shell,
executable path, payload digest or installation directory is accepted.

The protected broker owns inspect, install/start, stop/cleanup/start, component
replacement, readiness and rollback in the original elevated process. It never
invokes runas, pkexec or sudo. Windows installation preserves authenticated caller
ownership even when another administrator authorizes UAC. The transport closes
its listener after accepting the single connection and emits bounded stages and
terminal result. Closing the GUI does not cancel already-authorized mutations.

The running broker and installed paths must be protected. Windows retains image
and directory handles with ACL checks. Linux checks root ownership, nonwritable
permissions and symlink exclusion. The factory must be entered only after
transport authentication. Desktop remains responsible for trusted broker delivery.
Existing updater caller-supplied hashes are not publisher authenticity; repair
instead computes the digest of its own protected running image inside the
privilege boundary. External downloaded executable paths are not accepted.

## Implemented operations

- Missing service: verify absence, conflict gates, install from protected broker,
  start, hello and fresh status. Failure after installation triggers rollback.
- Owned stopped service: verify ownership and cleanup, conflict gates, start,
  readiness. Windows matches SCM path, account and owner; Linux matches exact
  unit, loaded fragment, command/account and absence of drop-ins.
- Owned unresponsive service: explicit disruption consent, graceful stop, exit
  and cleanup proof, start and readiness. No process termination is used.
- Confirmed owned leftover networking: explicit risk consent, scoped existing
  recovery APIs, verify owned artifacts absent, start and readiness. Linux uses
  the protected canonical recovery journal; Windows observes owned WFP/NRPT
  markers. Unknown endpoints, locks and ownership fail closed.
- Incompatible IPC: replace from protected broker image transactionally. Healthy
  IPC-compatible Core release versions are preserved; semantic version difference
  alone is not incompatibility. The updater verifies exact replacement version
  and fresh status before committing its backup.
- Missing/invalid owned service executable: verify canonical configuration,
  protected parent and exited process/cleanup evidence, stage broker image,
  atomically replace, activate/readiness, restore backup on failure. Missing
  original images are removed on failed activation after safe deactivation.
- Dead interrupted development transition can restore normally when no conflicting
  endpoint or lock remains. A live legacy daemon cannot be safely adopted: the
  Desktop v1 journal records intent but no durable process identity. It receives
  a precise failure; PID, endpoint name or matching SID alone never authorizes
  shutdown or network recovery.

The operation has a three-minute context and a separate thirty-second rollback
budget. Readiness probes are bounded to thirty seconds. Platform OS calls that
cannot be interrupted remain a runtime validation concern. Legacy update paths
now accept the session context. Linux privileged commands use absolute system
paths and sanitized environments.

## Remaining limitations

No trusted missing-broker bootstrap is supplied by Core itself. Desktop/installer
must provision the protected broker without elevating writable downloaded code.
Signed external acquisition supplies Wintun only, for the exact protected broker
release, as described below. Executable replacement uses the protected running
broker. Native tunnel startup is not claimed by hello/status readiness. Durable
identity for new developer sessions is implemented but remains under security
validation; live legacy identity cannot be reconstructed from the old journal.
ARM64 runtime and privileged VM repair/rollback/UAC behavior remain unverified.

Desktop's optional bootstrap embeds reviewed architecture-matched broker bytes
and, on Windows, Wintun in an updated protected GUI. Its headless entry provisions
the broker and transfers control without another elevation. The Core session
protocol is unchanged. Default Desktop builds embed no broker. Older GUI packages,
old pinned Core archives and wholly writable portable installations cannot supply
this trust root. A publisher must deliver the updated protected package; no
caller-supplied hash or writable downloaded executable substitutes for it.

No disposable guest or secure guest credential reference is assigned to this
repair validation. Existing running Windows 10 STD and unrelated lab guests must
not be restored or modified. Acceptance requires an explicitly assigned disposable
clone, an isolated network plan and secure guest access before lifecycle tests.
Historical VM update evidence is not repair-session acceptance.

## Evidence

Native Windows `go test ./cmd/bimeron ./internal/windowsnet` passed without
installed service or network mutation. Linux test binaries cross-compiled with
CGO disabled. Runner tests cover stopped/missing/healthy/unknown, consent refusal,
stop and cleanup failures, cancellation, install failure, rollback ordering,
contradictory ownership, replacement ordering and stage events. Hello fixtures
verify preservation of different compatible release versions. Separate transport
fixtures cover bounded request parsing and private authenticated endpoints.
These are not proof of actual elevation count or privileged platform lifecycle.

### Final adapter additions

Existing Windows service repair now detects a missing, invalid or wrong-machine
Wintun DLL. It stages the broker-adjacent protected DLL after ACL, architecture
and hash checks, preserves a fixed backup and commits it only after the service
repair succeeds. Failure safely stops the service before restoring that backup.
This corrects the earlier executable-only limitation; it does not prove real
VPN connection or tunnel behavior. The later signed acquisition extension below
adds a download fallback; no DLL is caller-selected.

A dedicated protected machine repair mutex/flock is held for the entire backend
lifetime. A concurrent broker fails busy instead of racing installation. Readiness
also requires a recognized authoritative status state: omitted, failed and
stopping states cannot report ready. Healthy connected/connecting/reconnecting
service states are preserved. Unreachable speculative live-daemon reconciliation
was removed after review: v1 journals cannot establish a lost live process identity.


Repair-specific updater mode activates and verifies even an initially stopped
service before committing the executable backup. Legacy `service update` keeps
its previous stopped-service behavior. This distinction is essential when a DLL
repair first stopped the service: neither DLL nor executable repair may commit
merely because copying succeeded.

## Final source verification (2026-11-03)

After the sidecar transaction, forced activation and cancellation-after-install
rollback corrections, the backend source was frozen for these checks:

- Native Windows amd64: `go test ./cmd/bimeron -count=1` passed (0.160 seconds).
- All four Core targets compiled with `CGO_ENABLED=0`, `GOOS=windows|linux` and
  `GOARCH=amd64|arm64`: `go build -o bin/repair-final-<os>-<arch>[.exe]
  ./cmd/bimeron`. These are ignored verification binaries, not release packages.
- Linux amd64: `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test ./cmd/bimeron -c
  -o bin/repair-final-linux-test` compiled the test executable. WSL then ran it
  natively from `cmd/bimeron` with `../../bin/repair-final-linux-test -test.run
  "Repair|Update|FailedStop|MissingStaged|FailedIPC|StoppedService|PendingLedger|LegacyWindows"
  -test.v`; all selected tests passed.

The final Linux run includes replacement sequences, cancellation after install
with rollback, compatible-release preservation, authoritative status, stopped
repair activation before commit, sidecar restoration on rollback, unchanged
legacy stopped-update behavior, request boundaries, cancellation budgets and
update failure/crash ledgers. These fixtures use fake lifecycle callbacks and
temporary files. No installed service or host networking was changed. Windows
ARM64 and Linux ARM64 remain compile-only evidence; real privileged UAC/polkit,
installer migration and VM rollback acceptance remain outstanding.

### Stopped replacement and bounded transition discovery

Stopped executable/DLL replacement does not request disruption consent; confirmed
network cleanup still requires its separate consent. Platform snapshots explicitly
retain the stopped state for replacement. Immediately before replacement, adapters
refuse a stopped-to-running change rather than stopping a newly active service.
Repeated diagnosis releases old Windows service/image handles and resets transient
flags before obtaining fresh observations.

SCM pending states and systemd activating/deactivating/reloading are observed for
at most thirty seconds within the original session context. This only repeats
read-only observations; access errors terminate immediately and no mutation is
retried. Fixtures cover pending-to-stable, cancellation, inspection errors,
stopped replacement without disruption consent, and retained network-consent gates.

## Same-session discovery consent and final revalidation

Fresh broker observations may discover disruption or owned network cleanup that
was absent from the GUI snapshot. Before mutation, the broker can emit at most
two challenges on the existing authenticated connection:
`{"consent":"disruption"}` or `{"consent":"network-recovery"}`. The only reply
is `{"consent":"<matching-kind>","approved":true|false}` followed by newline.
Each reply is limited to 1024 bytes; the initial request plus both replies are
bounded to 3072 bytes. Unknown fields, missing/nonboolean approval, wrong challenge
kind and trailing JSON fail closed. A challenge waits at most 60 seconds and
cannot extend the three-minute transaction deadline. Denial is terminal with
`consent-denied`; it never relaunches elevation.

After new approval, the runner repeats ownership/state inspection and rebuilds
the plan. A service that became healthy during consent receives readiness checks
only, not the previously planned stop. Only previously unapproved risk kinds can
trigger a challenge, so reinspection cannot create a consent loop. A stopped
replacement does not need disruption consent; owned leftover network recovery
still requires its own risk approval. Platform replacement adapters additionally
reject a stopped-to-running transition immediately before mutation.

After these final changes, all four Core builds at `bin/repair-final-*` and the
native WSL Linux focused suite described above passed again. Native Windows
`go test ./cmd/bimeron -count=1` passed again. New fixtures cover both challenges,
denial before mutation, timeout before mutation, strict reply fields, and a service
becoming healthy during approval (inspect, inspect, ready; no stop). Build outputs
postdate the final adapter changes. Privileged VM acceptance remains outstanding.

## Signed missing-sidecar acquisition follow-up

Acceptance: when the protected broker's Wintun source is missing or invalid,
repair may obtain that DLL within the original authenticated elevated session.
Only the exact protected broker build version is eligible; caller JSON cannot
select metadata, URL, version, key, digest or archive member. Production uses the
existing Desktop Ed25519 public key (key ID `7370a2d8cf890e5e`), not a new trust root.

`repair_acquire.go` verifies the existing signed update-manifest envelope, all four
unique platform targets, exact release/channel, reviewed GUI window [0.2.0,0.2.1),
IPC 1 and profile format 1, signed archive length and SHA-256. The deliberately
narrow GUI-window policy rejects other windows rather than guessing compatibility.
Signatures cover exact manifest bytes; duplicate JSON keys are rejected. Downloads
use HTTPS with no ambient proxy, fixed GitHub repository/tag paths, a restricted
redirect host set, four-hop limit, 45-second request timeout and the existing
session context. Metadata is bounded to 64 KiB; archives to 100 MiB; extracted
members to 64 MiB. The in-memory candidate is the bounded per-attempt cache; no
persistent untrusted cache is adopted. ZIP path traversal and symlink members are
rejected. The authenticated member is written exclusively under the protected
service directory, then Windows protection and PE architecture are revalidated
before the existing hash-checked sidecar transaction. The source is removed at
attempt completion. Existing rollback/verification and elevation count are unchanged.

This path currently supplies **Wintun only**. Executable replacement continues to
use the protected running broker image; no downloaded executable is elevated.
This does not bootstrap a missing broker. A publisher must publish a manifest
signed with the existing private key for the actual broker build version, reviewed
for the stated GUI window, and a matching platform ZIP containing the DLL. A
nonrelease/development version fails explicitly. No private key is needed in this
repository, and no new release/hash or signature was fabricated. Runtime network
acquisition and privileged DLL restoration still need disposable-VM acceptance.

## Integrated development validation (2026-11-03)

After acquisition and developer-record hardening, native Windows
`go test ./cmd/bimeron ./internal/control ./internal/windowsnet -count=1` passed.
All four Windows/Linux amd64/arm64 builds passed with `CGO_ENABLED=0` and explicit
`GOOS`/`GOARCH`. Outputs are `bin/repair-reviewed-<os>-<arch>[.exe]`.
The Linux amd64 command test binary was cross-compiled and executed natively in
WSL with the Developer, Repair, Update and focused lifecycle fixtures; it passed.
Private socket/pipe credential tests and fake signed-manifest/archive/download
tests require no installed service or network configuration changes.

`bin/repair-reviewed-artifacts.json` records absolute paths and SHA-256 digests
provided to Desktop for positive embedded-payload development tests. The source
is base revision `55ddd84f0104ec2d98e931772b3156589aa3136c` plus the uncommitted
`feat/single-elevation-repair` working tree, not a published release. These builds
do not supply signed release metadata for production acquisition. ARM64 remains
compile-only. No privileged guest acceptance, production mutation, commit or
publication was performed. The complete repair contract is not yet accepted.

### Missing Windows developer record regression

Acceptance: an installation that has never started a recorded developer daemon
must proceed to ordinary service inspection when the optional developer record
file or directory is absent. Windows image/directory locking must preserve the
native not-found cause while retaining the identity-rejection classification.
Access denial, sharing violations, untrusted ownership/ACLs and redirected paths
must still fail closed. No record is synthesized for an existing legacy daemon;
its endpoint continues to block mutation until that daemon exits safely.

Native regression fixtures must exercise missing files and missing parent paths,
and verify that non-absence errors cannot pass the optional-record absence gate.
This correction changes error propagation, not the protected-path policy.

### Repair readiness protocol regression

Acceptance: ordinary service status requests contain only ordinary IPC request
fields; the response instance must still equal the successful hello instance.
The foreground-only request instance field is not accepted by the standard
service dispatcher. Exercise readiness against the real standard control server
on a private listener with an inert engine, including response instance changes
and failed states. Apply the same handshake to service update verification.

### Missing-record/readiness correction validation (2026-11-04)

Windows protected locking now preserves native absent-file/parent errors while
retaining identity rejection; optional developer records no longer require an
already-created directory. Tests cover both public lock wrappers and reject
sharing conflicts as absence. Standard readiness requests omit the foreground-only
instance request field, then compare nonempty hello/status response instances.
The same helper serves repair and update checks. A real standard control server
with an inert engine verifies the wire contract. go vet also exposed and corrected
a malformed OS JSON tag in repair acquisition.

Native Windows go test ./cmd/bimeron ./internal/control ./internal/windowsnet and
go vet passed. Focused repair/developer/update/readiness fixtures passed natively
under WSL; all four target binaries built at bin/repair-record-fix-<os>-<arch>.
ARM64 remains compile-only. On the user's authorized Windows host, protected broker
repair installed and started the absent service, verified readiness and returned
ok=true; repeating with the final broker only inspected/verified the healthy
service. The prior disconnected local daemon exited through normal authenticated
IPC, without a forced kill. The manually prepared broker directory also needed its
existing package Wintun license. Service-pipe OS PID and matching hello/status
instances were verified; VPN stays disconnected. This result does not complete
alternate-credential, real UAC-count or disposable-VM matrix acceptance. No release
or package pins were changed and no publication or commit was made.
