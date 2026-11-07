# Proposed unified protected installation and first GUI IKEv2 contract

## Step 4 status: conditional consumer lifecycle proposal

The canonical decision proposal is Desktop
`docs/ikev2-installation-contract.md#step-4-decision-proposal-consumer-windows-lifecycle`
on the paired `plan/ikev2-installation-contract` branch, coordinated in
[Step 4](t3-thread://v1/mcp:d8ce536e-1c05-4247-9eed-8215bedf7a6a).
It conditionally recommends B: existing foreground/provisioning owners, offline
MSI payload servicing and Core-owned runtime enrollment, RAS/DNS/WFP and recovery.
No new resident broker, exact deferred-action attestation or managed-host policy
is a default prerequisite. This replaces proposed requirements only after explicit
product/security acceptance; it does not satisfy or erase the Step 2/3 design below.

Ordinary-user-triggerable cached maintenance remains within the protected scope;
actual historical packages/helpers must demonstrate exclusion or refusal before
conflicting mutation. Maintenance must quiesce runtime work and prove cleanup
before deleting recovery bytes/state. Owner exit, Restart Manager and SCM Stopped
are not cleanup evidence. Current RAS-before-WFP sequencing and recovery without
RAS reconciliation keep B conditional: the protection interval needs acceptance
or redesign, followed by separately authorized bounded lifecycle feasibility work.
Native remains disabled. No implementation, experiment or release is authorized;
the earlier codec-first recommendation is not the next milestone for proposed B.

**PROPOSED semantic v1 — REVIEW PENDING, 2026-11-03.** Step 2 evidence preserved;
Step 3 concrete engineering selections appear in the appendices below.
This is neither user/security acceptance nor permission to implement, execute MSI,
run native experiments, enable enrollment or release artifacts.

## Provenance and existing capabilities

This proposal was inspected on clean Core branch `plan/ikev2-installation-contract`,
HEAD and local master `6af5d72bd7e1e98461e78f437509a1994f395fab`, at
`<LOCAL_WORKTREES>/bimeron-core/plan-ikev2-installation-contract`.
The prior audit at `0b9158ed` is not evidence about this master. No root/geodata
checkout or old audit worktree was modified. Read prerequisites: Core AGENTS.md,
the complete native enrollment specification, Desktop AGENTS.md and the complete
Desktop `docs/build-and-packaging.md` in its isolated planning worktree. Core has
no `docs/build-and-packaging.md`; no counterpart is invented here.

The paired Desktop proposal is `docs/ikev2-installation-contract.md` on Desktop
`plan/ikev2-installation-contract`, based on `943c92d77a9c51587d94db49b3c32bf5b1f2737c`.
Both proposals must change together when their shared semantics change.

Narrow source inspection at the Core SHA above establishes these reusable pieces:

- `internal/windowsnet/network_windows.go`: `BeginInstallationTransaction()`
  acquires the connect mutex, pins the acquiring OS thread and returns its release
  function. It refuses abandoned acquisition and a present/unknown foreground
  marker. It supplies no durable journal, MSI controller or host participation.
  The search found its definition but no production caller.
- `internal/control/foreground.go`, `foreground_windows.go` and
  `cmd/bimeron/foreground_windows.go`: authenticated foreground discovery,
  exact unmodified `accept_revision`, instance/session binding, status/events,
  stop and explicit terminal `close_owner`. These are existing experimental
  interfaces, not proof of an accepted installed Core/Desktop pair.
- `internal/control/profile_control.go` and `internal/systemvpn/profile_windows.go`:
  separate preview owner, `state_token`/`plan_token`, reviewed apply/remove,
  recheck under the mutation lock, profile ownership and synchronous rollback.
  An incomplete journal refuses; this does not provision credentials or CA trust.
- `internal/nativeenrollment/model.go`, `file_reader_windows.go` and
  `update_health.go`: strict 64-byte BIMNENR1 codec, disconnected protected-file
  observer and offline update evidence classifiers. No production imports were
  found outside tests. `EligibleModelOnly` is not a permit; matching reads are not
  atomic admission. Expected-binding disappearance refuses. Native folder reading
  supports native amd64/arm64 only, not emulation or 386 positive acceptance.
- `cmd/bimeron/service_update_windows.go`: the existing updater stages/verifies,
  stops and replaces the service, checks candidate IPC when previously running,
  and on rollback restores the prior running/stopped state. Restored-running
  checking is SCM-only. Its update mutex is separate from the connect mutex;
  it does not implement enrolled admission or installation settlement.

These are source observations, not tests rerun in Step 2 or new native evidence.

## Reconciliation and ownership

The [older trusted-invocation route](NATIVE_ENROLLMENT_SPEC.MD#selected-trusted-invocation-procedure)
remains historical conditional prototype context. This proposal replaces that
direction with a Core owning-thread installation controller, subject to review.
Already-elevated same-user MSI invocation, effective callback token checks and a
post-Finalize acknowledgment cannot substitute for outer transaction ownership,
authenticated package/action/preload authority or durable terminal closure.
`verifyInitiatingClient` remains Unknown; none of those observations is promoted.
No existing accepted offline scope or frozen evidence is retroactively changed.

Core owns privileged installation, enrollment history, participating admission,
rollback/restoration, recovery and settlement. Desktop owns explicit consent,
authenticated status presentation, profile selection and foreground/provisioning
UI. MSI actions perform only the admitted bounded work; they cannot settle.
The installation owner is distinct from VPN and profile-provisioning owners.
Neither closing a transport nor exiting any process proves settlement.

Retain the existing threat boundary: Windows and authorized privileged principals
are trusted; malicious administrators/offline state rollback are outside it.
Ordinary users must not redirect, replace or delete authority. Elevation alone is
not package approval. Preserve protected ancestors, held image/object identities,
effective token checks and same-user interactive foreground peer authentication.
An authenticated pipe identifies a process, not its loaded action/export or MSI
session. Action and preload proof is an additional unresolved obligation.

## Minimal scope and nondeferrable refusal

Propose the first supported GUI connection on Windows amd64, one reviewed exact
Core/Desktop pair, a freshly and completely inventoried host with no legacy
installation, explicit enrollment, explicit owned-profile preview/confirmation,
foreground connect, Stop, verified cleanup and owner closure. No automatic native
reconnect/autostart, packet fallback, successful unenrollment or legacy migration
is needed for this first slice. ARM64 runtime support is a separate evidence gate.

Fresh means a verified no-predecessor baseline covering running/registered/cached
hosts, services, recovery/start paths, policies, images and rollback resources,
not a missing file or empty process list. Refuse any unknown/incompatible member.
Successful migration/repair/upgrade/removal may be deferred; safe refusal of their
direct, cached and nested routes cannot be deferred. An old ungated MSI cannot be
fixed by a check in a new controller it never calls. Preventing its later execution
against enrolled resources needs enforceable control or a revised product boundary.
No such mechanism is established on this base. Without one, even first fresh-host
GUI enablement remains blocked. A procedure telling users not to run it is insufficient.

Ordinary trusted Unenrolled packet behavior and signed update guarantees remain
unchanged. Enrolled incompatible update/repair routes refuse before mutation.
Admitted operations must preserve rollback and service restoration while Pending;
refusing every restart would make safe completion impossible.

## State and durable admission

`Unenrolled` requires authenticated complete no-predecessor evidence or an explicitly
retired failed-enrollment baseline with durable history. Native is unavailable.
`Settled` binds exact generation, approved pair and verified terminal inventory.
`Pending` binds admitted work and fences NEW conflicting participating work.
`Unsafe` is contradictory, corrupt, incomplete or uncertain authority and refuses.
Absence, access denial, sharing/query failure and unexplained disappearance are
distinct. Absence alone cannot erase prior enrollment or uncertainty.

All conflicting participants must share serialization and durable admission:
foreground/provisioning owners, packet service/start/recovery paths, update helpers,
installation actions and nested/cached old-product hosts. Atomically recheck and
acquire admission at actual launch/mutation; a prior status read is insufficient.
Close new admissions before acquisition can become ambiguous, drain existing work
without forced termination, then acquire the owning-thread guard. An acquisition
exception may mean it succeeded. Only proven-not-acquired with a live verified
unchanged baseline permits clean refusal. Durable fencing must survive controller
death before Pending publication too; the current volatile mutex cannot supply it.

BIMNENR1 remains a 64-byte observer format, not the full journal or an admission
capability. Desktop LPF48 remains separate; neither converts into the other.
The proposed store needs protected history, operation/plan binding, full inventory,
durable intent and terminal publication outside replaced/removed payload trees.
Its location, schema, atomic publication and recovery protocol require review.
Do not silently extend the existing fixed-location observer into a writer or grant.

## Controller order, restoration and crash recovery

1. Independently approve and stage/pin exact controller, GUI/Core pair, effective
   MSI database/Binary/preload, architecture, external payloads, allowed mutation
   properties, complete domain and rollback/service baseline. Staging must survive
   replacement/removal. Refuse transforms, patches and unapproved routes.
2. Establish guarded admission intent and drain conflicting work. Retain
   `BeginInstallationTransaction` on one owning OS thread. On that thread create
   a new outer `MsiBeginTransaction`; refuse existing transactions, never Join.
3. Publish bound Pending, flush and verify trusted readback before the exact
   synchronous `MsiInstallProduct`. Every effective participating package requires
   mandatory execute-sequence preflight AND first deferred admission gate before
   mutation, including direct/quiet/maintenance/cached/nested routes. Conditions,
   public properties and CustomActionData cannot bypass or confer authorization.
4. End commit or rollback on the same owning thread. Successful End supplies
   completion only for its proven bounded domain. Independently verify final
   inventory and closure, durably publish/read back settlement, release guard last.

Pending write/flush/readback failure after Begin prohibits Install and attempts
same-thread End rollback. Partial publication or unknown End requires recovery,
not absence inference. Failed Install followed by successful End rollback, exact
baseline restoration, complete closure and durable terminal publication is
`RestoredFailure`, never a successful install. Reboot, disabled rollback, unknown
End, incomplete inventory, late work and uncertain release cannot report success.

Bind every continuation to exact installation/generation/pair/operation/plan and
its admitted domain. Already admitted standard MSI segments may outlive the
controller. Separate surviving authority must permit only their exact rollback
and service restoration while Pending, without reacquiring the controller-held
mutex or settling first. It cannot admit a new network session or unrelated start.
Signed verification, candidate/rollback image pins, original running/stopped state
and required health observations must survive. Ordinary dispatch must remain
fenced; any proposed read-only health mode needs an authenticated restricted startup
gate. The disconnected health model and SCM Running alone do not establish this.

Closure must prevent future mutation by every nested action, rollback worker,
service continuation and delayed server segment. Refuse detached/chainer/reboot or
out-of-domain work. A quiet interval or inventory snapshot does not prove closure.
Controller death never calls End, settles or grants new work. Status becomes
RecoveryRequired when authority is uncertain; retain protected records and fence.
Explicit separately reviewed recovery must authenticate the exact outstanding
operation, reconcile commit versus restoration, establish domain closure and
durably publish its terminal result. No retry, timeout, force-kill or record deletion
is recovery. Failed first enrollment needs durable retirement/history before
Unenrolled can be reestablished. Successful unenrollment remains a separate contract.

## Fixed semantic v1 interfaces (design only)

These names are shared with Desktop, not released CLI commands, Go exports or wire
schemas. Encoding and authentication must be reviewed before production adapters.
Unknown version/field/enum, missing binding or malformed/oversized input refuses.
Canonical plan encoding, byte bounds and transport framing remain explicit decisions.

- `InstallationBinding { installationId, generation, pairIdentity, operationId,
  planDigest }`: exact equality; fresh nonreused generation/operation; pair binds
  Core revision/digest, GUI digest, architecture and compatible contract versions.
  Plan digest covers canonical approved inputs. These public values are not grants.
- `ApprovedInstallationPlan { binding, action, baseline, targetInventory,
  packageSet, mutationDomain, serviceBaseline }`: protected approved reference only,
  no arbitrary executable/path/command or caller-selected mutation properties.
- `InstallationStatus { availability: Ready|Unavailable|Unsafe,
  phase: Unenrolled|Settled|Pending|Unsafe, binding, reason, outcome }`, outcome
  `InProgress|Committed|RestoredFailure|RecoveryRequired`. Known Pending is
  Unavailable; unverifiable authority is Unsafe. Ready requires matching verified
  Settled state and compatibility but is not a reusable launch permit. A restored
  outcome is interpreted against its actual baseline; Unenrolled is never Ready.
- `GetInstallationStatus(expectedBinding)` and `GetInstallationOperation(binding)`
  observe authenticated state only. `ExecuteInstallationPlan(protectedPlanReference)`
  admits one bound operation; duplicate IDs return its result without reexecution.
  Lost replies require exact lookup, never a new-ID retry. Different data under
  the same ID refuses. Terminal operation records retain the full binding.
- `CloseInstallationOwner(binding)` closes only the caller's operation-owner
  lifecycle after verified terminal conditions. It cannot settle, delete durable
  records, terminate continuation or replace VPN/provisioning `close_owner`.
- Internal-only `AcquireParticipatingAdmission(role,binding)`,
  `AuthorizeInstallationAction(actionEvidence,binding)`,
  `ContinueBoundRestoration(continuationEvidence,binding)` and
  `RecoverInstallation(recoveryPlan)` obtain independent authority. No public
  Settle/Clean endpoint, verified boolean or ignore-barrier argument exists.

Proposed finite reason vocabulary: `ready`, `notEnrolled`, `operationPending`,
`unsupportedContract`, `invalidRequest`, `bindingMismatch`, `pairMismatch`,
`unsafeEvidence`, `incompatibleHost`, `packageRejected`, `actionUnproven`,
`preloadUnproven`, `ownerBusy`, `acquisitionUncertain`, `durabilityFailed`,
`terminalUnproven`, `recoveryRequired`. Unknown reasons fail closed; no arbitrary
elevated error text, paths, profiles or credentials cross this boundary. Exact
encoding and applicability rules require the paired adapter specification.

Desktop receives authority-related status only through authenticated Core responses.
Local Gates booleans, capabilities, package success and model Clean cannot produce
grants. Existing foreground read-only hello precedes exact `accept_revision`
activation; retain image/config digest, installation/instance/session checks,
status/events, stop and terminal close. Profile control retains its separate
preview/state_token/plan_token and mutation-time ownership recheck. Neither path
may bypass the new atomic participating admission check.

## Dependency-ordered implementation and file targets

1. Review this paired proposal and resolve the concrete security decisions below.
   Track implementation in issues (existing enrollment context is issue #73), on
   separate branches; discuss PR scope before opening. Record accepted architecture
   and alternatives in a new ADR after acceptance, not as an accepted ADR now.
2. With enablement off, add proposed `internal/installation/{contract,controller,
   admission,recovery}.go`, Windows store/action/MSI adapters and focused tests.
   Add proposed `cmd/bimeron/installation_windows.go` only after the invocation
   and plan schema are accepted. Reuse observer validation where applicable, with
   explicit changes in `internal/nativeenrollment/`; never treat Evaluate as permit.
3. Integrate durable participant acquisition with `internal/windowsnet/network_windows.go`,
   `internal/control/foreground_windows.go`, `foreground.go`, `profile_control.go`,
   `core/ikev2_windows.go`, `internal/systemvpn/profile_windows.go` and all enumerated
   packet/recovery paths. Update `cmd/bimeron/service_windows.go`,
   `service_update_windows.go` and `service_update_files.go` for enrolled bound
   restoration without changing unenrolled behavior or Linux shared-helper semantics.
   Writer, consumers and restoration must be delivered coherently; partial wiring
   cannot be enabled. Audit the complete entry-point inventory before connecting it.
4. Desktop implements approved production action gates/sequence in
   `packaging/windows/options.wxs`, new reviewed production action source and
   `CMakeLists.txt`; do not repurpose always-failing lab exports. Bind final artifacts
   via `cmake/core-release.cmake` and protected approval generation. Package gates
   depend on accepted preload/action authentication and historical-route prevention.
5. Desktop adds proposed `src/NativeInstallationClient.{h,cpp}` and updates
   `NativeIKEv2Transport`, `NativeIKEv2Session`, `CoreUpdater` and `MainWindow` for
   authenticated status, explicit provisioning/connect/stop and retained cleanup.
   Disabled typed adapters/UI fixtures can proceed alongside Core after contract
   acceptance; independent production wire/security adapters cannot.
6. Run focused CI and separately authorized native acceptance on exact paired
   artifacts; review evidence before enabling only the proved first-GUI scope.

First GUI requires durable admission, package refusal, rollback/restoration,
closure, exact pair, provisioning and full foreground lifecycle. PR completion
requires all accepted scope/negative criteria and truthful platform/unsupported-route
documentation, not one successful connection; it does not by itself complete
Desktop PR #16. Prerelease additionally requires the supported Windows x64/ARM64
and Linux amd64/arm64 test/build/package matrix, payload inspection and separately
justified runtime/install claims. No release or matrix execution is part of Step 2.
Scheduler/observation-host experiments are deferred and have no dependency here.

## Negative acceptance and evidence

Future tests must reject stale/replayed bindings; unknown versions/fields; wrong
pair/architecture/SID/session/peer; status-to-launch races; substituted plan, Binary,
effective DB or preload; forged action/export/CAD; skipped gates on quiet/cached/
nested routes; active old hosts and direct historical ungated packages. A positive
new-package test cannot establish old-package prevention.

Inject failure/death before and after acquisition, Begin, each Pending write/flush/
readback, Install, End, inventory, publication and release. Check no mutation before
durable Pending, no dead controller progress, no uncertain state becomes Ready,
and exact continuation survives only within its admitted domain. Test restoration
while Pending without deadlock, running/stopped baselines, candidate health failure,
retained backups, late continuation after closure, failed first-enrollment retirement,
and lost replies with no duplicate execution. Preserve ordinary packet regressions.

Use focused tests in new `internal/installation/*_test.go`, existing control/profile/
nativeenrollment/service-update tests and `.github/workflows/go.yml`; extend Desktop
transport/session/connection-management fixtures. Offline tests prove logic only.
Future native evidence must separately establish protected storage/durability,
real owning-thread behavior, authenticated actions/preload, competing actual hosts,
historical route prevention, death/rollback/restoration and enforceable closure.
Then prove the actual protected GUI handshake, provisioning confirmation, RAS,
DNS/WFP protection, Stop/cleanup/close and failure UX on exact hashes/OS/architecture.

Reuse existing source contracts, codec/model regressions and historical foreground/
profile/ACK observations only at their recorded scope and identities. They do not
prove the new controller. Desktop LPF48/ACK, finite models and Scheduler results
are not enrollment authority; unknown outcomes stay unknown. Frozen evidence,
VM state, tasks, handles and prior audit remain untouched. No native experiment,
test/build, benchmark or package matrix was executed for this documentation change.

## Concrete decisions blocking acceptance

1. **Durable authority/history:** choose a protected operation/history store plus
   atomic participant serialization, including death before Pending. Extending the
   observer alone is insufficient. A companion journal preserves the small codec
   but adds cross-record atomicity; a new authority store needs a migration/reader
   contract. Choose schema/location, fencing, generation allocation and retirement.
2. **Action/preload authentication:** specify the producer and verifier binding
   independently approved effective package, loaded Binary/action/session and outer
   operation before load/mutation. Process authentication or properties alone fail.
   Select a concrete enforcement mechanism; otherwise do not connect package gates.
3. **Historical package exclusion:** choose enforceable prevention of old ungated
   direct/cached execution on enrolled resources, or revise deployment/security scope.
   Fresh-host inventory reduces migration work but does not solve later bypass.
4. **Closure and survival:** define a closed admitted mutation domain, surviving
   rollback/service authority, revocation after closure and crash recovery evidence.
   Ordinary MSI End is only domain-bounded evidence, not a general late-work fence.
5. **Adapter and artifact contract:** select bounded canonical plan/wire encoding,
   authentication, approval producer, version negotiation/refusal and exact supported
   OS/architecture/pair. Resolve before production adapters or final artifact pins.

The Step 3 appendices select storage/admission and adapter details for engineering
review. The action, platform-policy and surviving-executor blockers remain open.
These alternatives need user/security review, not an implementation-time guess.
If they cannot be satisfied in the narrow Core-owned route, return a revised
proposal; do not weaken refusal or claim first-GUI readiness.

## Step 3 selection and acceptance boundary

Inspected again on the same HEAD and existing worktree, preserving all three
uncommitted Step 2 documents. T3 binding was independently verified as Core
project `1f5b8de3-79ba-4357-971b-eca7e285d6d8`, thread
`mcp:9aa0a236-9f66-4d64-a12c-29040cfa3fae`. The paired Desktop coordinator accepted
the shared storage/wire choices as **engineering selections for documentation**.
That is neither user/security acceptance nor native validation. No new accepted
ADR, release approval, production command or packaging canonical is created.

Appendices A and B supersede the earlier unspecified storage/encoding choices.
Gate 1 has a concrete design, pending implementation and durability validation.
Gate 5 has bounded adapter fields and a detached approval producer, pending
security acceptance and actual artifacts. Gates 2, 3 and 4 retain explicit
action/session, platform-policy and surviving-executor blockers. Consequently the
whole production contract is NOT implementation-ready or first-GUI-ready.
Only the disconnected storage/codec slice below is ready to propose next.

## Appendix A: authority, journal and atomic participant admission

### Fixed authority and bootstrap

Select native `FOLDERID_ProgramData`, flags zero, fixed suffix
`Bimeron/InstallationAuthority/v1`. This is independent of the replaced Program
Files payload, MSI component ownership, ordinary repair and uninstall. Files are
`anchor.json`, `history.wal`, `plans/<planDigest>.json`, and
`objects/<sha256>.json`; no environment override, caller path or registry fallback.
An approved independent bootstrap provisions the anchor before enrollment, imports
detached approval and creates/flushed-verifies the initial journal. It is a new
scope requiring authorization, not an existing Core installer capability.

Anchor JCS object has exactly `schema` (integer 1), `authorityId`, `installationId`
(each nonzero 32 lowercase hex), `bootstrapApprovalDigest`, `policyProfileDigest`
(64 lowercase hex SHA256), and `rootKeyId` (1..64 ASCII `[A-Za-z0-9_-]`). Maximum
anchor size is 4096 bytes. It is immutable for this authority lifetime. A trusted
bootstrap approval is independently signed under the selected verification root;
self-generated JSON or a directory created by the installer is not that approval.
Missing/invalid anchor, history or bootstrap approval always refuses the authority
profile. Never infer never-enrolled from absence, including on an apparently fresh
host. There is no create-on-read, automatic initialize, install reset or reenroll
over an old authority. Failed first enrollment retains its anchor and history.
`Unenrolled` is derived only from verified Bootstrap or explicit Retire history.
Ordinary packet behavior outside this new profile remains unchanged; selecting a
legacy route after an enrolled anchor disappears is forbidden. Enforcing that
selection against old hosts depends on the separate platform-policy blocker.

Resolve and hold the local fixed-volume root and every ancestor; reject reparses,
remote/device/ADS paths, case-sensitive components, ambiguous identities and
untrusted replacement rights. Require local NTFS and single-link authority files.
Authority owner is SYSTEM or Builtin Administrators; require protected non-null
DACL on the authority directory/files, allowing mutation only to those principals.
Reject unfamiliar effective ACEs and unsafe ancestors rather than repairing them.
TrustedInstaller ownership accepted by the older disconnected reader does not
silently broaden this new store. Windows adapter design must allow cooperating
trusted writers under the admission mutex. Deny write/delete sharing during each
short serialized IO operation, retaining the file handle through append, flush,
readback and identity checks, then close it before releasing admission. An
exclusive lifetime writer handle would deadlock cross-process journal writers.
Readers of authoritative status also serialize with that mutex. No unlocked
two-snapshot observation is promoted to admission.

### Bounded append-only records

Select UTF-8 [JCS, RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) canonical JSON
for anchor, plans, objects and journal payloads. Reject duplicate/unknown fields,
invalid UTF-8, BOM, noncanonical bytes, excessive depth (over 8), or trailing bytes.
Numbers are schema/version integers only; all uint64 values are decimal strings
without leading zeroes (zero allowed only where explicitly stated). No floats or
Unicode normalization. Hashes identify exact canonical bytes, not reparsed variants.

`history.wal` is at most 67108864 bytes (64 MiB), without automatic pruning,
compaction, rotation or reset. Each frame is four-byte little-endian payload length
N, N bytes canonical JSON, then 32 digest bytes. `1 <= N <= 65536`; the complete
frame is at most 65572 bytes. Its digest is
`SHA256(previousDigest || lengthLE || payload)`, initially using
`SHA256(anchor.json bytes)` as previousDigest. Sequence starts at `"1"`, increments
by one, never wraps or reuses. Read and validate the entire chain under the mutex.
Torn frames, trailing bytes, invalid transitions and hash/sequence mismatch are
Unsafe; never truncate to the last valid frame or automatically append past damage.
The chain detects corruption, not rollback to a valid prefix. Protected ACLs stop
ordinary writers; malicious privileged/offline rollback remains outside the threat
model. Disk/VM backup restoration requires explicit rebootstrap/recovery review;
neither this chain nor BIMNENR1 detects whole-store replay.

Each payload has exactly `schema`, `sequence`, `kind`, `binding`, `data`.
`schema=1`; binding is Appendix B's full binding or null only for Bootstrap.
The following discriminated `data` objects define all permitted record kinds:

- `Bootstrap`: `{anchorDigest, inventoryDigest}`; exactly once as first record.
- `Intent`: `{baselineDigest, targetInventoryDigest, owner}`; reserves the plan's
  next generation and operation ID and closes new participant admission. Persist
  the installation controller's OS-observed owner using exactly the LeaseOpen
  owner schema below before any guard acquisition or Begin.
- `LeaseOpen`: `{leaseId, role, owner, domainDigest}`; leaseId is nonzero 32 hex;
  role is `foreground|profile|packet|update|recovery`; owner is
  `{pid, created, sid, session, imageDigest}`, with pid/session uint32 decimal
  strings, created nonzero uint64 decimal string, SID at most 184 ASCII bytes and
  imageDigest SHA256. Identity is OS-observed, never copied from a client request.
- `LeaseClose`: `{leaseId, closureEvidenceDigest}`; requires the exact live lease
  and verified terminal domain evidence, not an asserted client boolean.
- `Pending`: `{domainDigest, continuationManifestDigest}`; after outer Begin and
  before any admitted installation mutation.
- `Terminal`: `{outcome, inventoryDigest, closureEvidenceDigest}`; outcome is
  `Committed|RestoredFailure`, with complete domain closure; prepares the verified
  target or restored baseline respectively, never merely the highest generation.
  RestoredFailure requires a prior verified Settled baseline; it cannot terminate
  failed first enrollment against an originally Unenrolled baseline.
  It remains publicly Pending and confers no new admission until ReleaseComplete.
- `ReleaseComplete`: `{terminalSequence}`; decimal-string sequence of the exact
  prepared Terminal (or Retire) for this binding, exactly once after proven connect
  release under admission serialization. Only this activates the prepared state.
- `Retire`: `{inventoryDigest, closureEvidenceDigest}`; failed first enrollment
  with the exact verified original Unenrolled baseline and full domain closure.
  The live original controller may prepare it directly after verified rollback;
  otherwise it requires separately accepted recovery. Checked connect release
  and durable ReleaseComplete are mandatory before it activates Unenrolled.
  It cannot implement successful unenrollment or erase operation IDs/generations.

All `*Digest` values are SHA256 hex. Record kinds do not accept additional data.
At most 32 unresolved leases; at most one unresolved Intent. New work refuses
before append if the journal would leave less than 1048576 bytes reserved for
closure/terminal records. No per-poll, heartbeat or progress records consume WAL.
One operation uses at most one Intent, Pending, Terminal or Retire, and
ReleaseComplete; lease open
and close occur once each. Exhaustion refuses new work and requires a separately
designed maintenance contract, never silently deletes history. Recovery evidence
objects are immutable and bounded as in Appendix B, not unlimited embedded logs.

Append using explicit checked offsets and complete writes, call
[FlushFileBuffers](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers),
then reread exact frame and retained file identity before allowing its effect.
A failed/ambiguous write or flush poisons this admission attempt. Do not claim that
readback proves power-loss durability: initial directory/file publication and
storage-stack persistence require separately authorized Windows validation. No
filesystem rename atomicity is assumed for multi-file authority; objects are
immutable and durably verified before a WAL record references them. Unreferenced
objects confer no authority. No production append or bootstrap is implemented here.

### Locks, leases and crash order

Select `Global\BimeronCoreInstallationAdmissionV1` as the short-held admission
mutex. Validate existing object type, owner and DACL with the same strict kernel
object policy as `Global\BimeronCoreConnect`; squatting or abandoned acquisition
refuses, never repairs. Acquire/release each mutex on its pinned OS thread. Never
wait for the connect mutex while holding the admission mutex. All connect
acquisitions below are zero-timeout, after admission mutex release; closing a
lease while holding connect may acquire admission because no inverse waiter exists.
Do not nest the existing independent updater mutex into an unreviewed lock cycle.

Participant admission is: authenticate exact role/image/binding and authority;
under admission mutex recheck Settled and no Intent, append/flush/readback LeaseOpen;
release admission mutex; acquire connect on the participant owning thread;
recheck the recorded lease and binding under admission mutex; then launch/admit
work. The lease precedes launch and mutation, including a launch that succeeds
before its caller receives a result. Acquire failure after LeaseOpen remains
unresolved unless the live owner proves no work was launched and closes the lease
under the mutex. Death in that gap leaves the lease fenced. Installer Intent cannot
overtake a previously recorded lease: it waits for its verified closure even if
the participant has not yet started. A lease never expires by timeout or heartbeat.

The participant keeps connect ownership for the entire protected lifetime,
including cleanup and owner close. After verified closure, it acquires admission,
releases connect with a checked result, then appends/flushes LeaseClose before
releasing admission last. Release ambiguity or death before LeaseClose leaves the
lease fenced. A proved no-launch acquisition refusal may close without a connect
release because it never owned that lock. This is a new adapter requirement: current
`BeginForegroundOwnership` releases connect after creating its marker, and Engine
work may run on other goroutines. Do not simply wrap it in another mutex and assume
recursive acquisition across threads works. Future enrolled adapters must route
protected operations through the lease's owning thread or replace their inner
acquisitions with unforgeable internal lease-scoped calls. No public bypass flag.
Existing unenrolled behavior is not changed by this design.

Installation order is: authenticate/pin plan and baseline; under admission mutex
reserve a never-reused generation and append/flush/readback Intent; release mutex;
drain existing leases through their normal cleanup (no forced kill); acquire
connect; recheck Intent and empty lease set; on that owning thread Begin a new MSI
transaction; append/flush/readback Pending; then invoke the exact synchronous MSI.
Internal Intent maps publicly to `Pending/Unavailable/InProgress`. Begin is never
attempted before durable Intent. Death before Intent can leave only unreferenced
staging; death after Intent, even before Begin/Pending, leaves admissions closed.
An uncertain acquisition is not clean refusal. Owner identity missing/dead/unknown
maps to Unsafe/RecoveryRequired, without removing the durable fence.

Revalidate Intent's retained process identity against OS-observed PID, creation
time, SID, session and held protected-image identity/hash. Live status requires
both positive identity evidence and authenticated active owner control bound to
this operation; a record or matching PID alone is insufficient. Absence, failed
queries or unknown control state yield Unsafe/RecoveryRequired, never cleanup,
lease closure, Retire or recovery authorization. A restarted controller is not the
same owner, even with identical executable bytes, SID and session; it must follow
the separately accepted recovery route rather than resume on the stored identity.

Same owning thread performs End commit/rollback. Verified inventory and complete
domain closure precede durable Terminal, which is a prepared candidate only and
remains externally Pending. Hold admission mutex, release connect with a checked
result, then append/flush/readback ReleaseComplete referencing that Terminal;
release admission mutex LAST. No participant can observe an authorized gap. Any
failure/death before durable ReleaseComplete leaves the candidate fenced, even if
another waiter consumed connect abandonment or all kernel objects disappeared.
There is no repeated Terminal or inference from process absence. After durable
ReleaseComplete the prepared target/baseline becomes authoritative; abandoned
admission acquisition still refuses. This refines the earlier Step 2 "release
guard last": the final guard is admission serialization. Explicit
recovery must authenticate exact outstanding bindings, examine actual platform
state and establish closure before appending a permitted terminal transition.
This recovery executor remains blocked as described in Appendix C.

## Appendix B: exact shared semantic v1 adapter

This is a proposed schema, not an existing Go API/CLI or the existing foreground
wire. `InstallationBinding` has exactly `installationId` (32 nonzero lowercase hex),
`generation` (nonzero uint64 decimal string), `pairIdentity` (SHA256 hex),
`operationId` (32 nonzero lowercase hex), `planDigest` (SHA256 hex). Generations
reserve monotonically at Intent; failed generations and operation IDs never reuse.
RestoredFailure preserves its attempted operation binding in lookup while current
status refers to the actual restored baseline binding. No first-enrollment failure
can fabricate a Settled baseline.
For a live verified first-enrollment rollback, Retire followed by ReleaseComplete
records the attempted operation's restored-failure outcome while current status
returns Unenrolled/Unavailable/notEnrolled. This does not use a Terminal
RestoredFailure record or imply that enrollment succeeded.

An ApprovedInstallationPlan is canonical JSON, at most 262144 bytes, exactly:
`schema:1`, `binding` containing the first four binding fields (no planDigest),
`action`, `baselineDigest`, `targetInventoryDigest`, `packageSetDigest`,
`mutationDomainDigest`, `serviceBaselineDigest`, `policyProfileDigest`.
All digest fields are SHA256 hex; action is `enroll|update|repair|remove|recover`.
`planDigest=SHA256(exact canonical plan bytes)` avoids a self-hash cycle. Known
actions are not automatically supported: initial candidate accepts enrollment
only after all gates; update/repair/remove/recover refuse until their own accepted
executor exists. Referenced manifests are immutable approved objects, each at
most 262144 bytes, at most 16 unique referenced objects and 4194304 aggregate
bytes. No recursive references, caller paths, commands or arbitrary properties.
Each manifest type requires its accepted closed schema before its action can run;
unknown package/domain/service schemas refuse, not opaque trusted digest bypass.

The Desktop-owned producer signs detached approval using Ed25519 only AFTER final
GUI, Core and MSI bytes exist. The verification root is compiled before the build;
detached approval is excluded from the hashed MSI and imported by independent
protected bootstrap. This avoids embedding an artifact's own final hash into it.
`pairIdentity` identifies the canonical signed approval payload, with exact Core
and Desktop revisions, final binary/package hashes, architecture, supported OS
profile, policy profile and contract schemas. Source SHAs in this document are
inspection references, not fabricated final artifact evidence. Key custody,
bootstrap approval and actual pair evidence require user/security acceptance.
Desktop's paired appendix owns the exact approval payload and package manifests.

Select pipe
`\\.\pipe\Bimeron.Core.Installation.<first-16-bytes-SHA256(UTF8-SID)-lowercase-hex>.<session-decimal>`.
Require first-instance exclusivity, local clients only, SYSTEM/server authority
and intended logon-SID client DACL, and medium-integrity access. Use individual
client read/write rights excluding FILE_CREATE_PIPE_INSTANCE, not generic write:
[Microsoft's pipe security contract](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
explains the shared append/create-instance bit. Client uses identification-only
SQOS. Verify both OS-observed peer PID/creation time, intended SID/logon/nonzero interactive session,
held protected image volume/index/hash and exact approved pair; Core is elevated.
Use effective thread token first and process token only on ERROR_NO_TOKEN, never
RevertToSelf to strengthen a peer. Hold identities for the exchange. Reopened GUI
may authenticate as the same approved image/user/session with a new process.
No fallback to service/development/foreground pipes. Pipe identity does not attest
an MSI action/export/session; that different boundary remains blocked.

One request/response per connection: UTF-8 JSON plus LF, maximum 65536 bytes
INCLUDING LF each way, at most 8 concurrent connections, five-second read/write
deadlines. Max depth 8; reject BOM, duplicate/unknown keys, invalid UTF-8, missing
fields, trailing frames and unknown version/enum. Plans never travel in the pipe.
An unknown wire version closes the connection without any response.
`unsupportedContract` is reserved for a valid v1 request encountering an
incompatible installed store, plan or pair contract, not wire-version negotiation.
Wire JSON need not be canonical; stored/signed bytes must be. No credentials or
native error text. `requestId` is 1..64 ASCII `[A-Za-z0-9_-]`; not authority.

Request fields are exactly `{version:1, requestId, command, binding}`; only
`executePlan` also requires `planReference` equal to binding.planDigest, resolving
only the fixed protected plans directory. Commands are `getStatus`, `getOperation`,
`executePlan`, `closeOwner`. Only `getStatus` permits null request binding for
authenticated initial discovery. Every other command requires the full binding.
`executePlan` maps to ExecuteInstallationPlan, not to an arbitrary path launcher;
`closeOwner` maps to CloseInstallationOwner and cannot settle or cancel work.

Response fields are exactly `{version:1, requestId, command, status}` with exact
request correlation; status is `{availability, phase, binding, reason, outcome}`
using the previously defined finite enums. Only `InProgress|Committed|
RestoredFailure|RecoveryRequired` outcomes exist; non-operation discovery uses
`InProgress` with Unavailable/notEnrolled, never a success outcome. Binding is
exact verified relevant state/operation or null for unbound Unavailable/Unsafe,
never null for Ready. `getOperation` reports that operation, whereas `getStatus`
reports current authority. A supplied binding mismatch returns Unsafe with
bindingMismatch and null binding rather than silently switching installations.
Corrupt/unreadable authority returns Unsafe/unsafeEvidence/RecoveryRequired;
unfinished work with dead/unknown owner returns Unsafe/recoveryRequired/RecoveryRequired.
Known live Pending returns Unavailable/operationPending/InProgress; verified
Unenrolled returns Unavailable/notEnrolled/InProgress. Ready requires verified
Settled plus ReleaseComplete and the exact compatible pair/policy; reason is ready,
with actual Committed or RestoredFailure outcome. Any unavailable native gate
refuses even if the journal is structurally valid. Parse/auth
failure before a valid envelope closes the connection, conferring no status.

Duplicate execute with identical operation/binding/plan returns the recorded
operation, without execution. Same operation ID with different data refuses.
Lost replies require exact lookup; IO timeout neither cancels the owner nor permits
a fresh ID retry. Status is observational, including Ready. Actual foreground and
profile activation still perform their own lease admission and preserve existing
accept_revision, instance/session and preview confirmation. No public Settle/Clean,
lease, verified boolean or recovery bypass endpoint is introduced.

## Appendix C: unresolved platform and continuation gates

Core selects **no production continuation executor** in this stage. The current
updater uses `Global\BimeronCoreUpdate`, allows abandoned acquisition, starts the
candidate ordinary service for IPC health, and restores a running baseline using
SCM state only (`cmd/bimeron/service_update_windows.go:50`). These are concrete
reasons it cannot simply run behind the new Pending barrier. The disconnected
health evidence model authenticates no production startup and grants no restart.

A possible future narrow surviving broker would be separately installed/pinned
outside replacement trees, authenticate operation-bound continuation manifests,
and allow only exact candidate read-only health, exact baseline restoration and
closure verification. It must persist action intents before effects, authenticate
SCM-launched children without trusting command-line/CAD assertions, disallow
ordinary network dispatch while Pending, and revoke continuation authority after
closure. It cannot reacquire the controller-held connect lock. Installation owner
still owns settlement; the broker cannot offer a public Settle/Clean operation.
Broker lifecycle, mutual authentication, startup route and crash-surviving fence
are an additional architecture/security decision, not specified executable proof.
Therefore rollback/restoration/recovery adapters are **BLOCKED**, including on
first enrollment where MSI rollback can outlive its original owner.

The admitted domain must enumerate exact files/directories, registry/service
objects, package standard actions, synchronous custom actions and rollback/commit
scripts; immutable closure evidence identifies every worker and outstanding effect.
Exclude transforms, patches, chainers, asyncNoWait actions, detached children,
reboot scheduling and post-Finalize resource work. A nested removal is admissible
only with an exact independently approved domain and existing gate participation;
initial fresh-host candidate refuses nested predecessor removal entirely. Ordinary
MSI End is evidence only for its own domain, not for an untracked worker. Recovery
cannot declare closure from a quiet interval, missing PID, callback, log or timeout.

Microsoft documents that [Begin](https://learn.microsoft.com/en-us/windows/win32/api/msi/nf-msi-msibegintransactionw)
has one process owner and ownerless transactions roll back; this does not prove
rollback has finished. [End](https://learn.microsoft.com/en-us/windows/win32/api/msi/nf-msi-msiendtransaction)
requires the current owner and reports still-running and rollback-disabled errors.
The same-thread rule here additionally preserves Windows mutex ownership; it is
not invented MSI thread-attestation documentation. Unknown return/owner state
retains the fence, never grants recovery or settles automatically.

Authenticated OS pipe peers and signed package hashes cannot prove the loaded
Binary export belongs to the expected effective MSI session. Microsoft explicitly
limits [deferred action context](https://learn.microsoft.com/en-us/windows/win32/msi/obtaining-context-information-for-deferred-execution-custom-actions);
the original session may no longer exist and its supported handle operations do
not include MsiGetActiveDatabase. No generic API attesting that action/export is
established. Desktop owns a frozen effective DB/projection, exact preload and
action sequence analysis, but the actual independent action/session evidence
producer remains **BLOCKED**. A self-report, signed CAD tuple or receipt is not a
substitute for such a producer. Keep AuthorizeInstallationAction unavailable.

Historical execution prevention AFTER enrollment is also **BLOCKED**. The bounded
alternative recommended for user/security consideration is a managed Windows
amd64 default-deny application-control/bootstrap profile installed before
enrollment, covering old executable/DLL/MSI/MST/MSP, cached repair/removal, nested
packages, service/recovery and restored images. It must remain effective throughout
rollback and after reboot. Exact OS version/edition, active policy composition,
default allowances and policy identity must be part of pair approval; no generic
Windows amd64 support claim. This is material deployment scope expansion.

[App Control feature availability](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/feature-availability)
documents applicable file classes, not proof that the proposed Bimeron domain is
closed. [AppLocker MSI defaults](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/applocker/windows-installer-rules-in-applocker)
allow administrators, signed installers and the Windows Installer cache; merely
enabling those defaults does not meet this contract. Policy in audit mode, a broad
publisher/path allow, managed-installer trust or a one-time inventory is inadequate
without a complete effective-policy analysis and actual negative evidence.

Bounded choices are: accept and separately design/validate the managed profile;
commission a different enforceable isolation/bootstrap architecture with the same
requirements; or retain disabled enrollment and ordinary packet-only operation.
Deferring all MSI changes after enrollment narrows supported operations but does
not stop someone running old/cached ungated MSI later. Fresh-host-only is not a
fourth solution. No conditional policy candidate is accepted or deployed here.

## Appendix D: dependency slices and reviewable negative evidence

Recommended next authorization is **low reasoning, disconnected offline
storage/codec only**, with no Windows writer or admission integration. Keep this
design/review at medium; unresolved native trust decisions warrant a focused
security review rather than a lower-effort implementation guess. Track the slice
under enrollment issue #73 or a linked scoped issue when implementation is
authorized; no issue/PR/commit is opened in this design stage.

1. Proposed `internal/installation/contract.go`, `codec.go`, `replay.go` and
   focused tests: pure JCS subset, bounds, frame chain and state transitions with
   byte fixtures. Do not add filesystem access, exported settlement, init hooks or
   production callers. A model acceptance means only structurally eligible data.
   Tests cover duplicate keys/Unicode/numeric traps, exact boundary lengths,
   broken/torn/trailing chain, sequence/generation reuse, terminal without Intent,
   closed lease reuse, valid-prefix replay limitation, capacity reserve, restored
   baseline identity and identical/different-data operation replay.
   Accept replay of live first-enrollment rollback only through Retire plus
   ReleaseComplete with exact original Unenrolled baseline and closure evidence;
   reject Terminal RestoredFailure there. Accept Terminal RestoredFailure only
   with a prior verified Settled baseline; reject Retire for a Settled baseline,
   missing closure, missing ReleaseComplete or an unauthenticated restarted owner.
   Reject Intent with missing/malformed owner and test PID reuse, changed creation
   time/SID/session/image, missing active owner control and failed OS identity
   queries. None may authorize cleanup or silently resume the old operation.
2. Separately accepted native storage slice targets proposed
   `store_windows.go`, `admission_windows.go`, `bootstrap_windows.go` in that
   package. Reuse concepts from `internal/nativeenrollment/file_descriptor_windows.go`
   and `file_reader_windows.go`, not their model grant or Program Files location.
   Test protected anchor provisioning, ordinary-user replacement/squatting,
   ProgramData redirection, share modes, concurrent writers, mutex abandonment,
   interrupted initial publication, flush failure, reboot and full WAL refusal.
   Fault injection after every lease/Intent write, flush and readback must prove
   no participant launch/installation Begin before the durable prerequisite.
3. Only after gate acceptance, proposed `controller_windows.go`,
   `action_windows.go`, `continuation_windows.go`, `recovery_windows.go` and
   `cmd/bimeron/installation_windows.go` integrate the owning-thread controller.
   Existing BeginInstallationTransaction returns a void release closure that
   ignores ReleaseMutex/CloseHandle errors; replace it for enrolled ownership with
   checked release before any ReleaseComplete, without inventing a current API.
   Current `internal/windowsnet/network_windows.go`, control foreground/profile
   paths and `core/ikev2_windows.go` need explicit owning-thread lease wiring.
   `cmd/bimeron/service_windows.go`, `service_update_windows.go` and shared
   `service_update_files.go` require enrolled dispatch/restoration isolation while
   preserving ordinary packet and Linux behavior. No partial production wiring.
4. Future controller/participant tests force death before Pending, after lease
   append but before launch, successful launch with lost reply, Intent racing
   delayed lease launch, competing cleanup, active owner drain and unknown lock
   release. Add death/IO failure between Terminal, connect release, ReleaseComplete
   and admission release; a valid Terminal alone must never become Ready, including
   after a different waiter consumes abandonment. Exercise the matching participant
   release-before-LeaseClose sequence. Verify no lock inversion or cross-thread
   recursive-lock assumption.
   Native proof must test missing/retained rollback broker, candidate health
   failure, old baseline images, restored-stopped/running states, broker death,
   late continuation after Terminal and ambiguous End/reboot. Model closure is
   never substituted for actual worker/domain evidence.
5. Pair-wire tests in Core and Desktop share fixed byte fixtures: null discovery
   only, exact command/request correlation, wrong SID/session/image/pair, stale
   generation, protected-object substitution, frame overrun, unknown enums,
   duplicate execute, lost responses and different-data/same-ID refusal. These
   fixtures distinguish unknown wire version (close, no response) from valid v1
   with incompatible installed contract (unsupportedContract, no execution). Future
   Windows fixtures additionally prove real peer authentication and protected
   approval import; existing foreground handshake tests do not prove this adapter.

Desktop owns its concrete package/policy/approval producer and client slices in
the paired contract. Its negative evidence must include old direct/cached/nested
routes AFTER enrollment, effective DB/Binary/preload substitution, mismatched
action/export/session, and policy loss/rollback/reboot. A new MSI success trace or
one connection cannot satisfy these negatives. Exactly approved final artifacts
must then pass actual GUI provisioning, connect, Stop, DNS/WFP/RAS cleanup and
owner-close validation before a release decision. No artifact hashes are invented.

Document checks in this stage are limited to diff/whitespace, relative links and
paired schema consistency. No build, unit/native test, MSI/service/VM action,
benchmark, commit or push was executed. Prior draft/frozen evidence remains intact.

## Step 3 independent review record

One read-only paired review (Astra/codex_petr, low) found missing controller owner
identity in Intent, ambiguous live first-enrollment failure retirement and differing
unknown-wire-version behavior. The paired contracts now persist/revalidate owner,
permit verified live Retire with ReleaseComplete, prohibit restored settlement
without a prior Settled baseline, and close unknown-version wire connections while
reserving unsupportedContract for valid v1 incompatibility. Replay/codec acceptance
was extended accordingly. Reviewer found prepared Terminal/Retire -> checked connect
release -> ReleaseComplete under admission serialization coherent. No second review,
security acceptance or native evidence is claimed. Desktop owns the finalized closed
outer approval payload/signature encoding; unresolved platform manifests still refuse.
