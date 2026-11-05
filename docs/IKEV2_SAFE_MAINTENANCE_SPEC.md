# Proposed IKEv2-safe Core maintenance

Status: plan only, review pending, 2026-11-05. No runtime or installer change is
authorized. Product native support remains OFF. RAS 775 remains unresolved and
668 normal cleanup failed in the supplied lab status; this document claims no
successful IKEv2 connection or recovery. Active lab recovery is outside this work.

## Evidence and scope

Inspected clean Core `plan/ikev2-safe-update-spec` at
`8ef0110326c86c1621a0c274dfb06a30b123324b`. T3 branch/path match Git;
provider/model are `codex_petr` / `gpt-6-astra`, medium reasoning. Read repository
instructions and the complete [build guide](BUILDING.md). This is a documentation
slice; no build, native call, service operation or network experiment is required.

The [installation proposal](IKEV2_INSTALLATION_CONTRACT.MD) Step 4 is conditional:
existing foreground/provisioning owners, offline payload servicing and Core-owned
runtime cleanup. Its earlier controller/journal/broker appendices are historical
alternatives, not implicitly selected requirements here. Preserve their unresolved
proof obligations without assuming a new broker or mandatory managed-host policy.
The [signed update contract](UPDATE_SPEC.md) and
[ADR 0002](adr/0002-signed-service-updates.md) remain the packet updater baseline.

Desktop `docs/ikev2-safe-maintenance-plan.md` was unavailable in committed main
`296130e3e5f255410dd70c0680b37b0ed351165b` and maintenance branch
`38e020eb41bfb619f2a794e9628e3d0fc6002a40`. No uncommitted Desktop file was read.
Reconcile this proposal with that plan before implementation authorization; no
cross-repository agreement is claimed. No active Core installation-contract
checkout, including ignored outputs, was read or written.

Existing evidence to reuse, not duplicate:

- `cmd/bimeron/service_update_windows.go`: independent update mutex, protected
  staging and digest/identity/architecture checks, service stop, candidate IPC
  health and rollback. `protectServiceDir` and staging precede network admission.
  Abandoned update mutex acquisition currently proceeds. Restored-running health
  is SCM-only, and deferred staged-file removal is unconditional.
- `cmd/bimeron/service_windows.go`: start invokes SCM directly; uninstall accepts
  Stopped then deletes service/event-log registration and payload files. Neither
  Stopped nor a zero service exit code establishes native cleanup authority.
- `internal/windowsnet/network_windows.go`: installation guard acquires
  `Global\BimeronCoreConnect`, pins the OS thread, refuses abandonment and a
  present/unknown foreground marker. Its release closure discards errors. It is
  not durable admission, a cleanup proof, or a production maintenance integration.
- `service_update_files_test.go`: real file-helper rollback, failed-stop backup
  retention, stopped-state preservation and simulated interruption coverage.
  Its Pending ledger is disconnected. `TestLegacyWindowsRestoreObservationSource`
  explicitly records the missing restored IPC probe.
- `internal/nativeenrollment/update_health.go` and its tests: offline identity,
  inventory and outcome comparison only; no authenticated producer or permit.
  `internal/windowsnet/transaction_windows_test.go` exercises isolated mutexes,
  not all installed/cached maintenance routes.

## Common admission before the first conflicting mutation

One Core-owned decision contract must cover update, repair, removal, install over
existing payload, service configuration/start/recovery and profile/foreground
mutation. Desktop preflight is advisory; every privileged participant rechecks at
its own effect boundary. A copied Boolean or prior status reply is not authority.

Read-only argument, signature and compatibility validation may precede admission.
Protecting/changing an existing directory ACL, writing `.update-new`, deleting an
old backup, changing SCM/event-log configuration, stopping a runtime or launching
a mutating package may not. Creating the protected admission reservation itself
is a separately approved prerequisite, not permission to alter payload/runtime.
Private download staging outside the installed/recovery domain is not an install.

Admission requires an exact supported installed pair and operation, trusted
protected-object identities, compatible runtime/cleanup schemas, preserved baseline
and recovery bytes, and no conflicting live or uncertain lifecycle. Distinguish:

- Verified idle and clean: eligible for an atomic recheck/reservation, not an
  unbounded grant. Preserve genuinely supported packet-only behavior.
- Starting, connecting, connected, stopping, cleaning, provisioning, rollback or
  terminal foreground owner still open: refuse without maintenance side effects.
- Missing expected owner/evidence, stale identity, access denied, corrupt or
  incomplete journal, failed cleanup, abandoned lock, unknown service/owner state
  or existing unresolved update backup: refuse and retain recovery resources.
- Never-enrolled packet baseline: requires the agreed baseline classification;
  absence of an enrollment file alone cannot establish it after native use.

SCM Stopped, empty RAS enumeration, GUI disconnection, process exit and timeout
are observations only. None may clear RAS/DNS/WFP/profile journals, release native
protection or authorize deleting the Core that can recover it. Cleanup evidence
must come from the accepted lifecycle owner/recovery protocol and cover all owned
resources, outstanding work and terminal owner closure. That producer is a
dependency, not a new trusted `clean=true` input to implement here.

## Proposed lock order and lifecycle exclusion

The names of new admission APIs/locks remain design placeholders. Required order:
shared admission reservation, then maintenance serialization
(`Global\BimeronCoreUpdate` where applicable), then connect guard on the owning
OS thread. Recheck state under that reservation before the first effect. No
participant may acquire the admission reservation while holding the connect guard.
The foreground marker is inspected as lifetime evidence, never stolen or cleared.
New foreground/provisioning/start paths must participate in the same reservation.

Use bounded/nonblocking acquisition; on busy state release what was acquired and
return a retry reason. Never wait for Stop, owner close or another process while
holding locks it needs for cleanup. An existing lifecycle finishes through its
own admitted path; maintenance retries only after it has finished and closed.
No implicit recursive acquisition, cross-thread mutex release or forced kill.

Hold operation exclusion across replacement and its exact rollback/restoration.
Checked reverse release is required; uncertain acquisition/release or owner death
does not make a clean baseline. A volatile mutex alone cannot retain a recovery
fence after death, especially if another waiter consumes abandonment. The accepted
protected recovery/admission state must survive outside replaced payloads. Until
that dependency is resolved, native maintenance integration remains blocked.

Restoration callbacks must not start an ordinary service that attempts to reacquire
the controller-held connect guard. Resolve this conflict before implementation:
either admit an exact bounded restoration continuation with ordinary network
dispatch fenced, or refuse native maintenance before mutation. Releasing exclusion
early to make restart succeed is not acceptable. No surviving broker is selected.

## Rollback, restoration and retained bytes

Retain the existing signed selection, elevated staging verification and protection
against source substitution. Bind a future operation to exact candidate/baseline
image identity and digest, architecture, version/protocol, service owner, original
running/stopped state and startup/recovery configuration. Do not persist secrets.

1. Before stopping or replacing anything, establish the admitted baseline and
   recoverable exact old bytes plus required helpers, configuration and cleanup
   metadata. The retention domain must survive failed update and uninstall.
2. Replace only within that domain. For a previously running service, require
   authenticated expected candidate health within a deadline; SCM Running alone
   is insufficient. A previously stopped service stays stopped and is not started
   solely to obtain a success response.
3. Candidate failure first proves candidate quiescence, then restores exact old
   bytes/settings. Restore the prior running state only through an accepted
   continuation; verify restored identity/protocol/health as well as SCM state.
   Preserve stopped state without claiming runtime health.
4. Report verified restoration as failed update with restored baseline, never
   successful update. Failed stop, failed restoration, lost owner, uncertain
   health or release yields recovery required, with no automatic reconnect.
5. Retain the last recoverable baseline and journals until both complete native
   cleanup and operation closure are verified. File-swap success or candidate IPC
   health alone cannot delete `.update-old`. Replace unconditional temporary-file
   cleanup only in a separately approved integration; retain any staged/helper
   bytes needed for recovery. Bound storage before admission; insufficient space
   refuses new work instead of evicting unresolved recovery data.

Recovery must reconcile RAS as well as DNS/WFP and ownership; current generic
recovery is not promoted to that authority. A Retry button cannot reset failure
state, reuse a stale permit, delete journals or start a second ambiguous operation.
After a lost reply, obtain the exact operation outcome before considering new work.
Manual recovery wording must not imply that running today's doctor/recover proves
native cleanup. Recovery execution remains separately authorized.

## Packet Stop and retry UX decision proposal

Recommend **Stop separately, then Retry** for this first maintenance contract.
When a packet session is active, refuse maintenance and offer the existing explicit
Stop action. After confirmed cleanup, retry from fresh admission. An idle running
packet service may still be stopped/restarted by an admitted updater while
preserving its prior service state. A native owner additionally requires verified
cleanup and explicit terminal owner closure. No maintenance-driven native Stop,
force-close, automatic native reconnect or packet fallback is introduced.

An integrated consented "Stop and update" could reduce clicks, but would add
session ownership, disconnect consent, cancellation and cleanup coordination to
the updater. Defer it pending user acceptance. Existing Desktop packet reconnect
behavior must be reconciled explicitly: retain it only after verified successful
packet update if still accepted, never after rollback/recovery or for native IKEv2.
Suggested messages are "Stop the VPN, then retry the update" for known active work
and "Cleanup could not be verified. Update blocked; recovery files retained" for
unknown/failed cleanup. Do not describe unknown state as merely busy.

## Historical and cached MSI boundary

A new Core preflight does not retrofit old MSI/custom actions or cached helpers
that never invoke it. Desktop must inventory exact historical package/helper bytes
and direct, quiet, repair, uninstall, cached and nested invocation routes. Prove
refusal/exclusion before each first conflicting effect, including standard actions
that remove recovery files or stop services. A newer GUI warning cannot prove it.

Fresh-host-only support and deferring normal upgrade do not prevent later cached
maintenance. No default-deny policy or new privileged broker is assumed. Product
choices requiring explicit acceptance are: demonstrate enforceable compatibility
within the existing consumer lifecycle; accept a separately designed deployment
restriction with its operational cost; or keep native support disabled. Until an
accepted mechanism covers ordinary-user-triggerable historical routes, readiness
remains blocked. No general safe-maintenance claim applies to uninstrumented MSI.

## Bounded future slices and negative acceptance

These are proposed targets, not permission to implement or new public APIs.

1. Reconcile this file, Desktop maintenance plan and Step 4 decision. Track a
   scoped issue under the existing enrollment work before substantial code.
   Record an ADR only after lock/continuation, packet UX and historical-route
   choices are accepted. No issue, PR or commit is created by this plan.
2. If authorized, add a pure `internal/maintenance/decision.go` and
   `decision_test.go` with finite operation/state/reason inputs. Its result is
   eligibility only, never OS authority. Reuse existing offline health types where
   semantics match; do not extend BIMNENR1 into a grant or add another journal.
3. Separately gate a private native admission adapter and checked guard release
   in `internal/windowsnet/network_windows.go`; map the accepted lifecycle evidence
   from `internal/control/foreground.go`, `profile_control.go` and
   `core/ikev2_windows.go`. No public cleanup/settlement bypass endpoint.
4. Only with all dependencies accepted, integrate `service_windows.go`,
   `service_update_windows.go` and `service_update_files.go`, plus their focused
   tests. Keep Linux and ordinary packet guarantees intact. Desktop owns package
   sequence gates, cache compatibility and UX; no MSI source is changed here.

Required negative acceptance for those future slices:

- Every maintenance route with active/unknown lifecycle produces zero payload,
  ACL, SCM, event-log, stop/start or package mutation calls, including staging.
- Race a new connect/provisioning/start against admission; exactly one may proceed.
  Reverse lock acquisition, cross-thread release and callback reacquisition fail
  tests rather than hang. Busy paths never impede an owner's cleanup.
- Stopped SCM plus residual DNS/WFP, empty RAS plus incomplete journal, missing
  owner after crash, access-denied observations and consumed abandonment all refuse.
- Wrong pair/image/schema, tampered source, preexisting backup, insufficient
  retention space and unsupported old helper all refuse before first effect.
- Inject failure before/after stage, stop, swap, health, rollback, baseline restart,
  terminal recording and lock release. Uncertainty retains recoverable exact bytes
  and fencing. Candidate or restored SCM Running alone never settles the operation.
- Previously stopped baseline stays stopped; restored running requires real
  authenticated baseline health. Candidate failure does not reconnect either VPN.
- Owner death, delayed worker, lost reply and repeated Retry cannot create a fresh
  conflicting operation or delete recovery resources. Cancellation after mutation
  is not evidence that rollback completed.
- Desktop proves direct/cached/nested historical routes cannot mutate enrolled
  resources before the common gate; UI-only refusal and package-signature-only
  evidence fail acceptance. These tests require separately authorized isolated
  fixtures, never the active recovery lab.

Validation for this plan is document review, relative-link checks, whitespace and
file-scope checks. Existing tests were inspected, not executed. Future pure tests
should be focused; native/installer validation needs separate authorization and
appropriate CI fixtures. No full build matrix or benchmark adds evidence here.
Proposed commit title, for later authorization only:
`docs(ikev2): specify safe Core maintenance admission and recovery`.
