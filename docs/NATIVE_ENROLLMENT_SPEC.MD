# Native enrollment safe primitives: bounded specification

Status: accepted product boundary; proposed offline implementation contract, 2026-10-30. Enrollment and protected-install support remain DISABLED. See [ADR 0029](adr/0029-disabled-native-enrollment-primitives.md) and [acceptance and implementer brief](NATIVE_ENROLLMENT_ACCEPTANCE.MD).

## Provenance and bounded review

Actual Core base: `83683e4b5c1a673f0d29d667c09b116f5805027b`. `git diff --quiet` against reviewed master `66d84d8f4dcfc6ada625eb11894b19feea51b7ba` returned zero. This establishes tree equivalence, not ancestry from 66d84d8f. No historical executable evidence is reassigned to this base.

Read scope: Core AGENTS.md; foreground owner lifecycle plan; IKEV2_FOREGROUND_CONTROL.MD; ADRs 0002 and authenticated-foreground 0026; UPDATE_SPEC.md; cmd/bimeron/foreground_windows.go, service_update_windows.go, service_update_files.go; internal/control/foreground_installation.go, foreground_identity_windows.go, foreground_windows.go; internal/windowsnet/network_windows.go and transaction_windows.go; core/ikev2_windows.go. Desktop read-only reference: `C:/Users/PC/.t3/worktrees/bimeron-desktop/plan-stage-8-ikev2`, AGENTS.md, docs/ikev2-profiles.md and all seven files in packaging/windows/foreground-prototype. Desktop reference HEAD at inspection: `881af2e7c293fca6481371b44c32b94b9666e6d5`, with a clean working tree. These are inspected source contracts, not newly executed prototype or live tests. No Desktop or old parent files are changed.

## Product contract

Separate explicit native enrollment is accepted. Ordinary packet-only installations and their signed updater staging, health check, restart and rollback behavior must remain unchanged. Trusted protected absence means NOT ENROLLED and nativeUnavailable; it is never a new packet-start prerequisite. Enrolled pending or unsafe state refuses participating protected admissions, including requests from the foreground process itself. Abnormal native failure may require explicit administrative recovery. Routine successful installation must not leave a manual-settlement lockout.

There is no enrollment command in this subset. Do not add a publication path, helper, setup wrapper, runtime writer, settlement endpoint, generic bypass, ignoreBarrier boolean or verified=true completion argument. Do not wire the model into current Core commands, Engine, windowsnet.Acquire, service updater, or Desktop. Existing experimental native source behavior is not newly enabled or globally disabled by these primitives; deployment of enrolled native support remains gated. This change alone enforces no production admission.

## Why enrollment is still refused

The connect mutex is thread-owned. DLL module pinning does not keep an MSI host alive; its death loses exclusion while outer rollback may continue. A commit callback may run before later rollback. RollbackDisabled can skip both commit and rollback actions. RemoveExistingProducts child removal must not settle an outer transaction. InstallFinalize can be a local boundary. MsiBeginTransaction/MsiEndTransaction require a real outer owner; an arbitrary DLL callback is not one. No authorized helper/wrapper or established safe outer terminal authority exists here.

The signed updater starts the replacement ordinary service to perform IPC health checks and restarts the restored ordinary service on rollback. A global pending refusal would break that contract. Settling before restart creates an unsafe gap. Old restored binaries ignore enrollment and may outlive updater death. Observing processes/markers is not enforcement. Until a future enrolled updater transaction proof preserves these semantics across success, failure, rollback and updater death, REFUSE ENROLLMENT; do not redesign the updater in this subset.

Future enrollment must also establish that every runnable managed network/recovery host participates, reject old/incompatible runnable hosts and prevent their later return through rollback. Enumeration, compatible version claims, installation markers and a one-time check cannot establish that. Proxy coverage is not claimed. Administrator compromise is outside the boundary, but ordinary users must not be able to redirect or erase enrollment state.

## Storage decision and limits

Choose a machine registry value as the future minimal durable representation: native HKLM SOFTWARE view, `SOFTWARE\Bimeron\Core\NativeEnrollment`, value `Record`, REG_BINARY. Use the OS-native view explicitly (64-bit on supported 64-bit Windows, including a 32-bit reader); never merge/fall back to WOW6432Node or HKCU. No registry key/value is created by this change. Registry fits one bounded record and handle-based security inspection; a file would add path/reparse/ancestor pinning. Neither gives outer transaction authority or automatic crash settlement.

Defer even a read-only Windows registry adapter: there is no authorized production caller and trustworthy absence is not equivalent to RegOpenKey failure. Implement the security/view/generation model and deterministic observations first. A later reader needs its own accepted contract and fixture evidence, not a silent expansion of this subset.

Trustworthy absence requires an authenticated native machine hive/view and a securely opened nearest existing ancestor chain that prevents untrusted create/delete/replace of the missing key/value. Only exact not-found at the intended location with that protection established is absence. Access denial, unknown view, broken chain, key deletion/recreation races, link redirection, query failure, missing value under an unexplained enrolled container, and unreadable security are Unsafe. An unprovisioned but securely protected vendor parent may establish non-enrollment; a generic missing subkey cannot. This model cannot remember that a privileged actor deleted an entire enrolled subtree. It claims no defense against malicious administrators or offline registry rollback.

Future registry security: owner SYSTEM or Builtin Administrators, present non-null protected DACL; reject unknown effective ACE forms and effective untrusted mutation rights (set value, create subkey, create link, delete, WRITE_DAC, WRITE_OWNER, generic write/all). Expand generic rights for registry objects. Read-only access is harmless. Validate inherited effective rights and every ancestor able to replace the child; do not copy the kernel-mutex access mask. TrustedInstaller ownership is not accepted for this new record contract without a spec change. Unsafe security cannot be converted to absence or repaired by a reader.

## Exact offline subset

Use one small platform-neutral internal package, `internal/nativeenrollment`, no new dependencies. Two production-source files at most (model/codec), focused tests and a short package comment. It is deliberately unconnected to production. No general storage interface, transaction framework, clock, background watcher, installer protocol or registry syscalls.

Record wire format is exactly 64 bytes, all integers little-endian:

- bytes 0..7: ASCII `BIMNENR1`;
- 8..9: uint16 schema 1;
- 10: phase 1 clean, 2 pending;
- 11..15: zero reserved bytes;
- 16..23: nonzero uint64 generation;
- 24..39: nonzero 16-byte public installation identity;
- 40..55: operation identity, all zero for clean, nonzero for pending;
- 56..63: zero reserved bytes.

Reject other lengths, magic/schema/phase, zero generation/installation, phase-operation mismatch and nonzero reserved bytes. This is an experimental codec, not a published cross-product ABI. Clean means only a hypothetical record phase, not proven safe networking or installer success. Pending is deliberately not split into committing/rolling-back: all are equally inadmissible. The record contains no credentials, paths, hashes or rollback payload. It does not replace the existing schema-1 foreground manifest or constitute a rollback journal.

Minimal API surface (names may follow Go conventions without broadening behavior): `Decode([]byte) (Record,error)`, `Encode(Record) ([]byte,error)`, `Evaluate(Observation) Decision`, and `AfterPendingEvent(Record, Event) (Record,error)`. Encode validates identically to Decode and cannot persist. No exported writer, Begin, Enroll, Settle or Clean constructor. Tests may directly form hypothetical clean Records.

Observation models explicit read result (protected absence, present, unsafe), view (native or other/unknown), security outcome (protected or unsafe/unknown), and two sampled record snapshots plus optional expected installation/generation binding. These are offline evidence inputs, not caller-granted authorization tokens. Do not accept a single trusted/verified boolean as a substitute for view/security/record/generation distinctions. Default/zero Observation must deny. A present record requires two byte-identical valid snapshots and protected native evidence throughout; changed identity, generation, phase, security or view denies. Expected bindings, when supplied, must match exactly; generation zero is invalid for a present record.

Decision has three orthogonal outputs: packet disposition (LegacyUnchanged or RefuseProtectedAdmission), native disposition (Unavailable, Refuse, or EligibleModelOnly), and stable reason enum: notEnrolled, cleanModelOnly, pending, unsafeEvidence, wrongView, invalidRecord, changedSnapshot, bindingMismatch. Validate evidence/view first, then decode, compare samples, compare bindings, then phase; return the first failed check in that order. Protected absence yields LegacyUnchanged/Unavailable/notEnrolled. Present clean, consistent and protected yields LegacyUnchanged/EligibleModelOnly/cleanModelOnly, never a runtime permit. Pending yields RefuseProtectedAdmission/Refuse/pending. Unsafe/unknown, malformed, stale or changed observations yield RefuseProtectedAdmission/Refuse with the corresponding reason. The packet refusal is a future participating-host model only; this disconnected package changes no real packet behavior, even for unsafe observations. No foregroundProcess input exists.

AfterPendingEvent accepts pending records only and a closed enum: hostLost, reboot, localCommitCallback, localRollbackCallback, childRemoval, rollbackDisabled, localFinalize, updaterLost. Every valid event returns the identical pending record; invalid records/events error. No event produces clean or deletes state. This small model makes the missing authority executable as a negative invariant without inventing a settlement framework. Do not add a Begin transition merely to complete a diagram.

Generation equality detects observed change, not ABA or malicious replay. Future writers must serialize, pin identities, publish pending before mutation, guarantee durable ordering and increment without wrap/reuse. Two samples are not atomic admission or rollback protection. Tests must make this limitation explicit. No production race-free reader/admission claim is made here.

## Follow-on boundary

The next PR can honestly claim strict codec validation and conservative offline decisions only. Completing enrollment requires a separately accepted architecture and proof of outer transaction authority, enforced participating-host compatibility, enrolled updater health-check/restore safety, durable publication and recovery. If those cannot be achieved within authorized packaging, native enrollment remains unavailable. No tags, binaries, assets or releases follow from this plan.
