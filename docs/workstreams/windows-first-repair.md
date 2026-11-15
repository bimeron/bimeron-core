# Windows first repair session: specification and acceptance

## Problem

Desktop 0.3.0 with Core candidate 0e08a5c8 can reject the first repair after
Task Manager terminates the owned service. A stopped SCM status with an abnormal
exit code and no remaining WFP/NRPT markers currently fails during inspection.
Marker absence alone is not cleanup proof, but this evidence must select the
existing owned recovery operation rather than prevent it.

## Required behavior

After protected service ownership is established, a stopped process with PID zero
requires recovery if owned markers remain OR its exit status does not prove clean
completion. Inspection remains read-only. Recovery requires explicit network
recovery consent, fresh identity, stopped/PID-zero evidence, conflict gates and
the VPN ownership lock. Existing recovery APIs must succeed and markers must be
absent before cleanup is proven, service start and IPC readiness verification.
No broker retry, additional elevation, forced process termination, weakened
identity checks or success on recovery failure is permitted. Damaged images keep
the existing file-not-found/bad-image exceptions and replacement flow.

## Acceptance criteria

- Abnormal stopped exit without markers selects recovery, not inspection failure.
- Clean/never-started status without markers retains ordinary start.
- Markers require recovery regardless of exit code; nonzero PID fails closed.
- Consent denial, recovery error and cleanup proof failure never reach start.
- One session runs recover, confirm-cleanup, start and readiness in that order.
- Windows native focused tests, Go tests/vet, race where supported and Windows
  cross-builds pass; report unavailable checks honestly.
- Disposable Windows 10 STD evidence records binary hashes and state. Real GUI
  first-click/UAC acceptance is separate from elevated CLI or backend tests.

## Scope

Core only; no Desktop checkout, frozen assets, signing keys, pins or publication.
No architecture change: use the existing repair planner and recovery boundary.
Re-freeze Core and rebuild/re-pin all Desktop packages before release acceptance.

## Local implementation and evidence (2026-11-15)

Root cause reproduced in the assigned Windows 10 STD VM: after killing only the
SCM-owned, exact protected Core process, the original adapter returned
`previous service cleanup unconfirmed` from its first Inspect (0.52 s). With
unchanged stopped state, the corrected adapter selected CleanupRequired and
completed inspect/recover/confirm-cleanup/start/verify/ready in one session
(1.92 s). A previous corrected run after a separate kill passed in 2.04 s.
The first harness invocation used incorrectly quoted PowerShell test flags and
returned exit 2 without running tests; the service was restarted immediately.

Before mutation the guest model was Virtual Machine and service image/PID were
verified. Installed Core, bundled Core and protected broker all matched expected
SHA-256 e1fb6792bac77f131ed0d7ffc554c060209637fd4fb042d800da578c115b7ce3.
Installed GUI SHA-256 was bba3a4905ce8ebc5d9f9e78c9b53a6a33fd8918df0c863f23e1785d4b9b4fb80;
its in-memory revision was not established. The temporary elevated test binary
used the real backend and predefined recovery consent, not Desktop/UAC. It was
removed from the guest after testing. No frozen candidate was overwritten.
Final service state was Running, PID 1116, exit code zero. VPN reconnection was
not verified; no profile was selected speculatively or modified. All PowerShell
Direct sessions were removed. Host services/network and other guests untouched.

Security review: abnormal exit is evidence requiring recovery, never permission
to skip it. Inspect still does no mutation. Recover rechecks canonical service
identity, stopped/PID-zero state, conflicting endpoints and exclusive network
ownership, invokes all existing scoped recovery APIs and checks owned markers.
The recovered flag is set only after all checks succeed. Consent refresh resets
that flag and rebuilds the plan. Existing cleanup/start/readiness failures remain
terminal. The damaged-image branch now also requests recovery for unexplained
abnormal exits, preserving the existing missing/bad-image exceptions. No protocol
or elevation flow changes; no new dependency or performance-sensitive operation
on the healthy path. Benchmarks are not relevant to this bounded repair fix.

Real first-click Desktop/UAC, alternate-admin and ARM64 runtime acceptance remain
required. This does not accept the old frozen candidate for release. A new Core
candidate, hashes/signed manifest, Desktop pins and rebuilt packages must be
prepared by the release owner and re-tested together. No publication authorized.

Validation completed locally: `go test -p 1 ./...`,
`go test ./cmd/bimeron ./internal/windowsnet -count=1`, `go vet ./...`, and
`go test -race ./cmd/bimeron ./internal/windowsnet -run 'Repair|WindowsServiceExitClean' -count=1`
passed. After adding replacement-plan coverage the focused cmd race suite was
rerun and passed. Windows arm64 CGO-disabled CLI build passed; native amd64 test
executables compiled and ran. ARM64 execution and hosted CI were not run; no
push was authorized. `git diff --check` passed. VM ownership was released to the
coordinating parent after all guest work ended, with no pending UAC/operations.

## Rebase validation against b9d73327

PR #141 adds payload hashing/replacement and alternate-administrator readiness,
but retains the abnormal-exit inspection rejection in both stopped-image paths.
The regression test was run on detached b9d73327 with a test-only seam containing
its unchanged stopped-service decision block (the production helper does not
exist on master). It failed for killed-without-markers with
`previous service cleanup unconfirmed`, and for the missing PID guard. With
this fix rebased onto b9d73327, the same regression passed. No VM operations or
frozen-candidate changes were made during this rebase. The only rebase conflict
was additive documentation, resolved by retaining both sections.
