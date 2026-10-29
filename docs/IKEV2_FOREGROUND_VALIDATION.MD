# Experimental foreground control validation

Validation completed on October 30, 2026 for Core source commit
`6a9bf825ecc0391e2440638b67ffe61b45a1e9c7`, on branch
`feat/ikev2-foreground-control`, tracking issue #68. Subsequent documentation-only
commits do not change this tested executable identity.

This is experimental evidence, not release or Desktop compatibility approval.
The original `v0.3.0-beta.1` baseline remains
`9f527efe0a4959786084675f1ff795edb8a0d910`; its annotated tag object is
`9cce36d43f70d30d406b020187ad100ac40ba0e7`. Remote default branch review found
master at that same baseline, and release-by-tag returned 404. None of the new
foreground interface is attributed to the unchanged tag.

## Artifact and environment

- Go 1.26.9, Windows amd64; `go build -trimpath ./cmd/bimeron`.
- Binary metadata: version `0.1.0-dev`, revision as above, modified=false.
- Tested executable SHA256:
  `14a3da9a87e07dfe78600c702a3b2f3e7c48e7dbd76baae1c4778c1826067795`.
- Separately authorized disposable Hyper-V VM, Windows 10 build 19044, controlled
  IKEv2 server. Existing lab profile, saved credentials and CA trust remained
  Windows-owned. No credentials or raw private network snapshots are included here.
- Protected Program Files installation, protected installation policy approving
  the exact test-client image, interactive same-user tasks at medium/high integrity.
  Scheduled tasks exercise actual integrity boundaries, not the UAC consent UI.

## Offline checks

The final source passed `go test ./...`, `go vet ./...`, and
`go test -race ./core ./internal/control ./internal/systemvpn ./internal/windowsnet ./internal/killswitch`
on Windows amd64 (race using GCC with CGO enabled).

Focused tests cover strict bounded/correlated framing, malformed/duplicate/unknown
fields, stale instance and installation identity, revision acceptance, activation
once, safe diagnostics, source event drops, timeout without duplicate start,
GUI/context loss, fatal listener loss preserving the owner, cleanup order and
retention, profile review tokens, ownership/journal/rollback guards, Windows pipe
ACL/peer/process identity, squatting, pinned files/ancestors, and PowerShell
environment/module-path poisoning. No offline test changes real VPN/network policy.
Opt-in live tests remain disabled in shared CI.

Compile checks passed for cmd/bimeron, core and internal/control on Linux
amd64/arm64, Windows arm64/386, and Darwin amd64/arm64. These are build checks,
not runtime support or native IKEv2 validation on those targets.
Local checks do not represent a remote CI run. The branch was subsequently pushed
and PR #69 opened after review; its required checks must pass before merge.

## Live results on the final source

| Check | Result |
| --- | --- |
| Protected connect, authoritative status, reconnect and ordered stop | Passed; activation to Connected 3.052 s, stop to cleanup 569 ms |
| Stop during early startup | Passed; cleanup wait 2.8 ms; does not establish a particular RasDial substage |
| Stop while observed DNS protection installation is in progress | Passed; cleanup wait 1.315 s |
| Separate profile-control preview/apply/idempotent apply/remove | Passed |
| Intentional crash of the fixture's connected owner | Passed; persistent WFP retained, IPC lost, no automatic recovery |
| New activation with retained protection | Refused before native open; explicit administrative recovery performed after owner stop |
| Medium GUI process exits, new medium GUI reopens | Passed; owner/protection survived the first process and the same session was stopped by the new process |
| Modified owned DNS policy during connection | Structured cleanup refusal; DNS modified and WFP retained; RAS cleanup completed |
| Explicit recovery after modified policy | Passed; separate foreign NRPT fixture preserved unchanged, then removed explicitly by its fixture |
| Active profile provisioning refusal | Passed without adopting or disconnecting the active RAS handle |
| Profile ownership/idempotency/collision/modification/journal/partial rollback | Existing native preparation live suite passed |

The earlier source `e5bcaabd9132db9383d945a0b84cbd67a792cf78` also passed a live
negative installation-policy check: a wrong approved GUI digest denied elevated
startup before endpoint/network changes; restoring the approved digest allowed
the same waiting medium client to connect. This result is recorded as intermediate
evidence, not a repeated final-source test. The final change only preserves owner
lifetime on control transport failure/panic; its regression check is offline.

Each intentional crash/modified-policy fixture was followed by a separate,
explicit recovery after confirming owner termination. No timeout was resolved by
force-kill, automatic restart, redial or automatic recovery.

## Final VM state

### Supervised UAC follow-up

On the same final-source executable, the user exercised real ShellExecute
`runas` prompts inside the VM. Cancellation returned Win32 error 1223 and no Core
owner appeared; the waiting test client timed out as expected. Consent under the
original account completed authenticated read-only discovery and owner closure
with both client and owner exiting zero (1.80 s client run). No session activation
was requested in these UI checks.

A separately authorized temporary local administrator was then used with native
`runas` password entry followed by a real elevation prompt. The elevated Core
exited 1 while the original user's approved requester was alive; no authenticated
endpoint appeared. The cross-account launcher receipt recorded the distinct SID
and requester PID. The unavailable-client test failure is expected negative-test
evidence, not a successful connection. No password was collected by the harness
or stored in repository artifacts. Test-launch quoting and public receipt ACL
mistakes were corrected before these final observations; they are not product
failures. This validates the Core CLI boundary, not a finished Desktop UAC UI.
Afterward the temporary account was disabled, removed from Administrators and
deleted; all UAC fixture tasks were removed. An orderly disposable-VM restart
unloaded its remaining user profile. The exact deleted account SID and profile
path were verified, then the unloaded profile was removed through
Win32_UserProfile. Final inspection confirmed that the temporary account, profile
record and directory were absent. The temporary public-receipt read ACL was
removed. Repeated network inspection again matched the original routes/DNS and
found no NRPT/WFP or active RAS state.

### Pre-PR review

Source review covered the privileged identity/config boundary, private command
allowlist and instance binding, owner lifetime on client/transport loss, ordered
cleanup/retention, reviewed provisioning, and shared-daemon compatibility. No
blocking findings were identified in this author review; it is not an independent
security audit. Focused control/Core/systemvpn/windowsnet/killswitch tests were
repeated uncached, together with `go vet ./...` and `git diff --check`, and passed.
Remote CI results are tracked by PR #69 and are separate from local evidence.

Final inspection found routes and DNS server settings equal to the recorded
pre-test baseline; zero NRPT rules, absent Bimeron WFP filters, zero active RAS
connections, zero provisioning ownership records, and zero remaining lab tasks
or lab processes. The one original lab profile remained. Credentials and
certificates were not provisioned by these tests.

The pre-existing packet service remained disconnected at revision
`6e0c171505be8e349d5f42570f7ceb3e50ac6697` and was not upgraded or restarted.
This is not a live validation of a newly upgraded packet service. Updated-owner
exclusion is covered by shared-lock tests and the medium-client fixture;
deployment must update participating managed Core hosts as documented.

## Remaining gates and limits

- Real ShellExecute/UAC consent, cancellation and different-account refusal were
  exercised as recorded above. The eventual Desktop launch/error UI still needs
  its own integration validation against the agreed Core SHA.
- Windows 11, RRAS, physical mobility, Windows ARM64 runtime and public IPv6
  remain unvalidated. Windows 10/controlled-server results do not close issue #66.
- No published assets, signed manifests, installer integration, remote CI result
  or Desktop compatibility approval is implied. Desktop files were not changed.
- Desktop must explicitly agree this immutable Core SHA and trusted installation
  policy before its GUI gate is lifted. Installer policy must approve the actual
  Desktop image rather than the test runner used here.
- Protection does not cover bootstrap before activation, BFE startup gaps, or
  privileged changes to OS policy; trust limitations remain in ADR 0026 and the
  foreground contract.

## Performance scope

The focused control serialization/status benchmark measured about 2.824 us/op,
2046 B/op and 16 allocations/op on the development i7-12700K host during this
implementation. It excludes Windows authentication, pipe transport and RAS.
Live timings above are individual observations, not a percentile/SLA or comparison
against a controlled performance baseline. No data-plane benchmark was repeated:
the change adds control/lifecycle paths rather than a new packet transport.

Protocol, installation and recovery requirements are defined in
[the foreground contract](IKEV2_FOREGROUND_CONTROL.MD) and
[ADR 0026](adr/0026-authenticated-ikev2-foreground-control.md).
