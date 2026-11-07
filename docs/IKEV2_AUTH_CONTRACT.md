# Disabled native IKEv2 authentication contract

Status: bounded offline specification, accepted for implementation on 2026-11-04.
This document is the local issue/acceptance record for this independent task;
no remote issue, PR, release or live authentication capability is created.

## Provenance and boundary

Worktree: `feat/ikev2-auth-contract`, based on local
`498596eabe4ec734cb0bda72059dd74a66c9dc49` from
`plan/ikev2-installation-contract`. The current reference checkout has that same
HEAD plus uncommitted lifecycle/RAS/WFP changes. Those are not this baseline and
are not copied. Desktop D2/D3 reference is commit `4edb869` and the current
read-only `docs/ikev2-gui-integration-plan.md`, NativeIKEv2Actions, Session and
Transport sources. No dirty-source dependency is required for this slice.

The current Core config contains only WindowsProfile, ServerName and KillSwitch.
Foreground authentication is executable/peer/installation authority, followed by
exact accept_revision and instance admission; it is not user VPN authentication.
Provisioning state_token/plan_token consent remains a separate operation.
Generic challenge/answers remain rejected on native foreground/provision routes.
Existing saved Windows credentials and EAP identity use is not a credential-input
or storage API. Existing protection flags on the committed baseline are outside
this change and are not evidence that the dirty reference's protection gate passed.

## Selected bounded design

Implement a small typed in-process pending-auth seam in internal/control, private
and disabled in production. It is owned by the foreground Server, with no exported
enable switch, credential JSON fields, IPC command, native driver callback or
configuration setting. Tests may install a private fixture consumer. Add public
static authentication capability fields reporting submission, attempt-only input,
Windows persistence, certificate selection and smart-card interaction false.
This additive capability is an unsupported declaration, not runtime readiness.

A pending request binds installation, owner instance, Core session, unique attempt,
unique request, exact Windows profile/server and a private authority identity from
the authenticated exchange. Caller-supplied IDs alone never grant authority.
Use a bounded lifetime (maximum two minutes), one outstanding request and no
automatic replacement/retry. Validate all fields before consuming an answer.
Represent username/password, certificate and smart-card intent distinctly, with
certificate/card unsupported; do not accept generic opaque EAP/password blobs.

Attempt-only is the default. Explicit Windows-storage consent is a separate enum
and must produce unsupported without invoking any consumer. Storage result is
separate from authentication acceptance; do not report saved or connected from
the offline seam. One matching valid answer is consumed once. Cancellation,
expiry, owner/session replacement, stop, accepted close and authority/IPC loss
retire pending state. Late, repeated and mismatched replies cannot dispatch or
revive it. GUI loss retires only its auth intent, not the existing foreground
network owner. Admission and retirement must be race-safe.

Take ownership of mutable credential byte buffers at submission, including rejected
submissions; best-effort clear them on every exit. Keep secrets out of exported
snapshots, JSON, fmt diagnostics, error text, events and config. Avoid converting
secrets to immutable strings. A fixture consumer may borrow buffers synchronously
only; it must not retain them. This cannot guarantee erasure of caller copies,
Go runtime/compiler copies, swap, crash dumps, OS/provider buffers or GUI strings.
No secret survives queued asynchronous work in this slice.

## Windows constraint and deferred decision

The baseline validates EAP legacy method 26 and retrieves method-owned identity
through RasGetEapUserIdentityW before passing it to RasDial. Microsoft describes
identity retrieval and the required RASDIALPARAMS/RASDIALEXTENSIONS transfer in
[RasGetEapUserIdentityW](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasgeteapuseridentityw).
This does not establish that arbitrary username/password bytes are a valid EAP
identity. [EAP interactive UI](https://learn.microsoft.com/en-us/windows/win32/api/eaphostpeerconfigapis/nf-eaphostpeerconfigapis-eaphostpeerinvokeinteractiveui)
uses method-produced UI context, specific allocation/free rules and an STA thread;
it is not evidence that the current legacy RAS path can use that API interchangeably.

Before runtime wiring, choose and validate either supported Windows method UI or
a documented method-specific credential preparation API in the correct user/thread
context. Prove attempt-only semantics and cancellation without implicit storage.
If Windows requires persistence, return for a product decision rather than silently
changing the default. Protected wire schema, authority lifetime across exchanges,
provider interaction, persistence/result handling and artifact approval need a
separate reviewed implementation. No native API is executed here.

## Acceptance before implementation

- Test the actual private seam and existing production dispatch/decoder paths.
- Default production remains unavailable and cannot receive native answers.
- Cover exact binding and every mismatch, invalid authority, malformed UTF-8,
  NUL, empty fields, size limits, expiry boundary and invalid lifetime.
- Cover one-shot answer, cancellation before/after answer, late/repeated answer,
  stop/close, IPC authority loss and session replacement; include concurrent
  retirement/answer where tooling supports race detection.
- Assert zeroed owned buffers on success and all rejection paths, no consumer
  retention, and synthetic sentinel absence in formatting/JSON/errors/events.
- Storage consent and certificate/card intent refuse without consumer execution.
- Preserve generic SSH authentication, foreground revision/session checks and
  provisioning token behavior. Add no dependency or packaging changes.
- Run focused offline tests/vet and suitable existing control/Core regressions;
  inspect test selection to exclude real RAS/WFP/profile/credential operations.
  Existing CI picks up ordinary Go tests; no live validation claim follows.

Implementation is delegated at LOW to codex_petr/gpt-6-astra only. One worker at a
time; stop/report on provider quota exhaustion. No commits unless separately
requested. Record concrete results and limitations below, then stop this stage.

## Final focused test-pass record

The private seam and lifecycle hooks are implemented in
`internal/control/ikev2_auth.go`, `foreground.go` and `server.go`; static false
flags are in `core/capabilities.go`. The ownership check now precedes lifecycle
inspection in beginIKEAuth, preventing a foreign authority from changing state.
The authEngine Status fixture uses its existing mutex.

Coverage resides in `internal/control/ikev2_auth_test.go`,
`ikev2_auth_acceptance_test.go` and `ikev2_auth_handle_test.go`: seven binding
mismatches; malformed, empty, NUL and oversized fields; unsupported intents and
storage without consumption; alias clearing; deadline refusal and bounded timer
retirement; one-shot, generation, cancellation, stop and close behavior; foreign
and missing authority; and concurrent answers against retirement, disable and
explicit expiry. Actual net.Pipe handle tests exercise authorization, decoder
rejection, exchange retirement, native generic-answer refusal and false hello
flags. Secret formatting and private JSON serialization are checked.

Bounds are byte counts: identifiers 1–256 bytes, username/password 1–1024 bytes,
valid UTF-8 without NUL. Lifetime is greater than zero and at most two minutes.
Exactly expired deadlines refuse; a timer proactively drops the consumer.
Retirement and synchronous dispatch serialize under ikeMu. One request may be
pending across exchanges; authority is per exchange and generation. Exchange
loss retires authentication intent while the foreground owner survives.

Validation on 2026-11-04 (all passed):

- `go test ./internal/control -count=1`
- `go vet ./internal/control ./core`
- `go test ./core -run 'Test(PlatformCapabilities|ConfigDocument|IKEv2SessionConfigValidation|IKEv2DoesNotInheritPacketCapabilities)' -count=1`
- `go test -race ./internal/control -run TestIKEAuth -count=1`
- `git diff --check` (line-ending notices only)

The bounded completion coverage in `ikev2_auth_completion_test.go` adds actual
net.Pipe handle cancellation and peer closure while the response has no reader,
with bounded completion, dead authority, cleared consumer/pending state, surviving
owner context and cleared late submissions. Ten rounds each exercise actual
foreground stop dispatch against two answers and short real timer expiry against
two answers, with locked state inspection and bounded waits.

Full begin/answer admission covers matching 256-byte installation, instance,
session, attempt, request and ASCII profile fields, plus a valid 253-byte DNS
name with labels no longer than 63 bytes. Mutating the original launch config
verifies the private copy. Nil consumer and missing launch config refuse.
Synthetic sentinel submissions cover rejected Windows storage and accepted
attempt-only input, synchronous consumer bytes, cleared buffers, actual status
and events, unchanged three-field native config, results/errors and secret fmt/JSON.
Storage reports unsupported or not_requested, never saved. The four requested
completion checks passed on 2026-11-04. This concrete coverage satisfies the
bounded acceptance; it does not claim exhaustive scheduling or diagnostic proof.

Runtime wiring, protected cross-exchange authority, native provider interaction,
persistence and native authentication remain outside this offline acceptance.
Only private fixtures and false capability flags are usable now. There is no
portable EAP blob, native credential submission, storage implementation or
production consumer. No native RAS/WFP/credential API, VM or lab operation was
performed. No commits, pushes or PRs were created. Buffer clearing is best effort
and cannot erase caller/runtime/OS copies. Native saved-identity errors retain
their existing meaning and do not diagnose OS configuration.
