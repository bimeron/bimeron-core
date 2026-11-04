# SSH auth reply lifecycle research (proposal, not an approved contract)

## Scope and pinned evidence

Core source: `7cc55f07ce2c48be4071b155c3dd58cf925a88ae`. This work changes only research documentation and local experiment tests. No production API, validator, or wire changes are approved or implemented. All evidence is source inspection or local in-process execution, not released, hosted, installed, or live acceptance. Apple main `a84e475`, H21 `ace5610e9e3817fb9238f256915898f95ab38f48`, and the isolated I/PR18 disabled runtime are supplied context, not independently validated Apple evidence here. No paused owner was contacted. No remote issue, PR, CI, socket, credentials, daemon, installation, or live SSH/VPN operation is part of this research.

## What the pinned code guarantees

`internal/control/server.go` defines protocol version 1. `prompt` validates 1–8 prompts, matching echo count, valid UTF-8 and at most 256 bytes per prompt. Each answer must be valid UTF-8 and at most 1024 bytes; count must match. These are byte limits, not character limits. `handle` caps the entire newline-terminated request at 16 KiB; direct dispatch experiments bypass this framing layer. `prompt` starts a two-minute timer after publishing the pending pointer. That timer is callback wake-up/cleanup, not a strict reply admission deadline. Earlier context cancellation can shorten its lifetime. Prompt kind is not validated by this function.

Each Server and each challenge obtains an independent 16-byte cryptographically random ID. The single pending slot holds a challenge and a buffered reply channel, but no session ID, generation token, context, or deadline. `auth_pending` copies that challenge under `authMu`, then dispatch reads engine Status separately. Thus outer `status.Session` is not an atomic ownership annotation for the challenge.

`auth_reply` validates ID, answer count and bounds under `authMu`; successful validation clears pending and sends a copy of the answers into that exact pending object's channel before unlocking. Concurrent valid replies cannot both consume the same slot. Invalid IDs/counts/answers do not consume it. Deferred prompt cleanup uses pointer equality and cannot erase a newer pending object. Old IDs do not intentionally address new challenges, including across daemon replacement (apart from negligible random collision probability). The pending slot is not per-client: any caller allowed by transport authorization can observe and consume it. Request `id` is correlation, not ownership.

`validDaemonGuardRequest` allows nonempty Instance only on start and stop; session without instance is rejected. Consequently auth_reply with either identity combination is `invalid_request`, even if the identities are correct. `daemon_session_guards` advertises start/stop support only. It is not an auth-reply capability.

## Session lifecycle and residual race

`core/engine.go:Start` creates a random SessionInfo, rejects another active session, derives a cancellable session context and starts the asynchronous run. `Stop` cancels it and waits for runResult.done; a timed-out Stop only ends the wait. Active remains true until run cleanup finishes; Start cannot replace it during cleanup. The control command mutex serializes start/stop/shutdown and their guards, but auth_reply does not acquire it.

`cfg.SSHPrompt = s.prompt` is passed through `core/runtime.go` into `internal/sshtunnel/client.go`. Key passphrase, password and keyboard-interactive callbacks use the supplied context and exact pending channel. Backend Open runs synchronously in the engine run; its prompt cleanup normally finishes before run completion allows restart. This gives strong practical cross-session isolation without a wire Session field. It does not establish explicit generation ownership in the control server. Transport reconnects can share one engine Session ID, so session guards alone would not identify an individual SSH attempt.

Cancellation and timeout are not checked in reply admission. A pending callback can be cancelled or its timer can fire while its deferred removal is waiting for authMu; auth_reply can still accept and enqueue a response before removal. If cancellation and the reply are both ready at the select, Go can choose either. A context already cancelled before prompt entry is also not rejected before publication. The two-minute timer is not stored and does not make expired replies synchronously invalid.

An accepted reply therefore proves one-time enqueueing only. It does not prove callback delivery, continued session ownership, host verification, key decryption, successful SSH authentication or Connected state. Password/key callbacks have no additional context check after prompt returns. SSH transport closure on dialCtx cancellation mitigates continued handshake use, but is not an admission guarantee. The dial/handshake context has a 20-second timeout while callbacks receive its parent; proxy resolution additionally supplies a 30-second parent. Do not promise the GUI a full two-minute SSH window. No cross-session credential delivery exploit is established by these findings.

## Architectural options

1. Keep the current protocol and document enqueue-only semantics. Random one-use challenge IDs already prevent intentional reply redirection to new callbacks. Lowest compatibility cost; leaves late acceptance and non-atomic UI ownership unresolved. Suitable only while the Apple sender remains disabled.
2. Bind challenge creation to an internal session/attempt owner and expiry; consume or invalidate it atomically. Keep legacy reply fields and existing error vocabulary. This addresses lifecycle correctness at the source and covers multiple attempts within a session. It needs a precise owner supplied before callbacks can publish; sampling engine.Status inside prompt is insufficient. It cannot express the client's expected owner on the wire by itself.
3. Add opt-in guarded replies plus option 2. Expose immutable challenge ownership and a distinct advertised capability. This lets the UI reject a challenge belonging to another session and lets Core check the client's expected owner. More wire and coordination work; simply permitting Instance/Session in the validator is insufficient and creates a check/use race.

Recommendation for discussion: option 2 as the lifecycle foundation, then option 3 only if Apple must assert ownership before sending. Do not add guards merely because start/stop have them. No option is selected as an approved architecture by this document. Keep Apple runtime sending disabled until the chosen contract and integration acceptance are agreed.

## Minimal candidate semantics for architectural agreement

The following is a proposed new contract, not current behavior:

- A start/attempt owner is allocated before prompt-capable work begins. A pending entry captures immutable instance, session, internal attempt token, context and expiry together with its random ID. Do not infer owner from a later status snapshot. Challenge generation binding remains necessary even with session guards.
- Publish only while the owner is live. Owner cancellation/retirement, expiry, and reply consumption use one lifecycle admission mechanism. Within it check owner liveness, deadline and current pending identity, then claim once or invalidate. Stop marks the owner retired before waiting for engine cleanup. Define cancellation after a successful claim as a later event: acceptance still cannot guarantee SSH success. A callback should recheck cancellation before returning answers. Do not promise rollback of an already claimed reply.
- Avoid holding the existing command mutex for engine.Stop while a callback needs it to finish: that can deadlock. Define and test lock order before implementation. A shared owner registry/admission lock or an atomic claim/retire state is preferable to adding a second non-atomic Status check. Session/attempt ownership requires core/control coordination; it is not a validator-only patch.
- Proposed handshake flag `daemon_auth_reply_guards: true` is separate from `daemon_session_guards`. A guarded auth challenge exposes its captured instance/session, not outer status sampled later. Clients require this explicit flag; absence means keep guarded GUI sending disabled. Never infer support from version 1, release version, or start/stop capability.
- Preserve unguarded legacy requests and their answer/count/framing rules. New guarded mode requires both nonempty identities. Existing start/stop behavior is unchanged. Never strip guards and retry after rejection. No automatic resend after an uncertain transport result: a reply may already have been consumed.
- Proposed guarded error order: malformed frame closes as today; semantic malformed request returns `invalid_request`; wrong instance returns `stale_instance`; absent/inactive/retired or mismatched captured session returns `stale_session`; absent/replaced/reused/cancelled/expired challenge or wrong count returns `invalid_auth_challenge`; invalid answer bytes return `invalid_auth_response`. Rejected wrong-owner or malformed-answer requests never consume another owner's live challenge. Retired/expired entries may be invalidated without delivering answers. Avoid a new detailed expiry error unless a caller requirement justifies it.
- An accepted response means atomically claimed for the captured callback, never authenticated. The UI follows current instance/session/attempt status and must not present success based on auth_reply alone. Socket authorization remains the security boundary; these identities are stale-intent guards, not client authentication.

Any stricter late-reply rejection changes a legacy edge case even if the wire shape remains compatible. Preserve normal legacy behavior and existing error strings; explicitly agree this race-boundary tightening before implementation. If exact historical cancellation-race behavior is required, gate the stricter lifecycle semantics too, rather than silently calling it unchanged.

## Local experiment evidence

The LOW child authored the initial five tests; coordinator review added an explicit expiry-state model and a stop barrier. `internal/control/ssh_auth_lifecycle_experiment_test.go` covers:

- Cancelled old ID rejected after cleanup while a new challenge remains usable; consumed ID rejected on reuse.
- Cancellation wins the real prompt select, with a custom Context.Err barrier delaying return/cleanup. Dispatch still accepts the reply, while the callback subsequently returns context.Canceled with zero answers. This is a deterministic enqueue-versus-delivery counterexample, not SSH authentication evidence. The custom context intentionally stretches an otherwise scheduling-dependent interval.
- Sixteen simultaneous replies: exactly one accepted and one callback result.
- Replacement Server rejects old challenge ID; instance/session fields reject with invalid_request and do not consume the replacement challenge.
- Fake Stop blocks while holding command admission. Auth reply still runs independently, rejects a wrong ID, and consumes the original callback once. Fake restart cannot reuse it. This fake deliberately does not cancel or own its prompt context; it demonstrates control-layer admission separation, not real Engine lifecycle behavior.
- Explicit expiry model installs the pending state representing timer-fired-before-cleanup. Dispatch accepts once. This executes real dispatch against a modeled state; it does not execute the production two-minute timer and proves no timing frequency.

The child and coordinator both observed the system Go 1.22.0 fail before compilation with `go.mod:58: unknown directive: tool` using GOTOOLCHAIN=local. The coordinator used the already cached Go 1.26.9 with GOPROXY=off, without installing or downloading a toolchain. Initial five tests passed under the race detector. Final six-test plus existing one-use regression validation is recorded below.

No framing/socket tests or broad package suite were run: existing package tests can open listeners. Real Engine/backend stop-and-restart is source-inspected, not experimentally exercised here. Real two-minute expiry, Apple behavior, daemon startup, keys, network transport and production SSH success remain untested. No source-built evidence is release/live/hosted acceptance.

Final validation (exit 0):

```sh
GOTOOLCHAIN=go1.26.9 GOPROXY=off go test -race ./internal/control -run '^TestSSHAuth(LifecycleExperiment|ChallengeOneUse)' -count=1
```

Result: `ok bimeron/internal/control 1.664s`. Six experiment tests and the existing one-use regression passed. Formatting and diff whitespace checks passed. This targeted run starts no listeners or daemon. No CI was run under the global pause.
