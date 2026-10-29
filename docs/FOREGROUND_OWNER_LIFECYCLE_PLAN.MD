# Foreground owner lifecycle correction plan

Baseline: `62438a971f60c530c9b706e2327699cb952d612b`. This acceptance update precedes implementation.

## Decisions

Reuse session launch serialization for activation, preactivation cancellation and irreversible close acceptance. Validate identity, revision and request shape before state transitions. Refresh terminal/inactive status under that lock. Release it before long stop waits and avoid Engine callback lock inversion. A valid stop before activation permanently cancels activation. Refused close leaves the owner usable. Provisioning uses its existing mutex to close admission atomically with task state; drain tasks outside that mutex.

Accepted close schedules shutdown after the response write attempt even if writing fails or encoding falls back to response_too_large. Document stable safe owner_closing and activation_cancelled errors (or justified equivalent).

For installer exclusion, prefer the existing Global\\BimeronCoreConnect transaction mutex plus the lifetime marker check under that mutex: retain the mutex on the acquiring OS thread throughout replacement, rollback or commit, admitting no concurrently starting updated owner. Inspect security, abandoned ownership and existing-object handling before documenting this as supported. The marker is not authentication; absent pipes/process enumeration never prove cleanup. If these primitives cannot provide the contract securely, specify and implement the smallest guard with focused tests or explicitly identify a dependency PR. Do not add a general Engine helper, policy-schema change, automatic shutdown, kill or recovery.

## Acceptance

Reproduce failures before production edits with deterministic fake Engine/channel tests. Cover both activation/close and apply/close orderings, blocked response writes with concurrent mutation, stop before activation, malformed/stale requests, refused-close usability, task draining, write failure and oversized-response shutdown. Run applicable full tests, vet, focused race detector and supported platform builds; preserve CI and updated packet host exclusion. Document exact tested source and remaining live gates without reassigning historical binary evidence.

Use a tracked issue and this separate branch. Implementation and independent review run gpt-6.1-sol low, Standard. Create a Conventional Commit and PR, register its URL, then wait for exact-head CI and resolve blocking review before authorized merge. No release, tag, asset publication, host network mutation, credentials or VM work. Desktop compatibility remains gated on separate live integration evidence.
