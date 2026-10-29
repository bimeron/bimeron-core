# Foreground owner lifecycle correction plan

Baseline: `62438a971f60c530c9b706e2327699cb952d612b`. This acceptance update precedes implementation.

## Decisions

Reuse session launch serialization for activation, preactivation cancellation and irreversible close acceptance. Validate identity, revision and request shape before state transitions. Refresh terminal/inactive status under that lock. Release it before long stop waits and avoid Engine callback lock inversion. A valid stop before activation permanently cancels activation. Refused close leaves the owner usable. Provisioning uses its existing mutex to close admission atomically with task state; drain tasks outside that mutex.

Accepted close schedules shutdown after the response write attempt even if writing fails or encoding falls back to response_too_large. Document stable safe owner_closing and activation_cancelled errors (or justified equivalent).

For installer exclusion, prefer the existing Global\\BimeronCoreConnect transaction mutex plus the lifetime marker check under that mutex: retain the mutex on the acquiring OS thread throughout replacement, rollback or commit, admitting no concurrently starting updated owner. Inspect security, abandoned ownership and existing-object handling before documenting this as supported. The marker is not authentication; absent pipes/process enumeration never prove cleanup. If these primitives cannot provide the contract securely, specify and implement the smallest guard with focused tests or explicitly identify a dependency PR. Do not add a general Engine helper, policy-schema change, automatic shutdown, kill or recovery.

## Acceptance

Reproduce failures before production edits with deterministic fake Engine/channel tests. Cover both activation/close and apply/close orderings, blocked response writes with concurrent mutation, stop before activation, malformed/stale requests, refused-close usability, task draining, write failure and oversized-response shutdown. Run applicable full tests, vet, focused race detector and supported platform builds; preserve CI and updated packet host exclusion. Document exact tested source and remaining live gates without reassigning historical binary evidence.

Use a tracked issue and this separate branch. Implementation and independent review run gpt-6.1-sol low, Standard. Create a Conventional Commit and PR, register its URL, then wait for exact-head CI and resolve blocking review before authorized merge. No release, tag, asset publication, host network mutation, credentials or VM work. Desktop compatibility remains gated on separate live integration evidence.

## CI fixture diagnosis follow-up

Two Windows CI attempts at d5a5b5e expired the 15-second test-fixture budget: native64 trusted module discovery, then 386 mocked DNS fixtures. A parallel exact-head run passed. Isolated AMD64/386 repetitions passed; DNS commands are in-memory mocks and module discovery executes no networking command. WOW64 redirects the configured System32 path to 32-bit PowerShell for 386 as expected. Startup/module loading latency is a hypothesis, not an established root cause.

Before selecting a behavioral fix, add bounded sanitized test-only phase/error diagnostics and controlled-cancellation coverage. Preserve production cancellation, trusted environment/module restrictions, poison detection, and DNS ownership assertions. Repeat isolated fresh-child fixtures on both architectures with bounded load. Do not automatically retry or inflate production deadlines. Send the new exact head and evidence to the coordinating parent, which owns CI watch, independent review and merge.

## MASQUE closed-client error precedence follow-up

Exact-head CI exposed a pre-existing MASQUE error-classification race, reproduced 3/30 times with the unchanged loopback concurrent_packets_and_shutdown reference test under the race detector. Its final assertion calls DialStream after Close returns. Shared connection admission selects canceled setup context versus semaphore before checking client closure, so scheduling chooses context.Canceled or net.ErrClosed. Relevant code predates this lifecycle PR.

Prioritize already-closed client detection in shared connection admission before the cancellation-sensitive select, retaining the protected check afterward. Preserve live-client caller cancellation and the existing reference assertion. Add a socket-free closed-client/canceled-context regression and live-client cancellation control, repeat the unchanged loopback reference subtest under race, and run the original six-package race command. No deadline changes, skips, manual CI reruns or host networking. The earlier PowerShell stall remains separate and unproven.
