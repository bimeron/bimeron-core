# ADR 0034: Bounded internal maintenance coordinator

Status: Accepted for the internal slice in issue #92 only.

## Context

The V86 maintenance contract is a proposal, not production authorization. Public
protocol 1 shutdown must remain usable after failure. Stop completion, an inactive
Engine, and a new boot do not prove resource cleanup.

## Decision

Add a package-private coordinator attached explicitly to an Engine. It starts
sealed and has no opening or release transition. Unattached engines retain their
existing behavior. Direct Start and asynchronous Acquire, Open and persistent
Reconnect entry check the attached fence. An effect that already crossed its
entry check may finish; Stop waits for its cleanup. This is an admission fence,
not a resource ledger or a receipt for verified cleanup.

Typed Status, Shutdown and Query use a fake-store boundary only. The owner alone
publishes the gate before invoking Shutdown; Core only reads it and writes a
bounded immutable observation. One immutable operation is retained per coordinator;
exact duplicates join it, conflicting reuse fails, and another operation fails
closed at capacity. There is no eviction or retry of terminal cleanup failure.
A cancelled waiter does not cancel operation-owned Stop or result publication.
Successful Stop is recorded as recovery required, never cleanup success. Failed
result publication is retained in memory as storage failure, never success.

Lock graph: command admission -> short Engine mutex. Engine code never acquires
command admission. Fence reads and attachment use the short Engine mutex; they never take
command admission. Store callbacks and Stop waits run without the Engine mutex. Query
and Status use a separate short result mutex, so they remain available during
blocked store callbacks and cleanup. Store callbacks must not call mutations on
the coordinator. Core never takes an owner transaction lock.

## Alternatives and limits

Integrating the public control server would change the authorization boundary and
is deferred. Implementing a production resource journal would require approved
resource identities, postconditions, authority and durability rules; a generic
framework would conceal those unresolved requirements. This slice instead denies
all new resource entry once attached, including work scheduled before attachment.

No endpoint, wire schema, persistence adapter, filesystem namespace, startup
integration, capability advertisement, recovery, release or reboot policy is
introduced. The fake boundary does not establish crash durability or replay
across process restarts. Existing sync.Once cleanup is not retry recovery.

## Validation

Focused fake-store/backend tests cover gate and result faults, immutable replay,
conflicts and capacity, session mismatch, cancellation independence, retained
cleanup failure, direct Start and asynchronous resource fences. Public control and
statistics source remains unchanged.

Local validation executed zero tests: both authorized focused race commands failed
before compilation because `GOTOOLCHAIN=local` selected Go 1.22.0, which cannot parse
the module's `tool` directive. The module requires Go 1.26.9; no module or local
installation was changed. Independent source review found no actionable defects.
The existing GitHub-hosted workflow selects Go from `go.mod` and runs all Core and
control tests, including these maintenance and public-v1 shutdown regressions,
with the race detector. Hosted results remain required validation evidence.
