# ADR 0033: Additive session-bound statistics

Status: Accepted

## Context

Legacy control dispatch reads Stats and Status separately. A replacement Start
between reads can associate one session's counters with another session's ID.
Engine already protects the counter pointer and session identity with one mutex,
but traffic writers update individual atomic counters outside that mutex.
Events are lossy and carry no session ID. Consumers cannot infer attribution
from the legacy pair or from event timing.

## Decision

Add Engine.StatsSnapshot and an optional stats_snapshot command/response. Copy
status/session/active, select the counter owner and read counters while holding
Engine.mu once. The existing Server-owned instance wraps the response; do not
invent an additional Engine instance namespace. Advertise session_bound_stats
only when the Engine supplies the optional snapshot interface. Existing Engine
interfaces and legacy commands retain their behavior. New consumers attribute
only using the inner copied status and actual response instance.

No accepted session means no counters/sample. Accepted Start establishes the
counter epoch through Session.ID. Reconnect keeps cumulative totals; Attempt is
only observation context. Termination retains totals. Native IKEv2 remains
explicitly unavailable. Counter fields remain independently atomic, not a
linearizable tuple. Consumer resync generations and monotonic rate timing stay
outside Core's counter ownership contract.

## Alternatives and consequences

A Go-only addition would leave daemon consumers unable to bind statistics.
Replacing existing command semantics would require a new control version and
consumer migration. Per-attempt counters would require changing writer ownership
and reset semantics without a current requirement. The separate optional
contract preserves version 1 compatibility and avoids all three expansions.

Legacy readers remain exposed to their existing pairing limitation. Consumers
must check support and cannot substitute legacy reads when binding is required.
Tests use deterministic fake backend interleavings and cover dispatch/provider
behavior without live tunnel acquisition. This does not implement an Apple
runtime adapter or establish native traffic measurement support.
