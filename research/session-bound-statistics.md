# Session-bound statistics: audit and decision brief

Status: option A approved for additive implementation; tracked by issue #89.
Source pin: `c04f20d575e4aed979b1024a32b421e7e5de1afe`.

## Ownership and call graph

- `core/engine.go:181-224`: Start validates first, then under `Engine.mu`
  rejects overlapping runs, allocates new counters, injects the pointer into
  SessionConfig, replaces Status with a fresh random Session.ID, and starts run.
  Rejected Start does not reset counters. Accepted Start resets even if later
  backend acquisition or opening fails.
- `core/engine.go:86-92,117-134`: Stats and Status individually hold the same
  mutex. Status copies Native and Session and derives Active from engine state.
  Stats selects the counters and native-unavailable flag consistently, but
  returns no session identity. Separate method calls have no joint consistency.
- `core/engine.go:259-353,357-414`: run acquires the backend, increments Attempt
  before Open, serves, closes and retries. Persistent Reconnect also increments
  Attempt. Neither retry path replaces the per-Start counter pointer. Completion
  marks inactive under the mutex before closing runResult.done. Stop waits for
  that completion; a caller timeout does not permit a replacement Start early.
- `core/config.go:56-57`, `core/runtime.go:94-97,236-275,493`: every VPN handler
  generation and SOCKS server receives the same per-Start counters. Handler
  replacement does not establish a new statistics epoch. `core/flow_router.go:34-41`
  swaps handlers under its own lock and then closes the old handler.
- `internal/vpn/handler.go`, `internal/vpn/dns.go`,
  `internal/proxy/server.go`, `internal/proxy/server_udp.go`: traffic paths update
  atomics without taking Engine.mu. TCP accounts bytes accepted by each write
  through `internal/telemetry/copy.go`; these are application-path byte counts,
  not wire overhead or OS interface measurements.
- `internal/telemetry/telemetry.go:10-88`: Snapshot independently loads each
  atomic. Fields can describe different instants; active counts are gauges.
  Locking Engine does not make the counter tuple linearizable.
- `internal/control/server.go:145-150,220-281,381`: Server owns the instance ID.
  Stats dispatch reads counters, then later reads Status; only mutating commands
  hold command admission. A Stop/Start between these reads can produce old
  counters beside new identity. Serializing command admission alone would not
  cover direct Go Engine users or autonomous state/attempt changes.
- `core/engine.go:136-153`, `internal/control/server.go:174-186,211-218`:
  Engine has a nonblocking 128-entry channel and drop count; Server drains it
  into another 128-entry history with cursor. Events lack Session.ID and can
  be delayed across Start boundaries. Cursor and Attempt are not counter epochs.

## Contract options

1. **Recommended staged additive observation.** Introduce a separate Go
   observation that copies status/session/active, selects counters, reads their
   existing values and captures Attempt in one Engine critical section. After
   integration review, expose it as an optional separate control response field
   with explicit capability detection, wrapping it with the existing Server
   instance. Preserve legacy Stats/status and event behavior. Older engines
   lacking the optional observation interface cannot advertise support.
   New consumers opt in; the legacy mixed pair remains unsuitable for binding.
2. **Go-only first.** Implement only the additive Engine observation after
   approval. Smaller initial surface; daemon consumers still have no safe
   binding until a separately reviewed wire addition. Apple has no live adapter
   today, so this may be sufficient for the next bounded implementation.
3. **Versioned replacement.** Strengthen existing stats command semantics or
   require new identity fields in a new protocol version. This offers one
   required contract but introduces negotiation/migration work. Resetting
   counters per attempt additionally requires a writer-ownership redesign;
   merely tagging cumulative values with Attempt does not achieve it.

The proposed guarantee is atomic identity and counter-owner selection, not an
atomic counter tuple. Session.ID already identifies the accepted-Start epoch;
Attempt describes retry progress and starts at zero before Open. It is neither
a counter-reset generation nor proof of successful transport installation.
The external scope would include Server instance + Session.ID, with Attempt
as separate observation context. Go Engine identity is the Engine object;
whether an exported instance token is needed requires a real caller requirement.
Do not add a second instance namespace speculatively.

For the new contract, distinguish no accepted Start, available per-Start
counters, and native unavailable counters. Keep terminal totals readable;
do not reinterpret native unsupported counters as zero traffic. Preserve
reset-on-accepted-Start and accumulation across reconnects. No promise of exact
attempt-attributed traffic or a frozen final tuple follows from this proposal.
Consumers must reject unsupported binding rather than infer it from lossy events,
timestamps, matching profile names or two independent reads.

`docs/CONTROL.MD` requires a new version for changed existing command semantics
or required fields. A separate optional observation can remain additive only
while the existing contract is preserved. A capability must follow actual
implementation and validation; this document advertises nothing. Record an ADR
after the architecture decision, not an accepted decision before review.

The Apple statistics owner confirmed read-only against PR #41 that its generation
is a consumer-local observation/resync token, not Core Attempt or a counter epoch.
It requires confirmed instance/session ownership, cumulative per-Start totals and
local monotonic rate timing. Loss, stale gaps, unavailable data, changed identity
or decreased byte counts invalidate the rate baseline. No Apple runtime adapter
is included in this work.

## Bounded validation

Test preparation uses only fake backend acquisition and sessions, no listeners,
OS tunnel acquisition, credentials, live network, or native installation.
A channel barrier holds a reader between Stats and Status while another
goroutine completes Stop and accepts a replacement Start. The expected
characterization is old totals paired with a new session ID, without a Go data
race. Separate lifecycle checks cover retained totals, rejected Start, reset
before backend progress, and isolation from a captured old counter pointer.
This reproduces the Engine call sequence used by dispatch; it does not itself
exercise the control wire or prove a proposed fix.

Implementation validation additionally covers detached identity-bound observations
across replacement Start, no sample before Start, retained terminal/native state,
and cumulative retry totals (17 + 29 = 46 with unchanged Session.ID and Attempt 2).
In-process control dispatch tests check provider capability gating, serialization,
captured inner status despite a differing independent Status, invalid requests,
and foreground admission. These checks do not open a control listener.
