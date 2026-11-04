# Offline Core maintenance contract

Run the standard-library tests from the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/maintenance-model -v
```

This is a pure in-memory contract model. It performs no socket, network, daemon,
installation or system operation. Only the three files in this directory belong
to this prototype. The S hosting proposal and servicing model in the sibling
`bimeron-macos/design-daemon-servicing-recovery` checkout supplied context;
this model covers Core admission and evidence rather than artifact replacement.

`Model.disk` represents an atomic durable snapshot. `snapshot()` returns an
independent copy. `fault='before'` or `'after'` on a modeled durable transition
raises `Crash` immediately before or after publication. Volatile approval,
readiness, exit observation and restart exclusion are discarded on crash.
The Core admission seal survives owner crash, but not a new Core instance.
Dirty evidence and the maintenance gate survive both. A start writes dirty
intent before symbolic resource acquisition; guarded and legacy callers share
the same admission rule. No transition automatically starts a session.

The caller obtains `current()` before `begin`, explicitly authorizing that exact
boot, instance and active or idle session. Maintenance then uses `target()`,
which adds the admitted operation and incremented generation. Shutdown requires
that exact installation/operation/generation/boot/instance/session. It seals
before cleanup, including failure. Successful cleanup publishes a durable scoped
receipt; exit alone never creates one. Commit independently requires that receipt,
exact observed exit and restart exclusion. All administrative calls use symbolic
root authorization; a normal start represents an already authorized control call.

A committed operation remains gated across reboot or instance replacement.
`reconcile` requires explicit root approval, successful recovery for the original
target produced by the exact current identity, independent restart exclusion,
and a new current binding. `readiness` then requires a request ID unused within this operation,
matching binding and build, required capabilities, recovered resources and an
inactive session. `release` rechecks those prerequisites before recording release result and finalization separately. A crash after the
result retains the gate until fresh reconciliation. Only finalization opens
the gate. It never acquires resources. Old receipts and readiness cannot be
replayed by a replacement process. Recovery after an interrupted committed reconciliation accepts fresh proof for
the same current binding and rejects prior readiness request IDs. A different
instance on the original boot requires reboot; it cannot adopt lost exit evidence.

Exact duplicate admission returns the retained outcome without mutation, even
while gated or at capacity. Conflicting operation-ID reuse rejects. History has a
fixed constructor capacity (default eight); new work rejects when full, including
after completion. No entry is evicted and unresolved evidence is never discarded.
`expire()` invalidates volatile authority and never opens a gate or clears dirty
intent. There is deliberately no force-unlock or automatic history compaction.

The named adversarial tests cover both start paths, before/after dirty-intent and
gate writes, every target identity component, non-root calls, cleanup failure,
receipt durability, independent exit/exclusion, committed reboot reconciliation,
rejection of same-boot instance replacement, stale producers/readiness, duplicate/conflicting
requests, capacity exhaustion, expiration, and commit/reconcile/release crash
boundaries. These are deterministic traces, not exhaustive state exploration.

Limitations: evidence is injected trusted synthetic data, not authenticated IPC,
cryptographic attestation or actual cleanup verification. Atomic dictionaries do
not prove fsync, record parsing, corruption handling or power-loss durability.
No locks, launchd adapter, process observer, filesystem, installer, artifact trust,
DNS/route/utun recovery algorithm or production Core API is implemented. Empty
engine state after restart does not prove cleanup. Failed or pre-commit recovery
remains gated without a recovery continuation in this deliberately narrow model.
Tests may inspect or alter snapshots as fixtures; direct mutation is not a
supported privileged input channel. Platform acceptance and CI are separate work.

Challenge issuance, actual expiry clocks and reconciliation sequence validation are
contract design only; the model checks synthetic request uniqueness within an operation.
