# RAS 668 positive cleanup

Status: accepted offline specification, 2026-11-05. Native Windows confirmation
is pending. This change does not enable the native backend, authorize a lab run
or relax any protection, admission or recovery gate.

## Problem

In the L7 lab run, `RasDial` returned 0 with a nonzero handle. A terminal
callback then reported error 775, and `RasHangUp` on the owned handle returned
668 (`ERROR_NO_CONNECTION`). The run recorded normal cleanup as failed and
retained protection. No positive cleanup was possible after any terminal dial
failure.

## Root cause

- The frozen L7 driver (uncommitted lab source) mapped HangUp 6/668 after a
  terminal callback directly to a cleanup failure. `Close` returned before it
  queried status after HangUp. The run never collected the completion signal
  that Microsoft documents: after HangUp, poll `RasGetConnectStatus` on the same
  handle until it returns `ERROR_INVALID_HANDLE` (6). The archived L7 events
  contain no status query after HangUp. The L7 failure is therefore a policy
  outcome, not an observed native cleanup failure.
- Committed Core (`internal/systemvpn`, identical at `498596e`, `8ef0110` and
  `master` `df7f2fd3`) did the opposite. It mapped HangUp 6/668 after a terminal
  callback to `errInvalidHandle`, the same sentinel that represents status 6.
  It then released resources on the first status 6 after HangUp. Defects:
  - HangUp 668 was conflated with an observed invalid handle.
  - The only release evidence was one status code.
  - A cleanup failure replaced the startup error, so 775 became unreachable.
  - No test covered 668 after a terminal callback.
- Native semantics remain open: whether Windows returns status 6 after
  HangUp 668 in the L7 scenario, and whether that coincides with actual
  state-machine teardown. Only a separately authorized lab run can answer this.

Microsoft references:
[RasHangUpW](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rashangupw),
[RasDialW](https://learn.microsoft.com/en-us/windows/win32/api/ras/nf-ras-rasdialw),
[RRAS error codes](https://learn.microsoft.com/en-us/windows/win32/rras/routing-and-remote-access-error-codes).

## Decision

668 is never success by itself. When HangUp is not accepted after terminal dial
evidence, Core must positively observe that the connection is gone before it
releases native data:

1. **Terminal evidence.** A latched callback or status shows a nonzero error, a
   disconnected state or a previously connected attempt. Without it, HangUp
   6/668 still means *dial pending*, and the existing bounded retry continues.
2. **Distinct classification.** With terminal evidence, HangUp 6/668 maps to a
   new internal sentinel, `errHangupNoConnection`. It never reuses
   `errInvalidHandle`. HangUp 0 remains *accepted*. Every other code remains a
   cleanup failure.
3. **Fresh status probe.** After either accepted or not-accepted HangUp, `Close`
   polls `RasGetConnectStatus` on the owned handle until it sees status 6. Any
   status 6 observed before HangUp never counts.
4. **Enumeration corroboration, not-accepted path only.** After the first fresh
   status 6 in a probe iteration, `Close` runs a read-only `RasEnumConnections`.
   The owned handle must be absent. Rules:
   - The handle is present: wait for the next tick, and repeat both the status
     probe and the enumeration.
   - Enumeration fails or cannot be bounded: cleanup fails.
   - The deadline expires: cleanup times out.

   Enumeration never adopts, disconnects or inspects unrelated connections. A
   reused handle value can only delay release (a false negative). It can never
   authorize release.
5. **Release.** Release happens once, only after the predicate holds. Release
   retires callback tracking and frees EAP identity data. Cleanup timeout,
   failure or ambiguity retains both and reports failure. `sync.Once` keeps the
   first result sticky.
6. **Diagnostics preserved.** When startup fails and cleanup also fails,
   `Error()` still returns the cleanup error. Existing public strings and the
   caller's `switch err.Error()` stay unchanged. `errors.Is` reaches both the
   cleanup error and the startup error (for example, 775 or context
   cancellation). When cleanup succeeds, the startup error is returned
   unchanged.

The accepted HangUp 0 path keeps its existing predicate: a fresh status 6. This
change adds enumeration only where HangUp gave no acknowledgement.

## Out of scope

- Not covered: the cause of 775, a new retry policy, owner-death or
  administrative recovery, service or process termination, guard release rules,
  and protection ordering in `core/ikev2_protection.go`.
- Not covered: the typed numeric failure record and wire/GUI contract
  (`cleanup_hangup` or `cleanup_status` stages). Raw codes stay internal here.
- Native remains OFF. No capability, admission, approval pin or Desktop change
  follows from this document.

## Acceptance criteria (offline)

Session-level tests use the injected fake driver. Windows-tagged tests exercise
the pure HangUp and enumeration classifiers without native calls.

1. **L7 sequence.** The steps are:
   - dial returns handle 196608 with no error;
   - status reports pending, then a terminal error 775;
   - HangUp returns not accepted;
   - the first status after HangUp is 6;
   - enumeration does not list the handle.

   Expected result: exactly one HangUp, exactly one release, and observer states
   `pending, succeeded`. The returned error is the startup error, not a cleanup
   error.
2. **L7 without a later invalidation.** The same sequence, but status never
   returns 6 after HangUp: cleanup timeout, no release, observer `failed`. The
   startup error stays reachable with `errors.Is`.
3. **Enumeration still lists the handle.** Release waits. If the handle later
   disappears before the deadline, release happens once. If it stays, cleanup
   times out with no release.
4. **Enumeration error.** Cleanup fails with no release.
5. **No early release.** Status 6 observed before HangUp, or while the dial is
   pending, never releases. HangUp 6/668 without terminal evidence stays pending
   and is retried within the deadline.
6. **Distinct classification.** The HangUp classifier maps:
   - 668 and 6 with terminal evidence to `errHangupNoConnection`, never
     `errInvalidHandle`;
   - the same codes without terminal evidence to `errDialPending`;
   - 0 to accepted;
   - other codes to non-sentinel failures.
7. **Enumeration classifier.** It reports absent for an empty list or for
   unrelated handles. It reports present for the owned handle at any index. It
   returns an error for a nonzero code, including buffer too small, and for a
   count larger than the buffer.
8. **Unchanged accepted path.** HangUp 0 followed by status 6 releases without
   enumeration. Existing tests stay green, with unchanged behavior and strings.
9. **Concurrency.** Concurrent `Close` calls on the not-accepted path perform one
   HangUp and one release, and return the same result. The package passes
   `go test -race` where the toolchain supports it.

## Native confirmation gate (not performed)

Before production use, a separately authorized lab run must record on the
owned handle:

- the raw HangUp code;
- every status code after HangUp;
- the enumeration result.

Each observation must be time-ordered against the terminal callback. The run
must confirm that status 6 and absence from enumeration follow HangUp 668
within the cleanup deadline. If they do not, the predicate keeps protection
retained, which is the safe outcome. No lab work is part of this change.
