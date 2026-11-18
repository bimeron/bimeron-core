# ADR 0039: Reconnect cycles and a held kill switch

Status: accepted, November 18, 2026. Tracked by Core issue #162.

## Context

Desktop 0.3.0 introduced a bounded reconnect budget: three attempts after a
failed initial connection or a later interruption, then `failed`. The budget
gave users a clear end state when a profile could not connect, but it also
turned every server outage longer than a few seconds into a terminal failure.
Users had to notice the failure and connect again by hand, even though the same
profile would have worked a few minutes later.

The packet kill switch was scoped to individual connection attempts: each
attempt installed and owned its own protection. Users who enable a kill switch
expect a simpler rule: traffic stays inside the tunnel or stops, from the moment
they press Connect until they press Disconnect.

## Decision

1. **Two recovery policies per run.** A run is one accepted `start`. Before its
   first `connected`, the initial connection keeps the bounded policy: the first
   attempt plus 3 retries (1, 2 and 4 second backoff), then `failed`; a
   nonretryable failure fails at once. After loss of an established session,
   recovery continues indefinitely in cycles of 10 attempts (backoff doubling
   from 1 second, capped at 15 seconds) separated by a 60 second wait, until
   success or an explicit stop. A connection shorter than 1 minute continues
   the previous cycle position, so a flapping server cannot force a tight loop.
2. **Retry what was working.** After loss, failures that would end an initial
   connection (an unavailable `ssconf` key, a TLS or handshake rejection, SSH
   authentication, tunnel adapter loss) are retried in the same cycles, and
   `LastError` keeps the specific code. Faults that require explicit recovery
   (`_run_recover` codes, a failed session close, a maintenance seal) still end
   the run.
3. **Early wake.** A backoff or wait ends early on the new `reconnect_now`
   command, a change of local network interfaces or a resume from sleep. An
   attempt in progress is never cancelled.
4. **Run-scoped kill switch.** With `KillSwitch = true`, protection is
   installed as the first step of a run, before network inspection, key
   resolution, bootstrap DNS and the transport check. On Windows the early set
   is the full rule set without the tunnel interface permit; it is replaced
   transactionally with the permit before routes and DNS are configured, and
   without it when a session closes. On Linux the nftables table is installed at
   the same point and matches the tunnel by name.
5. **Held until stop.** Protection is never released between attempts, during
   waits or in `failed`. Only an explicit stop (`stop`, `shutdown`, Ctrl+C of a
   foreground session, a service stop) with successful cleanup releases it. A
   failed removal reports `cleanup_failed_run_recover` and keeps protection
   until `recover`.
6. **Held failed state.** With the kill switch enabled, a run that reaches
   `failed` stays active: Status reports `failed` with `KillSwitch: "holding"`.
   `reconnect_now` restarts the bounded initial attempts. `start` with another
   VPN-mode profile that enables the kill switch replaces the held run and its
   filters without a gap; any other `start` is rejected with `kill_switch_held`.
7. **Additive contract.** Status and events gain `ReconnectCycle`,
   `ReconnectPhase`, `NextAttemptAt` and `KillSwitch`; capabilities gain
   `reconnect_now` and `kill_switch_hold`. IPC stays version 1 and the profile
   format stays 1. See [CONTROL.MD](../CONTROL.MD#reconnect-recovery-and-kill-switch-hold).

## Alternatives considered

- **Keep the bounded budget for every interruption.** Simple and predictable,
  but outages longer than the budget still require manual action, and the
  kill switch would remain tied to attempts rather than to the user's choice.
  Rejected.
- **End the run in `failed` and leave the filters installed, as after a
  crash.** Protection would hold, but the user would have to run `recover`, a
  privileged repair step, to get the network back after an ordinary outage, and
  status would no longer describe the installed filters. Rejected: a held run
  keeps ownership, reports `holding`, and is released by a normal stop.
- **Always require `stop` before `start` while held.** Simpler admission, but
  switching to another server would release protection between the two
  commands. Rejected for kill switch profiles; kept for profiles that would not
  hold protection (`kill_switch_held`).
- **Make the kill switch mandatory.** Removes the unprotected window entirely,
  but takes away the per-profile choice and breaks setups that rely on direct
  routing outside the tunnel when the VPN is down. Rejected: the option stays
  per profile, and documentation states plainly that without it traffic can
  leave outside the tunnel while connecting, reconnecting or after a failure.

## Consequences

- A foreground `bimeron connect` or `bimeron run` with the kill switch keeps
  running in held `failed` until Ctrl+C; `Engine.Wait` does not return in that
  state.
- A held run can be replaced in one `start` only by a kill switch profile in
  VPN mode; the new run's early arm replaces the previous filters
  transactionally. A guarded daemon `start` is admitted in the held state.
- Embedders that supply `SessionConfig.Resolve` and perform their own network
  I/O are blocked by early protection; they must use the provided network path
  (`ResolveOnNetwork`). `KeyFile`, `LoadConfig` and `FromConfig` already do.
- Native IKEv2 keeps the bounded policy and its own protection contract.
- Desktop 0.3.0 keeps working: it shows the 1–10 counter within cycles and
  "Reconnecting…" without a counter while waiting, and treats a held failure as
  `failed`. Desktop 0.3.1 can show the wait countdown, the holding notice and a
  Retry now button; the release that ships it must widen
  `release/compatibility.json`.
- Service stop and OS shutdown keep their behavior: they stop the session and
  release protection. Keeping protection from boot until the user connects
  ("always-on VPN") is out of scope and left to a later ADR.
