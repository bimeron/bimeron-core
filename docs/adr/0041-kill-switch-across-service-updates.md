# ADR 0041: Keep kill switch protection across a client-requested service update

Status: accepted, November 20, 2026. Refines point 5 of
[ADR 0039](0039-reconnect-cycles-and-held-kill-switch.md) and its consequence
about service stops. Tracked by Core issue #227.

## Context

ADR 0039 holds kill switch protection from an accepted `start` until an
explicit stop, and counts a service stop as an explicit stop. On Windows the
service is replaced in two places. Both run Core's `bimeron service update`
from the core bundled with Desktop, and that command stops the service through
SCM:

- the in-app core update, which Desktop elevates;
- the Desktop MSI, whose deferred custom action runs as `SYSTEM` after
  `InstallFiles`.

The SCM stop ends the session and removes the filters. Until a client starts
the profile again, traffic can leave outside the tunnel. After an MSI upgrade
nobody starts it again: Desktop does not remember which profile was connected.

## Decision

1. **Opt-in flag.** `service update` accepts `-keep-kill-switch` (Windows only;
   Linux rejects the flag). Without it, an update behaves as before.
2. **Request to the old service.** After staging and verifying the new
   executable, and immediately before the protected stop, the updater sends
   `prepare_update` to the running service over the readiness pipe.
   - Only administrators can open that pipe. The updater checks that the pipe's
     server process is the one SCM reports for the service.
   - The service arms a one-shot transaction for 60 seconds. The same live
     process sends its transaction ID in `commit_update` on the readiness
     pipe. The service stops itself and publishes a receipt after cleanup.
     Pipe access authorizes both requests, the process check binds the commit
     to the preparer, and the receipt proves the stop outcome. Windows service
     DACLs may grant standard users `SERVICE_USER_DEFINED_CONTROL`; the
     service uses no SCM custom control to authorize or consume a hold.
   - An IPC `stop` or `shutdown` cancels the hold, and so does a newer
     request. An OS shutdown never uses it.
   - The reply carries the kill switch state (`Status.KillSwitch`).
3. **A stop that keeps protection.** On that committed stop, the service ends the
   session as an owner exit (`MarkAbandon`, ADR 0039). The tunnel, routes and
   tunnel DNS are removed. The filters stay in place, normally in their early
   form, which blocks everything except the core, loopback, DHCP, neighbor
   discovery and `direct` destinations.
   - If the run owned protection at that moment, the service first records
     the held session's `profile_id` in its installation directory. The record
     is a file that only `SYSTEM` and Administrators can read or write.
   - The service exits cleanly. For an updater that asked for the hold, exit
     code 0 therefore no longer proves that no filters remain.
4. **Reported held profile.** The new service reports the filters as residual
   protection, as today: `failed`, `cleanup_failed_run_recover`, `KillSwitch:
   "residual"`. While the record exists, it adds:
   - `ResidualReason: "update"`;
   - `ResidualGeneration`: the digest of the held WFP rule IDs;
   - `ResidualProfile`: the recorded `profile_id`, the lowercase hex SHA-256 of
     the normalized absolute profile path, as in `Session.profile_id`.

   The record is removed when a run arms its own protection, or when no
   Bimeron protection is installed at all, for example after `recover`. A
   start that installs no protection leaves the record in place. The record
   survives a reboot and further updates.
5. **Restart by the client.** A client that sees `ResidualReason: "update"`
   requests `resume_update` with the current service instance, profile ID
   and residual generation. Core loads the profile, checks its effective kill
   switch, and verifies the held generation under the Windows session lock. It does so
   once its own update command has finished, or immediately if it ran no
   update, for example after an MSI upgrade or its own restart. This is an
   exception to the rule against starting automatically after
   `cleanup_failed_run_recover`. The new run's early arm replaces the filters
   in one transaction, so protection is never absent. The client shows the
   usual residual recovery prompt instead when:
   - `ResidualProfile` is absent;
   - no profile matches it;
   - the profile no longer enables the kill switch;
   - the start fails.
6. **Updater behavior.**
   - The updater reports on standard output whether protection was kept.
   - If the reply shows no protection (`KillSwitch` empty), there is nothing to
     keep. If it shows `residual`, the filters stay installed anyway.
   - A verified explicit legacy `invalid_request` permits a warned legacy
     update. Ambiguous preparation fails before commit. After a lost commit
     reply, replacement requires a clean stop and the matching durable
     receipt. An already stopped service stays stopped.
   - If the new service fails its health check, the updater asks it for the
     same hold before the rollback stop. A profile the client already
     restarted on it stays protected that way.
   - Clients rely on the reported status after the update rather than on the
     output, because an elevated or installer-run command's output is often
     not visible to them.
7. **Capability.** Ordinary service `hello` advertises
   `kill_switch_update_hold` and `kill_switch_update_resume`. The bundled
   Windows CLI exposes contract revision 1 via `service update-contract`.
   A signed Windows archive record binds revision 1 and executable SHA-256
   to the archive digest and architecture. Absent or unknown revision
   provides no opt-in signal. Replacement health accepts a verified
   residual profile/generation or an active/holding session with the exact
   expected profile ID. Rollback preserves the actual owner and retains the
   backup when a safe stop cannot be verified.

### Compatibility matrix

An in-app client opts in only when the installed service advertises both
capabilities, the bundled updater supports revision 1, and the selected
signed Windows replacement supports revision 1. A client omits the flag
on a supported legacy update path. For a cleanly stopped service, there
is no running owner to prepare. The client checks fresh authenticated
status after the updater exits, including after a rollback or error.

### Installers

Compare trusted installed and bundled executable SHA-256 values and
architecture first. Identical bytes leave Core and its VPN session running.
Desktop preserves the originating user's window or tray state and leaves a
previously closed GUI closed.

For interactive replacement with an active protected VPN, obtain consent and
secure a compatible relaunch in the owning session before opting in. Run Core
replacement after verified MSI completion. After the updater exits, the
relaunched GUI reads fresh service status and uses guarded `resume_update`.
An incompatible hold path requires a clear interruption warning and an
explicit user decision. Failed or unconfirmed resume follows ordinary recovery.

For silent replacement while the VPN is active, install the GUI only when it
is known compatible with the retained Core. If automatic Core activation is
unavailable, report `core_deferred_admin_required`. An incompatible or unknown
pairing defers the entire upgrade before mutation (`upgrade_deferred`).
Immediate hold is reserved for an explicit managed deployment with a verified
compatible relaunch in the owning session.

Standalone automatic idle activation remains disabled. In the native spike,
a failure after InstallFinalize returned 1603 despite a commit marker, exact
installed package and component identity, and no observed pending replacement
or rollback marker. Pending and commit-observed records remain inert. Managed
idle activation requires independently verified terminal MSI success, exact
machine/package/payload identity, no pending replacement, and exclusion against
competing product changes. Exit 3010 requires a reboot and revalidation.
External or multi-package transactions with an unproven terminal outcome,
disabled rollback, missing evidence, or unavailable worker fail closed.

The proposed managed worker runs headless as SYSTEM after those gates pass.
It uses Core's separate idle admission contract to reserve a clean disconnected
installation and commits a same-process stop. The worker must observe the
original service stopped and validate the matching durable receipt before image
mutation. Reboot or a lost reply requires reconciliation of the receipt,
journal and actual images. A committed stop is never replayed. This proposal
does not change the in-app update or resume protocol.

### Relation to ADR 0040

ADR 0040 (proposed) moves service replacement into a privileged maintenance
session on a signed store and replaces `service update -source` and the
installer step. If it is accepted, the same hold applies there, and that
design must keep two properties:

- **A channel for the request.** The hold request needs an
  administrator-only channel to the running service, bound to its process.
  ADR 0040 opens its readiness channel only for nonce starts, so a service
  started at boot or by `service start` would have none, and the request
  would fail and release protection. ADR 0040 must keep such a channel on
  every service start, or carry the request on its own maintenance channel.
- **No cleanup of kept protection.** ADR 0040's rollback treats pending
  filters as needing `Recover` before it starts the old image. A stop that
  kept protection on purpose (the record exists) must be exempt: the rollback
  starts the old image with the filters and the record in place, and re-arms
  the hold before any rollback stop, like the updater here.

The record, the status fields and the client contract stay unchanged.

## Alternatives considered

- **The updater installs bridge filters itself.** It does not know the
  profile's `direct` rules, and the old service's cleanup would remove them or
  fail on them. Rejected.
- **A custom SCM control code.** Under the default service security,
  interactive users have `SERVICE_USER_DEFINED_CONTROL`, so any user could make
  the next stop keep protection. Rejected in favor of the administrator-only
  readiness pipe.
- **Refuse the update when the installed service does not support the hold.**
  Safer for that one update, but it blocks moving from older cores that can
  never support the hold. Rejected: the client sees the capability first and
  can tell the user.
- **The updater or the new service restarts the session.** Neither has the
  client's prompts (SSH keyboard-interactive) or the user's decision to
  reconnect. Rejected: the client restarts the profile that Core reports.
- **Desktop remembers the profile itself.** This works for the in-app update,
  which already keeps the profile in memory. The MSI custom action runs as
  `SYSTEM` in another process, so Desktop would need a second persisted
  record. Rejected: Core already knows the held session and reports it to
  every client the same way.

## Consequences

- After an MSI upgrade that kept protection, traffic stays blocked until
  Desktop starts and restarts the profile, or the user stops the protection.
  This is what the kill switch promises.
- The filters are persistent. If the machine restarts before Desktop restarts
  the profile, protection holds from boot until then, as after a crash today;
  Desktop started at login completes the restart. This ADR adds no other boot
  behavior; keeping protection from boot in general is a separate decision.
- If the update fails and the old executable is restored, the restarted old
  service reports the same residual protection and record, and the client
  restarts the profile. If the service cannot be started at all, the filters
  stay until `bimeron recover` or Repair, as after a crash.
- The record holds only the profile identifier. Uninstall removes it with the
  service files.
- OS shutdown and an ordinary service stop keep releasing protection.
- Linux updates keep today's behavior; Desktop does not perform Linux service
  updates.
