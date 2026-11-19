# ADR 0042: Always-on VPN at boot

Status: proposed, November 19, 2026. All design questions (Q1–Q6) were decided
by the user on November 20, 2026 (see Decisions). The record becomes accepted
when it is merged. Not accepted yet. This record authorizes no implementation.

It amends [ADR 0039](0039-reconnect-cycles-and-held-kill-switch.md) for
persistent sessions:

- decision 1: a restored run cycles from its first attempt;
- decision 2: `_run_recover` faults and a maintenance seal no longer end a
  persistent run;
- decision 5 and its last consequence: a service stop or OS shutdown no longer
  releases protection;
- decision 6: a held `failed` state also exists without the kill switch, and a
  changed bundle hands over.

It also amends the CONTROL.MD statement that a maintenance seal releases
protection, and parts of [ADR 0040](0040-signed-core-store.md) listed under
Interactions. It builds on the service update hold of
[ADR 0041](0041-kill-switch-across-service-updates.md), which is proposed
separately and must land first or together with this record. It
takes over both items that ADR 0040 lists under "Related decisions recorded
separately": always-on VPN at boot and the service reading of profile files.

## Context

The user requirement for a kill switch profile is one rule: no traffic leaves
outside the VPN from the moment the user presses Connect until the user
presses Disconnect, including reconnects, waits and failures.

ADR 0039 meets this rule while one service process runs: protection is
installed as the first step of a run and held through every attempt, wait and
`failed` state. It deliberately stops at the process boundary:

| Event while a kill switch session is active | Windows today | Linux today |
| --- | --- | --- |
| `stop`, `shutdown`, Desktop Disconnect | Released (intended) | Released (intended) |
| Service stop (SCM, `systemctl stop`) | Released | Released |
| Normal OS shutdown or restart | Released, then traffic leaves outside the VPN after boot until the user connects | Same |
| Core update or repair | Released (the proposed ADR 0041 keeps it for clients that request it) | Released (ADR 0041 is Windows only) |
| Crash, forced termination, failed listener | Filters stay, `KillSwitch: "residual"` | nft table stays until reboot |
| Power loss, or crash followed by reboot | Persistent WFP filters stay, `residual` after boot | **Released**: nftables rules are not persisted |
| Early boot before the filtering engine starts | Not covered | Not covered |

The documented limitation is therefore the normal, healthy path: a user who
connects, shuts the laptop down and opens it the next morning is unprotected
from boot until Desktop or the user connects again. A leftover block appears
only after a crash or power loss, and then as an error state that needs
`recover`.

Three facts constrain any fix:

1. **Nobody is there to connect at boot.** Desktop auto-connect runs after the
   user signs in and the GUI starts. Machine traffic before sign-in (updates,
   sync clients, time and telemetry services) leaves first, and a machine that
   nobody signs in to never connects.
2. **The service should not read the user's profile by path.** Today the
   service opens the path that `start` names with its own SYSTEM or root
   rights. A privileged process should not open paths a caller chose, and the
   planned fix is that the client supplies the profile. At boot there is also
   no caller whose rights the service could use, and user files may be
   encrypted (EFS), on a network drive or in a profile that is not loaded.
3. **The kill switch stays optional per profile.** Direct routing and
   georouting rules behave differently with it, so it cannot become mandatory
   (ADR 0039, alternatives).

## Decision

### Summary

1. **A persistent session.** A packet VPN session started with `persist` is
   persistent: the service records the user's intent durably and restores the
   session by itself after boot, an update or a repair, before anyone signs
   in. The Core contract is a per-start `persist` flag. *Decided Q5:* this
   applies to profiles with and without the kill switch.
2. **The kill switch keeps its meaning.** With the kill switch, protection is
   kept on every exit that is not an explicit Disconnect and the network is
   blocked from early boot until the restored session connects. Without it,
   nothing is blocked: traffic leaves outside the VPN while the session
   connects, reconnects or has failed, exactly as for a kill switch off
   session today. *Decided Q1:* Desktop makes every kill switch connection
   persistent until an explicit Disconnect; persistence without the kill
   switch is an explicit choice of the user. The CLI stays opt-in
   (`-persist`).
3. **Disconnect is the only off switch.** `stop`, `shutdown` and the Desktop
   Disconnect button clear the record and release protection, as today.
   Everything else (service stop, OS shutdown, update, repair, crash, power
   loss) keeps the record, and with the kill switch the block. Removing the
   Desktop package counts as Disconnect.
4. **The service owns a copy of the profile.** At Connect the client sends the
   profile and every file it references as one bundle. The service loads it
   from memory and never opens a path that a client chose; for a persistent
   session it also stores the bundle in a protected service directory, while
   other bundles stay in memory only. *Decided Q4:* bundles are used for every
   connection, not only persistent ones.
5. **Blocked from the first moment of boot (kill switch).** Windows keeps the
   persistent WFP filters it already has and adds boot-time filters for the
   window before the filtering engine starts. Linux installs the same nftables
   table from an early boot unit, before the network is configured.
6. **Restore never gives up on its own.** A restored session retries in the
   ADR 0039 cycles until it connects or the user disconnects. With the kill
   switch the network stays blocked meanwhile (*decided Q2*); without it
   the network stays open.
7. **Recovery needs no network.** A broken GUI is bypassed with
   `bimeron stop`; a broken service with an elevated, persistence-aware
   `recover` from the core store; package removal restores normal access.
8. **Additive contract.** IPC stays version 1, with new capabilities, a
   two-phase `start` that carries a bundle and new Session fields. Old clients
   keep today's behavior.

### Terms

- **Persistent session**: a run with `persist` accepted. It continues across
  service processes and boots until an explicit Disconnect.
- **Persistence record**: the service-owned, durable statement "owner O
  connected profile P with bundle digest D and has not disconnected". Writing
  it is the commit point of a persistent Connect; removing it is the commit
  point of Disconnect. Its presence makes leftover filters intended rather
  than residual.
- **Bundle**: the profile bytes and the bytes of every file the profile
  references, produced by the Core CLI running as the user.
- **Retained exit**: the service process ends but keeps the record and, for a
  kill switch session, leaves protection installed for the next instance to
  take over: on Windows in the no-tunnel form (the full ADR 0039 set without
  the tunnel interface permit), on Linux as it is, because the table matches
  the tunnel by name. ADR 0039 already has the primitive
  (`Engine.Abandon`); ADR 0041 uses it once for an update; this record uses it
  for every non-Disconnect exit of a persistent session.
- **Restore**: the start of a persistent session by the service itself, from
  the stored bundle, without a client request.
- **Boot guard**: for a kill switch record, the protection that is in force
  from early boot until the restored run installs its own: boot-time and
  persistent WFP filters on Windows, the early nftables unit on Linux. Records
  without the kill switch have no boot guard.

### What the user sees

- Connect with a kill switch profile (*decided Q1*): "Protected until you
  disconnect, also after a restart". This happens automatically: the
  "keep connected after restart" control is shown on and locked for kill
  switch profiles. The behavior of ADR 0039 applies while the computer runs.
  Desktop explains the change once, at the first such Connect after the
  upgrade, including that the block applies to every account on the computer.
- Restart or shutdown while connected: after boot the service connects the
  same profile before anyone signs in. Until it connects, internet access is
  blocked for every application and every user of the computer, except the
  profile's `direct` destinations.
- Disconnect: normal internet access returns, and the next boot is normal.
- A profile without the kill switch, when the user has explicitly chosen to
  keep the VPN after a restart (*decided Q5*): after boot the service connects
  it before anyone signs in, also after an update or repair, until the user
  disconnects. Nothing is blocked. Until the session connects, and while it
  reconnects or has failed, traffic leaves outside the VPN, as for any kill
  switch off session.

### Persistence objects

| | Windows | Linux |
| --- | --- | --- |
| Private directory | `%ProgramFiles%\Bimeron Core\persist\`: protected DACL, owner SYSTEM, SYSTEM and Administrators only. Outside the core store and outside the ADR 0040 member set | Record and guard: `/etc/bimeron/persist/`, root, 0700. Bundle: `/var/lib/bimeron/persist/`, root, 0700 |
| Record | `record.json` | `/etc/bimeron/persist/record.json`, 0600 |
| Bundle | `bundle-<sha256>`, encrypted with DPAPI in the SYSTEM user scope (no `CRYPTPROTECT_LOCAL_MACHINE`) | `bundle-<sha256>`, 0600 |
| Network state for restore | Existing owned WFP and NRPT markers | The cleanup journal of a persistent session, including the original DNS configuration and the boot ID, kept durably in `/var/lib/bimeron/persist/` and written there before each network change, because `/run/bimeron/state.json` is lost on power loss |
| Boot guard (kill switch records only) | Boot-time and persistent WFP filters (BFE store) | `/etc/bimeron/persist/guard.nft`, 0600: the rendered ADR 0039 ruleset |
| Public copy, no secrets | Protected HKLM value `SOFTWARE\Bimeron\Core\PersistentSession`, readable by Users | `/etc/bimeron/persist.json`, root, 0644 |

- The record holds a format version, the owner SID or UID, the profile ID and
  name, the bundle digest, whether the profile enables the kill switch, and the
  creation time. It holds no secrets; the bundle does. The kill switch flag is
  derived by the service from the parsed bundle, never taken from the client.
- The guard and the record live in `/etc` on Linux, so the early unit needs
  only the root file system and reads files with the ordinary `etc_t` label
  under SELinux. The bundle, which the early unit never reads, stays in
  `/var/lib`.
- The directories follow the ADR 0040 rules for privileged objects:
  handle-relative creation and opening, no reparse points or symlinks,
  explicit owner and protected DACL at creation, write to a temporary name,
  flush, then rename. Program Files is used for the reason ADR 0040 gives:
  `%ProgramData%` lets Users pre-create subdirectories. Profiles never live in
  the core store `versions/`.
- The public copy lets Desktop explain the state while the service is stopped
  or broken: a blocked network for a kill switch record, a VPN that does not
  connect for a record without it. It holds `enabled`, `kill_switch`, the
  profile ID and name, and the time.

### Ordering and reconciliation

One rule covers every crash point: objects that are harmless without a record
are written before the record and removed after it, and the service reconciles
leftovers whenever it starts. The invariant is that the record names the
session that owns protection, or the session the owner last asked for.

- **Persistent Connect**, under the engine's lifecycle lock:
  1. every admission check of `start` (`kill_switch_held`,
     `session_already_running`, a maintenance seal,
     `kill_switch_pending_run_recover` and the others), so a start that will
     be rejected never writes anything;
  2. the new bundle, and, for a kill switch profile when no record exists yet,
     the boot guard (`guard.nft`, boot-time filters). Without a record they
     are nearly harmless: the guard unit requires the record, and
     reconciliation removes boot-time filters at the next service start; at
     worst they block the few seconds before BFE on the next boot;
  3. the record (atomic replace, the commit point). When a record already
     existed, the boot guard is rewritten for the new profile right after
     this step, so the guard always matches the record that survives;
  4. the handover or the run's early arm, then the public copy. The previous
     bundle is deleted only after the new run has armed.

  If step 2 or 3 fails, `start` fails with `persist_store_failed`, the boot
  guard is re-rendered from the record that survives (if any), and an earlier
  session keeps running untouched. Once the record is committed, it
  stands for the user's intent: if step 4 fails (for example the previous
  session's cleanup fails during a handover, or the early arm fails), `start`
  returns the error, and the service keeps a persistent run for the new
  record in held `failed` with the failure code and an active Session. The
  same holds for every failure before a restored run's first attempt, such
  as acquiring the session lock: a persistent run stays active. The record is
  written at Connect, not at the first `connected` (see Q2).
- **Disconnect**: record removal (the commit point) → release of the filters
  as on a normal stop → boot guard → public copy → bundle. If removing the
  record fails, nothing is released: `stop` fails with `persist_clear_failed`
  and the session stays as it was. Protection is never released while the
  record survives.
- **Changing persistence of a running session**: `persist` has three values.
  `true` writes the record and an explicit `false` removes it. Absent keeps
  the current state only for a `start` of the running profile (the same
  profile ID); for any other `start` it means `false`, so the CLI stays
  opt-in and never makes a session persistent by inheritance. A `start` of
  the running profile with the same bundle digest and a different explicit
  value writes or removes the record in place and leaves the session
  untouched; the change follows the Connect or
  Disconnect order above for the bundle and the boot guard. This covers
  toggling the control for a profile without the kill switch. A kill switch
  session that an older client started by path has no bundle digest, so after
  a Desktop upgrade it becomes persistent through a handover to a bundle start
  of the same profile ID, which leaves no gap.
- **Reconciliation at service start**:
  - No record: delete boot-time filters, `guard.nft`, the public copy and
    every `bundle-*`, and finish the network cleanup from the persisted Linux
    journal if one is left (for example after a power loss during
    Disconnect). Persistent and residual filters keep their ADR 0039 meaning:
    residual until a kill switch start or `recover`.
  - A record: restore. Make the boot guard and the public copy match it (no
    boot guard for a record without the kill switch) and delete bundles that
    it does not name.
  - A record with an unknown format version: fail closed. The service creates
    a run in held `failed` with `persistent_record_unsupported`, keeps any
    filters, and `stop` clears it. The kill switch flag of an unreadable
    record is unknown, so leftover filters are kept.
  - A record whose owner differs from the service's control owner (for example
    after a reinstall for another user): clear it as on Disconnect and report
    `persistence_cleared`. It is never adopted.

### Delivering the profile: a client-supplied bundle

The service stops opening caller-chosen paths. A privileged process then no
longer reads or uses files on behalf of a caller who could not read them,
opens network or device paths, or follows links.

1. The client runs the CLI it already trusts, as the user:
   `bimeron profile bundle <profile.conf>`. The CLI parses the profile with
   the normal parser, reads every referenced file as the user and writes a
   canonical bundle to stdout. The CLI owns the format; Desktop treats it as
   opaque bytes.
2. Referenced files: `[AccessKey] File`, `IdentityFile`, `KnownHostsFile`,
   `CAFile`, `GeoIPFile`, `GeoSiteFile`, and the URI options `ca=`,
   `identity=` and `known_hosts=` in `ssh://` and `masque://` values,
   including those inside a key file. The bundle rewrites each reference to a
   member. The CLI, which runs as the user, expands `~` against the user's own
   home, so profiles such as `identity=~/.ssh/...` keep working. SSH agents
   and default keys are refused, as in service mode today. The service rejects
   any path left in a bundle.
3. **Profile identity.** The CLI computes the profile ID exactly as today, from
   the normalized absolute path, and stores it in the bundle with the
   `[Profile] Name`. The ID is a label asserted by the owner's client: it only
   decides which of the owner's own sessions a `start` matches. The service
   computes the bundle digest itself. CONTROL.MD's "Profile identity is the
   profile file" becomes "the profile ID in the bundle, or the path for
   path-based starts".
4. Per-kind size limits: profile and key file 64 KiB, identity 64 KiB, CA and
   known_hosts 1 MiB, each geodata file 64 MiB. Kill switch profiles accept
   only CIDR rules (`kill_switch_cidr_only`), so their bundles never carry
   geodata and stay at about 2.2 MiB or less. Bundles of profiles without the
   kill switch may carry geodata, also when persistent; the stored copy then
   takes up to about 130 MiB.
5. The service parses the bundle with the in-memory loaders
   (`config.ParseDataWithGeoData`, `core.LoadConfigDataWithGeoData`) and passes
   key material to SSH and MASQUE as bytes. SSH known_hosts verification parses
   the received bytes and never reopens a path.
6. `ssconf` keys stay dynamic: the bundle contains the `ssconf` URL, and the
   service fetches it on every attempt through the core's own network path, as
   today.
7. **Format versions.** The bundle and the record carry a format number. The
   capability advertises the bundle formats a service reads
   (`profile_bundle: [1]`), and the CLI writes the one requested
   (`bimeron profile bundle -format N`), because the CLI that Desktop selects
   can be newer than the service (ADR 0040). Newer images read every older
   format. A new record or bundle format is written only after the ADR 0040
   switch that introduces it is committed, so a backward run never meets a
   format it cannot read.

*Decided Q4 extension:* bundles are used for every connection. Path-based
`start` (`config`) stays only for clients that do not use bundles yet (older
Desktop releases), and is removed in a later release after Desktop has
migrated. Until then the service still opens the path of such a start.
Persistence requires a bundle.

### Retained exits

While a record exists, every exit that is not an explicit Disconnect is a
retained exit:

- SCM stop, preshutdown and shutdown on Windows; SIGTERM, SIGHUP and SIGINT
  of the service on Linux (`systemctl stop`, system shutdown, an
  administrator's signal). LINUX.MD lists them as releases today; for a
  persistent session they keep the record and the table;
- the stop step of `service update`, the ADR 0040 maintenance session switch,
  repair and their undo paths;
- a maintenance seal, a failed control listener, a panic boundary or any other
  abandonment.

For a kill switch session on Windows, a retained exit first replaces the
filters, in one transaction, with the no-tunnel form: the full ADR 0039 set
without the tunnel interface permit. On Linux the table already matches the
tunnel by name and permits the core by socket mark, so it stays as it is.
Then the exit closes the session and removes routes, DNS settings and the
adapter as on a normal stop. It keeps only the packet filters. If the
replacement fails, the existing filters stay. A crash, a forced termination or
a power loss skips all of this: the filters that the run installed stay,
including the Windows interface permit for an adapter that no longer exists,
until the next instance replaces them.

A retained exit that completes its cleanup exits with code 0. While a record
exists, Bimeron's own filters are intended, so they never count as missing
cleanup proof: the update stop check, repair inspection and ADR 0040
reconciliation treat a clean exit with filters and a record as clean.

The cleanup is the same as on a normal stop, but the race against the OS
shutdown timeout becomes harmless: protection is already in its boot form
before cleanup starts.

For a session without the kill switch, a retained exit is a normal stop that
keeps the record. No filters are involved, and traffic leaves outside the VPN
from the moment the session closes until the next instance connects.

With a record, the ADR 0041 `prepare_update` request is harmless and
updaters can send it unconditionally: the stop is a retained exit in any
case, the new service restores the session itself, and the ADR 0041 update
record, if written, is deleted when the restored run starts, so Desktop sees
an active session instead of residual protection and does not restart the
profile. Without a record, exits behave exactly as today (ADR 0039),
including the ADR 0041 one-shot hold.

### Service start at boot

*Decided Q6:* a persistence-capable service is registered for automatic start
whenever it is installed or switched, and nothing changes the registration at
runtime. Records with and without the kill switch both rely on this.

- Windows: automatic start (not delayed) and a dependency on `BFE`. They are
  set by `service install` and by the first persistence-capable switch, as a
  journaled registration change under the ADR 0040 rules (including the
  registry flush of R5).
- Linux: `bimeron-core.service` is enabled, and `bimeron-core-guard.service`
  is installed and enabled. Both units are journaled registration objects
  under ADR 0040.
- Without a record the service starts idle, as `-automatic` does today, and
  does not connect.

The rejected alternative, switching the start type only while a record
exists, keeps manual-start installations but has the service rewrite its own
registration. That races the ADR 0040 switch journal, which compares the full
registration before every step and would abort or undo the change.

### Boot without the kill switch

A record without the kill switch has no boot guard. The service starts at its
normal place in the boot order (Windows automatic start, Linux
`bimeron-core.service` after `network-online.target`), reads the record and
restores the session. Traffic before that point, and while the session
connects, leaves outside the VPN as for any kill switch off session. The
sections below apply to kill switch records only.

### Boot: Windows

1. **Before BFE starts.** Boot-time filters (`FWPM_FILTER_FLAG_BOOTTIME`) are
   enforced from the start of `tcpip.sys` until the Base Filtering Engine
   starts. When a kill switch record is written, Core installs a boot-time
   set: permit loopback, DHCP and IPv6 neighbor discovery; block other
   outbound and inbound connections. No core exception is needed because no
   core process runs before BFE. Boot-time filters cannot also be persistent,
   so they are separate objects. Microsoft's pages describe their fate at BFE
   start differently ("disabled" on the WFP Operation page, "removed when BFE
   finishes initialization" on the Object Management page). Reconciliation
   therefore reinstalls the set at every service start while a kill switch
   record exists, and Disconnect and `recover` delete it.
   - They use their own sublayer under the Bimeron provider. Today's `arm`
     replaces every rule in the kill switch sublayer, and would otherwise
     delete the boot-time set at the first arm of a restored run. They keep the
     same provider, because the atomic handoff applies to a provider that has
     both kinds of filters.
   - WFP refuses to delete an object while others reference it. Today's
     release deletes the kill switch rules, its sublayer and the provider in
     one transaction, which would fail while boot-time objects reference the
     provider. Release therefore removes the boot-time filters and both
     sublayers together with the provider in one transaction.
   - *Feasibility check during implementation, on a test VM:* that the ALE
     connect and receive-accept layers accept boot-time filters; that
     boot-time filters may use a custom provider and sublayer; whether they
     survive BFE start and a reboot or must be added again each time; that a
     boot-time filter added while BFE runs is not enforced until the next boot
     (otherwise its block, in its own sublayer, would override the run's
     permits); and that the handoff to persistent filters leaves no gap. The
     WFP Operation page describes the transition as atomic for a provider that
     has both kinds of filters. If a check fails, this window stays documented
     as uncovered, as it is today.
2. **BFE start.** BFE loads the persistent filters left by the retained exit
   (or by a crash) in the no-tunnel form. The Bimeron provider has no
   associated service name. The WFP documentation ties the enabled state of a
   provider's filters at BFE start to its associated service, and the Object
   Management page and the `FWPM_FILTER_FLAG_DISABLED` description word this
   differently. The record relies on the October 8, 2026 reboot check, which
   confirmed that the current provider's persistent filters are enforced after
   reboot. Acceptance repeats the check.
3. **Service start.** The service reads the record, verifies the bundle digest
   and restores the session. The run's early arm replaces the persistent
   filters transactionally, so there is no gap.

### Boot: Linux

nftables rules live only in the kernel and vanish on reboot. The guard unit:

```ini
[Unit]
Description=Bimeron Core early network block
DefaultDependencies=no
Wants=network-pre.target
Before=network-pre.target
After=local-fs.target nftables.service firewalld.service ufw.service netfilter-persistent.service
ConditionPathExists=/etc/bimeron/persist/record.json
ConditionPathExists=/etc/bimeron/persist/guard.nft
ConditionPathExists=/etc/systemd/system/bimeron-core.service
ConditionKernelCommandLine=!bimeron.persist=off

[Service]
Type=oneshot
ExecStart=nft -f /etc/bimeron/persist/guard.nft

[Install]
WantedBy=sysinit.target
```

- All conditions must hold, so a leftover `guard.nft` without a record never
  blocks a boot. Requiring the daemon's unit file keeps a boot open after an
  older `service uninstall`, which deletes that unit but not the guard:
  without a service nothing could restore the session. The unit file is used
  rather than the executable, because ADR 0040 moves the executable at the
  first store-era switch. A residual risk remains: an older reinstall after an
  older uninstall brings the unit back with a daemon that does not know about
  persistence; ADR 0040 repair heals such an installation.
- `ExecStart=` names `nft` without a path; systemd 239 and later look it up in
  a fixed search path, so the unit stays valid if `nft` is installed after
  Bimeron.
- The unit pulls in nothing except `network-pre.target`: systemd checks
  conditions only when the job runs, after the jobs it pulls in were queued,
  so a `Wants=` on the daemon would start it at every boot regardless of the
  record. The daemon starts because its own unit is enabled (Q6).
- `guard.nft` is the ADR 0039 ruleset (tunnel matched by name, core sockets
  by mark) that the service renders whenever the persistent session starts
  or its profile changes. At boot no tunnel exists, so only loopback, DHCP,
  neighbor discovery and `direct` destinations pass. It must load whether or
  not the table exists. It uses the `add table`, `delete table`, recreate
  idiom, because `destroy table` needs nftables 1.0.8 and Ubuntu 22.04 ships
  1.0.2.
- Network managers (NetworkManager, systemd-networkd, ifupdown) are ordered
  after `network-pre.target`, so the block is in place before interfaces get
  addresses. The `After=` list makes distribution firewall loaders that flush
  the ruleset at boot run first.
- If the guard fails, networking still proceeds. The daemon detects this
  (record present, table absent at start), installs the table at once and
  reports `boot_guard_failed`.
- While a persistent run is active, the daemon checks every 5 seconds that its
  table is present and reinstalls it if another tool removed it
  (`kill_switch_reinstalled`). Up to 5 seconds of traffic can leave after an
  external flush; implementation may use `nft monitor` to shorten this. An
  administrator can still change the firewall, as today.
- The residual check and `recover` recognize an owned `bimeron_core` table
  (by its comment) even without the `/run` journal. Today both rely on the
  journal, which a reboot removes.
- `bimeron.persist=off` on the kernel command line is an offline escape hatch:
  the guard does not load and the daemon does not restore for that boot. It
  shows the record as a run in held `failed` with `persistence_suspended`, so
  that a guarded `stop` clears it. It needs boot loader access, which already
  implies full control of the machine, and it is unavailable where the command
  line is fixed (unified kernel images, signed command lines). It is a
  convenience, not the recovery path.
- Networking configured in the initramfs (network root file systems) or by
  units ordered before `network-pre.target` is outside the claimed protection.

### Restore and the recovery policy

- Before its first attempt, a restore runs the filter-preserving network
  cleanup itself: owned routes, DNS settings and leftover adapters from an
  unclean exit are removed, any filters and the record stay. On Linux it uses
  the durable journal in `/var/lib/bimeron/persist/`, which is written before
  each network change, so the original DNS configuration survives a power
  loss; today `Guard` refuses to run while that cleanup is pending. When the
  journal comes from an earlier boot (the boot ID differs):
  - if the DNS file still holds the bytes Core installed, the original is
    restored;
  - if it differs from both the original and Core's bytes, the system has
    regenerated it since then, and the cleanup adopts the current file instead
    of refusing because it "changed externally", as
    `recover --keep-current-dns` does today.

  In the same boot the normal checks apply. This is the one automatic cleanup
  Core performs, and it never opens the network. GUI_INTEGRATION.MD's "do not
  run `recover` automatically" still applies to clients.
- A restore starts before the control pipe and the readiness pipe accept
  mutating requests, so a client never sees a service with a record but no
  Session.
- A restored run gets a new `Session.id` and `Session.restored: true`. It
  continues a run that the user started, so it uses the ADR 0039 policy for
  loss of an established session from its first attempt: cycles of 10 attempts
  and 60 second waits, indefinitely, with the usual early wake on
  `reconnect_now`, network change and resume. Failures that end an initial
  connection (rejected key, TLS rejection, SSH authentication) are retried in
  the same cycles and keep their specific `LastError`. With the kill switch the
  network stays blocked throughout until an explicit Disconnect (*decided Q2*;
  the rejected alternative was giving up after a time limit and opening the
  network). Without it the same cycles run with the network open.
- A fresh Connect keeps the ADR 0039 initial policy: bounded initial attempts,
  then `failed` with the Retry button. The user is present and sees the error.
  A persistent run then stays active in `failed` even without the kill switch
  (ADR 0039 ends such a run), so that the session and the record agree:
  Disconnect clears the record, and a restart restores the run, which then
  cycles, even if the profile never connected.
  - `reconnect_now` restarts the attempts of any persistent run in `failed`,
    not only one that holds protection. Desktop recognizes such a run by
    `Session.active` and `Session.persistent` with state `failed`, and offers
    Retry for it.
  - A `start` replaces a persistent run in `failed`, subject to the kill switch
    admission rules: a profile without the kill switch cannot replace a run
    that holds protection. The control layer's guarded `start` admission is
    amended to match (see Changed in the contract outline).
  - Without the kill switch nothing is blocked and `Status.KillSwitch` stays
    omitted.
  - The held states `persistent_record_unsupported` and
    `persistence_suspended` have nothing to retry: `reconnect_now` returns
    `reconnect_not_pending`, a `start` replaces them under the same admission
    rules, and `stop` clears the record. `Status.KillSwitch` reports `holding`
    while Bimeron filters are installed and is omitted otherwise.
- Faults that require explicit recovery (`_run_recover` codes) do not end a
  persistent run: it stays active in `failed` with the code, any filters and
  the record stay, and `stop` works as usual. The same applies when the bundle
  is missing or corrupt (`persistent_profile_unavailable`). The service is
  never idle while a record exists.
- Interactive SSH authentication works unchanged: the restored run publishes
  its challenge and waits for the owner's Desktop after sign-in; an expired
  challenge fails the attempt and the next cycle asks again. With the kill
  switch the network stays blocked until the user answers.
- Security floors never block restore (ADR 0040, its decision Q4).

### Turning it off

- **Disconnect** (`stop` or `shutdown` from the owner, Desktop Disconnect,
  `bimeron stop`, the Desktop "stop Core on exit" preference on an explicit
  Quit) follows the Disconnect order above. If releasing the filters fails
  after the record is gone, the existing `cleanup_failed_run_recover` path
  applies. On Windows the filters then stay as residual; on Linux the table
  stays until `recover` or reboot, and the next boot is normal because the
  guard needs the record.
- **The owner does not need administrator rights to disconnect**, also when
  the service restored the session at boot. The exception is unchanged from
  today: when network cleanup itself fails (`cleanup_failed_run_recover`),
  the leftovers need `recover`.
- **Switching profiles** follows ADR 0039: a `start` with another kill switch
  profile hands over without a gap and replaces the record atomically. The
  record follows the running session: a handover with `persist: true` writes
  the new record, and any other handover removes the record once the new run
  has armed, followed by the boot guard, as in the Disconnect order. Without
  the kill
  switch there is no handover: Desktop sends `stop`, which clears the record,
  then `start` with `persist`, which writes a new one, as it switches such
  profiles today.
- **Editing the active profile**: for kill switch bundle starts, a `start` with
  the same profile ID and a different bundle digest hands over without a gap.
  ADR 0039 required `stop` and `start` for edits, which opened a short gap; the
  digest makes the change detectable. The same profile and digest return
  `session_already_running` while connecting, connected or reconnecting; in
  held `failed`, a `start` hands over as ADR 0039 already specifies. Edits of a
  profile without the kill switch keep using `stop` and `start`.

### Recovery when the network is blocked and Bimeron is broken

A record without the kill switch never blocks the network; a broken service
then only means that the VPN does not connect, and Desktop shows that from the
public copy. The table applies to kill switch records.

| Situation | Path |
| --- | --- |
| Desktop broken, service fine | `bimeron stop` from any terminal of the owner. No elevation, no network |
| Service stopped or crashing, filters in place | Desktop reads the public copy and shows "Internet is blocked because Bimeron Core is not running" with Start service, Repair and Turn off protection. Each needs elevation. Turn off is a maintenance-session operation (ADR 0040 entry points): a persistence-aware `recover` |
| No working GUI, administrator present | `bimeron service stop`, then `bimeron recover`, run from the newest committed core store version (`%ProgramFiles%\Bimeron Core\store\versions\<version>\bimeron.exe`, `/usr/local/lib/bimeron/store/versions/<version>/bimeron`). Under the "never below active" rule that binary knows the record format. `recover` clears the record, the public copy, boot-time filters and the Linux guard, and needs no network |
| Linux, nothing works | Boot once with `bimeron.persist=off`, then `bimeron stop` if the service runs, or `recover` if it is broken |
| Package removal | Clears persistence (below) |

A `recover` from a Core older than persistence support does not help: on
Windows its single transaction fails because the boot-time objects still
reference the provider, so it removes nothing; on Linux it ignores the record
and the guard. Likewise, an older `service uninstall` leaves the persistence
objects behind; on Windows the filters then stay with no service to restore
the session, while on Linux the guard does not load without the daemon's
unit file. The documentation says to use the current tools. A last-resort
procedure for a Windows machine whose Core files are all damaged is written
and validated on a test VM during implementation; it may not depend on
downloading anything.

### Interactions

**Sleep and resume.** Unchanged. The service keeps running and the session
recovers as in ADR 0039. Hibernation behaves like sleep. Windows Fast Startup
either hibernates the service (the session resumes) or stops it (a retained
exit). Both are protected, and acceptance covers Shut down and Restart.

**Updates (ADR 0041 and ADR 0040).**

- With a record, the update's service stop is a retained exit without any
  client flag, and the new service restores the session itself. The ADR 0041
  one-shot hold stays for kill switch sessions without a record, which only
  clients that do not send `persist` create (older Desktop releases, the CLI
  without `-persist`).
- Desktop does not send `start` after an update while `Session.persistent` is
  true; it waits for the restored session. A `start` with the same digest
  returns `session_already_running`, which Desktop treats as success.
- Update success checks accept a restored session (`connecting`,
  `reconnecting` or `connected`, with `KillSwitch` `holding` or `active` for a
  kill switch record) instead of a clean `disconnected` status. A restored run
  cycles from its first attempt, so it waits in `reconnecting` while the
  server is unreachable; that is not an update failure. Any `failed` state,
  including `_run_recover` and `persistent_*` codes, is.
- A record without the kill switch is restored after an update in the same
  way. There is no protection to keep, so ADR 0041 does not apply to it, and
  traffic leaves outside the VPN between the old session closing and the new
  one connecting.
- ADR 0040 amendments:
  - The switch `stop` step and the undo-side stop are retained exits; the
    `start` step restores. A retained exit with code 0 and Bimeron filters
    present, while a record exists, satisfies the stop step's cleanup proof.
  - Every network cleanup that the maintenance broker plans while a record
    exists (update, repair, reconciliation, and "Network cleanup before
    starting the old image") is the filter-preserving mode (routes and DNS
    only), never the full `Recover`. It does not open the network, so it
    needs no network-recovery consent. A full `Recover` happens only through
    Turn off protection, or in the consented backward run below. Without a
    record the rules are unchanged.
  - A backward run to an image without persistence support would show the
    filters as residual and never restore. With network-recovery consent, the
    undo first clears persistence as on Disconnect and reports
    `persistence_cleared` in the session result. Without that consent it
    leaves the old image stopped and closes with `rollback-incomplete`, as ADR
    0040 already does when cleanup needs consent. Store-era version rules
    otherwise prevent downgrades.
  - The `register` step no longer changes only `BinaryPathName`: the first
    persistence-capable switch also sets automatic start and the BFE
    dependency (Q6). The registration and the Linux guard unit are journaled
    registration objects.
  - The package removal action below is an additional elevated entry point,
    with the same self-check as the installer action.

**Repair.** Same as updates. Repair inspection treats Bimeron filters with a
record as intended, not as pending cleanup. Desktop's guided repair never runs
a full `recover` while a record exists, unless the user chose Turn off
protection.

**Package removal and service uninstall.**

- Under ADR 0040, removing the Desktop package leaves the service and the core
  store installed. Persistence must not outlive the GUI that explains it, so
  package removal sends `stop` to the service as SYSTEM or root, which the
  control endpoints already admit. The service then idles; uninstalling it
  stays a separate, explicit action.
  - MSI: a deferred action scheduled before `RemoveFiles`, conditioned on a
    real removal (`REMOVE="ALL" AND NOT UPGRADINGPRODUCTCODE`), so the old
    product's uninstall during a major upgrade does not disconnect.
  - DEB: `prerm remove` only, not `upgrade` or `deconfigure`.
- If the service does not answer, the action runs the persistence-aware
  `recover` from the newest committed store version. This is an amendment to
  the ADR 0040 installer-action rules and entry points.
- `service uninstall` also clears persistence and removes the Linux guard
  unit, the boot-time filters and every persistence object. An interrupted
  uninstall is resumed by running it again, as today. Removing files by hand
  is unsupported and leaves the block.

**Multiple users.** The service has one control owner. Persistence is
machine-wide, like the system VPN itself: once restored, the session carries
every account's traffic, and with the kill switch every account is blocked
until it connects. Only the owner (through the pipe) or an administrator
(`recover`) can turn it off. Other users' Desktop instances cannot control
the service; they can read the public copy and explain the state. Fast user
switching, sign-out and remote sessions do not affect the service-owned
session. A restored session runs before and without any sign-in.
Desktop exits caused by sign-out or OS shutdown never send `stop` or
`shutdown`; "stop Core on exit" applies to an explicit Quit only, and uses
IPC, not an SCM stop (which would be a retained exit).

**Captive portals.** Hotel and airport networks that require a sign-in page
before granting internet access cannot be reached through the VPN. Without
the kill switch the sign-in page stays reachable outside the VPN while the
session connects, so this concerns kill switch records only.

*Decided Q3:* no exception in the first version. The user presses Disconnect,
signs in and presses Connect again. To make this discoverable, Core reports a
likely captive portal and Desktop shows the hint:

- Core uses only traffic it already sends to connect, and sends no extra
  probe outside the VPN. The main sign is that the server's TCP or TLS
  transport receives a plain HTTP response or redirect, or a certificate for
  another name, instead of its handshake. Bootstrap DNS answering the server
  name with a private, link-local or shared-address-space address counts only
  together with a failed handshake, because some servers legitimately use such
  addresses.
- Status gains `NetworkHint: "captive_portal"` while these signs persist on the
  current network, cleared on `connected` or a network change, and the event
  `captive_portal_suspected` is published once per network.
- Desktop shows: this network seems to need a sign-in page; press Disconnect,
  sign in in the browser, then Connect again. The hint never disconnects by
  itself.

Other approaches are recorded for a later decision in issue #242: a 5-minute
pause for the whole computer, a temporary loopback proxy in Core for a
dedicated sign-in window, and a browser limited to the local network. An
automatic browser exception is rejected: traffic would leave outside the VPN
without a user action.

**LAN access.** Unchanged from the kill switch: only `direct` CIDRs of the
profile are reachable while blocked; DNS ports are blocked outside the tunnel
even to `direct` resolvers. Printers and NAS need explicit `direct` rules. The
boot-time set on Windows blocks the LAN for the few seconds before BFE starts.
A Desktop shortcut that adds private ranges as `direct` rules is a separate
Desktop decision.

**Domain-joined machines.** With the kill switch, until the VPN connects,
domain controller discovery and boot-time Group Policy fail, because DNS
outside the tunnel is blocked even to `direct` resolvers. Sign-in uses cached
credentials. Such machines need a VPN path to their domain controllers; this
record makes no exception.

**Desktop while blocked.** With the kill switch, Desktop cannot download
updates or geodata until the restored session connects. The profile list stays
usable.

**Deleting the active profile in Desktop.** The service keeps its own copy, so
the session continues. Desktop shows the persistent profile by name from
Status and offers Disconnect; it does not silently stop the session.

**Other platforms and backends.** Only the installed Windows service and the
Linux systemd service support persistence. Console daemons, foreground
`bimeron connect`, proxy mode, native IKEv2, macOS, Android and Apple reject
`persist`. Proxy mode is left out because it carries no system traffic and its
local listener would then run before any sign-in; it can be added later.

**Clock.** With the kill switch, time synchronization is blocked until the VPN
connects. A machine whose clock is far off fails TLS validation and stays
blocked; `LastError` names the TLS failure and Desktop shows it. No NTP
exception is proposed.

**Network boot.** Machines whose system disk depends on network storage are
out of scope; the boot guard may block it.

### IPC and Desktop contract outline

Normative text goes to CONTROL.MD, KILLSWITCH.MD, LINUX.MD, SERVICE.MD and
GUI_INTEGRATION.MD when this record is accepted. The outline:

**Capabilities** (hello and capabilities, additive):

- `profile_bundle` (array of integers): the bundle formats that `start`
  accepts, for example `[1]`.
- `persistent_session: true`: `start` accepts `persist`. Only the installed
  service reports it.

**Two-phase start with a bundle.** CONTROL.MD's transport rule ("one request,
one LF-terminated line") gains one explicit exception:

1. The client sends the request line:

   ```json
   {"version":1,"id":"start-1","command":"start","instance":"<hello.instance>","bundle":{"size":20480,"sha256":"<hex>"},"persist":true}
   ```

2. The service validates the line, the guards and the declared size, then
   answers with one line, `{"version":1,"id":"start-1","instance":"<instance>","continue":true}`,
   or a normal error response, after which the connection closes.
3. After `continue`, the client sends exactly `size` bytes. The service reads
   and hashes them outside the mutating-command lock, with a deadline scaled
   to the size. A body that is short, long or has another digest is rejected.
4. The service then takes the command lock, checks the guards and admission
   again, and sends the ordinary `start` response.

Reading outside the lock means an upload never blocks `bimeron stop`. One
upload runs at a time; a second gets `upload_in_progress`. An upload is
pending until its `start` holds the command lock; `stop` and `shutdown`
cancel a pending upload, whose `start` then returns `start_cancelled`, so a
Connect followed quickly by Disconnect never starts a session after the
Disconnect. `bundle` and `config` are mutually exclusive, and `persist` with
`config` is rejected; both return `invalid_request`.

`persist` is optional and has three values: `true` writes the record,
`false` removes it, and absent keeps the current persistence only for a
`start` of the running profile; for any other `start` absent means `false`.

Errors (catalog codes, kind `control`): `bundle_invalid`, `bundle_too_large`,
`upload_in_progress`, `start_cancelled`, `persist_unsupported_profile` (the
profile is not a packet profile in VPN mode, for example proxy mode or native
IKEv2), `persist_requires_service`, `persist_store_failed`,
`persist_clear_failed` (on `stop`).

**Session fields** (additive):

- `persistent` (boolean): the session has a record and survives restarts until
  `stop`.
- `restored` (boolean): the service started this run itself, at boot or after
  an update or repair.
- `bundle_digest` (string): SHA-256 of the running bundle, so Desktop knows
  whether its saved profile matches the running one.
- `profile_id` and `profile_name` keep their meaning, taken from the bundle.

**Status field** (additive): `NetworkHint` (string), `captive_portal` while
Core sees signs of a captive portal on the current network (see Captive
portals); omitted otherwise.

**Events:** `persistence_enabled`, `persistence_cleared`, `session_restored`,
`boot_guard_failed`, `persistence_suspended` (Linux kernel switch),
`kill_switch_reinstalled`, `captive_portal_suspected`.

**Status codes** (each a run in held `failed` with an active Session, so a
guarded `stop` works): `persistent_profile_unavailable` (the stored bundle
cannot be used; Connect again or Disconnect), `persistent_record_unsupported`
(the record has a format this service does not know), `persistence_suspended`
(Linux kernel switch).

**Changed:**

- `stop` and `shutdown` keep their requests; their meaning gains "and clear
  persistence", and they cancel a pending upload.
- `reconnect_now` also applies to any persistent run in `failed`.
- With persistence, a maintenance seal is a retained exit instead of a
  release.
- Daemon session guards: today a guarded `start` returns
  `session_already_running` while an unprotected session is active. It is
  also admitted when the active session is a persistent run in `failed`, or
  when it runs the same profile ID and bundle digest and only `persist`
  differs.
- The guards and handover otherwise keep their ADR 0039 rules.

**CLI:** `bimeron profile bundle <profile.conf>`; `bimeron start` sends a
bundle when the server supports it, without `persist`: a repeated start of
the running profile keeps its persistence, and any other start is not
persistent; `bimeron start -persist <profile.conf>` and
`bimeron start -persist=false <profile.conf>` set it explicitly;
`bimeron status` shows persistence.

**Desktop** (contract only; the work happens in the Desktop repository):

- Produce the bundle with the store-selected CLI (ADR 0040) and stream it for
  every connection (Q4). When the service reports `persistent_session`, send
  an explicit `persist` value with every bundle start: always `true` for kill
  switch profiles, showing the "keep connected after restart" control on and
  locked (Q1); for a profile without the kill switch, `true` only when the
  user has explicitly enabled that control and `false` otherwise (Q5); it is
  off by default. Send a new
  `start` after saving the active kill switch profile, and after toggling the
  control for the running profile (the record changes in place).
- Explain persistence once at the first persistent Connect. Show the
  persistent state with the profile name, the blocked state during restore of
  a kill switch record and the Q3 captive portal hint. For a record without
  the kill switch, say plainly that traffic is not protected until the VPN
  connects.
- Alert when `persistence_enabled` or `persistence_cleared` arrives, or
  `bundle_digest` changes, without a Desktop action. Another process of the
  same user can start a session or change its persistence.
- Adopt a restored session at startup, and skip GUI auto-connect while a
  persistent session exists. Offer Retry for a persistent run in `failed`,
  with or without the kill switch.
- When the service is stopped or unreachable and the public copy says enabled,
  show the blocked-network notice (kill switch) or a "VPN does not connect"
  notice (without it), with Start service, Repair and Turn off, all elevated
  through ADR 0040 entry points.
- Never run a full `recover` as part of update or repair while a record
  exists; only for an explicit Turn off protection.
- After an update with a persistent session, wait for the restored session
  instead of sending `start`.
- Never send `stop` or `shutdown` on sign-out or OS shutdown. Warn that "stop
  Core on exit" disconnects a persistent session on an explicit Quit.
- On package removal, run the persistence-clearing action described above.

## Options considered

**A. Service-owned persistent session (proposed).** The service records intent,
retains protection on every non-Disconnect exit, guards boot and restores from
its own bundle. The same mechanism restores profiles without the kill switch.

- For: meets the rule from Connect to Disconnect across boots; protects machine
  traffic before sign-in; connects before sign-in with or without the kill
  switch; works without a GUI; reuses ADR 0039 hold, handover and cycles and
  the ADR 0041 retained exit; ends the service's reading of caller-chosen
  paths.
- Against: the largest change; a second copy of profile secrets on disk;
  Desktop must produce bundles; a broken service blocks the network until an
  administrator acts.

**B. Desktop-driven reconnect after sign-in, Core only retains filters on
shutdown.**

- For: small Core change; no secret copy.
- Against: the network stays blocked until a user signs in and the GUI starts;
  other accounts cannot connect it; the service still opens user paths; a
  machine nobody signs in to is blocked forever. Rejected.

**C. Lockdown mode: block whenever no VPN is connected, independent of
Connect and Disconnect.**

- For: the strongest guarantee; simple to state.
- Against: Disconnect no longer restores the internet, which conflicts with the
  optional, per-profile kill switch and with direct routing. Not part of this
  record (Q1); a possible future option that would build on the same record
  and boot guard.

**D. The OS always-on VPN (Windows Always On VPN or VPNv2 LockDown, Linux
NetworkManager connection autoconnect).**

- For: platform-supported.
- Against: Windows lockdown applies to native IKEv2/RAS profiles only, not to
  the Wintun packet backend. NetworkManager has no kill switch and no boot
  block. Rejected for the packet backend; native IKEv2 keeps its own contract.

**Profile delivery alternatives.**

- *Open the files as the caller at Connect (Windows token duplication or
  impersonation, Linux `setfsuid`), then keep a copy.* Handles large files
  without streaming. Rejected: clients deliberately connect with
  identification-level security, so the pipe client cannot be impersonated;
  duplicating the client's process token ignores that choice; per-thread
  identity changes are fragile in Go; and the copy for boot is still needed.
- *Handle passing (`DuplicateHandle`, `SCM_RIGHTS`).* No copy through the
  pipe, but platform-specific, awkward from Qt, and still needs a stored copy
  for boot. Rejected.
- *Read the user's path at boot as SYSTEM or root.* Keeps the privileged path
  open and fails for EFS, network drives and unloaded profiles. Rejected.
- *Inline base64 in the JSON request.* Simple, but the 16 KiB request limit
  and 64 MiB geodata make one size rule impossible. Rejected in favor of the
  two-phase body.

## Security analysis

| Concern | Assessment and mitigation |
| --- | --- |
| Leak at boot | Closed after BFE (Windows) and before `network-pre.target` (Linux). Pre-BFE closed by boot-time filters if the feasibility check passes; otherwise documented, as today |
| Leak during shutdown, update, repair | Closed while Bimeron's filters stay installed: retained exits keep them (on Windows in the no-tunnel form) before closing the session. On Linux, a distribution firewall unit that flushes the whole ruleset when it stops at shutdown (for example `nftables.service`) removes the table in the last moments of shutdown, after the daemon has stopped; acceptance checks the ordering |
| Stale tunnel permit (Windows) | Removed by a clean retained exit: the retained form has no interface permit, so a later adapter with a reused LUID is not trusted. After a crash or forced termination the permit stays until the next arm replaces it |
| Linux external flush | While the daemon runs, up to 5 seconds until the presence check reinstalls the table. While the service is stopped, nothing reinstalls it; the next service start does. Ordering after distribution loaders at boot |
| Traffic outside the VPN for a record without the kill switch | By design and unchanged from kill switch off sessions: before the restored session connects, while it reconnects or has failed, and between a retained exit and the next connection. Desktop says so where the user enables it, and the control is off by default |
| Network blocked permanently (availability, kill switch records) | Intended while the record exists; ended by Disconnect without elevation, by a persistence-aware `recover` offline with elevation, by package removal and, on Linux, by the kernel switch. Desktop explains the state from the public copy even without the service |
| Malware running as the owner: blocking | Can already block the network until reboot; now until Disconnect, across boots. Administrators keep `recover`. Accepted |
| Malware running as the owner: redirection | Can already start its own profile and route traffic through its server until reboot; with persistence also before sign-in, for every account, across boots. Mitigated by visibility: Desktop alerts on persistence or bundle changes it did not make and always shows the persistent profile. Accepted: the owner already controls the machine's VPN |
| Other local users | Cannot create, change or clear persistence: the control pipe admits only the owner and SYSTEM or root; the private directories admit only SYSTEM, root and Administrators |
| Stale or foreign records | Bound to the owner SID or UID; never adopted after an owner change; an unknown format fails closed; reconciliation removes orphans |
| Secrets at rest | A second copy of profile secrets: SYSTEM, Administrators or root only. On Windows, DPAPI in the SYSTEM user scope protects a copy of the file alone, for example in a file-level backup; it does not protect against an administrator or a full backup that includes the system registry hives. Administrators and root can read it, as they can read the user's original. Removed on Disconnect and package removal |
| Privileged file access for callers | Removed for bundle starts: the service parses bounded bytes from the authenticated owner and never opens a caller-chosen path, device, pipe or share. Path-based starts from older clients keep today's behavior until they are removed |
| Store tampering, squatting | Program Files, `/etc` and `/var/lib` with protected, explicitly owned objects created handle-relative, per the ADR 0040 rules. The digest in the record binds the bundle |
| Untrusted bundle content | Parsed with the existing bounded parsers and per-kind limits; same trust as today's `start`, without file access. The upload is bounded, one at a time and outside the command lock |
| Boot guard without a reconnecting service | The service is always registered for boot start (Q6); a guard failure is reported; a disabled or broken service is visible to Desktop |
| Kernel command-line switch | Needs boot loader access, which already defeats any local protection |
| Floors and updates | Floors never block restore; updates and repairs keep protection |

What it does not protect, unchanged from the kill switch: an administrator or
root changing filters, other firewalls' deny rules, forwarded traffic on
Windows (tracked separately), and the profile's `direct` destinations by
design.

## Compatibility and migration

- IPC stays version 1, profile format 1. Every field, command variant, event
  and error is additive and gated by capabilities. The two-phase body is the
  only transport change, and only for `start` with `bundle`.
- Clients that do not send `persist` get exactly ADR 0039 and ADR 0041
  behavior. Desktop 0.3.x is unaffected.
- A newer Desktop with an older service sees no `persistent_session` and says
  that protection ends at restart, as today.
- Records are honored only by persistence-capable images. A backward switch to
  an older image clears persistence first (Interactions). Pre-store tools
  cannot manage a store-era service (ADR 0040, Q9).
- Path-based `start` remains for clients without bundle support until a later
  release removes it (Q4 extension).
- The service starts at every boot once persistence-capable (Q6); the
  `-automatic` install option no longer changes that.

## Work split

**Core**

- Bundle: the CLI producer, the format with per-kind limits and the profile
  ID, the two-phase `start`, bytes-based SSH and MASQUE inputs, rejection of
  paths, `~`, agents and default keys.
- Persistence: the record, the private directories, DPAPI, the public copy,
  ordering and reconciliation, owner binding, restore at service start, the
  filter-preserving cleanup, the `persist` admission rules and the new Session
  fields, events and codes.
- Retained exits for SCM, systemd, update, repair, the maintenance seal and
  abandonment, built on `Engine.Abandon` and the ADR 0041 hold.
- Registration: automatic start and the BFE dependency on Windows, the enabled
  units on Linux, as journaled registration changes.
- Windows boot-time filters in their own sublayer (after the feasibility
  check) and their removal.
- Linux guard unit, `guard.nft` rendering, the persisted cleanup journal, the
  presence check, guard failure detection, the kernel switch, and residual
  detection and `recover` without the `/run` journal.
- `recover`, `service uninstall`, the maintenance-session Turn off operation
  and the package removal action; the ADR 0040 amendments listed above.
- Captive portal signs from bootstrap DNS and transport handshakes, the
  `NetworkHint` field and its event.
- Docs: CONTROL.MD, KILLSWITCH.MD, LINUX.MD, SERVICE.MD, GUI_INTEGRATION.MD,
  CONF.MD, ERRORS.MD and the error catalog.

**Desktop** (separate repository, after acceptance): bundles, persistence UI
and alerts, the blocked-network notice, update, repair and exit rules, package
removal, the captive portal hint and the auto-connect interplay listed in the
contract outline.

## Acceptance plan

Unit tests use stub WFP and nft APIs and cover:

- the record life cycle and every crash point of the write and clear orders,
  including admission before the commit and the rollback of a failed handover;
- reconciliation, owner binding, unknown versions and bundle format numbers;
- bundle limits and digest checks; two-phase upload rejection paths; that an
  upload does not block `stop` and that `stop` cancels it;
- retained versus releasing exits for each stop reason; release of boot-time
  objects, sublayers and the provider in one transaction;
- the restore policy, the filter-preserving cleanup and adopting a DNS file
  from an earlier boot; `reconnect_now` and replacement of a persistent run in
  `failed`; changing `persist` in place; handover on a changed digest;
- `recover`, uninstall and package removal cleanup; capability gating;
- the absence of any file open on a caller path in service mode;
- the captive portal signs, with stub DNS answers and transport responses.

Live checks on a disposable Windows 10 VM (checkpoint first) and an Ubuntu
22.04 VM, with `Default = proxy` and a profile whose server can be blocked at
the router:

1. Connect, restart: no packet outside the tunnel from boot until `connected`
   (capture on the host side of the VM switch), restored before sign-in.
2. Connect, shut down (Fast Startup on and off), boot with the server blocked:
   blocked, cycling; unblock: connects without sign-in.
3. Service stop, update, repair while persistent: no gap; restored by itself.
4. Crash with a systemd or SCM restart, and power loss (VM hard reset) while
   persistent: blocked after boot, the filter-preserving cleanup runs, and the
   session is restored. With the Linux `resolv.conf` file method, check both
   cases: the file still holds Core's bytes (the original is restored), and
   the system regenerated it at boot (the current file is adopted).
5. Disconnect as a standard owner after a restored boot: normal access, normal
   next boot, no Bimeron filters or guard left.
6. Broken service (binary removed or service disabled): Desktop notice, a
   persistence-aware `recover` offline restores access; Linux kernel switch.
7. Desktop package removal while persistent: normal access, the service idles.
   `service uninstall`: nothing left.
8. Windows boot-time filters: present after enabling, enforced before BFE,
   handoff without gap, kept by a restored run's arm, removed on Disconnect,
   reconciliation and `recover`.
9. Linux: ordering against `nftables.service` that flushes the ruleset at boot;
   a failed guard is reported and repaired; the presence check after
   `nft flush ruleset`.
10. A second local account: blocked until connected, cannot control the
    service; Desktop exit during sign-out keeps the session; sleep and resume
    during restore; interactive SSH challenge after sign-in.
11. A profile without the kill switch, persistent: restart connects it before
    sign-in, with no Bimeron filters or guard at any point and normal traffic
    until it connects; with the server blocked the network stays open while it
    cycles; service stop and update restore it; Disconnect means the next boot
    does not connect; a bundle with geodata restores correctly.
12. A simulated captive portal (DNS answering every name with a local address
    and HTTP redirects on the router): `NetworkHint` appears with the
    protection held, the Desktop hint is shown, Disconnect, sign-in and Connect
    work, and the hint clears on `connected` or a network change.

Windows 11 and firewalld are not covered by the available VMs. Claims for them
wait for a separate check before release.

## Decisions

Decided by the user on November 20, 2026:

| # | Decision |
| --- | --- |
| Q1 | Every kill switch connection is persistent automatically, until an explicit Disconnect (option A). Desktop shows the "keep connected after restart" control on and locked for kill switch profiles and explains the change once after the upgrade. Rejected: the same control left optional for kill switch profiles (B). A lockdown mode that blocks even after Disconnect (C) is not part of this record and remains a possible future option |
| Q2 | When a kill switch profile cannot connect after boot, the service keeps retrying in cycles and the network stays blocked until an explicit Disconnect (option A). This also applies to a profile that never connected before the restart, because the record is written at Connect. The rejected alternative was giving up after a time limit and opening the network |
| Q3 | Captive portals: no exception in the first version (option A). The user disconnects, signs in and connects again; Core reports a likely captive portal and Desktop shows the hint. A 5-minute pause, a temporary loopback proxy in Core for a dedicated sign-in window and a browser limited to the local network are recorded for later in issue #242. An automatic browser exception is rejected |
| Q4 | The client sends a bundle and the service keeps a protected copy; bundles are used for every connection, not only persistent ones (option A with the extension). Alternatives were opening the files with the caller's identity at Connect and keeping a copy, or reading the user's path as SYSTEM or root |
| Q5 | When the user explicitly enables it, a profile without the kill switch is also connected at boot, before sign-in, through the same mechanism (option B). Kill switch off traffic semantics are preserved: nothing is blocked, and traffic leaves outside the VPN until the session connects and while it reconnects or has failed |
| Q6 | A persistence-capable service always starts at boot and stays idle without a record (option A). The alternative was changing its own registration at runtime while a record exists |

## Consequences

- The documented limitation "a reboot or service stop releases protection"
  ends for persistent sessions; KILLSWITCH.MD, LINUX.MD and the Desktop release
  notes change accordingly.
- `residual` keeps its meaning (unowned leftovers after a crash without a
  record, or after a failed cleanup); a persistent session never reports it.
- The service gains durable state, privileged data directories and boot-time
  registration. Uninstall, package removal, `recover` and the ADR 0040 switch
  must handle them.
- The service no longer reads profile files by path for bundle-capable
  clients; the old path is deprecated.
- A broken service with persistence blocks the network until someone
  disconnects or an administrator recovers. This is the price of the rule and
  is stated plainly to the user.
