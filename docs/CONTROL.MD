# Local control contract, version 1

The separate experimental [Windows IKEv2 foreground control contract](IKEV2_FOREGROUND_CONTROL.MD)
is available in development source. It does not change daemon start, the beta.1
baseline, published assets or Desktop compatibility approval.

Native Windows IKEv2 requires foreground execution. Daemon `start` rejects
such profiles with `ikev2_requires_foreground_user_session`. The optional
`capabilities.ikev2` object describes native support independently of the
top-level packet capabilities. Older daemons may omit it. See [IKEV2.MD](IKEV2.MD).

Native Go API sessions add optional Session fields `backend: "ikev2"` and
`stats_unavailable: true`, use `ipv6: "system"`, and mark stats snapshots
`unavailable: true`. Unsupported counters must not be interpreted as zero traffic.
These additive fields do not change protocol version 1.

Transport: a local Windows named pipe or Unix socket. Each connection carries one
request and one response: UTF-8 JSON terminated by LF. Requests are limited to
16 KiB and responses to 256 KiB. Unknown request fields are rejected. Profiles
remain `.conf` files.

Request: `version: 1`, `command`, optional `id` (up to 64 bytes),
`config` for start (an absolute path), and `after` for events (an event number).
Optional `instance` and `session` guard daemon mutations (see
[Daemon session guards](#daemon-session-guards)); `challenge_id` and `answers`
are used only by `auth_reply`.
Response: `version`, the same `id`, `instance` (the daemon process identifier),
`status`, and optional `error`, `problems`, `events`, `cursor`, `dropped`,
`stats`, `stats_snapshot`, `capabilities`, `core`, `auth`,
`session_bound_stats`, and `daemon_session_guards`. Existing Status/Event fields retain their capitalized Go
names, such as `State`, `LastError`, and `Time`; other fields use JSON tags.

The GUI first sends `hello` to obtain the version, instance identifier, platform
capabilities, and status. An unsupported version returns `unsupported_protocol`.
Reset the event cursor to 0 when instance changes. Events are a bounded history of
128 entries; reread status when dropped is reported. Status is authoritative;
events can be missed.

Optional status.Session describes the last accepted Start: id, profile_id,
profile_name, active, mode, ipv6, and kill_switch_requested. The session ID
survives reconnects and changes on a new Start. After Stop, the data remains with
active=false. The field is absent before the first Start. Profile ID is the
SHA256 of the normalized absolute path (lowercased on Windows); neither the path
nor the key is returned. Name comes from [Profile] Name, with up to 128 characters
and no control characters. The kill_switch_requested setting does not verify the
actual WFP/nftables state. Older daemons may omit Session; the GUI must handle this.

Optional Session.server_tcp and Session.server_udp contain transport endpoints
in host:port format ([host]:port for IPv6), without keys or passwords. VPN mode
reports selected IPs after checking the transport and updates them on reconnect.
If the key used a domain name, Session.server_tcp_name/server_udp_name contain
that original name for display alongside the selected IP.
SOCKS reports the configured TCP endpoint; the dialer performs DNS resolution.
MASQUE in SOCKS mode also reports `server_udp`, because its local listener
accepts UDP `ASSOCIATE`.
Show endpoints as an active connection only in the connected state.
These local details are not included in doctor output or the event log.

| Command | Result |
|---|---|
| hello / capabilities | Supported features of the current platform |
| version | Version and build parameters of the running core |
| start | Request accepted; connection is asynchronous; wait for connected through status/events |
| status | Current state and LastError diagnostic code |
| events | Events after after and a new cursor |
| stats | Counters from the last Start, retained after Stop |
| stats_snapshot | Counters bound to a session; see [below](#optional-session-bound-statistics) |
| auth_pending / auth_reply | Interactive SSH authentication; see [SSH.MD](SSH.MD) |
| reconnect_now | Ends a pending recovery wait or retries a held failed session; see [below](#reconnect-recovery-and-kill-switch-hold) |
| stop | Waits for session cleanup; the daemon remains available |
| shutdown | Waits for cleanup and exits the daemon; remains available on error |

States: disconnected, connecting, connected, reconnecting, stopping, failed.
Repeated stop is safe. Concurrent mutating commands are serialized.
Starting an active session again returns session_already_running, except when
the active session owns kill switch protection and the new profile also enables
the kill switch: a held failed session is replaced, and so is a session of a
different profile in any state. A repeated start of the running profile keeps
the live session (see [Kill switch hold](#kill-switch-hold)).
ID provides correlation, not request deduplication. If a start response is lost,
check status first. If a stop response is lost, repeat stop.

Error codes: `unsupported_protocol`, `invalid_request`, `invalid_cursor`,
`absolute_config_path_required`, `invalid_configuration`, `session_already_running`,
`session_start_failed`, `session_stop_failed`, `daemon_shutting_down`,
`unknown_command`, `response_too_large`, `stale_instance`, `stale_session`,
`invalid_auth_challenge`, `invalid_auth_response`, `kill_switch_held`,
`reconnect_not_pending`, and `ikev2_requires_foreground_user_session`.
Check the code, not console text. Connection-failure details are available through
Status.LastError and events; display a generic message for an unknown diagnostic
code. Responses do not contain secrets or configuration contents.

Response `error` values are catalog codes, of kind `control` except
`ikev2_requires_foreground_user_session`, which is of kind `connection`. `Status.LastError`
and event `LastError` values are catalog codes, usually of kind `connection`;
a failure without a specific code is reported as `connection_failed`, never as
free text. English and Russian texts come from the catalog described in
[ERRORS.MD](ERRORS.MD). `ErrorStage` and progress event codes are not catalog
codes.

Display response strings as plain text. A client cannot tell a genuine daemon
from an impostor by its text, so the CLI replaces control and bidirectional
formatting characters in every daemon string it prints as text, including
error codes, and escapes them as `\u` sequences in its JSON output
(`stats`, `version -daemon`, `doctor`).
SSH prompts follow [SSH.MD](SSH.MD#gui-and-local-control-ipc).

Changes to required fields or existing command semantics require a new version.

## Server identity

A client must verify the server of every local endpoint before it writes the
first request byte. If verification fails, close the connection without writing
and report `control_server_untrusted`. Never fall back to another endpoint after
a failed verification. The checks below use only OS-provided identity: the pipe
object owner, the pipe server process and Unix peer credentials. Response
fields are never proof of identity.

Object owners set by Core:

| Endpoint | Created by | Owner |
|---|---|---|
| `\\.\pipe\Bimeron.Core.Service` | BimeronCore service (LocalSystem) | `S-1-5-18` (SYSTEM) |
| `\\.\pipe\Bimeron.Core.Readiness` | BimeronCore service (LocalSystem) | `S-1-5-18` (SYSTEM) |
| `\\.\pipe\Bimeron.Core.<user-hash>` | Elevated console daemon of the user | `S-1-5-32-544` (Administrators) |
| `\\.\pipe\Bimeron.Core.IKEv2.<user-hash>.<session>` | Elevated foreground owner of the user | `S-1-5-32-544` (Administrators) |
| `\\.\pipe\Bimeron.Repair.<nonce>` | Elevated repair broker | `S-1-5-32-544` (Administrators) |
| `/run/bimeron/control.sock` (Linux), `/var/run/bimeron/control.sock` (macOS) | Root daemon or service | Socket file owned by the control owner UID or root; listener credentials are root |
| `/run/bimeron-repair/<nonce>.sock` | Root repair broker | Socket file owned by the caller UID; listener credentials are root |

Only principals that hold the owner SID in their token can assign it. A
non-administrator cannot create a pipe owned by Administrators or SYSTEM, and
an elevated administrator cannot assign SYSTEM without enabling
`SeRestorePrivilege`.

The owner applies to the whole pipe, and `GetNamedPipeServerProcessId` reports
the process that created the pipe, also for a later instance that another
process serves. Neither identifies the server of an individual instance. The
pipe DACLs therefore grant `FILE_CREATE_PIPE_INSTANCE` (`0x4`) only to the
server principal. Clients get `0x0012019B`: `FILE_GENERIC_READ |
FILE_GENERIC_WRITE` without `FILE_CREATE_PIPE_INSTANCE`, and without
`WRITE_DAC` or `WRITE_OWNER`. With these rights a client opens the pipe with
`GENERIC_READ | GENERIC_WRITE`, reads and writes, and reads the owner.

| Endpoint | DACL (protected) |
|---|---|
| `\\.\pipe\Bimeron.Core.Service` | SYSTEM: full; control owner: `0x0012019B` |
| `\\.\pipe\Bimeron.Core.Readiness` | SYSTEM: full; Administrators: `0x0012019B` |
| `\\.\pipe\Bimeron.Core.<user-hash>` | SYSTEM: full; user: `0x0012019B`; Administrators: `0x4` |
| `\\.\pipe\Bimeron.Core.IKEv2.<user-hash>.<session>` | SYSTEM: full; user: `0x0012019B`; Administrators: `0x4`; medium no-write-up label |
| `\\.\pipe\Bimeron.Repair.<nonce>` | SYSTEM: full; Administrators: full; caller: `0x0012019B` |

The console daemon and the IKEv2 foreground owner run elevated as the user, so
the user and Administrators entries together give them the rights to serve
further instances. Non-elevated processes of the user hold Administrators only
as a deny-only group and cannot serve the pipe. Only SYSTEM serves the
readiness pipe; administrators can connect to it but cannot add instances.
The repair broker runs elevated and serves its pipe through the
Administrators entry; the caller that launched it can only connect.

### Windows service pipe

1. Connect to `\\.\pipe\Bimeron.Core.Service` with identification or anonymous
   impersonation level. The handle has `READ_CONTROL`.
2. Read the owner with `GetSecurityInfo(handle, SE_KERNEL_OBJECT,
   OWNER_SECURITY_INFORMATION)`. Require exactly `S-1-5-18`.
3. Bind the service process. Open the service with
   `OpenSCManager(SC_MANAGER_CONNECT)` and `OpenService("BimeronCore",
   SERVICE_QUERY_STATUS)`, then call `QueryServiceStatusEx`. It must succeed
   and report a nonzero process ID, and `GetNamedPipeServerProcessId` must
   return the same ID. A service that serves the pipe always has a nonzero
   process ID. If the pipe exists but the service is not installed, is
   stopped, reports process ID 0 or the query fails, the endpoint is
   untrusted. Standard users have these rights under the default service
   security, so a failed query, including access denied, is not expected and
   fails closed.

Do not open the server process token. Standard users cannot open a LocalSystem
token, so a check that requires it fails for a normal GUI.

Unlike the console daemon and IKEv2 foreground clients, a service pipe client
keeps no handle to the server process. A LocalSystem process grants standard
users no access, so `OpenProcess` fails for a normal GUI, and the check does
not need a handle: only SYSTEM can create instances of the service pipe, so
every instance a client connects to is served by a SYSTEM process, and the
SCM process ID binds the pipe to the BimeronCore service.

A service built before explicit owners leaves the pipe owned by Administrators
(`S-1-5-32-544`). Clients with this check reject it until the service is
updated. `bimeron service update` is unaffected: it stops and starts the
service through SCM and verifies the updated service, which already sets the
new owner. `bimeron version -daemon` sends its request only after these checks,
so it reports `control_server_untrusted` for such a service instead of its
version. Core does not show the version that an unverified endpoint claims.

### Windows readiness pipe

`CallServiceReadiness` requires `GetNamedPipeServerProcessId` to match the
SCM-reported service process ID before writing. Only administrators can open
this pipe.

### Windows console daemon pipe

Fall back to `\\.\pipe\Bimeron.Core.<user-hash>` only when the service pipe does
not exist (`ERROR_FILE_NOT_FOUND`). Then:

1. Require pipe owner `S-1-5-32-544`.
2. Get the server process with `GetNamedPipeServerProcessId` and open it once
   with `PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE`. Open its token
   through that handle with `TOKEN_QUERY`. Require token user equal to the
   client's user SID and `TokenElevation` true. Then require the process to
   still be running, and keep the handle until the connection is closed, so
   the process ID cannot be reused in between. The daemon refuses to start
   without elevation.
3. If the client launched the daemon, also require the server process ID to
   match the retained process handle of that launch.

A non-elevated client can open the process and token of a daemon that the same
user elevated through UAC in the same logon. A daemon elevated in another logon
session, for example one started remotely, cannot be opened by a non-elevated
client and is rejected.

### Windows IKEv2 foreground pipe

Use `ForegroundClient` or perform the same checks. See
[IKEV2_FOREGROUND_CONTROL.MD](IKEV2_FOREGROUND_CONTROL.MD#installation-and-trust).
For each connection: dial with identification-only SQOS, get the server process
ID, retain a process handle with `SYNCHRONIZE`, and require an elevated token of
the same SID and interactive session. The image must lie under Program Files,
with protected ancestors that are retained open. Its SHA-256 (or the volume and
file index pinned by an earlier connection) must match the selected Core
digest. The response `installation` must equal the installation ID the client
sent, `endpoint` must be `ikev2_foreground` or `ikev2_profile`, and `owner` must
equal the observed identity. The process must still be running after
inspection. There is no fallback to the
service or console daemon pipe.

### Windows repair pipe

`\\.\pipe\Bimeron.Repair.<nonce>` uses a fresh 128-bit nonce from the client.
The client launches the broker itself and retains its process handle. Before
writing, `GetNamedPipeServerProcessId` must equal that process ID, and the
retained handle must show the process still running. The broker independently
binds its client PID, SID and session.

### Unix control and repair sockets

The authoritative check is the kernel peer credential of the connected socket:
`SO_PEERCRED` on Linux, `getpeereid` or `LOCAL_PEERCRED` on macOS. Require UID
0. The kernel records the credentials of the process that called `listen`. A
non-root process cannot produce UID 0 credentials, whoever owns the directory.
For the repair socket, also require the PID of the broker the client launched
when it is known.

Defence in depth before connecting: `lstat` the runtime directory and the
socket, and refuse to connect unless the directory is a directory (not a
symlink) owned by UID 0 without group or other write permission and the socket
path is a socket. The daemon creates `/run/bimeron` (`/var/run/bimeron` on
macOS) with mode `0711` and `/run/bimeron-repair` with mode `0755`, both owned
by root. A client that checks every path component must start from the
canonical path: on macOS `/var` is a symlink to `/private/var`. On Linux use
`/run/bimeron`, not the `/var/run` alias.

If the runtime directory exists but is not a root-owned directory, or is
writable by group or others, the daemon refuses to start and does not repair
it. Mode `0700` or `0751` in a root-owned directory is reset to `0711`. On Linux
`/run` is root-owned with mode `0755`, so other users cannot pre-create the
directory. On macOS `/private/var/run` is writable by the `daemon` group.

Core's own clients (`Call`, `CallService`, `Dial`, `DialService`) perform the
checks for the service, console daemon and Unix control endpoints.

## Daemon session guards

A daemon (not a foreground owner) reports `daemon_session_guards: true` on
hello/version. Without the flag, do not send guards. A guarded client copies
`instance` from hello into mutating requests:

```json
{"version":1,"id":"start-1","command":"start","instance":"<hello.instance>","config":"/absolute/profile.conf"}
{"version":1,"id":"stop-1","command":"stop","instance":"<hello.instance>","session":"<status.Session.id>"}
```

- `start` succeeds only for the current instance with no active session; omit
  `session`. An active session that owns kill switch protection is admitted to
  the engine, which hands it over or rejects the start (see
  [Kill switch hold](#kill-switch-hold)).
- `stop` and `reconnect_now` require the current instance and the ID of the
  active session.
- `stale_instance`: the daemon restarted. `stale_session`: the session was
  replaced or already stopped. A guarded start during an active session returns
  `session_already_running`.
- `invalid_request`: `session` without `instance`, guarded stop or
  `reconnect_now` without `session`, or guards on any other command, including
  `shutdown`.

Guard fields must be non-null strings: an empty `instance`, a `null` identity, or
`session` without `instance` is rejected before any command runs, and such
malformed requests never fall back to unguarded execution. An instance mismatch
takes precedence over a session mismatch. Rejections
include the current `instance` and a fresh `status`, and never load the
configuration or change the session. Requests without `instance` and `session`
stay unguarded; the CLI uses this mode, and unguarded stop remains idempotent.

## Optional session-bound statistics

Servers implementing the optional snapshot provider return
`session_bound_stats: true` on hello/capabilities. Older servers omit it.
The additive `stats_snapshot` command accepts the same empty config/after as
stats and returns `stats_snapshot: {status, counters?}`. Bind this observation
using the response's `instance` and the inner `status.Session.id`; use the inner
status exclusively for attribution. Legacy stats/status commands are unchanged
and their separately read values must not be combined to infer ownership.
Servers without the provider return `unknown_command`, without a legacy fallback.
Foreground owners expose the command under their existing identity guards and
advertise support on hello; their command allowlist otherwise stays unchanged.

The inner status/session/active and selection of the counter owner are captured
under one Engine lock. Before the first accepted Start, Session and counters are
absent: there is no sample, rather than measured zero traffic. Every accepted
Start creates a new Session ID and resets counters, including a Start whose
asynchronous setup later fails. Rejected Start leaves them unchanged. Counters
accumulate across reconnects and remain readable with the inactive session
after termination. Native IKEv2 counters have `unavailable: true`, including
after termination, and must not be displayed as zero traffic.

`status.Attempt` describes Open/Reconnect progress, not a counter reset epoch
or proof of an installed transport. Counter fields are independently atomic
loads and may reflect different instants; the guarantee is session ownership,
not a simultaneous counter tuple or attempt-specific traffic measurement.
Rate consumers use local monotonic sample time and invalidate their baseline
on identity changes, resync/loss, unavailable data or decreasing byte counters.
Any consumer observation generation remains local; events and cursors do not
establish identity or counter ownership.

Hello/version contain optional core: version, revision, commit_time, modified,
go_version, platform, architecture. This is the running core's version; the RPC
version remains 1. Older builds omit the field. The development version is
the nearest reachable Git tag plus `-dev` when built by project scripts;
distinguish builds using revision/modified. Without a reachable tag, the
fallback is 0.1.0-dev. VCS data may be absent.
TCP statistics update after every successful write, not only when a connection
closes. Adding optional fields is compatible: the GUI must ignore unknown response
fields. The GUI must not assume that every platform has identical capabilities.

## Reconnect recovery and kill switch hold

<a id="bounded-reconnect-recovery-desktop-030"></a>

### Recovery policy

A run is everything between an accepted `start` and the end of its session.
Recovery depends on whether the run has reached `connected`:

- **Initial connection** (before the first `connected` of a run, including a
  GUI auto-connect): the first attempt plus up to 3 retries with 1, 2 and 4
  second backoff, then `failed`. A nonretryable failure is `failed` at once.
- **Loss of an established session**: recovery continues in cycles until
  success or an explicit stop. A cycle has up to 10 attempts with 1, 2, 4, 8,
  then 15 second backoff. After a failed cycle, Core waits 60 seconds (phase
  `waiting`), then starts the next cycle with an immediate first attempt. A
  connection that drops again within 1 minute of `connected` continues the
  previous cycle position instead of starting a fresh cycle.

Any scheduled wait, either a backoff or the pause between cycles, ends early on
`reconnect_now`, on a change of local network interfaces (checked every 5
seconds) or on a detected resume from sleep. A network change ends at most one
wait per cycle (and one during initial attempts), so flapping virtual adapters
cannot bypass the backoff and the pause. An attempt in progress is never
interrupted. Stop cancels pending waits and attempts.

After loss of an established session, failures that end an initial connection
are retried in the same cycles, for example an unavailable `ssconf` key (HTTP
401, 403, 404 or 410), a TLS or handshake rejection, a changed `ssconf`
transport, SSH authentication or loss of the tunnel adapter. `LastError` keeps
the specific code. These still end the run with `failed`: codes ending in
`_run_recover` (cleanup or protection failures), a failed session close and a
maintenance seal.

Ordinary close/open recovery and persistent tunnel recovery share this policy.
A persistent VPN session keeps its tunnel while the transport recovers: `proxy`
traffic is blocked and `direct` traffic continues. Failures of the tunnel itself
(`tunnel_adapter_lost`, `dns_recovery_failed`, `conflicting_dns_policy`,
`adapter_name_in_use`) close the tunnel and open it again. Native IKEv2
sessions keep the bounded policy (3 retries) and do not use cycles.

### Kill switch hold

With `[Interface] KillSwitch = true` (VPN mode on Windows and Linux), Core
installs protection as the first step of a run, before network inspection,
key or `ssconf` resolution, bootstrap DNS and the transport check. Protection
stays installed through every attempt and wait, and while `failed`. It is
released only when the session is stopped: `stop` or `shutdown` (IPC or CLI),
Ctrl+C of a foreground `bimeron connect`, or a service stop, followed by
successful cleanup. See [KILLSWITCH.MD](KILLSWITCH.MD) and [LINUX.MD](LINUX.MD).

A `start` with the kill switch enabled returns only after the run has installed
its protection or failed to, so an accepted `start` never precedes protection.
A maintenance seal ends the run like a service stop and releases protection.
The filters are persistent: after a crash, a forced process termination or a
power loss during any phase they stay installed until a session with the kill
switch replaces them or `bimeron recover` removes them. An idle daemon or
service reports them as `failed` with `cleanup_failed_run_recover` and
`KillSwitch: "residual"`. A new run that fails in
setup before it installs protection (for example `session_lock_failed`) after
a handover leaves the earlier filters in place; use `recover`.

With the kill switch enabled, a run that reaches `failed` stays open. Status
shows `failed` with `LastError`, `KillSwitch: "holding"` and
`Session.active: true`. In this state:

- `reconnect_now` restarts the initial attempts (first attempt plus 3 retries)
  with the same profile. Protection stays installed. Network changes and resume
  do not restart a held session.
- `start` with a profile that also enables the kill switch in VPN mode (not
  IKEv2) replaces the held session without releasing protection; the new run
  replaces the filters transactionally. A guarded `start` is admitted in this
  state. Any other profile is rejected with `kill_switch_held`; send `stop`
  first.

The same handover applies to any active session that owns protection
(`KillSwitch` is `active` or `holding`) when the new kill switch VPN profile is
a different profile: the current session is
closed and the new one starts without releasing protection, so switching
servers leaves no gap. A repeated start of the same profile while it is
connecting, connected or reconnecting returns `session_already_running` and
keeps the live session. With a profile without the kill switch, an active
session returns `session_already_running`. If the previous session fails to
clean up during a handover, `start` fails, the status reports `failed` with the
cleanup code and protection stays until `recover`.

Profile identity is the profile file: `Session.profile_id` is derived from the
absolute path of the configuration file (case-insensitive on Windows). Edits to
a profile saved at the same path are therefore the same profile; apply them
with `stop` followed by `start`, because a repeated `start` keeps the running
session. Embedders without a profile path are compared by profile name.

If the daemon or service fails while a `start` waits for a handover, the
previous session's filters stay installed and the `start` fails; once the owner
has abandoned the engine, no later `start` is accepted. A user's `stop` that is
already in progress still releases protection.

Protection also stays installed when the daemon or service ends for a reason
other than a stop, for example a failed control listener or a crash: the
session is closed, the filters remain and an idle core then reports
`KillSwitch: "residual"`.
- `stop` and `shutdown` release protection. If removal fails, the session ends
  `failed` with `cleanup_failed_run_recover`, the command returns
  `session_stop_failed` and protection stays until `bimeron recover`.

With the kill switch disabled, the same recovery policy applies, but there is
no guarantee that traffic does not leave outside the tunnel while connecting,
reconnecting or after `failed`. A failed run without held protection ends:
`Session.active` becomes `false`.

`stop`, `shutdown` and service stop report only their own teardown. When a run
without held protection has already ended in `failed` (bounded attempts
exhausted, a nonretryable failure or `session_stopped_unexpectedly`), teardown
has already completed: `stop` and `shutdown` succeed and the daemon exits with
status 0. A held run is torn down by the stop itself, which reports the result
of that teardown. `Status` keeps `failed`, `LastError` and recovery progress
until the next transition. A session that ended with a cleanup failure still
returns `session_stop_failed` and a nonzero daemon exit, because service repair
uses that exit status as cleanup evidence.

### Status and event fields

Status and every Event carry these optional capitalized fields. Zero values are
omitted.

- `ReconnectAttempt` (integer): upcoming or current attempt, 1 to 3 during
  initial retries and 1 to 10 within a cycle. Published before its backoff and
  omitted during `waiting`. Retained in `failed` after the initial attempts;
  reset on `connected`, `disconnected`, a new `start` and `reconnect_now` on a
  held session.
- `ReconnectLimit` (integer): 3 during initial retries, 10 within a cycle;
  present together with `ReconnectAttempt`.
- `ReconnectCycle` (integer): the current or most recent cycle (1-based) after
  loss of an established session; omitted during initial attempts. During
  `waiting` it is the cycle that just failed; it increments when the next cycle
  starts.
- `ReconnectPhase` (string): `attempting` while an attempt is scheduled
  (`NextAttemptAt` is set) or running (`NextAttemptAt` is omitted); `waiting`
  during the pause between cycles. Omitted outside `reconnecting`, and briefly
  while the previous session closes before the first attempt is scheduled.
- `NextAttemptAt` (RFC 3339 UTC timestamp, whole seconds): when the next
  scheduled attempt or cycle starts. Omitted when nothing is scheduled: an
  attempt is in progress, or the state is not `reconnecting`. It uses the core
  host's clock; compute countdowns locally from it.
- `KillSwitch` (string): `active` while protection is installed and the session
  is `connected`; `holding` while protection is installed and the tunnel carries
  no traffic (`connecting`, `reconnecting`, held `failed`, `stopping`): traffic
  that the routing policy does not send `direct` is blocked until the VPN
  connects or the session is stopped. Omitted when the run owns no protection
  (kill switch disabled, proxy mode, native IKEv2, which reports its own
  protection under `native`). `residual` while no run is active but Bimeron
  kill switch protection is still installed, for example after a crash, a
  power loss during a held session, or a failed cleanup: the daemon or service
  then reports `failed` with `cleanup_failed_run_recover`, the code existing
  GUIs already route to network recovery (unless another failure is already
  shown), and `Session.active` is not `true`. Connecting a profile with the
  kill switch replaces the filters; `recover` removes them. Inspected at most
  every 5 seconds while idle. Protection owned by another running session, such
  as a foreground `bimeron connect` that holds the session lock, is not
  reported as residual.
- `LastErrorPermanent` (boolean): `LastError` is a failure that retrying alone
  does not fix, for example `access_key_unavailable` (a rejected or removed
  key) or a TLS rejection. It ends an initial connection at once; after loss of
  an established session Core still retries it in cycles. Omitted for
  transient failures and when `LastError` is cleared.

`Attempt` keeps its cumulative per-Start semantics, including initial Open and
transport generations; it is not a recovery counter. Status remains
authoritative if events are dropped. `LastError` carries the last catalog code,
not the generic retry log message; localize it through the error catalog and
keep its textual code visible, including in `failed`.

Progress event codes (not catalog codes):

| Code | Meaning |
|---|---|
| `reconnect_attempt` | An attempt is scheduled, or a new cycle starts; published even when state and error did not change |
| `reconnect_wait` | A cycle failed; waiting for the next cycle |
| `reconnect_requested` | `reconnect_now` ended a wait or restarted a held session |
| `network_changed`, `resume_detected` | A network change or resume from sleep ended a wait early (also reported by session monitoring) |
| `kill_switch_holding` | Protection was installed at the start of a run |
| `kill_switch_held` | The run failed and protection is held until stop |

### `reconnect_now` command

```json
{"version":1,"id":"retry-1","command":"reconnect_now","instance":"<hello.instance>","session":"<status.Session.id>"}
```

Admission matches `stop`: with `instance`, the request must name the active
session; without `instance` and `session` it runs unguarded, as the CLI
`bimeron reconnect` does. `config` and `after` are rejected with
`invalid_request`. The command ends a pending wait (backoff or pause between
cycles) or restarts the attempts of a held failed session. It never cancels an
attempt in progress. Errors: `reconnect_not_pending` (no wait is pending and no
session is held), `stale_session`, `stale_instance` and `invalid_request`.

Capabilities add two booleans. `reconnect_now` reports that the daemon accepts
the command. `kill_switch_hold` reports that an enabled kill switch is held from
start until an explicit stop and published in `Status.KillSwitch`; it is `true`
on Windows and Linux. Older cores omit both.

### Compatibility

All fields, events, the command and the `kill_switch_held` and
`reconnect_not_pending` errors are additive: IPC remains version 1 and profile
format remains 1. Older services omit the new fields; GUIs must not infer a
limit from `Attempt`, count log messages, or terminate a service-owned
connection locally. Desktop 0.3.0 behavior with this policy is listed in
[GUI_INTEGRATION.MD](GUI_INTEGRATION.MD#desktop-030-compatibility).
The GUI range in `release/compatibility.json` is widened to include Desktop
0.3.1 by the release that ships it.

Automated tests cover cycle backoff and pauses, flap handling, early wake on
`reconnect_now` and network change, stop during a wait, IKEv2 exclusion, the
held kill switch after initial and nonretryable failures, retry and handover of
a held session, cleanup and release failures, guarded `reconnect_now` and
`start` admission, early Windows arming and detach through a stub WFP API, and
the early Linux nftables guard. Real-network validation on Windows and Linux
remains a release gate.
