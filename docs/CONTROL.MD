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
| stop | Waits for session cleanup; the daemon remains available |
| shutdown | Waits for cleanup and exits the daemon; remains available on error |

States: disconnected, connecting, connected, reconnecting, stopping, failed.
Repeated stop is safe. Concurrent mutating commands are serialized.
Starting an active session again returns session_already_running.
ID provides correlation, not request deduplication. If a start response is lost,
check status first. If a stop response is lost, repeat stop.

Error codes: `unsupported_protocol`, `invalid_request`, `invalid_cursor`,
`absolute_config_path_required`, `invalid_configuration`, `session_already_running`,
`session_start_failed`, `session_stop_failed`, `daemon_shutting_down`,
`unknown_command`, `response_too_large`, `stale_instance`, `stale_session`,
`invalid_auth_challenge`, `invalid_auth_response`, and
`ikev2_requires_foreground_user_session`.
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
| `\\.\pipe\Bimeron.Repair.<nonce>` | Elevated repair broker | No explicit owner (the elevated token default, normally Administrators) |
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
| `\\.\pipe\Bimeron.Core.Readiness` | SYSTEM: full; Administrators: full |
| `\\.\pipe\Bimeron.Core.<user-hash>` | SYSTEM: full; user: `0x0012019B`; Administrators: `0x4` |
| `\\.\pipe\Bimeron.Core.IKEv2.<user-hash>.<session>` | SYSTEM: full; user: `0x0012019B`; Administrators: `0x4`; medium no-write-up label |

The console daemon and the IKEv2 foreground owner run elevated as the user, so
the user and Administrators entries together give them the rights to serve
further instances. Non-elevated processes of the user hold Administrators only
as a deny-only group and cannot serve the pipe.

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
  `session`.
- `stop` requires the current instance and the ID of the active session.
- `stale_instance`: the daemon restarted. `stale_session`: the session was
  replaced or already stopped. A guarded start during an active session returns
  `session_already_running`.
- `invalid_request`: `session` without `instance`, guarded stop without
  `session`, or guards on any other command, including `shutdown`.

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

## Bounded reconnect recovery (Desktop 0.3.0)

Core allows three reconnect attempts after a failed initial Open or a later
interruption. The initial Open is excluded. Both ordinary close/open recovery
and persistent tunnel transport recovery use this policy. Successful connection
resets the recovery budget for the next interruption. Nonretryable failures stop
immediately. Stop cancels pending backoff and recovery. After the third failure,
Core cleans up and enters `failed` with the final `LastError` and `ErrorStage`;
a cleanup failure takes precedence. No fourth attempt is scheduled.

A later `stop`, `shutdown` or service stop reports only teardown. After reconnect
exhaustion or `session_stopped_unexpectedly`, teardown has already completed:
`stop` and `shutdown` succeed, and the daemon exits with status 0. `Status` keeps
`failed`, `LastError` and recovery progress. A session that ended with a cleanup
failure still returns `session_stop_failed` and a nonzero daemon exit, because
service repair uses that exit status as cleanup evidence.

Status and every Event add optional capitalized integer fields:

- `ReconnectAttempt`: upcoming/current recovery attempt, 1 through 3. Published
  before its backoff, retained after exhaustion, reset on success/disconnection
  and a new Start. A cleanup transition can precede scheduling the first retry.
- `ReconnectLimit`: 3 while recovery progress is present; omitted when reset.

Zero values are omitted. `Attempt` retains its cumulative per-Start semantics,
including initial Open and transport generations; it is not a recovery counter.
`reconnect_attempt` events publish progress even when state/error did not change.
Status remains authoritative if events are dropped. `LastError` carries the last
catalog code, not the generic retry log message. Localize it through the error
catalog and retain its textual code in the tooltip, including terminal failure.

These fields are additive: IPC remains version 1, profile format remains 1 and
`release/compatibility.json` is unchanged (GUI `[0.3.0, 0.3.1)`, IPC 1/1).
Older services can omit both fields; GUIs must not infer a `/3` limit from
`Attempt`, count log messages, or terminate a service-owned connection locally.
The frozen e1cada7d candidate is unchanged; Desktop 0.3.0 requires a new reviewed
Core master candidate containing this change before release acceptance.

Local validation for issue #136: Windows amd64 `go vet ./...` and
`go test -p 1 ./...` passed; `go test -race ./core ./internal/control` passed.
The core suite also passed ten consecutive runs. Added tests assert both wire
field names in status/events, exact exhaustion, cleanup priority, reset on
success, cancellation during backoff and omission after reset. Existing
persistent-success and cancellation fixtures remain green. Diff review found no
compatibility/profile version changes. Benchmarks/profiling are not applicable
to this bounded control-flow correction. Cross-platform CI, a merge commit on
master and new-candidate Desktop VM acceptance remain release gates.
