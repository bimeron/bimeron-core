# Daemon session guard contract

Protocol version remains `1`. A successful daemon `hello` or `version` response
includes the top-level boolean `daemon_session_guards: true`, alongside `instance`,
`status`, `core`, and `capabilities`. Absence of the flag means callers must not
assume guard support. Foreground handshakes do not advertise this daemon contract.
The shared non-foreground server also provides it to service callers.

After verifying the handshake, a guarded client sends:

```json
{"version":1,"id":"start-1","command":"start","instance":"<hello.instance>","config":"/absolute/profile.conf"}
```

Start accepts only the expected daemon instance with no active session. Omit
`session` (an explicitly empty string with a valid instance is equivalent). An
inactive retained session identity does not prevent a new start. Start acceptance
schedules connection; it does not promise that the tunnel has connected.

```json
{"version":1,"id":"stop-1","command":"stop","instance":"<hello.instance>","session":"<status.Session.id>"}
```

Stop requires a nonempty instance and the exact ID of the active session. A
replaced, absent, or already stopped session rejects the command. A repeated
start while active also rejects instead of mutating the engine.

Request and outer response keys are lowercase snake_case. Existing nested status
casing is preserved: `status.State`, `status.Session.id`, and
`status.Session.active`. An inactive session may remain in status. Use `active`,
not the mere presence of `Session`, when deciding whether a session is active.

## Errors and admission

- `stale_instance`: instance does not match the running daemon.
- `stale_session`: stop does not identify the current active session.
- `session_already_running`: guarded start finds an active session.
- `invalid_request`: session without instance, guarded stop without session,
  nonempty session on start, or guards on other commands (including shutdown).
- Existing configuration, start/stop failure, and `daemon_shutting_down` errors
  retain their meanings.

Instance mismatch takes precedence over session mismatch. The response always
includes the current daemon `instance` and a refreshed `status` for semantic
rejections. For start/stop/shutdown, the snapshot is captured before releasing
command admission. Precondition checks, configuration loading, and engine
mutation share the same mutex with legacy commands. Asynchronous engine state
can still advance after the snapshot. A rejection never loads configuration or
calls Start/Stop when a guard fails.

Wire validation rejects duplicate or non-lowercase field names, unknown fields,
null identities, an explicitly empty instance, and any session field without an
instance. Malformed frames close the connection without a response, following
existing parser rejection behavior. They never fall back to unguarded execution.

## Compatibility and limitations

Requests omitting both `instance` and `session` remain explicitly **unguarded**.
The existing CLI uses this mode; legacy stop remains idempotent. Such clients can
still stop or replace sessions after observing stale state. Guards prevent stale
mutation, not malicious authorized callers: socket access control remains the
security boundary. Guarded clients must require the handshake flag and must never
retry a rejected guarded command by removing its guards.

Shutdown remains an unguarded administrative operation. Guard fields on shutdown
are rejected rather than ignored. Successful shutdown stops the engine and closes
start admission; failed cleanup leaves the daemon available. Serve still waits
for workers and performs final cleanup using a background context. No new process
ownership, authorization, timeouts, Windows foreground behavior, or Apple IPC
lifecycle behavior is introduced.

This keeps the approved decision local: optional guards extend the existing RPC
and admission mutex instead of introducing a separate session coordinator or
breaking legacy CLI requests.

## Compatible release plan

`v0.3.0-beta.2` lacks daemon session guard support. Clients must require the
runtime `daemon_session_guards: true` handshake flag rather than infer support
from a release version. Protocol version remains `1`.

The candidate next prerelease is `v0.3.0-beta.3`, only after approved merge and
passing CI, followed by a separately authorized release. This workstream does
not hardcode a release version bump or authorize merge, release, or live
acceptance. Publication approval covers the issue and pull request workflow.
