# Local control contract, version 1

Transport: a local Windows named pipe or Unix socket. Each connection carries one
request and one response: UTF-8 JSON terminated by LF. Requests are limited to
16 KiB and responses to 256 KiB. Unknown request fields are rejected. Profiles
remain `.conf` files.

Request: `version: 1`, `command`, optional `id` (up to 64 bytes),
`config` for start (an absolute path), and `after` for events (an event number).
Response: `version`, the same `id`, `instance` (the daemon process identifier),
`status`, and optional `error`, `events`, `cursor`, `dropped`, `stats`,
and `capabilities`. Existing Status/Event fields retain their capitalized Go
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
| stop | Waits for session cleanup; the daemon remains available |
| shutdown | Waits for cleanup and exits the daemon; remains available on error |

States: disconnected, connecting, connected, reconnecting, stopping, failed.
Repeated stop is safe. Concurrent mutating commands are serialized.
Starting an active session again returns session_already_running.
ID provides correlation, not request deduplication. If a start response is lost,
check status first. If a stop response is lost, repeat stop.

Error codes: unsupported_protocol, invalid_request, invalid_cursor,
absolute_config_path_required, invalid_configuration, session_already_running,
session_start_failed, session_stop_failed, daemon_shutting_down, unknown_command.
Check the code, not console text. Connection-failure details are available through
Status.LastError and events; display a generic message for an unknown diagnostic
code. Responses do not contain secrets or configuration contents.

Changes to required fields or existing command semantics require a new version.

Hello/version contain optional core: version, revision, commit_time, modified,
go_version, platform, architecture. This is the running core's version; the RPC
version remains 1. Older builds omit the field. The development version is
0.1.0-dev; distinguish builds using revision/modified. VCS data may be absent.
TCP statistics update after every successful write, not only when a connection
closes. Adding optional fields is compatible: the GUI must ignore unknown response
fields. The GUI must not assume that every platform has identical capabilities.
