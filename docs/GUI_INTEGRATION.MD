# Bimeron Core: integrating a separate GUI

Last reviewed against the source on November 15, 2026. This document can be
copied into a separate project: it describes the implemented contract without
requiring other repository files. Recheck it against core changes made after
this date.

Related contracts:

- [GeoIP/GeoSite routing editor](GUI_GEODATA_ROUTING.MD): configuration mapping,
  commented-out rules, and GUI combination restrictions for issue #67. It is in
  development source and not yet released; [GEODATA.MD](GEODATA.MD) describes the
  host APIs.
- [Windows IKEv2 foreground control](IKEV2_FOREGROUND_CONTROL.MD): experimental
  and in development source. It does not change daemon `start`, published assets,
  or Desktop compatibility approval.
- [VLESS transports](VLESS_TRANSPORTS.MD): link and `.conf` fields, transport
  combinations, validation, and interoperability limits for VLESS editors and
  importers. A GUI writes a profile file and uses the existing `start` RPC; no
  VLESS-specific RPC is needed.

## Project separation

The core is developed separately; each platform's GUI is a separate project. The
GUI manages profiles, status display, and user settings. The core handles network
operations, key resolution, routing, DNS, reconnection, and cleanup. Profiles are
`.conf` files; the local RPC uses JSON.

The main desktop integration path is IPC with a running service or daemon, which
any language with named pipe or Unix socket support can use. The CLI remains
available, but do not parse the text output of `status` or `watch` as an API. Go
programs can use the `bimeron/core` package (`New`, `LoadConfig`, `Start`, `Stop`,
`Status`, `Events`, `Stats`, `Wait`, `PlatformCapabilities`). Embedding the engine
in the GUI process requires network privileges in that process; IPC keeps them in
a separate one.

## Minimal first integration

This repository contains no GUI. A first Windows GUI needs only the installed
BimeronCore service and the existing RPC version 1. The user selects an existing
`.conf` file, and the client:

1. Sends `hello`, checks the protocol version, and reads the core capabilities.
2. Reads `status` and treats the service state as authoritative.
3. Sends the absolute path of the selected profile to `start`.
4. Shows the status, safe error codes, events, and summary statistics.
5. On user request, sends `stop` and waits for cleanup to finish.

The GUI stores only the list of profile paths and the selected profile. Profile
contents, keys, and passwords are never sent over RPC and must not appear in
settings, logs, or analytics. The files stay protected by the user's ACL and are
read directly by the service.

A profile editor, service installation, `recover`, `shutdown`, auto-connect, core
updates, a system tray, notifications, Linux/macOS, and per-application routing
are outside this first step. Decide them in the GUI repository.

Automated client tests should cover: an incompatible version; unavailable or
denied IPC; a start that reaches `connected` or `failed`; stop; restart; a changed
`instance`; `dropped=true`; an unknown error code; and no secrets in logs. Confirm
manually that a regular user can control the service without elevation.

## Platform support

| Platform | System VPN | Leak protection | Control |
|---|---|---|---|
| Windows amd64/arm64 | Wintun, TCP/UDP | WFP kill switch, if enabled | SCM service or console daemon, named pipe |
| Linux amd64/arm64 | TUN, TCP/UDP | nftables kill switch, if enabled; does not survive reboot | root daemon, Unix socket |
| macOS Intel/Apple Silicon | Experimental utun backend | Kill switch not implemented | root daemon, Unix socket |
| Android | Packet engine; the host app supplies `VpnService` | Host responsibility | [AAR integration](ANDROID_VPN_SERVICE.MD); desktop IPC is not a mobile VPN API |
| iOS | Not implemented | Not implemented | No iOS VPN host |

The separate [macOS NetworkExtension integration](APPLE_NETWORK_EXTENSION.MD)
provides a packet engine and a Swift provider; deployment requires signing and
provisioning. It does not use the experimental CLI `utun` backend.

Read capabilities from the running core through `hello` or `capabilities`. They
describe build support; they do not check whether a driver, permission, or server
is available.

- `domain_split` is true on Windows, Linux, and macOS. System VPN domain rules use
  limited DNS metadata and do not cover DoH/DoT, direct IP connections, or
  existing DNS caches.
- `app_split` is false; do not promise per-application routing.
- The local SOCKS5 listener accepts TCP `CONNECT`. Only MASQUE profiles also
  accept UDP `ASSOCIATE`.
- macOS requires testing on a real Mac. The Windows service has been checked
  manually for connection, normal stop, restart, and service update.

`hello` and `version` return an optional `core` object describing the running
daemon or service, not the GUI or a separate CLI: `version`, `revision` (Git SHA),
`commit_time`, `modified`, `go_version`, `platform`, and `architecture`. Do not
confuse `core.version` with the protocol `version: 1`. Development builds report
the nearest reachable Git tag plus `-dev`, so compare `revision` and `modified`
to tell them apart. Without VCS data, `revision` and `commit_time` may be missing;
older cores omit `core`, in which case display an unknown version. The CLI
`version` command describes the CLI itself; `version -daemon` describes the
running core.

## Transport and access

The Windows BimeronCore service runs as LocalSystem and listens on:

```text
\\.\pipe\Bimeron.Core.Service
```

Access is granted to SYSTEM and to the SID of the user who installed the service,
so that user's GUI works without elevation. If UAC elevated through a different
administrator account, that account is the owner. On access denied, report a
permission problem; do not silently switch to another core.

A Windows console daemon uses:

```text
\\.\pipe\Bimeron.Core.<user-hash>
```

`user-hash` is the first 16 bytes of the SHA-256 of the current user's SID string
(UTF-8), as 32 lowercase hex characters. Access is limited to that user and
SYSTEM. Prefer the service pipe, and fall back to the console daemon only when the
service pipe is missing (`ERROR_FILE_NOT_FOUND`), as the CLI does. A busy pipe,
access denied or a failed identity check does not mean the service is missing.
Remote pipe connections are rejected.

Verify the server before writing the first byte, as described in
[Server identity](CONTROL.MD#server-identity). In short:

- Service pipe: the pipe object owner, read from the connected handle with
  `GetSecurityInfo`, must be `S-1-5-18`. SCM must report a nonzero BimeronCore
  process ID, and `GetNamedPipeServerProcessId` must match it. If the pipe
  exists but SCM reports no service, process ID 0 or the query fails, the
  endpoint is untrusted. Do not open the server token: a standard user cannot
  open a LocalSystem token.
- Console daemon pipe: the owner must be `S-1-5-32-544`, and the server token
  must belong to the current user and be elevated. Open the server process
  once, inspect its token through that handle and keep the handle until the
  connection is closed. If the GUI launched the daemon, the server process ID
  must also match that launch.
- The process ID binding does not identify the server of an individual pipe
  instance. Only the server principal may create instances: the user has
  `0x0012019B` (read and write without `FILE_CREATE_PIPE_INSTANCE`) on the
  service, console daemon and IKEv2 foreground pipes. Open them with
  `GENERIC_READ | GENERIC_WRITE` as before.
- IKEv2 foreground and repair pipes: follow the checks in the same section.
- Unix sockets: the peer credentials (`SO_PEERCRED`, `getpeereid` or
  `LOCAL_PEERCRED`) must report UID 0. Check the runtime directory with `lstat`
  before connecting.

On failure, close the connection and report `control_server_untrusted`. Do not
fall back to another endpoint. A service built before this check leaves the
service pipe owned by `S-1-5-32-544` and is rejected until it is updated. Its
version is not available through the pipe then: `version -daemon` reports
`control_server_untrusted` as well.

On Linux the socket is `/run/bimeron/control.sock`; on macOS it is
`/var/run/bimeron/control.sock`. The socket mode is 0600. The client UID must be
root or the launching owner taken from `SUDO_UID`, so a regular GUI can connect to
a daemon started with sudo by the same user. The Linux systemd service passes the
stored owner UID through `BIMERON_CONTROL_UID`. A daemon started directly by root
without these variables is accessible only to root. launchd installation is not
implemented yet.

Do not run a console daemon alongside the service. Parallel daemons use different
channels, but only one system VPN session is allowed per machine.

## RPC version 1

Each connection carries one request and one response: UTF-8 JSON terminated by LF,
after which the connection closes. Pipes and sockets are byte streams: read until
LF instead of expecting the whole response in one read. Requests are limited to
16 KiB including LF; limit responses to 256 KiB on the client. The server waits up
to 5 seconds for a request. Invalid JSON, unknown fields, or an oversized request
may close the connection without a JSON response.

Request:

```json
{"version":1,"id":"gui-1","command":"hello"}
```

`version: 1` and `command` are required. `id` is optional (up to 64 bytes) and is
echoed in the response; it correlates requests but does not deduplicate them.
`config` is valid only for `start` and `after` only for `events`. Optional
`instance` and `session` guard daemon mutations, and `challenge_id` and `answers`
are used only by `auth_reply`; see [CONTROL.MD](CONTROL.MD). Do not send fields
the server does not know.

Example `hello` response from Windows (capability values vary by platform;
`core`, most `ikev2` fields, and other optional fields are omitted):

```json
{
  "version": 1,
  "id": "gui-1",
  "instance": "0123456789abcdef0123456789abcdef",
  "daemon_session_guards": true,
  "status": {
    "State": "disconnected",
    "Attempt": 0,
    "Since": "2026-10-06T17:00:00Z",
    "LastError": ""
  },
  "capabilities": {
    "platform": "windows",
    "vpn": true,
    "proxy": true,
    "ipv4": true,
    "ipv6": true,
    "ip_split": true,
    "domain_split": true,
    "geoip_split": true,
    "geosite_split": true,
    "geodata_schema": "v2ray-protobuf",
    "app_split": false,
    "kill_switch": true,
    "daemon": true,
    "ikev2": {"supported": true, "foreground_only": true, "kill_switch": true, "dns_protection": true, "stats": false},
    "explicit_access": ["shadowsocks", "socks5", "http", "https", "vless", "ssh", "trojan", "naive", "masque", "hysteria2", "tuic", "anytls", "vmess", "naive_quic"],
    "access_conversion": true,
    "reconnect_now": true,
    "kill_switch_hold": true
  }
}
```

`explicit_access` lists the protocols that `[AccessKey]` accepts as explicit
`Type = ...` parameters (see [CONF.MD](CONF.MD)); `naive_quic` is `Type = naive`
with `Network = quic`. Offer a parameter form only for listed protocols. An older
core omits the field and supports only the first nine entries.

`reconnect_now` and `kill_switch_hold` describe the recovery contract (see
[Reconnect recovery and kill switch hold](#reconnect-recovery-and-kill-switch-hold));
older cores omit them.

`access_conversion` reports the `bimeron document` operations `access_to_fields`
and `access_to_uri`, which convert `[AccessKey]` between a share URI and explicit
parameters (see [DESKTOP_DOCUMENT_API.MD](DESKTOP_DOCUMENT_API.MD)). An older core
omits it; the mobile libraries report `false` because they have no document
bridge.

`geoip_split`, `geosite_split`, and `geodata_schema` describe GeoIP/GeoSite rule
support (see [GEODATA.MD](GEODATA.MD)). `ikev2` describes the native Windows IKEv2
backend independently of the top-level packet capabilities (see
[Native IKEv2 boundary](#native-ikev2-boundary)).

Field casing: `status` contains `State`, `Attempt`, `Since`, `LastError`, and the
optional `ErrorStage`, `ReconnectAttempt`, `ReconnectLimit`, `ReconnectCycle`,
`ReconnectPhase`, `NextAttemptAt`, `KillSwitch`, `Session`, and `native`; each
event contains `Time`, `State`, `Code`, `Message`, `Attempt`, `LastError`, and
the optional `ErrorStage`, `ReconnectAttempt`, `ReconnectLimit`,
`ReconnectCycle`, `ReconnectPhase`, `NextAttemptAt`, and `KillSwitch` (see
[Reconnect recovery and kill switch hold](#reconnect-recovery-and-kill-switch-hold)).
All other RPC fields use snake_case. Do not normalize names. `Time`, `Since`,
and `NextAttemptAt` are RFC 3339 timestamps that may include fractional seconds
and a time zone; display them in local time. `instance` identifies the daemon process and changes
after a restart. Check `version`, `id` (if sent), and `error`, and ignore unknown
response fields. A response without `error` means the command was accepted; it
does not mean the VPN is connected.

## Commands and lifecycle

| Command | Additional fields | Behavior |
|---|---|---|
| hello | none | Status, version, instance, capabilities |
| version | none | Same as hello; used to read `core` |
| capabilities | none | Capabilities of the running core |
| status | none | Authoritative current state |
| start | `config`: absolute path; optional `instance` | Accepts the profile and connects asynchronously |
| events | `after`: event number, initially 0 | History, cursor, `dropped` |
| stats | none | Statistics of the last session |
| stats_snapshot | none | Statistics bound to a session; see [CONTROL.MD](CONTROL.MD#optional-session-bound-statistics) |
| auth_pending / auth_reply | `challenge_id`, `answers` for reply | Interactive SSH authentication; see [below](#ssh-profile-editor-and-interactive-authentication) |
| reconnect_now | optional `instance` and `session` | Ends a pending recovery wait or retries a failed session with a held kill switch; see [below](#reconnect-recovery-and-kill-switch-hold) |
| stop | optional `instance` and `session` | Disconnects the session, releases a held kill switch, and waits for cleanup; the daemon keeps running |
| shutdown | none | Disconnects the session and exits the daemon or service |

Start example:

```json
{"version":1,"id":"gui-2","command":"start","config":"C:\\VPN\\main.conf"}
```

States: `disconnected`, `connecting`, `connected`, `reconnecting`, `stopping`,
`failed`. `Attempt` is an attempt number, not a progress percentage. Setup can
take a long time, so do not treat a successful `start` response as an enabled
VPN. An initial connection fails after a bounded number of retries; an
established session that loses its server stays in `reconnecting` until it
recovers or is stopped. Access during reconnection is not guaranteed: the core
keeps the tunnel and tries to restore the upstream transport. With the kill
switch enabled, a failed session keeps protection until `stop`; see
[Reconnect recovery and kill switch hold](#reconnect-recovery-and-kill-switch-hold).

A typical GUI flow:

1. Connect to IPC, send `hello`, and save `instance` and `capabilities`.
2. Read `status`; do not impose a state the GUI saved earlier.
3. When the user clicks "Connect", send `start` once and display the core state.
4. Poll `events` about once per second, and `status` every 1–2 seconds or after
   `dropped` or an error. Poll `stats` about once per second while connected.
5. To disconnect, send `stop` and wait for cleanup to finish. Do not use
   `shutdown` for a regular "Disconnect" button.
6. Closing the GUI window does not stop the service or the VPN. Implement
   "disconnect on exit" only as an explicit user setting.

Run IPC off the UI thread. Practical client timeouts are 5 seconds for `status`
and up to 2 minutes for `stop` and `shutdown`. A disconnected client does not stop
an accepted session or cancel server cleanup. After a `start` timeout, check
`status` instead of repeating `start` blindly; `stop` is safe to repeat. To switch
profiles, send `stop`, wait for cleanup, then `start` with the new absolute path.
The only exception is a failed session with a held kill switch, which `start`
with another kill switch profile replaces directly. Hot reload, pause, and
general single-command profile switching are not implemented.

To avoid acting on stale state, a daemon that reports `daemon_session_guards: true`
accepts `instance` on `start` and `instance` plus `session` on `stop` and
`reconnect_now`; see
[Daemon session guards](CONTROL.MD#daemon-session-guards).

## Events and reconnecting the GUI

The `events` response contains an array of `{sequence, event}`, a `cursor`, and,
when history was lost, `dropped: true`. The last 128 events are kept; this is
polling, not a subscription. Order events by `sequence`. `after` is a JSON uint64;
in JavaScript, mind the exact-integer limit of `Number` for very large values.

When `instance` changes, reset `after` to 0 and reread `status` and `stats`. Even
an `invalid_cursor` response contains `instance`, so check for a restart first.
On `dropped`, reread `status`: a truncated history cannot reconstruct every
transition. After losing IPC, show "core unavailable" separately from "VPN
disconnected": kill switch filters may remain after a process crash.

## Errors

| `error` | GUI action |
|---|---|
| `unsupported_protocol` | Show that the core and GUI versions are incompatible |
| `invalid_request`, `unknown_command` | Client implementation error |
| `invalid_cursor` | Check `instance`, reset the cursor |
| `absolute_config_path_required` | Pass the absolute profile path |
| `invalid_configuration` | Offer to review or edit the profile; `problems` explains why |
| `session_already_running` | Reread `status`; do not start a second process |
| `kill_switch_held` | A failed session holds the kill switch and the new profile does not keep it; offer `stop` first |
| `reconnect_not_pending` | No recovery wait is pending and no failed session is held; reread `status` |
| `session_start_failed` | Reread `status` and `LastError` |
| `session_stop_failed` | Show a cleanup problem; do not report a successful disconnect |
| `daemon_shutting_down` | Wait for exit and reconnect to IPC later |
| `stale_instance`, `stale_session` | A guarded request used outdated state; reread `hello` and `status` |
| `invalid_auth_challenge`, `invalid_auth_response` | Reread `auth_pending`; the challenge expired or the answer was invalid |
| `ikev2_requires_foreground_user_session` | Use the foreground IKEv2 contract instead of daemon `start` |
| `response_too_large` | Client implementation or server limit error |

`Status.LastError` and `Event.Code`/`Event.LastError` are diagnostic codes, and
the set can grow: for an unknown code, show a generic message and the code.
`Event.Message` is useful for logs, not for program logic or error detection.
Response `error`, `Status.LastError`, and `Event.LastError` values are catalog
codes; take user-facing texts from the catalog ([ERRORS.MD](ERRORS.MD)).
`LastError` never contains free text: a failure without a specific code is
`connection_failed`. Codes ending in `_run_recover` mean the user must run network
recovery. Progress codes in `Event.Code` (`state`, `retry`, `network_setup`, and
similar) are not catalog codes.

After a cleanup failure, do not run `start` or `recover` automatically without a
user decision. `recover` removes remaining settings and protection, which can
allow direct network access. RPC has no `recover` command.

## Statistics and their limits

`stats` contains int64 counters: `tcp_total`, `tcp_active`, `tcp_failed`,
`udp_total`, `udp_active`, `udp_failed`, `dns_queries`, `dns_failed`, `bytes_up`,
`bytes_down`, `routed_proxy`, `routed_direct`, and `routed_block`. The counters
cover the session and its reconnections. They reset when a new `start` is
accepted, remain readable after `stop`, and are lost when the daemon restarts.
Each counter is read atomically, but a snapshot is not an atomic view of the
whole group.

Byte counters measure handler payload, not physical adapter counters or the exact
volume of encrypted traffic. TCP `bytes_up` and `bytes_down` update after every
successful write, including partial writes, without waiting for the connection to
close. Calculate speed from byte differences and monotonic time between
snapshots, and reset the baseline when `instance` or `Session.id` changes. The
result is handler payload throughput and excludes transport overhead.

## Profiles and secrets

The GUI stores the profile list and the selected profile. The core has no RPC to
list or create profiles and never returns the profile path. `status.Session`
describes the last accepted `start`:

```json
{"id":"0123456789abcdef0123456789abcdef","profile_id":"<64 hex>","profile_name":"Main","active":true,"mode":"vpn","ipv6":"disable","kill_switch_requested":true,"server_tcp":"192.0.2.10:443","server_udp":"192.0.2.11:53","server_tcp_name":"tcp.example","server_udp_name":"udp.example"}
```

- `id` is new for each `start` and survives reconnection.
- `active` means the lifecycle has not finished, including `connecting`,
  `reconnecting`, and `stopping`; it is not a synonym for `connected`. After the
  session ends, `Session` remains with `active: false`. After a daemon restart,
  it is absent until the first `start`.
- `profile_name` comes from `[Profile] Name`, limited to 128 Unicode characters
  with control characters removed. It is user text: render it as plain text, not
  HTML.
- `server_tcp` and `server_udp` are the transport addresses selected after the
  VPN transport check, and they update on reconnection. If the key used a domain
  name, `server_tcp_name` and `server_udp_name` keep that name for display next to
  the address. In SOCKS mode, `server_tcp` is the configured upstream, which the
  dialer resolves later; MASQUE also reports `server_udp`. These fields are
  available through the Windows service, the Linux/macOS daemon, the in-process
  Engine, and Apple `RLStatus`. Treat them as the current connection and show them
  only in the `connected` state. They are excluded from doctor output and events.

`profile_id` is the lowercase hex SHA-256 of the normalized absolute `.conf` path
in UTF-8: `filepath.Abs` and `filepath.Clean`, plus `strings.ToLower` on Windows.
Symbolic links are not resolved. The ID depends on the path, not the content:
moving the file changes it, editing the file in place does not. In Go, use
`core.ProfileIdentity(path)`; a GUI can compute IDs for its own profiles with the
same algorithm. An equal ID does not prove the file is unchanged. A session
started without a file may have no ID or name.

Older cores do not return `Session`. If it is missing or `profile_id` matches no
known profile, show "unknown profile" instead of guessing. Name and ID are for
local IPC, not public reports; doctor deliberately omits them.

Do not confuse capabilities with session settings: `capabilities.kill_switch`
does not mean the selected profile enables protection.
`Session.kill_switch_requested` reflects the profile request; check filter
availability and effectiveness separately. `Session` is optional, so protocol
version 1 is unchanged.

Minimal profile:

```ini
[Profile]
Version = 1
Name = Main

[AccessKey]
File = test.key

[Interface]
Mode = vpn
Name = Bimeron
MTU = 1420
DNS = 1.1.1.1, 8.8.8.8
IPv6 = disable
KillSwitch = true

[Routing]
Default = proxy

[Rule]
CIDR = 203.0.113.0/24, 198.51.100.1
Action = direct
```

On macOS, use `KillSwitch = false`: a profile requesting it fails at start with
`kill_switch_unsupported_on_macos`.

- `[AccessKey]` takes exactly one source: `File`, a protocol-specific URI field
  such as `SS`, `SSConf`, `VLESS`, or `SSH`, a generic `Key`, or explicit
  parameters with `Type`. [CONF.MD](CONF.MD) lists every source. A relative
  `File` is resolved against the `.conf` file, not the GUI working directory.
- Keys are stored in plaintext: restrict ACLs and permissions, and keep keys out
  of logs, analytics, Git, and crash reports.
- `DNS` takes 1 to 4 distinct unicast IPv4 addresses separated by commas; the
  default is `1.1.1.1`.
- `Routing.Default` is `proxy`, `direct`, or `block`. `Rule.CIDR` accepts single
  IPs, CIDR ranges, and lists. Rules are checked top to bottom until the first
  match. More specific existing OS routes can bypass the tunnel.

Save the profile before `start`, preferably by atomically replacing the file.
Editing the file does not change the active session; stop and start again.
`SSConf` keys are resolved again on reconnection. SYSTEM or root must be able to
read the profile and its `File` key; user-mapped drives and EFS may be
inaccessible. To validate without network access, run `bimeron validate <config>`
and check the exit code. [CONF.MD](CONF.MD) is the full format reference; this
example does not replace it for a complete settings editor.

### VMess profile importer

Accept base64 JSON `vmess://` links as the sole `VMess`, `Key`, or `File`
source. Preserve the complete link; the core validates AEAD (`aid=0`),
TCP/TLS or REALITY, WebSocket/TLS, HTTPUpgrade/TLS, gRPC/TLS or REALITY,
and XHTTP over TLS or REALITY, including SNI, path, optional TLS fingerprint,
ALPN, and encryption. XHTTP accepts HTTP/2 and HTTP/3 with the modes in the
transport matrix and an optional JSON-string `extra` field.
Unsupported fields and transports produce validation errors. The core
supports VMess TCP and UDP in VPN mode. Do not display the user ID or full
link in diagnostics. See [VMess transport matrix](VMESS_TRANSPORTS.MD).

### SSH profile editor and interactive authentication

SSH supports `[Interface] Mode = proxy` for a local SOCKS5 listener and
`Mode = vpn` for system TCP routing through SSH. Label VPN mode as TCP-only:
proxied non-DNS UDP is dropped, captured DNS uses TCP over SSH, and explicitly
direct-routed traffic remains outside the tunnel. Do not present it as a full
VPN or promise that applications with their own DNS cannot bypass the tunnel.
The GUI can import `ssh://user@host:22` as `SSH = ...` or write explicit
`Type = ssh`, `Server`, `Port`, and `Username` fields. Provide file pickers for
the identity and `known_hosts`; save absolute paths as `IdentityFile` and
`KnownHostsFile`. The service account may have a different home directory, so do
not rely on its `~/.ssh` defaults. Save the `.conf` atomically before `start`.

While connecting, poll the protected local control socket with
`{"version":1,"command":"auth_pending"}`. If the reply contains `auth`, show
each `prompts` entry with masking controlled by its matching `echo` value.
Send `{"version":1,"command":"auth_reply","challenge_id":"...","answers":["..."]}`.
The supported challenge kinds are `key_passphrase`, `password`, and
`keyboard_interactive`. An answer is used once and is never stored in the
profile, GUI settings, logs, status, or diagnostics. The core times out the
challenge after two minutes. Older cores reply `unknown_command` to
`auth_pending`; hide interactive authentication for them. See
[SSH.MD](SSH.MD) for the full wire contract, examples, and security limits.

### Trojan profile editor

For standard Trojan over TCP/TLS, write `Type = trojan`, `Server`, `Port`,
and `Password`. `ServerName` optionally overrides the TLS certificate name
and SNI. Alternatively, write a single `Trojan = trojan://...` or
`Key = trojan://...` source, or point `File` at such a link. Do not combine a link
source with explicit parameters. Reject unsupported link options rather than
silently dropping them. The core supports TCP and UDP through Trojan in VPN
mode; the local SOCKS5 proxy listener remains TCP only. Never display the
password in status or diagnostics.

Offer `Network = tcp|ws|grpc` with TLS. WS uses `WSPath` and `WSHost`;
gRPC uses required `GRPCServiceName`, optional `GRPCAuthority`, and
`GRPCMultiMode`. `ALPN` defaults to `http/1.1` for WS and `h2` for gRPC.
Keep SNI (`ServerName`) separate from HTTP Host/authority. Do not expose
REALITY, early data, custom gRPC paths, or insecure TLS for Trojan. See
[Trojan transport compatibility](TROJAN_TRANSPORTS.MD).

### Hysteria2 profile editor

Write one `Hysteria2 = hysteria2://server:port?auth=replace-me&sni=name&insecure=0&alpn=h3`,
`Key`, or `File` source. The `hy2://` alias and the older
`hysteria2://replace-me@server:port?sni=name` form are also accepted.
Percent-encode reserved password characters. Supply the password in exactly
one place: `auth` or URI userinfo. `sni` is optional and defaults to the
server hostname. `insecure=0` retains verified TLS; `insecure=1` is rejected.
The only accepted ALPN value is `h3`, which is offered by the Hysteria2 HTTP/3
client. Use a Hysteria2-specific QUIC fingerprint selector:

- Default: omit `fp`, preserving the core's existing ChromeParrot behavior.
- Firefox 116A: `firefox` or `firefox-116` (aliases; preserve the imported spelling).
- Firefox 116B: `firefox-116b`.
- Firefox 116C: `firefox-116c`.
- Chrome 115: `chrome-115` (legacy ALPS and GREASE ECH).
- Chrome 146: `chrome-146` (hybrid key share and two-datagram Initial flight).
- Chrome: `chrome`, the pinned apernet ChromeParrot preset, not a versioned
  uquic Chrome 115/146 preset.

The values are case-sensitive. Reject explicit empty values, unknown values,
and duplicate options. Never remove `fp` silently or fall back to a different
preset. Do not reuse VLESS/TCP's fingerprint list. The core applies the chosen
preset to the wire handshake. Address-family selection is automatic from the
resolved endpoint; the GUI must not append IPv4/IPv6 suffixes.
The versioned names describe the recorded Initial handshakes of official Chrome
for Testing 115.0.5790.170 and 146.0.7680.165; they do not promise complete
browser emulation. Keep `chrome` and an omitted `fp` unchanged.

For bimeron-desktop, this changes the previous contract as follows:

1. Import, preserve, and export one `fp` parameter from the list above; allow
   the complete query-auth URI ending in `&fp=firefox#label`.
2. Replace the previous unconditional Firefox rejection with the selector and
   exact allowlist. Keep unknown presets visible as unsupported until edited.
3. Continue exactly one password source (`auth` or userinfo), verified TLS,
   optional `sni`, and only `h3` ALPN. Omitted `fp` stays omitted on export.
4. Keep passwords and complete URIs out of errors, status, and diagnostics.
5. Gate these choices on a bundled core build containing ADR 0010. Older
   builds, including the previous `feat/hysteria2` binary, reject `fp`; no
   minimum released version has been assigned yet. Use `bimeron validate`
   before activating a profile and do not infer support from the development
   version string alone.
6. Gate `chrome-115` and `chrome-146` separately on a bundled core containing
   ADR 0011; ADR 0010 alone does not establish versioned Chrome support. Never
   migrate saved profiles automatically, and show unsupported imported values
   without dropping them.

Explain that these emulate historical QUIC handshakes, not an entire browser.
TLS resumption/0-RTT are disabled; compatible RSA/ECDSA server certificates are
required (Ed25519 is not offered). VPN mode uses TCP and UDP relay; local proxy
mode exposes TCP CONNECT. The server must support UDP relay. The existing
upstream UDP message-size and TCP half-close limitations still apply; see
[CONF.MD](CONF.MD#hysteria2-over-quic).

### TUIC profile editor

Write one `TUIC = tuic://...` source, a generic `Key = tuic://...`, or a
`File` containing the link. Require a UUID and password. The supported UDP
relay mode is `quic`; reject native mode and unknown options. Certificate
verification is mandatory. See [CONF.MD](CONF.MD) for the URI contract.

### Remote HTTP CONNECT profile editor

Write `HTTP = https://proxy.example.com:443`, or use `Type = https` with
`Server`, `Port`, and optional paired `Username` and `Password`. `Key` and `File`
also accept HTTPS proxy URIs. Require an explicit port and percent-encode URI
credentials. Do not combine explicit parameters with a URI source.

HTTPS uses verified HTTP/1.1 CONNECT: system CA trust and the configured proxy
hostname or IP are checked before Basic credentials are sent. There is no
server-name override or insecure TLS switch. Plain `http://` and `Type = http`
remain available but do not encrypt proxy credentials. Both variants carry TCP
only; VPN DNS uses TCP and other proxied UDP is dropped. The local listener
remains SOCKS5. See [configuration](CONF.MD#remote-http-connect-proxy).

### Remote SOCKS5 and Shadowsocks profile editors

The profile's upstream protocol is independent of `[Interface] Mode`: `vpn`
installs a system tunnel, while `proxy` opens a local SOCKS5 listener.
Use the following `[AccessKey]` fields when the user enters connection details:

```ini
[AccessKey]
Type = socks5
Server = proxy.example.com
Port = 1080
Username = alice
Password = secret
```

Omit both `Username` and `Password` for no authentication. For an imported URI,
write exactly one source such as
`Key = socks5://alice:secret@proxy.example.com:1080` or
`SOCKS5 = socks5://proxy.example.com:1080`. Encode reserved credential
characters in the URI. A `File` source may point to a UTF-8 file containing
that URI. Do not write `Type` alongside a link source.

For an explicit Shadowsocks profile, write `Type = shadowsocks` (the `ss`
alias is accepted), plus `Server`, `Port`, `Method`, and `Password`; `Prefix`
is optional. `Type` is required for all explicit parameter groups. An SS or
SSConf link still uses `SS`, `SSConf`, or `Key` without `Type`. Do not infer
`shadowsocks` when `Type` is missing.
For SS2022 AES methods, preserve `Password` as a complete SIP023 chain
`iPSK0:iPSK1:...:uPSK`, including every colon and base64 padding character.
The final key is the user key; preceding keys identify successive layers.
Each key has the method-specific length. ChaCha20 accepts a single key only.
The chain remains a secret and must not appear in logs or validation errors.

For embedded Shadowsocks WS/WSS, preserve the complete imported `ss://` URI,
including its percent-encoded `plugin` query. Do not extract only the cipher,
password, and endpoint: doing so would discard the required transport. For an
explicit parameter form, write `Plugin = v2ray-plugin` and `PluginOpts` alongside
the Shadowsocks parameters. Do not write these fields alongside a URI source.
See [Shadowsocks transport examples](SHADOWSOCKS_TRANSPORTS.MD).

Expose only the supported plugin options (`mode=websocket`, `tls`, `host`,
`path`, `mux`), with defaults from that guide. In particular, `host` controls
both HTTP Host and TLS SNI/certificate verification, and defaults to
`cloudfront.com`. Omit `tls` to disable TLS; `tls=false` enables it by presence.
Keep the imported URI and raw options out of logs and analytics.

For plugin profiles, indicate TCP-only proxying and DNS over TCP; disable
controls that imply proxied UDP support. Explicit direct routes retain their
usual behavior. Mux concurrency is a limit per shared WebSocket connection,
not a global connection limit. The embedded client requires no executable
picker or plugin process installation.

Run `bimeron validate <config-file>` for syntax and field checks without
network access or system changes. `bimeron check -config <config-file>` tests
the remote transport over the network without installing a VPN: TCP/TLS and
UDP/DNS in VPN mode, TCP/TLS only for SOCKS5 in local `proxy` mode. In VPN mode,
Shadowsocks plugin profiles instead test TCP/TLS and DNS over TCP. For SOCKS5,
the remote SOCKS5 server must support both TCP `CONNECT` and UDP `ASSOCIATE`;
failure to relay UDP/DNS prevents startup. Local `proxy` mode needs only TCP
`CONNECT`. The current VPN implementation resolves Shadowsocks and SOCKS5
upstream hosts to IPv4 without a plugin; Shadowsocks plugin profiles, VLESS,
Trojan, and Hysteria2 may use IPv6.
DNS settings, MTU, split rules, and direct/block actions use the same GUI
controls for SOCKS5 and Shadowsocks. The upstream SOCKS5 connection is not
encrypted by SOCKS5; explain this when users choose the protocol. Keep
credentials out of status displays, logs, analytics, and crash reports.

`bimeron inspect <key-file>` reports the protocol `type` (for example `socks5`,
`shadowsocks`, `vless`, or `hysteria2`) without the username or password.
Plugin profiles still report `type` as `shadowsocks`; `inspect` does not expose
plugin settings, and their UDP endpoint is empty. Do not use it to reconstruct a
complete access profile or infer the plugin configuration.

## Installation, updates, and diagnostics on Windows and Linux

Request elevation only for explicitly selected administrative actions:

```text
bimeron.exe service install [-automatic]
bimeron.exe service start
bimeron.exe service stop
bimeron.exe service update -source <absolute-path> -version <version> -sha256 <executable-sha256>
bimeron.exe service describe
bimeron.exe service uninstall
bimeron.exe recover
```

Linux uses the same commands without `.exe`; `install` also accepts
`-owner <uid>`. The GUI runs administrative actions through `pkexec`; status and
IPC do not require root. The core is copied to `/usr/local/lib/bimeron` and the
unit to `/etc/systemd/system/bimeron-core.service`. The socket stays accessible
only to root and the installation owner.

`install` sets a manual start by default; `-automatic` starts the service when
the OS boots. This does not connect the VPN automatically. The service
description is "VPN core and local control".

Run `service update` from the trusted core bundled in the installed GUI package,
not from the installed service binary, and pass the downloaded executable with
the version and SHA-256 from a verified release manifest. The update disconnects
the VPN, keeps the owner and startup type, replaces the executable, and returns
the service to its previous state. The Wintun DLL is not updated. On failure, it
tries to restore the old executable; if that is impossible, it keeps a backup and
reports an error. After an update or rollback, the VPN connects only on an
explicit `start`. See [SERVICE.MD](SERVICE.MD) for details.

Ship the CLI for the target architecture with `wintun.dll` for the same
architecture, `WINTUN-LICENSE.txt`, and the dependency licenses. Installation
copies the executable, DLL, and Wintun license to the protected
`Program Files\Bimeron Core` directory. Windows code signing and macOS
notarization are not implemented yet.

Doctor is a CLI command, not an RPC: `bimeron.exe doctor` or
`bimeron.exe doctor -output <new-file.json>`. It writes JSON with `schema: 1`,
reads only, and makes no external requests or network changes. WFP inspection
requires an elevated console; other checks may work for a regular user. The report
contains no keys, IP addresses, URLs, or profile paths. Let the user review or
save the report before sending it to anyone. Present filters do not prove their
effectiveness, and route counters are a snapshot. If Defender's controlled folder
access protects Documents, save stdout through a trusted shell instead of
disabling the protection automatically. `-output` never overwrites an existing
file.

## Verification status and required GUI tests

On October 8, 2026, a Windows service crash and a Windows reboot were checked:
SCM restarted the service without connecting the VPN, the kill switch and DNS
rules persisted, direct traffic was blocked, and `recover` cleaned up. Service
deletion while pending and an interactive access-denial check from another
account remain unverified.

Automated tests cover cancelling a local HTTPS `ssconf` fetch while waiting for
headers and while reading the body, cancelling reconnection, waiting for network
settings rollback, and rejecting a new `start` until rollback finishes. The
rollback test simulates network setup; it does not change a real Windows system.
The service ACL was checked with Windows `AccessCheck`: the owner is allowed and a
foreign SID is rejected. A separate named pipe test confirms that the owner can
connect without elevation. No interactive second-account login was performed, so
do not present the ACL check as a full multi-user test. Linux requires real
network changes, and macOS requires utun, route, and DNS checks on a Mac. Run
tests, vet, cross-builds, and Apple shell checks before a release.

Each GUI should test: `hello` and version incompatibility; start to `connected`;
stop and start again; profile switching; recovery waits, Retry now, and a failed
session with a held kill switch; IPC or permission denial; `dropped` and
a changed `instance`; restarting the GUI while the VPN is connected; regular
control without administrator rights; saving diagnostics; and no secrets in logs.
Do not kill the core process when closing the GUI window, and do not run
`recover` automatically to fix connection errors.

## Apple NetworkExtension: a separate control path

Besides the CLI/daemon backend, a technical Apple shell without a GUI is
available. The NetworkExtension session is controlled through
`NETunnelProviderManager` and `NETunnelProviderSession`, not the console daemon's
Unix socket. The Go/C ABI, `packetFlow`, Keychain, status and event messages, and
packaging limits are described in
[APPLE_NETWORK_EXTENSION.MD](APPLE_NETWORK_EXTENSION.MD). Choose one backend and
never run both VPNs at once. The NetworkExtension bundle is currently built
unsigned only, and a signed launch has not been verified: this is a contract, not
a finished VPN product.

## Native IKEv2 boundary

The experimental Windows IKEv2 backend uses a pre-provisioned current-user
profile and an elevated foreground process. Do not offer it through daemon
`start`: IPC rejects it with `ikev2_requires_foreground_user_session`. Read the
separate `capabilities.ikev2` object instead of inheriting top-level packet
features. Hide packet rules, packet kill switch settings, DNS/MTU overrides, and
traffic charts for this backend. A separate native protection option may use
`ikev2.kill_switch` and `ikev2.dns_protection`; explain its activation and
retained recovery behavior before enabling it. Native statistics are explicitly
unavailable. See [IKEV2.MD](IKEV2.MD) for configuration, profile requirements, and
unverified live behavior.

## Reconnect recovery and kill switch hold

<a id="bounded-reconnect-recovery-desktop-030"></a>

The full contract is in
[CONTROL.MD](CONTROL.MD#reconnect-recovery-and-kill-switch-hold). In short:

- **Initial connection** (before the first `connected` of a run, including
  auto-connect): the first attempt plus up to 3 retries (1, 2, 4 second
  backoff), then `failed`. A nonretryable failure is `failed` at once.
- **Loss of an established session**: recovery continues until success or an
  explicit stop, in cycles of up to 10 attempts (1, 2, 4, 8, then 15 second
  backoff) separated by a 60 second `waiting` phase. A connection that drops
  again within 1 minute continues the previous cycle position. After loss,
  failures such as an unavailable `ssconf` key, a TLS rejection or SSH
  authentication are retried too; `LastError` keeps the specific code. Codes
  ending in `_run_recover`, a failed session close and a maintenance seal still
  end in `failed`.
- A backoff or `waiting` ends early on `reconnect_now`, a change of local
  network interfaces or a resume from sleep. An attempt in progress is never
  interrupted.
- Native IKEv2 keeps the bounded policy (3 retries) without cycles.

With `KillSwitch = true` (VPN mode, Windows and Linux), protection is installed
before the first network activity of a run and held through every attempt,
wait and `failed`, until `stop` or `shutdown`. A run that fails keeps
`Session.active: true` with `KillSwitch: "holding"`; `reconnect_now` restarts
its initial attempts, and `start` with another kill switch profile in VPN mode
replaces it without releasing protection. Any other `start` returns
`kill_switch_held`. With the kill switch disabled, there is no guarantee that
traffic does not leave outside the tunnel while connecting, reconnecting or
after `failed`.

Status and every Event carry optional fields; zero values are omitted:

| Field | Values |
|---|---|
| `ReconnectAttempt`, `ReconnectLimit` | 1–3 of 3 during initial retries, 1–10 of 10 within a cycle; omitted during `waiting`. `ReconnectAttempt` stays in `failed` after the initial attempts. |
| `ReconnectCycle` | Current or most recent cycle (1-based) after loss; omitted during initial attempts. During `waiting`, the cycle that just failed. |
| `ReconnectPhase` | `attempting` (an attempt is scheduled, with `NextAttemptAt`, or running, without it) or `waiting` (pause between cycles); omitted outside `reconnecting`. |
| `NextAttemptAt` | RFC 3339 UTC, whole seconds: start of the next scheduled attempt or cycle; omitted when nothing is scheduled. Core host clock. |
| `KillSwitch` | `active` (protection installed, `connected`) or `holding` (protection installed, the tunnel carries no traffic: `connecting`, `reconnecting`, held `failed`, `stopping`); omitted when the run owns no protection (kill switch disabled, proxy mode, IKEv2) and after the run ends. |

New progress events: `reconnect_wait`, `reconnect_attempt` (also at the start of
a cycle), `reconnect_requested`, `kill_switch_holding` and `kill_switch_held`;
`network_changed` and `resume_detected` also report an early end of a wait.
Status stays authoritative. `Attempt` is cumulative per Start, not a recovery
counter; do not infer a limit from it or count log messages.

### Desktop 0.3.0 compatibility

Desktop 0.3.0 shows a counter only when the state is `reconnecting` and
`1 ≤ ReconnectAttempt ≤ ReconnectLimit`. It ignores the new fields, events,
capabilities and command. With this Core it shows:

| Core phase | Status fields 0.3.0 reads | Desktop 0.3.0 shows |
|---|---|---|
| Initial retries | `reconnecting`, `ReconnectAttempt` 1–3, `ReconnectLimit` 3 | "Reconnecting… (n/3)", unchanged |
| Attempt in a cycle after loss | `reconnecting`, `ReconnectAttempt` 1–10, `ReconnectLimit` 10 | "Reconnecting… (n/10)" |
| `waiting` between cycles | `reconnecting`, no `ReconnectAttempt` | "Reconnecting…" without a counter |
| Failed, kill switch held | `failed`, `LastError` | The failure and `LastError`, as before. Connect sends `start`: a profile with the kill switch takes over without releasing protection; another profile gets `kill_switch_held`, shown as an unknown error code. Disconnect sends `stop`, which releases protection. |
| Failed, kill switch disabled | `failed`, `LastError` | Unchanged |

IPC remains version 1 and profile format remains 1.
The GUI range in `release/compatibility.json` is widened to include Desktop
0.3.1 by the release that ships it.

### Guidance for Desktop 0.3.1

- `ReconnectPhase: "waiting"`: show "Server unavailable · retry in m:ss",
  counting down to `NextAttemptAt`.
- `attempting`: show "Reconnecting… (n/N)" from `ReconnectAttempt` and
  `ReconnectLimit`.
- `KillSwitch: "holding"`: show "Internet paused until VPN connects", including
  in `failed`. `active` needs no extra notice.
- While `reconnecting` with `NextAttemptAt` set, or in `failed` with
  `KillSwitch: "holding"`, offer **Retry now** (`reconnect_now`, only when
  `capabilities.reconnect_now` is `true`) and **Disconnect** (`stop`). Send
  `instance` and `session` as for `stop`. On `reconnect_not_pending`, reread
  `status`: an attempt has already started or the session changed.
- On `start` with `kill_switch_held`, explain that protection is held by the
  failed session and offer Disconnect before connecting with that profile.
