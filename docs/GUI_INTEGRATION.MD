# Bimeron Core: integration of individual GUI projects

Current as of October 23, 2026. This document can be copied into a separate project:
it describes the implemented contract without requiring access to other repository
files. Recheck the contract against core changes made after this date.

For VLESS profile editors and importers, read [VLESS_TRANSPORTS.MD](VLESS_TRANSPORTS.MD).
It lists the supported link and `.conf` fields, transport combinations,
validation behavior and current interoperability limits. A GUI should write a
profile file and use the existing `start` RPC; no new VLESS RPC is required.

## Project separation

Core is developed separately. GUI for each platform is a separate project.
The GUI manages profiles, status displays, and user settings;
core handles network operations, key resolution, routing, DNS,
reconnection and cleaning. The profile format is `.conf`, the local RPC format is JSON.

The main way to integrate desktop GUI is IPC with a running service/daemon.
Queries are available from any language that supports named pipes/Unix sockets.
The CLI remains available. Do not parse the stdout text of status/watch commands as an API.
For Go there is a package `bimeron/core`: New, LoadConfig, Start, Stop, Status,
Events, Stats, Wait, PlatformCapabilities. Embedding the engine into the GUI process
will require rights for network operations; IPC maintains privileges in a separate process.

## The first stage of using IPC with an external GUI

No GUI is created in this repository. The first integration stage verifies that RPC supports a separate future GUI
project. GUI source code and dependencies belong in that separate project.

The first stage of a separate Windows GUI project needs an installed
BimeronCore service and the existing RPC. The user selects an existing `.conf`,
then the external client follows these steps:

1. Sends `hello`, checks the protocol version and reads the core capabilities.
2. Reads `status` and accepts the service state as authoritative.
3. Transfers the absolute path of the selected profile to `start`.
4. Shows status, safe error code, events and general statistics.
5. At the user's command, sends `stop` and waits for the cleaning to complete.

The existing RPC version 1 is sufficient for this; no core changes required.
The GUI only stores a list of paths and the selected profile. Contents `.conf`, keys and
passwords are not transmitted via RPC and do not end up in settings, logs or GUI analytics.
The files remain protected by the user's ACL and are read directly by the service.

The description of the first stage does not include the profile editor, service installation,
`recover`, `shutdown`, auto-connection, core update, system tray,
notifications, Linux/macOS and app routing. Decisions on their implementation
are accepted in the corresponding GUI repository, not in Bimeron Core.

Requirements for external client automatic checks: incompatible version;
unavailable or prohibited IPC; launch to `connected` or `failed`; stop;
restart; change `instance`; `dropped=true`; unknown error code; absence
secrets in logs. A separate manual check confirms that the service is controlled from
a regular user without elevation.

## Platform support

| Platform | System VPN | Crash protection | Management |
|---|---|---|---|
| Windows amd64/arm64 | Wintun, TCP/UDP | WFP kill switch, if enabled | SCM service or console daemon, named pipe |
| Linux amd64/arm64 | TUN, TCP/UDP | nftables kill switch, if enabled; does not survive reboot | root daemon, Unix socket |
| macOS Intel/Apple Silicon | Experimental utun backend | Kill switch not implemented | root daemon, Unix socket |
| Android | Packet engine; host app supplies `VpnService` | Host responsibility | [AAR integration](ANDROID_VPN_SERVICE.MD); desktop IPC is not a mobile VPN API |
| iOS | Platform integration not implemented | Not implemented | No iOS VPN host |

The separate [macOS NetworkExtension integration](APPLE_NETWORK_EXTENSION.MD)
provides a packet engine and Swift provider; deployment requires signing and
provisioning. It does not use the experimental CLI `utun` backend above.

Read capabilities from the running core through hello/capabilities. These report
build support; they do not check whether a driver, permissions, or server is available.

Hello and the new version RPC command return an optional core field:
version (for development builds, the nearest reachable Git tag plus `-dev`), revision (Git SHA), commit_time, modified,
go_version, platform, architecture. This is the data of the running daemon/service,
not a GUI or a separate CLI. Do not confuse core.version with version=1 protocol.
For dev builds, compare revision and modified, and not just the same line
tag-derived development version. If there is no VCS data, revision/commit_time may be missing.
The old core may not have the core field - display an unknown version.
CLI `version` shows its assembly; `version -daemon` - running core.
DomainSplit is now true on Windows, Linux and macOS; system domain rules
VPNs use limited DNS metadata and do not cover DoH/DoT, direct IP and
old DNS cache. AppSplit remains false; Don't promise per-application routing.
SOCKS proxy - TCP, without UDP ASSOCIATE.
macOS requires testing on a real Mac; Windows service has already been manually checked
for connection, normal stop, restart and service update.

## Transport and access

The Windows service BimeronCore runs under LocalSystem. Its pipe is:

```text
\\.\pipe\Bimeron.Core.Service
```

Access is granted to the SYSTEM and SID of the user who installed the service. GUI of this
the user can work without elevation of rights. If UAC used another
administrator account, the owner will be that account.
If access denied, report a rights problem; Don't silently switch to another core.

Console daemon Windows uses:

```text
\\.\pipe\Bimeron.Core.<user-hash>
```

user-hash = first 16 bytes of the SHA256 UTF-8 string of the current user's SID,
represented by 32 lowercase hex characters. Access: this user and SYSTEM.
Prefer service channel. Fallback to console daemon should only be done when
missing service channel (ERROR_FILE_NOT_FOUND), like the current CLI. Pipe busy or
access denied does not mean the service is missing. Remote pipe connections are prohibited.

Linux: `/run/bimeron/control.sock`.
macOS: `/var/run/bimeron/control.sock`.
The socket mode is 0600. The client UID must be root or the launch owner via
SUDO_UID. The normal GUI is accessed by running the daemon via sudo from the same
user; The Linux systemd service passes the stored owner UID via
BIMERON_CONTROL_UID. Daemon launched directly by root without these
variables, accessible only by root. Installation of launchd is not yet implemented.

Do not run console daemon next to the service. Parallel daemon have different
channels, but only one system VPN session is allowed on a machine.

## RPC: version 1

One request and one response per connection. UTF-8 JSON + LF; after answer connection
closes. Socket/pipe - byte stream: read up to LF, do not expect the whole response in one
read. Request limit 16 KiB with LF; the client limits the response to 256 KiB.
The server waits for a request for up to 5 seconds. Invalid JSON, unknown fields and excess
limit may result in the connection being closed without a JSON response.

Request:

```json
{"version":1,"id":"gui-1","command":"hello"}
```

version=1 and command are required. id is optional, maximum 64 bytes; returns
in the answer. This is a correlation, not a deduplication mechanism. config is only valid for
start, after only for events. Do not add fields that the server does not know.

Reply hello (form example, capability values ​​vary by platform):

```json
{
  "version": 1,
  "id": "gui-1",
  "instance": "0123456789abcdef0123456789abcdef",
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
    "app_split": false,
    "kill_switch": true,
    "daemon": true
  }
}
```

Register feature: status contains State, Attempt, Since, LastError and an optional Session;
nested Event contains Time, State, Code, Message, Attempt, LastError.
The remaining RPC fields use snake_case. Don't normalize names arbitrarily.
Time - RFC3339 with possible fractional part and time zone; show locally.
Instance is unique to the daemon instance and changes after restart.
Check version, id (if specified), error; ignore unknown response fields.
The absence of error means the success of the command; it does not guarantee connected.

## Commands and lifecycle

| Command | Additional fields | Behavior |
|---|---|---|
| hello | no | Status, version, instance, capabilities |
| capabilities | no | Capabilities of the running core |
| status | no | Authoritative Current State |
| start | config: absolute path | Accepts profile and connects asynchronously |
| events | after: event number, initially 0 | History, cursor, dropped |
| stats | no | Statistics of the last session run |
| stop | no | Disconnects the session and waits for cleaning, daemon remains |
| shutdown | no | Disconnects the session and ends the daemon/service |

Start example:

```json
{"version":1,"id":"gui-2","command":"start","config":"C:\\VPN\\main.conf"}
```

States: disconnected, connecting, connected, reconnecting, stopping, failed.
Attempt - attempt number, not percentage of progress. The connection may remain for a long time
connecting and repeat when the network is unavailable. VPN cannot be considered enabled
just because start returned success. There is no guarantee of access when reconnecting
to Outline; core saves the tunnel and tries to restore the transport.

Example GUI script:

1. Connect to IPC, send hello and save instance/capabilities.
2. Get status; do not impose local state previously saved by the GUI.
3. When you click “Connect”, send start once, display the core state.
4. Poll events approximately once per second; status every 1–2 seconds or after
dropped/errors. Stats can be polled once per second when connected.
5. When disconnecting, send stop and wait for the cleaning to complete. Do not use
shutdown for the regular "Shutdown" button.
6. Closing the GUI window does not stop the service or VPN. Implement
   "disconnect on exit" only as an explicit user setting.

Perform IPC work outside the UI thread. Practical client timeout: 5 seconds
to read status, up to 2 minutes for stop/shutdown. Losing a client doesn't stop
accepted session and does not cancel the server cleanup. After timeout start check
status rather than repeating start blindly. Stop can be repeated safely.
Changing profile: stop, wait for clearing, then start with a new absolute path.
Hot reload, pause and profile switching with one RPC command are not implemented.

## Events and GUI connection recovery

The events response contains an array of `{sequence, event}`, cursor and, if necessary,
dropped=true. The last 128 events are stored; This is polling, not subscription.
The order is given by sequence. After - JSON uint64; for JavaScript respect the limit
accurate representation of Number for very large values.

When changing instance, reset after=0, re-read status and stats. Even the answer with
invalid_cursor contains instance - check restart first. When dropped
re-read status: it is impossible to restore all transitions from a truncated history.
After an IPC break, display “core unavailable” separately from “VPN disabled”:
kill switch filters may remain after a process crash.

## Errors

| error | GUI Action |
|---|---|
| unsupported_protocol | Show incompatibility between core and GUI versions |
| invalid_request/unknown_command | Client implementation error |
| invalid_cursor | Check instance, reset cursor |
| absolute_config_path_required | Pass profile absolute path |
| invalid_configuration | Suggest profile review/edit |
| session_already_running | Reread status; do not create a second process |
| session_start_failed | Reread status and LastError |
| session_stop_failed | Show cleanup problem, don't report shutdown success |
| daemon_shutting_down | Wait for completion and restore IPC later |

Status.LastError and Event.Code/LastError are diagnostic codes. They can
expand: for unknown code, show the general message and code. Event.Message
good for logging, but not for logic control or error detection.
After cleanup failure, do not perform automatic start/recover without a solution
user. Recover removes remaining settings and protection so it can
allow direct access to the network. There is no separate recover command in RPC.

## Statistics and their limitations

Stats contains int64: tcp_total, tcp_active, tcp_failed, udp_total, udp_active,
udp_failed, dns_queries, dns_failed, bytes_up, bytes_down, routed_proxy,
routed_direct, routed_block. The counters are common to the session and its reconnections.
Reset upon successful acceptance of a new Start, saved after Stop;
When the daemon is restarted, the previous statistics are lost. Snapshot of individual atomics
counters is not an atomic snapshot of the entire group.

Bytes - bytes counted by handlers, not physical adapter counters or
the exact volume of encrypted traffic. TCP bytes_up/down are now updated after
each successful data write, until the connection is closed, including partial writes.
The GUI speed is calculated by the difference between Bytes and the monotonic time between snapshots.
When changing instance or Session.id, reset the previous measurement point.
This is the processor payload speed, not guaranteed to match the readings
network card and without taking into account all overhead transport.

## Profiles and secrets

The list and the selected profile are stored by the GUI. Core does not provide RPC for
enumerate/create profiles and does not return the profile path. In the new core
status.Session contains the data of the last accepted Start:

```json
{"id":"0123456789abcdef0123456789abcdef","profile_id":"<64 hex>","profile_name":"Main","active":true,"mode":"vpn","ipv6":"disable","kill_switch_requested":true,"server_tcp":"192.0.2.10:443","server_udp":"192.0.2.11:53","server_tcp_name":"tcp.example","server_udp_name":"udp.example"}
```

id is new for each Start, saved after reconnection. active means
unfinished life cycle, including connecting/reconnecting/stopping; This
not a synonym for connected. After completion, the Session is saved with active=false,
when restarting, the daemon is missing until the first Start. profile_name is taken from
[Profile] Name, limited to 128 Unicode characters, control characters removed.
This is a custom label, output it as plain text, not HTML.

Optional server_tcp/server_udp - actually selected transport addresses
VPN after successful verification; when reconnecting they are updated. If the original key
contained a domain, server_tcp_name/server_udp_name save it for address signing.
For SOCKS, server_tcp contains a configured upstream that the dialer can allow
Later. The fields are available equally through Windows service, Linux/macOS daemon,
console Engine and Apple RLStatus. Consider them the current connection and show
to the user only with State=connected. They are not included in doctor and events.

profile_id = lowercase SHA256 UTF-8 normalized absolute path `.conf`:
filepath.Abs ​​+ filepath.Clean, on Windows additionally strings.ToLower.
Symbolic links are not expanded. The identifier is relative to the path, not
content: moving a file changes the ID, changing a file in the same path does not.
Go API: core.ProfileIdentity(path). The GUI can calculate the IDs of its profiles by
this algorithm; the same ID does not prove that the contents of the file are unchanged.
When running softly without a file, the ID/name may be missing.

The old core does not return Session. If it is not there or profile_id does not match
with known GUI profiles, show "profile unknown" rather than guess.
Name/ID data is for local IPC, not for public reporting:
doctor specifically does not include them.
Do not confuse capabilities with the current session settings: capabilities.kill_switch
does not mean that the user has enabled protection in the selected profile.
Session.kill_switch_requested describes the profile request; availability/effectiveness
filters need to be checked separately. Version=1 is retained: the Session field is optional.

Minimum profile:

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

For macOS KillSwitch=false: true is rejected until the network changes. In AccessKey
choose exactly one source: File, SS=ss://..., SSConf=ssconf://...,
SOCKS5=socks5://..., VLESS=vless://..., VMess=vmess://...,
Trojan=trojan://..., Hysteria2=hysteria2://..., TUIC=tuic://...,
SSH=ssh://..., Key, or explicit parameters. File is allowed
relative to `.conf`, not the GUI working directory. The keys are now plaintext:
limit ACL/permissions and exclude from logs, analytics, Git and crash reports.
DNS - from 1 to 4 different unicast IPv4 separated by commas; absence gives 1.1.1.1.
Routing.Default: proxy/direct/block; Rule.CIDR accepts separate IP and CIDR,
including lists. The rules are checked from top to bottom until the first match is made.
Existing more specific OS routes can bypass tunnel hijacking.

The GUI saves the profile before start, preferably by atomically replacing the file.
Changing the file does not change the rules of the active session: you need to stop/start.
SSConf is resolved again on reconnections. SYSTEM/root must have access
to the profile and File key; custom mapped drives and EFS may not be available.
Validation without a network: run CLI `validate <config>` and check the exit code.
Full format help is available in the core repository, docs/CONF.MD; this example does not
replace it when developing a full-fledged editor for all settings.

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
The GUI can import
`ssh://user@host:22` as `SSH = ...` or write explicit `Type = ssh`, `Server`,
`Port`, and `Username` fields. Provide file pickers for the identity and
`known_hosts`; save absolute paths as `IdentityFile` and `KnownHostsFile`.
The service account may have a different home directory, so do not rely on
its `~/.ssh` defaults. The GUI saves the `.conf` atomically before `start`.

While connecting, poll the protected local control socket with
`{"version":1,"command":"auth_pending"}`. If the reply contains `auth`, show
each `prompts` entry with masking controlled by its matching `echo` value.
Send `{"version":1,"command":"auth_reply","challenge_id":"...","answers":["..."]}`.
The supported challenge kinds are `key_passphrase`, `password`, and
`keyboard_interactive`. An answer is one-use and is never stored in the
profile, GUI settings, logs, status, or diagnostics. The core times out the
challenge after two minutes. Older cores reply `unknown_command` to
`auth_pending`; hide interactive authentication for them. See
[SSH.MD](SSH.MD) for the full wire contract, examples, and security limits.

### Trojan profile editor

For standard Trojan over TCP/TLS, write `Type = trojan`, `Server`, `Port`,
and `Password`. `ServerName` optionally overrides the TLS certificate name
and SNI. Alternatively, write a single `Trojan = trojan://...` or `Key =
trojan://...` source, or point `File` at such a link. Do not combine a link
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

### Remote SOCKS5 profile editor

The profile's upstream protocol is independent of `[Interface] Mode`: `vpn`
installs a system tunnel, while `proxy` opens a local TCP SOCKS5 listener.
Use the following `[AccessKey]` fields when the user enters connection details:

```ini
[AccessKey]
Type = socks5
Server = proxy.example.com
Port = 1080
Username = alice
Password = secret
```

`Username` and `Password` are both omitted for no authentication. For an
imported URI, write exactly one source such as
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

Run `bimeron validate <config-file>` for syntax and field checks without
network access or system changes. `bimeron check -config <config-file>` tests
the remote transport over the network without installing a VPN: TCP/TLS and
UDP/DNS in VPN mode, TCP/TLS only for SOCKS5 in local `proxy` mode. In VPN mode,
the remote SOCKS5 server must support both TCP `CONNECT` and UDP `ASSOCIATE`;
failure to relay UDP/DNS prevents startup. Local `proxy` mode needs only TCP
`CONNECT`. The current VPN implementation resolves Shadowsocks and SOCKS5
upstream hosts to IPv4; VLESS, Trojan, and Hysteria2 may use IPv6.
DNS settings, MTU, split rules, and direct/block actions use the same GUI
controls for SOCKS5 and Shadowsocks. The upstream SOCKS5 connection is not
encrypted by SOCKS5; explain this when users choose the protocol. Keep
credentials out of status displays, logs, analytics, and crash reports.
`bimeron inspect <key-file>` reports `type` as `socks5`, `trojan`, `hysteria2`, or `shadowsocks`
without reporting the username or password.

## Installation, update and diagnostics of Windows/Linux

Elevate rights only for explicitly selected administrative actions:

```text
bimeron.exe service install [-automatic]
bimeron.exe service start
bimeron.exe service stop
bimeron.exe service update
bimeron.exe service describe
bimeron.exe service uninstall
bimeron.exe recover
```

On Linux, the same commands are used without `.exe`; install additionally accepts
`-owner <uid>`. The GUI triggers administrative actions via `pkexec`, and status
and IPC do not require root. Core is copied to `/usr/local/lib/bimeron`, unit - to
`/etc/systemd/system/bimeron-core.service`. Socket remains accessible only
root and the owner of the installation.

Install is manual by default, -automatic enables the service to start when the OS boots.
This is not an automatic VPN connection. Description: VPN core and local control.
Update run from new project/supplied EXE, not installed EXE
services. It disables VPN, saves owner/autorun, replaces EXE and returns
service to its previous state. Wintun DLL does not update. If there is an error, it tries to return
old EXE; if recovery is impossible, saves a backup and reports an error.
VPN after update/rollback is connected only by explicit start.

Deliver CLI for the desired architecture and wintun.dll of the same architecture, together
with WINTUN-LICENSE.txt and dependency licenses. The installation copies EXE, DLL and
Wintun license to the protected directory Program Files/Bimeron Core.
Windows signing and macOS notarization are not yet implemented.

Doctor is a separate CLI command, not an RPC:
`bimeron.exe doctor` or `doctor -output <new-file.json>`.
Format JSON schema=1. Read only, no external requests or network changes.
WFP inspection requires an elevated console; other checks may work
ordinary user. The report does not contain keys, IPs, URLs or profile paths.
The GUI should show/offer to save the report before sending it to anyone.
The presence of filters does not prove their effectiveness; route counters - snapshot.
When protecting Documents in Defender, it is possible to save stdout through a trusted
shell; do not disable protection automatically. CLI -output does not overwrite the file.

## Deferred checks and mandatory GUI tests

October 8, 2026, Windows service crash and Windows reboot were checked:
SCM restart without automatic VPN connection, saving kill switch and DNS
rules, blocking direct traffic and cleaning via `recover`. Pending deletion
services and interactive verification of access denial from another account.

Autotests check for overriding local HTTPS ssconf while waiting for headers and
reading the body, canceling reconnect, waiting for the network settings to be rolled back and prohibiting new ones
Start before it ends. The network setup in the rollback test is simulated, not changed.
on working Windows. Service ACL checked Windows AccessCheck: owner allowed,
foreign SID rejected. A separate named pipe checks the owner's connection
without elevation of rights. There was no interactive login to the second account;
Don't pass off an ACL check as a full manual Windows multi-user test.
Do not mark those checks as completed. Linux requires real network changes;
macOS requires utun, route, and DNS checks on a Mac. There is no macOS kill switch.
Run tests, vet, cross-builds, and Apple shell checks before release.

For each GUI, check: hello and version incompatibility; start to connected;
stop and start again; profile switching; IPC/rights denial; dropped and changed
instance; restarting the GUI when the VPN is already connected; lack of admin rights
for normal control; saving diagnostics; lack of secrets in logs.
Do not terminate the core process to close the GUI window and do not run recover as
automatic way to fix any connection error.
## Apple NetworkExtension - a separate management method

In addition to the existing CLI/daemon backend, a technical Apple shell has been prepared
without GUI. The NE session is controlled by `NETunnelProviderManager` and
`NETunnelProviderSession`, non-Unix socket of the console daemon.
Go/C ABI, packetFlow, Keychain, status/events messages and packaging restrictions
are described in [APPLE_NETWORK_EXTENSION.MD](APPLE_NETWORK_EXTENSION.MD).
The GUI should select one backend and not run both VPNs at the same time.
At this stage, the NE bundle is only built unsigned; real signed launch
not verified. This is a preparation of a contract, not a statement of a ready-made VPN system.

### Desktop changes for issue #23

Add exactly `chrome-115` and `chrome-146` to the Hysteria2 allowlist and selector.
Preserve these exact strings on import/export. Keep `chrome` and omitted `fp`
unchanged; never migrate saved profiles automatically. The password, TLS, SNI,
ALPN and error-redaction contracts are unchanged. Gate the new entries on a
bundled core containing ADR 0011 and successful `bimeron validate`; ADR 0010
alone does not establish versioned Chrome support. No released minimum version
has been assigned. Show unsupported imported values without dropping them.
These presets do not claim full browser equivalence; see ADR 0011.
