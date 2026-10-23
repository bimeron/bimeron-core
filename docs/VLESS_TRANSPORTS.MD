# VLESS transport contract for core and GUI projects

This document describes the VLESS formats implemented by Bimeron Core. It is
intended for external GUI projects such as bimeron-desktop. A GUI can copy this
document, but the installed core's `validate` command remains authoritative.
The transport extensions below have local protocol tests; interoperability with
independent gRPC and XHTTP servers and system VPN on physical devices still
requires control profiles.

## Supported combinations

| `type` / `Network` | `security` / `Security` | `flow` / `Flow` | Extra options |
|---|---|---|---|
| `tcp` | `reality` | `xtls-rprx-vision` or `xtls-rprx-vision-udp443` | `sni`, `fp`, `pbk`; optional `sid`, `spx` |
| `tcp` | `tls` | Empty | Optional `sni`, `fp`, `alpn` |
| `ws` | `tls` | Empty | Optional `path`, `host`, `ed`; `alpn` must be `http/1.1` if supplied |
| `grpc` | `tls` | Empty | Required `serviceName`; `alpn` must be `h2` if supplied |
| `xhttp` | `tls` | Empty | Required `mode=packet-up`; optional `path`, `host`; `alpn` must be `h2` if supplied |
| `xhttp` | `reality` | Empty | Required `mode=stream-one`, `sni`, `fp`, `pbk`; optional `path`, `host`, `sid`, `spx`; `alpn` must be `h2` if supplied |

`encryption=none` is required for every VLESS link. Explicit parameters use
`Encryption = none`. Unsupported combinations and unknown or duplicate link
options are errors. The server's TLS certificate and name are verified for
`security=tls`. REALITY authentication is verified with the supplied public
key; the `spx` value is retained for link compatibility and does not enable
Xray's decoy-site crawler. The listed `fp` values are `chrome`, `firefox`,
`safari`, `ios`, `android`, and `edge`.

## Importing a link

Use exactly one `[AccessKey]` source. The simplest GUI output is:

```ini
[Profile]
Version = 1
Name = Example

[AccessKey]
VLESS = vless://123e4567-e89b-12d3-a456-426614174000@server.example:443?encryption=none&security=tls&type=grpc&serviceName=proxy

[Interface]
Mode = vpn

[Routing]
Default = proxy
```

The UUID and server above are placeholders. `File = relative-key.txt` can
instead refer to a file containing a complete link. `Key = vless://...` is
accepted for compatibility. A link fragment becomes the profile label.
Bracket IPv6 server literals, for example `@[2001:db8::1]:443`. Percent-encode
reserved characters in query values. Subscription URLs are not imported by
this contract.

Additional placeholder link shapes:

```text
vless://123e4567-e89b-12d3-a456-426614174000@server.example:443?encryption=none&security=tls&type=ws&path=%2Fchat%3Fed%3D2048
vless://123e4567-e89b-12d3-a456-426614174000@server.example:443?encryption=none&security=tls&type=xhttp&mode=packet-up&path=%2Fstream
```

WebSocket early data accepts `ed=N` as a top-level link query option or inside
the encoded `path`, for example `path=%2Fchat%3Fed%3D2048`. The two forms
cannot be combined. `N` must be from 1 through 8192. The core sends the first
VLESS write in the `Sec-WebSocket-Protocol` header when it fits the limit;
otherwise it sends normal WebSocket data. The early data value is removed from
the actual WebSocket path. Custom early data header names are not supported.

For gRPC, `serviceName` names the server service. The core uses its `Tun`
bidirectional stream and the standard `Hunk` data field. `TunMulti`, custom
method paths and gRPC tuning fields are not supported.

For XHTTP, set `mode` explicitly. `packet-up` uses a GET download stream and
numbered POST uploads; `stream-one` uses one bidirectional POST. Both use
HTTP/2 and Xray's default path placement and padding. `stream-up`, `auto`,
HTTP/3, `downloadSettings`, xmux, custom headers, custom padding and placement
options are not supported. Use a control profile before offering any new XHTTP
variant in a GUI.

## Explicit `.conf` parameters

Set `Type = vless`, `Server`, `Port`, `ID`, `Encryption`, `Network`, and
`Security`. `Flow`, `ServerName`, `Fingerprint`, `PublicKey`, `ShortID`,
`SpiderX`, and `ALPN` follow the combination table. Transport fields are:

| Transport | `.conf` fields | Link query fields |
|---|---|---|
| WebSocket | `WSPath`, `WSHost`, `WSEarlyData` | `path`, `host`, `ed` |
| gRPC | `GRPCServiceName` | `serviceName` |
| XHTTP | `XHTTPPath`, `XHTTPHost`, `XHTTPMode` | `path`, `host`, `mode` |

Example XHTTP profile with placeholder credentials:

```ini
[Profile]
Version = 1
Name = Example XHTTP

[AccessKey]
Type = vless
Server = server.example
Port = 443
ID = 123e4567-e89b-12d3-a456-426614174000
Encryption = none
Network = xhttp
Security = tls
ServerName = server.example
XHTTPMode = packet-up
XHTTPPath = /stream

[Interface]
Mode = proxy
```

`WSPath` defaults to `/`; `WSHost` defaults to `ServerName`, then `Server`.
`XHTTPPath` defaults to `/`; `XHTTPHost` defaults the same way. XHTTP normalizes
the path to end with `/`. For `.conf`, set `WSEarlyData` separately from
`WSPath`. Avoid showing credentials in logs, telemetry, URLs used for error
reports or GUI previews.

## GUI behavior and verification

Store the user's link or parameters in a protected `.conf` file and send its
absolute path to the core's existing `start` RPC. The GUI does not need a new
RPC command or a transport-specific VPN implementation. Run `bimeron validate
path/to/profile.conf` before connecting; it checks syntax without network or
system changes. `bimeron check -config path/to/profile.conf` performs TCP/TLS
and UDP/DNS checks through the configured upstream. Start completion is
asynchronous: show the core's reported `connected`, `reconnecting` or `failed`
state rather than treating an accepted `start` RPC as a connected VPN.

The core's proxy mode exposes a local SOCKS5 TCP listener. VPN mode routes TCP
and UDP through the VLESS client; XUDP carries UDP. The transport's physical
connections use the selected outbound interface to avoid recursive VPN
routing. Full system VPN and mobile platform behavior must be verified on each
target platform with working server profiles. The current implementation has
no transport-specific capability flags in RPC; use core version and `validate`
to decide whether a profile is accepted.
