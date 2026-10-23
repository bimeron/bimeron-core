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
| `tcp` | `reality` | Empty, `xtls-rprx-vision` or `xtls-rprx-vision-udp443` | `sni`, `fp`, `pbk`; optional `sid`, `spx` |
| `tcp` | `tls` | Empty | Optional `sni`, `fp`, `alpn` |
| `ws` | `tls` | Empty | Optional `path`, `host`, `ed`; `alpn` must be `http/1.1` if supplied |
| `grpc` | `tls` or `reality` | Empty | Required `serviceName`; optional `authority`, `mode=multi`; REALITY requires `sni`, `fp`, `pbk`; `alpn` must be `h2` if supplied |
| `xhttp` | `tls` | Empty | Required `mode=packet-up`, `stream-up` or `auto`; optional `path`, `host`; `alpn` may be `h2`, `h2,http/1.1`, or `h3` |
| `xhttp` | `reality` | Empty | Required `mode=stream-one`, `stream-up` or `auto`, `sni`, `fp`, `pbk`; optional `path`, `host`, `sid`, `spx`; `alpn` must be `h2` if supplied |

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

For gRPC, `serviceName=proxy` calls `/proxy/Tun` by default or
`/proxy/TunMulti` with `mode=multi`. A leading slash selects an explicit method
path, such as `serviceName=/proxy/Custom`. `authority` sets the HTTP/2 authority
independently of the TLS server name. The core uses `Hunk` or `MultiHunk`
framing to match the selected method. gRPC tuning fields are not supported.

For XHTTP, set `mode` explicitly. `packet-up` uses a GET download stream and
numbered POST uploads; `stream-up` uses a GET download stream and streaming
POST upload; `stream-one` uses one bidirectional POST. `auto` selects
`packet-up` with TLS and `stream-one` with REALITY. The default is HTTP/2;
`alpn=h3` selects HTTP/3 with TLS and no `fp` setting. Physical HTTP/3 UDP
sockets use the selected outbound interface. Without `extra`, these modes use
Xray's default path placement and padding. The optional `extra` query value is
a percent-encoded JSON object. The core accepts custom headers, padding and
metadata placement, packet upload data in headers or cookies, packet size and
timing settings, `downloadSettings`, and HTTP/2 xmux limits. Unknown fields and
duplicate JSON keys are errors. Use a control profile before offering any new
XHTTP variant in a GUI.

`downloadSettings` uses Xray's nested stream format. It requires an `address`,
`port`, `network: "xhttp"`, and `security: "tls"` or `"reality"`. Optional
`xhttpSettings` contains `host` and `path`; `tlsSettings` contains `serverName`
and `alpn`, while `realitySettings` contains `serverName`, `publicKey`,
`shortId`, and `fingerprint`. Nested downloads and `stream-one` downloads are
rejected. The download address resolves through the selected outbound network
before VPN routes change. Both physical connections close with the session.
Explicit xmux settings use HTTP/2 only; HTTP/3 plus xmux is rejected.

## Explicit `.conf` parameters

Set `Type = vless`, `Server`, `Port`, `ID`, `Encryption`, `Network`, and
`Security`. `Flow`, `ServerName`, `Fingerprint`, `PublicKey`, `ShortID`,
`SpiderX`, and `ALPN` follow the combination table. Transport fields are:

| Transport | `.conf` fields | Link query fields |
|---|---|---|
| WebSocket | `WSPath`, `WSHost`, `WSEarlyData` | `path`, `host`, `ed` |
| gRPC | `GRPCServiceName`, `GRPCAuthority`, `GRPCMultiMode` | `serviceName`, `authority`, `mode=multi` |
| XHTTP | `XHTTPPath`, `XHTTPHost`, `XHTTPMode`, `XHTTPExtra` or separate `XHTTP` option fields | `path`, `host`, `mode`, `extra` |

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

For extended XHTTP options, use one of these equivalent forms:

```ini
XHTTPExtra = {"headers":{"User-Agent":"Example"},"xmux":{"maxConnections":2}}
```

```ini
XHTTPHeaders = {"User-Agent":"Example"}
XHTTPXmux = {"maxConnections":2}
```

Do not combine `XHTTPExtra` with separate extended fields. Each separate
field uses the JSON name with an `XHTTP` prefix, for example
`XHTTPXPaddingBytes`, `XHTTPSessionPlacement`, and `XHTTPDownloadSettings`.
Ranges accept an integer, a quoted integer, or a quoted `from-to` range in JSON; a separate
`.conf` range accepts `from-to` without quotes. Protect values containing
credentials in files and GUI output.
`noSSEHeader`, `scStreamUpServerSecs`, and `serverMaxHeaderBytes` describe
server behavior and do not change client requests. Keep them only when
round-tripping an existing server configuration.

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

## Pending interoperability checks

Local tests cover parsing, framing and HTTP/2 exchange. With control profiles,
verify TCP and UDP through gRPC over TLS and REALITY, including `TunMulti` and
custom method paths; XHTTP `packet-up`, `stream-up`, `stream-one` and `auto`;
and repeated close and reconnect cycles. Repeat proxy and system VPN checks on
Windows, Linux, macOS, Android and iOS where supported. Include HTTP/3 over a
real UDP path. Record server version
and transport settings without storing credentials in test results.
