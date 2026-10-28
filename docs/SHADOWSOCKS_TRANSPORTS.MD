# Shadowsocks transports

Shadowsocks and Shadowsocks 2022 support direct TCP/UDP connections and an
embedded clients for `v2ray-plugin` WebSocket (WS/WSS) and `obfs-local`
simple-obfs HTTP/TLS-shaped obfuscation. Neither requires a plugin executable
on the user's device. The server must provide the matching plugin and mode.

| Transport | TCP | Proxied UDP in VPN mode | Captured DNS |
| --- | --- | --- | --- |
| Direct Shadowsocks | Yes | Yes | UDP with TCP fallback |
| Shadowsocks + WS/WSS | Yes | No | TCP through Shadowsocks |
| Shadowsocks + simple-obfs HTTP/TLS | Yes | No | TCP through Shadowsocks |

The local SOCKS5 listener supports TCP `CONNECT` only for all these transports.
In VPN mode, plugin profiles drop proxied non-DNS UDP. Explicit `direct`
routes still use the physical network. There is no fallback to direct traffic
or ordinary Shadowsocks UDP when the plugin cannot carry it.

## Import an access URI

Save this synthetic example as a `.conf` profile, replacing the server,
password, TLS hostname, and path with the server's settings:

```ini
[Profile]
Version = 1
Name = Shadowsocks WebSocket TLS

[AccessKey]
SS = ss://aes-256-gcm:replace-me@server.example.com:443/?plugin=v2ray-plugin%3Btls%3Bhost%3Dws.example.com%3Bpath%3D%2Ftunnel%3Bmux%3D8

[Interface]
Mode = proxy
Listen = 127.0.0.1:1080
```

The decoded `plugin` query value is:

```text
v2ray-plugin;tls;host=ws.example.com;path=/tunnel;mux=8
```

The URI uses the SIP002 scheme; its plugin options use the SIP003 grammar.
Percent-encode the complete query value once. Inside the decoded options,
escape literal semicolons, equal signs, and backslashes with a backslash.
For example, `path=/a\;b` represents `/a;b`, and its encoded plugin value is
`v2ray-plugin%3Bpath%3D%2Fa%5C%3Bb`.

The Shadowsocks server address selects the network endpoint. `host` selects
the HTTP Host header and, with TLS, the certificate name and SNI. These values
may differ when connecting through a reverse proxy. The TLS certificate must
be trusted by the system and valid for `host`.

## Explicit profile parameters

Instead of `SS`, use this access section with the same `[Profile]` and
`[Interface]` sections:

```ini
[AccessKey]
Type = shadowsocks
Server = server.example.com
Port = 443
Method = aes-256-gcm
Password = replace-me
Plugin = v2ray-plugin
PluginOpts = tls;host=ws.example.com;path=/tunnel;mux=8
```

`Plugin` and `PluginOpts` apply only to explicit Shadowsocks parameters.
Do not combine them with an `SS`, `Key`, `File`, or `SSConf` source; put plugin
settings inside that source instead. For `v2ray-plugin`, omit `PluginOpts` to
use upstream defaults. For `obfs-local`, the `obfs` mode is required.

Simple Shadowsocks JSON/YAML configurations returned by an HTTPS `ssconf://`
response also accept `plugin` and `plugin_opts`:

```json
{
  "server": "server.example.com",
  "server_port": 443,
  "method": "aes-256-gcm",
  "password": "replace-me",
  "plugin": "v2ray-plugin",
  "plugin_opts": "tls;host=ws.example.com;path=/tunnel;mux=8"
}
```

Plugin options cannot be combined with the separate-endpoint `tcpudp` YAML
format. A `File` key source contains an access URI, not this JSON object.
Existing Shadowsocks methods, including all three supported 2022
methods, retain their encryption and key requirements. See
[explicit Shadowsocks parameters](CONF.MD#alternative-explicit-shadowsocks-parameters).

## v2ray-plugin options

| Option | Default | Meaning |
| --- | --- | --- |
| `mode` | `websocket` | Only `websocket` is accepted. |
| `tls` | Absent: disabled | Presence enables verified TLS. Omit it for plain WS. |
| `host` | `cloudfront.com` | HTTP Host and TLS certificate name/SNI; no port suffix. |
| `path` | `/` | WebSocket request path. An empty value becomes `/`; a missing leading slash is added. |
| `mux` | `1` | Maximum concurrent sessions per pooled WebSocket; `0` disables Mux. Accepted range: `0`–`4294967295`. |

The host default matches the original plugin; it does not inherit the
Shadowsocks endpoint hostname. Set it explicitly for your deployment.
Following upstream presence semantics, **`tls=false` still enables TLS**.

With positive `mux`, sequential streams reuse connections, and concurrent
streams share a connection up to its configured session limit. Additional
streams open another connection. `mux=0` requires the server's corresponding
non-Mux mode; it is not a transparent substitute for the default server mode.

Unknown or duplicate options, malformed escapes, other plugin names, executable
paths, server mode, QUIC, Hysteria2 transport, endpoint overrides, `cert`,
`certRaw`, `key`, plugin logging, and socket-tuning options are rejected.
There is no option to disable certificate verification. Unlike the original
plugin's permissive parser, Bimeron rejects unsupported settings explicitly.
Combining a Shadowsocks plugin with a `[ShadowTLS]` wrapper is unsupported and
rejected; the core never silently omits either configured transport.

## simple-obfs options and examples

Use the canonical plugin name `obfs-local`, with a required `obfs=http` or
`obfs=tls` mode. The names `simple-obfs`, `obfs-server`, and executable paths
are rejected. This is an embedded client, not a SIP003 process launcher.

| Option | Default | Meaning |
| --- | --- | --- |
| `obfs` | Required | `http` or `tls`; must match the server. |
| `obfs-host` | `cloudfront.net` | Camouflage HTTP Host or TLS-shaped SNI, without a port suffix. Does not change the network endpoint. |
| `obfs-uri` | `/` in HTTP mode | HTTP-only origin-form URI, up to 4,096 ASCII bytes. Must begin with `/`; whitespace and non-ASCII characters must be percent-encoded. |
| `http-method` | `GET` in HTTP mode | HTTP-only method token, up to 64 bytes. |

The original HTTP transport prepends headers once and then carries raw
Shadowsocks ciphertext; it does not use WebSocket frames. The Host header
includes the configured server port unless it is 80. `obfs-uri` and
`http-method` require the later upstream implementation; the original
v0.0.5 client supports only `GET /`.

**Simple-obfs TLS mode is not a cryptographic TLS session.** It uses a
TLS-shaped handshake and records without certificate verification. The
inner Shadowsocks protocol provides encryption and authentication. It does
not use v2ray-plugin's `tls` flag, WSS, or ShadowTLS.

For HTTP, use this explicit access section:

```ini
[AccessKey]
Type = shadowsocks
Server = server.example.com
Port = 8388
Method = aes-256-gcm
Password = replace-me
Plugin = obfs-local
PluginOpts = obfs=http;obfs-host=cover.example.com;obfs-uri=/;http-method=GET
```

For TLS-shaped obfuscation, use this access URI:

```text
ss://aes-256-gcm:replace-me@server.example.com:443/?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dcover.example.com
```

Its decoded plugin value is
`obfs-local;obfs=tls;obfs-host=cover.example.com`. Percent-encode the complete
plugin query once; SIP003 backslash escaping works as described above. For
example, `obfs-uri=/a\;b%2Fc` preserves the URI `/a;b%2Fc` after import.
Simple Shadowsocks JSON/YAML also accepts `plugin: obfs-local` with
`plugin_opts: obfs=http;obfs-host=cover.example.com`.

Complete synthetic profiles are available as
[HTTP](../examples/shadowsocks-obfs-http.conf) and
[TLS-shaped](../examples/shadowsocks-obfs-tls.conf) examples.

HTTP-only options are rejected in TLS mode. Unknown options, duplicates,
missing values, malformed escapes, header injection, URI fragments, WS/Mux
options, process tuning, and combinations with `[ShadowTLS]` are rejected.
The camouflage host does not inherit the server hostname. VPN profiles remain
TCP-only: captured DNS uses TCP and other proxy-routed UDP is dropped.

Each stream uses its own TCP connection. Closing either direction closes
that stream, matching the original server; it does not close independent
streams. Framing errors terminate the connection, and application bytes are
not replayed. The client bounds setup to 15 seconds or the caller's earlier
deadline, honors cancellation during setup, and closes owned sockets at
runtime shutdown. Canceling a completed dial does not close its stream.

Original v0.0.5 and final-upstream server tests cover HTTP/TLS with six
AEAD/2022 methods, AES SS2022 multi-user identities, concurrency, transfers,
and shutdown. Custom Host/method/URI cases use final upstream. AES-192-GCM has
a synthetic HTTP peer test rather than an independent Xray case. These checks
do not claim mobile-device or packet-VPN data-plane interoperability.
See [reference checks](CI.MD#simple-obfs-reference-checks) and
[ADR 0027](adr/0027-embedded-simple-obfs-client.md).

## Validate and run

```sh
go run ./cmd/bimeron validate profiles/shadowsocks-ws.conf
go run ./cmd/bimeron check -config profiles/shadowsocks-ws.conf
go run ./cmd/bimeron run profiles/shadowsocks-ws.conf
```

`validate` checks configuration without connecting. `check` tests TCP/TLS and
DNS over TCP without installing a VPN. To use the system VPN, change
`Mode = proxy` to `Mode = vpn` and follow the platform setup instructions in
[configuration](CONF.MD). Real access profiles must remain outside version control.

## Connection limits and verification

For v2ray-plugin, idle pooled connections retire after 30 seconds. A session whose receive
queue exceeds 256 KiB is closed so it cannot stall other sessions. Closing
either stream direction closes that logical session; true TCP half-close is
not provided. Failure of a shared connection, including an interrupted frame
write, ends its active sessions. New streams reconnect; application data is
not automatically replayed.

Interoperability tests use the original `v2ray-plugin` v1.5.0 and Xray
v1.260327.0 as an independent Shadowsocks server. The matrix covers six
AEAD/2022 methods over WS/WSS with Mux 0/1/8, plus defaults, concurrency,
reuse, TLS rejection, large transfers, reconnection, and cleanup. AES-192-GCM
has a local encryption/transport test; it is outside that Xray matrix.
See [CI and local reference checks](CI.MD#shadowsocks-v2ray-plugin-reference-checks)
and [ADR 0022](adr/0022-embedded-shadowsocks-v2ray-plugin.md).
