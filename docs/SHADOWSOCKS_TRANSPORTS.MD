# Shadowsocks transports

Shadowsocks and Shadowsocks 2022 support direct TCP/UDP connections and an
embedded `v2ray-plugin` client for WebSocket (WS) or WebSocket over TLS (WSS).
The embedded client requires no plugin executable on the user's device.
The server must provide the matching `v2ray-plugin` transport.

| Transport | TCP | Proxied UDP in VPN mode | Captured DNS |
| --- | --- | --- | --- |
| Direct Shadowsocks | Yes | Yes | UDP with TCP fallback |
| Shadowsocks + WS/WSS | Yes | No | TCP through Shadowsocks |

The local SOCKS5 listener supports TCP `CONNECT` only for both transports.
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
settings inside that source instead. Omit `PluginOpts` to use upstream defaults.

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

## Supported plugin options

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

Unknown or duplicate options, malformed escapes, other plugins, executable
paths, server mode, QUIC, Hysteria2 transport, endpoint overrides, `cert`,
`certRaw`, `key`, plugin logging, and socket-tuning options are rejected.
There is no option to disable certificate verification. Unlike the original
plugin's permissive parser, Bimeron rejects unsupported settings explicitly.
Combining a Shadowsocks plugin with a `[ShadowTLS]` wrapper is unsupported and
rejected; the core never silently omits either configured transport.

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

Idle pooled connections retire after 30 seconds. A session whose receive
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
