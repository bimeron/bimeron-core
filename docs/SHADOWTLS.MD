# ShadowTLS v3

ShadowTLS v3 is an optional wrapper around an encrypted TCP upstream. It
authenticates and disguises the stream but does not encrypt the forwarded
application payload. Bimeron retains the inner protocol's encryption and
TLS/REALITY or SSH server verification.

Support described here applies to this source revision. For a released package,
read the documentation at its release tag.

## Configure a wrapped upstream

The server must run ShadowTLS v3 in strict mode, forward authenticated streams
to the selected inner proxy, and reach a TLS 1.3 handshake target. The inner
proxy must accept the protocol configured in `[AccessKey]`.

```ini
[Profile]
Version = 1
Name = Shadowsocks through ShadowTLS

[AccessKey]
SS = ss://aes-256-gcm:replace-inner-password@proxy.example.com:443

[ShadowTLS]
ServerName = handshake.example.com
Password = replace-shadowtls-password

[Interface]
Mode = proxy
Listen = 127.0.0.1:1080

[Routing]
Default = proxy
```

The SS URI points to the public ShadowTLS listener, not directly to its backend.
`replace-inner-password` authenticates the inner Shadowsocks proxy;
`replace-shadowtls-password` authenticates the outer wrapper. The server chooses
the backend address. Bimeron does not expose a second backend-address setting.

For an inner TLS or REALITY protocol, its existing `ServerName`/`sni` remains
the backend's name. `[ShadowTLS] ServerName` identifies the separate handshake
target. See [the VLESS gRPC example](../examples/shadowtls-vless.conf) for both
names in one profile, or [the Shadowsocks example](../examples/shadowtls-ss.conf).
File-based and dynamic access sources can use the same optional section.

With the Go API, set the optional field on the inner `core.Profile`:

```go
profile.ShadowTLS = &core.ShadowTLS{
    ServerName: "handshake.example.com",
    Password:   "replace-shadowtls-password",
}
```

Keep the existing inner profile type and credentials, and point its TCP endpoint
at the public ShadowTLS listener. The engine validates each resolved profile.

Save real profiles under the ignored `profiles/` directory. Validate and run:

```sh
go run ./cmd/bimeron validate profiles/shadowtls.conf
go run ./cmd/bimeron check -config profiles/shadowtls.conf
go run ./cmd/bimeron run profiles/shadowtls.conf
```

`validate` checks static configuration without connecting. `check` requires
working server credentials and tests the upstream connection, including DNS
where the selected protocol's check applies. A dynamic
source is fetched during `check` or startup and checked again after refresh.

## Supported combinations

All rows require strict v3 and a verified TLS 1.3 handshake target.

| Inner upstream | Supported transport inside ShadowTLS | UDP in VPN mode |
| --- | --- | --- |
| Shadowsocks AEAD | AES-128-GCM, AES-256-GCM, ChaCha20-IETF-Poly1305 over TCP | No; captured DNS uses TCP |
| Shadowsocks 2022 | The three supported `2022-blake3-*` methods over TCP | No; captured DNS uses TCP |
| VLESS | Existing TCP/TLS, WS/TLS, gRPC and HTTP/2 XHTTP combinations; permitted REALITY and Vision combinations | Existing UDP-over-stream |
| VMess AEAD | Existing TCP, WS, HTTPUpgrade, gRPC and HTTP/2 XHTTP combinations with TLS/REALITY | Existing UDP-over-stream |
| Trojan | TCP/TLS, WebSocket/TLS, gRPC/TLS | Existing UDP-over-stream |
| AnyTLS | TLS with existing session reuse and padding | UDP-over-TCP v2 |
| NaiveProxy-compatible | TLS with HTTP/2 CONNECT and padding | No; captured DNS uses TCP |
| SSH | Existing encrypted forwarding and host-key verification | No; captured DNS uses TCP |

The wrapper does not enable new inner transports: the restrictions in
[VLESS transports](VLESS_TRANSPORTS.MD), [VMess transports](VMESS_TRANSPORTS.MD)
and [SSH](SSH.MD) still apply. Split XHTTP requires a ShadowTLS listener at both
upload and download addresses, with the same outer password and handshake name.
The inner settings for each leg remain independent.

Plain SOCKS5, plaintext HTTP CONNECT, bare plaintext inner modes, Hysteria2,
TUIC and HTTP/3 cannot use this wrapper. AES-192-GCM remains available for
unwrapped Shadowsocks but is rejected in wrapped profiles because the selected
independent inner-server fixture does not implement that cipher.

## UDP and routing

ShadowTLS carries TCP bytes, not native UDP. VLESS, VMess, Trojan and AnyTLS
retain the UDP framing they already carry inside their TCP streams. Wrapped
Shadowsocks uses the existing TCP-only VPN policy: captured DNS is forwarded
through the proxy using DNS-over-TCP, and other proxy-routed UDP is dropped.
Explicit `direct` routes retain their normal physical-network behavior.
The local SOCKS5 listener remains TCP `CONNECT` only.

Failed authentication never falls back to an unwrapped connection. Bootstrap
DNS and control-plane connections keep their existing physical-interface path;
application streams use the supplied interface binding and protected sockets.

## Verification and limits

Tests use the unchanged official ShadowTLS `v0.2.25` server, pinned inner
reference servers, local TLS targets and synthetic credentials. They cover
large SOCKS5/Engine requests, TCP and retained UDP-over-stream, reconnects,
Vision TLS 1.3 traffic, split XHTTP, invalid authentication/certificates,
malformed records, timeouts, cancellation and socket controls. The SSH backend
uses an SSH protocol fixture; this is not an OpenSSH interoperability claim.

The outer handshake uses the pinned uTLS Chrome profile, TLS 1.3 and HTTP/1.1
ALPN; its settings are fixed. This does not claim browser-identical traffic,
resistance to a particular censorship system, every inner fingerprint/extra-
option combination, or live mobile/system-VPN validation. See
[the recorded matrix and evidence](SHADOWTLS_V3_RESEARCH.md),
[ADR 0023](adr/0023-shadowtls-v3-wrapper.md) and [CI checks](CI.MD).
