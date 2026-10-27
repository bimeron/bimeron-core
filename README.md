# Bimeron Core

Bimeron Core is a Go networking engine that turns a supported access profile into a local
SOCKS5 proxy or a system VPN.

[![CI](https://github.com/bimeron/bimeron-core/actions/workflows/go.yml/badge.svg)](https://github.com/bimeron/bimeron-core/actions/workflows/go.yml)
[![Release](https://img.shields.io/github/v/release/bimeron/bimeron-core?include_prereleases)](https://github.com/bimeron/bimeron-core/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Building a VPN application also requires tunnel setup, routing, DNS, connection state, and
recovery. Bimeron Core handles these tasks for its CLI and for applications using local IPC, the
Go API, or a platform packet API. You provide the upstream access profile. GUI projects integrate
the core from separate repositories.

**Start here:** [Try a local proxy](#try-a-local-proxy) · [Integrate the core](#integrate-the-core) · [Check platform status](#platform-status)

## Why use it?

- **One profile, two local modes:** expose a TCP SOCKS5 proxy to selected applications or route
  system traffic through a VPN tunnel.
- **Traffic rules in the core:** choose `proxy`, `direct`, or `block` for IP ranges and domains.
  In system VPN mode, domain rules use observed DNS responses and have
  [documented limits](docs/DNS_METADATA.MD).
- **A session API for applications:** control start and stop, read status, events, statistics,
  and safe diagnostic codes, and handle network changes without parsing CLI output.

## Supported upstreams

These upstreams currently support TCP. The UDP column describes system VPN mode; the local
SOCKS5 listener accepts TCP `CONNECT` only.

| Upstream | Input or transport | UDP in VPN mode |
| --- | --- | --- |
| Shadowsocks | `ss://`, `ssconf://` | Yes |
| VLESS | TCP, WebSocket, gRPC, XHTTP | Yes |
| VMess AEAD | TCP, WebSocket, HTTPUpgrade, gRPC, XHTTP | Yes |
| Trojan | TCP/TLS | Yes |
| Hysteria2 | QUIC | If the server allows UDP relay |
| TUIC v5 | QUIC | Stream-mode relay |
| Remote SOCKS5 | SOCKS5 | With upstream `UDP ASSOCIATE` |
| SSH | TCP forwarding | No; DNS is forwarded over TCP |

Transport and security combinations vary. See [configuration](docs/CONF.MD),
[VLESS transports](docs/VLESS_TRANSPORTS.MD), [VMess transports](docs/VMESS_TRANSPORTS.MD),
and [SSH](docs/SSH.MD) for exact support. Connections to a remote SOCKS5 upstream are not
encrypted by the core. Not every combination has passed live interoperability testing.

## Try a local proxy

You need Go 1.26.9 or newer and a working access URI for a supported upstream. This path runs
without administrator privileges or a system tunnel. The inline example uses Shadowsocks; see
the [configuration reference](docs/CONF.MD) for other protocol-specific URI fields.

1. Save this as `profiles/quickstart.conf`, replacing the sample `SS` URI with your own. The
   `profiles/` directory is ignored by Git; never commit real access keys.

   ```ini
   [Profile]
   Version = 1
   Name = Quick start

   [AccessKey]
   SS = ss://chacha20-ietf-poly1305:replace-me@server.example.com:8388

   [Interface]
   Mode = proxy
   Listen = 127.0.0.1:1080

   [Routing]
   Default = proxy
   ```

   To keep the URI in a separate file instead, replace the `[AccessKey]` section with:

   ```ini
   [AccessKey]
   File = access.key
   ```

   Put the complete URI in `profiles/access.key`. Use only one access source in a profile.

2. From the repository root, validate and start the profile:

   ```sh
   go run ./cmd/bimeron validate profiles/quickstart.conf
   go run ./cmd/bimeron run profiles/quickstart.conf
   ```

3. In another terminal, send a request through the local proxy:

   ```sh
   curl --proxy socks5h://127.0.0.1:1080 https://example.com
   ```

   In Windows PowerShell, use `curl.exe`. The request requires a reachable upstream; `validate`
   checks the configuration without connecting. Stop the core with Ctrl+C. The local SOCKS5
   listener accepts TCP `CONNECT` only.

For system VPN, set `Mode = vpn` and use the [Windows CLI](docs/CONF.MD#commands),
[Linux](docs/LINUX.MD), or [macOS](docs/MACOS.MD) guide. System network changes require elevated
privileges; the Windows distribution also includes the matching Wintun DLL.

## Platform status

| Target | Core functionality | Integration |
| --- | --- | --- |
| Windows amd64/arm64 | System VPN via Wintun; local SOCKS5 | Console, SCM service, named-pipe IPC; optional WFP kill switch |
| Linux amd64/arm64 | System VPN via TUN; local SOCKS5 | Console, daemon, Unix-socket IPC; optional nftables kill switch |
| macOS Intel/Apple Silicon | Experimental CLI VPN via utun; local SOCKS5 | Console and daemon; no core kill switch |
| Android | Packet engine distributed as an AAR | Host app supplies `VpnService`, TUN, permissions, and lifecycle |
| macOS NetworkExtension | Packet engine, Swift provider, and technical console shell | Signing and provisioning are required for deployment; no GUI |

Platform capabilities describe compiled support, not the availability of a driver, permission,
or compatible server on a particular device. See [desktop integration](docs/GUI_INTEGRATION.MD),
[Android](docs/ANDROID_VPN_SERVICE.MD), and
[Apple NetworkExtension](docs/APPLE_NETWORK_EXTENSION.MD) for the exact boundaries and
validation status.

## Integrate the core

- **Desktop application:** manage a privileged service through [local IPC](docs/CONTROL.MD).
  Start a `.conf` profile, then read authoritative status, events, and statistics. The
  [GUI integration contract](docs/GUI_INTEGRATION.MD) covers identity, secrets, and recovery.
- **Go application:** use `bimeron/core` to load a profile and manage an engine with `Start`,
  `Stop`, `Status`, `Events`, `Stats`, and `Wait`. See the [Go API guide](docs/CORE.MD).
- **Platform VPN host:** embed the [Android AAR](docs/ANDROID_VPN_SERVICE.MD) or the
  [Apple packet engine](docs/APPLE_NETWORK_EXTENSION.MD) and supply the operating system's VPN
  lifecycle and tunnel.

The `.conf` format keeps the access source, interface mode, and routing rules in one profile.
Start with the [configuration reference](docs/CONF.MD) and the [examples](examples/).
Domain-based VPN rules rely on DNS metadata; application-based split routing is not available.

## Build and verify

```sh
go test ./...
go run scripts/build-dist.go
go run scripts/check-dist.go
```

The distribution build produces six Windows, Linux, and macOS CLI packages. Android and Apple
extension builds use separate scripts. See [building and packaging](docs/BUILDING.md) for
prerequisites, output contents, Wintun verification, and platform-specific steps; see
[CI checks](docs/CI.MD) for automated coverage and its limits.

## License and third-party notices

Bimeron's original code is licensed under the [MIT License](LICENSE). Adapted VLESS and VMess
protocol files retain Xray-core's MPL 2.0 license; see `third_party/vless/` and
`third_party/vmess/`. Other third-party components retain their own licenses in
[THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt) and `third_party/wf/LICENSE`. Distributed
Wintun DLLs include `WINTUN-LICENSE.txt`, whose **Prebuilt Binaries License** differs from the
Go Wintun module license in `THIRD_PARTY_NOTICES.txt`. Read those terms before redistribution.

Bimeron Core uses the Outline SDK, gVisor, Wintun, and other libraries listed in `go.mod` and
`THIRD_PARTY_NOTICES.txt`. Their upstream names, links, and license notices remain theirs.
