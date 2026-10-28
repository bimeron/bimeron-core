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

**Choose documentation for your version.** This README and its linked guides describe the
Git revision you are viewing. For a downloaded package, open its entry in
[Releases](https://github.com/bimeron/bimeron-core/releases), follow the release tag, and open
`README.md` there. The default branch may contain changes that are absent from that release.

## Why use it?

- **One profile format across upstreams:** keep access settings and routing rules in a `.conf`
  profile shared by the CLI and your application. Use it for a local SOCKS5 proxy or system VPN.
- **Traffic rules in the core:** choose `proxy`, `direct`, or `block` for IP ranges and domains.
  In system VPN mode, domain rules use observed DNS responses and have
  [documented limits](docs/DNS_METADATA.MD).
- **Connection management for your application:** let the core handle tunnel setup, DNS,
  reconnects, and cleanup. Control sessions and read status, events, statistics, and diagnostic
  codes through an API.
- **A GUI that can run without elevation:** use local IPC to control a separately installed
  privileged service. Network operations stay in that service; your interface uses structured
  responses without parsing CLI output.

## Supported upstreams

Support below applies to this source revision; check the tagged README for a release package.

All upstreams shown here support TCP. The UDP column describes system VPN mode; the local
SOCKS5 listener accepts TCP `CONNECT` only.

| Upstream | Transport | UDP in VPN mode |
| --- | --- | --- |
| Shadowsocks | TCP, UDP | Yes |
| VLESS | TCP, WebSocket, gRPC, XHTTP | Yes |
| VMess AEAD | TCP, WebSocket, HTTPUpgrade, gRPC, XHTTP | Yes |
| Trojan | TCP/TLS | Yes |
| Hysteria2 | QUIC | If the server allows UDP relay |
| TUIC v5 | QUIC | Stream-mode relay |
| Remote SOCKS5 | TCP, UDP | With upstream `UDP ASSOCIATE` |
| Remote HTTP CONNECT | TCP | No; DNS is forwarded over TCP |
| SSH | TCP forwarding | No; DNS is forwarded over TCP |

Transport and security combinations vary. See [configuration](docs/CONF.MD),
[VLESS transports](docs/VLESS_TRANSPORTS.MD), [VMess transports](docs/VMESS_TRANSPORTS.MD),
and [SSH](docs/SSH.MD) for exact support. Connections to a remote SOCKS5 upstream are not
encrypted by the core. HTTP CONNECT also uses plaintext transport and sends Basic credentials
without encryption. Not every combination has passed live interoperability testing.

## Try a local proxy

This quick start runs **from source**. You need Git, Go 1.26.9 or newer, `curl`, and a working
access URI for a supported upstream. It runs without administrator privileges or a system
tunnel. Go is not required to use a prebuilt CLI package; use that release's tagged README
and configuration guide for its supported commands and profiles.

1. Get the source and create a directory for local profiles:

   ```sh
   git clone https://github.com/bimeron/bimeron-core.git
   cd bimeron-core
   mkdir profiles
   ```

   If you already have a checkout, use its root directory and create `profiles/` if needed.

2. Save this as `profiles/quickstart.conf`, replacing the sample `SS` URI with your own. The
   example uses Shadowsocks; see the [configuration reference](docs/CONF.MD) for other
   protocol-specific URI fields. The `profiles/` directory is ignored by Git; never commit
   real access keys.

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

   <details>
   <summary>Alternative: keep the access URI in a file</summary>

   Replace the `[AccessKey]` section with:

   ```ini
   [AccessKey]
   File = access.key
   ```

   Put the complete URI in `profiles/access.key`. Use only one access source in a profile.

   </details>

3. From the repository root, validate and start the profile:

   ```sh
   go run ./cmd/bimeron validate profiles/quickstart.conf
   go run ./cmd/bimeron run profiles/quickstart.conf
   ```

   Wait for a log entry containing:

   ```text
   SOCKS5 TCP listening on 127.0.0.1:1080
   ```

   This confirms the local listener is ready. `validate` checks the configuration without
   connecting; the next step checks that traffic can pass through your upstream.

4. Leave the core running and, in another terminal, send a request through the local proxy:

   ```sh
   curl --proxy socks5h://127.0.0.1:1080 https://example.com
   ```

   In Windows PowerShell, use `curl.exe`. Success prints the page's HTML, including
   `Example Domain`. If the request fails, check the URI and upstream reachability; if the
   listener cannot start, check whether port `1080` is already in use.

   Stop the core with Ctrl+C in its terminal.

For system VPN, set `Mode = vpn` and use the [Windows CLI](docs/CONF.MD#commands),
[Linux](docs/LINUX.MD), or [macOS](docs/MACOS.MD) guide. System network changes require elevated
privileges; the Windows distribution also includes the matching Wintun DLL.

## Platform status

| Desktop target | System VPN | Optional kill switch |
| --- | --- | --- |
| Windows amd64/arm64 | Wintun | WFP |
| Linux amd64/arm64 | TUN | nftables; does not survive reboot |
| macOS Intel/Apple Silicon | Experimental CLI VPN via utun | Not implemented |

All three desktop targets support the local SOCKS5 proxy and service/daemon control. IPC uses
named pipes on Windows and Unix sockets on Linux/macOS. Application-based split routing is
not available.

- **Android API 23+:** a packet engine is available as an AAR for a separate VPN application.
  See [Android integration](docs/ANDROID_VPN_SERVICE.MD) for the host contract and device checks.
- **iOS:** no supported iOS build is provided yet. The existing
  [Apple integration](docs/APPLE_NETWORK_EXTENSION.MD) targets macOS; iOS builds and
  memory-limit validation remain incomplete.

Platform capabilities describe compiled support, not the availability of a driver, permission,
or compatible server on a particular device. See [desktop integration](docs/GUI_INTEGRATION.MD)
for the service contract and platform limits. Platform-hosted packet engines are described below.

## Integrate the core

- **Desktop application:** manage a privileged service through [local IPC](docs/CONTROL.MD).
  Start a `.conf` profile, then read authoritative status, events, and statistics. The
  [GUI integration contract](docs/GUI_INTEGRATION.MD) covers identity, secrets, and recovery.
- **Go application:** use `bimeron/core` to load a profile and manage an engine with `Start`,
  `Stop`, `Status`, `Events`, `Stats`, and `Wait`. See the [Go API guide](docs/CORE.MD).
- **Android VPN host:** embed the [Android AAR](docs/ANDROID_VPN_SERVICE.MD). Your app supplies
  `VpnService`, the TUN interface, permissions, protected sockets, and lifecycle management.
- **macOS NetworkExtension host:** use the [Apple packet engine](docs/APPLE_NETWORK_EXTENSION.MD),
  Swift provider, and technical console shell. Deployment requires signing and provisioning;
  unsigned builds are for inspection. This integration does not include a GUI.

Start with the [configuration reference](docs/CONF.MD) and the [examples](examples/). The Android
and Apple guides document host responsibilities and device validation requirements.

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
