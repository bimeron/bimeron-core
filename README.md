# Bimeron Core

Bimeron Core is a VPN core for Windows, Linux, and macOS. It supports static `ss://` and dynamic `ssconf://` Shadowsocks access keys, VLESS over TCP with REALITY and Vision or ordinary TLS, VLESS over WebSocket with TLS and early data, VLESS over gRPC with TLS, VLESS over XHTTP with TLS or REALITY in selected modes, VMess AEAD over TCP, WebSocket, HTTPUpgrade, gRPC, or XHTTP with TLS or supported REALITY combinations and UDP relay, Trojan over TCP/TLS with UDP relay, Hysteria2 over QUIC with TCP and UDP relay, TUIC v5 over QUIC with stream-mode UDP relay, remote SOCKS5 upstreams, a local SOCKS5 proxy, system VPN integration, and profile-based routing rules. See [configuration](docs/CONF.MD), [VLESS transport contract](docs/VLESS_TRANSPORTS.MD), [VMess transport matrix](docs/VMESS_TRANSPORTS.MD), and [GUI integration](docs/GUI_INTEGRATION.MD).

Bimeron's original code is licensed under the MIT License; see `LICENSE`. Adapted VLESS and VMess protocol files retain Xray-core's MPL 2.0 license; see `third_party/vless/` and `third_party/vmess/`. Other third-party components retain their own licenses in `THIRD_PARTY_NOTICES.txt`, `third_party/wf/LICENSE`, and, for distributed Wintun DLLs, `WINTUN-LICENSE.txt`.

## Requirements

Go 1.26.9 or newer and `curl` for the verified Wintun download. Building the Apple NetworkExtension requires macOS and Xcode; signed deployment requires an Apple Developer account. Android bindings require `gomobile` and the Android SDK.

## Build and test

```sh
go test ./...
go run scripts/build-dist.go
go run scripts/check-dist.go
```

`go run scripts/build-dist.go` works on Windows, Linux, and macOS and builds six CLI distributions. `scripts/build-all.ps1` and `scripts/build-all.sh` are wrappers for the same command. `bin/` contains the raw cross-compiled binaries, named `bimeron-<os>-<arch>` (with `.exe` for Windows), and may contain the cached Wintun ZIP. Each `dist/` directory contains one distribution:

| Directory | Contents |
| --- | --- |
| `dist/windows-amd64/`, `dist/windows-arm64/` | `bimeron.exe`, matching `wintun.dll`, `LICENSE`, `WINTUN-LICENSE.txt`, `THIRD_PARTY_NOTICES.txt` |
| `dist/linux-amd64/`, `dist/linux-arm64/` | `bimeron`, `LICENSE`, `THIRD_PARTY_NOTICES.txt` |
| `dist/macos-amd64/`, `dist/macos-arm64/` | `bimeron`, `LICENSE`, `THIRD_PARTY_NOTICES.txt` |
| `dist/android/` | Android AAR, sources JAR, `LICENSE`, `THIRD_PARTY_NOTICES.txt` after the separate Android build |
| `dist/apple-system-extension-<arch>/` or `dist/apple-app-extension-<arch>/` | Native Mac app and extension, `LICENSE`, `THIRD_PARTY_NOTICES.txt` after the separate macOS build |

The CLI build downloads the official Wintun 0.14.1 ZIP and verifies its SHA-256 (`07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`) before extracting the two architecture-specific DLLs and the exact license. `scripts/install-wintun.ps1 -Architecture amd64` (or `arm64`) builds and refreshes just one Windows directory. The ZIP contains WireGuard LLC's **Prebuilt Binaries License** for the DLL; read `WINTUN-LICENSE.txt` before redistribution. Its terms differ from the license for the Go Wintun module in `THIRD_PARTY_NOTICES.txt`. Generated files and the downloaded ZIP are ignored by Git.

The CLI command does not build Android or Apple extension artifacts. Build the Android AAR with `sh scripts/build-android.sh` or, on Windows, `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-android.ps1` after installing the Android SDK, NDK, JDK, and `gomobile` and setting `ANDROID_HOME` and `ANDROID_NDK_HOME`. Build the Apple system extension on a Mac with Xcode using `sh scripts/build-apple.sh`; set `APPLE_EXTENSION_KIND=app-extension` to build that variant. The extension build uses the Mac's native architecture, so both amd64 and arm64 outputs require builds on the corresponding Macs. Without an Apple Developer account, these are **unsigned** builds for inspection only; NetworkExtension execution requires signing and provisioning. The Android output is an AAR, not an installable Android app.

## Usage

```sh
bimeron validate examples/main.conf
bimeron validate examples/vless.conf
bimeron validate examples/trojan.conf
bimeron validate examples/tuic.conf
bimeron check profiles/test.key
bimeron proxy profiles/test.key
bimeron connect profiles/test.key
bimeron doctor
```

Run system VPN commands with the privileges required by the platform. Store real access keys only in ignored local `profiles/` files. Never commit keys, profiles, or diagnostic output containing private data. The example profiles contain placeholders and will not connect as-is.

The CLI also provides `daemon`, `start`, `status`, `watch`, `stats`, `capabilities`, `stop`, `shutdown`, `run`, `recover`, `inspect`, and `route`. See `docs/` for platform and integration details. Verify platform-specific procedures against the code before deployment.

## Third-party projects

Bimeron Core uses the Outline SDK, gVisor, Wintun, and other libraries listed in `go.mod` and `THIRD_PARTY_NOTICES.txt`. Their upstream names, links, and license notices are not part of this project's rebranding.
