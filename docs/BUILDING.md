# Building and packaging

Run commands from the repository root. Building the CLI requires Go 1.26.9 or newer. The Windows
distribution build also uses `curl` to download the verified Wintun archive.

## CLI distributions

```sh
go test ./...
go run scripts/build-dist.go
go run scripts/check-dist.go
```

`build-dist.go` works on Windows, Linux, and macOS and builds six CLI distributions. Pass
`windows`, `windows-amd64`, `windows-arm64`, `linux`, or `macos` to build selected targets.
`scripts/build-all.ps1` and `scripts/build-all.sh` wrap the same command. `bin/` contains raw
cross-compiled binaries named `bimeron-<os>-<arch>` (with `.exe` on Windows) and may contain a
cached Wintun ZIP. Each `dist/` directory contains one distribution:

| Directory | Contents |
| --- | --- |
| `dist/windows-amd64/`, `dist/windows-arm64/` | `bimeron.exe`, matching `wintun.dll`, `LICENSE`, `WINTUN-LICENSE.txt`, `THIRD_PARTY_NOTICES.txt` |
| `dist/linux-amd64/`, `dist/linux-arm64/` | `bimeron`, `LICENSE`, `THIRD_PARTY_NOTICES.txt` |
| `dist/macos-amd64/`, `dist/macos-arm64/` | `bimeron`, `LICENSE`, `THIRD_PARTY_NOTICES.txt` |

Generated files and the downloaded ZIP are ignored by Git. The [CI workflow](CI.MD) tests and
builds the packages; workflow artifacts are separate from published releases.

## Wintun for Windows

The CLI build downloads the official Wintun 0.14.1 ZIP and verifies its SHA-256
(`07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`) before extracting the two
architecture-specific DLLs and the exact license.
`scripts/install-wintun.ps1 -Architecture amd64` (or `arm64`) builds and refreshes one Windows
directory.

The ZIP contains WireGuard LLC's **Prebuilt Binaries License** for the DLL; read
`WINTUN-LICENSE.txt` before redistribution. Its terms differ from the license for the Go Wintun
module in `THIRD_PARTY_NOTICES.txt`.

## Android AAR

The CLI build does not build Android artifacts. Install the Android SDK, NDK, JDK, and
`gomobile`, and set `ANDROID_HOME` and `ANDROID_NDK_HOME`. Build with
`sh scripts/build-android.sh` or, on Windows,
`powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-android.ps1`.

The output in `dist/android/` is an AAR and sources JAR, with `LICENSE` and
`THIRD_PARTY_NOTICES.txt`, not an installable Android app. See
[Android packet core](ANDROID_VPN_SERVICE.MD) for the host application contract and validation
requirements.

## Apple NetworkExtension

Build on a Mac with Xcode using `sh scripts/build-apple.sh`; set
`APPLE_EXTENSION_KIND=app-extension` to build that variant. The output in
`dist/apple-system-extension-<arch>/` or `dist/apple-app-extension-<arch>/` is a native Mac app
and extension with `LICENSE` and `THIRD_PARTY_NOTICES.txt`. The build uses the Mac's native
architecture, so amd64 and arm64 outputs require builds on the corresponding Macs.

Without an Apple Developer account, these are **unsigned** builds for inspection only;
NetworkExtension execution requires signing and provisioning. See the
[Apple NetworkExtension guide](APPLE_NETWORK_EXTENSION.MD) for the integration contract and
deployment requirements.
