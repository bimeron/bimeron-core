# Building and packaging

Run commands from the repository root. Building the CLI requires Go 1.26.11 or newer. The Windows
distribution build also uses `curl` to download the verified Wintun archive.

## CLI distributions

```sh
go test ./...
go run scripts/build-dist.go
go run scripts/check-dist.go
```

`build-dist.go` works on Windows, Linux, and macOS and builds six CLI distributions. Pass
`windows`, `windows-amd64`, `windows-arm64`, `linux`, or `macos` to build selected targets;
`check-dist.go` always expects all six. `scripts/build-all.sh` forwards an optional target to
`build-dist.go`, while `scripts/build-all.ps1` always builds all targets. `bin/` contains raw
cross-compiled binaries named `bimeron-<os>-<arch>` (with `.exe` on Windows).
`BIMERON_DIST_DIR` overrides the output directory for both scripts. Each `dist/` directory
contains one distribution:

| Directory | Contents |
| --- | --- |
| `dist/windows-amd64/`, `dist/windows-arm64/` | `bimeron.exe`, matching `wintun.dll`, `LICENSE`, `WINTUN-LICENSE.txt`, `THIRD_PARTY_NOTICES.txt` |
| `dist/linux-amd64/`, `dist/linux-arm64/` | `bimeron`, `LICENSE`, `THIRD_PARTY_NOTICES.txt` |
| `dist/macos-amd64/`, `dist/macos-arm64/` | `bimeron`, `LICENSE`, `THIRD_PARTY_NOTICES.txt` |

Generated files are ignored by Git. The [CI workflow](CI.MD) tests and
builds the packages; workflow artifacts are separate from published releases.

## Wintun for Windows

The CLI build downloads the official Wintun 0.14.1 ZIP to a temporary file and verifies its
SHA-256 (`07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`) before extracting
the two architecture-specific DLLs and the exact license. To build offline, place the ZIP at
`bin/wintun-0.14.1.zip` or point `BIMERON_WINTUN_ARCHIVE` at it; a file with the wrong
SHA-256 is ignored and downloaded again.
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
`THIRD_PARTY_NOTICES.txt`, not an installable Android app. The scripts build with `-trimpath`
and map the NDK path. gomobile records the absolute directory of the module in each library, so
`build-android.sh` builds through a link at the fixed path `/tmp/bimeron-core-android/src`, and
`build-android.ps1` from the root of a temporary drive letter created with `subst`. The native
libraries therefore name no directory of the build machine; CI and the release gate check this.
`GOFLAGS` and `GOEXPERIMENT` must be empty, also in `go env -w`. If `build-android.sh` reports
that `/tmp/bimeron-core-android` exists while no other Android build runs, remove that directory. See
[Android packet core](ANDROID_VPN_SERVICE.MD) for the host application contract and validation
requirements.

## Apple NetworkExtension

Build on a Mac with Xcode using `sh scripts/build-apple.sh`; set
`APPLE_EXTENSION_KIND=app-extension` to build that variant. The output in
`dist/apple-system-extension-<arch>/` or `dist/apple-app-extension-<arch>/` is a native Mac app
and extension with `LICENSE` and `THIRD_PARTY_NOTICES.txt`, targeting macOS 13.0 or later. The
build uses the Mac's native architecture by default; set `APPLE_ARCH=amd64` or `arm64` to
cross-build the other one. The C ABI test runs only for the native architecture.

Without an Apple Developer account, these are **unsigned** builds for inspection only;
NetworkExtension execution requires signing and provisioning. See the
[Apple NetworkExtension guide](APPLE_NETWORK_EXTENSION.MD) for the integration contract and
deployment requirements.

## Icons and version information

Core carries the Bimeron icon from [`assets/brand/bimeron.ico`](../assets/brand/README.md)
wherever the platform has an executable or bundle icon:

| Artifact | Icon | Mechanism |
| --- | --- | --- |
| `dist/windows-*/bimeron.exe` | Yes, with VERSIONINFO | PE resources linked by `build-dist.go` |
| `BimeronCore.app` and its packet tunnel extension | Yes | `Contents/Resources/Bimeron.icns` and `CFBundleIconFile` |
| `dist/macos-*/bimeron` | No | A Mach-O executable outside a bundle has no icon |
| `dist/linux-*/bimeron` | No | ELF has no icon; packages supply desktop entries and icons |
| `dist/android/bimeron-core.aar` | No | A library; the host app owns the launcher icon |

For each Windows target, `build-dist.go` generates a COFF object with
[`internal/winres`](../internal/winres), writes it to
`cmd/bimeron/zz_bimeron_resource_windows_<arch>.syso` for the duration of that
`go build` and then deletes it. The object holds the icon group and a
VERSIONINFO with product name and file description "Bimeron Core", company
"Bimeron Network" and the copyright from `LICENSE`. The file and product
version strings are the version passed to `-X bimeron/core.Version`, for example
`0.4.0-beta.1`; the numeric file version is `0.4.0.0`, with the prerelease flag
set for prerelease versions. A Windows build therefore requires
`BIMERON_VERSION`, or the last `v*` tag, to be a semantic version. Without
`BIMERON_VERSION`, the tag gets a `-dev` suffix, for example `0.3.0-beta.2-dev`;
without any version the strings read `dev`. The Android and Apple scripts use
the same rule. The generator adds no dependency and its output
is deterministic. `.gitignore` excludes the temporary object, so it does not
mark the build as modified; an interrupted build leaves one behind, and the next
`build-dist.go` run deletes it.

A plain `go build ./cmd/bimeron` works without this step and produces a Windows
executable without an icon or version information. `check-dist.go` requires
each Windows executable to keep its PE architecture, to contain every image of
`bimeron.ico` byte for byte and the expected VERSIONINFO, and, when
`BIMERON_VERSION` is set, that exact version.

`build-apple.sh` extracts the 16 to 256 px PNG images of `bimeron.ico` into an
iconset, converts it with the system `iconutil` and copies `Bimeron.icns` into
both bundles. The source has no 512 px image, so Finder scales the 256 px image
for the largest icon views. The Apple bundles have no version derived from the
Core release; `CFBundleShortVersionString` is unchanged.

The Windows Services console shows the same generic icon for every service; the
icon appears in Explorer, Task Manager and elevation prompts, and Task Manager
lists the process as "Bimeron Core".
