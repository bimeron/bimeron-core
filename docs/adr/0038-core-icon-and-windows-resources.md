# ADR 0038: Core icon and Windows resources

Status: accepted, November 14, 2026. Tracked by Core issue #111.

## Context

Core binaries had no icon, so the service, CLI and bundled Apple apps were
anonymous in Explorer, Task Manager, elevation prompts and Finder. Bimeron
Desktop owns the icon (`assets/icons/bimeron.ico`, PNG images from 16 to
256 px) and embeds it through `app.rc`. Core release builds are plain
`CGO_ENABLED=0` cross-compilations from any host, published as prepared,
reviewed bytes (ADR 0003), and `go build ./cmd/bimeron` must keep working for
development. The Go linker merges `.rsrc` sections only from `.syso` objects
in the package directory: `go build -overlay` does not supply them, and two
resource objects in one link fail with "too many .rsrc sections".

## Decision

- Copy the icon to `assets/brand/bimeron.ico` and record its Desktop source
  commit and SHA-256 in `assets/brand/README.md`. A test fails when the file
  and the recorded hash diverge. Desktop remains the canonical source; updates
  are copied by hand. The icon is distributed under the repository license.
- Generate the Windows resources at build time with the in-repo package
  `internal/winres`. `scripts/build-dist.go` writes a deterministic COFF object
  for each Windows architecture into `cmd/bimeron` (ignored by Git), links it
  and deletes it. Builds without this step still work and lack the resources.
- Add VERSIONINFO: product name and file description "Bimeron Core", company
  "Bimeron contributors", the `LICENSE` copyright and `bimeron.exe` as the
  original file name. The file and product version strings are the same
  semantic version passed to `-X bimeron/core.Version`; the numeric version is
  `major.minor.patch.0` and prereleases set `VS_FF_PRERELEASE`.
- `scripts/check-dist.go` verifies the PE architecture, every icon image byte
  for byte against the source, the VERSIONINFO strings and, with
  `BIMERON_VERSION`, the exact version.
- `scripts/build-apple.sh` builds `Bimeron.icns` from the PNG images with the
  system `iconutil` and sets `CFBundleIconFile` in `BimeronCore.app` and its
  packet tunnel extension.
- Linux and macOS CLI executables and the Android AAR have no embedded icon;
  this is documented.

## Alternatives

- Committed per-architecture `.syso` files would give plain `go build` an icon,
  but put regenerated binaries in Git, cannot carry the release version, and
  would still need a generator to prove they match the icon.
- A pinned third-party generator such as go-winres is mature, but runs
  external code and its dependencies in every release build.
- MinGW `windres` or LLVM `rc` add a native toolchain; the available MinGW
  `windres` cannot target arm64.
- Checking the icon against Desktop's `main` in CI couples Core CI to another
  repository and the network. Downloading it at build time, like Wintun, adds a
  network step for a small file the project owns.

## Tradeoffs

- Core owns a small encoder for COFF, the resource directory and VERSIONINFO.
  Tests parse its output, link it for amd64 and arm64 with the Go linker, and
  on Windows read it back through `ExtractIconEx`, `FindResource` and
  `GetFileVersionInfo`. The arm64 icon has not been checked visually on arm64
  hardware.
- The numeric file version does not distinguish prereleases of one version.
  Windows Installer compares numeric file versions when it overwrites a file
  without removing the old product first; Desktop's MSI must keep removing the
  previous product before installing, or it may keep an older Core of the same
  numeric version.
- The icon in Core can drift from Desktop until someone copies an update. The
  icon changes rarely, and Desktop pins Core releases.
- The source icon stops at 256 px, so macOS scales it for 512 px views.
- A Windows release build now requires a semantic version.
