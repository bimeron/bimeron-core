# Bimeron brand assets

`bimeron.ico` is the Bimeron application icon. Core embeds it in the Windows
executables and the macOS `BimeronCore.app` bundles; see
[Icons and version information](../../docs/BUILDING.md#icons-and-version-information).

## Provenance

| Field | Value |
| --- | --- |
| Source | `bimeron/bimeron-desktop`, `assets/icons/bimeron.ico` |
| Copied from | `main` at `516ea4b7a445c97a9398a322c5de28b5ebbd5d35` (file last changed in `67a05d1e`) |
| SHA-256 | `5824b02b014fff8c21e6e3c78bc3353d6e2934cd45d539b09ba6ff1c18142866` |
| Images | 16, 24, 32, 48, 64, 128 and 256 px, 32-bit PNG |

Bimeron Desktop is the canonical source. This copy is distributed under the
repository [LICENSE](../../LICENSE).

## Updating the icon

1. Copy the new `assets/icons/bimeron.ico` from Bimeron Desktop over
   `bimeron.ico`.
2. Update the commit and SHA-256 above; `go test ./internal/winres` fails
   until the recorded SHA-256 matches the file.
3. Keep square PNG images of 16, 32, 64, 128 and 256 px: `scripts/build-apple.sh`
   builds the macOS iconset from exactly these sizes.
4. Run `go run scripts/build-dist.go` and `go run scripts/check-dist.go`, and
   build the Apple bundles on a Mac.

Released binaries pick up a new icon only with a new Core release.
