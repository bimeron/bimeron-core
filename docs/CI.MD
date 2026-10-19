# Automated checks

`.github/workflows/go.yml` runs `go test ./...` and builds distribution
artifacts on pushes and pull requests. Go is selected from `go.mod`.

The `cli-dist` job builds all six Windows, Linux, and macOS CLI directories,
including the verified Wintun DLL and license in each Windows directory. It
runs `scripts/check-dist.go` and uploads `cli-dist` for 14 days. The
`android-dist` job builds the four-ABI Android AAR, checks its contents and
licenses, and uploads `android-dist` for 14 days. These workflow artifacts
are build outputs, not GitHub Releases. Apple NetworkExtension is excluded.

## Proposed test and build workflow

Additional jobs could cover:

- Windows, Linux, and macOS: go test ./... and go vet ./....
- Linux: govulncheck for execution paths in the project code.
- Linux and macOS: go test -race ./... with CGO. Windows race testing requires
  a separately configured compatible C compiler.
- A separate Linux job: TUN, HTTP, routes, nftables, and daemon tests in new
  network namespaces; daemon tests also use a new mount namespace with a separate /run.
- A separate macOS job: unsigned system-extension and app-extension builds,
  Go/C/Swift compilation, and a C ABI smoke test.
- Android `VpnService` execution on a device.
- A shared SHA256SUMS for release archives.

Do not upload keys, profiles, or diagnostic reports. Use synthetic test keys and
local endpoints. Automated tests must not connect a real VPN, install the Windows
service, or change the workstation's network. Restrict privileged checks to
disposable runners and namespaces. macOS unit tests and unsigned builds do not
replace testing a real `utun` VPN or a signed NetworkExtension on a Mac.

Build artifacts should use the per-platform directories described in the README,
including `LICENSE` and `THIRD_PARTY_NOTICES.txt`. Both Windows directories must
include the matching verified Wintun DLL and its exact prebuilt-binaries license.
Unsigned Apple builds must be identified as such and cannot run the NetworkExtension.

## Proposed release workflow

A future release workflow could run on `v*` tags, repeat tests, static analysis,
and vulnerability checks, embed the tag version, create archives for all six
platforms, and publish a GitHub Release with a shared `SHA256SUMS`.
Windows release archives should include verified Wintun binaries for the matching
architecture and their license. Tags with a suffix, such as `v0.1.0-rc1`,
should be published as prereleases.

No automatic release is configured. Configure branch protection using the
actual CI job names after the required jobs are in place.
