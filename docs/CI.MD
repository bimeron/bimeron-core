# Automated checks

`.github/workflows/go.yml` runs `go test ./...` and builds distribution
artifacts on pushes and pull requests. Go is selected from `go.mod`.
The Go job also builds pinned Xray-core `v1.260327.0` outside Bimeron's module
graph and checks VMess TCP, UDP, reconnect, and cleanup over every documented
TLS transport, both AEAD ciphers, and representative TLS fingerprints. The
compiled dependency and notice checks reject unwanted modules. The Linux job
also runs VLESS and VMess transport tests with Go's race detector.

The fingerprint dependency matrix also tests the two local Hysteria/QUIC
modules explicitly on Linux and Windows, including decoded UDP Initials and
Retry/loss/HelloRetryRequest. Linux jobs run focused race checks. Root Hysteria
tests build an independent, unmodified v2.13.0 reference server with `GOWORK=off`
and exercise simultaneous named presets over TCP and fragmented UDP. This
requires the Go toolchain and the fixture module's pinned dependencies.

The Linux job builds Caddy v2.11.7 with klzgrad/forwardproxy at
`c096d6a00cb28e019cc1995b04bdc6a9311d8024` outside the core module. The
NaiveProxy test verifies authenticated HTTP/2 CONNECT, padded large payloads,
and HTTP through Bimeron's local SOCKS5 listener against that independent
server. It uses synthetic credentials, a temporary
certificate, loopback listeners, and isolated Caddy storage. The newer
forwardproxy revision requires additional Caddy idle-timeout patches; this
fixture pins the preceding revision with the same padding protocol. Focused
NaiveProxy tests also run with the race detector.

The race run excludes only `TestFrameParserAllocs/STREAM`: Go's race
instrumentation randomly discards `sync.Pool` entries, invalidating its zero
allocation assertion. The ordinary unit run still requires this test to pass.

The `cli-dist` job builds all six Windows, Linux, and macOS CLI directories,
including the verified Wintun DLL and license in each Windows directory. It
runs `scripts/check-dist.go` and uploads `cli-dist` for 14 days. The
`android-dist` job builds the four-ABI Android AAR, checks its contents and
licenses, and uploads `android-dist` for 14 days. These workflow artifacts
are build outputs, not GitHub Releases. Apple NetworkExtension is excluded.

Pushing a `v*` tag runs the same checks and embeds the tag version in the CLI
and Android builds. CI does not publish releases. The
[prepared-release publisher](RELEASE_UPDATES.md#publish-prepared-bytes) verifies
the prepared archives, checksums, and signed manifest before publication and
requires successful tag CI. Its release notes link to the README at that tag
and describe the package scope, including the excluded Apple NetworkExtension.

## Proposed test and build workflow

Native IKEv2 configuration and lifecycle tests run through the normal suite.
Linux and Windows race checks include `internal/systemvpn`. Windows also runs
explicit RAS ABI/profile-guard/read-only API tests, validates the example without
network changes, and tests RAS/WFP/DNS ownership under GOARCH=386. Dedicated
Windows race checks cover persistent filter and native DNS-policy tests without
installing real protection. Distribution builds
cover the Windows ARM64 implementation.

CI must leave `BIMERON_IKEV2_TEST_CONFIG` unset: the live native lifecycle test
is intentionally skipped. Its [isolated procedure and measurement plan](IKEV2.MD#isolated-live-validation-and-measurements)
require a disposable Windows VPN machine. Passing ordinary CI does not establish
server interoperability, certificate rejection, leak protection or performance.

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

Do not upload keys, profiles, or diagnostic reports. Use synthetic test keys and
local endpoints. Automated tests must not connect a real VPN, install the Windows
service, or change the workstation's network. Restrict privileged checks to
disposable runners and namespaces. macOS unit tests and unsigned builds do not
replace testing a real `utun` VPN or a signed NetworkExtension on a Mac.

Build artifacts should use the per-platform directories described in [building and packaging](BUILDING.md),
including `LICENSE` and `THIRD_PARTY_NOTICES.txt`. Both Windows directories must
include the matching verified Wintun DLL and its exact prebuilt-binaries license.
Unsigned Apple builds must be identified as such and cannot run the NetworkExtension.

Configure branch protection using the actual CI job names after the required
jobs are in place.
