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

The Linux job downloads the official ShadowTLS `v0.2.25` Linux x86-64 binary
and verifies SHA-256
`a173f5f2d57f45211b68e10ceeddc15b1791077b914fa89747bc705fddc71532`
before executing it. This is a content pin, not a signed upstream attestation.
It reuses the pinned Xray, AnyTLS and Caddy binaries above to run the wrapped
matrix with the race detector: six Shadowsocks methods, 54 VMess cases,
26 VLESS cases, Trojan/AnyTLS UDP-over-stream, NaiveProxy, an SSH fixture,
socket controls and Core Engine/SOCKS5 requests. These tools are external test
processes and do not enter the distributed core's dependency graph.

`BIMERON_SHADOWTLS_BIN` enables the wrapper in existing inner reference tests;
without it those tests retain their direct mode. The standalone ShadowTLS
reference tests skip explicitly when it is absent. For local reproduction,
see [the recorded commands](SHADOWTLS_V3_RESEARCH.md#observed-verification).

CI also runs `BenchmarkReferenceServer` for 20 iterations per case. `Handshake`
includes TCP connection, strict-v3 authentication and close. `RoundTrip64KiB`
reuses one authenticated connection and reports one 64-KiB payload per echo
round trip, with allocation counts. Reproduce with:

```sh
BIMERON_SHADOWTLS_BIN=/path/to/shadow-tls \
  go test ./internal/shadowtls -run '^$' -bench '^BenchmarkReferenceServer$' -benchtime=20x -count=1
```

These are local regression measurements, not internet throughput predictions
or protocol rankings. The checks do not replace live privileged VPN or mobile
device validation; [the ShadowTLS guide](SHADOWTLS.MD) lists the supported scope.

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

## Shadowsocks v2ray-plugin reference checks

The Linux test job downloads the original `v2ray-plugin` v1.5.0 release and
verifies its pinned SHA-256 before extraction. It uses Xray v1.260327.0,
already built outside the product module graph, as the Shadowsocks server.
No plugin executable or V2Fly/Xray runtime is added to the distributed core.

The mandatory interop step sets `BIMERON_REQUIRE_SSPLUGIN_INTEROP=1`, so missing
reference binaries fail the step instead of silently skipping tests. It runs
the plugin and Mux packages with the race detector. The matrix covers six
Shadowsocks AEAD/2022 methods, WS/WSS, and Mux 0/1/8: 36 combinations. Additional
tests exercise defaults, concurrency and connection reuse, a transfer over
2 MB, reconnects, rejected TLS certificates/names, and incorrect WebSocket
paths. Unit tests cover malformed Mux frames, per-session deadlines,
slow-consumer isolation, setup cancellation, and runtime cleanup.

To repeat the reference checks locally, provide the two executables from the
same pinned versions used in [the workflow](../.github/workflows/go.yml).
For a POSIX shell:

```sh
export BIMERON_V2RAY_PLUGIN_BIN=/absolute/path/to/v2ray-plugin
export BIMERON_XRAY_BIN=/absolute/path/to/xray
export BIMERON_REQUIRE_SSPLUGIN_INTEROP=1
go test -race ./internal/ssplugin ./internal/v2raymux -count=1
go test ./internal/ssplugin -run '^$' -bench '^BenchmarkOriginalPlugin$' -benchtime=20x -count=1
```

In PowerShell, set each environment variable using `$env:NAME = 'C:/path/file.exe'`
before running the same `go test` commands. Race testing needs a compatible
C compiler. Without reference variables, ordinary local tests skip only the
external interop cases; they still run the in-process transport and Mux tests.

The benchmark measures loopback session setup/reuse and a 32 KiB echo transfer
through WSS and Mux. It is a smoke benchmark, not a claim about Internet
throughput. All test credentials, certificates, and endpoints are synthetic
and local. A successful local run does not replace a successful hosted CI run
or testing a real VPN deployment.

## simple-obfs reference checks

The Linux test job builds two original simple-obfs server revisions:

| Revision | simple-obfs commit | libcork submodule commit |
| --- | --- | --- |
| Final upstream | `486bebd9208539058e57e23a12f23103016e09b4` | `f02984545061c924808e4b9ea7cc6749a41f1979` |
| v0.0.5 | `a9c43588e4cb038e6ac02f050e4cab81f8228dff` | `29d7cbafc4b983192baeb0c962ab1ff591418f56` |

The workflow verifies both checkouts and submodule commits before building.
It installs autoconf, automake, libtool, libev, PCRE, OpenSSL development
headers, and pkg-config; runs `./autogen.sh` and
`./configure --disable-documentation`; and builds with `make -j2`.
v0.0.5 needs `-O2 -fcommon -Wno-error=stringop-overread` with modern GCC.
This permits a historical upstream warning without modifying its source and
does not relax Bimeron's compiler settings. Reference sources retain their
licenses. The GPL reference binaries run as separate test processes and are
not shipped or linked into Bimeron.

Both servers use the existing independent Xray v1.260327.0 backend. The
mandatory step sets `BIMERON_REQUIRE_SIMPLEOBFS_INTEROP=1`; missing reference
binaries fail instead of skipping. Wrapper tests and both reference matrices
run with the race detector. Coverage includes HTTP/TLS, six AEAD/2022 methods,
AES identity chains, parallel streams, reconnects, large transfers, and
shutdown. Final upstream additionally tests custom HTTP URI/method and Host.
The v0.0.5 run sets `BIMERON_SIMPLEOBFS_RELEASE=1` to omit custom-option cases.

For local reproduction, use the binaries from the pinned source builds in
[the workflow](../.github/workflows/go.yml):

```sh
export BIMERON_XRAY_BIN=/absolute/path/to/xray
export BIMERON_OBFS_SERVER_BIN=/absolute/path/to/final/obfs-server
export BIMERON_REQUIRE_SIMPLEOBFS_INTEROP=1
go test -race ./internal/simpleobfs -count=1
go test -race ./internal/ssplugin -run 'SimpleObfs' -count=1 -v
go test ./internal/ssplugin -run '^$' -bench '^BenchmarkOriginalSimpleObfs$' -benchtime=10x -count=1

export BIMERON_OBFS_SERVER_BIN=/absolute/path/to/v0.0.5/obfs-server
BIMERON_SIMPLEOBFS_RELEASE=1 go test -race ./internal/ssplugin -run '^TestOriginalSimpleObfs' -count=1 -v
```

The benchmark reuses a connection to echo a 56 KiB payload through each mode,
the original server, and Xray. It reports timing and allocations without a
hardware-dependent threshold. Its result measures the entire reference chain,
including TCP buffering and scheduling, rather than a client throughput limit.
Without the reference variables, ordinary local tests still run the synthetic
framing, configuration, lifecycle, and runtime-resolution tests. Local success
does not establish hosted CI or mobile/VPN data-plane success.

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

## Shadowsocks 2022 identity chains

The pinned external Xray binary also verifies SIP022 single-key clients for
all three methods and SIP023 for both AES methods. The SIP023 matrix covers
two users on a shared server, a relay followed by a multi-user server (two
identity headers), and rejection of wrong identity keys, wrong user keys,
and reordered chains over TCP and UDP. Xray remains outside the module graph.
The SS2022 step runs all package tests under the race detector, including
independent wire fixtures and datagram-size boundaries. Parser fuzz seeds
run with normal accesskey tests; a bounded fuzz campaign and identity-header
benchmarks run in the same Linux job. Benchmarks report results without a
hardware-dependent pass/fail threshold.
