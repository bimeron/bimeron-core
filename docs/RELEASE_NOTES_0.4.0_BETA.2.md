# Bimeron Core v0.4.0-beta.2

**Release notes — draft for review.** This is a security patch release on top
of v0.4.0-beta.1. Publication is pending candidate freeze, VM acceptance of the
Desktop 0.3.1 candidate with this Core candidate, and explicit approval.

The reviewed source range is `5fcadd71..aea4fca6` on master. `5fcadd71` is the
v0.4.0-beta.1 tag commit. The final candidate commit is recorded at freeze.

For package capabilities, see the [README at the release tag](https://github.com/bimeron/bimeron-core/blob/v0.4.0-beta.2/README.md).

## Summary

This release updates the Go toolchain and several dependencies to versions that
fix publicly disclosed vulnerabilities, and makes `govulncheck` a blocking CI
check. It contains no functional changes: IPC, profile format, configuration
syntax, capabilities and error codes are unchanged. Upgrading is recommended
for all users of v0.4.0-beta.1 and earlier.

## Fixed vulnerabilities

Updated in [#150](https://github.com/bimeron/bimeron-core/pull/150) (tracked by
[#149](https://github.com/bimeron/bimeron-core/issues/149)) and
[#154](https://github.com/bimeron/bimeron-core/pull/154). The impact
assessment below reflects how Bimeron Core uses each component.

| Advisory | Component | Previous | Fixed | Impact on Bimeron Core |
| --- | --- | --- | --- | --- |
| GO-2026-6865 | `github.com/klauspost/compress` (zstd) | v1.17.9 | v1.20.4 | High for `firefox` TLS fingerprint |
| GO-2026-6888 | `github.com/andybalholm/brotli` | v1.1.0 | v1.2.8 | High for Chrome-family and Firefox fingerprints |
| GO-2026-6348, GO-2026-6061 | `google.golang.org/grpc` | v1.79.3 | v1.83.2 | Medium for gRPC transports |
| GO-2026-6809 | Go standard library `crypto/x509` | go1.26.9 | go1.26.11 | Low; hardening |
| GO-2026-6859 | Go standard library `net/http` | go1.26.9 | go1.26.11 | Not practically affected |
| GO-2026-6866, GO-2026-6860 | `golang.org/x/net` (`html`) | v0.61.0 | v0.62.0 | Not affected; package not built |

### Certificate decompression in fingerprinted TLS (zstd, brotli)

Fingerprinted TLS client hellos advertise TLS certificate compression
(RFC 8879), and the client decompresses the server certificate during the
handshake, before the certificate is verified. A malicious server, or a party
able to intercept the connection, could therefore crash the Core process or
cause excessive memory use without valid credentials or a trusted certificate.
A crash ends the current VPN session.

- **zstd** (`klauspost/compress`) is advertised only by the `firefox`
  fingerprint (`fp=firefox`) in TCP TLS transports, including REALITY.
- **brotli** is advertised by the `chrome`, `edge` and `firefox` fingerprints
  in TCP TLS transports, including REALITY; by ShadowTLS, which always uses the
  Chrome fingerprint; by NaiveProxy over HTTP/2; and by the Chrome QUIC
  fingerprint of Hysteria2.
- The `safari` fingerprint advertises only zlib, which is not affected. The
  `ios` and `android` fingerprints, and connections without a fingerprint, do
  not advertise certificate compression.

### gRPC client (grpc)

The gRPC stream transport for VLESS, VMess and Trojan uses the grpc client. A
malicious or compromised gRPC server could cause excessive memory use in the
client. Other transports are not affected. The repository does not run a gRPC
server in shipped code.

### Certificate verification (crypto/x509)

Go 1.26.11 distrusts certificates issued by compromised intermediate
certificate authorities. This hardens verification of TLS server certificates
for all TLS-based protocols and for HTTPS requests such as SSConf and signed
release acquisition.

### HTML parsing (golang.org/x/net)

The fixed issues are in the `golang.org/x/net/html` package, which Bimeron
Core does not build. The update removes the module-level finding
([#154](https://github.com/bimeron/bimeron-core/pull/154), tracked by
[#151](https://github.com/bimeron/bimeron-core/issues/151)).

### HTTP server (net/http)

The fixed issues affect HTTP/1 servers. Shipped Bimeron Core code does not run
an HTTP server, so it is not practically affected. The toolchain update
removes the finding.

## Build and CI changes

- Building from source requires Go 1.26.11 or newer. The Apple release build
  gate requires exactly Go 1.26.11.
- `govulncheck` is now a blocking CI check for the `linux/amd64`,
  `windows/amd64`, `android/arm64` and `darwin/arm64` targets. Reachable
  findings fail the build. Findings in required modules whose vulnerable code
  is not called are reported without failing the build
  ([#150](https://github.com/bimeron/bimeron-core/pull/150)).
- `THIRD_PARTY_NOTICES.txt` lists the updated dependency versions.
- Documentation records the v0.4.0-beta.1 publication and the service update
  state preservation correction
  ([#148](https://github.com/bimeron/bimeron-core/pull/148)).

## Compatibility

IPC remains version **1** and profile format remains version **1**. No
capabilities, document operations or structured error codes were added or
removed.

**GUI compatibility range: [0.3.0, 0.3.2)**

## Upgrade notes / Desktop

Desktop 0.3.1 bundles this release as its CLI and repair broker, so explicit
repair keeps the service at this version. It is published together with this
release.

Desktop 0.3.0 is in the reviewed GUI range and is offered this release as a
service update when the user enables **Include beta core updates**. A service
update alone does not replace the CLI and repair broker bundled with Desktop
0.3.0, which remain v0.4.0-beta.1. To keep the bundled components current,
upgrade to Desktop 0.3.1.

Explicit repair restores the service executable bundled with the GUI package.
In Desktop 0.3.0, running Repair after this update therefore restores the Core
bundled with Desktop 0.3.0 (v0.4.0-beta.1). Desktop 0.3.0 shows Repair only
when the service is not ready. Install the update again afterwards, or upgrade
to Desktop 0.3.1, which bundles v0.4.0-beta.2. Reinstalling Desktop 0.3.0 does
not downgrade a newer installed service.

The repair broker embeds the reviewed compatibility policy from
`release/compatibility.json`, so signed acquisition of its own release accepts
the same GUI window as the publisher.

## Planned packages and verification

The asset layout matches v0.4.0-beta.1: six CLI ZIP packages for Windows,
Linux and macOS on amd64 and arm64, plus one Android AAR package. Each package
includes `LICENSE` and `THIRD_PARTY_NOTICES.txt`; Windows packages include the
matching Wintun DLL and its license. Android is an AAR, not an installable
application. Apple NetworkExtension is not included.

Verify archives with `SHA256SUMS`. Windows/Linux service update clients can
verify `update-manifest.json` with `update-manifest.json.sig` and a separately
trusted Ed25519 public key. The service manifest covers Windows/Linux amd64 and
arm64, not macOS or Android.

Before publication, freeze the candidate, complete VM acceptance of the Desktop
0.3.1 candidate with the Core candidate and the Desktop 0.3.0 service update
path, validate signed assets, and verify the tag-specific README link. These
notes do not claim completed candidate acceptance or new benchmarks.
