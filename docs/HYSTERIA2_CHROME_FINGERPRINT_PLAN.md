# Versioned Chrome QUIC fingerprints (#23)

Status: implemented. PR #24 CI passed. Independent Chrome for Testing Initial
captures were added on October 28, 2026; see ADR 0011 for scope and limits.

## Contract and implementation order

Extend the existing apernet backend, first Chrome 115, then Chrome 146.
Add exactly `chrome-115` and `chrome-146`; preserve `chrome`, omitted `fp`,
and all Firefox aliases. Select the address-family variant from the actual
remote UDP address. Keep TLS verification, h3, bound socket creation, and
official Hysteria TCP/UDP relay. No fallback for unsupported fingerprints.
Errors must not contain passwords, complete URIs, or authentication headers.

Reference: uquic commit 837c7ce1b72bf07b2d29b3dabd5b45c60bec0f42,
QUICChrome_115_IPv4/IPv6 and QUICChrome_146_IPv4/IPv6. Audit encoded bytes
and provenance rather than trusting comments. These are historical handshake
presets, not a claim of complete browser emulation. Retain MIT attribution.

## Acceptance gates

- Capture and decrypt real UDP Initials for both versions and address families.
  Reassemble CRYPTO across packets and compare independent expectations for
  ClientHello, transport parameters, IDs, packet numbers, frame layout, padding.
- Chrome 146 must emit and successfully use the hybrid key share and a
  multi-datagram Initial flight. Advertised limits must match runtime behavior.
- Exercise Retry, HelloRetryRequest, loss/retransmission, TLS rejection, ALPN,
  concurrent presets, TCP and fragmented UDP against the unmodified server.
- Test parsing, validation, duplicate/unknown rejection, and secret-free errors.
- Preserve legacy Chrome and Firefox wire/integration tests.
- Update CONF.MD, GUI_INTEGRATION.MD, ADR and dependency patch inventory.
- Run root and nested tests, race CI, CLI and Android builds. Report physical
  interface runtime evidence separately from callback tests and cross-builds.

An incompatible TLS engine or backend change requires renewed architecture
discussion. A reference discrepancy must be resolved or explicitly documented
before claiming the corresponding fingerprint is verified.

## Local validation (October 27, 2026)

Passed root `go test ./...` and `go vet ./...`; nested QUIC unit, wire,
handshake and ackhandler tests; Firefox/Chrome integration; nested Hysteria
client/server tests; QUIC `go vet ./...`; Linux/amd64 WSL race checks matching
CI (excluding only the existing STREAM allocation assertion under race).
Built and checked all six CLI distributions, validated both synthetic URI
profiles with the built Windows CLI, and built the four-ABI Android AAR with
NDK 27.1.12297006 (CI pins 27.2). Verified ABI entries and license copies.
A five-iteration Windows first-Initial benchmark smoke run passed for all
families; it is not a statistically meaningful speed comparison.

On October 28, 2026, official Chrome for Testing 115.0.5790.170 and
146.0.7680.165 supplied independent IPv4/IPv6 Initial captures. Their
decrypted fields corrected the versioned presets as recorded in ADR 0011.
The captured packets and SHA-256 provenance are kept in the nested QUIC module's
`testdata/chrome-browser-initial/` directory. This verifies the recorded
Initial fields for those browser builds and launch conditions; it does not
establish a distributional match or subsequent browser transport behavior.

No real VPN or physical-interface routing was performed. CI already selects
the ChromeParrot integration tests. PR #24 CI passed; CI for this later capture
correction branch remains pending publication.
