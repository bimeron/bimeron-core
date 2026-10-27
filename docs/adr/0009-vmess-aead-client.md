# ADR 0009: Add a focused VMess AEAD client

Status: accepted, October 26, 2026.

The supported transport scope was expanded by ADR 0010 and ADR 0011 on
October 27, 2026. The options below describe the initial release decision.

## Context

Users need VMess share links. The VPN backend requires both TCP streams and UDP
packets, while the local SOCKS5 proxy uses TCP streams. Importing Xray-core
would add its broad module graph, including dependencies excluded by ADR 0004.
VMess authentication and body encryption must interoperate with current AEAD
servers.

## Decision

Adapt the VMess AEAD header and chunk framing from Xray-core v1.260327.0 into
focused MPL 2.0 files. Use the existing Go crypto and `x/crypto` packages,
verified Go TLS, and the existing WebSocket package. Accept only base64 JSON
`vmess://` links with alter ID zero, TCP/TLS or WebSocket/TLS, and AES-128-GCM
or ChaCha20-Poly1305 body encryption. Map `auto` to AES-128-GCM. Implement one
UDP stream per destination through the existing packet interface. Reject
unsupported JSON fields and transports during validation.

## Alternatives and tradeoffs

- Importing Xray-core would cover more VMess variants but conflicts with the
  project's dependency and distribution constraints.
- A separate native protocol implementation would avoid adapting MPL files but
  increase cryptographic compatibility and maintenance risk.
- The focused client requires comparison with upstream protocol changes and
  reference-server tests. Legacy alter IDs, plaintext, HTTP/2, gRPC, QUIC,
  REALITY, and browser TLS fingerprints remain unsupported.

## Verification

The optional `BIMERON_XRAY_BIN` integration test starts an Xray reference
server and checks TCP and UDP echo over both supported networks and both body
ciphers. Ordinary CI runs parsing and build tests without a bundled Xray
binary. Real remote servers and mobile VPN devices still need field testing.
