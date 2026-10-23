# ADR 0004: Embed a focused VLESS client without GPL dependencies

Status: accepted, October 23, 2026.

## Context

Bimeron needs VLESS over TCP with REALITY and XTLS Vision in its proxy and
packet VPN backends, including Android and Apple embeddings. Importing
Xray-core brings `sagernet/sing` into the compiled Go dependency graph. The
separate `xtls/reality` module imports `juju/ratelimit` under LGPLv3. Bimeron
must keep its own source under MIT and its distributed binaries free of GPL
and LGPL dependencies.

## Decision

Adapt only the required client protocol paths from Xray-core v1.260327.0 as
separately attributed MPL 2.0 files. Use uTLS and existing Go cryptographic
libraries for REALITY. Implement VLESS framing, Vision stream handling, and
XUDP framing behind the existing Outline SDK transport interfaces. Pin uTLS
because Vision's direct-copy transition reads its internal buffers. Keep the
full MPL text and source attribution with the distribution notices. Reject
unsupported URI options instead of silently changing their meaning.

## Tradeoffs

- Bimeron's original code remains MIT, while adapted protocol files retain
  MPL 2.0 obligations. This is not an MIT-only source tree.
- The client is smaller than an embedded Xray-core and contains no GPL/LGPL
  module, but protocol updates must be compared with upstream Xray.
- uTLS buffer access is version-sensitive and requires a pinned dependency,
  a runtime layout check, and interoperability tests with a reference server.
- The existing local SOCKS5 proxy supports TCP CONNECT. XUDP supplies UDP to
  the packet VPN backend; it does not add SOCKS5 UDP ASSOCIATE.
