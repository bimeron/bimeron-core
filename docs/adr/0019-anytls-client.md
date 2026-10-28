# ADR 0019: Implement a focused AnyTLS client

Status: accepted, October 28, 2026.

## Context

Bimeron's proxy mode needs a TCP stream dialer; its VPN mode also needs a UDP
packet listener. AnyTLS carries both through TLS, with mandatory session reuse,
padding scheme updates, and sing-box UDP-over-TCP version 2. Its upstream Go
client is GPLv3, while the reference implementation does not publish a license.
ADR 0004 excludes GPL and LGPL code from distributed binaries.

## Decision

Implement the documented AnyTLS wire protocol in a focused internal package,
without copying upstream implementation code. Reuse Bimeron's certificate-
verified TLS and existing stream and packet interfaces. Accept `anytls://`
links with password, server address, optional SNI, and `insecure=0`; reject
unsupported parameters. Support TCP in proxy mode and TCP plus UDP in VPN
mode. Keep the server-selected padding scheme per client and reuse healthy idle
sessions.

## Alternatives and tradeoffs

- Importing `github.com/anytls/sing-anytls` would reduce protocol work but
  violate the compiled GPL dependency constraint.
- Shipping only a TCP adapter would leave VPN mode unusable. Shipping a client
  without session reuse or padding updates would violate the protocol.
- A focused implementation keeps the dependency graph small, but requires
  reference-server interoperability tests and continued protocol maintenance.

## Verification

Use local parser and session tests plus optional interoperability tests against
the upstream server for TCP and UDP. CI runs unit tests, race checks, and
cross-platform build checks. The reference-server benchmark measures a 16-byte
TCP request and response with fresh TLS sessions and with idle session reuse.
It is a local regression aid, not a comparison of network performance between
protocols.
