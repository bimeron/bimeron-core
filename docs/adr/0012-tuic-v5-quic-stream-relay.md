# ADR 0012: TUIC v5 with QUIC stream UDP relay

## Status

Accepted for the first TUIC v5 implementation.

## Context

Bimeron already uses `quic-go` and exposes stream and packet transports to
the VPN handler. TUIC v5 defines authenticated QUIC streams for TCP and two
UDP relay modes: QUIC datagrams (`native`) and unidirectional streams (`quic`).
The latter carries a full UDP packet without datagram MTU fragmentation on
the sending side. A real remote profile is unavailable, so interoperability
can be checked with the upstream reference server on localhost.

## Decision

Implement TUIC v5 with TLS certificate verification, `quic-go`, shared QUIC
connections, TCP streams, and `quic` UDP relay mode. Parse `tuic://` links
strictly. Accept fragmented UDP responses and reassemble them with bounded
memory. Use the existing outbound interface binding for the QUIC socket.

## Alternatives

- Native QUIC datagrams are common but require sender fragmentation and path
  MTU handling. Add them when interoperability testing or users require them.
- A separate TUIC library would introduce another QUIC stack and a larger
  dependency tree. The existing `quic-go` package covers this scope.

## Consequences

Servers must support TUIC v5 `udp_relay_mode=quic`. Keys requiring `native`
are rejected. Local protocol tests verify authentication, TCP, UDP, and
fragment reassembly. An optional test also verifies TCP and UDP against the
upstream `tuic-server` v1.0.0 reference implementation on localhost. Remote
network behavior remains unverified.
