# ADR 0009: Use the upstream Hysteria2 client

Status: accepted, October 26, 2026.

## Context

Hysteria2 requires authenticated HTTP/3 over QUIC, TCP streams, and UDP
datagrams. Bimeron's VPN mode must bind the UDP socket to the physical
interface before installing tunnel routes. The existing quic-go dependency
does not implement the Hysteria2 protocol.

## Decision

Use `github.com/apernet/hysteria/core/v2/client` for the wire protocol and
adapt its TCP and UDP APIs to Bimeron's transport interfaces. Supply a UDP
socket through the client's `ConnFactory`, using the platform's existing
outbound interface binding. Verify TLS certificates and names. Reject link
options that the adapter does not implement.

## Alternatives and tradeoffs

- Implementing the protocol on the existing quic-go dependency avoids the
  upstream client's fork of quic-go, but requires maintaining authentication,
  stream framing, datagram fragmentation, and compatibility ourselves.
- The upstream client keeps protocol behavior aligned with Hysteria2 and
  permits an interface-bound socket. It increases binary dependencies and
  uses a separate quic-go fork. Its TCP API does not expose half-close, so
  the adapter cannot forward a TCP FIN independently of closing the stream.
- The first release supports password authentication and SNI. Additional
  link settings require explicit interoperability and security review.
- The client fixes HTTP/3 ALPN to `h3`, so `alpn=h3` asserts the protocol used
  on the wire. Named QUIC fingerprints are now supplied by the local apernet
  extension described in [ADR 0010](0010-hysteria2-quic-fingerprints.md), while
  retaining this upstream client and its TCP/UDP protocol implementation.
