# ADR 0006: Support Trojan over TCP/TLS with UDP relay

Status: accepted, October 23, 2026.

## Context

Bimeron's VPN backend requires both stream and packet upstream interfaces.
It checks TCP and UDP/DNS before installing the tunnel. A TCP-only Trojan
client would therefore work only with the local SOCKS5 proxy mode.

## Decision

Implement the standard Trojan TCP/TLS transport for both TCP connections and
UDP datagrams. Use Go's verified TLS client with the server address as the
default certificate name, or an explicit SNI name. Reuse the existing
stream and packet interfaces, outbound network binding, and VPN precheck.
Accept `trojan://` links and explicit profile settings. Reject unsupported
URI options and transport combinations.

## Tradeoffs

- Supporting UDP in the first version makes the protocol usable in VPN mode
  and requires datagram framing and packet connection lifecycle handling.
- Standard TLS adds no new module dependency. Browser TLS fingerprints and
  WebSocket, gRPC, and REALITY transports need separate interoperability work.
- Certificate verification is mandatory; profiles have no insecure toggle.

## Follow-up

[ADR 0022](0022-shared-grpc-trojan-transports.md) adds verified WebSocket/TLS
and gRPC/TLS transports while retaining this TCP/TLS baseline.
