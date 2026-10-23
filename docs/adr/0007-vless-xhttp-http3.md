# ADR 0007: Use interface-bound QUIC for XHTTP over HTTP/3

## Context

XHTTP over HTTP/3 uses UDP for its physical connection. The VPN captures
ordinary outbound traffic, so an unbound QUIC socket could enter its own
tunnel. The current HTTP/2 XHTTP client reuses the session's bound TCP dialer.
The project also requires an MIT-compatible dependency graph and verified TLS.

## Decision

Use `quic-go` HTTP/3 when an XHTTP TLS profile explicitly sets `ALPN=h3`.
Create the QUIC UDP socket with the session dialer's `Control` hook, which
binds it to the selected physical interface or calls Android
`VpnService.protect`. Retain the socket and QUIC transport in the VLESS client
and close them on stop or reconnect. Keep HTTP/2 as the default. Reject
REALITY and uTLS fingerprints for HTTP/3 until their QUIC behavior is defined.

## Alternatives considered

- A regular HTTP/3 transport creates its own UDP socket and cannot preserve
  the VPN's physical-interface binding.
- Implementing QUIC locally would add substantial protocol and cryptography
  work without improving compatibility.
- Importing Xray-core would conflict with the project's dependency policy.

## Consequences

`quic-go` and its `qpack` dependency have MIT licenses and are included in
third-party notices. Local HTTP/3 tests cover certificate verification,
request exchange and client cleanup. Interoperability with independent XHTTP
servers and physical-device VPN routing remains to be verified.
