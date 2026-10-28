# ADR 0026: Explicit NaiveProxy HTTP/3 CONNECT

Status: accepted, October 28, 2026. Tracks issue #62. Extends ADR 0021.

## Context

Upstream NaiveProxy supports a `quic://` proxy and carries the same authenticated
CONNECT and negotiated first-eight-record padding protocol over HTTP/2 and
HTTP/3. Bimeron already uses quic-go HTTP/3 for XHTTP and must preserve embedded
operation and interface-bound outbound sockets.

## Decision

Add `naive+quic://` alongside `naive+https://`. Both resolve to the existing
Naive profile, with `Naive.QUIC` selecting HTTP/3. Existing URI and explicit
parameter profiles retain HTTP/2 behavior. URI sources (`Naive`, `Key`, and
`File`) expose HTTP/3 without another global configuration field.

Use the existing github.com/quic-go/quic-go HTTP/3 transport. Share CONNECT,
Basic proxy authentication, padding and stream lifecycle code with HTTP/2.
Pool by proxy endpoint while CONNECT authority names the target. Resolve the
proxy through the supplied dialer's resolver, prefer IPv4 when both families
are available, and create UDP sockets through its Control hook. Preserve the
original TLS server name independently of resolved IPs. Verify certificates,
require TLS 1.3 and h3, and complete the handshake before sending credentials.
Each connection owns its socket; failed handshakes, connection termination
and client closure release sockets, including pending dials.

The upstream remains a stream dialer: TCP-only user traffic, DNS over TCP in
VPN mode, and dropped other proxy-routed UDP. UDP transport to the proxy does
not imply UDP relay. Reject ShadowTLS with HTTP/3 because it wraps TCP.

## Alternatives and tradeoffs

- Automatic H3-to-H2 fallback would help when UDP is blocked, but adds latency,
  error classification and switching rules. Explicit protocol selection keeps
  failures predictable; fallback is outside this change.
- A Chromium subprocess would provide a closer browser fingerprint, but adds
  packaging and lifecycle costs for Android and Apple embeddings. The embedded
  Go implementation is protocol-compatible and makes no Chromium fingerprint
  claim for TLS, HTTP/2, QUIC or HTTP/3.
- No new dependency, transport framework, proxy chain, datagram relay or 0-RTT
  support is introduced. A fresh UDP socket per connection favors predictable
  cleanup over socket sharing across reconnects.

## Verification

Exercise H2/H3 ordinary and padded tunnels, authentication and TLS failures,
SNI mismatch, setup-context lifetime, concurrent streams, half-close, client
close during CONNECT and handshake, resolver and socket-control hooks, and
reconnection with a new socket. Preserve VPN TCP-only profile behavior.
Use pinned Caddy with the independent klzgrad/forwardproxy implementation for
large padded transfers and HTTP through local SOCKS5, disabling H2 for the H3
fixture. Run unit, race and reference checks plus a loopback H2/H3 benchmark
in CI, retaining existing CLI, Android and Apple build checks.
