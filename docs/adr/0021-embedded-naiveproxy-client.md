# ADR 0021: Embed a NaiveProxy-compatible HTTP/2 client

Status: accepted, October 28, 2026. Tracks issue #42.

HTTP/3 support is added by [ADR 0026](0026-naiveproxy-http3.md); the original
HTTP/2 decision and remaining limits below describe the first version.

## Context

NaiveProxy carries TCP streams through authenticated HTTPS CONNECT, optionally
with a negotiated padding format. The official client uses Chromium's network
stack to match browser traffic. Bimeron also runs inside Android and Apple
embeddings, where managing a separate Chromium-based process would not fit the
existing transport lifecycle or interface-bound outbound dialer.

## Decision

Implement an in-process Go HTTP/2 CONNECT client behind the existing stream
dialer interface. Reuse the project's uTLS Chrome ClientHello and x/net HTTP/2
transport. Verify certificates and server names, require HTTP/2 ALPN, use Basic
proxy authentication, and implement NaiveProxy's optional first-eight-record
padding. Accept a dedicated `naive+https://` access URI rather than treating
arbitrary HTTPS URLs as access keys. Support TCP in local proxy and TCP-only VPN
modes; use the existing DNS-over-TCP and UDP-drop behavior in VPN mode.

## Tradeoffs

- Go's HTTP/2 frames and settings need not match Chromium's. This client is
  protocol-compatible, but exact Chromium camouflage is not claimed.
- HTTP/3, UDP relay, proxy chains, insecure TLS, and custom Chrome releases are
  outside this first version.
- The in-process approach keeps Android and Apple support and interface-bound
  dialing, but requires interoperability and wire-behavior checks against
  upstream NaiveProxy releases.

## Verification

Exercise ordinary and padded HTTP/2 CONNECT streams, auth failures, TLS
verification, cancellation, and concurrent streams. Test profile parsing and
TCP-only VPN integration. Check large payloads against pinned Caddy with the
independent klzgrad/forwardproxy padding implementation. Run unit and race tests on CI, plus existing platform
builds. Compare TLS and HTTP/2 captures with the official client before any
claim of indistinguishable traffic.
