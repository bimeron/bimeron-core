# ADR 0005: Extend the focused VLESS client with TLS and WebSocket

Status: accepted, October 23, 2026.

## Context

The existing VLESS client couples TCP, REALITY, and Vision. Common VLESS
profiles also use ordinary TLS over TCP and WebSocket over TLS. The core must
use its selected outbound network interface in VPN mode and keep the binary
free of GPL and LGPL dependencies.

## Decision

Use the existing VLESS framing and XUDP implementation for all supported
transports. Apply Vision only to the REALITY flow. Use Go's verified TLS
client by default; use the already pinned uTLS dependency when a TLS
fingerprint is explicitly configured. Use `golang.org/x/net/websocket`,
already in the module graph under a BSD license, over the protected TLS
connection. WebSocket uses HTTP/1.1 ALPN. Reject unsupported combinations
and options rather than silently ignoring them.

## Tradeoffs

- No new module dependency or license family is introduced.
- A configured uTLS fingerprint can differ from an actual browser when its
  ALPN list is restricted to HTTP/1.1 for WebSocket compatibility.
- WebSocket early data, gRPC, and XHTTP need separate interoperability work.
- TLS certificate verification remains mandatory; no insecure toggle is
  provided by this change.
