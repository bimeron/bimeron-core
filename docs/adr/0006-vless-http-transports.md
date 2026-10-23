# ADR 0006: Add focused VLESS HTTP transports

## Context

Bimeron already has VLESS framing, XUDP, TCP TLS/REALITY and WebSocket TLS.
Common profiles also use WebSocket early data, gRPC and XHTTP. Importing the
whole Xray-core module would bring an incompatible dependency graph into the
MIT-based Bimeron build. Reimplementing HTTP/2, TLS or REALITY cryptography is
unnecessary and difficult to maintain.

## Decision

Keep the existing VLESS framing and interface-bound physical dialer. Add
WebSocket early data to the current WebSocket handshake. Use `grpc-go` for
HTTP/2 gRPC, with a small local codec for Xray's single-field `Hunk` message.
Use Go's HTTP client and `x/net/http2` for a focused XHTTP client. Support
gRPC `Tun` with TLS, XHTTP `packet-up` with TLS, and XHTTP `stream-one` with
REALITY. Reject other modes and options during profile validation. Each
transport connection is owned by the VLESS client and closed on session stop
or reconnect.

## Alternatives considered

- Importing Xray-core: broad compatibility, but its dependency graph conflicts
  with the project's license constraint and substantially increases the build.
- Implementing gRPC over raw HTTP/2: fewer dependencies, but more protocol code
  and maintenance risk than `grpc-go`.
- Copying XHTTP transport code from Xray: closer feature parity, but it pulls
  in HTTP/3, xmux and other settings outside the supported matrix.

## Consequences

The core has a strict, documented subset of Xray transport options. The gRPC
dependency graph adds Apache 2.0 and BSD-licensed modules; their notices are
included in `THIRD_PARTY_NOTICES.txt`. No GPL/LGPL module is added. Local tests
exercise profile parsing, gRPC framing, XHTTP packet requests and WebSocket
early data. Independent server profiles and physical-device VPN tests remain
necessary to establish interoperability across platforms.
