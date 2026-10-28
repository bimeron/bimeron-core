# ADR 0022: Share gRPC transport ownership and add Trojan HTTP transports

Status: accepted, October 28, 2026.

## Context

ADR 0015 left gRPC and XHTTP ownership in VLESS until another protocol needed
these streams. Trojan now needs gRPC/TLS and WebSocket/TLS. Reusing a VLESS
client for Trojan would require an artificial user ID and couple password
authentication to unrelated protocol configuration.

## Decision

Move Xray-compatible gRPC stream ownership, Hunk/MultiHunk codecs, method
selection, and the net.Conn adapter into `internal/streamtransport`. VLESS,
VMess, and Trojan use this component directly. Its small configuration holds
address, HTTP authority, service name, multi mode, and a connection callback.
That callback supplies a TLS- or REALITY-authenticated HTTP/2 connection;
the component does not import protocol profiles or own their authentication.
The caller closes each stream; the transport owner closes the reusable
HTTP/2 connection and rejects later streams.

Keep TLS/REALITY handshakes with the existing callers. VMess still uses the
VLESS secure-connection adapter for REALITY and its existing VLESS adapter for
XHTTP. XHTTP is not moved. Trojan does not import VLESS and uses verified TLS
only. SNI remains independent of HTTP authority.

Support Trojan TCP/TLS, binary WebSocket/TLS, and gRPC/TLS single and multi
against Xray v1.260327.0. Reuse existing Trojan TCP and UDP framing above the
stream. Preserve TCP/TLS defaults. Reject unsupported transport options.
Trojan WS early data, custom gRPC paths, REALITY, and fingerprints are outside
this initial contract. Trojan-Go has been compared at source level but is
not an independently verified target. See `docs/TROJAN_TRANSPORTS.MD`.

## Alternatives and tradeoffs

- Reusing VLESS.DialTransport would minimize the diff but retain the artificial
  profile and make a third protocol depend on VLESS's transport owner.
- Moving all HTTP transports would improve separation further but broaden
  the regression surface beyond this feature.
- Duplicating gRPC would avoid package coupling while duplicating wire and
  lifecycle maintenance. Importing Xray would violate dependency constraints.

The shared adapter retains the existing deadline behavior: read or write
deadlines cancel the entire stream; an expired stream is not reusable.
Changing that behavior requires separate design and interoperability work.
The setup context is detached after stream creation, so callers may cancel
setup without killing a working connection. Protocol callers remain
responsible for bounding and canceling their initial request write.

## Verification

Shared tests cover codecs, custom method naming, single/multi streams,
connection reuse, canceled setup, parallel streams, deadlines, and owner
shutdown. The reference fixture in `internal/vmess` verifies both VLESS and
VMess gRPC over TLS and REALITY with TCP and UDP, while retaining the complete
VMess transport matrix. Trojan's reference fixture verifies TCP/TLS, WS/TLS,
and gRPC single/multi with TCP, UDP, parallel large transfers, wrong-route
rejection, and shutdown. CI runs the reference fixtures and race checks.
No production dependency or license family is added.
