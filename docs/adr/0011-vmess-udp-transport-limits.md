# ADR 0011: Require protected VMess transport and reliable UDP boundaries

Status: accepted, October 27, 2026.

## Context

VMess profiles in Bimeron must carry TCP streams and UDP packets for the VPN.
Xray-core v1.260327.0 also recognizes mKCP, Hysteria, and the `zero` VMess
body mode. Recognizing a name in a share link is insufficient unless the
transport preserves the protection and packet behavior required by Bimeron.

## Decision

Support the XHTTP HTTP/3, XHTTP `stream-one`, and TCP, gRPC, and XHTTP REALITY
combinations verified against a local Xray server. Reject mKCP, Hysteria, and
`scy=zero` at import for now. Keep legacy alter IDs and unprotected transports
outside the VMess scope.

Xray's mKCP dialer wraps its KCP connection in TLS when configured, so mKCP/TLS
can meet the protection requirement. Implementing it requires a separate KCP
packet transport and UDP lifecycle, beyond the existing stream adapters.
Xray's Hysteria transport uses QUIC/TLS and a separate HTTP/3 authentication
exchange, stream format, and UDP datagrams. The current common base64 JSON
`vmess://` importer has no defined mapping for its transport authentication.
Neither transport is silently mapped to another network.

Xray maps VMess `zero` to security `none` with chunk framing disabled after
the authenticated request header. The resulting byte stream has no UDP packet
boundaries. In a local Xray interoperability test, two consecutive datagrams
`one` and `two` were returned as one `onetwo` packet. Supporting TCP alone
would leave an imported VPN profile unable to carry UDP reliably. A future
implementation needs an explicit packet-preserving design and repeated UDP
interoperability tests before accepting `zero`.

## Alternatives and tradeoffs

- Importing Xray-core would supply the other transports but add its broad
  dependency graph, which conflicts with the compiled-license constraint.
- Adapting mKCP and Hysteria into focused transport packages would avoid that
  graph, but requires separate protocol, lifecycle, and cross-platform tests.
- Accepting `zero` for TCP only would make a profile appear valid while its VPN
  UDP traffic fails or changes packet boundaries.

## Verification

The optional Xray interoperability test covers TCP, UDP, and reconnects on
every supported VMess transport and security combination. CI checks the
compiled dependency graph and third-party notices. The `zero` UDP boundary
failure was reproduced locally against Xray-core v1.260327.0.
