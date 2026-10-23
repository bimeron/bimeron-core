# ADR 0008: Model extended XHTTP settings without importing Xray-core

## Context

XHTTP offers optional request headers, padding and metadata placement,
`downloadSettings`, and xmux connection limits. The current client implements
the default HTTP/2 layout with one `http2.Transport`. That transport hides its
physical connection pool, so applying Xray's xmux counters to it would be
misleading. A separate download endpoint also needs DNS resolution and a
physical-interface-bound socket before the VPN changes routes.

## Decision

Parse a percent-encoded XHTTP `extra` JSON object from links and equivalent
explicit `.conf` fields into one typed settings value. Keep Xray's JSON field
names for link compatibility. Accept `headers`, `xPaddingBytes`, padding
placement/key/header/method, session and sequence placement/key, and the
uplink HTTP method only when the request builder implements each option.
Reject unknown options and invalid combinations. `.conf` should provide
separate `XHTTP`-prefixed fields for simple values and an `XHTTPExtra` JSON
field for structured settings; the two forms must not silently override each
other. Implement these options in one request builder shared by GET,
streaming POST and packet POST. Preserve the existing default request layout
when `extra` is absent.

Represent `downloadSettings` as a second endpoint and transport owned by the
same VLESS client generation. Resolve its hostname with the bootstrap
resolver before the tunnel starts, retain its original TLS name, bind every
physical socket through the selected network dialer, and close both transports
on stop or reconnect. Support a second XHTTP-over-TLS or REALITY endpoint and
its host, path, name, ALPN and authentication settings first. Reject nested
downloads, unsupported transport types and `downloadSettings` with
`stream-one`; never silently reuse the upload endpoint for an invalid
download configuration.

For xmux over HTTP/2, use an explicit pool of `http2.ClientConn` values so
max concurrency, max connections, reuse count and age refer to actual physical
connections. Each connection must be closed when its generation ends. Reject
xmux settings for HTTP/3 until QUIC connection accounting has an equivalent
implementation. Map Xray's `maxConcurrency`, `maxConnections`,
`cMaxReuseTimes`, `hMaxRequestTimes`, `hMaxReusableSecs` and
`hKeepAlivePeriod` fields explicitly. Keep the current `http2.Transport` path
for profiles without xmux settings.

## Alternatives considered

- Exposing xmux fields while retaining the opaque `http2.Transport` pool would
  accept configurations whose limits are not enforced.
- Importing Xray-core would add a prohibited dependency graph.
- A separate unbound HTTP client for downloads could loop into the VPN.

## Consequences

The implementation uses a dedicated HTTP/2 pool when xmux is set. Each pool
tracks physical connections and active requests; request bodies release their
slot on close or EOF. Separate download settings retain the Xray nested JSON
shape at import, then use a second bound transport owned by the same session.
Server-only fields can be parsed for compatibility but have no client effect.

The GUI contract can expose only fields implemented and validated by the core.
Connection-pool tests must cover limit enforcement, concurrent TCP/XUDP
streams, close and reconnect. Download tests must verify separate endpoint
selection and cleanup. Working control profiles are still required for
interoperability and physical-device VPN checks.

The current Xray WebSocket implementation sends early data in
`Sec-WebSocket-Protocol`. A configurable early-data header would not be
interoperable with that server behavior, so it remains unsupported unless a
specific compatible server format and control profile are identified.
