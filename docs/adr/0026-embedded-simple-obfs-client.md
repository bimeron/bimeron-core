# ADR 0026: Embed a focused simple-obfs client

Status: Proposed, October 28, 2026. Research and implementation handoff only;
the transport is not implemented or verified yet.

Tracking issue: [#61](https://github.com/bimeron/bimeron-core/issues/61).

## Context and alternatives

Bimeron supports direct Shadowsocks AEAD and Shadowsocks 2022, plus embedded
v2ray-plugin WS/WSS with Mux. It rejects `plugin=obfs-local`. The requested
feature is compatibility with simple-obfs HTTP and TLS servers.

An external `obfs-local` process would reuse upstream behavior but require
platform-specific binaries, trusted executable selection, subprocess lifecycle
management, and a different mobile integration strategy. An embedded Go client
fits the existing transport interfaces and requires no runtime executable.
The embedded approach is recommended; this proposal records its concrete scope
for review before implementation.

The original project is deprecated and licensed under GPL-3.0-or-later. ADR 0004
requires distributed Bimeron binaries to remain free of GPL/LGPL dependencies.
Do not copy or translate upstream implementation files, vendor them, or link
them into Bimeron. Write the interoperability implementation in this repository;
keep the original server in an isolated reference-test build. Do not describe
source research as a clean-room process or remove third-party license terms.

## Reference versions and observed wire behavior

Research baseline: Bimeron master `7ed3ae3`.

- Original release v0.0.5: `a9c43588e4cb038e6ac02f050e4cab81f8228dff`.
- Original final master: `486bebd9208539058e57e23a12f23103016e09b4`.
- The TLS framing source and header are identical between these revisions.
  Later HTTP changes add configurable request method and URI. Default HTTP
  behavior remains `GET /`; test this against both revisions. Test custom
  methods and URIs against the final revision.

### HTTP

The client prepends one HTTP/1.1 request header to the first encrypted bytes.
The header includes Host, a curl-style User-Agent, Upgrade and Connection,
a random Sec-WebSocket-Key, and Content-Length for that initial payload.
Upstream defaults the host to `cloudfront.net`, not the v2ray-plugin default
`cloudfront.com`. It appends the actual remote port to the HTTP Host when that
port is not 80. The default URI is `/` and the default method is `GET`.

The server prepends an HTTP/1.1 101 response header once. It can send an empty
101 response before backend payload arrives. Following the initial headers,
both directions carry raw encrypted Shadowsocks bytes. There are no WebSocket
frames, masking, Mux frames, or additional HTTP requests. Content-Length does
not delimit the lifetime of the underlying stream. The server's
Sec-WebSocket-Accept is independently random; a WebSocket handshake validator
would reject a valid simple-obfs peer.

Parse the response incrementally through the first CRLF-CRLF, with a bounded
header size, and preserve any following payload already buffered. Accept an
empty initial response without returning a misleading EOF. Validate the
expected response status without imposing ordinary WebSocket validation.

### TLS

This is a TLS-shaped byte stream, not a TLS session. Do not call the shared
TLS helper, uTLS, certificate verification, or the ShadowTLS implementation.
The inner Shadowsocks protocol supplies encryption and authentication.

The first client write becomes a ClientHello-shaped record: record version
0x0301, handshake version 0x0303, random and session ID fields, and encrypted
Shadowsocks bytes in a session-ticket extension (0x0023). The original server
expects a fixed ClientHello prefix, including the cipher-suite list length,
and the session-ticket extension immediately after that prefix. A generic
TLS ClientHello with arbitrary extension order is insufficient. SNI follows
the ticket, then the remaining protocol extensions. Preserve the required
wire layout while writing the encoder independently.

The first server response consists of ServerHello, ChangeCipherSpec, then
an encrypted-handshake-shaped record whose body contains the first encrypted
Shadowsocks response bytes. Those body bytes are payload, not padding to
discard. Subsequent records in both directions use application-data type
0x17 and version 0x0303, with a two-byte big-endian payload length.

The upstream decoder rejects application-data records larger than 16,384
bytes. Split large writes; never encode the length by truncating to uint16.
Bound the entire initial ClientHello below the original server's 16 KiB input
buffer, including host and extension overhead. Carry remaining first-write
bytes in application-data records. Verify the exact first-record budget and
all integer conversions in the transport implementation.

Maintain receive state across arbitrary read boundaries, including partial
record headers, first-response payload, and several records in one read.
Bound lengths before allocating or consuming a body. Reject malformed or
truncated framing; do not replay bytes through a plain TCP connection.

## Proposed integration

### Configuration handoff (Low)

Keep `Profile.SSPlugin` as the single plugin configuration entry point.
Extend the existing settings with a plugin discriminator and the required
simple-obfs settings. An empty discriminator must retain the current
v2ray-plugin meaning for existing direct Go callers. Prefer reusing the
existing Host and Path fields where their meanings align; avoid a general
plugin registry or an executable interface.

- Canonical identifier: `obfs-local`. The project name `simple-obfs` is not
  an executable alias by default. Reject `obfs-server`, paths, and other names.
- Require exactly one `obfs=http` or `obfs=tls` setting. Omitting it must not
  silently select direct TCP or a default obfuscation mode.
- Optional `obfs-host`, default `cloudfront.net`. It controls HTTP Host or
  the TLS-shaped SNI, not the network endpoint or certificate trust.
- For HTTP only, accept `obfs-uri` (default `/`) and `http-method` (default
  `GET`). Require an origin-form URI and an HTTP token method. Reject raw
  whitespace, control characters, fragments, and header injection. Preserve
  escaped path/query content rather than decoding the URI a second time.
- For TLS, reject HTTP-only options, even when upstream silently ignores
  them. Reject WS/TLS/Mux options belonging to v2ray-plugin and contradictory
  direct Go settings; conversely reject obfs options on v2ray-plugin.
- Validate hosts and bound lengths for the wire encoders. Do not resolve
  the camouflage host or substitute it for the configured server.
- Reuse the existing SIP003 escaped-options scanner. Preserve duplicate,
  malformed-escape, unknown-option, and missing-value rejection. URI query
  decoding happens once before the plugin scanner.
- URI, simple JSON/YAML, and explicit `Plugin`/`PluginOpts` must use the same
  parser. Retain the existing rejection of plugins in unsupported transport
  config shapes. Errors must not echo credentials or raw option strings.
- Keep all existing v2ray-plugin defaults, presence semantics, and tests.

Parser checks: both modes, default/custom host, HTTP URI/method, percent and
backslash escaping, duplicate options and plugin query parameters, unknown
identifiers, invalid combinations, and matching URI/JSON/YAML/INI results.
Include direct Go configuration validation and credential-safe errors.

### Transport and runtime handoff (Medium)

Add a focused `internal/simpleobfs` stream wrapper. Compose it with
`proxy.OutlineStream` through `transport.StreamEndpoint`, so classic AEAD,
salt-prefix rules, and SS2022 identity handling stay in their existing layers.
Have `ssplugin.New` dispatch the new configuration while preserving its
existing public call sites. Refactor only the lifecycle code needed to return
a common stream client with `DialStream` and `Close`; do not add a second
encryption implementation or change the WS/Mux protocol.

The outbound `net.Dialer` must preserve interface controls. Keep socket setup
and the initial encrypted request bounded by a setup deadline and context
cancellation. Do not wait for a server response before sending the first
encrypted request: the TLS server waits for backend response data. Ensure
the deadline also covers SS2022's eager request write and does not remain
attached to established application traffic.

Support concurrent reading and writing with separate framing state. Handle
short writes and zero-progress writes, report counts in caller payload bytes,
and make framing failures terminal. Do not keep a global I/O lock across a
blocking read. Closing the client must interrupt connection setup and active
I/O, release owned connections, and reject new connections. Never hold an
ownership lock while waiting for network operations. Define and test half-close
behavior against the actual server instead of promising end-to-end half-close
merely because the raw socket supports it.

Use the existing TCP-only plugin policy initially: clear the UDP endpoint,
use DNS over TCP in VPN mode, and drop other proxy-routed UDP. This is a
Bimeron scope choice, not a claim that ordinary Shadowsocks UDP is impossible
alongside simple-obfs. Adding a separate native UDP endpoint would require an
explicit profile design; do not silently send it without obfuscation.

Keep the existing ShadowTLS/plugin combination rejection. Verify bootstrap
endpoint resolution, route exclusions, local proxy creation, VPN creation,
CLI checks, network replacement, and runtime shutdown. Do not route obfs
profiles into the WS/TLS-specific diagnostic or certificate paths.

### Interoperability and acceptance (Medium)

Run the original `obfs-server` as a standalone process in front of the
independent backend already used by plugin tests (Xray, in a separate process).
Test the wrapper alone against the original server and a TCP echo backend as
well, so framing defects are distinguishable from Shadowsocks defects.

- HTTP and TLS; default host and custom host; custom HTTP URI/method.
- Classic `aes-128-gcm`, `aes-256-gcm`, and `chacha20-ietf-poly1305`.
- All three existing SS2022 methods, plus AES identity chains. Do not claim
  compatibility until these tests pass. Explicitly cover or document any
  existing cipher unsupported by the independent reference backend.
- Large bidirectional transfers, independent concurrent connections, server
  disconnects, reconnects, deadlines, cancellation, and runtime cleanup.
- Synthetic peers for fragmented/coalesced headers and records, short writes,
  empty initial responses, truncated bodies, oversized lengths, and malformed
  input. Do not reproduce upstream's fragile partial-read assumptions.
- Existing direct Shadowsocks and v2ray-plugin regression tests.

### Documentation and CI handoff (Low)

Build pinned reference revisions in an isolated Linux test step, including
pinned transitive build inputs/submodules. Final master is required for custom
HTTP parameters; also test default profiles against v0.0.5. Verify downloaded
archives by checksum when using release artifacts. Keep the original license
with reference source; do not add these binaries to distributed artifacts.

Use explicit reference binary environment variables and a required-interop
flag: local runs may skip absent references, CI must fail instead. Follow the
existing Xray/plugin setup and add targeted race tests. Add a focused HTTP/TLS
transfer benchmark without hardware-specific pass/fail thresholds. Run the
existing test, vet, and compiled-dependency-notice checks.

Update `docs/SHADOWSOCKS_TRANSPORTS.MD`, `docs/CONF.MD`, CI documentation, and
examples. Explain the canonical plugin name, defaults, port behavior,
HTTP-only options, fake TLS, TCP-only VPN behavior, and verified cipher scope.
Do not mark this ADR accepted or the feature supported before the architecture
is agreed and implementation is verified. Discuss results before opening a PR;
push only when requested.

## Sources

- [Original README and license](https://github.com/shadowsocks/simple-obfs/blob/486bebd9208539058e57e23a12f23103016e09b4/README.md)
- [Client options and defaults](https://github.com/shadowsocks/simple-obfs/blob/486bebd9208539058e57e23a12f23103016e09b4/src/local.c)
- [HTTP protocol reference](https://github.com/shadowsocks/simple-obfs/blob/486bebd9208539058e57e23a12f23103016e09b4/src/obfs_http.c)
- [TLS protocol reference](https://github.com/shadowsocks/simple-obfs/blob/486bebd9208539058e57e23a12f23103016e09b4/src/obfs_tls.c)
- [TLS wire structures](https://github.com/shadowsocks/simple-obfs/blob/486bebd9208539058e57e23a12f23103016e09b4/src/obfs_tls.h)
- [Original server buffering](https://github.com/shadowsocks/simple-obfs/blob/486bebd9208539058e57e23a12f23103016e09b4/src/server.c)
- [v0.0.5 HTTP reference](https://github.com/shadowsocks/simple-obfs/blob/a9c43588e4cb038e6ac02f050e4cab81f8228dff/src/obfs_http.c)
- [SIP002 URI scheme](https://shadowsocks.org/doc/sip002.html)
- [SIP003 plugin interface](https://shadowsocks.org/doc/sip003.html)
- [Existing licensing policy](0004-vless-client-without-gpl.md)
- [Existing embedded plugin architecture](0022-embedded-shadowsocks-v2ray-plugin.md)
