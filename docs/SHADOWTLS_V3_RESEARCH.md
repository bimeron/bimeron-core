# ShadowTLS v3 compatibility and implementation proposal

Status: Expanded HIGH-phase implementation and independent interoperability
checks completed. CI wiring, benchmarks and final public guides remain for the
separate LOW phase. This document records source-level support and test evidence.

Tracking: [issue #51](https://github.com/bimeron/bimeron-core/issues/51), branch
`feat/shadowtls-v3`.

## Reference baseline

- Official implementation: `ihciah/shadow-tls`, release `v0.2.25`, commit
  `dee3a5a819d6f56cfdd56c44a0d42be186c44238`.
- [Protocol description](https://github.com/ihciah/shadow-tls/blob/dee3a5a819d6f56cfdd56c44a0d42be186c44238/docs/protocol-v3-en.md).
- [Client implementation](https://github.com/ihciah/shadow-tls/blob/dee3a5a819d6f56cfdd56c44a0d42be186c44238/src/client.rs)
  and [record implementation](https://github.com/ihciah/shadow-tls/blob/dee3a5a819d6f56cfdd56c44a0d42be186c44238/src/util.rs).
- Official Linux x86-64 release binary SHA-256:
  `a173f5f2d57f45211b68e10ceeddc15b1791077b914fa89747bc705fddc71532`.
  This is a locally measured content pin, not an upstream signed attestation.
- The official release binary starts under the available Ubuntu WSL2 instance
  and reports `shadow-tls 0.2.25`. This establishes test-tool availability only.
- A local tool check also started the unchanged strict-v3 server with Xray
  `26.3.27` and an OpenSSL TLS 1.3 target. A standard, unauthenticated TLS client
  reached the target through ShadowTLS and verified its localhost certificate.
  Authenticated Bimeron interoperability remains untested.
- The current upstream master revision inspected initially was
  `02dd0bc7bae8a2011729f95021690e694fd8e43e`. Use the release commit above for
  reproducible protocol comparisons and tests.

## Protocol facts relevant to integration

ShadowTLS v3 is an authenticated TCP stream wrapper. It does not encrypt the
forwarded application payload or provide forward secrecy for that payload.
An encrypted inner protocol remains necessary. The real TLS handshake does
not turn subsequent ShadowTLS application records into ordinary encrypted TLS.

Strict v3 requires a TLS 1.3 handshake target and verified target certificate
and hostname. Do not support v1, v2, permissive v3, certificate bypass, or an
automatic connection without ShadowTLS after a failure.

The signed ClientHello contains a 32-byte session ID: 28 random bytes and a
four-byte HMAC prefix. The protocol uses HMAC-SHA1, including its cumulative
state, not HMAC-SHA256. The signature covers the handshake message with the
four signature bytes zeroed, excluding the five-byte TLS record header.
The English description occasionally says bits where the source uses bytes.

During the handshake, the wrapper extracts ServerRandom, verifies the server's
modified application records, and reverses their XOR transformation using
SHA-256(password || ServerRandom). After the TLS handshake, the application
uses separate directional HMAC chains initialized with ServerRandom and `C`
or `S`; each payload and its four-byte tag advance the chain. The reader must
filter authenticated residual handshake records until the first data record.
These details require a record adapter around the TLS connection and a
controlled transition to raw records. `streamtransport.TLS` alone cannot do it.

The official strict client also performs a bounded, ordinary TLS cover request
when a valid TLS connection does not authenticate as ShadowTLS. That path must
never transmit an inner-protocol header, password, or destination. Preserve
protocol-appropriate failure behavior; do not claim resistance to detection
solely because functional interoperability passes.

## Compatibility matrix

The user selected broader encrypted-TCP support instead of a Shadowsocks-only
first implementation. The enabled rows below passed the independent checks
listed under "Observed verification"; rejected rows fail profile validation.

| Current upstream | Assessment with ShadowTLS v3 | Proposed initial status | UDP through this combination |
| --- | --- | --- | --- |
| Shadowsocks AEAD: AES-128/256-GCM, ChaCha20-Poly1305 | Encrypted TCP payload is a natural fit | Verified with official ShadowTLS and Xray | No native UDP; use TCP-only VPN policy |
| Shadowsocks AEAD: AES-192-GCM | Same stream model, but the existing independent Xray fixture does not implement this cipher | Deferred unless a separate independent fixture is added | No native UDP |
| Shadowsocks 2022: all three currently supported methods | Encrypted TCP payload is a natural fit | Verified with official ShadowTLS and Xray | No native UDP; use TCP-only VPN policy |
| VLESS with TLS, WS/TLS, gRPC/TLS, XHTTP over HTTP/2 | Wrap every underlying TCP connection, preserving inner TLS | Verified with official ShadowTLS and Xray | Preserve inner UDP-over-stream |
| VLESS with REALITY or Vision | REALITY stays inside the wrapper; Vision's raw connection refers to the wrapped stream | Verified, including TLS 1.3 application traffic through Vision | Preserve inner UDP-over-stream |
| VMess AEAD over current TLS-based TCP/WS/HTTPUpgrade/gRPC/XHTTP transports | Preserve current TLS/REALITY and AEAD requirements; propagate settings to the shared HTTP transport | Verified with both AEAD ciphers; bare VMess remains unsupported | Preserve inner UDP-over-stream |
| Trojan TCP/TLS | Retain the inner TLS layer | Verified with official ShadowTLS and Xray | Preserve Trojan UDP-over-stream |
| AnyTLS | Wrap new sessions and preserve session reuse/padding | Verified with official ShadowTLS and the reference AnyTLS server | Preserve UDP-over-TCP v2 |
| NaiveProxy-compatible HTTPS CONNECT | Retain inner TLS, HTTP/2 CONNECT, pooling and padding | Verified with official ShadowTLS and Caddy/forwardproxy | Existing implementation is TCP-only |
| SSH | Retain encryption, host-key verification and connection startup behavior | Verified with official ShadowTLS and an SSH protocol fixture | Existing implementation is TCP-only |
| Remote SOCKS5 or plaintext HTTP CONNECT | No payload encryption; ShadowTLS does not supply the missing confidentiality | Reject | Native UDP cannot be wrapped |
| Hysteria2, TUIC, or XHTTP over HTTP/3 | QUIC/UDP is not a TCP byte stream | Reject direct composition | Unsupported |

Bare plaintext VLESS, VMess `none`/`zero`, generic TCP-over-UDP conversion, and
new UDP-over-TCP extensions are outside scope. The wrapped server selects its
inner data endpoint; the client does not request a separate backend address.

## Proposed architecture

Option A (not selected): implement a small `internal/shadowtls` package, using
the existing pinned uTLS dependency and standard-library HMAC/SHA primitives.
Expose a connection wrapper usable as an Outline `transport.StreamEndpoint`.
Add only the connection injection needed by the two Shadowsocks clients.
Leave protocol framing, routing, and unrelated transport owners in place.

Option B (selected): integrate the wrapper at every encrypted TCP upstream's
socket boundary and enable the broader candidates now. Keep the existing
`net.Dialer` constructors; a shared `streamtransport` dialing helper can dial
through the supplied interface/protected socket path and perform ShadowTLS
before handing the stream to the inner protocol. This avoids introducing a
new dialer hierarchy while covering ordinary, pooled, and HTTP transport paths.
Implement the wire protocol in `internal/shadowtls` using existing uTLS and Go
cryptographic primitives. The wider matrix needs dedicated nested TLS,
REALITY/Vision, pooling, and UDP-over-stream tests.

Option C: invoke an external ShadowTLS client process. This reduces Go protocol
work but complicates packaging, process ownership, mobile embedding, socket
protection, and routing. It is a poor match for an embedded networking core.

The popular Go package `github.com/sagernet/sing-shadowtls` is GPLv3 according
to its [license](https://github.com/SagerNet/sing-shadowtls/blob/main/LICENSE).
It cannot enter Bimeron's compiled dependency graph under ADR 0004. The
official Rust reference has an MIT LICENSE file and describes dual licensing
in Cargo metadata. Preserve attribution for any adapted material. Do not copy
GPL implementation code into a local package.

### Proposed profile model and configuration

Keep the inner profile type unchanged. Add optional wrapper settings to
the resolved profile; do not register ShadowTLS as a standalone proxy protocol.
Use the access profile's TCP host and port for the public ShadowTLS endpoint,
with existing inner-protocol credentials and security settings describing its backend.
No second client-visible backend endpoint is required.

Proposed additive section, paired with the existing `[AccessKey]` source:

```ini
[AccessKey]
SS = ss://aes-256-gcm:replace-inner-password@proxy.example.com:443

[ShadowTLS]
ServerName = handshake.example.com
Password = replace-shadowtls-password
```

Presence of the section opts in. Its only supported wire behavior is strict
v3, with verified TLS 1.3, the existing pinned uTLS Chrome ClientHello, and
outer HTTP/1.1 ALPN for the cover-request path. Session resumption is disabled.
The inner ALPN and server name remain independent. There is no version
negotiation, arbitrary outer TLS customization or SIP003 plugin subprocess.
This is not a claim of byte-identical browser traffic or censorship resistance.

Apply wrapper settings after resolving local, file, and dynamic access sources,
and revalidate after each dynamic refresh. Reject duplicate/empty sections,
unknown fields, invalid server names, missing passwords, and incompatible inner
profiles without echoing credentials. Supply the same validation for Go API
callers and the CLI. Treat outer credentials separately from inner credentials.
Preserve independent inner and outer server names: `[ShadowTLS] ServerName`
is the handshake target, not the backend TLS/REALITY hostname.

For XHTTP `downloadSettings`, every upload and download address must be a
ShadowTLS listener using the same outer settings. Propagate the wrapper to the
derived client and reject HTTP/3 on either leg. Never route a secondary
connection directly because its address differs from the main endpoint.

### Transport and UDP policy

- Configure the public upstream address as the ShadowTLS listener. Preserve SNI
  separately when bootstrap DNS replaces the host with an IP address.
- Retain the outbound dialer's interface binding and socket protection. Keep
  bootstrap/control-plane DNS on its existing physical-network path.
- Construct wrapped streams in VPN preparation, local proxy startup, CLI
  `check`, and the shared packet/embedded path.
- Never construct the native Shadowsocks packet listener for a wrapped profile.
  Do not resolve an unused UDP upstream endpoint or report one in status.
- Preserve UDP carried inside VLESS, VMess, Trojan and AnyTLS streams. Those
  packet adapters must use the same wrapped TCP connections as ordinary traffic.
- Reuse the existing `UDP == nil` VPN behavior: captured DNS uses upstream TCP,
  other proxy-routed UDP is dropped. Explicit direct routes retain their stated
  routing policy. Do not introduce a UDP fallback or claim full UDP VPN support.
- Preserve deadlines, context cancellation, concurrent reader/writer behavior,
  bounded buffering, and close/half-close semantics through every wrapper.

## Independent verification plan

Run the unmodified official ShadowTLS `v0.2.25` executable in strict v3 mode,
with independent inner servers behind it: Xray `v1.260327.0` for Shadowsocks,
VLESS, VMess and Trojan; the existing pinned AnyTLS and NaiveProxy reference
servers; and an SSH reference fixture. The local TLS 1.3 handshake target uses
httptest's public test certificate. Trust it only through test-specific pools
or a temporary SSL_CERT_FILE before the test process's first system-pool lookup.
Hostname and certificate verification remain enabled in the client.
Use Linux/WSL networking consistently for all processes to avoid localhost
forwarding differences. Neither reference executable is a compiled dependency
or a shipped product component.

Require passing tests for the three selected AEAD methods and three 2022
methods before enabling their combinations. AES-192-GCM needs a different
independent inner server, or must fail wrapped-profile validation explicitly.
Verify each enabled VLESS/VMess transport, both available VMess ciphers,
REALITY, Vision direct-copy, XHTTP modes/secondary connections, AnyTLS session
reuse, NaiveProxy HTTP/2 pooling, SSH host-key rejection, and packet round trips
for every retained UDP-over-stream adapter.
Cover ordinary requests, binary payloads exceeding several records, bidirectional
traffic, reconnects, wrong ShadowTLS and inner passwords, bad certificates/SNI,
TLS 1.2-only targets, missing ShadowTLS authentication, timeouts, cancellation,
record tampering/truncation/reordering, and closure without resource leaks.

Verify a real request through Bimeron's SOCKS5 listener, not just the wrapper
in isolation. Exercise wrapped profile resolution and TCP-only packet handling
without privileged changes to the host network. Keep credentials ephemeral.
Self-generated client/server round trips supplement independent tests; they
cannot replace them.

## Observed verification

All independent checks ran on Ubuntu WSL2 with the unchanged official ShadowTLS
`v0.2.25` executable. Reference processes and credentials are test-only and are
not shipped or added to the runtime dependency graph.

- `internal/shadowtls/TestReferenceServer`: large bidirectional streams,
  reconnects, setup-context cancellation after connection, wrong password,
  wrong hostname and untrusted certificate.
- `internal/proxy/TestShadowTLSShadowsocks`: all six enabled methods through a
  real local SOCKS5 listener, binary HTTP responses larger than several records,
  and rejection of a wrong inner password. Wrapped 2022 clients reject native UDP.
- `internal/vmess/TestXrayVMessAEAD`: 54 wrapped cases covering both AEAD
  ciphers, TCP, WebSocket, HTTPUpgrade, both gRPC modes, permitted TLS/REALITY
  combinations and XHTTP modes. Each case checks TCP, UDP-over-stream, reconnect
  and client closure. Six cases exercise separate wrapped XHTTP upload/download
  addresses, also using the xmux path and TCP keepalive configuration.
- `internal/vmess/TestXrayVLESS`: 26 corresponding wrapped VLESS cases, including
  three split-XHTTP cases and REALITY/Vision. Vision also carries a large HTTPS
  response over a real TLS 1.3 application connection to exercise direct copy.
- Existing Trojan and AnyTLS reference tests pass through the wrapper, including
  their UDP-over-stream adapters. AnyTLS's pinned fixture retains its existing
  localhost certificate-name adjustment; it is not part of the client runtime.
- The pinned Caddy/klzgrad-forwardproxy reference test passes HTTP/2 CONNECT,
  large padded transfers, and a second stream through local SOCKS5.
- SSH forwarding and incorrect host-key rejection pass through official
  ShadowTLS. The inner SSH fixture uses `golang.org/x/crypto/ssh`; no independent
  OpenSSH interoperability claim is made.
- `core/TestShadowTLSProxyEngine` verifies in-memory configuration loading,
  Engine startup, a real local SOCKS5 request and public endpoint status.
- `internal/streamtransport/TestShadowTLSPreservesSocketControl` verifies the
  supplied socket Control callback and that a wrong outer password never opens
  a backend data connection.
- Unit checks reject tampering, replay, reordering, truncation, partial headers,
  oversized records, wrong record versions/types and late handshake residuals.
  They verify short writes, timeout recovery within a partial record, handshake
  cancellation, TLS 1.2 rejection and an ordinary verified TLS cover request.
- Config/core checks cover duplicate/unsupported options, invalid combinations,
  dynamic source refresh, immutable wrapper snapshots, unused UDP endpoint
  suppression and preservation of UDP-over-stream endpoint metadata. Existing
  netstack DNS tests verify the reused DNS-over-TCP behavior when UDP is absent.
- `go test ./...`, `go vet ./...` and targeted Windows `go test -race` checks
  pass. The compiled dependency notice check passes; `go.mod` and `go.sum` are
  unchanged and no GPL/LGPL module was added.

These checks do not cover every inner fingerprint or XHTTP extra-option
cross-product, mobile devices, a live privileged system VPN, or resistance to
real censorship systems. HTTP/3, native UDP through ShadowTLS, plaintext inner
protocols and AES-192-GCM remain explicitly unsupported in wrapped profiles.

To reproduce on Linux, set `BIMERON_SHADOWTLS_BIN` to the official executable
and the inner reference variable needed by the selected test:

```sh
BIMERON_SHADOWTLS_BIN=/path/to/shadow-tls \
  BIMERON_XRAY_BIN=/path/to/xray \
  go test ./internal/vmess -run '^TestXray' -count=1 -v
```

The other existing fixture variables are `BIMERON_ANYTLS_BIN` and
`BIMERON_NAIVE_CADDY_BIN`. Without the ShadowTLS variable, the existing inner
reference tests retain their direct connection mode. Without reference binaries,
ordinary unit tests run and independent tests skip with an explicit reason.

The HIGH phase includes implementation, meaningful unit/integration tests,
independent interoperability results, and protocol/security review. The later
LOW phase adds routine CI wiring, final public guides/examples, benchmarks,
and broad release checks. Do not describe pending work as complete.

## Selected scope

1. Broader encrypted TCP support: six independently verifiable Shadowsocks
   AEAD/2022 methods, VLESS, VMess, Trojan, AnyTLS, NaiveProxy and SSH, including
   their current TCP-based transports. Do not add protocols missing from the
   branch's baseline or claim passing support before tests succeed.
2. Additive `[ShadowTLS]` settings and an optional resolved-profile wrapper,
   using the existing access endpoint as the public ShadowTLS address.
3. Strict v3 only and no new runtime dependency. Use TCP-only VPN behavior for
   wrapped Shadowsocks, NaiveProxy and SSH, with DNS carried over TCP; preserve
   existing UDP-over-stream functionality for the other encrypted upstreams.
