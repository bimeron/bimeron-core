# ShadowTLS v3 compatibility and implementation proposal

Status: Research complete; architecture awaiting user agreement. No ShadowTLS
combination is implemented or interoperability-verified by Bimeron yet.

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

These are protocol and code-path assessments, not passing test results.
"Deferred" means not enabled by the proposed first implementation.

| Current upstream | Assessment with ShadowTLS v3 | Proposed initial status | UDP through this combination |
| --- | --- | --- | --- |
| Shadowsocks AEAD: AES-128/256-GCM, ChaCha20-Poly1305 | Encrypted TCP payload is a natural fit | Implement and verify | No native UDP; use TCP-only VPN policy |
| Shadowsocks AEAD: AES-192-GCM | Same stream model, but the existing independent Xray fixture does not implement this cipher | Deferred unless a separate independent fixture is added | No native UDP |
| Shadowsocks 2022: all three currently supported methods | Encrypted TCP payload is a natural fit | Implement and verify | No native UDP; use TCP-only VPN policy |
| VLESS with TLS, WS/TLS, gRPC/TLS, XHTTP over HTTP/2 | Nested TLS is theoretically possible; requires a raw-socket injection path for every connection | Deferred | Inner UDP-over-stream could work, but requires separate tests |
| VLESS with REALITY or Vision | Do not assume compatibility: handshake and direct-copy paths need dedicated analysis | Deferred | No support claim |
| VMess AEAD over current TLS-based TCP/WS/HTTPUpgrade/gRPC/XHTTP transports | Encrypted TCP composition is possible in principle, but Bimeron currently requires TLS or REALITY | Deferred; do not silently add bare VMess | Inner UDP-over-stream could work, but requires separate tests |
| Trojan TCP/TLS | Nested TLS is theoretically possible; retain the inner TLS layer | Deferred | Trojan UDP-over-stream could work after separate verification |
| AnyTLS | Nested TLS and session reuse require all underlying connections to use the wrapper | Deferred | Its UDP-over-TCP v2 could work after separate verification |
| NaiveProxy-compatible HTTPS CONNECT | Nested TLS and HTTP/2 CONNECT are possible in principle | Deferred | Existing implementation is TCP-only |
| SSH | Encrypted TCP is possible in principle; preserve host-key verification and connection startup behavior | Deferred | Existing implementation is TCP-only |
| Remote SOCKS5 or plaintext HTTP CONNECT | No payload encryption; ShadowTLS does not supply the missing confidentiality | Reject | Native UDP cannot be wrapped |
| Hysteria2, TUIC, or XHTTP over HTTP/3 | QUIC/UDP is not a TCP byte stream | Reject direct composition | Unsupported |

Bare plaintext VLESS, VMess `none`/`zero`, generic TCP-over-UDP conversion, and
new UDP-over-TCP extensions are outside scope. The wrapped server selects its
inner data endpoint; the client does not request a separate backend address.

## Proposed architecture

Option A (recommended): implement a small `internal/shadowtls` package, using
the existing pinned uTLS dependency and standard-library HMAC/SHA primitives.
Expose a connection wrapper usable as an Outline `transport.StreamEndpoint`.
Add only the connection injection needed by the two Shadowsocks clients.
Leave protocol framing, routing, and unrelated transport owners in place.

Option B: inject a generic raw-stream dialer through every TCP upstream and
enable all encrypted candidates now. This increases constructor churn, nested
TLS/REALITY risk, pooling coverage, and the required independent server matrix.
It offers a wider initial feature set but substantially increases review scope.

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

Keep the inner profile type as Shadowsocks. Add optional wrapper settings to
the resolved profile; do not register ShadowTLS as a standalone proxy protocol.
Use the access profile's TCP host and port for the public ShadowTLS endpoint,
with existing Shadowsocks cipher and password fields describing its backend.
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
v3, with verified TLS 1.3 and a fixed supported ClientHello/ALPN policy for the
initial release. Do not add version negotiation, arbitrary TLS customization,
or SIP003 plugin subprocesses. Finalize the exact ClientHello and cover-request
ALPN policy during implementation review and test it against the reference.

Apply wrapper settings after resolving local, file, and dynamic access sources,
and revalidate after each dynamic refresh. Reject duplicate/empty sections,
unknown fields, invalid server names, missing passwords, and incompatible inner
profiles without echoing credentials. Supply the same validation for Go API
callers and the CLI. Treat the two passwords as separate secrets.

### Transport and UDP policy

- Configure the public upstream address as the ShadowTLS listener. Preserve SNI
  separately when bootstrap DNS replaces the host with an IP address.
- Retain the outbound dialer's interface binding and socket protection. Keep
  bootstrap/control-plane DNS on its existing physical-network path.
- Construct wrapped streams in VPN preparation, local proxy startup, CLI
  `check`, and the shared packet/embedded path.
- Never construct the native Shadowsocks packet listener for a wrapped profile.
  Do not resolve an unused UDP upstream endpoint or report one in status.
- Reuse the existing `UDP == nil` VPN behavior: captured DNS uses upstream TCP,
  other proxy-routed UDP is dropped. Explicit direct routes retain their stated
  routing policy. Do not introduce a UDP fallback or claim full UDP VPN support.
- Preserve deadlines, context cancellation, concurrent reader/writer behavior,
  bounded buffering, and close/half-close semantics through every wrapper.

## Independent verification plan

Run the unmodified official ShadowTLS `v0.2.25` executable in strict v3 mode,
with an independent Xray `v1.260327.0` Shadowsocks server behind it. Use a local
TLS 1.3 handshake target with an ephemeral test CA, and trust that CA only in
the test instance. Test harness trust injection must not disable verification.
Use Linux/WSL networking consistently for all processes to avoid localhost
forwarding differences. Neither reference executable is a compiled dependency
or a shipped product component.

Require passing tests for the three selected AEAD methods and three 2022
methods before enabling their combinations. AES-192-GCM needs a different
independent inner server, or must fail wrapped-profile validation explicitly.
Cover ordinary requests, binary payloads exceeding several records, bidirectional
traffic, reconnects, wrong ShadowTLS and inner passwords, bad certificates/SNI,
TLS 1.2-only targets, missing ShadowTLS authentication, timeouts, cancellation,
record tampering/truncation/reordering, and closure without resource leaks.

Verify a real request through Bimeron's SOCKS5 listener, not just the wrapper
in isolation. Exercise wrapped profile resolution and TCP-only packet handling
without privileged changes to the host network. Keep credentials ephemeral.
Self-generated client/server round trips supplement independent tests; they
cannot replace them.

The HIGH phase includes implementation, meaningful unit/integration tests,
independent interoperability results, and protocol/security review. The later
LOW phase adds routine CI wiring, final public guides/examples, benchmarks,
and broad release checks. Do not describe pending work as complete.

## Decisions required before implementation

1. Initial scope: six independently verifiable Shadowsocks AEAD/2022 methods,
   with other upstream combinations documented but rejected until tested.
2. Additive `[ShadowTLS]` settings and an optional resolved-profile wrapper,
   using the existing access endpoint as the public ShadowTLS address.
3. Strict v3 only, no new runtime dependency, and TCP-only VPN behavior for
   wrapped Shadowsocks, with DNS carried over TCP.
