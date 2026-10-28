# ADR 0023: Add an optional strict ShadowTLS v3 stream wrapper

Status: Accepted with expanded scope, October 28, 2026.

Tracks [issue #51](https://github.com/bimeron/bimeron-core/issues/51).

## Context

ShadowTLS v3 authenticates and disguises a TCP byte stream but does not encrypt
its payload or carry native UDP. Bimeron already has encrypted Shadowsocks
AEAD and 2022 clients, interface-aware socket dialing, and a TCP-only VPN path
that forwards DNS over TCP. Its upstream constructors currently take concrete
socket dialers. A broad transport refactor would increase the scope of the
first ShadowTLS implementation substantially.

The commonly used Go ShadowTLS implementation is GPLv3, incompatible with the
compiled dependency policy in ADR 0004. The existing uTLS module exposes the
ClientHello customization required by v3.

## Decision

Implement strict v3 in a focused internal package with existing uTLS and Go
cryptographic primitives. Make ShadowTLS optional metadata on an inner profile,
configured by an additive `[ShadowTLS]` section. Use the existing access TCP
endpoint for the public ShadowTLS listener and keep outer credentials separate.
Support encrypted TCP upstreams in the first implementation: Shadowsocks AEAD
and 2022, VLESS, VMess, Trojan, AnyTLS, NaiveProxy and SSH. Retain each inner
protocol's TLS/REALITY/encryption and host-key verification. Enable combinations
only when independent tests pass; reject plaintext and QUIC combinations.

Use a shared stream dialing helper at socket boundaries without changing the
existing interface-aware `net.Dialer` constructor contract. Propagate wrapper
settings to HTTP/gRPC connection pools and XHTTP secondary clients. Vision's
direct-copy connection must remain the ShadowTLS stream. Secondary XHTTP
addresses also require ShadowTLS with the same outer settings; reject HTTP/3
on either leg.

Preserve verified TLS 1.3 handshaking and ShadowTLS server authentication. Do
not offer version fallback, certificate bypass, or direct connection fallback.
Construct no native UDP transport for wrapped Shadowsocks. Reuse TCP-only VPN
handling and DNS-over-TCP without changing explicit direct routing rules.
Keep the existing UDP-over-stream adapters for VLESS, VMess, Trojan and AnyTLS.

## Alternatives and tradeoffs

- A Shadowsocks-only first release would reduce connection-pool and nested TLS
  coverage. The user selected broader support immediately, accepting a larger
  implementation and independent test matrix.
- Running an external client would simplify protocol code but complicate
  packaging, mobile embedding, protected sockets, and process cleanup.
- Importing the GPL Go implementation conflicts with the project's license
  policy. A local implementation instead requires ongoing wire-protocol care.
- Native Shadowsocks UDP outside the wrapper would be reachable separately and
  would not have ShadowTLS camouflage. Rejecting that implicit path limits UDP
  functionality but makes the configured behavior explicit and testable.

## Verification

Use the unchanged official ShadowTLS `v0.2.25` server, pinned to commit
`dee3a5a819d6f56cfdd56c44a0d42be186c44238`, with an independent inner server.
Require successful real proxy traffic and negative authentication/certificate/
record tests. Verify outbound socket controls and TCP-only packet policy.
See [the research and compatibility proposal](../SHADOWTLS_V3_RESEARCH.md).

The implementation passed the recorded official-server matrix, including
54 VMess and 26 VLESS cases, all six selected Shadowsocks methods, Trojan,
AnyTLS, NaiveProxy and SSH fixtures, plus negative record/authentication tests.
CI now runs the pinned official-server matrix with the race detector and
handshake/round-trip benchmarks. The public configuration guide and examples
are in [ShadowTLS v3](../SHADOWTLS.MD). The CI selection was validated locally
under Linux/WSL; a hosted Actions run requires a later push.
