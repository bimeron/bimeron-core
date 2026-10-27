# ADR 0011: Versioned Chrome QUIC presets

Status: accepted implementation approach, October 27, 2026; local protocol tests passed; browser-capture fidelity remains unverified.

## Decision

Extend ADR 0010's single apernet backend with `chrome-115` and `chrome-146`,
in that order, as authorized by the user. Preserve legacy `chrome` and omitted
`fp`. A common configurable fingerprint framework and a second QUIC backend
would increase scope without helping these two fixed presets.

Reuse uTLS, QUIC packet protection, congestion control and Hysteria relay.
Version-specific code controls ClientHello, transport parameters, Initial
packet-number widths, and CRYPTO/PING/padding composition. The actual remote
address selects the 1250-byte IPv4 or 1230-byte IPv6 Initial target.
Chrome 146 offers X25519MLKEM768 and X25519 and sends two Initial datagrams;
Chrome 115 offers X25519 and fits the fixture ClientHello into one.

## Reference audit and deliberate corrections

Reference: refraction-networking/uquic commit
837c7ce1b72bf07b2d29b3dabd5b45c60bec0f42, `u_parrot.go`; Chrome 146 was
introduced by 544b8096eacbcfa6ca04e1b9f51fac2f4083b09b. Retain LICENSE.uquic.

The 146 source describes a single reference capture but does not include that
capture in the pinned repository tree. Its comments identify RFC parameter
0x11 while its `LegacyID: true` emits 0xff73db. This implementation uses 0x11
for 146 and retains 0xff73db for 115. This is a documented interpretation of
the reference, not independent verification against the original capture.
The existing apernet preset's trust-anchor extension and ORIG option are not
carried into either named preset. 115 uses RVCM and google_quic_version;
146 uses 10AF and the reference's randomized 1000–20000 microsecond RTT hint.

uquic also leaves complete cross-packet CRYPTO scatter as future work. Retain
apernet's head/tail scatter and absolute offsets rather than copying that
limitation. Reserve space for the version-specific randomized frame layout;
preserve total datagram size when packet-number width changes. Reference
payload-size comments are not treated as complete UDP lengths. Count ranges
describe generated frames; adjacent padding runs may merge on the wire.

The multi-packet HRR test exposed an existing tail-offset accounting defect:
after a tail is emitted early, the next TLS message must start after that tail,
not after the drained middle. Fix this shared stream behavior and retain a
regression test. Zero-ID Chrome transports also need receive capacity above
the ordinary 1452-byte pool to honor their advertised 1472-byte UDP limit;
initialize the existing large receive pool before starting their read loop.

## Evidence and limits

Wire tests decrypt actual Initial packets and reassemble all CRYPTO bytes,
checking version-specific TLS fields, QUIC parameters, IDs, packet numbers,
frame counts and datagram sizes on IPv4 and IPv6. They are reference-derived
conformance checks, not independent browser captures. Their success must not
be described as proof of complete Chrome indistinguishability. Randomized
layout distributions and subsequent apernet/Hysteria traffic are additional
limits. Resumption and 0-RTT remain disabled; RSA/ECDSA certificates are needed.

Integration tests cover TLS rejection, Retry, HRR, loss and concurrent presets,
including TCP and fragmented UDP with an unmodified official Hysteria server.
Physical-interface routing still requires a dedicated runtime check; socket
callback tests and cross-builds do not prove it. Desktop contract changes are
listed in GUI_INTEGRATION.MD. See HYSTERIA2_CHROME_FINGERPRINT_PLAN.md for gates.
