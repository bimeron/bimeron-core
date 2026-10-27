# ADR 0010: Extend apernet QUIC with Hysteria2 handshake presets

Status: accepted, October 27, 2026. Firefox passed the real-wire and
unmodified-reference-server feasibility gates.

## Context

Hysteria2 URI fingerprints must alter the network handshake. The current
upstream client's `DisableChromeParrot` switch cannot produce Firefox.
uquic supplies Firefox 116 and Chrome 115/146 reference presets, but temporary
integration probes required fixes for current uTLS compatibility and connection
ID limits. Replacing the protocol transport would create additional relay and
congestion-control maintenance responsibilities.

The user rejected a second Hysteria2 backend and requested a plan for extending
the current apernet stack (architecture 2).

## Decision

Keep the upstream Hysteria2 protocol implementation. Maintain pinned local
snapshots of apernet/quic-go and Hysteria core, extending the former's existing
uTLS and Chrome-parroting machinery with named QUIC presets and adding minimal
configuration propagation to the latter. Adapt reference preset material from
uquic with its attribution; do not add uquic as another runtime transport.

Presets cover TLS ClientHello, QUIC transport parameters, and Initial packet
construction. Runtime protocol limits must match advertised values. Explicit
unsupported settings fail; there is no fingerprint fallback. Default profiles
retain the current behavior. Keep secure TLS verification and existing bound
UDP socket creation. Resumption and 0-RTT remain disabled for preset handshakes.

Firefox 116A/B/C pass captured Initial decoding and an unmodified reference
server test, including TCP and fragmented UDP relay. A required
TLS engine replacement, protocol rewrite, or security weakening triggers renewed
architecture discussion rather than an implicit scope change.

## Alternatives and tradeoffs

- A separate uquic backend offers a shorter prototype path but duplicates
  Hysteria2 transport responsibility. The user rejected this option.
- Replacing the entire backend with uquic leaves one backend but expands the
  migration risk to all Hysteria2 profiles and requires protocol integration
  and congestion-control validation. This remains an alternative if the port
  proves impractical, requiring another explicit decision.
- Extending apernet retains protocol behavior and existing uTLS integration,
  but requires maintaining a QUIC fork plus a small Hysteria configuration
  patch. Future upstream updates require patch review and wire regression tests.
- Local module snapshots make builds reproducible without a newly published
  fork repository, at the cost of repository size and explicit nested-module CI.
- Browser presets describe selected handshake behavior, not complete browser
  equivalence. Historical versions and disabled resumption are public limits.

## Acceptance and follow-up

The [implementation plan](../HYSTERIA2_QUIC_FINGERPRINT_PLAN.md) defines URI
semantics, feasibility gates, wire/integration checks, packaging, and desktop
changes. The implemented URI values are `firefox`, `firefox-116`, `firefox-116b`,
`firefox-116c`, and `chrome`. Firefox aliases are pinned to 116A. Chrome names
the existing apernet preset; inspection found differences from uquic 146
(including trust-anchor and transport parameter extensions), so it must not
be presented as a verified versioned 146 preset. The candidate Chrome 115/146
ports are not shipped and their names remain rejected. This narrows the
candidate inventory without changing the single-backend architecture.

Firefox requires per-connection CID limits, asymmetric receive windows,
20 ms advertised ACK delay with a 19 ms timer, DATAGRAM limits, RFC 9287
receive support, and 65527-byte receive capacity because its preset omits
`max_udp_payload_size`. Large receive buffers use a separate bounded-size
pool; ordinary send buffers and other connection defaults are unchanged.

Tests cover IPv4/IPv6 Initials, Retry, loss of the first Initial,
HelloRetryRequest, TLS rejection, and simultaneous mixed presets against an
independently built upstream server. Physical-interface routing and platform
runtime evidence must be reported separately from callback and build checks.
