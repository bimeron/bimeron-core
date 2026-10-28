# ADR 0024: MASQUE CONNECT-UDP over HTTP/3

Status: accepted, October 28, 2026. Tracks issue #60.

## Context

The HTTP upstream introduced by ADR 0021 provides HTTP/1.1 CONNECT for TCP
only. MASQUE adds UDP forwarding, including DNS and QUIC applications, but
requires a specific HTTP version, datagram transport, and interoperability
target. Existing VPN transports expose `transport.StreamDialer` and
`transport.PacketListener`. The local SOCKS5 server initially accepted TCP
CONNECT only, so UDP in proxy mode also needs UDP ASSOCIATE.

## Decision

Add an explicit `Type = masque` profile and `masque://` access keys. Accept
them through `MASQUE`, `Key`, `File`, or explicit parameters. Existing HTTP
profiles retain their HTTP/1.1 TCP-only behavior.

The compatibility profile is RFC 9298 CONNECT-UDP over HTTP/3, RFC 9297 HTTP
Datagrams and Capsule Protocol, and RFC 9221 QUIC DATAGRAM. Require verified
TLS 1.3 with ALPN `h3`, Extended CONNECT, HTTP Datagrams, and peer QUIC
DATAGRAM support. Check these capabilities before opening either kind of
tunnel; a TCP-only HTTP/3 proxy must not masquerade as a working UDP profile.
Optional Basic proxy authentication is sent only inside TLS.

For UDP, send Extended CONNECT with `:protocol = connect-udp` and
`Capsule-Protocol: ?1`; require a true Capsule Protocol response. The default
URI template is
`https://{proxy-authority}/.well-known/masque/udp/{target_host}/{target_port}/`.
`MASQUEPath` (URI option `udp_path`) may change the path using simple RFC 6570
expansion of exactly those two target variables. Authority, query templates,
additional variables, and reserved expansion are not configurable through the
path template. Target expansion must not change the proxy authority.

Use one request stream per UDP destination and Context ID zero. Forward packet
payloads through HTTP Datagrams, preserving empty datagrams. Ignore unknown
context IDs and skip unknown capsules without allocating their advertised
length. Do not implement UDP payload delivery through DATAGRAM capsules,
fragmentation, old draft variants, CONNECT-IP, or HTTP/2 fallback.

Carry TCP over ordinary HTTP/3 CONNECT on the same QUIC connection, with
independent streams, cancellation, deadlines, and TCP half-close behavior.
A compatible deployment must provide ordinary CONNECT as well as CONNECT-UDP.

Keep the original proxy host for HTTP authority and the configured TLS name
for certificate verification when bootstrap resolves the physical dial IP.
Use the outbound dialer's socket control for the QUIC UDP socket. Publish
the same endpoint for both logical transports so existing physical route and
session handling retains the proxy's UDP endpoint. Network changes create a
new transport generation through the existing session reconnection path.
Within a client, subsequent tunnels can establish a new QUIC connection after
connection loss; existing TCP streams and lost UDP datagrams are not replayed.

A failed request-stream open retires that connection from the current cache
and permits one retry on a replacement before CONNECT headers are sent. This
handles GOAWAY without replaying a CONNECT request. Draining generations keep
their existing TCP and UDP streams; their sockets and QUIC transports are
released when the connection ends or the client closes. The pinned quic-go
version does not export its GOAWAY error, so the bounded retry applies to
non-context errors from stream creation rather than matching an error string.

A normal TCP close sends FIN, interrupts application reads using a deadline,
and drains the response in the background for at most five seconds. It then
waits for QUIC send completion within that same absolute deadline. The tunnel
slot is retained until completion or timeout; client shutdown interrupts both
waits. Application reads and deadline changes after close cannot interfere.
Setup cancellation, UDP teardown, and closing during a blocked TCP write abort
immediately. A timeout can discard pending data, as can peer errors or explicit
client shutdown; Close is not an application-level delivery acknowledgement.

The upstream v0.64.1 HTTP/3 tracker treats local Close as send completion, so
GOAWAY can close QUIC before queued payload and FIN are sent. A local source
snapshot in `third_party/quic-go` adds a separate send-completion context that
finishes after QUIC ACKs (or reset/connection termination), preserving the public
Context semantics. Normal HTTP/3 close uses this completion signal. ACK alone
still does not mean a peer application consumed buffered data: an unmodified
peer can discard it when CONNECTION_CLOSE arrives. MASQUE therefore opts into
an additional five-second GOAWAY connection-close grace after the last tracked
stream completes. Other HTTP/3 consumers retain the default zero grace. The
old connection still rejects new streams immediately; Client.Close interrupts
the grace and releases its socket. This handles EOF and CloseRead before the
final write as well as both Close and CloseWrite. No protocol replay, private
field access, or dependency-cache mutation is used. See the snapshot's
`PATCHES.md` for the upstream baseline, changed files, and removal criteria.

UDP tunnel read failures carry their destination in a
`net.OpError` and are temporary: a subsequent write can reopen that destination.
The SOCKS relay consumes temporary packet errors while retaining the association
and its healthy destinations; cancellation and terminal socket errors still
close the association.

System certificate roots remain enabled. `CAFile` (URI option `ca`) adds a
local CA, allowing a private proxy without disabling certificate verification.
URI CA paths must be absolute. Explicit file configurations resolve relative
CA paths against the configuration directory; in-memory configurations require
an absolute path.

Enable local SOCKS5 UDP ASSOCIATE only when its server is explicitly supplied
with a packet transport. Initially only the MASQUE backend opts in. Each
association belongs to its TCP control connection, accepts only that peer's
loopback IP, pins the client's UDP source port, rejects SOCKS fragments, and
applies the existing proxy/direct/block policy per destination. Other upstream
profiles retain their current local-listener behavior.

## Implementation and limits

Use `github.com/quic-go/quic-go v0.64.1` from the local snapshot described above.
Use `yosida95/uritemplate` for RFC 6570 expansion and `dunglas/httpsfv` for
structured Capsule Protocol headers. Keep the patch limited to send completion and opt-in GOAWAY close grace.

Use low-level HTTP/3 request streams rather than the pinned `masque-go` client:
that client's response-header wait does not independently cancel a request,
and its write deadline is unimplemented. Per-request cancellation must not
close neighboring tunnels. Also, quic-go's `SendDatagram` can block on its
connection-wide queue. One client-owned sender and a bounded 32-entry queue
allow callers to stop waiting on deadline or cancellation without creating an
unbounded number of blocked send goroutines. Once handed to QUIC, a datagram
cannot be withdrawn if its deadline races with queueing; delivery remains
unreliable and the adapter never retransmits it.

Initial limits are 256 simultaneous tunnels per client, 128 packet listeners,
32 UDP destinations per packet listener, and 64 queued received packets per
packet listener. Idle UDP tunnels expire after 60 seconds, checked every
30 seconds. Setup takes at most 15 seconds. Slow readers drop datagrams rather
than blocking other streams. Response headers are limited to 16 KiB.

The application payload ceiling is 1500 bytes, matching the reference proxy;
the effective ceiling is lower when QUIC's current datagram limit requires it.
Writes that exceed that limit return an error with zero bytes accepted. A read
buffer smaller than a received packet returns `io.ErrShortBuffer` and discards
that packet. Larger UDP payloads are not fragmented or silently carried over
a reliable stream. Nested HTTP/3 interoperability is tested with 1200-byte
inner QUIC packets. Applications using larger QUIC packets must respect the
effective tunnel MTU; this profile does not promise arbitrary UDP sizes.

## Reference server and validation

Build `internal/masque/testdata/reference-server` as a separate module with
`GOWORK=off` and `-mod=readonly`. Pin upstream `quic-go/masque-go` to commit
`a08a5a221b16281f5c9d73d542f264478bf85a56`
(`v0.6.1-0.20261027113634-a08a5a221b16`), using its `quic-go v0.63.0` dependency.
The production client uses v0.64.1, exercising the wire protocol across the
two versions. The fixture uses an ephemeral CA and certificate, fixed synthetic
credentials, loopback-only targets, and no public proxy or external service.
The MASQUE proxy implementation remains unmodified. A fixture-owned ordinary
CONNECT handler supplies TCP forwarding; masque-go itself supplies UDP only.

Tests cover TCP half-close and dial-context lifetime, IPv4/IPv6 and empty UDP
packets, multiple destinations, DNS messages, nested HTTP/3, custom templates,
unknown contexts and capsules, TLS/authentication/status/capability failures,
deadlines, cancellation, expiry, reconnection, GOAWAY replacement with active
tunnels, completed TCP writes followed by close (including the last stream after
GOAWAY), read/write interruption, bounded drain/ACK cleanup, EOF and CloseRead before the final GOAWAY write,
destination failure isolation,
limits, source pinning, routing
policy, and active shutdown. A local packet bridge drops every eleventh packet
in each direction to exercise nested QUIC recovery. A URI fuzz target and UDP
echo benchmarks cover parsing and 64/512/1200-byte round trips.

Core tests exercise the SOCKS backend and the real VPN flow handler against
the reference transport without administrator privileges. An opt-in Linux
namespace test additionally sends TCP IPv4/IPv6 and UDP through a real TUN,
policy routes, and an interface-bound MASQUE socket. It maps synthetic routed
destinations to the fixture's allowlisted loopback services. The namespace
suite also verifies immediate TUN reuse, route/DNS recovery, and nftables cleanup;
it does not change the host network namespace or resolver.

Local Windows and Linux/WSL2 full tests, vet, transport race checks, dependency
QUIC/HTTP3 race checks, and Linux namespace integration have passed. CI builds
the pinned fixture for Linux and Windows and runs the same lifecycle tests,
plus Linux fuzzing and benchmarks. Helpers accept
`BIMERON_MASQUE_REFERENCE_BIN` to reuse a separately built fixture. Hosted
GitHub Actions requires a later push; physical Wi-Fi/Ethernet handover and
privileged macOS/Windows adapter validation remain platform acceptance checks.
No push or PR is part of this local implementation task.

## Alternatives and consequences

- HTTP/2 with DATAGRAM capsules would work when outbound UDP is blocked, but
  would impose TCP head-of-line blocking. It is a separate compatibility profile
  rather than an automatic fallback.
- Reusing the upstream MASQUE client would reduce request code, but its current
  cancellation and deadline behavior does not meet the transport contract.
- Supporting UDP only would simplify the implementation, but would not provide
  a complete upstream for existing proxy and VPN sessions.
- The reference proxy shares the quic-go ecosystem with the client. Its separate
  module and version improve test independence, but these tests do not establish
  compatibility with every vendor's HTTPS proxy or authentication scheme.
