# MASQUE HTTP/3 upstream

Bimeron carries TCP through ordinary HTTP/3 CONNECT and UDP through RFC 9298
CONNECT-UDP on the same QUIC connection. UDP uses RFC 9297 HTTP Datagrams and
RFC 9221 QUIC DATAGRAM with Context ID zero. This is an explicit compatibility
profile, selected by `Type = masque` or a `masque://` access key.

## Server requirements

The proxy must provide all of the following:

- HTTP/3 over QUIC with ALPN `h3`, TLS 1.3 and a valid server certificate.
- Ordinary CONNECT for TCP destinations.
- Extended CONNECT with `:protocol = connect-udp`, HTTP Datagrams, QUIC
  DATAGRAM, and Capsule Protocol acknowledgement for UDP destinations.
- The configured UDP URI template, by default
  `https://proxy.example.com:443/.well-known/masque/udp/{target_host}/{target_port}/`.
- Optional Basic proxy authentication with the configured username/password.

The proxy's UDP port must be reachable from the client's physical network.
An HTTP/1.1 or HTTP/2-only HTTPS proxy does not meet this profile. There is no
fallback when UDP is blocked. A server implementing CONNECT-UDP alone also
needs an ordinary CONNECT handler for complete Bimeron sessions.

Bimeron verifies both the certificate chain and the TLS server name. System
roots are used by default. A private CA can be added through `CAFile`; this
supplements system roots and does not disable verification. The original
proxy host remains the HTTP authority when its physical endpoint is resolved
to an IP or a different TLS `ServerName` is configured.

## Configure and run

Copy [examples/masque.conf](../examples/masque.conf) and replace the proxy
address, port and optional credentials. The checked-in values are placeholders.
The default example runs a loopback SOCKS5 proxy:

```sh
go run ./cmd/bimeron validate examples/masque.conf
go run ./cmd/bimeron run examples/masque.conf
```

Validation parses the profile without connecting to the proxy. The run command
requires a compatible server at the configured address. TCP applications can
use the local SOCKS5 listener at `127.0.0.1:1080`. UDP applications must support
SOCKS5 UDP ASSOCIATE and keep its TCP control connection open. SOCKS fragments
are rejected. Proxy/direct/block routing rules apply to UDP destinations too.

For system VPN operation, change `[Interface] Mode` to `vpn` and configure DNS
for your deployment. Run with the platform privileges required for a system
VPN. UDP and DNS then use the tunnel; direct routing rules retain their usual
meaning. See [configuration](CONF.MD#masque-http3-proxy) for every MASQUE field,
URI option and CA-path rule.

## Packet sizes and failure behavior

The UDP application payload ceiling is 1500 bytes, and QUIC's current datagram
MTU can impose a smaller limit. Oversized writes return an error; the client
does not fragment packets or switch them to a reliable stream. A VPN interface
MTU setting does not increase the outer QUIC datagram capacity. Nested HTTP/3
interoperability tests use 1200-byte inner QUIC packets; this does not guarantee
that an application using larger packets will fit the tunnel.

UDP datagrams can be lost, reordered, or dropped when receive queues are full.
The adapter does not retransmit them. A datagram already passed to QUIC cannot
be withdrawn if its send races with a write deadline. Read buffers smaller than
a received packet return `io.ErrShortBuffer` and discard that packet.

Each client permits 256 simultaneous tunnels and 128 packet listeners. A packet
listener permits 32 UDP destinations and queues 64 received packets. UDP
sessions idle for 60 seconds expire on a 30-second sweep. Setup is bounded to
15 seconds. Other tunnels retain their own deadlines and lifecycle.

TCP close sends FIN and returns promptly, then drains the response and waits
for QUIC send completion within one five-second deadline while retaining its
tunnel slot. Peer errors or client shutdown end the wait sooner. Reads and
deadline changes after close return `net.ErrClosed`. Setup cancellation, UDP
teardown, and closing during an in-progress TCP write reset the stream.

The client uses a local quic-go v0.64.1 snapshot with a send-completion fix.
After GOAWAY, it also allows five seconds after the last tracked stream finishes
before closing the old connection. This lets peers consume buffered data even
when their response reached EOF before the client's final write. New tunnels
use a replacement connection immediately. Explicit client shutdown interrupts
the grace period. A grace timeout, peer error, or client shutdown can discard
pending data; successful Write/Close does not acknowledge application delivery.
See [the patch notes](../third_party/quic-go/PATCHES.md).

Missing protocol capabilities, failed TLS validation and rejected CONNECT
requests return errors. After connection loss, subsequent tunnels can create
a new QUIC connection; existing TCP streams and lost UDP packets are not
replayed. A graceful server GOAWAY moves new tunnels to a replacement connection while
existing tunnels finish on their original connection. A failed UDP destination
can be reopened without replacing its SOCKS5 UDP association or interrupting
healthy destinations. The core's existing reconnection path recreates the
transport after network changes.

## Reproduce interoperability tests

The reference server is `quic-go/masque-go` pinned to commit
`a08a5a221b16281f5c9d73d542f264478bf85a56`
(`v0.6.1-0.20261027113634-a08a5a221b16`). It runs in a separate Go module with
upstream `quic-go v0.63.0`; the production client uses `quic-go v0.64.1`.
The fixture supplies an ordinary TCP CONNECT handler alongside the unmodified
MASQUE UDP proxy. It uses temporary certificates, synthetic credentials and
loopback targets, without public proxies or system route changes.

From the repository root, these commands build and start the fixture
automatically. The Go toolchain and module dependencies must be available:

```sh
go test ./internal/masque -run '^TestReferenceServer$' -count=1 -v
go test ./core -run 'Test(MASQUE|ResolveMASQUE)' -count=1 -v
go test -race ./internal/masque ./internal/proxy ./core
go test ./internal/accesskey -run '^$' -fuzz '^FuzzMASQUEURI$' -fuzztime=5s
go test ./internal/masque -run '^$' -bench '^BenchmarkUDPEcho$' -benchtime=200ms -count=1
```

The race detector requires CGO and a compatible C compiler. Benchmarks report
64/512/1200-byte UDP echo round trips and allocations. They have no
hardware-dependent pass/fail threshold and are not network throughput promises.
The nested HTTP/3 tests also run through a local bridge that drops every
eleventh packet in each direction.

To reuse a single compiled fixture on Linux or macOS:

```sh
GOWORK=off go -C internal/masque/testdata/reference-server build -mod=readonly -o /tmp/bimeron-masque-reference .
BIMERON_MASQUE_REFERENCE_BIN=/tmp/bimeron-masque-reference go test ./internal/masque ./core -run 'Test(ReferenceServer|MASQUE|ResolveMASQUE)' -count=1
```

On Windows PowerShell:

```powershell
$env:GOWORK = 'off'
$masqueBinary = Join-Path $env:TEMP 'bimeron-masque-reference.exe'
go -C internal/masque/testdata/reference-server build -mod=readonly -o $masqueBinary .
$env:BIMERON_MASQUE_REFERENCE_BIN = $masqueBinary
go test ./internal/masque ./core -run 'Test(ReferenceServer|MASQUE|ResolveMASQUE)' -count=1
Remove-Item Env:BIMERON_MASQUE_REFERENCE_BIN
Remove-Item Env:GOWORK
```

The tests own the server process and stop it during cleanup. CI builds this
pinned fixture once per Linux/Windows job; see [automated checks](CI.MD).
Local VPN tests exercise real TCP/UDP flow handlers without installing TUN
routes. They do not replace privileged platform testing of a real TUN session,
route cleanup, or a physical interface change. Tests against this reference
do not establish compatibility with every vendor's HTTPS proxy.
