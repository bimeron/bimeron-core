# ADR 0022: Embed the Shadowsocks v2ray-plugin WebSocket client

Status: Accepted, October 28, 2026. The user selected option B.

Tracking issue: [#50](https://github.com/bimeron/bimeron-core/issues/50).

## Context

Bimeron already implements Shadowsocks AEAD through the Outline SDK and
Shadowsocks 2022 through `internal/ss2022`. Both currently connect directly to
the Shadowsocks server. The URI parser rejects the `plugin` query parameter.
VLESS already uses certificate-verified TLS and `golang.org/x/net/websocket`.

The requested feature is built-in client compatibility with the original
`v2ray-plugin` in WebSocket and WebSocket/TLS modes, importing its configuration
and verifying interoperability with the original plugin. It is not a general
SIP003 executable host or a new Shadowsocks encryption implementation.

Reference upstream: `shadowsocks/v2ray-plugin` v1.5.0, commit
`7466d1f3a124a0e9f98184a5e0b2d766371c2d84`, using V2Fly v5.54.2.
The default settings are `mode=websocket`, `host=cloudfront.com`, `path=/`,
TLS disabled, and `mux=1`. The host controls both HTTP Host and the TLS server
name. It does not default to the Shadowsocks endpoint hostname.

The default Mux setting is a wire protocol requirement: encrypted Shadowsocks
bytes travel inside V2Ray Mux frames inside binary WebSocket frames. Simply
wrapping Shadowsocks bytes in WebSocket is compatible only with a server
configured for the corresponding non-Mux mode.

SIP002 specifies the `ss://` URI and percent-encoded `plugin` query value.
SIP003 specifies the plugin options grammar and process ABI. This implementation
imports the configuration and implements the wire transport in process; it
does not launch an executable or implement the process ABI.

## Decision: option B

Implement a focused embedded WS/WSS client with V2Ray Mux concurrency and
connection reuse. `mux=0` opens an independent non-Mux WebSocket per stream;
positive values limit concurrent sessions on each pooled WebSocket, with the
upstream default of `1`. Retire idle connections and connections that exhaust
their session identifiers. Bound per-session receive queues; a stalled session
must not block delivery to unrelated sessions. Normal session closure and
timeouts while waiting for the shared writer affect only that session. An
interrupted frame write retires the shared connection because its framing can
no longer be trusted. A connection failure terminates its active sessions;
new streams establish a fresh connection instead of replaying application data.

Reuse the existing TLS helper with HTTP/1.1 ALPN and the existing WebSocket
dependency. Extract only the small shared WebSocket handshake helper if it
avoids duplication; preserve VLESS early-data behavior and existing tests.
Do not import the complete V2Fly or Xray runtime into the product module graph.

### Configuration and validation

- Keep typed plugin settings on `accesskey.Profile`, separate from `Endpoint`,
  whose existing positional literals and plain Shadowsocks meaning remain valid.
- Import the `plugin` URI query, simple Shadowsocks JSON/YAML `plugin` and
  `plugin_opts` fields, and explicit `.conf` plugin fields through one parser.
- Support only the exact plugin identifier `v2ray-plugin` and the options
  `mode=websocket`, `tls`, `host`, `path`, and unsigned 32-bit `mux` concurrency.
- Preserve upstream defaults and normalize an empty path to `/` and a relative
  path by adding a leading `/`.
- URI-decode the query once, then parse the backslash-escaped plugin options.
  Preserve literal escaped semicolons, equal signs, and backslashes.
- Match upstream presence semantics for `tls`: an explicitly supplied value,
  including `false`, still enables TLS. Document this behavior.
- Reject duplicates, malformed escapes, unknown options, other plugin names,
  executable paths, endpoint overrides, server mode, and other transport modes.
  Rejecting ambiguous and unsupported options is deliberately stricter than
  upstream's first-value and unknown-option behavior.
- Initially reject `cert`, `certRaw`, `key`, socket tuning, and plugin-specific
  logging options. TLS uses the system trust store; internal tests can inject
  a trust store. Do not add an insecure certificate-verification switch.
- Preserve existing plain Shadowsocks URI forms and salt-prefix behavior.
  Do not include credentials, complete access URIs, or raw options in errors.

### Transport and lifecycle

Compose the existing encryption layer with a `transport.StreamEndpoint`:
Shadowsocks encryption, optional V2Ray Mux framing, WebSocket, optional TLS,
then interface-bound TCP. Keep the destination address in the encrypted
Shadowsocks request and treat the plugin server as the transport endpoint.

Allow the Shadowsocks 2022 stream constructor to receive the same endpoint
without changing its encryption or existing direct TCP/UDP behavior. Claim
method combinations only after verifying them; reject any intentionally
unsupported combination during validation.

Bound handshakes and frame sizes, honor cancellation and deadlines, and close
all owned connections on runtime shutdown and transport generation replacement.
Validate Mux metadata, session identifiers, data lengths, status, and error
flags. Test peer termination, malformed frames, partial I/O, and cleanup.
Do not promise TCP half-close behavior that WebSocket/Mux cannot provide.
Closing either stream direction closes that logical Mux session. Its peers
remain usable unless the shared underlying connection fails. Receive queues
are limited to 256 KiB per session; exceeding the limit closes that session
instead of stalling the shared reader. Idle pooled connections retire after
30 seconds. These limits are implementation policy, not new URI options.

### Runtime behavior

Profiles using this plugin have a TCP-only proxy transport. Use the existing
DNS-over-TCP behavior, leave the proxied UDP transport absent, and never fall
back to direct or ordinary Shadowsocks UDP. Preserve explicit direct-routing
policy. Update bootstrap endpoint resolution, route exclusions, diagnostics,
CLI checks, and proxy/VPN creation consistently.

### Verification and CI

Use the original v1.5.0 plugin server as a separate test process in front of an
independent Shadowsocks server. Test WS and WSS, default Mux framing, explicit
Mux settings, custom Host/path, verified TLS failures, concurrent independent
connections, large bidirectional transfers, cancellation, and reconnects.
Include existing Shadowsocks 2022 methods in the verified scope where the
reference server supports them.

Pin reference versions and verify release archive SHA-256 checksums. Local
interop tests may skip when their explicitly configured reference binaries are
absent. The CI interoperability job must install them and fail if they are
missing. Run regression tests, targeted race checks, dependency-notice checks,
and focused handshake/transfer benchmarks.

Local reference tests use `BIMERON_V2RAY_PLUGIN_BIN` and `BIMERON_XRAY_BIN`.
Set `BIMERON_REQUIRE_SSPLUGIN_INTEROP=1` to make absent binaries a test failure.
Run `go test -race ./internal/ssplugin ./internal/v2raymux -count=1` with those
variables set. CI downloads and verifies the original plugin release and uses
the already pinned Xray reference server outside the product module graph.

## Alternatives and tradeoffs

### Option A: support only Mux 0/1 without a connection pool

Open one WebSocket per Shadowsocks stream and support the default Mux framing
without sharing or reuse. This is smaller but rejects profiles with `mux>1`
and repeats TCP/TLS/WebSocket handshakes for sequential streams. The user chose
full Mux behavior to improve compatibility and keep the transport reusable.

### Non-Mux-only client

Implement only `mux=0`. This is smaller but cannot read a default plugin profile
and connect to a default server without configuration changes. It does not meet
the intended default-compatibility goal and is not recommended.

### External original-plugin process

Reuse upstream protocol and pooling behavior by spawning its binary. This adds
binary packaging, executable trust, process management, and mobile integration
work, and does not meet the requested built-in implementation approach.

## Sources

- [Original plugin source and defaults](https://github.com/shadowsocks/v2ray-plugin/blob/v1.5.0/main.go)
- [Original plugin options grammar](https://github.com/shadowsocks/v2ray-plugin/blob/v1.5.0/args.go)
- [Original plugin CLI reference](https://github.com/shadowsocks/v2ray-plugin/blob/v1.5.0/docs/CLI.md)
- [V2Ray Mux framing](https://github.com/v2fly/v2ray-core/blob/v5.54.2/common/mux/frame.go)
- [SIP002 URI scheme](https://shadowsocks.org/doc/sip002.html)
- [SIP003 plugin design](https://shadowsocks.org/doc/sip003.html)
