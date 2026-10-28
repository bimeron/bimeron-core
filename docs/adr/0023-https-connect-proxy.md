# ADR 0023: Verified TLS for HTTP CONNECT proxies

Status: accepted, October 28, 2026. Tracks issue #49.

## Context

The HTTP CONNECT upstream supports Basic authentication over plaintext TCP.
HTTPS proxies require verification before credentials are transmitted. VPN
bootstrap resolves the endpoint to an IP, so the original proxy identity must
survive that resolution.

## Decision

Accept `https://` through `HTTP`, `Key`, and `File`, and support explicit
`Type = https`. Keep the internal profile type `http` and store a nonempty
`HTTPServerName` to enable TLS and preserve the URI hostname or IP independently
of the dial endpoint. Both proxy and VPN modes use this identity.

Reuse the existing verified TLS helper without browser fingerprinting. Require
TLS 1.2 or newer, offer only HTTP/1.1 through ALPN, and use system trust roots.
Send CONNECT and optional Basic credentials only after certificate chain and
hostname verification succeed. Keep the interface-bound dialer, setup deadline,
and cancellation. Do not retry over plaintext after TLS failure.

Retain buffered tunnel data and support TLS write half-close through
`close_notify`; read half-close shuts down the underlying TCP read direction.
Keep the existing TCP-only VPN behavior and local SOCKS5 listener.

## Alternatives and tradeoffs

- A separate internal `https` type would duplicate transport selection and
  TCP-only routing conditions. A TLS identity on the existing profile is enough.
- Custom CA paths and server-name overrides would support additional private
  deployments but expand configuration and validation. Use operating-system
  trust installation initially; no insecure verification option is provided.
- A general HTTP transport abstraction or HTTP/2 implementation is unnecessary
  for this HTTP/1.1 feature. NaiveProxy remains a separate protocol.
- Configuration credentials remain plaintext on disk. Plain HTTP remains
  available for compatibility and does not encrypt proxy credentials.

## Validation

Cover URI/configuration sources, preserved TLS identity after DNS resolution,
authentication success and rejection, untrusted/expired certificates, hostname
mismatch, setup cancellation, buffered bytes, and TLS half-close. CI runs an
independent pinned Caddy forward proxy restricted to HTTP/1.1, checks Basic
authentication failures, bidirectional payloads, and a local SOCKS5 relay.
The external binary is a test fixture, not a compiled core dependency.

Run `go test ./...`, `go vet ./...`, relevant race checks, and the local
`BenchmarkHTTPSConnect` setup benchmark. To run interoperability locally, set
`BIMERON_HTTP_CADDY_BIN` to the Caddy forwardproxy binary built by CI.
