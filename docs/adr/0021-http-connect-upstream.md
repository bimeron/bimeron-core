# ADR 0021: HTTP CONNECT upstream

Status: accepted, October 28, 2026. Tracks issue #43.

## Context

Some networks provide a standard HTTP proxy rather than a SOCKS5 server. The
core already separates TCP streams from UDP packets and supports TCP-only VPN
operation for SSH.

## Decision

Add an outbound HTTP/1.1 CONNECT dialer. Accept `http://` proxy URIs through
`HTTP`, `Key`, or `File`, plus explicit `Type = http` parameters. Support optional
Basic authentication. Use the existing local SOCKS5 listener in proxy mode.
In VPN mode, carry DNS over TCP and drop other proxied UDP, following the
existing TCP-only path. Preserve physical-interface binding and endpoint
resolution for the proxy connection.

## Tradeoffs

- Plain HTTP provides no encryption for proxy credentials or traffic to the
  proxy. HTTPS proxy transport needs a separate TLS validation design.
- UDP applications do not work through this upstream unless routed directly.
- The existing local listener remains SOCKS5; an inbound HTTP proxy would be a
  separate feature.
