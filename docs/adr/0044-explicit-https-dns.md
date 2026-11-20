# ADR 0044. Explicit DNS over HTTPS for captured VPN DNS

## Status

Accepted for Core issue #246.

## Context

Core captures system DNS at a synthetic tunnel address. It forwards the
wire question through the session upstream and uses validated answers for
domain routing metadata. Plain DNS gives the upstream access to those
questions and answers. An encrypted resolver must be reachable without the
resolver hostname itself triggering lookup or a routing loop.

## Decision

A profile opts into DoH with HTTPS URLs and positional groups of numeric
dial addresses. The URL keeps its HTTP authority and TLS identity. Core
dials the active numeric addresses through the upstream, with normal
certificate verification. WireGuard and AmneziaWG require these addresses
inside the peer AllowedIPs and apply the same resolver to internal lookups.
Physical bootstrap for the upstream transport and SSConf retains its
existing behavior.

The resolver retries addresses within each endpoint, then moves to the next
endpoint. It accepts validated NXDOMAIN as final. All attempts share a
bounded deadline. Failure returns SERVFAIL to the captured client and leaves
DNS metadata untouched. The OS keeps using the synthetic tunnel DNS address,
and the kill switch gains no physical HTTPS exceptions.

## Alternatives

Putting URLs in the existing DNS option would change its IPv4 transport
bootstrap and host parsing contracts. Using platform HTTPS resolvers would
split implementation across hosts and move responses outside the shared
metadata path. Resolving DoH hosts dynamically would require an additional
trusted resolver or out-of-band configuration.

## Consequences

An explicit configuration can fail when numeric addresses change. Profiles
can list multiple addresses and endpoints for redundancy. Older Core builds
reject active DoH keys. Host editors need to preserve both fields together.
The profile and round-trip rules are in the configuration and Desktop
document references.
