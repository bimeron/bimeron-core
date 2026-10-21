# ADR 0001: Select upstream transports by profile type

Status: Accepted

## Context

The core originally used Shadowsocks for all proxied flows. Routing, DNS,
MTU, and tunnel setup already operate on stream and packet transport
interfaces. Remote SOCKS5 should use those paths, and future protocols may
need their own parameters.

## Decision

- A complete access URI selects its protocol by scheme. `Key` and `File`
  accept `ss://`, `ssconf://`, and `socks5://`; dedicated `SS`, `SSConf`, and
  `SOCKS5` fields are available. Only one source is allowed.
- Explicit server parameters require `Type`. Use `shadowsocks` as the
  documented name (`ss` is an alias), or `socks5`. Missing and unknown types
  fail validation. Shadowsocks fields retain their existing meanings;
  SOCKS5 uses optional username/password authentication.
- Remote SOCKS5 implements TCP `CONNECT` and UDP `ASSOCIATE`. VPN startup
  requires both through the existing transport check. The local SOCKS5
  listener remains TCP only and therefore needs only upstream `CONNECT`.
- The upstream socket uses the selected physical interface in VPN mode.
  Routing, DNS, MTU, and kill-switch behavior remain shared by transports.

## Alternatives and tradeoffs

Inferring Shadowsocks from `Method` would preserve old explicit profiles but
make the format ambiguous as more protocols are added. Explicit `Type` was
chosen because these profiles are not deployed to other users.

Allowing TCP-only SOCKS5 in VPN mode would leave proxied UDP and DNS over UDP
unavailable while appearing connected. Requiring `UDP ASSOCIATE` makes the
failure visible before tunnel setup. The tradeoff is that SOCKS5 servers
without UDP support can only be used in local `proxy` mode.

SOCKS5 provides no transport encryption or dynamic configuration service.
Those remain protocol differences, not features emulated by the core.
