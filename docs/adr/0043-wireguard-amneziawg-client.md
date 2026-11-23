# ADR 0043: WireGuard and AmneziaWG client upstream

[ADR 0045](0045-wireguard-reserved-bytes.md) extends this design for
plain WireGuard profiles with Reserved bytes.

Status: accepted, November 20, 2026. Tracks issue #202.

## Context

Users want to connect to WireGuard servers and to AmneziaWG (AWG) servers,
whose obfuscation has evolved through versions 1.0, 1.5, 2.0, 3.0 and 3.1.
Bimeron already has a shared VPN pipeline: a TUN adapter, a gVisor stack via
tun2socks, policy routing (proxy, direct, block), DNS handling, statistics, a
kill switch and a SOCKS5 mode. Every upstream plugs in as a
`transport.StreamDialer` and `transport.PacketListener` (MASQUE is the
closest example, ADR 0028). There are two places WireGuard could plug in:

- a userspace WireGuard device whose own netstack is used as an ordinary
  upstream (Bimeron TUN → gVisor → flows → WireGuard netstack → peer);
- a direct path that forwards raw IP packets from Bimeron's TUN into the
  WireGuard device, bypassing flow handling.

Shipped clients use the GPL-licensed amneziawg-tools and Linux kernel module,
and the AmneziaVPN client is GPL-3.0. Bimeron must not ship GPL code.

## Decision

1. **Upstream model.** Run a userspace device over the engine's
   `tun/netstack` and expose it as a normal upstream (`internal/wireguard`).
   Routing, DNS, statistics, the kill switch and SOCKS stay shared. Bimeron
   does not build the direct TUN-to-WireGuard path. If benchmarks show a
   significant gap to a native client, that is tracked as a separate issue.
2. **One engine.** Use `github.com/amnezia-vpn/amneziawg-go/v3` (MIT) for both
   AWG and plain WireGuard, since plain WireGuard is AWG with no obfuscation
   options. The engine sits behind a small internal `tunnel` interface: start
   with a bind and a netstack, dial TCP, dial UDP, read the last handshake,
   initiate, close. Plain WireGuard could move to upstream `wireguard-go` by
   adding one implementation. Compatibility with the upstream `wireguard-go`
   reference server is tested on every CI run.
3. **Pinned revision.** Pin the tag `v3.1.20261116` (2026-11-16). It builds
   with the gVisor revision used by tun2socks (unlike `v1.0.4`, which
   requires a newer gVisor and breaks tun2socks). It has full AWG 3.1
   support: header protection, random trailers, disabled cookie replies,
   ranged timers and content padding. It cross-compiles for every shipped
   target. The Outline SDK moves from v0.0.21 to v0.0.23 as part of the
   upgrade.
4. **Network path.** A custom `conn.Bind` opens one UDP socket for the fixed
   peer endpoint through the session's outbound `net.Dialer` control. That
   control applies desktop interface binding, Android protect or the Apple
   host network, so tunnel datagrams never loop into the TUN. The kill switch
   already exempts the core's own sockets. Datagrams from other sources are
   dropped. The endpoint name is resolved for every session generation (in
   VPN mode on the outbound path with bootstrap DNS), so a reconnect after a
   network change creates a new device and resolves the name again.
5. **Connected status.** A session reports connected only after a completed
   handshake (20-second bound). In VPN mode a DNS check through the scope
   follows (a public HTTPS target may be outside AllowedIPs), and health
   monitoring uses handshake freshness and forces a handshake when the last
   one is older than 150 seconds, instead of HTTP probes.
6. **AllowedIPs scope.** `[Routing] AllowedIPsMode` (`direct` by default,
   `block`, `ignore`, `only`) is applied inside the WireGuard client to every
   flow Bimeron policy sends upstream, including DNS and checks. Destinations
   outside AllowedIPs go direct through the outbound path, are dropped, or
   (with `ignore`) enter a tunnel whose peer allows everything. `only`
   compiles an empty Bimeron policy, so AllowedIPs alone decide. When
   AllowedIPs covers all of IPv4 but not all of IPv6, IPv6 that would go
   direct only because it is outside AllowedIPs is blocked, to prevent leaks.
7. **Profile format.** The wg-quick text is the key source: `[AccessKey] File`
   stores it byte for byte, and explicit `Type = wireguard` options use the
   same key names. One peer only. Hooks, `Table`, `FwMark`, `SaveConfig`,
   unknown keys and several peers are rejected with structured problems. In
   the text, `Address` holds the tunnel addresses, and only its `DNS` (IPv4
   entries) and `MTU` (also the adapter MTU) apply: Bimeron `[Interface]`
   DNS and MTU are ignored for these profiles, also in older profiles.
8. **Desktop API.** The desktop does not parse WireGuard text. The
   `bimeron wireguard` bridge provides detect, inspect, byte-preserving edit,
   AllowedIPs coverage and link import. Problems inside the text carry
   `document: "wireguard"`.
9. **Links.** `vpn://` (Amnezia), `wireguard://` and `wg://` parsers are
   written from the observed formats and sample data; no AmneziaVPN or other
   GPL code is used. Amnezia service keys, other protocols, non-zero
   `reserved` (WARP, issue #208) and unknown parameters are refused.

## Consequences

- Each connection crosses two userspace stacks (tun2socks gVisor and the
  WireGuard netstack). This costs CPU compared to a kernel or direct-path
  client; the benchmarks in [WIREGUARD.MD](../WIREGUARD.MD) quantify it.
- TCP from apps is terminated locally and re-originated inside the tunnel, so
  MSS, window and ECN behavior follow the WireGuard netstack, not the app.
  UDP datagrams larger than the tunnel MTU are fragmented by the inner stack.
- The bind uses one socket and a batch size of 1. Batching (recvmmsg/GSO) is
  a possible later optimization, but it must keep the outbound control.
- Only one peer per profile. WARP `reserved`, `awg://` links, Karing
  `obfsParam` and Hiddify noise parameters are not supported.
- WireGuard and AWG are experimental until they are validated live on Windows
  and Linux. Android and Apple builds compile and pass unit tests but are not
  validated live.

## Alternatives

- **Direct TUN-to-WireGuard path.** Faster, but it bypasses Bimeron's flow
  policy, DNS, statistics and per-destination routing, and it would need a
  second routing implementation. Rejected for now.
- **Upstream wireguard-go plus a separate AWG engine.** Two engines with
  nearly identical code. Rejected; the interface keeps that switch cheap.
- **amneziawg-go v1.0.4.** Requires a newer gVisor that breaks tun2socks.
- **Kernel module or amneziawg-tools.** GPL, and they need privileges and
  platform integration that the userspace model avoids.
