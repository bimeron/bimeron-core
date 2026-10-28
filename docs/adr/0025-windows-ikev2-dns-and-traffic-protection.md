# ADR 0025: Windows IKEv2 DNS and persistent traffic protection

Status: accepted for the experimental Windows backend, October 28, 2026.
Tracks [issue #56](https://github.com/bimeron/bimeron-core/issues/56).

## Context

Live captures demonstrated Windows DNS queries reaching the LAN resolver while
the native VPN was connected, and direct traffic after disconnection. Route
flags and NRPT alone cannot enforce traffic isolation. The user selected DNS
protection and a full kill switch now, rather than a DNS-only first milestone.

## Decision

Add the explicit optional `[IKEv2] KillSwitch = true` setting. It enables both
traffic protection and an owned NRPT root rule using the connected VPN adapter's
DNS servers. Existing configurations remain unprotected unless they opt in.
The packet backend's `[Interface] KillSwitch` is still rejected on this path.

Reuse the existing Windows filtering library, persistent Bimeron provider,
sublayer, transactions, shared session lock and `bimeron recover` command.
Native rules have a distinct name so packet sessions cannot replace retained
native protection. Do not add a firewall service, Wintun dependency or embedded
DNS resolver. Provisioning and certificate/credential ownership remain unchanged.

RAS bootstrap, including initial DNS resolution/authentication, happens before
protection is installed. Do not claim protection during this preparation phase.
Engine publishes `connected` only after both WFP and NRPT setup succeed.
Protection is system-wide on the Windows machine, not restricted to Bimeron's
process or the invoking Windows account.

WFP blocks IPv4 and IPv6 at connect/receive authorization and inbound/outbound
transport layers, covering new connections and existing packet flows. Higher
priority permits are limited to the VPN interface (NET_LUID and transport-layer
interface index), loopback, DHCP port pairs, link-local NDP types and native IKE/
IPsec traffic to the observed peer endpoint. No blanket Bimeron application
exception or LAN bypass is allowed. Native RAS also needs a System-only ALE
authorization for IP-in-IP protocols 4/41 to that peer before IPsec wrapping;
transport-layer carrier permits remain pinned to the peer. These are native
control/data-plane exceptions, not permission for arbitrary application traffic.

The peer is obtained from this session's RAS handle, verified against the native
connection enumeration. RASCONN's connection LUID is not a network interface
NET_LUID. Read the connected PPP adapter's NET_LUID/index and DNS through native
IP Helper APIs instead. Unknown endpoints, missing DNS/interface data or
conflicting local/effective NRPT policies cause protected startup to fail.
Alternative remote peers are not silently permitted; remote endpoint changes
can interrupt connectivity until explicit recovery and a new connection.

Install WFP atomically before adding NRPT. NRPT uses an unpredictable owned tag
and supplies all namespaces to the VPN's DNS. Never overwrite existing DNS
policies, adapter DNS settings, group policy or profile properties. Cleanup
checks that the owned root rule's servers/namespace were not externally changed.
Applications can still choose a resolver reachable through the VPN; NRPT does
not interpret or rewrite application-managed DNS/DoH. The full traffic guard
blocks their ordinary physical-interface paths as well.

## Cleanup and recovery

An explicit successful stop closes the native RAS handle first, removes the
owned NRPT rule and flushes DNS cache, then removes WFP filters. Independent
cleanup deadlines apply after cancellation. Setup failures roll back the owned
resources in the same order; failures that prevent safe cleanup retain WFP.
Mutating DNS setup uses its own bounded context so caller cancellation cannot
kill it between an NRPT change and rollback. An indeterminate timeout retains
protection for explicit recovery instead of reopening traffic.

Unexpected session loss, process termination or failed RAS/DNS cleanup retains
persistent protection. A native tunnel can survive process termination; any
remaining allowed traffic still uses that OS tunnel. Starting another session
does not silently clear retained rules. Explicit elevated `bimeron recover`
removes owned native DNS policy before releasing WFP. Disconnect a surviving
lab tunnel explicitly in Windows when recovering; recovery does not adopt or
disconnect unrelated RAS profiles. No reboot-time automatic restoration is
promised: this milestone uses retained protection and explicit recovery.

## Tradeoffs and validation

NRPT alone would steer the Windows resolver but leave application DNS and other
traffic free to use physical routes. A dynamic WFP session would clean itself
up after a crash and reopen direct traffic. Both are rejected for protected mode.
Persistent policy can intentionally leave the machine offline until recovery;
this cost is explicit and covered by live failure/recovery tests.

Test persistent/atomic rule installation, peer/interface scoping, absence of
application escapes, cleanup ordering, cancellation, policy conflicts and
modified-rule retention. Live checks must include usable IPv4/IPv6 VPN traffic,
uncached DNS, physically bound new and pre-existing sockets, manual disconnect,
owner termination, restart refusal and explicit recovery. Packet capture must
include positive cleartext controls; empty negative captures are insufficient.
DHCP/NDP and native IPsec exceptions are intentional; this is not protection
against a privileged attacker changing Windows firewall/routing policy.

References: [WFP layer conditions](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer),
[Windows VPN name resolution](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/vpn/vpn-name-resolution),
and [Windows SDK RAS definitions](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/Ras.h).
