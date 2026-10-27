# ADR 0017: TCP-only system VPN mode for SSH

Status: accepted, October 27, 2026. Tracks issue #32 and extends ADR 0013.

## Context

SSH direct TCP forwarding works as a local proxy but cannot relay UDP. Users
want TCP applications to use SSH without configuring each application's proxy.
The system VPN path currently requires both TCP and UDP transport checks.

## Decision

Allow SSH profiles in VPN mode with the existing TUN packet path and SSH TCP
dialer. Carry captured DNS through SSH using DNS-over-TCP, including DNS queries
received from applications over UDP. Drop other proxied UDP flows rather than
falling back to the physical network. Preserve explicitly direct-routed traffic
and the physical-network path used to reach and resolve the SSH server.

## Tradeoffs

- This is not a full VPN: UDP applications do not work unless routed directly.
- DNS-over-TCP requires the configured resolver to support TCP on port 53.
- Applications that bypass system routing or use their own DNS are not covered.
- A UDP-capable upstream remains the preferred solution for full VPN behavior.
