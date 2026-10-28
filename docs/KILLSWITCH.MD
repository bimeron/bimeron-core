# Windows kill switch

The following rules describe the packet backend. For the experimental native
IKEv2 backend, use `[IKEv2] KillSwitch = true` and follow
[its traffic/DNS protection contract](IKEV2.MD#native-traffic-and-dns-protection).
Native protection has no general executable or direct-routing exemption and
retains rules after unexpected native session loss until explicit recovery.

```ini
[Interface]
Mode = vpn
KillSwitch = true
```

The option is disabled by default. Enable it in your local `profiles/main.conf`
for manual testing. Protection activates after route setup, and the console
prints `Kill switch active`. Blocking is not guaranteed before that message.

## Rules

The implementation uses Windows Filtering Platform at the outbound connection
and connection-receive ALE layers, separately for IPv4 and IPv6. Filters and
their owner are persistent, not tied to the process's dynamic session.
Closing or crashing the core does not remove them. Installation, replacement,
and removal use atomic WFP transactions.

- Connections through the Bimeron interface are allowed.
- The core executable itself is allowed to operate the Outline transport,
  `ssconf`, service DNS, and direct forwarding according to core policy.
- Other applications may access destinations outside the tunnel only through
  `direct`. `proxy` and `block` deny such access. First-match order is
  retained, including multiple CIDRs in one section. `Default = direct` allows
  remaining destinations; `Default = proxy` and `block` deny them outside the tunnel.
- Loopback, DHCP, and local ICMPv6 neighbor-discovery traffic are allowed regardless
  of policy. There is no general exemption for physical-interface DNS servers.
- With `IPv6 = disable`, ordinary IPv6 destinations outside the tunnel are
  blocked even with `direct`; local ICMPv6 control traffic and loopback remain available.

With the kill switch enabled, the local network is **not automatically exempt**.
If a system route bypasses the tunnel, access requires an explicit `direct` rule:

```ini
[Rule]
CIDR = 192.168.1.0/24
Action = direct
```

This blocks traffic for the whole computer, not just one application. It does not
override independent deny rules from another firewall. Policy changes by an
administrator process and early Windows boot before BFE starts are outside the
claimed protection.

## Shutdown and crashes

Ctrl+C performs normal cleanup of DNS, routes, and owned WFP filters.
Forced process termination leaves filters in place. Remove them with:

```cmd
dist\windows-amd64\bimeron.exe recover
```

Run this from an administrator CMD after stopping all core instances.
It removes only Bimeron-owned filters and DNS rules. The WFP recovery call does
not require internet access.

Restarting with `KillSwitch = true` atomically replaces old filters after the
tunnel is ready. With `KillSwitch = false`, protection left after a crash is
not removed automatically: the command returns `kill_switch_pending_run_recover`.

Codes `kill_switch_arm_failed_run_recover`, `kill_switch_inspect_failed`, and
`cleanup_failed_run_recover` mean startup/cleanup has not been confirmed.
After stopping, use `recover`; do not treat this state as `connected`.

## Manual validation

1. Disconnect any other VPN. From an administrator CMD, run
   `dist\windows-amd64\bimeron.exe run profiles\main.conf`. Wait for `Kill switch active` and `connected`.
2. Check websites and the external IP. With `Default = proxy`, only the Outline IP should appear.
3. Repeat network changes/loss. External-IP queries may fail during reconnection;
   your original IP must not appear.
4. In a separate administrator CMD, forcibly terminate the core using
   `taskkill /F /IM bimeron.exe`. With `Default = proxy`,
   `curl.exe --max-time 5 --noproxy "*" https://api.ipify.org` must fail.
5. Run `dist\windows-amd64\bimeron.exe recover`. Normal internet access should return.
6. Start the VPN again, stop with Ctrl+C, and check that internet access is restored.
7. Check a `direct` exception separately: it should remain directly accessible
   even with protection left after a crash. This is an intentional exception, not a leak.

The historical October 8, 2026 check used Windows amd64 and the core service.
After forced termination, persistent WFP filters and the owned NRPT rule remained,
active tunnel routes disappeared, and direct HTTPS and DNS were blocked.
SCM restarted the service without connecting the VPN. After reboot, WFP and NRPT
persisted and continued blocking; `recover` removed them, left no core-owned
routes, and restored direct internet access.

Automated tests do not install real filters: they test policy compilation and
management through a stub WFP API. The user runs real crash scenarios.

The implementation uses [tailscale/wf](https://github.com/tailscale/wf), a pinned
BSD-licensed copy with a small `Transaction` addition. Layers and conditions are
described in the [Microsoft WFP documentation](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers).

