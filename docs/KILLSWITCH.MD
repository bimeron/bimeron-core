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
for manual testing. Protection is installed as the first step of a connection,
before any session network activity, and the console prints
`Kill switch active`. It stays installed until the session is stopped,
including while the core reconnects and after a connection failure. Without
the kill switch, traffic can leave outside the tunnel while connecting,
reconnecting or after a failure.

## Rules

The implementation uses Windows Filtering Platform at the outbound connection
and connection-receive ALE layers, separately for IPv4 and IPv6. Filters and
their owner are persistent, not tied to the process's dynamic session.
Closing or crashing the core does not remove them. Installation, replacement,
and removal use atomic WFP transactions.

- Connections through the Bimeron interface are allowed.
- The core executable itself is allowed to operate the upstream transport,
  `ssconf`, service DNS, and direct forwarding according to core policy.
  This exception applies only to processes of the core image that run as
  `SYSTEM` or with an elevated administrator token. Other instances of the same
  executable, such as CLI commands started by a standard user or from a
  non-elevated terminal, are subject to the same rules as other applications.
- Other applications may access destinations outside the tunnel only through
  `direct`. `proxy` and `block` deny such access. First-match order is
  retained, including multiple CIDRs in one section. `Default = direct` allows
  remaining destinations; `Default = proxy` and `block` deny them outside the tunnel.
- Loopback, DHCP, and local ICMPv6 neighbor-discovery traffic are allowed regardless
  of policy. There is no general exemption for physical-interface DNS servers:
  DNS ports (53 and 853, TCP and UDP) are blocked outside the tunnel for every
  process except the core, even to a resolver inside a `direct` CIDR, so names
  are not resolved outside the tunnel while protection holds. A `direct` rule
  for a LAN or corporate DNS server therefore does not make that server usable
  while the kill switch is enabled; names resolve through the tunnel DNS. DNS
  over HTTPS on port 443 to a resolver inside a `direct` CIDR is not covered.
  LLMNR (UDP and TCP 5355) and the NetBIOS name service (UDP 137), which
  disclose queried and local names to the local link, are blocked the same way
  and are also refused inbound. mDNS (UDP 5353) is not blocked separately: it
  is permitted only where a `direct` rule covers its multicast destination
  (`224.0.0.251/32` or `ff02::fb/128`), so a LAN rule such as `192.168.1.0/24`
  alone does not permit it. Answers arrive from the responders' LAN addresses,
  so local discovery such as printers and casting needs `direct` rules for both
  the multicast address and the LAN range; mDNS can then disclose names of
  local services queried on that link.
- Forwarded traffic (Internet Connection Sharing, WinNAT for WSL2 or Hyper-V
  guests) does not pass the application layers these filters use and is not
  covered by the kill switch.
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

## Lifecycle

Protection belongs to the whole session, from an accepted start to an explicit
stop, not to a single connection attempt:

1. **Start.** Before network inspection, key or `ssconf` resolution, bootstrap
   DNS and the transport check, the core installs the full rule set without the
   tunnel interface permit: the core executable exception, loopback, DHCP,
   IPv6 neighbor discovery, the name port block (DNS 53 and 853, LLMNR 5355
   and NetBIOS names 137 for every process but the core, above `direct`
   CIDRs), `direct` CIDRs and the default block.
   Filters left by an earlier process are replaced in the same transaction.
2. **Tunnel adapter created.** The core installs the set again with the permit
   for the new adapter before it configures routes and DNS. Each replacement is
   one transaction, so protection is never absent in between.
3. **Session closed** for a reconnect or after a failure. The set is installed
   again without the adapter permit; protection is not removed between
   attempts.
4. **Waits and failure.** Protection stays through recovery waits and in
   `failed`. A failed session holds it (`Status.KillSwitch` is `holding`) until
   a retry, a start with another kill switch profile, or a stop; see
   [CONTROL.MD](CONTROL.MD#kill-switch-hold). While protection holds, other
   applications reach only `direct` destinations: internet access is paused
   until the VPN connects.
5. **Stop.** `stop`, `shutdown`, Ctrl+C of a foreground session or a service
   stop removes the filters after the session is closed. If removal fails, the
   session reports `failed` with `cleanup_failed_run_recover` and the filters
   stay until `recover`.

## Shutdown and crashes

Ctrl+C performs normal cleanup of DNS, routes, and owned WFP filters.
Closing the console window, signing out, or shutting down Windows starts the
same cleanup, but Windows ends the process after a few seconds; if cleanup does
not finish in time, the filters stay in place as after a forced termination.
Forced process termination leaves filters in place. Remove them with:

```cmd
dist\windows-amd64\bimeron.exe recover
```

Run this from an administrator CMD after stopping all core instances.
It removes only Bimeron-owned filters and DNS rules. The WFP recovery call does
not require internet access.

Protection is installed at the start of a session, so a crash, forced
termination or power loss while connecting, reconnecting or in `failed` also
leaves the filters installed. After a reboot the service starts without a
session and reports `failed` with `cleanup_failed_run_recover` and
`KillSwitch: "residual"` while the filters keep blocking. Connect a profile
with `KillSwitch = true` or run `recover` to leave this state.

Restarting with `KillSwitch = true` atomically replaces old filters at the
start of the new session. With `KillSwitch = false`, protection left after a
crash is not removed automatically: the command returns
`kill_switch_pending_run_recover`.

Codes `kill_switch_arm_failed_run_recover` and `cleanup_failed_run_recover`
mean startup or cleanup has not been confirmed. After stopping, use `recover`;
do not treat this state as `connected`. `kill_switch_inspect_failed` is reported
when a start with `KillSwitch = false` cannot inspect leftover filters; restart
the application and try again.

## Manual validation

1. Disconnect any other VPN. From an administrator CMD, run
   `dist\windows-amd64\bimeron.exe run profiles\main.conf`. Wait for `Kill switch active` and `connected`.
2. Check websites and the external IP. With `Default = proxy`, only the upstream server's IP should appear.
3. Repeat network changes/loss. External-IP queries may fail during reconnection;
   your original IP must not appear. The session returns to `connected` after
   the network is restored.
4. Stop with Ctrl+C. Make the upstream server unreachable (for example, block
   its address on the router) and start again. After the initial attempts the
   console reports `failed` and keeps running. With `Default = proxy`,
   `curl.exe --max-time 5 --noproxy "*" https://api.ipify.org` must fail.
   Press Ctrl+C and check that internet access is restored. Unblock the server.
5. Start the VPN again. In a separate administrator CMD, forcibly terminate the
   core using `taskkill /F /IM bimeron.exe`. With `Default = proxy`, the same
   `curl.exe` command must fail.
6. Run `dist\windows-amd64\bimeron.exe recover`. Normal internet access should return.
7. Start the VPN again, stop with Ctrl+C, and check that internet access is restored.
8. Check a `direct` exception separately: it should remain directly accessible
   while protection holds and after a crash. This is an intentional exception.

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
