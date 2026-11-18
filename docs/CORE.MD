# Bimeron Core

The `bimeron/core` package manages a VPN or SOCKS5 session. The CLI uses the same
package available to a GUI. System VPN is implemented for Windows and Linux;
the macOS CLI backend is experimental. The external packet backend for
NetworkExtension is described in [APPLE_NETWORK_EXTENSION.MD](APPLE_NETWORK_EXTENSION.MD).

## Using the Go API

For native Windows IKEv2, load an [IKEv2 configuration](IKEV2.MD), or construct
`core.SessionConfig{Mode: "vpn", IKEv2: &core.IKEv2Config{WindowsProfile: "Corporate VPN", ServerName: "vpn.example.com"}}`.
Do not start from `DefaultConfig`: its packet options are rejected. This path
requires an elevated foreground user process and a pre-provisioned profile.
Native `connected` means RAS readiness plus requested protection setup. Set
`IKEv2Config.KillSwitch = true` to enable native persistent WFP/NRPT protection;
the top-level packet `SessionConfig.KillSwitch` is rejected. Unexpected native
loss retains protection until explicit recovery. Windows owns mobility/rekey,
while a disconnect ends the session without Engine redial. Packet DNS interception and Windows
reconnection described below apply only to the packet backend.

Read `PlatformCapabilities().IKEv2` for native support and limitations.
Native metadata reports `Backend = "ikev2"`, `IPv6 = "system"` and
`StatsUnavailable = true`; `Stats().Unavailable` is true even after Stop.
Do not display zero counters as observed native traffic.

```go
cfg, err := core.LoadConfig("profiles/main.conf")
if err != nil {
    return err
}
engine := core.New(core.Options{})
if err := engine.Start(ctx, cfg); err != nil {
    return err
}
// Start connects asynchronously. Readiness is indicated by
// engine.Status().State == core.Connected or engine.Events().
// ctx must remain alive for the entire session.
return engine.Wait(context.Background())
```

Call `engine.Stop(stopCtx)` to stop explicitly. It cancels startup or the active
session and waits for resources to be released. If `stopCtx` expires, cleanup
continues; a new `Start` is prohibited until cleanup completes. Repeated and
concurrent `Stop` calls are allowed. Once complete, `Start` can be called again
on the same Engine. `Wait` only waits for completion; canceling its context
does not stop the session. Canceling the context passed to `Start` stops the
session like `Stop`.

With `KillSwitch` enabled, a session that fails stays active and keeps its
protection: `Status()` reports `failed` with `KillSwitch == core.KillSwitchHolding`,
and `Wait` does not return until `Stop`, a new `Start` with a kill switch
profile, or `ReconnectNow`, which restarts the initial attempts. A `Start` with
a profile without the kill switch returns `core.ErrKillSwitchHeld`. See
[CONTROL.MD](CONTROL.MD#reconnect-recovery-and-kill-switch-hold).

`core.KeyFile(path)` creates settings for the legacy key-file launch format.
`SessionConfig.Resolve` lets an application supply its own key source.
For a network source, also provide `ResolveOnNetwork` and use the supplied HTTP
transport: system DNS remains on the tunnel during reconnection, and with the
kill switch enabled, protection is already installed when the key is resolved.
A `Resolve` callback that opens its own connections instead of using the
supplied path is blocked by that protection. `core.KeyFile`, `LoadConfig` and
`FromConfig` already use the supplied path. The callback
must honor context cancellation and safely access shared state. Do not modify
settings or callbacks while the session is running.

## States and events

- `disconnected`: the session ended and cleanup succeeded.
- `connecting`: initial startup is in progress.
- `connected`: the transport is verified and the system tunnel configured; in SOCKS mode, the listener is open.
- `reconnecting`: the old session is closing, the next attempt is pending or
  running, or recovery waits between cycles.
- `stopping`: a requested stop is in progress.
- `failed`: the initial attempts are exhausted, or a non-retryable error or
  cleanup failure occurred; details are in `LastError`. With the kill switch
  enabled, the session stays active and holds protection until `Stop`.

An initial connection makes the first attempt plus up to 3 retries. After loss
of an established session, recovery continues in cycles of up to 10 attempts
separated by 60 second waits until success or `Stop`. `ReconnectNow` ends a
pending wait. The full policy is in
[CONTROL.MD](CONTROL.MD#reconnect-recovery-and-kill-switch-hold).

`Status()` returns the state, attempt number, transition time, last error
code, `ErrorStage`, recovery progress (`ReconnectAttempt`, `ReconnectLimit`,
`ReconnectCycle`, `ReconnectPhase`, `NextAttemptAt`), and the kill switch state
(`KillSwitch`). `Events()` is a bounded event queue for one consumer. It lives
as long as the Engine and does not close between starts. A slow consumer may miss events;
the current state is always available through `Status`. Each diagnostic event
code is reported at most once every 5 seconds. Events contain no keys, passwords,
`ssconf` URLs, or addresses of visited sites.

`Stats()` returns a snapshot of counters since the last `Start`: TCP and UDP
flows (total, active, errors), DNS requests and errors, uploaded and downloaded
bytes, and `proxy`/`direct`/`block` routing decisions. Counters reset on every
`Start` and remain readable after the session ends. Snapshots contain no
addresses, keys, or visited resources. Counter methods are safe to call on a nil
pointer, so handlers also work without statistics.

TCP bytes are counted after every successful write, including partial writes,
without waiting for the connection to close. A GUI can calculate speed from
snapshot differences and monotonic time, resetting its baseline for a new
Session.id/instance. These counters measure handler payload, not all traffic on
the network adapter.

`GetBuildInfo()` describes the running core: version, Git revision, modified
build flag, Go version, and architecture. IPC hello/version return this data in
the optional core field. CLI version without -daemon describes the CLI;
with -daemon, it describes the running service/daemon.

`PlatformCapabilities()` returns a static summary of build capabilities
(system VPN, kill switch, IP and domain split routing). Application-based split
routing is not implemented; macOS does not advertise a kill switch until it is
implemented and verified. The CLI prints events to the console. Windows, Linux,
and macOS support `start`, `status`, `watch`, `stats`, `reconnect`, `stop`, and `shutdown`
through a local daemon; `capabilities` runs locally without one:
see [DAEMON.MD](DAEMON.MD) and [LINUX.MD](LINUX.MD).

## DNS metadata for domain rules

System VPN intercepts DNS at `198.18.0.2`. After validating a DNS response, and
before returning it to the application, the core records the original name's
association with A/AAAA records reachable through CNAMEs. Subsequent TCP/UDP
connections receive all valid domains for the IP, and policy applies the first
matching CIDR or domain rule in configuration order. The order of concurrent DNS
responses does not change the decision.

The store is shared across transport generations within a session: reconnect
preserves it, Stop removes it. It holds only domains that can match the active
policy, is limited to 4096 associations, and caps TTL at 24 hours. Domains do not
appear in events, statistics, doctor output, or state files. DoH/DoT, direct IPs,
and old DNS caches have no metadata; see [DNS_METADATA.MD](DNS_METADATA.MD).

## Windows VPN reconnection

The original physical interfaces, gateways, and IP addresses are checked every
5 seconds. Network loss or a path change triggers transport reconnection.
A gap exceeding 30 seconds between checks is treated as wake from sleep (or a
long process suspension) and also refreshes the transport. If another process
removes the adapter, the session fails with `tunnel_adapter_lost`.

Every 30 seconds, TCP/TLS is checked through `https://api.ipify.org` and DNS
through the configured resolvers. Three consecutive failures trigger reconnection.
The check site's own unavailability also counts as a failed check.
Checks use the upstream transport and bind to the original interface.

Recovery sequence:

1. Keep Wintun, the packet stack, routes, and NRPT in place.
2. Close old transport flows. Reject new `proxy` connections; `direct` rules
   use the selected original interface if available.
3. Wait between attempts according to the recovery policy: 1, 2, 4, 8, then
   15 seconds within a cycle of 10 attempts, and 60 seconds between cycles.
4. Detect the interface again and resolve the key, including fetching current `ssconf` data.
5. Check the transport and attach a new flow handler to the same tunnel.

Fetching `ssconf` and resolving the upstream server use a transport bound to the
physical interface. Service DNS queries use that interface's DNS servers; if
the list is empty, they use addresses from the configuration. These queries
bypass the VPN so recovery does not depend on VPN availability. User DNS queries
continue through the upstream transport and may receive `SERVFAIL` during recovery.
Applications with their own DNS retain the existing rule semantics.

A connection that drops again within one minute continues the previous cycle
instead of starting a new one. A network change or a resume from sleep ends a
pending wait early. An initial connection gives up after the first attempt and
3 retries and enters `failed`; permission errors, an occupied adapter name,
conflicting DNS policies, external macOS DNS changes, and Wintun setup errors
fail it at once. After loss of an established session, these failures are
retried in cycles until success or Ctrl+C. Cleanup errors and other codes ending
in `_run_recover` stop further automatic attempts. With the kill switch
enabled, a foreground `bimeron connect` or `bimeron run` whose session fails
keeps running in `failed` and keeps protection installed until Ctrl+C.

Existing TCP/UDP connections close when the transport refreshes. Applications must
reestablish them. During normal reconnection, captured `proxy` traffic does not
receive a direct transport. Routes and DNS are removed only on final shutdown or
failure. Without the kill switch, this does not cover process crashes or
external route removal, and traffic can leave outside the tunnel while
connecting, reconnecting or after a failure. The optional Windows kill switch
is described in [KILLSWITCH.MD](KILLSWITCH.MD). Local networks and more specific routes retain
their existing semantics.

The `.conf` file is loaded once; restart to change settings. The remote
`ssconf` response refreshes on every reconnect. SOCKS mode shares the lifecycle
but not the Windows system-route monitor; the full monitoring and recovery
described above apply to `Mode = vpn`.

## Platform boundaries

- `core/engine.go`: states, concurrent Start/Stop, events, and retry delays.
- `core/runtime.go`: upstream transports, rules, DNS, SOCKS, and availability monitoring.
- `core/platform_windows.go`, `internal/windowsnet`: Windows, Wintun, routes, and NRPT.
- `core/platform_linux.go`, `internal/linuxnet`: Linux TUN, routes, DNS, and nftables.
- `core/platform_darwin.go`, `internal/macnet`: experimental macOS utun, routes, and DNS; no kill switch.
- `core/platform_other.go`: explicitly rejects system VPN on unsupported operating systems.

The platform interface is internal and can evolve as operating systems are added,
while preserving the public session API. A GUI and service can use this API;
the Windows VPN process must still run with administrator privileges.

## Main diagnostic codes

| Code | Meaning |
|---|---|
| `administrator_required` | Run the command from an administrator CMD. |
| `wintun_dll_missing` | `wintun.dll` is missing next to the executable. |
| `session_lock_failed` | Could not acquire the exclusive VPN lock; check for another instance. |
| `adapter_name_in_use` | Another adapter already uses the tunnel name. On Windows, a stale Bimeron Wintun interface left by an unclean exit (killed process, power loss) does not count: the session reuses it under its original GUID and a clean disconnect removes it. |
| `conflicting_dns_policy` | Incompatible NRPT rules were detected. |
| `macos_dns_changed_externally` | Another macOS provider became the effective DNS provider; the session closes and cleans up Bimeron-owned settings. An initial connection fails; an established session retries in recovery cycles. |
| `access_key_resolve_failed` | Could not read or resolve the key/ssconf. |
| `endpoint_dns_failed` | Could not resolve the upstream server address. |
| `network_inspect_failed`, `network_unavailable` | No original network path is available, or network state could not be read. |
| `network_changed`, `resume_detected` | The network changed or the process resumed after a long pause; also ends a pending recovery wait early. |
| `reconnect_attempt`, `reconnect_wait` | Event only. An attempt is scheduled or a cycle starts; a cycle failed and the next one starts after a wait. |
| `reconnect_requested` | Event only. `reconnect_now` ended a wait or restarted a failed session with a held kill switch. |
| `kill_switch_holding`, `kill_switch_held` | Event only. Kill switch protection was installed at the start of a session; the session failed and protection is held until stop. |
| `transport_suspend`, `transport_retry` | Event only. The tunnel is retained while the transport refreshes; `proxy` traffic does not go directly. |
| `tunnel_adapter_lost` | The tunnel adapter disappeared. An established session closes and reopens the tunnel; otherwise the session fails. |
| `transport_check_failed`, `transport_unavailable` | Upstream TCP/TLS or UDP/DNS checks are failing. |
| `hysteria2_invalid_config` | The Hysteria2 profile or fingerprint is invalid. |
| `hysteria2_network_failed` | Server endpoint resolution failed. |
| `hysteria2_network_timeout` | Connection setup timed out. |
| `hysteria2_outbound_socket_failed` | The outbound UDP socket or interface binding failed. |
| `hysteria2_tls_failed` | TLS certificate verification or negotiation failed. |
| `hysteria2_auth_rejected` | The server rejected authentication. |
| `hysteria2_udp_disabled` | The server accepted the connection but disabled UDP relay. |
| `hysteria2_unknown` | Connection setup failed without a safely identifiable cause. |
| `ssh_network_failed` | The SSH server was unreachable: timeout, refused or reset connection, unreachable route, or DNS failure. Retryable. |
| `ssh_connection_failed` | SSH host-key verification, authentication, or transport setup failed. Terminal. Sessions that opt in to accept-new or run profile-only report `ssh_host_key_*` and `ssh_known_hosts_missing` instead (see `docs/android-ssh-auth.md`). |
| `dns_failed` | Event only. An individual DNS query failed; this does not necessarily mean the whole session failed. |
| `network_setup_failed` | Routes or DNS could not be configured; rollback is in progress. |
| `cleanup_failed_run_recover` | Cleanup failed; after stopping, run `dist\windows-amd64\bimeron.exe recover` from an administrator CMD. |

### Hysteria2 error contract for desktop clients

`Status.LastError` and `Event.LastError` contain a stable catalog code from the
table above; codes marked "Event only" appear only in `Event.Code`. `Status.ErrorStage` and `Event.ErrorStage` contain a bounded stage name:
`configuration`, `endpoint_resolution`, `outbound_socket`, `connection`, `tls`,
`authentication`, or `udp_capability`. The event `Code` remains `state` for
state transitions; use `LastError` for the failure category. Both `ErrorStage`
fields are omitted from JSON when empty. `Status()` is authoritative if an
event is dropped. A successful connection clears both error fields.

`hysteria2_network_failed`, `hysteria2_network_timeout`, and
`hysteria2_outbound_socket_failed` are retryable. Invalid configuration, TLS
failure, authentication rejection, disabled UDP relay, and unknown failure are
terminal. The last category is deliberately terminal until evidence identifies
a safe retry condition. Upstream error text, passwords, complete URIs, and
authentication headers must never be included in these fields or messages.

For a real connection failure, record the code, stage, attempt count, selected
fingerprint, outbound interface selection, and server-side result separately.
The code alone cannot establish a server or fingerprint defect.

## Windows validation

Automated tests cover concurrent stops, startup cancellation, resource-release
order, reconnection, sleep, health-check failures, and Windows commands through
stub cmdlets. They do not switch the workstation's network.

Real-adapter checks are performed separately:

1. Run `dist\windows-amd64\bimeron.exe run profiles\main.conf`, wait for `connected`, and check websites.
2. Stop with Ctrl+C; wait for `disconnected` and check normal internet access.
3. Start again, temporarily disconnect the network, and restore it: expect
   `reconnecting`, then `connected`. The adapter and its index must remain
   unchanged; no new `Creating Wintun adapter` messages should appear during
   reconnection. With `Default = proxy`, repeatedly query the external IP:
   request errors are acceptable during recovery; afterward, only the VPN IP
   should appear.
4. If Wi-Fi and Ethernet are available, switch the active network.
5. Put the computer to sleep for more than 30 seconds, wake it, and check recovery.
6. Make the upstream server unreachable for several minutes while connected:
   expect `reconnecting` with cycles of attempts and 60 second waits, then
   `connected` once the server is reachable again. In a daemon session,
   `bimeron reconnect` during a wait starts the next attempt at once.

Passing unit tests does not confirm these checks on a real machine.

## Project scope

This repository is for Bimeron Core only. GUI development belongs in separate
projects for each platform; the integration contract is in
[GUI_INTEGRATION.MD](GUI_INTEGRATION.MD). This scope was reaffirmed on October 6,
2026. NetworkExtension integration is developed here: the external packet
adapter, library API, Go/Swift bridge, Apple extension target, and technical app
bundle with console-based VPN registration and no windows. The GUI remains a
separate project. Console startup of the existing core backend is preserved.
