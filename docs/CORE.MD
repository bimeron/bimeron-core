# Bimeron Core

The `bimeron/core` package manages a VPN or SOCKS5 session. The CLI uses the same
package available to a GUI. System VPN is implemented for Windows and Linux;
the macOS CLI backend is experimental. The external packet backend for
NetworkExtension is described in [APPLE_NETWORK_EXTENSION.MD](APPLE_NETWORK_EXTENSION.MD).

## Using the Go API

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
does not stop the session.

`core.KeyFile(path)` creates settings for the legacy key-file launch format.
`SessionConfig.Resolve` lets an application supply its own key source.
For a network source, also provide `ResolveOnNetwork` and use the supplied HTTP
transport: system DNS remains on the tunnel during reconnection. The callback
must honor context cancellation and safely access shared state. Do not modify
settings or callbacks while the session is running.

## States and events

- `disconnected`: the session ended and cleanup succeeded.
- `connecting`: initial startup is in progress.
- `connected`: the transport is verified and the system tunnel configured; in SOCKS mode, the listener is open.
- `reconnecting`: the old session is closing or the next attempt is pending.
- `stopping`: a requested stop is in progress.
- `failed`: a non-retryable error or cleanup failure; details are in `LastError`.

`Status()` returns the state, attempt number, transition time, and last error
code. `Events()` is a bounded event queue for one consumer. It lives as long as
the Engine and does not close between starts. A slow consumer may miss events;
the current state is always available through `Status`. Identical diagnostic
messages are limited to one every 5 seconds. Events contain no keys, passwords,
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
and macOS support `start`, `status`, `watch`, `stats`, `capabilities`,
`stop`, and `shutdown` through a local daemon:
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
Checks use Outline and bind to the original interface.

Recovery sequence:

1. Keep Wintun, the packet stack, routes, and NRPT in place.
2. Close old transport flows. Reject new `proxy` connections; `direct` rules
   use the selected original interface if available.
3. Wait 1, 2, 4, 8, 16, then at most 30 seconds between attempts.
4. Detect the interface again and resolve the key, including fetching current `ssconf` data.
5. Check the transport and attach a new flow handler to the same tunnel.

Fetching `ssconf` and resolving the Outline server use a transport bound to the
physical interface. Service DNS queries use that interface's DNS servers; if
the list is empty, they use addresses from the configuration. These queries
bypass the VPN so recovery does not depend on VPN availability. User DNS queries
continue through Outline and may receive `SERVFAIL` during recovery.
Applications with their own DNS retain the existing rule semantics.

After one minute of stable operation, the delay resets. Without a network, startup
remains in `reconnecting` until connectivity returns or Ctrl+C is pressed.
Permission errors, an occupied adapter name, conflicting DNS policies, external
macOS DNS changes, and Wintun setup errors end the session with `failed`.
Cleanup errors stop further automatic attempts.

Existing TCP/UDP connections close when the transport refreshes. Applications must
reestablish them. During normal reconnection, captured `proxy` traffic does not
receive a direct transport. Routes and DNS are removed only on final shutdown or
failure. Without additional protection, this does not cover process crashes or
external route removal. The optional Windows kill switch is described in
[KILLSWITCH.MD](KILLSWITCH.MD). Local networks and more specific routes retain
their existing semantics.

The `.conf` file is loaded once; restart to change settings. The remote
`ssconf` response refreshes on every reconnect. SOCKS mode shares the lifecycle
but not the Windows system-route monitor; the full monitoring and recovery
described above apply to `Mode = vpn`.

## Platform boundaries

- `core/engine.go`: states, concurrent Start/Stop, events, and retry delays.
- `core/runtime.go`: Outline, rules, DNS, SOCKS, and availability monitoring.
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
| `adapter_name_in_use` | The adapter name is already in use. |
| `conflicting_dns_policy` | Incompatible NRPT rules were detected. |
| `macos_dns_changed_externally` | Another macOS provider became the effective DNS provider; the session exits and cleans up Bimeron-owned settings. |
| `access_key_resolve_failed` | Could not read or resolve the key/ssconf. |
| `endpoint_dns_failed` | Could not resolve the Outline server address. |
| `network_inspect_failed`, `network_unavailable` | No original network path is available, or network state could not be read. |
| `network_changed`, `resume_detected` | The network changed or the process resumed after a long pause. |
| `transport_suspend`, `transport_retry` | The tunnel is retained while the transport refreshes; `proxy` traffic does not go directly. |
| `tunnel_adapter_lost` | The tunnel adapter disappeared; the session failed. |
| `transport_check_failed`, `transport_unavailable` | Outline TCP/TLS or DNS checks are failing. |
| `tcp_dial_failed`, `tcp_read_failed`, `dns_failed` | An individual flow failed; this does not necessarily mean the whole session failed. |
| `network_setup_failed` | Routes or DNS could not be configured; rollback is in progress. |
| `cleanup_failed_run_recover` | Cleanup failed; after stopping, run `dist\windows-amd64\bimeron.exe recover` from an administrator CMD. |

Messages for `tcp_dial_failed` and `tcp_read_failed` include the `direct` or
`proxy` direction and a safe cause category, such as
`(direct: connection refused)` or `(proxy: timeout)`. An unrecognized cause is
reported as `unknown`. Raw network errors, destination addresses, and keys are
not included.

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

Passing unit tests does not confirm these checks on a real machine.

## Project scope

This repository is for Bimeron Core only. GUI development belongs in separate
projects for each platform; the integration contract is in
[GUI_INTEGRATION.MD](GUI_INTEGRATION.MD). This scope was reaffirmed on October 6,
2026. NetworkExtension integration is developed here: the external packet
adapter, library API, Go/Swift bridge, Apple extension target, and technical app
bundle with console-based VPN registration and no windows. The GUI remains a
separate project. Console startup of the existing core backend is preserved.

