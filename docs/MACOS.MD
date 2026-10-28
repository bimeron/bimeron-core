# Bimeron Core for macOS

An experimental CLI backend supports Intel (`amd64`) and Apple Silicon
(`arm64`). Historical cross-builds and static checks passed; route, DNS,
rollback, and recovery logic was tested using simulated system commands.
On a real Mac, ordinary tests, the race detector, static checks, and a native
build passed. Real `utun`, system network-configuration commands, outgoing VPN
socket binding, the root daemon, sleep, network changes, and `recover` were
also checked. These results describe the tested builds.

## Native validation — October 6–7, 2026

macOS 26.5 (25F71), Apple Silicon ARM64, was checked over SSH. Only tracked
source files were transferred, without user profiles or keys.
Go 1.26.5 from the user's toolchain cache and system Clang were used.
`CGO_ENABLED=1 go test -race -timeout 5m ./...` passed for all 13 packages with
tests, along with `go vet ./...` and a native CLI build.
Commands `version`, `capabilities`, and `doctor` were checked.
No data races or errors were found in these scenarios.

The first read-only run did not change the network. In later runs, the user
locally launched privileged commands, the VPN, and the daemon.
SSH testing retained access to the actual local network and a local recovery
method. macOS has no kill switch.

The first manual launch found a service/interface name mismatch:
`scutil` returned `iPhone`, while `networksetup` returned `iPhone USB`.
UUID mapping was fixed: if the service name is not found, the interface's
`UserDefinedName` is checked. Ambiguous matches are rejected.
A regression test and opt-in read-only `TestNativeServiceMapping`
(`BIMERON_MACOS_TEST=1`) were added. The real service-list check, all tests with
`-race`, and `go vet` passed; the CLI was rebuilt on the test Mac.
Connection testing needed to be repeated after that fix.

On October 7, all package race tests, `go vet`, native read-only network-service
inspection, the new `doctor`, and both unsigned NetworkExtension builds passed
again. During an active `utun` session, doctor saw effective tunnel DNS,
three IPv4 capture routes, and two IPv6 routes. Real requests confirmed distinct
external IPs for the VPN and physical interface, HTTP 200 for Google and YouTube,
an A response from tunnel DNS, and no AAAA with `IPv6 = disable`.

The next manual run found lost upstream access after utun routes were added.
During the failure, `route get -ifscope en0 1.1.1.1` found no route, and
`curl --interface en0` immediately failed to connect.
A separate IPv4 default route through the physical gateway with `-ifscope`
was added: bound core sockets can use it, while ordinary traffic remains captured
by utun. An existing scoped default is reused without claiming ownership;
a core-created route is journaled, updated when the physical path changes,
and removed during recovery after checking gateway, interface, and boot ID.
Rollback, preservation of others' routes, interface changes, and repeated cleanup
after removal failure passed alongside native `-race` and `go vet`.
In the subsequent active run, the scoped route was found and
`curl --interface en0` succeeded. Through the core, Google returned HTTP 200
and tunnel DNS `198.18.0.2` resolved Google and example.com.
IP split routing was confirmed: api.ipify.org showed VPN egress, while
checkip.amazonaws.com showed physical egress.
Safe error categories and direct/proxy direction were added to diagnose temporary
network failures without addresses or keys. Repetitive log noise was removed.
Later checks confirmed cleanup of the owned scoped route, sleep, network changes,
and crash recovery; results follow below.

Following a user's report about YouTube in Chrome, the active session and YouTube
access were checked separately: the homepage HTML, an image from i.ytimg.com,
and a public youtubei browse request returned HTTP 200 with nonempty data.
A normal request without forced IPv4 also passed; tunnel DNS returned no AAAA
with `IPv6 = disable`. This did not test video playback or HTTP/3:
the system curl lacks HTTP/3 support. A separate check below confirmed the cause
of the Chrome content error; a QUIC failure was not established.

### Cloudflare WARP DNS conflict

On the test Mac, WARP was connected in `DnsOverTls` mode.
Although `networksetup -getdnsservers Wi-Fi` showed `198.18.0.2`, effective
resolvers in `scutil --dns` remained `127.0.2.2` and `127.0.2.3`.
System DNS returned YouTube AAAA records, bypassing the core's filter despite
`IPv6 = disable`. After the user disabled WARP, YouTube worked in Chrome
without a browser restart, and `scutil --dns` showed `198.18.0.2`.
The exact effect of each returned address was not tested; a conflict between
simultaneously active DNS providers was confirmed.

On October 7, 2026, startup with active WARP DNS was manually checked.
It failed with `macos_dns_changed_externally` before installing IPv4/IPv6
capture routes; effective WARP DNS settings remained unchanged and functional.

The CLI backend fails startup or an active session with
`macos_dns_changed_externally` if another provider becomes the effective system
DNS provider. It removes Bimeron-owned routes and settings; another provider's
DNS is not automatically disabled or overwritten. Before restarting, disable
WARP DNS or the conflicting provider. Inspect effective resolvers with
`scutil --dns`: `networksetup` alone does not prove that the OS uses core DNS.
`doctor` reports `dns_provider_conflict = detected` when network services
are configured for Bimeron DNS but the effective system resolver uses a different
address set. The check does not identify the provider or expose its addresses
in the diagnostic report.

## Startup

From the project directory, for Apple Silicon:

```sh
chmod +x bin/bimeron-macos-arm64
./bin/bimeron-macos-arm64 validate examples/macos.conf
sudo ./bin/bimeron-macos-arm64 run examples/macos.conf
```

For Intel, use `bin/bimeron-macos-amd64`. The example reads the key from
`profiles/test.key`: `File` is resolved relative to the configuration file.
You can replace it with one `SS` or `SSConf` option; all fields are documented
in [CONF.MD](CONF.MD). Ctrl+C disconnects and restores settings.

This macOS version requires `KillSwitch = false`. `true` is rejected with
`kill_switch_unsupported_on_macos` before OS settings change.
System-firewall protection is not implemented. A process crash or reconnection
may allow traffic through the ordinary IP.

## Tunnel, routes, and DNS

The system assigns the interface name `utunN`. `Name = Bimeron` is a logical
label and does not rename utun. The shared TCP/UDP stack and Outline transport
support `ss://`, `ssconf://`, IP/CIDR rules, and multiple DNS servers.

Routes covering both halves of IPv4 and IPv6 address space are installed, along
with a separate route to tunnel DNS `198.18.0.2`.
Core sockets bind to the outgoing interface so Outline connections do not loop
back into utun. Existing local and more specific routes retain OS priority.
Split rules apply to traffic the OS sends into the tunnel.
Outline does not support ICMP/ping. `IPv6 = disable` blocks captured IPv6
traffic and removes AAAA from tunnel DNS responses.

DNS for active network services is temporarily changed using `networksetup`.
Original values and service UUIDs are saved first, so renaming a service does
not prevent recovery. An absence of manual DNS servers is restored using
`Empty`, returning to network-provided DNS. Newly enabled services are monitored
during the session. External DNS changes are not silently overwritten.

After successful transport recovery, Bimeron refreshes `mDNSResponder` once.
This clears macOS's cached "no network" state, which could leave the system
resolver unavailable for several minutes even though tunnel DNS already responds.
Refresh failures are reported as `dns_refresh_failed` without interrupting a
working transport.

The `/var/db/bimeron/state.json` journal is root-only and survives reboot.
On a new launch, the core recovers unfinished changes. The OS boot identifier
prevents removal of routes belonging to another VPN that received the same
interface name and index after reboot.

For manual crash recovery:

```sh
sudo ./bin/bimeron-macos-arm64 recover
```

Keep the recovery binary in a persistent directory, not `/tmp`, which macOS
clears on reboot. Until a launchd service exists, a crash or reboot during an
active session may require manual `recover`. The persistent journal allows
DNS restoration even after OS boot.

If another application changed DNS, ordinary `recover` reports a conflict.
`recover --keep-current-dns` accepts new values for conflicting services while
restoring other Bimeron settings.

## Process control

In the first console:

```sh
sudo ./bin/bimeron-macos-arm64 daemon
```

In the second, as the same user who invoked sudo:

```sh
./bin/bimeron-macos-arm64 start examples/macos.conf
./bin/bimeron-macos-arm64 watch
./bin/bimeron-macos-arm64 status
./bin/bimeron-macos-arm64 stats
./bin/bimeron-macos-arm64 capabilities
./bin/bimeron-macos-arm64 stop
./bin/bimeron-macos-arm64 shutdown
```

`stop` disconnects and keeps the daemon available. `shutdown` disconnects,
then exits the daemon. IPC uses `/var/run/bimeron/control.sock`, mode `0600`,
and client UID checks; root and the user who launched it through sudo have access.
File locks block duplicate daemons and concurrent VPN sessions.
This is a console process: no launchd service, GUI, notarization, or installer is
ready. The separate NetworkExtension integration has an unsigned technical bundle;
signing and actual system startup remain unverified:
see [APPLE_NETWORK_EXTENSION.MD](APPLE_NETWORK_EXTENSION.MD).

## Validation on a Mac

1. Save output from `scutil --dns`, `networksetup -getdnsservers "Wi-Fi"`,
   and `netstat -rn` before startup.
2. Start the profile and wait for `connected`. Check the browser,
   `curl -4 https://api.ipify.org`, TCP, and UDP/DNS. With `IPv6 = disable`,
   verify that captured IPv6 does not go directly.
3. Switch Wi-Fi/Ethernet, disconnect and restore networking, and test sleep/wake.
4. Check Ctrl+C, `stop`/`shutdown`, and reconnection. After stopping, compare
   DNS and routes with the baseline.
5. Check forced termination and `recover`, then recovery after reboot.
   Do not expect internet access to be blocked after a process crash.

Historical Apple Silicon checks covered sleep/wake on both mains power and battery,
plus disabling and reenabling Wi-Fi. The process and `utun` survived, DNS and
routes recovered, and proxy/direct traffic continued working.
Network-parameter changes after DHCP may cause a second brief
`network_changed` cycle; the core rechecks the transport and retains the same
tunnel interface.

The daemon lifecycle was also checked: `start`, `status`, `watch`, `stats`,
`stop`, another `start`, and `shutdown`.
After forced SSH disconnection and after reboot with an active session,
`recover` restored original DNS and removed owned settings; normal internet
access and the physical IP returned.

Domain split routing was checked with `Default = direct`: an IP from a fresh
DNS response matching a domain rule used Outline, while a control domain stayed
direct. A DNS-cache entry created before session startup follows the domain rule
only after a new DNS response through Bimeron.

Build from source on a Mac: `go test ./...`, `go vet ./...`,
`go build -o bin/bimeron ./cmd/bimeron`. Run root tests only on a dedicated
test system.

## IKEv2/IPsec availability

The experimental [native IKEv2 backend](IKEV2.MD) currently targets Windows only.
This platform's packet VPN support does not imply native IKEv2 support. Native
system profiles are rejected on this platform; no embedded IPsec fallback is provided.
