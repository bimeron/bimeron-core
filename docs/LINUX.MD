# Bimeron Core on Linux and WSL2

Implemented features include system TUN for TCP/UDP IPv4/IPv6, IP/CIDR split
routing, multiple DNS servers, ss/ssconf, reconnection while retaining the adapter,
an nftables kill switch, crash recovery, and local daemon control.
The `.conf` format is the same as on Windows: see [CONF.MD](CONF.MD).

## Requirements and startup

Requirements: Linux with `/dev/net/tun`, root privileges, and `iproute2`.
`KillSwitch = true` requires nftables 1.0+. A physical IPv4 default route in
the `main` table is used. Interface names may contain at most 15 ASCII
characters; the default `Bimeron` fits. Build the appropriate binary as
`bin/bimeron-linux-amd64` or `bin/bimeron-linux-arm64`.
Building from source requires the Go version specified in `go.mod`.

In Ubuntu/WSL2, run from the project directory:

```sh
sudo apt update
sudo apt install iproute2 nftables
sudo ./bin/bimeron-linux-amd64 run profiles/main.conf
```

Ctrl+C or SIGTERM stops the session and cleans up settings.
The legacy `connect profiles/test.key` format is also supported.
Linux does not need the Windows binary or Wintun DLL.
On ARM64, use `bimeron-linux-arm64`.

To control the core from another console, first run:

```sh
sudo ./bin/bimeron-linux-amd64 daemon
```

Then, as the same user who invoked `sudo`:

```sh
./bin/bimeron-linux-amd64 start profiles/main.conf
./bin/bimeron-linux-amd64 status
./bin/bimeron-linux-amd64 watch
./bin/bimeron-linux-amd64 stats
./bin/bimeron-linux-amd64 capabilities
./bin/bimeron-linux-amd64 stop
./bin/bimeron-linux-amd64 shutdown
```

`start` accepts the request asynchronously: wait for `connected`.
`stop` disconnects the VPN but keeps the daemon running; `shutdown`
disconnects and exits the daemon. `watch` does not affect the session.
If the daemon was launched directly by root without `sudo`, control commands
also require root.

For a persistent systemd service, install the same binary on behalf of the user
who should control it:

```sh
sudo ./bin/bimeron-linux-amd64 service install -automatic
sudo ./bin/bimeron-linux-amd64 service start
./bin/bimeron-linux-amd64 service status
```

`sudo` passes `SUDO_UID`; a GUI explicitly passes the UID with `-owner`.
The service runs as root, but its `0600` socket belongs to the specified user
and additionally checks the client's UID. `-automatic` enables the unit at boot
without automatically connecting the VPN. Update and uninstall with:

```sh
sudo ./bin/bimeron-linux-amd64 service update
sudo ./bin/bimeron-linux-amd64 service stop
sudo ./bin/bimeron-linux-amd64 service uninstall
```

## Routes, split routing, and protection

Main OS routes are not replaced. Separate table `51892` sends locally generated
traffic into TUN. Rules with priorities `10900..10902` and protocol `242`
belong to Bimeron. Occupied priorities/tables are rejected; earlier user routing
rules are also rejected to prevent bypass.
Core sockets receive `SO_MARK = 0x524c` and bind to the physical interface,
allowing ssconf fetching, Outline connections, and `direct` traffic without
looping back into TUN. Incoming TUN replies support strict `rp_filter`.
Do not use this mark for other applications' sockets.

All local TCP/UDP except loopback and the machine's own addresses enters the
shared policy handler. Local networks also follow IP/CIDR rules: add their ranges
with `Action = direct` for direct access. Domain split routing uses DNS metadata;
see [DNS_METADATA.MD](DNS_METADATA.MD). Process-based split routing is not
implemented. Outline does not carry ICMP/ping.

During reconnection, the adapter, routes, and DNS remain in place.
Old transport flows close; new `proxy` connections fail until recovery, while
`direct` uses the physical network. Check intervals and backoff are shared with
Windows: see [CORE.MD](CORE.MD).

With `KillSwitch = true`, a separate `inet bimeron_core` table blocks traffic
outside the tunnel according to the first matching CIDR rule.
`direct` is allowed; `proxy` and `block` are denied outside the tunnel;
the default applies after rules. With `IPv6 = disable`, user IPv6 traffic is
blocked. Loopback, marked core sockets, TUN itself, DHCP, and IPv6 ND control
traffic are allowed. Root processes do not receive a blanket exemption.
Other firewall tables are not cleared; their restrictions may additionally block
connections allowed by Bimeron.

Protection covers local outgoing traffic. Forwarded container/router traffic is
not tunneled; with the kill switch it is blocked in FORWARD, and without it,
normal routing applies. This is not a VPN gateway for other machines.

nftables rules survive SIGKILL. Restarting with the kill switch enabled retains
protection during preparation and replaces it atomically. Starting with the kill
switch disabled while protection remains requires explicit `recover`.
Protection does not survive Linux reboot: these nftables rules are not persisted
to disk. Root can change firewall rules/marks; this does not protect against an
administrator.

## DNS and recovery

If the OS uses systemd-resolved through its stub/uplink resolv.conf, DNS is
configured only on the new TUN through `resolvectl`, with routing domain `~.`.
Shutdown performs `revert` on that interface. Other interfaces' DNS is not
rewritten. Otherwise, the original contents of the file targeted by
`/etc/resolv.conf` are saved, then DNS is set to `198.18.0.2`.
The shared core handles multiple upstream DNS servers from `.conf` through Outline.

The recovery journal is `/run/bimeron/state.json`, accessible only to root and
containing no keys. After a crash, TUN disappears automatically, but DNS, policy
rules, and the kill switch require recovery:

```sh
sudo ./bin/bimeron-linux-amd64 recover
```

The command cannot run while another VPN session owns the lock.
If an external manager changed resolv.conf, Bimeron reports it, preserves the new
file, and leaves protection active. To explicitly accept current DNS and finish cleanup:

```sh
sudo ./bin/bimeron-linux-amd64 recover --keep-current-dns
```

The daemon uses `/run/bimeron/control.sock` with mode `0600`, Linux peer
credential checks, and ownership from `SUDO_UID`. Root also has access.
flock locks `daemon.lock` and `vpn.lock` prohibit a second daemon and second
VPN session respectively. Ordinary network changes do not change these locks.

## WSL2 validation

After `connected`, use Linux `curl`, not `curl.exe`, in another WSL console:

```sh
curl --noproxy '*' --max-time 15 https://api.ipify.org
curl -4 -I --noproxy '*' --max-time 15 https://www.google.com
```

Check shutdown, restart, then SIGKILL (using `sudo kill -KILL PID`) with
`Default = proxy` and the kill switch: after the crash, IP queries must fail;
after restarting, they must again show the Outline IP; after `recover`, normal
access must return. `direct` ranges remain accessible even after a crash.
Run the SIGKILL test only after a successful connection.

WSL2 has its own network and depends on NAT/mirrored mode, DNS tunneling, and
Windows firewall. The Linux VPN does not enable VPN for the Windows browser.
Some configurations share resolv.conf across WSL distributions. A Windows VPN
may also affect WSL's outgoing traffic; use a known baseline network for Linux
testing. See [Microsoft WSL networking](https://learn.microsoft.com/en-us/windows/wsl/networking).
Sleep, physical-network changes, and DNS-manager integration also require checks
on conventional Linux.

## Historical automated validation

Portable core, Unix-socket IPC, and settings-recovery tests passed in WSL2.
Separate network namespaces tested exclusive TUN, real IPv4/IPv6 policy rules
and SO_MARK, HTTP through TUN with IPv4/IPv6 and strict rp_filter, nftables
installation and atomic replacement, blocking after TUN disappears, core and
direct exceptions, DNS restoration, and removal of owned rules.
These tests use no real keys and do not change the working WSL network.

On October 6, 2026, Ubuntu/WSL2 amd64 with kernel
`6.18.40.1-microsoft-standard-WSL2` passed all 13 packages with tests,
`TestNativeNetworkConfigureRecover`, `TestLinuxTUNHTTP`, and
`TestLinuxDaemonBinary`. The last test starts a separate daemon process,
checks rejection of duplicate startup, and exercises `stop`, `status`, and
`shutdown`. No failures were found.

Test binaries were cross-compiled on Windows for Linux and run inside WSL.
Firewall tests used nftables 1.0.9 from locally extracted Ubuntu packages;
the system firewall was unchanged. The race detector was not run in this pass:
Linux Go was unavailable, and Windows builds with `-race` do not support this
cross-compilation method. ARM64 validation at that point covered compilation
only; the later Raspberry Pi 5 run is described below.

Later on October 6, 2026, `CGO_ENABLED=1 go test -race -timeout 5m ./...` ran
directly in WSL with Linux Go 1.26.5 and GCC. All 13 packages with tests passed;
no data races were found. These were ordinary race-detector tests; the privileged
namespace tests above ran separately without `-race`.

On Linux with Go and the required dependencies installed:

```sh
sh scripts/test-linux.sh
```

Real connection, Ethernet loss, and Ethernet/Wi-Fi switching were checked on the
Raspberry Pi as described below. These results describe the tested builds.

## Raspberry Pi 5 ARM64 validation — October 8, 2026

A Linux ARM64 binary was checked on Raspberry Pi 5 with Debian 12 ARM64 and kernel
`6.12.34+rpt-rpi-2712`. A real Outline connection changed the external IP and
DNS worked through the tunnel. The `192.168.1.0/24 = direct` rule preserved
Ethernet SSH access, while external `1.1.1.1/32 = direct` simultaneously showed
the original IP as other external traffic used Outline. Normal shutdown restored
the original IP and DNS and cleared policy rules, the route table, journal, and
nftables; reconnecting also passed.

The first run found that CIDR `direct` applied only after traffic entered TUN,
causing replies to incoming SSH connections to stall. The fix adds `throw`
routes for direct CIDRs to table `51892`, allowing the kernel to continue
looking in the main table before TUN. The repeat run retained SSH after
`connected`; route installation and removal are covered by a test.

The kill switch was tested after SIGKILL: the process exited, protected external
traffic was blocked, SSH in the direct subnet remained accessible, and nftables
and the recovery journal persisted. An nftables 1.0.6 incompatibility was found:
the table-owner comment appears in text output but not JSON. An exact text
fallback was added; afterward, `recover`, restart from the protected state,
and subsequent normal cleanup passed.

Losing Ethernet for 10 seconds through NetworkManager moved the core to
`network_unavailable`. Requests failed during the outage without exposing the
original IP; when `eth0` returned, the core automatically reached `connected`,
and successful requests again showed only the Outline IP.
The network was clean after the final stop. Temperatures during runs were
37.8–46.1 °C; the throttling flag remained `0x0` after cooling was installed.

After reserving `192.168.1.109` for the `wlan0` MAC address, Ethernet → Wi-Fi →
Ethernet switching was checked separately with the kill switch active.
Both transitions reported `network_changed`, kept the tunnel installed,
blocked traffic during recovery, and returned to `connected` within 2–3 seconds.
Sampled requests showed only brief errors and the Outline IP, never the original
IP. SSH over Wi-Fi remained accessible.

NetworkManager changed `/etc/resolv.conf` on the return transition, so normal
shutdown correctly refused to overwrite external DNS and left the kill switch
active. Explicit `recover --keep-current-dns` accepted current DNS and cleared
the journal, routes, and nftables. This confirms the documented safe DNS-conflict
behavior. Sleep/wake testing on a Linux computer supporting suspend remains deferred.

## IKEv2/IPsec availability

The experimental [native IKEv2 backend](IKEV2.MD) currently targets Windows only.
This platform's packet VPN support does not imply native IKEv2 support. Native
system profiles are rejected on this platform; no embedded IPsec fallback is provided.
