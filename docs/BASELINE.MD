# Historical validation baseline

The following recorded results provide validation context for the tested builds.
They do not by themselves verify changes made after those tests.

The recorded baseline included project restructuring, statistics, and fixes for
concurrent Start/Stop. It passed go test ./..., go vet ./..., 20 repetitions of
the core tests, and Windows/Linux/macOS amd64/arm64 builds. The race detector was
not run at that stage because GCC was unavailable.

These were automated checks, not a new manual VPN certification. Earlier user
checks on Windows do not replace checking an updated binary.

Before marking a version as manually verified:

1. run: connect a profile, check the IP and browser, stop, and check DNS/IP.
2. daemon: start, wait for connected, send traffic, check stats, and stop.
3. Start again: statistics should reset; changing networks should restore the connection.
4. With KillSwitch=true, forcibly terminate the process; direct access should be blocked.
5. A new launch should restore the VPN; recover after a crash should restore networking.

The user performs real VPN tests. Automated checks at that stage did not connect
the core using the user's key.

On October 6, 2026, the user confirmed that service stop restored the normal IP
and that reconnecting through the service reached connected. Doctor read the
current session and nonzero counters. Crash checks deferred then were performed
on October 8, 2026, and recorded in the service and kill-switch documentation.

## Windows checks deferred on October 6 and completed on October 8, 2026

The user confirmed a successful service update using service update.
The following manual checks were subsequently performed separately:

- Forced termination of the Windows service process: kill-switch persistence,
  automatic service restart by SCM, no automatic VPN connection, and recovery
  through an explicit start command.
- Windows reboot: service startup behavior, network/DNS and kill-switch recovery,
  followed by an explicit VPN connection.

SCM restarted the service without automatically connecting the VPN. The kill
switch and DNS rule persisted, protected direct traffic remained blocked, and
`recover` cleared the state. The same safe recovery was checked after reboot.

## Linux ARM64 check deferred on October 6 and completed on October 8, 2026

The Raspberry Pi 5 check was initially deferred. The final run is described below;
WSL results are recorded separately in [LINUX.MD](LINUX.MD).

The test matrix included:

- Running the ARM64 binary and establishing a real connection with an ss/ssconf key.
- External IP, website access, DNS, and IP/CIDR split routing.
- Normal shutdown with restoration of the original network, followed by reconnection.
- Kill switch after forced termination, relaunch, and `recover`.
- Reconnection after network loss and Ethernet/Wi-Fi changes, with no direct-IP
  leak for traffic that should use the VPN.

Perform the first run on the Pi as a separate client, not on a home gateway or
shared DNS server. Before starting, add the actual local management subnet with
`Action = direct` to retain SSH access, and have a monitor and keyboard available
for local recovery. Test normal connection and shutdown first, then forced
termination with the kill switch. Sleep/wake testing on a conventional Linux
computer remains separate; a Raspberry Pi does not fully replace it.

## Race detector in WSL — October 6, 2026

Ubuntu/WSL2 amd64 ran `CGO_ENABLED=1 go test -race -timeout 5m ./...` with Go
1.26.5 and GCC. All 13 packages with tests passed; no data races were detected.
The official Go archive was used, with its SHA256 checked against go.dev metadata.
The check used no real keys and did not change the working network.
Privileged namespace tests were not included in this run; their earlier results
without `-race` are described in [LINUX.MD](LINUX.MD).
A successful run covers the executed scenarios and does not prove the absence of
races under every possible operating condition.

## Raspberry Pi 5 ARM64 — October 8, 2026

A Raspberry Pi 5 running Debian 12 ARM64 was used to test a real Outline
connection, external IP, DNS, external IP/CIDR split routing, normal shutdown,
reconnection, SIGKILL with the kill switch, relaunch, `recover`, and Ethernet
loss and restoration. No requests succeeded with the original IP while the
network was lost; after recovery, the core reconnected through Outline.
SSH with `192.168.1.0/24 = direct` remained available after the Linux routing fix.
Details and compatibility findings are in [LINUX.MD](LINUX.MD).

After reserving a separate Wi-Fi address, Ethernet → Wi-Fi → Ethernet switching
was also tested with the kill switch active. Both transitions produced only brief
request errors until `connected` returned; the original IP never appeared.
A NetworkManager change to `/etc/resolv.conf` was safely rejected during shutdown
and subsequently accepted using `recover --keep-current-dns`.

Raspberry Pi sleep/wake behavior does not replace suspend testing on a conventional
Linux computer; that test remains deferred.
