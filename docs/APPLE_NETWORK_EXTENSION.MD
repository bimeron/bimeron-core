# Integrating Apple NetworkExtension with the core

This guide covers the core, the Go/C ABI, the Swift packet provider, and a
technical console shell. There is no GUI. Work that requires a paid Apple
Developer Program team is described in
[separate technical specifications](APPLE_PAID_DEVELOPER_SPEC.MD).

The existing `bimeron run` command uses its own utun backend and cannot run
alongside a system NetworkExtension session.

## What is implemented

- `core.NewPacketEngine`: gVisor receives IP packets from the external host
  instead of a TUN device. IPv4/IPv6, upstream transports, DNS, IP/CIDR policies,
  status, statistics, and reconnection use the shared core. This backend runs no
  system network commands.
- `core.LoadConfigData`: loads the configuration from memory. The `File` source
  is rejected in this API; the Apple console shell resolves it relative to the
  `.conf` file first.
- `cmd/bimeron-apple`: a C archive with copied buffers and numeric handles.
- `apple/PacketTunnel`: a Swift `NEPacketTunnelProvider` that handles
  `packetFlow`, applies IPv4/IPv6/DNS settings through Apple APIs, observes path
  changes, and stops the core.
- `apple/Control`: a windowless executable inside the app bundle that manages
  extension registration and the NetworkExtension session through Apple APIs. The
  configuration, including the key, is stored in the Data Protection Keychain;
  VPN preferences hold only a random profile ID.

`IPv6 = disable` keeps IPv6 capture and blocks IPv6 in the core, filtering AAAA
answers. `KillSwitch = true` is rejected: NetworkExtension protection is not
implemented, and the core must not silently weaken the profile. Do not treat a
NetworkExtension kill switch as available until it is implemented and verified.
External DNS providers, including WARP, need a separate compatibility check.

Experimental WireGuard and AmneziaWG profiles must use explicit
`Type = wireguard` parameters: the console shell inlines `File` only as a
one-line `Key`, so multi-line WireGuard text is refused at install. The
WireGuard UDP socket is a regular provider-originated socket like other
upstream sockets. `RLCapabilities()` lists `wireguard` in `explicit_access`
but does not include the `wireguard` capability object. WireGuard builds and
passes unit tests on Apple platforms but has not been validated live. See
[WIREGUARD.MD](WIREGUARD.MD).

## Packaging formats

By default, `scripts/build-apple.sh` builds a macOS **system extension** in
`Contents/Library/SystemExtensions`, the NetworkExtension format for direct
distribution. `APPLE_EXTENSION_KIND=app-extension` builds an `.appex` in
`Contents/PlugIns` for development and the App Store.

Apple documents the supported distribution options in
[TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)
and the
[NetworkExtension entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension).
A Development certificate is not enough for direct distribution: releasing a
system extension requires a Developer ID, a matching provisioning profile, and
notarization. None of these steps is automated.

A system extension runs outside the user context, so it cannot read the user's
Data Protection Keychain. The console shell's `start` command therefore passes
the configuration through `NETunnelProviderSession.startTunnel(options:)`.
Starting the system extension automatically after a reboot or crash without an
explicit `start` is not supported, because no secret is stored in the root
context. That is a separate open task, and it is no reason to store the key in
VPN preferences. An app extension can read the user's shared Keychain access
group; see [TN3137: On Mac keychain APIs and implementations](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains).

## Building on a Mac

Requirements: macOS, Go 1.26.11 or newer, Xcode, and Python 3. The build targets
macOS 13.0 or later and was tested with the macOS 15.5 SDK and Xcode 16.4. To
build and run the C ABI smoke test without installing the extension:

```sh
sh scripts/build-apple.sh
APPLE_EXTENSION_KIND=app-extension sh scripts/build-apple.sh
```

The default target is the host architecture. Set `APPLE_ARCH=arm64` or
`APPLE_ARCH=amd64` to cross-build with the installed macOS SDK. Go, Swift, and
the C ABI test are compiled and linked for that target, but the C ABI test runs
only when the target matches the host architecture; cross-built binaries still
need validation on a native machine.

CI uses `macos-15-intel` because hosted ARM64 jobs were repeatedly cancelled
before acquiring a runner. It builds both extension variants for Intel and
ARM64, runs the C ABI test natively on Intel, and verifies ARM64 linkage. Native
ARM64 runtime validation remains a separate requirement.

The system extension build is written to
`dist/apple-system-extension-<arch>/BimeronCore.app`, with `LICENSE`,
`THIRD_PARTY_NOTICES.txt`, and, for unsigned builds, `UNSIGNED.txt`. To sign,
set `TEAM_ID`, `BUNDLE_ID`, `SIGN_IDENTITY`, `HOST_PROFILE`, and
`EXTENSION_PROFILE`. The default bundle ID is `com.noob-rp.bimeron` and the
provider ID is `com.noob-rp.bimeron.packet`; choose your own IDs when preparing
provisioning profiles.

```sh
TEAM_ID=YOUR_TEAM BUNDLE_ID=your.bundle.core \
SIGN_IDENTITY='YOUR_SIGNING_IDENTITY' \
HOST_PROFILE=/absolute/host.provisionprofile \
EXTENSION_PROFILE=/absolute/provider.provisionprofile \
sh scripts/build-apple.sh
```

The profiles must allow both App IDs, the required NetworkExtension type, the
Keychain access group for the host (and the provider for `.appex`), and
`com.apple.developer.system-extension.install` for the system extension host.
The script checks the Team ID, App ID, expiration date, required entitlements,
and bundle signature. The test Mac must be registered in the development profile
and the certificate must match the profile; an actual launch still requires
verification on macOS.

An unsigned build is suitable for compilation and ABI checks only; do not treat
it as an installed or running system VPN. The script does not disable SIP or
change Mac security settings.

## Console shell commands

After signing, install the system extension bundle as
`/Applications/BimeronCore.app`. Run the commands as a regular user, without
`sudo`; macOS requests system permissions itself:

```sh
/Applications/BimeronCore.app/Contents/MacOS/BimeronControl version
/Applications/BimeronCore.app/Contents/MacOS/BimeronControl activate
/Applications/BimeronCore.app/Contents/MacOS/BimeronControl install /absolute/profile.conf
/Applications/BimeronCore.app/Contents/MacOS/BimeronControl start
/Applications/BimeronCore.app/Contents/MacOS/BimeronControl status
/Applications/BimeronCore.app/Contents/MacOS/BimeronControl events
/Applications/BimeronCore.app/Contents/MacOS/BimeronControl stop
/Applications/BimeronCore.app/Contents/MacOS/BimeronControl remove
/Applications/BimeronCore.app/Contents/MacOS/BimeronControl deactivate
```

- `activate` and `deactivate` apply only to the system extension; macOS may ask
  for confirmation in Privacy & Security or for a reboot.
- `install` imports one profile without connecting and requires a disconnected
  session.
- `start` and `stop` report that the request was accepted; use `status` for the
  actual state.
- `status` prints the numeric `NEVPNStatus` and JSON with the core status,
  statistics, and the same optional `status.Session.server_tcp`/`server_udp` and
  `server_tcp_name`/`server_udp_name` fields as the local daemon.
- `events` returns up to eight events per request, best effort.
- `remove` deletes the configuration and Keychain item only while the VPN is
  disconnected.

Do not run a second utun VPN in parallel, and do not change the system session's
profile while it is connecting. For the first run, keep local access to the Mac
and a way to stop the VPN, and review system permission prompts locally.

## ABI and package contract

The generated `libBimeronCore.h` is the source of the exact C declarations.

| Function | Contract |
| --- | --- |
| `RLCreate(data, size)` | Synchronously validates the inline `.conf` and copies it into Go. Returns a handle, or 0 on failure. Does not configure the network. |
| `RLCreateWithGeoData(...)` | `RLCreate` with GeoIP/GeoSite dataset bytes; see [GEODATA.MD](GEODATA.MD). |
| `RLStart(handle)` | Starts asynchronously. 0 means the request was accepted; readiness is status `connected`. |
| `RLWritePacket(handle, data, size)` | Copies a raw IP packet. 0: accepted; -1: error or not ready. |
| `RLReadPacket(handle, out, capacity, timeout_ms)` | Buffer of 65535–65536 bytes, timeout of 1–1000 ms. >0: packet length; 0: timeout; -1: closed or error. |
| `RLStatus(handle)` | Allocated UTF-8 JSON with status and statistics. |
| `RLEvents(handle)` | Allocated JSON array of up to eight events, removed from the queue. |
| `RLSettings(handle)` | Allocated JSON with the MTU and IPv6-disable intents. |
| `RLNetworkChanged(handle)` | Signals an external path change and triggers reconnection. |
| `RLStop(handle)` | Closes the port and waits up to 60 seconds for Stop. 0: completed and handle released; -1: timeout or error, handle kept so cleanup can be retried. |
| `RLVersion()` | Allocated JSON with the Go core version. |
| `RLCapabilities()` | Allocated JSON with the packet engine's capabilities. |
| `RLValidateConfigWithGeoData(...)`, `RLGeoDataGroups(...)` | Validation and GeoIP/GeoSite group listing; see [GEODATA.MD](GEODATA.MD). |
| `RLErrorCatalog()` | Allocated JSON error catalog; see [ERRORS.MD](ERRORS.MD). |
| `RLFree(pointer)` | Frees returned JSON strings; never use it on caller-owned buffers. |

Packets carry no Ethernet or utun family header. The IP version is taken from the
first byte; Swift passes `AF_INET` or `AF_INET6` to `packetFlow.writePackets`.
No Go pointers cross the ABI: inputs are copied, and outputs are written to
C/Swift memory. The egress queue holds up to 256 packets and drops packets on
overflow instead of growing without bound. Close cancels a pending read. One
engine/port and handle pair serves one session, including reconnects; create a
new pair for the next Start after Stop.

In Go, `PacketOptions.Outbound` must provide a dialer whose traffic does not
return into the captured tunnel. The Apple bridge uses regular provider-originated
sockets; whether NetworkExtension actually excludes these Go sockets from its
routes must be confirmed on the first signed launch. Compilation alone does not
prove it.

## Verification status

On October 6, 2026, signing prerequisites were checked over SSH. The local Xcode
cache showed only a free Personal Team with a Development certificate and no
suitable host or provider provisioning profiles. This was cached local data;
verify current team membership in the Apple Developer account or after
refreshing the account in Xcode. A Personal Team cannot sign a NetworkExtension
launch; that needs an Apple Developer Program team with the required
capabilities. No passwords or tokens were read. See
[supported macOS capabilities](https://developer.apple.com/help/account/reference/supported-capabilities-macos)
and the [signing workflow](https://help.apple.com/xcode/mac/current/en.lproj/dev60b6fbbc7.html).

On October 7, 2026, on an ARM64 Mac, both unsigned variants were rebuilt and
passed the extended C ABI test (without real keys or network connections), the
Go tests with the race detector, `go vet`, and native read-only checks of network
services. All Go tests and vet also passed on Windows. Packet TCP SYN/ACK was
verified for IPv4 and IPv6, closing unblocks Read, and the sandboxed
configuration loader rejects `File` without reading the file.

Still open: provisioning and signing, OS permission and activation, the VPN
preferences entry, Keychain access, real traffic through `packetFlow` and
provider socket exclusion, split routing and DNS, network changes and sleep,
start/stop/restart errors in the real NetworkExtension lifecycle, DNS conflict
detection, persistent system extension restart, and a kill switch. iOS builds
and iOS memory-limit checks have not been done.
