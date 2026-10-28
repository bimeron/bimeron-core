# Integrating Apple NetworkExtension into core

Work that requires a paid Apple Developer Program team is described in
[separate technical specifications](APPLE_PAID_DEVELOPER_SPEC.MD).

Here are the core, Go/C ABI, Swift packet provider and technical console
shell. There is no GUI. The existing `bimeron run` command uses its own utun
backend and cannot run alongside a system NetworkExtension session.

## What is implemented

- `core.NewPacketEngine`: gVisor receives IP packets from external host instead of TUN.
  IPv4/IPv6, Outline, DNS, IP/CIDR policies, status, statistics, and reconnection
  use the shared core. This backend does not run system network commands.
- `core.LoadConfigData`: configuration from memory. Source `File` in this API
  is prohibited; the Apple console shell first resolves it relative to `.conf`.
- `cmd/bimeron-apple`: C archive with copying buffers and numeric handles.
- `apple/PacketTunnel`: Swift `NEPacketTunnelProvider`, `packetFlow`, settings
IPv4/IPv6/DNS via Apple API, observing path changes and stopping core.
- `apple/Control`: executable inside app bundle, no windows. Manages registration
and NE session via Apple API. The configuration with the key is stored in Data Protection
Keychain; Only a random profile ID is stored in VPN preferences.

`IPv6 = disable` retains IPv6 capture and IPv6 blocking in core, with filtering
AAAA. `KillSwitch = true` is rejected for now: NE protection has not yet been
implemented and must not silently weaken the profile. Do not consider the NE kill
switch available until it has been implemented and verified separately. External
DNS providers (including WARP) require a compatibility check.

## Packaging formats

By default, `scripts/build-apple.sh` creates macOS **system extension** in
`Contents/Library/SystemExtensions`. This is the macOS NetworkExtension format for direct distribution. `APPLE_EXTENSION_KIND=app-extension` creates `.appex`
in `Contents/PlugIns` for development/App Store.

Apple distinguishes between supported distribution options:
[TN3134](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment),
[NetworkExtension entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension).
Having a Development certificate does not mean readiness for direct distribution:
To release a system extension, you need a Developer ID, a suitable profile and notarization.
These procedures are not performed automatically.

System extension runs outside the user context, so it doesn't read
custom Data Protection Keychain. When `start` console shell
sends the configuration via `NETunnelProviderSession.startTunnel(options:)`.
Automatic launch of system extension after reboot/crash without explicit
`start` is not supported: there is no secret stored in the root context. This is a separate
An open task, there is no reason to write down the key in VPN preferences.
The App extension can read the user's shared Keychain access group.
[Keychain contexts: TN3137](https://developer.apple.com/documentation/technotes/tn3137-on-mac-keychains).

## Build on Mac

Requires macOS, Go 1.26+, Xcode, Python 3. Tested SDK - macOS 15.5, Xcode 16.4.
Assembly and C ABI smoke test, without installing the extension:

```sh
sh scripts/build-apple.sh
APPLE_EXTENSION_KIND=app-extension sh scripts/build-apple.sh
```

The default target is the host architecture. Set `APPLE_ARCH=arm64` or
`APPLE_ARCH=amd64` to cross-build using the installed macOS SDK. Go, Swift,
and the C ABI test are compiled and linked for that target. The C ABI test
executes only when the target matches the host architecture; cross-built
binaries still require validation on a native target machine.

CI uses `macos-15-intel` because hosted ARM64 jobs were repeatedly cancelled
before acquiring a runner. It builds both extension variants for Intel and
ARM64, executes the C ABI test natively on Intel, and verifies ARM64 linkage.
Native ARM64 runtime validation remains a separate requirement.

The native system extension build appears in
`dist/apple-system-extension-<arch>/BimeronCore.app`, with `LICENSE`,
`THIRD_PARTY_NOTICES.txt`, and `UNSIGNED.txt` when it is unsigned.
For signature, set `TEAM_ID`, `BUNDLE_ID`, `SIGN_IDENTITY`, `HOST_PROFILE`
and `EXTENSION_PROFILE`. By default bundle ID is `org.bimeron.core.dev`,
provider - `org.bimeron.core.dev.packet`; when preparing profiles you can
select your IDs.

```sh
TEAM_ID=YOUR_TEAM BUNDLE_ID=your.bundle.core \
SIGN_IDENTITY='YOUR_SIGNING_IDENTITY' \
HOST_PROFILE=/absolute/host.provisionprofile \
EXTENSION_PROFILE=/absolute/provider.provisionprofile \
sh scripts/build-apple.sh
```

Profiles must allow both specific App IDs, the desired NetworkExtension type,
Keychain access group host (also provider for `.appex`) and
`com.apple.developer.system-extension.install` for system-extension host.
The script checks Team ID, App ID, term, required entitlement and bundle signature.
Registering a test Mac in a development profile and matching the certificate
profile are also required; actual launch still requires macOS verification.

An unsigned assembly is suitable for compilation/ABI checking; it can't be counted
installed or running system VPN. The script does not disable SIP and does not change
Mac security settings.

## Technical shell commands

After a valid signature, the system-extension bundle must be installed in
`/Applications/BimeronCore.app`. The commands below are executed by the user,
without `sudo` (system permissions are requested by macOS):

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

`activate`/`deactivate` are only applicable to system extension; may be needed
confirmation in Privacy & Security or reboot at the discretion of the OS. `install`
imports one profile, does not connect and requires a disconnected session.
`start`/`stop` report an accepted request: for the actual status, see
`status`. Numeric status - `NEVPNStatus`; JSON contains status, statistics
core and the same optional `status.Session.server_tcp/server_udp` with the original ones
`server_tcp_name/server_udp_name`, which is the local daemon. `events` takes up to
eight events per request, best effort.
`remove` deletes the configuration and Keychain item only when the VPN is disabled.

Do not run a second own utun VPN in parallel. Don't change profile
system session during connection. For the first run, keep local
Mac access and how to stop; Check system permission requests locally.

## ABI and package contract

The generated `libBimeronCore.h` is the source of exact C declarations.

| Function | Contract |
| --- | --- |
| `RLCreate(data, size)` | Synchronously checks inline `.conf`, copies it to Go; handle or 0. The network does not configure. |
| `RLStart(handle)` | Asynchronous Start; 0 means acceptance, readiness - status `connected`. |
| `RLWritePacket(handle, data, size)` | Copies raw IP packet; 0 — accepted, -1 — error/not ready. |
| `RLReadPacket(handle, out, capacity, timeout_ms)` | Buffer 65535..65536 bytes; timeout 1..1000 ms. >0 — length, 0 — timeout, -1 — closed/error. |
| `RLStatus(handle)` | malloc UTF-8 JSON with status/stats. |
| `RLEvents(handle)` | malloc JSON array of up to eight events; picks them up from the queue. |
| `RLSettings(handle)` | malloc JSON MTU and disable IPv6 intents. |
| `RLNetworkChanged(handle)` | External path change signal for general reconnection. |
| `RLStop(handle)` | Closes the port, waits for Stop for up to 60 seconds. 0 — completed and handle deleted; -1 — timeout/error, handle saved for cleaning again. |
| `RLVersion()` | malloc JSON version of Go core. |
| `RLFree(pointer)` | Frees the returned JSON strings; do not apply to caller-owned buffers. |

Packets do not contain Ethernet/utun family header. IP version is determined first
byte; Swift passes AF_INET/AF_INET6 to `packetFlow.writePackets`.
Go pointers are not passed through the ABI. Inputs are copied; outputs are written to
C/Swift memory. The egress queue is limited to 256 packets. On stack overflow
loses packets rather than accumulating memory indefinitely. Read is canceled by Close.
The engine/port and handle pair are used for one session with reconnects;
for the next Start after Stop a new pair is created.

In Go `PacketOptions.Outbound` is required to give a dialer that is not returned to
captured tunnel. Apple bridge uses regular provider-originated sockets:
the actual exclusion of these Go sockets from NE routes still needs to be checked the first time
signed launch. This is not confirmed by one compilation.

## Checked and remains

Checking signing prerequisites via SSH October 6, 2026: in local Xcode cache
the command `VF9CVWFHRK` has `teamType = Personal Team` and
`isFreeProvisioningTeam = true`. Development certificate is present, suitable
No suitable host/provider provisioning profiles are present. This is local cached information;
current membership and access to another team must be verified with Apple Developer
Account or after updating your account in Xcode. Personal Team is not enough for
signed launch NetworkExtension; need access to the Apple Developer team
Program with appropriate capabilities. Passwords and tokens were not read.
[macOS Features](https://developer.apple.com/help/account/reference/supported-capabilities-macos),
[Signing workflow](https://help.apple.com/xcode/mac/current/en.lproj/dev60b6fbbc7.html).

October 7, 2026 on Mac ARM64 both unsigned variants were rebuilt, completed
extended C ABI test without real keys and network connection, Go tests with
race detector, `go vet` and native read-only checking of network services.
Passed all Go tests and vet on Windows; packet TCP SYN/ACK verified for IPv4/IPv6,
closing unblocks Read, sandbox config rejects File without reading the file.

Open: provisioning and signing, OS permission/activation, VPN preferences entry,
Keychain access, real traffic via packetFlow and bypass provider sockets,
split/DNS, network change/sleep, startup/stop/restart error in real NE lifecycle,
DNS conflict detection, persistent restart system extension, kill switch.
iOS build and iOS memory limits check have not yet been completed.
