# Android packet core for a separate application

This repository supplies the Go packet engine and Android AAR. Application and
`VpnService` code belong in a separate repository. The desktop daemon and CLI
are not needed.

## Building

Requirements: the Go version in `go.mod`, Android SDK, NDK, JDK, and
`gomobile` from `golang.org/x/mobile/cmd/gomobile`. Install it with
`go install golang.org/x/mobile/cmd/gomobile@v0.0.0-20261011034528-197770444867`,
run `gomobile init`, and add `$(go env GOPATH)/bin` to `PATH`.
Set `ANDROID_HOME` and `ANDROID_NDK_HOME`, then run
`sh scripts/build-android.sh` (or `scripts/build-android.ps1` on Windows). The scripts build `dist/android/bimeron-core.aar` for
`armeabi-v7a`, `arm64-v8a`, `x86`, and `x86_64`, targeting Android API 23+.
The Java package is `org.bimeron.core`. Publish the artifact with the core
version and SHA256; the application should depend on a specific version.
Distribute `LICENSE` and `THIRD_PARTY_NOTICES.txt` with the AAR.
The AAR contains no Activity, Service, or VPN manifest.

## Contract

The exported Go package is `bimeron/androidcore`; generated Java declarations
inside the AAR are authoritative for exact signatures. One `Session` represents
one VPN run:

1. The application stores the profile as a secret and passes UTF-8 `.conf` bytes
   to `NewSession(profile, protector)`. Inline `SS`, `SSConf`, `Key`, and
   explicit parameters are supported; `File` is prohibited through
   `LoadConfigData`. `Mode` must be `vpn`. `KillSwitch = true` is rejected.
2. Before `Start`, the application selects the physical network and calls
   `SetNetwork(id, dns)`. `id` must distinguish underlying-network changes;
   `dns` is a comma-separated list of up to four IPv4 DNS addresses.
   An empty `id` means no network. Repeat the call when the network or its DNS changes.
3. `VpnService.Builder` sets the interface address, IPv4/IPv6 default routes,
   DNS `198.18.0.2`, and `Session.MTU()`; `establish()` then returns a TUN fd.
   Addresses can follow the Apple provider: `198.18.0.1/24` and
   `fdfe:524c::1/128`. The DNS address must fall within a VPN route.
   With `DisableIPv6()`, an IPv6 route is still required: the core blocks IPv6
   and filters AAAA.
4. After creating TUN, call `Start()`. This acknowledges the request, not
   readiness. `Status()` contains `status.State`: wait for `connected` or
   `failed`. `Events()` returns up to eight events on a best-effort basis;
   `Status()` remains authoritative. When needed, `Stats()` is included in
   the `Status()` JSON as `stats`. `Version()` and `Capabilities()` are
   available before startup.
5. Read raw IP packets from TUN and pass each to `WritePacket`. A separate loop
   calls `ReadPacket(timeoutMs)` with 1..1000 ms and writes returned bytes to
   TUN. `nil` means timeout. Packets contain no Ethernet or utun headers;
   the IP version is in the high four bits of the first byte.
   Inputs are copied; the caller owns the output buffer.
6. When stopping the service, call `Stop()`, wait for completion, and close the
   TUN fd. `Stop` immediately unblocks `ReadPacket`; on timeout, `Stop` can
   be retried. Create a new `Session` for the next run.

Go calls `SocketProtector.Protect(fd)` before connecting **every** outgoing
TCP/UDP socket. The service implementation must call `VpnService.protect(fd)`
and return `false` on any error. The generated Java API uses a `long` callback
argument: check its range and convert to `int` before calling the Android API.
If the application explicitly selects a `Network`, the callback must also bind
the socket to that physical network before connecting.
For `Network.bindSocket(FileDescriptor)`, obtain a temporary duplicate using
`ParcelFileDescriptor.fromFd(fd)`, bind its `fileDescriptor`, and close the
duplicate. Do not use `adoptFd`: Go owns the original fd.
Never return `true` if the socket remains on the VPN path, which would create a
loop. Calls may be concurrent; keep the callback functional until `Stop()`
completes.

The core handles Outline, DNS through the VPN, `proxy`/`direct`/`block`
rules, state, and reconnection. `VpnService` handles user permission, TUN,
routes, system DNS, protected sockets, foreground lifecycle, and system
always-on/lockdown policy. Android application split routing, if needed, is
configured through `VpnService.Builder`; `Capabilities()` does not yet
advertise it. A core kill switch is not implemented on Android.

## Validation

Without an application: `go test ./androidcore ./core`, Go-package
cross-compilation, AAR builds, ABI/Java API checks, and a callback test that
prohibits dialing when `protect` fails. These do not verify Android VPN operation.

On a device or emulator with a test `VpnService`, check permission and TUN
creation, raw TCP/UDP/DNS, protection of **all** outgoing core sockets,
`ssconf` and direct routing, IPv6, Wi-Fi/mobile-network and DNS changes,
stop/restart, process crashes, always-on/lockdown, and memory use.
Compilation alone does not prove the absence of a VPN loop.
