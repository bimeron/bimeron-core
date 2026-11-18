# Bimeron Core v0.4.0-beta.2

**Release notes — draft for review.** This is a security patch release on top
of v0.4.0-beta.1. Publication is pending candidate freeze, VM acceptance of the
Desktop 0.3.1 candidate with this Core candidate, and explicit approval.

The reviewed source range is `5fcadd71..9521d8b4` on master. `5fcadd71` is the
v0.4.0-beta.1 tag commit. The final candidate commit is recorded at freeze.

For package capabilities, see the [README at the release tag](https://github.com/bimeron/bimeron-core/blob/v0.4.0-beta.2/README.md).

## Summary

This release updates the Go toolchain and several dependencies to versions that
fix publicly disclosed vulnerabilities, makes `govulncheck` a blocking CI
check, and hardens local trust boundaries and resource limits: control server
identity, service update staging, profile file reads, geosite regex size,
HTTP upgrade handshakes and the Windows kill switch exception. It also changes
reconnect recovery to retry indefinitely after an established session is lost
and holds kill switch protection from start until an explicit disconnect. IPC
and profile format versions are unchanged; all IPC changes are additive. Some previously accepted inputs are now
rejected, and three structured problem codes are new; see
[Compatibility](#compatibility). Upgrading is recommended for all users of
v0.4.0-beta.1 and earlier.

## Fixed vulnerabilities

Updated in [#150](https://github.com/bimeron/bimeron-core/pull/150) (tracked by
[#149](https://github.com/bimeron/bimeron-core/issues/149)) and
[#154](https://github.com/bimeron/bimeron-core/pull/154). The impact
assessment below reflects how Bimeron Core uses each component.

| Advisory | Component | Previous | Fixed | Impact on Bimeron Core |
| --- | --- | --- | --- | --- |
| GO-2026-6865 | `github.com/klauspost/compress` (zstd) | v1.17.9 | v1.20.4 | High for `firefox` TLS fingerprint |
| GO-2026-6888 | `github.com/andybalholm/brotli` | v1.1.0 | v1.2.8 | High for Chrome-family and Firefox fingerprints |
| GO-2026-6348, GO-2026-6061 | `google.golang.org/grpc` | v1.79.3 | v1.83.2 | Medium for gRPC transports |
| GO-2026-6809 | Go standard library `crypto/x509` | go1.26.9 | go1.26.11 | Low; hardening |
| GO-2026-6859 | Go standard library `net/http` | go1.26.9 | go1.26.11 | Not practically affected |
| GO-2026-6866, GO-2026-6860 | `golang.org/x/net` (`html`) | v0.61.0 | v0.62.0 | Not affected; package not built |

### Certificate decompression in fingerprinted TLS (zstd, brotli)

Fingerprinted TLS client hellos advertise TLS certificate compression
(RFC 8879), and the client decompresses the server certificate during the
handshake, before the certificate is verified. A malicious server, or a party
able to intercept the connection, could therefore crash the Core process or
cause excessive memory use without valid credentials or a trusted certificate.
A crash ends the current VPN session.

- **zstd** (`klauspost/compress`) is advertised only by the `firefox`
  fingerprint (`fp=firefox`) in TCP TLS transports, including REALITY.
- **brotli** is advertised by the `chrome`, `edge` and `firefox` fingerprints
  in TCP TLS transports, including REALITY; by ShadowTLS, which always uses the
  Chrome fingerprint; by NaiveProxy over HTTP/2; and by the Chrome QUIC
  fingerprint of Hysteria2.
- The `safari` fingerprint advertises only zlib, which is not affected. The
  `ios` and `android` fingerprints, and connections without a fingerprint, do
  not advertise certificate compression.

### gRPC client (grpc)

The gRPC stream transport for VLESS, VMess and Trojan uses the grpc client. A
malicious or compromised gRPC server could cause excessive memory use in the
client. Other transports are not affected. The repository does not run a gRPC
server in shipped code.

### Certificate verification (crypto/x509)

Go 1.26.11 distrusts certificates issued by compromised intermediate
certificate authorities. This hardens verification of TLS server certificates
for all TLS-based protocols and for HTTPS requests such as SSConf and signed
release acquisition.

### HTML parsing (golang.org/x/net)

The fixed issues are in the `golang.org/x/net/html` package, which Bimeron
Core does not build. The update removes the module-level finding
([#154](https://github.com/bimeron/bimeron-core/pull/154), tracked by
[#151](https://github.com/bimeron/bimeron-core/issues/151)).

### HTTP server (net/http)

The fixed issues affect HTTP/1 servers. Shipped Bimeron Core code does not run
an HTTP server, so it is not practically affected. The toolchain update
removes the finding.

## Reconnection and kill switch

Changed in [#163](https://github.com/bimeron/bimeron-core/pull/163). See
[Reconnect recovery and kill switch hold](CONTROL.MD#reconnect-recovery-and-kill-switch-hold).

- **Reconnect policy.** After an established session is lost, Core reconnects
  indefinitely in cycles of 10 attempts. Attempts within a cycle back off 1, 2,
  4, 8, then 15 seconds; cycles are separated by a 60-second pause. A network
  change, a resume from sleep, or the new `reconnect_now` command (CLI:
  `bimeron reconnect`) starts the next attempt immediately. A network change
  ends at most one wait per cycle. The initial connection is unchanged: the
  first attempt plus 3 retries. Native IKEv2 sessions keep the bounded policy.
  This replaces the three-attempt limit after an interruption introduced in
  v0.4.0-beta.1.
- **Kill switch hold.** When a profile enables the kill switch
  (`[Interface] KillSwitch = true`, Windows and Linux VPN mode), protection is
  installed before any connection traffic, including access key and `ssconf`
  resolution. It is held across all attempts, waits and the `failed` state, and
  is released only when the user disconnects. While it is held, applications
  other than Core cannot resolve names outside the tunnel (DNS ports 53 and
  853), including through resolvers in `direct` ranges.
- **Profile switching.** Starting a different kill switch profile while one is
  active switches without an unprotected gap. Starting the same profile again
  keeps the running session.
- **Leftover protection.** Protection left after a crash or power loss is
  reported as `KillSwitch: "residual"` together with `failed` and
  `cleanup_failed_run_recover`. Connecting a kill switch profile or running
  network recovery clears it.
- **Without the kill switch.** The same reconnect policy applies, but traffic
  may leave outside the tunnel while connecting, reconnecting or after a
  failure.

### IPC additions (IPC 1)

All fields are omitted when zero.

- `ReconnectAttempt` and `ReconnectLimit`: 1–3 of 3 during the initial
  connection, 1–10 of 10 within a cycle, omitted while `waiting`.
- `ReconnectCycle`: the current or most recent cycle after loss of an
  established session; omitted during the initial connection.
- `ReconnectPhase`: `attempting` or `waiting`.
- `NextAttemptAt`: RFC 3339 UTC timestamp in whole seconds; the attempt does
  not start earlier.
- `KillSwitch`: `active` (installed and connected), `holding` (installed while
  the tunnel carries no traffic: connecting, reconnecting, held failure,
  stopping) or `residual` (idle with leftover protection).
- `LastErrorPermanent`: `LastError` is a failure that retrying alone does not
  fix.
- Events: `reconnect_attempt`, `reconnect_wait`, `reconnect_requested`,
  `kill_switch_holding` and `kill_switch_held`.
- Capabilities: `reconnect_now` and `kill_switch_hold`.
- Command `reconnect_now`, with the same guards as `stop`. Errors:
  `reconnect_not_pending`, `stale_session`, `stale_instance` and
  `invalid_request`.
- New `start` error `kill_switch_held`: a failed session holds protection and
  the new profile has no kill switch.

### Known limitations

- The Windows kill switch does not cover forwarded traffic, such as Internet
  Connection Sharing or WSL2 and Hyper-V NAT
  ([#164](https://github.com/bimeron/bimeron-core/issues/164)).
- mDNS (UDP 5353) remains allowed to `direct` ranges.
- With the outbound path blocked, loss of a session is detected after about
  80 seconds (a health check every 30 seconds, 3 failures). This is unchanged.
- `service update` releases kill switch protection while the service restarts.

## Hardening

### Local control endpoints

- Clients verify the identity of the local control server before sending any
  request. On Windows, the service and readiness pipes are owned by LocalSystem
  and clients bind the pipe server process to the BimeronCore service; the
  console daemon and IKEv2 foreground pipes are owned by Administrators. On
  Linux and macOS, clients check the runtime directory and socket and require
  root peer credentials. A failed check reports the new
  `control_server_untrusted` code, and the client does not fall back to
  another endpoint ([#159](https://github.com/bimeron/bimeron-core/pull/159)).
- The console daemon and IKEv2 foreground mode require membership in the
  Administrators group.

### Service updates

- `service update -source` accepts only a regular file on a fixed local drive,
  given as a plain drive-letter path on Windows (long paths work without the
  `\\?\` prefix), of at most 256 MiB. Links, junctions, network and other
  non-local sources are rejected, and the checks apply to the opened file as
  well as its path. The source is staged privately, and the installed
  permissions are applied only after the digest, Go identity and architecture
  checks pass. A staged copy is removed on failure, and a copy left by an
  interrupted update no longer blocks a retry. Rollback and service state
  restoration are unchanged
  ([#156](https://github.com/bimeron/bimeron-core/pull/156),
  [#165](https://github.com/bimeron/bimeron-core/pull/165)).

### Profile and referenced files

- Profiles and every file they reference (access key files, geodata, MASQUE CA
  files, SSH identities and known_hosts) are read through one local-only,
  size-bounded reader. Directories, devices, FIFOs, sockets and named pipes are
  rejected before opening, and the opened file is checked again
  ([#160](https://github.com/bimeron/bimeron-core/pull/160)).
- These locations are no longer supported for profiles and referenced files:
  - Windows: network shares, including `\\wsl$` and `\\wsl.localhost`,
    VirtualBox shared folders (`\\vboxsvr`), Remote Desktop drives
    (`\\tsclient`) and Documents or Desktop folders redirected to a network
    share; files on a network file system reached through a mapped drive, a
    `subst` drive, a symbolic link or a mount point; device-namespace paths,
    including explicit long paths such as `\\?\C:\...`; reserved device
    names; and alternate data streams.
  - Unix: process substitution (`<(...)`) and `/dev/stdin` or `/dev/fd/N`
    connected to a pipe.

  Copy such a file to a local folder and reference the copy. OneDrive and
  other cloud files in synchronized local folders remain supported; reading a
  file that is not stored locally downloads it first. See
  [Referenced files](CONF.MD#referenced-files).
- Non-local paths and non-regular files report the new `file_path_not_local`
  and `file_not_regular` codes. A read error in the middle of a file now
  reports `file_unreadable` instead of `file_too_large`.

### Resource limits

- Geosite regex entries are bounded in pattern length and compiled size, per
  entry and per dataset; overflow reports the existing `geodata_limit` code.
  Real-world datasets remain accepted
  ([#157](https://github.com/bimeron/bimeron-core/pull/157)).
- WebSocket and HTTPUpgrade handshakes read at most 64 KiB of response before
  the data phase. VMess and Trojan WebSocket share the common upgrade path
  ([#158](https://github.com/bimeron/bimeron-core/pull/158)).

### Windows kill switch

- The kill switch exception for the Core executable applies only to SYSTEM and
  elevated Administrators. While the kill switch is active, non-elevated CLI
  helpers started from the same executable (for example `check` or `proxy`)
  follow the ordinary protection rules. The service and elevated console or
  foreground sessions are unaffected
  ([#161](https://github.com/bimeron/bimeron-core/pull/161)).

## Build and CI changes

- Building from source requires Go 1.26.11 or newer. The Apple release build
  gate requires exactly Go 1.26.11.
- `govulncheck` is now a blocking CI check for the `linux/amd64`,
  `windows/amd64`, `android/arm64` and `darwin/arm64` targets. Reachable
  findings fail the build. Findings in required modules whose vulnerable code
  is not called are reported without failing the build
  ([#150](https://github.com/bimeron/bimeron-core/pull/150)).
- `THIRD_PARTY_NOTICES.txt` lists the updated dependency versions.
- Documentation records the v0.4.0-beta.1 publication and the service update
  state preservation correction
  ([#148](https://github.com/bimeron/bimeron-core/pull/148)).

## Compatibility

IPC remains version **1** and profile format remains version **1**. IPC
changes are additive: the reconnect and kill switch fields, events,
capabilities and the `reconnect_now` command listed under
[IPC additions](#ipc-additions-ipc-1). No document operations were added or
removed.

- New structured problem codes: `control_server_untrusted`,
  `file_path_not_local`, `file_not_regular`, `reconnect_not_pending` and
  `kill_switch_held`. Clients should render them from the catalog.
- Profiles that reference files in the locations listed under
  [Profile and referenced files](#profile-and-referenced-files) now fail
  validation.
- Control server identity (#159): updated clients, such as the CLI of this
  release and Desktop 0.3.1, reject a service built before this release with
  `control_server_untrusted` until the service is updated. `version -daemon`
  then reports that code instead of the service version. `service update` from
  an older service and Windows repair keep working, and after the update,
  clients that verify the control server accept the updated service (verified
  on a Windows 10 VM). Older clients, including Desktop 0.3.0, keep working
  with the new service.
- Running the console daemon or IKEv2 foreground mode requires membership in
  the Administrators group.

**GUI compatibility range: [0.3.0, 0.3.2)**

## Upgrade notes / Desktop

Desktop 0.3.1 bundles this release as its CLI and repair broker, so explicit
repair keeps the service at this version. It is published together with this
release.

Desktop 0.3.0 is in the reviewed GUI range and is offered this release as a
service update when the user enables **Include beta core updates**. A service
update alone does not replace the CLI and repair broker bundled with Desktop
0.3.0, which remain v0.4.0-beta.1. To keep the bundled components current,
upgrade to Desktop 0.3.1.

Explicit repair restores the service executable bundled with the GUI package.
In Desktop 0.3.0, running Repair after this update therefore restores the Core
bundled with Desktop 0.3.0 (v0.4.0-beta.1). Desktop 0.3.0 shows Repair only
when the service is not ready. Install the update again afterwards, or upgrade
to Desktop 0.3.1, which bundles v0.4.0-beta.2. Reinstalling Desktop 0.3.0 does
not downgrade a newer installed service.

Desktop 0.3.0 with this service shows reconnection as follows. It shows a
counter only while `reconnecting` with an attempt within the limit.

| Core state | Desktop 0.3.0 shows |
| --- | --- |
| Initial retries (1–3 of 3) | "Reconnecting… (n/3)", unchanged |
| Attempt within a cycle (1–10 of 10) | "Reconnecting… (n/10)" |
| Pause between cycles | "Reconnecting…" without a counter |
| Failure with protection held | The failure as before; **Disconnect** sends `stop` and releases protection |
| Leftover protection after a crash or reboot | The **Emergency network recovery** button |
| Failure without the kill switch | Unchanged |

Desktop 0.3.0 does not verify the identity of the local control server before
sending requests, and updating the service does not add this check to it.
Desktop 0.3.1 adds the check
([bimeron-desktop#63](https://github.com/bimeron/bimeron-desktop/pull/63)).
Upgrading to Desktop 0.3.1 is recommended.

The repair broker embeds the reviewed compatibility policy from
`release/compatibility.json`, so signed acquisition of its own release accepts
the same GUI window as the publisher.

## Planned packages and verification

The asset layout matches v0.4.0-beta.1: six CLI ZIP packages for Windows,
Linux and macOS on amd64 and arm64, plus one Android AAR package. Each package
includes `LICENSE` and `THIRD_PARTY_NOTICES.txt`; Windows packages include the
matching Wintun DLL and its license. Android is an AAR, not an installable
application. Apple NetworkExtension is not included.

Verify archives with `SHA256SUMS`. Windows/Linux service update clients can
verify `update-manifest.json` with `update-manifest.json.sig` and a separately
trusted Ed25519 public key. The service manifest covers Windows/Linux amd64 and
arm64, not macOS or Android.

Before publication, freeze the candidate, complete VM acceptance of the Desktop
0.3.1 candidate with the Core candidate and the Desktop 0.3.0 service update
path, validate signed assets, and verify the tag-specific README link. These
notes do not claim completed candidate acceptance or new benchmarks.
