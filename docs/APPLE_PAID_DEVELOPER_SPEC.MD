# Specification: releasing and validating the Apple NetworkExtension

## 1. Purpose

This document describes the work that remains once a paid Apple Developer
Program team is available. The result should be a signed and verified Bimeron
system VPN for macOS based on `NetworkExtension` that:

- appears in the system VPN settings;
- starts and stops with standard macOS tools;
- passes IPv4 and IPv6 packets between `NEPacketTunnelProvider` and the shared Go core;
- supports Bimeron access profiles (for example `ss://` and `ssconf://`), DNS, and IP/CIDR policies;
- survives network changes, sleep, wake, and provider restarts;
- never stores keys in VPN preferences or prints them in logs;
- supports signed, notarized, and reproducible builds.

A GUI is out of scope. Control uses the technical console shell and macOS system
tools.

All work happens in the `bimeron-core` repository: the Go core, C ABI, Swift
provider, technical shell, build scripts, tests, and documentation. No separate
repository or standalone NetworkExtension project is created. If Apple tooling
requires an Xcode project, it lives in this repository and uses the existing
sources instead of forming a separate code base.

## 2. Starting point

Before the paid stage begins, the repository must keep working:

- the shared Go core and the packet backend `core.NewPacketEngine`;
- the C ABI in `cmd/bimeron-apple`;
- the `NEPacketTunnelProvider` and the technical shell `BimeronControl`;
- unsigned system extension and app extension builds;
- the C ABI smoke test;
- the separate, working macOS `utun` backend.

An unsigned build confirms compilation and the ABI contract. It does not confirm
that the NetworkExtension works, that system routing is correct, or that signing
rights are in place.

## 3. Prerequisites

Before implementation, the Apple team owner must provide:

1. Active membership in the Apple Developer Program.
2. Developer access to the team in Xcode and the Apple Developer account.
3. Separate explicit App IDs for the host application and the packet tunnel provider.
4. The Network Extensions capability enabled for both App IDs.
5. A test Mac registered for development profiles.
6. An Apple Development certificate for test builds.
7. For direct distribution outside the Mac App Store:
   - a Developer ID Application certificate;
   - Developer ID provisioning profiles for the host and the provider;
   - access to Apple's notarization service.
8. Final bundle identifiers. After a public release they cannot change without a
   migration plan.

Signing secrets, private keys, passwords, API keys, and provisioning profiles are
never committed to Git.

## 4. Distribution format

The primary format for direct macOS distribution is a packet tunnel provider
packaged as a system extension, using the
`packet-tunnel-provider-systemextension` entitlement.

An app extension with the `packet-tunnel-provider` entitlement remains a separate
option for development and possible Mac App Store distribution. A Mac App Store
release is decided separately and must not complicate the first Developer ID
release.

Before release, confirm the chosen format against Apple's current documentation:

- [Network Extension provider deployment](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)
- [Network Extensions entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)
- [Installing system extensions and drivers](https://developer.apple.com/documentation/systemextensions/installing-system-extensions-and-drivers)

## 5. Identifiers, entitlements, and profiles

Create and test the following matrix for the two executables:

| Component | Required data |
| --- | --- |
| Host | App ID, bundle ID, Team ID, profile, system extension installation entitlement, Keychain access |
| Provider | App ID, bundle ID, Team ID, profile, NetworkExtension entitlement, sandbox and network entitlements |

Before signing, the build script must check:

- that the Team IDs match;
- that the application identifiers match exactly;
- the required NetworkExtension type;
- the validity period of each profile;
- that each provisioning profile matches the certificate;
- that the host has `com.apple.developer.system-extension.install`;
- the allowed Keychain access groups where they are used;
- that no entitlements beyond those the architecture needs are present.

After signing, automatically verify the signatures with `codesign`, the
entitlements with `codesign -d --entitlements`, the certificate chain, and the
app bundle's integrity.

## 6. Building and signing

Extend `scripts/build-apple.sh` with two explicit modes:

1. `unsigned`: local or automated verification without signing secrets.
2. `development` or `distribution`: signing with the matching certificates and
   profiles.

A signed build must:

- take the product version and build number from a single source;
- sign the provider first, then the host;
- enable the hardened runtime for Developer ID builds when the chosen
  distribution scheme requires it;
- fail if profiles or entitlements do not match;
- never print secrets or profile contents;
- write a separate artifact directory without the original `.conf` files or keys.

## 7. Installation and activation

The `activate`, `deactivate`, `install`, `remove`, `start`, `stop`, `status`, and
`events` commands must be idempotent or return a clear diagnostic error.

Handle every `OSSystemExtensionRequest` outcome:

- successful activation;
- user approval required;
- reboot required;
- a newer or older version already installed;
- system failure;
- replacing the existing version;
- deactivation and removal.

After activation, the host creates exactly one `NETunnelProviderManager`
configuration. Running `install` again updates only the Bimeron-owned
configuration and leaves other VPN configurations untouched.

## 8. Storing profiles and keys

VPN preferences may store only the non-secret profile ID and service settings.
Complete `ss://` or `ssconf://` keys, passwords, and decrypted profile data must
never be stored there.

An app extension may share a Keychain access group between the host and the
provider.

A system extension runs outside the user context. The current safe minimum is to
pass the profile through `startTunnel(options:)` on an explicit start. Before
implementing automatic recovery, choose and agree on a secret storage model:

- who creates and deletes the record;
- which process and user can access it;
- what happens after the user logs out and after a reboot;
- how other applications and users are prevented from reading the secret;
- how old records are migrated and revoked.

Until that model is adopted, the system extension does not start automatically
after a reboot.

## 9. Starting the packet tunnel

On the first signed launch, confirm this sequence:

1. The provider receives and validates the inline configuration.
2. `RLCreate` creates one session without changing macOS network settings.
3. The provider applies `NEPacketTunnelNetworkSettings`.
4. `RLStart` starts the shared core.
5. `startTunnel` completes only after the `connected` state confirms readiness.
6. Packets from `packetFlow.readPackets` go to `RLWritePacket`.
7. Packets from `RLReadPacket` return through `packetFlow.writePackets` with the
   correct address family.
8. Stop cancels the pending read, stops the core, and releases the handle.

Also verify the queue limit, packet drops on overflow, cancellation of a blocked
read, and that no Go pointers cross the C ABI boundary.

## 10. Routing and outgoing sockets

The critical requirement is that the core's outgoing sockets, both upstream and
`direct`, never loop back into the captured tunnel.

Test:

- IPv4 and IPv6;
- TCP and UDP;
- `proxy`, `direct`, and `block`;
- a full tunnel;
- several IP/CIDR rules;
- switching between Wi-Fi and Ethernet;
- an unavailable server and subsequent recovery.

If regular provider-originated sockets do not bypass the tunnel reliably,
reconsider the outbound transport architecture before further development.
Bypassing through unconfirmed exclusion routes is not acceptable.

## 11. DNS

Test:

- system DNS queries through the Bimeron virtual address;
- several upstream DNS servers with fallback;
- AAAA filtering with `IPv6 = disable`;
- default behavior for `proxy`, `direct`, and `block`;
- recovery after a network change;
- conflicts with WARP and other DNS or VPN providers;
- no DNS leak while the transport recovers.

When an incompatible active DNS provider is detected, Bimeron must return a
diagnostic error instead of silently changing another provider's configuration.

## 12. Lifecycle and recovery

Required scenarios:

- regular start and stop;
- start again after stop;
- stop during startup;
- failure to apply network settings;
- core startup failure;
- Wi-Fi loss;
- switching between Wi-Fi and Ethernet;
- sleep and wake;
- updating a dynamic `ssconf://` key during reconnection;
- the system terminating the provider;
- updating the system extension;
- rebooting the Mac;
- a damaged or deleted profile record.

Each scenario must end in one defined state, leave no stuck handles, and offer a
safe, repeatable recovery command.

## 13. Kill switch

`KillSwitch = true` stays rejected for NetworkExtension until a separate
architecture design and testing are complete.

Before implementation, determine:

- which Apple APIs guarantee blocking during startup, reconnection, and crashes;
- whether blocking persists after the host and provider exit;
- how local network access is preserved;
- how an emergency shutdown works;
- what happens when the extension is updated or removed;
- how the limits differ between system and app extensions.

A kill switch cannot be declared ready based only on included routes or a passing
unit test.

## 14. Diagnostics and logs

Provide:

- stable error codes for the host, provider, and Go core;
- status and event reads that never hang;
- host, provider, and core versions in diagnostics;
- safe system logs without keys, dynamic key URLs, or passwords;
- clear separation of signing, profile, user permission, routing, DNS, and
  transport failures;
- instructions for users to collect diagnostics.

## 15. Security

Before release, a separate review must cover:

- the Swift, C ABI, and Go trust boundaries;
- the sizes and lifetimes of all buffers;
- concurrent start, stop, and message operations;
- handling of damaged configurations;
- Keychain and app bundle file permissions;
- no secrets in process arguments, preferences, or logs;
- secure profile deletion;
- behavior when the bundle is replaced or damaged;
- the minimal set of entitlements.

## 16. Testing

### Automated checks

- Go unit and integration tests;
- the race detector;
- the C ABI smoke test;
- unsigned builds of both extension variants;
- tests for configuration parsing and C ABI errors;
- entitlement and signature checks on a dedicated macOS runner;
- a check that artifacts contain no keys or provisioning profiles beyond the
  profiles embedded in the signed bundle.

### Manual macOS matrix

- clean installation;
- update over the previous version;
- removal and reinstallation;
- Apple Silicon;
- supported macOS versions;
- Wi-Fi and Ethernet;
- IPv4-only, dual stack, and unavailable IPv6;
- sleep, wake, and reboot;
- WARP or another VPN or DNS provider;
- full tunnel and split routing;
- static and dynamic keys;
- server failure and recovery.

## 17. Notarization and distribution

For direct distribution:

1. Build and sign the bundle with the Developer ID Application certificate.
2. Verify the signatures locally.
3. Package the artifact in a supported format.
4. Submit it with `notarytool`.
5. Review the notarization log.
6. Staple the ticket to the artifact.
7. Test Gatekeeper on a clean Mac.
8. Publish checksums and installation and removal instructions.

References:

- [Notarizing macOS software before distribution](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
- [Customizing the notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)

## 18. Build automation and secrets

Public runners perform only unsigned builds and tests without Apple secrets.

Signed builds run on a controlled macOS runner or in a separate protected
process. Secrets have minimal permissions, never appear in logs, and are removed
from the temporary Keychain after the job.

A release is published only after tests, signature verification, notarization,
and a manual smoke test pass.

## 19. Project owner involvement

The project owner is needed to:

- join the Apple Developer Program or grant access to the team;
- approve the bundle identifiers and the distribution method;
- create or confirm the App IDs, certificates, and profiles;
- approve the system extension in macOS settings;
- approve adding the VPN configuration;
- manually check the system VPN switch, browsing, sleep, and network changes;
- approve the secret storage model and kill switch requirements;
- decide on publication and release.

## 20. Completion criteria

The work is complete when all of the following hold:

- the signed provider activates the standard way;
- Bimeron appears in the system VPN settings;
- real TCP/UDP and DNS traffic passes through the upstream server;
- IPv4, IPv6, and split routing match the configuration;
- outgoing sockets do not loop into the tunnel;
- stop, sleep, wake, network changes, and restarts leave no stale state;
- no secrets appear in preferences, logs, or diagnostics;
- the signed bundle passes automated checks and notarization;
- the manual matrix is documented and executed;
- the kill switch and automatic start limitations are either resolved or
  explicitly reflected in the product capabilities.

## 21. Proposed task breakdown

Track the remaining work as separate tasks:

1. Apple team, App IDs, certificates, and provisioning profiles.
2. Development signing and first activation of the system extension.
3. Real packet flow and verification that outgoing sockets bypass the tunnel.
4. DNS, split routing, and network conflicts.
5. Lifecycle: network changes, sleep, restart, and updates.
6. Secret storage model and automatic recovery.
7. Kill switch architecture and testing.
8. Developer ID build, hardened runtime, and notarization.
9. Signed build and release process.
10. Final security review and acceptance matrix.

Implement each significant task on a separate branch and submit it as a separate
pull request after the architecture is approved.
