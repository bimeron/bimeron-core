# Terms of Reference: Release and Validation of Apple NetworkExtension

## 1. Purpose

This document describes the work that needs to be done after gaining access
to the paid Apple Developer Program team. The result should be a signed and
verified Bimeron system VPN for macOS based on `NetworkExtension`, which:

- appears in the VPN system section;
- starts and stops using standard macOS tools;
- transmits IPv4 and IPv6 packets between `NEPacketTunnelProvider` and the common Go core;
- supports Bimeron `ss://`, `ssconf://`, DNS, and IP/CIDR policies;
- correctly survives network changes, sleep, awakening and restarting of the provider;
- does not save keys in VPN preferences and does not display them in logs;
- allows for signed, notarized and reproducible assembly.

GUI is not included in the scope of this task. Management is carried out by technical
console shell and macOS system tools.

All implementation of this job is done inside the current repository
`bimeron-core`: Go core, C ABI, Swift provider, technical shell, build
scripts, tests, and documentation. Separate repository or standalone
the project for NetworkExtension is not created. If Apple tools require
Xcode project, it must be part of this repository and use existing ones
sources, rather than forming a separate code base.

## 2. Initial state

Before the paid stage begins, the following must remain operational in the repository:

- common Go core and package backend `core.NewPacketEngine`;
- C ABI `cmd/bimeron-apple`;
- `NEPacketTunnelProvider` and technical shell `BimeronControl`;
- unsigned assembly of system extension and app extension;
- C ABI smoke test;
- separate working macOS backend based on `utun`.

An unsigned build confirms compilation and the ABI contract, but does not confirm
NetworkExtension health, system routing, or signing rights.

## 3. Prerequisites

Before implementation begins, the Apple Team Owner must provide:

1. Active membership in the Apple Developer Program.
2. Developer access to the required command in Xcode and Apple Developer Account.
3. Separate explicit App IDs for the host application and packet tunnel provider.
4. Allowed capability Network Extensions for both App IDs.
5. Registered test Mac for development profiles.
6. Apple Development Certificate for test builds.
7. For direct distribution outside the Mac App Store:
- Developer ID Application certificate;
- Developer ID provisioning profiles for host and provider;
- access to Apple's notarization service.
8. Selected constant bundle identifiers. After public release, change them
It’s impossible without a migration plan.

Signature secrets, private keys, passwords, API keys and provisioning profiles are not
are added to Git.

## 4. Distribution option

The main option for direct distribution of macOS is packet tunnel provider in
system extension format. Entitlement is used for it
`packet-tunnel-provider-systemextension`.

App extension with entitlement `packet-tunnel-provider` remains a separate option
for development and possible distribution through the Mac App Store. Decision on
publications in the Mac App Store are accepted separately and should not complicate the first
Developer ID release.

Before release, you need to confirm the selected option using current documentation
Apple:

- [Deploy Network Extension](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)
- [Entitlement Network Extensions](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.networking.networkextension)
- [Installing system extension](https://developer.apple.com/documentation/systemextensions/installing-system-extensions-and-drivers)

## 5. Identifiers, rights and profiles

We need to create and test a matrix for two executable components:

| Component | Required data |
| --- | --- |
| Host | App ID, bundle ID, Team ID, profile, right to install system extension, access to Keychain |
| Provider | App ID, bundle ID, Team ID, profile, NetworkExtension entitlement, sandbox and network rights |

The assembly script must check before signing:

- Team ID match;
- exact match of application identifier;
- required NetworkExtension type;
- validity period of each profile;
- compliance with the certificate provisioning profile;
- presence of `com.apple.developer.system-extension.install` in the host;
- permitted Keychain access groups where they are used;
- absence of unnecessary entitlement not provided for by the architecture.

After signing, you need to automatically check the attached signatures via `codesign`,
rights via `codesign -d --entitlements`, certificate chain and app integrity
bundle.

## 6. Assembly and signature

It is necessary to bring `scripts/build-apple.sh` to two explicit modes:

1. `unsigned` - local or automated verification without signing secrets.
2. `development` or `distribution` - signature with appropriate certificates and
profiles.

The signed assembly must:

- use the product version and build number from one source;
- sign the provider first, then the host;
- enable hardened runtime for the Developer ID build, if required by the selected one
distribution scheme;
- fail with an error if the profiles or entitlement do not match;
- do not print secrets and profile contents;
- create a separate catalog of artifacts without the original `.conf` and keys.

## 7. Installation and activation

Commands `activate`, `deactivate`, `install`, `remove`, `start`, `stop`, `status` and
`events` must be idempotent or return a clear diagnostic error.

You need to check all the results of `OSSystemExtensionRequest`:

- successful activation;
- the need for confirmation by the user;
- need to reboot;
- installed newer or older version;
- system failure;
- replacement of the existing version;
- deactivation and removal.

After activation, the host must create exactly one configuration
`NETunnelProviderManager`. Repeated `install` updates owned by Bimeron
configuration and does not affect other VPN configurations.

## 8. Storing profile and keys

VPN preferences are only allowed to store the unclassified profile ID and
service settings. Full `ss://`, `ssconf://`, password and decrypted data
It is prohibited to store your profile there.

For app extension, a common Keychain access group host and provider is allowed.

System extension works outside the user context. Current safe
the minimum is to transfer the profile via `startTunnel(options:)` when launched explicitly.
Before implementing automatic recovery, you must separately select and
agree on a secret storage model:

- who creates and deletes the record;
- which process and user have access;
- what happens after the user logs out and reboots;
- how the secret is prevented from being read by other applications or users;
- how migration and revocation of old records is performed.

Before adopting this model, system extension automatically starts after reboot
is not implemented.

## 9. Starting a packet tunnel

At the first signed launch, you need to confirm the following order:

1. Provider receives and checks the inline configuration.
2. `RLCreate` creates one session without changing macOS network settings.
3. Provider applies `NEPacketTunnelNetworkSettings`.
4. `RLStart` launches the common core.
5. Readiness is confirmed by the `connected` state, after which it completes
   `startTunnel`.
6. Packets from `packetFlow.readPackets` are transmitted to `RLWritePacket`.
7. Packets from `RLReadPacket` are returned via `packetFlow.writePackets` with
the correct family of addresses.
8. Stop cancels the read, terminates the core and frees the handle.

Need to check queue limit, packet loss due to overflow, cancellation
blocking read and lack of Go pointers outside the C ABI boundary.

## 10. Routing and outgoing sockets

Critical criterion - outgoing Outline and direct rules sockets should not
return to the captured tunnel.

The check should include:

- IPv4 and IPv6;
- TCP and UDP;
- `proxy`, `direct` and `block`;
- full tunnel;
- several IP/CIDR rules;
- changing Wi-Fi to Ethernet and vice versa;
- unavailable server and subsequent recovery.

If regular provider-originated sockets do not provide stable bypass,
The outbound transport architecture needs to be reconsidered before further development.
Bypass through unconfirmed exclusion routes is not accepted.

## 11. DNS

Need to check:

- system DNS requests through the virtual address Bimeron;
- several upstream DNS with fallback;
- AAAA filtering at `IPv6 = disable`;
- default behavior for `proxy`, `direct` and `block`;
- recovery after network change;
- conflict with WARP and other DNS/VPN providers;
- no DNS leak when restoring transport.

When an active incompatible DNS provider is detected, Bimeron should return
diagnostic error, rather than silently changing someone else's configuration.

## 12. Life cycle and recovery

Required scripts:

- regular start and stop;
- repeated start after stop;
- stop during startup;
- error applying network settings;
- core launch error;
- loss of Wi-Fi;
- Wi-Fi/Ethernet transition;
- sleep and awakening;
- updating dynamic `ssconf://` during reconnection;
- completion of the provider system;
- system extension update;
- reboot Mac;
- damaged or deleted profile entry.

Each scenario must end in one specific state, not leave
stuck handles and issue a safe repeated recovery command.

## 13. Kill switch

`KillSwitch = true` remains prohibited for NetworkExtension until a separate
architectural design and testing.

Before implementation you need to determine:

- which Apple APIs guarantee blocking at startup, reconnection and crash;
- whether the blocking is valid after the completion of host and provider;
- how access to the local network is maintained;
- how emergency shutdown is performed;
- what happens when updating and deleting an extension;
- what restrictions differ between system extension and app extension.

You cannot declare a kill switch ready based solely on included routes or
successful unit test.

## 14. Diagnostics and logs

It is necessary to provide:

- stable error codes for host, provider and Go core;
- reading status and events without freezing;
- version of host, provider and core in diagnostics;
- secure system logs without keys, dynamic key URLs and passwords;
- distinguish between signature, profile, user permission, route, DNS and
transport;
- instructions for collecting diagnostics by the user.

## 15. Security

A separate review is required before release:

- Swift, C ABI and Go trust boundaries;
- sizes and lifetime of all buffers;
- parallel start/stop/message operations;
- processing of damaged configuration;
- Keychain and app bundle file rights;
- lack of secrets in process arguments, preferences and logs;
- secure profile deletion;
- behavior when the bundle is replaced or damaged;
- minimum set of entitlement.

## 16. Testing

### Automatic checks

- Go unit and integration tests;
- race detector;
- C ABI smoke test;
- unsigned assembly of both extension options;
- tests for parsing configuration and C ABI errors;
- checking entitlement and signatures on a dedicated macOS runner;
- checking that artifacts do not contain keys and provisioning profiles in excess
the necessary embedded profiles of the signed bundle.

### macOS Manual Matrix

- clean installation;
- update over the previous version;
- removal and reinstallation;
- Apple Silicon;
- supported macOS versions;
- Wi-Fi and Ethernet;
- IPv4-only, dual stack and unavailable IPv6;
- sleep, awakening and reboot;
- WARP or other VPN/DNS provider;
- full tunnel and split routing;
- static and dynamic key;
- server failure and recovery.

## 17. Notarization and distribution

For direct distribution you need:

1. Collect and sign the bundle with the Developer ID Application certificate.
2. Check signatures locally.
3. Package the artifact in a supported way.
4. Send it via `notarytool`.
5. Check the notarization log.
6. Attach the ticket to the artifact.
7. Test Gatekeeper on a clean Mac.
8. Publish checksum and installation/removal instructions.

Links:

- [Software Notarization for macOS](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution)
- [Setting up the notarization process](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)

## 18. Build automation and secrets

Public runners only perform unsigned builds and tests without Apple secrets.

The signed build runs on a controlled macOS runner or a separate one
protected process. Secrets should have minimal rights, not be shared
logs and deleted from the temporary Keychain after job.

The release is published only after successful tests, signature verification,
notarization and manual smoke test.

## 19. Participation of the project owner

A project owner will be required for the following:

- joining the Apple Developer Program or providing access to the team;
- approval of bundle identifiers and distribution method;
- creation or confirmation of App ID, certificates and profiles;
- confirmation of system extension in macOS settings;
- confirmation of adding a VPN configuration;
- manual check of VPN system switch, browser, sleep and network change;
- approval of the secret storage model and kill switch requirements;
- decision on publication and release.

## 20. Readiness criteria

The work is considered completed when the following conditions are simultaneously met:

- the signed provider is activated in the normal way;
- Bimeron is displayed in the VPN system section;
- real TCP/UDP and DNS traffic passes through Outline;
- IPv4, IPv6 and split routing correspond to the configuration;
- outgoing sockets are not looped into the tunnel;
- stop, sleep, wake, network change and restart pass without state leaks;
- secrets are missing in preferences, logs and diagnostics;
- the signed bundle undergoes automatic checks and notarization;
- manual matrix is ​​documented and executed;
- kill switch and autorun restrictions are either eliminated or explicitly reflected in
product capabilities.

## 21. Proposed task breakdown

Track the remaining work as separate tasks:

1. Apple Team, App ID, certificates and provisioning profiles.
2. Development signature and first activation of the system extension.
3. Real packet flow and bypass check of outgoing sockets.
4. DNS, split routing and network conflicts.
5. Lifecycle: network change, sleep, restart and update.
6. Secret storage model and automatic recovery.
7. Architecture and testing of kill switch.
8. Developer ID assembly, hardened runtime and notarization.
9. Signed build and release process.
10. Final security review and acceptance matrix.

Each significant task is performed in a separate branch and is issued in a separate
pull request after architecture approval.
