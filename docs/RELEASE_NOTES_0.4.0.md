# Bimeron Core v0.4.0

Core v0.4.0 is a stable-channel release. Desktop 0.3.1 supports this update for Windows and Linux service installations. Desktop 0.3.2 compatibility was checked against the unpublished `release/0.3.2` branch. Both versions trust the hardware release keys and support IPC 1 and profile format 1.

## Changes since v0.4.0-beta.2

- Experimental WireGuard and AmneziaWG client support includes configuration import, a document editing interface and CLI key operations. Clients can discover support through the service capabilities response.
- Local SOCKS5 listeners support optional username/password authentication. Core now bounds idle TCP relay connections and cancels abandoned Hysteria2 dials.
- Windows binds the packet tunnel to its selected adapter and verifies DNS policy. Linux guards DNS queries through systemd-resolved. Kill switch cleanup and failure handling retain protection across additional error paths.
- Service updates check the opened source volume. SSH agent requests have bounded deadlines, and the daemon skips the interactive agent. Profile validation reports the trust files it uses.

## Packages and verification

The seven ZIPs contain six CLI distributions for Windows, Linux and macOS on amd64 and arm64, and one Android AAR. Verify each ZIP against SHA256SUMS. The signed service update manifest covers the four Windows and Linux targets. Its primary signing key ID is `e6fb20d55656904a`.

The release tag is `v0.4.0`, the embedded Core version is `0.4.0`, and the service update channel is `stable`. The reviewed Desktop interval is `[0.3.1, 0.3.3)`. The Android package is a library for application developers.

See [the signed update policy](RELEASE_UPDATES.md) and [the previous security release](RELEASE_NOTES_0.4.0_BETA.2.md).
