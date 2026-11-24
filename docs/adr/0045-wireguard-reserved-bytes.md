# ADR 0045: WireGuard Reserved bytes

An existing Cloudflare WARP WireGuard profile can carry three peer-specific
bytes in the WireGuard header. Core keeps those bytes through import, editing
and runtime loading. [Issue #208](https://github.com/bimeron/bimeron-core/issues/208)

Store the bytes in `[Peer] Reserved` and accept the same value in an explicit
`[AccessKey]` for embedding. Both share-link schemes accept decimal triples
with commas or hyphens and standard Base64 encoding exactly three bytes.
Existing all-zero aliases retain their behavior. Nonzero Reserved requires
plain WireGuard, since AWG may assign meaning to the full header word.

Stamp the outbound header at the shared UDP Bind for the configured peer and
clear the reserved bytes on receive. The engine retains its cookie state and
computes both handshake MACs over the normalized header. The remote peer must
verify those MACs over the normalized header too. The triggering MAC1 remains
the cookie reply's associated data. A synthetic peer verifies the cookie
challenge and MAC2 retry. Live WARP verification is pending.

An engine change could support a peer authenticating the on-wire header by
stamping before MAC generation and verifying inbound MACs before header
normalization. That approach increases dependency maintenance and requires
retesting the shared engine. A second engine adds a separate lifecycle on all
platforms. Any live evidence against Bind normalization requires review before
changing the implementation.

The CLI advertises document support through the bridge capability. The service
advertises runtime support through its own hello response. An updated CLI can
save profiles while the installed service awaits an update.
