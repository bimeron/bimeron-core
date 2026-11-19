# Release signing keys

Service update manifests (`update-manifest.json`) are signed with Ed25519, see
[RELEASE_UPDATES.md](RELEASE_UPDATES.md). This page lists every public key a
verifier may pin. A `key_id` is the first eight bytes of SHA-256 of the 32-byte
public key, as 16 lowercase hex digits; it selects a pinned key but does not
establish trust on its own.

| key_id | Public key (standard base64) | Holder | Signs |
| --- | --- | --- | --- |
| `7370a2d8cf890e5e` | `bk6SfABmDG88uhUupYT+ia6dtSrpHbnGaBCfYvihJF0=` | Software key (retiring) | Every release up to and including `v0.4.0-beta.2`. Signs nothing new. |
| `e6fb20d55656904a` | `lRcnhdj4yU4TrinOa4U177FG7wrwUPv/v9zxA/WiJMI=` | Hardware key A, YubiKey serial 22337246 | Primary signer for releases after `v0.4.0-beta.2`. |
| `095d295f5fe9a4e2` | `6K8uY/1qIogN2j3ZdpEr4PuTqXzH7EseTd6kzHxpIr4=` | Hardware key B, YubiKey serial 19344964 | Backup signer, used only when key A is unavailable. |

Desktop 0.3.1 and later pin all three keys. Core repair acquisition
(`cmd/bimeron/repair_acquire.go`) fetches only the broker's own exact release, so
a Core built from this source pins only keys A and B.

## Hardware keys

Keys A and B were generated on 2026-11-19 inside the OpenPGP application of two
YubiKey 5 devices (firmware 5.4.3) and cannot be exported. Each sits in the
OpenPGP signature slot with Ed25519 attributes and the touch policy `fixed`:
every signature needs the PIN and a physical touch, and the policy cannot be
switched off without resetting the OpenPGP application, which destroys the key.
Other applications on the devices are unrelated to release signing.

| Key | OpenPGP fingerprint | Created (UTC) |
| --- | --- | --- |
| A | `4094E98D859610E7FCF38A57762BBD1FB90D13AD` | 2026-11-19T15:59:55Z |
| B | `14EDB3365D0CAAB96489F62AC95621E7955C0079` | 2026-11-19T16:14:31Z |

The card computes plain RFC 8032 Ed25519 (PureEdDSA) over the complete manifest
bytes, so the signature format and every verifier are unchanged. YubiKey 5
OpenPGP accepts at most 3070 bytes of signature input; the publisher therefore
refuses any manifest above 2560 bytes (`releasecard.MaxManifestSize`) for every
key type, and a test keeps the current manifest well below that bound. Signing
vectors produced by both devices during the ceremony are kept in
`internal/releasecard/testdata`.

Sign over USB. Key B also works through an NFC reader, but over NFC presence in
the field satisfies the touch policy, so NFC is only a fallback. Store key B
apart from key A. Keep each device's OpenPGP PIN and admin PIN in a password
manager, labelled with the device serial; three wrong admin PIN entries lock the
OpenPGP application, and recovery means a reset that destroys the key.

## Relation to ADR 0040

Keys A and B are the hardware keys `H1` and `H2` of
[ADR 0040](adr/0040-signed-core-store.md). That design is not implemented yet;
until it is, a schema 1 manifest carries one signature from a hardware key.
Implementing it moves this list into `release/trust.json` with the YubiKey
attestation material, adds the offline release key `R2`, and requires `R2` plus
a hardware key for every release. Store-era builds never trust
`7370a2d8cf890e5e`. The OpenPGP attestation for each key can be exported at any
time with `ykman openpgp keys attest sig` while the device is connected.

## Ceremony and signing tools

`scripts/release-card.go` lists cards, shows public metadata, generates a key in
an empty signature slot (it refuses to replace an existing key), and runs a
signing self-test. `scripts/release-manifest.go` signs with a card when
`BIMERON_RELEASE_CARD_SERIAL` is set; see [RELEASE_UPDATES.md](RELEASE_UPDATES.md).
Both read PINs from the console without echo and never print them. Hardware
signing is implemented for Windows PC/SC.

## Adding, rotating and retiring keys

A verifier trusts only the keys compiled into its release; nothing can add a
key remotely. To add a key:

1. Generate it on a new device with `release-card generate` and run
   `release-card selftest`.
2. Add its public key and `key_id` to this page, to Desktop's trust store and,
   when it will sign Core releases, to `repairUpdateKeys`.
3. Release Desktop (and Core) with the new trust list.
4. Sign with the new key only after the supported update window lets users
   reach that Desktop release.

To retire a key, stop signing with it, then remove it from Desktop's trust store
after no supported Desktop update path needs releases it signed. Retire
`7370a2d8cf890e5e` this way: no new release uses it, and Desktop drops it once
releases up to `v0.4.0-beta.2` leave the supported update window. Removal does
not revoke a key in Desktop versions already installed. Treat a lost or
compromised key as an incident: sign with the other hardware key and ship a
Desktop release without the affected key promptly.
