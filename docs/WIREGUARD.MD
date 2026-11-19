# WireGuard and AmneziaWG

Status: **experimental**. Bimeron is a WireGuard and AmneziaWG (AWG) client.
Live validation is planned on Windows and Linux. Android and Apple builds
compile and pass unit tests, but they have **not been validated live**.

Tracking issue: [#202](https://github.com/bimeron/bimeron-core/issues/202).

## Profile sources

A WireGuard profile uses one peer. Bimeron reads the standard wg-quick or AWG
text in one of two ways.

1. Recommended: a separate file, stored byte for byte:

   ```ini
   [Profile]
   Version = 1
   Name = Home

   [AccessKey]
   File = home.wg.conf

   [Interface]
   Mode = vpn

   [Routing]
   Default = proxy
   ```

   A relative `File` path is resolved against the profile's directory. Core
   recognizes the content: wg-quick text becomes a WireGuard profile, and any
   other content is read as a URI key as before. The size limit is 64 KiB of
   UTF-8. A BOM and CRLF line endings are accepted and kept. Core never
   rewrites the file. In-memory profiles (`ParseData`, Android and Apple
   embedding) cannot read files, so they use the explicit form below.

2. Explicit options in `[AccessKey]` (CLI, embedding and editors):

   ```ini
   [AccessKey]
   Type = wireguard
   PrivateKey = <base64>
   Address = 10.8.0.2/32, fd00::2/128
   PublicKey = <base64>
   Endpoint = vpn.example.com:51820
   AllowedIPs = 0.0.0.0/0, ::/0
   Jc = 4
   ```

   The option names are the same as in wg-quick text, and `Endpoint` is used
   instead of `Server`/`Port`. Problems point to the `[AccessKey]` option.

## WireGuard text

Section names and keys are matched case-insensitively, as in wg-quick. Edits
and `fields` use the canonical spelling shown here. A `#` starts a comment,
including at the end of a line. Lines with an empty value are treated as unset,
except for required keys.

| Section | Key | Notes |
|---|---|---|
| Interface | `PrivateKey` | Required. 32 bytes in base64, not all zero. Secret. |
| Interface | `Address` | Required. A list of IPv4/IPv6 addresses or prefixes; may repeat. These are the tunnel addresses. |
| Interface | `DNS` | A list of IP addresses (no search domains); may repeat. |
| Interface | `MTU` | 576–9000. Tunnel MTU; the default is 1420. IPv6 addresses need at least 1280. |
| Interface | `ListenPort` | 0–65535. The local UDP port. |
| Peer | `PublicKey` | Required. Not all zero. |
| Peer | `PresharedKey` | Optional. Secret. |
| Peer | `Endpoint` | Required. `host:port`; IPv6 goes in brackets. |
| Peer | `AllowedIPs` | Required. A list of prefixes; may repeat. |
| Peer | `PersistentKeepalive` | `off`, 0–65535, or an AWG 3 range `lo-hi`. |

These keys are refused with a problem:

- `PreUp`, `PostUp`, `PreDown`, `PostDown`: `wireguard_hook_unsupported`.
- `Table`, `FwMark`, `SaveConfig`: `option_not_supported`.
- Any other key, including the AWG 1.5 drafts `J1`–`J3` and `Itime`: `option_unknown`.
- Sections other than `[Interface]` and `[Peer]`: `section_unknown`.
- Zero or several `[Peer]` sections: `wireguard_peer_count`.

### AmneziaWG options

All AWG options go in `[Interface]`. The protocol is reported as `amneziawg`
when any AWG option is set. `awg_version` is the oldest version that has all
the options in use.

| Version | Options |
|---|---|
| 1.0 | `Jc` (0–128), `Jmin`, `Jmax` (0–65507, `Jmin` ≤ `Jmax`), `S1` (0–65359), `S2` (0–65415), `H1`–`H4` (single uint32 values) |
| 1.5 | `I1`–`I5`: signature packets written as tags `<b 0xHEX>`, `<r N>`, `<rc N>`, `<rd N>`, `<t>`, plus the data tags `<d>`, `<ds>` and `<dz N>` (a size field of 1–8 bytes). `0x` before hex bytes is optional. One packet is at most 65,507 bytes |
| 2.0 | `S3` (0–65443), `S4`; `H1`–`H4` as ranges `lo-hi`. `S4` plus 32, the tunnel MTU and the largest `ContentPaddingAddition` must fit 65,507 bytes |
| 3.0 | `HeaderProtectionKey` (base64, secret; requires every S1–S4 to be at least 12), `ContentPaddingAddition` (range), `RekeyAfterTime`, `RekeyTimeout`, `RejectAfterTime`, `KeepaliveTimeout`, `MaxHandshakeAttempts` (ranges, at least 1); `PersistentKeepalive` as a range |
| 3.1 | `RandomTrailers`, `DisableCookies` (`true`, `false`, `on`, `off`) |

H1–H4 must not overlap. Unset values count as 1, 2, 3 and 4, which are the
plain WireGuard message types. Server-side options (H1–H4, S1–S4,
`HeaderProtectionKey`, `RandomTrailers`) must match the server. Client-side
options (`Jc`, `Jmin`, `Jmax`, `I1`–`I5`, timers, `DisableCookies`) need not.

## Mapping to Bimeron settings

- `Address`, `DNS` and `MTU` in the WireGuard text describe the tunnel, not
  Bimeron's own TUN adapter.
- Bimeron `[Interface] MTU` (default 1420) is the system TUN. WireGuard `MTU`
  (default 1420) is the tunnel. They are independent.
- DNS: when the profile has no `[Interface] DNS`, Bimeron's resolver uses the
  WireGuard `DNS` entries, at most four IPv4 addresses in order. IPv6 entries
  are not used, because Bimeron's resolver forwards to IPv4 servers only. An
  explicit `[Interface] DNS` wins. With neither, the default is 1.1.1.1. DNS
  queries are routed like other traffic.
- `Mode = proxy` (SOCKS5, TCP only), `IPv6 = disable` and `KillSwitch` work as
  for other upstreams.

### AllowedIPs priority

`[Routing] AllowedIPsMode` chooses how AllowedIPs combines with Bimeron rules.
It is valid only for WireGuard profiles; on other profiles it fails with
`allowed_ips_mode_requires_wireguard`.

| Value | Behavior |
|---|---|
| `direct` (default) | Bimeron rules decide. Proxy traffic outside AllowedIPs goes direct. |
| `block` | Bimeron rules decide. Proxy traffic outside AllowedIPs is blocked. |
| `ignore` | All proxy traffic goes into the tunnel; Core configures the peer with `0.0.0.0/0, ::/0`. |
| `only` | Bimeron `[Rule]` sections and `Default` are not applied to this profile. Traffic inside AllowedIPs uses the tunnel and everything else goes direct, as with plain WireGuard. |

These rules always hold:

- Block rules win in `direct`, `block` and `ignore`.
- Direct rules apply inside AllowedIPs too.
- When AllowedIPs covers all of IPv4 but not all of IPv6 (`coverage` =
  `ipv4_only`), IPv6 traffic that would go direct only because it is outside
  AllowedIPs is blocked. This applies in `direct` and `only`.
- With full coverage, `direct`, `block` and `ignore` behave the same.

## Share links

`bimeron wireguard` `import_uri` turns links into wg-quick text.

- `vpn://` (Amnezia): base64url of Qt qCompress output (a 4-byte big-endian
  length followed by zlib). Uncompressed JSON is also accepted.
  - Bimeron takes the `amnezia-awg2`, `amnezia-awg` or `amnezia-wireguard`
    container. `defaultContainer` wins when it is one of them.
  - It uses `last_config.config`, fills `$PRIMARY_DNS`/`$SECONDARY_DNS` from
    `dns1`/`dns2`, and applies `last_config.mtu` when the text has no MTU.
  - Other protocols only: `vpn_uri_container_missing`.
  - Amnezia Premium/Free service keys (`config_version`, `api_config`,
    `auth_data`, `api_key`, `api_endpoint`): `vpn_uri_api_key_unsupported`.
  - A damaged payload or `format_version` above 1: `vpn_uri_invalid`.
  - This is an independent implementation of the observed format.
- `wireguard://` and `wg://` (v2rayN/v2rayNG, Hiddify, Throne/NekoRay).
  - The private key comes from the userinfo or from `privatekey`/`pk`.
  - Parameter names are compared in lowercase, ignoring `_` and `-`. Accepted
    aliases: `publickey`/`peerpublickey`/`pub`/`peerpub`/`peerpk`,
    `presharedkey`/`psk`, `address`/`ip`/`localaddress` (Throne's
    `-`-separated lists too), `allowedips` (default `0.0.0.0/0, ::/0`),
    `keepalive`/`persistentkeepalive`/`persistentkeepaliveinterval`, `mtu`,
    `dns`, `enable_amnezia`, and every AWG option name.
  - Key spaces are restored to `+`, and base64url and hex header-protection
    keys are converted.
  - A non-zero `reserved` (Cloudflare WARP) fails with
    `wireguard_reserved_unsupported` ([#208](https://github.com/bimeron/bimeron-core/issues/208)).
  - Unknown or duplicate parameters fail with `uri_option_unsupported`.
  - `awg://` is not supported.

## Desktop document bridge

`bimeron wireguard` follows the same framing as `bimeron document` (see
[DESKTOP_DOCUMENT_API.MD](DESKTOP_DOCUMENT_API.MD)):

- Run it with no arguments. Write exactly one UTF-8 JSON object, at most 1 MiB,
  to stdin, then read one JSON object followed by LF from stdout.
- Protocol and operation failures exit with zero; inspect `problems`.
- Unknown members, trailing JSON and a version other than `1` are rejected
  with `invalid_request`.
- The text limit is 65,536 bytes before and after every operation.
- The bridge never touches files, DNS or the network.
- A response that contains `text` or `fields` carries secrets.

| op | Members | Result |
|---|---|---|
| `capabilities` | — | `capabilities` (the object below) |
| `detect` | `text` | `format`: `bimeron` or `wireguard`, or problem `document_format_unknown` / `document_format_ambiguous` |
| `inspect` | `text` | inspection |
| `edit` | `text`, `operations` | inspection plus `text` |
| `import_uri` | `uri` | inspection plus `text` and `name`, or only `problems` when the link cannot be converted |

Detection treats text as `wireguard` when it has a `[Peer]` section, or a
`PrivateKey` in `[Interface]`, and no Bimeron-only section (`Profile`,
`AccessKey`, `Routing`, `Rule`, `GeoData`, `IKEv2`, `ShadowTLS`). Text with only
Bimeron-only sections is `bimeron`. Text with both kinds is ambiguous, and text
with neither is unknown.

Inspection members:

- `format`, `protocol` (`wireguard`/`amneziawg`), `awg_version` (`""` or a version).
- `fields`: a flat object of `"Section/Key"` to the decoded value. Repeated
  list keys are joined with `", "`.
- `fields_error`: set instead of `fields` when the structure is ambiguous: a
  duplicate `[Interface]`, several `[Peer]` sections, a duplicate non-list
  key or a malformed line. Use raw editing then.
- `secret_fields`: `Interface/PrivateKey`, `Peer/PresharedKey` and
  `Interface/HeaderProtectionKey`.
- `allowed_ips`: `prefixes`, `ipv4` and `ipv6` (each `full`, `partial` or
  `none`), and `coverage`. Coverage is `full` when both families are covered,
  `ipv4_only` when IPv4 is full and IPv6 is not, and `partial` otherwise.
  Core computes the union, so `0.0.0.0/1` with `128.0.0.0/1` counts as full.
- `problems`: the full validation result, `[]` when the text is runnable.
  Inspection returns `fields` even when validation fails.

An `edit` operation is `{"op":"set_field","section":"Interface"|"Peer","key":K,"value":V}`.

- A non-empty value replaces the first occurrence of the key, keeping its
  spelling, spacing, comment and line ending. Other occurrences of a list key
  are removed.
- A missing key is appended after the last non-blank line of its section.
- A missing section is created. `[Interface]` always comes before `[Peer]`, and
  keys in a new section follow the order of the operations.
- `value: ""` removes every line of the key.
- Keys must use the canonical spelling. Values containing `#`, CR or LF, or
  with spaces at either end, fail with `value_has_invalid_characters`.
- A batch holds at most 256 operations; more fail with `invalid_request`.
- Operations run in order. Any failure returns the original text and its
  inspection, with `error` and the failing problem.
- An edit does not validate the result; check `problems` in the response.

Problems located in WireGuard text carry `"document": "wireguard"`. Their
`section`, `field` and `line` then refer to that text. When the text was
read through `[AccessKey] File`, `source` is `File`. A missing or unreadable
file reports `file_unreadable` (or `file_not_regular`, `file_path_not_local`,
`file_too_large`) at `AccessKey`/`File` without the `document` marker. Text that mixes WireGuard and Bimeron sections fails with
`document_format_ambiguous` (`document: "wireguard"`, `source: "File"`)
instead of being read as a URI key.

### Capabilities

`hello.capabilities.wireguard` and `bimeron wireguard` `capabilities` report:

```json
{"supported":true,"experimental":true,"protocols":["wireguard","amneziawg"],
 "awg_versions":["1.0","1.5","2.0","3.0","3.1"],"uri_schemes":["vpn","wireguard","wg"],
 "allowed_ips_modes":["direct","block","ignore","only"],"document_api":1}
```

Older daemons omit the object. An older CLI answers `bimeron wireguard` with an
unknown-command error and a nonzero exit.

## Runtime

Design record: [ADR 0041](adr/0041-wireguard-amneziawg-client.md).

- Engine: `github.com/amnezia-vpn/amneziawg-go/v3` `v3.1.20261116` (MIT) with
  its gVisor netstack. Plain WireGuard runs on the same engine without
  AmneziaWG options.
- The WireGuard UDP socket is opened through the session's outbound path
  (desktop interface binding, Android protect, Apple host network), so it
  never loops into Bimeron's TUN. The kill switch already permits the core's
  own sockets. Datagrams from other sources are dropped.
- The endpoint name is resolved on the outbound path for each session
  generation. Every reconnect, including one after a network change, starts
  a new device and resolves the name again.
- The session reports connected only after a completed handshake (up to 20
  seconds), followed by the usual transport check. A missing handshake fails
  with the retryable `wireguard_handshake_timeout`. Health checks force a
  handshake when the last one is older than 150 seconds.
- AllowedIPs scope applies to all upstream traffic, including DNS queries
  and checks. Names given to the SOCKS5 server are resolved through Bimeron's
  DNS servers, and those queries follow the scope too.
- UDP datagrams larger than the tunnel MTU are fragmented by the inner
  stack. Each UDP socket is limited to 64 tunnel destinations and 64 queued
  replies.
- The engine logger is silent. Keys never appear in logs, status, problems or
  diagnostics.

## Compatibility matrix

| Server | Client profile | Loopback CI test | Live check |
|---|---|---|---|
| upstream `wireguard-go` | plain WireGuard | yes: TCP, UDP, IPv6, fragmented UDP | pending |
| `amneziawg-go` without options | plain WireGuard | yes | pending |
| `amneziawg-go` 1.0 options | AWG 1.0 | yes | pending |
| `amneziawg-go` with client-side I1–I5 | AWG 1.5 | yes | pending |
| `amneziawg-go` 2.0 options (S3/S4, H ranges) | AWG 2.0 | yes | pending |
| `amneziawg-go` 3.1 options (header protection, random trailers, disabled cookies, timers, content padding) | AWG 3.x | yes | pending |
| mismatched AWG options or keys | — | yes: handshake fails | — |

Platforms: Windows and Linux will be checked live. Android (AAR) and Apple
builds compile and their unit tests pass, but they have **not been
validated live**.

## Tests

`internal/wgconf` contains parser, editor and importer tests and the fuzz
targets `FuzzParse`, `FuzzEdit` and `FuzzImportURI`. `internal/wireguard`
starts in-process reference servers (`internal/wireguard/wgtest`) on
127.0.0.1: upstream `wireguard-go` and `amneziawg-go` in 1.x, 2.0 and 3.1
modes. Run these tests in CI or on a test VM, not on a machine whose network
depends on an installed Bimeron:

```sh
go test ./internal/wgconf ./internal/wireguard/... ./internal/config ./cmd/bimeron ./core -run 'WireGuard|AWG|AmneziaWG|Upstream|Import|Edit|Parse|Coverage|Detect'
go test ./internal/wgconf -run '^$' -fuzz '^FuzzParse$' -fuzztime 30s
```
