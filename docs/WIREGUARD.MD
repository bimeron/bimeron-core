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
   recognizes the content with the same rule as `detect` (see
   [Desktop document bridge](#desktop-document-bridge)): wg-quick text becomes
   a WireGuard profile, and any other content is read as a URI key as before.
   The size limit is 64 KiB of UTF-8. A BOM and CRLF line endings are accepted
   and kept. Core never rewrites the file. In-memory profiles
   (`LoadConfigData`, Android and Apple embedding) cannot read files, so they
   use the explicit form below.

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
   instead of `Server`/`Port`. Each option appears once; write lists
   comma-separated. Problems point to the `[AccessKey]` option and carry no
   `document` marker. `Server`, `Port`, `Method`, `Password`, `Prefix`,
   `Username`, `ServerName` and VLESS options other than `PublicKey` fail with
   `option_not_supported`. WireGuard options without `Type = wireguard` fail
   with `option_requires_type`.

## WireGuard text

Section names and keys are matched case-insensitively, as in wg-quick. Edits
and `fields` use the canonical spelling shown here. A `#` starts a comment,
including at the end of a line. Lines with an empty value are treated as unset,
except for required keys.

| Section | Key | Notes |
|---|---|---|
| Interface | `PrivateKey` | Required. 32 bytes in base64, not all zero. Secret. |
| Interface | `Address` | Required. A list of distinct IPv4/IPv6 addresses or prefixes; may repeat. These are the tunnel addresses. |
| Interface | `DNS` | Up to 8 IP addresses (no search domains); may repeat. |
| Interface | `MTU` | 576–9000. Tunnel MTU; the default is 1420. An explicit MTU below 1280 fails when `Address` has an IPv6 address. |
| Interface | `ListenPort` | 0–65535. The local UDP port; 0 or unset picks a free port. |
| Peer | `PublicKey` | Required. Not all zero. |
| Peer | `PresharedKey` | Optional. Secret. |
| Peer | `Endpoint` | Required. `host:port` with port 1–65535; IPv6 goes in brackets. |
| Peer | `AllowedIPs` | Required. A list of prefixes or bare addresses; may repeat. |
| Peer | `PersistentKeepalive` | `off`, 0–65535, or an AWG 3 range `lo-hi`. |

Value problems: `wireguard_key_invalid` (keys are 32 bytes in standard
base64), `wireguard_address_invalid`, `wireguard_allowed_ips_invalid`,
`wireguard_endpoint_invalid`, `wireguard_dns_invalid` (search domains or
non-IP entries), and shared codes such as `number_invalid`,
`number_out_of_range`, `port_invalid`, `host_invalid` and `dns_too_many`.

These keys and layouts are refused with a problem:

- `PreUp`, `PostUp`, `PreDown`, `PostDown`: `wireguard_hook_unsupported`.
- `Table`, `FwMark`, `SaveConfig`: `option_not_supported`.
- Any other key, including the AWG 1.5 drafts `J1`–`J3` and `Itime`: `option_unknown`.
- Sections other than `[Interface]` and `[Peer]`: `section_unknown`.
- Zero or several `[Peer]` sections: `wireguard_peer_count`.
- A duplicate `[Interface]`: `section_duplicate`. A missing `[Interface]` or
  required key: `value_required`.
- A repeated key other than the list keys `Address`, `DNS` and `AllowedIPs`:
  `option_duplicate`. A line that is neither a header nor `key = value`:
  `syntax_invalid`.

### AmneziaWG options

All AWG options go in `[Interface]`. The protocol is reported as `amneziawg`
when any AWG option or a `PersistentKeepalive` range is set. `awg_version` is
the oldest version that has all the options in use.

| Version | Options |
|---|---|
| 1.0 | `Jc` (0–128), `Jmin`, `Jmax` (0–65507, `Jmin` ≤ `Jmax`), `S1` (0–65359), `S2` (0–65415), `H1`–`H4` (single uint32 values) |
| 1.5 | `I1`–`I5`: signature packets written as tags `<b 0xHEX>`, `<r N>`, `<rc N>`, `<rd N>`, `<t>`, plus the data tags `<d>`, `<ds>` and `<dz N>` (a size field of 1–8 bytes). `0x` before hex bytes is optional. One packet is at most 65,507 bytes |
| 2.0 | `S3` (0–65443), `S4`; `H1`–`H4` as ranges `lo-hi`. `S4` plus 32 and the tunnel MTU must fit 65,507 bytes (the engine caps `ContentPaddingAddition` itself) |
| 3.0 | `HeaderProtectionKey` (base64, secret; requires every S1–S4 to be at least 12), `ContentPaddingAddition` (range), `RekeyAfterTime`, `RekeyTimeout`, `RejectAfterTime`, `KeepaliveTimeout`, `MaxHandshakeAttempts` (ranges, at least 1); `PersistentKeepalive` as a range |
| 3.1 | `RandomTrailers`, `DisableCookies` (`true`, `false`, `on`, `off`, `1`, `0`) |

H1–H4 must not overlap. Unset values count as 1, 2, 3 and 4, which are the
plain WireGuard message types. Server-side options (H1–H4, S1–S4,
`HeaderProtectionKey`, `RandomTrailers`) must match the server. Client-side
options (`Jc`, `Jmin`, `Jmax`, `I1`–`I5`, timers, `DisableCookies`) need not.

AWG problems: `awg_range_invalid` (a range or `Jmin`/`Jmax` in the wrong
order), `awg_header_overlap`, `awg_header_protection_requires_padding`
(`args.min` is 12), `awg_tag_invalid` (I1–I5) and `boolean_invalid`.

## Mapping to Bimeron settings

- The WireGuard text is the source of `DNS` and `MTU` for these profiles.
  Editors show them as the profile's DNS and MTU and write them into the
  WireGuard text. `Address` holds the tunnel addresses.
- MTU: the WireGuard `MTU` is the tunnel MTU and also the system adapter MTU,
  clamped to the adapter range 1280–1500. Without it both stay automatic
  (1420). Import never adds an `MTU` line.
- DNS: Bimeron's resolver uses the WireGuard `DNS` entries: the first four
  distinct unicast IPv4 addresses, in order. IPv6 entries are not used,
  because Bimeron's resolver forwards to IPv4 servers only. Without usable
  entries the resolver uses 1.1.1.1 followed by 1.0.0.1. DNS queries are routed like other
  traffic, so a resolver outside AllowedIPs follows `AllowedIPsMode`.
- A Bimeron `[Interface] MTU` or `DNS` in a WireGuard profile is ignored when
  connecting, including profiles written by older versions: the WireGuard
  value wins on a conflict, and a missing WireGuard line means automatic
  behavior, not the old Bimeron value. Other protocols are unchanged.
- `Mode = proxy` (SOCKS5, TCP only), `IPv6 = disable` and `KillSwitch` work as
  for other upstreams.

### AllowedIPs priority

`[Routing] AllowedIPsMode` chooses how AllowedIPs combines with Bimeron rules.
It is valid only for WireGuard profiles; on other profiles it fails with
`allowed_ips_mode_requires_wireguard`. Another value fails with
`choice_invalid`.

| Value | Behavior |
|---|---|
| `direct` (default) | Bimeron rules decide. Proxy traffic outside AllowedIPs goes direct. |
| `block` | Bimeron rules decide. Proxy traffic outside AllowedIPs is blocked. |
| `ignore` | All proxy traffic goes into the tunnel; Core configures the peer with `0.0.0.0/0, ::/0`. |
| `only` | Bimeron `[Rule]` sections and `Default` are not applied to this profile. Traffic inside AllowedIPs uses the tunnel and everything else goes direct, as with plain WireGuard. |

These rules always hold:

- Block rules win in `direct`, `block` and `ignore`.
- In these modes direct rules apply inside AllowedIPs too.
- When AllowedIPs covers all of IPv4 but not all of IPv6 (`coverage` =
  `ipv4_only`), IPv6 traffic that would go direct only because it is outside
  AllowedIPs is blocked. This applies in `direct` and `only`.
- With full coverage, `direct`, `block` and `ignore` behave the same.
- A connection that the scope sends into the tunnel fails when `Address` has
  no address of its family.

### Windows adapter name

On Windows the VPN adapter of a WireGuard profile is named after the
recognized protocol and the configuration: `Bimeron WG — <label>` or
`Bimeron AWG — <label>`. The label is the WireGuard file name without
`.conf`, or the profile name for explicit `Type = wireguard` options. The
adapter description stays `Bimeron Tunnel`.

- This generated name is separate from `[Interface] Name`, which keeps its
  portable rule (1–32 ASCII letters, digits, `_`, `-`) for other profiles and
  platforms.
- Whitespace is collapsed. Control and format characters (including bidi
  controls) are removed. The PowerShell wildcard characters `*`, `?`, `[`,
  `]` and `` ` `` become `_`, because the network scripts look adapters up
  by name. The label is limited to 48 characters and the whole name to 100
  UTF-16 units. A label that is empty after cleanup gives `Bimeron WG` or
  `Bimeron AWG`.
- An adapter of another owner with the same name is never touched: the
  session fails with `adapter_name_in_use`. A stale Bimeron adapter left by
  a crash is reused under the same name.
- Other platforms keep `[Interface] Name`.

## Running a WireGuard file directly

For step-by-step commands and connection checks, see the
[WireGuard CLI guide](WIREGUARD_CLI.MD).

`bimeron run <file.conf>` and `bimeron connect -config <file.conf>` accept a
plain WireGuard or AmneziaWG file as well as a Bimeron profile; the format is
detected from the content. A WireGuard file runs as an in-memory VPN profile,
the way wg-quick would run it:

- `AllowedIPsMode = only`: AllowedIPs alone decide what uses the tunnel.
- DNS and MTU come from its `[Interface]`; without them the defaults apply.
- The profile is named after the file without `.conf`, which also names the
  Windows adapter.
- Nothing is written to disk. Ctrl+C stops the session and restores the
  network settings it changed.

`bimeron proxy [-listen 127.0.0.1:1080] [-policy file.json] <file.conf>` runs
such a file as a loopback SOCKS5 proxy (TCP), without an adapter, routes or
system DNS changes. AllowedIPs decide what uses the tunnel; with `-policy`
the policy decides and destinations outside AllowedIPs go direct. Other key
files keep their previous handling.

## Share links

`bimeron wireguard` `import_uri` turns links into wg-quick text. A link is
at most 65,536 bytes (`value_too_long`). Other schemes fail with
`uri_scheme_invalid`. A converted link that does not validate still returns
its text; the inspection's `problems` report why.

- `vpn://` (Amnezia): base64url of Qt qCompress output (a 4-byte big-endian
  length followed by zlib). Standard base64 and uncompressed JSON are also
  accepted. The decoded JSON is at most 1 MiB.
  - Bimeron takes the `amnezia-awg2`, `amnezia-awg` or `amnezia-wireguard`
    container, in that order. `defaultContainer` wins when it is one of them.
  - It uses `last_config.config`, fills `$PRIMARY_DNS`/`$SECONDARY_DNS` from
    `dns1`/`dns2` (IP addresses only; empty entries are dropped), and applies
    `last_config.mtu` when the text has no MTU. The suggested name is
    `description`, or `name` when that is empty.
  - Other protocols only: `vpn_uri_container_missing`.
  - Amnezia Premium/Free service keys (`config_version`, `api_config`,
    `auth_data`, `api_key`, `api_endpoint`): `vpn_uri_api_key_unsupported`.
  - A damaged payload, `format_version` above 1 or any other `$` placeholder
    left in the text: `vpn_uri_invalid`.
  - This is an independent implementation of the observed format.
- `wireguard://` and `wg://` (v2rayN/v2rayNG, Hiddify, Throne/NekoRay).
  - The endpoint is the link's `host:port`; a missing host or port fails with
    `wireguard_endpoint_invalid`. The fragment is the suggested name.
  - The private key comes from the userinfo or from `privatekey`/`secretkey`/`pk`.
    A userinfo password fails with `uri_credentials_invalid`.
  - Parameter names are compared in lowercase, ignoring `_` and `-`. Accepted
    aliases: `publickey`/`peerpublickey`/`pub`/`peerpub`/`peerpk`,
    `presharedkey`/`psk`, `address`/`ip`/`localaddress` (Throne's
    `-`-separated lists too), `allowedips` (default `0.0.0.0/0, ::/0`),
    `keepalive`/`persistentkeepalive`/`persistentkeepaliveinterval`, `mtu`,
    `dns`, `enable_amnezia`, and every AWG option name.
  - `enable_amnezia=false` together with an AWG option fails with
    `uri_option_unsupported`. `RandomTrailers` and `DisableCookies` also
    accept `1`/`0` and `yes`/`no`.
  - In key parameters, spaces are restored to `+`, and base64url keys and
    64-digit hex keys are converted to standard base64.
  - A non-zero `reserved` (Cloudflare WARP) fails with
    `wireguard_reserved_unsupported` ([#208](https://github.com/bimeron/bimeron-core/issues/208)).
    An all-zero `reserved` is ignored.
  - Unknown or duplicate parameters fail with `uri_option_unsupported`.
  - `awg://` is not supported.

## Desktop document bridge

`bimeron wireguard` follows the same framing as `bimeron document` (see
[DESKTOP_DOCUMENT_API.MD](DESKTOP_DOCUMENT_API.MD)):

- Run it with no arguments. Write exactly one UTF-8 JSON object, at most 1 MiB,
  to stdin, then read one JSON object followed by LF from stdout.
- A request is `{"version":1,"op":...}` plus the members of its operation.
  Every response has `"version": 1`.
- Protocol and operation failures exit with zero. A failed request adds
  `"error": "request failed"` and the failing problem in `problems`.
- Unknown members, trailing JSON, a version other than `1`, an unknown `op`
  and members that do not belong to the operation are rejected with
  `invalid_request`.
- The text limit is 65,536 bytes before and after every operation
  (`file_too_large`). A request that is not valid UTF-8 fails with
  `invalid_request`.
- The bridge never touches files, DNS or the network.
- A response that contains `text` or `fields` carries secrets.

| op | Members | Result |
|---|---|---|
| `capabilities` | — | `capabilities` (the object below) |
| `detect` | `text` | `format`: `bimeron` or `wireguard`, or problem `document_format_unknown` / `document_format_ambiguous` |
| `inspect` | `text` | inspection |
| `edit` | `text`, `operations` | inspection plus `text` |
| `import_uri` | `uri` | inspection plus `text` and `name` (`""` when the link has none), or only `problems` when the link cannot be converted |

Detection treats text as `wireguard` when it has a `[Peer]` section, or a
`PrivateKey` in `[Interface]`, and no Bimeron-only section (`Profile`,
`AccessKey`, `Routing`, `Rule`, `GeoData`, `IKEv2`, `ShadowTLS`). Text with a
Bimeron-only section and neither WireGuard marker is `bimeron`. Text with both
kinds is ambiguous, and text with neither is unknown. Section names are
matched case-insensitively.

Inspection members:

- `format`, `protocol` (`wireguard`/`amneziawg`), `awg_version` (`""` or a version).
- `fields`: a flat object of `"Section/Key"` to the value as written, for
  recognized keys with a non-empty value. Repeated list keys are joined with
  `", "`.
- `fields_error`: set instead of `fields` when the structure is ambiguous: a
  duplicate `[Interface]`, several `[Peer]` sections, a duplicate non-list
  key or a malformed line. Use raw editing then.
- `secret_fields`: `Interface/PrivateKey`, `Peer/PresharedKey` and
  `Interface/HeaderProtectionKey`.
- `allowed_ips`: `prefixes` (valid entries in text order, normalized to their
  network address), `ipv4` and `ipv6` (each `full`, `partial` or `none`), and
  `coverage`. Coverage is `full` when both families are covered, `ipv4_only`
  when IPv4 is full and IPv6 is not, and `partial` otherwise. Core computes
  the union, so `0.0.0.0/1` with `128.0.0.0/1` counts as full.
- `problems`: validation problems, `[]` when the text is runnable. Validation
  stops at the first problem, so the list has at most one element today.
  Inspection returns `fields` even when validation fails.

An `edit` operation is `{"op":"set_field","section":"Interface"|"Peer","key":K,"value":V}`.

- A non-empty value replaces the first occurrence of the key, keeping its
  spelling, spacing, comment and line ending. Other occurrences of a list key
  are removed.
- A missing key is appended after the last non-blank line of its section.
- A missing section is created. `[Interface]` always comes before `[Peer]`, and
  keys in a new section follow the order of the operations.
- `value: ""` removes every line of the key.
- Keys must use the canonical spelling; other keys fail with
  `option_unknown`, and other sections with `section_unknown`. Values
  containing `#`, CR or LF, or with spaces at either end, fail with
  `value_has_invalid_characters`.
- Editing a key that appears twice outside a list fails with
  `option_duplicate`; editing a section that appears twice fails with
  `section_ambiguous`.
- `value` is required. A batch holds at most 256 operations; more, or an
  `op` other than `set_field`, fail with `invalid_request`.
- Operations run in order. Any failure returns the original text and its
  inspection, with `error` and the failing problem.
- An edit does not validate the result; check `problems` in the response.

Problems located in WireGuard text carry `"document": "wireguard"`. Their
`section`, `field` and `line` then refer to that text. When the text was
read through `[AccessKey] File`, `source` is `File`. A missing or unreadable
file reports `file_unreadable` (or `file_not_regular`, `file_path_not_local`,
`file_too_large`, `file_not_utf8`) at `AccessKey`/`File` without the
`document` marker. Text that mixes WireGuard and Bimeron sections fails with
`document_format_ambiguous` (`document: "wireguard"`, `source: "File"`, no
section or field) instead of being read as a URI key.

### Capabilities

`hello.capabilities.wireguard` and `bimeron wireguard` `capabilities` report:

```json
{"supported":true,"experimental":true,"protocols":["wireguard","amneziawg"],
 "awg_versions":["1.0","1.5","2.0","3.0","3.1"],"uri_schemes":["vpn","wireguard","wg"],
 "allowed_ips_modes":["direct","block","ignore","only"],"document_api":1,
 "key_operations":["generate_keypair","public_key","generate_preshared_key"]}
```

The values are static for the build and the same on every desktop platform.
`explicit_access` also lists `wireguard`. Older daemons omit the object; treat
absence as unsupported, and a missing `key_operations` as no key operations.
An older CLI answers `bimeron wireguard` with an unknown-command error and a
nonzero exit. The Android `Capabilities()` and Apple `RLCapabilities()`
results include the object with `document_api` 0 and no `key_operations`:
there is no CLI bridge there, and profiles use explicit `Type = wireguard`
options.

## Runtime

Design record: [ADR 0043](adr/0043-wireguard-amneziawg-client.md).

- Engine: `github.com/amnezia-vpn/amneziawg-go/v3` `v3.1.20261116` (MIT) with
  its gVisor netstack. Plain WireGuard runs on the same engine without
  AmneziaWG options.
- The WireGuard UDP socket is opened through the session's outbound path
  (desktop interface binding, Android protect, Apple host network), so it
  never loops into Bimeron's TUN. The kill switch already permits the core's
  own sockets. Datagrams from other sources are dropped.
- The endpoint name is resolved once for each session generation, preferring
  IPv4 answers, and status reports that physical UDP endpoint. VPN mode
  resolves it on the outbound path; SOCKS5 mode uses the system resolver. A
  name that does not resolve fails with the retryable `endpoint_dns_failed`.
  Every reconnect, including one after a network change, starts a new device
  and resolves the name again. With a fixed `ListenPort`, the old device is
  closed before the new one opens the port. The socket hook may be
  `Control` or `ControlContext` of the outbound dialer.
- The session reports connected only after a completed handshake (up to 20
  seconds). Meanwhile the progress event `wireguard_handshake` is reported.
  In VPN mode a DNS check through the AllowedIPs scope follows
  (`transport_check`); SOCKS5 mode starts its listener right after the
  handshake. There is no public HTTPS check, because its target may lie
  outside AllowedIPs. A missing handshake fails with the retryable
  `wireguard_handshake_timeout`. In VPN mode, health checks force a new
  handshake when the last one is older than 150 seconds and wait until the
  handshake time changes.
- Start failures: `wireguard_socket_failed` (retryable; the outbound UDP
  socket or a fixed `ListenPort` could not be opened),
  `wireguard_platform_limit` (not retryable; packet sizes from S1–S4, `Jmax`,
  I1–I5 or MTU exceed the engine buffers of this platform; Windows and iOS
  use 2,016 and 1,700 bytes, other platforms 65,535) and
  `invalid_wireguard_transport` (not retryable).
- AllowedIPs scope applies to all upstream traffic, including DNS queries
  and checks. Names given to the SOCKS5 server are resolved through Bimeron's
  DNS servers (A and AAAA, one 2-second exchange per server, then the next
  server; NXDOMAIN is final), and those queries follow the scope too. Answers that the scope
  blocks, and tunnel answers of a family the tunnel has no address for, are
  skipped; the rest are tried in order, IPv4 first. A truncated UDP answer is
  retried over TCP.
- UDP datagrams larger than the tunnel MTU are fragmented by the inner
  stack. Each UDP socket is limited to 64 tunnel destinations and 64 queued
  replies. Closing a generation closes every socket and stream it opened,
  including direct ones outside the tunnel.
- The engine logger is silent. Keys never appear in logs, status, problems or
  diagnostics.

## Compatibility matrix

| Server | Client profile | Loopback CI test | Container CI test | Live check |
|---|---|---|---|---|
| upstream `wireguard-go` | plain WireGuard | yes: TCP, UDP, IPv6, fragmented UDP | yes: TCP, UDP, IPv6, fragmented UDP | pending |
| `amneziawg-go` without options | plain WireGuard | yes | yes | pending |
| `amneziawg-go` 1.0 options | AWG 1.0 | yes | yes | pending |
| `amneziawg-go` with client-side I1–I5 | AWG 1.5 | yes | yes | pending |
| `amneziawg-go` 2.0 options (S3/S4, H ranges) | AWG 2.0 | yes | yes | pending |
| `amneziawg-go` 3.1 options (header protection, random trailers, disabled cookies, timers, content padding) | AWG 3.x | yes | yes | pending |
| mismatched AWG options or keys | — | yes: handshake fails | yes: a plain client and a wrong header protection key fail | — |

At Core source `67a7ad97`, the CLI imported `wg://`, `wireguard://`, and
`vpn://` profiles for all six positive rows on Windows 10 and Ubuntu 22.04.
A synthetic test harness exercised the Core engine against reference peers
on guest loopback without a native system VPN session. Encrypted TCP and UDP
traffic resumed after a peer-only UDP interruption of about 2.5 seconds,
before the next natural handshake.

At the same revision, Ubuntu 22.04 native VPN passed with plain WireGuard,
AWG 2.0 and AWG 3.1 via `bimeron run`, and with plain WireGuard via the
daemon. The isolated test checked TUN routing, OS DNS, and TCP/UDP traffic
before and after a peer-only interruption. Foreground WireGuard recovered
after an interruption longer than 170 seconds. Stopping Core restored the
baseline routes, policy rules and resolver and removed the TUN adapter.
The first Windows 10 native WireGuard pilot connected and stopped. Management
errors interrupted its data-plane and rollback checks. A follow-up using
`bimeron run` passed plain WireGuard, AWG 2.0 and AWG 3.1 against synthetic
peers on Ubuntu. It verified Wintun IPv4 split routes, NRPT and the Core DNS
proxy, and IPv4 TCP/UDP traffic. Traffic and DNS recovered automatically
after each peer-only UDP interruption of about five seconds. Stopping Core
restored the baseline adapters, routes, DNS, NRPT and service state.
Windows daemon operation and recovery after a prolonged outage remain
unverified.

An external AWG 3.1 peer passed a scoped Windows amd64 userspace engine check
at Core source `67a7ad97` with server tools `v3.1.20260812`. Profile inspection
reported AWG 3.1, and the initial handshake and IPv4 TCP/UDP payload checks
passed. After a client-only UDP interruption of about three seconds, traffic
resumed in 91 ms without a restart. An explicit client rekey confirmed a
fresh handshake 5.192 seconds after restoration. The temporary runtime peer
was removed, and the server peer inventory and persisted configuration
matched their baselines. External native VPN and daemon checks and checks
against the other external peer profiles remain pending.
[External AWG 3.1 test evidence](https://github.com/bimeron/bimeron-core/issues/207#issuecomment-7067850019)

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

### Reference servers in containers

`TestReferenceContainers` runs the same client against real server
processes with kernel TUN devices, one Docker container per server:
upstream `wireguard-go` (plain WireGuard) and `amneziawg-go` without
options and in AWG 1.0, 1.5, 2.0 and 3.1 modes. Both servers are built from
the module cache at the versions pinned in `go.mod`, as static binaries.
The container entry point is `internal/wireguard/wgtest/refserver`. It
starts the server in the foreground, writes the device configuration to the
server's UAPI socket (`/var/run/wireguard/wg0.sock` or
`/var/run/amneziawg/wg0.sock`), gives `wg0` the addresses `10.77.0.1/24`
and `fd77::1/64` over rtnetlink, and runs TCP and UDP echo on port 7. No
`wg` or `awg` tools are used. Keys are generated for each run.

For every server, the test checks the handshake and TCP and UDP echo over
IPv4 and IPv6, plus a UDP datagram larger than the tunnel MTU. For every AWG
server it also checks that a plain WireGuard client cannot complete a
handshake, and for AWG 3.1 that a wrong header protection key cannot. The
test is skipped unless `BIMERON_WG_REFERENCE_IMAGE` is set. It needs Linux,
the `docker` CLI and a test process that can reach the containers' bridge
addresses. The `test` CI job runs it; to repeat it on a disposable Linux
machine:

```sh
dir="$(mktemp -d)"
go mod download golang.zx2c4.com/wireguard github.com/amnezia-vpn/amneziawg-go/v3
for pair in golang.zx2c4.com/wireguard:wireguard-go github.com/amnezia-vpn/amneziawg-go/v3:amneziawg-go; do
  GOWORK=off CGO_ENABLED=0 go -C "$(go list -m -f '{{.Dir}}' "${pair%%:*}")" build -mod=readonly -trimpath -o "$dir/${pair##*:}" .
done
CGO_ENABLED=0 go build -trimpath -o "$dir/refserver" ./internal/wireguard/wgtest/refserver
tar -C "$dir" -c . | docker import -c 'ENTRYPOINT ["/refserver"]' - bimeron-wireguard-reference:local
BIMERON_WG_REFERENCE_IMAGE=bimeron-wireguard-reference:local go test ./internal/wireguard -run '^TestReferenceContainers$' -count=1 -v
```

## Benchmarks

`BenchmarkTCPBulk` in `internal/wireguard` moves 1 MiB per operation through
one TCP connection and back over loopback. The WireGuard and Shadowsocks
servers run in the same process, so CPU time includes the server and both
WireGuard netstacks. Use the rows to compare implementations, not to
estimate link speed. "native" is amneziawg-go as its own examples use it:
its batched standard bind and netstack, without Bimeron's bind, scope or
resource tracking. It gets the same engine configuration as the Bimeron
client, built from the same client text, including client-side AWG options
such as `Jc`, I1–I5, timers and content padding.

The VLESS row uses Bimeron's VLESS client (TCP, REALITY, Vision) against an
independent Xray server, a separate process on loopback. Its CPU column
covers only the client and the echo server, not Xray. The row is skipped
unless `BIMERON_XRAY_BIN` points to an Xray binary; CI builds Xray
`v1.260327.0` for its interoperability tests.

Linux test VM, 10 vCPU, median of three 3-second runs in one benchmark run
(2026-11-20):

| Path | MB/s | CPU µs per MiB | Heap in use |
|---|---:|---:|---:|
| Bimeron, plain WireGuard | 74 | 62,800 | 20 MiB |
| native amneziawg-go, plain WireGuard | 80 | 60,500 | 67 MiB |
| Bimeron, AWG 1.0 | 82 | 62,800 | 20 MiB |
| native amneziawg-go, AWG 1.0 | 90 | 60,800 | 65 MiB |
| Bimeron, AWG 2.0 | 81 | 65,400 | 20 MiB |
| native amneziawg-go, AWG 2.0 | 87 | 60,600 | 73 MiB |
| Bimeron, AWG 3.1 | 79 | 63,900 | 20 MiB |
| native amneziawg-go, AWG 3.1 | 82 | 66,500 | 69 MiB |
| Bimeron, Shadowsocks chacha20-ietf-poly1305 (no netstack on either side) | 586 | 5,200 | 15 MiB |
| Bimeron, VLESS REALITY Vision to Xray (no netstack; Xray CPU not counted) | 496 | 3,900 | 12 MiB |

The VM shared its host with other workloads during the run, and single
3-second runs varied by up to a factor of seven, so compare medians only.
Bimeron's single-socket bind stays within 10% of the engine's own batched
bind in every WireGuard row. The memory difference comes from the standard
bind's preallocated batches. The Shadowsocks and VLESS rows are not a
like-for-like comparison: the WireGuard rows include two userspace TCP
stacks, which a real deployment also has (Bimeron's TUN stack plus the
tunnel netstack).
Threshold for regressions: Bimeron within 20% of native amneziawg-go
throughput on the same run. If a live comparison with a kernel-level
WireGuard client shows a larger gap, it is tracked separately (ADR 0043).

Run:

```sh
BIMERON_XRAY_BIN=/absolute/path/to/xray go test ./internal/wireguard -run '^$' -bench TCPBulk -benchtime 3s -count 3
```
