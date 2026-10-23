# Bimeron configuration (.conf)

The format uses WireGuard-style sections. This is a Bimeron configuration, not a
WireGuard file. One file contains the upstream proxy source, tunnel settings, and
split-routing rules.

Lifecycle, automatic reconnection, and diagnostic codes are documented in
[CORE.MD](CORE.MD). Network recovery is automatic in VPN mode and requires no new
`.conf` options.

## Minimal example

```ini
[Profile]
Version = 1
Name = Main

[AccessKey]
SSConf = ssconf://connect.outlineaccesskey.com/outline/ru/REPLACE_ME

[Interface]
Mode = vpn
Name = Bimeron
MTU = 1420
DNS = 1.1.1.1, 8.8.8.8

[Routing]
Default = proxy
```

Replace `REPLACE_ME` with the complete corresponding part of your key.
Keep personal configurations in `profiles`, which is excluded from Git.
Keys are stored in plain text in configuration files. A `profiles/main.conf`
using `File = test.key` reads your local `profiles/test.key`; create these
local files as needed.

## [Profile]

| Option | Required / default | Meaning |
|---|---|---|
| `Version` | Required; currently only `1` | Format version. Other versions are rejected. |
| `Name` | Optional; empty string | Human-readable profile label. Does not rename the network interface or change routing. |

## [AccessKey]

**Choose exactly one source: `File`, `SS`, `SSConf`, `SOCKS5`, `VLESS`, `Key`, or explicit parameters.** Specifying two
sources is an error; neither takes automatic precedence.

### Key in a file

```ini
[AccessKey]
File = test.key
```

`File` is the path to a UTF-8 file containing a complete `ss://...`,
`ssconf://...`, `socks5://...`, or `vless://...` key. Relative paths are resolved against the `.conf` directory,
not the terminal's working directory. For example, `profiles/main.conf` with
`File = test.key` reads `profiles/test.key`. Absolute paths are allowed.
Leading and trailing whitespace and line breaks are removed; a UTF-8 BOM is
allowed. The maximum key-file size is 64 KiB.

### Inline static key

```ini
[AccessKey]
SS = ss://chacha20-ietf-poly1305:replace-me@server.example.com:8388
```

`SS` is a complete static key and must start with `ss://`. The server, port,
cipher, and password come from the key. Plain parameters, base64-encoded
credentials, and legacy keys with the entire connection portion base64-encoded
are supported. The `#...` fragment is retained as the key label.
The `outline` and `prefix` options are supported; unknown options are rejected.

### Inline dynamic key

```ini
[AccessKey]
SSConf = ssconf://connect.outlineaccesskey.com/outline/ru/REPLACE_ME
```

`SSConf` is a complete dynamic key and must start with `ssconf://`.
At startup or during `check`, configuration is fetched over HTTPS. Responses
may contain `ss://`, simple Shadowsocks JSON/YAML, or basic `tcpudp` YAML with
separate TCP and UDP settings. Unsupported schemas are explicitly rejected.

URL parameters and `#...` are preserved. Fetching is limited to 15 seconds,
64 KiB, and four redirects; HTTPS-to-HTTP redirects are forbidden.
There is no periodic refresh during a healthy connection: content is fetched
again at the next start or reconnect, as described in [CORE.MD](CORE.MD).
The `validate` command checks the URL without fetching it.

### Inline SOCKS5 URI

```ini
[AccessKey]
SOCKS5 = socks5://alice:secret@proxy.example.com:1080
```

Without authentication, use `socks5://proxy.example.com:1080`. The URI must
have a host and port and no path, query, or fragment. Username and password
must either both be present or both absent. Percent-encode reserved characters
in credentials (for example `@` as `%40`). This is Bimeron's import syntax;
SOCKS5 does not define a universal profile-link format. Credentials are stored
as plaintext in the configuration file.

### Inline VLESS URI

```ini
[AccessKey]
VLESS = vless://123e4567-e89b-12d3-a456-426614174000@server.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=example.com&fp=firefox&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd&type=tcp
```

This example uses placeholder credentials and will not connect. The supported
combination is TCP, REALITY, and `xtls-rprx-vision`. `encryption=none`,
`type=tcp`, `security=reality`, `flow`, `sni`, `fp`, and `pbk` are required.
`sid` and `spx` are optional. Supported fingerprints are `chrome`, `firefox`,
`safari`, `ios`, `android`, and `edge`. Use brackets around an IPv6 server
address, as in `@[2001:db8::1]:443`. The fragment is the profile label.
Unknown or duplicate URI options are rejected. Subscriptions are not supported.
`spx` is accepted for link compatibility; Bimeron rejects failed REALITY
authentication and does not run Xray's decoy-site crawler.

Use `flow=xtls-rprx-vision-udp443` only when the server explicitly permits
UDP/443. The normal Vision flow rejects that destination. In `proxy` mode the
local SOCKS5 listener supports TCP CONNECT; in `vpn` mode XUDP carries UDP
traffic through the VLESS server.

### Explicit VLESS parameters

See [`examples/vless.conf`](../examples/vless.conf). Set `Type = vless`,
`Server`, `Port`, `ID`, `Encryption`, `Flow`, `Network`, `Security`,
`ServerName`, `PublicKey`, and `Fingerprint`. `ShortID` and `SpiderX` are
optional. A link in `VLESS` or `Key`, or a file containing a link in `File`,
is an alternative to these fields.

### Compatibility: Key

The generic `Key` option is retained for existing configurations:

```ini
[AccessKey]
Key = ssconf://server.example.com/config
```

It accepts `ss://`, `ssconf://`, `socks5://`, or `vless://`. `Key` is a separate source and cannot be
combined with `File`, `SS`, `SSConf`, `SOCKS5`, `VLESS`, or the explicit parameters below.
Prefer the scheme-specific options in new configurations.

### Alternative: explicit Shadowsocks parameters

Instead of a key or file, specify one parameter group:

```ini
[AccessKey]
Type = shadowsocks
Server = server.example.com
Port = 8388
Method = chacha20-ietf-poly1305
Password = replace-me
```

| Option | Required | Meaning |
|---|---|---|
| `Type` | Required for explicit parameters | `shadowsocks` (preferred) or its `ss` alias. |
| `Server` | Required for the explicit group | Server name or IP address. The current system VPN requires the endpoint to resolve to IPv4. |
| `Port` | Required for the explicit group | Server port, an integer from `1` to `65535`. |
| `Method` | Required for the explicit group | Cipher: `chacha20-ietf-poly1305`, `aes-128-gcm`, `aes-192-gcm`, or `aes-256-gcm`. |
| `Password` | Required for the explicit group | Nonempty server password. |
| `Prefix` | Optional; empty string | Shadowsocks salt prefix for disguising the connection. Changes the wire protocol; use only with the appropriate server configuration. |

The group uses identical settings for TCP and UDP. Use a dynamic key for separate
endpoints. This group cannot be combined with other sources.

### Alternative: explicit SOCKS5 parameters

```ini
[AccessKey]
Type = socks5
Server = proxy.example.com
Port = 1080
Username = alice
Password = secret
```

`Type`, `Server`, and `Port` are required. `Username` and `Password` must both
be set for username/password authentication, or both omitted for no
authentication. Credentials must be at most 255 bytes each. `Method` and
`Prefix` do not apply. Explicit parameters without `Type` are rejected,
including Shadowsocks parameters.

In VPN mode the upstream SOCKS5 server must support `CONNECT` and `UDP
ASSOCIATE`. Failure of either check prevents the VPN from starting. In local
`proxy` mode, only `CONNECT` is needed because the local listener accepts TCP
connections only. SOCKS5 does not encrypt the connection to the upstream
server. DNS, MTU, and routing settings below use the same configuration as
Shadowsocks; DNS and proxied UDP in VPN mode use `UDP ASSOCIATE`.

`Prefix` accepts characters with codes `0..255` and escaped values, such as
`Prefix = "GET \r\n"`. The implementation retains at least 16 random salt bytes:
the maximum prefix is 16 bytes for ChaCha20/AES-256 and 8 bytes for AES-192;
AES-128 does not support a nonempty prefix. These limits are checked when creating
the transport (`check`/`run`), not only when parsing `.conf`.

## [Interface]

This section is optional; missing options receive defaults.

| Option | Default | Meaning |
|---|---|---|
| `Mode` | `vpn` | `vpn`: system Windows Wintun or Linux TUN, or experimental macOS utun; `proxy`: local TCP SOCKS5 proxy. Determines `run` behavior. |
| `Name` | `Bimeron` | Interface name in `vpn` mode. 1–32 ASCII characters on Windows, up to 15 on Linux: letters, digits, `_`, `-`; the first character must be a letter. An occupied name is rejected. On macOS, this is a logical label; the OS assigns utunN. |
| `MTU` | `1420` | Maximum tunnel IP-packet size in bytes. Integers `1280..1500` are allowed. Unused in `proxy` mode. |
| `IPv6` | `enable` | `enable`: route IPv6 according to the rules. `disable`: block IPv6 connections and return empty successful responses to system AAAA DNS queries so applications choose IPv4. Available only with `Mode = vpn`. |
| `KillSwitch` | `false` | `true`: enable Windows WFP or Linux nftables filters that block application traffic outside the tunnel according to IP split rules. `false`: install no protection. Only for `Mode = vpn`. Rules survive core crashes; normal shutdown or explicit `recover` removes them. Linux protection does not survive an OS reboot. On macOS, true is rejected before network setup because a kill switch is not implemented; see [MACOS.MD](MACOS.MD). See [KILLSWITCH.MD](KILLSWITCH.MD) and [LINUX.MD](LINUX.MD). |
| `DNS` | `1.1.1.1` | 1–4 distinct unicast IPv4 addresses, comma-separated in priority order. In `vpn` mode, system DNS goes through the selected upstream transport to these servers. Also used by preconnection checks and `check`. |
| `Listen` | `127.0.0.1:1080` | SOCKS5 address in `proxy` mode: a loopback IP and port `1..65535`, such as `127.0.0.1:11080` or `[::1]:1080`. Unused in `vpn` mode. |

Values are validated even when unused in the selected mode.

System VPN DNS always goes through the selected upstream transport, regardless of `Default` and rules.

Each query starts with the first server. A network error, timeout (2 seconds per
server), or error response such as `SERVFAIL` or `REFUSED` causes a retry with
the next server. `NXDOMAIN` is final and does not trigger fallback. If every
server is unavailable, the client receives `SERVFAIL`. DNS over UDP and TCP is
supported. If `DNS` is omitted, `1.1.1.1` is used. IPv6 server addresses,
DoH, and DoT are not yet supported by this option. Servers must be reachable from
the Outline server.

Physical-adapter DNS settings are preserved. Applications with their own DNS,
including DoH, use normal IP routing and are not subject to the system DNS rule.
IPv6 traffic is captured even with `IPv6 = disable` so it can be blocked without
bypassing the VPN. This mode does not change physical-adapter IPv6 settings.
Applications with their own DNS/DoH may receive IPv6 addresses, but their IPv6
connections in the tunnel are blocked. Existing more specific routes may still
bypass the tunnel. With `IPv6 = enable`, IPv6 destination availability depends
on the Outline server.

## [Routing]

| Option | Default | Meaning |
|---|---|---|
| `Default` | `proxy` | Action for connections matching no rule. Allowed values: `proxy`, `direct`, `block`. |

| Action | Behavior |
|---|---|
| `proxy` | Send through Outline. |
| `direct` | Connect directly through the original network interface. |
| `block` | Deny the connection. |

Two split-routing modes:

- `Default = proxy`: all captured traffic uses the VPN; `direct` rules specify exceptions.
- `Default = direct`: all captured traffic goes directly; `proxy` rules select VPN destinations.

## [Rule]

Repeat this section for each rule. Rules are checked **top to bottom, stopping at
the first match**. Rules are optional; without them, `Default` applies.

| Option | Required | Meaning |
|---|---|---|
| `CIDR` | Exactly one of `CIDR` / `Domain` | One IPv4/IPv6 subnet or a comma-separated list, such as `8.8.4.0/24, 8.8.8.0/24`. A single IPv4 address means `/32`; a single IPv6 address means `/128`. |
| `Domain` | Exactly one of `CIDR` / `Domain` | A domain and its subdomains, such as `example.com`. Available for SOCKS5 and system VPN. |
| `Action` | Required | `proxy`, `direct`, or `block`. |

Example rules (illustrative addresses):

```ini
[Routing]
Default = proxy

[Rule]
CIDR = 203.0.113.25/32
Action = direct

[Rule]
CIDR = 198.51.100.0/24
Action = block
```

Multiple subnets can share a section. `Action` applies to every list entry;
IPv4 and IPv6 can be mixed. Whitespace around entries is allowed; empty entries
and invalid CIDRs are rejected. Separate `[Rule]` sections are also supported.

```ini
[Routing]
Default = direct

[Rule]
CIDR = 8.8.4.0/24, 8.8.8.0/24, 8.34.208.0/20
Action = proxy
```

A more specific CIDR receives no automatic priority: rule order matters.
Domain rules are case-insensitive, include subdomains, and do not use `*`.
In SOCKS5, the client must supply the domain.

In system VPN mode, Bimeron remembers validated A/AAAA responses from its DNS and
associates IPs with the originally queried domain, including CNAME responses.
Associations live only in memory, honor TTL, survive reconnect, and are removed
on Stop. If an IP has several domains, the first matching rule in file order wins.
The table is limited to 4096 associations and TTL to 24 hours. Direct IPs, prior
system DNS caches, DoH/DoT, and application-owned DNS create no metadata; CIDR
rules and `Default` apply to them. See [DNS_METADATA.MD](DNS_METADATA.MD) for
detailed limitations.

System rules apply to traffic captured by the tunnel interface. Local networks
and other more specific system routes may bypass the tunnel. Outline does not
carry ICMP; `ping` does not test the transport.

## File syntax

- UTF-8, with an optional BOM; LF and CRLF line endings.
- Section and option names are case-sensitive: `SSConf`, `MTU`, `CIDR`.
- Each section except `[Rule]` may appear once; options cannot repeat within a section.
- `[Profile] Version = 1` and one source in `[AccessKey]` are required.
- Unknown sections, options, versions, and duplicates are rejected.
- The `.conf` size limit is 64 KiB.
- Comments begin with `#` or `;` **on a separate line**.
- No trailing comments: `#`, `;`, and `=` are preserved inside keys and passwords.
- Leading/trailing value whitespace is trimmed; double quotes preserve it.
- Quoted values support escapes `\r`, `\n`, `\t`, `\\`, `\"`.
- Windows paths are easiest to write unquoted: `File = C:\VPN\test.key`.

## Commands

```cmd
dist\windows-amd64\bimeron.exe validate profiles\main.conf
dist\windows-amd64\bimeron.exe check -config profiles\main.conf
dist\windows-amd64\bimeron.exe run profiles\main.conf
```

`validate`: check the file, rules, static-key format, or dynamic-key URL;
reads `File` when specified. Makes no network requests or Windows settings changes.
`check`: test real TCP/TLS and UDP/DNS through Outline and print the external IP;
does not change system settings.
`run`: start the mode selected by `[Interface] Mode`. For `vpn`, use an
administrator CMD; stop with `Ctrl+C`. `proxy` needs no administrator privileges.

Explicit commands: `connect -config profiles/main.conf` for VPN and
`proxy -config profiles/proxy.conf` for SOCKS5. Do not combine `-config` with
a positional key file or `-dns`, `-policy`, or `-listen` flags; change these
settings in the configuration.

After a crash, remove a remaining DNS rule from an administrator CMD:

```cmd
dist\windows-amd64\bimeron.exe recover
```

