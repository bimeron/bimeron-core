# Desktop document CLI API

Status: development source, protocol version 1. Core owns this non-networking
adapter; it adds no RPC, dependency, helper executable, download or session action.

## Acceptance contract

- Inspecting a draft returns exact bytes; supported mutations preserve unrelated
  bytes, BOM, comments, unknown fields and section order.
- A batch applies sequentially with zero-based current document row indices
  (including disabled rows). Any failure returns the original profile and rows.
- Unsafe edits refuse malformed/unknown rule fields; section patches refuse
  duplicate target sections or any duplicate/malformed keys in that section.
- All input, file reads and output are bounded. No profile contents enter argv,
  stderr diagnostics or logs. The response profile is secret-bearing.

## Framing and lifetime

Run `bimeron document` with no arguments. Write exactly one UTF-8 JSON object to
stdin and close stdin. The process reads through EOF and writes one JSON object
plus LF to stdout. Cancel by terminating this short-lived process; no state or
files are changed. Transport/write errors use the ordinary nonzero CLI exit.
Protocol and operation failures use exit zero with `error`; always inspect JSON.
Unknown JSON members, trailing JSON, absent required fields and version mismatch
are rejected. JSON uses standard Go decoding (duplicate members use the last
value); callers must emit unique member names.

Request limit: 1 MiB encoded JSON, profile limit: 65,536 UTF-8 bytes both before
and after every operation. Invalid UTF-8 is rejected. Output limit: 32 MiB
excluding terminal LF; overflow returns only version and error. Inputs requiring
arbitrary non-UTF-8 bytes are outside this string protocol.

```json
{"version":1,"profile":"[Routing]\nDefault=proxy\n","operations":[]}
```

Each operation has `op` plus these fields:

| op | Required fields |
|---|---|
| set_rule | index, matcher, value, action |
| toggle | index, enabled (boolean) |
| move | index, to (final row index) |
| add | index (0 through row count), matcher, value, action, enabled |
| delete | index |
| set_field | section, key, value (strings; empty value allowed) |
| set_doh | value and bootstrap (strings), or neither to remove both keys |
| access_to_fields | none; any other member is rejected |
| access_to_uri | none; any other member is rejected |

Matcher IDs are `CIDR`, `Domain`, `GeoIP`, `GeoSite`; actions are `direct`,
`proxy`, `block`. CIDR input must already be a prefix; no IP normalization occurs.
Disabled blocks use one outer comment layer, never an Enabled field. Added blocks
use the document's CRLF if present, otherwise LF. Creating a section or rule,
patching a section, or editing rule fields ensures at least one blank line at
that block's outer boundaries when neighboring content exists. A move adds
missing blank separators only at changed adjacency boundaries. Existing blank
lines (including whitespace-only lines) are retained, never collapsed. Missing
line terminators at those boundaries are supplied before the blank separator.
Disabled Rule headers are section boundaries too; section keys are never added
to a following disabled block. Comments retain their bytes and existing block
ownership; no comment attachment is inferred or normalized. Untouched boundaries
may remain adjacent. Inspection, no-op moves and toggles do not repair spacing;
toggle round trips retain their original bytes. Failed mutations change nothing. Delete removes the complete block and its attached
trailing comments. Add at row count appends after existing document content.
Section patches target a non-Rule section, replace a key or add the missing
key/section, and quote edited values using Go string quoting. Existing key
spacing and line endings survive replacement. Adding text may add a separator
and final newline. Section/key identifiers are case-sensitive. No implicit delete
or runtime interpretation is performed by set_field.


### DNS mode editing

`doh: true` in Core capabilities indicates support. Inspect returns
`Interface.DoH` and `Interface.DoHBootstrap` in `fields` when present.
Use `{"op":"set_doh","value":"https://one.example/dns-query","bootstrap":"192.0.2.10|2001:db8::10"}`
to set both keys, or `{"op":"set_doh"}` to remove both. Both values must be
present or both absent. The operation preserves `DNS` and applies atomically.
Use normal Core validation before saving or starting. Preserve URL spelling and
the endpoint and address order in editors and import/export. Shared parser
vectors live in `internal/dnsconfig/testdata/doh-v1.json`.

### Access source conversion

`access_to_fields` replaces a share URI source in `[AccessKey]` (`SS`, `SOCKS5`,
`HTTP`, `VLESS`, `VMess`, `Trojan`, `Naive`, `Hysteria2`, `AnyTLS`, `TUIC`, `SSH`,
`MASQUE`, or `Key` holding one of these URIs) with the equivalent explicit
`Type = ...` options. `access_to_uri` replaces explicit options with the URI
under the protocol's own source key, for example `Hysteria2 = hysteria2://...`.
Capabilities report `access_conversion: true` when both operations exist.

- Only the replaced option lines change: the first becomes the new options, in
  a fixed order, and the others are removed. Comments, other sections, rules,
  `[ShadowTLS]`, BOM and line endings keep their bytes. `IdentityFile` and
  `KnownHostsFile` stay as options; SSH file paths from the URI query become
  these options unless they are already set.
- Core resolves `[AccessKey]` before and after the change and fails unless both
  produce an equivalent runtime profile. Only `[AccessKey]` takes part, so
  routing rules and GeoData files do not need to be valid or present.
- The conversion is semantic, not byte-identical: `hy2://` becomes
  `hysteria2://`, percent-encoding and option order may change, defaults may
  become explicit, and the URI fragment is dropped because `[Profile] Name`
  holds the name. Separate `XHTTP*` options become one `extra` JSON value, and a
  URI `extra` becomes `XHTTPExtra`.
- Values that a bare option line would not preserve, such as values with outer
  spaces, are written as Go quoted strings.
- `SSConf`, `File`, a `Key` holding `ssconf://`, profiles without `[AccessKey]`
  (including IKEv2), and a source already in the requested form fail with
  `access_conversion_unsupported`. A source Core rejects fails with its usual
  problem, without a line number. If the converted form would connect
  differently, the operation fails with `access_conversion_mismatch`.
- Duplicate `[AccessKey]` sections, duplicate options and options after a
  disabled rule header are refused as for `set_field`. Problems never contain
  option values or the input URI.

Response: `version:1`, `profile:string`, `rules:array`, optional `error:string`,
optional `details:object` and, on failure, `problems:array` of structured problems
(see [ERRORS.MD](ERRORS.MD)). Decide on problem codes, never on `error` text. Rules contain `index`, `enabled`, `matcher`,
`value`, `action`, `editable`, and optional `error`. Invalid requests rejected
before accepting a profile omit profile/rules. Error text is intentionally generic
and must not be parsed. Row errors explain unsafe document edits. Draft editing
never certifies runtime policy, dataset membership or endpoint capabilities.

## Local catalogs

`bimeron geodata groups <geoip|geosite> <absolute-file>` returns
`{"version":1,"groups":["stable-id"]}` with optional error/details/problems. Errors return
an empty groups array. Only local data files are accepted, checked before and
after opening as described in [Referenced files](CONF.MD#referenced-files); opening
follows OS symlinks and uses the caller's permissions. Reads are limited to 64 MiB plus one
sentinel byte, including growing files. The existing bounded V2Ray protobuf
decoder validates content and returns sorted lowercase identifiers. No download,
DNS lookup, ACL change or daemon access occurs. Generic failures are redacted.
Typed GeoData details contain `code`, `kind`, optional `group` and `rule` (one-based
active executable rule number, not a document row). These are the existing shared
Core error fields; do not infer typed locations from prose.

## Validation and integration gaps

Use existing `bimeron validate <absolute-profile-path>` for file-based runnable
validation in the final profile directory. It resolves dataset paths against
that directory and does not start networking. `bimeron validate --json <absolute-profile-path>` wraps the same file validator
and returns version, `problems` (an empty array on success; see
[ERRORS.MD](ERRORS.MD)), and on failure the generic error and shared typed GeoData
details. A successful response also has `trust_files`, an array that is empty
when the profile references no trust files (see [Trust files](#trust-files)):
success without trust files is exactly
{"version":1,"problems":[],"trust_files":[]}. Older Cores return
{"version":1,"problems":[]}. `bimeron errors --json`
prints the catalog of human-readable texts for problem codes. It retains the existing file parser and dataset
limits and profile-relative resource handling. The existing embedded
`ValidateConfigDataWithGeoData` also remains available. Plain validate diagnostics
are not this JSON protocol. File validation and service access
must be checked separately; a GUI-readable catalog proves no service permission
or loaded-session state. Check CLI build identity and active endpoint capabilities
separately. Runtime/UI/package acceptance and local-network checkbox precedence
remain outside this adapter.

The document response additionally exposes `fields`, a flat JSON object mapping
`section/key` to Core-decoded non-Rule values, including Go quoted escapes.
`fields_error` instead marks ambiguous duplicate/malformed sections or fields.
GUIs must retain original bytes and use these values only for controls; this is
not runtime validation. It prevents double-quoting credentials and numeric fields.

GeoData rule editing and catalogs share the identifier contract in
[GEODATA.MD](GEODATA.MD): 1–256 ASCII letters/digits, `_`, `-`, or literal `!`.
Catalogs normalize case to lowercase; document edits preserve the supplied spelling.
Bang is part of the stable ID, never negation. Attribute selectors, controls,
non-ASCII, empty/oversized IDs and empty comma entries are rejected.

## WireGuard and AmneziaWG text

WireGuard/AmneziaWG files referenced by `[AccessKey] File` are edited with the
separate `bimeron wireguard` bridge. It has the same framing and limits as this
adapter and provides the `capabilities`, `detect`, `inspect`, `edit` and
`import_uri` operations. `bimeron document` itself never reads the referenced
file; `bimeron validate --json` does and reports problems with
`"document": "wireguard"`. `[Routing] AllowedIPsMode` is edited here with
`set_field`. The full contract is in [WIREGUARD.MD](WIREGUARD.MD#desktop-document-bridge).

## Trust files

Some profile options name files that decide whom Bimeron trusts or which key
it uses: an SSH identity, an SSH `known_hosts` file and a MASQUE CA. An imported
share URI or `.conf` file can name them, so the user must confirm them.

`bimeron validate --json <absolute-profile-path>` lists them in every
successful response; `trust_files` is an empty array when the profile
references none, and the member is never present when validation fails:

```json
{"version":1,"problems":[],"trust_files":[{"kind":"ssh_known_hosts","source":"uri","path":"C:\\Users\\alice\\keys\\known_hosts"}]}
```

| Member | Values |
|---|---|
| `kind` | `ssh_identity`, `ssh_known_hosts`, `masque_ca` |
| `source` | `uri`: a query option of a share URI (`identity=`, `known_hosts=`, `ca=`), including a URI in `Key` or in the file named by `File`; `option`: an explicit `IdentityFile`, `KnownHostsFile` or `CAFile` |
| `path` | exactly the path string the session opens |

Entries come in the order `ssh_identity`, `ssh_known_hosts`, `masque_ca`, with
at most one entry per kind. An explicit option replaces the URI value for its
kind, and only the explicit path is listed then. `ssconf://` keys are resolved
when a session starts and never reference trust files.

Core stores each path in this form when it loads the profile, so the session
opens exactly the reported string. `path` is absolute and normalized as
follows:

- a relative path is resolved against the profile's directory;
- the result is cleaned like Go's `filepath.Clean`: `.` and `..` elements and
  repeated separators are removed, and on Windows `/` becomes `\`;
- on Windows the drive letter is upper case;
- other letter case is kept as written, and symbolic links, junctions, mount
  points and 8.3 short names are not resolved. They are followed only when
  the file is opened.

The one exception is a home-relative path: `~`, `~/...` or `~\...` is reported
exactly as written and is not absolute. The account that runs the session
resolves it against its own home directory; for sessions that the installed
service starts, that is the service account's profile, not the user's home.
Recognize such an entry by its leading `~`.

Compare two entries by `kind` and `path`: on Windows compare `path` with an
ordinal case-insensitive comparison, elsewhere byte for byte.

On Windows, Core refuses network and device paths in these options before it
lists them: `\\server\share` and `//server/share`, WebDAV paths such as
`\\host@SSL\DavWWWRoot\...`, `\\?\`, `\\.\` and `\??\` paths, drive-relative
paths such as `C:known_hosts`, reserved device names and alternate data
streams. Such a profile fails validation with
`file_path_not_local`, with the option (`IdentityFile`, `KnownHostsFile` or
`CAFile`) as the problem field. A local-looking path that reaches a network
share, for example through a mapped drive or a link, is refused when the file
is opened.

GUI contract:

1. When importing a share URI or a `.conf` file, write the draft to its final
   directory or to a directory where relative paths resolve the same way, and
   run `validate --json` on it before saving it as a profile.
2. If `trust_files` is not empty, show every entry before saving: the kind in
   words ("SSH private key", "SSH known hosts", "MASQUE certificate authority")
   and the path exactly as Core reported it, without shortening or
   re-normalizing it, for example "This profile wants to trust the file
   C:\Users\alice\keys\known_hosts". Mention when the entry came from the URI.
   Save only after the user confirms; on cancel, save nothing.
3. Do not offer a home-relative entry (leading `~`) for confirmation as a
   concrete file, because the service resolves it under its own account. Ask
   the user to pick the file instead and save the absolute path as the
   explicit option (`IdentityFile`, `KnownHostsFile` or `CAFile`).
4. Remember the confirmed set of (`kind`, `path`) pairs with the profile. Run
   `validate --json` again immediately before every `start` and after any
   edit, import or replacement of `[AccessKey]` content (including
   `access_to_fields` and `access_to_uri`). This also catches changes to the
   file named by `File`, which the GUI cannot observe. If the set contains an
   entry that is not in the confirmed set, do not start; ask the user to
   confirm the new or changed entries first. Removing entries needs no
   confirmation. A change between that check and `start` is not detected.
5. Files the user picks in the GUI's own file picker count as confirmed.
6. A response without `trust_files` comes from an older Core. Treat it as
   "unknown", not as "none": for SSH and MASQUE profiles, show the paths from
   the profile fields and URI query options yourself, or ask the user to pick
   the files. An empty array means the profile references no trust files.

Core still reads these files only when a connection starts and checks them as
described in [Referenced files](CONF.MD#referenced-files); confirmation does
not make an unreadable or non-local file usable.
