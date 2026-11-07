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
an empty groups array. Only regular files are accepted; opening follows OS
symlinks and uses the caller's permissions. Reads are limited to 64 MiB plus one
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
details. Success is exactly {"version":1,"problems":[]}. `bimeron errors --json`
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
