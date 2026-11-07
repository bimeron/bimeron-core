# ADR 0035: Structured problems and a shared error catalog

Status: accepted, 2026-11-07.
Tracking: issue #105.

## Context

Configuration validation returned free-form English strings, for example
`[Interface] Name must start with a letter ...` or `invalid VLESS options`.
Desktop, Android and Apple clients could only display that text verbatim or
pattern-match it. Pattern matching breaks silently when wording changes, cannot
locate the failing field and cannot be localized. Many messages named only the
protocol ("invalid VLESS options") without the field.

Connection failures already used diagnostic codes in `Status.LastError`, but
several platform paths stored raw error text there, and every client needed its
own texts for the codes.

## Decision

1. Every configuration validation failure is a `problem.Error` with a stable
   catalog `code`. The location uses the profile vocabulary: `section`, a
   canonical `field`, optional `related` fields, the URI key that held the value
   (`source`), a one-based `rule` and the profile `line`. Canonical field names
   are the explicit `.conf` option names, so the same check reports the same
   field for a URI key and for explicit parameters.
2. A problem may carry `args` with safe values only: limits, permitted values,
   group identifiers. It never contains secrets, URIs, hostnames supplied by the
   user, paths or configuration fragments. `value` reports only whether the field
   had a value (`present` or `absent`), so a client can show a fixed mask for a
   secret field it already holds.
3. Transports return a list, `problems`. The core currently stops at the first
   failure, so the list has at most one element. Clients must accept several.
4. The core embeds one catalog of human-readable texts in English and Russian for
   configuration, control and connection codes. Texts omit field names; clients
   prepend their own field labels. Placeholders are `{name}` and are filled from
   `args`. The catalog also lists secret fields.
5. The catalog is exposed through `bimeron errors --json`, the Android
   `ErrorCatalog()` binding and the Apple `RLErrorCatalog()` export. Validation
   problems are returned by `validate --json`, the desktop document bridge, the
   control `start` response, Android `ValidateConfigWithGeoData` and Apple
   `RLValidate`.
6. The English `message` stays the previous error text. CLI output, logs and
   existing string-based callers are unchanged.
7. Every `Status.LastError` and event error value is a catalog code.

This ADR makes the catalog the single place where the core ships non-English
user-facing text. Everything else in the repository remains English.

## Alternatives and tradeoffs

- Client-side pattern matching of English text needs no core change, but every
  wording change breaks clients silently and three platforms would maintain
  duplicate tables. Rejected.
- Client-owned texts keyed by code keep wording close to each UI and do not need
  a core release to fix a typo. They triple the translation work and drift
  between platforms. The user chose one shared catalog; clients may still
  override individual texts locally.
- Collecting every problem in one pass gives better UX but requires restructuring
  the parser and every validator. The list-shaped contract allows adding this
  later without a protocol change.
- Protocol-specific codes (`vless_id_invalid`) are easy to add but multiply the
  catalog. Codes describe the rule instead (`uuid_invalid`), and the location
  names the field and protocol context.

## Consequences

- Adding a validation failure requires a catalog entry in both languages. A
  source-scanning test fails on unknown or unused codes, and a mutation test
  fails when a malformed profile produces an uncoded error.
- Renaming or removing a code is a breaking change for clients. Codes may be
  added freely; clients show the English `message` or a generic text for unknown
  codes.
- Fixing catalog wording requires a core release. Clients bundle the catalog of
  the core they ship with.
- See [ERRORS.MD](../ERRORS.MD) for the exact contract.
