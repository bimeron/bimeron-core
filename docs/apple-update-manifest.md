# Apple update manifest contract (schema 1)

Preparation only; Core issue #84. This contract is separate from
`update-manifest.json` and does not change its generator, policy, consumers, or
publication script. The illustrative, unsigned fixture is
`release/applemanifest/testdata/apple-update-manifest.json`; its zero identifiers,
hashes and one-byte archive sizes are placeholders, not trusted artifacts.

## Wire format and trust

Names: `apple-update-manifest.json` and `apple-update-manifest.json.sig`.
JSON is a complete valid UTF-8 object ending immediately with one LF byte.
The manifest limit is 65536 bytes including LF. The detached Ed25519 signature
is exactly 89 bytes: standard canonical base64 of the 64 signature bytes
(88 characters), then LF. Verify the exact received JSON bytes, never a parsed
or re-encoded representation. The generator emits deterministic two-space
indented JSON with LF; verifiers may accept other interior JSON whitespace.

All objects have exact field sets listed below; no unknown, missing, or null
fields. Keys are lowercase ASCII letters/digits/underscores only. Case aliases and
duplicate decoded keys, including escaped equivalents, are rejected everywhere.
Escaped spellings of a unique allowed key decode normally. Unsupported schemas
are rejected. Numeric integer fields must decode as Go/JSON integers.

Production fails closed without an independently trusted 32-byte public key,
an explicitly locally approved exact tag and full revision, and
`apple_reviewed:true`. No pin or approved candidate is shipped. `key_id` is the
lowercase hex encoding of the first eight bytes of SHA-256(public key), not a
trust source. A public key used for preparation identifies a key only.

## Exact fields

Root: `schema`, `product`, `tag`, `core_version`, `channel`, `source_revision`,
`key_id`, `compatibility`, `archives`.

- `schema`: 1; `product`: `bimeron-apple-core`.
- `core_version`: numeric SemVer major.minor.patch, optionally a SemVer
  prerelease (ASCII alphanumeric/hyphen identifiers separated by dots; numeric
  identifiers have no leading zeros). No build suffix. Maximum 128 bytes.
- `tag`: `v` plus core_version. Channel is `beta` for a prerelease, `stable`
  otherwise.
- `source_revision`: exactly 40 lowercase hexadecimal characters identifying
  the exact build commit, never a branch, baseline, or abbreviated revision.
- `key_id`: exactly 16 lowercase hexadecimal characters.

Compatibility fields: `schema`, `app_min`, `app_max_exclusive`,
`apple_reviewed`, `ipc_min`, `ipc_max`, `profile_format`,
`daemon_session_guards`. Schema is 1, IPC min/max are both 1, profile format is
1, guards is true. App bounds are plain numeric triplets without leading zeros,
each at most 128 bytes, each numeric component at most UInt64 maximum
18446744073709551615, min strictly less than max; the interval is half-open.
The independent policy is `release/apple-compatibility.json`.

Shipping policy is `app_min:"0.1.0"`, `app_max_exclusive:"0.1.1"`,
`apple_reviewed:false`. These provisional bounds reflect actual app
CFBundleShortVersionString 0.1.0, build 1, baseline a84e475. They are NOT approval.
Setting true requires a separately documented actual review and authorization;
tests and architecture approval never constitute that review. Synthetic tests
may inject true, a synthetic pin and explicit synthetic candidate approval.
The signed daemon-session-guards claim is separate from runtime hello guards
and readiness checks, which consumers must still perform.

Each archive has exactly `os`, `arch`, `name`, `size`, `sha256`.
Exactly two unique records: os `macos`, arch `amd64` and `arm64`; publisher emits
that order, consumers may accept either order. Name is exactly
`bimeron-<tag>-macos-<arch>.zip`. Size is positive and at most 268435456 bytes.
SHA-256 is 64 lowercase hex characters over final ZIP bytes. Verify every
archive's signed hash and size before parsing any supplied ZIP.

## ZIP and executable validation

Each ZIP contains exactly three regular nonempty files:
`macos-<arch>/bimeron`, `macos-<arch>/LICENSE`, and
`macos-<arch>/THIRD_PARTY_NOTICES.txt`. Only the exact parent directory entry is
optional (zero uncompressed bytes); at most four total entries. No other path,
absolute path, backslash, dot component, normalized alias, duplicate, symlink,
special file, or encryption is allowed. Stored and deflate are the only methods.
The executable must have at least one executable permission bit. Its maximum
uncompressed size is 268435456 bytes; each notice/license maximum is 4194304
bytes. These constants match `release/applemanifest` and consumer G.

Read the binary as bytes, never execute it: require executable thin Mach-O of
the expected CPU and Go build info with GOOS `darwin`, exact GOARCH,
`vcs.revision` equal to source_revision, and explicitly present
`vcs.modified=false`. Require exact `-X bimeron/core.Version=<core_version>`
linker metadata: the exact supported recipe is
`-s -w -X bimeron/core.Version=<core_version>`, with no other linker arguments.
Missing or ambiguous evidence fails without subprocess fallback.

**Current build limitation:** Go 1.26.9 strips `-ldflags` build-info settings
with `-trimpath`, including when build-dist uses `-trimpath -s -w`. The validator
therefore rejects current build-dist binaries. No build or policy workaround is
silently applied. See ADR 0031; production preparation remains blocked pending
an authorized provenance design.

## Local use and validation

The command prepares unsigned JSON to stdout or verifies existing files using
an explicit base64 public key and exact tag/revision. It never loads private
keys, signs, installs, runs binaries, or publishes. Input files are bounded
before reading. Run `go test ./release/...` and `go vet ./release/applemanifest`.
The existing CI `go test ./...` includes these tests; existing release tests
remain unmodified.

The deterministic synthetic manifest-only interop vector is
`release/applemanifest/testdata/synthetic-reviewed-manifest.json`, its `.sig`,
and `synthetic-vector.json` metadata. Public key base64 is
`O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=`, key ID
`139e3940e64b5491`. It uses explicitly synthetic reviewed compatibility,
forty-zero revision and fake archive hashes; successful descriptor verification
never implies those archives are acceptable. The library returns a
`VerifiedManifest` descriptor; `VerifyArchives` separately verifies ZIP bytes.

Tests record deterministic encoding and the fixed public-key/key-ID/signature
vector; exact-byte signature tampering, missing/wrong trust and candidate gates;
shipping-false review; malformed UTF-8, final LF, missing/null/unknown fields,
duplicates including escaped/case aliases, integer fraction/exponent/negative
zero/leading-zero forms, unsupported schemas, SemVer and UInt64 bounds;
unique archive identities and order independence; final-byte tampering before
ZIP parsing; extra/missing/duplicate/aliased/absolute/backslash/dot paths,
links and special files, missing execute bits, empty/oversized contents,
encryption, unsupported compression, CRC corruption; both Mach-O architectures
and each architecture's missing/dirty/wrong revision, OS, architecture and version
metadata. Tiny synthetic binaries use `-s -w` and the exact version assignment;
the paired `-trimpath` builds prove the current production blocker. The old
`release/manifest_test.go` suite runs unchanged alongside these checks.
