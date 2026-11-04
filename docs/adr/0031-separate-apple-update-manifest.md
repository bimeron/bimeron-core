# ADR 0031: Separate Apple update preparation

Status: Accepted contract; production publication blocked. Tracked by Core issue #84.

## Context

Apple consumer G needs macOS-only archives with exact build provenance and a
separate application compatibility review. The existing Windows/Linux four-target
manifest, policy, consumers and ten-asset publication script remain unchanged.

## Decision

Use the standalone `release/applemanifest` library and public-only
`scripts/apple-release-manifest.go` preparation/verification command. See
[the contract](../apple-update-manifest.md) and the
[illustrative JSON](../../release/applemanifest/testdata/apple-update-manifest.json).
No default trusted key, approved candidate, signing environment, or publication
integration is supplied. Signing is an explicit library operation, exercised only
with synthetic keys in tests. Verification requires independent trust, exact local
tag/revision approval, and reviewed compatibility.

The bounds and exact schema were frozen with consumer G. Runtime hello/session
readiness remains a separate check; a signed claim cannot prove readiness.

## Alternatives and consequences

Extending the old manifest would alter existing consumers and mix independently
reviewed compatibility policies. A separate contract avoids that migration.
Executing an archived binary to obtain a version is unsafe and is prohibited.

Go 1.26.9 retains GOOS, GOARCH and VCS settings with `-trimpath -s -w`, but omits
`-ldflags` from build info under `-trimpath`. Therefore the existing build-dist
output cannot prove `-X bimeron/core.Version` through `debug/buildinfo.Read`.
ADR0032 now authorizes local production integration of a retained canonical
record, shared generation/runtime extraction/static checking, and an explicit
Darwin-only release build selection. The validator replaces only the invalid
ldflags evidence with exact record recovery; source/clean/CPU/OS/architecture and
archive checks remain required. No signed wire change is introduced. This does
not approve consumer G/E changes, Apple compatibility, a key, a release candidate,
or shipping.
