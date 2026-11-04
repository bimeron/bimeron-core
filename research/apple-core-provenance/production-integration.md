# Local production integration of retained Apple Core version

This is local implementation evidence under ADR0032, not a release approval.
The tested production/test source commit is
`36b930e09724b26ee4c33712bf086be1c114ce10`. Subsequent report-only commits do not
change that evidence identity. The fixture version `0.1.0-beta.1` is synthetic,
not an approved production candidate. No original Core85 or paused G/E worktree
was changed or contacted.

## Implementation and explicit inputs

`internal/appleversion` owns strict bounded canonical SemVer and framing,
exact runtime decoding, and bounded static Mach-O section recovery. Runtime
prefix checks are split so parser/generator marker constants are dead eliminated
from the real CLI; successful static checking requires exactly one full marker
in `__TEXT,__rodata`. The active segment must be readable and non-writable, unique,
and its section/file/virtual ranges must agree. `Maxprot` is not used as current
protection: pinned Go permits a writable maximum while `Prot` is read-only.

`core.GetBuildInfo` uses the exact embedded record under the explicit Darwin-only
`bimeron_apple_release` tag. Missing record fails compilation; invalid contents
fail runtime extraction. Non-Darwin tag selection fails compilation. The default
selection still uses legacy mutable `core.Version`, including linker `-X`.
Existing CLI, daemon hello, doctor and repair consume the same GetBuildInfo path.
No response JSON fields were changed.

The standalone `scripts/build-apple-release.go` requires explicit exact version
and full revision matching clean HEAD. It deterministically regenerates ignored
`core/apple-version.record`, builds both CPU targets with the pinned installed Go,
`CGO_ENABLED=0`, `-buildvcs=true -trimpath -tags=bimeron_apple_release -ldflags='-s -w'`,
then creates and statically checks actual ZIPs through `CheckArchive`. All caches,
intermediate binaries and ZIPs stay under ignored `.tmp`. The generated record is
an additional explicit input, not authenticated by `vcs.modified=false`.
The synthetic 72-byte record has SHA-256
`1c5eb2a1c3c437a8f1275c04763e5994fc391f8ff8b7e9464007db6ef5c5fc64`.
The builder prints its exact bytes as hexadecimal. It neither signs nor selects
keys/trust/candidates. `scripts/build-dist` and the legacy publisher are unchanged.

## Reproduction

Run from this worktree with the pinned compiler; set these variables for every
Go command, including compilation of the standalone builder itself:

```sh
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off
export GOCACHE="$PWD/.tmp/gocache" GOTMPDIR="$PWD/.tmp" TMPDIR="$PWD/.tmp"
mkdir -p .tmp
GO=<LOCAL_HOME>/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.9.darwin-arm64/bin/go
"$GO" test ./internal/appleversion ./release/applemanifest ./core ./cmd/bimeron -skip TestMASQUE
BIMERON_APPLE_INTEGRATION=1 "$GO" test -v ./research/apple-core-provenance -run TestProductionIntegration -count=1
```

The opt-in integration test archives local HEAD into two local temporary
checkouts, obtains the same commit objects from this worktree by filesystem-only
Git fetch (no remote configured or network), and runs the actual standalone
builder in each. Temporary checkouts are removed by Go testing; no binaries are
tracked. To invoke the builder separately at a clean approved commit:

```sh
"$GO" run ./scripts/build-apple-release.go -version='<explicit approved version>' -revision='<full approved commit>'
```

## Evidence and limits

Targeted common-record, release-library, Core and real CLI tests pass with only
`TestMASQUE*` excluded. Full `go test ./core` was attempted offline and failed in
existing `TestMASQUEProxyBackend` and `TestMASQUEVPNFlows`: the module cache lacks
`github.com/quic-go/masque-go v0.6.1-0.20261027113634-a08a5a221b16` and
`github.com/quic-go/quic-go v0.63.0` needed by their reference helper. Go reported
`module lookup disabled by GOPROXY=off`; no network fallback was enabled.
The real production CLI dependency build itself succeeds offline.

The final integration run passed in 76.37 seconds. Both independent checkout
paths produced byte-identical archives for the tested commit:

- amd64 ZIP SHA-256: `30e9a9f2c1b2f38269b509549cc470cb5dcba5d404621f114ecd759bc2244b10`
- arm64 ZIP SHA-256: `966b068e52eaeaa39a36c447726b35a758ef32fbdf8f68a779138e299e3b4fcc`

The integration matrix exercises real source-built arm64 CLI version output,
Apple runtime and static immunity to both legacy and nonexistent `-X` assignments,
legacy runtime `-X`, missing embed, unsupported OS, invalid version/revision,
dirty source rejection, stale ignored record regeneration, both CPU static ZIP
checks and byte-for-byte checkout-path reproducibility. amd64 is compiled and
statically checked, not executed. Release fixtures retain synthetic-only signing
keys and exercise authenticated hash-before-ZIP parsing, CPU/OS/architecture,
revision/clean VCS, missing/malformed/duplicate/oversized record, read-only section
placement/ranges, stripping retention, and existing ZIP path/type/size negatives.
Windows checkout fixture bytes are protected from CRLF conversion.

Producer-consumer delta: the Apple producer now supplies a retained canonical
record and runtime extraction from the same bytes. The local release validator
replaces only the invalid exact-ldflags evidence with that record plus trimpath
and Git VCS evidence. Signed JSON, signature domain, compatibility gates, trust,
archive size/hash and ZIP policy are unchanged. Consumer G/E still needs a
separately authorized matching binary-evidence policy update; it must not assume
that prior ldflags evidence accepts these binaries. No consumer patch, private
key, signing/notarization, publication, issue/PR, push, tag, remote, CI execution,
watcher or main merge was performed. Independent review remains the parent's task.
Embedded claims and clean Git metadata do not prove an honest builder; authenticated
archives, independently reproduced source derivation and VPN readiness remain
separate trust boundaries. Compiler upgrades require fresh retention evidence.
