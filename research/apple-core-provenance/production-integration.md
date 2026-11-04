# Local production integration of retained Apple Core version

This is local implementation evidence under ADR0032, not a release approval.
The latest tested production/test source commit is
`e8de4354e2dc5d0364a2fb93119c50971cdf8a5c`; see the final handoff evidence below.
Earlier hardening evidence below applies to
`3bc62c51341d08afc7733acc567b6e8f583a9c6f`. Subsequent report-only commits do not
change those evidence identities. The fixture version `0.1.0-beta.1` is synthetic,
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
then creates and statically checks actual ZIPs through `CheckArchive`. Archive
names follow the existing preparer contract:
`bimeron-v<version>-macos-<arch>.zip`. All caches,
intermediate binaries and ZIPs stay under ignored `.tmp`. The generated record is
an additional explicit input, not authenticated by `vcs.modified=false`.
The synthetic 72-byte record has SHA-256
`1c5eb2a1c3c437a8f1275c04763e5994fc391f8ff8b7e9464007db6ef5c5fc64`.
The builder prints its exact bytes as hexadecimal. It neither signs nor selects
keys/trust/candidates. `scripts/build-dist` and the legacy publisher are unchanged.

## Reproduction

Run from this worktree with the pinned compiler; set these variables for every
Go command, including compilation of the standalone builder itself. Tool launch is
a caller trust boundary: `go run` can apply an overlay before builder checks run.
Compile the builder under a trusted clean environment before hostile-input tests:

```sh
export GOENV=off GOFLAGS= GOEXPERIMENT= GOAMD64=v1 GOARM64=v8.0
export BIMERON_TEST_GIT=/Users/wrk/.local/bin/git
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off
export GOCACHE="$PWD/.tmp/gocache" GOTMPDIR="$PWD/.tmp" TMPDIR="$PWD/.tmp"
mkdir -p .tmp
GO=/Users/wrk/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.9.darwin-arm64/bin/go
"$GO" test ./internal/appleversion ./release/applemanifest ./core ./cmd/bimeron -skip TestMASQUE
BIMERON_APPLE_INTEGRATION=1 "$GO" test -v ./research/apple-core-provenance -run TestProductionIntegration -count=1
```

The opt-in integration test archives local HEAD into two local temporary
checkouts, obtains the same commit objects from this worktree by filesystem-only
Git fetch (no remote configured or network), and runs the actual standalone
builder in each. Temporary checkouts are removed by Go testing; no binaries are
tracked. To invoke the builder separately at a clean approved commit:

```sh
"$GO" build -o .tmp/apple-builder ./scripts/build-apple-release.go
.tmp/apple-builder -git="$BIMERON_TEST_GIT" -go="$GO" -version='<explicit approved version>' -revision='<full approved commit>'
# Unsigned preparation only; PUBLIC_KEY is an explicit base64 public identifier.
"$GO" run ./scripts/apple-release-manifest.go -dir=.tmp/apple-release \
  -tag='v<explicit approved version>' -revision='<full approved commit>' \
  -public-key="$PUBLIC_KEY" -compat=release/apple-compatibility.json
```

## Evidence and limits

Targeted common-record, release-library, Core and real CLI tests pass with only
`TestMASQUE*` excluded. Full `go test ./core` was attempted offline and failed in
existing `TestMASQUEProxyBackend` and `TestMASQUEVPNFlows`: the module cache lacks
`github.com/quic-go/masque-go v0.6.1-0.20261027113634-a08a5a221b16` and
`github.com/quic-go/quic-go v0.63.0` needed by their reference helper. Go reported
`module lookup disabled by GOPROXY=off`; no network fallback was enabled.
The real production CLI dependency build itself succeeds offline.

The final integration run passed in 81.21 seconds. Both independent checkout
paths produced byte-identical archives for the tested commit:

- amd64 ZIP SHA-256: `efdf1906bbef782c0f2eec3f575434ff5f41e7642e0b147d9287945ed9cdb6b3`
- arm64 ZIP SHA-256: `b33855d1932c511d6cbc001d7bf27546fc0cbbc3dea81f20a66b77df6e40c441`

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

## Ambient-input hardening

The builder rejects nonempty ambient `GOFLAGS`, including overlays, and launches
Go with an explicit environment rather than inheriting build settings. `GOENV=off`
disables persisted configuration; experiments are empty, CPU levels are pinned to
`GOAMD64=v1` and `GOARM64=v8.0`, CGO is disabled and target OS/CPU are explicit.
Ambient `GOROOT`, `GOTOOLDIR`, architecture, compiler and other Go settings are
excluded. The module cache/GOPATH location remains an input for offline dependency
availability. Cache and temporary outputs stay under each checkout's `.tmp`.

`-go` defaults to the running builder's `runtime.GOROOT()/bin/go`; `-git` defaults
to installed Git resolution. Explicit paths are supported. The compiler must
report exactly `go1.26.9` on Darwin arm64 or amd64. Go VCS stamping resolves a local
Git link to the same selected executable. These installed tools and their truthful
version reports remain trusted inputs. Local checks explicitly select the scoped
`/Users/wrk/.local/bin/git`; no unscoped Git is executed here.

Regression controls compile the builder first, reject ambient overlay/other flags,
missing tools, wrong Go version and unsupported compiler host, then compare a clean
build against one with hostile persisted GOENV flags, experiments, CPU levels,
GOROOT and GOTOOLDIR. The existing runtime/static and path matrix remains intact.

The hardening matrix passed at the source commit named above after committing
with a clean tracked tree. Both CPU hashes matched across checkout paths,
including the hostile-environment second build. Targeted tests for
`internal/appleversion`, `release/applemanifest`, `core`, `cmd/bimeron` and this
research package passed with `TestMASQUE*` excluded. Vet passed for those packages
and the standalone builder. Local logs are in ignored
`.tmp/hardening-integration.log`. MASQUE remains excluded for the documented
missing offline helper dependencies; amd64 remains static-only on this arm64 host.
Independent rereview of these fixes is still required and was not delegated by
the implementation agent.

## Final builder-to-preparer handoff evidence

The clean committed implementation `e8de4354e2dc5d0364a2fb93119c50971cdf8a5c`
passed the complete real integration matrix in 88.80 seconds (Go package elapsed
89.069 seconds). The reproduction command above was used with the pinned local
Go 1.26.9 compiler, offline dependencies and explicitly scoped Git. The tracked
tree was clean before execution. Logs are local and ignored at
`.tmp/preparer-handoff-integration.log`.

Both checkout paths, including the hostile-environment second builder invocation,
produced identical bytes:

- `bimeron-v0.1.0-beta.1-macos-amd64.zip`: SHA-256 `c428a7cddabb752505cb4f0b0e2ad8d951b0302541c1f5d42ac6c5e5befa5fc5`
- `bimeron-v0.1.0-beta.1-macos-arm64.zip`: SHA-256 `ffd977be9be015ebb6c7e1a1bb6b218d8066c79afa9f873db6a581bdf0d6e479`

In each checkout the actual preparer CLI consumed the builder output directory
without renaming archives, with explicit synthetic tag, exact source revision,
and a synthetic 32-byte public identifier (all bytes `0x42`; no private key).
The test parsed the unsigned output with `applemanifest.Parse`, checked both
archive names, byte sizes and SHA-256 identities against the actual builder ZIPs,
and checked tag/version/revision/key identifier plus exact original shipping
compatibility including `apple_reviewed:false`. No isolated policy was needed.
Preparation does not sign, establish a trust pin, or approve Apple review; the
production verification review gate and wire contract remain unchanged.

Targeted tests passed for `internal/appleversion`, `release/applemanifest`, `core`,
`cmd/bimeron` and this research package with `TestMASQUE*` excluded. Vet passed
for the same packages and standalone builder. The prior missing offline MASQUE
helper dependency limitation remains; amd64 was statically checked, not executed.
No network, real key, installation, CI, remote, push, publication or G/E contact
was used. Parent independent read-only review of this small diff remains pending.
