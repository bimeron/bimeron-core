# Local option 2 prototype

Research only. No production code, network, dependencies, CI, installs, signing
keys, remote operations, or consumer changes. Uses the existing Go toolchain and
`/Users/wrk/.local/bin/git`; scratch Git identity is `solarcadence`.

## Run and observed results

From the worktree root, with an already installed Go >=1.26 on PATH:

```sh
PATH="/Users/wrk/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.9.darwin-arm64/bin:$PATH" \
  research/apple-core-provenance/prototype/run.sh
```

`run.sh` disables Go dependency and toolchain downloads. All generated repositories,
executables, temporary files and caches stay in this prototype's ignored `.scratch`
and `.cache` directories. Each run replaces `.scratch` and writes `results.json`.
It creates a new synthetic local commit, then copies that exact commit into a
second path. Commit timestamps can change between runs; recorded hashes compare
two builds of the same commit within one run, not arbitrary runs.

Observed on Go 1.26.9, darwin/arm64: all tests pass. Both darwin/arm64 and
darwin/amd64 compile with `-buildvcs=true -trimpath -ldflags '-s -w'`.
The two checkout paths produce equal SHA-256 hashes for each architecture, and
neither checkout path occurs in the bytes. Static verification succeeds after
stripping for both architectures. Only the locally source-built arm64 executable
is executed: its real CLI output equals the recovered version, including after
`-X missing.local/core.Version=9.9.9` and after the ignored record changes to `2.0.0`.
Source-built host CLI controls reject short, nondecimal-length, oversized and
trailing-byte frames with explicit parser failures. amd64 execution/Rosetta was not attempted.
Exact hashes and synthetic revision are in `results.json`.

## Record and runtime binding

`testdata/version.record` is a fixed canonical binary file. The synthetic CLI
source in `testdata/main.go.txt` embeds it as a **string**, and `Version()` parses
and returns the version from those exact embedded bytes. There is no second
version constant or linker version variable. The harness copies both into scratch
repositories; the file is deliberately ignored there to test generation behavior.
`Frame` validates generated input as the sidecar-compatible SemVer subset (no `+` build suffix) before the ignored-generation control.
The fixed fixture is independently validated before building.

The wire format is the full domain prefix `BIMERON.APPLE.CORE.VERSION/v1\0`,
three ASCII decimal length digits, `:`, 1–128 ASCII SemVer bytes without build metadata, and the exact
terminator `\0END.APPLE.CORE.RECORD/v1\0`. Numeric prerelease identifiers cannot
have leading zeros. Both `Frame` and `Parse` reject `+local` and other build suffixes. The CLI splits the prefix check into two literal pieces so
its parser does not itself introduce a second full domain prefix in rodata.

For this compiler and fixture the embedded string resides in Mach-O
`__TEXT,__rodata`, backed by a segment whose initial protections exclude write.
`Verify` accepts only a thin executable with the expected CPU, bounds regular-file reads to 256 MiB (including growth during the read), reads exactly one
such section (maximum 64 MiB), and requires exactly one full domain prefix within
it. It checks canonical framing and SemVer, expected version, Go OS/architecture,
Git revision, `vcs.modified=false`, and `-trimpath=true`. It rejects duplicate build
settings. Section placement is an observed compiler behavior and parser policy,
not a promised Go ABI or a dedicated ownership section. Other compiler versions
must repeat this experiment. The Go string's backing data is immutable through
normal Go string operations; its variable header and executable behavior are not
an adversarial trust boundary.

## Rejection coverage and trust boundary

Tests cover missing, duplicate, malformed, truncated, oversized, noncanonical
length and invalid SemVer records; binary record mutations; a full marker appended
outside the allowed section; a writable embedded byte-slice marker; wrong expected
version, revision, CPU and digest; ELF format rejection; same-length mutations of GOOS, GOARCH and missing/mismatched
VCS revision inside valid Mach-O files; absent VCS; and dirty tracked source.
The nonexistent `-X` argument is accepted by Go but cannot change the embedded
record or observed host CLI output. Both CPUs are statically verified, including all binary record mutations and
build-setting mutations. The duplicate control asserts two prefixes inside allowed
rodata. Section-size and regular-file-size limits have direct rejection controls.
Every record and build-setting mutation checks hash-first rejection before
recomputing its digest to isolate the subsequent parser or setting rejection.

The SHA-256 comparison occurs **before** Mach-O or record parsing. The expected
hash must come from an independently authenticated signed sidecar in a real
integration. Here it is computed by the harness: this tests the hash boundary,
not signature verification, signing policy, archive validation, or key lifecycle.
No real keys or signature code are used.

The ignored-generation control changes the record from `1.2.3-beta.1` to `2.0.0`
and still passes a matching static expectation with `vcs.modified=false` and the
same source revision. A tracked source edit is rejected. Thus clean VCS proves
neither the contents nor authorization of ignored generated inputs. Production
would need a validated generation recipe and a trusted version input bound to
release policy, plus independent reproducible rebuilds or builder attestations
when source derivation is required. Section location, build info and matching CLI
output alone do not prove authenticity against a malicious builder.

Full Core builds, consumer integration, universal binaries, signatures,
notarization, hosted CI, archive handling and VPN readiness remain untested.
