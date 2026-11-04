# Apple Core binary provenance investigation

Status: proposal for discussion; no production architecture selected or changed.
Baseline: Core master 7cc55f0; inspected Core85 draft worktree and consumer G read-only.
No publication, networking, keys, trust pins, compatibility approval or readiness claims.

## Evidence

Run `python3 research/apple-core-provenance/experiment.py` from this checkout.
It uses the locally installed Go toolchain, disables dependency networking, builds
only synthetic source, and reads generated binaries with `go version -m`.
Generated binaries are never executed. Scratch repositories and build cache stay
inside this worktree. `results.json` records Go 1.26.9 and all build-info output.
Both darwin/arm64 and darwin/amd64 were cross-built with CGO disabled.

For both architectures, `-trimpath -ldflags '-s -w -X
bimeron/core.Version=0.1.0-beta.1'` removes the entire `-ldflags` setting but retains
GOOS, GOARCH, vcs.revision and vcs.modified=false. Without trimpath, ldflags
survive. Two copies of the same synthetic commit in different directories yield
identical hashes with trimpath; without it hashes differ and the checkout path
is present in binary bytes despite stripping symbols/debug information.
This demonstrates path independence for this fixture, not universal reproducibility
across toolchains, SDKs, cgo, signing, timestamps or archive construction.

Local Go source `src/cmd/go/internal/load/pkg.go` explicitly suppresses ldflags
when trimpath is enabled because linker arguments can disclose paths (issue 52372).
Stripping `-s -w` is not the relevant switch.

The fixture deliberately has NO bimeron/core.Version variable. Go nevertheless
accepts the exact -X argument and records it in untrimmed build info. A copied,
unmodified Core85 checkBinary accepts those untrimmed binaries for both CPUs;
it rejects trimmed equivalents with missing Core version evidence. The additional
assertion is preserved as `validator-test.go.txt`; copy it into an isolated copy
of Core85's applemanifest package and set PROVENANCE_SCRATCH to this scratch
absolute path to reproduce. Thus linker recipe metadata is not independently
recovered runtime version, even before the trimpath problem.

A reachable synthetic provenance string survives all eight builds. This is a
feasibility check only: byte presence is not a production parser or a guarantee
that the executable's version command uses that value.

## Options and recommendation

1. Remove trimpath only for separate Apple builds. Smallest producer diff;
   current Core85 validator accepts the existing exact recipe without a schema
   change. Costs: source/toolchain path disclosure and checkout-dependent bytes.
   More importantly, recipe metadata still does not prove the variable exists or
   equals the runtime version. Consider only if the requirement is explicitly
   narrowed to declared build recipe evidence; it does not meet independent
   static version recovery. Do not change legacy build-dist globally.
2. Retain trimpath and add a stable, bounded version record retained in the
   executable, generated from the same validated version input used by the CLI.
   Recommended smallest design that preserves path trimming AND static version
   recovery. Prefer a generated source constant used directly for runtime version
   and a domain-separated framed record; remove competing Apple -X overrides.
   A static parser must require exactly one canonical record in an allowed Mach-O
   data region, reject absent/duplicate/malformed/mismatched records, and compare
   its version with the signed sidecar. Avoid a raw unbounded strings search.
   Exact framing, retention and section ownership need a separate small prototype
   before agreement; a Go string alone does not guarantee a dedicated section.
   Preserve GOOS/GOARCH, thin executable CPU, exact revision and clean-tree checks.
   Generated-source staging must not silently bypass vcs.modified=false: generate
   in an ignored build-only package or use a committed release value, explicitly
   test dirty tracked source rejection, and document the generation recipe.
   Requires producer code/generator, Core85 parser/tests and contract/ADR amendment;
   no new signed JSON fields are inherently necessary. Not implemented here.
3. Rely on signed manifest or additional build attestations binding archive hash
   to version/source. Keeps trimpath and can authenticate a builder's declaration;
   it cannot recover binary version independently. A separate attestation requires
   builder identity, verification and lifecycle policy; the current sidecar already
   binds archive hash to a source/version declaration. This is a different trust
   requirement, not a transparent substitute for option 2.

All three need an explicit decision. Option 1 is the smallest textual change;
option 2 is the smallest recommended change meeting the stated evidence goals.
No self-reported metadata proves source derivation cryptographically: malicious
builders can forge build info, embedded records and CLI behavior. Independent
reproducible rebuilds or trusted-builder attestations address that separate claim.
Signed hashes authenticate final archive bytes and signed declarations under the
trusted key; they do not prove a declaration true or demonstrate VPN readiness.

## Producer and consumer scope

Core85 currently checks thin Mach-O CPU/type, Go build info and exact ldflags;
preparation and verified archive checking share the strict code. Keep rejection
in place until an agreed replacement exists. Preserve the separate Apple sidecar,
exact candidate/trust gates, archive hashes/size and strict ZIP validation, and the
legacy publisher unchanged. Update docs/apple-update-manifest.md and ADR0031 only
after the provenance decision; this research is not a superseding ADR.

Consumer G's AppleCoreRelease.swift verifies signed descriptor and candidate
identity; its source_revision field is a signed declaration. Its documented
provenance blocker must be updated only after replacement evidence is validated.
Any consumer executable validation must adopt the same agreed evidence policy;
manifest-only success cannot stand for binary validation. No SwiftUI changes are
needed, and paused G/E owners were not contacted.

Before production adoption, test both CPUs: version runtime/record agreement on
source-built trusted fixtures; missing/wrong/duplicate/truncated record; wrong
version/revision/CPU/OS; dirty and missing VCS; signed hash tampering before parsing;
and identical builds from distinct paths. Include dead-code/linker retention and
fake marker in unrelated data negatives. Full Core builds, signed/notarized outputs,
consumer integration, hosted CI and actual VPN readiness were not tested here.
