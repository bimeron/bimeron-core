# ADR 0032: Retained Apple Core release version

Status: Approved for local integration only; publication and shipping blocked.

## Context and scope

Core85 draft 643d4863d468a0a922d792b52aa74b477cfee065 is imported locally,
without changing its original worktree. Its separate Apple manifest schema,
compatibility policy and trust gates remain intact. Prototype 139d20b demonstrates
Go 1.26.9 retention and static recovery with trimpath on both macOS CPUs.
The former exact ldflags recipe cannot establish runtime version and is omitted
by Go under trimpath. The user approved replacing that evidence locally.

## Decision

Use an explicit Apple release build selection, `bimeron_apple_release`, only on
Darwin. Default builds retain existing core.Version and legacy -X behavior.
Apple GetBuildInfo obtains version from a generated canonical embedded immutable
record, never a second linker version value. Share canonical version validation
and framing rules between generation, runtime extraction and static verification.
The compiler must retain exactly one record in the bounded read-only Mach-O
__TEXT,__rodata section after -trimpath -s -w; reject unsupported placement.

The standalone Apple-only build entry point requires an explicit exact approved
version and full source revision; it validates them, requires clean tracked source,
generates deterministic record bytes, builds both CPUs with explicit Go VCS
stamping, and validates output against those expectations. It performs no signing,
publication, candidate approval or key handling. Record bytes and the approved
version are additional explicit build inputs; an ignored generated file and
vcs.modified=false alone do not authenticate those inputs. Regenerate and validate
on every build, fail closed on missing or malformed inputs, and record the recipe.
Do not modify legacy build-dist or its publisher. No default trusted candidate,
key, review approval or network access is introduced.

Only replace the binary ldflags requirement in Apple validation with exact
record version recovery. Preserve thin executable CPU, Go OS/architecture, exact
source revision and explicit clean state, authenticated archive size/hash before
ZIP parsing, and all existing ZIP path/type/size checks. No JSON wire change.
Static parsing remains bounded and rejects absent, duplicate, malformed, truncated,
oversized or mismatched records. Runtime uses those same record bytes.

## Alternatives and limits

Dropping trimpath leaks paths and loses path-independent output; linker recipes
still do not prove runtime values. Manifest/attestations authenticate declarations
but do not recover version. A custom native section adds linker-specific machinery
unnecessary for the observed pinned compiler. Compiler/section layout changes must
fail closed and require fresh tests. Generated ignored bytes remain outside Git
source identity; reproducible recipes must enumerate them. Neither embedded data,
VCS metadata nor CLI output prevents a malicious builder from forging claims.
Signed archive hash, pinned trust, source derivation and VPN readiness are distinct.

## Validation and integration boundary

Exercise real locally source-built Core version output on host arm64; build and
statically inspect amd64 separately without claiming runtime execution. Compare
both CPU outputs across checkout paths at the same clean commit with identical
explicit inputs. Preserve stripping, negative controls, release-library tests,
legacy version behavior and synthetic signature vectors. Record environment/cache
limitations rather than enabling networking. Independent local review is required
before handoff. Production publication, remote changes and consumer G/E integration
remain paused; consumer binary-evidence policy must be updated in a later scope.
