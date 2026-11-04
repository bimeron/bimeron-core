# Production scope for later approval

This is a local prototype plan, not an accepted production ADR.

The current real CLI `cmd/bimeron/version.go` emits `core.GetBuildInfo()`;
`core/version.go` currently copies mutable `core.Version` into that response.
Changing only a linker record would leave two independent values and fail the
binding requirement. A future Apple implementation must have GetBuildInfo obtain
its version from the same embedded canonical record consumed by static checking.
The synthetic prototype tests that data-flow pattern, not the full application's
runtime integration. Existing daemon hello, doctor and repair expectations also
consume BuildDetails and must continue to agree. Preserve their JSON shape.

Prefer an immutable go:embed string retained by a function that extracts version
from the record itself. Unlike a separate version constant plus metadata string,
this gives the CLI one input. Do not expose an Apple mutable Version override.
Keep the legacy build's -X behavior behind a separate build selection if adopting
this in production; review all direct core.Version callers before choosing that
selection. Production build-tag/API design needs approval and regression checks.

An ignored generated record keeps tracked source clean but is not authenticated
by vcs.modified=false. It is an explicit additional build input. The generator
must validate a locally approved exact version, write deterministically, verify
its output before building, and the final static check must compare the recovered
version with the approved version and signed declaration. Clean VCS settings alone
do not prove ignored inputs. A release pipeline should enumerate/hash all generated
inputs in its reproducibility recipe. Do not bypass clean checks by rewriting
tracked files or forcing VCS metadata through linker arguments.

A bounded record search in an explicitly allowed read-only Mach-O section avoids
whole-file arbitrary strings discovery. Require unique framing and canonical
length/version syntax; reject ambiguous candidates. It does not establish an
adversarial producer's honest control flow. A malicious binary can embed a valid
record while reporting anything. Trust in signed archive bytes, builder/source
claims, and independently reproduced builds remains a separate boundary.

## Prototype review outcome

The executable record is now demonstrated using an immutable embedded string in
Go 1.26.9's `__TEXT,__rodata`; no custom linker section or post-link binary patch
is required. Recommend this observed placement policy for an initial production
proposal, retaining the pinned compiler matrix and fail-closed behavior if section
placement changes. The prototype uses a domain prefix, three fixed decimal length
digits, a colon, at most 128 contract-compatible version bytes, and an exact NUL
framed terminator. Static verification demands one candidate in one allowed
read-only section, then exact expected version. No build suffix is accepted.

The CLI extracts its version from the record itself. Its small framing decoder
assumes generation has already validated SemVer; the static verifier independently
validates SemVer and canonical framing. That deliberate split is acceptable for
this synthetic feasibility experiment, but a future production API should make
invalid generated input a build failure and include runtime/parser agreement tests.
The synthetic main is not the real Core CLI; no full Core integration is claimed.

Before approving a production patch, explicitly agree on the Apple-only build
selection and generator/version authority, then amend the Apple binary-validation
contract and ADR0031. Keep signed JSON shape and legacy publication unchanged.
Replace only the ldflags evidence requirement with the agreed embedded record
policy; retain revision/clean/CPU/OS/architecture/hash/ZIP checks. Port structural
and bound checks into the existing validator rather than treating this research
path-based Verify helper as a production archive verifier. Use bounded in-memory
archive bytes already authenticated by the current sidecar. Harden segment/section
range relationships for hostile Mach-O inputs as part of that integration.

A later production review should exercise full CLI/daemon JSON agreement, legacy
-X behavior, actual archive bytes, compiler upgrades and signed/notarized final
outputs. Those checks remain outside this approved local prototype.
