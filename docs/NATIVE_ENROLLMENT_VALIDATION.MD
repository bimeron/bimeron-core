# Disabled native enrollment: implementation validation

Tracking: [issue #73](https://github.com/bimeron/bimeron-core/issues/73).

## Scope and provenance

The implementation branch starts at actual base `83683e4b5c1a673f0d29d667c09b116f5805027b`. A local `git diff --quiet` confirmed tree equivalence with reviewed `66d84d8f4dcfc6ada625eb11894b19feea51b7ba`; this is not an ancestry claim. Immutable design commit `4330af30f505ffff1091b96e2e6dcfcef97036df` was cherry-picked as `d7dcf7f` before tests or source edits. All three design documents were read fully.

Tests were written first. `go test ./internal/nativeenrollment` failed with undefined model/codec API symbols before production source existed. The first implementation exposed an incorrectly transcribed golden fixture; the expected byte string was corrected to the specified offsets and exact 64-byte length. The final package has one production file and one test file, standard-library imports only, and no I/O. Clean fixtures are hypothetical; EligibleModelOnly grants no runtime permission.

No existing source, dependencies, updater, service, Desktop or CI files changed. A repository Go-source search found no imports or callers of nativeenrollment outside its own package. Existing wildcard CI test/vet coverage includes the package; no explicit list change was required.

## Local validation (2026-10-30)

Host: Windows amd64, Go 1.26.9. Dependency fetching was disabled with GOPROXY=off for full-suite and cross-target checks. No live-test opt-ins were enabled.

- `go test ./internal/nativeenrollment`: passed.
- `go vet ./internal/nativeenrollment`: passed.
- `go test -race -count=20 ./internal/nativeenrollment`: passed, including after final test additions.
- `go test ./internal/nativeenrollment -cover`: passed, 97.8% statement coverage. Coverage is not security proof.
- `go test ./...` and `go vet ./...`: passed on Windows amd64 using the existing offline/default harness. External reference-server and live fixtures remain subject to their existing skips.
- Targeted existing fake-file updater tests passed: executable replacement/activation failure, backup preservation after failed stop, missing staged executable, IPC health-check failure with running-state restoration, stopped-state preservation, staged digest expectations and version/protocol validation.
- Existing foreground/profile/owner tests passed in internal/control, core and internal/systemvpn with the offline selection from repository CI (plus Owner).
- `CGO_ENABLED=0 go build ./...` and `go vet ./...`: passed for windows/amd64, windows/arm64, linux/amd64 and linux/arm64. Foreign target tests were not executed on this Windows host; cross-vet compiles their applicable test sources but is not runtime evidence.
- `git diff --check`: passed.

The new tests exercise deterministic golden/invalid codec behavior, fail-closed classifications and check precedence, native-view absence, optional binding, observed generation/identity/phase changes, matching-sample ABA limitation and all eight pending-preserving events. The security fixtures supply explicit protected/unsafe/unknown classifications; they do not parse descriptors or prove Windows registry ACL enforcement. Matching samples cannot detect an unobserved A-to-B-to-A transition. The pending event chain includes mutex-host disappearance and never establishes settlement authority.

The non-enrolled fixture is a pure model regression. Existing packet/updater/foreground tests are independent baseline regressions; none integrates this disconnected package or proves protected admission enforcement. No claim is made that all admissions participate.

## Remaining gates and security limits

Enrollment and protected-install support remain DISABLED. There is no registry adapter, syscall, production caller, enrollment command, writer, Begin, settlement path, clean constructor, completion boolean or foreground bypass. Unknown evidence denies in the model. A future reader must independently establish native machine view, trusted SYSTEM/Administrators ownership, protected non-null DACL, effective rights and secure ancestor/absence handling. Caller-supplied classifications are offline inputs, not authentication.

Still missing: an accepted MSI outer terminal authority that survives host loss and handles rollback-disabled/nested removal cases; enforced participation and exclusion of old/incompatible runnable hosts; enrolled updater health-check and restored old-binary safety across success, rollback and updater death; durable serialized publication and recovery with generation non-reuse. Generation equality is neither ABA nor malicious replay protection. Administrator compromise/offline rollback is outside the contract.

No host registry, elevation, VM, network policy mutation, credentials, releases, tags, signing, assets or binary publication were used. Parent owns independent review, hosted CI and merge. Local passing tests do not close these architecture gates.
