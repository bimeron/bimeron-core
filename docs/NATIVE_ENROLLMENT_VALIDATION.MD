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

## Combined disconnected reader and updater evidence (2026-10-30)

This section supersedes the historical no-I/O/no-reader description only for the accepted A+B delta. Enrollment remains DISABLED. Workspace: `C:/Users/PC/.t3/worktrees/bimeron-core/t3-22e3e8cb`; branch: `feat/native-offline-reader-updateproof`. Immutable specification head `b0ebc0757e4d3b011bbd45ddf11d4613c0b0940b` directly follows `d124178dd85fd2e8e8ef8a333054eccdf34dafe3`. After `git fetch origin master`, `git merge-base origin/master HEAD` returned that exact d124178d base. `git merge-base --is-ancestor 83683e4b5c1a673f0d29d667c09b116f5805027b HEAD` returned 1: the old squash is not an ancestor.

A `089045015e56b7dff281a8f949f1325c5fcbf32e` and B `f8eaac7fc48d1439de58c0219dba71d693522388` cherry-picked without conflicts as `6093c9a7` and `30f54b7a`. Combined source/test head `940ac15f634371f97a9f8426333fb0f6b7ff7b56` adds exact expected updater callback event sequences: the original relative-order assertions alone could miss an omitted callback. The only existing production change is the model.go package comment, correcting its stale no-I/O statement; codec/model behavior is unchanged. Documentation is centralized here and in the existing accepted specification, acceptance and ADR 0029.

### Commands and results

Host: Windows amd64, Go `go1.26.9`; local race compiler `C:/msys64/ucrt64/bin/gcc.exe`. All Go checks below used `$env:GOPROXY='off'`. No live opt-in was enabled. The focused selection was exactly:

```powershell
$selection = 'Test(FileDescriptor|Native|BoundedNative|Codec|Evidence|Pending|ValidationOrder|Health|Update|InvalidOperation|ServiceExecutable|FailedStop|MissingStaged|FailedIPC|StoppedService|LegacyWindows|WindowsSource)'
go test -count=1 -v ./internal/nativeenrollment ./cmd/bimeron -run $selection
go vet ./internal/nativeenrollment ./cmd/bimeron
go test -race -count=5 ./internal/nativeenrollment ./cmd/bimeron -run $selection
go test ./...
go vet ./...
go test ./internal/control ./core ./internal/systemvpn -run 'Test(Foreground|ProfileControl|ObservedFailedStartup|NativeCleanupSnapshot|NativeStatusIsCopied|ReviewedProfileToken|Owner)' -count=1
```

All passed, with no baseline failures observed. Every new nativeenrollment test and the actual updater-helper ledger ran in the focused selection. The disposable reparse test passed without its optional symlink skip. Protected native positive execution was unavailable and was not attempted; in-memory Windows descriptors provide the positive parser evidence. Full-suite success is limited to the existing default offline harness: external reference binaries, opt-in live tests and privileged integration remain subject to their existing gates, not newly executed acceptance evidence. Raw full-suite and vet output was captured locally in `$env:TEMP/native-integration-full-test.log` and `$env:TEMP/native-integration-full-vet.log` (not repository artifacts).

```powershell
$env:CGO_ENABLED='0'
foreach ($target in @('windows/amd64','windows/arm64','linux/amd64','linux/arm64')) {
    $env:GOOS,$env:GOARCH=$target.Split('/')
    go build ./...
    go vet ./...
}
$env:GOOS='windows'; $env:GOARCH='386'
go test -c -o $env:TEMP/nativeenrollment-integration-386.test.exe ./internal/nativeenrollment
git diff --check
```

Every build/vet and the 386 test compilation passed. Foreign-target compilation/vet is not execution. No foreign-target runtime or privileged native-positive result is claimed. Existing wildcard CI includes these packages; no workflow edit or manual CI rerun was made. Parent owns independent review, hosted CI and merge.

### Security inspection and evidence limits

The actual reader resolves FOLDERID_ProgramFiles with flags zero, traverses a fixed local volume GUID root through held parent-relative handles, and compares known-folder identity against that traversal. Opens use read access, existing-object disposition and read sharing only. Every ancestor/leaf is checked for disk type, reparse attributes, volume/file identity and safe descriptor rights; directory case-sensitive flags must query successfully and equal zero. Parent-child identities, descriptors and known-folder mapping are rechecked while the chain remains held. WOW64 Program Files versus ProgramFilesX64 identity mismatch denies. The only public reader location is `Bimeron Core/NativeEnrollment/record.bin`; the arbitrary-path seam is private and retains all checks.

The descriptor parser uses real OS/in-memory descriptors, exact SYSTEM/Administrators/TrustedInstaller owner and allow trust, protected present non-null container/record DACLs, file generic-right expansion, inherited effective mutation checks and conservative unknown-effective-ACE rejection. Deny ACEs cannot excuse unsafe allows. Inherit-only entries are deliberately excluded from effective rights. Disposable tests establish native rejection, sharing pins, type/hard-link/reparse rejection and cleanup-error reporting; they cannot manufacture a trusted native positive. Exact missing bootstrap directories beneath a validated held ancestor differ from a missing record inside an existing enrollment container, which remains unsafe. Samples are bounded to 65 bytes; the 64-byte goldens remain unchanged and 48-byte LPF input is rejected.

B tests call real replaceServiceExecutable/restorePreviousService helpers against temporary files, with activation/health failures, blocked stop/remove/restore, restored running/stopped observations and simulated death boundaries. Exact callback sequences supplement byte and backup assertions. The rename-failure fixture moves backup bytes to a separate retained fixture path to force the real restore rename failure; it is not production backup-retention evidence for that artificial external move. The pending ledger is test-local and remains unchanged; it is no durable transaction journal. The AST regression inspects the actual Windows restore callback's Start/waitServiceState calls. Legacy restored-running means SCM Running only, with no restored IPC probe; stopped cases invoke no start/IPC probe. No SCM service was operated.

Health evidence binds installation/generation/operation, challenge, PID/creation time, held image volume/file/digest and exact role/version/protocol. Inputs remain unauthenticated offline observations. Repeated identical inputs cannot detect replay; a future authenticated transport must obtain identities and consume fresh challenges. Complete runnable and rollback set fixtures reject unknown/incompatible members but cannot enforce completeness or prevent later old-host return.

Repository Go-source import/caller/initializer searches found ZERO production imports of nativeenrollment outside its package, and no production caller or init hook. Only cmd/bimeron/service_update_files_test.go imports it externally. The actual three-dot scope is the four approved documents, seven new nativeenrollment source/test files, the existing updater test file and model.go COMMENT ONLY. No runtime packet/updater/Linux semantics, enrollment/writer/repair/delete/settlement path, registry, Desktop, VM, elevation, credentials, installation, network policy, signing or release work was added.

This partial scope proves no atomic admission, ABA/replay resistance, privileged-deletion detection, native authentication, SCM execution, compatible-host enforcement, safe enrolled rollback set or terminal settlement. Native protected positives, independently authenticated runtime SCM/process identity, enforced compatible runnable/rollback sets, and an accepted outer terminal authority remain open gates. Enrollment stays disabled.

## P1/P2 correction validation disclaimer

The reader review at `94154c1abd8493e637f599fa829704d4e21c1b0b` found that protected absence bypasses supplied Expected binding, and WOW64 handling compares process ProgramFiles against ProgramFilesX64 instead of resolving the native folder directly. Earlier passing checks above did not cover those contracts. The new specification/acceptance correction is documentation only; no new runtime validation is claimed here. After implementation, model.go will contain a disconnected production-logic change and the earlier COMMENT ONLY scope statement will no longer describe the PR. The parent must record the exact fix head, fail-old regressions, read-only 386 unsupported-resolution execution, native resolver checks, cross-builds, independent review and CI evidence. Native ARM64 execution and protected native positive coverage remain unproved; 386-on-64 native-folder resolution is explicitly unsupported under the bounded documented API strategy. Enrollment remains disabled and there are no outside production callers.
