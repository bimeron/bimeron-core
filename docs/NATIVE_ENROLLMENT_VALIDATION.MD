# Disabled native enrollment: implementation validation

Tracking: [issue #73](https://github.com/bimeron/bimeron-core/issues/73).

## Volume-root contract and failed native evidence

Documentation-only checkpoint, 2026-10-30. After fetching origin master, the fresh clean branch `docs/73-volume-root-contract` in `C:/Users/PC/.t3/worktrees/bimeron-core/docs-73-volume-root-contract` started at exact `6af5d72bd7e1e98461e78f437509a1994f395fab` (also fetched origin/master). The ancestry check for full old `83683e4b5c1a673f0d29d667c09b116f5805027b` returned 1. Only specification, acceptance, this validation and ADR 0029 change; no source edits or runtime tests occur in this checkpoint. Local verification is documentation diff/links/anchors and `git diff --check` only.

Parent-supplied evidence: native `clean` FAILED; ONE read-only repeat also returned UnsafeRead. The other 17 cases are UNEXECUTED. The captured root ACE for AU grants LC (`FILE_ADD_SUBDIRECTORY`, `0x4`), which the current parser refuses for outsiders. Nine actual-parser in-memory counterfactuals supplied by the parent establish that this ACE is a sufficient descriptor blocker under the old policy. They are NOT instrumented runtime attribution: the native reader has other refusal points and other failures remain possible. No new native or parser execution, exact raw SDDL capture, artifact hash verification or independent reproduction is claimed by this docs commit. The implementer must obtain the original captured SDDL/evidence from the parent before asserting exact-descriptor fail-old coverage.

The [accepted amendment](NATIVE_ENROLLMENT_SPEC.MD#volume-root-only-descriptor-amendment-2026-10-30) permits only root `0x4` with all remaining safeguards intact; it does not authorize changing a VM root ACL. The [LOW brief](NATIVE_ENROLLMENT_ACCEPTANCE.MD#volume-root-only-low-correction-contract) requires initial and repeated root-only policy selection, strict Program Files/descendant regressions, offline checks and a newly frozen source-bound proof executable. Historical frozen `3cf`-prefixed evidence below cannot validate a new source head. For the new binary all native cases remain UNEXECUTED until parent review, CI assessment and a new VM run. In-memory parser acceptance cannot stand in for native protected-file success.

Source inspection found the shared reader's initial root check and held-files recheck index 0, strict descendant checks, and no production import/caller outside nativeenrollment (the external updater import is test-only). No production integration is authorized. Enrollment stays DISABLED; atomic admission, unobserved ABA/replay, privileged whole-subtree deletion, authenticated runtime identity, compatible-host enforcement and terminal settlement remain unproved. Historical results below keep their original provenance.

## Integrated volume-root correction (2026-10-30)

Accepted contract commit `c791f18ab16e5994d1a655df06f44ab55805b487` preceded source. Source `483c8b451864a206aff67a59eb9337b3f47c04a5` was cherry-picked cleanly as `a3fb14c6` into `docs/73-volume-root-contract`, workspace `C:/Users/PC/.t3/worktrees/bimeron-core/docs-73-volume-root-contract`. Fresh `git fetch origin master` and `git merge-base origin/master HEAD` both establish base `6af5d72bd7e1e98461e78f437509a1994f395fab`; no newer master was folded in. Old `83683e4b5c1a673f0d29d667c09b116f5805027b` ancestry is absent. Actual three-dot scope is exactly the four central documents and descriptor/reader plus their two tests.

Inspection and regressions confirm only initial root and repeated held index 0 select the private root policy. Outsider `0x4` alone or with read/execute is accepted there; the same captured root descriptor is refused by strict Program Files/downstream policy. Strict fileDescriptor remains the default. Effective inherited rights, generic expansion, other mutation refusals, exact trusted ownership, non-null DACL, unknown-effective ACE refusal, inherit-only handling, protected container/leaf requirements and all identity/case/type/reparse/sharing/Expected checks remain. Caller/import/init inspection found only the existing updater test imports externally and no production integration.

The source handoff records fail-old `go test ./internal/nativeenrollment -run '^TestCapturedVolumeRootDescriptor$' -count=1` returning exit 1, captured root rejected, before production edits. This integration did not rerun or relabel that historical fail-old. The exact root and Program Files SDDL constants match parent metadata `C:/Users/PC/.t3/worktrees/bimeron-desktop/plan-stage-8-ikev2/build/vm-lab-evidence-20261030/core-reader-clean-metadata.json`, whose independently checked SHA-256 is `bee63055dd5eb6f9663ba8cf290a5b1858f7a353634e641b13b3017a1fc98b42`. In-memory parser acceptance establishes removal of a sufficient descriptor blocker, NOT native success or exact runtime attribution.

### New offline integration checks

Windows amd64, Go `go1.26.9`; all commands below passed with GOPROXY=off. Logs are local ignored `.tmp/root-policy-integration/*.log`. No baseline failure was observed. Focused verbose checks had no skips, including disposable reparse rejection. Full default suites retain existing external/live gates; they establish no new opt-in coverage.

```powershell
$env:GOPROXY='off'
go test -count=1 ./internal/nativeenrollment ./cmd/bimeron
go vet ./internal/nativeenrollment ./cmd/bimeron
$env:CGO_ENABLED='1'; $env:CC='C:/msys64/ucrt64/bin/gcc.exe'
go test -race -count=5 ./internal/nativeenrollment ./cmd/bimeron
go test ./...
go vet ./...
go test -count=1 -v ./internal/nativeenrollment -run 'Test(CapturedVolumeRootDescriptor|VolumeRootDescriptorPolicy|NativeRootPolicySelection|NativeReparseRejection|CodecGolden)$'
$env:CGO_ENABLED='0'
foreach ($target in @('windows/amd64','windows/arm64','linux/amd64','linux/arm64','windows/386')) {
    $env:GOOS,$env:GOARCH=$target.Split('/')
    go build ./...
    go vet ./...
}
$env:GOOS='windows'
foreach ($arch in @('amd64','arm64','386')) {
    $env:GOARCH=$arch
    go test -c -tags core_reader_proof -o .tmp/root-policy-integration/core-reader-proof-$arch.test.exe ./internal/nativeenrollment
    go vet -tags core_reader_proof ./internal/nativeenrollment
}
git diff --check
```

Cross-target and tagged compilation/vet are not execution. Integration binaries do not replace the frozen source artifact. Existing wildcard CI covers the packages; fresh independent review and hosted CI assessment remain parent-owned. No manual CI rerun, watch or merge occurred.

### New frozen artifact, unchanged goldens and limits

Frozen source workspace is `C:/Users/PC/.t3/worktrees/bimeron-core/core-root-policy-c791`, source commit `483c8b451864a206aff67a59eb9337b3f47c04a5`. Manifest `.tmp/root-policy/manifest.json` SHA-256 is `7256f876be36fd6daafd43badd09bada55698d4c95906743895b07f15fa2aae6`; exact source commands/failures/limits are `.tmp/root-policy/commands-and-limits.txt` there. All executable hashes were independently verified. `git diff --exit-code 483c8b -- internal/nativeenrollment` and all ten manifest Git blob comparisons passed. A raw source-file hash comparison initially differed because this integration checkout uses CRLF while the four edited source-workspace files use LF; this is Git source equivalence, not identical working-byte or build provenance.

Frozen build: Go 1.26.9, GOPROXY=off, CGO_ENABLED=0, GOOS=windows, compiler gc, tag core_reader_proof, amd64 GOAMD64=v1, empty GOFLAGS, no trimpath/ldflags. Build command from that workspace for each architecture: `go test -c -tags core_reader_proof -o .tmp/root-policy/core-reader-proof-$arch.test.exe ./internal/nativeenrollment`.

- NEW amd64: `.tmp/root-policy/core-reader-proof-amd64.test.exe`, SHA-256 `171bf714d74b32669c0b92a772b9e787c08d058549f66244feeb753ec262ee0c`.
- ARM64: `.tmp/root-policy/core-reader-proof-arm64.test.exe`, SHA-256 `77daf2a62629742c1a4a9cd15b52fd9bc8c5fc573710c454aa2945fb47ce8d3c`.
- 386: `.tmp/root-policy/core-reader-proof-386.test.exe`, SHA-256 `3e4351f47ce8d3dd7a4f6c9a6f496b18acb80f1a9185c685c22b312bf952a731`.

The manifest's exact 64-byte clean/pending hex matches unchanged TestCodecGolden and the historical hex below. SHA-256 remains clean `c94a8f5a50d77e7507d9627ced650c9eb0bb354dbbe60dc02aaf4bd8f6483b67`, pending `36455b4896921732c186f5058eef683cefd7b2ceefde8151052d868fc0d2b00b`.

Historical `3cf` binary: clean FAILED, one read-only repeat UnsafeRead, other 17 cases UNEXECUTED. NEW binary: ALL 18 cases UNEXECUTED; no tagged executable invoked, even without opt-in. Parent owns fresh independent review, CI assessment and any later disposable-VM run. ARM64 runtime remains unproved; 386 reader remains unsupported. No VM, root ACL modification, elevation, registry, SCM, network-policy, credentials, Desktop, writer, enrollment, settlement, production caller or binary publication occurred. Enrollment stays DISABLED. Atomic admission, ABA/replay resistance, durable privileged-deletion detection, authenticated runtime identity, compatible-host enforcement and terminal settlement remain unproved. Historical evidence below retains its original provenance.

## Protected reader proof: documentation-only checkpoint

The [frozen acceptance](NATIVE_ENROLLMENT_ACCEPTANCE.MD#protected-reader-proof-frozen-next-implementation-contract) records the parent-accepted next step before any implementation. Workspace `C:/Users/PC/.t3/worktrees/bimeron-core/docs-73-reader-acceptance`, branch `docs/73-protected-reader-acceptance`, starts directly at fetched origin/master `0dab6310f38613765fb8fb2bff1f2e5b9d6a6780`. HEAD matched that exact base before documentation edits; `git merge-base --is-ancestor 83683e4b5c1a673f0d29d667c09b116f5805027b HEAD` returned 1. No old squash ancestry was introduced.

This checkpoint changes only acceptance and validation Markdown. Source inspection covered the actual reader, descriptor/security checks, model, tests, specification and ADR; no source or test behavior changed. Documentation verification comprises the two-file diff, local link/anchor checks and git diff --check. No Go test/build/vet/race, tagged executable, fixture provisioning or native protected-positive execution is claimed for this docs commit. Historical results below retain their original heads and do not validate the future refactor.

The next implementer owes the two-file implementation, offline check results, frozen executable/golden hashes and parent provisioning brief. Every tagged native case remains UNEXECUTED pending independent review and parent-only VM provisioning/execution. In-memory descriptor evidence is not a native protected-file positive; cross-compilation is not ARM64 runtime evidence. Clean remains storage/model evidence, enrollment remains DISABLED, and atomic admission, unobserved ABA/replay, privileged whole-subtree deletion, authenticated runtime identity, compatible-host enforcement and terminal settlement remain open. No VM, elevation, SCM, updater, registry, Desktop, credentials, production integration, publication, CI rerun/watch or merge occurred here.

## Integrated protected reader harness (2026-10-30)

This section supersedes the documentation-only checkpoint for this delta. Acceptance `c21db02cf2626b6f2f88c0978a6cd609a7a8f5c4` directly follows `0dab6310f38613765fb8fb2bff1f2e5b9d6a6780`. Source `0facb42c7ff2cdcb890e930eab7ac36226e4fd28` was cherry-picked without conflict as `19273da9` in `C:/Users/PC/.t3/worktrees/bimeron-core/docs-73-reader-acceptance`, branch `docs/73-protected-reader-acceptance`. Fetched origin/master still equals that exact base; old `83683e4b` ancestry is absent. The three-dot diff contains only this validation, acceptance, and the two approved reader/harness files. The final documentation commit differs from the frozen build source; `git diff --exit-code 0facb42 -- internal/nativeenrollment` passed, establishing identical package source/test content, not identical build provenance.

Inspection confirms production passes nil prefix; B=P preserves all previous offsets. For the lab B=P+3, missing prefix indices never qualify as bootstrap absence, suffix offsets 0/1 alone may qualify, initial protected-DACL threshold is B+1 and held-file threshold B+2. Known-folder identity stays ids[P]. Actual native resolution/rechecks, held identities, security checks, read sharing, both bounded samples and reverse-close/error behavior remain unchanged. The tagged wrapper validates lowercase nonzero GUID and one of 18 closed IDs before traversal, uses the real anchor and asserts full Observation, Expected pointer and Evaluate result. There is no public arbitrary path, trust/resolver injection, writer, runtime permit or outside production integration. Repository searches found only the existing updater test imports externally; only the tagged test passes nonempty prefix.

### Offline integration checks

Windows amd64, Go 1.26.9, GOPROXY=off. All commands passed; no baseline failures observed:

```powershell
go test -count=1 ./internal/nativeenrollment ./cmd/bimeron
go vet ./internal/nativeenrollment ./cmd/bimeron
$env:CGO_ENABLED='1'; $env:CC='C:/msys64/ucrt64/bin/gcc.exe'
go test -race -count=5 ./internal/nativeenrollment ./cmd/bimeron
go test ./...
go vet ./...
$env:CGO_ENABLED='0'
foreach ($target in @('windows/amd64','windows/arm64','linux/amd64','linux/arm64')) {
    $env:GOOS,$env:GOARCH=$target.Split('/')
    go build ./...
    go vet ./...
}
$env:GOOS='windows'
foreach ($arch in @('amd64','arm64','386')) {
    $env:GOARCH=$arch
    go test -c -tags core_reader_proof -o .tmp/reader-proof-integration/core-reader-proof-$arch.test.exe ./internal/nativeenrollment
    go vet -tags core_reader_proof ./internal/nativeenrollment
}
git diff --check
```

Default suites retain their existing live/external-reference gates; no new live opt-in was enabled. Integration executables were compiled only and do not replace the frozen artifacts below. No tagged executable was invoked, even without opt-in. Skip-before-traversal is inspected/compiled, not a recorded runtime skip. Existing wildcard CI is unchanged; parent owns fresh hosted CI assessment and independent review. No manual rerun, watch or merge.

### Frozen source artifact and fixture manifest

All following paths are under `C:/Users/PC/.t3/worktrees/bimeron-core/t3-398f83ad/.tmp/reader-proof/`, ignored and untracked. Hashes were independently read during integration. Build source is exactly `0facb42c7ff2cdcb890e930eab7ac36226e4fd28`; Go 1.26.9, windows target, CGO_ENABLED=0, compiler gc, amd64 GOAMD64=v1, tag core_reader_proof, no trimpath/ldflags/custom GOFLAGS. Handoff records `go test -c -tags core_reader_proof -o .tmp/reader-proof/core-reader-proof-<arch>.test.exe ./internal/nativeenrollment` from that source workspace for each architecture.

| Artifact | SHA-256 |
| --- | --- |
| core-reader-proof-amd64.test.exe | 3cf34ad70030742e57d2cfc8b40d89f7b00318f392957708abe251340885c264 |
| core-reader-proof-arm64.test.exe | 4c85edf01290732da6da3dfc09d9febd78a0a0342fe9b0a0e50b631c00e42eea |
| core-reader-proof-386.test.exe | f787a2220482e6dad1b7f58fbdb7ea6def4d090deaf59d7ce1b350dd315cada0 |
| clean.bin (64 bytes) | c94a8f5a50d77e7507d9627ced650c9eb0bb354dbbe60dc02aaf4bd8f6483b67 |
| pending.bin (64 bytes) | 36455b4896921732c186f5058eef683cefd7b2ceefde8151052d868fc0d2b00b |
| handoff.txt | ccd47c190355013872226c9b9879a951ecd683bd7eacc991f3775db17bf83f9c |

Exact goldens match TestCodecGolden (generation 1, installation `[16]byte{1}`, clean zero operation, pending operation `[16]byte{2}`):

```text
clean:   42494d4e454e52310100010000000000010000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000
pending: 42494d4e454e52310100020000000000010000000000000001000000000000000000000000000000020000000000000000000000000000000000000000000000
```

### Parent-only provisioning brief: UNEXECUTED

The exact detailed brief is local `handoff.txt` above, including descriptors, evidence requirements, invocation and cleanup. Proposed run GUID `73b1c9d0-4ed2-4e54-bba7-49e4bda9f682` must first be independently verified unused. PF is the actual nativeProgramFiles zero-flags result on the disposable native VM. R is PF/BimeronCoreReaderProof/run-guid; each case has its own R/case/Bimeron Core/NativeEnrollment/record.bin. No guessed/environment anchor or production tree is permitted.

Baseline proposed for newly provisioned objects: BA owner; directories `D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)`, leaf `D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;BU)`. Existing ancestors must independently pass without ACL repair. All are disk objects on the same fixed GUID volume, stable nonzero IDs, no reparse, directory case flags zero, leaf one link. Parent must record actual owner/DACL/control/effective ACEs, attributes, case flags, IDs/links, precise missing-child/sharing errors and binary/source/fixture hashes before each execution; all other ancestors must pass, so an unrelated refusal cannot validate the named fault.

C means Present with both protected NativeView clean snapshots and LegacyUnchanged/EligibleModelOnly/cleanModelOnly. P means Present with pending snapshots and RefuseProtectedAdmission/Refuse/pending. A means ProtectedAbsence with both protected empty NativeView snapshots and LegacyUnchanged/Unavailable/notEnrolled. U means UnsafeRead with zero snapshots and RefuseProtectedAdmission/Refuse/unsafeEvidence. M is matching installation/generation 1; S is same installation/generation 2. Expected must be retained exactly.

| Closed case | Required deviation from full clean baseline | Expected | Required result |
| --- | --- | --- | --- |
| clean | none | nil | C |
| clean-match | none | M | C |
| clean-stale | none | S | C snapshots; bindingMismatch/refusal |
| pending | pending.bin | nil | P |
| pending-match | pending.bin | M | P |
| pending-stale | pending.bin | S | P snapshots; bindingMismatch/refusal |
| absent-core | case directory exists; exact Bimeron Core absent | nil | A |
| absent-container | Bimeron Core exists; exact NativeEnrollment absent | nil | A |
| absent-core-bound | own absent-core tree | M | A snapshots; bindingMismatch/refusal |
| absent-container-bound | own absent-container tree | M | A snapshots; bindingMismatch/refusal |
| missing-prefix | R exists; exact case directory absent | nil | U, never absence |
| missing-leaf | full directories; record.bin absent | nil | U |
| unsafe-owner | leaf owner BU | nil | U |
| unsafe-dacl | leaf DACL additionally allows BU GW | nil | U |
| case-sensitive | case's Bimeron Core directory case flags nonzero | nil | U |
| reparse | case's Bimeron Core directory is reparse | nil | U |
| multilink | leaf link count >1 | nil | U |
| sharing | parent holds existing leaf FILE_WRITE_DATA writer | nil | U |

Reparse tag/target and second hard-link location require parent approval within this isolated run before provisioning; no arbitrary alias/target is approved here. Parent closes its sharing handle on every outcome. Only after independent source/manifest review may parent use existing PSDirect, set ENABLE=1, RUN and one exact CASE, and invoke the frozen executable with `-test.run=^TestCoreReaderProof$ -test.v -test.count=1`. Preserve evidence before cleanup of only the independently verified exact run/approved same-run aliases, without following reparses or removing common parents. No provisioning or cleanup script is supplied.

All 18 protected native cases remain **UNEXECUTED**, not passed or runtime-skipped. Native ARM64 runtime remains unknown; 386/emulation is unsupported. In-memory descriptor positives remain parser evidence only. Enrollment remains **DISABLED**. No atomic admission, ABA/replay resistance, durable privileged-deletion detection, compatible-host enforcement or terminal settlement is proven. This integration performed no VM/provisioning, elevation, registry, SCM, updater mutation, network-policy, credentials, Desktop, signing, binary publication, enrollment or production hooks.

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

## Executed P1/P2 correction (2026-10-30)

Implementation starts exactly at accepted specification `c13b134a47c5ac01c795e8535078d9669afade12`, on `feat/native-offline-reader-updateproof`, for PR #76. This section supersedes the earlier COMMENT ONLY model scope and documentation-only correction disclaimer: model.go now changes disconnected production logic. No outside production caller or initializer exists; enrollment remains disabled.

P1 review response: Evaluate retains evidence/security, view and nonempty-absence precedence, then refuses every supplied Expected binding on protected absence with bindingMismatch. Expected is never cleared. Nil-bound empty trusted absence retains LegacyUnchanged/Unavailable/notEnrolled. Before the logic edit, the following command failed BOTH new tests with `{Packet:1 Native:1 Reason:notEnrolled}`, wanted bindingMismatch:

```powershell
go test ./internal/nativeenrollment -run 'Test(ProtectedAbsencePriorBinding|NativeBootstrapAbsencePriorBinding)' -count=1
```

Model cases cover multiple valid bindings and invalid supplied bindings. The test-only readerEvidenceBootstrapAbsence seam covers first missing Bimeron Core, missing NativeEnrollment, prior bound-record disappearance and unsafe missing record inside an existing container. These are synthetic classification evidence, not protected native positives or privileged deletion execution.

P2 review response: a single private resolver uses real IsWow64Process2 plus the compiled process architecture. Only native amd64-on-amd64 and arm64-on-arm64 select FOLDERID_ProgramFiles with flags zero; initial selection and identity rechecks reuse it. 386, emulation, unknown/unproven pairs and query/resolver failure refuse. No ProgramFilesX64, environment, registry, guessed path or processor-feature fallback remains. Known-folder object identity, zero case-sensitivity, descriptor checks, held parents and volume GUID pins remain required. This deliberately sacrifices reader availability on 386, including 386-on-64; it is not bitness-independent resolution.

Commands below passed on Windows amd64 Go 1.26.9 with GOPROXY=off. The full suite uses the existing default offline harness; no live opt-in was enabled. Native disposable reparse coverage passed without a skip.

```powershell
$env:GOPROXY='off'
go test ./internal/nativeenrollment -count=1 -v
go vet ./internal/nativeenrollment
$selection = 'Test(FileDescriptor|Native|BoundedNative|Codec|Evidence|ProtectedAbsence|Pending|ValidationOrder|Health|Update|InvalidOperation|ServiceExecutable|FailedStop|MissingStaged|FailedIPC|StoppedService|LegacyWindows|WindowsSource)'
go test -count=1 -v ./internal/nativeenrollment ./cmd/bimeron -run $selection
go vet ./internal/nativeenrollment ./cmd/bimeron
$env:CGO_ENABLED='1'; $env:CC='C:/msys64/ucrt64/bin/gcc.exe'
go test -race -count=5 ./internal/nativeenrollment ./cmd/bimeron -run $selection
go test ./...
go vet ./...
go test ./internal/control ./core ./internal/systemvpn -run 'Test(Foreground|ProfileControl|ObservedFailedStartup|NativeCleanupSnapshot|NativeStatusIsCopied|ReviewedProfileToken|Owner)' -count=1
$env:CGO_ENABLED='0'
foreach ($target in @('windows/amd64','windows/arm64','linux/amd64','linux/arm64')) {
    $env:GOOS,$env:GOARCH=$target.Split('/')
    go build ./...
    go vet ./...
}
$env:GOOS='windows'; $env:GOARCH='386'
go test -c -o $env:TEMP/nativeenrollment-p1p2-386.test.exe ./internal/nativeenrollment
& $env:TEMP/nativeenrollment-p1p2-386.test.exe '-test.run=^TestNativeResolverRuntime$' '-test.v'
git diff --check
```

Real native amd64 resolver output: GOARCH=amd64, process=0x0, native=0x8664, query success, path `C:\Program Files`, resolver success, equal to the direct zero-flags known-folder query. Actual read-only 386 executable output: GOARCH=386, process=0x14c, native=0x8664, query success, empty path, resolver error; public observation asserted UnsafeRead and identical Expected pointer. An initial PowerShell invocation with unquoted dotted test flags was rejected by the test argument parser; the quoted command above executed and passed. ARM64 was cross-built/vetted only, never executed. No protected positive fixture was manufactured.

B carry-forward: `git diff --exit-code 94154c1abd8493e637f599fa829704d4e21c1b0b --` with the following four paths returned zero. Their Git blob IDs remain unchanged, preserving the independently reviewed B content:

| Path | Git blob |
| --- | --- |
| cmd/bimeron/service_update_files_test.go | 9e17ab8c562e485d028167a73f9201315ce7c62a |
| internal/nativeenrollment/update_health.go | 3f404ab89b916f71eeac0283785ed07d3c51782e |
| internal/nativeenrollment/update_health_test.go | 37969fff8621f8bcc064b9115597293aae481e98 |
| internal/nativeenrollment/update_proof_test.go | f57dba6ac3369e774e670978f93a97cd5f317b46 |

Go-source caller/import/init searches again found no outside production import/caller or package initializer; the only external import is the existing updater test. The implementation delta is the four owned model/reader files plus this centralized validation document. No other production logic changed. PR #76 scope is corrected to acknowledge the model logic change and native-only release constraint. Historical old-head CI (including its 14 successful checks) does not validate this fix. Fresh independent reader review and hosted CI assessment at the pushed head remain parent-owned; no manual rerun, watch or merge was performed.

Limits remain: no ARM64 runtime or trusted protected-file positive, atomic admission, unobserved ABA/replay resistance, durable privileged-deletion detection, authenticated runtime SCM/process identity, compatible-host enforcement or terminal settlement. No MSI/SCM operation, protected writes, registry, elevation, VM, credentials, network policy, Desktop, writer, enrollment, startup hook or runtime admission permit was introduced or exercised.
