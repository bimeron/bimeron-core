# Integration delta and verification limits

Offline candidate for fresh-run administrative recovery (see SPEC.md). Not admitted
for operational use.

## Implemented (offline, inert seams)

- Admission, private root, request reservation ledger, sticky failure retention
  (`admin_recovery.py`, `admin_entry.py`, `preparation_entry.py`, `admin_bootstrap.py`).
- Fixed original-owner `advance` continuation (`admin_handoff.py`): monitor drain,
  Stage.before_restore / restore permit, ResidentRPC readback, close, finish, phase1,
  capture confirmation/archive, sink retirement, cooperative watcher, phase2, SETTLED.
- Pre-controller branch: an explicit retained `controllerEntered=False` record seals an
  empty reader inventory over the same retained preparation Popen
  (`OriginalProcesses.observe_original`); no spawn, no PID reopen, no guest replay.
  Covered by `test_admin_handoff.py::test_precontroller_identity_failure_keeps_same_child_and_finishes`.
- Sink `--collect` ExecStopPost receipt plus exact-unit `systemctl stop` with
  `SendSIGKILL=no` (`sink_contract.py`); phase2 requires receipt plus fresh unit absence.
- Two-step watcher admission: idle watcher started at bootstrap, idle abort before
  capture config (`admin_containment.py`, `admin_watcher*.py`).

- r5 admission corrections (SPEC.md "Live admission corrections"): embeddable
  interpreter pinned strictly inside `admissionRoot` (`python` config object);
  no git process against the original checkout (`gitCheckout` config object,
  pinned `.git`/`gitdir`/`commondir`/`HEAD`/ref metadata); relaxed ancestor mask
  limited to true ancestors; system executable pin evidence.

## Verification performed

`check_offline.py` run `validation/run-5d7d3f12cf5846c3810d6a12ba8b3218` (newer than every
candidate source, after the r5 corrections: strict embeddable interpreter, git-free
checkout metadata, ancestor-only relaxed mask, system executable evidence; and the
r5 review fixes: `python.treeSHA256` bound in configuration and review
(`fresh-admin-review-v2`), pyvenv.cfg/base-executable/prefix refusal, `ssh -F none`
on every candidate ssh argv with the body argv published to the Handoff; no bare
local executable names, enforced by a static Python/PowerShell scan test):
test_admin_recovery 54/54, test_admin_handoff 5/5,
test_rpc_regression 16/16, each also under `-O`; PS5.1 and PS7 resident inert tests;
PowerShell parser over all 64 runtime scripts; both sealed snapshots verified before and after.

## Not verified / live gates (mandatory before any operational use)

- Native CreateDirectoryW protected-DACL admission and ProcessPin behaviour (syntax/inspection only).
- Native read-only source pins on the real host ACLs (inert CreateFileW/ReadFile doubles only).
- Installed systemd ExecStopPost property rendering and `--collect` receipt on the lab guest.
- Real PowerShell remoting resident session, Process execution-policy capture/restore.
- Real capture supervisor, sink, watcher and SSH transport; all were inert test doubles.
- Linux, ARM64 and product package matrix: not applicable (no product change).
- Stock post-permit administrative disposition remains the existing stock controller path.
- Operator pre-launch comparison of the interpreter directory with the official
  zip (system PowerShell) and the `treeSHA256` computation: documented in SPEC.md,
  not exercised. The in-process tree check does not replace it.
- Official python.org embeddable interpreter extracted under a strict-ACL
  admission root, and native pinning of its loaded DLL/.pyd files while running
  (sharing compatibility with the loader): not exercised on the real host.
- "No other changes in the checkout" is no longer proven: `git status` is not run;
  only the twenty Core file hashes, HEAD, branch and worktree metadata are checked.
- Only a linked worktree (`.git` file) is supported; a plain `.git` directory refuses.
- Interface change: `collect.py`/`supervise.py` need `--ssh`, `finish-preparation.py`
  needs the ssh path as its second argument, `freeze-final.py` needs the git path,
  `stock-control.ps1` needs `-PythonPath`. The live stock and guest paths with the
  new absolute images were not exercised.
- `test_preparation_early.py` and `test_rejected_launch.py` are hermetic (outside
  `check_offline.py`): every `Adapter._ps` helper and local runner is replaced, the
  preparation harness routes absolute `rasdial`/`netsh`/`icacls` images to mocks and
  refuses any other absolute native image, and guest service/port facts are fixtures.
  The preparation harness still takes the shared `Local\BimeronStep10-<LAB_VM_ID_PREFIX>-session-start`
  mutex for at most 3 seconds.

## Resident seal-no-launch regression

- Live: resident operation `seal-no-launch` returned `Failed` with no output and
  never reached the guest mailbox. Cause: the resident runspace dot-sources
  `resident-guest.ps1` (`Set-StrictMode -Version Latest`), and
  `Get-OwnerTransitiveProofs` enumerated `$Value.PSObject.Properties.Name` on the
  empty `{}` body, which throws under strict mode before any `Invoke-Command`.
  The standalone `protected-guest.ps1` in the sealed source runs without strict
  mode, so the defect exists only on the resident path.
- Fixed strict-mode-safe property enumeration in `owner-mailbox.ps1` (transitive
  proofs, exit-supervisor body) and `Complete-OwnerFinal` (`ownerExit`/`noLaunch`).
- `fresh-resident-response-v1` now carries `error`: `null` when `Collected`; for
  `Failed`, the innermost exception type/message with `script:line`, control
  characters removed, at most 512 characters. The host Hold includes it.
- `collect-original`/`advance` `observation: unresolved` results carry `reason`
  (bounded, control characters removed) in addition to the exception type.

## Resident strict-mode audit

- `test-resident-strict.ps1` (PS5.1 and PS7, inside `check_offline.py`): 45 cases drive
  every resident operation through the real `Submit-ResidentRequest`,
  `Start-ResidentInvocation` (worker runspace dot-sources the real
  `protected-guest.ps1` and `resident-guest.ps1` under `Set-StrictMode -Version Latest`),
  `Collect-ResidentOriginal`, `Get-ResidentResponse`, `Close-ResidentOriginal`, and the
  real `resident-main.ps1` loop (ready, close, finish). Only `Invoke-Command`,
  `New-PSSession`, `Remove-PSSession` and `Import-Clixml` are replaced inside the worker
  runspace. Covered: session admission with retained policy capture, principal,
  restore-session-policy, guest/services/absence, clock/ready/integration, challenge,
  transition, preflight, sample, seal-no-launch (submit and fetch), cleanup with
  transitive proofs, exit-supervisor (Submit-OwnerCommand + Complete-OwnerFinal);
  `$null`, empty, many-item, single-element-array and missing-field outputs.
  Open-OwnerSession still takes the shared local session-start mutex for at most 3 s.
- Fixes found by the audit:
  - `resident-main.ps1` threw `Resident output shape` on every loop iteration for an
    unexpected `Collected` output and never published a response. New
    `Get-ResidentResponse` turns it into a terminal `Failed` response with
    `error='Resident output shape: N item(s)'`; PSObject wrappers are unwrapped without
    pipeline enumeration (PowerShell 7).
  - `Complete-OwnerFinal` output is discarded on the resident exit-supervisor path.
  - `Read-AdministrativeGuest`: `services` refuses a missing/non-string status;
    `guest`/`absence` refuse an empty readback instead of publishing nothing.
  - `Install-OwnerTask` refuses a missing registration record before the Run intent.
  - `Fetch-OwnerResponse` refuses a missing bundle or reference record explicitly
    (previously a strict-mode PropertyNotFound) and checks each reference namespace.
- Not changed: `test-integration-helper.ps1` (outside `check_offline.py`) already fails
  with `Transitive wrapper schema mismatch` because its fixture lacks the wrapper
  `schema`; it predates this audit.

## Held run 4fb18829: branch-B disposition tool

`runtime/host/dispose-held-run.py` with the thin `runtime/host/dispose-held-run.ps1`.
For one operator use after review and user approval. Not executed live.

- B1: precondition (new PS Direct session) guest `transport/commands` and
  `responses` empty, owner task running its original instance, exactly the original
  supervisor PID from the evidence. Stages the exact held bytes (compared with the
  evidence manifest) into `<work>/owner-transport`, delivers seq 1 `seal-no-launch`
  (unchanged bytes) and then seq 2 `exit-supervisor` through
  `protected-guest.ps1 -Operation final`. Proves `SEALED_NO_LAUNCH`, `no-launch.json`,
  `supervisor-exit-ready.json`, `task-final.json`, then a fresh readback: no run
  process, no task, RAS `No connections`, services equal to baseline, UDP 500/4500 free,
  persistent execution policies `Undefined`.
- Before B1 and B2: the held private root `guest-control/resident-(request|reserved|response)-*`
  names and digests must equal the evidence manifest (owner quiescent); otherwise STOPPED.
- B2: removes exactly `C:/BimeronFull300/<nonce>` and `C:/BimeronStep10Probe/<nonce>`
  (reparse points refuse, also on the two parents and all their ancestors) and reads
  back absence.
- B3: `sink_contract.retirement_commands`: confirmation, capture stop if pending (then a
  bounded read-only `health.json` poll, 30 x 1 s, until `ExitCode` is set; it must be 0,
  timeout stops with every poll journaled),
  archive fetch (`capture_archive`), sink stop, ExecStopPost receipt, unit absent,
  nft/ethtool/ip equal to the bound baseline. ssh argv is the recorded
  `-F none` argv with the absolute image.
- B4: checks all four identities (PID, creation FILETIME exact where the journal has it,
  otherwise microseconds from the process tree, image path, parent) before any effect,
  then terminates 55576, 63848, 64808, 62144 in that order, rechecking each on the
  same handle before `TerminateProcess`. Then a read-only process scan finds processes whose
  command line contains the nonce or the admission root (this tool, its launcher chain and
  its helpers excluded). Each one is terminated in B4 only when it is a descendant of the
  terminated tree proven by parent PID and a creation FILETIME later than its parent's;
  any other leftover is journaled and B4 stops. A leftover that exits by itself between
  the scan and verification or termination is journaled as `leftover-gone-<pid>` and is not
  a stop. A rescan proves the terminated ones gone by PID plus creation time (compared at
  the CIM microsecond precision), so a reused PID does not count as remaining.
- Each step runs once, needs the previous step proven, takes host network/VPN snapshots
  before and after, journals the step proof (`<step>-performed`) before the after
  snapshot, and stops on any difference in SID, adapters (including the WireGuard tunnel
  state), routes or VPN lists. DNS servers and adapter link speeds are journaled but not
  compared (router-provided IPv6 DNS and link speed change by themselves). On failure it writes `final-record.json`
  with `status=STOPPED`. Success after B4 writes `status=DISPOSED`. Both carry
  `label="administratively disposed, not SETTLED"`, `settled=false`, `normalCleanup=false`.
- Dry run (evidence copy only, no writes):
  `python -I -B runtime/host/dispose-held-run.py dry-run --evidence <LAB_PRIVATE_ROOT>\evidence-4fb18829`
- `--work` is validated before B1 and before every later step: absolute, every ancestor
  present and not a reparse point, no write-type allow ACE for broad principals on the
  parent (and on the directory and no reparse point inside it for B2..B4). The ACL is read
  with Windows PowerShell `Get-Acl`; the path is passed through the `BIMERON_ACL_PATH`
  environment variable because PowerShell 5.1 folds arguments after `-Command` into the
  command text.
- Real (one step per call, B1..B4):
  `python -I -B runtime/host/dispose-held-run.py run --step B1 --evidence <evidence> --private-root <held capture-prep-<nonce> root> --work <new absolute dir> --approve-nonce <nonce>`
- Tests: `runtime/host/test_dispose_held_run.py` (43, inside `check_offline.py`, also `-O`).
- Not verified live: PS Direct readback/removal scripts, delivery through the real old
  guest supervisor, ssh retirement on the observer, native process termination.

Verification: `check_offline.py` run `validation/run-6f3d0413154048aead42ee007afa374b`
(passed: test_admin_recovery 58, test_admin_handoff 5, test_rpc_regression 16,
test_dispose_held_run 43, each also under `-O`; resident and resident-strict on PS5.1 and
PS7; parser over 66 PowerShell files; sealed snapshots before and after) and
`HERMETIC.json` in the same run (test_rejected_launch 8, test_preparation_early 5).

## Windows PowerShell 5.1 child environment

- Live: when the Python harness was started from PowerShell 7, every Windows PowerShell 5.1
  child inherited the PowerShell 7 `PSModulePath`, autoloaded the PowerShell 7
  `Microsoft.PowerShell.Security`/`Management` modules and failed
  (`Get-Acl`: `CouldNotAutoloadMatchingModule`). The workaround was launching from PowerShell 5.1.
- Fix: `runtime/driver/windows_powershell.py` is the single helper. `environment(image)`
  accepts only `%WINDIR%\System32\WindowsPowerShell\v1.0\powershell.exe` (no reparse points,
  core module manifests present and not the PowerShell 7 ones), removes every inherited
  `PSModulePath` (any case) and `POWERSHELL_DISTRIBUTION_CHANNEL`, and sets `PSModulePath` to
  exactly `%WINDIR%\System32\WindowsPowerShell\v1.0\Modules;%ProgramFiles%\WindowsPowerShell\Modules`.
  The per-user `Documents\WindowsPowerShell\Modules` root is deliberately excluded
  (user-writable, account-dependent). `PSExecutionPolicyPreference` is retained.
  `pwsh_environment()` (only `check_offline.py` and `test-expected-entry.py --ps7`) drops the
  inherited `PSModulePath` so PowerShell 7 uses its own default.
- `stock_controller._stock_child_environment` now delegates to the helper (same `Hold` messages).
- Call sites now using it: `barrier.py`, `collect.py`, `hash-context.py`, `supervise.py` (guest
  query), `readiness_diagnostics.owned_query`, `protected_transport` (`PSDirectRPC` and
  `Adapter._ps`), `cancellation.Transport` (now for every reader, not only administrative ones),
  `host/dispose-held-run.py` (`_powershell`, `read_sddl`), `check_offline.py`, the test drivers
  `test-file-sha256.py`/`test-expected-entry.py` and the tests that start a real `powershell.exe`.
  `resident_rpc`, `stock_controller` and `admin_processes` already used it.
- Tests: `runtime/driver/test_windows_powershell.py` (8, inside `check_offline.py`, also `-O`):
  a real `powershell.exe` with a polluted parent `PSModulePath` (fake
  `Microsoft.PowerShell.Security` plus the PowerShell 7 module root) reproduces the live failure
  without the helper and resolves `Get-Acl` from `$PSHOME` with it; a static AST inventory
  requires every PowerShell spawn in `runtime/*/*.py` and `check_offline.py` to pass `env=`
  derived from the helper, and every generic spawner to pass `env=`.

## check_offline.py without sealed snapshots

- When both `../source` and `../supplement-01` are absent (for example a Git checkout), seal
  verification and `test_rpc_regression.py` (needs the sealed source) are skipped, listed in
  `RESULT.json` `skipped`, and the run is recorded as `status: "partial"`, `passed: false`
  (exit code 0 when all executed checks pass). Exactly one snapshot present is an error.
  With both present the behaviour is unchanged (`status: "passed"`).

Verification: `check_offline.py` run `validation/run-e315fb39f2f44cfba6dc4c9ad2a74581`
(status passed: test_admin_recovery 58, test_admin_handoff 5, test_windows_powershell 8,
test_rpc_regression 16, test_dispose_held_run 43, each also under `-O`; resident and
resident-strict on PS5.1 and PS7; parser over 66 PowerShell files; sealed snapshots before and
after) and `HERMETIC.json` in the same run (test_rejected_launch 8, test_preparation_early 5).
Partial mode was smoke-tested once on a temporary copy without the snapshots (status partial).

## MAX_PATH publication failure (live run 9de2f235)

- Live: the failed-run watcher ACK `administrative-watcher-closed.json` was published through
  `watcher_release.publish` with the temporary `<name>.<32 hex>.pending`. In the 184-character
  private root (`...\runtime\driver\capture-prep-<64 hex>`) that temporary is exactly 260
  characters; with `LongPathsEnabled=0` every tick failed with `FileNotFoundError`.
  `watch-prep.py` kept only the first sticky failure (`failure = failure or ...`), so the
  repeated refusal was invisible and the owner waited for the watcher exit indefinitely.
- Publication temporaries are now a fixed short same-directory name `.<8 hex>.tmp`
  (13 characters, independent of the target name): `watcher_release.publish` (via
  `admin_recovery.short_temporary`), `cancellation.publish_once`, `binding.publish_once` and the
  guest-side `persistent-reader.ps1` evidence publication. `owner-mailbox.ps1` already used a
  target-independent name and is unchanged.
- Write-time guard: `admin_recovery.require_path` (Journal.write, watcher publication),
  `protected_transport.freeze`, `transport.retain` and `cancellation.publish_once` refuse any
  full path over 259 characters with a named `MAX_PATH budget` reason instead of an opaque
  `FileNotFoundError`. Long-path support is never relied on.
- Admission-time budget: `admin_entry.run` computes `admin_recovery.run_path_budget(root)` over
  `RUN_PATH_INVENTORY` (deepest fixed templates at their widest counters, a 64-character
  reserve for dynamic guest archive, integration and settlement proof basenames, and a
  publication temporary beside every entry) and refuses before the private root exists when the
  longest path exceeds 259 characters.
- The private root is now `cp-<first 16 hex of the nonce>` (was `capture-prep-<64 hex>`). The full
  nonce stays bound in `owner-created.json` and in the new `run-identity.json`
  (`fresh-admin-run-identity-v1`: nonce, rootName). The held run 4fb18829 and its disposition
  tool keep the old `capture-prep-<nonce>` name; the legacy `live_prepare.py` path is unchanged.
- Current admission root `<LAB_PRIVATE_ROOT>\admission-774d219d9bad42bc94732eb8097b7cd4\verified-package\runtime\driver\`
  (106 characters): private root 126, longest run path 214
  (`preparation/guest/logs/<64-character reserve>`); the longest fixed template
  `owner-transport/rpc-evidence/999999-submit/transport-999-rpc.observer-exit.json` is 206.
  The old root name would give 272 and is refused by the same check.
- `watch-prep.py`: every loop refusal/exception (config, cleanup once the release request exists,
  query, query staleness, release ACK, administrative tick, heartbeat, stop) is written to
  `independent-tick-errors.jsonl` via `watcher_query.TickJournal`: consecutive identical
  refusals are folded into `repeatsOfPrevious`, at most 256 records (`limitReached` on the last),
  journal write failures are counted and never mask the refusal. The heartbeat carries `tick` and
  `tickRefusals`. A heartbeat write failure is now a recorded sticky failure instead of
  terminating the independent watcher.
- `watcher_query.Query.unresolved()` resolves deterministically from the retained original Popen:
  no child (failure before spawn, or transport construction failure) is a known no-dispatch;
  a child whose handle/identity read failed stays owned while that Popen reports running and
  resolves as `terminal-unauthenticated` once it exits (no PID reopen, no signal, no output read,
  recorded as a supervision failure, transport closed for observer-exit evidence). The next call
  releases the slot with a named Hold; a later call submits a fresh query.
- Tests (in `test_admin_recovery.py`, `PathBudgetTests`, 7): a 184-character root where the old
  temporary is exactly 260 characters fails to open (asserted when `LongPathsEnabled=0`, as on
  this host) while the new publication, `cancellation.publish_once` and `binding.publish_once`
  succeed with no leftovers; temporary length independence; named over-budget refusals in every
  guarded writer; admission refusal for the old live root, acceptance and exact budget (126/214)
  for the new one, and source order in `admin_entry.run`; bounded tick journal folding/limit and
  write-failure counting; an AST check that every exception handler and sticky-failure
  assignment in the `watch-prep.py` loop journals; `unresolved()` for no-child, identity-failed
  (surviving, then terminal) and transport-construction failure.

Verification: `check_offline.py` run `validation/run-b0b268f2059d4b7b9a32f1904470c9fb`
(status passed: test_admin_recovery 65, test_admin_handoff 5, test_windows_powershell 8,
test_rpc_regression 16, test_dispose_held_run 43, each also under `-O`; resident and
resident-strict on PS5.1 and PS7; parser over 66 PowerShell files; sealed snapshots before and
after) and `HERMETIC.json` in the same run (test_rejected_launch 8, test_preparation_early 5).
Not verified live: the watcher/owner path on the real host after this change.

## Generic held-run disposition (dispose-held-run.py/.ps1)

- The tool is no longer bound to run 4fb18829. The plan comes from the evidence copy (every file
  bound to `MANIFEST.json`): nonce (`run`), private root (the watcher's `--config` directory, either
  `capture-prep-<nonce>` or `cp-<16 hex>`), owner configuration/task instance, observer query,
  capture identity and baseline.
- Processes: the journaled owner (`journalOwner`) plus its direct children except `conhost.exe`;
  each must carry exactly one role marker (`pinned_watcher.py` watcher, `resident-main.ps1`
  resident, `prepare-task.ps1` task helper, `preparation.py` owner), non-owners must name the nonce
  (or `cp-<16 hex>`), the watcher must be `journalContainment`, and `owner-created.json`, when
  present, must name the same owner/watcher identities. Deeper descendants (for example the
  watcher's ssh) stay with the leftover scan. B4 terminates in role order
  watcher -> resident(s) -> task helper(s) -> owner.
- Step modes are derived from the evidence: `act` when no effect of the step is visible,
  `confirm` when all of it is, refusal when only part is (B1: commands 2, responses 1/2, both
  proofs and `task-final.json`; B3: health `ExitCode`, `cleanup-confirmed.json`, `sink-exit.json`).
  B1 confirm needs a clean guest in evidence (no run process, task absent); B2 confirm needs
  `dirsExist` False for both directories; B3 confirm also checks the evidence capture archive,
  unit absence and nft/ethtool/ip against the baseline.
- Confirm steps are read-only: B1 compares the private-root seal/exit exchange with the evidence
  and reads the guest state (no delivery, nothing staged); B2 reads the guest state; B3 reads
  cleanup-confirmed, health (ExitCode 0, no stop is sent), the archive, the sink receipt (equal to
  the evidence) and the unit listing, then compares nft/ethtool/ip. Journal events
  `<step>-confirmed`; `final-record.json` (`held-run-disposition-final-v2`) records the modes and
  `planSHA256`.
- Operator parameters: `run` needs `--approve-nonce` and `--approve-plan <planSHA256>` printed by
  `dry-run` (digest over nonce, evidence manifest, private root, modes, actions, removal targets,
  ordered process list, capture and ssh argv). `--private-root` must use one of the two names, equal
  the watcher root from the evidence and match `nonce.txt`/`run-identity.json` when present.
- `dispose-held-run.ps1` accepts any exact lowercase 64-hex nonce (ValidatePattern alone is
  case-insensitive) and refuses an absent `protected-guest.ps1` before any session.
- Dry runs (read-only, `validation/run-dbe23e6f33684b45aae5d20d1c99d578/dry-run-*.json`):
  - 9de2f235 (manifest `2260b7f3…`): B1 confirm, B2 act (remove both nonce directories),
    B3 confirm, B4 watcher 80044 (134383940282437166) -> owner 80928 (134383940249249215);
    planSHA256 `e800518e39cddf10aecb6032477929417082335d290da0d8c43153a528c3b1ca`.
  - 4fb18829 (manifest `cf08a961…`): unchanged behaviour, B1..B4 act, B4 watcher 55576 ->
    resident 63848 -> task helper 64808 -> owner 62144;
    planSHA256 `8abf20c2194049cfecbd5a460ba77ade24a3e4d8c9cebd4ff7e2db70450ba06b`.
- Tests: `runtime/host/test_dispose_held_run.py` 58 (was 43): the 4fb18829-shaped suite on the new
  API plus a 9de2f235-shaped fixture (plan modes and digest, full run with no delivery/stop/confirm
  command, B1 confirm refusals for a live supervisor or changed private response, B3 confirm
  refusals for a running capture or different receipt, B2 confirm, partial B1/B3 evidence
  refusals, baseline mismatch, generic role order with two residents/a task helper and an unknown
  child, owner-claim mismatch, both private-root names and binding, plan approval), and the real
  9de2f235 evidence dry run.
- Not verified live: confirm steps against the real guest/observer, termination of 80044/80928.

Verification: `check_offline.py` run `validation/run-dbe23e6f33684b45aae5d20d1c99d578`
(status passed: test_admin_recovery 65, test_admin_handoff 5, test_windows_powershell 8,
test_rpc_regression 16, test_dispose_held_run 58, each also under `-O`; resident and
resident-strict on PS5.1 and PS7; parser over 66 PowerShell files; sealed snapshots before and
after) and `HERMETIC.json` in the same run (test_rejected_launch 8, test_preparation_early 5,
both dry runs). A previous run in this change failed on a stale test name in
`test_windows_powershell.py` (fixed) and once on PS5.1 resident-strict (`resident-closed.json` in
use by another process, a test-side file race in an unchanged script); that run directory was
discarded.

## Private-root name in preparation scripts (live run f8956ea0)

- Live: after the rename to `cp-<16 hex>`, `prepare-task.ps1` still required
  `ControlPath == $PSScriptRoot/capture-prep-<nonce>` and exited 1 before publishing any
  outcome; `guest-read.ps1 -Mode stop` read the host request from
  `capture-prep-<nonce>/stop-request.json` ("Host stop request missing"), so the controller
  returned HOLD "stop delivery unproven at 10s". Private root `cp-f8956ea0a5906183`.
- Recovery assessment for that live owner (package 7d505057, read-only): `advance` cannot reach
  phase1. `Handoff._prepare_restore` stops the in-process monitor thread, runs
  `collect_original` (observation only), then reads `preparation-outcome.json`
  (`admin_handoff.py:158`), which does not exist (prepare-task never got past line 7). Even with
  it, `no_launch`/`closure_proven` (`admin_handoff.py:159-163`) and `restored is True`
  (`admin_handoff.py:180`) cannot hold: the task helper is dead and never restores. The
  exception is caught by `Owner.request` (`admin_recovery.py:402` in 7d505057) and answered as `observation: unresolved`; the state
  stays FAILED. No restore permit, remote retirement, watcher request or phase proof is written,
  so the failure is safe and repeatable but never reaches settlement. Retirement, watcher ACK
  and phase2 use `owner.journal.root` and `/var/lib/step8/run-<nonce>` only; the resident
  guest-read modes (clock/ready/integration) take no host root. The live owner needs the
  held-run disposition tool.
- Fix: the private root is passed explicitly and checked against its own `run-identity.json`
  (`fresh-admin-run-identity-v1`: nonce, rootName); no runtime code derives a root name.
  - `cancellation.ps1`: `Resolve-ProbeControlRoot` (root must sit beside the driver, exist,
    and its run identity must bind the nonce and the directory name).
  - `prepare-task.ps1`: uses the resolver instead of the fixed template.
  - `guest-read.ps1`: new `-ControlPath`; `restore-permit`, `stop` and `persistent` resolve it.
  - `preparation_body.py`: every controller `guest-read.ps1` launch passes `-ControlPath <root>`.
  - `live_prepare.prepare_live`: `out` is required (no default name).
  - `host/stock-control.ps1`: the evidence parent must carry a matching `run-identity.json`.
  - `finish-preparation.py`: `admin_recovery.bound_private_root(driver/private_root_name(n), n)`.
  - The old name stays only in `host/dispose-held-run.py` (legacy evidence).
- Tests: `test_admin_recovery.py` `PrivateRootNameTests` (4): a static scan that no non-test
  runtime `.py`/`.ps1` contains `capture-prep-` outside the allowlist; controller argv carries
  `-ControlPath`; `bound_private_root` binding and the `live_prepare` refusal; and a hermetic
  Windows PowerShell harness `test-private-root.ps1` (session cmdlets stubbed) that runs
  `guest-read.ps1` restore-permit/stop/persistent and `prepare-task.ps1` against a `cp-<16 hex>`
  root, plus refusals for a missing root, the legacy name, a wrong binding/nonce and a root
  outside the driver. `test_preparation_early.py` now uses a `cp-<16 hex>` root with
  `run-identity.json`.

Verification: `check_offline.py` run `validation/run-4aadb57ce9994c80811b6991877545ef`
(status passed: test_admin_recovery 69, test_admin_handoff 5, test_windows_powershell 8,
test_rpc_regression 16, test_dispose_held_run 58, each also under `-O`; resident and
resident-strict on PS5.1 and PS7; parser over 67 PowerShell files; sealed snapshots before and
after) and `HERMETIC.json` in the same run (test_rejected_launch 8, test_preparation_early 5;
dry runs not repeated, the disposition tool is unchanged). An earlier run in this change failed
only on the PowerShell call-site inventory (new test spawn not yet registered); that run
directory was discarded. Not verified live.

## Held-run disposition for run f8956ea0 (transient monitor query, unreserved seal)

- Dry run against `evidence-f8956ea0` (manifest `ca2b6096…`) refused with "Process role unknown
  or ambiguous: 18356": the process tree held a transient `ssh.exe` child of the owner 66184 (the
  owner's per-second capture status query, `preparation_body.monitor`), image and command line
  unreadable when the tree was collected.
- Transient monitor query: an unmarked owner child is accepted only if its name is `ssh.exe`, its
  tree image is absent or the configured absolute `ssh.exe`, its tree command line is absent or
  exactly the `host-supervisor-config.json` query argv, it is not older than the owner, the
  evidence holds at least one owner `transport-NNNNNN.json` record with exactly that argv bound to
  the journaled owner, and there is at most one. It is not in the B4 kill list; the plan lists it
  (`transientMonitorQueries`, with image/argv basis) and, if still alive after the owner, the
  leftover scan terminates it as a verified descendant. Any other unmarked child still refuses.
- B1 unreserved-seal variant (`b1Variant`): chosen only when the host `owner-transport` has no
  `commands/`, `responses/`, `receipts/` and only `proofs/supervisor-once.json`, no resident
  request or reservation names a seal (otherwise "Reserved/unreserved seal ambiguity"), the guest
  mailbox is empty in files and listing, the guest config and `supervisor-once.json` equal the
  host copies, the proof names the single running supervisor (pid) and the one running owner task,
  and the resident preflight output equals that proof. Seq 1 is built by
  `protected_transport.MailboxClient.command('seal-no-launch', {})` (the owner's own path, over the
  staged `config.json`); dry run predicts the bytes in a temporary directory and the plan digest
  covers `b1Variant` and `unreservedSeal` (seal SHA-256, config SHA-256, supervisor-once SHA-256,
  supervisor pid, builder). At run time the host mailbox listing must still be empty, the guest
  precondition is the same as the reserved variant, the seal bytes must equal the approved bytes
  before delivery (journal `command-1` holds bytes and digest), seq 2 `exit-supervisor` is built
  by the same client, both are delivered with `protected-guest.ps1 -Operation final -Mode submit`
  (Submit-OwnerCommand, then Complete-OwnerFinal for seq 2), and proofs, `task-final.json` and the
  fresh guest readback are checked as in the reserved variant.
- Identity of listed processes (`identityBasis` in the dry-run report, outside the digest; the
  digest covers the process list itself): owner and watcher by journaled FILETIME; a resident or
  task helper without a journal FILETIME by PID, creation time in microseconds, image and parent
  from the process tree, verified live on the termination handle.
- Plans of runs without a transient query or unreserved seal are unchanged (the new keys are
  added only when used).
- Dry runs (read-only, `validation/run-a92ec99e2a4f4275939461403ddcda4d/dry-run-*.json`):
  - f8956ea0: B1 act (unreserved-seal, seal `3a85742b…`, supervisor 3672), B2 act, B3 act,
    B4 watcher 44692 -> resident 11128 -> owner 66184, transient monitor query 18356;
    planSHA256 `a0576d9e89ae71af42eaa2c3c41a48e76d5ad3a8f3ca5412e94088b43409aa7b`.
  - 9de2f235: unchanged, planSHA256 `e800518e39cddf10aecb6032477929417082335d290da0d8c43153a528c3b1ca`.
  - 4fb18829: unchanged, planSHA256 `8abf20c2194049cfecbd5a460ba77ade24a3e4d8c9cebd4ff7e2db70450ba06b`.
- Tests: `test_dispose_held_run.py` 68 (was 58): f8956ea0-shaped dry-run plan and digest, full
  run delivering the owner-built seal with the transient query terminated by the leftover scan,
  unknown child and non-monitor ssh refusals, missing owner monitor record, reserved/unreserved
  ambiguity, non-empty guest commands (evidence files, listing, live readback), live reserved host
  command, supervisor-once mismatch, seal bytes differing from the plan, and the real f8956ea0
  evidence dry run.
- Not verified live: B1..B4 against the real guest, observer and host processes.

Verification: `check_offline.py` run `validation/run-a92ec99e2a4f4275939461403ddcda4d`
(status passed: test_admin_recovery 69, test_admin_handoff 5, test_windows_powershell 8,
test_rpc_regression 16, test_dispose_held_run 68, each also under `-O`; resident and
resident-strict on PS5.1 and PS7; parser over 67 PowerShell files; sealed snapshots before and
after) and `HERMETIC.json` in the same run (test_rejected_launch 8, test_preparation_early 5,
three dry runs).

## Atomic guest-control publications (live run 7a85aad9)

- Live failure (setup): `failure.json` "JSONDecodeError: Expecting value: line 1 column 1
  (char 0)". `resident-main.ps1` created `resident-ready.json` with `CreateNew` and then wrote
  the bytes; `ResidentRPC._wait` returned the still-empty file and `decode` failed. The same
  pattern applied to `resident-closed.json`, `resident-finished.json`, resident responses and
  reservations, and in the other direction to `ResidentRPC._publish` (requests, close/finish
  requests, fixed contexts) and `Journal.write` (polled by the independent watcher:
  `containment-abort.json`, `administrative-watcher-request.json`).
- Writers: `Publish-ResidentBytesOnce` (`resident-guest.ps1`, used by `Write-ResidentBytes` in
  `resident-main.ps1`) writes `.<8 hex>.tmp` in the same directory, flushes to disk, then
  `File.Move` without overwrite. `admin_recovery.publish_exclusive` writes a
  `short_temporary`, fsyncs, then `os.link` (never replaces); it backs `Journal.write` and
  `ResidentRPC._publish`. Identical existing bytes are idempotent; different bytes are refused
  ("Resident publication conflict" / "Journal collision"); the temporary is always removed.
  Temporary names stay 13 characters (MAX_PATH budget unchanged). Already atomic and unchanged:
  `watcher_release.publish`, `Publish-OwnerBytesOnce`, `Publish-PreparationOutcome`,
  `binding.publish_once`, `cancellation.publish_once`.
- Readers: `ResidentRPC._wait` treats absent, zero-length, unreadable or undecodable files as
  "not yet" until the deadline. A complete document is returned and its binding is validated by
  the caller (a mismatch still fails). A file still undecodable at the deadline fails
  ("Resident publication malformed at deadline"); an exited resident with only a partial file
  fails ("exited with malformed publication"); absent until deadline stays the existing HOLD.
  `resident-main.ps1` reads requests, close and finish requests through `Read-ResidentPublished`
  (absent or zero-length is "not yet").
- `dispose-held-run.py` (r8 minor items): B1 unreserved live host mailbox check now includes
  `owner-transport/receipts`; a transient ssh query is tied to the owner's journaled queries by
  creation time (the exact journaled identity in `original-transport-NNNNNN/…identity.json`, or
  newer than every journaled query identity and at most 60 s before the process-tree `utc`;
  reported as `createdBasis`); B4 journals `B4-transient-ssh-<pid>` (live or not, no effect)
  before termination.
- Tests: `test_admin_recovery` 74 (was 69): old-writer race (empty file, bytes after 0.3 s: the
  old immediate read fails to decode, the new reader returns the complete bytes), complete
  file failing binding, partial at deadline, empty timeout, exit with partial,
  `publish_exclusive` idempotent/conflict/race/short temporary, Journal and resident
  publications. `test_dispose_held_run` 70 (was 68): creation window (missing tree time, after
  tree, too old, older than a journaled identity, exact identity), live host receipt refused,
  B4 note asserted in the full run. `test-resident-strict.ps1` 55 cases on PS5.1 and PS7
  (atomic writer, idempotent, conflict, existing final, bad name, no temporary left, reader
  absent/empty/complete, and the real resident-main loop ignoring an empty close request).
- Dry runs (`validation/run-712c43f134d2417ab064038f47bc241b/dry-run-*.json`):
  - 4fb18829: unchanged, planSHA256 `8abf20c2194049cfecbd5a460ba77ade24a3e4d8c9cebd4ff7e2db70450ba06b`.
  - 9de2f235: unchanged, planSHA256 `e800518e39cddf10aecb6032477929417082335d290da0d8c43153a528c3b1ca`.
  - f8956ea0: planSHA256 `4cdf2592b52db039ab664dd98ab707cd022b9dcffd5f71559079926f47d76ea5`
    (was `a0576d9e…`); the only report difference is the new
    `transientMonitorQueries[0].createdBasis`, which the plan digest covers.
- Not verified live: the resident publications against the real guest-control root.

Verification: `check_offline.py` run `validation/run-712c43f134d2417ab064038f47bc241b`
(status passed: test_admin_recovery 74, test_admin_handoff 5, test_windows_powershell 8,
test_rpc_regression 16, test_dispose_held_run 70, each also under `-O`; resident and
resident-strict on PS5.1 and PS7; parser over 67 PowerShell files; sealed snapshots before and
after) and `HERMETIC.json` in the same run (test_rejected_launch 8, test_preparation_early 5,
three dry runs).
