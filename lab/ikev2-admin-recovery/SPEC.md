# Fresh-run administrative recovery, bounded offline candidate

2026-11-05. This specification precedes implementation. No deployment or operational
admission is granted. Historical U8 remains restored, failed before stock entry,
with zero stock attempts. Source anchor: 3434a394284e919ece57a6217b3affbb7ee97d9989545a6888ed1eb9c6b43991.
Supplement anchor: 514500493d4b5a244ed3b13b11af0b889b4d004bfb17bbb93fd0d2046a9a8e08.
Both manifests and every copied entry were independently verified before use.

## Scope and source findings

Keep the reviewed launcher and stock disposition. Do not add manual launch,
credentials, VM lifecycle, shared-process termination, or normal-success claims.
The implementation is a fresh-run protocol and integration delta in this directory;
it is not a reconstruction of transient historical phase2 commands. All effect
boundaries in tests are inert. Existing operational sources are never executed.

The required additions are explicit: atomic private host directory admission;
source/module bootstrap admission; original-owner failure retention; a reserved
administrative request ledger; pure fresh-run phase1/phase2 validation; cooperative
failed-watcher disposition. Existing normal settlement cannot validate a failed
lifecycle, and no complete administrative validator/private-directory primitive
exists in the supplied source. Merely removing its failure check is forbidden.

## Authority and state

The original preparation owner creates a fresh nonce and private run directory
before setup effects. Admission binds exact candidate manifest, run configuration,
baseline bytes, original coordinator identity and separately retained containment
owner identity. A nonce or a hash alone does not authenticate a caller. The endpoint
is private local storage accessible only to the original user, SYSTEM and BA.
Bootstrap runs from an explicitly reviewed immutable path; it validates exact
source bytes before imports and rejects mismatched preloaded modules. No arbitrary
sys.path prepend or environment-wide PSModulePath mutation is permitted.

Directory creation uses CREATE_NEW-equivalent CreateDirectoryW with an explicit
protected DACL in SECURITY_ATTRIBUTES. No create-then-SetAcl window or existing-root
adoption. Retain source file pins without write/delete sharing. Directory pins hold
only attribute/READ_CONTROL access and therefore impose no sharing: a pinned
directory can still be renamed and its name rebound. Revalidation re-opens every
pinned path by name and compares its file ID. Validate owners,
ACE masks, inheritance and reparse metadata; reject aliases and untrusted ancestor
mutation. Trusted administrator compromise is outside this local ACL boundary.
Native implementation is inspected and syntax-checked only in this task; native admission
must be demonstrated separately by the sole operator before any operational use.

The state sequence is SETUP -> RUNNING -> FAILED -> PHASE1 -> PHASE2 -> SETTLED.
Normal preparation may finish normally through its existing distinct path. Any
setup/body/finalizer exception or Stage ABORTED/HOLD sets sticky failure and routes
to the same retained owner, preserving Stage, Adapter, MailboxClient, RPC children,
request bytes and original session/job objects. No finalizer is replayed. A timeout
only ends an observation slice; it never closes handles or acknowledges settlement.
The owner serves bounded explicit requests, rather than sleeping without a usable
completion path. Loss of that owner is an external ownership-loss condition, not
an opportunity for a new owner to adopt old receipts.

Administrative requests bind all admission digests, original owner, exact next
sequence and immutable body. Reserve and flush/read back the request BEFORE calling
any effect/continuation. Duplicate identical requests return the original cached
result; reserved-but-uncertain requests report uncertainty without re-entry.
Conflicting sequence/body and new mutations after failure refuse. Read-only late
collection targets the original owned operation. It never repeats submission.
RPC fetch of preflight or exit-supervisor refuses before disposal or spawn because
the existing final helper can delete a task. Successful collection does not clear
sticky failure, restore anything, release capture, or close an original session.

## Evidence and finite administrative completion

All validators are pure: receive immutable bytes and trusted admission context,
perform no file, process, network or session operations. Exact key sets, strict
JSON types, duplicate rejection and bounded references are mandatory. Every proof
binds the fresh nonce/configuration/admission and monotonically ordered owner
observations; old phase1 command numbers 28/29/30 are not constants in the protocol.

Phase1 requires actual original drain and independent absence through the existing
raw validators, exact original waiter termination and restoration readback,
wrapper/policy/task baseline restoration, positive closure of every registered
session/operation, and all eight current baseline comparisons (nft, two feature
sets, topology, services, guest, absence, Git exact twenty files). Inventory is
reserved before setup so absence of a record cannot mean an effect did not occur.
Only explicitly never-submitted resources can be marked not applicable. Services
and NIC retain existing stock isolation/quiescence/restoration ordering; the new
protocol grants no alternative stop/kill or reconnect predicate.

Phase2 requires phase1 bytes plus the original capture identity, complete bounded
archive with successful actual capture exit, positive exact sink-unit retirement,
original watcher cooperative administrative acknowledgement and observed exit,
and no unresolved transport/session/monitor operations. A separate administrative
watcher request may be accepted after phase1 even when failure is sticky. It drains
its original outstanding query, records FAILED supervision, cooperatively exits only
after capture/archive/sink proof validation, and never writes normal release ACK.
The original owner validates and publishes final administrative settlement last.
normalCleanupSucceeded is always false; the original failure is retained verbatim
in private evidence. No exit code or timeout substitutes for these proofs.

## Acceptance criteria and integration order

1. Admission and request reservation reject altered modules, foreign owners/ACEs,
   junctions, stale nonce/config/owner and conflicting requests before any callback.
2. Actual changed preparation entry/failure boundary is tested at setup, body,
   Stage ABORTED, finalizer, publication and close failures. Identical original
   objects remain reachable; no automatic body/finalizer retry occurs.
3. Actual RPC code rejects dangerous fetch before close/spawn and passes the
   validated child-only environment to Transport.observe. Preserve 30/150 budgets.
4. Actual stock recovery request dispatcher reserves before controller advancement,
   handles publication failure, and cannot replay an uncertain sequence.
5. Pure phase validators reject every missing/stale/rebound proof and accept a
   complete fresh administrative restoration; failure remains a failed run.
6. Actual watcher transition accepts complete administrative disposition, drains
   outstanding work, and produces a positive finite distinct failed-run exit.
7. Run focused Python normal/optimized and PS5.1/7 inert tests, syntax/compilation,
   source preservation and diff checks. Product package matrix and performance
   profiling are inapplicable: no product or performance-sensitive change.

Each transition and any scope correction is reported to primary before proceeding.
The final integration delta must identify any unimplemented adapter or live evidence
gate honestly; offline passing tests alone cannot claim a runtime admission bundle.
One exact complete-byte HIGH review is arranged by primary. No child review chain,
commit, push, merge, release, runtime enablement or actual native/lab operation.

Late collection uses only the retained original child, handle and file paths. A
terminal child with authenticated original identity permits bounded output
collection; it does not prove remote/session closure. No original command is
submitted again. A failure to persist a request reservation before dispatch is a
known no-dispatch result, cached under that sequence; a new explicit sequence may
continue after storage is usable. Neither that failure nor an uncertain action
is silently retried.

Before setup, the original owner initializes an explicit attempt inventory for
guest control, preparation waiter, capture, sink and local monitor. Each flag is
set before its effect. A setup abort with all operational attempts still false
can return only a distinct `BOOTSTRAP_ABORTED_NEVER_SUBMITTED` result after positive
resident/idle-containment closure. It does not claim lab restoration or phase1/2.
If capture was attempted but ordinary preparation/native launch were never
admitted, fresh phase1 uses an explicit never-entered branch plus the same eight current readbacks and
session closure; it cannot fabricate an inspector/waiter receipt. A missing
capture identity after uncertain startup remains owned and unresolved, not an
excuse to signal a guessed process. Sink never-submitted is likewise validated
against the original in-memory flag, never absent service files.
If the original supervisor was admitted, this branch still requires its existing
validated no-launch seal, final task readback and independent absence proof.
It only omits the ordinary preparation waiter that was explicitly never submitted.

The source starts the sink with systemd-run --collect. Its Result property may
be unloaded after stop, so requiring a later Result=success property alone would
strand a correctly stopped fresh run. The fresh transient unit therefore records
a fixed, nonce-bound ExecStopPost receipt in the already-private capture root,
including systemd's SERVICE_RESULT/EXIT_CODE/EXIT_STATUS/INVOCATION_ID. No helper
is deployed: the reviewed literal is passed as the transient unit property.
The existing exact-unit systemctl stop remains the only retirement action;
SendSIGKILL=no forbids escalation by timeout. Phase2 requires that original
post-stop receipt AND a fresh exact-unit list read showing absence. The receipt
is not reconstructed from historical phase2 outcomes. Installed systemd support
and this exact command's property rendering remain mandatory live gates.
Primary contracts: https://www.freedesktop.org/software/systemd/man/253/systemd-run.html
and https://freedesktop.org/software/systemd/man/latest/systemd.service.html
and https://freedesktop.org/software/systemd/man/latest/systemd.exec.html.

## Source-derived correction before session implementation

The existing protected-guest entry unconditionally opens/removes a short-lived
session. Retaining its Python Popen cannot preserve the original session object.
Add a narrow resident guest owner to the same fresh preparation, before mailbox
effects. It keeps one PowerShell runspace and the original Session in shared owner
state; asynchronous invocation is reserved before BeginInvoke. Terminal collection
uses EndInvoke once, retains original output/errors and permits no submission retry.
Open-OwnerSession must expose a newly returned session to this state BEFORE identity
validation, and must not remove it in a failure catch. Explicit closure waits for
all original work, records actual Session.State Closed, and returns a bound receipt.
The resident host exits only through a separate original-owner finish handshake.
No generic PowerShell body is accepted from requests. This closes an additional
source-derived authority gap within the authorized limited new-run protocol.

The original helper sets Process execution policy to Bypass. A resident session
must not report that temporary value as baseline restoration. Capture its exact
original Process value in the same remote session before changing it, bound to
the fresh nonce. A fixed one-shot restoration operation restores only this value
after all supervisor helpers finish; subsequent guest/services/absence readback
uses literal ScriptBlocks through that same session. No persistent policy scope
is changed. Original closure follows those readbacks. This is a source-derived
correction to the retained-session integration, not a new credential/auth flow.

Publication-failure refinement: rejection by a pure evidence validator happens
before reservation and consumes no sequence. After an accepted action, its exact
response and any final settlement bytes are cached before publication. Repeating
that SAME request may finish only these immutable publications, never re-enter
the action. Failed original read-only collection remains inspectable; a new
explicit collect request may observe the same original objects again, with no
submission API. Mutation uncertainty still prohibits replay under another ID.

The new administrative phase1/phase2 receipt is specifically for fresh pre-stock
failure (the missing U8-shaped path), not a replacement for stock_controller's
existing post-permit administrative disposition. The original owner must retain
an explicit never-submitted stock permit/deployment record. Once stock deployment
or permit was attempted, this new receipt refuses; the existing retained stock
controller/launcher receipt path remains required. Missing files cannot establish
that exclusion. This avoids inventing a second stock retirement implementation.

## Fixed original-owner continuation

Containment admission is two-stage to avoid a circular owner binding: bootstrap
creates the private root and starts the same reviewed watcher in an idle mode,
before capture/guest effects. It retains the original Popen/ChildHandle and checks
an exact readiness receipt. The final Owner binding then includes that actual
identity. Preparation publishes its capture config to that same idle watcher,
rather than launching a replacement. A bootstrap failure before capture config
can only request the original idle watcher's explicit abort acknowledgement and
observe its original exit. After capture config publication the normal retained
Owner protocol is mandatory. The isolated child loader accepts only the pinned
watcher source closure; no arbitrary script target or sys.path injection.

The private endpoint also accepts `advance` with an empty proof body. It invokes
only the original owner's fixed Handoff object, not code or commands supplied by
the request. The continuation stops the local monitor observation loop (the
independent watcher/capture remain), collects retained work, and completes the
existing Stage drain/absence and original waiter's restore-permit path. Validated
drain/absence bytes are cached; accepted cleanup/exit commands are reused as
evidence and never submitted again. Restoration, readback, resident closure,
phase1 validation, capture/archive/sink retirement and cooperative watcher exit
remain separate ordered boundaries. The phase1 readbacks occur before closing
the original resident session; its positive closure is the last phase1 observation.

Each fixed remote continuation has its own in-memory original request identity.
After observation expiry, `advance` may collect that original request, not submit
it again. Pure rejection and observation expiry retain the owner. A positive path
must terminate with the distinct administrative settlement; unknown effects stay
owned and cannot be converted to success by another sequence or elapsed time.

Pre-controller observation refinement: retain the exact original preparation
argv and Popen before inspecting its handle. The resident owner also retains its
original Popen before identity inspection. An identity/publication failure may
retry observation of that same handle and the local immutable startup binding,
never Popen or PID reopening. Only an explicit controllerEntered=False record,
with no retained controller state, permits sealing an empty reader inventory.
The actual preparation outcome and existing early-drain validator are still
required before restore permission; missing files or a process exit prove nothing.

## Reliability corrections (offline review)

Request files are read once through a temporary validated handle and closed; no
request pin is retained. A request rejected before reservation is published
append-only as `rejected-N-<sha>.json`; that slot then accepts only
`admin-request-N-<sha>.json` bound to the rejected bytes. A failing serve slice
pauses before the next one.

The three retirement effects (cleanup confirmation, capture stop, sink stop) use
one effect-once ledger, `OriginalTransports.retire`, with fixed keys and the exact
argv/bytes from `sink_contract.retirement_commands`, for both the normal body and
the Handoff. An attempted key is never sent again; only readback decides. An
attempt flag without a fixed record, or changed bytes, refuses.

`HOLD` is a distinct terminal outcome (`administrative-hold.json`,
`ADMINISTRATIVE_HOLD`): no settlement, nothing closed or released. It is used
when a normal watcher release ACK already exists, and when the finalizer fails
after a completed normal body (the failed-run settlement is unreachable then).

All Handoff readbacks (nft, ethtool, ip, cat) are non-mutating numbered
fresh reads. A terminal failed read releases the transport slot. The resident
guest/services/absence readbacks may be observed again after a terminal Failed;
the policy restoration never repeats.

A failure before spawn/publication is a known `NotDispatched` result: the slot is
released and the fixed key may reserve again. The transport keeps the consumed
number; the resident rolls its sequence back because the host admits only the
next contiguous sequence. The stock dispatcher caches a `dispatched=false`
response and admits the next explicit ID. A resident start without a spawned
process has no session to close. The idle containment abort is bounded and ends
in a HOLD that retains the original child.

The failed-run watcher uses the original owner failure from its context, never
its own failure. The restoration duration comes from the original absence
readback. Reader closure binds pid and creation FILETIME.

### Review round 2 corrections

- The endpoint caches, per sequence, the accepted file name and bytes. A response
  publication retry republishes from that cache and never re-reads the slot
  (including a rejected original next to its `admin-request-N-<sha>.json`
  replacement); slot N+1 is served afterwards.
- The endpoint requires `request.sequence == N` for slot N before `Owner.request`;
  an older request copied into a later slot is rejected through `rejected-N-<sha>.json`.
  An unreadable slot file (bound, hardlink, reparse) is rejected inside the same
  path, bound to `sha256("unreadable:" + slot name)`.
- Once observation `eight` is recorded, a retry of `advance` after a later step
  failed (close, finish, closures, `administrative-phase1.json`) reuses that proof
  and does not re-read nft/ethtool/ip (raw bytes change naturally) or checkout metadata.
- `resolve_retirement` on a `NotDispatched` retirement key (nothing was sent)
  accepts the independent readback proof, records `dispatched=false` and marks the
  key `Resolved`; the effect is never sent afterwards.
- A bootstrap failure before preparation (containment start, or the round 3 `owner_stage`)
  writes `bootstrap-failure.json` with its stage. If the bounded idle abort ends
  in Hold, it also writes `administrative-hold.json`. After this no Owner serves
  requests: nothing can advance, settle or release this run; the
  original containment child is retained for manual handling.

### Review round 3 corrections

- Clients must publish each request atomically: write a temporary file in the
  private root, close it, then rename it to `admin-request-N[-<sha>].json`.
- A slot that is not readable yet is transient, never a rejection: `read_once`
  raises `Pending` (an `OSError`) for "Cannot open file" (a writer still holds the
  file) and "File changed during read" (the file is growing). Any other `OSError`
  from the native read (`GetFileInformationByHandle`, `ReadFile`, `CloseHandle`) is
  treated the same way. The endpoint retries on the next tick; a permanently
  unopenable slot is resolved by the client deleting and republishing it.
  Oversized, hardlink/reparse/type mismatch and invalid content are still rejected
  through `rejected-N-<sha>.json`. A `Pending` proof file is treated as unavailable.
- `owner_stage` covers everything from a started idle containment up to
  `run_preparation`: the bound record, `Owner()`, transports, process owner,
  handoff and endpoint wiring. Any failure there writes `bootstrap-failure.json`
  (stage `owner`, context `nonce` and `configSHA256`) and runs the bounded idle
  abort; `administrative-hold.json` is written only if that abort is unconfirmed,
  with `ownerExists` showing whether `Owner()` had already returned.

## Live admission corrections

- Ancestor (non-private) DACL check: ACEs with `INHERIT_ONLY_ACE` (0x08) do not
  apply to the ancestor itself and are skipped for the mask check (their ACE type
  is still checked; unsupported types refuse). `FILE_ADD_FILE` (0x2) and
  `FILE_ADD_SUBDIRECTORY` (0x4) are no longer ancestor mutation: creating new
  entries cannot rename, delete or replace an existing path component. The
  untrusted-principal mask is `0x500d0150` (WRITE_EA, DELETE_CHILD,
  WRITE_ATTRIBUTES, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_ALL, GENERIC_WRITE),
  so the stock `C:\` DACL is accepted. Private-root and owner checks are unchanged.
- The relaxed mask applies only to true ancestor directories. The pinned target
  itself (file or directory) and every code directory use the full mask
  `0x500d0156` (0x2/0x4 also forbidden): the interpreter directory, `driver`,
  `host` (declared by `admin_entry` through
  `WindowsAdmission.declare_code_directories` before the first pin; a code
  directory is never relaxed even when pinned as an ancestor) and the directory
  holding a system executable (`pin_system_executable`). `read_once` and
  `revalidate` use the same per-pin decision.
- Admission root and embeddable interpreter (configuration `admissionRoot` and
  `python` = exactly `path`, `sha256`, `treeSHA256`; the former top-level
  `pythonSHA256` is removed; the review record is `fresh-admin-review-v2`, whose
  `pythonSHA256` binds `python.sha256` and `pythonTreeSHA256` binds
  `python.treeSHA256`). The
  operator downloads the official python.org Windows embeddable zip for the
  running version, verifies its published hash, and extracts it inside the strict
  admission root; `driver`, `host` and `python.path` must lie under
  `admissionRoot`, otherwise admission refuses before any pin. The embeddable
  distribution uses `pythonXY._pth`, which makes the interpreter isolated with no
  `site` and fixed `sys.path`. `admin_entry.pinned_python` (called right after the
  review check, before further modules load) requires `sys.executable` to be
  exactly `python.path`, pins the interpreter directory and every entry in it with
  `pin_source` (strict, never tolerant), requires a flat tree (no `Lib`, no
  `site-packages`, no subdirectory), exactly one `pythonXY._pth` whose non-comment
  lines are only `pythonXY.zip` or `.`, `python.exe` hashing to
  `python.sha256`, and the whole directory hashing to `python.treeSHA256`. All
  entry hashes and the tree hash are journaled as `python-pins.json`
  (`fresh-admin-python-v2`). The whole extracted tree is under the strict ACL;
  the harness uses the standard library only (no third-party packages, no
  site-packages).
- `python.treeSHA256` definition: for every file in the interpreter directory
  (flat, so the relative name is the file name exactly as stored, case
  preserved), form the line `<name>` TAB `<sha256>` LF, where `<sha256>` is the
  lowercase hex SHA-256 of the file bytes, TAB is U+0009 and LF is U+000A (no
  CR). Sort the lines by name in ordinal (code point) order, concatenate them,
  encode as UTF-8 without BOM, and take the lowercase hex SHA-256 of the result.
  Every file counts, including `python.exe`, `pythonXY._pth` and `pythonXY.zip`
  (`admin_entry.python_tree_sha256`).
- venv redirection: `pinned_python` refuses when a `pyvenv.cfg` entry of any
  kind exists in the interpreter directory or its parent, and requires
  `sys._base_executable == sys.executable` and `sys.prefix` equal to the
  interpreter directory (case-insensitive path compare).
- No bare local executable names. Under elevation `CreateProcess` and the
  PowerShell call operator resolve a bare name through the current directory and
  `PATH`, both possibly writable by the sandbox, so every local child image in
  the runtime is an absolute local path (drive-rooted; relative, root-relative
  and UNC paths refuse):
  - ssh: every candidate ssh argv starts with `<ssh> -F none`. Admitted paths use
    the pinned `config['ssh']['path']` (`resources['sshExecutable']`). The
    preparation body publishes its exact argv prefix as `resources['ssh']` (and
    `resources['capture']`), which the Handoff reuses, so retirement fingerprints
    stay byte-equal. `live_prepare.ssh_command(command, ssh)` and
    `prepare_live(..., ssh=...)` require the path (`absolute_executable`);
    `protected_transport` passes `resources['ssh'][0]` and refuses without an
    admitted owner. `stock_controller.finalize_controller` and
    `host/stock-check-protection.py` take the image from the owner-published
    `host-supervisor-config.json` `query[0]`. The standalone scripts require it
    explicitly: `collect.py --ssh`, `supervise.py --ssh`,
    `finish-preparation.py NONCE SSH`.
  - git: `freeze-final.py ABSOLUTE-GIT-PATH`.
  - Windows PowerShell: the fixed literal
    `C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe`; no
    `SystemRoot`-derived image path (an inherited `SystemRoot` could be relative).
  - Python for host stock checks: `stock-control.ps1 -PythonPath` (mandatory,
    drive-rooted, existing file), passed by `stock_controller` as the admitted
    `sys.executable`.
  - Guest scripts: `rasdial`, `netsh`, `icacls` through
    `C:/Windows/System32/<name>.exe`.
  - `test_admin_recovery.py::test_every_local_child_image_is_absolute` scans every
    runtime Python file (list literals starting with a known bare executable
    name, and constant argv[0] of spawn calls) and every `.ps1` file (PowerShell
    AST: native command names without a path, `Start-Process` constant targets).
    Remote command words inside the ssh command (`sudo`, `python3`) are not local
    images.
- Operator procedure for the interpreter (mandatory, outside the harness):
  1. Create `admissionRoot` as a new directory under `<LAB_USER_PROFILE>`, so it
     inherits the clean `<LAB_USER_PROFILE>` ACL. Never create it directly under `C:\`,
     whose stock DACL lets Authenticated Users create entries.
  2. Only then extract the official embeddable zip (published hash verified)
     into the interpreter directory under `admissionRoot`.
  3. Before launch, with the system PowerShell
     (`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`), compare every
     file in the interpreter directory with the official zip: the same set of
     names, and for each name the same SHA-256 as the zip entry. Then compute
     `treeSHA256` as defined above and put it in the configuration and in the
     review record.
  4. The in-process `pinned_python` check runs inside the interpreter it checks,
     so it cannot detect a tampered interpreter. It binds the reviewed tree to
     the run and does not replace the pre-launch check in step 3.
- Read-only source pins (`WindowsAdmission.pin_readonly_source`). Threat model:
  third-party principals (observed: a local sandbox group and an unresolved SID
  with Modify `0x1301bf`, including DELETE) may hold write/delete rights on the
  ancestors and the leaf of external read-only inputs. For these inputs untrusted
  Allow ACEs with mutation bits are tolerated but never silently: each pinned
  component records its untrusted writers (SID, mask, flags) and file ID, and the
  records are journaled (`readonly-source-pins.json` at bootstrap,
  `readonly-core-pins.json` in phase1, `readonly-ssh-pins.json` in the
  preparation body). Integrity comes from the held leaf handle
  (share=READ, so no write/delete while held), the content hash bound by the
  caller and verified on bytes read through that handle, and `revalidate`
  (re-open by name, file ID and descriptor compare). Owner, ACE-type, reparse,
  hardlink and case-sensitivity checks are unchanged; the leaf must be a file and
  a caller without an expected hash cannot use `pin_readonly_source`. Tolerant
  call sites: the native owner (`nativeOwner.sha256`), the twenty original Core
  files (baseline `git.files` hashes), the checkout metadata (below) and the SSH inputs
  `known_hosts2`/`client2` (required configuration object `sshInputs` with exactly
  `knownHostsSHA256` and `clientSHA256`, lowercase hex SHA-256; a missing, extra
  or malformed field refuses, with no strict-pin fallback). Key bytes are only
  hashed; journals and evidence carry paths, hashes and ACL records. Writable state (private root, `create_root` parent chain, admission and
  package locations, manifests, configuration, review and baseline) stays strict.
  The interpreter is no longer a tolerant call site (see admission root above).
- Tolerant-path denial of service: an untrusted principal holding WRITE_DAC (or
  any mutation right) on a tolerant component can change its descriptor or
  rename it; `revalidate` then refuses (descriptor or file ID differs). This is a
  denial of service, not a bypass.
- Checkout without git (`admin_handoff.read_checkout`). No git process is ever
  run against the original checkout (an elevated git there would honour
  sandbox-writable config: fsmonitor, filters, gitdir). Configuration
  `gitCheckout` = exactly `gitDir`, `commonDir` (absolute) replaces the former
  `git` executable object; review `gitSHA256` and resource `gitExecutable` are
  removed. Each metadata file is a read-only content pin
  (`WindowsAdmission.pin_readonly_content`: tolerant ACL, reparse/hardlink
  refused, held share=READ, bytes read through the held handle, exact content
  check, hash recorded, then `revalidate`): `<baselineRoot>\.git` must be one
  line `gitdir: <gitDir>`; `<gitDir>\gitdir` must point back to
  `<baselineRoot>\.git`; `<gitDir>\commondir` must resolve to `commonDir`;
  `<gitDir>\HEAD` must be `ref: refs/heads/<baseline branch>`; the loose ref
  `<commonDir>\refs\heads\<branch>` (or, when absent, exactly one
  `packed-refs` entry) must equal the baseline commit. Lines are LF-terminated,
  single, no CR/NUL. The records are journaled with the twenty Core file pins in
  `readonly-core-pins.json`. Phase1 `eight.git` is now `HEAD`, `branch`, `files`,
  `worktree` (`gitDir`, `commonDir`, `ref` = `loose`|`packed`); validation
  compares HEAD/branch/files with the baseline and the worktree paths with
  `gitCheckout`. Checkout integrity is proven only by the twenty file hashes.
  The baseline `git status --short` text (formerly required to match exactly)
  is no longer checked, so "no other changes in the checkout" is no longer
  proven. Only linked worktrees (a `.git` file) are supported.
- System executable hardlink exception (`WindowsAdmission.pin_system_executable`,
  call site `admin_entry.system_anchored` for `config['ssh']`; Git is no longer
  admitted). Observed on the real host: `C:\Windows\System32\OpenSSH\ssh.exe`
  has a second link in WinSxS (owner TrustedInstaller); it passed the strict ACL
  check but failed `links == 1`. For this leaf only, `links > 1` is accepted when the
  leaf owner is TrustedInstaller (`S-1-5-80-956008885-...`), SYSTEM or
  BUILTIN Administrators (pure decision `validate_links`). The leaf is held open
  with share=READ; sharing applies to the file object, so writes or deletion
  through any other name are refused while it is held. The leaf bytes are read
  through the held handle and must match the configuration-bound hash
  (`ssh.sha256`, also bound in the review as `sshSHA256`), then `revalidate`
  re-opens by name. Ancestor and leaf ACL checks stay strict (not tolerant).
  Every other source (`pin_source`, `pin_readonly_source`, `read_once`) still
  requires `links == 1`. The pin returns evidence like a read-only pin (path,
  hash, link count, owner, file ID, components with untrusted writers), recorded
  in `readonly-source-pins.json`.
