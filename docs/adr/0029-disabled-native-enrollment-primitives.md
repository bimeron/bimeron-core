# ADR 0029: Disabled native enrollment and offline admission primitives

Status: accepted user boundary; bounded implementation design, 2026-10-30.
Tracking: [issue #73](https://github.com/bimeron/bimeron-core/issues/73).

## Volume-root descriptor policy amendment (2026-10-30)

Parent accepts the [minimal contract delta](../NATIVE_ENROLLMENT_SPEC.MD#volume-root-only-descriptor-amendment-2026-10-30) before code: permit outsider FILE_ADD_SUBDIRECTORY (`0x4`) only at the held volume GUID root, initially and on every index-0 recheck. Root child creation does not replace/delete existing Program Files while all other outsider mutation rights are refused and Program Files/downstream ACL and identity pins remain strict. Trusted ownership, present non-null DACL, unknown-effective-ACE refusal and inherited-effective validation remain required.

Alternative: keep the blanket prohibition and retain the observed descriptor blocker. Selected tradeoff: a narrowly explicit private root policy permits unrelated child creation while retaining every protected-path check. Reject changing the VM root ACL, general traversal exceptions, boolean ignore/trust bypasses and broader descendant rights. The [central evidence checkpoint](../NATIVE_ENROLLMENT_VALIDATION.MD#volume-root-contract-and-failed-native-evidence) records failed native clean/repeat and separates sufficient parser evidence from unproved runtime attribution. No runtime success or enrollment authority follows; parent review, fresh binary/CI/native evidence and all existing enrollment gates remain outstanding.

## Context

Explicit separate native IKEv2 enrollment is accepted; packet-only installation and signed service update health checks/rollback must remain unchanged. Core base `83683e4b5c1a673f0d29d667c09b116f5805027b` is tree-equivalent to reviewed master `66d84d8f4dcfc6ada625eb11894b19feea51b7ba`, not asserted to descend from it. Desktop's standalone prototype is fail-only and demonstrates mechanics, not safe MSI completion.

The existing mutex cannot survive its owning MSI host thread. Commit callbacks, local InstallFinalize, nested old uninstall and rollback-disabled execution do not establish outer terminal authority. The updater must start replacement/restored ordinary services, including old binaries which ignore enrollment and can survive updater death. No safe enrolled updater transaction is proven.

## Decision

Keep enrollment DISABLED and refuse future enrollment until those proofs exist. Specify only a disconnected, platform-neutral strict 64-byte record codec, conservative admission decision and pending-preserving event model. There is no production mutation, Begin or settlement command, registry reader or admission hook. Hypothetical clean records are codec fixtures, not permission to run native operations.

Select a native-view protected HKLM binary value as the future minimal representation, conditional on separately proven security, absence and durability handling. Implement only explicit security/view/generation observations now. Trusted protected absence is non-enrollment/nativeUnavailable, preserving legacy packet behavior. Enrolled unsafe/pending refuses participating protected admission with no foreground-process bypass. Observation alone cannot enforce old-host exclusion or proxy coverage.

The [specification](../NATIVE_ENROLLMENT_SPEC.MD) fixes record layout, API boundary, trustworthy-absence requirements and limits. The [acceptance brief](../NATIVE_ENROLLMENT_ACCEPTANCE.MD) defines tests before code and the separate low/Standard execution subset.

## Alternatives and tradeoffs

- Global missing-state lockout: rejected by the user; breaks packet-only installations and ordinary updater health checks/restoration.
- Protected file journal: possible future storage, but adds path/ancestor/reparse pinning and still lacks outer terminal authority. Existing foreground JSON remains an identity policy, not a settlement journal.
- Registry with runtime reader now: compact storage, but no authorized caller, atomic admission proof or fully validated absence adapter yet. Deferring the reader avoids unused privileged surface while retaining useful pure validation tests.
- MSI DLL worker/commit action as completion authority: insufficient lifetime and callback ordering. Module pinning cannot pin the host process. No child transaction may settle its parent.
- Service restart exceptions, generic bypass, early settlement or caller-supplied verified boolean: rejected; each allows an unproven admission or changes update semantics.
- Helper service/setup wrapper or updater redesign: outside authorization. No speculative protocol is added to make the plan appear complete.

## Consequences

The next implementation can safely improve validation and make negative invariants executable. It delivers no enrolled installation, no rollback journal, no crash-safe publication and no production enforcement. Equality of generations detects observed change only; it is not replay/ABA protection. Security observations are not real Windows ACL verification.

Abnormal native failures may ultimately need explicit administrator recovery; routine success must have a proven automatic terminal boundary, not manual unlock. A follow-up architecture decision must resolve outer transaction ownership, old-host enforcement and preserved enrolled updater success/restore/death before enabling enrollment. If that is infeasible within the accepted packaging boundary, native enrollment stays unavailable. Parent owns later review, CI and merge; no publication is authorized.

## Approved launch-boundary amendment (2026-10-30)

Tracking remains issue #73. This amendment uses merged Core `4366a5c9d07775def8cd751efaa380a8095acdd7`; the isolated docs checkout first merged origin/master into the historical `83683e4b` ancestry, producing local base `eb07b2cd1b07730e898706b2b19f232818a46569`. Desktop reference is committed `docs/ikev2-profiles.md` at `2183b744547a386b85fc75e63b43890ca079b5b9`. Earlier provenance and validation above remain historical.

Historical boundary (superseded by the selected procedure below): the user approves an already fully elevated, same-user interactive initiating MSI client for native enrollment and EVERY modification of an enrolled installation. Otherwise refuse before mutation and request an administrative launch. Server-side per-machine elevation alone is insufficient. Native enrollment remains explicit opt-in; trusted protected absence preserves ordinary packet installation, signed updater health checks and rollback.

Only the bounded offline Desktop prototype and static fixtures are authorized now. This is an approved launch boundary, not an accepted production trust implementation or observed Windows token semantics. The fixed-package transaction and conditional settlement requirements are specified in the [amended specification](../NATIVE_ENROLLMENT_SPEC.MD#approved-fixed-package-offline-prototype-boundary); the [acceptance amendment](../NATIVE_ENROLLMENT_ACCEPTANCE.MD#offline-prototype-acceptance-amendment) separates offline checks from deferred MSI evidence. The existing Core model remains unchanged and cannot enforce this boundary.

A durable exclusive handoff may replace worker-thread continuity only after all resource mutations, including rollback/commit work, are quiescent. A callback or child transaction alone cannot establish this. This narrowly qualifies the continuous-thread alternative above; it does not add a settlement API, generic bypass, verified=true input, registry reader or runtime enablement.

Actual elevated disposable-VM experiments and production enablement are not authorized. Before any future production change, a bounded reviewed ADR amendment must record the demonstrated token, package, handoff and durable-reader contract and remaining updater/host exclusions. Until then, no routine-success automatic settlement or freedom from manual lockout is proven. SYSTEM and Administrators remain trusted within the existing threat scope; this is not protection against malicious administrators.


## Disconnected file reader and update proof decision (2026-10-30)

The user accepts the A+B disconnected-only delta in the [current specification](../NATIVE_ENROLLMENT_SPEC.MD#disconnected-reader-and-update-proof-amendment) and [split acceptance](../NATIVE_ENROLLMENT_ACCEPTANCE.MD#split-implementation-acceptance). This supersedes the historical registry choice and reader deferral above. Choose native Program Files with flags zero and exactly `Bimeron Core/NativeEnrollment/record.bin`, retaining the Core 64-byte codec. Registry storage is rejected for this iteration; accepting the extra file identity/ancestor work aligns the fixed location with Core installation and permits bounded descriptor/reader evidence without a writer. Desktop LPF interoperability and a configurable storage framework are rejected.

Exact SYSTEM/Administrators/TrustedInstaller trust aligns with Core file identity validation; it does not weaken protected container/record DACL or ancestor checks. Bootstrap absence needs a validated held nearest ancestor; missing leaf inside an existing enrollment container is unsafe. Whole-subtree administrative deletion remains unsolved.

The second workstream records actual updater outcomes and disconnected authenticated health bindings. It does not change restore-to-SCM-Running-only behavior, stopped-service probe omission, Linux semantics or ordinary dispatch. Future health startup gating needs separate acceptance; no early settlement or Pending bypass is permitted. Tradeoff: useful offline negative proofs and descriptor parsing, with no claim of production admission, compatible-host enforcement, atomic reading, crash-safe publication or routine-success settlement. Enrollment remains disabled. Issue #73, parent independent review and hosted CI remain the completion path.


## Selected trusted invocation revision (2026-10-30)

Option 1 authorizes specification revision and independent review of a trusted already-fully-elevated, same-user interactive invocation procedure, exact protected package/preload approval, and independent callback effective-context validation. The [selected specification](../NATIVE_ENROLLMENT_SPEC.MD#selected-trusted-invocation-procedure) and [acceptance](../NATIVE_ENROLLMENT_ACCEPTANCE.MD#trusted-invocation-reconciliation-acceptance) reconcile Desktop `59c566631dab25e2844e8e82997e5ea98d88b56e` from fetched Core master `727c60ad58f05b4f393b736f57cc17da382be41e`. Earlier provenance and evidence remain historical.

Tradeoff: original-process attestation is not established; correct privileged invocation is deliberately trusted, with that explicit residual risk subject to independent review. Administrator/SYSTEM callback authority cannot prove the initiator. `verifyInitiatingClient` remains Unknown. Missing required authenticated interactive binding or independently approved preload still refuses; this decision invents neither mechanism. Production Session 0 is unsupported. GUI/Core executable and OS peer authentication remain unchanged.

This is specification acceptance for review only, not production trust acceptance. All native protected-positive, durable-reader, compatible-host/rollback, authenticated health, updater and terminal-settlement gates remain. Enrollment stays DISABLED, the Core 64-byte and Desktop 48-byte formats remain separate, and no runtime, schema, reader or updater implementation changes follow from this documentation revision. Tracking remains issue #73.
