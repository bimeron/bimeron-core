# ADR 0029: Disabled native enrollment and offline admission primitives

Status: accepted user boundary; bounded implementation design, 2026-10-30.
Tracking: [issue #73](https://github.com/bimeron/bimeron-core/issues/73).

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
