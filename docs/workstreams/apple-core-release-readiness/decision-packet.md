# First compatible Apple Core artifact: readiness proposal

Status: source-only proposal; no candidate, trust pin, compatibility approval or
release authorization is established. Work is isolated on
`docs/release-readiness-current-staging`, tracked by Core issue #91. Core79 native
proof remains independently open.

## Source selection and version decision

The current inspected merged baselines are Core `origin/master`
`0d5fd06bbb9d7b00942e50606fc0017851ca6c24` and Apple `origin/main`
`888f7a945dd0f12d26ca4eb4ce62f0636fd69b18` (local remote-tracking refs inspected
offline on 2026-11-05; no fetch). These identify current source, not an approved
release pair. Core `c04f20d575e4aed979b1024a32b421e7e5de1afe` remains the
**historical proposed, not accepted candidate** from the original packet; do not
promote it or silently substitute the current baseline as a release selection.
Core's delta adds optional session-bound statistics (`docs/adr/0033-session-bound-statistics.md`);
its release preparation and compatibility policy are unchanged. The Apple baseline
includes authenticated staging commit `728d709`, the standalone statistics model
and the hosted-runner CI change. The original Apple `f48d9c8` baseline and later
`859f15b` observation are historical, superseded as current source observations.
Any release source selection requires explicit review of the exact pair and new
artifact evidence bound to its full SHAs.

The exact Core version is **undecided**. Recommend a new unused beta SemVer in
the current release line, after checking authoritative public tag/release metadata.
Local tags include `v0.3.0-beta.2`; they are not a complete current public inventory.
Do not reuse the synthetic `0.1.0-beta.1` from the integration report or infer a
version from the app's `0.1.0`. Approve the tuple `(full Core SHA, exact version,
tag v<version>, beta channel)` independently of the manifest. Stable publication
would make a stronger acceptance claim and is not recommended for first review.
No tag is created by this proposal. Canonical version has no build suffix and
must match the retained record, manifest and archive names exactly.

## Independent key provenance

No production public key or pin is available or approved here. Obtain the actual
32-byte Ed25519 public key from the designated signing custodian through an
independently authenticated channel. Record its canonical base64, full SHA-256,
derived key ID, custodian identity, intended Apple signing scope, authenticated
channel/reference, confirmation date and approving reviewer. Compare full key
bytes or full fingerprint through a second authenticated confirmation before
accepting consumer trust configuration. A manifest, its adjacent download, a
key ID or this document cannot bootstrap trust.

Recommend explicit reviewed consumer pin provisioning; defer key distribution
automation until the custody and rotation owner are agreed. Rotation/revocation
must name who can authorize a replacement and how consumers receive it. This is
a proposed process, not a selected key-management architecture. Synthetic vector
keys are publicly known test material and must never become production pins.
Do not request or inspect private keys or secret environment variables.

## Compatibility and staging evidence

Preserve shipping `release/apple-compatibility.json`: `[0.1.0, 0.1.1)`,
`apple_reviewed:false`, IPC 1, profile format 1, daemon session guards true.
Recommend keeping that narrow provisional interval until actual review; broadening
it requires evidence for the additional app versions. App source at `888f7a9`
declares `CFBundleShortVersionString=0.1.0`, `CFBundleVersion=1` in
`scripts/build-app.sh`. This is source evidence only; no built bundle was inspected.

Staging must return explicit evidence fields with status (`available`, `missing`,
`not run`, or `failed`), producer/reviewer, tool versions and log/digest references:

- Apple app: full selected source SHA, clean state and recipe, actual built
  bundle version/build, bundle identifier, architecture and digest. Bind the
  tested app build to this identity; do not infer it from a source script.
- Core: exact approved version/tag/channel/full SHA; compiler and Git identity,
  explicit generated record bytes/digest, recipe, and clean source checks.
- For **both amd64 and arm64** separately: final ZIP size/SHA-256, executable
  digest, retained canonical version, thin Mach-O CPU, Go OS/architecture,
  exact revision, explicit modified=false, git/trimpath evidence, ZIP role
  counts and per-file hashes, and static Apple consumer acceptance result.
- Consumer evidence: exact verifier commit, bounded original manifest/signature
  identity, independent approval identity, app version/channel/context and trusted
  pin provenance reference. A key identifier carried by an envelope supplies no trust.
- Compatibility review: actual app/Core pair, IPC hello/version and guards,
  profile format behavior, supported lifecycle/readiness and refusal paths,
  supported CPU/OS coverage, failures and limitations, named reviewer and explicit
  authorization for the exact interval and candidate. Source/synthetic tests
  cannot replace actual integration acceptance; any installation/live work needs
  its own later authorization.

### Current merged staging API

At Apple `888f7a9`, `Sources/BimeronCoreCLI/AppleCoreRelease.swift`,
`AppleArchiveGate.swift` and `AppleCoreStaging.swift` implement the seam documented
in Apple `docs/workstreams/core-delivery/authenticated-staging.md`. The old relay
that the gate returns Void and extraction has not started is obsolete.

- `AppleCoreRelease.verifyManifest(..., context:)` detaches bounded owned copies
  before authentication. Its privately constructed manifest retains
  `AppleCoreVerificationEvidence`: exact signed manifest/signature, supplied public
  key/key ID, app version/channel/architecture, independent approval tag/revision,
  policy revision `apple-core-static-v1` and caller context. Manifest/signature/key
  limits are 65,536/89/32 bytes; separately supplied strings are bounded to 1,024
  UTF-8 bytes. Context classification (`unspecified`, `syntheticUntrusted`,
  `independentlyConfigured`), approval identity, pin provenance and Apple build
  identity are caller assertions, not verified production trust or build identity.
- `verifyArchive(_:manifest:)` authenticates an owned archive snapshot and returns
  privately constructed `AppleCoreReleaseVerifiedArchive` only after the whole
  static gate succeeds. `AppleArchiveGate` remains the sole ZIP interpreter and
  returns the three validated contents. Fixed `AppleCorePayloadRole` values are
  `bimeron`, `LICENSE`, `THIRD_PARTY_NOTICES.txt`; files carry owned contents,
  counts and SHA-256. No archive storage, arbitrary path or extraction plan crosses
  this seam; the unchanged manifest descriptor carries evidence onward.
- `AppleCoreStagingCoordinator(stagingParent:)` requires a caller-provisioned,
  exclusively controlled app parent. `stage(_:cancelled:)` permits one active
  operation, creates only fixed leaves with no-follow/exclusive opens, uses
  0700 directories and nonexecutable 0600 files, checks ownership/ACLs/identities
  and hashes, and publishes by same-parent exclusive rename. Returned
  `AppleCoreStagedCandidate` retains the manifest, per-role count/hash/device/inode
  and held read-only descriptors; `withFileDescriptor(for:_:)` borrows a duplicate,
  and `discard()` performs identity-checked disposal. Prepublication cleanup can
  report `cleanupIncomplete`; postpublication confirmation can report
  `publishedButUnconfirmed` carrying the candidate for explicit reconciliation.

This is a disposable unprivileged candidate, not protected Prepared state,
installation, execution or readiness. Same-UID mutation remains possible; a later
privileged consumer must copy into protected storage and revalidate actual bytes,
original evidence and independent policy. There is no fsync/crash-durability claim.
The documented 520 MiB archive/payload overlap (776 MiB with caller archive) is an
arithmetic budget, not measured maximum RSS; maximum-size and hard latency bounds
remain unvalidated. Original-byte retention is implemented, so it is no longer an
unresolved architecture prerequisite. Production trust/approval provisioning,
actual app bundle identity and both-CPU Core-to-Apple acceptance for the current
pair remain missing.

Only a separately documented actual review and authorization can permit
`apple_reviewed:true`. If policy is committed true, freeze and rebuild from the
resulting final SHA; never retain pre-change revision evidence as final evidence.
Signed guards do not replace runtime hello/session readiness checks.

## Responsibilities and publication boundary

Proposed roles (people remain unassigned): builder preserves exact inputs and
two-CPU outputs; independent reproducer compares final bytes; Apple reviewer
owns compatibility evidence; signing custodian signs only approved exact manifest
bytes; publisher uploads only the approved immutable assets; release approver
authorizes candidate, tag and publication separately. Recommend independent
reviewer and signing approval rather than builder self-approval.

The Apple preparer is public-only and has no signing mode. A future authorized
signer must sign the exact bounded LF-terminated JSON bytes with Ed25519, producing
the canonical detached signature. Verify with the independently authenticated pin
and exact approval, then authenticate ZIP sizes/hashes before parsing. Any changed
asset or manifest requires a fresh review/signature. Apple developer code signing
or notarization, if required by the chosen distribution path, is a separate scope;
manifest signing does not provide it.

There is no approved Apple publication integration. ADR0003's preserve-reviewed-
bytes principle applies, but its legacy publisher must not be repurposed: it has
a different asset contract. A future Apple publication plan needs exact asset
inventory, destination, successful source CI, immutable upload/digest verification,
and explicit publication authorization. Current CI coordination remains independent.
No tag, key generation, signing, publication, installation, network or live action
is authorized by this packet.

## Offline verification independent of release

Existing [contract](../../apple-update-manifest.md),
[ADR0031](../../adr/0031-separate-apple-update-manifest.md),
[ADR0032](../../adr/0032-retained-apple-core-version.md) and
[production integration report](../../../research/apple-core-provenance/production-integration.md)
define the recipe and prior evidence. The latter's `e8de435` fixture hashes are
not artifacts or reproducibility evidence for `c04f20d`.

For future offline reproduction use two clean isolated checkouts at the selected
full SHA, installed trusted Go 1.26.9 on Darwin and explicitly selected Git,
cached dependencies, network-disabled Go settings, identical explicit version and
record inputs, CGO disabled and the builder's sanitized environment. Compile the
builder itself in a trusted clean environment; compare both final ZIPs byte for
byte across checkout paths. Record archive, binary and generated-record hashes.
Missing cached dependencies block the check rather than enable downloads.
Keep synthetic runs clearly labeled, inject review=true only into synthetic
policy, and leave shipping policy untouched. Do not execute supplied archives.

The original packet records offline synthetic tests at `c04f20d` using installed Go 1.26.9:
`TestCanonicalAgreement`, `TestSyntheticInterop`, `TestStrictContract`, and
`TestBuildProvenanceAndArchives` passed. The archive test builds tiny synthetic
Darwin fixtures for both CPUs and exercises static checks; it does not build the
production Core artifact.
These establish parser/record/signature/gate behavior with known synthetic keys,
not production trust or candidate acceptance. No real Core rebuild, app build or live acceptance for the current pair follows
from those historical checks.

Apple `888f7a9:docs/workstreams/core-delivery/authenticated-staging.md` records
historical local implementation validation: final parent Swift run passed 47
XCTest and 85 Swift Testing tests, explicitly counting all 348 signed synthetic
vectors (`/private/tmp/staging-parent-final-swift-348-retry.log`). The separate
Core parity run used detached `e8de4354e2dc5d0364a2fb93119c50971cdf8a5c`, installed
Go 1.26.9 and disabled downloads; it reported `PASS 348 Core archive vectors`
(`/private/tmp/staging-parent-core-348.log`). The document also records the earlier
46/85 run, subsequent 12 staging tests, and the unrelated editor-save timeout
that passed alone and on unchanged full retry. Actual Core CLI execution remained
skipped. These are recorded synthetic parser/staging regressions on macOS arm64,
with both archive CPUs checked statically, not fresh runs or release acceptance
at `888f7a9`/`0d5fd06`. The 348-vector corpus is finite regression coverage,
not proof for all possible archives. The temporary logs were not re-read for this
reconciliation.

Separately, the coordinator supplied verified hosted source-CI provenance:
Apple commit `888f7a945dd0f12d26ca4eb4ce62f0636fd69b18` has a successful
[build check](https://github.com/bimeron/bimeron-apple/actions/runs/42013491023/job/127198083962),
reported from the GitHub commit check-runs API. This exact-baseline source CI does
not establish a selected release artifact, independent pin, compatibility approval
or live acceptance. The coordinator queried existing check metadata only; this
reconciliation did not rerun CI.

This update inspected source, documentation and existing check metadata; it ran no experiments,
builds, tests, artifact execution or acceptance work.

## Smallest remaining decisions

1. Approve the exact Core source/version tuple and selected Apple app baseline;
   review the current inspected pair for bounded offline evaluation first, with a new
   unused beta version after public metadata review. Candidate approval is separate.
2. Name signing custodian, independent pin authenticator and release approver;
   supply public-key provenance without exposing private material.
3. Agree the actual compatibility acceptance scope and owner; recommend retaining
   `[0.1.0,0.1.1)` and false until evidence and authorization exist.
4. Review the implemented unprivileged staging boundary and decide the later
   protected-copy/revalidation integration, actual build/artifact evidence and
   resource acceptance scope. Signing/publication mechanics remain subsequent
   authorized decisions; this packet selects no architecture or role owner.

Parent review should use the exact current source identities above and the merged
staging API, retain both CPU evidence independently, and report missing built-app
identity. Neither the historical proposal, synthetic regressions nor hosted source
CI supplies candidate approval. No version, pin, role assignment or compatibility
approval is selected by this reconciliation; shipping remains false/no-key.
