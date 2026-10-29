# ADR 0026: Authenticated Windows IKEv2 foreground control

Status: architecture approved; implementation under validation.
Tracks issue #68. This document does not lift the Desktop implementation gate.

## Context

The reviewed baseline and remote master both resolve to
`9f527efe0a4959786084675f1ff795edb8a0d910`. The annotated beta.1 tag object is
`9cce36d43f70d30d406b020187ad100ac40ba0e7`. The release-by-tag endpoint returned
404 during review. Source support does not establish published assets, signed
compatibility metadata, or Desktop approval.

The existing foreground CLI owns an Engine but exposes text events and signal
cancellation. The daemon IPC cannot be used to run native current-user IKEv2.
Desktop must not parse logs, create a separate Engine helper, or implement RAS,
WFP or NRPT itself.

## Approved decisions

Installation identity is a protected, bounded `bimeron-foreground.json` next to
Core: schema 1, public installation ID and one authorized GUI SHA256. Core pins
this file, refuses an unapproved requester image even in Program Files, and
requires the installation ID on every request/response. Only the installer or
administrator writes this metadata; there is no IPC registration/update command.

Use the same Core executable as an elevated interactive foreground owner under
the GUI user's SID. Reject over-the-shoulder elevation before network mutation.
Production native GUI launches require an executable in a protected location;
a writable development executable does not receive the same security claim or
compatibility approval. Verify OS-derived peer process identity, creation time,
interactive session and executable file identity/hash, not only PID or pipe name.

Bind configuration to the exact reviewed bytes, expected SHA256 and secured file
identity. The privileged loader must open the absolute path without write/delete
sharing, reject unsafe reparse substitution, read bounded bytes once, and retain
that snapshot. Changes require another preview. The byte parser accepts native
IKEv2 only and performs no referenced-file resolution. Existing native config
restrictions remain authoritative; do not broaden packet file/reference rules.

Apply provisioning only against reviewed parameters and the expected public
settings/ownership snapshot, rechecked under the existing lock. Preserve GUID,
collision, unchanged/inactive ownership, pending journal and rollback guards.
Start never provisions or repairs profiles. Credentials, EAP identity and CA trust
remain Windows-owned.

Keep the foreground owner alive after terminal success or failure so a reopened
GUI can read the authoritative result. Add a narrow `close_owner` operation
permitted only after Engine completion. It does not recover networking, remove
retained policy or convert failed cleanup into success.

## Implementation boundary

Reuse IPC 1 JSON/LF framing, bounded correlated exchanges and event history, but
provide a private foreground dispatcher and explicit dial without service
fallback. Session operations are hello, status, events, stop and close_owner.
There is one launch-selected native config and no IPC start, shell execution,
credential operation, arbitrary path mutation or automatic recovery command.

The [wire and launch contract](../IKEV2_FOREGROUND_CONTROL.MD) specifies mutual authentication, same-SID trust
limits, UAC launch binding, restart discovery, squatting refusal, instance/session
binding and executable replacement resistance. A claimed revision in hello is
not executable authentication. ACLs alone do not authenticate a pipe server.
Do not add an unauthenticated interim endpoint.

Expose authoritative structured requested/active/retained/modified/unknown
protection and per-stage cleanup outcomes. Compiled capabilities, profile and
credential readiness, RAS connection readiness, protection readiness, cleanup
and process exit are separate observations. Native statistics are unavailable.

Keep GUI disconnection independent of owner lifetime. Stop cancels startup or
disconnects and waits for RAS, then owned DNS cleanup, then WFP release. Timeout
only bounds the caller's wait. Unknown ownership, retained policy and ambiguous
cleanup block another start; do not kill, adopt, redial or recover automatically.
Use the existing shared network-owner lock for packet/native exclusion, retaining
the packet service's rejection of IKEv2. Do not stop another backend implicitly.

Provisioning remains a separate explicit operation with bounded structured
results carried through an authenticated channel, not arbitrary elevated stdout.
Network recovery does not repair interrupted provisioning transactions.

Privileged PowerShell must not resolve its executable through inherited
SystemRoot/PATH or autoload user modules. Share a Windows-system command
constructor for runtime and provisioning scripts, preserving their existing
cancellation policies. Reset the system module path after startup and exclude
unrelated application environment secrets. This is part of the privileged
boundary rather than a new networking backend.

## Validation and release gate

Offline tests must use fake network drivers and temporary files, never real VPN,
routes, credentials, certificates, DNS or firewall policy. Cover wrong SID/peer,
spoofing, replay/stale instance/PID reuse, duplicate launch, UAC cancellation,
startup timeout, GUI loss/reconnect, owner crash, stop during setup, cleanup
failure/retention, malformed/oversized messages, provisioning conflicts and
interrupted rollback. Check secret sentinels in all public diagnostics.

Run existing tests/vet and focused race tests, Windows pipe/token tests, supported
platform builds and existing daemon/protocol regressions. Windows ARM64 builds
are not runtime interoperability evidence. Preserve current CI coverage.

Live checks require separate authorization for a disposable Windows VM and
controlled server; never run them in shared CI. Preserve the bootstrap/BFE and
privileged-policy limitations from ADR 0025. Windows 10/strongSwan evidence does
not establish Windows 11, RRAS, physical mobility, ARM64 or public IPv6 support.
Measure control responsiveness and start/stop latency; repeat data-plane
benchmarks only with evidence of a relevant regression.

Desktop remains blocked until the complete wire/launch contract, focused tests,
sanitized live evidence and a new immutable Core SHA are explicitly reviewed.
Do not assign new capabilities to the unchanged beta.1 tag.
