# ADR 0024: Explicit Windows IKEv2 profile preparation

Status: accepted; explicit preparation command implemented, October 28, 2026.
Tracks [issue #56](https://github.com/bimeron/bimeron-core/issues/56).

## Context

The native backend intentionally controls an existing current-user Windows
profile. Preparing one manually is error-prone: default authentication, redial
and IPv6 routing settings can differ from the supported configuration. Setup
also touches persistent user configuration and certificate/credential policy,
whereas starting an Engine session should only acquire a connection handle.

The user selected a separate profile preparation command after considering
administrator-only preparation and automatic provisioning during connection.

## Decision

Provide an explicit Windows-only preparation command, separate from Engine
Start/Stop. A proposed CLI spelling is `bimeron ikev2 profile`; the final spelling
is an implementation detail. The command must support viewing the proposed
changes before applying them. Reading a Bimeron configuration or starting a
connection must never implicitly create or repair a Windows profile.

Use Windows profile APIs/cmdlets and the existing native profile validator.
Do not add an embedded IKE stack, a second credential store or a persistent
provisioning service. Scope the first version to current-user IKEv2-only,
EAP-MSCHAPv2 profiles and the algorithms supported by the validated Windows
milestone. Enterprise policy remains authoritative.

The command creates and manages only profiles it owns. Ownership must be
recorded in a per-user manifest with the profile identity and the exact public
settings created. A name prefix alone is not ownership. An existing unowned
name is an error; there is no implicit adoption, overwrite or force takeover.
On subsequent updates/removal, refuse active profiles and conflicting manual
changes rather than deleting or overwriting an administrator's work.

Creation is transactional as far as the native APIs allow: record each owned
resource, validate the result and roll back only resources created by that
invocation on failure. Report incomplete rollback explicitly. Repeat preparation
with matching settings is a no-op. Removal requires an explicit command and
only removes an inactive, unchanged, owned profile and its ownership record.

Certificate trust and credentials remain Windows/administrator responsibilities:

- Show the expected server DNS identity and required trust/authentication policy.
- Never accept a password in configuration, command arguments or logs; never
  export saved RAS credentials or EAP identity blobs.
- Do not install a root CA, change machine certificate policy, disable certificate
  validation or initiate authentication as part of profile preparation.
- Direct the user to Windows for initial authentication and saving credentials.
  Readiness checks report missing credentials without trying to obtain them.

IPv6 routes are explicit profile settings. The validated Windows 10 setup uses
two profile-owned routes, `::/1` and `8000::/1`, because that build does not install
`::/0` from its default-gateway flag. Windows applies/removes them with the
connection. Do not disable DAD, add machine-wide persistent routes or alter
physical interfaces to make the profile work. Route coverage is not a kill
switch: local/more-specific routes and disconnected periods can bypass a VPN.
The live run also confirmed DNS fallback to the LAN. Report the need for an
administrator-supplied namespace policy; the first preparation command must
not silently create persistent machine-wide NRPT rules or claim DNS isolation.

## Alternatives and tradeoffs

- Administrator-only provisioning stays supported and is appropriate for managed
  corporate profiles, but does not address repeatable setup for owned profiles.
- Provisioning inside Start hides persistent changes behind connection lifecycle
  and complicates rollback and credential ownership. It is rejected.
- A separate PowerShell setup script is a possible first delivery if it meets
  the same ownership, preview and rollback contract. A new service is unnecessary.
- Machine profiles, EAP-TLS, managed-device policy and service impersonation need
  their own design and are outside the first command's scope.

## Implementation acceptance

Verify name collision, repeated setup, failure rollback, manual modification,
active profile refusal and explicit removal on a disposable Windows account.
Ensure preview is read-only and errors never reveal credentials. Validate the
created profile through the existing guards and an interactive live connection,
including IPv6 route insertion/removal across repeated connections. Keep this
command unavailable until these checks pass. The implementation is
`bimeron ikev2 profile`, with read-only preview, `-apply`, and explicit `-remove`.
It records a pending per-user journal before creation and exact public settings
after native validation. Interrupted/ambiguous transactions require manual
administrator review; they are never automatically adopted. Windows credential
and CA preparation remain separate, and fixed algorithms match the validated
strongSwan milestone. See the [guide](../IKEV2.MD) and
[live validation report](../IKEV2_LIVE_VALIDATION.MD) for checks and limitations.
