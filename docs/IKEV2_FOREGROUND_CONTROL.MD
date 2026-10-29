# Experimental Windows IKEv2 foreground control

This private IPC 1 endpoint is separate from the system daemon. Desktop remains
gated on review of a new immutable Core SHA and separately recorded live evidence.
The unchanged `v0.3.0-beta.1` does not contain this interface. See ADR 0026.

## Installation and trust

Both Core and the requesting GUI must be installed below native `Program Files`.
The file and every directory through that root must have SYSTEM, Administrators
or TrustedInstaller ownership, with no effective allow ACE granting other SIDs
write/delete/ownership rights. Unknown ACE forms are refused. A path under Program
Files alone is insufficient. Existing installations with a user-owned executable
must be corrected by their installer; this endpoint never silently repairs ACLs.
Development binaries in writable directories are refused.

Processes of the same SID are not isolated from each other's GUI memory or
intent. This design does not claim protection against injection/control of the
trusted GUI by that SID, another administrator, or privileged OS policy changes.
It narrows the elevated interface to one reviewed native operation and verifies
the installed binaries rather than trusting a random pipe name or a claimed PID.
Go callers can use `NewForegroundClient` to pin verified image/process handles
between polls and avoid rehashing binaries; Close releases those handles. Calls
on one client are serialized. The GUI must implement the same checks, including checking
the selected Core executable digest before sending even the initial hello.

## Launch and discovery

The GUI reads/validates the native configuration without mutation, records its
SHA256 and its own process PID and creation FILETIME, and obtains the selected
Core digest/revision from its approved installation metadata. It launches that
exact absolute executable using `ShellExecuteExW` with verb `runas`, explicit
arguments and `SEE_MASK_NOCLOSEPROCESS`. Never use a shell, PATH lookup, environment
secrets or another executable on failure. UAC cancellation ends this attempt.
Keep the returned process handle while resolving launch outcome.

Session arguments:

```text
ikev2 foreground -config <absolute-path> -sha256 <64-hex-config-digest> -requester-pid <GUI-PID> -requester-created <GUI-creation-FILETIME-as-uint64>
```

Core verifies its own protected image and elevation and opens the requester
process. It verifies creation time, SID and nonzero interactive token session
against its own token. Different-account elevation fails before network changes.
It holds image/directory handles without write/delete sharing. The config is
restricted to a local fixed drive (no UNC/device/alternate stream paths); its
ancestors are pinned before opening the file. Reparse ancestors/files are refused,
write/delete sharing is denied, and at most
64 KiB is read once. The reviewed digest must match. Only native configuration
is parsed; no referenced files, arbitrary executable or packet source is allowed.
The secured config remains pinned until the owner closes.

Discovery is deterministic, using the intended user's SID and interactive session:

```text
\\.\pipe\Bimeron.Core.IKEv2.<first-16-bytes-of-SHA256(UTF8-SID)-lowercase-hex>.<session-id-decimal>
```

Core creates the first pipe instance exclusively. DACL permits intended owner and
SYSTEM only; medium integrity is explicitly allowed and remote clients are
rejected by the pinned go-winio implementation. Squatting/unknown ownership fails
closed. Precreation or holding an owner marker can deny availability; Core never
tries to seize or delete an unknown owner object. A machine-wide owner marker, created while holding the shared network
lock, also blocks updated packet-VPN/recovery/provisioning hosts until explicit owner
closure. This marker is not authentication. Do not automatically stop a service.
A packet proxy has no system network-owner lock; Desktop must separately check
authoritative service/Development status and refuse a conflicting managed session
before launch. Older Core binaries cannot enforce the new lifetime marker; use
the reviewed updated Core for every managed network/recovery host.

Each connection checks the OS-reported peer PID, process creation time, token SID,
token session and protected executable hash/file volume/index. Server peers must
match the original GUI image identity, allowing a reopened GUI process. The GUI
requires an elevated same-SID/session server matching the selected Core digest,
and checks the response owner identity against the OS observation. Hold handles
through the exchange to prevent PID reuse. Dial with identification-only SQOS.
There is no fallback to `ServicePipe` or the development daemon.

The initial authenticated hello is read-only. After verifying Core identity, the
GUI sends a second hello with this instance and accept_revision matching the exact
40-hex unmodified Core revision. Only this confirmation starts the launch-bound
Engine once. Subsequent discovery/reconnect never restarts it. Launch success, hello success
and process presence are not connected readiness. A missing/unknown endpoint is
not proof of cleanup or permission to duplicate launch. Poll status after delayed
startup or ambiguous timeouts; do not force-kill or retry Start. A new GUI probes
this same endpoint and verifies identity before considering another launch.

## Session wire contract

One request and response per connection, UTF-8 JSON plus LF. Request limit is
16 KiB, response read limit 256 KiB, request ID is required and at most 64 bytes.
Unknown fields, duplicate JSON keys, invalid UTF-8, oversized and malformed frames
are rejected. At most 32 requests run concurrently. Read/write deadlines are five
seconds. Use asynchronous client calls, at least seven seconds for stop exchange,
and bounded status polling (for example 500 ms active, two seconds terminal).

```json
{"version":1,"id":"hello-1","command":"hello"}
```

Hello includes `core` BuildDetails (version, exact revision, modified, platform,
architecture and build metadata), `capabilities.ikev2`, `instance`, `status`,
`endpoint:"ikev2_foreground"` and `owner`. Owner fields are `pid`, `created`,
`sid`, `session`, `image_sha256`, `image_volume`, `image_index`, `elevated`.
`created` and `image_index` are decimal strings to preserve all 64 bits.
Missing identity or an unapproved revision is incompatible, not a fallback cue.
Build metadata is not a substitute for executable authentication. Before starting,
confirm the reviewed identity on the same owner:

```json
{"version":1,"id":"activate-1","command":"hello","instance":"<owner-instance>","accept_revision":"<reviewed-40-hex-Core-SHA>"}
```

Missing/mismatched/modified revision returns core_identity_mismatch without Start.
After an ambiguous activation timeout, read status on that instance; do not launch
a second owner. The owner cannot start a different config or a second session.

Every subsequent request supplies that `instance` and `status.Session.id` as
`session`; a session not yet accepted uses an empty session string:

```json
{"version":1,"id":"status-1","command":"status","instance":"<owner-instance>","session":"<session-id>"}
{"version":1,"id":"events-1","command":"events","instance":"<owner-instance>","session":"<session-id>","after":0}
{"version":1,"id":"stop-1","command":"stop","instance":"<owner-instance>","session":"<session-id>"}
{"version":1,"id":"close-1","command":"close_owner","instance":"<owner-instance>","session":"<session-id>"}
```

Responses preserve existing capitalized Status/Event field names. Session states
remain connecting, connected, stopping, disconnected or failed; there is no native
automatic redial. `status.Session.active` is Engine activity, not RAS adoption.
Native stats are unavailable (`stats_unavailable:true`); stats commands/counters
are not offered. All commands outside hello/status/events/stop/close_owner fail.

Events retain the existing 128-entry cursor/dropped contract. Reset after instance
change; reread authoritative status after dropped events. `source_drops` counts
loss before the control history; once nonzero, dropped remains conservative for
that owner. Events and text logs are never the authoritative protection state.

`status.native` separates `requested`, `wfp`, `dns`, `profile_readiness`,
`credential_readiness`, `certificate_readiness`, `ras_cleanup`, `dns_cleanup`,
`wfp_cleanup` and `recovery_required`. Protection values include inactive,
installing, active, retained, modified and unknown as applicable. Readiness is
not_checked until checked; missing credentials/profile are separate from compiled
support. Windows-authenticated means that this connection passed Windows
authentication, not a reusable certificate trust inventory or Internet probe.
These are lifecycle observations, not continuous auditing of privileged policy.

Bootstrap remains unprotected. Connected is published only after required policy
setup. Stop cancels startup or disconnects and waits up to five seconds per call;
`cleanup_pending` means the wait ended while cleanup continues. Repeat status or
stop, never Start/kill/recover. Cleanup order is owned RAS handle invalidation,
owned DNS cleanup/cache flush, WFP release. Partial failure retains/marks unknown
protection; disconnected/process exit alone does not prove cleanup success.

GUI/IPC loss never cancels the owner. Terminal owners remain available until
close_owner; active owners refuse it with session_not_terminal. Closing a failed
owner does not remove retained policy. Recovery remains a separately confirmed
administrative operation after owner closure, with explicit handling of surviving
RAS tunnels in Windows. Foreign RAS handles/policy are never adopted or removed.

Safe errors include existing IPC codes plus stale_instance, cleanup_pending,
session_not_terminal, foreground_identity_rejected, foreground_owner_unavailable,
foreground_configuration_rejected/changed. Display a generic localized message
for unknown codes; never display arbitrary elevated stdout/stderr/native errors.

## Separate provisioning owner

```text
ikev2 profile-control -name <Windows-profile> -server <DNS-name> -action apply|remove -requester-pid <GUI-PID> -requester-created <GUI-creation-FILETIME>
```

This exclusive owner uses the same authenticated transport and discovery, but
reports `endpoint:"ikev2_profile"`. It cannot start a session. Hello schedules
read-only preview; status reports operation previewing/previewed/applying/
succeeded/failed and bounded `profile` public settings. Preview includes
`state_token`, hashing config, exact native public settings/GUID and journal.

After the user reviews that exact preview, send command apply or remove (matching
the launch-selected action), instance, `accept_revision` for the exact reviewed
unmodified Core SHA, and `plan_token:profile.state_token`.
No session field is used. Core rechecks the token while holding the mutation
lock. A changed profile/journal requires a new preview owner; no adoption/repair
is attempted. Confirmation schedules one synchronous native transaction; status
remains responsive and GUI loss does not cancel rollback. Lost confirmation
responses are resolved through status, not duplicate apply. close_owner refuses
an in-progress operation. Existing CLI preview/apply/remove remain compatible.

Provisioning does not install certificates, obtain passwords, seed EAP identity
or touch WFP/NRPT. Incomplete journals require manual administrative review;
network recover does not reconcile them. Returned error codes are allowlisted;
untrusted free text is never an operation error payload.

## Validation boundary

Offline tests use fake engines/drivers, temporary files and isolated test pipes;
they never connect real VPNs or modify routes/DNS/WFP. Run tests/vet and focused
race tests, native Windows ACL/file-sharing tests, Linux amd64/arm64 and Windows
amd64/arm64/386 builds. ARM64 compile success is not runtime evidence.

Live acceptance requires an authorized disposable VM and controlled server:
medium-to-elevated handshake/UAC cancellation, other-account refusal, reconnect,
duplicate launch, crash retention, cancellation during bootstrap/protection,
ordered cleanup/failure/recovery and provisioning guards. Capture positive
baseline/recovered controls and exact binary identities. Never use production
credentials or shared CI. Measure control responsiveness and start/stop latency;
do not repeat data-plane benchmarks without evidence of a relevant regression.
Windows 11/RRAS/physical mobility/public IPv6 claims remain deferred in issue #66.

### Opt-in foreground lifecycle harness

`TestWindowsForegroundLiveLifecycle` is skipped unless
`BIMERON_IKEV2_FOREGROUND_LIVE=1`. On the authorized disposable VM, install the
compiled control test executable and selected Core below a protected Program
Files lab directory with the ownership/ACL requirements above. Do not run this
setup on the host workstation or shared CI. Run the test executable from an
elevated interactive account with a prepared current-user test profile.

Set only public test metadata:

```powershell
$env:BIMERON_IKEV2_FOREGROUND_LIVE = '1'
$env:BIMERON_IKEV2_FOREGROUND_BIN = '<protected absolute Core executable>'
$env:BIMERON_IKEV2_FOREGROUND_REVISION = '<reviewed immutable Core SHA>'
$env:BIMERON_IKEV2_TEST_CONFIG = '<local absolute native test config>'
& '<protected control.test.exe>' -test.run '^TestWindowsForegroundLiveLifecycle$' -test.v -test.timeout 10m
```

The harness verifies authenticated read-only discovery, immutable-revision
activation, authoritative connected/protection state, IPC reconnect preserving
session identity, unavailable statistics, and ordered cleanup. It records
activation/stop latency without endpoint/credential data and closes the owner
only after a structured stop outcome. Unknown outcomes never cause force-kill or
automatic recovery. This harness does not establish UAC interaction, another-user
login refusal, crash/modified-policy recovery or physical leak behavior; those
require the separately documented manual disposable-VM matrix. Compilation or
skipping this test is not live evidence.
