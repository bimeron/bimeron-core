# ADR 0022: Native IKEv2/IPsec session backend

Status: accepted for the experimental Windows milestone, October 28, 2026.
Tracks [issue #56](https://github.com/bimeron/bimeron-core/issues/56).

## Context

Corporate VPNs and system clients commonly use IKEv2/IPsec. The existing
TUN/gVisor backend routes individual flows through upstream dialers. A system
IPsec tunnel instead owns its data plane, routing and DNS outside that stack.
Treating it as another dialer would misrepresent policy and protection support.

## Decision

Reuse Engine's backend/session lifecycle, bypassing the packet backend. Start
with a pre-provisioned current-user Windows RAS profile using IKEv2-only and
EAP-MSCHAPv2. The user authorized this system-integration direction and a
pre-provisioned profile as the initial safe integration boundary.

The version-1 configuration adds an exclusive `[IKEv2]` section containing
`WindowsProfile` and `ServerName`. The latter must be a DNS name matching the
Windows profile's server address. Windows validates its certificate trust,
name and EKU; the RAS flag disabling those checks is rejected. No custom IKE
identity, fallback protocol, PSK, dial hook, machine authentication, interactive
authentication or independent redial/always-on owner is accepted.

The native RAS APIs read profile properties and saved dial/EAP identity, dial
asynchronously, poll status and hang up only the returned handle. Saved dial
parameters contain an opaque password handle; no plaintext password enters
the configuration, command line or logs. EAP memory is released with the native
API. One process-wide callback is used, avoiding a callback allocation per run.
Windows ABI structures retain ras.h's four-byte packing on both pointer widths.

The existing global Bimeron lock and retained WFP protection checks are reused.
The initial path requires an elevated foreground process under the profile's
own user. IPC rejects system profiles rather than silently using a service
account's credentials. There is no Wintun dependency on the native path.

Only encrypted IPv4/IPv6 default-route profiles are accepted. Packet-specific
DNS/MTU/interface overrides, IPv6 disabling, SOCKS proxy mode, routing rules and
kill switch requests are rejected before system changes. Windows owns actual
route/DNS negotiation and mobility; default-route settings alone do not prove
absence of DNS or IPv6 leaks. No leak-prevention guarantee is advertised.

Capabilities have a separate `ikev2` object; existing top-level flags keep
their packet-backend meaning. `supported` means compiled support, with native
availability and profile checks performed at connection time. Session metadata
identifies the backend, reports IPv6 as `system`, and marks stats unavailable.
Stats snapshots also explicitly mark unavailability instead of implying that
unobserved native traffic equals zero.

Setup cancellation/error always rolls back a nonzero RasDial handle, including
when RasDial itself returns an error. Cleanup waits for handle invalidation
with an independent deadline; a cleanup failure overrides cancellation. An
existing RAS connection prevents startup. No existing connection is adopted,
and no profile, certificate, route or DNS setting is created or deleted.

Windows retains its native IKE mobility/rekey behavior. A lost connection or
manual disconnect ends the session without Engine redial. This prevents
competing retry owners and reconnecting against explicit user intent.

## Alternatives and tradeoffs

- An embedded IKE/IPsec stack offers more uniform behavior but adds protocol,
  cryptographic, licensing and platform maintenance. It is not selected.
- Automatic profile provisioning needs a separate EAP/certificate/secret-store
  contract. Requiring an existing profile makes the first integration smaller
  and keeps enterprise policy provisioning with Windows/administrators.
- A service identity cannot transparently use a GUI user's saved credentials.
  Service impersonation and machine profiles require a separate design.
- Profiles must not be edited or independently connected while Bimeron uses
  them. Inspection is repeated immediately before dialing, but Windows does
  not offer an atomic inspect-and-dial operation. If another caller references
  the same connection concurrently, cleanup may time out; Bimeron does not
  force-disconnect other handles.
- After a process crash a native tunnel may remain connected. Startup refuses
  to adopt it; disconnect it explicitly in Windows before trying again.
- Native connection success is RAS readiness, not a validated Internet probe.
  Restricted corporate networks must not depend on a public health endpoint.
- Linux strongSwan/VICI, Apple NEVPNManager and Android VpnManager remain
  separate milestones. Existing packet hosts reject system profiles.

## Validation

Test native profile rejection, packet-default isolation, foreground/service
boundaries, state transitions, cancellation, error rollback, cleanup failure
and concurrent Close. Verify ABI offsets against the Windows SDK ras.h with
an independent C compiler and exercise read-only native calls on Windows.
The ABI reference is Microsoft's
[Windows SDK ras.h](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/Ras.h).
Run existing tests/vet and targeted race tests; cross-compile supported targets.

Live interoperability, certificate rejection, IPv6/DNS behavior, NAT-T, rekey,
sleep/network changes, crash recovery and connection/throughput benchmarks need
a disposable Windows account/profile and a controlled strongSwan/RRAS server.
Unit tests and successful builds do not establish those properties. Keep this
milestone experimental until that matrix is completed.
