# Experimental Windows IKEv2/IPsec

The separate experimental [Windows IKEv2 foreground control contract](IKEV2_FOREGROUND_CONTROL.MD)
is available in development source. It does not change daemon start, the beta.1
baseline, published assets or Desktop compatibility approval.


Bimeron controls a pre-provisioned current-user Windows VPN profile through
native RAS APIs. Windows owns IPsec, credentials, certificates, routes and DNS.
This backend bypasses Wintun and the Go packet stack. An initial
[Windows 10/strongSwan live run](IKEV2_LIVE_VALIDATION.MD) verified IPv4 traffic,
certificate rejection, cancellation and rekey. A follow-up verified internal
IPv6 with profile-owned routes and found DNS leakage in unprotected mode.
Optional native traffic/DNS protection is described below. RRAS remains
unverified. Other platforms are not
implemented yet; see [ADR 0023](adr/0023-native-ikev2-system-vpn.md).

## Prepare the profile

For a Bimeron-owned current-user profile, preview the public settings, then
explicitly apply them in an elevated terminal under the Windows account that
will run the VPN:

```powershell
bimeron.exe ikev2 profile -name 'Corporate VPN' -server vpn.example.com
bimeron.exe ikev2 profile -name 'Corporate VPN' -server vpn.example.com -apply
```

The preview is read-only. Apply creates an IKEv2-only EAP-MSCHAPv2 profile with
required encryption, no automatic redial, both address families and the two
IPv6 profile routes below. It selects IKE AES256/SHA256/DH14 and ESP
AES256/SHA256 without PFS; ask the VPN administrator to confirm server support.
The native backend's existing profile validator verifies the result.

Preparation does not connect, import a CA, configure DNS/WFP protection, or
read/write credentials. Provision the server CA through Windows and perform
initial authentication/save credentials in Windows before using `bimeron run`.
Saving a password alone may not establish the saved EAP identity: the first
successful Windows connection is also required. An `unchanged` preparation
result verifies public settings, not certificate trust or credential readiness.

Repeat apply with matching settings is a no-op. Existing unowned names, machine
profile name collisions, active RAS connections and manually changed owned
settings are refused. There is no adoption, forced overwrite or repair mode.
Preparation also rejects wildcard characters in profile names.
Do not edit/connect profiles concurrently with preparation. Other administrators
can bypass Bimeron's lock; this command is not an OS-wide policy transaction.

To remove an inactive, unchanged profile created by this command:

```powershell
bimeron.exe ikev2 profile -name 'Corporate VPN' -server vpn.example.com -remove
```

Ownership records live in `%LOCALAPPDATA%\Bimeron\ikev2-profiles`, under a
SHA256 filename derived from the case-insensitive profile name. They contain
the profile identity and exact public RAS/EAP-method/IPsec/route settings,
including the native GUID, never passwords or EAP user identity blobs. Preserve
these records; a name prefix alone is not ownership. Changing the server or
policy requires explicit removal/recreation or administrator provisioning.

Creation journals intent before mutation and rolls back only resources created
by that invocation. Mutations wait synchronously for Windows rather than
cancelling a child process during rollback. A crash, ambiguous failure or failed
rollback leaves the journal and refuses subsequent management with a manual
review diagnostic. An administrator must inspect the named profile and record,
resolve any active/modified/foreign resources, and explicitly reconcile them;
the command never automatically takes over an incomplete transaction. This is
separate from `bimeron recover`, which handles runtime protection only.

### Administrator-provisioned profiles

Have the VPN administrator provision and verify a current-user profile under
the account that will run Bimeron. All-user/machine profiles are unsupported.
The profile must use:

- IKEv2 only, with EAP-MSCHAPv2 (EAP type 26).
- A server DNS name matching the expected certificate identity, with Windows
  certificate trust, name and EKU checks enabled.
- Required encryption, IPv4 and IPv6, and default gateways for both families.
- Saved credentials and an EAP identity usable without authentication UI.
- No automatic redial, always-on trigger, scripts, custom dial DLLs,
  prerequisite connections, alternate addresses or custom IKE identities.

Bimeron rejects incompatible settings rather than changing them. Windows
defaults may need administrator adjustment; creating a basic Settings profile
alone does not establish compatibility. Provision certificates and credentials
outside this repository.

### IPv6 routes on Windows 10

The default-gateway flag alone did not install an IPv6 default route on the
validated Windows 10 build 19044. For an administrator-approved test profile,
configure these two routes while disconnected, then reconnect:

```powershell
$name = 'Bimeron IKEv2 Lab' # Replace with your own approved profile name.
Add-VpnConnectionRoute -ConnectionName $name -DestinationPrefix '::/1' -RouteMetric 1
Add-VpnConnectionRoute -ConnectionName $name -DestinationPrefix '8000::/1' -RouteMetric 1
```

The two prefixes cover IPv6 destinations; Windows installs/removes the routes
with the profile connection. Verify the assigned address becomes `Preferred`
and both routes use the VPN interface. Internal IPv6 HTTP/DNS passed on repeated
connections without disabling DAD or modifying physical interfaces. Address
assignment can finish after RAS reports connected; RAS readiness alone does not
prove either address-family's data plane is ready.

Do not add duplicate profile routes. To undo this preparation while disconnected,
use `Remove-VpnConnectionRoute` for each of these exact prefixes. This changes
profile preparation, not Engine's runtime behavior. Public IPv6 egress still
requires an IPv6-capable server and has not been validated in this lab.
See [strongSwan's Windows IPv6 interoperability notes](https://docs.strongswan.org/docs/latest/interop/windowsClients.html#_ipv6)
and [Microsoft's route cmdlet](https://learn.microsoft.com/en-us/powershell/module/vpnclient/add-vpnconnectionroute).

### DNS and traffic exposure

Without native protection, an active connection is not a leak-prevention boundary. A packet capture found
a system DNS query leaving the VM toward its LAN resolver while the VPN was
connected. Default routes do not remove more-specific local routes or prevent
Windows resolver fallback. Ordinary IPv4/IPv6 traffic can leave outside the VPN
before connection and after disconnection. Enable the native protection setting
below when this behavior is unacceptable.

For unprotected sessions, administrators must provide an appropriate Windows DNS policy if private names
must not reach other resolvers. A temporary NRPT rule for the isolated lab's
namespace was tested separately. Unprotected sessions do not install DNS policy.
Namespace rules do not block arbitrary DNS/DoH from applications and do not
provide general traffic protection. See [Windows VPN name resolution](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/vpn/vpn-name-resolution)
and the [capture results](IKEV2_LIVE_VALIDATION.MD).

Profile preparation is an explicit operation outside Start/Stop;
[ADR 0024](adr/0024-windows-ikev2-profile-provisioning.md) records the agreed
architecture. Starting a connection never creates or repairs a profile.

## Configure and run

Copy [the example](../examples/ikev2-windows.conf) to your local profile directory:

```ini
[Profile]
Version = 1
Name = Corporate IKEv2

[IKEv2]
WindowsProfile = Corporate VPN
ServerName = vpn.example.com
KillSwitch = true

[Interface]
Mode = vpn
```

Use the exact existing profile name and its DNS server address. Do not include
passwords, private keys or certificate data. Validate without network changes,
then run in an elevated foreground terminal under the profile's Windows user:

```powershell
bimeron.exe validate profiles/corporate.conf
bimeron.exe run profiles/corporate.conf
```

Ctrl+C cancels startup or disconnects this run's handle. Startup refuses an
existing RAS connection. After a crash, disconnect any remaining tunnel in
Windows before retrying. Bimeron does not adopt stale connections or delete
profiles. Do not edit or independently connect the profile during use.

`connected` means RAS readiness and, when requested, completed protection setup;
it is not a public Internet probe. Windows owns
mobility and rekey. Manual disconnection or loss of the native session ends
the Bimeron session without Engine redial.

## Native traffic and DNS protection

Set `KillSwitch = true` in **`[IKEv2]`**, or set `IKEv2Config.KillSwitch` through
the API. It defaults to false for existing configurations. This enables a full
system-wide IPv4/IPv6 WFP guard and an owned NRPT root policy using the connected
VPN's DNS servers. `[Interface] KillSwitch` remains a packet-only setting and is
rejected for native profiles.

Initial RAS bootstrap, including server-name resolution/authentication, is
unprotected. Wait for `ikev2_protection_active` and `connected`: protected
readiness is not reported until WFP and DNS setup succeed. Missing native
interface/DNS/peer information or conflicting local/effective NRPT policies
causes protected startup to fail. Existing corporate DNS policy is preserved.

The guard permits the VPN interface, loopback, DHCP/NDP and native IKE/IPsec
exchange with the observed VPN peer. It blocks ordinary LAN access and direct
physical-interface DNS, DoT, HTTPS/DoH and other application traffic. Application
DNS/DoH can still use destinations reachable through the VPN. There is no blanket
Bimeron-process exception. A change to a different remote VPN peer can interrupt
connectivity; it is not silently added to firewall permits.

Ctrl+C performs ordered cleanup: disconnect RAS, remove owned DNS policy/flush
cache, then remove WFP protection. Caller cancellation waits for bounded DNS
mutation to finish before rollback. Unexpected disconnection, a process crash or
failed cleanup retains persistent policy and can leave the machine offline.
Starting another session will refuse retained protection. Restore connectivity
explicitly from an elevated terminal after stopping the owner:

```powershell
bimeron.exe recover
```

If a native OS tunnel survived the crash, disconnect that profile explicitly in
Windows as well. Recovery removes only owned policy; it does not adopt or
disconnect another profile. A modified owned DNS rule causes automatic cleanup
to refuse and keep WFP protection until explicit recovery. Protection is not
claimed before activation, during early boot before BFE, or against a privileged
process changing Windows network/security policy. See
[ADR 0025](adr/0025-windows-ikev2-dns-and-traffic-protection.md) and the
[protected live checks](IKEV2_LIVE_VALIDATION.MD).

## Configuration and capabilities

`[IKEv2]` is exclusive with `[AccessKey]`; both IKEv2 fields are required.
Only `Mode = vpn` is allowed in `[Interface]`; omit every other interface
option, including explicit defaults. `[Routing] Default = proxy` is allowed,
but all rules and other defaults are rejected.

- No local SOCKS mode, upstream `check`, IP/domain/application rules,
  DNS/MTU overrides or IPv6 disabling.
- No daemon `start`: it returns `ikev2_requires_foreground_user_session`.
- External packet-engine hosts reject system profiles.
- Session metadata reports `backend: "ikev2"`, `ipv6: "system"` and
  `stats_unavailable: true`; `Stats()` reports `unavailable: true`.
- Read `capabilities.ikev2`; top-level flags retain their packet-backend meaning.
  `ikev2.supported` means compiled support, not runtime/profile availability.
- `ikev2.kill_switch` and `ikev2.dns_protection` describe optional native protection;
  `kill_switch_requested` is intent, with activation reported separately.

Default-route flags alone do not prove absence of DNS or IPv6 leaks. Retained
Bimeron kill-switch protection prevents startup
until explicitly recovered using the existing recovery procedure.

Common codes include `administrator_required`, `ikev2_windows_profile_not_found`,
`ikev2_saved_credentials_required`, `ikev2_saved_eap_identity_required`,
`ikev2_server_identity_mismatch`, `ikev2_existing_ras_connection`,
`ikev2_connect_timeout` and `ikev2_cleanup_failed`. Show a generic failure for
unknown diagnostic codes.

## Isolated live validation and measurements

Use a disposable Windows account/machine and a controlled strongSwan/RRAS server.
Provision credentials outside the repository. The opt-in test changes active
VPN/routes; never enable it on shared CI workers or a working workstation.

```powershell
$env:BIMERON_IKEV2_TEST_CONFIG = 'C:\private\ikev2-test.conf'
go test ./core -run '^TestWindowsIKEv2NativeLifecycle$' -count=1 -v
Remove-Item Env:BIMERON_IKEV2_TEST_CONFIG
```

This verifies readiness and cleanup. Separately test wrong credentials,
untrusted/expired certificates, wrong identity, DNS/IPv6, UDP 500/4500 and NAT-T,
rekey, sleep/wake, network changes, crashes and manual recovery. Record
Windows/server versions, authentication and negotiated algorithms.

Measure at least 20 independent connection cycles: median/p95 Start-to-connected
and Stop-to-cleanup time. Compare with the same profile through Windows. Measure
TCP/UDP throughput against a controlled endpoint inside the VPN with identical
path, packet sizes and duration; record CPU and network conditions. Core counters
cannot measure this backend. Results for the current lab are recorded in the
[live report](IKEV2_LIVE_VALIDATION.MD).

### Reproducible preparation and measurement tests

The preparation test creates/removes uniquely named profiles, tests ownership,
manual modifications and partial rollback, and does not authenticate:

```powershell
$env:BIMERON_IKEV2_PROFILE_TEST_SERVER = 'vpn.example.com'
go test ./internal/systemvpn -run '^TestWindowsIKEv2ProfilePreparation$' -count=1 -v
Remove-Item Env:BIMERON_IKEV2_PROFILE_TEST_SERVER
```

Run the measurement test from an elevated interactive session on the isolated
machine. It uses the same saved profile for 20 native RAS cycles (the native
driver directly, without Engine/protection), 20 Engine
cycles, and 20 protected Engine cycles. Each mode also runs 10-second idle and
TCP/UDP upload/download measurements at a requested 50 Mbit/s, with 1200-byte
UDP payloads. Supply a trusted iperf3 executable and controlled iperf3/HTTP/DNS
servers reachable through the VPN. The HTTP probes expect port 8080 `/health`.

```powershell
$env:BIMERON_IKEV2_TEST_CONFIG = 'C:\private\ikev2-test.conf'
$env:BIMERON_IKEV2_MEASURE_OUTPUT = 'C:\private\ikev2-measurements.json'
$env:BIMERON_IKEV2_IPERF = 'C:\tools\iperf3.exe'
$env:BIMERON_IKEV2_SOAK_SECONDS = '900'
$env:BIMERON_IKEV2_PROBE_ADDRESS = '10.77.55.1'
$env:BIMERON_IKEV2_PROBE_ADDRESS6 = 'fd42:6269:6d65::1'
$env:BIMERON_IKEV2_PROBE_DNS = 'probe.bimeron.test'
go test ./core -run '^TestWindowsIKEv2Measurements$' -count=1 -v -timeout 30m
```

The protected soak probes IPv4/IPv6 HTTP and Windows system DNS every ten
seconds and records CPU/working-set/Go-heap samples. JSON contains endpoint and
machine measurement metadata; keep raw output outside Git. Process CPU includes
the Go test harness; Windows owns the IPsec data plane, so guest-wide and iperf
CPU are recorded separately. Fixed-rate runs are not maximum-throughput claims.
All modes run sequentially in one test process; memory samples include retained
measurement data and Go runtime caches, and are not an isolated CLI memory budget.
Data-plane readiness/retries are recorded separately from RAS connection latency;
the test allows up to 45 seconds for IPv4/IPv6 HTTP readiness before transfers.
Repeated system DNS lookups may use the Windows cache; they do not constitute
uncached DNS-leak checks.
These tests are skipped by default and must not be enabled on shared CI runners.
Windows 11, RRAS, physical sleep and Wi-Fi/Ethernet transitions are deferred in
[issue #66](https://github.com/bimeron/bimeron-core/issues/66).
