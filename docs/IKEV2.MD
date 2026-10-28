# Experimental Windows IKEv2/IPsec

Bimeron controls a pre-provisioned current-user Windows VPN profile through
native RAS APIs. Windows owns IPsec, credentials, certificates, routes and DNS.
This backend bypasses Wintun and the Go packet stack. An initial
[Windows 10/strongSwan live run](IKEV2_LIVE_VALIDATION.MD) verified IPv4 traffic,
certificate rejection, cancellation and rekey. A follow-up verified internal
IPv6 with profile-owned routes and found DNS leakage to the LAN resolver.
RRAS remains unverified; leak prevention is not provided. Other platforms are not
implemented yet; see [ADR 0023](adr/0023-native-ikev2-system-vpn.md).

## Prepare the profile

Have the VPN administrator provision and verify a current-user profile under
the account that will run Bimeron. All-user/machine profiles are unsupported.
The profile must use:

- IKEv2 only, with EAP-MSCHAPv2 (EAP type 26).
- A DNS server address matching the expected certificate identity, with Windows
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

An active connection is not a leak-prevention boundary. A packet capture found
a system DNS query leaving the VM toward its LAN resolver while the VPN was
connected. Default routes do not remove more-specific local routes or prevent
Windows resolver fallback. Ordinary IPv4/IPv6 traffic can leave outside the VPN
before connection and after disconnection. There is no native-backend kill switch.

Administrators must provide an appropriate Windows DNS policy if private names
must not reach other resolvers. A temporary NRPT rule for the isolated lab's
namespace was tested separately; it is not installed or managed by Bimeron.
Namespace rules do not block arbitrary DNS/DoH from applications and do not
provide general traffic protection. See [Windows VPN name resolution](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/vpn/vpn-name-resolution)
and the [capture results](IKEV2_LIVE_VALIDATION.MD).

Profile preparation will remain an explicit operation outside Start/Stop;
[ADR 0024](adr/0024-windows-ikev2-profile-provisioning.md) records the agreed
architecture. The preparation command is not implemented yet.

## Configure and run

Copy [the example](../examples/ikev2-windows.conf) to your local profile directory:

```ini
[Profile]
Version = 1
Name = Corporate IKEv2

[IKEv2]
WindowsProfile = Corporate VPN
ServerName = vpn.example.com

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

`connected` means RAS readiness, not a public Internet probe. Windows owns
mobility and rekey. Manual disconnection or loss of the native session ends
the Bimeron session without Engine redial.

## Configuration and capabilities

`[IKEv2]` is exclusive with `[AccessKey]`; both IKEv2 fields are required.
Only `Mode = vpn` is allowed in `[Interface]`; omit every other interface
option, including explicit defaults. `[Routing] Default = proxy` is allowed,
but all rules and other defaults are rejected.

- No local SOCKS mode, upstream `check`, IP/domain/application rules, core kill
  switch, DNS/MTU overrides or IPv6 disabling.
- No daemon `start`: it returns `ikev2_requires_foreground_user_session`.
- External packet-engine hosts reject system profiles.
- Session metadata reports `backend: "ikev2"`, `ipv6: "system"` and
  `stats_unavailable: true`; `Stats()` reports `unavailable: true`.
- Read `capabilities.ikev2`; top-level flags retain their packet-backend meaning.
  `ikev2.supported` means compiled support, not runtime/profile availability.

Default-route flags do not prove absence of DNS or IPv6 leaks. No leak-prevention
guarantee is advertised. Retained Bimeron kill-switch protection prevents startup
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
cannot measure this backend. No performance results are claimed before these runs.
