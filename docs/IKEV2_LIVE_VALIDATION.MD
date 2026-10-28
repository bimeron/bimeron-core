# Windows IKEv2 live validation, October 28, 2026

These results cover an isolated Hyper-V Windows 10 Enterprise Evaluation VM
(build 19044) and Ubuntu 22.04/strongSwan 5.9.5. They do not establish support
for every Windows build, enterprise policy or server. The profile used a test
CA, EAP-MSCHAPv2, IKE AES256/SHA256/DH14 and ESP AES256/SHA256.

Initial native Windows RAS login provisioned the saved EAP identity. The host's
trust store and network settings were not modified. VM preparation included a
checkpoint and baseline route/DNS records. Credentials and raw results remain
outside the repository.

## Passed checks

- Native Windows RAS connected and reached an HTTP endpoint inside the VPN.
- Bimeron connected with the same profile and saved credentials. IPv4 HTTP,
  explicit tunnel DNS A/AAAA queries and system DNS resolution succeeded.
- An incorrect password was rejected by native RAS; valid credentials connected
  again afterward.
- Bimeron rejected wrong-name, expired and untrusted server certificates. None
  reached `connected`; restoring the valid certificate restored success.
- Twenty successive Bimeron connect/stop cycles reached `connected` and then
  `disconnected`. Ten additional starts were cancelled at varying early times;
  all completed cleanup without a cleanup error.
- CHILD_SA and IKE_SA rekey completed; IPv4 HTTP still worked afterward.
- A three-second guest Ethernet interruption preserved/recovered the native
  connection, with IPv4 HTTP working afterward.
- Saving/resuming the VM preserved/recovered IPv4 HTTP through the VPN.
- Manual Windows disconnection ended the Engine session after one attempt,
  without automatic redial.
- Killing the owning process left the OS tunnel connected. A subsequent start
  refused to adopt it with `ikev2_existing_ras_connection`; explicit Windows
  disconnection recovered the test profile.
- The opt-in `TestWindowsIKEv2NativeLifecycle` passed in the interactive VM.
- Native statistics explicitly reported unavailability.
- After cleanup, guest routes and DNS matched their pre-test snapshots.

For twenty positive cycles, Start-to-connected median was 3110.5 ms and p95
was 3167 ms. Across all thirty positive/cancelled cycles, Stop-to-cleanup median
was 21.5 ms and p95 was 56 ms. These are timings from one small VM/network path,
not a throughput benchmark or a native-client comparison.

## Startup race found and fixed

The first Bimeron run exposed an asynchronous RAS race: `RasDial` returned a
handle before its port existed. Immediate status queries returned
`ERROR_INVALID_HANDLE`; premature hangup could return `ERROR_NO_CONNECTION`.
The old implementation treated these as terminal failures and reported a
cleanup error even though the native dial could proceed.

The backend now uses one RASDIALFUNC2 callback with per-attempt IDs. Callback
state distinguishes an unallocated port from a failed/disconnected connection.
Cancellation retries hangup while allocation is pending, within the independent
cleanup deadline. EAP memory and callback tracking remain owned until handle
invalidation confirms cleanup. Late callbacks for released attempts are ignored.
Unit/race tests cover these transitions alongside the repeated live checks.

## Initial IPv6 limitation

The server assigned an IPv6 address and negotiated IPv6 selectors. On this
Windows image, the VPN address remained tentative and no IPv6 default route
appeared despite the profile's enabled IPv6/default-gateway flags. Unassisted
IPv6 HTTP/DNS therefore failed.

Diagnostic IPv6 HTTP/DNS succeeded only after disabling DAD on the dedicated
VPN interface and adding a temporary active-store `::/0` route. The server also
needed IPv6 payload processing and a protected return route for its private
client pool over the IPv4 IPsec transport. This proves that the internal IPv6
data plane can work, not automatic IPv6 readiness. Do not generalize these
manual diagnostic changes into a production workaround.

There is no public IPv6 uplink on the test server. External IPv6 and absence of
DNS/IP leaks have not been established.

## IPv6 and leak follow-up

The follow-up used the same Windows 10 image and server. The assigned IPv6
address became `Preferred` with the VPN interface's normal `DadTransmits = 3`.
The initial observation that disabling DAD was necessary was not reproduced;
no production DAD workaround is justified. The reproducible routing problem was
the absence of an IPv6 default route despite the profile's gateway flag.

With the lab profile disconnected, two persistent *profile* routes were added
through `Add-VpnConnectionRoute`: `::/1` and `8000::/1`, each with metric 1.
Windows installed them on connection and removed their active instances on
disconnection. Repeated connections then reached the internal IPv6 HTTP endpoint
and queried the tunnel DNS server over IPv6 without temporary active-store
routes, DAD changes or physical-interface changes. This addresses the validated
build's setup requirement; Bimeron still does not provision or repair profiles.
The server still has no public IPv6 uplink.

### Capture method

Guest-NIC-only captures were empty and discarded as evidence. A second attempt
restricted to the VM's Hyper-V component did not reliably show positive-control
traffic. The final capture used host Packet Monitor across all components,
filtered by the test VM's MAC address. This exposed clear packets at the VM's
network boundary without collecting unrelated workstation traffic. The full
capture held 6,040 packet observations with no reported lost events. Packets
appear at multiple stack components, so these are not unique wire-packet counts.

The test generated tagged UDP payloads to documentation IPv4/IPv6 destinations,
LAN UDP traffic and unique uncached system DNS questions. A temporary IPv6
address, synthetic gateway neighbor and default route existed only inside the
guest so IPv6 could attempt a physical-interface path. The synthetic path
establishes packet emission, not delivery or public IPv6 connectivity. The host's
addresses/routes, trust store and DNS configuration were not changed.

Stages included disconnected baseline, startup, connected state, profile-route
comparison, stop, reconnect, manual disconnect and an immediate stop request.
The immediate-stop harness waits for readiness before processing its stop flag;
it is not evidence of cancellation during native startup. The earlier ten
startup-cancellation tests remain the cancellation evidence.

| Check | Observation |
| --- | --- |
| Connected IPv6 with both profile routes | Internal HTTP and IPv6 DNS succeeded on both checked connections. |
| Connected system DNS without an explicit namespace policy | A tagged query was observed in cleartext toward the LAN DNS server. DNS leakage is confirmed. |
| Temporary NRPT rule for `.bimeron.test` using the tunnel DNS server | A new tagged lookup was not observed on the LAN; the known probe name resolved to its internal A/AAAA addresses. |
| UDP canaries during the stable connected stage with prepared routes | No matching clear IPv4/IPv6 canary was observed; NAT-T traffic was present. This bounded sample is not a general leak-prevention proof. |
| Manual disconnection | Tagged IPv4 and synthetic IPv6 packets were observed outside IPsec afterward. |
| Local routes and connection transitions | LAN bypass traffic was observed. Default routing does not enforce traffic blocking across every route or lifecycle stage. |

The DNS rule was an owned temporary diagnostic rule, removed by its exact
identifier before cleanup. It does not establish application DNS/DoH protection,
automatic session-scoped policy or protection of other namespaces. Windows
administrators need an appropriate DNS policy for confidential namespaces;
Bimeron neither installs one nor advertises DNS-leak protection. Automatic DNS
isolation or a native kill switch would require a separate policy/ownership
design and failure/crash testing. No existing protection guarantee was expanded.

After the final run, the VPN was disconnected, temporary guest IPv6 resources,
NRPT rule and scheduled task were removed, and route/DNS snapshots matched the
baseline exactly. The two approved profile routes remain for future connections.
Packet Monitor was stopped and its owned host filter removed. Raw captures,
harnesses and timestamped JSON remain outside Git in the private lab directory.

To reproduce, use a disposable VM, a unique canary per stage and a positive
cleartext control after disconnection. Capture its MAC with `pktmon filter add`,
then `pktmon start --capture --comp all --pkt-size 0`. Record state transitions,
generate traffic with the system resolver as well as explicit tunnel DNS, stop
capture and convert with `pktmon etl2pcap`. Analyze queries/payloads outside NAT-T,
correlating timestamps with actual connection state. Reject empty captures and
do not treat duplicated observations or an empty negative sample as proof.

References: [strongSwan Windows IPv6 notes](https://docs.strongswan.org/docs/latest/interop/windowsClients.html#_ipv6),
[Windows VPN name resolution](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/vpn/vpn-name-resolution),
and [Windows VPN routing](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/vpn/vpn-routing).

## Remaining checks

Throughput/CPU measurements, broader protection/mobility coverage, actual laptop sleep
and physical network changes, long-running mobility, RRAS and other Windows
builds/policies remain separate validation. VM save/resume is not a substitute
for physical power-management testing. See [the guide](IKEV2.MD) for the procedure.

## Protected-mode follow-up

The observations above describe unprotected configurations and motivated
[ADR 0025](adr/0025-windows-ikev2-dns-and-traffic-protection.md). The same isolated
Windows 10/strongSwan lab was then checked with `[IKEv2] KillSwitch = true`.
This optional mode adds persistent WFP traffic protection and a tagged NRPT root
policy. Older configurations without the setting retain their prior behavior.

The first protected attempt exposed a missing two-byte alignment gap before
`RASCONNSTATUS`'s tunnel endpoints. The total structure size was already correct,
but the previously unused endpoint offsets were wrong. Offsets 564/584 are now
checked explicitly. Another attempt showed that native RAS authorizes a System
IP-in-IP carrier before IPsec wrapping; a peer-scoped carrier exception restored
the data plane. No clear IP-in-IP carrier was observed at the captured boundary.

The protection capture used all host components filtered by the VM MAC, with
uncached tagged DNS, physically bound IPv4/IPv6 UDP and physical-interface TCP
attempts to ports 53, 853 and 443. One UDP socket was opened before protection
and reused afterward. A temporary documentation-prefix IPv6 source/default
gateway existed only in the guest. This is an egress test, not public IPv6
delivery. The capture held 19,773 duplicated stack observations with no reported
lost events; it is not a count of unique wire packets.

| Scenario | Verified result |
| --- | --- |
| Protected connected state | Internal IPv4/IPv6 HTTP and system DNS A/AAAA resolution succeeded. |
| Physically bound new and pre-existing UDP | Tagged cleartext was visible before protection and after recovery, absent while protected. |
| Physical TCP DNS, DoT and HTTPS | SYNs were visible in baseline/recovered stages, absent in protected stages. |
| System DNS | Tagged queries reached the LAN resolver in baseline/recovered stages, not during connected/retained stages. |
| Manual Windows disconnection | Engine ended with `ikev2_protection_retained_run_recover`; the owned DNS rule and persistent filtering remained. Direct IPv4/IPv6 canaries stayed absent. |
| Restart with retained policy | Start refused with `ikev2_existing_kill_switch_requires_recovery`. |
| Owner process termination | The native OS tunnel survived. After explicitly disconnecting it, DNS policy remained and direct canaries stayed absent until recovery. |
| Explicit recovery | Owned NRPT/WFP policy was removed; positive direct-traffic controls appeared again. |
| Graceful Stop | RAS disconnected, the owned DNS policy was removed and normal direct UDP returned. |
| Modified owned DNS policy | Stop returned `ikev2_dns_cleanup_failed_run_recover`, preserved the modified rule and retained all 84 native WFP filters. Explicit recovery removed the owned policy. |
| Foreign DNS policy | Protected startup refused before connection; the foreign rule remained unchanged. |
| Cancellation during DNS installation | Two attempts cancelled at the DNS-protection stage, immediately and after 200 ms, both finished `disconnected` without cleanup errors. |
| Repository opt-in lifecycle test | `TestWindowsIKEv2NativeLifecycle` passed with protected configuration in the interactive VM (1.92 s). |

The cancellation checks exercised the bounded DNS mutation/rollback path rather
than just pre-dial cancellation. Socket Send success alone was not used as proof
of egress: transport-layer WFP drops can occur after a send is accepted. The
conclusions rely on capture controls and persisted policy inspection.

The final lab VPN is disconnected. Temporary guest routes/addresses, test DNS
rules and scheduled tasks were removed. Route/DNS snapshots matched baseline;
Packet Monitor was stopped and its owned filter removed. Raw evidence remains
outside Git. No host firewall policy, network configuration, certificate store,
server authentication material or unrelated RAS profile was changed.

The protection boundary starts after native bootstrap and successful policy
installation. DHCP/NDP, loopback and required native peer traffic are intentional
exceptions. The checks do not establish protection during bootstrap/early boot,
against privileged policy changes, across remote-peer changes, on other Windows
builds or with RRAS. Public IPv6, physical mobility and long-running behavior
still need the remaining validation matrix.
