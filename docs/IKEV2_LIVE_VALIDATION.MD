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

## IPv6 limitation

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

## Remaining checks

Throughput/CPU measurements, packet-capture leak checks, actual laptop sleep
and physical network changes, long-running mobility, RRAS and other Windows
builds/policies remain separate validation. VM save/resume is not a substitute
for physical power-management testing. See [the guide](IKEV2.MD) for the procedure.
