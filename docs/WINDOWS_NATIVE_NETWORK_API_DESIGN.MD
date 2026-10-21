# Windows VPN network API migration study

Status: hybrid prototype on `design/windows-native-network-api`. It is not deployed and no startup improvement has been measured.

The prototype uses IP Helper for outbound-path inspection and for tunnel address and capture-route creation/removal. The startup NRPT conflict/recovery check and tunnel interface, DNS, NRPT, and DNS-cache settings still use PowerShell. It retains WFP when network cleanup fails. The committed `perf/windows-vpn-startup` timing work was merged into this branch without changing that branch.

Windows unit tests and a read-only comparison with PowerShell on one connected host have passed. Native address/route writes, cleanup, crash recovery, DHCP interaction, and repeated connection timing have **not** been validated on an isolated Windows host. Do not install this prototype into the active service until those checks pass.

## Scope and baseline

The reported startup time is about 8 seconds, including approximately 4.1 seconds in `manage.ps1 setup` and 1.7 seconds in `inspect`. These are observations for one environment, not an API performance estimate. Measure cold and warm runs, individual commands, adapter creation, transport checks, WFP installation, and time to `connected` before selecting a migration.

On October 21, the installed service (revision `14ba35e`) exposed two complete, read-only event traces. The intervals from `network_inspect` to `connected` were 5.848 and 7.746 seconds. Their `network_setup` intervals were 2.744 and 4.080 seconds, while the sum of the six in-script setup timings was 1.075 and 1.025 seconds. The respective 1.669 and 3.055 second gaps include PowerShell process startup, module initialization, adapter lookup before the script stopwatch, serialization, and any other unmeasured work. The event trace does not separate those costs. The two startup inspections took 1.707 and 2.216 seconds; key resolution 0.330 and 0.355 seconds; transport checks 0.417 and 0.416 seconds; Wintun creation 0.651 and 0.679 seconds. These are two observations, not a performance comparison or evidence of a stable improvement.

The current flow holds `Global\BimeronCoreConnect`, checks for retained kill-switch filters, recovers stale owned NRPT rules during startup inspection, selects a physical outbound path, prepares transport, opens Wintun, installs addresses/routes/DNS/NRPT, and finally arms WFP. A session owns the adapter, packet stack, routes, NRPT rule, and WFP guard. A crash may leave persistent WFP and NRPT state. Explicit `recover` removes owned NRPT and WFP objects. The code and tests at the time of this study are the reference for exact behavior; the startup optimization branch is active independently.

## Candidate API mapping

| Operation | Candidate API | Compatibility condition |
| --- | --- | --- |
| Create/open tunnel | Keep the existing Wintun library and `tun.Open`; map its adapter to GUID/LUID with `ConvertInterfaceIndexToLuid` and inspect with `GetIfEntry2` or `GetIfTable2`. | Confirm adapter identity before deleting any object. Interface index and name alone may be reused. |
| Discover physical egress | `GetIfTable2`, `GetIpForwardTable2`, `GetIpInterfaceEntry`, `GetUnicastIpAddressTable`, and `GetAdaptersAddresses` for physical DNS. | Reproduce `Get-NetAdapter -Physical`, Up state, active default routes, gateway selection, route plus interface metric, tie breaks, preferred addresses, and optional IPv6. Compare behavior on real adapters. |
| Configure IPv4/IPv6 interface | Read each `MIB_IPINTERFACE_ROW` with `GetIpInterfaceEntry`, then use `SetIpInterfaceEntry` for MTU and metric. | Preserve other fields. Verify equivalence of IPv4 DHCP disabling; use the documented `MSFT_NetIPInterface` CIM provider if IP Helper does not provide it. |
| Add addresses | `InitializeUnicastIpAddressEntry`, `CreateUnicastIpAddressEntry`, `GetUnicastIpAddressEntry`, `DeleteUnicastIpAddressEntry`. | Preserve `198.18.0.1/30` and `fd69:726f:7574::1/128`. Check duplicate-address detection and address readiness. |
| Add capture routes | `InitializeIpForwardEntry`, `CreateIpForwardEntry2`, `GetIpForwardEntry2`, `DeleteIpForwardEntry2`. | Keep active-only `0.0.0.0/1`, `128.0.0.0/1`, `::/1`, and `8000::/1`; leave physical defaults intact. Do not delete a route solely because its prefix and index match. |
| Configure adapter DNS | `GetInterfaceDnsSettings` and `SetInterfaceDnsSettings` with the required setting flags. | Require a supported Windows build; verify `198.18.0.2` and disabled address registration against current cmdlet behavior. |
| Manage NRPT | Documented `PS_DnsClientNrptRule` Get/Add/Remove methods under `Root\Microsoft\Windows\Dns`, invoked through MI/COM. | Keep namespace `.`, server `198.18.0.2`, and the `BimeronCore:<session>` comment. Reject conflicting foreign policy. Do not edit the NRPT registry directly. |
| Flush DNS cache | `MSFT_DNSClientCache.Clear` through CIM. | Verify that it matches `Clear-DnsClientCache` after NRPT changes and cleanup. |
| Kill switch | Keep existing persistent WFP provider, sublayer, filters, and transactions. | Preserve startup refusal when old protection exists and kill switch is disabled. Retain old filters until a replacement is ready. |

IP Helper has no single transaction spanning addresses, routes, DNS, and NRPT. WFP transactions cover WFP objects only. NRPT has a documented CIM provider but no equivalent simple Win32 NRPT rule API. DHCP and DNS registration behavior also need a CIM fallback if the chosen Win32 calls do not reproduce the cmdlets. Editing undocumented registry state or calling undocumented DNS exports is outside this proposal.

## Ordering and concurrency

Read-only physical route discovery, adapter-name validation, and initial NRPT enumeration can run concurrently after taking the session lock. Stale owned NRPT removal and cache clearing must finish before concluding that no conflicting DNS policy exists. Revalidate the selected physical interface before transport use because enumeration is not an atomic network snapshot.

After opening the adapter, IPv4 and IPv6 interface/address setup can be explored in parallel by family. Each family's capture routes depend on its address being ready. Install NRPT only when the tunnel DNS endpoint and routes are ready; arm WFP after network setup and transport validation. Parallel writes make failure handling harder and should be added only if measurements justify them. During teardown, remove owned NRPT and flush DNS before removing owned capture routes and closing the tunnel.

## Ownership, rollback, and failure safety

Retain the named mutex and a random session tag. Before the first mutation, durably record the adapter GUID/LUID, session tag, intended exact address and route keys, and previous interface/DNS settings that must be restored. Update the journal after each successful step; remove it only after verified cleanup. A startup or explicit recovery pass must compare recorded identity and current objects, tolerate already-removed objects, and leave ambiguous or foreign objects untouched. Exact route keys still cannot prove ownership if another actor replaced the route; compare the installed row with the journal and fail visibly on ambiguity.

Rollback needs an independent bounded context after cancellation and should attempt every safe inverse operation, reporting all failures. Never clear the journal on partial failure. Keep WFP protection when cleanup of NRPT or routes is unconfirmed; the current cleanup action order should be reviewed because it can close the WFP guard after a network-cleanup error. Explicit recovery removes only verified Bimeron resources. For a crash with kill switch off, do not assume capture routes vanished with the adapter; inspect and reconcile journaled state. A crash with kill switch on must retain persistent WFP filters until replacement or explicit recovery. Protection is not claimed before the `kill_switch_active` event, while another administrator changes policy, or during early boot before BFE starts.

## Options and decision gate

1. **Optimize the existing PowerShell path.** Time cmdlets individually, avoid repeated enumeration and processes where safe, and retain tested policy semantics. Lowest implementation risk; process startup and module initialization remain.
2. **Move read-only inspection to IP Helper first.** This also benefits periodic `observe`. Compare selected paths against PowerShell on real Windows machines. Moderate implementation scope; no write or rollback change yet.
3. **Move setup/cleanup incrementally, retaining CIM or a narrow PowerShell path for NRPT.** Requires durable ownership and fault-injection tests. A full MI/COM implementation removes `powershell.exe` but adds ABI, provider, and OS-version risk.

Do not project seconds saved from the reported totals. Accept migration only if repeated end-to-end measurements show a material improvement without regression in DNS, direct routing, recovery, or kill-switch safety. An ADR should record the minimum Windows version, NRPT access choice, recovery-journal format, alternatives, and test results before a write-path migration.

## Windows validation plan

1. Measure at least several dozen cold and warm runs on the same OS image and build. Instrument `executeScript` around process start/exit and instrument the script from its first statement, including adapter lookup and module loading where observable. Record median and tail latency for `inspect`, `setup`, each cmdlet group, Wintun, WFP, and total startup. Correlate every stage by attempt/session ID. Do not run simultaneous VPN managers during timing.
2. Compare a read-only native snapshot with the script on Ethernet, Wi-Fi, dual-homed hosts, IPv4-only and dual-stack networks, a competing virtual adapter/VPN, and during route or DHCP changes.
3. In disposable Windows VMs, verify addresses, DAD, route metrics, DNS resolution, NRPT effective policy, tunneled and `direct` traffic, and IPv6 behavior. Check supported Windows builds separately.
4. Inject failure and cancellation after every setup and cleanup step. Verify preservation of foreign rules/routes, idempotent recovery, adapter index reuse, a conflicting NRPT rule, and DNS cache behavior.
5. Repeat Ctrl+C, forced termination, service restart, reboot, offline `recover`, and failed-cleanup scenarios. After `kill_switch_active`, direct external traffic must remain blocked except explicit `direct` policy. If cleanup is incomplete, WFP must remain installed and the error must be visible.

Current PowerShell tests use mocked cmdlets and cannot validate OS behavior. Add focused pure logic tests for route selection and ownership, then run privileged integration and crash tests only on disposable Windows systems. Keep CI cross-build and unit tests separate from privileged network tests.

## Primary references

- [IP Helper route table](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipforwardtable2), [interface settings](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setipinterfaceentry), [unicast address creation](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createunicastipaddressentry)
- [Adapter address enumeration](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses) and [interface DNS settings](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setinterfacednssettings)
- [NRPT CIM provider](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/dnsclientpsprov/ps-dnsclientnrptrule), [MI method invocation](https://learn.microsoft.com/en-us/windows/win32/api/mi/nf-mi-mi_session_invoke), and [DNS client cache Clear method](https://learn.microsoft.com/en-us/windows/win32/fwp/wmi/dnsclientcimprov/clear-msft-dnsclientcache)
