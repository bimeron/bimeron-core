# Bimeron Core diagnostics

```cmd
bin\bimeron-doctor.exe doctor
bin\bimeron-doctor.exe doctor -output doctor-report.json
```

The command only reads state: it does not start a VPN, stop the service, change
routes, DNS, or firewall settings, or send external network requests.
It works with the current service without updating the installed EXE.
The regular updated CLI also supports `bimeron.exe doctor`.

The JSON includes platform and architecture, the diagnostic CLI's Go version and
Git revision (not the installed service's), session state, statistics, and up to
20 recent events. If the daemon restarts, the report does not mix statistics from
different instances. Other checks continue when no daemon is available.

Windows checks include service state, the number of tunnel adapters in the
Bimeron subnet, their Up state, the number of IPv4/IPv6 capture routes, and owned
NRPT rules, including rules targeting tunnel DNS. The WFP check reports whether
owned filters exist and requires an administrator CMD. Without elevation, it
returns requires_elevation rather than incorrectly concluding there is no
protection. Failure to read system settings is reported as
unavailable_or_permission_denied.

Existing settings do not guarantee Outline availability or effective protection.
This is a snapshot of separate checks, not an atomic check of the entire OS;
values may change during a network transition. The command does not know the
current profile rules and does not treat a missing kill switch as an error:
the profile may not enable it. Linux currently provides general information,
IPC, events, and statistics; system-route, DNS, and firewall inspection is marked
as unimplemented.

macOS additionally reports the number of active network services, services using
Bimeron DNS, IPv4/IPv6 capture routes, and effective DNS state:
`tunnel`, `other`, or `unavailable`. This read-only check does not expose
service names, interface names, or DNS addresses. Routes and DNS do not prove
transport availability, but help distinguish an active Bimeron configuration from
a conflict with another DNS provider.

The `dns_provider_conflict` check compares Bimeron DNS settings in active network
services with effective macOS DNS. Results: `detected`, `not_detected`,
`unavailable`, and `not_applicable`. `detected` means at least one active
service is configured for Bimeron DNS, but the first system resolver without a
domain restriction uses a different address set. The provider's name and
addresses are intentionally omitted.

Reports contain no keys, URLs, passwords, IP addresses, domains, profile paths,
adapter names, or free-form event text. Machine codes are retained; invalid codes
are replaced with redacted_error. Statistics and event times still describe
session activity, so review reports before publishing.
The output file must be new; existing files are not overwritten. Unix mode is
0600; Windows access follows the directory's inherited ACL.

If Windows Defender Controlled Folder Access blocks the EXE from writing to
Documents, the system error may say "The system cannot find the file specified".
Do not disable protection. In a regular CMD, redirect output through the shell:
`dist\windows-amd64\bimeron.exe doctor > doctor-report.json`. This redirection overwrites an
existing file, so choose the filename deliberately.

A historical read-only check of a connected session reported connected, service
running, one active tunnel, two IPv4 and two IPv6 routes, and an owned DNS rule.
Traffic counters were nonzero. Without elevation, WFP returned requires_elevation.
To check the disconnected state, the user must stop the VPN/service and rerun
doctor; the command does not do this itself.

