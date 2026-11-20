# Bimeron Core system service

## Linux (systemd)

The same Linux binary serves as CLI and daemon. Installation copies it to
`/usr/local/lib/bimeron/bimeron-core` and creates
`/etc/systemd/system/bimeron-core.service`:

```sh
sudo ./bimeron-linux-amd64 service install -automatic
sudo ./bimeron-linux-amd64 service start
./bimeron-linux-amd64 service status
```

Without `-automatic`, the unit is not enabled at boot. Neither installation nor
service startup connects the VPN. The control owner comes from
`SUDO_UID`/`PKEXEC_UID`; a GUI explicitly passes `-owner <uid>`.
The root daemon creates `/run/bimeron/control.sock` with mode `0600`, owned by
that UID, and checks every client's peer UID. Other local users cannot control
the VPN.

Run updates through the trusted core bundled in the installed GUI package. Pass
the downloaded executable's absolute path, expected version, and SHA-256 from a
verified release manifest. The source must be a regular file of at most
256 MiB, not a symlink; FIFOs and devices are refused without blocking. The
updater copies it as data into the protected directory as a root-only (0600)
file, replacing a staged copy left by an interrupted update, and checks staged
ELF architecture, Go identity, and digest before making it executable and
stopping the old service. It then requires IPC `hello` with the expected version
and protocol after restart. On failure it restores the old binary and prior
running state, preserving the owner and automatic-start setting:

```sh
sudo /usr/bin/bimeron-core service update -source /absolute/path/to/downloaded/bimeron -version 0.1.0-beta.2 -sha256 <executable-sha256>
sudo ./bimeron-linux-amd64 service stop
sudo ./bimeron-linux-amd64 service uninstall
```

Uninstallation is allowed only after stopping. A desktop GUI runs administrative
commands through polkit/pkexec; ordinary IPC commands work without root.

## Windows (SCM)

The BimeronCore service supports installation, startup, shutdown, status, and
uninstallation. The binary and Wintun are copied to Program Files/Bimeron Core
with an ACL permitting writes only by SYSTEM and Administrators.
The service runs as LocalSystem. The control pipe
`\\.\pipe\Bimeron.Core.Service` is accessible to SYSTEM and the installing
user's SID. Install from an elevated console under your own account.
If you elevate using another administrator account, that account becomes the
control owner.

From an administrator CMD in the project directory:

```cmd
dist\windows-amd64\bimeron.exe service install
dist\windows-amd64\bimeron.exe service start
dist\windows-amd64\bimeron.exe service status
```

`service status` only reads SCM state and does not require elevation.
Other `service` commands require Administrator.

For automatic startup when Windows boots, install using
`dist\windows-amd64\bimeron.exe service install -automatic`. Startup is manual by default.
Installation does not start the service. Starting the service does not connect
the VPN. Keys and profiles are not copied to Program Files or retained by the
service. The only session data the service keeps is the `profile_id` (a hash of
the profile path) of a session whose kill switch protection was kept across an
update, in a file readable only by SYSTEM and Administrators (see Updating).

After startup, in a regular CMD under the same user:

```cmd
dist\windows-amd64\bimeron.exe start profiles\main.conf
dist\windows-amd64\bimeron.exe watch
dist\windows-amd64\bimeron.exe stats
dist\windows-amd64\bimeron.exe stop
```

start passes an absolute path. SYSTEM must be able to read the configuration and
key; user network drives and EFS files may be inaccessible.
start/stop control the VPN; service start/stop control the service process.
shutdown also disconnects the VPN and exits the service. The CLI prefers the
service, then a regular daemon; access denial by the service does not cause
fallback to another daemon. Do not run a daemon alongside the service: their
control channels differ, and the machine-wide lock still permits only one system
VPN session. run retains console mode and requires elevation.

SCM stop/Windows shutdown cancels the session and waits for cleanup; while waiting,
the service reports StopPending with progress. Cleanup failure is recorded as a
service error. The Application event log, source BimeronCore, contains only generic
readiness/error messages without keys. After a crash, SCM restarts the service
after 5 and 15 seconds, then stops retrying; the VPN does not reconnect
automatically. With the kill switch enabled, protection and the owned DNS rule
persist after a crash until explicit `recover`, while active tunnel routes
disappear with the process.

Stop and uninstall as administrator:

```cmd
dist\windows-amd64\bimeron.exe service stop
dist\windows-amd64\bimeron.exe service uninstall
```

Uninstallation is allowed only after stopping; it removes the service, event
source, and three installed files. If uninstallation is interrupted after the
service registration is removed, run it again to remove the remaining event
source and files; it reports every cleanup step that fails. When no service is
registered, installation also replaces files and the event source left by an
interrupted installation or uninstallation. The adjacent wintun.dll must match the EXE's
architecture. WINTUN-LICENSE.txt is also required. Installation verifies the
copied wintun.dll and WINTUN-LICENSE.txt against the SHA-256 digests of the
Wintun 0.14.1 release pinned in the core and refuses other files. Profiles and keys remain in place.

## Updating

From an elevated CMD, run the trusted core bundled in the installed GUI package:

```cmd
"C:\Program Files\Bimeron\bimeron-core.exe" service update -source C:\absolute\path\to\downloaded\bimeron.exe -version 0.1.0-beta.2 -sha256 <executable-sha256>
```

The command checks the installed path and owner. The source must be a regular
file of at most 256 MiB, given as a plain drive-letter path on a fixed local
drive. Removable drives, mapped network drives, UNC paths, device paths and
`\\?\` paths are refused; a path longer than 260 characters works without the
`\\?\` prefix. The drive type is the one the volume reports: a RAM disk that
reports `DRIVE_RAMDISK` is refused, but one that reports a fixed drive, as
common RAM disk drivers do, is accepted. The updater opens the file without
following a symbolic link or junction at the final path component and refuses
it if the opened file resolves to a network share or to a volume that is not a
fixed drive, for example through a linked directory or a removable volume
mounted in a folder. The volume is taken from the opened file; a volume
without a volume GUID path is refused. AF_UNIX sockets and WSL FIFOs and
device files are refused as non-regular files. Other reparse points, such as
OneDrive placeholders, are read as data; keep the file fully available
locally, because its digest is checked only after staging.

The opened file is checked after opening. If a directory in the source path
links to a network share, opening the source already contacts that server,
with the elevated updater's credentials, before the updater refuses the file.
Extract the update to a local directory whose path contains no links.

The updater first copies the downloaded EXE into the protected directory with
an ACL limited to SYSTEM and Administrators, replacing a staged copy left by an
interrupted update, and checks the staged copy's digest, Go identity, and PE
architecture. Only then does the staged file take the directory's inherited
ACL; the command stops the service, waits for cleanup, and replaces the EXE. If
the service was running, it restarts, but the VPN remains disconnected;
explicitly call start <config>. If it was stopped, it stays stopped.

With `-keep-kill-switch`, the command asks the running service, just before
stopping it, to keep kill switch protection on that stop
([ADR 0041](adr/0041-kill-switch-across-service-updates.md)). The service then
leaves the filters installed, records the held session's `profile_id` in
`kill-switch-update-hold.json` in its installation directory, and exits
cleanly; the updated service reports the protection as residual with
`ResidualReason: "update"`. The command prints whether protection was kept.
Start the same profile again to resume the VPN; until then, traffic stays
blocked, also across a reboot. An installed service without
`kill_switch_update_hold`, or one that cannot be reached, releases protection
as before, and the command prints a warning. If the updated service fails its
check, the command asks the running replacement for a fresh hold before the rollback stop, even if the original service had no protection. If preparation fails, rollback stops before sending the stop request and retains the backup. A verified update hold also survives a second opt-in update. Linux
rejects the flag. Uninstall removes the record.
The owner, automatic-start setting, and recovery settings are preserved.
Wintun DLL and its license are not replaced: this updates the core, not the driver.

If replacement or startup fails, the old EXE is restored; a previously running
service restarts with the old EXE without automatically connecting the VPN. A
running service also must answer IPC `hello` with the expected core version and
protocol before the update is considered successful.
If stopping the new process or restoring the backup fails, an error is returned
and the backup is retained. Interrupting the updater may also leave a backup;
another update will not overwrite it. Files bimeron.exe.update-old/update-new in
Program Files/Bimeron Core require manual inspection with the service stopped.
This rolls back command failures; it does not guarantee automatic recovery after
power loss. Successful startup is checked through SCM Running, not a network test.

The description for new and updated services is `VPN core and local control`.
To change only an installed service's description without disconnecting the VPN:

```cmd
dist\windows-amd64\bimeron.exe service describe
```

An elevated CMD is required. Tests for replacement, rollback, failed stopping,
and missing staged files run in temporary directories. The user performs actual
updates of the installed service; these were not run automatically against a
working VPN session.

Code, named-pipe, and service-handler lifecycle checks run without SCM installation.
In historical validation on October 6, 2026, the user confirmed installation,
connection, service stop restoring the normal IP, and subsequent service
start/start reaching connected. Doctor read the running service and nonzero
statistics without changing the network.
On October 8, 2026, Windows amd64 checks confirmed forced service termination,
SCM restarts after 5 and 15 seconds without automatic VPN connection, persistent
blocking after reboot, and complete removal of owned DNS/WFP settings by
`recover`. Service uninstallation and interactive access denial for another
user require separate tests.

IPC access was also checked with automated Windows AccessCheck against the
production DACL: the owner's token receives access, while a DACL with an unrelated
SID rejects the same token. A native test of the owner connecting to a separate
pipe passed without elevation. This checks ACLs, not interactive login with a
second account. These tests did not modify the working service.
