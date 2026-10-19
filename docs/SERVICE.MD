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

Run updates from a newly supplied binary. The updater checks ELF architecture and
rolls back on startup failure, preserving the owner and automatic-start setting:

```sh
sudo ./bimeron-linux-amd64 service update
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
service.

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
source, and three installed files. The adjacent wintun.dll must match the EXE's
architecture. WINTUN-LICENSE.txt is also required. Profiles and keys remain in place.

## Updating

From an elevated CMD, run the new binary in the project directory:

```cmd
dist\windows-amd64\bimeron.exe service update
```

The command checks the installed path, owner, Go binary, and matching PE
architecture. It first copies the new EXE into the protected directory, then
stops the service, waits for cleanup, and replaces the EXE. If the service was
running, it restarts, but the VPN remains disconnected; explicitly call
start <config>. If it was stopped, it stays stopped.
The owner, automatic-start setting, and recovery settings are preserved.
Wintun DLL and its license are not replaced: this updates the core, not the driver.

If replacement or startup fails, the old EXE is restored; a previously running
service restarts with the old EXE without automatically connecting the VPN.
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

