# Controlling Bimeron Core

The GUI protocol is documented in [CONTROL.MD](CONTROL.MD).
A [Windows service](SERVICE.MD) is available for background operation.

`run` retains its existing behavior: it starts one session in the current
console. Ctrl+C disconnects it, restores network settings, and exits the process.
This command does not require a daemon.

To control the core with separate commands, first open an administrator CMD:

```cmd
dist\windows-amd64\bimeron.exe daemon
```

The daemon stays in that console and waits for commands. This is a regular
process, not an installed Windows service. In a second console under the same user:

```cmd
dist\windows-amd64\bimeron.exe start profiles\main.conf
dist\windows-amd64\bimeron.exe status
dist\windows-amd64\bimeron.exe watch
dist\windows-amd64\bimeron.exe stats
dist\windows-amd64\bimeron.exe capabilities
dist\windows-amd64\bimeron.exe stop
dist\windows-amd64\bimeron.exe shutdown
```

| Command | Behavior |
| --- | --- |
| `start <config>` | Sends the profile to the daemon and starts connecting. Returns as soon as the request is accepted; wait for `connected` through `status` or `watch`. |
| `status` | Shows session state, the last error, and active TCP/UDP transport endpoints. |
| `stats` | Session counters: TCP/UDP flows, DNS, bytes, and routing decisions. No addresses or keys. |
| `capabilities` | Platform capabilities: VPN, kill switch, split routing. The GUI reads this instead of assuming parity. Runs locally without a daemon; also available through IPC. |
| `watch` | Shows events. Ctrl+C stops only the viewer. |
| `stop` | Disconnects the session and waits for route, DNS, and kill-switch cleanup. The daemon keeps running and accepts another `start`. Repeated `stop` is safe. |
| `shutdown` | Stops the session, then exits the daemon. If cleanup fails, returns an error and keeps the daemon available. |

Ctrl+C in the daemon console also disconnects the session and exits after waiting
for cleanup. Forced termination through taskkill is a crash: if enabled, the kill
switch remains active until a new connection or `recover`.

Control commands apply only to the daemon's session, not a separate `run`.
The existing lock prohibits two simultaneous system VPN sessions.
The profile path is resolved relative to the console directory where `start`
was invoked.

IPC uses a local Windows named pipe. Access is allowed to the current Windows
user and SYSTEM; remote connections are prohibited. Another user, including an
account selected for privilege elevation, uses a separate endpoint.
Keys are not passed in IPC commands: the daemon reads the profile itself.
The log retains the last 128 events; `watch` reports gaps.

Linux and macOS provide the same commands through a Unix socket. Startup,
permissions, and recovery are documented in [LINUX.MD](LINUX.MD) and
[MACOS.MD](MACOS.MD). The macOS backend is experimental. These commands are not
yet implemented on other platforms.

