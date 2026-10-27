# SSH TCP proxy

Bimeron can establish an SSH connection itself and use SSH direct TCP forwarding
as the upstream of its local SOCKS5 proxy. An SSH server with TCP forwarding
enabled is required. In `[Interface] Mode = proxy`, applications use the local
SOCKS5 listener, which accepts TCP `CONNECT` only. Configure remote hostname
resolution where available (for example, `socks5h` in curl).

`[Interface] Mode = vpn` carries system TCP flows through SSH without per-app
proxy settings. It is **TCP-only**, not a full VPN: ordinary SSH forwarding has
no UDP relay. Proxied UDP flows other than DNS are dropped, not sent directly.
DNS requests captured by Bimeron, whether received over UDP or TCP, are sent
to configured resolvers over TCP through SSH. Explicit `direct` routing rules
still use the physical network, including for UDP. The SSH server itself is
resolved on the physical network before the tunnel starts. Some applications
may use their own DNS or bypass the system tunnel; this mode does not guarantee
that all traffic is protected. Use a UDP-capable upstream for full VPN behavior.

## Connect with explicit fields

Create a local `.conf` such as `profiles/ssh.conf`:

```ini
[Profile]
Version = 1
Name = SSH example

[AccessKey]
Type = ssh
Server = ssh.example.com
Port = 22
Username = alice
IdentityFile = C:\Users\Alice\.ssh\id_ed25519
KnownHostsFile = C:\Users\Alice\.ssh\known_hosts

[Interface]
Mode = proxy
Listen = 127.0.0.1:1080
```

Replace the host, user, and file paths. The values above are placeholders.
`IdentityFile` is optional for an interactive foreground command. `KnownHostsFile`
is optional there when the user's `~/.ssh/known_hosts` exists. For a daemon or
service started through control RPC, set `KnownHostsFile` explicitly. Select an
absolute identity path for a GUI-managed service profile. Relative paths in a
file-backed `.conf` are resolved against the `.conf` directory; `~/` expands
under the process account. Use absolute paths in the GUI to avoid interpreting
`~` under the service account.

Validate, test, and start:

```sh
bimeron validate profiles/ssh.conf
bimeron check -config profiles/ssh.conf
bimeron run profiles/ssh.conf
```

`validate` checks syntax without connecting. `check` establishes SSH and tests
a TCP/TLS request through it. `run` starts the local proxy in the foreground.
The equivalent explicit command is `bimeron proxy -config profiles/ssh.conf`.
Once it reports that the SOCKS5 listener is ready, a test client can use:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://api.ipify.org
```

`--socks5-hostname` sends the hostname to the proxy. A browser must be set to
use SOCKS5 with remote DNS resolution to avoid resolving website names outside
the SSH connection. The DNS lookup for the SSH server itself uses the system
resolver before the tunnel is established.

To use TCP-only system routing instead, change `Mode = proxy` to `Mode = vpn`
in the profile. The local SOCKS5 listener is not started in that mode.

## Connect with an SSH string

Use one of these `[AccessKey]` sources:

```ini
SSH = ssh://alice@ssh.example.com:22
```

```ini
Key = ssh://alice@ssh.example.com:22?identity=~%2F.ssh%2Fid_ed25519
```

```ini
File = ssh.key
```

In the last example, `ssh.key` contains a single `ssh://...` line. `File` is
relative to the `.conf` directory. `Port` defaults to 22 if omitted. The URI
may use `identity=` and `known_hosts=` query options; percent-encode reserved
characters in their paths. For example, `/` becomes `%2F` and a space becomes
`%20`. An SSH URI is a Bimeron import format, not a portable credential: its
paths refer to files on the device that connects. A selected GUI key path can
also be saved as `IdentityFile` beside an `SSH = ssh://...` line, and it takes
precedence over `identity=`. `KnownHostsFile` similarly overrides
`known_hosts=`. Unknown or duplicate query options are rejected. URI passwords
are rejected; do not put a password or private-key content in a URI or `.conf`.

## Identity selection and prompts

For foreground CLI commands, Bimeron tries authentication methods in this
order:

1. The explicitly selected `IdentityFile`, if any.
2. Available identities from SSH agent. The agent performs signatures without
   sending private-key bytes to Bimeron.
3. When no identity file was selected, existing standard files named
   `id_ed25519`, `id_ecdsa`, and `id_rsa` under the current user's `~/.ssh`.
   Bimeron does not scan other filenames.
4. If the server offers it, an account-password or keyboard-interactive
   challenge, including a one-time code.

An encrypted key causes a **key passphrase** prompt. This is separate from the
SSH account password. Foreground CLI prompts require an interactive terminal;
secret input is hidden. Bimeron does not save passwords, passphrases, or
keyboard-interactive answers. Authentication can be requested again on a new
connection. Multiple rejected keys may hit a server's authentication-attempt
limit; select a specific identity when that happens.

The control daemon does not search the service account's standard identity
files: those are often unrelated to the GUI user. It can use an explicit
`IdentityFile`, a reachable agent, or a password supplied through the local
control challenge described below. An unavailable GUI means an interactive
challenge times out after two minutes. There is no unattended password cache.

## Verify the SSH server

Bimeron requires a matching entry in `known_hosts`. It never automatically
trusts a new key and has no insecure verification switch. Establish the server
fingerprint through a trusted channel before adding its public key to
`known_hosts`. `ssh-keyscan` can collect a key, but **does not authenticate it**;
compare its fingerprint with the trusted value before using it. A changed key
causes connection failure until investigated and corrected. Do not remove an
old entry solely to silence that failure.

The identity and `known_hosts` files must be readable by the Bimeron process.
On Windows, the installed service runs as `LocalSystem`; mapped drives and
user-protected EFS files may be unavailable. The GUI should save absolute paths
and verify access before starting a session. Copying private-key contents into
the profile is unnecessary.

## GUI and local control IPC

The GUI is a separate project. It stores the selected identity and
`known_hosts` **paths** in the `.conf` file, saves the file atomically, then
sends the existing `start` request with the absolute `.conf` path. The core
keeps the selected key material in memory only while needed.

Control protocol version 1 adds two commands. During SSH connection setup,
the GUI polls `auth_pending` on the same protected local pipe/socket:

```json
{"version":1,"command":"auth_pending"}
```

When input is needed, the response has an `auth` object:

```json
{"auth":{"id":"0123456789abcdef0123456789abcdef","kind":"key_passphrase","prompts":["Key passphrase"],"echo":[false]}}
```

The remaining response fields (`version`, `instance`, `status`) follow the
ordinary control response. If no input is needed, `auth` is absent. Valid
`kind` values are `key_passphrase`, `password`, and `keyboard_interactive`.
`prompts` and `echo` arrays have the same length; `false` means masked input.
Keyboard-interactive prompts originate at the SSH server and should be shown
as untrusted text. Each prompt is limited to 256 bytes; at most eight prompts
are accepted. The GUI sends one answer for each prompt:

```json
{"version":1,"command":"auth_reply","challenge_id":"0123456789abcdef0123456789abcdef","answers":["user input"]}
```

The challenge ID is random and usable once. A missing, expired, or wrong ID
returns `invalid_auth_challenge`. Input over 1024 bytes per answer returns
`invalid_auth_response`. The request is limited to 16 KiB. The answer is sent
only over the protected local control channel; it is absent from status,
events, diagnostics, and the response to `auth_reply`. Do not log the request
in the GUI either. `stop` cancels a pending challenge. An unanswered challenge
expires after two minutes. The GUI should continue polling while connecting
and close its prompt if the session stops or fails.

An older core returns `unknown_command` for `auth_pending`; in that case the
GUI must not assume interactive SSH authentication is available. A GUI without
these commands can still connect with an unencrypted selected key.

## Limits

- SSH server TCP forwarding must be enabled. Server policy can reject a
  destination even after login succeeds.
- Local proxy mode does not automatically reconnect after the SSH session
  breaks. Stop and start the profile again; a future proxy reconnection policy
  can add automatic recovery.
- The system VPN, UDP traffic, SSH config aliases, agent forwarding, and
  password persistence are outside this version.
