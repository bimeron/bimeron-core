# ADR 0036: Android SSH uses only profile-selected files

Status: accepted, November 7, 2026 (user decision 8). Targets Bimeron v1.9.
Complements ADR 0035.

## Context

`core.LoadConfig` and the config parsers set `SSHDefaultKeys`. Without an
`IdentityFile`, the SSH client then probes `~/.ssh/id_ed25519`, `id_ecdsa` and
`id_rsa`. Without a `KnownHostsFile`, it trusts `~/.ssh/known_hosts`. It also
expands `~` in both paths and dials an agent named by `SSH_AUTH_SOCK`. The
Android Session inherited all of this, but an Android app has no meaningful
user home: `HOME` may be unset, `/` or a shared directory. Keys or trust found
there were not imported by the user into the app, so using them is unexpected
and unauditable.

## Decision

Every Session that androidcore creates (`NewSession`,
`NewSessionWithGeoData`, `NewSessionWithSSConfSnapshot`, all through
`newSession`) sets `SSHDefaultKeys = false` and `SSHProfileOnly = true`. The
app cannot turn this off. `sshtunnel.Options.ProfileOnly` then means:

- no `os.UserHomeDir` call, no default identity scan and no default
  `known_hosts`;
- `~`, `~/…` and `~\…` paths are refused (generic `ssh_connection_failed`);
- no SSH agent connection, even if `SSH_AUTH_SOCK` is set;
- a profile with no `KnownHostsFile` whose Session did not call
  `AcceptNewHostKeys` fails before dialing with LastError
  `ssh_known_hosts_missing`.

Only the files the profile names (paths into app storage) and the app-owned
trusted lines passed to `AcceptNewHostKeys` are used. CLI, daemon, desktop and
Apple consumers do not set `SSHProfileOnly` and keep their behaviour and
error text.

## Alternatives

- **Rely on the app** to always set an identity and known_hosts. A single
  missing field would silently fall back to the home directory; the guard
  belongs in the embedding.
- **Turn off `SSHDefaultKeys` only.** That already refuses a missing
  known_hosts with a generic error, but still expands `~`, dials the agent and
  reports `ssh_connection_failed`, which the app cannot tell apart from a
  network failure.
- **Reject at Session construction.** Profiles can also come from resolvers
  at connect time, so the check runs in the SSH client for every attempt.

## Tradeoffs

- A profile that relied on `~` paths or an agent stops working on Android.
  Such profiles were never supported by the app.
- `sshtunnel.SetFileTrace` is an exported test hook in an internal package,
  so it is not part of the AAR API. The androidcore test uses it to prove that
  nothing under a fake `$HOME` holding a usable key and `known_hosts` is
  opened or stat'ed.
