# ADR 0012: Built-in SSH TCP upstream

Status: accepted, October 27, 2026. Tracks issue #26.

## Context

Bimeron has a local SOCKS5 proxy and a system VPN backend. The VPN backend
requires both TCP and UDP relay. Ordinary SSH direct TCP forwarding has no UDP
relay. The daemon runs under a service account, which may have a different home
directory from the GUI user.

## Decision

Implement SSH direct TCP forwarding as an upstream for proxy mode only. Accept
explicit profile fields and an `ssh://` URI. Verify server keys using a
`known_hosts` file. Try an explicit identity, an available agent, then standard
identity filenames. Do not scan other files in `.ssh`. Allow password,
encrypted-key passphrase, and keyboard-interactive challenges through an
ephemeral local control request. Do not persist those secrets. Require explicit
paths when the service account cannot resolve the user's home directory.

## Tradeoffs

- Proxy mode supports TCP CONNECT; applications must use the local SOCKS5
  listener. VPN mode and UDP need a separate transport decision.
- An SSH URI without an identity is convenient in an interactive user process.
  A service may need an absolute identity and host-key file path.
- Interactive authentication needs a versioned IPC extension and an available
  GUI or CLI client. Reconnection can ask again; unattended password-based
  reconnection is unavailable.
- Host-key trust must be established before connecting. No automatic
  trust-on-first-use or insecure bypass is provided.
