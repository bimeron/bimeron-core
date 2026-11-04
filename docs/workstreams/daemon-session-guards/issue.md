# Issue #82: reject stale daemon session mutations

Issue: https://github.com/bimeron/bimeron-core/issues/82.
Status: publication authorized; parent handles push and pull request creation.
Base: df7f2fd32a69efc49018e58efcc8d0f4f4c4e697.
Branch: `feat/daemon-session-guards-publication`.

A GUI can observe a privileged Unix daemon and later send a start or stop after
that daemon or its session has changed. A separate status check cannot protect
the mutation. Both v0.3.0-beta.2 and the base reject daemon instance/session fields.

Implement the approved atomic guard option before Apple IPC lifecycle work:

- Explicitly advertise support in the handshake.
- Bind start to the daemon instance and absence of an active session.
- Bind stop to the daemon instance and exact active session identity.
- Validate and execute under the existing command admission mutex, returning
  refreshed authoritative status on rejection without changing the engine.
- Keep legacy CLI requests working, explicitly unguarded. Preserve foreground
  control and shutdown cleanup semantics.
- Reject ambiguous JSON that could erase guards. Cover stale, duplicate,
  replacement, concurrent admission, and serialized RPC behavior without tunnels.

No Apple checkout edits, live tunnel sessions, privileged installation, dependency
changes, merge, release, live acceptance, or new lifecycle framework are authorized
by publication approval.
