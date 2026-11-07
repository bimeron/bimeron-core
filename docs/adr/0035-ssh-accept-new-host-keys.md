# ADR 0035: Opt-in accept-new SSH host keys

Status: accepted, November 7, 2026. Targets Bimeron v1.9. Amends the last
tradeoff of ADR 0013 for opted-in hosts only.

## Context

SSH host keys are verified only against a `known_hosts` file (ADR 0013). On
Android the user must import such a file before the first connection, which
most users cannot do. Every SSH failure becomes one fault,
`ssh_connection_failed`, so the app cannot tell a changed host key, a possible
attack, from a wrong password or a timeout. The Android app already polls a
bounded authentication bridge (`PendingAuth`, `ReplyAuth`, `CancelAuth`) for
password, passphrase and keyboard-interactive prompts.

## Decision

Add accept-new host-key handling as an explicit opt-in. Only the embedded
Android Session opts in, through `Session.AcceptNewHostKeys(trustedKnownHosts)`
before `Start`. CLI, daemon, desktop and Apple consumers keep known_hosts-only
verification, their error text and the single `ssh_connection_failed` fault.

For an opted-in connection:

- Trusted keys are the union of the profile's `KnownHostsFile` (user import,
  full OpenSSH syntax, unchanged) and the app-owned bytes passed to
  `AcceptNewHostKeys`. Those bytes accept only plain `host[,host] type base64
  [comment]` lines with literal hosts. Without a `KnownHostsFile`, no default
  `~/.ssh/known_hosts` is read.
- A match in either source connects without an offer.
- A host known in either source with no matching key, or a key marked
  `@revoked` in the file, is refused without an offer. The fault is
  `ssh_host_key_mismatch`. No path accepts a changed key.
- An unknown host produces one `host_key` offer through the existing bridge.
  It uses the same per-prompt 60-second limit, eight-round limit, paused
  network budget, generation binding and Stop/network invalidation as other
  prompts.
- `ReplyAuth(sessionId, requestId, '["accept"]')` is the only acceptance.
  Any other answer is rejected without consuming the offer. `CancelAuth`
  declines and fails with `ssh_host_key_rejected`. Timeout, withdrawal, Stop,
  network change, deadline or connection loss fails with
  `ssh_host_key_unanswered`. If no offer can be made, the fault is
  `ssh_host_key_unknown`.
- An accepted key is remembered in memory for the Session's reconnects. Core
  does not write files. The offer carries the exact `knownHostsLine`; the app
  persists it in its per-profile store after `ReplyAuth` succeeds and passes
  the stored lines to the next Session.
- Host-key algorithms for key types already trusted for the host are
  preferred, as in OpenSSH. Otherwise a server with an additional key type
  that the library prefers would look like a changed key. A `KnownHostsFile`
  with `@cert-authority` lines keeps the library order.

The offer is a new `kind` in the same pendingAuth JSON. Existing kinds keep
byte-identical output:

```json
{"sessionId":"<48 hex>","requestId":"<48 hex>","kind":"host_key","host":"ssh.example.com:22","keyType":"ssh-ed25519","fingerprint":"SHA256:<43 base64 chars, no padding>","knownHostsLine":"ssh.example.com ssh-ed25519 AAAAC3Nza..."}
```

`host` is `host:port` as dialed (IPv6 in brackets). `knownHostsLine` uses
OpenSSH normalization: the bare host for port 22, `[host]:port` otherwise. It is
exactly three space-separated printable ASCII fields, at most 12 KiB, with no
newline. The offer has no `prompts` or `echo` field.

## Alternatives

- **Accept reply returns the line**, through `ReplyAuth`'s return value or a
  later event. It needs a second channel and an ordering rule between reply and
  persistence. The offer already holds everything the app shows and stores.
- **Offer carries only the public key; the app builds the line.** This
  duplicates OpenSSH host normalization in Kotlin, where it can drift from
  Core's matching.
- **App-owned keys as a second file path.** This matches the existing
  `KnownHostsFile` mechanism but couples Core to the app's file generations. A
  file may also not exist before the first acceptance. Bytes match the existing
  explicit-bytes geodata API.
- **Core persists accepted keys.** Core would own a writable trust store and
  its crash consistency. The app already owns per-profile resources (Android
  session ownership contract, section 9).
- **Default-on for every consumer.** The control daemon and CLI would see a new
  challenge kind that older GUIs cannot render, and their faults would change.
  Opt-in keeps existing contracts.
- **Accept-changed or auto-accept.** Rejected by decision: a changed key is
  never trusted interactively, and no key is trusted silently.

## Tradeoffs

- The app must not persist a line before `ReplyAuth` succeeds. A later
  authentication failure does not undo the acceptance, matching OpenSSH
  `accept-new`.
- `ssh_host_key_unanswered` also covers connection loss during the offer.
  The app's own reply history separates a user cancel from a timeout.
- A host that is trusted only by a `@cert-authority` line but presents a
  plain key is treated as known with no matching key. The fault is
  `ssh_host_key_mismatch`, the existing knownhosts semantics.
- In opt-in mode the preferred-algorithm list omits `ssh-dss`.
- Android apps whose parser does not know `host_key` must not call
  `AcceptNewHostKeys`; an unrendered offer would time out after 60 seconds.
