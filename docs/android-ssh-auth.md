# Android SSH authentication

Issue #96. SSH identities and the user-imported known_hosts remain filesystem
paths. App-owned trusted host keys are passed as bytes (see "Host-key offers"
below, ADR 0035). No in-memory identity import or protocol capability flag is
provided.

`Session.PendingAuth()` returns JSON null or an object containing `sessionId`,
`requestId`, `kind`, `prompts`, and `echo`. IDs are opaque random 48-character hex
strings scoped to the Session/request. Kinds are password, key_passphrase, and
keyboard_interactive. There are 1–8 prompts, each at most 1 KiB UTF-8, at most
8 KiB combined. Invalid UTF-8, control/format characters and Unicode line/paragraph
separators are rejected, never truncated. Echo count matches prompt count.
Serialized pending JSON cannot exceed 16 KiB, including JSON escaping.

`ReplyAuth(sessionID, requestID, answersJSON)` accepts a JSON string array matching
the prompt count: at most 8 answers, 4 KiB per answer and 16 KiB combined decoded
UTF-8. The separate wire cap is 128 KiB to allow JSON escaping. Invalid input uses
fixed redacted errors. `CancelAuth(sessionID, requestID)` consumes the request once.
Wrong-session, expired, duplicate and stale operations fail atomically. Answers
never appear in pending JSON, status, events or errors.

The host must mask **all** answer fields regardless of echo hints. Keep answers
only in transient memory; never store them in savedState, preferences, backups,
logs, analytics, screenshots or clipboard. Go strings cannot guarantee erasure.

Each SSH attempt permits at most eight prompt rounds, each bounded by 60 seconds
and the caller's remaining deadline. The VPN setup's existing 75-second outer
limit is unchanged. Its clock never pauses. The cumulative 20-second network
budget pauses only during local prompt callbacks and resumes with the remaining
budget. Identity/passphrase processing belongs to the same attempt. There is no
120-second interaction guarantee. Noninteractive connections retain their
20-second network budget.

Cancellation, prompt failure, deadline expiry and socket failure terminate the
attempt and prevent fallback prompts. Stop and network changes invalidate pending
requests synchronously; generation-bound callbacks reject stale first publication.
PendingAuth and reply/cancel check context expiry before exposing or consuming a
request. The host should dismiss the form when pending becomes null.

Reply validation rejects null elements and unpaired escaped UTF-16 surrogates
without consuming the pending request. Empty strings, valid surrogate pairs and
literal U+FFFD remain valid answers.

Validation includes generated local SSH fixtures with two
two-second human waits and accumulated network delays against the production
20-second budget, actual parent deadline expiry, terminal socket closure and
callback counts. Network-change and Stop hooks also reject stale callbacks.
Android device, SDK and AAR validation is separate.

## Host-key offers (accept-new)

Host-key offers are opt-in. Call `Session.AcceptNewHostKeys(trustedKnownHosts)`
at most once, before `Start`. Without that call, nothing below applies:
verification uses only the profile's `KnownHostsFile`, and every SSH failure
stays `ssh_connection_failed`.

`trustedKnownHosts` holds the app-owned known_hosts lines for the profile:
null or empty for none, at most 256 KiB. Blank lines and `#` comments are
ignored. Every other line must be `host[,host...] keytype base64 [comment]`,
where each host is a literal name or IP, or `[host]:port`. Markers
(`@revoked`, `@cert-authority`), hashed hosts (`|1|`), patterns (`*`, `?`, `!`)
and certificates are rejected; import such files through `KnownHostsFile`. An
invalid line fails the call with an error naming only its line number. The
user-imported `KnownHostsFile` keeps full OpenSSH syntax. Without it, no
default `~/.ssh/known_hosts` is read.

Verification, in order:

1. A key that `KnownHostsFile` marks `@revoked` is refused.
2. A key that matches either source connects with no offer.
3. A host listed in either source with no matching key is refused with no
   offer, whatever the key type. No call accepts a changed key.
4. Otherwise the host is unknown, and `PendingAuth` returns one offer.

An offer has exactly these seven string fields, in this order:

```json
{"sessionId":"<48 hex>","requestId":"<48 hex>","kind":"host_key","host":"ssh.example.com:2222","keyType":"ssh-ed25519","fingerprint":"SHA256:<base64>","knownHostsLine":"[ssh.example.com]:2222 ssh-ed25519 AAAAC3Nza..."}
```

- `host` is the dialed `host:port`. An IPv6 literal is bracketed. Only
  `A-Z a-z 0-9 . - _ : % [ ]` appear in it.
- `keyType` is the SSH public-key type, such as `ssh-ed25519`,
  `ecdsa-sha2-nistp256` or `ssh-rsa`. It has at most 128 bytes and no space
  or comma.
- `fingerprint` is the OpenSSH SHA-256 form: `SHA256:` followed by 43
  unpadded standard-base64 characters.
- `knownHostsLine` is the exact line to persist, with no newline. It has three
  fields separated by single spaces: the normalized host (bare for port 22,
  `[host]:port` otherwise), `keyType`, and the base64 key. Each field is
  printable ASCII; the line has at most 12 KiB.
- `prompts` and `echo` are absent. The kinds `password`, `key_passphrase` and
  `keyboard_interactive` keep their previous byte-identical JSON.

Render `host`, `keyType` and `fingerprint`. Show the full fingerprint; do not
truncate it.

- **Accept:** `ReplyAuth(sessionId, requestId, "[\"accept\"]")`. Any other array,
  including `["Accept"]`, `[""]` or two elements, is rejected and leaves the
  offer pending.
- **Decline:** `CancelAuth(sessionId, requestId)`.

An offer has the same 60-second limit, eight-round limit, generation binding,
and Stop/network invalidation as other prompts, and it is consumed once.

After `ReplyAuth` accepts, the app appends `knownHostsLine` to its per-profile
store. It passes the stored lines to the next Session's `AcceptNewHostKeys`.
The same Session remembers the accepted key for its reconnects, so a reconnect
does not offer again. Core writes no files. A later authentication failure
does not revoke the acceptance; this matches OpenSSH `accept-new`.

With opt-in, `Status.LastError` uses these host-key faults. Other SSH
failures stay `ssh_connection_failed`.

| LastError | Meaning | Suggested app code |
|---|---|---|
| `ssh_host_key_mismatch` | Known host with no matching key, or a revoked key. No offer was made. | `HOST_KEY_MISMATCH` |
| `ssh_host_key_rejected` | The user declined the offer with `CancelAuth`. | `AUTH_CANCELLED` |
| `ssh_host_key_unanswered` | The offer timed out (60 s), the round limit was hit, or the offer was withdrawn by a network change, Stop, deadline or connection loss. | `AUTH_UNANSWERED` |
| `ssh_host_key_unknown` | The host is unknown and no offer could be made, for example because the host is not a literal name. | `SSH_CONNECTION_FAILED` |

All four faults are terminal: Core does not retry them. An app whose
pendingAuth parser does not know `host_key` must not opt in, because an
unrendered offer only expires after 60 seconds.
