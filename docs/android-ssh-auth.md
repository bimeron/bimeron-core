# Android SSH authentication

Issue #96. SSH identities and known_hosts remain filesystem paths. No in-memory
key import or protocol capability flag is provided.

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

Focused review validation includes generated local SSH fixtures with two
two-second human waits and accumulated network delays against the production
20-second budget, actual parent deadline expiry, terminal socket closure and
callback counts. Network-change and Stop hooks also reject stale callbacks.
Full suite, race checks, desktop/proxy regression checks and Android device/SDK/AAR
validation are deferred while the host is resource constrained.
