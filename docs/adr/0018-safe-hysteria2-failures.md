# ADR 0018: Safe Hysteria2 connection failures

Status: accepted, October 28, 2026. Tracks issue #21.

## Context

Hysteria2 connection errors were discarded and both VPN and proxy startup
reported retryable `invalid_udp_transport`. This concealed permanent TLS and
authentication failures and caused repeated connection attempts. Raw upstream
errors may contain server addresses or authentication material.

## Decision

Classify failures at the Hysteria2 client boundary into fixed codes, stages,
and retryability. Do not retain the upstream error in the public failure. Both
runtime paths map that failure into the existing core error mechanism. Keep the
stable failure code in `LastError` and add `ErrorStage` to status and events.
Unrecognized failures stop retries until they can be classified safely.

## Alternatives and tradeoffs

- Encoding the stage inside `LastError` would avoid a new field but require
  desktop clients to parse a compound string and break existing code matching.
- Passing wrapped upstream errors to core would preserve debugging detail but
  risk leaking credentials and server information through public events.
- A terminal unknown category can stop a connection that might recover on its
  own. It prevents an endless retry loop for an unidentified permanent error;
  new typed evidence can justify reclassifying that case later.
- quic-go can flatten a local TLS failure into a transport error message. The
  classifier recognizes its local `tls: ` prefix without exporting the message.
  A future upstream change may require another safe typed signal.
