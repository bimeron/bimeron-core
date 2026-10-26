# XHTTP intermittent upstream failures

Status: open; upstream availability remains unresolved.

## Reproduction on 2026-10-26

The imported XHTTP profile uses VLESS, TLS, HTTP/2, packet-up, and
header-carried upload data. Both clients were bound to the same physical
Ethernet interface. Tests did not install routes or switch the system VPN.
The reference was Xray v1.260327.0. Its configuration was supplied through
stdin; credentials were not written into a diagnostic configuration file.

Requests used `https://example.com/`, a five-second request timeout, and a
fresh destination HTTP transport per request. Each client retained its own
upstream transport across requests.

| Series | Bimeron HTTPS successes | Xray HTTPS successes |
| --- | --- | --- |
| Sequential mixed DNS and HTTPS probes | 4/20 | 13/20 |
| HTTPS only, alternating which client runs first | 1/20 | 3/20 |

The first series also sent UDP DNS and TCP DNS through Bimeron before each
HTTPS pair, so it is not an equal-load client comparison. The second removes
that difference. These short samples demonstrate current failures, not
long-term failure probabilities or proven performance parity.

Instrumentation observed XHTTP upload responses with status 502. Xray's
logs contained 10 occurrences of HTTP 502 in the first series and 30 in the
second. One application request can produce multiple transport requests;
these counts are not counts of failed HTTPS requests. The second series
used the status propagation fix described below, which does not alter
requests or retry policy.

The application's latest retained session reported 47 DNS failures out of
148 queries, including failures after both UDP and TCP attempts. Successful
`dns_tcp_fallback` events confirm that fallback was active in this session.

## Confirmed client defect

The packet upload worker cancelled the stream before publishing its error.
Readers could therefore observe cancellation instead of the original HTTP
502. DNS diagnostics reduced this further to an unspecified read failure.

The fix publishes the upload error before cancellation under a separate
mutex. It must not acquire the write mutex first: a writer can hold that
mutex while waiting for upload queue space. A typed HTTP status error allows
DNS diagnostics to show the numeric upstream status without exposing request
URLs, headers, credentials, or raw error strings.

Regression tests cover propagation to readers, release of blocked writers,
and diagnostic redaction. `go test ./...` passed. Race instrumentation could
not run because the environment has CGO disabled and no C compiler on PATH.

## Resolution boundary

The local fix improves error attribution; it does not repair HTTP 502 responses.
The exact failing component cannot be established without server or intermediary
logs. Reference-client failures establish that the native Bimeron implementation
is not the sole condition needed to reproduce the outage. Client differences
remain possible and should be investigated against a stable reference endpoint.

For reliable service, obtain a working alternate endpoint or a repaired profile
from the provider and validate it through both clients before selecting it.
A different transport requires matching server support and credentials; changing
the local transport field alone is not a valid migration. Embedding Xray is an
architectural option, but these results do not justify it as a remedy for this
endpoint. No automatic replay of interrupted application requests was added.
