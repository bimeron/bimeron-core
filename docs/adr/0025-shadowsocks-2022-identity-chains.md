# ADR 0025: Extend the SS2022 client with SIP023 identity chains

Status: accepted, October 28, 2026. Supersedes ADR 0020's EIH restriction.
Tracking issue: #55.

## Context

The SIP022 client uses one pre-shared key for requests and responses. SIP023
adds identity layers so the same client can reach multi-user servers and
identity relays. It extends SS2022 rather than introducing a protocol type.

## Decision

Accept `iPSK0:iPSK1:...:uPSK` in the existing password/secret field for
`2022-blake3-aes-128-gcm` and `2022-blake3-aes-256-gcm`. Decode and validate
every component using a shared accesskey parser. Each key must have the
method's required length. Empty components and salt prefixes are rejected.
Single-key configurations retain SIP022 behavior. ChaCha20 chains are
rejected because SIP023's separate UDP header construction applies to AES.

Keep immutable identity keys and next-key hashes in the SS2022 client.
TCP derives identity subkeys using the request salt and inserts a 16-byte
header for every identity key before the AEAD chunks. UDP encrypts its
outgoing separate header with the first identity key and inserts identity
headers bound to the plaintext session ID and packet ID. Payload encryption
and incoming response processing use the terminal user key. Outgoing and
incoming UDP header ciphers are separate. Existing replay and session checks
remain in effect, and UDP size validation includes every identity header.

Use existing AES and BLAKE3 dependencies. Do not add an SS2022 server,
account management, relay hosting, or a new public configuration field.
Errors must not reveal key material or complete credential URIs.

## Alternatives and tradeoffs

- A separate identity-key array would make configuration explicit but add
  schema and import changes. SIP023's colon-separated representation fits
  the existing secret field and preserves existing profiles.
- Replacing the SS2022 implementation with a full proxy runtime would add
  dependencies and licensing constraints without being needed here.
- Maintaining EIH locally adds cryptographic framing responsibilities.
  Independent Python-generated wire vectors and pinned external Xray tests
  cover both AES methods, multiple users, and a relay plus multi-user server.

## Validation

Require parser and import tests, exact TCP/UDP identity-header vectors,
UDP datagram boundaries, single-key regressions, and external TCP/UDP
interoperability. Reject wrong identity keys, wrong user keys, and reordered
chains with bounded test deadlines. Run focused race checks, bounded parser
fuzzing, and header-generation benchmarks in CI. Reference server binaries
are built outside Bimeron's dependency graph.

Specification: <https://shadowsocks.org/doc/sip023.html>.

Local validation on October 28, 2026 passed the full Go tests and vet,
Windows race checks for SS2022/accesskey/config, and the pinned Xray matrix.
A five-second parser fuzz campaign completed approximately 767,000 executions.
Header benchmarks ran for zero, one, and four identity layers. All six CLI
distributions and the four-ABI Android AAR built and passed package checks in
a clean staging directory. Hosted CI remains pending publication.
