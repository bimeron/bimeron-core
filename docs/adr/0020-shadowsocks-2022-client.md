# ADR 0020: Implement the single-user Shadowsocks 2022 client

Status: Accepted

## Context

The existing Outline SDK transport supports older Shadowsocks AEAD methods.
Shadowsocks 2022 changes key handling, TCP headers, and UDP sessions, so adding
its method names to the old cipher list would produce incompatible traffic.
The complete Go clients surveyed either use GPL/AGPL or bring a large proxy
runtime and do not implement all three selected methods.

## Decision

Implement the SIP022 single-user client in a small package using Go's standard
AES-GCM, `golang.org/x/crypto` ChaCha20-Poly1305, and MIT-licensed BLAKE3.
Select it by method in the existing Shadowsocks TCP and UDP constructors.
Keep older methods on the Outline SDK. Support the two required AES methods and
the optional ChaCha20 method. Require a correctly sized base64 key and reject
salt prefixes for 2022 methods. Do not accept SIP023 extensible identity headers.

## Alternatives and tradeoffs

- SagerNet and database64128 clients support all three methods but have
  GPL/AGPL licenses incompatible with the current dependency policy.
- V2Fly is MIT-licensed but its client supports only the AES methods and pulls
  in a full proxy runtime.
- Maintaining protocol code locally requires ongoing care. An independent Xray
  server test covers TCP and UDP for every enabled method in CI, alongside unit
  tests for configuration validation and replay filtering.
