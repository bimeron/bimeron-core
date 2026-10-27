# Hysteria2 QUIC fingerprint implementation plan

Status: implemented with the verified preset set and outstanding environment
checks recorded below.
Date: October 27, 2026.
Branch: `feat/hysteria2`.
Tracking: [issue 19](https://github.com/bimeron/bimeron-core/issues/19).
Architecture: [ADR 0010](adr/0010-hysteria2-quic-fingerprints.md).

## Objective and boundaries

Extend the existing apernet QUIC stack with real client handshake presets while
retaining the upstream Hysteria2 client, authentication, congestion control,
TCP streams, and UDP framing/fragmentation. Use one Hysteria2 backend.
An explicit `fp` must select the corresponding wire handshake or fail; it must
never silently fall back to another fingerprint.

The current branch already supports query authentication, `insecure=0`, and
`alpn=h3`. Those features are regression requirements, not new implementations.
Implementation was authorized by the user after reviewing this plan.

## Evidence and starting points

- Go: `1.26.9`; Hysteria core: `v2.13.0`.
- apernet/quic-go: `v0.63.1-0.20261004180939-a10df75c260c`.
- uTLS: `v1.8.3-0.20260301010127-aa6edf4b11af`.
- Reference uquic: `v0.0.7-0.20260804184259-837c7ce1b72b`.
- Hysteria `client/config.go` and `client/client.go` currently expose and apply
  `DisableChromeParrot`, including transport-level connection ID selection.
- apernet already has a uTLS event adapter in
  `internal/handshake/tls_conn_utls.go`, a Chrome ClientHello specification,
  transport parameter serialization, and Initial packet shaping. Reuse these.
- Its uTLS path already disables session resumption and 0-RTT. Keep that
  limitation explicit for the new presets; do not import uquic's incompatible
  session-store integration.
- Temporary uquic probes demonstrated verified TLS, negotiated `h3`, and small
  TCP/UDP echo with Firefox 116 and Chrome 115/146 after research patches.
  They did not prove the apernet port, complete wire fidelity, physical-interface
  routing, fragmentation, or behavior under loss.
- Firefox advertises eight active connection IDs. Both implementations need
  scrutiny where connection ID accounting uses a fixed implementation limit.
  Raising a global constant is not an acceptable production fix.

## URI specification

Example using a public placeholder only:

```text
hysteria2://host.example:8449?auth=replace-me&sni=name.example&insecure=0&alpn=h3&fp=firefox#label
```

- Preserve `hysteria2` and `hy2`, userinfo authentication, and query `auth`.
  Reject two password sources, including empty conflicting sources.
- Preserve strict rejection of unknown or repeated query parameters.
- `insecure=0` retains certificate-chain and hostname verification;
  `insecure=1` remains rejected. `alpn` may be omitted or exactly `h3`.
- An omitted `fp` preserves the current upstream ChromeParrot behavior.
  Explicit empty, unknown, or unsupported values fail validation before dialing.
- Planned named presets: `firefox` and `firefox-116` select Firefox 116A;
  `chrome` and `chrome-146` select Chrome 146; `chrome-115` selects Chrome 115.
  Aliases are pinned, not automatically advanced with dependency upgrades.
- Evaluate Firefox 116B/116C during the preset inventory. Expose additional
  names only with their own specification and passing wire/integration tests.
  Do not infer support from VLESS/TCP lists or unimplemented uquic constants.
- The planned names become supported only after their acceptance gates pass.
  Do not relabel existing ChromeParrot as Chrome 146 without proving equivalence.
- Errors and logs must omit the complete URI, credentials, raw query values,
  and user-controlled fingerprint text. Tests use synthetic credentials only.

## Implementation sequence

### 1. Freeze the reference and prepare reproducible dependency changes

- Record source versions, licenses, copied-code attribution, and an independently
  reviewed expected wire description for each candidate.
- Use repository-local module snapshots under `third_party/apernet-quic-go`
  and `third_party/hysteria-core`, with root `go.mod` replacements. Preserve
  upstream module identities, source/tests, and license notices. Follow the
  repository's existing local replacement approach; do not edit the Go cache.
- Record upstream provenance and a concise patch inventory so later upgrades
  can distinguish imported source from local modifications.
- Keep the Hysteria core patch limited to fingerprint configuration validation
  and propagation. No new relay engine or runtime uquic dependency.

### 2. Prove Firefox on apernet before broadening the implementation

- Add a typed, per-connection preset selection, compatible with legacy
  `ChromeParrot`. Define precedence and reject contradictory configuration.
- Pass selection from Hysteria configuration into QUIC configuration and
  transport construction. Connection ID length belongs to the transport;
  avoid shared mutable or process-wide fingerprint settings.
- Extend the existing uTLS adapter with the Firefox 116A ClientHello.
- Match QUIC version, initial packet number and encoding, source/destination
  connection IDs, CRYPTO/PADDING/PING layout, and Initial datagram sizing.
- Serialize the reference transport parameters and make runtime flow-control,
  stream limits, datagram limits, ACK behavior, idle timeout, and connection ID
  handling agree with advertised values. Keep receive limits bounded.
- Handle retransmitted Initials, Retry, and TLS HelloRetryRequest without
  reusing packet numbers or corrupting the TLS transcript.

Gate: a captured/decrypted Firefox Initial matches the reference description;
the port builds with the pinned Go/uTLS, authenticates to an unmodified official
Hysteria2 server, completes TCP/UDP echo, and rejects invalid TLS certificates.
No user-visible parser support is enabled before this gate.

If this requires replacing the TLS engine, changing the Hysteria protocol, or
weakening TLS verification, report the concrete blocker and revisit architecture
with the user. Do not silently switch to architecture 1 or 3.

### 3. Complete and verify the available preset set

- Port Chrome 115 and Chrome 146 reference behavior using the same apernet
  machinery. Account for IPv4/IPv6 differences and Chrome 146's larger key
  share and multi-datagram Initial flight.
- Reuse existing Chrome behavior only where wire evidence proves it matches.
- Preserve valid randomness and GREASE; create fresh mutable preset state per
  connection. Test concurrent connections with different presets.
- Test the actual connection ID limit, duplicate/retired IDs, and rejection
  beyond the advertised limit. Do not globally loosen limits for other modes.
- Verify default connections still use the existing ChromeParrot behavior.
- Record each supported preset's certificate/signature algorithm limitations;
  a server incompatible with the selected preset fails without fallback.

### 4. Connect the URI and validation path

- Add `Fingerprint` to `accesskey.Hysteria2`; validate it both in the URI parser
  and in typed-profile validation to prevent direct callers bypassing checks.
- Forward the value through `internal/hysteria2/client.go` to the patched core.
- Cover `bimeron validate`, configuration loading, and runtime dialing.
- Add table tests for aliases, both schemes/authentication forms, encoding,
  duplicates, unsupported/empty values, TLS/ALPN constraints, and redaction.
- Keep `ConnFactory` and the existing platform socket-control path; fingerprint
  selection must not create an unbound replacement socket.

### 5. Integration and wire acceptance

- Capture actual outbound UDP bytes, remove QUIC Initial header protection,
  decrypt Initial packets, and reassemble CRYPTO offsets across the flight.
- Assert ClientHello suites/extensions/groups/signatures/ALPN and transport
  parameter presence, values, ordering rules, and varint encodings. Also assert
  packet header fields, CID lengths, packet numbers, frame layout, padding,
  and IPv4/IPv6 size rules against separately recorded references.
- Normalize only defined random fields. Test allowed shuffled-order rules
  without flaky statistical assertions. Byte inequality alone is not proof.
- Include a negative control: a default or different preset must fail the
  Firefox expectation. Confirm the URI-selected preset reaches the wire.
- Run against a separately built, pinned official Hysteria2 server without
  local module replacements. In-process tests sharing patched dependencies
  remain useful but are not the sole interoperability evidence.
- Test trusted/untrusted/expired certificates, wrong SNI, negotiated `h3`,
  unsupported server ALPN, rejected authentication, and UDP-disabled servers.
- Exercise TCP and UDP, datagrams requiring Hysteria fragmentation, concurrent
  sessions, cancellation, deadlines, close, and creating a fresh client after
  failure. Preserve existing documented half-close limitations.
- Exercise loss, reordering, Initial retransmission, and Retry at QUIC level.
  Compare bounded throughput/allocation measurements with the default backend
  to identify regressions caused by changed windows or handshake shaping.
- Verify socket-control invocation automatically. Verify actual egress and
  absence of tunnel-route recursion in disposable Windows/Linux VPN test
  environments, including IPv6 where available. A callback invocation is not
  physical-interface proof. Do not alter the development workstation routes.

### 6. Documentation, CI, and packaging

- Update `docs/CONF.MD`, `docs/GUI_INTEGRATION.MD`, and ADR 0009 with the exact
  shipped preset set, aliases, defaults, limitations, and verified examples.
- Finalize ADR 0010 with evidence and any adjustments made during the spike.
- Update `THIRD_PARTY_NOTICES.txt` and distribution notices for adapted code.
- Extend CI to test local replacement modules explicitly: root `go test ./...`
  does not run tests in nested Go modules. Verify standalone module dependency
  resolution uses the intended local QUIC code via explicit replacements or a
  generated CI workspace, never an accidental upstream copy.
- Retain Linux/Windows tests, dependency/license gates, six CLI distributions,
  and four-ABI Android packaging. Add focused Linux race checks for changed
  packages and meaningful upstream QUIC regression suites.

## Verification commands and evidence

Run during implementation, not as claims of completed work:

```text
go test ./internal/accesskey ./internal/hysteria2 ./cmd/bimeron ./core
go test ./...
go vet ./...
go run scripts/build-dist.go
go run scripts/check-dist.go
```

Also run targeted handshake, wire, connection ID, packet-packer, configuration,
and integration tests inside the patched QUIC module, and client/server tests
inside the patched Hysteria module. Use Linux race testing with CGO and the
existing Android CI toolchain. Re-run affected VLESS tests because uTLS is shared.
Record exact commands, versions, passed/skipped checks, and artifact hashes.
Cross-compilation does not count as platform runtime or routing validation.
No push, PR, or remote CI execution is implied by this plan.

## bimeron-desktop contract changes

- Provide a Hysteria2-specific selector containing only shipped QUIC presets;
  do not reuse the VLESS fingerprint selector.
- Preserve imported explicit `fp` values and serialize a single parameter.
  Never strip an unsupported value to make validation succeed.
- Keep an omitted fingerprint as the documented core default. Round-trip aliases
  without silently upgrading them to newer browser versions.
- Continue single-source authentication, secure TLS, and `h3` ALPN behavior.
- Explain historical preset versions and the lack of resumption/0-RTT. Claim
  handshake emulation, not complete browser indistinguishability: Hysteria's
  application traffic remains Hysteria traffic.
- Gate the selector on a core release documented to support this contract;
  older cores reject `fp`. Record the minimum version when a release is assigned.

## Completion criteria

Every published `fp` passes parser, real-wire, TLS, and relay tests. The example
URI validates and connects with Firefox semantics. Default profiles remain
compatible. Required builds and available platform checks pass, with any missing
environment-dependent evidence stated explicitly. Documentation gives the exact
supported names and limitations; passwords and complete URIs never appear in
diagnostics. Deliver work on `feat/hysteria2` with Conventional Commits and no
push or PR unless separately requested.

## Implementation outcome (October 27, 2026)

The feasibility gate passed on the retained apernet/Hysteria backend. Shipped
names: `firefox`, `firefox-116`, `firefox-116b`, `firefox-116c`, and `chrome`.
The Firefox variants have 8/9/15-byte initial DCIDs. Chrome explicitly selects
the existing apernet preset. The candidate mapping of `chrome` to uquic 146
was not adopted: the existing preset differs, and versioned 115/146 names
remain rejected until separately ported and verified. See ADR 0010.

Real UDP Initial tests decode TLS and QUIC fields for all Firefox variants on
IPv4/IPv6, with a Chrome negative control. Reference integration builds an
unmodified Hysteria server in an independent Go module and exercises the URI
parser and production adapter, TCP, and 3500-byte fragmented UDP concurrently.
The upstream relay's 4096-byte message buffer is an existing limitation.

Root tests/vet and nested QUIC/Hysteria tests are run locally on Windows.
Linux race checks and platform routing need an appropriate runner; WSL has
no Go toolchain. A socket-control callback check is not physical-interface
routing proof. CLI cross-builds are not macOS/Linux runtime evidence.

### Local verification results

- Windows/amd64, Go 1.26.9: root `go test ./...` and `go vet ./...` passed.
- Patched QUIC: root, handshake, wire, and ACK-handler tests passed; the
  `Test(FirefoxParrot|ChromeParrot)` integration selection and module vet passed.
- Patched Hysteria: `go test ./client ./server` passed.
- The built Windows CLI accepted the complete query-auth Firefox fixture with
  `bimeron validate`; no network or system configuration changes were made.
- `scripts/build-dist.go` and `scripts/check-dist.go` passed for Windows, Linux,
  and macOS, amd64/arm64. Windows packages include verified Wintun and notices.
- Android build passed with local NDK 27.1.12297006; the AAR contains all four
  ABIs and matching license/notice files. CI uses its existing pinned NDK.
- Initial-construction benchmark (20 iterations, Windows i7-12700K): Chrome
  490420 ns/op, 87513 B/op, 676 allocations; Firefox 116A 342235 ns/op,
  67342 B/op, 532 allocations. Includes socket setup and first UDP emission;
  it does not measure WAN throughput, loss recovery performance, or TUN routing.
- Linux race tests are configured in CI but were not run locally: WSL has no
  Go toolchain and Windows has no compatible race C compiler configured.
  No push or remote CI run was performed. Physical-interface/TUN egress and
  native Linux/macOS/Android runtime behavior remain environment checks.

The previous Windows executable was in use, so the new CLI distributions are
under `dist/hysteria2-fingerprints/`. Windows/amd64 SHA256:
`C0B34DDB8A97799AFFC732CDF4A217CF524E11486B875DE74BF00781D4171BDB`.
Android outputs are under `dist/android/`.
