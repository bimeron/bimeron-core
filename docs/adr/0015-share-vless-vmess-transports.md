# ADR 0015: Share stream transports between VLESS and VMess

Status: accepted, October 27, 2026.

## Context

VLESS and VMess use the same TLS, gRPC, and XHTTP transport protocols but have
different request and response framing. Maintaining two TLS client hello and
HTTP/2 implementations would create compatibility and security drift. The
existing VLESS gRPC and XHTTP clients already include stream lifetime,
connection pooling, and cleanup behavior.

## Decision

Put certificate-verified TLS and optional browser client hello selection in
`internal/streamtransport`. Both protocol clients call it. Expose a
protocol-neutral byte-stream method on the existing VLESS gRPC/XHTTP client;
VMess opens that stream and writes only VMess framing. Keep VMess AEAD code in
`internal/vmess` and VLESS framing in `internal/vless`.

The VLESS package currently owns the gRPC and XHTTP transport machinery. This
small adapter reuses it without moving roughly a thousand lines of working
transport code at once. If another protocol needs these streams, move the
transport owner into `internal/streamtransport` without changing wire behavior.

## Alternatives and tradeoffs

- Duplicating gRPC and XHTTP would avoid the temporary package-level coupling
  but double maintenance and testing.
- Moving the entire VLESS HTTP transport implementation now would give cleaner
  package boundaries but introduce a large, unrelated diff and regression risk.
- Importing Xray-core would bring its wider dependency graph, conflicting with
  ADR 0004 and the compiled-license constraint.

## Verification

Reference Xray tests cover TCP and UDP over each supported VMess transport and
both AEAD ciphers. CI checks the compiled dependency graph and third-party
notices. VLESS tests remain in the full Go suite.
