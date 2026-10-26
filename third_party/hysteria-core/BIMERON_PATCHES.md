# Bimeron Hysteria core snapshot

Base: `github.com/apernet/hysteria/core/v2 v2.13.0` from the Go module
distribution, without Git history. Preserve `LICENSE.md`.

Local changes are confined to client fingerprint validation/propagation and
transport construction: Firefox uses a 3-byte source connection ID and enables
the QUIC fork's fixed-bit/large-receive handling. Authentication, congestion
control, stream framing, and UDP relay/fragmentation remain upstream code.

This module replaces apernet/quic-go with the adjacent local snapshot and pins
uTLS to the root project's version so standalone tests use the intended code.
Run `go test ./client ./server` here. The independent fixture under
`internal/hysteria2/testdata/reference-server` deliberately has no replacements.
