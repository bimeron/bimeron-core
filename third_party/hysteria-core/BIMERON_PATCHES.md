# Bimeron Hysteria core snapshot

Base: `github.com/apernet/hysteria/core/v2 v2.13.0` from the Go module
distribution, without Git history. Preserve `LICENSE.md`.

Local changes are confined to client fingerprint validation/propagation and
transport construction: Firefox uses a 3-byte source connection ID and enables
the QUIC fork's fixed-bit/large-receive handling. Authentication, congestion
control, stream framing, and UDP relay/fragmentation remain upstream code.

The generated `client/mock_udpIO.go` is renamed to `client/mock_udpIO_test.go`
(and `client/.mockery.yaml` sets the matching `filename`) so testify stays out
of the non-test client package and therefore out of release binaries.

This module replaces apernet/quic-go with the adjacent local snapshot and pins
uTLS to the root project's version so standalone tests use the intended code.
Run `go test ./client ./server` here. The independent fixture under
`internal/hysteria2/testdata/reference-server` deliberately has no replacements.

`client.(*clientImpl).TCPContext` (and `TCP`, which now calls it with a
background context) resets the request stream with `CancelRead`/`CancelWrite`
when the context ends, so an abandoned dial no longer keeps a goroutine and a
QUIC stream until the server answers. The wire format is unchanged.
The server returns the stream credit when it finishes with the reset
stream. `internal/integration_tests/tcp_context_test.go` checks that cancelled
dials return promptly, leave no waiting goroutines and keep the connection
usable.
