# Local quic-go changes

Baseline: the Go module archive for `github.com/quic-go/quic-go v0.64.1`,
https://github.com/quic-go/quic-go/releases/tag/v0.64.1. The upstream source,
tests, attribution, and MIT license are retained. The root module selects this
snapshot with a local `replace`; the independent MASQUE reference module keeps
its unmodified upstream v0.63.0 dependency.

## Send completion and GOAWAY

Issue: https://github.com/bimeron/bimeron-core/issues/60.

HTTP/3 previously cleared a normally closed stream as soon as the application
called Close. After GOAWAY, clearing the last stream immediately closed QUIC,
which could discard queued payload and FIN. Waiting only for response EOF does
not help when the peer half-closes its send direction before reading the final
client bytes.

Local changes:

- `send_stream.go`: add a lazily allocated `SendCompletionContext`, canceled
  after data/FIN ACK, reset completion, or connection shutdown. Existing Context
  still ends at local Close, preserving its public contract.
- `stream.go` and `http3/stream.go`: forward that completion signal.
- `http3/state_tracking_stream.go`: retain normal sends until transport
  completion; keep prompt error/reset handling. Writes attempted after normal
  Close must not bypass completion tracking.
- `http3/client.go` and `http3/transport.go`: add opt-in `GoAwayCloseDelay`.
  ACK means transport receipt, not application consumption; a peer can discard
  buffered bytes on connection closure. MASQUE uses a five-second grace after
  the last tracked stream completes. Zero preserves the upstream default for
  other HTTP/3 consumers. Explicit connection shutdown interrupts the timer.
- `send_completion_test.go` and `http3/send_completion_test.go`: cover ACK
  ordering, lost-frame retransmission, reset/shutdown, EOF before the final
  write, reading only after FIN ACK, and grace expiry. Root MASQUE tests cover
  CloseRead, CloseWrite, blocked I/O, slot bounds, GOAWAY replacement, and
  client/socket cleanup.

The application separately bounds its response drain and ACK wait to one
five-second deadline. Neither grace interval promises delivery after timeout,
peer failure, or explicit shutdown. No unsafe access or wire-protocol change is
introduced. This patch has not been submitted upstream.

## Validation and updates

Run `go -C third_party/quic-go test -race . ./http3 -timeout 120s` and the root
MASQUE lifecycle/interoperability tests. CI runs both on Linux and Windows.

When updating the dependency, compare these files with the new upstream module
archive and rerun the EOF + GOAWAY regressions with server reads held until
after transport completion. Remove the local snapshot and `replace` only when
upstream provides equivalent send-completion and graceful connection-lifetime
behavior, and adapt the MASQUE adapter to that API. Keep license notices intact.
