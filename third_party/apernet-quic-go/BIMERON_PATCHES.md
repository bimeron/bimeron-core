# Bimeron apernet QUIC snapshot

Base: `github.com/apernet/quic-go v0.63.1-0.20261004180939-a10df75c260c`.
Source: the Go module distribution, without Git history.
Keep the upstream `LICENSE` and `LICENSE.uquic` intact.

Local patch inventory:

- `QUICFingerprint` selection and configuration propagation; legacy
  `ChromeParrot` remains available. Firefox requires a dedicated transport
  with 3-byte source IDs and `AllowQUICBitGrease` enabled.
- Firefox 116A/B/C ClientHello adapted from uquic commit
  `837c7ce1b72bf07b2d29b3dabd5b45c60bec0f42` (`u_parrot.go`, MIT).
  Reuse the existing uTLS adapter and retain disabled resumption/0-RTT.
- Firefox transport parameter serialization, 8/9/15-byte initial destination
  IDs, single-byte first packet number, unscrambled CRYPTO, and external
  datagram padding to 1357 bytes.
- Per-connection active CID limit, asymmetric stream receive windows,
  advertised 20 ms ACK delay / 19 ms timer, and 1200-byte DATAGRAM limit.
- Opt-in RFC 9287 fixed-bit receive handling and separate 65527-byte receive
  buffers, preserving AEAD authentication and ordinary buffer pools.
- Wire, runtime, large-receive, Retry/loss/HelloRetryRequest tests. The upstream
  Windows socket tests needed their missing third `newConn` argument fixed.
- Pin uTLS to the same revision as the Bimeron root module.

Run tests in this module explicitly; root `go test ./...` excludes nested
modules. When rebasing, review the patch inventory, rerun wire expectations
and unmodified-server integration, and preserve default Chrome behavior.
The explicit `chrome` name pins this snapshot's existing ChromeParrot behavior;
it does not claim equivalence to uquic Chrome 115/146.
