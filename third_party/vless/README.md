# VLESS client source attribution

The following Bimeron files adapt client protocol behavior from Xray-core
v1.260327.0 (commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`):

- `internal/vless/reality.go` from `transport/internet/reality/reality.go`;
- `internal/vless/vision.go` from `proxy/proxy.go`;
- `internal/vless/wire.go` from `proxy/vless/encoding/encoding.go` and `addons.go`;
- `internal/vless/packet.go` from `common/xudp/xudp.go`.

These files were modified for Bimeron's `net.Conn` and `net.PacketConn` transport
interfaces. The client-only REALITY code uses uTLS and Go cryptographic
libraries. Xray-core and `xtls/reality` are not module dependencies. The
adapted files remain under MPL 2.0; see [LICENSE](LICENSE). Other Bimeron
files remain under the repository MIT license unless otherwise stated.
