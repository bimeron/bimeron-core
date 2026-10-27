# VMess client source attribution

`internal/vmess/wire.go` adapts the VMess AEAD request header, authentication ID,
KDF, response header, and authenticated body framing from Xray-core
v1.260327.0 (commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`):

- `proxy/vmess/aead/authid.go`, `encrypt.go`, `kdf.go`, and `consts.go`;
- `proxy/vmess/encoding/auth.go` and `client.go`;
- `common/protocol/id.go`, `address.go`, and `headers.go`;
- `common/crypto/auth.go`.

The code was modified for Bimeron's `net.Conn` and `net.PacketConn`
interfaces and limited to current AEAD profiles. Xray-core is not a module
dependency. The adapted file remains under MPL 2.0; see [LICENSE](LICENSE).
Other Bimeron files remain under the repository MIT license unless otherwise
stated.
