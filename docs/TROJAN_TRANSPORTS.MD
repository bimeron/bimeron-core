# Trojan transport compatibility

The implementation target is Xray-core v1.260327.0, commit
`d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`, also pinned in CI.

## Wire contract

All transports carry the existing Trojan request: 56 ASCII hex bytes of
SHA-224(password), CRLF, command (1 for TCP or 3 for UDP), SOCKS-style
address and port, CRLF, then payload. UDP retains address, two-byte big-endian
payload length, CRLF, and payload for each datagram. Transport message
boundaries do not delimit Trojan requests or UDP datagrams.

WebSocket uses verified TLS, HTTP/1.1 Upgrade, and binary frames containing
Trojan bytes. `path` defaults to `/`; `host` defaults to SNI. SNI defaults to
the server address. Host and SNI may differ. Early data (`ed`, including in
the path), custom headers, and additional encryption are unsupported.

Xray gRPC uses verified TLS with HTTP/2 and a bidirectional stream at
`/<serviceName>/Tun`, or `/<serviceName>/TunMulti` for `mode=multi`.
`Hunk` has protobuf bytes field 1; `MultiHunk` has repeated bytes field 1.
Incoming multi chunks are concatenated as a byte stream. `serviceName` is
required and must be a simple name, not a custom method path. `authority`
defaults to SNI and does not change the TLS certificate name. The default
mode is `gun` (single). REALITY, insecure TLS, and TLS fingerprints are
outside this contract.

## Configuration

Existing TCP/TLS links and explicit profiles retain their defaults. URI
options are `type=tcp|ws|grpc`, `security=tls`, `sni`, and `alpn`, plus
`path`/`host` for WS or `serviceName`/`authority`/`mode=gun|multi` for gRPC.
Unknown and duplicate options are rejected. WS requires `http/1.1` and gRPC
requires `h2` when ALPN is explicitly supplied.

Explicit profiles use `Network`, optional `Security = tls`, `ServerName`,
`ALPN`, `WSPath`, `WSHost`, `GRPCServiceName`, `GRPCAuthority`, and
`GRPCMultiMode`. Certificate verification remains mandatory.

## Reference server configurations

Use a Trojan inbound with `settings.clients = [{"password":"replace-me"}]`,
a `freedom` outbound, and one of these `streamSettings` objects. Replace the
certificate paths with a certificate trusted by the client.

```json
{
  "network": "ws",
  "security": "tls",
  "tlsSettings": {
    "certificates": [{"certificateFile":"cert.pem","keyFile":"key.pem"}]
  },
  "wsSettings": {"path":"/trojan","host":"front.example.com"}
}
```

```json
{
  "network": "grpc",
  "security": "tls",
  "tlsSettings": {
    "certificates": [{"certificateFile":"cert.pem","keyFile":"key.pem"}]
  },
  "grpcSettings": {"serviceName":"trojan"}
}
```

The same gRPC inbound accepts single and multi client streams.

## Evidence and scope

Pinned source references:

- [Trojan framing](https://github.com/XTLS/Xray-core/blob/v1.260327.0/proxy/trojan/protocol.go)
- [WebSocket upgrade and early data](https://github.com/XTLS/Xray-core/blob/v1.260327.0/transport/internet/websocket/hub.go)
- [WebSocket byte stream](https://github.com/XTLS/Xray-core/blob/v1.260327.0/transport/internet/websocket/connection.go)
- [gRPC schema](https://github.com/XTLS/Xray-core/blob/v1.260327.0/transport/internet/grpc/encoding/stream.proto)
- [gRPC method naming](https://github.com/XTLS/Xray-core/blob/v1.260327.0/transport/internet/grpc/config.go)

Trojan-Go v0.10.6 also uses an HTTP Upgrade and WebSocket stream in its
[client](https://github.com/p4gefau1t/trojan-go/blob/v0.10.6/tunnel/websocket/client.go)
and [server](https://github.com/p4gefau1t/trojan-go/blob/v0.10.6/tunnel/websocket/server.go).
That source-level similarity is not an interoperability guarantee. Trojan-Go,
its multiplexing and optional encryption extensions are not certified targets
of this change. No Trojan-Go or Xray production module dependency is added.

Run the independent reference test with `BIMERON_XRAY_BIN` pointing to the
pinned Xray executable:

```sh
go test ./internal/trojan -run '^TestXrayTrojanInterop$' -count=1 -v
```

The matrix covers TCP/TLS, WS/TLS, gRPC single/TLS, and gRPC multi/TLS,
each carrying TCP and UDP, including parallel large TCP transfers.
