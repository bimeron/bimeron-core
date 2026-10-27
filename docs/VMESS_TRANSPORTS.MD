# VMess AEAD transport matrix

This matrix is based on Xray-core `v1.260327.0` and local reference-server
tests. It describes the Bimeron share-link importer, not every Xray JSON option.

| Network in `vmess://` JSON | Security | Status | Link fields |
| --- | --- | --- | --- |
| `tcp` | TLS | Supported | `sni`, optional `alpn` and `fp` |
| `ws` | TLS | Supported | `path`, optional `host`, `sni`, `alpn`, `fp` |
| `httpupgrade` | TLS | Supported | `path`, optional `host`, `sni`, `alpn`, `fp` |
| `grpc` | TLS | Supported | `path` as service name, optional `host` as authority, `mode=multi`, `sni`, `alpn`, `fp` |
| `xhttp` | TLS over HTTP/2 | Supported | `path`, optional `host`, `mode=auto`, `packet-up`, or `stream-up`, `sni`, `alpn`, `fp` |
| `tcp`, `grpc`, `xhttp` | REALITY | Later phase | Needs separate handshake and transport verification |
| `mkcp`, `hysteria` | Protected combinations | Later phase | Needs protection and UDP transport assessment |

The supported rows use VMess AEAD with `aid=0` and `scy=auto`, `aes-128-gcm`,
or `chacha20-poly1305`. The core supports TCP and UDP upstream requests on
each supported network. TLS certificates are verified. WebSocket and
HTTPUpgrade require ALPN `http/1.1` when explicitly set; gRPC and basic XHTTP
require `h2`. An omitted ALPN selects the transport default.

Xray accepts `raw`/`tcp`, XHTTP, mKCP, gRPC, WebSocket, HTTPUpgrade, and
Hysteria transport names. It rejects the removed HTTP/2 and QUIC transports.
Legacy `alterId > 0` and unprotected connections are outside this project
scope. Bimeron rejects unsupported networks, modes, and unknown share fields
during import rather than silently changing the transport.

Reference: Xray-core `infra/conf/transport_internet.go` at `v1.260327.0`.
