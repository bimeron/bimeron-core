# VMess AEAD transport matrix

This matrix is based on Xray-core `v1.260327.0` and local reference-server
tests. It describes the Bimeron share-link importer, not every Xray JSON option.

| Network in `vmess://` JSON | Security | Status | Link fields |
| --- | --- | --- | --- |
| `tcp` | TLS | Supported | `sni`, optional `alpn` and `fp` |
| `ws` | TLS | Supported | `path`, optional `host`, `sni`, `alpn`, `fp` |
| `httpupgrade` | TLS | Supported | `path`, optional `host`, `sni`, `alpn`, `fp` |
| `grpc` | TLS | Supported | `path` as service name, optional `host` as authority, `mode=multi`, `sni`, `alpn`, `fp` |
| `xhttp` | TLS over HTTP/2 | Supported | `path`, optional `host`, `mode=auto`, `packet-up`, `stream-up`, or `stream-one`, `extra`, `sni`, `alpn`, `fp` |
| `xhttp` | TLS over HTTP/3 | Supported | `alpn=h3`, `path`, optional `host`, `mode=auto`, `packet-up`, `stream-up`, or `stream-one`, `extra`, `sni`; no `fp` |
| `tcp` | REALITY | Supported | `sni`, `fp`, `pbk`, optional `sid` and `spx` |
| `grpc` | REALITY | Supported | gRPC fields plus `sni`, `fp`, `pbk`, optional `sid` and `spx` |
| `xhttp` | REALITY over HTTP/2 | Supported | XHTTP fields plus `sni`, `fp`, `pbk`, optional `sid` and `spx`; `mode=auto`, `stream-up`, or `stream-one` |
| `kcp`/`mkcp`, `hysteria` | Protected combinations | Unsupported | See [ADR 0016](adr/0016-vmess-udp-transport-limits.md) |

The supported rows use VMess AEAD with `aid=0` and `scy=auto`, `aes-128-gcm`,
or `chacha20-poly1305`. The core supports TCP and UDP upstream requests on
each supported network. TLS certificates are verified; REALITY authenticates
the server with its public key and requires a client fingerprint. WebSocket
and HTTPUpgrade require ALPN `http/1.1` when explicitly set; gRPC uses HTTP/2.
XHTTP accepts `h2` or `h3` over TLS. An omitted ALPN selects the transport
default. XHTTP `extra` is a JSON string with the validated settings described
in [XHTTP transport options](VLESS_TRANSPORTS.MD).

Xray accepts `raw`/`tcp`, XHTTP, mKCP, gRPC, WebSocket, HTTPUpgrade, and
Hysteria transport names. It rejects the removed HTTP/2 and QUIC transports.
Legacy `alterId > 0` and unprotected connections are outside this project
scope. `scy=zero` is rejected because it loses UDP packet boundaries in the
VPN's stream-to-packet adapter; a local Xray test merged two datagrams.
Bimeron rejects unsupported networks, modes, and unknown share fields during
import rather than silently changing the transport.

Reference: Xray-core `infra/conf/transport_internet.go` at `v1.260327.0`.
