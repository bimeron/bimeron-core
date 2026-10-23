# Core v0.2.0-beta.1 local candidate

The VLESS input and transport contract is in [VLESS_TRANSPORTS.MD](VLESS_TRANSPORTS.MD). The supported combinations are TCP/TLS, TCP/REALITY with optional Vision flow, WebSocket/TLS, gRPC/TLS or REALITY, XHTTP/TLS or REALITY, and XHTTP over HTTP/3 with TLS. Unsupported combinations fail validation. Links and explicit profile version 1 fields use the same validation path; proxy and VPN modes retain IPC protocol 1.

## Acceptance criteria

- `go test ./...` and `go vet ./...` pass on the candidate commit.
- Windows and Linux amd64 and arm64 builds contain the candidate version and revision. ZIP assets contain the expected executable and third-party notices; Windows also contains Wintun and its license.
- Representative VLESS links and explicit fields pass `validate` without network or system changes. Invalid transport/security combinations fail.
- IPC 1, profile format 1, installed service update staging, digest and identity checks, health check, and rollback tests pass. No live installed service or active VPN is changed during candidate preparation.
- The GUI update verifier accepts a signed manifest and all four desktop ZIPs at GUI version 0.2.0, and rejects altered signatures, hashes, unsafe paths, wrong architectures, and incompatible bounds. The installed GUI must bundle a trusted updater that supports `service update -source`.
- The release signing key matches the public key pinned in the GUI package. `gui_reviewed` becomes true only after verification against the actual GUI 0.2.0 package and its update and rollback flow.

The proposed GUI range is `[0.2.0, 0.2.1)` with IPC 1 and profile format 1. It is provisional while `gui_reviewed` is false. A manifest carrying this flag is intentionally rejected by GUI update discovery and by the release publisher.

## Remaining live interoperability checks

One XHTTP/TLS `packet-up` profile has passed TCP/TLS and UDP/DNS checks. Four available XHTTP/REALITY `stream-one` profiles timed out during response checks; their interoperability remains unresolved. gRPC/TLS and REALITY, XHTTP `stream-up`, `stream-one`, `auto`, `downloadSettings`, HTTP/3, and mobile system VPN require working control profiles and target devices. Repeat TCP, UDP, close, and reconnect checks for each transport. Never include control profile credentials in release assets or reports.
