# Architecture decision records

Each ADR records one lasting decision: its context, the alternatives
considered, and the tradeoffs. The status line at the top of each record says
whether it is accepted, amended, or superseded.

Numbers 0006 and 0021 to 0026 were each assigned to two records. The
files are kept as they are so that existing links keep working;
refer to these records by file name. New records continue from the highest
number.

| ADR | Decision |
| --- | --- |
| 0001 | [Select upstream transports by profile type](0001-upstream-protocols.md) |
| 0002 | [Signed manifests and service update health checks](0002-signed-service-updates.md) |
| 0003 | [Publish prepared release bytes](0003-publish-prepared-release-bytes.md) |
| 0004 | [Embed a focused VLESS client without GPL dependencies](0004-vless-client-without-gpl.md) |
| 0005 | [Extend the focused VLESS client with TLS and WebSocket](0005-vless-tls-websocket.md) |
| 0006 | [Support Trojan over TCP/TLS with UDP relay](0006-trojan-client.md) |
| 0006 | [Add focused VLESS HTTP transports](0006-vless-http-transports.md) |
| 0007 | [Use interface-bound QUIC for XHTTP over HTTP/3](0007-vless-xhttp-http3.md) |
| 0008 | [Model extended XHTTP settings without importing Xray-core](0008-vless-xhttp-extended-settings.md) |
| 0009 | [Use the upstream Hysteria2 client](0009-hysteria2-client.md) |
| 0010 | [Extend apernet QUIC with Hysteria2 handshake presets](0010-hysteria2-quic-fingerprints.md) |
| 0011 | [Versioned Chrome QUIC presets](0011-versioned-chrome-quic.md) |
| 0012 | [TUIC v5 with QUIC stream UDP relay](0012-tuic-v5-quic-stream-relay.md) |
| 0013 | [Built-in SSH TCP upstream](0013-ssh-tcp-proxy.md) |
| 0014 | [Add a focused VMess AEAD client](0014-vmess-aead-client.md) |
| 0015 | [Share stream transports between VLESS and VMess](0015-share-vless-vmess-transports.md) |
| 0016 | [Require protected VMess transport and reliable UDP boundaries](0016-vmess-udp-transport-limits.md) |
| 0017 | [TCP-only system VPN mode for SSH](0017-ssh-tcp-only-vpn.md) |
| 0018 | [Safe Hysteria2 connection failures](0018-safe-hysteria2-failures.md) |
| 0019 | [Implement a focused AnyTLS client](0019-anytls-client.md) |
| 0020 | [Implement the single-user Shadowsocks 2022 client](0020-shadowsocks-2022-client.md) |
| 0021 | [Embed a NaiveProxy-compatible HTTP/2 client](0021-embedded-naiveproxy-client.md) |
| 0021 | [HTTP CONNECT upstream](0021-http-connect-upstream.md) |
| 0022 | [Embed the Shadowsocks v2ray-plugin WebSocket client](0022-embedded-shadowsocks-v2ray-plugin.md) |
| 0022 | [Share gRPC transport ownership and add Trojan HTTP transports](0022-shared-grpc-trojan-transports.md) |
| 0023 | [Verified TLS for HTTP CONNECT proxies](0023-https-connect-proxy.md) |
| 0023 | [Native IKEv2/IPsec session backend](0023-native-ikev2-system-vpn.md) |
| 0024 | [Add an optional strict ShadowTLS v3 stream wrapper](0024-shadowtls-v3-wrapper.md) |
| 0024 | [Explicit Windows IKEv2 profile preparation](0024-windows-ikev2-profile-provisioning.md) |
| 0025 | [Extend the SS2022 client with SIP023 identity chains](0025-shadowsocks-2022-identity-chains.md) |
| 0025 | [Windows IKEv2 DNS and persistent traffic protection](0025-windows-ikev2-dns-and-traffic-protection.md) |
| 0026 | [Authenticated Windows IKEv2 foreground control](0026-authenticated-ikev2-foreground-control.md) |
| 0026 | [Explicit NaiveProxy HTTP/3 CONNECT](0026-naiveproxy-http3.md) |
| 0027 | [Embed a focused simple-obfs client](0027-embedded-simple-obfs-client.md) |
| 0028 | [MASQUE CONNECT-UDP over HTTP/3](0028-masque-connect-udp.md) |
| 0029 | [Disabled native enrollment and offline admission primitives](0029-disabled-native-enrollment-primitives.md) |
| 0030 | [Explicit geodata resources for embedded hosts](0030-explicit-geodata-host-bindings.md) |
| 0031 | [Separate Apple update preparation](0031-separate-apple-update-manifest.md) |
| 0032 | [Retained Apple Core release version](0032-retained-apple-core-version.md) |
| 0033 | [Additive session-bound statistics](0033-session-bound-statistics.md) |
| 0034 | [Bounded internal maintenance coordinator](0034-internal-maintenance-coordinator.md) |
| 0035 | [Structured problems and a shared error catalog](0035-structured-problems-and-shared-catalog.md) |
| 0036 | [Android SSH uses only profile-selected files](0036-android-ssh-profile-files-only.md) |
| 0037 | [Opt-in accept-new SSH host keys](0037-ssh-accept-new-host-keys.md) |
| 0038 | [Core icon and Windows resources](0038-core-icon-and-windows-resources.md) |
| 0039 | [Reconnect cycles and a held kill switch](0039-reconnect-cycles-and-held-kill-switch.md) |
| 0040 | [Signed versioned core store and anti-rollback floor](0040-signed-core-store.md) |
| 0041 | [Keep kill switch protection across a client-requested service update](0041-kill-switch-across-service-updates.md) |
