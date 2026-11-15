# Bimeron Core documentation

Start with the [project README](../README.md). The guides below describe the Git
revision you are viewing; for a release package, read the documentation at that
release's tag.

## Using and integrating the core

### Profiles and routing

- [Configuration reference](CONF.MD): the `.conf` format, every section and option, and CLI commands.
- [GeoIP and GeoSite API](GEODATA.MD) and [GUI routing contract](GUI_GEODATA_ROUTING.MD).
- [DNS metadata for domain rules](DNS_METADATA.MD).
- [Errors and the error catalog](ERRORS.MD).

### Upstream protocols

- [Shadowsocks transports](SHADOWSOCKS_TRANSPORTS.MD), [ShadowTLS v3](SHADOWTLS.MD).
- [VLESS transports](VLESS_TRANSPORTS.MD), [VMess transports](VMESS_TRANSPORTS.MD), [Trojan transports](TROJAN_TRANSPORTS.MD).
- [MASQUE](MASQUE.MD), [SSH](SSH.MD).
- Hysteria2, TUIC v5, AnyTLS, NaiveProxy, SOCKS5, and HTTP CONNECT are covered in the [configuration reference](CONF.MD).

### Platforms and operation

- [Windows daemon](DAEMON.MD), [system service](SERVICE.MD), [kill switch](KILLSWITCH.MD), and [diagnostics](DOCTOR.MD).
- [Linux and WSL2](LINUX.MD), [macOS](MACOS.MD).
- [Experimental Windows IKEv2](IKEV2.MD) and its [foreground control contract](IKEV2_FOREGROUND_CONTROL.MD).

### Integration

- [GUI integration](GUI_INTEGRATION.MD) and the [local control protocol](CONTROL.MD).
- [Go API](CORE.MD) and [desktop document CLI API](DESKTOP_DOCUMENT_API.MD).
- [Android packet core](ANDROID_VPN_SERVICE.MD), [Android SSH authentication](android-ssh-auth.md),
  [SSConf resolver](ssconf.md), and [SSConf snapshots](android-ssconf-snapshot.md).
- [Apple NetworkExtension](APPLE_NETWORK_EXTENSION.MD).

### Building and releasing

- [Building and packaging](BUILDING.md) and [CI checks](CI.MD).
- [Signed service update releases](RELEASE_UPDATES.md) and the [Apple update manifest](apple-update-manifest.md).

## Architecture decisions

[Architecture decision records](adr/README.md) explain lasting decisions, the
alternatives considered, and their tradeoffs.

## Design records

Specifications, research, and validation records written while designing and
verifying features. They capture context and evidence for maintainers and may
describe proposals that were never implemented; check each record's status line.
The user guides above take precedence.

### Specifications and proposals

- [Signed desktop service updates](UPDATE_SPEC.md)
- [Apple NetworkExtension release with a paid developer team](APPLE_PAID_DEVELOPER_SPEC.MD)
- [Apple Core artifact readiness](workstreams/apple-core-release-readiness/decision-packet.md)
- [Core maintenance contract](workstreams/core-maintenance-contract/contract.md) and its [model results](workstreams/core-maintenance-contract/model-results.md)
- [Privileged repair session](REPAIR_SESSION.md)
- [Native IKEv2 authentication](IKEV2_AUTH_CONTRACT.md)
- [Protected installation and first GUI IKEv2 contract](IKEV2_INSTALLATION_CONTRACT.MD)
- [IKEv2-safe Core maintenance](IKEV2_SAFE_MAINTENANCE_SPEC.md)
- [IKEv2 offline error draft](ikev2-offline-error-draft.md) and its [raw JSON addendum](ikev2-offline-error-raw-addendum.md)
- [Native enrollment primitives](NATIVE_ENROLLMENT_SPEC.MD)
- [Foreground owner lifecycle correction plan](FOREGROUND_OWNER_LIFECYCLE_PLAN.MD)

### Research

- [ShadowTLS v3 compatibility](SHADOWTLS_V3_RESEARCH.md)
- [Hysteria2 QUIC fingerprints](HYSTERIA2_QUIC_FINGERPRINT_PLAN.md) and [versioned Chrome fingerprints](HYSTERIA2_CHROME_FINGERPRINT_PLAN.md)
- [Windows VPN network API migration study](WINDOWS_NATIVE_NETWORK_API_DESIGN.MD)
- [XHTTP intermittent upstream failures](XHTTP_INSTABILITY_INVESTIGATION.MD)
- [SSH authentication reply lifecycle](workstreams/guarded-ssh-auth-reply/research.md)
- [Session-bound statistics](../research/session-bound-statistics.md)
- [Apple Core binary provenance](../research/apple-core-provenance/README.md)

### Validation records

- [Historical validation baseline](BASELINE.MD)
- [Windows IKEv2 live validation](IKEV2_LIVE_VALIDATION.MD)
- [IKEv2 foreground control validation](IKEV2_FOREGROUND_VALIDATION.MD)
- [RAS 668 cleanup](IKEV2_RAS_668_CLEANUP.MD)
- [Native enrollment validation](NATIVE_ENROLLMENT_VALIDATION.MD)
