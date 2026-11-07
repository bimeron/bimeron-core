# Android SSConf resolver

Issue #95 adds a single-use operation independent of Session.Start and storage:

- NewSSConfRequest(source, networkID, dns string, sockets SSConfSocketProtector) (*SSConfRequest, error)
- SSConfSocketProtector.Protect(fd int) bool and Bind(fd int) bool
- request.Resolve() (*SSConfResult, error)
- request.Cancel()
- result.Content() []byte
- result.Metadata() string

Construction performs no networking. Supply an ssconf URL, a nonempty physical network ID, and one to four comma-separated IPv4 DNS addresses. There is no OS DNS fallback. The host must capture the exact physical Network in Bind. Every DNS and HTTPS socket invokes Protect before Bind; The first protection, binding, or socket control failure terminates the entire request, including subsequent socket attempts. Callbacks are synchronous and must return promptly: cancellation cannot forcibly interrupt host callback code.

Resolve has a 15-second total deadline, verified HTTPS, the existing redirect policy (reject when len(via) >= 5, non-HTTPS, or user information), a 64 KiB response header limit, and a 64 KiB decoded body limit. ParseConfig validates the complete body before publication. Errors contain no source or credentials. Content returns a defensive copy; metadata is fixed-schema JSON containing only the byte count.

Resolve is single-use, including failures. Cancel is idempotent and concurrent-safe; cancellation before success publication prevents success. Cancellation after success cannot mutate returned bytes. Hosts still need guards against stale results after network or lifecycle changes.

This resolves configuration; it does not perform a proxy protocol handshake. Android API 26 binding requires a duplicated descriptor. Service-owned protection while the VPN is stopped remains a host integration concern. No Android SDK or device validation is included here.
