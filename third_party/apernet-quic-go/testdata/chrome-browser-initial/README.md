# Chrome for Testing QUIC Initial captures

These six UDP datagrams were captured on October 28, 2026 from unmodified
official Chrome for Testing Windows x64 binaries:

- Chrome 115.0.5790.170: `https://storage.googleapis.com/chrome-for-testing-public/115.0.5790.170/win64/chrome-win64.zip`
- Chrome 146.0.7680.165: `https://storage.googleapis.com/chrome-for-testing-public/146.0.7680.165/win64/chrome-win64.zip`

Each browser was launched with a fresh user data directory, `--headless=new`,
`--enable-quic`, `--no-proxy-server`, and
`--origin-to-force-quic-on=fixture.example:<ephemeral-port>`. The resolver rule
mapped `fixture.example` to `127.0.0.1` or `[::1]`. A local UDP listener saved
the first Initial datagram for Chrome 115 and the first two Initial datagrams
with the same destination connection ID for Chrome 146. The listener sent no
response, so authentication, certificate trust, resumption, and server behavior
cannot affect these Initials. The captures contain no user profile or secret.

`TestChromeBrowserCapture` decrypts and reassembles the packets. The captures
show ECH GREASE in both versions, empty trust anchors in Chrome 146, Chrome
146's `ORIG` connection option, no cached RTT hint, and a 300-second idle
timeout. Those fields differ from the pinned uquic reference. Browser patch
versions and command-line settings can change a fingerprint; these captures
establish the values above for these exact binaries and launch conditions.

| File | SHA-256 |
| --- | --- |
| `chrome-115-ipv4-0.bin` | `0a1aa934165f11a153e0965a86bf2eb787206703fce71d19a6c6ed2649db2589` |
| `chrome-115-ipv6-0.bin` | `d9587862bfd416571c929570c9b6b0e866e56a32fa21655419d6d117b0dfa1cc` |
| `chrome-146-ipv4-0.bin` | `a3faea38c5cdc454f227a4b8d69821a82290d7ac64df3c4177e01ad35d757a7d` |
| `chrome-146-ipv4-1.bin` | `c8d71bf6b84b6f96f7ed7a9e744f499cf3b0c42929bbe6737422ce99f801cdf3` |
| `chrome-146-ipv6-0.bin` | `34d96515cb80f6e4ab6774913bed08e2cfd5cefc0c5a06be6625e309c6f6e529` |
| `chrome-146-ipv6-1.bin` | `55537071d77a8de24aed68e1dad07704bca92b81961629fb2bb1ff90cb01af99` |
