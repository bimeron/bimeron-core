# Android SSConf snapshots

Create a snapshot with NewSSConfSnapshot(source, content), then pass the original
full configuration, snapshot, optional geodata bytes and socket protector to
NewSessionWithSSConfSnapshot. Both calls are synchronous and local. Construction
does not start the session or invoke the protector; call SetNetwork and Start
afterward.

The source must be a lowercase ssconf:// URL with a host, no user information,
and a valid nonzero port when supplied. Identity is the exact source after
strings.TrimSpace, including its fragment. There is no case normalization,
percent decoding, canonicalization or BOM removal for identity. The decoded
fragment overrides the resolved profile name only.

Content must contain 1 through 65536 bytes of an ss URI or strict Shadowsocks
YAML/JSON supported by the existing access-key parser, including its TCP/UDP and
plugin forms. Nested SSConf and full Bimeron configurations are rejected. Inputs
are copied and parsed immediately. The snapshot exposes no mutable data.

The original configuration must select exactly one matching SSConf source through
SSConf or Key. Sandbox restrictions and Android mode restrictions still apply.
Original routing, DNS, interface, geodata and ShadowTLS settings remain effective.
Both resolver paths return isolated fixed profiles, including after reconnect;
they never fetch an updated body. Refresh by constructing another snapshot and
session.

A typed snapshot proves local validation, not authenticity or freshness. The host
owns source, revision, digest, attempt and lease pairing. Persist the exact source
and body securely, and reload them through NewSSConfSnapshot; do not serialize
the opaque handle. Public errors use fixed categories and contain no supplied
source, credentials, body or parser diagnostics. Failed construction returns nil.
