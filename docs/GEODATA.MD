# GeoIP and GeoSite API

Tracking: issue #67. See [GUI routing contract](GUI_GEODATA_ROUTING.MD) and
[ADR 0030](adr/0030-explicit-geodata-host-bindings.md).

## Configuration and datasets

```ini
[GeoData]
GeoIPFile = data/geoip.dat
GeoSiteFile = data/geosite.dat
[Routing]
Default = direct
[Rule]
GeoIP = ru, by
Action = direct
[Rule]
GeoSite = github
Action = proxy
```

Each active rule has exactly one CIDR, Domain, GeoIP or GeoSite matcher and one
direct, proxy or block action. Comma-separated identifiers mean OR. All rule
types share first-match order; an unknown active group or empty identifier is
an error. Commented disabled rules do not require datasets. Preserve disabled
blocks and comments in the document editor rather than reconstructing them
from executable policy.

The schema identifier is `v2ray-protobuf`: V2Ray GeoIPList and GeoSiteList
protobuf messages, not arbitrary files with a `.dat` extension. The wire fields
are verified against the [V2Ray v4 schema](https://github.com/v2fly/v2ray-core/blob/v4.45.2/app/router/config.proto)
and [V2Ray v5 schema](https://github.com/v2fly/v2ray-core/blob/master/app/router/routercommon/common.proto). GeoIP supports
IPv4/IPv6 CIDRs and reverse-match groups. GeoSite supports plain substring,
regular expression, domain suffix and full domain entries (types 0 through 3).
Attribute metadata is ignored; attribute selectors are unsupported. Group IDs
are normalized to lowercase; enumeration returns sorted stable identifiers.
Malformed protobuf, invalid entries, duplicate groups and unsupported selectors
must be corrected before startup. The shared decoder limits each dataset to
64 MiB. Across the supplied resources it permits at most 100,000 groups and
2,000,000 group/entry records, 4,096 bytes per string, 10,000 regular expressions
and 1 MiB of total regex text. Group identifiers allow ASCII letters, digits,
hyphens and underscores, up to 256 bytes. Empty or group-free resources mean
unavailable data. Unknown protobuf fields are skipped after framing validation;
deprecated protobuf groups are rejected. No dataset downloads
or updates occur here.

File-based `core.LoadConfig(path)` resolves relative dataset paths against the
profile directory. Absolute paths refer to that host's filesystem; the service
must have permission to read them. Export referenced files with portable
profiles or report missing dependencies. `core.LoadConfigData` retains its
no-file-access contract. Sandboxed hosts must read approved resources themselves
and provide explicit bytes; `[GeoData]` paths are metadata in that API and do
not authorize hidden filesystem or network access. Empty dataset bytes mean
unavailable data, not a request to open a path.

## Go API

```go
core.LoadConfigDataWithGeoData(data, geoIP, geoSite []byte) (core.SessionConfig, error)
core.GeoDataGroups(kind string, data []byte) ([]string, error)
core.ValidateConfigDataWithGeoData(data, geoIP, geoSite []byte) error
```

Use `kind = "geoip"` or `"geosite"`. Validation performs no networking and
returns an error for an unrunnable profile. Loading returns a configuration or
an error; neither validation nor enumeration starts a session. Errors include
human-readable diagnostics. Geodata failures support
`errors.As(err, &details)` with `var details *core.GeoDataError`. Its JSON fields
are `code`, `kind` (`geoip` or `geosite`), optional `group` and optional `rule`. Rule is one-based;
absence means a dataset-level failure. Codes are `geodata_invalid`,
`geodata_limit`, `geodata_group_unknown`, `geodata_required`,
`geodata_identifier_invalid` and `geodata_unreadable` (file loading). Use these
fields to associate dataset/group/rule
controls; do not parse error text. Generic configuration and host restrictions
need not have typed details. Retain the draft and show errors without logging
profile credentials. There are no new RPC commands.

Capabilities use `geoip_split`, `geosite_split` and `geodata_schema` JSON fields
(`GeoIPSplit`, `GeoSiteSplit`, `GeoDataSchema` in Go). Check explicit flags and
the recognized schema, not versions or the older IP/domain flags. Backend
restrictions still apply even when dataset decoding is supported.

## Android gomobile

```go
androidcore.NewSessionWithGeoData(profile, geoIP, geoSite []byte, protector androidcore.SocketProtector) (*androidcore.Session, error)
androidcore.GeoDataGroups(kind string, data []byte) string
androidcore.ValidateConfigWithGeoData(profile, geoIP, geoSite []byte) string
androidcore.Capabilities() string
```

Constructors return gomobile errors on failure. `NewSession` delegates to the
same constructor with absent datasets. A socket protector remains mandatory.
Group enumeration returns `{"groups":["github"],"error":null}`; an empty result
is `[]`. Validation returns `{"groups":null,"error":null}` on success. Failures
return an `error` string and, for typed geodata failures, a `details` object
with the fields above; groups must not be used after an error. Generic errors
omit `details`. Capabilities
returns the embedded Android packet backend's capability JSON.

## Apple C ABI

The generated `libBimeronCore.h` declares these functions (`void *` buffers are
input bytes; lengths are signed `int`):

```c
unsigned long long RLCreateWithGeoData(void *profile, int profileSize,
    void *geoIP, int geoIPSize, void *geoSite, int geoSiteSize);
char *RLGeoDataGroups(char *kind, void *data, int size);
char *RLValidateConfigWithGeoData(void *profile, int profileSize,
    void *geoIP, int geoIPSize, void *geoSite, int geoSiteSize);
char *RLCapabilities(void);
void RLFree(void *ptr);
```

`kind` is a NUL-terminated string. Each dataset is limited to 64 MiB at the C
boundary. Negative lengths, oversized buffers and nonzero lengths with NULL
pointers are rejected before copying. NULL with zero length means absent data.
Profiles retain the existing 65,536-byte limit. The caller must supply valid
readable memory for every declared length until the function returns.

Creation returns zero on failure and a nonzero session handle on success;
`RLCreate` retains its existing behavior and shares instance creation logic.
Use validation to obtain diagnostics before creation. Enumeration, validation
and capabilities return allocated JSON strings; release every result with
`RLFree`. Groups and validation use the same JSON envelopes as Android,
including allocated error JSON for invalid C buffer arguments. Capabilities
reports the embedded Apple packet backend. Stop session handles with `RLStop`.

## Runtime restrictions

Android and Apple embedded packet hosts require VPN mode and forbid the core
kill switch and IKEv2, including when no geodata rules are present. Elsewhere a packet
VPN kill switch permits CIDR rules only: active Domain/GeoIP/GeoSite rules must
be rejected. IKEv2 lacks split routing. Never silently disable protection or
rewrite an imported profile to bypass a conflict. IPv6 disable remains dominant.

Dataset contents are frozen for the session, including reconnects. Replacing
files or changing supplied bytes requires a new session; show restart required
in the GUI. GeoIP only matches known destination IPs. SOCKS domain requests do
not trigger implicit local resolution for GeoIP; later rules or Default apply
when the IP is unknown. GeoSite in packet VPN uses existing trusted, bounded
DNS metadata and retains TTL, shared-IP and cache limitations. Bare IP traffic,
application DoH/DoT and old DNS caches may have no usable domain metadata.
