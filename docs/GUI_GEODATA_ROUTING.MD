# GUI contract: GeoIP and GeoSite routing

Status: implemented in development source for [issue #67](https://github.com/bimeron/bimeron-core/issues/67); not yet released.
Configuration and embedded APIs are described in [GEODATA.MD](GEODATA.MD). No new RPC commands are introduced. GUI controls remain work for the separate GUI projects.
GUI implementations belong in their platform repositories. See
[GUI_INTEGRATION.MD](GUI_INTEGRATION.MD) for the current integration contract.

## Configuration mapping

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
GeoSite = github, youtube
Action = proxy

# [Rule]
# GeoSite = category-ads-all
# Action = block
```

One table row maps to one `[Rule]` block. Each active rule has exactly one
matcher (`CIDR`, `Domain`, `GeoIP`, or `GeoSite`) and one action (`direct`,
`proxy`, or `block`). GeoIP/GeoSite identifiers separated by commas mean OR;
empty entries and unknown identifiers are errors. All types share first-match
order. Moving a row moves its complete block, including its disabled state.

The type selector offers IP/CIDR, domain, countries (GeoIP), and site groups
(GeoSite). Geodata destinations use searchable multiple selection populated
from the selected dataset. Show localized labels and stable identifiers;
serialize identifiers only. Fall back to identifiers when labels are absent.
Initially, support one local file per dataset type. The supported schema is `v2ray-protobuf`, as documented in GEODATA.MD; the extension
alone does not guarantee compatibility. Automatic downloads are outside scope.

## Disabled rules and preservation

There is no `Enabled` option. Unchecking comments every nonblank line of the
block, including `[Rule]`, with `#`. Rechecking removes the single outer comment
layer added for disabling, preserving original comments.

Recognize a candidate starting with `# [Rule]` (allow whitespace), followed by
commented rule fields until the next section or disabled-rule header. Only
interpret it as a disabled row when removing one outer comment layer yields a
structurally valid rule. Otherwise preserve it as ordinary comment text.
Well-formed commented examples follow this convention and may appear as rows.
Disabled rules do not match traffic or require their datasets to be installed.
Validate them when enabling; retain their values and positions meanwhile.

Use a document-preserving editor model separate from executable policy. The
current runtime parser ignores comments and cannot reconstruct disabled rows.
Table/raw/table transitions must preserve comments and disabled blocks. Preserve
unknown fields; if the table cannot represent them safely, retain raw editing
and block destructive table serialization with an explanation.

## GUI restrictions

Prevent unsupported combinations before Apply/Start. Core must independently
validate active combinations from raw edits, imports and other clients.

| Condition | GUI requirement |
|---|---|
| Core has not explicitly advertised geodata support | Disable creation/enabling of GeoIP/GeoSite rules. Preserve imported content and explain the missing support. Existing `ip_split` and `domain_split` flags do not imply geodata support. |
| Backend lacks split routing, including current IKEv2 | Disable creation/enabling of split rules; prevent Apply/Start with active incompatible rules. |
| Packet VPN with `KillSwitch = true` | Initially prohibit active GeoIP/GeoSite rules. Retain the existing prohibition on active Domain rules: the current kill switch supports CIDR rules only. |
| User enables kill switch with incompatible active rules | Explain the conflict. Require an explicit choice to cancel or disable the affected rules. Never silently remove rules or disable protection. |
| User enables an incompatible rule with kill switch active | Prevent enabling; explain that kill switch must be explicitly turned off or the rule kept disabled. |
| Proxy mode | Disable packet VPN kill-switch controls. GeoIP applies only to known destination IPs; do not implicitly resolve domains locally. |
| GeoSite in system VPN | Require domain-routing support for the selected host/backend; explain DNS metadata limitations. |
| Active rule has missing/unreadable/malformed dataset or unknown group | Show a field/row error and prevent Apply/Start; retain values for correction. |
| Disabled rule has unavailable dataset/group | Preserve it with an informational state; validate before enabling. |
| `IPv6 = disable` | Explain that IPv6 remains blocked; geodata actions cannot override this setting. |
| Imported/raw-edited profile has incompatible settings | Preserve contents, show conflicts and prevent Apply/Start until resolved. Never silently rewrite the policy. |

Show a visible reason for unavailable choices, not only a tooltip. Raw drafts
may be retained but must not replace validated runnable profiles through
Apply/Start. Unchanged disabled rules must not prevent editing supported rules.

SOCKS domain requests can match Domain/GeoSite. Without a known IP, GeoIP does
not match; later rules or Default apply. Do not promise geographic matching for
every SOCKS domain request. VPN GeoSite uses existing bounded trusted DNS
metadata: TTL, shared-IP and cache limitations remain; application-owned DoH/DoT,
old DNS caches and bare IPs provide no domain metadata.

The existing ignore-local-network checkbox receives no new `.conf` field here.
Its ranges and precedence require a separate explicit cross-platform contract.

## Dataset management and core integration

Provide a dataset-management view with selected files, validation state and
available groups. Resolve relative paths against the profile directory, not the
GUI working directory. Absolute paths are host-local. Portable export must
include referenced files or explicitly report missing dependencies.

Files must be readable by the actual core service/host, not merely the GUI.
Sandboxed embedding needs an explicit dataset-bytes/resource API. Preserve
`LoadConfigData`'s no-file-access contract; do not add hidden filesystem reads.
Validate datasets and referenced active groups before startup. Contents remain
fixed during the session, including reconnects. File replacements take effect
at the next session start; GUI should indicate that a restart is required.

Use the support discovery, group enumeration and validation APIs documented in GEODATA.MD. Do not invent RPC commands or infer support from a version
string. Associate errors with dataset/group/rule controls without exposing secrets.

## Acceptance checks

- Table/raw/table preserves order, identifiers, comments and disabled blocks;
  repeated toggles do not accumulate comment prefixes.
- Malformed commented candidates remain intact as comments.
- Test every restriction above, both directions of kill-switch conflicts and
  imported/raw-edited profiles. Core independently rejects invalid combinations.
- Missing capabilities disable new controls while preserving imported content;
  localization never changes serialized identifiers.
- Test dataset replacement, unknown groups, service access and sandbox loading;
  disabled rules remain recoverable without installed datasets.
- Verify mixed-rule first-match behavior, SOCKS unknown-IP behavior and VPN DNS
  metadata limitations.

## Document editor API

Use core.ParseConfigDocument with Bytes, RuleCount, Rule and RulesJSON to inspect
a draft. SetRuleEnabled toggles a block, SetRule edits its matcher and action,
and MoveRule changes order. These APIs never access files or validate dataset
membership; validate the resulting runnable profile before Apply/Start. Unknown
fields block unsafe edits/enabling. Quoted values are decoded; edits may normalize
their quote formatting. GUI JSON row enabled is editor state, not a .conf option.

Desktop CLI consumers can use the non-networking document and local catalog
commands in [DESKTOP_DOCUMENT_API.MD](DESKTOP_DOCUMENT_API.MD). This extends
ConfigDocument with InsertRule, DeleteRule and SetSectionField; no new RPC exists.

Identifier compatibility (2026-11-02): group IDs contain 1–256 ASCII letters,
digits, `_`, `-` or `!`; normalize ASCII case for lookup/enumeration. A bang is
a literal stable identifier character, never policy negation. Preserve it in
selection and serialization (for example `category-games-!cn`). Attribute
selectors (`@`), controls, non-ASCII and empty IDs remain invalid. The V2Ray
schema stores country_code as a string independently of Domain attributes;
Loyalsoldier uses bang-bearing category names. Expand only this alphabet,
without filtering IDs or changing matcher semantics. ConfigDocument enforces
the same syntax before editing; dataset membership remains runtime validation.
