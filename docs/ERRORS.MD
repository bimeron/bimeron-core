# Structured problems and the error catalog

Decision record: [ADR 0035](adr/0035-structured-problems-and-shared-catalog.md).

Clients must decide on `code` and location, never on the English `message`.

## Problem object

A configuration problem is a JSON object:

```json
{
  "code": "interface_name_invalid",
  "message": "[Interface] Name must start with a letter and contain 1-32 ASCII letters, digits, underscores or hyphens",
  "section": "Interface",
  "field": "Name",
  "line": 7,
  "value": "present",
  "args": {"max": "32"}
}
```

| Field | Presence | Meaning |
|---|---|---|
| `code` | always | Catalog code. Stable; renaming is a breaking change. |
| `message` | always | English diagnostic text for CLI output and logs. Not for decisions. |
| `section` | optional | Profile section without brackets: `Profile`, `Interface`, `AccessKey`, `ShadowTLS`, `IKEv2`, `GeoData`, `Routing`, `Rule`. |
| `field` | optional | Canonical field name, see below. Absent for whole-section or whole-file problems. |
| `related` | optional | Other canonical fields that take part in a combination rule. |
| `source` | optional | `[AccessKey]` option that held the value as a URI or key: `VLESS`, `SS`, `Key`, `File` and similar. Absent for explicit parameters. |
| `rule` | optional | One-based index of the `[Rule]` section in the profile. |
| `line` | optional | One-based profile line of the field, the source option or the section header. |
| `value` | optional | `present` when the field had a non-empty value, `absent` otherwise. Never the value itself. |
| `args` | optional | String-to-string map of safe placeholder values. |

`args` and `message` never contain passwords, user IDs, keys, URIs, user-supplied
host names, file paths or profile fragments. A client already holds the profile
and reads values from its own editor state.

Transports return problems as a list named `problems`. The core currently stops
at the first failure, so the list has zero or one element. Clients must accept
several elements and show them in order.

## Canonical fields

Canonical names are the explicit `.conf` option names. The same check reports
the same `field` whether the value came from explicit parameters or from a URI;
in the URI case `source` names the URI option.

- `Profile`: `Version`, `Name`.
- `Interface`: `Mode`, `Name`, `MTU`, `DNS`, `IPv6`, `KillSwitch`, `Listen`.
- `Routing`: `Default`. `Rule`: `CIDR`, `Domain`, `GeoIP`, `GeoSite`, `Action`.
- `GeoData`: `GeoIPFile`, `GeoSiteFile`. `ShadowTLS`: `ServerName`, `Password`.
- `IKEv2`: the option names documented in [IKEV2.MD](IKEV2.MD).
- `AccessKey` sources: `File`, `Key`, `SS`, `SSConf`, `SOCKS5`, `HTTP`, `VLESS`,
  `VMess`, `Trojan`, `Naive`, `Hysteria2`, `AnyTLS`, `SSH`, `TUIC`, `MASQUE`.
- `AccessKey` parameters: `Type`, `Server`, `Port`, `Method`, `Password`,
  `Prefix`, `Username`, `ServerName`, `Plugin`, `PluginOpts`, `IdentityFile`,
  `KnownHostsFile`, `MASQUEPath`, `CAFile`, `ID`, `Encryption`, `Flow`,
  `Network`, `Security`, `PublicKey`, `ShortID`, `Fingerprint`, `SpiderX`,
  `ALPN`, `WSPath`, `WSHost`, `WSEarlyData`, `GRPCServiceName`,
  `GRPCAuthority`, `GRPCMultiMode`, `XHTTPPath`, `XHTTPHost`, `XHTTPMode`,
  `XHTTPExtra` and the separate `XHTTP*` options.
- Fields that exist only inside URIs use the same naming style. They are listed
  in the catalog under `uri_fields` with the protocols that use them.

## Catalog

`bimeron errors --json`, Android `ErrorCatalog()` and Apple `RLErrorCatalog()`
return the catalog embedded in that core build:

```json
{
  "version": 1,
  "languages": ["en", "ru"],
  "secret_fields": ["Password", "ID", "..."],
  "uri_fields": {"ObfsPassword": ["Hysteria2"]},
  "codes": {
    "interface_name_invalid": {
      "kind": "config",
      "en": "Must start with a Latin letter and contain up to {max} Latin letters, digits, underscores or hyphens.",
      "ru": "..."
    }
  }
}
```

- `kind` is `config` (profile validation), `control` (local control errors) or
  `connection` (`Status.LastError` and event errors).
- Texts omit the field name. Show `<client field label>: <text>` when the client
  maps the location to a field, otherwise the text alone.
- Replace `{name}` with `args[name]`. Leave an unknown placeholder as is.
- Unknown code: show the `unclassified` text and offer `message` as details.
- `unclassified` is also the code of any failure the core could not classify.
  Tests keep validation paths free of it.
- Secret fields: when `value` is `present`, show a fixed mask of eight bullet
  characters, never a mask of the value length. A client may offer a local
  reveal action using the value from its own editor state.

## Transports

| Transport | Problems | Catalog |
|---|---|---|
| CLI | `bimeron validate --json <absolute-path>` prints `{"version":1,"problems":[...]}`. Failures keep the existing `error` and `details` fields. Plain `validate` output is unchanged. | `bimeron errors --json` |
| Desktop document bridge | `bimeron document` and `bimeron geodata` responses add `problems` on failure. | |
| Local control | A rejected `start` keeps `error: "invalid_configuration"` and adds `problems`. | |
| Android | `ValidateConfigWithGeoData` adds `problems`. | `ErrorCatalog()` |
| Apple | `RLValidate(data, size, geoIP, geoIPSize, geoSite, geoSiteSize)` returns `{"version":1,"problems":[...]}`; free with `RLFree`. | `RLErrorCatalog()`; free with `RLFree` |

Connection failures keep using `Status.LastError` and event `error` values; each
value is a catalog code of kind `connection`.

## Compatibility

All fields are additive. Older cores omit `problems` and the catalog command;
clients detect this and fall back to their previous behavior. New codes may
appear in any release; renamed or removed codes require a contract version
change.
