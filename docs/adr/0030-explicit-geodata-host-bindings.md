# ADR 0030: Explicit geodata resources for embedded hosts

Status: accepted implementation boundary, 2026-11-01.
Tracking: issue #67.

## Context

Android and Apple packet hosts embed core in sandboxes. Profile paths alone
cannot grant filesystem access. GUIs need support discovery, group selection
and validation without starting networking. Existing inline profile APIs must
retain their no-file-access behavior.

## Decision

Use explicit GeoIP and GeoSite byte inputs with the shared core decoder and
immutable session policy. Expose the schema and separate capability flags;
return stable group IDs and human-readable validation errors through gomobile
JSON strings and allocated Apple C JSON strings freed with RLFree. Preserve
existing constructors through shared creation helpers. Check Apple dataset
lengths against 64 MiB each before copying C memory. Keep existing host mode
and kill-switch restrictions. See [the exact API contract](../GEODATA.MD).

The runtime decodes only the documented V2Ray GeoIPList/GeoSiteList wire
schema using the existing protobuf wire dependency. It checks framing, entry
values and resource budgets before constructing immutable matchers. Prefix hash
indexes and exact/suffix domain maps avoid scanning dataset entries on common
lookups. Rules remain ordered, so indexes cannot change first-match precedence.
Plain substring and regex entries retain bounded scans; a more complex text
index is deferred until measurements justify it. GeoSite participates in the
existing DomainRelevant filter for trusted DNS metadata.

## Alternatives and tradeoffs

Implicit filesystem reads would make inline profiles dependent on sandbox and
working-directory state; reject them. A downloader or new RPC surface adds
resource ownership and security concerns outside this issue. Explicit buffers
require host-managed file permissions and memory, but make resource lifetime
and validation reproducible. Retain human-readable error strings for generic failures and attach shared
typed geodata details for dataset/group/rule controls. One-based rule indices
refer to active executable rules rather than document lines.

Importing an entire V2Ray runtime would add dependencies beyond the two dataset
messages. Maintaining generated schema types would require generated sources
and a regeneration process without removing semantic validation. The bounded
wire decoder keeps this integration local and makes supported entry types
explicit. Expanding GeoIP into OS bypass routes would risk overriding earlier
rules; retain geodata decisions in the packet/proxy policy and conservatively
suppress later CIDR bypasses where an earlier geodata rule could conflict.

## Consequences

Hosts enumerate and validate before startup, retain invalid drafts, and require
a new session after dataset replacement. Relative paths in the file API remain
profile-relative. DNS visibility limitations, IPv6 restrictions and unsupported
IKEv2 split routing remain visible to callers. CI exercises host JSON contracts,
Apple ABI symbols, routing fuzzing/benchmarks and existing platform builds.
