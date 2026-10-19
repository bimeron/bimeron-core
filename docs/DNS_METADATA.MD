# DNS metadata architecture

This document describes domain rules for system VPN. Metadata lives only in core
memory and supplements the existing IP/CIDR policy.

## Goal

System DNS already passes through Bimeron, but the TCP/UDP handler receives only
the destination IP from the packet stack. A validated DNS response must be linked
to a subsequent connection so the domain name can be passed to the existing policy.

The solution must not write domain history to disk, expose domains in logs, or
treat DNS metadata as proof of any connection's origin.

## Alternatives considered

### One latest domain per IP

A simple `IP → domain` table is nondeterministic: a shared CDN address may be
returned for several domains, and the result depends on the order of concurrent
DNS responses. This option was rejected.

### Fixed action priority

Storing several domains and always choosing `block`, then `proxy`, then
`direct` would violate the documented rule order and change configuration
semantics. This option was rejected.

### Domain set with the existing rule order

The implementation stores all unexpired associations between an IP and relevant
domains. On connection, rules are checked top to bottom. A CIDR rule matches the
IP; a domain rule matches if any domain in the set matches. The first rule wins,
regardless of DNS response order.

## Data model

Metadata exists only in memory for one VPN session and is shared across handler
generations during reconnect. Stopping the session removes the table.

Each IP has a set of normalized domains and an expiration time for each
association. Only domains that can match at least one domain rule in the active
policy enter the table. This reduces memory use and avoids unnecessary browsing
history.

Current limits:

- At most 4096 IP–domain associations per session.
- TTL comes from the validated DNS response and is capped at 24 hours.
- TTL 0 is not stored.
- Expired entries are removed on reads and inserts.
- When full, associations expiring soonest are evicted.

A linear scan for eviction is acceptable with a 4096-entry limit. A more complex
structure is warranted only after a measured performance impact.

## DNS processing

Metadata is extracted only after existing response validation: ID, opcode, and
questions must match, and the result must be `NOERROR`. The association is
stored before the response reaches the application, so an immediate connection
already sees it.

One IN-class question of type A or AAAA is supported. For a CNAME chain, the
original queried name is stored only for A/AAAA addresses reachable through that
chain. Lifetime cannot exceed the minimum TTL of the CNAMEs and address record
used.

NXDOMAIN, SERVFAIL, REFUSED, truncated responses, and unvalidated responses add
nothing. The synthetic empty AAAA response for `IPv6 = disable` also adds
nothing. Responses with multiple questions are still forwarded, but this initial
implementation does not extract metadata from them.

## Route selection

Policy receives an IP and its set of valid domains. It still applies the first
matching rule:

1. Compare CIDR with the IP.
2. Compare Domain with every domain in the set, including subdomains under the
   existing normalization rules.
3. If the rule does not match, continue to the next rule.
4. If none match, use `Default`.

If one IP belongs to several domains with different actions, rule order in
`.conf` determines the result. DNS response and goroutine ordering do not
affect the decision.

## Guarantee boundaries

A domain rule works when an application first obtains A/AAAA through Bimeron DNS,
then opens a connection before the metadata expires. Without a validated
association, ordinary IP rules and `Default` apply.

Metadata is unavailable for:

- An IP address entered directly.
- A DNS cache populated before session startup.
- DoH, DoT, and application-owned DNS.
- An address whose TTL expired or whose entry was evicted.
- An unsupported DNS response containing multiple questions.

Domain rules therefore do not constitute an independent kill switch.
Applications with their own DNS are governed only by IP/CIDR rules and `Default`.

## Concurrency and privacy

One lock protects the bounded table. DNS parsing happens before entering the
critical section. Reads return a copy of valid domains; policy does not hold the
metadata lock during network connection setup.

Domains are not included in events, errors, statistics, doctor output, crash
reports, or state files. The table does not survive Stop or process restart.
If needed, counters may record only numbers of hits, misses, and evictions,
without addresses or names.

## Core implementation

The bounded store is in `internal/vpn`. One table belongs to a VPN session and
is passed to each handler generation on reconnect. UDP and TCP DNS add metadata
before returning the response to the client. Policy accepts a domain set; the
single-domain API remains for SOCKS5. On Windows, Linux, and macOS,
`capabilities.domain_split = true`.

No external dependencies or new background process are required.

## Automated checks

- A and AAAA, CNAME, TTL 0, and TTL expiration.
- One IP shared by several domains with different actions.
- Combined CIDR and Domain ordering.
- Identical results with different concurrent DNS response orders.
- Metadata retained on reconnect and removed on Stop.
- The 4096 limit and predictable eviction.
- No learning from erroneous or unvalidated responses.
- DNS over UDP and TCP.
- Race detection for concurrent DNS responses and connections.
- Public-structure code checks that domains are not passed into events or diagnostics.

## Manual validation

A historical Mac ARM64 check used `Default = direct` and a `proxy` domain rule.
After a fresh DNS response, a connection to the returned IP used Outline, while
a domain without a rule retained direct routing. This also confirmed the guarantee
boundary: an address in the system DNS cache from before session startup uses
`Default` until Bimeron sees a new DNS response.
