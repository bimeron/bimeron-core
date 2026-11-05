# Offline draft raw JSON addendum 1

Status: coordinated offline clarification only. Original frozen draft and fixture
remain unchanged. This adds raw-input acceptance tests, not a wire revision.

Reject duplicate decoded property names in the member and either record, whether
values are equal or different and including JSON-escaped equivalent names.
Neither first-value nor last-value selection is allowed.

Version, code and record attempt must use the JSON positive integer lexical
grammar `[1-9][0-9]*` with the original semantic bounds. Thus `1` is valid but
`1.0`, `1e0`, `1E+0`, `-0`, strings and booleans are invalid. Whitespace outside
tokens is allowed. No leading plus or leading zeros. The enclosing attempt is
a caller-supplied validated integer, not parsed from this member.

The supplemental fixture `core/testdata/ikev2-error-raw-addendum-v1.json` holds
raw member strings to preserve duplicates and numeric spellings. Each case has
`name`, `attempt`, `valid`, `raw`. Decode raw as UTF-8, then apply the original
512-byte limit and exact draft shape. A bounded raw-token preflight may supplement
Qt's normal JSON decoder; do not replace it with a general parser framework.
Core's token/uint32 decoder already enforces these rules. Desktop's QJsonObject
alone cannot detect them. This clarification grants no runtime authority.

Input must be valid UTF-8. Reject unpaired escaped UTF-16 surrogates, including
in property names; paired high/low escapes are permitted as Unicode strings but
still subject to the exact field/domain/stage allowlists. Do not normalize keys
beyond JSON escape decoding. No replacement-character repair of malformed input.

Bounded Desktop design: scan only the known root and its two optional record
objects, rejecting unexpected nesting; tokenize strings respecting escapes, let
Qt decode individual string tokens to compare decoded keys, and check numeric
tokens against the grammar above. Validate UTF-8 and surrogate escape pairing.
Then retain Qt's final JSON validation and existing semantic checks. This avoids
a general recursive parser. Core retains its existing standard-library token
decoder with a small surrogate-escape preflight. Tests consume the same raw corpus.
