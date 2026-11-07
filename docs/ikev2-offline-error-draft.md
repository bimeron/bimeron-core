# Frozen offline IKEv2 error draft

Status: disconnected draft only, not accepted wire format or published v2 support.
Native remains OFF. No producer, control protocol, capability or auth seam changes.
Based on the read-only Desktop error-contract planning proposal.

The shared fixture is `core/testdata/ikev2-error-draft-v1.json`. Its top-level
`draft`, `valid`, and `invalid` fields are test scaffolding, never a wire envelope.
Each case has a name, enclosing `attempt`, and optional `native_failure`.
Valid absence means unknown numeric evidence, never success. Explicit JSON null
is invalid when the member is present. Operation and cleanup are independently
optional; at least one must be present in a present member.

A member has exactly `version: 1` and optional `operation` and `cleanup` objects.
Each record has exactly `domain`, `code`, `stage`, `attempt`. Domain is
`windows_ras`; code is an integer 1..4294967295; attempt is an integer
1..2147483647 equal to the enclosing attempt. No coercion, null, unknown fields,
arrays, messages, raw diagnostics or extension bags. Maximum member size is 512
UTF-8 bytes. Unknown version/domain/stage is rejected. Unknown valid numeric codes
are preserved with unknown cause, including 775. Zero means absence, not a record.

Operation stages: `profile_inspection`, `dial`, `connection_status`.
Cleanup stages: `cleanup_hangup`, `cleanup_status`.
Slots cannot exchange stages. Cleanup 668 is separate cleanup evidence and cannot
replace an operation failure or establish successful connection or clean state.

The disconnected model validates against an explicit current attempt. A late
record from an earlier attempt fails validation. No stateful authority, merge,
event, exchange generation or lifecycle tracker is introduced. Future producers
must retain first operation/cleanup failures independently, clear on new attempt,
and separately validate identity/exchange freshness; this draft grants no authority.

Choice: a small standalone typed record with validation and standard JSON tags,
rather than modifying Engine/Status or adding a production transport codec.
This keeps offline consumers testable without claiming producer propagation.
The fixture is frozen once shared; changes require explicit Core/Desktop coordination.
