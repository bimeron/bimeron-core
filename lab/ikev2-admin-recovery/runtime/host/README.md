# One-attempt host integration

Only the parent operates the lab. The real `build/l1/live-config.json` remains absent until kernel tests and HIGH review pass. `live-config.example.json` is inert, with nonexistent paths and zero hashes. Missing files, changed hashes, duplicate keys, unknown fields, boolean admission values, or failed controls refuse. No guard removal, offload restoration, retry, or cleanup after uncertain installation/publication is implemented.

Ordinary preflight is unchanged. Successful cleanup requires original drain and its validated owner sample. The hook consumes the raw six-field sample (`pid`, `creationFileTime`, `path`, `sha256`, `handleState`, `exitCode`), requiring `live` and null exit code. `Adapter.owner_identity` remains the original four-field identity. Failure cleanup bypasses the hook. The separate native `live-admission.json` contains exactly `Binding`, `GuardSHA256`, `FixtureSHA256`, `ReviewedSHA256`. No admission field is added to the strict cleanup request.

## Exact configuration schemas

All schemas have exactly the listed fields. Digests are lowercase SHA256 over exact bytes. Relative paths resolve against the config directory. No flag grants admission.

- Config: `schema: "l1-live-config-v1"`, `templateTable`, `artifacts`. The table matches `ikeq_[a-z][a-z0-9_]{0,24}` and names the table in the tested expectation. Every artifact is `{ "path": "...", "sha256": "..." }`.
- Required artifacts: `renderer`, `expected`, `kernel`, `review`, `fixture`, `ca`, `topology`, `hostCode`, `events`, `ownerExe`. `ownerExe` is the final reviewed `native/full300-owner.exe`; its digest must equal the current owner binding. `expected` and `events` name the fixture's actual `expected-guard.json` and `events.jsonl`; never fabricate either from intended outcomes.
- `renderer`: exact reviewed `guard/render.py`, exposing `render(run, lab, uplink) -> str`. Verified bytes execute with run `l<noncefirst16>`, lab `labnet`, uplink `uplink`. The table is `ikeq_l<noncefirst16>`.
- `expected`: `{ "nftables": [...] }` from actual installed fixture rules, containing only the tested guard's objects. Empty expectations and unrelated objects refuse. Only JSON string values exactly equal to `templateTable` are substituted. Comparison preserves order and semantic fields, excluding metainfo objects, handles, and counter packet/byte values only. Raw readbacks are also retained.
- `kernel`: `{ "schema": "l1-kernel-result-v1", "result": "PASS", "rendererSHA256": "...", "expectedSHA256": "...", "fixtureSHA256": "...", "topologySHA256": "...", "eventsSHA256": "...", "tests": {...} }`. Parent must truthfully map actual fixture results. `tests` contains exactly `valid500`, `valid4500`, `esp`, `udpESP`, `keepalive`, `truncated`, `markerOnly`, `wrongVersion`, `wrongExchange`, `firstFragment`, `laterFragment`, `ipv6`, `dnsInput`, `existingFlow`, each the string `PASS`. Review must assess their meaning and coverage; these strings alone are not independent kernel proof.
- `review`: `{ "schema": "l1-review-v1", "effort": "HIGH", "verdict": "APPROVED", "artifacts": {...} }`. `artifacts` maps every artifact name except `review` to its exact digest, including `kernel`, `events`, `hostCode`. Review follows completed evidence. The validator generates no approval.
- `hostCode`: `{ "schema": "l1-host-code-v1", "files": {...} }`. `files` maps every direct `driver/*.py`, `driver/*.ps1`, and `host/publish-live.ps1` path (relative to `build/l1`, forward slashes) to its digest. Every current file and the complete set are checked. Native executable bytes bind separately through `Binding.SHA256`, owner sample, guest config, and current executable readback; include native source/executable review in the parent's freeze too.
- `ca`: trusted root certificate DER bytes, matching `fixture.caSHA256`.
- `fixture`: exactly `{ "schema": "l1-live-fixture-v1", "vm": "<LAB_VM_ID>", "guest": "<LAB_GUEST_NAME>", "principalSid": "<LAB_GUEST_SID_1001>", "guestIP": "192.0.2.2", "guestMAC": "<LAB_GUEST_MAC>", "peer": "<LAB_PUBLIC_IP>", "profile": "Bimeron Step8", "serverName": "ikev2.bimeron.test", "caSHA256": "...", "lab": "labnet", "uplink": "uplink" }`. Map original CA/VM evidence truthfully. Publisher checks current VM, credential SID, guest network identity, per-user IKEv2/EAP profile, trusted CA bytes, owner-once, gate binding, completed observation, and retained current PID/creation/executable identity.
- `topology`: `{ "links": [...], "addresses": [...], "routes": [...] }`, from `ip -j link show`, `ip -j address show`, `ip -j route show table all`. Exclude only `valid_life_time` and `preferred_life_time` within address `addr_info`. All other fields and array order remain exact. Freeze fresh immediately before the authorized action if other fields change; do not broaden exclusions. Kernel review must establish absence of bridge/flowtable/hardware bypass: ip readbacks alone cannot prove that.

## Offline commands

```powershell
python build/l1/host/validate-live.py --code-manifest build/l1/host-code.json
python build/l1/host/validate-live.py --config build/l1/live-config.json
python -m unittest discover -s build/l1/host -p 'test_*.py'
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File build/l1/host/test-parser.ps1
```

The first command exclusively creates a local code manifest, not configuration, kernel results, or approval. Validation reads files only. Tests mock every subprocess. PowerShell tests only parse scripts.

## Evidence and outcome

`<run>/live/` retains an exclusive attempt latch, frozen inputs, rendered batch, substituted canonical expectation, topology, before/after ethtool features, raw/canonical nft baselines, full post-install ruleset, canonical guard readback, hash-bound verification record, and publication receipt. SSH uses the exact protected observer key/options from `preparation.py`. Commands are fixed and batches travel via stdin. GRO is disabled only if needed on dedicated labnet/uplink and then read back. The installer exits before a separate ruleset readback. Any failure keeps guard/offload state for parent disposition.

Native final `Live` is hash-checked via owner-exit, recorded in `live-outcome.json` and the protected result. A failed dial remains failed even when restoration succeeds. Unknown termination holds before supervisor release. Guard removal/offload restoration remain explicit parent actions after verified owned termination and original restoration evidence.
