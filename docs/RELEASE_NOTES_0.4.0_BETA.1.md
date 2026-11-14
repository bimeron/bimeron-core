# Bimeron Core v0.4.0-beta.1

**Draft — reviewed on 2026-11-14.** Finalize after the pending changes merge and the release candidate is validated. This document does not announce a published release.

The reviewed source range is `abd705b6..46a21da7` on master. `abd705b6` is the master equivalent of the previous release, v0.3.0-beta.2; its tag points to `66d84d8f`, outside master history.

For package capabilities, see the [README at the planned release tag](https://github.com/bimeron/bimeron-core/blob/v0.4.0-beta.1/README.md). This future link must be verified during finalization.

## Merged changes

### Routing and configuration editing

- Local V2Ray-format GeoIP/GeoSite datasets, ordered routing, catalogs, typed validation and comment-preserving Desktop document editing ([#80](https://github.com/bimeron/bimeron-core/pull/80)). Dataset downloads and updates remain host responsibilities.
- Explicit Hysteria2, VMess, TUIC, AnyTLS and Naive QUIC parameters, advertised through `explicit_access` ([#115](https://github.com/bimeron/bimeron-core/pull/115)).
- Conversion between share URIs and explicit fields through `access_to_fields` and `access_to_uri`, with runtime-equivalence checks and preservation of unrelated document bytes ([#116](https://github.com/bimeron/bimeron-core/pull/116)). SSConf, File and IKEv2 conversion is unsupported. The original document API came from #80; #115 and #116 extend it.
- Structured configuration and connection problems with stable codes, field locations and a shared English/Russian catalog ([#106](https://github.com/bimeron/bimeron-core/pull/106)). `LastError` now carries catalog codes rather than raw diagnostic text; platform errors no longer append free-form suffixes. Clients should render the catalog instead of parsing English messages.

### Recovery and session control

- Authenticated single-session Windows/Linux recovery with consent, readiness checks and transactional recovery ([#81](https://github.com/bimeron/bimeron-core/pull/81)). Privileged rollback, alternate-administrator acceptance and historical package migration still have validation gaps.
- Optional daemon instance/session guards prevent stale commands from mutating replacement sessions ([#83](https://github.com/bimeron/bimeron-core/pull/83)); optional session-bound statistics snapshots keep status and counter ownership together ([#90](https://github.com/bimeron/bimeron-core/pull/90)). Native IKEv2 statistics remain unavailable.
- Windows repair/update accepts a never-started service as a clean exit while retaining recovery-marker checks ([#112](https://github.com/bimeron/bimeron-core/pull/112)). macOS Stop preserves cancellation during network setup and distinguishes rollback failures ([#102](https://github.com/bimeron/bimeron-core/pull/102)).

### Android, SSConf and SSH

- Cancellable, single-use protected SSConf resolution ([#97](https://github.com/bimeron/bimeron-core/pull/97)) and immutable snapshot sessions without refetching ([#100](https://github.com/bimeron/bimeron-core/pull/100)). Hosts retain persistence and network-binding responsibilities.
- Bounded, session-scoped SSH authentication prompts ([#98](https://github.com/bimeron/bimeron-core/pull/98)). Android can opt into accept-new host-key offers; changed or revoked keys are rejected, and the host owns persistence ([#104](https://github.com/bimeron/bimeron-core/pull/104)). CLI, daemon, Desktop and Apple retain known-hosts-only verification.
- SSConf response headers are capped at 64 KiB, alongside the existing body limit ([#109](https://github.com/bimeron/bimeron-core/pull/109)).

### Apple preparation, internal models and validation

- Separate Apple archive metadata and retained version provenance preparation ([#85](https://github.com/bimeron/bimeron-core/pull/85), incorporating [#88](https://github.com/bimeron/bimeron-core/pull/88)), with release-packet documentation aligned to the staging API ([#93](https://github.com/bimeron/bimeron-core/pull/93)). This is source preparation: compatibility approval, a trusted pin and candidate/runtime validation remain required.
- Apple bundle identifiers are `com.noob-rp.bimeron` and `com.noob-rp.bimeron.packet` ([#117](https://github.com/bimeron/bimeron-core/pull/117)).
- Maintenance admission/recovery models and an internal sealed coordinator ([#86](https://github.com/bimeron/bimeron-core/pull/86), [#94](https://github.com/bimeron/bimeron-core/pull/94)) do not provide a production maintenance endpoint or verified OS cleanup.
- Offline native enrollment primitives, reader and proof harness remain disabled and do not establish native acceptance ([#74](https://github.com/bimeron/bimeron-core/pull/74), [#75](https://github.com/bimeron/bimeron-core/pull/75), [#76](https://github.com/bimeron/bimeron-core/pull/76), [#77](https://github.com/bimeron/bimeron-core/pull/77), [#78](https://github.com/bimeron/bimeron-core/pull/78)).
- SSH lifecycle evidence and Windows fixture improvements ([#87](https://github.com/bimeron/bimeron-core/pull/87)), Android NDK debug-path normalization ([#107](https://github.com/bimeron/bimeron-core/pull/107)), validation-only socket/goroutine regression coverage ([#108](https://github.com/bimeron/bimeron-core/pull/108)), and host-key documentation reference cleanup ([#110](https://github.com/bimeron/bimeron-core/pull/110)). These changes do not establish installed-package or live VPN acceptance for this candidate.

## Experimental IKEv2 and known limitations

Native Windows IKEv2 integration is merged ([#103](https://github.com/bimeron/bimeron-core/pull/103)) but remains experimental. It uses foreground execution and a current-user profile; daemon, proxy, split-routing and statistics support are unavailable. Offline authentication/failure/maintenance models are not production lifecycle support.

Windows 11, RRAS interoperability, physical network transitions, sleep/resume and public IPv6 remain unconfirmed. DNS can leak without native protection. The broader validation in [#66](https://github.com/bimeron/bimeron-core/issues/66) is deferred; merge does not imply that those checks passed.

## Compatibility — review required

IPC remains version **1** and profile format remains version **1**. New capabilities, document operations and structured errors require client integration review even though these version numbers are unchanged. Clients should check capabilities such as `daemon_session_guards`, `session_bound_stats`, `explicit_access` and `access_conversion` before using optional operations.

**GUI version range and Desktop update channel: OPEN.** Await the Desktop compatibility investigation and actual candidate validation. The existing `release/compatibility.json` records GUI `[0.2.0, 0.2.1)`, `gui_reviewed: true`, IPC 1 and profile format 1. Those are existing values, not approval for this release; this draft does not change that file.

## Pending — not included in the reviewed master

Retain these items until finalization, even if they merge while this draft is being prepared. Recheck their final commits and outcomes before moving them into the merged section.

- Core icon ([issue #111](https://github.com/bimeron/bimeron-core/issues/111)).
- Native enrollment volume-root rights ([PR #79](https://github.com/bimeron/bimeron-core/pull/79)).
- SSH robustness: bare `~` panic and network retries.
- Protocol lifecycle: UDP domain replies, Hysteria2 dial cancellation and TUIC races.
- Linux network guards: `ipv6.disable=1`, kill-switch rollback and leading-dot domain rules.
- CLI/service lifecycle: resumable Windows uninstall, Wintun digest pinning and watch across daemon restarts.
- Windows PowerShell UTF-8 output.
- CI hygiene.

## Planned packages and verification

Confirm the final asset inventory during finalization. The expected layout follows the previous release: six CLI ZIP packages for Windows, Linux and macOS on amd64 and arm64, plus one Android AAR package. Each package includes `LICENSE` and `THIRD_PARTY_NOTICES.txt`; Windows packages include the matching Wintun DLL and its license. Android is an AAR, not an installable application. Apple NetworkExtension is not included in this planned package set.

Verify archives with `SHA256SUMS`. Windows/Linux service update clients can verify `update-manifest.json` with `update-manifest.json.sig` and a separately trusted Ed25519 public key. The service manifest covers Windows/Linux amd64 and arm64, not macOS or Android. Apple metadata preparation does not imply an approved Apple release.

Before publication, reconcile pending changes, resolve GUI compatibility and the Desktop channel, validate the final candidate and signed assets, and verify the tag-specific README link. No new candidate tests, benchmarks or CI results are claimed by this documentation-only draft.
