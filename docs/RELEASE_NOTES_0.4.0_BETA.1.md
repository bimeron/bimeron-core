# Bimeron Core v0.4.0-beta.1

**Release notes — reviewed on 2026-11-14.** GUI compatibility and release-candidate validation remain release gates. This document does not announce a published release.

The reviewed source range is `abd705b6..7f9e3087` on master. `abd705b6` is the master equivalent of the previous release, v0.3.0-beta.2; its tag points to `66d84d8f`, outside master history.

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

### Platform, protocol and lifecycle fixes

- Windows PowerShell output is decoded as UTF-8, preserving Unicode adapter names and localized diagnostics ([#123](https://github.com/bimeron/bimeron-core/pull/123)).
- SSH fixes the bare `~` path panic, reports retryable network failures as `ssh_network_failed`, and prefers host key types from `known_hosts` in file-only mode. File-only mode no longer offers `ssh-dss`; each network retry re-prompts for interactive input such as passphrases ([#124](https://github.com/bimeron/bimeron-core/pull/124)).
- Distribution Windows executables embed the Bimeron icon and VERSIONINFO; Apple builds include the icon in `BimeronCore.app` and its extension. Windows `build-dist` now requires a SemVer version. Plain `go build` does not embed Windows resources ([#125](https://github.com/bimeron/bimeron-core/pull/125)).
- CLI/service lifecycle adds signal cleanup, resumable Windows uninstall, leftover-tolerant install and Wintun digest pinning. `watch` survives daemon restarts after its first connection; help exits 0 (the existing `errors -h` exception remains) ([#126](https://github.com/bimeron/bimeron-core/pull/126)).
- Linux supports kernels booted with `ipv6.disable=1`, preserves retained kill switches on setup rollback and skips IPv6 direct throw routes when IPv6 is disabled. Leading-dot domain rules match the base domain and its subdomains consistently in the runtime and document editor ([#127](https://github.com/bimeron/bimeron-core/pull/127)).
- Protocol fixes deliver UDP domain replies, honor Hysteria2 dial cancellation with sanitized `hysteria2_dial_rejected` errors, and fix TUIC cancellation races and buffered delivery. Linux and Windows lifecycle race checks were added; abandoned upstream Hysteria2 calls remain bounded by the QUIC connection lifetime ([#128](https://github.com/bimeron/bimeron-core/pull/128)). The rejection's Russian locale text is corrected ([#131](https://github.com/bimeron/bimeron-core/pull/131)).
- Native enrollment permits outsider subdirectory-creation rights only at the held volume root while retaining strict descendant checks. Native proof remains unexecuted, enrollment remains disabled, and [issue #73](https://github.com/bimeron/bimeron-core/issues/73) stays open ([#79](https://github.com/bimeron/bimeron-core/pull/79)).
- CI adds a lint job, pinned actions, job timeouts, checkout hardening and CLI artifact source-SHA verification, while preserving lifecycle race coverage ([#130](https://github.com/bimeron/bimeron-core/pull/130)).

## Experimental IKEv2 and known limitations

Native Windows IKEv2 integration is merged ([#103](https://github.com/bimeron/bimeron-core/pull/103)) but remains experimental. It uses foreground execution and a current-user profile; daemon, proxy, split-routing and statistics support are unavailable. Offline authentication/failure/maintenance models are not production lifecycle support.

Windows 11, RRAS interoperability, physical network transitions, sleep/resume and public IPv6 remain unconfirmed. DNS can leak without native protection. The broader validation in [#66](https://github.com/bimeron/bimeron-core/issues/66) is deferred; merge does not imply that those checks passed.

## Compatibility — review required

IPC remains version **1** and profile format remains version **1**. New capabilities, document operations and structured errors require client integration review even though these version numbers are unchanged. Clients should check capabilities such as `daemon_session_guards`, `session_bound_stats`, `explicit_access` and `access_conversion` before using optional operations.

**GUI compatibility range: to be finalized before tagging**

## Upgrade notes / Desktop

Published Desktop 0.2.0 and Desktop main at 516ea4b both pin Core v0.3.0-beta.2. The next Desktop release, 0.3.0, will bundle this Core release and needs the updated Core pin to deliver the new features. Current Desktop main already uses the configuration document API, `explicit_access` (#115) and `access_conversion` (#116).

Desktop offers beta Core updates only when the user enables **Include beta core updates** for the current session. A service update alone does not replace the bundled CLI.

The GUI compatibility range will be decided in `release/compatibility.json` together with the Desktop 0.3.0 release decisions; this document does not change that file. Versioning policy is postponed.

## Planned packages and verification

Confirm the final asset inventory during finalization. The expected layout follows the previous release: six CLI ZIP packages for Windows, Linux and macOS on amd64 and arm64, plus one Android AAR package. Each package includes `LICENSE` and `THIRD_PARTY_NOTICES.txt`; Windows packages include the matching Wintun DLL and its license. Android is an AAR, not an installable application. Apple NetworkExtension is not included in this planned package set.

Verify archives with `SHA256SUMS`. Windows/Linux service update clients can verify `update-manifest.json` with `update-manifest.json.sig` and a separately trusted Ed25519 public key. The service manifest covers Windows/Linux amd64 and arm64, not macOS or Android. Apple metadata preparation does not imply an approved Apple release.

Before publication, resolve GUI compatibility, validate the final candidate and signed assets, and verify the tag-specific README link. No new candidate tests, benchmarks or CI results are claimed by this documentation-only draft.
