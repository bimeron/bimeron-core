#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 || ( $# -eq 2 && "$2" != "--upload" ) ]]; then
  echo 'usage: scripts/backfill-update-manifest.sh <tag> [--upload]' >&2
  exit 2
fi
tag=$1
mode=${2:-dry-run}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

gh release download "$tag" --repo bimeron/bimeron-core --pattern '*.zip' --pattern SHA256SUMS --dir "$tmp"
(cd "$tmp" && sha256sum --check SHA256SUMS)
review_flag=()
if [[ "$mode" == '--upload' ]]; then review_flag=(-require-reviewed); fi
go run scripts/release-manifest.go -tag "$tag" -dir "$tmp" "${review_flag[@]}"
go run scripts/release-manifest.go -tag "$tag" -dir "$tmp" -verify "${review_flag[@]}"

assets=$(gh release view "$tag" --repo bimeron/bimeron-core --json assets --jq '.assets[].name')
has_manifest=0
has_signature=0
if grep -qx 'update-manifest.json' <<< "$assets"; then has_manifest=1; fi
if grep -qx 'update-manifest.json.sig' <<< "$assets"; then has_signature=1; fi
if [[ "$has_manifest" != "$has_signature" ]]; then
  echo 'release contains only one metadata asset; refusing partial backfill' >&2
  exit 1
fi
if [[ "$has_manifest" == 1 ]]; then
  existing=$(mktemp -d)
  trap 'rm -rf "$tmp" "$existing"' EXIT
  gh release download "$tag" --repo bimeron/bimeron-core --pattern update-manifest.json --pattern update-manifest.json.sig --dir "$existing"
  cmp "$tmp/update-manifest.json" "$existing/update-manifest.json"
  cmp "$tmp/update-manifest.json.sig" "$existing/update-manifest.json.sig"
  echo "$tag: metadata already matches; no upload needed"
  exit 0
fi
echo "$tag: prepared update-manifest.json and update-manifest.json.sig ($mode)"
if [[ "$mode" == '--upload' ]]; then
  gh release upload "$tag" "$tmp/update-manifest.json" "$tmp/update-manifest.json.sig" --repo bimeron/bimeron-core
fi
