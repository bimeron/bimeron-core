#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 || ( $# -eq 3 && "$3" != "--publish" ) ]]; then
  echo 'usage: scripts/publish-prepared-release.sh <tag> <release-dir> [--publish]' >&2
  exit 2
fi

tag=$1
dir=$(cd "$2" && pwd)
mode=${3:-dry-run}
repo=bimeron/bimeron-core
commit=$(git rev-parse HEAD)
targets=(android linux-amd64 linux-arm64 macos-amd64 macos-arm64 windows-amd64 windows-arm64)
assets=(SHA256SUMS update-manifest.json update-manifest.json.sig)
for target in "${targets[@]}"; do
  assets+=("bimeron-${tag}-${target}.zip")
done

if [[ -z "${BIMERON_RELEASE_ED25519_PUBLIC_KEY:-}" ]]; then
  echo 'set BIMERON_RELEASE_ED25519_PUBLIC_KEY to the pinned public key' >&2
  exit 1
fi
if [[ -n "$(git status --porcelain)" ]]; then
  echo 'the source checkout must be clean' >&2
  exit 1
fi
for name in "${assets[@]}"; do
  if [[ ! -f "$dir/$name" ]]; then
    echo "missing release asset: $name" >&2
    exit 1
  fi
done
actual=$(find "$dir" -maxdepth 1 -type f -printf '%f\n' | sort)
expected=$(printf '%s\n' "${assets[@]}" | sort)
if [[ "$actual" != "$expected" ]]; then
  echo 'release directory has unexpected files' >&2
  diff -u <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") >&2 || true
  exit 1
fi
sum_names=$(awk '{print $2}' "$dir/SHA256SUMS" | sort)
zip_names=$(printf '%s\n' "${assets[@]:3}" | sort)
if [[ "$sum_names" != "$zip_names" ]]; then
  echo 'SHA256SUMS must list exactly the seven ZIP assets' >&2
  exit 1
fi
(cd "$dir" && sha256sum --check --strict SHA256SUMS)
go run scripts/release-manifest.go -tag "$tag" -dir "$dir" -verify -require-reviewed

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
for target in "${targets[@]}"; do
  archive="$dir/bimeron-${tag}-${target}.zip"
  unzip -tq "$archive" >/dev/null
  if [[ "$target" == android ]]; then continue; fi
  binary=bimeron
  if [[ "$target" == windows-* ]]; then binary=bimeron.exe; fi
  unzip -p "$archive" "$target/$binary" > "$tmp/$binary"
  if ! go version -m "$tmp/$binary" | grep -Fq "vcs.revision=$commit"; then
    echo "$archive does not contain core built from $commit" >&2
    exit 1
  fi
done

if [[ "$mode" != --publish ]]; then
  echo "$tag: prepared assets verified against commit $commit (dry-run)"
  exit 0
fi

if [[ "$(git rev-parse "$tag^{commit}")" != "$commit" ]]; then
  echo 'local tag does not point to the prepared commit' >&2
  exit 1
fi
remote=$(git ls-remote origin "refs/tags/$tag" "refs/tags/$tag^{}")
if ! grep -Fq "$commit" <<< "$remote"; then
  echo 'remote tag does not point to the prepared commit' >&2
  exit 1
fi
if gh release view "$tag" --repo "$repo" >/dev/null 2>&1; then
  echo 'release already exists; refusing to replace assets' >&2
  exit 1
fi
if [[ $(gh run list --repo "$repo" --workflow go.yml --event push --commit "$commit" --json headBranch,conclusion --jq '[.[] | select(.headBranch == "'"$tag"'" and .conclusion == "success")] | length') -lt 1 ]]; then
  echo 'successful tag CI run is required before publication' >&2
  exit 1
fi

cat > "$tmp/notes.md" <<EOF
Bimeron Core $tag.

For the capabilities of these packages, see the [README at this release tag](https://github.com/$repo/blob/$tag/README.md).

The assets contain six CLI packages for Windows, Linux, and macOS (amd64 and arm64) and one Android AAR package. Each package includes LICENSE and THIRD_PARTY_NOTICES.txt. The Windows packages include the matching Wintun DLL and its license.

Verify archives with SHA256SUMS. Windows/Linux service update clients can verify update-manifest.json with update-manifest.json.sig and a separately trusted Ed25519 public key. Android is an AAR, not an installable app. Apple NetworkExtension is not included.
EOF
prerelease=()
if [[ "$tag" == *-* ]]; then prerelease=(--prerelease); fi
paths=()
for name in "${assets[@]}"; do paths+=("$dir/$name"); done
gh release create "$tag" "${paths[@]}" --repo "$repo" --title "Bimeron Core $tag" --notes-file "$tmp/notes.md" --draft --verify-tag "${prerelease[@]}"

expected_remote=$(for name in "${assets[@]}"; do
  printf '%s\t%s\tsha256:%s\n' "$name" "$(wc -c < "$dir/$name" | tr -d ' ')" "$(sha256sum "$dir/$name" | cut -d ' ' -f1)"
done | sort)
actual_remote=$(gh release view "$tag" --repo "$repo" --json assets --jq '.assets[] | [.name, (.size|tostring), .digest] | @tsv' | sort)
if [[ "$expected_remote" != "$actual_remote" ]]; then
  echo 'uploaded assets differ from prepared files; release remains a draft' >&2
  diff -u <(printf '%s\n' "$expected_remote") <(printf '%s\n' "$actual_remote") >&2 || true
  exit 1
fi
gh release edit "$tag" --repo "$repo" --draft=false
echo "$tag: published the verified prepared bytes"
