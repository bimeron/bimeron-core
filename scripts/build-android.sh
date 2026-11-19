#!/bin/sh
# Build the Android packet core; no app or VPN service is bundled.
set -eu
cd "$(dirname "$0")/.."
: "${ANDROID_HOME:?Set ANDROID_HOME to the Android SDK directory}"
: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to an installed NDK directory}"
command -v gomobile >/dev/null 2>&1 || { echo 'gomobile is required' >&2; exit 1; }
sh scripts/release-go.sh
output="${ANDROID_BUILD_DIR:-$PWD/dist/android}"
mkdir -p "$output"
output=$(cd "$output" && pwd)
# Keep the NDK install path out of the C/DWARF debug info and, with -trimpath,
# the source and module cache paths out of the Go code, so the library names no
# local directory and builds on different hosts match.
export CGO_CFLAGS="${CGO_CFLAGS:--O2 -g} -ffile-prefix-map=$ANDROID_NDK_HOME=/android-ndk"
if [ -n "${BIMERON_VERSION:-}" ]; then
    set -- -ldflags "-X bimeron/core.Version=${BIMERON_VERSION#v}"
elif tag=$(git describe --tags --abbrev=0 --match 'v[0-9]*' 2>/dev/null); then
    set -- -ldflags "-X bimeron/core.Version=${tag#v}-dev"
else
    set --
fi
# gomobile records the absolute directory of this module and of the vendored
# snapshots in each library's build information. Build through a link at a
# fixed path so that path names no user or workspace either. mkdir is atomic:
# a second build, or another user, cannot take over the private directory,
# and sticky /tmp keeps others from replacing it.
dir=/tmp/bimeron-core-android
if ! mkdir -m 700 "$dir"; then
    echo "$dir exists: another Android build is running, or remove it and retry" >&2
    exit 1
fi
src=$PWD
trap 'rm -f "$dir/src"; rmdir "$dir"' EXIT
ln -s "$src" "$dir/src"
cd "$dir/src"
gomobile bind -trimpath "$@" -target=android/arm,android/arm64,android/386,android/amd64 -androidapi=23 -javapkg=org.bimeron.core -o "$output/bimeron-core.aar" ./androidcore
cp LICENSE "$output/"
cp THIRD_PARTY_NOTICES.txt "$output/"
printf '%s\n' "$output/bimeron-core.aar"
