#!/bin/sh
# Build the Android packet core; no app or VPN service is bundled.
set -eu
cd "$(dirname "$0")/.."
: "${ANDROID_HOME:?Set ANDROID_HOME to the Android SDK directory}"
: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to an installed NDK directory}"
command -v gomobile >/dev/null 2>&1 || { echo 'gomobile is required' >&2; exit 1; }
output="${ANDROID_BUILD_DIR:-$PWD/dist/android}"
mkdir -p "$output"
# Keep the NDK install path out of the C/DWARF debug info so builds on different hosts match.
export CGO_CFLAGS="${CGO_CFLAGS:--O2 -g} -ffile-prefix-map=$ANDROID_NDK_HOME=/android-ndk"
if [ -n "${BIMERON_VERSION:-}" ]; then
    set -- -ldflags "-X bimeron/core.Version=${BIMERON_VERSION#v}"
elif tag=$(git describe --tags --abbrev=0 --match 'v[0-9]*' 2>/dev/null); then
    set -- -ldflags "-X bimeron/core.Version=${tag#v}-dev"
else
    set --
fi
gomobile bind "$@" -target=android/arm,android/arm64,android/386,android/amd64 -androidapi=23 -javapkg=org.bimeron.core -o "$output/bimeron-core.aar" ./androidcore
cp LICENSE "$output/"
cp THIRD_PARTY_NOTICES.txt "$output/"
printf '%s\n' "$output/bimeron-core.aar"
