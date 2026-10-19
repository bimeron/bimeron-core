#!/bin/sh
# Build the Android packet core; no app or VPN service is bundled.
set -eu
cd "$(dirname "$0")/.."
: "${ANDROID_HOME:?Set ANDROID_HOME to the Android SDK directory}"
: "${ANDROID_NDK_HOME:?Set ANDROID_NDK_HOME to an installed NDK directory}"
command -v gomobile >/dev/null 2>&1 || { echo 'gomobile is required' >&2; exit 1; }
output="${ANDROID_BUILD_DIR:-$PWD/dist/android}"
mkdir -p "$output"
gomobile bind -target=android/arm,android/arm64,android/386,android/amd64 -androidapi=23 -javapkg=org.bimeron.core -o "$output/bimeron-core.aar" ./androidcore
cp LICENSE "$output/"
cp THIRD_PARTY_NOTICES.txt "$output/"
printf '%s\n' "$output/bimeron-core.aar"
