#!/bin/sh
# Build and package CLI targets from any directory. Optional: windows, linux, macos.
set -eu
cd "$(dirname "$0")/.."
sh scripts/release-go.sh run scripts/build-dist.go "${1:-all}"
