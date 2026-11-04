#!/bin/sh
set -eu
cd "$(dirname "$0")"
# Use an already installed Go >=1.26 on PATH; never auto-download a toolchain.
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOWORK=off
export GOCACHE="$PWD/.cache" GOMODCACHE="$PWD/.cache/mod" GOTMPDIR="$PWD/.cache"
mkdir -p "$GOCACHE"
go test -count=1 -v ./...
